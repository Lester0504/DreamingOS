// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Passive AP discovery for the controller. See ac_discovery.h for why this
 * listens instead of probing.
 */
#include "ac_discovery.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <libubox/uloop.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "ac_internal.h"

/*
 * Candidates live in memory only. They are unauthenticated hearsay with a
 * short TTL, so persisting them would mean carrying unverified claims across
 * restarts and inviting them into backups. A restart simply re-learns from
 * the next beacon.
 */
static struct ac_discovery_candidate g_candidates[AC_DISCOVERY_MAX_CANDIDATES];
static int g_candidate_count;
static struct uloop_fd g_beacon_fd = { .fd = -1 };
static int g_available;
static char g_reason[128] = "discovery_not_started";

static void ac_discovery_ticket_clear(struct ac_discovery_candidate *candidate)
{
    if (!candidate)
        return;
    OPENSSL_cleanse(candidate->confirm_ticket,
                    sizeof(candidate->confirm_ticket));
    candidate->confirm_ticket_expires_at = 0;
}

static int ac_discovery_ticket_issue(struct ac_discovery_candidate *candidate,
                                     int64_t now)
{
    static const char hex[] = "0123456789abcdef";
    unsigned char random[16];
    size_t i;

    if (!candidate || !candidate->ap_id[0] || !candidate->key_id[0] ||
        candidate->adopted_elsewhere)
        return -1;
    if (candidate->confirm_ticket[0] &&
        candidate->confirm_ticket_expires_at > now)
        return 0;
    ac_discovery_ticket_clear(candidate);
    if (RAND_bytes(random, sizeof(random)) != 1)
        return -1;
    for (i = 0; i < sizeof(random); i++) {
        candidate->confirm_ticket[i * 2] = hex[random[i] >> 4];
        candidate->confirm_ticket[i * 2 + 1] = hex[random[i] & 0x0f];
    }
    candidate->confirm_ticket[32] = '\0';
    candidate->confirm_ticket_expires_at = now + AC_BINDING_TICKET_TTL;
    OPENSSL_cleanse(random, sizeof(random));
    return 0;
}

static void ac_discovery_set_reason(const char *reason)
{
    snprintf(g_reason, sizeof(g_reason), "%s", reason ? reason : "");
}

int ac_discovery_available(void)
{
    return g_available;
}

const char *ac_discovery_reason(void)
{
    return g_reason;
}

static int ac_discovery_text_ok(const char *value, size_t max)
{
    size_t i;

    if (!value)
        return 0;
    for (i = 0; value[i]; i++) {
        if (i >= max)
            return 0;
        /* printable ASCII only; a beacon must not be able to inject control
         * characters into logs or the admin UI */
        if ((unsigned char)value[i] < 0x20 || (unsigned char)value[i] > 0x7e)
            return 0;
    }
    return 1;
}

static const char *ac_discovery_json_str(struct json_object *root,
                                         const char *key)
{
    struct json_object *value = NULL;

    if (root && json_object_object_get_ex(root, key, &value) && value &&
        json_object_is_type(value, json_type_string))
        return json_object_get_string(value);
    return "";
}

static int ac_discovery_json_optional_str(struct json_object *root,
                                          const char *key,
                                          const char **out)
{
    struct json_object *value = NULL;

    if (out)
        *out = "";
    if (!root || !key || !json_object_object_get_ex(root, key, &value))
        return 0;
    if (!value || !json_object_is_type(value, json_type_string))
        return -1;
    if (out)
        *out = json_object_get_string(value);
    return 1;
}

static int ac_discovery_uuid_valid(const char *value, char version)
{
    static const size_t hyphens[] = {8, 13, 18, 23};
    size_t i;
    size_t h = 0;

    if (!value || strlen(value) != 36 || value[14] != version ||
        (value[19] != '8' && value[19] != '9' &&
         value[19] != 'a' && value[19] != 'b'))
        return 0;
    for (i = 0; i < 36; i++) {
        if (h < sizeof(hyphens) / sizeof(hyphens[0]) && i == hyphens[h]) {
            if (value[i] != '-')
                return 0;
            h++;
        } else if (!((value[i] >= '0' && value[i] <= '9') ||
                     (value[i] >= 'a' && value[i] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static int ac_discovery_key_id_valid(const char *value)
{
    size_t i;

    if (!value || strlen(value) != AC_ENROLLMENT_KEY_ID_LEN ||
        strncmp(value, "sha256:", 7) != 0)
        return 0;
    for (i = 7; i < AC_ENROLLMENT_KEY_ID_LEN; i++)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f')))
            return 0;
    return 1;
}

static int ac_discovery_mac_valid(const char *value)
{
    size_t i;

    if (!value || strlen(value) != 17)
        return 0;
    for (i = 0; i < 17; i++) {
        if ((i + 1) % 3 == 0) {
            if (value[i] != ':')
                return 0;
        } else if (!isxdigit((unsigned char)value[i])) {
            return 0;
        }
    }
    return 1;
}

static int ac_discovery_ip_valid(const char *value)
{
    struct in_addr ipv4;
    struct in6_addr ipv6;

    return value && value[0] &&
        (inet_pton(AF_INET, value, &ipv4) == 1 ||
         inet_pton(AF_INET6, value, &ipv6) == 1);
}

int ac_discovery_parse_beacon(const char *payload, size_t payload_len,
                              const char *observed_ip,
                              struct ac_discovery_candidate *out)
{
    struct json_tokener *tokener = NULL;
    struct json_object *root = NULL;
    enum json_tokener_error error;
    const char *magic;
    const char *value;
    struct json_object *port = NULL;
    size_t parse_end;
    int rc = -1;

    if (!payload || !out || !payload_len ||
        payload_len >= AC_DISCOVERY_PAYLOAD_MAX || payload_len > INT_MAX)
        return -1;
    memset(out, 0, sizeof(*out));

    tokener = json_tokener_new();
    if (!tokener)
        return -1;
    json_tokener_set_flags(tokener, JSON_TOKENER_STRICT);
    root = json_tokener_parse_ex(tokener, payload, (int)payload_len);
    error = json_tokener_get_error(tokener);
    parse_end = json_tokener_get_parse_end(tokener);
    while (parse_end < payload_len &&
           isspace((unsigned char)payload[parse_end]))
        parse_end++;
    if (error != json_tokener_success || parse_end != payload_len || !root ||
        !json_object_is_type(root, json_type_object))
        goto done;
    magic = ac_discovery_json_str(root, "magic");
    if (strcmp(magic, AC_DISCOVERY_BEACON_MAGIC) != 0)
        goto done;
    value = ac_discovery_json_str(root, "contract_version");
    if (strcmp(value, AC_CONTRACT_VERSION) != 0)
        goto done;

    value = ac_discovery_json_str(root, "ap_id");
    if (!ac_discovery_uuid_valid(value, '4'))
        goto done;          /* without a valid ap_id there is nothing to key on */
    snprintf(out->ap_id, sizeof(out->ap_id), "%s", value);

    value = ac_discovery_json_str(root, "key_id");
    if (!ac_discovery_key_id_valid(value))
        goto done;
    snprintf(out->key_id, sizeof(out->key_id), "%s", value);
    {
        int present = ac_discovery_json_optional_str(root, "mac", &value);

        if (present < 0)
            goto done;
        if (present && !ac_discovery_mac_valid(value))
            goto done;
        if (present)
            snprintf(out->mac, sizeof(out->mac), "%s", value);
    }
    {
        int present = ac_discovery_json_optional_str(root, "model", &value);

        if (present < 0 ||
            (present && !ac_discovery_text_ok(value,
                                              sizeof(out->model) - 1)))
            goto done;
        if (present)
            snprintf(out->model, sizeof(out->model), "%s", value);
    }
    {
        int present = ac_discovery_json_optional_str(root, "board_name",
                                                     &value);

        if (present < 0 ||
            (present && !ac_discovery_text_ok(
                value, sizeof(out->board_name) - 1)))
            goto done;
        if (present)
            snprintf(out->board_name, sizeof(out->board_name), "%s", value);
    }

    /*
     * The AP may state an address, but we keep it apart from what we
     * observed. A claimed address is useful when the AP sits behind NAT and
     * misleading when it lies, so the UI can show both.
     */
    {
        int present = ac_discovery_json_optional_str(root, "mgmt_ip", &value);

        if (present < 0 || (present && !ac_discovery_ip_valid(value)))
            goto done;
        if (present)
            snprintf(out->claimed_ip, sizeof(out->claimed_ip), "%s", value);
    }
    if (observed_ip && observed_ip[0]) {
        if (!ac_discovery_ip_valid(observed_ip))
            goto done;
        snprintf(out->mgmt_ip, sizeof(out->mgmt_ip), "%s", observed_ip);
    }

    if (json_object_object_get_ex(root, "mgmt_port", &port)) {
        int p = json_object_get_int(port);

        if (!port || !json_object_is_type(port, json_type_int) ||
            p <= 0 || p > 65535)
            goto done;
        out->mgmt_port = (uint16_t)p;
    }
    if (!out->mgmt_port)
        out->mgmt_port = 22;

    {
        int present = ac_discovery_json_optional_str(
            root, "adopted_controller_id", &value);

        if (present < 0 ||
            (present && !ac_discovery_uuid_valid(value, '5')))
            goto done;
        if (present) {
            snprintf(out->adopted_controller_id,
                     sizeof(out->adopted_controller_id), "%s", value);
            out->adopted_elsewhere = 1;
        }
    }

    rc = 0;
done:
    json_object_put(root);
    json_tokener_free(tokener);
    if (rc != 0)
        memset(out, 0, sizeof(*out));
    return rc;
}

int ac_discovery_record(const struct ac_discovery_candidate *candidate)
{
    int64_t now = ac_now_s();
    int i;

    if (!candidate || !candidate->ap_id[0])
        return -1;

    /* An adopted AP is inventory, not a candidate. */
    if (ac_db_ap_is_adopted(candidate->ap_id))
        return 0;

    for (i = 0; i < g_candidate_count; i++) {
        if (strcmp(g_candidates[i].ap_id, candidate->ap_id) != 0)
            continue;
        /* refresh in place, preserving first_seen */
        {
            int64_t first_seen = g_candidates[i].first_seen;
            int same_identity =
                !strcmp(g_candidates[i].key_id, candidate->key_id) &&
                !strcmp(g_candidates[i].mgmt_ip, candidate->mgmt_ip) &&
                g_candidates[i].adopted_elsewhere ==
                    candidate->adopted_elsewhere;
            char ticket[sizeof(g_candidates[i].confirm_ticket)];
            int64_t ticket_expires_at =
                g_candidates[i].confirm_ticket_expires_at;

            memset(ticket, 0, sizeof(ticket));
            if (same_identity)
                memcpy(ticket, g_candidates[i].confirm_ticket,
                       sizeof(ticket));
            else
                ac_discovery_ticket_clear(&g_candidates[i]);

            g_candidates[i] = *candidate;
            g_candidates[i].first_seen = first_seen;
            g_candidates[i].last_seen = now;
            if (same_identity) {
                memcpy(g_candidates[i].confirm_ticket, ticket,
                       sizeof(ticket));
                g_candidates[i].confirm_ticket_expires_at =
                    ticket_expires_at;
            }
            OPENSSL_cleanse(ticket, sizeof(ticket));
        }
        return 0;
    }

    if (g_candidate_count >= AC_DISCOVERY_MAX_CANDIDATES) {
        /*
         * Full table: drop the stalest entry rather than the newest arrival,
         * so a flood of bogus ap_ids cannot permanently lock out a real AP
         * that is still announcing.
         */
        int oldest = 0;

        for (i = 1; i < g_candidate_count; i++)
            if (g_candidates[i].last_seen < g_candidates[oldest].last_seen)
                oldest = i;
        ac_discovery_ticket_clear(&g_candidates[oldest]);
        g_candidates[oldest] = *candidate;
        g_candidates[oldest].first_seen = now;
        g_candidates[oldest].last_seen = now;
        return 0;
    }

    g_candidates[g_candidate_count] = *candidate;
    g_candidates[g_candidate_count].first_seen = now;
    g_candidates[g_candidate_count].last_seen = now;
    g_candidate_count++;
    return 0;
}

void ac_discovery_expire(int64_t now)
{
    int i = 0;

    while (i < g_candidate_count) {
        if (now - g_candidates[i].last_seen >
                AC_DISCOVERY_CANDIDATE_TTL_SECONDS ||
            ac_db_ap_is_adopted(g_candidates[i].ap_id)) {
            ac_discovery_ticket_clear(&g_candidates[i]);
            g_candidates[i] = g_candidates[g_candidate_count - 1];
            memset(&g_candidates[g_candidate_count - 1], 0,
                   sizeof(g_candidates[g_candidate_count - 1]));
            g_candidate_count--;
            continue;
        }
        i++;
    }
}

static void ac_discovery_beacon_read(struct uloop_fd *fd, unsigned int events)
{
    char buffer[AC_DISCOVERY_PAYLOAD_MAX];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    ssize_t length;

    (void)events;
    for (;;) {
        char source[INET_ADDRSTRLEN] = { 0 };
        struct ac_discovery_candidate candidate;

        length = recvfrom(fd->fd, buffer, sizeof(buffer) - 1, MSG_DONTWAIT,
                          (struct sockaddr *)&from, &from_len);
        if (length <= 0)
            break;
        buffer[length] = '\0';
        if (!inet_ntop(AF_INET, &from.sin_addr, source, sizeof(source)))
            continue;
        if (ac_discovery_parse_beacon(buffer, (size_t)length, source,
                                      &candidate) == 0)
            ac_discovery_record(&candidate);
        /* Malformed beacons are ignored silently; logging every one would
         * hand any host on the segment a log-flood primitive. */
    }
}

int ac_discovery_start(void)
{
    struct sockaddr_in address;
    int fd;
    int reuse = 1;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        ac_discovery_set_reason("discovery_socket_failed");
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0) {
        close(fd);
        ac_discovery_set_reason("discovery_sockopt_failed");
        return -1;
    }
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(AC_DISCOVERY_BEACON_PORT);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        ac_discovery_set_reason("discovery_bind_failed");
        return -1;
    }

    g_beacon_fd.fd = fd;
    g_beacon_fd.cb = ac_discovery_beacon_read;
    if (uloop_fd_add(&g_beacon_fd, ULOOP_READ) != 0) {
        close(fd);
        g_beacon_fd.fd = -1;
        ac_discovery_set_reason("discovery_uloop_failed");
        return -1;
    }
    g_available = 1;
    ac_discovery_set_reason("listening");
    return 0;
}

void ac_discovery_stop(void)
{
    int i;

    if (g_beacon_fd.fd >= 0) {
        uloop_fd_delete(&g_beacon_fd);
        close(g_beacon_fd.fd);
        g_beacon_fd.fd = -1;
    }
    for (i = 0; i < g_candidate_count; i++)
        ac_discovery_ticket_clear(&g_candidates[i]);
    g_available = 0;
    g_candidate_count = 0;
    ac_discovery_set_reason("discovery_stopped");
}

int ac_discovery_candidate_get(const char *ap_id,
                               struct ac_discovery_candidate *out)
{
    int i;

    if (!ap_id || !out)
        return -1;
    ac_discovery_expire(ac_now_s());
    for (i = 0; i < g_candidate_count; i++) {
        if (strcmp(g_candidates[i].ap_id, ap_id) != 0)
            continue;
        *out = g_candidates[i];
        return 0;
    }
    return -1;
}

int ac_discovery_ticket_consume(const char *ap_id, const char *ticket)
{
    int i;

    if (!ap_id || !ticket || !ticket[0])
        return -1;
    for (i = 0; i < g_candidate_count; i++) {
        if (strcmp(g_candidates[i].ap_id, ap_id) != 0 ||
            strcmp(g_candidates[i].confirm_ticket, ticket) != 0)
            continue;
        ac_discovery_ticket_clear(&g_candidates[i]);
        return 0;
    }
    return -1;
}

int ac_discovery_controller_host(const struct ac_discovery_candidate *candidate,
                                 char *out, size_t out_size)
{
    struct sockaddr_in peer;
    struct sockaddr_in local;
    socklen_t local_len = sizeof(local);
    int fd;

    if (!candidate || !candidate->mgmt_ip[0] || !out || out_size < 8)
        return -1;
    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons(candidate->mgmt_port ? candidate->mgmt_port : 9);
    if (inet_pton(AF_INET, candidate->mgmt_ip, &peer.sin_addr) != 1)
        return -1;
    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer)) != 0 ||
        getsockname(fd, (struct sockaddr *)&local, &local_len) != 0 ||
        !inet_ntop(AF_INET, &local.sin_addr, out, out_size)) {
        close(fd);
        return -1;
    }
    close(fd);
    return strcmp(out, "0.0.0.0") == 0 ? -1 : 0;
}

struct json_object *ac_discovery_list_json(void)
{
    struct json_object *root = json_object_new_object();
    struct json_object *items = json_object_new_array();
    int64_t now = ac_now_s();
    int i;

    ac_discovery_expire(now);

    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "contract_version",
                           json_object_new_string(AC_CONTRACT_VERSION));
    json_object_object_add(root, "source",
                           json_object_new_string(AC_SERVICE_NAME));
    json_object_object_add(root, "observed_at", json_object_new_int64(now));
    json_object_object_add(root, "available",
                           json_object_new_boolean(g_available));
    json_object_object_add(root, "reason", json_object_new_string(g_reason));
    json_object_object_add(root, "discovery_method",
                           json_object_new_string("ap_initiated_beacon"));

    for (i = 0; i < g_candidate_count; i++) {
        struct json_object *item = json_object_new_object();
        struct ac_discovery_candidate *c = &g_candidates[i];
        char controller_host[INET_ADDRSTRLEN] = { 0 };
        int confirm_ready = ac_transport_bootstrap_ready() &&
            !c->adopted_elsewhere && c->key_id[0] &&
            !ac_db_binding_pending(c->ap_id, NULL) &&
            ac_discovery_controller_host(c, controller_host,
                                         sizeof(controller_host)) == 0 &&
            ac_discovery_ticket_issue(c, now) == 0;

        json_object_object_add(item, "ap_id", json_object_new_string(c->ap_id));
        json_object_object_add(item, "key_id",
                               json_object_new_string(c->key_id));
        json_object_object_add(item, "mac", json_object_new_string(c->mac));
        json_object_object_add(item, "model", json_object_new_string(c->model));
        json_object_object_add(item, "board_name",
                               json_object_new_string(c->board_name));
        json_object_object_add(item, "mgmt_ip",
                               json_object_new_string(c->mgmt_ip));
        json_object_object_add(item, "claimed_ip",
                               json_object_new_string(c->claimed_ip));
        json_object_object_add(item, "mgmt_port",
                               json_object_new_int(c->mgmt_port));
        json_object_object_add(item, "first_seen",
                               json_object_new_int64(c->first_seen));
        json_object_object_add(item, "last_seen",
                               json_object_new_int64(c->last_seen));
        json_object_object_add(item, "adopted_elsewhere",
                               json_object_new_boolean(c->adopted_elsewhere));
        json_object_object_add(item, "adopted_controller_id",
                               json_object_new_string(
                                   c->adopted_controller_id));
        /*
         * Stated plainly in the payload so no UI can mistake a candidate for
         * something trustworthy: discovery never implies adoption.
         */
        json_object_object_add(item, "trusted", json_object_new_boolean(0));
        json_object_object_add(item, "adoption_requires",
                               json_object_new_string(
                                   "operator_fingerprint_confirmation_or_pairing_code"));
        if (confirm_ready) {
            struct json_object *request = json_object_new_object();
            struct json_object *body = json_object_new_object();

            json_object_object_add(body, "ap_id",
                                   json_object_new_string(c->ap_id));
            json_object_object_add(body, "key_fingerprint",
                                   json_object_new_string(c->key_id));
            json_object_object_add(body, "ticket",
                                   json_object_new_string(c->confirm_ticket));
            json_object_object_add(body, "ticket_expires_at",
                                   json_object_new_int64(
                                       c->confirm_ticket_expires_at));
            json_object_object_add(body, "controller_id",
                                   json_object_new_string(
                                       ac_transport_controller_id()));
            json_object_object_add(body, "site_id",
                                   json_object_new_string("default"));
            json_object_object_add(request, "api",
                                   json_object_new_string(
                                       "/api/v1/ac/discovery/confirm"));
            json_object_object_add(request, "method",
                                   json_object_new_string("POST"));
            json_object_object_add(request, "ubus_method",
                                   json_object_new_string(
                                       "discovery_confirm"));
            json_object_object_add(request, "body", body);
            json_object_object_add(item, "confirm_request", request);
        }
        json_object_array_add(items, item);
    }
    json_object_object_add(root, "confirm_available",
                           json_object_new_boolean(
                               ac_transport_bootstrap_ready()));
    json_object_object_add(root, "confirm_api",
                           json_object_new_string(
                               "/api/v1/ac/discovery/confirm"));
    json_object_object_add(root, "items", items);
    json_object_object_add(root, "count",
                           json_object_new_int(g_candidate_count));
    return root;
}

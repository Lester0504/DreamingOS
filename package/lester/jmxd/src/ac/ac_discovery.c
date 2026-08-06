// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Passive AP discovery for the controller. See ac_discovery.h for why this
 * listens instead of probing.
 */
#include "ac_discovery.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <libubox/uloop.h>

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

int ac_discovery_parse_beacon(const char *payload, size_t payload_len,
                              const char *observed_ip,
                              struct ac_discovery_candidate *out)
{
    struct json_object *root;
    const char *magic;
    const char *value;
    struct json_object *port = NULL;

    if (!payload || !out || !payload_len ||
        payload_len >= AC_DISCOVERY_PAYLOAD_MAX)
        return -1;
    memset(out, 0, sizeof(*out));

    root = json_tokener_parse(payload);
    if (!root || !json_object_is_type(root, json_type_object)) {
        json_object_put(root);
        return -1;
    }
    magic = ac_discovery_json_str(root, "magic");
    if (strcmp(magic, AC_DISCOVERY_BEACON_MAGIC) != 0) {
        json_object_put(root);
        return -1;
    }

    value = ac_discovery_json_str(root, "ap_id");
    if (strlen(value) != 36 || !ac_discovery_text_ok(value, 36)) {
        json_object_put(root);
        return -1;          /* without an ap_id there is nothing to key on */
    }
    snprintf(out->ap_id, sizeof(out->ap_id), "%s", value);

    value = ac_discovery_json_str(root, "key_id");
    if (ac_discovery_text_ok(value, sizeof(out->key_id) - 1))
        snprintf(out->key_id, sizeof(out->key_id), "%s", value);
    value = ac_discovery_json_str(root, "mac");
    if (ac_discovery_text_ok(value, sizeof(out->mac) - 1))
        snprintf(out->mac, sizeof(out->mac), "%s", value);
    value = ac_discovery_json_str(root, "model");
    if (ac_discovery_text_ok(value, sizeof(out->model) - 1))
        snprintf(out->model, sizeof(out->model), "%s", value);
    value = ac_discovery_json_str(root, "board_name");
    if (ac_discovery_text_ok(value, sizeof(out->board_name) - 1))
        snprintf(out->board_name, sizeof(out->board_name), "%s", value);

    /*
     * The AP may state an address, but we keep it apart from what we
     * observed. A claimed address is useful when the AP sits behind NAT and
     * misleading when it lies, so the UI can show both.
     */
    value = ac_discovery_json_str(root, "mgmt_ip");
    if (ac_discovery_text_ok(value, sizeof(out->claimed_ip) - 1))
        snprintf(out->claimed_ip, sizeof(out->claimed_ip), "%s", value);
    if (observed_ip && observed_ip[0])
        snprintf(out->mgmt_ip, sizeof(out->mgmt_ip), "%s", observed_ip);

    if (json_object_object_get_ex(root, "mgmt_port", &port) && port &&
        json_object_is_type(port, json_type_int)) {
        int p = json_object_get_int(port);

        if (p > 0 && p <= 65535)
            out->mgmt_port = (uint16_t)p;
    }
    if (!out->mgmt_port)
        out->mgmt_port = 22;

    value = ac_discovery_json_str(root, "adopted_controller_id");
    if (strlen(value) == 36 && ac_discovery_text_ok(value, 36)) {
        snprintf(out->adopted_controller_id,
                 sizeof(out->adopted_controller_id), "%s", value);
        out->adopted_elsewhere = 1;
    }

    json_object_put(root);
    return 0;
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

            g_candidates[i] = *candidate;
            g_candidates[i].first_seen = first_seen;
            g_candidates[i].last_seen = now;
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
                AC_DISCOVERY_CANDIDATE_TTL_SECONDS) {
            g_candidates[i] = g_candidates[g_candidate_count - 1];
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
    if (g_beacon_fd.fd >= 0) {
        uloop_fd_delete(&g_beacon_fd);
        close(g_beacon_fd.fd);
        g_beacon_fd.fd = -1;
    }
    g_available = 0;
    g_candidate_count = 0;
    ac_discovery_set_reason("discovery_stopped");
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
        const struct ac_discovery_candidate *c = &g_candidates[i];

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
        json_object_array_add(items, item);
    }
    json_object_object_add(root, "items", items);
    json_object_object_add(root, "count",
                           json_object_new_int(g_candidate_count));
    return root;
}

// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
/* DreamingWrt client identity collectors: mDNS, SSDP, DHCP lease evidence. */
#include "jmx_identity_collector.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>
#include <libubox/uloop.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

#include "jmx.h"
#include "jmx_huginn.h"

#define JMX_ID_BUF 2048
#define SSDP_DISCOVERY_INTERVAL_SEC 120
#define ROUTED_GATEWAY_PROBE_INTERVAL_SEC 300
#define LAN_SERVICE_PROBE_INTERVAL_SEC 300
#define IDENTITY_SIGNAL_DEDUPE_SLOTS 512
#define IDENTITY_SIGNAL_DEDUPE_SEC 60

typedef struct identity_signal_dedupe_entry {
    uint64_t fingerprint;
    time_t sent_at;
} identity_signal_dedupe_entry_t;

static struct uloop_fd g_mdns_fd = { .fd = -1 };
static struct uloop_fd g_ssdp_fd = { .fd = -1 };
static struct uloop_fd g_ssdp_query_fd = { .fd = -1 };
static struct uloop_fd g_dhcp_fd = { .fd = -1 };
static struct ubus_context *g_identity_ubus = NULL;
static time_t g_next_ssdp_discovery_at = 0;
static time_t g_next_routed_gateway_probe_at = 0;
static time_t g_next_lan_service_probe_at = 0;
static identity_signal_dedupe_entry_t
    g_identity_signal_dedupe[IDENTITY_SIGNAL_DEDUPE_SLOTS];
static unsigned int g_identity_signal_dedupe_cursor;
static int g_collector_initialized;

static uint64_t identity_signal_hash_part(uint64_t hash, const char *value)
{
    const unsigned char *p = (const unsigned char *)(value ? value : "");

    while (*p) {
        hash ^= *p++;
        hash *= UINT64_C(1099511628211);
    }
    hash ^= 0xff;
    hash *= UINT64_C(1099511628211);
    return hash;
}

static uint64_t identity_signal_fingerprint(const char *address,
                                            const char *source,
                                            const char *key,
                                            const char *value,
                                            int confidence,
                                            const char *raw)
{
    uint64_t hash = UINT64_C(1469598103934665603);
    char confidence_text[24];

    snprintf(confidence_text, sizeof(confidence_text), "%d", confidence);
    hash = identity_signal_hash_part(hash, address);
    hash = identity_signal_hash_part(hash, source);
    hash = identity_signal_hash_part(hash, key);
    hash = identity_signal_hash_part(hash, value);
    hash = identity_signal_hash_part(hash, confidence_text);
    return identity_signal_hash_part(hash, raw);
}

static int identity_signal_recent(uint64_t fingerprint, time_t now)
{
    unsigned int i;

    if (!fingerprint)
        return 0;
    for (i = 0; i < IDENTITY_SIGNAL_DEDUPE_SLOTS; i++) {
        identity_signal_dedupe_entry_t *entry = &g_identity_signal_dedupe[i];

        if (entry->fingerprint != fingerprint)
            continue;
        return entry->sent_at > 0 && now >= entry->sent_at &&
               now - entry->sent_at < IDENTITY_SIGNAL_DEDUPE_SEC;
    }
    return 0;
}

static void identity_signal_remember(uint64_t fingerprint, time_t now)
{
    identity_signal_dedupe_entry_t *entry;
    unsigned int i;

    if (!fingerprint)
        return;
    for (i = 0; i < IDENTITY_SIGNAL_DEDUPE_SLOTS; i++) {
        entry = &g_identity_signal_dedupe[i];
        if (entry->fingerprint == fingerprint) {
            entry->sent_at = now;
            return;
        }
    }
    entry = &g_identity_signal_dedupe[
        g_identity_signal_dedupe_cursor++ % IDENTITY_SIGNAL_DEDUPE_SLOTS];
    entry->fingerprint = fingerprint;
    entry->sent_at = now;
}

static void identity_ubus_close(void)
{
    if (g_identity_ubus) {
        ubus_free(g_identity_ubus);
        g_identity_ubus = NULL;
    }
}

static int identity_ubus_ensure(void)
{
    if (g_identity_ubus)
        return 0;
    g_identity_ubus = ubus_connect(NULL);
    return g_identity_ubus ? 0 : -1;
}

static int identity_ubus_call(const char *method, struct json_object *payload)
{
    uint32_t id;
    struct blob_buf b = {0};
    const char *json;
    int rc;

    if (!method || !payload || identity_ubus_ensure() != 0)
        return -1;
    if (ubus_lookup_id(g_identity_ubus, "dreamingwrt", &id) != UBUS_STATUS_OK) {
        identity_ubus_close();
        return -1;
    }

    blob_buf_init(&b, 0);
    json = json_object_to_json_string(payload);
    if (json)
        blobmsg_add_json_from_string(&b, json);
    rc = ubus_invoke(g_identity_ubus, id, method, b.head, NULL, NULL, 1000);
    blob_buf_free(&b);
    if (rc != UBUS_STATUS_OK) {
        identity_ubus_close();
        return -1;
    }
    return 0;
}

static int identity_observe_signal(const char *mac, const char *source, const char *key,
                                   const char *value, int confidence, const char *raw)
{
    struct json_object *o;
    int rc;
    time_t now = time(NULL);
    uint64_t fingerprint;

    if (!mac || !mac[0] || !source || !source[0] || !key || !key[0] || !value || !value[0])
        return -1;
    fingerprint = identity_signal_fingerprint(mac, source, key, value,
                                              confidence, raw);
    if (identity_signal_recent(fingerprint, now))
        return 0;
    o = json_object_new_object();
    json_object_object_add(o, "mac", json_object_new_string(mac));
    json_object_object_add(o, "source", json_object_new_string(source));
    json_object_object_add(o, "key", json_object_new_string(key));
    json_object_object_add(o, "value", json_object_new_string(value));
    json_object_object_add(o, "confidence", json_object_new_int(confidence));
    if (raw && raw[0])
        json_object_object_add(o, "raw", json_object_new_string(raw));
    rc = identity_ubus_call("identity_signal", o);
    json_object_put(o);
    if (rc == 0)
        identity_signal_remember(fingerprint, now);
    return rc;
}

static int identity_observe_signal_by_ip(const char *ip, const char *source, const char *key,
                                         const char *value, int confidence, const char *raw)
{
    struct json_object *o;
    int rc;
    time_t now = time(NULL);
    uint64_t fingerprint;

    if (!ip || !ip[0] || !source || !source[0] || !key || !key[0] || !value || !value[0])
        return -1;
    fingerprint = identity_signal_fingerprint(ip, source, key, value,
                                              confidence, raw);
    if (identity_signal_recent(fingerprint, now))
        return 0;
    o = json_object_new_object();
    json_object_object_add(o, "ip", json_object_new_string(ip));
    json_object_object_add(o, "source", json_object_new_string(source));
    json_object_object_add(o, "key", json_object_new_string(key));
    json_object_object_add(o, "value", json_object_new_string(value));
    json_object_object_add(o, "confidence", json_object_new_int(confidence));
    if (raw && raw[0])
        json_object_object_add(o, "raw", json_object_new_string(raw));
    rc = identity_ubus_call("identity_signal_by_ip", o);
    json_object_put(o);
    if (rc == 0)
        identity_signal_remember(fingerprint, now);
    return rc;
}

static int identity_observe_network_state_ex(const char *mac, const char *ip, const char *iface,
                                             const char *network, const char *parent_mac,
                                             const char *parent_id, const char *port,
                                             const char *link_type, const char *link_speed,
                                             int online)
{
    struct json_object *o;
    int rc;

    if (!mac || !mac[0] || !ip || !ip[0])
        return -1;
    o = json_object_new_object();
    json_object_object_add(o, "mac", json_object_new_string(mac));
    json_object_object_add(o, "ip", json_object_new_string(ip));
    json_object_object_add(o, "iface", json_object_new_string(iface && iface[0] ? iface : ""));
    json_object_object_add(o, "network", json_object_new_string(network && network[0] ? network : ""));
    json_object_object_add(o, "parent_mac", json_object_new_string(parent_mac && parent_mac[0] ? parent_mac : ""));
    json_object_object_add(o, "parent_id", json_object_new_string(parent_id && parent_id[0] ? parent_id : ""));
    json_object_object_add(o, "port", json_object_new_string(port && port[0] ? port : ""));
    json_object_object_add(o, "link_type", json_object_new_string(link_type && link_type[0] ? link_type : "wired"));
    json_object_object_add(o, "link_speed", json_object_new_string(link_speed && link_speed[0] ? link_speed : ""));
    json_object_object_add(o, "online", json_object_new_int(online ? 1 : 0));
    rc = identity_ubus_call("identity_network_state", o);
    json_object_put(o);
    return rc;
}

static int identity_observe_network_state(const char *mac, const char *ip, const char *iface,
                                          const char *network, int online)
{
    return identity_observe_network_state_ex(mac, ip, iface, network, "", "", "",
                                             "wired", "", online);
}

static void trim_crlf(char *s)
{
    size_t n;
    if (!s) return;
    while (*s && isspace((unsigned char)*s)) memmove(s, s + 1, strlen(s));
    n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
}

static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int make_mcast_socket(const char *group, int port)
{
    int fd, on = 1;
    struct sockaddr_in addr;
    struct ip_mreq mreq;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr.s_addr = inet_addr(group);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    if (set_nonblock(fd) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

static int make_udp_query_socket(void)
{
    int fd;
    int on = 1;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    if (set_nonblock(fd) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

/* Pending signal buffer: signals received before IP→MAC mapping existed.
 * Stored as a ring buffer; replayed after ARP table populates mappings. */
#define PENDING_SIG_MAX 128
typedef struct {
    char ip[64];
    char source[32];
    char key[64];
    char value[256];
    int confidence;
    int used;
} pending_signal_t;
static pending_signal_t g_pending_sigs[PENDING_SIG_MAX];
static int g_pending_next = 0;
static int g_pending_count = 0;

#define BRIDGE_LINK_MAX 64

typedef struct {
    char mac[32];
    char ifname[32];
    char port_no[32];
    char link_speed[32];
} bridge_link_t;

static int read_first_line(const char *path, char *out, size_t out_len)
{
    FILE *f;
    if (!path || !out || out_len == 0)
        return -1;
    out[0] = '\0';
    f = fopen(path, "r");
    if (!f)
        return -1;
    if (!fgets(out, out_len, f)) {
        fclose(f);
        out[0] = '\0';
        return -1;
    }
    fclose(f);
    trim_crlf(out);
    return out[0] ? 0 : -1;
}

static void lowercase_copy(char *dst, size_t dst_len, const char *src)
{
    size_t i;
    if (!dst || dst_len == 0)
        return;
    dst[0] = '\0';
    if (!src)
        return;
    for (i = 0; src[i] && i < dst_len - 1; i++)
        dst[i] = (char)tolower((unsigned char)src[i]);
    dst[i] = '\0';
}

static int normalize_bridge_port_no(const char *raw, char *out, size_t out_len)
{
    char *end = NULL;
    unsigned long v;

    if (!raw || !raw[0] || !out || out_len == 0)
        return -1;
    errno = 0;
    v = strtoul(raw, &end, 0);
    if (errno || end == raw)
        return -1;
    while (end && *end) {
        if (!isspace((unsigned char)*end))
            return -1;
        end++;
    }
    snprintf(out, out_len, "%lu", v);
    return out[0] ? 0 : -1;
}

/* struct __fdb_entry record size exposed by /sys/class/net/<br>/brforward. */
#define JMX_FDB_ENTRY_SIZE 16
#define JMX_FDB_MAC_LEN 6

/* Reject anything that cannot be a kernel interface name before it reaches a
 * /sys path, so a caller can never walk outside /sys/class/net/<name>/. */
static int jmx_bridge_name_ok(const char *name)
{
    size_t i;

    if (!name || !name[0])
        return 0;
    if (strlen(name) >= IFNAMSIZ)
        return 0;
    if (!strcmp(name, ".") || !strcmp(name, ".."))
        return 0;
    for (i = 0; name[i]; i++) {
        unsigned char c = (unsigned char)name[i];

        if (c == '/' || c == '\\' || isspace(c) || !isprint(c))
            return 0;
    }
    return 1;
}

/* Strict aa:bb:cc:dd:ee:ff parse into raw bytes; no truncation, no partials. */
static int jmx_parse_mac_bytes(const char *mac, unsigned char out[JMX_FDB_MAC_LEN])
{
    unsigned int v[JMX_FDB_MAC_LEN];
    char tail = '\0';
    int n;
    int i;

    if (!mac || !out)
        return -1;
    n = sscanf(mac, "%2x:%2x:%2x:%2x:%2x:%2x%c",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &tail);
    if (n != JMX_FDB_MAC_LEN)
        return -1;
    for (i = 0; i < JMX_FDB_MAC_LEN; i++) {
        if (v[i] > 0xff)
            return -1;
        out[i] = (unsigned char)v[i];
    }
    return 0;
}

static int load_bridge_links(const char *bridge, bridge_link_t *links, int max_links,
                             char *bridge_mac, size_t bridge_mac_len)
{
    char br_path[128];
    DIR *dir;
    struct dirent *de;
    int count = 0;

    if (bridge_mac && bridge_mac_len)
        bridge_mac[0] = '\0';
    if (!bridge || !links || max_links <= 0)
        return 0;
    snprintf(br_path, sizeof(br_path), "/sys/class/net/%s/address", bridge);
    if (bridge_mac && bridge_mac_len) {
        char raw[32];
        if (read_first_line(br_path, raw, sizeof(raw)) == 0)
            lowercase_copy(bridge_mac, bridge_mac_len, raw);
    }
    snprintf(br_path, sizeof(br_path), "/sys/class/net/%s/brif", bridge);
    dir = opendir(br_path);
    if (!dir)
        return 0;
    while ((de = readdir(dir)) != NULL && count < max_links) {
        char path[256];
        char raw[64];
        bridge_link_t *l;

        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;
        l = &links[count];
        memset(l, 0, sizeof(*l));
        snprintf(l->ifname, sizeof(l->ifname), "%s", de->d_name);
        snprintf(path, sizeof(path), "/sys/class/net/%s/address", de->d_name);
        if (read_first_line(path, raw, sizeof(raw)) == 0)
            lowercase_copy(l->mac, sizeof(l->mac), raw);
        snprintf(path, sizeof(path), "/sys/class/net/%s/brif/%s/port_no", bridge, de->d_name);
        if (read_first_line(path, raw, sizeof(raw)) != 0) {
            snprintf(path, sizeof(path), "/sys/class/net/%s/brport/port_no", de->d_name);
            raw[0] = '\0';
        }
        if (read_first_line(path, raw, sizeof(raw)) == 0)
            normalize_bridge_port_no(raw, l->port_no, sizeof(l->port_no));
        snprintf(path, sizeof(path), "/sys/class/net/%s/speed", de->d_name);
        if (read_first_line(path, raw, sizeof(raw)) == 0 && strcmp(raw, "-1"))
            snprintf(l->link_speed, sizeof(l->link_speed), "%s Mbps", raw);
        count++;
    }
    closedir(dir);
    return count;
}

static const bridge_link_t *find_bridge_link_by_port_no(const bridge_link_t *links, int link_count,
                                                        const char *port_no)
{
    int i;
    char want[32];
    if (!links || !port_no || !port_no[0])
        return NULL;
    if (normalize_bridge_port_no(port_no, want, sizeof(want)) != 0)
        snprintf(want, sizeof(want), "%s", port_no);
    for (i = 0; i < link_count; i++) {
        if (links[i].port_no[0] && !strcasecmp(links[i].port_no, want))
            return &links[i];
    }
    return NULL;
}

static int lookup_bridge_fdb_port(const char *bridge, const char *mac, char *port_no, size_t port_len)
{
    /*
     * U-15: read the kernel bridge forwarding database directly instead of
     * shelling out to "brctl showmacs". /sys/class/net/<bridge>/brforward is
     * the exact source brctl parses, so this removes a root shell hop plus a
     * runtime dependency on BusyBox brctl without changing semantics.
     *
     * Each record is a struct __fdb_entry (16 bytes):
     *   [0..5]  mac_addr
     *   [6]     port_no
     *   [7]     is_local
     *   [8..11] ageing_timer_value
     *   [12]    port_hi
     *   [13]    pad0
     *   [14..15] unused
     */
    unsigned char entry[JMX_FDB_ENTRY_SIZE];
    char path[128];
    unsigned char want[JMX_FDB_MAC_LEN];
    int fd;
    int rc = -1;

    if (!bridge || !mac || !port_no || port_len == 0)
        return -1;
    port_no[0] = '\0';
    if (!jmx_bridge_name_ok(bridge))
        return -1;
    if (jmx_parse_mac_bytes(mac, want) != 0)
        return -1;
    if ((size_t)snprintf(path, sizeof(path), "/sys/class/net/%s/brforward",
                         bridge) >= sizeof(path))
        return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    for (;;) {
        size_t got = 0;
        unsigned int port;

        while (got < sizeof(entry)) {
            ssize_t n = read(fd, entry + got, sizeof(entry) - got);

            if (n < 0) {
                if (errno == EINTR)
                    continue;
                close(fd);
                return -1;
            }
            if (n == 0)
                break;
            got += (size_t)n;
        }
        if (got == 0)
            break;
        if (got < sizeof(entry))
            break;
        if (entry[7])
            continue;
        if (memcmp(entry, want, JMX_FDB_MAC_LEN))
            continue;
        port = (unsigned int)entry[6] | ((unsigned int)entry[12] << 8);
        if ((size_t)snprintf(port_no, port_len, "%u", port) >= port_len) {
            port_no[0] = '\0';
            break;
        }
        rc = 0;
        break;
    }
    close(fd);
    return rc;
}

static void observe_lan_bridge_state(const char *mac, const char *ip, const char *fallback_iface)
{
    bridge_link_t links[BRIDGE_LINK_MAX];
    char bridge_mac[32] = {0};
    char port_no[32] = {0};
    const bridge_link_t *link = NULL;
    int link_count;

    if (!mac || !mac[0] || !ip || !ip[0])
        return;
    link_count = load_bridge_links("br-lan", links, BRIDGE_LINK_MAX,
                                   bridge_mac, sizeof(bridge_mac));
    if (lookup_bridge_fdb_port("br-lan", mac, port_no, sizeof(port_no)) == 0)
        link = find_bridge_link_by_port_no(links, link_count, port_no);
    identity_observe_network_state_ex(mac, ip,
                                      fallback_iface && fallback_iface[0] ? fallback_iface : "br-lan",
                                      "lan",
                                      bridge_mac,
                                      "br-lan",
                                      link && link->ifname[0] ? link->ifname : "",
                                      "wired",
                                      link ? link->link_speed : "",
                                      1);
}


static void store_pending_signal(const char *ip, const char *source, const char *key, const char *value, int confidence)
{
    if (!ip || !source || !key || !value) return;
    pending_signal_t *p = &g_pending_sigs[g_pending_next];
    snprintf(p->ip, sizeof(p->ip), "%s", ip);
    snprintf(p->source, sizeof(p->source), "%s", source);
    snprintf(p->key, sizeof(p->key), "%s", key);
    snprintf(p->value, sizeof(p->value), "%s", value);
    p->confidence = confidence;
    p->used = 1;
    g_pending_next = (g_pending_next + 1) % PENDING_SIG_MAX;
    if (g_pending_count < PENDING_SIG_MAX)
        g_pending_count++;
}

static void flush_pending_ip_signals(void)
{
    int i, flushed = 0;
    for (i = 0; i < g_pending_count; i++) {
        pending_signal_t *p = &g_pending_sigs[i];
        if (!p->used || !p->ip[0]) continue;
        int rc = identity_observe_signal_by_ip(p->ip, p->source, p->key, p->value, p->confidence, "");
        if (rc == 0) { flushed++; p->used = 0; }
    }
    if (flushed > 0) LOG_INFO("identity: flushed pending signals");
}


static void observe_ip(const char *ip, const char *source, const char *key, const char *value, int conf, const char *raw)
{
    if (!ip || !ip[0] || !value || !value[0]) return;
    if (identity_observe_signal_by_ip(ip, source, key, value, conf, raw ? raw : "") != 0)
        store_pending_signal(ip, source, key, value, conf);
}

static void scan_printable_tokens(const unsigned char *buf, int len, const char *ip, const char *source)
{
    char tok[256];
    int n = 0, i;
    for (i = 0; i <= len; i++) {
        int c = (i < len) ? buf[i] : 0;
        if (i < len && c >= 32 && c <= 126 && n < (int)sizeof(tok) - 1) {
            tok[n++] = (char)c;
            continue;
        }
        if (n >= 3) {
            tok[n] = '\0';
            if (strstr(tok, "model=")) observe_ip(ip, source, "model", strchr(tok, '=') + 1, 90, tok);
            else if (strstr(tok, "_device-info._tcp")) observe_ip(ip, source, "service", "_device-info._tcp", 85, tok);
            else if (strstr(tok, "_airplay._tcp")) observe_ip(ip, source, "service", "_airplay._tcp", 75, tok);
            else if (strstr(tok, "_homekit._tcp")) observe_ip(ip, source, "service", "_homekit._tcp", 75, tok);
            else if (strstr(tok, "_googlecast._tcp")) observe_ip(ip, source, "service", "_googlecast._tcp", 75, tok);
            else if (strstr(tok, "_printer._tcp")) observe_ip(ip, source, "service", "_printer._tcp", 75, tok);
        }
        n = 0;
    }
}

static void mdns_cb(struct uloop_fd *u, unsigned int events)
{
    unsigned char buf[JMX_ID_BUF];
    struct sockaddr_in from;
    socklen_t flen = sizeof(from);
    char ip[INET_ADDRSTRLEN];
    int n;
    (void)events;
    while ((n = recvfrom(u->fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen)) > 0) {
        inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));
        scan_printable_tokens(buf, n, ip, "mdns");
    }
}

static char *header_value(char *msg, const char *name)
{
    size_t nl = strlen(name);
    char *p = msg;
    while (p && *p) {
        char *e = strstr(p, "\r\n");
        if (e) *e = '\0';
        if (!strncasecmp(p, name, nl) && p[nl] == ':') {
            char *v = p + nl + 1;
            trim_crlf(v);
            return v;
        }
        if (!e) break;
        *e = '\r';
        p = e + 2;
    }
    return NULL;
}


static int is_private_ipv4(const char *ip)
{
    unsigned int a,b,c,d;
    if (!ip || sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    if (a == 10) return 1;
    if (a == 172 && b >= 16 && b <= 31) return 1;
    if (a == 192 && b == 168) return 1;
    if (a == 169 && b == 254) return 1;
    return 0;
}

static int is_private_ipv4_addr(struct in_addr addr)
{
    uint32_t a = ntohl(addr.s_addr);
    uint8_t o1 = (uint8_t)((a >> 24) & 0xff);
    uint8_t o2 = (uint8_t)((a >> 16) & 0xff);

    if (o1 == 10)
        return 1;
    if (o1 == 172 && o2 >= 16 && o2 <= 31)
        return 1;
    if (o1 == 192 && o2 == 168)
        return 1;
    if (o1 == 169 && o2 == 254)
        return 1;
    return 0;
}

static int http_fetch_small(const char *host, int port, const char *path, char *out, size_t out_len);
static int http_status_code(const char *resp);
static void lower_ascii_text(char *dst, size_t dst_len, const char *src);

static int mac_is_virtual_nic_prefix(const char *mac)
{
    char m[32];
    if (!mac || !mac[0])
        return 0;
    lower_ascii_text(m, sizeof(m), mac);
    return !strncmp(m, "bc:24:11", 8) ||  /* Proxmox/QEMU */
           !strncmp(m, "52:54:00", 8) ||  /* QEMU/KVM */
           !strncmp(m, "00:0c:29", 8) ||  /* VMware */
           !strncmp(m, "00:50:56", 8) ||  /* VMware */
           !strncmp(m, "00:05:69", 8) ||  /* VMware */
           !strncmp(m, "08:00:27", 8) ||  /* VirtualBox */
           !strncmp(m, "00:15:5d", 8);    /* Hyper-V */
}

static int tcp_probe_port(const char *ip, int port, char *banner, size_t banner_len)
{
    int fd, flags, rc;
    struct sockaddr_in sa;
    fd_set wfds;
    struct timeval tv;
    int soerr = 0;
    socklen_t soerr_len = sizeof(soerr);

    if (banner && banner_len)
        banner[0] = '\0';
    if (!ip || !is_private_ipv4(ip) || port <= 0 || port > 65535)
        return -1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    tv.tv_sec = 0;
    tv.tv_usec = 350000;
    rc = select(fd + 1, NULL, &wfds, NULL, &tv);
    if (rc <= 0 || !FD_ISSET(fd, &wfds) ||
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &soerr_len) != 0 ||
        soerr != 0) {
        close(fd);
        return -1;
    }
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags);
    if (banner && banner_len > 1) {
        struct timeval rtv = { .tv_sec = 0, .tv_usec = 150000 };
        int n;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));
        n = recv(fd, banner, banner_len - 1, 0);
        if (n > 0) {
            banner[n] = '\0';
            trim_crlf(banner);
        } else {
            banner[0] = '\0';
        }
    }
    close(fd);
    return 0;
}

static int dns_probe_recursive_a(const char *ip)
{
    int fd, rc;
    struct sockaddr_in sa;
    struct timeval tv = { .tv_sec = 0, .tv_usec = 500000 };
    unsigned char req[64];
    unsigned char resp[512];
    size_t off = 0;
    uint16_t flags, qd, an;

    if (!ip || !is_private_ipv4(ip))
        return 0;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(53);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        close(fd);
        return 0;
    }

    memset(req, 0, sizeof(req));
    req[0] = 0x44; req[1] = 0x57;
    req[2] = 0x01; req[3] = 0x00;
    req[5] = 0x01;
    off = 12;
    req[off++] = 3; memcpy(req + off, "www", 3); off += 3;
    req[off++] = 5; memcpy(req + off, "baidu", 5); off += 5;
    req[off++] = 3; memcpy(req + off, "com", 3); off += 3;
    req[off++] = 0;
    req[off++] = 0; req[off++] = 1;
    req[off++] = 0; req[off++] = 1;

    if (sendto(fd, req, off, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return 0;
    }
    rc = recv(fd, resp, sizeof(resp), 0);
    close(fd);
    if (rc < 12 || resp[0] != req[0] || resp[1] != req[1])
        return 0;
    flags = (uint16_t)((resp[2] << 8) | resp[3]);
    qd = (uint16_t)((resp[4] << 8) | resp[5]);
    an = (uint16_t)((resp[6] << 8) | resp[7]);
    return ((flags & 0x8000) && !(flags & 0x000f) && qd == 1 && an > 0) ? 1 : 0;
}

static void observe_lan_service_identity(const char *mac, const char *ip)
{
    static const int ports[] = {22, 53, 80, 443, 602, 5000, 8080, 8443, 11504, 12517};
    char raw[256];
    char banner[128];
    int open_22 = 0, open_53 = 0, open_602 = 0;
    int i;

    if (!mac || !mac[0] || !ip || !is_private_ipv4(ip))
        return;

    for (i = 0; i < (int)(sizeof(ports) / sizeof(ports[0])); i++) {
        if (tcp_probe_port(ip, ports[i], banner, sizeof(banner)) == 0) {
            char port_buf[16];
            snprintf(port_buf, sizeof(port_buf), "%d", ports[i]);
            snprintf(raw, sizeof(raw), "ip=%s tcp_open=%d", ip, ports[i]);
            identity_observe_signal(mac, "service-probe", "tcp_port", port_buf, 45, raw);
            if (banner[0])
                identity_observe_signal(mac, "service-probe", ports[i] == 22 ? "ssh_banner" : "tcp_banner", banner, 55, raw);
            if (ports[i] == 22) open_22 = 1;
            else if (ports[i] == 53) open_53 = 1;
            else if (ports[i] == 602) open_602 = 1;
        }
    }

    if (dns_probe_recursive_a(ip)) {
        snprintf(raw, sizeof(raw), "ip=%s udp53_recursive=true", ip);
        identity_observe_signal(mac, "service-probe", "dns_recursive", "true", 70, raw);
        open_53 = 1;
    }

    if (open_22 && open_53 && open_602) {
        snprintf(raw, sizeof(raw), "ip=%s ports=22,53,602 dns_recursive=%s", ip, open_53 ? "true" : "unknown");
        identity_observe_signal(mac, "service-probe", "router_candidate", "true", 62, raw);
    }

    if (open_602) {
        char html[2048];
        if (http_fetch_small(ip, 602, "/wireless_mac_vlan", html, sizeof(html)) > 0 &&
            http_status_code(html) == 200) {
            snprintf(raw, sizeof(raw), "ip=%s port=602 path=/wireless_mac_vlan", ip);
            identity_observe_signal(mac, "ikuai-ac-http", "manufacturer", "iKuaiOS", 92, raw);
            identity_observe_signal(mac, "ikuai-ac-http", "modelName", "iKuaiOS router", 93, raw);
            identity_observe_signal(mac, "ikuai-ac-http", "friendlyName", "iKuaiOS router", 92, raw);
            identity_observe_signal(mac, "ikuai-ac-http", "device_type", "router", 88, raw);
            identity_observe_signal(mac, "ikuai-ac-http", "management_ip", ip, 70, raw);
        }
    }
}

static int identity_iface_is_client_lan(const char *ifname)
{
    if (!ifname || !ifname[0])
        return 0;
    if (!strncmp(ifname, "wan", 3) || !strncmp(ifname, "wwan", 4) ||
        !strncmp(ifname, "br-wan", 6) || !strncmp(ifname, "docker", 6) ||
        !strncmp(ifname, "br-docker", 9))
        return 0;
    return !strncmp(ifname, "br-", 3) || !strncmp(ifname, "lan", 3) ||
           !strncmp(ifname, "guest", 5) || !strncmp(ifname, "iot", 3);
}

static void probe_lan_services(int force)
{
    FILE *f;
    char line[256];
    time_t now = time(NULL);
    int probed = 0;

    if (!force && g_next_lan_service_probe_at > 0 && now < g_next_lan_service_probe_at)
        return;
    g_next_lan_service_probe_at = now + LAN_SERVICE_PROBE_INTERVAL_SEC;
    f = fopen("/proc/net/arp", "r");
    if (!f)
        return;
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return;
    }
    while (fgets(line, sizeof(line), f)) {
        char ip[64] = {0}, hw[8] = {0}, flags[16] = {0}, mac[32] = {0}, mask[16] = {0}, dev[32] = {0};
        char mac_l[32] = {0};
        unsigned int fl = 0;
        size_t i;

        if (sscanf(line, "%31s %7s %15s %31s %15s %31s", ip, hw, flags, mac, mask, dev) < 6)
            continue;
        if (!identity_iface_is_client_lan(dev))
            continue;
        sscanf(flags, "%x", &fl);
        if (!(fl & 0x2) || !strcmp(mac, "00:00:00:00:00:00") || !is_private_ipv4(ip))
            continue;
        for (i = 0; mac[i] && i < sizeof(mac_l) - 1; i++)
            mac_l[i] = (char)tolower((unsigned char)mac[i]);
        if (!mac_is_virtual_nic_prefix(mac_l))
            continue;
        observe_lan_service_identity(mac_l, ip);
        if (++probed >= 64)
            break;
    }
    fclose(f);
}

static int iface_is_lan_discovery_candidate(const char *ifname, unsigned int flags,
                                            const struct sockaddr_in *sin,
                                            int strict_lan_name)
{
    if (!ifname || !sin)
        return 0;
    if (!(flags & IFF_UP) || (flags & IFF_LOOPBACK))
        return 0;
    if (!is_private_ipv4_addr(sin->sin_addr))
        return 0;
    if (!strict_lan_name)
        return 1;
    if (identity_iface_is_client_lan(ifname))
        return 1;
    return 0;
}

static int send_ssdp_msearch_on_addr(struct in_addr local_addr)
{
    static const char *targets[] = {
        "ssdp:all",
        "upnp:rootdevice",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        NULL
    };
    struct sockaddr_in dst;
    unsigned char loop = 0;
    int sent = 0;
    int i;

    int fd = g_ssdp_query_fd.fd >= 0 ? g_ssdp_query_fd.fd : g_ssdp_fd.fd;

    if (fd < 0)
        return -1;

    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));
    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &local_addr, sizeof(local_addr));

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(1900);
    dst.sin_addr.s_addr = inet_addr("239.255.255.250");

    for (i = 0; targets[i]; i++) {
        char req[512];
        int len = snprintf(req, sizeof(req),
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 1\r\n"
            "ST: %s\r\n"
            "USER-AGENT: DreamingWrt/1.0 UPnP/1.1 identityd/1.0\r\n"
            "\r\n",
            targets[i]);
        if (len > 0 && len < (int)sizeof(req) &&
            sendto(fd, req, (size_t)len, 0, (struct sockaddr *)&dst, sizeof(dst)) == len)
            sent++;
    }

    return sent > 0 ? 0 : -1;
}

static void send_ssdp_msearch(int force)
{
    struct ifaddrs *ifas = NULL;
    struct ifaddrs *ifa;
    time_t now = time(NULL);
    int sent = 0;
    int pass;

    if (g_ssdp_fd.fd < 0)
        return;
    if (!force && g_next_ssdp_discovery_at > 0 && now < g_next_ssdp_discovery_at)
        return;
    g_next_ssdp_discovery_at = now + SSDP_DISCOVERY_INTERVAL_SEC;

    if (getifaddrs(&ifas) != 0) {
        struct in_addr any;
        any.s_addr = htonl(INADDR_ANY);
        send_ssdp_msearch_on_addr(any);
        return;
    }

    for (pass = 0; pass < 2; pass++) {
        for (ifa = ifas; ifa; ifa = ifa->ifa_next) {
            struct sockaddr_in *sin;

            if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
                continue;
            sin = (struct sockaddr_in *)ifa->ifa_addr;
            if (!iface_is_lan_discovery_candidate(ifa->ifa_name, ifa->ifa_flags, sin, pass == 0))
                continue;
            if (send_ssdp_msearch_on_addr(sin->sin_addr) == 0)
                sent++;
        }
        if (sent > 0)
            break;
    }

    freeifaddrs(ifas);
    if (sent > 0)
        LOG_INFO("identity collector: SSDP active discovery sent on %d interface(s)\n", sent);
}

static int parse_http_url(const char *url, char *host, size_t host_len, int *port, char *path, size_t path_len)
{
    const char *p, *slash, *colon;
    size_t hl;
    const char *q;
    if (!url || strncasecmp(url, "http://", 7)) return -1;
    p = url + 7;
    slash = strchr(p, '/');
    if (!slash) return -1;
    colon = memchr(p, ':', slash - p);
    if (colon) {
        hl = (size_t)(colon - p);
        if (colon + 1 == slash)
            return -1;
        *port = 0;
        for (q = colon + 1; q < slash; q++) {
            if (!isdigit((unsigned char)*q))
                return -1;
            *port = (*port * 10) + (*q - '0');
            if (*port > 65535)
                return -1;
        }
    } else {
        hl = (size_t)(slash - p);
        *port = 80;
    }
    if (hl == 0 || hl >= host_len || *port <= 0 || *port > 65535) return -1;
    for (q = slash; *q; q++) {
        if ((unsigned char)*q <= 0x20 || (unsigned char)*q == 0x7f)
            return -1;
    }
    memcpy(host, p, hl); host[hl] = '\0';
    snprintf(path, path_len, "%s", slash);
    return 0;
}

static int http_fetch_small(const char *host, int port, const char *path, char *out, size_t out_len)
{
    int fd, n, total = 0;
    struct sockaddr_in sa;
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    char req[512];
    if (!is_private_ipv4(host) || !out || out_len < 2) return -1;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) { close(fd); return -1; }
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(fd); return -1; }
    snprintf(req, sizeof(req), "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: jmxd/identity\r\nConnection: close\r\n\r\n", path, host);
    if (send(fd, req, strlen(req), 0) < 0) { close(fd); return -1; }
    while (total < (int)out_len - 1 && (n = recv(fd, out + total, out_len - 1 - total, 0)) > 0)
        total += n;
    close(fd);
    out[total] = '\0';
    return total > 0 ? total : -1;
}

static int http_status_code(const char *resp)
{
    int code = 0;
    if (!resp)
        return 0;
    if (sscanf(resp, "HTTP/%*s %d", &code) == 1)
        return code;
    return 0;
}

static int header_value_copy(const char *msg, const char *name, char *out, size_t out_len)
{
    size_t nl;
    const char *p;

    if (!msg || !name || !out || out_len == 0)
        return -1;
    out[0] = '\0';
    nl = strlen(name);
    p = msg;
    while (p && *p) {
        const char *e = strstr(p, "\r\n");
        size_t len = e ? (size_t)(e - p) : strlen(p);
        if (len > nl && !strncasecmp(p, name, nl) && p[nl] == ':') {
            const char *v = p + nl + 1;
            while (*v && isspace((unsigned char)*v) && v < p + len)
                v++;
            if ((size_t)(p + len - v) >= out_len)
                len = (size_t)(v - p) + out_len - 1;
            else
                len = (size_t)(p + len - v);
            memcpy(out, v, len);
            out[len] = '\0';
            trim_crlf(out);
            return out[0] ? 0 : -1;
        }
        if (!e)
            break;
        p = e + 2;
    }
    return -1;
}

static int http_fetch_small_follow(const char *host, int port, const char *path,
                                   char *out, size_t out_len)
{
    char cur_path[256];
    int rc;
    int redirects;

    if (!host || !path || !out || out_len < 2)
        return -1;
    snprintf(cur_path, sizeof(cur_path), "%s", path[0] ? path : "/");
    for (redirects = 0; redirects < 3; redirects++) {
        char location[256] = "";
        int status;

        rc = http_fetch_small(host, port, cur_path, out, out_len);
        if (rc <= 0)
            return rc;
        status = http_status_code(out);
        if (status < 300 || status >= 400)
            return rc;
        if (header_value_copy(out, "Location", location, sizeof(location)) != 0)
            return rc;
        if (location[0] == '/') {
            snprintf(cur_path, sizeof(cur_path), "%s", location);
            continue;
        }
        if (!strncasecmp(location, "http://", 7)) {
            char redir_host[64], redir_path[256];
            int redir_port = 80;
            if (parse_http_url(location, redir_host, sizeof(redir_host),
                               &redir_port, redir_path, sizeof(redir_path)) != 0)
                return rc;
            if (strcmp(redir_host, host) || redir_port != port)
                return rc;
            snprintf(cur_path, sizeof(cur_path), "%s", redir_path);
            continue;
        }
        return rc;
    }
    return rc;
}

static uint32_t route_hex_to_ipv4_host(const char *hex)
{
    unsigned long raw = 0;
    if (!hex)
        return 0;
    raw = strtoul(hex, NULL, 16);
    return ((raw & 0xff) << 24) |
           (((raw >> 8) & 0xff) << 16) |
           (((raw >> 16) & 0xff) << 8) |
           ((raw >> 24) & 0xff);
}

static void ipv4_host_to_text(uint32_t ip, char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return;
    snprintf(out, out_len, "%u.%u.%u.%u",
             (unsigned int)((ip >> 24) & 0xff),
             (unsigned int)((ip >> 16) & 0xff),
             (unsigned int)((ip >> 8) & 0xff),
             (unsigned int)(ip & 0xff));
}

static int ipv4_host_is_private(uint32_t ip)
{
    unsigned int a = (ip >> 24) & 0xff;
    unsigned int b = (ip >> 16) & 0xff;

    if (a == 10)
        return 1;
    if (a == 172 && b >= 16 && b <= 31)
        return 1;
    if (a == 192 && b == 168)
        return 1;
    return 0;
}

static int ipv4_prefix_len(uint32_t mask)
{
    int i, prefix = 0;
    for (i = 31; i >= 0; i--) {
        if (mask & (1u << i))
            prefix++;
        else
            break;
    }
    return prefix;
}

static int lookup_arp_mac(const char *ip, char *mac_out, size_t mac_len)
{
    FILE *f;
    char line[256];

    if (!ip || !mac_out || mac_len == 0)
        return -1;
    mac_out[0] = '\0';
    f = fopen("/proc/net/arp", "r");
    if (!f)
        return -1;
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return -1;
    }
    while (fgets(line, sizeof(line), f)) {
        char ent_ip[64] = {0}, hw[8] = {0}, flags[16] = {0}, mac[32] = {0};
        unsigned int fl = 0;
        size_t i;

        if (sscanf(line, "%63s %7s %15s %31s", ent_ip, hw, flags, mac) < 4)
            continue;
        if (strcmp(ent_ip, ip))
            continue;
        sscanf(flags, "%x", &fl);
        if (!(fl & 0x2) || !strcmp(mac, "00:00:00:00:00:00"))
            continue;
        for (i = 0; mac[i] && i < mac_len - 1; i++)
            mac_out[i] = (char)tolower((unsigned char)mac[i]);
        mac_out[i] = '\0';
        fclose(f);
        return mac_out[0] ? 0 : -1;
    }
    fclose(f);
    return -1;
}

static int html_title(const char *html, char *out, size_t out_len)
{
    const char *a, *b;
    size_t n;

    if (!html || !out || out_len == 0)
        return -1;
    out[0] = '\0';
    a = strcasestr(html, "<title");
    if (!a)
        return -1;
    a = strchr(a, '>');
    if (!a)
        return -1;
    a++;
    b = strcasestr(a, "</title>");
    if (!b)
        return -1;
    n = (size_t)(b - a);
    if (n >= out_len)
        n = out_len - 1;
    memcpy(out, a, n);
    out[n] = '\0';
    trim_crlf(out);
    return out[0] ? 0 : -1;
}

static void lower_ascii_text(char *dst, size_t dst_len, const char *src)
{
    size_t i;
    if (!dst || dst_len == 0)
        return;
    dst[0] = '\0';
    if (!src)
        return;
    for (i = 0; src[i] && i < dst_len - 1; i++)
        dst[i] = (char)tolower((unsigned char)src[i]);
    dst[i] = '\0';
}

static void observe_known_router_web_identity(const char *mac, const char *mgmt_ip,
                                              const char *html)
{
    char title[256] = "";
    char hay[1024];
    char raw[512];
    const char *manufacturer = NULL;
    const char *model = NULL;

    if (!mac || !mac[0] || !mgmt_ip || !mgmt_ip[0] || !html || !html[0])
        return;
    html_title(html, title, sizeof(title));
    lower_ascii_text(hay, sizeof(hay), title[0] ? title : html);

    if (strstr(hay, "ikuai os") || strstr(hay, "ikuaios") || strstr(hay, "ikuai")) {
        manufacturer = "iKuaiOS";
        model = "iKuaiOS router";
    } else if (strstr(hay, "openwrt") || strstr(hay, "luci")) {
        manufacturer = "OpenWrt";
        model = "OpenWrt router";
    } else if (strstr(hay, "routeros") || strstr(hay, "mikrotik")) {
        manufacturer = "MikroTik";
        model = "RouterOS router";
    } else if (strstr(hay, "pfsense")) {
        manufacturer = "pfSense";
        model = "pfSense router";
    } else if (strstr(hay, "opnsense")) {
        manufacturer = "OPNsense";
        model = "OPNsense router";
    }

    if (!manufacturer || !model)
        return;

    snprintf(raw, sizeof(raw), "management_ip=%s title=%s", mgmt_ip, title);
    identity_observe_signal(mac, "route-downstream-http", "management_ip", mgmt_ip, 75, raw);
    if (title[0])
        identity_observe_signal(mac, "route-downstream-http", "http_title", title, 75, raw);
    identity_observe_signal(mac, "route-downstream-http", "manufacturer", manufacturer, 88, raw);
    identity_observe_signal(mac, "route-downstream-http", "modelName", model, 90, raw);
    identity_observe_signal(mac, "route-downstream-http", "friendlyName", model, 88, raw);
    identity_observe_signal(mac, "route-downstream-http", "device_type", "router", 82, raw);
}

static void probe_routed_gateway_management(int force)
{
    FILE *f;
    char line[256];
    time_t now = time(NULL);

    if (!force && g_next_routed_gateway_probe_at > 0 && now < g_next_routed_gateway_probe_at)
        return;
    g_next_routed_gateway_probe_at = now + ROUTED_GATEWAY_PROBE_INTERVAL_SEC;

    f = fopen("/proc/net/route", "r");
    if (!f)
        return;
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return;
    }
    while (fgets(line, sizeof(line), f)) {
        char iface[32] = {0}, dest_hex[16] = {0}, gw_hex[16] = {0}, flags_hex[16] = {0};
        char mask_hex[16] = {0};
        char gateway_ip[32], mgmt_ip[32], mac[32], cidr[64], html[8192];
        uint32_t dest, gateway, mask, mgmt;
        int prefix;

        if (sscanf(line, "%31s %15s %15s %15s %*s %*s %*s %15s",
                   iface, dest_hex, gw_hex, flags_hex, mask_hex) < 5)
            continue;
        if (strcmp(iface, "br-lan") && strncmp(iface, "lan", 3))
            continue;
        dest = route_hex_to_ipv4_host(dest_hex);
        gateway = route_hex_to_ipv4_host(gw_hex);
        mask = route_hex_to_ipv4_host(mask_hex);
        if (!dest || !gateway || !mask || !ipv4_host_is_private(dest) || !ipv4_host_is_private(gateway))
            continue;
        prefix = ipv4_prefix_len(mask);
        if (prefix <= 0 || prefix > 30)
            continue;
        mgmt = (dest & mask) | 1u;
        if (mgmt == gateway || !ipv4_host_is_private(mgmt))
            continue;

        ipv4_host_to_text(gateway, gateway_ip, sizeof(gateway_ip));
        if (lookup_arp_mac(gateway_ip, mac, sizeof(mac)) != 0)
            continue;
        ipv4_host_to_text(mgmt, mgmt_ip, sizeof(mgmt_ip));
        snprintf(cidr, sizeof(cidr), "%s/%d", mgmt_ip, prefix);
        identity_observe_signal(mac, "route-gateway", "gateway_ip", gateway_ip, 65, line);
        identity_observe_signal(mac, "route-gateway", "routed_management_ip", mgmt_ip, 68, line);
        identity_observe_signal(mac, "route-gateway", "routed_network", cidr, 60, line);

        if (http_fetch_small_follow(mgmt_ip, 80, "/", html, sizeof(html)) > 0)
            observe_known_router_web_identity(mac, mgmt_ip, html);
    }
    fclose(f);
}

static int xml_text(const char *xml, const char *tag, char *out, size_t out_len)
{
    char open[64], close_tag[64];
    const char *a, *b;
    size_t n;
    snprintf(open, sizeof(open), "<%s>", tag);
    snprintf(close_tag, sizeof(close_tag), "</%s>", tag);
    a = strcasestr(xml, open);
    if (!a) return -1;
    a += strlen(open);
    b = strcasestr(a, close_tag);
    if (!b) return -1;
    n = (size_t)(b - a);
    if (n >= out_len) n = out_len - 1;
    memcpy(out, a, n); out[n] = '\0';
    trim_crlf(out);
    return out[0] ? 0 : -1;
}

static void fetch_ssdp_location_xml(const char *src_ip, const char *location)
{
    char host[64], path[256], xml[8192], val[256];
    int port = 80;
    if (parse_http_url(location, host, sizeof(host), &port, path, sizeof(path)) != 0)
        return;
    if (strcmp(host, src_ip) && !is_private_ipv4(host))
        return;
    if (http_fetch_small(host, port, path, xml, sizeof(xml)) <= 0)
        return;
    if (xml_text(xml, "friendlyName", val, sizeof(val)) == 0) observe_ip(src_ip, "ssdp", "friendlyName", val, 85, location);
    if (xml_text(xml, "manufacturer", val, sizeof(val)) == 0) observe_ip(src_ip, "ssdp", "manufacturer", val, 85, location);
    if (xml_text(xml, "modelName", val, sizeof(val)) == 0) observe_ip(src_ip, "ssdp", "modelName", val, 88, location);
    if (xml_text(xml, "modelNumber", val, sizeof(val)) == 0) observe_ip(src_ip, "ssdp", "modelNumber", val, 80, location);
    if (xml_text(xml, "deviceType", val, sizeof(val)) == 0) observe_ip(src_ip, "ssdp", "deviceType", val, 80, location);
}

static void ssdp_cb(struct uloop_fd *u, unsigned int events)
{
    char buf[JMX_ID_BUF];
    struct sockaddr_in from;
    socklen_t flen = sizeof(from);
    char ip[INET_ADDRSTRLEN];
    int n;
    (void)events;
    while ((n = recvfrom(u->fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&from, &flen)) > 0) {
        char raw[JMX_ID_BUF];
        char *v;
        buf[n] = '\0';
        memcpy(raw, buf, n + 1);
        inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));
        if ((v = header_value(buf, "SERVER"))) observe_ip(ip, "ssdp", "server", v, 65, raw);
        memcpy(buf, raw, n + 1);
        if ((v = header_value(buf, "USN"))) observe_ip(ip, "ssdp", "usn", v, 65, raw);
        memcpy(buf, raw, n + 1);
        if ((v = header_value(buf, "ST"))) observe_ip(ip, "ssdp", "st", v, 60, raw);
        memcpy(buf, raw, n + 1);
        if ((v = header_value(buf, "NT"))) observe_ip(ip, "ssdp", "nt", v, 60, raw);
        memcpy(buf, raw, n + 1);
        if ((v = header_value(buf, "LOCATION"))) { observe_ip(ip, "ssdp", "location", v, 70, raw); fetch_ssdp_location_xml(ip, v); }
    }
}

static void collect_dhcp_leases(void)
{
    FILE *f = fopen("/tmp/dhcp.leases", "r");
    char line[512];
    if (!f) f = fopen("/tmp/hosts/dhcp.leases", "r");
    if (!f) return;
    while (fgets(line, sizeof(line), f)) {
        char ts[32], mac[32], ip[64], host[128];
        if (sscanf(line, "%31s %31s %63s %127s", ts, mac, ip, host) == 4) {
            if (strcmp(host, "*"))
                identity_observe_signal(mac, "dhcp", "hostname", host, 70, line);
            identity_observe_signal(mac, "dhcp", "lease_ip", ip, 60, line);
            /* DHCP leases are identity/IP evidence, not liveness evidence.
             * A valid lease can outlive a powered-off client; writing
             * network_state.online=1 here races with ARP/neigh/runtime and
             * makes the web client row flicker online/offline.  Only
             * complete ARP/neigh/af_client observations assert online state. */
        }
    }
    fclose(f);
}


struct dhcp_fixed_hdr {
    uint8_t op, htype, hlen, hops;
    uint32_t xid;
    uint16_t secs, flags;
    uint32_t ciaddr, yiaddr, siaddr, giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
} __attribute__((packed));

static int make_dhcp_packet_socket(void)
{
    int fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    if (fd < 0) return -1;
    if (set_nonblock(fd) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

static void mac_to_text(const uint8_t *m, char *out, size_t out_len)
{
    snprintf(out, out_len, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void option_bytes_csv(const uint8_t *p, int len, char *out, size_t out_len)
{
    int i, off = 0;
    if (!out || out_len == 0) return;
    out[0] = '\0';
    for (i = 0; i < len; i++) {
        int n = snprintf(out + off, out_len - off, "%s%u", i ? "," : "", p[i]);
        if (n < 0 || off + n >= (int)out_len) break;
        off += n;
    }
}

static void option_bytes_hex(const uint8_t *p, int len, char *out, size_t out_len)
{
    int i, off = 0;
    if (!out || out_len == 0) return;
    out[0] = '\0';
    if (!p || len <= 0) return;
    for (i = 0; i < len; i++) {
        int n = snprintf(out + off, out_len - off, "%02x", p[i]);
        if (n < 0 || off + n >= (int)out_len) break;
        off += n;
    }
}

static void observe_huginn_option55(const char *mac, const char *option55)
{
    huginn_result_t hr;

    if (!mac || !mac[0] || !option55 || !option55[0])
        return;
    if (huginn_lookup_by_option55(option55, &hr) != 0)
        return;
    if (hr.device_name[0])
        identity_observe_signal(mac, "huginn-muninn", "model", hr.device_name, 70, "dhcp-option-55");
    if (hr.device_vendor[0])
        identity_observe_signal(mac, "huginn-muninn", "vendor", hr.device_vendor, 60, "dhcp-option-55");
    if (hr.device_type[0] && strcmp(hr.device_type, "Miscellaneous"))
        identity_observe_signal(mac, "huginn-muninn", "device_type", hr.device_type, 60, "dhcp-option-55");
}

static void observe_huginn_vendor_class(const char *mac, const char *vendor_class)
{
    huginn_result_t hr;

    if (!mac || !mac[0] || !vendor_class || !vendor_class[0])
        return;
    if (huginn_lookup_by_vendor_class(vendor_class, &hr) != 0)
        return;
    if (hr.device_name[0])
        identity_observe_signal(mac, "huginn-muninn", "model", hr.device_name, 65, "dhcp-option-60");
    if (hr.device_vendor[0])
        identity_observe_signal(mac, "huginn-muninn", "vendor", hr.device_vendor, 55, "dhcp-option-60");
    if (hr.device_type[0] && strcmp(hr.device_type, "Miscellaneous"))
        identity_observe_signal(mac, "huginn-muninn", "device_type", hr.device_type, 55, "dhcp-option-60");
}

static void dhcp_cb(struct uloop_fd *u, unsigned int events)
{
    uint8_t buf[2048];
    int n;
    (void)events;
    while ((n = recv(u->fd, buf, sizeof(buf), 0)) > 0) {
        struct iphdr *ip;
        struct udphdr *udp;
        struct dhcp_fixed_hdr *dh;
        uint8_t *opt;
        int ip_hl, udp_total_len, udp_len, opt_len, i;
        char mac[32];
        if (n < (int)(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dhcp_fixed_hdr) + 4)) continue;
        ip = (struct iphdr *)buf;
        if (ip->version != 4 || ip->protocol != IPPROTO_UDP) continue;
        ip_hl = ip->ihl * 4;
        if (ip_hl < (int)sizeof(struct iphdr) || n < ip_hl + (int)sizeof(struct udphdr)) continue;
        udp = (struct udphdr *)(buf + ip_hl);
        if (!(ntohs(udp->source) == 67 || ntohs(udp->source) == 68 || ntohs(udp->dest) == 67 || ntohs(udp->dest) == 68)) continue;
        udp_total_len = ntohs(udp->len);
        if (udp_total_len < (int)sizeof(struct udphdr) || n < ip_hl + udp_total_len) continue;
        udp_len = udp_total_len - (int)sizeof(struct udphdr);
        if (udp_len < (int)sizeof(struct dhcp_fixed_hdr) + 4) continue;
        dh = (struct dhcp_fixed_hdr *)(buf + ip_hl + sizeof(struct udphdr));
        if (dh->hlen < 6) continue;
        opt = (uint8_t *)dh + sizeof(struct dhcp_fixed_hdr);
        if (!(opt[0] == 0x63 && opt[1] == 0x82 && opt[2] == 0x53 && opt[3] == 0x63)) continue;
        mac_to_text(dh->chaddr, mac, sizeof(mac));
        opt += 4;
        opt_len = udp_len - (int)sizeof(struct dhcp_fixed_hdr) - 4;
        for (i = 0; i < opt_len;) {
            uint8_t code = opt[i++];
            uint8_t len;
            char val[512];
            if (code == 0) continue;
            if (code == 255) break;
            if (i >= opt_len) break;
            len = opt[i++];
            if (i + len > opt_len) break;
            val[0] = '\0';
            if (code == 12 || code == 60 || code == 61 || code == 77) {
                int copy = len < sizeof(val) - 1 ? len : sizeof(val) - 1;
                memcpy(val, opt + i, copy); val[copy] = '\0';
                for (int k = 0; val[k]; k++) if ((unsigned char)val[k] < 32) val[k] = '.';
                if (code == 12) identity_observe_signal(mac, "dhcp-packet", "hostname", val, 80, "dhcp-option-12");
                else if (code == 60) {
                    identity_observe_signal(mac, "dhcp-packet", "vendor_class", val, 85, "dhcp-option-60");
                    identity_observe_signal(mac, "dhcp-packet", "dhcp_vendor_class", val, 60, "dhcp-option-60");
                    observe_huginn_vendor_class(mac, val);
                }
                else if (code == 61) {
                    option_bytes_hex(opt + i, len, val, sizeof(val));
                    identity_observe_signal(mac, "dhcp-packet", "client_id_hex", val, 70, "dhcp-option-61");
                }
                else if (code == 77) identity_observe_signal(mac, "dhcp-packet", "user_class", val, 75, "dhcp-option-77");
            } else if (code == 55) {
                option_bytes_csv(opt + i, len, val, sizeof(val));
                identity_observe_signal(mac, "dhcp-packet", "option55", val, 90, "dhcp-option-55");
                identity_observe_signal(mac, "dhcp-packet", "dhcp_option55", val, 70, "dhcp-option-55");
                observe_huginn_option55(mac, val);
            }
            i += len;
        }
    }
}

static int identity_register_listener(struct uloop_fd *u, uloop_fd_handler cb,
                                      const char *name)
{
    int saved_errno;

    if (!u || u->fd < 0)
        return -1;
    u->cb = cb;
    if (uloop_fd_add(u, ULOOP_READ) == 0) {
        LOG_INFO("identity collector: %s listener ready\n", name ? name : "network");
        return 0;
    }

    saved_errno = errno;
    close(u->fd);
    u->fd = -1;
    errno = saved_errno;
    LOG_WARN("identity collector: %s listener register failed: %s\n",
             name ? name : "network", strerror(errno));
    return -1;
}

int jmx_identity_collector_init(void)
{
    jmx_identity_collector_close();
    g_mdns_fd.fd = make_mcast_socket("224.0.0.251", 5353);
    if (g_mdns_fd.fd >= 0)
        identity_register_listener(&g_mdns_fd, mdns_cb, "mDNS");
    else
        LOG_WARN("identity collector: mDNS listener failed: %s\n", strerror(errno));

    g_ssdp_fd.fd = make_mcast_socket("239.255.255.250", 1900);
    if (g_ssdp_fd.fd >= 0)
        identity_register_listener(&g_ssdp_fd, ssdp_cb, "SSDP");
    else
        LOG_WARN("identity collector: SSDP listener failed: %s\n", strerror(errno));

    g_ssdp_query_fd.fd = make_udp_query_socket();
    if (g_ssdp_query_fd.fd >= 0)
        identity_register_listener(&g_ssdp_query_fd, ssdp_cb, "SSDP active query");
    else
        LOG_WARN("identity collector: SSDP active query socket failed: %s\n", strerror(errno));

    g_dhcp_fd.fd = make_dhcp_packet_socket();
    if (g_dhcp_fd.fd >= 0)
        identity_register_listener(&g_dhcp_fd, dhcp_cb, "DHCP packet");
    else
        LOG_WARN("identity collector: DHCP packet listener failed: %s\n", strerror(errno));

    collect_dhcp_leases();
    send_ssdp_msearch(1);
    probe_lan_services(1);
    g_collector_initialized = 1;
    return jmx_identity_collector_ready() ? 0 : -1;
}

int jmx_identity_collector_listener_count(void)
{
    return (g_mdns_fd.fd >= 0) + (g_ssdp_fd.fd >= 0) +
           (g_ssdp_query_fd.fd >= 0) + (g_dhcp_fd.fd >= 0);
}

int jmx_identity_collector_ready(void)
{
    return g_collector_initialized &&
           (jmx_identity_collector_listener_count() > 0 ||
            access("/proc/net/arp", R_OK) == 0);
}

static void collect_arp_entries(void)
{
    FILE *f = fopen("/proc/net/arp", "r");
    char line[256];
    if (!f) return;
    /* skip header */
    if (!fgets(line, sizeof(line), f)) { fclose(f); return; }
    while (fgets(line, sizeof(line), f)) {
        char ip[64] = {0}, hw[8] = {0}, flags[16] = {0}, mac[32] = {0}, mask[16] = {0}, dev[32] = {0};
        if (sscanf(line, "%31s %7s %15s %31s %15s %31s", ip, hw, flags, mac, mask, dev) < 6) continue;
        if (!identity_iface_is_client_lan(dev))
            continue;
        /* skip incomplete entries (flags 0x0) */
        unsigned int fl = 0;
        sscanf(flags, "%x", &fl);
        if (!(fl & 0x2)) continue;  /* ATF_COM = complete */
        if (!strcmp(mac, "00:00:00:00:00:00")) continue;
        /* normalize MAC to lowercase */
        char mac_l[32] = {0};
        size_t i;
        for (i = 0; mac[i] && i < sizeof(mac_l) - 1; i++)
            mac_l[i] = (char)tolower((unsigned char)mac[i]);

        observe_lan_bridge_state(mac_l, ip, dev);
        identity_observe_signal(mac_l, "arp", "ip", ip, 40, line);

        flush_pending_ip_signals();
    }
    fclose(f);
}

void jmx_identity_collector_tick(void)
{
    if (g_ssdp_query_fd.fd >= 0)
        ssdp_cb(&g_ssdp_query_fd, ULOOP_READ);
    if (g_ssdp_fd.fd >= 0)
        ssdp_cb(&g_ssdp_fd, ULOOP_READ);
    collect_dhcp_leases();
    collect_arp_entries();
    flush_pending_ip_signals();
    probe_routed_gateway_management(0);
    probe_lan_services(0);
    send_ssdp_msearch(0);
}

void jmx_identity_collector_close(void)
{
    if (g_mdns_fd.fd >= 0) { uloop_fd_delete(&g_mdns_fd); close(g_mdns_fd.fd); g_mdns_fd.fd = -1; }
    if (g_ssdp_fd.fd >= 0) { uloop_fd_delete(&g_ssdp_fd); close(g_ssdp_fd.fd); g_ssdp_fd.fd = -1; }
    if (g_ssdp_query_fd.fd >= 0) { uloop_fd_delete(&g_ssdp_query_fd); close(g_ssdp_query_fd.fd); g_ssdp_query_fd.fd = -1; }
    if (g_dhcp_fd.fd >= 0) { uloop_fd_delete(&g_dhcp_fd); close(g_dhcp_fd.fd); g_dhcp_fd.fd = -1; }
    identity_ubus_close();
    g_collector_initialized = 0;
}

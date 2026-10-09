#include "../system/memory_profile.h"
#define _GNU_SOURCE
// SPDX-License-Identifier: GPL-2.0-or-later
#include "flowd_internal.h"
#include "flowd_qoe_cache.h"
#include "../routed/jmx_route.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnfnetlink/linux_nfnetlink_compat.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netlink.h>
#include <maxminddb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <nftables/libnftables.h>
#include <poll.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/uio.h>

#define FLOWD_QOE_CITY_MMDB "/etc/dreamingwrt/geoip/GeoLite2-City.mmdb"
#define FLOWD_QOE_ASN_MMDB "/etc/dreamingwrt/geoip/GeoLite2-ASN.mmdb"
#define FLOWD_QOE_ENABLE_FILE "/etc/dreamingwrt/smart-path.enabled"
#define FLOWD_QOE_CONFIRM_FILE "/etc/dreamingwrt/smart-path.confirmed"
#define FLOWD_QOE_NFT_TABLE "dreamingwrt_smart_path"
#define FLOWD_QOE_NFT_OWNER "owned-by=dreamingwrt-flowd smart-path-canary-v1"
#define FLOWD_QOE_TICK_MS 1000
#define FLOWD_QOE_READBACK_INTERVAL_MS 10000ULL
#define FLOWD_QOE_PROBE_TIMEOUT_MS 1500
#define FLOWD_QOE_QUEUE_CAPACITY 64
#define FLOWD_QOE_CANDIDATES_PER_TICK 8
#define FLOWD_QOE_BINDING_CAPACITY 2048
#define FLOWD_QOE_CONNTRACK_RCVBUF_BYTES (4 * 1024 * 1024)
#define FLOWD_QOE_CONNTRACK_BATCH_BYTES (64 * 1024)
#define FLOWD_QOE_NEGATIVE_TTL_MS 60000ULL
#define FLOWD_QOE_NEGATIVE_TTL_MAX_MS (30ULL * 60ULL * 1000ULL)
#define FLOWD_QOE_NEGATIVE_STREAK_MAX 6
#define FLOWD_QOE_NO_GEO_TTL_MS (5ULL * 60ULL * 1000ULL)
#define FLOWD_QOE_PROBE_MAGIC 0x51504531U
#define FLOWD_QOE_PROBE_VERSION 3U
#define FLOWD_QOE_PROBE_PATHS FLOWD_QOE_MAX_WANS
#define FLOWD_QOE_ROUTE_PROC "/proc/dreamingwrt/jmx/jmx_route"
#define FLOWD_QOE_LAN_IFNAME "br-lan"
#define FLOWD_QOE_MAX_POLICY_RULES 256

struct flowd_qoe_wan_runtime {
    uint8_t id;
    char logical_name[32];
    char ifname[IFNAMSIZ];
    uint32_t fwmark;
    struct in6_addr ipv6_source;
    uint8_t carrier_id;
    uint8_t healthy;
    uint8_t present;
    uint8_t ipv6_source_valid;
};

/*
 * Populated at runtime from FLOWD_QOE_ROUTE_PROC.  WAN ids are not assumed to be
 * dense or to start at 1, so every consumer resolves an id through
 * qoe_wan_by_id() instead of indexing by (id - 1).
 */
static struct flowd_qoe_wan_runtime g_qoe_wans[FLOWD_QOE_MAX_WANS];
static size_t g_qoe_wan_count;

struct flowd_qoe_policy_runtime {
    uint16_t prio;
    uint8_t enabled;
    uint8_t smart_requested;
    uint8_t member_count;
    uint8_t members[FLOWD_QOE_MAX_WANS];
    char smart_mode[12];
    char runtime_reason[64];
};

static struct flowd_qoe_policy_runtime g_qoe_policies[FLOWD_QOE_MAX_POLICY_RULES];
static size_t g_qoe_policy_count;
static int g_qoe_policy_ready;
static int g_qoe_global_requested;
static uint64_t g_qoe_policy_revision;

static int qoe_wan_topology_changed(const struct flowd_qoe_wan_runtime *next,
                                    size_t next_count)
{
    size_t i;
    size_t j;

    if (next_count != g_qoe_wan_count)
        return 1;
    for (i = 0; i < next_count; i++) {
        const struct flowd_qoe_wan_runtime *old = NULL;

        for (j = 0; j < g_qoe_wan_count; j++) {
            if (g_qoe_wans[j].id == next[i].id) {
                old = &g_qoe_wans[j];
                break;
            }
        }
        if (!old || old->fwmark != next[i].fwmark ||
            strcmp(old->logical_name, next[i].logical_name) ||
            strcmp(old->ifname, next[i].ifname) ||
            old->ipv6_source_valid != next[i].ipv6_source_valid ||
            (old->ipv6_source_valid &&
             memcmp(&old->ipv6_source, &next[i].ipv6_source,
                    sizeof(old->ipv6_source))))
            return 1;
    }
    return 0;
}

static struct flowd_qoe_wan_runtime *qoe_wan_by_id(uint8_t wan_id)
{
    size_t i;

    if (!wan_id)
        return NULL;
    for (i = 0; i < g_qoe_wan_count; i++) {
        if (g_qoe_wans[i].id == wan_id)
            return &g_qoe_wans[i];
    }
    return NULL;
}

static int qoe_wan_healthy(uint8_t wan_id)
{
    const struct flowd_qoe_wan_runtime *wan = qoe_wan_by_id(wan_id);

    return wan && wan->healthy;
}

static struct flowd_qoe_policy_runtime *qoe_policy_by_prio(uint16_t prio)
{
    size_t i;

    if (!prio)
        return NULL;
    for (i = 0; i < g_qoe_policy_count; i++)
        if (g_qoe_policies[i].prio == prio)
            return &g_qoe_policies[i];
    return NULL;
}

static int qoe_policy_has_wan(const struct flowd_qoe_policy_runtime *policy,
                              uint8_t wan_id)
{
    size_t i;

    if (!policy || !wan_id)
        return 0;
    for (i = 0; i < policy->member_count; i++)
        if (policy->members[i] == wan_id)
            return 1;
    return 0;
}

static int qoe_policy_effective(const struct flowd_qoe_policy_runtime *policy)
{
    return policy && policy->enabled && policy->smart_requested &&
           policy->member_count > 0;
}

static uint64_t qoe_policy_hash_mix(uint64_t hash, const void *data, size_t len)
{
    const unsigned char *bytes = data;
    size_t i;

    for (i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

/* Read the policy overlay from config.db.  The route writer commits this column
 * atomically with the matching rule, and the kernel exports that rule's prio in
 * ctmark high bits.  The two together make the nft override policy-scoped. */
static int qoe_refresh_policy_table(void)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *rules = NULL;
    sqlite3_stmt *members = NULL;
    struct flowd_qoe_policy_runtime next[FLOWD_QOE_MAX_POLICY_RULES];
    size_t next_count = 0;
    uint64_t revision = 1469598103934665603ULL;
    int rc = -1;
    int changed;
    int rule_rc;
    int global_requested = access(FLOWD_QOE_ENABLE_FILE, F_OK) == 0;

    if (sqlite3_open_v2(FLOWD_CONFIG_DB_PATH, &db, SQLITE_OPEN_READONLY, NULL) !=
        SQLITE_OK)
        goto done;
    sqlite3_busy_timeout(db, 50);
    if (sqlite3_prepare_v2(db,
        "SELECT rule_id,prio,enabled,smart_path_mode FROM route_rule ORDER BY position",
        -1, &rules, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db,
        "SELECT wan_id FROM route_rule_wan WHERE rule_id=?1 ORDER BY position",
        -1, &members, NULL) != SQLITE_OK)
        goto done;
    while ((rule_rc = sqlite3_step(rules)) == SQLITE_ROW) {
        struct flowd_qoe_policy_runtime *policy;
        const unsigned char *mode;
        int rule_id;
        int member_rc;

        if (next_count >= FLOWD_QOE_MAX_POLICY_RULES)
            goto done;
        policy = &next[next_count];
        memset(policy, 0, sizeof(*policy));
        rule_id = sqlite3_column_int(rules, 0);
        policy->prio = (uint16_t)sqlite3_column_int(rules, 1);
        policy->enabled = sqlite3_column_int(rules, 2) ? 1 : 0;
        mode = sqlite3_column_text(rules, 3);
        snprintf(policy->smart_mode, sizeof(policy->smart_mode), "%s",
                 mode && mode[0] ? (const char *)mode : "inherit");
        if (!strcmp(policy->smart_mode, "enabled") ||
            (!strcmp(policy->smart_mode, "inherit") && global_requested))
            policy->smart_requested = 1;
        else if (strcmp(policy->smart_mode, "inherit") &&
                 strcmp(policy->smart_mode, "disabled"))
            goto done;
        sqlite3_reset(members);
        sqlite3_clear_bindings(members);
        sqlite3_bind_int(members, 1, rule_id);
        while ((member_rc = sqlite3_step(members)) == SQLITE_ROW) {
            int wan_id = sqlite3_column_int(members, 0);

            if (wan_id <= 0 || wan_id > UINT8_MAX ||
                policy->member_count >= FLOWD_QOE_MAX_WANS)
                goto done;
            policy->members[policy->member_count++] = (uint8_t)wan_id;
        }
        if (member_rc != SQLITE_DONE)
            goto done;
        snprintf(policy->runtime_reason, sizeof(policy->runtime_reason), "%s",
                 qoe_policy_effective(policy) ? "nft_policy_scope_ready" :
                 (!policy->enabled ? "policy_disabled" :
                  (!policy->smart_requested ? "not_requested" :
                   "policy_has_no_members")));
        revision = qoe_policy_hash_mix(revision, policy, sizeof(*policy));
        next_count++;
    }
    if (rule_rc != SQLITE_DONE)
        goto done;
    changed = !g_qoe_policy_ready || revision != g_qoe_policy_revision;
    memcpy(g_qoe_policies, next, sizeof(g_qoe_policies));
    g_qoe_policy_count = next_count;
    g_qoe_global_requested = global_requested;
    g_qoe_policy_revision = revision;
    g_qoe_policy_ready = 1;
    rc = changed ? 1 : 0;
done:
    if (members) sqlite3_finalize(members);
    if (rules) sqlite3_finalize(rules);
    if (db) sqlite3_close(db);
    return rc;
}

static int qoe_any_policy_requested(void)
{
    size_t i;

    for (i = 0; i < g_qoe_policy_count; i++)
        if (qoe_policy_effective(&g_qoe_policies[i]))
            return 1;
    return 0;
}

static uint8_t qoe_carrier_normalize(int carrier_id, const char *carrier_key)
{
    switch (carrier_id) {
    case JMX_CARRIER_TELECOM:
    case JMX_CARRIER_UNICOM:
    case JMX_CARRIER_MOBILE:
    case JMX_CARRIER_EDU:
        return (uint8_t)carrier_id;
    default:
        break;
    }
    if (!carrier_key || !carrier_key[0])
        return JMX_CARRIER_ANY;
    if (!strcmp(carrier_key, "mobile"))
        return JMX_CARRIER_MOBILE;
    if (!strcmp(carrier_key, "unicom"))
        return JMX_CARRIER_UNICOM;
    if (!strcmp(carrier_key, "telecom"))
        return JMX_CARRIER_TELECOM;
    if (!strcmp(carrier_key, "edu") || !strcmp(carrier_key, "cernet"))
        return JMX_CARRIER_EDU;
    return JMX_CARRIER_ANY;
}

/*
 * Carrier identity is taken from the operator-authored carrier rules already
 * present in jmx_route, e.g. "carrier 3 ... wans 2,4" declares those uplinks as
 * mobile. This is status metadata only; the generic QoE selector never reads
 * carrier_id when ranking paths.
 *
 * Reverse DNS/prefix lookup on the WAN address is not usable here: some uplinks
 * present a private PPPoE local address which no public prefix table can
 * attribute. This metadata is therefore best-effort and informational only.
 */
static void qoe_apply_carrier_rules(struct flowd_qoe_wan_runtime *wans,
                                    size_t wan_count, FILE *fp)
{
    char line[512];

    while (fgets(line, sizeof(line), fp)) {
        const char *wan_list;
        unsigned carrier;
        unsigned enabled;
        size_t i;

        /* prio en proto appid carrier src/mask dst/mask dport mode ... wans */
        if (sscanf(line, "%*u %u %*u %*u %u", &enabled, &carrier) != 2)
            continue;
        if (!enabled || !carrier)
            continue;
        wan_list = strrchr(line, ' ');
        if (!wan_list)
            continue;
        wan_list++;
        for (i = 0; i < wan_count; i++) {
            const char *p = wan_list;

            if (wans[i].carrier_id != JMX_CARRIER_ANY)
                continue;
            while (*p) {
                unsigned id = 0;

                while (*p >= '0' && *p <= '9')
                    id = id * 10 + (unsigned)(*p++ - '0');
                if (id == wans[i].id) {
                    wans[i].carrier_id = qoe_carrier_normalize((int)carrier, NULL);
                    break;
                }
                if (!*p)
                    break;
                p++;
            }
        }
    }
}

/*
 * The logical WAN name from jmx_route ("wan", "wan2", ...) is not the L3 device
 * that SO_BINDTODEVICE needs.  Resolve the real interface, preferring the PPPoE
 * session when one exists and falling back to the logical name itself.
 */
static void qoe_wan_resolve_ifname(struct flowd_qoe_wan_runtime *wan)
{
    char candidate[IFNAMSIZ];

    if (!wan || !wan->logical_name[0])
        return;
    wan->ifname[0] = '\0';
    if (snprintf(candidate, sizeof(candidate), "pppoe-%s", wan->logical_name) <
        (int)sizeof(candidate) && if_nametoindex(candidate)) {
        snprintf(wan->ifname, sizeof(wan->ifname), "%s", candidate);
        return;
    }
    /* A silently truncated copy would name a different interface, so only fall
     * back to the logical name when it actually fits in an ifname. */
    if (strlen(wan->logical_name) < sizeof(wan->ifname) &&
        if_nametoindex(wan->logical_name))
        memcpy(wan->ifname, wan->logical_name, strlen(wan->logical_name) + 1);
}

static int qoe_ipv6_source_usable(const struct in6_addr *address)
{
    if (!address || IN6_IS_ADDR_UNSPECIFIED(address) ||
        IN6_IS_ADDR_LOOPBACK(address) || IN6_IS_ADDR_MULTICAST(address) ||
        IN6_IS_ADDR_LINKLOCAL(address) || IN6_IS_ADDR_V4MAPPED(address))
        return 0;
    return (address->s6_addr[0] & 0xfeU) != 0xfcU;
}

static void qoe_wan_resolve_ipv6_sources(struct flowd_qoe_wan_runtime *wans,
                                         size_t wan_count)
{
    struct ifaddrs *addresses = NULL;
    struct ifaddrs *item;
    size_t i;

    for (i = 0; i < wan_count; i++) {
        memset(&wans[i].ipv6_source, 0, sizeof(wans[i].ipv6_source));
        wans[i].ipv6_source_valid = 0;
    }
    if (getifaddrs(&addresses) != 0)
        return;
    for (item = addresses; item; item = item->ifa_next) {
        const struct sockaddr_in6 *in6;

        if (!item->ifa_name || !item->ifa_addr ||
            item->ifa_addr->sa_family != AF_INET6)
            continue;
        in6 = (const struct sockaddr_in6 *)item->ifa_addr;
        if (!qoe_ipv6_source_usable(&in6->sin6_addr))
            continue;
        for (i = 0; i < wan_count; i++) {
            if (wans[i].ipv6_source_valid ||
                strcmp(item->ifa_name, wans[i].ifname))
                continue;
            wans[i].ipv6_source = in6->sin6_addr;
            wans[i].ipv6_source_valid = 1;
        }
    }
    freeifaddrs(addresses);
}

/*
 * Rebuild the WAN table from jmx_route. Health transitions are reported to the
 * caller through down_ids; the return value is -1 on read failure, 0 for a
 * health/metadata-only refresh, and 1 when id/name/ifname/fwmark topology changed.
 */
static int qoe_refresh_wan_table(uint8_t *down_ids, size_t *down_count)
{
    struct flowd_qoe_wan_runtime next[FLOWD_QOE_MAX_WANS];
    size_t next_count = 0;
    FILE *fp;
    char line[512];
    int in_wans = 0;
    int saw_rules = 0;
    int topology_changed;

    if (down_count)
        *down_count = 0;
    fp = fopen(FLOWD_QOE_ROUTE_PROC, "r");
    if (!fp)
        return -1;
    memset(next, 0, sizeof(next));
    while (fgets(line, sizeof(line), fp)) {
        struct flowd_qoe_wan_runtime *slot;
        const struct flowd_qoe_wan_runtime *prev;
        char name[32];
        unsigned id;
        unsigned fwmark;
        unsigned health;

        if (!strncmp(line, "WANs:", 5)) {
            in_wans = 1;
            continue;
        }
        if (!strncmp(line, "Rules:", 6)) {
            saw_rules = 1;
            break;
        }
        if (!in_wans)
            continue;
        /* id name fwmark table gateway health ... */
        if (sscanf(line, "%u %31s 0x%x %*u %*63s %u",
                   &id, name, &fwmark, &health) != 4)
            continue;
        if (!id || id > UINT8_MAX || next_count >= FLOWD_QOE_MAX_WANS)
            continue;

        slot = &next[next_count++];
        slot->id = (uint8_t)id;
        snprintf(slot->logical_name, sizeof(slot->logical_name), "%s", name);
        slot->fwmark = fwmark;
        slot->healthy = health ? 1 : 0;
        slot->present = 1;

        prev = qoe_wan_by_id(slot->id);
        if (prev && !strcmp(prev->logical_name, slot->logical_name)) {
            snprintf(slot->ifname, sizeof(slot->ifname), "%s", prev->ifname);
            if (prev->healthy && !slot->healthy && down_ids && down_count &&
                *down_count < FLOWD_QOE_MAX_WANS)
                down_ids[(*down_count)++] = slot->id;
        }
        if (!slot->ifname[0])
            qoe_wan_resolve_ifname(slot);
    }
    qoe_wan_resolve_ipv6_sources(next, next_count);
    /* Header line of the Rules section is consumed by the carrier parser. */
    if (saw_rules && next_count)
        qoe_apply_carrier_rules(next, next_count, fp);
    fclose(fp);
    if (!next_count)
        return -1;
    topology_changed = qoe_wan_topology_changed(next, next_count);
    memcpy(g_qoe_wans, next, sizeof(g_qoe_wans));
    g_qoe_wan_count = next_count;
    return topology_changed;
}

struct flowd_qoe_candidate {
    struct flowd_qoe_address address;
    uint16_t port;
    uint16_t policy_prio;
};

struct flowd_qoe_binding {
    struct flowd_qoe_address address;
    uint64_t valid_until_ms;
    uint8_t wan_id;
    uint8_t used;
    uint16_t policy_prio;
    /* Consecutive failed probes for this address, driving the negative-TTL
     * back-off.  Sits in the tail padding valid_until_ms already forces, so
     * the binding table does not grow. */
    uint8_t fail_streak;
};

struct flowd_qoe_probe_result {
    struct flowd_qoe_address address;
    uint16_t port;
    uint16_t path_count;
    struct flowd_qoe_path paths[FLOWD_QOE_PROBE_PATHS];
};

struct flowd_qoe_probe_path_wire {
    uint32_t wan_id;
    uint32_t healthy;
    uint32_t confidence;
    uint32_t rtt_us;
    uint32_t penalty_us;
    uint32_t score_us;
};

struct flowd_qoe_probe_result_wire {
    uint32_t magic;
    uint32_t version;
    uint32_t wire_size;
    uint32_t family;
    uint32_t port;
    uint32_t path_count;
    uint32_t reserved;
    uint8_t address[16];
    struct flowd_qoe_probe_path_wire paths[FLOWD_QOE_PROBE_PATHS];
};

_Static_assert(sizeof(struct flowd_qoe_probe_path_wire) == 24,
               "probe path wire format changed");
_Static_assert(FLOWD_QOE_PROBE_PATHS == 8,
               "probe wire size assertion assumes 8 paths");
_Static_assert(sizeof(struct flowd_qoe_probe_result_wire) == 236,
               "probe result wire format changed");

struct flowd_qoe_runtime {
    struct flowd_qoe_cache cache;
    struct flowd_qoe_token_bucket probes;
    struct nft_ctx *nft;
    struct nfct_handle *conntrack;
    MMDB_s city_db;
    MMDB_s asn_db;
    struct uloop_timeout tick;
    struct uloop_process probe_process;
    struct uloop_fd conntrack_fd;
    struct uloop_fd probe_result_fd;
    struct flowd_qoe_candidate queue[FLOWD_QOE_QUEUE_CAPACITY];
    struct flowd_qoe_binding bindings[FLOWD_QOE_BINDING_CAPACITY];
    struct flowd_qoe_candidate active_candidate;
    struct flowd_qoe_probe_result probe_result;
    char last_probe_ip[INET6_ADDRSTRLEN];
    char last_error[128];
    char last_nft_error[256];
    uint64_t last_readback_ms;
    uint64_t last_probe_at_ms;
    uint64_t candidates_seen;
    uint64_t candidates_queued;
    uint64_t candidates_dropped;
    uint64_t conntrack_events;
    uint64_t conntrack_filtered;
    uint64_t conntrack_errors;
    uint64_t conntrack_enobufs;
    uint64_t cache_routes;
    uint64_t probe_jobs;
    uint64_t probe_successes;
    uint64_t probe_failures;
    /* probe_failures is the sum of the five below.  Eight code paths used to
     * collapse into it, so a GFW-blocked destination and a failed fork() were
     * indistinguishable in status output. */
    uint64_t probe_setup_failures;
    uint64_t probe_child_failures;
    uint64_t probe_no_healthy_path;
    uint64_t probe_cache_record_failures;
    uint64_t probe_bind_failures;
    uint64_t probe_backoff_extensions;
    uint64_t nft_updates;
    uint64_t nft_failures;
    uint64_t health_failovers;
    uint64_t binding_evictions;
    uint64_t binding_eviction_failures;
    size_t queue_head;
    size_t queue_tail;
    size_t queue_count;
    int initialized;
    int city_open;
    int asn_open;
    int started;
    int enabled_requested;
    int nft_active;
    int nft_readback_ok;
    int probe_active;
    int probe_result_ready;
    int probe_result_eof;
    int probe_child_done;
    int probe_child_status;
    int disabled_cleanup_done;
};

static struct flowd_qoe_runtime g_qoe;

static uint64_t qoe_monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return (uint64_t)flowd_now_s() * 1000ULL;
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static int qoe_mmdb_open(const char *path, MMDB_s *db)
{
    struct stat st;

    if (!path || !db || stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    memset(db, 0, sizeof(*db));
    return MMDB_open(path, MMDB_MODE_MMAP, db) == MMDB_SUCCESS;
}

static uint32_t qoe_mmdb_u32(MMDB_entry_s *entry, const char *first,
                             const char *second)
{
    MMDB_entry_data_s data;
    int rc;

    memset(&data, 0, sizeof(data));
    rc = second ? MMDB_get_value(entry, &data, first, second, NULL)
                : MMDB_get_value(entry, &data, first, NULL);
    if (rc != MMDB_SUCCESS || !data.has_data)
        return 0;
    if (data.type == MMDB_DATA_TYPE_UINT32)
        return data.uint32;
    if (data.type == MMDB_DATA_TYPE_UINT16)
        return data.uint16;
    return 0;
}

static uint32_t qoe_mmdb_country_code(MMDB_entry_s *entry, const char *first)
{
    MMDB_entry_data_s data;
    char iso[3] = {0};

    memset(&data, 0, sizeof(data));
    if (MMDB_get_value(entry, &data, first, "iso_code", NULL) != MMDB_SUCCESS ||
        !data.has_data || data.type != MMDB_DATA_TYPE_UTF8_STRING ||
        data.data_size != 2)
        return 0;
    iso[0] = data.utf8_string[0];
    iso[1] = data.utf8_string[1];
    return flowd_qoe_country_code_id(iso);
}

static int qoe_lookup(MMDB_s *db, const char *ip, MMDB_lookup_result_s *result)
{
    int gai_error = 0;
    int mmdb_error = MMDB_SUCCESS;

    if (!db || !ip || !ip[0] || !result)
        return 0;
    *result = MMDB_lookup_string(db, ip, &gai_error, &mmdb_error);
    return !gai_error && mmdb_error == MMDB_SUCCESS && result->found_entry;
}

static void qoe_error_set(const char *error)
{
    snprintf(g_qoe.last_error, sizeof(g_qoe.last_error), "%s", error ? error : "");
}

static void qoe_nft_error_set(const char *error)
{
    size_t in = 0;
    size_t out = 0;
    int space = 0;

    memset(g_qoe.last_nft_error, 0, sizeof(g_qoe.last_nft_error));
    if (!error)
        return;
    while (error[in] && out + 1 < sizeof(g_qoe.last_nft_error)) {
        unsigned char c = (unsigned char)error[in++];

        if (c == '\n' || c == '\r' || c == '\t' || c == ' ') {
            space = out != 0;
            continue;
        }
        if (space && out + 1 < sizeof(g_qoe.last_nft_error))
            g_qoe.last_nft_error[out++] = ' ';
        g_qoe.last_nft_error[out++] = (char)c;
        space = 0;
    }
    g_qoe.last_nft_error[out] = '\0';
}

static int qoe_nft_run(const char *command, const char **output)
{
    const char *error;
    const char *result;
    int rc;

    if (output)
        *output = "";
    if (!g_qoe.nft || !command || !command[0]) {
        qoe_nft_error_set("libnftables context unavailable");
        return -1;
    }

    /* Reading a buffered result rewinds it, so each command starts empty. */
    (void)nft_ctx_get_output_buffer(g_qoe.nft);
    (void)nft_ctx_get_error_buffer(g_qoe.nft);
    rc = nft_run_cmd_from_buffer(g_qoe.nft, command);
    result = nft_ctx_get_output_buffer(g_qoe.nft);
    error = nft_ctx_get_error_buffer(g_qoe.nft);
    if (output)
        *output = result ? result : "";
    qoe_nft_error_set(rc == 0 ? "" : (error && error[0] ? error :
                                      "libnftables command failed"));
    return rc == 0 ? 0 : -1;
}

static int qoe_nft_output_has_table(const char *output)
{
    static const char needle[] = "table inet " FLOWD_QOE_NFT_TABLE;
    const char *line = output;
    size_t needle_len = sizeof(needle) - 1;

    if (!output)
        return 0;
    while (*line) {
        const char *end = strchr(line, '\n');
        size_t len = end ? (size_t)(end - line) : strlen(line);

        while (len && isspace((unsigned char)*line)) {
            line++;
            len--;
        }
        if (len >= needle_len && !memcmp(line, needle, needle_len) &&
            (len == needle_len || isspace((unsigned char)line[needle_len]) ||
             line[needle_len] == '{'))
            return 1;
        if (!end)
            break;
        line = end + 1;
    }
    return 0;
}

enum qoe_nft_table_state {
    QOE_NFT_TABLE_ERROR = -1,
    QOE_NFT_TABLE_ABSENT = 0,
    QOE_NFT_TABLE_OWNED = 1,
    QOE_NFT_TABLE_FOREIGN = 2,
};

static enum qoe_nft_table_state qoe_nft_table_state(void)
{
    const char *output = NULL;

    if (qoe_nft_run("list tables\n", &output) != 0) {
        qoe_error_set("nft_table_list_failed");
        return QOE_NFT_TABLE_ERROR;
    }
    if (!qoe_nft_output_has_table(output))
        return QOE_NFT_TABLE_ABSENT;
    if (qoe_nft_run("list table inet " FLOWD_QOE_NFT_TABLE "\n", &output) != 0) {
        qoe_error_set("nft_table_readback_failed");
        return QOE_NFT_TABLE_ERROR;
    }
    return strstr(output, FLOWD_QOE_NFT_OWNER) != NULL
        ? QOE_NFT_TABLE_OWNED : QOE_NFT_TABLE_FOREIGN;
}

static int qoe_nft_delete(void)
{
    enum qoe_nft_table_state state = qoe_nft_table_state();

    if (state == QOE_NFT_TABLE_ABSENT)
        return 0;
    if (state == QOE_NFT_TABLE_FOREIGN) {
        qoe_error_set("nft_table_ownership_conflict");
        return -1;
    }
    if (state != QOE_NFT_TABLE_OWNED)
        return -1;
    if (qoe_nft_run("delete table inet " FLOWD_QOE_NFT_TABLE "\n", NULL) != 0) {
        qoe_error_set("nft_delete_failed");
        return -1;
    }
    return 0;
}

static int qoe_nft_readback_all(void)
{
    const char *output = NULL;
    size_t i;

    if (qoe_nft_run("list table inet " FLOWD_QOE_NFT_TABLE "\n", &output) != 0 ||
        !output || !strstr(output, FLOWD_QOE_NFT_OWNER)) {
        qoe_error_set("nft_table_readback_failed");
        return 0;
    }
    for (i = 0; i < g_qoe_policy_count; i++) {
        const struct flowd_qoe_policy_runtime *policy = &g_qoe_policies[i];
        size_t j;

        if (!qoe_policy_effective(policy))
            continue;
        for (j = 0; j < policy->member_count; j++) {
            char definition[64];
            char reference[64];

            snprintf(definition, sizeof(definition), "set p%u_wan%u",
                     policy->prio, policy->members[j]);
            snprintf(reference, sizeof(reference), "@p%u_wan%u",
                     policy->prio, policy->members[j]);
            if (!strstr(output, definition) || !strstr(output, reference)) {
                qoe_error_set("nft_policy_scope_readback_mismatch");
                return 0;
            }
            snprintf(definition, sizeof(definition), "set p%u_wan%u_v6",
                     policy->prio, policy->members[j]);
            snprintf(reference, sizeof(reference), "@p%u_wan%u_v6",
                     policy->prio, policy->members[j]);
            if (!strstr(output, definition) || !strstr(output, reference)) {
                qoe_error_set("nft_policy_scope_readback_mismatch");
                return 0;
            }
        }
    }
    return 1;
}

static int qoe_nft_install(void)
{
    char *text = NULL;
    size_t text_len = 0;
    FILE *fp = NULL;
    size_t i;
    enum qoe_nft_table_state state = qoe_nft_table_state();
    int replace;
    int failed = 0;

    if (state == QOE_NFT_TABLE_ERROR)
        return -1;
    if (state == QOE_NFT_TABLE_FOREIGN) {
        qoe_error_set("nft_table_ownership_conflict");
        return -1;
    }
    if (!g_qoe_wan_count) {
        qoe_error_set("wan_table_unavailable");
        return -1;
    }
    replace = state == QOE_NFT_TABLE_OWNED;

    fp = open_memstream(&text, &text_len);
    if (!fp)
        goto render_failed;
    if (replace)
        fprintf(fp, "delete table inet %s\n", FLOWD_QOE_NFT_TABLE);
    fprintf(fp, "table inet %s {\n  comment \"%s\"\n",
            FLOWD_QOE_NFT_TABLE, FLOWD_QOE_NFT_OWNER);
    for (i = 0; i < g_qoe_policy_count; i++) {
        const struct flowd_qoe_policy_runtime *policy = &g_qoe_policies[i];
        size_t j;

        if (!qoe_policy_effective(policy))
            continue;
        for (j = 0; j < policy->member_count; j++) {
            uint8_t wan_id = policy->members[j];

            if (!qoe_wan_by_id(wan_id)) {
                qoe_error_set("policy_wan_unavailable");
                failed = 1;
                break;
            }
            fprintf(fp,
                    "  set p%u_wan%u { type ipv4_addr; flags timeout; timeout 30m; }\n"
                    "  set p%u_wan%u_v6 { type ipv6_addr; flags timeout; timeout 30m; }\n",
                    policy->prio, wan_id, policy->prio, wan_id);
        }
        if (failed)
            break;
    }
    fprintf(fp,
            "  chain prerouting {\n"
            "    type filter hook prerouting priority mangle + 2; policy accept;\n");
    for (i = 0; !failed && i < g_qoe_policy_count; i++) {
        const struct flowd_qoe_policy_runtime *policy = &g_qoe_policies[i];
        uint32_t policy_mark = (uint32_t)policy->prio << 16;
        size_t j;

        if (!qoe_policy_effective(policy))
            continue;
        for (j = 0; j < policy->member_count; j++) {
            const struct flowd_qoe_wan_runtime *wan =
                qoe_wan_by_id(policy->members[j]);

            if (!wan) {
                failed = 1;
                break;
            }
            fprintf(fp,
                    "    iifname \"%s\" ct state new ct mark & 0xffff0000 == 0x%08x ip daddr @p%u_wan%u ct mark set ct mark & 0xffff0000\n"
                    "    iifname \"%s\" ct state new ct mark & 0xffff0000 == 0x%08x ip6 daddr @p%u_wan%u_v6 ct mark set ct mark & 0xffff0000\n"
                    "    iifname \"%s\" ct state new ct mark & 0xffff0000 == 0x%08x ip daddr @p%u_wan%u ct mark set ct mark | 0x%08x\n"
                    "    iifname \"%s\" ct state new ct mark & 0xffff0000 == 0x%08x ip6 daddr @p%u_wan%u_v6 ct mark set ct mark | 0x%08x\n"
                    "    iifname \"%s\" ct state new ct mark & 0xffff0000 == 0x%08x ip daddr @p%u_wan%u meta mark set 0x%x\n"
                    "    iifname \"%s\" ct state new ct mark & 0xffff0000 == 0x%08x ip6 daddr @p%u_wan%u_v6 meta mark set 0x%x\n"
                    "    iifname \"%s\" ct mark & 0xffff0000 == 0x%08x ct mark & 0x0000ffff == 0x%08x meta mark set 0x%x\n",
                    FLOWD_QOE_LAN_IFNAME, policy_mark, policy->prio, wan->id,
                    FLOWD_QOE_LAN_IFNAME, policy_mark, policy->prio, wan->id,
                    FLOWD_QOE_LAN_IFNAME, policy_mark, policy->prio, wan->id, wan->id,
                    FLOWD_QOE_LAN_IFNAME, policy_mark, policy->prio, wan->id, wan->id,
                    FLOWD_QOE_LAN_IFNAME, policy_mark, policy->prio, wan->id, wan->fwmark,
                    FLOWD_QOE_LAN_IFNAME, policy_mark, policy->prio, wan->id, wan->fwmark,
                    FLOWD_QOE_LAN_IFNAME, policy_mark, wan->id, wan->fwmark);
        }
    }
    fprintf(fp, "  }\n}\n");
    if (fclose(fp) != 0) {
        fp = NULL;
        goto render_failed;
    }
    fp = NULL;
    if (failed || !text || !text_len)
        goto render_failed;
    nft_ctx_set_dry_run(g_qoe.nft, true);
    if (qoe_nft_run(text, NULL) != 0) {
        nft_ctx_set_dry_run(g_qoe.nft, false);
        qoe_error_set("nft_validation_failed");
        free(text);
        return -1;
    }
    nft_ctx_set_dry_run(g_qoe.nft, false);
    if (qoe_nft_run(text, NULL) != 0 || !qoe_nft_readback_all()) {
        qoe_error_set("nft_apply_or_readback_failed");
        free(text);
        return -1;
    }
    free(text);
    g_qoe.nft_readback_ok = 1;
    memset(g_qoe.bindings, 0, sizeof(g_qoe.bindings));
    qoe_error_set("");
    return 0;

render_failed:
    if (fp)
        fclose(fp);
    free(text);
    qoe_error_set("nft_render_failed");
    return -1;
}

static int qoe_nft_bind(uint16_t policy_prio,
                        uint8_t old_wan_id, uint8_t new_wan_id,
                        const struct flowd_qoe_address *address,
                        uint64_t ttl_ms)
{
    char ip[INET6_ADDRSTRLEN];
    char text[512];
    int family;
    const void *bytes;
    const char *set_suffix;
    unsigned long long ttl_s;
    int n;

    if (!policy_prio || !address || !qoe_wan_by_id(new_wan_id) ||
        (old_wan_id && !qoe_wan_by_id(old_wan_id)))
        return -1;
    family = address->family;
    bytes = address->bytes;
    set_suffix = family == AF_INET6 ? "_v6" : "";
    if ((family != AF_INET && family != AF_INET6) ||
        !inet_ntop(family, bytes, ip, sizeof(ip)))
        return -1;
    ttl_s = (ttl_ms + 999ULL) / 1000ULL;
    if (!ttl_s)
        ttl_s = 1;
    if (ttl_s > FLOWD_QOE_DEFAULT_TTL_MS / 1000ULL)
        ttl_s = FLOWD_QOE_DEFAULT_TTL_MS / 1000ULL;
    if (old_wan_id)
        n = snprintf(text, sizeof(text),
                     "destroy element inet %s p%u_wan%u%s { %s }\n"
                     "add element inet %s p%u_wan%u%s { %s timeout %llus }\n",
                     FLOWD_QOE_NFT_TABLE, policy_prio, old_wan_id, set_suffix, ip,
                     FLOWD_QOE_NFT_TABLE, policy_prio, new_wan_id, set_suffix,
                     ip, ttl_s);
    else
        n = snprintf(text, sizeof(text),
                     "add element inet %s p%u_wan%u%s { %s timeout %llus }\n",
                     FLOWD_QOE_NFT_TABLE, policy_prio, new_wan_id, set_suffix,
                     ip, ttl_s);
    if (n <= 0 || (size_t)n >= sizeof(text))
        return -1;
    return qoe_nft_run(text, NULL);
}

static int qoe_nft_element_readback(uint16_t policy_prio, uint8_t wan_id,
                                    const struct flowd_qoe_address *address)
{
    char ip[INET6_ADDRSTRLEN];
    char text[320];
    const char *set_suffix;
    int n;

    if (!policy_prio || !address || !qoe_wan_by_id(wan_id) ||
        (address->family != AF_INET && address->family != AF_INET6) ||
        !inet_ntop(address->family, address->bytes, ip, sizeof(ip)))
        return -1;
    set_suffix = address->family == AF_INET6 ? "_v6" : "";
    n = snprintf(text, sizeof(text),
                 "get element inet %s p%u_wan%u%s { %s }\n",
                 FLOWD_QOE_NFT_TABLE, policy_prio, wan_id, set_suffix, ip);
    if (n <= 0 || (size_t)n >= sizeof(text))
        return -1;
    return qoe_nft_run(text, NULL);
}

static int qoe_nft_unbind(uint16_t policy_prio, uint8_t wan_id,
                          const struct flowd_qoe_address *address)
{
    char ip[INET6_ADDRSTRLEN];
    char text[320];
    const char *set_suffix;
    int n;

    if (!policy_prio || !address || !qoe_wan_by_id(wan_id) ||
        (address->family != AF_INET && address->family != AF_INET6) ||
        !inet_ntop(address->family, address->bytes, ip, sizeof(ip)))
        return -1;
    set_suffix = address->family == AF_INET6 ? "_v6" : "";
    n = snprintf(text, sizeof(text),
                 "destroy element inet %s p%u_wan%u%s { %s }\n",
                 FLOWD_QOE_NFT_TABLE, policy_prio, wan_id, set_suffix, ip);
    if (n <= 0 || (size_t)n >= sizeof(text))
        return -1;
    return qoe_nft_run(text, NULL);
}

static size_t qoe_binding_slot(const struct flowd_qoe_address *address,
                               uint16_t policy_prio, uint64_t now_ms, int *found)
{
    uint64_t hash = 1469598103934665603ULL;
    size_t length;
    size_t start;
    size_t available = SIZE_MAX;
    size_t i;

    if (!address || !policy_prio || !flowd_qoe_address_length(address)) {
        *found = 0;
        return SIZE_MAX;
    }
    length = flowd_qoe_address_length(address);
    hash ^= address->family;
    hash *= 1099511628211ULL;
    hash ^= policy_prio;
    hash *= 1099511628211ULL;
    for (i = 0; i < length; i++) {
        hash ^= address->bytes[i];
        hash *= 1099511628211ULL;
    }
    start = (size_t)(hash % FLOWD_QOE_BINDING_CAPACITY);
    *found = 0;
    for (i = 0; i < FLOWD_QOE_BINDING_CAPACITY; i++) {
        size_t slot = (start + i) % FLOWD_QOE_BINDING_CAPACITY;
        struct flowd_qoe_binding *binding = &g_qoe.bindings[slot];

        if (binding->used && binding->policy_prio == policy_prio &&
            flowd_qoe_address_equal(&binding->address, address)) {
            *found = 1;
            return slot;
        }
        if ((!binding->used || binding->valid_until_ms <= now_ms) &&
            available == SIZE_MAX)
            available = slot;
    }
    return available;
}

static struct flowd_qoe_binding *qoe_binding_find(const struct flowd_qoe_address *address,
                                                  uint16_t policy_prio,
                                                  uint64_t now_ms)
{
    int found;
    size_t slot = qoe_binding_slot(address, policy_prio, now_ms, &found);

    if (!found || slot == SIZE_MAX || g_qoe.bindings[slot].valid_until_ms <= now_ms)
        return NULL;
    return &g_qoe.bindings[slot];
}

static struct flowd_qoe_binding *qoe_binding_find_any(const struct flowd_qoe_address *address,
                                                      uint16_t policy_prio,
                                                      uint64_t now_ms)
{
    int found;
    size_t slot = qoe_binding_slot(address, policy_prio, now_ms, &found);

    return found && slot != SIZE_MAX ? &g_qoe.bindings[slot] : NULL;
}

static size_t qoe_binding_oldest_slot(int allow_positive)
{
    uint64_t oldest_until = UINT64_MAX;
    size_t oldest = SIZE_MAX;
    size_t i;

    for (i = 0; i < FLOWD_QOE_BINDING_CAPACITY; i++) {
        const struct flowd_qoe_binding *binding = &g_qoe.bindings[i];

        if (!binding->used || (!allow_positive && binding->wan_id) ||
            binding->valid_until_ms >= oldest_until)
            continue;
        oldest_until = binding->valid_until_ms;
        oldest = i;
    }
    return oldest;
}

static int qoe_binding_reserve(const struct flowd_qoe_address *address,
                               uint16_t policy_prio,
                               uint64_t now_ms,
                               int allow_positive_eviction, size_t *slot_out)
{
    struct flowd_qoe_binding *binding;
    int found;
    size_t slot;

    if (!slot_out)
        return -1;
    slot = qoe_binding_slot(address, policy_prio, now_ms, &found);
    if (found) {
        binding = &g_qoe.bindings[slot];
        if (binding->valid_until_ms <= now_ms) {
            if (binding->wan_id &&
                qoe_nft_unbind(binding->policy_prio, binding->wan_id,
                               &binding->address) != 0) {
                g_qoe.binding_eviction_failures++;
                g_qoe.nft_failures++;
                qoe_error_set("nft_binding_expiry_cleanup_failed");
                return -1;
            }
            memset(binding, 0, sizeof(*binding));
        }
        *slot_out = slot;
        return 0;
    }
    if (slot == SIZE_MAX)
        slot = qoe_binding_oldest_slot(allow_positive_eviction);
    if (slot == SIZE_MAX)
        return -1;

    binding = &g_qoe.bindings[slot];
    if (binding->used && binding->wan_id &&
        qoe_nft_unbind(binding->policy_prio, binding->wan_id,
                       &binding->address) != 0) {
        g_qoe.binding_eviction_failures++;
        g_qoe.nft_failures++;
        qoe_error_set("nft_binding_eviction_failed");
        return -1;
    }
    if (binding->used) {
        g_qoe.binding_evictions++;
        memset(binding, 0, sizeof(*binding));
    }
    *slot_out = slot;
    return 0;
}

static int qoe_binding_store(const struct flowd_qoe_address *address,
                             uint16_t policy_prio, uint8_t wan_id,
                             uint64_t valid_until_ms, uint64_t now_ms,
                             int allow_positive_eviction)
{
    size_t slot;

    if (qoe_binding_reserve(address, policy_prio, now_ms,
                            allow_positive_eviction, &slot) != 0)
        return -1;
    if (!wan_id && g_qoe.bindings[slot].used && g_qoe.bindings[slot].wan_id &&
        g_qoe.bindings[slot].valid_until_ms > now_ms)
        return 0;
    g_qoe.bindings[slot].address = *address;
    g_qoe.bindings[slot].policy_prio = policy_prio;
    g_qoe.bindings[slot].wan_id = wan_id;
    g_qoe.bindings[slot].valid_until_ms = valid_until_ms;
    g_qoe.bindings[slot].used = 1;
    return 0;
}

/* Store the negative binding a failed probe leaves behind, with an exponential
 * suppression window: 60 s, then 2 min, 4, 8, 16, capped at 30 min --
 * FLOWD_QOE_DEFAULT_TTL_MS, so a destination that never answers ends up costing
 * no more probe slots than one that does.  A flat 60 s window meant the reverse:
 * 30x the re-probe rate of a healthy destination, against a probe path that is
 * serialised one per 1000 ms tick with a 1500 ms deadline.
 *
 * The streak has to be carried by hand.  qoe_binding_reserve() memsets a slot
 * whose binding has expired, and that is precisely the slot a repeat failure
 * lands on, so the old streak is read before the store and written back after. */
static void qoe_negative_binding_store(const struct flowd_qoe_address *address,
                                       uint16_t policy_prio, uint64_t now_ms)
{
    const struct flowd_qoe_binding *previous;
    struct flowd_qoe_binding *stored;
    unsigned int streak = 1;
    uint64_t ttl_ms;

    if (!address || !policy_prio)
        return;
    previous = qoe_binding_find_any(address, policy_prio, now_ms);
    if (previous && !previous->wan_id && previous->fail_streak)
        streak = previous->fail_streak < FLOWD_QOE_NEGATIVE_STREAK_MAX ?
                 (unsigned int)previous->fail_streak + 1u :
                 FLOWD_QOE_NEGATIVE_STREAK_MAX;
    ttl_ms = FLOWD_QOE_NEGATIVE_TTL_MS << (streak - 1u);
    if (ttl_ms > FLOWD_QOE_NEGATIVE_TTL_MAX_MS)
        ttl_ms = FLOWD_QOE_NEGATIVE_TTL_MAX_MS;
    if (qoe_binding_store(address, policy_prio, 0, now_ms + ttl_ms, now_ms, 0) != 0)
        return;
    stored = qoe_binding_find_any(address, policy_prio, now_ms);
    /* qoe_binding_store() declines to overwrite a live positive binding; when it
     * did, the slot still holds a wan_id and the streak is not ours to touch. */
    if (!stored || stored->wan_id)
        return;
    stored->fail_streak = (uint8_t)streak;
    if (streak > 1u)
        g_qoe.probe_backoff_extensions++;
}

static int qoe_bind_address(const struct flowd_qoe_address *address,
                            uint16_t policy_prio, uint8_t wan_id, uint64_t now_ms,
                            uint64_t valid_until_ms)
{
    struct flowd_qoe_binding *old;
    uint8_t old_wan_id;
    uint64_t ttl_ms;
    size_t slot;

    if (!address || !policy_prio || !qoe_wan_by_id(wan_id) || !g_qoe.nft_active ||
        valid_until_ms <= now_ms)
        return -1;
    old = qoe_binding_find_any(address, policy_prio, now_ms);
    old_wan_id = old ? old->wan_id : 0;
    if (old_wan_id == wan_id && old->valid_until_ms >= valid_until_ms)
        return 0;
    if (qoe_binding_reserve(address, policy_prio, now_ms, 1, &slot) != 0)
        return -1;
    old = &g_qoe.bindings[slot];
    if (old->used && old->policy_prio == policy_prio &&
        flowd_qoe_address_equal(&old->address, address) &&
        old->valid_until_ms > now_ms)
        old_wan_id = old->wan_id;
    else
        old_wan_id = 0;
    ttl_ms = valid_until_ms - now_ms;
    if (qoe_nft_bind(policy_prio, old_wan_id, wan_id, address, ttl_ms) != 0) {
        g_qoe.nft_failures++;
        qoe_error_set("nft_element_update_failed");
        return -1;
    }
    if (qoe_nft_element_readback(policy_prio, wan_id, address) != 0) {
        if (qoe_nft_unbind(policy_prio, wan_id, address) != 0)
            g_qoe.nft_failures++;
        memset(&g_qoe.bindings[slot], 0, sizeof(g_qoe.bindings[slot]));
        g_qoe.nft_failures++;
        qoe_error_set("nft_element_readback_failed");
        return -1;
    }
    g_qoe.bindings[slot].address = *address;
    g_qoe.bindings[slot].policy_prio = policy_prio;
    g_qoe.bindings[slot].wan_id = wan_id;
    g_qoe.bindings[slot].valid_until_ms = valid_until_ms;
    g_qoe.bindings[slot].used = 1;
    g_qoe.nft_updates++;
    return 0;
}

static int qoe_ipv4_private(uint32_t address)
{
    uint32_t ip = ntohl(address);

    return (ip >> 24) == 10 || (ip >> 24) == 127 ||
           (ip >> 20) == 0xAC1 || (ip >> 16) == 0xC0A8 ||
           (ip >> 22) == 0x0191 || (ip >> 16) == 0xA9FE;
}

static int qoe_ipv4_public(uint32_t address)
{
    uint32_t ip = ntohl(address);

    if (!ip || ip == UINT32_MAX || qoe_ipv4_private(address))
        return 0;
    return (ip >> 28) != 0xE && (ip >> 28) != 0xF;
}

static int qoe_candidate_equal(const struct flowd_qoe_candidate *candidate,
                               const struct flowd_qoe_address *address,
                               uint16_t port, uint16_t policy_prio)
{
    return candidate && flowd_qoe_address_equal(&candidate->address, address) &&
           candidate->port == port && candidate->policy_prio == policy_prio;
}

static int qoe_candidate_pending(const struct flowd_qoe_address *address,
                                 uint16_t port, uint16_t policy_prio)
{
    size_t i;

    if (g_qoe.probe_active &&
        qoe_candidate_equal(&g_qoe.active_candidate, address, port, policy_prio))
        return 1;
    for (i = 0; i < g_qoe.queue_count; i++) {
        size_t slot = (g_qoe.queue_head + i) % FLOWD_QOE_QUEUE_CAPACITY;

        if (qoe_candidate_equal(&g_qoe.queue[slot], address, port, policy_prio))
            return 1;
    }
    return 0;
}

static int qoe_queue_push(const struct flowd_qoe_address *address, uint16_t port,
                          uint16_t policy_prio)
{
    if (!address || !policy_prio || !flowd_qoe_address_length(address))
        return -1;
    if (qoe_candidate_pending(address, port, policy_prio))
        return 0;
    if (g_qoe.queue_count >= FLOWD_QOE_QUEUE_CAPACITY) {
        g_qoe.candidates_dropped++;
        return -1;
    }
    g_qoe.queue[g_qoe.queue_tail].address = *address;
    g_qoe.queue[g_qoe.queue_tail].port = port;
    g_qoe.queue[g_qoe.queue_tail].policy_prio = policy_prio;
    g_qoe.queue_tail = (g_qoe.queue_tail + 1) % FLOWD_QOE_QUEUE_CAPACITY;
    g_qoe.queue_count++;
    g_qoe.candidates_queued++;
    return 0;
}

static int qoe_queue_pop(struct flowd_qoe_candidate *candidate)
{
    if (!candidate || !g_qoe.queue_count)
        return -1;
    *candidate = g_qoe.queue[g_qoe.queue_head];
    memset(&g_qoe.queue[g_qoe.queue_head], 0, sizeof(g_qoe.queue[0]));
    g_qoe.queue_head = (g_qoe.queue_head + 1) % FLOWD_QOE_QUEUE_CAPACITY;
    g_qoe.queue_count--;
    return 0;
}

static uint8_t qoe_entry_wan(const struct flowd_qoe_entry *entry)
{
    size_t i;

    if (!entry)
        return 0;
    if (entry->preferred_wan && qoe_wan_healthy(entry->preferred_wan)) {
        for (i = 0; i < entry->path_count; i++) {
            if (entry->paths[i].wan_id == entry->preferred_wan &&
                entry->paths[i].healthy)
                return entry->preferred_wan;
        }
    }
    for (i = 0; i < entry->path_count; i++) {
        uint8_t wan_id = entry->paths[i].wan_id;

        if (entry->paths[i].healthy && qoe_wan_healthy(wan_id))
            return wan_id;
    }
    return 0;
}

int flowd_qoe_destination_lookup(const char *ip,
                                 struct flowd_qoe_destination *destination)
{
    MMDB_lookup_result_s result;

    if (!destination)
        return -1;
    memset(destination, 0, sizeof(*destination));
    if (g_qoe.asn_open && qoe_lookup(&g_qoe.asn_db, ip, &result))
        destination->asn = qoe_mmdb_u32(&result.entry,
                                        "autonomous_system_number", NULL);
    if (g_qoe.city_open && qoe_lookup(&g_qoe.city_db, ip, &result)) {
        destination->city_id = qoe_mmdb_u32(&result.entry, "city", "geoname_id");
        destination->country_id = qoe_mmdb_u32(&result.entry, "country", "geoname_id");
        if (!destination->country_id)
            destination->country_id = qoe_mmdb_u32(&result.entry,
                                                    "registered_country",
                                                    "geoname_id");
        if (!destination->country_id)
            destination->country_id = qoe_mmdb_country_code(&result.entry, "country");
        if (!destination->country_id)
            destination->country_id = qoe_mmdb_country_code(&result.entry,
                                                             "registered_country");
    }
    return destination->asn ? 0 : -1;
}

static int qoe_destination_for_address(const struct flowd_qoe_address *address,
                                       struct flowd_qoe_destination *destination,
                                       char ip[INET6_ADDRSTRLEN])
{
    if (!address || !flowd_qoe_address_length(address) ||
        !inet_ntop(address->family, address->bytes, ip, INET6_ADDRSTRLEN))
        return -1;
    if (flowd_qoe_destination_lookup(ip, destination) != 0)
        return -1;
    destination->family = address->family;
    return 0;
}

static int qoe_route_from_cache(const struct flowd_qoe_address *address,
                                uint16_t policy_prio, uint64_t now_ms)
{
    struct flowd_qoe_destination destination;
    const struct flowd_qoe_entry *entry;
    enum flowd_qoe_scope scope = 0;
    char ip[INET6_ADDRSTRLEN];
    uint8_t wan_id;

    if (qoe_destination_for_address(address, &destination, ip) != 0) {
        return qoe_binding_store(address, policy_prio, 0,
                                 now_ms + FLOWD_QOE_NO_GEO_TTL_MS,
                                 now_ms, 0) == 0;
    }
    entry = flowd_qoe_cache_lookup(&g_qoe.cache, &destination, policy_prio,
                                   now_ms, &scope);
    wan_id = qoe_entry_wan(entry);
    if (!wan_id)
        return 0;
    if (qoe_bind_address(address, policy_prio, wan_id, now_ms,
                         entry->valid_until_ms) == 0) {
        g_qoe.cache_routes++;
        return 1;
    }
    return 0;
}

static int qoe_ipv6_public(const struct in6_addr *address)
{
    if (!qoe_ipv6_source_usable(address))
        return 0;
    return !(address->s6_addr[0] == 0x20 && address->s6_addr[1] == 0x01 &&
             address->s6_addr[2] == 0x0d && address->s6_addr[3] == 0xb8);
}

static int qoe_conntrack_candidate(const struct nf_conntrack *ct,
                                   struct flowd_qoe_address *address,
                                   uint16_t *port, uint16_t *policy_prio)
{
    uint32_t src;
    uint32_t dst;
    const void *src6;
    const void *dst6;
    uint8_t family;
    uint16_t dport;
    uint8_t tcp_state;

    uint32_t mark;

    if (!ct || !address || !port || !policy_prio ||
        !nfct_attr_is_set(ct, ATTR_ORIG_L3PROTO) ||
        !nfct_attr_is_set(ct, ATTR_ORIG_L4PROTO) ||
        !nfct_attr_is_set(ct, ATTR_ORIG_PORT_DST) ||
        !nfct_attr_is_set(ct, ATTR_MARK) ||
        !nfct_attr_is_set(ct, ATTR_TCP_STATE) ||
        nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO) != IPPROTO_TCP)
        return 0;
    mark = nfct_get_attr_u32(ct, ATTR_MARK);
    *policy_prio = (uint16_t)(mark >> 16);
    if (!qoe_policy_effective(qoe_policy_by_prio(*policy_prio)))
        return 0;
    family = nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO);
    tcp_state = nfct_get_attr_u8(ct, ATTR_TCP_STATE);
    if (tcp_state != TCP_CONNTRACK_SYN_SENT &&
        tcp_state != TCP_CONNTRACK_ESTABLISHED)
        return 0;
    dport = ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST));
    if (!dport)
        return 0;
    if (family == AF_INET) {
        if (!nfct_attr_is_set(ct, ATTR_ORIG_IPV4_SRC) ||
            !nfct_attr_is_set(ct, ATTR_ORIG_IPV4_DST))
            return 0;
        src = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
        dst = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);
        if (!qoe_ipv4_private(src) || !qoe_ipv4_public(dst) ||
            flowd_qoe_address_set(address, AF_INET, &dst) != 0)
            return 0;
    } else if (family == AF_INET6) {
        if (!nfct_attr_is_set(ct, ATTR_ORIG_IPV6_SRC) ||
            !nfct_attr_is_set(ct, ATTR_ORIG_IPV6_DST))
            return 0;
        src6 = nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC);
        dst6 = nfct_get_attr(ct, ATTR_ORIG_IPV6_DST);
        if (!src6 || !dst6 ||
            (((const struct in6_addr *)src6)->s6_addr[0] & 0xfeU) != 0xfcU ||
            !qoe_ipv6_public((const struct in6_addr *)dst6) ||
            flowd_qoe_address_set(address, AF_INET6, dst6) != 0)
            return 0;
    } else {
        return 0;
    }
    *port = dport;
    return 1;
}

static void qoe_conntrack_stop(void);

static void qoe_conntrack_fd_cb(struct uloop_fd *fd, unsigned int events)
{
    unsigned char buffer[FLOWD_QOE_CONNTRACK_BATCH_BYTES];
    struct iovec iov = { .iov_base = buffer, .iov_len = sizeof(buffer) };
    struct msghdr msg;
    struct nlmsghdr *nlh;
    ssize_t received;
    int remaining;

    (void)events;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    received = recvmsg(fd->fd, &msg, MSG_DONTWAIT);
    if (received < 0 && errno == EINTR)
        received = recvmsg(fd->fd, &msg, MSG_DONTWAIT);
    if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        return;
    if (received < 0) {
        if (errno == ENOBUFS)
            g_qoe.conntrack_enobufs++;
        g_qoe.conntrack_errors++;
        qoe_error_set(errno == ENOBUFS ? "conntrack_event_loss" :
                                      "conntrack_event_read_failed");
        if (errno != ENOBUFS)
            qoe_conntrack_stop();
        return;
    }
    if (!received)
        return;
    if (msg.msg_flags & MSG_TRUNC) {
        g_qoe.conntrack_errors++;
        qoe_error_set("conntrack_event_truncated");
        return;
    }

    remaining = (int)received;
    for (nlh = (struct nlmsghdr *)buffer; NLMSG_OK(nlh, remaining);
         nlh = NLMSG_NEXT(nlh, remaining)) {
        struct nf_conntrack *ct;
        struct flowd_qoe_address address;
        uint16_t port = 0;
        uint16_t policy_prio = 0;

        memset(&address, 0, sizeof(address));

        if (nlh->nlmsg_type == NLMSG_ERROR) {
            g_qoe.conntrack_errors++;
            continue;
        }
        if (NFNL_SUBSYS_ID(nlh->nlmsg_type) != NFNL_SUBSYS_CTNETLINK ||
            NFNL_MSG_TYPE(nlh->nlmsg_type) != IPCTNL_MSG_CT_NEW ||
            !(nlh->nlmsg_flags & (NLM_F_CREATE | NLM_F_EXCL))) {
            g_qoe.conntrack_filtered++;
            continue;
        }
        ct = nfct_new();
        if (!ct) {
            g_qoe.conntrack_errors++;
            continue;
        }
        if (nfct_nlmsg_parse(nlh, ct) != 0 ||
            !qoe_conntrack_candidate(ct, &address, &port, &policy_prio)) {
            g_qoe.conntrack_filtered++;
            nfct_destroy(ct);
            continue;
        }
        nfct_destroy(ct);
        g_qoe.conntrack_events++;
        g_qoe.candidates_seen++;
        (void)qoe_queue_push(&address, port, policy_prio);
    }
}

static int qoe_conntrack_start(void)
{
    int flags;
    int requested = FLOWD_QOE_CONNTRACK_RCVBUF_BYTES;
    int fd;

    if (g_qoe.conntrack)
        return 0;
    g_qoe.conntrack = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_NEW);
    if (!g_qoe.conntrack) {
        qoe_error_set("conntrack_event_open_failed");
        return -1;
    }
    fd = nfct_fd(g_qoe.conntrack);
    if (fd < 0) {
        qoe_error_set("conntrack_event_fd_failed");
        qoe_conntrack_stop();
        return -1;
    }
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &requested, sizeof(requested));
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0 ||
        fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
        qoe_error_set("conntrack_event_nonblock_failed");
        qoe_conntrack_stop();
        return -1;
    }
    memset(&g_qoe.conntrack_fd, 0, sizeof(g_qoe.conntrack_fd));
    g_qoe.conntrack_fd.fd = fd;
    g_qoe.conntrack_fd.cb = qoe_conntrack_fd_cb;
    if (uloop_fd_add(&g_qoe.conntrack_fd, ULOOP_READ) != 0) {
        qoe_error_set("conntrack_event_uloop_failed");
        g_qoe.conntrack_fd.fd = -1;
        qoe_conntrack_stop();
        return -1;
    }
    qoe_error_set("");
    return 0;
}

static void qoe_conntrack_stop(void)
{
    if (!g_qoe.conntrack)
        return;
    if (g_qoe.conntrack_fd.fd >= 0)
        uloop_fd_delete(&g_qoe.conntrack_fd);
    nfct_close(g_qoe.conntrack);
    g_qoe.conntrack = NULL;
    memset(&g_qoe.conntrack_fd, 0, sizeof(g_qoe.conntrack_fd));
    g_qoe.conntrack_fd.fd = -1;
}

static void qoe_fail_over_wan(uint8_t wan_id, uint64_t now_ms)
{
    size_t i;

    (void)flowd_qoe_cache_mark_wan_down(&g_qoe.cache, wan_id, now_ms);
    for (i = 0; i < FLOWD_QOE_BINDING_CAPACITY; i++) {
        struct flowd_qoe_binding *binding = &g_qoe.bindings[i];

        if (!binding->used || binding->valid_until_ms <= now_ms ||
            binding->wan_id != wan_id)
            continue;
        if (qoe_route_from_cache(&binding->address, binding->policy_prio,
                                 now_ms)) {
            g_qoe.health_failovers++;
        } else {
            if (qoe_nft_unbind(binding->policy_prio, binding->wan_id,
                               &binding->address) != 0)
                g_qoe.nft_failures++;
            binding->valid_until_ms = now_ms;
        }
    }
}

static int qoe_refresh_wan_health(uint64_t now_ms)
{
    uint8_t down_ids[FLOWD_QOE_MAX_WANS];
    size_t down_count = 0;
    size_t i;
    int topology_changed;

    topology_changed = qoe_refresh_wan_table(down_ids, &down_count);
    if (topology_changed < 0)
        return -1;
    for (i = 0; i < down_count; i++)
        qoe_fail_over_wan(down_ids[i], now_ms);
    return topology_changed;
}

static int qoe_probe_child(const struct flowd_qoe_address *address,
                           uint16_t port, uint16_t policy_prio, int result_fd)
{
    struct flowd_qoe_probe_result result;
    struct flowd_qoe_probe_result_wire wire;
    struct sockaddr_storage target;
    socklen_t target_len;
    struct pollfd pfds[FLOWD_QOE_PROBE_PATHS];
    uint64_t started[FLOWD_QOE_PROBE_PATHS] = {0};
    int sockets[FLOWD_QOE_PROBE_PATHS];
    const struct flowd_qoe_policy_runtime *policy =
        qoe_policy_by_prio(policy_prio);
    int path_count = policy ? (int)policy->member_count : 0;
    uint64_t deadline;
    int pending = 0;
    int i;

    memset(&result, 0, sizeof(result));
    memset(&wire, 0, sizeof(wire));
    memset(&target, 0, sizeof(target));
    memset(pfds, 0, sizeof(pfds));
    for (i = 0; i < (int)FLOWD_QOE_PROBE_PATHS; i++)
        sockets[i] = -1;
    if (path_count > (int)FLOWD_QOE_PROBE_PATHS)
        path_count = (int)FLOWD_QOE_PROBE_PATHS;
    result.address = *address;
    result.port = port;
    result.path_count = (uint16_t)path_count;
    target_len = address->family == AF_INET ? sizeof(struct sockaddr_in) :
                 sizeof(struct sockaddr_in6);
    if (address->family == AF_INET) {
        struct sockaddr_in *target4 = (struct sockaddr_in *)&target;

        target4->sin_family = AF_INET;
        memcpy(&target4->sin_addr, address->bytes, sizeof(target4->sin_addr));
        target4->sin_port = htons(port);
    } else if (address->family == AF_INET6) {
        struct sockaddr_in6 *target6 = (struct sockaddr_in6 *)&target;

        target6->sin6_family = AF_INET6;
        memcpy(&target6->sin6_addr, address->bytes, sizeof(target6->sin6_addr));
        target6->sin6_port = htons(port);
    } else {
        return 1;
    }

    for (i = 0; i < (int)FLOWD_QOE_PROBE_PATHS; i++)
        pfds[i].fd = -1;
    for (i = 0; i < path_count; i++) {
        struct flowd_qoe_path *path_result = &result.paths[i];
        const struct flowd_qoe_wan_runtime *wan =
            qoe_wan_by_id(policy->members[i]);
        int flags;
        int rc;

        if (!wan)
            continue;
        path_result->wan_id = wan->id;
        path_result->confidence = 100;
        /* No resolved L3 device means SO_BINDTODEVICE cannot pin this uplink;
         * leave the path unhealthy rather than probing an unbound socket. */
        if (!wan->ifname[0])
            continue;
        sockets[i] = socket(address->family, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
        if (sockets[i] < 0)
            continue;
        if (setsockopt(sockets[i], SOL_SOCKET, SO_MARK,
                       &wan->fwmark, sizeof(wan->fwmark)) != 0 ||
            setsockopt(sockets[i], SOL_SOCKET, SO_BINDTODEVICE,
                       wan->ifname, strlen(wan->ifname) + 1) != 0) {
            close(sockets[i]);
            sockets[i] = -1;
            continue;
        }
        if (address->family == AF_INET6) {
            struct sockaddr_in6 source6;

            if (!wan->ipv6_source_valid) {
                close(sockets[i]);
                sockets[i] = -1;
                continue;
            }
            memset(&source6, 0, sizeof(source6));
            source6.sin6_family = AF_INET6;
            source6.sin6_addr = wan->ipv6_source;
            if (bind(sockets[i], (struct sockaddr *)&source6, sizeof(source6)) != 0) {
                close(sockets[i]);
                sockets[i] = -1;
                continue;
            }
        }
        flags = fcntl(sockets[i], F_GETFL, 0);
        if (flags < 0 || fcntl(sockets[i], F_SETFL, flags | O_NONBLOCK) != 0) {
            close(sockets[i]);
            sockets[i] = -1;
            continue;
        }
        started[i] = qoe_monotonic_ms();
        rc = connect(sockets[i], (struct sockaddr *)&target, target_len);
        if (rc == 0) {
            path_result->healthy = 1;
            path_result->rtt_us = 1;
            close(sockets[i]);
            sockets[i] = -1;
            continue;
        }
        if (errno != EINPROGRESS) {
            close(sockets[i]);
            sockets[i] = -1;
            continue;
        }
        pfds[i].fd = sockets[i];
        pfds[i].events = POLLOUT;
        pending++;
    }

    deadline = qoe_monotonic_ms() + FLOWD_QOE_PROBE_TIMEOUT_MS;
    while (pending > 0) {
        uint64_t now = qoe_monotonic_ms();
        int timeout = now >= deadline ? 0 : (int)(deadline - now);
        int rc = poll(pfds, (nfds_t)path_count, timeout);

        if (rc <= 0)
            break;
        for (i = 0; i < path_count; i++) {
            struct flowd_qoe_path *path_result = &result.paths[i];
            int error = 0;
            socklen_t error_len = sizeof(error);
            uint64_t elapsed;

            if (pfds[i].fd < 0 || !(pfds[i].revents & (POLLOUT | POLLERR | POLLHUP)))
                continue;
            elapsed = qoe_monotonic_ms() - started[i];
            if (getsockopt(pfds[i].fd, SOL_SOCKET, SO_ERROR, &error, &error_len) == 0 &&
                error == 0) {
                uint64_t rtt_us = elapsed * 1000ULL;

                path_result->healthy = 1;
                path_result->rtt_us = rtt_us > UINT32_MAX ? UINT32_MAX : (uint32_t)rtt_us;
            }
            close(pfds[i].fd);
            sockets[i] = -1;
            pfds[i].fd = -1;
            pending--;
        }
    }
    for (i = 0; i < (int)FLOWD_QOE_PROBE_PATHS; i++)
        if (sockets[i] >= 0)
            close(sockets[i]);
    wire.magic = FLOWD_QOE_PROBE_MAGIC;
    wire.version = FLOWD_QOE_PROBE_VERSION;
    wire.wire_size = sizeof(wire);
    wire.family = result.address.family;
    memcpy(wire.address, result.address.bytes, sizeof(wire.address));
    wire.port = result.port;
    wire.path_count = result.path_count;
    for (i = 0; i < result.path_count; i++) {
        wire.paths[i].wan_id = result.paths[i].wan_id;
        wire.paths[i].healthy = result.paths[i].healthy;
        wire.paths[i].confidence = result.paths[i].confidence;
        wire.paths[i].rtt_us = result.paths[i].rtt_us;
        wire.paths[i].penalty_us = result.paths[i].penalty_us;
        wire.paths[i].score_us = result.paths[i].score_us;
    }
    do {
        i = (int)send(result_fd, &wire, sizeof(wire), MSG_NOSIGNAL);
    } while (i < 0 && errno == EINTR);
    if (i != (int)sizeof(wire))
        return 1;
    return 0;
}

static int qoe_probe_result_decode(const struct flowd_qoe_probe_result_wire *wire,
                                   struct flowd_qoe_probe_result *result)
{
    uint8_t seen[UINT8_MAX + 1] = {0};
    size_t seen_count = 0;
    int i;

    if (!wire || !result || wire->magic != FLOWD_QOE_PROBE_MAGIC ||
        wire->version != FLOWD_QOE_PROBE_VERSION ||
        wire->wire_size != sizeof(*wire) || wire->reserved != 0 ||
        wire->family != g_qoe.active_candidate.address.family ||
        memcmp(wire->address, g_qoe.active_candidate.address.bytes,
               sizeof(wire->address)) != 0 ||
        wire->port != g_qoe.active_candidate.port ||
        !wire->path_count || wire->path_count > FLOWD_QOE_PROBE_PATHS)
        return -1;
    memset(result, 0, sizeof(*result));
    if (wire->family != AF_INET && wire->family != AF_INET6)
        return -1;
    result->address.family = (uint8_t)wire->family;
    memcpy(result->address.bytes, wire->address, sizeof(result->address.bytes));
    result->port = (uint16_t)wire->port;
    result->path_count = (uint16_t)wire->path_count;
    for (i = 0; i < (int)wire->path_count; i++) {
        const struct flowd_qoe_probe_path_wire *in = &wire->paths[i];
        struct flowd_qoe_path *out = &result->paths[i];
        /* wan_id is an identifier, not a slot index: validate it against the
         * live WAN table instead of the path-array bound. */
        if (!in->wan_id || in->wan_id > UINT8_MAX ||
            !qoe_wan_by_id((uint8_t)in->wan_id) ||
            !qoe_policy_has_wan(qoe_policy_by_prio(
                                    g_qoe.active_candidate.policy_prio),
                                (uint8_t)in->wan_id) ||
            in->healthy > 1 || in->confidence > 100)
            return -1;
        if (seen[in->wan_id])
            return -1;
        seen[in->wan_id] = 1;
        seen_count++;
        out->wan_id = (uint8_t)in->wan_id;
        out->healthy = (uint8_t)in->healthy;
        out->confidence = (uint16_t)in->confidence;
        out->rtt_us = in->rtt_us;
        out->penalty_us = in->penalty_us;
        out->score_us = in->score_us;
    }
    return seen_count == wire->path_count ? 0 : -1;
}

static void qoe_probe_channel_close(void)
{
    if (g_qoe.probe_result_fd.fd < 0)
        return;
    uloop_fd_delete(&g_qoe.probe_result_fd);
    close(g_qoe.probe_result_fd.fd);
    g_qoe.probe_result_fd.fd = -1;
}

static void qoe_probe_finish(void)
{
    struct flowd_qoe_probe_result *result = &g_qoe.probe_result;
    struct flowd_qoe_destination destination;
    enum flowd_qoe_scope scope;
    uint64_t key;
    uint64_t now_ms = qoe_monotonic_ms();
    char ip[INET6_ADDRSTRLEN];
    const struct flowd_qoe_entry *entry;
    uint8_t wan_id;
    int successes = 0;
    uint16_t policy_prio = g_qoe.active_candidate.policy_prio;
    int i;

    if (!g_qoe.probe_active || !g_qoe.probe_child_done ||
        (!g_qoe.probe_result_ready && !g_qoe.probe_result_eof))
        return;
    qoe_probe_channel_close();
    g_qoe.probe_active = 0;
    if (!WIFEXITED(g_qoe.probe_child_status) ||
        WEXITSTATUS(g_qoe.probe_child_status) != 0 ||
        !g_qoe.probe_result_ready ||
        qoe_destination_for_address(&result->address, &destination, ip) != 0) {
        g_qoe.probe_failures++;
        g_qoe.probe_child_failures++;
        qoe_negative_binding_store(&g_qoe.active_candidate.address, policy_prio,
                                   now_ms);
        goto done;
    }
    for (i = 0; i < result->path_count && i < (int)FLOWD_QOE_PROBE_PATHS; i++) {
        uint8_t id = result->paths[i].wan_id;

        if (id && (!qoe_wan_healthy(id) ||
                   !qoe_policy_has_wan(qoe_policy_by_prio(policy_prio), id)))
            result->paths[i].healthy = 0;
        if (result->paths[i].healthy)
            successes++;
    }
    if (!successes) {
        g_qoe.probe_failures++;
        g_qoe.probe_no_healthy_path++;
        qoe_negative_binding_store(&result->address, policy_prio, now_ms);
        goto done;
    }
    scope = destination.city_id ? FLOWD_QOE_SCOPE_CITY :
            (destination.country_id ? FLOWD_QOE_SCOPE_COUNTRY : FLOWD_QOE_SCOPE_ASN);
    key = flowd_qoe_key(destination.asn,
                        scope == FLOWD_QOE_SCOPE_CITY ? destination.city_id :
                        (scope == FLOWD_QOE_SCOPE_COUNTRY ? destination.country_id : 0));
    if (flowd_qoe_cache_record(&g_qoe.cache, scope, destination.family, key,
                               policy_prio,
                               result->paths,
                               result->path_count, now_ms, FLOWD_QOE_DEFAULT_TTL_MS) != 0) {
        g_qoe.probe_failures++;
        g_qoe.probe_cache_record_failures++;
        goto done;
    }
    entry = flowd_qoe_cache_lookup(&g_qoe.cache, &destination, policy_prio,
                                   now_ms, NULL);
    wan_id = qoe_entry_wan(entry);
    if (!wan_id || qoe_bind_address(&result->address, policy_prio, wan_id, now_ms,
                                    entry->valid_until_ms) != 0) {
        g_qoe.probe_failures++;
        g_qoe.probe_bind_failures++;
        goto done;
    }
    g_qoe.probe_successes++;
    g_qoe.last_probe_at_ms = now_ms;
    snprintf(g_qoe.last_probe_ip, sizeof(g_qoe.last_probe_ip), "%s", ip);
done:
    memset(&g_qoe.probe_result, 0, sizeof(g_qoe.probe_result));
    g_qoe.probe_result_ready = 0;
    g_qoe.probe_result_eof = 0;
    g_qoe.probe_child_done = 0;
    g_qoe.probe_child_status = 0;
    memset(&g_qoe.active_candidate, 0, sizeof(g_qoe.active_candidate));
}

static void qoe_probe_result_fd_cb(struct uloop_fd *fd, unsigned int events)
{
    struct flowd_qoe_probe_result_wire wire;
    struct iovec iov = { .iov_base = &wire, .iov_len = sizeof(wire) };
    struct msghdr msg;
    ssize_t received;

    (void)events;
    memset(&wire, 0, sizeof(wire));
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    received = recvmsg(fd->fd, &msg, MSG_DONTWAIT);
    if (received < 0 && errno == EINTR)
        received = recvmsg(fd->fd, &msg, MSG_DONTWAIT);
    if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        return;
    if (received == (ssize_t)sizeof(wire) && !(msg.msg_flags & MSG_TRUNC) &&
        qoe_probe_result_decode(&wire, &g_qoe.probe_result) == 0) {
        g_qoe.probe_result_ready = 1;
    } else {
        g_qoe.probe_result_eof = 1;
        qoe_error_set(received == 0 ? "probe_result_eof" : "probe_result_invalid");
    }
    qoe_probe_channel_close();
    qoe_probe_finish();
}

static void qoe_probe_done(struct uloop_process *process, int status)
{
    (void)process;
    g_qoe.probe_child_done = 1;
    g_qoe.probe_child_status = status;
    memset(&g_qoe.probe_process, 0, sizeof(g_qoe.probe_process));
    if (g_qoe.probe_result_fd.fd >= 0)
        qoe_probe_result_fd_cb(&g_qoe.probe_result_fd, ULOOP_READ);
    qoe_probe_finish();
}

static void qoe_probe_abort(void)
{
    if (g_qoe.probe_active) {
        uloop_process_delete(&g_qoe.probe_process);
        kill(g_qoe.probe_process.pid, SIGTERM);
        while (waitpid(g_qoe.probe_process.pid, NULL, 0) < 0 && errno == EINTR)
            ;
    }
    qoe_probe_channel_close();
    memset(&g_qoe.probe_process, 0, sizeof(g_qoe.probe_process));
    memset(&g_qoe.probe_result, 0, sizeof(g_qoe.probe_result));
    memset(&g_qoe.active_candidate, 0, sizeof(g_qoe.active_candidate));
    g_qoe.probe_active = 0;
    g_qoe.probe_result_ready = 0;
    g_qoe.probe_result_eof = 0;
    g_qoe.probe_child_done = 0;
    g_qoe.probe_child_status = 0;
}

static void qoe_probe_start(uint64_t now_ms)
{
    struct flowd_qoe_candidate candidate = {0};
    int pair[2] = {-1, -1};
    unsigned int examined = 0;
    int selected = 0;
    const struct flowd_qoe_policy_runtime *policy = NULL;
    size_t probe_paths = 0;
    pid_t pid;
    int i;

    if (g_qoe.probe_active || !g_qoe.queue_count || !g_qoe_wan_count)
        return;
    while (g_qoe.queue_count && examined++ < FLOWD_QOE_CANDIDATES_PER_TICK) {
        if (qoe_queue_pop(&candidate) != 0)
            return;
        policy = qoe_policy_by_prio(candidate.policy_prio);
        if (!qoe_policy_effective(policy))
            continue;
        probe_paths = policy->member_count;
        if (flowd_qoe_token_bucket_available(&g_qoe.probes, now_ms) < probe_paths)
            return;
        if (qoe_binding_find(&candidate.address, candidate.policy_prio, now_ms))
            continue;
        if (qoe_route_from_cache(&candidate.address, candidate.policy_prio, now_ms))
            continue;
        selected = 1;
        break;
    }
    if (!selected)
        return;
    for (i = 0; i < (int)probe_paths; i++)
        if (!flowd_qoe_token_bucket_take(&g_qoe.probes, now_ms))
            return;
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK,
                   0, pair) != 0) {
        g_qoe.probe_failures++;
        g_qoe.probe_setup_failures++;
        qoe_negative_binding_store(&candidate.address, candidate.policy_prio,
                                   now_ms);
        return;
    }
    g_qoe.active_candidate = candidate;
    memset(&g_qoe.probe_result, 0, sizeof(g_qoe.probe_result));
    g_qoe.probe_result_ready = 0;
    g_qoe.probe_result_eof = 0;
    g_qoe.probe_child_done = 0;
    g_qoe.probe_child_status = 0;
    pid = fork();
    if (pid < 0) {
        close(pair[0]);
        close(pair[1]);
        g_qoe.probe_failures++;
        g_qoe.probe_setup_failures++;
        qoe_negative_binding_store(&candidate.address, candidate.policy_prio,
                                   now_ms);
        memset(&g_qoe.active_candidate, 0, sizeof(g_qoe.active_candidate));
        return;
    }
    if (pid == 0) {
        close(pair[0]);
        signal(SIGINT, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        _exit(qoe_probe_child(&candidate.address, candidate.port,
                              candidate.policy_prio, pair[1]));
    }
    close(pair[1]);
    memset(&g_qoe.probe_result_fd, 0, sizeof(g_qoe.probe_result_fd));
    g_qoe.probe_result_fd.fd = pair[0];
    g_qoe.probe_result_fd.cb = qoe_probe_result_fd_cb;
    if (uloop_fd_add(&g_qoe.probe_result_fd, ULOOP_READ) != 0) {
        close(pair[0]);
        g_qoe.probe_result_fd.fd = -1;
        kill(pid, SIGTERM);
        while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
            ;
        g_qoe.probe_failures++;
        g_qoe.probe_setup_failures++;
        qoe_negative_binding_store(&candidate.address, candidate.policy_prio,
                                   now_ms);
        memset(&g_qoe.active_candidate, 0, sizeof(g_qoe.active_candidate));
        return;
    }
    memset(&g_qoe.probe_process, 0, sizeof(g_qoe.probe_process));
    g_qoe.probe_process.pid = pid;
    g_qoe.probe_process.cb = qoe_probe_done;
    if (uloop_process_add(&g_qoe.probe_process) != 0) {
        kill(pid, SIGTERM);
        while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
            ;
        qoe_probe_channel_close();
        memset(&g_qoe.probe_process, 0, sizeof(g_qoe.probe_process));
        g_qoe.probe_failures++;
        g_qoe.probe_setup_failures++;
        qoe_negative_binding_store(&candidate.address, candidate.policy_prio,
                                   now_ms);
        memset(&g_qoe.active_candidate, 0, sizeof(g_qoe.active_candidate));
        return;
    }
    g_qoe.probe_active = 1;
    g_qoe.probe_jobs++;
}

static void qoe_runtime_clear_learned(void)
{
    qoe_probe_abort();
    flowd_qoe_cache_clear(&g_qoe.cache);
    memset(g_qoe.bindings, 0, sizeof(g_qoe.bindings));
    memset(g_qoe.queue, 0, sizeof(g_qoe.queue));
    g_qoe.queue_head = 0;
    g_qoe.queue_tail = 0;
    g_qoe.queue_count = 0;
}

static int qoe_reconcile_enabled(void)
{
    int policy_changed = qoe_refresh_policy_table();
    int desired;

    if (policy_changed < 0) {
        qoe_error_set("policy_config_unavailable");
        return -1;
    }
    desired = qoe_any_policy_requested();

    g_qoe.enabled_requested = desired;
    if (policy_changed > 0) {
        qoe_conntrack_stop();
        qoe_runtime_clear_learned();
        g_qoe.nft_active = 0;
        g_qoe.nft_readback_ok = 0;
    }
    if (!desired) {
        if (dw_mp_compact()) {
            if (g_qoe.city_open) { MMDB_close(&g_qoe.city_db); g_qoe.city_open = 0; }
            if (g_qoe.asn_open) { MMDB_close(&g_qoe.asn_db); g_qoe.asn_open = 0; }
        }
        qoe_conntrack_stop();
        if (!g_qoe.disabled_cleanup_done || g_qoe.nft_active) {
            if (qoe_nft_delete() != 0) {
                qoe_error_set("nft_disable_failed");
                return -1;
            }
            g_qoe.disabled_cleanup_done = 1;
        }
        qoe_error_set("");
        qoe_runtime_clear_learned();
        g_qoe.nft_active = 0;
        g_qoe.nft_readback_ok = 0;
        return 0;
    }
    g_qoe.disabled_cleanup_done = 0;
    /* An enabled policy is an actual consumer; compact mode only avoids the
     * eager mapping when no policy is using it. Never disable active QoE. */
    if (!g_qoe.city_open) g_qoe.city_open = qoe_mmdb_open(FLOWD_QOE_CITY_MMDB, &g_qoe.city_db);
    if (!g_qoe.asn_open) g_qoe.asn_open = qoe_mmdb_open(FLOWD_QOE_ASN_MMDB, &g_qoe.asn_db);
    if (!g_qoe.city_open || !g_qoe.asn_open) {
        qoe_error_set("city_or_asn_mmdb_unavailable");
        return -1;
    }
    /* Discover uplinks before the first probe so the WAN table is never empty. */
    if (!g_qoe_wan_count) {
        qoe_refresh_wan_table(NULL, NULL);
        if (!g_qoe_wan_count) {
            qoe_error_set("wan_table_unavailable");
            return -1;
        }
    }
    if (!g_qoe.nft_active) {
        if (qoe_nft_install() == 0)
            g_qoe.nft_active = 1;
        else
            g_qoe.nft_failures++;
    }
    if (g_qoe.nft_active && !g_qoe.conntrack && qoe_conntrack_start() != 0)
        return -1;
    return g_qoe.nft_active && g_qoe.nft_readback_ok && g_qoe.conntrack ? 0 : -1;
}

static void qoe_tick(struct uloop_timeout *timeout)
{
    uint64_t now_ms = qoe_monotonic_ms();

    qoe_reconcile_enabled();
    if (g_qoe.nft_active) {
        int topology_changed = qoe_refresh_wan_health(now_ms);

        if (topology_changed > 0) {
            qoe_conntrack_stop();
            qoe_probe_abort();
            flowd_qoe_cache_clear(&g_qoe.cache);
            memset(g_qoe.queue, 0, sizeof(g_qoe.queue));
            g_qoe.queue_head = 0;
            g_qoe.queue_tail = 0;
            g_qoe.queue_count = 0;
            if (qoe_nft_install() != 0) {
                g_qoe.nft_active = 0;
                g_qoe.nft_failures++;
                qoe_error_set("wan_topology_rebuild_failed");
            } else if (qoe_conntrack_start() != 0) {
                g_qoe.nft_active = 0;
            }
        }
        if (!g_qoe.nft_active)
            goto reschedule;
        qoe_probe_start(now_ms);
        if (now_ms - g_qoe.last_readback_ms >= FLOWD_QOE_READBACK_INTERVAL_MS) {
            g_qoe.nft_readback_ok = qoe_nft_readback_all();
            g_qoe.last_readback_ms = now_ms;
            if (!g_qoe.nft_readback_ok) {
                qoe_conntrack_stop();
                g_qoe.nft_active = 0;
                qoe_error_set("nft_runtime_readback_failed");
            }
        }
    }
reschedule:
    uloop_timeout_set(timeout, FLOWD_QOE_TICK_MS);
}

int flowd_qoe_runtime_init(void)
{
    uint64_t now_ms;

    if (g_qoe.initialized)
        return 0;
    memset(&g_qoe, 0, sizeof(g_qoe));
    g_qoe.conntrack_fd.fd = -1;
    g_qoe.probe_result_fd.fd = -1;
    if (flowd_qoe_cache_init(&g_qoe.cache, FLOWD_QOE_DEFAULT_CAPACITY) != 0)
        return -1;
    g_qoe.nft = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!g_qoe.nft || nft_ctx_buffer_output(g_qoe.nft) != 0 ||
        nft_ctx_buffer_error(g_qoe.nft) != 0) {
        if (g_qoe.nft)
            nft_ctx_free(g_qoe.nft);
        g_qoe.nft = NULL;
        flowd_qoe_cache_destroy(&g_qoe.cache);
        return -1;
    }
    nft_ctx_input_set_flags(g_qoe.nft,
                            nft_ctx_input_get_flags(g_qoe.nft) |
                            NFT_CTX_INPUT_NO_DNS);
    now_ms = qoe_monotonic_ms();
    flowd_qoe_token_bucket_init(&g_qoe.probes,
                                 FLOWD_QOE_DEFAULT_PROBE_RATE,
                                 FLOWD_QOE_DEFAULT_PROBE_BURST,
                                 now_ms);
    if (!dw_mp_compact()) {
        g_qoe.city_open = qoe_mmdb_open(FLOWD_QOE_CITY_MMDB, &g_qoe.city_db);
        g_qoe.asn_open = qoe_mmdb_open(FLOWD_QOE_ASN_MMDB, &g_qoe.asn_db);
    }
    g_qoe.initialized = 1;
    return 0;
}

int flowd_qoe_runtime_start(void)
{
    if (!g_qoe.initialized || g_qoe.started)
        return g_qoe.initialized ? 0 : -1;
    memset(&g_qoe.tick, 0, sizeof(g_qoe.tick));
    g_qoe.tick.cb = qoe_tick;
    g_qoe.started = 1;
    qoe_reconcile_enabled();
    uloop_timeout_set(&g_qoe.tick, FLOWD_QOE_TICK_MS);
    return 0;
}

struct json_object *flowd_qoe_reconcile_json(void)
{
    struct json_object *status;
    int rc;

    if (!g_qoe.initialized)
        rc = -1;
    else
        rc = qoe_reconcile_enabled();
    status = flowd_qoe_status_json();
    json_object_object_add(status, "reconcile_ok", json_object_new_boolean(rc == 0));
    json_object_object_add(status, "reconcile_reason",
                           json_object_new_string(rc == 0 ? "runtime_matches_config" :
                                                  (g_qoe.last_error[0] ?
                                                   g_qoe.last_error :
                                                   "runtime_reconcile_failed")));
    return status;
}

void flowd_qoe_runtime_close(void)
{
    if (!g_qoe.initialized)
        return;
    if (g_qoe.started)
        uloop_timeout_cancel(&g_qoe.tick);
    qoe_conntrack_stop();
    qoe_probe_abort();
    (void)qoe_nft_delete();
    if (g_qoe.city_open)
        MMDB_close(&g_qoe.city_db);
    if (g_qoe.asn_open)
        MMDB_close(&g_qoe.asn_db);
    if (g_qoe.nft)
        nft_ctx_free(g_qoe.nft);
    flowd_qoe_cache_destroy(&g_qoe.cache);
    memset(&g_qoe, 0, sizeof(g_qoe));
}

static size_t qoe_binding_count(uint64_t now_ms, uint8_t wan_id)
{
    size_t count = 0;
    size_t i;

    for (i = 0; i < FLOWD_QOE_BINDING_CAPACITY; i++) {
        const struct flowd_qoe_binding *binding = &g_qoe.bindings[i];

        if (binding->used && binding->wan_id && binding->valid_until_ms > now_ms &&
            (!wan_id || binding->wan_id == wan_id))
            count++;
    }
    return count;
}

struct json_object *flowd_qoe_status_json(void)
{
    struct json_object *status = json_object_new_object();
    struct json_object *capabilities = json_object_new_object();
    struct json_object *bindings = json_object_new_object();
    struct json_object *policy_runtime = json_object_new_array();
    uint64_t now_ms = qoe_monotonic_ms();
    uint32_t available = g_qoe.initialized
        ? flowd_qoe_token_bucket_available(&g_qoe.probes, now_ms) : 0;
    int active = g_qoe.initialized && g_qoe.enabled_requested &&
                 g_qoe.city_open && g_qoe.asn_open &&
                 g_qoe.nft_active && g_qoe.nft_readback_ok &&
                 g_qoe.conntrack != NULL;
    int i;

    json_object_object_add(status, "foundation_ready",
                           json_object_new_boolean(g_qoe.initialized));
    json_object_object_add(status, "scheduler_active", json_object_new_boolean(active));
    json_object_object_add(status, "phase",
                           json_object_new_string(active ? "canary-active" : "foundation"));
    json_object_object_add(status, "fallback_mode", json_object_new_string("hash_src_dst"));
    json_object_object_add(status, "key_model", json_object_new_string("asn+city/country/asn"));
    json_object_object_add(status, "enable_file", json_object_new_string(FLOWD_QOE_ENABLE_FILE));
    json_object_object_add(status, "enabled_requested",
                           json_object_new_boolean(g_qoe.enabled_requested));
    json_object_object_add(status, "global_enabled_requested",
                           json_object_new_boolean(g_qoe_global_requested));
    json_object_object_add(status, "policy_scoped", json_object_new_boolean(1));
    json_object_object_add(status, "policy_config_ready",
                           json_object_new_boolean(g_qoe_policy_ready));
    json_object_object_add(status, "policy_config_revision",
                           json_object_new_int64((int64_t)g_qoe_policy_revision));
    json_object_object_add(status, "confirmed",
                           json_object_new_boolean(access(FLOWD_QOE_CONFIRM_FILE, F_OK) == 0));
    json_object_object_add(status, "last_error",
                           json_object_new_string(g_qoe.last_error));
    json_object_object_add(status, "cache_capacity",
                           json_object_new_int64((int64_t)g_qoe.cache.capacity));
    json_object_object_add(status, "cache_entries",
                           json_object_new_int64((int64_t)g_qoe.cache.count));
    json_object_object_add(status, "cache_bytes",
                           json_object_new_int64((int64_t)(g_qoe.cache.capacity *
                                                          sizeof(struct flowd_qoe_entry))));
    json_object_object_add(status, "cache_lookups",
                           json_object_new_int64((int64_t)g_qoe.cache.lookups));
    json_object_object_add(status, "cache_hits",
                           json_object_new_int64((int64_t)g_qoe.cache.hits));
    json_object_object_add(status, "cache_misses",
                           json_object_new_int64((int64_t)g_qoe.cache.misses));
    json_object_object_add(status, "cache_evictions",
                           json_object_new_int64((int64_t)g_qoe.cache.evictions));
    json_object_object_add(status, "cache_expirations",
                           json_object_new_int64((int64_t)g_qoe.cache.expirations));
    {
        /*
         * Layered hit accounting. A single hits total cannot show which of the
         * three lookup scopes answered, so report the breakdown alongside it
         * and publish the invariant that ties them together.
         */
        struct json_object *by_scope = json_object_new_object();
        uint64_t scope_asn = g_qoe.cache.hits_by_scope[FLOWD_QOE_SCOPE_ASN];
        uint64_t scope_country = g_qoe.cache.hits_by_scope[FLOWD_QOE_SCOPE_COUNTRY];
        uint64_t scope_city = g_qoe.cache.hits_by_scope[FLOWD_QOE_SCOPE_CITY];
        uint64_t scope_total = scope_asn + scope_country + scope_city;
        int counters_consistent =
            scope_total == g_qoe.cache.hits &&
            g_qoe.cache.hits + g_qoe.cache.misses == g_qoe.cache.lookups;
        const char *state;
        const char *zero_reason;

        json_object_object_add(by_scope, "asn",
                               json_object_new_int64((int64_t)scope_asn));
        json_object_object_add(by_scope, "country",
                               json_object_new_int64((int64_t)scope_country));
        json_object_object_add(by_scope, "city",
                               json_object_new_int64((int64_t)scope_city));
        json_object_object_add(status, "cache_hits_by_scope", by_scope);
        json_object_object_add(status, "cache_hits_by_scope_total",
                               json_object_new_int64((int64_t)scope_total));
        json_object_object_add(status, "cache_counters_consistent",
                               json_object_new_boolean(counters_consistent));
        json_object_object_add(status, "cache_occupancy_permille",
                               json_object_new_int(g_qoe.cache.capacity
                                   ? (int)((g_qoe.cache.count * 1000ULL) /
                                           g_qoe.cache.capacity) : 0));

        /*
         * Zero counters have two very different causes and the response must
         * say which one it is: a cache nobody consulted looks identical to a
         * cache that was consulted and missed if only hits is reported.
         */
        if (!g_qoe.initialized) {
            state = "uninitialized";
            zero_reason = "qoe_runtime_not_initialized";
        } else if (!g_qoe.enabled_requested) {
            state = "disabled";
            zero_reason = "smart_path_not_enabled";
        } else if (!g_qoe.cache.lookups) {
            state = "never-consulted";
            zero_reason = active ? "no_lookup_traffic_yet"
                                 : "scheduler_inactive_no_dataplane";
        } else if (!g_qoe.cache.hits) {
            state = "consulted-all-missed";
            zero_reason = g_qoe.cache.count ? "lookups_missed_populated_cache"
                                            : "lookups_missed_empty_cache";
        } else {
            state = "active";
            zero_reason = "none";
        }
        json_object_object_add(status, "cache_state",
                               json_object_new_string(state));
        json_object_object_add(status, "cache_counters_zero_reason",
                               json_object_new_string(zero_reason));
    }
    json_object_object_add(status, "probe_rate_per_s",
                           json_object_new_int((int)g_qoe.probes.rate_per_s));
    json_object_object_add(status, "probe_burst",
                           json_object_new_int((int)g_qoe.probes.burst));
    json_object_object_add(status, "probe_tokens_available", json_object_new_int((int)available));
    json_object_object_add(status, "probe_queue_capacity",
                           json_object_new_int(FLOWD_QOE_QUEUE_CAPACITY));
    json_object_object_add(status, "candidates_per_tick",
                           json_object_new_int(FLOWD_QOE_CANDIDATES_PER_TICK));
    json_object_object_add(status, "probe_queue_depth",
                           json_object_new_int64((int64_t)g_qoe.queue_count));
    json_object_object_add(status, "probe_active", json_object_new_boolean(g_qoe.probe_active));
    json_object_object_add(status, "probe_jobs",
                           json_object_new_int64((int64_t)g_qoe.probe_jobs));
    json_object_object_add(status, "probe_successes",
                           json_object_new_int64((int64_t)g_qoe.probe_successes));
    json_object_object_add(status, "probe_failures",
                           json_object_new_int64((int64_t)g_qoe.probe_failures));
    {
        struct json_object *causes = json_object_new_object();
        uint64_t cause_total = g_qoe.probe_setup_failures +
                               g_qoe.probe_child_failures +
                               g_qoe.probe_no_healthy_path +
                               g_qoe.probe_cache_record_failures +
                               g_qoe.probe_bind_failures;

        /* setup            pre-fork: socketpair/fork/uloop registration
         * child            child died, sent nothing, or sent an address that
         *                  no longer resolves to a destination
         * no_healthy_path  the probe ran and every path came back unhealthy --
         *                  the ordinary blocked/unreachable-destination case
         * cache_record     flowd_qoe_cache_record() refused the result
         * bind             no eligible WAN, or the nft binding failed */
        json_object_object_add(causes, "setup",
            json_object_new_int64((int64_t)g_qoe.probe_setup_failures));
        json_object_object_add(causes, "child",
            json_object_new_int64((int64_t)g_qoe.probe_child_failures));
        json_object_object_add(causes, "no_healthy_path",
            json_object_new_int64((int64_t)g_qoe.probe_no_healthy_path));
        json_object_object_add(causes, "cache_record",
            json_object_new_int64((int64_t)g_qoe.probe_cache_record_failures));
        json_object_object_add(causes, "bind",
            json_object_new_int64((int64_t)g_qoe.probe_bind_failures));
        json_object_object_add(status, "probe_failures_by_cause", causes);
        json_object_object_add(status, "probe_failures_by_cause_total",
                               json_object_new_int64((int64_t)cause_total));
        json_object_object_add(status, "probe_counters_consistent",
            json_object_new_boolean(cause_total == g_qoe.probe_failures));
        json_object_object_add(status, "probe_backoff_extensions",
            json_object_new_int64((int64_t)g_qoe.probe_backoff_extensions));
        json_object_object_add(status, "probe_negative_ttl_ms",
            json_object_new_int64((int64_t)FLOWD_QOE_NEGATIVE_TTL_MS));
        json_object_object_add(status, "probe_negative_ttl_max_ms",
            json_object_new_int64((int64_t)FLOWD_QOE_NEGATIVE_TTL_MAX_MS));
    }
    json_object_object_add(status, "last_probe_ip",
                           json_object_new_string(g_qoe.last_probe_ip));
    json_object_object_add(status, "last_probe_at_ms",
                           json_object_new_int64((int64_t)g_qoe.last_probe_at_ms));
    json_object_object_add(status, "candidates_seen",
                           json_object_new_int64((int64_t)g_qoe.candidates_seen));
    json_object_object_add(status, "candidates_queued",
                           json_object_new_int64((int64_t)g_qoe.candidates_queued));
    json_object_object_add(status, "candidates_dropped",
                           json_object_new_int64((int64_t)g_qoe.candidates_dropped));
    json_object_object_add(status, "cache_routes",
                           json_object_new_int64((int64_t)g_qoe.cache_routes));
    json_object_object_add(status, "nft_table", json_object_new_string(FLOWD_QOE_NFT_TABLE));
    json_object_object_add(status, "address_family", json_object_new_string("ipv4+ipv6"));
    json_object_object_add(status, "learning_source",
                           json_object_new_string("conntrack_netlink_new_tcp"));
    json_object_object_add(status, "conntrack_event_active",
                           json_object_new_boolean(g_qoe.conntrack != NULL));
    json_object_object_add(status, "conntrack_events",
                           json_object_new_int64((int64_t)g_qoe.conntrack_events));
    json_object_object_add(status, "conntrack_filtered",
                           json_object_new_int64((int64_t)g_qoe.conntrack_filtered));
    json_object_object_add(status, "conntrack_errors",
                           json_object_new_int64((int64_t)g_qoe.conntrack_errors));
    json_object_object_add(status, "conntrack_enobufs",
                           json_object_new_int64((int64_t)g_qoe.conntrack_enobufs));
    json_object_object_add(status, "binding_capacity",
                           json_object_new_int(FLOWD_QOE_BINDING_CAPACITY));
    json_object_object_add(status, "binding_bytes",
                           json_object_new_int64((int64_t)sizeof(g_qoe.bindings)));
    json_object_object_add(status, "queue_bytes",
                           json_object_new_int64((int64_t)sizeof(g_qoe.queue)));
    json_object_object_add(status, "nft_active", json_object_new_boolean(g_qoe.nft_active));
    json_object_object_add(status, "nft_readback_ok",
                           json_object_new_boolean(g_qoe.nft_readback_ok));
    json_object_object_add(status, "nft_updates",
                           json_object_new_int64((int64_t)g_qoe.nft_updates));
    json_object_object_add(status, "nft_failures",
                           json_object_new_int64((int64_t)g_qoe.nft_failures));
    json_object_object_add(status, "nft_last_error",
                           json_object_new_string(g_qoe.last_nft_error));
    json_object_object_add(status, "binding_evictions",
                           json_object_new_int64((int64_t)g_qoe.binding_evictions));
    json_object_object_add(status, "binding_eviction_failures",
                           json_object_new_int64((int64_t)g_qoe.binding_eviction_failures));
    json_object_object_add(status, "health_failovers",
                           json_object_new_int64((int64_t)g_qoe.health_failovers));
    json_object_object_add(status, "equivalent_path_abs_us",
                           json_object_new_int(FLOWD_QOE_EQUIVALENT_ABS_US));
    json_object_object_add(status, "equivalent_path_percent",
                           json_object_new_int(FLOWD_QOE_EQUIVALENT_PERCENT));
    {
        struct json_object *wans = json_object_new_array();
        size_t i;

        /* Populate on demand so the WAN/carrier view is inspectable before the
         * scheduler is ever enabled. */
        if (!g_qoe_wan_count)
            qoe_refresh_wan_table(NULL, NULL);
        for (i = 0; i < g_qoe_wan_count; i++) {
            struct json_object *wan = json_object_new_object();
            const char *carrier;

            switch (g_qoe_wans[i].carrier_id) {
            case JMX_CARRIER_TELECOM: carrier = "telecom"; break;
            case JMX_CARRIER_UNICOM:  carrier = "unicom";  break;
            case JMX_CARRIER_MOBILE:  carrier = "mobile";  break;
            case JMX_CARRIER_EDU:     carrier = "edu";     break;
            default:                  carrier = "unknown"; break;
            }
            json_object_object_add(wan, "id", json_object_new_int(g_qoe_wans[i].id));
            json_object_object_add(wan, "name",
                                   json_object_new_string(g_qoe_wans[i].logical_name));
            json_object_object_add(wan, "ifname",
                                   json_object_new_string(g_qoe_wans[i].ifname));
            json_object_object_add(wan, "fwmark",
                                   json_object_new_int64((int64_t)g_qoe_wans[i].fwmark));
            json_object_object_add(wan, "carrier", json_object_new_string(carrier));
            json_object_object_add(wan, "healthy",
                                   json_object_new_boolean(g_qoe_wans[i].healthy));
            json_object_array_add(wans, wan);
        }
        json_object_object_add(status, "wan_paths", wans);
        json_object_object_add(status, "wan_path_count",
                               json_object_new_int((int)g_qoe_wan_count));
    }
    json_object_object_add(status, "city_mmdb_mapped",
                           json_object_new_boolean(g_qoe.city_open));
    json_object_object_add(status, "asn_mmdb_mapped",
                           json_object_new_boolean(g_qoe.asn_open));
    for (i = 0; i < (int)g_qoe_wan_count; i++) {
        char key[16];
        uint8_t wan_id = g_qoe_wans[i].id;

        snprintf(key, sizeof(key), "wan%u", wan_id);
        json_object_object_add(bindings, key,
                               json_object_new_int64((int64_t)qoe_binding_count(now_ms,
                                                                                wan_id)));
    }
    json_object_object_add(bindings, "total",
                           json_object_new_int64((int64_t)qoe_binding_count(now_ms, 0)));
    json_object_object_add(status, "bindings", bindings);
    json_object_object_add(capabilities, "kernel_cache_hook", json_object_new_boolean(0));
    json_object_object_add(capabilities, "nft_cache_hook", json_object_new_boolean(active));
    json_object_object_add(capabilities, "active_tcp_probe", json_object_new_boolean(active));
    json_object_object_add(capabilities, "policy_scoped", json_object_new_boolean(1));
    json_object_object_add(capabilities, "inet_diag_feedback", json_object_new_boolean(0));
    json_object_object_add(capabilities, "udp_passive_feedback", json_object_new_boolean(0));
    json_object_object_add(status, "capabilities", capabilities);
    if (!active) {
        const char *reason = g_qoe.last_error[0] ? g_qoe.last_error :
            (!g_qoe.enabled_requested ? "not_enabled" :
             (!g_qoe.city_open || !g_qoe.asn_open ? "city_or_asn_mmdb_unavailable" :
              (!g_qoe.conntrack ? "conntrack_event_not_ready" :
               "nft_cache_hook_not_ready")));

        json_object_object_add(status, "unavailable_reason", json_object_new_string(reason));
    } else {
        json_object_object_add(status, "unavailable_reason", json_object_new_string(""));
    }
    for (i = 0; i < (int)g_qoe_policy_count; i++) {
        const struct flowd_qoe_policy_runtime *policy = &g_qoe_policies[i];
        struct json_object *item = json_object_new_object();
        struct json_object *members = json_object_new_array();
        int requested = policy->enabled && policy->smart_requested;
        int runtime_applied = !requested ||
            (policy->member_count > 0 && active && g_qoe.nft_readback_ok);
        int effective = requested && runtime_applied;
        const char *reason;
        size_t j;

        if (!policy->enabled)
            reason = "policy_disabled";
        else if (!policy->smart_requested)
            reason = !strcmp(policy->smart_mode, "inherit") ?
                "global_smart_path_disabled" : "disabled_as_configured";
        else if (!policy->member_count)
            reason = "policy_has_no_members";
        else if (!g_qoe.city_open || !g_qoe.asn_open)
            reason = "city_or_asn_mmdb_unavailable";
        else if (!g_qoe.nft_active)
            reason = g_qoe.last_error[0] ? g_qoe.last_error :
                "nft_policy_scope_not_active";
        else if (!g_qoe.nft_readback_ok)
            reason = "nft_policy_scope_readback_mismatch";
        else if (!g_qoe.conntrack)
            reason = "conntrack_event_not_ready";
        else
            reason = "nft_policy_scope_ready";
        for (j = 0; j < policy->member_count; j++)
            json_object_array_add(members,
                                  json_object_new_int(policy->members[j]));
        json_object_object_add(item, "prio", json_object_new_int(policy->prio));
        json_object_object_add(item, "mode",
                               json_object_new_string(policy->smart_mode));
        json_object_object_add(item, "configured",
                               json_object_new_boolean(
                                   strcmp(policy->smart_mode, "inherit") != 0));
        json_object_object_add(item, "requested",
                               json_object_new_boolean(requested));
        json_object_object_add(item, "effective",
                               json_object_new_boolean(effective));
        json_object_object_add(item, "runtime_applied",
                               json_object_new_boolean(runtime_applied));
        json_object_object_add(item, "runtime_reason",
                               json_object_new_string(reason));
        json_object_object_add(item, "members", members);
        json_object_object_add(item, "member_count",
                               json_object_new_int(policy->member_count));
        json_object_object_add(item, "existing_connections",
                               json_object_new_string("unchanged"));
        json_object_array_add(policy_runtime, item);
    }
    json_object_object_add(status, "policy_runtime", policy_runtime);
    return status;
}

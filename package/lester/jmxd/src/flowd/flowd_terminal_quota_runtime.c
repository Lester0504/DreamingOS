// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Terminal-policy quota accounting runtime.
 *
 * This is deliberately smaller than the flow export runtime: it does not build
 * NetFlow records, it only folds conntrack byte deltas into the unified
 * terminal policy quota_usage table so blocked_quota can actually transition
 * from a counter, not from a pretend storage field.
 *
 * Conntrack Netlink is the accounting source.  The timer below only refreshes
 * policy configuration and lifecycle state; packet/byte deltas never require
 * a procfs table scan on the uloop thread.
 */
#include "flowd_export_runtime.h"
#include "flowd_internal.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnfnetlink/linux_nfnetlink_compat.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netlink.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>

#include "../terminal_policy/terminal_policy.h"
#include "jmx_utils.h"

#define FLOWD_TP_QUOTA_TICK_MS 5000
/* Drift reconciliation runs on a slower cadence than the accounting tick.  A
 * readback plus a possible apply forks nft/tc, so doing it every 5s would be
 * wasteful; 30s bounds how long a dataplane that diverged from storage can stay
 * that way without anyone touching the API. */
#define FLOWD_TP_RECONCILE_INTERVAL_MS 30000
#define FLOWD_TP_MAX_STATE 4096
#define FLOWD_TP_TABLE_SLOTS (FLOWD_TP_MAX_STATE * 2)
#define FLOWD_TP_SLOT_EMPTY 0
#define FLOWD_TP_SLOT_LIVE 1
#define FLOWD_TP_SLOT_TOMB 2
#define FLOWD_TP_PENDING_SLOTS 1024
#define FLOWD_TP_MAX_LOCAL_ADDRS 64
#define FLOWD_TP_MAX_TARGETS_PER_ACCOUNT 4096
/* Bounded write-behind: a client's aggregate is flushed to SQLite as soon as
 * it reaches this many bytes, so the worst-case under-accounting after an
 * unclean stop is this value per client with pending data, plus whatever
 * arrives inside one tick.  Both numbers are reported in the status object so
 * the contract can state a real bound instead of a guess. */
#define FLOWD_TP_CHECKPOINT_BYTES (4ULL * 1024ULL * 1024ULL)

struct flowd_tp_quota_src {
    int in_use;
    uint8_t family;
    uint8_t protocol;
    unsigned char src_addr[16];
    unsigned char dst_addr[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint64_t up_bytes;
    uint64_t down_bytes;
    uint8_t counter_mask; /* bit 0: orig/up, bit 1: repl/down */
    uint64_t last_seen_ms;
};

struct flowd_tp_quota_target {
    int in_use;
    int family;
    int prefix_len;
    char prefix[INET6_ADDRSTRLEN];
};

struct flowd_tp_quota_account {
    int in_use;
    char id[65];
    long long quota_bytes;
    char quota_mode[16];
    char status[32];
    struct flowd_tp_quota_target *targets;
    size_t target_count;
    size_t target_capacity;
};

/* One in-memory aggregate per (policy, client address), or one policy-wide
 * aggregate for shared quotas. The conntrack event path only touches these;
 * SQLite is written by the checkpoint path. */
struct flowd_tp_quota_pending {
    int in_use;
    char policy_id[65];
    int family;               /* 4 or 6 */
    char client_ip[INET6_ADDRSTRLEN];
    uint64_t up_bytes;
    uint64_t down_bytes;
};

struct flowd_tp_local_addr {
    int family;               /* AF_INET / AF_INET6 */
    int prefix_len;
    int is_lan;               /* address belongs to the LAN bridge */
    unsigned char addr[16];
};

struct flowd_tp_quota_runtime {
    int active;
    struct uloop_timeout timer;
    struct nfct_handle *conntrack;
    struct uloop_fd conntrack_fd;
    struct nfct_handle *dump_conntrack;
    struct uloop_fd dump_fd;
    struct flowd_settings settings;
    int settings_loaded;
    int exhausted_seen;
    struct flowd_tp_quota_src state[FLOWD_TP_TABLE_SLOTS];
    size_t state_live;
    struct flowd_tp_quota_account accounts[256];
    size_t account_count;
    struct flowd_tp_quota_pending pending[FLOWD_TP_PENDING_SLOTS];
    size_t pending_live;
    uint64_t pending_bytes;
    uint64_t pending_dropped;
    struct flowd_tp_local_addr local_addrs[FLOWD_TP_MAX_LOCAL_ADDRS];
    size_t local_addr_count;
    uint64_t local_refresh_ms;
    uint64_t skipped_not_forward;
    uint64_t checkpoint_writes;
    uint64_t checkpoint_errors;
    int64_t checkpoint_at;
    uint64_t resyncs;
    int resync_dumping;
    uint64_t polls;
    uint64_t conntrack_events;
    uint64_t conntrack_filtered;
    uint64_t conntrack_errors;
    uint64_t conntrack_enobufs;
    uint64_t event_parse_failures;
    uint64_t event_no_counters;
    uint64_t target_misses;
    uint64_t target_matches;
    char last_sample_src[INET6_ADDRSTRLEN];
    char last_sample_dst[INET6_ADDRSTRLEN];
    int last_sample_family;
    uint64_t dump_requests;
    uint64_t dump_send_errors;
    int dump_last_errno;
    uint64_t dump_completed;
    uint64_t dump_at_ms;
    unsigned int dump_pending;
    int dump_family_next;
    int conntrack_resync_needed;
    uint64_t poll_errors;
    uint64_t checkpointed;
    uint64_t skipped_no_accounting;
    uint64_t policy_revision;
    uint64_t reconcile_at_ms;
    uint64_t reconciles;
    uint64_t reconcile_failures;
    char reconcile_reason[128];
    char last_error[128];
};

static struct flowd_tp_quota_runtime g_tp_quota;

static uint64_t flowd_tp_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return (uint64_t)time(NULL) * 1000ULL;
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000L);
}

static void flowd_tp_quota_error_set(const char *err)
{
    snprintf(g_tp_quota.last_error, sizeof(g_tp_quota.last_error), "%s", err ? err : "");
}

static void flowd_tp_quota_release_accounts(struct flowd_tp_quota_account *accounts,
                                            size_t count)
{
    size_t i;

    if (!accounts)
        return;
    for (i = 0; i < count; i++) {
        free(accounts[i].targets);
        accounts[i].targets = NULL;
        accounts[i].target_count = 0;
        accounts[i].target_capacity = 0;
    }
}

static void flowd_tp_quota_clear(void)
{
    memset(g_tp_quota.state, 0, sizeof(g_tp_quota.state));
    g_tp_quota.state_live = 0;
    flowd_tp_quota_release_accounts(g_tp_quota.accounts,
                                    sizeof(g_tp_quota.accounts) /
                                    sizeof(g_tp_quota.accounts[0]));
    memset(g_tp_quota.accounts, 0, sizeof(g_tp_quota.accounts));
    g_tp_quota.account_count = 0;
    memset(g_tp_quota.pending, 0, sizeof(g_tp_quota.pending));
    g_tp_quota.pending_live = 0;
    g_tp_quota.pending_bytes = 0;
    g_tp_quota.pending_dropped = 0;
    memset(g_tp_quota.local_addrs, 0, sizeof(g_tp_quota.local_addrs));
    g_tp_quota.local_addr_count = 0;
    g_tp_quota.local_refresh_ms = 0;
    g_tp_quota.skipped_not_forward = 0;
    g_tp_quota.checkpoint_writes = 0;
    g_tp_quota.checkpoint_errors = 0;
    g_tp_quota.checkpoint_at = 0;
    g_tp_quota.resyncs = 0;
    g_tp_quota.resync_dumping = 0;
    g_tp_quota.polls = 0;
    g_tp_quota.poll_errors = 0;
    g_tp_quota.checkpointed = 0;
    g_tp_quota.skipped_no_accounting = 0;
    g_tp_quota.exhausted_seen = 0;
    g_tp_quota.conntrack_resync_needed = 0;
    g_tp_quota.event_parse_failures = 0;
    g_tp_quota.event_no_counters = 0;
    g_tp_quota.target_misses = 0;
    g_tp_quota.target_matches = 0;
    g_tp_quota.last_sample_src[0] = '\0';
    g_tp_quota.last_sample_dst[0] = '\0';
    g_tp_quota.last_sample_family = 0;
    g_tp_quota.dump_requests = 0;
    g_tp_quota.dump_send_errors = 0;
    g_tp_quota.dump_last_errno = 0;
    g_tp_quota.dump_completed = 0;
    g_tp_quota.dump_at_ms = 0;
    g_tp_quota.dump_pending = 0;
    g_tp_quota.dump_family_next = AF_INET;
    g_tp_quota.reconcile_at_ms = 0;
    g_tp_quota.reconciles = 0;
    g_tp_quota.reconcile_failures = 0;
    g_tp_quota.reconcile_reason[0] = '\0';
    g_tp_quota.last_error[0] = '\0';
}

static size_t flowd_tp_addr_len(uint8_t family)
{
    return family == AF_INET6 ? 16 : 4;
}

static int flowd_tp_same_flow(const struct flowd_tp_quota_src *a,
                              const struct flowd_tp_quota_src *b)
{
    size_t len = flowd_tp_addr_len(a->family);

    return a->family == b->family && a->protocol == b->protocol &&
           a->src_port == b->src_port && a->dst_port == b->dst_port &&
           !memcmp(a->src_addr, b->src_addr, len) &&
           !memcmp(a->dst_addr, b->dst_addr, len);
}

static uint32_t flowd_tp_quota_hash(const struct flowd_tp_quota_src *s)
{
    uint32_t h = 2166136261U;
    size_t len = flowd_tp_addr_len(s->family);
    size_t i;

    h = (h ^ (uint32_t)s->family) * 16777619U;
    h = (h ^ (uint32_t)s->protocol) * 16777619U;
    for (i = 0; i < len; i++)
        h = (h ^ s->src_addr[i]) * 16777619U;
    for (i = 0; i < len; i++)
        h = (h ^ s->dst_addr[i]) * 16777619U;
    h = (h ^ s->src_port) * 16777619U;
    h = (h ^ s->dst_port) * 16777619U;
    return h;
}

static struct flowd_tp_quota_src *
flowd_tp_quota_lookup(const struct flowd_tp_quota_src *key, int insert)
{
    size_t mask = FLOWD_TP_TABLE_SLOTS - 1;
    size_t start = flowd_tp_quota_hash(key) & mask;
    struct flowd_tp_quota_src *free_slot = NULL;
    size_t probe;

    for (probe = 0; probe < FLOWD_TP_TABLE_SLOTS; probe++) {
        struct flowd_tp_quota_src *s =
            &g_tp_quota.state[(start + probe) & mask];

        if (s->in_use == FLOWD_TP_SLOT_EMPTY) {
            if (!free_slot)
                free_slot = s;
            break;
        }
        if (s->in_use == FLOWD_TP_SLOT_TOMB) {
            if (!free_slot)
                free_slot = s;
            continue;
        }
        if (flowd_tp_same_flow(s, key))
            return s;
    }
    if (!insert || !free_slot ||
        g_tp_quota.state_live >= FLOWD_TP_MAX_STATE)
        return NULL;
    *free_slot = *key;
    free_slot->in_use = FLOWD_TP_SLOT_LIVE;
    g_tp_quota.state_live++;
    return free_slot;
}

static int flowd_tp_prefix_match(int family, const char *prefix, int plen,
                                 const unsigned char *addr)
{
    unsigned char masked_addr[16] = { 0 };
    unsigned char masked_prefix[16] = { 0 };
    int addr_len = (family == AF_INET6) ? 16 : 4;
    int max_plen = (family == AF_INET6) ? 128 : 32;
    int i;

    if (!prefix || !addr || plen < 0 || plen > max_plen ||
        inet_pton(family, prefix, masked_prefix) != 1)
        return 0;
    for (i = 0; i < addr_len && plen > 0; i++) {
        unsigned int mask;
        if (plen >= 8) {
            mask = 0xffU;
            plen -= 8;
        } else {
            mask = 0xffU << (8 - plen);
            plen = 0;
        }
        masked_addr[i] = addr[i] & mask;
        masked_prefix[i] = masked_prefix[i] & mask;
    }
    return memcmp(masked_addr, masked_prefix, (size_t)addr_len) == 0;
}

/*
 * The contract counts only LAN -> Internet forwarded bytes.  A conntrack entry
 * whose destination is one of the router's own addresses is management-plane
 * traffic, and one whose destination lies inside a locally attached LAN prefix
 * is intra-LAN.  Both must be excluded, so the router's own interface
 * addresses and prefixes are refreshed periodically and consulted per flow.
 */
static int flowd_tp_addr_in_prefix(int family, const unsigned char *prefix,
                                   int plen, const unsigned char *addr)
{
    int addr_len = family == AF_INET6 ? 16 : 4;
    int max_plen = addr_len * 8;
    int full;
    int rest;

    if (!prefix || !addr || plen < 0 || plen > max_plen)
        return 0;
    full = plen / 8;
    rest = plen % 8;
    if (full && memcmp(prefix, addr, (size_t)full))
        return 0;
    if (rest) {
        unsigned char mask = (unsigned char)(0xffU << (8 - rest));

        if ((prefix[full] & mask) != (addr[full] & mask))
            return 0;
    }
    return 1;
}

static void flowd_tp_quota_refresh_local(void)
{
    struct ifaddrs *list = NULL;
    struct ifaddrs *it;
    size_t n = 0;

    if (getifaddrs(&list) != 0 || !list) {
        if (list)
            freeifaddrs(list);
        return;
    }
    for (it = list; it && n < FLOWD_TP_MAX_LOCAL_ADDRS; it = it->ifa_next) {
        struct flowd_tp_local_addr *slot = &g_tp_quota.local_addrs[n];

        if (!it->ifa_addr || !it->ifa_name || !(it->ifa_flags & IFF_UP))
            continue;
        memset(slot, 0, sizeof(*slot));
        if (it->ifa_addr->sa_family == AF_INET) {
            const struct sockaddr_in *a = (const struct sockaddr_in *)it->ifa_addr;
            const struct sockaddr_in *m = (const struct sockaddr_in *)it->ifa_netmask;
            uint32_t mask = m ? ntohl(m->sin_addr.s_addr) : 0xffffffffU;
            int plen = 0;

            while (plen < 32 && (mask & (0x80000000U >> plen)))
                plen++;
            slot->family = AF_INET;
            slot->prefix_len = plen;
            memcpy(slot->addr, &a->sin_addr, 4);
        } else if (it->ifa_addr->sa_family == AF_INET6) {
            const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)it->ifa_addr;
            const struct sockaddr_in6 *m = (const struct sockaddr_in6 *)it->ifa_netmask;
            int plen = 0;
            int i;

            if (m) {
                for (i = 0; i < 16; i++) {
                    unsigned char byte = m->sin6_addr.s6_addr[i];
                    int bit;

                    for (bit = 0; bit < 8; bit++) {
                        if (!(byte & (0x80U >> bit)))
                            goto done6;
                        plen++;
                    }
                }
            } else {
                plen = 128;
            }
done6:
            slot->family = AF_INET6;
            slot->prefix_len = plen;
            memcpy(slot->addr, &a->sin6_addr, 16);
        } else {
            continue;
        }
        /* Only bridge/LAN-side prefixes imply intra-LAN traffic; a WAN prefix
         * must not be treated as local, or a same-subnet Internet peer would
         * silently stop being metered. */
        slot->is_lan = jmx_iface_is_lan(it->ifa_name);
        n++;
    }
    freeifaddrs(list);
    g_tp_quota.local_addr_count = n;
    g_tp_quota.local_refresh_ms = flowd_tp_now_ms();
}

/* 1 when this flow's destination counts as Internet-forwarded traffic. */
static int flowd_tp_quota_dst_is_internet(uint8_t family,
                                          const unsigned char *dst)
{
    int af = family == AF_INET6 ? AF_INET6 : AF_INET;
    size_t i;

    if (!dst)
        return 0;
    if (af == AF_INET) {
        /* loopback and link-local are never Internet destinations */
        if (dst[0] == 127 || (dst[0] == 169 && dst[1] == 254))
            return 0;
        if (dst[0] >= 224)          /* multicast / reserved */
            return 0;
    } else {
        static const unsigned char v6_loopback[16] = {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        };

        if (!memcmp(dst, v6_loopback, 16))
            return 0;
        if (dst[0] == 0xfe && (dst[1] & 0xc0) == 0x80)   /* fe80::/10 */
            return 0;
        if (dst[0] == 0xff)                              /* multicast */
            return 0;
    }
    for (i = 0; i < g_tp_quota.local_addr_count; i++) {
        const struct flowd_tp_local_addr *l = &g_tp_quota.local_addrs[i];

        if (l->family != af)
            continue;
        /* the router's own address: management plane */
        if (flowd_tp_addr_in_prefix(af, l->addr, af == AF_INET6 ? 128 : 32, dst))
            return 0;
        /* inside an attached LAN prefix: intra-LAN */
        if (l->is_lan &&
            flowd_tp_addr_in_prefix(af, l->addr, l->prefix_len, dst))
            return 0;
    }
    return 1;
}

static uint32_t flowd_tp_pending_hash(const char *policy_id, int family,
                                      const char *client_ip)
{
    uint32_t h = 2166136261U;
    const unsigned char *p;

    for (p = (const unsigned char *)policy_id; p && *p; p++)
        h = (h ^ *p) * 16777619U;
    h = (h ^ (uint32_t)family) * 16777619U;
    for (p = (const unsigned char *)client_ip; p && *p; p++)
        h = (h ^ *p) * 16777619U;
    return h;
}

static struct flowd_tp_quota_pending *
flowd_tp_pending_slot(const char *policy_id, int family, const char *client_ip,
                      int insert)
{
    size_t mask = FLOWD_TP_PENDING_SLOTS - 1;
    size_t start = flowd_tp_pending_hash(policy_id, family, client_ip) & mask;
    struct flowd_tp_quota_pending *empty = NULL;
    size_t probe;

    for (probe = 0; probe < FLOWD_TP_PENDING_SLOTS; probe++) {
        struct flowd_tp_quota_pending *s =
            &g_tp_quota.pending[(start + probe) & mask];

        if (!s->in_use) {
            if (!empty)
                empty = s;
            break;
        }
        if (s->family == family && !strcmp(s->policy_id, policy_id) &&
            !strcmp(s->client_ip, client_ip))
            return s;
    }
    if (!insert || !empty)
        return NULL;
    memset(empty, 0, sizeof(*empty));
    empty->in_use = 1;
    empty->family = family;
    snprintf(empty->policy_id, sizeof(empty->policy_id), "%s", policy_id);
    snprintf(empty->client_ip, sizeof(empty->client_ip), "%s", client_ip);
    g_tp_quota.pending_live++;
    return empty;
}

/* Flushes one pending aggregate into the store.  Zero-byte slots are simply
 * retired.  On a store failure the bytes stay pending so nothing is lost. */
static int flowd_tp_pending_flush_slot(struct flowd_tp_quota_pending *slot)
{
    int64_t up;
    int64_t down;
    int exhausted = 0;

    if (!slot || !slot->in_use)
        return 0;
    if (!slot->up_bytes && !slot->down_bytes) {
        slot->in_use = 0;
        if (g_tp_quota.pending_live)
            g_tp_quota.pending_live--;
        return 0;
    }
    up = (int64_t)slot->up_bytes;
    down = (int64_t)slot->down_bytes;
    if (slot->family == 0) {
        int rc = tp_policy_account_usage(slot->policy_id, up, down, NULL);
        if (rc < 0) {
            g_tp_quota.checkpoint_errors++;
            return -1;
        }
        if (rc > 0)
            exhausted = 1;
    } else if (tp_policy_account_usage_for_client(slot->policy_id, slot->family,
                                                  slot->client_ip, up, down,
                                                  NULL, &exhausted) != 0) {
        g_tp_quota.checkpoint_errors++;
        return -1;
    }
    if (g_tp_quota.pending_bytes >= slot->up_bytes + slot->down_bytes)
        g_tp_quota.pending_bytes -= slot->up_bytes + slot->down_bytes;
    else
        g_tp_quota.pending_bytes = 0;
    slot->up_bytes = 0;
    slot->down_bytes = 0;
    slot->in_use = 0;
    if (g_tp_quota.pending_live)
        g_tp_quota.pending_live--;
    g_tp_quota.checkpoint_writes++;
    g_tp_quota.checkpointed++;
    if (exhausted)
        g_tp_quota.exhausted_seen = 1;
    return 0;
}

static void flowd_tp_pending_flush_all(void)
{
    size_t i;

    for (i = 0; i < FLOWD_TP_PENDING_SLOTS; i++) {
        if (g_tp_quota.pending[i].in_use)
            (void)flowd_tp_pending_flush_slot(&g_tp_quota.pending[i]);
    }
    g_tp_quota.checkpoint_at = (int64_t)time(NULL);
}

static int flowd_tp_quota_refresh_accounts(void)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *pol = NULL, *tgt = NULL;
    sqlite3_stmt *rev = NULL;
    struct flowd_tp_quota_account next_accounts[
        sizeof(g_tp_quota.accounts) / sizeof(g_tp_quota.accounts[0])];
    size_t n = 0;
    int row_rc;
    int target_rc;
    uint64_t revision = 0;

    memset(next_accounts, 0, sizeof(next_accounts));
    if (sqlite3_open_v2(TP_DB_PATH, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        flowd_tp_quota_error_set("terminal_policy_db_unavailable");
        return -1;
    }
    if (sqlite3_prepare_v2(db,
        "SELECT (COALESCE(MAX(updated_at),0) << 16) ^ COUNT(*) FROM policies",
        -1, &rev, NULL) == SQLITE_OK) {
        if (sqlite3_step(rev) == SQLITE_ROW)
            revision = (uint64_t)sqlite3_column_int64(rev, 0);
        sqlite3_finalize(rev);
    }
    if (sqlite3_prepare_v2(db,
        "SELECT id,enabled,quota_bytes,quota_mode,status FROM policies WHERE enabled=1 "
        "AND quota_bytes>0 ORDER BY created_at DESC", -1, &pol, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        flowd_tp_quota_error_set("terminal_policy_query_failed");
        return -1;
    }
    while ((row_rc = sqlite3_step(pol)) == SQLITE_ROW) {
        const char *id = (const char *)sqlite3_column_text(pol, 0);
        const char *quota_mode = (const char *)sqlite3_column_text(pol, 3);
        const char *status = (const char *)sqlite3_column_text(pol, 4);
        if (n >= sizeof(g_tp_quota.accounts) / sizeof(g_tp_quota.accounts[0]) ||
            !id || !id[0] || !sqlite3_column_int(pol, 1) || !status)
            continue;
        snprintf(next_accounts[n].id, sizeof(next_accounts[n].id), "%s", id);
        snprintf(next_accounts[n].quota_mode, sizeof(next_accounts[n].quota_mode), "%s", quota_mode && quota_mode[0] ? quota_mode : TP_QUOTA_PER_IP);
        snprintf(next_accounts[n].status, sizeof(next_accounts[n].status), "%s", status);
        next_accounts[n].in_use = 1;
        next_accounts[n].quota_bytes = sqlite3_column_int64(pol, 2);
        n++;
    }
    sqlite3_finalize(pol);
    pol = NULL;
    if (row_rc != SQLITE_DONE) {
        sqlite3_close(db);
        flowd_tp_quota_error_set("terminal_policy_query_failed");
        return -1;
    }
    if (sqlite3_prepare_v2(db,
        "SELECT policy_id,family,prefix,prefix_len FROM targets ORDER BY policy_id,family,prefix",
        -1, &tgt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        flowd_tp_quota_error_set("terminal_policy_target_query_failed");
        return -1;
    }
    while ((target_rc = sqlite3_step(tgt)) == SQLITE_ROW) {
        const char *pid = (const char *)sqlite3_column_text(tgt, 0);
        const char *prefix = (const char *)sqlite3_column_text(tgt, 2);
        int family = sqlite3_column_int(tgt, 1);
        int plen = sqlite3_column_int(tgt, 3);
        size_t i;
        if (!pid || !prefix || !prefix[0])
            continue;
        for (i = 0; i < n; i++) {
            struct flowd_tp_quota_account *a = &next_accounts[i];
            int af = family == 4 ? AF_INET : (family == 6 ? AF_INET6 : family);
            struct flowd_tp_quota_target *t;
            unsigned char parsed[16];
            if (!a->in_use || strcmp(a->id, pid))
                continue;
            if (a->target_count >= FLOWD_TP_MAX_TARGETS_PER_ACCOUNT) {
                sqlite3_finalize(tgt);
                sqlite3_close(db);
                flowd_tp_quota_release_accounts(next_accounts,
                                                sizeof(next_accounts) /
                                                sizeof(next_accounts[0]));
                flowd_tp_quota_error_set("terminal_policy_quota_target_limit");
                return -1;
            }
            if ((af != AF_INET && af != AF_INET6) ||
                plen < 0 || (af == AF_INET ? plen > 32 : plen > 128) ||
                inet_pton(af, prefix, parsed) != 1) {
                sqlite3_finalize(tgt);
                sqlite3_close(db);
                flowd_tp_quota_release_accounts(next_accounts,
                                                sizeof(next_accounts) /
                                                sizeof(next_accounts[0]));
                flowd_tp_quota_error_set("terminal_policy_quota_target_invalid");
                return -1;
            }
            if (a->target_count == a->target_capacity) {
                size_t cap = a->target_capacity ? a->target_capacity * 2 : 64;
                struct flowd_tp_quota_target *grown;

                if (cap > FLOWD_TP_MAX_TARGETS_PER_ACCOUNT)
                    cap = FLOWD_TP_MAX_TARGETS_PER_ACCOUNT;
                grown = realloc(a->targets, cap * sizeof(*grown));
                if (!grown) {
                    sqlite3_finalize(tgt);
                    sqlite3_close(db);
                    flowd_tp_quota_release_accounts(next_accounts,
                                                    sizeof(next_accounts) /
                                                    sizeof(next_accounts[0]));
                    flowd_tp_quota_error_set("terminal_policy_quota_target_oom");
                    return -1;
                }
                a->targets = grown;
                a->target_capacity = cap;
            }
            t = &a->targets[a->target_count++];
            t->in_use = 1;
            t->family = af;
            t->prefix_len = plen;
            snprintf(t->prefix, sizeof(t->prefix), "%s", prefix);
            break;
        }
    }
    sqlite3_finalize(tgt);
    if (target_rc != SQLITE_DONE) {
        sqlite3_close(db);
        flowd_tp_quota_release_accounts(next_accounts,
                                        sizeof(next_accounts) /
                                        sizeof(next_accounts[0]));
        flowd_tp_quota_error_set("terminal_policy_target_query_failed");
        return -1;
    }
    sqlite3_close(db);

    /* Publish only a complete, validated snapshot.  A transient SQLite or
     * allocation error must not erase the last working quota map. */
    flowd_tp_quota_release_accounts(g_tp_quota.accounts,
                                    sizeof(g_tp_quota.accounts) /
                                    sizeof(g_tp_quota.accounts[0]));
    memcpy(g_tp_quota.accounts, next_accounts, sizeof(next_accounts));
    memset(next_accounts, 0, sizeof(next_accounts));
    g_tp_quota.account_count = n;
    g_tp_quota.policy_revision = revision;
    return 0;
}

static void flowd_tp_quota_account_line(const struct flowd_tp_quota_account *acct,
                                        const struct flowd_tp_quota_src *src,
                                        uint64_t up_delta, uint64_t down_delta)
{
    size_t i;

    if (!acct || !acct->in_use || !src || (!up_delta && !down_delta))
        return;
    if (strcmp(acct->status, TP_STATUS_ACTIVE) != 0 &&
        strcmp(acct->status, TP_STATUS_BLOCKED_QUOTA) != 0)
        return;
    for (i = 0; i < acct->target_count; i++) {
        const struct flowd_tp_quota_target *t = &acct->targets[i];

        if (t->in_use && t->family == (int)src->family &&
            flowd_tp_prefix_match(t->family, (const char *)t->prefix,
                                  t->prefix_len, src->src_addr)) {
            char client_ip[INET6_ADDRSTRLEN];
            int family = src->family == AF_INET6 ? 6 : 4;
            struct flowd_tp_quota_pending *slot;

            if (!inet_ntop(src->family, src->src_addr, client_ip, sizeof(client_ip)))
                return;
            g_tp_quota.target_matches++;
            /* Hot path: fold into the in-memory aggregate.  SQLite is only
             * touched by the checkpoint below, either when this client's
             * pending bytes cross the bound or on the periodic tick. */
            /* Shared quota is keyed only by policy.  family 0 plus an empty
             * address makes IPv4, IPv6 and every matching client share one
             * write-behind bucket and one persistent quota_usage row. */
            if (!strcmp(acct->quota_mode, TP_QUOTA_SHARED)) {
                family = 0;
                client_ip[0] = '\0';
            }
            slot = flowd_tp_pending_slot(acct->id, family, client_ip, 1);
            if (!slot) {
                g_tp_quota.pending_dropped++;
                return;
            }
            slot->up_bytes += up_delta;
            slot->down_bytes += down_delta;
            g_tp_quota.pending_bytes += up_delta + down_delta;
            if (slot->up_bytes + slot->down_bytes >= FLOWD_TP_CHECKPOINT_BYTES)
                (void)flowd_tp_pending_flush_slot(slot);
            return;
        }
    }
}

static int flowd_tp_quota_event_to_src(const struct nf_conntrack *ct,
                                       struct flowd_tp_quota_src *src)
{
    uint8_t family, protocol;
    if (!ct || !src || !nfct_attr_is_set(ct, ATTR_ORIG_L3PROTO) ||
        !nfct_attr_is_set(ct, ATTR_ORIG_L4PROTO))
        return -1;
    family = nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO);
    protocol = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
    memset(src, 0, sizeof(*src));
    src->in_use = 1;
    src->family = family;
    src->protocol = protocol;
    if (family == AF_INET) {
        if (!nfct_attr_is_set(ct, ATTR_ORIG_IPV4_SRC) ||
            !nfct_attr_is_set(ct, ATTR_ORIG_IPV4_DST))
            return -1;
        /*
         * libnetfilter_conntrack returns CTA_IP_V4_* as the host-order value
         * backed by the network-order payload.  Copying that u32's bytes keeps
         * the original network-order octets for inet_ntop/prefix matching.
         */
        {
            uint32_t src_v4 = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
            uint32_t dst_v4 = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);
            memcpy(src->src_addr, &src_v4, sizeof(src_v4));
            memcpy(src->dst_addr, &dst_v4, sizeof(dst_v4));
        }
    } else if (family == AF_INET6) {
        if (!nfct_attr_is_set(ct, ATTR_ORIG_IPV6_SRC) ||
            !nfct_attr_is_set(ct, ATTR_ORIG_IPV6_DST))
            return -1;
        memcpy(src->src_addr, nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC), 16);
        memcpy(src->dst_addr, nfct_get_attr(ct, ATTR_ORIG_IPV6_DST), 16);
    } else {
        return -1;
    }
    if (nfct_attr_is_set(ct, ATTR_ORIG_PORT_SRC))
        src->src_port = ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC));
    if (nfct_attr_is_set(ct, ATTR_ORIG_PORT_DST))
        src->dst_port = ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST));
    if (nfct_attr_is_set(ct, ATTR_ORIG_COUNTER_BYTES)) {
        src->up_bytes = nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_BYTES);
        src->counter_mask |= 1U;
    }
    if (nfct_attr_is_set(ct, ATTR_REPL_COUNTER_BYTES)) {
        src->down_bytes = nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_BYTES);
        src->counter_mask |= 2U;
    }
    if (!nfct_attr_is_set(ct, ATTR_ORIG_COUNTER_BYTES) &&
        !nfct_attr_is_set(ct, ATTR_REPL_COUNTER_BYTES))
        g_tp_quota.event_no_counters++;
    src->last_seen_ms = flowd_tp_now_ms();
    return 0;
}

static void flowd_tp_quota_process_event(const struct nf_conntrack *ct, int destroyed)
{
    struct flowd_tp_quota_src sample;
    struct flowd_tp_quota_src *old;
    uint64_t up_delta = 0, down_delta = 0;
    uint8_t old_counter_mask;
    size_t i;

    if (flowd_tp_quota_event_to_src(ct, &sample) != 0) {
        g_tp_quota.event_parse_failures++;
        return;
    }
    g_tp_quota.last_sample_family = sample.family;
    inet_ntop(sample.family, sample.src_addr, g_tp_quota.last_sample_src,
              sizeof(g_tp_quota.last_sample_src));
    inet_ntop(sample.family, sample.dst_addr, g_tp_quota.last_sample_dst,
              sizeof(g_tp_quota.last_sample_dst));
    /* internet_forward scope: management-plane and intra-LAN destinations are
     * skipped outright so they never even establish a byte baseline. */
    if (!flowd_tp_quota_dst_is_internet(sample.family, sample.dst_addr)) {
        g_tp_quota.skipped_not_forward++;
        return;
    }
    old = flowd_tp_quota_lookup(&sample, 1);
    if (!old)
        return;
    old_counter_mask = old->counter_mask;
    /* Lifecycle notifications frequently omit CTA_COUNTERS_*.  They must not
     * turn an established counter baseline into zero.  For a direction whose
     * counter appears for the first time, establish a baseline and wait for a
     * later sample before accounting; otherwise a long-lived flow would charge
     * all bytes accumulated before the first dump/event with counters. */
    if (sample.counter_mask & 1U) {
        if (old_counter_mask & 1U) {
            if (sample.up_bytes >= old->up_bytes)
                up_delta = sample.up_bytes - old->up_bytes;
            else
                old->up_bytes = sample.up_bytes;
        } else {
            old->up_bytes = sample.up_bytes;
        }
        old->counter_mask |= 1U;
    }
    if (sample.counter_mask & 2U) {
        if (old_counter_mask & 2U) {
            if (sample.down_bytes >= old->down_bytes)
                down_delta = sample.down_bytes - old->down_bytes;
            else
                old->down_bytes = sample.down_bytes;
        } else {
            old->down_bytes = sample.down_bytes;
        }
        old->counter_mask |= 2U;
    }
    if (up_delta || down_delta) {
        for (i = 0; i < g_tp_quota.account_count; i++)
            flowd_tp_quota_account_line(&g_tp_quota.accounts[i], old,
                                        up_delta, down_delta);
    } else if (sample.counter_mask && g_tp_quota.account_count) {
        g_tp_quota.target_misses++;
    }
    old->last_seen_ms = sample.last_seen_ms;
    if (destroyed) {
        old->in_use = FLOWD_TP_SLOT_TOMB;
        if (g_tp_quota.state_live)
            g_tp_quota.state_live--;
    }
}

/*
 * Conntrack lifecycle notifications are not required to carry CTA_COUNTERS.
 * Keep the uloop event path non-blocking, but periodically request a dump over
 * the same netlink socket.  The dump replies arrive asynchronously in
 * flowd_tp_quota_conntrack_cb(), where they update the same monotonic baselines
 * as NEW/UPDATE events.  This is kernel netlink, never procfs text polling.
 */
static void flowd_tp_quota_request_dump(void)
{
    int family;

    if (!g_tp_quota.dump_conntrack || g_tp_quota.dump_pending)
        return;
    /*
     * One dump request at a time.  libnfnetlink tracks request sequences on
     * the handle; sending IPv4 and IPv6 dumps back-to-back makes the second
     * request collide with the first reply stream on this firmware.  Alternate
     * families after NLMSG_DONE instead.
     */
    family = g_tp_quota.dump_family_next == AF_INET6 ? AF_INET6 : AF_INET;
    /*
     * libnetfilter_conntrack forwards nfct_send() to nfnl_send(), whose
     * successful return value is the number of bytes sent.  Treat every
     * non-negative result as success.
     */
    if (nfct_send(g_tp_quota.dump_conntrack, NFCT_Q_DUMP, &family) >= 0) {
        g_tp_quota.dump_pending = 1;
        g_tp_quota.dump_requests++;
    } else {
        g_tp_quota.dump_send_errors++;
        g_tp_quota.dump_last_errno = errno;
        g_tp_quota.conntrack_errors++;
    }
    if (g_tp_quota.dump_pending)
        g_tp_quota.resync_dumping = 1;
}

static void flowd_tp_quota_conntrack_cb(struct uloop_fd *fd, unsigned int events)
{
    unsigned char buffer[64 * 1024];

    (void)events;
    for (;;) {
        struct iovec iov = { .iov_base = buffer, .iov_len = sizeof(buffer) };
        struct msghdr msg;
        struct nlmsghdr *nlh;
        ssize_t received;
        int remaining;

        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        received = recvmsg(fd->fd, &msg, MSG_DONTWAIT);
        if (received < 0 && errno == EINTR)
            continue;
        if (received < 0) {
            if (errno == ENOBUFS) {
                g_tp_quota.conntrack_enobufs++;
                g_tp_quota.conntrack_resync_needed = 1;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            g_tp_quota.conntrack_errors++;
            return;
        }
        if (!received)
            return;
        if (msg.msg_flags & MSG_TRUNC) {
            g_tp_quota.conntrack_errors++;
            g_tp_quota.conntrack_resync_needed = 1;
            continue;
        }
        remaining = (int)received;
        for (nlh = (struct nlmsghdr *)buffer; NLMSG_OK(nlh, remaining);
             nlh = NLMSG_NEXT(nlh, remaining)) {
        struct nf_conntrack *ct;
        int msg_type;
        int destroyed;

            if (nlh->nlmsg_type == NLMSG_DONE) {
                if (g_tp_quota.dump_pending > 0) {
                    g_tp_quota.dump_pending--;
                    g_tp_quota.resync_dumping = 0;
                    g_tp_quota.dump_completed++;
                    g_tp_quota.dump_family_next =
                        g_tp_quota.dump_family_next == AF_INET6 ? AF_INET : AF_INET6;
                }
                continue;
            }
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                if (g_tp_quota.dump_pending > 0) {
                    g_tp_quota.dump_pending--;
                    g_tp_quota.dump_send_errors++;
                    g_tp_quota.dump_last_errno = EIO;
                    if (g_tp_quota.dump_pending == 0)
                        g_tp_quota.resync_dumping = 0;
                }
                g_tp_quota.conntrack_errors++;
                continue;
            }
            if (NFNL_SUBSYS_ID(nlh->nlmsg_type) != NFNL_SUBSYS_CTNETLINK) {
                g_tp_quota.conntrack_filtered++;
                continue;
            }
            msg_type = NFNL_MSG_TYPE(nlh->nlmsg_type);
            /* ctnetlink represents both NEW and UPDATE notifications with the
             * CT_NEW netlink message; the library's callback type is the finer
             * distinction, but the raw message family has no CT_UPDATE opcode. */
            if (msg_type != IPCTNL_MSG_CT_NEW && msg_type != IPCTNL_MSG_CT_DELETE) {
                g_tp_quota.conntrack_filtered++;
                continue;
            }
            destroyed = msg_type == IPCTNL_MSG_CT_DELETE;
            ct = nfct_new();
            if (!ct || nfct_nlmsg_parse(nlh, ct) != 0) {
                g_tp_quota.conntrack_errors++;
                if (ct) nfct_destroy(ct);
                continue;
            }
            flowd_tp_quota_process_event(ct, destroyed);
            nfct_destroy(ct);
            g_tp_quota.conntrack_events++;
        }
        if (remaining != 0) {
            g_tp_quota.conntrack_errors++;
            g_tp_quota.conntrack_resync_needed = 1;
        }
    }
}

static void flowd_tp_quota_poll(void)
{
    int lifecycle_changed = flowd_terminal_policy_lifecycle_scan();

    g_tp_quota.polls++;
    if (flowd_tp_quota_refresh_accounts() != 0)
        g_tp_quota.poll_errors++;
    if (flowd_tp_now_ms() - g_tp_quota.local_refresh_ms >= 30000ULL)
        flowd_tp_quota_refresh_local();
    if (g_tp_quota.conntrack_resync_needed) {
        /* Event loss means the in-memory byte baselines are no longer
         * trustworthy.  Flush what is already attributed, drop the baselines,
         * then ask the kernel for a full table dump so the next deltas are
         * measured from real counters instead of from zero (which would
         * double-count every long-lived connection). Drop them and let subsequent UPDATE/NEW events
         * establish fresh baselines after the dump. */
        flowd_tp_pending_flush_all();
        memset(g_tp_quota.state, 0, sizeof(g_tp_quota.state));
        g_tp_quota.state_live = 0;
        g_tp_quota.conntrack_resync_needed = 0;
        if (g_tp_quota.dump_conntrack) {
            flowd_tp_quota_request_dump();
            g_tp_quota.resyncs++;
        }
    }
    /* Bounded periodic checkpoint of whatever is still only in memory. */
    flowd_tp_pending_flush_all();
    if (g_tp_quota.dump_conntrack &&
        flowd_tp_now_ms() - g_tp_quota.dump_at_ms >= FLOWD_TP_QUOTA_TICK_MS) {
        flowd_tp_quota_request_dump();
        g_tp_quota.dump_at_ms = flowd_tp_now_ms();
    }
    /* Reload settings: apply_mode and the runtime dir can change under us while
     * the daemon keeps running, and a stale copy meant reconciliation silently
     * used the mode that was in effect at start-up. */
    if (flowd_settings_load(&g_tp_quota.settings) == 0)
        g_tp_quota.settings_loaded = 1;
    if ((g_tp_quota.exhausted_seen || lifecycle_changed > 0) &&
        g_tp_quota.settings_loaded) {
        struct json_object *r = flowd_terminal_policy_apply(&g_tp_quota.settings);
        if (r)
            json_object_put(r);
        g_tp_quota.exhausted_seen = 0;
        g_tp_quota.reconcile_at_ms = flowd_tp_now_ms();
    } else if (g_tp_quota.settings_loaded &&
               flowd_tp_now_ms() - g_tp_quota.reconcile_at_ms >=
                   FLOWD_TP_RECONCILE_INTERVAL_MS) {
        char reason[128] = "";
        int rc = flowd_terminal_policy_reconcile(&g_tp_quota.settings,
                                                 reason, sizeof(reason));

        g_tp_quota.reconcile_at_ms = flowd_tp_now_ms();
        if (rc > 0) {
            g_tp_quota.reconciles++;
            snprintf(g_tp_quota.reconcile_reason,
                     sizeof(g_tp_quota.reconcile_reason), "%s", reason);
        } else if (rc < 0) {
            g_tp_quota.reconcile_failures++;
            snprintf(g_tp_quota.reconcile_reason,
                     sizeof(g_tp_quota.reconcile_reason), "%s", reason);
        }
    }
    uloop_timeout_set(&g_tp_quota.timer, FLOWD_TP_QUOTA_TICK_MS);
}

static void flowd_tp_quota_tick(struct uloop_timeout *t)
{
    (void)t;
    flowd_tp_quota_poll();
}

int flowd_terminal_quota_runtime_start(void)
{
    int flags;
    int fd;
    char startup_reason[128] = "";
    int startup_reconcile;
    if (g_tp_quota.active)
        return 0;
    flowd_tp_quota_clear();
    memset(&g_tp_quota.settings, 0, sizeof(g_tp_quota.settings));
    g_tp_quota.settings_loaded = flowd_settings_load(&g_tp_quota.settings) == 0;
    (void)flowd_tp_quota_refresh_accounts();
    flowd_tp_quota_refresh_local();
    g_tp_quota.conntrack = nfct_open(CONNTRACK,
                                      NF_NETLINK_CONNTRACK_NEW |
                                      NF_NETLINK_CONNTRACK_UPDATE |
                                      NF_NETLINK_CONNTRACK_DESTROY);
    if (!g_tp_quota.conntrack) {
        flowd_tp_quota_error_set("conntrack_event_open_failed");
    } else {
        fd = nfct_fd(g_tp_quota.conntrack);
        flags = fd >= 0 ? fcntl(fd, F_GETFL, 0) : -1;
        if (fd < 0 || flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0 ||
            fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
            nfct_close(g_tp_quota.conntrack);
            g_tp_quota.conntrack = NULL;
            flowd_tp_quota_error_set("conntrack_event_nonblock_failed");
        } else {
            memset(&g_tp_quota.conntrack_fd, 0, sizeof(g_tp_quota.conntrack_fd));
            g_tp_quota.conntrack_fd.fd = fd;
            g_tp_quota.conntrack_fd.cb = flowd_tp_quota_conntrack_cb;
            if (uloop_fd_add(&g_tp_quota.conntrack_fd, ULOOP_READ) != 0) {
                g_tp_quota.conntrack_fd.fd = -1;
                nfct_close(g_tp_quota.conntrack);
                g_tp_quota.conntrack = NULL;
                flowd_tp_quota_error_set("conntrack_event_uloop_failed");
            }
        }
    }
    g_tp_quota.dump_conntrack = nfct_open(CONNTRACK, 0);
    if (!g_tp_quota.dump_conntrack) {
        flowd_tp_quota_error_set("conntrack_dump_open_failed");
    } else {
        fd = nfct_fd(g_tp_quota.dump_conntrack);
        flags = fd >= 0 ? fcntl(fd, F_GETFL, 0) : -1;
        if (fd < 0 || flags < 0 ||
            fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0 ||
            fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
            nfct_close(g_tp_quota.dump_conntrack);
            g_tp_quota.dump_conntrack = NULL;
            flowd_tp_quota_error_set("conntrack_dump_nonblock_failed");
        } else {
            memset(&g_tp_quota.dump_fd, 0, sizeof(g_tp_quota.dump_fd));
            g_tp_quota.dump_fd.fd = fd;
            g_tp_quota.dump_fd.cb = flowd_tp_quota_conntrack_cb;
            if (uloop_fd_add(&g_tp_quota.dump_fd, ULOOP_READ) != 0) {
                g_tp_quota.dump_fd.fd = -1;
                nfct_close(g_tp_quota.dump_conntrack);
                g_tp_quota.dump_conntrack = NULL;
                flowd_tp_quota_error_set("conntrack_dump_uloop_failed");
            }
        }
    }
    memset(&g_tp_quota.timer, 0, sizeof(g_tp_quota.timer));
    g_tp_quota.timer.cb = flowd_tp_quota_tick;
    g_tp_quota.active = 1;
    /* Converge storage and the kernel before the first periodic tick.  A
     * restart can inherit an old terminal-policy nft table, and waiting for
     * the 5s accounting timer leaves a real enforcement gap.  This is a single
     * bounded startup operation; subsequent drift checks remain periodic. */
    g_tp_quota.reconcile_at_ms = flowd_tp_now_ms();
    if (g_tp_quota.settings_loaded) {
        startup_reconcile = flowd_terminal_policy_reconcile(
            &g_tp_quota.settings, startup_reason, sizeof(startup_reason));
        if (startup_reconcile > 0) {
            g_tp_quota.reconciles++;
            snprintf(g_tp_quota.reconcile_reason,
                     sizeof(g_tp_quota.reconcile_reason), "startup:%s",
                     startup_reason[0] ? startup_reason : "applied");
        } else if (startup_reconcile < 0) {
            g_tp_quota.reconcile_failures++;
            snprintf(g_tp_quota.reconcile_reason,
                     sizeof(g_tp_quota.reconcile_reason), "startup:%s",
                     startup_reason[0] ? startup_reason : "failed");
        }
    }
    uloop_timeout_set(&g_tp_quota.timer, FLOWD_TP_QUOTA_TICK_MS);
    return 0;
}

void flowd_terminal_quota_runtime_stop(void)
{
    if (!g_tp_quota.active)
        return;
    uloop_timeout_cancel(&g_tp_quota.timer);
    /* Persist whatever is still only in memory so a clean stop loses nothing. */
    flowd_tp_pending_flush_all();
    if (g_tp_quota.conntrack) {
        if (g_tp_quota.conntrack_fd.fd >= 0)
            uloop_fd_delete(&g_tp_quota.conntrack_fd);
        nfct_close(g_tp_quota.conntrack);
        g_tp_quota.conntrack = NULL;
    }
    if (g_tp_quota.dump_conntrack) {
        if (g_tp_quota.dump_fd.fd >= 0)
            uloop_fd_delete(&g_tp_quota.dump_fd);
        nfct_close(g_tp_quota.dump_conntrack);
        g_tp_quota.dump_conntrack = NULL;
    }
    g_tp_quota.active = 0;
    flowd_tp_quota_clear();
}

/*
 * Accounting runtime state.  The checkpoint bound is published here so the
 * contract can state a measured worst-case under-accounting instead of an
 * assurance: at most FLOWD_TP_CHECKPOINT_BYTES per client with pending data,
 * plus whatever arrives inside one tick.
 */
struct json_object *flowd_terminal_quota_runtime_status(void)
{
    struct json_object *out = json_object_new_object();
    size_t target_count = 0;
    size_t i;

    if (!out)
        return NULL;
    for (i = 0; i < g_tp_quota.account_count; i++)
        target_count += g_tp_quota.accounts[i].target_count;
    json_object_object_add(out, "active", json_object_new_boolean(g_tp_quota.active));
    json_object_object_add(out, "source",
                           json_object_new_string("conntrack_netlink_events"));
    json_object_object_add(out, "accounting_scope",
                           json_object_new_string("internet_forward"));
    json_object_object_add(out, "hot_path",
                           json_object_new_string("memory_aggregate_bounded_checkpoint"));
    json_object_object_add(out, "tick_ms",
                           json_object_new_int(FLOWD_TP_QUOTA_TICK_MS));
    json_object_object_add(out, "checkpoint_bytes_per_client",
                           json_object_new_int64((int64_t)FLOWD_TP_CHECKPOINT_BYTES));
    json_object_object_add(out, "checkpoint_at",
                           json_object_new_int64(g_tp_quota.checkpoint_at));
    json_object_object_add(out, "checkpoint_writes",
                           json_object_new_int64((int64_t)g_tp_quota.checkpoint_writes));
    json_object_object_add(out, "checkpoint_errors",
                           json_object_new_int64((int64_t)g_tp_quota.checkpoint_errors));
    json_object_object_add(out, "pending_clients",
                           json_object_new_int64((int64_t)g_tp_quota.pending_live));
    json_object_object_add(out, "pending_bytes",
                           json_object_new_int64((int64_t)g_tp_quota.pending_bytes));
    json_object_object_add(out, "pending_dropped",
                           json_object_new_int64((int64_t)g_tp_quota.pending_dropped));
    json_object_object_add(out, "max_unaccounted_bytes_per_client",
                           json_object_new_int64((int64_t)FLOWD_TP_CHECKPOINT_BYTES));
    json_object_object_add(out, "tracked_flows",
                           json_object_new_int64((int64_t)g_tp_quota.state_live));
    json_object_object_add(out, "conntrack_events",
                           json_object_new_int64((int64_t)g_tp_quota.conntrack_events));
    json_object_object_add(out, "conntrack_filtered",
                           json_object_new_int64((int64_t)g_tp_quota.conntrack_filtered));
    json_object_object_add(out, "conntrack_errors",
                           json_object_new_int64((int64_t)g_tp_quota.conntrack_errors));
    json_object_object_add(out, "conntrack_enobufs",
                           json_object_new_int64((int64_t)g_tp_quota.conntrack_enobufs));
    json_object_object_add(out, "event_parse_failures",
                           json_object_new_int64((int64_t)g_tp_quota.event_parse_failures));
    json_object_object_add(out, "event_no_counters",
                           json_object_new_int64((int64_t)g_tp_quota.event_no_counters));
    json_object_object_add(out, "target_misses",
                           json_object_new_int64((int64_t)g_tp_quota.target_misses));
    json_object_object_add(out, "target_matches",
                           json_object_new_int64((int64_t)g_tp_quota.target_matches));
    json_object_object_add(out, "last_sample_family",
                           json_object_new_int(g_tp_quota.last_sample_family));
    json_object_object_add(out, "last_sample_src",
                           json_object_new_string(g_tp_quota.last_sample_src));
    json_object_object_add(out, "last_sample_dst",
                           json_object_new_string(g_tp_quota.last_sample_dst));
    json_object_object_add(out, "dump_requests",
                           json_object_new_int64((int64_t)g_tp_quota.dump_requests));
    json_object_object_add(out, "dump_completed",
                           json_object_new_int64((int64_t)g_tp_quota.dump_completed));
    json_object_object_add(out, "dump_pending",
                           json_object_new_int((int)g_tp_quota.dump_pending));
    json_object_object_add(out, "dump_send_errors",
                           json_object_new_int64((int64_t)g_tp_quota.dump_send_errors));
    json_object_object_add(out, "dump_last_errno",
                           json_object_new_int(g_tp_quota.dump_last_errno));
    json_object_object_add(out, "resyncs",
                           json_object_new_int64((int64_t)g_tp_quota.resyncs));
    json_object_object_add(out, "skipped_not_forward",
                           json_object_new_int64((int64_t)g_tp_quota.skipped_not_forward));
    json_object_object_add(out, "local_prefixes",
                           json_object_new_int64((int64_t)g_tp_quota.local_addr_count));
    json_object_object_add(out, "polls",
                           json_object_new_int64((int64_t)g_tp_quota.polls));
    json_object_object_add(out, "poll_errors",
                           json_object_new_int64((int64_t)g_tp_quota.poll_errors));
    json_object_object_add(out, "accounts",
                           json_object_new_int64((int64_t)g_tp_quota.account_count));
    json_object_object_add(out, "targets_loaded",
                           json_object_new_int64((int64_t)target_count));
    json_object_object_add(out, "max_targets_per_account",
                           json_object_new_int(FLOWD_TP_MAX_TARGETS_PER_ACCOUNT));
    json_object_object_add(out, "reconcile_interval_ms",
                           json_object_new_int(FLOWD_TP_RECONCILE_INTERVAL_MS));
    json_object_object_add(out, "reconciles",
                           json_object_new_int64((int64_t)g_tp_quota.reconciles));
    json_object_object_add(out, "reconcile_failures",
                           json_object_new_int64((int64_t)g_tp_quota.reconcile_failures));
    if (g_tp_quota.reconcile_reason[0])
        json_object_object_add(out, "reconcile_reason",
                               json_object_new_string(g_tp_quota.reconcile_reason));
    if (g_tp_quota.last_error[0])
        json_object_object_add(out, "last_error",
                               json_object_new_string(g_tp_quota.last_error));
    return out;
}

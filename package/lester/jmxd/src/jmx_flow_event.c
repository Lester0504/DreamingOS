// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DreamingWrt conntrack event collector.
 *
 * This subscribes to ctnetlink NEW/UPDATE/DESTROY via
 * libnetfilter_conntrack.  To avoid the audit database explosion seen with
 * raw event streams, it persists only completed DESTROY lifecycle rows into
 * audit_flow_event_lifecycle.  UPDATE events are kept in a bounded in-memory
 * cache only to recover first_seen/last_seen/event_count for the final row.
 */
#include "jmx_flow_event.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <sqlite3.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include "proc_path.h"
#include "jmx_netconfig_db.h"

#ifndef NFCT_ALL_CT_GROUPS
#define NFCT_ALL_CT_GROUPS (NFCT_T_ALL)
#endif

#define JMX_FLOW_EVENT_BUCKETS 4096
#define JMX_FLOW_EVENT_MAX_TRACKED 120000
#define JMX_FLOW_EVENT_TRACK_TTL_SEC (6 * 3600)
#define JMX_FLOW_EVENT_DB_BUSY_MS 80
#define JMX_FLOW_EVENT_AUDIT_DIR "/opt/dreamingwrt/audit"
#define JMX_FLOW_EVENT_AUDIT_DB JMX_FLOW_EVENT_AUDIT_DIR "/audit.db"
#define JMX_FLOW_EVENT_STREAM_DIR JMX_FLOW_EVENT_AUDIT_DIR "/flow-stream"
#define JMX_FLOW_EVENT_INDEX_DIR JMX_FLOW_EVENT_AUDIT_DIR "/flow-index"
#define JMX_FLOW_EVENT_STREAM_RETENTION_SEC (32 * 86400)
#define JMX_FLOW_EVENT_INDEX_FLUSH_ROWS 256
#define JMX_FLOW_EVENT_LOCAL_PREFIX_MAX 64
#define JMX_FLOW_EVENT_LOCAL_PREFIX_TTL_SEC 30
#define JMX_FLOW_EVENT_RCVBUF_BYTES (4 * 1024 * 1024)
#define JMX_FLOW_EVENT_GROUPS (NFCT_T_NEW | NFCT_T_UPDATE | NFCT_T_DESTROY)
#define JMX_FLOW_EVENT_MAX_DB_ROWS 300000
#define JMX_FLOW_EVENT_PRUNE_INTERVAL_SEC 15
#define JMX_FLOW_EVENT_PRUNE_BATCH_ROWS 10000

struct jmx_flow_track {
    struct jmx_flow_track *next;
    char key[192];
    int64_t first_seen;
    int64_t last_seen;
    uint32_t event_count;
    uint64_t orig_bytes;
    uint64_t repl_bytes;
    uint64_t orig_packets;
    uint64_t repl_packets;
    uint8_t counter_seen;
    uint8_t counter_reset_observed;
};

struct jmx_flow_tuple {
    char src[64];
    char dst[64];
    char repl_src[64];
    char repl_dst[64];
    char snat_ip[64];
    char dnat_ip[64];
    char proto[16];
    int sport;
    int dport;
    int repl_sport;
    int repl_dport;
    int snat_port;
    int dnat_port;
    uint32_t mark;
    uint16_t route_rule_prio;
    uint16_t route_wan_id;
    int mark_set;
    uint64_t orig_bytes;
    uint64_t repl_bytes;
    uint64_t orig_packets;
    uint64_t repl_packets;
    int orig_bytes_set;
    int repl_bytes_set;
    int orig_packets_set;
    int repl_packets_set;
};

struct jmx_flow_local_prefix {
    int family;
    unsigned char addr[16];
    unsigned char mask[16];
    int lan_prefix;
};

struct jmx_flow_event_state {
    pthread_mutex_t lock;
    pthread_t thread;
    int thread_started;
    int stop;
    int active;
    int supported;
    int open_ok;
    int callback_ok;
    int receive_buffer_requested;
    int receive_buffer_bytes;
    int exact_lifecycle_supported;
    int db_accounting_enabled;
    int db_ready;
    int retry_count;
    int last_errno;
    int64_t started_at;
    int64_t updated_at;
    int64_t last_event_at;
    int64_t last_open_at;
    int64_t last_error_at;
    int64_t last_db_init_at;
    int64_t last_db_write_at;
    uint64_t events_total;
    uint64_t events_new;
    uint64_t events_update;
    uint64_t events_destroy;
    uint64_t events_error;
    uint64_t destroy_with_bytes;
    uint64_t destroy_orig_bytes;
    uint64_t destroy_repl_bytes;
    uint64_t db_writes;
    uint64_t db_write_errors;
    uint64_t db_open_errors;
    uint64_t db_completed_rows;
    uint64_t db_prune_runs;
    uint64_t db_prune_rows;
    uint64_t db_prune_errors;
    int64_t last_db_prune_at;
    uint64_t stream_writes;
    uint64_t stream_write_errors;
    uint64_t stream_bytes;
    uint64_t stream_rotations;
    int64_t last_stream_write_at;
    char stream_hour[16];
    char last_stream_error[160];
    uint64_t tracked_current;
    uint64_t track_created;
    uint64_t track_evicted;
    uint64_t track_dropped;
    char state[48];
    char reason[128];
    char last_error[160];
    char last_db_error[200];
    char last_db_prune_error[200];
    char last_event_type[32];
    char last_proto[16];
    char last_src[64];
    char last_dst[64];
    int last_sport;
    int last_dport;
};

static struct jmx_flow_event_state g_flow_event = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .supported = 1,
    .exact_lifecycle_supported = 0,
    .db_accounting_enabled = 0,
    .db_ready = 0,
    .state = "stopped",
    .reason = "not_started",
};

static struct jmx_flow_track *g_tracks[JMX_FLOW_EVENT_BUCKETS];
static sqlite3 *g_flow_db = NULL;
static sqlite3_stmt *g_flow_insert = NULL;
static FILE *g_flow_stream = NULL;
static char g_flow_stream_hour[16];
static uint64_t g_flow_stream_rows;
static uint64_t g_flow_stream_tx_bytes;
static uint64_t g_flow_stream_rx_bytes;
static uint64_t g_flow_stream_tcp;
static uint64_t g_flow_stream_udp;
static uint64_t g_flow_stream_icmp;
static uint64_t g_flow_stream_other;
static struct jmx_flow_local_prefix g_local_prefixes[JMX_FLOW_EVENT_LOCAL_PREFIX_MAX];
static int g_local_prefix_count;
static int64_t g_local_prefix_updated_at;

static int jmx_flow_event_ensure_dir(const char *path, mode_t mode);

static int64_t jmx_flow_event_now(void)
{
    return (int64_t)time(NULL);
}

static void jmx_flow_event_stream_index_write(void)
{
    char path[256];
    char tmp[272];
    FILE *fp;

    if (!g_flow_stream_hour[0])
        return;
    snprintf(path, sizeof(path), "%s/%s", JMX_FLOW_EVENT_INDEX_DIR,
             g_flow_stream_hour);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    fp = fopen(tmp, "w");
    if (!fp)
        return;
    fprintf(fp,
            "version\t1\nrecords\t%llu\ntx_bytes\t%llu\nrx_bytes\t%llu\n"
            "proto_tcp\t%llu\nproto_udp\t%llu\nproto_icmp\t%llu\nproto_other\t%llu\n",
            (unsigned long long)g_flow_stream_rows,
            (unsigned long long)g_flow_stream_tx_bytes,
            (unsigned long long)g_flow_stream_rx_bytes,
            (unsigned long long)g_flow_stream_tcp,
            (unsigned long long)g_flow_stream_udp,
            (unsigned long long)g_flow_stream_icmp,
            (unsigned long long)g_flow_stream_other);
    if (fclose(fp) == 0)
        (void)rename(tmp, path);
    else
        (void)unlink(tmp);
}

static void jmx_flow_event_stream_prune(int64_t now)
{
    const char *dirs[] = { JMX_FLOW_EVENT_STREAM_DIR, JMX_FLOW_EVENT_INDEX_DIR };
    size_t i;

    for (i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        DIR *dir = opendir(dirs[i]);
        struct dirent *de;

        if (!dir)
            continue;
        while ((de = readdir(dir)) != NULL) {
            char path[320];
            struct stat st;

            if (de->d_name[0] == '.')
                continue;
            snprintf(path, sizeof(path), "%s/%s", dirs[i], de->d_name);
            if (stat(path, &st) == 0 && S_ISREG(st.st_mode) &&
                now - (int64_t)st.st_mtime > JMX_FLOW_EVENT_STREAM_RETENTION_SEC)
                (void)unlink(path);
        }
        closedir(dir);
    }
}

static void jmx_flow_event_stream_index_load(const char *hour)
{
    char path[256];
    char key[64];
    unsigned long long value;
    FILE *fp;

    if (!hour || !hour[0])
        return;
    snprintf(path, sizeof(path), "%s/%s", JMX_FLOW_EVENT_INDEX_DIR, hour);
    fp = fopen(path, "r");
    if (!fp)
        return;
    while (fscanf(fp, "%63[^\t]\t%llu\n", key, &value) == 2) {
        if (!strcmp(key, "records")) g_flow_stream_rows = value;
        else if (!strcmp(key, "tx_bytes")) g_flow_stream_tx_bytes = value;
        else if (!strcmp(key, "rx_bytes")) g_flow_stream_rx_bytes = value;
        else if (!strcmp(key, "proto_tcp")) g_flow_stream_tcp = value;
        else if (!strcmp(key, "proto_udp")) g_flow_stream_udp = value;
        else if (!strcmp(key, "proto_icmp")) g_flow_stream_icmp = value;
        else if (!strcmp(key, "proto_other")) g_flow_stream_other = value;
    }
    fclose(fp);
}

static int jmx_flow_event_stream_open(int64_t now)
{
    struct tm tmv;
    time_t when = (time_t)now;
    char hour[16];
    char path[256];

    if (!localtime_r(&when, &tmv))
        return -1;
    if (!strftime(hour, sizeof(hour), "%Y%m%dT%H0000", &tmv))
        return -1;
    if (g_flow_stream && !strcmp(hour, g_flow_stream_hour))
        return 0;

    if (g_flow_stream) {
        fflush(g_flow_stream);
        jmx_flow_event_stream_index_write();
        fclose(g_flow_stream);
        g_flow_stream = NULL;
    }
    if (jmx_flow_event_ensure_dir(JMX_FLOW_EVENT_STREAM_DIR, 0755) != 0 ||
        jmx_flow_event_ensure_dir(JMX_FLOW_EVENT_INDEX_DIR, 0755) != 0)
        return -1;
    snprintf(path, sizeof(path), "%s/%s", JMX_FLOW_EVENT_STREAM_DIR, hour);
    g_flow_stream = fopen(path, "a");
    if (!g_flow_stream)
        return -1;
    setvbuf(g_flow_stream, NULL, _IOLBF, 0);
    snprintf(g_flow_stream_hour, sizeof(g_flow_stream_hour), "%s", hour);
    g_flow_stream_rows = 0;
    g_flow_stream_tx_bytes = 0;
    g_flow_stream_rx_bytes = 0;
    g_flow_stream_tcp = 0;
    g_flow_stream_udp = 0;
    g_flow_stream_icmp = 0;
    g_flow_stream_other = 0;
    jmx_flow_event_stream_index_load(hour);
    jmx_flow_event_stream_prune(now);

    pthread_mutex_lock(&g_flow_event.lock);
    g_flow_event.stream_rotations++;
    snprintf(g_flow_event.stream_hour, sizeof(g_flow_event.stream_hour), "%s", hour);
    g_flow_event.last_stream_error[0] = '\0';
    pthread_mutex_unlock(&g_flow_event.lock);
    return 0;
}

static void jmx_flow_event_stream_write(const struct jmx_flow_tuple *t,
                                        int64_t first_seen, int64_t last_seen,
                                        int64_t destroy_ts, uint32_t event_count,
                                        const char *direction,
                                        const char *initiator,
                                        const char *client_ip,
                                        const char *remote_ip,
                                        const char *service,
                                        uint64_t orig_packets,
                                        uint64_t repl_packets,
                                        uint64_t orig_bytes,
                                        uint64_t repl_bytes,
                                        uint64_t tx_bytes,
                                        uint64_t rx_bytes)
{
    int n;

    if (!t || jmx_flow_event_stream_open(destroy_ts) != 0) {
        pthread_mutex_lock(&g_flow_event.lock);
        g_flow_event.stream_write_errors++;
        snprintf(g_flow_event.last_stream_error,
                 sizeof(g_flow_event.last_stream_error), "open: %s", strerror(errno));
        pthread_mutex_unlock(&g_flow_event.lock);
        return;
    }
    n = fprintf(g_flow_stream,
                "%lld\t%lld\t%lld\t%u\t%s\t%s\t%d\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t"
                "%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%s\t%s\t%d\t%d\t%u\t%u\t%u\t%s\n",
                (long long)destroy_ts, (long long)first_seen, (long long)last_seen,
                event_count, t->proto, t->src, t->sport, t->dst, t->dport,
                direction, initiator, client_ip, remote_ip, service,
                (unsigned long long)orig_packets, (unsigned long long)repl_packets,
                (unsigned long long)orig_bytes, (unsigned long long)repl_bytes,
                (unsigned long long)tx_bytes, (unsigned long long)rx_bytes,
                t->snat_ip, t->dnat_ip, t->snat_port, t->dnat_port,
                t->mark, (unsigned)t->route_rule_prio, (unsigned)t->route_wan_id,
                t->repl_dst);
    if (n < 0) {
        clearerr(g_flow_stream);
        pthread_mutex_lock(&g_flow_event.lock);
        g_flow_event.stream_write_errors++;
        snprintf(g_flow_event.last_stream_error,
                 sizeof(g_flow_event.last_stream_error), "write: %s", strerror(errno));
        pthread_mutex_unlock(&g_flow_event.lock);
        return;
    }
    g_flow_stream_rows++;
    g_flow_stream_tx_bytes += tx_bytes;
    g_flow_stream_rx_bytes += rx_bytes;
    if (!strcasecmp(t->proto, "tcp")) g_flow_stream_tcp++;
    else if (!strcasecmp(t->proto, "udp")) g_flow_stream_udp++;
    else if (!strncasecmp(t->proto, "icmp", 4)) g_flow_stream_icmp++;
    else g_flow_stream_other++;
    if (g_flow_stream_rows % JMX_FLOW_EVENT_INDEX_FLUSH_ROWS == 0) {
        fflush(g_flow_stream);
        jmx_flow_event_stream_index_write();
    }
    pthread_mutex_lock(&g_flow_event.lock);
    g_flow_event.stream_writes++;
    g_flow_event.stream_bytes += (uint64_t)n;
    g_flow_event.last_stream_write_at = destroy_ts;
    pthread_mutex_unlock(&g_flow_event.lock);
}

static void jmx_flow_event_set_state(const char *state, const char *reason,
                                     int err)
{
    pthread_mutex_lock(&g_flow_event.lock);
    snprintf(g_flow_event.state, sizeof(g_flow_event.state), "%s",
             state ? state : "unknown");
    snprintf(g_flow_event.reason, sizeof(g_flow_event.reason), "%s",
             reason ? reason : "");
    g_flow_event.last_errno = err;
    g_flow_event.updated_at = jmx_flow_event_now();
    if (err) {
        g_flow_event.last_error_at = g_flow_event.updated_at;
        snprintf(g_flow_event.last_error, sizeof(g_flow_event.last_error),
                 "%s: errno=%d (%s)", reason ? reason : "error", err,
                 strerror(err));
    }
    pthread_mutex_unlock(&g_flow_event.lock);
}

static void jmx_flow_event_set_db_error(const char *where, sqlite3 *db)
{
    const char *msg = db ? sqlite3_errmsg(db) : "sqlite unavailable";
    pthread_mutex_lock(&g_flow_event.lock);
    g_flow_event.db_write_errors++;
    g_flow_event.last_db_init_at = jmx_flow_event_now();
    snprintf(g_flow_event.last_db_error, sizeof(g_flow_event.last_db_error),
             "%s: %s", where ? where : "db", msg ? msg : "unknown");
    g_flow_event.updated_at = g_flow_event.last_db_init_at;
    pthread_mutex_unlock(&g_flow_event.lock);
}

static uint32_t jmx_flow_hash_key(const char *s)
{
    uint32_t h = 2166136261u;
    const unsigned char *p = (const unsigned char *)(s ? s : "");

    while (*p) {
        h ^= *p++;
        h *= 16777619u;
    }
    return h;
}

static int jmx_flow_event_ensure_dir(const char *path, mode_t mode)
{
    struct stat st;

    if (mkdir(path, mode) == 0)
        return 0;
    if (errno != EEXIST)
        return -1;
    if (stat(path, &st) != 0)
        return -1;
    return S_ISDIR(st.st_mode) ? 0 : -1;
}

static int jmx_flow_event_ipv4_private(const char *ip)
{
    struct in_addr a;
    uint32_t v;

    if (!ip || inet_pton(AF_INET, ip, &a) != 1)
        return 0;
    v = ntohl(a.s_addr);
    if ((v >> 24) == 10)
        return 1;
    if ((v >> 20) == ((172 << 4) | 1)) /* 172.16.0.0/12 */
        return 1;
    if ((v >> 16) == ((192 << 8) | 168))
        return 1;
    if ((v >> 22) == ((100 << 2) | 1)) /* 100.64.0.0/10 */
        return 1;
    if ((v >> 16) == ((169 << 8) | 254))
        return 1;
    if ((v >> 24) == 127)
        return 1;
    return 0;
}

static int jmx_flow_event_ipv6_local(const char *ip)
{
    struct in6_addr a;

    if (!ip || inet_pton(AF_INET6, ip, &a) != 1)
        return 0;
    if ((a.s6_addr[0] & 0xfe) == 0xfc) /* fc00::/7 */
        return 1;
    if (a.s6_addr[0] == 0xfe && (a.s6_addr[1] & 0xc0) == 0x80) /* fe80::/10 */
        return 1;
    for (int i = 0; i < 15; i++)
        if (a.s6_addr[i])
            return 0;
    return a.s6_addr[15] == 1;
}

static int jmx_flow_event_ip_private_or_local(const char *ip)
{
    return jmx_flow_event_ipv4_private(ip) || jmx_flow_event_ipv6_local(ip);
}

static int jmx_flow_event_ifname_is_wan(const char *name)
{
    const char *p;

    if (!name || !name[0])
        return 0;
    if (!strncasecmp(name, "ppp", 3))
        return 1;
    for (p = name; p[0] && p[1] && p[2]; p++) {
        if (tolower((unsigned char)p[0]) == 'w' &&
            tolower((unsigned char)p[1]) == 'a' &&
            tolower((unsigned char)p[2]) == 'n')
            return 1;
    }
    return 0;
}

static int jmx_flow_event_ifname_is_lan(const char *name)
{
    const char *p;

    if (!name || !name[0] || !strcmp(name, "lo") ||
        jmx_flow_event_ifname_is_wan(name))
        return 0;
    if (!strncasecmp(name, "br-", 3) || !strncasecmp(name, "docker", 6))
        return 1;
    for (p = name; p[0] && p[1] && p[2]; p++) {
        if (tolower((unsigned char)p[0]) == 'l' &&
            tolower((unsigned char)p[1]) == 'a' &&
            tolower((unsigned char)p[2]) == 'n')
            return 1;
    }
    return 0;
}

static void jmx_flow_event_refresh_local_prefixes(int64_t now)
{
    struct ifaddrs *ifas = NULL;
    struct ifaddrs *ifa;

    if (g_local_prefix_updated_at > 0 &&
        now - g_local_prefix_updated_at < JMX_FLOW_EVENT_LOCAL_PREFIX_TTL_SEC)
        return;
    g_local_prefix_count = 0;
    if (getifaddrs(&ifas) != 0) {
        g_local_prefix_updated_at = now;
        return;
    }
    for (ifa = ifas; ifa && g_local_prefix_count < JMX_FLOW_EVENT_LOCAL_PREFIX_MAX;
         ifa = ifa->ifa_next) {
        struct jmx_flow_local_prefix *p;
        const void *addr = NULL;
        const void *mask = NULL;
        size_t len = 0;

        if (!ifa->ifa_addr || !ifa->ifa_netmask)
            continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            addr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            mask = &((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr;
            len = 4;
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            addr = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
            mask = &((struct sockaddr_in6 *)ifa->ifa_netmask)->sin6_addr;
            len = 16;
        } else {
            continue;
        }
        p = &g_local_prefixes[g_local_prefix_count++];
        memset(p, 0, sizeof(*p));
        p->family = ifa->ifa_addr->sa_family;
        memcpy(p->addr, addr, len);
        memcpy(p->mask, mask, len);
        p->lan_prefix = jmx_flow_event_ifname_is_lan(ifa->ifa_name);
    }
    freeifaddrs(ifas);
    g_local_prefix_updated_at = now;
}

static int jmx_flow_event_ip_matches_local(const char *ip, int lan_prefix)
{
    unsigned char addr[16];
    int family;
    size_t len;
    int i, j;

    if (!ip || !ip[0])
        return 0;
    family = strchr(ip, ':') ? AF_INET6 : AF_INET;
    len = family == AF_INET6 ? 16 : 4;
    if (inet_pton(family, ip, addr) != 1)
        return 0;
    for (i = 0; i < g_local_prefix_count; i++) {
        struct jmx_flow_local_prefix *p = &g_local_prefixes[i];
        int matched = 1;

        if (p->family != family || (lan_prefix && !p->lan_prefix))
            continue;
        for (j = 0; j < (int)len; j++) {
            unsigned char wanted_mask = lan_prefix ? p->mask[j] : 0xff;
            if ((addr[j] & wanted_mask) != (p->addr[j] & wanted_mask)) {
                matched = 0;
                break;
            }
        }
        if (matched)
            return 1;
    }
    return 0;
}

static const char *jmx_flow_event_direction_from_tuple(const struct jmx_flow_tuple *t,
                                                        const char **initiator,
                                                        const char **source)
{
    int src_lan, dst_lan, src_host, dst_host, repl_src_lan;

    if (initiator)
        *initiator = "unknown";
    if (source)
        *source = "unresolved_original_reply_tuple";
    if (!t)
        return "unknown";
    jmx_flow_event_refresh_local_prefixes(jmx_flow_event_now());
    src_lan = jmx_flow_event_ip_private_or_local(t->src) ||
              jmx_flow_event_ip_matches_local(t->src, 1);
    dst_lan = jmx_flow_event_ip_private_or_local(t->dst) ||
              jmx_flow_event_ip_matches_local(t->dst, 1);
    src_host = jmx_flow_event_ip_matches_local(t->src, 0);
    dst_host = jmx_flow_event_ip_matches_local(t->dst, 0);
    repl_src_lan = jmx_flow_event_ip_private_or_local(t->repl_src) ||
                   jmx_flow_event_ip_matches_local(t->repl_src, 1);

    /* Exact router addresses take precedence over broad private prefixes. */
    if (src_host && dst_lan) {
        if (initiator) *initiator = "local";
        if (source) *source = "original_source_router_address_to_lan";
        return "lan";
    }
    if (src_lan && dst_host) {
        if (initiator) *initiator = "local";
        if (source) *source = "original_source_lan_to_router_address";
        return "lan";
    }
    if (src_host && !dst_lan) {
        if (initiator) *initiator = "local";
        if (source) *source = "original_source_router_address";
        return "outbound";
    }
    if (!src_lan && dst_host) {
        if (initiator) *initiator = "remote";
        if (source) *source = repl_src_lan ?
            "original_destination_router_address+reply_source_lan_dnat" :
            "original_destination_router_address";
        return "inbound";
    }
    if (src_lan && !dst_lan) {
        if (initiator) *initiator = "local";
        if (source) *source = "original_source_lan_prefix";
        return "outbound";
    }
    if (!src_lan && dst_lan) {
        if (initiator) *initiator = "remote";
        if (source) *source = "original_destination_lan_prefix";
        return "inbound";
    }
    if (!src_lan && repl_src_lan) {
        if (initiator) *initiator = "remote";
        if (source) *source = "reply_source_lan_dnat";
        return "inbound";
    }
    if (src_lan && dst_lan) {
        if (initiator) *initiator = "local";
        if (source) *source = "original_lan_to_lan";
        return "lan";
    }
    return "unknown";
}

static const char *jmx_flow_event_service_hint(const char *proto, int dport,
                                               char *buf, size_t len)
{
    int tcp = proto && !strcasecmp(proto, "tcp");
    int udp = proto && !strcasecmp(proto, "udp");
    const char *svc = "";

    if (!buf || len == 0)
        return "";
    buf[0] = '\0';
    switch (dport) {
    case 20:
    case 21: svc = "ftp"; break;
    case 22: svc = "ssh"; break;
    case 25: svc = "smtp"; break;
    case 53: svc = "dns"; break;
    case 67:
    case 68: svc = "dhcp"; break;
    case 80: svc = "http"; break;
    case 110: svc = "pop3"; break;
    case 123: svc = "ntp"; break;
    case 143: svc = "imap"; break;
    case 443: svc = udp ? "quic" : (tcp ? "https" : "https"); break;
    case 465: svc = "smtps"; break;
    case 500: svc = "ipsec-isakmp"; break;
    case 587: svc = "smtp-submission"; break;
    case 853: svc = "dns-over-tls"; break;
    case 993: svc = "imaps"; break;
    case 995: svc = "pop3s"; break;
    case 1194: svc = "openvpn"; break;
    case 1701: svc = "l2tp"; break;
    case 1723: svc = "pptp"; break;
    case 1900: svc = "ssdp"; break;
    case 1935: svc = "rtmp"; break;
    case 3478:
    case 5349: svc = "stun-turn"; break;
    case 4500: svc = "ipsec-nat-t"; break;
    case 5222:
    case 5223: svc = "xmpp"; break;
    case 5353: svc = "mdns"; break;
    case 8080: svc = "http-alt"; break;
    default:
        if (dport > 0 && dport <= 65535)
            snprintf(buf, len, "%s/%d", (proto && proto[0]) ? proto : "ip", dport);
        return buf;
    }
    snprintf(buf, len, "%s", svc);
    return buf;
}

/*
 * Destination host / application lookup for destroyed flows.
 *
 * audit_flow_event_lifecycle declares destination_host, host, host_source,
 * destination_app_id and destination_app_name, but the INSERT never bound them,
 * so all 300k rows carried empty values from the first day. Aggregating that
 * table by application could then only ever produce protocol names such as
 * "https" or "tcp/25565", which is what the UI was showing where an application
 * name belonged.
 *
 * The evidence lives in the af_active_host procfs table. Two constraints shape
 * how it can be used here:
 *
 * 1. This runs on the ctnetlink worker thread at roughly 8-10 destroy events per
 *    second on 30.1 (300093 events over 37316 s measured, 576 in the busiest
 *    60 s window). Re-reading a 65-line procfs file per event would be wasteful,
 *    so the snapshot is cached with a short TTL.
 * 2. By the time conntrack reports a destroy, the matching af_active_host entry
 *    may already have aged out (that table ages at 180 s). Matching is therefore
 *    best-effort and a miss is recorded as an empty host rather than a guess.
 */
#define JMX_FLOW_HOST_CACHE_TTL_SEC 5
#define JMX_FLOW_HOST_CACHE_MAX 512

struct jmx_flow_host_entry {
    char host[256];
    char src_ip[64];
    char dst_ip[64];
    char proto[16];
    int dst_port;
    int app_id;
    char app_name[128];
};

static struct jmx_flow_host_entry g_flow_hosts[JMX_FLOW_HOST_CACHE_MAX];
static int g_flow_host_count;
static int64_t g_flow_host_loaded_at;

/* Caller must hold no lock; only the ctnetlink worker thread touches this. */
static void jmx_flow_event_refresh_hosts(int64_t now)
{
    FILE *fp;
    char line[1024];
    int line_no = 0;
    sqlite3 *sig_db = NULL;

    if (g_flow_host_loaded_at > 0 &&
        now - g_flow_host_loaded_at < JMX_FLOW_HOST_CACHE_TTL_SEC)
        return;
    g_flow_host_loaded_at = now;
    g_flow_host_count = 0;

    fp = jmx_fopen_af("af_active_host", "r");
    if (!fp)
        return;
    (void)jmx_signature_db_open(&sig_db);

    while (fgets(line, sizeof(line), fp) && g_flow_host_count < JMX_FLOW_HOST_CACHE_MAX) {
        char host[256] = {0}, mac[32] = {0}, src_ip[64] = {0}, dst_ip[64] = {0}, proto[16] = {0};
        unsigned int src_port = 0, dst_port = 0, app_proto = 0, drop = 0, last_update = 0;
        struct jmx_flow_host_entry *e;

        if (line_no++ == 0)
            continue;
        if (sscanf(line, "%255s %31s %63s %u %63s %u %15s %u %u %u",
                   host, mac, src_ip, &src_port, dst_ip, &dst_port, proto,
                   &app_proto, &drop, &last_update) < 10)
            continue;
        if (!host[0] || !strcmp(host, "-"))
            continue;

        e = &g_flow_hosts[g_flow_host_count];
        memset(e, 0, sizeof(*e));
        snprintf(e->host, sizeof(e->host), "%s", host);
        snprintf(e->src_ip, sizeof(e->src_ip), "%s", src_ip);
        snprintf(e->dst_ip, sizeof(e->dst_ip), "%s", dst_ip);
        snprintf(e->proto, sizeof(e->proto), "%s", proto);
        e->dst_port = (int)dst_port;
        /* app_proto from this table is a protocol class (1/2), never an app_id -
         * resolve the real one from the hostname instead. */
        if (sig_db && jmx_signature_db_resolve_host_app_id_with_db(sig_db, host, proto,
                                                                  (int)dst_port,
                                                                  &e->app_id) != 0)
            e->app_id = 0;
        /* Resolve the name here, on this thread, from the same handle. The global
         * app_name_table that get_app_name_by_id() reads is owned by the main
         * thread and rebuilt on signature updates, so it is not safe to read from
         * the ctnetlink worker. */
        if (e->app_id > 0 && sig_db) {
            sqlite3_stmt *st = NULL;

            if (sqlite3_prepare_v2(sig_db, "SELECT COALESCE(name,'') FROM app WHERE app_id=?1",
                                   -1, &st, NULL) == SQLITE_OK) {
                sqlite3_bind_int(st, 1, e->app_id);
                if (sqlite3_step(st) == SQLITE_ROW) {
                    const char *name = (const char *)sqlite3_column_text(st, 0);

                    if (name && name[0])
                        snprintf(e->app_name, sizeof(e->app_name), "%s", name);
                }
                sqlite3_finalize(st);
            }
        }
        g_flow_host_count++;
    }
    if (sig_db)
        sqlite3_close(sig_db);
    fclose(fp);
}

/* Returns 1 when a hostname was found. Matching prefers the full destination
 * tuple and falls back to destination IP alone, because NAT can rewrite the port
 * between what af_active_host observed and what conntrack reports. */
static int jmx_flow_event_lookup_host(const char *client_ip, const char *remote_ip,
                                      const char *proto, int dport,
                                      char *host, size_t host_len,
                                      int *app_id, char *app_name, size_t app_name_len,
                                      const char **host_source)
{
    int i;
    int fallback = -1;

    if (host && host_len)
        host[0] = '\0';
    if (app_id)
        *app_id = 0;
    if (app_name && app_name_len)
        app_name[0] = '\0';
    if (host_source)
        *host_source = "";
    if (!remote_ip || !remote_ip[0] || !host || !host_len)
        return 0;

    for (i = 0; i < g_flow_host_count; i++) {
        struct jmx_flow_host_entry *e = &g_flow_hosts[i];

        if (strcmp(e->dst_ip, remote_ip))
            continue;
        if (client_ip && client_ip[0] && e->src_ip[0] && strcmp(e->src_ip, client_ip)) {
            if (fallback < 0)
                fallback = i;
            continue;
        }
        if (dport > 0 && e->dst_port > 0 && e->dst_port != dport) {
            if (fallback < 0)
                fallback = i;
            continue;
        }
        if (proto && proto[0] && e->proto[0] && strcasecmp(e->proto, proto)) {
            if (fallback < 0)
                fallback = i;
            continue;
        }
        snprintf(host, host_len, "%s", e->host);
        if (app_id)
            *app_id = e->app_id;
        if (app_name && app_name_len)
            snprintf(app_name, app_name_len, "%s", e->app_name);
        if (host_source)
            *host_source = "af_active_host";
        return 1;
    }
    if (fallback >= 0) {
        /* Same destination address, weaker agreement on port/protocol/client.
         * Label it distinctly so a consumer can tell how the host was obtained. */
        snprintf(host, host_len, "%s", g_flow_hosts[fallback].host);
        if (app_id)
            *app_id = g_flow_hosts[fallback].app_id;
        if (app_name && app_name_len)
            snprintf(app_name, app_name_len, "%s", g_flow_hosts[fallback].app_name);
        if (host_source)
            *host_source = "af_active_host_dst_ip";
        return 1;
    }
    return 0;
}

static int jmx_flow_event_lookup_arp_mac(const char *ip, char *mac, size_t len)
{
    FILE *fp;
    char line[256];

    if (mac && len)
        mac[0] = '\0';
    if (!ip || !ip[0] || !mac || len < 18)
        return -1;
    fp = fopen("/proc/net/arp", "r");
    if (!fp)
        return -1;
    while (fgets(line, sizeof(line), fp)) {
        char row_ip[64] = "";
        char row_mac[32] = "";

        if (sscanf(line, "%63s %*s %*s %31s %*s %*s", row_ip, row_mac) != 2)
            continue;
        if (!strcmp(row_ip, ip) && strcmp(row_mac, "00:00:00:00:00:00")) {
            snprintf(mac, len, "%s", row_mac);
            fclose(fp);
            return 0;
        }
    }
    fclose(fp);
    return -1;
}

static const char *jmx_flow_event_type_name(enum nf_conntrack_msg_type type)
{
    if (type == NFCT_T_NEW)
        return "new";
    if (type == NFCT_T_UPDATE)
        return "update";
    if (type == NFCT_T_DESTROY)
        return "destroy";
    if (type == NFCT_T_ERROR)
        return "error";
    return "unknown";
}

static void jmx_flow_event_ipv4_to_str(uint32_t addr, char *buf, size_t len)
{
    struct in_addr a;

    if (!buf || !len)
        return;
    buf[0] = '\0';
    a.s_addr = addr;
    if (!inet_ntop(AF_INET, &a, buf, len))
        buf[0] = '\0';
}

static void jmx_flow_event_ipv6_to_str(const void *addr, char *buf, size_t len)
{
    if (!buf || !len)
        return;
    buf[0] = '\0';
    if (!addr)
        return;
    if (!inet_ntop(AF_INET6, addr, buf, len))
        buf[0] = '\0';
}

static void jmx_flow_event_extract_tuple(struct nf_conntrack *ct,
                                         struct jmx_flow_tuple *t)
{
    uint8_t l4 = 0;
    uint8_t l3 = 0;

    if (!t)
        return;
    memset(t, 0, sizeof(*t));
    if (!ct)
        return;

    if (nfct_attr_is_set(ct, ATTR_ORIG_L3PROTO))
        l3 = nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO);

    if ((l3 == AF_INET6 || nfct_attr_is_set(ct, ATTR_ORIG_IPV6_SRC)) &&
        nfct_attr_is_set(ct, ATTR_ORIG_IPV6_SRC)) {
        jmx_flow_event_ipv6_to_str(nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC),
                                   t->src, sizeof(t->src));
        if (nfct_attr_is_set(ct, ATTR_ORIG_IPV6_DST))
            jmx_flow_event_ipv6_to_str(nfct_get_attr(ct, ATTR_ORIG_IPV6_DST),
                                       t->dst, sizeof(t->dst));
    } else {
        if (nfct_attr_is_set(ct, ATTR_ORIG_IPV4_SRC))
            jmx_flow_event_ipv4_to_str(nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC),
                                       t->src, sizeof(t->src));
        if (nfct_attr_is_set(ct, ATTR_ORIG_IPV4_DST))
            jmx_flow_event_ipv4_to_str(nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST),
                                       t->dst, sizeof(t->dst));
    }

    if (nfct_attr_is_set(ct, ATTR_REPL_IPV6_SRC)) {
        jmx_flow_event_ipv6_to_str(nfct_get_attr(ct, ATTR_REPL_IPV6_SRC),
                                   t->repl_src, sizeof(t->repl_src));
        if (nfct_attr_is_set(ct, ATTR_REPL_IPV6_DST))
            jmx_flow_event_ipv6_to_str(nfct_get_attr(ct, ATTR_REPL_IPV6_DST),
                                       t->repl_dst, sizeof(t->repl_dst));
    } else {
        if (nfct_attr_is_set(ct, ATTR_REPL_IPV4_SRC))
            jmx_flow_event_ipv4_to_str(nfct_get_attr_u32(ct, ATTR_REPL_IPV4_SRC),
                                       t->repl_src, sizeof(t->repl_src));
        if (nfct_attr_is_set(ct, ATTR_REPL_IPV4_DST))
            jmx_flow_event_ipv4_to_str(nfct_get_attr_u32(ct, ATTR_REPL_IPV4_DST),
                                       t->repl_dst, sizeof(t->repl_dst));
    }

    if (nfct_attr_is_set(ct, ATTR_ORIG_L4PROTO)) {
        l4 = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
        if (l4 == IPPROTO_TCP)
            snprintf(t->proto, sizeof(t->proto), "tcp");
        else if (l4 == IPPROTO_UDP)
            snprintf(t->proto, sizeof(t->proto), "udp");
        else if (l4 == IPPROTO_ICMP)
            snprintf(t->proto, sizeof(t->proto), "icmp");
        else if (l4 == IPPROTO_ICMPV6)
            snprintf(t->proto, sizeof(t->proto), "icmpv6");
        else
            snprintf(t->proto, sizeof(t->proto), "%u", (unsigned)l4);
    }
    if (nfct_attr_is_set(ct, ATTR_ORIG_PORT_SRC))
        t->sport = ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC));
    if (nfct_attr_is_set(ct, ATTR_ORIG_PORT_DST))
        t->dport = ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST));
    if (nfct_attr_is_set(ct, ATTR_REPL_PORT_SRC))
        t->repl_sport = ntohs(nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC));
    if (nfct_attr_is_set(ct, ATTR_REPL_PORT_DST))
        t->repl_dport = ntohs(nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST));
    if (nfct_attr_is_set(ct, ATTR_SNAT_IPV4))
        jmx_flow_event_ipv4_to_str(nfct_get_attr_u32(ct, ATTR_SNAT_IPV4),
                                   t->snat_ip, sizeof(t->snat_ip));
    if (nfct_attr_is_set(ct, ATTR_DNAT_IPV4))
        jmx_flow_event_ipv4_to_str(nfct_get_attr_u32(ct, ATTR_DNAT_IPV4),
                                   t->dnat_ip, sizeof(t->dnat_ip));
    if (nfct_attr_is_set(ct, ATTR_SNAT_PORT))
        t->snat_port = ntohs(nfct_get_attr_u16(ct, ATTR_SNAT_PORT));
    if (nfct_attr_is_set(ct, ATTR_DNAT_PORT))
        t->dnat_port = ntohs(nfct_get_attr_u16(ct, ATTR_DNAT_PORT));
    /*
     * DESTROY notifications do not consistently carry the dedicated NAT
     * attributes.  ORIGINAL and REPLY are still kernel-owned evidence: an
     * unchanged flow has orig.src == reply.dst and orig.dst == reply.src.
     */
    if (!t->snat_ip[0] && t->src[0] && t->repl_dst[0] &&
        strcmp(t->src, t->repl_dst))
        snprintf(t->snat_ip, sizeof(t->snat_ip), "%s", t->repl_dst);
    if (!t->dnat_ip[0] && t->dst[0] && t->repl_src[0] &&
        strcmp(t->dst, t->repl_src))
        snprintf(t->dnat_ip, sizeof(t->dnat_ip), "%s", t->repl_src);
    if (!t->snat_port && t->sport > 0 && t->repl_dport > 0 &&
        t->sport != t->repl_dport)
        t->snat_port = t->repl_dport;
    if (!t->dnat_port && t->dport > 0 && t->repl_sport > 0 &&
        t->dport != t->repl_sport)
        t->dnat_port = t->repl_sport;
    if (nfct_attr_is_set(ct, ATTR_ORIG_COUNTER_BYTES)) {
        t->orig_bytes = nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_BYTES);
        t->orig_bytes_set = 1;
    }
    if (nfct_attr_is_set(ct, ATTR_REPL_COUNTER_BYTES)) {
        t->repl_bytes = nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_BYTES);
        t->repl_bytes_set = 1;
    }
    if (nfct_attr_is_set(ct, ATTR_ORIG_COUNTER_PACKETS)) {
        t->orig_packets = nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_PACKETS);
        t->orig_packets_set = 1;
    }
    if (nfct_attr_is_set(ct, ATTR_REPL_COUNTER_PACKETS)) {
        t->repl_packets = nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_PACKETS);
        t->repl_packets_set = 1;
    }
    if (nfct_attr_is_set(ct, ATTR_MARK)) {
        t->mark = nfct_get_attr_u32(ct, ATTR_MARK);
        t->mark_set = 1;
        /*
         * jmx.ko exports route policy attribution through ct mark:
         * bits 31..16 = route rule priority, bits 15..0 = selected WAN id.
         * This is metadata for ctnetlink lifecycle rows; skb->mark still
         * carries the real fwmark used by ip rule lookup.
         */
        t->route_rule_prio = (uint16_t)((t->mark >> 16) & 0xffff);
        t->route_wan_id = (uint16_t)(t->mark & 0xffff);
    }
}

static void jmx_flow_event_make_key(const struct jmx_flow_tuple *t,
                                    char *buf, size_t len)
{
    if (!buf || !len)
        return;
    snprintf(buf, len, "%s|%s|%d|%s|%d",
             t && t->proto[0] ? t->proto : "unknown",
             t && t->src[0] ? t->src : "",
             t ? t->sport : 0,
             t && t->dst[0] ? t->dst : "",
             t ? t->dport : 0);
}

static void jmx_flow_event_prune_tracks(int64_t now)
{
    uint64_t evicted = 0;

    for (int i = 0; i < JMX_FLOW_EVENT_BUCKETS; i++) {
        struct jmx_flow_track **pp = &g_tracks[i];
        while (*pp) {
            struct jmx_flow_track *cur = *pp;
            if (cur->last_seen > 0 && cur->last_seen < now - JMX_FLOW_EVENT_TRACK_TTL_SEC) {
                *pp = cur->next;
                free(cur);
                evicted++;
            } else {
                pp = &cur->next;
            }
        }
    }
    if (evicted) {
        pthread_mutex_lock(&g_flow_event.lock);
        if (g_flow_event.tracked_current >= evicted)
            g_flow_event.tracked_current -= evicted;
        else
            g_flow_event.tracked_current = 0;
        g_flow_event.track_evicted += evicted;
        pthread_mutex_unlock(&g_flow_event.lock);
    }
}

static struct jmx_flow_track *jmx_flow_event_track_get(const char *key,
                                                       int create,
                                                       int64_t now)
{
    static int64_t last_prune;
    uint32_t h;
    struct jmx_flow_track *tr;
    uint64_t current;

    if (!key || !key[0])
        return NULL;
    if (create && now - last_prune > 60) {
        jmx_flow_event_prune_tracks(now);
        last_prune = now;
    }

    h = jmx_flow_hash_key(key) % JMX_FLOW_EVENT_BUCKETS;
    for (tr = g_tracks[h]; tr; tr = tr->next) {
        if (!strcmp(tr->key, key))
            return tr;
    }
    if (!create)
        return NULL;

    pthread_mutex_lock(&g_flow_event.lock);
    current = g_flow_event.tracked_current;
    pthread_mutex_unlock(&g_flow_event.lock);
    if (current >= JMX_FLOW_EVENT_MAX_TRACKED) {
        pthread_mutex_lock(&g_flow_event.lock);
        g_flow_event.track_dropped++;
        pthread_mutex_unlock(&g_flow_event.lock);
        return NULL;
    }

    tr = calloc(1, sizeof(*tr));
    if (!tr) {
        pthread_mutex_lock(&g_flow_event.lock);
        g_flow_event.track_dropped++;
        pthread_mutex_unlock(&g_flow_event.lock);
        return NULL;
    }
    snprintf(tr->key, sizeof(tr->key), "%s", key);
    tr->first_seen = now;
    tr->last_seen = now;
    tr->next = g_tracks[h];
    g_tracks[h] = tr;

    pthread_mutex_lock(&g_flow_event.lock);
    g_flow_event.tracked_current++;
    g_flow_event.track_created++;
    pthread_mutex_unlock(&g_flow_event.lock);
    return tr;
}

static void jmx_flow_event_track_remove(struct jmx_flow_track *tr)
{
    uint32_t h;
    struct jmx_flow_track **pp;

    if (!tr)
        return;
    h = jmx_flow_hash_key(tr->key) % JMX_FLOW_EVENT_BUCKETS;
    pp = &g_tracks[h];
    while (*pp) {
        if (*pp == tr) {
            *pp = tr->next;
            free(tr);
            pthread_mutex_lock(&g_flow_event.lock);
            if (g_flow_event.tracked_current > 0)
                g_flow_event.tracked_current--;
            pthread_mutex_unlock(&g_flow_event.lock);
            return;
        }
        pp = &(*pp)->next;
    }
}

static void jmx_flow_event_track_update(struct jmx_flow_track *tr,
                                        const struct jmx_flow_tuple *t,
                                        int64_t now)
{
    if (!tr || !t)
        return;
    if (!tr->first_seen)
        tr->first_seen = now;
    tr->last_seen = now;
    tr->event_count++;
#define JMX_FLOW_TRACK_COUNTER(set_field, value_field) do { \
        if (t->set_field) { \
            tr->counter_seen = 1; \
            if (tr->value_field > 0 && t->value_field < tr->value_field) \
                tr->counter_reset_observed = 1; \
            else if (t->value_field >= tr->value_field) \
                tr->value_field = t->value_field; \
        } \
    } while (0)
    JMX_FLOW_TRACK_COUNTER(orig_bytes_set, orig_bytes);
    JMX_FLOW_TRACK_COUNTER(repl_bytes_set, repl_bytes);
    JMX_FLOW_TRACK_COUNTER(orig_packets_set, orig_packets);
    JMX_FLOW_TRACK_COUNTER(repl_packets_set, repl_packets);
#undef JMX_FLOW_TRACK_COUNTER
}

static int jmx_flow_event_db_exec(sqlite3 *db, const char *sql)
{
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}


static int jmx_flow_event_table_has_column(sqlite3 *db, const char *table, const char *column)
{
    sqlite3_stmt *st = NULL;
    char sql[160];
    int found = 0;

    if (!db || !table || !column)
        return 0;
    snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table);
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(st, 1);
        if (name && !strcmp((const char *)name, column)) {
            found = 1;
            break;
        }
    }
    sqlite3_finalize(st);
    return found;
}

static int jmx_flow_event_add_column_if_missing(sqlite3 *db, const char *table,
                                                const char *column,
                                                const char *definition)
{
    char sql[512];

    if (!db || !table || !column || !definition)
        return -1;
    if (jmx_flow_event_table_has_column(db, table, column))
        return 0;
    snprintf(sql, sizeof(sql), "ALTER TABLE %s ADD COLUMN %s %s", table, column, definition);
    return jmx_flow_event_db_exec(db, sql);
}

static int64_t jmx_flow_event_db_count(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *st = NULL;
    int64_t v = 0;

    if (!db || !sql)
        return 0;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return 0;
    if (sqlite3_step(st) == SQLITE_ROW)
        v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

static void jmx_flow_event_prune_if_needed(int64_t now)
{
    sqlite3_stmt *st = NULL;
    int64_t rows;
    int limit;
    int rc;
    int changed = 0;

    if (!g_flow_db || !g_flow_insert)
        return;
    pthread_mutex_lock(&g_flow_event.lock);
    if (g_flow_event.last_db_prune_at > 0 &&
        now - g_flow_event.last_db_prune_at < JMX_FLOW_EVENT_PRUNE_INTERVAL_SEC) {
        pthread_mutex_unlock(&g_flow_event.lock);
        return;
    }
    g_flow_event.last_db_prune_at = now;
    pthread_mutex_unlock(&g_flow_event.lock);

    rows = jmx_flow_event_db_count(g_flow_db,
        "SELECT COUNT(*) FROM audit_flow_event_lifecycle");
    if (rows <= JMX_FLOW_EVENT_MAX_DB_ROWS) {
        pthread_mutex_lock(&g_flow_event.lock);
        g_flow_event.db_completed_rows = rows;
        g_flow_event.last_db_prune_error[0] = '\0';
        pthread_mutex_unlock(&g_flow_event.lock);
        return;
    }
    limit = (int)(rows - JMX_FLOW_EVENT_MAX_DB_ROWS);
    if (limit > JMX_FLOW_EVENT_PRUNE_BATCH_ROWS)
        limit = JMX_FLOW_EVENT_PRUNE_BATCH_ROWS;

    rc = sqlite3_prepare_v2(g_flow_db,
        "DELETE FROM audit_flow_event_lifecycle WHERE rowid IN ("
        "SELECT rowid FROM audit_flow_event_lifecycle "
        "ORDER BY destroy_ts ASC,rowid ASC LIMIT ?1)", -1, &st, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int(st, 1, limit);
        rc = sqlite3_step(st);
        if (rc == SQLITE_DONE)
            changed = sqlite3_changes(g_flow_db);
    }
    if (st)
        sqlite3_finalize(st);

    pthread_mutex_lock(&g_flow_event.lock);
    if (rc == SQLITE_DONE) {
        g_flow_event.db_prune_runs++;
        g_flow_event.db_prune_rows += changed;
        g_flow_event.db_completed_rows = rows - changed;
        g_flow_event.last_db_prune_error[0] = '\0';
    } else {
        g_flow_event.db_prune_errors++;
        snprintf(g_flow_event.last_db_prune_error,
                 sizeof(g_flow_event.last_db_prune_error), "%s",
                 sqlite3_errmsg(g_flow_db));
    }
    pthread_mutex_unlock(&g_flow_event.lock);
}

static void jmx_flow_event_db_close(void)
{
    if (g_flow_insert) {
        sqlite3_finalize(g_flow_insert);
        g_flow_insert = NULL;
    }
    if (g_flow_db) {
        sqlite3_close(g_flow_db);
        g_flow_db = NULL;
    }
}

static int jmx_flow_event_db_ensure(void)
{
    static const char *insert_sql =
        "INSERT OR REPLACE INTO audit_flow_event_lifecycle ("
        "flow_id,flow_key,first_seen,last_seen,destroy_ts,event_count,"
        "proto,protocol,state,app_proto,service,src_ip,dst_ip,src_port,dst_port,"
        "source_ip,destination_ip,source_port,destination_port,client_ip,client_mac,remote_ip,destination_private,"
        "orig_packets,repl_packets,orig_bytes,repl_bytes,tx_bytes,rx_bytes,"
        "direction,initiator,direction_source,reply_src_ip,reply_dst_ip,reply_src_port,reply_dst_port,"
        "snat_ip,dnat_ip,snat_port,dnat_port,"
        "source,exact_lifecycle,byte_accounting_exact,byte_counter_valid,byte_counter_reason,created_at,updated_at,"
        "policy_id,policy_name,policy_type,policy_action,policy_hit,policy_source,policy_mark,route_rule_prio,route_wan_id,route_wan,"
        "destination_host,host,host_source,destination_app_id,destination_app_name) "
        /* kept adjacent to the legacy column list by adding new bindings at the end */
        "VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'destroyed',?9,?10,?11,?12,?13,?14,"
        "?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,"
        "?30,?31,?32,?33,?34,?35,?36,?37,?38,?39,'ctnetlink_destroy',?40,?41,?42,?43,?44,?45,"
        "?46,?47,?48,?49,?50,?51,?52,?53,?54,?55,"
        "?56,?57,?58,?59,?60)";
    int rc;

    if (g_flow_db && g_flow_insert)
        return 0;

    if (jmx_flow_event_ensure_dir("/opt/dreamingwrt", 0755) != 0 ||
        jmx_flow_event_ensure_dir(JMX_FLOW_EVENT_AUDIT_DIR, 0755) != 0) {
        pthread_mutex_lock(&g_flow_event.lock);
        g_flow_event.db_open_errors++;
        snprintf(g_flow_event.last_db_error, sizeof(g_flow_event.last_db_error),
                 "mkdir %s failed: %s", JMX_FLOW_EVENT_AUDIT_DIR, strerror(errno));
        g_flow_event.last_db_init_at = jmx_flow_event_now();
        pthread_mutex_unlock(&g_flow_event.lock);
        return -1;
    }

    rc = sqlite3_open_v2(JMX_FLOW_EVENT_AUDIT_DB, &g_flow_db,
                         SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                         NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_lock(&g_flow_event.lock);
        g_flow_event.db_open_errors++;
        snprintf(g_flow_event.last_db_error, sizeof(g_flow_event.last_db_error),
                 "sqlite open %s failed: %s", JMX_FLOW_EVENT_AUDIT_DB,
                 g_flow_db ? sqlite3_errmsg(g_flow_db) : "no handle");
        g_flow_event.last_db_init_at = jmx_flow_event_now();
        pthread_mutex_unlock(&g_flow_event.lock);
        jmx_flow_event_db_close();
        return -1;
    }
    sqlite3_busy_timeout(g_flow_db, JMX_FLOW_EVENT_DB_BUSY_MS);
    (void)jmx_flow_event_db_exec(g_flow_db, "PRAGMA journal_mode=WAL");
    (void)jmx_flow_event_db_exec(g_flow_db, "PRAGMA synchronous=NORMAL");
    (void)jmx_flow_event_db_exec(g_flow_db, "PRAGMA temp_store=MEMORY");
    (void)jmx_flow_event_db_exec(g_flow_db, "PRAGMA wal_autocheckpoint=1000");
    (void)jmx_flow_event_db_exec(g_flow_db, "PRAGMA journal_size_limit=16777216");

    if (jmx_flow_event_db_exec(g_flow_db,
        "CREATE TABLE IF NOT EXISTS audit_flow_event_lifecycle ("
        "flow_id TEXT PRIMARY KEY,flow_key TEXT NOT NULL DEFAULT '',"
        "first_seen INTEGER NOT NULL DEFAULT 0,last_seen INTEGER NOT NULL DEFAULT 0,destroy_ts INTEGER NOT NULL DEFAULT 0,"
        "event_count INTEGER NOT NULL DEFAULT 0,"
        "proto TEXT DEFAULT '',protocol TEXT DEFAULT '',state TEXT DEFAULT '',app_proto TEXT DEFAULT '',service TEXT DEFAULT '',"
        "src_ip TEXT DEFAULT '',dst_ip TEXT DEFAULT '',src_port INTEGER DEFAULT 0,dst_port INTEGER DEFAULT 0,"
        "source_ip TEXT DEFAULT '',destination_ip TEXT DEFAULT '',source_port INTEGER DEFAULT 0,destination_port INTEGER DEFAULT 0,"
        "direction TEXT DEFAULT '',initiator TEXT DEFAULT 'unknown',direction_source TEXT DEFAULT '',"
        "reply_src_ip TEXT DEFAULT '',reply_dst_ip TEXT DEFAULT '',reply_src_port INTEGER DEFAULT 0,reply_dst_port INTEGER DEFAULT 0,"
        "snat_ip TEXT DEFAULT '',dnat_ip TEXT DEFAULT '',snat_port INTEGER DEFAULT 0,dnat_port INTEGER DEFAULT 0,"
        "client_ip TEXT DEFAULT '',client_mac TEXT DEFAULT '',client_name TEXT DEFAULT '',remote_ip TEXT DEFAULT '',"
        "destination_private INTEGER DEFAULT 0,destination_host TEXT DEFAULT '',host TEXT DEFAULT '',host_source TEXT DEFAULT '',"
        "destination_app_id INTEGER DEFAULT 0,destination_app_name TEXT DEFAULT '',"
        "orig_packets INTEGER DEFAULT 0,repl_packets INTEGER DEFAULT 0,orig_bytes INTEGER DEFAULT 0,repl_bytes INTEGER DEFAULT 0,"
        "tx_bytes INTEGER DEFAULT 0,rx_bytes INTEGER DEFAULT 0,wan_id TEXT DEFAULT '',wan_ifname TEXT DEFAULT '',"
        "source_network_id TEXT DEFAULT '',in_network_id TEXT DEFAULT '',in_interface TEXT DEFAULT '',"
        "destination_network_id TEXT DEFAULT '',out_network_id TEXT DEFAULT '',out_interface TEXT DEFAULT '',"
        "source_country_code TEXT DEFAULT '',source_country_name TEXT DEFAULT '',source_region_code TEXT DEFAULT '',"
        "source_region_name TEXT DEFAULT '',source_city_name TEXT DEFAULT '',source_geo_precision TEXT DEFAULT '',"
        "destination_country_code TEXT DEFAULT '',destination_country_name TEXT DEFAULT '',destination_region_code TEXT DEFAULT '',"
        "destination_region_name TEXT DEFAULT '',destination_city_name TEXT DEFAULT '',destination_geo_precision TEXT DEFAULT '',"
        "risk TEXT DEFAULT 'unknown',action TEXT DEFAULT 'allow',"
        "source TEXT DEFAULT 'ctnetlink_destroy',exact_lifecycle INTEGER DEFAULT 1,byte_accounting_exact INTEGER DEFAULT 1,"
        "byte_counter_valid INTEGER DEFAULT 1,byte_counter_reason TEXT DEFAULT '',"
        "policy_id TEXT DEFAULT '',policy_name TEXT DEFAULT '',policy_type TEXT DEFAULT '',policy_action TEXT DEFAULT '',"
        "policy_hit INTEGER DEFAULT 0,policy_source TEXT DEFAULT '',policy_mark INTEGER DEFAULT 0,"
        "route_rule_prio INTEGER DEFAULT 0,route_wan_id INTEGER DEFAULT 0,route_wan TEXT DEFAULT '',"
        "created_at INTEGER DEFAULT 0,updated_at INTEGER DEFAULT 0)") != 0 ||
        jmx_flow_event_db_exec(g_flow_db,
        "CREATE INDEX IF NOT EXISTS idx_audit_flow_event_lifecycle_destroy ON audit_flow_event_lifecycle(destroy_ts)") != 0 ||
        jmx_flow_event_db_exec(g_flow_db,
        "CREATE INDEX IF NOT EXISTS idx_audit_flow_event_lifecycle_tuple ON audit_flow_event_lifecycle(proto,src_ip,dst_ip,dst_port,destroy_ts)") != 0 ||
        jmx_flow_event_db_exec(g_flow_db,
        "CREATE INDEX IF NOT EXISTS idx_audit_flow_event_lifecycle_remote ON audit_flow_event_lifecycle(remote_ip,destroy_ts)") != 0) {
        jmx_flow_event_set_db_error("schema", g_flow_db);
        jmx_flow_event_db_close();
        return -1;
    }

    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "byte_counter_valid", "INTEGER DEFAULT 1");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "byte_counter_reason", "TEXT DEFAULT ''");
    /* These five are declared in the CREATE TABLE above, but a database created
     * before they were added would not have them, and CREATE TABLE IF NOT EXISTS
     * does not backfill columns. The INSERT binds them now, so a missing column
     * would fail every write. */
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "destination_host", "TEXT DEFAULT ''");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "host", "TEXT DEFAULT ''");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "host_source", "TEXT DEFAULT ''");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "destination_app_id", "INTEGER DEFAULT 0");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "destination_app_name", "TEXT DEFAULT ''");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "policy_id", "TEXT DEFAULT ''");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "policy_name", "TEXT DEFAULT ''");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "policy_type", "TEXT DEFAULT ''");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "policy_action", "TEXT DEFAULT ''");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "policy_hit", "INTEGER DEFAULT 0");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "policy_source", "TEXT DEFAULT ''");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "policy_mark", "INTEGER DEFAULT 0");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "route_rule_prio", "INTEGER DEFAULT 0");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "route_wan_id", "INTEGER DEFAULT 0");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "route_wan", "TEXT DEFAULT ''");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "initiator", "TEXT DEFAULT 'unknown'");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "direction_source", "TEXT DEFAULT ''");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "reply_src_ip", "TEXT DEFAULT ''");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "reply_dst_ip", "TEXT DEFAULT ''");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "reply_src_port", "INTEGER DEFAULT 0");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "reply_dst_port", "INTEGER DEFAULT 0");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "snat_ip", "TEXT DEFAULT ''");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "dnat_ip", "TEXT DEFAULT ''");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "snat_port", "INTEGER DEFAULT 0");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "dnat_port", "INTEGER DEFAULT 0");
    (void)jmx_flow_event_add_column_if_missing(g_flow_db, "audit_flow_event_lifecycle",
        "client_mac", "TEXT DEFAULT ''");
    (void)jmx_flow_event_db_exec(g_flow_db,
        "UPDATE audit_flow_event_lifecycle SET "
        "byte_counter_valid=CASE WHEN COALESCE(orig_bytes,0)>0 OR COALESCE(repl_bytes,0)>0 "
        "OR COALESCE(orig_packets,0)>0 OR COALESCE(repl_packets,0)>0 THEN 1 ELSE 0 END,"
        "byte_accounting_exact=CASE WHEN COALESCE(orig_bytes,0)>0 OR COALESCE(repl_bytes,0)>0 "
        "OR COALESCE(orig_packets,0)>0 OR COALESCE(repl_packets,0)>0 THEN 1 ELSE 0 END,"
        "byte_counter_reason=CASE WHEN COALESCE(orig_bytes,0)>0 OR COALESCE(repl_bytes,0)>0 "
        "OR COALESCE(orig_packets,0)>0 OR COALESCE(repl_packets,0)>0 THEN 'ctnetlink_destroy_counters' "
        "ELSE 'ctnetlink_destroy_no_counter_attrs_or_zero_packet_flow' END "
        "WHERE COALESCE(byte_counter_reason,'')='' OR byte_counter_reason GLOB '[0-9]*' "
        "OR typeof(byte_counter_valid)!='integer' "
        "OR (COALESCE(byte_counter_valid,1)!=0 AND COALESCE(orig_bytes,0)=0 AND COALESCE(repl_bytes,0)=0 "
        "AND COALESCE(orig_packets,0)=0 AND COALESCE(repl_packets,0)=0)");

    if (sqlite3_prepare_v2(g_flow_db, insert_sql, -1, &g_flow_insert, NULL) != SQLITE_OK) {
        jmx_flow_event_set_db_error("prepare insert", g_flow_db);
        jmx_flow_event_db_close();
        return -1;
    }

    pthread_mutex_lock(&g_flow_event.lock);
    g_flow_event.db_ready = 1;
    g_flow_event.db_accounting_enabled = 1;
    g_flow_event.exact_lifecycle_supported = 1;
    g_flow_event.last_db_init_at = jmx_flow_event_now();
    g_flow_event.db_completed_rows = (uint64_t)jmx_flow_event_db_count(g_flow_db,
        "SELECT COUNT(*) FROM audit_flow_event_lifecycle");
    snprintf(g_flow_event.last_db_error, sizeof(g_flow_event.last_db_error), "%s", "");
    pthread_mutex_unlock(&g_flow_event.lock);
    return 0;
}

static void jmx_flow_event_persist_destroy(const char *key,
                                           const struct jmx_flow_tuple *t,
                                           const struct jmx_flow_track *tr,
                                           int64_t now)
{
    char flow_id[256];
    const char *direction;
    const char *initiator;
    const char *direction_source;
    int64_t first_seen;
    int64_t last_seen;
    uint32_t event_count;
    uint64_t orig_bytes, repl_bytes, orig_packets, repl_packets;
    uint64_t tx_bytes, rx_bytes;
    int byte_counter_valid;
    int exact_lifecycle;
    int byte_accounting_exact;
    const char *byte_counter_reason;
    const char *client_ip;
    const char *remote_ip;
    char client_mac[32] = "";
    int destination_private;
    char service[48];
    char policy_id[64] = "";
    char policy_name[96] = "";
    char route_wan[32] = "";
    int policy_hit;
    char dest_host[256] = "";
    char dest_app_name[128] = "";
    const char *host_source = "";
    int dest_app_id = 0;
    int idx = 1;

    if (!key || !t)
        return;

    first_seen = tr && tr->first_seen ? tr->first_seen : now;
    last_seen = tr && tr->last_seen ? tr->last_seen : now;
    if (last_seen < now)
        last_seen = now;
    event_count = tr && tr->event_count ? tr->event_count : 1;
    orig_bytes = t->orig_bytes_set ? t->orig_bytes : (tr ? tr->orig_bytes : 0);
    repl_bytes = t->repl_bytes_set ? t->repl_bytes : (tr ? tr->repl_bytes : 0);
    orig_packets = t->orig_packets_set ? t->orig_packets : (tr ? tr->orig_packets : 0);
    repl_packets = t->repl_packets_set ? t->repl_packets : (tr ? tr->repl_packets : 0);
    direction = jmx_flow_event_direction_from_tuple(t, &initiator, &direction_source);
    if (!strcmp(direction, "inbound")) {
        client_ip = (t->repl_src[0] &&
                     (jmx_flow_event_ip_private_or_local(t->repl_src) ||
                      jmx_flow_event_ip_matches_local(t->repl_src, 1))) ?
                    t->repl_src : t->dst;
        remote_ip = t->src;
        tx_bytes = repl_bytes;
        rx_bytes = orig_bytes;
    } else {
        client_ip = t->src;
        remote_ip = t->dst;
        tx_bytes = orig_bytes;
        rx_bytes = repl_bytes;
    }
    if (client_ip && client_ip[0])
        (void)jmx_flow_event_lookup_arp_mac(client_ip, client_mac, sizeof(client_mac));
    exact_lifecycle = (tr && tr->first_seen > 0 && tr->event_count > 0) ? 1 : 0;
    byte_counter_valid = (t->orig_bytes_set || t->repl_bytes_set ||
                          t->orig_packets_set || t->repl_packets_set ||
                          (tr && tr->counter_seen));
    byte_accounting_exact = byte_counter_valid && !(tr && tr->counter_reset_observed);
    if (byte_accounting_exact)
        byte_counter_reason = "ctnetlink_destroy_counters";
    else if (tr && tr->counter_reset_observed)
        byte_counter_reason = "ctnetlink_counter_reset_or_non_monotonic_observed";
    else
        byte_counter_reason = "ctnetlink_destroy_no_counter_attrs";
    destination_private = jmx_flow_event_ip_private_or_local(remote_ip);
    jmx_flow_event_service_hint(t->proto, t->dport, service, sizeof(service));
    snprintf(flow_id, sizeof(flow_id), "%s|%lld", key, (long long)first_seen);
    policy_hit = t->mark_set && t->route_rule_prio > 0 && t->route_wan_id > 0;
    if (policy_hit) {
        snprintf(policy_id, sizeof(policy_id), "rule-%u", (unsigned)t->route_rule_prio);
        snprintf(policy_name, sizeof(policy_name), "规则 %u", (unsigned)t->route_rule_prio);
        if (t->route_wan_id == 1)
            snprintf(route_wan, sizeof(route_wan), "wan");
        else
            snprintf(route_wan, sizeof(route_wan), "wan%u", (unsigned)t->route_wan_id);
    }

    jmx_flow_event_stream_write(t, first_seen, last_seen, now, event_count,
                                direction, initiator, client_ip, remote_ip,
                                service, orig_packets, repl_packets,
                                orig_bytes, repl_bytes, tx_bytes, rx_bytes);

    if (jmx_flow_event_db_ensure() != 0)
        return;

    /* Resolve the destination hostname and application before binding. Only for
     * flows leaving the LAN: a private destination has no hostname in
     * af_active_host and matching one would be wrong. */
    if (!destination_private) {
        jmx_flow_event_refresh_hosts(now);
        (void)jmx_flow_event_lookup_host(client_ip, remote_ip, t->proto, t->dport,
                                         dest_host, sizeof(dest_host),
                                         &dest_app_id, dest_app_name,
                                         sizeof(dest_app_name), &host_source);
    }

    sqlite3_reset(g_flow_insert);
    sqlite3_clear_bindings(g_flow_insert);
    sqlite3_bind_text(g_flow_insert, idx++, flow_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_flow_insert, idx++, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(g_flow_insert, idx++, first_seen);
    sqlite3_bind_int64(g_flow_insert, idx++, last_seen);
    sqlite3_bind_int64(g_flow_insert, idx++, now);
    sqlite3_bind_int(g_flow_insert, idx++, (int)event_count);
    sqlite3_bind_text(g_flow_insert, idx++, t->proto, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_flow_insert, idx++, t->proto, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_flow_insert, idx++, service, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_flow_insert, idx++, service, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_flow_insert, idx++, t->src, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_flow_insert, idx++, t->dst, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(g_flow_insert, idx++, t->sport);
    sqlite3_bind_int(g_flow_insert, idx++, t->dport);
    sqlite3_bind_text(g_flow_insert, idx++, t->src, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_flow_insert, idx++, t->dst, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(g_flow_insert, idx++, t->sport);
    sqlite3_bind_int(g_flow_insert, idx++, t->dport);
    sqlite3_bind_text(g_flow_insert, idx++, client_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_flow_insert, idx++, client_mac, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_flow_insert, idx++, remote_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(g_flow_insert, idx++, destination_private);
    sqlite3_bind_int64(g_flow_insert, idx++, (sqlite3_int64)orig_packets);
    sqlite3_bind_int64(g_flow_insert, idx++, (sqlite3_int64)repl_packets);
    sqlite3_bind_int64(g_flow_insert, idx++, (sqlite3_int64)orig_bytes);
    sqlite3_bind_int64(g_flow_insert, idx++, (sqlite3_int64)repl_bytes);
    sqlite3_bind_int64(g_flow_insert, idx++, (sqlite3_int64)tx_bytes);
    sqlite3_bind_int64(g_flow_insert, idx++, (sqlite3_int64)rx_bytes);
    sqlite3_bind_text(g_flow_insert, idx++, direction, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_flow_insert, idx++, initiator, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_flow_insert, idx++, direction_source, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_flow_insert, idx++, t->repl_src, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_flow_insert, idx++, t->repl_dst, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(g_flow_insert, idx++, t->repl_sport);
    sqlite3_bind_int(g_flow_insert, idx++, t->repl_dport);
    sqlite3_bind_text(g_flow_insert, idx++, t->snat_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_flow_insert, idx++, t->dnat_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(g_flow_insert, idx++, t->snat_port);
    sqlite3_bind_int(g_flow_insert, idx++, t->dnat_port);
    sqlite3_bind_int(g_flow_insert, idx++, exact_lifecycle);
    sqlite3_bind_int(g_flow_insert, idx++, byte_accounting_exact);
    sqlite3_bind_int(g_flow_insert, idx++, byte_counter_valid);
    sqlite3_bind_text(g_flow_insert, idx++, byte_counter_reason, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(g_flow_insert, idx++, now);
    sqlite3_bind_int64(g_flow_insert, idx++, now);
    sqlite3_bind_text(g_flow_insert, idx++, policy_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_flow_insert, idx++, policy_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_flow_insert, idx++, policy_hit ? "pbr" : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_flow_insert, idx++, policy_hit ? "route" : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(g_flow_insert, idx++, policy_hit);
    sqlite3_bind_text(g_flow_insert, idx++, policy_hit ? "ctnetlink_conntrack_mark" : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(g_flow_insert, idx++, (sqlite3_int64)t->mark);
    sqlite3_bind_int(g_flow_insert, idx++, (int)t->route_rule_prio);
    sqlite3_bind_int(g_flow_insert, idx++, (int)t->route_wan_id);
    sqlite3_bind_text(g_flow_insert, idx++, route_wan, -1, SQLITE_TRANSIENT);
    /* destination_host and host carry the same value: the table declares both and
     * consumers read either one, so leaving one empty would make the row look
     * half-populated. host_source names how the match was made, and stays empty
     * on a miss so an absent host is never mistaken for a resolved one. */
    sqlite3_bind_text(g_flow_insert, idx++, dest_host, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_flow_insert, idx++, dest_host, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_flow_insert, idx++, host_source, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(g_flow_insert, idx++, dest_app_id);
    sqlite3_bind_text(g_flow_insert, idx++, dest_app_name, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(g_flow_insert) == SQLITE_DONE) {
        pthread_mutex_lock(&g_flow_event.lock);
        g_flow_event.db_writes++;
        g_flow_event.db_completed_rows++;
        g_flow_event.last_db_write_at = now;
        g_flow_event.updated_at = now;
        pthread_mutex_unlock(&g_flow_event.lock);
        sqlite3_reset(g_flow_insert);
        jmx_flow_event_prune_if_needed(now);
    } else {
        jmx_flow_event_set_db_error("insert lifecycle", g_flow_db);
    }
}

static int jmx_flow_event_cb(enum nf_conntrack_msg_type type,
                             struct nf_conntrack *ct, void *data)
{
    struct jmx_flow_tuple tuple;
    char key[192] = "";
    struct jmx_flow_track *tr = NULL;
    int64_t now = jmx_flow_event_now();

    (void)data;
    jmx_flow_event_extract_tuple(ct, &tuple);
    jmx_flow_event_make_key(&tuple, key, sizeof(key));

    if (type == NFCT_T_NEW || type == NFCT_T_UPDATE || type == NFCT_T_DESTROY) {
        tr = jmx_flow_event_track_get(key, type != NFCT_T_DESTROY, now);
        if (tr)
            jmx_flow_event_track_update(tr, &tuple, now);
    }

    pthread_mutex_lock(&g_flow_event.lock);
    g_flow_event.events_total++;
    g_flow_event.last_event_at = now;
    g_flow_event.updated_at = now;
    snprintf(g_flow_event.last_event_type, sizeof(g_flow_event.last_event_type),
             "%s", jmx_flow_event_type_name(type));
    snprintf(g_flow_event.last_src, sizeof(g_flow_event.last_src), "%s", tuple.src);
    snprintf(g_flow_event.last_dst, sizeof(g_flow_event.last_dst), "%s", tuple.dst);
    snprintf(g_flow_event.last_proto, sizeof(g_flow_event.last_proto), "%s", tuple.proto);
    g_flow_event.last_sport = tuple.sport;
    g_flow_event.last_dport = tuple.dport;
    if (type == NFCT_T_NEW)
        g_flow_event.events_new++;
    else if (type == NFCT_T_UPDATE)
        g_flow_event.events_update++;
    else if (type == NFCT_T_DESTROY) {
        g_flow_event.events_destroy++;
        if (tuple.orig_bytes || tuple.repl_bytes) {
            g_flow_event.destroy_with_bytes++;
            g_flow_event.destroy_orig_bytes += tuple.orig_bytes;
            g_flow_event.destroy_repl_bytes += tuple.repl_bytes;
        }
    } else if (type == NFCT_T_ERROR) {
        g_flow_event.events_error++;
    }
    pthread_mutex_unlock(&g_flow_event.lock);

    if (type == NFCT_T_DESTROY) {
        jmx_flow_event_persist_destroy(key, &tuple, tr, now);
        if (tr)
            jmx_flow_event_track_remove(tr);
    }
    return NFCT_CB_CONTINUE;
}

static void *jmx_flow_event_thread_main(void *arg)
{
    (void)arg;

    pthread_mutex_lock(&g_flow_event.lock);
    g_flow_event.started_at = jmx_flow_event_now();
    g_flow_event.updated_at = g_flow_event.started_at;
    snprintf(g_flow_event.state, sizeof(g_flow_event.state), "%s", "starting");
    snprintf(g_flow_event.reason, sizeof(g_flow_event.reason), "%s", "opening_ctnetlink");
    pthread_mutex_unlock(&g_flow_event.lock);

    /* Initialize the compressed lifecycle sink early so status can report it. */
    (void)jmx_flow_event_db_ensure();

    while (1) {
        struct nfct_handle *h = NULL;
        int rc;

        pthread_mutex_lock(&g_flow_event.lock);
        if (g_flow_event.stop) {
            pthread_mutex_unlock(&g_flow_event.lock);
            break;
        }
        g_flow_event.last_open_at = jmx_flow_event_now();
        pthread_mutex_unlock(&g_flow_event.lock);

        /*
         * NEW/UPDATE/DESTROY are all lifecycle evidence.  DESTROY carries the
         * completed row; NEW/UPDATE only maintain an in-memory first/last and
         * counter monotonicity cache.  The raw UPDATE stream is not persisted.
         */
        h = nfct_open(CONNTRACK, JMX_FLOW_EVENT_GROUPS);
        if (!h) {
            int err = errno ? errno : ENODEV;
            pthread_mutex_lock(&g_flow_event.lock);
            g_flow_event.open_ok = 0;
            g_flow_event.callback_ok = 0;
            g_flow_event.active = 0;
            g_flow_event.retry_count++;
            pthread_mutex_unlock(&g_flow_event.lock);
            jmx_flow_event_set_state("unavailable", "nfct_open_failed", err);
            sleep(5);
            continue;
        }

        pthread_mutex_lock(&g_flow_event.lock);
        g_flow_event.open_ok = 1;
        g_flow_event.supported = 1;
        pthread_mutex_unlock(&g_flow_event.lock);

        {
            int fd = nfct_fd(h);
            int requested = JMX_FLOW_EVENT_RCVBUF_BYTES;
            int actual = 0;
            socklen_t actual_len = sizeof(actual);

            if (fd >= 0)
                (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                                 &requested, sizeof(requested));
            if (fd >= 0 && getsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                                     &actual, &actual_len) != 0)
                actual = 0;
            pthread_mutex_lock(&g_flow_event.lock);
            g_flow_event.receive_buffer_requested = requested;
            g_flow_event.receive_buffer_bytes = actual;
            pthread_mutex_unlock(&g_flow_event.lock);
        }

        if (nfct_callback_register(h, NFCT_T_ALL, jmx_flow_event_cb, NULL) < 0) {
            int err = errno ? errno : EINVAL;
            pthread_mutex_lock(&g_flow_event.lock);
            g_flow_event.callback_ok = 0;
            g_flow_event.active = 0;
            g_flow_event.retry_count++;
            pthread_mutex_unlock(&g_flow_event.lock);
            jmx_flow_event_set_state("unavailable", "nfct_callback_register_failed", err);
            nfct_close(h);
            sleep(5);
            continue;
        }

        pthread_mutex_lock(&g_flow_event.lock);
        g_flow_event.callback_ok = 1;
        g_flow_event.active = 1;
        snprintf(g_flow_event.state, sizeof(g_flow_event.state), "%s", "running");
        snprintf(g_flow_event.reason, sizeof(g_flow_event.reason), "%s", "ctnetlink_subscribed");
        g_flow_event.updated_at = jmx_flow_event_now();
        pthread_mutex_unlock(&g_flow_event.lock);

        while (1) {
            pthread_mutex_lock(&g_flow_event.lock);
            if (g_flow_event.stop) {
                pthread_mutex_unlock(&g_flow_event.lock);
                break;
            }
            pthread_mutex_unlock(&g_flow_event.lock);
            rc = nfct_catch(h);
            if (rc < 0) {
                int err = errno ? errno : EIO;
                pthread_mutex_lock(&g_flow_event.lock);
                g_flow_event.active = 0;
                g_flow_event.retry_count++;
                pthread_mutex_unlock(&g_flow_event.lock);
                jmx_flow_event_set_state("retrying", "nfct_catch_failed", err);
                break;
            }
        }
        nfct_callback_unregister(h);
        nfct_close(h);
        sleep(1);
    }

    jmx_flow_event_db_close();
    if (g_flow_stream) {
        fflush(g_flow_stream);
        jmx_flow_event_stream_index_write();
        fclose(g_flow_stream);
        g_flow_stream = NULL;
    }
    pthread_mutex_lock(&g_flow_event.lock);
    g_flow_event.active = 0;
    snprintf(g_flow_event.state, sizeof(g_flow_event.state), "%s", "stopped");
    snprintf(g_flow_event.reason, sizeof(g_flow_event.reason), "%s", "stop_requested");
    g_flow_event.updated_at = jmx_flow_event_now();
    pthread_mutex_unlock(&g_flow_event.lock);
    return NULL;
}

int jmx_flow_event_collector_start(void)
{
    const char *v = getenv("DREAMINGWRT_FLOW_EVENT_COLLECTOR");
    int disabled = v && (!strcmp(v, "0") || !strcasecmp(v, "false") ||
                         !strcasecmp(v, "no") || !strcasecmp(v, "off"));
    int rc;

    if (disabled) {
        jmx_flow_event_set_state("disabled", "disabled_by_env", 0);
        return 0;
    }

    pthread_mutex_lock(&g_flow_event.lock);
    if (g_flow_event.thread_started) {
        pthread_mutex_unlock(&g_flow_event.lock);
        return 0;
    }
    g_flow_event.stop = 0;
    pthread_mutex_unlock(&g_flow_event.lock);

    rc = pthread_create(&g_flow_event.thread, NULL,
                        jmx_flow_event_thread_main, NULL);
    if (rc != 0) {
        jmx_flow_event_set_state("unavailable", "pthread_create_failed", rc);
        return -1;
    }
    pthread_detach(g_flow_event.thread);
    pthread_mutex_lock(&g_flow_event.lock);
    g_flow_event.thread_started = 1;
    pthread_mutex_unlock(&g_flow_event.lock);
    return 0;
}

void jmx_flow_event_collector_stop(void)
{
    pthread_mutex_lock(&g_flow_event.lock);
    g_flow_event.stop = 1;
    pthread_mutex_unlock(&g_flow_event.lock);
}

struct json_object *jmx_flow_event_status_json(void)
{
    struct json_object *o = json_object_new_object();
    struct json_object *last = json_object_new_object();
    struct json_object *track = json_object_new_object();
    struct jmx_flow_event_state s;

    pthread_mutex_lock(&g_flow_event.lock);
    s = g_flow_event;
    pthread_mutex_unlock(&g_flow_event.lock);

    json_object_object_add(o, "supported", json_object_new_boolean(s.supported));
    json_object_object_add(o, "enabled", json_object_new_boolean(s.thread_started));
    json_object_object_add(o, "active", json_object_new_boolean(s.active));
    json_object_object_add(o, "open_ok", json_object_new_boolean(s.open_ok));
    json_object_object_add(o, "callback_ok", json_object_new_boolean(s.callback_ok));
    json_object_object_add(o, "state", json_object_new_string(s.state));
    json_object_object_add(o, "reason", json_object_new_string(s.reason));
    json_object_object_add(o, "last_error", json_object_new_string(s.last_error));
    json_object_object_add(o, "last_errno", json_object_new_int(s.last_errno));
    json_object_object_add(o, "retry_count", json_object_new_int(s.retry_count));
    json_object_object_add(o, "started_at", json_object_new_int64(s.started_at));
    json_object_object_add(o, "updated_at", json_object_new_int64(s.updated_at));
    json_object_object_add(o, "last_open_at", json_object_new_int64(s.last_open_at));
    json_object_object_add(o, "last_error_at", json_object_new_int64(s.last_error_at));
    json_object_object_add(o, "last_event_at", json_object_new_int64(s.last_event_at));
    json_object_object_add(o, "events_total", json_object_new_int64((int64_t)s.events_total));
    json_object_object_add(o, "events_new", json_object_new_int64((int64_t)s.events_new));
    json_object_object_add(o, "events_update", json_object_new_int64((int64_t)s.events_update));
    json_object_object_add(o, "events_destroy", json_object_new_int64((int64_t)s.events_destroy));
    json_object_object_add(o, "events_error", json_object_new_int64((int64_t)s.events_error));
    json_object_object_add(o, "destroy_with_bytes", json_object_new_int64((int64_t)s.destroy_with_bytes));
    json_object_object_add(o, "destroy_orig_bytes", json_object_new_int64((int64_t)s.destroy_orig_bytes));
    json_object_object_add(o, "destroy_repl_bytes", json_object_new_int64((int64_t)s.destroy_repl_bytes));
    json_object_object_add(o, "ctnetlink_source", json_object_new_string("libnetfilter_conntrack"));
    json_object_object_add(o, "kernel_module", json_object_new_string("nf_conntrack_netlink"));
    json_object_object_add(o, "conntrack_events_required", json_object_new_boolean(1));
    json_object_object_add(o, "subscribed_new", json_object_new_boolean(1));
    json_object_object_add(o, "subscribed_update", json_object_new_boolean(1));
    json_object_object_add(o, "subscribed_destroy", json_object_new_boolean(1));
    json_object_object_add(o, "receive_buffer_requested_bytes",
                           json_object_new_int(s.receive_buffer_requested));
    json_object_object_add(o, "receive_buffer_bytes",
                           json_object_new_int(s.receive_buffer_bytes));
    json_object_object_add(o, "exact_lifecycle_supported", json_object_new_boolean(s.exact_lifecycle_supported));
    json_object_object_add(o, "db_accounting_enabled", json_object_new_boolean(s.db_accounting_enabled));
    json_object_object_add(o, "db_ready", json_object_new_boolean(s.db_ready));
    json_object_object_add(o, "db_path", json_object_new_string(JMX_FLOW_EVENT_AUDIT_DB));
    json_object_object_add(o, "db_table", json_object_new_string("audit_flow_event_lifecycle"));
    json_object_object_add(o, "db_writes", json_object_new_int64((int64_t)s.db_writes));
    json_object_object_add(o, "db_write_errors", json_object_new_int64((int64_t)s.db_write_errors));
    json_object_object_add(o, "db_open_errors", json_object_new_int64((int64_t)s.db_open_errors));
    json_object_object_add(o, "completed_lifecycle_rows", json_object_new_int64((int64_t)s.db_completed_rows));
    json_object_object_add(o, "db_max_rows", json_object_new_int(JMX_FLOW_EVENT_MAX_DB_ROWS));
    json_object_object_add(o, "db_prune_interval_sec",
                           json_object_new_int(JMX_FLOW_EVENT_PRUNE_INTERVAL_SEC));
    json_object_object_add(o, "db_prune_batch_rows",
                           json_object_new_int(JMX_FLOW_EVENT_PRUNE_BATCH_ROWS));
    json_object_object_add(o, "db_prune_runs", json_object_new_int64((int64_t)s.db_prune_runs));
    json_object_object_add(o, "db_prune_rows", json_object_new_int64((int64_t)s.db_prune_rows));
    json_object_object_add(o, "db_prune_errors", json_object_new_int64((int64_t)s.db_prune_errors));
    json_object_object_add(o, "last_db_prune_at", json_object_new_int64(s.last_db_prune_at));
    json_object_object_add(o, "last_db_prune_error",
                           json_object_new_string(s.last_db_prune_error));
    json_object_object_add(o, "last_db_init_at", json_object_new_int64(s.last_db_init_at));
    json_object_object_add(o, "last_db_write_at", json_object_new_int64(s.last_db_write_at));
    json_object_object_add(o, "last_db_error", json_object_new_string(s.last_db_error));
    json_object_object_add(o, "hour_stream_enabled", json_object_new_boolean(1));
    json_object_object_add(o, "hour_stream_dir", json_object_new_string(JMX_FLOW_EVENT_STREAM_DIR));
    json_object_object_add(o, "hour_index_dir", json_object_new_string(JMX_FLOW_EVENT_INDEX_DIR));
    json_object_object_add(o, "hour_stream_retention_sec",
                           json_object_new_int(JMX_FLOW_EVENT_STREAM_RETENTION_SEC));
    json_object_object_add(o, "stream_writes", json_object_new_int64((int64_t)s.stream_writes));
    json_object_object_add(o, "stream_write_errors",
                           json_object_new_int64((int64_t)s.stream_write_errors));
    json_object_object_add(o, "stream_bytes", json_object_new_int64((int64_t)s.stream_bytes));
    json_object_object_add(o, "stream_rotations",
                           json_object_new_int64((int64_t)s.stream_rotations));
    json_object_object_add(o, "stream_hour", json_object_new_string(s.stream_hour));
    json_object_object_add(o, "last_stream_write_at",
                           json_object_new_int64(s.last_stream_write_at));
    json_object_object_add(o, "last_stream_error",
                           json_object_new_string(s.last_stream_error));
    json_object_object_add(o, "writes_raw_conntrack_events", json_object_new_boolean(0));
    json_object_object_add(o, "writes_audit_flow_event", json_object_new_boolean(0));
    json_object_object_add(o, "writes_audit_flow_event_lifecycle", json_object_new_boolean(s.db_accounting_enabled));
    json_object_object_add(o, "writes_audit_flow_lifecycle_exact", json_object_new_boolean(s.db_accounting_enabled));
    json_object_object_add(o, "byte_accounting_exact", json_object_new_boolean(s.db_accounting_enabled));
    json_object_object_add(o, "storage_strategy", json_object_new_string("hour_stream_plus_sqlite_hot_window"));
    json_object_object_add(o, "next_action", json_object_new_string(
        s.db_accounting_enabled ?
        "validate_additional_real_wan_and_forwarded_dnat_paths" :
        "fix_ctnetlink_lifecycle_db_sink"));

    json_object_object_add(track, "current", json_object_new_int64((int64_t)s.tracked_current));
    json_object_object_add(track, "max", json_object_new_int(JMX_FLOW_EVENT_MAX_TRACKED));
    json_object_object_add(track, "created", json_object_new_int64((int64_t)s.track_created));
    json_object_object_add(track, "evicted", json_object_new_int64((int64_t)s.track_evicted));
    json_object_object_add(track, "dropped", json_object_new_int64((int64_t)s.track_dropped));
    json_object_object_add(track, "ttl_sec", json_object_new_int(JMX_FLOW_EVENT_TRACK_TTL_SEC));
    json_object_object_add(o, "track_cache", track);

    json_object_object_add(last, "type", json_object_new_string(s.last_event_type));
    json_object_object_add(last, "proto", json_object_new_string(s.last_proto));
    json_object_object_add(last, "src", json_object_new_string(s.last_src));
    json_object_object_add(last, "dst", json_object_new_string(s.last_dst));
    json_object_object_add(last, "sport", json_object_new_int(s.last_sport));
    json_object_object_add(last, "dport", json_object_new_int(s.last_dport));
    json_object_object_add(o, "last_event", last);
    return o;
}

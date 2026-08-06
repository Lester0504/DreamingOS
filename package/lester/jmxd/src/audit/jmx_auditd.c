// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * jmx_auditd.c - Traffic audit daemon for DreamingWrt
 * Reads DPI data from kernel procfs, aggregates per-client per-app stats,
 * stores hourly/daily records in SQLite, exposes via ubus.
 *
 * Data sources (procfs):
 *   /proc/dreamingwrt/jmx/af_client_visit_list  - per-client per-app packet/byte counters
 *   /proc/dreamingwrt/jmx/af_client             - client list with IP/MAC/rates
 *   /proc/dreamingwrt/jmx/af_active_app         - currently active connections with appid
 *   /proc/dreamingwrt/jmx/af_conn               - connection tracking table
 *
 * Storage: SQLite database at /opt/dreamingwrt/audit/audit.db
 * Tables mirror iKuai schema:
 *   terminal_3proto_load_hour  - hourly per-client per-app traffic
 *   terminal_3proto_load_day   - daily aggregated traffic
 *
 * ubus object: jmx_audit
 *   Methods:
 *     status {}
 *     get_traffic {"period":"hour|day","mac":"xx:xx:xx:xx:xx:xx","limit":50}
 *     get_active_apps {"mac":"xx:xx:xx:xx:xx:xx"}
 *     get_clients {}
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <sqlite3.h>
#include "../jmx_storage_guard.h"
#include "../jmx_system_data_path.h"
#include <libubus.h>
#include <dirent.h>
#include <stdint.h>
#include <ctype.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#define DW_AUDIT_STATE_DIR "/opt/dreamingwrt/audit"
#define DW_AUDIT_DB_PATH DW_AUDIT_STATE_DIR "/audit.db"
#define DB_PATH         DW_AUDIT_DB_PATH
#define WORKER_STATUS_VERSION "1.0"
#define URL_STREAM_DIR  DW_AUDIT_STATE_DIR "/stream"
#define URL_INDEX_DIR   DW_AUDIT_STATE_DIR "/index"
#define URL_RETENTION_DAYS_DEFAULT 3
#define URL_AUDIT_SAMPLE_INTERVAL 60
#define URL_AUDIT_MAX_ROWS_PER_HOUR 20000
#define URL_AUDIT_MAX_TRACKED_KEYS URL_AUDIT_MAX_ROWS_PER_HOUR
#define URL_AUDIT_KEY_LEN 384
#define URL_AUDIT_DIM_KEY_LEN 256
static const char *PROC_BASE_NEW = "/proc/dreamingwrt/jmx";
static const char *PROC_BASE_OLD = "/proc/net";

static FILE* audit_fopen_af(const char *name, const char *mode) {
    char path[256];
    FILE *fp;
    snprintf(path, sizeof(path), "%s/%s", PROC_BASE_NEW, name);
    fp = fopen(path, mode);
    if (fp) return fp;
    snprintf(path, sizeof(path), "%s/%s", PROC_BASE_OLD, name);
    return fopen(path, mode);
}

#define PROC_VISIT      "af_client_visit_list"
#define PROC_CLIENT     "af_client"
#define PROC_ACTIVE_APP "af_active_app"
#define PROC_HOST       "af_active_host"
#define PROC_CONN       "af_conn"
#define PROC_NF_CONNTRACK "nf_conntrack"

#define MAX_CLIENTS     64
#define MAX_APPS        512
#define MAX_APPID_NAME  128
#define AGG_INTERVAL    60      /* seconds between aggregation runs */
#define HOUR_SECONDS    3600
#define DAY_SECONDS     86400

/* ---------- data structures ---------- */

typedef struct {
    char mac[20];
    char ip[48];
    char ipv6[48];
    uint64_t up_rate;
    uint64_t down_rate;
} client_info_t;

typedef struct {
    char mac[20];
    int appid;
    int total_num;      /* total packets */
    int drop_num;       /* dropped packets */
    int conn_count;     /* active connections */
    int is_http;
    int64_t latest_time;
    int64_t offline_time;
} visit_entry_t;

typedef struct {
    int appid;
    char mac[20];
    char src_ip[48];
    int src_port;
    char dst_ip[48];
    int dst_port;
    int proto;
    int app_proto;
    int drop;
    char host[256];
    int64_t last_update;
    char uri[256];
} active_app_t;

typedef struct {
    int id;
    char src_ip[48];
    char dst_ip[48];
    int src_port;
    int dst_port;
    int protocol;
    int app_id;
    int drop;
    int inactive;
    int total_pkts;
} conn_entry_t;

/* Host entry from af_active_host */
typedef struct {
    char host[256];
    char mac[20];
    char src_ip[48];
    int src_port;
    char dst_ip[48];
    int dst_port;
    int proto;
    int app_proto;
    int drop;
    int64_t last_update;
} host_entry_t;

typedef struct {
    uint64_t hash;
} url_audit_seen_t;

typedef struct {
    char key[URL_AUDIT_DIM_KEY_LEN];
    int count;
} url_audit_dim_count_t;

typedef struct {
    char hour_name[32];
    char stream_path[512];
    char index_path[512];
    FILE *stream_fp;
    url_audit_seen_t seen[URL_AUDIT_MAX_TRACKED_KEYS];
    int seen_count;
    url_audit_dim_count_t ip_counts[4096];
    int ip_count;
    url_audit_dim_count_t mac_counts[1024];
    int mac_count;
    url_audit_dim_count_t host_counts[8192];
    int host_count;
    url_audit_dim_count_t proto_counts[512];
    int proto_count;
    int stream_rows;
    int duplicate_dropped;
    int limit_dropped;
    int parse_dropped;
} url_audit_hour_state_t;

/* Conntrack entry with bytes */
typedef struct {
    char src_ip[48];
    char dst_ip[48];
    int src_port;
    int dst_port;
    int protocol;
    long long orig_packets;
    long long orig_bytes;
    long long reply_packets;
    long long reply_bytes;
} nf_ct_entry_t;

/* App name cache: appid -> Chinese name */
typedef struct {
    int appid;
    char name[MAX_APPID_NAME];
} app_name_t;

static app_name_t g_app_names[8192];
static int g_app_name_count = 0;
static struct stat g_app_db_stat;
static char g_app_db_path[512];
static char g_app_db_error[64];
static enum jmx_system_db_source g_app_db_source = JMX_SYSTEM_DB_SOURCE_NONE;

/* Aggregated stats: per MAC per appid */
typedef struct {
    char mac[20];
    int appid;
    int conn_count;
    int in_pkts;
    int out_pkts;
    int64_t in_bytes;
    int64_t out_bytes;
    int64_t total_bytes;
    int64_t last_update;
} app_stat_t;


static sqlite3 *g_db = NULL;

/*
 * Strict aa:bb:cc:dd:ee:ff check, mirroring webd_capture_safe_mac(). MAC values
 * arrive both from ubus callers and from procfs records whose contents are
 * ultimately declared by client devices, so they are validated before reaching
 * any SQL statement. Defined here, ahead of both call sites.
 */
static int auditd_mac_format_ok(const char *mac)
{
    int i;

    if (!mac || strlen(mac) != 17)
        return 0;
    for (i = 0; i < 17; i++) {
        if ((i + 1) % 3 == 0) {
            if (mac[i] != ':')
                return 0;
        } else if (!isxdigit((unsigned char)mac[i])) {
            return 0;
        }
    }
    return 1;
}
static struct ubus_context *g_ubus_ctx = NULL;
static volatile int g_running = 1;
static struct blob_buf g_b;
static url_audit_hour_state_t g_url_audit_state;
static uint64_t g_storage_suppressed_samples;
static int64_t g_storage_last_suppressed_at;
static struct jmx_storage_guard_state g_storage_state;
static time_t g_started_at;
static time_t g_last_agg_at;
static time_t g_last_url_sample_at;
static int g_last_agg_ok;
static int g_last_url_sample_rows;

/*
 * Aggregation counters are routine statistics, not errors. procd folds a
 * service's stderr into syslog at err level, so printing them every
 * AGG_INTERVAL made daemon.err the most common level in logread and buried
 * real faults. Keep the numbers available for field diagnosis, but off by
 * default and rate limited when enabled.
 */
#define AGG_DEBUG_MIN_INTERVAL  300     /* seconds between agg debug lines */

static int agg_debug_enabled(void)
{
    static int cached = -1;
    const char *env;

    if (cached >= 0)
        return cached;

    env = getenv("JMX_AUDITD_DEBUG");
    cached = (env && *env && strcmp(env, "0") != 0) ? 1 : 0;
    return cached;
}

static void agg_debug_stats(int nconns, int nct, int ct_with_bytes)
{
    static time_t last_emit;
    time_t now;

    if (!agg_debug_enabled())
        return;

    now = time(NULL);
    if (last_emit && now - last_emit < AGG_DEBUG_MIN_INTERVAL)
        return;
    last_emit = now;

    fprintf(stderr, "jmx_auditd: debug agg conns=%d ct=%d ct_with_bytes=%d\n",
            nconns, nct, ct_with_bytes);
}

static int audit_bulk_writes_allowed(time_t now, int count_suppressed)
{
    int allowed = jmx_storage_guard_allow(DW_AUDIT_STATE_DIR,
                                           JMX_STORAGE_WRITE_BULK,
                                           &g_storage_state);

    if (!allowed && count_suppressed) {
        g_storage_suppressed_samples++;
        g_storage_last_suppressed_at = now > 0 ? now : time(NULL);
    }
    return allowed;
}

/* ---------- app name lookup ---------- */

static void cache_app_names_to_db(void)
{
    sqlite3_stmt *st = NULL;

    if (!g_db || sqlite3_prepare_v2(g_db,
            "INSERT OR REPLACE INTO app_name_cache (appid,name) VALUES(?1,?2)",
            -1, &st, NULL) != SQLITE_OK)
        return;
    sqlite3_exec(g_db, "BEGIN;", NULL, NULL, NULL);
    for (int i = 0; i < g_app_name_count; i++) {
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        sqlite3_bind_int(st, 1, g_app_names[i].appid);
        sqlite3_bind_text(st, 2, g_app_names[i].name, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE)
            break;
    }
    sqlite3_finalize(st);
    sqlite3_exec(g_db, "COMMIT;", NULL, NULL, NULL);
}

static int load_app_names(const char *path,
                          enum jmx_system_db_source source)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct stat db_stat;
    int rc;

    if (!path || !path[0] || stat(path, &db_stat) != 0) {
        snprintf(g_app_db_error, sizeof(g_app_db_error), "%s",
                 "database_stat_failed");
        return -1;
    }
    rc = sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL);
    if (rc != SQLITE_OK) {
        snprintf(g_app_db_error, sizeof(g_app_db_error), "%s",
                 "database_open_failed");
        goto fail;
    }
    rc = sqlite3_prepare_v2(db,
        "SELECT app_id,name FROM app WHERE enabled=1 ORDER BY app_id",
        -1, &st, NULL);
    if (rc != SQLITE_OK) {
        snprintf(g_app_db_error, sizeof(g_app_db_error), "%s",
                 "app_catalog_query_failed");
        goto fail;
    }

    g_app_name_count = 0;
    memset(g_app_names, 0, sizeof(g_app_names));
    while (g_app_name_count < (int)ARRAY_SIZE(g_app_names) &&
           sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(st, 1);

        g_app_names[g_app_name_count].appid = sqlite3_column_int(st, 0);
        snprintf(g_app_names[g_app_name_count].name,
                 sizeof(g_app_names[g_app_name_count].name), "%s",
                 name ? (const char *)name : "");
        g_app_name_count++;
    }
    sqlite3_finalize(st);
    sqlite3_close(db);
    g_app_db_stat = db_stat;
    snprintf(g_app_db_path, sizeof(g_app_db_path), "%s", path);
    g_app_db_source = source;
    g_app_db_error[0] = '\0';
    return g_app_name_count;

fail:
    if (st)
        sqlite3_finalize(st);
    if (db)
        sqlite3_close(db);
    return -1;
}

static void maybe_reload_app_names(void)
{
    char path[512] = {0};
    char error[64] = {0};
    enum jmx_system_db_source source = JMX_SYSTEM_DB_SOURCE_NONE;
    struct stat st;

    if (jmx_system_db_resolve(JMX_SYSTEM_DB_SIGNATURE, path, sizeof(path),
                              &source, error, sizeof(error)) != 0) {
        g_app_db_source = JMX_SYSTEM_DB_SOURCE_NONE;
        g_app_db_path[0] = '\0';
        snprintf(g_app_db_error, sizeof(g_app_db_error), "%s",
                 error[0] ? error : "signature_db_resolve_failed");
        return;
    }
    if (stat(path, &st) != 0) {
        g_app_db_source = source;
        snprintf(g_app_db_path, sizeof(g_app_db_path), "%s", path);
        snprintf(g_app_db_error, sizeof(g_app_db_error), "%s",
                 "database_stat_failed");
        return;
    }
    if (g_app_name_count > 0 &&
        !strcmp(path, g_app_db_path) &&
        st.st_ino == g_app_db_stat.st_ino &&
        st.st_size == g_app_db_stat.st_size &&
        st.st_mtime == g_app_db_stat.st_mtime)
        return;
    if (load_app_names(path, source) >= 0) {
        if (audit_bulk_writes_allowed(time(NULL), 1))
            cache_app_names_to_db();
        fprintf(stderr, "jmx_auditd: reloaded %d app names from %s\n",
                g_app_name_count, path);
    }
}

static const char *get_app_name(int appid)
{
    for (int i = 0; i < g_app_name_count; i++) {
        if (g_app_names[i].appid == appid)
            return g_app_names[i].name;
    }
    return "";
}

/* ---------- SQLite helpers ---------- */

static void ensure_audit_state_dirs(void)
{
    mkdir("/opt", 0755);
    mkdir("/opt/dreamingwrt", 0755);
    mkdir(DW_AUDIT_STATE_DIR, 0755);
    mkdir(URL_STREAM_DIR, 0755);
    mkdir(URL_INDEX_DIR, 0755);
}

static int db_init(void)
{
    /* Ensure directory exists */
    mkdir("/etc/dreamingwrt", 0755);
    ensure_audit_state_dirs();

    int rc = sqlite3_open(DB_PATH, &g_db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "jmx_auditd: cannot open db: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    sqlite3_exec(g_db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(g_db, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);

    /* Create tables matching iKuai schema */
    const char *schema =
        "CREATE TABLE IF NOT EXISTS terminal_3proto_load_hour ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  timestamp INTEGER,"
        "  ipaddr TEXT DEFAULT '',"
        "  mac TEXT DEFAULT '',"
        "  appid_load TEXT DEFAULT '',"
        "  comment TEXT DEFAULT '',"
        "  CONSTRAINT ts_mac UNIQUE(mac, timestamp)"
        ");"
        "CREATE TABLE IF NOT EXISTS terminal_3proto_load_day ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  timestamp INTEGER,"
        "  ipaddr TEXT DEFAULT '',"
        "  mac TEXT DEFAULT '',"
        "  appid_load TEXT DEFAULT '',"
        "  comment TEXT DEFAULT '',"
        "  CONSTRAINT ts_mac UNIQUE(mac, timestamp)"
        ");"
        "CREATE TABLE IF NOT EXISTS app_name_cache ("
        "  appid INTEGER PRIMARY KEY,"
        "  name TEXT DEFAULT ''"
        ");"
        "CREATE TABLE IF NOT EXISTS audit_protocol_snapshot (id INTEGER PRIMARY KEY AUTOINCREMENT,ts INTEGER NOT NULL,window_sec INTEGER NOT NULL DEFAULT 86400,proto_id TEXT NOT NULL,name TEXT NOT NULL,category TEXT NOT NULL,subcategory TEXT DEFAULT '',connections INTEGER DEFAULT 0,up_rate INTEGER DEFAULT 0,down_rate INTEGER DEFAULT 0,bytes INTEGER DEFAULT 0,clients INTEGER DEFAULT 0,evidence TEXT DEFAULT '') ;"
        "CREATE INDEX IF NOT EXISTS idx_audit_protocol_snapshot_ts ON audit_protocol_snapshot(ts);"
        "CREATE TABLE IF NOT EXISTS audit_client_snapshot (id INTEGER PRIMARY KEY AUTOINCREMENT,ts INTEGER NOT NULL,client_id TEXT NOT NULL,name TEXT DEFAULT '',ip TEXT DEFAULT '',mac TEXT DEFAULT '',up_rate INTEGER DEFAULT 0,down_rate INTEGER DEFAULT 0,up_bytes INTEGER DEFAULT 0,down_bytes INTEGER DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS audit_traffic_day (id INTEGER PRIMARY KEY AUTOINCREMENT,day TEXT NOT NULL,mode TEXT NOT NULL,subject TEXT NOT NULL,display_name TEXT DEFAULT '',ip TEXT DEFAULT '',up_bytes INTEGER DEFAULT 0,down_bytes INTEGER DEFAULT 0,last_seen INTEGER DEFAULT 0,UNIQUE(day, mode, subject));"
        "CREATE TABLE IF NOT EXISTS audit_traffic_detail_day (id INTEGER PRIMARY KEY AUTOINCREMENT,day TEXT NOT NULL,mode TEXT NOT NULL,subject TEXT NOT NULL,app_id TEXT DEFAULT '',app_name TEXT DEFAULT '',category TEXT DEFAULT '',bytes INTEGER DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS audit_event (id INTEGER PRIMARY KEY AUTOINCREMENT,ts INTEGER NOT NULL,kind TEXT NOT NULL,client_id TEXT DEFAULT '',client_name TEXT DEFAULT '',detail TEXT DEFAULT '',proto_id TEXT DEFAULT '',app_id TEXT DEFAULT '',url TEXT DEFAULT '',ifname TEXT DEFAULT '');"
        "CREATE TABLE IF NOT EXISTS audit_url_event (id INTEGER PRIMARY KEY AUTOINCREMENT,ts INTEGER NOT NULL,client_id TEXT DEFAULT '',client_name TEXT DEFAULT '',ip TEXT DEFAULT '',mac TEXT DEFAULT '',account TEXT DEFAULT '',url TEXT DEFAULT '',host TEXT DEFAULT '',path TEXT DEFAULT '',app_id TEXT DEFAULT '',app_name TEXT DEFAULT '',category TEXT DEFAULT '',action TEXT DEFAULT 'allow',method TEXT DEFAULT '',status INTEGER DEFAULT 0,up_bytes INTEGER DEFAULT 0,down_bytes INTEGER DEFAULT 0,wan TEXT DEFAULT '',evidence TEXT DEFAULT '');"
        "CREATE INDEX IF NOT EXISTS idx_audit_event_ts_kind ON audit_event(ts,kind);"
        "CREATE INDEX IF NOT EXISTS idx_audit_event_client ON audit_event(client_id,ts);"
        "CREATE INDEX IF NOT EXISTS idx_audit_traffic_day_subject ON audit_traffic_day(mode,subject,day);"
        "CREATE INDEX IF NOT EXISTS idx_audit_traffic_detail_subject ON audit_traffic_detail_day(mode,subject,day);"
        "CREATE INDEX IF NOT EXISTS idx_audit_url_event_ts ON audit_url_event(ts);"
        "CREATE INDEX IF NOT EXISTS idx_audit_url_event_host ON audit_url_event(host,ts);"
        "CREATE INDEX IF NOT EXISTS idx_audit_url_event_client ON audit_url_event(client_id,ts);";

    char *err = NULL;
    rc = sqlite3_exec(g_db, schema, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "jmx_auditd: schema error: %s\n", err);
        sqlite3_free(err);
        return -1;
    }

    return 0;
}

/* ---------- procfs parsers ---------- */

static int parse_client_visit(visit_entry_t *out, int max)
{
    FILE *fp = audit_fopen_af(PROC_VISIT, "r");
    if (!fp) return 0;

    char line[512];
    int count = 0;
    int first = 1;

    while (fgets(line, sizeof(line), fp) && count < max) {
        if (first) { first = 0; continue; } /* skip header */

        visit_entry_t *e = &out[count];
        memset(e, 0, sizeof(*e));

        int n = sscanf(line, "%19s %d %d %d %d %d %ld %*d %ld",
                       e->mac, &e->appid, &e->total_num, &e->drop_num,
                       &e->conn_count, &e->is_http,
                       &e->latest_time, &e->offline_time);
        if (n >= 6)
            count++;
    }
    fclose(fp);
    return count;
}

static int parse_clients(client_info_t *out, int max)
{
    FILE *fp = audit_fopen_af(PROC_CLIENT, "r");
    if (!fp) return 0;

    char line[512];
    int count = 0;
    int first = 1;

    while (fgets(line, sizeof(line), fp) && count < max) {
        if (first) { first = 0; continue; }

        client_info_t *c = &out[count];
        memset(c, 0, sizeof(*c));

        int id;
        int n = sscanf(line, "%d %19s %47s %47s %lu %lu",
                       &id, c->mac, c->ip, c->ipv6,
                       &c->up_rate, &c->down_rate);
        if (n >= 3)
            count++;
    }
    fclose(fp);
    return count;
}

static int parse_active_hosts(host_entry_t *out, int max)
{
    FILE *fp = audit_fopen_af(PROC_HOST, "r");
    if (!fp) return 0;

    char line[512];
    int count = 0;
    int first = 1;

    while (fgets(line, sizeof(line), fp) && count < max) {
        if (first) { first = 0; continue; }

        host_entry_t *e = &out[count];
        memset(e, 0, sizeof(*e));

        /* Format: Host MAC SrcIP SrcPort DstIP DstPort Proto AppProto Drop LastUpdate */
        char proto_name[16] = {0};
        int n = sscanf(line, "%255s %19s %47s %d %47s %d %15s %d %d %ld",
                       e->host, e->mac, e->src_ip, &e->src_port,
                       e->dst_ip, &e->dst_port, proto_name, &e->app_proto,
                       &e->drop, &e->last_update);
        if (n >= 7) {
            if (strcmp(proto_name, "TCP") == 0)
                e->proto = 6;
            else if (strcmp(proto_name, "UDP") == 0)
                e->proto = 17;
            else
                e->proto = atoi(proto_name);
            count++;
        }
    }
    fclose(fp);
    return count;
}

static int parse_nf_conntrack(nf_ct_entry_t *out, int max)
{
    FILE *fp = audit_fopen_af(PROC_NF_CONNTRACK, "r");
    if (!fp) return 0;

    char line[1024];
    int count = 0;

    while (fgets(line, sizeof(line), fp) && count < max) {
        nf_ct_entry_t *e = &out[count];
        memset(e, 0, sizeof(*e));

        /* Line format: "ipv4 2 proto 6 state src=X dst=Y sport=Z dport=W packets=P bytes=B src=X2 dst=Y2 sport=Z2 dport=W2 packets=P2 bytes=B2 ..."
         * First src/dst/sport/dport = original direction (LAN->WAN)
         * Second src/dst/sport/dport = reply direction (WAN->LAN)
         * We parse both directions carefully. */

        char *p = strstr(line, "src=");
        if (!p) continue;
        sscanf(p + 4, "%47s", e->src_ip);

        p = strstr(p, "dst=");
        if (!p) continue;
        sscanf(p + 4, "%47s", e->dst_ip);

        p = strstr(p, "sport=");
        if (!p) continue;
        sscanf(p + 6, "%d", &e->src_port);

        p = strstr(p, "dport=");
        if (!p) continue;
        sscanf(p + 6, "%d", &e->dst_port);

        /* Protocol */
        if (strstr(line, "tcp ")) e->protocol = 6;
        else if (strstr(line, "udp ")) e->protocol = 17;

        /* First direction packets/bytes */
        p = strstr(line, "packets=");
        if (p) sscanf(p + 8, "%lld", &e->orig_packets);
        p = strstr(line, "bytes=");
        if (p) sscanf(p + 6, "%lld", &e->orig_bytes);

        /* Reply direction: skip past first block, find next packets=/bytes= */
        /* The reply block starts after "[UNREPLIED]" or "[ASSURED]" or "mark=" */
        char *reply = strstr(line, "src=");
        if (reply) {
            reply = strstr(reply + 4, "src=");
            if (reply) {
                p = strstr(reply, "packets=");
                if (p) sscanf(p + 8, "%lld", &e->reply_packets);
                p = strstr(reply, "bytes=");
                if (p) sscanf(p + 6, "%lld", &e->reply_bytes);
            }
        }

        count++;
    }
    fclose(fp);
    return count;
}

/* Find conntrack bytes for a given 5-tuple */
static void find_ct_bytes(const nf_ct_entry_t *ct_entries, int nct,
                          const char *src_ip, const char *dst_ip,
                          int src_port, int dst_port, int proto,
                          long long *in_bytes, long long *out_bytes)
{
    *in_bytes = 0;
    *out_bytes = 0;

    for (int i = 0; i < nct; i++) {
        const nf_ct_entry_t *e = &ct_entries[i];
        if (e->protocol != proto) continue;

        /* Match both directions */
        if (strcmp(e->src_ip, src_ip) == 0 && e->src_port == src_port &&
            strcmp(e->dst_ip, dst_ip) == 0 && e->dst_port == dst_port) {
            *out_bytes = e->orig_bytes;   /* LAN -> WAN = upload */
            *in_bytes = e->reply_bytes;   /* WAN -> LAN = download */
            return;
        }
        if (strcmp(e->src_ip, dst_ip) == 0 && e->src_port == dst_port &&
            strcmp(e->dst_ip, src_ip) == 0 && e->dst_port == src_port) {
            *out_bytes = e->reply_bytes;
            *in_bytes = e->orig_bytes;
            return;
        }
    }
}

/* Find IP for a given MAC from client list */
static const char *find_ip_for_mac(const client_info_t *clients, int nclients, const char *mac)
{
    for (int i = 0; i < nclients; i++) {
        if (strcmp(clients[i].mac, mac) == 0)
            return clients[i].ip;
    }
    return "";
}

/* ---------- procfs parsers (continued) ---------- */
static int parse_conn(conn_entry_t *out, int max)
{
    FILE *fp = audit_fopen_af(PROC_CONN, "r");
    if (!fp) return 0;

    char line[512];
    int count = 0;
    int first = 1;

    while (fgets(line, sizeof(line), fp) && count < max) {
        if (first) { first = 0; continue; }

        conn_entry_t *e = &out[count];
        memset(e, 0, sizeof(*e));

        int id;
        int n = sscanf(line, "%d %47s %47s %d %d %d %d %d %d %d",
                       &id, e->src_ip, e->dst_ip, &e->src_port, &e->dst_port,
                       &e->protocol, &e->app_id, &e->drop, &e->inactive, &e->total_pkts);
        if (n >= 7)
            count++;
    }
    fclose(fp);
    return count;
}


/* ---------- aggregation + DB write ---------- */

static void dw_write_audit_tables(time_t bucket, int period, const char *mac, const char *ip, const char *appid_load)
{
    sqlite3 *db = NULL; sqlite3_stmt *st = NULL;
    char day[16]; struct tm tmv; int64_t up_total = 0, down_total = 0, total = 0; int conns = 0;
    char tmp[8192]; char *save = NULL; char *tok;
    if (!mac || !mac[0]) return;
    localtime_r(&bucket, &tmv); strftime(day, sizeof(day), "%Y-%m-%d", &tmv);
    snprintf(tmp, sizeof(tmp), "%s", appid_load ? appid_load : "");
    if (sqlite3_open(DW_AUDIT_DB_PATH, &db) != SQLITE_OK) { if (db) sqlite3_close(db); return; }
    sqlite3_exec(db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);
    tok = strtok_r(tmp, ",", &save);
    while (tok) {
        int appid = 0, conn = 0, total_num = 0, drop_num = 0, latest = 0; long long in_b = 0, out_b = 0, bytes = 0;
        if (sscanf(tok, "%d|%d|%d|%d|%d|%lld|%lld|%lld", &appid, &conn, &total_num, &drop_num, &latest, &in_b, &out_b, &bytes) >= 8 && appid > 0) {
            const char *name = get_app_name(appid);
            char proto_id[64]; snprintf(proto_id, sizeof(proto_id), "%d", appid);
            conns += conn; up_total += out_b; down_total += in_b; total += bytes;
            if (sqlite3_prepare_v2(db, "INSERT INTO audit_protocol_snapshot(ts,window_sec,proto_id,name,category,subcategory,connections,up_rate,down_rate,bytes,clients,evidence) VALUES(?1,?2,?3,?4,'应用识别','',?5,0,0,?6,1,'jmx_auditd af_client_visit_list + conntrack')", -1, &st, NULL) == SQLITE_OK) {
                sqlite3_bind_int64(st,1,(sqlite3_int64)bucket); sqlite3_bind_int(st,2,period); sqlite3_bind_text(st,3,proto_id,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,4,name&&name[0]?name:proto_id,-1,SQLITE_TRANSIENT); sqlite3_bind_int(st,5,conn); sqlite3_bind_int64(st,6,(sqlite3_int64)bytes); sqlite3_step(st); sqlite3_finalize(st);
            }
            if (sqlite3_prepare_v2(db, "INSERT INTO audit_traffic_detail_day(day,mode,subject,app_id,app_name,category,bytes) VALUES(?1,'mac',?2,?3,?4,'应用识别',?5)", -1, &st, NULL) == SQLITE_OK) {
                sqlite3_bind_text(st,1,day,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,2,mac,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,3,proto_id,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,4,name&&name[0]?name:proto_id,-1,SQLITE_TRANSIENT); sqlite3_bind_int64(st,5,(sqlite3_int64)bytes); sqlite3_step(st); sqlite3_finalize(st);
            }
        }
        tok = strtok_r(NULL, ",", &save);
    }
    if (sqlite3_prepare_v2(db, "INSERT INTO audit_client_snapshot(ts,client_id,name,ip,mac,up_rate,down_rate,up_bytes,down_bytes) VALUES(?1,?2,'',?3,?2,0,0,?4,?5)", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st,1,(sqlite3_int64)bucket); sqlite3_bind_text(st,2,mac,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,3,ip?ip:"",-1,SQLITE_TRANSIENT); sqlite3_bind_int64(st,4,(sqlite3_int64)up_total); sqlite3_bind_int64(st,5,(sqlite3_int64)down_total); sqlite3_step(st); sqlite3_finalize(st);
    }
    if (sqlite3_prepare_v2(db, "INSERT INTO audit_traffic_day(day,mode,subject,display_name,ip,up_bytes,down_bytes,last_seen) VALUES(?1,'mac',?2,'',?3,?4,?5,?6) ON CONFLICT(day,mode,subject) DO UPDATE SET ip=excluded.ip,up_bytes=excluded.up_bytes,down_bytes=excluded.down_bytes,last_seen=excluded.last_seen", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st,1,day,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,2,mac,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,3,ip?ip:"",-1,SQLITE_TRANSIENT); sqlite3_bind_int64(st,4,(sqlite3_int64)up_total); sqlite3_bind_int64(st,5,(sqlite3_int64)down_total); sqlite3_bind_int64(st,6,(sqlite3_int64)bucket); sqlite3_step(st); sqlite3_finalize(st);
    }
    if (total > 0 && sqlite3_prepare_v2(db, "INSERT INTO audit_event(ts,kind,client_id,client_name,detail,proto_id,app_id,url,ifname) VALUES(?1,'protocol',?2,'','aggregated traffic sample','','','', '')", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st,1,(sqlite3_int64)bucket); sqlite3_bind_text(st,2,mac,-1,SQLITE_TRANSIENT); sqlite3_step(st); sqlite3_finalize(st);
    }
    sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL); sqlite3_close(db);
}

static int aggregate_and_store(int period)
{
    visit_entry_t visits[MAX_CLIENTS * MAX_APPS];
    client_info_t clients[MAX_CLIENTS];

    int nvisits = parse_client_visit(visits, MAX_CLIENTS * MAX_APPS);
    int nclients = parse_clients(clients, MAX_CLIENTS);

    int ok = 1;

    if (nvisits == 0)
        return 1;

    time_t now = time(NULL);
    /* Round to period boundary */
    time_t bucket;
    if (period == HOUR_SECONDS)
        bucket = (now / HOUR_SECONDS) * HOUR_SECONDS;
    else
        bucket = (now / DAY_SECONDS) * DAY_SECONDS;

    /* Build aggregated appid_load string per MAC */
    /* Group by MAC */
    char seen_macs[MAX_CLIENTS][20];
    int nmacs = 0;

    for (int i = 0; i < nvisits; i++) {
        int found = 0;
        for (int j = 0; j < nmacs; j++) {
            if (strcmp(seen_macs[j], visits[i].mac) == 0) {
                found = 1;
                break;
            }
        }
        if (!found && nmacs < MAX_CLIENTS) {
            strncpy(seen_macs[nmacs], visits[i].mac, 19);
            nmacs++;
        }
    }

    /* Also read af_conn and nf_conntrack for byte stats */
    conn_entry_t conns[2048];
    int nconns = parse_conn(conns, 2048);

    nf_ct_entry_t ct_entries[4096];
    int nct = parse_nf_conntrack(ct_entries, 4096);

    int ct_with_bytes = 0;
    for (int i = 0; i < nct; i++) {
        if (ct_entries[i].orig_bytes > 0 || ct_entries[i].reply_bytes > 0)
            ct_with_bytes++;
    }
    agg_debug_stats(nconns, nct, ct_with_bytes);

    const char *table = (period == HOUR_SECONDS) ?
        "terminal_3proto_load_hour" : "terminal_3proto_load_day";

    if (sqlite3_exec(g_db, "BEGIN IMMEDIATE;", NULL, NULL, NULL) != SQLITE_OK)
        return 0;

    for (int m = 0; m < nmacs; m++) {
        /* Collect all visit entries for this MAC */
        char appid_load[8192];
        appid_load[0] = '\0';
        int first_app = 1;

        for (int i = 0; i < nvisits; i++) {
            if (strcmp(visits[i].mac, seen_macs[m]) != 0)
                continue;
            if (visits[i].appid == 0)
                continue;

            /* Find bytes from conntrack for this appid */
            long long app_in = 0, app_out = 0;
            for (int c = 0; c < nconns; c++) {
                if (conns[c].app_id != visits[i].appid)
                    continue;
                /* Find matching client IP */
                int is_client_src = 0;
                for (int cl = 0; cl < nclients; cl++) {
                    if (strcmp(clients[cl].mac, seen_macs[m]) == 0 &&
                        strcmp(clients[cl].ip, conns[c].src_ip) == 0) {
                        is_client_src = 1;
                        break;
                    }
                }
                if (!is_client_src) continue;

                long long in_b = 0, out_b = 0;
                find_ct_bytes(ct_entries, nct,
                              conns[c].src_ip, conns[c].dst_ip,
                              conns[c].src_port, conns[c].dst_port,
                              conns[c].protocol, &in_b, &out_b);
                app_in += in_b;
                app_out += out_b;
            }

            char entry[512];
            snprintf(entry, sizeof(entry), "%s%d|%d|%d|%d|%d|%lld|%lld|%lld",
                     first_app ? "" : ",",
                     visits[i].appid,
                     visits[i].conn_count,
                     visits[i].total_num,
                     visits[i].drop_num,
                     (int)(visits[i].latest_time),
                     app_in, app_out, app_in + app_out);
            strncat(appid_load, entry, sizeof(appid_load) - strlen(appid_load) - 1);
            first_app = 0;
        }

        const char *ip = find_ip_for_mac(clients, nclients, seen_macs[m]);

        /* The MAC originates from procfs records populated from client-declared
         * addresses, so it is validated and then bound rather than interpolated.
         * The table name is one of two internal constants. */
        if (!auditd_mac_format_ok(seen_macs[m])) {
            fprintf(stderr, "jmx_auditd: skipping malformed mac\n");
            continue;
        }

        /* UPSERT: update if exists, insert otherwise */
        char sql[512];
        snprintf(sql, sizeof(sql),
            "INSERT INTO %s (timestamp, ipaddr, mac, appid_load) "
            "VALUES (?1, ?2, ?3, ?4) "
            "ON CONFLICT(mac, timestamp) DO UPDATE SET "
            "ipaddr=excluded.ipaddr, appid_load=excluded.appid_load",
            table);

        sqlite3_stmt *ins = NULL;
        if (sqlite3_prepare_v2(g_db, sql, -1, &ins, NULL) != SQLITE_OK) {
            fprintf(stderr, "jmx_auditd: sql error: %s\n", sqlite3_errmsg(g_db));
            ok = 0;
        } else {
            sqlite3_bind_int64(ins, 1, (sqlite3_int64)bucket);
            sqlite3_bind_text(ins, 2, ip ? ip : "", -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins, 3, seen_macs[m], -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins, 4, appid_load, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(ins) != SQLITE_DONE) {
                fprintf(stderr, "jmx_auditd: sql error: %s\n", sqlite3_errmsg(g_db));
                ok = 0;
            }
            sqlite3_finalize(ins);
        }
    }

    if (sqlite3_exec(g_db, ok ? "COMMIT;" : "ROLLBACK;", NULL, NULL, NULL) != SQLITE_OK)
        ok = 0;
    return ok;
}

/* ---------- ubus methods ---------- */

static int audit_proc_source_available(const char *name)
{
    FILE *fp = audit_fopen_af(name, "r");

    if (!fp)
        return 0;
    fclose(fp);
    return 1;
}

static int handle_status(struct ubus_context *ctx, struct ubus_object *obj,
                         struct ubus_request_data *req, const char *method,
                         struct blob_attr *msg)
{
    struct stat db_st = {0};
    int db_rc = g_db ? sqlite3_errcode(g_db) : SQLITE_CANTOPEN;
    int db_ready = g_db && (db_rc == SQLITE_OK || db_rc == SQLITE_ROW ||
                            db_rc == SQLITE_DONE);
    int status_ok = db_ready;
    int degraded;
    int64_t protocol_snapshots = 0;
    int64_t client_snapshots = 0;
    int64_t traffic_days = 0;
    int64_t url_events = 0;
    char last_error[128] = "";
    char app_name_source[576] = "";
    sqlite3_stmt *st = NULL;
    time_t now = time(NULL);
    void *sources;
    void *stream;
    void *dependencies;
    void *datasets;

    (void)obj;
    (void)method;
    (void)msg;
    (void)jmx_storage_guard_check(DW_AUDIT_STATE_DIR, &g_storage_state);
    if (db_ready) {
        int rc = sqlite3_prepare_v2(g_db,
            "SELECT (SELECT COUNT(*) FROM audit_protocol_snapshot),"
            "(SELECT COUNT(*) FROM audit_client_snapshot),"
            "(SELECT COUNT(*) FROM audit_traffic_day),"
            "(SELECT COUNT(*) FROM audit_url_event)", -1, &st, NULL);

        if (rc == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW) {
            protocol_snapshots = sqlite3_column_int64(st, 0);
            client_snapshots = sqlite3_column_int64(st, 1);
            traffic_days = sqlite3_column_int64(st, 2);
            url_events = sqlite3_column_int64(st, 3);
        } else {
            status_ok = 0;
            snprintf(last_error, sizeof(last_error), "%s",
                     g_db ? sqlite3_errmsg(g_db) : "audit dataset query failed");
        }
        sqlite3_finalize(st);
    } else {
        snprintf(last_error, sizeof(last_error), "%s",
                 g_db ? sqlite3_errmsg(g_db) : "audit database unavailable");
    }
    if (g_last_agg_at > 0 && !g_last_agg_ok && !last_error[0])
        snprintf(last_error, sizeof(last_error), "%s", "last aggregation failed");
    if (g_app_db_error[0] && !last_error[0])
        snprintf(last_error, sizeof(last_error), "%s", g_app_db_error);
    degraded = !status_ok || g_app_db_error[0] ||
               (g_last_agg_at > 0 && !g_last_agg_ok);
    blob_buf_init(&g_b, 0);
    blobmsg_add_u8(&g_b, "ok", status_ok);
    blobmsg_add_string(&g_b, "service", "dreamingwrt-auditd");
    blobmsg_add_string(&g_b, "version", WORKER_STATUS_VERSION);
    blobmsg_add_u32(&g_b, "schema_version", 0);
    blobmsg_add_string(&g_b, "schema_source",
                       "none:unversioned audit.db schema");
    blobmsg_add_string(&g_b, "migration_state", "not_tracked");
    blobmsg_add_string(&g_b, "state", degraded ? "degraded" : "running");
    blobmsg_add_u8(&g_b, "degraded", degraded);
    blobmsg_add_string(&g_b, "last_error", last_error);
    blobmsg_add_u64(&g_b, "updated_at", (uint64_t)(
        g_last_agg_at > g_last_url_sample_at ? g_last_agg_at : g_last_url_sample_at));
    blobmsg_add_u64(&g_b, "ts", (uint64_t)now);
    blobmsg_add_u64(&g_b, "pid", (uint64_t)getpid());
    blobmsg_add_u64(&g_b, "started_at", (uint64_t)g_started_at);
    blobmsg_add_u64(&g_b, "uptime_sec",
                    (uint64_t)(g_started_at > 0 && now >= g_started_at ? now - g_started_at : 0));
    blobmsg_add_u32(&g_b, "aggregation_interval_sec", AGG_INTERVAL);
    blobmsg_add_u64(&g_b, "last_aggregation_at", (uint64_t)g_last_agg_at);
    blobmsg_add_u8(&g_b, "last_aggregation_ok", g_last_agg_ok);
    blobmsg_add_u32(&g_b, "url_sample_interval_sec", URL_AUDIT_SAMPLE_INTERVAL);
    blobmsg_add_u64(&g_b, "last_url_sample_at", (uint64_t)g_last_url_sample_at);
    blobmsg_add_u32(&g_b, "last_url_sample_rows", (uint32_t)g_last_url_sample_rows);
    blobmsg_add_string(&g_b, "storage_pressure",
                       jmx_storage_pressure_name(g_storage_state.pressure));
    blobmsg_add_string(&g_b, "storage_reason", g_storage_state.reason);
    blobmsg_add_u64(&g_b, "storage_total_bytes", g_storage_state.total_bytes);
    blobmsg_add_u64(&g_b, "storage_available_bytes", g_storage_state.available_bytes);
    blobmsg_add_u32(&g_b, "storage_used_pct", g_storage_state.used_pct);
    blobmsg_add_u64(&g_b, "storage_checked_at", (uint64_t)g_storage_state.checked_at);
    blobmsg_add_u64(&g_b, "storage_suppressed_samples", g_storage_suppressed_samples);
    blobmsg_add_u64(&g_b, "storage_last_suppressed_at",
                    (uint64_t)g_storage_last_suppressed_at);
    blobmsg_add_string(&g_b, "db_path", DB_PATH);
    blobmsg_add_u8(&g_b, "db_ready", db_ready);
    blobmsg_add_u32(&g_b, "db_error_code", (uint32_t)db_rc);
    blobmsg_add_u64(&g_b, "db_size_bytes",
                    stat(DB_PATH, &db_st) == 0 ? (uint64_t)db_st.st_size : 0);
    blobmsg_add_u32(&g_b, "app_name_count", (uint32_t)g_app_name_count);
    if (g_app_db_path[0])
        snprintf(app_name_source, sizeof(app_name_source), "%s:app", g_app_db_path);
    blobmsg_add_string(&g_b, "app_name_source", app_name_source);
    blobmsg_add_string(&g_b, "app_name_db_source",
                       jmx_system_db_source_name(g_app_db_source));
    blobmsg_add_string(&g_b, "app_name_source_error", g_app_db_error);

    dependencies = blobmsg_open_table(&g_b, "dependencies");
    blobmsg_add_u8(&g_b, "audit_db", db_ready);
    blobmsg_add_u8(&g_b, "signature_db",
                   g_app_db_path[0] && access(g_app_db_path, R_OK) == 0 &&
                   !g_app_db_error[0]);
    blobmsg_close_table(&g_b, dependencies);

    datasets = blobmsg_open_table(&g_b, "datasets");
    blobmsg_add_u64(&g_b, "protocol_snapshots", (uint64_t)protocol_snapshots);
    blobmsg_add_u64(&g_b, "client_snapshots", (uint64_t)client_snapshots);
    blobmsg_add_u64(&g_b, "traffic_days", (uint64_t)traffic_days);
    blobmsg_add_u64(&g_b, "url_events", (uint64_t)url_events);
    blobmsg_add_u32(&g_b, "app_names", (uint32_t)g_app_name_count);
    blobmsg_close_table(&g_b, datasets);

    sources = blobmsg_open_table(&g_b, "sources");
    blobmsg_add_u8(&g_b, "client_visit", audit_proc_source_available(PROC_VISIT));
    blobmsg_add_u8(&g_b, "clients", audit_proc_source_available(PROC_CLIENT));
    blobmsg_add_u8(&g_b, "active_hosts", audit_proc_source_available(PROC_HOST));
    blobmsg_add_u8(&g_b, "connections", audit_proc_source_available(PROC_CONN));
    blobmsg_close_table(&g_b, sources);

    stream = blobmsg_open_table(&g_b, "current_hour");
    blobmsg_add_string(&g_b, "hour", g_url_audit_state.hour_name);
    blobmsg_add_string(&g_b, "stream_path", g_url_audit_state.stream_path);
    blobmsg_add_string(&g_b, "index_path", g_url_audit_state.index_path);
    blobmsg_add_u8(&g_b, "stream_open", g_url_audit_state.stream_fp != NULL);
    blobmsg_add_u32(&g_b, "stream_rows", (uint32_t)g_url_audit_state.stream_rows);
    blobmsg_add_u32(&g_b, "duplicate_dropped",
                    (uint32_t)g_url_audit_state.duplicate_dropped);
    blobmsg_add_u32(&g_b, "limit_dropped", (uint32_t)g_url_audit_state.limit_dropped);
    blobmsg_add_u32(&g_b, "parse_dropped", (uint32_t)g_url_audit_state.parse_dropped);
    blobmsg_close_table(&g_b, stream);

    ubus_send_reply(ctx, req, g_b.head);
    return UBUS_STATUS_OK;
}

enum { TRAFFIC_PERIOD, TRAFFIC_MAC, TRAFFIC_LIMIT };
static const struct blobmsg_policy traffic_policy[] = {
    [TRAFFIC_PERIOD] = { .name = "period", .type = BLOBMSG_TYPE_STRING },
    [TRAFFIC_MAC]    = { .name = "mac",    .type = BLOBMSG_TYPE_STRING },
    [TRAFFIC_LIMIT]  = { .name = "limit",  .type = BLOBMSG_TYPE_INT32 },
};

static int handle_get_active_apps(struct ubus_context *ctx, struct ubus_object *obj,
                                  struct ubus_request_data *req, const char *method,
                                  struct blob_attr *msg)
{
    visit_entry_t visits[MAX_CLIENTS * MAX_APPS];
    int nvisits = parse_client_visit(visits, MAX_CLIENTS * MAX_APPS);

    blob_buf_init(&g_b, 0);
    void *cookie = blobmsg_open_array(&g_b, "apps");
    for (int i = 0; i < nvisits; i++) {
        if (visits[i].appid == 0)
            continue;
        void *rec = blobmsg_open_table(&g_b, NULL);
        blobmsg_add_string(&g_b, "mac", visits[i].mac);
        blobmsg_add_u32(&g_b, "appid", visits[i].appid);
        blobmsg_add_string(&g_b, "name", get_app_name(visits[i].appid));
        blobmsg_add_u32(&g_b, "conn", visits[i].conn_count);
        blobmsg_add_u32(&g_b, "packets", visits[i].total_num);
        blobmsg_add_u32(&g_b, "drops", visits[i].drop_num);
        blobmsg_add_u32(&g_b, "is_http", visits[i].is_http);
        blobmsg_close_table(&g_b, rec);
    }
    blobmsg_close_array(&g_b, cookie);

    ubus_send_reply(ctx, req, g_b.head);
    return UBUS_STATUS_OK;
}

static int handle_get_clients(struct ubus_context *ctx, struct ubus_object *obj,
                              struct ubus_request_data *req, const char *method,
                              struct blob_attr *msg)
{
    client_info_t clients[MAX_CLIENTS];
    int nclients = parse_clients(clients, MAX_CLIENTS);

    blob_buf_init(&g_b, 0);
    void *cookie = blobmsg_open_array(&g_b, "clients");
    for (int i = 0; i < nclients; i++) {
        void *rec = blobmsg_open_table(&g_b, NULL);
        blobmsg_add_string(&g_b, "mac", clients[i].mac);
        blobmsg_add_string(&g_b, "ip", clients[i].ip);
        blobmsg_add_u64(&g_b, "up_rate", clients[i].up_rate);
        blobmsg_add_u64(&g_b, "down_rate", clients[i].down_rate);
        blobmsg_close_table(&g_b, rec);
    }
    blobmsg_close_array(&g_b, cookie);

    ubus_send_reply(ctx, req, g_b.head);
    return UBUS_STATUS_OK;
}


/* ---------- URL audit file management ---------- */

static void cleanup_old_url_files(void);

static void url_audit_make_hour_name(time_t now, char *out, size_t out_len)
{
    struct tm tm_now;
    localtime_r(&now, &tm_now);
    snprintf(out, out_len, "%04d%02d%02dT%02d0000",
             tm_now.tm_year + 1900, tm_now.tm_mon + 1,
             tm_now.tm_mday, tm_now.tm_hour);
}

static int url_audit_dim_inc(url_audit_dim_count_t *items, int *count, int max,
                             const char *key)
{
    if (!key || !key[0])
        return 0;
    for (int i = 0; i < *count; i++) {
        if (strcmp(items[i].key, key) == 0) {
            items[i].count++;
            return 1;
        }
    }
    if (*count >= max)
        return 0;
    snprintf(items[*count].key, sizeof(items[*count].key), "%s", key);
    items[*count].count = 1;
    (*count)++;
    return 1;
}

static int url_audit_is_hex(char c)
{
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

static int url_audit_valid_mac(const char *mac)
{
    if (!mac || strlen(mac) != 17)
        return 0;
    for (int i = 0; i < 17; i++) {
        if ((i + 1) % 3 == 0) {
            if (mac[i] != ':')
                return 0;
        } else if (!url_audit_is_hex(mac[i])) {
            return 0;
        }
    }
    return 1;
}

static int url_audit_valid_ip_token(const char *ip)
{
    if (!ip || !ip[0])
        return 0;
    size_t len = strlen(ip);
    if (len >= 3 && ip[0] == '[' && ip[len - 1] == ']')
        return 1;
    for (size_t i = 0; i < len; i++) {
        if (!(isdigit((unsigned char)ip[i]) || ip[i] == '.'))
            return 0;
    }
    return strchr(ip, '.') != NULL;
}

static int url_audit_valid_host(const char *host)
{
    if (!host || !host[0] || host[0] == '-')
        return 0;
    for (const unsigned char *p = (const unsigned char *)host; *p; p++) {
        if (*p < 0x21 || *p > 0x7e)
            return 0;
    }
    return 1;
}

static int url_audit_valid_record(const char *ip, const char *mac,
                                  const char *host, int src_port,
                                  int dst_port)
{
    return url_audit_valid_ip_token(ip) &&
           url_audit_valid_mac(mac) &&
           url_audit_valid_host(host) &&
           src_port >= 0 && src_port <= 65535 &&
           dst_port >= 0 && dst_port <= 65535;
}

static uint64_t url_audit_hash_key(const char *key)
{
    const unsigned char *p = (const unsigned char *)(key ? key : "");
    uint64_t h = 1469598103934665603ULL;
    while (*p) {
        h ^= (uint64_t)(*p++);
        h *= 1099511628211ULL;
    }
    return h ? h : 1;
}

static int url_audit_seen_has_hash(const url_audit_hour_state_t *st, uint64_t hash)
{
    if (!hash)
        return 0;
    for (int i = 0; i < st->seen_count; i++) {
        if (st->seen[i].hash == hash)
            return 1;
    }
    return 0;
}

static int url_audit_seen_add(url_audit_hour_state_t *st, const char *key)
{
    if (!key || !key[0])
        return 0;
    uint64_t hash = url_audit_hash_key(key);
    if (url_audit_seen_has_hash(st, hash))
        return 0;
    if (st->seen_count >= URL_AUDIT_MAX_TRACKED_KEYS)
        return -1;
    st->seen[st->seen_count].hash = hash;
    st->seen_count++;
    return 1;
}

static const char *url_audit_proto_label(int app_proto, int proto, int dst_port,
                                         char *buf, size_t buf_len)
{
    if (app_proto > 0) {
        snprintf(buf, buf_len, "app:%d", app_proto);
        return buf;
    }
    if (dst_port == 443) return "HTTPS";
    if (dst_port == 80) return "HTTP";
    if (dst_port == 53) return "DNS";
    if (proto == 6) return "TCP";
    if (proto == 17) return "UDP";
    snprintf(buf, buf_len, "proto:%d", proto);
    return buf;
}

static void url_audit_make_key(char *out, size_t out_len, const char *ip,
                               const char *mac, const char *host,
                               int app_proto, int proto, int dst_port)
{
    /* Keep the key iKuai-like: one URL/host event per client per hour.
     * Destination IP is intentionally excluded because IPv6 and CDN endpoint
     * churn makes snapshot-style procfs data explode without adding much audit
     * value for the web UI. */
    snprintf(out, out_len, "%.19s\t%.47s\t%.255s\t%d\t%d\t%d",
             mac ? mac : "", ip ? ip : "", host ? host : "",
             app_proto, proto, dst_port);
}

static void url_audit_index_write(const url_audit_hour_state_t *st)
{
    if (!st || !st->index_path[0])
        return;

    char tmp_path[576];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%ld", st->index_path, (long)getpid());
    FILE *fp = fopen(tmp_path, "w");
    if (!fp)
        return;

    fprintf(fp, "total\ttotal\t%d\n", st->stream_rows);
    fprintf(fp, "meta\tunique_keys\t%d\n", st->seen_count);
    fprintf(fp, "meta\tduplicate_dropped\t%d\n", st->duplicate_dropped);
    fprintf(fp, "meta\tlimit_dropped\t%d\n", st->limit_dropped);
    fprintf(fp, "meta\tparse_dropped\t%d\n", st->parse_dropped);
    fprintf(fp, "meta\tsample_interval_sec\t%d\n", URL_AUDIT_SAMPLE_INTERVAL);
    fprintf(fp, "meta\tmax_rows_per_hour\t%d\n", URL_AUDIT_MAX_ROWS_PER_HOUR);

    for (int i = 0; i < st->ip_count; i++)
        fprintf(fp, "ip\t%s\t%d\n", st->ip_counts[i].key, st->ip_counts[i].count);
    for (int i = 0; i < st->mac_count; i++)
        fprintf(fp, "mac\t%s\t%d\n", st->mac_counts[i].key, st->mac_counts[i].count);
    for (int i = 0; i < st->host_count; i++)
        fprintf(fp, "host\t%s\t%d\n", st->host_counts[i].key, st->host_counts[i].count);
    for (int i = 0; i < st->proto_count; i++)
        fprintf(fp, "proto\t%s\t%d\n", st->proto_counts[i].key, st->proto_counts[i].count);

    fclose(fp);
    rename(tmp_path, st->index_path);
}

static void url_audit_note_record(url_audit_hour_state_t *st, const char *ip,
                                  const char *mac, const char *host,
                                  int app_proto, int proto, int dst_port,
                                  int count_row)
{
    char proto_label[32];
    const char *p = url_audit_proto_label(app_proto, proto, dst_port,
                                          proto_label, sizeof(proto_label));

    if (count_row)
        st->stream_rows++;
    url_audit_dim_inc(st->ip_counts, &st->ip_count,
                      (int)ARRAY_SIZE(st->ip_counts), ip);
    url_audit_dim_inc(st->mac_counts, &st->mac_count,
                      (int)ARRAY_SIZE(st->mac_counts), mac);
    url_audit_dim_inc(st->host_counts, &st->host_count,
                      (int)ARRAY_SIZE(st->host_counts), host);
    url_audit_dim_inc(st->proto_counts, &st->proto_count,
                      (int)ARRAY_SIZE(st->proto_counts), p);
}

static void url_audit_rebuild_from_stream(url_audit_hour_state_t *st)
{
    FILE *fp = fopen(st->stream_path, "r");
    if (!fp)
        return;

    char compact_path[576];
    snprintf(compact_path, sizeof(compact_path), "%s.compact.%ld", st->stream_path, (long)getpid());
    FILE *compact = fopen(compact_path, "w");
    if (!compact)
        st->parse_dropped++;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char ip[48] = {0}, mac[20] = {0}, host[256] = {0}, dst_ip[48] = {0};
        long ts = 0;
        int appid = 0, proto = 0, dst_port = 0;
        if (sscanf(line, "%47s\t%19s\t%ld\t%255s\t%d\t%d\t%47s\t%d",
                   ip, mac, &ts, host, &appid, &proto, dst_ip, &dst_port) < 8) {
            st->parse_dropped++;
            continue;
        }
        if (!url_audit_valid_record(ip, mac, host, 0, dst_port)) {
            st->parse_dropped++;
            continue;
        }
        char key[URL_AUDIT_KEY_LEN];
        url_audit_make_key(key, sizeof(key), ip, mac, host, appid, proto, dst_port);
        int added = url_audit_seen_add(st, key);
        if (added < 0) {
            st->limit_dropped++;
            continue;
        }
        if (added == 0) {
            st->duplicate_dropped++;
            continue;
        }
        url_audit_note_record(st, ip, mac, host, appid, proto, dst_port, 1);
        if (compact)
            fputs(line, compact);
    }
    fclose(fp);

    if (compact) {
        fclose(compact);
        if (st->duplicate_dropped > 0 || st->limit_dropped > 0 || st->parse_dropped > 0) {
            char backup_path[576];
            snprintf(backup_path, sizeof(backup_path), "%s.precompact.%ld", st->stream_path, (long)getpid());
            if (rename(st->stream_path, backup_path) == 0) {
                if (rename(compact_path, st->stream_path) != 0) {
                    rename(backup_path, st->stream_path);
                    unlink(compact_path);
                } else {
                    unlink(backup_path);
                }
            } else {
                unlink(compact_path);
            }
        } else {
            unlink(compact_path);
        }
    }
}

static void url_audit_hour_close(url_audit_hour_state_t *st)
{
    if (!st)
        return;
    if (st->stream_fp) {
        fflush(st->stream_fp);
        fclose(st->stream_fp);
        st->stream_fp = NULL;
    }
    if (st->hour_name[0])
        url_audit_index_write(st);
}

static int url_audit_hour_open(url_audit_hour_state_t *st, time_t now)
{
    char hour_name[32];
    url_audit_make_hour_name(now, hour_name, sizeof(hour_name));
    if (strcmp(st->hour_name, hour_name) == 0 && st->stream_fp)
        return 0;

    url_audit_hour_close(st);
    memset(st, 0, sizeof(*st));
    snprintf(st->hour_name, sizeof(st->hour_name), "%s", hour_name);
    snprintf(st->stream_path, sizeof(st->stream_path), "%s/%s",
             URL_STREAM_DIR, st->hour_name);
    snprintf(st->index_path, sizeof(st->index_path), "%s/%s",
             URL_INDEX_DIR, st->hour_name);

    url_audit_rebuild_from_stream(st);
    st->stream_fp = fopen(st->stream_path, "a");
    if (!st->stream_fp)
        return -1;

    cleanup_old_url_files();
    url_audit_index_write(st);
    return 0;
}

static void url_audit_compact_existing_files(void)
{
    DIR *dir = opendir(URL_STREAM_DIR);
    if (!dir)
        return;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] != '2')
            continue;
        if (strlen(ent->d_name) >= sizeof(((url_audit_hour_state_t *)0)->hour_name))
            continue;

        url_audit_hour_state_t *st = calloc(1, sizeof(*st));
        if (!st)
            break;

        strncpy(st->hour_name, ent->d_name, sizeof(st->hour_name) - 1);
        st->hour_name[sizeof(st->hour_name) - 1] = '\0';
        snprintf(st->stream_path, sizeof(st->stream_path), "%s/%s",
                 URL_STREAM_DIR, st->hour_name);
        snprintf(st->index_path, sizeof(st->index_path), "%s/%s",
                 URL_INDEX_DIR, st->hour_name);

        url_audit_rebuild_from_stream(st);
        url_audit_index_write(st);
        free(st);
    }
    closedir(dir);
}

static int url_audit_write_host(url_audit_hour_state_t *st,
                                const host_entry_t *host, time_t now)
{
    if (!st || !st->stream_fp || !host)
        return 0;
    if (!url_audit_valid_record(host->src_ip, host->mac, host->host,
                                host->src_port, host->dst_port)) {
        st->parse_dropped++;
        return 0;
    }

    char key[URL_AUDIT_KEY_LEN];
    url_audit_make_key(key, sizeof(key), host->src_ip, host->mac, host->host,
                       host->app_proto, host->proto, host->dst_port);

    int added = url_audit_seen_add(st, key);
    if (added == 0) {
        st->duplicate_dropped++;
        return 0;
    }
    if (added < 0 || st->stream_rows >= URL_AUDIT_MAX_ROWS_PER_HOUR) {
        st->limit_dropped++;
        return 0;
    }

    fprintf(st->stream_fp, "%s\t%s\t%ld\t%s\t%d\t%d\t%s\t%d\n",
            host->src_ip, host->mac, (long)now, host->host,
            host->app_proto, host->proto, host->dst_ip, host->dst_port);
    url_audit_note_record(st, host->src_ip, host->mac, host->host,
                          host->app_proto, host->proto, host->dst_port, 1);
    return 1;
}

/* Read retention days from the shared config.db authority. */
static int get_url_retention_days(void)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int days = URL_RETENTION_DAYS_DEFAULT;

    if (sqlite3_open_v2("/etc/dreamingwrt/config.db", &db,
                        SQLITE_OPEN_READONLY, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(db,
            "SELECT record_time FROM legacy_jmx_settings WHERE id=1",
            -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW) {
        int configured = sqlite3_column_int(st, 0);

        if (configured > 0)
            days = configured;
    }
    sqlite3_finalize(st);
    if (db)
        sqlite3_close(db);
    return days;
}

static void cleanup_old_url_files(void)
{
    int retention = get_url_retention_days();
    time_t cutoff = time(NULL) - (retention * 86400);

    struct tm tm_cutoff;
    localtime_r(&cutoff, &tm_cutoff);
    char cutoff_str[32];
    snprintf(cutoff_str, sizeof(cutoff_str), "%04d%02d%02dT%02d0000",
             tm_cutoff.tm_year + 1900, tm_cutoff.tm_mon + 1,
             tm_cutoff.tm_mday, tm_cutoff.tm_hour);

    const char *dirs[] = { URL_STREAM_DIR, URL_INDEX_DIR, NULL };
    for (int d = 0; dirs[d]; d++) {
        DIR *dir = opendir(dirs[d]);
        if (!dir) continue;
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_name[0] != '2') continue;
            if (strcmp(ent->d_name, cutoff_str) < 0) {
                char path[512];
                snprintf(path, sizeof(path), "%s/%s", dirs[d], ent->d_name);
                unlink(path);
            }
        }
        closedir(dir);
    }
}

static int handle_get_url_audit(struct ubus_context *ctx, struct ubus_object *obj,
                               struct ubus_request_data *req, const char *method,
                               struct blob_attr *msg)
{
    (void)obj;
    (void)method;
    (void)msg;

    blob_buf_init(&g_b, 0);
    void *cookie = blobmsg_open_array(&g_b, "urls");

    /* Read latest stream file (most recent hour) */
    DIR *dir = opendir(URL_STREAM_DIR);
    if (dir) {
        struct dirent *ent;
        char latest[32] = {0};
        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_name[0] == '2' && strcmp(ent->d_name, latest) > 0)
                strncpy(latest, ent->d_name, sizeof(latest) - 1);
        }
        closedir(dir);

        if (latest[0]) {
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", URL_STREAM_DIR, latest);
            FILE *fp = fopen(path, "r");
            if (fp) {
                char line[1024];
                int count = 0;
                while (fgets(line, sizeof(line), fp) && count < 200) {
                    /* TSV: ip mac timestamp host appid proto dst_ip dst_port */
                    char ip[48] = {0}, mac[20] = {0}, host[256] = {0};
                    char dst_ip[48] = {0};
                    long ts = 0;
                    int appid = 0, proto = 0, dst_port = 0;
                    if (sscanf(line, "%47s\t%19s\t%ld\t%255s\t%d\t%d\t%47s\t%d",
                               ip, mac, &ts, host, &appid, &proto,
                               dst_ip, &dst_port) >= 4) {
                        void *rec = blobmsg_open_table(&g_b, NULL);
                        blobmsg_add_u32(&g_b, "timestamp", (uint32_t)ts);
                        blobmsg_add_string(&g_b, "mac", mac);
                        blobmsg_add_string(&g_b, "ip", ip);
                        blobmsg_add_u32(&g_b, "appid", appid);
                        blobmsg_add_string(&g_b, "app_name", get_app_name(appid));
                        blobmsg_add_string(&g_b, "host", host);
                        blobmsg_close_table(&g_b, rec);
                        count++;
                    }
                }
                fclose(fp);
            }
        }
    }

    blobmsg_close_array(&g_b, cookie);
    ubus_send_reply(ctx, req, g_b.head);
    return UBUS_STATUS_OK;
}

static int handle_get_traffic(struct ubus_context *ctx, struct ubus_object *obj,
                              struct ubus_request_data *req, const char *method,
                              struct blob_attr *msg)
{
    struct blob_attr *tb[3];
    blobmsg_parse(traffic_policy, 3, tb, blob_data(msg), blob_len(msg));

    const char *period = "hour";
    const char *mac_filter = NULL;
    int limit = 50;

    if (tb[TRAFFIC_PERIOD])
        period = blobmsg_get_string(tb[TRAFFIC_PERIOD]);
    if (tb[TRAFFIC_MAC])
        mac_filter = blobmsg_get_string(tb[TRAFFIC_MAC]);
    if (tb[TRAFFIC_LIMIT])
        limit = blobmsg_get_u32(tb[TRAFFIC_LIMIT]);

    const char *table = (strcmp(period, "day") == 0) ?
        "terminal_3proto_load_day" : "terminal_3proto_load_hour";

    /* A malformed mac filter is rejected outright rather than being widened to
     * "no filter", which would hand back the whole table to a caller that asked
     * for one client. */
    if (mac_filter && !auditd_mac_format_ok(mac_filter))
        return UBUS_STATUS_INVALID_ARGUMENT;
    if (limit < 1)
        limit = 1;
    else if (limit > 5000)
        limit = 5000;

    /* Table name is one of two internal constants; the caller-supplied mac and
     * limit are bound, never interpolated. */
    char sql[512];
    snprintf(sql, sizeof(sql),
        "SELECT timestamp, ipaddr, mac, appid_load FROM %s %s"
        "ORDER BY timestamp DESC LIMIT ?2",
        table, mac_filter ? "WHERE mac=?1 " : "");

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        if (mac_filter)
            sqlite3_bind_text(stmt, 1, mac_filter, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, limit);
    }

    blob_buf_init(&g_b, 0);
    void *cookie = blobmsg_open_array(&g_b, "records");
    if (rc == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            void *rec = blobmsg_open_table(&g_b, NULL);
            /* The columns default to '' but are not NOT NULL, so a NULL would
             * reach blobmsg_add_string() and strlen(NULL). */
            const char *c_ip = (const char *)sqlite3_column_text(stmt, 1);
            const char *c_mac = (const char *)sqlite3_column_text(stmt, 2);
            const char *c_load = (const char *)sqlite3_column_text(stmt, 3);

            blobmsg_add_u32(&g_b, "timestamp", sqlite3_column_int(stmt, 0));
            blobmsg_add_string(&g_b, "ipaddr", c_ip ? c_ip : "");
            blobmsg_add_string(&g_b, "mac", c_mac ? c_mac : "");
            blobmsg_add_string(&g_b, "appid_load", c_load ? c_load : "");
            blobmsg_close_table(&g_b, rec);
        }
    }
    sqlite3_finalize(stmt);

    blobmsg_close_array(&g_b, cookie);
    ubus_send_reply(ctx, req, g_b.head);
    return UBUS_STATUS_OK;
}

static const struct ubus_method jmx_audit_methods[] = {
    UBUS_METHOD_NOARG("status", handle_status),
    UBUS_METHOD("get_traffic",    handle_get_traffic,    traffic_policy),
    UBUS_METHOD_NOARG("get_active_apps", handle_get_active_apps),
    UBUS_METHOD_NOARG("get_clients",     handle_get_clients),
    UBUS_METHOD_NOARG("get_url_audit",   handle_get_url_audit),
};

static struct ubus_object_type jmx_audit_type =
    UBUS_OBJECT_TYPE("jmx_audit", jmx_audit_methods);

static struct ubus_object jmx_audit_obj = {
    .name = "jmx_audit",
    .type = &jmx_audit_type,
    .methods = jmx_audit_methods,
    .n_methods = ARRAY_SIZE(jmx_audit_methods),
};

/* ---------- main ---------- */

static void sig_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);
    g_started_at = time(NULL);

    /* Load app name cache */
    maybe_reload_app_names();
    fprintf(stderr, "jmx_auditd: loaded %d app names\n", g_app_name_count);

    /* Init DB */
    if (db_init() != 0)
        return 1;

    /* Ensure audit dirs exist */
    ensure_audit_state_dirs();
    if (audit_bulk_writes_allowed(time(NULL), 1)) {
        url_audit_compact_existing_files();
        cache_app_names_to_db();
    }

    /* Init ubus */
    g_ubus_ctx = ubus_connect(NULL);
    if (!g_ubus_ctx) {
        fprintf(stderr, "jmx_auditd: ubus connect failed\n");
        return 1;
    }

    if (ubus_add_object(g_ubus_ctx, &jmx_audit_obj)) {
        fprintf(stderr, "jmx_auditd: ubus add object failed\n");
        return 1;
    }

    fprintf(stderr, "jmx_auditd: started, polling every %ds\n", AGG_INTERVAL);

    time_t last_day = 0;

    while (g_running) {
        /* Handle ubus events */
        ubus_handle_event(g_ubus_ctx);

        time_t now = time(NULL);
        maybe_reload_app_names();

        /* Aggregate every AGG_INTERVAL seconds */
        static time_t last_agg = 0;
        if (now - last_agg >= AGG_INTERVAL &&
            audit_bulk_writes_allowed(now, 0)) {
            g_last_agg_ok = aggregate_and_store(HOUR_SECONDS);
            last_agg = now;
            g_last_agg_at = now;
        } else if (now - last_agg >= AGG_INTERVAL) {
            (void)audit_bulk_writes_allowed(now, 1);
            last_agg = now;
        }

        /* URL audit: sample procfs once per minute, then keep one compact
         * client/host/proto row per hour. The old 500ms full-snapshot append
         * made DreamingWrt hourly files tens of MB larger than iKuai's audit
         * stream for the same traffic shape. */
        static time_t last_url_sample = 0;
        if (now - last_url_sample >= URL_AUDIT_SAMPLE_INTERVAL &&
            audit_bulk_writes_allowed(now, 0)) {
            if (url_audit_hour_open(&g_url_audit_state, now) == 0) {
                host_entry_t hosts[512];
                int wrote = 0;
                int nhosts = parse_active_hosts(hosts, 512);
                for (int i = 0; i < nhosts; i++)
                    wrote += url_audit_write_host(&g_url_audit_state, &hosts[i], now);
                if (wrote > 0) {
                    fflush(g_url_audit_state.stream_fp);
                    url_audit_index_write(&g_url_audit_state);
                }
                g_last_url_sample_rows = wrote;
            }
            last_url_sample = now;
            g_last_url_sample_at = now;
        } else if (now - last_url_sample >= URL_AUDIT_SAMPLE_INTERVAL) {
            (void)audit_bulk_writes_allowed(now, 1);
            last_url_sample = now;
        }

        /* Daily aggregation at midnight */
        time_t today_start = (now / DAY_SECONDS) * DAY_SECONDS;
        if (last_day != today_start && last_day != 0 &&
            audit_bulk_writes_allowed(now, 1)) {
            (void)aggregate_and_store(DAY_SECONDS);
        }
        last_day = today_start;

        usleep(500000); /* 500ms */
    }

    url_audit_hour_close(&g_url_audit_state);
    sqlite3_close(g_db);
    ubus_free(g_ubus_ctx);
    fprintf(stderr, "jmx_auditd: stopped\n");
    return 0;
}

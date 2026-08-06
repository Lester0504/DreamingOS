// SPDX-License-Identifier: GPL-2.0-or-later
/* DreamingWrt SQLite control-plane database, phase 1: client identity. */
#include "jmx_db.h"
#include "jmx_huginn.h"
#include "jmx_dhcp_sniff.h"
#include "jmx_network.h"
#include "jmx_uci.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <libubox/list.h>
#include <openssl/evp.h>

#include "jmx.h"
#include "jmx_user.h"
#include "jmx_hosttype.h"
#include "jmx_netconfig_db.h"
#include "jmx_signature_db.h"
#include "jmx_storage_guard.h"
#include "jmx_system_data_path.h"

extern struct list_head client_list;

static sqlite3 *g_db = NULL;
static const char *g_db_path = JMX_DB_PATH_DEFAULT;
static int g_fingerprint_catalog_changed = 0;

#define FINGERPRINT_CATALOG_VERSION 4
#define FINGERPRINT_DB_APPLICATION_ID 1146570320
#define FINGERPRINT_DB_SCHEMA_VERSION 1
#define JMX_DB_SCHEMA_VERSION 7

static int db_signature_db_path(char *path, size_t path_len)
{
    enum jmx_system_db_source source;
    char error[64];

    if (jmx_system_db_resolve(JMX_SYSTEM_DB_SIGNATURE, path, path_len,
                              &source, error, sizeof(error)) == 0)
        return 0;
    LOG_WARN("signature DB resolve failed: %s\n", error);
    return -1;
}

static int db_exec(const char *sql)
{
    char *err = NULL;
    int rc;
    if (!g_db) return -1;
    rc = sqlite3_exec(g_db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        LOG_ERROR("sqlite exec failed rc=%d err=%s sql=%s\n", rc, err ? err : "", sql ? sql : "");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static int db_table_has_column(const char *table, const char *column)
{
    sqlite3_stmt *st = NULL;
    char sql[256];
    int found = 0;

    if (!g_db || !table || !table[0] || !column || !column[0])
        return 0;
    snprintf(sql, sizeof(sql), "PRAGMA table_info(%s);", table);
    if (sqlite3_prepare_v2(g_db, sql, -1, &st, NULL) != SQLITE_OK)
        return 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(st, 1);
        if (name && !strcmp(name, column)) {
            found = 1;
            break;
        }
    }
    sqlite3_finalize(st);
    return found;
}

static int db_table_exists(const char *table)
{
    sqlite3_stmt *st = NULL;
    int found = 0;

    if (!g_db || !table || !table[0])
        return 0;
    if (sqlite3_prepare_v2(g_db,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, table, -1, SQLITE_TRANSIENT);
    found = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return found;
}

static int db_schema_version(void)
{
    sqlite3_stmt *st = NULL;
    int version = 0;

    if (!db_table_exists("db_meta"))
        return 0;
    if (sqlite3_prepare_v2(g_db,
            "SELECT value FROM db_meta WHERE key='schema_version' LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
        return 0;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *value = (const char *)sqlite3_column_text(st, 0);
        if (value)
            version = atoi(value);
    }
    sqlite3_finalize(st);
    return version > 0 ? version : 0;
}

static int db_set_schema_version(int version)
{
    sqlite3_stmt *st = NULL;
    char value[16];
    int rc;

    snprintf(value, sizeof(value), "%d", version);
    if (sqlite3_prepare_v2(g_db,
            "INSERT INTO db_meta(key,value,updated_at) VALUES('schema_version',?1,?2) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, value, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)time(NULL));
    rc = sqlite3_step(st) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(st);
    return rc;
}

static int db_mkdirs(void)
{
    mkdir("/etc/dreamingwrt", 0755);
    mkdir("/etc/dreamingwrt/assets", 0755);
    mkdir("/etc/dreamingwrt/assets/fingerprint", 0755);
    return 0;
}

static int db_begin(void) { return db_exec("BEGIN IMMEDIATE TRANSACTION;"); }
static int db_commit(void) { return db_exec("COMMIT;"); }
static void db_rollback(void) { db_exec("ROLLBACK;"); }
static int64_t now_s(void) { return (int64_t)time(NULL); }

/*
 * Opt-in write batching for callers that issue many small related writes in one
 * pass.
 *
 * The WAN refresh in dw_build_wans_internal() performs at least five separate
 * autocommit writes per WAN (interface state, daily usage counter, lifetime
 * usage, health sample, session). Each autocommit statement is its own durable
 * transaction, so on a 45 MB database with a multi-megabyte WAL the pass is
 * dominated by commit latency rather than by the queries themselves; measured
 * on 30.1 it reached 5.5 s inside the metrics tick, against a 200 ms budget.
 * Grouping the pass into one transaction turns N commits into one.
 *
 * Kept as a depth counter so it is safe if a caller is already inside a
 * transaction, or if two batched regions nest: only the outermost pair issues
 * BEGIN/COMMIT. Callers must pair begin/end on every exit path.
 */
static int g_db_batch_depth;

int jmx_db_write_batch_begin(void)
{
    if (g_db_batch_depth > 0) {
        g_db_batch_depth++;
        return 0;
    }
    if (db_begin() != 0)
        return -1;
    g_db_batch_depth = 1;
    return 0;
}

int jmx_db_write_batch_end(int commit)
{
    int rc = 0;

    if (g_db_batch_depth <= 0)
        return -1;
    if (--g_db_batch_depth > 0)
        return 0;
    if (commit) {
        rc = db_commit();
        if (rc != 0)
            db_rollback();
    } else {
        db_rollback();
    }
    return rc;
}

static int64_t db_read_system_uptime_sec(void)
{
    FILE *fp;
    double up = 0;

    fp = fopen("/proc/uptime", "r");
    if (!fp)
        return 0;
    if (fscanf(fp, "%lf", &up) != 1)
        up = 0;
    fclose(fp);
    return up > 0 ? (int64_t)up : 0;
}

static int db_runtime_online_session(client_node_t *runtime, int online, int64_t now,
                                     int64_t *since_out, int64_t *duration_out,
                                     char *source, size_t source_len)
{
    int64_t since;
    int64_t uptime;
    int64_t boot_ts = 0;
    const char *src = "client_runtime";

    if (since_out)
        *since_out = 0;
    if (duration_out)
        *duration_out = 0;
    if (source && source_len)
        source[0] = '\0';
    if (!runtime || !online || !runtime->online || runtime->online_time == 0 ||
        now <= 0 || (int64_t)runtime->online_time > now)
        return 0;

    since = (int64_t)runtime->online_time;
    uptime = db_read_system_uptime_sec();
    if (uptime > 0)
        boot_ts = now - uptime;
    if (boot_ts > 0 && since < boot_ts) {
        since = boot_ts;
        src = "client_runtime_boot_clamped";
    } else if (runtime->online_source[0]) {
        src = runtime->online_source;
    }

    if (since_out)
        *since_out = since;
    if (duration_out)
        *duration_out = now >= since ? now - since : 0;
    if (source && source_len)
        snprintf(source, source_len, "%s", src);
    return 1;
}

static void db_safe_text_copy(char *out, size_t out_len, const char *in)
{
    size_t oi = 0;
    const unsigned char *p = (const unsigned char *)in;
    size_t ii = 0;
    size_t in_len;

    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (!p)
        return;
    in_len = strlen(in);
    while (ii < in_len && oi + 1 < out_len) {
        unsigned char c = p[ii++];

        if (c >= 0x20 && c < 0x7f) {
            out[oi++] = (char)c;
        } else if (c == '\n' || c == '\r' || c == '\t') {
            out[oi++] = ' ';
        } else if (c >= 0xc2 && c <= 0xdf && ii < in_len &&
                   (p[ii] & 0xc0) == 0x80) {
            if (oi + 2 >= out_len) break;
            out[oi++] = (char)c;
            out[oi++] = (char)p[ii++];
        } else if (ii + 1 < in_len &&
                   ((c == 0xe0 && p[ii] >= 0xa0 && p[ii] <= 0xbf) ||
                    (c >= 0xe1 && c <= 0xec && (p[ii] & 0xc0) == 0x80) ||
                    (c == 0xed && p[ii] >= 0x80 && p[ii] <= 0x9f) ||
                    (c >= 0xee && c <= 0xef && (p[ii] & 0xc0) == 0x80)) &&
                   (p[ii + 1] & 0xc0) == 0x80) {
            if (oi + 3 >= out_len) break;
            out[oi++] = (char)c;
            out[oi++] = (char)p[ii++];
            out[oi++] = (char)p[ii++];
        } else if (ii + 2 < in_len &&
                   ((c == 0xf0 && p[ii] >= 0x90 && p[ii] <= 0xbf) ||
                    (c >= 0xf1 && c <= 0xf3 && (p[ii] & 0xc0) == 0x80) ||
                    (c == 0xf4 && p[ii] >= 0x80 && p[ii] <= 0x8f)) &&
                   (p[ii + 1] & 0xc0) == 0x80 &&
                   (p[ii + 2] & 0xc0) == 0x80) {
            if (oi + 4 >= out_len) break;
            out[oi++] = (char)c;
            out[oi++] = (char)p[ii++];
            out[oi++] = (char)p[ii++];
            out[oi++] = (char)p[ii++];
        } else if (oi + 4 < out_len) {
            int n = snprintf(out + oi, out_len - oi, "\\x%02x", c);
            if (n <= 0 || (size_t)n >= out_len - oi)
                break;
            oi += (size_t)n;
        } else {
            break;
        }
    }
    out[oi] = '\0';
}

static const char *db_sqlite_safe_text(sqlite3_stmt *st, int col, char *buf, size_t buf_len)
{
    const char *s = (const char *)sqlite3_column_text(st, col);

    db_safe_text_copy(buf, buf_len, s ? s : "");
    return buf;
}

static int normalize_mac(const char *in, char *out, size_t out_len)
{
    char hex[13];
    int n = 0;
    size_t i;
    if (!in || !out || out_len < 18) return -1;
    for (i = 0; in[i] && n < 12; i++) {
        if (isxdigit((unsigned char)in[i]))
            hex[n++] = (char)tolower((unsigned char)in[i]);
        else if (in[i] == ':' || in[i] == '-' || in[i] == '.' || isspace((unsigned char)in[i]))
            continue;
        else
            return -1;
    }
    if (n != 12) return -1;
    hex[12] = '\0';
    snprintf(out, out_len, "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",
             hex[0], hex[1], hex[2], hex[3], hex[4], hex[5],
             hex[6], hex[7], hex[8], hex[9], hex[10], hex[11]);
    return 0;
}

static const char *json_s(struct json_object *o, const char *k, const char *def)
{
    struct json_object *v = NULL;
    if (!o || !json_object_object_get_ex(o, k, &v) || !v) return def;
    return json_object_get_string(v) ? json_object_get_string(v) : def;
}

static int json_i(struct json_object *o, const char *k, int def)
{
    struct json_object *v = NULL;
    if (!o || !json_object_object_get_ex(o, k, &v) || !v) return def;
    return json_object_get_int(v);
}

static int db_json_has_key(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;

    return o && key && json_object_object_get_ex(o, key, &v);
}

static int db_json_has_any_key(struct json_object *o, const char *a, const char *b)
{
    return db_json_has_key(o, a) || (b && db_json_has_key(o, b));
}

static struct json_object *db_override_fields_json(struct json_object *req)
{
    struct json_object *fields = json_object_new_array();

    if (db_json_has_any_key(req, "nickname", "custom_name"))
        json_object_array_add(fields, json_object_new_string("nickname"));
    if (db_json_has_key(req, "device_name"))
        json_object_array_add(fields, json_object_new_string("device_name"));
    if (db_json_has_any_key(req, "vendor_name", "custom_vendor"))
        json_object_array_add(fields, json_object_new_string("vendor_name"));
    if (db_json_has_any_key(req, "device_type", "custom_device_type"))
        json_object_array_add(fields, json_object_new_string("device_type"));
    if (db_json_has_any_key(req, "custom_image_path", "custom_icon"))
        json_object_array_add(fields, json_object_new_string("custom_image_path"));
    if (db_json_has_key(req, "engine"))
        json_object_array_add(fields, json_object_new_string("engine"));
    if (db_json_has_key(req, "device_id"))
        json_object_array_add(fields, json_object_new_string("device_id"));
    if (db_json_has_key(req, "pinned"))
        json_object_array_add(fields, json_object_new_string("pinned"));
    if (db_json_has_key(req, "hidden"))
        json_object_array_add(fields, json_object_new_string("hidden"));
    if (db_json_has_key(req, "note"))
        json_object_array_add(fields, json_object_new_string("note"));
    return fields;
}

static int64_t json_i64(struct json_object *o, const char *k, int64_t def)
{
    struct json_object *v = NULL;
    if (!o || !json_object_object_get_ex(o, k, &v) || !v) return def;
    return json_object_get_int64(v);
}

static double json_d(struct json_object *o, const char *k, double def)
{
    struct json_object *v = NULL;
    if (!o || !json_object_object_get_ex(o, k, &v) || !v) return def;
    return json_object_get_double(v);
}

static int db_ipv6_is_link_local(const char *addr)
{
    return addr && addr[0] && !strncasecmp(addr, "fe80:", 5);
}

static int db_ipv6_is_ula(const char *addr)
{
    return addr && addr[0] &&
           (!strncasecmp(addr, "fc", 2) || !strncasecmp(addr, "fd", 2));
}

static int db_ipv6_is_loopback(const char *addr)
{
    return addr && (!strcmp(addr, "::1") || !strcasecmp(addr, "0:0:0:0:0:0:0:1"));
}

/*
 * The IPv6 mirror of the 0.0.0.0 problem. :: is the unspecified address, which
 * the kernel client table reports for a MAC it has no IPv6 evidence for; it is
 * not an address the device holds. It was passing db_ipv6_usable() because only
 * ::1 was screened, so a client with no IPv6 published ipv6 = "::" alongside a
 * one-element ipv6_addrs list, which reads as "has IPv6" to every consumer.
 */
static int db_ipv6_is_unspecified(const char *addr)
{
    return addr && (!strcmp(addr, "::") || !strcmp(addr, "0:0:0:0:0:0:0:0"));
}

static int db_ipv6_usable(const char *addr)
{
    return addr && addr[0] && strchr(addr, ':') &&
           !db_ipv6_is_loopback(addr) && !db_ipv6_is_unspecified(addr);
}

/*
 * An IPv4 address the client actually holds. 0.0.0.0 is the "no address"
 * sentinel the collectors store when a MAC was only ever seen over IPv6, and
 * it must never be published as if it were a real address: consumers use the
 * ip field as a jump target, a flow-attribution key and a display value, and
 * a placeholder there reads as a misconfigured device rather than as an absent
 * lease. The same value is already treated as empty when rows are merged
 * (dw_merge_device_runtime_evidence) and when flows are attributed
 * (dw_flow_ip_usable), so the output side is the only place that still leaked it.
 */
static int db_ipv4_usable(const char *addr)
{
    if (!addr || !addr[0])
        return 0;
    if (!strcmp(addr, "0.0.0.0") || !strcmp(addr, "255.255.255.255"))
        return 0;
    if (!strncmp(addr, "127.", 4))
        return 0;
    return strchr(addr, '.') != NULL;
}

static void db_ipv6_array_add_unique(struct json_object *arr, const char *addr)
{
    int i, n;

    if (!arr || !db_ipv6_usable(addr))
        return;
    n = (int)json_object_array_length(arr);
    for (i = 0; i < n; i++) {
        const char *have = json_object_get_string(json_object_array_get_idx(arr, i));
        if (have && !strcasecmp(have, addr))
            return;
    }
    json_object_array_add(arr, json_object_new_string(addr));
}

static void db_ipv6_parse_pipe(struct json_object *arr, const char *pipe)
{
    const char *p = pipe;

    if (!arr || !pipe)
        return;
    while ((p = strchr(p, '|')) != NULL) {
        const char *end = strchr(p + 1, '|');
        char addr[128];
        size_t len;

        if (!end)
            break;
        len = (size_t)(end - (p + 1));
        if (len > 0 && len < sizeof(addr)) {
            memcpy(addr, p + 1, len);
            addr[len] = '\0';
            db_ipv6_array_add_unique(arr, addr);
        }
        p = end + 1;
    }
}

static void db_add_ipv6_contract(struct json_object *o, const char *raw_json,
                                 const char *fallback_raw,
                                 const char *fallback_global,
                                 const char *fallback_lan,
                                 const char *fallback_link_local)
{
    struct json_object *arr = json_object_new_array();
    struct json_object *parsed = NULL;
    struct json_object *v = NULL;
    char global[128] = "";
    char lan[128] = "";
    char link_local[128] = "";
    const char *primary = "";
    int i, n;

    if (raw_json && raw_json[0])
        parsed = json_tokener_parse(raw_json);
    if (parsed && json_object_is_type(parsed, json_type_object)) {
        const char *s;
        if (json_object_object_get_ex(parsed, "addrs", &v) && v &&
            json_object_is_type(v, json_type_array)) {
            n = (int)json_object_array_length(v);
            for (i = 0; i < n; i++)
                db_ipv6_array_add_unique(arr, json_object_get_string(json_object_array_get_idx(v, i)));
        }
        s = json_s(parsed, "global", json_s(parsed, "ipv6_global", ""));
        if (db_ipv6_usable(s))
            snprintf(global, sizeof(global), "%s", s);
        s = json_s(parsed, "lan", json_s(parsed, "ipv6_lan", ""));
        if (db_ipv6_usable(s))
            snprintf(lan, sizeof(lan), "%s", s);
        s = json_s(parsed, "link_local", json_s(parsed, "ipv6_link_local", ""));
        if (db_ipv6_usable(s))
            snprintf(link_local, sizeof(link_local), "%s", s);
    } else if (parsed && json_object_is_type(parsed, json_type_array)) {
        n = (int)json_object_array_length(parsed);
        for (i = 0; i < n; i++)
            db_ipv6_array_add_unique(arr, json_object_get_string(json_object_array_get_idx(parsed, i)));
    }
    db_ipv6_parse_pipe(arr, fallback_raw);
    db_ipv6_array_add_unique(arr, fallback_global);
    db_ipv6_array_add_unique(arr, fallback_lan);
    db_ipv6_array_add_unique(arr, fallback_link_local);

    n = (int)json_object_array_length(arr);
    for (i = 0; i < n; i++) {
        const char *addr = json_object_get_string(json_object_array_get_idx(arr, i));

        if (!db_ipv6_usable(addr))
            continue;
        if (!link_local[0] && db_ipv6_is_link_local(addr))
            snprintf(link_local, sizeof(link_local), "%s", addr);
        else if (!lan[0] && db_ipv6_is_ula(addr))
            snprintf(lan, sizeof(lan), "%s", addr);
        else if (!global[0] && !db_ipv6_is_link_local(addr) && !db_ipv6_is_ula(addr))
            snprintf(global, sizeof(global), "%s", addr);
    }
    primary = global[0] ? global : (lan[0] ? lan : link_local);

    json_object_object_add(o, "ipv6", json_object_new_string(primary ? primary : ""));
    json_object_object_add(o, "ipv6_addrs", arr);
    json_object_object_add(o, "ipv6_global", json_object_new_string(global));
    json_object_object_add(o, "global_ipv6", json_object_new_string(global));
    json_object_object_add(o, "ipv6_lan", json_object_new_string(lan));
    json_object_object_add(o, "lan_ipv6", json_object_new_string(lan));
    json_object_object_add(o, "ipv6_link_local", json_object_new_string(link_local));
    json_object_object_add(o, "link_local_ipv6", json_object_new_string(link_local));
    /* The single-value fields cannot express a dual-prefix client, so state how
     * they were picked instead of leaving the consumer to guess. ipv6_addrs is
     * the complete list; these are a convenience view over it. */
    json_object_object_add(o, "ipv6_primary_rule",
                           json_object_new_string("global_first_then_ula_then_link_local"));
    if (parsed)
        json_object_put(parsed);
}

/*
 * STALE is deliberately excluded. Its kernel meaning is "was reachable once,
 * not verified since", and an IPv6 STALE entry can survive long after a client
 * disappears. Treating it as liveness is what kept deleted container veths
 * listed as online.
 */
static int db_client_neigh_reachable(const char *state)
{
    return state && state[0] &&
           (strstr(state, "REACHABLE") || strstr(state, "DELAY") ||
            strstr(state, "PROBE") || strstr(state, "PERMANENT") ||
            strstr(state, "NOARP") || strstr(state, "arp_reachable"));
}

/*
 * Online decision, isolated from row/JSON plumbing so it can be exercised
 * directly by tests. Every field is evidence the caller has already gathered;
 * this function only weighs it.
 *
 * Ghost-client rule: a client whose IPv4 neighbour entry FAILED, or that the
 * LAN bridge has not seen a frame from, is offline unless traffic, conntrack
 * or a genuinely reachable neighbour state says otherwise. STALE is not
 * reachable: it only means "was reachable once, unverified now".
 */
void jmx_db_client_online_verdict(const struct jmx_db_client_evidence *ev,
                                  struct jmx_db_client_verdict *out)
{
    int online;
    int sample_valid;
    int has_active_evidence;
    int neigh_failed = 0;
    int neigh_reachable = 0;
    int fdb_absent;
    int64_t tx_rate;
    int64_t rx_rate;
    int connections;

    if (!ev || !out)
        return;
    memset(out, 0, sizeof(*out));
    online = ev->db_online;
    tx_rate = ev->tx_rate;
    rx_rate = ev->rx_rate;
    connections = ev->connections;

    /* IPv4 is authoritative because this router owns the IPv4 LAN. An IPv6
     * STALE entry must never mask an IPv4 FAILED one; that shared field was
     * the original defect. */
    if (strstr(ev->neigh_state_v4, "FAILED") ||
        strstr(ev->neigh_state_v4, "INCOMPLETE"))
        neigh_failed = 1;
    else if (!ev->neigh_state_v4[0] &&
             (strstr(ev->neigh_state_v6, "FAILED") ||
              strstr(ev->neigh_state_v6, "INCOMPLETE")))
        neigh_failed = 1;
    else if (strstr(ev->neigh_state, "FAILED") ||
             strstr(ev->neigh_state, "INCOMPLETE"))
        neigh_failed = 1;
    neigh_reachable = db_client_neigh_reachable(ev->neigh_state_v4) ||
                      db_client_neigh_reachable(ev->neigh_state_v6) ||
                      db_client_neigh_reachable(ev->neigh_state);
    /* -1 means no bridge could be read, which is not evidence of absence. */
    fdb_absent = ev->bridge_fdb_present == 0;

    sample_valid = ev->sample_age_ms >= 0 && ev->sample_age_ms <= 30000;
    if (!sample_valid) {
        tx_rate = 0;
        rx_rate = 0;
        connections = 0;
    }
    has_active_evidence = (sample_valid &&
                           (tx_rate > 0 || rx_rate > 0 || connections > 0 ||
                            (ev->last_seen_age >= 0 && ev->last_seen_age <= 120))) ||
                          (ev->runtime_online && sample_valid) ||
                          (online && sample_valid && !neigh_failed);
    if (fdb_absent && !neigh_reachable && tx_rate <= 0 && rx_rate <= 0 &&
        connections <= 0) {
        has_active_evidence = 0;
        out->offline_reason = "not_in_bridge_fdb";
    }
    if (online && (!has_active_evidence ||
                   (neigh_failed && tx_rate <= 0 && rx_rate <= 0 &&
                    connections <= 0))) {
        online = 0;
        if (ev->sample_age_ms < 0 || ev->sample_age_ms > 30000)
            sample_valid = 0;
    }

    out->online = online;
    out->sample_valid = sample_valid;
    out->neigh_failed = neigh_failed;
    out->neigh_reachable = neigh_reachable;
    out->has_active_evidence = has_active_evidence;
    out->tx_rate = tx_rate;
    out->rx_rate = rx_rate;
    out->connections = connections;
    /* Only report a live source while the client is actually online; otherwise
     * a leftover runtime value keeps claiming "arp" for a client this router
     * can no longer see. */
    out->online_source = (online && ev->runtime_online_source &&
                          ev->runtime_online_source[0]) ? ev->runtime_online_source :
                         (online ? "client_network_state" :
                          (out->offline_reason ? out->offline_reason :
                           (neigh_failed ? "neigh_failed" :
                            (!has_active_evidence ? "stale_client_db" : ""))));
    out->zero_reason = (tx_rate > 0 || rx_rate > 0) ? "" :
                       (online ? (sample_valid ? "idle" : "no_sample") :
                        (out->offline_reason ? out->offline_reason :
                         (neigh_failed ? "neigh_failed" : "no_active_evidence")));
}

/* Mirrors jmx_core_legacy_netlink_enabled() in main.c and its twin in
 * jmx_dreamingwrt_api.c. Both are file-static there, and the value decides which
 * writer fills the hourly byte buckets, so the reader has to ask the same
 * question the same way - accepting the value, not merely the variable's
 * presence. */
static int db_legacy_netlink_enabled(void)
{
    const char *v = getenv("DREAMINGWRT_CORE_LEGACY_NETLINK");

    return v && (!strcmp(v, "1") || !strcasecmp(v, "true") ||
                 !strcasecmp(v, "yes") || !strcasecmp(v, "on"));
}

static client_node_t *db_find_runtime_client(const char *mac)
{
    client_node_t *c = NULL;
    char wanted[MAX_MAC_LEN] = {0};

    if (normalize_mac(mac, wanted, sizeof(wanted)) != 0)
        return NULL;
    list_for_each_entry(c, &client_list, client) {
        char have[MAX_MAC_LEN] = {0};

        if (normalize_mac(c->mac, have, sizeof(have)) != 0)
            continue;
        if (!strcmp(have, wanted))
            return c;
    }
    return NULL;
}

static int db_count_conntrack_for_ip(const char *ip)
{
    FILE *fp;
    char line[1024];
    int count = 0;

    if (!ip || !ip[0])
        return 0;
    fp = fopen("/proc/net/nf_conntrack", "r");
    if (!fp)
        fp = fopen("/proc/net/ip_conntrack", "r");
    if (!fp)
        return 0;
    while (fgets(line, sizeof(line), fp)) {
        char src[128];
        char dst[128];

        snprintf(src, sizeof(src), "src=%s", ip);
        snprintf(dst, sizeof(dst), "dst=%s", ip);
        if (strstr(line, src) || strstr(line, dst))
            count++;
    }
    fclose(fp);
    return count;
}

/* Per-family conntrack counts for one client.
 *
 * db_count_conntrack_for_ip() above cannot see IPv6 traffic: it takes a single
 * IPv4 string and matches it literally, while conntrack prints IPv6 addresses
 * fully expanded and zero padded (src=2409:8a10:001e:8aa4:...) where the client
 * record holds the compressed form (2409:8a10:1e:8aa4::6c9). A literal compare
 * of those two spellings can never succeed.
 *
 * Addresses are normalised with inet_pton and compared as bytes, so both
 * spellings agree. One pass over conntrack serves both families.
 *
 * Rates and byte counters are NOT split by family: the kernel module exposes a
 * single UpRate/DownRate pair per MAC in /proc/dreamingwrt/jmx/af_client with no
 * family dimension, so a per-family rate would be invented. Callers publish
 * ipv6_rate_supported=false with a reason instead. */
#define DB_CONN_ADDR_MAX 12

typedef struct {
    unsigned char bytes[16];
    int len;
} db_conn_addr_t;

static void db_conn_addr_add(db_conn_addr_t *slots, int *count, const char *addr)
{
    unsigned char buf[16];
    int len;
    int i;

    if (!slots || !count || *count >= DB_CONN_ADDR_MAX || !addr || !addr[0])
        return;
    if (strchr(addr, ':')) {
        if (inet_pton(AF_INET6, addr, buf) != 1)
            return;
        len = 16;
    } else {
        if (inet_pton(AF_INET, addr, buf) != 1)
            return;
        len = 4;
    }
    for (i = 0; i < *count; i++)
        if (slots[i].len == len && !memcmp(slots[i].bytes, buf, (size_t)len))
            return;
    memcpy(slots[*count].bytes, buf, (size_t)len);
    slots[*count].len = len;
    (*count)++;
}

/* client_node_t.ipv6_addrs is a |-delimited list. */
static void db_conn_addr_add_pipe(db_conn_addr_t *slots, int *count, const char *pipe)
{
    const char *p = pipe;

    if (!slots || !count || !pipe)
        return;
    while ((p = strchr(p, '|')) != NULL) {
        const char *end = strchr(p + 1, '|');
        char addr[128];
        size_t len;

        if (!end)
            break;
        len = (size_t)(end - (p + 1));
        if (len > 0 && len < sizeof(addr)) {
            memcpy(addr, p + 1, len);
            addr[len] = '\0';
            db_conn_addr_add(slots, count, addr);
        }
        p = end;
    }
}

static void db_count_conntrack_by_family(const client_node_t *c,
                                         int *out_v4, int *out_v6)
{
    db_conn_addr_t addrs[DB_CONN_ADDR_MAX];
    int addr_count = 0;
    FILE *fp;
    char line[2048];
    int v4 = 0;
    int v6 = 0;

    if (out_v4)
        *out_v4 = 0;
    if (out_v6)
        *out_v6 = 0;
    if (!c)
        return;

    memset(addrs, 0, sizeof(addrs));
    db_conn_addr_add(addrs, &addr_count, c->ip);
    db_conn_addr_add(addrs, &addr_count, c->ipv6);
    db_conn_addr_add(addrs, &addr_count, c->ipv6_global);
    db_conn_addr_add(addrs, &addr_count, c->ipv6_lan);
    db_conn_addr_add(addrs, &addr_count, c->ipv6_link_local);
    db_conn_addr_add_pipe(addrs, &addr_count, c->ipv6_addrs);
    if (addr_count == 0)
        return;

    fp = fopen("/proc/net/nf_conntrack", "r");
    if (!fp)
        fp = fopen("/proc/net/ip_conntrack", "r");
    if (!fp)
        return;
    while (fgets(line, sizeof(line), fp)) {
        const char *keys[2] = { "src=", "dst=" };
        int matched_len = 0;
        int k;

        for (k = 0; k < 2 && !matched_len; k++) {
            const char *p = strstr(line, keys[k]);
            char addr[128];
            unsigned char buf[16];
            const char *e;
            size_t len;
            int alen;
            int i;

            if (!p)
                continue;
            p += 4;
            e = p;
            while (*e && *e != ' ' && *e != '\t' && *e != '\n')
                e++;
            len = (size_t)(e - p);
            if (len == 0 || len >= sizeof(addr))
                continue;
            memcpy(addr, p, len);
            addr[len] = '\0';
            if (strchr(addr, ':')) {
                if (inet_pton(AF_INET6, addr, buf) != 1)
                    continue;
                alen = 16;
            } else {
                if (inet_pton(AF_INET, addr, buf) != 1)
                    continue;
                alen = 4;
            }
            for (i = 0; i < addr_count; i++) {
                if (addrs[i].len == alen &&
                    !memcmp(addrs[i].bytes, buf, (size_t)alen)) {
                    matched_len = alen;
                    break;
                }
            }
        }
        if (matched_len == 16)
            v6++;
        else if (matched_len == 4)
            v4++;
    }
    fclose(fp);
    if (out_v4)
        *out_v4 = v4;
    if (out_v6)
        *out_v6 = v6;
}

static const char *db_guess_type_from_hostname(const char *host)
{
    char h[128];
    size_t i;
    if (!host || !host[0]) return "unknown";
    snprintf(h, sizeof(h), "%s", host);
    for (i = 0; h[i]; i++) h[i] = (char)tolower((unsigned char)h[i]);
    /* Smartphones */
    if (strstr(h, "iphone") || strstr(h, "android") || strstr(h, "phone") || strstr(h, "redmi") || strstr(h, "poco") ||
        strstr(h, "galaxy") || strstr(h, "pixel") || strstr(h, "oneplus") || strstr(h, "huawei") || strstr(h, "honor"))
        return "smartphone";
    /* Tablets */
    if (strstr(h, "ipad") || strstr(h, "tablet") || strstr(h, "surface")) return "tablet";
    /* Computers */
    if (strstr(h, "macbook") || strstr(h, "imac") || strstr(h, "mac ") || !strcmp(h, "mac") || strstr(h, "windows") || strstr(h, "desktop") ||
        strstr(h, "laptop") || strstr(h, "thinkpad") || strstr(h, "dell") || strstr(h, "lenovo") ||
        strstr(h, "ubuntu") || strstr(h, "debian") || strstr(h, "linux") || strstr(h, "server"))
        return "computer";
    /* TVs / Streaming */
    if (strstr(h, "tv") || strstr(h, "television") || strstr(h, "roku") || strstr(h, "firetv") || strstr(h, "chromecast") ||
        strstr(h, "appletv") || strstr(h, "mi tv") || strstr(h, "xiaomi tv"))
        return "tv";
    /* Printers */
    if (strstr(h, "printer") || strstr(h, "canon") || strstr(h, "epson") || strstr(h, "hp laser") || strstr(h, "brother"))
        return "printer";
    /* Cameras */
    if (strstr(h, "camera") || strstr(h, "cam") || strstr(h, "hikvision") || strstr(h, "dahua") || strstr(h, "ipcam"))
        return "camera";
    /* Game Consoles */
    if (strstr(h, "xbox") || strstr(h, "playstation") || strstr(h, "ps5") || strstr(h, "switch") || strstr(h, "nintendo"))
        return "game_console";
    /* IoT / Smart Home */
    if (strstr(h, "xiaomi") || strstr(h, "yeelight") || strstr(h, "aqara") || strstr(h, "tuya") || strstr(h, "shelly") ||
        strstr(h, "sonoff") || strstr(h, "miaisoundbox") || strstr(h, "soundbox") || strstr(h, "speaker") || strstr(h, "esp32") || strstr(h, "esp8266") || strstr(h, "mibt") || strstr(h, "miap") ||
        strstr(h, "chunmi") || strstr(h, "dreame") || strstr(h, "roborock") || strstr(h, "viomi") || strstr(h, "zhimi") ||
        strstr(h, "vela") || strstr(h, "yeelink") || strstr(h, "cook") || strstr(h, "pot") || strstr(h, "lamp") ||
        strstr(h, "bulb") || strstr(h, "plug") || strstr(h, "sensor") || strstr(h, "thermostat") || strstr(h, "lock"))
        return "iot";
    /* Routers */
    if (strstr(h, "router") || strstr(h, "gateway") || strstr(h, "openwrt") || strstr(h, "ikuai"))
        return "router";
    /* NAS */
    if (strstr(h, "nas") || strstr(h, "synology") || strstr(h, "qnap") || strstr(h, "diskstation"))
        return "nas";
    return "unknown";
}

static const char *db_guess_os_from_hostname(const char *host)
{
    char h[128];
    size_t i;
    if (!host || !host[0]) return "";
    snprintf(h, sizeof(h), "%s", host);
    for (i = 0; h[i]; i++) h[i] = (char)tolower((unsigned char)h[i]);
    if (strstr(h, "iphone") || strstr(h, "ipad")) return "Apple iOS";
    if (strstr(h, "macbook") || strstr(h, "imac")) return "Apple macOS";
    if (strstr(h, "android")) return "Android";
    if (strstr(h, "windows") || strstr(h, "desktop") || strstr(h, "laptop")) return "Windows";
    return "";
}

static const char *db_vendor_from_mac_text(const char *mac)
{
    uint8_t b[6];
    if (!mac || sscanf(mac, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return "";
    const char *v = jmx_ht_match_mac(b);
    return v ? v : "";
}

static void db_trim_crlf(char *s)
{
    size_t n;
    if (!s) return;
    while (*s && isspace((unsigned char)*s)) memmove(s, s + 1, strlen(s));
    n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
    n = strlen(s);
    if (n >= 2 && ((s[0] == '"' && s[n - 1] == '"') || (s[0] == '\'' && s[n - 1] == '\''))) {
        memmove(s, s + 1, n - 2);
        s[n - 2] = '\0';
    }
}

static void db_lower_ascii_copy(char *out, size_t out_len, const char *in)
{
    size_t i;
    if (!out || !out_len) return;
    out[0] = '\0';
    if (!in) return;
    for (i = 0; i + 1 < out_len && in[i]; i++)
        out[i] = (char)tolower((unsigned char)in[i]);
    out[i] = '\0';
}

static int db_prepare(sqlite3_stmt **st, const char *sql);
static const char *db_vendor_from_evidence(const char *value);

static int db_text_has_any(const char *text, const char **needles)
{
    int i;
    char v[256];
    if (!text || !text[0]) return 0;
    db_lower_ascii_copy(v, sizeof(v), text);
    for (i = 0; needles && needles[i]; i++) {
        if (strstr(v, needles[i])) return 1;
    }
    return 0;
}

static int db_value_is_oui_only_signal(const char *key, const char *source)
{
    return key && source && !strcmp(key, "vendor") && !strcmp(source, "oui");
}

/*
 * Generic-router placeholder for iKuaiOS devices.
 *
 * The fingerprint gallery has no iKuai-specific asset, so client_profile
 * substitutes the generic router icon (device 3797) and flags it as a fallback.
 * The list serializer used to skip that step entirely, which is why the same
 * device arrived with an image from /api/v1/client_profile and with empty
 * image fields from /api/v1/clients. Keep this predicate identical to
 * webd_ikuai_router_identity() in webd/jmx_app_api.c; two divergent copies is
 * the defect this is fixing.
 */
#define DB_GENERIC_ROUTER_WEB_IMAGE \
    "/luci-static/dreamingwrt/fingerprint/images/engine-0/3797/257x257.png"

static int db_ikuai_router_identity(const char *vendor,
                                    const char *device_type,
                                    const char *model)
{
    char text[768];

    snprintf(text, sizeof(text), "%s %s %s",
             vendor ? vendor : "",
             device_type ? device_type : "",
             model ? model : "");
    for (char *p = text; *p; p++)
        *p = (char)tolower((unsigned char)*p);
    return strstr(text, "ikuai") && strstr(text, "router");
}

static int db_vendor_is_virtual_nic(const char *vendor)
{
    char v[256];
    if (!vendor || !vendor[0]) return 0;
    db_lower_ascii_copy(v, sizeof(v), vendor);

    /* These are virtual NIC / VM platform OUIs, not reliable device identities.
     * A bc:24:11 MAC only proves the NIC was allocated by Proxmox; the guest OS
     * may be iKuaiOS/OpenWrt/Linux/etc.  Do not promote these OUI vendors to
     * vendor/type unless we also have higher-level evidence such as SSDP/HTTP. */
    if (strstr(v, "proxmox")) return 1;
    if (strstr(v, "qemu") || strstr(v, "kvm")) return 1;
    if (strstr(v, "vmware")) return 1;
    if (strstr(v, "virtualbox") || strstr(v, "oracle virtual")) return 1;
    if (strstr(v, "parallels")) return 1;
    if (strstr(v, "xen")) return 1;
    if (strstr(v, "bhyve")) return 1;
    if (strstr(v, "red hat") && (strstr(v, "virt") || strstr(v, "qemu"))) return 1;
    return 0;
}

static int db_vendor_type_fallback_allowed(const char *vendor)
{
    char v[256];
    if (!vendor || !vendor[0]) return 0;
    db_lower_ascii_copy(v, sizeof(v), vendor);
    if (db_vendor_is_virtual_nic(vendor)) return 0;
    if (strstr(v, "xiaomi") || strstr(v, "beijing xiaomi") || strstr(v, "redmi") || !strcmp(v, "mi")) return 0;
    if (strstr(v, "apple") || strstr(v, "samsung") || strstr(v, "huawei") || strstr(v, "honor") || strstr(v, "sony") || strstr(v, "google") || strstr(v, "lg")) return 0;
    return 1;
}

static int db_synology_model_token_present(const char *lower_text)
{
    static const char *prefixes[] = {"ds", "rs", "sa", "fs", "hd", "uc", "dva", NULL};
    int i;

    if (!lower_text || !lower_text[0])
        return 0;
    for (i = 0; prefixes[i]; i++) {
        size_t plen = strlen(prefixes[i]);
        const char *p = lower_text;

        while ((p = strstr(p, prefixes[i])) != NULL) {
            int before_ok = (p == lower_text) ||
                            !isalnum((unsigned char)p[-1]);
            int after_ok = isdigit((unsigned char)p[plen]);

            if (before_ok && after_ok)
                return 1;
            p++;
        }
    }
    return 0;
}

static void db_apply_known_model_hint(const char *key, const char *value, char *best_name, size_t name_len, char *best_vendor, size_t vendor_len, char *best_type, size_t type_len, int *score, char *source, size_t source_len)
{
    char v[256];
    int key_is_name;
    if (!value || !value[0]) return;
    db_lower_ascii_copy(v, sizeof(v), value);
    key_is_name = !key || !key[0] ||
                  !strcmp(key, "friendlyName") ||
                  !strcmp(key, "modelName") ||
                  !strcmp(key, "modelNumber") ||
                  !strcmp(key, "model") ||
                  !strcmp(key, "hostname") ||
                  !strcmp(key, "dhcp_hostname");
    if (strstr(v, "macsamba")) return;
    if (strstr(v, "macbook") || strstr(v, "mac mini") || strstr(v, "macmini") || strstr(v, "mac studio") || strstr(v, "imac") || !strcmp(v, "mac")) {
        if (best_name && !best_name[0]) snprintf(best_name, name_len, "%s", value);
        if (best_vendor && (!best_vendor[0] || !strcmp(best_vendor, "unknown"))) snprintf(best_vendor, vendor_len, "%s", "Apple");
        if (best_type && !strcmp(best_type, "unknown")) snprintf(best_type, type_len, "%s", "computer");
        if (score && *score < 85) *score = 85;
        if (source) snprintf(source, source_len, "%s", "model-hint");
        return;
    }
    if (strstr(v, "mac") && strchr(v, ',')) {
        if (best_name && !best_name[0]) snprintf(best_name, name_len, "%s", value);
        if (best_vendor && (!best_vendor[0] || !strcmp(best_vendor, "unknown"))) snprintf(best_vendor, vendor_len, "%s", "Apple");
        if (best_type && !strcmp(best_type, "unknown")) snprintf(best_type, type_len, "%s", "computer");
        if (score && *score < 87) *score = 87;
        if (source) snprintf(source, source_len, "%s", "model-code");
        return;
    }
    if (strstr(v, "iphone") || strstr(v, "ipad")) {
        if (best_name && !best_name[0]) snprintf(best_name, name_len, "%s", value);
        if (best_vendor && (!best_vendor[0] || !strcmp(best_vendor, "unknown"))) snprintf(best_vendor, vendor_len, "%s", "Apple");
        if (best_type && !strcmp(best_type, "unknown")) snprintf(best_type, type_len, "%s", strstr(v, "ipad") ? "tablet" : "smartphone");
        if (score && *score < 88) *score = 88;
        if (source) snprintf(source, source_len, "%s", strchr(v, ',') ? "model-code" : "model-hint");
        return;
    }
    if (strstr(v, "synology") || db_synology_model_token_present(v)) {
        int has_model = db_synology_model_token_present(v);

        if (best_name && key_is_name && !strstr(v, "/dsm/") &&
            (!best_name[0] || has_model))
            snprintf(best_name, name_len, "%s", value);
        if (best_vendor && (!best_vendor[0] || !strcmp(best_vendor, "unknown"))) snprintf(best_vendor, vendor_len, "%s", "Synology");
        if (best_type && !strcmp(best_type, "unknown")) snprintf(best_type, type_len, "%s", "nas");
        if (score && *score < (has_model ? 90 : 82)) *score = has_model ? 90 : 82;
        if (source) snprintf(source, source_len, "%s", has_model ? "model-code" : "model-hint");
        return;
    }
    if (strstr(v, "miaisoundbox") || strstr(v, "mi ai soundbox") || strstr(v, "lx06")) {
        if (best_name && (!best_name[0] || strstr(v, "miaisoundbox") || strstr(v, "lx06"))) snprintf(best_name, name_len, "%s", value);
        if (best_vendor && (!best_vendor[0] || !strcmp(best_vendor, "unknown"))) snprintf(best_vendor, vendor_len, "%s", "Xiaomi");
        if (best_type && !strcmp(best_type, "unknown")) snprintf(best_type, type_len, "%s", "speaker");
        if (score && *score < 88) *score = 88;
        if (source) snprintf(source, source_len, "%s", "model-hint");
        return;
    }
}

static int db_vendor_conflicts(const char *trusted_vendor, const char *candidate_vendor)
{
    char a[128], b[128];
    if (!trusted_vendor || !trusted_vendor[0] || !candidate_vendor || !candidate_vendor[0]) return 0;
    db_lower_ascii_copy(a, sizeof(a), trusted_vendor);
    db_lower_ascii_copy(b, sizeof(b), candidate_vendor);
    if ((strstr(a, "synology") && strstr(b, "apple")) || (strstr(a, "apple") && strstr(b, "synology"))) return 1;
    if ((strstr(a, "xiaomi") && strstr(b, "apple")) || (strstr(a, "apple") && strstr(b, "xiaomi"))) return 1;
    return 0;
}

static int db_signal_name_specific_enough(const char *name)
{
    char n[256];
    int has_digit = 0;
    int has_sep = 0;
    int len = 0;
    int i;

    if (!name || !name[0])
        return 0;
    db_lower_ascii_copy(n, sizeof(n), name);
    if (!strcmp(n, "synology nas") || !strcmp(n, "xiaomi router") ||
        !strcmp(n, "openwrt router") || !strcmp(n, "ikuaios router"))
        return 0;
    for (i = 0; n[i]; i++) {
        if (isalnum((unsigned char)n[i]))
            len++;
        if (isdigit((unsigned char)n[i]))
            has_digit = 1;
        if (n[i] == '-' || n[i] == '_' || n[i] == '(' || n[i] == ')')
            has_sep = 1;
    }
    if (len >= 6 && (has_digit || has_sep))
        return 1;
    return len >= 12;
}

static void db_clean_signal_device_name(const char *friendly, const char *model,
                                        char *out, size_t out_len)
{
    char name[256];
    char model_l[128];
    char name_l[256];
    char *p;

    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (friendly && friendly[0])
        snprintf(name, sizeof(name), "%s", friendly);
    else if (model && model[0])
        snprintf(name, sizeof(name), "%s", model);
    else
        return;

    db_trim_crlf(name);
    p = strchr(name, '(');
    if (p && strchr(p, ')')) {
        char suffix[128];
        char *end = strchr(p, ')');
        size_t suffix_len;
        *p = '\0';
        suffix_len = (size_t)(end - p - 1);
        if (suffix_len >= sizeof(suffix))
            suffix_len = sizeof(suffix) - 1;
        memcpy(suffix, p + 1, suffix_len);
        suffix[suffix_len] = '\0';
        db_trim_crlf(name);
        db_trim_crlf(suffix);
        if (suffix[0] && !strstr(name, suffix))
            snprintf(name + strlen(name), sizeof(name) - strlen(name), " %s", suffix);
    }

    if (model && model[0]) {
        db_lower_ascii_copy(name_l, sizeof(name_l), name);
        db_lower_ascii_copy(model_l, sizeof(model_l), model);
        if (!strstr(name_l, model_l)) {
            size_t used = strlen(name);
            snprintf(name + used, sizeof(name) - used, "%s%s",
                     used ? " " : "", model);
        }
    }

    db_trim_crlf(name);
    snprintf(out, out_len, "%s", name);
}

static int db_apply_specific_signal_name(const char *mac, char *best_name, size_t name_len,
                                         char *best_vendor, size_t vendor_len,
                                         char *best_type, size_t type_len,
                                         int *score, char *source, size_t source_len)
{
    struct signal_name_group {
        char source[64];
        char friendly[256];
        char model[128];
        char manufacturer[128];
        char device_type[64];
        int friendly_conf;
        int model_conf;
        int manufacturer_conf;
        int device_type_conf;
        int best_conf;
    };
    sqlite3_stmt *st = NULL;
    struct signal_name_group groups[8];
    char name[256] = "";
    char selected_name[256] = "";
    char selected_manufacturer[128] = "";
    char selected_type[64] = "";
    int selected_score = -1;
    int i, group_count = 0;

    if (!mac || !best_name || !score)
        return 0;
    memset(groups, 0, sizeof(groups));
    if (db_prepare(&st,
        "SELECT source,key,value,confidence FROM client_identity_signals "
        "WHERE mac=?1 AND source IN ('ssdp','mdns','route-downstream-http','service-probe','ikuai-ac-http') "
        "AND key IN ('friendlyName','modelName','modelNumber','model','manufacturer','device_type','deviceType') "
        "ORDER BY confidence DESC,last_seen DESC LIMIT 32") != 0)
        return 0;
    sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *sig_source = (const char *)sqlite3_column_text(st, 0);
        const char *key = (const char *)sqlite3_column_text(st, 1);
        const char *val = (const char *)sqlite3_column_text(st, 2);
        int conf = sqlite3_column_int(st, 3);
        int idx = -1;
        if (!sig_source || !sig_source[0] || !key || !val || !val[0])
            continue;
        for (i = 0; i < group_count; i++) {
            if (!strcmp(groups[i].source, sig_source)) {
                idx = i;
                break;
            }
        }
        if (idx < 0) {
            if (group_count >= (int)(sizeof(groups) / sizeof(groups[0])))
                continue;
            idx = group_count++;
            snprintf(groups[idx].source, sizeof(groups[idx].source), "%s", sig_source);
        }
        if (conf > groups[idx].best_conf)
            groups[idx].best_conf = conf;
        if (!strcmp(key, "friendlyName") && conf >= groups[idx].friendly_conf) {
            snprintf(groups[idx].friendly, sizeof(groups[idx].friendly), "%s", val);
            groups[idx].friendly_conf = conf;
        } else if ((!strcmp(key, "modelName") || !strcmp(key, "modelNumber") || !strcmp(key, "model")) && conf >= groups[idx].model_conf) {
            snprintf(groups[idx].model, sizeof(groups[idx].model), "%s", val);
            groups[idx].model_conf = conf;
        } else if (!strcmp(key, "manufacturer") && conf >= groups[idx].manufacturer_conf) {
            snprintf(groups[idx].manufacturer, sizeof(groups[idx].manufacturer), "%s", val);
            groups[idx].manufacturer_conf = conf;
        } else if ((!strcmp(key, "device_type") || !strcmp(key, "deviceType")) && conf >= groups[idx].device_type_conf) {
            snprintf(groups[idx].device_type, sizeof(groups[idx].device_type), "%s", val);
            groups[idx].device_type_conf = conf;
        }
    }
    sqlite3_finalize(st);

    for (i = 0; i < group_count; i++) {
        int group_score;
        db_clean_signal_device_name(groups[i].friendly, groups[i].model, name, sizeof(name));
        if (!db_signal_name_specific_enough(name))
            continue;
        group_score = groups[i].best_conf;
        if (groups[i].friendly[0] && groups[i].model[0])
            group_score += 10;
        else if (groups[i].friendly[0])
            group_score += 5;
        if (groups[i].manufacturer[0])
            group_score += 2;
        if (!strcmp(groups[i].source, "ssdp") || !strcmp(groups[i].source, "route-downstream-http"))
            group_score += 3;
        if (group_score > selected_score) {
            selected_score = group_score;
            snprintf(selected_name, sizeof(selected_name), "%s", name);
            snprintf(selected_manufacturer, sizeof(selected_manufacturer), "%s", groups[i].manufacturer);
            snprintf(selected_type, sizeof(selected_type), "%s", groups[i].device_type);
        }
    }

    if (!selected_name[0])
        return 0;
    snprintf(best_name, name_len, "%s", selected_name);
    if (selected_manufacturer[0] && best_vendor && vendor_len)
        snprintf(best_vendor, vendor_len, "%s", db_vendor_from_evidence(selected_manufacturer)[0] ? db_vendor_from_evidence(selected_manufacturer) : selected_manufacturer);
    if (best_type && type_len && !strcmp(best_type, "unknown")) {
        if (selected_type[0])
            snprintf(best_type, type_len, "%s", selected_type);
        else if (selected_manufacturer[0] && strstr(selected_manufacturer, "Synology"))
            snprintf(best_type, type_len, "%s", "nas");
    }
    if (*score < 96)
        *score = 96;
    if (source && source_len)
        snprintf(source, source_len, "%s", "signal-specific-name");
    return 1;
}

static void db_apply_vendor_family_hint(const char *vendor, char *best_name, size_t name_len, char *best_vendor, size_t vendor_len, char *best_type, size_t type_len, int *score, char *source, size_t source_len)
{
    char v[128];
    if (!vendor || !vendor[0]) return;
    db_lower_ascii_copy(v, sizeof(v), vendor);
    if (strstr(v, "synology")) {
        if (best_name && !best_name[0]) snprintf(best_name, name_len, "%s", "Synology NAS");
        if (best_vendor) snprintf(best_vendor, vendor_len, "%s", "Synology");
        if (best_type) snprintf(best_type, type_len, "%s", "nas");
        if (score && *score < 78) *score = 78;
        if (source) snprintf(source, source_len, "%s", "vendor-family");
    } else if (strstr(v, "xiaomi")) {
        if (best_name && !best_name[0]) snprintf(best_name, name_len, "%s", "Xiaomi Router");
        if (best_vendor) snprintf(best_vendor, vendor_len, "%s", "Xiaomi");
        if (best_type && !strcmp(best_type, "unknown")) snprintf(best_type, type_len, "%s", "router");
        if (score && *score < 58) *score = 58;
        if (source) snprintf(source, source_len, "%s", "vendor-family");
    }
}

static void db_apply_generic_catalog_hint(char *best_name, size_t name_len, const char *best_vendor, const char *best_type)
{
    char n[256], v[128], t[64];
    if (!best_name) return;
    db_lower_ascii_copy(n, sizeof(n), best_name);
    db_lower_ascii_copy(v, sizeof(v), best_vendor);
    db_lower_ascii_copy(t, sizeof(t), best_type);
    if (strstr(v, "synology") && (strstr(t, "nas") || !best_name[0]))
        snprintf(best_name, name_len, "%s", "Synology NAS");
    else if (strstr(v, "xiaomi") && (strstr(t, "router") || !best_name[0]))
        snprintf(best_name, name_len, "%s", "Xiaomi Router");
    else if (strstr(v, "apple") && strstr(t, "smartphone") && (!strcmp(n, "iphone") || !best_name[0]))
        snprintf(best_name, name_len, "%s", "Apple iPhone");
    else if (strstr(v, "apple") && strstr(t, "tablet") && (!strcmp(n, "ipad") || !best_name[0]))
        snprintf(best_name, name_len, "%s", "Apple iPad");
}

static int db_catalog_name_usable(const char *name)
{
    int alpha = 0, digit = 0, other = 0;
    const unsigned char *p = (const unsigned char *)name;
    if (!name || !name[0]) return 0;
    while (*p) {
        if (isalpha(*p)) alpha++;
        else if (isdigit(*p)) digit++;
        else if (!isspace(*p) && *p != '-' && *p != '_' && *p != '.') other++;
        p++;
    }
    if (alpha + digit + other < 3) return 0;
    if (alpha == 0 && other == 0) return 0;
    if (alpha == 1 && digit == 0 && other == 0) return 0;
    return 1;
}

static int db_catalog_model_token(const char *name)
{
    const unsigned char *p = (const unsigned char *)name;
    int alpha = 0, digit = 0;
    if (!name || !name[0]) return 0;
    while (*p) {
        if (isalpha(*p)) alpha++;
        else if (isdigit(*p)) digit++;
        p++;
    }
    return alpha > 0 && digit > 0 && strlen(name) >= 4;
}

static int db_catalog_match_quality(const char *observed, const char *catalog)
{
    char a[256], b[256];
    size_t alen, blen;
    if (!db_catalog_name_usable(observed) || !db_catalog_name_usable(catalog)) return 0;
    db_lower_ascii_copy(a, sizeof(a), observed);
    db_lower_ascii_copy(b, sizeof(b), catalog);
    alen = strlen(a);
    blen = strlen(b);
    if (!alen || !blen) return 0;
    if (!strcmp(a, b)) return 100;
    if (db_catalog_model_token(a) && strstr(b, a)) return 92;
    if (alen < 6 || blen < 6) return 0;
    if (strstr(a, b) || strstr(b, a)) return 60;
    return 0;
}

static int db_lookup_catalog_family_image(const char *vendor, const char *type,
                                          char *out, size_t out_len)
{
    sqlite3_stmt *st = NULL;
    int rc = 0;

    if (!out || out_len == 0)
        return 0;
    out[0] = '\0';
    if (!vendor || !vendor[0] || !type || !type[0])
        return 0;
    if (db_prepare(&st,
        "SELECT COALESCE(best_image,'') FROM fingerprint_devices "
        "WHERE best_image IS NOT NULL AND best_image!='' "
        "AND lower(vendor_name) LIKE '%'||lower(?1)||'%' "
        "AND lower(device_type)=lower(?2) "
        "ORDER BY CASE "
        " WHEN lower(device_name)=lower(?1||' '||?2) THEN 0 "
        " WHEN lower(device_name) LIKE lower(?1||' %') THEN 1 "
        " ELSE 2 END, length(device_name) ASC LIMIT 1") != 0)
        return 0;
    sqlite3_bind_text(st, 1, vendor, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, type, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *image = (const char *)sqlite3_column_text(st, 0);

        if (image && image[0]) {
            snprintf(out, out_len, "%s", image);
            rc = 1;
        }
    }
    sqlite3_finalize(st);
    return rc;
}

static void db_normalize_catalog_type(char *out, size_t out_len, const char *type, const char *family)
{
    char t[128], f[128];
    if (!out || !out_len) return;
    out[0] = '\0';
    db_lower_ascii_copy(t, sizeof(t), type);
    db_lower_ascii_copy(f, sizeof(f), family);
    if (strstr(t, "smartphone") || strstr(f, "smartphone")) snprintf(out, out_len, "%s", "smartphone");
    else if (strstr(t, "tablet") || strstr(f, "tablet")) snprintf(out, out_len, "%s", "tablet");
    else if (strstr(t, "router") || strstr(f, "router")) snprintf(out, out_len, "%s", "router");
    else if (strstr(t, "nas") || strstr(f, "nas")) snprintf(out, out_len, "%s", "nas");
    else if (strstr(t, "printer") || strstr(f, "printer")) snprintf(out, out_len, "%s", "printer");
    else if (strstr(t, "camera") || strstr(f, "camera")) snprintf(out, out_len, "%s", "camera");
    else if (strstr(t, "computer") || strstr(f, "computer") || strstr(t, "laptop") || strstr(f, "laptop")) snprintf(out, out_len, "%s", "computer");
    else if (strstr(t, "tv") || strstr(f, "tv") || strstr(t, "media") || strstr(f, "media")) snprintf(out, out_len, "%s", "tv");
    else if (strstr(t, "handheld") && f[0]) snprintf(out, out_len, "%s", f);
    else if (type && type[0]) snprintf(out, out_len, "%s", type);
    else if (family && family[0]) snprintf(out, out_len, "%s", family);
}

static void db_normalize_catalog_vendor(char *out, size_t out_len, const char *vendor)
{
    char v[160];
    if (!out || !out_len) return;
    out[0] = '\0';
    if (!vendor || !vendor[0]) return;
    db_lower_ascii_copy(v, sizeof(v), vendor);
    if (strstr(v, "apple")) snprintf(out, out_len, "%s", "Apple");
    else if (strstr(v, "synology")) snprintf(out, out_len, "%s", "Synology");
    else if (strstr(v, "xiaomi") || strstr(v, "redmi") || strstr(v, "beijing xiaomi")) snprintf(out, out_len, "%s", "Xiaomi");
    else if (strstr(v, "ubiquiti") || strstr(v, "unifi")) snprintf(out, out_len, "%s", "Ubiquiti");
    else if (strstr(v, "tp-link") || strstr(v, "tplink")) snprintf(out, out_len, "%s", "TP-Link");
    else if (strstr(v, "asustek") || strstr(v, "asus")) snprintf(out, out_len, "%s", "ASUS");
    else snprintf(out, out_len, "%s", vendor);
}

static void db_normalize_catalog_image(char *out, size_t out_len, const char *image)
{
    const char *p;
    if (!out || !out_len) return;
    out[0] = '\0';
    if (!image || !image[0]) return;
    if (!strncmp(image, "/luci-static/", 13) || strstr(image, "://")) {
        snprintf(out, out_len, "%s", image);
        return;
    }
    p = strstr(image, "fingerprint/engine-");
    if (p) {
        snprintf(out, out_len, "/luci-static/dreamingwrt/fingerprint/images/%s", p + strlen("fingerprint/"));
        return;
    }
    p = strstr(image, "fingerprint/vendors/");
    if (p) {
        snprintf(out, out_len, "/luci-static/dreamingwrt/fingerprint/images/%s", p + strlen("fingerprint/"));
        return;
    }
    snprintf(out, out_len, "%s", image);
}

static int db_prepare(sqlite3_stmt **st, const char *sql)
{
    int rc = sqlite3_prepare_v2(g_db, sql, -1, st, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("sqlite prepare failed rc=%d err=%s sql=%s\n", rc, sqlite3_errmsg(g_db), sql);
        return -1;
    }
    return 0;
}

static int db_step_done(sqlite3_stmt *st)
{
    int rc = sqlite3_step(st);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("sqlite step failed rc=%d err=%s\n", rc, sqlite3_errmsg(g_db));
        return -1;
    }
    return 0;
}

static const char *db_json_string_def(struct json_object *obj, const char *key,
                                      const char *def)
{
    struct json_object *v = NULL;

    if (!obj || !key || !json_object_object_get_ex(obj, key, &v) || !v)
        return def;
    return json_object_get_string(v);
}

static void bind_text_or_null(sqlite3_stmt *st, int idx, const char *v)
{
    char safe[1024];

    db_safe_text_copy(safe, sizeof(safe), v);
    if (safe[0]) sqlite3_bind_text(st, idx, safe, -1, SQLITE_TRANSIENT);
    else sqlite3_bind_null(st, idx);
}

static int64_t db_client_id_by_mac(const char *mac)
{
    sqlite3_stmt *st = NULL;
    int64_t id = 0;
    if (db_prepare(&st, "SELECT client_id FROM clients WHERE mac=?1") != 0) return 0;
    sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        id = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return id;
}

static int db_upsert_client(const char *mac, const char *hostname, const char *display_name,
                            const char *vendor, const char *oui, const char *device_type,
                            const char *os_name, int is_wired, int64_t seen_ts, int64_t *client_id)
{
    sqlite3_stmt *st = NULL;
    int64_t ts = now_s();
    const char *sql =
        "INSERT INTO clients(mac,hostname,display_name,vendor,oui,device_type,os_name,is_wired,first_seen,last_seen,created_at,updated_at) "
        "VALUES(?1,NULLIF(?2,''),NULLIF(?3,''),NULLIF(?4,''),NULLIF(?5,''),NULLIF(?6,''),NULLIF(?7,''),?8,?9,?10,?11,?12) "
        "ON CONFLICT(mac) DO UPDATE SET "
        "hostname=COALESCE(NULLIF(excluded.hostname,''), clients.hostname), "
        "display_name=COALESCE(NULLIF(excluded.display_name,''), clients.display_name), "
        "vendor=CASE WHEN excluded.vendor IS NOT NULL AND excluded.vendor!='' AND (clients.vendor IS NULL OR clients.vendor='') THEN excluded.vendor ELSE clients.vendor END, "
        "oui=COALESCE(NULLIF(excluded.oui,''), clients.oui), "
        "device_type=CASE WHEN excluded.device_type IS NOT NULL AND excluded.device_type!='' AND excluded.device_type!='unknown' THEN excluded.device_type ELSE clients.device_type END, "
        "os_name=COALESCE(NULLIF(excluded.os_name,''), clients.os_name), "
        "is_wired=excluded.is_wired, last_seen=excluded.last_seen, updated_at=excluded.updated_at";
    if (!mac || !mac[0]) return -1;
    if (seen_ts <= 0) seen_ts = ts;
    if (db_prepare(&st, sql) != 0) return -1;
    sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
    bind_text_or_null(st, 2, hostname);
    bind_text_or_null(st, 3, display_name && display_name[0] ? display_name : hostname);
    bind_text_or_null(st, 4, vendor);
    bind_text_or_null(st, 5, oui);
    bind_text_or_null(st, 6, device_type && device_type[0] ? device_type : "unknown");
    bind_text_or_null(st, 7, os_name);
    sqlite3_bind_int(st, 8, is_wired ? 1 : 0);
    sqlite3_bind_int64(st, 9, seen_ts);
    sqlite3_bind_int64(st, 10, seen_ts);
    sqlite3_bind_int64(st, 11, ts);
    sqlite3_bind_int64(st, 12, ts);
    if (db_step_done(st) != 0) { sqlite3_finalize(st); return -1; }
    sqlite3_finalize(st);
    if (client_id) *client_id = db_client_id_by_mac(mac);
    return 0;
}

static int db_upsert_alias(int64_t client_id, const char *type, const char *value, const char *source, double conf, int64_t seen_ts)
{
    sqlite3_stmt *st = NULL;
    int64_t ts = now_s();
    const char *sql =
        "INSERT INTO client_aliases(client_id,alias_type,alias_value,source,confidence,first_seen,last_seen,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) "
        "ON CONFLICT(client_id,alias_type,alias_value,source) DO UPDATE SET "
        "confidence=excluded.confidence,last_seen=excluded.last_seen,updated_at=excluded.updated_at";
    if (client_id <= 0 || !type || !value || !value[0] || !source) return 0;
    if (seen_ts <= 0) seen_ts = ts;
    if (db_prepare(&st, sql) != 0) return -1;
    sqlite3_bind_int64(st, 1, client_id);
    sqlite3_bind_text(st, 2, type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, value, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, source, -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(st, 5, conf);
    sqlite3_bind_int64(st, 6, seen_ts);
    sqlite3_bind_int64(st, 7, seen_ts);
    sqlite3_bind_int64(st, 8, ts);
    sqlite3_bind_int64(st, 9, ts);
    int ret = db_step_done(st);
    sqlite3_finalize(st);
    return ret;
}
static int db_upsert_identity_signal(const char *mac, const char *source, const char *key, const char *value, int confidence, const char *raw_json, int64_t seen_ts)
{
    sqlite3_stmt *st = NULL;
    char safe_value[1024];
    char safe_raw[1024];
    if (!mac || !mac[0] || !source || !source[0] || !key || !key[0] || !value || !value[0]) return -1;
    db_safe_text_copy(safe_value, sizeof(safe_value), value);
    db_safe_text_copy(safe_raw, sizeof(safe_raw), raw_json ? raw_json : "");
    if (!safe_value[0]) return -1;
    if (db_prepare(&st, "INSERT INTO client_identity_signals(mac,source,key,value,confidence,first_seen,last_seen,raw_json) VALUES(?1,?2,?3,?4,?5,?6,?7,NULLIF(?8,'')) ON CONFLICT(mac,source,key,value) DO UPDATE SET confidence=excluded.confidence,last_seen=excluded.last_seen,raw_json=COALESCE(excluded.raw_json,client_identity_signals.raw_json)") != 0)
        return -1;
    sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, source, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, safe_value, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 5, confidence);
    sqlite3_bind_int64(st, 6, seen_ts);
    sqlite3_bind_int64(st, 7, seen_ts);
    bind_text_or_null(st, 8, safe_raw);
    int ret = db_step_done(st);
    sqlite3_finalize(st);
    return ret;
}

static int db_upsert_identity_override(const char *mac, struct json_object *req)
{
    sqlite3_stmt *st = NULL;
    int64_t ts = now_s();
    const char *sql =
        "INSERT INTO client_identity_overrides(mac,nickname,engine,device_id,device_name,vendor_name,device_type,custom_image_path,note,updated_at) "
        "VALUES(?1,NULLIF(?2,''),?3,?4,NULLIF(?5,''),NULLIF(?6,''),NULLIF(?7,''),NULLIF(?8,''),NULLIF(?9,''),?10) "
        "ON CONFLICT(mac) DO UPDATE SET "
        "nickname=CASE WHEN ?11 THEN excluded.nickname ELSE client_identity_overrides.nickname END,"
        "engine=CASE WHEN ?12 THEN excluded.engine ELSE client_identity_overrides.engine END,"
        "device_id=CASE WHEN ?13 THEN excluded.device_id ELSE client_identity_overrides.device_id END,"
        "device_name=CASE WHEN ?14 THEN excluded.device_name ELSE client_identity_overrides.device_name END,"
        "vendor_name=CASE WHEN ?15 THEN excluded.vendor_name ELSE client_identity_overrides.vendor_name END,"
        "device_type=CASE WHEN ?16 THEN excluded.device_type ELSE client_identity_overrides.device_type END,"
        "custom_image_path=CASE WHEN ?17 THEN excluded.custom_image_path ELSE client_identity_overrides.custom_image_path END,"
        "note=CASE WHEN ?18 THEN excluded.note ELSE client_identity_overrides.note END,"
        "updated_at=excluded.updated_at";
    if (db_prepare(&st, sql) != 0)
        return -1;
    sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
    bind_text_or_null(st, 2, json_s(req, "nickname", json_s(req, "custom_name", "")));
    sqlite3_bind_int(st, 3, json_i(req, "engine", 0));
    sqlite3_bind_int(st, 4, json_i(req, "device_id", 0));
    bind_text_or_null(st, 5, json_s(req, "device_name", ""));
    bind_text_or_null(st, 6, json_s(req, "vendor_name", json_s(req, "custom_vendor", "")));
    bind_text_or_null(st, 7, json_s(req, "device_type", json_s(req, "custom_device_type", "")));
    bind_text_or_null(st, 8, json_s(req, "custom_image_path", json_s(req, "custom_icon", "")));
    bind_text_or_null(st, 9, json_s(req, "note", ""));
    sqlite3_bind_int64(st, 10, ts);
    sqlite3_bind_int(st, 11, db_json_has_any_key(req, "nickname", "custom_name"));
    sqlite3_bind_int(st, 12, db_json_has_key(req, "engine"));
    sqlite3_bind_int(st, 13, db_json_has_key(req, "device_id"));
    sqlite3_bind_int(st, 14, db_json_has_key(req, "device_name"));
    sqlite3_bind_int(st, 15, db_json_has_any_key(req, "vendor_name", "custom_vendor"));
    sqlite3_bind_int(st, 16, db_json_has_any_key(req, "device_type", "custom_device_type"));
    sqlite3_bind_int(st, 17, db_json_has_any_key(req, "custom_image_path", "custom_icon"));
    sqlite3_bind_int(st, 18, db_json_has_key(req, "note"));
    int ret = db_step_done(st);
    sqlite3_finalize(st);
    return ret;
}

static int db_upsert_network_state(int64_t client_id, struct json_object *ns)
{
    sqlite3_stmt *st = NULL;
    int64_t ts = now_s();
    struct json_object *ipv6 = NULL;
    const char *ipv6_json = "[]";
    const char *sql =
        "INSERT INTO client_network_state(client_id,ip,ipv6_json,interface,network,ssid,parent_mac,parent_id,port,link_type,link_speed,signal,tx_rate,rx_rate,tx_bytes,rx_bytes,connections,online,updated_at) "
        "VALUES(?1,NULLIF(?2,''),?3,NULLIF(?4,''),NULLIF(?5,''),NULLIF(?6,''),NULLIF(?7,''),NULLIF(?8,''),NULLIF(?9,''),NULLIF(?10,''),NULLIF(?11,''),?12,?13,?14,?15,?16,?17,?18,?19) "
        "ON CONFLICT(client_id) DO UPDATE SET "
        "ip=COALESCE(excluded.ip,client_network_state.ip),"
        "ipv6_json=CASE WHEN excluded.ipv6_json IS NOT NULL AND excluded.ipv6_json!='[]' AND excluded.ipv6_json!='{}' THEN excluded.ipv6_json ELSE client_network_state.ipv6_json END,"
        "interface=COALESCE(excluded.interface,client_network_state.interface),"
        "network=COALESCE(excluded.network,client_network_state.network),"
        "ssid=COALESCE(excluded.ssid,client_network_state.ssid),"
        "parent_mac=COALESCE(excluded.parent_mac,client_network_state.parent_mac),"
        "parent_id=COALESCE(excluded.parent_id,client_network_state.parent_id),"
        "port=COALESCE(excluded.port,client_network_state.port),"
        "link_type=CASE WHEN excluded.link_type IS NOT NULL AND excluded.link_type!='unknown' THEN excluded.link_type ELSE client_network_state.link_type END,"
        "link_speed=COALESCE(excluded.link_speed,client_network_state.link_speed),"
        "signal=excluded.signal,tx_rate=excluded.tx_rate,rx_rate=excluded.rx_rate,tx_bytes=excluded.tx_bytes,rx_bytes=excluded.rx_bytes,connections=excluded.connections,online=excluded.online,updated_at=excluded.updated_at";
    if (client_id <= 0 || !ns) return 0;
    if (json_object_object_get_ex(ns, "ipv6", &ipv6) && ipv6)
        ipv6_json = json_object_to_json_string(ipv6);
    if (db_prepare(&st, sql) != 0) return -1;
    sqlite3_bind_int64(st, 1, client_id);
    /* Bind the 0.0.0.0 sentinel as NULL, not as a value. bind_text_or_null only
     * screens the empty string, so the placeholder used to be stored as a real
     * address and then pinned there forever by the COALESCE above: once written,
     * no later observation could clear it, because a client with no IPv4 never
     * supplies a replacement. An IPv6-only client is the case that exposed this. */
    bind_text_or_null(st, 2, db_ipv4_usable(json_s(ns, "ip", "")) ?
                             json_s(ns, "ip", "") : "");
    sqlite3_bind_text(st, 3, ipv6_json, -1, SQLITE_TRANSIENT);
    bind_text_or_null(st, 4, json_s(ns, "interface", ""));
    bind_text_or_null(st, 5, json_s(ns, "network", ""));
    bind_text_or_null(st, 6, json_s(ns, "ssid", ""));
    bind_text_or_null(st, 7, json_s(ns, "parent_mac", ""));
    bind_text_or_null(st, 8, json_s(ns, "parent_id", ""));
    bind_text_or_null(st, 9, json_s(ns, "port", ""));
    bind_text_or_null(st, 10, json_s(ns, "link_type", "unknown"));
    bind_text_or_null(st, 11, json_s(ns, "link_speed", ""));
    sqlite3_bind_int(st, 12, json_i(ns, "signal", 0));
    sqlite3_bind_int64(st, 13, json_i64(ns, "tx_rate", 0));
    sqlite3_bind_int64(st, 14, json_i64(ns, "rx_rate", 0));
    sqlite3_bind_int64(st, 15, json_i64(ns, "tx_bytes", 0));
    sqlite3_bind_int64(st, 16, json_i64(ns, "rx_bytes", 0));
    sqlite3_bind_int(st, 17, json_i(ns, "connections", 0));
    sqlite3_bind_int(st, 18, json_i(ns, "online", 0));
    sqlite3_bind_int64(st, 19, ts);
    int ret = db_step_done(st);
    sqlite3_finalize(st);
    return ret;
}

int jmx_db_observe_network_state(const char *mac_in, const char *ip, const char *iface,
                                 const char *network, const char *parent_mac,
                                 const char *parent_id, const char *port,
                                 const char *link_type, const char *link_speed,
                                 int online)
{
    char mac[MAX_MAC_LEN] = {0};
    struct json_object *ns = NULL;
    int64_t cid = 0;
    int rc = -1;

    if (jmx_db_init() != 0 || normalize_mac(mac_in, mac, sizeof(mac)) != 0)
        return -1;
    if (db_begin() != 0)
        return -1;
    if (db_upsert_client(mac, "", "", "", "", "unknown", "", 0, now_s(), &cid) != 0 ||
        cid <= 0)
        goto out;
    ns = json_object_new_object();
    if (!ns)
        goto out;
    json_object_object_add(ns, "ip", json_object_new_string(ip ? ip : ""));
    json_object_object_add(ns, "interface", json_object_new_string(iface ? iface : ""));
    json_object_object_add(ns, "network", json_object_new_string((network && network[0]) ? network : "lan"));
    json_object_object_add(ns, "parent_mac", json_object_new_string(parent_mac ? parent_mac : ""));
    json_object_object_add(ns, "parent_id", json_object_new_string(parent_id ? parent_id : ""));
    json_object_object_add(ns, "port", json_object_new_string(port ? port : ""));
    json_object_object_add(ns, "link_type", json_object_new_string((link_type && link_type[0]) ? link_type : "wired"));
    json_object_object_add(ns, "link_speed", json_object_new_string(link_speed ? link_speed : ""));
    json_object_object_add(ns, "online", json_object_new_int(online ? 1 : 0));
    rc = db_upsert_network_state(cid, ns);
out:
    if (ns)
        json_object_put(ns);
    if (rc == 0)
        rc = db_commit();
    else
        db_rollback();
    return rc;
}

static const char *db_device_type_from_evidence(const char *key, const char *value)
{
    char v[256]; size_t i;
    if (!value) return "unknown";
    snprintf(v, sizeof(v), "%s", value);
    for (i = 0; v[i]; i++) v[i] = (char)tolower((unsigned char)v[i]);

    /* Router / gateway: iKuaiOS, OpenWrt, routerOS, internetgatewaydevice */
    if (strstr(v, "ikuaios") || strstr(v, "ikuai")) return "router";
    if (strstr(v, "openwrt") || strstr(v, "lede")) return "router";
    if (strstr(v, "routeros") || strstr(v, "mikrotik")) return "router";
    if (strstr(v, "pfsense") || strstr(v, "opnsense") || strstr(v, "vyos")) return "router";
    if (key && !strcmp(key, "deviceType") && strstr(v, "internetgatewaydevice")) return "router";

    /* Hypervisor / virtualization host */
    if (strstr(v, "proxmox") || strstr(v, "pve") || strstr(v, "ve-server")) return "hypervisor";
    if (strstr(v, "esxi") || strstr(v, "vmware esxi")) return "hypervisor";
    if (strstr(v, "qemu") || strstr(v, "kvm")) return "hypervisor";

    /* NAS */
    if (strstr(v, "nas") || strstr(v, "synology") || strstr(v, "qnap") || strstr(v, "truenas") || strstr(v, "unraid")) return "nas";

    /* End-user devices */
    if (strstr(v, "iphone") || strstr(v, "android") || strstr(v, "phone")) return "smartphone";
    if (strstr(v, "ipad") || strstr(v, "tablet")) return "tablet";
    if (strstr(v, "mac14,") || strstr(v, "macbook") || strstr(v, "imac") || strstr(v, "windows") || strstr(v, "pc") || strstr(v, "computer")) return "computer";
    if (strstr(v, "tv") || strstr(v, "television") || strstr(v, "mediarenderer") || strstr(v, "googlecast") || strstr(v, "airplay")) return "tv";
    if (strstr(v, "printer") || strstr(v, "ipp")) return "printer";
    if (strstr(v, "camera") || strstr(v, "webcam")) return "camera";
    if (strstr(v, "xbox") || strstr(v, "playstation") || strstr(v, "ps5") || strstr(v, "nintendo")) return "game_console";
    if (strstr(v, "miaisoundbox") || strstr(v, "mi ai soundbox") || strstr(v, "soundbox") || strstr(v, "speaker") || strstr(v, "lx06")) return "iot";

    /* SSDP server header: iKuaiOS/xxx → router */
    if (key && (!strcmp(key, "server") || !strcmp(key, "modelName") || !strcmp(key, "manufacturer") || !strcmp(key, "friendlyName"))) {
        if (strstr(v, "ikuai")) return "router";
    }

    return "unknown";
}

static const char *db_vendor_from_evidence(const char *value)
{
    char v[256]; size_t i;
    if (!value) return "";
    snprintf(v, sizeof(v), "%s", value);
    for (i = 0; v[i]; i++) v[i] = (char)tolower((unsigned char)v[i]);

    /* Network / router vendors */
    if (strstr(v, "ikuaios") || strstr(v, "ikuai")) return "iKuaiOS";
    if (strstr(v, "mikrotik") || strstr(v, "routeros")) return "MikroTik";
    if (strstr(v, "openwrt") || strstr(v, "lede")) return "OpenWrt";
    if (strstr(v, "pfsense")) return "pfSense";
    if (strstr(v, "opnsense")) return "OPNsense";
    if (strstr(v, "ubiquiti") || strstr(v, "unifi")) return "Ubiquiti";
    if (strstr(v, "tp-link") || strstr(v, "tplink")) return "TP-Link";
    if (strstr(v, "netgear")) return "Netgear";
    if (strstr(v, "asus")) return "ASUS";
    if (strstr(v, "linksys")) return "Linksys";
    if (strstr(v, "tenda")) return "Tenda";
    if (strstr(v, "ruijie") || strstr(v, "reyee")) return "Ruijie";

    /* Virtualization / hypervisor */
    if (strstr(v, "proxmox") || strstr(v, "pve")) return "Proxmox";
    if (strstr(v, "vmware") || strstr(v, "esxi")) return "VMware";
    if (strstr(v, "qemu") || strstr(v, "kvm")) return "QEMU/KVM";

    /* NAS */
    if (strstr(v, "synology")) return "Synology";
    if (strstr(v, "qnap")) return "QNAP";
    if (strstr(v, "truenas") || strstr(v, "freenas")) return "TrueNAS";
    if (strstr(v, "unraid")) return "Unraid";

    /* Consumer electronics */
    if (strstr(v, "apple") || strstr(v, "iphone") || strstr(v, "ipad") || strstr(v, "macbook") || strstr(v, "imac") || strstr(v, "mac14,")) return "Apple";
    if (strstr(v, "samsung")) return "Samsung";
    if (strstr(v, "xiaomi") || strstr(v, "redmi") || strstr(v, "mi ")) return "Xiaomi";
    if (strstr(v, "huawei") || strstr(v, "honor")) return "Huawei";
    if (strstr(v, "sony") || strstr(v, "playstation")) return "Sony";
    if (strstr(v, "microsoft") || strstr(v, "xbox")) return "Microsoft";
    if (strstr(v, "google") || strstr(v, "chromecast")) return "Google";
    if (strstr(v, "amazon") || strstr(v, "alexa") || strstr(v, "echo")) return "Amazon";
    if (strstr(v, "roku")) return "Roku";
    if (strstr(v, "lg")) return "LG";
    if (strstr(v, "hisense")) return "Hisense";

    return "";
}

static void db_json_add_signal(struct json_object *arr, const char *source, const char *key, const char *value, int conf)
{
    struct json_object *o = json_object_new_object();
    char safe_source[128], safe_key[128], safe_value[1024];

    db_safe_text_copy(safe_source, sizeof(safe_source), source);
    db_safe_text_copy(safe_key, sizeof(safe_key), key);
    db_safe_text_copy(safe_value, sizeof(safe_value), value);
    json_object_object_add(o, "source", json_object_new_string(safe_source));
    json_object_object_add(o, "key", json_object_new_string(safe_key));
    json_object_object_add(o, "value", json_object_new_string(safe_value));
    json_object_object_add(o, "confidence", json_object_new_int(conf));
    json_object_array_add(arr, o);
}

static int db_apply_identity_aggregator(const char *mac);

static int db_insert_candidate(const char *mac, int engine, int device_id, const char *device_name, const char *vendor_name, const char *source, int score, struct json_object *evidence)
{
    sqlite3_stmt *st = NULL;
    int64_t ts = now_s();
    const char *ej = evidence ? json_object_to_json_string(evidence) : "[]";
    /* Keep only latest 3 candidates per mac (prevent unbounded growth) */
    (void)mac; (void)engine; (void)device_id; (void)device_name; (void)vendor_name; (void)source; (void)score; (void)ej; (void)ts; return 0; /* candidates removed */
}

static const char *db_type_from_vendor(const char *vendor)
{
    char v[256]; size_t i;
    if (!vendor || !vendor[0]) return "unknown";
    snprintf(v, sizeof(v), "%s", vendor);
    for (i = 0; v[i]; i++) v[i] = (char)tolower((unsigned char)v[i]);
    /* NAS */
    if (strstr(v, "synology") || strstr(v, "qnap") || strstr(v, "truenas") || strstr(v, "unraid") || strstr(v, "western digital") || strstr(v, "wd ")) return "nas";
    /* Routers / Networking */
    if (strstr(v, "ubiquiti") || strstr(v, "unifi") || strstr(v, "mikrotik") || strstr(v, "routeros")) return "router";
    if (strstr(v, "tp-link") || strstr(v, "netgear") || strstr(v, "asus") || strstr(v, "linksys") || strstr(v, "tenda") || strstr(v, "ruijie")) return "router";
    if (strstr(v, "openwrt") || strstr(v, "ikuai") || strstr(v, "ikuaios") || strstr(v, "pfsense") || strstr(v, "opnsense")) return "router";
    if (strstr(v, "proxmox") || strstr(v, "vmware") || strstr(v, "qemu") || strstr(v, "kvm")) return "hypervisor";
    /* Smartphones */
    if (strstr(v, "iphone") || strstr(v, "samsung mobile") || strstr(v, "huawei device") ||
        strstr(v, "oppo") || strstr(v, "vivo") || strstr(v, "oneplus") || strstr(v, "realme") || strstr(v, "motorola") ||
        strstr(v, "nokia") || strstr(v, "sony") || strstr(v, "lg electronics") || strstr(v, "google") || strstr(v, "pixel"))
        return "smartphone";
    /* Tablets */
    if (strstr(v, "ipad")) return "tablet";
    /* Computers */
    if (strstr(v, "intel") || strstr(v, "amd") || strstr(v, "lenovo") || strstr(v, "dell") || strstr(v, "hp inc") ||
        strstr(v, "microsoft") || strstr(v, "razer") || strstr(v, "corsair") || strstr(v, "gigabyte") || strstr(v, "msi") ||
        strstr(v, "asustek")) return "computer";
    /* TVs / Media */
    if (strstr(v, "roku") || strstr(v, "chromecast") || strstr(v, "fire tv") || strstr(v, "tcl") || strstr(v, "hisense") ||
        strstr(v, "sonos") || strstr(v, "bose") || strstr(v, "harman") || strstr(v, "jbl") || strstr(v, "marshall"))
        return "tv";
    /* IoT / Smart Home */
    if (strstr(v, "yeelight") || strstr(v, "aqara") || strstr(v, "tuya") || strstr(v, "philips hue") ||
        strstr(v, "ikea") || strstr(v, "wiz") || strstr(v, "gosund") || strstr(v, "chunmi") || strstr(v, "dreame") ||
        strstr(v, "roborock") || strstr(v, "ecovacs") || strstr(v, "switchbot") || strstr(v, "shelly") || strstr(v, "sonoff") ||
        strstr(v, "zigbee") || strstr(v, "z-wave") || strstr(v, "matter"))
        return "iot";
    /* Printers */
    if (strstr(v, "canon") || strstr(v, "epson") || strstr(v, "brother") || strstr(v, "xerox") || strstr(v, "ricoh") ||
        strstr(v, "lexmark") || strstr(v, "kyocera"))
        return "printer";
    /* Cameras */
    if (strstr(v, "hikvision") || strstr(v, "dahua") || strstr(v, "reolink") || strstr(v, "amcrest") || strstr(v, "wyze") ||
        strstr(v, "arlo") || strstr(v, "ring") || strstr(v, "nest") || strstr(v, "eufy"))
        return "camera";
    /* Game Consoles */
    if (strstr(v, "nintendo") || strstr(v, "sony interactive") || strstr(v, "microsoft xbox"))
        return "game_console";
    return "unknown";
}

static int db_write_chosen_fingerprint(const char *mac, const char *device_name, const char *vendor_name, const char *device_type, const char *image_path, const char *source, int confidence, struct json_object *evidence)
{
    sqlite3_stmt *st = NULL;
    int64_t ts = now_s();
    const char *ej = evidence ? json_object_to_json_string(evidence) : "[]";
    char safe_evidence[8192];
    db_safe_text_copy(safe_evidence, sizeof(safe_evidence), ej);
    if (db_prepare(&st, "INSERT OR REPLACE INTO client_fingerprints(mac,engine,device_id,vendor_id,device_name,vendor_name,device_type,family,os_class,os_name,image_path,source,confidence,evidence_json,updated_at) VALUES(?1,0,0,0,NULLIF(?2,''),NULLIF(?3,''),NULLIF(?4,''),'','','',NULLIF(?5,''),?6,?7,?8,?9)") != 0)
        return -1;
    sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
    bind_text_or_null(st, 2, device_name);
    bind_text_or_null(st, 3, vendor_name);
    bind_text_or_null(st, 4, device_type);
    bind_text_or_null(st, 5, image_path);
    sqlite3_bind_text(st, 6, source ? source : "aggregator", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 7, confidence);
    sqlite3_bind_text(st, 8, safe_evidence, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 9, ts);
    int ret = db_step_done(st);
    sqlite3_finalize(st);
    return ret;
}
static int db_meta_get_i64(const char *key, int64_t *value)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;
    if (db_prepare(&st, "SELECT value FROM db_meta WHERE key=?1") != 0) return -1;
    sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) { if (value) *value = atoll((const char *)sqlite3_column_text(st, 0)); rc = 0; }
    sqlite3_finalize(st);
    return rc;
}

static int db_meta_get_text(const char *key, char *value, size_t value_len)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!value || value_len == 0)
        return -1;
    value[0] = '\0';
    if (db_prepare(&st, "SELECT value FROM db_meta WHERE key=?1") != 0)
        return -1;
    sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_text(st, 0)) {
        snprintf(value, value_len, "%s", (const char *)sqlite3_column_text(st, 0));
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

static void db_meta_set_text(const char *key, const char *value)
{
    sqlite3_stmt *st = NULL;

    if (db_prepare(&st, "INSERT INTO db_meta(key,value,updated_at) VALUES(?1,?2,?3) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at") != 0)
        return;
    sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, value ? value : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, now_s());
    db_step_done(st);
    sqlite3_finalize(st);
}

static int db_sha256_file(const char *path, char out[65])
{
    EVP_MD_CTX *ctx = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    unsigned char buf[64 * 1024];
    FILE *fp = NULL;
    size_t n;
    unsigned int i;
    int rc = -1;

    out[0] = '\0';
    fp = fopen(path, "rb");
    ctx = EVP_MD_CTX_new();
    if (!fp || !ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
        goto done;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
        if (EVP_DigestUpdate(ctx, buf, n) != 1)
            goto done;
    if (ferror(fp) || EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1 ||
        digest_len != 32)
        goto done;
    for (i = 0; i < digest_len; i++)
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    out[64] = '\0';
    rc = 0;
done:
    if (fp)
        fclose(fp);
    EVP_MD_CTX_free(ctx);
    return rc;
}

static int db_fingerprint_db_path(char *path, size_t path_len)
{
    enum jmx_system_db_source source;
    char error[64];

    if (jmx_system_db_resolve(JMX_SYSTEM_DB_FINGERPRINT, path, path_len,
                              &source, error, sizeof(error)) == 0)
        return 0;
    LOG_WARN("fingerprint DB resolve failed: %s\n", error);
    return -1;
}

static void db_meta_set_i64(const char *key, int64_t value)
{
    sqlite3_stmt *st = NULL;
    char buf[64];
    snprintf(buf, sizeof(buf), "%lld", (long long)value);
    if (db_prepare(&st, "INSERT INTO db_meta(key,value,updated_at) VALUES(?1,?2,?3) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at") != 0) return;
    sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, buf, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, now_s());
    db_step_done(st);
    sqlite3_finalize(st);
}

static int db_upsert_fingerprint_device_full(int engine, int device_id, int vendor_id, const char *device_name, const char *vendor_name, const char *device_type, const char *family, const char *os_class, const char *os_name, const char *best_image, const char *sizes)
{
    sqlite3_stmt *st = NULL;
    char normalized_vendor[128], normalized_type[64], normalized_image[512];
    if (!device_name || !device_name[0]) return -1;
    db_normalize_catalog_vendor(normalized_vendor, sizeof(normalized_vendor), vendor_name);
    db_normalize_catalog_type(normalized_type, sizeof(normalized_type), device_type, family);
    db_normalize_catalog_image(normalized_image, sizeof(normalized_image), best_image);
    if (db_prepare(&st, "INSERT INTO fingerprint_devices(engine,device_id,device_name,vendor_id,vendor_name,device_type,family,os_class,os_name,best_image,sizes) VALUES(?1,?2,?3,?4,NULLIF(?5,''),NULLIF(?6,''),NULLIF(?7,''),NULLIF(?8,''),NULLIF(?9,''),NULLIF(?10,''),NULLIF(?11,'')) ON CONFLICT(engine,device_id) DO UPDATE SET device_name=excluded.device_name,vendor_id=excluded.vendor_id,vendor_name=excluded.vendor_name,device_type=excluded.device_type,family=excluded.family,os_class=excluded.os_class,os_name=excluded.os_name,best_image=excluded.best_image,sizes=excluded.sizes") != 0)
        return -1;
    sqlite3_bind_int(st, 1, engine);
    sqlite3_bind_int(st, 2, device_id);
    sqlite3_bind_text(st, 3, device_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 4, vendor_id);
    bind_text_or_null(st, 5, normalized_vendor[0] ? normalized_vendor : vendor_name);
    bind_text_or_null(st, 6, normalized_type[0] ? normalized_type : device_type);
    bind_text_or_null(st, 7, family);
    bind_text_or_null(st, 8, os_class);
    bind_text_or_null(st, 9, os_name);
    bind_text_or_null(st, 10, normalized_image[0] ? normalized_image : best_image);
    bind_text_or_null(st, 11, sizes);
    int ret = db_step_done(st);
    sqlite3_finalize(st);
    return ret;
}

static int db_upsert_fingerprint_model_alias(const char *alias_key, const char *device_name, const char *vendor_name, const char *device_type)
{
    sqlite3_stmt *st = NULL;
    char alias[128], vendor[128], type[64];
    if (!alias_key || !alias_key[0] || !device_name || !device_name[0]) return -1;
    db_lower_ascii_copy(alias, sizeof(alias), alias_key);
    db_normalize_catalog_vendor(vendor, sizeof(vendor), vendor_name);
    db_normalize_catalog_type(type, sizeof(type), device_type, "");
    if (db_prepare(&st, "INSERT INTO fingerprint_model_aliases(alias_key,device_name,vendor_name,device_type,updated_at) VALUES(?1,?2,NULLIF(?3,''),NULLIF(?4,''),?5) ON CONFLICT(alias_key) DO UPDATE SET device_name=excluded.device_name,vendor_name=excluded.vendor_name,device_type=excluded.device_type,updated_at=excluded.updated_at") != 0)
        return -1;
    sqlite3_bind_text(st, 1, alias, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, device_name, -1, SQLITE_TRANSIENT);
    bind_text_or_null(st, 3, vendor[0] ? vendor : vendor_name);
    bind_text_or_null(st, 4, type[0] ? type : device_type);
    sqlite3_bind_int64(st, 5, now_s());
    if (db_step_done(st) != 0) { sqlite3_finalize(st); return -1; }
    sqlite3_finalize(st);
    return 0;
}

static int db_lookup_fingerprint_model_alias(const char *alias_key, char *device_name, size_t name_len, char *vendor_name, size_t vendor_len, char *device_type, size_t type_len)
{
    sqlite3_stmt *st = NULL;
    char alias[128];
    int found = 0;
    if (!alias_key || !alias_key[0]) return 0;
    db_lower_ascii_copy(alias, sizeof(alias), alias_key);
    if (db_prepare(&st, "SELECT COALESCE(device_name,''),COALESCE(vendor_name,''),COALESCE(device_type,'') FROM fingerprint_model_aliases WHERE alias_key=?1") != 0)
        return 0;
    sqlite3_bind_text(st, 1, alias, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *dn = (const char *)sqlite3_column_text(st, 0);
        const char *vn = (const char *)sqlite3_column_text(st, 1);
        const char *dt = (const char *)sqlite3_column_text(st, 2);
        if (device_name && name_len && dn && dn[0]) snprintf(device_name, name_len, "%s", dn);
        if (vendor_name && vendor_len && vn && vn[0]) snprintf(vendor_name, vendor_len, "%s", vn);
        if (device_type && type_len && dt && dt[0]) snprintf(device_type, type_len, "%s", dt);
        found = 1;
    }
    sqlite3_finalize(st);
    return found;
}

static int db_import_fingerprint_database(const char *path)
{
    sqlite3 *catalog = NULL;
    sqlite3_stmt *st = NULL;
    int application_id = 0, schema_version = 0, expected = 0, imported = 0;
    const char *sql =
        "SELECT engine,device_id,vendor_id,device_name,vendor_name,device_type,"
        "family,os_class,os_name,web_image,sizes "
        "FROM fingerprint_device ORDER BY engine,device_id";

    if (sqlite3_open_v2(path, &catalog, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        goto failed;
    if (sqlite3_prepare_v2(catalog, "PRAGMA application_id", -1, &st, NULL) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_ROW)
        goto failed;
    application_id = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(catalog, "PRAGMA user_version", -1, &st, NULL) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_ROW)
        goto failed;
    schema_version = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    st = NULL;
    if (application_id != FINGERPRINT_DB_APPLICATION_ID ||
        schema_version != FINGERPRINT_DB_SCHEMA_VERSION)
        goto failed;
    if (sqlite3_prepare_v2(catalog,
            "SELECT CAST(value AS INTEGER) FROM fingerprint_meta WHERE key='device_count'",
            -1, &st, NULL) != SQLITE_OK || sqlite3_step(st) != SQLITE_ROW)
        goto failed;
    expected = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    st = NULL;
    if (expected <= 0 || db_begin() != 0)
        goto failed;
    if (db_exec("DELETE FROM fingerprint_devices") != 0)
        goto rollback;
    if (sqlite3_prepare_v2(catalog, sql, -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *device_name = (const char *)sqlite3_column_text(st, 3);
        const char *vendor_name = (const char *)sqlite3_column_text(st, 4);
        const char *device_type = (const char *)sqlite3_column_text(st, 5);
        const char *family = (const char *)sqlite3_column_text(st, 6);
        const char *os_class = (const char *)sqlite3_column_text(st, 7);
        const char *os_name = (const char *)sqlite3_column_text(st, 8);
        const char *web_image = (const char *)sqlite3_column_text(st, 9);
        const char *sizes = (const char *)sqlite3_column_text(st, 10);

        if (db_upsert_fingerprint_device_full(
                sqlite3_column_int(st, 0), sqlite3_column_int(st, 1),
                sqlite3_column_int(st, 2), device_name, vendor_name, device_type,
                family, os_class, os_name, web_image, sizes) != 0)
            goto rollback;
        imported++;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (imported != expected || db_commit() != 0)
        goto rollback;
    sqlite3_close(catalog);
    return imported;

rollback:
    db_rollback();
failed:
    sqlite3_finalize(st);
    if (catalog)
        sqlite3_close(catalog);
    return -1;
}

int db_try_import_fingerprint_catalog(void)
{
    int64_t version = 0;
    char path[512];
    char catalog_sha256[65];
    char imported_sha256[65];
    int imported;

    if (db_fingerprint_db_path(path, sizeof(path)) != 0)
        return -1;
    if (db_sha256_file(path, catalog_sha256) != 0) {
        LOG_WARN("fingerprint catalog: cannot hash %s\n", path);
        return -1;
    }
    if (db_meta_get_i64("fingerprint_catalog_version", &version) == 0 &&
        version == FINGERPRINT_CATALOG_VERSION &&
        db_meta_get_text("fingerprint_catalog_sha256", imported_sha256,
                         sizeof(imported_sha256)) == 0 &&
        !strcmp(imported_sha256, catalog_sha256))
        return 0;
    imported = db_import_fingerprint_database(path);
    if (imported <= 0) {
        LOG_WARN("fingerprint catalog: cannot import %s\n", path);
        return -1;
    }
    db_meta_set_i64("fingerprint_catalog_version", FINGERPRINT_CATALOG_VERSION);
    db_meta_set_text("fingerprint_catalog_sha256", catalog_sha256);
    g_fingerprint_catalog_changed = 1;
    LOG_INFO("fingerprint catalog: imported %d devices from %s\n",
             imported, path);
    return imported;
}

static void db_refresh_all_client_fingerprints(void)
{
    sqlite3_stmt *st = NULL;
    int count = 0;
    if (db_prepare(&st, "SELECT mac FROM clients ORDER BY last_seen DESC LIMIT 512") != 0) return;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *mac = (const char *)sqlite3_column_text(st, 0);
        if (mac && mac[0] && db_apply_identity_aggregator(mac) == 0) count++;
    }
    sqlite3_finalize(st);
    LOG_INFO("refreshed %d client fingerprints after catalog update\n", count);
}

static void db_update_chosen_image_path(const char *mac, const char *image_path)
{
    sqlite3_stmt *st = NULL;
    if (!image_path || !image_path[0]) return;
    if (db_prepare(&st, "UPDATE client_fingerprints SET image_path=?2,updated_at=?3 WHERE mac=?1") != 0) return;
    sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, image_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, now_s());
    db_step_done(st);
    sqlite3_finalize(st);
}

void db_startup_sig_match(void)
{
    /* One-time signature DB model matching at startup */
    sqlite3_stmt *st = NULL;
    char signature_path[512];
    int matched = 0;
    if (db_signature_db_path(signature_path, sizeof(signature_path)) != 0)
        return;
    if (sqlite3_prepare_v2(g_db,
        "SELECT mac, COALESCE(hostname,''), COALESCE(display_name,'') FROM clients "
        "WHERE (hostname IS NOT NULL AND hostname != '') OR (display_name IS NOT NULL AND display_name != '')",
        -1, &st, NULL) != SQLITE_OK) return;

    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *mac = (const char *)sqlite3_column_text(st, 0);
        const char *hn = (const char *)sqlite3_column_text(st, 1);
        const char *dn = (const char *)sqlite3_column_text(st, 2);
        const char *match_name = hn && hn[0] ? hn : (dn && dn[0] ? dn : NULL);
        if (!match_name || !match_name[0]) continue;

        sqlite3 *sdb = NULL;
        sqlite3_stmt *rst = NULL;
        if (sqlite3_open_v2(signature_path, &sdb, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) continue;
        if (sqlite3_prepare_v2(sdb,
            "SELECT COALESCE(v.name,''), COALESCE(t.name,''), r.model, r.pattern, r.confidence "
            "FROM device_fingerprint_rule r "
            "LEFT JOIN device_vendor v ON v.vendor_id=r.vendor_id "
            "LEFT JOIN device_type t ON t.type_id=r.type_id "
            "WHERE r.enabled=1 AND r.match_type='hostname' AND ( "
            "  (?1 = r.pattern) OR "
            "  (?1 LIKE r.pattern||'%') OR "
            "  (length(r.pattern) >= 4 AND ?1 LIKE '%'||r.pattern||'%') "
            ") "
            "ORDER BY r.confidence DESC, length(r.pattern) DESC LIMIT 1",
            -1, &rst, NULL) != SQLITE_OK) {
            sqlite3_close(sdb);
            continue;
        }
        sqlite3_bind_text(rst, 1, match_name, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(rst) == SQLITE_ROW) {
            const char *r_vendor = (const char *)sqlite3_column_text(rst, 0);
            const char *r_type = (const char *)sqlite3_column_text(rst, 1);
            const char *r_model = (const char *)sqlite3_column_text(rst, 2);
            double r_conf = sqlite3_column_double(rst, 4);
            if (r_model && r_model[0] && r_conf >= 60 && strcmp(r_model, "Unknown")) {
                const char *mapped_type = "unknown";
                if (r_type && r_type[0]) {
                    if (strstr(r_type, "手机") || strstr(r_type, "smartphone")) mapped_type = "smartphone";
                    else if (strstr(r_type, "电脑") || strstr(r_type, "computer")) mapped_type = "computer";
                    else if (strstr(r_type, "平板") || strstr(r_type, "tablet")) mapped_type = "tablet";
                    else if (strstr(r_type, "电视") || strstr(r_type, "tv")) mapped_type = "tv";
                    else if (strstr(r_type, "路由") || strstr(r_type, "router")) mapped_type = "router";
                    else if (strstr(r_type, "NAS")) mapped_type = "nas";
                    else if (strstr(r_type, "打印") || strstr(r_type, "printer")) mapped_type = "printer";
                    else if (strstr(r_type, "摄像") || strstr(r_type, "camera")) mapped_type = "camera";
                    else if (strstr(r_type, "游戏") || strstr(r_type, "game")) mapped_type = "game_console";
                    else if (strstr(r_type, "智能") || strstr(r_type, "iot")) mapped_type = "iot";
                }
                /* Update client with signature DB match */
                sqlite3_stmt *upd = NULL;
                if (sqlite3_prepare_v2(g_db,
                    "UPDATE clients SET display_name=?1, device_type=CASE WHEN ?2 != 'unknown' THEN ?2 ELSE device_type END WHERE mac=?3",
                    -1, &upd, NULL) == SQLITE_OK) {
                    sqlite3_bind_text(upd, 1, r_model, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(upd, 2, mapped_type, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(upd, 3, mac, -1, SQLITE_TRANSIENT);
                    sqlite3_step(upd);
                    sqlite3_finalize(upd);
                }
                /* Update client_fingerprints */
                sqlite3_stmt *fp_upd = NULL;
                if (sqlite3_prepare_v2(g_db,
                    "UPDATE client_fingerprints SET vendor_name=?1, device_type=?2 WHERE mac=?3",
                    -1, &fp_upd, NULL) == SQLITE_OK) {
                    sqlite3_bind_text(fp_upd, 1, r_vendor && r_vendor[0] ? r_vendor : "", -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(fp_upd, 2, mapped_type, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(fp_upd, 3, mac, -1, SQLITE_TRANSIENT);
                    sqlite3_step(fp_upd);
                    sqlite3_finalize(fp_upd);
                }
                matched++;
                LOG_ERROR("startup_sig: mac=%s name=%s -> model=%s type=%s conf=%.0f\n",
                    mac, match_name, r_model, mapped_type, r_conf);
            }
        }
        sqlite3_finalize(rst);
        sqlite3_close(sdb);
    }
    sqlite3_finalize(st);
    if (matched > 0) LOG_ERROR("startup_sig: matched %d clients\n", matched);
}



static int db_apply_identity_aggregator(const char *mac)
{
    sqlite3_stmt *st = NULL;
    char best_name[256] = "", best_vendor[128] = "", best_type[64] = "unknown";
    char best_image[256] = "";
    char trusted_vendor[128] = "";
    char source[64] = "aggregator";
    char override_name[256] = "", override_vendor[128] = "", override_type[64] = "unknown";
    int score = 0;
    int has_identity_override = 0;
    struct json_object *evidence = json_object_new_array();
    if (!mac || !mac[0]) return -1;

    if (db_prepare(&st, "SELECT COALESCE(device_name,''),COALESCE(vendor_name,''),COALESCE(device_type,''),COALESCE(custom_image_path,''),COALESCE(nickname,'') FROM client_identity_overrides WHERE mac=?1") == 0) {
        sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *dn=(const char*)sqlite3_column_text(st,0), *vn=(const char*)sqlite3_column_text(st,1), *dt=(const char*)sqlite3_column_text(st,2), *im=(const char*)sqlite3_column_text(st,3), *nn=(const char*)sqlite3_column_text(st,4);
            if (dn && dn[0]) snprintf(override_name,sizeof(override_name),"%s",dn);
            (void)nn; /* Nickname changes presentation only; it is not fingerprint evidence. */
            if (vn && vn[0]) snprintf(override_vendor,sizeof(override_vendor),"%s",vn);
            if (dt && dt[0]) snprintf(override_type,sizeof(override_type),"%s",dt);
            (void)im; /* A custom image is presentation state, not detected fingerprint evidence. */
            has_identity_override = override_name[0] || override_vendor[0] ||
                                    strcmp(override_type, "unknown");
        }
        sqlite3_finalize(st);
    }
    {
        if (db_prepare(&st, "SELECT source,key,value,confidence FROM client_identity_signals WHERE mac=?1 ORDER BY confidence DESC,last_seen DESC LIMIT 64") != 0) { json_object_put(evidence); return -1; }
        sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *src=(const char*)sqlite3_column_text(st,0), *key=(const char*)sqlite3_column_text(st,1), *val=(const char*)sqlite3_column_text(st,2);
            int conf = sqlite3_column_int(st,3);
            const char *dt = db_device_type_from_evidence(key, val);
            const char *vn = db_vendor_from_evidence(val);
            int model_vendor_conflict = 0;
            db_json_add_signal(evidence, src, key, val, conf);
            if (!trusted_vendor[0] && db_value_is_oui_only_signal(key, src) && vn[0] &&
                !db_vendor_is_virtual_nic(vn) &&
                !db_vendor_is_virtual_nic(val))
                snprintf(trusted_vendor, sizeof(trusted_vendor), "%s", vn);
            if (trusted_vendor[0] && (!strcmp(key, "model") || !strcmp(key, "modelName") || !strcmp(key, "friendlyName")) &&
                db_vendor_conflicts(trusted_vendor, db_vendor_from_evidence(val)))
                model_vendor_conflict = 1;
            if (!db_value_is_oui_only_signal(key, src) && !model_vendor_conflict)
                db_apply_known_model_hint(key, val, best_name, sizeof(best_name), best_vendor, sizeof(best_vendor), best_type, sizeof(best_type), &score, source, sizeof(source));
            if (!strcmp(key,"modelName") || !strcmp(key,"model") || !strcmp(key,"friendlyName") || !strcmp(key,"hostname") || !strcmp(key,"dhcp_hostname")) {
                if (!model_vendor_conflict && !best_name[0] && val && val[0] && !db_text_has_any(val, (const char *[]){"macsamba", NULL}) && !db_vendor_conflicts(trusted_vendor, vn)) snprintf(best_name,sizeof(best_name),"%s",val);
                if (conf + 10 > score) { score = conf + 10; snprintf(source,sizeof(source),"%s",src?src:"signal"); }
            }
            if (!model_vendor_conflict && !best_vendor[0] && vn[0] &&
                !db_value_is_oui_only_signal(key, src) &&
                !db_vendor_is_virtual_nic(vn) &&
                !db_vendor_conflicts(trusted_vendor, vn)) snprintf(best_vendor,sizeof(best_vendor),"%s",vn);
            if (!best_vendor[0] && (!strcmp(key,"manufacturer") || !strcmp(key,"vendor") || !strcmp(key,"server")) &&
                val && val[0] && !db_value_is_oui_only_signal(key, src) &&
                !db_vendor_is_virtual_nic(val)) snprintf(best_vendor,sizeof(best_vendor),"%s",val);
            if (!model_vendor_conflict && !strcmp(best_type,"unknown") && strcmp(dt,"unknown") &&
                !db_value_is_oui_only_signal(key, src) &&
                !db_vendor_is_virtual_nic(vn) &&
                !db_vendor_conflicts(trusted_vendor, vn)) snprintf(best_type,sizeof(best_type),"%s",dt);
            if (!strcmp(key,"option55") && conf > score) { score = conf; snprintf(source,sizeof(source),"dhcp-fingerprint"); }
        }
        sqlite3_finalize(st);
        if (!best_vendor[0]) {
            sqlite3_stmt *probe_st = NULL;
            if (db_prepare(&probe_st,
                "SELECT 1 FROM client_identity_signals "
                "WHERE mac=?1 AND source='service-probe' "
                "AND key='router_candidate' AND value='true' "
                "LIMIT 1") == 0) {
                sqlite3_bind_text(probe_st, 1, mac, -1, SQLITE_TRANSIENT);
                if (sqlite3_step(probe_st) == SQLITE_ROW) {
                    snprintf(best_type, sizeof(best_type), "%s", "router");
                    snprintf(source, sizeof(source), "%s", "service-probe");
                    if (score < 52) score = 52;
                }
                sqlite3_finalize(probe_st);
            }
        }
        if (trusted_vendor[0] && (db_vendor_conflicts(trusted_vendor, best_vendor) || db_vendor_conflicts(trusted_vendor, db_vendor_from_evidence(best_name)))) {
            best_name[0] = '\0';
            snprintf(best_type, sizeof(best_type), "%s", "unknown");
            if (score > 70) score = 70;
            snprintf(source, sizeof(source), "%s", "vendor-conflict");
        }
        if (trusted_vendor[0] && (!best_vendor[0] || db_vendor_conflicts(trusted_vendor, best_vendor)))
            snprintf(best_vendor, sizeof(best_vendor), "%s", trusted_vendor);
        db_apply_vendor_family_hint(trusted_vendor, best_name, sizeof(best_name), best_vendor, sizeof(best_vendor), best_type, sizeof(best_type), &score, source, sizeof(source));
        /* Gateway detection: if this client's IP is in the routing table as a default gateway,
         * it's almost certainly a router. Check /proc/net/route for default gateway IPs. */
        if (!strcmp(best_type, "unknown")) {
            sqlite3_stmt *gw_st = NULL;
            if (db_prepare(&gw_st, "SELECT ip FROM client_network_state WHERE client_id=(SELECT client_id FROM clients WHERE mac=?1) LIMIT 1") == 0) {
                sqlite3_bind_text(gw_st, 1, mac, -1, SQLITE_TRANSIENT);
                if (sqlite3_step(gw_st) == SQLITE_ROW) {
                    const char *client_ip = (const char *)sqlite3_column_text(gw_st, 0);
                    if (client_ip && client_ip[0]) {
                        /* Check if this IP appears as a gateway in /proc/net/route */
                        FILE *rt = fopen("/proc/net/route", "r");
                        if (rt) {
                            char rl[256];
                            fgets(rl, sizeof(rl), rt); /* skip header */
                            while (fgets(rl, sizeof(rl), rt)) {
                                char iface[32], dest[16], gw[16];
                                unsigned long gw_raw = 0;
                                if (sscanf(rl, "%31s %15s %15s", iface, dest, gw) >= 3) {
                                    sscanf(gw, "%lx", &gw_raw);
                                    if (gw_raw != 0) {
                                        char gw_ip[32];
                                        snprintf(gw_ip, sizeof(gw_ip), "%lu.%lu.%lu.%lu",
                                            gw_raw & 0xff, (gw_raw >> 8) & 0xff,
                                            (gw_raw >> 16) & 0xff, (gw_raw >> 24) & 0xff);
                                        if (!strcmp(gw_ip, client_ip)) {
                                            snprintf(best_type, sizeof(best_type), "router");
                                            if (!best_vendor[0] || !strcmp(best_vendor, "Proxmox Server Solutions GmbH"))
                                                snprintf(best_vendor, sizeof(best_vendor), "Gateway");
                                            snprintf(source, sizeof(source), "gateway-detected");
                                            if (score < 60) score = 60;
                                            break;
                                        }
                                    }
                                }
                            }
                            fclose(rt);
                        }
                    }
                }
                sqlite3_finalize(gw_st);
            }
        }
        /* Signature DB model matching: match hostname/mdns model against fingerprint rules */
        {
            sqlite3_stmt *sig_st = NULL;
            /* Get hostname and mdns model signals */
            if (db_prepare(&sig_st, "SELECT key, value FROM client_identity_signals WHERE mac=?1 AND key IN ('hostname','dhcp_hostname','model','modelName','friendlyName','useragent','server') ORDER BY confidence DESC LIMIT 16") == 0) {
                sqlite3_bind_text(sig_st, 1, mac, -1, SQLITE_TRANSIENT);
                while (sqlite3_step(sig_st) == SQLITE_ROW) {
                    const char *sig_key = (const char *)sqlite3_column_text(sig_st, 0);
                    const char *sig_val = (const char *)sqlite3_column_text(sig_st, 1);
                    if (!sig_val || !sig_val[0]) continue;
                    /* Determine match_type to query */
                    const char *match_type = "hostname";
                    if (!strcmp(sig_key, "useragent")) match_type = "user_agent";
                    else if (!strcmp(sig_key, "model") || !strcmp(sig_key, "modelName")) match_type = "hostname";
                    else if (!strcmp(sig_key, "server")) match_type = "user_agent";

                    /* Query signature DB for matching rules */
                    sqlite3 *sdb = NULL;
                    sqlite3_stmt *rule_st = NULL;
                    LOG_ERROR("sig_match: key=%s val=%s type=%s\n", sig_key ? sig_key : "", sig_val ? sig_val : "", match_type ? match_type : "");
                    char signature_path[512];
                    if (db_signature_db_path(signature_path, sizeof(signature_path)) == 0 &&
                        sqlite3_open_v2(signature_path, &sdb, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                        /* Use LIKE pattern matching for hostname, exact for user_agent */
                        const char *sql = "SELECT COALESCE(v.name,''), COALESCE(t.name,''), r.model, r.pattern, r.confidence "
                            "FROM device_fingerprint_rule r "
                            "LEFT JOIN device_vendor v ON v.vendor_id=r.vendor_id "
                            "LEFT JOIN device_type t ON t.type_id=r.type_id "
                            "WHERE r.enabled=1 AND r.match_type=?1 AND ( "
                            "  (?2 = r.pattern) OR "
                            "  (?2 LIKE r.pattern||'%') OR "
                            "  (?2 LIKE '%'||r.pattern) OR "
                            "  (length(r.pattern) >= 4 AND ?2 LIKE '%'||r.pattern||'%') "
                            ") "
                            "ORDER BY r.confidence DESC, length(r.pattern) DESC LIMIT 1";
                        if (sqlite3_prepare_v2(sdb, sql, -1, &rule_st, NULL) == SQLITE_OK) {
                            sqlite3_bind_text(rule_st, 1, match_type, -1, SQLITE_TRANSIENT);
                            sqlite3_bind_text(rule_st, 2, sig_val, -1, SQLITE_TRANSIENT);
                            if (sqlite3_step(rule_st) == SQLITE_ROW) {
                                const char *r_vendor = (const char *)sqlite3_column_text(rule_st, 0);
                                const char *r_type = (const char *)sqlite3_column_text(rule_st, 1);
                                const char *r_model = (const char *)sqlite3_column_text(rule_st, 2);
                                double r_conf = sqlite3_column_double(rule_st, 4);
                                if (r_model && r_model[0] && r_conf >= 60 && strcmp(r_model, "Unknown")) {
                                    /* Map Chinese type names */
                                    const char *mapped_type = "unknown";
                                    if (r_type && r_type[0]) {
                                        if (strstr(r_type, "手机") || strstr(r_type, "smartphone")) mapped_type = "smartphone";
                                        else if (strstr(r_type, "电脑") || strstr(r_type, "computer")) mapped_type = "computer";
                                        else if (strstr(r_type, "平板") || strstr(r_type, "tablet")) mapped_type = "tablet";
                                        else if (strstr(r_type, "电视") || strstr(r_type, "tv")) mapped_type = "tv";
                                        else if (strstr(r_type, "路由") || strstr(r_type, "router")) mapped_type = "router";
                                        else if (strstr(r_type, "NAS") || strstr(r_type, "nas")) mapped_type = "nas";
                                        else if (strstr(r_type, "打印") || strstr(r_type, "printer")) mapped_type = "printer";
                                        else if (strstr(r_type, "摄像") || strstr(r_type, "camera")) mapped_type = "camera";
                                        else if (strstr(r_type, "游戏") || strstr(r_type, "game")) mapped_type = "game_console";
                                        else if (strstr(r_type, "智能") || strstr(r_type, "iot")) mapped_type = "iot";
                                        else if (strstr(r_type, "手机")) mapped_type = "smartphone";
                                    }
                                    /* Always update model name from signature DB (upgrade hostname to model) */
                                    snprintf(best_name, sizeof(best_name), "%s", r_model);
                                    if (r_vendor && r_vendor[0] && (!best_vendor[0] || !strcmp(best_vendor, "unknown"))) snprintf(best_vendor, sizeof(best_vendor), "%s", r_vendor);
                                    if (strcmp(mapped_type, "unknown") && (!strcmp(best_type, "unknown"))) snprintf(best_type, sizeof(best_type), "%s", mapped_type);
                                    snprintf(source, sizeof(source), "sig-db-model");
                                    if ((int)r_conf > score) score = (int)r_conf;
                                }
                            }
                            sqlite3_finalize(rule_st);
                        }
                        sqlite3_close(sdb);
                    }
                }
                sqlite3_finalize(sig_st);
            }
        }

/* Hosttype engine matching: try UA/host patterns against signals */
        if (!strcmp(best_type, "unknown")) {
            sqlite3_stmt *ht_st = NULL;
            if (db_prepare(&ht_st, "SELECT key,value FROM client_identity_signals WHERE mac=?1 AND key IN ('hostname','useragent','server','modelName','friendlyName','dhcp_hostname') ORDER BY confidence DESC LIMIT 8") == 0) {
                sqlite3_bind_text(ht_st, 1, mac, -1, SQLITE_TRANSIENT);
                while (sqlite3_step(ht_st) == SQLITE_ROW) {
                    const char *ht_key = (const char *)sqlite3_column_text(ht_st, 0);
                    const char *ht_val = (const char *)sqlite3_column_text(ht_st, 1);
                    if (!ht_val || !ht_val[0]) continue;
                    char brand[64] = "", os_name[64] = "", desc[64] = "";
                    uint16_t cat = jmx_ht_match_ua(ht_val, (int)strlen(ht_val), brand, sizeof(brand), os_name, sizeof(os_name), desc, sizeof(desc));
                    if (cat > 0 && cat < JMX_HT_CAT_MAX) {
                        const char *cat_names[] = {"unknown","smartphone","tablet","computer","tv","router","iot","printer","camera","game_console"};
                        snprintf(best_type, sizeof(best_type), "%s", cat_names[cat]);
                        if (!best_vendor[0] && brand[0]) snprintf(best_vendor, sizeof(best_vendor), "%s", brand);
                        if (!best_name[0] && desc[0]) snprintf(best_name, sizeof(best_name), "%s", desc);
                        snprintf(source, sizeof(source), "hosttype-ua");
                        if (score < 70) score = 70;
                        break;
                    }
                }
                sqlite3_finalize(ht_st);
            }
        }
                /* Vendor→type fallback: if type still unknown, infer from vendor name */
        if (!strcmp(best_type, "unknown") && best_vendor[0] && db_vendor_type_fallback_allowed(best_vendor)) {
            const char *vt = db_type_from_vendor(best_vendor);
            if (strcmp(vt, "unknown")) {
                snprintf(best_type, sizeof(best_type), "%s", vt);
                snprintf(source, sizeof(source), "vendor-type-infer");
            }
        }
        if (score <= 0 && (best_name[0] || best_vendor[0] || strcmp(best_type,"unknown"))) score = 50;
        if (score > 99) score = 99;
    }
    if (best_name[0]) {
        char alias_name[256] = "", alias_vendor[128] = "", alias_type[64] = "";
        if (db_lookup_fingerprint_model_alias(best_name, alias_name, sizeof(alias_name), alias_vendor, sizeof(alias_vendor), alias_type, sizeof(alias_type))) {
            snprintf(best_name, sizeof(best_name), "%s", alias_name);
            if (alias_vendor[0]) snprintf(best_vendor, sizeof(best_vendor), "%s", alias_vendor);
            if (alias_type[0]) snprintf(best_type, sizeof(best_type), "%s", alias_type);
            if (score < 94) score = 94;
            snprintf(source, sizeof(source), "%s", "model-alias");
        }
    }
    db_apply_specific_signal_name(mac, best_name, sizeof(best_name), best_vendor, sizeof(best_vendor),
                                  best_type, sizeof(best_type), &score, source, sizeof(source));
    if (!db_signal_name_specific_enough(best_name))
        db_apply_generic_catalog_hint(best_name, sizeof(best_name), best_vendor, best_type);
    if (best_name[0]) {
        sqlite3_stmt *cat = NULL;
        if (db_prepare(&cat, "SELECT engine,device_id,COALESCE(device_name,''),COALESCE(vendor_name,''),COALESCE(device_type,''),COALESCE(best_image,'') FROM fingerprint_devices WHERE lower(device_name)=lower(?1) OR (length(device_name) >= 6 AND lower(?1) LIKE '%'||lower(device_name)||'%') OR (length(?1) >= 6 AND lower(device_name) LIKE '%'||lower(?1)||'%') ORDER BY length(device_name) DESC LIMIT 5") == 0) {
            sqlite3_bind_text(cat, 1, best_name, -1, SQLITE_TRANSIENT);
            while (sqlite3_step(cat) == SQLITE_ROW) {
                int cengine = sqlite3_column_int(cat, 0);
                const char *cn=(const char*)sqlite3_column_text(cat,2), *cv=(const char*)sqlite3_column_text(cat,3), *ct=(const char*)sqlite3_column_text(cat,4), *ci=(const char*)sqlite3_column_text(cat,5);
                int quality = db_catalog_match_quality(best_name, cn);
                int cscore;
                if (quality <= 0) continue;
                if (best_vendor[0] && cv && cv[0] && db_vendor_conflicts(best_vendor, cv)) continue;
                if (cengine != 0 && quality < 100) continue;
                cscore = score + (quality >= 100 ? 8 : 3); if (cscore > 99) cscore = 99;
                db_insert_candidate(mac, cengine, sqlite3_column_int(cat,1), cn, cv, "catalog", cscore, evidence);
                if (quality >= 100 && cscore >= score && !db_signal_name_specific_enough(best_name)) {
                    snprintf(best_name,sizeof(best_name),"%s",cn?cn:best_name);
                    if (cv && cv[0]) snprintf(best_vendor,sizeof(best_vendor),"%s",cv);
                    if (ct && ct[0]) snprintf(best_type,sizeof(best_type),"%s",ct);
                    if (ci && ci[0]) snprintf(best_image,sizeof(best_image),"%s",ci);
                    snprintf(source,sizeof(source),"catalog"); score = cscore;
                }
            }
            sqlite3_finalize(cat);
        }
    }
    if (!best_image[0])
        db_lookup_catalog_family_image(best_vendor, best_type, best_image, sizeof(best_image));
    if (override_name[0])
        snprintf(best_name, sizeof(best_name), "%s", override_name);
    if (override_vendor[0])
        snprintf(best_vendor, sizeof(best_vendor), "%s", override_vendor);
    if (strcmp(override_type, "unknown"))
        snprintf(best_type, sizeof(best_type), "%s", override_type);
    if (has_identity_override) {
        score = 100;
        snprintf(source, sizeof(source), "%s", "override");
    }
    db_insert_candidate(mac, 0, 0, best_name, best_vendor, source, score, evidence);
    db_write_chosen_fingerprint(mac, best_name, best_vendor, best_type, best_image, source, score, evidence);
    /* Also update client_fingerprint table (no 's') so client_detail API picks it up */
    {
        int64_t cid = db_client_id_by_mac(mac);
        if (cid > 0) {
            sqlite3_stmt *fpst = NULL;
            /* Map device_type to dev_cat enum */
            int dev_cat = 0;
            if (!strcmp(best_type, "smartphone")) dev_cat = 1;
            else if (!strcmp(best_type, "tablet")) dev_cat = 2;
            else if (!strcmp(best_type, "computer") || !strcmp(best_type, "pc")) dev_cat = 3;
            else if (!strcmp(best_type, "tv")) dev_cat = 4;
            else if (!strcmp(best_type, "nas")) dev_cat = 5;
            else if (!strcmp(best_type, "router") || !strcmp(best_type, "network")) dev_cat = 6;
            else if (!strcmp(best_type, "printer")) dev_cat = 7;
            else if (!strcmp(best_type, "camera")) dev_cat = 8;
            else if (!strcmp(best_type, "iot")) dev_cat = 9;
            else if (!strcmp(best_type, "game_console")) dev_cat = 10;
            else if (!strcmp(best_type, "hypervisor")) dev_cat = 11;
            if (db_prepare(&fpst, "INSERT INTO client_fingerprint(client_id,engine,device_id,vendor_id,os_class,os_name_id,dev_cat,dev_vendor,confidence,source,raw_json,updated_at) VALUES(?1,0,0,0,0,0,?2,0,?3,?4,?5,?6) ON CONFLICT(client_id) DO UPDATE SET dev_cat=excluded.dev_cat,dev_vendor=excluded.dev_vendor,confidence=excluded.confidence,source=excluded.source,raw_json=excluded.raw_json,updated_at=excluded.updated_at") == 0) {
                sqlite3_bind_int64(fpst, 1, cid);
                sqlite3_bind_int(fpst, 2, dev_cat);
                sqlite3_bind_int(fpst, 3, score);
                sqlite3_bind_text(fpst, 4, source ? source : "aggregator", -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(fpst, 5, evidence ? json_object_to_json_string(evidence) : "[]", -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(fpst, 6, now_s());
                db_step_done(fpst);
                sqlite3_finalize(fpst);
            }
        }
    }
    /* Also update clients table so client_detail API picks up the resolved vendor/type.
     * Unknown from the aggregator intentionally clears stale guessed types. */
    {
        sqlite3_stmt *upd = NULL;
        if (db_prepare(&upd,
            "UPDATE clients SET "
            "vendor=CASE "
            " WHEN NULLIF(?1,'') IS NOT NULL THEN ?1 "
            " WHEN lower(COALESCE(vendor,'')) LIKE '%proxmox%' "
            "   OR lower(COALESCE(vendor,'')) LIKE '%qemu%' "
            "   OR lower(COALESCE(vendor,'')) LIKE '%kvm%' "
            "   OR lower(COALESCE(vendor,'')) LIKE '%vmware%' "
            "   OR lower(COALESCE(vendor,'')) LIKE '%virtualbox%' "
            "   OR lower(COALESCE(vendor,'')) LIKE '%parallels%' "
            "   OR lower(COALESCE(vendor,'')) LIKE '%hyper-v%' THEN NULL "
            " ELSE vendor END, "
            "device_type=CASE WHEN ?2='unknown' THEN NULL ELSE ?2 END, "
            "display_name=COALESCE(NULLIF(?3,''),display_name), updated_at=?4 WHERE mac=?5") == 0) {
            bind_text_or_null(upd, 1, best_vendor);
            sqlite3_bind_text(upd, 2, best_type, -1, SQLITE_TRANSIENT);
            bind_text_or_null(upd, 3, best_name);
            sqlite3_bind_int64(upd, 4, now_s());
            sqlite3_bind_text(upd, 5, mac, -1, SQLITE_TRANSIENT);
            db_step_done(upd);
            sqlite3_finalize(upd);
        }
    }
    json_object_put(evidence);
    return 0;
}

static int db_upsert_fingerprint(int64_t client_id, struct json_object *fp)
{
    sqlite3_stmt *st = NULL;
    int64_t ts = now_s();
    struct json_object *raw = NULL;
    const char *raw_json = "{}";
    const char *sql =
        "INSERT INTO client_fingerprint(client_id,engine,device_id,vendor_id,os_class,os_name_id,dev_cat,dev_vendor,confidence,source,raw_json,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,NULLIF(?10,''),?11,?12) "
        "ON CONFLICT(client_id) DO UPDATE SET engine=excluded.engine,device_id=excluded.device_id,vendor_id=excluded.vendor_id,os_class=excluded.os_class,os_name_id=excluded.os_name_id,dev_cat=excluded.dev_cat,dev_vendor=excluded.dev_vendor,confidence=excluded.confidence,source=excluded.source,raw_json=excluded.raw_json,updated_at=excluded.updated_at";
    if (client_id <= 0 || !fp) return 0;
    if (json_object_object_get_ex(fp, "raw", &raw) && raw)
        raw_json = json_object_to_json_string(raw);
    if (db_prepare(&st, sql) != 0) return -1;
    sqlite3_bind_int64(st, 1, client_id);
    sqlite3_bind_int(st, 2, json_i(fp, "engine", 0));
    sqlite3_bind_int(st, 3, json_i(fp, "device_id", 0));
    sqlite3_bind_int(st, 4, json_i(fp, "vendor_id", 0));
    sqlite3_bind_int(st, 5, json_i(fp, "os_class", 0));
    sqlite3_bind_int(st, 6, json_i(fp, "os_name_id", 0));
    sqlite3_bind_int(st, 7, json_i(fp, "dev_cat", 0));
    sqlite3_bind_int(st, 8, json_i(fp, "dev_vendor", 0));
    sqlite3_bind_double(st, 9, json_d(fp, "confidence", 0));
    bind_text_or_null(st, 10, json_s(fp, "source", ""));
    sqlite3_bind_text(st, 11, raw_json, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 12, ts);
    int ret = db_step_done(st);
    sqlite3_finalize(st);
    return ret;
}

static int db_schema_v2(void);

static int db_schema_v1(void)
{
    const char *sql =
        "PRAGMA foreign_keys=ON;"
        "CREATE TABLE IF NOT EXISTS db_meta (key TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS clients ("
        " client_id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT NOT NULL UNIQUE, hostname TEXT, display_name TEXT, vendor TEXT, oui TEXT, device_type TEXT, os_name TEXT, is_wired INTEGER, first_seen INTEGER, last_seen INTEGER, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);"
        "CREATE INDEX IF NOT EXISTS idx_clients_last_seen ON clients(last_seen);"
        "CREATE INDEX IF NOT EXISTS idx_clients_vendor ON clients(vendor);"
        "CREATE INDEX IF NOT EXISTS idx_clients_device_type ON clients(device_type);"
        "CREATE TABLE IF NOT EXISTS client_aliases ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT, client_id INTEGER NOT NULL, alias_type TEXT NOT NULL, alias_value TEXT NOT NULL, source TEXT NOT NULL, confidence REAL, first_seen INTEGER, last_seen INTEGER, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, FOREIGN KEY(client_id) REFERENCES clients(client_id) ON DELETE CASCADE);"
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_client_alias_unique ON client_aliases(client_id, alias_type, alias_value, source);"
        "CREATE TABLE IF NOT EXISTS client_identity_signals ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT NOT NULL, source TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, confidence INTEGER DEFAULT 0, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, raw_json TEXT);"
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_client_identity_signal_unique ON client_identity_signals(mac, source, key, value);"
        "CREATE INDEX IF NOT EXISTS idx_client_identity_signal_mac ON client_identity_signals(mac,last_seen);"
        "CREATE TABLE IF NOT EXISTS client_fingerprints ("
        " mac TEXT PRIMARY KEY, engine INTEGER, device_id INTEGER, vendor_id INTEGER, device_name TEXT, vendor_name TEXT, device_type TEXT, family TEXT, os_class TEXT, os_name TEXT, image_path TEXT, source TEXT NOT NULL, confidence INTEGER NOT NULL, evidence_json TEXT, updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS client_identity_overrides ("
        " mac TEXT PRIMARY KEY, nickname TEXT, engine INTEGER, device_id INTEGER, device_name TEXT, vendor_name TEXT, device_type TEXT, custom_image_path TEXT, note TEXT, updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS fingerprint_devices ("
        " engine INTEGER NOT NULL, device_id INTEGER NOT NULL, device_name TEXT, vendor_id INTEGER, vendor_name TEXT, device_type TEXT, family TEXT, os_class TEXT, os_name TEXT, best_image TEXT, sizes TEXT, PRIMARY KEY(engine, device_id));"
        "CREATE INDEX IF NOT EXISTS idx_fingerprint_devices_name ON fingerprint_devices(device_name,vendor_name,device_type);"
        "CREATE TABLE IF NOT EXISTS fingerprint_model_aliases ("
        " alias_key TEXT PRIMARY KEY, device_name TEXT NOT NULL, vendor_name TEXT, device_type TEXT, updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS client_overrides ("
        " client_id INTEGER PRIMARY KEY, custom_name TEXT, custom_icon TEXT, custom_device_type TEXT, custom_vendor TEXT, pinned INTEGER NOT NULL DEFAULT 0, hidden INTEGER NOT NULL DEFAULT 0, note TEXT, updated_at INTEGER NOT NULL, FOREIGN KEY(client_id) REFERENCES clients(client_id) ON DELETE CASCADE);"
        "CREATE TABLE IF NOT EXISTS client_network_state ("
        " client_id INTEGER PRIMARY KEY, ip TEXT, ipv6_json TEXT, interface TEXT, network TEXT, ssid TEXT, parent_mac TEXT, parent_id TEXT, port TEXT, link_type TEXT, link_speed TEXT, signal INTEGER, tx_rate INTEGER NOT NULL DEFAULT 0, rx_rate INTEGER NOT NULL DEFAULT 0, tx_bytes INTEGER NOT NULL DEFAULT 0, rx_bytes INTEGER NOT NULL DEFAULT 0, connections INTEGER NOT NULL DEFAULT 0, online INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL, FOREIGN KEY(client_id) REFERENCES clients(client_id) ON DELETE CASCADE);"
        "CREATE INDEX IF NOT EXISTS idx_client_network_online ON client_network_state(online, updated_at);"
        "CREATE TABLE IF NOT EXISTS client_fingerprint ("
        " client_id INTEGER PRIMARY KEY, engine INTEGER, device_id INTEGER, vendor_id INTEGER, os_class INTEGER, os_name_id INTEGER, dev_cat INTEGER, dev_vendor INTEGER, confidence REAL, source TEXT, raw_json TEXT, updated_at INTEGER NOT NULL, FOREIGN KEY(client_id) REFERENCES clients(client_id) ON DELETE CASCADE);"
        "CREATE INDEX IF NOT EXISTS idx_client_fingerprint_device ON client_fingerprint(engine, device_id);"
        "CREATE INDEX IF NOT EXISTS idx_client_fingerprint_vendor ON client_fingerprint(vendor_id);"
        "CREATE TABLE IF NOT EXISTS client_image_assets ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, engine INTEGER, device_id INTEGER, vendor_id INTEGER, size INTEGER NOT NULL, label TEXT, path TEXT NOT NULL, sha256 TEXT, bytes INTEGER, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);"
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_client_image_asset_path ON client_image_assets(path);"
        "CREATE INDEX IF NOT EXISTS idx_client_image_asset_fingerprint ON client_image_assets(engine, device_id, vendor_id, size);";
    int64_t ts = now_s();
    if (db_exec(sql) != 0) return -1;

    sqlite3_stmt *st = NULL;
    if (db_prepare(&st, "INSERT INTO db_meta(key,value,updated_at) VALUES(?1,?2,?3) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at") != 0)
        return -1;
    sqlite3_bind_text(st, 1, "schema_version", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, "1", -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 3, ts);
    if (db_step_done(st) != 0) { sqlite3_finalize(st); return -1; }
    sqlite3_reset(st);
    sqlite3_clear_bindings(st);
    sqlite3_bind_text(st, 1, "created_by", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, "jmxd", -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 3, ts);
    if (db_step_done(st) != 0) { sqlite3_finalize(st); return -1; }
    sqlite3_finalize(st);

    db_prepare(&st, "INSERT INTO db_meta(key,value,updated_at) VALUES('created_at',?1,?2) ON CONFLICT(key) DO NOTHING");
    if (st) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%lld", (long long)ts);
        sqlite3_bind_text(st, 1, buf, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, ts);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
    return 0;
}

int jmx_db_init(void)
{
    int rc;
    int version;
    int migration_started = 0;

    if (g_db) return 0;
    db_mkdirs();
    rc = sqlite3_open(g_db_path, &g_db);
    if (rc != SQLITE_OK) {
        LOG_ERROR("open db failed path=%s err=%s\n", g_db_path, g_db ? sqlite3_errmsg(g_db) : "oom");
        if (g_db) sqlite3_close(g_db);
        g_db = NULL;
        return -1;
    }
    sqlite3_busy_timeout(g_db, 5000);
    if (db_exec("PRAGMA journal_mode=WAL;") != 0)
        goto failed;
    db_exec("PRAGMA synchronous=NORMAL;");
    db_exec("PRAGMA wal_autocheckpoint=1000;");
    db_exec("PRAGMA cache_size=-8192;");
    db_exec("PRAGMA temp_store=MEMORY;");
    db_exec("PRAGMA mmap_size=67108864;");

    version = db_schema_version();
    if (version > JMX_DB_SCHEMA_VERSION) {
        LOG_ERROR("database schema version %d is newer than supported version %d\n",
                  version, JMX_DB_SCHEMA_VERSION);
        goto failed;
    }
    if (version < JMX_DB_SCHEMA_VERSION) {
        if (db_begin() != 0)
            goto failed;
        migration_started = 1;
        if (version < 1 && db_schema_v1() != 0)
            goto migration_failed;
        if (version < 2 && db_schema_v2() != 0)
            goto migration_failed;

        /* Schema v3: migrate net_interface_state to UNIQUE(iface_id) for UPSERT. */
        if (version < 3) {
            int has_unique = 0;
            sqlite3_stmt *ck = NULL;

            if (db_prepare(&ck,
                    "SELECT sql FROM sqlite_master WHERE type='table' "
                    "AND name='net_interface_state'") != 0)
                goto migration_failed;
            if (sqlite3_step(ck) == SQLITE_ROW) {
                const char *ddl = (const char *)sqlite3_column_text(ck, 0);
                if (ddl && strstr(ddl, "UNIQUE"))
                    has_unique = 1;
            }
            sqlite3_finalize(ck);
            if (!has_unique) {
                LOG_INFO("migrating net_interface_state to UNIQUE(iface_id)\n");
                if (db_exec("ALTER TABLE net_interface_state "
                            "RENAME TO net_interface_state_old;") != 0 ||
                    db_exec("CREATE TABLE net_interface_state ("
                            " iface_id INTEGER NOT NULL UNIQUE, ts INTEGER NOT NULL, "
                            " online INTEGER NOT NULL DEFAULT 0, "
                            " rx_bytes INTEGER NOT NULL DEFAULT 0, "
                            " tx_bytes INTEGER NOT NULL DEFAULT 0, "
                            " rx_rate INTEGER NOT NULL DEFAULT 0, "
                            " tx_rate INTEGER NOT NULL DEFAULT 0, "
                            " latency_ms INTEGER NOT NULL DEFAULT 0, "
                            " loss_pct INTEGER NOT NULL DEFAULT 0, "
                            " FOREIGN KEY(iface_id) REFERENCES net_interfaces(iface_id) "
                            "ON DELETE CASCADE);") != 0 ||
                    db_exec("INSERT OR IGNORE INTO net_interface_state "
                            "SELECT * FROM net_interface_state_old;") != 0 ||
                    db_exec("DROP TABLE net_interface_state_old;") != 0 ||
                    db_exec("CREATE INDEX IF NOT EXISTS idx_net_interface_state_ts "
                            "ON net_interface_state(iface_id,ts);") != 0)
                    goto migration_failed;
                LOG_INFO("net_interface_state migration done\n");
            }
        }
        /* Schema v4: persistent activity sampling and daily WAN counters. */
        if (version < 4) {
            sqlite3_stmt *ck = NULL;
            int has_activity = 0;

            if (db_prepare(&ck,
                    "SELECT 1 FROM sqlite_master WHERE type='table' "
                    "AND name='dashboard_activity_sample'") != 0)
                goto migration_failed;
            if (sqlite3_step(ck) == SQLITE_ROW)
                has_activity = 1;
            sqlite3_finalize(ck);
            if (!has_activity) {
                LOG_INFO("creating dashboard_activity_sample table\n");
                if (db_exec("CREATE TABLE dashboard_activity_sample ("
                            " ts INTEGER NOT NULL,"
                            " wan_id TEXT NOT NULL DEFAULT 'wan',"
                            " up_rate INTEGER NOT NULL DEFAULT 0,"
                            " down_rate INTEGER NOT NULL DEFAULT 0,"
                            " connections INTEGER NOT NULL DEFAULT 0,"
                            " latency_avg REAL NOT NULL DEFAULT 0,"
                            " latency_min REAL NOT NULL DEFAULT 0,"
                            " latency_max REAL NOT NULL DEFAULT 0,"
                            " PRIMARY KEY(ts, wan_id));") != 0 ||
                    db_exec("CREATE INDEX IF NOT EXISTS idx_dashboard_activity_sample_ts "
                            "ON dashboard_activity_sample(ts);") != 0)
                    goto migration_failed;
            }
            if (db_exec("CREATE TABLE IF NOT EXISTS dashboard_daily_usage_counter ("
                        " day_start INTEGER NOT NULL,"
                        " wan_id TEXT NOT NULL,"
                        " baseline_ts INTEGER NOT NULL DEFAULT 0,"
                        " baseline_rx_bytes INTEGER NOT NULL DEFAULT 0,"
                        " baseline_tx_bytes INTEGER NOT NULL DEFAULT 0,"
                        " last_ts INTEGER NOT NULL DEFAULT 0,"
                        " last_rx_bytes INTEGER NOT NULL DEFAULT 0,"
                        " last_tx_bytes INTEGER NOT NULL DEFAULT 0,"
                        " rx_bytes INTEGER NOT NULL DEFAULT 0,"
                        " tx_bytes INTEGER NOT NULL DEFAULT 0,"
                        " sample_count INTEGER NOT NULL DEFAULT 0,"
                        " reset_count INTEGER NOT NULL DEFAULT 0,"
                        " updated_at INTEGER NOT NULL DEFAULT 0,"
                        " PRIMARY KEY(day_start, wan_id));") != 0 ||
                db_exec("CREATE INDEX IF NOT EXISTS idx_dashboard_daily_usage_counter_day "
                        "ON dashboard_daily_usage_counter(day_start);") != 0)
                goto migration_failed;
        }
        /* Schema v5: CPU/memory/disk/load monitoring history. */
        if (version < 5) {
            if (db_exec("CREATE TABLE IF NOT EXISTS system_health_sample ("
                        " ts INTEGER NOT NULL PRIMARY KEY,"
                        " cpu_percent REAL NOT NULL DEFAULT 0,"
                        " mem_percent REAL NOT NULL DEFAULT 0,"
                        " disk_percent REAL NOT NULL DEFAULT 0,"
                        " connections INTEGER NOT NULL DEFAULT 0,"
                        " forward_pps INTEGER NOT NULL DEFAULT 0,"
                        " client_num INTEGER NOT NULL DEFAULT 0,"
                        " rx_packets INTEGER NOT NULL DEFAULT 0,"
                        " tx_packets INTEGER NOT NULL DEFAULT 0,"
                        " forward_packets INTEGER NOT NULL DEFAULT 0,"
                        " counter_reset INTEGER NOT NULL DEFAULT 0);") != 0)
                goto migration_failed;
            if (!db_table_has_column("system_health_sample", "rx_packets") &&
                db_exec("ALTER TABLE system_health_sample ADD COLUMN "
                        "rx_packets INTEGER NOT NULL DEFAULT 0;") != 0)
                goto migration_failed;
            if (!db_table_has_column("system_health_sample", "tx_packets") &&
                db_exec("ALTER TABLE system_health_sample ADD COLUMN "
                        "tx_packets INTEGER NOT NULL DEFAULT 0;") != 0)
                goto migration_failed;
            if (!db_table_has_column("system_health_sample", "forward_packets") &&
                db_exec("ALTER TABLE system_health_sample ADD COLUMN "
                        "forward_packets INTEGER NOT NULL DEFAULT 0;") != 0)
                goto migration_failed;
            if (!db_table_has_column("system_health_sample", "counter_reset") &&
                db_exec("ALTER TABLE system_health_sample ADD COLUMN "
                        "counter_reset INTEGER NOT NULL DEFAULT 0;") != 0)
                goto migration_failed;
            if (db_exec("CREATE INDEX IF NOT EXISTS idx_system_health_sample_ts "
                        "ON system_health_sample(ts);") != 0)
                goto migration_failed;
        }
        /* Schema v6: physical-disk runtime history for storage overview. */
        if (version < 6) {
            if (db_exec("CREATE TABLE IF NOT EXISTS storage_disk_sample ("
                        " ts INTEGER NOT NULL,"
                        " disk_id TEXT NOT NULL,"
                        " device TEXT NOT NULL,"
                        " used_percent REAL,"
                        " read_bps REAL,"
                        " write_bps REAL,"
                        " read_latency_ms REAL,"
                        " write_latency_ms REAL,"
                        " PRIMARY KEY(ts,disk_id));") != 0 ||
                db_exec("CREATE INDEX IF NOT EXISTS idx_storage_disk_sample_ts "
                        "ON storage_disk_sample(ts);") != 0 ||
                db_exec("CREATE INDEX IF NOT EXISTS idx_storage_disk_sample_disk_ts "
                        "ON storage_disk_sample(disk_id,ts);") != 0)
                goto migration_failed;
        }
        /* Schema v7: lifetime WAN byte counters that survive interface rebuilds.
         * PPPoE recreates its virtual interface on every reconnect, which resets
         * the kernel counter to zero.  Reading that counter directly made the
         * reported cumulative usage collapse to "since last reconnect" without
         * telling anyone (Acceptance A-013). */
        if (version < 7) {
            if (db_exec("CREATE TABLE IF NOT EXISTS wan_lifetime_usage ("
                        " wan_id TEXT PRIMARY KEY,"
                        " first_seen_ts INTEGER NOT NULL DEFAULT 0,"
                        " last_ts INTEGER NOT NULL DEFAULT 0,"
                        " last_rx_bytes INTEGER NOT NULL DEFAULT 0,"
                        " last_tx_bytes INTEGER NOT NULL DEFAULT 0,"
                        " base_rx_bytes INTEGER NOT NULL DEFAULT 0,"
                        " base_tx_bytes INTEGER NOT NULL DEFAULT 0,"
                        " reset_count INTEGER NOT NULL DEFAULT 0,"
                        " last_reset_ts INTEGER NOT NULL DEFAULT 0,"
                        " sample_count INTEGER NOT NULL DEFAULT 0,"
                        " updated_at INTEGER NOT NULL DEFAULT 0);") != 0)
                goto migration_failed;
        }
        if (db_set_schema_version(JMX_DB_SCHEMA_VERSION) != 0 || db_commit() != 0)
            goto migration_failed;
        migration_started = 0;
    }

    /* Load fingerprint rules from signature database */
    db_try_import_fingerprint_catalog();
    if (g_fingerprint_catalog_changed)
        db_refresh_all_client_fingerprints();
    return 0;

migration_failed:
    if (migration_started)
        db_rollback();
failed:
    if (g_db)
        sqlite3_close(g_db);
    g_db = NULL;
    return -1;
}

void jmx_db_close(void)
{
    if (g_db) sqlite3_close(g_db);
    g_db = NULL;
}

/* ── dashboard_activity_sample: persistent activity sampling ── */

void jmx_db_write_activity_sample(const char *wan_id, int64_t up_rate, int64_t down_rate,
                                   int connections, double latency_avg,
                                   double latency_min, double latency_max)
{
    int64_t now;
    sqlite3_stmt *st = NULL;
    if (!wan_id || !wan_id[0]) return;
    if (!jmx_storage_guard_allow("/", JMX_STORAGE_WRITE_BULK, NULL)) return;
    if (jmx_db_init() != 0) return;

    now = now_s();
    /* round to 10-second buckets for uniform sampling */
    now = (now / 10) * 10;

    if (db_prepare(&st,
        "INSERT INTO dashboard_activity_sample(ts,wan_id,up_rate,down_rate,connections,latency_avg,latency_min,latency_max) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8) "
        "ON CONFLICT(ts,wan_id) DO UPDATE SET "
        "up_rate=excluded.up_rate,down_rate=excluded.down_rate,"
        "connections=excluded.connections,latency_avg=excluded.latency_avg,"
        "latency_min=excluded.latency_min,latency_max=excluded.latency_max") == 0) {
        sqlite3_bind_int64(st, 1, now);
        sqlite3_bind_text(st, 2, wan_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, up_rate);
        sqlite3_bind_int64(st, 4, down_rate);
        sqlite3_bind_int(st, 5, connections);
        sqlite3_bind_double(st, 6, latency_avg);
        sqlite3_bind_double(st, 7, latency_min);
        sqlite3_bind_double(st, 8, latency_max);
        db_step_done(st);
        sqlite3_finalize(st);
    }
}

int jmx_db_prune_activity_samples(int64_t max_age_sec)
{
    int64_t cutoff;
    sqlite3_stmt *st = NULL;
    int rc = -1;
    if (jmx_db_init() != 0) return -1;
    if (max_age_sec <= 0) max_age_sec = 31 * 86400;
    cutoff = now_s() - max_age_sec;
    if (db_prepare(&st, "DELETE FROM dashboard_activity_sample WHERE ts < ?1") == 0) {
        sqlite3_bind_int64(st, 1, cutoff);
        rc = db_step_done(st);
        sqlite3_finalize(st);
    }
    return rc;
}

static int64_t jmx_db_local_day_start(int64_t now)
{
    time_t t = (time_t)now;
    struct tm tmv;

    if (localtime_r(&t, &tmv) == NULL)
        return now - (now % 86400);
    tmv.tm_hour = 0;
    tmv.tm_min = 0;
    tmv.tm_sec = 0;
    tmv.tm_isdst = -1;
    return (int64_t)mktime(&tmv);
}

int jmx_db_update_daily_usage_counter(const char *wan_id,
                                      unsigned long long rx_bytes,
                                      unsigned long long tx_bytes,
                                      int online)
{
    sqlite3_stmt *st = NULL;
    int64_t now = now_s();
    int64_t day_start = jmx_db_local_day_start(now);
    int64_t last_rx = 0, last_tx = 0;
    int64_t acc_rx = 0, acc_tx = 0;
    int sample_count = 0, reset_count = 0;
    int have = 0;
    int rc = -1;

    if (!wan_id || !wan_id[0] || !online)
        return -1;
    if (jmx_db_init() != 0)
        return -1;

    if (db_prepare(&st,
        "SELECT last_rx_bytes,last_tx_bytes,rx_bytes,tx_bytes,sample_count,reset_count "
        "FROM dashboard_daily_usage_counter WHERE day_start=?1 AND wan_id=?2") == 0) {
        sqlite3_bind_int64(st, 1, day_start);
        sqlite3_bind_text(st, 2, wan_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            last_rx = sqlite3_column_int64(st, 0);
            last_tx = sqlite3_column_int64(st, 1);
            acc_rx = sqlite3_column_int64(st, 2);
            acc_tx = sqlite3_column_int64(st, 3);
            sample_count = sqlite3_column_int(st, 4);
            reset_count = sqlite3_column_int(st, 5);
            have = 1;
        }
        sqlite3_finalize(st);
    }

    if (!have) {
        if (db_prepare(&st,
            "INSERT INTO dashboard_daily_usage_counter("
            "day_start,wan_id,baseline_ts,baseline_rx_bytes,baseline_tx_bytes,"
            "last_ts,last_rx_bytes,last_tx_bytes,rx_bytes,tx_bytes,sample_count,reset_count,updated_at) "
            "VALUES(?1,?2,?3,?4,?5,?3,?4,?5,0,0,1,0,?3) "
            "ON CONFLICT(day_start,wan_id) DO NOTHING") != 0)
            return -1;
        sqlite3_bind_int64(st, 1, day_start);
        sqlite3_bind_text(st, 2, wan_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, now);
        sqlite3_bind_int64(st, 4, (sqlite3_int64)rx_bytes);
        sqlite3_bind_int64(st, 5, (sqlite3_int64)tx_bytes);
        rc = db_step_done(st);
        sqlite3_finalize(st);
        return rc;
    }

    if ((int64_t)rx_bytes >= last_rx)
        acc_rx += (int64_t)rx_bytes - last_rx;
    else {
        acc_rx += (int64_t)rx_bytes;
        reset_count++;
    }
    if ((int64_t)tx_bytes >= last_tx)
        acc_tx += (int64_t)tx_bytes - last_tx;
    else {
        acc_tx += (int64_t)tx_bytes;
        reset_count++;
    }

    if (db_prepare(&st,
        "UPDATE dashboard_daily_usage_counter SET "
        "last_ts=?3,last_rx_bytes=?4,last_tx_bytes=?5,"
        "rx_bytes=?6,tx_bytes=?7,sample_count=sample_count+1,"
        "reset_count=?8,updated_at=?3 "
        "WHERE day_start=?1 AND wan_id=?2") != 0)
        return -1;
    sqlite3_bind_int64(st, 1, day_start);
    sqlite3_bind_text(st, 2, wan_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, now);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)rx_bytes);
    sqlite3_bind_int64(st, 5, (sqlite3_int64)tx_bytes);
    sqlite3_bind_int64(st, 6, acc_rx < 0 ? 0 : acc_rx);
    sqlite3_bind_int64(st, 7, acc_tx < 0 ? 0 : acc_tx);
    sqlite3_bind_int(st, 8, reset_count);
    rc = db_step_done(st);
    sqlite3_finalize(st);
    return rc;
}

/* Lifetime WAN counters (schema v7).
 *
 * The kernel byte counters we sample live on the WAN's runtime device.  For
 * PPPoE that device is destroyed and recreated on every reconnect, so the
 * counter restarts from zero and any consumer reading it directly sees the
 * cumulative usage collapse.  We therefore keep a monotonic total per WAN:
 * every sample adds the forward delta, and a counter that moved backwards is
 * treated as a rebuild whose pre-reset total is already banked in base_*.
 *
 * This also covers 32-bit counter wrap, which is indistinguishable from a
 * rebuild at this layer.  Traffic that flowed while the interface was down is
 * unobservable and is not invented here.
 */
int jmx_db_update_wan_lifetime_usage(const char *wan_id,
                                     unsigned long long rx_bytes,
                                     unsigned long long tx_bytes,
                                     int online)
{
    sqlite3_stmt *st = NULL;
    int64_t now = now_s();
    int64_t last_rx = 0, last_tx = 0;
    int64_t base_rx = 0, base_tx = 0;
    int64_t last_reset_ts = 0;
    int reset_count = 0;
    int have = 0;
    int reset_seen = 0;
    int rc = -1;

    if (!wan_id || !wan_id[0])
        return -1;
    if (jmx_db_init() != 0)
        return -1;

    if (db_prepare(&st,
        "SELECT last_rx_bytes,last_tx_bytes,base_rx_bytes,base_tx_bytes,"
        "reset_count,last_reset_ts FROM wan_lifetime_usage WHERE wan_id=?1") == 0) {
        sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            last_rx = sqlite3_column_int64(st, 0);
            last_tx = sqlite3_column_int64(st, 1);
            base_rx = sqlite3_column_int64(st, 2);
            base_tx = sqlite3_column_int64(st, 3);
            reset_count = sqlite3_column_int(st, 4);
            last_reset_ts = sqlite3_column_int64(st, 5);
            have = 1;
        }
        sqlite3_finalize(st);
    }

    if (!have) {
        /* First observation: adopt the counter as-is.  It already reflects real
         * traffic on the current interface generation, so discarding it would
         * under-report; what we cannot know is anything from generations before
         * we started watching, and first_seen_ts says exactly that. */
        if (db_prepare(&st,
            "INSERT INTO wan_lifetime_usage("
            "wan_id,first_seen_ts,last_ts,last_rx_bytes,last_tx_bytes,"
            "base_rx_bytes,base_tx_bytes,reset_count,last_reset_ts,"
            "sample_count,updated_at) "
            "VALUES(?1,?2,?2,?3,?4,0,0,0,0,1,?2) "
            "ON CONFLICT(wan_id) DO NOTHING") != 0)
            return -1;
        sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, now);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)rx_bytes);
        sqlite3_bind_int64(st, 4, (sqlite3_int64)tx_bytes);
        rc = db_step_done(st);
        sqlite3_finalize(st);
        return rc;
    }

    /* An offline WAN keeps its banked total but must not fold a stale or zeroed
     * counter into the baseline; re-baseline instead and wait for it to return. */
    if (!online) {
        if ((int64_t)rx_bytes < last_rx || (int64_t)tx_bytes < last_tx) {
            base_rx += last_rx;
            base_tx += last_tx;
            reset_count++;
            last_reset_ts = now;
            reset_seen = 1;
        }
    } else if ((int64_t)rx_bytes < last_rx || (int64_t)tx_bytes < last_tx) {
        /* Counter went backwards on at least one direction: the device was
         * rebuilt (or wrapped).  Bank both directions together so rx and tx
         * stay on the same baseline generation. */
        base_rx += last_rx;
        base_tx += last_tx;
        reset_count++;
        last_reset_ts = now;
        reset_seen = 1;
    }

    if (db_prepare(&st,
        "UPDATE wan_lifetime_usage SET last_ts=?2,last_rx_bytes=?3,last_tx_bytes=?4,"
        "base_rx_bytes=?5,base_tx_bytes=?6,reset_count=?7,last_reset_ts=?8,"
        "sample_count=sample_count+1,updated_at=?2 WHERE wan_id=?1") != 0)
        return -1;
    sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)rx_bytes);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)tx_bytes);
    sqlite3_bind_int64(st, 5, base_rx < 0 ? 0 : base_rx);
    sqlite3_bind_int64(st, 6, base_tx < 0 ? 0 : base_tx);
    sqlite3_bind_int(st, 7, reset_count);
    sqlite3_bind_int64(st, 8, last_reset_ts);
    rc = db_step_done(st);
    sqlite3_finalize(st);
    (void)reset_seen;
    return rc;
}

int jmx_db_read_wan_lifetime_usage(const char *wan_id,
                                   struct jmx_wan_lifetime_usage *out)
{
    sqlite3_stmt *st = NULL;
    int found = 0;

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    if (!wan_id || !wan_id[0])
        return -1;
    if (jmx_db_init() != 0)
        return -1;
    if (db_prepare(&st,
        "SELECT first_seen_ts,last_ts,last_rx_bytes,last_tx_bytes,"
        "base_rx_bytes,base_tx_bytes,reset_count,last_reset_ts,sample_count "
        "FROM wan_lifetime_usage WHERE wan_id=?1") != 0)
        return -1;
    sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        int64_t last_rx = sqlite3_column_int64(st, 2);
        int64_t last_tx = sqlite3_column_int64(st, 3);
        int64_t base_rx = sqlite3_column_int64(st, 4);
        int64_t base_tx = sqlite3_column_int64(st, 5);

        out->first_seen_ts = sqlite3_column_int64(st, 0);
        out->last_ts = sqlite3_column_int64(st, 1);
        out->reset_count = sqlite3_column_int(st, 6);
        out->last_reset_ts = sqlite3_column_int64(st, 7);
        out->sample_count = sqlite3_column_int(st, 8);
        out->rx_bytes = (base_rx < 0 ? 0 : base_rx) + (last_rx < 0 ? 0 : last_rx);
        out->tx_bytes = (base_tx < 0 ? 0 : base_tx) + (last_tx < 0 ? 0 : last_tx);
        found = 1;
    }
    sqlite3_finalize(st);
    return found ? 0 : -1;
}

/* Emit a WAN's cumulative byte counters into a response object.
 *
 * Every caller that used to add up_bytes/down_bytes straight from the sampled
 * kernel counter goes through here, so a new response builder cannot quietly
 * reintroduce the PPPoE-reconnect zeroing. The raw counter is still published
 * as device_*_bytes because it is the honest answer to "this session".
 */
void jmx_db_add_wan_cumulative_bytes(struct json_object *out, const char *wan_id,
                                     int64_t device_rx_bytes,
                                     int64_t device_tx_bytes)
{
    struct jmx_wan_lifetime_usage lt;
    int64_t rx = device_rx_bytes < 0 ? 0 : device_rx_bytes;
    int64_t tx = device_tx_bytes < 0 ? 0 : device_tx_bytes;
    const char *source = "runtime_device_counter";

    if (!out)
        return;
    if (wan_id && wan_id[0] && jmx_db_read_wan_lifetime_usage(wan_id, &lt) == 0) {
        /* The lifetime total is a superset of the current counter by
         * construction; never report less than the device shows. */
        if (lt.rx_bytes > rx)
            rx = lt.rx_bytes;
        if (lt.tx_bytes > tx)
            tx = lt.tx_bytes;
        source = "persisted_lifetime_counter";
        json_object_object_add(out, "counter_since", json_object_new_int64(lt.first_seen_ts));
        json_object_object_add(out, "counter_reset_detected",
                               json_object_new_boolean(lt.reset_count > 0));
        json_object_object_add(out, "counter_reset_count", json_object_new_int(lt.reset_count));
        json_object_object_add(out, "counter_last_reset_at",
                               json_object_new_int64(lt.last_reset_ts));
    } else {
        /* No persisted history, so the raw counter is all we have.  Say so
         * instead of implying it covers the interface's whole life. */
        json_object_object_add(out, "counter_since", json_object_new_int64(0));
        json_object_object_add(out, "counter_reset_detected", json_object_new_boolean(0));
        json_object_object_add(out, "counter_reset_count", json_object_new_int(0));
        json_object_object_add(out, "counter_last_reset_at", json_object_new_int64(0));
    }
    json_object_object_add(out, "up_bytes", json_object_new_int64(tx));
    json_object_object_add(out, "down_bytes", json_object_new_int64(rx));
    json_object_object_add(out, "device_up_bytes", json_object_new_int64(device_tx_bytes));
    json_object_object_add(out, "device_down_bytes", json_object_new_int64(device_rx_bytes));
    json_object_object_add(out, "bytes_source", json_object_new_string(source));
}

static int jmx_db_usage_counter_all_wans(int64_t start, int64_t end,
                                         int64_t *up_bytes,
                                         int64_t *down_bytes,
                                         int64_t *total_bytes,
                                         int *sample_count,
                                         int64_t *earliest_baseline_ts,
                                         int *partial)
{
    sqlite3_stmt *st = NULL;
    int64_t up = 0, down = 0;
    int64_t earliest = 0;
    int samples = 0, rows = 0, partial_rows = 0;

    if (up_bytes) *up_bytes = 0;
    if (down_bytes) *down_bytes = 0;
    if (total_bytes) *total_bytes = 0;
    if (sample_count) *sample_count = 0;
    if (earliest_baseline_ts) *earliest_baseline_ts = 0;
    if (partial) *partial = 0;
    if (start <= 0 || end <= start)
        return -1;
    if (jmx_db_init() != 0)
        return -1;

    if (db_prepare(&st,
        "SELECT wan_id,baseline_ts,rx_bytes,tx_bytes,sample_count "
        "FROM dashboard_daily_usage_counter "
        "WHERE day_start=?1 AND wan_id<>'global' AND sample_count>=2") != 0)
        return -1;
    sqlite3_bind_int64(st, 1, start);
    while (sqlite3_step(st) == SQLITE_ROW) {
        int64_t baseline_ts = sqlite3_column_int64(st, 1);
        int64_t rx = sqlite3_column_int64(st, 2);
        int64_t tx = sqlite3_column_int64(st, 3);
        int sc = sqlite3_column_int(st, 4);

        (void)sqlite3_column_text(st, 0);
        if (rx < 0) rx = 0;
        if (tx < 0) tx = 0;
        down += rx;
        up += tx;
        samples += sc;
        rows++;
        if (baseline_ts > start + 300)
            partial_rows++;
        if (earliest == 0 || (baseline_ts > 0 && baseline_ts < earliest))
            earliest = baseline_ts;
    }
    sqlite3_finalize(st);

    if (rows <= 0)
        return -1;
    if (up_bytes) *up_bytes = up;
    if (down_bytes) *down_bytes = down;
    if (total_bytes) *total_bytes = up + down;
    if (sample_count) *sample_count = samples;
    if (earliest_baseline_ts) *earliest_baseline_ts = earliest;
    if (partial) *partial = partial_rows > 0;
    return 0;
}

static int jmx_db_usage_integrate_window(const char *wan_id, int64_t start,
                                         int64_t end, int64_t max_gap_sec,
                                         int64_t *up_bytes,
                                         int64_t *down_bytes,
                                         int64_t *total_bytes,
                                         int *sample_count)
{
    sqlite3_stmt *st = NULL;
    int64_t prev_ts = 0, prev_up = 0, prev_down = 0;
    int64_t up = 0, down = 0;
    int samples = 0;
    int rc = -1;

    if (up_bytes) *up_bytes = 0;
    if (down_bytes) *down_bytes = 0;
    if (total_bytes) *total_bytes = 0;
    if (sample_count) *sample_count = 0;
    if (!wan_id || !wan_id[0] || start <= 0 || end <= start)
        return -1;
    if (jmx_db_init() != 0)
        return -1;
    if (max_gap_sec <= 0)
        max_gap_sec = 300;

    if (db_prepare(&st,
        "SELECT ts,up_rate,down_rate "
        "FROM dashboard_activity_sample "
        "WHERE ts>=?1 AND ts<=?2 AND wan_id=?3 "
        "ORDER BY ts ASC") != 0)
        return -1;
    sqlite3_bind_int64(st, 1, start);
    sqlite3_bind_int64(st, 2, end);
    sqlite3_bind_text(st, 3, wan_id, -1, SQLITE_TRANSIENT);

    while (sqlite3_step(st) == SQLITE_ROW) {
        int64_t ts = sqlite3_column_int64(st, 0);
        int64_t cur_up = sqlite3_column_int64(st, 1);
        int64_t cur_down = sqlite3_column_int64(st, 2);
        samples++;
        if (prev_ts > 0 && ts > prev_ts) {
            int64_t dt = ts - prev_ts;
            /* Do not bridge long collection gaps as real traffic. */
            if (dt <= max_gap_sec) {
                if (prev_up < 0) prev_up = 0;
                if (cur_up < 0) cur_up = 0;
                if (prev_down < 0) prev_down = 0;
                if (cur_down < 0) cur_down = 0;
                up += ((prev_up + cur_up) * dt) / 2;
                down += ((prev_down + cur_down) * dt) / 2;
            }
        }
        prev_ts = ts;
        prev_up = cur_up;
        prev_down = cur_down;
    }
    sqlite3_finalize(st);

    if (samples >= 2) {
        if (up_bytes) *up_bytes = up < 0 ? 0 : up;
        if (down_bytes) *down_bytes = down < 0 ? 0 : down;
        if (total_bytes) *total_bytes = (up < 0 ? 0 : up) + (down < 0 ? 0 : down);
        if (sample_count) *sample_count = samples;
        rc = 0;
    }
    return rc;
}

static int jmx_db_usage_integrate_all_wans(int64_t start, int64_t end,
                                           int64_t max_gap_sec,
                                           int64_t *up_bytes,
                                           int64_t *down_bytes,
                                           int64_t *total_bytes,
                                           int *sample_count)
{
    sqlite3_stmt *st = NULL;
    int64_t total_up = 0, total_down = 0;
    int total_samples = 0;
    int wan_count = 0;

    if (up_bytes) *up_bytes = 0;
    if (down_bytes) *down_bytes = 0;
    if (total_bytes) *total_bytes = 0;
    if (sample_count) *sample_count = 0;
    if (start <= 0 || end <= start)
        return -1;
    if (jmx_db_init() != 0)
        return -1;

    if (db_prepare(&st,
        "SELECT wan_id "
        "FROM dashboard_activity_sample "
        "WHERE ts>=?1 AND ts<=?2 AND wan_id<>'global' "
        "GROUP BY wan_id HAVING COUNT(*)>=2 "
        "ORDER BY wan_id ASC") != 0)
        return -1;
    sqlite3_bind_int64(st, 1, start);
    sqlite3_bind_int64(st, 2, end);

    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *id = (const char *)sqlite3_column_text(st, 0);
        char wan_id[64];
        int64_t up = 0, down = 0, sum = 0;
        int samples = 0;

        if (!id || !id[0])
            continue;
        snprintf(wan_id, sizeof(wan_id), "%s", id);
        if (jmx_db_usage_integrate_window(wan_id, start, end, max_gap_sec,
                                          &up, &down, &sum, &samples) == 0 &&
            samples >= 2) {
            total_up += up;
            total_down += down;
            total_samples += samples;
            wan_count++;
        }
    }
    sqlite3_finalize(st);

    if (wan_count <= 0)
        return -1;
    if (up_bytes) *up_bytes = total_up;
    if (down_bytes) *down_bytes = total_down;
    if (total_bytes) *total_bytes = total_up + total_down;
    if (sample_count) *sample_count = total_samples;
    return 0;
}

int jmx_db_today_usage_estimate(const char *wan_id, int allow_global_fallback,
                                int64_t *up_bytes, int64_t *down_bytes,
                                int64_t *total_bytes, int *sample_count,
                                int64_t *period_start, int64_t *period_end,
                                char *source, size_t source_len)
{
    const char *wanted = (wan_id && wan_id[0]) ? wan_id : "global";
    int64_t now = now_s();
    int64_t start = jmx_db_local_day_start(now);
    int rc;

    if (up_bytes) *up_bytes = 0;
    if (down_bytes) *down_bytes = 0;
    if (total_bytes) *total_bytes = 0;
    if (sample_count) *sample_count = 0;
    if (period_start) *period_start = start;
    if (period_end) *period_end = now;
    if (source && source_len) source[0] = '\0';

    if (!strcmp(wanted, "all_wans") || !strcmp(wanted, "*")) {
        int64_t c_up = 0, c_down = 0, c_total = 0, c_base = 0;
        int64_t s_up = 0, s_down = 0, s_total = 0;
        int c_samples = 0, s_samples = 0, c_partial = 0;
        int c_rc = jmx_db_usage_counter_all_wans(start, now,
                                                 &c_up, &c_down, &c_total,
                                                 &c_samples, &c_base, &c_partial);
        int s_rc = jmx_db_usage_integrate_all_wans(start, now, 300,
                                                   &s_up, &s_down, &s_total,
                                                   &s_samples);

        if (c_rc == 0 && (!c_partial || s_rc != 0 || c_total >= s_total)) {
            if (up_bytes) *up_bytes = c_up;
            if (down_bytes) *down_bytes = c_down;
            if (total_bytes) *total_bytes = c_total;
            if (sample_count) *sample_count = c_samples;
            if (source && source_len)
                snprintf(source, source_len, "%s",
                         c_partial ? "dashboard_daily_counter_partial_wan_sum_today" :
                                     "dashboard_daily_counter_wan_sum_today");
            return 0;
        }
        if (s_rc == 0) {
            if (up_bytes) *up_bytes = s_up;
            if (down_bytes) *down_bytes = s_down;
            if (total_bytes) *total_bytes = s_total;
            if (sample_count) *sample_count = s_samples;
            if (source && source_len)
                snprintf(source, source_len, "%s", "dashboard_activity_sample_wan_sum_today");
            return 0;
        }
        rc = c_rc == 0 ? 0 : s_rc;
        if (!allow_global_fallback)
            return rc;
        wanted = "global";
    }

    rc = jmx_db_usage_integrate_window(wanted, start, now, 300,
                                       up_bytes, down_bytes, total_bytes,
                                       sample_count);
    if (rc != 0 && allow_global_fallback && strcmp(wanted, "global")) {
        rc = jmx_db_usage_integrate_window("global", start, now, 300,
                                           up_bytes, down_bytes, total_bytes,
                                           sample_count);
        if (rc == 0 && source && source_len)
            snprintf(source, source_len, "%s", "dashboard_activity_sample_global_fallback");
        return rc;
    }
    if (rc == 0 && source && source_len)
        snprintf(source, source_len, "%s", "dashboard_activity_sample_integrated_today");
    return rc;
}

int jmx_db_monthly_usage_estimate(const char *wan_id, int allow_global_fallback,
                                  int64_t *up_bytes, int64_t *down_bytes,
                                  int64_t *total_bytes, int *sample_count,
                                  int64_t *period_start, int64_t *period_end,
                                  char *source, size_t source_len)
{
    const char *wanted = (wan_id && wan_id[0]) ? wan_id : "global";
    int64_t now = now_s();
    int64_t start = now - 30LL * 86400LL;
    int64_t up = 0, down = 0;
    int samples = 0;
    int rc = -1;

    if (up_bytes) *up_bytes = 0;
    if (down_bytes) *down_bytes = 0;
    if (total_bytes) *total_bytes = 0;
    if (sample_count) *sample_count = 0;
    if (period_start) *period_start = start;
    if (period_end) *period_end = now;
    if (source && source_len) source[0] = '\0';
    rc = jmx_db_usage_integrate_window(wanted, start, now, 300,
                                       &up, &down, NULL, &samples);

    if (rc != 0 && allow_global_fallback && strcmp(wanted, "global")) {
        rc = jmx_db_monthly_usage_estimate("global", 0, up_bytes, down_bytes,
                                           total_bytes, sample_count,
                                           period_start, period_end,
                                           NULL, 0);
        if (rc == 0 && source && source_len)
            snprintf(source, source_len, "%s", "dashboard_activity_sample_global_fallback");
        return rc;
    }

    if (rc == 0) {
        if (up < 0) up = 0;
        if (down < 0) down = 0;
        if (up_bytes) *up_bytes = up;
        if (down_bytes) *down_bytes = down;
        if (total_bytes) *total_bytes = up + down;
        if (sample_count) *sample_count = samples;
        if (period_start) *period_start = start;
        if (period_end) *period_end = now;
        if (source && source_len)
            snprintf(source, source_len, "%s", "dashboard_activity_sample_integrated");
    }
    return rc;
}

struct json_object *jmx_db_api_activity(struct json_object *req)
{
    struct json_object *data = json_object_new_object();
    struct json_object *buckets = json_object_new_array();
    const char *range = "1d";
    int64_t now = now_s();
    int64_t start_ts, bucket_sec, retention_sec;
    sqlite3_stmt *st = NULL;
    int has_data = 0;
    struct json_object *rv = NULL;
    const char *wan_id = "";
    const char *query_wan_id = "global";
    int wan_filter = 0;

    if (req) {
        rv = NULL;
        if (json_object_object_get_ex(req, "range", &rv) && rv)
            range = json_object_get_string(rv);
        rv = NULL;
        if (json_object_object_get_ex(req, "wan_id", &rv) && rv)
            wan_id = json_object_get_string(rv);
        if ((!wan_id || !wan_id[0]) && json_object_object_get_ex(req, "ifname", &rv) && rv)
            wan_id = json_object_get_string(rv);
    }
    if (!range) range = "1d";
    if (!wan_id) wan_id = "";
    wan_filter = wan_id[0] && strcmp(wan_id, "all") && strcmp(wan_id, "global");
    query_wan_id = wan_filter ? wan_id : "global";

    /* Determine time range and aggregation bucket */
    if (!strcmp(range, "1h")) {
        retention_sec = 3600;
        bucket_sec = 60;
    } else if (!strcmp(range, "1d")) {
        retention_sec = 86400;
        bucket_sec = 300;
    } else if (!strcmp(range, "1w")) {
        retention_sec = 7 * 86400;
        bucket_sec = 3600;
    } else if (!strcmp(range, "1m")) {
        retention_sec = 30 * 86400;
        bucket_sec = 86400;
    } else {
        retention_sec = 86400;
        bucket_sec = 300;
        range = "1d";
    }
    start_ts = now - retention_sec;

    json_object_object_add(data, "ts", json_object_new_int64(now));
    json_object_object_add(data, "range", json_object_new_string(range));
    json_object_object_add(data, "wan_id", json_object_new_string(wan_filter ? wan_id : ""));
    json_object_object_add(data, "scope", json_object_new_string(wan_filter ? "wan" : "global"));
    json_object_object_add(data, "start_ts", json_object_new_int64(start_ts));
    json_object_object_add(data, "end_ts", json_object_new_int64(now));
    json_object_object_add(data, "bucket_sec", json_object_new_int64(bucket_sec));
    json_object_object_add(data, "retention_sec", json_object_new_int64(retention_sec));
    json_object_object_add(data, "unit", json_object_new_string("B/s"));
    json_object_object_add(data, "latency_unit", json_object_new_string("ms"));

    if (jmx_db_init() == 0 && db_prepare(&st,
        "SELECT "
        " (ts / ?3) * ?3 AS bucket_ts,"
        " AVG(up_rate), MAX(up_rate),"
        " AVG(down_rate), MAX(down_rate),"
        " AVG(connections), MAX(connections),"
        " AVG(CASE WHEN latency_avg > 0 THEN latency_avg END),"
        " MIN(CASE WHEN latency_min > 0 THEN latency_min END),"
        " MAX(CASE WHEN latency_max > 0 THEN latency_max END),"
        " COUNT(*)"
        " FROM dashboard_activity_sample"
        " WHERE ts >= ?1 AND ts <= ?2"
        " AND wan_id=?4"
        " GROUP BY bucket_ts"
        " ORDER BY bucket_ts ASC") == 0) {
        sqlite3_bind_int64(st, 1, start_ts);
        sqlite3_bind_int64(st, 2, now);
        sqlite3_bind_int64(st, 3, bucket_sec);
        sqlite3_bind_text(st, 4, query_wan_id, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *b = json_object_new_object();
            json_object_object_add(b, "ts", json_object_new_int64(sqlite3_column_int64(st, 0)));
            json_object_object_add(b, "up_avg", json_object_new_int64(sqlite3_column_int64(st, 1)));
            json_object_object_add(b, "up_max", json_object_new_int64(sqlite3_column_int64(st, 2)));
            json_object_object_add(b, "down_avg", json_object_new_int64(sqlite3_column_int64(st, 3)));
            json_object_object_add(b, "down_max", json_object_new_int64(sqlite3_column_int64(st, 4)));
            json_object_object_add(b, "connections", json_object_new_int64(sqlite3_column_int64(st, 5)));
            json_object_object_add(b, "connections_avg", json_object_new_int64(sqlite3_column_int64(st, 5)));
            json_object_object_add(b, "connections_max", json_object_new_int64(sqlite3_column_int64(st, 6)));
            if (sqlite3_column_type(st, 7) != SQLITE_NULL)
                json_object_object_add(b, "latency_avg", json_object_new_double(sqlite3_column_double(st, 7)));
            if (sqlite3_column_type(st, 8) != SQLITE_NULL)
                json_object_object_add(b, "latency_min", json_object_new_double(sqlite3_column_double(st, 8)));
            if (sqlite3_column_type(st, 9) != SQLITE_NULL)
                json_object_object_add(b, "latency_max", json_object_new_double(sqlite3_column_double(st, 9)));
            json_object_object_add(b, "sample_count", json_object_new_int(sqlite3_column_int(st, 10)));
            json_object_array_add(buckets, b);
            has_data = 1;
        }
        sqlite3_finalize(st);
    }

    if (!has_data) {
        json_object_object_add(data, "degraded", json_object_new_boolean(1));
        json_object_object_add(data, "missing", json_object_new_string("no historical samples yet"));
    }
    json_object_object_add(data, "buckets", buckets);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

/* ── system_health_sample: persistent load monitoring history ── */

static double db_clamp_percent(double v)
{
    if (v < 0.0)
        return 0.0;
    if (v > 100.0)
        return 100.0;
    return v;
}

void jmx_db_write_system_health_sample(double cpu_percent, double mem_percent,
                                       double disk_percent, int connections,
                                       int forward_pps, int client_num,
                                       int64_t rx_packets_delta,
                                       int64_t tx_packets_delta,
                                       int counter_reset)
{
    int64_t ts;
    sqlite3_stmt *st = NULL;
    int64_t forward_packets_delta = 0;

    if (!jmx_storage_guard_allow("/", JMX_STORAGE_WRITE_BULK, NULL))
        return;
    if (jmx_db_init() != 0)
        return;

    ts = now_s();
    /* 10s raw buckets; API performs range-specific downsampling. */
    ts = (ts / 10) * 10;
    if (rx_packets_delta < 0)
        rx_packets_delta = 0;
    if (tx_packets_delta < 0)
        tx_packets_delta = 0;
    forward_packets_delta = rx_packets_delta + tx_packets_delta;

    if (db_prepare(&st,
        "INSERT INTO system_health_sample(ts,cpu_percent,mem_percent,disk_percent,connections,forward_pps,client_num,rx_packets,tx_packets,forward_packets,counter_reset) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11) "
        "ON CONFLICT(ts) DO UPDATE SET "
        "cpu_percent=excluded.cpu_percent,"
        "mem_percent=excluded.mem_percent,"
        "disk_percent=excluded.disk_percent,"
        "connections=excluded.connections,"
        "forward_pps=excluded.forward_pps,"
        "client_num=excluded.client_num,"
        "rx_packets=excluded.rx_packets,"
        "tx_packets=excluded.tx_packets,"
        "forward_packets=excluded.forward_packets,"
        "counter_reset=excluded.counter_reset") != 0)
        return;
    sqlite3_bind_int64(st, 1, ts);
    sqlite3_bind_double(st, 2, db_clamp_percent(cpu_percent));
    sqlite3_bind_double(st, 3, db_clamp_percent(mem_percent));
    sqlite3_bind_double(st, 4, db_clamp_percent(disk_percent));
    sqlite3_bind_int(st, 5, connections >= 0 ? connections : 0);
    sqlite3_bind_int(st, 6, forward_pps >= 0 ? forward_pps : 0);
    sqlite3_bind_int(st, 7, client_num >= 0 ? client_num : 0);
    sqlite3_bind_int64(st, 8, rx_packets_delta);
    sqlite3_bind_int64(st, 9, tx_packets_delta);
    sqlite3_bind_int64(st, 10, forward_packets_delta);
    sqlite3_bind_int(st, 11, counter_reset ? 1 : 0);
    db_step_done(st);
    sqlite3_finalize(st);
}

int jmx_db_prune_system_health_samples(int64_t max_age_sec)
{
    int64_t cutoff;
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (jmx_db_init() != 0)
        return -1;
    if (max_age_sec <= 0)
        max_age_sec = 31 * 86400;
    cutoff = now_s() - max_age_sec;
    if (db_prepare(&st, "DELETE FROM system_health_sample WHERE ts < ?1") == 0) {
        sqlite3_bind_int64(st, 1, cutoff);
        rc = db_step_done(st);
        sqlite3_finalize(st);
    }
    return rc;
}

struct json_object *jmx_db_api_system_health_history(struct json_object *req)
{
    struct json_object *data = json_object_new_object();
    struct json_object *points = json_object_new_array();
    const char *range = db_json_string_def(req, "range", "1h");
    int64_t now = now_s();
    int64_t retention_sec;
    int64_t bucket_sec;
    int64_t start_ts;
    sqlite3_stmt *st = NULL;
    int has_data = 0;

    if (!range || !range[0])
        range = "1h";
    if (!strcmp(range, "1h")) {
        retention_sec = 3600;
        bucket_sec = 60;
    } else if (!strcmp(range, "1d")) {
        retention_sec = 86400;
        bucket_sec = 300;
    } else if (!strcmp(range, "1w") || !strcmp(range, "7d")) {
        retention_sec = 7 * 86400;
        bucket_sec = 3600;
        range = "7d";
    } else if (!strcmp(range, "1m") || !strcmp(range, "30d")) {
        retention_sec = 30 * 86400;
        bucket_sec = 86400;
        range = "30d";
    } else {
        retention_sec = 3600;
        bucket_sec = 60;
        range = "1h";
    }
    start_ts = now - retention_sec;

    json_object_object_add(data, "range", json_object_new_string(range));
    json_object_object_add(data, "ts", json_object_new_int64(now));
    json_object_object_add(data, "start_ts", json_object_new_int64(start_ts));
    json_object_object_add(data, "end_ts", json_object_new_int64(now));
    json_object_object_add(data, "bucket_sec", json_object_new_int64(bucket_sec));
    json_object_object_add(data, "retention_sec", json_object_new_int64(retention_sec));
    json_object_object_add(data, "unit", json_object_new_string("percent"));
    json_object_object_add(data, "packet_unit", json_object_new_string("packets_per_bucket"));
    json_object_object_add(data, "forward_pps_unit", json_object_new_string("pps"));
    json_object_object_add(data, "source", json_object_new_string("system_health_sample"));

    if (jmx_db_init() == 0 && db_prepare(&st,
        "SELECT "
        " (ts / ?3) * ?3 AS bucket_ts,"
        " AVG(cpu_percent), MAX(cpu_percent),"
        " AVG(mem_percent), MAX(mem_percent),"
        " AVG(disk_percent), MAX(disk_percent),"
        " AVG(connections), MAX(connections),"
        " AVG(forward_pps), MAX(forward_pps),"
        " AVG(client_num), MAX(client_num),"
        " SUM(rx_packets), SUM(tx_packets), SUM(forward_packets),"
        " AVG(forward_packets), MAX(forward_packets), MAX(counter_reset),"
        " COUNT(*)"
        " FROM system_health_sample"
        " WHERE ts >= ?1 AND ts <= ?2"
        " GROUP BY bucket_ts"
        " ORDER BY bucket_ts ASC") == 0) {
        sqlite3_bind_int64(st, 1, start_ts);
        sqlite3_bind_int64(st, 2, now);
        sqlite3_bind_int64(st, 3, bucket_sec);
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *p = json_object_new_object();
            json_object_object_add(p, "ts", json_object_new_int64(sqlite3_column_int64(st, 0)));
            json_object_object_add(p, "cpu_percent", json_object_new_double(sqlite3_column_double(st, 1)));
            json_object_object_add(p, "cpu_avg", json_object_new_double(sqlite3_column_double(st, 1)));
            json_object_object_add(p, "cpu_max", json_object_new_double(sqlite3_column_double(st, 2)));
            json_object_object_add(p, "mem_percent", json_object_new_double(sqlite3_column_double(st, 3)));
            json_object_object_add(p, "mem_avg", json_object_new_double(sqlite3_column_double(st, 3)));
            json_object_object_add(p, "mem_max", json_object_new_double(sqlite3_column_double(st, 4)));
            json_object_object_add(p, "disk_percent", json_object_new_double(sqlite3_column_double(st, 5)));
            json_object_object_add(p, "disk_avg", json_object_new_double(sqlite3_column_double(st, 5)));
            json_object_object_add(p, "disk_max", json_object_new_double(sqlite3_column_double(st, 6)));
            json_object_object_add(p, "connections", json_object_new_int64(sqlite3_column_int64(st, 7)));
            json_object_object_add(p, "connections_avg", json_object_new_int64(sqlite3_column_int64(st, 7)));
            json_object_object_add(p, "connections_max", json_object_new_int64(sqlite3_column_int64(st, 8)));
            json_object_object_add(p, "forward_pps", json_object_new_int64(sqlite3_column_int64(st, 9)));
            json_object_object_add(p, "forward_pps_avg", json_object_new_int64(sqlite3_column_int64(st, 9)));
            json_object_object_add(p, "forward_pps_max", json_object_new_int64(sqlite3_column_int64(st, 10)));
            json_object_object_add(p, "client_num", json_object_new_int64(sqlite3_column_int64(st, 11)));
            json_object_object_add(p, "client_num_avg", json_object_new_int64(sqlite3_column_int64(st, 11)));
            json_object_object_add(p, "client_num_max", json_object_new_int64(sqlite3_column_int64(st, 12)));
            json_object_object_add(p, "rx_packets", json_object_new_int64(sqlite3_column_int64(st, 13)));
            json_object_object_add(p, "tx_packets", json_object_new_int64(sqlite3_column_int64(st, 14)));
            json_object_object_add(p, "forward_packets", json_object_new_int64(sqlite3_column_int64(st, 15)));
            json_object_object_add(p, "forward_packets_avg", json_object_new_int64(sqlite3_column_int64(st, 16)));
            json_object_object_add(p, "forward_packets_max", json_object_new_int64(sqlite3_column_int64(st, 17)));
            json_object_object_add(p, "counter_reset", json_object_new_boolean(sqlite3_column_int(st, 18) > 0));
            json_object_object_add(p, "packet_unit", json_object_new_string("packets_per_bucket"));
            json_object_object_add(p, "sample_count", json_object_new_int(sqlite3_column_int(st, 19)));
            json_object_array_add(points, p);
            has_data = 1;
        }
        sqlite3_finalize(st);
    }

    if (!has_data) {
        json_object_object_add(data, "degraded", json_object_new_boolean(1));
        json_object_object_add(data, "missing", json_object_new_string("no historical system health samples yet"));
    }
    json_object_object_add(data, "points", points);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

sqlite3 *jmx_db_handle(void)
{
    if (!g_db) jmx_db_init();
    return g_db;
}

static int db_observe_json(struct json_object *req, int64_t *out_id)
{
    char mac[32] = {0};
    const char *raw_mac = json_s(req, "mac", "");
    const char *hostname = json_s(req, "hostname", "");
    const char *vendor = json_s(req, "vendor", "");
    const char *oui = json_s(req, "oui", "");
    const char *device_type = json_s(req, "device_type", "unknown");
    const char *os_name = json_s(req, "os_name", "");
    int64_t client_id = 0;
    int64_t ts = now_s();
    struct json_object *ns = NULL, *fp = NULL, *aliases = NULL;
    int i;

    if (normalize_mac(raw_mac, mac, sizeof(mac)) != 0) return -1;
    if (db_upsert_client(mac, hostname, hostname, vendor, oui, device_type, os_name,
                         json_i(req, "is_wired", 0), ts, &client_id) != 0)
        return -1;
    if (hostname && hostname[0])
        db_upsert_alias(client_id, "hostname", hostname, "jmxd", 0.6, ts);
    if (json_object_object_get_ex(req, "network_state", &ns) && ns)
        db_upsert_network_state(client_id, ns);
    if (json_object_object_get_ex(req, "fingerprint", &fp) && fp)
        db_upsert_fingerprint(client_id, fp);
    if (json_object_object_get_ex(req, "aliases", &aliases) && aliases && json_object_is_type(aliases, json_type_array)) {
        for (i = 0; i < json_object_array_length(aliases); i++) {
            struct json_object *a = json_object_array_get_idx(aliases, i);
            db_upsert_alias(client_id, json_s(a, "type", "hostname"), json_s(a, "value", ""), json_s(a, "source", "jmxd"), json_d(a, "confidence", 0.5), ts);
        }
    }
    if (out_id) *out_id = client_id;
    return 0;
}

int jmx_db_sync_clients_from_memory(void)
{
    client_node_t *c = NULL;
    int count = 0;
    if (!jmx_storage_guard_allow("/", JMX_STORAGE_WRITE_BULK, NULL))
        return 0;
    if (jmx_db_init() != 0) return -1;
    if (db_begin() != 0) return -1;
    /* Import captured DHCP signals from sniffer ring buffer */
    {
        dhcp_signal_t dsig[32];
        int dcount = dhcp_sniff_consume(dsig, 32);
        for (int di = 0; di < dcount; di++) {
            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                dsig[di].mac[0], dsig[di].mac[1], dsig[di].mac[2],
                dsig[di].mac[3], dsig[di].mac[4], dsig[di].mac[5]);
            if (dsig[di].option55[0])
                db_upsert_identity_signal(mac_str, "dhcp-packet", "dhcp_option55", dsig[di].option55, 70, "", (int64_t)dsig[di].timestamp);
            if (dsig[di].vendor_class[0])
                db_upsert_identity_signal(mac_str, "dhcp-packet", "dhcp_vendor_class", dsig[di].vendor_class, 60, "", (int64_t)dsig[di].timestamp);
        }
    }

    list_for_each_entry(c, &client_list, client) {
        char mac[32] = {0};
        int64_t cid = 0;
        struct json_object *ns;
        if (normalize_mac(c->mac, mac, sizeof(mac)) != 0) continue;
        const char *vendor = db_vendor_from_mac_text(mac);
        const char *dtype = db_guess_type_from_hostname(c->hostname);
        const char *osn = db_guess_os_from_hostname(c->hostname);
        char oui[9] = {0};
        snprintf(oui, sizeof(oui), "%.8s", mac);
        if (db_upsert_client(mac, c->hostname, c->nickname[0] ? c->nickname : c->hostname,
                             vendor, oui, dtype, osn, 0,
                             c->online ? now_s() : (int64_t)c->offline_time, &cid) != 0)
            continue;
        if (c->hostname[0]) db_upsert_alias(cid, "dhcp_hostname", c->hostname, "jmxd-client-list", 0.7, now_s());
        if (c->hostname[0]) db_upsert_identity_signal(mac, "jmxd-client-list", "dhcp_hostname", c->hostname, 70, "", now_s());
        if (vendor && vendor[0]) db_upsert_alias(cid, "vendor", vendor, "oui", 0.25, now_s());
        if (vendor && vendor[0]) db_upsert_identity_signal(mac, "oui", "vendor", vendor, 25, "", now_s());
        if (dtype && strcmp(dtype, "unknown")) db_upsert_alias(cid, "device_type", dtype, "hostname-pattern", 0.55, now_s());
        if (dtype && strcmp(dtype, "unknown")) db_upsert_identity_signal(mac, "hostname-pattern", "device_type", dtype, 55, "", now_s());
        if (osn && osn[0]) db_upsert_alias(cid, "os_name", osn, "hostname-pattern", 0.55, now_s());
        if (osn && osn[0]) db_upsert_identity_signal(mac, "hostname-pattern", "os_name", osn, 55, "", now_s());
        /* Signature DB model matching: match hostname against fingerprint rules */
        {
            const char *hn = c->hostname[0] ? c->hostname : NULL;
            if (!hn) {
                sqlite3_stmt *hn_st = NULL;
                if (g_db && sqlite3_prepare_v2(g_db, "SELECT hostname FROM clients WHERE mac=?1 LIMIT 1", -1, &hn_st, NULL) == SQLITE_OK) {
                    sqlite3_bind_text(hn_st, 1, mac, -1, SQLITE_TRANSIENT);
                    if (sqlite3_step(hn_st) == SQLITE_ROW) {
                        hn = (const char *)sqlite3_column_text(hn_st, 0);
                    }
                    sqlite3_finalize(hn_st);
                }
            }
            if (hn && hn[0]) {
                sqlite3 *sdb = NULL;
                sqlite3_stmt *rst = NULL;
                char signature_path[512];
                if (db_signature_db_path(signature_path, sizeof(signature_path)) == 0 &&
                    sqlite3_open_v2(signature_path, &sdb, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                    if (sqlite3_prepare_v2(sdb,
                        "SELECT COALESCE(v.name,''), COALESCE(t.name,''), r.model, r.pattern, r.confidence "
                        "FROM device_fingerprint_rule r "
                        "LEFT JOIN device_vendor v ON v.vendor_id=r.vendor_id "
                        "LEFT JOIN device_type t ON t.type_id=r.type_id "
                        "WHERE r.enabled=1 AND r.match_type='hostname' AND ( "
                        "  (?1 = r.pattern) OR "
                        "  (?1 LIKE r.pattern||'%') OR "
                        "  (length(r.pattern) >= 4 AND ?1 LIKE '%'||r.pattern||'%') "
                        ") "
                        "ORDER BY r.confidence DESC, length(r.pattern) DESC LIMIT 1",
                        -1, &rst, NULL) == SQLITE_OK) {
                        sqlite3_bind_text(rst, 1, hn, -1, SQLITE_TRANSIENT);
                        if (sqlite3_step(rst) == SQLITE_ROW) {
                            const char *r_vendor = (const char *)sqlite3_column_text(rst, 0);
                            const char *r_type = (const char *)sqlite3_column_text(rst, 1);
                            const char *r_model = (const char *)sqlite3_column_text(rst, 2);
                            double r_conf = sqlite3_column_double(rst, 4);
                            if (r_model && r_model[0] && r_conf >= 60 && strcmp(r_model, "Unknown")) {
                                const char *mapped_type = "unknown";
                                if (r_type && r_type[0]) {
                                    if (strstr(r_type, "手机") || strstr(r_type, "smartphone")) mapped_type = "smartphone";
                                    else if (strstr(r_type, "电脑") || strstr(r_type, "computer")) mapped_type = "computer";
                                    else if (strstr(r_type, "平板") || strstr(r_type, "tablet")) mapped_type = "tablet";
                                    else if (strstr(r_type, "电视") || strstr(r_type, "tv")) mapped_type = "tv";
                                    else if (strstr(r_type, "路由") || strstr(r_type, "router")) mapped_type = "router";
                                    else if (strstr(r_type, "NAS")) mapped_type = "nas";
                                    else if (strstr(r_type, "打印") || strstr(r_type, "printer")) mapped_type = "printer";
                                    else if (strstr(r_type, "摄像") || strstr(r_type, "camera")) mapped_type = "camera";
                                    else if (strstr(r_type, "游戏") || strstr(r_type, "game")) mapped_type = "game_console";
                                    else if (strstr(r_type, "智能") || strstr(r_type, "iot")) mapped_type = "iot";
                                }
                                db_upsert_alias(cid, "model", r_model, "sig-db", r_conf/100.0, now_s());
                                if (r_vendor && r_vendor[0]) db_upsert_alias(cid, "vendor", r_vendor, "sig-db", r_conf/100.0, now_s());
                                if (strcmp(mapped_type, "unknown")) {
                                    db_upsert_alias(cid, "device_type", mapped_type, "sig-db", r_conf/100.0, now_s());
                                    db_upsert_identity_signal(mac, "sig-db", "device_type", mapped_type, (int)r_conf, "", now_s());
                                }
                                db_upsert_identity_signal(mac, "sig-db", "model", r_model, (int)r_conf, "", now_s());
                            }
                        }
                        sqlite3_finalize(rst);
                    }
                    sqlite3_close(sdb);
                }
            }
        }
        /* Huginn-Muninn external DB lookup (option 55) */
        {
            sqlite3_stmt *hst = NULL;
            if (g_db && sqlite3_prepare_v2(g_db,
                "SELECT value FROM client_identity_signals "
                "WHERE mac=?1 AND key='dhcp_option55' ORDER BY last_seen DESC LIMIT 1",
                -1, &hst, NULL) == SQLITE_OK) {
                sqlite3_bind_text(hst, 1, mac, -1, SQLITE_TRANSIENT);
                if (sqlite3_step(hst) == SQLITE_ROW) {
                    const char *opt55 = (const char *)sqlite3_column_text(hst, 0);
                    if (opt55 && opt55[0]) {
                        huginn_result_t hr;
                        if (huginn_lookup_by_option55(opt55, &hr) == 0) {
                            if (hr.device_name[0])
                                db_upsert_alias(cid, "model", hr.device_name, "huginn-muninn", 0.7, now_s());
                            if (hr.device_vendor[0])
                                db_upsert_alias(cid, "vendor", hr.device_vendor, "huginn-muninn", 0.6, now_s());
                            if (hr.device_type[0] && strcmp(hr.device_type, "Miscellaneous"))
                                db_upsert_alias(cid, "device_type", hr.device_type, "huginn-muninn", 0.6, now_s());
                        }
                    }
                }
                sqlite3_finalize(hst);
            }
        }
        if (c->nickname[0]) db_upsert_alias(cid, "user_label", c->nickname, "jmxd-nickname", 0.9, now_s());
        if (c->nickname[0]) db_upsert_identity_signal(mac, "jmxd-nickname", "user_label", c->nickname, 90, "", now_s());
        ns = json_object_new_object();
        json_object_object_add(ns, "ip", json_object_new_string(c->ip));
        {
            struct json_object *ipv6 = json_object_new_object();
            struct json_object *addrs = json_object_new_array();

            db_ipv6_parse_pipe(addrs, c->ipv6_addrs);
            db_ipv6_array_add_unique(addrs, c->ipv6);
            db_ipv6_array_add_unique(addrs, c->ipv6_global);
            db_ipv6_array_add_unique(addrs, c->ipv6_lan);
            db_ipv6_array_add_unique(addrs, c->ipv6_link_local);
            json_object_object_add(ipv6, "addrs", addrs);
            json_object_object_add(ipv6, "global", json_object_new_string(c->ipv6_global));
            json_object_object_add(ipv6, "lan", json_object_new_string(c->ipv6_lan));
            json_object_object_add(ipv6, "link_local", json_object_new_string(c->ipv6_link_local));
            json_object_object_add(ipv6, "primary", json_object_new_string(
                c->ipv6_global[0] ? c->ipv6_global :
                (c->ipv6_lan[0] ? c->ipv6_lan :
                 (c->ipv6_link_local[0] ? c->ipv6_link_local : c->ipv6))));
            json_object_object_add(ns, "ipv6", ipv6);
        }
        json_object_object_add(ns, "interface", json_object_new_string("br-lan"));
        json_object_object_add(ns, "network", json_object_new_string("lan"));
        json_object_object_add(ns, "link_type", json_object_new_string("unknown"));
        json_object_object_add(ns, "tx_rate", json_object_new_int64(c->up_rate));
        json_object_object_add(ns, "rx_rate", json_object_new_int64(c->down_rate));
        /* Byte counters were never written here, so client_network_state.tx_bytes
         * and rx_bytes stayed at their column default of 0 for every client on
         * every router, while the rates next to them were live. The numbers did
         * exist in memory the whole time; they were simply dropped on the way to
         * the database.
         *
         * What we have is a per-hour ring for the current day only
         * (client_node_t.daily_stats.hourly_traffic[24], accumulated in
         * jmx_netlink.c). There is no lifetime counter anywhere in jmxd for a
         * client, so summing the 24 buckets yields a TODAY total that resets at
         * local midnight - not a lifetime total. The reader publishes
         * bytes_window="today" next to these values so no consumer can mistake
         * one for the other. */
        {
            daily_hourly_stat_t *today = get_today_stat(c);
            unsigned long long up = 0, down = 0;

            if (today) {
                int hour;
                for (hour = 0; hour < HOURS_PER_DAY; hour++) {
                    up += today->hourly_traffic[hour].up_bytes;
                    down += today->hourly_traffic[hour].down_bytes;
                }
            }
            json_object_object_add(ns, "tx_bytes", json_object_new_int64((int64_t)up));
            json_object_object_add(ns, "rx_bytes", json_object_new_int64((int64_t)down));
        }
        json_object_object_add(ns, "connections", json_object_new_int(db_count_conntrack_for_ip(c->ip)));
        json_object_object_add(ns, "online", json_object_new_int(c->online));
        db_upsert_network_state(cid, ns);
        json_object_put(ns);
        db_apply_identity_aggregator(mac);
        count++;
    }
    if (db_commit() != 0) { db_rollback(); return -1; }
    return count;
}

static void add_col_text(struct json_object *o, const char *key, sqlite3_stmt *st, int col)
{
    char safe[8192];

    json_object_object_add(o, key, json_object_new_string(db_sqlite_safe_text(st, col, safe, sizeof(safe))));
}

static int db_signal_model_from_evidence(const char *raw_json,
                                         char *model, size_t model_len,
                                         char *source, size_t source_len)
{
    static const char *keys[] = {"modelName", "modelNumber", "model", "friendlyName", NULL};
    struct json_object *root = NULL;
    int i, k;

    if (model && model_len)
        model[0] = '\0';
    if (source && source_len)
        source[0] = '\0';
    if (!raw_json || !raw_json[0] || !model || model_len == 0)
        return 0;
    root = json_tokener_parse(raw_json);
    if (!root || !json_object_is_type(root, json_type_array)) {
        if (root)
            json_object_put(root);
        return 0;
    }

    for (k = 0; keys[k]; k++) {
        int best_conf = -1;
        const char *best_value = NULL;
        const char *best_source = NULL;

        for (i = 0; i < (int)json_object_array_length(root); i++) {
            struct json_object *o = json_object_array_get_idx(root, i);
            const char *key = json_s(o, "key", "");
            const char *value = json_s(o, "value", "");
            const char *sig_source = json_s(o, "source", "");
            int conf = json_i(o, "confidence", 0);

            if (!key[0] || strcmp(key, keys[k]) || !value[0])
                continue;
            if (conf >= best_conf) {
                best_conf = conf;
                best_value = value;
                best_source = sig_source;
            }
        }
        if (best_value && best_value[0]) {
            snprintf(model, model_len, "%s", best_value);
            db_trim_crlf(model);
            if (source && source_len)
                snprintf(source, source_len, "%s.%s", best_source && best_source[0] ? best_source : "identity", keys[k]);
            json_object_put(root);
            return model[0] != '\0';
        }
    }

    json_object_put(root);
    return 0;
}

/*
 * True when the MAC has the locally-administered bit set, i.e. it is randomized
 * and carries no OUI.
 *
 * Acceptance hit this with ea:6a:9a:62:3d:96: 0xea & 0x02 is set, so no vendor
 * lookup can ever succeed and the device looks anonymous rather than absent.
 * Reported as a plain fact so nothing downstream has to re-derive it from the
 * string.
 */
static int db_mac_is_locally_administered(const char *mac)
{
    unsigned int first = 0;

    if (!mac || !mac[0])
        return 0;
    if (sscanf(mac, "%2x", &first) != 1)
        return 0;
    return (first & 0x02) != 0;
}

static struct json_object *db_row_to_client(sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();
    struct json_object *fp = json_object_new_object();
    int engine = sqlite3_column_int(st, 30);
    int device_id = sqlite3_column_int(st, 31);
    int vendor_id = sqlite3_column_int(st, 32);
    const unsigned char *custom_name = sqlite3_column_text(st, 11);
    const unsigned char *custom_type = sqlite3_column_text(st, 13);
    const unsigned char *custom_vendor = sqlite3_column_text(st, 14);
    const unsigned char *display_name = sqlite3_column_text(st, 3);
    const unsigned char *hostname = sqlite3_column_text(st, 2);
    const unsigned char *vendor = sqlite3_column_text(st, 4);
    const unsigned char *device_type = sqlite3_column_text(st, 6);
    const unsigned char *custom_icon = sqlite3_column_text(st, 12);
    const char *fp_raw_json = (const char *)sqlite3_column_text(st, 39);
    const char *ipv6_json = (const char *)sqlite3_column_text(st, 46);
    int64_t network_updated_at = sqlite3_column_int64(st, 47);
    int64_t now = now_s();
    int64_t last_seen = sqlite3_column_int64(st, 10);
    int64_t last_seen_age = last_seen > 0 && now >= last_seen ? now - last_seen : -1;
    int64_t sample_age_ms = network_updated_at > 0 && now >= network_updated_at ? (now - network_updated_at) * 1000 : -1;
    int64_t tx_rate = sqlite3_column_int64(st, 25);
    int64_t rx_rate = sqlite3_column_int64(st, 26);
    int64_t tx_bytes = sqlite3_column_int64(st, 27);
    int64_t rx_bytes = sqlite3_column_int64(st, 28);
    const char *bytes_source = "client_network_state";
    int connections = sqlite3_column_int(st, 29);
    int online = sqlite3_column_int(st, 37) != 0;
    int sample_valid;
    int has_active_evidence;
    const char *offline_reason = NULL;
    const char *verdict_online_source = NULL;
    const char *verdict_zero_reason = NULL;
    client_node_t *runtime = NULL;
    struct jmx_db_client_evidence evidence;
    struct jmx_db_client_verdict verdict;
    int64_t online_since = 0;
    int64_t online_duration = 0;
    char online_duration_source[64] = "";
    char resolved_model[256] = "";
    char model_source[96] = "";
    int conn_v4 = 0;
    int conn_v6 = 0;

    runtime = db_find_runtime_client((const char *)sqlite3_column_text(st, 1));
    if (runtime) {
        /* Count both families in one conntrack pass. The old call counted only
         * the IPv4 literal, so a dual-stack client's IPv6 connections were
         * missing from the total the UI shows. */
        int runtime_ct;
        int runtime_live = runtime->online || runtime->up_rate > 0 || runtime->down_rate > 0;

        db_count_conntrack_by_family(runtime, &conn_v4, &conn_v6);
        runtime_ct = conn_v4 + conn_v6;

        /* Runtime can keep an old offline client node around while DB/identityd
         * has fresher topology/IP evidence.  Do not let a stale runtime node, or
         * a lingering conntrack entry by itself, overwrite DB online/timestamp
         * truth; otherwise /api/v1/clients and realtime clients.metrics flap. */
        if (runtime->up_rate > 0 || runtime->down_rate > 0) {
            tx_rate = runtime->up_rate;
            rx_rate = runtime->down_rate;
        }
        /* Byte totals get the same runtime override the rates already had. The
         * stored row is only as fresh as the last bulk sync, and on a router
         * whose storage guard is refusing bulk writes it is never refreshed at
         * all - which is exactly the state 30.1 was in, reporting live rates
         * beside zero byte counters. Reading the in-memory day ring here keeps
         * the two consistent. Larger-wins because the ring is authoritative for
         * today and the stored row can only lag it. */
        {
            daily_hourly_stat_t *today = get_today_stat(runtime);

            if (today) {
                unsigned long long up = 0, down = 0;
                int hour;

                for (hour = 0; hour < HOURS_PER_DAY; hour++) {
                    up += today->hourly_traffic[hour].up_bytes;
                    down += today->hourly_traffic[hour].down_bytes;
                }
                if ((int64_t)up > tx_bytes || (int64_t)down > rx_bytes) {
                    if ((int64_t)up > tx_bytes)
                        tx_bytes = (int64_t)up;
                    if ((int64_t)down > rx_bytes)
                        rx_bytes = (int64_t)down;
                    bytes_source = "client_hourly_traffic";
                }
            }
        }
        if (runtime_live && runtime_ct > connections)
            connections = runtime_ct;
        if (runtime_live) {
            online = 1;
            if (runtime->runtime_updated_at > 0) {
                network_updated_at = runtime->runtime_updated_at;
                sample_age_ms = now >= network_updated_at ? (now - network_updated_at) * 1000 : -1;
            }
            last_seen = runtime->last_seen_ts ? runtime->last_seen_ts : last_seen;
            last_seen_age = last_seen > 0 && now >= last_seen ? now - last_seen : -1;
        }
    }
    /* One shared verdict function so the API, the tests and any future caller
     * cannot drift apart on what "online" means. */
    memset(&evidence, 0, sizeof(evidence));
    evidence.db_online = online;
    evidence.runtime_online = runtime && runtime->online;
    evidence.tx_rate = tx_rate;
    evidence.rx_rate = rx_rate;
    evidence.connections = connections;
    evidence.sample_age_ms = sample_age_ms;
    evidence.last_seen_age = last_seen_age;
    /* Ask the bridge directly rather than reading runtime->bridge_fdb_present:
     * that field is only refreshed by the legacy scheduler, which is disabled on
     * current deployments, so it would stay -1 and silently switch off the
     * ghost-client cross-check. */
    evidence.bridge_fdb_present =
        client_bridge_fdb_present((const char *)sqlite3_column_text(st, 1));
    if (evidence.bridge_fdb_present < 0 && runtime)
        evidence.bridge_fdb_present = runtime->bridge_fdb_present;
    if (runtime) {
        snprintf(evidence.neigh_state, sizeof(evidence.neigh_state), "%s",
                 runtime->neigh_state);
        snprintf(evidence.neigh_state_v4, sizeof(evidence.neigh_state_v4), "%s",
                 runtime->neigh_state_v4);
        snprintf(evidence.neigh_state_v6, sizeof(evidence.neigh_state_v6), "%s",
                 runtime->neigh_state_v6);
        evidence.runtime_online_source = runtime->online_source;
    }
    jmx_db_client_online_verdict(&evidence, &verdict);
    online = verdict.online;
    sample_valid = verdict.sample_valid;
    has_active_evidence = verdict.has_active_evidence;
    tx_rate = verdict.tx_rate;
    rx_rate = verdict.rx_rate;
    connections = verdict.connections;
    offline_reason = verdict.offline_reason;
    verdict_online_source = verdict.online_source;
    verdict_zero_reason = verdict.zero_reason;
    (void)has_active_evidence;
    (void)offline_reason;
    (void)db_runtime_online_session(runtime, online, now, &online_since,
                                    &online_duration, online_duration_source,
                                    sizeof(online_duration_source));

    add_col_text(o, "mac", st, 1);
    /* Locally-administered bit: a randomized MAC carries no OUI, so no vendor
     * database can ever name it and no fingerprint can pin it to a model. The
     * flag is stated as a fact about the address so the UI can say "randomized"
     * instead of leaving the user to read an unknown vendor as an intruder. The
     * label itself belongs to the frontend; this only supplies the bit. */
    json_object_object_add(o, "mac_randomized",
                           json_object_new_boolean(
                               db_mac_is_locally_administered(
                                   (const char *)sqlite3_column_text(st, 1))));
    add_col_text(o, "hostname", st, 2);
    add_col_text(o, "display_name", st, 3);
    add_col_text(o, "custom_name", st, 11);
    /* Name resolution, with the rule published rather than implied. The last
     * step is the MAC itself, which is why a randomized-MAC client shows an
     * address as its name: there is no hostname, no fingerprint and no user
     * label to use. Saying "the name you see is the MAC, and here is why"
     * lets the UI substitute a friendlier label instead of guessing whether
     * the string it received is a real device name. */
    {
        const char *resolved_name;
        const char *name_source;

        if (custom_name && custom_name[0]) {
            resolved_name = (const char *)custom_name;
            name_source = "custom_name";
        } else if (display_name && display_name[0]) {
            resolved_name = (const char *)display_name;
            name_source = "display_name";
        } else if (hostname && hostname[0]) {
            resolved_name = (const char *)hostname;
            name_source = "hostname";
        } else {
            resolved_name = (const char *)sqlite3_column_text(st, 1);
            name_source = "mac_fallback";
        }
        json_object_object_add(o, "name",
                               json_object_new_string(resolved_name ? resolved_name : ""));
        json_object_object_add(o, "name_source", json_object_new_string(name_source));
        json_object_object_add(o, "name_fallback_rule",
            json_object_new_string("custom_name_then_display_name_then_hostname_then_mac"));
        json_object_object_add(o, "name_is_placeholder",
                               json_object_new_boolean(!strcmp(name_source, "mac_fallback")));
    }
    /* Resolve vendor: prefer custom_vendor, then client_fingerprints vendor_name (col 40), then clients.vendor (col 4) */
    const unsigned char *fp_vendor = sqlite3_column_text(st, 40);
    const unsigned char *fp_image = sqlite3_column_text(st, 42);
    const char *resolved_vendor = (custom_vendor && custom_vendor[0]) ? (const char *)custom_vendor :
                                  (fp_vendor && fp_vendor[0]) ? (const char *)fp_vendor :
                                  (vendor && vendor[0]) ? (const char *)vendor : "";
    json_object_object_add(o, "vendor", json_object_new_string(resolved_vendor));
    add_col_text(o, "oui", st, 5);
    /* Resolve type: prefer custom_type, then client_fingerprints device_type (col 41), then clients.device_type, then dev_cat */
    const unsigned char *fp_type = sqlite3_column_text(st, 41);
    const char *resolved_type = "unknown";
    if (custom_type && custom_type[0]) resolved_type = (const char *)custom_type;
    else if (fp_type && fp_type[0] && strcmp((const char *)fp_type, "unknown")) resolved_type = (const char *)fp_type;
    else if (device_type && device_type[0] && strcmp((const char *)device_type, "unknown") && strcmp((const char *)fp_type, "unknown")) resolved_type = (const char *)device_type;
    else {
        int dev_cat = sqlite3_column_int(st, 35);
        switch (dev_cat) {
            case 1: resolved_type = "smartphone"; break;
            case 2: resolved_type = "tablet"; break;
            case 3: resolved_type = "computer"; break;
            case 4: resolved_type = "tv"; break;
            case 5: resolved_type = "nas"; break;
            case 6: resolved_type = "router"; break;
            case 7: resolved_type = "printer"; break;
            case 8: resolved_type = "camera"; break;
            case 9: resolved_type = "iot"; break;
            case 10: resolved_type = "game_console"; break;
            case 11: resolved_type = "hypervisor"; break;
        }
    }
    /* If type is still unknown, try hostname-based inference */
    if (!strcmp(resolved_type, "unknown")) {
        const char *hn = (const char *)sqlite3_column_text(st, 2); /* hostname */
        if (hn && hn[0] && !db_text_has_any(hn, (const char *[]){"macsamba", NULL})) {
            const char *guessed = db_guess_type_from_hostname(hn);
            if (strcmp(guessed, "unknown")) resolved_type = guessed;
        }
    }
    /* col 40/41 already contain vendor_name/device_type from client_fingerprints subquery in client_select_sql.
     * If type is still unknown, fall back to dev_cat mapping (already done above). No extra DB lookup needed. */
    json_object_object_add(o, "type", json_object_new_string(resolved_type));
    /* A bare "unknown" makes the consumer guess whether identification failed,
     * is still pending, or the device is genuinely unidentifiable. State which
     * one it is. A randomized MAC carries no OUI, so vendor and model lookups
     * cannot succeed at all - that is a permanent limit, not a pending result. */
    if (!strcmp(resolved_type, "unknown")) {
        int randomized = db_mac_is_locally_administered(
                             (const char *)sqlite3_column_text(st, 1));
        const char *has_fp = (const char *)sqlite3_column_text(st, 38);

        json_object_object_add(o, "type_reason", json_object_new_string(
            randomized ? "randomized_mac_no_oui_and_no_fingerprint_evidence" :
            (has_fp && has_fp[0] ? "fingerprint_evidence_inconclusive" :
                                   "no_fingerprint_evidence_collected")));
        json_object_object_add(o, "type_identifiable",
                               json_object_new_boolean(!randomized));
    } else {
        json_object_object_add(o, "type_reason", json_object_new_string(""));
        json_object_object_add(o, "type_identifiable", json_object_new_boolean(1));
    }
    json_object_object_add(o, "vendor_name", json_object_new_string(resolved_vendor));
    db_signal_model_from_evidence(fp_raw_json, resolved_model, sizeof(resolved_model),
                                  model_source, sizeof(model_source));
    json_object_object_add(o, "model", json_object_new_string(resolved_model));
    json_object_object_add(o, "device_name", json_object_new_string(resolved_model));
    json_object_object_add(o, "model_source", json_object_new_string(model_source));
    add_col_text(o, "os_name", st, 7);
    json_object_object_add(o, "first_seen", json_object_new_int64(sqlite3_column_int64(st, 9)));
    json_object_object_add(o, "last_seen", json_object_new_int64(last_seen));
    json_object_object_add(o, "last_seen_age", json_object_new_int64(last_seen_age));
    add_col_text(o, "custom_icon", st, 12);
    json_object_object_add(o, "custom_image_path",
                           json_object_new_string(custom_icon && custom_icon[0] ?
                                                  (const char *)custom_icon : ""));
    json_object_object_add(o, "pinned", json_object_new_boolean(sqlite3_column_int(st, 15) != 0));
    json_object_object_add(o, "hidden", json_object_new_boolean(sqlite3_column_int(st, 16) != 0));
    add_col_text(o, "note", st, 17);
    /* IPv4 contract. The stored column carries 0.0.0.0 for a client that has
     * only ever been seen over IPv6, so the key is published empty and the
     * absence is stated in ipv4_available/ipv4_reason instead of being encoded
     * as a placeholder address. The key itself is kept (never deleted) because
     * the Web module and the iOS App both read client.ip unconditionally. */
    {
        char ip_buf[8192];
        const char *stored_ip = db_sqlite_safe_text(st, 18, ip_buf, sizeof(ip_buf));
        const char *effective_ip = db_ipv4_usable(stored_ip) ? stored_ip : "";
        const char *ipv4_source = "";
        const char *ipv4_reason = "";
        int stored_placeholder = stored_ip[0] && !db_ipv4_usable(stored_ip);
        int has_ipv6 = (runtime && runtime->ipv6_addrs[0]) ||
                       (ipv6_json && strchr(ipv6_json, ':') != NULL);

        if (!effective_ip[0] && runtime && db_ipv4_usable(runtime->ip)) {
            effective_ip = runtime->ip;
            ipv4_source = "client_runtime";
        } else if (effective_ip[0]) {
            ipv4_source = "client_network_state";
        }
        if (!effective_ip[0]) {
            if (has_ipv6)
                ipv4_reason = "ipv6_only_client_no_ipv4_address_observed";
            else if (online)
                ipv4_reason = "no_ipv4_address_observed_for_mac";
            else
                ipv4_reason = "offline_no_ipv4_address_recorded";
        }
        json_object_object_add(o, "ip", json_object_new_string(effective_ip));
        json_object_object_add(o, "ipv4", json_object_new_string(effective_ip));
        json_object_object_add(o, "ipv4_available",
                               json_object_new_boolean(effective_ip[0] != '\0'));
        json_object_object_add(o, "ipv4_reason", json_object_new_string(ipv4_reason));
        json_object_object_add(o, "ipv4_source", json_object_new_string(ipv4_source));
        /* Diagnostic: says the row in client_network_state still holds the
         * sentinel, so a future reader does not mistake the empty output for a
         * missing database column. */
        json_object_object_add(o, "ipv4_stored_placeholder",
                               json_object_new_boolean(stored_placeholder));
    }
    add_col_text(o, "interface", st, 19);
    add_col_text(o, "network", st, 20);
    add_col_text(o, "ssid", st, 21);
    /* link_type stays "unknown" when neither the wireless station table nor
     * the switch port map claimed this MAC. Publish the reason so the UI can
     * say "attachment unknown" rather than rendering an empty medium icon, and
     * so acceptance can tell a collection gap from an unidentifiable device. */
    {
        char lt_buf[8192];
        const char *link_type = db_sqlite_safe_text(st, 22, lt_buf, sizeof(lt_buf));
        const char *ssid = (const char *)sqlite3_column_text(st, 21);
        int signal = sqlite3_column_int(st, 24);
        int unknown = !link_type[0] || !strcmp(link_type, "unknown");

        json_object_object_add(o, "link_type", json_object_new_string(link_type));
        if (unknown)
            json_object_object_add(o, "link_type_reason", json_object_new_string(
                (ssid && ssid[0]) || signal ?
                    "wireless_evidence_present_but_medium_not_classified" :
                    "no_wireless_station_entry_and_no_switch_port_evidence"));
        else
            json_object_object_add(o, "link_type_reason", json_object_new_string(""));

        /*
         * is_wired is derived from link_type rather than read from
         * clients.is_wired.
         *
         * That column has never been written by anything: the only writer is
         * jmx_db_api_clients_observe(), which binds json_i(req, "is_wired", 0),
         * and no caller anywhere in the tree passes the key - so the stored
         * value was 0 for every row ever created. The field therefore reported
         * "not wired" for all 8 clients on 30.1 while link_type said "wired"
         * for 7 of them, and a consumer comparing the two saw the record
         * contradict itself.
         *
         * link_type is the authoritative medium: it is populated from the
         * wireless station table and the switch port map. is_wired is published
         * as a convenience view over it, plus a source field so the derivation
         * is not a hidden assumption.
         *
         * When the medium is unknown, is_wired is false and
         * is_wired_known is false: "we did not determine the medium" must not
         * read as "we determined it is wireless". A consumer that needs the
         * three-state answer reads is_wired_known first.
         */
        {
            int wired = !unknown && (!strcmp(link_type, "wired") ||
                                     !strcmp(link_type, "ethernet"));

            json_object_object_add(o, "is_wired", json_object_new_boolean(wired));
            json_object_object_add(o, "is_wired_known",
                                   json_object_new_boolean(!unknown));
            json_object_object_add(o, "is_wired_source",
                                   json_object_new_string(unknown ?
                                       "undetermined_link_type" :
                                       "derived_from_link_type"));
        }
    }
    add_col_text(o, "link_speed", st, 23);
    add_col_text(o, "parent_mac", st, 43);
    add_col_text(o, "parent_id", st, 44);
    add_col_text(o, "port", st, 45);
    /* When the in-memory collector has IPv6 evidence for this MAC it is the
     * authoritative view of what the client holds *right now*, so it replaces
     * the stored row instead of being unioned with it. Unioning kept addresses
     * from a withdrawn ISP prefix in the response forever: client_network_state
     * .ipv6_json is only overwritten when the incoming value is non-empty
     * (see db_upsert_network_state), so an address that disappeared from the
     * neighbour table was never removed from the stored copy, and merging the
     * two republished it beside the live one. The stored row remains the
     * fallback for a client the collector has not observed this round. */
    if (runtime && runtime->ipv6_addrs[0])
        db_add_ipv6_contract(o, NULL,
                             runtime->ipv6_addrs,
                             runtime->ipv6_global,
                             runtime->ipv6_lan,
                             runtime->ipv6_link_local);
    else
        db_add_ipv6_contract(o, ipv6_json, "", "", "", "");
    json_object_object_add(o, "ipv6_source",
                           json_object_new_string(runtime && runtime->ipv6_addrs[0] ?
                                                  "client_runtime" :
                                                  "client_network_state"));
    json_object_object_add(o, "signal", json_object_new_int(sqlite3_column_int(st, 24)));
    json_object_object_add(o, "tx_rate", json_object_new_int64(tx_rate));
    json_object_object_add(o, "rx_rate", json_object_new_int64(rx_rate));
    json_object_object_add(o, "up_rate", json_object_new_int64(tx_rate));
    json_object_object_add(o, "down_rate", json_object_new_int64(rx_rate));
    json_object_object_add(o, "tx_bytes", json_object_new_int64(tx_bytes));
    json_object_object_add(o, "rx_bytes", json_object_new_int64(rx_bytes));
    /* These two are a TODAY total, not a lifetime one: jmxd keeps per-client
     * traffic in a 24-hour ring for the current day and has no lifetime counter,
     * so the value resets at local midnight. Saying so explicitly is the whole
     * point - the field names read like lifetime counters and cannot be renamed
     * without breaking the shipped Web module and the iOS App, so the window is
     * published alongside them instead. */
    json_object_object_add(o, "bytes_window", json_object_new_string("today"));
    json_object_object_add(o, "bytes_source", json_object_new_string(bytes_source));
    json_object_object_add(o, "bytes_reset_at", json_object_new_string("local_midnight"));
    /* The hourly buckets behind these values are normally filled by integrating
     * the sampled rate, so treat them as an estimate unless the exact kernel
     * counter path is running. client_traffic_history.today_metrics.bytes_method
     * names which writer produced them. */
    json_object_object_add(o, "bytes_estimated",
                           json_object_new_boolean(!db_legacy_netlink_enabled()));
    json_object_object_add(o, "connections", json_object_new_int(connections));
    /* IPv6 dimension the UI asked for. Connection counts are real (conntrack);
     * rates and byte counters are family-agnostic in the kernel module, so they
     * are reported as unsupported with a reason instead of a fabricated 0. */
    json_object_object_add(o, "ipv4_connections", json_object_new_int(conn_v4));
    json_object_object_add(o, "ipv6_connections", json_object_new_int(conn_v6));
    json_object_object_add(o, "connections_ipv4", json_object_new_int(conn_v4));
    json_object_object_add(o, "connections_ipv6", json_object_new_int(conn_v6));
    json_object_object_add(o, "connections_source",
                           json_object_new_string(conn_v4 + conn_v6 > 0 ?
                                                  "nf_conntrack_by_family" :
                                                  "client_network_state"));
    json_object_object_add(o, "ipv6_connections_supported", json_object_new_boolean(1));
    json_object_object_add(o, "ipv6_rate_supported", json_object_new_boolean(0));
    json_object_object_add(o, "ipv6_rate_reason",
        json_object_new_string("jmx_per_client_accounting_is_family_agnostic"));
    json_object_object_add(o, "ipv6_bytes_supported", json_object_new_boolean(0));
    json_object_object_add(o, "ipv6_bytes_reason",
        json_object_new_string("jmx_per_client_accounting_is_family_agnostic"));
    json_object_object_add(o, "online", json_object_new_boolean(online));
    if (online_since > 0) {
        json_object_object_add(o, "online_since", json_object_new_int64(online_since));
        json_object_object_add(o, "connected_at", json_object_new_int64(online_since));
        json_object_object_add(o, "session_started_at", json_object_new_int64(online_since));
        json_object_object_add(o, "online_duration", json_object_new_int64(online_duration));
        json_object_object_add(o, "online_seconds", json_object_new_int64(online_duration));
        json_object_object_add(o, "connected_seconds", json_object_new_int64(online_duration));
        json_object_object_add(o, "session_duration", json_object_new_int64(online_duration));
        json_object_object_add(o, "online_duration_source",
                               json_object_new_string(online_duration_source[0] ?
                                                      online_duration_source : "client_runtime"));
    } else {
        json_object_object_add(o, "online_duration_source",
                               json_object_new_string(online ? "unknown_session_start" : ""));
    }
    json_object_object_add(o, "updated_at", json_object_new_int64(network_updated_at));
    json_object_object_add(o, "sample_age_ms", json_object_new_int64(sample_age_ms));
    json_object_object_add(o, "sample_valid", json_object_new_boolean(sample_valid));
    json_object_object_add(o, "rate_source", json_object_new_string(
        runtime && (runtime->up_rate > 0 || runtime->down_rate > 0) ? "client_runtime" : "client_network_state"));
    json_object_object_add(o, "online_source", json_object_new_string(
        verdict_online_source ? verdict_online_source : ""));
    json_object_object_add(o, "neigh_state", json_object_new_string(
        runtime && runtime->neigh_state[0] ? runtime->neigh_state : ""));
    /* Publish both families so a disagreement is diagnosable from the API
     * instead of requiring shell access to the router. */
    json_object_object_add(o, "neigh_state_ipv4", json_object_new_string(
        runtime && runtime->neigh_state_v4[0] ? runtime->neigh_state_v4 : ""));
    json_object_object_add(o, "neigh_state_ipv6", json_object_new_string(
        runtime && runtime->neigh_state_v6[0] ? runtime->neigh_state_v6 : ""));
    if (evidence.bridge_fdb_present >= 0)
        json_object_object_add(o, "bridge_fdb_present",
                               json_object_new_boolean(evidence.bridge_fdb_present));
    else {
        json_object_object_add(o, "bridge_fdb_present", NULL);
        json_object_object_add(o, "bridge_fdb_reason",
                               json_object_new_string("bridge_fdb_unreadable"));
    }
    json_object_object_add(o, "zero_reason", json_object_new_string(
        verdict_zero_reason ? verdict_zero_reason : ""));

    json_object_object_add(fp, "engine", json_object_new_int(engine));
    json_object_object_add(fp, "device_id", json_object_new_int(device_id));
    json_object_object_add(fp, "vendor_id", json_object_new_int(vendor_id));
    json_object_object_add(fp, "os_class", json_object_new_int(sqlite3_column_int(st, 33)));
    json_object_object_add(fp, "dev_cat", json_object_new_int(sqlite3_column_int(st, 35)));
    json_object_object_add(fp, "confidence", json_object_new_double(sqlite3_column_double(st, 36)));
    add_col_text(fp, "source", st, 38);
    add_col_text(fp, "raw_json", st, 39);
    json_object_object_add(fp, "device_type", json_object_new_string(resolved_type));
    json_object_object_add(fp, "vendor_name", json_object_new_string(resolved_vendor));
    json_object_object_add(fp, "device_name", json_object_new_string(resolved_model));
    json_object_object_add(fp, "model_source", json_object_new_string(model_source));
    /* One image resolution for the whole row, so /api/v1/clients agrees with
     * client_profile.basic instead of resolving the same device twice with
     * different rules. detected_image stays the raw fingerprint hit; the
     * effective image may be an override or a fallback placeholder. */
    {
        const char *detected = (fp_image && fp_image[0]) ? (const char *)fp_image : "";
        const char *override_image = (custom_icon && custom_icon[0]) ?
                                     (const char *)custom_icon : "";
        const char *image = override_image[0] ? override_image : detected;
        const char *image_source = override_image[0] ? "override" :
                                   (detected[0] ? "fingerprint" : "none");
        int image_fallback = 0;
        const char *image_fallback_reason = "";

        if (!image[0] && db_ikuai_router_identity(resolved_vendor, resolved_type,
                                                  resolved_model)) {
            image = DB_GENERIC_ROUTER_WEB_IMAGE;
            image_source = "fallback";
            image_fallback = 1;
            image_fallback_reason = "generic_router_icon_for_ikuai";
        }

        json_object_object_add(fp, "image", json_object_new_string(detected));
        json_object_object_add(fp, "detected_image", json_object_new_string(detected));
        json_object_object_add(fp, "effective_image", json_object_new_string(image));
        json_object_object_add(o, "fingerprint", fp);

        json_object_object_add(o, "detected_image", json_object_new_string(detected));
        json_object_object_add(o, "image", json_object_new_string(image));
        json_object_object_add(o, "image_url", json_object_new_string(image));
        json_object_object_add(o, "effective_image", json_object_new_string(image));
        json_object_object_add(o, "image_source", json_object_new_string(image_source));
        json_object_object_add(o, "image_fallback",
                               json_object_new_boolean(image_fallback));
        json_object_object_add(o, "image_fallback_reason",
                               json_object_new_string(image_fallback_reason));
    }
    {
        struct json_object *override_fields = json_object_new_array();
        if (custom_name && custom_name[0])
            json_object_array_add(override_fields, json_object_new_string("nickname"));
        if (custom_icon && custom_icon[0])
            json_object_array_add(override_fields, json_object_new_string("custom_image_path"));
        if (custom_type && custom_type[0])
            json_object_array_add(override_fields, json_object_new_string("device_type"));
        if (custom_vendor && custom_vendor[0])
            json_object_array_add(override_fields, json_object_new_string("vendor_name"));
        if (sqlite3_column_int(st, 15))
            json_object_array_add(override_fields, json_object_new_string("pinned"));
        if (sqlite3_column_int(st, 16))
            json_object_array_add(override_fields, json_object_new_string("hidden"));
        json_object_object_add(o, "override_fields", override_fields);
    }
    return o;
}

static const char *client_select_sql =
    "SELECT c.client_id,c.mac,c.hostname,c.display_name,c.vendor,c.oui,c.device_type,c.os_name,c.is_wired,c.first_seen,c.last_seen,"
    "COALESCE(o.custom_name,''),COALESCE(o.custom_icon,''),COALESCE(o.custom_device_type,''),COALESCE(o.custom_vendor,''),COALESCE(o.pinned,0),COALESCE(o.hidden,0),COALESCE(o.note,''),"
    "COALESCE(n.ip,''),COALESCE(n.interface,''),COALESCE(n.network,''),COALESCE(n.ssid,''),COALESCE(n.link_type,'unknown'),COALESCE(n.link_speed,''),COALESCE(n.signal,0),COALESCE(n.tx_rate,0),COALESCE(n.rx_rate,0),COALESCE(n.tx_bytes,0),COALESCE(n.rx_bytes,0),COALESCE(n.connections,0),"
    "COALESCE(f.engine,0),COALESCE(f.device_id,0),COALESCE(f.vendor_id,0),COALESCE(f.os_class,0),COALESCE(f.os_name_id,0),COALESCE(f.dev_cat,0),COALESCE(f.confidence,0),COALESCE(n.online,0),COALESCE(f.source,''),COALESCE(f.raw_json,'{}'),"
    "COALESCE((SELECT fp2.vendor_name FROM client_fingerprints fp2 WHERE fp2.mac=c.mac ORDER BY fp2.updated_at DESC LIMIT 1),''),"
    "COALESCE((SELECT fp2.device_type FROM client_fingerprints fp2 WHERE fp2.mac=c.mac ORDER BY fp2.updated_at DESC LIMIT 1),''),"
    "COALESCE((SELECT fp2.image_path FROM client_fingerprints fp2 WHERE fp2.mac=c.mac ORDER BY fp2.updated_at DESC LIMIT 1),''),"
    "COALESCE(n.parent_mac,''),COALESCE(n.parent_id,''),COALESCE(n.port,''),COALESCE(n.ipv6_json,'[]'),COALESCE(n.updated_at,0) "
    "FROM clients c LEFT JOIN client_overrides o ON o.client_id=c.client_id LEFT JOIN client_network_state n ON n.client_id=c.client_id LEFT JOIN client_fingerprint f ON f.client_id=c.client_id";

/*
 * True when an offline client row is old enough to drop out of the default
 * inventory.
 *
 * Anything the user has touched is exempt: a pinned device, a renamed one, or
 * one carrying a note is there on purpose, and silently removing it after a
 * week would look like data loss. A row with no usable last_seen is treated as
 * stale, because that is what an entry observed once and never resolved looks
 * like.
 *
 * The caller must have decided the row is offline; this only judges age.
 */
int jmx_db_client_row_stale(struct json_object *client, int64_t now,
                            int64_t retention_sec)
{
    int64_t last_seen;
    int64_t age;

    if (!client || retention_sec <= 0)
        return 0;
    if (json_i(client, "pinned", 0))
        return 0;
    if (json_s(client, "custom_name", "")[0])
        return 0;
    if (json_s(client, "note", "")[0])
        return 0;

    last_seen = json_i64(client, "last_seen", 0);
    if (last_seen <= 0)
        return 1;
    age = now - last_seen;
    if (age < 0)
        return 0;
    return age > retention_sec;
}

struct json_object *jmx_db_api_clients_observe(struct json_object *req)
{
    struct json_object *data = json_object_new_object();
    int64_t cid = 0;
    char mac[32] = {0};
    if (jmx_db_init() != 0 || !req || normalize_mac(json_s(req, "mac", ""), mac, sizeof(mac)) != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("invalid_mac_or_db"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (db_begin() != 0 || db_observe_json(req, &cid) != 0 || db_commit() != 0) {
        db_rollback();
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("observe_failed"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "client_id", json_object_new_int64(cid));
    json_object_object_add(data, "mac", json_object_new_string(mac));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

struct json_object *jmx_db_api_client_override(struct json_object *req)
{
    struct json_object *data = json_object_new_object();
    char mac[32] = {0};
    int64_t cid, ts = now_s();
    sqlite3_stmt *st = NULL;
    if (jmx_db_init() != 0 || !req || normalize_mac(json_s(req, "mac", ""), mac, sizeof(mac)) != 0) {
        json_object_object_add(data, "error", json_object_new_string("invalid_mac_or_db"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (db_begin() != 0) return jmx_gen_api_response_data(API_CODE_ERROR, data);
    if (db_upsert_client(mac, "", "", "", "", "unknown", "", 0, ts, &cid) != 0) { db_rollback(); return jmx_gen_api_response_data(API_CODE_ERROR, data); }
    if (db_prepare(&st,
        "INSERT INTO client_overrides(client_id,custom_name,custom_icon,custom_device_type,custom_vendor,pinned,hidden,note,updated_at) "
        "VALUES(?1,NULLIF(?2,''),NULLIF(?3,''),NULLIF(?4,''),NULLIF(?5,''),?6,?7,NULLIF(?8,''),?9) "
        "ON CONFLICT(client_id) DO UPDATE SET "
        "custom_name=CASE WHEN ?10 THEN excluded.custom_name ELSE client_overrides.custom_name END,"
        "custom_icon=CASE WHEN ?11 THEN excluded.custom_icon ELSE client_overrides.custom_icon END,"
        "custom_device_type=CASE WHEN ?12 THEN excluded.custom_device_type ELSE client_overrides.custom_device_type END,"
        "custom_vendor=CASE WHEN ?13 THEN excluded.custom_vendor ELSE client_overrides.custom_vendor END,"
        "pinned=CASE WHEN ?14 THEN excluded.pinned ELSE client_overrides.pinned END,"
        "hidden=CASE WHEN ?15 THEN excluded.hidden ELSE client_overrides.hidden END,"
        "note=CASE WHEN ?16 THEN excluded.note ELSE client_overrides.note END,"
        "updated_at=excluded.updated_at") != 0) { db_rollback(); return jmx_gen_api_response_data(API_CODE_ERROR, data); }
    sqlite3_bind_int64(st, 1, cid);
    bind_text_or_null(st, 2, json_s(req, "custom_name", json_s(req, "nickname", "")));
    bind_text_or_null(st, 3, json_s(req, "custom_icon", json_s(req, "custom_image_path", "")));
    bind_text_or_null(st, 4, json_s(req, "custom_device_type", json_s(req, "device_type", "")));
    bind_text_or_null(st, 5, json_s(req, "custom_vendor", json_s(req, "vendor_name", "")));
    sqlite3_bind_int(st, 6, json_i(req, "pinned", 0));
    sqlite3_bind_int(st, 7, json_i(req, "hidden", 0));
    bind_text_or_null(st, 8, json_s(req, "note", ""));
    sqlite3_bind_int64(st, 9, ts);
    sqlite3_bind_int(st, 10, db_json_has_any_key(req, "custom_name", "nickname"));
    sqlite3_bind_int(st, 11, db_json_has_any_key(req, "custom_icon", "custom_image_path"));
    sqlite3_bind_int(st, 12, db_json_has_any_key(req, "custom_device_type", "device_type"));
    sqlite3_bind_int(st, 13, db_json_has_any_key(req, "custom_vendor", "vendor_name"));
    sqlite3_bind_int(st, 14, db_json_has_key(req, "pinned"));
    sqlite3_bind_int(st, 15, db_json_has_key(req, "hidden"));
    sqlite3_bind_int(st, 16, db_json_has_key(req, "note"));
    if (db_step_done(st) != 0) { sqlite3_finalize(st); db_rollback(); return jmx_gen_api_response_data(API_CODE_ERROR, data); }
    sqlite3_finalize(st);
    if (db_upsert_identity_override(mac, req) != 0 ||
        db_apply_identity_aggregator(mac) != 0) {
        db_rollback();
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (db_commit() != 0) return jmx_gen_api_response_data(API_CODE_ERROR, data);
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "mac", json_object_new_string(mac));
    json_object_object_add(data, "override_fields", db_override_fields_json(req));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

struct json_object *jmx_db_api_client_get(struct json_object *req)
{
    struct json_object *data = json_object_new_object();
    char mac[32] = {0};
    sqlite3_stmt *st = NULL;
    char sql[2048];
    if (jmx_db_init() != 0 || !req || normalize_mac(json_s(req, "mac", ""), mac, sizeof(mac)) != 0)
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    snprintf(sql, sizeof(sql), "%s WHERE c.mac=?1", client_select_sql);
    if (db_prepare(&st, sql) != 0) return jmx_gen_api_response_data(API_CODE_ERROR, data);
    sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *client = db_row_to_client(st);
        json_object_object_add(data, "client", client);
        sqlite3_finalize(st);
        return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
    }
    sqlite3_finalize(st);
    json_object_object_add(data, "error", json_object_new_string("not_found"));
    return jmx_gen_api_response_data(API_CODE_ERROR, data);
}

struct json_object *jmx_db_api_clients_list(struct json_object *req)
{
    struct json_object *data = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    struct json_object *cap = json_object_new_object();
    sqlite3_stmt *st = NULL;
    char sql[4096];
    int bind = 1;
    const char *q = json_s(req, "q", "");
    const char *type = json_s(req, "type", "");
    const char *vendor = json_s(req, "vendor", "");
    int online = json_i(req, "online", -1);
    /* Offline rows used to live in this list forever, so a router that had been
     * up for three weeks answered with 23 offline entries against 3 live ones -
     * mostly randomized MACs that each held a DHCP lease once. Age them out of
     * the default view. The rows stay in the DB and stay reachable through
     * /api/v1/clients/{mac} and include_stale=1; this only decides what the
     * inventory shows by default. */
    int include_stale = json_i(req, "include_stale", 0) != 0;
    int64_t retention_sec = JMX_DB_CLIENT_STALE_RETENTION_SEC;
    int64_t now = now_s();
    int stale_hidden = 0;

    /* Caller-supplied retention, in days, for tests and for a future setting.
     * Anything <= 0 keeps the built-in constant. */
    if (json_i(req, "stale_days", 0) > 0)
        retention_sec = (int64_t)json_i(req, "stale_days", 0) * 86400;

    if (jmx_db_init() != 0) return jmx_gen_api_response_data(API_CODE_ERROR, data);
    snprintf(sql, sizeof(sql), "%s WHERE COALESCE(o.hidden,0)=0", client_select_sql);
    if (type[0]) strncat(sql, " AND COALESCE(o.custom_device_type,c.device_type,'unknown')=?", sizeof(sql) - strlen(sql) - 1);
    if (vendor[0]) strncat(sql, " AND COALESCE(o.custom_vendor,c.vendor,'')=?", sizeof(sql) - strlen(sql) - 1);
    if (q[0]) strncat(sql, " AND (c.mac LIKE ? OR COALESCE(c.hostname,'') LIKE ? OR COALESCE(c.display_name,'') LIKE ? OR COALESCE(o.custom_name,'') LIKE ?)", sizeof(sql) - strlen(sql) - 1);
    strncat(sql, " ORDER BY COALESCE(n.online,0) DESC, c.last_seen DESC", sizeof(sql) - strlen(sql) - 1);

    if (db_prepare(&st, sql) != 0) return jmx_gen_api_response_data(API_CODE_ERROR, data);
    if (type[0]) sqlite3_bind_text(st, bind++, type, -1, SQLITE_TRANSIENT);
    if (vendor[0]) sqlite3_bind_text(st, bind++, vendor, -1, SQLITE_TRANSIENT);
    if (q[0]) {
        char like[256];
        snprintf(like, sizeof(like), "%%%s%%", q);
        sqlite3_bind_text(st, bind++, like, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, bind++, like, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, bind++, like, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, bind++, like, -1, SQLITE_TRANSIENT);
    }
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *client = db_row_to_client(st);

        if ((online == 0 || online == 1) &&
            json_i(client, "online", -1) != online) {
            json_object_put(client);
            continue;
        }
        if (!include_stale && !json_i(client, "online", 0) &&
            jmx_db_client_row_stale(client, now, retention_sec)) {
            stale_hidden++;
            json_object_put(client);
            continue;
        }
        json_object_array_add(arr, client);
    }
    sqlite3_finalize(st);
    json_object_object_add(data, "clients", arr);
    json_object_object_add(data, "total", json_object_new_int(json_object_array_length(arr)));
    /* Self-describe the filter so the UI does not have to guess why a MAC it
     * saw yesterday is gone, and so acceptance can read the retention off the
     * response instead of the source. */
    json_object_object_add(data, "stale_hidden", json_object_new_int(stale_hidden));
    json_object_object_add(data, "stale_retention_sec", json_object_new_int64(retention_sec));
    json_object_object_add(data, "stale_filter_applied",
                           json_object_new_boolean(!include_stale));
    json_object_object_add(cap, "stale_offline_retention", json_object_new_boolean(1));
    json_object_object_add(cap, "stale_retention_sec", json_object_new_int64(retention_sec));
    json_object_object_add(cap, "stale_retention_days",
                           json_object_new_int64(retention_sec / 86400));
    json_object_object_add(cap, "include_stale_param", json_object_new_string("include_stale"));
    json_object_object_add(cap, "stale_days_param", json_object_new_string("stale_days"));
    json_object_object_add(cap, "stale_exempt",
                           json_object_new_string("pinned,custom_name,note"));
    json_object_object_add(data, "capabilities", cap);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

static struct json_object *db_query_aliases(int64_t client_id)
{
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;
    if (db_prepare(&st, "SELECT alias_type,alias_value,source,confidence,first_seen,last_seen FROM client_aliases WHERE client_id=?1 ORDER BY confidence DESC,last_seen DESC") != 0)
        return arr;
    sqlite3_bind_int64(st, 1, client_id);
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *o = json_object_new_object();
        add_col_text(o, "key", st, 0);
        add_col_text(o, "value", st, 1);
        add_col_text(o, "source", st, 2);
        json_object_object_add(o, "confidence", json_object_new_double(sqlite3_column_double(st, 3)));
        json_object_object_add(o, "first_seen", json_object_new_int64(sqlite3_column_int64(st, 4)));
        json_object_object_add(o, "last_seen", json_object_new_int64(sqlite3_column_int64(st, 5)));
        json_object_array_add(arr, o);
    }
    sqlite3_finalize(st);
    return arr;
}

static struct json_object *db_query_override(int64_t client_id)
{
    struct json_object *o = json_object_new_object();
    struct json_object *fields = json_object_new_array();
    sqlite3_stmt *st = NULL;
    if (db_prepare(&st, "SELECT custom_name,custom_icon,custom_device_type,custom_vendor,pinned,hidden,note,updated_at FROM client_overrides WHERE client_id=?1") != 0) {
        json_object_object_add(o, "override_fields", fields);
        return o;
    }
    sqlite3_bind_int64(st, 1, client_id);
    if (sqlite3_step(st) == SQLITE_ROW) {
        add_col_text(o, "nickname", st, 0);
        add_col_text(o, "custom_image_path", st, 1);
        add_col_text(o, "device_type", st, 2);
        add_col_text(o, "vendor_name", st, 3);
        json_object_object_add(o, "pinned", json_object_new_boolean(sqlite3_column_int(st, 4) != 0));
        json_object_object_add(o, "hidden", json_object_new_boolean(sqlite3_column_int(st, 5) != 0));
        add_col_text(o, "note", st, 6);
        json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 7)));
        if (sqlite3_column_text(st, 0) && sqlite3_column_text(st, 0)[0])
            json_object_array_add(fields, json_object_new_string("nickname"));
        if (sqlite3_column_text(st, 1) && sqlite3_column_text(st, 1)[0])
            json_object_array_add(fields, json_object_new_string("custom_image_path"));
        if (sqlite3_column_text(st, 2) && sqlite3_column_text(st, 2)[0])
            json_object_array_add(fields, json_object_new_string("device_type"));
        if (sqlite3_column_text(st, 3) && sqlite3_column_text(st, 3)[0])
            json_object_array_add(fields, json_object_new_string("vendor_name"));
        if (sqlite3_column_int(st, 4))
            json_object_array_add(fields, json_object_new_string("pinned"));
        if (sqlite3_column_int(st, 5))
            json_object_array_add(fields, json_object_new_string("hidden"));
        if (sqlite3_column_text(st, 6) && sqlite3_column_text(st, 6)[0])
            json_object_array_add(fields, json_object_new_string("note"));
    }
    sqlite3_finalize(st);
    json_object_object_add(o, "override_fields", fields);
    return o;
}

static struct json_object *db_query_candidates_by_mac(const char *mac)
{
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;
        return arr;
    sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *o = json_object_new_object();
        json_object_object_add(o, "engine", json_object_new_int(sqlite3_column_int(st, 0)));
        json_object_object_add(o, "device_id", json_object_new_int(sqlite3_column_int(st, 1)));
        add_col_text(o, "device_name", st, 2);
        add_col_text(o, "vendor_name", st, 3);
        add_col_text(o, "source", st, 4);
        json_object_object_add(o, "score", json_object_new_int(sqlite3_column_int(st, 5)));
        add_col_text(o, "evidence_json", st, 6);
        json_object_object_add(o, "created_at", json_object_new_int64(sqlite3_column_int64(st, 7)));
        json_object_array_add(arr, o);
    }
    sqlite3_finalize(st);
    return arr;
}
static struct json_object *db_query_resolved_fingerprint(const char *mac)
{
    struct json_object *o = NULL;
    sqlite3_stmt *st = NULL;
    if (db_prepare(&st, "SELECT engine,device_id,vendor_id,COALESCE(device_name,''),COALESCE(vendor_name,''),COALESCE(device_type,''),COALESCE(family,''),COALESCE(os_class,''),COALESCE(os_name,''),COALESCE(image_path,''),source,confidence,COALESCE(evidence_json,'[]'),updated_at FROM client_fingerprints WHERE mac=?1") != 0)
        return NULL;
    sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *fp = json_object_new_object();
        struct json_object *img = json_object_new_object();
        json_object_object_add(fp, "engine", json_object_new_int(sqlite3_column_int(st, 0)));
        json_object_object_add(fp, "device_id", json_object_new_int(sqlite3_column_int(st, 1)));
        json_object_object_add(fp, "vendor_id", json_object_new_int(sqlite3_column_int(st, 2)));
        add_col_text(fp, "device_name", st, 3);
        add_col_text(fp, "vendor_name", st, 4);
        add_col_text(fp, "device_type", st, 5);
        add_col_text(fp, "family", st, 6);
        add_col_text(fp, "os_class", st, 7);
        add_col_text(fp, "os_name", st, 8);
        add_col_text(img, "path", st, 9);
        json_object_object_add(fp, "image", img);
        add_col_text(fp, "source", st, 10);
        json_object_object_add(fp, "confidence", json_object_new_int(sqlite3_column_int(st, 11)));
        add_col_text(fp, "evidence_json", st, 12);
        json_object_object_add(fp, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 13)));
        o = fp;
    }
    sqlite3_finalize(st);
    return o;
}

static struct json_object *db_query_identity_signals(const char *mac)
{
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;
    if (db_prepare(&st, "SELECT source,key,value,confidence,first_seen,last_seen,COALESCE(raw_json,'') FROM client_identity_signals WHERE mac=?1 ORDER BY confidence DESC,last_seen DESC") != 0)
        return arr;
    sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *o = json_object_new_object();
        add_col_text(o, "source", st, 0);
        add_col_text(o, "key", st, 1);
        add_col_text(o, "value", st, 2);
        json_object_object_add(o, "confidence", json_object_new_int(sqlite3_column_int(st, 3)));
        json_object_object_add(o, "first_seen", json_object_new_int64(sqlite3_column_int64(st, 4)));
        json_object_object_add(o, "last_seen", json_object_new_int64(sqlite3_column_int64(st, 5)));
        add_col_text(o, "raw_json", st, 6);
        json_object_array_add(arr, o);
    }
    sqlite3_finalize(st);
    return arr;
}

struct json_object *jmx_db_api_client_identity(struct json_object *req)
{
    struct json_object *data = json_object_new_object();
    char mac[32] = {0};
    sqlite3_stmt *st = NULL;
    char sql[2048];
    int64_t client_id = 0;

    if (jmx_db_init() != 0 || !req || normalize_mac(json_s(req, "mac", ""), mac, sizeof(mac)) != 0) {
        json_object_object_add(data, "error", json_object_new_string("invalid_mac_or_db"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }

    snprintf(sql, sizeof(sql), "%s WHERE c.mac=?1", client_select_sql);
    if (db_prepare(&st, sql) != 0) return jmx_gen_api_response_data(API_CODE_ERROR, data);
    sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        json_object_object_add(data, "error", json_object_new_string("not_found"));
        json_object_object_add(data, "mac", json_object_new_string(mac));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }

    client_id = sqlite3_column_int64(st, 0);
    json_object_object_add(data, "client", db_row_to_client(st));
    sqlite3_finalize(st);

    json_object_object_add(data, "mac", json_object_new_string(mac));
    {
        struct json_object *fp_resolved = db_query_resolved_fingerprint(mac);
        if (fp_resolved) json_object_object_add(data, "fingerprint", fp_resolved);
        else json_object_object_add(data, "fingerprint", NULL);
    }
    json_object_object_add(data, "signals", db_query_identity_signals(mac));
    json_object_object_add(data, "candidates", db_query_candidates_by_mac(mac));
    json_object_object_add(data, "override", db_query_override(client_id));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

int jmx_db_observe_signal(const char *mac_in, const char *source, const char *key, const char *value, int confidence, const char *raw_json)
{
    char mac[32] = {0};
    int64_t cid = 0, ts = now_s();
    sqlite3_stmt *st = NULL;
    int rc;
    if (!source || !source[0] || !key || !key[0] || !value || !value[0]) return -1;
    if (jmx_db_init() != 0 || normalize_mac(mac_in, mac, sizeof(mac)) != 0) return -1;
    if (db_begin() != 0) return -1;
    if (db_upsert_client(mac, "", "", "", "", "unknown", "", 0, ts, &cid) != 0) { db_rollback(); return -1; }
    rc = db_upsert_alias(cid, key, value, source, confidence / 100.0, ts);
    db_upsert_identity_signal(mac, source, key, value, confidence, raw_json ? raw_json : "", ts);
    if (!strcmp(key, "hostname")) {
        db_prepare(&st, "UPDATE clients SET hostname=COALESCE(NULLIF(?1,''),hostname),display_name=COALESCE(NULLIF(?1,''),display_name),updated_at=?2 WHERE client_id=?3");
        if (st) {
            bind_text_or_null(st, 1, value);
            sqlite3_bind_int64(st, 2, ts);
            sqlite3_bind_int64(st, 3, cid);
            db_step_done(st);
            sqlite3_finalize(st);
        }
    }
    if (rc != 0) { db_rollback(); return -1; }
    db_apply_identity_aggregator(mac);
    return db_commit();
}

int jmx_db_observe_signal_by_ip(const char *ip, const char *source, const char *key, const char *value, int confidence, const char *raw_json)
{
    sqlite3_stmt *st = NULL;
    char mac[32] = {0};
    int rc = -1;
    if (!ip || !ip[0]) return -1;
    if (jmx_db_init() != 0) return -1;
    if (db_prepare(&st, "SELECT c.mac FROM clients c JOIN client_network_state n ON n.client_id=c.client_id WHERE n.ip=?1 ORDER BY n.updated_at DESC LIMIT 1") != 0)
        return -1;
    sqlite3_bind_text(st, 1, ip, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *m = sqlite3_column_text(st, 0);
        if (m) snprintf(mac, sizeof(mac), "%s", (const char *)m);
    }
    sqlite3_finalize(st);
    if (mac[0]) rc = jmx_db_observe_signal(mac, source, key, value, confidence, raw_json);
    return rc;
}

/* ──────────────────────────────────────────────────────────────────────────
 * Schema v2: DreamingWrt dashboard/control-plane runtime data
 * ────────────────────────────────────────────────────────────────────────── */
static int db_schema_v2(void)
{
    const char *sql =
        "CREATE TABLE IF NOT EXISTS net_interfaces ("
        " iface_id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, kind TEXT NOT NULL DEFAULT 'wan', device TEXT, proto TEXT, carrier TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);"
        "CREATE INDEX IF NOT EXISTS idx_net_interfaces_kind ON net_interfaces(kind);"
        "CREATE TABLE IF NOT EXISTS net_interface_state ("
        " iface_id INTEGER NOT NULL UNIQUE, ts INTEGER NOT NULL, online INTEGER NOT NULL DEFAULT 0, rx_bytes INTEGER NOT NULL DEFAULT 0, tx_bytes INTEGER NOT NULL DEFAULT 0, rx_rate INTEGER NOT NULL DEFAULT 0, tx_rate INTEGER NOT NULL DEFAULT 0, latency_ms INTEGER NOT NULL DEFAULT 0, loss_pct INTEGER NOT NULL DEFAULT 0, FOREIGN KEY(iface_id) REFERENCES net_interfaces(iface_id) ON DELETE CASCADE);"
        "CREATE INDEX IF NOT EXISTS idx_net_interface_state_ts ON net_interface_state(iface_id,ts);"
        "CREATE TABLE IF NOT EXISTS wan_health_samples ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT, iface_id INTEGER NOT NULL, ts INTEGER NOT NULL, latency_ms INTEGER NOT NULL DEFAULT 0, loss_pct INTEGER NOT NULL DEFAULT 0, FOREIGN KEY(iface_id) REFERENCES net_interfaces(iface_id) ON DELETE CASCADE);"
        "CREATE INDEX IF NOT EXISTS idx_wan_health_samples_ts ON wan_health_samples(iface_id,ts);"
        "CREATE TABLE IF NOT EXISTS traffic_buckets ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT, bucket_ts INTEGER NOT NULL, bucket_sec INTEGER NOT NULL DEFAULT 3600, iface_id INTEGER, rx_bytes INTEGER NOT NULL DEFAULT 0, tx_bytes INTEGER NOT NULL DEFAULT 0, UNIQUE(bucket_ts,bucket_sec,iface_id));"
        "CREATE INDEX IF NOT EXISTS idx_traffic_buckets_ts ON traffic_buckets(bucket_ts);"
        "CREATE TABLE IF NOT EXISTS audit_url_events ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, mac TEXT, appid INTEGER, host TEXT NOT NULL, uri TEXT, sni TEXT, hit_count INTEGER NOT NULL DEFAULT 1);"
        "CREATE INDEX IF NOT EXISTS idx_audit_url_events_ts ON audit_url_events(ts);"
        "CREATE INDEX IF NOT EXISTS idx_audit_url_events_host ON audit_url_events(host,ts);"
        "CREATE TABLE IF NOT EXISTS audit_app_events ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, mac TEXT, appid INTEGER NOT NULL, hit_count INTEGER NOT NULL DEFAULT 1);"
        "CREATE INDEX IF NOT EXISTS idx_audit_app_events_ts ON audit_app_events(ts);"
        "CREATE INDEX IF NOT EXISTS idx_audit_app_events_appid ON audit_app_events(appid,ts);"
        "CREATE TABLE IF NOT EXISTS audit_runtime_stats ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, total_events INTEGER NOT NULL DEFAULT 0, dropped_events INTEGER NOT NULL DEFAULT 0, url_row_count INTEGER NOT NULL DEFAULT 0, app_row_count INTEGER NOT NULL DEFAULT 0);"
        "CREATE INDEX IF NOT EXISTS idx_audit_runtime_stats_ts ON audit_runtime_stats(ts);""CREATE TABLE IF NOT EXISTS wan_profile ( id TEXT PRIMARY KEY, ifname TEXT NOT NULL, display_name TEXT, note TEXT, carrier TEXT, access_mode TEXT, configured_up_rate INTEGER NOT NULL DEFAULT 0, configured_down_rate INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);""CREATE TABLE IF NOT EXISTS wan_session ( id INTEGER PRIMARY KEY AUTOINCREMENT, wan_id TEXT NOT NULL, ifname TEXT NOT NULL, ip TEXT, gateway TEXT, access_mode TEXT, started_at INTEGER NOT NULL, ended_at INTEGER, end_reason TEXT);""CREATE INDEX IF NOT EXISTS idx_wan_session_wan_id_ts ON wan_session(wan_id,started_at);""CREATE TABLE IF NOT EXISTS wan_health_bucket ( id INTEGER PRIMARY KEY AUTOINCREMENT, wan_id TEXT NOT NULL, bucket_start INTEGER NOT NULL, bucket_seconds INTEGER NOT NULL DEFAULT 1800, status TEXT NOT NULL, reason TEXT, latency_avg REAL DEFAULT 0, latency_max REAL DEFAULT 0, latency_min REAL DEFAULT 0, loss_up REAL DEFAULT 0, loss_down REAL DEFAULT 0, avg_up_rate INTEGER DEFAULT 0, avg_down_rate INTEGER DEFAULT 0, configured_up_rate INTEGER DEFAULT 0, configured_down_rate INTEGER DEFAULT 0, busy INTEGER DEFAULT 0, samples INTEGER DEFAULT 0, UNIQUE(wan_id, bucket_start));""CREATE INDEX IF NOT EXISTS idx_wan_health_bucket_wan_id_bucket_start ON wan_health_bucket(wan_id,bucket_start);";

    sqlite3_stmt *st = NULL;
    int64_t ts = now_s();
    if (db_exec(sql) != 0) return -1;
    if (db_prepare(&st, "INSERT INTO db_meta(key,value,updated_at) VALUES('schema_version','2',?1) ON CONFLICT(key) DO UPDATE SET value='2',updated_at=excluded.updated_at") != 0)
        return -1;
    sqlite3_bind_int64(st, 1, ts);
    if (db_step_done(st) != 0) { sqlite3_finalize(st); return -1; }
    sqlite3_finalize(st);
    return 0;
}

static int64_t db_iface_id(const char *name)
{
    sqlite3_stmt *st = NULL;
    int64_t id = 0;
    if (!name || !name[0]) return 0;
    if (db_prepare(&st, "SELECT iface_id FROM net_interfaces WHERE name=?1") != 0) return 0;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) id = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return id;
}

int jmx_db_upsert_interface(const char *name, const char *kind, const char *device, const char *proto, const char *carrier)
{
    sqlite3_stmt *st = NULL;
    int64_t ts = now_s();
    int rc;
    if (!name || !name[0]) return -1;
    if (jmx_db_init() != 0) return -1;
    if (db_prepare(&st, "INSERT INTO net_interfaces(name,kind,device,proto,carrier,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?6) ON CONFLICT(name) DO UPDATE SET kind=excluded.kind,device=COALESCE(excluded.device,net_interfaces.device),proto=COALESCE(excluded.proto,net_interfaces.proto),carrier=COALESCE(excluded.carrier,net_interfaces.carrier),updated_at=excluded.updated_at") != 0)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, (kind && kind[0]) ? kind : "wan", -1, SQLITE_TRANSIENT);
    bind_text_or_null(st, 3, device);
    bind_text_or_null(st, 4, proto);
    bind_text_or_null(st, 5, carrier);
    sqlite3_bind_int64(st, 6, ts);
    rc = db_step_done(st);
    sqlite3_finalize(st);
    return rc;
}

int jmx_db_write_interface_state(const char *name, int online, unsigned long long rx_bytes, unsigned long long tx_bytes, int64_t rx_rate, int64_t tx_rate, int latency_ms, int loss_pct)
{
    sqlite3_stmt *st = NULL;
    int64_t id, ts = now_s();
    int rc;
    if (jmx_db_upsert_interface(name, "wan", NULL, NULL, NULL) != 0) return -1;
    id = db_iface_id(name);
    if (id <= 0) return -1;
    if (db_prepare(&st, "INSERT INTO net_interface_state(iface_id,ts,online,rx_bytes,tx_bytes,rx_rate,tx_rate,latency_ms,loss_pct) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(iface_id) DO UPDATE SET ts=excluded.ts,online=excluded.online,rx_bytes=excluded.rx_bytes,tx_bytes=excluded.tx_bytes,rx_rate=excluded.rx_rate,tx_rate=excluded.tx_rate,latency_ms=excluded.latency_ms,loss_pct=excluded.loss_pct") != 0)
        return -1;
    sqlite3_bind_int64(st, 1, id); sqlite3_bind_int64(st, 2, ts); sqlite3_bind_int(st, 3, online ? 1 : 0);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)rx_bytes); sqlite3_bind_int64(st, 5, (sqlite3_int64)tx_bytes);
    sqlite3_bind_int64(st, 6, rx_rate); sqlite3_bind_int64(st, 7, tx_rate); sqlite3_bind_int(st, 8, latency_ms); sqlite3_bind_int(st, 9, loss_pct);
    rc = db_step_done(st);
    sqlite3_finalize(st);
    if (rc == 0) {
        jmx_db_update_daily_usage_counter(name, rx_bytes, tx_bytes, online);
        /* Lifetime totals must be maintained on every sample, online or not, or
         * a reconnect that lands between two samples silently rebases them. */
        jmx_db_update_wan_lifetime_usage(name, rx_bytes, tx_bytes, online);
    }
    return rc;
}

int jmx_db_write_wan_health(const char *name, int latency_ms, int loss_pct)
{
    sqlite3_stmt *st = NULL;
    int64_t id, ts = now_s();
    int rc;
    if (jmx_db_upsert_interface(name, "wan", NULL, NULL, NULL) != 0) return -1;
    id = db_iface_id(name);
    if (id <= 0) return -1;
    if (db_prepare(&st, "INSERT INTO wan_health_samples(iface_id,ts,latency_ms,loss_pct) VALUES(?1,?2,?3,?4)") != 0) return -1;
    sqlite3_bind_int64(st, 1, id); sqlite3_bind_int64(st, 2, ts); sqlite3_bind_int(st, 3, latency_ms); sqlite3_bind_int(st, 4, loss_pct);
    rc = db_step_done(st); sqlite3_finalize(st); return rc;
}

int jmx_db_write_traffic_bucket(int64_t bucket_ts, int bucket_sec, const char *iface_name, unsigned long long rx_bytes, unsigned long long tx_bytes)
{
    sqlite3_stmt *st = NULL;
    int64_t id = 0;
    int rc;
    if (jmx_db_init() != 0) return -1;
    if (iface_name && iface_name[0]) { jmx_db_upsert_interface(iface_name, "wan", NULL, NULL, NULL); id = db_iface_id(iface_name); }
    if (db_prepare(&st, "INSERT INTO traffic_buckets(bucket_ts,bucket_sec,iface_id,rx_bytes,tx_bytes) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(bucket_ts,bucket_sec,iface_id) DO UPDATE SET rx_bytes=excluded.rx_bytes,tx_bytes=excluded.tx_bytes") != 0) return -1;
    sqlite3_bind_int64(st, 1, bucket_ts); sqlite3_bind_int(st, 2, bucket_sec > 0 ? bucket_sec : 3600);
    if (id > 0) sqlite3_bind_int64(st, 3, id); else sqlite3_bind_null(st, 3);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)rx_bytes); sqlite3_bind_int64(st, 5, (sqlite3_int64)tx_bytes);
    rc = db_step_done(st); sqlite3_finalize(st); return rc;
}

int jmx_db_write_audit_stats(int64_t now_ts, uint64_t total, uint64_t dropped, int url_count, int app_count)
{
    sqlite3_stmt *st = NULL; int rc;
    if (jmx_db_init() != 0) return -1;
    if (db_prepare(&st, "INSERT INTO audit_runtime_stats(ts,total_events,dropped_events,url_row_count,app_row_count) VALUES(?1,?2,?3,?4,?5)") != 0) return -1;
    sqlite3_bind_int64(st, 1, now_ts ? now_ts : now_s()); sqlite3_bind_int64(st, 2, (sqlite3_int64)total); sqlite3_bind_int64(st, 3, (sqlite3_int64)dropped);
    sqlite3_bind_int(st, 4, url_count); sqlite3_bind_int(st, 5, app_count);
    rc = db_step_done(st); sqlite3_finalize(st); return rc;
}

int jmx_db_flush_audit_urls(int64_t now_ts, int max_rows) { (void)max_rows; return jmx_db_write_audit_stats(now_ts, 0, 0, 0, 0); }
int jmx_db_flush_audit_apps(int64_t now_ts, int max_rows) { (void)now_ts; (void)max_rows; return jmx_db_init(); }

static int db_delete_before(const char *sql, int64_t cutoff)
{
    sqlite3_stmt *st = NULL; int changes;
    if (jmx_db_init() != 0) return -1;
    if (db_prepare(&st, sql) != 0) return -1;
    sqlite3_bind_int64(st, 1, cutoff);
    if (db_step_done(st) != 0) { sqlite3_finalize(st); return -1; }
    changes = sqlite3_changes(g_db);
    sqlite3_finalize(st); return changes;
}

int jmx_db_prune_audit(int64_t now_ts, int64_t max_age_sec)
{
    int a, b, cutoff = (int)((now_ts ? now_ts : now_s()) - (max_age_sec > 0 ? max_age_sec : 7 * 86400));
    a = db_delete_before("DELETE FROM audit_url_events WHERE ts<?1", cutoff);
    b = db_delete_before("DELETE FROM audit_app_events WHERE ts<?1", cutoff);
    return (a < 0 || b < 0) ? -1 : a + b;
}
int jmx_db_prune_traffic_buckets(int64_t now_ts, int64_t max_age_sec) { return db_delete_before("DELETE FROM traffic_buckets WHERE bucket_ts<?1", (now_ts ? now_ts : now_s()) - (max_age_sec > 0 ? max_age_sec : 30 * 86400)); }
int jmx_db_prune_interface_state(int64_t now_ts, int64_t max_age_sec) { return db_delete_before("DELETE FROM net_interface_state WHERE ts<?1", (now_ts ? now_ts : now_s()) - (max_age_sec > 0 ? max_age_sec : 7 * 86400)); }
int jmx_db_prune_wan_health(int64_t now_ts, int64_t max_age_sec) { return db_delete_before("DELETE FROM wan_health_samples WHERE ts<?1", (now_ts ? now_ts : now_s()) - (max_age_sec > 0 ? max_age_sec : 30 * 86400)); }

int jmx_db_prune_and_vacuum(void)
{
    int64_t now = now_s();
    int n;
    int rc = 0;

    if (jmx_db_init() != 0) return -1;

    /* prune: audit 3d, traffic 7d, interface_state UPSERT so no prune needed, wan_health 1d */
    n = jmx_db_prune_audit(now, 3 * 86400);
    if (n < 0) rc = -1;
    if (n > 0) LOG_INFO("prune audit: deleted %d rows\n", n);

    n = jmx_db_prune_traffic_buckets(now, 7 * 86400);
    if (n < 0) rc = -1;
    if (n > 0) LOG_INFO("prune traffic_buckets: deleted %d rows\n", n);

    n = jmx_db_prune_wan_health(now, 6 * 3600);  /* keep only 6h of samples */
    if (n < 0) rc = -1;
    if (n > 0) LOG_INFO("prune wan_health_samples: deleted %d rows\n", n);

    if (jmx_db_prune_activity_samples(31 * 86400) < 0)  /* keep 31 days of activity samples */
        rc = -1;
    if (jmx_db_prune_system_health_samples(31 * 86400) < 0)  /* keep 31 days of system health samples */
        rc = -1;

    /* cap audit_runtime_stats: keep latest 168 rows (7 days hourly) */
    db_exec("DELETE FROM audit_runtime_stats WHERE id NOT IN "
            "(SELECT id FROM audit_runtime_stats ORDER BY ts DESC LIMIT 168)");
    /* WAL checkpoint to prevent wal file bloat */
    db_exec("PRAGMA wal_checkpoint(TRUNCATE);");

    /* Drop candidates table if exists (removed feature) */
    db_exec("DROP TABLE IF EXISTS client_fingerprint_candidates");

    /* VACUUM once daily (check hour to avoid running every prune cycle) */
    {
        time_t t = (time_t)now;
        struct tm *tm = localtime(&t);
        if (tm && tm->tm_hour == 3 && tm->tm_min < 10) {
            LOG_INFO("daily VACUUM starting...\n");
            db_exec("VACUUM;");
            LOG_INFO("daily VACUUM done\n");
        }
    }
    return rc;
}

struct json_object *jmx_db_api_audit_urls(struct json_object *req)
{
    struct json_object *data = json_object_new_object(), *arr = json_object_new_array();
    sqlite3_stmt *st = NULL; int limit = json_i(req, "limit", 100); int64_t from = json_i64(req, "ts_from", 0), to = json_i64(req, "ts_to", now_s());
    if (limit <= 0 || limit > 1000) limit = 100;
    if (jmx_db_init() != 0 || db_prepare(&st, "SELECT ts,COALESCE(mac,''),COALESCE(appid,0),host,COALESCE(uri,''),COALESCE(sni,''),hit_count FROM audit_url_events WHERE ts>=?1 AND ts<=?2 ORDER BY ts DESC LIMIT ?3") != 0) {
        json_object_object_add(data, "urls", arr); return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    sqlite3_bind_int64(st, 1, from); sqlite3_bind_int64(st, 2, to); sqlite3_bind_int(st, 3, limit);
    while (sqlite3_step(st) == SQLITE_ROW) { struct json_object *o = json_object_new_object(); json_object_object_add(o,"ts",json_object_new_int64(sqlite3_column_int64(st,0))); add_col_text(o,"mac",st,1); json_object_object_add(o,"appid",json_object_new_int(sqlite3_column_int(st,2))); add_col_text(o,"host",st,3); add_col_text(o,"uri",st,4); add_col_text(o,"sni",st,5); json_object_object_add(o,"hit_count",json_object_new_int(sqlite3_column_int(st,6))); json_object_array_add(arr,o); }
    sqlite3_finalize(st); json_object_object_add(data, "urls", arr); return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

struct json_object *jmx_db_api_audit_apps(struct json_object *req)
{
    struct json_object *data = json_object_new_object(), *arr = json_object_new_array();
    sqlite3_stmt *st = NULL; int limit = json_i(req, "limit", 100); int64_t from = json_i64(req, "ts_from", 0), to = json_i64(req, "ts_to", now_s());
    if (limit <= 0 || limit > 1000) limit = 100;
    if (jmx_db_init() != 0 || db_prepare(&st, "SELECT ts,COALESCE(mac,''),appid,hit_count FROM audit_app_events WHERE ts>=?1 AND ts<=?2 ORDER BY ts DESC LIMIT ?3") != 0) { json_object_object_add(data, "apps", arr); return jmx_gen_api_response_data(API_CODE_ERROR, data); }
    sqlite3_bind_int64(st, 1, from); sqlite3_bind_int64(st, 2, to); sqlite3_bind_int(st, 3, limit);
    while (sqlite3_step(st) == SQLITE_ROW) { struct json_object *o = json_object_new_object(); json_object_object_add(o,"ts",json_object_new_int64(sqlite3_column_int64(st,0))); add_col_text(o,"mac",st,1); json_object_object_add(o,"appid",json_object_new_int(sqlite3_column_int(st,2))); json_object_object_add(o,"hit_count",json_object_new_int(sqlite3_column_int(st,3))); json_object_array_add(arr,o); }
    sqlite3_finalize(st); json_object_object_add(data, "apps", arr); return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

struct json_object *jmx_db_api_audit_status(struct json_object *req)
{
    struct json_object *data = json_object_new_object(); sqlite3_stmt *st = NULL; (void)req;
    json_object_object_add(data, "db_path", json_object_new_string(JMX_DB_PATH_DEFAULT));
    if (jmx_db_init() == 0 && db_prepare(&st, "SELECT ts,total_events,dropped_events,url_row_count,app_row_count FROM audit_runtime_stats ORDER BY ts DESC LIMIT 1") == 0) {
        if (sqlite3_step(st) == SQLITE_ROW) { json_object_object_add(data,"ts",json_object_new_int64(sqlite3_column_int64(st,0))); json_object_object_add(data,"total_events",json_object_new_int64(sqlite3_column_int64(st,1))); json_object_object_add(data,"dropped_events",json_object_new_int64(sqlite3_column_int64(st,2))); json_object_object_add(data,"url_row_count",json_object_new_int(sqlite3_column_int(st,3))); json_object_object_add(data,"app_row_count",json_object_new_int(sqlite3_column_int(st,4))); }
        sqlite3_finalize(st);
    }
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

/** Forward declarations for line health types/helpers defined below */

/* line_load API: return interfaces[] matching frontend spec */
struct json_object *jmx_db_api_line_load(struct json_object *req)
{
    struct json_object *data = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;
    int limit = json_i(req, "limit", 32);
    int64_t now = now_s();
    if (limit <= 0 || limit > 128) limit = 32;

    json_object_object_add(data, "ts", json_object_new_int64(now));
    if (jmx_db_init() == 0 && db_prepare(&st,
        "SELECT i.name,i.kind,i.device,i.proto,i.carrier,s.ts,s.online,s.rx_bytes,s.tx_bytes,s.rx_rate,s.tx_rate,s.latency_ms,s.loss_pct "
        "FROM net_interfaces i LEFT JOIN net_interface_state s ON s.rowid=(SELECT rowid FROM net_interface_state WHERE iface_id=i.iface_id ORDER BY ts DESC LIMIT 1) "
        "WHERE i.kind='wan' ORDER BY i.name LIMIT ?1") == 0) {
        sqlite3_bind_int(st, 1, limit);
        int idx = 1;
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *name = (const char *)sqlite3_column_text(st, 0);
            const char *device = (const char *)sqlite3_column_text(st, 2);
            const char *proto = (const char *)sqlite3_column_text(st, 3);
            const char *carrier = (const char *)sqlite3_column_text(st, 4);
            int online = sqlite3_column_int(st, 6);
            int64_t rx_bytes = sqlite3_column_int64(st, 7);
            int64_t tx_bytes = sqlite3_column_int64(st, 8);
            int rx_rate = sqlite3_column_int(st, 9);
            int tx_rate = sqlite3_column_int(st, 10);
            int latency = sqlite3_column_int(st, 11);
            int loss = sqlite3_column_int(st, 12);
            const char *note = "";

            int link_speed = 0;
            if (device && device[0]) {
                char path[128];
                snprintf(path, sizeof(path), "/sys/class/net/%s/speed", device);
                FILE *f = fopen(path, "r");
                if (f) { if (fscanf(f, "%d", &link_speed) != 1) link_speed = 0; fclose(f); }
            }

            char ip[32] = "", ipv6[64] = "";
            char gateway[32] = "";
            if (name && name[0]) {
                iface_status_t ifs;
                memset(&ifs, 0, sizeof(ifs));
                if (get_iface_status((char *)name, &ifs) == 0) {
                    snprintf(ip, sizeof(ip), "%s", ifs.ip);
                    snprintf(ipv6, sizeof(ipv6), "%s", ifs.ipv6);
                    snprintf(gateway, sizeof(gateway), "%s", ifs.gateway);
                }
                jmx_db_update_wan_session(name, name, ip, gateway,
                                          proto ? proto : "", online);
            }

            struct json_object *o = json_object_new_object();
            json_object_object_add(o, "id", json_object_new_string(name ? name : ""));
            json_object_object_add(o, "order", json_object_new_int(idx));
            json_object_object_add(o, "type", json_object_new_string("wan"));
            json_object_object_add(o, "name", json_object_new_string(name ? name : ""));
            json_object_object_add(o, "note", json_object_new_string(note));
            json_object_object_add(o, "ifname", json_object_new_string(name ? name : ""));
            json_object_object_add(o, "device", json_object_new_string(device ? device : ""));
            json_object_object_add(o, "proto", json_object_new_string(proto ? proto : ""));
            json_object_object_add(o, "carrier", json_object_new_string(carrier ? carrier : ""));
            json_object_object_add(o, "ip", json_object_new_string(ip));
            json_object_object_add(o, "ipv6", json_object_new_string(ipv6));
            json_object_object_add(o, "gateway", json_object_new_string(gateway));
            if (link_speed > 0) {
                char spd[32]; snprintf(spd, sizeof(spd), "%d Mbps", link_speed);
                json_object_object_add(o, "link_speed", json_object_new_string(spd));
            } else {
                json_object_object_add(o, "link_speed", json_object_new_string(""));
            }
            json_object_object_add(o, "up_rate", json_object_new_int64((int64_t)tx_rate));
            json_object_object_add(o, "down_rate", json_object_new_int64((int64_t)rx_rate));
            jmx_db_add_wan_cumulative_bytes(o, name, rx_bytes, tx_bytes);
            json_object_object_add(o, "connections", json_object_new_int(0));
            json_object_object_add(o, "online", json_object_new_boolean(online != 0));
            json_object_object_add(o, "status", json_object_new_string(online ? ((loss >= 50 || latency >= 180) ? "bad" : ((loss > 0 || latency >= 80) ? "warn" : "ok")) : "down"));
            json_object_object_add(o, "latency", json_object_new_int(latency));
            json_object_object_add(o, "latency_ms", json_object_new_int(latency));
            json_object_object_add(o, "loss", json_object_new_int(loss));
            json_object_object_add(o, "loss_pct", json_object_new_int(loss));
            jmx_db_add_wan_session_contract(o, name, now);
            jmx_db_add_wan_loss_contract(o, name, now);
            json_object_array_add(arr, o);
            idx++;
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(data, "interfaces", arr);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

/* ══════════════════════════════════════════════════════════════════════
 * line_health: memory ring buffer + WAN session + health bucket
 * ══════════════════════════════════════════════════════════════════════ */

#define DW_MAX_WANS_H          16
#define MAX_WAN_PROFILES       64
#define MAX_WAN_SESSIONS       16
#define MAX_HEALTH_BUCKETS     1024
#define BUCKET_SECONDS         1800   /* 30 min */
#define HISTORY_24H_BUCKETS    48
#define LATENCY_BAD_MS         150
#define LATENCY_WARN_MS        60
#define LOSS_BAD_PCT           5
#define LOSS_WARN_PCT          2

typedef struct {
    char ifname[32];
    char display_name[64];
    char note[128];
    char carrier[32];
    char access_mode[32];
    int  configured_up_rate;   /* kbps */
    int  configured_down_rate; /* kbps */
    int  dirty;
} wan_profile_t;

typedef struct {
    char wan_id[64];
    char ifname[32];
    char ip[64];
    char gateway[64];
    char access_mode[32];
    int64_t started_at;
    int64_t ended_at;
    char end_reason[64];
    int  active;
    int  dirty;
} wan_session_state_t;

typedef struct {
    char wan_id[64];
    int64_t bucket_start;
    int  samples;
    int  latency_sum_ms;
    int  latency_max_ms;
    int  latency_min_ms;
    int  loss_up_sum;
    int  loss_down_sum;
    int  up_rate_sum;
    int  down_rate_sum;
    int  online_count;
    int  total_count;
    int  dirty;
} wan_health_bucket_mem_t;

static wan_profile_t         g_profiles[MAX_WAN_PROFILES];
static int                   g_profile_count = 0;
static wan_session_state_t   g_sessions[MAX_WAN_SESSIONS];
static int                   g_session_count = 0;
static wan_health_bucket_mem_t g_buckets[MAX_HEALTH_BUCKETS];
static int                   g_bucket_count = 0;

static int g_health_flush_sec    = 60;
static int g_health_prune_sec    = 300;
static int g_health_max_age_days = 30;

/* ── helpers ── */

static wan_profile_t *find_profile(const char *ifname)
{
    int i;
    if (!ifname || !ifname[0]) return NULL;
    for (i = 0; i < g_profile_count; i++)
        if (strcmp(g_profiles[i].ifname, ifname) == 0) return &g_profiles[i];
    return NULL;
}

static wan_profile_t *find_or_create_profile(const char *ifname)
{
    wan_profile_t *p = find_profile(ifname);
    if (p) return p;
    if (g_profile_count >= MAX_WAN_PROFILES) return NULL;
    p = &g_profiles[g_profile_count++];
    memset(p, 0, sizeof(*p));
    snprintf(p->ifname, sizeof(p->ifname), "%s", ifname ? ifname : "");
    return p;
}

static wan_session_state_t *find_session(const char *wan_id)
{
    int i;
    if (!wan_id || !wan_id[0]) return NULL;
    for (i = 0; i < g_session_count; i++)
        if (strcmp(g_sessions[i].wan_id, wan_id) == 0) return &g_sessions[i];
    return NULL;
}

static wan_session_state_t *find_or_create_session(const char *wan_id, const char *ifname)
{
    wan_session_state_t *s = find_session(wan_id);
    if (s) return s;
    if (g_session_count >= MAX_WAN_SESSIONS) return NULL;
    s = &g_sessions[g_session_count++];
    memset(s, 0, sizeof(*s));
    snprintf(s->wan_id, sizeof(s->wan_id), "%s", wan_id ? wan_id : "");
    snprintf(s->ifname, sizeof(s->ifname), "%s", ifname ? ifname : "");
    return s;
}

static int64_t bucket_start_for(int64_t ts)
{
    return (ts / BUCKET_SECONDS) * BUCKET_SECONDS;
}

static wan_health_bucket_mem_t *find_bucket(const char *wan_id, int64_t bucket_start)
{
    int i;
    for (i = 0; i < g_bucket_count; i++)
        if (strcmp(g_buckets[i].wan_id, wan_id) == 0 &&
            g_buckets[i].bucket_start == bucket_start) return &g_buckets[i];
    return NULL;
}

static wan_health_bucket_mem_t *find_or_create_bucket(const char *wan_id, int64_t bucket_start)
{
    wan_health_bucket_mem_t *b = find_bucket(wan_id, bucket_start);
    if (b) return b;
    if (g_bucket_count >= MAX_HEALTH_BUCKETS) {
        /* evict oldest */
        int oldest = 0, i;
        for (i = 1; i < g_bucket_count; i++)
            if (g_buckets[i].bucket_start < g_buckets[oldest].bucket_start) oldest = i;
        b = &g_buckets[oldest];
        memset(b, 0, sizeof(*b));
    } else {
        b = &g_buckets[g_bucket_count++];
        memset(b, 0, sizeof(*b));
    }
    snprintf(b->wan_id, sizeof(b->wan_id), "%s", wan_id ? wan_id : "");
    b->bucket_start = bucket_start;
    return b;
}

/* ── health config from config.db ── */

void jmx_db_load_health_config(void)
{
    jmx_legacy_settings_t settings;

    if (jmx_legacy_settings_get(&settings) == 0) {
        if (settings.health_flush_sec > 0)
            g_health_flush_sec = settings.health_flush_sec;
        if (settings.health_prune_sec > 0)
            g_health_prune_sec = settings.health_prune_sec;
        if (settings.health_max_age_days > 0)
            g_health_max_age_days = settings.health_max_age_days;
    }
    LOG_INFO("health config: flush=%ds prune=%ds max_age=%dd\n",
             g_health_flush_sec, g_health_prune_sec, g_health_max_age_days);
}

/* ── profile upsert ── */

int jmx_db_upsert_wan_profile(const char *ifname, const char *display_name,
                               const char *note, const char *carrier,
                               const char *access_mode,
                               int configured_up_rate, int configured_down_rate)
{
    wan_profile_t *p;
    if (!ifname || !ifname[0]) return -1;

    /* memory */
    p = find_or_create_profile(ifname);
    if (!p) return -1;
    if (display_name && display_name[0]) snprintf(p->display_name, sizeof(p->display_name), "%s", display_name);
    if (note && note[0]) snprintf(p->note, sizeof(p->note), "%s", note);
    if (carrier && carrier[0]) snprintf(p->carrier, sizeof(p->carrier), "%s", carrier);
    if (access_mode && access_mode[0]) snprintf(p->access_mode, sizeof(p->access_mode), "%s", access_mode);
    if (configured_up_rate > 0) p->configured_up_rate = configured_up_rate;
    if (configured_down_rate > 0) p->configured_down_rate = configured_down_rate;
    p->dirty = 1;

    /* DB */
    if (jmx_db_init() == 0) {
        sqlite3_stmt *st = NULL;
        int64_t ts = now_s();
        if (db_prepare(&st,
            "INSERT INTO wan_profile(id,ifname,display_name,note,carrier,access_mode,"
            "configured_up_rate,configured_down_rate,created_at,updated_at) "
            "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?9) "
            "ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name,"
            "note=excluded.note,carrier=excluded.carrier,access_mode=excluded.access_mode,"
            "configured_up_rate=excluded.configured_up_rate,"
            "configured_down_rate=excluded.configured_down_rate,updated_at=excluded.updated_at") == 0) {
            sqlite3_bind_text(st, 1, ifname, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, ifname, -1, SQLITE_TRANSIENT);
            bind_text_or_null(st, 3, p->display_name);
            bind_text_or_null(st, 4, p->note);
            bind_text_or_null(st, 5, p->carrier);
            bind_text_or_null(st, 6, p->access_mode);
            sqlite3_bind_int(st, 7, p->configured_up_rate);
            sqlite3_bind_int(st, 8, p->configured_down_rate);
            sqlite3_bind_int64(st, 9, ts);
            db_step_done(st);
            sqlite3_finalize(st);
        }
    }
    return 0;
}

/* ── session tracking ── */

void jmx_db_update_wan_session(const char *wan_id, const char *ifname,
                                const char *ip, const char *gateway,
                                const char *access_mode, int online)
{
    wan_session_state_t *s;
    int changed = 0;
    int64_t existing_started_at = 0;
    int64_t current_ts;
    int64_t boot_uptime;
    int64_t boot_at = 0;
    if (!wan_id || !wan_id[0]) return;

    s = find_or_create_session(wan_id, ifname);
    if (!s) return;

    if (online) {
        if (!s->active) {
            /* new session */
            s->active = 1;
            current_ts = now_s();
            boot_uptime = db_read_system_uptime_sec();
            if (boot_uptime > 0 && boot_uptime <= current_ts)
                boot_at = current_ts - boot_uptime;
            existing_started_at = jmx_db_wan_session_started_at(wan_id);
            if (existing_started_at > current_ts ||
                (boot_at > 0 && existing_started_at > 0 && existing_started_at < boot_at)) {
                if (jmx_db_init() == 0) {
                    sqlite3_stmt *st = NULL;
                    if (db_prepare(&st,
                        "UPDATE wan_session SET ended_at=?1,end_reason=?2 "
                        "WHERE wan_id=?3 AND ended_at IS NULL") == 0) {
                        sqlite3_bind_int64(st, 1, current_ts);
                        sqlite3_bind_text(st, 2,
                            existing_started_at > current_ts ?
                            "future_timestamp_pruned" : "previous_boot_pruned",
                            -1, SQLITE_STATIC);
                        sqlite3_bind_text(st, 3, wan_id, -1, SQLITE_TRANSIENT);
                        db_step_done(st);
                        sqlite3_finalize(st);
                    }
                }
                existing_started_at = 0;
            }
            s->started_at = existing_started_at > 0 ? existing_started_at : current_ts;
            s->ended_at = 0;
            s->end_reason[0] = '\0';
            changed = existing_started_at <= 0;
        }
        /* check ip/gateway change */
        if (ip && strcmp(s->ip, ip) != 0) {
            snprintf(s->ip, sizeof(s->ip), "%s", ip);
            changed = 1;
        }
        if (gateway && strcmp(s->gateway, gateway) != 0) {
            snprintf(s->gateway, sizeof(s->gateway), "%s", gateway);
            changed = 1;
        }
        if (access_mode && strcmp(s->access_mode, access_mode) != 0) {
            snprintf(s->access_mode, sizeof(s->access_mode), "%s", access_mode);
            changed = 1;
        }
        if (changed) {
            s->dirty = 1;
            /* write to DB */
            if (jmx_db_init() == 0) {
                sqlite3_stmt *st = NULL;
                if (existing_started_at > 0) {
                    if (db_prepare(&st,
                        "UPDATE wan_session SET ifname=?1,ip=?2,gateway=?3,access_mode=?4 "
                        "WHERE wan_id=?5 AND ended_at IS NULL") == 0) {
                        sqlite3_bind_text(st, 1, ifname ? ifname : "", -1, SQLITE_TRANSIENT);
                        bind_text_or_null(st, 2, s->ip);
                        bind_text_or_null(st, 3, s->gateway);
                        bind_text_or_null(st, 4, s->access_mode);
                        sqlite3_bind_text(st, 5, wan_id, -1, SQLITE_TRANSIENT);
                        db_step_done(st);
                        sqlite3_finalize(st);
                    }
                } else if (db_prepare(&st,
                    "INSERT INTO wan_session(wan_id,ifname,ip,gateway,access_mode,started_at) "
                    "VALUES(?1,?2,?3,?4,?5,?6)") == 0) {
                        sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(st, 2, ifname ? ifname : "", -1, SQLITE_TRANSIENT);
                        bind_text_or_null(st, 3, s->ip);
                        bind_text_or_null(st, 4, s->gateway);
                        bind_text_or_null(st, 5, s->access_mode);
                        sqlite3_bind_int64(st, 6, s->started_at);
                        db_step_done(st);
                        sqlite3_finalize(st);
                }
                st = NULL;
                if (db_prepare(&st,
                    "UPDATE wan_session SET ended_at=?1,end_reason='duplicate_active_pruned' "
                    "WHERE wan_id=?2 AND ended_at IS NULL AND id NOT IN "
                    "(SELECT id FROM wan_session WHERE wan_id=?2 AND ended_at IS NULL "
                    " ORDER BY started_at ASC, id ASC LIMIT 1)") == 0) {
                    sqlite3_bind_int64(st, 1, now_s());
                    sqlite3_bind_text(st, 2, wan_id, -1, SQLITE_TRANSIENT);
                    db_step_done(st);
                    sqlite3_finalize(st);
                }
            }
        }
    } else {
        if (s->active) {
            /* session ended */
            s->active = 0;
            s->ended_at = now_s();
            snprintf(s->end_reason, sizeof(s->end_reason), "link_down");
            /* update DB end time */
            if (jmx_db_init() == 0) {
                sqlite3_stmt *st = NULL;
                if (db_prepare(&st,
                    "UPDATE wan_session SET ended_at=?1,end_reason=?2 "
                    "WHERE wan_id=?3 AND ended_at IS NULL") == 0) {
                    sqlite3_bind_int64(st, 1, s->ended_at);
                    sqlite3_bind_text(st, 2, "link_down", -1, SQLITE_STATIC);
                    sqlite3_bind_text(st, 3, wan_id, -1, SQLITE_TRANSIENT);
                    db_step_done(st);
                    sqlite3_finalize(st);
                }
            }
        }
    }
}

int64_t jmx_db_wan_session_uptime(const char *wan_id, int64_t now_ts)
{
    sqlite3_stmt *st = NULL;
    int64_t started_at = 0;
    int64_t boot_uptime;
    int64_t boot_at = 0;

    if (!wan_id || !wan_id[0])
        return 0;
    if (jmx_db_init() != 0)
        return 0;
    if (now_ts <= 0)
        now_ts = now_s();
    if (db_prepare(&st,
        "SELECT started_at FROM wan_session WHERE wan_id=?1 AND ended_at IS NULL "
        "ORDER BY started_at ASC, id ASC LIMIT 1") != 0)
        return 0;
    sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        started_at = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    if (started_at <= 0 || started_at > now_ts)
        return 0;
    boot_uptime = db_read_system_uptime_sec();
    if (boot_uptime > 0 && boot_uptime <= now_ts)
        boot_at = now_ts - boot_uptime;
    if (boot_at > 0 && started_at < boot_at)
        return 0;
    return now_ts - started_at;
}

int64_t jmx_db_wan_session_started_at(const char *wan_id)
{
    sqlite3_stmt *st = NULL;
    int64_t started_at = 0;

    if (!wan_id || !wan_id[0])
        return 0;
    if (jmx_db_init() != 0)
        return 0;
    if (db_prepare(&st,
        "SELECT started_at FROM wan_session WHERE wan_id=?1 AND ended_at IS NULL "
        "ORDER BY started_at ASC, id ASC LIMIT 1") != 0)
        return 0;
    sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        started_at = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return started_at > 0 ? started_at : 0;
}

void jmx_db_add_wan_session_contract(struct json_object *obj,
                                     const char *wan_id,
                                     int64_t now_ts)
{
    int64_t started_at;
    int64_t uptime;
    int64_t boot_uptime;
    int64_t boot_at = 0;
    int valid = 0;
    const char *source = "wan_session_db";
    const char *reason = "no_active_session";

    if (!obj || !wan_id || !wan_id[0])
        return;
    if (now_ts <= 0)
        now_ts = now_s();
    started_at = jmx_db_wan_session_started_at(wan_id);
    boot_uptime = db_read_system_uptime_sec();
    if (boot_uptime > 0 && boot_uptime <= now_ts)
        boot_at = now_ts - boot_uptime;
    uptime = 0;
    if (started_at > now_ts) {
        reason = "future_session_timestamp";
    } else if (started_at > 0 && boot_at > 0 && started_at < boot_at) {
        started_at = 0;
        source = "system_boot_guard";
        reason = "session_predates_current_boot";
    } else if (started_at > 0) {
        uptime = now_ts - started_at;
        valid = 1;
        reason = "ok";
    }
    json_object_object_add(obj, "uptime", json_object_new_int64(uptime));
    json_object_object_add(obj, "online_seconds", json_object_new_int64(uptime));
    json_object_object_add(obj, "connected_seconds", json_object_new_int64(uptime));
    if (started_at > 0)
        json_object_object_add(obj, "connected_at", json_object_new_int64(started_at));
    json_object_object_add(obj, "connection_time_source", json_object_new_string(source));
    json_object_object_add(obj, "connection_time_valid", json_object_new_boolean(valid));
    json_object_object_add(obj, "connection_time_reason", json_object_new_string(reason));
}

void jmx_db_add_wan_loss_contract(struct json_object *obj,
                                  const char *wan_id,
                                  int64_t now_ts)
{
    sqlite3_stmt *st = NULL;
    int64_t cutoff;
    double up = 0.0;
    double down = 0.0;
    double latency = 0.0;
    int samples = 0;

    if (!obj || !wan_id || !wan_id[0])
        return;
    if (now_ts <= 0)
        now_ts = now_s();
    cutoff = now_ts - 86400;
    if (jmx_db_init() == 0 &&
        db_prepare(&st,
            "SELECT COALESCE(SUM(loss_up*samples)*1.0/NULLIF(SUM(samples),0),0),"
            "       COALESCE(SUM(loss_down*samples)*1.0/NULLIF(SUM(samples),0),0),"
            "       COALESCE(SUM(latency_avg*samples)*1.0/NULLIF(SUM(samples),0),0),"
            "       COALESCE(SUM(samples),0) "
            "FROM wan_health_bucket WHERE wan_id=?1 AND bucket_start>=?2 AND bucket_start<=?3") == 0) {
        sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, cutoff);
        sqlite3_bind_int64(st, 3, now_ts);
        if (sqlite3_step(st) == SQLITE_ROW) {
            up = sqlite3_column_double(st, 0);
            down = sqlite3_column_double(st, 1);
            latency = sqlite3_column_double(st, 2);
            samples = sqlite3_column_int(st, 3);
        }
        sqlite3_finalize(st);
    }

    json_object_object_add(obj, "up_loss_24h", json_object_new_double(up));
    json_object_object_add(obj, "down_loss_24h", json_object_new_double(down));
    json_object_object_add(obj, "loss_up_24h", json_object_new_double(up));
    json_object_object_add(obj, "loss_down_24h", json_object_new_double(down));
    json_object_object_add(obj, "loss_window_sec", json_object_new_int(86400));
    json_object_object_add(obj, "loss_window_label", json_object_new_string("24h"));
    json_object_object_add(obj, "loss_source", json_object_new_string("wan_health_bucket"));
    json_object_object_add(obj, "loss_sample_count", json_object_new_int(samples));
    if (samples > 0)
        json_object_object_add(obj, "latency_avg", json_object_new_double(latency));
}

/* ── health bucket update ── */

void jmx_db_update_wan_health_bucket(const char *wan_id, const char *ifname,
                                      int latency_ms, int loss_up_pct,
                                      int loss_down_pct, int64_t rx_rate,
                                      int64_t tx_rate, int online)
{
    int64_t now, bs;
    wan_health_bucket_mem_t *b;
    wan_profile_t *p;
    if (!wan_id || !wan_id[0]) return;

    now = now_s();
    bs = bucket_start_for(now);
    b = find_or_create_bucket(wan_id, bs);
    if (!b) return;

    b->samples++;
    b->total_count++;
    if (online) {
        b->online_count++;
        b->latency_sum_ms += latency_ms;
        if (latency_ms > b->latency_max_ms || b->samples == 1) b->latency_max_ms = latency_ms;
        if (latency_ms < b->latency_min_ms || b->samples == 1) b->latency_min_ms = latency_ms;
        b->loss_up_sum += loss_up_pct;
        b->loss_down_sum += loss_down_pct;
        b->up_rate_sum += (int)tx_rate;
        b->down_rate_sum += (int)rx_rate;
    }
    b->dirty = 1;

    (void)ifname;
}

/* ── flush memory buckets to DB ── */

int jmx_db_flush_health_buckets(void)
{
    int i, flushed = 0;
    if (!jmx_storage_guard_allow("/", JMX_STORAGE_WRITE_BULK, NULL))
        return 0;
    if (jmx_db_init() != 0) return -1;

    for (i = 0; i < g_bucket_count; i++) {
        wan_health_bucket_mem_t *b = &g_buckets[i];
        sqlite3_stmt *st = NULL;
        const char *status, *reason;
        int latency_avg, latency_max, latency_min;
        int loss_up, loss_down, avg_up, avg_down, busy_pct = 0;
        wan_profile_t *p;

        if (!b->dirty) continue;

        /* compute averages */
        if (b->online_count > 0) {
            latency_avg = b->latency_sum_ms / b->online_count;
            latency_max = b->latency_max_ms;
            latency_min = b->latency_min_ms;
            loss_up = b->loss_up_sum / b->online_count;
            loss_down = b->loss_down_sum / b->online_count;
            avg_up = b->up_rate_sum / b->online_count;
            avg_down = b->down_rate_sum / b->online_count;
        } else {
            latency_avg = 0; latency_max = 0; latency_min = 0;
            loss_up = 0; loss_down = 0; avg_up = 0; avg_down = 0;
        }

        /* determine status and reason */
        if (b->online_count == 0) {
            status = "down"; reason = "link_down";
        } else if (latency_max > LATENCY_BAD_MS * 3) {
            status = "bad"; reason = "gateway_fail";
        } else if (loss_up > LOSS_BAD_PCT * 2 || loss_down > LOSS_BAD_PCT * 2) {
            status = "bad"; reason = "dns_fail";
        } else if (latency_avg > LATENCY_BAD_MS) {
            status = "bad"; reason = "jitter";
        } else if (latency_avg > LATENCY_WARN_MS || loss_up > LOSS_WARN_PCT || loss_down > LOSS_WARN_PCT) {
            status = "warn"; reason = "unstable";
        } else {
            status = "ok"; reason = "normal";
        }

        /* busy based on configured rate */
        p = find_profile(b->wan_id);
        if (p && p->configured_down_rate > 0) {
            int total = avg_up + avg_down;
            int configured = (p->configured_up_rate + p->configured_down_rate) * 1000 / 8; /* kbps->bytes/s */
            if (configured > 0) busy_pct = total * 100 / configured;
            if (busy_pct > 100) busy_pct = 100;
            if (busy_pct >= 80 && strcmp(status, "ok") == 0) {
                status = "warn"; reason = "congestion";
            }
            if (busy_pct >= 95 && strcmp(status, "warn") == 0) {
                status = "bad"; reason = "congestion";
            }
        }

        if (db_prepare(&st,
            "INSERT INTO wan_health_bucket(wan_id,bucket_start,bucket_seconds,"
            "status,reason,latency_avg,latency_max,latency_min,"
            "loss_up,loss_down,avg_up_rate,avg_down_rate,"
            "configured_up_rate,configured_down_rate,busy,samples) "
            "VALUES(?1,?2,1800,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15) "
            "ON CONFLICT(wan_id,bucket_start) DO UPDATE SET "
            "status=excluded.status,reason=excluded.reason,"
            "latency_avg=excluded.latency_avg,latency_max=excluded.latency_max,"
            "latency_min=excluded.latency_min,loss_up=excluded.loss_up,"
            "loss_down=excluded.loss_down,avg_up_rate=excluded.avg_up_rate,"
            "avg_down_rate=excluded.avg_down_rate,"
            "configured_up_rate=excluded.configured_up_rate,"
            "configured_down_rate=excluded.configured_down_rate,"
            "busy=excluded.busy,samples=excluded.samples") == 0) {
            sqlite3_bind_text(st, 1, b->wan_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 2, b->bucket_start);
            sqlite3_bind_text(st, 3, status, -1, SQLITE_STATIC);
            sqlite3_bind_text(st, 4, reason, -1, SQLITE_STATIC);
            sqlite3_bind_int(st, 5, latency_avg);
            sqlite3_bind_int(st, 6, latency_max);
            sqlite3_bind_int(st, 7, latency_min);
            sqlite3_bind_int(st, 8, loss_up);
            sqlite3_bind_int(st, 9, loss_down);
            sqlite3_bind_int(st, 10, avg_up);
            sqlite3_bind_int(st, 11, avg_down);
            sqlite3_bind_int(st, 12, p ? p->configured_up_rate : 0);
            sqlite3_bind_int(st, 13, p ? p->configured_down_rate : 0);
            sqlite3_bind_int(st, 14, busy_pct);
            sqlite3_bind_int(st, 15, b->samples);
            db_step_done(st);
            sqlite3_finalize(st);
        }
        b->dirty = 0;
        flushed++;
    }
    return flushed;
}

/* load profiles from DB into memory on startup */
void jmx_db_load_profiles_from_db(void)
{
    sqlite3_stmt *st = NULL;
    if (jmx_db_init() != 0) return;
    if (db_prepare(&st, "SELECT id,ifname,display_name,note,carrier,access_mode,configured_up_rate,configured_down_rate FROM wan_profile") != 0) return;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *id = (const char *)sqlite3_column_text(st, 0);
        wan_profile_t *p = find_or_create_profile(id);
        if (p) {
            const char *v;
            v = (const char *)sqlite3_column_text(st, 2);
            if (v && v[0]) snprintf(p->display_name, sizeof(p->display_name), "%s", v);
            v = (const char *)sqlite3_column_text(st, 3);
            if (v && v[0]) snprintf(p->note, sizeof(p->note), "%s", v);
            v = (const char *)sqlite3_column_text(st, 4);
            if (v && v[0]) snprintf(p->carrier, sizeof(p->carrier), "%s", v);
            v = (const char *)sqlite3_column_text(st, 5);
            if (v && v[0]) snprintf(p->access_mode, sizeof(p->access_mode), "%s", v);
            p->configured_up_rate = sqlite3_column_int(st, 6);
            p->configured_down_rate = sqlite3_column_int(st, 7);
        }
    }
    sqlite3_finalize(st);
    LOG_INFO("loaded %d wan profiles from DB", g_profile_count);
}

/* line_health API: returns ts + wans[] with current status + 24h buckets + session history */
struct json_object *jmx_db_api_line_health(struct json_object *req)
{
    struct json_object *data = json_object_new_object();
    struct json_object *wans_arr = json_object_new_array();
    sqlite3_stmt *st = NULL;
    int64_t now = now_s();
    int limit = json_i(req, "limit", 32);
    if (limit <= 0 || limit > 128) limit = 32;

    json_object_object_add(data, "ts", json_object_new_int64(now));

    if (jmx_db_init() != 0) {
        json_object_object_add(data, "wans", wans_arr);
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }

    /* query all interfaces with latest state */
    if (db_prepare(&st,
        "SELECT i.name,i.proto,i.carrier,s.ts,s.online,s.rx_bytes,s.tx_bytes,s.rx_rate,s.tx_rate,s.latency_ms,s.loss_pct "
        "FROM net_interfaces i LEFT JOIN net_interface_state s ON s.rowid=(SELECT rowid FROM net_interface_state WHERE iface_id=i.iface_id ORDER BY ts DESC LIMIT 1) "
        "WHERE i.kind='wan' ORDER BY i.name LIMIT ?1") == 0) {
        sqlite3_bind_int(st, 1, limit);
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *name = (const char *)sqlite3_column_text(st, 0);
            const char *proto = (const char *)sqlite3_column_text(st, 1);
            const char *carrier = (const char *)sqlite3_column_text(st, 2);
            int64_t state_ts = sqlite3_column_int64(st, 3);
            int online = sqlite3_column_int(st, 4);
            int64_t rx_bytes = sqlite3_column_int64(st, 5);
            int64_t tx_bytes = sqlite3_column_int64(st, 6);
            int rx_rate = sqlite3_column_int(st, 7);
            int tx_rate = sqlite3_column_int(st, 8);
            int latency = sqlite3_column_int(st, 9);
            int loss = sqlite3_column_int(st, 10);
            wan_profile_t *prof = find_profile(name);
            wan_session_state_t *sess = find_session(name);
            struct json_object *w = json_object_new_object();
            struct json_object *hist = json_object_new_array();
            sqlite3_stmt *bst = NULL;
            int idx = g_profile_count > 0 ? 1 : 1;
            (void)idx;

            if (!name || !jmx_netconfig_wan_configured(name, name)) {
                json_object_put(w);
                json_object_put(hist);
                continue;
            }

            /* current status */
            json_object_object_add(w, "name", json_object_new_string(name ? name : ""));
            json_object_object_add(w, "id", json_object_new_string(name ? name : ""));
            json_object_object_add(w, "ifname", json_object_new_string(name ? name : ""));
            json_object_object_add(w, "carrier", json_object_new_string(carrier ? carrier : ""));
            json_object_object_add(w, "proto", json_object_new_string(proto ? proto : ""));
            json_object_object_add(w, "access_mode", json_object_new_string(prof ? prof->access_mode : ""));
            json_object_object_add(w, "note", json_object_new_string(prof ? prof->note : ""));
            json_object_object_add(w, "health", json_object_new_boolean(online != 0));
            json_object_object_add(w, "online", json_object_new_boolean(online != 0));
            json_object_object_add(w, "ts", json_object_new_int64(state_ts));
            json_object_object_add(w, "rx_bytes", json_object_new_int64(rx_bytes));
            json_object_object_add(w, "tx_bytes", json_object_new_int64(tx_bytes));
            json_object_object_add(w, "down_rate", json_object_new_int(rx_rate));
            json_object_object_add(w, "up_rate", json_object_new_int(tx_rate));
            json_object_object_add(w, "latency", json_object_new_int(latency));
            json_object_object_add(w, "latency_ms", json_object_new_int(latency));
            json_object_object_add(w, "loss", json_object_new_int(loss));
            json_object_object_add(w, "loss_pct", json_object_new_int(loss));
            json_object_object_add(w, "status", json_object_new_string(online ? ((loss >= 50 || latency >= 180) ? "bad" : ((loss > 0 || latency >= 80) ? "warn" : "ok")) : "down"));
            json_object_object_add(w, "configured_up_rate", json_object_new_int(prof ? prof->configured_up_rate : 0));
            json_object_object_add(w, "configured_down_rate", json_object_new_int(prof ? prof->configured_down_rate : 0));

            /* session info */
            if (sess) {
                json_object_object_add(w, "ip", json_object_new_string(sess->ip));
                json_object_object_add(w, "gateway", json_object_new_string(sess->gateway));
            }
            jmx_db_add_wan_session_contract(w, name, now);
            jmx_db_add_wan_loss_contract(w, name, now);

            /* 24h health buckets */
            if (db_prepare(&bst,
                "SELECT bucket_start,status,reason,latency_avg,latency_max,latency_min,loss_up,loss_down,avg_up_rate,avg_down_rate,busy,samples "
                "FROM wan_health_bucket WHERE wan_id=?1 AND bucket_start>=?2 AND bucket_start<=?3 ORDER BY bucket_start ASC") == 0) {
                sqlite3_bind_text(bst, 1, name, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(bst, 2, now - 86400);
                sqlite3_bind_int64(bst, 3, now);
                while (sqlite3_step(bst) == SQLITE_ROW) {
                    struct json_object *hb = json_object_new_object();
                    json_object_object_add(hb, "ts", json_object_new_int64(sqlite3_column_int64(bst, 0)));
                    add_col_text(hb, "status", bst, 1);
                    add_col_text(hb, "reason", bst, 2);
                    json_object_object_add(hb, "latency_avg", json_object_new_int(sqlite3_column_int(bst, 3)));
                    json_object_object_add(hb, "latency_max", json_object_new_int(sqlite3_column_int(bst, 4)));
                    json_object_object_add(hb, "latency_min", json_object_new_int(sqlite3_column_int(bst, 5)));
                    json_object_object_add(hb, "loss_up", json_object_new_int(sqlite3_column_int(bst, 6)));
                    json_object_object_add(hb, "loss_down", json_object_new_int(sqlite3_column_int(bst, 7)));
                    json_object_object_add(hb, "avg_up_rate", json_object_new_int(sqlite3_column_int(bst, 8)));
                    json_object_object_add(hb, "avg_down_rate", json_object_new_int(sqlite3_column_int(bst, 9)));
                    json_object_object_add(hb, "busy", json_object_new_int(sqlite3_column_int(bst, 10)));
                    json_object_object_add(hb, "samples", json_object_new_int(sqlite3_column_int(bst, 11)));
                    json_object_array_add(hist, hb);
                }
                sqlite3_finalize(bst);
            }
            json_object_object_add(w, "health_history", hist);
            json_object_array_add(wans_arr, w);
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(data, "wans", wans_arr);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

/* ipv6_load API - read IPv6 addresses from /proc/net/if_inet6 */
/* ipv6_load API: return interfaces[] with IPv6 addresses + traffic stats */
struct json_object *jmx_db_api_ipv6_load(struct json_object *req)
{
    struct json_object *data = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;
    int64_t now = now_s();
    int limit = json_i(req, "limit", 32);
    int idx = 1;
    (void)req;
    if (limit <= 0 || limit > 128) limit = 32;

    json_object_object_add(data, "ts", json_object_new_int64(now));

    /* Enumerate WAN interfaces that have IPv6 addresses */
    if (jmx_db_init() == 0 && db_prepare(&st,
        "SELECT i.name,i.device,i.carrier,s.online,s.rx_bytes,s.tx_bytes,s.rx_rate,s.tx_rate "
        "FROM net_interfaces i LEFT JOIN net_interface_state s ON s.rowid=(SELECT rowid FROM net_interface_state WHERE iface_id=i.iface_id ORDER BY ts DESC LIMIT 1) "
        "WHERE i.kind='wan' ORDER BY i.name LIMIT ?1") == 0) {
        sqlite3_bind_int(st, 1, limit);
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *name = (const char *)sqlite3_column_text(st, 0);
            const char *device = (const char *)sqlite3_column_text(st, 1);
            const char *carrier = (const char *)sqlite3_column_text(st, 2);
            int64_t rx_bytes = sqlite3_column_int64(st, 4);
            int64_t tx_bytes = sqlite3_column_int64(st, 5);
            int rx_rate = sqlite3_column_int(st, 6);
            int tx_rate = sqlite3_column_int(st, 7);

            /* Read IPv6 from ifstatus */
            char ipv6[64] = "";
            if (name && name[0]) {
                iface_status_t ifs;
                memset(&ifs, 0, sizeof(ifs));
                if (get_iface_status((char *)name, &ifs) == 0)
                    snprintf(ipv6, sizeof(ipv6), "%s", ifs.ipv6);
            }
            /* Skip interfaces without IPv6 */
            if (!ipv6[0]) continue;

            struct json_object *o = json_object_new_object();
            json_object_object_add(o, "id", json_object_new_string(name ? name : ""));
            json_object_object_add(o, "order", json_object_new_int(idx));
            json_object_object_add(o, "type", json_object_new_string("wan"));
            json_object_object_add(o, "name", json_object_new_string(name ? name : ""));
            json_object_object_add(o, "note", json_object_new_string(""));
            json_object_object_add(o, "ifname", json_object_new_string(name ? name : ""));
            json_object_object_add(o, "device", json_object_new_string(device ? device : ""));
            json_object_object_add(o, "carrier", json_object_new_string(carrier ? carrier : ""));
            json_object_object_add(o, "ipv6", json_object_new_string(ipv6));
            json_object_object_add(o, "up_rate", json_object_new_int64((int64_t)tx_rate));
            json_object_object_add(o, "down_rate", json_object_new_int64((int64_t)rx_rate));
            jmx_db_add_wan_cumulative_bytes(o, name, rx_bytes, tx_bytes);
            json_object_object_add(o, "connections", json_object_new_int(0));
            json_object_object_add(o, "uptime", json_object_new_int64(0));
            json_object_array_add(arr, o);
            idx++;
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(data, "interfaces", arr);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

static long long jmx_read_ll_file(const char*p){FILE*f=fopen(p,"r");long long v=0;if(f){fscanf(f,"%lld",&v);fclose(f);}return v;}
static void jmx_add_vpn_if(struct json_object*protos,const char*proto,const char*ifn,const char*name){struct json_object*arr=NULL,*o=json_object_new_object();char path[256];json_object_object_get_ex(protos,proto,&arr);if(!arr)return;snprintf(path,sizeof(path),"/sys/class/net/%s/statistics/rx_bytes",ifn);long long rx=jmx_read_ll_file(path);snprintf(path,sizeof(path),"/sys/class/net/%s/statistics/tx_bytes",ifn);long long tx=jmx_read_ll_file(path);json_object_object_add(o,"id",json_object_new_string(ifn));json_object_object_add(o,"order",json_object_new_int(0));json_object_object_add(o,"name",json_object_new_string(name?name:ifn));json_object_object_add(o,"note",json_object_new_string("runtime interface scan"));json_object_object_add(o,"ifname",json_object_new_string(ifn));json_object_object_add(o,"device",json_object_new_string(ifn));json_object_object_add(o,"up_rate",json_object_new_int64(0));json_object_object_add(o,"up_bytes",json_object_new_int64(tx));json_object_object_add(o,"down_rate",json_object_new_int64(0));json_object_object_add(o,"down_bytes",json_object_new_int64(rx));json_object_object_add(o,"connections",json_object_new_int(0));json_object_array_add(arr,o);}
struct json_object *jmx_db_api_vpn_status(struct json_object *req)
{(void)req;static const char*pns[]={"pptp","l2tp","openvpn","ipsec","ikev2","wireguard",NULL};struct json_object*d=json_object_new_object(),*protos=json_object_new_object();for(int i=0;pns[i];i++)json_object_object_add(protos,pns[i],json_object_new_array());DIR*dir=opendir("/sys/class/net");struct dirent*e;if(dir){while((e=readdir(dir))){const char*n=e->d_name;if(!strcmp(n,".")||!strcmp(n,".."))continue;if(!strncmp(n,"wg",2))jmx_add_vpn_if(protos,"wireguard",n,n);else if(!strncmp(n,"tun",3)||!strncmp(n,"tap",3)||strstr(n,"ovpn"))jmx_add_vpn_if(protos,"openvpn",n,n);else if(!strncmp(n,"ppp",3))jmx_add_vpn_if(protos,"pptp",n,n);else if(strstr(n,"ipsec")||!strncmp(n,"xfrm",4))jmx_add_vpn_if(protos,"ipsec",n,n);}closedir(dir);}json_object_object_add(d,"ts",json_object_new_int64((int64_t)time(NULL)));json_object_object_add(d,"protocols",protos);return jmx_gen_api_response_data(API_CODE_SUCCESS,d);}

struct json_object *jmx_db_api_client_detail(struct json_object *req)
{struct json_object*d=json_object_new_object(),*arr=json_object_new_array();const char*q="";struct json_object*v=NULL;if(req&&json_object_object_get_ex(req,"query",&v))q=json_object_get_string(v);client_node_t*c=NULL;list_for_each_entry(c,&client_list,client){if(q&&*q&&(!strstr(c->mac,q)&&!strstr(c->ip,q)&&!strstr(c->hostname,q)&&!strstr(c->nickname,q)))continue;struct json_object*o=json_object_new_object();json_object_object_add(o,"mac",json_object_new_string(c->mac));json_object_object_add(o,"ip",json_object_new_string(c->ip));json_object_object_add(o,"ipv6",json_object_new_string(c->ipv6));json_object_object_add(o,"hostname",json_object_new_string(c->hostname));json_object_object_add(o,"nickname",json_object_new_string(c->nickname));json_object_object_add(o,"up_rate",json_object_new_int64(c->up_rate));json_object_object_add(o,"down_rate",json_object_new_int64(c->down_rate));json_object_object_add(o,"online",json_object_new_boolean(c->online));json_object_object_add(o,"online_time",json_object_new_int64(c->online_time));json_object_object_add(o,"offline_time",json_object_new_int64(c->offline_time));json_object_object_add(o,"visiting_url",json_object_new_string(c->visiting_url));json_object_object_add(o,"visiting_app",json_object_new_int(c->visiting_app));json_object_array_add(arr,o);}json_object_object_add(d,"ts",json_object_new_int64((int64_t)time(NULL)));json_object_object_add(d,"clients",arr);return jmx_gen_api_response_data(API_CODE_SUCCESS,d);}

struct json_object *jmx_db_api_system_health(struct json_object *req)
{(void)req;struct json_object*d=json_object_new_object(),*sys=json_object_new_object(),*traf=json_object_new_object();char host[128]={0};FILE*f=fopen("/proc/sys/kernel/hostname","r");if(f){fgets(host,sizeof(host),f);host[strcspn(host,"\r\n")]=0;fclose(f);}long long mt=0,ma=0,freev=0,buff=0,cached=0;char key[64];long long val;f=fopen("/proc/meminfo","r");if(f){while(fscanf(f,"%63s %lld kB",key,&val)==2){if(!strcmp(key,"MemTotal:"))mt=val*1024;else if(!strcmp(key,"MemAvailable:"))ma=val*1024;else if(!strcmp(key,"MemFree:"))freev=val*1024;else if(!strcmp(key,"Buffers:"))buff=val*1024;else if(!strcmp(key,"Cached:"))cached=val*1024;}fclose(f);}if(!ma)ma=freev+buff+cached;struct statvfs sv;long long dt=0,du=0;if(statvfs("/",&sv)==0){dt=(long long)sv.f_blocks*sv.f_frsize;du=(long long)(sv.f_blocks-sv.f_bfree)*sv.f_frsize;}double up=0,la=0;f=fopen("/proc/uptime","r");if(f){fscanf(f,"%lf",&up);fclose(f);}f=fopen("/proc/loadavg","r");if(f){fscanf(f,"%lf",&la);fclose(f);}json_object_object_add(sys,"hostname",json_object_new_string(host));json_object_object_add(sys,"model",json_object_new_string("DreamingWrt"));json_object_object_add(sys,"uptime",json_object_new_int((int)up));json_object_object_add(sys,"cpu_percent",json_object_new_int((int)(la*100)));json_object_object_add(sys,"mem_total",json_object_new_int64(mt));json_object_object_add(sys,"mem_used",json_object_new_int64(mt>ma?mt-ma:0));json_object_object_add(sys,"disk_total",json_object_new_int64(dt));json_object_object_add(sys,"disk_used",json_object_new_int64(du));json_object_object_add(sys,"client_num",json_object_new_int(0));json_object_object_add(traf,"up_rate",json_object_new_int64(0));json_object_object_add(traf,"down_rate",json_object_new_int64(0));json_object_object_add(d,"ts",json_object_new_int64((int64_t)time(NULL)));json_object_object_add(d,"system",sys);json_object_object_add(d,"traffic",traf);return jmx_gen_api_response_data(API_CODE_SUCCESS,d);}
struct json_object *jmx_db_api_lan_config(struct json_object *req) { (void)req; return jmx_netconfig_lan_list(); }

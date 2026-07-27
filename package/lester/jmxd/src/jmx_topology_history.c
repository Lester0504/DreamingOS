// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Bounded 24-hour infrastructure history for the UniFi-compatible Time Machine.
 * Full snapshots are stored compressed; hashes intentionally ignore volatile
 * traffic counters and timestamps so idle sampling does not create fake events.
 */
#include "jmx_topology_history.h"

#include <errno.h>
#include <openssl/sha.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#define JTH_DEFAULT_DB "/opt/dreamingwrt/topology/history.db"
#define JTH_RETENTION_MS (24LL * 60LL * 60LL * 1000LL)
#define JTH_ANCHOR_MS (5LL * 60LL * 1000LL)
#define JTH_MAX_SNAPSHOTS 4096
#define JTH_MAX_EVENTS 32768
#define JTH_MAX_PAYLOAD_BYTES (32U * 1024U * 1024U)

struct jth_buf {
    char *data;
    size_t len;
    size_t cap;
};

static sqlite3 *g_jth_db;
static const char *jth_db_path(void);

static void jth_secure_files(void)
{
    char sidecar[1024];
    const char *path = jth_db_path();

    chmod(path, 0640);
    if (snprintf(sidecar, sizeof(sidecar), "%s-wal", path) < (int)sizeof(sidecar))
        chmod(sidecar, 0640);
    if (snprintf(sidecar, sizeof(sidecar), "%s-shm", path) < (int)sizeof(sidecar))
        chmod(sidecar, 0640);
}

static int64_t jth_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return (int64_t)time(NULL) * 1000LL;
    return (int64_t)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static const char *jth_db_path(void)
{
    const char *override = getenv("DREAMINGWRT_TOPOLOGY_HISTORY_DB");

    return override && override[0] ? override : JTH_DEFAULT_DB;
}

static int jth_ensure_dir(const char *path)
{
    struct stat st;

    if (mkdir(path, 0750) == 0)
        return 0;
    if (errno != EEXIST || stat(path, &st) != 0 || !S_ISDIR(st.st_mode))
        return -1;
    return 0;
}

static int jth_exec(const char *sql)
{
    char *err = NULL;
    int rc;

    rc = sqlite3_exec(g_jth_db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-core] topology history sqlite: %s: %s\n",
                sql, err ? err : sqlite3_errmsg(g_jth_db));
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static int jth_db_open(void)
{
    const char *path;

    if (g_jth_db)
        return 0;
    path = jth_db_path();
    if (!strcmp(path, JTH_DEFAULT_DB) &&
        (jth_ensure_dir("/opt/dreamingwrt") != 0 ||
         jth_ensure_dir("/opt/dreamingwrt/topology") != 0))
        return -1;
    if (sqlite3_open_v2(path, &g_jth_db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                        NULL) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-core] cannot open topology history db %s: %s\n",
                path, g_jth_db ? sqlite3_errmsg(g_jth_db) : "open failed");
        if (g_jth_db)
            sqlite3_close(g_jth_db);
        g_jth_db = NULL;
        return -1;
    }
    sqlite3_busy_timeout(g_jth_db, 750);
    if (jth_exec("PRAGMA journal_mode=WAL") != 0 ||
        jth_exec("PRAGMA synchronous=NORMAL") != 0 ||
        jth_exec("PRAGMA wal_autocheckpoint=64") != 0 ||
        jth_exec("PRAGMA journal_size_limit=1048576") != 0 ||
        jth_exec("PRAGMA temp_store=MEMORY") != 0 ||
        jth_exec("CREATE TABLE IF NOT EXISTS topology_snapshots("
                 "id INTEGER PRIMARY KEY,ts_ms INTEGER NOT NULL UNIQUE,"
                 "state_hash TEXT NOT NULL,anchor INTEGER NOT NULL DEFAULT 0,"
                 "payload_zlib BLOB NOT NULL,raw_bytes INTEGER NOT NULL,"
                 "compressed_bytes INTEGER NOT NULL)") != 0 ||
        jth_exec("CREATE INDEX IF NOT EXISTS idx_topology_snapshots_ts "
                 "ON topology_snapshots(ts_ms)") != 0 ||
        jth_exec("CREATE TABLE IF NOT EXISTS topology_events("
                 "event_id TEXT PRIMARY KEY,timestamp_ms INTEGER NOT NULL,"
                 "end_timestamp_ms INTEGER,type TEXT NOT NULL,node_id TEXT,"
                 "mac TEXT,name TEXT,port_idx INTEGER,link_id TEXT,"
                 "before_json TEXT,after_json TEXT)") != 0 ||
        jth_exec("CREATE INDEX IF NOT EXISTS idx_topology_events_ts "
                 "ON topology_events(timestamp_ms)") != 0) {
        sqlite3_close(g_jth_db);
        g_jth_db = NULL;
        return -1;
    }
    jth_secure_files();
    return 0;
}

static int jth_buf_reserve(struct jth_buf *b, size_t extra)
{
    size_t need;
    size_t cap;
    char *p;

    if (!b || extra > SIZE_MAX - b->len - 1)
        return -1;
    need = b->len + extra + 1;
    if (need <= b->cap)
        return 0;
    cap = b->cap ? b->cap : 256;
    while (cap < need) {
        if (cap > SIZE_MAX / 2)
            return -1;
        cap *= 2;
    }
    p = realloc(b->data, cap);
    if (!p)
        return -1;
    b->data = p;
    b->cap = cap;
    return 0;
}

static int jth_buf_addn(struct jth_buf *b, const char *s, size_t n)
{
    if (jth_buf_reserve(b, n) != 0)
        return -1;
    if (n)
        memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
    return 0;
}

static int jth_buf_add(struct jth_buf *b, const char *s)
{
    return jth_buf_addn(b, s ? s : "", s ? strlen(s) : 0);
}

static int jth_cmp_strptr(const void *a, const void *b)
{
    const char *const *sa = a;
    const char *const *sb = b;

    return strcmp(*sa, *sb);
}

static int jth_volatile_key(const char *key)
{
    static const char *const exact[] = {
        "ts", "timestamp", "generated_at", "updated_at", "sample_age_ms",
        "last_seen", "last_seen_age", "first_seen", "online_since",
        "connected_at", "session_started_at", "online_duration",
        "online_seconds", "connected_seconds", "session_duration", "uptime",
        "connections", "client_count", "flow_count", "traffic", "traffic_level",
        "particle_level", "rateMbps", "rx_rate", "tx_rate", "up_rate",
        "down_rate", "rate_source", "sample_valid", "zero_reason", "degraded",
        "latency", "latency_ms", "latency_avg", "loss", "loss_pct",
        "loss_percent", "health_history", "history", "apps", "active_url",
        "active_app", "active_app_id", "app_id", "app_name", "today_up",
        "today_down", "monthly_usage_label", "month_usage_label", "data_usage_label",
        "rx_bytes-r", "tx_bytes-r", NULL
    };
    int i;

    if (!key)
        return 0;
    for (i = 0; exact[i]; i++)
        if (!strcmp(key, exact[i]))
            return 1;
    if (strstr(key, "_bytes") || strstr(key, "_packets") ||
        !strncmp(key, "monthly_", 8) || !strncmp(key, "month_", 6) ||
        !strncmp(key, "loss_", 5) || !strncmp(key, "up_loss_", 8) ||
        !strncmp(key, "down_loss_", 10))
        return 1;
    return 0;
}

static int jth_canonical(struct json_object *obj, struct jth_buf *out);

static int jth_canonical_object(struct json_object *obj, struct jth_buf *out)
{
    char **keys = NULL;
    size_t count = 0;
    size_t i = 0;
    int rc = -1;

    {
        json_object_object_foreach(obj, count_key, count_value) {
            (void)count_value;
            if (!jth_volatile_key(count_key))
                count++;
        }
    }
    keys = count ? calloc(count, sizeof(*keys)) : NULL;
    if (count && !keys)
        return -1;
    {
        json_object_object_foreach(obj, collect_key, collect_value) {
            (void)collect_value;
            if (!jth_volatile_key(collect_key))
                keys[i++] = (char *)collect_key;
        }
    }
    if (count > 1)
        qsort(keys, count, sizeof(*keys), jth_cmp_strptr);
    if (jth_buf_add(out, "{") != 0)
        goto done;
    for (i = 0; i < count; i++) {
        struct json_object *name_obj;
        struct json_object *v = NULL;
        const char *encoded;

        if (i && jth_buf_add(out, ",") != 0)
            goto done;
        name_obj = json_object_new_string(keys[i]);
        if (!name_obj)
            goto done;
        encoded = json_object_to_json_string_ext(name_obj, JSON_C_TO_STRING_PLAIN);
        if (jth_buf_add(out, encoded) != 0 || jth_buf_add(out, ":") != 0) {
            json_object_put(name_obj);
            goto done;
        }
        json_object_put(name_obj);
        if (!json_object_object_get_ex(obj, keys[i], &v) || jth_canonical(v, out) != 0)
            goto done;
    }
    if (jth_buf_add(out, "}") != 0)
        goto done;
    rc = 0;
done:
    free(keys);
    return rc;
}

static int jth_canonical_array(struct json_object *obj, struct jth_buf *out)
{
    size_t count = json_object_array_length(obj);
    char **items = count ? calloc(count, sizeof(*items)) : NULL;
    size_t i;
    int rc = -1;

    if (count && !items)
        return -1;
    for (i = 0; i < count; i++) {
        struct jth_buf item = {0};

        if (jth_canonical(json_object_array_get_idx(obj, i), &item) != 0) {
            free(item.data);
            goto done;
        }
        items[i] = item.data ? item.data : strdup("null");
        if (!items[i])
            goto done;
    }
    if (count > 1)
        qsort(items, count, sizeof(*items), jth_cmp_strptr);
    if (jth_buf_add(out, "[") != 0)
        goto done;
    for (i = 0; i < count; i++) {
        if ((i && jth_buf_add(out, ",") != 0) || jth_buf_add(out, items[i]) != 0)
            goto done;
    }
    if (jth_buf_add(out, "]") != 0)
        goto done;
    rc = 0;
done:
    for (i = 0; i < count; i++)
        free(items[i]);
    free(items);
    return rc;
}

static int jth_canonical(struct json_object *obj, struct jth_buf *out)
{
    const char *plain;

    if (!obj)
        return jth_buf_add(out, "null");
    if (json_object_is_type(obj, json_type_object))
        return jth_canonical_object(obj, out);
    if (json_object_is_type(obj, json_type_array))
        return jth_canonical_array(obj, out);
    plain = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN);
    return jth_buf_add(out, plain ? plain : "null");
}

static int jth_state_hash(struct json_object *snapshot, char hex[SHA256_DIGEST_LENGTH * 2 + 1])
{
    struct jth_buf canonical = {0};
    struct json_object *hash_scope = NULL;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    int i;

    if (!snapshot || !json_object_object_get_ex(snapshot, "infrastructure", &hash_scope) ||
        !hash_scope || !json_object_is_type(hash_scope, json_type_object))
        return -1;
    if (jth_canonical(hash_scope, &canonical) != 0) {
        free(canonical.data);
        return -1;
    }
    SHA256((const unsigned char *)(canonical.data ? canonical.data : ""),
           canonical.len, digest);
    free(canonical.data);
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(hex + i * 2, 3, "%02x", digest[i]);
    hex[SHA256_DIGEST_LENGTH * 2] = '\0';
    return 0;
}

static int jth_compress_snapshot(struct json_object *snapshot, unsigned char **out,
                                 size_t *out_len, size_t *raw_len)
{
    const char *plain;
    uLong source_len;
    uLongf bound;
    unsigned char *compressed;

    if (!snapshot || !out || !out_len || !raw_len)
        return -1;
    plain = json_object_to_json_string_ext(snapshot, JSON_C_TO_STRING_PLAIN);
    if (!plain)
        return -1;
    source_len = (uLong)strlen(plain);
    if (source_len == 0 || source_len > JTH_MAX_PAYLOAD_BYTES)
        return -1;
    bound = compressBound(source_len);
    compressed = malloc(bound);
    if (!compressed)
        return -1;
    if (compress2(compressed, &bound, (const Bytef *)plain, source_len, 6) != Z_OK) {
        free(compressed);
        return -1;
    }
    *out = compressed;
    *out_len = (size_t)bound;
    *raw_len = (size_t)source_len;
    return 0;
}

static struct json_object *jth_decompress_json(const void *blob, int blob_len, int raw_len)
{
    unsigned char *plain;
    uLongf out_len;
    struct json_object *obj;

    if (!blob || blob_len <= 0 || raw_len <= 0 || raw_len > (int)JTH_MAX_PAYLOAD_BYTES)
        return NULL;
    plain = malloc((size_t)raw_len + 1);
    if (!plain)
        return NULL;
    out_len = (uLongf)raw_len;
    if (uncompress(plain, &out_len, blob, (uLong)blob_len) != Z_OK ||
        out_len != (uLongf)raw_len) {
        free(plain);
        return NULL;
    }
    plain[out_len] = '\0';
    obj = json_tokener_parse((const char *)plain);
    free(plain);
    return obj;
}

static const char *jth_str(struct json_object *obj, const char *key)
{
    struct json_object *v = NULL;

    if (!obj || !key || !json_object_object_get_ex(obj, key, &v) || !v)
        return "";
    return json_object_get_string(v) ? json_object_get_string(v) : "";
}

static int jth_int(struct json_object *obj, const char *key, int def)
{
    struct json_object *v = NULL;

    if (!obj || !json_object_object_get_ex(obj, key, &v) || !v)
        return def;
    return json_object_get_int(v);
}

static int jth_online(struct json_object *obj, int def)
{
    struct json_object *v = NULL;
    const char *state;

    if (!obj)
        return def;
    if (json_object_object_get_ex(obj, "online", &v) && v)
        return json_object_get_boolean(v);
    state = jth_str(obj, "state");
    if (!state[0])
        state = jth_str(obj, "status");
    if (!strcasecmp(state, "online") || !strcasecmp(state, "connected") ||
        !strcasecmp(state, "up") || !strcasecmp(state, "ok"))
        return 1;
    if (!strcasecmp(state, "offline") || !strcasecmp(state, "disconnected") ||
        !strcasecmp(state, "down") || !strcasecmp(state, "disabled") ||
        !strcasecmp(state, "blocked"))
        return 0;
    if (json_object_object_get_ex(obj, "link_detected", &v) && v)
        return json_object_get_boolean(v);
    return def;
}

static const char *jth_entity_id(struct json_object *obj)
{
    const char *id = jth_str(obj, "id");

    if (!id[0]) id = jth_str(obj, "port_id");
    if (!id[0]) id = jth_str(obj, "node_id");
    if (!id[0]) id = jth_str(obj, "mac");
    if (!id[0]) id = jth_str(obj, "wan_id");
    return id;
}

static struct json_object *jth_infra(struct json_object *root)
{
    struct json_object *infra = NULL;

    if (root && json_object_object_get_ex(root, "infrastructure", &infra) && infra &&
        json_object_is_type(infra, json_type_object))
        return infra;
    return NULL;
}

static struct json_object *jth_array(struct json_object *root, const char *key)
{
    struct json_object *arr = NULL;

    if (root && json_object_object_get_ex(root, key, &arr) && arr &&
        json_object_is_type(arr, json_type_array))
        return arr;
    return NULL;
}

static struct json_object *jth_find(struct json_object *arr, const char *id)
{
    size_t i;

    if (!arr || !id || !id[0])
        return NULL;
    for (i = 0; i < json_object_array_length(arr); i++) {
        struct json_object *item = json_object_array_get_idx(arr, i);
        if (!strcmp(jth_entity_id(item), id))
            return item;
    }
    return NULL;
}

static void jth_event_id(char out[65], int64_t ts_ms, const char *type,
                         const char *entity_id, int port_idx)
{
    char seed[512];
    unsigned char digest[SHA256_DIGEST_LENGTH];
    size_t i;

    snprintf(seed, sizeof(seed), "%lld|%s|%s|%d", (long long)ts_ms,
             type ? type : "", entity_id ? entity_id : "", port_idx);
    SHA256((const unsigned char *)seed, strlen(seed), digest);
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    out[64] = '\0';
}

static int jth_insert_event(int64_t ts_ms, const char *type, const char *entity_id,
                            struct json_object *before, struct json_object *after,
                            int port_idx, int is_link)
{
    sqlite3_stmt *st = NULL;
    char event_id[65];
    const char *mac = after ? jth_str(after, "mac") : jth_str(before, "mac");
    const char *name = after ? jth_str(after, "name") : jth_str(before, "name");
    const char *before_s = before ? json_object_to_json_string_ext(before, JSON_C_TO_STRING_PLAIN) : NULL;
    const char *after_s = after ? json_object_to_json_string_ext(after, JSON_C_TO_STRING_PLAIN) : NULL;
    int rc;

    jth_event_id(event_id, ts_ms, type, entity_id, port_idx);
    rc = sqlite3_prepare_v2(g_jth_db,
        "INSERT OR IGNORE INTO topology_events(event_id,timestamp_ms,type,node_id,mac,name,"
        "port_idx,link_id,before_json,after_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
        -1, &st, NULL);
    if (rc != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, event_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, ts_ms);
    sqlite3_bind_text(st, 3, type, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 4, is_link ? "" : entity_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, mac, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, name, -1, SQLITE_TRANSIENT);
    if (port_idx >= 0) sqlite3_bind_int(st, 7, port_idx); else sqlite3_bind_null(st, 7);
    sqlite3_bind_text(st, 8, is_link ? entity_id : "", -1, SQLITE_TRANSIENT);
    if (before_s) sqlite3_bind_text(st, 9, before_s, -1, SQLITE_TRANSIENT); else sqlite3_bind_null(st, 9);
    if (after_s) sqlite3_bind_text(st, 10, after_s, -1, SQLITE_TRANSIENT); else sqlite3_bind_null(st, 10);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? sqlite3_changes(g_jth_db) : -1;
}

static int jth_diff_array(int64_t ts_ms, struct json_object *before_arr,
                          struct json_object *after_arr, int kind)
{
    size_t i;
    int events = 0;

    /* kind: 0=device, 1=network, 2=link, 3=port */
    if (after_arr) {
        for (i = 0; i < json_object_array_length(after_arr); i++) {
            struct json_object *after = json_object_array_get_idx(after_arr, i);
            const char *id = jth_entity_id(after);
            struct json_object *before = jth_find(before_arr, id);
            int rc = 0;

            if (!id[0])
                continue;
            if (!before) {
                const char *type = kind == 0 ? "DEVICE_ADOPTED" :
                                   kind == 1 ? "NETWORK_ONLINE" : "LINK_UP";
                if (kind == 1 && !jth_online(after, 0))
                    continue;
                if (kind >= 2 && !jth_online(after, 1))
                    continue;
                rc = jth_insert_event(ts_ms, type, id, NULL, after,
                                      kind == 3 ? jth_int(after, "index", -1) : -1,
                                      kind >= 2);
            } else {
                int was_online = jth_online(before, 1);
                int is_online = jth_online(after, 1);
                const char *type = NULL;

                if (was_online != is_online)
                    type = kind == 0 ? (is_online ? "DEVICE_ONLINE" : "DEVICE_OFFLINE") :
                           kind == 1 ? (is_online ? "NETWORK_ONLINE" : "NETWORK_OFFLINE") :
                                       (is_online ? "LINK_UP" : "LINK_DOWN");
                else if (kind == 3 && is_online &&
                         (jth_int(before, "speed_mbps", 0) != jth_int(after, "speed_mbps", 0) ||
                          strcmp(jth_str(before, "duplex"), jth_str(after, "duplex")) != 0))
                    type = "LINK_UP";
                if (type)
                    rc = jth_insert_event(ts_ms, type, id, before, after,
                                          kind == 3 ? jth_int(after, "index", -1) : -1,
                                          kind >= 2);
            }
            if (rc > 0)
                events += rc;
            else if (rc < 0)
                return -1;
        }
    }
    if (before_arr) {
        for (i = 0; i < json_object_array_length(before_arr); i++) {
            struct json_object *before = json_object_array_get_idx(before_arr, i);
            const char *id = jth_entity_id(before);
            const char *type;
            int rc;

            if (!id[0] || jth_find(after_arr, id))
                continue;
            type = kind == 0 ? "DEVICE_REMOVED" :
                   kind == 1 ? "NETWORK_OFFLINE" : "LINK_DOWN";
            rc = jth_insert_event(ts_ms, type, id, before, NULL,
                                  kind == 3 ? jth_int(before, "index", -1) : -1,
                                  kind >= 2);
            if (rc > 0)
                events += rc;
            else if (rc < 0)
                return -1;
        }
    }
    return events;
}

static int jth_diff_devices(int64_t ts_ms, struct json_object *before,
                            struct json_object *after)
{
    static const char *const groups[] = { "gateways", "switches", "aps", "clients", NULL };
    struct json_object *bi = jth_infra(before);
    struct json_object *ai = jth_infra(after);
    int total = 0;
    int i;

    for (i = 0; groups[i]; i++) {
        int rc = jth_diff_array(ts_ms, jth_array(bi, groups[i]), jth_array(ai, groups[i]), 0);
        if (rc < 0)
            return -1;
        total += rc;
    }
    return total;
}

static int jth_generate_events(int64_t ts_ms, struct json_object *before,
                               struct json_object *after)
{
    struct json_object *bi = jth_infra(before);
    struct json_object *ai = jth_infra(after);
    int total;
    int rc;

    total = jth_diff_devices(ts_ms, before, after);
    if (total < 0)
        return -1;
    rc = jth_diff_array(ts_ms, jth_array(bi, "wans"), jth_array(ai, "wans"), 1);
    if (rc < 0) return -1;
    total += rc;
    rc = jth_diff_array(ts_ms, jth_array(bi, "links"), jth_array(ai, "links"), 2);
    if (rc < 0) return -1;
    total += rc;
    rc = jth_diff_array(ts_ms, jth_array(bi, "ports"), jth_array(ai, "ports"), 3);
    if (rc < 0) return -1;
    return total + rc;
}

static int jth_latest_meta(int64_t *ts_ms, char hash[65])
{
    sqlite3_stmt *st = NULL;
    int found = 0;

    if (sqlite3_prepare_v2(g_jth_db,
            "SELECT ts_ms,state_hash FROM topology_snapshots "
            "ORDER BY ts_ms DESC LIMIT 1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        if (ts_ms) *ts_ms = sqlite3_column_int64(st, 0);
        if (hash) snprintf(hash, 65, "%s", (const char *)sqlite3_column_text(st, 1));
        found = 1;
    }
    sqlite3_finalize(st);
    return found;
}

static struct json_object *jth_snapshot_by_timestamp(int64_t ts_ms)
{
    sqlite3_stmt *st = NULL;
    struct json_object *obj = NULL;

    if (sqlite3_prepare_v2(g_jth_db,
            "SELECT payload_zlib,raw_bytes FROM topology_snapshots WHERE ts_ms=?",
            -1, &st, NULL) != SQLITE_OK)
        return NULL;
    sqlite3_bind_int64(st, 1, ts_ms);
    if (sqlite3_step(st) == SQLITE_ROW)
        obj = jth_decompress_json(sqlite3_column_blob(st, 0), sqlite3_column_bytes(st, 0),
                                  sqlite3_column_int(st, 1));
    sqlite3_finalize(st);
    return obj;
}

static int jth_prune(int64_t now_ms)
{
    sqlite3_stmt *st = NULL;
    int removed = 0;

    if (sqlite3_prepare_v2(g_jth_db,
        "DELETE FROM topology_snapshots WHERE ts_ms < ?", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, now_ms - JTH_RETENTION_MS);
    if (sqlite3_step(st) != SQLITE_DONE) { sqlite3_finalize(st); return -1; }
    removed += sqlite3_changes(g_jth_db);
    sqlite3_finalize(st);
    if (sqlite3_prepare_v2(g_jth_db,
        "DELETE FROM topology_events WHERE timestamp_ms < ?", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, now_ms - JTH_RETENTION_MS);
    if (sqlite3_step(st) != SQLITE_DONE) { sqlite3_finalize(st); return -1; }
    removed += sqlite3_changes(g_jth_db);
    sqlite3_finalize(st);
    if (jth_exec("DELETE FROM topology_snapshots WHERE id NOT IN "
                 "(SELECT id FROM topology_snapshots ORDER BY ts_ms DESC LIMIT 4096)") != 0 ||
        jth_exec("DELETE FROM topology_events WHERE event_id NOT IN "
                 "(SELECT event_id FROM topology_events ORDER BY timestamp_ms DESC LIMIT 32768)") != 0)
        return -1;
    return removed;
}

static struct json_object *jth_error(const char *reason)
{
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "available", json_object_new_boolean(0));
    json_object_object_add(o, "degraded", json_object_new_boolean(1));
    json_object_object_add(o, "reason", json_object_new_string(reason ? reason : "history_error"));
    json_object_object_add(o, "retention_ms", json_object_new_int64(JTH_RETENTION_MS));
    return o;
}

int jmx_topology_history_capture(struct json_object *snapshot, int force_anchor,
                                 struct json_object **result_out)
{
    char hash[65] = {0};
    char latest_hash[65] = {0};
    int64_t now_ms = jth_now_ms();
    int64_t latest_ts = 0;
    struct json_object *previous = NULL;
    struct json_object *result = NULL;
    unsigned char *compressed = NULL;
    size_t compressed_len = 0;
    size_t raw_len = 0;
    sqlite3_stmt *st = NULL;
    int changed;
    int anchor;
    int events = 0;
    int pruned = 0;
    int rc = -1;

    if (result_out) *result_out = NULL;
    if (!snapshot || jth_db_open() != 0 || jth_state_hash(snapshot, hash) != 0)
        goto done;
    if (jth_latest_meta(&latest_ts, latest_hash) < 0)
        goto done;
    if (latest_ts && now_ms <= latest_ts)
        now_ms = latest_ts + 1;
    changed = !latest_ts || strcmp(hash, latest_hash) != 0;
    anchor = !latest_ts || (!changed && (force_anchor || now_ms - latest_ts >= JTH_ANCHOR_MS));
    if (!changed && !anchor) {
        result = json_object_new_object();
        json_object_object_add(result, "captured", json_object_new_boolean(0));
        json_object_object_add(result, "reason", json_object_new_string("unchanged_before_anchor"));
        json_object_object_add(result, "latest_timestamp", json_object_new_int64(latest_ts));
        json_object_object_add(result, "next_anchor_at", json_object_new_int64(latest_ts + JTH_ANCHOR_MS));
        rc = 0;
        goto done;
    }
    if (jth_compress_snapshot(snapshot, &compressed, &compressed_len, &raw_len) != 0)
        goto done;
    if (latest_ts && changed) {
        previous = jth_snapshot_by_timestamp(latest_ts);
        if (!previous)
            goto done;
    }
    if (jth_exec("BEGIN IMMEDIATE") != 0)
        goto done;
    if (sqlite3_prepare_v2(g_jth_db,
        "INSERT INTO topology_snapshots(ts_ms,state_hash,anchor,payload_zlib,raw_bytes,compressed_bytes)"
        " VALUES(?,?,?,?,?,?)", -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_int64(st, 1, now_ms);
    sqlite3_bind_text(st, 2, hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, anchor ? 1 : 0);
    sqlite3_bind_blob(st, 4, compressed, (int)compressed_len, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 5, (sqlite3_int64)raw_len);
    sqlite3_bind_int64(st, 6, (sqlite3_int64)compressed_len);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st); st = NULL;
        goto rollback;
    }
    sqlite3_finalize(st); st = NULL;
    if (latest_ts && changed) {
        events = jth_generate_events(now_ms, previous, snapshot);
        if (events < 0)
            goto rollback;
    }
    pruned = jth_prune(now_ms);
    if (pruned < 0 || jth_exec("COMMIT") != 0)
        goto rollback_after_commit;
    sqlite3_wal_checkpoint_v2(g_jth_db, NULL, SQLITE_CHECKPOINT_PASSIVE, NULL, NULL);
    jth_secure_files();
    result = json_object_new_object();
    json_object_object_add(result, "captured", json_object_new_boolean(1));
    json_object_object_add(result, "timestamp", json_object_new_int64(now_ms));
    json_object_object_add(result, "changed", json_object_new_boolean(changed));
    json_object_object_add(result, "anchor", json_object_new_boolean(anchor));
    json_object_object_add(result, "events_created", json_object_new_int(events));
    json_object_object_add(result, "pruned_rows", json_object_new_int(pruned));
    json_object_object_add(result, "state_hash", json_object_new_string(hash));
    json_object_object_add(result, "raw_bytes", json_object_new_int64((int64_t)raw_len));
    json_object_object_add(result, "compressed_bytes", json_object_new_int64((int64_t)compressed_len));
    rc = 0;
    goto done;

rollback:
    if (st) sqlite3_finalize(st);
    jth_exec("ROLLBACK");
    goto done;
rollback_after_commit:
    jth_exec("ROLLBACK");
done:
    free(compressed);
    if (previous) json_object_put(previous);
    if (rc != 0 && !result)
        result = jth_error(g_jth_db ? sqlite3_errmsg(g_jth_db) : "history_db_unavailable");
    if (result_out) *result_out = result;
    else if (result) json_object_put(result);
    return rc;
}

static void jth_normalize_range(int64_t *start_ms, int64_t *end_ms)
{
    int64_t now = jth_now_ms();

    if (!end_ms || !start_ms)
        return;
    if (*end_ms <= 0 || *end_ms > now + 60000)
        *end_ms = now;
    if (*start_ms <= 0 || *start_ms < *end_ms - JTH_RETENTION_MS)
        *start_ms = *end_ms - JTH_RETENTION_MS;
}

struct json_object *jmx_topology_history_timeline(int64_t start_ms, int64_t end_ms)
{
    struct json_object *root;
    struct json_object *events;
    sqlite3_stmt *st = NULL;

    if (jth_db_open() != 0)
        return jth_error("history_db_unavailable");
    jth_normalize_range(&start_ms, &end_ms);
    if (start_ms > end_ms)
        return jth_error("invalid_time_range");
    root = json_object_new_object();
    events = json_object_new_array();
    if (sqlite3_prepare_v2(g_jth_db,
        "SELECT event_id,timestamp_ms,end_timestamp_ms,type,node_id,mac,name,port_idx,"
        "link_id,before_json,after_json FROM topology_events "
        "WHERE timestamp_ms BETWEEN ? AND ? ORDER BY timestamp_ms ASC,event_id ASC",
        -1, &st, NULL) != SQLITE_OK) {
        json_object_put(root);
        json_object_put(events);
        return jth_error(sqlite3_errmsg(g_jth_db));
    }
    sqlite3_bind_int64(st, 1, start_ms);
    sqlite3_bind_int64(st, 2, end_ms);
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *e = json_object_new_object();
        const char *before_s = (const char *)sqlite3_column_text(st, 9);
        const char *after_s = (const char *)sqlite3_column_text(st, 10);
        struct json_object *parsed;

        json_object_object_add(e, "id", json_object_new_string((const char *)sqlite3_column_text(st, 0)));
        json_object_object_add(e, "event_id", json_object_new_string((const char *)sqlite3_column_text(st, 0)));
        json_object_object_add(e, "timestamp", json_object_new_int64(sqlite3_column_int64(st, 1)));
        if (sqlite3_column_type(st, 2) != SQLITE_NULL)
            json_object_object_add(e, "end_timestamp", json_object_new_int64(sqlite3_column_int64(st, 2)));
        json_object_object_add(e, "type", json_object_new_string((const char *)sqlite3_column_text(st, 3)));
        json_object_object_add(e, "node_id", json_object_new_string((const char *)sqlite3_column_text(st, 4)));
        json_object_object_add(e, "mac", json_object_new_string((const char *)sqlite3_column_text(st, 5)));
        json_object_object_add(e, "name", json_object_new_string((const char *)sqlite3_column_text(st, 6)));
        if (sqlite3_column_type(st, 7) != SQLITE_NULL)
            json_object_object_add(e, "port_idx", json_object_new_int(sqlite3_column_int(st, 7)));
        if (sqlite3_column_text(st, 8) && ((const char *)sqlite3_column_text(st, 8))[0])
            json_object_object_add(e, "link_id", json_object_new_string((const char *)sqlite3_column_text(st, 8)));
        parsed = before_s ? json_tokener_parse(before_s) : NULL;
        if (parsed) json_object_object_add(e, "before", parsed);
        parsed = after_s ? json_tokener_parse(after_s) : NULL;
        if (parsed) json_object_object_add(e, "after", parsed);
        json_object_array_add(events, e);
    }
    sqlite3_finalize(st);
    json_object_object_add(root, "events", events);
    json_object_object_add(root, "start", json_object_new_int64(start_ms));
    json_object_object_add(root, "end", json_object_new_int64(end_ms));
    json_object_object_add(root, "retention_ms", json_object_new_int64(JTH_RETENTION_MS));
    json_object_object_add(root, "event_count", json_object_new_int((int)json_object_array_length(events)));
    json_object_object_add(root, "available", json_object_new_boolean(1));
    return root;
}

struct json_object *jmx_topology_history_timestamps(int64_t start_ms, int64_t end_ms)
{
    struct json_object *root;
    struct json_object *timestamps;
    sqlite3_stmt *st = NULL;

    if (jth_db_open() != 0)
        return jth_error("history_db_unavailable");
    jth_normalize_range(&start_ms, &end_ms);
    if (start_ms > end_ms)
        return jth_error("invalid_time_range");
    root = json_object_new_object();
    timestamps = json_object_new_array();
    if (sqlite3_prepare_v2(g_jth_db,
        "SELECT ts_ms FROM topology_snapshots WHERE ts_ms BETWEEN ? AND ? ORDER BY ts_ms ASC",
        -1, &st, NULL) != SQLITE_OK) {
        json_object_put(root);
        json_object_put(timestamps);
        return jth_error(sqlite3_errmsg(g_jth_db));
    }
    sqlite3_bind_int64(st, 1, start_ms);
    sqlite3_bind_int64(st, 2, end_ms);
    while (sqlite3_step(st) == SQLITE_ROW)
        json_object_array_add(timestamps, json_object_new_int64(sqlite3_column_int64(st, 0)));
    sqlite3_finalize(st);
    json_object_object_add(root, "timestamps", timestamps);
    json_object_object_add(root, "start", json_object_new_int64(start_ms));
    json_object_object_add(root, "end", json_object_new_int64(end_ms));
    json_object_object_add(root, "retention_ms", json_object_new_int64(JTH_RETENTION_MS));
    json_object_object_add(root, "snapshot_count", json_object_new_int((int)json_object_array_length(timestamps)));
    json_object_object_add(root, "available", json_object_new_boolean(1));
    return root;
}

struct json_object *jmx_topology_history_at(int64_t timestamp_ms)
{
    sqlite3_stmt *st = NULL;
    struct json_object *snapshot = NULL;
    int64_t resolved = 0;

    if (jth_db_open() != 0)
        return jth_error("history_db_unavailable");
    if (timestamp_ms <= 0)
        return jth_error("invalid_timestamp");
    if (sqlite3_prepare_v2(g_jth_db,
        "SELECT ts_ms,payload_zlib,raw_bytes FROM topology_snapshots WHERE ts_ms<=? "
        "ORDER BY ts_ms DESC LIMIT 1", -1, &st, NULL) != SQLITE_OK)
        return jth_error(sqlite3_errmsg(g_jth_db));
    sqlite3_bind_int64(st, 1, timestamp_ms);
    if (sqlite3_step(st) == SQLITE_ROW) {
        resolved = sqlite3_column_int64(st, 0);
        snapshot = jth_decompress_json(sqlite3_column_blob(st, 1), sqlite3_column_bytes(st, 1),
                                       sqlite3_column_int(st, 2));
    }
    sqlite3_finalize(st); st = NULL;
    if (!snapshot) {
        if (sqlite3_prepare_v2(g_jth_db,
            "SELECT ts_ms,payload_zlib,raw_bytes FROM topology_snapshots WHERE ts_ms>? "
            "ORDER BY ts_ms ASC LIMIT 1", -1, &st, NULL) != SQLITE_OK)
            return jth_error(sqlite3_errmsg(g_jth_db));
        sqlite3_bind_int64(st, 1, timestamp_ms);
        if (sqlite3_step(st) == SQLITE_ROW) {
            resolved = sqlite3_column_int64(st, 0);
            snapshot = jth_decompress_json(sqlite3_column_blob(st, 1), sqlite3_column_bytes(st, 1),
                                           sqlite3_column_int(st, 2));
        }
        sqlite3_finalize(st);
    }
    if (!snapshot)
        return jth_error("no_historical_snapshot");
    {
        struct json_object *meta = json_object_new_object();
        json_object_object_add(meta, "requested_timestamp", json_object_new_int64(timestamp_ms));
        json_object_object_add(meta, "resolved_timestamp", json_object_new_int64(resolved));
        json_object_object_add(meta, "exact", json_object_new_boolean(timestamp_ms == resolved));
        json_object_object_add(meta, "historical", json_object_new_boolean(1));
        json_object_object_add(meta, "retention_ms", json_object_new_int64(JTH_RETENTION_MS));
        json_object_object_add(snapshot, "history", meta);
        json_object_object_add(snapshot, "requested_timestamp", json_object_new_int64(timestamp_ms));
        json_object_object_add(snapshot, "resolved_timestamp", json_object_new_int64(resolved));
    }
    return snapshot;
}

struct json_object *jmx_topology_history_status(void)
{
    struct json_object *root;
    sqlite3_stmt *st = NULL;
    struct stat sb;
    char wal_path[1024];
    int64_t snapshots = 0, events = 0, oldest = 0, newest = 0;
    int64_t db_bytes = 0, wal_bytes = 0;

    if (jth_db_open() != 0)
        return jth_error("history_db_unavailable");
    if (sqlite3_prepare_v2(g_jth_db,
        "SELECT COUNT(*),COALESCE(MIN(ts_ms),0),COALESCE(MAX(ts_ms),0) FROM topology_snapshots",
        -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW) {
        snapshots = sqlite3_column_int64(st, 0);
        oldest = sqlite3_column_int64(st, 1);
        newest = sqlite3_column_int64(st, 2);
    }
    sqlite3_finalize(st); st = NULL;
    if (sqlite3_prepare_v2(g_jth_db, "SELECT COUNT(*) FROM topology_events", -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        events = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    if (stat(jth_db_path(), &sb) == 0) db_bytes = sb.st_size;
    snprintf(wal_path, sizeof(wal_path), "%s-wal", jth_db_path());
    if (stat(wal_path, &sb) == 0) wal_bytes = sb.st_size;
    jth_secure_files();
    root = json_object_new_object();
    json_object_object_add(root, "available", json_object_new_boolean(1));
    json_object_object_add(root, "database", json_object_new_string(jth_db_path()));
    json_object_object_add(root, "retention_ms", json_object_new_int64(JTH_RETENTION_MS));
    json_object_object_add(root, "anchor_interval_ms", json_object_new_int64(JTH_ANCHOR_MS));
    json_object_object_add(root, "snapshot_count", json_object_new_int64(snapshots));
    json_object_object_add(root, "event_count", json_object_new_int64(events));
    json_object_object_add(root, "oldest_timestamp", json_object_new_int64(oldest));
    json_object_object_add(root, "newest_timestamp", json_object_new_int64(newest));
    json_object_object_add(root, "database_bytes", json_object_new_int64(db_bytes));
    json_object_object_add(root, "wal_bytes", json_object_new_int64(wal_bytes));
    json_object_object_add(root, "snapshot_row_cap", json_object_new_int(JTH_MAX_SNAPSHOTS));
    json_object_object_add(root, "event_row_cap", json_object_new_int(JTH_MAX_EVENTS));
    return root;
}

void jmx_topology_history_close(void)
{
    if (g_jth_db) {
        sqlite3_wal_checkpoint_v2(g_jth_db, NULL, SQLITE_CHECKPOINT_TRUNCATE, NULL, NULL);
        sqlite3_close(g_jth_db);
        g_jth_db = NULL;
    }
}

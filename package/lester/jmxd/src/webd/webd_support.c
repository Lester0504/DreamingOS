// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
#include "webd_support.h"
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#define SUPPORT_BODY_MAX (3U * 1024U * 1024U)
static const char *str(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    return o && json_object_object_get_ex(o, key, &v) && json_object_is_type(v, json_type_string) ? json_object_get_string(v) : "";
}
static long long num(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    return o && json_object_object_get_ex(o, key, &v) && json_object_is_type(v, json_type_int) ? json_object_get_int64(v) : -1;
}
static struct json_object *get(struct json_object *o, const char *key)
{ struct json_object *v = NULL; if (o) json_object_object_get_ex(o, key, &v); return v; }
static void txt(struct json_object *o, const char *key, const char *value)
{ json_object_object_add(o, key, json_object_new_string(value ? value : "")); }
static void integer(struct json_object *o, const char *key, long long n)
{ json_object_object_add(o, key, json_object_new_int64(n)); }
static void boolean(struct json_object *o, const char *key, int b)
{ json_object_object_add(o, key, json_object_new_boolean(b)); }
static struct json_object *copy(struct json_object *o)
{ return o ? json_tokener_parse(json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN)) : NULL; }
static struct json_object *error(int *status, int code, const char *name, const char *message)
{
    struct json_object *o = json_object_new_object(), *e = json_object_new_object();
    *status = code; boolean(o, "ok", 0); integer(o, "code", code); txt(o, "error_code", name); txt(o, "message", message);
    txt(e, "code", name); txt(e, "message", message); json_object_object_add(o, "error", e); return o;
}
static struct json_object *ok(struct json_object *data, int *status, int code)
{
    struct json_object *o = json_object_new_object(); *status = code;
    boolean(o, "ok", 1); integer(o, "code", 2000); json_object_object_add(o, "data", data); return o;
}
static sqlite3_stmt *prepare(sqlite3 *db, const char *sql)
{ sqlite3_stmt *q = NULL; return sqlite3_prepare_v2(db, sql, -1, &q, NULL) == SQLITE_OK ? q : NULL; }
static void sql_bind(sqlite3_stmt *q, int index, const char *value)
{ sqlite3_bind_text(q, index, value ? value : "", -1, SQLITE_TRANSIENT); }
static int done(sqlite3_stmt *q)
{ int rc = q && sqlite3_step(q) == SQLITE_DONE ? 0 : -1; sqlite3_finalize(q); return rc; }
static int random_id(char out[65], const char *prefix)
{
    unsigned char bytes[16]; if (RAND_bytes(bytes, sizeof(bytes)) != 1) return -1;
    size_t n = strlen(prefix); memcpy(out, prefix, n);
    for (size_t i = 0; i < sizeof(bytes); ++i) snprintf(out + n + 2*i, 3, "%02x", bytes[i]);
    return 0;
}
static void digest_hex(const void *bytes, size_t len, char out[65])
{
    unsigned char digest[32]; SHA256(bytes, len, digest);
    for (unsigned i = 0; i < 32; ++i) snprintf(out + 2*i, 3, "%02x", digest[i]);
}
static void timestamp(char out[32])
{ time_t now = time(NULL); struct tm tm; gmtime_r(&now, &tm); strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", &tm); }
static const char *column(sqlite3_stmt *q, int index)
{ const unsigned char *value = sqlite3_column_text(q, index); return value ? (const char *)value : ""; }
static int fields(struct json_object *o, const char *const *names)
{
    if (!o || !json_object_is_type(o, json_type_object)) return 0;
    json_object_object_foreach(o, key, value) {
        (void)value; int found = 0;
        for (int i = 0; names[i]; ++i) if (!strcmp(key, names[i])) found = 1;
        if (!found) return 0;
    }
    return 1;
}
static int chars(const char *s)
{
    int count = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p;) {
        unsigned n = *p < 0x80 ? 1 : (*p >= 0xc2 && *p <= 0xdf) ? 2 : (*p >= 0xe0 && *p <= 0xef) ? 3 : (*p >= 0xf0 && *p <= 0xf4) ? 4 : 0;
        if (!n) return -1;
        for (unsigned i = 1; i < n; ++i) if (!p[i] || (p[i] & 0xc0) != 0x80) return -1;
        if ((n == 3 && ((p[0] == 0xe0 && p[1] < 0xa0) || (p[0] == 0xed && p[1] >= 0xa0))) ||
            (n == 4 && ((p[0] == 0xf0 && p[1] < 0x90) || (p[0] == 0xf4 && p[1] >= 0x90)))) return -1;
        p += n; ++count;
    }
    return count;
}
static int bounded_text(struct json_object *o, const char *key, int min, int max)
{
    struct json_object *v = get(o, key);
    if (!v || !json_object_is_type(v, json_type_string)) return 0;
    const char *s = json_object_get_string(v);
    int n = chars(s); return n >= min && n <= max && (size_t)json_object_get_string_len(v) == strlen(s);
}
static int request_id(const char *s)
{ size_t n = strlen(s); return n >= 8 && n <= 100 && strspn(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") == n; }
static int compare_keys(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }
static struct json_object *canonical(struct json_object *o)
{
    if (!o) return NULL;
    if (json_object_is_type(o, json_type_array)) {
        struct json_object *a = json_object_new_array();
        for (size_t i = 0; i < json_object_array_length(o); ++i) json_object_array_add(a, canonical(json_object_array_get_idx(o, i)));
        return a;
    }
    if (!json_object_is_type(o, json_type_object)) return copy(o);
    size_t count = json_object_object_length(o), i = 0; char **keys = calloc(count ? count : 1, sizeof(char *));
    if (!keys) return NULL;
    json_object_object_foreach(o, key, value) { (void)value; keys[i++] = (char *)key; }
    qsort(keys, count, sizeof(char *), compare_keys);
    struct json_object *result = json_object_new_object();
    for (i = 0; i < count; ++i) json_object_object_add(result, keys[i], canonical(get(o, keys[i])));
    free(keys); return result;
}
int support_config_load_file(struct support_config *config, const char *path)
{
    memset(config, 0, sizeof(*config));
    snprintf(config->db_path, sizeof(config->db_path), "%s", SUPPORT_DB_PATH);
    snprintf(config->key_dir, sizeof(config->key_dir), "%s", SUPPORT_IDENTITY_DIR);
    struct json_object *o = json_object_from_file(path);
    if (!o) return -1;
    const char *url = str(o, "url");
    CURLU *u = curl_url(); char *scheme = NULL, *host = NULL, *user = NULL, *pass = NULL, *query = NULL, *fragment = NULL;
    int valid = u && !curl_url_set(u, CURLUPART_URL, url, 0) && !curl_url_get(u, CURLUPART_SCHEME, &scheme, 0) &&
        !curl_url_get(u, CURLUPART_HOST, &host, 0) && !strcmp(scheme, "https") && host[0] &&
        curl_url_get(u, CURLUPART_USER, &user, 0) && curl_url_get(u, CURLUPART_PASSWORD, &pass, 0) &&
        curl_url_get(u, CURLUPART_QUERY, &query, 0) && curl_url_get(u, CURLUPART_FRAGMENT, &fragment, 0) && strlen(url) < sizeof(config->url);
    if (valid) snprintf(config->url, sizeof(config->url), "%s", url);
    curl_free(scheme); curl_free(host); curl_free(user); curl_free(pass); curl_free(query); curl_free(fragment); curl_url_cleanup(u);
    json_object_put(o); return valid ? 0 : -1;
}
int support_config_load(struct support_config *config)
{ return support_config_load_file(config, SUPPORT_CONFIG_PATH); }
int support_db_open(const char *path, sqlite3 **db)
{
    *db = NULL;
    if (sqlite3_open_v2(path, db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL) != SQLITE_OK) goto fail;
    chmod(path, 0600); sqlite3_busy_timeout(*db, 5000);
    const char *sql = "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;"
        "CREATE TABLE IF NOT EXISTS support_version(version INTEGER PRIMARY KEY);INSERT OR IGNORE INTO support_version VALUES(1);"
        "CREATE TABLE IF NOT EXISTS feedback(id TEXT PRIMARY KEY,subject TEXT NOT NULL,request_id TEXT NOT NULL,payload TEXT NOT NULL,"
        " state TEXT NOT NULL DEFAULT 'queued',cloud_id TEXT NOT NULL DEFAULT '',cloud_json TEXT NOT NULL DEFAULT '{}',"
        " error TEXT NOT NULL DEFAULT '',attempts INTEGER NOT NULL DEFAULT 0,next_attempt INTEGER NOT NULL DEFAULT 0,"
        " synced_at INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,read_comment TEXT NOT NULL DEFAULT '',UNIQUE(subject,request_id));"
        "CREATE TABLE IF NOT EXISTS support_outbox(id TEXT PRIMARY KEY,ticket_id TEXT NOT NULL REFERENCES feedback(id),"
        " subject TEXT NOT NULL,request_id TEXT NOT NULL,kind TEXT NOT NULL,payload TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'queued',"
        " error TEXT NOT NULL DEFAULT '',attempts INTEGER NOT NULL DEFAULT 0,next_attempt INTEGER NOT NULL DEFAULT 0,UNIQUE(subject,request_id));"
        "CREATE INDEX IF NOT EXISTS feedback_subject ON feedback(subject,created_at,id);";
    if (sqlite3_exec(*db, sql, NULL, NULL, NULL) != SQLITE_OK) goto fail;
    sqlite3_stmt *q = prepare(*db, "SELECT version FROM support_version");
    int valid = q && sqlite3_step(q) == SQLITE_ROW && sqlite3_column_int(q, 0) == 1 && sqlite3_step(q) == SQLITE_DONE;
    sqlite3_finalize(q); if (!valid) goto fail; return 0;
fail:
    if (*db) sqlite3_close(*db); *db = NULL; return -1;
}
int support_subject(sqlite3 *db, const char *username, char out[65])
{
    /* A support-only key follows account rename and is deleted with the account.
       It grants no permission and never changes the user's credential material. */
    if (sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS web_support_subjects(username TEXT PRIMARY KEY REFERENCES web_users(username)"
        " ON UPDATE CASCADE ON DELETE CASCADE,subject TEXT UNIQUE NOT NULL)", NULL, NULL, NULL) != SQLITE_OK) return -1;
    char value[65]; if (random_id(value, "subject-")) return -1;
    sqlite3_stmt *q = prepare(db, "INSERT OR IGNORE INTO web_support_subjects SELECT username,?2 FROM web_users WHERE username=?1 AND status='enabled'");
    if (!q) return -1; sql_bind(q, 1, username); sql_bind(q, 2, value); if (done(q)) return -1;
    q = prepare(db, "SELECT subject FROM web_support_subjects WHERE username=?1");
    if (!q) return -1; sql_bind(q, 1, username); int valid = sqlite3_step(q) == SQLITE_ROW;
    if (valid) snprintf(out, 65, "%s", column(q, 0)); sqlite3_finalize(q); return valid ? 0 : -1;
}
struct json_object *support_diagnostics(void)
{
    struct json_object *o = json_object_new_object(); struct utsname un;
    txt(o, "firmware_version", ""); txt(o, "board", ""); txt(o, "architecture", uname(&un) ? "" : un.machine);
    char line[512]; FILE *f = fopen("/etc/openwrt_release", "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) if (!strncmp(line, "DISTRIB_DESCRIPTION=", 20)) {
            char *v = line + 20; v[strcspn(v, "\r\n")] = 0;
            if ((*v == '\'' || *v == '"') && strlen(v) > 1) { ++v; v[strlen(v)-1] = 0; }
            txt(o, "firmware_version", v); break;
        }
        fclose(f);
    }
    f = fopen("/tmp/sysinfo/board_name", "r");
    if (f) { if (fgets(line, sizeof(line), f)) { line[strcspn(line, "\r\n")] = 0; txt(o, "board", line); } fclose(f); }
    double uptime = 0; f = fopen("/proc/uptime", "r"); if (f) { if (fscanf(f, "%lf", &uptime) != 1) uptime = 0; fclose(f); }
    integer(o, "uptime_seconds", (long long)uptime);
    struct json_object *ordered = canonical(o); const char *raw = json_object_to_json_string_ext(ordered, JSON_C_TO_STRING_PLAIN);
    char digest[65]; digest_hex(raw, strlen(raw), digest); txt(o, "snapshot_id", digest); json_object_put(ordered); return o;
}
static int validate_diagnostics(struct json_object *d)
{
    const char *const keys[] = {"snapshot_id", "firmware_version", "board", "architecture", "uptime_seconds", NULL};
    if (!d || json_object_is_type(d, json_type_null)) return 1;
    if (!fields(d, keys) || !bounded_text(d, "snapshot_id", 64, 64) || !bounded_text(d, "firmware_version", 0, 160) ||
        !bounded_text(d, "board", 0, 160) || !bounded_text(d, "architecture", 0, 160) || num(d, "uptime_seconds") < 0) return 0;
    struct json_object *without = copy(d); json_object_object_del(without, "snapshot_id");
    struct json_object *ordered = canonical(without); const char *raw = json_object_to_json_string_ext(ordered, JSON_C_TO_STRING_PLAIN);
    char digest[65]; digest_hex(raw, strlen(raw), digest); int same = !strcmp(digest, str(d, "snapshot_id"));
    json_object_put(ordered); json_object_put(without); return same;
}
static const char *module_name(const char *id)
{
    static const char *ids[] = {"network", "wireless", "storage", "system", "desktop", "plugins", "other", NULL};
    static const char *labels[] = {"网络与连接", "无线与 AP", "存储与文件", "系统与升级", "桌面与界面", "应用与插件", "其他问题"};
    for (int i = 0; ids[i]; ++i) if (!strcmp(ids[i], id)) return labels[i]; return NULL;
}
static struct json_object *capabilities(const struct support_config *config, int writable)
{
    struct json_object *o = json_object_new_object(), *list = json_object_new_array();
    static const char *ids[] = {"network", "wireless", "storage", "system", "desktop", "plugins", "other", NULL};
    for (int i = 0; ids[i]; ++i) { struct json_object *m = json_object_new_object(); txt(m, "id", ids[i]); txt(m, "label", module_name(ids[i])); json_object_array_add(list, m); }
    integer(o, "version", 1); boolean(o, "configured", config->url[0]); boolean(o, "read", 1); boolean(o, "submit", writable && config->url[0]);
    boolean(o, "reply", writable && config->url[0]); boolean(o, "mark_read", writable); boolean(o, "diagnostics", 1); boolean(o, "attachments", 1);
    txt(o, "reason", config->url[0] ? (writable ? "" : "当前账号仅可查看反馈") : "云工单服务尚未配置");
    json_object_object_add(o, "modules", list);
    json_object_object_add(o, "limits", json_tokener_parse("{\"description_min\":20,\"description_max\":10000,\"comment_max\":5000,\"attachments_max\":5,\"attachment_bytes\":524288,\"attachments_total_bytes\":2097152,\"mime_types\":[\"image/png\"],\"image_dimension_max\":4096,\"image_pixels_max\":4194304,\"image_interlaced\":false}"));
    return o;
}
static struct json_object *detail(sqlite3 *db, const char *subject, const char *id, int writable)
{
    sqlite3_stmt *q = prepare(db, "SELECT payload,state,cloud_id,cloud_json,error,synced_at,created_at,read_comment,request_id,next_attempt FROM feedback WHERE id=?1 AND subject=?2");
    if (!q) return NULL; sql_bind(q, 1, id); sql_bind(q, 2, subject);
    if (sqlite3_step(q) != SQLITE_ROW) { sqlite3_finalize(q); return NULL; }
    struct json_object *payload = json_tokener_parse(column(q, 0)), *o = json_tokener_parse(column(q, 3));
    if (!payload || !o) { json_object_put(payload); json_object_put(o); sqlite3_finalize(q); return NULL; }
    char read_comment[100]; snprintf(read_comment, sizeof(read_comment), "%s", column(q, 7));
    txt(o, "id", id); txt(o, "request_id", column(q, 8)); txt(o, "cloud_ticket_id", column(q, 2)); txt(o, "delivery_state", column(q, 1));
    txt(o, "sync_error", column(q, 4)); integer(o, "synced_at", sqlite3_column_int64(q, 5));
    int cloud = column(q, 2)[0], deleted = !strcmp(column(q, 1), "deleted");
    if (!cloud) {
        txt(o, "module_id", str(payload, "module_id")); txt(o, "module_name", module_name(str(payload, "module_id")));
        txt(o, "description", str(payload, "description")); txt(o, "reporter_name", str(payload, "reporter_name"));
        txt(o, "reporter_contact", str(payload, "reporter_contact")); txt(o, "created_at", column(q, 6)); txt(o, "updated_at", column(q, 6));
        json_object_object_add(o, "status", NULL); integer(o, "revision", 0); txt(o, "resolution", "");
        struct json_object *d = get(payload, "diagnostics"); txt(o, "system_info", d ? json_object_to_json_string_ext(d, JSON_C_TO_STRING_PLAIN) : "");
        struct json_object *atts = json_object_new_array(), *files = get(payload, "attachments");
        for (size_t i = 0; files && i < json_object_array_length(files); ++i) {
            struct json_object *file = json_object_array_get_idx(files, i), *a = json_object_new_object(); char aid[40];
            snprintf(aid, sizeof(aid), "local-att-%zu", i); txt(a, "id", aid); txt(a, "name", str(file, "name")); txt(a, "mime_type", "image/png");
            size_t n = strlen(str(file, "data")); integer(a, "size", (long long)(n / 4 * 3 - (n && str(file, "data")[n-1] == '=') - (n > 1 && str(file, "data")[n-2] == '='))); json_object_array_add(atts, a);
        }
        json_object_object_add(o, "attachments", atts); json_object_object_add(o, "comments", json_object_new_array());
    }
    boolean(o, "deleted", deleted); boolean(o, "retryable", !deleted && strcmp(column(q, 1), "submitted") && sqlite3_column_int64(q, 9) >= 0);
    sqlite3_finalize(q); json_object_put(payload);
    struct json_object *perms = json_object_new_object(); boolean(perms, "update", 0); boolean(perms, "delete", 0);
    boolean(perms, "reply", writable && cloud && !deleted && strcmp(str(o, "status"), "closed")); json_object_object_add(o, "permissions", perms);
    struct json_object *comments = get(o, "comments"); int seen = !read_comment[0], unread = 0;
    for (size_t i = 0; comments && i < json_object_array_length(comments); ++i) {
        struct json_object *c = json_object_array_get_idx(comments, i);
        if (seen && !strcmp(str(c, "author_kind"), "admin")) ++unread;
        if (!strcmp(str(c, "id"), read_comment)) seen = 1;
    }
    integer(o, "unread", unread); txt(o, "last_read_comment_id", read_comment);
    struct json_object *pending = json_object_new_array();
    q = prepare(db, "SELECT request_id,payload,state,error FROM support_outbox WHERE ticket_id=? AND kind='comments' AND state!='submitted' ORDER BY rowid");
    if (q) {
        sql_bind(q, 1, id); while (sqlite3_step(q) == SQLITE_ROW) {
            struct json_object *item = json_tokener_parse(column(q, 1));
            if (!item) continue; txt(item, "delivery_state", column(q, 2)); txt(item, "error", column(q, 3)); json_object_array_add(pending, item);
        } sqlite3_finalize(q);
    }
    json_object_object_add(o, "pending_comments", pending); return o;
}
static int validate_create(struct json_object *body, int *status)
{
    const char *const keys[] = {"request_id", "module_id", "description", "reporter_name", "reporter_contact", "diagnostics", "attachments", NULL};
    if (!fields(body, keys) || !request_id(str(body, "request_id")) || !module_name(str(body, "module_id")) ||
        !bounded_text(body, "description", 20, 10000) || !bounded_text(body, "reporter_name", 1, 80) ||
        (get(body, "reporter_contact") && !bounded_text(body, "reporter_contact", 0, 200)) || !validate_diagnostics(get(body, "diagnostics"))) return -1;
    struct json_object *images = get(body, "attachments");
    if (images && (!json_object_is_type(images, json_type_array) || json_object_array_length(images) > 5)) { *status = 413; return -1; }
    size_t total = 0;
    for (size_t i = 0; images && i < json_object_array_length(images); ++i) {
        const char *const image_keys[] = {"name", "mime_type", "data", NULL};
        struct json_object *a = json_object_array_get_idx(images, i); const char *encoded = str(a, "data"); size_t n = strlen(encoded);
        if (!fields(a, image_keys) || !bounded_text(a, "name", 1, 120) || strcmp(str(a, "mime_type"), "image/png") ||
            n < 76 || n % 4 || strncmp(encoded, "iVBORw0KGgo", 11) || strspn(encoded, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") != n) { *status = 415; return -1; }
        size_t bytes = n / 4 * 3 - (encoded[n-1] == '=') - (encoded[n-2] == '=');
        if (bytes > 524288) { *status = 413; return -1; } total += bytes;
    }
    if (total > 2097152) { *status = 413; return -1; } return 0;
}
struct json_object *support_handle(sqlite3 *db, const struct support_config *config,
    const char *subject, int writable, const char *method, const char *path,
    struct json_object *query, struct json_object *body, int *status)
{
    int reading = !strcmp(method, "GET"), posting = !strcmp(method, "POST");
    if (!subject || !*subject) return error(status, 403, "personal_session_required", "需要个人设备会话");
    if (!reading && !writable) return error(status, 403, "permission_denied", "当前账号仅可查看反馈");
    if (reading && !strcmp(path, "capabilities")) { struct json_object *c = capabilities(config, writable); txt(c, "subject", subject); return ok(c, status, 200); }
    if (reading && !strcmp(path, "diagnostics")) return ok(support_diagnostics(), status, 200);
    if (posting && !strcmp(path, "tickets")) {
        if (!config->url[0]) return error(status, 503, "support_not_configured", "云工单服务尚未配置");
        *status = 422; if (validate_create(body, status)) return error(status, *status, "invalid_feedback", "请检查必填字段、诊断快照和图片限制");
        struct json_object *ordered = canonical(body); if (!ordered) return error(status, 503, "storage_unavailable", "反馈暂时无法保存");
        const char *payload = json_object_to_json_string_ext(ordered, JSON_C_TO_STRING_PLAIN); char local_id[65] = "", now[32];
        if (strlen(payload) > SUPPORT_BODY_MAX) { json_object_put(ordered); return error(status, 413, "payload_too_large", "反馈内容过大"); }
        if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) goto create_fail;
        sqlite3_stmt *q = prepare(db, "SELECT id,payload FROM feedback WHERE subject=? AND request_id=?");
        if (!q) goto create_rollback; sql_bind(q, 1, subject); sql_bind(q, 2, str(body, "request_id"));
        int rc = sqlite3_step(q);
        if (rc == SQLITE_ROW) {
            int same = !strcmp(payload, column(q, 1)); snprintf(local_id, sizeof(local_id), "%s", column(q, 0)); sqlite3_finalize(q);
            if (!same) { sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL); json_object_put(ordered); return error(status, 409, "request_id_conflict", "同一请求标识已用于其他内容"); }
        } else {
            sqlite3_finalize(q); if (rc != SQLITE_DONE || random_id(local_id, "local-")) goto create_rollback;
            q = prepare(db, "SELECT count(*) FROM feedback WHERE state IN ('queued','submitting','failed')");
            if (!q) goto create_rollback; int full = sqlite3_step(q) != SQLITE_ROW || sqlite3_column_int(q, 0) >= 100; sqlite3_finalize(q);
            if (full) { sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL); json_object_put(ordered); return error(status, 429, "queue_full", "待投递反馈已达100条，请等待恢复后再提交"); }
            timestamp(now); q = prepare(db, "INSERT INTO feedback(id,subject,request_id,payload,created_at) VALUES(?,?,?,?,?)");
            if (!q) goto create_rollback; sql_bind(q, 1, local_id); sql_bind(q, 2, subject); sql_bind(q, 3, str(body, "request_id")); sql_bind(q, 4, payload); sql_bind(q, 5, now);
            if (done(q)) goto create_rollback;
        }
        if (sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) goto create_rollback;
        json_object_put(ordered); struct json_object *d = detail(db, subject, local_id, writable);
        return d ? ok(d, status, *str(d, "cloud_ticket_id") ? 200 : 202) : error(status, 503, "storage_unavailable", "反馈已保存，但暂时无法读取回执");
create_rollback:
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
create_fail:
        json_object_put(ordered); return error(status, 503, "storage_unavailable", "反馈未能保存，请保留内容重试");
    }
    if (reading && (!strcmp(path, "tickets") || !strcmp(path, "unread"))) {
        long long page = num(query, "page"), size = num(query, "page_size");
        if (page < 0) page = 1; if (size < 0) size = 20;
        if (page < 1 || page > 100000 || (size != 20 && size != 50 && size != 100)) return error(status, 422, "invalid_pagination", "分页参数无效");
        const char *filter = str(query, "status"); if (*filter && strcmp(filter, "pending") && strcmp(filter, "processing") && strcmp(filter, "resolved") && strcmp(filter, "closed")) return error(status, 422, "invalid_status", "状态筛选无效");
        int unread_only = !strcmp(path, "unread");
        struct json_object *items = json_object_new_array(), *o = json_object_new_object(); long long total = 0, count = 0;
        sqlite3_stmt *q = prepare(db, "SELECT id FROM feedback WHERE subject=? ORDER BY created_at DESC,id DESC");
        if (!q) { json_object_put(items); json_object_put(o); return error(status, 503, "storage_unavailable", "反馈暂时无法读取"); }
        sql_bind(q, 1, subject); int rc;
        while ((rc = sqlite3_step(q)) == SQLITE_ROW) {
            struct json_object *d = detail(db, subject, column(q, 0), writable);
            if (!d) { rc = SQLITE_ERROR; break; }
            if (*filter && strcmp(filter, str(d, "status"))) { json_object_put(d); continue; }
            count += num(d, "unread");
            if (unread_only) {
                if (num(d, "unread") > 0) { struct json_object *u = json_object_new_object(); txt(u, "id", str(d, "id")); integer(u, "unread", num(d, "unread")); json_object_array_add(items, u); }
                json_object_put(d);
            } else if (total >= (page-1)*size && total < page*size) {
                json_object_object_del(d, "comments"); json_object_object_del(d, "attachments"); json_object_object_del(d, "system_info"); json_object_object_del(d, "pending_comments"); json_object_array_add(items, d);
            } else json_object_put(d);
            ++total;
        }
        sqlite3_finalize(q); if (rc != SQLITE_DONE) { json_object_put(items); json_object_put(o); return error(status, 503, "storage_unavailable", "反馈暂时无法读取"); }
        json_object_object_add(o, "items", items); integer(o, "total", total); integer(o, "page", page); integer(o, "page_size", size); integer(o, "count", count);
        boolean(o, "configured", config->url[0]); return ok(o, status, 200);
    }
    if (!strncmp(path, "tickets/", 8)) {
        const char *rest = path + 8, *slash = strchr(rest, '/'); size_t n = slash ? (size_t)(slash-rest) : strlen(rest); char id[65];
        if (n >= sizeof(id) || n < 1) return error(status, 404, "ticket_not_found", "反馈不存在");
        memcpy(id, rest, n); id[n] = 0; const char *action = slash ? slash+1 : "";
        struct json_object *d = detail(db, subject, id, writable);
        if (!d) return error(status, 404, "ticket_not_found", "反馈不存在");
        if (reading && !*action) return ok(d, status, 200);
        if (reading && !strncmp(action, "attachments/", 12)) {
            const char *aid = action + 12; struct json_object *atts = get(d, "attachments"); size_t index = (size_t)-1;
            for (size_t i = 0; atts && i < json_object_array_length(atts); ++i) if (!strcmp(str(json_object_array_get_idx(atts, i), "id"), aid)) index = i;
            if (index == (size_t)-1 || json_object_get_boolean(get(d, "deleted"))) { json_object_put(d); return error(status, 404, "attachment_not_found", "图片不存在或已不可用"); }
            sqlite3_stmt *q = prepare(db, "SELECT payload FROM feedback WHERE id=? AND subject=?"); struct json_object *payload = NULL;
            if (q) { sql_bind(q, 1, id); sql_bind(q, 2, subject); if (sqlite3_step(q) == SQLITE_ROW) payload = json_tokener_parse(column(q, 0)); sqlite3_finalize(q); }
            struct json_object *file = payload ? get(payload, "attachments") : NULL;
            struct json_object *image = file && index < json_object_array_length(file) ? copy(json_object_array_get_idx(file, index)) : NULL;
            json_object_put(payload); json_object_put(d);
            if (!image) return error(status, 404, "attachment_not_found", "图片不存在"); txt(image, "id", aid); return ok(image, status, 200);
        }
        if (posting && (!strcmp(action, "comments") || !strcmp(action, "read"))) {
            int is_read = !strcmp(action, "read");
            const char *const comment_keys[] = {"request_id", "expected_revision", "content", NULL};
            const char *const read_keys[] = {"last_comment_id", NULL};
            if (!*str(d, "cloud_ticket_id") || json_object_get_boolean(get(d, "deleted"))) { json_object_put(d); return error(status, 409, "ticket_not_submitted", "请等待反馈投递完成"); }
            if (!is_read && (!fields(body, comment_keys) || !request_id(str(body, "request_id")) || !bounded_text(body, "content", 1, 5000) || num(body, "expected_revision") < 1)) { json_object_put(d); return error(status, 422, "invalid_comment", "回复内容或版本无效"); }
            int found = 0;
            if (is_read) {
                struct json_object *comments = get(d, "comments");
                if (fields(body, read_keys)) for (size_t i = 0; comments && i < json_object_array_length(comments); ++i)
                    if (!strcmp(str(json_object_array_get_idx(comments, i), "id"), str(body, "last_comment_id"))) found = 1;
                if (!found) { json_object_put(d); return error(status, 422, "invalid_read_cursor", "已读游标不属于此反馈"); }
            }
            struct json_object *ordered = canonical(body); const char *raw = json_object_to_json_string_ext(ordered, JSON_C_TO_STRING_PLAIN);
            char reqid[101], opid[65]; if (is_read) snprintf(reqid, sizeof(reqid), "read-%s", str(body, "last_comment_id")); else snprintf(reqid, sizeof(reqid), "%s", str(body, "request_id"));
            if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) goto comment_fail;
            sqlite3_stmt *q = prepare(db, "SELECT ticket_id,kind,payload FROM support_outbox WHERE subject=? AND request_id=?");
            if (!q) goto comment_rollback; sql_bind(q, 1, subject); sql_bind(q, 2, reqid); int rc = sqlite3_step(q);
            if (rc == SQLITE_ROW) {
                int same = !strcmp(column(q, 0), id) && !strcmp(column(q, 1), action) && !strcmp(column(q, 2), raw); sqlite3_finalize(q);
                if (!same) { sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL); json_object_put(ordered); json_object_put(d); return error(status, 409, "request_id_conflict", "请求标识已用于其他内容"); }
            } else {
                sqlite3_finalize(q); if (rc != SQLITE_DONE || random_id(opid, "op-")) goto comment_rollback;
                if (!is_read && (!strcmp(str(d, "status"), "closed") || num(body, "expected_revision") != num(d, "revision"))) {
                    sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL); json_object_put(ordered); int closed = !strcmp(str(d, "status"), "closed"); json_object_put(d);
                    return error(status, closed ? 403 : 409, closed ? "ticket_closed" : "revision_conflict", closed ? "工单已关闭，需支持人员重新打开" : "记录已更新，请重新载入");
                }
                q = prepare(db, "INSERT INTO support_outbox(id,ticket_id,subject,request_id,kind,payload) VALUES(?,?,?,?,?,?)");
                if (!q) goto comment_rollback; sql_bind(q, 1, opid); sql_bind(q, 2, id); sql_bind(q, 3, subject); sql_bind(q, 4, reqid); sql_bind(q, 5, action); sql_bind(q, 6, raw); if (done(q)) goto comment_rollback;
                if (is_read) {
                    const char *current = str(d, "last_read_comment_id"); struct json_object *comments = get(d, "comments"); int passed = !*current, advance = 0;
                    for (size_t i = 0; comments && i < json_object_array_length(comments); ++i) {
                        const char *cid = str(json_object_array_get_idx(comments, i), "id"); if (!strcmp(cid, current)) passed = 1;
                        if (!strcmp(cid, str(body, "last_comment_id")) && passed) advance = 1;
                    }
                    if (advance) { q = prepare(db, "UPDATE feedback SET read_comment=? WHERE id=?"); if (!q) goto comment_rollback;
                        sql_bind(q, 1, str(body, "last_comment_id")); sql_bind(q, 2, id); if (done(q)) goto comment_rollback; }
                }
            }
            if (sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) goto comment_rollback;
            json_object_put(ordered); json_object_put(d); d = detail(db, subject, id, writable);
            return d ? ok(d, status, 202) : error(status, 503, "storage_unavailable", "回执暂时不可读");
comment_rollback:
            sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
comment_fail:
            json_object_put(ordered); json_object_put(d); return error(status, 503, "storage_unavailable", "操作未保存，请重试");
        }
        json_object_put(d);
    }
    return error(status, 404, "not_found", "接口不存在");
}

struct response_buffer { char *bytes; size_t length; };
static size_t receive(void *bytes, size_t size, size_t count, void *opaque)
{
    struct response_buffer *out = opaque; size_t n = size * count;
    if (n > 4U*1024U*1024U - out->length) return 0;
    char *next = realloc(out->bytes, out->length+n+1); if (!next) return 0;
    out->bytes = next; memcpy(out->bytes+out->length, bytes, n); out->length += n; out->bytes[out->length] = 0; return n;
}
static int read_key(const char *directory, const char *leaf, unsigned char out[32])
{
    char path[1024]; snprintf(path, sizeof(path), "%s/%s", directory, leaf);
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW); struct stat st;
    int valid = fd >= 0 && !fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_size == 32 && read(fd, out, 32) == 32;
    if (fd >= 0) close(fd); return valid ? 0 : -1;
}
struct json_object *support_remote(const struct support_config *config, const char *subject,
    const char *method, const char *path, struct json_object *query, struct json_object *body, int *status)
{
    if (!config->url[0]) return error(status, 503, "support_not_configured", "云工单服务尚未配置");
#ifndef SUPPORT_TEST
    if (strncmp(config->url, "https://", 8)) return error(status, 503, "support_not_configured", "云工单地址必须使用 HTTPS");
#else
    if (strncmp(config->url, "https://", 8) && strncmp(config->url, "http://127.0.0.1:", 17)) return error(status, 503, "support_not_configured", "测试仅允许回环 HTTP");
#endif
    unsigned char kex_secret[32] = {0}, sign_secret[32] = {0}, kex_pub[32], sign_pub[32], signature[64], cat[64];
    EVP_PKEY *kex = NULL, *signer = NULL; EVP_MD_CTX *sign_ctx = NULL; struct json_object *payload = NULL, *envelope = NULL, *result = NULL;
    CURL *curl = NULL; struct curl_slist *headers = NULL; struct response_buffer response = {0};
    int result_status = 503; const char *failure = "device_identity_unavailable", *message = "设备签名身份未就绪";
    if (read_key(config->key_dir, "identity.x25519", kex_secret) || read_key(config->key_dir, "identity.ed25519", sign_secret)) goto cleanup;
    kex = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, kex_secret, 32); signer = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, sign_secret, 32);
    OPENSSL_cleanse(kex_secret, sizeof(kex_secret)); OPENSSL_cleanse(sign_secret, sizeof(sign_secret)); size_t len = 32;
    if (!kex || !signer || EVP_PKEY_get_raw_public_key(kex, kex_pub, &len) != 1 || len != 32) goto cleanup;
    len = 32; if (EVP_PKEY_get_raw_public_key(signer, sign_pub, &len) != 1 || len != 32) goto cleanup;
    memcpy(cat, kex_pub, 32); memcpy(cat+32, sign_pub, 32); char digest[65], router[48], nonce[65], signed_message[256], kex64[45], pub64[45], sig64[89];
    digest_hex(cat, sizeof(cat), digest); snprintf(router, sizeof(router), "router-%.32s", digest); if (random_id(nonce, "")) goto cleanup;
    payload = json_object_new_object(); txt(payload, "subject", subject); txt(payload, "method", method); txt(payload, "path", path);
    json_object_object_add(payload, "query", query ? copy(query) : json_object_new_object()); json_object_object_add(payload, "body", body ? copy(body) : json_object_new_object());
    const char *raw = json_object_to_json_string_ext(payload, JSON_C_TO_STRING_PLAIN); digest_hex(raw, strlen(raw), digest); long long now = (long long)time(NULL);
    int signed_len = snprintf(signed_message, sizeof(signed_message), "%s\n%s\n%lld\n%s\n%s", config->proof_domain[0] ? config->proof_domain : "dreamingos-support-v1", router, now, nonce, digest);
    sign_ctx = EVP_MD_CTX_new(); size_t sig_len = sizeof(signature);
    if (!sign_ctx || EVP_DigestSignInit(sign_ctx, NULL, NULL, NULL, signer) != 1 || EVP_DigestSign(sign_ctx, signature, &sig_len, (unsigned char *)signed_message, (size_t)signed_len) != 1) goto cleanup;
    EVP_EncodeBlock((unsigned char *)kex64, kex_pub, 32); EVP_EncodeBlock((unsigned char *)pub64, sign_pub, 32); EVP_EncodeBlock((unsigned char *)sig64, signature, 64);
    envelope = json_object_new_object(); integer(envelope, "version", 1); txt(envelope, "kex_pub", kex64); txt(envelope, "sign_pub", pub64); integer(envelope, "timestamp", now);
    txt(envelope, "nonce", nonce); txt(envelope, "payload", raw); txt(envelope, "signature", sig64);
    curl = curl_easy_init(); if (!curl) goto cleanup;
    headers = curl_slist_append(headers, "Content-Type: application/json"); headers = curl_slist_append(headers, "Expect:");
    curl_easy_setopt(curl, CURLOPT_URL, config->url); curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_object_to_json_string_ext(envelope, JSON_C_TO_STRING_PLAIN));
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L); curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L); curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    #ifdef SUPPORT_TEST
    const char *test_ca = getenv("SUPPORT_TEST_CA");
    if (test_ca && test_ca[0]) curl_easy_setopt(curl, CURLOPT_CAINFO, test_ca);
#endif
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L); curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L); curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive); curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    failure = "cloud_result_unknown"; message = "云端结果待确认，将使用原请求标识重试";
    if (curl_easy_perform(curl) != CURLE_OK) goto cleanup;
    long http = 0; curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http);
    struct json_object *parsed = response.bytes ? json_tokener_parse(response.bytes) : NULL;
    if (!parsed || !get(parsed, "ok") || json_object_get_boolean(get(parsed, "ok")) != (http >= 200 && http < 300) ||
        (http >= 200 && http < 300 && !json_object_is_type(get(parsed, "data"), json_type_object))) {
        json_object_put(parsed); failure = "cloud_invalid_response"; message = "云工单返回了无效回执"; goto cleanup;
    }
    result_status = (int)http; result = parsed;
cleanup:
    OPENSSL_cleanse(kex_secret, sizeof(kex_secret)); OPENSSL_cleanse(sign_secret, sizeof(sign_secret));
    EVP_PKEY_free(kex); EVP_PKEY_free(signer); EVP_MD_CTX_free(sign_ctx); curl_slist_free_all(headers); curl_easy_cleanup(curl);
    json_object_put(envelope); json_object_put(payload); free(response.bytes);
    if (!result) result = error(&result_status, 503, failure, message);
    *status = result_status; return result;
}
static void sync_error(sqlite3 *db, const char *table, const char *id, struct json_object *response, int status, int attempts, int refreshing)
{
    const char *code = str(get(response, "error"), "code"); if (!*code) code = str(response, "error_code");
    int retry = status == 401 || status == 408 || status == 429 || status >= 500;
    long long next = retry ? (long long)time(NULL) + (attempts > 7 ? 300 : (2LL << attempts)) : -1;
    if (status == 429 && next < (long long)time(NULL)+60) next = (long long)time(NULL)+60;
    char sql[320]; snprintf(sql, sizeof(sql), "UPDATE %s SET error=?,state=?,attempts=attempts+1,next_attempt=?%s WHERE id=?", table, refreshing ? ",synced_at=strftime('%s','now')" : "");
    sqlite3_stmt *q = prepare(db, sql); if (!q) return;
    sql_bind(q, 1, *code ? code : "cloud_result_unknown"); sql_bind(q, 2, refreshing ? (status == 410 ? "deleted" : "submitted") : "failed");
    sqlite3_bind_int64(q, 3, next); sql_bind(q, 4, id); done(q);
}
int support_sync_step(const struct support_config *config)
{
    if (!config->url[0]) return 0;
    char lockpath[600]; snprintf(lockpath, sizeof(lockpath), "%s.sync-lock", config->db_path);
    int lock = open(lockpath, O_CREAT | O_RDWR | O_CLOEXEC, 0600); struct flock fl = { .l_type = F_WRLCK, .l_whence = SEEK_SET };
    if (lock < 0 || fcntl(lock, F_SETLK, &fl)) { if (lock >= 0) close(lock); return 0; }
    sqlite3 *db = NULL; if (support_db_open(config->db_path, &db)) { close(lock); return -1; }
    const char *sql = "SELECT id,subject,payload,attempts FROM feedback WHERE state IN ('queued','submitting','failed') AND next_attempt>=0 AND next_attempt<=? ORDER BY rowid LIMIT 1";
    sqlite3_stmt *q = prepare(db, sql); int worked = 0;
    if (!q) goto finished;
    sqlite3_bind_int64(q, 1, time(NULL));
    if (sqlite3_step(q) == SQLITE_ROW) {
        char id[65], subject[129]; snprintf(id, sizeof(id), "%s", column(q, 0)); snprintf(subject, sizeof(subject), "%s", column(q, 1));
        struct json_object *body = json_tokener_parse(column(q, 2)); int attempts = sqlite3_column_int(q, 3); sqlite3_finalize(q);
        q = prepare(db, "UPDATE feedback SET state='submitting',next_attempt=? WHERE id=?");
        if (!q) { json_object_put(body); goto finished; } sqlite3_bind_int64(q, 1, (long long)time(NULL)+45); sql_bind(q, 2, id);
        if (done(q)) { json_object_put(body); goto finished; }
        int status = 503; struct json_object *response = support_remote(config, subject, "POST", "", NULL, body, &status), *data = get(response, "data");
        const char *cloud_id = str(data, "id");
        if (status == 200 && !strncmp(cloud_id, "ticket-", 7) && strlen(cloud_id) == 39 && !strcmp(str(data, "request_id"), str(body, "request_id"))) {
            q = prepare(db, "UPDATE feedback SET state='submitted',cloud_id=?,cloud_json=?,error='',attempts=0,next_attempt=0,synced_at=? WHERE id=?");
            if (q) { sql_bind(q, 1, cloud_id); sql_bind(q, 2, json_object_to_json_string_ext(data, JSON_C_TO_STRING_PLAIN)); sqlite3_bind_int64(q, 3, time(NULL)); sql_bind(q, 4, id); done(q); }
        } else sync_error(db, "feedback", id, response, status == 200 ? 503 : status, attempts, 0);
        json_object_put(response); json_object_put(body); worked = 1; goto finished;
    }
    sqlite3_finalize(q);
    q = prepare(db, "SELECT o.id,o.ticket_id,o.subject,o.kind,o.payload,o.attempts,f.cloud_id FROM support_outbox o JOIN feedback f ON f.id=o.ticket_id"
        " WHERE o.state IN ('queued','submitting','failed') AND o.next_attempt>=0 AND o.next_attempt<=? AND f.state='submitted' ORDER BY o.rowid LIMIT 1");
    if (!q) goto finished; sqlite3_bind_int64(q, 1, time(NULL));
    if (sqlite3_step(q) == SQLITE_ROW) {
        char id[65], ticket_id[65], subject[129], kind[16], cloud_id[65], path[100];
        snprintf(id, sizeof(id), "%s", column(q, 0)); snprintf(ticket_id, sizeof(ticket_id), "%s", column(q, 1)); snprintf(subject, sizeof(subject), "%s", column(q, 2));
        snprintf(kind, sizeof(kind), "%s", column(q, 3)); struct json_object *body = json_tokener_parse(column(q, 4)); int attempts = sqlite3_column_int(q, 5);
        snprintf(cloud_id, sizeof(cloud_id), "%s", column(q, 6)); snprintf(path, sizeof(path), "%s/%s", cloud_id, kind); sqlite3_finalize(q);
        q = prepare(db, "UPDATE support_outbox SET state='submitting',next_attempt=? WHERE id=?");
        if (!q) { json_object_put(body); goto finished; } sqlite3_bind_int64(q, 1, (long long)time(NULL)+45); sql_bind(q, 2, id);
        if (done(q)) { json_object_put(body); goto finished; }
        int status = 503; struct json_object *response = support_remote(config, subject, "POST", path, NULL, body, &status), *data = get(response, "data");
        if (status == 200 && !strcmp(str(data, "id"), cloud_id)) {
            if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK) {
                int valid = 1;
                if (!strcmp(kind, "comments")) {
                    q = prepare(db, "UPDATE feedback SET cloud_json=?,error='',synced_at=? WHERE id=?");
                    if (!q) valid = 0;
                    else { sql_bind(q, 1, json_object_to_json_string_ext(data, JSON_C_TO_STRING_PLAIN)); sqlite3_bind_int64(q, 2, time(NULL)); sql_bind(q, 3, ticket_id); if (done(q)) valid = 0; }
                }
                q = prepare(db, "UPDATE support_outbox SET state='submitted',error='',attempts=0,next_attempt=0 WHERE id=?");
                if (!q) valid = 0; else { sql_bind(q, 1, id); if (done(q)) valid = 0; }
                sqlite3_exec(db, valid ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
            }
        } else sync_error(db, "support_outbox", id, response, status == 200 ? 503 : status, attempts, 0);
        json_object_put(response); json_object_put(body); worked = 1; goto finished;
    }
    sqlite3_finalize(q);
    q = prepare(db, "SELECT id,subject,cloud_id FROM feedback WHERE state='submitted' AND synced_at<? ORDER BY synced_at,id LIMIT 1");
    if (!q) goto finished; sqlite3_bind_int64(q, 1, (long long)time(NULL)-30);
    if (sqlite3_step(q) == SQLITE_ROW) {
        char id[65], subject[129], cloud_id[65]; snprintf(id, sizeof(id), "%s", column(q, 0)); snprintf(subject, sizeof(subject), "%s", column(q, 1)); snprintf(cloud_id, sizeof(cloud_id), "%s", column(q, 2));
        sqlite3_finalize(q); int status = 503;
        struct json_object *response = support_remote(config, subject, "GET", cloud_id, NULL, NULL, &status), *data = get(response, "data");
        if (status == 200 && !strcmp(str(data, "id"), cloud_id)) {
            q = prepare(db, "UPDATE feedback SET cloud_json=?,error='',synced_at=? WHERE id=?");
            if (q) { sql_bind(q, 1, json_object_to_json_string_ext(data, JSON_C_TO_STRING_PLAIN)); sqlite3_bind_int64(q, 2, time(NULL)); sql_bind(q, 3, id); done(q); }
        } else sync_error(db, "feedback", id, response, status == 200 ? 503 : status, 0, 1);
        json_object_put(response); worked = 1;
    } else sqlite3_finalize(q);
finished:
    sqlite3_close(db); close(lock); return worked;
}

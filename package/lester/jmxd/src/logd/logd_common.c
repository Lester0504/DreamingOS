// SPDX-License-Identifier: GPL-2.0-or-later
#include "logd_internal.h"

sqlite3 *g_logd_db;
sqlite3 *g_config_db;
struct ubus_context *g_logd_ubus;
struct blob_buf g_logd_blob;
uint64_t g_event_seq;
uint64_t g_logd_storage_suppressed;
int64_t g_logd_storage_last_suppressed_at;

int64_t logd_now_s(void)
{
    return (int64_t)time(NULL);
}

const char *logd_json_str(struct json_object *o, const char *key, const char *def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    if (!json_object_is_type(v, json_type_string))
        return def;
    return json_object_get_string(v) ? json_object_get_string(v) : def;
}

int64_t logd_json_i64(struct json_object *o, const char *key, int64_t def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    return json_object_get_int64(v);
}

int logd_json_int(struct json_object *o, const char *key, int def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    return json_object_get_int(v);
}

int logd_json_bool(struct json_object *o, const char *key, int def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    return json_object_get_boolean(v) ? 1 : 0;
}

struct json_object *logd_json_parse_or_object(const char *s)
{
    struct json_object *o = NULL;

    if (s && s[0])
        o = json_tokener_parse(s);
    if (!o || !json_object_is_type(o, json_type_object)) {
        if (o)
            json_object_put(o);
        return json_object_new_object();
    }
    return o;
}

const char *logd_sqlite_text(sqlite3_stmt *st, int col, const char *def)
{
    const unsigned char *s;

    if (!st)
        return def;
    s = sqlite3_column_text(st, col);
    return s ? (const char *)s : def;
}

struct json_object *logd_json_from_blob(struct blob_attr *msg)
{
    char *s;
    struct json_object *o = NULL;

    if (!msg)
        return json_object_new_object();
    s = blobmsg_format_json(msg, true);
    if (s) {
        o = json_tokener_parse(s);
        free(s);
    }
    return o ? o : json_object_new_object();
}

struct json_object *logd_payload_or_self(struct json_object *body)
{
    struct json_object *payload = NULL;

    if (body && json_object_object_get_ex(body, "payload", &payload) && payload &&
        json_object_is_type(payload, json_type_object))
        return payload;
    return body;
}

int logd_file_read_line(const char *path, char *out, size_t out_len)
{
    FILE *fp;
    size_t n;

    if (!path || !out || out_len == 0)
        return -1;
    out[0] = 0;
    fp = fopen(path, "r");
    if (!fp)
        return -1;
    if (!fgets(out, out_len, fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    n = strlen(out);
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r' || out[n - 1] == ' ' || out[n - 1] == '\t'))
        out[--n] = 0;
    return 0;
}

int logd_file_read_int(const char *path, int def)
{
    char buf[64];

    if (logd_file_read_line(path, buf, sizeof(buf)) != 0 || !buf[0])
        return def;
    return atoi(buf);
}

int logd_file_exists(const char *path)
{
    struct stat st;

    return path && stat(path, &st) == 0;
}

void logd_runtime_note(struct logd_collector_runtime *rt, int ok, const char *err)
{
    if (!rt)
        return;
    rt->last_run = logd_now_s();
    rt->runs++;
    if (ok) {
        rt->last_ok = rt->last_run;
        rt->last_error[0] = 0;
    } else {
        rt->errors++;
        snprintf(rt->last_error, sizeof(rt->last_error), "%s", err && err[0] ? err : "collector_failed");
    }
}

uint64_t logd_hash64(const char *s)
{
    uint64_t h = 1469598103934665603ULL;
    const unsigned char *p = (const unsigned char *)s;

    if (!s)
        return h;
    while (*p) {
        h ^= (uint64_t)*p++;
        h *= 1099511628211ULL;
    }
    return h;
}

void logd_hash_hex(const char *s, char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return;
    snprintf(out, out_len, "%016" PRIx64, logd_hash64(s));
}

int logd_text_ok(const char *s, size_t max_len)
{
    const unsigned char *p;

    if (!s)
        return 1;
    if (strlen(s) > max_len)
        return 0;
    for (p = (const unsigned char *)s; *p; p++) {
        if (*p < 0x20 && *p != '\t')
            return 0;
        if (*p == 0x7f)
            return 0;
    }
    return 1;
}

int logd_token_ok(const char *s, size_t max_len)
{
    const unsigned char *p;

    if (!s || !s[0] || strlen(s) > max_len)
        return 0;
    for (p = (const unsigned char *)s; *p; p++) {
        if (!(isalnum(*p) || *p == '_' || *p == '-' || *p == '.' || *p == ':' || *p == '/'))
            return 0;
    }
    return 1;
}

const char *logd_severity(const char *s)
{
    if (!s || !s[0]) return "info";
    if (!strcmp(s, "debug") || !strcmp(s, "info") || !strcmp(s, "notice") ||
        !strcmp(s, "warning") || !strcmp(s, "error") || !strcmp(s, "critical"))
        return s;
    return "info";
}

int logd_contains_ci(const char *s, const char *needle)
{
    size_t nlen;
    const char *p;

    if (!s || !needle || !needle[0])
        return 0;
    nlen = strlen(needle);
    for (p = s; *p; p++) {
        if (strncasecmp(p, needle, nlen) == 0)
            return 1;
    }
    return 0;
}

void logd_sanitize_line(char *s)
{
    unsigned char *p;

    if (!s)
        return;
    for (p = (unsigned char *)s; *p; p++) {
        if (*p < 0x20 && *p != '\t')
            *p = ' ';
        else if (*p == 0x7f)
            *p = ' ';
    }
}

void logd_title_from_line(const char *line, char *out, size_t out_len)
{
    size_t n;

    if (!out || out_len == 0)
        return;
    snprintf(out, out_len, "%s", line ? line : "");
    n = strlen(out);
    if (n > 180) {
        out[177] = '.';
        out[178] = '.';
        out[179] = '.';
        out[180] = 0;
    }
}

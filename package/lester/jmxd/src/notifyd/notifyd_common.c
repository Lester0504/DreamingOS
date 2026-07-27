// SPDX-License-Identifier: GPL-2.0-or-later
#include "notifyd_internal.h"

sqlite3 *g_notify_db;
sqlite3 *g_notify_config_db;
struct ubus_context *g_notify_ubus;
struct blob_buf g_notify_blob;
uint64_t g_notify_seq;
uint64_t g_notify_storage_suppressed;
int64_t g_notify_storage_last_suppressed_at;

int64_t notifyd_now_s(void)
{
    return (int64_t)time(NULL);
}

void notifyd_make_id(const char *prefix, char *out, size_t out_len)
{
    struct timeval tv;

    if (!out || out_len == 0)
        return;
    gettimeofday(&tv, NULL);
    snprintf(out, out_len, "%s-%lld-%06ld-%llu-%u",
             prefix && prefix[0] ? prefix : "id",
             (long long)tv.tv_sec, (long)tv.tv_usec,
             (unsigned long long)++g_notify_seq, (unsigned)getpid());
}

const char *notifyd_json_str(struct json_object *o, const char *key, const char *def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    if (!json_object_is_type(v, json_type_string))
        return def;
    return json_object_get_string(v) ? json_object_get_string(v) : def;
}

int notifyd_json_int(struct json_object *o, const char *key, int def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    return json_object_get_int(v);
}

int64_t notifyd_json_i64(struct json_object *o, const char *key, int64_t def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    return json_object_get_int64(v);
}

int notifyd_json_bool(struct json_object *o, const char *key, int def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    return json_object_get_boolean(v) ? 1 : 0;
}

struct json_object *notifyd_json_parse_or_object(const char *s)
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

const char *notifyd_sqlite_text(sqlite3_stmt *st, int col, const char *def)
{
    const unsigned char *s;

    if (!st)
        return def;
    s = sqlite3_column_text(st, col);
    return s ? (const char *)s : def;
}

struct json_object *notifyd_json_from_blob(struct blob_attr *msg)
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

struct json_object *notifyd_payload_or_self(struct json_object *body)
{
    struct json_object *payload = NULL;

    if (body && json_object_object_get_ex(body, "payload", &payload) && payload &&
        json_object_is_type(payload, json_type_object))
        return payload;
    return body;
}

int notifyd_text_ok(const char *s, size_t max_len)
{
    const unsigned char *p;

    if (!s)
        return 1;
    if (strlen(s) > max_len)
        return 0;
    for (p = (const unsigned char *)s; *p; p++) {
        if (*p < 0x20 && *p != '\t' && *p != '\n' && *p != '\r')
            return 0;
    }
    return 1;
}

int notifyd_token_ok(const char *s, size_t max_len)
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

int notifyd_id_ok(const char *s)
{
    return notifyd_token_ok(s, NOTIFYD_MAX_ID - 1);
}

int notifyd_url_ok(const char *s)
{
    const unsigned char *p;

    if (!s || !s[0] || strlen(s) > 2048)
        return 0;
    if (strncmp(s, "https://", 8) && strncmp(s, "http://", 7))
        return 0;
    for (p = (const unsigned char *)s; *p; p++) {
        if (*p <= 0x20 || *p == 0x7f)
            return 0;
    }
    return 1;
}

int notifyd_json_fits(struct json_object *o, size_t max_len)
{
    const char *s = o ? json_object_to_json_string(o) : "{}";

    return s && strlen(s) <= max_len;
}

const char *notifyd_severity(const char *s)
{
    if (!s || !s[0]) return "info";
    if (!strcmp(s, "debug") || !strcmp(s, "info") || !strcmp(s, "notice") ||
        !strcmp(s, "warning") || !strcmp(s, "error") || !strcmp(s, "critical"))
        return s;
    return "info";
}

int notifyd_severity_rank(const char *s)
{
    s = notifyd_severity(s);
    if (!strcmp(s, "debug")) return 0;
    if (!strcmp(s, "info")) return 1;
    if (!strcmp(s, "notice")) return 2;
    if (!strcmp(s, "warning")) return 3;
    if (!strcmp(s, "error")) return 4;
    if (!strcmp(s, "critical")) return 5;
    return 1;
}

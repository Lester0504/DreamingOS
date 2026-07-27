// SPDX-License-Identifier: GPL-2.0-or-later
#include "aegisxd_internal.h"

sqlite3 *g_aegisxd_config_db;
sqlite3 *g_aegisxd_db;
struct ubus_context *g_aegisxd_ubus;
struct blob_buf g_aegisxd_blob;

int64_t aegisxd_now_s(void)
{
    return (int64_t)time(NULL);
}

int aegisxd_mkdir_p(const char *path, mode_t mode)
{
    char buf[AEGISXD_MAX_PATH];
    char *p;

    if (!path || path[0] != '/' || strlen(path) >= sizeof(buf))
        return -1;
    snprintf(buf, sizeof(buf), "%s", path);
    for (p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, mode) != 0 && errno != EEXIST)
            return -1;
        *p = '/';
    }
    if (mkdir(buf, mode) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

void aegisxd_json_add_string(struct json_object *o, const char *key, const char *value)
{
    if (!o || !key)
        return;
    json_object_object_add(o, key, json_object_new_string(value ? value : ""));
}

const char *aegisxd_json_str(struct json_object *o, const char *key, const char *def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    if (!json_object_is_type(v, json_type_string))
        return def;
    return json_object_get_string(v) ? json_object_get_string(v) : def;
}

int aegisxd_json_bool(struct json_object *o, const char *key, int def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    return json_object_get_boolean(v) ? 1 : 0;
}

struct json_object *aegisxd_error(const char *code, const char *message)
{
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "ok", json_object_new_boolean(0));
    aegisxd_json_add_string(o, "service", "dreamingwrt-aegisxd");
    aegisxd_json_add_string(o, "error", code ? code : "error");
    aegisxd_json_add_string(o, "message", message ? message : "");
    return o;
}

struct json_object *aegisxd_safe_not_implemented(const char *op)
{
    struct json_object *o = aegisxd_error("not_implemented",
        "aegisxd control-plane contract exists, but this operation is not implemented yet");

    aegisxd_json_add_string(o, "operation", op ? op : "");
    json_object_object_add(o, "changed", json_object_new_boolean(0));
    json_object_object_add(o, "dataplane_changed", json_object_new_boolean(0));
    return o;
}

struct json_object *aegisxd_json_from_blob(struct blob_attr *msg)
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

struct json_object *aegisxd_payload_or_self(struct json_object *body)
{
    struct json_object *payload = NULL;

    if (body && json_object_object_get_ex(body, "payload", &payload) && payload &&
        json_object_is_type(payload, json_type_object))
        return payload;
    return body;
}

const char *aegisxd_sqlite_text(sqlite3_stmt *st, int col, const char *def)
{
    const unsigned char *s;

    if (!st)
        return def;
    s = sqlite3_column_text(st, col);
    return s ? (const char *)s : def;
}

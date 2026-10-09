// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * json-c accessors and small object/array builders.
 *
 * Nothing here talks to ubus, the database or the request; these are pure shape
 * helpers, which is why they can move first. app_nc_json_str() alone has ~1,700
 * call sites in the dispatch file, so these declarations are what make every
 * later phase possible rather than an aesthetic tidy-up.
 */
#include <stdint.h>
#include <string.h>
#include <json-c/json.h>
#include <sqlite3.h>

#include "api_json.h"
#include "api_error.h"

/* Local JSON helpers (nc_json_* are static in netconfig_db.c) */
const char *app_nc_json_str(struct json_object *o, const char *k, const char *def)
{
    struct json_object *v = NULL;
    if (!o || !json_object_object_get_ex(o, k, &v) || !v) return def;
    const char *s = json_object_get_string(v);
    return s ? s : def;
}

int app_nc_json_int(struct json_object *o, const char *k, int def)
{
    struct json_object *v = NULL;
    if (!o || !json_object_object_get_ex(o, k, &v) || !v) return def;
    return json_object_get_int(v);
}

int64_t app_nc_json_int64(struct json_object *o, const char *k, int64_t def)
{
    struct json_object *v = NULL;
    if (!o || !json_object_object_get_ex(o, k, &v) || !v) return def;
    return json_object_get_int64(v);
}

double app_nc_json_double(struct json_object *o, const char *k, double def)
{
    struct json_object *v = NULL;
    if (!o || !json_object_object_get_ex(o, k, &v) || !v) return def;
    return json_object_get_double(v);
}

int app_nc_json_bool(struct json_object *o, const char *k, int def)
{
    struct json_object *v = NULL;
    if (!o || !json_object_object_get_ex(o, k, &v) || !v) return def;
    return json_object_get_boolean(v);
}

int app_nc_json_has(struct json_object *o, const char *k)
{
    struct json_object *v = NULL;
    return o && k && json_object_object_get_ex(o, k, &v) && v;
}

struct json_object *webd_obj_child(struct json_object *obj, const char *key)
{
    struct json_object *v = NULL;

    if (!obj || !key || !json_object_object_get_ex(obj, key, &v) || !v)
        return NULL;
    return v;
}

struct json_object *webd_obj_child_obj(struct json_object *obj, const char *key)
{
    struct json_object *v = webd_obj_child(obj, key);

    return (v && json_object_is_type(v, json_type_object)) ? v : NULL;
}

struct json_object *webd_obj_child_array(struct json_object *obj, const char *key)
{
    struct json_object *v = webd_obj_child(obj, key);

    return (v && json_object_is_type(v, json_type_array)) ? v : NULL;
}

void webd_obj_add_str(struct json_object *obj, const char *key, const char *value)
{
    json_object_object_add(obj, key, json_object_new_string(value ? value : ""));
}

const char *webd_sql_text(sqlite3_stmt *st, int col)
{
    const unsigned char *s = sqlite3_column_text(st, col);

    return s ? (const char *)s : "";
}

int64_t webd_json_inc_int64(struct json_object *obj, const char *key, int64_t delta)
{
    int64_t v;

    if (!obj || !key)
        return delta;
    v = app_nc_json_int64(obj, key, 0) + delta;
    json_object_object_add(obj, key, json_object_new_int64(v));
    return v;
}

struct json_object *app_json_id_param(const char *id)
{
    struct json_object *params = json_object_new_object();

    json_object_object_add(params, "id", json_object_new_string(id ? id : ""));
    return params;
}

struct json_object *app_json_id_payload(const char *id, struct json_object *payload)
{
    struct json_object *params = json_object_new_object();

    if (payload && json_object_is_type(payload, json_type_object)) {
        json_object_object_foreach(payload, key, val) {
            json_object_object_add(params, key, json_object_get(val));
        }
    }
    json_object_object_add(params, "id", json_object_new_string(id ? id : ""));
    return params;
}

struct json_object *app_json_id_action_payload(const char *id, const char *action,
                                                      struct json_object *payload)
{
    struct json_object *params = app_json_id_payload(id, payload);

    json_object_object_add(params, "action", json_object_new_string(action ? action : ""));
    return params;
}

void webd_copy_field_if_present(struct json_object *dst, struct json_object *src,
                                       const char *key)
{
    struct json_object *value = NULL;

    if (!dst || !src || !key || !key[0])
        return;
    if (json_object_object_get_ex(src, key, &value) && value)
        json_object_object_add(dst, key, json_object_get(value));
}

struct json_object *webd_json_clone(struct json_object *src)
{
    const char *s;

    if (!src)
        return NULL;
    s = json_object_to_json_string_ext(src, JSON_C_TO_STRING_PLAIN);
    if (!s)
        return NULL;
    return json_tokener_parse(s);
}

void webd_json_copy_key(struct json_object *dst, const char *dst_key,
                               struct json_object *src, const char *src_key)
{
    struct json_object *v = NULL;

    if (!dst || !dst_key || !src || !src_key)
        return;
    if (json_object_object_get_ex(src, src_key, &v) && v)
        json_object_object_add(dst, dst_key, json_object_get(v));
}

int webd_json_array_contains_int_value(struct json_object *arr, int value)
{
    int i, n;

    if (!arr || !json_object_is_type(arr, json_type_array))
        return 0;
    n = json_object_array_length(arr);
    if (n == 0)
        return 0;
    for (i = 0; i < n; i++) {
        if (json_object_get_int(json_object_array_get_idx(arr, i)) == value)
            return 1;
    }
    return 0;
}

int webd_json_array_contains_string_value(struct json_object *arr, const char *value)
{
    int i, n;

    if (!arr || !json_object_is_type(arr, json_type_array) || !value || !value[0])
        return 0;
    n = json_object_array_length(arr);
    if (n == 0)
        return 0;
    for (i = 0; i < n; i++) {
        const char *cur = json_object_get_string(json_object_array_get_idx(arr, i));
        if (cur && !strcmp(cur, value))
            return 1;
    }
    return 0;
}

struct json_object *webd_data_from_jmx_response(struct json_object *resp)
{
    struct json_object *code_obj = NULL;
    struct json_object *data_obj = NULL;

    if (!resp)
        return NULL;
    if (json_object_object_get_ex(resp, "code", &code_obj) && code_obj &&
        json_object_get_int(code_obj) != APP_API_CODE_SUCCESS)
        return NULL;
    if (!json_object_object_get_ex(resp, "data", &data_obj) || !data_obj)
        return NULL;
    return json_object_get(data_obj);
}

struct json_object *webd_data_or_self_from_jmx_response(struct json_object *resp)
{
    struct json_object *code_obj = NULL;
    struct json_object *data_obj = NULL;

    if (!resp)
        return NULL;
    if (json_object_object_get_ex(resp, "code", &code_obj) && code_obj &&
        json_object_get_int(code_obj) != APP_API_CODE_SUCCESS)
        return NULL;
    if (json_object_object_get_ex(resp, "data", &data_obj) && data_obj)
        return json_object_get(data_obj);
    return json_object_get(resp);
}

struct json_object *webd_json_array_from_text(const char *text)
{
    struct json_object *value = NULL;

    if (text && text[0])
        value = json_tokener_parse(text);
    if (!value || !json_object_is_type(value, json_type_array)) {
        if (value)
            json_object_put(value);
        value = json_object_new_array();
    }
    return value;
}

int webd_json_bool_field(struct json_object *obj, const char *key, int *out)
{
    struct json_object *v = NULL;

    if (!obj || !key || !json_object_object_get_ex(obj, key, &v) || !v)
        return 0;
    if (out)
        *out = json_object_get_boolean(v) ? 1 : 0;
    return 1;
}

void webd_json_array_add_unique_string(struct json_object *arr, const char *s)
{
    int i, n;

    if (!arr || !s || !s[0] || !json_object_is_type(arr, json_type_array))
        return;
    n = json_object_array_length(arr);
    for (i = 0; i < n; i++) {
        struct json_object *v = json_object_array_get_idx(arr, i);
        const char *old = v ? json_object_get_string(v) : NULL;
        if (old && !strcmp(old, s))
            return;
    }
    json_object_array_add(arr, json_object_new_string(s));
}

void webd_json_array_remove_string(struct json_object *arr, const char *s)
{
    int i;

    if (!arr || !s || !json_object_is_type(arr, json_type_array))
        return;
    for (i = (int)json_object_array_length(arr) - 1; i >= 0; i--) {
        struct json_object *v = json_object_array_get_idx(arr, i);
        const char *old = v ? json_object_get_string(v) : NULL;

        if (old && !strcmp(old, s))
            json_object_array_del_idx(arr, i, 1);
    }
}

int64_t webd_json_i64_def(struct json_object *o, const char *k, int64_t def)
{
    struct json_object *v = NULL;

    if (!o || !json_object_object_get_ex(o, k, &v) || !v)
        return def;
    return json_object_get_int64(v);
}

int webd_json_add_double_if_present(struct json_object *dst, const char *out_key,
                                           struct json_object *src, const char *in_key)
{
    struct json_object *v = NULL;

    if (!dst || !out_key || !src || !in_key)
        return 0;
    if (!json_object_object_get_ex(src, in_key, &v) || !v)
        return 0;
    json_object_object_add(dst, out_key, json_object_new_double(json_object_get_double(v)));
    return 1;
}

// SPDX-License-Identifier: GPL-2.0-or-later
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
#ifndef WEBD_API_JSON_H
#define WEBD_API_JSON_H

#include <stdint.h>
#include <json-c/json.h>
#include <sqlite3.h>

const char *app_nc_json_str(struct json_object *o, const char *k, const char *def);
int app_nc_json_int(struct json_object *o, const char *k, int def);
int64_t app_nc_json_int64(struct json_object *o, const char *k, int64_t def);
double app_nc_json_double(struct json_object *o, const char *k, double def);
int app_nc_json_bool(struct json_object *o, const char *k, int def);
int app_nc_json_has(struct json_object *o, const char *k);
struct json_object *webd_obj_child(struct json_object *obj, const char *key);
struct json_object *webd_obj_child_obj(struct json_object *obj, const char *key);
struct json_object *webd_obj_child_array(struct json_object *obj, const char *key);
void webd_obj_add_str(struct json_object *obj, const char *key, const char *value);
const char *webd_sql_text(sqlite3_stmt *st, int col);
int64_t webd_json_inc_int64(struct json_object *obj, const char *key, int64_t delta);
struct json_object *app_json_id_param(const char *id);
struct json_object *app_json_id_payload(const char *id, struct json_object *payload);
struct json_object *app_json_id_action_payload(const char *id, const char *action,
                                                      struct json_object *payload);
void webd_copy_field_if_present(struct json_object *dst, struct json_object *src,
                                       const char *key);
struct json_object *webd_json_clone(struct json_object *src);
void webd_json_copy_key(struct json_object *dst, const char *dst_key,
                               struct json_object *src, const char *src_key);
int webd_json_array_contains_int_value(struct json_object *arr, int value);
int webd_json_array_contains_string_value(struct json_object *arr, const char *value);
struct json_object *webd_data_from_jmx_response(struct json_object *resp);
struct json_object *webd_data_or_self_from_jmx_response(struct json_object *resp);
struct json_object *webd_json_array_from_text(const char *text);
int webd_json_bool_field(struct json_object *obj, const char *key, int *out);
void webd_json_array_add_unique_string(struct json_object *arr, const char *s);
void webd_json_array_remove_string(struct json_object *arr, const char *s);
int64_t webd_json_i64_def(struct json_object *o, const char *k, int64_t def);
int webd_json_add_double_if_present(struct json_object *dst, const char *out_key,
                                           struct json_object *src, const char *in_key);

#endif /* WEBD_API_JSON_H */

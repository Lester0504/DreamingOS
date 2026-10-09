/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef AP_CONTROL_LOG_H
#define AP_CONTROL_LOG_H
#include <json-c/json.h>
#include <stdint.h>
#include <string.h>
#define AP_LOG_QUEUE_LIMIT 256
#define AP_LOG_BATCH_LIMIT 4
#define AP_LOG_EVENT_MAX 12288
#define AP_LOG_CAPABILITY "ap_logs_v1"

static inline int ap_log_string(struct json_object *o, const char *key,
                                size_t min, size_t max)
{
    struct json_object *v = NULL;
    const char *s;
    if (!json_object_object_get_ex(o, key, &v) ||
        !json_object_is_type(v, json_type_string)) return 0;
    s = json_object_get_string(v);
    return s && strlen(s) == (size_t)json_object_get_string_len(v) &&
        strlen(s) >= min && strlen(s) <= max;
}
static inline int ap_log_id_valid(const char *id)
{
    return id && strlen(id) == 32 && strspn(id, "0123456789abcdef") == 32;
}
static inline int ap_log_event_valid(struct json_object *e)
{
    struct json_object *ts = NULL;
    const char *level;
    if (!e || !json_object_is_type(e, json_type_object) ||
        json_object_object_length(e) != 8 ||
        !ap_log_string(e, "id", 32, 32) ||
        !ap_log_id_valid(json_object_get_string(json_object_object_get(e, "id"))) ||
        !ap_log_string(e, "severity", 4, 8) ||
        !ap_log_string(e, "category", 1, 63) ||
        !ap_log_string(e, "event", 1, 127) ||
        !ap_log_string(e, "source", 0, 127) ||
        !ap_log_string(e, "title", 0, 511) ||
        !ap_log_string(e, "detail_json", 0, 8191) ||
        !json_object_object_get_ex(e, "ts", &ts) ||
        !json_object_is_type(ts, json_type_int) || json_object_get_int64(ts) <= 0 ||
        strlen(json_object_to_json_string_ext(e, JSON_C_TO_STRING_PLAIN)) > AP_LOG_EVENT_MAX)
        return 0;
    level = json_object_get_string(json_object_object_get(e, "severity"));
    return !strcmp(level, "debug") || !strcmp(level, "info") ||
        !strcmp(level, "notice") || !strcmp(level, "warning") ||
        !strcmp(level, "error") || !strcmp(level, "critical");
}
static inline int ap_log_batch_valid(struct json_object *events)
{
    size_t i, n;
    if (!events || !json_object_is_type(events, json_type_array)) return 0;
    n = json_object_array_length(events);
    if (!n || n > AP_LOG_BATCH_LIMIT) return 0;
    for (i = 0; i < n; i++)
        if (!ap_log_event_valid(json_object_array_get_idx(events, i))) return 0;
    return 1;
}
static inline struct json_object *ap_log_result(int ok, const char *error)
{
    struct json_object *r = json_object_new_object();
    json_object_object_add(r, "ok", json_object_new_boolean(ok));
    json_object_object_add(r, "persisted", json_object_new_boolean(ok));
    if (error) json_object_object_add(r, "error", json_object_new_string(error));
    return r;
}
#endif

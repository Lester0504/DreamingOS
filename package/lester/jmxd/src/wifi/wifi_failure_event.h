/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef DW_WIFI_FAILURE_EVENT_H
#define DW_WIFI_FAILURE_EVENT_H
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <json-c/json.h>

/* Only identifiers leave the failing operation. No request object, message,
 * credentials or free-form daemon diagnostic is accepted by this builder. */
static inline const char *dw_wifi_failure_token(const char *value, const char *fallback)
{
    if (!value || !value[0] || strlen(value) > 64) return fallback;
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p)
        if (!isalnum(*p) && *p != '_' && *p != '-' && *p != '.' && *p != ':')
            return fallback;
    return value;
}
static inline const char *dw_wifi_failure_id(const char *operation, const char *code)
{
    if (code && strstr(code, "readback") &&
        (strstr(code, "mismatch") || strstr(code, "verification_failed")))
        return "WIFI_CONFIG_READBACK_MISMATCH";
    return !strcmp(operation, "wifi_config_save") ?
        "WIFI_CONFIG_SAVE_FAILED" : "WIFI_CONFIG_APPLY_FAILED";
}
static inline int dw_wifi_failure_event(const char *event)
{
    return event && (!strcmp(event, "WIFI_CONFIG_SAVE_FAILED") ||
        !strcmp(event, "WIFI_CONFIG_APPLY_FAILED") ||
        !strcmp(event, "WIFI_CONFIG_READBACK_MISMATCH"));
}
static inline uint64_t dw_wifi_failure_hash(const char *text, uint64_t hash)
{
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p)
        hash = (hash ^ *p) * UINT64_C(1099511628211);
    return (hash ^ 255) * UINT64_C(1099511628211);
}
static inline struct json_object *dw_wifi_failure_detail(const char *operation,
    const char *scope, const char *actor, const char *device_id,
    const char *ap_id, const char *code, const char *stage, int64_t timestamp)
{
    struct json_object *detail = json_object_new_object();
    uint64_t hash = UINT64_C(14695981039346656037);
    char key[32];
    operation = !strcmp(operation, "wifi_config_save") ? operation : "wifi_config_apply";
    scope = !strcmp(scope, "managed_ap") ? "managed_ap" : "local";
    code = dw_wifi_failure_token(code, "operation_failed");
    stage = dw_wifi_failure_token(stage, "webd.wifi");
    device_id = dw_wifi_failure_token(device_id, "local");
    ap_id = dw_wifi_failure_token(ap_id, "");
    const char *parts[] = {operation, scope, actor ? actor : "system", device_id, ap_id, code, stage};
    for (unsigned i = 0; i < sizeof(parts)/sizeof(parts[0]); i++) hash = dw_wifi_failure_hash(parts[i], hash);
    snprintf(key, sizeof(key), "wifi:%016llx", (unsigned long long)hash);
#define DW_WIFI_DETAIL(k, v) json_object_object_add(detail, (k), json_object_new_string(v))
    DW_WIFI_DETAIL("operation", operation);
    DW_WIFI_DETAIL("scope", scope);
    DW_WIFI_DETAIL("device_id", device_id);
    DW_WIFI_DETAIL("ap_id", ap_id);
    DW_WIFI_DETAIL("result", "failed");
    DW_WIFI_DETAIL("error_code", code);
    DW_WIFI_DETAIL("failure_stage", stage);
    DW_WIFI_DETAIL("dedupe_key", key);
    json_object_object_add(detail, "timestamp", json_object_new_int64(timestamp));
#undef DW_WIFI_DETAIL
    return detail;
}
#endif

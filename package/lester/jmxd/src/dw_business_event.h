// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_BUSINESS_EVENT_H
#define DREAMINGWRT_BUSINESS_EVENT_H

#include <json-c/json.h>
#include <string.h>
#include <syslog.h>

/* Existing system_log transport, with a versioned envelope. Call only when an
 * operation reaches a real terminal state or a trusted observed state changes.
 * Status/list requests must not log themselves or repeat unchanged samples.
 * The allowlist excludes task specifications, credentials and error dumps. */
static inline void dw_business_event(const char *producer, const char *event,
                                     struct json_object *detail)
{
    static const char *fields[] = {
        "task_id", "request_id", "object_id", "object_name", "app_id", "actor",
        "source_ip", "action", "result", "failure_stage", "failure_reason",
        "version", "previous_version", "engine", "provider", "use", "path", "trigger", "checksum", "size_bytes",
        "smart_status", "previous_smart_status"
    };
    struct json_object *root = json_object_new_object(), *safe = json_object_new_object();
    if (!root || !safe) { json_object_put(root); json_object_put(safe); return; }
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        struct json_object *v = NULL;
        if (detail && json_object_object_get_ex(detail, fields[i], &v) &&
            json_object_is_type(v, json_type_string)) {
            const char *s = json_object_get_string(v);
            json_object_object_add(safe, fields[i], json_object_new_string_len(s, (int)strnlen(s, 256)));
        }
    }
    json_object_object_add(root, "schema", json_object_new_string("dreamingwrt.business/1"));
    json_object_object_add(root, "producer", json_object_new_string(producer));
    json_object_object_add(root, "event", json_object_new_string(event));
    json_object_object_add(root, "detail", safe);
    const char *text = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    /* logd reads 768-byte syslog lines, including the syslog prefix. Retain
     * operation identity/result first and omit optional context if necessary. */
    for (size_t i = sizeof(fields) / sizeof(fields[0]); text && strlen(text) > 600 && i > 0; ) {
        const char *field = fields[--i];
        if (!strcmp(field, "task_id") || !strcmp(field, "object_id") ||
            !strcmp(field, "action") || !strcmp(field, "result")) continue;
        json_object_object_del(safe, field);
        text = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    }
    if (text && strlen(text) <= 600) syslog(LOG_NOTICE, "DWRT_BUSINESS_V1 %s", text);
    json_object_put(root);
}
#endif

// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DWRT_SAFEOPS_TASK_PROJECTION_H
#define DWRT_SAFEOPS_TASK_PROJECTION_H

#include <stdint.h>
#include <string.h>
#include <json-c/json.h>

/* A single server sample; a terminal task has no remaining confirmation window. */
static inline void safeops_task_clock(struct json_object *task, int64_t now)
{
    struct json_object *v = NULL;
    const char *state = "";
    int64_t deadline = 0;
    int64_t started = 0;
    int64_t timeout = 0;

    if (!task || !json_object_object_get_ex(task, "state", &v))
        return;
    state = json_object_get_string(v);
    if (json_object_object_get_ex(task, "rollback_deadline", &v))
        deadline = json_object_get_int64(v);
    if (deadline <= 0) {
        if (json_object_object_get_ex(task, "started_at", &v))
            started = json_object_get_int64(v);
        if (json_object_object_get_ex(task, "rollback_timeout", &v))
            timeout = json_object_get_int64(v);
        if (started > 0 && timeout > 0)
            deadline = started + timeout;
    }
    json_object_object_add(task, "server_time", json_object_new_int64(now));
    json_object_object_add(task, "confirm_before", json_object_new_int64(deadline));
    json_object_object_add(task, "seconds_left", json_object_new_int64(
        state && !strcmp(state, "pending") && deadline > now ? deadline - now : 0));
    if (json_object_object_get_ex(task, "apply_executor", &v) &&
        !strcmp(json_object_get_string(v), "netconfig_guarded_v1")) {
        struct json_object *readback = NULL;
        int applied = 0;
        if (state && (!strcmp(state, "rollback_failed") || !strcmp(state, "rolling_back"))) {
            json_object_object_add(task, "persisted", NULL);
            json_object_object_add(task, "applied", NULL);
            json_object_object_add(task, "transaction_only", json_object_new_boolean(0));
            return;
        }
        if (state && (!strcmp(state, "pending") || !strcmp(state, "confirmed")) &&
            json_object_object_get_ex(task, "readback", &readback) &&
            json_object_is_type(readback, json_type_array) &&
            json_object_array_length(readback) > 0) {
            struct json_object *entry = json_object_array_get_idx(readback, 0), *ok = NULL;
            applied = json_object_object_get_ex(entry, "applied", &ok) && json_object_get_boolean(ok);
        }
        json_object_object_add(task, "persisted", json_object_new_boolean(applied));
        json_object_object_add(task, "applied", json_object_new_boolean(applied));
        json_object_object_add(task, "transaction_only", json_object_new_boolean(0));
    }
}

#endif

// SPDX-License-Identifier: GPL-2.0-or-later
#include "otad_internal.h"
#include "otad_task_projection.h"

#define OTAD_TASK_COOLDOWN_SECONDS 180

static const char *map_task_state(const char *state,
                                  int64_t completed_at,
                                  int64_t now)
{
    if (!state || !state[0])
        return "idle";
    if (!strcmp(state, "idle"))
        return "idle";
    if (!strcmp(state, "validating"))
        return "pending";
    if (!strcmp(state, "pending"))
        return "pending";
    if (!strcmp(state, "writing") || !strcmp(state, "rebooting") ||
        !strcmp(state, "reconnecting"))
        return "in_progress";
    if (!strcmp(state, "success"))
        return completed_at > 0 && now >= completed_at &&
            now - completed_at < OTAD_TASK_COOLDOWN_SECONDS ?
            "cooldown" : "success";
    if (!strcmp(state, "failed"))
        return "failed";
    if (!strcmp(state, "rolled_back"))
        return "rolled_back";
    return "in_progress";
}

struct json_object *otad_task_projection_get(void)
{
    static const char *query =
        "SELECT operation_id,kind,state,progress,started_at,completed_at,"
        "from_version,to_version,error_code,error_message "
        "FROM ota_operations ORDER BY created_at DESC LIMIT 1";
    struct json_object *envelope = json_object_new_object();
    struct json_object *data = json_object_new_object();
    struct json_object *meta = json_object_new_object();
    sqlite3_stmt *st = otad_inventory_prepare(query);
    const char *task_state = "idle";
    char operation_id[64] = "ota-none";
    char state[32] = "idle";
    char error_code[128] = "";
    char error_message[512] = "";
    char from_version[128] = "";
    char to_version[128] = "";
    int progress = 0;
    int64_t started_at = 0;
    int64_t completed_at = 0;

    if (st && sqlite3_step(st) == SQLITE_ROW) {
        const char *value;

        value = (const char *)sqlite3_column_text(st, 0);
        if (value && value[0])
            snprintf(operation_id, sizeof(operation_id), "%s", value);
        started_at = sqlite3_column_int64(st, 4);
        completed_at = sqlite3_column_int64(st, 5);
        value = (const char *)sqlite3_column_text(st, 2);
        snprintf(state, sizeof(state), "%s", value && value[0] ? value : "");
        progress = sqlite3_column_int(st, 3);
        value = (const char *)sqlite3_column_text(st, 6);
        if (value)
            snprintf(from_version, sizeof(from_version), "%s", value);
        value = (const char *)sqlite3_column_text(st, 7);
        if (value)
            snprintf(to_version, sizeof(to_version), "%s", value);
        value = (const char *)sqlite3_column_text(st, 8);
        if (value)
            snprintf(error_code, sizeof(error_code), "%s", value);
        value = (const char *)sqlite3_column_text(st, 9);
        if (value)
            snprintf(error_message, sizeof(error_message), "%s", value);
    }
    if (st)
        sqlite3_finalize(st);

    task_state = map_task_state(state, completed_at, otad_now_s());

    json_object_object_add(envelope, "contract",
                           json_object_new_string("product-plane.v1"));
    json_object_object_add(envelope, "resource",
                           json_object_new_string("ota.task"));
    json_object_object_add(envelope, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "task_id",
                           json_object_new_string(operation_id));
    json_object_object_add(data, "type", json_object_new_string("ota_update"));
    json_object_object_add(data, "state",
                           json_object_new_string(task_state));
    json_object_object_add(data, "progress",
                           json_object_new_int(progress));
    json_object_object_add(data, "message", error_message[0] ?
                           json_object_new_string(error_message) : NULL);
    json_object_object_add(data, "started_at",
                           json_object_new_int64(started_at));
    json_object_object_add(data, "completed_at",
                           json_object_new_int64(completed_at));
    json_object_object_add(data, "version_from", from_version[0] ?
                           json_object_new_string(from_version) : NULL);
    json_object_object_add(data, "version_to", to_version[0] ?
                           json_object_new_string(to_version) : NULL);
    if (!strcmp(task_state, "failed") && error_code[0]) {
        struct json_object *error = json_object_new_object();

        json_object_object_add(error, "code",
                               json_object_new_string(error_code));
        json_object_object_add(error, "message", error_message[0] ?
                               json_object_new_string(error_message) : NULL);
        json_object_object_add(data, "error", error);
    }
    json_object_object_add(envelope, "data", data);
    json_object_object_add(meta, "observed_at",
                           json_object_new_int64(otad_now_s()));
    json_object_object_add(meta, "stale", json_object_new_boolean(0));
    json_object_object_add(envelope, "meta", meta);

    return envelope;
}

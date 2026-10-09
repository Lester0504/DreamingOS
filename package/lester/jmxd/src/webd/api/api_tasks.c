// SPDX-License-Identifier: GPL-2.0-or-later
/* Read-only TaskCenter projections. Execution remains with otad and AC. */
#include <sqlite3.h>
#include <string.h>
#include <time.h>
#include "api_tasks.h"
#include "api_error.h"
#include "api_ubus.h"

#ifndef WEBD_TASKS_CONFIG_DB
#define WEBD_TASKS_CONFIG_DB "/etc/dreamingwrt/config.db"
#endif
#define TASK_RETENTION_SECONDS 86400
#define TASK_PAGE_SIZE 64

static struct json_object *ota_task(struct jmx_api_ctx *ctx)
{
    return app_ubus_route_or_error("dreamingwrt.otad", "task_projection", NULL,
                                   2000, &ctx->status);
}

static const char *wifi_task_state(const char *state)
{
    if (!strcmp(state, "applied")) return "success";
    if (!strcmp(state, "rolled_back")) return "rolled_back";
    if (!strcmp(state, "failed") || !strcmp(state, "rollback_failed") ||
        !strcmp(state, "partially_applied")) return "failed";
    if (!strcmp(state, "pending")) return "pending";
    return "in_progress";
}

static struct json_object *wifi_tasks(struct jmx_api_ctx *ctx)
{
    static const char *sql =
        "SELECT t.transaction_id,t.state,t.created_at,t.updated_at,"
        "COUNT(x.ap_id),COALESCE(SUM(x.state IN ('applied','failed',"
        "'rolled_back','rollback_failed','cancelled')),0) "
        "FROM ac_transactions t LEFT JOIN ac_transaction_targets x "
        "ON x.transaction_id=t.transaction_id "
        "WHERE t.updated_at>=?1 OR t.state NOT IN ('applied','failed',"
        "'rolled_back','rollback_failed','partially_applied') "
        "GROUP BY t.transaction_id "
        "ORDER BY t.state NOT IN ('applied','failed','rolled_back',"
        "'rollback_failed','partially_applied') DESC,t.created_at DESC "
        "LIMIT 65";
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *tasks = json_object_new_array();
    struct json_object *data, *response, *meta;
    time_t now = time(NULL);
    int rc, count = 0, truncated = 0;

    /* Never create an empty replacement database or schema on a read. */
    if (sqlite3_open_v2(WEBD_TASKS_CONFIG_DB, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        goto unavailable;
    sqlite3_busy_timeout(db, 1000);
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        goto unavailable;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)now - TASK_RETENTION_SECONDS);
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const char *raw_state = (const char *)sqlite3_column_text(st, 1);
        const char *state = wifi_task_state(raw_state ? raw_state : "");
        int total = sqlite3_column_int(st, 4);
        int done = sqlite3_column_int(st, 5);
        struct json_object *task;
        if (count++ == TASK_PAGE_SIZE) { truncated = 1; break; }
        task = json_object_new_object();
        json_object_object_add(task, "task_id", json_object_new_string(
            (const char *)sqlite3_column_text(st, 0)));
        json_object_object_add(task, "type", json_object_new_string("wifi_configuration"));
        json_object_object_add(task, "state", json_object_new_string(state));
        json_object_object_add(task, "source_state", json_object_new_string(raw_state));
        json_object_object_add(task, "started_at", json_object_new_int64(sqlite3_column_int64(st, 2)));
        json_object_object_add(task, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 3)));
        json_object_object_add(task, "targets_total", json_object_new_int(total));
        json_object_object_add(task, "targets_finished", json_object_new_int(done));
        json_object_object_add(task, "progress", total > 0 ?
            json_object_new_int(done * 100 / total) : NULL);
        json_object_object_add(task, "message", json_object_new_string(
            !strcmp(state, "success") ? "Wi-Fi configuration applied" :
            !strcmp(state, "failed") ? "Wi-Fi configuration failed; inspect transaction details" :
            !strcmp(state, "rolled_back") ? "Wi-Fi configuration rolled back" :
            "Wi-Fi configuration in progress"));
        json_object_array_add(tasks, task);
    }
    if (rc != SQLITE_DONE && !truncated) goto unavailable;
    sqlite3_finalize(st);
    sqlite3_close(db);
    data = json_object_new_object();
    json_object_object_add(data, "tasks", tasks);
    json_object_object_add(data, "truncated", json_object_new_boolean(truncated));
    json_object_object_add(data, "retention_seconds", json_object_new_int(TASK_RETENTION_SECONDS));
    response = json_object_new_object();
    json_object_object_add(response, "contract", json_object_new_string("product-plane.v1"));
    json_object_object_add(response, "resource", json_object_new_string("wifi.task"));
    json_object_object_add(response, "ok", json_object_new_boolean(1));
    json_object_object_add(response, "data", data);
    meta = json_object_new_object();
    json_object_object_add(meta, "observed_at", json_object_new_int64(now));
    json_object_object_add(meta, "stale", json_object_new_boolean(0));
    json_object_object_add(response, "meta", meta);
    ctx->status = 200;
    return response;
unavailable:
    sqlite3_finalize(st);
    sqlite3_close(db);
    json_object_put(tasks);
    ctx->status = 503;
    return webd_error("wifi_task_source_unavailable", "Wi-Fi task journal is unavailable", "", "webd.tasks");
}

const struct jmx_api_route tasks_api_routes[] = {
    JMX_API_ROUTE(9611, "/api/v1/system/ota/task", "GET", JMX_API_EXACT, ota_task),
    JMX_API_ROUTE(9612, "/api/v1/wifi/tasks", "GET", JMX_API_EXACT, wifi_tasks),
    JMX_API_ROUTE_END,
};

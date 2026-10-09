// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#define _GNU_SOURCE

#include <stdint.h>
#include <string.h>

#include "api_dashboard.h"
#include "api_error.h"
#include "api_json.h"
#include "api_ubus.h"
#include "api_util.h"

static const char *webd_health_level_for_metrics(int cpu_percent, int mem_percent, int disk_percent)
{
    if (cpu_percent >= 95 || mem_percent >= 95 || disk_percent >= 95)
        return "critical";
    if (cpu_percent >= 85 || mem_percent >= 85 || disk_percent >= 90)
        return "warning";
    return "ok";
}

static struct json_object *webd_dashboard_status_response(void)
{
    struct json_object *system = app_ubus_invoke("system_health", NULL);
    struct json_object *wan_list = app_ubus_invoke("wan_list", NULL);
    struct json_object *line = webd_cached_line_health();
    struct json_object *notify = app_ubus_object_or_error("dreamingwrt.notifyd", "status", NULL);
    struct json_object *sys_data = webd_data_from_jmx_response(system);
    struct json_object *wan_data = webd_data_from_jmx_response(wan_list);
    struct json_object *line_data = webd_data_from_jmx_response(line);
    struct json_object *notify_data = webd_data_from_jmx_response(notify);
    struct json_object *resp, *data, *items, *item, *v = NULL;
    int cpu = 0, mem = 0, disk = 0;
    int has_warning = 0, has_critical = 0;
    const char *level = "ok";
    const char *summary = "系统运行正常";
    int notify_available = notify_data != NULL;

    if (!sys_data && !line_data && !notify_available) {
        if (system) json_object_put(system);
        if (wan_list) json_object_put(wan_list);
        if (line) json_object_put(line);
        if (notify) json_object_put(notify);
        return webd_error("source_unavailable", "dashboard status source is not available",
                          "dreamingwrt system_health/line_health/notifyd status",
                          "webd.dashboard");
    }

    data = json_object_new_object();
    items = json_object_new_array();

    if (sys_data && json_object_object_get_ex(sys_data, "system", &v) && v) {
        struct json_object *sys = v;
        int64_t mem_used = app_nc_json_int64(sys, "mem_used", 0);
        int64_t mem_total = app_nc_json_int64(sys, "mem_total", 1);
        int64_t disk_used = app_nc_json_int64(sys, "disk_used", 0);
        int64_t disk_total = app_nc_json_int64(sys, "disk_total", 1);

        cpu = app_nc_json_int(sys, "cpu_percent", 0);
        mem = (int)((double)mem_used * 100.0 / (double)(mem_total > 0 ? mem_total : 1));
        disk = (int)((double)disk_used * 100.0 / (double)(disk_total > 0 ? disk_total : 1));
        level = webd_health_level_for_metrics(cpu, mem, disk);
        if (strcmp(level, "ok")) {
            item = json_object_new_object();
            json_object_object_add(item, "code", json_object_new_string("system_resource"));
            json_object_object_add(item, "level", json_object_new_string(level));
            json_object_object_add(item, "target", json_object_new_string("system"));
            json_object_object_add(item, "title", json_object_new_string("系统资源"));
            json_object_object_add(item, "detail", json_object_new_string("CPU、内存或磁盘占用偏高"));
            json_object_object_add(item, "ts", json_object_new_int64(app_nc_json_int(sys_data, "ts", now_s())));
            json_object_array_add(items, item);
            if (!strcmp(level, "warning"))
                has_warning = 1;
            else
                has_critical = 1;
        }
    }

    if (wan_data && json_object_object_get_ex(wan_data, "wans", &v) && v &&
        json_object_is_type(v, json_type_array)) {
        int i, wan_count = json_object_array_length(v);

        for (i = 0; i < wan_count; i++) {
            struct json_object *wan = json_object_array_get_idx(v, i);
            struct json_object *runtime = NULL;
            const char *wan_name = app_nc_json_str(wan, "id", "wan");
            const char *wan_status = app_nc_json_str(wan, "status", "unknown");
            int online = app_nc_json_bool(wan, "health", !strcmp(wan_status, "ok"));
            int latency = -1;
            int loss = -1;

            if (json_object_object_get_ex(wan, "runtime", &runtime) && runtime) {
                latency = app_nc_json_int(runtime, "latency_ms", -1);
                loss = app_nc_json_int(runtime, "loss_pct", -1);
                online = app_nc_json_bool(runtime, "online", online);
            }
            if (online && !strcmp(wan_status, "ok"))
                continue;
            item = json_object_new_object();
            json_object_object_add(item, "code", json_object_new_string(online ? "wan_degraded" : "wan_down"));
            json_object_object_add(item, "level", json_object_new_string(online ? "warning" : "critical"));
            json_object_object_add(item, "target", json_object_new_string(wan_name));
            json_object_object_add(item, "title", json_object_new_string("WAN 状态"));
            json_object_object_add(item, "detail", json_object_new_string(online ? "线路质量异常" : "线路不可用"));
            json_object_object_add(item, "ts", json_object_new_int64(now_s()));
            if (latency >= 0)
                json_object_object_add(item, "latency_ms", json_object_new_int(latency));
            if (loss >= 0)
                json_object_object_add(item, "loss_pct", json_object_new_int(loss));
            json_object_array_add(items, item);
            if (online)
                has_warning = 1;
            else
                has_critical = 1;
        }
    } else if (line_data && json_object_object_get_ex(line_data, "wans", &v) && v &&
        json_object_is_type(v, json_type_array)) {
        int i, wan_count = json_object_array_length(v);

        for (i = 0; i < wan_count; i++) {
            struct json_object *wan = json_object_array_get_idx(v, i);
            const char *wan_name = app_nc_json_str(wan, "name", "wan");
            const char *wan_status = app_nc_json_str(wan, "status", "unknown");
            const char *reason = app_nc_json_str(wan, "reason", "");
            int latency = app_nc_json_int(wan, "latency", -1);
            int loss = app_nc_json_int(wan, "loss", -1);

            if (!strcmp(wan_status, "ok"))
                continue;
            item = json_object_new_object();
            json_object_object_add(item, "code", json_object_new_string(!strcmp(wan_status, "down") ? "wan_down" : "wan_degraded"));
            json_object_object_add(item, "level", json_object_new_string(!strcmp(wan_status, "down") ? "critical" : "warning"));
            json_object_object_add(item, "target", json_object_new_string(wan_name));
            json_object_object_add(item, "title", json_object_new_string("WAN 状态"));
            json_object_object_add(item, "detail", json_object_new_string(reason[0] ? reason : "线路异常"));
            json_object_object_add(item, "ts", json_object_new_int64(app_nc_json_int(wan, "ts", now_s())));
            if (latency >= 0)
                json_object_object_add(item, "latency_ms", json_object_new_int(latency));
            if (loss >= 0)
                json_object_object_add(item, "loss_pct", json_object_new_int(loss));
            json_object_array_add(items, item);
            if (!strcmp(wan_status, "down"))
                has_critical = 1;
            else
                has_warning = 1;
        }
    }

    if (notify_available && json_object_object_get_ex(notify_data, "active_by_level", &v) && v &&
        json_object_object_length(v) > 0) {
        item = json_object_new_object();
        json_object_object_add(item, "code", json_object_new_string("notify_active"));
        json_object_object_add(item, "level", json_object_new_string("warning"));
        json_object_object_add(item, "target", json_object_new_string("notifyd"));
        json_object_object_add(item, "title", json_object_new_string("通知待处理"));
        json_object_object_add(item, "detail", json_object_new_string("存在未处理的通知事件"));
        json_object_object_add(item, "ts", json_object_new_int64(now_s()));
        json_object_array_add(items, item);
        has_warning = 1;
    }

    if (has_critical)
        level = "critical";
    else if (has_warning && !strcmp(level, "ok"))
        level = "warning";

    if (!strcmp(level, "critical"))
        summary = "系统存在严重告警";
    else if (!strcmp(level, "warning"))
        summary = "系统存在告警";

    json_object_object_add(data, "status", json_object_new_string(level));
    json_object_object_add(data, "summary", json_object_new_string(summary));
    json_object_object_add(data, "items", items);
    json_object_object_add(data, "source", json_object_new_string(notify_available ? "notifyd" : "dreamingwrt.core_runtime"));
    if (sys_data)
        json_object_object_add(data, "system", json_object_get(sys_data));
    if (wan_data)
        json_object_object_add(data, "wan_list", json_object_get(wan_data));
    if (line_data)
        json_object_object_add(data, "line", json_object_get(line_data));
    if (notify_data)
        json_object_object_add(data, "notify", json_object_get(notify_data));

    resp = webd_envelope(data, "jmxd.dashboard_status");
    json_object_object_add(resp, "code", json_object_new_int(APP_API_CODE_SUCCESS));

    if (sys_data) json_object_put(sys_data);
    if (wan_data) json_object_put(wan_data);
    if (line_data) json_object_put(line_data);
    if (notify_data) json_object_put(notify_data);
    if (system) json_object_put(system);
    if (wan_list) json_object_put(wan_list);
    if (line) json_object_put(line);
    if (notify) json_object_put(notify);
    return resp;
}

static struct json_object *dashboard_status(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = webd_dashboard_status_response();

    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

const struct jmx_api_route dashboard_api_routes[] = {
    JMX_API_ROUTE(305, "/api/v1/dashboard/status", "GET", JMX_API_EXACT, dashboard_status),
    JMX_API_ROUTE_END,
};

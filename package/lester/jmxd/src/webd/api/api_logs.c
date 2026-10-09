// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Log-center BFF (Phase 6N). The /api/v1/logs/* read/write surface: query /
 * export / clear, events (add + search), alarms (+ summary), warning-rules,
 * channels, delivery stats, settings, the syslog subtree (test / queue / certs
 * / presets), search / summary / count / mark-read / ack / filter-data, and the
 * bare collection GET. logd (dreamingwrt.logd) owns the persistent truth; these
 * handlers are thin BFF adapters. Each branch body moves VERBATIM from
 * jmx_app_api.c behind an alias preamble (req/body_json/device_id as referenced;
 * resp+status always), so no second implementation remains there.
 *
 * Four paths carry a GET reader and a POST/PUT writer (warning-rules, channels,
 * settings, syslog/certs). They are distinct (path, methods) rows matched on
 * path+method, so each is a plain JMX_API_ROUTE — no predicate is needed.
 *
 * GET /api/v1/logs/download stays inline in jmx_app_api.c: it is a RAW_FD
 * handler (webd_logs_download_response writes the socket directly and closes
 * fd), which cannot flow through the JSON response table.
 *
 * Borrowed from jmx_app_api.c (declared in api_logs_internal.h; definitions stay
 * in main), de-static'd: webd_logs_v2_response, webd_logs_v2_flat_response,
 * webd_logs_attach_actor. Every other symbol these bodies use is already
 * exported from api_ubus.c / api_request.c.
 */
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>

#include "api_logs.h"
#include "api_logs_internal.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_ubus.h"
#include "webd_http_req.h"
#include "../jmx_app_api.h"

/* ── logs route handlers (verbatim bodies behind an alias preamble) ── */

static struct json_object *logs_query(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_invoke("log_center_query", body_json);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_export(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = webd_logs_v2_response("unifi_export", body_json, "dreamingwrt.logd.unifi_export", &status);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_clear(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_invoke("log_center_clear", body_json);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_events_search(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_invoke("log_center_event_search", body_json);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_events(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_invoke("log_center_event_add", body_json);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_alarms(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        resp = app_ubus_invoke("log_center_alarm_get", NULL);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_alarms_summary(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        resp = app_ubus_invoke("log_center_alarm_summary", NULL);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_warning_rules_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        resp = app_ubus_invoke("log_center_warning_rules_get", NULL);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_warning_rules_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_ok_only("log_center_warning_rules_set", body_json);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_channels_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        resp = app_ubus_invoke("log_center_channels_get", NULL);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_channels_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_ok_only("log_center_channels_set", body_json);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_delivery_stats(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        resp = app_ubus_invoke("log_center_delivery_stats", NULL);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_settings_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = webd_logs_v2_response("settings_get", body_json, "dreamingwrt.logd.settings", &status);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_settings_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = webd_logs_v2_response("settings_set", body_json, "dreamingwrt.logd.settings", &status);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_syslog_test(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = webd_logs_v2_response("syslog_test", body_json, "dreamingwrt.logd.syslog_test", &status);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_syslog_queue(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = webd_logs_v2_response("syslog_queue_status", body_json, "dreamingwrt.logd.syslog_queue_status", &status);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_syslog_queue_flush(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = webd_logs_v2_response("syslog_queue_flush", body_json, "dreamingwrt.logd.syslog_queue_flush", &status);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_syslog_queue_clear(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = webd_logs_v2_response("syslog_queue_clear", body_json, "dreamingwrt.logd.syslog_queue_clear", &status);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_syslog_certs_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = webd_logs_v2_response("syslog_cert_list", body_json, "dreamingwrt.logd.syslog_cert_list", &status);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_syslog_certs_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = webd_logs_v2_response("syslog_cert_upload", body_json, "dreamingwrt.logd.syslog_cert_upload", &status);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_syslog_certs_delete(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        char name[128];

        if (webd_query_get(req.query, "name", name, sizeof(name)) && name[0] &&
            !json_object_object_get(body_json, "name"))
            json_object_object_add(body_json, "name", json_object_new_string(name));
        resp = webd_logs_v2_response("syslog_cert_delete", body_json, "dreamingwrt.logd.syslog_cert_delete", &status);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_syslog_presets(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;

        struct json_object *params = json_object_new_object();
        char vendor[64];
        char id[96];

        if (webd_query_get(req.query, "vendor", vendor, sizeof(vendor)) && vendor[0])
            json_object_object_add(params, "vendor", json_object_new_string(vendor));
        if (webd_query_get(req.query, "id", id, sizeof(id)) && id[0])
            json_object_object_add(params, "id", json_object_new_string(id));
        resp = webd_logs_v2_response("syslog_presets", params, "dreamingwrt.logd.syslog_presets", &status);
        json_object_put(params);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_syslog_presets_preview(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = webd_logs_v2_response("syslog_presets", body_json, "dreamingwrt.logd.syslog_presets", &status);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_search(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        webd_logs_attach_actor(body_json, device_id);
        resp = webd_logs_v2_flat_response("unifi_search", body_json,
                                          "dreamingwrt.logd.unifi_search", &status);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_summary(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        struct json_object *params = json_object_new_object();
        char qbuf[128];

        if (params && webd_query_get(req.query, "timestampFrom", qbuf, sizeof(qbuf)))
            json_object_object_add(params, "timestampFrom", json_object_new_string(qbuf));
        if (params && webd_query_get(req.query, "timestampTo", qbuf, sizeof(qbuf)))
            json_object_object_add(params, "timestampTo", json_object_new_string(qbuf));
        if (params && webd_query_get(req.query, "start", qbuf, sizeof(qbuf)))
            json_object_object_add(params, "timestampFrom", json_object_new_string(qbuf));
        if (params && webd_query_get(req.query, "end", qbuf, sizeof(qbuf)))
            json_object_object_add(params, "timestampTo", json_object_new_string(qbuf));
        if (params && webd_query_get(req.query, "severity", qbuf, sizeof(qbuf)))
            json_object_object_add(params, "severity", json_object_new_string(qbuf));
        if (params && webd_query_get(req.query, "category", qbuf, sizeof(qbuf)))
            json_object_object_add(params, "category", json_object_new_string(qbuf));
        if (params && webd_query_get(req.query, "event", qbuf, sizeof(qbuf)))
            json_object_object_add(params, "event", json_object_new_string(qbuf));
        if (params && webd_query_get(req.query, "search_text", qbuf, sizeof(qbuf)))
            json_object_object_add(params, "search_text", json_object_new_string(qbuf));
        if (params && webd_query_get(req.query, "query", qbuf, sizeof(qbuf)))
            json_object_object_add(params, "search_text", json_object_new_string(qbuf));
        if (params)
            webd_logs_attach_actor(params, device_id);
        resp = webd_logs_v2_response("unifi_count", params ? params : body_json,
                                     "dreamingwrt.logd.unifi_count.summary", &status);
        if (params)
            json_object_put(params);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_count(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        webd_logs_attach_actor(body_json, device_id);
        resp = webd_logs_v2_response("unifi_count", body_json, "dreamingwrt.logd.unifi_count", &status);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_mark_read(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        webd_logs_attach_actor(body_json, device_id);
        resp = webd_logs_v2_response("unifi_mark_read", body_json, "dreamingwrt.logd.unifi_mark_read", &status);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_ack(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        webd_logs_attach_actor(body_json, device_id);
        resp = webd_logs_v2_response("unifi_ack", body_json, "dreamingwrt.logd.unifi_ack", &status);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_filter_data(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = webd_logs_v2_response("unifi_filter_data", body_json, "dreamingwrt.logd.unifi_filter_data", &status);

    ctx->status = status;
    return resp;
}

static struct json_object *logs_root(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;
    const char *device_id = ctx->device_id;

        struct json_object *params = json_object_new_object();
        char qbuf[256];

        json_object_object_add(params, "pageNumber", json_object_new_int(0));
        json_object_object_add(params, "pageSize", json_object_new_int(100));
        if (webd_query_get(req.query, "pageNumber", qbuf, sizeof(qbuf)))
            json_object_object_add(params, "pageNumber", json_object_new_int(atoi(qbuf)));
        if (webd_query_get(req.query, "pageSize", qbuf, sizeof(qbuf)))
            json_object_object_add(params, "pageSize", json_object_new_int(atoi(qbuf)));
        if (webd_query_get(req.query, "search_text", qbuf, sizeof(qbuf)) ||
            webd_query_get(req.query, "query", qbuf, sizeof(qbuf)) ||
            webd_query_get(req.query, "q", qbuf, sizeof(qbuf)))
            json_object_object_add(params, "search_text", json_object_new_string(qbuf));
        if (webd_query_get(req.query, "timestampFrom", qbuf, sizeof(qbuf)))
            json_object_object_add(params, "timestampFrom", json_object_new_string(qbuf));
        if (webd_query_get(req.query, "timestampTo", qbuf, sizeof(qbuf)))
            json_object_object_add(params, "timestampTo", json_object_new_string(qbuf));
        webd_logs_attach_actor(params, device_id);
        resp = webd_logs_v2_response("unifi_search", params,
                                     "dreamingwrt.logd.unifi_search", &status);
        json_object_put(params);

    ctx->status = status;
    return resp;
}

const struct jmx_api_route logs_api_routes[] = {
    JMX_API_ROUTE(672, "/api/v1/logs/query", "POST,PUT", JMX_API_EXACT, logs_query),
    JMX_API_ROUTE(673, "/api/v1/logs/export", "POST,PUT", JMX_API_EXACT, logs_export),
    JMX_API_ROUTE(674, "/api/v1/logs/clear", "POST,PUT", JMX_API_EXACT, logs_clear),
    JMX_API_ROUTE(675, "/api/v1/logs/events/search", "POST,PUT", JMX_API_EXACT, logs_events_search),
    JMX_API_ROUTE(676, "/api/v1/logs/events", "POST,PUT", JMX_API_EXACT, logs_events),
    JMX_API_ROUTE(677, "/api/v1/logs/alarms", "GET", JMX_API_EXACT, logs_alarms),
    JMX_API_ROUTE(678, "/api/v1/logs/alarms/summary", "GET", JMX_API_EXACT, logs_alarms_summary),
    JMX_API_ROUTE(679, "/api/v1/logs/warning-rules", "GET", JMX_API_EXACT, logs_warning_rules_get),
    JMX_API_ROUTE(680, "/api/v1/logs/warning-rules", "POST,PUT", JMX_API_EXACT, logs_warning_rules_post),
    JMX_API_ROUTE(681, "/api/v1/logs/channels", "GET", JMX_API_EXACT, logs_channels_get),
    JMX_API_ROUTE(682, "/api/v1/logs/channels", "POST,PUT", JMX_API_EXACT, logs_channels_post),
    JMX_API_ROUTE(688, "/api/v1/logs/delivery/stats", "GET", JMX_API_EXACT, logs_delivery_stats),
    JMX_API_ROUTE(689, "/api/v1/logs/settings", "GET", JMX_API_EXACT, logs_settings_get),
    JMX_API_ROUTE(690, "/api/v1/logs/settings", "POST,PUT", JMX_API_EXACT, logs_settings_post),
    JMX_API_ROUTE(691, "/api/v1/logs/syslog/test", "POST", JMX_API_EXACT, logs_syslog_test),
    JMX_API_ROUTE(692, "/api/v1/logs/syslog/queue", "GET", JMX_API_EXACT, logs_syslog_queue),
    JMX_API_ROUTE(693, "/api/v1/logs/syslog/queue/flush", "POST", JMX_API_EXACT, logs_syslog_queue_flush),
    JMX_API_ROUTE(694, "/api/v1/logs/syslog/queue/clear", "POST", JMX_API_EXACT, logs_syslog_queue_clear),
    JMX_API_ROUTE(695, "/api/v1/logs/syslog/certs", "GET", JMX_API_EXACT, logs_syslog_certs_get),
    JMX_API_ROUTE(696, "/api/v1/logs/syslog/certs", "POST,PUT", JMX_API_EXACT, logs_syslog_certs_post),
    JMX_API_ROUTE(697, "/api/v1/logs/syslog/certs/delete", "POST,PUT,DELETE", JMX_API_EXACT, logs_syslog_certs_delete),
    JMX_API_ROUTE(698, "/api/v1/logs/syslog/presets", "GET", JMX_API_EXACT, logs_syslog_presets),
    JMX_API_ROUTE(699, "/api/v1/logs/syslog/presets/preview", "POST,PUT", JMX_API_EXACT, logs_syslog_presets_preview),
    JMX_API_ROUTE(700, "/api/v1/logs/search", "POST,PUT", JMX_API_EXACT, logs_search),
    JMX_API_ROUTE(701, "/api/v1/logs/summary", "GET", JMX_API_EXACT, logs_summary),
    JMX_API_ROUTE(702, "/api/v1/logs/count", "POST,PUT", JMX_API_EXACT, logs_count),
    JMX_API_ROUTE(703, "/api/v1/logs/mark-read", "POST,PUT", JMX_API_EXACT, logs_mark_read),
    JMX_API_ROUTE(704, "/api/v1/logs/ack", "POST,PUT", JMX_API_EXACT, logs_ack),
    JMX_API_ROUTE(705, "/api/v1/logs/filter-data", "POST,PUT", JMX_API_EXACT, logs_filter_data),
    JMX_API_ROUTE(719, "/api/v1/logs", "GET", JMX_API_EXACT, logs_root),
    JMX_API_ROUTE_END,
};

// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Logd event-backend REST adapters (Phase 6H). The /api/v1/logd/* surface is a
 * thin proxy onto the dreamingwrt.logd ubus object: status, settings get/set,
 * syslog test, collector list/config, collect-now, and the event
 * list/query/add/clear lifecycle. Bodies are moved VERBATIM from jmx_app_api.c
 * behind a small alias preamble (body_json/status/resp), so no second
 * implementation remains there. Zero borrowed helpers: app_ubus_object_or_error
 * and app_response_status are already exported from api_ubus.c / api_error.c.
 */
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>

#include "api_logd.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_ubus.h"
#include "../jmx_app_api.h"

/* ── logd route handlers (verbatim bodies behind an alias preamble) ── */

static struct json_object *logd_status(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.logd", "status", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *logd_settings_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.logd", "settings_get", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *logd_settings_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.logd", "settings_set", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *logd_syslog_test(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.logd", "syslog_test", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *logd_collectors_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.logd", "collectors_get", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *logd_collectors_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.logd", "collectors_set", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *logd_collect_now(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.logd", "collect_now", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *logd_events_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.logd", "event_list", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *logd_events_query(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.logd", "event_list", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *logd_events_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.logd", "event_add", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *logd_events_clear(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.logd", "event_clear", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

const struct jmx_api_route logd_api_routes[] = {
    JMX_API_ROUTE(106, "/api/v1/logd/status", "GET", JMX_API_EXACT, logd_status),
    JMX_API_ROUTE(107, "/api/v1/logd/settings", "GET", JMX_API_EXACT, logd_settings_get),
    JMX_API_ROUTE(108, "/api/v1/logd/settings", "POST,PUT,PATCH", JMX_API_EXACT, logd_settings_post),
    JMX_API_ROUTE(109, "/api/v1/logd/syslog/test", "POST", JMX_API_EXACT, logd_syslog_test),
    JMX_API_ROUTE(110, "/api/v1/logd/collectors", "GET", JMX_API_EXACT, logd_collectors_get),
    JMX_API_ROUTE(111, "/api/v1/logd/collectors", "POST,PUT,PATCH", JMX_API_EXACT, logd_collectors_post),
    JMX_API_ROUTE(112, "/api/v1/logd/collect-now", "POST", JMX_API_EXACT, logd_collect_now),
    JMX_API_ROUTE(113, "/api/v1/logd/events", "GET", JMX_API_EXACT, logd_events_get),
    JMX_API_ROUTE(114, "/api/v1/logd/events/query", "POST,PUT", JMX_API_EXACT, logd_events_query),
    JMX_API_ROUTE(115, "/api/v1/logd/events", "POST,PUT", JMX_API_EXACT, logd_events_post),
    JMX_API_ROUTE(116, "/api/v1/logd/events/clear", "POST,PUT", JMX_API_EXACT, logd_events_clear),
    JMX_API_ROUTE_END,
};

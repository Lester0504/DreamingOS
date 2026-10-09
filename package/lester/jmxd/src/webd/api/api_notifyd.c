// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Notifyd delivery-backend REST adapters (Phase 6I). The /api/v1/notifyd/*
 * surface is the notification control plane: status, event catalog, settings
 * get/set, the signed-in user's own preference mute, channels/routes CRUD reads
 * and writes, triggers, enqueue, test-send, and the outbox list/query/retry/get
 * + deliver-due lifecycle. Bodies are moved VERBATIM from jmx_app_api.c behind a
 * small alias preamble (req/body_json/device_id/status/resp), so no second
 * implementation remains there. The channels/, routes/ and outbox/ strncmp
 * prefix branches deliberately stay in the legacy chain: their single-segment
 * guard cannot be expressed as a plain JMX_API_PREFIX route.
 */
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>

#include "api_notifyd.h"
#include "api_notifyd_internal.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_ubus.h"
#include "webd_http_req.h"
#include "../jmx_app_api.h"

/* ── notifyd route handlers (verbatim bodies behind an alias preamble) ── */

static struct json_object *notifyd_status(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.notifyd", "status", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *notifyd_events(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.notifyd", "event_catalog", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *notifyd_settings_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.notifyd", "settings_get", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *notifyd_settings_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.notifyd", "settings_set", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *notifyd_preferences_me(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        const char *pref_user = webd_identity_username(device_id);

        if (!webd_identity_is_user(device_id) || !pref_user[0]) {
            /* API-key and paired-app identities are not a person, so there is
             * no "me" whose preference could be read or written. */
            status = 403;
            resp = webd_error("notification_preference_forbidden",
                              "a personal notification preference requires an authenticated Web session",
                              "Web user session", "webd.dreamingwrt.notifyd");
        } else {
            struct json_object *params = json_object_new_object();
            const char *pref_error;
            int writing = strcmp(req.method, "GET") != 0;

            json_object_object_add(params, "username",
                                   json_object_new_string(pref_user));
            if (writing) {
                struct json_object *channel_ids = NULL;

                if (app_nc_json_has(body_json, "muted"))
                    json_object_object_add(params, "muted",
                        json_object_new_boolean(app_nc_json_bool(body_json, "muted", 0)));
                if (app_nc_json_has(body_json, "muted_until"))
                    json_object_object_add(params, "muted_until",
                        json_object_new_int64(app_nc_json_int64(body_json, "muted_until", 0)));
                if (json_object_object_get_ex(body_json, "channel_ids", &channel_ids) &&
                    channel_ids)
                    json_object_object_add(params, "channel_ids",
                                           json_object_get(channel_ids));
                if (app_nc_json_has(body_json, "expected_updated_at"))
                    json_object_object_add(params, "expected_updated_at",
                        json_object_new_int64(app_nc_json_int64(body_json,
                                                               "expected_updated_at", -1)));
            }
            resp = app_ubus_object_or_error("dreamingwrt.notifyd",
                                            writing ? "preferences_set" : "preferences_get",
                                            params);
            json_object_put(params);
            status = app_response_status(resp, status);
            pref_error = app_nc_json_str(resp, "error", "");
            if (!strcmp(pref_error, "notification_preference_revision_conflict"))
                status = 409;
            else if (!strcmp(pref_error, "notification_preference_forbidden"))
                status = 403;
        }

    ctx->status = status;
    return resp;
}

static struct json_object *notifyd_channels_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.notifyd", "channels_get", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *notifyd_channels_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.notifyd", "channels_set", body_json);
        status = app_response_status(resp, status);
        if (!strcmp(app_nc_json_str(resp, "error", ""), "revision_conflict"))
            status = 409;

    ctx->status = status;
    return resp;
}

static struct json_object *notifyd_routes_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.notifyd", "routes_get", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *notifyd_triggers(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;

        struct json_object *params = json_object_new_object();
        char value[512];

        if (webd_query_get(req.query, "route_id", value, sizeof(value)) && value[0])
            json_object_object_add(params, "route_id", json_object_new_string(value));
        if (webd_query_get(req.query, "cursor", value, sizeof(value)) && value[0])
            json_object_object_add(params, "cursor", json_object_new_string(value));
        if (webd_query_get(req.query, "limit", value, sizeof(value)) && value[0])
            json_object_object_add(params, "limit", json_object_new_int(atoi(value)));
        resp = app_ubus_object_or_error("dreamingwrt.notifyd", "triggers_get", params);
        json_object_put(params);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *notifyd_routes_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.notifyd", "routes_set", body_json);
        status = app_response_status(resp, status);
        if (!strcmp(app_nc_json_str(resp, "error", ""), "revision_conflict"))
            status = 409;

    ctx->status = status;
    return resp;
}

static struct json_object *notifyd_enqueue(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.notifyd", "enqueue", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *notifyd_test_send(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        /* A real TLS SMTP transaction commonly exceeds the generic 2s RPC budget. */
        resp = app_ubus_invoke_object_timeout("dreamingwrt.notifyd", "test_send",
                                              body_json, 30000);
        if (!resp)
            resp = webd_error("source_unavailable", "ubus source is not available",
                              "dreamingwrt.notifyd test_send",
                              "webd.dreamingwrt.notifyd");
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *notifyd_outbox(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;

        struct json_object *params = json_object_new_object();
        char value[512];

        if (webd_query_get(req.query, "state", value, sizeof(value)) && value[0])
            json_object_object_add(params, "state", json_object_new_string(value));
        if (webd_query_get(req.query, "search", value, sizeof(value)) && value[0])
            json_object_object_add(params, "search", json_object_new_string(value));
        if (webd_query_get(req.query, "cursor", value, sizeof(value)) && value[0])
            json_object_object_add(params, "cursor", json_object_new_string(value));
        if (webd_query_get(req.query, "limit", value, sizeof(value)) && value[0])
            json_object_object_add(params, "limit", json_object_new_int(atoi(value)));
        resp = app_ubus_object_or_error("dreamingwrt.notifyd", "outbox_list", params);
        json_object_put(params);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *notifyd_outbox_query(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.notifyd", "outbox_list", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *notifyd_outbox_retry(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.notifyd", "outbox_retry", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *notifyd_deliver_due(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.notifyd", "deliver_due", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

const struct jmx_api_route notifyd_api_routes[] = {
    JMX_API_ROUTE(117, "/api/v1/notifyd/status", "GET", JMX_API_EXACT, notifyd_status),
    JMX_API_ROUTE(118, "/api/v1/notifyd/events", "GET", JMX_API_EXACT, notifyd_events),
    JMX_API_ROUTE(119, "/api/v1/notifyd/settings", "GET", JMX_API_EXACT, notifyd_settings_get),
    JMX_API_ROUTE(120, "/api/v1/notifyd/settings", "POST,PUT,PATCH", JMX_API_EXACT, notifyd_settings_post),
    JMX_API_ROUTE(121, "/api/v1/notifyd/preferences/me", "GET,POST,PUT,PATCH", JMX_API_EXACT, notifyd_preferences_me),
    JMX_API_ROUTE(122, "/api/v1/notifyd/channels", "GET", JMX_API_EXACT, notifyd_channels_get),
    JMX_API_ROUTE(123, "/api/v1/notifyd/channels", "POST,PUT,PATCH", JMX_API_EXACT, notifyd_channels_post),
    JMX_API_ROUTE(125, "/api/v1/notifyd/routes", "GET", JMX_API_EXACT, notifyd_routes_get),
    JMX_API_ROUTE(126, "/api/v1/notifyd/triggers", "GET", JMX_API_EXACT, notifyd_triggers),
    JMX_API_ROUTE(127, "/api/v1/notifyd/routes", "POST,PUT,PATCH", JMX_API_EXACT, notifyd_routes_post),
    JMX_API_ROUTE(129, "/api/v1/notifyd/enqueue", "POST,PUT", JMX_API_EXACT, notifyd_enqueue),
    JMX_API_ROUTE(130, "/api/v1/notifyd/test-send", "POST", JMX_API_EXACT, notifyd_test_send),
    JMX_API_ROUTE(131, "/api/v1/notifyd/outbox", "GET", JMX_API_EXACT, notifyd_outbox),
    JMX_API_ROUTE(132, "/api/v1/notifyd/outbox/query", "POST,PUT", JMX_API_EXACT, notifyd_outbox_query),
    JMX_API_ROUTE(133, "/api/v1/notifyd/outbox/retry", "POST,PUT", JMX_API_EXACT, notifyd_outbox_retry),
    JMX_API_ROUTE(135, "/api/v1/notifyd/deliver-due", "POST", JMX_API_EXACT, notifyd_deliver_due),
    JMX_API_ROUTE_END,
};

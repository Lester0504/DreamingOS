// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Transactional config BFF (Phase 6S). The /api/v1/config/* surface: snapshot,
 * validate, apply, confirm, rollback, and last-apply. The core owns the
 * persistent truth; these handlers are thin BFF adapters. Each branch body moves
 * VERBATIM from jmx_app_api.c behind an alias preamble (req/body_json/device_id
 * as referenced; resp+status always), so no second implementation remains there.
 *
 * 6 single-exact routes (JMX_API_EXACT); snapshot and last-apply carry no method
 * check (any method, emitted as methods=""). No prefix and no multi-exact routes.
 *
 * Zero borrowed helpers: the moved bodies reach no static-in-main function, so
 * there is no api_config_internal.h. The jmx_config_* entry points they call are
 * declared in the public jmx_app_api.h (included as ../jmx_app_api.h); every
 * other symbol is already exported (app_jmx_response_*, app_nc_json_*, json-c).
 */
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>

#include "api_config.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_ubus.h"
#include "api_ports_internal.h"
#include "webd_http_req.h"
#include "../jmx_app_api.h"
#include "../../safeops/task_projection.h"
#include <time.h>
#include <sqlite3.h>

extern sqlite3 *g_app_db;

static int config_response_status(struct json_object *response, int status)
{
    struct json_object *code = NULL;
    if (response && json_object_object_get_ex(response, "code", &code) &&
        json_object_get_int(code) >= 400 && json_object_get_int(code) <= 599)
        return json_object_get_int(code);
    return app_response_status(response, status);
}

static struct json_object *config_network_call(const char *method, struct json_object *body)
{
    return app_ubus_invoke_timeout(method, body, 55000);
}

/* ── storage alias predicate (raid|raids) ── */


/* ── storage route handlers (verbatim bodies behind an alias preamble) ── */

static struct json_object *config_snapshot(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

    char domain[16] = "", id[96] = "";
    webd_query_get(ctx->req->query, "domain", domain, sizeof(domain));
    webd_query_get(ctx->req->query, "id", id, sizeof(id));
    if (!strcmp(domain, "vlan")) {
        resp = webd_port_vlan_snapshot(id, &status);
    } else if (domain[0]) {
        struct json_object *query = json_object_new_object();
        json_object_object_add(query, "domain", json_object_new_string(domain));
        json_object_object_add(query, "id", json_object_new_string(id));
        resp = config_network_call("network_transaction_get", query);
        json_object_put(query);
        status = config_response_status(resp, status);
    } else {
        resp = jmx_config_snapshot(body_json);
        struct json_object *data = NULL, *snapshot = NULL;
        if (resp && !json_object_object_get_ex(resp, "snapshot", &snapshot) &&
            json_object_object_get_ex(resp, "data", &data))
            json_object_object_get_ex(data, "snapshot", &snapshot);
        if (snapshot && json_object_is_type(snapshot, json_type_object))
            json_object_object_add(snapshot, "port_vlans", webd_port_vlan_resources());
    }

    ctx->status = status;
    return resp;
}

static struct json_object *config_validate(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

    if (body_json && !strcmp(app_nc_json_str(body_json, "domain", ""), "iptv"))
        json_object_object_add(body_json, "peer_ip", json_object_new_string(ctx->req->peer_ip));

        resp = !strcmp(app_nc_json_str(body_json, "domain", ""), "vlan") ?
            webd_port_vlan_request(ctx->req, body_json, 0, &status) :
            app_nc_json_str(body_json, "domain", "")[0] ?
            config_network_call("network_transaction_validate", body_json) :
            jmx_config_validate(body_json);
        status = config_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *config_apply(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        /* Inject the transport-observed origin into the request body so the
         * apply can record it in the preflight evidence blob without changing
         * the jmx_config_apply() signature (which internal callers share). */
        if (body_json) {
            if (!strcmp(app_nc_json_str(body_json, "domain", ""), "iptv"))
                json_object_object_add(body_json, "peer_ip", json_object_new_string(req.peer_ip));
            if (req.client_ip[0])
                json_object_object_add(body_json, "client_ip",
                                       json_object_new_string(req.client_ip));
            if (req.peer_ip[0])
                json_object_object_add(body_json, "peer_ip",
                                       json_object_new_string(req.peer_ip));
        }
        if (!strcmp(app_nc_json_str(body_json, "domain", ""), "vlan")) {
            resp = webd_port_vlan_request(ctx->req, body_json, 1, &status);
        } else if (app_nc_json_str(body_json, "domain", "")[0]) {
            resp = config_network_call("network_transaction_apply", body_json);
            status = config_response_status(resp, status);
            if (resp && app_nc_json_bool(resp, "ok", 0) &&
                app_nc_json_int(resp, "task_id", 0) > 0) {
                struct json_object *task = jmx_tasks_get(app_nc_json_int(resp, "task_id", 0));
                json_object_put(resp);
                resp = task;
            }
        } else {
            resp = jmx_config_apply(body_json);
        }
        safeops_task_clock(resp, (int64_t)time(NULL));
        status = config_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *config_confirm(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = jmx_config_confirm(body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *config_rollback(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = jmx_config_rollback(body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *config_last_apply(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

    char key[256] = "";
    webd_query_get(ctx->req->query, "idempotency_key", key, sizeof(key));
    if (key[0]) {
        sqlite3_stmt *st = NULL;
        int task_id = 0;
        if (sqlite3_prepare_v2(g_app_db,
            "SELECT id FROM config_apply_tasks WHERE idempotency_key=?1 ORDER BY id DESC LIMIT 1",
            -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(st) == SQLITE_ROW) task_id = sqlite3_column_int(st, 0);
            sqlite3_finalize(st);
            resp = task_id > 0 ? jmx_tasks_get(task_id) : json_object_new_object();
            json_object_object_add(resp, "found", json_object_new_boolean(task_id > 0));
            json_object_object_add(resp, "ok", json_object_new_boolean(1));
        } else {
            status = 503;
        }
    } else {
        resp = jmx_config_last_apply();
    }
        safeops_task_clock(resp, (int64_t)time(NULL));

    ctx->status = status;
    return resp;
}

const struct jmx_api_route config_api_routes[] = {
    JMX_API_ROUTE(557, "/api/v1/config/snapshot", "", JMX_API_EXACT, config_snapshot),
    JMX_API_ROUTE(558, "/api/v1/config/validate", "POST", JMX_API_EXACT, config_validate),
    JMX_API_ROUTE(559, "/api/v1/config/apply", "POST", JMX_API_EXACT, config_apply),
    JMX_API_ROUTE(560, "/api/v1/config/confirm", "POST", JMX_API_EXACT, config_confirm),
    JMX_API_ROUTE(561, "/api/v1/config/rollback", "POST", JMX_API_EXACT, config_rollback),
    JMX_API_ROUTE(562, "/api/v1/config/last-apply", "", JMX_API_EXACT, config_last_apply),
    JMX_API_ROUTE_END,
};

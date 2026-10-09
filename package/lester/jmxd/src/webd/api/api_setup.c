// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * First-run setup wizard BFF (Phase 6P). The /api/v1/setup/* surface: the wizard
 * status/progress, the save-* steps (device / wan / wifi), test-wan, apply,
 * finish, reset-wizard, support-bundle, detect-wan (start/status), assist-mode,
 * security (+ ssh), llm (+ status), and oauth (providers/start). The core owns
 * the persistent first-run truth; these handlers are thin BFF adapters. Each
 * branch body moves VERBATIM from jmx_app_api.c behind an alias preamble
 * (req/body_json/device_id as referenced; resp+status always), so no second
 * implementation remains there.
 *
 * 18 single-exact routes (JMX_API_EXACT) + 2 multi-exact alias routes
 * (detect-wan/start|detect_wan/start, detect-wan/status|detect_wan/status): the
 * hyphen/underscore spellings are one route each, emitted as a
 * JMX_API_PREDICATE_ROUTE + JMX_API_PREDICATE_ONLY whose predicate OR's the two
 * exact aliases, reproducing the legacy match byte-for-byte (all_paths=2,
 * match=exact). No prefix routes exist in the setup dispatch.
 *
 * TWO cross-domain OR branches STAY inline in jmx_app_api.c and are NOT part of
 * this module: save-lan|device/config/lan (POST,PUT) and
 * app-pairing/cancel|auth/pair/cancel (POST). device/config/lan and
 * auth/pair/cancel are also handled pre-auth (public-write / pairing blocks), so
 * the setup module deliberately does not take ownership of a device or auth path.
 *
 * Borrowed from jmx_app_api.c (definitions stay in main), de-static'd:
 * app_setup_finish_response, app_setup_oauth_response,
 * app_setup_security_response, app_setup_status_slice_response,
 * app_wifi_capability_disabled_response (declared in api_setup_internal.h), and
 * the generic jmx_app_audit_log_ex (declared in the public jmx_app_api.h beside
 * jmx_app_audit_log). Every other symbol these bodies use is already exported.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>

#include "api_setup.h"
#include "api_setup_internal.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_ubus.h"
#include "webd_http_req.h"
#include "../ai_oauth.h"
#include "../jmx_app_api.h"
#include "../../storage/data_storage.h"

/* ── setup alias predicates (multi-exact hyphen/underscore spellings) ── */

static int setup_detect_wan_start_path(const char *path)
{
    return path &&
           (!strcmp(path, "/api/v1/setup/detect-wan/start") ||
            !strcmp(path, "/api/v1/setup/detect_wan/start"));
}

static int setup_detect_wan_status_path(const char *path)
{
    return path &&
           (!strcmp(path, "/api/v1/setup/detect-wan/status") ||
            !strcmp(path, "/api/v1/setup/detect_wan/status"));
}

/* ── setup wizard route handlers (verbatim bodies behind an alias preamble) ── */

static struct json_object *setup_status(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_or_error("setup_status", body_json);

    ctx->status = status;
    return resp;
}

static struct json_object *setup_start(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_or_error("setup_start", body_json);
        status = app_jmx_response_http_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *setup_save_device(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_or_error("setup_save_device", body_json);
        status = app_jmx_response_http_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *setup_save_wan(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_or_error("setup_save_wan", body_json);
        status = app_jmx_response_http_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *setup_test_wan(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_or_error("setup_test_wan", body_json);
        status = app_jmx_response_http_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *setup_save_wifi(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        status = 409;
        resp = app_wifi_capability_disabled_response(
            "save_config", "transactional_secret_safe_save_pending");

    ctx->status = status;
    return resp;
}

static struct json_object *setup_apply(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_or_error("setup_apply", body_json);
        status = app_jmx_response_http_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *setup_progress(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_or_error("setup_progress", body_json);

    ctx->status = status;
    return resp;
}

static struct json_object *setup_finish(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        char finish_actor[192];

        if (webd_identity_is_user(device_id))
            snprintf(finish_actor, sizeof(finish_actor), "web:%s",
                     webd_identity_username(device_id));
        else
            snprintf(finish_actor, sizeof(finish_actor), "app:%s", device_id);
        resp = app_setup_finish_response(body_json, finish_actor, &status);

    ctx->status = status;
    return resp;
}

static struct json_object *setup_reset_wizard(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        /*
         * reset_wizard is the one setup write that must still work on an
         * initialized router -- that is its purpose -- so the core asks for a
         * dedicated intent flag instead of refusing. This route already required
         * an authenticated session and a JMX_RISK_HIGH check, so the intent is
         * established and asserted here rather than pushed onto the API.
         */
        if (!body_json)
            body_json = json_object_new_object();
        if (body_json && json_object_is_type(body_json, json_type_object))
            json_object_object_add(body_json, "confirm_reset_initialized",
                                   json_object_new_boolean(1));
        resp = app_ubus_or_error("setup_reset_wizard", body_json);
        status = app_jmx_response_http_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *setup_support_bundle(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_or_error("setup_support_bundle", body_json);
        status = app_jmx_response_http_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *setup_detect_wan_start(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_or_error("setup_detect_wan_start", body_json);
        status = app_jmx_response_http_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *setup_detect_wan_status(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_or_error("setup_detect_wan_status", body_json);

    ctx->status = status;
    return resp;
}

static struct json_object *setup_assist_mode(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_or_error("setup_assist_mode", body_json);
        status = app_jmx_response_http_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *setup_security(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        resp = app_setup_security_response();
        status = app_jmx_response_http_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *setup_security_ssh(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_or_error("setup_security_ssh_set", body_json);
        status = app_jmx_response_http_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *setup_llm_status(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        resp = app_setup_status_slice_response("llm");
        status = app_jmx_response_http_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *setup_llm(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_ai_ok_envelope("ai_config_set", body_json);
        status = app_jmx_response_http_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *setup_oauth_providers(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        resp = app_setup_oauth_response();
        status = app_jmx_response_http_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *setup_oauth_start(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        resp = webd_ai_oauth_start(body_json, device_id, &status);
        jmx_app_audit_log_ex(device_id, device_id, "setup.oauth.start", "medium",
                             app_nc_json_str(body_json, "provider", ""), req.client_ip,
                             status >= 200 && status < 300 ? "success" : "failed",
                             status >= 200 && status < 300 ? "" : "oauth_start_failed");

    ctx->status = status;
    return resp;
}

static struct json_object *setup_import_config_start(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    struct json_object *d = NULL, *err = NULL;

        resp = app_ubus_or_error("setup_import_config_start", body_json);
        status = app_jmx_response_http_status(resp, status);
        /* capability_disabled -> 409, aligning the services/nfs capability pattern */
        if (resp && json_object_object_get_ex(resp, "data", &d) && d &&
            json_object_object_get_ex(d, "error", &err) && err &&
            !strcmp(json_object_get_string(err), "capability_disabled"))
            status = 409;

    ctx->status = status;
    return resp;
}

static struct json_object *setup_import_config_status(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    struct json_object *tmp = NULL;
    char sid[64] = "";

        if (ctx->req)
            webd_query_get(ctx->req->query, "session_id", sid, sizeof(sid));
        if (sid[0]) {
            if (!body_json || !json_object_is_type(body_json, json_type_object))
                body_json = tmp = json_object_new_object();
            json_object_object_add(body_json, "session_id", json_object_new_string(sid));
        }
        resp = app_ubus_or_error("setup_import_config_status", body_json);
        if (tmp)
            json_object_put(tmp);

    ctx->status = status;
    return resp;
}

static struct json_object *setup_import_config_stop(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_or_error("setup_import_config_stop", body_json);
        status = app_jmx_response_http_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *setup_storage(struct jmx_api_ctx *ctx)
{
    if (!strcmp(ctx->req->method, "GET"))
        return data_storage_response(NULL, &ctx->status);
    struct json_object *body = ctx->body ? json_object_get(ctx->body) : json_object_new_object();
    struct json_object *out = data_storage_response(body, &ctx->status);
    json_object_put(body);
    return out;
}

const struct jmx_api_route setup_api_routes[] = {
    JMX_API_ROUTE(1450, "/api/v1/setup/storage", "GET,POST", JMX_API_EXACT, setup_storage),
    JMX_API_ROUTE(48, "/api/v1/setup/status", "GET", JMX_API_EXACT, setup_status),
    JMX_API_ROUTE(49, "/api/v1/setup/start", "POST", JMX_API_EXACT, setup_start),
    JMX_API_ROUTE(50, "/api/v1/setup/save-device", "POST,PUT", JMX_API_EXACT, setup_save_device),
    JMX_API_ROUTE(51, "/api/v1/setup/save-wan", "POST,PUT", JMX_API_EXACT, setup_save_wan),
    JMX_API_ROUTE(52, "/api/v1/setup/test-wan", "POST", JMX_API_EXACT, setup_test_wan),
    JMX_API_ROUTE(54, "/api/v1/setup/save-wifi", "POST,PUT", JMX_API_EXACT, setup_save_wifi),
    JMX_API_ROUTE(55, "/api/v1/setup/apply", "POST", JMX_API_EXACT, setup_apply),
    JMX_API_ROUTE(56, "/api/v1/setup/progress", "GET", JMX_API_EXACT, setup_progress),
    JMX_API_ROUTE(57, "/api/v1/setup/finish", "POST", JMX_API_EXACT, setup_finish),
    JMX_API_ROUTE(58, "/api/v1/setup/reset-wizard", "POST", JMX_API_EXACT, setup_reset_wizard),
    JMX_API_ROUTE(59, "/api/v1/setup/support-bundle", "POST", JMX_API_EXACT, setup_support_bundle),
    JMX_API_PREDICATE_ROUTE(60, "/api/v1/setup/detect-wan/start", "POST", JMX_API_PREDICATE_ONLY, setup_detect_wan_start_path, setup_detect_wan_start),
    JMX_API_PREDICATE_ROUTE(61, "/api/v1/setup/detect-wan/status", "GET", JMX_API_PREDICATE_ONLY, setup_detect_wan_status_path, setup_detect_wan_status),
    JMX_API_ROUTE(62, "/api/v1/setup/assist-mode", "POST,PUT", JMX_API_EXACT, setup_assist_mode),
    JMX_API_ROUTE(63, "/api/v1/setup/security", "GET", JMX_API_EXACT, setup_security),
    JMX_API_ROUTE(64, "/api/v1/setup/security/ssh", "POST,PUT", JMX_API_EXACT, setup_security_ssh),
    JMX_API_ROUTE(65, "/api/v1/setup/llm/status", "GET", JMX_API_EXACT, setup_llm_status),
    JMX_API_ROUTE(66, "/api/v1/setup/llm", "POST,PUT", JMX_API_EXACT, setup_llm),
    JMX_API_ROUTE(67, "/api/v1/setup/oauth/providers", "GET", JMX_API_EXACT, setup_oauth_providers),
    JMX_API_ROUTE(68, "/api/v1/setup/oauth/start", "POST", JMX_API_EXACT, setup_oauth_start),
    JMX_API_ROUTE(913, "/api/v1/setup/import-config/start", "POST", JMX_API_EXACT, setup_import_config_start),
    JMX_API_ROUTE(914, "/api/v1/setup/import-config/status", "GET", JMX_API_EXACT, setup_import_config_status),
    JMX_API_ROUTE(915, "/api/v1/setup/import-config/stop", "POST", JMX_API_EXACT, setup_import_config_stop),
    JMX_API_ROUTE_END,
};

/* -- Setup response builders (Phase 7X) --------------------------------------
 * The first-run status slice, OAuth catalog, security summary, and finish
 * response builders, lifted verbatim out of jmx_app_api.c. handle_client and
 * the setup BFF adapters above dispatch these; none is a jmx_api_route table
 * row, so no route moved. Declared in api_setup_internal.h. The 2FA prepare/
 * enable builders stay static in jmx_app_api.c (contract-pinned there).
 */
struct json_object *app_setup_status_slice_response(const char *field)
{
    struct json_object *upstream = app_ubus_or_error("setup_status", NULL);
    struct json_object *data = webd_data_from_jmx_response(upstream);
    struct json_object *slice = NULL;
    struct json_object *resp;

    if (data && field && json_object_object_get_ex(data, field, &slice) && slice) {
        resp = app_jmx_response_data(APP_API_CODE_SUCCESS, json_object_get(slice));
    } else if (!data && upstream) {
        resp = json_object_get(upstream);
    } else {
        struct json_object *err = json_object_new_object();
        json_object_object_add(err, "ok", json_object_new_boolean(0));
        json_object_object_add(err, "error", json_object_new_string("source_unavailable"));
        json_object_object_add(err, "message", json_object_new_string("setup status slice is not available"));
        json_object_object_add(err, "field", json_object_new_string(field ? field : ""));
        resp = app_jmx_response_data(APP_API_CODE_ERROR, err);
    }
    if (data)
        json_object_put(data);
    if (upstream)
        json_object_put(upstream);
    return resp;
}

struct json_object *app_setup_oauth_response(void)
{
    struct json_object *catalog = webd_ai_oauth_catalog();
    json_object_object_add(catalog, "available", json_object_new_boolean(1));
    return app_jmx_response_data(APP_API_CODE_SUCCESS, catalog);
}

struct json_object *app_setup_security_response(void)
{
    struct json_object *upstream = app_ubus_or_error("setup_status", NULL);
    struct json_object *data = webd_data_from_jmx_response(upstream);
    struct json_object *security = NULL;
    struct json_object *app_pairing = NULL;
    struct json_object *out = json_object_new_object();
    struct json_object *resp;

    if (data && json_object_object_get_ex(data, "security", &security) && security)
        json_object_object_add(out, "security", json_object_get(security));
    else
        json_object_object_add(out, "security", json_object_new_object());
    if (data && json_object_object_get_ex(data, "app_pairing", &app_pairing) && app_pairing)
        json_object_object_add(out, "app_pairing", json_object_get(app_pairing));
    else
        json_object_object_add(out, "app_pairing", json_object_new_object());
    if (data) {
        resp = app_jmx_response_data(APP_API_CODE_SUCCESS, out);
    } else if (upstream) {
        json_object_put(out);
        resp = json_object_get(upstream);
    } else {
        resp = app_jmx_response_data(APP_API_CODE_ERROR, out);
    }
    if (data)
        json_object_put(data);
    if (upstream)
        json_object_put(upstream);
    return resp;
}

struct json_object *app_setup_finish_response(
    struct json_object *body, const char *setup_actor, int *status)
{
    struct json_object *request = body ? webd_json_clone(body) :
                                        json_object_new_object();
    struct json_object *finish = NULL;
    struct json_object *readback = NULL;
    struct json_object *state = NULL;
    const char *finished_by;
    const char *version;
    int64_t finished_at;

    if (status)
        *status = 500;
    if (!request || !setup_actor || !setup_actor[0])
        goto unavailable;
    json_object_object_del(request, "completed_by");
    json_object_object_del(request, "actor");
    json_object_object_del(request, "version");
    json_object_object_add(request, "completed_by",
                           json_object_new_string(setup_actor));
    json_object_object_add(request, "actor", json_object_new_string(setup_actor));
    finish = app_ubus_or_error("setup_finish", request);
    json_object_put(request);
    request = NULL;
    if (!app_ubus_response_ok(finish)) {
        if (status) *status = app_jmx_response_http_status(finish, 400);
        return finish;
    }
    readback = app_ubus_or_error("setup_status", NULL);
    state = webd_data_from_jmx_response(readback);
    finished_at = app_nc_json_int64(state, "setup_finished_at", 0);
    finished_by = app_nc_json_str(state, "setup_finished_by", "");
    version = app_nc_json_str(state, "setup_version", "");
    if (!state || !app_nc_json_bool(state, "initialized", 0) ||
        finished_at <= 0 || strcmp(finished_by, setup_actor) || !version[0]) {
        if (finish) json_object_put(finish);
        if (state) json_object_put(state);
        if (readback) json_object_put(readback);
        if (status) *status = 503;
        return app_setup_session_error_response(
            "setup_finish_readback_mismatch",
            "setup completion was not confirmed by its persisted readback");
    }
    json_object_object_add(state, "finish_readback_verified",
                           json_object_new_boolean(1));
    if (finish) json_object_put(finish);
    if (readback) json_object_put(readback);
    if (status) *status = 200;
    return app_jmx_response_data(APP_API_CODE_SUCCESS, state);

unavailable:
    if (request) json_object_put(request);
    if (finish) json_object_put(finish);
    return app_setup_session_error_response(
        "setup_finish_request_failed", "setup completion request could not be created");
}

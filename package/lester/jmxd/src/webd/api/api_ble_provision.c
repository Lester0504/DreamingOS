// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#include <ctype.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>

#include "api_ble_provision.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_ubus.h"

#define BLE_PROVISION_SOURCE "webd.ac_ble_provision"
#define BLE_PROVISION_OBJECT "dreamingwrt.apd"
#define BLE_SESSION_HEX_LEN 32U
#define BLE_PUBLIC_KEY_HEX_LEN 64U

static int ble_hex_string(const char *text, size_t want)
{
    size_t i;

    if (!text || strlen(text) != want)
        return 0;
    for (i = 0; i < want; i++) {
        if (!isxdigit((unsigned char)text[i]))
            return 0;
    }
    return 1;
}

static int ble_uuid_string(const char *text)
{
    static const unsigned char hyphen[] = { 8, 13, 18, 23 };
    size_t i;
    size_t h = 0;

    if (!text || strlen(text) != 36)
        return 0;
    for (i = 0; i < 36; i++) {
        if (h < sizeof(hyphen) && i == hyphen[h]) {
            if (text[i] != '-')
                return 0;
            h++;
        } else if (!isxdigit((unsigned char)text[i])) {
            return 0;
        }
    }
    return h == sizeof(hyphen);
}

static int ble_body_object(const struct jmx_api_ctx *ctx)
{
    return ctx && ctx->body && json_object_is_type(ctx->body, json_type_object);
}

static int ble_body_allowed(const struct jmx_api_ctx *ctx,
                            const char *const *allowed, size_t allowed_count)
{
    json_object_object_foreach(ctx->body, key, value) {
        size_t i;
        int known = 0;

        (void)value;
        for (i = 0; i < allowed_count; i++) {
            if (!strcmp(key, allowed[i])) {
                known = 1;
                break;
            }
        }
        if (!known)
            return 0;
    }
    return 1;
}

static const char *ble_body_string(const struct jmx_api_ctx *ctx,
                                   const char *key)
{
    struct json_object *value = NULL;

    if (!ble_body_object(ctx) ||
        !json_object_object_get_ex(ctx->body, key, &value) || !value ||
        !json_object_is_type(value, json_type_string))
        return NULL;
    return json_object_get_string(value);
}

static int ble_query_session(const struct jmx_api_ctx *ctx,
                             char out[BLE_SESSION_HEX_LEN + 1])
{
    const char *query = ctx && ctx->req ? ctx->req->query : NULL;
    const char *p;
    int found = 0;

    if (!query || !query[0] || !out)
        return 0;
    p = query;
    while (*p) {
        const char *end = strchr(p, '&');
        const char *eq;
        size_t name_len;
        char name[32];

        if (!end)
            end = p + strlen(p);
        eq = memchr(p, '=', (size_t)(end - p));
        name_len = (size_t)((eq ? eq : end) - p);
        if (name_len == 0 || name_len >= sizeof(name))
            return 0;
        memcpy(name, p, name_len);
        name[name_len] = '\0';
        if (strcmp(name, "session_id"))
            return 0;
        if (found || !eq)
            return 0;
        webd_query_decode(eq + 1, (size_t)(end - (eq + 1)), out,
                          BLE_SESSION_HEX_LEN + 1);
        found = 1;
        p = *end ? end + 1 : end;
    }
    return found && ble_hex_string(out, BLE_SESSION_HEX_LEN);
}

static int ble_error_status(const char *code)
{
    if (!code || !code[0])
        return 502;
    if (!strcmp(code, "session_not_found"))
        return 404;
    if (!strcmp(code, "setup_code_invalid") ||
        !strcmp(code, "invalid_argument") ||
        !strcmp(code, "invalid_bootstrap_id") ||
        !strcmp(code, "invalid_request_id") ||
        !strcmp(code, "invalid_app_public_key") ||
        !strcmp(code, "invalid_ble_peripheral_id") ||
        !strcmp(code, "unsupported_protocol"))
        return 400;
    if (!strcmp(code, "attempt_limit_exceeded"))
        return 429;
    if (!strcmp(code, "physical_auth_required") ||
        !strcmp(code, "commit_not_allowed") ||
        !strcmp(code, "commit_started") ||
        !strcmp(code, "handshake_required") ||
        !strcmp(code, "session_expired") ||
        !strcmp(code, "session_already_active") ||
        !strcmp(code, "target_ap_mismatch") ||
        !strcmp(code, "busy"))
        return 409;
    if (!strcmp(code, "physical_auth_unavailable") ||
        !strcmp(code, "database_unavailable") ||
        !strcmp(code, "config_executor_unavailable") ||
        !strcmp(code, "bootstrap_identity_unavailable") ||
        !strcmp(code, "target_ap_unreachable") ||
        !strcmp(code, "unavailable") ||
        !strcmp(code, "source_unavailable"))
        return 503;
    return 400;
}

static struct json_object *ble_response(struct jmx_api_ctx *ctx,
                                        struct json_object *upstream,
                                        const char *method)
{
    const char *code = NULL;
    struct json_object *code_value = NULL;
    struct json_object *error;

    if (!upstream) {
        /* These routes only ever reach the apd on THIS host, and there is no
         * AP-to-AP relay: an AC has no apd at all, and an unadopted AP has no
         * IP for webd to reach.  So an absent backend means the AP the caller
         * asked for cannot be reached from here -- say that with a stable code
         * instead of a generic backend error, because the app's correct next
         * move is to provision over BLE, not to retry the HTTP route. */
        ctx->status = 503;
        return webd_error("target_ap_unreachable",
                          "No BLE provisioning backend on this host for the requested AP",
                          method, BLE_PROVISION_SOURCE);
    }
    if (app_ubus_response_ok(upstream)) {
        json_object_object_del(upstream, "ok");
        return webd_envelope(upstream, BLE_PROVISION_SOURCE);
    }
    code = app_ubus_response_error_code(upstream);
    if ((!code || !strcmp(code, "backend_rejected")) &&
        json_object_object_get_ex(upstream, "code", &code_value) &&
        code_value && json_object_is_type(code_value, json_type_string))
        code = json_object_get_string(code_value);
    if (!code || !code[0])
        code = "backend_rejected";
    ctx->status = ble_error_status(code);
    error = webd_error(code, "BLE provisioning request was rejected",
                       method, BLE_PROVISION_SOURCE);
    json_object_put(upstream);
    return error;
}

static struct json_object *ble_invalid(struct jmx_api_ctx *ctx,
                                       const char *detail)
{
    ctx->status = 400;
    return webd_error("invalid_argument", "Invalid BLE provisioning request",
                      detail, BLE_PROVISION_SOURCE);
}

static struct json_object *ble_begin(struct jmx_api_ctx *ctx)
{
    static const char *const allowed[] = {
        "bootstrap_id", "request_id", "app_public_key", "ble_peripheral_id"
    };
    const char *bootstrap_id;
    const char *request_id;
    const char *app_public_key;
    const char *peripheral_id;
    struct json_object *upstream;

    if (!ble_body_object(ctx) ||
        !ble_body_allowed(ctx, allowed, sizeof(allowed) / sizeof(allowed[0])))
        return ble_invalid(ctx, "begin.body.fields");
    bootstrap_id = ble_body_string(ctx, "bootstrap_id");
    request_id = ble_body_string(ctx, "request_id");
    app_public_key = ble_body_string(ctx, "app_public_key");
    peripheral_id = ble_body_string(ctx, "ble_peripheral_id");
    if (!ble_uuid_string(bootstrap_id) || !ble_uuid_string(request_id) ||
        !ble_hex_string(app_public_key, BLE_PUBLIC_KEY_HEX_LEN) ||
        !ble_uuid_string(peripheral_id))
        return ble_invalid(ctx, "begin.body.values");
    upstream = app_ubus_route_or_error(BLE_PROVISION_OBJECT,
                                       "ble_provision_begin", ctx->body,
                                       4000, &ctx->status);
    return ble_response(ctx, upstream, "dreamingwrt.apd ble_provision_begin");
}

static struct json_object *ble_physical_confirm(struct jmx_api_ctx *ctx)
{
    static const char *const allowed[] = { "session_id", "setup_code" };
    const char *session_id;
    const char *setup_code;
    struct json_object *upstream;

    if (!ble_body_object(ctx) ||
        !ble_body_allowed(ctx, allowed, sizeof(allowed) / sizeof(allowed[0])))
        return ble_invalid(ctx, "physical-confirm.body.fields");
    session_id = ble_body_string(ctx, "session_id");
    setup_code = ble_body_string(ctx, "setup_code");
    if (!ble_hex_string(session_id, BLE_SESSION_HEX_LEN) ||
        !setup_code || !setup_code[0] || strlen(setup_code) > 64)
        return ble_invalid(ctx, "physical-confirm.body.values");
    upstream = app_ubus_route_or_error(BLE_PROVISION_OBJECT,
                                       "ble_provision_physical_confirm",
                                       ctx->body, 4000, &ctx->status);
    return ble_response(ctx, upstream,
                        "dreamingwrt.apd ble_provision_physical_confirm");
}

static struct json_object *ble_status(struct jmx_api_ctx *ctx)
{
    char requested[BLE_SESSION_HEX_LEN + 1];
    struct json_object *upstream;
    struct json_object *value = NULL;
    const char *actual;

    if (!ble_query_session(ctx, requested))
        return ble_invalid(ctx, "status.query");
    upstream = app_ubus_route_or_error(BLE_PROVISION_OBJECT,
                                       "ble_provision_status", NULL,
                                       3000, &ctx->status);
    if (!upstream)
        return ble_response(ctx, upstream, "dreamingwrt.apd ble_provision_status");
    if (!app_ubus_response_ok(upstream))
        return ble_response(ctx, upstream, "dreamingwrt.apd ble_provision_status");
    if (!json_object_object_get_ex(upstream, "session_id", &value) || !value ||
        !json_object_is_type(value, json_type_string) ||
        !(actual = json_object_get_string(value)) || strcasecmp(actual, requested)) {
        json_object_put(upstream);
        ctx->status = 404;
        return webd_error("session_not_found", "BLE provisioning session was not found",
                          "session_id", BLE_PROVISION_SOURCE);
    }
    json_object_object_del(upstream, "ok");
    return webd_envelope(upstream, BLE_PROVISION_SOURCE);
}

static struct json_object *ble_session_action(struct jmx_api_ctx *ctx,
                                              const char *method,
                                              const char *detail)
{
    static const char *const allowed[] = { "session_id" };
    const char *session_id;
    struct json_object *upstream;

    if (!ble_body_object(ctx) ||
        !ble_body_allowed(ctx, allowed, sizeof(allowed) / sizeof(allowed[0])))
        return ble_invalid(ctx, detail);
    session_id = ble_body_string(ctx, "session_id");
    if (!ble_hex_string(session_id, BLE_SESSION_HEX_LEN))
        return ble_invalid(ctx, detail);
    upstream = app_ubus_route_or_error(BLE_PROVISION_OBJECT, method,
                                       ctx->body, 10000, &ctx->status);
    return ble_response(ctx, upstream, detail);
}

static struct json_object *ble_commit(struct jmx_api_ctx *ctx)
{
    return ble_session_action(ctx, "ble_provision_commit",
                              "dreamingwrt.apd ble_provision_commit");
}

static struct json_object *ble_cancel(struct jmx_api_ctx *ctx)
{
    return ble_session_action(ctx, "ble_provision_cancel",
                              "dreamingwrt.apd ble_provision_cancel");
}

const struct jmx_api_route ble_provision_api_routes[] = {
    JMX_API_ROUTE(753, "/api/v1/ac/ble-provision/begin", "POST", JMX_API_EXACT, ble_begin),
    JMX_API_ROUTE(754, "/api/v1/ac/ble-provision/physical-confirm", "POST", JMX_API_EXACT, ble_physical_confirm),
    JMX_API_ROUTE(755, "/api/v1/ac/ble-provision/status", "GET", JMX_API_EXACT, ble_status),
    JMX_API_ROUTE(756, "/api/v1/ac/ble-provision/commit", "POST", JMX_API_EXACT, ble_commit),
    JMX_API_ROUTE(757, "/api/v1/ac/ble-provision/cancel", "POST", JMX_API_EXACT, ble_cancel),
    JMX_API_ROUTE_END,
};

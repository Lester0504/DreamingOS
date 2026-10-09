// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Authentication / captive-portal BFF (Phase 6L). The /api/v1/authentication/*
 * read/write surface: aggregate/web/portal config, access-rules, online-users,
 * accounts (+ bulk/import/password-policy), ledger, packages, vouchers,
 * delegated-services and the notifications lifecycle. Authd owns the persistent
 * truth; these handlers are thin BFF adapters onto the dreamingwrt.authd ubus
 * object. Each branch body moves VERBATIM from jmx_app_api.c behind an alias
 * preamble (req/body_json/device_id as referenced; resp+status always), so no
 * second implementation remains there and the audit semantics — encapsulated
 * inside app_authentication_write — are byte-for-byte preserved.
 *
 * The notifications realtime|expiry|expired PUT branch matched three exact paths,
 * so it is one JMX_API_PREDICATE_ROUTE with JMX_API_PREDICATE_ONLY: the predicate
 * carries the three exact aliases and the matcher resolves any of them — one
 * physical row, one inventory 'exact' route with all_paths=3 (net-zero).
 *
 * The seven `sizeof("...")-1` id-detail prefix branches (access-rules/,
 * delegated-services/, notifications/periodic/, packages/, accounts/, ledger/,
 * vouchers/) stay inline in jmx_app_api.c: they are id-detail PUT/PATCH/DELETE
 * fall-throughs, and the router dispatches every module EXACT route before main's
 * inline PREFIX chain, so exact-before-prefix precedence is preserved.
 *
 * Borrowed from jmx_app_api.c (declared in api_authentication_internal.h; the
 * definition stays in main with its 14 inline callers): app_authentication_write,
 * de-static'd. Every other symbol these bodies use is already exported from
 * api_json.c / api_error.c / api_ubus.c / api_request.c.
 */
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>

#include "api_authentication.h"
#include "api_authentication_internal.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_ubus.h"
#include "webd_http_req.h"
#include "../jmx_app_api.h"

/* ── authentication route handlers (verbatim bodies behind an alias preamble) ── */

static struct json_object *auth(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.authd", "aggregate_get", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *auth_web_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.authd", "web_get", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *auth_web_put(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        resp = app_authentication_write("web_set", body_json, "web", 0,
                                        device_id, &status);

    ctx->status = status;
    return resp;
}

static struct json_object *auth_web_portal_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.authd", "portal_get", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *auth_web_portal_put(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        resp = app_authentication_write("portal_set", body_json, "portal", 0,
                                        device_id, &status);

    ctx->status = status;
    return resp;
}

static struct json_object *auth_web_access_rules_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        struct json_object *upstream = app_ubus_object_or_error("dreamingwrt.authd", "web_get", body_json);
        if (!upstream || !app_nc_json_bool(upstream, "ok", 0)) {
            resp = upstream ? upstream : webd_error("source_unavailable",
                "authentication service unavailable", "dreamingwrt.authd", "webd.authentication");
            status = app_response_status(resp, 503);
        } else {
        struct json_object *data = webd_data_or_self_from_jmx_response(upstream);
        struct json_object *rules = data ? webd_obj_child_array(data, "access_rules") : NULL;
        struct json_object *result = json_object_new_object();
        json_object_object_add(result, "items", rules ? json_object_get(rules) : json_object_new_array());
        json_object_object_add(result, "capabilities", data && webd_obj_child_obj(data, "capabilities") ?
                               json_object_get(webd_obj_child_obj(data, "capabilities")) :
                               json_object_new_object());
        json_object_object_add(result, "source", json_object_new_string("dreamingwrt.authd"));
        if (data) json_object_put(data);
        if (upstream) json_object_put(upstream);
        resp = webd_envelope(result, "dreamingwrt.authd");
        }

    ctx->status = status;
    return resp;
}

static struct json_object *auth_web_access_rules_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        resp = app_authentication_write("access_rule_upsert", body_json, NULL, 0,
                                        device_id, &status);

    ctx->status = status;
    return resp;
}

static struct json_object *auth_online_users(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;

        struct json_object *params = json_object_new_object();
        char value[32];
        if (webd_query_get(req.query, "limit", value, sizeof(value)) && value[0])
            json_object_object_add(params, "limit", json_object_new_int(atoi(value)));
        if (webd_query_get(req.query, "offset", value, sizeof(value)) && value[0])
            json_object_object_add(params, "offset", json_object_new_int(atoi(value)));
        resp = app_ubus_object_or_error("dreamingwrt.authd", "online_users_get", params);
        json_object_put(params);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *auth_accounts_get(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;

        struct json_object *params = json_object_new_object();
        char value[32];
        if (webd_query_get(req.query, "limit", value, sizeof(value)) && value[0])
            json_object_object_add(params, "limit", json_object_new_int(atoi(value)));
        if (webd_query_get(req.query, "offset", value, sizeof(value)) && value[0])
            json_object_object_add(params, "offset", json_object_new_int(atoi(value)));
        resp = app_ubus_object_or_error("dreamingwrt.authd", "accounts_get", params);
        json_object_put(params);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *auth_ledger_get(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;

        struct json_object *params = json_object_new_object();
        char value[32];
        if (webd_query_get(req.query, "limit", value, sizeof(value)) && value[0])
            json_object_object_add(params, "limit", json_object_new_int(atoi(value)));
        if (webd_query_get(req.query, "offset", value, sizeof(value)) && value[0])
            json_object_object_add(params, "offset", json_object_new_int(atoi(value)));
        resp = app_ubus_object_or_error("dreamingwrt.authd", "ledger_get", params);
        json_object_put(params);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *auth_packages_get(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;

        struct json_object *params = json_object_new_object();
        char value[32];
        if (webd_query_get(req.query, "limit", value, sizeof(value)) && value[0])
            json_object_object_add(params, "limit", json_object_new_int(atoi(value)));
        if (webd_query_get(req.query, "offset", value, sizeof(value)) && value[0])
            json_object_object_add(params, "offset", json_object_new_int(atoi(value)));
        resp = app_ubus_object_or_error("dreamingwrt.authd", "packages_get", params);
        json_object_put(params);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *auth_vouchers_get(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;

        struct json_object *params = json_object_new_object();
        char value[32];
        if (webd_query_get(req.query, "limit", value, sizeof(value)) && value[0])
            json_object_object_add(params, "limit", json_object_new_int(atoi(value)));
        if (webd_query_get(req.query, "offset", value, sizeof(value)) && value[0])
            json_object_object_add(params, "offset", json_object_new_int(atoi(value)));
        resp = app_ubus_object_or_error("dreamingwrt.authd", "vouchers_get", params);
        json_object_put(params);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *auth_delegated_services_get(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;

        struct json_object *params = json_object_new_object();
        char value[32];
        if (webd_query_get(req.query, "limit", value, sizeof(value)) && value[0])
            json_object_object_add(params, "limit", json_object_new_int(atoi(value)));
        if (webd_query_get(req.query, "offset", value, sizeof(value)) && value[0])
            json_object_object_add(params, "offset", json_object_new_int(atoi(value)));
        resp = app_ubus_object_or_error("dreamingwrt.authd", "delegated_get", params);
        json_object_put(params);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *auth_delegated_services_import(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        resp = app_authentication_write("delegated_import", body_json, "import", 0,
                                        device_id, &status);

    ctx->status = status;
    return resp;
}

static struct json_object *auth_delegated_services_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        resp = app_authentication_write("delegated_upsert", body_json, NULL, 0,
                                        device_id, &status);

    ctx->status = status;
    return resp;
}

static struct json_object *auth_notifications(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.authd", "notifications_get", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *auth_notifications_preview(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.authd", "notification_preview", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *auth_notifications_periodic(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        resp = app_authentication_write("notification_schedule_upsert", body_json, NULL, 0,
                                        device_id, &status);

    ctx->status = status;
    return resp;
}

static struct json_object *auth_packages_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        resp = app_authentication_write("package_upsert", body_json, NULL, 0,
                                        device_id, &status);

    ctx->status = status;
    return resp;
}

static struct json_object *auth_accounts_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        resp = app_authentication_write("account_upsert", body_json, NULL, 0,
                                        device_id, &status);

    ctx->status = status;
    return resp;
}

static struct json_object *auth_accounts_bulk(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        resp = app_authentication_write("accounts_bulk", body_json, NULL, 0,
                                        device_id, &status);

    ctx->status = status;
    return resp;
}

static struct json_object *auth_accounts_import(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        resp = app_authentication_write("accounts_import", body_json, NULL, 0,
                                        device_id, &status);

    ctx->status = status;
    return resp;
}

static struct json_object *auth_accounts_password_policy(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        resp = app_authentication_write("password_policy_set", body_json, NULL, 0,
                                        device_id, &status);

    ctx->status = status;
    return resp;
}

static struct json_object *auth_ledger_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        resp = app_authentication_write("ledger_upsert", body_json, NULL, 0,
                                        device_id, &status);

    ctx->status = status;
    return resp;
}

static struct json_object *auth_vouchers_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        resp = app_authentication_write("voucher_create", body_json, NULL, 0,
                                        device_id, &status);

    ctx->status = status;
    return resp;
}

static struct json_object *auth_vouchers_expired(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    const char *device_id = ctx->device_id;

        resp = app_authentication_write("vouchers_expired_delete", NULL, "expired", 0,
                                        device_id, &status);

    ctx->status = status;
    return resp;
}

static struct json_object *auth_notifications_kind_set(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        const char *kind = strrchr(req.path, '/');
        struct json_object *params = app_json_id_payload(kind ? kind + 1 : "", body_json);
        json_object_object_add(params, "kind", json_object_new_string(kind ? kind + 1 : ""));
        resp = app_authentication_write("notification_set", params, kind ? kind + 1 : "", 0,
                                        device_id, &status);
        json_object_put(params);

    ctx->status = status;
    return resp;
}

/* ── notifications kind predicate (realtime|expiry|expired, one 'exact' route) ── */

static int auth_notifications_kind_path(const char *path)
{
    return path &&
           (!strcmp(path, "/api/v1/authentication/notifications/realtime") ||
            !strcmp(path, "/api/v1/authentication/notifications/expiry") ||
            !strcmp(path, "/api/v1/authentication/notifications/expired"));
}

const struct jmx_api_route authentication_api_routes[] = {
    JMX_API_ROUTE(79, "/api/v1/authentication", "GET", JMX_API_EXACT, auth),
    JMX_API_ROUTE(80, "/api/v1/authentication/web", "GET", JMX_API_EXACT, auth_web_get),
    JMX_API_ROUTE(81, "/api/v1/authentication/web", "PUT", JMX_API_EXACT, auth_web_put),
    JMX_API_ROUTE(82, "/api/v1/authentication/web/portal", "GET", JMX_API_EXACT, auth_web_portal_get),
    JMX_API_ROUTE(83, "/api/v1/authentication/web/portal", "PUT", JMX_API_EXACT, auth_web_portal_put),
    JMX_API_ROUTE(84, "/api/v1/authentication/web/access-rules", "GET", JMX_API_EXACT, auth_web_access_rules_get),
    JMX_API_ROUTE(85, "/api/v1/authentication/web/access-rules", "POST", JMX_API_EXACT, auth_web_access_rules_post),
    JMX_API_ROUTE(86, "/api/v1/authentication/online-users", "GET", JMX_API_EXACT, auth_online_users),
    JMX_API_ROUTE(87, "/api/v1/authentication/accounts", "GET", JMX_API_EXACT, auth_accounts_get),
    JMX_API_ROUTE(88, "/api/v1/authentication/ledger", "GET", JMX_API_EXACT, auth_ledger_get),
    JMX_API_ROUTE(89, "/api/v1/authentication/packages", "GET", JMX_API_EXACT, auth_packages_get),
    JMX_API_ROUTE(90, "/api/v1/authentication/vouchers", "GET", JMX_API_EXACT, auth_vouchers_get),
    JMX_API_ROUTE(91, "/api/v1/authentication/delegated-services", "GET", JMX_API_EXACT, auth_delegated_services_get),
    JMX_API_ROUTE(92, "/api/v1/authentication/delegated-services/import", "POST", JMX_API_EXACT, auth_delegated_services_import),
    JMX_API_ROUTE(93, "/api/v1/authentication/delegated-services", "POST", JMX_API_EXACT, auth_delegated_services_post),
    JMX_API_ROUTE(94, "/api/v1/authentication/notifications", "GET", JMX_API_EXACT, auth_notifications),
    JMX_API_ROUTE(95, "/api/v1/authentication/notifications/preview", "POST", JMX_API_EXACT, auth_notifications_preview),
    JMX_API_PREDICATE_ROUTE(96, "/api/v1/authentication/notifications/realtime", "PUT", JMX_API_PREDICATE_ONLY, auth_notifications_kind_path, auth_notifications_kind_set),
    JMX_API_ROUTE(97, "/api/v1/authentication/notifications/periodic", "POST", JMX_API_EXACT, auth_notifications_periodic),
    JMX_API_ROUTE(98, "/api/v1/authentication/packages", "POST", JMX_API_EXACT, auth_packages_post),
    JMX_API_ROUTE(99, "/api/v1/authentication/accounts", "POST", JMX_API_EXACT, auth_accounts_post),
    JMX_API_ROUTE(100, "/api/v1/authentication/accounts/bulk", "POST", JMX_API_EXACT, auth_accounts_bulk),
    JMX_API_ROUTE(101, "/api/v1/authentication/accounts/import", "POST", JMX_API_EXACT, auth_accounts_import),
    JMX_API_ROUTE(102, "/api/v1/authentication/accounts/password-policy", "PUT,PATCH", JMX_API_EXACT, auth_accounts_password_policy),
    JMX_API_ROUTE(103, "/api/v1/authentication/ledger", "POST", JMX_API_EXACT, auth_ledger_post),
    JMX_API_ROUTE(104, "/api/v1/authentication/vouchers", "POST", JMX_API_EXACT, auth_vouchers_post),
    JMX_API_ROUTE(105, "/api/v1/authentication/vouchers/expired", "DELETE", JMX_API_EXACT, auth_vouchers_expired),
    JMX_API_ROUTE_END,
};

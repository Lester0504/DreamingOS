// SPDX-License-Identifier: GPL-2.0-or-later
#include "api_wifi_certificates.h"
#include "api_error.h"
#include "api_json.h"
#include "api_ubus.h"
#include "../jmx_app_api.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#define CERT_ROOT "/api/v1/wifi/certificates"
#define CERT_TASKS CERT_ROOT "/tasks"

static int certificate_uuid(const char *s)
{
    size_t i;
    if (!s || strlen(s) != 36) return 0;
    for (i = 0; i < 36; i++)
        if ((i == 8 || i == 13 || i == 18 || i == 23) ? s[i] != '-' :
            !isxdigit((unsigned char)s[i])) return 0;
    return 1;
}

static const char *certificate_text(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    return o && json_object_object_get_ex(o, key, &v) && v &&
        json_object_is_type(v, json_type_string) ? json_object_get_string(v) : "";
}

static struct json_object *certificate_error(struct jmx_api_ctx *ctx,
    int status, const char *code)
{
    ctx->status = status;
    return webd_error(code, code, NULL, "webd.wifi.certificates");
}

static struct json_object *certificate_route(struct jmx_api_ctx *ctx)
{
    const char *path = ctx->req->path, *action = "status", *operation = "";
    const char *target = "", *reason = "";
    char task[37] = "", audit_action[80];
    struct json_object *params, *reply, *v = NULL;
    int write = !strcmp(ctx->req->method, "POST");
    if (!jmx_perm_check(ctx->role, write ? JMX_RISK_HIGH : JMX_RISK_LOW))
        return certificate_error(ctx, 403, "permission_denied");
    if (!strcmp(path, CERT_ROOT "/server-renew")) operation = "server_renew";
    else if (!strcmp(path, CERT_ROOT "/ap-renew")) operation = "ap_renew";
    else if (!strcmp(path, CERT_ROOT "/ca-rotate")) operation = "ca_rotate";
    else if (!strcmp(path, CERT_ROOT "/revoke")) action = "revoke";
    else if (!strncmp(path, CERT_TASKS "/", strlen(CERT_TASKS "/"))) {
        const char *tail = path + strlen(CERT_TASKS "/");
        const char *slash = strchr(tail, '/');
        size_t length = slash ? (size_t)(slash - tail) : strlen(tail);
        if (length != 36) return certificate_error(ctx, 404, "not_found");
        memcpy(task, tail, 36);
        if (!certificate_uuid(task)) return certificate_error(ctx, 400, "invalid_task_id");
        if (write) {
            if (!slash || (strcmp(slash, "/cancel") && strcmp(slash, "/retry") && strcmp(slash, "/rollback")))
                return certificate_error(ctx, 404, "not_found");
            action = slash + 1;
        } else if (slash) return certificate_error(ctx, 404, "not_found");
    } else if (strcmp(path, CERT_TASKS)) return certificate_error(ctx, 404, "not_found");
    if (operation[0]) action = "submit";
    if (write && !strcmp(action, "status")) return certificate_error(ctx, 404, "not_found");
    params = json_object_new_object();
    if (write) {
        if (!ctx->device_id || !ctx->device_id[0] || strlen(ctx->device_id) > 95 ||
            !ctx->body || !json_object_is_type(ctx->body, json_type_object)) goto invalid;
        json_object_object_foreach(ctx->body, key, value) {
            (void)value;
            if (!strcmp(key, "confirmed") || !strcmp(key, "reason")) continue;
            if (!strcmp(action, "submit") && !strcmp(key, "request_id")) continue;
            if (!strcmp(operation, "ap_renew") && !strcmp(key, "ap_id")) continue;
            if (!strcmp(action, "revoke") && !strcmp(key, "certificate_id")) continue;
            goto invalid;
        }
        if (!json_object_object_get_ex(ctx->body, "confirmed", &v) || !v ||
            !json_object_is_type(v, json_type_boolean) || !json_object_get_boolean(v)) goto invalid;
        reason = certificate_text(ctx->body, "reason");
        if (!reason[0] || strlen(reason) > 255) goto invalid;
        if (!strcmp(action, "submit")) {
            const char *id = certificate_text(ctx->body, "request_id");
            if (!certificate_uuid(id)) goto invalid;
            json_object_object_add(params, "request_id", json_object_new_string(id));
            json_object_object_add(params, "operation", json_object_new_string(operation));
            if (!strcmp(operation, "ap_renew")) {
                target = certificate_text(ctx->body, "ap_id");
                if (!certificate_uuid(target)) goto invalid;
                json_object_object_add(params, "ap_id", json_object_new_string(target));
            }
        } else if (!strcmp(action, "revoke")) {
            target = certificate_text(ctx->body, "certificate_id");
            if (!certificate_uuid(target)) goto invalid;
            json_object_object_add(params, "certificate_id", json_object_new_string(target));
        }
        /* Only the authenticated session identity supplies the actor. */
        json_object_object_add(params, "actor", json_object_new_string(ctx->device_id));
        json_object_object_add(params, "reason", json_object_new_string(reason));
        json_object_object_add(params, "confirmed", json_object_new_boolean(1));
    }
    json_object_object_add(params, "action", json_object_new_string(action));
    if (task[0]) {
        json_object_object_add(params, "task_id", json_object_new_string(task));
        target = task;
    }
    reply = app_ubus_invoke_object_timeout("dreamingwrt.ac", "certificate_lifecycle", params, 3000);
    json_object_put(params);
    if (!reply) return certificate_error(ctx, 503, "certificate_service_unavailable");
    if (!json_object_object_get_ex(reply, "ok", &v) || !v || !json_object_get_boolean(v)) {
        const char *code = certificate_text(reply, "error");
        ctx->status = !strncmp(code, "invalid_", 8) || !strcmp(code, "operator_confirmation_required") ? 400 :
            strstr(code, "not_found") ? 404 :
            strstr(code, "conflict") || strstr(code, "busy") || strstr(code, "not_allowed") ||
            !strcmp(code, "ap_not_adopted") || !strcmp(code, "certificate_task_in_progress") ||
            !strcmp(code, "certificate_task_terminal") || strstr(code, "boundary_crossed") ? 409 :
            strstr(code, "unavailable") ? 503 : 500;
    } else ctx->status = write && !strcmp(action, "submit") ? 202 : 200;
    if (write) {
        snprintf(audit_action, sizeof(audit_action), "wifi.certificate.%s", operation[0] ? operation : action);
        jmx_app_audit_log_response(ctx->device_id, ctx->device_id, audit_action,
            "high", target, ctx->req->client_ip, reply, ctx->status);
    }
    return reply;
invalid:
    json_object_put(params);
    return certificate_error(ctx, 400, "invalid_certificate_request");
}

const struct jmx_api_route wifi_certificate_api_routes[] = {
    JMX_API_ROUTE(9618, CERT_TASKS, "GET", JMX_API_EXACT, certificate_route),
    JMX_API_ROUTE(9619, CERT_TASKS "/", "GET,POST", JMX_API_PREFIX, certificate_route),
    JMX_API_ROUTE(9620, CERT_ROOT "/server-renew", "POST", JMX_API_EXACT, certificate_route),
    JMX_API_ROUTE(9621, CERT_ROOT "/ap-renew", "POST", JMX_API_EXACT, certificate_route),
    JMX_API_ROUTE(9622, CERT_ROOT "/ca-rotate", "POST", JMX_API_EXACT, certificate_route),
    JMX_API_ROUTE(9623, CERT_ROOT "/revoke", "POST", JMX_API_EXACT, certificate_route),
    JMX_API_ROUTE_END
};

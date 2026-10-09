// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Network-control / terminal-control BFF (Phase 6O). The
 * /api/v1/network-control/* surface: the collection GET, terminal rate limits
 * (list / create / update / delete), terminal policies (runtime + list / create
 * / per-id get-update-delete / reset-usage / renew / apply), the domain apply,
 * status, and the MAC allowlist (list / members / create-update / confirm).
 * routed / tc own the persistent truth; these handlers are thin BFF adapters.
 * Each branch body moves VERBATIM from jmx_app_api.c behind an alias preamble
 * (req/body_json/device_id as referenced; resp+status always), so no second
 * implementation remains there.
 *
 * 15 exact routes (JMX_API_EXACT) + 5 prefix routes (JMX_API_PREFIX). Each
 * prefix's legacy length literal equals strlen(path), so JMX_API_PREFIX
 * reproduces the !strncmp match byte-for-byte. Several paths carry more than one
 * method row (terminal-limits GET/POST; terminal-policies GET/POST; the three
 * terminal-policies/ prefix method-variants; mac-allowlist GET/POST) — distinct
 * (path, methods) rows matched on path+method, so each is a plain JMX_API_ROUTE,
 * no predicate. A prefix (trailing-slash) route's handler slug carries a
 * "_detail" infix so it never collides with the exact stem of the same path.
 *
 * The routes are emitted in baseline seq order (410-429); the router walks a
 * table in array order and takes the first match, so seq 415
 * /terminal-policies/runtime (exact GET) is checked before seq 418
 * /terminal-policies/ (prefix GET) and is not swallowed by it.
 *
 * The inline CSRF write-preflight guard in jmx_app_api.c (which OR's
 * /api/v1/network-control among 35 paths and writes the socket on rejection)
 * STAYS inline: it is a RAW_FD mutation gate textually before the post-auth
 * router dispatch, so every nc write still passes it before reaching these
 * handlers.
 *
 * Borrowed from jmx_app_api.c (declared in api_netcontrol_internal.h;
 * definitions stay in main), de-static'd: webd_mac_for_ip,
 * webd_netctl_rule_id_ok, webd_netctl_terminal_rule_exists,
 * webd_terminal_policy_apply_ok, webd_terminal_policy_apply_rollback_noop,
 * webd_terminal_policy_id_ok, webd_terminal_policy_init_schema. Every other
 * symbol these bodies use is already exported from api_ubus.c / api_request.c.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <json-c/json.h>

#include "api_netcontrol.h"
#include "api_netcontrol_internal.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_ubus.h"
#include "webd_http_req.h"
#include "../jmx_app_api.h"

/* ── network-control route handlers (verbatim bodies behind an alias preamble) ── */

static struct json_object *netcontrol_root(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        resp = webd_netctl_get_response(&status);

    ctx->status = status;
    return resp;
}

static struct json_object *netcontrol_terminal_limits_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        struct json_object *data = json_object_new_object();
        struct json_object *rules = webd_netctl_terminal_rules();

        json_object_object_add(data, "terminal_limits", rules);
        json_object_object_add(data, "count",
                               json_object_new_int((int)json_object_array_length(rules)));
        json_object_object_add(data, "capabilities", webd_netctl_terminal_capabilities());
        resp = webd_envelope(data, "ubus:network_control_get");
        status = 200;

    ctx->status = status;
    return resp;
}

static struct json_object *netcontrol_terminal_limits_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        const char *code = "invalid_parameter";
        char err[256] = "";
        char rule_id[80];
        const char *supplied = app_nc_json_str(body_json, "id", "");
        struct json_object *rule;

        /*
         * An id may be supplied for idempotent creation; otherwise one is
         * generated. Generated ids are time-based because the rule table is
         * keyed by id and ordered by priority, so the id itself carries no
         * ordering meaning.
         */
        if (supplied[0])
            snprintf(rule_id, sizeof(rule_id), "%s", supplied);
        else
            snprintf(rule_id, sizeof(rule_id), "tl-%llx",
                     (unsigned long long)time(NULL) ^ (unsigned long long)getpid());

        if (!supplied[0] && webd_netctl_terminal_rule_exists(rule_id)) {
            resp = webd_error("conflict", "generated rule id already exists; retry",
                              NULL, "webd.network_control");
            status = 409;
        } else {
            rule = webd_netctl_terminal_rule_build(body_json, rule_id, &code,
                                                   err, sizeof(err));
            if (!rule) {
                resp = webd_error(code, err, NULL, "webd.network_control");
                status = 400;
            } else {
                struct json_object *rules = webd_netctl_terminal_rules();
                int existing = (int)json_object_array_length(rules);
                int already = webd_netctl_terminal_rule_exists(rule_id);

                json_object_put(rules);
                if (!already && existing >= WEBD_NETCTL_TERMINAL_MAX_RULES) {
                    json_object_put(rule);
                    snprintf(err, sizeof(err),
                             "terminal limit rules are capped at %d by the tc plan "
                             "(NC_NETCTL_TC_MAX_RULES); %d already exist",
                             WEBD_NETCTL_TERMINAL_MAX_RULES, existing);
                    resp = webd_error("rule_limit_reached", err, NULL,
                                      "webd.network_control");
                    status = 409;
                } else {
                    resp = webd_netctl_terminal_write(rule, &status);
                    jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
                                      "network_control.terminal_limit.create",
                                      "medium", rule_id, "",
                                      status < 400 ? "success" :
                                          app_ubus_response_error_code(resp));
                }
            }
        }

    ctx->status = status;
    return resp;
}

static struct json_object *netcontrol_terminal_limits_detail_put(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        const char *rule_id = req.path + 40;
        const char *code = "invalid_parameter";
        char err[256] = "";
        struct json_object *rule;

        if (!webd_netctl_terminal_rule_exists(rule_id)) {
            resp = webd_error("not_found", "no terminal limit rule with that id",
                              NULL, "webd.network_control");
            status = 404;
        } else if (!(rule = webd_netctl_terminal_rule_build(body_json, rule_id, &code,
                                                            err, sizeof(err)))) {
            resp = webd_error(code, err, NULL, "webd.network_control");
            status = 400;
        } else {
            resp = webd_netctl_terminal_write(rule, &status);
            jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
                              "network_control.terminal_limit.update",
                              "medium", rule_id, "",
                              status < 400 ? "success" :
                                  app_ubus_response_error_code(resp));
        }

    ctx->status = status;
    return resp;
}

static struct json_object *netcontrol_terminal_limits_detail_delete(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;
    const char *device_id = ctx->device_id;

        const char *rule_id = req.path + 40;

        if (!webd_netctl_rule_id_ok(rule_id)) {
            resp = webd_error("invalid_parameter",
                              "id must be 1-64 chars of [A-Za-z0-9._-]",
                              NULL, "webd.network_control");
            status = 400;
        } else if (!webd_netctl_terminal_rule_exists(rule_id)) {
            resp = webd_error("not_found", "no terminal limit rule with that id",
                              NULL, "webd.network_control");
            status = 404;
        } else {
            struct json_object *params = json_object_new_object();
            struct json_object *ids = json_object_new_array();
            struct json_object *del;

            json_object_array_add(ids, json_object_new_string(rule_id));
            json_object_object_add(params, "ids", ids);
            json_object_object_add(params, "type",
                                   json_object_new_string("terminal_limit"));
            del = app_ubus_or_error("network_control_bulk_delete", params);
            json_object_put(params);
            if (!app_ubus_response_ok(del)) {
                resp = del;
                status = app_response_status(del, 502);
            } else {
                json_object_put(del);
                /* Removing the row is not enough: the committed tc plan still
                 * holds the filter until apply reconciles it. */
                resp = app_ubus_invoke_timeout("network_control_apply", NULL, 15000);
                status = app_response_status(resp, 200);
            }
            jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
                              "network_control.terminal_limit.delete",
                              "medium", rule_id, "",
                              status < 400 ? "success" :
                                  app_ubus_response_error_code(resp));
        }

    ctx->status = status;
    return resp;
}

static struct json_object *netcontrol_terminal_policies_runtime(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        resp = webd_terminal_policy_flowd("terminal_policy_runtime", &status);

    ctx->status = status;
    return resp;
}

static struct json_object *netcontrol_terminal_policies_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        resp = webd_terminal_policy_response(NULL, &status);

    ctx->status = status;
    return resp;
}

static struct json_object *netcontrol_terminal_policies_post(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        char id[96];
        const char *supplied = app_nc_json_str(body_json, "id", "");

        if (supplied[0])
            snprintf(id, sizeof(id), "%s", supplied);
        else
            snprintf(id, sizeof(id), "tp-%llx", (unsigned long long)time(NULL) ^
                     (unsigned long long)getpid());
        resp = webd_terminal_policy_write(body_json, id,
                                          strcmp(req.method, "POST") != 0,
                                          &status);
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
                          "terminal_policy.write", "medium", id, "",
                          status < 400 ? "success" : "failed");

    ctx->status = status;
    return resp;
}

static struct json_object *netcontrol_terminal_policies_detail_get(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;

        const char *id = req.path + 42;
        struct json_object *data;

        if (!webd_terminal_policy_id_ok(id)) {
            status = 400;
            resp = webd_error("invalid_parameter", "invalid terminal policy id", NULL,
                              "webd.terminal_policy");
        } else {
            resp = webd_terminal_policy_response(id, &status);
            data = webd_obj_child_obj(resp, "data");
            if (data) {
                struct json_object *rules = webd_obj_child_array(data, "rules");
                if (!rules || json_object_array_length(rules) == 0) {
                    json_object_put(resp);
                    status = 404;
                    resp = webd_error("not_found", "terminal policy not found", NULL,
                                      "webd.terminal_policy");
                }
            }
        }

    ctx->status = status;
    return resp;
}

static struct json_object *netcontrol_terminal_policies_detail_put(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        const char *id = req.path + 42;
        resp = webd_terminal_policy_write(body_json, id, 1, &status);
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
                          "terminal_policy.update", "medium", id, "",
                          status < 400 ? "success" : "failed");

    ctx->status = status;
    return resp;
}

static struct json_object *netcontrol_terminal_policies_detail_delete(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;
    const char *device_id = ctx->device_id;

        const char *id = req.path + 42;
        if (!webd_terminal_policy_id_ok(id)) {
            status = 400;
            resp = webd_error("invalid_parameter", "invalid terminal policy id", NULL,
                              "webd.terminal_policy");
        } else if (webd_terminal_policy_init_schema() != 0) {
            status = 404;
            resp = webd_error("not_found", "terminal policy not found", NULL,
                              "webd.terminal_policy");
        } else {
            struct json_object *old = tp_policy_snapshot(id);
            struct json_object *apply = NULL;
            struct json_object *restore = NULL;
            struct json_object *data;
            tp_error_t tp_err;
            int apply_status = 502;
            int rollback_ok = 1;

            if (!old) {
                status = 404;
                resp = webd_error("not_found", "terminal policy not found", NULL,
                                  "webd.terminal_policy");
            } else if (tp_policy_delete(id) != 0) {
                status = 500;
                resp = webd_error("storage_failed", "terminal policy delete failed",
                                  NULL, "webd.terminal_policy");
            } else {
                apply = webd_terminal_policy_apply(&apply_status);
                if (!webd_terminal_policy_apply_ok(apply)) {
                    memset(&tp_err, 0, sizeof(tp_err));
                    restore = webd_terminal_policy_restore(old, id, 0, &tp_err);
                    if (!restore)
                        rollback_ok = 0;
                    if (rollback_ok && !webd_terminal_policy_apply_rollback_noop(apply)) {
                        struct json_object *reapply =
                            webd_terminal_policy_apply(&apply_status);
                        if (!webd_terminal_policy_apply_ok(reapply))
                            rollback_ok = 0;
                        if (reapply)
                            json_object_put(reapply);
                    }
                    resp = webd_terminal_policy_apply_error(
                        apply, rollback_ok,
                        rollback_ok ? "previous generation restored" :
                        "failed to restore previous generation");
                    status = rollback_ok ? 502 : 500;
                } else {
                    data = json_object_new_object();
                    json_object_object_add(data, "deleted", json_object_new_boolean(1));
                    json_object_object_add(data, "id", json_object_new_string(id));
                    json_object_object_add(data, "runtime_applied", json_object_new_boolean(1));
                    json_object_object_add(data, "apply", webd_json_clone(apply));
                    status = 200;
                    resp = webd_envelope(data, "webd.terminal_policy");
                }
            }
            if (old)
                json_object_put(old);
            if (restore)
                json_object_put(restore);
            if (apply)
                json_object_put(apply);
        }
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
                          "terminal_policy.delete", "medium", id, "",
                          status < 400 ? "success" : "failed");

    ctx->status = status;
    return resp;
}

static struct json_object *netcontrol_terminal_policies_reset_usage(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        const char *id = app_nc_json_str(body_json, "id", "");

        if (!webd_terminal_policy_id_ok(id)) {
            status = 400;
            resp = webd_error("invalid_parameter", "id is required", NULL,
                              "webd.terminal_policy");
        } else if (webd_terminal_policy_init_schema() != 0) {
            status = 500;
            resp = webd_error("storage_unavailable", "terminal policy storage unavailable",
                              NULL, "webd.terminal_policy");
        } else {
            struct json_object *old = tp_policy_snapshot(id);
            struct json_object *apply = NULL;
            struct json_object *restore = NULL;
            struct json_object *data;
            struct json_object *rule = NULL;
            tp_error_t tp_err;
            int apply_status = 502;
            int rollback_ok = 1;

            if (!old) {
                status = 404;
                resp = webd_error("not_found", "terminal policy not found", NULL,
                                  "webd.terminal_policy");
            } else if (tp_policy_reset_usage(id) != 0) {
                status = 500;
                resp = webd_error("storage_failed", "terminal policy reset failed",
                                  NULL, "webd.terminal_policy");
            } else {
                apply = webd_terminal_policy_apply(&apply_status);
                if (!webd_terminal_policy_apply_ok(apply)) {
                    memset(&tp_err, 0, sizeof(tp_err));
                    restore = webd_terminal_policy_restore(old, id, 1, &tp_err);
                    if (!restore)
                        rollback_ok = 0;
                    if (rollback_ok && !webd_terminal_policy_apply_rollback_noop(apply)) {
                        struct json_object *reapply =
                            webd_terminal_policy_apply(&apply_status);
                        if (!webd_terminal_policy_apply_ok(reapply))
                            rollback_ok = 0;
                        if (reapply)
                            json_object_put(reapply);
                    }
                    resp = webd_terminal_policy_apply_error(
                        apply, rollback_ok,
                        rollback_ok ? "previous generation restored" :
                        "failed to restore previous generation");
                    status = rollback_ok ? 502 : 500;
                } else {
                    rule = tp_policy_get(id, 1);
                    data = json_object_new_object();
                    json_object_object_add(data, "reset", json_object_new_boolean(1));
                    json_object_object_add(data, "runtime_applied", json_object_new_boolean(1));
                    json_object_object_add(data, "apply", webd_json_clone(apply));
                    if (rule) {
                        struct json_object *gen = NULL;
                        if (json_object_object_get_ex(rule, "generation", &gen))
                            json_object_object_add(data, "generation", webd_json_clone(gen));
                        json_object_object_add(data, "rule", rule);
                    }
                    status = 200;
                    resp = webd_envelope(data, "webd.terminal_policy");
                }
            }
            if (old)
                json_object_put(old);
            if (restore)
                json_object_put(restore);
            if (apply)
                json_object_put(apply);
        }
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
                          "terminal_policy.reset_usage", "high", id, "",
                          status < 400 ? "success" : "failed");

    ctx->status = status;
    return resp;
}

static struct json_object *netcontrol_terminal_policies_renew(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        const char *id = app_nc_json_str(body_json, "id", "");
        int64_t count = app_nc_json_int64(body_json, "count", 0);
        const char *unit = app_nc_json_str(body_json, "unit", "hours");
        int keep = app_nc_json_bool(body_json, "keep_quota_usage", 1);

        if (!webd_terminal_policy_id_ok(id) || count <= 0 || !tp_valid_unit(unit)) {
            status = 400;
            resp = webd_error("invalid_parameter",
                              "id, positive count, and valid unit are required",
                              NULL, "webd.terminal_policy");
        } else if (webd_terminal_policy_init_schema() != 0) {
            status = 500;
            resp = webd_error("storage_unavailable",
                              "terminal policy storage unavailable",
                              NULL, "webd.terminal_policy");
        } else {
            struct json_object *old = tp_policy_snapshot(id);
            struct json_object *apply = NULL;
            struct json_object *restore = NULL;
            struct json_object *data;
            struct json_object *rule = NULL;
            tp_error_t tp_err;
            int apply_status = 502;
            int rollback_ok = 1;

            if (!old) {
                status = 404;
                resp = webd_error("not_found", "terminal policy not found",
                                  NULL, "webd.terminal_policy");
            } else if (tp_policy_renew(id, count, unit, keep) != 0) {
                status = 500;
                resp = webd_error("storage_failed",
                                  "terminal policy renew failed",
                                  NULL, "webd.terminal_policy");
            } else {
                apply = webd_terminal_policy_apply(&apply_status);
                if (!webd_terminal_policy_apply_ok(apply)) {
                    memset(&tp_err, 0, sizeof(tp_err));
                    /* renew updates an existing row; restore it in place so
                     * the exact previous generation is put back. */
                    restore = webd_terminal_policy_restore(old, id, 1, &tp_err);
                    if (!restore)
                        rollback_ok = 0;
                    if (rollback_ok && !webd_terminal_policy_apply_rollback_noop(apply)) {
                        struct json_object *reapply =
                            webd_terminal_policy_apply(&apply_status);
                        if (!webd_terminal_policy_apply_ok(reapply))
                            rollback_ok = 0;
                        if (reapply)
                            json_object_put(reapply);
                    }
                    resp = webd_terminal_policy_apply_error(
                        apply, rollback_ok,
                        rollback_ok ? "previous generation restored" :
                        "failed to restore previous generation");
                    status = rollback_ok ? 502 : 500;
                } else {
                    rule = tp_policy_get(id, 1);
                    data = json_object_new_object();
                    json_object_object_add(data, "renewed",
                                           json_object_new_boolean(1));
                    json_object_object_add(data, "runtime_applied",
                                           json_object_new_boolean(1));
                    json_object_object_add(data, "apply",
                                           webd_json_clone(apply));
                    if (rule) {
                        struct json_object *gen = NULL;
                        if (json_object_object_get_ex(rule, "generation", &gen))
                            json_object_object_add(data, "generation",
                                                   webd_json_clone(gen));
                        json_object_object_add(data, "rule", rule);
                    }
                    status = 200;
                    resp = webd_envelope(data, "webd.terminal_policy");
                }
            }
            if (old)
                json_object_put(old);
            if (restore)
                json_object_put(restore);
            if (apply)
                json_object_put(apply);
        }
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
                          "terminal_policy.renew", "high", id, "",
                          status < 400 ? "success" : "failed");

    ctx->status = status;
    return resp;
}

static struct json_object *netcontrol_terminal_policies_apply(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    const char *device_id = ctx->device_id;

        resp = webd_terminal_policy_flowd("terminal_policy_apply", &status);
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
                          "terminal_policy.apply", "medium", "all", "",
                          status < 400 ? "success" :
                              app_ubus_response_error_code(resp));

    ctx->status = status;
    return resp;
}

static struct json_object *netcontrol_apply(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        /* Body is forwarded so a caller can pass apply_nft/apply_tc; both
         * default to 1 in nc_netctl_apply(). */
        resp = app_ubus_invoke_timeout("network_control_apply", body_json, 20000);
        status = app_response_status(resp, status);
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
                          "network_control.apply", "medium", "terminal_limit", "",
                          status < 400 ? "success" :
                              app_ubus_response_error_code(resp));

    ctx->status = status;
    return resp;
}

static struct json_object *netcontrol_status(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        resp = app_ubus_invoke_timeout("network_control_status", NULL, 3000);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *netcontrol_mac_allowlist_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        resp = app_ubus_invoke_timeout("network_control_mac_allowlist_get", NULL, 3000);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *netcontrol_mac_allowlist_members(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        resp = app_ubus_invoke_timeout("network_control_mac_allowlist_members_set",
                                       body_json, 5000);
        status = app_response_status(resp, status);
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
                          "network_control.mac_allowlist.members.replace", "medium",
                          "mac_allowlist", "",
                          status < 400 ? "success" : app_ubus_response_error_code(resp));

    ctx->status = status;
    return resp;
}

static struct json_object *netcontrol_mac_allowlist_post(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        struct json_object *params = body_json && json_object_is_type(body_json, json_type_object) ?
                                     webd_json_clone(body_json) : json_object_new_object();
        const char *mode = app_nc_json_str(params, "mode", "");
        int want_enabled = !strcmp(mode, "whitelist") ? 1 :
                           (!strcmp(mode, "blacklist") ? 0 :
                            app_nc_json_bool(params, "enabled", 0));
        char admin_mac[64] = "";
        char mac_reason[64] = "";
        int have_mac = webd_mac_for_ip(req.peer_ip, admin_mac, sizeof(admin_mac),
                                       mac_reason, sizeof(mac_reason));

        /* Overwritten, not defaulted: whatever the body claimed is discarded. */
        json_object_object_del(params, "admin_mac");
        json_object_object_del(params, "admin_ip");
        json_object_object_del(params, "admin_mac_source");
        if (have_mac) {
            webd_obj_add_str(params, "admin_mac", admin_mac);
            webd_obj_add_str(params, "admin_ip", req.peer_ip);
            webd_obj_add_str(params, "admin_mac_source", "webd_request_origin_peer_ip");
        }
        if (want_enabled && !have_mac) {
            /*
             * Refused in webd rather than forwarded: the core would reject it
             * anyway, and answering here can name the reason the lookup failed.
             */
            char detail[256];

            snprintf(detail, sizeof(detail),
                     "cannot resolve the MAC of this session (peer_ip=%s, reason=%s); "
                     "enabling allowlist mode without it can lock the operator out",
                     req.peer_ip[0] ? req.peer_ip : "unknown",
                     mac_reason[0] ? mac_reason : "unknown");
            resp = webd_error("admin_origin_unresolved", detail, NULL,
                              "webd.network_control");
            status = 409;
        } else {
            resp = app_ubus_invoke_timeout("network_control_mac_allowlist_set",
                                           params, 25000);
            status = app_response_status(resp, status);
        }
        json_object_put(params);
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
                          want_enabled ? "network_control.mac_allowlist.enable" :
                                         "network_control.mac_allowlist.disable",
                          "high", "mac_allowlist", "",
                          status < 400 ? "success" :
                              app_ubus_response_error_code(resp));

    ctx->status = status;
    return resp;
}

static struct json_object *netcontrol_mac_allowlist_confirm(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    const char *device_id = ctx->device_id;

        resp = app_ubus_invoke_timeout("network_control_mac_allowlist_confirm",
                                       NULL, 10000);
        status = app_response_status(resp, status);
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
                          "network_control.mac_allowlist.confirm", "medium",
                          "mac_allowlist", "",
                          status < 400 ? "success" :
                              app_ubus_response_error_code(resp));

    ctx->status = status;
    return resp;
}

const struct jmx_api_route netcontrol_api_routes[] = {
    JMX_API_ROUTE(410, "/api/v1/network-control", "GET", JMX_API_EXACT, netcontrol_root),
    JMX_API_ROUTE(411, "/api/v1/network-control/terminal-limits", "GET", JMX_API_EXACT, netcontrol_terminal_limits_get),
    JMX_API_ROUTE(412, "/api/v1/network-control/terminal-limits", "POST", JMX_API_EXACT, netcontrol_terminal_limits_post),
    JMX_API_ROUTE(413, "/api/v1/network-control/terminal-limits/", "PUT,PATCH", JMX_API_PREFIX, netcontrol_terminal_limits_detail_put),
    JMX_API_ROUTE(414, "/api/v1/network-control/terminal-limits/", "DELETE", JMX_API_PREFIX, netcontrol_terminal_limits_detail_delete),
    JMX_API_ROUTE(415, "/api/v1/network-control/terminal-policies/runtime", "GET", JMX_API_EXACT, netcontrol_terminal_policies_runtime),
    JMX_API_ROUTE(416, "/api/v1/network-control/terminal-policies", "GET", JMX_API_EXACT, netcontrol_terminal_policies_get),
    JMX_API_ROUTE(417, "/api/v1/network-control/terminal-policies", "POST,PUT,PATCH", JMX_API_EXACT, netcontrol_terminal_policies_post),
    JMX_API_ROUTE(418, "/api/v1/network-control/terminal-policies/", "GET", JMX_API_PREFIX, netcontrol_terminal_policies_detail_get),
    JMX_API_ROUTE(419, "/api/v1/network-control/terminal-policies/", "PUT,PATCH", JMX_API_PREFIX, netcontrol_terminal_policies_detail_put),
    JMX_API_ROUTE(420, "/api/v1/network-control/terminal-policies/", "DELETE", JMX_API_PREFIX, netcontrol_terminal_policies_detail_delete),
    JMX_API_ROUTE(421, "/api/v1/network-control/terminal-policies/reset-usage", "POST", JMX_API_EXACT, netcontrol_terminal_policies_reset_usage),
    JMX_API_ROUTE(422, "/api/v1/network-control/terminal-policies/renew", "POST", JMX_API_EXACT, netcontrol_terminal_policies_renew),
    JMX_API_ROUTE(423, "/api/v1/network-control/terminal-policies/apply", "POST", JMX_API_EXACT, netcontrol_terminal_policies_apply),
    JMX_API_ROUTE(424, "/api/v1/network-control/apply", "POST", JMX_API_EXACT, netcontrol_apply),
    JMX_API_ROUTE(425, "/api/v1/network-control/status", "GET", JMX_API_EXACT, netcontrol_status),
    JMX_API_ROUTE(426, "/api/v1/network-control/mac-allowlist", "GET", JMX_API_EXACT, netcontrol_mac_allowlist_get),
    JMX_API_ROUTE(427, "/api/v1/network-control/mac-allowlist/members", "POST,PUT", JMX_API_EXACT, netcontrol_mac_allowlist_members),
    JMX_API_ROUTE(428, "/api/v1/network-control/mac-allowlist", "POST,PUT,PATCH", JMX_API_EXACT, netcontrol_mac_allowlist_post),
    JMX_API_ROUTE(429, "/api/v1/network-control/mac-allowlist/confirm", "POST", JMX_API_EXACT, netcontrol_mac_allowlist_confirm),
    JMX_API_ROUTE_END,
};

// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Terminal-policy subsystem (Phase 6Y).
 *
 * The unified terminal-policy contract lifted verbatim out of jmx_app_api.c: the
 * storage/readback validators (id/target/protocols), the capabilities probe, the
 * flowd runtime bridge, the runtime-overlay merge chain, the policy builder, the
 * list serializer, and the /api/v1 terminal-policy write / apply / apply-error /
 * rollback / restore / response builders.
 *
 * The ten entry points (id_ok, init_schema, flowd, apply_ok, apply_rollback_noop,
 * apply, apply_error, restore, write, response) were de-static'd earlier so the
 * network-control BFF adapters in api_netcontrol.c (the actual dispatchers) could
 * reuse the single implementations; those definitions move here and the linker
 * resolves api_netcontrol.c's calls to this object. They are also declared in
 * api_terminal_internal.h, which both this TU and jmx_app_api.c include, so the
 * definition-vs-declaration contract is compiler-checked and, since main also
 * includes api_netcontrol_internal.h, the caller-side prototypes are forced to
 * agree with these definitions.
 *
 * Borrowed from jmx_app_api.c (definition stays there): webd_terminal_policy_open,
 * the tp_db_init lifecycle helper, is de-static'd there and declared in
 * api_terminal_internal.h (its other callers are main-only lifecycle sites).
 *
 * The nine file-local helpers keep their `static` linkage; the two in-region
 * caps (WEBD_TERMINAL_POLICY_MAX_RULES / _MAX_TARGETS) travel with the slice.
 *
 * This file is a pure extraction: no behaviour changed, no route moved.
 */
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <json-c/json.h>

#include "../../terminal_policy/terminal_policy.h"
#include "api_error.h"
#include "api_json.h"
#include "api_ubus.h"
#include "api_terminal_internal.h"

/* Unified terminal-policy contract: storage/readback API.  The dataplane
 * executor is deliberately reported as pending until flowd/nft/tc can apply
 * the rule atomically. */
#define WEBD_TERMINAL_POLICY_MAX_RULES 256
#define WEBD_TERMINAL_POLICY_MAX_TARGETS 4096

int webd_terminal_policy_id_ok(const char *id)
{
    const unsigned char *p = (const unsigned char *)id;
    if (!id || !id[0] || strlen(id) > 80) return 0;
    for (; *p; p++)
        if (!(isalnum(*p) || *p == '_' || *p == '-' || *p == '.')) return 0;
    return 1;
}

static int webd_terminal_policy_target_ok(struct json_object *target, int index,
                                          char *err, size_t err_len)
{
    const char *kind;
    const char *value;
    const char *start;
    const char *end;
    struct in_addr v4;
    struct in6_addr v6;

    if (!target || !json_object_is_type(target, json_type_object)) {
        snprintf(err, err_len, "targets[%d] must be an object", index);
        return -1;
    }
    kind = app_nc_json_str(target, "kind", "");
    value = app_nc_json_str(target, "value", "");
    start = app_nc_json_str(target, "start", "");
    end = app_nc_json_str(target, "end", "");
    if (!strcmp(kind, "ip")) {
        if (inet_pton(AF_INET, value, &v4) != 1 && inet_pton(AF_INET6, value, &v6) != 1) {
            snprintf(err, err_len, "targets[%d].value must be an IPv4 or IPv6 address", index);
            return -1;
        }
    } else if (!strcmp(kind, "cidr")) {
        char buf[INET6_ADDRSTRLEN + 8];
        char *slash;
        long prefix;
        char *tail = NULL;
        snprintf(buf, sizeof(buf), "%s", value);
        slash = strchr(buf, '/');
        if (!slash) {
            snprintf(err, err_len, "targets[%d].value must be CIDR", index);
            return -1;
        }
        *slash++ = 0;
        errno = 0;
        prefix = strtol(slash, &tail, 10);
        if (errno || !tail || *tail ||
            (inet_pton(AF_INET, buf, &v4) == 1 ? (prefix < 0 || prefix > 32) :
             (inet_pton(AF_INET6, buf, &v6) == 1 ? (prefix < 0 || prefix > 128) : 1))) {
            snprintf(err, err_len, "targets[%d].value must be a valid IPv4/IPv6 CIDR", index);
            return -1;
        }
    } else if (!strcmp(kind, "range")) {
        int f4 = inet_pton(AF_INET, start, &v4) == 1;
        int f6 = inet_pton(AF_INET6, start, &v6) == 1;
        if ((!f4 && !f6) || (f4 && inet_pton(AF_INET, end, &v4) != 1) ||
            (f6 && inet_pton(AF_INET6, end, &v6) != 1)) {
            snprintf(err, err_len, "targets[%d] range must use one address family", index);
            return -1;
        }
    } else {
        snprintf(err, err_len, "targets[%d].kind must be ip, cidr or range", index);
        return -1;
    }
    return 0;
}

static int webd_terminal_policy_protocols_ok(struct json_object *arr,
                                              char *err, size_t err_len)
{
    size_t i;
    if (!arr) return 0;
    if (!json_object_is_type(arr, json_type_array)) {
        snprintf(err, err_len, "deny_protocols must be an array");
        return -1;
    }
    for (i = 0; i < json_object_array_length(arr); i++) {
        const char *p = json_object_get_string(json_object_array_get_idx(arr, i));
        if (!p || (strcmp(p, "tcp") && strcmp(p, "udp") && strcmp(p, "icmp"))) {
            snprintf(err, err_len, "deny_protocols[%zu] must be tcp, udp or icmp", i);
            return -1;
        }
    }
    return 0;
}

int webd_terminal_policy_init_schema(void)
{
    return webd_terminal_policy_open();
}

static struct json_object *webd_terminal_policy_capabilities(void)
{
    struct json_object *cap = tp_capabilities();
    if (!cap)
        return json_object_new_object();
    json_object_object_add(cap, "max_rules", json_object_new_int(WEBD_TERMINAL_POLICY_MAX_RULES));
    json_object_object_add(cap, "max_targets_per_rule",
                           json_object_new_int(WEBD_TERMINAL_POLICY_MAX_TARGETS));
    return cap;
}

struct json_object *webd_terminal_policy_flowd(const char *method,
                                                      int *status)
{
    struct json_object *resp = app_ubus_invoke_object_timeout(
        "dreamingwrt.flowd", method, NULL, 5000);
    struct json_object *error = NULL;

    /*
     * flowd terminal-policy methods return a direct business result rather
     * than a WebD envelope.  In particular, runtime is expected to answer
     * {"ok":false,"reason":"terminal_policy_nft_table_absent"} while the
     * executor has not applied a table yet.  app_response_status() treats any
     * bare ok:false as a client error, which used to turn that valid state
     * into the misleading flowd_terminal_policy_unavailable response.
     *
     * A missing ubus response is the transport/backend failure.  A response
     * with flowd's structured `error` member is also a real backend error.
     * Bare ok:false responses are business-state results and remain HTTP 200
     * so callers can inspect `reason`/`rollback_ok` without losing context.
     */
    if (!resp) {
        *status = 503;
        struct json_object *err = webd_error("flowd_terminal_policy_unavailable",
                                             "flowd terminal policy executor unavailable",
                                             NULL, "webd.terminal_policy");
        return err;
    }

    if (json_object_object_get_ex(resp, "error", &error) && error) {
        *status = app_response_status(resp, 503);
        return resp;
    }

    *status = 200;
    return resp;
}

static struct json_object *webd_terminal_policy_runtime_overlay(int *status)
{
    struct json_object *resp = webd_terminal_policy_flowd("terminal_policy_runtime", status);
    // Keep storage capabilities honest; only expose the flowd nft applicability snapshot.
    if (!resp)
        return NULL;
    return resp;
}

/* Merge the aggregate flowd proof into each stored rule.  The policy library
 * owns lifecycle/quota state; flowd owns the kernel proof.  Keeping both
 * layers in the response lets the UI distinguish a saved rule from one that
 * is actually present in nft/tc without inventing a second status machine. */
static void webd_terminal_policy_merge_runtime(struct json_object *rules,
                                                struct json_object *runtime)
{
    struct json_object *applied = NULL;
    struct json_object *reason = NULL;
    struct json_object *nft = NULL;
    struct json_object *tc = NULL;
    struct json_object *quota = NULL;
    size_t i;

    if (!rules || !json_object_is_type(rules, json_type_array) || !runtime)
        return;
    json_object_object_get_ex(runtime, "runtime_applied", &applied);
    json_object_object_get_ex(runtime, "reason", &reason);
    json_object_object_get_ex(runtime, "runtime_reason", &reason);
    json_object_object_get_ex(runtime, "nft_verified", &nft);
    json_object_object_get_ex(runtime, "tc", &tc);
    json_object_object_get_ex(runtime, "quota", &quota);
    for (i = 0; i < json_object_array_length(rules); i++) {
        struct json_object *rule = json_object_array_get_idx(rules, i);
        struct json_object *state = NULL;
        struct json_object *rt = NULL;
        if (!rule)
            continue;
        json_object_object_get_ex(rule, "runtime", &state);
        rt = state;
        if (!rt) {
            rt = json_object_new_object();
            json_object_object_add(rule, "runtime", rt);
            json_object_object_add(rt, "state", json_object_new_string("active"));
        }
        json_object_object_add(rt, "runtime_applied",
                               json_object_new_boolean(applied &&
                                   json_object_get_boolean(applied)));
        json_object_object_add(rt, "runtime_reason",
                               json_object_new_string(reason ?
                                   json_object_get_string(reason) :
                                   (applied && json_object_get_boolean(applied) ?
                                    "terminal_policy_runtime_applied" :
                                    "terminal_policy_runtime_unverified")));
        if (nft)
            json_object_object_add(rt, "nft_verified", json_object_get(nft));
        if (tc) {
            struct json_object *tc_applied = NULL;
            if (json_object_object_get_ex(tc, "rate_rules_applied", &tc_applied))
                json_object_object_add(rt, "tc_verified", json_object_get(tc_applied));
        }
        if (quota)
            json_object_object_add(rt, "quota", json_object_get(quota));
    }
}

/* Write responses already have the freshly committed flowd apply result.  The
 * policy library intentionally has no dataplane dependency, so its embedded
 * runtime object starts as a plan-only placeholder.  Project the just-applied
 * readback onto a single rule before returning it to keep `rule`, `rules`, and
 * the aggregate runtime contract identical in the same response. */
static void webd_terminal_policy_merge_runtime_rule(struct json_object *rule,
                                                     struct json_object *runtime)
{
    struct json_object *rules;

    if (!rule || !runtime)
        return;
    rules = json_object_new_array();
    if (!rules)
        return;
    json_object_array_add(rules, json_object_get(rule));
    webd_terminal_policy_merge_runtime(rules, runtime);
    json_object_put(rules);
}

static void webd_terminal_policy_merge_capabilities(struct json_object *cap,
                                                    struct json_object *runtime)
{
    struct json_object *available = NULL;
    struct json_object *readback = NULL;
    struct json_object *tc = NULL;

    if (!cap || !runtime)
        return;
    json_object_object_get_ex(runtime, "available", &available);
    json_object_object_get_ex(runtime, "nft_verified", &readback);
    json_object_object_get_ex(runtime, "tc", &tc);
    if (!available || !json_object_get_boolean(available))
        return;
    /* These fields mean the live executor answered and exposed readback.  A
     * false value is still useful evidence: it means the executor is present
     * but the current generation is not applied. */
    json_object_object_add(cap, "runtime_apply_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "runtime_readback",
                           json_object_new_boolean(readback != NULL && tc != NULL));
    json_object_object_add(cap, "dataplane", json_object_new_string("nft_tc_quota"));
}

static struct json_object *webd_terminal_policy_build(struct json_object *body,
                                                      const char *id,
                                                      const char **code,
                                                      char *err, size_t err_len)
{
    struct json_object *rule = NULL;
    struct json_object *targets = NULL;
    struct json_object *rate = NULL;
    struct json_object *quota = NULL;
    struct json_object *lifetime = NULL;
    struct json_object *deny = NULL;
    const char *action;
    const char *scope;
    size_t i;

    *code = "invalid_parameter";
    if (!body || !json_object_is_type(body, json_type_object) ||
        !webd_terminal_policy_id_ok(id)) {
        snprintf(err, err_len, "invalid terminal policy request or id");
        return NULL;
    }
    if (!json_object_object_get_ex(body, "targets", &targets) || !targets ||
        !json_object_is_type(targets, json_type_array) ||
        json_object_array_length(targets) == 0 ||
        json_object_array_length(targets) > WEBD_TERMINAL_POLICY_MAX_TARGETS) {
        snprintf(err, err_len, "targets must contain 1-%d entries",
                 WEBD_TERMINAL_POLICY_MAX_TARGETS);
        return NULL;
    }
    for (i = 0; i < json_object_array_length(targets); i++)
        if (webd_terminal_policy_target_ok(json_object_array_get_idx(targets, i),
                                           (int)i, err, err_len) != 0)
            return NULL;
    if (json_object_object_get_ex(body, "rate", &rate) && rate &&
        !json_object_is_type(rate, json_type_object)) {
        snprintf(err, err_len, "rate must be an object");
        return NULL;
    }
    if (rate) {
        const char *mode = app_nc_json_str(rate, "mode", "per_ip");
        double up = app_nc_json_double(rate, "upload_kbps", 0);
        double down = app_nc_json_double(rate, "download_kbps", 0);
        if ((strcmp(mode, "per_ip") && strcmp(mode, "shared")) || up < 0 || down < 0) {
            snprintf(err, err_len, "rate.mode or rate values are invalid");
            return NULL;
        }
    }
    if (json_object_object_get_ex(body, "quota", &quota) && quota &&
        !json_object_is_type(quota, json_type_object)) {
        snprintf(err, err_len, "quota must be an object");
        return NULL;
    }
    if (quota) {
        const char *mode = app_nc_json_str(quota, "mode", "per_ip");
        const char *accounting = app_nc_json_str(quota, "accounting", "upload_plus_download");
        if (strcmp(mode, "per_ip") && strcmp(mode, "shared") ||
            strcmp(accounting, "upload_plus_download") ||
            app_nc_json_int64(quota, "limit_bytes", 0) < 0) {
            snprintf(err, err_len, "quota mode/accounting/limit_bytes are invalid");
            return NULL;
        }
    }
    if (json_object_object_get_ex(body, "lifetime", &lifetime) && lifetime) {
        const char *unit;
        int64_t count;
        if (!json_object_is_type(lifetime, json_type_object)) {
            snprintf(err, err_len, "lifetime must be an object");
            return NULL;
        }
        unit = app_nc_json_str(lifetime, "unit", "");
        count = app_nc_json_int64(lifetime, "count", 0);
        if ((strcmp(unit, "hours") && strcmp(unit, "days") && strcmp(unit, "weeks") &&
             strcmp(unit, "months") && strcmp(unit, "years")) || count <= 0) {
            snprintf(err, err_len, "lifetime count/unit are invalid");
            return NULL;
        }
    }
    if (json_object_object_get_ex(body, "deny_protocols", &deny) &&
        webd_terminal_policy_protocols_ok(deny, err, err_len) != 0)
        return NULL;
    action = app_nc_json_str(body, "exhausted_action", "block");
    scope = app_nc_json_str(body, "block_scope", "internet_forward");
    if (strcmp(action, "block") || strcmp(scope, "internet_forward")) {
        snprintf(err, err_len, "only block/internet_forward is supported");
        return NULL;
    }
    rule = webd_json_clone(body);
    if (!rule) return NULL;
    /* terminal_policy stores a flat, typed record.  Keep the public HTTP
     * contract nested, but normalize it once at this boundary so WebD and
     * the policy library never maintain two different schemas. */
    {
        struct json_object *v = NULL;
        int64_t started_at = 0;
        int64_t duration_count = 0;
        const char *duration_unit = "days";
        int64_t quota_bytes = 0;
        const char *quota_accounting = "upload_plus_download";
        const char *quota_mode = "per_ip";
        const char *rate_mode = "per_ip";
        int64_t rate_up = 0;
        int64_t rate_down = 0;
        char deny_text[128] = "";

        if (rate && json_object_object_get_ex(rate, "upload_kbps", &v))
            rate_up = json_object_get_int64(v);
        if (rate && json_object_object_get_ex(rate, "download_kbps", &v))
            rate_down = json_object_get_int64(v);
        if (rate)
            rate_mode = app_nc_json_str(rate, "mode", "per_ip");
        if (quota && json_object_object_get_ex(quota, "limit_bytes", &v))
            quota_bytes = json_object_get_int64(v);
        if (quota) {
            quota_accounting = app_nc_json_str(quota, "accounting", "upload_plus_download");
            quota_mode = app_nc_json_str(quota, "mode", "per_ip");
        }
        if (lifetime) {
            started_at = app_nc_json_int64(lifetime, "starts_at", 0);
            duration_count = app_nc_json_int64(lifetime, "count", 0);
            duration_unit = app_nc_json_str(lifetime, "unit", "days");
        }
        if (deny && json_object_is_type(deny, json_type_array)) {
            size_t n = json_object_array_length(deny);
            size_t used = 0;
            for (i = 0; i < n; i++) {
                const char *proto = json_object_get_string(json_object_array_get_idx(deny, i));
                int wrote;
                if (!proto || !proto[0])
                    continue;
                wrote = snprintf(deny_text + used, sizeof(deny_text) - used,
                                 "%s%s", used ? "," : "", proto);
                if (wrote < 0 || (size_t)wrote >= sizeof(deny_text) - used)
                    break;
                used += (size_t)wrote;
            }
        }
        json_object_object_del(rule, "rate");
        json_object_object_del(rule, "quota");
        json_object_object_del(rule, "lifetime");
        json_object_object_del(rule, "deny_protocols");
        json_object_object_add(rule, "rate_upload_kbps", json_object_new_int64(rate_up));
        json_object_object_add(rule, "rate_download_kbps", json_object_new_int64(rate_down));
        json_object_object_add(rule, "rate_mode", json_object_new_string(rate_mode));
        json_object_object_add(rule, "quota_bytes", json_object_new_int64(quota_bytes));
        json_object_object_add(rule, "quota_accounting", json_object_new_string(quota_accounting));
        json_object_object_add(rule, "quota_mode", json_object_new_string(quota_mode));
        json_object_object_add(rule, "started_at", json_object_new_int64(started_at));
        json_object_object_add(rule, "duration_count", json_object_new_int64(duration_count));
        json_object_object_add(rule, "duration_unit", json_object_new_string(duration_unit));
        json_object_object_add(rule, "deny_protocols", json_object_new_string(deny_text));
    }
    json_object_object_add(rule, "id", json_object_new_string(id));
    {
        struct json_object *name_obj = NULL;
        if (!json_object_object_get_ex(rule, "name", &name_obj) || !name_obj)
            json_object_object_add(rule, "name", json_object_new_string(id));
    }
    return rule;
}

static struct json_object *webd_terminal_policy_list(const char *id);

int webd_terminal_policy_apply_ok(struct json_object *resp)
{
    struct json_object *ok = NULL;

    if (!resp || !json_object_object_get_ex(resp, "ok", &ok) || !ok)
        return 0;
    return json_object_get_boolean(ok) ? 1 : 0;
}

int webd_terminal_policy_apply_rollback_noop(struct json_object *resp)
{
    struct json_object *noop = NULL;

    return resp && json_object_object_get_ex(resp, "rollback_noop", &noop) &&
           noop && json_object_get_boolean(noop);
}

struct json_object *webd_terminal_policy_apply(int *status)
{
    struct json_object *resp = app_ubus_invoke_object_timeout(
        "dreamingwrt.flowd", "terminal_policy_apply", NULL, 15000);
    struct json_object *error = NULL;

    if (!resp) {
        *status = 503;
        return webd_error("flowd_terminal_policy_unavailable",
                          "flowd terminal policy executor unavailable",
                          NULL, "webd.terminal_policy");
    }
    if (json_object_object_get_ex(resp, "error", &error) && error) {
        *status = app_response_status(resp, 502);
        return resp;
    }
    if (!webd_terminal_policy_apply_ok(resp)) {
        *status = 502;
        return resp;
    }
    *status = 200;
    return resp;
}

struct json_object *webd_terminal_policy_apply_error(
    struct json_object *apply, int rollback_ok, const char *detail)
{
    struct json_object *data = json_object_new_object();

    json_object_object_add(data, "saved", json_object_new_boolean(0));
    json_object_object_add(data, "runtime_applied", json_object_new_boolean(0));
    json_object_object_add(data, "rollback_ok", json_object_new_boolean(rollback_ok));
    if (detail && detail[0])
        json_object_object_add(data, "rollback_detail", json_object_new_string(detail));
    if (apply)
        json_object_object_add(data, "apply", webd_json_clone(apply));
    return webd_envelope(data, "webd.terminal_policy");
}

struct json_object *webd_terminal_policy_restore(struct json_object *old,
                                                         const char *id,
                                                         int update,
                                                         tp_error_t *tp_err)
{
    struct json_object *restored;

    if (tp_err)
        memset(tp_err, 0, sizeof(*tp_err));
    if (!old || !id || !id[0])
        return NULL;
    /* old is an exact storage snapshot (tp_policy_snapshot), not a display
     * view.  Restoring through tp_policy_update() would bump generation and
     * recompute status; the storage-level restore puts the row back verbatim
     * (recreate=1 also reinserts a policy deleted during rollback). */
    if (tp_policy_restore_snapshot(id, old, update ? 0 : 1, tp_err) != 0)
        return NULL;
    restored = tp_policy_get(id, 1);
    return restored;
}

struct json_object *webd_terminal_policy_write(struct json_object *body,
                                                       const char *id,
                                                       int update,
                                                       int *status)
{
    const char *code = "invalid_parameter";
    char err[256] = "";
    struct json_object *rule;
    struct json_object *data;
    struct json_object *policy = NULL;
    struct json_object *old = NULL;
    struct json_object *apply = NULL;
    struct json_object *restore = NULL;
    struct json_object *rules = NULL;
    struct json_object *cap = NULL;
    tp_error_t tp_err;
    int apply_status = 502;
    int rollback_ok = 1;

    if (update) {
        if (webd_terminal_policy_init_schema() != 0 ||
            !(old = tp_policy_snapshot(id))) {
            *status = 404;
            return webd_error("not_found", "terminal policy not found", NULL,
                              "webd.terminal_policy");
        }
    }
    rule = webd_terminal_policy_build(body, id, &code, err, sizeof(err));
    if (!rule) {
        if (old) json_object_put(old);
        *status = 400;
        return webd_error(code, err, NULL, "webd.terminal_policy");
    }
    memset(&tp_err, 0, sizeof(tp_err));
    policy = update ? tp_policy_update(id, rule, &tp_err) :
                      tp_policy_create(rule, &tp_err);
    json_object_put(rule);
    if (!policy) {
        if (old) json_object_put(old);
        *status = tp_err.code && !strcmp(tp_err.code, "not_found") ? 404 :
                  tp_err.code && (!strcmp(tp_err.code, "dup_id") ||
                                  !strcmp(tp_err.code, "conflict")) ? 409 :
                  tp_err.code && (!strcmp(tp_err.code, "bad_body") ||
                                  !strcmp(tp_err.code, "bad_targets") ||
                                  !strcmp(tp_err.code, "bad_ip") ||
                                  !strcmp(tp_err.code, "bad_cidr") ||
                                  !strcmp(tp_err.code, "bad_range") ||
                                  !strcmp(tp_err.code, "bad_kind") ||
                                  !strcmp(tp_err.code, "bad_proto") ||
                                  !strcmp(tp_err.code, "bad_unit") ||
                                  !strcmp(tp_err.code, "bad_value") ||
                                  !strcmp(tp_err.code, "bad_quota_acct") ||
                                  !strcmp(tp_err.code, "unsupported_rate_mode") ||
                                  !strcmp(tp_err.code, "unsupported_quota_mode") ||
                                  !strcmp(tp_err.code, "rate_target_requires_host") ||
                                  !strcmp(tp_err.code, "too_many_targets")) ? 400 : 500;
        return webd_error(tp_err.code ? tp_err.code : "storage_failed",
                          tp_err.detail[0] ? tp_err.detail : "terminal policy operation failed",
                          NULL, "webd.terminal_policy");
    }

    /* The policy row is not a successful write until flowd has committed the
     * corresponding nft/tc generation.  If the runtime rejects it, restore the
     * previous generation (or remove a newly-created row) before responding. */
    apply = webd_terminal_policy_apply(&apply_status);
    if (!webd_terminal_policy_apply_ok(apply)) {
        if (update) {
            memset(&tp_err, 0, sizeof(tp_err));
            restore = webd_terminal_policy_restore(old, id, 1, &tp_err);
            if (!restore)
                rollback_ok = 0;
        } else if (tp_policy_delete(id) != 0) {
            rollback_ok = 0;
        }
        if (rollback_ok && !webd_terminal_policy_apply_rollback_noop(apply)) {
            struct json_object *reapply = webd_terminal_policy_apply(&apply_status);
            if (!webd_terminal_policy_apply_ok(reapply))
                rollback_ok = 0;
            if (reapply) json_object_put(reapply);
        }
        json_object_put(policy);
        if (old) json_object_put(old);
        if (apply) {
            struct json_object *failure = webd_terminal_policy_apply_error(
                apply, rollback_ok, rollback_ok ? "previous generation restored" :
                "failed to restore previous generation");
            json_object_put(apply);
            *status = rollback_ok ? 502 : 500;
            return failure;
        }
        *status = rollback_ok ? 502 : 500;
        return webd_error("terminal_policy_apply_failed",
                          rollback_ok ? "runtime apply failed; previous generation restored" :
                          "runtime apply failed and rollback failed",
                          NULL, "webd.terminal_policy");
    }

    data = json_object_new_object();
    rules = webd_terminal_policy_list(id);
    cap = webd_terminal_policy_capabilities();
    webd_terminal_policy_merge_runtime_rule(policy, apply);
    webd_terminal_policy_merge_runtime(rules, apply);
    webd_terminal_policy_merge_capabilities(cap, apply);
    json_object_object_add(data, "saved", json_object_new_boolean(1));
    json_object_object_add(data, "applied", json_object_new_boolean(1));
    json_object_object_add(data, "runtime_applied", json_object_new_boolean(1));
    json_object_object_add(data, "apply", apply);
    json_object_object_add(data, "rule", policy);
    json_object_object_add(data, "rules", rules);
    json_object_object_add(data, "capabilities", cap);
    if (old) json_object_put(old);
    *status = 200;
    return webd_envelope(data, "webd.terminal_policy");
}


static struct json_object *webd_terminal_policy_list(const char *id)
{
    struct json_object *arr = json_object_new_array();
    struct json_object *one;
    struct json_object *all;

    if (webd_terminal_policy_init_schema() != 0)
        goto fail;
    if (id && id[0]) {
        one = tp_policy_get(id, 1);
        if (one)
            json_object_array_add(arr, one);
        return arr;
    }
    all = tp_policy_list();
    if (!all) goto fail;
    json_object_put(arr);
    return all;
fail:
    json_object_put(arr);
    return arr;
}

struct json_object *webd_terminal_policy_response(const char *id, int *status)
{
    struct json_object *data = json_object_new_object();
    struct json_object *rules = webd_terminal_policy_list(id);
    struct json_object *runtime;
    struct json_object *cap;
    int rt_status = 0;
    if (!rules) {
        *status = 500;
        json_object_put(data);
        return webd_error("storage_unavailable", "terminal policy storage unavailable", NULL, "webd.terminal_policy");
    }
    json_object_object_add(data, "rules", rules);
    json_object_object_add(data, "count", json_object_new_int((int)json_object_array_length(rules)));
    runtime = webd_terminal_policy_runtime_overlay(&rt_status);
    if (runtime) {
        webd_terminal_policy_merge_runtime(rules, runtime);
        json_object_object_add(data, "runtime", runtime);
    }
    cap = webd_terminal_policy_capabilities();
    webd_terminal_policy_merge_capabilities(cap, runtime);
    json_object_object_add(data, "capabilities", cap);
    *status = 200;
    return webd_envelope(data, "webd.terminal_policy");
}

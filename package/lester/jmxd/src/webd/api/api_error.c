// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Response envelopes and the upstream-error to HTTP-status mapping.
 *
 * app_response_status() is the single place that decides what a core failure looks
 * like over HTTP, and it is ~240 lines of error-code table. Keeping it next to
 * webd_error(), webd_envelope() and webd_meta() means a new error code is added in
 * one file and a route module gets the mapping from one header.
 *
 * ai_envelope_diag() reads struct app_ubus_call_diag. api_error.h only forward
 * declares that type; the full definition is in api_ubus.h, included from this .c,
 * so the two headers do not include each other.
 */
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <json-c/json.h>

#include "api_error.h"
#include "api_util.h"
#include "api_ubus.h"

struct json_object *app_jmx_response_data(int code, struct json_object *data_obj)
{
    struct json_object *root_obj = json_object_new_object();
    if (!root_obj)
        return NULL;
    json_object_object_add(root_obj, "code", json_object_new_int(code));
    if (data_obj)
        json_object_object_add(root_obj, "data", data_obj);
    return root_obj;
}

int app_response_status(struct json_object *resp, int current_status)
{
    struct json_object *data = NULL;
    struct json_object *okv = NULL;
    struct json_object *err = NULL;
    struct json_object *code = NULL;
    const char *code_s;

    if (!resp)
        return 500;
    if (json_object_object_get_ex(resp, "code", &code) && code &&
        json_object_get_int(code) == APP_API_CODE_ERROR) {
        if (json_object_object_get_ex(resp, "data", &data) && data &&
            json_object_object_get_ex(data, "error", &err) && err) {
            code_s = json_object_get_string(err);
            if (code_s && !strcmp(code_s, "not_found"))
                return 404;
            if (code_s && (!strcmp(code_s, "reservation_not_found") ||
                           !strcmp(code_s, "profile_not_found") ||
                           !strcmp(code_s, "network_not_found") ||
                           !strcmp(code_s, "package_not_found") ||
                           !strcmp(code_s, "account_not_found") ||
                           !strcmp(code_s, "ledger_not_found") ||
                           !strcmp(code_s, "access_rule_not_found") ||
                           !strcmp(code_s, "delegated_service_not_found") ||
                           !strcmp(code_s, "delegated_interface_not_found") ||
                           !strcmp(code_s, "delegated_account_not_found") ||
                           !strcmp(code_s, "container_job_not_found") ||
                           !strcmp(code_s, "notification_not_found") ||
                           !strcmp(code_s, "notification_schedule_not_found") ||
                           !strcmp(code_s, "schedule_not_found") ||
                           !strcmp(code_s, "voucher_not_found") ||
                           !strcmp(code_s, "wan_dns_policy_not_found") ||
                           !strcmp(code_s, "wan_not_found") ||
                           !strcmp(code_s, "upnp_acl_not_found") ||
                           !strcmp(code_s, "upnp_mapping_not_found") ||
                           /* IP-table import: the preview id and the job id are
                            * both server-issued, so an id that resolves to
                            * nothing is a stale client reference, not a bad
                            * request. preview_expired is 409 below instead --
                            * that row does exist, it is just past its TTL. */
                           !strcmp(code_s, "preview_not_found") ||
                           !strcmp(code_s, "job_not_found")))
                return 404;
            if (code_s && (!strcmp(code_s, "insufficient_role") ||
                           /* The runtime executor refused the uci/dnsmasq write
                            * outright. Distinct from
                            * runtime_executor_unavailable (503): the executor
                            * answered, and the answer was no. */
                           !strcmp(code_s, "permission_denied")))
                return 403;
            if (code_s && (!strcmp(code_s, "authorization_not_pending") ||
                           !strcmp(code_s, "tool_call_conflict") ||
                           !strcmp(code_s, "task_active") ||
                           !strcmp(code_s, "task_purge_not_supported") ||
                           !strcmp(code_s, "capability_disabled") ||
                           /* WAN redial refused because the line is switched
                            * off: a state conflict, not a malformed request. */
                           !strcmp(code_s, "line_disabled") ||
                           /* Delegated dialing needs an enabled WAN and there
                            * is none. The request was well formed; the network
                            * configuration is what blocks it. */
                           !strcmp(code_s, "delegated_interface_unavailable") ||
                           !strcmp(code_s, "protected_management_lan") ||
                           !strcmp(code_s, "last_enabled_lan") ||
                           !strcmp(code_s, "lan_ports_attached") ||
                           !strcmp(code_s, "child_lans_attached") ||
                           !strcmp(code_s, "ipam_network_attached") ||
                           !strcmp(code_s, "package_exists") ||
                           !strcmp(code_s, "account_exists") ||
                           !strcmp(code_s, "ledger_exists") ||
                           !strcmp(code_s, "access_rule_exists") ||
                           !strcmp(code_s, "delegated_service_exists") ||
                           !strcmp(code_s, "delegated_username_conflict") ||
                           !strcmp(code_s, "notification_schedule_exists") ||
                           !strcmp(code_s, "schedule_conflict") ||
                           !strcmp(code_s, "schedule_pending") ||
                           !strcmp(code_s, "immediate_action_pending") ||
                           !strcmp(code_s, "package_in_use") ||
                           !strcmp(code_s, "account_name_conflict") ||
                           !strcmp(code_s, "account_has_active_sessions") ||
                           !strcmp(code_s, "profile_in_use") ||
                           !strcmp(code_s, "revision_conflict") ||
                           !strcmp(code_s, "draft_pending") ||
                           !strcmp(code_s, "allowlist_enabled") ||
                           !strcmp(code_s, "whitelist_empty") ||
                           !strcmp(code_s, "not_pending") ||
                           !strcmp(code_s, "confirm_window_expired") ||
                           /*
                            * IP-table write contract. All six are "the request
                            * was well formed but the world moved": the address
                            * or MAC is taken, the caller's expected_version is
                            * behind, the preview aged out or was computed
                            * against an older revision, or a request_id was
                            * reused for a different batch. A client can resolve
                            * every one of them by re-reading and re-previewing,
                            * which is what 409 tells it to do.
                            */
                           !strcmp(code_s, "address_conflict") ||
                           !strcmp(code_s, "mac_conflict") ||
                           !strcmp(code_s, "expected_version_mismatch") ||
                           !strcmp(code_s, "request_id_conflict") ||
                           !strcmp(code_s, "preview_expired") ||
                           !strcmp(code_s, "preview_stale") ||
                           /* The confirmation digest did not match the stored
                            * summary, so the batch the user approved is not the
                            * batch being committed. */
                           !strcmp(code_s, "confirmation_mismatch") ||
                           !strcmp(code_s, "management_reachability_risk")))
                return 409;
            if (code_s && (!strcmp(code_s, "dns_snapshot_incomplete") ||
                           !strcmp(code_s, "dns_listen_interface_invalid") ||
                           !strcmp(code_s, "dns_validation_failed") ||
                           !strcmp(code_s, "upnp_mapping_invalid") ||
                           !strcmp(code_s, "missing_expected_revision") ||
                           !strcmp(code_s, "invalid_expected_revision") ||
                           !strcmp(code_s, "invalid_items") ||
                           !strcmp(code_s, "invalid_ssid_ids") ||
                           !strcmp(code_s, "invalid_ssid_id") ||
                           !strcmp(code_s, "duplicate_ssid_id") ||
                           !strcmp(code_s, "invalid_action") ||
                           !strcmp(code_s, "invalid_mac") ||
                           !strcmp(code_s, "config_revision_required") ||
                           !strcmp(code_s, "missing_id") ||
                           /*
                            * IP-table write contract: payload accepted, content
                            * rejected. Grouped with missing_id and
                            * missing_expected_revision above, which are the same
                            * shape -- a field the route requires and the caller
                            * left out or filled with something unusable. The
                            * csv_* codes and too_many_rows are the CSV parser's
                            * verdicts, so they belong here too rather than at
                            * 400: the request framing was fine, the file was
                            * not.
                            */
                           !strcmp(code_s, "invalid_address") ||
                           !strcmp(code_s, "missing_confirmation") ||
                           !strcmp(code_s, "missing_expected_version") ||
                           !strcmp(code_s, "missing_preview_id") ||
                           !strcmp(code_s, "missing_request_id") ||
                           !strcmp(code_s, "missing_job_id") ||
                           !strcmp(code_s, "missing_rows") ||
                           !strcmp(code_s, "empty_rows") ||
                           !strcmp(code_s, "empty_csv") ||
                           !strcmp(code_s, "csv_too_large") ||
                           !strcmp(code_s, "csv_header_missing") ||
                           !strcmp(code_s, "csv_too_many_columns") ||
                           !strcmp(code_s, "too_many_rows") ||
                           /* Every row in the stored preview failed validation,
                            * so there is nothing to commit. The per-row reasons
                            * are in the preview response, not in this code. */
                           !strcmp(code_s, "preview_has_no_valid_rows") ||
                           !strcmp(code_s, "ip_outside_network_subnet")))
                return 422;
            /* IPAM item failures keep their root cause: a rolled back write is
             * storage/consistency state, not a malformed request. */
            if (code_s && (!strcmp(code_s, "transaction_busy") ||
                           !strcmp(code_s, "transaction_rolled_back") ||
                           !strcmp(code_s, "refresh_rolled_back") ||
                           !strcmp(code_s, "ipam_address_write_failed") ||
                           !strcmp(code_s, "ipam_address_delete_failed") ||
                           !strcmp(code_s, "ipam_metadata_write_failed") ||
                           !strcmp(code_s, "dhcp_reservation_write_failed") ||
                           !strcmp(code_s, "dhcp_reservation_cleanup_failed") ||
                           !strcmp(code_s, "dhcp_exclude_write_failed") ||
                           !strcmp(code_s, "dhcp_exclude_cleanup_failed") ||
                           !strcmp(code_s, "stale_reservation_cleanup_failed") ||
                           !strcmp(code_s, "readback_mismatch") ||
                           !strcmp(code_s, "wifi_apply_failed") ||
                           !strcmp(code_s, "wifi_delete_failed")))
                return 503;
            if (code_s && !strcmp(code_s, "rate_limited"))
                return 429;
            if (code_s && (!strcmp(code_s, "upnp_static_mapping_unsupported") ||
                           !strcmp(code_s, "upnp_stun_unsupported") ||
                           !strcmp(code_s, "upnp_mapping_port_conflict") ||
                           !strcmp(code_s, "upnp_mapping_local_listener") ||
                           !strcmp(code_s, "upnp_mapping_management_port")))
                return 409;
            if (code_s && !strcmp(code_s, "upnp_mapping_dataplane_failed"))
                return 500;
            if (code_s && !strcmp(code_s, "runtime_rollback_failed"))
                return 500;
            if (code_s && !strcmp(code_s, "desired_rollback_failed"))
                return 500;
            /*
             * The write failed AND the restore of /etc/config/dhcp failed, so the
             * box is left in a state neither the caller nor the server intended.
             * The two *_rollback_failed codes above are exact matches and do not
             * cover this bare one; without this row it fell through to 400, which
             * would have told a client to fix its request when the actual problem
             * is that DHCP config needs manual attention.
             */
            if (code_s && !strcmp(code_s, "rollback_failed"))
                return 500;
            if (code_s && !strcmp(code_s, "storage_error"))
                return 500;
            if (code_s && (strstr(code_s, "save_failed") ||
                           strstr(code_s, "delete_failed") ||
                           strstr(code_s, "apply_failed")))
                return 500;
            if (code_s && (!strcmp(code_s, "source_unavailable") ||
                           !strcmp(code_s, "storage_unavailable") ||
                           !strcmp(code_s, "scheduler_unavailable") ||
                           /* No usable path to uci/dnsmasq at all, so the write
                            * was never attempted and nothing changed. Retryable
                            * once the executor is back, which is what separates
                            * it from permission_denied (403). */
                           !strcmp(code_s, "runtime_executor_unavailable") ||
                           !strcmp(code_s, "backend_starting_or_unavailable")))
                return 503;
            /* The daemon is up and this build simply has no such method. 503
             * would invite a retry that can never succeed, so this reads as
             * "not implemented" instead. */
            if (code_s && !strcmp(code_s, "method_not_registered"))
                return 501;
            /* The dependency answered late, not never: 504 keeps that apart
             * from 503 so a client can offer "retry/refresh" rather than
             * reporting the backend as down. */
            if (code_s && !strcmp(code_s, "dependency_timeout"))
                return 504;
        }
        return 400;
    }
    if (json_object_object_get_ex(resp, "ok", &okv) && okv && !json_object_get_boolean(okv))
    {
        if (json_object_object_get_ex(resp, "error", &err) && err &&
            json_object_object_get_ex(err, "code", &code) && code) {
            code_s = json_object_get_string(code);
            if (code_s && (!strcmp(code_s, "source_unavailable") ||
                           !strcmp(code_s, "backend_starting_or_unavailable")))
                return 503;
            if (code_s && !strcmp(code_s, "method_not_registered"))
                return 501;
            if (code_s && !strcmp(code_s, "dependency_timeout"))
                return 504;
        }
        return 400;
    }
    return current_status;
}

/*
 * Failure envelope for the AI routes.
 *
 * `default_code` is the code to use when the upstream reply carries none, and
 * every caller passes 200 because that is the success code. On the NULL path
 * that made the failure report `ok:false` alongside `code:200`, which is not
 * merely untidy: a client that decides success from `code` reads the failure as
 * a success carrying no `data`, i.e. "the backend has no providers" rather than
 * "the call never landed". So the NULL branch sets its own code and never
 * borrows the success one.
 *
 * `diag` is optional. When the caller used the diag-aware invoke it tells
 * connect / lookup / invoke apart, which is the difference between "core is not
 * running", "core is up but the method is not registered", and "the call timed
 * out". Collapsing those into one `internal_error` is what made this
 * undiagnosable from the outside.
 */
struct json_object *ai_envelope_diag(struct json_object *resp, int default_code,
                                            const struct app_ubus_call_diag *diag)
{
    if (!resp) {
        struct json_object *e = json_object_new_object();
        const char *stage = (diag && diag->stage) ? diag->stage : "";
        /*
         * 504 only for a call that reached the object and then failed to
         * complete; connect/lookup mean the dependency is not there to talk to,
         * which is 502. app_routed_http_status() picks `http_status` up ahead of
         * everything else, so the HTTP status and the body agree.
         */
        int http_status = !strcmp(stage, "invoke") ? 504 : 502;
        const char *message = "core_unavailable";

        if (!strcmp(stage, "invoke"))
            message = "core_call_timeout";
        else if (!strcmp(stage, "lookup"))
            message = "core_method_unavailable";
        else if (!strcmp(stage, "connect"))
            message = "core_not_reachable";

        json_object_object_add(e, "ok", json_object_new_boolean(0));
        json_object_object_add(e, "code", json_object_new_int(http_status));
        json_object_object_add(e, "http_status", json_object_new_int(http_status));
        json_object_object_add(e, "message", json_object_new_string(message));
        if (stage[0])
            json_object_object_add(e, "stage", json_object_new_string(stage));
        if (diag && diag->rc >= 0)
            json_object_object_add(e, "ubus_rc", json_object_new_int(diag->rc));
        /*
         * Keep the old name reachable so a client that matched on
         * "internal_error" still sees it, while the specific reason is in
         * `message`.
         */
        json_object_object_add(e, "reason", json_object_new_string("internal_error"));
        json_object_object_add(e, "ts", json_object_new_int64(time(NULL)));
        (void)default_code;
        return e;
    }
    struct json_object *code_obj = NULL;
    struct json_object *data_obj = NULL;
    int code = default_code;
    int is_ok = 1;
    const char *msg = "";

    if (json_object_object_get_ex(resp, "code", &code_obj) && code_obj)
        code = json_object_get_int(code_obj);
    is_ok = code == APP_API_CODE_SUCCESS || code == 200;
    json_object_object_get_ex(resp, "data", &data_obj);
    if (data_obj) {
        struct json_object *ok_obj = NULL;
        struct json_object *err_obj = NULL;
        if (json_object_object_get_ex(data_obj, "ok", &ok_obj) && ok_obj)
            is_ok = json_object_get_boolean(ok_obj);
        if (json_object_object_get_ex(data_obj, "error", &err_obj) && err_obj && json_object_get_string(err_obj))
            msg = json_object_get_string(err_obj);
        if (!is_ok && (!msg || !msg[0])) {
            struct json_object *msg_obj = NULL;
            if (json_object_object_get_ex(data_obj, "message", &msg_obj) && msg_obj && json_object_get_string(msg_obj))
                msg = json_object_get_string(msg_obj);
        }
    }
    struct json_object *env = json_object_new_object();
    json_object_object_add(env, "ok", json_object_new_boolean(is_ok));
    json_object_object_add(env, "code", json_object_new_int(code));
    if (msg && msg[0]) json_object_object_add(env, "message", json_object_new_string(msg));
    if (data_obj) json_object_object_add(env, "data", json_object_get(data_obj));
    json_object_object_add(env, "ts", json_object_new_int64(time(NULL)));
    json_object_put(resp);
    return env;
}

/*
 * Envelope without call diagnostics, for callers whose upstream object is not
 * reached through the diag-aware invoke. The NULL branch still reports 502
 * rather than the success code.
 */
struct json_object *ai_envelope(struct json_object *resp, int default_code)
{
    return ai_envelope_diag(resp, default_code, NULL);
}

int app_jmx_response_http_status(struct json_object *resp, int default_status)
{
    struct json_object *code_obj = NULL;
    struct json_object *data_obj = NULL;
    struct json_object *ok_obj = NULL;
    struct json_object *err_obj = NULL;

    if (!resp)
        return 500;
    if (json_object_object_get_ex(resp, "code", &code_obj) && code_obj &&
        json_object_get_int(code_obj) != APP_API_CODE_SUCCESS) {
        if (json_object_object_get_ex(resp, "data", &data_obj) && data_obj &&
            json_object_object_get_ex(data_obj, "error", &err_obj) && err_obj) {
            const char *err = json_object_get_string(err_obj);

            if (err && !strcmp(err, "capability_disabled"))
                return 409;
            if (err && (!strcmp(err, "source_unavailable") || !strcmp(err, "backend_starting_or_unavailable")))
                return 503;
            /* Missing on this build, not temporarily down: never retryable. */
            if (err && !strcmp(err, "method_not_registered"))
                return 501;
        }
        return 400;
    }
    if (json_object_object_get_ex(resp, "data", &data_obj) && data_obj &&
        json_object_object_get_ex(data_obj, "ok", &ok_obj) && ok_obj &&
        !json_object_get_boolean(ok_obj)) {
        if (json_object_object_get_ex(data_obj, "error", &err_obj) && err_obj) {
            const char *err = json_object_get_string(err_obj);

            if (err && !strcmp(err, "capability_disabled"))
                return 409;
            if (err && (!strcmp(err, "source_unavailable") || !strcmp(err, "backend_starting_or_unavailable")))
                return 503;
            if (err && (!strcmp(err, "controller_disabled") || !strcmp(err, "controller_not_started")))
                return 503;
            if (err && !strcmp(err, "method_not_registered"))
                return 501;
        }
        return 400;
    }
    return default_status;
}

int app_routed_http_status(struct json_object *resp, int current_status)
{
    struct json_object *v = NULL;
    const char *error = "";
    const char *reason = "";

    if (!resp)
        return 500;
    if (json_object_object_get_ex(resp, "http_status", &v) && v) {
        int status = json_object_get_int(v);
        if (status >= 400 && status <= 599)
            return status;
    }
    if (json_object_object_get_ex(resp, "error", &v) && v)
        error = json_object_get_string(v);
    /* flowd terminal-policy apply/runtime methods return direct business
     * state.  `ok:false` here means the dataplane is not applied (for example
     * terminal_policy_nft_table_absent or flowd_apply_mode_disabled), not that
     * the HTTP request was malformed.  Preserve the status assigned by the
     * route so callers can inspect the reason and capabilities. */
    if (json_object_object_get_ex(resp, "reason", &v) && v)
        reason = json_object_get_string(v);
    if (json_object_object_get_ex(resp, "available", &v) && v &&
        json_object_get_boolean(v) && reason && reason[0] &&
        (!strncmp(reason, "terminal_policy_", 16) ||
         !strncmp(reason, "flowd_apply_mode_", 17)))
        return current_status;
    if (!strcmp(error, "reference_conflict") || !strcmp(error, "conflict"))
        return 409;
    if (!strcmp(error, "not_found"))
        return 404;
    if (!strcmp(error, "storage_error"))
        return 500;
    if (!strcmp(error, "source_unavailable"))
        return 503;
    return app_response_status(resp, current_status);
}

struct json_object *webd_meta(const char *source)
{
    char request_id[64];
    struct json_object *meta = json_object_new_object();

    webd_request_id(request_id, sizeof(request_id));
    json_object_object_add(meta, "request_id", json_object_new_string(request_id));
    json_object_object_add(meta, "source", json_object_new_string(source ? source : "webd"));
    json_object_object_add(meta, "generated_at", json_object_new_int64(now_s()));
    return meta;
}

struct json_object *webd_envelope(struct json_object *data, const char *source)
{
    struct json_object *root = json_object_new_object();

    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "data", data ? data : json_object_new_object());
    json_object_object_add(root, "meta", webd_meta(source));
    return root;
}

void webd_mark_cached_response_stale(struct json_object *resp, int age_ms,
                                            const char *source_error)
{
    struct json_object *meta = NULL;
    struct json_object *data = NULL;
    struct json_object *traffic = NULL;
    const char *reason = (source_error && source_error[0]) ?
                         source_error : "upstream_timeout_stale_cache";

    if (!resp)
        return;

    if (!json_object_object_get_ex(resp, "meta", &meta) || !meta ||
        !json_object_is_type(meta, json_type_object)) {
        meta = webd_meta("webd.dashboard_snapshot_cache");
        json_object_object_add(resp, "meta", meta);
    }

    json_object_object_add(meta, "cached", json_object_new_boolean(1));
    json_object_object_add(meta, "stale", json_object_new_boolean(1));
    json_object_object_add(meta, "degraded", json_object_new_boolean(1));
    json_object_object_add(meta, "cache_age_ms", json_object_new_int(age_ms));
    json_object_object_add(meta, "source_error", json_object_new_string(reason));

    if (json_object_object_get_ex(resp, "data", &data) && data &&
        json_object_is_type(data, json_type_object)) {
        json_object_object_add(data, "stale", json_object_new_boolean(1));
        json_object_object_add(data, "degraded", json_object_new_boolean(1));
        json_object_object_add(data, "cache_age_ms", json_object_new_int(age_ms));
        json_object_object_add(data, "source_error", json_object_new_string(reason));

        if (json_object_object_get_ex(data, "traffic", &traffic) && traffic &&
            json_object_is_type(traffic, json_type_object)) {
            json_object_object_add(traffic, "stale", json_object_new_boolean(1));
            json_object_object_add(traffic, "degraded", json_object_new_boolean(1));
            json_object_object_add(traffic, "cache_age_ms", json_object_new_int(age_ms));
            json_object_object_add(traffic, "source_error", json_object_new_string(reason));
        }
    }
}

struct json_object *webd_error(const char *code, const char *message,
                                      const char *missing, const char *source)
{
    struct json_object *root = json_object_new_object();
    struct json_object *err = json_object_new_object();
    struct json_object *details = json_object_new_object();

    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(err, "code", json_object_new_string(code ? code : "internal_error"));
    json_object_object_add(err, "message", json_object_new_string(message ? message : "internal error"));
    if (missing && missing[0])
        json_object_object_add(details, "missing", json_object_new_string(missing));
    json_object_object_add(err, "details", details);
    json_object_object_add(root, "error", err);
    json_object_object_add(root, "meta", webd_meta(source ? source : "webd"));
    return root;
}

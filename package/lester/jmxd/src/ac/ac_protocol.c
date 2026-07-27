// SPDX-License-Identifier: GPL-2.0-or-later
#include "ac_internal.h"

#include <openssl/crypto.h>

static void ac_capability(struct json_object *cap, struct json_object *reasons,
                          const char *name, int enabled, const char *reason)
{
    json_object_object_add(cap, name, json_object_new_boolean(enabled));
    if (!enabled)
        json_object_object_add(reasons, name,
            json_object_new_string(reason ? reason : "phase0_not_implemented"));
}

struct json_object *ac_capabilities_json(void)
{
    struct json_object *root = json_object_new_object();
    struct json_object *cap = json_object_new_object();
    struct json_object *reasons = json_object_new_object();
    int scan_execution_ap_count = 0;
    int scan_execution = ac_db_scan_execution_available(
        ac_now_s() - AC_AP_ONLINE_TIMEOUT_SECONDS,
        &scan_execution_ap_count) > 0;

    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "contract_version",
                           json_object_new_string(AC_CONTRACT_VERSION));
    json_object_object_add(root, "source", json_object_new_string(AC_SERVICE_NAME));
    ac_capability(cap, reasons, "status", 1, NULL);
    ac_capability(cap, reasons, "capabilities", 1, NULL);
    ac_capability(cap, reasons, "local_wifi_required", 0,
                  "controller_does_not_require_local_phy");
    ac_capability(cap, reasons, "pairing_token_security_base", 1, NULL);
    ac_capability(cap, reasons, "admin_pairing_ipc", 1, NULL);
    ac_capability(cap, reasons, "node_enrollment_core", 1, NULL);
    ac_capability(cap, reasons, "pairing_token_ipc", ac_transport_listening(),
                  ac_transport_reason());
    ac_capability(cap, reasons, "ap_adoption", ac_transport_listening(),
                  ac_transport_reason());
    ac_capability(cap, reasons, "heartbeat", ac_transport_listening(),
                  ac_transport_reason());
    ac_capability(cap, reasons, "certificate_rotation", 0,
                  "phase1_certificate_lifecycle_pending");
    ac_capability(cap, reasons, "remote_telemetry", 1, NULL);
    ac_capability(cap, reasons, "telemetry", 1, NULL);
    ac_capability(cap, reasons, "scan_job_store", 1, NULL);
    ac_capability(cap, reasons, "scan_job_control_plane", 1, NULL);
    /* Bounded station connectivity/roam event store fed by the
     * snapshot-diff producer.  The store being present does not claim
     * fine-grained hostapd event granularity; every row carries
     * source=ac_snapshot_diff and its observation window. */
    ac_capability(cap, reasons, "station_event_store", 1, NULL);
    ac_capability(cap, reasons, "scan_dispatch", scan_execution,
                  "no_online_ap_control_v2_session");
    ac_capability(cap, reasons, "scan_execution", scan_execution,
                  "no_online_ap_control_v2_session");
    json_object_object_add(cap, "scan_execution_ap_count",
                           json_object_new_int(scan_execution_ap_count));
    ac_capability(cap, reasons, "ssid_create", 0,
                  "phase2_transactional_apply_pending");
    ac_capability(cap, reasons, "ssid_update", 0,
                  "phase2_transactional_apply_pending");
    ac_capability(cap, reasons, "ssid_delete", 0,
                  "phase2_transactional_apply_pending");
    ac_capability(cap, reasons, "password_rotation", 0,
                  "phase2_secret_safe_apply_pending");
    ac_capability(cap, reasons, "radio_update", 0,
                  "phase2_transactional_apply_pending");
    ac_capability(cap, reasons, "ap_actions", 0,
                  "phase2_transactional_apply_pending");
    ac_capability(cap, reasons, "offline_queue", 0,
                  "phase3_reconciliation_pending");
    ac_capability(cap, reasons, "transactional_apply", 0,
                  "validate_apply_readback_rollback_pending");
    ac_capability(cap, reasons, "automatic_rollback", 0,
                  "validate_apply_readback_rollback_pending");
    ac_capability(cap, reasons, "node_transport", ac_transport_listening(),
                  ac_transport_reason());
    json_object_object_add(cap, "reasons", reasons);
    json_object_object_add(root, "capabilities", cap);
    return root;
}

static struct json_object *ac_radio_job_item(const struct ac_radio_job *job,
                                             int include_idempotency)
{
    struct json_object *item = json_object_new_object();

    json_object_object_add(item, "job_id", json_object_new_string(job->job_id));
    json_object_object_add(item, "ap_id", json_object_new_string(job->ap_id));
    json_object_object_add(item, "radio_id", json_object_new_string(job->radio_id));
    json_object_object_add(item, "mode", json_object_new_string(job->mode));
    json_object_object_add(item, "state", json_object_new_string(job->state));
    if (include_idempotency)
        json_object_object_add(item, "idempotency_key",
                               json_object_new_string(job->idempotency_key));
    json_object_object_add(item, "created_at", json_object_new_int64(job->created_at));
    json_object_object_add(item, "updated_at", json_object_new_int64(job->updated_at));
    json_object_object_add(item, "lease_owner",
                           json_object_new_string(job->lease_owner));
    json_object_object_add(item, "lease_expires_at",
                           json_object_new_int64(job->lease_expires_at));
    json_object_object_add(item, "session_epoch",
                           json_object_new_string(job->session_epoch));
    json_object_object_add(item, "attempt_id",
                           json_object_new_string(job->attempt_id));
    json_object_object_add(item, "dispatch_generation",
                           json_object_new_int64(job->dispatch_generation));
    json_object_object_add(item, "request_digest",
                           json_object_new_string(job->request_digest));
    json_object_object_add(item, "finish_id",
                           json_object_new_string(job->finish_id));
    json_object_object_add(item, "finish_digest",
                           json_object_new_string(job->finish_digest));
    json_object_object_add(item, "last_progress_at",
                           json_object_new_int64(job->last_progress_at));
    json_object_object_add(item, "reconcile_deadline",
                           json_object_new_int64(job->reconcile_deadline));
    json_object_object_add(item, "result_count", json_object_new_int(job->result_count));
    json_object_object_add(item, "result_bytes", json_object_new_int64(job->result_bytes));
    json_object_object_add(item, "result_digest",
                           json_object_new_string(job->result_digest));
    json_object_object_add(item, "result_complete",
                           json_object_new_boolean(job->result_complete));
    json_object_object_add(item, "error_code",
                           json_object_new_string(job->error_code));
    json_object_object_add(item, "expected_impact",
                           json_object_new_string(job->expected_impact));
    return item;
}

static struct json_object *ac_radio_job_error(const char *operation,
                                              const char *error,
                                              const char *reason)
{
    struct json_object *root = json_object_new_object();

    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "contract_version",
                           json_object_new_string(AC_CONTRACT_VERSION));
    json_object_object_add(root, "source", json_object_new_string(AC_SERVICE_NAME));
    json_object_object_add(root, "operation",
                           json_object_new_string(operation ? operation : "radio_job"));
    json_object_object_add(root, "error",
                           json_object_new_string(error ? error : "radio_job_error"));
    json_object_object_add(root, "reason",
                           json_object_new_string(reason ? reason : "radio_job_failed"));
    return root;
}

static struct json_object *ac_radio_job_response(const char *operation,
                                                  const struct ac_radio_job *job,
                                                  int idempotent)
{
    struct json_object *root = json_object_new_object();

    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "contract_version",
                           json_object_new_string(AC_CONTRACT_VERSION));
    json_object_object_add(root, "source", json_object_new_string(AC_SERVICE_NAME));
    json_object_object_add(root, "operation",
                           json_object_new_string(operation ? operation : "radio_job"));
    json_object_object_add(root, "idempotent", json_object_new_boolean(idempotent));
    json_object_object_add(root, "item", ac_radio_job_item(job, 1));
    return root;
}

struct json_object *ac_radio_job_create_json(const char *ap_id,
                                             const char *radio_id,
                                             const char *mode,
                                             const char *idempotency_key)
{
    struct ac_radio_job job;
    int result = ac_db_radio_job_create(ap_id, radio_id, mode, idempotency_key, &job);

    if (result != AC_RADIO_JOB_OK && result != AC_RADIO_JOB_IDEMPOTENT)
        return ac_radio_job_error("radio_job_create",
            result == AC_RADIO_JOB_UNAVAILABLE ? "capability_disabled" :
            result == AC_RADIO_JOB_INVALID_TARGET ? "invalid_target" :
            result == AC_RADIO_JOB_CONFLICT ? "idempotency_conflict" : "database_error",
            result == AC_RADIO_JOB_UNAVAILABLE ? "no_online_ap_control_v2_session" :
            result == AC_RADIO_JOB_INVALID_TARGET ?
                "ap_not_adopted_or_radio_not_current" :
            result == AC_RADIO_JOB_CONFLICT ? "idempotency_key_binding_mismatch" :
            "radio_job_store_failed");
    {
        struct json_object *root = ac_radio_job_response(
            "radio_job_create", &job, result == AC_RADIO_JOB_IDEMPOTENT);
        int dispatched = strcmp(job.state, "queued") != 0;
        int executed = !strcmp(job.state, "running") ||
            !strcmp(job.state, "completed") || !strcmp(job.state, "failed") ||
            !strcmp(job.state, "cancelled");
        const char *reason = !strcmp(job.state, "queued") ?
            "scan_job_queued" : !strcmp(job.state, "leased") ?
            "scan_job_delivery_pending" : !strcmp(job.state, "running") ?
            "scan_job_running" : "scan_job_state_available";

        json_object_object_add(root, "accepted", json_object_new_boolean(1));
        json_object_object_add(root, "persisted", json_object_new_boolean(1));
        json_object_object_add(root, "dispatched",
                               json_object_new_boolean(dispatched));
        json_object_object_add(root, "executed",
                               json_object_new_boolean(executed));
        json_object_object_add(root, "invoked",
                               json_object_new_boolean(executed));
        json_object_object_add(root, "reason", json_object_new_string(reason));
        return root;
    }
}

struct json_object *ac_radio_job_status_json(const char *job_id)
{
    struct ac_radio_job job;

    if (ac_db_radio_job_status(job_id, &job) != AC_RADIO_JOB_OK)
        return ac_radio_job_error("radio_job_status", "not_found", "radio_job_not_found");
    return ac_radio_job_response("radio_job_status", &job, 0);
}

struct ac_radio_job_list_context {
    struct json_object *items;
};

static int ac_radio_job_list_visit_json(const struct ac_radio_job *job, void *opaque)
{
    struct ac_radio_job_list_context *context = opaque;

    json_object_array_add(context->items, ac_radio_job_item(job, 1));
    return 0;
}

struct json_object *ac_radio_job_list_json(const char *ap_id)
{
    struct ac_radio_job_list_context context = { .items = json_object_new_array() };
    struct json_object *root = json_object_new_object();
    int limited = 0;
    int count = ac_db_radio_job_list(ap_id, ac_radio_job_list_visit_json,
                                     &context, &limited);

    if (count < 0) {
        json_object_put(context.items);
        json_object_put(root);
        return ac_radio_job_error("radio_job_list", "database_error", "radio_job_list_failed");
    }
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "contract_version",
                           json_object_new_string(AC_CONTRACT_VERSION));
    json_object_object_add(root, "source", json_object_new_string(AC_SERVICE_NAME));
    json_object_object_add(root, "items", context.items);
    json_object_object_add(root, "count", json_object_new_int(count));
    json_object_object_add(root, "limited", json_object_new_boolean(limited));
    json_object_object_add(root, "limit",
                           json_object_new_int(AC_RADIO_JOB_LIST_LIMIT));
    return root;
}

struct json_object *ac_radio_job_cancel_json(const char *job_id)
{
    struct ac_radio_job job;

    if (ac_db_radio_job_cancel(job_id, &job) != AC_RADIO_JOB_OK)
        return ac_radio_job_error("radio_job_cancel", "not_found_or_conflict",
                                  "radio_job_cancel_failed");
    return ac_radio_job_response("radio_job_cancel", &job, 0);
}

struct json_object *ac_radio_job_result_json(const char *job_id)
{
    struct ac_radio_job job;
    char *result_json = NULL;
    struct json_object *items = NULL;
    int payload_available = 0;
    int terminal;

    if (ac_db_radio_job_result_metadata(job_id, &job) != AC_RADIO_JOB_OK)
        return ac_radio_job_error("radio_job_result", "not_found", "radio_job_not_found");
    {
        struct json_object *root = ac_radio_job_response("radio_job_result", &job, 0);

        if (ac_db_radio_job_result_payload(job_id, &result_json) == AC_RADIO_JOB_OK) {
            items = json_tokener_parse(result_json);
            payload_available = items &&
                json_object_is_type(items, json_type_array);
        }
        free(result_json);
        if (!items || !json_object_is_type(items, json_type_array)) {
            json_object_put(items);
            items = json_object_new_array();
        }
        terminal = !strcmp(job.state, "completed") || !strcmp(job.state, "failed") ||
                   !strcmp(job.state, "cancelled");
        json_object_object_add(root, "result_available",
                               json_object_new_boolean(terminal && payload_available));
        json_object_object_add(root, "result_complete",
                               json_object_new_boolean(job.result_complete));
        json_object_object_add(root, "result_truncated",
                               json_object_new_boolean(!strcmp(job.state, "completed") &&
                                                       !job.result_complete));
        json_object_object_add(root, "items", items);
        json_object_object_add(root, "reason", json_object_new_string(
            terminal && payload_available ?
            (job.result_complete ? "scan_result_persisted" :
                                   "scan_result_persisted_truncated") :
            (job.error_code[0] ? job.error_code : "scan_result_pending")));
        return root;
    }
}

struct json_object *ac_radio_job_latest_results_json(void)
{
    struct json_object *root = ac_db_radio_job_latest_results_json();

    return root ? root : ac_radio_job_error(
        "radio_job_latest_results", "database_error",
        "radio_job_latest_results_failed");
}

struct json_object *ac_status_json(void)
{
    struct json_object *root = json_object_new_object();
    struct json_object *controller = json_object_new_object();
    struct json_object *local_wifi = json_object_new_object();
    struct json_object *managed = json_object_new_object();
    struct json_object *transport = json_object_new_object();
    int managed_count = 0;
    int managed_online = 0;
    int managed_status;

    managed_status = ac_db_managed_ap_counts(
        ac_now_s() - AC_AP_ONLINE_TIMEOUT_SECONDS,
        &managed_count, &managed_online);

    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "contract_version",
                           json_object_new_string(AC_CONTRACT_VERSION));
    json_object_object_add(root, "service", json_object_new_string(AC_SERVICE_NAME));
    json_object_object_add(root, "schema_version", json_object_new_int(AC_SCHEMA_VERSION));
    json_object_object_add(root, "started_at", json_object_new_int64(g_ac_started_at));
    json_object_object_add(root, "uptime_seconds",
                           json_object_new_int64(ac_now_s() - g_ac_started_at));
    json_object_object_add(controller, "available", json_object_new_boolean(1));
    json_object_object_add(controller, "requires_local_phy", json_object_new_boolean(0));
    json_object_object_add(controller, "controller_id",
                           json_object_new_string(ac_transport_controller_id()));
    json_object_object_add(root, "controller", controller);
    json_object_object_add(local_wifi, "available", json_object_new_boolean(0));
    json_object_object_add(local_wifi, "reason",
                           json_object_new_string("no_phy_detected"));
    json_object_object_add(local_wifi, "scope",
                           json_object_new_string("controller_local_only"));
    json_object_object_add(root, "local_wifi", local_wifi);
    json_object_object_add(managed, "available",
                           json_object_new_boolean(managed_status == 0));
    json_object_object_add(managed, "count",
                           json_object_new_int(managed_count));
    json_object_object_add(managed, "online",
                           json_object_new_int(managed_online));
    json_object_object_add(managed, "online_timeout_seconds",
                           json_object_new_int(AC_AP_ONLINE_TIMEOUT_SECONDS));
    json_object_object_add(managed, "reason", json_object_new_string(
        managed_status == 0 ?
        (managed_count > 0 ? "heartbeat_readback" : "no_managed_aps") :
        "managed_ap_readback_failed"));
    json_object_object_add(root, "managed_aps", managed);
    json_object_object_add(transport, "listening",
                           json_object_new_boolean(ac_transport_listening()));
    json_object_object_add(transport, "port",
                           json_object_new_int(ac_transport_port()));
    json_object_object_add(transport, "reason",
                           json_object_new_string(ac_transport_reason()));
    json_object_object_add(root, "transport", transport);
    json_object_object_add(root, "capabilities", ac_capabilities_json());
    return root;
}

struct json_object *ac_write_disabled_json(const char *operation,
                                           const char *reason)
{
    struct json_object *root = json_object_new_object();

    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "error",
                           json_object_new_string("capability_disabled"));
    json_object_object_add(root, "operation",
                           json_object_new_string(operation ? operation : "write"));
    json_object_object_add(root, "reason", json_object_new_string(
        reason ? reason : "phase0_write_pipeline_disabled"));
    json_object_object_add(root, "accepted", json_object_new_boolean(0));
    json_object_object_add(root, "persisted", json_object_new_boolean(0));
    json_object_object_add(root, "applied", json_object_new_boolean(0));
    return root;
}

static struct json_object *ac_pairing_error(const char *operation,
                                            const char *error,
                                            const char *reason)
{
    struct json_object *root = json_object_new_object();

    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "contract_version",
                           json_object_new_string(AC_CONTRACT_VERSION));
    json_object_object_add(root, "source", json_object_new_string(AC_SERVICE_NAME));
    json_object_object_add(root, "operation",
                           json_object_new_string(operation ? operation : "pairing_token"));
    json_object_object_add(root, "error",
                           json_object_new_string(error ? error : "pairing_token_error"));
    json_object_object_add(root, "reason",
                           json_object_new_string(reason ? reason : "pairing_token_error"));
    json_object_object_add(root, "mtls_ready", json_object_new_boolean(0));
    json_object_object_add(root, "adopted", json_object_new_boolean(0));
    return root;
}

static struct json_object *ac_pairing_status_object(
    const struct ac_pairing_token_status *status)
{
    struct json_object *item = json_object_new_object();

    json_object_object_add(item, "token_id", json_object_new_string(status->token_id));
    json_object_object_add(item, "state", json_object_new_string(status->state));
    json_object_object_add(item, "site_id", json_object_new_string(status->site_id));
    json_object_object_add(item, "hardware_bound",
                           json_object_new_boolean(status->hardware_bound));
    json_object_object_add(item, "attempts", json_object_new_int(status->attempts));
    json_object_object_add(item, "max_attempts",
                           json_object_new_int(status->max_attempts));
    json_object_object_add(item, "created_at",
                           json_object_new_int64(status->created_at));
    json_object_object_add(item, "expires_at",
                           json_object_new_int64(status->expires_at));
    json_object_object_add(item, "consumed_at",
                           json_object_new_int64(status->consumed_at));
    json_object_object_add(item, "revoked_at",
                           json_object_new_int64(status->revoked_at));
    return item;
}

struct json_object *ac_pairing_token_create_json(int64_t ttl_seconds,
                                                  int max_attempts,
                                                  const char *site_id,
                                                  const char *hardware_digest)
{
    struct ac_pairing_token_secret secret;
    struct json_object *root;

    memset(&secret, 0, sizeof(secret));
    if (ac_db_pairing_token_create(ttl_seconds, max_attempts, site_id,
                                   hardware_digest, &secret) != 0)
        return ac_pairing_error("pairing_token_create", "invalid_request",
                                "pairing_token_create_failed");
    root = json_object_new_object();
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "contract_version",
                           json_object_new_string(AC_CONTRACT_VERSION));
    json_object_object_add(root, "source", json_object_new_string(AC_SERVICE_NAME));
    json_object_object_add(root, "token_id", json_object_new_string(secret.token_id));
    json_object_object_add(root, "token", json_object_new_string(secret.token));
    json_object_object_add(root, "display_once", json_object_new_boolean(1));
    json_object_object_add(root, "created_at", json_object_new_int64(secret.created_at));
    json_object_object_add(root, "expires_at", json_object_new_int64(secret.expires_at));
    json_object_object_add(root, "max_attempts", json_object_new_int(secret.max_attempts));
    json_object_object_add(root, "mtls_ready", json_object_new_boolean(0));
    json_object_object_add(root, "adopted", json_object_new_boolean(0));
    OPENSSL_cleanse(&secret, sizeof(secret));
    return root;
}

struct json_object *ac_pairing_token_status_json(const char *token_id)
{
    struct ac_pairing_token_status status;
    struct json_object *root;

    if (ac_db_pairing_token_status(token_id, &status) != 0)
        return ac_pairing_error("pairing_token_status", "not_found",
                                "pairing_token_not_found");
    root = json_object_new_object();
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "contract_version",
                           json_object_new_string(AC_CONTRACT_VERSION));
    json_object_object_add(root, "source", json_object_new_string(AC_SERVICE_NAME));
    json_object_object_add(root, "item", ac_pairing_status_object(&status));
    return root;
}

struct ac_pairing_list_context {
    struct json_object *items;
};

static int ac_pairing_list_visit(const struct ac_pairing_token_status *status,
                                 void *opaque)
{
    struct ac_pairing_list_context *context = opaque;

    json_object_array_add(context->items, ac_pairing_status_object(status));
    return 0;
}

struct json_object *ac_pairing_token_list_json(void)
{
    struct ac_pairing_list_context context;
    struct json_object *root = json_object_new_object();
    int count;

    context.items = json_object_new_array();
    count = ac_db_pairing_token_list(ac_pairing_list_visit, &context);
    if (count < 0) {
        json_object_put(context.items);
        json_object_put(root);
        return ac_pairing_error("pairing_token_list", "database_error",
                                "pairing_token_list_failed");
    }
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "contract_version",
                           json_object_new_string(AC_CONTRACT_VERSION));
    json_object_object_add(root, "source", json_object_new_string(AC_SERVICE_NAME));
    json_object_object_add(root, "items", context.items);
    json_object_object_add(root, "count", json_object_new_int(count));
    return root;
}

struct json_object *ac_pairing_token_revoke_json(const char *token_id)
{
    struct json_object *root;

    if (ac_db_pairing_token_revoke(token_id) != 0)
        return ac_pairing_error("pairing_token_revoke", "conflict",
                                "pairing_token_not_active");
    root = ac_pairing_token_status_json(token_id);
    json_object_object_add(root, "revoked", json_object_new_boolean(1));
    json_object_object_add(root, "mtls_ready", json_object_new_boolean(0));
    json_object_object_add(root, "adopted", json_object_new_boolean(0));
    return root;
}

struct json_object *ac_pairing_token_redeem_json(const char *token_id,
                                                  const char *token,
                                                  const char *site_id,
                                                  const char *hardware_digest)
{
    struct ac_pairing_token_status status;
    struct json_object *root;
    const char *reason;
    int result = ac_db_pairing_token_redeem(token_id, token, site_id,
                                            hardware_digest, &status);

    if (result != AC_PAIRING_REDEEM_OK) {
        switch (result) {
        case AC_PAIRING_REDEEM_INVALID: reason = "invalid_pairing_token"; break;
        case AC_PAIRING_REDEEM_EXPIRED: reason = "pairing_token_expired"; break;
        case AC_PAIRING_REDEEM_REVOKED: reason = "pairing_token_revoked"; break;
        case AC_PAIRING_REDEEM_CONSUMED: reason = "pairing_token_consumed"; break;
        case AC_PAIRING_REDEEM_EXHAUSTED: reason = "pairing_token_attempts_exhausted"; break;
        default: reason = "pairing_token_redeem_failed"; break;
        }
        return ac_pairing_error("pairing_token_redeem", "redeem_rejected", reason);
    }
    root = json_object_new_object();
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "contract_version",
                           json_object_new_string(AC_CONTRACT_VERSION));
    json_object_object_add(root, "source", json_object_new_string(AC_SERVICE_NAME));
    json_object_object_add(root, "redeemed", json_object_new_boolean(1));
    json_object_object_add(root, "item", ac_pairing_status_object(&status));
    json_object_object_add(root, "mtls_ready", json_object_new_boolean(0));
    json_object_object_add(root, "adopted", json_object_new_boolean(0));
    return root;
}

int ac_protocol_init(void)
{
    return 0;
}

void ac_protocol_close(void)
{
}

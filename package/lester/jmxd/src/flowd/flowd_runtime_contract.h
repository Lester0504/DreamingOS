// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_FLOWD_RUNTIME_CONTRACT_H
#define DREAMINGWRT_FLOWD_RUNTIME_CONTRACT_H

#include <string.h>

#include <json-c/json.h>

#define FLOWD_RUNTIME_CONTRACT_VERSION "flow-engine-runtime-v1"
#define FLOWD_EFFECTIVE_APPLY_MODE "managed"
#define FLOWD_APPLY_MODE_DISABLED_REASON "flowd_apply_mode_disabled"
#define FLOWD_APPLY_UNAVAILABLE_REASON "dataplane_apply_executor_missing"
#define FLOWD_READBACK_UNAVAILABLE_REASON "dataplane_readback_not_implemented"
#define FLOWD_RUNTIME_DB_MISSING_REASON "runtime_db_missing"
#define FLOWD_RUNTIME_NOT_APPLIED_REASON "runtime_not_applied"
#define FLOWD_RUNTIME_NOT_POPULATED_REASON "runtime_not_populated"
#define FLOWD_RUNTIME_CONTRACT_ABI_VERSION 2U

struct flowd_runtime_contract_input {
    int configured_enabled;
    const char *configured_apply_mode;
    int config_store_available;
    int runtime_snapshot_available;
    int nft_binary_available;
    int runtime_dir_available;
    int tc_binary_available;
    int apply_executor_available;
    int runtime_readback_available;
    int runtime_applied;
    int runtime_db_present;
    int runtime_db_openable;
    int runtime_populated;
    char runtime_reason[128];
};

static inline const char *flowd_runtime_contract_state_reason(
    const struct flowd_runtime_contract_input *input,
    int managed)
{
    if (!managed)
        return input->configured_enabled ? FLOWD_APPLY_MODE_DISABLED_REASON :
                                           "flow_engine_disabled";
    if (!input->runtime_db_present)
        return FLOWD_RUNTIME_DB_MISSING_REASON;
    if (!input->runtime_db_openable)
        return "runtime_db_open_failed";
    if (!input->runtime_populated)
        return FLOWD_RUNTIME_NOT_POPULATED_REASON;
    if (!input->apply_executor_available)
        return FLOWD_APPLY_UNAVAILABLE_REASON;
    if (!input->runtime_readback_available)
        return FLOWD_READBACK_UNAVAILABLE_REASON;
    if (input->runtime_reason[0] &&
        strcmp(input->runtime_reason, "runtime_state_missing"))
        return input->runtime_reason;
    if (!input->runtime_applied)
        return FLOWD_RUNTIME_NOT_APPLIED_REASON;
    return "runtime_applied";
}

static inline void flowd_runtime_contract_add(
    struct json_object *response,
    const struct flowd_runtime_contract_input *input)
{
    struct json_object *capabilities;
    struct json_object *reasons;
    const char *configured_apply_mode;
    const char *runtime_reason;
    int managed;
    int apply_available;
    int readback_available;

    if (!response || !input)
        return;

    configured_apply_mode = input->configured_apply_mode &&
                            input->configured_apply_mode[0]
        ? input->configured_apply_mode : FLOWD_EFFECTIVE_APPLY_MODE;
    managed = input->configured_enabled &&
              !strcmp(configured_apply_mode, "managed");
    /* Executables alone do not prove that a runtime snapshot exists. */
    apply_available = managed && input->runtime_db_present &&
                      input->runtime_db_openable && input->runtime_populated &&
                      (input->apply_executor_available ||
                       (input->tc_binary_available && input->runtime_dir_available));
    readback_available = managed && input->runtime_db_present &&
                         input->runtime_db_openable && input->runtime_populated &&
                         (input->runtime_readback_available ||
                          (input->tc_binary_available && input->runtime_snapshot_available));
    capabilities = json_object_new_object();
    reasons = json_object_new_object();
    runtime_reason = flowd_runtime_contract_state_reason(input, managed);
    {
        const char *apply_reason = runtime_reason;
        const char *readback_reason = runtime_reason;

        if (!input->configured_enabled) {
            apply_reason = "flow_engine_disabled";
            readback_reason = "flow_engine_disabled";
        } else if (!managed) {
            apply_reason = FLOWD_APPLY_MODE_DISABLED_REASON;
            readback_reason = FLOWD_APPLY_MODE_DISABLED_REASON;
        } else if (!input->runtime_db_present) {
            apply_reason = FLOWD_RUNTIME_DB_MISSING_REASON;
            readback_reason = FLOWD_RUNTIME_DB_MISSING_REASON;
        } else if (!input->runtime_db_openable) {
            apply_reason = "runtime_db_open_failed";
            readback_reason = "runtime_db_open_failed";
        } else if (!input->runtime_populated) {
            apply_reason = FLOWD_RUNTIME_NOT_POPULATED_REASON;
            readback_reason = FLOWD_RUNTIME_NOT_POPULATED_REASON;
        } else if (!input->apply_executor_available) {
            apply_reason = FLOWD_APPLY_UNAVAILABLE_REASON;
            readback_reason = FLOWD_READBACK_UNAVAILABLE_REASON;
        } else if (!input->runtime_readback_available) {
            readback_reason = FLOWD_READBACK_UNAVAILABLE_REASON;
        }
        json_object_object_add(reasons, "flow_engine_apply",
                               json_object_new_string(apply_available ? runtime_reason : apply_reason));
        json_object_object_add(reasons, "flow_engine_runtime_readback",
                               json_object_new_string(readback_available ? runtime_reason : readback_reason));
    }
    json_object_object_add(capabilities, "flow_engine_read",
                           json_object_new_boolean(1));
    json_object_object_add(capabilities, "flow_engine_config_write",
                           json_object_new_boolean(managed &&
                                                   input->config_store_available));
    json_object_object_add(capabilities, "flow_engine_apply",
                           json_object_new_boolean(apply_available));
    json_object_object_add(capabilities, "flow_engine_apply_ready",
                           json_object_new_boolean(apply_available));
    json_object_object_add(capabilities, "flow_engine_runtime_readback",
                           json_object_new_boolean(readback_available));
    json_object_object_add(capabilities, "nft_revision_transaction",
                           json_object_new_boolean(input->config_store_available &&
                                                   input->nft_binary_available));
    json_object_object_add(capabilities, "nft_revision_readback",
                           json_object_new_boolean(input->config_store_available &&
                                                   input->nft_binary_available &&
                                                   input->runtime_dir_available));
    json_object_object_add(capabilities, "nft_revision_sentinel_only",
                           json_object_new_boolean(1));
    if (!input->config_store_available)
        json_object_object_add(reasons, "flow_engine_config_write",
                               json_object_new_string("config_store_unavailable"));
    else if (!input->configured_enabled)
        json_object_object_add(reasons, "flow_engine_config_write",
                               json_object_new_string("flow_engine_disabled"));
    else if (!managed)
        json_object_object_add(reasons, "flow_engine_config_write",
                               json_object_new_string(FLOWD_APPLY_MODE_DISABLED_REASON));
    if (!input->config_store_available || !input->nft_binary_available) {
        const char *nft_reason = !input->config_store_available
            ? "config_store_unavailable" : "nft_binary_unavailable";

        json_object_object_add(reasons, "nft_revision_transaction",
                               json_object_new_string(nft_reason));
        json_object_object_add(reasons, "nft_revision_readback",
                               json_object_new_string(nft_reason));
    } else if (!input->runtime_dir_available) {
        json_object_object_add(reasons, "nft_revision_readback",
                               json_object_new_string("runtime_dir_unavailable"));
    }
    json_object_object_add(capabilities, "reasons", reasons);

    json_object_object_add(response, "runtime_contract_version",
                           json_object_new_string(FLOWD_RUNTIME_CONTRACT_VERSION));
    json_object_object_add(response, "configured_enabled",
                           json_object_new_boolean(input->configured_enabled));
    json_object_object_add(response, "configured_apply_mode",
                           json_object_new_string(configured_apply_mode));
    json_object_object_add(response, "apply_mode",
                           json_object_new_string(configured_apply_mode));
    json_object_object_add(response, "worker_available",
                           json_object_new_boolean(1));
    json_object_object_add(response, "runtime_snapshot_available",
                           json_object_new_boolean(input->runtime_snapshot_available));
    json_object_object_add(response, "runtime_db_present",
                           json_object_new_boolean(input->runtime_db_present));
    json_object_object_add(response, "runtime_db_openable",
                           json_object_new_boolean(input->runtime_db_openable));
    json_object_object_add(response, "runtime_populated",
                           json_object_new_boolean(input->runtime_populated));
    json_object_object_add(response, "runtime_applied",
                           json_object_new_boolean(managed && input->runtime_applied));
    json_object_object_add(response, "runtime_reason",
                           json_object_new_string(runtime_reason));
    json_object_object_add(response, "degraded",
                           json_object_new_boolean(!(managed && input->runtime_applied)));
    json_object_object_add(response, "capabilities", capabilities);
}

#endif

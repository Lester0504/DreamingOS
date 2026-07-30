// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_FLOWD_RUNTIME_CONTRACT_H
#define DREAMINGWRT_FLOWD_RUNTIME_CONTRACT_H

#include <string.h>

#include <json-c/json.h>

#define FLOWD_RUNTIME_CONTRACT_VERSION "flow-engine-runtime-v1"
#define FLOWD_EFFECTIVE_APPLY_MODE "plan-only"
#define FLOWD_APPLY_UNAVAILABLE_REASON "dataplane_apply_executor_missing"
#define FLOWD_READBACK_UNAVAILABLE_REASON "dataplane_readback_not_implemented"

struct flowd_runtime_contract_input {
    int configured_enabled;
    const char *configured_apply_mode;
    int config_store_available;
    int runtime_snapshot_available;
    int nft_binary_available;
    int runtime_dir_available;
};

static inline void flowd_runtime_contract_add(
    struct json_object *response,
    const struct flowd_runtime_contract_input *input)
{
    struct json_object *capabilities;
    struct json_object *reasons;
    const char *configured_apply_mode;
    const char *runtime_reason;

    if (!response || !input)
        return;

    configured_apply_mode = input->configured_apply_mode &&
                            input->configured_apply_mode[0]
        ? input->configured_apply_mode : FLOWD_EFFECTIVE_APPLY_MODE;
    runtime_reason = input->configured_enabled
        ? FLOWD_APPLY_UNAVAILABLE_REASON : "flow_engine_disabled";

    capabilities = json_object_new_object();
    reasons = json_object_new_object();
    json_object_object_add(capabilities, "flow_engine_read",
                           json_object_new_boolean(1));
    json_object_object_add(capabilities, "flow_engine_config_write",
                           json_object_new_boolean(input->config_store_available));
    json_object_object_add(capabilities, "flow_engine_apply",
                           json_object_new_boolean(0));
    json_object_object_add(capabilities, "flow_engine_runtime_readback",
                           json_object_new_boolean(0));
    json_object_object_add(capabilities, "nft_revision_transaction",
                           json_object_new_boolean(input->config_store_available &&
                                                   input->nft_binary_available));
    json_object_object_add(capabilities, "nft_revision_readback",
                           json_object_new_boolean(input->config_store_available &&
                                                   input->nft_binary_available &&
                                                   input->runtime_dir_available));
    json_object_object_add(capabilities, "nft_revision_sentinel_only",
                           json_object_new_boolean(1));
    json_object_object_add(reasons, "flow_engine_apply",
                           json_object_new_string(FLOWD_APPLY_UNAVAILABLE_REASON));
    json_object_object_add(reasons, "flow_engine_runtime_readback",
                           json_object_new_string(FLOWD_READBACK_UNAVAILABLE_REASON));
    if (!input->config_store_available)
        json_object_object_add(reasons, "flow_engine_config_write",
                               json_object_new_string("config_store_unavailable"));
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
                           json_object_new_string(FLOWD_EFFECTIVE_APPLY_MODE));
    json_object_object_add(response, "worker_available",
                           json_object_new_boolean(1));
    json_object_object_add(response, "runtime_snapshot_available",
                           json_object_new_boolean(input->runtime_snapshot_available));
    json_object_object_add(response, "runtime_applied",
                           json_object_new_boolean(0));
    json_object_object_add(response, "runtime_reason",
                           json_object_new_string(runtime_reason));
    json_object_object_add(response, "degraded", json_object_new_boolean(1));
    json_object_object_add(response, "capabilities", capabilities);
}

#endif

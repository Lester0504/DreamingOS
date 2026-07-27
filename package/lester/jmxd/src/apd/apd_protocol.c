// SPDX-License-Identifier: GPL-2.0-or-later
#include "apd_internal.h"

static void apd_capability(struct json_object *cap, struct json_object *reasons,
                           const char *name, int enabled, const char *reason)
{
    json_object_object_add(cap, name, json_object_new_boolean(enabled));
    if (!enabled)
        json_object_object_add(reasons, name,
            json_object_new_string(reason ? reason : "phase0_not_implemented"));
}

static void apd_hex_public(char out[APD_ED25519_KEY_LEN * 2 + 1],
                           const unsigned char public_key[APD_ED25519_KEY_LEN])
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < APD_ED25519_KEY_LEN; i++) {
        out[i * 2] = digits[public_key[i] >> 4];
        out[i * 2 + 1] = digits[public_key[i] & 15];
    }
    out[APD_ED25519_KEY_LEN * 2] = '\0';
}

static struct json_object *apd_local_error(const char *operation,
                                           const char *reason)
{
    struct json_object *root = json_object_new_object();

    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "error",
                           json_object_new_string("local_state_unavailable"));
    json_object_object_add(root, "operation", json_object_new_string(operation));
    json_object_object_add(root, "reason", json_object_new_string(reason));
    return root;
}

struct json_object *apd_capabilities_json(void)
{
    struct json_object *root = json_object_new_object();
    struct json_object *cap = json_object_new_object();
    struct json_object *reasons = json_object_new_object();
    struct json_object *probe = NULL;
    const struct apd_backend_ops *backend = apd_backend();
    int snapshot_supported = backend && backend->snapshot_supported &&
                             backend->snapshot;

    if (backend && backend->probe)
        backend->probe(&probe);
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "contract_version",
                           json_object_new_string(APD_CONTRACT_VERSION));
    json_object_object_add(root, "source", json_object_new_string(APD_SERVICE_NAME));
    json_object_object_add(root, "backend",
                           json_object_new_string(backend ? backend->name : "none"));
    if (probe)
        json_object_object_add(root, "probe", probe);
    apd_capability(cap, reasons, "status", 1, NULL);
    apd_capability(cap, reasons, "capabilities", 1, NULL);
    apd_capability(cap, reasons, "local_probe", backend != NULL,
                   "openwrt_backend_unavailable");
    apd_capability(cap, reasons, "snapshot", snapshot_supported,
                   "normalized_snapshot_backend_unavailable");
    apd_capability(cap, reasons, "local_station_telemetry", snapshot_supported,
                   "hostapd_snapshot_backend_unavailable");
    apd_capability(cap, reasons, "identity", 1, NULL);
    apd_capability(cap, reasons, "pairing_status", 1, NULL);
    apd_capability(cap, reasons, "pairing_state_machine", 1, NULL);
    apd_capability(cap, reasons, "pairing", APD_NODE_TRANSPORT_ENABLED,
                   apd_transport_reason());
    apd_capability(cap, reasons, "controller_transport", apd_transport_connected(),
                   apd_transport_reason());
    apd_capability(cap, reasons, "heartbeat", apd_transport_connected(),
                   apd_transport_reason());
    apd_capability(cap, reasons, "remote_telemetry", snapshot_supported,
                   "normalized_snapshot_backend_unavailable");
    apd_capability(cap, reasons, "validate", 0,
                   "phase2_candidate_validation_pending");
    apd_capability(cap, reasons, "stage", 0,
                   "phase2_atomic_staging_pending");
    apd_capability(cap, reasons, "apply", 0,
                   "phase2_transactional_apply_pending");
    apd_capability(cap, reasons, "readback", 0,
                   "phase2_canonical_readback_pending");
    apd_capability(cap, reasons, "rollback", 0,
                   "phase2_rollback_readback_pending");
    json_object_object_add(cap, "reasons", reasons);
    json_object_object_add(root, "capabilities", cap);
    return root;
}

struct json_object *apd_snapshot_json(void)
{
    const struct apd_backend_ops *backend = apd_backend();
    struct json_object *snapshot = NULL;

    if (!backend || !backend->snapshot_supported || !backend->snapshot)
        return apd_backend_disabled("snapshot",
            "normalized_snapshot_backend_unavailable");
    if (backend->snapshot(&snapshot) != 0 || !snapshot) {
        if (snapshot)
            return snapshot;
        return apd_backend_disabled("snapshot", "snapshot_collection_failed");
    }
    return snapshot;
}

struct json_object *apd_identity_json(void)
{
    struct apd_node_identity identity;
    struct json_object *root;
    char public_key_hex[APD_ED25519_KEY_LEN * 2 + 1];

    memset(&identity, 0, sizeof(identity));
    memset(public_key_hex, 0, sizeof(public_key_hex));
    if (apd_db_identity_get(&identity) != 0)
        return apd_local_error("identity", "identity_read_failed");
    apd_hex_public(public_key_hex, identity.public_key);
    root = json_object_new_object();
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "contract_version",
                           json_object_new_string(APD_CONTRACT_VERSION));
    json_object_object_add(root, "ap_id", json_object_new_string(identity.ap_id));
    json_object_object_add(root, "algorithm", json_object_new_string("Ed25519"));
    json_object_object_add(root, "key_id", json_object_new_string(identity.key_id));
    json_object_object_add(root, "public_key_encoding",
                           json_object_new_string("raw-hex"));
    json_object_object_add(root, "public_key",
                           json_object_new_string(public_key_hex));
    json_object_object_add(root, "created_at",
                           json_object_new_int64(identity.created_at));
    json_object_object_add(root, "key_exportable",
                           json_object_new_boolean(0));
    OPENSSL_cleanse(&identity, sizeof(identity));
    OPENSSL_cleanse(public_key_hex, sizeof(public_key_hex));
    return root;
}

struct json_object *apd_pairing_status_json(void)
{
    struct apd_pairing_status status;
    struct json_object *root;
    int adopted;

    memset(&status, 0, sizeof(status));
    if (apd_db_pairing_status_get(&status) != 0)
        return apd_local_error("pairing_status", "pairing_state_read_failed");
    adopted = apd_transport_adopted();
    root = json_object_new_object();
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "contract_version",
                           json_object_new_string(APD_CONTRACT_VERSION));
    json_object_object_add(root, "state",
                           json_object_new_string(adopted ? "adopted" : status.state));
    json_object_object_add(root, "enrollment_state",
                           json_object_new_string(status.state));
    json_object_object_add(root, "controller_id",
                           json_object_new_string(status.controller_id));
    json_object_object_add(root, "request_id",
                           json_object_new_string(status.request_id));
    json_object_object_add(root, "challenge_present",
                           json_object_new_boolean(status.challenge_present));
    json_object_object_add(root, "attempts", json_object_new_int(status.attempts));
    json_object_object_add(root, "expires_at",
                           json_object_new_int64(status.expires_at));
    json_object_object_add(root, "updated_at",
                           json_object_new_int64(status.updated_at));
    json_object_object_add(root, "remote_transport_ready",
                           json_object_new_boolean(apd_transport_connected()));
    json_object_object_add(root, "mtls_ready", json_object_new_boolean(adopted));
    json_object_object_add(root, "adopted", json_object_new_boolean(adopted));
    OPENSSL_cleanse(&status, sizeof(status));
    return root;
}

struct json_object *apd_status_json(void)
{
    struct json_object *root = json_object_new_object();
    struct json_object *transport = json_object_new_object();
    struct apd_node_identity identity;
    struct apd_pairing_status pairing;
    int adopted;

    memset(&identity, 0, sizeof(identity));
    memset(&pairing, 0, sizeof(pairing));
    adopted = apd_transport_adopted();

    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "contract_version",
                           json_object_new_string(APD_CONTRACT_VERSION));
    json_object_object_add(root, "service", json_object_new_string(APD_SERVICE_NAME));
    json_object_object_add(root, "schema_version", json_object_new_int(APD_SCHEMA_VERSION));
    json_object_object_add(root, "started_at", json_object_new_int64(g_apd_started_at));
    json_object_object_add(root, "uptime_seconds",
                           json_object_new_int64(apd_now_s() - g_apd_started_at));
    json_object_object_add(transport, "connected",
                           json_object_new_boolean(apd_transport_connected()));
    json_object_object_add(transport, "reason",
                           json_object_new_string(apd_transport_reason()));
    json_object_object_add(root, "transport", transport);
    if (apd_db_identity_get(&identity) == 0)
        json_object_object_add(root, "ap_id", json_object_new_string(identity.ap_id));
    if (apd_db_pairing_status_get(&pairing) == 0) {
        json_object_object_add(root, "pairing_state",
                               json_object_new_string(adopted ? "adopted" :
                                                              pairing.state));
        json_object_object_add(root, "enrollment_state",
                               json_object_new_string(pairing.state));
    }
    json_object_object_add(root, "adoption_state",
                           json_object_new_string(adopted ?
                                                  "adopted" : "not_adopted"));
    json_object_object_add(root, "capabilities", apd_capabilities_json());
    OPENSSL_cleanse(&identity, sizeof(identity));
    OPENSSL_cleanse(&pairing, sizeof(pairing));
    return root;
}

struct json_object *apd_write_disabled_json(const char *operation,
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

int apd_protocol_init(void)
{
    return apd_backend() ? 0 : -1;
}

void apd_protocol_close(void)
{
}

// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * ubus surface for the relay agent.
 *
 * Read-only by design. webd calls `identity` to answer pair/confirm and login
 * with the router's public key, and `status` backs operator diagnostics. There
 * is deliberately no method that changes relay configuration: that lives in UCI
 * so it goes through the normal config authority instead of a second path.
 */
#include "cloud_internal.h"

struct ubus_context *g_cloud_ubus;
struct blob_buf g_cloud_blob;

static int cloud_send_json(struct ubus_context *ctx,
                           struct ubus_request_data *req,
                           struct json_object *response)
{
    const char *text = response ? json_object_to_json_string(response) : "{}";

    blob_buf_init(&g_cloud_blob, 0);
    if (!blobmsg_add_json_from_string(&g_cloud_blob, text)) {
        blob_buf_free(&g_cloud_blob);
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    ubus_send_reply(ctx, req, g_cloud_blob.head);
    blob_buf_free(&g_cloud_blob);
    return UBUS_STATUS_OK;
}

/*
 * The public key and router_id are non-secret by design: the App needs both to
 * establish the channel, and the relay learns router_id anyway. The private key
 * is never exposed here.
 */
struct json_object *cloud_identity_json(void)
{
    const struct cloud_identity *identity = cloud_identity();
    struct json_object *root = json_object_new_object();
    struct json_object *data;
    char *encoded = NULL;
    char *signing_encoded = NULL;

    if (!root)
        return NULL;
    json_object_object_add(root, "contract_version",
                           json_object_new_string(CLOUD_CONTRACT_VERSION));
    json_object_object_add(root, "source",
                           json_object_new_string(CLOUD_SERVICE_NAME));

    if (!identity) {
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "error",
                               json_object_new_string("identity_unavailable"));
        return root;
    }
    if (cloud_base64_encode(identity->public_key, CLOUD_X25519_KEY_LEN,
                            &encoded) != 0 ||
        cloud_base64_encode(identity->signing_public_key,
                            CLOUD_ED25519_KEY_LEN, &signing_encoded) != 0) {
        free(encoded);
        free(signing_encoded);
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "error",
                               json_object_new_string("encode_failed"));
        return root;
    }

    data = json_object_new_object();
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "router_id",
                           json_object_new_string(identity->router_id));
    json_object_object_add(data, "router_public_key",
                           json_object_new_string(encoded));
    json_object_object_add(data, "kex", json_object_new_string("x25519"));
    /* The App pins both halves: the kex key opens the channel, the signing key
     * is what makes router_id verifiable rather than a claim. */
    json_object_object_add(data, "router_signing_key",
                           json_object_new_string(signing_encoded));
    json_object_object_add(data, "signing_algorithm",
                           json_object_new_string("ed25519"));
    /*
     * Whether router_id is the contract fingerprint of both keys. A legacy UUID
     * still routes, but cannot self enroll, and the UI needs to be able to say
     * so instead of offering a button that can only fail.
     */
    json_object_object_add(data, "router_id_key_derived",
                           json_object_new_boolean(identity->router_id_is_key_derived));
    if (!identity->router_id_is_key_derived)
        json_object_object_add(data, "router_id_reason",
                               json_object_new_string("legacy_router_id"));
    json_object_object_add(data, "fingerprint",
                           json_object_new_string(identity->fingerprint));
    json_object_object_add(root, "data", data);
    free(encoded);
    free(signing_encoded);
    return root;
}

struct json_object *cloud_status_json(void)
{
    const struct cloud_identity *identity = cloud_identity();
    struct json_object *root = json_object_new_object();
    struct json_object *data;
    struct json_object *tunnel;
    struct cloud_config config;
    uint64_t forwarded = 0, rejected = 0;
    int64_t since;
    int devices = 0;

    if (!root)
        return NULL;
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "contract_version",
                           json_object_new_string(CLOUD_CONTRACT_VERSION));
    json_object_object_add(root, "source",
                           json_object_new_string(CLOUD_SERVICE_NAME));

    data = json_object_new_object();
    json_object_object_add(data, "uptime_seconds",
                           json_object_new_int64(cloud_now_s() - g_cloud_started_at));
    json_object_object_add(data, "router_id",
                           identity ? json_object_new_string(identity->router_id) :
                                      NULL);
    json_object_object_add(data, "fingerprint",
                           identity ? json_object_new_string(identity->fingerprint) :
                                      NULL);
    if (!identity)
        json_object_object_add(data, "identity_reason",
                               json_object_new_string("identity_unavailable"));
    if (identity) {
        json_object_object_add(data, "router_id_key_derived",
                               json_object_new_boolean(identity->router_id_is_key_derived));
        /* Distinguishes "not enrolled yet" from "enrolled but cannot connect",
         * which otherwise look identical from the outside. */
        json_object_object_add(data, "enrolled",
                               json_object_new_boolean(cloud_enroll_token_present()));
    }

    cloud_tunnel_counters(&forwarded, &rejected);
    since = cloud_tunnel_connected_since();

    tunnel = json_object_new_object();
    json_object_object_add(tunnel, "state",
                           json_object_new_string(cloud_tunnel_state()));
    json_object_object_add(tunnel, "connected",
                           json_object_new_boolean(cloud_tunnel_connected()));
    /* null rather than 0 when never connected, per the project's
     * "no placeholder values" convention. */
    json_object_object_add(tunnel, "connected_since",
                           since > 0 ? json_object_new_int64(since) : NULL);
    if (since <= 0)
        json_object_object_add(tunnel, "connected_since_reason",
                               json_object_new_string("never_connected"));
    {
        const char *reason = cloud_tunnel_reason();

        json_object_object_add(tunnel, "reason",
                               reason && reason[0] ?
                                   json_object_new_string(reason) : NULL);
    }
    json_object_object_add(tunnel, "requests_forwarded",
                           json_object_new_int64((int64_t)forwarded));
    json_object_object_add(tunnel, "requests_rejected",
                           json_object_new_int64((int64_t)rejected));
    json_object_object_add(data, "tunnel", tunnel);

    /* Report the effective configuration, minus the shared secret. Whether a
     * token is set is useful for diagnosis; its value is not. */
    if (cloud_config_load(&config) == 0) {
        struct json_object *settings = json_object_new_object();

        json_object_object_add(settings, "enabled",
                               json_object_new_boolean(config.enabled));
        json_object_object_add(settings, "host",
                               config.host[0] ?
                                   json_object_new_string(config.host) : NULL);
        json_object_object_add(settings, "port",
                               json_object_new_int(config.port));
        json_object_object_add(settings, "auth_token_configured",
                               json_object_new_boolean(config.auth_token[0] ? 1 : 0));
        json_object_object_add(settings, "tls_verify",
                               json_object_new_boolean(config.tls_verify));
        /* Reported separately from the UCI token because the effective
         * credential may come from either place. */
        json_object_object_add(settings, "tunnel_token_stored",
                               json_object_new_boolean(cloud_enroll_token_present()));
        json_object_object_add(data, "config", settings);
        cloud_config_cleanse(&config);
    }

    if (cloud_devices_count(&devices) == 0) {
        json_object_object_add(data, "registered_app_devices",
                               json_object_new_int(devices));
    } else {
        json_object_object_add(data, "registered_app_devices", NULL);
        json_object_object_add(data, "registered_app_devices_reason",
                               json_object_new_string("app_db_unavailable"));
    }

    /* The enrollment job is reported here so a caller polls one endpoint rather
     * than correlating two. */
    {
        struct json_object *job = cloud_enroll_job_json();

        if (job)
            json_object_object_add(data, "enrollment", job);
    }

    json_object_object_add(root, "data", data);
    return root;
}

static int cloud_handle_status(struct ubus_context *ctx, struct ubus_object *obj,
                               struct ubus_request_data *req, const char *method,
                               struct blob_attr *msg)
{
    struct json_object *response = cloud_status_json();

    (void)obj; (void)method; (void)msg;
    cloud_send_json(ctx, req, response);
    if (response)
        json_object_put(response);
    return UBUS_STATUS_OK;
}

static int cloud_handle_identity(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg)
{
    struct json_object *response = cloud_identity_json();

    (void)obj; (void)method; (void)msg;
    cloud_send_json(ctx, req, response);
    if (response)
        json_object_put(response);
    return UBUS_STATUS_OK;
}

/*
 * Triggers self enrollment on demand.
 *
 * This is the one method that changes state, and it is here rather than in UCI
 * because the result is a secret the router obtains at runtime, not something an
 * operator types. It is idempotent on the relay side: re-enrolling issues a new
 * token and keeps the already-authorized App list.
 *
 * Callers reach it through webd, which enforces admin authentication. ubus
 * itself is root-only on this device.
 */
enum {
    CLOUD_ENROLL_ATTR_FORCE,
    __CLOUD_ENROLL_ATTR_MAX,
};

static const struct blobmsg_policy cloud_enroll_policy[__CLOUD_ENROLL_ATTR_MAX] = {
    [CLOUD_ENROLL_ATTR_FORCE] = { .name = "force", .type = BLOBMSG_TYPE_BOOL },
};

static int cloud_handle_enroll(struct ubus_context *ctx, struct ubus_object *obj,
                               struct ubus_request_data *req, const char *method,
                               struct blob_attr *msg)
{
    struct blob_attr *fields[__CLOUD_ENROLL_ATTR_MAX] = {0};
    struct json_object *root = json_object_new_object();
    struct json_object *job;
    int force = 0;
    int started;

    (void)obj; (void)method;
    if (!root)
        return UBUS_STATUS_UNKNOWN_ERROR;
    json_object_object_add(root, "contract_version",
                           json_object_new_string(CLOUD_CONTRACT_VERSION));
    json_object_object_add(root, "source",
                           json_object_new_string(CLOUD_SERVICE_NAME));

    if (msg)
        blobmsg_parse(cloud_enroll_policy, __CLOUD_ENROLL_ATTR_MAX, fields,
                      blob_data(msg), blob_len(msg));
    if (fields[CLOUD_ENROLL_ATTR_FORCE])
        force = blobmsg_get_bool(fields[CLOUD_ENROLL_ATTR_FORCE]);

    /*
     * An existing token is not replaced unless asked. Re-enrolling revokes the
     * old token immediately, so an accidental call would drop a working tunnel
     * until the new credential took effect.
     */
    if (!force && cloud_enroll_token_present()) {
        json_object_object_add(root, "ok", json_object_new_boolean(1));
        json_object_object_add(root, "code",
                               json_object_new_string("already_enrolled"));
        json_object_object_add(root, "message",
                               json_object_new_string(
                                   "a tunnel token is already stored; pass "
                                   "force to replace it"));
    } else {
        /*
         * Accepted, not completed: the work happens on its own thread so the
         * event loop keeps answering status, which is what the caller polls.
         */
        started = cloud_enroll_job_start(force);
        json_object_object_add(root, "ok",
                               json_object_new_boolean(started >= 0 ? 1 : 0));
        json_object_object_add(root, "code",
                               json_object_new_string(
                                   started == 1 ? "enrollment_in_progress" :
                                   started == 0 ? "enrollment_started" :
                                                  "enrollment_start_failed"));
        json_object_object_add(root, "message",
                               json_object_new_string(
                                   started >= 0 ?
                                       "poll status for the result" :
                                       "the enrollment worker could not start"));
    }

    job = cloud_enroll_job_json();
    if (job)
        json_object_object_add(root, "data", job);
    cloud_send_json(ctx, req, root);
    json_object_put(root);
    return UBUS_STATUS_OK;
}

static const struct ubus_method cloud_methods[] = {
    UBUS_METHOD_NOARG("status", cloud_handle_status),
    UBUS_METHOD_NOARG("identity", cloud_handle_identity),
    UBUS_METHOD("enroll", cloud_handle_enroll, cloud_enroll_policy),
};

static struct ubus_object_type cloud_object_type =
    UBUS_OBJECT_TYPE("dreamingos.cloud", cloud_methods);

static struct ubus_object cloud_object = {
    .name = "dreamingos.cloud",
    .type = &cloud_object_type,
    .methods = cloud_methods,
    .n_methods = ARRAY_SIZE(cloud_methods),
};

/* Alias under the dreamingwrt namespace so callers can use either prefix, the
 * same way apd exposes both. */
static struct ubus_object cloud_alias_object = {
    .name = "dreamingwrt.cloud",
    .type = &cloud_object_type,
    .methods = cloud_methods,
    .n_methods = ARRAY_SIZE(cloud_methods),
};

int cloud_ubus_start(void)
{
    int rc;

    g_cloud_ubus = ubus_connect(NULL);
    if (!g_cloud_ubus)
        return -1;
    ubus_add_uloop(g_cloud_ubus);

    rc = ubus_add_object(g_cloud_ubus, &cloud_object);
    if (rc != UBUS_STATUS_OK) {
        ubus_free(g_cloud_ubus);
        g_cloud_ubus = NULL;
        return -1;
    }
    rc = ubus_add_object(g_cloud_ubus, &cloud_alias_object);
    if (rc != UBUS_STATUS_OK) {
        ubus_remove_object(g_cloud_ubus, &cloud_object);
        ubus_free(g_cloud_ubus);
        g_cloud_ubus = NULL;
        return -1;
    }
    return 0;
}

void cloud_ubus_stop(void)
{
    if (!g_cloud_ubus)
        return;
    ubus_remove_object(g_cloud_ubus, &cloud_alias_object);
    ubus_remove_object(g_cloud_ubus, &cloud_object);
    ubus_free(g_cloud_ubus);
    g_cloud_ubus = NULL;
}

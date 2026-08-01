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
                            &encoded) != 0) {
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
    json_object_object_add(data, "fingerprint",
                           json_object_new_string(identity->fingerprint));
    json_object_object_add(root, "data", data);
    free(encoded);
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

static const struct ubus_method cloud_methods[] = {
    UBUS_METHOD_NOARG("status", cloud_handle_status),
    UBUS_METHOD_NOARG("identity", cloud_handle_identity),
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

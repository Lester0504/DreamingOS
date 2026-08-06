// SPDX-License-Identifier: GPL-2.0-or-later
#include "apd_internal.h"

static int apd_send_json(struct ubus_context *ctx, struct ubus_request_data *req,
                         struct json_object *response)
{
    const char *text = response ? json_object_to_json_string(response) : "{}";

    blob_buf_init(&g_apd_blob, 0);
    if (!blobmsg_add_json_from_string(&g_apd_blob, text)) {
        blob_buf_free(&g_apd_blob);
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    ubus_send_reply(ctx, req, g_apd_blob.head);
    blob_buf_free(&g_apd_blob);
    return UBUS_STATUS_OK;
}

static int apd_handle_status(struct ubus_context *ctx, struct ubus_object *obj,
                             struct ubus_request_data *req, const char *method,
                             struct blob_attr *msg)
{
    struct json_object *response = apd_status_json();
    (void)obj; (void)method; (void)msg;
    apd_send_json(ctx, req, response);
    json_object_put(response);
    return UBUS_STATUS_OK;
}

static int apd_handle_capabilities(struct ubus_context *ctx, struct ubus_object *obj,
                                   struct ubus_request_data *req, const char *method,
                                   struct blob_attr *msg)
{
    struct json_object *response = apd_capabilities_json();
    (void)obj; (void)method; (void)msg;
    apd_send_json(ctx, req, response);
    json_object_put(response);
    return UBUS_STATUS_OK;
}

static int apd_handle_snapshot(struct ubus_context *ctx, struct ubus_object *obj,
                               struct ubus_request_data *req, const char *method,
                               struct blob_attr *msg)
{
    struct json_object *response = apd_snapshot_json();
    (void)obj; (void)method; (void)msg;
    apd_send_json(ctx, req, response);
    json_object_put(response);
    return UBUS_STATUS_OK;
}

static int apd_handle_identity(struct ubus_context *ctx, struct ubus_object *obj,
                               struct ubus_request_data *req, const char *method,
                               struct blob_attr *msg)
{
    struct json_object *response = apd_identity_json();
    (void)obj; (void)method; (void)msg;
    apd_send_json(ctx, req, response);
    json_object_put(response);
    return UBUS_STATUS_OK;
}

static int apd_handle_pairing_status(struct ubus_context *ctx,
                                     struct ubus_object *obj,
                                     struct ubus_request_data *req,
                                     const char *method, struct blob_attr *msg)
{
    struct json_object *response = apd_pairing_status_json();
    (void)obj; (void)method; (void)msg;
    apd_send_json(ctx, req, response);
    json_object_put(response);
    return UBUS_STATUS_OK;
}

enum {
    APD_UNPAIR_CONFIRM,
    __APD_UNPAIR_MAX
};

static const struct blobmsg_policy apd_unpair_policy[__APD_UNPAIR_MAX] = {
    [APD_UNPAIR_CONFIRM] = { .name = "confirm", .type = BLOBMSG_TYPE_BOOL },
};

/*
 * Destructive: drops the certificate and adoption state, after which the
 * controller can no longer manage this AP. The explicit confirm flag exists so
 * a mistyped or replayed call cannot unadopt a live AP; a missing flag is
 * refused by apd_unpair_json() rather than treated as consent.
 */
static int apd_handle_unpair(struct ubus_context *ctx, struct ubus_object *obj,
                             struct ubus_request_data *req, const char *method,
                             struct blob_attr *msg)
{
    struct blob_attr *tb[__APD_UNPAIR_MAX];
    struct json_object *response;
    int confirmed = 0;

    (void)obj; (void)method;
    blobmsg_parse(apd_unpair_policy, __APD_UNPAIR_MAX, tb, blob_data(msg),
                  blob_len(msg));
    if (tb[APD_UNPAIR_CONFIRM])
        confirmed = blobmsg_get_bool(tb[APD_UNPAIR_CONFIRM]);
    response = apd_unpair_json(confirmed);
    apd_send_json(ctx, req, response);
    json_object_put(response);
    return UBUS_STATUS_OK;
}

static const struct ubus_method apd_methods[] = {
    UBUS_METHOD_NOARG("status", apd_handle_status),
    UBUS_METHOD_NOARG("capabilities", apd_handle_capabilities),
    UBUS_METHOD_NOARG("identity", apd_handle_identity),
    UBUS_METHOD_NOARG("pairing_status", apd_handle_pairing_status),
    {
        .name = "snapshot",
        .handler = apd_handle_snapshot,
    },
    UBUS_METHOD("unpair", apd_handle_unpair, apd_unpair_policy),
};

static struct ubus_object_type apd_object_type =
    UBUS_OBJECT_TYPE("dreamingwrt.apd", apd_methods);

static struct ubus_object apd_object = {
    .name = "dreamingwrt.apd",
    .type = &apd_object_type,
    .methods = apd_methods,
    .n_methods = ARRAY_SIZE(apd_methods),
};

static struct ubus_object apd_alias_object = {
    .name = "dreamingos.apd",
    .type = &apd_object_type,
    .methods = apd_methods,
    .n_methods = ARRAY_SIZE(apd_methods),
};

int apd_ubus_start(void)
{
    int rc;

    g_apd_ubus = ubus_connect(APD_UBUS_SOCKET_PATH);
    if (!g_apd_ubus)
        return -1;
    ubus_add_uloop(g_apd_ubus);
    rc = ubus_add_object(g_apd_ubus, &apd_object);
    if (rc != UBUS_STATUS_OK) {
        ubus_free(g_apd_ubus);
        g_apd_ubus = NULL;
        return -1;
    }
    rc = ubus_add_object(g_apd_ubus, &apd_alias_object);
    if (rc != UBUS_STATUS_OK) {
        ubus_remove_object(g_apd_ubus, &apd_object);
        ubus_free(g_apd_ubus);
        g_apd_ubus = NULL;
        return -1;
    }
    return 0;
}

void apd_ubus_stop(void)
{
    if (!g_apd_ubus)
        return;
    ubus_remove_object(g_apd_ubus, &apd_alias_object);
    ubus_remove_object(g_apd_ubus, &apd_object);
    ubus_free(g_apd_ubus);
    g_apd_ubus = NULL;
}

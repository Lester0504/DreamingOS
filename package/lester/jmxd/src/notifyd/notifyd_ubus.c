// SPDX-License-Identifier: GPL-2.0-or-later
#include "notifyd_internal.h"

static int notifyd_send_json(struct ubus_context *ctx, struct ubus_request_data *req,
                             struct json_object *obj)
{
    const char *s = obj ? json_object_to_json_string(obj) : "{}";

    blob_buf_init(&g_notify_blob, 0);
    if (!blobmsg_add_json_from_string(&g_notify_blob, s)) {
        blob_buf_free(&g_notify_blob);
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    ubus_send_reply(ctx, req, g_notify_blob.head);
    blob_buf_free(&g_notify_blob);
    return UBUS_STATUS_OK;
}

static int notifyd_handle_status(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)method; (void)msg;

    resp = notifyd_status_json();
    notifyd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int notifyd_handle_event_catalog(struct ubus_context *ctx, struct ubus_object *obj,
                                        struct ubus_request_data *req, const char *method,
                                        struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)method; (void)msg;

    resp = notifyd_event_catalog_json();
    notifyd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int notifyd_handle_settings_get(struct ubus_context *ctx, struct ubus_object *obj,
                                       struct ubus_request_data *req, const char *method,
                                       struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)method; (void)msg;

    resp = notifyd_settings_json();
    notifyd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int notifyd_handle_settings_set(struct ubus_context *ctx, struct ubus_object *obj,
                                       struct ubus_request_data *req, const char *method,
                                       struct blob_attr *msg)
{
    struct json_object *body = notifyd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = notifyd_settings_update(notifyd_payload_or_self(body));
    notifyd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int notifyd_handle_channels_get(struct ubus_context *ctx, struct ubus_object *obj,
                                       struct ubus_request_data *req, const char *method,
                                       struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)method; (void)msg;

    resp = notifyd_channels_json();
    notifyd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int notifyd_handle_channels_set(struct ubus_context *ctx, struct ubus_object *obj,
                                       struct ubus_request_data *req, const char *method,
                                       struct blob_attr *msg)
{
    struct json_object *body = notifyd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = notifyd_channels_update(notifyd_payload_or_self(body));
    notifyd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int notifyd_handle_channels_delete(struct ubus_context *ctx, struct ubus_object *obj,
                                          struct ubus_request_data *req, const char *method,
                                          struct blob_attr *msg)
{
    struct json_object *body = notifyd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = notifyd_channels_delete(notifyd_payload_or_self(body));
    notifyd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int notifyd_handle_routes_get(struct ubus_context *ctx, struct ubus_object *obj,
                                     struct ubus_request_data *req, const char *method,
                                     struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)method; (void)msg;

    resp = notifyd_routes_json();
    notifyd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int notifyd_handle_routes_set(struct ubus_context *ctx, struct ubus_object *obj,
                                     struct ubus_request_data *req, const char *method,
                                     struct blob_attr *msg)
{
    struct json_object *body = notifyd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = notifyd_routes_update(notifyd_payload_or_self(body));
    notifyd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int notifyd_handle_routes_delete(struct ubus_context *ctx, struct ubus_object *obj,
                                        struct ubus_request_data *req, const char *method,
                                        struct blob_attr *msg)
{
    struct json_object *body = notifyd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = notifyd_routes_delete(notifyd_payload_or_self(body));
    notifyd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int notifyd_handle_enqueue(struct ubus_context *ctx, struct ubus_object *obj,
                                  struct ubus_request_data *req, const char *method,
                                  struct blob_attr *msg)
{
    struct json_object *body = notifyd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = notifyd_enqueue_event(notifyd_payload_or_self(body));
    notifyd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int notifyd_handle_test_send(struct ubus_context *ctx, struct ubus_object *obj,
                                    struct ubus_request_data *req, const char *method,
                                    struct blob_attr *msg)
{
    struct json_object *body = notifyd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = notifyd_test_send(notifyd_payload_or_self(body));
    notifyd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int notifyd_handle_outbox_list(struct ubus_context *ctx, struct ubus_object *obj,
                                      struct ubus_request_data *req, const char *method,
                                      struct blob_attr *msg)
{
    struct json_object *body = notifyd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = notifyd_outbox_list(notifyd_payload_or_self(body));
    notifyd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int notifyd_handle_outbox_retry(struct ubus_context *ctx, struct ubus_object *obj,
                                       struct ubus_request_data *req, const char *method,
                                       struct blob_attr *msg)
{
    struct json_object *body = notifyd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = notifyd_outbox_retry(notifyd_payload_or_self(body));
    notifyd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int notifyd_handle_outbox_get(struct ubus_context *ctx, struct ubus_object *obj,
                                     struct ubus_request_data *req, const char *method,
                                     struct blob_attr *msg)
{
    struct json_object *body = notifyd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = notifyd_outbox_get(notifyd_payload_or_self(body));
    notifyd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int notifyd_handle_deliver_due(struct ubus_context *ctx, struct ubus_object *obj,
                                      struct ubus_request_data *req, const char *method,
                                      struct blob_attr *msg)
{
    struct json_object *body = notifyd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = notifyd_deliver_due(notifyd_payload_or_self(body));
    notifyd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static const struct blobmsg_policy notifyd_any_policy[] = {
    { .name = "payload", .type = BLOBMSG_TYPE_UNSPEC },
};

static const struct ubus_method notifyd_methods[] = {
    UBUS_METHOD("status", notifyd_handle_status, notifyd_any_policy),
    UBUS_METHOD("event_catalog", notifyd_handle_event_catalog, notifyd_any_policy),
    UBUS_METHOD("settings_get", notifyd_handle_settings_get, notifyd_any_policy),
    UBUS_METHOD("settings_set", notifyd_handle_settings_set, notifyd_any_policy),
    UBUS_METHOD("channels_get", notifyd_handle_channels_get, notifyd_any_policy),
    UBUS_METHOD("channels_set", notifyd_handle_channels_set, notifyd_any_policy),
    UBUS_METHOD("channels_delete", notifyd_handle_channels_delete, notifyd_any_policy),
    UBUS_METHOD("routes_get", notifyd_handle_routes_get, notifyd_any_policy),
    UBUS_METHOD("routes_set", notifyd_handle_routes_set, notifyd_any_policy),
    UBUS_METHOD("routes_delete", notifyd_handle_routes_delete, notifyd_any_policy),
    UBUS_METHOD("enqueue", notifyd_handle_enqueue, notifyd_any_policy),
    UBUS_METHOD("test_send", notifyd_handle_test_send, notifyd_any_policy),
    UBUS_METHOD("outbox_list", notifyd_handle_outbox_list, notifyd_any_policy),
    UBUS_METHOD("outbox_get", notifyd_handle_outbox_get, notifyd_any_policy),
    UBUS_METHOD("outbox_retry", notifyd_handle_outbox_retry, notifyd_any_policy),
    UBUS_METHOD("deliver_due", notifyd_handle_deliver_due, notifyd_any_policy),
};

static struct ubus_object_type notifyd_object_type =
    UBUS_OBJECT_TYPE("dreamingwrt_notifyd", notifyd_methods);

static struct ubus_object notifyd_object = {
    .name = "dreamingwrt.notifyd",
    .type = &notifyd_object_type,
    .methods = notifyd_methods,
    .n_methods = ARRAY_SIZE(notifyd_methods),
};

static struct ubus_object notifyd_alias_object = {
    .name = "dreamingos.notifyd",
    .type = &notifyd_object_type,
    .methods = notifyd_methods,
    .n_methods = ARRAY_SIZE(notifyd_methods),
};

int notifyd_ubus_start(void)
{
    int rc;

    g_notify_ubus = ubus_connect(NULL);
    if (!g_notify_ubus) {
        fprintf(stderr, "[dreamingwrt-notifyd] ubus connect failed\n");
        return -1;
    }
    ubus_add_uloop(g_notify_ubus);
    rc = ubus_add_object(g_notify_ubus, &notifyd_object);
    if (rc != UBUS_STATUS_OK) {
        fprintf(stderr, "[dreamingwrt-notifyd] ubus object register failed rc=%d\n", rc);
        ubus_free(g_notify_ubus);
        g_notify_ubus = NULL;
        return -1;
    }
    rc = ubus_add_object(g_notify_ubus, &notifyd_alias_object);
    if (rc != UBUS_STATUS_OK) {
        fprintf(stderr, "[dreamingwrt-notifyd] ubus alias register failed rc=%d\n", rc);
        ubus_remove_object(g_notify_ubus, &notifyd_object);
        ubus_free(g_notify_ubus);
        g_notify_ubus = NULL;
        return -1;
    }
    return 0;
}

void notifyd_ubus_stop(void)
{
    if (g_notify_ubus) {
        ubus_remove_object(g_notify_ubus, &notifyd_alias_object);
        ubus_remove_object(g_notify_ubus, &notifyd_object);
        ubus_free(g_notify_ubus);
        g_notify_ubus = NULL;
    }
}

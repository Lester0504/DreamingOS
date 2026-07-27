// SPDX-License-Identifier: GPL-2.0-or-later
#include "otad_internal.h"

static int otad_send_json(struct ubus_context *ctx, struct ubus_request_data *req,
                          struct json_object *obj)
{
    const char *s = obj ? json_object_to_json_string(obj) : "{}";

    blob_buf_init(&g_otad_blob, 0);
    if (!blobmsg_add_json_from_string(&g_otad_blob, s)) {
        blob_buf_free(&g_otad_blob);
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    ubus_send_reply(ctx, req, g_otad_blob.head);
    blob_buf_free(&g_otad_blob);
    return UBUS_STATUS_OK;
}

static int otad_handle_status(struct ubus_context *ctx, struct ubus_object *obj,
                              struct ubus_request_data *req, const char *method,
                              struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)method; (void)msg;

    resp = otad_status_json();
    otad_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int otad_handle_check(struct ubus_context *ctx, struct ubus_object *obj,
                             struct ubus_request_data *req, const char *method,
                             struct blob_attr *msg)
{
    struct json_object *body = otad_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = otad_check_manifest(otad_payload_or_self(body));
    otad_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int otad_handle_inventory_scan(struct ubus_context *ctx, struct ubus_object *obj,
                                      struct ubus_request_data *req, const char *method,
                                      struct blob_attr *msg)
{
    struct json_object *body = otad_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = otad_inventory_scan(otad_payload_or_self(body));
    otad_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int otad_handle_unknowns(struct ubus_context *ctx, struct ubus_object *obj,
                                struct ubus_request_data *req, const char *method,
                                struct blob_attr *msg)
{
    struct json_object *body = otad_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = otad_unknowns_json(otad_payload_or_self(body));
    otad_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int otad_handle_safe_disabled(struct ubus_context *ctx, struct ubus_object *obj,
                                     struct ubus_request_data *req, const char *method,
                                     struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)msg;

    resp = otad_safe_not_implemented(method);
    otad_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int otad_handle_verify(struct ubus_context *ctx, struct ubus_object *obj,
                              struct ubus_request_data *req, const char *method,
                              struct blob_attr *msg)
{
    struct json_object *body = otad_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = otad_update_verify(otad_payload_or_self(body));
    otad_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int otad_handle_apply(struct ubus_context *ctx, struct ubus_object *obj,
                             struct ubus_request_data *req, const char *method,
                             struct blob_attr *msg)
{
    struct json_object *body = otad_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = otad_update_apply(otad_payload_or_self(body));
    otad_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int otad_handle_operation_status(struct ubus_context *ctx,
                                        struct ubus_object *obj,
                                        struct ubus_request_data *req,
                                        const char *method,
                                        struct blob_attr *msg)
{
    struct json_object *body = otad_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = otad_operation_status(otad_payload_or_self(body));
    otad_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int otad_handle_rollback(struct ubus_context *ctx, struct ubus_object *obj,
                                struct ubus_request_data *req, const char *method,
                                struct blob_attr *msg)
{
    struct json_object *body = otad_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = otad_firmware_rollback(otad_payload_or_self(body));
    otad_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int otad_handle_confirm_boot(struct ubus_context *ctx, struct ubus_object *obj,
                                    struct ubus_request_data *req, const char *method,
                                    struct blob_attr *msg)
{
    struct json_object *body = otad_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = otad_confirm_boot(otad_payload_or_self(body));
    otad_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static const struct blobmsg_policy otad_any_policy[] = {
    { .name = "payload", .type = BLOBMSG_TYPE_UNSPEC },
};

static const struct ubus_method otad_methods[] = {
    UBUS_METHOD("status", otad_handle_status, otad_any_policy),
    UBUS_METHOD("check", otad_handle_check, otad_any_policy),
    UBUS_METHOD("verify", otad_handle_verify, otad_any_policy),
    UBUS_METHOD("download", otad_handle_safe_disabled, otad_any_policy),
    UBUS_METHOD("apply", otad_handle_apply, otad_any_policy),
    UBUS_METHOD("operation_status", otad_handle_operation_status, otad_any_policy),
    UBUS_METHOD("rollback", otad_handle_rollback, otad_any_policy),
    UBUS_METHOD("confirm_boot", otad_handle_confirm_boot, otad_any_policy),
    UBUS_METHOD("inventory_scan", otad_handle_inventory_scan, otad_any_policy),
    UBUS_METHOD("unknowns", otad_handle_unknowns, otad_any_policy),
};

static struct ubus_object_type otad_object_type =
    UBUS_OBJECT_TYPE("dreamingwrt_otad", otad_methods);

static struct ubus_object otad_object = {
    .name = "dreamingwrt.otad",
    .type = &otad_object_type,
    .methods = otad_methods,
    .n_methods = ARRAY_SIZE(otad_methods),
};

static struct ubus_object otad_alias_object = {
    .name = "dreamingos.otad",
    .type = &otad_object_type,
    .methods = otad_methods,
    .n_methods = ARRAY_SIZE(otad_methods),
};

int otad_ubus_start(void)
{
    int rc;

    g_otad_ubus = ubus_connect(NULL);
    if (!g_otad_ubus) {
        fprintf(stderr, "[dreamingwrt-otad] ubus connect failed\n");
        return -1;
    }
    ubus_add_uloop(g_otad_ubus);
    rc = ubus_add_object(g_otad_ubus, &otad_object);
    if (rc != UBUS_STATUS_OK) {
        fprintf(stderr, "[dreamingwrt-otad] ubus object register failed rc=%d\n", rc);
        ubus_free(g_otad_ubus);
        g_otad_ubus = NULL;
        return -1;
    }
    rc = ubus_add_object(g_otad_ubus, &otad_alias_object);
    if (rc != UBUS_STATUS_OK) {
        fprintf(stderr, "[dreamingwrt-otad] ubus alias register failed rc=%d\n", rc);
        ubus_remove_object(g_otad_ubus, &otad_object);
        ubus_free(g_otad_ubus);
        g_otad_ubus = NULL;
        return -1;
    }
    return 0;
}

void otad_ubus_stop(void)
{
    if (g_otad_ubus) {
        ubus_remove_object(g_otad_ubus, &otad_alias_object);
        ubus_remove_object(g_otad_ubus, &otad_object);
        ubus_free(g_otad_ubus);
        g_otad_ubus = NULL;
    }
}

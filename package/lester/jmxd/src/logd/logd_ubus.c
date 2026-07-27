// SPDX-License-Identifier: GPL-2.0-or-later
#include "logd_internal.h"

static int logd_send_json(struct ubus_context *ctx, struct ubus_request_data *req,
                          struct json_object *obj)
{
    const char *s = obj ? json_object_to_json_string(obj) : "{}";

    blob_buf_init(&g_logd_blob, 0);
    if (!blobmsg_add_json_from_string(&g_logd_blob, s)) {
        blob_buf_free(&g_logd_blob);
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    ubus_send_reply(ctx, req, g_logd_blob.head);
    blob_buf_free(&g_logd_blob);
    return UBUS_STATUS_OK;
}

static int logd_handle_status(struct ubus_context *ctx, struct ubus_object *obj,
                              struct ubus_request_data *req, const char *method,
                              struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)method; (void)msg;

    resp = logd_status_json();
    logd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int logd_handle_settings_get(struct ubus_context *ctx, struct ubus_object *obj,
                                    struct ubus_request_data *req, const char *method,
                                    struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)method; (void)msg;

    resp = logd_settings_json();
    logd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int logd_handle_settings_set(struct ubus_context *ctx, struct ubus_object *obj,
                                    struct ubus_request_data *req, const char *method,
                                    struct blob_attr *msg)
{
    struct json_object *body = logd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = logd_settings_update(logd_payload_or_self(body));
    logd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int logd_handle_syslog_test(struct ubus_context *ctx, struct ubus_object *obj,
                                   struct ubus_request_data *req, const char *method,
                                   struct blob_attr *msg)
{
    struct json_object *body = logd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = logd_syslog_test(logd_payload_or_self(body));
    logd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int logd_handle_syslog_queue_status(struct ubus_context *ctx, struct ubus_object *obj,
                                           struct ubus_request_data *req, const char *method,
                                           struct blob_attr *msg)
{
    struct json_object *body = logd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = logd_syslog_queue_status(logd_payload_or_self(body));
    logd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int logd_handle_syslog_queue_flush(struct ubus_context *ctx, struct ubus_object *obj,
                                          struct ubus_request_data *req, const char *method,
                                          struct blob_attr *msg)
{
    struct json_object *body = logd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = logd_syslog_queue_flush(logd_payload_or_self(body));
    logd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int logd_handle_syslog_queue_clear(struct ubus_context *ctx, struct ubus_object *obj,
                                          struct ubus_request_data *req, const char *method,
                                          struct blob_attr *msg)
{
    struct json_object *body = logd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = logd_syslog_queue_clear(logd_payload_or_self(body));
    logd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int logd_handle_syslog_cert_list(struct ubus_context *ctx, struct ubus_object *obj,
                                        struct ubus_request_data *req, const char *method,
                                        struct blob_attr *msg)
{
    struct json_object *body = logd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = logd_syslog_cert_list(logd_payload_or_self(body));
    logd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int logd_handle_syslog_cert_upload(struct ubus_context *ctx, struct ubus_object *obj,
                                          struct ubus_request_data *req, const char *method,
                                          struct blob_attr *msg)
{
    struct json_object *body = logd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = logd_syslog_cert_upload(logd_payload_or_self(body));
    logd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int logd_handle_syslog_cert_delete(struct ubus_context *ctx, struct ubus_object *obj,
                                          struct ubus_request_data *req, const char *method,
                                          struct blob_attr *msg)
{
    struct json_object *body = logd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = logd_syslog_cert_delete(logd_payload_or_self(body));
    logd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int logd_handle_syslog_presets(struct ubus_context *ctx, struct ubus_object *obj,
                                      struct ubus_request_data *req, const char *method,
                                      struct blob_attr *msg)
{
    struct json_object *body = logd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = logd_syslog_presets_json(logd_payload_or_self(body));
    logd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int logd_handle_event_add(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg)
{
    struct json_object *body = logd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = logd_add_event(logd_payload_or_self(body));
    logd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int logd_handle_event_list(struct ubus_context *ctx, struct ubus_object *obj,
                                  struct ubus_request_data *req, const char *method,
                                  struct blob_attr *msg)
{
    struct json_object *body = logd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = logd_list_events(logd_payload_or_self(body));
    logd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int logd_handle_event_clear(struct ubus_context *ctx, struct ubus_object *obj,
                                   struct ubus_request_data *req, const char *method,
                                   struct blob_attr *msg)
{
    struct json_object *body = logd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = logd_clear_events(logd_payload_or_self(body));
    logd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int logd_handle_unifi_search(struct ubus_context *ctx, struct ubus_object *obj,
                                    struct ubus_request_data *req, const char *method,
                                    struct blob_attr *msg)
{
    struct json_object *body = logd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = logd_unifi_search(logd_payload_or_self(body));
    logd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int logd_handle_unifi_get_by_ids(struct ubus_context *ctx, struct ubus_object *obj,
                                       struct ubus_request_data *req, const char *method,
                                       struct blob_attr *msg)
{
    struct json_object *body = logd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = logd_unifi_get_by_ids(logd_payload_or_self(body));
    logd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int logd_handle_unifi_count(struct ubus_context *ctx, struct ubus_object *obj,
                                   struct ubus_request_data *req, const char *method,
                                   struct blob_attr *msg)
{
    struct json_object *body = logd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = logd_unifi_count(logd_payload_or_self(body));
    logd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int logd_handle_unifi_filter_data(struct ubus_context *ctx, struct ubus_object *obj,
                                         struct ubus_request_data *req, const char *method,
                                         struct blob_attr *msg)
{
    struct json_object *body = logd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = logd_unifi_filter_data(logd_payload_or_self(body));
    logd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int logd_handle_unifi_export(struct ubus_context *ctx, struct ubus_object *obj,
                                    struct ubus_request_data *req, const char *method,
                                    struct blob_attr *msg)
{
    struct json_object *body = logd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = logd_unifi_export(logd_payload_or_self(body));
    logd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int logd_handle_unifi_mark_read(struct ubus_context *ctx, struct ubus_object *obj,
                                       struct ubus_request_data *req, const char *method,
                                       struct blob_attr *msg)
{
    struct json_object *body = logd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = logd_unifi_mark_read(logd_payload_or_self(body));
    logd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int logd_handle_unifi_ack(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg)
{
    struct json_object *body = logd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = logd_unifi_ack(logd_payload_or_self(body));
    logd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int logd_handle_collectors_get(struct ubus_context *ctx, struct ubus_object *obj,
                                      struct ubus_request_data *req, const char *method,
                                      struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)method; (void)msg;

    resp = logd_collectors_json();
    logd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int logd_handle_collectors_set(struct ubus_context *ctx, struct ubus_object *obj,
                                      struct ubus_request_data *req, const char *method,
                                      struct blob_attr *msg)
{
    struct json_object *body = logd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = logd_collectors_update(logd_payload_or_self(body));
    logd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int logd_handle_collect_now(struct ubus_context *ctx, struct ubus_object *obj,
                                   struct ubus_request_data *req, const char *method,
                                   struct blob_attr *msg)
{
    struct json_object *body = logd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = logd_collect_now(logd_payload_or_self(body));
    logd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static const struct blobmsg_policy logd_any_policy[] = {
    { .name = "payload", .type = BLOBMSG_TYPE_UNSPEC },
};

static const struct ubus_method logd_methods[] = {
    UBUS_METHOD("status", logd_handle_status, logd_any_policy),
    UBUS_METHOD("settings_get", logd_handle_settings_get, logd_any_policy),
    UBUS_METHOD("settings_set", logd_handle_settings_set, logd_any_policy),
    UBUS_METHOD("syslog_test", logd_handle_syslog_test, logd_any_policy),
    UBUS_METHOD("syslog_queue_status", logd_handle_syslog_queue_status, logd_any_policy),
    UBUS_METHOD("syslog_queue_flush", logd_handle_syslog_queue_flush, logd_any_policy),
    UBUS_METHOD("syslog_queue_clear", logd_handle_syslog_queue_clear, logd_any_policy),
    UBUS_METHOD("syslog_cert_list", logd_handle_syslog_cert_list, logd_any_policy),
    UBUS_METHOD("syslog_cert_upload", logd_handle_syslog_cert_upload, logd_any_policy),
    UBUS_METHOD("syslog_cert_delete", logd_handle_syslog_cert_delete, logd_any_policy),
    UBUS_METHOD("syslog_presets", logd_handle_syslog_presets, logd_any_policy),
    UBUS_METHOD("event_add", logd_handle_event_add, logd_any_policy),
    UBUS_METHOD("event_list", logd_handle_event_list, logd_any_policy),
    UBUS_METHOD("event_clear", logd_handle_event_clear, logd_any_policy),
    UBUS_METHOD("unifi_search", logd_handle_unifi_search, logd_any_policy),
    UBUS_METHOD("unifi_get_by_ids", logd_handle_unifi_get_by_ids, logd_any_policy),
    UBUS_METHOD("unifi_count", logd_handle_unifi_count, logd_any_policy),
    UBUS_METHOD("unifi_filter_data", logd_handle_unifi_filter_data, logd_any_policy),
    UBUS_METHOD("unifi_export", logd_handle_unifi_export, logd_any_policy),
    UBUS_METHOD("unifi_mark_read", logd_handle_unifi_mark_read, logd_any_policy),
    UBUS_METHOD("unifi_ack", logd_handle_unifi_ack, logd_any_policy),
    UBUS_METHOD("collectors_get", logd_handle_collectors_get, logd_any_policy),
    UBUS_METHOD("collectors_set", logd_handle_collectors_set, logd_any_policy),
    UBUS_METHOD("collect_now", logd_handle_collect_now, logd_any_policy),
};

static struct ubus_object_type logd_object_type =
    UBUS_OBJECT_TYPE("dreamingwrt_logd", logd_methods);

static struct ubus_object logd_object = {
    .name = "dreamingwrt.logd",
    .type = &logd_object_type,
    .methods = logd_methods,
    .n_methods = ARRAY_SIZE(logd_methods),
};

static struct ubus_object logd_alias_object = {
    .name = "dreamingos.logd",
    .type = &logd_object_type,
    .methods = logd_methods,
    .n_methods = ARRAY_SIZE(logd_methods),
};

int logd_ubus_start(void)
{
    int rc;

    g_logd_ubus = ubus_connect(NULL);
    if (!g_logd_ubus) {
        fprintf(stderr, "[dreamingwrt-logd] ubus connect failed\n");
        return -1;
    }
    ubus_add_uloop(g_logd_ubus);
    rc = ubus_add_object(g_logd_ubus, &logd_object);
    if (rc != UBUS_STATUS_OK) {
        fprintf(stderr, "[dreamingwrt-logd] ubus object register failed rc=%d\n", rc);
        ubus_free(g_logd_ubus);
        g_logd_ubus = NULL;
        return -1;
    }
    rc = ubus_add_object(g_logd_ubus, &logd_alias_object);
    if (rc != UBUS_STATUS_OK) {
        fprintf(stderr, "[dreamingwrt-logd] ubus alias register failed rc=%d\n", rc);
        ubus_remove_object(g_logd_ubus, &logd_object);
        ubus_free(g_logd_ubus);
        g_logd_ubus = NULL;
        return -1;
    }
    return 0;
}

void logd_ubus_stop(void)
{
    if (g_logd_ubus) {
        ubus_remove_object(g_logd_ubus, &logd_alias_object);
        ubus_remove_object(g_logd_ubus, &logd_object);
        ubus_free(g_logd_ubus);
        g_logd_ubus = NULL;
    }
}

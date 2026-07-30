// SPDX-License-Identifier: GPL-2.0-or-later
#include "flowd_internal.h"

static int flowd_send_json(struct ubus_context *ctx, struct ubus_request_data *req,
                           struct json_object *obj)
{
    const char *s = obj ? json_object_to_json_string(obj) : "{}";

    blob_buf_init(&g_flowd_blob, 0);
    if (!blobmsg_add_json_from_string(&g_flowd_blob, s)) {
        blob_buf_free(&g_flowd_blob);
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    ubus_send_reply(ctx, req, g_flowd_blob.head);
    blob_buf_free(&g_flowd_blob);
    return UBUS_STATUS_OK;
}

struct flowd_core_invoke_result {
    struct json_object *json;
    int rc;
};

static void flowd_core_invoke_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct flowd_core_invoke_result *r = req ? req->priv : NULL;
    char *s;

    (void)type;
    if (!r || !msg)
        return;
    s = blobmsg_format_json(msg, true);
    if (!s)
        return;
    if (r->json)
        json_object_put(r->json);
    r->json = json_tokener_parse(s);
    free(s);
}

static struct json_object *flowd_core_call(const char *method, struct json_object *payload,
                                           int timeout_ms)
{
    struct ubus_context *uctx = NULL;
    struct blob_buf b = {};
    struct flowd_core_invoke_result result = { .json = NULL, .rc = -1 };
    uint32_t id = 0;
    int rc;

    if (!method || !method[0])
        return flowd_error("invalid_core_method", "missing core ubus method");
    uctx = ubus_connect(NULL);
    if (!uctx)
        return flowd_error("core_ubus_unavailable", "unable to connect ubus");
    if (ubus_lookup_id(uctx, "dreamingwrt", &id) != UBUS_STATUS_OK) {
        ubus_free(uctx);
        return flowd_error("core_unavailable", "dreamingwrt ubus object is unavailable");
    }

    blob_buf_init(&b, 0);
    if (payload) {
        const char *s = json_object_to_json_string_ext(payload, JSON_C_TO_STRING_PLAIN);

        if (s && s[0] && !blobmsg_add_json_from_string(&b, s)) {
            blob_buf_free(&b);
            ubus_free(uctx);
            return flowd_error("core_payload_invalid", "unable to encode ubus payload");
        }
    }
    rc = ubus_invoke(uctx, id, method, b.head, flowd_core_invoke_cb, &result,
                     timeout_ms > 0 ? timeout_ms : 5000);
    blob_buf_free(&b);
    ubus_free(uctx);
    if (rc != UBUS_STATUS_OK) {
        struct json_object *err = flowd_error("core_invoke_failed", ubus_strerror(rc));

        json_object_object_add(err, "ubus_rc", json_object_new_int(rc));
        return err;
    }
    if (!result.json)
        return flowd_error("core_empty_response", "core returned no JSON body");
    return result.json;
}

static struct json_object *flowd_core_data_or_self(struct json_object *resp)
{
    struct json_object *data = NULL;

    if (resp && json_object_object_get_ex(resp, "data", &data) && data &&
        json_object_is_type(data, json_type_object))
        return data;
    return resp;
}

static int flowd_handle_status(struct ubus_context *ctx, struct ubus_object *obj,
                               struct ubus_request_data *req, const char *method,
                               struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)method; (void)msg;

    resp = flowd_status_json();
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int flowd_handle_settings_get(struct ubus_context *ctx, struct ubus_object *obj,
                                     struct ubus_request_data *req, const char *method,
                                     struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)method; (void)msg;

    resp = flowd_settings_json();
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int flowd_handle_settings_set(struct ubus_context *ctx, struct ubus_object *obj,
                                     struct ubus_request_data *req, const char *method,
                                     struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_settings_update(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_geoip_sources_get(struct ubus_context *ctx, struct ubus_object *obj,
                                          struct ubus_request_data *req, const char *method,
                                          struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)method; (void)msg;

    resp = flowd_geoip_sources_json();
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int flowd_handle_geoip_source_set(struct ubus_context *ctx, struct ubus_object *obj,
                                         struct ubus_request_data *req, const char *method,
                                         struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_geoip_source_update(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_geoip_source_delete(struct ubus_context *ctx, struct ubus_object *obj,
                                            struct ubus_request_data *req, const char *method,
                                            struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_geoip_source_delete(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_geoip_import_status(struct ubus_context *ctx, struct ubus_object *obj,
                                            struct ubus_request_data *req, const char *method,
                                            struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_geoip_import_status(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_geoip_import(struct ubus_context *ctx, struct ubus_object *obj,
                                     struct ubus_request_data *req, const char *method,
                                     struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_geoip_import(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_country_policies_get(struct ubus_context *ctx, struct ubus_object *obj,
                                             struct ubus_request_data *req, const char *method,
                                             struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)method; (void)msg;

    resp = flowd_country_policies_json();
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int flowd_handle_country_policy_set(struct ubus_context *ctx, struct ubus_object *obj,
                                           struct ubus_request_data *req, const char *method,
                                           struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_country_policy_update(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_country_policy_delete(struct ubus_context *ctx, struct ubus_object *obj,
                                              struct ubus_request_data *req, const char *method,
                                              struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_country_policy_delete(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_country_sets_generate(struct ubus_context *ctx, struct ubus_object *obj,
                                              struct ubus_request_data *req, const char *method,
                                              struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_country_sets_generate(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_objects_get(struct ubus_context *ctx, struct ubus_object *obj,
                                    struct ubus_request_data *req, const char *method,
                                    struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_objects_json(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_object_set(struct ubus_context *ctx, struct ubus_object *obj,
                                   struct ubus_request_data *req, const char *method,
                                   struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_object_update(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_object_delete(struct ubus_context *ctx, struct ubus_object *obj,
                                      struct ubus_request_data *req, const char *method,
                                      struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_object_delete(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_custom_protocols_get(struct ubus_context *ctx, struct ubus_object *obj,
                                             struct ubus_request_data *req, const char *method,
                                             struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_custom_protocols_json(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_custom_protocol_set(struct ubus_context *ctx, struct ubus_object *obj,
                                            struct ubus_request_data *req, const char *method,
                                            struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_custom_protocol_update(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_custom_protocol_delete(struct ubus_context *ctx, struct ubus_object *obj,
                                               struct ubus_request_data *req, const char *method,
                                               struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_custom_protocol_delete(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_route_groups_get(struct ubus_context *ctx, struct ubus_object *obj,
                                         struct ubus_request_data *req, const char *method,
                                         struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_route_groups_json(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_route_group_set(struct ubus_context *ctx, struct ubus_object *obj,
                                        struct ubus_request_data *req, const char *method,
                                        struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_route_group_update(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_route_group_delete(struct ubus_context *ctx, struct ubus_object *obj,
                                           struct ubus_request_data *req, const char *method,
                                           struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_route_group_delete(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_wan_capacity_get(struct ubus_context *ctx, struct ubus_object *obj,
                                         struct ubus_request_data *req, const char *method,
                                         struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_wan_capacity_json(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_wan_capacity_set(struct ubus_context *ctx, struct ubus_object *obj,
                                         struct ubus_request_data *req, const char *method,
                                         struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_wan_capacity_update(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_wan_capacity_delete(struct ubus_context *ctx, struct ubus_object *obj,
                                            struct ubus_request_data *req, const char *method,
                                            struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_wan_capacity_delete(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_wan_health_get(struct ubus_context *ctx, struct ubus_object *obj,
                                       struct ubus_request_data *req, const char *method,
                                       struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_wan_health_json(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_wan_health_set(struct ubus_context *ctx, struct ubus_object *obj,
                                       struct ubus_request_data *req, const char *method,
                                       struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_wan_health_update(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_wan_health_delete(struct ubus_context *ctx, struct ubus_object *obj,
                                          struct ubus_request_data *req, const char *method,
                                          struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_wan_health_delete(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_split_rules_get(struct ubus_context *ctx, struct ubus_object *obj,
                                        struct ubus_request_data *req, const char *method,
                                        struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_split_rules_json(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_split_rule_set(struct ubus_context *ctx, struct ubus_object *obj,
                                       struct ubus_request_data *req, const char *method,
                                       struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_split_rule_update(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_split_rule_delete(struct ubus_context *ctx, struct ubus_object *obj,
                                          struct ubus_request_data *req, const char *method,
                                          struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_split_rule_delete(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_domain_rules_get(struct ubus_context *ctx, struct ubus_object *obj,
                                         struct ubus_request_data *req, const char *method,
                                         struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_domain_rules_json(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_domain_rule_set(struct ubus_context *ctx, struct ubus_object *obj,
                                        struct ubus_request_data *req, const char *method,
                                        struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_domain_rule_update(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_domain_rule_delete(struct ubus_context *ctx, struct ubus_object *obj,
                                           struct ubus_request_data *req, const char *method,
                                           struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_domain_rule_delete(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_qos_settings_get(struct ubus_context *ctx, struct ubus_object *obj,
                                         struct ubus_request_data *req, const char *method,
                                         struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)method; (void)msg;

    resp = flowd_qos_settings_json();
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int flowd_handle_qos_settings_set(struct ubus_context *ctx, struct ubus_object *obj,
                                         struct ubus_request_data *req, const char *method,
                                         struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_qos_settings_update(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_qos_classes_get(struct ubus_context *ctx, struct ubus_object *obj,
                                        struct ubus_request_data *req, const char *method,
                                        struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_qos_classes_json(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_qos_class_set(struct ubus_context *ctx, struct ubus_object *obj,
                                      struct ubus_request_data *req, const char *method,
                                      struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_qos_class_update(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_qos_class_delete(struct ubus_context *ctx, struct ubus_object *obj,
                                         struct ubus_request_data *req, const char *method,
                                         struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_qos_class_delete(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_qos_rules_get(struct ubus_context *ctx, struct ubus_object *obj,
                                      struct ubus_request_data *req, const char *method,
                                      struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_qos_rules_json(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_qos_rule_set(struct ubus_context *ctx, struct ubus_object *obj,
                                     struct ubus_request_data *req, const char *method,
                                     struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_qos_rule_update(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_qos_rule_delete(struct ubus_context *ctx, struct ubus_object *obj,
                                        struct ubus_request_data *req, const char *method,
                                        struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_qos_rule_delete(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_smart_qos_categories_get(struct ubus_context *ctx, struct ubus_object *obj,
                                                 struct ubus_request_data *req, const char *method,
                                                 struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_smart_qos_categories_json(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_smart_qos_category_set(struct ubus_context *ctx, struct ubus_object *obj,
                                               struct ubus_request_data *req, const char *method,
                                               struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_smart_qos_category_update(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_smart_qos_category_delete(struct ubus_context *ctx, struct ubus_object *obj,
                                                  struct ubus_request_data *req, const char *method,
                                                  struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_smart_qos_category_delete(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_quota_rules_get(struct ubus_context *ctx, struct ubus_object *obj,
                                        struct ubus_request_data *req, const char *method,
                                        struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_quota_rules_json(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_quota_rule_set(struct ubus_context *ctx, struct ubus_object *obj,
                                       struct ubus_request_data *req, const char *method,
                                       struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_quota_rule_update(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_quota_rule_delete(struct ubus_context *ctx, struct ubus_object *obj,
                                          struct ubus_request_data *req, const char *method,
                                          struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_quota_rule_delete(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_conn_limit_rules_get(struct ubus_context *ctx, struct ubus_object *obj,
                                             struct ubus_request_data *req, const char *method,
                                             struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_conn_limit_rules_json(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_conn_limit_rule_set(struct ubus_context *ctx, struct ubus_object *obj,
                                            struct ubus_request_data *req, const char *method,
                                            struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_conn_limit_rule_update(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_conn_limit_rule_delete(struct ubus_context *ctx, struct ubus_object *obj,
                                               struct ubus_request_data *req, const char *method,
                                               struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_conn_limit_rule_delete(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_app_rules_get(struct ubus_context *ctx, struct ubus_object *obj,
                                      struct ubus_request_data *req, const char *method,
                                      struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_app_rules_json(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_app_rule_set(struct ubus_context *ctx, struct ubus_object *obj,
                                     struct ubus_request_data *req, const char *method,
                                     struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_app_rule_update(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_app_rule_delete(struct ubus_context *ctx, struct ubus_object *obj,
                                        struct ubus_request_data *req, const char *method,
                                        struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_app_rule_delete(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_compile(struct ubus_context *ctx, struct ubus_object *obj,
                                struct ubus_request_data *req, const char *method,
                                struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_compile(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_apply_jobs(struct ubus_context *ctx, struct ubus_object *obj,
                                   struct ubus_request_data *req, const char *method,
                                   struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_apply_jobs_json(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_nft_revision_apply(struct ubus_context *ctx,
                                           struct ubus_object *obj,
                                           struct ubus_request_data *req,
                                           const char *method,
                                           struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_nft_revision_apply(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_nft_revision_status(struct ubus_context *ctx,
                                            struct ubus_object *obj,
                                            struct ubus_request_data *req,
                                            const char *method,
                                            struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)method; (void)msg;

    resp = flowd_nft_revision_status();
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int flowd_handle_runtime(struct ubus_context *ctx, struct ubus_object *obj,
                                struct ubus_request_data *req, const char *method,
                                struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = flowd_runtime_json(flowd_payload_or_self(body));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int flowd_handle_flow_ingest(struct ubus_context *ctx, struct ubus_object *obj,
                                    struct ubus_request_data *req, const char *method,
                                    struct blob_attr *msg)
{
    struct json_object *body = flowd_json_from_blob(msg);
    struct json_object *payload = flowd_payload_or_self(body);
    struct json_object *resp;
    struct json_object *data;
    int code = 0;
    int accepted = 0;
    int rejected = 0;
    (void)obj; (void)method;

    if (!payload || !json_object_is_type(payload, json_type_object)) {
        resp = flowd_error("invalid_request", "flow_ingest payload must be an object");
        flowd_send_json(ctx, req, resp);
        json_object_put(resp);
        json_object_put(body);
        return UBUS_STATUS_OK;
    }
    if (!flowd_json_str(payload, "source", "")[0])
        json_object_object_add(payload, "source", json_object_new_string("flowd.external_ingest"));

    resp = flowd_core_call("audit_flow_ingest", payload, 8000);
    data = flowd_core_data_or_self(resp);
    code = flowd_json_int(resp, "code", 0);
    accepted = flowd_json_int(data, "accepted", 0);
    rejected = flowd_json_int(data, "rejected", 0);
    json_object_object_add(resp, "ok", json_object_new_boolean(code == 2000 && accepted > 0));
    json_object_object_add(resp, "ingest_backend", json_object_new_string("dreamingwrt.audit_flow_ingest"));
    json_object_object_add(resp, "accepted", json_object_new_int(accepted));
    json_object_object_add(resp, "rejected", json_object_new_int(rejected));
    json_object_object_add(resp, "flowd_source", json_object_new_string(flowd_json_str(payload, "source", "")));
    flowd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static const struct blobmsg_policy flowd_any_policy[] = {
    { .name = "payload", .type = BLOBMSG_TYPE_UNSPEC },
};

static const struct ubus_method flowd_methods[] = {
    UBUS_METHOD("status", flowd_handle_status, flowd_any_policy),
    UBUS_METHOD("settings_get", flowd_handle_settings_get, flowd_any_policy),
    UBUS_METHOD("settings_set", flowd_handle_settings_set, flowd_any_policy),
    UBUS_METHOD("geoip_sources_get", flowd_handle_geoip_sources_get, flowd_any_policy),
    UBUS_METHOD("geoip_source_set", flowd_handle_geoip_source_set, flowd_any_policy),
    UBUS_METHOD("geoip_source_delete", flowd_handle_geoip_source_delete, flowd_any_policy),
    UBUS_METHOD("geoip_import_status", flowd_handle_geoip_import_status, flowd_any_policy),
    UBUS_METHOD("geoip_import", flowd_handle_geoip_import, flowd_any_policy),
    UBUS_METHOD("country_policies_get", flowd_handle_country_policies_get, flowd_any_policy),
    UBUS_METHOD("country_policy_set", flowd_handle_country_policy_set, flowd_any_policy),
    UBUS_METHOD("country_policy_delete", flowd_handle_country_policy_delete, flowd_any_policy),
    UBUS_METHOD("country_sets_generate", flowd_handle_country_sets_generate, flowd_any_policy),
    UBUS_METHOD("objects_get", flowd_handle_objects_get, flowd_any_policy),
    UBUS_METHOD("object_set", flowd_handle_object_set, flowd_any_policy),
    UBUS_METHOD("object_delete", flowd_handle_object_delete, flowd_any_policy),
    UBUS_METHOD("custom_protocols_get", flowd_handle_custom_protocols_get, flowd_any_policy),
    UBUS_METHOD("custom_protocol_set", flowd_handle_custom_protocol_set, flowd_any_policy),
    UBUS_METHOD("custom_protocol_delete", flowd_handle_custom_protocol_delete, flowd_any_policy),
    UBUS_METHOD("route_groups_get", flowd_handle_route_groups_get, flowd_any_policy),
    UBUS_METHOD("route_group_set", flowd_handle_route_group_set, flowd_any_policy),
    UBUS_METHOD("route_group_delete", flowd_handle_route_group_delete, flowd_any_policy),
    UBUS_METHOD("wan_capacity_get", flowd_handle_wan_capacity_get, flowd_any_policy),
    UBUS_METHOD("wan_capacity_set", flowd_handle_wan_capacity_set, flowd_any_policy),
    UBUS_METHOD("wan_capacity_delete", flowd_handle_wan_capacity_delete, flowd_any_policy),
    UBUS_METHOD("wan_health_get", flowd_handle_wan_health_get, flowd_any_policy),
    UBUS_METHOD("wan_health_set", flowd_handle_wan_health_set, flowd_any_policy),
    UBUS_METHOD("wan_health_delete", flowd_handle_wan_health_delete, flowd_any_policy),
    UBUS_METHOD("split_rules_get", flowd_handle_split_rules_get, flowd_any_policy),
    UBUS_METHOD("split_rule_set", flowd_handle_split_rule_set, flowd_any_policy),
    UBUS_METHOD("split_rule_delete", flowd_handle_split_rule_delete, flowd_any_policy),
    UBUS_METHOD("domain_rules_get", flowd_handle_domain_rules_get, flowd_any_policy),
    UBUS_METHOD("domain_rule_set", flowd_handle_domain_rule_set, flowd_any_policy),
    UBUS_METHOD("domain_rule_delete", flowd_handle_domain_rule_delete, flowd_any_policy),
    UBUS_METHOD("qos_settings_get", flowd_handle_qos_settings_get, flowd_any_policy),
    UBUS_METHOD("qos_settings_set", flowd_handle_qos_settings_set, flowd_any_policy),
    UBUS_METHOD("qos_classes_get", flowd_handle_qos_classes_get, flowd_any_policy),
    UBUS_METHOD("qos_class_set", flowd_handle_qos_class_set, flowd_any_policy),
    UBUS_METHOD("qos_class_delete", flowd_handle_qos_class_delete, flowd_any_policy),
    UBUS_METHOD("qos_rules_get", flowd_handle_qos_rules_get, flowd_any_policy),
    UBUS_METHOD("qos_rule_set", flowd_handle_qos_rule_set, flowd_any_policy),
    UBUS_METHOD("qos_rule_delete", flowd_handle_qos_rule_delete, flowd_any_policy),
    UBUS_METHOD("smart_qos_categories_get", flowd_handle_smart_qos_categories_get, flowd_any_policy),
    UBUS_METHOD("smart_qos_category_set", flowd_handle_smart_qos_category_set, flowd_any_policy),
    UBUS_METHOD("smart_qos_category_delete", flowd_handle_smart_qos_category_delete, flowd_any_policy),
    UBUS_METHOD("quota_rules_get", flowd_handle_quota_rules_get, flowd_any_policy),
    UBUS_METHOD("quota_rule_set", flowd_handle_quota_rule_set, flowd_any_policy),
    UBUS_METHOD("quota_rule_delete", flowd_handle_quota_rule_delete, flowd_any_policy),
    UBUS_METHOD("conn_limit_rules_get", flowd_handle_conn_limit_rules_get, flowd_any_policy),
    UBUS_METHOD("conn_limit_rule_set", flowd_handle_conn_limit_rule_set, flowd_any_policy),
    UBUS_METHOD("conn_limit_rule_delete", flowd_handle_conn_limit_rule_delete, flowd_any_policy),
    UBUS_METHOD("app_rules_get", flowd_handle_app_rules_get, flowd_any_policy),
    UBUS_METHOD("app_rule_set", flowd_handle_app_rule_set, flowd_any_policy),
    UBUS_METHOD("app_rule_delete", flowd_handle_app_rule_delete, flowd_any_policy),
    UBUS_METHOD("compile", flowd_handle_compile, flowd_any_policy),
    UBUS_METHOD("nft_revision_status", flowd_handle_nft_revision_status, flowd_any_policy),
    UBUS_METHOD("nft_revision_apply", flowd_handle_nft_revision_apply, flowd_any_policy),
    UBUS_METHOD("apply_jobs", flowd_handle_apply_jobs, flowd_any_policy),
    UBUS_METHOD("runtime", flowd_handle_runtime, flowd_any_policy),
    UBUS_METHOD("flow_ingest", flowd_handle_flow_ingest, flowd_any_policy),
};

static struct ubus_object_type flowd_object_type =
    UBUS_OBJECT_TYPE("dreamingwrt_flowd", flowd_methods);

static struct ubus_object flowd_object = {
    .name = "dreamingwrt.flowd",
    .type = &flowd_object_type,
    .methods = flowd_methods,
    .n_methods = ARRAY_SIZE(flowd_methods),
};

static struct ubus_object flowd_alias_object = {
    .name = "dreamingos.flowd",
    .type = &flowd_object_type,
    .methods = flowd_methods,
    .n_methods = ARRAY_SIZE(flowd_methods),
};

int flowd_ubus_start(void)
{
    int rc;

    g_flowd_ubus = ubus_connect(NULL);
    if (!g_flowd_ubus) {
        fprintf(stderr, "[dreamingwrt-flowd] ubus connect failed\n");
        return -1;
    }
    ubus_add_uloop(g_flowd_ubus);
    rc = ubus_add_object(g_flowd_ubus, &flowd_object);
    if (rc != UBUS_STATUS_OK) {
        fprintf(stderr, "[dreamingwrt-flowd] ubus object register failed rc=%d\n", rc);
        ubus_free(g_flowd_ubus);
        g_flowd_ubus = NULL;
        return -1;
    }
    rc = ubus_add_object(g_flowd_ubus, &flowd_alias_object);
    if (rc != UBUS_STATUS_OK) {
        fprintf(stderr, "[dreamingwrt-flowd] ubus alias register failed rc=%d\n", rc);
        ubus_remove_object(g_flowd_ubus, &flowd_object);
        ubus_free(g_flowd_ubus);
        g_flowd_ubus = NULL;
        return -1;
    }
    return 0;
}

void flowd_ubus_stop(void)
{
    if (g_flowd_ubus) {
        ubus_remove_object(g_flowd_ubus, &flowd_alias_object);
        ubus_remove_object(g_flowd_ubus, &flowd_object);
        ubus_free(g_flowd_ubus);
        g_flowd_ubus = NULL;
    }
}

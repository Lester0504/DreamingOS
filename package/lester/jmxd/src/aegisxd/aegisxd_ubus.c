// SPDX-License-Identifier: GPL-2.0-or-later
#include "aegisxd_internal.h"

static int aegisxd_send_json(struct ubus_context *ctx, struct ubus_request_data *req,
                             struct json_object *obj)
{
    const char *s = obj ? json_object_to_json_string(obj) : "{}";

    blob_buf_init(&g_aegisxd_blob, 0);
    if (!blobmsg_add_json_from_string(&g_aegisxd_blob, s)) {
        blob_buf_free(&g_aegisxd_blob);
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    ubus_send_reply(ctx, req, g_aegisxd_blob.head);
    blob_buf_free(&g_aegisxd_blob);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_status(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)method; (void)msg;

    resp = aegisxd_status_json();
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_feeds(struct ubus_context *ctx, struct ubus_object *obj,
                                struct ubus_request_data *req, const char *method,
                                struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)method; (void)msg;

    resp = aegisxd_feeds_json();
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_feed_status(struct ubus_context *ctx, struct ubus_object *obj,
                                      struct ubus_request_data *req, const char *method,
                                      struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)method; (void)msg;

    resp = aegisxd_feed_status_json();
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_feed_update_start(struct ubus_context *ctx, struct ubus_object *obj,
                                            struct ubus_request_data *req,
                                            const char *method,
                                            struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = aegisxd_feed_update_start(aegisxd_payload_or_self(body));
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_feed_import_start(struct ubus_context *ctx, struct ubus_object *obj,
                                            struct ubus_request_data *req,
                                            const char *method,
                                            struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = aegisxd_feed_import_start(aegisxd_payload_or_self(body));
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_feed_import_status(struct ubus_context *ctx, struct ubus_object *obj,
                                             struct ubus_request_data *req,
                                             const char *method,
                                             struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)method; (void)msg;

    resp = aegisxd_feed_import_status_json();
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_categories(struct ubus_context *ctx, struct ubus_object *obj,
                                     struct ubus_request_data *req, const char *method,
                                     struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)method; (void)msg;

    resp = aegisxd_categories_json();
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_signature_categories(struct ubus_context *ctx,
                                               struct ubus_object *obj,
                                               struct ubus_request_data *req,
                                               const char *method,
                                               struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)method; (void)msg;

    resp = aegisxd_signature_categories_json();
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_runtime(struct ubus_context *ctx, struct ubus_object *obj,
                                  struct ubus_request_data *req, const char *method,
                                  struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)method; (void)msg;

    resp = aegisxd_runtime_json();
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_events_recent(struct ubus_context *ctx, struct ubus_object *obj,
                                        struct ubus_request_data *req, const char *method,
                                        struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)method; (void)msg;

    resp = aegisxd_events_recent_json();
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_stats(struct ubus_context *ctx, struct ubus_object *obj,
                                struct ubus_request_data *req, const char *method,
                                struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)method; (void)msg;

    resp = aegisxd_stats_json();
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_health(struct ubus_context *ctx, struct ubus_object *obj,
                                 struct ubus_request_data *req, const char *method,
                                 struct blob_attr *msg)
{
    struct json_object *resp;
    (void)obj; (void)method; (void)msg;

    resp = aegisxd_health_json();
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_dns_hit_producer(struct ubus_context *ctx,
                                           struct ubus_object *obj,
                                           struct ubus_request_data *req,
                                           const char *method,
                                           struct blob_attr *msg)
{
    struct json_object *resp = json_object_new_object();
    (void)obj; (void)method; (void)msg;

    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "service", "dreamingwrt-aegisxd");
    json_object_object_add(resp, "producer", aegisxd_dns_hit_producer_status_json());
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_nft_hit_producer(struct ubus_context *ctx,
                                           struct ubus_object *obj,
                                           struct ubus_request_data *req,
                                           const char *method,
                                           struct blob_attr *msg)
{
    struct json_object *resp = json_object_new_object();
    (void)obj; (void)method; (void)msg;

    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "service", "dreamingwrt-aegisxd");
    json_object_object_add(resp, "producer", aegisxd_nft_hit_producer_status_json());
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_suricata_hit_producer(struct ubus_context *ctx,
                                                struct ubus_object *obj,
                                                struct ubus_request_data *req,
                                                const char *method,
                                                struct blob_attr *msg)
{
    struct json_object *resp = json_object_new_object();
    (void)obj; (void)method; (void)msg;

    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "service", "dreamingwrt-aegisxd");
    json_object_object_add(resp, "producer", aegisxd_suricata_hit_producer_status_json());
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}


static int aegisxd_handle_ingest_suricata_eve(struct ubus_context *ctx,
                                              struct ubus_object *obj,
                                              struct ubus_request_data *req,
                                              const char *method,
                                              struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = aegisxd_ingest_suricata_eve(aegisxd_payload_or_self(body));
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_policy_hit_producer(struct ubus_context *ctx,
                                              struct ubus_object *obj,
                                              struct ubus_request_data *req,
                                              const char *method,
                                              struct blob_attr *msg)
{
    struct json_object *resp = json_object_new_object();
    (void)obj; (void)method; (void)msg;

    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "service", "dreamingwrt-aegisxd");
    json_object_object_add(resp, "producer", aegisxd_policy_hit_producer_status_json());
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_signature_policies(struct ubus_context *ctx,
                                               struct ubus_object *obj,
                                               struct ubus_request_data *req,
                                               const char *method,
                                               struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = aegisxd_signature_policies_json(aegisxd_payload_or_self(body));
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_set_signature_policy(struct ubus_context *ctx,
                                                struct ubus_object *obj,
                                                struct ubus_request_data *req,
                                                const char *method,
                                                struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = aegisxd_set_signature_policy_json(aegisxd_payload_or_self(body));
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_suppress_signature(struct ubus_context *ctx,
                                              struct ubus_object *obj,
                                              struct ubus_request_data *req,
                                              const char *method,
                                              struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = aegisxd_suppress_signature_json(aegisxd_payload_or_self(body));
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_unsuppress_signature(struct ubus_context *ctx,
                                                struct ubus_object *obj,
                                                struct ubus_request_data *req,
                                                const char *method,
                                                struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = aegisxd_unsuppress_signature_json(aegisxd_payload_or_self(body));
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_apply(struct ubus_context *ctx, struct ubus_object *obj,
                                struct ubus_request_data *req, const char *method,
                                struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = aegisxd_apply(aegisxd_payload_or_self(body));
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_set_enabled(struct ubus_context *ctx, struct ubus_object *obj,
                                      struct ubus_request_data *req, const char *method,
                                      struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = aegisxd_set_enabled(aegisxd_payload_or_self(body));
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_set_mode(struct ubus_context *ctx, struct ubus_object *obj,
                                   struct ubus_request_data *req, const char *method,
                                   struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = aegisxd_set_mode(aegisxd_payload_or_self(body));
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_set_profile(struct ubus_context *ctx, struct ubus_object *obj,
                                      struct ubus_request_data *req, const char *method,
                                      struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = aegisxd_set_profile(aegisxd_payload_or_self(body));
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_compile(struct ubus_context *ctx, struct ubus_object *obj,
                                  struct ubus_request_data *req, const char *method,
                                  struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp;
    (void)obj; (void)method;

    resp = aegisxd_compile_plan(aegisxd_payload_or_self(body));
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_honeypot_validate(struct ubus_context *ctx, struct ubus_object *obj,
                                             struct ubus_request_data *req, const char *method,
                                             struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp = aegisxd_honeypot_validate_json(aegisxd_payload_or_self(body));
    (void)obj; (void)method;
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp); json_object_put(body);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_honeypot_set(struct ubus_context *ctx, struct ubus_object *obj,
                                       struct ubus_request_data *req, const char *method,
                                       struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp = aegisxd_honeypot_set_json(aegisxd_payload_or_self(body));
    (void)obj; (void)method;
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp); json_object_put(body);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_honeypot_delete(struct ubus_context *ctx, struct ubus_object *obj,
                                          struct ubus_request_data *req, const char *method,
                                          struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp = aegisxd_honeypot_delete_json(aegisxd_payload_or_self(body));
    (void)obj; (void)method;
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp); json_object_put(body);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_honeypot_events(struct ubus_context *ctx, struct ubus_object *obj,
                                          struct ubus_request_data *req, const char *method,
                                          struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp = aegisxd_honeypot_events_json(aegisxd_payload_or_self(body));
    (void)obj; (void)method;
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp); json_object_put(body);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_honeypot_event_ingest(struct ubus_context *ctx,
                                                 struct ubus_object *obj,
                                                 struct ubus_request_data *req,
                                                 const char *method,
                                                 struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp = aegisxd_honeypot_event_ingest(aegisxd_payload_or_self(body));
    (void)obj; (void)method;
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp); json_object_put(body);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_honeypot_get(struct ubus_context *ctx, struct ubus_object *obj,
                                       struct ubus_request_data *req, const char *method,
                                       struct blob_attr *msg)
{
    struct json_object *resp = aegisxd_honeypot_get_json();
    (void)obj; (void)method; (void)msg;
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_content_policies(struct ubus_context *ctx, struct ubus_object *obj,
                                           struct ubus_request_data *req, const char *method,
                                           struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp = aegisxd_content_policies_json(aegisxd_payload_or_self(body));
    (void)obj; (void)method; aegisxd_send_json(ctx, req, resp);
    json_object_put(resp); json_object_put(body); return UBUS_STATUS_OK;
}

static int aegisxd_handle_content_policy_validate(struct ubus_context *ctx, struct ubus_object *obj,
                                                  struct ubus_request_data *req, const char *method,
                                                  struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp = aegisxd_content_policy_validate_json(aegisxd_payload_or_self(body));
    (void)obj; (void)method; aegisxd_send_json(ctx, req, resp);
    json_object_put(resp); json_object_put(body); return UBUS_STATUS_OK;
}

static int aegisxd_handle_content_policy_set(struct ubus_context *ctx, struct ubus_object *obj,
                                             struct ubus_request_data *req, const char *method,
                                             struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp = aegisxd_content_policy_set_json(aegisxd_payload_or_self(body));
    (void)obj; (void)method; aegisxd_send_json(ctx, req, resp);
    json_object_put(resp); json_object_put(body); return UBUS_STATUS_OK;
}

static int aegisxd_handle_content_policy_delete(struct ubus_context *ctx, struct ubus_object *obj,
                                                struct ubus_request_data *req, const char *method,
                                                struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp = aegisxd_content_policy_delete_json(aegisxd_payload_or_self(body));
    (void)obj; (void)method; aegisxd_send_json(ctx, req, resp);
    json_object_put(resp); json_object_put(body); return UBUS_STATUS_OK;
}

static int aegisxd_handle_pcdn_get(struct ubus_context *ctx, struct ubus_object *obj,
                                   struct ubus_request_data *req, const char *method,
                                   struct blob_attr *msg)
{
    struct json_object *resp = aegisxd_pcdn_get_json();
    (void)obj; (void)method; (void)msg;
    aegisxd_send_json(ctx, req, resp); json_object_put(resp); return UBUS_STATUS_OK;
}

static int aegisxd_handle_pcdn_validate(struct ubus_context *ctx, struct ubus_object *obj,
                                        struct ubus_request_data *req, const char *method,
                                        struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp = aegisxd_pcdn_validate_json(aegisxd_payload_or_self(body));
    (void)obj; (void)method;
    aegisxd_send_json(ctx, req, resp); json_object_put(resp); json_object_put(body);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_pcdn_set(struct ubus_context *ctx, struct ubus_object *obj,
                                   struct ubus_request_data *req, const char *method,
                                   struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp = aegisxd_pcdn_set_json(aegisxd_payload_or_self(body));
    (void)obj; (void)method;
    aegisxd_send_json(ctx, req, resp); json_object_put(resp); json_object_put(body);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_pcdn_sync(struct ubus_context *ctx, struct ubus_object *obj,
                                    struct ubus_request_data *req, const char *method,
                                    struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp = aegisxd_pcdn_sync_json(aegisxd_payload_or_self(body));
    (void)obj; (void)method;
    aegisxd_send_json(ctx, req, resp); json_object_put(resp); json_object_put(body);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_geo_get(struct ubus_context *ctx, struct ubus_object *obj,
                                  struct ubus_request_data *req, const char *method,
                                  struct blob_attr *msg)
{
    struct json_object *resp = aegisxd_geo_get_json();
    (void)obj; (void)method; (void)msg;
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_geo_apply(struct ubus_context *ctx, struct ubus_object *obj,
                                    struct ubus_request_data *req, const char *method,
                                    struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp = aegisxd_geo_apply_json(aegisxd_payload_or_self(body));
    (void)obj; (void)method;
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    json_object_put(body);
    return UBUS_STATUS_OK;
}

static int aegisxd_handle_domain_overrides(struct ubus_context *ctx, struct ubus_object *obj,
                                           struct ubus_request_data *req, const char *method,
                                           struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp = aegisxd_domain_overrides_json(aegisxd_payload_or_self(body));
    (void)obj; (void)method; aegisxd_send_json(ctx, req, resp);
    json_object_put(resp); json_object_put(body); return UBUS_STATUS_OK;
}

static int aegisxd_handle_domain_override_set(struct ubus_context *ctx, struct ubus_object *obj,
                                              struct ubus_request_data *req, const char *method,
                                              struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp = aegisxd_domain_override_set_json(aegisxd_payload_or_self(body));
    (void)obj; (void)method; aegisxd_send_json(ctx, req, resp);
    json_object_put(resp); json_object_put(body); return UBUS_STATUS_OK;
}

static int aegisxd_handle_domain_override_delete(struct ubus_context *ctx, struct ubus_object *obj,
                                                 struct ubus_request_data *req, const char *method,
                                                 struct blob_attr *msg)
{
    struct json_object *body = aegisxd_json_from_blob(msg);
    struct json_object *resp = aegisxd_domain_override_delete_json(aegisxd_payload_or_self(body));
    (void)obj; (void)method; aegisxd_send_json(ctx, req, resp);
    json_object_put(resp); json_object_put(body); return UBUS_STATUS_OK;
}

#define AEGISXD_CERTIFICATE_HANDLER(name, function)                                      \
static int name(struct ubus_context *ctx, struct ubus_object *obj,                       \
                struct ubus_request_data *req, const char *method,                       \
                struct blob_attr *msg)                                                    \
{                                                                                         \
    struct json_object *body = aegisxd_json_from_blob(msg);                               \
    struct json_object *resp = function(aegisxd_payload_or_self(body));                    \
    (void)obj; (void)method;                                                               \
    aegisxd_send_json(ctx, req, resp);                                                     \
    json_object_put(resp);                                                                 \
    json_object_put(body);                                                                 \
    return UBUS_STATUS_OK;                                                                 \
}

AEGISXD_CERTIFICATE_HANDLER(aegisxd_handle_certificate_generate,
                            aegisxd_certificate_generate_json)
AEGISXD_CERTIFICATE_HANDLER(aegisxd_handle_certificate_rotate,
                            aegisxd_certificate_rotate_json)
AEGISXD_CERTIFICATE_HANDLER(aegisxd_handle_certificate_revoke,
                            aegisxd_certificate_revoke_json)
AEGISXD_CERTIFICATE_HANDLER(aegisxd_handle_certificate_download,
                            aegisxd_certificate_download_json)
AEGISXD_CERTIFICATE_HANDLER(aegisxd_handle_certificate_distribution_downloaded,
                            aegisxd_certificate_distribution_downloaded_json)
AEGISXD_CERTIFICATE_HANDLER(aegisxd_handle_certificate_distributions,
                            aegisxd_certificate_distributions_json)
AEGISXD_CERTIFICATE_HANDLER(aegisxd_handle_certificate_distribution_create,
                            aegisxd_certificate_distribution_create_json)
AEGISXD_CERTIFICATE_HANDLER(aegisxd_handle_certificate_distribution_get,
                            aegisxd_certificate_distribution_get_json)

static int aegisxd_handle_certificate_status(struct ubus_context *ctx,
                                             struct ubus_object *obj,
                                             struct ubus_request_data *req,
                                             const char *method,
                                             struct blob_attr *msg)
{
    struct json_object *resp = aegisxd_certificate_status_json();

    (void)obj; (void)method; (void)msg;
    aegisxd_send_json(ctx, req, resp);
    json_object_put(resp);
    return UBUS_STATUS_OK;
}

static const struct blobmsg_policy aegisxd_any_policy[] = {
    { .name = "payload", .type = BLOBMSG_TYPE_UNSPEC },
};

static const struct ubus_method aegisxd_methods[] = {
    UBUS_METHOD("status", aegisxd_handle_status, aegisxd_any_policy),
    UBUS_METHOD("feeds", aegisxd_handle_feeds, aegisxd_any_policy),
    UBUS_METHOD("feed_status", aegisxd_handle_feed_status, aegisxd_any_policy),
    UBUS_METHOD("feed_update_status", aegisxd_handle_feed_status, aegisxd_any_policy),
    UBUS_METHOD("categories", aegisxd_handle_categories, aegisxd_any_policy),
    UBUS_METHOD("signature_categories", aegisxd_handle_signature_categories, aegisxd_any_policy),
    UBUS_METHOD("runtime", aegisxd_handle_runtime, aegisxd_any_policy),
    UBUS_METHOD("events_recent", aegisxd_handle_events_recent, aegisxd_any_policy),
    UBUS_METHOD("stats", aegisxd_handle_stats, aegisxd_any_policy),
    UBUS_METHOD("health", aegisxd_handle_health, aegisxd_any_policy),
    UBUS_METHOD("dns_hit_producer", aegisxd_handle_dns_hit_producer, aegisxd_any_policy),
    UBUS_METHOD("nft_hit_producer", aegisxd_handle_nft_hit_producer, aegisxd_any_policy),
    UBUS_METHOD("suricata_hit_producer", aegisxd_handle_suricata_hit_producer, aegisxd_any_policy),
    UBUS_METHOD("ingest_suricata_eve", aegisxd_handle_ingest_suricata_eve, aegisxd_any_policy),
    UBUS_METHOD("policy_hit_producer", aegisxd_handle_policy_hit_producer, aegisxd_any_policy),
    UBUS_METHOD("feed_update_start", aegisxd_handle_feed_update_start, aegisxd_any_policy),
    UBUS_METHOD("feed_import_start", aegisxd_handle_feed_import_start, aegisxd_any_policy),
    UBUS_METHOD("feed_import_status", aegisxd_handle_feed_import_status, aegisxd_any_policy),
    UBUS_METHOD("compile", aegisxd_handle_compile, aegisxd_any_policy),
    UBUS_METHOD("apply", aegisxd_handle_apply, aegisxd_any_policy),
    UBUS_METHOD("set_enabled", aegisxd_handle_set_enabled, aegisxd_any_policy),
    UBUS_METHOD("set_mode", aegisxd_handle_set_mode, aegisxd_any_policy),
    UBUS_METHOD("set_profile", aegisxd_handle_set_profile, aegisxd_any_policy),
    UBUS_METHOD("honeypot_get", aegisxd_handle_honeypot_get, aegisxd_any_policy),
    UBUS_METHOD("honeypot_validate", aegisxd_handle_honeypot_validate, aegisxd_any_policy),
    UBUS_METHOD("honeypot_set", aegisxd_handle_honeypot_set, aegisxd_any_policy),
    UBUS_METHOD("honeypot_delete", aegisxd_handle_honeypot_delete, aegisxd_any_policy),
    UBUS_METHOD("honeypot_events", aegisxd_handle_honeypot_events, aegisxd_any_policy),
    UBUS_METHOD("honeypot_event_ingest", aegisxd_handle_honeypot_event_ingest, aegisxd_any_policy),
    UBUS_METHOD("signature_policies", aegisxd_handle_signature_policies, aegisxd_any_policy),
    UBUS_METHOD("set_signature_policy", aegisxd_handle_set_signature_policy, aegisxd_any_policy),
    UBUS_METHOD("content_policy_get", aegisxd_handle_content_policies, aegisxd_any_policy),
    UBUS_METHOD("content_policy_list", aegisxd_handle_content_policies, aegisxd_any_policy),
    UBUS_METHOD("content_policy_validate", aegisxd_handle_content_policy_validate, aegisxd_any_policy),
    UBUS_METHOD("set_content_policy", aegisxd_handle_content_policy_set, aegisxd_any_policy),
    UBUS_METHOD("content_policy_delete", aegisxd_handle_content_policy_delete, aegisxd_any_policy),
    UBUS_METHOD("content_pcdn_get", aegisxd_handle_pcdn_get, aegisxd_any_policy),
    UBUS_METHOD("content_pcdn_validate", aegisxd_handle_pcdn_validate, aegisxd_any_policy),
    UBUS_METHOD("content_pcdn_set", aegisxd_handle_pcdn_set, aegisxd_any_policy),
    UBUS_METHOD("content_pcdn_sync", aegisxd_handle_pcdn_sync, aegisxd_any_policy),
    UBUS_METHOD("certificate_status", aegisxd_handle_certificate_status, aegisxd_any_policy),
    UBUS_METHOD("certificate_generate", aegisxd_handle_certificate_generate, aegisxd_any_policy),
    UBUS_METHOD("certificate_rotate", aegisxd_handle_certificate_rotate, aegisxd_any_policy),
    UBUS_METHOD("certificate_revoke", aegisxd_handle_certificate_revoke, aegisxd_any_policy),
    UBUS_METHOD("certificate_download", aegisxd_handle_certificate_download, aegisxd_any_policy),
    UBUS_METHOD("certificate_distribution_downloaded", aegisxd_handle_certificate_distribution_downloaded, aegisxd_any_policy),
    UBUS_METHOD("certificate_distributions", aegisxd_handle_certificate_distributions, aegisxd_any_policy),
    UBUS_METHOD("certificate_distribution_create", aegisxd_handle_certificate_distribution_create, aegisxd_any_policy),
    UBUS_METHOD("certificate_distribution_get", aegisxd_handle_certificate_distribution_get, aegisxd_any_policy),
    UBUS_METHOD("domain_overrides", aegisxd_handle_domain_overrides, aegisxd_any_policy),
    UBUS_METHOD("add_domain_override", aegisxd_handle_domain_override_set, aegisxd_any_policy),
    UBUS_METHOD("remove_domain_override", aegisxd_handle_domain_override_delete, aegisxd_any_policy),
    UBUS_METHOD("geo_get", aegisxd_handle_geo_get, aegisxd_any_policy),
    UBUS_METHOD("geo_apply", aegisxd_handle_geo_apply, aegisxd_any_policy),
    UBUS_METHOD("suppress_signature", aegisxd_handle_suppress_signature, aegisxd_any_policy),
    UBUS_METHOD("unsuppress_signature", aegisxd_handle_unsuppress_signature, aegisxd_any_policy),
};

static struct ubus_object_type aegisxd_object_type =
    UBUS_OBJECT_TYPE("dreamingwrt_aegis", aegisxd_methods);

static struct ubus_object aegisxd_object = {
    .name = "dreamingwrt.aegis",
    .type = &aegisxd_object_type,
    .methods = aegisxd_methods,
    .n_methods = ARRAY_SIZE(aegisxd_methods),
};

static struct ubus_object aegisxd_alias_object = {
    .name = "dreamingos.aegis",
    .type = &aegisxd_object_type,
    .methods = aegisxd_methods,
    .n_methods = ARRAY_SIZE(aegisxd_methods),
};

int aegisxd_ubus_start(void)
{
    int rc;

    g_aegisxd_ubus = ubus_connect(NULL);
    if (!g_aegisxd_ubus) {
        fprintf(stderr, "[dreamingwrt-aegisxd] ubus connect failed\n");
        return -1;
    }
    ubus_add_uloop(g_aegisxd_ubus);
    rc = ubus_add_object(g_aegisxd_ubus, &aegisxd_object);
    if (rc != UBUS_STATUS_OK) {
        fprintf(stderr, "[dreamingwrt-aegisxd] ubus object register failed rc=%d\n", rc);
        ubus_free(g_aegisxd_ubus);
        g_aegisxd_ubus = NULL;
        return -1;
    }
    rc = ubus_add_object(g_aegisxd_ubus, &aegisxd_alias_object);
    if (rc != UBUS_STATUS_OK) {
        fprintf(stderr, "[dreamingwrt-aegisxd] ubus alias register failed rc=%d\n", rc);
        ubus_remove_object(g_aegisxd_ubus, &aegisxd_object);
        ubus_free(g_aegisxd_ubus);
        g_aegisxd_ubus = NULL;
        return -1;
    }
    return 0;
}

void aegisxd_ubus_stop(void)
{
    if (g_aegisxd_ubus) {
        ubus_remove_object(g_aegisxd_ubus, &aegisxd_alias_object);
        ubus_remove_object(g_aegisxd_ubus, &aegisxd_object);
        ubus_free(g_aegisxd_ubus);
        g_aegisxd_ubus = NULL;
    }
}

// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Aegisxd security-intelligence REST adapters (Phase 6F). The /api/v1/aegis/*
 * surface is the threat-feed / signature-policy / honeypot / content-policy /
 * domain-override / certificate control plane; most routes proxy the
 * dreamingwrt.aegis (a few the root dreamingwrt) ubus object, with one richer
 * reader (events) that annotates upstream events with client attribution.
 * Bodies are moved VERBATIM from jmx_app_api.c behind a small alias preamble
 * (req/body_json/device_id/status/resp), so no second implementation remains
 * there. The geo (shared with firewall), 5 strncmp prefix and the RAW_FD
 * certificate-download branches deliberately stay in the legacy chain.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>

#include "api_aegis.h"
#include "api_aegis_internal.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_ubus.h"
#include "webd_http_req.h"
#include "../jmx_app_api.h"

/* ── events reader (moved verbatim; annotates upstream events with client
 *    attribution borrowed from the insights subsystem) ── */

static void webd_aegis_events_annotate_client_attribution(struct json_object *data)
{
    struct json_object *events = NULL;
    int i, n;

    if (!data || !json_object_is_type(data, json_type_object))
        return;
    if (!json_object_object_get_ex(data, "events", &events) || !events ||
        !json_object_is_type(events, json_type_array))
        return;
    n = (int)json_object_array_length(events);
    for (i = 0; i < n; i++) {
        struct json_object *event = json_object_array_get_idx(events, i);
        const char *source_ip = app_nc_json_str(event, "source_ip", "");
        const char *source_mac = app_nc_json_str(event, "source_mac", "");

        if (event && json_object_is_type(event, json_type_object))
            webd_insights_add_client_attribution(event, source_ip, source_mac);
    }
}

static struct json_object *webd_aegis_events_response(struct json_object *body, int *status)
{
    struct json_object *upstream = app_ubus_object_or_error("dreamingwrt.aegis",
                                                            "events_recent", body);
    struct json_object *data = NULL;
    struct json_object *resp = NULL;
    struct json_object *ok_obj = NULL;

    if (!upstream) {
        if (status)
            *status = 503;
        return webd_error("source_unavailable", "aegis source is not available",
                          "dreamingwrt.aegis events_recent", "webd.aegis_events");
    }

    if (json_object_object_get_ex(upstream, "ok", &ok_obj) && ok_obj &&
        !json_object_get_boolean(ok_obj)) {
        if (status)
            *status = app_response_status(upstream, status ? *status : 400);
        return upstream;
    }

    data = webd_data_or_self_from_jmx_response(upstream);
    if (!data) {
        if (status)
            *status = app_response_status(upstream, status ? *status : 400);
        return upstream;
    }

    webd_aegis_events_annotate_client_attribution(data);
    resp = webd_envelope(data, "dreamingwrt.aegis.events_recent");
    webd_copy_field_if_present(resp, data, "service");
    webd_copy_field_if_present(resp, data, "available");
    webd_copy_field_if_present(resp, data, "total");
    webd_copy_field_if_present(resp, data, "limit");
    webd_copy_field_if_present(resp, data, "events");
    webd_copy_field_if_present(resp, data, "capabilities");
    webd_copy_field_if_present(resp, data, "degraded");
    webd_copy_field_if_present(resp, data, "reason");

    json_object_put(upstream);
    return resp;
}

/* ── aegis multi-alias route predicates ── */

static int aegis_match_feed_status(const char *path)
{
    return !strcmp(path, "/api/v1/aegis/feed-status") ||
           !strcmp(path, "/api/v1/aegis/feed_status") ||
           !strcmp(path, "/api/v1/aegis/feed-update/status") ||
           !strcmp(path, "/api/v1/aegis/feed_update_status");
}

static int aegis_match_feed_update_start(const char *path)
{
    return !strcmp(path, "/api/v1/aegis/feed-update/start") ||
           !strcmp(path, "/api/v1/aegis/feed_update_start") ||
           !strcmp(path, "/api/v1/aegis/feeds/update");
}

static int aegis_match_feed_import_status(const char *path)
{
    return !strcmp(path, "/api/v1/aegis/feed-import/status") ||
           !strcmp(path, "/api/v1/aegis/feed_import_status");
}

static int aegis_match_signature_categories(const char *path)
{
    return !strcmp(path, "/api/v1/aegis/signature-categories") ||
           !strcmp(path, "/api/v1/aegis/signatures/categories");
}

static int aegis_match_events(const char *path)
{
    return !strcmp(path, "/api/v1/aegis/events") ||
           !strcmp(path, "/api/v1/aegis/events/recent");
}

static int aegis_match_ingest_suricata_eve(const char *path)
{
    return !strcmp(path, "/api/v1/aegis/ingest-suricata-eve") ||
           !strcmp(path, "/api/v1/aegis/suricata/eve/ingest");
}

static int aegis_match_policies(const char *path)
{
    return !strcmp(path, "/api/v1/aegis/policies") ||
           !strcmp(path, "/api/v1/aegis/signature-policy") ||
           !strcmp(path, "/api/v1/aegis/signatures/policies");
}

/* ── aegis route handlers (verbatim bodies behind an alias preamble) ── */

static struct json_object *aegis_status(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "status", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_feeds(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "feeds", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_feed_status(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "feed_status", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_feed_update_start(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "feed_update_start", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_feed_import_start(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "feed_import_start", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_feed_import_status(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "feed_import_status", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_categories(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "categories", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_signature_categories(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "signature_categories", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_runtime(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "runtime", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_events(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = webd_aegis_events_response(body_json, &status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_stats(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "stats", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_health(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "health", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_certificates_inspection_ca(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "certificate_status", body_json);
        status = webd_aegis_certificate_http_status(resp);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_certificates_inspection_ca_generate(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "certificate_generate", body_json);
        status = webd_aegis_certificate_http_status(resp);
        jmx_app_audit_log(device_id, device_id, "aegis.certificate.generate", "high",
                          "inspection-ca", "", status < 400 ? "success" : "failed");

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_certificates_inspection_ca_rotate(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "certificate_rotate", body_json);
        status = webd_aegis_certificate_http_status(resp);
        jmx_app_audit_log(device_id, device_id, "aegis.certificate.rotate", "high",
                          "inspection-ca", "", status < 400 ? "success" : "failed");

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_certificates_inspection_ca_revoke(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "certificate_revoke", body_json);
        status = webd_aegis_certificate_http_status(resp);
        jmx_app_audit_log(device_id, device_id, "aegis.certificate.revoke", "high",
                          "inspection-ca", "", status < 400 ? "success" : "failed");

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_certificates_inspection_ca_distributions_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "certificate_distributions", body_json);
        status = webd_aegis_certificate_http_status(resp);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_certificates_inspection_ca_distributions_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "certificate_distribution_create", body_json);
        status = webd_aegis_certificate_http_status(resp);
        jmx_app_audit_log(device_id, device_id, "aegis.certificate.distribution.create",
                          "medium", app_nc_json_str(body_json, "target_id", ""), "",
                          status < 400 ? "ready_for_download" : "failed");

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_identification_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt", "aegis_identification_get", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_identification_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        resp = app_ubus_object_or_error("dreamingwrt", "aegis_identification_set", body_json);
        status = app_response_status(resp, status);
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
                          "aegis.identification.set", "medium",
                          app_nc_json_str(body_json, "mode", ""), "",
                          status < 400 ? "success" : "failed");

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_traffic_history_clear(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        if (!app_nc_json_bool(body_json, "confirm", 0)) {
            status = 400;
            resp = webd_error("confirmation_required", "confirm=true is required",
                              "confirm", "webd.aegis.traffic_history");
        } else {
            resp = app_ubus_object_or_error("dreamingwrt", "audit_clear_traffic", body_json);
            status = app_response_status(resp, status);
        }
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
                          "aegis.traffic_history.clear", "high", "traffic", "",
                          status < 400 ? "success" : "rejected");

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_app_blocks_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt", "aegis_app_blocks", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_app_blocks_validate(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt", "aegis_app_block_validate", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_app_blocks_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        const char *error;

        resp = app_ubus_object_or_error("dreamingwrt", "aegis_app_block_upsert", body_json);
        status = app_response_status(resp, status);
        error = app_ubus_response_error_code(resp);
        if (!strcmp(error, "revision_conflict"))
            status = 409;
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
                          "aegis.app_block.create", "medium",
                          app_nc_json_str(body_json, "id", ""), "",
                          status < 400 ? "success" : error);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_honeypot(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "honeypot_get", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_honeypot_events(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;

        struct json_object *params = json_object_new_object();
        char limit[32];
        char offset[32];
        if (webd_query_get(req.query, "limit", limit, sizeof(limit)) && limit[0])
            json_object_object_add(params, "limit", json_object_new_int(atoi(limit)));
        if (webd_query_get(req.query, "offset", offset, sizeof(offset)) && offset[0])
            json_object_object_add(params, "offset", json_object_new_int(atoi(offset)));
        resp = app_ubus_object_or_error("dreamingwrt.aegis", "honeypot_events", params);
        json_object_put(params);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_honeypot_validate(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "honeypot_validate", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_honeypot_config(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "honeypot_set", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_compile(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "compile", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_apply(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        /* scope=dns_filter (and scope=all) restarts dnsmasq inside the call. */
        resp = app_ubus_object_or_error_timeout("dreamingwrt.aegis", "apply", body_json,
                                               WEBD_AEGIS_DNSMASQ_APPLY_TIMEOUT_MS,
                                               &status);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_ingest_suricata_eve(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "ingest_suricata_eve", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_settings(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        const char *method = NULL;
        struct json_object *tmp = NULL;

        if (json_object_object_get_ex(body_json, "enabled", &tmp))
            method = "set_enabled";
        else if (json_object_object_get_ex(body_json, "mode", &tmp) ||
                 json_object_object_get_ex(body_json, "suricata_interface", &tmp) ||
                 json_object_object_get_ex(body_json, "suricata_queue_num", &tmp) ||
                 json_object_object_get_ex(body_json, "suricata_fail_open", &tmp))
            method = "set_mode";
        /*
         * Traffic-log fields must be tested before the set_profile fallback:
         * that fallback is the else branch, so a body carrying only
         * traffic_log_scope would otherwise be handed to set_profile, which
         * does not know the field and would answer ok/changed=false while
         * silently storing nothing.
         */
        else if (json_object_object_get_ex(body_json, "traffic_log_scope", &tmp) ||
                 json_object_object_get_ex(body_json, "traffic_log", &tmp) ||
                 json_object_object_get_ex(body_json, "traffic_log_sources", &tmp) ||
                 json_object_object_get_ex(body_json, "traffic_log_gateway_dns", &tmp) ||
                 json_object_object_get_ex(body_json, "traffic_log_aegisx_service", &tmp) ||
                 json_object_object_get_ex(body_json, "traffic_log_device_admin", &tmp))
            method = "set_traffic_log";
        else if (json_object_object_get_ex(body_json, "profile", &tmp))
            method = "set_profile";
        else
            method = "set_profile";
        resp = app_ubus_object_or_error("dreamingwrt.aegis", method, body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_policies_get(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;

        struct json_object *params = json_object_new_object();
        char value[64];
        int parsed;

        if (webd_query_get(req.query, "gid", value, sizeof(value)) && value[0]) {
            if (!app_parse_positive_int_segment(value, &parsed)) {
                status = 400;
                resp = webd_error("invalid_signature_id", "gid must be a positive integer",
                                  "gid", "webd.aegis.signature_policy");
            } else {
                json_object_object_add(params, "gid", json_object_new_int(parsed));
            }
        }
        if (!resp && webd_query_get(req.query, "sid", value, sizeof(value)) && value[0]) {
            if (!app_parse_positive_int_segment(value, &parsed)) {
                status = 400;
                resp = webd_error("invalid_signature_id", "sid must be a positive integer",
                                  "sid", "webd.aegis.signature_policy");
            } else {
                json_object_object_add(params, "sid", json_object_new_int(parsed));
            }
        }
        if (!resp && webd_query_get(req.query, "limit", value, sizeof(value)) && value[0]) {
            if (!app_parse_positive_int_segment(value, &parsed) || parsed > 500) {
                status = 400;
                resp = webd_error("invalid_limit", "limit must be between 1 and 500",
                                  "limit", "webd.aegis.signature_policy");
            } else {
                json_object_object_add(params, "limit", json_object_new_int(parsed));
            }
        }
        if (!resp && webd_query_get(req.query, "offset", value, sizeof(value)) && value[0]) {
            if (!app_parse_nonnegative_int_segment(value, &parsed)) {
                status = 400;
                resp = webd_error("invalid_offset", "offset must be a non-negative integer",
                                  "offset", "webd.aegis.signature_policy");
            } else {
                json_object_object_add(params, "offset", json_object_new_int(parsed));
            }
        }
        if (!resp) {
            const char *error;

            resp = app_ubus_object_or_error("dreamingwrt.aegis", "signature_policies", params);
            status = app_response_status(resp, status);
            error = app_ubus_response_error_code(resp);
            if (!strcmp(error, "signature_not_found"))
                status = 404;
        }
        json_object_put(params);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_policies_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        const char *error;
        char sid_target[32];

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "set_signature_policy", body_json);
        status = app_response_status(resp, status);
        error = app_ubus_response_error_code(resp);
        if (!strcmp(error, "signature_not_found"))
            status = 404;
        else if (!strcmp(error, "signature_revision_mismatch") ||
                 !strcmp(error, "revision_conflict"))
            status = 409;
        snprintf(sid_target, sizeof(sid_target), "%d",
                 app_nc_json_int(body_json, "sid", 0));
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
                          "aegis.signature_policy.set", "medium",
                          sid_target, "",
                          status < 400 ? "success" : error);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_content_policy_pcdn_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "content_pcdn_get", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_content_policy_pcdn_validate(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "content_pcdn_validate", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_content_policy_pcdn_sync(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "content_pcdn_sync", body_json);
        status = app_response_status(resp, status);
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
                          "aegis.content.pcdn.sync", "medium", "openhosts-pcdn", "",
                          status < 400 ? "success" : app_ubus_response_error_code(resp));

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_content_policy_pcdn_put(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        const char *error;
        /* Enabling PCDN restarts dnsmasq synchronously (~3.1s measured), so the
         * generic 2s budget reported a healthy backend as unavailable. */
        resp = app_ubus_object_or_error_timeout("dreamingwrt.aegis", "content_pcdn_set",
                                               body_json,
                                               WEBD_AEGIS_DNSMASQ_APPLY_TIMEOUT_MS,
                                               &status);
        status = app_response_status(resp, status);
        error = app_ubus_response_error_code(resp);
        if (!strcmp(error, "pcdn_revision_conflict"))
            status = 409;
        else if (!strcmp(error, "pcdn_revision_required") ||
                 !strcmp(error, "invalid_pcdn_revision"))
            status = 422;
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
                          "aegis.content.pcdn.set", "medium", "pcdn", "",
                          status < 400 ? "success" : error);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_content_policy_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "content_policy_list", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_content_policy_validate(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "content_policy_validate", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_content_policy_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        /* apply:true ends in the same synchronous dnsmasq restart as PCDN. */
        resp = app_ubus_object_or_error_timeout("dreamingwrt.aegis", "set_content_policy",
                                               body_json,
                                               WEBD_AEGIS_DNSMASQ_APPLY_TIMEOUT_MS,
                                               &status);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_domain_overrides_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "domain_overrides", body_json);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_domain_overrides_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error_timeout("dreamingwrt.aegis", "add_domain_override",
                                               body_json,
                                               WEBD_AEGIS_DNSMASQ_APPLY_TIMEOUT_MS,
                                               &status);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_domain_overrides_delete(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_object_or_error_timeout("dreamingwrt.aegis", "remove_domain_override",
                                               body_json,
                                               WEBD_AEGIS_DNSMASQ_APPLY_TIMEOUT_MS,
                                               &status);
        status = app_response_status(resp, status);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_signatures_suppress(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        const char *error;
        char sid_target[32];

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "suppress_signature", body_json);
        status = app_response_status(resp, status);
        error = app_ubus_response_error_code(resp);
        if (!strcmp(error, "signature_not_found"))
            status = 404;
        else if (!strcmp(error, "signature_revision_mismatch") ||
                 !strcmp(error, "revision_conflict"))
            status = 409;
        snprintf(sid_target, sizeof(sid_target), "%d",
                 app_nc_json_int(body_json, "sid", 0));
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
                          "aegis.signature.suppress", "medium",
                          sid_target, "",
                          status < 400 ? "success" : error);

    ctx->status = status;
    return resp;
}

static struct json_object *aegis_signatures_unsuppress(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        const char *error;
        char sid_target[32];

        resp = app_ubus_object_or_error("dreamingwrt.aegis", "unsuppress_signature", body_json);
        status = app_response_status(resp, status);
        error = app_ubus_response_error_code(resp);
        if (!strcmp(error, "signature_not_found"))
            status = 404;
        else if (!strcmp(error, "signature_revision_mismatch") ||
                 !strcmp(error, "revision_conflict"))
            status = 409;
        snprintf(sid_target, sizeof(sid_target), "%d",
                 app_nc_json_int(body_json, "sid", 0));
        jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
                          "aegis.signature.unsuppress", "medium",
                          sid_target, "",
                          status < 400 ? "success" : error);

    ctx->status = status;
    return resp;
}

const struct jmx_api_route aegis_api_routes[] = {
    JMX_API_ROUTE(155, "/api/v1/aegis/status", "GET", JMX_API_EXACT, aegis_status),
    JMX_API_ROUTE(156, "/api/v1/aegis/feeds", "GET", JMX_API_EXACT, aegis_feeds),
    JMX_API_PREDICATE_ROUTE(157, "/api/v1/aegis/feed-status", "GET", JMX_API_EXACT, aegis_match_feed_status, aegis_feed_status),
    JMX_API_PREDICATE_ROUTE(158, "/api/v1/aegis/feed-update/start", "POST,PUT", JMX_API_EXACT, aegis_match_feed_update_start, aegis_feed_update_start),
    JMX_API_ROUTE(159, "/api/v1/aegis/feed-import/start", "POST,PUT", JMX_API_EXACT, aegis_feed_import_start),
    JMX_API_PREDICATE_ROUTE(160, "/api/v1/aegis/feed-import/status", "GET", JMX_API_EXACT, aegis_match_feed_import_status, aegis_feed_import_status),
    JMX_API_ROUTE(161, "/api/v1/aegis/categories", "GET", JMX_API_EXACT, aegis_categories),
    JMX_API_PREDICATE_ROUTE(162, "/api/v1/aegis/signature-categories", "GET", JMX_API_EXACT, aegis_match_signature_categories, aegis_signature_categories),
    JMX_API_ROUTE(163, "/api/v1/aegis/runtime", "GET", JMX_API_EXACT, aegis_runtime),
    JMX_API_PREDICATE_ROUTE(164, "/api/v1/aegis/events", "GET", JMX_API_EXACT, aegis_match_events, aegis_events),
    JMX_API_ROUTE(165, "/api/v1/aegis/stats", "GET", JMX_API_EXACT, aegis_stats),
    JMX_API_ROUTE(166, "/api/v1/aegis/health", "GET", JMX_API_EXACT, aegis_health),
    JMX_API_ROUTE(167, "/api/v1/aegis/certificates/inspection-ca", "GET", JMX_API_EXACT, aegis_certificates_inspection_ca),
    JMX_API_ROUTE(168, "/api/v1/aegis/certificates/inspection-ca/generate", "POST", JMX_API_EXACT, aegis_certificates_inspection_ca_generate),
    JMX_API_ROUTE(169, "/api/v1/aegis/certificates/inspection-ca/rotate", "POST", JMX_API_EXACT, aegis_certificates_inspection_ca_rotate),
    JMX_API_ROUTE(170, "/api/v1/aegis/certificates/inspection-ca/revoke", "POST", JMX_API_EXACT, aegis_certificates_inspection_ca_revoke),
    JMX_API_ROUTE(171, "/api/v1/aegis/certificates/inspection-ca/distributions", "GET", JMX_API_EXACT, aegis_certificates_inspection_ca_distributions_get),
    JMX_API_ROUTE(172, "/api/v1/aegis/certificates/inspection-ca/distributions", "POST", JMX_API_EXACT, aegis_certificates_inspection_ca_distributions_post),
    JMX_API_ROUTE(173, "/api/v1/aegis/identification", "GET", JMX_API_EXACT, aegis_identification_get),
    JMX_API_ROUTE(174, "/api/v1/aegis/identification", "POST,PUT", JMX_API_EXACT, aegis_identification_post),
    JMX_API_ROUTE(175, "/api/v1/aegis/traffic-history/clear", "POST", JMX_API_EXACT, aegis_traffic_history_clear),
    JMX_API_ROUTE(176, "/api/v1/aegis/app-blocks", "GET", JMX_API_EXACT, aegis_app_blocks_get),
    JMX_API_ROUTE(177, "/api/v1/aegis/app-blocks/validate", "POST", JMX_API_EXACT, aegis_app_blocks_validate),
    JMX_API_ROUTE(178, "/api/v1/aegis/app-blocks", "POST", JMX_API_EXACT, aegis_app_blocks_post),
    JMX_API_ROUTE(185, "/api/v1/aegis/honeypot", "GET", JMX_API_EXACT, aegis_honeypot),
    JMX_API_ROUTE(186, "/api/v1/aegis/honeypot/events", "GET", JMX_API_EXACT, aegis_honeypot_events),
    JMX_API_ROUTE(187, "/api/v1/aegis/honeypot/validate", "POST", JMX_API_EXACT, aegis_honeypot_validate),
    JMX_API_ROUTE(188, "/api/v1/aegis/honeypot/config", "PUT", JMX_API_EXACT, aegis_honeypot_config),
    JMX_API_ROUTE(189, "/api/v1/aegis/compile", "POST", JMX_API_EXACT, aegis_compile),
    JMX_API_ROUTE(190, "/api/v1/aegis/apply", "POST", JMX_API_EXACT, aegis_apply),
    JMX_API_PREDICATE_ROUTE(191, "/api/v1/aegis/ingest-suricata-eve", "POST", JMX_API_EXACT, aegis_match_ingest_suricata_eve, aegis_ingest_suricata_eve),
    JMX_API_ROUTE(192, "/api/v1/aegis/settings", "POST,PUT,PATCH", JMX_API_EXACT, aegis_settings),
    JMX_API_PREDICATE_ROUTE(193, "/api/v1/aegis/policies", "GET", JMX_API_EXACT, aegis_match_policies, aegis_policies_get),
    JMX_API_PREDICATE_ROUTE(194, "/api/v1/aegis/policies", "POST,PUT,PATCH", JMX_API_EXACT, aegis_match_policies, aegis_policies_post),
    JMX_API_ROUTE(195, "/api/v1/aegis/content-policy/pcdn", "GET", JMX_API_EXACT, aegis_content_policy_pcdn_get),
    JMX_API_ROUTE(196, "/api/v1/aegis/content-policy/pcdn/validate", "POST", JMX_API_EXACT, aegis_content_policy_pcdn_validate),
    JMX_API_ROUTE(197, "/api/v1/aegis/content-policy/pcdn/sync", "POST", JMX_API_EXACT, aegis_content_policy_pcdn_sync),
    JMX_API_ROUTE(198, "/api/v1/aegis/content-policy/pcdn", "PUT,PATCH", JMX_API_EXACT, aegis_content_policy_pcdn_put),
    JMX_API_ROUTE(199, "/api/v1/aegis/content-policy", "GET", JMX_API_EXACT, aegis_content_policy_get),
    JMX_API_ROUTE(200, "/api/v1/aegis/content-policy/validate", "POST", JMX_API_EXACT, aegis_content_policy_validate),
    JMX_API_ROUTE(201, "/api/v1/aegis/content-policy", "POST,PUT,PATCH", JMX_API_EXACT, aegis_content_policy_post),
    JMX_API_ROUTE(202, "/api/v1/aegis/domain-overrides", "GET", JMX_API_EXACT, aegis_domain_overrides_get),
    JMX_API_ROUTE(203, "/api/v1/aegis/domain-overrides", "POST,PUT", JMX_API_EXACT, aegis_domain_overrides_post),
    JMX_API_ROUTE(204, "/api/v1/aegis/domain-overrides/delete", "POST,PUT,DELETE", JMX_API_EXACT, aegis_domain_overrides_delete),
    JMX_API_ROUTE(205, "/api/v1/aegis/signatures/suppress", "POST", JMX_API_EXACT, aegis_signatures_suppress),
    JMX_API_ROUTE(206, "/api/v1/aegis/signatures/unsuppress", "POST", JMX_API_EXACT, aegis_signatures_unsuppress),
    JMX_API_ROUTE_END,
};

// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Wi-Fi REST adapters (Phase 6G). The /api/v1/wifi/* surface is the SSID/radio
 * config + apply/transaction control plane, channel-AI plan reads, environment
 * survey / tx-retry / connectivity telemetry, and scan control. Bodies are moved
 * VERBATIM from jmx_app_api.c behind a small alias preamble
 * (req/body_json/device_id/authenticated_role/status/resp), so no second
 * implementation remains there. The channel-ai/plans/, transactions/ and
 * scan/jobs/ strncmp prefix branches deliberately stay in the legacy chain.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <libubus.h>
#include <json-c/json.h>

#include "api_wifi.h"
#include "api_wifi_internal.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_ubus.h"
#include "webd_http_req.h"
#include "../jmx_app_cache.h"
#include "../../ap_radio_id.h"
#include "../jmx_wifi_contract.h"
#include "../webd_wifi_aggregate.h"
#include "../jmx_app_api.h"

/* ── wifi route handlers (verbatim bodies behind an alias preamble) ── */

static struct json_object *wifi_config_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    const char *authenticated_role = ctx->authenticated_role;

        struct json_object *raw = jmx_cache_get("wifi_config_aggregate");
        struct json_object *data = raw ? webd_obj_child_obj(raw, "data") : NULL;

        if (!raw) {
            raw = webd_wifi_aggregate_response(0);
            if (raw)
                jmx_cache_put("wifi_config_aggregate", raw, 10);
            data = raw ? webd_obj_child_obj(raw, "data") : NULL;
        }
        resp = wifi_contract_read(data, authenticated_role);
        if (raw)
            json_object_put(raw);

    ctx->status = status;
    return resp;
}

static struct json_object *wifi_channel_ai_status(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        struct json_object *aggregate = webd_wifi_aggregate_response(1);
        struct json_object *data = aggregate ? webd_obj_child_obj(aggregate,
                                                                    "data") : NULL;
        struct json_object *channel_ai = data ? webd_obj_child_obj(data,
                                                                    "channel_ai") : NULL;

        if (!channel_ai) {
            resp = app_jmx_response_data(APP_API_CODE_ERROR,
                wifi_channel_ai_apply_disabled_json("", "insufficient_evidence"));
            status = 503;
        } else {
            resp = app_jmx_response_data(APP_API_CODE_SUCCESS,
                                         webd_json_clone(channel_ai));
        }
        if (aggregate)
            json_object_put(aggregate);

    ctx->status = status;
    return resp;
}

static struct json_object *wifi_channel_ai_plan_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        struct json_object *aggregate = webd_wifi_aggregate_response(1);
        struct json_object *data = aggregate ? webd_obj_child_obj(aggregate,
                                                                    "data") : NULL;
        struct json_object *channel_ai = data ? webd_obj_child_obj(data,
                                                                    "channel_ai") : NULL;

        if (!channel_ai) {
            resp = app_jmx_response_data(APP_API_CODE_ERROR,
                wifi_channel_ai_apply_disabled_json("", "insufficient_evidence"));
            status = 503;
        } else {
            resp = app_jmx_response_data(APP_API_CODE_SUCCESS,
                                         webd_json_clone(channel_ai));
        }
        if (aggregate)
            json_object_put(aggregate);

    ctx->status = status;
    return resp;
}

static struct json_object *wifi_channel_ai_plan_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        struct json_object *aggregate = webd_wifi_aggregate_response(1);
        struct json_object *data = aggregate ? webd_obj_child_obj(aggregate,
                                                                    "data") : NULL;
        struct json_object *channel_ai = data ? webd_obj_child_obj(data,
                                                                    "channel_ai") : NULL;
        struct json_object *plan = channel_ai ? webd_obj_child_obj(channel_ai,
                                                                    "plan") : NULL;
        const char *idempotency_key = body_json ? app_nc_json_str(body_json,
                                                                    "idempotency_key", "") : "";
        const char *failure = "plan_storage_failed";
        int idempotent = 0;
        int store_status = 500;
        struct json_object *stored = NULL;

        if (body_json && (!json_object_is_type(body_json, json_type_object) ||
                          (app_nc_json_has(body_json, "idempotency_key") &&
                           !webd_ac_radio_job_key_valid(idempotency_key)))) {
            resp = webd_error("invalid_request",
                              "idempotency_key is invalid",
                              "idempotency_key", "webd.wifi.channel_ai");
            status = 400;
        } else if (!channel_ai || !plan) {
            resp = app_jmx_response_data(APP_API_CODE_ERROR,
                wifi_channel_ai_apply_disabled_json("", "insufficient_evidence"));
            status = 503;
        } else {
            stored = webd_wifi_channel_ai_plan_store(plan, idempotency_key,
                                                     &store_status, &idempotent,
                                                     &failure);
            if (!stored) {
                resp = webd_error(store_status == 409 ? "conflict" :
                                  "database_error", failure,
                                  "plan_id", "webd.wifi.channel_ai");
                status = store_status;
            } else {
                struct json_object *out = webd_json_clone(channel_ai);
                struct json_object *out_plan = out ? webd_obj_child_obj(out,
                                                                         "plan") : NULL;
                if (!out || !out_plan) {
                    json_object_put(out);
                    resp = webd_error("database_error",
                                      "stored channel AI plan could not be returned",
                                      "plan_id", "webd.wifi.channel_ai");
                    status = 500;
                } else {
                    json_object_object_del(out, "plan");
                    json_object_object_add(out, "plan", stored);
                    json_object_object_add(out, "persisted",
                                           json_object_new_boolean(1));
                    json_object_object_add(out, "idempotent",
                                           json_object_new_boolean(idempotent));
                    resp = app_jmx_response_data(APP_API_CODE_SUCCESS, out);
                    status = store_status;
                }
            }
        }
        if (aggregate)
            json_object_put(aggregate);

    ctx->status = status;
    return resp;
}

static struct json_object *wifi_config_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        /* Core preserves secrets, snapshots desired state and rolls UCI and
         * runtime back on a failed readback, so it is the gate.  A local box
         * with no phy still fails closed there with no_phy_detected, and an
         * unadopted AP is not treated as a managed-AP transaction. */
        /*
         * These three run past the shared 2s ubus budget by design.  Save
         * validates every radio against the driver (`iw phy` on a cold cache),
         * and apply copies the UCI draft, reloads wifi and then waits up to 5s
         * for the UCI and beacon readback -- twice more when it has to roll
         * back.  Measured on 31.251: apply is ~0.2s in the steady state, 7-8s
         * when a beacon never appears, and the first call after a core restart
         * is ~15s.  Under the default budget the browser was told "dreamingwrt
         * ubus source is not available or did not answer in time" while the
         * identical call succeeded from the shell, and the write kept going
         * server-side, so the UI reported a failure over a config that did
         * change.  The budgets below cover the observed worst case, and an
         * invoke-stage timeout now reads as `dependency_timeout`/504 -- still
         * applying -- instead of blaming the daemon.
         */
        resp = app_ubus_core_route_source("wifi_config_save", body_json,
                                          30000, &status, "webd.wifi");
        webd_wifi_failure_observe(ctx, "wifi_config_save", resp, status);
        /* The aggregate read model is cached for 10s.  A save that is not
         * followed by an invalidation makes the very next GET replay the
         * pre-write snapshot, so the browser reads back rows it just changed
         * or deleted and reports a phantom readback mismatch. */
        jmx_cache_invalidate("wifi_config_aggregate");

    ctx->status = status;
    return resp;
}

static struct json_object *wifi_config_apply(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_core_route_source("wifi_config_apply", body_json,
                                          45000, &status, "webd.wifi");
        webd_wifi_failure_observe(ctx, "wifi_config_apply", resp, status);
        jmx_cache_invalidate("wifi_config_aggregate");

    ctx->status = status;
    return resp;
}

static struct json_object *wifi_ssids_delete(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        resp = app_ubus_core_route_source("wifi_ssids_delete", body_json,
                                          45000, &status, "webd.wifi");
        jmx_cache_invalidate("wifi_config_aggregate");

    ctx->status = status;
    return resp;
}

static struct json_object *wifi_transactions(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;

        struct json_object *params = webd_wifi_transaction_create_params(
            body_json, device_id, &status);

        if (!params) {
            resp = webd_error(status == 500 ? "internal_error" :
                              "invalid_request",
                              status == 500 ?
                              "could not allocate Wi-Fi transaction request" :
                              "idempotency_key, consistency, base_revision and targets are required",
                              "idempotency_key|consistency|base_revision|targets",
                              "webd.wifi.transactions");
        } else {
            resp = webd_ac_ubus_or_disabled(
                                            "wifi_transaction_apply", params);
            status = webd_ac_http_status(resp, status);
            jmx_app_audit_log(device_id[0] ? device_id : "http", device_id,
                              "wifi.transaction.apply", "high", req.path,
                              "", "");
            json_object_put(params);
        }

    webd_wifi_failure_observe(ctx, "wifi_config_apply", resp, status);
    ctx->status = status;
    return resp;
}

static struct json_object *wifi_status(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;

        resp = jmx_cache_get("wifi_status_aggregate");
        if (!resp) {
            resp = webd_wifi_aggregate_response(1);
            if (resp) jmx_cache_put("wifi_status_aggregate", resp, 5);
        }

    ctx->status = status;
    return resp;
}

static struct json_object *wifi_environment_survey_history(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;

        struct json_object *params = webd_wifi_survey_history_params(req.query,
                                                                     &status);

        if (!params) {
            resp = webd_error(status == 500 ? "internal_error" : "invalid_query",
                              status == 500 ?
                              "could not allocate Wi-Fi Survey history request" :
                              "Wi-Fi Survey history query parameters are invalid",
                              "ap_id|radio_id|start|end|resolution|limit|after_id",
                              "webd.wifi.survey_history");
        } else {
            struct app_ubus_call_diag diag = { .rc = -1, .stage = NULL };

            resp = app_ubus_invoke_object_diag("dreamingwrt.ac",
                                               "survey_history", params,
                                               2000, &diag);
            if (resp) {
                status = webd_ac_http_status(resp, status);
            } else if (diag.stage && !strcmp(diag.stage, "invoke") &&
                       diag.rc == UBUS_STATUS_INVALID_ARGUMENT) {
                /* AC answered and rejected the arguments.  That is a
                 * request/contract failure, not a transport outage, and
                 * must not masquerade as "source unavailable". */
                status = 400;
                resp = webd_error("upstream_rejected_request",
                                  "dreamingwrt.ac rejected the Wi-Fi Survey history arguments",
                                  "dreamingwrt.ac survey_history stage=invoke rc=invalid_argument",
                                  "webd.wifi.survey_history");
            } else {
                char dependency[128];

                snprintf(dependency, sizeof(dependency),
                         "dreamingwrt.ac survey_history stage=%s rc=%d",
                         diag.stage ? diag.stage : "unknown", diag.rc);
                status = 503;
                resp = webd_error("source_unavailable",
                                  "ubus source is not available", dependency,
                                  "webd.wifi.survey_history");
            }
            json_object_put(params);
        }

    ctx->status = status;
    return resp;
}

static struct json_object *wifi_environment_tx_retry_history(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;

        struct json_object *params = webd_wifi_survey_history_params(req.query,
                                                                     &status);
        struct json_object *resolution = NULL;

        /* The shared parser also accepts the Survey hourly rollup, which the
         * retry chain does not keep: only 300s buckets are written. Rejecting
         * it here names the real reason instead of letting the AC answer a
         * generic invalid-argument that reads like a transport fault. */
        if (params &&
            json_object_object_get_ex(params, "resolution", &resolution) &&
            resolution && json_object_is_type(resolution, json_type_string) &&
            strcmp(json_object_get_string(resolution), "auto") &&
            strcmp(json_object_get_string(resolution), "300")) {
            json_object_put(params);
            params = NULL;
            status = 400;
        }
        if (!params) {
            resp = webd_error(status == 500 ? "internal_error" : "invalid_query",
                              status == 500 ?
                              "could not allocate Wi-Fi TX retry history request" :
                              "Wi-Fi TX retry history query parameters are invalid; "
                              "resolution must be auto or 300",
                              "ap_id|radio_id|start|end|resolution|limit|after_id",
                              "webd.wifi.tx_retry_history");
        } else {
            struct app_ubus_call_diag diag = { .rc = -1, .stage = NULL };

            resp = app_ubus_invoke_object_diag("dreamingwrt.ac",
                                               "tx_retry_history", params,
                                               2000, &diag);
            if (resp) {
                status = webd_ac_http_status(resp, status);
            } else if (diag.stage && !strcmp(diag.stage, "invoke") &&
                       diag.rc == UBUS_STATUS_INVALID_ARGUMENT) {
                status = 400;
                resp = webd_error("upstream_rejected_request",
                                  "dreamingwrt.ac rejected the Wi-Fi TX retry history arguments",
                                  "dreamingwrt.ac tx_retry_history stage=invoke rc=invalid_argument",
                                  "webd.wifi.tx_retry_history");
            } else {
                char dependency[128];

                snprintf(dependency, sizeof(dependency),
                         "dreamingwrt.ac tx_retry_history stage=%s rc=%d",
                         diag.stage ? diag.stage : "unknown", diag.rc);
                status = 503;
                resp = webd_error("source_unavailable",
                                  "ubus source is not available", dependency,
                                  "webd.wifi.tx_retry_history");
            }
            json_object_put(params);
        }

    ctx->status = status;
    return resp;
}

static struct json_object *wifi_connectivity_events(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;

        struct json_object *params = webd_wifi_station_events_params(
            req.query, &status);

        if (!params) {
            resp = webd_error(status == 500 ? "internal_error" : "invalid_query",
                              status == 500 ?
                              "could not allocate Wi-Fi connectivity events request" :
                              "Wi-Fi connectivity events query parameters are invalid",
                              "ap_id|event|start|end|after_id|limit",
                              "webd.wifi.connectivity_events");
        } else {
            struct app_ubus_call_diag diag = { .rc = -1, .stage = NULL };

            resp = app_ubus_invoke_object_diag("dreamingwrt.ac",
                                               "station_events", params,
                                               2000, &diag);
            if (resp) {
                status = webd_ac_http_status(resp, status);
            } else if (diag.stage && !strcmp(diag.stage, "invoke") &&
                       diag.rc == UBUS_STATUS_INVALID_ARGUMENT) {
                status = 400;
                resp = webd_error("upstream_rejected_request",
                                  "dreamingwrt.ac rejected the connectivity events arguments",
                                  "dreamingwrt.ac station_events stage=invoke rc=invalid_argument",
                                  "webd.wifi.connectivity_events");
            } else {
                char dependency[128];

                snprintf(dependency, sizeof(dependency),
                         "dreamingwrt.ac station_events stage=%s rc=%d",
                         diag.stage ? diag.stage : "unknown", diag.rc);
                status = 503;
                resp = webd_error("source_unavailable",
                                  "ubus source is not available", dependency,
                                  "webd.wifi.connectivity_events");
            }
            json_object_put(params);
        }

    ctx->status = status;
    return resp;
}

static struct json_object *wifi_scan(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = NULL;
    int status = ctx->status;
    struct json_object *body_json = ctx->body;

        struct json_object *params = webd_ac_radio_job_create_params(body_json,
                                                                     &status);

        if (!params) {
            resp = webd_error(status == 500 ? "internal_error" : "invalid_request",
                              status == 500 ?
                              "could not allocate Wi-Fi scan job request" :
                              "ap_id, local phy radio_id, mode and idempotency_key are required",
                              "ap_id|radio_id|mode|idempotency_key",
                              "webd.wifi.scan_jobs");
        } else {
            resp = webd_ac_ubus_or_disabled(
                                            "radio_job_create", params);
            status = webd_ac_http_status(resp, status);
            json_object_put(params);
        }

    ctx->status = status;
    return resp;
}

static struct json_object *wifi_scan_jobs(struct jmx_api_ctx *ctx)
{
    struct http_req req = *ctx->req;
    struct json_object *resp = NULL;
    int status = ctx->status;

        char ap_id[64];

        if (!webd_query_get(req.query, "ap_id", ap_id, sizeof(ap_id)) ||
            !webd_ac_token_id_valid(ap_id)) {
            status = 400;
            resp = webd_error("invalid_ap_id", "ap_id must be a UUID v4",
                              "ap_id", "webd.wifi.scan_jobs");
        } else {
            struct json_object *params = json_object_new_object();

            json_object_object_add(params, "ap_id", json_object_new_string(ap_id));
            resp = webd_ac_ubus_or_disabled(
                                            "radio_job_list", params);
            status = webd_ac_http_status(resp, status);
            json_object_put(params);
        }

    ctx->status = status;
    return resp;
}

const struct jmx_api_route wifi_api_routes[] = {
    JMX_API_ROUTE(630, "/api/v1/wifi/config", "GET", JMX_API_EXACT, wifi_config_get),
    JMX_API_ROUTE(631, "/api/v1/wifi/channel-ai/status", "GET", JMX_API_EXACT, wifi_channel_ai_status),
    JMX_API_ROUTE(632, "/api/v1/wifi/channel-ai/plan", "GET", JMX_API_EXACT, wifi_channel_ai_plan_get),
    JMX_API_ROUTE(633, "/api/v1/wifi/channel-ai/plan", "POST", JMX_API_EXACT, wifi_channel_ai_plan_post),
    JMX_API_ROUTE(635, "/api/v1/wifi/config", "POST,PUT", JMX_API_EXACT, wifi_config_post),
    JMX_API_ROUTE(636, "/api/v1/wifi/config/apply", "POST,PUT", JMX_API_EXACT, wifi_config_apply),
    JMX_API_ROUTE(637, "/api/v1/wifi/ssids/delete", "POST", JMX_API_EXACT, wifi_ssids_delete),
    JMX_API_ROUTE(638, "/api/v1/wifi/transactions", "POST,PUT", JMX_API_EXACT, wifi_transactions),
    JMX_API_ROUTE(639, "/api/v1/wifi/status", "GET", JMX_API_EXACT, wifi_status),
    JMX_API_ROUTE(640, "/api/v1/wifi/environment/survey-history", "GET", JMX_API_EXACT, wifi_environment_survey_history),
    JMX_API_ROUTE(641, "/api/v1/wifi/environment/tx-retry-history", "GET", JMX_API_EXACT, wifi_environment_tx_retry_history),
    JMX_API_ROUTE(642, "/api/v1/wifi/connectivity/events", "GET", JMX_API_EXACT, wifi_connectivity_events),
    JMX_API_ROUTE(643, "/api/v1/wifi/scan", "POST,PUT", JMX_API_EXACT, wifi_scan),
    JMX_API_ROUTE(644, "/api/v1/wifi/scan/jobs", "GET", JMX_API_EXACT, wifi_scan_jobs),
    JMX_API_ROUTE_END,
};

static int webd_ac_radio_job_mode_valid(const char *value)
{
    return value && (!strcmp(value, "neighbor") || !strcmp(value, "survey"));
}

/* Radio ids come in two shapes and both are legitimate.  `phyN` is the legacy
 * one-radio-per-wiphy form; `phyNrM` selects radio M inside wiphy N, which is
 * what mac80211 hardware exposing several radios through a single phy reports
 * (Gemtek W1700K on 31.250/31.251 publishes phy0r0/phy0r1/phy0r2).  The AC
 * accepts both through dreamingwrt_ap_radio_id_valid(); this validator used to
 * carry its own digits-only copy, so every POST /api/v1/wifi/scan for a real
 * radio was rejected with 400 "ap_id, local phy radio_id, mode and
 * idempotency_key are required" before it ever reached the AC.  Share the one
 * parser instead of keeping a second, stricter opinion here. */
static int webd_ac_radio_id_valid(const char *value)
{
    return dreamingwrt_ap_radio_id_valid(value);
}

static int webd_ac_radio_id_normalize(const char *ap_id, const char *value,
                                      char *out, size_t out_size)
{
    char prefix[96];
    const char *local_id = value;

    if (!ap_id || !value || !out || out_size == 0)
        return -1;
    if (!strncmp(value, "ap:", 3)) {
        if (snprintf(prefix, sizeof(prefix), "ap:%s:radio:", ap_id) >=
                (int)sizeof(prefix) || strncmp(value, prefix, strlen(prefix)))
            return -1;
        local_id = value + strlen(prefix);
    }
    if (!webd_ac_radio_id_valid(local_id) ||
        snprintf(out, out_size, "%s", local_id) >= (int)out_size)
        return -1;
    return 0;
}

int webd_ac_radio_job_key_valid(const char *value)
{
    size_t i;

    if (!value || !value[0] || strlen(value) > 128)
        return 0;
    for (i = 0; value[i]; i++) {
        unsigned char c = (unsigned char)value[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' ||
              c == ':' || c == '-'))
            return 0;
    }
    return 1;
}

/* The local-phy write routes forward unconditionally to core, which owns the
 * only authoritative gate: it re-checks phy presence, the secret vault and the
 * wifi CLI, and publishes the matching capability bits.  A compile-time switch
 * here used to shadow those bits, so GET reported save_config=true while every
 * POST returned a fixed 409.  Managed AP writes remain a separate AC/APD
 * transaction surface. */

struct webd_wifi_survey_history_query {
    char ap_id[64];
    char radio_id[32];
    char resolution[8];
    int64_t start;
    int64_t end;
    int64_t after_id;
    int limit;
    unsigned int present;
};

enum {
    WEBD_WIFI_SURVEY_AP_ID = 1u << 0,
    WEBD_WIFI_SURVEY_RADIO_ID = 1u << 1,
    WEBD_WIFI_SURVEY_START = 1u << 2,
    WEBD_WIFI_SURVEY_END = 1u << 3,
    WEBD_WIFI_SURVEY_RESOLUTION = 1u << 4,
    WEBD_WIFI_SURVEY_LIMIT = 1u << 5,
    WEBD_WIFI_SURVEY_AFTER_ID = 1u << 6
};

static int webd_wifi_query_decode_strict(const char *src, size_t src_len,
                                         char *out, size_t out_len)
{
    size_t i = 0;
    size_t j = 0;

    if (!src || !out || out_len == 0)
        return 0;
    while (i < src_len) {
        unsigned char value;

        if (src[i] == '%') {
            int hi;
            int lo;

            if (i + 2 >= src_len)
                return 0;
            hi = webd_hex_value(src[i + 1]);
            lo = webd_hex_value(src[i + 2]);
            if (hi < 0 || lo < 0)
                return 0;
            value = (unsigned char)((hi << 4) | lo);
            i += 3;
        } else {
            value = (unsigned char)(src[i] == '+' ? ' ' : src[i]);
            i++;
        }
        if (value == '\0' || j + 1 >= out_len)
            return 0;
        out[j++] = (char)value;
    }
    out[j] = '\0';
    return 1;
}

static int webd_wifi_parse_int64_strict(const char *value, int64_t *out)
{
    const char *p = value;
    char *end = NULL;
    long long parsed;

    if (out)
        *out = 0;
    if (!value || !value[0] || !out)
        return 0;
    if (*p == '-')
        p++;
    if (!*p)
        return 0;
    while (*p) {
        if (!isdigit((unsigned char)*p))
            return 0;
        p++;
    }
    errno = 0;
    parsed = strtoll(value, &end, 10);
    if (errno == ERANGE || !end || *end)
        return 0;
    *out = (int64_t)parsed;
    return 1;
}

static int webd_wifi_survey_history_parse_pair(
    struct webd_wifi_survey_history_query *parsed,
    const char *name, const char *value)
{
    unsigned int bit;
    int64_t number;

    if (!parsed || !name || !name[0] || !value || !value[0])
        return 0;
    if (!strcmp(name, "ap_id"))
        bit = WEBD_WIFI_SURVEY_AP_ID;
    else if (!strcmp(name, "radio_id"))
        bit = WEBD_WIFI_SURVEY_RADIO_ID;
    else if (!strcmp(name, "start"))
        bit = WEBD_WIFI_SURVEY_START;
    else if (!strcmp(name, "end"))
        bit = WEBD_WIFI_SURVEY_END;
    else if (!strcmp(name, "resolution"))
        bit = WEBD_WIFI_SURVEY_RESOLUTION;
    else if (!strcmp(name, "limit"))
        bit = WEBD_WIFI_SURVEY_LIMIT;
    else if (!strcmp(name, "after_id"))
        bit = WEBD_WIFI_SURVEY_AFTER_ID;
    else
        return 0;
    if (parsed->present & bit)
        return 0;

    if (bit == WEBD_WIFI_SURVEY_AP_ID) {
        if (!webd_ac_token_id_valid(value) ||
            snprintf(parsed->ap_id, sizeof(parsed->ap_id), "%s", value) >=
                (int)sizeof(parsed->ap_id))
            return 0;
    } else if (bit == WEBD_WIFI_SURVEY_RADIO_ID) {
        if (!webd_ac_radio_id_valid(value) ||
            snprintf(parsed->radio_id, sizeof(parsed->radio_id), "%s", value) >=
                (int)sizeof(parsed->radio_id))
            return 0;
    } else if (bit == WEBD_WIFI_SURVEY_RESOLUTION) {
        if (strcmp(value, "auto") && strcmp(value, "300") &&
            strcmp(value, "3600"))
            return 0;
        if (!strcmp(value, "auto"))
            memcpy(parsed->resolution, "auto", sizeof("auto"));
        else if (!strcmp(value, "300"))
            memcpy(parsed->resolution, "300", sizeof("300"));
        else
            memcpy(parsed->resolution, "3600", sizeof("3600"));
    } else {
        if (!webd_wifi_parse_int64_strict(value, &number))
            return 0;
        if (bit == WEBD_WIFI_SURVEY_START)
            parsed->start = number;
        else if (bit == WEBD_WIFI_SURVEY_END)
            parsed->end = number;
        else if (bit == WEBD_WIFI_SURVEY_AFTER_ID) {
            if (number < 0)
                return 0;
            parsed->after_id = number;
        } else {
            if (number < 1 || number > WEBD_WIFI_SURVEY_HISTORY_MAX_LIMIT)
                return 0;
            parsed->limit = (int)number;
        }
    }
    parsed->present |= bit;
    return 1;
}

struct json_object *webd_wifi_survey_history_params(
    const char *query, int *http_status)
{
    struct webd_wifi_survey_history_query parsed = {
        .limit = WEBD_WIFI_SURVEY_HISTORY_DEFAULT_LIMIT
    };
    const char *cursor = query ? query : "";
    struct json_object *params;

    if (http_status)
        *http_status = 400;
    while (*cursor) {
        const char *pair_end = strchr(cursor, '&');
        const char *equals;
        char name[32];
        char value[128];

        if (!pair_end)
            pair_end = cursor + strlen(cursor);
        if (pair_end == cursor)
            return NULL;
        equals = memchr(cursor, '=', (size_t)(pair_end - cursor));
        if (!equals || equals == cursor || equals + 1 == pair_end ||
            !webd_wifi_query_decode_strict(cursor, (size_t)(equals - cursor),
                                           name, sizeof(name)) ||
            !webd_wifi_query_decode_strict(equals + 1,
                                           (size_t)(pair_end - equals - 1),
                                           value, sizeof(value)) ||
            !webd_wifi_survey_history_parse_pair(&parsed, name, value))
            return NULL;
        if (*pair_end && !pair_end[1])
            return NULL;
        cursor = *pair_end ? pair_end + 1 : pair_end;
    }
    if ((parsed.present & WEBD_WIFI_SURVEY_RADIO_ID) &&
        !(parsed.present & WEBD_WIFI_SURVEY_AP_ID))
        return NULL;
    if ((parsed.present & WEBD_WIFI_SURVEY_START) &&
        (parsed.present & WEBD_WIFI_SURVEY_END) && parsed.start > parsed.end)
        return NULL;

    params = json_object_new_object();
    if (!params) {
        if (http_status)
            *http_status = 500;
        return NULL;
    }
    if (parsed.present & WEBD_WIFI_SURVEY_AP_ID)
        json_object_object_add(params, "ap_id",
                               json_object_new_string(parsed.ap_id));
    if (parsed.present & WEBD_WIFI_SURVEY_RADIO_ID)
        json_object_object_add(params, "radio_id",
                               json_object_new_string(parsed.radio_id));
    if (parsed.present & WEBD_WIFI_SURVEY_START)
        json_object_object_add(params, "start",
                               json_object_new_int64(parsed.start));
    if (parsed.present & WEBD_WIFI_SURVEY_END)
        json_object_object_add(params, "end", json_object_new_int64(parsed.end));
    if (parsed.present & WEBD_WIFI_SURVEY_RESOLUTION)
        json_object_object_add(params, "resolution",
                               json_object_new_string(parsed.resolution));
    json_object_object_add(params, "limit", json_object_new_int(parsed.limit));
    if (parsed.present & WEBD_WIFI_SURVEY_AFTER_ID)
        json_object_object_add(params, "after_id",
                               json_object_new_int64(parsed.after_id));
    if (http_status)
        *http_status = 200;
    return params;
}

#define WEBD_WIFI_STATION_EVENTS_MAX_LIMIT 1024
#define WEBD_WIFI_STATION_EVENTS_DEFAULT_LIMIT 256

/* Strict allowlist parser for /api/v1/wifi/connectivity/events.  Unknown
 * or duplicate query parameters fail closed exactly like the Survey
 * history contract. */
struct json_object *webd_wifi_station_events_params(
    const char *query, int *http_status)
{
    struct json_object *params;
    const char *cursor = query ? query : "";
    char ap_id[64] = { 0 };
    char event[16] = { 0 };
    int64_t start = 0;
    int64_t end = 0;
    int64_t after_id = 0;
    int64_t limit = 0;
    unsigned int seen = 0;

    if (http_status)
        *http_status = 400;
    while (*cursor) {
        const char *pair_end = strchr(cursor, '&');
        const char *equals;
        char name[32];
        char value[128];
        unsigned int bit;
        int64_t number;

        if (!pair_end)
            pair_end = cursor + strlen(cursor);
        if (pair_end == cursor)
            return NULL;
        equals = memchr(cursor, '=', (size_t)(pair_end - cursor));
        if (!equals || equals == cursor || equals + 1 == pair_end ||
            !webd_wifi_query_decode_strict(cursor, (size_t)(equals - cursor),
                                           name, sizeof(name)) ||
            !webd_wifi_query_decode_strict(equals + 1,
                                           (size_t)(pair_end - equals - 1),
                                           value, sizeof(value)))
            return NULL;
        if (!strcmp(name, "ap_id")) {
            bit = 1u << 0;
            if ((seen & bit) || !webd_ac_token_id_valid(value) ||
                snprintf(ap_id, sizeof(ap_id), "%s", value) >=
                    (int)sizeof(ap_id))
                return NULL;
        } else if (!strcmp(name, "event")) {
            bit = 1u << 1;
            if ((seen & bit) ||
                (strcmp(value, "connect") && strcmp(value, "disconnect") &&
                 strcmp(value, "roam")) ||
                snprintf(event, sizeof(event), "%s", value) >=
                    (int)sizeof(event))
                return NULL;
        } else if (!strcmp(name, "start") || !strcmp(name, "end") ||
                   !strcmp(name, "after_id") || !strcmp(name, "limit")) {
            if (!webd_wifi_parse_int64_strict(value, &number))
                return NULL;
            if (!strcmp(name, "start")) {
                bit = 1u << 2;
                if ((seen & bit) || number <= 0)
                    return NULL;
                start = number;
            } else if (!strcmp(name, "end")) {
                bit = 1u << 3;
                if ((seen & bit) || number <= 0)
                    return NULL;
                end = number;
            } else if (!strcmp(name, "after_id")) {
                bit = 1u << 4;
                if ((seen & bit) || number < 0)
                    return NULL;
                after_id = number;
            } else {
                bit = 1u << 5;
                if ((seen & bit) || number < 1 ||
                    number > WEBD_WIFI_STATION_EVENTS_MAX_LIMIT)
                    return NULL;
                limit = number;
            }
        } else {
            return NULL;
        }
        seen |= bit;
        if (*pair_end && !pair_end[1])
            return NULL;
        cursor = *pair_end ? pair_end + 1 : pair_end;
    }
    if ((seen & (1u << 2)) && (seen & (1u << 3)) && start > end)
        return NULL;
    params = json_object_new_object();
    if (!params) {
        if (http_status)
            *http_status = 500;
        return NULL;
    }
    if (ap_id[0])
        json_object_object_add(params, "ap_id",
                               json_object_new_string(ap_id));
    if (event[0])
        json_object_object_add(params, "event",
                               json_object_new_string(event));
    if (seen & (1u << 2))
        json_object_object_add(params, "start",
                               json_object_new_int64(start));
    if (seen & (1u << 3))
        json_object_object_add(params, "end", json_object_new_int64(end));
    if (seen & (1u << 4))
        json_object_object_add(params, "after_id",
                               json_object_new_int64(after_id));
    json_object_object_add(params, "limit", json_object_new_int(
        limit > 0 ? (int)limit : WEBD_WIFI_STATION_EVENTS_DEFAULT_LIMIT));
    if (http_status)
        *http_status = 200;
    return params;
}

struct json_object *webd_ac_radio_job_create_params(
    struct json_object *body, int *http_status)
{
    struct json_object *value = NULL;
    const char *ap_id;
    const char *radio_id;
    const char *mode;
    const char *idempotency_key;
    struct json_object *params;
    char normalized_radio_id[32];

    if (!body || !json_object_is_type(body, json_type_object))
        goto invalid;
    json_object_object_foreach(body, key, ignored) {
        (void)ignored;
        if (strcmp(key, "ap_id") && strcmp(key, "radio_id") &&
            strcmp(key, "mode") && strcmp(key, "idempotency_key"))
            goto invalid;
    }
    if (!json_object_object_get_ex(body, "ap_id", &value) || !value ||
        !json_object_is_type(value, json_type_string))
        goto invalid;
    ap_id = json_object_get_string(value);
    if (!webd_ac_token_id_valid(ap_id))
        goto invalid;
    if (!json_object_object_get_ex(body, "radio_id", &value) || !value ||
        !json_object_is_type(value, json_type_string))
        goto invalid;
    radio_id = json_object_get_string(value);
    if (webd_ac_radio_id_normalize(ap_id, radio_id, normalized_radio_id,
                                   sizeof(normalized_radio_id)) != 0)
        goto invalid;
    if (!json_object_object_get_ex(body, "mode", &value) || !value ||
        !json_object_is_type(value, json_type_string))
        goto invalid;
    mode = json_object_get_string(value);
    if (!webd_ac_radio_job_mode_valid(mode))
        goto invalid;
    if (!json_object_object_get_ex(body, "idempotency_key", &value) || !value ||
        !json_object_is_type(value, json_type_string))
        goto invalid;
    idempotency_key = json_object_get_string(value);
    if (!webd_ac_radio_job_key_valid(idempotency_key))
        goto invalid;

    params = json_object_new_object();
    if (!params) {
        if (http_status)
            *http_status = 500;
        return NULL;
    }
    json_object_object_add(params, "ap_id", json_object_new_string(ap_id));
    json_object_object_add(params, "radio_id",
                           json_object_new_string(normalized_radio_id));
    json_object_object_add(params, "mode", json_object_new_string(mode));
    json_object_object_add(params, "idempotency_key",
                           json_object_new_string(idempotency_key));
    return params;

invalid:
    if (http_status)
        *http_status = 400;
    return NULL;
}


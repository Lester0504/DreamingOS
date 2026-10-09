// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_WIFI_INTERNAL_H
#define WEBD_API_WIFI_INTERNAL_H

struct json_object;
struct jmx_api_ctx;
void webd_wifi_failure_observe(struct jmx_api_ctx *ctx, const char *operation,
                                struct json_object *response, int status);

/* Bounded Wi-Fi Survey-history limits. Shared between the status aggregate
 * builder in jmx_app_api.c and the query parser in api_wifi.c, so the single
 * definition lives here (both translation units include this header). */
#define WEBD_WIFI_SURVEY_HISTORY_DEFAULT_LIMIT 2048
#define WEBD_WIFI_SURVEY_HISTORY_MAX_LIMIT 4096
#define WEBD_WIFI_SURVEY_HISTORY_STATUS_WINDOW_S 43200

/*
 * Cross-TU wifi/AC helpers. webd_wifi_aggregate_response() is defined in
 * jmx_app_api.c; the other four are defined in api_wifi.c (moved out of the
 * main translation unit in Phase 7V together with their static-callee
 * closure). Declared here so every caller -- api_wifi.c's route handlers and
 * api_wifi_ac_apply.c -- resolves to the single definition of each.
 */
int webd_ac_radio_job_key_valid(const char *value);
struct json_object *webd_wifi_survey_history_params(const char *query, int *http_status);
struct json_object *webd_wifi_station_events_params(const char *query, int *http_status);
struct json_object *webd_ac_radio_job_create_params(struct json_object *body, int *http_status);
struct json_object *webd_wifi_aggregate_response(int runtime_status);
int webd_ac_token_id_valid(const char *token_id);
struct json_object *webd_wifi_channel_ai_plan_store(struct json_object *plan,
                                                    const char *idempotency_key,
                                                    int *http_status, int *idempotent,
                                                    const char **failure);
struct json_object *webd_wifi_transaction_create_params(struct json_object *body,
                                                        const char *identity,
                                                        int *http_status);
int webd_ac_http_status(struct json_object *resp, int default_status);
struct json_object *webd_ac_ubus_or_disabled(const char *method,
                                             struct json_object *params);


/* Phase 7I: AC-param / wifi-transaction / channel-AI-plan-load validators
 * moved out of jmx_app_api.c (behavior-preserving; routes unchanged, still
 * dispatched from handle_client() in the main TU). */
struct json_object *webd_ac_create_params(struct json_object *body, int *http_status);
struct json_object *webd_ac_discovery_confirm_params( struct json_object *body, const char *client_info, int *http_status);
int webd_wifi_transaction_actor_id(const char *identity, char out[37]);
int webd_wifi_transaction_digest_valid(const char *value);
int webd_wifi_channel_ai_plan_id_valid(const char *value);
int webd_wifi_channel_ai_plan_schema(void);
struct json_object *webd_wifi_channel_ai_plan_load(const char *plan_id);


/* Phase 7J: channel-AI apply cluster (validate / receipt load-reserve-store)
 * moved out of jmx_app_api.c (behavior-preserving; routes unchanged, still
 * dispatched from handle_client() in the main TU). The apply-validation enum
 * is shared with the POST handler that stays in main, so it is declared here
 * (before the validate prototype that returns it). transaction_create_params
 * is already declared above (L24). */
enum webd_wifi_channel_ai_apply_validation {
    WEBD_WIFI_CHANNEL_AI_APPLY_VALID = 0,
    WEBD_WIFI_CHANNEL_AI_APPLY_INVALID,
    WEBD_WIFI_CHANNEL_AI_APPLY_NOT_FOUND,
    WEBD_WIFI_CHANNEL_AI_APPLY_CONFLICT,
    WEBD_WIFI_CHANNEL_AI_APPLY_STALE,
    WEBD_WIFI_CHANNEL_AI_APPLY_STORAGE_ERROR,
};
enum webd_wifi_channel_ai_apply_validation webd_wifi_channel_ai_apply_validate( const char *plan_id, struct json_object *body, struct json_object **stored_out, const char **failure);
struct json_object *webd_wifi_channel_ai_apply_receipt_load( const char *identity, const char *idempotency_key, const char *plan_id, const char *plan_digest, int *http_status, int *conflict, int *pending);
int webd_wifi_channel_ai_apply_receipt_reserve( const char *identity, const char *idempotency_key, const char *plan_id, const char *plan_digest);
int webd_wifi_channel_ai_apply_receipt_store( const char *identity, const char *idempotency_key, const char *plan_id, const char *plan_digest, int http_status, struct json_object *response);
/* Phase 7P: channel-AI EXECUTE cluster (response_data + result_identity /
 * local_results / managed_results / apply_execute) moved out of
 * jmx_app_api.c into api_wifi_ac_apply.c (behavior-preserving; routes
 * unchanged, still dispatched from handle_client() in the main TU).
 * response_data and apply_execute are called from the POST handler in
 * main, so both are declared here; the three result builders stay
 * file-static in api_wifi_ac_apply.c. */
struct json_object *webd_wifi_channel_ai_response_data( struct json_object *response);
struct json_object *webd_wifi_channel_ai_apply_execute(struct json_object *plan,
                                                       struct json_object *body,
                                                       const char *identity,
                                                       int *http_status);

/* Phase 7Q: AC controller helpers relocated to api_wifi_ac_control.c */
struct json_object *webd_ac_ap_update_params(const char *ap_id,
                                                    struct json_object *body,
                                                    int *http_status);
int webd_ac_secret_rotation_path(const char *path, char ap_id[37],
                                        char ssid_id[65]);
int webd_ac_secret_status_path(const char *path, char job_id[37]);
int webd_ac_txpower_mode_path(const char *path, char ap_id[37]);
struct json_object *webd_ac_txpower_mode_params(const char *ap_id,
                                                        struct json_object *body,
                                                        int *http_status);
int webd_ac_response_ok(struct json_object *resp);
int webd_ac_controller_enabled(void);
struct json_object *webd_ac_ubus_or_disabled_timeout(
	const char *method, struct json_object *params, int timeout_ms,
	int *http_status);

#endif /* WEBD_API_WIFI_INTERNAL_H */

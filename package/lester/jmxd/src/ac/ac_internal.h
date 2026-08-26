// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_AC_INTERNAL_H
#define DREAMINGWRT_AC_INTERNAL_H

#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <sqlite3.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "ac_secrets.h"

#define AC_CONFIG_DB_PATH "/etc/dreamingwrt/config.db"
#define AC_CONTRACT_VERSION "ap-control.v1"
#define AC_SCHEMA_VERSION 14
#define AC_SECRETS_KEY_PATH "/etc/dreamingwrt/ac-secrets.key"
#define AC_SERVICE_NAME "dreamingwrt-ac"
#define AC_NODE_TRANSPORT_ENABLED 1
#define AC_PAIRING_TOKEN_ID_LEN 36
#define AC_PAIRING_TOKEN_LEN 43
#define AC_PAIRING_SITE_ID_LEN 64
#define AC_PAIRING_HARDWARE_DIGEST_LEN 71
#define AC_PAIRING_TOKEN_TTL_MIN 60
#define AC_PAIRING_TOKEN_TTL_MAX 86400
#define AC_PAIRING_TOKEN_ATTEMPTS_MAX 10
#define AC_ENROLLMENT_ID_LEN 36
#define AC_ENROLLMENT_KEY_ID_LEN 71
#define AC_ENROLLMENT_PUBLIC_KEY_LEN 32
#define AC_ENROLLMENT_NONCE_LEN 32
#define AC_ENROLLMENT_SIGNATURE_LEN 64
#define AC_ENROLLMENT_CSR_MAX 8192
#define AC_ENROLLMENT_CERT_MAX 16384
#define AC_ENROLLMENT_CHALLENGE_TTL_MIN 30
#define AC_ENROLLMENT_CHALLENGE_TTL_MAX 300
#define AC_ENROLLMENT_CLAIM_TTL 600
#define AC_ENROLLMENT_ACTIVATION_TTL 300
#define AC_ENROLLMENT_ACTIVATION_ATTEMPTS 5
#define AC_TRANSPORT_DEFAULT_PORT 18443
#define AC_TRANSPORT_WORKERS_MAX 8
#define AC_AP_ONLINE_TIMEOUT_SECONDS 45
#define AC_TELEMETRY_STALE_TIMEOUT_SECONDS 360
#define AC_DEVICE_MODEL_MAX 255
#define AC_DEVICE_BOARD_NAME_MAX 127
#define AC_DEVICE_MODEL_SOURCE_MAX 63
#define AC_DEVICE_MODEL_REASON_MAX 127
#define AC_TELEMETRY_SCHEMA "apd-backend.snapshot"
#define AC_TELEMETRY_VERSION 1
#define AC_RADIO_JOB_ID_LEN 36
#define AC_RADIO_JOB_RADIO_ID_MAX 31
#define AC_RADIO_JOB_IDEMPOTENCY_MAX 128
#define AC_RADIO_JOB_SESSION_EPOCH_MAX 64
#define AC_RADIO_JOB_RESULT_DIGEST_MAX 71
#define AC_RADIO_JOB_ERROR_MAX 127
#define AC_RADIO_JOB_IMPACT_MAX 95
#define AC_RADIO_JOB_LEASE_SECONDS 90
#define AC_RADIO_JOB_RECONCILE_SECONDS 90
#define AC_RADIO_JOB_RESULT_ITEMS_MAX 128
#define AC_RADIO_JOB_RESULT_JSON_MAX (48U * 1024U)
#define AC_RADIO_JOB_LIST_LIMIT 128
#define AC_RADIO_JOB_RETENTION_SECONDS 86400
#define AC_RADIO_JOB_RETENTION_MIN 128
#define AC_SURVEY_SAMPLE_MIN_SECONDS 240
#define AC_SURVEY_SAMPLE_GAP_SECONDS 900
#define AC_SURVEY_FINE_RESOLUTION_SECONDS 300
#define AC_SURVEY_FINE_RETENTION_SECONDS (48 * 60 * 60)
#define AC_SURVEY_FINE_RETENTION_ROWS 576
#define AC_SURVEY_HOUR_RESOLUTION_SECONDS 3600
#define AC_SURVEY_HOUR_RETENTION_SECONDS (31 * 24 * 60 * 60)
#define AC_SURVEY_HOUR_RETENTION_ROWS 744
#define AC_SURVEY_HISTORY_LIMIT_MAX 4096
#define AC_TX_RETRY_FINE_RESOLUTION_SECONDS 300
#define AC_TX_RETRY_FINE_RETENTION_SECONDS (48 * 60 * 60)
#define AC_TX_RETRY_FINE_RETENTION_ROWS 576
#define AC_TX_RETRY_HISTORY_LIMIT_MAX 4096
#define AC_AP_TRAFFIC_SAMPLE_MAX_SECONDS 3600
#define AC_AP_TRAFFIC_RESOLUTION_SECONDS 60
#define AC_AP_TRAFFIC_RETENTION_SECONDS (31 * 24 * 60 * 60)
#define AC_AP_TRAFFIC_RETENTION_ROWS 44640

struct ac_pki;
struct ac_pki_issued_certificate;

enum ac_pairing_redeem_result {
    AC_PAIRING_REDEEM_ERROR = -1,
    AC_PAIRING_REDEEM_OK = 0,
    AC_PAIRING_REDEEM_INVALID = 1,
    AC_PAIRING_REDEEM_EXPIRED = 2,
    AC_PAIRING_REDEEM_REVOKED = 3,
    AC_PAIRING_REDEEM_CONSUMED = 4,
    AC_PAIRING_REDEEM_EXHAUSTED = 5,
};

enum ac_enrollment_result {
    AC_ENROLLMENT_ERROR = -1,
    AC_ENROLLMENT_OK = 0,
    AC_ENROLLMENT_INVALID = 1,
    AC_ENROLLMENT_EXPIRED = 2,
    AC_ENROLLMENT_REVOKED = 3,
    AC_ENROLLMENT_CONFLICT = 4,
    AC_ENROLLMENT_EXHAUSTED = 5,
    AC_ENROLLMENT_IDEMPOTENT = 6,
};

struct ac_pairing_token_secret {
    char token_id[AC_PAIRING_TOKEN_ID_LEN + 1];
    char token[AC_PAIRING_TOKEN_LEN + 1];
    int64_t created_at;
    int64_t expires_at;
    int max_attempts;
};

struct ac_pairing_token_status {
    char token_id[AC_PAIRING_TOKEN_ID_LEN + 1];
    char site_id[AC_PAIRING_SITE_ID_LEN + 1];
    int hardware_bound;
    int attempts;
    int max_attempts;
    int64_t created_at;
    int64_t expires_at;
    int64_t consumed_at;
    int64_t revoked_at;
    int64_t claimed_at;
    char state[16];
};

struct ac_enrollment_challenge {
    char challenge_id[AC_ENROLLMENT_ID_LEN + 1];
    unsigned char server_nonce[AC_ENROLLMENT_NONCE_LEN];
    int64_t created_at;
    int64_t expires_at;
};

struct ac_enrollment_claim {
    char challenge_id[AC_ENROLLMENT_ID_LEN + 1];
    unsigned char server_nonce[AC_ENROLLMENT_NONCE_LEN];
    unsigned char client_nonce[AC_ENROLLMENT_NONCE_LEN];
    char enrollment_id[AC_ENROLLMENT_ID_LEN + 1];
    char token_id[AC_PAIRING_TOKEN_ID_LEN + 1];
    const char *token;
    char ap_id[AC_ENROLLMENT_ID_LEN + 1];
    char key_id[AC_ENROLLMENT_KEY_ID_LEN + 1];
    unsigned char public_key[AC_ENROLLMENT_PUBLIC_KEY_LEN];
    char site_id[AC_PAIRING_SITE_ID_LEN + 1];
    char hardware_digest[AC_PAIRING_HARDWARE_DIGEST_LEN + 1];
    const unsigned char *csr_der;
    size_t csr_der_len;
    unsigned char csr_sha256[32];
    int64_t challenge_expires_at;
};

struct ac_enrollment_signed_request {
    struct ac_enrollment_claim claim;
    unsigned char signature[AC_ENROLLMENT_SIGNATURE_LEN];
};

struct ac_enrollment_record {
    char enrollment_id[AC_ENROLLMENT_ID_LEN + 1];
    char token_id[AC_PAIRING_TOKEN_ID_LEN + 1];
    char ap_id[AC_ENROLLMENT_ID_LEN + 1];
    char site_id[AC_PAIRING_SITE_ID_LEN + 1];
    char key_id[AC_ENROLLMENT_KEY_ID_LEN + 1];
    char certificate_id[AC_ENROLLMENT_ID_LEN + 1];
    char state[32];
    int64_t claim_expires_at;
    int64_t created_at;
    int64_t updated_at;
    int64_t adopted_at;
};

struct ac_enrollment_certificate {
    char enrollment_id[AC_ENROLLMENT_ID_LEN + 1];
    char certificate_id[AC_ENROLLMENT_ID_LEN + 1];
    char serial[129];
    char issuer_key_id[AC_ENROLLMENT_KEY_ID_LEN + 1];
    const unsigned char *certificate_der;
    size_t certificate_der_len;
    unsigned char fingerprint_sha256[32];
    int64_t not_before;
    int64_t not_after;
};

struct ac_device_model_report {
    char model[AC_DEVICE_MODEL_MAX + 1];
    char board_name[AC_DEVICE_BOARD_NAME_MAX + 1];
    char model_source[AC_DEVICE_MODEL_SOURCE_MAX + 1];
    char reason[AC_DEVICE_MODEL_REASON_MAX + 1];
    int model_available;
};

enum ac_radio_job_result {
    AC_RADIO_JOB_ERROR = -1,
    AC_RADIO_JOB_OK = 0,
    AC_RADIO_JOB_IDEMPOTENT = 1,
    AC_RADIO_JOB_NOT_FOUND = 2,
    AC_RADIO_JOB_CONFLICT = 3,
    AC_RADIO_JOB_INVALID_TARGET = 4,
    AC_RADIO_JOB_UNAVAILABLE = 5,
};

struct ac_radio_job {
    char job_id[AC_RADIO_JOB_ID_LEN + 1];
    char ap_id[AC_ENROLLMENT_ID_LEN + 1];
    char radio_id[AC_RADIO_JOB_RADIO_ID_MAX + 1];
    char mode[9];
    char state[17];
    char idempotency_key[AC_RADIO_JOB_IDEMPOTENCY_MAX + 1];
    int64_t created_at;
    int64_t updated_at;
    char lease_owner[AC_ENROLLMENT_ID_LEN + 1];
    int64_t lease_expires_at;
    char session_epoch[AC_RADIO_JOB_SESSION_EPOCH_MAX + 1];
    char attempt_id[AC_RADIO_JOB_ID_LEN + 1];
    int64_t dispatch_generation;
    char request_digest[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1];
    char finish_id[AC_RADIO_JOB_ID_LEN + 1];
    char finish_digest[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1];
    int64_t last_progress_at;
    int64_t reconcile_deadline;
    int result_count;
    int64_t result_bytes;
    char result_digest[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1];
    int result_complete;
    char error_code[AC_RADIO_JOB_ERROR_MAX + 1];
    char expected_impact[AC_RADIO_JOB_IMPACT_MAX + 1];
};

typedef int (*ac_pairing_token_visit_fn)(
    const struct ac_pairing_token_status *status, void *opaque);
typedef int (*ac_radio_job_visit_fn)(const struct ac_radio_job *job,
                                    void *opaque);

extern sqlite3 *g_ac_db;
extern struct ubus_context *g_ac_ubus;
extern struct blob_buf g_ac_blob;
extern int64_t g_ac_started_at;

int64_t ac_now_s(void);
const char *ac_db_path(void);
int ac_db_init(void);
void ac_db_close(void);
int ac_db_count(const char *table);
int ac_db_managed_ap_counts(int64_t online_since, int *total, int *online);
int ac_db_ap_session_begin(const char *ap_id, const char *session_epoch,
                           int protocol_version, int64_t received_at);
int ac_db_ap_session_begin_with_capabilities(
    const char *ap_id, const char *session_epoch, int protocol_version,
    int write_capable, int64_t received_at);
int ac_db_ap_session_end(const char *ap_id, const char *session_epoch);
int ac_db_ap_heartbeat(const char *ap_id, const char *session_epoch,
                       int64_t received_at);
int ac_db_scan_execution_available(int64_t online_since, int *ap_count);
int ac_db_wifi_write_execution_available(int64_t online_since,
                                         int *ap_count);
int ac_db_ap_identity_report(const char *ap_id,
                             const struct ac_device_model_report *report);
int ac_db_ap_telemetry_store(const char *ap_id, const char *session_epoch,
                             int64_t sequence,
                             int64_t observed_at, int64_t received_at,
                             const char *snapshot_id,
                             const struct ac_device_model_report *report,
                             struct json_object *snapshot);
int ac_db_radio_job_create(const char *ap_id, const char *radio_id,
                           const char *mode, const char *idempotency_key,
                           struct ac_radio_job *out);
int ac_db_radio_job_status(const char *job_id, struct ac_radio_job *out);
int ac_db_radio_job_list(const char *ap_id, ac_radio_job_visit_fn visit,
                         void *opaque, int *limited);
int ac_db_radio_jobs_prune(int64_t now);

/* ── Periodic survey schedule ────────────────────────────────────────────
 * Only mode='survey' is schedulable. A neighbour scan leaves the working
 * channel and stays manual; see the ac_survey_schedule DDL in ac_db.c.
 */
#define AC_SURVEY_SCHEDULE_MIN_INTERVAL 60
#define AC_SURVEY_SCHEDULE_MAX_INTERVAL 3600
#define AC_SURVEY_SCHEDULE_DEFAULT_INTERVAL 300
#define AC_SURVEY_SCHEDULE_INVALID_INTERVAL (-2)

struct ac_survey_schedule {
    int enabled;
    char mode[9];
    int interval_seconds;
    int64_t last_run_at;
    int last_dispatched;
    char last_error[64];
};

int ac_db_survey_schedule_load(struct ac_survey_schedule *out);
/* enabled < 0 or interval_seconds <= 0 leaves that field unchanged. */
int ac_db_survey_schedule_save(int enabled, int interval_seconds);
/* Dispatches one survey job per eligible radio when the interval has elapsed. */
int ac_db_survey_schedule_tick(int64_t now, int *dispatched_out);
int ac_db_radio_job_cancel(const char *job_id, struct ac_radio_job *out);
int ac_db_radio_job_result_metadata(const char *job_id,
                                    struct ac_radio_job *out);
int ac_db_ap_session_is_current(const char *ap_id, const char *session_epoch);
/* 1 when ac_aps.adoption_state is 'adopted'. 0 on unknown ap_id or db error, so
 * discovery errs toward listing a candidate rather than hiding a real AP. */
int ac_db_ap_is_adopted(const char *ap_id);
int ac_db_radio_job_lease_next(const char *ap_id, const char *session_epoch,
                               int64_t now, struct ac_radio_job *out);
int ac_db_radio_job_mark_running(const char *job_id, const char *attempt_id,
                                 int64_t dispatch_generation,
                                 const char *request_digest, const char *ap_id,
                                 const char *session_epoch,
                                 struct ac_radio_job *out);
int ac_db_radio_job_progress(const char *job_id, const char *attempt_id,
                             int64_t dispatch_generation,
                             const char *request_digest, const char *ap_id,
                             const char *session_epoch, int64_t now,
                             struct ac_radio_job *out);
int ac_db_radio_job_finish(const char *job_id, const char *attempt_id,
                           int64_t dispatch_generation,
                           const char *request_digest, const char *ap_id,
                           const char *session_epoch, const char *finish_id,
                           const char *outcome, const char *error_code,
                           const char *result_json, int result_truncated,
                           struct ac_radio_job *out);
int ac_db_radio_job_reconcile(const char *job_id, const char *attempt_id,
                              int64_t dispatch_generation,
                              const char *request_digest, const char *ap_id,
                              const char *session_epoch,
                              const char *reported_state, int64_t now,
                              struct ac_radio_job *out);
int ac_db_radio_jobs_reconcile_expired(int64_t now);
int ac_db_radio_job_result_payload(const char *job_id, char **result_json_out);
struct json_object *ac_db_radio_job_latest_results_json(void);
struct json_object *ac_db_survey_history_json(const char *ap_id,
                                              const char *radio_id,
                                              int64_t start, int64_t end,
                                              int resolution_seconds,
                                              int limit, int64_t after_id);
struct json_object *ac_db_tx_retry_history_json(const char *ap_id,
                                                const char *radio_id,
                                                int64_t start, int64_t end,
                                                int resolution_seconds,
                                                int limit, int64_t after_id);
struct json_object *ac_db_ap_traffic_history_json(const char *range,
                                                 const char *ap_id);
struct json_object *ac_db_station_events_json(const char *ap_id,
                                              const char *event,
                                              int64_t start, int64_t end,
                                              int limit, int64_t after_id);
struct json_object *ac_db_aps_list_json(int64_t observed_at,
                                        int64_t online_since);
struct json_object *ac_db_wifi_transaction_validate_json(
    const char *ap_id, int64_t base_revision, const char *idempotency_key,
    const char *changes_json, int64_t now);

/* ---- Phase W2b: config job store (dispatch side of the write
 * transaction).  Creation stays internal until the W3 orchestration;
 * no ubus/REST surface exposes these. ---- */

enum ac_config_job_result {
    AC_CONFIG_JOB_ERROR = -1,
    AC_CONFIG_JOB_OK = 0,
    AC_CONFIG_JOB_IDEMPOTENT = 1,
    AC_CONFIG_JOB_NOT_FOUND = 2,
    AC_CONFIG_JOB_CONFLICT = 3,
    AC_CONFIG_JOB_INVALID = 4,
    AC_CONFIG_JOB_UNAVAILABLE = 5,
};

#define AC_CONFIG_JOB_CANDIDATE_MAX_BYTES (16 * 1024)
#define AC_CONFIG_JOB_READBACK_MAX_BYTES (16 * 1024)
#define AC_CONFIG_JOB_LEASE_SECONDS 60

struct ac_config_job {
    char job_id[AC_RADIO_JOB_ID_LEN + 1];
    char ap_id[AC_ENROLLMENT_ID_LEN + 1];
    char state[17];
    char idempotency_key[AC_RADIO_JOB_IDEMPOTENCY_MAX + 1];
    char candidate_digest[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1];
    int64_t created_at;
    int64_t updated_at;
    int64_t lease_expires_at;
    char session_epoch[AC_RADIO_JOB_SESSION_EPOCH_MAX + 1];
    char attempt_id[AC_RADIO_JOB_ID_LEN + 1];
    int64_t dispatch_generation;
    char request_digest[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1];
    char finish_id[AC_RADIO_JOB_ID_LEN + 1];
    char outcome[15];
    char error_code[AC_RADIO_JOB_ERROR_MAX + 1];
};

int ac_db_config_job_create(const char *ap_id, const char *candidate_json,
                            const char *candidate_digest,
                            const char *idempotency_key,
                            struct ac_config_job *out);
int ac_db_config_job_status(const char *job_id, struct ac_config_job *out);
int ac_db_config_job_lease_next(const char *ap_id,
                                const char *session_epoch, int64_t now,
                                struct ac_config_job *out,
                                char **candidate_json_out);
int ac_db_config_job_mark_running(const char *job_id, const char *attempt_id,
                                  int64_t dispatch_generation,
                                  const char *request_digest,
                                  const char *ap_id,
                                  const char *session_epoch, int64_t now,
                                  struct ac_config_job *out);
int ac_db_config_job_finish(const char *job_id, const char *attempt_id,
                            int64_t dispatch_generation,
                            const char *request_digest, const char *ap_id,
                            const char *session_epoch,
                            const char *finish_id, const char *outcome,
                            const char *error_code,
                            const char *readback_json, int64_t now,
                            struct ac_config_job *out);
int ac_db_config_jobs_recover(int64_t now);

/* Managed Wi-Fi transaction orchestration. One apply fans out to one
 * ac_transactions row, one ac_transaction_targets row per AP and one queued
 * ac_config_jobs row per AP. Creation is allowed only for adopted targets on
 * a current write-capable ap-control.v3 session. */

#define AC_WIFI_TX_TARGETS_MAX 32
#define AC_WIFI_TX_CANDIDATE_MAX_BYTES (16 * 1024)

int ac_db_wifi_transaction_apply(const char *actor_id,
                                 const char *idempotency_key,
                                 const char *consistency,
                                 int64_t base_revision,
                                 const char *targets_json, int64_t now,
                                 char transaction_id_out[AC_RADIO_JOB_ID_LEN + 1],
                                 char *error_out, size_t error_len);
struct json_object *ac_db_wifi_transaction_status_json(
    const char *transaction_id);
struct json_object *ac_wifi_transaction_apply_json(
    const char *actor_id, const char *idempotency_key,
    const char *consistency, int64_t base_revision,
    const char *targets_json);
struct json_object *ac_wifi_transaction_status_json(
    const char *transaction_id);
int ac_db_pairing_token_create(int64_t ttl_seconds, int max_attempts,
                               const char *site_id,
                               const char *hardware_digest,
                               struct ac_pairing_token_secret *out);
int ac_db_pairing_token_status(const char *token_id,
                               struct ac_pairing_token_status *out);
int ac_db_pairing_token_list(ac_pairing_token_visit_fn visit, void *opaque);
int ac_db_pairing_token_revoke(const char *token_id);
int ac_db_ap_label_valid(const char *value);
/* ac_db_ap_update() outcomes; the caller maps these to HTTP statuses. */
#define AC_AP_UPDATE_INVALID   (-1)
#define AC_AP_UPDATE_NOT_FOUND (-2)
#define AC_AP_UPDATE_DB_ERROR  (-3)
int ac_db_ap_update(const char *ap_id, const char *name,
                    const char *model_override);
int ac_db_pairing_token_redeem(const char *token_id, const char *token,
                               const char *site_id,
                               const char *hardware_digest,
                               struct ac_pairing_token_status *out);
int ac_db_enrollment_challenge_create(
    int64_t ttl_seconds, struct ac_enrollment_challenge *out);
int ac_db_enrollment_challenge_get(
    const char *challenge_id, struct ac_enrollment_challenge *out);
int ac_db_enrollment_claim(const struct ac_enrollment_claim *claim,
                           struct ac_enrollment_record *out);
int ac_db_enrollment_certificate_commit(
    const struct ac_enrollment_certificate *certificate,
    struct ac_enrollment_record *out);
int ac_db_enrollment_certificate_get(
    const char *enrollment_id, struct ac_enrollment_certificate *out,
    unsigned char **owned_der);
int ac_db_certificate_peer_authorize(
    const char *certificate_id, const char *ap_id,
    const unsigned char fingerprint_sha256[32], int require_active);
int ac_db_enrollment_activation_begin(
    const char *enrollment_id, const char *certificate_id,
    unsigned char challenge[AC_ENROLLMENT_NONCE_LEN]);
int ac_db_enrollment_activate(
    const char *enrollment_id, const char *certificate_id,
    const unsigned char peer_fingerprint_sha256[32],
    const unsigned char *challenge, size_t challenge_len,
    struct ac_enrollment_record *out);
int ac_enrollment_verify_and_claim(
    const struct ac_enrollment_signed_request *request,
    struct ac_enrollment_record *out);
int ac_enrollment_transcript_build(
    const struct ac_enrollment_claim *claim,
    unsigned char **out, size_t *out_len);

int ac_pki_init(struct ac_pki **out);
/* Server certificate validity window, so status can show an unusable
 * certificate instead of leaving it to be found with openssl by hand. */
int ac_transport_server_certificate_window(int64_t *not_before,
                                           int64_t *not_after,
                                           int *usable_now,
                                           int *not_yet_valid);
void ac_pki_free(struct ac_pki *pki);
const char *ac_pki_controller_id(const struct ac_pki *pki);
const char *ac_pki_ca_key_id(const struct ac_pki *pki);
const unsigned char *ac_pki_ca_fingerprint_sha256(const struct ac_pki *pki);
const char *ac_pki_ca_fingerprint_text(const struct ac_pki *pki);
X509 *ac_pki_ca_certificate_dup(const struct ac_pki *pki);
X509 *ac_pki_server_certificate_dup(const struct ac_pki *pki);
EVP_PKEY *ac_pki_server_private_key_dup(const struct ac_pki *pki);
int ac_pki_ca_der(const struct ac_pki *pki, unsigned char **out,
                  size_t *out_len);
int ac_pki_ca_pem(const struct ac_pki *pki, unsigned char **out,
                  size_t *out_len);
int ac_pki_issue_ap_certificate(
    const struct ac_pki *pki, const char *ap_id,
    const unsigned char raw_public_key[AC_ENROLLMENT_PUBLIC_KEY_LEN],
    const unsigned char *csr_der, size_t csr_der_len,
    struct ac_pki_issued_certificate **out);
void ac_pki_issued_certificate_free(
    struct ac_pki_issued_certificate *certificate);
const unsigned char *ac_pki_issued_certificate_der(
    const struct ac_pki_issued_certificate *certificate, size_t *out_len);
const char *ac_pki_issued_certificate_serial(
    const struct ac_pki_issued_certificate *certificate);
const char *ac_pki_issued_certificate_issuer_key_id(
    const struct ac_pki_issued_certificate *certificate);
const unsigned char *ac_pki_issued_certificate_fingerprint_sha256(
    const struct ac_pki_issued_certificate *certificate);
const char *ac_pki_issued_certificate_fingerprint_text(
    const struct ac_pki_issued_certificate *certificate);
int64_t ac_pki_issued_certificate_not_before(
    const struct ac_pki_issued_certificate *certificate);
int64_t ac_pki_issued_certificate_not_after(
    const struct ac_pki_issued_certificate *certificate);

struct json_object *ac_capabilities_json(void);
struct json_object *ac_status_json(void);
struct json_object *ac_write_disabled_json(const char *operation,
                                           const char *reason);
struct json_object *ac_pairing_token_create_json(int64_t ttl_seconds,
                                                  int max_attempts,
                                                  const char *site_id,
                                                  const char *hardware_digest);
struct json_object *ac_pairing_token_status_json(const char *token_id);
struct json_object *ac_pairing_token_list_json(void);
struct json_object *ac_pairing_token_revoke_json(const char *token_id);
struct json_object *ac_ap_update_json(const char *ap_id, const char *name,
                                      const char *model_override);
struct json_object *ac_pairing_token_redeem_json(const char *token_id,
                                                  const char *token,
                                                  const char *site_id,
                                                  const char *hardware_digest);
struct json_object *ac_radio_job_create_json(const char *ap_id,
                                             const char *radio_id,
                                             const char *mode,
                                             const char *idempotency_key);
struct json_object *ac_radio_job_status_json(const char *job_id);
struct json_object *ac_radio_job_list_json(const char *ap_id);
struct json_object *ac_radio_job_cancel_json(const char *job_id);
struct json_object *ac_radio_job_result_json(const char *job_id);
struct json_object *ac_radio_job_latest_results_json(void);

int ac_protocol_init(void);
void ac_protocol_close(void);
int ac_transport_start(void);
void ac_transport_stop(void);
int ac_transport_listening(void);
int ac_transport_port(void);
const char *ac_transport_controller_id(void);
const char *ac_transport_reason(void);

int ac_ubus_start(void);
void ac_ubus_stop(void);

#endif

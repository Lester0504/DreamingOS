// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_AC_TRANSPORT_FIXTURE_H
#define DREAMINGWRT_AC_TRANSPORT_FIXTURE_H

#include "ac_enrollment_fixture.h"

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <json-c/json.h>

#define AC_SERVICE_NAME "dreamingwrt-ac-test"
#define AC_CONTRACT_VERSION "ap-control.v1"
#define AC_TRANSPORT_DEFAULT_PORT 18443
#define AC_TRANSPORT_WORKERS_MAX 8
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

struct ac_device_model_report {
    char model[AC_DEVICE_MODEL_MAX + 1];
    char board_name[AC_DEVICE_BOARD_NAME_MAX + 1];
    char model_source[AC_DEVICE_MODEL_SOURCE_MAX + 1];
    char reason[AC_DEVICE_MODEL_REASON_MAX + 1];
    int model_available;
};

struct ac_pki;
struct ac_pki_issued_certificate;

extern char fixture_current_session_epoch[AC_RADIO_JOB_SESSION_EPOCH_MAX + 1];
void fixture_radio_jobs_reset(const char *session_epoch);

int ac_pki_init(struct ac_pki **out);
void ac_pki_free(struct ac_pki *pki);
const char *ac_pki_controller_id(const struct ac_pki *pki);
const unsigned char *ac_pki_ca_fingerprint_sha256(const struct ac_pki *pki);
X509 *ac_pki_ca_certificate_dup(const struct ac_pki *pki);
X509 *ac_pki_server_certificate_dup(const struct ac_pki *pki);
EVP_PKEY *ac_pki_server_private_key_dup(const struct ac_pki *pki);
int ac_pki_issue_ap_certificate(const struct ac_pki *pki, const char *ap_id,
    const unsigned char public_key[32], const unsigned char *csr_der,
    size_t csr_der_len, struct ac_pki_issued_certificate **out);
void ac_pki_issued_certificate_free(struct ac_pki_issued_certificate *value);
const unsigned char *ac_pki_issued_certificate_der(
    const struct ac_pki_issued_certificate *value, size_t *length);
const char *ac_pki_issued_certificate_serial(
    const struct ac_pki_issued_certificate *value);
const char *ac_pki_issued_certificate_issuer_key_id(
    const struct ac_pki_issued_certificate *value);
const unsigned char *ac_pki_issued_certificate_fingerprint_sha256(
    const struct ac_pki_issued_certificate *value);
int64_t ac_pki_issued_certificate_not_before(
    const struct ac_pki_issued_certificate *value);
int64_t ac_pki_issued_certificate_not_after(
    const struct ac_pki_issued_certificate *value);
int64_t ac_now_s(void);
int ac_db_enrollment_challenge_create(
    int64_t ttl, struct ac_enrollment_challenge *out);
int ac_enrollment_verify_and_claim(
    const struct ac_enrollment_signed_request *request,
    struct ac_enrollment_record *out);
int ac_db_enrollment_certificate_commit(
    const struct ac_enrollment_certificate *certificate,
    struct ac_enrollment_record *out);
int ac_db_enrollment_certificate_get(
    const char *enrollment_id, struct ac_enrollment_certificate *out,
    unsigned char **owned_der);
int ac_db_certificate_peer_authorize(const char *certificate_id,
    const char *ap_id, const unsigned char fingerprint[32], int active);
int ac_db_enrollment_activation_begin(const char *enrollment_id,
    const char *certificate_id, unsigned char challenge[32]);
int ac_db_enrollment_activate(const char *enrollment_id,
    const char *certificate_id, const unsigned char fingerprint[32],
    const unsigned char *challenge, size_t challenge_len,
    struct ac_enrollment_record *out);
int ac_db_ap_session_begin(const char *ap_id, const char *session_epoch,
                           int protocol_version, int64_t received_at);
int ac_db_ap_session_end(const char *ap_id, const char *session_epoch);
int ac_db_ap_heartbeat(const char *ap_id, const char *session_epoch,
                       int64_t received_at);
int ac_db_ap_identity_report(const char *ap_id,
                             const struct ac_device_model_report *report);
int ac_db_ap_telemetry_store(const char *ap_id, const char *session_epoch,
                             int64_t sequence,
                             int64_t observed_at, int64_t received_at,
                             const char *snapshot_id,
                             const struct ac_device_model_report *report,
                             struct json_object *snapshot);
int ac_db_ap_session_is_current(const char *ap_id, const char *session_epoch);
int ac_db_radio_job_status(const char *job_id, struct ac_radio_job *out);
int ac_db_radio_job_lease_next(const char *ap_id, const char *session_epoch,
                               int64_t now, struct ac_radio_job *out);
int ac_db_radio_job_mark_running(const char *job_id, const char *attempt_id,
                                 int64_t dispatch_generation,
                                 const char *request_digest, const char *ap_id,
                                 const char *session_epoch,
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

enum ac_config_job_result {
    AC_CONFIG_JOB_ERROR = -1,
    AC_CONFIG_JOB_OK = 0,
    AC_CONFIG_JOB_IDEMPOTENT = 1,
    AC_CONFIG_JOB_NOT_FOUND = 2,
    AC_CONFIG_JOB_CONFLICT = 3,
    AC_CONFIG_JOB_INVALID = 4,
};
#define AC_CONFIG_JOB_READBACK_MAX_BYTES (16 * 1024)
struct ac_config_job {
    char job_id[AC_RADIO_JOB_ID_LEN + 1];
    char ap_id[37];
    char state[17];
    char idempotency_key[129];
    char candidate_digest[72];
    int64_t created_at;
    int64_t updated_at;
    int64_t lease_expires_at;
    char session_epoch[65];
    char attempt_id[AC_RADIO_JOB_ID_LEN + 1];
    int64_t dispatch_generation;
    char request_digest[72];
    char finish_id[AC_RADIO_JOB_ID_LEN + 1];
    char outcome[15];
    char error_code[AC_RADIO_JOB_ERROR_MAX + 1];
};
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

#endif

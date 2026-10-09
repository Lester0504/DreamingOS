// SPDX-License-Identifier: GPL-2.0-or-later
#include "../wifi/wifi_failure_event.h"
#include "../ap_radio_id.h"
#include "../ap_mlo_members.h"
#define AC_ROAMING_PROBE_TTL_SECONDS 30
#ifdef AC_DB_TEST_STANDALONE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <json-c/json.h>
#include <sqlite3.h>
#include "ac_secrets.h"
#if defined(AC_DB_TELEMETRY_TEST_STANDALONE)
#define AC_DEVICE_MODEL_MAX 255
#define AC_DEVICE_BOARD_NAME_MAX 127
#define AC_DEVICE_MODEL_SOURCE_MAX 63
#define AC_DEVICE_MODEL_REASON_MAX 127
#define AC_CONTRACT_VERSION "ap-control.v1"
struct ac_device_model_report {
    char model[AC_DEVICE_MODEL_MAX + 1];
    char board_name[AC_DEVICE_BOARD_NAME_MAX + 1];
    char model_source[AC_DEVICE_MODEL_SOURCE_MAX + 1];
    char reason[AC_DEVICE_MODEL_REASON_MAX + 1];
    int model_available;
};
#endif
#define AC_CONFIG_DB_PATH "/etc/dreamingwrt/config.db"
#define AC_SCHEMA_VERSION 20
#define AC_ROAMING_DOMAIN_INVALID   (-1)
#define AC_ROAMING_DOMAIN_NOT_FOUND (-2)
#define AC_ROAMING_DOMAIN_CONFLICT  (-3)
#define AC_ROAMING_DOMAIN_DB_ERROR  (-4)
#ifndef AC_CONTRACT_VERSION
#define AC_CONTRACT_VERSION "ac-controller.v1"
#endif
#define AC_SERVICE_NAME "dreamingwrt-ac"
#define AC_AP_ONLINE_TIMEOUT_SECONDS 45
#define AC_TELEMETRY_STALE_TIMEOUT_SECONDS 360
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
#define AC_BINDING_ID_LEN 36
#define AC_BINDING_NONCE_LEN 16
#define AC_BINDING_TICKET_TTL     300
#define AC_BINDING_REQUEST_TTL    3600
#define AC_BINDING_NONCE_RETAIN   86400
#define AC_BINDING_OK              0
#define AC_BINDING_ERR_QR         (-1)
#define AC_BINDING_ERR_VERSION    (-2)
#define AC_BINDING_ERR_EXPIRED    (-3)
#define AC_BINDING_ERR_TICKET     (-4)
#define AC_BINDING_ERR_CONSUMED   (-5)
#define AC_BINDING_ERR_REPLAYED   (-6)
#define AC_BINDING_ERR_AP_NOT_FOUND   (-7)
#define AC_BINDING_ERR_AP_MISMATCH    (-8)
#define AC_BINDING_ERR_GW_NOT_FOUND   (-9)
#define AC_BINDING_ERR_GW_MISMATCH    (-10)
#define AC_BINDING_ERR_SITE_NOT_FOUND (-11)
#define AC_BINDING_ERR_AP_BOUND       (-12)
#define AC_BINDING_ERR_PERMISSION     (-13)
#define AC_BINDING_ERR_ENROLL_PENDING (-14)
#define AC_BINDING_ERR_NOT_FOUND      (-15)
#define AC_BINDING_ERR_NOT_CANCELLABLE (-16)
#define AC_BINDING_ERR_IDEMPOTENCY    (-17)
#define AC_BINDING_ERR_DB             (-18)
#define AC_ENROLLMENT_NONCE_LEN 32
#define AC_ENROLLMENT_CSR_MAX 8192
#define AC_ENROLLMENT_CERT_MAX 16384
#define AC_ENROLLMENT_CHALLENGE_TTL_MIN 30
#define AC_ENROLLMENT_CHALLENGE_TTL_MAX 300
#define AC_ENROLLMENT_CLAIM_TTL 600
#define AC_ENROLLMENT_ACTIVATION_TTL 300
#define AC_ENROLLMENT_ACTIVATION_ATTEMPTS 5
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
#define AC_SURVEY_SCHEDULE_MIN_INTERVAL 60
#define AC_SURVEY_SCHEDULE_MAX_INTERVAL 3600
#define AC_SURVEY_SCHEDULE_DEFAULT_INTERVAL 300
#define AC_SURVEY_SCHEDULE_INVALID_INTERVAL (-2)
#define AC_AP_UPDATE_INVALID (-1)
#define AC_AP_UPDATE_NOT_FOUND (-2)
#define AC_AP_UPDATE_DB_ERROR (-3)
struct ac_survey_schedule {
    int enabled;
    char mode[9];
    int interval_seconds;
    int64_t last_run_at;
    int last_dispatched;
    char last_error[64];
};
#ifndef AC_ENROLLMENT_FIXTURE_TYPES
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

#define AC_AP_UNBIND_REQUEST_ID_LEN 36
#define AC_AP_UNBIND_ERROR_MAX 127
#define AC_AP_UNBIND_OK 0
#define AC_AP_UNBIND_NOT_FOUND (-1)
#define AC_AP_UNBIND_NOT_ADOPTED (-2)
#define AC_AP_UNBIND_DB (-3)

struct ac_ap_unbind_request {
    char request_id[AC_AP_UNBIND_REQUEST_ID_LEN + 1];
    char ap_id[AC_ENROLLMENT_ID_LEN + 1];
    char certificate_id[AC_ENROLLMENT_ID_LEN + 1];
    char enrollment_id[AC_ENROLLMENT_ID_LEN + 1];
    char state[16];
    int64_t requested_at;
    int64_t acknowledged_at;
    char error_code[AC_AP_UNBIND_ERROR_MAX + 1];
};
#endif
#ifdef AC_DB_TEST_STANDALONE
enum ac_radio_job_result {
    AC_RADIO_JOB_ERROR = -1,
    AC_RADIO_JOB_OK = 0,
    AC_RADIO_JOB_IDEMPOTENT = 1,
    AC_RADIO_JOB_NOT_FOUND = 2,
    AC_RADIO_JOB_CONFLICT = 3,
    AC_RADIO_JOB_INVALID_TARGET = 4,
    AC_RADIO_JOB_UNAVAILABLE = 5,
};
struct ac_roaming_policy {
    int weak_rssi_dbm;
    int minimum_candidate_gain_db;
    int candidate_min_rssi_dbm;
    int decision_min_interval_sec;
    int post_roam_cooldown_sec;
    int max_btm_attempts_per_hour;
    int deauth_after_btm_failures;
    int deauth_cooldown_sec;
    int domain_action_rate_limit;
    int64_t revision;
    int64_t updated_at;
    char updated_by[65];
    int reassoc_block_enabled;
    int reassoc_block_sec;
    char reassoc_block_scope[6];
    char steering_preference[16];
    int high_band_steer_enabled;
    int force_disassoc_on_reject;
    int lower_band_block_enabled;
    int band_steer_mode;
    int band_steer_min_rssi_dbm;
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
    char operation[9];
    char rollback_of_job_id[AC_RADIO_JOB_ID_LEN + 1];
};
#define AC_WIFI_TX_TARGETS_MAX 32
#define AC_WIFI_TX_CANDIDATE_MAX_BYTES (16 * 1024)
/* Mirrors ac_internal.h, which carries the rationale. */
#define AC_WIFI_TX_BASE_REVISION_CURRENT ((int64_t)-1)
int ac_db_wifi_transaction_apply(const char *actor_id,
                                 const char *idempotency_key,
                                 const char *consistency,
                                 int64_t base_revision,
                                 const char *targets_json, int64_t now,
                                 char transaction_id_out[AC_RADIO_JOB_ID_LEN + 1],
                                 char *error_out, size_t error_len);
struct json_object *ac_db_wifi_transaction_status_json(
    const char *transaction_id);
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
/* Binding struct and forward declarations (defined later in this TU). */
struct ac_binding_request {
    char binding_id[AC_BINDING_ID_LEN + 1];
    char bootstrap_id[AC_ENROLLMENT_ID_LEN + 1];
    char key_fingerprint[AC_ENROLLMENT_KEY_ID_LEN + 1];
    char ticket_nonce[AC_BINDING_NONCE_LEN * 2 + 1];
    int64_t ticket_expires_at;
    int64_t ticket_consumed_at;
    char controller_id[AC_ENROLLMENT_ID_LEN + 1];
    char site_id[AC_PAIRING_SITE_ID_LEN + 1];
    char state[32];
    char enrollment_id[AC_ENROLLMENT_ID_LEN + 1];
    char pairing_token_id[AC_PAIRING_TOKEN_ID_LEN + 1];
    char idempotency_key[AC_BINDING_ID_LEN + 1];
    char client_info[256];
    char error_code[64];
    char failure_code[64];
    int64_t created_at;
    int64_t updated_at;
    int64_t expires_at;
};
int ac_db_binding_schema_init(void);
int ac_db_binding_get(const char *, struct ac_binding_request *);
int ac_db_binding_update_state(const char *, const char *, const char *,
                               const char *, const char *, const char *);
struct json_object *ac_db_roaming_policy_json(const char *domain_id);
#endif
void ac_db_close(void);
#else
#include "ac_internal.h"
#include "ac_certificate_lifecycle.h"
#include "ac_secret_rotation.h"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#endif

#ifndef O_NOFOLLOW
#error "dreamingwrt-ac requires O_NOFOLLOW for pairing token storage"
#endif

#if !defined(SQLITE_OPEN_NOFOLLOW) && !defined(AC_DB_TEST_STANDALONE)
#error "dreamingwrt-ac requires SQLITE_OPEN_NOFOLLOW for pairing token storage"
#endif

#define AC_PAIRING_DIGEST_VERSION 1
#define AC_PAIRING_DIGEST_LEN SHA256_DIGEST_LENGTH
#define AC_PAIRING_DOMAIN "dreamingwrt-ac-pairing-token-v1"

sqlite3 *g_ac_db;
#include "ac_client_history.c"
#ifndef AC_DB_TEST_STANDALONE
struct ubus_context *g_ac_ubus;
struct blob_buf g_ac_blob;
#endif
int64_t g_ac_started_at;

static int ac_uuid_valid(const char *value);
#ifdef AC_DB_TEST_STANDALONE
static int ac_db_secret_rotation_busy(const char *ssid_id)
{
    (void)ssid_id;
    return 0;
}
#else
static int ac_db_secret_rotation_busy(const char *ssid_id)
{
    return ac_secret_rotation_ssid_busy(ssid_id);
}
#endif
#ifdef AC_DB_TEST_STANDALONE
#define AC_DB_STANDALONE_UNUSED __attribute__((unused))
#else
#define AC_DB_STANDALONE_UNUSED
#endif
#if defined(AC_DB_TEST_STANDALONE) && \
    !defined(AC_DB_ROAMING_ACTIONS_TEST) && \
    !defined(AC_DB_WIFI_TRANSACTION_TEST)
static int AC_DB_STANDALONE_UNUSED
ac_wifi_tx_refresh_locked(const char *transaction_id, int64_t now)
{
    (void)transaction_id;
    (void)now;
    return 0;
}
#else
static int AC_DB_STANDALONE_UNUSED
ac_wifi_tx_refresh_locked(const char *transaction_id, int64_t now);
#endif
static int ac_generate_uuid(char out[AC_RADIO_JOB_ID_LEN + 1]);
static int ac_exec(const char *sql);
static int ac_radio_jobs_recover_after_restart(void);
static int ac_radio_jobs_prune_locked(int64_t now);
static int ac_db_radio_job_get(const char *job_id, struct ac_radio_job *out);
static int ac_site_id_normalize(const char *input,
                                char out[AC_PAIRING_SITE_ID_LEN + 1]);
static int ac_hardware_digest_normalize(
    const char *input, char out[AC_PAIRING_HARDWARE_DIGEST_LEN + 1]);

int64_t ac_now_s(void)
{
    return (int64_t)time(NULL);
}

const char *ac_db_path(void)
{
    const char *override = getenv("DREAMINGWRT_AC_DB_PATH");

    return override && override[0] ? override : AC_CONFIG_DB_PATH;
}

static int ac_path_parent(const char *path, char *out, size_t out_size)
{
    const char *slash = path ? strrchr(path, '/') : NULL;
    size_t len;

    if (!slash || slash == path || !out || out_size == 0)
        return -1;
    len = (size_t)(slash - path);
    if (len >= out_size)
        return -1;
    memcpy(out, path, len);
    out[len] = '\0';
    return 0;
}

static int ac_secure_owner(uid_t owner)
{
#ifdef AC_DB_TEST_STANDALONE
    return owner == geteuid();
#else
    return geteuid() == 0 && owner == 0;
#endif
}

static int ac_radio_job_mode_valid(const char *mode)
{
    return mode && (!strcmp(mode, "neighbor") || !strcmp(mode, "survey"));
}

static int ac_radio_job_idempotency_valid(const char *key)
{
    size_t i;
    size_t len = key ? strlen(key) : 0;

    if (len == 0 || len > AC_RADIO_JOB_IDEMPOTENCY_MAX)
        return 0;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)key[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' ||
              c == ':' || c == '-'))
            return 0;
    }
    return 1;
}

static int ac_radio_job_radio_id_valid(const char *radio_id)
{
    return dreamingwrt_ap_radio_id_valid(radio_id);
}

static int ac_radio_job_target_state(const char *ap_id, const char *radio_id,
                                     int64_t now)
{
    sqlite3_stmt *st = NULL;
    int result = AC_RADIO_JOB_INVALID_TARGET;

    if (!g_ac_db || !ac_uuid_valid(ap_id) ||
        !ac_radio_job_radio_id_valid(radio_id) || now <= 0 ||
        sqlite3_prepare_v2(g_ac_db,
            "SELECT COALESCE(ar.session_connected,0),"
            "COALESCE(ar.control_protocol_version,0),a.last_seen_at "
            "FROM ac_aps a JOIN ac_radio_runtime r ON r.ap_id=a.ap_id "
            "JOIN ac_ap_runtime ar ON ar.ap_id=a.ap_id "
            "AND r.radio_id=?2 WHERE a.ap_id=?1 AND a.adoption_state='adopted' "
            "AND r.stale=0 AND r.observed_at>0 LIMIT 1", -1, &st, NULL) != SQLITE_OK)
        return result;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, radio_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        result = sqlite3_column_int(st, 0) != 0 &&
                 sqlite3_column_int(st, 1) >= 2 &&
                 sqlite3_column_int64(st, 2) >=
                    now - AC_AP_ONLINE_TIMEOUT_SECONDS ?
                 AC_RADIO_JOB_OK : AC_RADIO_JOB_UNAVAILABLE;
    sqlite3_finalize(st);
    return result;
}

static void ac_radio_job_copy_text(char *out, size_t out_size,
                                   const unsigned char *value)
{
    if (!out || out_size == 0)
        return;
    snprintf(out, out_size, "%s", value ? (const char *)value : "");
}

static int ac_radio_job_digest_valid(const char *value)
{
    size_t i;

    if (!value || strlen(value) != AC_RADIO_JOB_RESULT_DIGEST_MAX ||
        strncmp(value, "sha256:", 7) != 0)
        return 0;
    for (i = 7; i < AC_RADIO_JOB_RESULT_DIGEST_MAX; i++)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f')))
            return 0;
    return 1;
}

static int ac_radio_job_sha256(const void *data, size_t data_len,
                               char out[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1])
{
    static const char hex[] = "0123456789abcdef";
    unsigned char digest[SHA256_DIGEST_LENGTH];
    size_t i;

    if ((!data && data_len) || !out || !SHA256(data, data_len, digest))
        return -1;
    memcpy(out, "sha256:", 7);
    for (i = 0; i < sizeof(digest); i++) {
        out[7 + i * 2] = hex[digest[i] >> 4];
        out[8 + i * 2] = hex[digest[i] & 0x0f];
    }
    out[AC_RADIO_JOB_RESULT_DIGEST_MAX] = '\0';
    OPENSSL_cleanse(digest, sizeof(digest));
    return 0;
}

static int ac_radio_job_request_digest(const char *job_id, const char *ap_id,
                                       const char *radio_id, const char *mode,
                                       const char *attempt_id,
                                       int64_t dispatch_generation,
                                       char out[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1])
{
    char input[512];
    int length;

    length = snprintf(input, sizeof(input),
        "ac-radio-job-request-v2\n%s\n%s\n%s\n%s\n%s\n%lld\n",
        job_id, ap_id, radio_id, mode, attempt_id,
        (long long)dispatch_generation);
    if (length < 0 || length >= (int)sizeof(input))
        return -1;
    return ac_radio_job_sha256(input, (size_t)length, out);
}

static int ac_radio_job_from_stmt(sqlite3_stmt *st, struct ac_radio_job *out)
{
    int state_valid;
    if (!st || !out || !sqlite3_column_text(st, 0) ||
        !sqlite3_column_text(st, 1) || !sqlite3_column_text(st, 2) ||
        !sqlite3_column_text(st, 3) || !sqlite3_column_text(st, 4))
        return -1;
    memset(out, 0, sizeof(*out));
    ac_radio_job_copy_text(out->job_id, sizeof(out->job_id), sqlite3_column_text(st, 0));
    ac_radio_job_copy_text(out->ap_id, sizeof(out->ap_id), sqlite3_column_text(st, 1));
    ac_radio_job_copy_text(out->radio_id, sizeof(out->radio_id), sqlite3_column_text(st, 2));
    ac_radio_job_copy_text(out->mode, sizeof(out->mode), sqlite3_column_text(st, 3));
    ac_radio_job_copy_text(out->state, sizeof(out->state), sqlite3_column_text(st, 4));
    ac_radio_job_copy_text(out->idempotency_key, sizeof(out->idempotency_key),
                           sqlite3_column_text(st, 5));
    out->created_at = sqlite3_column_int64(st, 6);
    out->updated_at = sqlite3_column_int64(st, 7);
    ac_radio_job_copy_text(out->lease_owner, sizeof(out->lease_owner),
                           sqlite3_column_text(st, 8));
    out->lease_expires_at = sqlite3_column_int64(st, 9);
    ac_radio_job_copy_text(out->session_epoch, sizeof(out->session_epoch),
                           sqlite3_column_text(st, 10));
    ac_radio_job_copy_text(out->attempt_id, sizeof(out->attempt_id),
                           sqlite3_column_text(st, 11));
    out->dispatch_generation = sqlite3_column_int64(st, 12);
    ac_radio_job_copy_text(out->request_digest, sizeof(out->request_digest),
                           sqlite3_column_text(st, 13));
    ac_radio_job_copy_text(out->finish_id, sizeof(out->finish_id),
                           sqlite3_column_text(st, 14));
    ac_radio_job_copy_text(out->finish_digest, sizeof(out->finish_digest),
                           sqlite3_column_text(st, 15));
    out->last_progress_at = sqlite3_column_int64(st, 16);
    out->reconcile_deadline = sqlite3_column_int64(st, 17);
    out->result_count = sqlite3_column_int(st, 18);
    out->result_bytes = sqlite3_column_int64(st, 19);
    ac_radio_job_copy_text(out->result_digest, sizeof(out->result_digest),
                           sqlite3_column_text(st, 20));
    out->result_complete = sqlite3_column_int(st, 21);
    ac_radio_job_copy_text(out->error_code, sizeof(out->error_code),
                           sqlite3_column_text(st, 22));
    ac_radio_job_copy_text(out->expected_impact, sizeof(out->expected_impact),
                           sqlite3_column_text(st, 23));
    state_valid = !strcmp(out->state, "queued") || !strcmp(out->state, "leased") ||
        !strcmp(out->state, "running") || !strcmp(out->state, "cancel_requested") ||
        !strcmp(out->state, "completed") || !strcmp(out->state, "failed") ||
        !strcmp(out->state, "cancelled") || !strcmp(out->state, "expired");
    return ac_uuid_valid(out->job_id) && ac_uuid_valid(out->ap_id) && state_valid &&
        ac_radio_job_radio_id_valid(out->radio_id) &&
        ac_radio_job_mode_valid(out->mode) && out->created_at > 0 &&
        out->updated_at >= out->created_at && out->result_count >= 0 &&
        out->result_bytes >= 0 && out->dispatch_generation >= 0 &&
        out->last_progress_at >= 0 && out->reconcile_deadline >= 0 &&
        (!out->attempt_id[0] || ac_uuid_valid(out->attempt_id)) &&
        (!out->request_digest[0] || ac_radio_job_digest_valid(out->request_digest)) &&
        (!out->finish_id[0] || ac_uuid_valid(out->finish_id)) &&
        (!out->finish_digest[0] || ac_radio_job_digest_valid(out->finish_digest)) &&
        (out->dispatch_generation == 0 || (out->attempt_id[0] &&
                                           out->request_digest[0])) &&
        out->result_count <= AC_RADIO_JOB_RESULT_ITEMS_MAX &&
        out->result_bytes <= AC_RADIO_JOB_RESULT_JSON_MAX &&
        (out->result_complete == 0 ||
                                   out->result_complete == 1) ? 0 : -1;
}

static const char ac_radio_job_select[] =
    "SELECT job_id,ap_id,radio_id,mode,state,idempotency_key,created_at,updated_at,"
    "lease_owner,lease_expires_at,session_epoch,attempt_id,dispatch_generation,"
    "request_digest,finish_id,finish_digest,last_progress_at,reconcile_deadline,"
    "result_count,result_bytes,result_digest,result_complete,error_code,expected_impact "
    "FROM ac_radio_jobs";

int ac_db_radio_job_create(const char *ap_id, const char *radio_id,
                           const char *mode, const char *idempotency_key,
                           struct ac_radio_job *out)
{
    sqlite3_stmt *st = NULL;
    char job_id[AC_RADIO_JOB_ID_LEN + 1];
    const char *impact;
    int target_result;
    int rc = AC_RADIO_JOB_ERROR;
    int64_t now = ac_now_s();

    if (!g_ac_db || !out || !ac_uuid_valid(ap_id) ||
        !ac_radio_job_radio_id_valid(radio_id) || !ac_radio_job_mode_valid(mode) ||
        !ac_radio_job_idempotency_valid(idempotency_key))
        return AC_RADIO_JOB_INVALID_TARGET;
    if (ac_exec("BEGIN IMMEDIATE") != 0)
        return AC_RADIO_JOB_ERROR;
    if (ac_radio_jobs_prune_locked(now) < 0)
        goto rollback;
    if (sqlite3_prepare_v2(g_ac_db, ac_radio_job_select,
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    {
        char sql[sizeof(ac_radio_job_select) + 64];
        sqlite3_finalize(st);
        st = NULL;
        if (snprintf(sql, sizeof(sql), "%s WHERE ap_id=?1 AND idempotency_key=?2",
                     ac_radio_job_select) >= (int)sizeof(sql) ||
            sqlite3_prepare_v2(g_ac_db, sql, -1, &st, NULL) != SQLITE_OK)
            goto rollback;
        sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, idempotency_key, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            if (ac_radio_job_from_stmt(st, out) != 0)
                goto rollback;
            rc = (!strcmp(out->radio_id, radio_id) && !strcmp(out->mode, mode)) ?
                AC_RADIO_JOB_IDEMPOTENT : AC_RADIO_JOB_CONFLICT;
            sqlite3_finalize(st);
            st = NULL;
            if (ac_exec("COMMIT") != 0)
                return AC_RADIO_JOB_ERROR;
            return rc;
        }
    }
    target_result = ac_radio_job_target_state(ap_id, radio_id, now);
    if (target_result != AC_RADIO_JOB_OK)
        goto target_unavailable;
    sqlite3_finalize(st);
    st = NULL;
    if (ac_generate_uuid(job_id) != 0)
        goto rollback;
    impact = !strcmp(mode, "neighbor") ?
        "radio_may_leave_working_channel" : "survey_channel_dwell_only";
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_radio_jobs(job_id,ap_id,radio_id,mode,state,idempotency_key,"
            "created_at,updated_at,expected_impact) VALUES(?1,?2,?3,?4,'queued',?5,?6,?6,?7)",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, job_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, radio_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, mode, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, idempotency_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, now);
    sqlite3_bind_text(st, 7, impact, -1, SQLITE_STATIC);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    {
        char sql[sizeof(ac_radio_job_select) + 32];
        if (snprintf(sql, sizeof(sql), "%s WHERE job_id=?1", ac_radio_job_select) >=
                (int)sizeof(sql) || sqlite3_prepare_v2(g_ac_db, sql, -1, &st, NULL) != SQLITE_OK)
            goto rollback;
        sqlite3_bind_text(st, 1, job_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_ROW || ac_radio_job_from_stmt(st, out) != 0)
            goto rollback;
    }
    sqlite3_finalize(st);
    if (ac_exec("COMMIT") != 0)
        return AC_RADIO_JOB_ERROR;
    return AC_RADIO_JOB_OK;
rollback:
    sqlite3_finalize(st);
    ac_exec("ROLLBACK");
    return AC_RADIO_JOB_ERROR;
target_unavailable:
    ac_exec("ROLLBACK");
    return target_result;
}

static int ac_db_radio_job_get(const char *job_id, struct ac_radio_job *out)
{
    sqlite3_stmt *st = NULL;
    char sql[sizeof(ac_radio_job_select) + 32];
    int rc = -1;

    if (!g_ac_db || !out || !ac_uuid_valid(job_id) ||
        snprintf(sql, sizeof(sql), "%s WHERE job_id=?1", ac_radio_job_select) >=
            (int)sizeof(sql) || sqlite3_prepare_v2(g_ac_db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, job_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        rc = ac_radio_job_from_stmt(st, out);
    sqlite3_finalize(st);
    return rc;
}

int ac_db_radio_job_status(const char *job_id, struct ac_radio_job *out)
{
    return ac_db_radio_job_get(job_id, out) == 0 ? AC_RADIO_JOB_OK :
           AC_RADIO_JOB_NOT_FOUND;
}

int ac_db_radio_job_result_metadata(const char *job_id, struct ac_radio_job *out)
{
    return ac_db_radio_job_status(job_id, out);
}

/* ── Periodic survey schedule ─────────────────────────────────────────────
 * Survey mode only. See the ac_survey_schedule DDL for why neighbour scans are
 * deliberately excluded from periodic dispatch.
 */
int ac_db_survey_schedule_load(struct ac_survey_schedule *out)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    out->interval_seconds = AC_SURVEY_SCHEDULE_DEFAULT_INTERVAL;
    snprintf(out->mode, sizeof(out->mode), "%s", "survey");
    if (!g_ac_db)
        return -1;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT enabled,mode,interval_seconds,last_run_at,last_dispatched,"
            "last_error FROM ac_survey_schedule WHERE id=1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        out->enabled = sqlite3_column_int(st, 0) ? 1 : 0;
        ac_radio_job_copy_text(out->mode, sizeof(out->mode),
                               sqlite3_column_text(st, 1));
        out->interval_seconds = sqlite3_column_int(st, 2);
        out->last_run_at = sqlite3_column_int64(st, 3);
        out->last_dispatched = sqlite3_column_int(st, 4);
        ac_radio_job_copy_text(out->last_error, sizeof(out->last_error),
                               sqlite3_column_text(st, 5));
        rc = 0;
    }
    sqlite3_finalize(st);
    if (out->interval_seconds < AC_SURVEY_SCHEDULE_MIN_INTERVAL ||
        out->interval_seconds > AC_SURVEY_SCHEDULE_MAX_INTERVAL)
        out->interval_seconds = AC_SURVEY_SCHEDULE_DEFAULT_INTERVAL;
    /* Only survey may be scheduled; a row saying otherwise is not honoured. */
    if (strcmp(out->mode, "survey"))
        snprintf(out->mode, sizeof(out->mode), "%s", "survey");
    return rc;
}

int ac_db_survey_schedule_save(int enabled, int interval_seconds)
{
    sqlite3_stmt *st = NULL;
    int rc;

    if (!g_ac_db)
        return -1;
    if (interval_seconds > 0 &&
        (interval_seconds < AC_SURVEY_SCHEDULE_MIN_INTERVAL ||
         interval_seconds > AC_SURVEY_SCHEDULE_MAX_INTERVAL))
        return AC_SURVEY_SCHEDULE_INVALID_INTERVAL;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_survey_schedule SET "
            "enabled=CASE WHEN ?1<0 THEN enabled ELSE ?1 END,"
            "interval_seconds=CASE WHEN ?2<=0 THEN interval_seconds ELSE ?2 END,"
            "updated_at=?3 WHERE id=1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(st, 1, enabled);
    sqlite3_bind_int(st, 2, interval_seconds);
    sqlite3_bind_int64(st, 3, ac_now_s());
    rc = sqlite3_step(st) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(st);
    return rc;
}

static void ac_db_survey_schedule_record(int64_t now, int dispatched,
                                         const char *error)
{
    sqlite3_stmt *st = NULL;

    if (!g_ac_db || sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_survey_schedule SET last_run_at=?1,last_dispatched=?2,"
            "last_error=?3 WHERE id=1", -1, &st, NULL) != SQLITE_OK)
        return;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_int(st, 2, dispatched);
    sqlite3_bind_text(st, 3, error ? error : "", -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

/*
 * Create one survey job per eligible radio.
 *
 * "Eligible" is decided by the same conditions ac_radio_job_create() enforces
 * (adopted AP, live v2 session, non-stale radio runtime), so the scheduler
 * cannot manufacture jobs the manual path would refuse. Radios that are not
 * ready are skipped quietly: an AP being offline is a normal state, not a
 * scheduling error.
 *
 * The idempotency key is derived from the interval bucket, so a restart or an
 * overlapping tick inside the same window reuses the existing job instead of
 * queueing a second one for the same radio.
 */
int ac_db_survey_schedule_tick(int64_t now, int *dispatched_out)
{
    struct ac_survey_schedule schedule;
    sqlite3_stmt *st = NULL;
    int dispatched = 0, skipped = 0;
    int64_t bucket;

    if (dispatched_out)
        *dispatched_out = 0;
    if (ac_db_survey_schedule_load(&schedule) != 0 || !schedule.enabled)
        return 0;
    if (schedule.last_run_at > 0 &&
        now - schedule.last_run_at < schedule.interval_seconds)
        return 0;
    if (!g_ac_db)
        return -1;
    bucket = now / schedule.interval_seconds;

    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT r.ap_id,r.radio_id FROM ac_radio_runtime r "
            "JOIN ac_aps a ON a.ap_id=r.ap_id "
            "JOIN ac_ap_runtime ar ON ar.ap_id=r.ap_id "
            "WHERE a.adoption_state='adopted' AND r.stale=0 AND r.observed_at>0 "
            "AND COALESCE(ar.session_connected,0)<>0 "
            "AND COALESCE(ar.control_protocol_version,0)>=2 "
            "AND a.last_seen_at>=?1 ORDER BY r.ap_id,r.radio_id",
            -1, &st, NULL) != SQLITE_OK) {
        ac_db_survey_schedule_record(now, 0, "radio_enumeration_failed");
        return -1;
    }
    sqlite3_bind_int64(st, 1, now - AC_AP_ONLINE_TIMEOUT_SECONDS);
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct ac_radio_job job;
        char ap_id[AC_ENROLLMENT_ID_LEN + 1] = "";
        char radio_id[AC_RADIO_JOB_RADIO_ID_MAX + 1] = "";
        char key[AC_RADIO_JOB_IDEMPOTENCY_MAX + 1];
        int rc;

        ac_radio_job_copy_text(ap_id, sizeof(ap_id), sqlite3_column_text(st, 0));
        ac_radio_job_copy_text(radio_id, sizeof(radio_id),
                               sqlite3_column_text(st, 1));
        if (snprintf(key, sizeof(key), "sched.survey.%lld.%s",
                     (long long)bucket, radio_id) >= (int)sizeof(key))
            continue;
        memset(&job, 0, sizeof(job));
        rc = ac_db_radio_job_create(ap_id, radio_id, "survey", key, &job);
        if (rc == AC_RADIO_JOB_OK)
            dispatched++;
        else if (rc != AC_RADIO_JOB_IDEMPOTENT)
            skipped++;
    }
    sqlite3_finalize(st);
    ac_db_survey_schedule_record(now, dispatched,
                                 dispatched == 0 ?
                                     (skipped > 0 ? "no_eligible_radio" :
                                      "no_candidate_radio") : "");
    if (dispatched_out)
        *dispatched_out = dispatched;
    return 0;
}

static int ac_radio_job_binding_valid(const char *ap_id,
                                      const char *session_epoch)
{
    size_t length;

    if (!ac_uuid_valid(ap_id) || !session_epoch)
        return 0;
    length = strlen(session_epoch);
    if (length != AC_RADIO_JOB_SESSION_EPOCH_MAX)
        return 0;
    for (size_t i = 0; i < length; i++)
        if (!((session_epoch[i] >= '0' && session_epoch[i] <= '9') ||
              (session_epoch[i] >= 'a' && session_epoch[i] <= 'f')))
            return 0;
    return 1;
}

static int ac_db_ap_session_is_current_locked(const char *ap_id,
                                              const char *session_epoch)
{
    sqlite3_stmt *st = NULL;
    int current = 0;

    if (!g_ac_db || !ac_radio_job_binding_valid(ap_id, session_epoch) ||
        sqlite3_prepare_v2(g_ac_db,
            "SELECT 1 FROM ac_ap_runtime r JOIN ac_aps a ON a.ap_id=r.ap_id "
            "WHERE r.ap_id=?1 AND r.boot_id=?2 AND r.session_connected=1 "
            "AND a.adoption_state='adopted' LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, session_epoch, -1, SQLITE_TRANSIENT);
    current = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return current;
}

static int AC_DB_STANDALONE_UNUSED ac_db_ap_write_session_is_current_locked(
    const char *ap_id, const char *session_epoch)
{
    sqlite3_stmt *st = NULL;
    int current = 0;

    if (!g_ac_db || !ac_radio_job_binding_valid(ap_id, session_epoch) ||
        sqlite3_prepare_v2(g_ac_db,
            "SELECT 1 FROM ac_ap_runtime r JOIN ac_aps a ON a.ap_id=r.ap_id "
            "WHERE r.ap_id=?1 AND r.boot_id=?2 AND r.session_connected=1 "
            "AND r.control_protocol_version=3 AND r.write_capable=1 "
            "AND a.adoption_state='adopted' LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, session_epoch, -1, SQLITE_TRANSIENT);
    current = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return current;
}

int ac_db_ap_session_is_current(const char *ap_id, const char *session_epoch)
{
    return ac_db_ap_session_is_current_locked(ap_id, session_epoch);
}

static int ac_radio_job_execution_matches(const struct ac_radio_job *job,
                                          const char *job_id,
                                          const char *attempt_id,
                                          int64_t dispatch_generation,
                                          const char *request_digest,
                                          const char *ap_id)
{
    return job && ac_uuid_valid(job_id) && ac_uuid_valid(attempt_id) &&
        dispatch_generation > 0 && ac_radio_job_digest_valid(request_digest) &&
        ac_uuid_valid(ap_id) && !strcmp(job->job_id, job_id) &&
        !strcmp(job->attempt_id, attempt_id) &&
        job->dispatch_generation == dispatch_generation &&
        !strcmp(job->request_digest, request_digest) &&
        !strcmp(job->ap_id, ap_id);
}

static int ac_radio_job_execution_identity_valid(const char *job_id,
                                                 const char *attempt_id,
                                                 int64_t dispatch_generation,
                                                 const char *request_digest,
                                                 const char *ap_id)
{
    return ac_uuid_valid(job_id) && ac_uuid_valid(attempt_id) &&
        dispatch_generation > 0 && ac_radio_job_digest_valid(request_digest) &&
        ac_uuid_valid(ap_id);
}

static int ac_radio_job_reconcile_expired_locked(int64_t now)
{
    sqlite3_stmt *st = NULL;
    int changed = -1;

    if (now <= 0 || sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_radio_jobs SET state='failed',updated_at=?1,lease_owner='',"
            "lease_expires_at=0,result_complete=0,error_code=CASE state "
            "WHEN 'leased' THEN 'delivery_unknown' WHEN 'running' THEN "
            "'execution_unknown' ELSE 'cancellation_unknown' END "
            "WHERE state IN ('leased','running','cancel_requested') "
            "AND reconcile_deadline>0 AND reconcile_deadline<=?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, now);
    if (sqlite3_step(st) == SQLITE_DONE)
        changed = sqlite3_changes(g_ac_db);
    sqlite3_finalize(st);
    return changed;
}

int ac_db_radio_jobs_reconcile_expired(int64_t now)
{
    int changed;

    if (!g_ac_db || now <= 0 || ac_exec("BEGIN IMMEDIATE") != 0)
        return AC_RADIO_JOB_ERROR;
    changed = ac_radio_job_reconcile_expired_locked(now);
    if (changed < 0 || ac_exec("COMMIT") != 0) {
        ac_exec("ROLLBACK");
        return AC_RADIO_JOB_ERROR;
    }
    return changed;
}

int ac_db_radio_job_lease_next(const char *ap_id, const char *session_epoch,
                               int64_t now, struct ac_radio_job *out)
{
    sqlite3_stmt *st = NULL;
    char job_id[AC_RADIO_JOB_ID_LEN + 1] = { 0 };
    char radio_id[AC_RADIO_JOB_RADIO_ID_MAX + 1] = { 0 };
    char mode[9] = { 0 };
    char attempt_id[AC_RADIO_JOB_ID_LEN + 1] = { 0 };
    char request_digest[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1] = { 0 };
    int64_t dispatch_generation = 0;

    if (!g_ac_db || !out || now <= 0 ||
        !ac_radio_job_binding_valid(ap_id, session_epoch))
        return AC_RADIO_JOB_INVALID_TARGET;
    if (ac_exec("BEGIN IMMEDIATE") != 0)
        return AC_RADIO_JOB_ERROR;
    if (!ac_db_ap_session_is_current_locked(ap_id, session_epoch) ||
        ac_radio_job_reconcile_expired_locked(now) < 0)
        goto rollback;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT q.job_id,q.radio_id,q.mode,q.dispatch_generation "
            "FROM ac_radio_jobs q WHERE q.ap_id=?1 AND q.state='queued' "
            "AND NOT EXISTS (SELECT 1 FROM ac_radio_jobs a WHERE a.ap_id=q.ap_id "
            "AND a.radio_id=q.radio_id AND a.state IN ('leased','running','cancel_requested')) "
            "ORDER BY q.created_at,q.job_id LIMIT 1", -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        st = NULL;
        if (ac_exec("COMMIT") != 0)
            return AC_RADIO_JOB_ERROR;
        return AC_RADIO_JOB_NOT_FOUND;
    }
    ac_radio_job_copy_text(job_id, sizeof(job_id), sqlite3_column_text(st, 0));
    ac_radio_job_copy_text(radio_id, sizeof(radio_id), sqlite3_column_text(st, 1));
    ac_radio_job_copy_text(mode, sizeof(mode), sqlite3_column_text(st, 2));
    dispatch_generation = sqlite3_column_int64(st, 3) + 1;
    sqlite3_finalize(st);
    st = NULL;
    if (!ac_uuid_valid(job_id) || !ac_radio_job_radio_id_valid(radio_id) ||
        !ac_radio_job_mode_valid(mode) || dispatch_generation <= 0 ||
        ac_generate_uuid(attempt_id) != 0 ||
        ac_radio_job_request_digest(job_id, ap_id, radio_id, mode, attempt_id,
                                    dispatch_generation, request_digest) != 0 ||
        sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_radio_jobs SET state='leased',updated_at=?1,lease_owner=?2,"
            "lease_expires_at=?3,session_epoch=?4,attempt_id=?5,"
            "dispatch_generation=?6,request_digest=?7,finish_id='',finish_digest='',"
            "last_progress_at=?1,reconcile_deadline=?3,error_code='' "
            "WHERE job_id=?8 AND state='queued'", -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, now + AC_RADIO_JOB_LEASE_SECONDS);
    sqlite3_bind_text(st, 4, session_epoch, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, attempt_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, dispatch_generation);
    sqlite3_bind_text(st, 7, request_digest, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, job_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (ac_db_radio_job_get(job_id, out) != 0 || ac_exec("COMMIT") != 0)
        goto rollback;
    return AC_RADIO_JOB_OK;
rollback:
    sqlite3_finalize(st);
    ac_exec("ROLLBACK");
    return AC_RADIO_JOB_ERROR;
}

int ac_db_radio_job_mark_running(const char *job_id, const char *attempt_id,
                                 int64_t dispatch_generation,
                                 const char *request_digest, const char *ap_id,
                                 const char *session_epoch,
                                 struct ac_radio_job *out)
{
    sqlite3_stmt *st = NULL;
    struct ac_radio_job existing;
    int64_t now = ac_now_s();
    int64_t lease_deadline;
    int result = AC_RADIO_JOB_CONFLICT;

    if (!g_ac_db || !out || !ac_radio_job_execution_identity_valid(
            job_id, attempt_id, dispatch_generation, request_digest, ap_id) ||
        !ac_radio_job_binding_valid(ap_id, session_epoch) ||
        ac_exec("BEGIN IMMEDIATE") != 0)
        return AC_RADIO_JOB_INVALID_TARGET;
    lease_deadline = now + AC_RADIO_JOB_LEASE_SECONDS;
    if (!ac_db_ap_session_is_current_locked(ap_id, session_epoch) ||
        ac_db_radio_job_get(job_id, &existing) != 0 ||
        !ac_radio_job_execution_matches(&existing, job_id, attempt_id,
            dispatch_generation, request_digest, ap_id) ||
        (!existing.finish_id[0] &&
         strcmp(existing.session_epoch, session_epoch)) ||
        strcmp(existing.lease_owner, ap_id))
        goto rollback;
    if (!strcmp(existing.state, "running")) {
        *out = existing;
        result = AC_RADIO_JOB_IDEMPOTENT;
        goto commit;
    }
    if (strcmp(existing.state, "leased"))
        goto rollback;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_radio_jobs SET state='running',updated_at=?1,"
            "lease_expires_at=?2,last_progress_at=?1,reconcile_deadline=?2 "
            "WHERE job_id=?3 AND attempt_id=?4 AND dispatch_generation=?5 "
            "AND request_digest=?6 AND ap_id=?7 AND lease_owner=?7 "
            "AND session_epoch=?8 AND state='leased'",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_int64(st, 2, lease_deadline);
    sqlite3_bind_text(st, 3, job_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, attempt_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 5, dispatch_generation);
    sqlite3_bind_text(st, 6, request_digest, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, session_epoch, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (ac_db_radio_job_get(job_id, out) != 0)
        goto rollback;
    result = AC_RADIO_JOB_OK;
commit:
    if (ac_exec("COMMIT") != 0)
        return AC_RADIO_JOB_ERROR;
    return result;
rollback:
    sqlite3_finalize(st);
    ac_exec("ROLLBACK");
    return AC_RADIO_JOB_CONFLICT;
}

static int ac_radio_job_mac_valid(const char *value)
{
    size_t i;

    if (!value || strlen(value) != 17)
        return 0;
    for (i = 0; i < 17; i++) {
        if ((i + 1) % 3 == 0) {
            if (value[i] != ':')
                return 0;
        } else if (!((value[i] >= '0' && value[i] <= '9') ||
                     (value[i] >= 'a' && value[i] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static int ac_radio_job_json_scalar(struct json_object *value)
{
    enum json_type type = value ? json_object_get_type(value) : json_type_null;

    return type == json_type_null || type == json_type_boolean ||
        type == json_type_double || type == json_type_int ||
        (type == json_type_string && json_object_get_string_len(value) <= 512);
}

static int ac_radio_job_item_valid(struct json_object *item, const char *mode)
{
    struct json_object *value = NULL;
    int fields = 0;

    if (!item || !json_object_is_type(item, json_type_object))
        return 0;
    json_object_object_foreach(item, key, child) {
        size_t array_length;

        if (++fields > 32 || !key || strlen(key) == 0 || strlen(key) > 63)
            return 0;
        if (ac_radio_job_json_scalar(child))
            continue;
        if (!json_object_is_type(child, json_type_array) ||
            (array_length = json_object_array_length(child)) > 32)
            return 0;
        for (size_t i = 0; i < array_length; i++)
            if (!ac_radio_job_json_scalar(json_object_array_get_idx(child, i)))
                return 0;
    }
    if (!strcmp(mode, "neighbor")) {
        return json_object_object_get_ex(item, "bssid", &value) && value &&
            json_object_is_type(value, json_type_string) &&
            ac_radio_job_mac_valid(json_object_get_string(value));
    }
    if (!json_object_object_get_ex(item, "frequency_mhz", &value) || !value ||
        !json_object_is_type(value, json_type_int) ||
        json_object_get_int(value) < 2300 || json_object_get_int(value) > 7200)
        return 0;
    return 1;
}

static int ac_radio_job_result_validate(const char *result_json,
                                        const char *mode, int *count_out,
                                        int64_t *bytes_out,
                                        char digest_out[
                                            AC_RADIO_JOB_RESULT_DIGEST_MAX + 1])
{
    struct json_tokener *tokener = NULL;
    struct json_object *root = NULL;
    enum json_tokener_error error;
    size_t payload_len = result_json ? strlen(result_json) : 0;
    size_t count;
    int rc = -1;

    if (!count_out || !bytes_out || !digest_out || payload_len == 0 ||
        payload_len > AC_RADIO_JOB_RESULT_JSON_MAX ||
        !(tokener = json_tokener_new()))
        return -1;
    json_tokener_set_flags(tokener, JSON_TOKENER_STRICT);
    root = json_tokener_parse_ex(tokener, result_json, (int)payload_len);
    error = json_tokener_get_error(tokener);
    if (error != json_tokener_success ||
        json_tokener_get_parse_end(tokener) != payload_len || !root ||
        !json_object_is_type(root, json_type_array) ||
        (count = json_object_array_length(root)) > AC_RADIO_JOB_RESULT_ITEMS_MAX)
        goto done;
    for (size_t i = 0; i < count; i++)
        if (!ac_radio_job_item_valid(json_object_array_get_idx(root, i), mode))
            goto done;
    if (ac_radio_job_sha256(result_json, payload_len, digest_out) != 0)
        goto done;
    *count_out = (int)count;
    *bytes_out = (int64_t)payload_len;
    rc = 0;
done:
    json_object_put(root);
    json_tokener_free(tokener);
    return rc;
}

static int ac_radio_job_finish_digest(const char *outcome,
                                      int result_truncated,
                                      const char *error_code,
                                      const char *result_digest,
                                      char out[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1])
{
    char input[512];
    int length = snprintf(input, sizeof(input),
        "ac-radio-job-finish-v2\n%s\n%d\n%s\n%s\n", outcome,
        result_truncated, error_code, result_digest);

    if (length < 0 || length >= (int)sizeof(input))
        return -1;
    return ac_radio_job_sha256(input, (size_t)length, out);
}

int ac_db_radio_job_progress(const char *job_id, const char *attempt_id,
                             int64_t dispatch_generation,
                             const char *request_digest, const char *ap_id,
                             const char *session_epoch, int64_t now,
                             struct ac_radio_job *out)
{
    sqlite3_stmt *st = NULL;
    struct ac_radio_job existing;

    if (!g_ac_db || !out || now <= 0 ||
        !ac_radio_job_execution_identity_valid(job_id, attempt_id,
            dispatch_generation, request_digest, ap_id) ||
        !ac_radio_job_binding_valid(ap_id, session_epoch) ||
        ac_exec("BEGIN IMMEDIATE") != 0)
        return AC_RADIO_JOB_INVALID_TARGET;
    if (!ac_db_ap_session_is_current_locked(ap_id, session_epoch) ||
        ac_db_radio_job_get(job_id, &existing) != 0 ||
        !ac_radio_job_execution_matches(&existing, job_id, attempt_id,
            dispatch_generation, request_digest, ap_id) ||
        strcmp(existing.session_epoch, session_epoch) ||
        strcmp(existing.lease_owner, ap_id) ||
        (strcmp(existing.state, "running") &&
         strcmp(existing.state, "cancel_requested")))
        goto conflict;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_radio_jobs SET updated_at=?1,last_progress_at=?1,"
            "lease_expires_at=?2,reconcile_deadline=?2 WHERE job_id=?3",
            -1, &st, NULL) != SQLITE_OK)
        goto error;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_int64(st, 2, now + AC_RADIO_JOB_LEASE_SECONDS);
    sqlite3_bind_text(st, 3, job_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto error;
    sqlite3_finalize(st);
    st = NULL;
    if (ac_db_radio_job_get(job_id, out) != 0 || ac_exec("COMMIT") != 0)
        goto error_no_transaction;
    return AC_RADIO_JOB_OK;
conflict:
    ac_exec("ROLLBACK");
    return AC_RADIO_JOB_CONFLICT;
error:
    sqlite3_finalize(st);
    ac_exec("ROLLBACK");
error_no_transaction:
    return AC_RADIO_JOB_ERROR;
}

int ac_db_radio_job_finish(const char *job_id, const char *attempt_id,
                           int64_t dispatch_generation,
                           const char *request_digest, const char *ap_id,
                           const char *session_epoch, const char *finish_id,
                           const char *outcome, const char *error_code,
                           const char *result_json, int result_truncated,
                           struct ac_radio_job *out)
{
    sqlite3_stmt *st = NULL;
    struct ac_radio_job existing;
    char result_digest[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1];
    char finish_digest[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1];
    int result_count;
    int64_t result_bytes;
    int64_t now = ac_now_s();
    int rc = AC_RADIO_JOB_CONFLICT;

    if (!g_ac_db || !out || !ac_uuid_valid(finish_id) ||
        !ac_radio_job_execution_identity_valid(job_id, attempt_id,
            dispatch_generation, request_digest, ap_id) ||
        !ac_radio_job_binding_valid(ap_id, session_epoch) ||
        !outcome || (strcmp(outcome, "completed") &&
                     strcmp(outcome, "failed") &&
                     strcmp(outcome, "cancelled")) ||
        (result_truncated != 0 && result_truncated != 1) ||
        !error_code || strlen(error_code) > AC_RADIO_JOB_ERROR_MAX ||
        (!strcmp(outcome, "completed") ? error_code[0] != '\0' :
                                         error_code[0] == '\0') ||
        ac_exec("BEGIN IMMEDIATE") != 0)
        return AC_RADIO_JOB_INVALID_TARGET;
    if (!ac_db_ap_session_is_current_locked(ap_id, session_epoch) ||
        ac_db_radio_job_get(job_id, &existing) != 0 ||
        !ac_radio_job_execution_matches(&existing, job_id, attempt_id,
            dispatch_generation, request_digest, ap_id) ||
        ac_radio_job_result_validate(result_json, existing.mode, &result_count,
            &result_bytes, result_digest) != 0 ||
        ac_radio_job_finish_digest(outcome, result_truncated, error_code,
                                   result_digest, finish_digest) != 0)
        goto rollback;
    if (existing.finish_id[0]) {
        if (!strcmp(existing.finish_id, finish_id) &&
            !strcmp(existing.finish_digest, finish_digest)) {
            *out = existing;
            rc = AC_RADIO_JOB_IDEMPOTENT;
        }
        goto commit;
    }
    if (strcmp(existing.session_epoch, session_epoch))
        goto rollback;
    if (strcmp(existing.state, "running") &&
        strcmp(existing.state, "cancel_requested") &&
        strcmp(existing.state, outcome))
        goto rollback;
    if (!strcmp(existing.state, outcome) &&
        strcmp(existing.error_code, error_code))
        goto rollback;
    if (!strcmp(outcome, "cancelled") &&
        strcmp(existing.state, "cancel_requested"))
        goto rollback;
    if (strcmp(existing.lease_owner, ap_id))
        goto rollback;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_radio_jobs SET state=?1,updated_at=?2,lease_owner='',lease_expires_at=0,"
            "finish_id=?3,finish_digest=?4,last_progress_at=?2,reconcile_deadline=0,"
            "result_count=?5,result_bytes=?6,result_digest=?7,"
            "result_complete=CASE WHEN ?1 IN ('completed','cancelled') "
            "AND ?8=0 THEN 1 ELSE 0 END,"
            "error_code=?9,result_json=?10 WHERE job_id=?11 AND attempt_id=?12 "
            "AND dispatch_generation=?13 AND request_digest=?14 AND ap_id=?15 "
            "AND session_epoch=?16 AND (state IN ('running','cancel_requested') "
            "OR (state=?1 AND finish_id=''))",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, outcome, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now);
    sqlite3_bind_text(st, 3, finish_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, finish_digest, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 5, result_count);
    sqlite3_bind_int64(st, 6, result_bytes);
    sqlite3_bind_text(st, 7, result_digest, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 8, result_truncated);
    sqlite3_bind_text(st, 9, error_code, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 10, result_json, (int)result_bytes, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 11, job_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 12, attempt_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 13, dispatch_generation);
    sqlite3_bind_text(st, 14, request_digest, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 15, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 16, session_epoch, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (ac_db_radio_job_get(job_id, out) != 0)
        goto rollback;
    rc = AC_RADIO_JOB_OK;
commit:
    if (ac_exec("COMMIT") != 0)
        return AC_RADIO_JOB_ERROR;
    return rc;
rollback:
    sqlite3_finalize(st);
    ac_exec("ROLLBACK");
    return AC_RADIO_JOB_CONFLICT;
}

int ac_db_radio_job_reconcile(const char *job_id, const char *attempt_id,
                              int64_t dispatch_generation,
                              const char *request_digest, const char *ap_id,
                              const char *session_epoch,
                              const char *reported_state, int64_t now,
                              struct ac_radio_job *out)
{
    sqlite3_stmt *st = NULL;
    struct ac_radio_job existing;
    const char *next_state;
    const char *error_code = "";
    int terminal = 0;

    if (!g_ac_db || !out || now <= 0 ||
        !ac_radio_job_execution_identity_valid(job_id, attempt_id,
            dispatch_generation, request_digest, ap_id) ||
        !ac_radio_job_binding_valid(ap_id, session_epoch) || !reported_state ||
        (strcmp(reported_state, "leased") && strcmp(reported_state, "running") &&
         strcmp(reported_state, "interrupted") &&
         strcmp(reported_state, "cancelled")) ||
        ac_exec("BEGIN IMMEDIATE") != 0)
        return AC_RADIO_JOB_INVALID_TARGET;
    if (!ac_db_ap_session_is_current_locked(ap_id, session_epoch) ||
        ac_db_radio_job_get(job_id, &existing) != 0 ||
        !ac_radio_job_execution_matches(&existing, job_id, attempt_id,
            dispatch_generation, request_digest, ap_id) ||
        (strcmp(existing.state, "leased") && strcmp(existing.state, "running") &&
         strcmp(existing.state, "cancel_requested")))
        goto conflict;
    if (!strcmp(reported_state, "interrupted")) {
        next_state = "failed";
        error_code = "apd_restarted_during_execution";
        terminal = 1;
    } else if (!strcmp(reported_state, "cancelled")) {
        if (strcmp(existing.state, "cancel_requested"))
            goto conflict;
        next_state = "cancelled";
        error_code = "cancelled_by_apd";
        terminal = 1;
    } else if (!strcmp(reported_state, "running")) {
        if (!strcmp(existing.state, "cancel_requested"))
            next_state = "cancel_requested";
        else
            next_state = "running";
    } else {
        if (strcmp(existing.state, "leased"))
            goto conflict;
        next_state = "leased";
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_radio_jobs SET state=?1,updated_at=?2,session_epoch=?3,"
            "lease_owner=CASE WHEN ?4=1 THEN '' ELSE ap_id END,"
            "lease_expires_at=CASE WHEN ?4=1 THEN 0 ELSE ?5 END,"
            "last_progress_at=?2,reconcile_deadline=CASE WHEN ?4=1 THEN 0 ELSE ?5 END,"
            "result_complete=CASE WHEN ?4=1 THEN 0 ELSE result_complete END,"
            "error_code=?6 WHERE job_id=?7 AND attempt_id=?8 "
            "AND dispatch_generation=?9 AND request_digest=?10",
            -1, &st, NULL) != SQLITE_OK)
        goto error;
    sqlite3_bind_text(st, 1, next_state, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, now);
    sqlite3_bind_text(st, 3, session_epoch, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 4, terminal);
    sqlite3_bind_int64(st, 5, now + AC_RADIO_JOB_RECONCILE_SECONDS);
    sqlite3_bind_text(st, 6, error_code, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 7, job_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, attempt_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 9, dispatch_generation);
    sqlite3_bind_text(st, 10, request_digest, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto error;
    sqlite3_finalize(st);
    st = NULL;
    if (ac_db_radio_job_get(job_id, out) != 0 || ac_exec("COMMIT") != 0)
        goto error_no_transaction;
    return AC_RADIO_JOB_OK;
conflict:
    ac_exec("ROLLBACK");
    return AC_RADIO_JOB_CONFLICT;
error:
    sqlite3_finalize(st);
    ac_exec("ROLLBACK");
error_no_transaction:
    return AC_RADIO_JOB_ERROR;
}

int ac_db_radio_job_result_payload(const char *job_id, char **result_json_out)
{
    sqlite3_stmt *st = NULL;
    const unsigned char *value;
    int rc = AC_RADIO_JOB_NOT_FOUND;

    if (!g_ac_db || !result_json_out || !ac_uuid_valid(job_id))
        return AC_RADIO_JOB_INVALID_TARGET;
    *result_json_out = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT result_json FROM ac_radio_jobs WHERE job_id=?1 "
            "AND state IN ('completed','failed','cancelled')", -1, &st, NULL) != SQLITE_OK)
        return AC_RADIO_JOB_ERROR;
    sqlite3_bind_text(st, 1, job_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW &&
        (value = sqlite3_column_text(st, 0)) != NULL &&
        sqlite3_column_bytes(st, 0) > 0 &&
        sqlite3_column_bytes(st, 0) <= (int)AC_RADIO_JOB_RESULT_JSON_MAX) {
        *result_json_out = strdup((const char *)value);
        if (*result_json_out)
            rc = AC_RADIO_JOB_OK;
    }
    sqlite3_finalize(st);
    return rc;
}

struct json_object *ac_db_radio_job_latest_results_json(void)
{
    static const int maximum_samples = 128;
    sqlite3_stmt *st = NULL;
    struct json_object *samples = json_object_new_array();
    int count = 0;

    if (!g_ac_db || !samples || sqlite3_prepare_v2(g_ac_db,
            "SELECT j.job_id,j.ap_id,j.radio_id,j.updated_at,j.result_count,"
            "j.result_complete,j.result_json FROM ac_radio_jobs j "
            "WHERE j.mode='neighbor' AND j.state='completed' AND NOT EXISTS ("
            "SELECT 1 FROM ac_radio_jobs newer WHERE newer.ap_id=j.ap_id "
            "AND newer.radio_id=j.radio_id AND newer.mode='neighbor' "
            "AND newer.state='completed' AND (newer.updated_at>j.updated_at OR "
            "(newer.updated_at=j.updated_at AND newer.job_id>j.job_id))) "
            "ORDER BY j.updated_at DESC,j.job_id DESC LIMIT ?1",
            -1, &st, NULL) != SQLITE_OK) {
        json_object_put(samples);
        sqlite3_finalize(st);
        return NULL;
    }
    sqlite3_bind_int(st, 1, maximum_samples);
    while (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *job_id = sqlite3_column_text(st, 0);
        const unsigned char *ap_id = sqlite3_column_text(st, 1);
        const unsigned char *radio_id = sqlite3_column_text(st, 2);
        const unsigned char *payload = sqlite3_column_text(st, 6);
        int payload_bytes = sqlite3_column_bytes(st, 6);
        struct json_object *items = NULL;
        struct json_object *sample;

        if (!job_id || !ap_id || !radio_id || !payload || payload_bytes <= 0 ||
            payload_bytes > (int)AC_RADIO_JOB_RESULT_JSON_MAX)
            continue;
        items = json_tokener_parse((const char *)payload);
        if (!items || !json_object_is_type(items, json_type_array)) {
            json_object_put(items);
            continue;
        }
        sample = json_object_new_object();
        if (!sample) {
            json_object_put(items);
            json_object_put(samples);
            sqlite3_finalize(st);
            return NULL;
        }
        json_object_object_add(sample, "job_id",
                               json_object_new_string((const char *)job_id));
        json_object_object_add(sample, "ap_id",
                               json_object_new_string((const char *)ap_id));
        json_object_object_add(sample, "radio_id",
                               json_object_new_string((const char *)radio_id));
        json_object_object_add(sample, "sample_time",
                               json_object_new_int64(sqlite3_column_int64(st, 3)));
        json_object_object_add(sample, "item_count",
                               json_object_new_int(sqlite3_column_int(st, 4)));
        json_object_object_add(sample, "complete",
                               json_object_new_boolean(sqlite3_column_int(st, 5)));
        json_object_object_add(sample, "truncated",
                               json_object_new_boolean(!sqlite3_column_int(st, 5)));
        json_object_object_add(sample, "items", items);
        json_object_array_add(samples, sample);
        count++;
    }
    sqlite3_finalize(st);
    {
        struct json_object *root = json_object_new_object();

        if (!root) {
            json_object_put(samples);
            return NULL;
        }
        json_object_object_add(root, "ok", json_object_new_boolean(1));
        json_object_object_add(root, "contract_version",
                               json_object_new_string(AC_CONTRACT_VERSION));
        json_object_object_add(root, "source",
                               json_object_new_string(AC_SERVICE_NAME));
        json_object_object_add(root, "samples", samples);
        json_object_object_add(root, "count", json_object_new_int(count));
        json_object_object_add(root, "limited",
                               json_object_new_boolean(count == maximum_samples));
        json_object_object_add(root, "limit",
                               json_object_new_int(maximum_samples));
        return root;
    }
}

struct json_object *ac_db_survey_history_json(const char *ap_id,
                                              const char *radio_id,
                                              int64_t start, int64_t end,
                                              int resolution_seconds,
                                              int limit, int64_t after_id)
{
    static const char sql[] =
        "SELECT sample_id,ap_id,radio_id,bucket_start,first_received_at,last_received_at,"
        "sample_count,active_delta_ms,busy_delta_ms,receive_delta_ms,transmit_delta_ms,"
        "utilization_pct,noise_dbm,complete,source FROM ac_radio_survey_bucket "
        "WHERE resolution_seconds=?1 AND bucket_start>=?2 AND bucket_start<=?3 "
        "AND sample_id>?4 AND (?5='' OR ap_id=?5) AND (?6='' OR radio_id=?6) "
        "ORDER BY bucket_start,sample_id LIMIT ?7";
    struct json_object *root = json_object_new_object();
    struct json_object *points = json_object_new_array();
    sqlite3_stmt *st = NULL;
    int count = 0;
    int limited = 0;
    int64_t next_cursor = after_id;
    int64_t latest_received = 0;

    if (!root || !points || !g_ac_db || start <= 0 || end < start ||
        after_id < 0 || limit < 1 || limit > AC_SURVEY_HISTORY_LIMIT_MAX ||
        (ap_id && ap_id[0] && !ac_uuid_valid(ap_id)) ||
        (radio_id && radio_id[0] &&
         (!ap_id || !ap_id[0] || !ac_radio_job_radio_id_valid(radio_id))))
        goto fail;
    if (resolution_seconds == 0)
        resolution_seconds = end - start <= AC_SURVEY_FINE_RETENTION_SECONDS ?
            AC_SURVEY_FINE_RESOLUTION_SECONDS :
            AC_SURVEY_HOUR_RESOLUTION_SECONDS;
    if (resolution_seconds != AC_SURVEY_FINE_RESOLUTION_SECONDS &&
        resolution_seconds != AC_SURVEY_HOUR_RESOLUTION_SECONDS)
        goto fail;
    if (sqlite3_prepare_v2(g_ac_db, sql, -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_int(st, 1, resolution_seconds);
    sqlite3_bind_int64(st, 2, start - start % resolution_seconds);
    sqlite3_bind_int64(st, 3, end);
    sqlite3_bind_int64(st, 4, after_id);
    sqlite3_bind_text(st, 5, ap_id ? ap_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, radio_id ? radio_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 7, limit + 1);
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *point;
        int64_t sample_id;

        if (count == limit) {
            limited = 1;
            break;
        }
        point = json_object_new_object();
        if (!point)
            goto fail;
        sample_id = sqlite3_column_int64(st, 0);
        json_object_object_add(point, "sample_id",
                               json_object_new_int64(sample_id));
        json_object_object_add(point, "ap_id", json_object_new_string(
            (const char *)sqlite3_column_text(st, 1)));
        json_object_object_add(point, "radio_id", json_object_new_string(
            (const char *)sqlite3_column_text(st, 2)));
        json_object_object_add(point, "bucket_start",
                               json_object_new_int64(sqlite3_column_int64(st, 3)));
        json_object_object_add(point, "timestamp",
                               json_object_new_int64(sqlite3_column_int64(st, 3)));
        json_object_object_add(point, "first_received_at",
                               json_object_new_int64(sqlite3_column_int64(st, 4)));
        json_object_object_add(point, "last_received_at",
                               json_object_new_int64(sqlite3_column_int64(st, 5)));
        json_object_object_add(point, "sample_count",
                               json_object_new_int(sqlite3_column_int(st, 6)));
        json_object_object_add(point, "active_delta_ms",
                               json_object_new_int64(sqlite3_column_int64(st, 7)));
        json_object_object_add(point, "busy_delta_ms",
                               json_object_new_int64(sqlite3_column_int64(st, 8)));
        json_object_object_add(point, "receive_delta_ms",
            sqlite3_column_type(st, 9) == SQLITE_NULL ? json_object_new_null() :
            json_object_new_int64(sqlite3_column_int64(st, 9)));
        json_object_object_add(point, "transmit_delta_ms",
            sqlite3_column_type(st, 10) == SQLITE_NULL ? json_object_new_null() :
            json_object_new_int64(sqlite3_column_int64(st, 10)));
        json_object_object_add(point, "utilization_pct",
                               json_object_new_double(sqlite3_column_double(st, 11)));
        json_object_object_add(point, "value",
                               json_object_new_double(sqlite3_column_double(st, 11)));
        json_object_object_add(point, "noise_dbm",
            sqlite3_column_type(st, 12) == SQLITE_NULL ? json_object_new_null() :
            json_object_new_int(sqlite3_column_int(st, 12)));
        json_object_object_add(point, "complete",
                               json_object_new_boolean(sqlite3_column_int(st, 13)));
        json_object_object_add(point, "source", json_object_new_string(
            (const char *)sqlite3_column_text(st, 14)));
        json_object_array_add(points, point);
        next_cursor = sample_id;
        if (sqlite3_column_int64(st, 5) > latest_received)
            latest_received = sqlite3_column_int64(st, 5);
        count++;
    }
    sqlite3_finalize(st);
    st = NULL;
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "contract_version",
                           json_object_new_string(AC_CONTRACT_VERSION));
    json_object_object_add(root, "source",
                           json_object_new_string(AC_SERVICE_NAME));
    json_object_object_add(root, "resolution_seconds",
                           json_object_new_int(resolution_seconds));
    json_object_object_add(root, "start", json_object_new_int64(start));
    json_object_object_add(root, "end", json_object_new_int64(end));
    json_object_object_add(root, "points", points);
    json_object_object_add(root, "count", json_object_new_int(count));
    json_object_object_add(root, "limited", json_object_new_boolean(limited));
    json_object_object_add(root, "next_cursor",
                           json_object_new_int64(next_cursor));
    json_object_object_add(root, "latest_received_at",
                           latest_received ? json_object_new_int64(latest_received) :
                                             json_object_new_null());
    json_object_object_add(root, "reason", json_object_new_string(
        count >= 2 ? "available" : count == 1 ? "warming_up" : "no_samples"));
    return root;
fail:
    sqlite3_finalize(st);
    json_object_put(points);
    if (!root)
        return NULL;
    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "error",
                           json_object_new_string("invalid_survey_history_query"));
    json_object_object_add(root, "points", json_object_new_array());
    return root;
}

/* True when a baseline exists for this radio but no bucket has been produced
 * yet. Without this, the first sample after enrollment reports `no_samples`,
 * which reads as "this AP has no retry counters" when the truth is "one more
 * interval and the first delta lands". The two states drive different UI copy
 * and different acceptance verdicts, so they must not collapse. */
static int ac_db_tx_retry_cursor_exists(const char *ap_id, const char *radio_id)
{
    sqlite3_stmt *st = NULL;
    int exists = 0;

    if (!g_ac_db || sqlite3_prepare_v2(g_ac_db,
            "SELECT 1 FROM ac_radio_tx_retry_cursor WHERE (?1='' OR ap_id=?1) "
            "AND (?2='' OR radio_id=?2) LIMIT 1", -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, ap_id ? ap_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, radio_id ? radio_id : "", -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        exists = 1;
    sqlite3_finalize(st);
    return exists;
}

struct json_object *ac_db_tx_retry_history_json(const char *ap_id,
                                                const char *radio_id,
                                                int64_t start, int64_t end,
                                                int resolution_seconds,
                                                int limit, int64_t after_id)
{
    static const char sql[] =
        "SELECT sample_id,ap_id,radio_id,bucket_start,first_received_at,last_received_at,"
        "sample_count,tx_total_delta,tx_retries_delta,retry_rate_pct,complete,source "
        "FROM ac_radio_tx_retry_bucket WHERE resolution_seconds=?1 "
        "AND bucket_start>=?2 AND bucket_start<=?3 AND sample_id>?4 "
        "AND (?5='' OR ap_id=?5) AND (?6='' OR radio_id=?6) "
        "ORDER BY bucket_start,sample_id LIMIT ?7";
    struct json_object *root = json_object_new_object();
    struct json_object *points = json_object_new_array();
    sqlite3_stmt *st = NULL;
    int count = 0;
    int limited = 0;
    int64_t next_cursor = after_id;
    int64_t latest_received = 0;

    if (!root || !points || !g_ac_db || start <= 0 || end < start ||
        after_id < 0 || limit < 1 || limit > AC_TX_RETRY_HISTORY_LIMIT_MAX ||
        (resolution_seconds != 0 &&
         resolution_seconds != AC_TX_RETRY_FINE_RESOLUTION_SECONDS) ||
        (ap_id && ap_id[0] && !ac_uuid_valid(ap_id)) ||
        (radio_id && radio_id[0] &&
         (!ap_id || !ap_id[0] || !ac_radio_job_radio_id_valid(radio_id))))
        goto fail;
    if (resolution_seconds == 0)
        resolution_seconds = AC_TX_RETRY_FINE_RESOLUTION_SECONDS;
    if (sqlite3_prepare_v2(g_ac_db, sql, -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_int(st, 1, resolution_seconds);
    sqlite3_bind_int64(st, 2, start - start % resolution_seconds);
    sqlite3_bind_int64(st, 3, end);
    sqlite3_bind_int64(st, 4, after_id);
    sqlite3_bind_text(st, 5, ap_id ? ap_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, radio_id ? radio_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 7, limit + 1);
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *point;
        int64_t sample_id;

        if (count == limit) {
            limited = 1;
            break;
        }
        point = json_object_new_object();
        if (!point)
            goto fail;
        sample_id = sqlite3_column_int64(st, 0);
        json_object_object_add(point, "sample_id",
                               json_object_new_int64(sample_id));
        json_object_object_add(point, "ap_id", json_object_new_string(
            (const char *)sqlite3_column_text(st, 1)));
        json_object_object_add(point, "radio_id", json_object_new_string(
            (const char *)sqlite3_column_text(st, 2)));
        json_object_object_add(point, "bucket_start",
                               json_object_new_int64(sqlite3_column_int64(st, 3)));
        json_object_object_add(point, "timestamp",
                               json_object_new_int64(sqlite3_column_int64(st, 3)));
        json_object_object_add(point, "first_received_at",
                               json_object_new_int64(sqlite3_column_int64(st, 4)));
        json_object_object_add(point, "last_received_at",
                               json_object_new_int64(sqlite3_column_int64(st, 5)));
        json_object_object_add(point, "sample_count",
                               json_object_new_int(sqlite3_column_int(st, 6)));
        json_object_object_add(point, "tx_total_delta",
                               json_object_new_int64(sqlite3_column_int64(st, 7)));
        json_object_object_add(point, "tx_retries_delta",
                               json_object_new_int64(sqlite3_column_int64(st, 8)));
        json_object_object_add(point, "retry_rate_pct",
                               json_object_new_double(sqlite3_column_double(st, 9)));
        json_object_object_add(point, "value",
                               json_object_new_double(sqlite3_column_double(st, 9)));
        json_object_object_add(point, "complete",
                               json_object_new_boolean(sqlite3_column_int(st, 10)));
        json_object_object_add(point, "source", json_object_new_string(
            (const char *)sqlite3_column_text(st, 11)));
        json_object_array_add(points, point);
        next_cursor = sample_id;
        if (sqlite3_column_int64(st, 5) > latest_received)
            latest_received = sqlite3_column_int64(st, 5);
        count++;
    }
    sqlite3_finalize(st);
    st = NULL;
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "contract_version",
                           json_object_new_string(AC_CONTRACT_VERSION));
    json_object_object_add(root, "source",
                           json_object_new_string(AC_SERVICE_NAME));
    json_object_object_add(root, "resolution_seconds",
                           json_object_new_int(resolution_seconds));
    json_object_object_add(root, "start", json_object_new_int64(start));
    json_object_object_add(root, "end", json_object_new_int64(end));
    json_object_object_add(root, "points", points);
    json_object_object_add(root, "count", json_object_new_int(count));
    json_object_object_add(root, "limited", json_object_new_boolean(limited));
    json_object_object_add(root, "next_cursor",
                           json_object_new_int64(next_cursor));
    json_object_object_add(root, "latest_received_at",
                           latest_received ? json_object_new_int64(latest_received) :
                                             json_object_new_null());
    json_object_object_add(root, "reason", json_object_new_string(
        count >= 2 ? "available" :
        count == 1 ? "warming_up" :
        ac_db_tx_retry_cursor_exists(ap_id, radio_id) ? "warming_up" :
                                                        "no_samples"));
    return root;
fail:
    sqlite3_finalize(st);
    json_object_put(points);
    if (!root)
        return NULL;
    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "error",
                           json_object_new_string("invalid_tx_retry_history_query"));
    json_object_object_add(root, "points", json_object_new_array());
    return root;
}

struct json_object *ac_db_ap_traffic_history_json(const char *range,
                                                 const char *ap_id)
{
    static const char sql[] =
        "WITH traffic_ap AS ("
        " SELECT (bucket_start/?3)*?3 AS ts,ap_id,"
        " CAST(SUM(up_bytes) AS REAL)/SUM(duration_seconds) AS up_rate,"
        " CAST(SUM(down_bytes) AS REAL)/SUM(duration_seconds) AS down_rate,"
        " CAST(SUM(station_count_sum) AS REAL)/SUM(sample_count) AS station_avg,"
        " SUM(sample_count) AS samples,SUM(duration_seconds) AS duration,"
        " SUM(counter_reset_count) AS resets,MIN(complete) AS complete,"
        " MAX(last_observed_at) AS observed_at,MAX(last_received_at) AS updated_at"
        " FROM ac_ap_traffic_bucket WHERE bucket_start>=?1 AND bucket_start<=?2"
        " AND (?4='' OR ap_id=?4) AND (?4<>'' OR EXISTS (SELECT 1 FROM ac_aps a"
        " WHERE a.ap_id=ac_ap_traffic_bucket.ap_id"
        " AND a.adoption_state='adopted' AND a.last_seen_at>=?6))"
        " GROUP BY ts,ap_id),"
        " traffic AS ("
        " SELECT ts,SUM(up_rate) AS up_rate,SUM(down_rate) AS down_rate,"
        " SUM(station_avg) AS station_avg,SUM(samples) AS samples,"
        " SUM(duration) AS duration,SUM(resets) AS resets,MIN(complete) AS complete,"
        " MAX(observed_at) AS observed_at,MAX(updated_at) AS updated_at,"
        " COUNT(*) AS ap_count FROM traffic_ap GROUP BY ts),"
        " survey AS ("
        " SELECT (bucket_start/?3)*?3 AS ts,"
        " CAST(SUM(busy_delta_ms) AS REAL)*100.0/SUM(active_delta_ms) AS utilization"
        " FROM ac_radio_survey_bucket WHERE bucket_start>=?1 AND bucket_start<=?2"
        " AND resolution_seconds=?5 AND (?4='' OR ap_id=?4)"
        " AND (?4<>'' OR EXISTS (SELECT 1 FROM ac_aps a"
        " WHERE a.ap_id=ac_radio_survey_bucket.ap_id"
        " AND a.adoption_state='adopted' AND a.last_seen_at>=?6))"
        " GROUP BY ts)"
        " SELECT traffic.ts,traffic.up_rate,traffic.down_rate,traffic.station_avg,"
        " traffic.samples,traffic.duration,traffic.resets,traffic.complete,"
        " traffic.observed_at,traffic.updated_at,traffic.ap_count,survey.utilization"
        " FROM traffic LEFT JOIN survey ON survey.ts=traffic.ts ORDER BY traffic.ts";
    struct json_object *root = json_object_new_object();
    struct json_object *points = json_object_new_array();
    sqlite3_stmt *st = NULL;
    sqlite3_stmt *meta = NULL;
    const char *selected_ap = ap_id && strcmp(ap_id, "all") ? ap_id : "";
    int64_t now = ac_now_s();
    int64_t retention = 3600;
    int64_t start;
    int output_resolution = 60;
    int survey_resolution = AC_SURVEY_FINE_RESOLUTION_SECONDS;
    int count = 0;
    int64_t samples = 0;
    int64_t latest_observed = 0;
    int64_t latest_updated = 0;
    int64_t resets = 0;
    int selected_aps = 0;
    int telemetry_rows = 0;
    int64_t expected_samples;
    const char *reason = "traffic_collection_warming_up";

    if (!root || !points || !g_ac_db || !range ||
        (selected_ap[0] && !ac_uuid_valid(selected_ap)))
        goto fail;
    if (!strcmp(range, "1h")) {
        retention = 60 * 60;
        output_resolution = 60;
    } else if (!strcmp(range, "1d")) {
        retention = 24 * 60 * 60;
        output_resolution = 300;
    } else if (!strcmp(range, "1w")) {
        retention = 7LL * 24 * 60 * 60;
        output_resolution = 3600;
        survey_resolution = AC_SURVEY_HOUR_RESOLUTION_SECONDS;
    } else if (!strcmp(range, "1m")) {
        retention = 30LL * 24 * 60 * 60;
        output_resolution = 24 * 60 * 60;
        survey_resolution = AC_SURVEY_HOUR_RESOLUTION_SECONDS;
    } else {
        goto fail;
    }
    start = now - retention;
    if (sqlite3_prepare_v2(g_ac_db, sql, -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_int64(st, 1, start);
    sqlite3_bind_int64(st, 2, now);
    sqlite3_bind_int(st, 3, output_resolution);
    sqlite3_bind_text(st, 4, selected_ap, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 5, survey_resolution);
    sqlite3_bind_int64(st, 6, now - AC_AP_ONLINE_TIMEOUT_SECONDS);
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *point = json_object_new_object();

        if (!point)
            goto fail;
        json_object_object_add(point, "ts",
                               json_object_new_int64(sqlite3_column_int64(st, 0)));
        json_object_object_add(point, "up_rate", json_object_new_int64(
            (int64_t)sqlite3_column_double(st, 1)));
        json_object_object_add(point, "down_rate", json_object_new_int64(
            (int64_t)sqlite3_column_double(st, 2)));
        json_object_object_add(point, "station_count_avg",
                               json_object_new_double(sqlite3_column_double(st, 3)));
        json_object_object_add(point, "sample_count",
                               json_object_new_int64(sqlite3_column_int64(st, 4)));
        json_object_object_add(point, "valid_duration",
                               json_object_new_int64(sqlite3_column_int64(st, 5)));
        json_object_object_add(point, "counter_reset_count",
                               json_object_new_int64(sqlite3_column_int64(st, 6)));
        json_object_object_add(point, "complete",
                               json_object_new_boolean(sqlite3_column_int(st, 7)));
        json_object_object_add(point, "observed_at",
                               json_object_new_int64(sqlite3_column_int64(st, 8)));
        json_object_object_add(point, "updated_at",
                               json_object_new_int64(sqlite3_column_int64(st, 9)));
        json_object_object_add(point, "ap_count",
                               json_object_new_int(sqlite3_column_int(st, 10)));
        json_object_object_add(point, "channel_utilization_avg",
            sqlite3_column_type(st, 11) == SQLITE_NULL ? json_object_new_null() :
            json_object_new_double(sqlite3_column_double(st, 11)));
        json_object_object_add(point, "source",
                               json_object_new_string("ac_station_counter_delta"));
        json_object_array_add(points, point);
        samples += sqlite3_column_int64(st, 4);
        resets += sqlite3_column_int64(st, 6);
        if (sqlite3_column_int64(st, 8) > latest_observed)
            latest_observed = sqlite3_column_int64(st, 8);
        if (sqlite3_column_int64(st, 9) > latest_updated)
            latest_updated = sqlite3_column_int64(st, 9);
        count++;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT COUNT(*),COALESCE(SUM(CASE WHEN r.observed_at>0 THEN 1 ELSE 0 END),0),"
            "(SELECT COUNT(*) FROM ac_aps WHERE adoption_state='adopted'"
            " AND (?1='' OR ap_id=?1)) "
            "FROM ac_aps a LEFT JOIN ac_ap_runtime r ON r.ap_id=a.ap_id "
            "WHERE a.adoption_state='adopted' AND (?1='' OR a.ap_id=?1)"
            " AND (?1<>'' OR a.last_seen_at>=?2)",
            -1, &meta, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(meta, 1, selected_ap, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(meta, 2, now - AC_AP_ONLINE_TIMEOUT_SECONDS);
    if (sqlite3_step(meta) == SQLITE_ROW) {
        selected_aps = sqlite3_column_int(meta, 0);
        telemetry_rows = sqlite3_column_int(meta, 1);
        if (!selected_ap[0] && selected_aps == 0 &&
            sqlite3_column_int(meta, 2) > 0)
            reason = "no_online_managed_aps";
    }
    sqlite3_finalize(meta);
    meta = NULL;
    expected_samples = retention / AC_AP_TRAFFIC_RESOLUTION_SECONDS *
                       (selected_aps > 0 ? selected_aps : 1);
    if (count > 0)
        reason = latest_updated > 0 &&
                 now - latest_updated > AC_TELEMETRY_STALE_TIMEOUT_SECONDS ?
                 "traffic_samples_stale" : "available";
    else if (selected_aps == 0 && strcmp(reason, "no_online_managed_aps"))
        reason = selected_ap[0] ? "ap_not_found" : "no_managed_aps";
    else if (telemetry_rows == 0)
        reason = "telemetry_not_received";
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "contract_version",
                           json_object_new_string(AC_CONTRACT_VERSION));
    json_object_object_add(root, "range", json_object_new_string(range));
    json_object_object_add(root, "scope", json_object_new_string("ap"));
    json_object_object_add(root, "ap_id",
                           json_object_new_string(selected_ap[0] ? selected_ap : "all"));
    json_object_object_add(root, "direction",
                           json_object_new_string("wireless_station"));
    json_object_object_add(root, "unit", json_object_new_string("B/s"));
    json_object_object_add(root, "bucket_sec",
                           json_object_new_int(output_resolution));
    json_object_object_add(root, "retention_sec",
                           json_object_new_int64(retention));
    json_object_object_add(root, "start_ts", json_object_new_int64(start));
    json_object_object_add(root, "end_ts", json_object_new_int64(now));
    json_object_object_add(root, "source",
                           json_object_new_string("ac_station_counter_delta"));
    json_object_object_add(root, "channel_utilization_aggregation",
                           json_object_new_string("airtime_weighted_busy_over_active"));
    json_object_object_add(root, "observed_at",
                           latest_observed ? json_object_new_int64(latest_observed) :
                                             json_object_new_null());
    json_object_object_add(root, "updated_at",
                           latest_updated ? json_object_new_int64(latest_updated) :
                                            json_object_new_null());
    json_object_object_add(root, "sample_count", json_object_new_int64(samples));
    json_object_object_add(root, "expected_sample_count",
                           json_object_new_int64(expected_samples));
    json_object_object_add(root, "completeness_ratio", json_object_new_double(
        expected_samples > 0 ? (samples > expected_samples ? 1.0 :
        (double)samples / expected_samples) : 0.0));
    json_object_object_add(root, "counter_reset_count",
                           json_object_new_int64(resets));
    json_object_object_add(root, "missing", json_object_new_boolean(count == 0));
    json_object_object_add(root, "reason", json_object_new_string(reason));
    json_object_object_add(root, "points", points);
    return root;
fail:
    sqlite3_finalize(st);
    sqlite3_finalize(meta);
    json_object_put(points);
    if (!root)
        return NULL;
    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "error",
                           json_object_new_string("invalid_ap_traffic_history_query"));
    json_object_object_add(root, "points", json_object_new_array());
    return root;
}

int ac_db_radio_job_list(const char *ap_id, ac_radio_job_visit_fn visit,
                         void *opaque, int *limited)
{
    sqlite3_stmt *st = NULL;
    char sql[sizeof(ac_radio_job_select) + 80];
    int count = 0;

    if (limited)
        *limited = 0;
    if (!g_ac_db || !ac_uuid_valid(ap_id) || !visit || !limited ||
        snprintf(sql, sizeof(sql),
                 "%s WHERE ap_id=?1 ORDER BY created_at DESC,job_id DESC LIMIT ?2",
                 ac_radio_job_select) >= (int)sizeof(sql) ||
        sqlite3_prepare_v2(g_ac_db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, AC_RADIO_JOB_LIST_LIMIT + 1);
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct ac_radio_job job;
        if (count == AC_RADIO_JOB_LIST_LIMIT) {
            *limited = 1;
            break;
        }
        if (ac_radio_job_from_stmt(st, &job) != 0 || visit(&job, opaque) != 0) {
            sqlite3_finalize(st);
            return -1;
        }
        count++;
    }
    sqlite3_finalize(st);
    return count;
}

static int ac_radio_jobs_prune_locked(int64_t now)
{
    sqlite3_stmt *st = NULL;
    int changed;

    if (!g_ac_db)
        return -1;
    if (now <= AC_RADIO_JOB_RETENTION_SECONDS)
        return 0;
    if (sqlite3_prepare_v2(g_ac_db,
            "DELETE FROM ac_radio_jobs WHERE "
            "state IN ('completed','failed','cancelled','expired') "
            "AND updated_at<?1 AND (SELECT COUNT(*) FROM ac_radio_jobs newer "
            "WHERE newer.ap_id=ac_radio_jobs.ap_id "
            "AND newer.state IN ('completed','failed','cancelled','expired') "
            "AND (newer.updated_at>ac_radio_jobs.updated_at OR "
            "(newer.updated_at=ac_radio_jobs.updated_at AND "
            "newer.job_id>ac_radio_jobs.job_id)))>=?2 "
            "AND NOT (mode='neighbor' AND state='completed' AND NOT EXISTS ("
            "SELECT 1 FROM ac_radio_jobs newer_result "
            "WHERE newer_result.ap_id=ac_radio_jobs.ap_id "
            "AND newer_result.radio_id=ac_radio_jobs.radio_id "
            "AND newer_result.mode='neighbor' AND newer_result.state='completed' "
            "AND (newer_result.updated_at>ac_radio_jobs.updated_at OR "
            "(newer_result.updated_at=ac_radio_jobs.updated_at AND "
            "newer_result.job_id>ac_radio_jobs.job_id))))",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, now - AC_RADIO_JOB_RETENTION_SECONDS);
    sqlite3_bind_int(st, 2, AC_RADIO_JOB_RETENTION_MIN);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return -1;
    }
    changed = sqlite3_changes(g_ac_db);
    sqlite3_finalize(st);
    return changed;
}

int ac_db_radio_jobs_prune(int64_t now)
{
    int changed;

    if (!g_ac_db || now <= 0 || ac_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    changed = ac_radio_jobs_prune_locked(now);
    if (changed < 0 || ac_exec("COMMIT") != 0) {
        ac_exec("ROLLBACK");
        return -1;
    }
    return changed;
}

int ac_db_radio_job_cancel(const char *job_id, struct ac_radio_job *out)
{
    sqlite3_stmt *st = NULL;
    int rc = AC_RADIO_JOB_ERROR;
    int64_t now = ac_now_s();

    if (!g_ac_db || !out || !ac_uuid_valid(job_id) || ac_exec("BEGIN IMMEDIATE") != 0)
        return AC_RADIO_JOB_NOT_FOUND;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_radio_jobs SET state=CASE state "
            "WHEN 'running' THEN 'cancel_requested' WHEN 'leased' THEN 'cancel_requested' "
            "WHEN 'queued' THEN 'cancelled' ELSE state END,"
            "updated_at=?1,error_code='' WHERE job_id=?2 AND "
            "state IN ('queued','leased','running','cancel_requested')",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, job_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (ac_db_radio_job_get(job_id, out) != 0 || ac_exec("COMMIT") != 0)
        goto rollback;
    rc = AC_RADIO_JOB_OK;
    return rc;
rollback:
    sqlite3_finalize(st);
    ac_exec("ROLLBACK");
    return rc;
}

static int ac_validate_parent(const char *path)
{
    char parent[512];
    struct stat st;

    if (ac_path_parent(path, parent, sizeof(parent)) != 0 ||
        lstat(parent, &st) != 0 || !S_ISDIR(st.st_mode) ||
        !ac_secure_owner(st.st_uid) || (st.st_mode & 0022) != 0) {
        fprintf(stderr, "[%s] unsafe database parent for %s\n",
                AC_SERVICE_NAME, path ? path : "(null)");
        return -1;
    }
    return 0;
}

static int ac_validate_db_file(const char *path)
{
    struct stat st;

    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
        !ac_secure_owner(st.st_uid) || (st.st_mode & 0022) != 0) {
        fprintf(stderr, "[%s] unsafe database file %s\n", AC_SERVICE_NAME, path);
        return -1;
    }
    return 0;
}

static int ac_prepare_db_file(const char *path)
{
    int fd;

    if (ac_validate_parent(path) != 0)
        return -1;
    fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd >= 0) {
        if (fchmod(fd, 0600) != 0 || fsync(fd) != 0) {
            close(fd);
            unlink(path);
            return -1;
        }
        close(fd);
    } else if (errno != EEXIST) {
        fprintf(stderr, "[%s] cannot securely create %s: %s\n",
                AC_SERVICE_NAME, path, strerror(errno));
        return -1;
    }
    return ac_validate_db_file(path);
}

static int ac_init_lock_acquire(const char *path)
{
    char lock_path[576];
    struct stat st;
    int fd;

    if (!path || snprintf(lock_path, sizeof(lock_path), "%s.ac-init.lock", path) >=
                     (int)sizeof(lock_path) || ac_validate_parent(path) != 0)
        return -1;
    fd = open(lock_path, O_RDWR | O_CREAT | O_NOFOLLOW, 0600);
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_nlink != 1 || !ac_secure_owner(st.st_uid) ||
        (st.st_mode & 0777) != 0600 || flock(fd, LOCK_EX) != 0) {
        fprintf(stderr, "[%s] cannot acquire secure database lock\n", AC_SERVICE_NAME);
        if (fd >= 0)
            close(fd);
        return -1;
    }
    return fd;
}

static void ac_init_lock_release(int fd)
{
    if (fd < 0)
        return;
    flock(fd, LOCK_UN);
    close(fd);
}

static int ac_exec(const char *sql)
{
    char *error = NULL;
#ifdef AC_DB_TEST_STANDALONE
    static int injected_commit_failure;

    if (!injected_commit_failure && !strcmp(sql, "COMMIT") &&
        getenv("AC_DB_TEST_FAIL_COMMIT_ONCE")) {
        injected_commit_failure = 1;
        return -1;
    }
#endif
    int rc = sqlite3_exec(g_ac_db, sql, NULL, NULL, &error);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "[%s] sqlite error: %s\n", AC_SERVICE_NAME,
                error ? error : sqlite3_errmsg(g_ac_db));
        sqlite3_free(error);
        return -1;
    }
    return 0;
}

static int ac_column_exists(const char *table, const char *column)
{
    sqlite3_stmt *st = NULL;
    char sql[128];
    int found = 0;

    if (snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table) >=
            (int)sizeof(sql) ||
        sqlite3_prepare_v2(g_ac_db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(st, 1);
        if (name && strcmp((const char *)name, column) == 0) {
            found = 1;
            break;
        }
    }
    sqlite3_finalize(st);
    return found;
}

static int ac_add_column(const char *table, const char *column,
                         const char *definition)
{
    char sql[256];
    int exists = ac_column_exists(table, column);

    if (exists < 0)
        return -1;
    if (exists)
        return 0;
    if (snprintf(sql, sizeof(sql), "ALTER TABLE %s ADD COLUMN %s %s",
                 table, column, definition) >= (int)sizeof(sql))
        return -1;
    return ac_exec(sql);
}

static int ac_migrate_roaming_band_steering(void)
{
    int legacy_exists = ac_column_exists("ac_roaming_policies",
                                         "band_steering_enabled");
    int current_exists = ac_column_exists("ac_roaming_policies",
                                          "high_band_steer_enabled");

    if (legacy_exists < 0 || current_exists < 0)
        return -1;
    if (!current_exists &&
        ac_add_column("ac_roaming_policies", "high_band_steer_enabled",
                      "INTEGER NOT NULL DEFAULT 0") != 0)
        return -1;
    if (!legacy_exists)
        return 0;
    return ac_exec(
        "UPDATE ac_roaming_policies SET high_band_steer_enabled=1 "
        "WHERE band_steering_enabled<>0 AND high_band_steer_enabled=0");
}

static int ac_schema_migrate(void)
{
    static const char schema[] =
        "CREATE TABLE IF NOT EXISTS ac_schema_meta ("
        " singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
        " version INTEGER NOT NULL,owner TEXT NOT NULL,migrated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS ac_controllers ("
        " controller_id TEXT PRIMARY KEY,name TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS ac_sites ("
        " site_id TEXT PRIMARY KEY,name TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 0,updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS ac_ap_groups ("
        " group_id TEXT PRIMARY KEY,site_id TEXT NOT NULL,name TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 0,updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS ac_aps ("
        " ap_id TEXT PRIMARY KEY,site_id TEXT NOT NULL DEFAULT 'default',name TEXT NOT NULL DEFAULT '',"
        " adoption_state TEXT NOT NULL DEFAULT 'pending_pairing',desired_revision INTEGER NOT NULL DEFAULT 0,"
        " applied_revision INTEGER NOT NULL DEFAULT 0,readback_digest TEXT NOT NULL DEFAULT '',"
        " last_seen_at INTEGER NOT NULL DEFAULT 0,capability_json TEXT NOT NULL DEFAULT '{}',"
        " reported_model TEXT NOT NULL DEFAULT '',board_name TEXT NOT NULL DEFAULT '',"
        " model_source TEXT NOT NULL DEFAULT 'unavailable',model_available INTEGER NOT NULL DEFAULT 0,"
        " model_reason TEXT NOT NULL DEFAULT 'reliable_model_source_unavailable',"
        " model_override TEXT NOT NULL DEFAULT '');"
        "CREATE TABLE IF NOT EXISTS ac_ap_unbind_requests ("
        " request_id TEXT PRIMARY KEY,ap_id TEXT NOT NULL,"
        " certificate_id TEXT NOT NULL,enrollment_id TEXT NOT NULL,"
        " state TEXT NOT NULL CHECK(state IN ('pending','completed'))," 
        " requested_at INTEGER NOT NULL,acknowledged_at INTEGER NOT NULL DEFAULT 0,"
        " error_code TEXT NOT NULL DEFAULT '');"
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_ac_ap_unbind_pending "
        " ON ac_ap_unbind_requests(ap_id) WHERE state='pending';"
        "CREATE TABLE IF NOT EXISTS ac_ap_group_members ("
        " group_id TEXT NOT NULL,ap_id TEXT NOT NULL,PRIMARY KEY(group_id,ap_id));"
        "CREATE TABLE IF NOT EXISTS ac_device_certificates ("
        " certificate_id TEXT PRIMARY KEY,ap_id TEXT NOT NULL,serial TEXT NOT NULL,key_id TEXT NOT NULL,"
        " not_before INTEGER NOT NULL,not_after INTEGER NOT NULL,state TEXT NOT NULL,revoked_at INTEGER NOT NULL DEFAULT 0,"
        " certificate_der BLOB NOT NULL DEFAULT X'',fingerprint_sha256 BLOB NOT NULL DEFAULT X'',"
        " issuer_key_id TEXT NOT NULL DEFAULT '',issued_at INTEGER NOT NULL DEFAULT 0,"
        " activated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS ac_pairing_tokens ("
        " token_id TEXT PRIMARY KEY,token_hash BLOB NOT NULL,digest_version INTEGER NOT NULL DEFAULT 1,"
        " created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,max_attempts INTEGER NOT NULL,"
        " attempts INTEGER NOT NULL DEFAULT 0,consumed_at INTEGER NOT NULL DEFAULT 0,"
        " revoked_at INTEGER NOT NULL DEFAULT 0,site_id TEXT NOT NULL DEFAULT '',"
        " hardware_digest TEXT NOT NULL DEFAULT '',scope_json TEXT NOT NULL DEFAULT '{}',"
        " claimed_enrollment_id TEXT NOT NULL DEFAULT '',claimed_at INTEGER NOT NULL DEFAULT 0,"
        " consumed_enrollment_id TEXT NOT NULL DEFAULT '');"
        "CREATE TABLE IF NOT EXISTS ac_enrollment_challenges ("
        " challenge_id TEXT PRIMARY KEY,server_nonce BLOB NOT NULL CHECK(length(server_nonce)=32),"
        " created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,consumed_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS ac_enrollments ("
        " enrollment_id TEXT PRIMARY KEY,token_id TEXT NOT NULL UNIQUE,ap_id TEXT NOT NULL,"
        " site_id TEXT NOT NULL,key_id TEXT NOT NULL,public_key BLOB NOT NULL CHECK(length(public_key)=32),"
        " csr_der BLOB NOT NULL,csr_sha256 BLOB NOT NULL CHECK(length(csr_sha256)=32),"
        " hardware_digest TEXT NOT NULL DEFAULT '',client_nonce BLOB NOT NULL CHECK(length(client_nonce)=32),"
        " challenge_id TEXT NOT NULL UNIQUE,state TEXT NOT NULL CHECK(state IN "
        " ('claimed','mtls_pending','adopted','expired','failed','revoked')),"
        " attempts INTEGER NOT NULL DEFAULT 0,claim_expires_at INTEGER NOT NULL,"
        " certificate_id TEXT NOT NULL DEFAULT '',failure_code TEXT NOT NULL DEFAULT '',"
        " activation_challenge_hash BLOB,activation_expires_at INTEGER NOT NULL DEFAULT 0,"
        " created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,adopted_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_ac_enrollments_ap_active ON ac_enrollments(ap_id) "
        "WHERE state IN ('claimed','mtls_pending','adopted');"
        "CREATE TABLE IF NOT EXISTS ac_ssids ("
        " ssid_id TEXT PRIMARY KEY,site_id TEXT NOT NULL,name TEXT NOT NULL,config_json TEXT NOT NULL DEFAULT '{}',"
        " secret_id TEXT NOT NULL DEFAULT '',revision INTEGER NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS ac_ssid_bindings ("
        " ssid_id TEXT NOT NULL,ap_id TEXT NOT NULL,radio_id TEXT NOT NULL,desired_revision INTEGER NOT NULL DEFAULT 0,"
        " applied_revision INTEGER NOT NULL DEFAULT 0,state TEXT NOT NULL DEFAULT 'pending',bssid TEXT NOT NULL DEFAULT '',"
        " error_code TEXT NOT NULL DEFAULT '',PRIMARY KEY(ssid_id,ap_id,radio_id));"
        "CREATE TABLE IF NOT EXISTS ac_radio_desired ("
        " radio_id TEXT NOT NULL,ap_id TEXT NOT NULL,config_json TEXT NOT NULL DEFAULT '{}',revision INTEGER NOT NULL,"
        " updated_at INTEGER NOT NULL,PRIMARY KEY(ap_id,radio_id));"
        "CREATE TABLE IF NOT EXISTS ac_ap_runtime ("
        " ap_id TEXT PRIMARY KEY,boot_id TEXT NOT NULL DEFAULT '',observed_at INTEGER NOT NULL DEFAULT 0,"
        " received_at INTEGER NOT NULL DEFAULT 0,"
        " snapshot_id TEXT NOT NULL DEFAULT '',runtime_json TEXT NOT NULL DEFAULT '{}',stale INTEGER NOT NULL DEFAULT 1,"
        " telemetry_sequence INTEGER NOT NULL DEFAULT -1,"
        " control_protocol_version INTEGER NOT NULL DEFAULT 0,"
        " write_capable INTEGER NOT NULL DEFAULT 0,"
        " session_connected INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS ac_radio_runtime ("
        " radio_id TEXT NOT NULL,ap_id TEXT NOT NULL,observed_at INTEGER NOT NULL DEFAULT 0,"
        " runtime_json TEXT NOT NULL DEFAULT '{}',stale INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(ap_id,radio_id));"
        "CREATE TABLE IF NOT EXISTS ac_radio_survey_cursor ("
        " ap_id TEXT NOT NULL,radio_id TEXT NOT NULL,interface TEXT NOT NULL DEFAULT '',"
        " frequency_mhz INTEGER NOT NULL,observed_at INTEGER NOT NULL,received_at INTEGER NOT NULL,"
        " session_epoch TEXT NOT NULL,source TEXT NOT NULL DEFAULT 'iw_survey',"
        " active_ms INTEGER NOT NULL,busy_ms INTEGER NOT NULL,"
        " receive_ms INTEGER,transmit_ms INTEGER,noise_dbm INTEGER,"
        " PRIMARY KEY(ap_id,radio_id));"
        "CREATE TABLE IF NOT EXISTS ac_radio_survey_bucket ("
        " sample_id INTEGER PRIMARY KEY AUTOINCREMENT,ap_id TEXT NOT NULL,radio_id TEXT NOT NULL,"
        " resolution_seconds INTEGER NOT NULL CHECK(resolution_seconds IN (300,3600)),"
        " bucket_start INTEGER NOT NULL,first_received_at INTEGER NOT NULL,last_received_at INTEGER NOT NULL,"
        " sample_count INTEGER NOT NULL,active_delta_ms INTEGER NOT NULL,busy_delta_ms INTEGER NOT NULL,"
        " receive_delta_ms INTEGER,transmit_delta_ms INTEGER,utilization_pct REAL NOT NULL,"
        " noise_dbm INTEGER,complete INTEGER NOT NULL DEFAULT 1,source TEXT NOT NULL DEFAULT 'iw_survey_delta',"
        " UNIQUE(ap_id,radio_id,resolution_seconds,bucket_start));"
        "CREATE INDEX IF NOT EXISTS idx_ac_radio_survey_bucket_range "
        "ON ac_radio_survey_bucket(ap_id,radio_id,resolution_seconds,bucket_start,sample_id);"
        "CREATE INDEX IF NOT EXISTS idx_ac_radio_survey_bucket_retention "
        "ON ac_radio_survey_bucket(resolution_seconds,last_received_at,sample_id);"
        "CREATE TABLE IF NOT EXISTS ac_radio_tx_retry_cursor ("
        " ap_id TEXT NOT NULL,radio_id TEXT NOT NULL,source TEXT NOT NULL,"
        " session_epoch TEXT NOT NULL,observed_at INTEGER NOT NULL,received_at INTEGER NOT NULL,"
        " tx_total INTEGER NOT NULL,tx_retries INTEGER NOT NULL,"
        " PRIMARY KEY(ap_id,radio_id));"
        "CREATE TABLE IF NOT EXISTS ac_radio_tx_retry_bucket ("
        " sample_id INTEGER PRIMARY KEY AUTOINCREMENT,ap_id TEXT NOT NULL,radio_id TEXT NOT NULL,"
        " resolution_seconds INTEGER NOT NULL CHECK(resolution_seconds=300),"
        " bucket_start INTEGER NOT NULL,first_received_at INTEGER NOT NULL,last_received_at INTEGER NOT NULL,"
        " sample_count INTEGER NOT NULL,tx_total_delta INTEGER NOT NULL,"
        " tx_retries_delta INTEGER NOT NULL,retry_rate_pct REAL NOT NULL,"
        " complete INTEGER NOT NULL DEFAULT 1,source TEXT NOT NULL,"
        " UNIQUE(ap_id,radio_id,resolution_seconds,bucket_start));"
        "CREATE INDEX IF NOT EXISTS idx_ac_radio_tx_retry_bucket_range "
        "ON ac_radio_tx_retry_bucket(ap_id,radio_id,resolution_seconds,bucket_start,sample_id);"
        "CREATE INDEX IF NOT EXISTS idx_ac_radio_tx_retry_bucket_retention "
        "ON ac_radio_tx_retry_bucket(resolution_seconds,last_received_at,sample_id);"
        /*
         * Periodic survey scheduling.
         *
         * mode is fixed at 'survey' and the CHECK enforces it: a neighbour scan
         * does leave the working channel (ac_radio_job_create() picks the
         * impact string by mode), so it must stay a manual, low-frequency
         * action. A survey job only reads the driver's airtime counters on the
         * channel already in use, which is why this can run on a minute-scale
         * interval without disturbing associated clients.
         *
         * Disabled by default. Enabling periodic collection is a decision for
         * the operator, not something a schema migration switches on.
         */
        "CREATE TABLE IF NOT EXISTS ac_survey_schedule ("
        " id INTEGER PRIMARY KEY CHECK(id=1),"
        " enabled INTEGER NOT NULL DEFAULT 0,"
        " mode TEXT NOT NULL DEFAULT 'survey' CHECK(mode='survey'),"
        " interval_seconds INTEGER NOT NULL DEFAULT 300"
        "   CHECK(interval_seconds BETWEEN 60 AND 3600),"
        " last_run_at INTEGER NOT NULL DEFAULT 0,"
        " last_dispatched INTEGER NOT NULL DEFAULT 0,"
        " last_error TEXT NOT NULL DEFAULT '',"
        " updated_at INTEGER NOT NULL DEFAULT 0);"
        "INSERT OR IGNORE INTO ac_survey_schedule(id) VALUES(1);"
        "CREATE TABLE IF NOT EXISTS ac_radio_jobs ("
        " job_id TEXT PRIMARY KEY,ap_id TEXT NOT NULL,radio_id TEXT NOT NULL,"
        " mode TEXT NOT NULL CHECK(mode IN ('neighbor','survey')),"
        " state TEXT NOT NULL CHECK(state IN ('queued','leased','running','cancel_requested','completed','failed','cancelled','expired')),"
        " idempotency_key TEXT NOT NULL,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,"
        " lease_owner TEXT NOT NULL DEFAULT '',lease_expires_at INTEGER NOT NULL DEFAULT 0,"
        " session_epoch TEXT NOT NULL DEFAULT '',attempt_id TEXT NOT NULL DEFAULT '',"
        " dispatch_generation INTEGER NOT NULL DEFAULT 0,"
        " request_digest TEXT NOT NULL DEFAULT '',finish_id TEXT NOT NULL DEFAULT '',"
        " finish_digest TEXT NOT NULL DEFAULT '',last_progress_at INTEGER NOT NULL DEFAULT 0,"
        " reconcile_deadline INTEGER NOT NULL DEFAULT 0,"
        " result_count INTEGER NOT NULL DEFAULT 0,"
        " result_bytes INTEGER NOT NULL DEFAULT 0,result_digest TEXT NOT NULL DEFAULT '',"
        " result_complete INTEGER NOT NULL DEFAULT 0,error_code TEXT NOT NULL DEFAULT '',"
        " expected_impact TEXT NOT NULL,result_json TEXT NOT NULL DEFAULT '[]');"
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_ac_radio_jobs_idempotency "
        "ON ac_radio_jobs(ap_id,idempotency_key);"
        "CREATE INDEX IF NOT EXISTS idx_ac_radio_jobs_state_created "
        "ON ac_radio_jobs(state,created_at);"
        "CREATE INDEX IF NOT EXISTS idx_ac_radio_jobs_target "
        "ON ac_radio_jobs(ap_id,radio_id,created_at);"
        "CREATE INDEX IF NOT EXISTS idx_ac_radio_jobs_retention "
        "ON ac_radio_jobs(ap_id,state,updated_at,job_id);"
        "CREATE TABLE IF NOT EXISTS ac_ssid_runtime ("
        " ssid_id TEXT NOT NULL,ap_id TEXT NOT NULL,radio_id TEXT NOT NULL DEFAULT '',"
        " observed_at INTEGER NOT NULL DEFAULT 0,runtime_json TEXT NOT NULL DEFAULT '{}',"
        " stale INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(ap_id,ssid_id));"
        "CREATE TABLE IF NOT EXISTS ac_station_sessions ("
        " association_id TEXT PRIMARY KEY,ap_id TEXT NOT NULL,radio_id TEXT NOT NULL,ssid_id TEXT NOT NULL,"
        " mac TEXT NOT NULL,connected_at INTEGER NOT NULL,disconnected_at INTEGER NOT NULL DEFAULT 0,"
        " last_seen_at INTEGER NOT NULL,runtime_json TEXT NOT NULL DEFAULT '{}');"
        "CREATE TABLE IF NOT EXISTS ac_station_events ("
        " event_id INTEGER PRIMARY KEY AUTOINCREMENT,ap_id TEXT NOT NULL,"
        " event TEXT NOT NULL,station_mac TEXT NOT NULL,"
        " radio_id TEXT NOT NULL DEFAULT '',ssid_id TEXT NOT NULL DEFAULT '',"
        " interface TEXT NOT NULL DEFAULT '',"
        " from_radio_id TEXT NOT NULL DEFAULT '',"
        " from_interface TEXT NOT NULL DEFAULT '',"
        " from_bssid TEXT NOT NULL DEFAULT '',to_bssid TEXT NOT NULL DEFAULT '',"
        " signal_dbm INTEGER,previous_signal_dbm INTEGER,"
        " observed_at INTEGER NOT NULL,window_started_at INTEGER NOT NULL,"
        " source TEXT NOT NULL DEFAULT 'ac_snapshot_diff',"
        " created_at INTEGER NOT NULL);"
        "CREATE INDEX IF NOT EXISTS idx_ac_station_events_ap "
        "ON ac_station_events(ap_id,event_id);"
        "CREATE TABLE IF NOT EXISTS ac_ap_traffic_bucket ("
        " sample_id INTEGER PRIMARY KEY AUTOINCREMENT,ap_id TEXT NOT NULL,"
        " resolution_seconds INTEGER NOT NULL CHECK(resolution_seconds=60),"
        " bucket_start INTEGER NOT NULL,first_observed_at INTEGER NOT NULL,"
        " last_observed_at INTEGER NOT NULL,first_received_at INTEGER NOT NULL,"
        " last_received_at INTEGER NOT NULL,sample_count INTEGER NOT NULL,"
        " duration_seconds INTEGER NOT NULL,up_bytes INTEGER NOT NULL,"
        " down_bytes INTEGER NOT NULL,station_count_sum INTEGER NOT NULL,"
        " counter_reset_count INTEGER NOT NULL DEFAULT 0,"
        " complete INTEGER NOT NULL DEFAULT 1,"
        " source TEXT NOT NULL DEFAULT 'ac_station_counter_delta',"
        " UNIQUE(ap_id,resolution_seconds,bucket_start));"
        "CREATE INDEX IF NOT EXISTS idx_ac_ap_traffic_bucket_range "
        "ON ac_ap_traffic_bucket(ap_id,resolution_seconds,bucket_start,sample_id);"
        "CREATE INDEX IF NOT EXISTS idx_ac_ap_traffic_bucket_retention "
        "ON ac_ap_traffic_bucket(resolution_seconds,last_received_at,sample_id);"
        "CREATE TABLE IF NOT EXISTS ac_transactions ("
        " transaction_id TEXT PRIMARY KEY,actor_id TEXT NOT NULL,idempotency_key TEXT NOT NULL,base_revision INTEGER NOT NULL,"
        " desired_revision INTEGER NOT NULL,state TEXT NOT NULL,consistency TEXT NOT NULL,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);"
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_ac_transactions_idempotency ON ac_transactions(actor_id,idempotency_key);"
        "CREATE TABLE IF NOT EXISTS ac_transaction_targets ("
        " transaction_id TEXT NOT NULL,ap_id TEXT NOT NULL,state TEXT NOT NULL,candidate_digest TEXT NOT NULL DEFAULT '',"
        " previous_digest TEXT NOT NULL DEFAULT '',previous_revision INTEGER NOT NULL DEFAULT 0,"
        " readback_digest TEXT NOT NULL DEFAULT '',error_code TEXT NOT NULL DEFAULT '',"
        " apply_job_id TEXT NOT NULL DEFAULT '',rollback_job_id TEXT NOT NULL DEFAULT '',"
        " updated_at INTEGER NOT NULL,PRIMARY KEY(transaction_id,ap_id));"
        "CREATE TABLE IF NOT EXISTS ac_roaming_domains ("
        " domain_id TEXT PRIMARY KEY,name TEXT NOT NULL,ssid_ids_json TEXT NOT NULL DEFAULT '[]',"
        " ap_group_ids_json TEXT NOT NULL DEFAULT '[]',security_profile_id TEXT NOT NULL DEFAULT '',"
        " mobility_domain TEXT NOT NULL DEFAULT '',ft_enabled INTEGER NOT NULL DEFAULT 0,"
        " ft_mode TEXT NOT NULL DEFAULT 'over_air' CHECK(ft_mode IN ('over_air','over_ds')),"
        " key_revision INTEGER NOT NULL DEFAULT 0,neighbor_report_enabled INTEGER NOT NULL DEFAULT 0,"
        " bss_transition_enabled INTEGER NOT NULL DEFAULT 0,deauth_enabled INTEGER NOT NULL DEFAULT 0,"
        " revision INTEGER NOT NULL DEFAULT 1,updated_at INTEGER NOT NULL,updated_by TEXT NOT NULL);"
        "CREATE TABLE IF NOT EXISTS ac_roaming_domain_members ("
        " domain_id TEXT NOT NULL,ap_id TEXT NOT NULL,radio_id TEXT NOT NULL DEFAULT '',"
        " ssid_id TEXT NOT NULL DEFAULT '',bssid TEXT NOT NULL DEFAULT '',state TEXT NOT NULL DEFAULT 'excluded'"
        " CHECK(state IN ('eligible','excluded','pending','applied','partial')),"
        " excluded_reason TEXT NOT NULL DEFAULT 'capability_unverified',"
        " applied_revision INTEGER NOT NULL DEFAULT 0,readback_revision INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL,PRIMARY KEY(domain_id,ap_id,radio_id,ssid_id));"
        "CREATE INDEX IF NOT EXISTS idx_ac_roaming_members_ap "
        "ON ac_roaming_domain_members(ap_id,domain_id);"
        "CREATE TABLE IF NOT EXISTS ac_roaming_policies ("
        " domain_id TEXT PRIMARY KEY,weak_rssi_dbm INTEGER NOT NULL DEFAULT -75,"
        " steering_preference TEXT NOT NULL DEFAULT 'stability'"
        " CHECK(steering_preference IN ('stability','performance')),"
        " high_band_steer_enabled INTEGER NOT NULL DEFAULT 0"
        " CHECK(high_band_steer_enabled IN (0,1)),"
        " force_disassoc_on_reject INTEGER NOT NULL DEFAULT 0"
        " CHECK(force_disassoc_on_reject IN (0,1)),"
        " lower_band_block_enabled INTEGER NOT NULL DEFAULT 0"
        " CHECK(lower_band_block_enabled IN (0,1)),"
        " band_steer_mode INTEGER NOT NULL DEFAULT 0"
        " CHECK(band_steer_mode IN (0,1,2)),"
        " band_steer_min_rssi_dbm INTEGER NOT NULL DEFAULT -70,"
        " minimum_candidate_gain_db INTEGER NOT NULL DEFAULT 10,"
        " candidate_min_rssi_dbm INTEGER NOT NULL DEFAULT -67,"
        " decision_min_interval_sec INTEGER NOT NULL DEFAULT 120,"
        " post_roam_cooldown_sec INTEGER NOT NULL DEFAULT 300,"
        " max_btm_attempts_per_hour INTEGER NOT NULL DEFAULT 2,"
        " deauth_after_btm_failures INTEGER NOT NULL DEFAULT 1,"
        " deauth_cooldown_sec INTEGER NOT NULL DEFAULT 900,"
        " domain_action_rate_limit INTEGER NOT NULL DEFAULT 2,"
        " revision INTEGER NOT NULL DEFAULT 1,updated_at INTEGER NOT NULL,"
        " updated_by TEXT NOT NULL);"
        "CREATE TABLE IF NOT EXISTS ac_roaming_cooldowns ("
        " domain_id TEXT NOT NULL,station_mac TEXT NOT NULL,"
        " cooldown_until INTEGER NOT NULL,reason TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL,"
        " PRIMARY KEY(domain_id,station_mac));"
        "CREATE TABLE IF NOT EXISTS ac_roaming_station_state ("
        " domain_id TEXT NOT NULL,station_mac TEXT NOT NULL,"
        " last_evaluated_at INTEGER NOT NULL DEFAULT 0,"
        " last_measurement_at INTEGER NOT NULL DEFAULT 0,"
        " measurement_transaction_id TEXT NOT NULL DEFAULT '',"
        " PRIMARY KEY(domain_id,station_mac));"
        "CREATE TABLE IF NOT EXISTS ac_roaming_exclusions ("
        " exclusion_id TEXT PRIMARY KEY,domain_id TEXT NOT NULL,"
        " rule_type TEXT NOT NULL CHECK(rule_type IN ('mac','station_group','ssid')),"
        " pattern TEXT NOT NULL,label TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);"
        "CREATE INDEX IF NOT EXISTS idx_ac_roaming_exclusions_domain "
        "ON ac_roaming_exclusions(domain_id);"
        "CREATE TABLE IF NOT EXISTS ac_roaming_audit ("
        " audit_id INTEGER PRIMARY KEY AUTOINCREMENT,domain_id TEXT NOT NULL,"
        " station_mac TEXT NOT NULL,observed_at INTEGER NOT NULL,"
        " current_ap_id TEXT NOT NULL DEFAULT '',current_bssid TEXT NOT NULL DEFAULT '',"
        " current_signal_dbm INTEGER NOT NULL DEFAULT 0,"
        " candidates_json TEXT NOT NULL DEFAULT '[]',"
        " decision TEXT NOT NULL DEFAULT '',reason TEXT NOT NULL DEFAULT '',"
        " policy_revision INTEGER NOT NULL DEFAULT 0,"
        " capability_snapshot_json TEXT NOT NULL DEFAULT '{}');"
        "CREATE INDEX IF NOT EXISTS idx_ac_roaming_audit_domain_station "
        "ON ac_roaming_audit(domain_id,station_mac,observed_at);"
        "CREATE TABLE IF NOT EXISTS ac_events ("
        " event_id TEXT PRIMARY KEY,ap_id TEXT NOT NULL DEFAULT '',topic TEXT NOT NULL,seq INTEGER NOT NULL,"
        " observed_at INTEGER NOT NULL,received_at INTEGER NOT NULL,severity TEXT NOT NULL,entity_type TEXT NOT NULL,"
        " entity_id TEXT NOT NULL,payload_json TEXT NOT NULL DEFAULT '{}');"
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_ac_events_topic_seq ON ac_events(topic,seq);"
        "CREATE TABLE IF NOT EXISTS ac_ap_audit_events ("
        " ap_id TEXT NOT NULL,event_id TEXT NOT NULL,occurred_at INTEGER NOT NULL,"
        " received_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,session_epoch TEXT NOT NULL,"
        " actor TEXT NOT NULL,actor_session TEXT NOT NULL DEFAULT '',source_ip TEXT NOT NULL DEFAULT '',"
        " action TEXT NOT NULL,risk TEXT NOT NULL,target TEXT NOT NULL,"
        " result TEXT NOT NULL CHECK(result IN ('reserved','success','failed','denied')),"
        " failure_reason TEXT NOT NULL DEFAULT '',request_id TEXT NOT NULL,"
        " schema_version INTEGER NOT NULL,source TEXT NOT NULL DEFAULT 'ap_remote'"
        " CHECK(source='ap_remote'),PRIMARY KEY(ap_id,event_id));"
        "CREATE INDEX IF NOT EXISTS idx_ac_ap_audit_received "
        "ON ac_ap_audit_events(received_at DESC,ap_id,event_id);"
        "CREATE TABLE IF NOT EXISTS ac_secrets ("
        " secret_id TEXT PRIMARY KEY NOT NULL,version INTEGER NOT NULL CHECK(version > 0),"
        " key_id TEXT NOT NULL,nonce BLOB NOT NULL CHECK(length(nonce)=12),"
        " ciphertext BLOB NOT NULL,tag BLOB NOT NULL CHECK(length(tag)=16));"
        "CREATE TABLE IF NOT EXISTS ac_config_jobs ("
        " job_id TEXT PRIMARY KEY,ap_id TEXT NOT NULL,"
        " state TEXT NOT NULL DEFAULT 'queued' CHECK(state IN"
        " ('queued','leased','running','applied','failed','rolled_back','cancelled')),"
        " idempotency_key TEXT NOT NULL,candidate_json TEXT NOT NULL,"
        " candidate_digest TEXT NOT NULL,readback_json TEXT NOT NULL DEFAULT '',"
        " transaction_id TEXT NOT NULL DEFAULT '',session_epoch TEXT NOT NULL DEFAULT '',"
        " attempt_id TEXT NOT NULL DEFAULT '',dispatch_generation INTEGER NOT NULL DEFAULT 0,"
        " request_digest TEXT NOT NULL DEFAULT '',finish_id TEXT NOT NULL DEFAULT '',"
        " outcome TEXT NOT NULL DEFAULT '' CHECK(outcome IN ('','applied','failed','rolled_back')),"
        " error_code TEXT NOT NULL DEFAULT '',lease_expires_at INTEGER NOT NULL DEFAULT 0,"
        " created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,"
        " operation TEXT NOT NULL DEFAULT 'apply',"
        " rollback_of_job_id TEXT NOT NULL DEFAULT '');"
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_ac_config_jobs_idempotency"
        " ON ac_config_jobs(ap_id,idempotency_key);"
        "CREATE INDEX IF NOT EXISTS idx_ac_config_jobs_dispatch"
        " ON ac_config_jobs(ap_id,state,created_at);"
        "CREATE TABLE IF NOT EXISTS ac_btm_actions ("
        " btm_id INTEGER PRIMARY KEY AUTOINCREMENT,domain_id TEXT NOT NULL,"
        " station_mac TEXT NOT NULL,ap_id TEXT NOT NULL DEFAULT '',"
        " source_bssid TEXT NOT NULL DEFAULT '',"
        " target_bssid TEXT NOT NULL DEFAULT '',"
        " target_bssid_2 TEXT NOT NULL DEFAULT '',"
        " sent_at INTEGER NOT NULL DEFAULT 0,sent_ok INTEGER NOT NULL DEFAULT 0,"
        " outcome TEXT NOT NULL DEFAULT 'pending'"
        " CHECK(outcome IN ('pending','roamed','not_roamed','timed_out','disabled')),"
        " outcome_at INTEGER NOT NULL DEFAULT 0,"
        " outcome_reason TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE INDEX IF NOT EXISTS idx_ac_btm_actions_domain_station"
        " ON ac_btm_actions(domain_id,station_mac,sent_at);"
        "CREATE INDEX IF NOT EXISTS idx_ac_btm_actions_outcome"
        " ON ac_btm_actions(domain_id,outcome,sent_at);"
        /* Phase 4 deauth audit.  Every column here exists because the handoff
         * requires a deauth to be answerable after the fact: who triggered it,
         * what the evidence was at the time, what BTM had already been tried,
         * whether the frame went out, and where the station ended up.
         * `outcome='returned'` is deliberately distinct from 'not_roamed' --
         * a station that comes back to the same BSSID is the ping-pong signal
         * the circuit breaker trips on, and collapsing the two would hide it. */
        "CREATE TABLE IF NOT EXISTS ac_deauth_actions ("
        " deauth_id INTEGER PRIMARY KEY AUTOINCREMENT,domain_id TEXT NOT NULL,"
        " station_mac TEXT NOT NULL,ap_id TEXT NOT NULL DEFAULT '',"
        " source_bssid TEXT NOT NULL DEFAULT '',"
        " target_bssid TEXT NOT NULL DEFAULT '',"
        " target_bssid_2 TEXT NOT NULL DEFAULT '',"
        " trigger_source TEXT NOT NULL DEFAULT 'policy'"
        " CHECK(trigger_source IN ('policy','manual')),"
        " triggered_by TEXT NOT NULL DEFAULT '',"
        " signal_dbm INTEGER NOT NULL DEFAULT 0,"
        " candidate_json TEXT NOT NULL DEFAULT '',"
        " btm_history_json TEXT NOT NULL DEFAULT '',"
        " policy_revision INTEGER NOT NULL DEFAULT 0,"
        " sent_at INTEGER NOT NULL DEFAULT 0,sent_ok INTEGER NOT NULL DEFAULT 0,"
        " outcome TEXT NOT NULL DEFAULT 'pending'"
        " CHECK(outcome IN ('pending','roamed','returned','not_roamed',"
        "'timed_out','blocked')),"
        " outcome_bssid TEXT NOT NULL DEFAULT '',"
        " outcome_at INTEGER NOT NULL DEFAULT 0,"
        " outcome_reason TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE INDEX IF NOT EXISTS idx_ac_deauth_actions_domain_station"
        " ON ac_deauth_actions(domain_id,station_mac,sent_at);"
        "CREATE INDEX IF NOT EXISTS idx_ac_deauth_actions_outcome"
        " ON ac_deauth_actions(domain_id,outcome,sent_at);"
        "CREATE TABLE IF NOT EXISTS ac_neighbor_sync_state ("
        " domain_id TEXT NOT NULL,ap_id TEXT NOT NULL,"
        " neighbor_hash TEXT NOT NULL DEFAULT '',"
        " synced_at INTEGER NOT NULL DEFAULT 0,"
        " PRIMARY KEY(domain_id,ap_id));"
        "CREATE TABLE IF NOT EXISTS ac_neighbor_sync_domains ("
        " domain_id TEXT PRIMARY KEY,enabled INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS ac_roaming_domain_action_state ("
        " domain_id TEXT PRIMARY KEY,"
        " steering_enabled INTEGER NOT NULL DEFAULT 1,"
        " disabled_reason TEXT NOT NULL DEFAULT '',"
        " disabled_at INTEGER NOT NULL DEFAULT 0,"
        " last_action_at INTEGER NOT NULL DEFAULT 0);";
    /* AP binding tables are created via ac_db_binding_schema_init() after
     * the main schema migration succeeds, so they participate in the same
     * transaction and rollback on failure. */
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (ac_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (ac_exec(schema) != 0 ||
        ac_add_column("ac_station_events", "reason", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_add_column("ac_neighbor_sync_state", "session_epoch", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_add_column("ac_neighbor_sync_state", "attempted_at", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        ac_add_column("ac_neighbor_sync_state", "attempts", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        ac_add_column("ac_neighbor_sync_state", "transaction_id", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_add_column("ac_neighbor_sync_state", "reason", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_add_column("ac_roaming_domain_action_state", "steering_station_mac", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_add_column("ac_roaming_policies", "reassoc_block_enabled", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        ac_add_column("ac_roaming_policies", "reassoc_block_sec", "INTEGER NOT NULL DEFAULT 10") != 0 ||
        ac_add_column("ac_roaming_policies", "reassoc_block_scope", "TEXT NOT NULL DEFAULT 'ap'") != 0 ||
        ac_add_column("ac_roaming_policies", "steering_preference", "TEXT NOT NULL DEFAULT 'stability'") != 0 ||
        ac_migrate_roaming_band_steering() != 0 ||
        ac_add_column("ac_roaming_policies", "force_disassoc_on_reject", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        ac_add_column("ac_roaming_policies", "lower_band_block_enabled", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        ac_add_column("ac_roaming_policies", "band_steer_mode", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        ac_add_column("ac_roaming_policies", "band_steer_min_rssi_dbm", "INTEGER NOT NULL DEFAULT -70") != 0 ||
        ac_add_column("ac_btm_actions", "policy_revision", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        ac_add_column("ac_btm_actions", "target_bssid_2", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_add_column("ac_deauth_actions", "transaction_id", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_add_column("ac_deauth_actions", "target_bssid_2", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_add_column("ac_deauth_actions", "block_scope", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_add_column("ac_deauth_actions", "block_duration_sec", "INTEGER NOT NULL DEFAULT 0") != 0 ||
#ifndef AC_DB_TEST_STANDALONE
        ac_secrets_schema_init(g_ac_db) != AC_SECRETS_OK ||
#endif
        ac_add_column("ac_pairing_tokens", "digest_version", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        ac_add_column("ac_pairing_tokens", "created_at", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        ac_add_column("ac_pairing_tokens", "revoked_at", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        ac_add_column("ac_pairing_tokens", "site_id", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_add_column("ac_pairing_tokens", "hardware_digest", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_add_column("ac_pairing_tokens", "claimed_enrollment_id", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_add_column("ac_pairing_tokens", "claimed_at", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        ac_add_column("ac_pairing_tokens", "consumed_enrollment_id", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_add_column("ac_device_certificates", "certificate_der", "BLOB NOT NULL DEFAULT X''") != 0 ||
        ac_add_column("ac_device_certificates", "fingerprint_sha256", "BLOB NOT NULL DEFAULT X''") != 0 ||
        ac_add_column("ac_device_certificates", "issuer_key_id", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_add_column("ac_device_certificates", "issued_at", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        ac_add_column("ac_device_certificates", "activated_at", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        ac_add_column("ac_aps", "reported_model", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_add_column("ac_aps", "board_name", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_add_column("ac_aps", "model_source", "TEXT NOT NULL DEFAULT 'unavailable'") != 0 ||
        ac_add_column("ac_aps", "model_available", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        ac_add_column("ac_aps", "model_reason", "TEXT NOT NULL DEFAULT 'reliable_model_source_unavailable'") != 0 ||
        ac_add_column("ac_aps", "model_override", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_add_column("ac_ap_runtime", "received_at", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        ac_add_column("ac_ap_runtime", "telemetry_sequence", "INTEGER NOT NULL DEFAULT -1") != 0 ||
        ac_add_column("ac_ap_runtime", "control_protocol_version", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        ac_add_column("ac_ap_runtime", "write_capable", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        ac_add_column("ac_ap_runtime", "session_connected", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        ac_add_column("ac_radio_survey_cursor", "source", "TEXT NOT NULL DEFAULT 'iw_survey'") != 0 ||
        ac_add_column("ac_radio_jobs", "result_json", "TEXT NOT NULL DEFAULT '[]'") != 0 ||
        ac_add_column("ac_radio_jobs", "attempt_id", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_add_column("ac_radio_jobs", "dispatch_generation", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        ac_add_column("ac_radio_jobs", "request_digest", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_add_column("ac_radio_jobs", "finish_id", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_add_column("ac_radio_jobs", "finish_digest", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_add_column("ac_radio_jobs", "last_progress_at", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        ac_add_column("ac_radio_jobs", "reconcile_deadline", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        ac_add_column("ac_ssids", "secret_present", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        ac_add_column("ac_ssid_bindings", "updated_at", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        ac_add_column("ac_ssid_bindings", "section_name", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_add_column("ac_transaction_targets", "previous_revision", "INTEGER NOT NULL DEFAULT 0") != 0 ||
        ac_add_column("ac_transaction_targets", "apply_job_id", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_add_column("ac_transaction_targets", "rollback_job_id", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_add_column("ac_config_jobs", "operation", "TEXT NOT NULL DEFAULT 'apply'") != 0 ||
        ac_add_column("ac_config_jobs", "rollback_of_job_id", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_exec("UPDATE ac_transaction_targets SET apply_job_id=(SELECT "
                "job_id FROM ac_config_jobs j WHERE j.transaction_id="
                "ac_transaction_targets.transaction_id AND j.ap_id="
                "ac_transaction_targets.ap_id AND j.operation='apply' "
                "ORDER BY j.created_at,j.job_id LIMIT 1) WHERE "
                "apply_job_id='' AND EXISTS (SELECT 1 FROM ac_config_jobs j "
                "WHERE j.transaction_id=ac_transaction_targets.transaction_id "
                "AND j.ap_id=ac_transaction_targets.ap_id AND "
                "j.operation='apply')") != 0 ||
        ac_add_column("ac_btm_actions", "transaction_id", "TEXT NOT NULL DEFAULT ''") != 0 ||
        ac_exec("CREATE INDEX IF NOT EXISTS idx_ac_pairing_tokens_state "
                "ON ac_pairing_tokens(consumed_at,revoked_at,expires_at)") != 0 ||
        ac_exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_ac_device_cert_active "
                "ON ac_device_certificates(ap_id) WHERE state='active'") != 0)
        goto rollback;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_pairing_tokens SET revoked_at=?1 "
            "WHERE digest_version<>?2 AND consumed_at=0 AND revoked_at=0",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_int64(st, 1, ac_now_s());
    sqlite3_bind_int(st, 2, AC_PAIRING_DIGEST_VERSION);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_schema_meta(singleton,version,owner,migrated_at) VALUES(1,?1,?2,?3) "
            "ON CONFLICT(singleton) DO UPDATE SET version=excluded.version,owner=excluded.owner,migrated_at=excluded.migrated_at "
            "WHERE ac_schema_meta.version<excluded.version OR ac_schema_meta.owner<>excluded.owner",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_int(st, 1, AC_SCHEMA_VERSION);
    sqlite3_bind_text(st, 2, AC_SERVICE_NAME, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 3, ac_now_s());
    if (sqlite3_step(st) != SQLITE_DONE)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (ac_exec("COMMIT") != 0) {
        ac_exec("ROLLBACK");
        return -1;
    }
    return 0;

rollback:
    sqlite3_finalize(st);
    ac_exec("ROLLBACK");
    return rc;
}

static int ac_ap_audit_text_valid(const char *value, size_t minimum,
                                  size_t maximum)
{
    size_t length;

    if (!value)
        return 0;
    length = strlen(value);
    return length >= minimum && length <= maximum;
}

static int ac_ap_audit_result_valid(const char *result)
{
    return result && (!strcmp(result, "reserved") ||
                      !strcmp(result, "success") ||
                      !strcmp(result, "failed") ||
                      !strcmp(result, "denied"));
}

static int ac_ap_audit_hex_valid(const char *value, size_t length)
{
    size_t i;

    if (!value || strlen(value) != length)
        return 0;
    for (i = 0; i < length; i++) {
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f') ||
              (value[i] >= 'A' && value[i] <= 'F')))
            return 0;
    }
    return 1;
}

static int ac_ap_audit_actor_session_valid(const char *value)
{
    if (!value || !value[0])
        return 1;
    if (!strncmp(value, "sha256:", 7))
        return ac_ap_audit_hex_valid(value + 7, 64);
    if (!strncmp(value, "api_key:", 8))
        return ac_ap_audit_hex_valid(value + 8, 16);
    return 0;
}

static int ac_ap_audit_risk_valid(const char *risk)
{
    return risk && (!strcmp(risk, "low") || !strcmp(risk, "low_write") ||
                    !strcmp(risk, "medium") || !strcmp(risk, "high") ||
                    !strcmp(risk, "blocked") || !strcmp(risk, "critical"));
}

static int ac_ap_audit_result_reason_valid(const char *result,
                                           const char *failure_reason)
{
    if (!result || !failure_reason)
        return 0;
    if (!strcmp(result, "reserved") || !strcmp(result, "success"))
        return failure_reason[0] == '\0';
    return failure_reason[0] != '\0';
}

/* The transport result alone does not prove logd or notifyd persisted anything. */
#ifndef AC_DB_TEST_STANDALONE
static void ac_wifi_failure_reply(struct ubus_request *req, int type,
                                   struct blob_attr *msg)
{
    int *persisted = req ? req->priv : NULL;
    char *text = msg ? blobmsg_format_json(msg, true) : NULL;
    struct json_object *reply = text ? json_tokener_parse(text) : NULL;
    struct json_object *ok = NULL, *notified = NULL;
    (void)type;
    if (persisted && reply && json_object_object_get_ex(reply, "ok", &ok) &&
        json_object_get_boolean(ok) &&
        json_object_object_get_ex(reply, "notified", &notified) &&
        json_object_get_boolean(notified)) *persisted = 1;
    json_object_put(reply);
    free(text);
}
#endif
static int ac_wifi_failure_send(struct json_object *event)
{
#ifdef AC_DB_TEST_STANDALONE
#ifdef AC_DB_WIFI_FAILURE_TEST
    extern int ac_wifi_failure_test_send(struct json_object *event);
    return ac_wifi_failure_test_send(event);
#else
    (void)event;
    return -1; /* A database-only test has no log/notification transport. */
#endif
#else
    struct ubus_context *ctx = ubus_connect(NULL);
    struct blob_buf blob = {};
    uint32_t id;
    int persisted = 0, rc = -1;
    if (ctx && ubus_lookup_id(ctx, "dreamingwrt.logd", &id) == UBUS_STATUS_OK) {
        blob_buf_init(&blob, 0);
        if (blobmsg_add_json_from_string(&blob,
                json_object_to_json_string_ext(event, JSON_C_TO_STRING_PLAIN)))
            rc = ubus_invoke(ctx, id, "event_add", blob.head,
                             ac_wifi_failure_reply, &persisted, 1500);
        blob_buf_free(&blob);
    }
    if (ctx) ubus_free(ctx);
    return rc == UBUS_STATUS_OK && persisted ? 0 : -1;
#endif
}

/* An AP supplies only a bounded identifier record; the authenticated transport
 * supplies ap_id. Rebuild the log payload from the allow-list before publishing. */
static int ac_wifi_failure_publish(const char *action, const char *ap_id,
    const char *actor, const char *target, const char *code, int64_t occurred_at)
{
    struct json_object *input = json_tokener_parse(target);
    struct json_object *event = json_object_new_object();
    struct json_object *detail, *value = NULL;
    const char *operation = !strcmp(action, "WIFI_CONFIG_SAVE_FAILED") ? "wifi_config_save" : "wifi_config_apply";
    const char *stage = "ap.wifi";
    int rc;
    if (input && json_object_object_get_ex(input, "operation", &value) &&
        json_object_is_type(value, json_type_string) &&
        !strcmp(json_object_get_string(value), "wifi_config_save")) operation = "wifi_config_save";
    if (input && json_object_object_get_ex(input, "failure_stage", &value))
        stage = dw_wifi_failure_token(json_object_get_string(value), "ap.wifi");
    detail = dw_wifi_failure_detail(operation, "managed_ap", actor, ap_id,
                                    ap_id, code, stage, occurred_at / 1000);
    json_object_put(input);
    json_object_object_add(detail, "actor", json_object_new_string(actor));
    json_object_object_add(event, "event", json_object_new_string(action));
    json_object_object_add(event, "category", json_object_new_string("ADMIN"));
    json_object_object_add(event, "source", json_object_new_string("dreamingwrt-ac"));
    json_object_object_add(event, "severity", json_object_new_string("error"));
    json_object_object_add(event, "title", json_object_new_string(action));
    json_object_object_add(event, "notify", json_object_new_boolean(1));
    json_object_object_add(event, "ts", json_object_new_int64(occurred_at / 1000));
    if (json_object_object_get_ex(detail, "dedupe_key", &value))
        json_object_object_add(event, "dedupe_key", json_object_get(value));
    json_object_object_add(event, "detail_json", detail);
    rc = ac_wifi_failure_send(event);
    json_object_put(event);
    return rc;
}

int ac_db_ap_audit_store(const char *ap_id, const char *event_id,
                         int64_t occurred_at, const char *session_epoch,
                         const char *actor, const char *actor_session,
                         const char *source_ip, const char *action,
                         const char *risk, const char *target,
                         const char *result, const char *failure_reason,
                         const char *request_id, int64_t schema_version)
{
    sqlite3_stmt *st = NULL;
    int exists = 0;
    int stable_match = 0;
    int same_final = 0;
    int current_reserved = 0;
    int64_t now = ac_now_s();

    if (!g_ac_db || !ac_uuid_valid(ap_id) || !ac_uuid_valid(event_id) ||
        occurred_at <= 0 || now <= 0 || schema_version != 1 ||
        !ac_ap_audit_text_valid(session_epoch, 64, 64) ||
        !ac_ap_audit_text_valid(actor, 1, 95) ||
        !ac_ap_audit_text_valid(actor_session, 0, 128) ||
        !ac_ap_audit_actor_session_valid(actor_session) ||
        !ac_ap_audit_text_valid(source_ip, 0, 64) ||
        !ac_ap_audit_text_valid(action, 1, 128) ||
        !ac_ap_audit_text_valid(risk, 1, 15) ||
        !ac_ap_audit_risk_valid(risk) ||
        !ac_ap_audit_text_valid(target, 1, 512) ||
        !ac_ap_audit_result_valid(result) ||
        !ac_ap_audit_text_valid(failure_reason, 0, 256) ||
        !ac_ap_audit_result_reason_valid(result, failure_reason) ||
        !ac_ap_audit_text_valid(request_id, 1, 64) ||
        ac_exec("BEGIN IMMEDIATE") != 0)
        return -1;

    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT occurred_at,session_epoch,actor,actor_session,source_ip,"
            "action,risk,target,result,failure_reason,request_id,schema_version "
            "FROM ac_ap_audit_events WHERE ap_id=?1 AND event_id=?2",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, event_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *stored_result =
            (const char *)sqlite3_column_text(st, 8);
        const char *stored_reason =
            (const char *)sqlite3_column_text(st, 9);

        exists = 1;
        stable_match = sqlite3_column_int64(st, 0) == occurred_at &&
            !strcmp((const char *)sqlite3_column_text(st, 1), session_epoch) &&
            !strcmp((const char *)sqlite3_column_text(st, 2), actor) &&
            !strcmp((const char *)sqlite3_column_text(st, 3), actor_session) &&
            !strcmp((const char *)sqlite3_column_text(st, 4), source_ip) &&
            !strcmp((const char *)sqlite3_column_text(st, 5), action) &&
            !strcmp((const char *)sqlite3_column_text(st, 6), risk) &&
            !strcmp((const char *)sqlite3_column_text(st, 7), target) &&
            !strcmp((const char *)sqlite3_column_text(st, 10), request_id) &&
            sqlite3_column_int64(st, 11) == schema_version;
        current_reserved = stored_result && !strcmp(stored_result, "reserved");
        same_final = stored_result && stored_reason &&
            !strcmp(stored_result, result) &&
            !strcmp(stored_reason, failure_reason);
    }
    sqlite3_finalize(st);
    st = NULL;

    if (exists) {
        if (!stable_match || (!current_reserved && !same_final) ||
            (current_reserved && !strcmp(result, "reserved") &&
             failure_reason[0]))
            goto rollback;
        if (current_reserved && strcmp(result, "reserved")) {
            if (sqlite3_prepare_v2(g_ac_db,
                    "UPDATE ac_ap_audit_events SET result=?3,failure_reason=?4,"
                    "updated_at=?5 WHERE ap_id=?1 AND event_id=?2 AND result='reserved'",
                    -1, &st, NULL) != SQLITE_OK)
                goto rollback;
            sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, event_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, result, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 4, failure_reason, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 5, now);
            if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
                goto rollback;
            sqlite3_finalize(st);
            st = NULL;
        }
    } else {
        if (sqlite3_prepare_v2(g_ac_db,
                "INSERT INTO ac_ap_audit_events("
                "ap_id,event_id,occurred_at,received_at,updated_at,session_epoch,"
                "actor,actor_session,source_ip,action,risk,target,result,"
                "failure_reason,request_id,schema_version,source) VALUES("
                "?1,?2,?3,?4,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,'ap_remote')",
                -1, &st, NULL) != SQLITE_OK)
            goto rollback;
        sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, event_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, occurred_at);
        sqlite3_bind_int64(st, 4, now);
        sqlite3_bind_text(st, 5, session_epoch, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, actor, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, actor_session, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, source_ip, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, action, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 10, risk, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 11, target, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 12, result, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 13, failure_reason, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 14, request_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 15, schema_version);
        if (sqlite3_step(st) != SQLITE_DONE)
            goto rollback;
        sqlite3_finalize(st);
        st = NULL;
    }

    if (ac_exec("COMMIT") == 0) {
        if (dw_wifi_failure_event(action) && !strcmp(result, "failed"))
            return ac_wifi_failure_publish(action, ap_id, actor, target,
                                           failure_reason, occurred_at);
        return 0;
    }
rollback:
    sqlite3_finalize(st);
    ac_exec("ROLLBACK");
    return -1;
}

/* The REST acceptance precedes the AP receipt. Emit the final failure from
 * the committed job, never from its secret-bearing candidate/readback body. */
static void AC_DB_STANDALONE_UNUSED
ac_wifi_job_failure_observe(const char *transaction_id, const char *ap_id,
    const char *session_epoch, const char *finish_id, const char *error_code,
    int64_t now)
{
    sqlite3_stmt *st = NULL;
    char actor[96] = "system:ac";
    struct json_object *detail;
    const char *target, *code, *event;
    if (!transaction_id || !transaction_id[0]) return;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT actor_id FROM ac_transactions WHERE transaction_id=?1",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, transaction_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_text(st, 0))
            snprintf(actor, sizeof(actor), "%s", (const char *)sqlite3_column_text(st, 0));
    }
    sqlite3_finalize(st);
    code = dw_wifi_failure_token(error_code, "operation_failed");
    event = dw_wifi_failure_id("wifi_config_apply", code);
    detail = dw_wifi_failure_detail("wifi_config_apply", "managed_ap", actor,
        ap_id, ap_id, code, "ac.wifi.transaction", now);
    if (!detail) return;
    target = json_object_to_json_string_ext(detail, JSON_C_TO_STRING_PLAIN);
    /* An unavailable sink does not rewrite the actual transaction outcome. */
    ac_db_ap_audit_store(ap_id, finish_id, now * 1000, session_epoch, actor,
        "", "", event, "medium", target, "failed", code, transaction_id, 1);
    json_object_put(detail);
}

struct json_object *ac_db_ap_audit_events_json(const char *ap_id, int limit,
                                               int64_t before_received_at)
{
    struct json_object *root = json_object_new_object();
    struct json_object *items = json_object_new_array();
    sqlite3_stmt *st = NULL;
    int count = 0;

    if (!root || !items) {
        json_object_put(root);
        json_object_put(items);
        return NULL;
    }
    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "items", items);
    if (!g_ac_db || (ap_id && ap_id[0] && !ac_uuid_valid(ap_id)) ||
        limit < 1 || limit > 500 || before_received_at < 0) {
        json_object_object_add(root, "error",
                               json_object_new_string("invalid_request"));
        return root;
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT ap_id,event_id,occurred_at,received_at,updated_at,"
            "session_epoch,actor,actor_session,source_ip,action,risk,target,"
            "result,failure_reason,request_id,schema_version,source "
            "FROM ac_ap_audit_events WHERE (?1='' OR ap_id=?1) "
            "AND (?2=0 OR received_at<?2) "
            "ORDER BY received_at DESC,ap_id,event_id LIMIT ?3",
            -1, &st, NULL) != SQLITE_OK) {
        json_object_object_add(root, "error",
                               json_object_new_string("database_error"));
        return root;
    }
    sqlite3_bind_text(st, 1, ap_id ? ap_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, before_received_at);
    sqlite3_bind_int(st, 3, limit);
    while (sqlite3_step(st) == SQLITE_ROW) {
        static const char *const names[] = {
            "ap_id", "event_id", NULL, NULL, NULL, "session_epoch", "actor",
            "actor_session", "source_ip", "action", "risk", "target",
            "result", "failure_reason", "request_id", NULL, "source"
        };
        struct json_object *item = json_object_new_object();
        int i;

        if (!item)
            break;
        for (i = 0; i < 17; i++) {
            if (i == 2)
                json_object_object_add(item, "occurred_at",
                    json_object_new_int64(sqlite3_column_int64(st, i)));
            else if (i == 3)
                json_object_object_add(item, "received_at",
                    json_object_new_int64(sqlite3_column_int64(st, i)));
            else if (i == 4)
                json_object_object_add(item, "updated_at",
                    json_object_new_int64(sqlite3_column_int64(st, i)));
            else if (i == 15)
                json_object_object_add(item, "schema_version",
                    json_object_new_int64(sqlite3_column_int64(st, i)));
            else
                json_object_object_add(item, names[i], json_object_new_string(
                    (const char *)sqlite3_column_text(st, i)));
        }
        json_object_array_add(items, item);
        count++;
    }
    sqlite3_finalize(st);
    json_object_object_del(root, "ok");
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "count", json_object_new_int(count));
    return root;
}

static int ac_integrity_check(void)
{
    sqlite3_stmt *st = NULL;
    int ok = 0;

    if (sqlite3_prepare_v2(g_ac_db, "PRAGMA quick_check(1)", -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW && sqlite3_column_text(st, 0) &&
        strcmp((const char *)sqlite3_column_text(st, 0), "ok") == 0)
        ok = 1;
    sqlite3_finalize(st);
    return ok ? 0 : -1;
}

static int ac_pairing_tokens_validate(void)
{
    sqlite3_stmt *st = NULL;
    char site[AC_PAIRING_SITE_ID_LEN + 1];
    char hardware[AC_PAIRING_HARDWARE_DIGEST_LEN + 1];
    const unsigned char *token_id;
    const unsigned char *site_id;
    const unsigned char *hardware_digest;
    int rc = -1;

    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT token_id,token_hash,digest_version,created_at,expires_at,max_attempts,"
            "attempts,site_id,hardware_digest FROM ac_pairing_tokens "
            "WHERE consumed_at=0 AND revoked_at=0 AND expires_at>?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, ac_now_s());
    while (sqlite3_step(st) == SQLITE_ROW) {
        token_id = sqlite3_column_text(st, 0);
        site_id = sqlite3_column_text(st, 7);
        hardware_digest = sqlite3_column_text(st, 8);
        if (!token_id || !site_id || !hardware_digest ||
            !ac_uuid_valid((const char *)token_id) ||
            sqlite3_column_bytes(st, 1) != AC_PAIRING_DIGEST_LEN ||
            !sqlite3_column_blob(st, 1) ||
            sqlite3_column_int(st, 2) != AC_PAIRING_DIGEST_VERSION ||
            sqlite3_column_int64(st, 3) <= 0 ||
            sqlite3_column_int64(st, 4) <= sqlite3_column_int64(st, 3) ||
            sqlite3_column_int(st, 5) < 1 ||
            sqlite3_column_int(st, 5) > AC_PAIRING_TOKEN_ATTEMPTS_MAX ||
            sqlite3_column_int(st, 6) < 0 ||
            sqlite3_column_int(st, 6) > sqlite3_column_int(st, 5) ||
            ac_site_id_normalize((const char *)site_id, site) != 0 ||
            ac_hardware_digest_normalize((const char *)hardware_digest,
                                         hardware) != 0)
            goto done;
    }
    rc = 0;
done:
    sqlite3_finalize(st);
    OPENSSL_cleanse(hardware, sizeof(hardware));
    return rc;
}

static int ac_enrollment_state_validate(void)
{
    sqlite3_stmt *st = NULL;
    int invalid = 1;

    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT COUNT(*) FROM ac_enrollments e "
            "LEFT JOIN ac_pairing_tokens t ON t.token_id=e.token_id "
            "LEFT JOIN ac_aps a ON a.ap_id=e.ap_id "
            "LEFT JOIN ac_device_certificates c ON c.certificate_id=e.certificate_id "
            "WHERE t.token_id IS NULL OR a.ap_id IS NULL OR "
            "(e.state='claimed' AND (t.claimed_enrollment_id<>e.enrollment_id OR "
            "t.consumed_at<>0 OR e.certificate_id<>'')) OR "
            "(e.state='mtls_pending' AND (t.claimed_enrollment_id<>e.enrollment_id OR "
            "t.consumed_at<=0 OR t.consumed_enrollment_id<>e.enrollment_id OR "
            "c.certificate_id IS NULL OR c.state<>'pending_activation' OR "
            "c.ap_id<>e.ap_id OR a.adoption_state<>'pending_pairing')) OR "
            "(e.state='adopted' AND (t.consumed_at<=0 OR "
            "t.consumed_enrollment_id<>e.enrollment_id OR c.certificate_id IS NULL OR "
            "c.state<>'active' OR c.ap_id<>e.ap_id OR "
            "(a.adoption_state<>'adopted' AND NOT (a.adoption_state='unbinding' "
            "AND EXISTS(SELECT 1 FROM ac_ap_unbind_requests u WHERE u.ap_id=e.ap_id "
            "AND u.enrollment_id=e.enrollment_id AND u.certificate_id=e.certificate_id "
            "AND u.state='pending'))))) OR "
            "(e.state IN ('claimed','mtls_pending') AND a.adoption_state='adopted') OR "
            "(e.activation_challenge_hash IS NOT NULL AND "
            "length(e.activation_challenge_hash)<>32)", -1, &st, NULL) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_ROW)
        goto done;
    invalid = sqlite3_column_int(st, 0) != 0;
done:
    sqlite3_finalize(st);
    return invalid ? -1 : 0;
}

static int ac_radio_jobs_recover_after_restart(void)
{
    sqlite3_stmt *st = NULL;
    int64_t now = ac_now_s();

    if (ac_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_radio_jobs SET updated_at=?1,reconcile_deadline=?2,"
            "error_code=CASE WHEN error_code='' THEN 'controller_restart_reconcile_pending' "
            "ELSE error_code END WHERE state IN ('leased','running','cancel_requested')",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_int64(st, 2, now + AC_RADIO_JOB_RECONCILE_SECONDS);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto rollback;
    sqlite3_finalize(st);
    if (ac_exec("COMMIT") == 0)
        return 0;
    return -1;
rollback:
    sqlite3_finalize(st);
    ac_exec("ROLLBACK");
    return -1;
}

int ac_db_init(void)
{
    mode_t old_umask;
    int open_flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                     SQLITE_OPEN_FULLMUTEX;
    int lock_fd;

    lock_fd = ac_init_lock_acquire(ac_db_path());
    if (lock_fd < 0 || ac_prepare_db_file(ac_db_path()) != 0) {
        ac_init_lock_release(lock_fd);
        return -1;
    }
    old_umask = umask(0077);
#if defined(SQLITE_OPEN_NOFOLLOW) && !defined(AC_DB_TEST_STANDALONE)
    open_flags |= SQLITE_OPEN_NOFOLLOW;
#endif
    if (sqlite3_open_v2(ac_db_path(), &g_ac_db, open_flags, NULL) != SQLITE_OK) {
        fprintf(stderr, "[%s] cannot open %s: %s\n", AC_SERVICE_NAME,
                ac_db_path(), g_ac_db ? sqlite3_errmsg(g_ac_db) : "open failed");
        ac_db_close();
        umask(old_umask);
        ac_init_lock_release(lock_fd);
        return -1;
    }
    sqlite3_busy_timeout(g_ac_db, 5000);
    if (ac_exec("PRAGMA foreign_keys=ON") != 0 || ac_integrity_check() != 0 ||
        ac_schema_migrate() != 0 || ac_pairing_tokens_validate() != 0 ||
        ac_db_binding_schema_init() != 0 ||
        ac_client_history_init(g_ac_db) != 0 ||
        ac_enrollment_state_validate() != 0 ||
        ac_radio_jobs_recover_after_restart() != 0 ||
#if !defined(AC_DB_TEST_STANDALONE) || defined(AC_DB_TELEMETRY_TEST_STANDALONE)
        ac_db_config_jobs_recover(ac_now_s()) != AC_CONFIG_JOB_OK ||
#endif
#ifndef AC_DB_TEST_STANDALONE
        ac_certificate_lifecycle_init(g_ac_db) != 0 ||
        ac_exec("UPDATE ac_ap_runtime SET session_connected=0,write_capable=0") != 0 ||
#endif
        ac_validate_db_file(ac_db_path()) != 0) {
        fprintf(stderr, "[%s] controller database validation failed\n", AC_SERVICE_NAME);
        ac_db_close();
        umask(old_umask);
        ac_init_lock_release(lock_fd);
        return -1;
    }
    umask(old_umask);
    ac_init_lock_release(lock_fd);
    return 0;
}

void ac_db_close(void)
{
    if (g_ac_db)
        sqlite3_close(g_ac_db);
    g_ac_db = NULL;
}

int ac_db_count(const char *table)
{
    static const char *const allowed[] = {
        "ac_aps", "ac_ssids", "ac_radio_runtime", "ac_ssid_runtime",
        "ac_station_sessions", "ac_radio_jobs",
        "ac_transactions", NULL
    };
    sqlite3_stmt *st = NULL;
    char sql[96];
    int count = 0;
    int allowed_table = 0;
    size_t i;

    for (i = 0; allowed[i]; i++) {
        if (table && strcmp(table, allowed[i]) == 0) {
            allowed_table = 1;
            break;
        }
    }
    if (!allowed_table || !g_ac_db)
        return 0;
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s", table);
    if (sqlite3_prepare_v2(g_ac_db, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        count = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return count;
}

int ac_db_managed_ap_counts(int64_t online_since, int *total, int *online)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!g_ac_db || !total || !online || online_since <= 0)
        return -1;
    *total = 0;
    *online = 0;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT COUNT(*),COALESCE(SUM(CASE WHEN last_seen_at>=?1 THEN 1 ELSE 0 END),0) "
            "FROM ac_aps WHERE adoption_state='adopted'",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, online_since);
    if (sqlite3_step(st) == SQLITE_ROW) {
        *total = sqlite3_column_int(st, 0);
        *online = sqlite3_column_int(st, 1);
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

static int ac_db_session_epoch_valid(const char *session_epoch)
{
    size_t i;

    if (!session_epoch || strlen(session_epoch) != 64)
        return 0;
    for (i = 0; i < 64; i++)
        if (!((session_epoch[i] >= '0' && session_epoch[i] <= '9') ||
              (session_epoch[i] >= 'a' && session_epoch[i] <= 'f')))
            return 0;
    return 1;
}

static int ac_db_ap_session_begin_with_capabilities_locked(
    const char *ap_id, const char *session_epoch, int protocol_version,
    int write_capable, int64_t received_at)
{
    sqlite3_stmt *st = NULL;

    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_aps SET last_seen_at=MAX(last_seen_at,?1) "
            "WHERE ap_id=?2 AND (adoption_state='adopted' OR "
            "(adoption_state='unbinding' AND EXISTS(SELECT 1 "
            "FROM ac_ap_unbind_requests u WHERE u.ap_id=ac_aps.ap_id "
            "AND u.state='pending')))",
            -1, &st, NULL) != SQLITE_OK)
        goto failed;
    sqlite3_bind_int64(st, 1, received_at);
    sqlite3_bind_text(st, 2, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto failed;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_ap_runtime(ap_id,boot_id,stale,telemetry_sequence,"
            "control_protocol_version,write_capable,session_connected) "
            "VALUES(?1,?2,1,-1,?3,?4,1) ON CONFLICT(ap_id) DO UPDATE SET "
            "boot_id=excluded.boot_id,stale=1,telemetry_sequence=-1,"
            "control_protocol_version=excluded.control_protocol_version,"
            "write_capable=excluded.write_capable,"
            "session_connected=1",
            -1, &st, NULL) != SQLITE_OK)
        goto failed;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, session_epoch, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, protocol_version);
    sqlite3_bind_int(st, 4, write_capable);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto failed;
    sqlite3_finalize(st);
    return 0;

failed:
    sqlite3_finalize(st);
    return -1;
}

static int ac_db_ap_session_args_valid(
    const char *ap_id, const char *session_epoch, int protocol_version,
    int write_capable, int64_t received_at)
{
    return g_ac_db && ac_uuid_valid(ap_id) &&
        ac_db_session_epoch_valid(session_epoch) &&
        (protocol_version == 1 || protocol_version == 2 ||
         protocol_version == 3) &&
        (write_capable == 0 || write_capable == 1) &&
        (!write_capable || protocol_version == 3) && received_at > 0;
}

int ac_db_ap_session_begin_with_capabilities(
    const char *ap_id, const char *session_epoch, int protocol_version,
    int write_capable, int64_t received_at)
{
    if (!ac_db_ap_session_args_valid(ap_id, session_epoch, protocol_version,
                                     write_capable, received_at) ||
        ac_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (ac_db_ap_session_begin_with_capabilities_locked(
            ap_id, session_epoch, protocol_version, write_capable,
            received_at) == 0 && ac_exec("COMMIT") == 0)
        return 0;
    ac_exec("ROLLBACK");
    return -1;
}

static int ac_db_unbind_request_read(sqlite3_stmt *st,
                                     struct ac_ap_unbind_request *out)
{
    const unsigned char *value;

    if (!st || !out)
        return -1;
    memset(out, 0, sizeof(*out));
    value = sqlite3_column_text(st, 0);
    if (!value || !ac_uuid_valid((const char *)value))
        return -1;
    snprintf(out->request_id, sizeof(out->request_id), "%s", value);
    value = sqlite3_column_text(st, 1);
    if (!value || !ac_uuid_valid((const char *)value))
        return -1;
    snprintf(out->ap_id, sizeof(out->ap_id), "%s", value);
    value = sqlite3_column_text(st, 2);
    if (value)
        snprintf(out->certificate_id, sizeof(out->certificate_id), "%s", value);
    value = sqlite3_column_text(st, 3);
    if (value)
        snprintf(out->enrollment_id, sizeof(out->enrollment_id), "%s", value);
    value = sqlite3_column_text(st, 4);
    if (!value || strlen((const char *)value) >= sizeof(out->state))
        return -1;
    snprintf(out->state, sizeof(out->state), "%s", value);
    out->requested_at = sqlite3_column_int64(st, 5);
    out->acknowledged_at = sqlite3_column_int64(st, 6);
    value = sqlite3_column_text(st, 7);
    if (value)
        snprintf(out->error_code, sizeof(out->error_code), "%s", value);
    return 0;
}

int ac_db_ap_unbind_request_pending(const char *ap_id,
                                    struct ac_ap_unbind_request *out)
{
    sqlite3_stmt *st = NULL;
    int step;
    int rc = AC_AP_UNBIND_DB;

    if (!g_ac_db || !ac_uuid_valid(ap_id) || !out ||
        sqlite3_prepare_v2(g_ac_db,
            "SELECT request_id,ap_id,certificate_id,enrollment_id,state,"
            "requested_at,acknowledged_at,error_code FROM ac_ap_unbind_requests "
            "WHERE ap_id=?1 AND state='pending' LIMIT 1", -1, &st, NULL) != SQLITE_OK)
        return AC_AP_UNBIND_DB;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    step = sqlite3_step(st);
    if (step == SQLITE_ROW)
        rc = ac_db_unbind_request_read(st, out);
    else if (step == SQLITE_DONE) {
        memset(out, 0, sizeof(*out));
        rc = AC_AP_UNBIND_NOT_FOUND;
    }
    sqlite3_finalize(st);
    return rc;
}

int ac_db_ap_unbind_request_status(const char *ap_id,
                                   struct ac_ap_unbind_request *out)
{
    sqlite3_stmt *st = NULL;
    int rc = AC_AP_UNBIND_DB;

    if (!g_ac_db || !ac_uuid_valid(ap_id) || !out ||
        sqlite3_prepare_v2(g_ac_db,
            "SELECT request_id,ap_id,certificate_id,enrollment_id,state,"
            "requested_at,acknowledged_at,error_code FROM ac_ap_unbind_requests "
            "WHERE ap_id=?1 ORDER BY requested_at DESC,rowid DESC LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
        return rc;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    int step = sqlite3_step(st);
    if (step == SQLITE_ROW)
        rc = ac_db_unbind_request_read(st, out);
    else if (step == SQLITE_DONE)
        rc = AC_AP_UNBIND_NOT_FOUND;
    sqlite3_finalize(st);
    return rc;
}

int ac_db_ap_session_begin_with_capabilities_and_unbind(
    const char *ap_id, const char *session_epoch, int protocol_version,
    int write_capable, int64_t received_at,
    struct ac_ap_unbind_request *unbind_out)
{
    int pending;

    if (unbind_out)
        memset(unbind_out, 0, sizeof(*unbind_out));
    if (!ac_db_ap_session_args_valid(ap_id, session_epoch, protocol_version,
                                     write_capable, received_at) ||
        ac_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    pending = ac_db_ap_unbind_request_pending(ap_id, unbind_out);
    if (pending != AC_AP_UNBIND_OK && pending != AC_AP_UNBIND_NOT_FOUND)
        goto rollback;
    if (ac_db_ap_session_begin_with_capabilities_locked(
            ap_id, session_epoch, protocol_version,
            pending == AC_AP_UNBIND_OK ? 0 : write_capable,
            received_at) != 0)
        goto rollback;
    if (ac_exec("COMMIT") == 0)
        return 0;
rollback:
    ac_exec("ROLLBACK");
    return -1;
}

int ac_db_ap_unbind_request_create(const char *ap_id,
                                   struct ac_ap_unbind_request *out)
{
    sqlite3_stmt *st = NULL;
    struct ac_ap_unbind_request existing;
    char request_id[AC_AP_UNBIND_REQUEST_ID_LEN + 1] = {0};
    char certificate_id[AC_ENROLLMENT_ID_LEN + 1] = {0};
    char enrollment_id[AC_ENROLLMENT_ID_LEN + 1] = {0};
    int64_t now = ac_now_s();
    int rc = AC_AP_UNBIND_DB;

    if (out)
        memset(out, 0, sizeof(*out));
    if (!g_ac_db || !ac_uuid_valid(ap_id) || now <= 0)
        return AC_AP_UNBIND_NOT_ADOPTED;
    if (ac_exec("BEGIN IMMEDIATE") != 0)
        return AC_AP_UNBIND_DB;
    rc = ac_db_ap_unbind_request_pending(ap_id, &existing);
    if (rc == AC_AP_UNBIND_OK) {
        if (out)
            *out = existing;
        goto done;
    }
    if (rc != AC_AP_UNBIND_NOT_FOUND)
        goto done;
    rc = AC_AP_UNBIND_DB;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT a.ap_id,COALESCE(c.certificate_id,''),"
            "COALESCE(e.enrollment_id,'') FROM ac_aps a "
            "LEFT JOIN ac_enrollments e ON e.ap_id=a.ap_id AND e.state='adopted' "
            "LEFT JOIN ac_device_certificates c ON c.certificate_id=e.certificate_id "
            "AND c.ap_id=a.ap_id AND c.state='active' "
            "WHERE a.ap_id=?1 AND a.adoption_state='adopted' LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) {
        rc = ac_db_ap_unbind_request_status(ap_id, &existing);
        if (rc == AC_AP_UNBIND_OK && !strcmp(existing.state, "completed")) {
            if (out)
                *out = existing;
        } else {
            rc = AC_AP_UNBIND_NOT_ADOPTED;
        }
        goto done;
    }
    if (sqlite3_column_text(st, 1))
        snprintf(certificate_id, sizeof(certificate_id), "%s",
                 sqlite3_column_text(st, 1));
    if (sqlite3_column_text(st, 2))
        snprintf(enrollment_id, sizeof(enrollment_id), "%s",
                 sqlite3_column_text(st, 2));
    sqlite3_finalize(st);
    st = NULL;
    if (ac_generate_uuid(request_id) != 0 ||
        sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_ap_unbind_requests(request_id,ap_id,certificate_id,"
            "enrollment_id,state,requested_at,acknowledged_at,error_code) "
            "VALUES(?1,?2,?3,?4,'pending',?5,0,'')", -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, request_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, certificate_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, enrollment_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 5, now);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_aps SET adoption_state='unbinding' "
            "WHERE ap_id=?1 AND adoption_state='adopted'", -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_ap_runtime SET write_capable=0,stale=1 "
            "WHERE ap_id=?1", -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (ac_db_ap_unbind_request_pending(ap_id, out) != 0)
        goto done;
    rc = AC_AP_UNBIND_OK;
done:
    sqlite3_finalize(st);
    if (rc == AC_AP_UNBIND_OK && ac_exec("COMMIT") == 0)
        return rc;
    ac_exec("ROLLBACK");
    return rc == AC_AP_UNBIND_OK ? AC_AP_UNBIND_DB : rc;
}

int ac_db_ap_unbind_request_ack(const char *ap_id,
                                const char *session_epoch,
                                const char *request_id, int unpaired,
                                const char *error_code,
                                struct ac_ap_unbind_request *out)
{
    sqlite3_stmt *st = NULL;
    char certificate_id[AC_ENROLLMENT_ID_LEN + 1] = {0};
    char enrollment_id[AC_ENROLLMENT_ID_LEN + 1] = {0};
    int64_t now = ac_now_s();
    int rc = AC_AP_UNBIND_DB;

    if (out)
        memset(out, 0, sizeof(*out));
    if (!g_ac_db || !ac_uuid_valid(ap_id) || !ac_db_session_epoch_valid(session_epoch) ||
        !ac_uuid_valid(request_id) || (unpaired != 0 && unpaired != 1) ||
        !error_code || strlen(error_code) > AC_AP_UNBIND_ERROR_MAX)
        return AC_AP_UNBIND_DB;
    if (ac_exec("BEGIN IMMEDIATE") != 0)
        return AC_AP_UNBIND_DB;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT 1 FROM ac_ap_runtime r JOIN ac_aps a ON a.ap_id=r.ap_id "
            "WHERE r.ap_id=?1 AND r.boot_id=?2 AND r.session_connected=1 "
            "AND a.adoption_state='unbinding'", -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, session_epoch, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (!unpaired) {
        if (sqlite3_prepare_v2(g_ac_db,
                "UPDATE ac_ap_unbind_requests SET error_code=?1 "
                "WHERE request_id=?2 AND ap_id=?3 AND state='pending'",
                -1, &st, NULL) != SQLITE_OK)
            goto done;
        sqlite3_bind_text(st, 1, error_code, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, request_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, ap_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
            goto done;
        sqlite3_finalize(st);
        st = NULL;
        rc = ac_db_ap_unbind_request_pending(ap_id, out) == 0 ?
            AC_AP_UNBIND_OK : AC_AP_UNBIND_DB;
        goto done;
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT certificate_id,enrollment_id FROM ac_ap_unbind_requests "
            "WHERE request_id=?1 AND ap_id=?2 AND state='pending' LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, request_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW)
        goto done;
    if (sqlite3_column_text(st, 0))
        snprintf(certificate_id, sizeof(certificate_id), "%s",
                 sqlite3_column_text(st, 0));
    if (sqlite3_column_text(st, 1))
        snprintf(enrollment_id, sizeof(enrollment_id), "%s",
                 sqlite3_column_text(st, 1));
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_device_certificates SET state='revoked',revoked_at=?1 "
            "WHERE certificate_id=?2 AND ap_id=?3 AND state='active'",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, certificate_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_enrollments SET state='revoked',failure_code='ap_unpaired',"
            "activation_challenge_hash=NULL,activation_expires_at=0,updated_at=?1 "
            "WHERE enrollment_id=?2 AND certificate_id=?3 AND ap_id=?4 "
            "AND state='adopted'", -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, enrollment_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, certificate_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_aps SET adoption_state='pending_pairing' "
            "WHERE ap_id=?1 AND adoption_state='unbinding'", -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_ap_runtime SET session_connected=0,write_capable=0 "
            "WHERE ap_id=?1", -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_ap_unbind_requests SET state='completed',acknowledged_at=?1,"
            "error_code='' WHERE request_id=?2 AND ap_id=?3 AND state='pending'",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, request_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT request_id,ap_id,certificate_id,enrollment_id,state,"
            "requested_at,acknowledged_at,error_code FROM ac_ap_unbind_requests "
            "WHERE request_id=?1", -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, request_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW && out)
        rc = ac_db_unbind_request_read(st, out) == 0 ? AC_AP_UNBIND_OK : AC_AP_UNBIND_DB;
done:
    sqlite3_finalize(st);
    if (rc == AC_AP_UNBIND_OK && ac_exec("COMMIT") == 0)
        return rc;
    ac_exec("ROLLBACK");
    return rc == AC_AP_UNBIND_OK ? AC_AP_UNBIND_DB : rc;
}

int ac_db_ap_session_begin(const char *ap_id, const char *session_epoch,
                           int protocol_version, int64_t received_at)
{
    return ac_db_ap_session_begin_with_capabilities(
        ap_id, session_epoch, protocol_version, 0, received_at);
}

int ac_db_ap_session_end(const char *ap_id, const char *session_epoch)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!g_ac_db || !ac_uuid_valid(ap_id) ||
        !ac_db_session_epoch_valid(session_epoch) ||
        sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_ap_runtime SET session_connected=0,write_capable=0 "
            "WHERE ap_id=?1 AND boot_id=?2 AND session_connected=1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, session_epoch, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE)
        rc = 0;
    sqlite3_finalize(st);
    return rc;
}

int ac_db_scan_execution_available(int64_t online_since, int *ap_count)
{
    sqlite3_stmt *st = NULL;
    int count = 0;
    int rc = -1;

    if (!g_ac_db || online_since <= 0 ||
        sqlite3_prepare_v2(g_ac_db,
            "SELECT COUNT(*) FROM ac_aps a JOIN ac_ap_runtime r "
            "ON r.ap_id=a.ap_id WHERE a.adoption_state='adopted' "
            "AND a.last_seen_at>=?1 AND r.session_connected=1 "
            "AND r.control_protocol_version>=2",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, online_since);
    if (sqlite3_step(st) == SQLITE_ROW) {
        count = sqlite3_column_int(st, 0);
        rc = count > 0;
    }
    sqlite3_finalize(st);
    if (ap_count)
        *ap_count = count;
    return rc;
}

int ac_db_wifi_write_execution_available(int64_t online_since, int *ap_count)
{
    sqlite3_stmt *st = NULL;
    int count = 0;
    int rc = -1;

    if (!g_ac_db || online_since <= 0 ||
        sqlite3_prepare_v2(g_ac_db,
            "SELECT COUNT(*) FROM ac_aps a JOIN ac_ap_runtime r "
            "ON r.ap_id=a.ap_id WHERE a.adoption_state='adopted' "
            "AND a.last_seen_at>=?1 AND r.session_connected=1 "
            "AND r.control_protocol_version=3 AND r.write_capable=1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, online_since);
    if (sqlite3_step(st) == SQLITE_ROW) {
        count = sqlite3_column_int(st, 0);
        rc = count > 0;
    }
    sqlite3_finalize(st);
    if (ap_count)
        *ap_count = count;
    return rc;
}

int ac_db_ap_heartbeat(const char *ap_id, const char *session_epoch,
                       int64_t received_at)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!g_ac_db || !ac_uuid_valid(ap_id) ||
        !ac_db_session_epoch_valid(session_epoch) || received_at <= 0)
        return -1;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_aps SET last_seen_at=MAX(last_seen_at,?1) "
            "WHERE ap_id=?2 AND adoption_state='adopted' AND EXISTS ("
            "SELECT 1 FROM ac_ap_runtime r WHERE r.ap_id=ac_aps.ap_id "
            "AND r.boot_id=?3 AND r.session_connected=1)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, received_at);
    sqlite3_bind_text(st, 2, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, session_epoch, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_ac_db) == 1)
        rc = 0;
    sqlite3_finalize(st);
    return rc;
}

#if !defined(AC_DB_TEST_STANDALONE) || defined(AC_DB_TELEMETRY_TEST_STANDALONE)
static int ac_db_model_report_valid(const struct ac_device_model_report *report)
{
    return report && strlen(report->model) <= AC_DEVICE_MODEL_MAX &&
        strlen(report->board_name) <= AC_DEVICE_BOARD_NAME_MAX &&
        strlen(report->model_source) <= AC_DEVICE_MODEL_SOURCE_MAX &&
        strlen(report->reason) <= AC_DEVICE_MODEL_REASON_MAX &&
        (report->model_available == 0 || report->model_available == 1) &&
        (report->model_available ? report->model[0] != '\0' :
                                   report->model[0] == '\0') &&
        (report->model_available || report->reason[0] != '\0');
}

static int ac_db_telemetry_error(const char *stage)
{
    fprintf(stderr,
            "[%s] telemetry store failed stage=%s sqlite_code=%d error=%s\n",
            AC_SERVICE_NAME, stage ? stage : "unknown",
            g_ac_db ? sqlite3_extended_errcode(g_ac_db) : SQLITE_MISUSE,
            g_ac_db ? sqlite3_errmsg(g_ac_db) : "database unavailable");
    return -1;
}

int ac_db_ap_identity_report(const char *ap_id,
                             const struct ac_device_model_report *report)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!g_ac_db || !ac_uuid_valid(ap_id) || !ac_db_model_report_valid(report) ||
        sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_aps SET reported_model=?1,board_name=?2,model_source=?3,"
            "model_available=?4,model_reason=?5 WHERE ap_id=?6",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, report->model, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, report->board_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, report->model_source, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 4, report->model_available);
    sqlite3_bind_text(st, 5, report->reason, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_ac_db) == 1)
        rc = 0;
    sqlite3_finalize(st);
    return rc;
}

static int ac_db_runtime_item_store(const char *sql, const char *id,
                                    const char *ap_id, const char *radio_id,
                                    int64_t observed_at,
                                    struct json_object *item)
{
    const char *runtime = json_object_to_json_string_ext(
        item, JSON_C_TO_STRING_PLAIN);
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!runtime || sqlite3_prepare_v2(g_ac_db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, radio_id ? radio_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, observed_at);
    sqlite3_bind_text(st, 5, runtime, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE)
        rc = 0;
    sqlite3_finalize(st);
    return rc;
}

static const char *ac_db_json_string(struct json_object *object,
                                     const char *name)
{
    struct json_object *value = NULL;

    return object && json_object_object_get_ex(object, name, &value) && value &&
        json_object_is_type(value, json_type_string) ?
        json_object_get_string(value) : NULL;
}

/* Absent or wrong-typed reads as false on purpose: every caller uses this for
 * a capability gate, where "we have no readback for this yet" must behave the
 * same as "the member said no". */
static int ac_db_json_bool(struct json_object *object, const char *name)
{
    struct json_object *value = NULL;

    return object && json_object_object_get_ex(object, name, &value) && value &&
        json_object_is_type(value, json_type_boolean) ?
        json_object_get_boolean(value) : 0;
}

static const char *ac_db_station_radio(struct json_object *ssids,
                                       const char *interface,
                                       const char **ssid_id)
{
    size_t i;

    *ssid_id = "";
    for (i = 0; ssids && i < json_object_array_length(ssids); i++) {
        struct json_object *item = json_object_array_get_idx(ssids, i);
        const char *item_interface = ac_db_json_string(item, "interface");

        if (item_interface && strcmp(item_interface, interface) == 0) {
            const char *radio_id = ac_db_json_string(item, "radio_id");
            const char *id = ac_db_json_string(item, "id");

            *ssid_id = id ? id : "";
            return radio_id ? radio_id : "";
        }
    }
    return "";
}

/* Runtime SSID ids are interface names; roaming uses controller SSID ids. */
static int ac_db_station_managed_ssid(const char *ap_id, const char *radio_id,
    struct json_object *ssids, const char *interface, char out[37])
{
    sqlite3_stmt *st = NULL;
    size_t i;
    int rc = 0;

    out[0] = '\0';
    for (i = 0; ssids && i < json_object_array_length(ssids); i++) {
        struct json_object *item = json_object_array_get_idx(ssids, i);
        const char *ifname = ac_db_json_string(item, "interface");
        const char *bssid = ac_db_json_string(item, "bssid");
        const char *name = ac_db_json_string(item, "broadcast_name");
        int step;

        if (!ifname || strcmp(ifname, interface) || !bssid || !name)
            continue;
        if (sqlite3_prepare_v2(g_ac_db,
                "SELECT b.ssid_id FROM ac_ssid_bindings b "
                "JOIN ac_ssids s ON s.ssid_id=b.ssid_id "
                "WHERE b.ap_id=?1 AND b.radio_id=?2 "
                "AND b.bssid=?3 COLLATE NOCASE AND s.name=?4",
                -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, radio_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, bssid, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, name, -1, SQLITE_TRANSIENT);
        step = sqlite3_step(st);
        if (step == SQLITE_ROW) {
            snprintf(out, 37, "%s", sqlite3_column_text(st, 0));
            rc = 1;
            step = sqlite3_step(st);
        }
        sqlite3_finalize(st);
        return step == SQLITE_DONE ? rc : -1;
    }
    return 0;
}

/* ── Station connectivity events (source: ac_snapshot_diff) ──────────────
 * Events are derived from consecutive APD hostapd station inventories in
 * the same session epoch.  This records only observed presence
 * transitions with their observation window; it does not invent
 * association reasons, timestamps inside the window, or events across
 * degraded collections.  A future hostapd event-stream producer must keep
 * the same row semantics and change only `source`. */

#define AC_STATION_EVENT_RETENTION_PER_AP 4096
#define AC_STATION_EVENT_WINDOW_MAX_S 3600
#define AC_STATION_EVENT_LIMIT_MAX 1024
#define AC_STATION_EVENT_LIMIT_DEFAULT 256

static int ac_db_snapshot_hostapd_authoritative(struct json_object *snapshot)
{
    struct json_object *sources = NULL;
    struct json_object *hostapd = NULL;
    struct json_object *value = NULL;

    return snapshot &&
        json_object_object_get_ex(snapshot, "sources", &sources) && sources &&
        json_object_object_get_ex(sources, "hostapd", &hostapd) && hostapd &&
        json_object_object_get_ex(hostapd, "available", &value) && value &&
        json_object_get_boolean(value) &&
        json_object_object_get_ex(hostapd, "complete", &value) && value &&
        json_object_get_boolean(value);
}

static const char *ac_db_iface_bssid(struct json_object *ssids,
                                     const char *interface)
{
    size_t i;

    for (i = 0; ssids && interface &&
                i < json_object_array_length(ssids); i++) {
        struct json_object *item = json_object_array_get_idx(ssids, i);
        const char *item_interface = ac_db_json_string(item, "interface");

        if (item_interface && !strcmp(item_interface, interface)) {
            const char *bssid = ac_db_json_string(item, "bssid");

            return bssid ? bssid : "";
        }
    }
    return "";
}

static int ac_db_station_signal(struct json_object *item, int *value_out)
{
    struct json_object *value = NULL;

    if (item && json_object_object_get_ex(item, "signal_dbm", &value) &&
        value && json_object_is_type(value, json_type_int)) {
        *value_out = (int)json_object_get_int64(value);
        return 1;
    }
    return 0;
}

struct ac_station_diff_entry {
    const char *mac;
    const char *interface;
    struct json_object *item;
    int consumed;
};

static size_t ac_db_station_entries(struct json_object *stations,
                                    struct ac_station_diff_entry *entries,
                                    size_t max_entries)
{
    size_t count = 0;
    size_t i;

    for (i = 0; stations && i < json_object_array_length(stations) &&
                count < max_entries; i++) {
        struct json_object *item = json_object_array_get_idx(stations, i);
        const char *mac = ac_db_json_string(item, "mac");
        const char *interface = ac_db_json_string(item, "interface");

        if (!mac || !mac[0] || !interface || !interface[0])
            continue;
        entries[count].mac = mac;
        entries[count].interface = interface;
        entries[count].item = item;
        entries[count].consumed = 0;
        count++;
    }
    return count;
}

static struct ac_station_diff_entry *ac_db_station_find(
    struct ac_station_diff_entry *entries, size_t count, const char *mac,
    const char *interface, int require_same_interface)
{
    size_t i;

    for (i = 0; i < count; i++) {
        if (entries[i].consumed || strcmp(entries[i].mac, mac) != 0)
            continue;
        if (require_same_interface) {
            if (!strcmp(entries[i].interface, interface))
                return &entries[i];
        } else if (strcmp(entries[i].interface, interface) != 0) {
            return &entries[i];
        }
    }
    return NULL;
}

static int ac_db_station_event_insert(
    const char *ap_id, const char *event, const char *mac,
    const char *radio_id, const char *ssid_id, const char *interface,
    const char *from_radio_id, const char *from_interface,
    const char *from_bssid, const char *to_bssid,
    int signal_present, int signal_dbm,
    int previous_signal_present, int previous_signal_dbm,
    int64_t observed_at, int64_t window_started_at, int64_t created_at)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_station_events(ap_id,event,station_mac,radio_id,"
            "ssid_id,interface,from_radio_id,from_interface,from_bssid,"
            "to_bssid,signal_dbm,previous_signal_dbm,observed_at,"
            "window_started_at,source,created_at) "
            "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,"
            "'ac_snapshot_diff',?15)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, event, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, mac, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, radio_id ? radio_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, ssid_id ? ssid_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, interface ? interface : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, from_radio_id ? from_radio_id : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, from_interface ? from_interface : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, from_bssid ? from_bssid : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 10, to_bssid ? to_bssid : "", -1, SQLITE_TRANSIENT);
    if (signal_present)
        sqlite3_bind_int(st, 11, signal_dbm);
    else
        sqlite3_bind_null(st, 11);
    if (previous_signal_present)
        sqlite3_bind_int(st, 12, previous_signal_dbm);
    else
        sqlite3_bind_null(st, 12);
    sqlite3_bind_int64(st, 13, observed_at);
    sqlite3_bind_int64(st, 14, window_started_at);
    sqlite3_bind_int64(st, 15, created_at);
    if (sqlite3_step(st) == SQLITE_DONE)
        rc = 0;
    sqlite3_finalize(st);
    return rc;
}

#define AC_STATION_DIFF_MAX 512

/* Runs inside the telemetry store transaction.  Emits nothing unless both
 * inventories are authoritative and the observation window is sane. */
static int ac_db_station_events_ingest(const char *ap_id,
                                       struct json_object *previous_snapshot,
                                       struct json_object *snapshot,
                                       int64_t previous_observed_at,
                                       int64_t observed_at,
                                       int64_t received_at)
{
    struct ac_station_diff_entry old_entries[AC_STATION_DIFF_MAX];
    struct ac_station_diff_entry new_entries[AC_STATION_DIFF_MAX];
    struct json_object *old_stations = NULL;
    struct json_object *new_stations = NULL;
    struct json_object *old_ssids = NULL;
    struct json_object *new_ssids = NULL;
    size_t old_count;
    size_t new_count;
    size_t i;
    sqlite3_stmt *st = NULL;

    if (!previous_snapshot || previous_observed_at <= 0 ||
        observed_at <= previous_observed_at ||
        observed_at - previous_observed_at > AC_STATION_EVENT_WINDOW_MAX_S ||
        !ac_db_snapshot_hostapd_authoritative(previous_snapshot) ||
        !ac_db_snapshot_hostapd_authoritative(snapshot))
        return 0;
    if (!json_object_object_get_ex(previous_snapshot, "stations",
                                   &old_stations) ||
        !json_object_object_get_ex(snapshot, "stations", &new_stations) ||
        !json_object_is_type(old_stations, json_type_array) ||
        !json_object_is_type(new_stations, json_type_array))
        return 0;
    json_object_object_get_ex(previous_snapshot, "ssids", &old_ssids);
    json_object_object_get_ex(snapshot, "ssids", &new_ssids);
    old_count = ac_db_station_entries(old_stations, old_entries,
                                      AC_STATION_DIFF_MAX);
    new_count = ac_db_station_entries(new_stations, new_entries,
                                      AC_STATION_DIFF_MAX);
    for (i = 0; i < new_count; i++) {
        struct ac_station_diff_entry *same = ac_db_station_find(
            old_entries, old_count, new_entries[i].mac,
            new_entries[i].interface, 1);
        struct ac_station_diff_entry *moved;
        const char *ssid_id = "";
        const char *radio_id;
        const char *from_ssid_id = "";
        int signal_dbm = 0;
        int signal_present;

        if (same) {
            same->consumed = 1;
            new_entries[i].consumed = 1;
            continue;
        }
        radio_id = ac_db_station_radio(new_ssids, new_entries[i].interface,
                                       &ssid_id);
        signal_present = ac_db_station_signal(new_entries[i].item,
                                              &signal_dbm);
        moved = ac_db_station_find(old_entries, old_count, new_entries[i].mac,
                                   new_entries[i].interface, 0);
        if (moved) {
            const char *from_radio_id = ac_db_station_radio(
                old_ssids, moved->interface, &from_ssid_id);
            int previous_signal = 0;
            int previous_present = ac_db_station_signal(moved->item,
                                                        &previous_signal);

            moved->consumed = 1;
            new_entries[i].consumed = 1;
            if (ac_db_station_event_insert(ap_id, "roam",
                    new_entries[i].mac, radio_id, ssid_id,
                    new_entries[i].interface, from_radio_id,
                    moved->interface,
                    ac_db_iface_bssid(old_ssids, moved->interface),
                    ac_db_iface_bssid(new_ssids, new_entries[i].interface),
                    signal_present, signal_dbm, previous_present,
                    previous_signal, observed_at, previous_observed_at,
                    received_at) != 0)
                return -1;
            continue;
        }
        new_entries[i].consumed = 1;
        if (ac_db_station_event_insert(ap_id, "connect", new_entries[i].mac,
                radio_id, ssid_id, new_entries[i].interface, "", "", "",
                ac_db_iface_bssid(new_ssids, new_entries[i].interface),
                signal_present, signal_dbm, 0, 0, observed_at,
                previous_observed_at, received_at) != 0)
            return -1;
    }
    for (i = 0; i < old_count; i++) {
        const char *ssid_id = "";
        const char *radio_id;
        int previous_signal = 0;
        int previous_present;

        if (old_entries[i].consumed)
            continue;
        radio_id = ac_db_station_radio(old_ssids, old_entries[i].interface,
                                       &ssid_id);
        previous_present = ac_db_station_signal(old_entries[i].item,
                                                &previous_signal);
        if (ac_db_station_event_insert(ap_id, "disconnect",
                old_entries[i].mac, radio_id, ssid_id,
                old_entries[i].interface, radio_id, old_entries[i].interface,
                ac_db_iface_bssid(old_ssids, old_entries[i].interface), "",
                0, 0, previous_present, previous_signal, observed_at,
                previous_observed_at, received_at) != 0)
            return -1;
    }
    /* Bounded retention: newest AC_STATION_EVENT_RETENTION_PER_AP rows
     * per AP survive; the cursor contract makes trimmed history explicit
     * through the monotonically increasing event_id. */
    if (sqlite3_prepare_v2(g_ac_db,
            "DELETE FROM ac_station_events WHERE ap_id=?1 AND event_id<=("
            "SELECT event_id FROM ac_station_events WHERE ap_id=?1 "
            "ORDER BY event_id DESC LIMIT 1 OFFSET ?2)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, AC_STATION_EVENT_RETENTION_PER_AP);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    return 0;
}

static int ac_db_station_counter(struct json_object *station,
                                 const char *name, uint64_t *value_out)
{
    struct json_object *value = NULL;
    int64_t parsed;

    if (!station || !name || !value_out ||
        !json_object_object_get_ex(station, name, &value) || !value ||
        !json_object_is_type(value, json_type_int))
        return 0;
    parsed = json_object_get_int64(value);
    if (parsed < 0)
        return 0;
    *value_out = (uint64_t)parsed;
    return 1;
}

static int ac_db_station_reconnected(struct json_object *previous,
                                     struct json_object *current)
{
    uint64_t previous_connected;
    uint64_t current_connected;

    return ac_db_station_counter(previous, "connected_time_seconds",
                                 &previous_connected) &&
           ac_db_station_counter(current, "connected_time_seconds",
                                 &current_connected) &&
           current_connected <= previous_connected;
}

/* Item 6: dedicated auth-failure insert.  Kept separate from
 * ac_db_station_event_insert so the three snapshot-diff call sites stay
 * byte-identical; this one hard-codes event/source and carries the reason. */
static int ac_db_station_event_insert_authfail(
    const char *ap_id, const char *mac, const char *interface,
    const char *reason, int64_t observed_at, int64_t window_started_at,
    int64_t created_at)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_station_events(ap_id,event,station_mac,radio_id,"
            "ssid_id,interface,from_radio_id,from_interface,from_bssid,"
            "to_bssid,signal_dbm,previous_signal_dbm,observed_at,"
            "window_started_at,source,created_at,reason) "
            "VALUES(?1,'auth_failure',?2,'','',?3,'','','','',NULL,NULL,?4,?5,"
            "'hostapd_control_event',?6,?7)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, mac, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, interface, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, observed_at);
    sqlite3_bind_int64(st, 5, window_started_at);
    sqlite3_bind_int64(st, 6, created_at);
    sqlite3_bind_text(st, 7, reason, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE)
        rc = 0;
    sqlite3_finalize(st);
    return rc;
}

/* Item 6: hostapd auth-failure event ingest.
 *
 * A station that fails authentication never enters the station dump, so the
 * snapshot-diff producer above cannot see it.  APD forwards the failures the
 * hostapd control monitor reports under sources.hostapd.auth_failures[]; this
 * records each as an ac_station_events row (event='auth_failure', the reason
 * carried verbatim, source='hostapd_control_event' per the row-semantics note
 * at the top of this section).  Absolute events, so unlike the diff producer
 * this runs on the current snapshot alone and is not gated on a previous
 * sequence.  Dedup is by (ap_id, station_mac, interface, observed_at): a
 * failure re-sent unchanged within APD's 300s TTL keeps its observed_at and
 * collapses to one row, while each new occurrence bumps observed_at and lands
 * a fresh row.  Gated on the hostapd source being authoritative so failures
 * from a degraded collection are not recorded. */
static int ac_db_auth_failures_ingest(const char *ap_id,
                                      struct json_object *snapshot,
                                      int64_t observed_at,
                                      int64_t received_at)
{
    struct json_object *sources = NULL;
    struct json_object *hostapd = NULL;
    struct json_object *failures = NULL;
    size_t i;

    if (!g_ac_db || !ap_id || !ap_id[0] || !snapshot ||
        !ac_db_snapshot_hostapd_authoritative(snapshot))
        return 0;
    if (!json_object_object_get_ex(snapshot, "sources", &sources) ||
        !json_object_object_get_ex(sources, "hostapd", &hostapd) ||
        !json_object_object_get_ex(hostapd, "auth_failures", &failures) ||
        !json_object_is_type(failures, json_type_array))
        return 0;

    for (i = 0; i < json_object_array_length(failures); i++) {
        struct json_object *entry = json_object_array_get_idx(failures, i);
        const char *mac = ac_db_json_string(entry, "station_mac");
        const char *interface = ac_db_json_string(entry, "interface");
        const char *reason = ac_db_json_string(entry, "reason");
        const char *source = ac_db_json_string(entry, "source");
        struct json_object *ov = NULL;
        int64_t ev_at = observed_at;
        sqlite3_stmt *st = NULL;
        int seen = 0;

        if (!mac || !mac[0] || !interface || !interface[0] ||
            !reason || !reason[0] || !source ||
            strcmp(source, "hostapd_control_event"))
            continue;
        if (json_object_object_get_ex(entry, "observed_at", &ov) && ov &&
            json_object_is_type(ov, json_type_int)) {
            int64_t v = json_object_get_int64(ov);

            if (v > 0 && v <= received_at + 5)
                ev_at = v;
        }
        if (sqlite3_prepare_v2(g_ac_db,
                "SELECT 1 FROM ac_station_events WHERE ap_id=?1 AND "
                "event='auth_failure' AND station_mac=?2 AND interface=?3 AND "
                "observed_at=?4 LIMIT 1", -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, mac, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, interface, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 4, ev_at);
        seen = (sqlite3_step(st) == SQLITE_ROW);
        sqlite3_finalize(st);
        if (seen)
            continue;
        if (ac_db_station_event_insert_authfail(ap_id, mac, interface, reason,
                ev_at, observed_at, received_at) != 0)
            return -1;
    }
    return 0;
}

static int ac_db_ap_traffic_prune(const char *ap_id, int64_t now)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (sqlite3_prepare_v2(g_ac_db,
            "DELETE FROM ac_ap_traffic_bucket WHERE ap_id=?1 AND "
            "last_received_at<?2", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now - AC_AP_TRAFFIC_RETENTION_SECONDS);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "DELETE FROM ac_ap_traffic_bucket WHERE ap_id=?1 AND sample_id "
            "NOT IN (SELECT sample_id FROM ac_ap_traffic_bucket WHERE ap_id=?1 "
            "ORDER BY bucket_start DESC,sample_id DESC LIMIT ?2)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, AC_AP_TRAFFIC_RETENTION_ROWS);
    if (sqlite3_step(st) == SQLITE_DONE)
        rc = 0;
done:
    sqlite3_finalize(st);
    return rc;
}

/* AP-side rx_bytes is traffic received from wireless stations (terminal
 * uplink); AP-side tx_bytes is traffic sent to stations (terminal downlink).
 * Only the same station on the same interface across two authoritative
 * snapshots contributes a delta. Roams, reconnects and counter decreases
 * establish a new baseline instead of creating a spike. */
static int ac_db_ap_traffic_ingest(const char *ap_id,
                                   struct json_object *previous_snapshot,
                                   struct json_object *snapshot,
                                   int64_t previous_observed_at,
                                   int64_t observed_at,
                                   int64_t received_at)
{
    struct ac_station_diff_entry old_entries[AC_STATION_DIFF_MAX];
    struct ac_station_diff_entry new_entries[AC_STATION_DIFF_MAX];
    struct json_object *old_stations = NULL;
    struct json_object *new_stations = NULL;
    sqlite3_stmt *st = NULL;
    size_t old_count;
    size_t new_count;
    size_t i;
    int64_t interval;
    uint64_t up_bytes = 0;
    uint64_t down_bytes = 0;
    int reset_count = 0;
    int rc = -1;

    if (!previous_snapshot || previous_observed_at <= 0 ||
        observed_at <= previous_observed_at ||
        observed_at - previous_observed_at > AC_AP_TRAFFIC_SAMPLE_MAX_SECONDS ||
        !ac_db_snapshot_hostapd_authoritative(previous_snapshot) ||
        !ac_db_snapshot_hostapd_authoritative(snapshot))
        return 0;
    if (!json_object_object_get_ex(previous_snapshot, "stations",
                                   &old_stations) ||
        !json_object_object_get_ex(snapshot, "stations", &new_stations) ||
        !json_object_is_type(old_stations, json_type_array) ||
        !json_object_is_type(new_stations, json_type_array))
        return 0;
    old_count = ac_db_station_entries(old_stations, old_entries,
                                      AC_STATION_DIFF_MAX);
    new_count = ac_db_station_entries(new_stations, new_entries,
                                      AC_STATION_DIFF_MAX);
    for (i = 0; i < new_count; i++) {
        struct ac_station_diff_entry *previous = ac_db_station_find(
            old_entries, old_count, new_entries[i].mac,
            new_entries[i].interface, 1);
        uint64_t old_rx;
        uint64_t old_tx;
        uint64_t new_rx;
        uint64_t new_tx;

        if (!previous)
            continue;
        previous->consumed = 1;
        if (!ac_db_station_counter(previous->item, "rx_bytes", &old_rx) ||
            !ac_db_station_counter(previous->item, "tx_bytes", &old_tx) ||
            !ac_db_station_counter(new_entries[i].item, "rx_bytes", &new_rx) ||
            !ac_db_station_counter(new_entries[i].item, "tx_bytes", &new_tx))
            continue;
        if (ac_db_station_reconnected(previous->item, new_entries[i].item) ||
            new_rx < old_rx || new_tx < old_tx) {
            reset_count++;
            continue;
        }
        up_bytes += new_rx - old_rx;
        down_bytes += new_tx - old_tx;
    }
    interval = observed_at - previous_observed_at;
    if (up_bytes > INT64_MAX || down_bytes > INT64_MAX)
        return -1;
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_ap_traffic_bucket(ap_id,resolution_seconds,"
            "bucket_start,first_observed_at,last_observed_at,first_received_at,"
            "last_received_at,sample_count,duration_seconds,up_bytes,down_bytes,"
            "station_count_sum,counter_reset_count,complete,source) "
            "VALUES(?1,60,?2,?3,?4,?5,?5,1,?6,?7,?8,?9,?10,?11,"
            "'ac_station_counter_delta') ON CONFLICT(ap_id,resolution_seconds,"
            "bucket_start) DO UPDATE SET first_observed_at=MIN("
            "ac_ap_traffic_bucket.first_observed_at,excluded.first_observed_at),"
            "last_observed_at=MAX(ac_ap_traffic_bucket.last_observed_at,"
            "excluded.last_observed_at),first_received_at=MIN("
            "ac_ap_traffic_bucket.first_received_at,excluded.first_received_at),"
            "last_received_at=MAX(ac_ap_traffic_bucket.last_received_at,"
            "excluded.last_received_at),sample_count=ac_ap_traffic_bucket."
            "sample_count+1,duration_seconds=ac_ap_traffic_bucket."
            "duration_seconds+excluded.duration_seconds,up_bytes="
            "ac_ap_traffic_bucket.up_bytes+excluded.up_bytes,down_bytes="
            "ac_ap_traffic_bucket.down_bytes+excluded.down_bytes,"
            "station_count_sum=ac_ap_traffic_bucket.station_count_sum+"
            "excluded.station_count_sum,counter_reset_count="
            "ac_ap_traffic_bucket.counter_reset_count+"
            "excluded.counter_reset_count,complete=MIN("
            "ac_ap_traffic_bucket.complete,excluded.complete),source="
            "excluded.source", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, observed_at -
                       observed_at % AC_AP_TRAFFIC_RESOLUTION_SECONDS);
    sqlite3_bind_int64(st, 3, previous_observed_at);
    sqlite3_bind_int64(st, 4, observed_at);
    sqlite3_bind_int64(st, 5, received_at);
    sqlite3_bind_int64(st, 6, interval);
    sqlite3_bind_int64(st, 7, (int64_t)up_bytes);
    sqlite3_bind_int64(st, 8, (int64_t)down_bytes);
    sqlite3_bind_int64(st, 9, (int64_t)new_count);
    sqlite3_bind_int(st, 10, reset_count);
    sqlite3_bind_int(st, 11, reset_count == 0);
    if (sqlite3_step(st) == SQLITE_DONE &&
        ac_db_ap_traffic_prune(ap_id, received_at) == 0)
        rc = 0;
    sqlite3_finalize(st);
    return rc;
}

struct json_object *ac_db_station_events_json(const char *ap_id,
                                              const char *event,
                                              int64_t start, int64_t end,
                                              int limit, int64_t after_id)
{
    struct json_object *root = json_object_new_object();
    struct json_object *items = json_object_new_array();
    sqlite3_stmt *st = NULL;
    int count = 0;
    int limited = 0;
    int64_t next_after_id = after_id;

    if (limit < 1 || limit > AC_STATION_EVENT_LIMIT_MAX)
        limit = AC_STATION_EVENT_LIMIT_DEFAULT;
    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "items", items);
    if (!g_ac_db || start <= 0 || end < start || after_id < 0) {
        json_object_object_add(root, "error",
                               json_object_new_string("invalid_request"));
        return root;
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT event_id,ap_id,event,station_mac,radio_id,ssid_id,"
            "interface,from_radio_id,from_interface,from_bssid,to_bssid,"
            "signal_dbm,previous_signal_dbm,observed_at,window_started_at,"
            "source FROM ac_station_events WHERE (?1='' OR ap_id=?1) AND "
            "(?2='' OR event=?2) AND observed_at>=?3 AND observed_at<=?4 "
            "AND event_id>?5 ORDER BY event_id ASC LIMIT ?6",
            -1, &st, NULL) != SQLITE_OK) {
        json_object_object_add(root, "error",
                               json_object_new_string("database_error"));
        return root;
    }
    sqlite3_bind_text(st, 1, ap_id ? ap_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, event ? event : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, start);
    sqlite3_bind_int64(st, 4, end);
    sqlite3_bind_int64(st, 5, after_id);
    sqlite3_bind_int(st, 6, limit + 1);
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *item;

        if (count == limit) {
            limited = 1;
            break;
        }
        item = json_object_new_object();
        json_object_object_add(item, "event_id", json_object_new_int64(
            sqlite3_column_int64(st, 0)));
        json_object_object_add(item, "ap_id", json_object_new_string(
            (const char *)sqlite3_column_text(st, 1)));
        json_object_object_add(item, "event", json_object_new_string(
            (const char *)sqlite3_column_text(st, 2)));
        json_object_object_add(item, "station_mac", json_object_new_string(
            (const char *)sqlite3_column_text(st, 3)));
        json_object_object_add(item, "radio_id", json_object_new_string(
            (const char *)sqlite3_column_text(st, 4)));
        json_object_object_add(item, "ssid_id", json_object_new_string(
            (const char *)sqlite3_column_text(st, 5)));
        json_object_object_add(item, "interface", json_object_new_string(
            (const char *)sqlite3_column_text(st, 6)));
        json_object_object_add(item, "from_radio_id", json_object_new_string(
            (const char *)sqlite3_column_text(st, 7)));
        json_object_object_add(item, "from_interface",
            json_object_new_string(
                (const char *)sqlite3_column_text(st, 8)));
        json_object_object_add(item, "from_bssid", json_object_new_string(
            (const char *)sqlite3_column_text(st, 9)));
        json_object_object_add(item, "to_bssid", json_object_new_string(
            (const char *)sqlite3_column_text(st, 10)));
        if (sqlite3_column_type(st, 11) == SQLITE_NULL)
            json_object_object_add(item, "signal_dbm",
                                   json_object_new_null());
        else
            json_object_object_add(item, "signal_dbm", json_object_new_int(
                sqlite3_column_int(st, 11)));
        if (sqlite3_column_type(st, 12) == SQLITE_NULL)
            json_object_object_add(item, "previous_signal_dbm",
                                   json_object_new_null());
        else
            json_object_object_add(item, "previous_signal_dbm",
                json_object_new_int(sqlite3_column_int(st, 12)));
        json_object_object_add(item, "observed_at", json_object_new_int64(
            sqlite3_column_int64(st, 13)));
        json_object_object_add(item, "window_started_at",
            json_object_new_int64(sqlite3_column_int64(st, 14)));
        json_object_object_add(item, "source", json_object_new_string(
            (const char *)sqlite3_column_text(st, 15)));
        json_object_array_add(items, item);
        next_after_id = sqlite3_column_int64(st, 0);
        count++;
    }
    sqlite3_finalize(st);
    json_object_object_del(root, "ok");
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "count", json_object_new_int(count));
    json_object_object_add(root, "limit", json_object_new_int(limit));
    json_object_object_add(root, "limited", json_object_new_boolean(limited));
    json_object_object_add(root, "next_after_id",
                           json_object_new_int64(next_after_id));
    json_object_object_add(root, "source",
                           json_object_new_string("ac_snapshot_diff"));
    if (count == 0)
        json_object_object_add(root, "reason",
                               json_object_new_string("no_events"));
    return root;
}

/* ---- Phase W1: read-only wifi transaction validate ----
 *
 * Static validation of a desired-config changeset against AP-reported
 * evidence (ac_radio_runtime channel_catalog).  No writes, no capability
 * change: save_config, apply_config, the ssid ops and radio_update stay
 * false and the 2026-07-20 fail-closed gates are untouched.  The
 * idempotency key is echoed for the future W3 apply binding but not
 * persisted here. */

#define AC_WIFI_VALIDATE_CHANGES_MAX 32768
#define AC_WIFI_VALIDATE_RADIOS_MAX 8
#define AC_WIFI_VALIDATE_SSIDS_MAX 16
#define AC_WIFI_VALIDATE_SSID_NAME_MAX 32

static int ac_wifi_validate_radio_id(const char *value)
{
    return dreamingwrt_ap_radio_id_valid(value);
}

static int ac_wifi_validate_ssid_id(const char *value)
{
    size_t i;
    size_t len = value ? strlen(value) : 0;

    if (len == 0 || len > 64)
        return 0;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)value[i];

        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
            return 0;
    }
    return 1;
}

static int ac_wifi_validate_utf8(const unsigned char *bytes, size_t length)
{
    size_t i = 0;

    while (i < length) {
        unsigned char c = bytes[i++];
        unsigned int code;
        int continuation;

        if (c < 0x80) {
            if (c < 0x20 || c == 0x7f)
                return 0;
            continue;
        }
        if (c >= 0xc2 && c <= 0xdf) {
            code = c & 0x1f; continuation = 1;
        } else if (c >= 0xe0 && c <= 0xef) {
            code = c & 0x0f; continuation = 2;
        } else if (c >= 0xf0 && c <= 0xf4) {
            code = c & 0x07; continuation = 3;
        } else {
            return 0;
        }
        if (i + (size_t)continuation > length)
            return 0;
        for (int j = 0; j < continuation; j++) {
            unsigned char next = bytes[i++];

            if ((next & 0xc0) != 0x80)
                return 0;
            code = (code << 6) | (next & 0x3f);
        }
        if ((continuation == 2 && code < 0x800) ||
            (continuation == 3 && code < 0x10000) ||
            (code >= 0xd800 && code <= 0xdfff) || code > 0x10ffff)
            return 0;
    }
    return 1;
}

/* Secrets must never transit the validate path, not even for inspection. */
static int ac_wifi_validate_has_secret_key(struct json_object *node)
{
    static const char *const forbidden[] = {
        "psk", "password", "passphrase", "secret", "key"
    };
    size_t i;

    if (!node)
        return 0;
    if (json_object_is_type(node, json_type_object)) {
        json_object_object_foreach(node, name, child) {
            for (i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); i++)
                if (!strcmp(name, forbidden[i]))
                    return 1;
            if (ac_wifi_validate_has_secret_key(child))
                return 1;
        }
        return 0;
    }
    if (json_object_is_type(node, json_type_array)) {
        for (i = 0; i < json_object_array_length(node); i++)
            if (ac_wifi_validate_has_secret_key(
                    json_object_array_get_idx(node, i)))
                return 1;
    }
    return 0;
}

/*
 * Published in `capabilities.wifi_desired_revision` so a caller can build a
 * transaction without first losing one to `revision_conflict`. Every write
 * bumps it, so a client that hardcodes 0 works exactly once.
 */
int64_t ac_db_wifi_desired_revision(void)
{
    static const char sql[] =
        "SELECT MAX(revision) FROM ("
        "SELECT COALESCE(MAX(revision),0) AS revision FROM ac_radio_desired "
        "UNION ALL SELECT COALESCE(MAX(revision),0) FROM ac_ssids "
        "UNION ALL SELECT COALESCE(MAX(desired_revision),0) "
        "FROM ac_transactions)";
    sqlite3_stmt *st = NULL;
    int64_t revision = 0;

    if (!g_ac_db ||
        sqlite3_prepare_v2(g_ac_db, sql, -1, &st, NULL) != SQLITE_OK)
        return 0;
    if (sqlite3_step(st) == SQLITE_ROW)
        revision = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return revision;
}

/* Fetch the freshest reported catalog for one radio.  Returns the parsed
 * runtime root (caller frees) with *catalog_out borrowed from it, or NULL
 * with reason[] set.  Evidence is fail-closed: missing, stale or
 * incomplete evidence rejects the target instead of passing it. */
static struct json_object *ac_wifi_validate_evidence(
    const char *ap_id, const char *radio_id, int64_t now,
    struct json_object **catalog_out, const char **reason_out)
{
    static const char sql[] =
        "SELECT observed_at,runtime_json,stale FROM ac_radio_runtime "
        "WHERE ap_id=?1 AND radio_id=?2";
    sqlite3_stmt *st = NULL;
    struct json_object *root = NULL;
    struct json_object *catalog = NULL;
    struct json_object *field = NULL;
    const unsigned char *runtime;
    int64_t observed_at = 0;

    *catalog_out = NULL;
    *reason_out = NULL;
    if (!g_ac_db ||
        sqlite3_prepare_v2(g_ac_db, sql, -1, &st, NULL) != SQLITE_OK) {
        *reason_out = "radio_evidence_unavailable";
        return NULL;
    }
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, radio_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        *reason_out = "radio_evidence_missing";
        return NULL;
    }
    observed_at = sqlite3_column_int64(st, 0);
    runtime = sqlite3_column_text(st, 1);
    if (sqlite3_column_int(st, 2) != 0 ||
        observed_at < now - AC_TELEMETRY_STALE_TIMEOUT_SECONDS) {
        sqlite3_finalize(st);
        *reason_out = "radio_evidence_stale";
        return NULL;
    }
    root = runtime ? json_tokener_parse((const char *)runtime) : NULL;
    sqlite3_finalize(st);
    if (!root || !json_object_is_type(root, json_type_object)) {
        json_object_put(root);
        *reason_out = "radio_evidence_unparseable";
        return NULL;
    }
    if (!json_object_object_get_ex(root, "channel_catalog", &catalog) ||
        !catalog || !json_object_is_type(catalog, json_type_object)) {
        json_object_put(root);
        *reason_out = "channel_catalog_missing";
        return NULL;
    }
    if (!json_object_object_get_ex(catalog, "complete", &field) || !field ||
        !json_object_get_boolean(field)) {
        json_object_put(root);
        *reason_out = "channel_catalog_incomplete";
        return NULL;
    }
    *catalog_out = catalog;
    return root;
}

static int ac_wifi_validate_int_in_array(struct json_object *array,
                                         int candidate)
{
    size_t i;

    if (!array || !json_object_is_type(array, json_type_array))
        return 0;
    for (i = 0; i < json_object_array_length(array); i++) {
        struct json_object *entry = json_object_array_get_idx(array, i);

        if (entry && json_object_get_int(entry) == candidate)
            return 1;
    }
    return 0;
}

static void ac_wifi_validate_error(struct json_object *errors,
                                   const char *code, int *valid)
{
    json_object_array_add(errors, json_object_new_string(code));
    *valid = 0;
}

static struct json_object *ac_wifi_validate_radio_target(
    const char *ap_id, struct json_object *change, int64_t now)
{
    struct json_object *target = json_object_new_object();
    struct json_object *errors = json_object_new_array();
    struct json_object *evidence_root = NULL;
    struct json_object *catalog = NULL;
    struct json_object *field = NULL;
    const char *radio_id = "";
    const char *reason = NULL;
    int valid = 1;
    int has_candidate = 0;

    json_object_object_add(target, "type", json_object_new_string("radio"));
    if (!json_object_is_type(change, json_type_object)) {
        json_object_object_add(target, "radio_id",
                               json_object_new_string(""));
        ac_wifi_validate_error(errors, "radio_change_not_object", &valid);
        goto done;
    }
    if (json_object_object_get_ex(change, "radio_id", &field) && field &&
        json_object_is_type(field, json_type_string))
        radio_id = json_object_get_string(field);
    json_object_object_add(target, "radio_id",
                           json_object_new_string(radio_id));
    if (!ac_wifi_validate_radio_id(radio_id)) {
        ac_wifi_validate_error(errors, "radio_id_invalid", &valid);
        goto done;
    }
    {
        json_object_object_foreach(change, name, child) {
            (void)child;
            if (strcmp(name, "radio_id") && strcmp(name, "channel") &&
                strcmp(name, "width_mhz") && strcmp(name, "tx_power_dbm"))
                ac_wifi_validate_error(errors, "radio_field_unknown",
                                       &valid);
        }
    }
    if (!valid)
        goto done;
    evidence_root = ac_wifi_validate_evidence(ap_id, radio_id, now,
                                              &catalog, &reason);
    if (!evidence_root) {
        ac_wifi_validate_error(errors, reason, &valid);
        goto done;
    }
    if (json_object_object_get_ex(catalog, "observed_at", &field) && field)
        json_object_object_add(target, "evidence_observed_at",
            json_object_new_int64(json_object_get_int64(field)));
    if (json_object_object_get_ex(change, "channel", &field) && field) {
        struct json_object *supported = NULL;

        has_candidate = 1;
        if (!json_object_is_type(field, json_type_int)) {
            ac_wifi_validate_error(errors, "channel_invalid", &valid);
        } else {
            json_object_object_get_ex(catalog, "supported_channels",
                                      &supported);
            if (!supported)
                ac_wifi_validate_error(errors, "channel_evidence_missing",
                                       &valid);
            else if (!ac_wifi_validate_int_in_array(supported,
                         json_object_get_int(field)))
                ac_wifi_validate_error(errors, "channel_not_supported",
                                       &valid);
        }
    }
    if (json_object_object_get_ex(change, "width_mhz", &field) && field) {
        struct json_object *widths = NULL;

        has_candidate = 1;
        if (!json_object_is_type(field, json_type_int)) {
            ac_wifi_validate_error(errors, "width_invalid", &valid);
        } else {
            json_object_object_get_ex(catalog, "supported_widths_mhz",
                                      &widths);
            if (!widths)
                ac_wifi_validate_error(errors, "width_evidence_missing",
                                       &valid);
            else if (!ac_wifi_validate_int_in_array(widths,
                         json_object_get_int(field)))
                ac_wifi_validate_error(errors, "width_not_supported",
                                       &valid);
        }
    }
    if (json_object_object_get_ex(change, "tx_power_dbm", &field) && field) {
        struct json_object *range = NULL;
        struct json_object *bound = NULL;
        double candidate;

        has_candidate = 1;
        if (!json_object_is_type(field, json_type_int) &&
            !json_object_is_type(field, json_type_double)) {
            ac_wifi_validate_error(errors, "tx_power_invalid", &valid);
        } else {
            candidate = json_object_get_double(field);
            json_object_object_get_ex(catalog, "tx_power_range_dbm",
                                      &range);
            if (!range || !json_object_is_type(range, json_type_object)) {
                ac_wifi_validate_error(errors, "tx_power_evidence_missing",
                                       &valid);
            } else if ((json_object_object_get_ex(range, "min", &bound) &&
                        bound &&
                        candidate < json_object_get_double(bound)) ||
                       (json_object_object_get_ex(range, "max", &bound) &&
                        bound &&
                        candidate > json_object_get_double(bound))) {
                ac_wifi_validate_error(errors, "tx_power_out_of_range",
                                       &valid);
            }
        }
    }
    if (!has_candidate)
        ac_wifi_validate_error(errors, "radio_change_empty", &valid);
done:
    json_object_put(evidence_root);
    json_object_object_add(target, "valid", json_object_new_boolean(valid));
    json_object_object_add(target, "errors", errors);
    return target;
}

static struct json_object *ac_wifi_validate_ssid_target(
    const char *ap_id, struct json_object *change, int64_t now)
{
    struct json_object *target = json_object_new_object();
    struct json_object *errors = json_object_new_array();
    struct json_object *field = NULL;
    const char *ssid_id = "";
    int valid = 1;

    json_object_object_add(target, "type", json_object_new_string("ssid"));
    if (!json_object_is_type(change, json_type_object)) {
        json_object_object_add(target, "ssid_id",
                               json_object_new_string(""));
        ac_wifi_validate_error(errors, "ssid_change_not_object", &valid);
        goto done;
    }
    if (json_object_object_get_ex(change, "ssid_id", &field) && field &&
        json_object_is_type(field, json_type_string))
        ssid_id = json_object_get_string(field);
    json_object_object_add(target, "ssid_id",
                           json_object_new_string(ssid_id));
    if (!ac_wifi_validate_ssid_id(ssid_id))
        ac_wifi_validate_error(errors, "ssid_id_invalid", &valid);
    {
        json_object_object_foreach(change, name, child) {
            (void)child;
            if (strcmp(name, "ssid_id") && strcmp(name, "name") &&
                strcmp(name, "enabled") && strcmp(name, "bindings"))
                ac_wifi_validate_error(errors, "ssid_field_unknown", &valid);
        }
    }
    if (json_object_object_get_ex(change, "name", &field) && field) {
        const char *name_value = json_object_is_type(field,
            json_type_string) ? json_object_get_string(field) : NULL;
        size_t length = name_value ? strlen(name_value) : 0;

        if (!name_value || length == 0 ||
            length > AC_WIFI_VALIDATE_SSID_NAME_MAX ||
            !ac_wifi_validate_utf8((const unsigned char *)name_value,
                                   length))
            ac_wifi_validate_error(errors, "ssid_name_invalid", &valid);
    } else {
        ac_wifi_validate_error(errors, "ssid_name_missing", &valid);
    }
    if (json_object_object_get_ex(change, "enabled", &field) && field &&
        !json_object_is_type(field, json_type_boolean))
        ac_wifi_validate_error(errors, "ssid_enabled_invalid", &valid);
    if (json_object_object_get_ex(change, "bindings", &field) && field) {
        size_t i;

        if (!json_object_is_type(field, json_type_array) ||
            json_object_array_length(field) == 0 ||
            json_object_array_length(field) > AC_WIFI_VALIDATE_RADIOS_MAX) {
            ac_wifi_validate_error(errors, "ssid_bindings_invalid", &valid);
        } else {
            for (i = 0; i < json_object_array_length(field); i++) {
                struct json_object *binding =
                    json_object_array_get_idx(field, i);
                struct json_object *bound_radio = NULL;
                struct json_object *evidence_root = NULL;
                struct json_object *catalog = NULL;
                const char *radio_id = NULL;
                const char *reason = NULL;

                if (!binding ||
                    !json_object_is_type(binding, json_type_object) ||
                    !json_object_object_get_ex(binding, "radio_id",
                                               &bound_radio) ||
                    !bound_radio ||
                    !json_object_is_type(bound_radio, json_type_string) ||
                    !ac_wifi_validate_radio_id(
                        (radio_id = json_object_get_string(bound_radio)))) {
                    ac_wifi_validate_error(errors,
                                           "ssid_binding_radio_invalid",
                                           &valid);
                    continue;
                }
                evidence_root = ac_wifi_validate_evidence(ap_id, radio_id,
                                                          now, &catalog,
                                                          &reason);
                if (!evidence_root)
                    ac_wifi_validate_error(errors,
                        "ssid_binding_radio_evidence_missing", &valid);
                json_object_put(evidence_root);
            }
        }
    }
done:
    json_object_object_add(target, "valid", json_object_new_boolean(valid));
    json_object_object_add(target, "errors", errors);
    return target;
}

struct json_object *ac_db_wifi_transaction_validate_json(
    const char *ap_id, int64_t base_revision, const char *idempotency_key,
    const char *changes_json, int64_t now)
{
    struct json_object *root = json_object_new_object();
    struct json_object *targets = json_object_new_array();
    struct json_object *changes = NULL;
    struct json_object *radios = NULL;
    struct json_object *ssids = NULL;
    const char *error = NULL;
    int64_t current_revision = ac_db_wifi_desired_revision();
    int valid = 1;
    size_t i;

    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "contract_version",
                           json_object_new_string(AC_CONTRACT_VERSION));
    json_object_object_add(root, "source",
                           json_object_new_string(AC_SERVICE_NAME));
    json_object_object_add(root, "operation",
                           json_object_new_string("wifi_transaction_validate"));
    json_object_object_add(root, "observed_at",
                           json_object_new_int64(now));
    json_object_object_add(root, "ap_id",
                           json_object_new_string(ap_id ? ap_id : ""));
    json_object_object_add(root, "idempotency_key",
        json_object_new_string(idempotency_key ? idempotency_key : ""));
    json_object_object_add(root, "base_revision",
                           json_object_new_int64(base_revision));
    json_object_object_add(root, "current_revision",
                           json_object_new_int64(current_revision));
    if (base_revision != current_revision) {
        error = "revision_conflict";
        goto done;
    }
    if (!changes_json ||
        strlen(changes_json) > AC_WIFI_VALIDATE_CHANGES_MAX) {
        error = "changes_too_large";
        goto done;
    }
    changes = json_tokener_parse(changes_json);
    if (!changes || !json_object_is_type(changes, json_type_object)) {
        error = "changes_invalid_json";
        goto done;
    }
    {
        int unknown = 0;

        json_object_object_foreach(changes, name, child) {
            (void)child;
            if (strcmp(name, "radios") && strcmp(name, "ssids"))
                unknown = 1;
        }
        if (unknown) {
            error = "changes_unknown_field";
            goto done;
        }
    }
    if (ac_wifi_validate_has_secret_key(changes)) {
        error = "secret_in_validate";
        goto done;
    }
    json_object_object_get_ex(changes, "radios", &radios);
    json_object_object_get_ex(changes, "ssids", &ssids);
    if ((radios && (!json_object_is_type(radios, json_type_array) ||
                    json_object_array_length(radios) >
                        AC_WIFI_VALIDATE_RADIOS_MAX)) ||
        (ssids && (!json_object_is_type(ssids, json_type_array) ||
                   json_object_array_length(ssids) >
                       AC_WIFI_VALIDATE_SSIDS_MAX))) {
        error = "changes_target_bounds";
        goto done;
    }
    if ((!radios || json_object_array_length(radios) == 0) &&
        (!ssids || json_object_array_length(ssids) == 0)) {
        error = "changes_empty";
        goto done;
    }
    for (i = 0; radios && i < json_object_array_length(radios); i++) {
        struct json_object *target = ac_wifi_validate_radio_target(
            ap_id, json_object_array_get_idx(radios, i), now);
        struct json_object *target_valid = NULL;

        if (json_object_object_get_ex(target, "valid", &target_valid) &&
            !json_object_get_boolean(target_valid))
            valid = 0;
        json_object_array_add(targets, target);
    }
    for (i = 0; ssids && i < json_object_array_length(ssids); i++) {
        struct json_object *target = ac_wifi_validate_ssid_target(
            ap_id, json_object_array_get_idx(ssids, i), now);
        struct json_object *target_valid = NULL;

        if (json_object_object_get_ex(target, "valid", &target_valid) &&
            !json_object_get_boolean(target_valid))
            valid = 0;
        json_object_array_add(targets, target);
    }
done:
    if (error) {
        valid = 0;
        json_object_object_add(root, "error",
                               json_object_new_string(error));
    }
    json_object_object_add(root, "valid", json_object_new_boolean(valid));
    json_object_object_add(root, "targets", targets);
    json_object_put(changes);
    return root;
}

/* ---- Config job store and candidate contract. ---- */

#define AC_CONFIG_CANDIDATE_FORMAT "uci-wireless-candidate.v1"
#define AC_CONFIG_CANDIDATE_SECTIONS_MAX 16U
/* Counts options and list-option *names* together, exactly as APD does
 * (APD_CONFIG_OPTIONS_MAX), because the number a candidate is measured against
 * is whichever side is stricter and that side is the AP.
 *
 * 8 was too small for the work already shipped: an FT member section carries
 * ieee80211r, ieee80211k, ieee80211v, bss_transition, rrm_neighbor_report,
 * mobility_domain, ft_over_ds and nas_identifier -- eight -- plus the r0kh and
 * r1kh lists, which appear as soon as a domain has a second member.  Ten
 * against a limit of eight, so every FT domain worth having was refused by APD
 * with candidate_options_bounds after the AC had already journalled the
 * transaction.  Neither constant guards an array, so raising both is a bound
 * change only; a test pins them to each other. */
#define AC_CONFIG_CANDIDATE_OPTIONS_MAX 16U
#define AC_CONFIG_CANDIDATE_LIST_OPTIONS_MAX 32U
#define AC_CONFIG_CANDIDATE_NAME_MAX 32U
#define AC_CONFIG_CANDIDATE_VALUE_MAX 64U
/* One option carries a structured JSON document rather than a UCI scalar, so
 * it cannot live under the 64-byte, quote-free rule above.  See
 * ac_config_candidate_option_value_valid().  Defined from the shared header so
 * the bound cannot drift away from the checker that enforces it. */
#define AC_CONFIG_CANDIDATE_JSON_VALUE_MAX DREAMINGWRT_MLO_MEMBERS_VALUE_MAX

static int ac_config_candidate_name_valid(const char *value)
{
    size_t i;
    size_t length = value ? strlen(value) : 0;

    if (length == 0 || length > AC_CONFIG_CANDIDATE_NAME_MAX)
        return 0;
    for (i = 0; i < length; i++)
        if (!((value[i] >= 'a' && value[i] <= 'z') ||
              (value[i] >= '0' && value[i] <= '9') || value[i] == '_'))
            return 0;
    return 1;
}

static int ac_config_candidate_value_valid(const char *value)
{
    size_t i;
    size_t length = value ? strlen(value) : 0;

    if (length == 0 || length > AC_CONFIG_CANDIDATE_VALUE_MAX)
        return 0;
    for (i = 0; i < length; i++) {
        unsigned char c = (unsigned char)value[i];

        if (c < 0x20 || c > 0x7e || c == '\'' || c == '"' || c == '\\')
            return 0;
    }
    return 1;
}

/* Per-option value check.  Every option is a UCI scalar under the rule above
 * except `dreamingwrt_mlo_members`, whose value is the JSON record of what an
 * MLO group looked like before it was merged: it contains double quotes and
 * runs past 64 bytes, so the scalar rule refused it with
 * candidate_value_invalid even after the name was added to the allow-list.
 * The structured check lives in ../ap_mlo_members.h so that this side and APD
 * cannot disagree -- a divergence would produce a transaction the controller
 * journals and the AP is certain to refuse. */
static int ac_config_candidate_option_value_valid(const char *option,
                                                  const char *value)
{
    if (dreamingwrt_mlo_members_option(option))
        return dreamingwrt_mlo_members_value_valid(value);
    return ac_config_candidate_value_valid(value);
}

/* Options whose value is secret material.
 *
 * Refused explicitly, and before the allow-list, so a caller is told the real
 * reason instead of reading a generic "not allowed" as a vocabulary gap it
 * could close by adding a name here.  APD refuses the same three
 * (apd_config_option_secret) for a reason that cannot be answered on this
 * side: its rollback journals each option's previous value, so carrying a
 * passphrase would put it in clear into the AP's job journal, and redacting it
 * instead would make a rollback delete the passphrase rather than restore it.
 * Changing one needs the compensating transaction driven from the AC secret
 * store that capability `password_rotation` still reports as
 * phase2_secret_safe_apply_pending. */
static int ac_config_candidate_option_secret(const char *name)
{
    return name && (!strcmp(name, "key") || !strcmp(name, "wpa_passphrase") ||
                    !strcmp(name, "auth_secret"));
}

static int ac_config_candidate_option_allowed(const char *name)
{
    static const char *const allowed[] = {
        "channel", "htmode", "txpower", "disabled", "ssid",
        /* wifi-iface (SSID) options.  An option APD accepts and this side
         * drops is a write the controller can never send, which is how
         * ssid_create stayed at transaction_scope_not_supported while the AP
         * had been ready for it; the two lists are pinned to each other by
         * tests/test_ac_wifi_transaction_runtime.py.  Secrets are absent from
         * both by design -- see ac_config_candidate_option_secret. */
        "device", "mode", "network", "encryption", "mlo",
        "dreamingwrt_mlo_members",
        "hidden", "isolate", "ifname", "ieee80211w", "wpa_group_rekey",
        "macfilter", "maxassoc",
        /* Roaming-domain 11r/k/v options (Phase 1). */
        "ieee80211r", "ieee80211k", "ieee80211v",
        "bss_transition", "rrm_neighbor_report", "rrm_beacon_report",
        "mobility_domain", "ft_over_ds", "ft_protocol",
        "nas_identifier",
    };
    size_t i;

    for (i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++)
        if (!strcmp(name, allowed[i]))
            return 1;
    return 0;
}

static int ac_config_candidate_list_option_allowed(const char *name)
{
    static const char *const allowed[] = {
        "r0kh", "r1kh", "device",
    };
    size_t i;

    for (i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++)
        if (!strcmp(name, allowed[i]))
            return 1;
    return 0;
}

/* A hostapd runtime action is not a UCI option write.
 *
 * APD splits the two apart before its config executor ever runs: any section
 * whose options carry `hostapd_action_type` is dispatched over the hostapd
 * control socket instead (apd_config_apply_hostapd_actions), and never reaches
 * /etc/config/wireless.  Validating those sections against the UCI allow-list
 * therefore rejects every steering action the AC emits -- including the
 * SET_NEIGHBOR sections a Phase 1 roaming apply attaches, which took the whole
 * apply down with `target_invalid` whenever 11k was enabled.
 *
 * They still get validated, just against their own vocabulary, so an unknown
 * action option is refused here rather than silently ignored at the AP. */
static int ac_config_candidate_section_is_action(struct json_object *options)
{
    return options && json_object_object_get(options, "hostapd_action_type");
}

/* Must stay in step with APD's dispatcher: an action type this side accepts
 * and that side does not know is counted there as a failure, and one this side
 * rejects can never be sent at all. */
static int ac_config_candidate_action_type_valid(const char *value)
{
    static const char *const allowed[] = {
        "set_neighbor", "del_neighbor",  /* 11k neighbour report */
        "btm_request",                   /* 11v BSS transition */
        "beacon_request",                /* 11k beacon measurement */
        "deauth_request",                /* Phase 4 forced disassociation */
        "reassoc_block",
    };
    size_t i;

    if (!value)
        return 0;
    for (i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++)
        if (!strcmp(value, allowed[i]))
            return 1;
    return 0;
}

static int ac_config_candidate_action_option_allowed(const char *name)
{
    static const char *const allowed[] = {
        "hostapd_action_type", "station_mac",
        /* set_neighbor / del_neighbor */
        "neighbor_bssid", "neighbor_ssid", "neighbor_opclass",
        "neighbor_channel", "neighbor_phy", "neighbor_ft",
        "source_bssid", "source_ssid",
        /* btm_request */
        "target_bssid", "target_opclass", "target_channel", "target_phy",
        "target_ft", "btm_validity",
        "target_bssid_2", "target_opclass_2", "target_channel_2",
        "target_phy_2", "target_ft_2", "btm_disassoc_imminent",
        "btm_disassoc_timer",
        /* beacon_request */
        "measure_opclass", "measure_channel", "measure_duration_tu", "measure_ssid",
        "measure_bssid",
        /* deauth_request */
        "deauth_reason",
        "block_scope", "block_duration_sec", "target_frequency_mhz",
        "block_not_after",
    };
    size_t i;

    for (i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++)
        if (!strcmp(name, allowed[i]))
            return 1;
    return 0;
}

/* An action section is addressed by the *BSS* it acts on, which is either a
 * hostapd interface name (`wlan0-1`, `phy0-ap0`) or a BSSID
 * (`02:00:00:00:10:01`) -- APD accepts either and resolves a BSSID by matching
 * STATUS across its sockets.  Both contain characters a UCI section name may
 * not, so this cannot reuse ac_config_candidate_name_valid.  Still a strict
 * character class, because the value ends up in a control-socket command:
 * alnum, `-`, `_`, `.` and `:` only, and never an AP UUID.  Uppercase is
 * accepted because a BSSID is routinely written that way and the bindings
 * table compares them COLLATE NOCASE; a mis-cased interface name simply fails
 * to resolve at the AP, which is a reported failure rather than a silent one. */
static int ac_config_candidate_action_section_valid(const char *value)
{
    size_t i;
    size_t length = value ? strlen(value) : 0;

    if (length == 0 || length > AC_CONFIG_CANDIDATE_NAME_MAX)
        return 0;
    for (i = 0; i < length; i++)
        if (!((value[i] >= 'a' && value[i] <= 'z') ||
              (value[i] >= 'A' && value[i] <= 'Z') ||
              (value[i] >= '0' && value[i] <= '9') ||
              value[i] == '_' || value[i] == '-' || value[i] == '.' ||
              value[i] == ':'))
            return 0;
    return 1;
}

/* A section with no explicit operation is a plain option update, which is what
 * every candidate written before SSID CRUD existed means.  Same default as
 * APD's apd_config_section_operation, and it has to stay the same: the marker
 * is digest-bound, so a disagreement about the default would make every
 * pre-existing candidate's digest mismatch. */
static const char *ac_config_candidate_section_operation(
    struct json_object *section)
{
    struct json_object *operation = NULL;

    if (section &&
        json_object_object_get_ex(section, "operation", &operation) &&
        operation && json_object_is_type(operation, json_type_string))
        return json_object_get_string(operation);
    return "set";
}

static int ac_config_candidate_operation_valid(const char *value)
{
    return value && (!strcmp(value, "set") || !strcmp(value, "create") ||
                     !strcmp(value, "delete"));
}

/* A UCI section *type* is not a section name: the real types are `wifi-iface`
 * and `wifi-device`, and both contain '-', which a name may not.  So types get
 * their own check, and it is a single value rather than a character class --
 * the only type a candidate has business creating is a VAP.  A `wifi-device`
 * is a radio, enumerated from hardware that is present, and inventing one
 * would describe a radio that does not exist.  APD's
 * apd_config_section_type_allowed is the same single value; widening one
 * without the other produces a create the AP refuses. */
static int ac_config_candidate_section_type_allowed(const char *value)
{
    return value && !strcmp(value, "wifi-iface");
}

static int ac_config_candidate_digest(struct json_object *sections,
                                      char out[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1])
{
    EVP_MD_CTX *context = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length = 0;
    static const char hex[] = "0123456789abcdef";
    size_t i;

    if (!sections || !(context = EVP_MD_CTX_new()) ||
        EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1)
        goto fail;
    for (i = 0; i < json_object_array_length(sections); i++) {
        struct json_object *section = json_object_array_get_idx(sections, i);
        struct json_object *name = NULL;
        struct json_object *options = NULL;
        struct json_object *list_options = NULL;
        const char *section_name;
        const char *operation;

        if (!json_object_object_get_ex(section, "section", &name) ||
            !json_object_object_get_ex(section, "options", &options))
            goto fail;
        section_name = json_object_get_string(name);
        if (EVP_DigestUpdate(context, section_name, strlen(section_name)) != 1 ||
            EVP_DigestUpdate(context, "\n", 1) != 1)
            goto fail;
        /* Bind the operation in, or a candidate could be flipped from create to
         * delete without changing its digest and still verify.  Emitted only
         * when it is not the default "set", byte for byte as APD writes it
         * (apd_config_digest_hex_internal), so every candidate written before
         * SSID CRUD keeps the digest it already has. */
        operation = ac_config_candidate_section_operation(section);
        if (strcmp(operation, "set") &&
            (EVP_DigestUpdate(context, "!", 1) != 1 ||
             EVP_DigestUpdate(context, operation, strlen(operation)) != 1 ||
             EVP_DigestUpdate(context, "\n", 1) != 1))
            goto fail;
        json_object_object_foreach(options, option, value) {
            const char *text = json_object_get_string(value);

            if (EVP_DigestUpdate(context, option, strlen(option)) != 1 ||
                EVP_DigestUpdate(context, "=", 1) != 1 ||
                EVP_DigestUpdate(context, text, strlen(text)) != 1 ||
                EVP_DigestUpdate(context, "\n", 1) != 1)
                goto fail;
        }
        /* A section carrying no list at all is the common case -- a plain
         * option write, and every hostapd action -- but json-c's foreach
         * dereferences the hash table without checking it, so iterating the
         * absent object segfaults instead of iterating nothing.  Any apply
         * whose candidate had a section without list_options took the AC down
         * here, which is also why no fixture could reach the code past this
         * point.  The type check is not redundant with the validator: the
         * roaming dispatchers digest sections they assembled themselves and
         * never pass through it. */
        if (json_object_object_get_ex(section, "list_options", &list_options) &&
            json_object_is_type(list_options, json_type_object)) {
            json_object_object_foreach(list_options, lo_name, values) {
                size_t j;

                if (!values || !json_object_is_type(values, json_type_array))
                    goto fail;
                for (j = 0; j < json_object_array_length(values); j++) {
                    struct json_object *entry =
                        json_object_array_get_idx(values, j);
                    const char *text = json_object_get_string(entry);

                    if (EVP_DigestUpdate(context, lo_name,
                                         strlen(lo_name)) != 1 ||
                        EVP_DigestUpdate(context, "=", 1) != 1 ||
                        EVP_DigestUpdate(context, text, strlen(text)) != 1 ||
                        EVP_DigestUpdate(context, "\n", 1) != 1)
                        goto fail;
                }
            }
        }
    }
    if (EVP_DigestFinal_ex(context, digest, &digest_length) != 1 ||
        digest_length != SHA256_DIGEST_LENGTH)
        goto fail;
    EVP_MD_CTX_free(context);
    memcpy(out, "sha256:", 7);
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        out[7 + i * 2] = hex[digest[i] >> 4];
        out[8 + i * 2] = hex[digest[i] & 0x0f];
    }
    out[AC_RADIO_JOB_RESULT_DIGEST_MAX] = '\0';
    OPENSSL_cleanse(digest, sizeof(digest));
    return 0;
fail:
    EVP_MD_CTX_free(context);
    OPENSSL_cleanse(digest, sizeof(digest));
    return -1;
}

static int ac_config_candidate_validate(const char *candidate_json,
                                        const char *expected_digest,
                                        char **canonical_out,
                                        char *error_out, size_t error_len)
{
    struct json_object *candidate = NULL;
    struct json_object *format = NULL;
    struct json_object *digest = NULL;
    struct json_object *sections = NULL;
    const char *canonical;
    char computed[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1];
    size_t i;
    int valid = 0;

#define AC_CANDIDATE_FAIL(code_) do { \
    if (error_out && error_len) snprintf(error_out, error_len, "%s", (code_)); \
    goto done; \
} while (0)

    if (canonical_out)
        *canonical_out = NULL;
    if (!candidate_json || !candidate_json[0] ||
        strlen(candidate_json) > AC_CONFIG_JOB_CANDIDATE_MAX_BYTES ||
        !ac_radio_job_digest_valid(expected_digest))
        AC_CANDIDATE_FAIL("candidate_invalid");
    candidate = json_tokener_parse(candidate_json);
    if (!candidate || !json_object_is_type(candidate, json_type_object))
        AC_CANDIDATE_FAIL("candidate_not_object");
    {
        size_t fields = 0;
        json_object_object_foreach(candidate, name, child) {
            (void)child;
            fields++;
            if (strcmp(name, "format") && strcmp(name, "candidate_digest") &&
                strcmp(name, "sections"))
                AC_CANDIDATE_FAIL("candidate_unknown_field");
        }
        if (fields != 3)
            AC_CANDIDATE_FAIL("candidate_fields_incomplete");
    }
    if (!json_object_object_get_ex(candidate, "format", &format) || !format ||
        !json_object_is_type(format, json_type_string) ||
        strcmp(json_object_get_string(format), AC_CONFIG_CANDIDATE_FORMAT))
        AC_CANDIDATE_FAIL("candidate_format_invalid");
    if (!json_object_object_get_ex(candidate, "candidate_digest", &digest) ||
        !digest || !json_object_is_type(digest, json_type_string) ||
        strcmp(json_object_get_string(digest), expected_digest))
        AC_CANDIDATE_FAIL("candidate_digest_mismatch");
    if (!json_object_object_get_ex(candidate, "sections", &sections) ||
        !sections || !json_object_is_type(sections, json_type_array) ||
        json_object_array_length(sections) == 0 ||
        json_object_array_length(sections) > AC_CONFIG_CANDIDATE_SECTIONS_MAX)
        AC_CANDIDATE_FAIL("candidate_sections_invalid");
    for (i = 0; i < json_object_array_length(sections); i++) {
        struct json_object *section = json_object_array_get_idx(sections, i);
        struct json_object *name = NULL;
        struct json_object *options = NULL;
        struct json_object *action_type = NULL;
        struct json_object *operation = NULL;
        struct json_object *section_type = NULL;
        const char *op = "set";
        size_t fields = 0;
        size_t option_count = 0;
        int is_action;
        int has_operation;
        int has_section_type;

        if (!section || !json_object_is_type(section, json_type_object))
            AC_CANDIDATE_FAIL("candidate_section_invalid");
        json_object_object_foreach(section, key, child) {
            (void)child;
            fields++;
            if (strcmp(key, "section") && strcmp(key, "options") &&
                strcmp(key, "list_options") && strcmp(key, "operation") &&
                strcmp(key, "section_type"))
                AC_CANDIDATE_FAIL("candidate_section_unknown_field");
        }
        if (fields < 2 || fields > 5 ||
            !json_object_object_get_ex(section, "section", &name) || !name ||
            !json_object_is_type(name, json_type_string) ||
            !json_object_object_get_ex(section, "options", &options) ||
            !options || !json_object_is_type(options, json_type_object))
            AC_CANDIDATE_FAIL("candidate_section_invalid");
        is_action = ac_config_candidate_section_is_action(options);
        if (!(is_action ?
                ac_config_candidate_action_section_valid(
                    json_object_get_string(name)) :
                ac_config_candidate_name_valid(json_object_get_string(name))))
            AC_CANDIDATE_FAIL("candidate_section_invalid");
        has_operation = json_object_object_get_ex(section, "operation",
                                                 &operation);
        has_section_type = json_object_object_get_ex(section, "section_type",
                                                    &section_type);
        /* A hostapd action is dispatched over a control socket and never
         * reaches /etc/config/wireless, so there is no section for an operation
         * to create or delete -- and nothing on the AP side would notice one.
         * APD digests the whole array (apd_openwrt_apply verifies the parent
         * digest before splitting), so `!delete` would be signed in, but the
         * action sections are then handed to the dispatcher and only the UCI
         * subset reaches apd_config_candidate_check.  The result is a candidate
         * whose digest attests a delete and whose effect is a runtime action. */
        if (is_action && (has_operation || has_section_type))
            AC_CANDIDATE_FAIL("candidate_action_operation_unexpected");
        if (has_operation) {
            if (!operation || !json_object_is_type(operation, json_type_string))
                AC_CANDIDATE_FAIL("candidate_operation_invalid");
            op = json_object_get_string(operation);
            if (!ac_config_candidate_operation_valid(op))
                AC_CANDIDATE_FAIL("candidate_operation_invalid");
        }
        /* A create needs a type to create the section as; a set or a delete
         * must not carry one, so the field cannot be used to retype an existing
         * section behind the operation's back. */
        if (!strcmp(op, "create")) {
            if (!has_section_type || !section_type ||
                !json_object_is_type(section_type, json_type_string) ||
                !ac_config_candidate_section_type_allowed(
                    json_object_get_string(section_type)))
                AC_CANDIDATE_FAIL("candidate_section_type_invalid");
        } else if (has_section_type) {
            AC_CANDIDATE_FAIL("candidate_section_type_unexpected");
        }
        json_object_object_foreach(options, option, value) {
            option_count++;
            /* Checked before the allow-list, and for both section kinds, so the
             * caller is told the real reason rather than a generic "not
             * allowed" it might try to close by adding a name to a list. */
            if (ac_config_candidate_option_secret(option))
                AC_CANDIDATE_FAIL("candidate_option_secret_not_supported");
            if (!(is_action ?
                    ac_config_candidate_action_option_allowed(option) :
                    ac_config_candidate_option_allowed(option)))
                AC_CANDIDATE_FAIL("candidate_option_not_allowed");
            if (!value || !json_object_is_type(value, json_type_string) ||
                !ac_config_candidate_option_value_valid(
                    option, json_object_get_string(value)))
                AC_CANDIDATE_FAIL("candidate_value_invalid");
        }
        /* Reject an unknown action here rather than letting it travel.  APD
         * does count it as a failure, but only after the transaction has been
         * journalled and leased, so the audit trail records a dispatched
         * action that no AP could ever have performed. */
        if (is_action &&
            (!json_object_object_get_ex(options, "hostapd_action_type",
                                        &action_type) ||
             !ac_config_candidate_action_type_valid(
                 json_object_get_string(action_type))))
            AC_CANDIDATE_FAIL("candidate_action_type_invalid");
        /* Validate list_options if present. */
        {
            struct json_object *list_options = NULL;

            if (json_object_object_get_ex(section, "list_options",
                                          &list_options)) {
                size_t list_option_count = 0;

                /* No hostapd action takes a list.  One here means the section
                 * was assembled wrong, and APD would drop it without a word. */
                if (is_action)
                    AC_CANDIDATE_FAIL("candidate_list_options_invalid");
                if (!json_object_is_type(list_options, json_type_object))
                    AC_CANDIDATE_FAIL("candidate_list_options_invalid");
                json_object_object_foreach(list_options, lo_name, values) {
                    size_t j;

                    list_option_count++;
                    if (!ac_config_candidate_list_option_allowed(lo_name))
                        AC_CANDIDATE_FAIL("candidate_list_option_not_allowed");
                    if (!values ||
                        !json_object_is_type(values, json_type_array) ||
                        json_object_array_length(values) == 0 ||
                        json_object_array_length(values) >
                            AC_CONFIG_CANDIDATE_LIST_OPTIONS_MAX)
                        AC_CANDIDATE_FAIL("candidate_list_option_values_invalid");
                    for (j = 0; j < json_object_array_length(values); j++) {
                        struct json_object *entry =
                            json_object_array_get_idx(values, j);

                        if (!entry ||
                            !json_object_is_type(entry, json_type_string) ||
                            !ac_config_candidate_value_valid(
                                json_object_get_string(entry)))
                            AC_CANDIDATE_FAIL("candidate_list_option_value_invalid");
                    }
                }
                option_count += list_option_count;
            }
        }
        /* Counted after the lists, and against the same limit, because that is
         * how APD counts.  Checking before them left the combined bound
         * unenforced on this side -- the `option_count +=` above fed nothing --
         * so the AC could forward a section APD was certain to refuse.
         *
         * A delete removes the whole section, so it legitimately carries no
         * options; every other operation must name at least one. */
        if ((option_count == 0 && strcmp(op, "delete")) ||
            option_count > AC_CONFIG_CANDIDATE_OPTIONS_MAX)
            AC_CANDIDATE_FAIL("candidate_options_bounds");
    }
    if (ac_config_candidate_digest(sections, computed) != 0 ||
        strcmp(computed, expected_digest))
        AC_CANDIDATE_FAIL("candidate_digest_mismatch");
    canonical = json_object_to_json_string_ext(candidate, JSON_C_TO_STRING_PLAIN);
    if (!canonical || strlen(canonical) > AC_CONFIG_JOB_CANDIDATE_MAX_BYTES ||
        (canonical_out && !(*canonical_out = strdup(canonical))))
        AC_CANDIDATE_FAIL("candidate_canonicalization_failed");
    valid = 1;
done:
    json_object_put(candidate);
    if (!valid && canonical_out) {
        free(*canonical_out);
        *canonical_out = NULL;
    }
#undef AC_CANDIDATE_FAIL
    return valid ? 0 : -1;
}

static int ac_config_readback_validate(const char *readback_json,
                                       const char *candidate_digest,
                                       int require_match,
                                       char readback_digest[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1],
                                       char **canonical_out)
{
    struct json_object *readback = NULL;
    struct json_object *candidate = NULL;
    struct json_object *digest = NULL;
    struct json_object *match = NULL;
    struct json_object *ok = NULL;
    const char *canonical;
    int valid = 0;

    if (readback_digest)
        readback_digest[0] = '\0';
    if (canonical_out)
        *canonical_out = NULL;
    if (!readback_json || !readback_json[0] ||
        strlen(readback_json) > AC_CONFIG_JOB_READBACK_MAX_BYTES)
        return require_match ? -1 : 0;
    readback = json_tokener_parse(readback_json);
    if (!readback || !json_object_is_type(readback, json_type_object))
        goto done;
    if (json_object_object_get_ex(readback, "readback_digest", &digest) &&
        digest && json_object_is_type(digest, json_type_string) &&
        ac_radio_job_digest_valid(json_object_get_string(digest)) &&
        readback_digest)
        snprintf(readback_digest, AC_RADIO_JOB_RESULT_DIGEST_MAX + 1, "%s",
                 json_object_get_string(digest));
    if (require_match &&
        (!json_object_object_get_ex(readback, "ok", &ok) || !ok ||
         !json_object_is_type(ok, json_type_boolean) ||
         !json_object_get_boolean(ok) ||
         !json_object_object_get_ex(readback, "match", &match) || !match ||
         !json_object_is_type(match, json_type_boolean) ||
         !json_object_get_boolean(match) ||
         !json_object_object_get_ex(readback, "candidate_digest", &candidate) ||
         !candidate || !json_object_is_type(candidate, json_type_string) ||
         strcmp(json_object_get_string(candidate), candidate_digest) ||
         !readback_digest || !readback_digest[0] ||
         strcmp(readback_digest, candidate_digest)))
        goto done;
    canonical = json_object_to_json_string_ext(readback, JSON_C_TO_STRING_PLAIN);
    if (!canonical || strlen(canonical) > AC_CONFIG_JOB_READBACK_MAX_BYTES ||
        (canonical_out && !(*canonical_out = strdup(canonical))))
        goto done;
    valid = 1;
done:
    json_object_put(readback);
    if (!valid && canonical_out) {
        free(*canonical_out);
        *canonical_out = NULL;
    }
    return valid ? 0 : -1;
}

static int AC_DB_STANDALONE_UNUSED
ac_config_rollback_readback_validate(const char *readback_json,
                                     char **canonical_out)
{
    struct json_object *readback = NULL;
    struct json_object *ok = NULL;
    struct json_object *match = NULL;
    struct json_object *operation = NULL;
    const char *canonical;
    int parsed = 0;
    int valid = 0;

    if (canonical_out)
        *canonical_out = NULL;
    if (!readback_json || !readback_json[0] ||
        strlen(readback_json) > AC_CONFIG_JOB_READBACK_MAX_BYTES)
        return -1;
    readback = json_tokener_parse(readback_json);
    if (!readback || !json_object_is_type(readback, json_type_object))
        goto done;
    canonical = json_object_to_json_string_ext(readback,
                                               JSON_C_TO_STRING_PLAIN);
    if (!canonical || strlen(canonical) > AC_CONFIG_JOB_READBACK_MAX_BYTES ||
        (canonical_out && !(*canonical_out = strdup(canonical))))
        goto done;
    parsed = 1;
    if (!json_object_object_get_ex(readback, "ok", &ok) ||
        !json_object_is_type(ok, json_type_boolean) ||
        !json_object_get_boolean(ok) ||
        !json_object_object_get_ex(readback, "match", &match) ||
        !json_object_is_type(match, json_type_boolean) ||
        !json_object_get_boolean(match) ||
        !json_object_object_get_ex(readback, "operation", &operation) ||
        !json_object_is_type(operation, json_type_string) ||
        strcmp(json_object_get_string(operation), "rollback_readback"))
        goto done;
    valid = 1;
done:
    json_object_put(readback);
    if (!parsed && canonical_out) {
        free(*canonical_out);
        *canonical_out = NULL;
    }
    return valid ? 0 : -1;
}

static int ac_config_job_idempotency_valid(const char *value)
{
    size_t i;
    size_t len = value ? strlen(value) : 0;

    if (len == 0 || len > AC_RADIO_JOB_IDEMPOTENCY_MAX)
        return 0;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)value[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' ||
              c == ':' || c == '-'))
            return 0;
    }
    return 1;
}

#define AC_CONFIG_JOB_COLUMNS \
    "job_id,ap_id,state,idempotency_key,candidate_digest,created_at," \
    "updated_at,lease_expires_at,session_epoch,attempt_id," \
    "dispatch_generation,request_digest,finish_id,outcome,error_code," \
    "operation,rollback_of_job_id"

static void ac_config_job_copy(char *out, size_t size,
                               const unsigned char *value)
{
    snprintf(out, size, "%s", value ? (const char *)value : "");
}

static void ac_config_job_from_stmt(sqlite3_stmt *st,
                                    struct ac_config_job *out)
{
    memset(out, 0, sizeof(*out));
    ac_config_job_copy(out->job_id, sizeof(out->job_id),
                       sqlite3_column_text(st, 0));
    ac_config_job_copy(out->ap_id, sizeof(out->ap_id),
                       sqlite3_column_text(st, 1));
    ac_config_job_copy(out->state, sizeof(out->state),
                       sqlite3_column_text(st, 2));
    ac_config_job_copy(out->idempotency_key, sizeof(out->idempotency_key),
                       sqlite3_column_text(st, 3));
    ac_config_job_copy(out->candidate_digest,
                       sizeof(out->candidate_digest),
                       sqlite3_column_text(st, 4));
    out->created_at = sqlite3_column_int64(st, 5);
    out->updated_at = sqlite3_column_int64(st, 6);
    out->lease_expires_at = sqlite3_column_int64(st, 7);
    ac_config_job_copy(out->session_epoch, sizeof(out->session_epoch),
                       sqlite3_column_text(st, 8));
    ac_config_job_copy(out->attempt_id, sizeof(out->attempt_id),
                       sqlite3_column_text(st, 9));
    out->dispatch_generation = sqlite3_column_int64(st, 10);
    ac_config_job_copy(out->request_digest, sizeof(out->request_digest),
                       sqlite3_column_text(st, 11));
    ac_config_job_copy(out->finish_id, sizeof(out->finish_id),
                       sqlite3_column_text(st, 12));
    ac_config_job_copy(out->outcome, sizeof(out->outcome),
                       sqlite3_column_text(st, 13));
    ac_config_job_copy(out->error_code, sizeof(out->error_code),
                       sqlite3_column_text(st, 14));
    ac_config_job_copy(out->operation, sizeof(out->operation),
                       sqlite3_column_text(st, 15));
    ac_config_job_copy(out->rollback_of_job_id,
                       sizeof(out->rollback_of_job_id),
                       sqlite3_column_text(st, 16));
}

static int ac_config_job_load(const char *job_id, struct ac_config_job *out)
{
    sqlite3_stmt *st = NULL;
    int rc = AC_CONFIG_JOB_ERROR;

    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT " AC_CONFIG_JOB_COLUMNS
            " FROM ac_config_jobs WHERE job_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        return AC_CONFIG_JOB_ERROR;
    sqlite3_bind_text(st, 1, job_id, -1, SQLITE_TRANSIENT);
    switch (sqlite3_step(st)) {
    case SQLITE_ROW:
        if (out)
            ac_config_job_from_stmt(st, out);
        rc = AC_CONFIG_JOB_OK;
        break;
    case SQLITE_DONE:
        rc = AC_CONFIG_JOB_NOT_FOUND;
        break;
    default:
        break;
    }
    sqlite3_finalize(st);
    return rc;
}

static int ac_config_job_request_digest(
    const char *job_id, const char *ap_id, const char *candidate_digest,
    const char *operation, const char *rollback_of_job_id,
    const char *attempt_id, int64_t dispatch_generation,
    char out[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1])
{
    char input[512];
    int length;

    length = snprintf(input, sizeof(input),
        "ac-config-job-request-v2\n%s\n%s\n%s\n%s\n%s\n%s\n%lld\n",
        job_id, ap_id, candidate_digest, operation,
        rollback_of_job_id ? rollback_of_job_id : "", attempt_id,
        (long long)dispatch_generation);
    if (length < 0 || length >= (int)sizeof(input))
        return -1;
    return ac_radio_job_sha256(input, (size_t)length, out);
}

static int ac_config_job_binding_matches(
    const struct ac_config_job *job, const char *attempt_id,
    int64_t dispatch_generation, const char *request_digest,
    const char *ap_id, const char *session_epoch)
{
    return !strcmp(job->attempt_id, attempt_id) &&
           job->dispatch_generation == dispatch_generation &&
           !strcmp(job->request_digest, request_digest) &&
           !strcmp(job->ap_id, ap_id) &&
           !strcmp(job->session_epoch, session_epoch);
}

int ac_db_config_job_create(const char *ap_id, const char *candidate_json,
                            const char *candidate_digest,
                            const char *idempotency_key,
                            struct ac_config_job *out)
{
    sqlite3_stmt *st = NULL;
    char job_id[AC_RADIO_JOB_ID_LEN + 1] = { 0 };
    char candidate_error[AC_RADIO_JOB_ERROR_MAX + 1] = { 0 };
    char *canonical_candidate = NULL;
    int64_t now = ac_now_s();

    if (!g_ac_db || !ac_uuid_valid(ap_id) ||
        !ac_config_job_idempotency_valid(idempotency_key) ||
        ac_config_candidate_validate(candidate_json, candidate_digest,
                                     &canonical_candidate, candidate_error,
                                     sizeof(candidate_error)) != 0)
        return AC_CONFIG_JOB_INVALID;
    if (ac_exec("BEGIN IMMEDIATE") != 0) {
        free(canonical_candidate);
        return AC_CONFIG_JOB_ERROR;
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT " AC_CONFIG_JOB_COLUMNS " FROM ac_config_jobs "
            "WHERE ap_id=?1 AND idempotency_key=?2",
            -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, idempotency_key, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        struct ac_config_job existing;

        ac_config_job_from_stmt(st, &existing);
        sqlite3_finalize(st);
        st = NULL;
        ac_exec("ROLLBACK");
        free(canonical_candidate);
        if (strcmp(existing.candidate_digest, candidate_digest) != 0)
            return AC_CONFIG_JOB_CONFLICT;
        if (out)
            *out = existing;
        return AC_CONFIG_JOB_IDEMPOTENT;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (ac_generate_uuid(job_id) != 0 ||
        sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_config_jobs(job_id,ap_id,state,"
            "idempotency_key,candidate_json,candidate_digest,"
            "created_at,updated_at) VALUES(?1,?2,'queued',?3,?4,?5,?6,?6)",
            -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, job_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, idempotency_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, canonical_candidate, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, candidate_digest, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, now);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(st);
    st = NULL;
    if (ac_config_job_load(job_id, out) != AC_CONFIG_JOB_OK)
        goto fail;
    if (ac_exec("COMMIT") != 0)
        goto fail;
    free(canonical_candidate);
    return AC_CONFIG_JOB_OK;
fail:
    free(canonical_candidate);
    sqlite3_finalize(st);
    ac_exec("ROLLBACK");
    return AC_CONFIG_JOB_ERROR;
}

int ac_db_config_job_status(const char *job_id, struct ac_config_job *out)
{
    if (!g_ac_db || !ac_uuid_valid(job_id))
        return AC_CONFIG_JOB_INVALID;
    return ac_config_job_load(job_id, out);
}

int ac_db_config_job_lease_next(const char *ap_id,
                                const char *session_epoch, int64_t now,
                                struct ac_config_job *out,
                                char **candidate_json_out)
{
    sqlite3_stmt *st = NULL;
    char job_id[AC_RADIO_JOB_ID_LEN + 1] = { 0 };
    char candidate_digest[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1] = { 0 };
    char operation[9] = { 0 };
    char rollback_of_job_id[AC_RADIO_JOB_ID_LEN + 1] = { 0 };
    char attempt_id[AC_RADIO_JOB_ID_LEN + 1] = { 0 };
    char request_digest[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1] = { 0 };
    char *candidate = NULL;
    int64_t dispatch_generation = 0;

    if (!g_ac_db || !out || !candidate_json_out || now <= 0 ||
        !ac_uuid_valid(ap_id))
        return AC_CONFIG_JOB_INVALID;
    *candidate_json_out = NULL;
    if (ac_exec("BEGIN IMMEDIATE") != 0)
        return AC_CONFIG_JOB_ERROR;
    if (!ac_db_ap_write_session_is_current_locked(ap_id, session_epoch))
        goto fail;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT q.job_id,q.candidate_digest,q.dispatch_generation,"
            "q.candidate_json,q.operation,q.rollback_of_job_id "
            "FROM ac_config_jobs q "
            "WHERE q.ap_id=?1 AND q.state='queued' AND NOT EXISTS ("
            "SELECT 1 FROM ac_config_jobs a WHERE a.ap_id=q.ap_id "
            "AND a.state IN ('leased','running')) "
            "ORDER BY q.created_at,q.job_id LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        st = NULL;
        if (ac_exec("COMMIT") != 0)
            return AC_CONFIG_JOB_ERROR;
        return AC_CONFIG_JOB_NOT_FOUND;
    }
    ac_config_job_copy(job_id, sizeof(job_id), sqlite3_column_text(st, 0));
    ac_config_job_copy(candidate_digest, sizeof(candidate_digest),
                       sqlite3_column_text(st, 1));
    dispatch_generation = sqlite3_column_int64(st, 2) + 1;
    candidate = strdup(sqlite3_column_text(st, 3) ?
                       (const char *)sqlite3_column_text(st, 3) : "");
    ac_config_job_copy(operation, sizeof(operation), sqlite3_column_text(st, 4));
    ac_config_job_copy(rollback_of_job_id, sizeof(rollback_of_job_id),
                       sqlite3_column_text(st, 5));
    sqlite3_finalize(st);
    st = NULL;
    if (!candidate || !ac_uuid_valid(job_id) ||
        ac_generate_uuid(attempt_id) != 0 ||
        ac_config_job_request_digest(job_id, ap_id, candidate_digest,
                                     operation, rollback_of_job_id,
                                     attempt_id, dispatch_generation,
                                     request_digest) != 0 ||
        sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_config_jobs SET state='leased',session_epoch=?2,"
            "attempt_id=?3,dispatch_generation=?4,request_digest=?5,"
            "lease_expires_at=?6,updated_at=?7 WHERE job_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, job_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, session_epoch, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, attempt_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, dispatch_generation);
    sqlite3_bind_text(st, 5, request_digest, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, now + AC_CONFIG_JOB_LEASE_SECONDS);
    sqlite3_bind_int64(st, 7, now);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_transaction_targets SET state=CASE WHEN (SELECT "
            "operation FROM ac_config_jobs WHERE job_id=?1)='rollback' "
            "THEN 'rollback_leased' ELSE 'leased' END,updated_at=?2 "
            "WHERE transaction_id=(SELECT transaction_id FROM ac_config_jobs "
            "WHERE job_id=?1) AND ap_id=?3",
            -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, job_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now);
    sqlite3_bind_text(st, 3, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(st);
    st = NULL;
    if (ac_config_job_load(job_id, out) != AC_CONFIG_JOB_OK)
        goto fail;
    if (ac_exec("COMMIT") != 0)
        goto fail;
    *candidate_json_out = candidate;
    return AC_CONFIG_JOB_OK;
fail:
    free(candidate);
    sqlite3_finalize(st);
    ac_exec("ROLLBACK");
    return AC_CONFIG_JOB_ERROR;
}

int ac_db_config_job_mark_running(const char *job_id, const char *attempt_id,
                                  int64_t dispatch_generation,
                                  const char *request_digest,
                                  const char *ap_id,
                                  const char *session_epoch, int64_t now,
                                  struct ac_config_job *out)
{
    struct ac_config_job job;
    sqlite3_stmt *st = NULL;
    int rc;

    if (!g_ac_db || !ac_uuid_valid(job_id) || !ac_uuid_valid(attempt_id) ||
        dispatch_generation <= 0 ||
        !ac_radio_job_digest_valid(request_digest) ||
        !ac_uuid_valid(ap_id) || now <= 0)
        return AC_CONFIG_JOB_INVALID;
    if (ac_exec("BEGIN IMMEDIATE") != 0)
        return AC_CONFIG_JOB_ERROR;
    rc = ac_config_job_load(job_id, &job);
    if (rc != AC_CONFIG_JOB_OK) {
        ac_exec("ROLLBACK");
        return rc;
    }
    if (!ac_db_ap_write_session_is_current_locked(ap_id, session_epoch) ||
        !ac_config_job_binding_matches(&job, attempt_id,
                                       dispatch_generation, request_digest,
                                       ap_id, session_epoch)) {
        ac_exec("ROLLBACK");
        return AC_CONFIG_JOB_CONFLICT;
    }
    if (!strcmp(job.state, "running")) {
        ac_exec("ROLLBACK");
        if (out)
            *out = job;
        return AC_CONFIG_JOB_IDEMPOTENT;
    }
    if (strcmp(job.state, "leased") != 0) {
        ac_exec("ROLLBACK");
        return AC_CONFIG_JOB_CONFLICT;
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_config_jobs SET state='running',updated_at=?2 "
            "WHERE job_id=?1", -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, job_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_transaction_targets SET state=CASE WHEN (SELECT "
            "operation FROM ac_config_jobs WHERE job_id=?1)='rollback' "
            "THEN 'rollback_running' ELSE 'running' END,updated_at=?2 "
            "WHERE transaction_id=(SELECT transaction_id FROM ac_config_jobs "
            "WHERE job_id=?1) AND ap_id=?3",
            -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, job_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now);
    sqlite3_bind_text(st, 3, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(st);
    st = NULL;
    if (ac_config_job_load(job_id, out) != AC_CONFIG_JOB_OK)
        goto fail;
    if (ac_exec("COMMIT") != 0)
        goto fail;
    return AC_CONFIG_JOB_OK;
fail:
    sqlite3_finalize(st);
    ac_exec("ROLLBACK");
    return AC_CONFIG_JOB_ERROR;
}

int ac_db_config_job_finish(const char *job_id, const char *attempt_id,
                            int64_t dispatch_generation,
                            const char *request_digest, const char *ap_id,
                            const char *session_epoch,
                            const char *finish_id, const char *outcome,
                            const char *error_code,
                            const char *readback_json, int64_t now,
                            struct ac_config_job *out)
{
    struct ac_config_job job;
    sqlite3_stmt *st = NULL;
    char transaction_id[AC_RADIO_JOB_ID_LEN + 1] = { 0 };
    char readback_digest[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1] = { 0 };
    char *canonical_readback = NULL;
    const char *terminal;
    const char *stored_error;
    int is_rollback;
    char *stored_readback = NULL;
    int readback_valid;
    int rc;

    if (!g_ac_db || !ac_uuid_valid(job_id) || !ac_uuid_valid(attempt_id) ||
        dispatch_generation <= 0 ||
        !ac_radio_job_digest_valid(request_digest) ||
        !ac_uuid_valid(ap_id) || !ac_uuid_valid(finish_id) || now <= 0)
        return AC_CONFIG_JOB_INVALID;
    if (!outcome || !error_code ||
        strlen(error_code) > AC_RADIO_JOB_ERROR_MAX)
        return AC_CONFIG_JOB_INVALID;
    if (!strcmp(outcome, "applied")) {
        if (error_code[0])
            return AC_CONFIG_JOB_INVALID;
        terminal = "applied";
    } else if (!strcmp(outcome, "failed")) {
        if (!error_code[0])
            return AC_CONFIG_JOB_INVALID;
        terminal = "failed";
    } else if (!strcmp(outcome, "rolled_back")) {
        if (!error_code[0])
            return AC_CONFIG_JOB_INVALID;
        terminal = "rolled_back";
    } else {
        return AC_CONFIG_JOB_INVALID;
    }
    if (readback_json &&
        strlen(readback_json) > AC_CONFIG_JOB_READBACK_MAX_BYTES)
        return AC_CONFIG_JOB_INVALID;
    if (ac_exec("BEGIN IMMEDIATE") != 0)
        return AC_CONFIG_JOB_ERROR;
    rc = ac_config_job_load(job_id, &job);
    if (rc != AC_CONFIG_JOB_OK) {
        ac_exec("ROLLBACK");
        return rc;
    }
    if (strcmp(job.attempt_id, attempt_id) ||
        job.dispatch_generation != dispatch_generation ||
        strcmp(job.request_digest, request_digest) || strcmp(job.ap_id, ap_id) ||
        !ac_db_ap_write_session_is_current_locked(ap_id, session_epoch)) {
        ac_exec("ROLLBACK");
        return AC_CONFIG_JOB_CONFLICT;
    }
    is_rollback = !strcmp(job.operation, "rollback");
    if (!strcmp(job.state, "cancelled") &&
        !strcmp(job.error_code, "roaming_action_expired")) {
        /* Retire a late same-assignment receipt without reopening an expired
         * action. APD otherwise reconnects forever trying to finish recovery. */
        ac_exec("ROLLBACK");
        if (out) {
            *out = job;
            snprintf(out->finish_id, sizeof(out->finish_id), "%s", finish_id);
        }
        return AC_CONFIG_JOB_IDEMPOTENT;
    }
    if (is_rollback) {
        readback_valid = ac_config_rollback_readback_validate(
            readback_json, &canonical_readback) == 0;
        if (strcmp(outcome, "rolled_back") || !readback_valid) {
            terminal = "failed";
            stored_error = !readback_valid ?
                "rollback_readback_verification_failed" :
                (error_code[0] ? error_code : "rollback_failed");
        } else {
            terminal = "rolled_back";
            stored_error = error_code;
        }
    } else {
        readback_valid = ac_config_readback_validate(
            readback_json, job.candidate_digest, !strcmp(outcome, "applied"),
            readback_digest, &canonical_readback) == 0;
        if (!strcmp(outcome, "applied") && !readback_valid) {
            terminal = "failed";
            stored_error = "readback_verification_failed";
        } else {
            stored_error = error_code;
        }
    }
    if (job.finish_id[0]) {
        if (sqlite3_prepare_v2(g_ac_db,
                "SELECT readback_json FROM ac_config_jobs WHERE job_id=?1",
                -1, &st, NULL) != SQLITE_OK)
            goto fail;
        sqlite3_bind_text(st, 1, job_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_ROW ||
            !(stored_readback = strdup(sqlite3_column_text(st, 0) ?
                (const char *)sqlite3_column_text(st, 0) : "")))
            goto fail;
        sqlite3_finalize(st);
        st = NULL;
        ac_exec("ROLLBACK");
        if (!strcmp(job.finish_id, finish_id) &&
            !strcmp(job.outcome, outcome) && !strcmp(job.state, terminal) &&
            !strcmp(job.error_code, stored_error) &&
            !strcmp(stored_readback,
                    canonical_readback ? canonical_readback : "")) {
            free(stored_readback);
            free(canonical_readback);
            if (out)
                *out = job;
            return AC_CONFIG_JOB_IDEMPOTENT;
        }
        free(stored_readback);
        free(canonical_readback);
        return AC_CONFIG_JOB_CONFLICT;
    }
    if (strcmp(job.state, "leased") != 0 &&
        strcmp(job.state, "running") != 0) {
        ac_exec("ROLLBACK");
        free(canonical_readback);
        return AC_CONFIG_JOB_CONFLICT;
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT transaction_id FROM ac_config_jobs WHERE job_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, job_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW)
        goto fail;
    ac_config_job_copy(transaction_id, sizeof(transaction_id),
                       sqlite3_column_text(st, 0));
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_config_jobs SET state=?2,finish_id=?3,outcome=?4,"
            "error_code=?5,readback_json=?6,session_epoch=?7,"
            "lease_expires_at=0,updated_at=?8 WHERE job_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, job_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, terminal, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, finish_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, outcome, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, stored_error, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, canonical_readback ? canonical_readback : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, session_epoch, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 8, now);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto fail;
    sqlite3_finalize(st);
    st = NULL;
    if (transaction_id[0]) {
        const char *target_state = terminal;

        if ((!is_rollback && !strcmp(terminal, "failed") &&
             (!strncmp(stored_error, "rollback_", 9) ||
              strstr(stored_error, "rollback_failed"))) ||
            (is_rollback && strcmp(terminal, "rolled_back")))
            target_state = "rollback_failed";
        if (sqlite3_prepare_v2(g_ac_db,
                "UPDATE ac_transaction_targets SET state=?3,"
                "readback_digest=?4,error_code=?5,updated_at=?6 "
                "WHERE transaction_id=?1 AND ap_id=?2",
                -1, &st, NULL) != SQLITE_OK)
            goto fail;
        sqlite3_bind_text(st, 1, transaction_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, ap_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, target_state, -1, SQLITE_STATIC);
        sqlite3_bind_text(st, 4,
                          !strcmp(terminal, "applied") ? readback_digest : "",
                          -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, stored_error, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 6, now);
        if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
            goto fail;
        sqlite3_finalize(st);
        st = NULL;
        if (!is_rollback && !strcmp(terminal, "applied")) {
            if (sqlite3_prepare_v2(g_ac_db,
                    "UPDATE ac_aps SET applied_revision=(SELECT desired_revision "
                    "FROM ac_transactions WHERE transaction_id=?2),"
                    "readback_digest=?3 WHERE ap_id=?1",
                    -1, &st, NULL) != SQLITE_OK)
                goto fail;
            sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, transaction_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, readback_digest, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(st) != SQLITE_DONE ||
                sqlite3_changes(g_ac_db) != 1)
                goto fail;
            sqlite3_finalize(st);
            st = NULL;
        } else if (is_rollback && !strcmp(terminal, "rolled_back")) {
            if (sqlite3_prepare_v2(g_ac_db,
                    "UPDATE ac_aps SET desired_revision=(SELECT "
                    "previous_revision FROM ac_transaction_targets WHERE "
                    "transaction_id=?2 AND ap_id=?1),"
                    "applied_revision=(SELECT "
                    "previous_revision FROM ac_transaction_targets WHERE "
                    "transaction_id=?2 AND ap_id=?1),readback_digest=(SELECT "
                    "previous_digest FROM ac_transaction_targets WHERE "
                    "transaction_id=?2 AND ap_id=?1) WHERE ap_id=?1",
                    -1, &st, NULL) != SQLITE_OK)
                goto fail;
            sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, transaction_id, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(st) != SQLITE_DONE ||
                sqlite3_changes(g_ac_db) != 1)
                goto fail;
            sqlite3_finalize(st);
            st = NULL;
        }
        if (ac_wifi_tx_refresh_locked(transaction_id, now) != 0)
            goto fail;
    }
    if (ac_config_job_load(job_id, out) != AC_CONFIG_JOB_OK)
        goto fail;
    if (ac_exec("COMMIT") != 0)
        goto fail;
    free(canonical_readback);
    if (!strcmp(terminal, "failed"))
        ac_wifi_job_failure_observe(transaction_id, ap_id, session_epoch,
                                     finish_id, stored_error, now);
    return AC_CONFIG_JOB_OK;
fail:
    free(canonical_readback);
    sqlite3_finalize(st);
    ac_exec("ROLLBACK");
    return AC_CONFIG_JOB_ERROR;
}

int ac_db_config_jobs_recover(int64_t now)
{
    sqlite3_stmt *st = NULL;

    if (!g_ac_db || now <= 0)
        return AC_CONFIG_JOB_INVALID;
    if (ac_exec("BEGIN IMMEDIATE") != 0)
        return AC_CONFIG_JOB_ERROR;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_transaction_targets SET state=CASE WHEN EXISTS ("
            "SELECT 1 FROM ac_config_jobs j WHERE j.transaction_id="
            "ac_transaction_targets.transaction_id AND j.ap_id="
            "ac_transaction_targets.ap_id AND j.state='leased' AND "
            "j.lease_expires_at<?1 AND j.operation='rollback') THEN "
            "'rollback_queued' ELSE 'queued' END,updated_at=?1 "
            "WHERE EXISTS (SELECT 1 FROM ac_config_jobs j WHERE "
            "j.transaction_id=ac_transaction_targets.transaction_id AND "
            "j.ap_id=ac_transaction_targets.ap_id AND j.state='leased' AND "
            "j.lease_expires_at<?1)",
            -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_int64(st, 1, now);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_config_jobs SET state='queued',session_epoch='',"
            "attempt_id='',request_digest='',lease_expires_at=0,updated_at=?1 "
            "WHERE state='leased' AND lease_expires_at<?1",
            -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_int64(st, 1, now);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(st);
    if (ac_exec("COMMIT") != 0)
        goto fail_no_transaction;
    return AC_CONFIG_JOB_OK;
fail:
    sqlite3_finalize(st);
    ac_exec("ROLLBACK");
fail_no_transaction:
    return AC_CONFIG_JOB_ERROR;
}

/* ---- Managed Wi-Fi transaction orchestration. ---- */

static int ac_wifi_tx_consistency_valid(const char *value)
{
    return value && (!strcmp(value, "all_or_nothing") ||
                     !strcmp(value, "per_target"));
}

static void ac_wifi_tx_error(char *out, size_t out_len, const char *error)
{
    if (out && out_len)
        snprintf(out, out_len, "%s", error ? error : "database_error");
}

static int ac_wifi_tx_target_gate_locked(
    const char *ap_id, int64_t now,
    char previous_digest[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1],
    int64_t *previous_revision)
{
    sqlite3_stmt *st = NULL;
    int result = AC_CONFIG_JOB_INVALID;

    if (previous_digest)
        previous_digest[0] = '\0';
    if (previous_revision)
        *previous_revision = 0;
    if (!ac_uuid_valid(ap_id) || now <= 0 ||
        sqlite3_prepare_v2(g_ac_db,
            "SELECT a.readback_digest,a.applied_revision,a.last_seen_at,"
            "COALESCE(r.session_connected,0),"
            "COALESCE(r.control_protocol_version,0),"
            "COALESCE(r.write_capable,0) FROM ac_aps a "
            "LEFT JOIN ac_ap_runtime r ON r.ap_id=a.ap_id "
            "WHERE a.ap_id=?1 AND a.adoption_state='adopted' LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
        return AC_CONFIG_JOB_ERROR;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *digest = sqlite3_column_text(st, 0);

        if (previous_digest)
            snprintf(previous_digest,
                     AC_RADIO_JOB_RESULT_DIGEST_MAX + 1, "%s",
                     digest ? (const char *)digest : "");
        if (previous_revision)
            *previous_revision = sqlite3_column_int64(st, 1);
        result = sqlite3_column_int64(st, 2) >=
                     now - AC_AP_ONLINE_TIMEOUT_SECONDS &&
                 sqlite3_column_int(st, 3) != 0 &&
                 sqlite3_column_int(st, 4) == 3 &&
                 sqlite3_column_int(st, 5) != 0 ?
                 AC_CONFIG_JOB_OK : AC_CONFIG_JOB_UNAVAILABLE;
    }
    sqlite3_finalize(st);
    return result;
}

#if !defined(AC_DB_TEST_STANDALONE) || defined(AC_DB_ROAMING_ACTIONS_TEST) || \
    defined(AC_DB_WIFI_TRANSACTION_TEST)
static int AC_DB_STANDALONE_UNUSED
ac_wifi_tx_refresh_locked(const char *transaction_id, int64_t now)
{
    sqlite3_stmt *st = NULL;
    char consistency[32] = { 0 };
    int total = 0;
    int applied = 0;
    int failed = 0;
    int rolled_back = 0;
    int rollback_failed = 0;
    int cancelled = 0;
    int rollback_pending = 0;
    int pending = 0;
    const char *state;

    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT consistency FROM ac_transactions WHERE transaction_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, transaction_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        return -1;
    }
    ac_config_job_copy(consistency, sizeof(consistency),
                       sqlite3_column_text(st, 0));
    sqlite3_finalize(st);
    st = NULL;

    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT COUNT(*),"
            "COALESCE(SUM(state='applied'),0),"
            "COALESCE(SUM(state='failed'),0),"
            "COALESCE(SUM(state='rolled_back'),0),"
            "COALESCE(SUM(state='rollback_failed'),0),"
            "COALESCE(SUM(state='cancelled'),0),"
            "COALESCE(SUM(state IN ('rollback_queued','rollback_leased',"
            "'rollback_running')),0),"
            "COALESCE(SUM(state IN ('queued','leased','running')),0) "
            "FROM ac_transaction_targets WHERE transaction_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, transaction_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        return -1;
    }
    total = sqlite3_column_int(st, 0);
    applied = sqlite3_column_int(st, 1);
    failed = sqlite3_column_int(st, 2);
    rolled_back = sqlite3_column_int(st, 3);
    rollback_failed = sqlite3_column_int(st, 4);
    cancelled = sqlite3_column_int(st, 5);
    rollback_pending = sqlite3_column_int(st, 6);
    pending = sqlite3_column_int(st, 7);
    sqlite3_finalize(st);
    st = NULL;
    if (total <= 0)
        return -1;

    if (!strcmp(consistency, "all_or_nothing") &&
        (failed > 0 || rolled_back > 0 || rollback_failed > 0 ||
         rollback_pending > 0 || cancelled > 0)) {
        /* Stop work that has not started. A target already leased/running may
         * still finish; refresh will queue its compensation when it does. */
        if (sqlite3_prepare_v2(g_ac_db,
                "UPDATE ac_config_jobs SET state='cancelled',"
                "error_code='transaction_peer_failed',updated_at=?2 "
                "WHERE transaction_id=?1 AND operation='apply' "
                "AND state='queued'", -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_text(st, 1, transaction_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, now);
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            return -1;
        }
        sqlite3_finalize(st);
        st = NULL;
        if (sqlite3_prepare_v2(g_ac_db,
                "UPDATE ac_transaction_targets SET state='cancelled',"
                "error_code='transaction_peer_failed',updated_at=?2 "
                "WHERE transaction_id=?1 AND state='queued'", -1, &st,
                NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_text(st, 1, transaction_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, now);
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            return -1;
        }
        sqlite3_finalize(st);
        st = NULL;
        /* Queue one compensation job per applied target. The APD resolves the
         * rollback reference from the original job journal. */
        if (sqlite3_prepare_v2(g_ac_db,
                "INSERT INTO ac_config_jobs(job_id,ap_id,state,"
                "idempotency_key,candidate_json,candidate_digest,"
                "transaction_id,created_at,updated_at,operation,"
                "rollback_of_job_id) "
                "SELECT lower(hex(randomblob(4)))||'-'||"
                "lower(hex(randomblob(2)))||'-4'||substr(lower(hex(randomblob(2))),2)||'-'||"
                "substr('89ab',abs(random())%4+1,1)||substr(lower(hex(randomblob(2))),2)||'-'||"
                "lower(hex(randomblob(6))),t.ap_id,'queued',"
                "'wifitx-rollback:'||t.transaction_id||':'||t.ap_id,"
                "j.candidate_json,j.candidate_digest,t.transaction_id,?2,?2,"
                "'rollback',j.job_id FROM ac_transaction_targets t "
                "JOIN ac_config_jobs j ON j.job_id=t.apply_job_id "
                "WHERE t.transaction_id=?1 AND t.state='applied' "
                "AND t.rollback_job_id=''", -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_text(st, 1, transaction_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, now);
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            return -1;
        }
        sqlite3_finalize(st);
        st = NULL;
        if (sqlite3_prepare_v2(g_ac_db,
                "UPDATE ac_transaction_targets SET state='rollback_queued',"
                "rollback_job_id=(SELECT job_id FROM ac_config_jobs j WHERE "
                "j.transaction_id=ac_transaction_targets.transaction_id "
                "AND j.ap_id=ac_transaction_targets.ap_id "
                "AND j.operation='rollback' LIMIT 1),updated_at=?2 "
                "WHERE transaction_id=?1 AND state='applied' "
                "AND rollback_job_id=''", -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_text(st, 1, transaction_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, now);
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            return -1;
        }
        sqlite3_finalize(st);
        st = NULL;
        /* Refresh the counts after cancellation/compensation queueing. */
        if (sqlite3_prepare_v2(g_ac_db,
                "SELECT COALESCE(SUM(state IN ('leased','running')),0),"
                "COALESCE(SUM(state IN ('rollback_queued','rollback_leased',"
                "'rollback_running')),0),"
                "COALESCE(SUM(state='rolled_back'),0),"
                "COALESCE(SUM(state='rollback_failed'),0),"
                "COALESCE(SUM(state='cancelled'),0),"
                "COALESCE(SUM(state='failed'),0) FROM ac_transaction_targets "
                "WHERE transaction_id=?1", -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_text(st, 1, transaction_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_ROW) {
            sqlite3_finalize(st);
            return -1;
        }
        pending = sqlite3_column_int(st, 0);
        rollback_pending = sqlite3_column_int(st, 1);
        rolled_back = sqlite3_column_int(st, 2);
        rollback_failed = sqlite3_column_int(st, 3);
        cancelled = sqlite3_column_int(st, 4);
        failed = sqlite3_column_int(st, 5);
        sqlite3_finalize(st);
        st = NULL;
        if (rollback_failed > 0)
            state = "rollback_failed";
        else if (pending > 0 || rollback_pending > 0)
            state = "rolling_back";
        else if (rolled_back > 0 && rolled_back + failed + cancelled == total)
            state = "rolled_back";
        else
            state = "failed";
    } else if (pending > 0)
        state = "pending";
    else if (applied == total)
        state = "applied";
    else if (applied > 0)
        state = "partially_applied";
    else if (failed > 0)
        state = "failed";
    else if (rolled_back == total)
        state = "rolled_back";
    else
        state = "failed";
    if (!strcmp(state, "rolled_back") || !strcmp(state, "failed")) {
        if (sqlite3_prepare_v2(g_ac_db,
                "UPDATE ac_aps SET desired_revision=(SELECT "
                "previous_revision FROM ac_transaction_targets t WHERE "
                "t.transaction_id=?1 AND t.ap_id=ac_aps.ap_id) "
                "WHERE ap_id IN (SELECT ap_id FROM ac_transaction_targets "
                "WHERE transaction_id=?1)", -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_text(st, 1, transaction_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            return -1;
        }
        sqlite3_finalize(st);
        st = NULL;
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_transactions SET state=?2,updated_at=?3 "
            "WHERE transaction_id=?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, transaction_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, state, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 3, now);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    return 0;
}
#endif

int ac_db_wifi_transaction_apply(const char *actor_id,
                                 const char *idempotency_key,
                                 const char *consistency,
                                 int64_t base_revision,
                                 const char *targets_json, int64_t now,
                                 char transaction_id_out[AC_RADIO_JOB_ID_LEN + 1],
                                 char *error_out, size_t error_len)
{
    struct json_object *targets = NULL;
    sqlite3_stmt *st = NULL;
    char transaction_id[AC_RADIO_JOB_ID_LEN + 1] = { 0 };
    int64_t current_revision;
    int64_t desired_revision;
    size_t i;

    if (error_out && error_len)
        error_out[0] = '\0';
    if (!g_ac_db || !ac_uuid_valid(actor_id) ||
        !ac_config_job_idempotency_valid(idempotency_key) ||
        !ac_wifi_tx_consistency_valid(consistency) ||
        base_revision < AC_WIFI_TX_BASE_REVISION_CURRENT ||
        !targets_json ||
        strlen(targets_json) > AC_WIFI_TX_CANDIDATE_MAX_BYTES *
                               AC_WIFI_TX_TARGETS_MAX) {
        if (error_out && error_len)
            snprintf(error_out, error_len, "%s", "invalid_request");
        return AC_CONFIG_JOB_INVALID;
    }
    targets = json_tokener_parse(targets_json);
    if (!targets || !json_object_is_type(targets, json_type_array) ||
        json_object_array_length(targets) == 0 ||
        json_object_array_length(targets) > AC_WIFI_TX_TARGETS_MAX) {
        json_object_put(targets);
        if (error_out && error_len)
            snprintf(error_out, error_len, "%s", "targets_invalid");
        return AC_CONFIG_JOB_INVALID;
    }
    if (ac_exec("BEGIN IMMEDIATE") != 0) {
        json_object_put(targets);
        return AC_CONFIG_JOB_ERROR;
    }
    /* Idempotent replay by (actor_id, idempotency_key). */
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT transaction_id FROM ac_transactions "
            "WHERE actor_id=?1 AND idempotency_key=?2",
            -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, actor_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, idempotency_key, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        ac_config_job_copy(transaction_id, sizeof(transaction_id),
                           sqlite3_column_text(st, 0));
        sqlite3_finalize(st);
        st = NULL;
        ac_exec("ROLLBACK");
        json_object_put(targets);
        if (transaction_id_out)
            snprintf(transaction_id_out, AC_RADIO_JOB_ID_LEN + 1, "%s",
                     transaction_id);
        return AC_CONFIG_JOB_IDEMPOTENT;
    }
    sqlite3_finalize(st);
    st = NULL;
    current_revision = ac_db_wifi_desired_revision();
    /* Read inside BEGIN IMMEDIATE, so a caller opting out of the concurrency
     * claim cannot lose to a writer that landed between its own read and
     * this one. */
    if (base_revision == AC_WIFI_TX_BASE_REVISION_CURRENT)
        base_revision = current_revision;
    if (base_revision != current_revision) {
        ac_exec("ROLLBACK");
        json_object_put(targets);
        ac_wifi_tx_error(error_out, error_len, "revision_conflict");
        return AC_CONFIG_JOB_CONFLICT;
    }
    desired_revision = current_revision + 1;
    if (desired_revision <= current_revision) {
        ac_exec("ROLLBACK");
        json_object_put(targets);
        ac_wifi_tx_error(error_out, error_len, "revision_exhausted");
        return AC_CONFIG_JOB_CONFLICT;
    }
    if (ac_generate_uuid(transaction_id) != 0)
        goto fail;
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_transactions(transaction_id,actor_id,"
            "idempotency_key,base_revision,desired_revision,state,"
            "consistency,created_at,updated_at) "
            "VALUES(?1,?2,?3,?4,?5,'pending',?6,?7,?7)",
            -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, transaction_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, actor_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, idempotency_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, base_revision);
    sqlite3_bind_int64(st, 5, desired_revision);
    sqlite3_bind_text(st, 6, consistency, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 7, now);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(st);
    st = NULL;
    for (i = 0; i < json_object_array_length(targets); i++) {
        struct json_object *target = json_object_array_get_idx(targets, i);
        struct json_object *field = NULL;
        const char *ap_id = NULL;
        const char *candidate = NULL;
        const char *candidate_digest = NULL;
        char job_id[AC_RADIO_JOB_ID_LEN + 1] = { 0 };
        char job_key[AC_RADIO_JOB_IDEMPOTENCY_MAX + 1];
        char previous_digest[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1] = { 0 };
        int64_t previous_revision = 0;
        char candidate_error[AC_RADIO_JOB_ERROR_MAX + 1] = { 0 };
        char *canonical_candidate = NULL;
        int target_gate;

        if (!target || !json_object_is_type(target, json_type_object) ||
            !json_object_object_get_ex(target, "ap_id", &field) ||
            !field || !(ap_id = json_object_get_string(field)) ||
            !ac_uuid_valid(ap_id) ||
            !json_object_object_get_ex(target, "candidate", &field) ||
            !field || !(candidate = json_object_get_string(field)) ||
            !json_object_object_get_ex(target, "candidate_digest",
                                       &field) || !field ||
            !(candidate_digest = json_object_get_string(field))) {
            ac_wifi_tx_error(error_out, error_len, "target_invalid");
            goto rollback_invalid;
        }
        target_gate = ac_wifi_tx_target_gate_locked(ap_id, now,
                                                    previous_digest,
                                                    &previous_revision);
        if (target_gate == AC_CONFIG_JOB_ERROR)
            goto fail;
        if (target_gate != AC_CONFIG_JOB_OK) {
            ac_wifi_tx_error(error_out, error_len,
                target_gate == AC_CONFIG_JOB_UNAVAILABLE ?
                "target_write_capability_unavailable" : "target_invalid");
            sqlite3_finalize(st);
            st = NULL;
            ac_exec("ROLLBACK");
            json_object_put(targets);
            return target_gate;
        }
        if (ac_config_candidate_validate(candidate, candidate_digest,
                                         &canonical_candidate,
                                         candidate_error,
                                         sizeof(candidate_error)) != 0) {
            ac_wifi_tx_error(error_out, error_len,
                             candidate_error[0] ? candidate_error :
                             "candidate_invalid");
            goto rollback_invalid;
        }
        /* One queued config job per target, keyed to the transaction so a
         * replay of this apply is idempotent at the job layer too. */
        if (ac_generate_uuid(job_id) != 0) {
            free(canonical_candidate);
            goto fail;
        }
        snprintf(job_key, sizeof(job_key), "wifitx:%s:%s", transaction_id,
                 ap_id);
        if (sqlite3_prepare_v2(g_ac_db,
                "INSERT INTO ac_config_jobs(job_id,ap_id,state,"
                "idempotency_key,candidate_json,candidate_digest,"
                "transaction_id,created_at,updated_at) "
                "VALUES(?1,?2,'queued',?3,?4,?5,?6,?7,?7)",
                -1, &st, NULL) != SQLITE_OK) {
            free(canonical_candidate);
            goto fail;
        }
        sqlite3_bind_text(st, 1, job_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, ap_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, job_key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, canonical_candidate, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, candidate_digest, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, transaction_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 7, now);
        if (sqlite3_step(st) != SQLITE_DONE) {
            /* Duplicate AP in one apply collides on the unique
             * (ap_id, idempotency_key); reject the whole fan-out. */
            sqlite3_finalize(st);
            st = NULL;
            free(canonical_candidate);
            ac_wifi_tx_error(error_out, error_len, "target_duplicate");
            goto rollback_invalid;
        }
        free(canonical_candidate);
        sqlite3_finalize(st);
        st = NULL;
        if (sqlite3_prepare_v2(g_ac_db,
                "INSERT INTO ac_transaction_targets(transaction_id,ap_id,"
                "state,candidate_digest,previous_digest,previous_revision,"
                "apply_job_id,updated_at) "
                "VALUES(?1,?2,'queued',?3,?4,?5,?6,?7)",
                -1, &st, NULL) != SQLITE_OK)
            goto fail;
        sqlite3_bind_text(st, 1, transaction_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, ap_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, candidate_digest, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, previous_digest, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 5, previous_revision);
        sqlite3_bind_text(st, 6, job_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 7, now);
        if (sqlite3_step(st) != SQLITE_DONE)
            goto fail;
        sqlite3_finalize(st);
        st = NULL;
        if (sqlite3_prepare_v2(g_ac_db,
                "UPDATE ac_aps SET desired_revision=?2 WHERE ap_id=?1",
                -1, &st, NULL) != SQLITE_OK)
            goto fail;
        sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, desired_revision);
        if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
            goto fail;
        sqlite3_finalize(st);
        st = NULL;
    }
    json_object_put(targets);
    if (ac_exec("COMMIT") != 0) {
        ac_exec("ROLLBACK");
        return AC_CONFIG_JOB_ERROR;
    }
    if (transaction_id_out)
        snprintf(transaction_id_out, AC_RADIO_JOB_ID_LEN + 1, "%s",
                 transaction_id);
    return AC_CONFIG_JOB_OK;
rollback_invalid:
    sqlite3_finalize(st);
    ac_exec("ROLLBACK");
    json_object_put(targets);
    return AC_CONFIG_JOB_INVALID;
fail:
    sqlite3_finalize(st);
    ac_exec("ROLLBACK");
    json_object_put(targets);
    return AC_CONFIG_JOB_ERROR;
}

struct json_object *ac_db_wifi_transaction_status_json(
    const char *transaction_id)
{
    struct json_object *root = json_object_new_object();
    struct json_object *targets_array = json_object_new_array();
    sqlite3_stmt *st = NULL;
    int found = 0;
    int step_rc;

    if (!g_ac_db || !ac_uuid_valid(transaction_id)) {
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "error",
                               json_object_new_string("invalid_transaction"));
        json_object_put(targets_array);
        return root;
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT state,consistency,base_revision,desired_revision,"
            "created_at,updated_at FROM ac_transactions "
            "WHERE transaction_id=?1", -1, &st, NULL) != SQLITE_OK) {
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "error",
                               json_object_new_string("database_error"));
        json_object_put(targets_array);
        return root;
    }
    sqlite3_bind_text(st, 1, transaction_id, -1, SQLITE_TRANSIENT);
    step_rc = sqlite3_step(st);
    if (step_rc == SQLITE_ROW) {
        found = 1;
        json_object_object_add(root, "state", json_object_new_string(
            (const char *)sqlite3_column_text(st, 0)));
        json_object_object_add(root, "consistency",
            json_object_new_string(
                (const char *)sqlite3_column_text(st, 1)));
        json_object_object_add(root, "base_revision",
            json_object_new_int64(sqlite3_column_int64(st, 2)));
        json_object_object_add(root, "desired_revision",
            json_object_new_int64(sqlite3_column_int64(st, 3)));
        json_object_object_add(root, "created_at",
            json_object_new_int64(sqlite3_column_int64(st, 4)));
        json_object_object_add(root, "updated_at",
            json_object_new_int64(sqlite3_column_int64(st, 5)));
    } else if (step_rc != SQLITE_DONE) {
        sqlite3_finalize(st);
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "error",
                               json_object_new_string("database_error"));
        json_object_put(targets_array);
        return root;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (!found) {
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "error",
                               json_object_new_string("transaction_not_found"));
        json_object_put(targets_array);
        return root;
    }
    /* Return the full journal evidence needed to reconcile AC and APD. */
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT t.ap_id,t.state,t.candidate_digest,t.previous_digest,"
            "t.readback_digest,t.error_code,a.state,a.outcome,a.error_code,"
            "a.readback_json,r.state,r.outcome,r.error_code,r.readback_json "
            "FROM ac_transaction_targets t LEFT JOIN ac_config_jobs a "
            "ON a.job_id=t.apply_job_id LEFT JOIN ac_config_jobs r "
            "ON r.job_id=t.rollback_job_id "
            "WHERE t.transaction_id=?1 ORDER BY t.ap_id",
            -1, &st, NULL) != SQLITE_OK) {
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "error",
                               json_object_new_string("database_error"));
        json_object_put(targets_array);
        return root;
    }
    {
        int target_rc;

        sqlite3_bind_text(st, 1, transaction_id, -1, SQLITE_TRANSIENT);
        while ((target_rc = sqlite3_step(st)) == SQLITE_ROW) {
            struct json_object *entry = json_object_new_object();
            const unsigned char *job_state = sqlite3_column_text(st, 6);
            const unsigned char *job_outcome = sqlite3_column_text(st, 7);
            const unsigned char *readback_text = sqlite3_column_text(st, 9);
            const unsigned char *rollback_state = sqlite3_column_text(st, 10);
            const unsigned char *rollback_outcome = sqlite3_column_text(st, 11);
            const unsigned char *rollback_readback_text =
                sqlite3_column_text(st, 13);
            struct json_object *readback = NULL;
            struct json_object *rollback_readback = NULL;

            json_object_object_add(entry, "ap_id", json_object_new_string(
                (const char *)sqlite3_column_text(st, 0)));
            json_object_object_add(entry, "state", json_object_new_string(
                (const char *)sqlite3_column_text(st, 1)));
            json_object_object_add(entry, "candidate_digest",
                json_object_new_string(
                    (const char *)sqlite3_column_text(st, 2)));
            json_object_object_add(entry, "previous_digest",
                json_object_new_string(
                    (const char *)sqlite3_column_text(st, 3)));
            json_object_object_add(entry, "readback_digest",
                json_object_new_string(
                    (const char *)sqlite3_column_text(st, 4)));
            json_object_object_add(entry, "error_code",
                json_object_new_string(
                    (const char *)sqlite3_column_text(st, 5)));
            json_object_object_add(entry, "job_state",
                job_state && job_state[0] ?
                json_object_new_string((const char *)job_state) : NULL);
            json_object_object_add(entry, "job_outcome",
                job_outcome && job_outcome[0] ?
                json_object_new_string((const char *)job_outcome) : NULL);
            json_object_object_add(entry, "job_error_code",
                sqlite3_column_text(st, 8) && sqlite3_column_bytes(st, 8) > 0 ?
                json_object_new_string(
                    (const char *)sqlite3_column_text(st, 8)) : NULL);
            if (readback_text && readback_text[0])
                readback = json_tokener_parse((const char *)readback_text);
            json_object_object_add(entry, "readback", readback);
            json_object_object_add(entry, "rollback_job_state",
                rollback_state && rollback_state[0] ?
                json_object_new_string((const char *)rollback_state) : NULL);
            json_object_object_add(entry, "rollback_job_outcome",
                rollback_outcome && rollback_outcome[0] ?
                json_object_new_string((const char *)rollback_outcome) : NULL);
            json_object_object_add(entry, "rollback_job_error_code",
                sqlite3_column_text(st, 12) &&
                sqlite3_column_bytes(st, 12) > 0 ?
                json_object_new_string(
                    (const char *)sqlite3_column_text(st, 12)) : NULL);
            if (rollback_readback_text && rollback_readback_text[0])
                rollback_readback = json_tokener_parse(
                    (const char *)rollback_readback_text);
            json_object_object_add(entry, "rollback_readback",
                                   rollback_readback);
            json_object_array_add(targets_array, entry);
        }
        if (target_rc != SQLITE_DONE) {
            sqlite3_finalize(st);
            json_object_object_add(root, "ok", json_object_new_boolean(0));
            json_object_object_add(root, "error",
                                   json_object_new_string("database_error"));
            json_object_put(targets_array);
            return root;
        }
    }
    sqlite3_finalize(st);
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "transaction_id",
                           json_object_new_string(transaction_id));
    json_object_object_add(root, "targets", targets_array);
    return root;
}

/* ---- P2: managed SSID CRUD ---------------------------------------------------
 *
 * Closes capabilities ssid_create / ssid_update / ssid_delete, which reported
 * `transaction_scope_not_supported`.  That string undersold the gap: it was not
 * a scope restriction but a missing producer.  Nothing in this daemon had ever
 * written ac_ssids or ac_ssid_bindings -- the tables were created at schema
 * time, telemetry ingest filled ac_ssid_runtime right next to them, and the
 * desired-state half stayed empty forever.  APD has carried the executor half
 * for a while: apd_config_section_create_live / _drop_live address a wifi-iface
 * by UCI section name, and apd_config_capture_previous records `existed` so a
 * create is reversible.
 *
 * Shape of a write: one transaction per operation, one candidate per AP, one
 * section per binding.  An AP has a single /etc/config/wireless, so an SSID on
 * both bands of one AP is two sections inside that AP's candidate rather than
 * two transactions -- split them and the 5 GHz half could commit while the
 * 2.4 GHz half rolls back, and there is no repair path for half an SSID.
 */

#define AC_SSID_NAME_MAX 32U      /* an 802.11 SSID is 32 octets */
#define AC_SSID_SECTION_HEX 20U   /* 80 bits of the ssid_id, so names cannot collide */
#define AC_SSID_BINDINGS_MAX 64U

/* Derive the UCI section name for one (SSID, radio) pair.
 *
 * A wifi-iface section *is* the binding of one SSID to one radio, so a
 * dual-band SSID is two sections and the name has to carry the radio: one name
 * for both would make the second section overwrite the first.
 *
 * `ssid_id` is a UUID -- 36 characters with dashes -- against a candidate name
 * of [a-z0-9_] and at most 32 (ac_config_candidate_name_valid), so the dashes
 * come out and 20 hex digits are kept.  Nothing is truncated silently: a device
 * name long enough to overflow the budget refuses, because two SSIDs whose
 * names collided would each be editing the other's VAP.
 */
static int ac_ssid_section_name(const char *ssid_id, const char *device,
                                char out[AC_CONFIG_CANDIDATE_NAME_MAX + 1])
{
    size_t used = 0;
    size_t hex = 0;
    size_t i;

    if (!ssid_id || !device || !device[0] || !out)
        return -1;
    out[used++] = 'd';
    out[used++] = 'w';
    out[used++] = '_';
    for (i = 0; ssid_id[i] && hex < AC_SSID_SECTION_HEX; i++) {
        char c = ssid_id[i];

        if (c == '-')
            continue;
        if (c >= 'A' && c <= 'F')
            c = (char)(c - 'A' + 'a');
        out[used++] = c;
        hex++;
    }
    if (hex != AC_SSID_SECTION_HEX ||
        used + 1 + strlen(device) > AC_CONFIG_CANDIDATE_NAME_MAX)
        return -1;
    out[used++] = '_';
    snprintf(out + used, AC_CONFIG_CANDIDATE_NAME_MAX + 1 - used, "%s", device);
    return ac_config_candidate_name_valid(out) ? 0 : -1;
}

/* The AP's UCI wifi-device section name for a radio.
 *
 * A wifi-iface has to name the radio it rides on, and `device` is a UCI section
 * name -- `radio0` on most targets, `wifi0` on the QCA boards here.  Runtime's
 * radio_id is the phy (`phy0`), which is not it, and no rule maps one to the
 * other: the mapping is whatever that AP's /etc/config/wireless happens to say.
 *
 * APD publishes it.  The snapshot's `desired` block is read straight out of UCI,
 * so each desired radio's `id` is the section name and its `phy` is what runtime
 * calls radio_id, and the whole snapshot is already stored verbatim in
 * ac_ap_runtime.runtime_json.
 *
 * Fails closed.  Guessing `radio0` would attach the VAP to the wrong band or to
 * a section that does not exist -- and `uci set` creates what it cannot find, so
 * the AP would end up with a wifi-iface pointing at a phantom radio.
 */
static int ac_ssid_uci_device(const char *ap_id, const char *radio_id,
                              int64_t now,
                              char out[AC_CONFIG_CANDIDATE_NAME_MAX + 1])
{
    sqlite3_stmt *st = NULL;
    struct json_object *snapshot = NULL;
    struct json_object *desired = NULL;
    struct json_object *radios = NULL;
    const unsigned char *text;
    int64_t observed_at;
    size_t i;
    int rc = -1;

    if (out)
        out[0] = '\0';
    if (!g_ac_db || !ap_id || !radio_id || !radio_id[0] || !out)
        return -1;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT observed_at,runtime_json,stale FROM ac_ap_runtime "
            "WHERE ap_id=?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        observed_at = sqlite3_column_int64(st, 0);
        text = sqlite3_column_text(st, 1);
        if (sqlite3_column_int(st, 2) == 0 && text &&
            observed_at >= now - AC_TELEMETRY_STALE_TIMEOUT_SECONDS)
            snapshot = json_tokener_parse((const char *)text);
    }
    sqlite3_finalize(st);
    if (!snapshot)
        return -1;
    if (!json_object_object_get_ex(snapshot, "desired", &desired) ||
        !json_object_object_get_ex(desired, "radios", &radios) ||
        !json_object_is_type(radios, json_type_array)) {
        json_object_put(snapshot);
        return -1;
    }
    for (i = 0; i < json_object_array_length(radios); i++) {
        struct json_object *radio = json_object_array_get_idx(radios, i);
        const char *phy = ac_db_json_string(radio, "phy");
        const char *id = ac_db_json_string(radio, "id");

        /* Match the phy first, then the section name itself: a caller that
         * already knows the UCI name may pass it, and accepting both is not a
         * guess -- either way the name came from this AP's own report. */
        if (!id || !ac_config_candidate_name_valid(id))
            continue;
        if ((phy && !strcmp(phy, radio_id)) || !strcmp(id, radio_id)) {
            snprintf(out, AC_CONFIG_CANDIDATE_NAME_MAX + 1, "%s", id);
            rc = 0;
            break;
        }
    }
    /* Multi-radio phys report the UCI reference among their interfaces. */
    if (rc != 0) {
        struct json_object *runtime_radios = NULL;

        json_object_object_get_ex(snapshot, "radios", &runtime_radios);
        for (i = 0; runtime_radios &&
             i < json_object_array_length(runtime_radios); i++) {
            struct json_object *radio = json_object_array_get_idx(runtime_radios, i);
            struct json_object *interfaces = NULL;
            const char *id = ac_db_json_string(radio, "id");
            size_t j, k;

            if (!id || strcmp(id, radio_id))
                continue;
            json_object_object_get_ex(radio, "interfaces", &interfaces);
            for (j = 0; interfaces && j < json_object_array_length(interfaces); j++) {
                const char *interface = ac_db_json_string(
                    json_object_array_get_idx(interfaces, j), "interface");

                for (k = 0; interface && k < json_object_array_length(radios); k++) {
                    const char *device = ac_db_json_string(
                        json_object_array_get_idx(radios, k), "id");

                    if (!device || strcmp(device, interface) ||
                        !ac_config_candidate_name_valid(device))
                        continue;
                    if (rc == 0 && strcmp(out, device)) {
                        json_object_put(snapshot);
                        out[0] = '\0';
                        return -1;
                    }
                    snprintf(out, AC_CONFIG_CANDIDATE_NAME_MAX + 1, "%s", device);
                    rc = 0;
                }
            }
        }
    }
    json_object_put(snapshot);
    return rc;
}

/* Resolve an existing, non-MLO BSS without reading or changing its key. */
static const char *ac_ssid_existing_binding(
    const char *ap_id, const char *radio_id, const char *section_name,
    const char *bssid, const char *name, int64_t now,
    struct json_object **desired_out, struct json_object **runtime_out)
{
    struct json_object *snapshot = NULL, *desired = NULL, *ssids = NULL;
    struct json_object *selected = NULL, *runtime = NULL;
    sqlite3_stmt *st = NULL;
    char device[AC_CONFIG_CANDIDATE_NAME_MAX + 1];
    const char *reason = "roaming_binding_section_unavailable";
    size_t i;

    if (desired_out) *desired_out = NULL;
    if (runtime_out) *runtime_out = NULL;
    if (!section_name || !ac_config_candidate_name_valid(section_name) ||
        !bssid || !ac_radio_job_mac_valid(bssid))
        return reason;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT runtime_json,observed_at,stale FROM ac_ap_runtime "
            "WHERE ap_id=?1", -1, &st, NULL) != SQLITE_OK)
        return "database_error";
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW &&
        !sqlite3_column_int(st, 2) &&
        sqlite3_column_int64(st, 1) >= now - AC_TELEMETRY_STALE_TIMEOUT_SECONDS)
        snapshot = json_tokener_parse((const char *)sqlite3_column_text(st, 0));
    sqlite3_finalize(st);
    if (!snapshot)
        return "roaming_binding_section_stale";
    if (ac_ssid_uci_device(ap_id, radio_id, now, device) != 0)
        goto done;
    json_object_object_get_ex(snapshot, "desired", &desired);
    json_object_object_get_ex(desired, "ssids", &ssids);
    for (i = 0; ssids && i < json_object_array_length(ssids); i++) {
        struct json_object *item = json_object_array_get_idx(ssids, i);
        const char *id = ac_db_json_string(item, "id");
        const char *radio = ac_db_json_string(item, "radio_id");
        const char *broadcast = ac_db_json_string(item, "broadcast_name");
        const char *mode = ac_db_json_string(item, "mode");

        if (!id || strcmp(id, section_name))
            continue;
        if (!radio || strcmp(radio, device) || !broadcast ||
            (name && strcmp(name, broadcast)) ||
            (mode && strcmp(mode, "ap")) || ac_db_json_bool(item, "mlo") ||
            ac_db_json_bool(item, "stale"))
            goto done;
        selected = item;
    }
    if (!selected)
        goto done;
    ssids = NULL;
    json_object_object_get_ex(snapshot, "ssids", &ssids);
    for (i = 0; ssids && i < json_object_array_length(ssids); i++) {
        struct json_object *item = json_object_array_get_idx(ssids, i);
        const char *mac = ac_db_json_string(item, "bssid");
        const char *radio = ac_db_json_string(item, "radio_id");
        const char *broadcast = ac_db_json_string(item, "broadcast_name");

        if (!mac || strcasecmp(mac, bssid))
            continue;
        if (!radio || strcmp(radio, radio_id) || !broadcast ||
            strcmp(broadcast, ac_db_json_string(selected, "broadcast_name")) ||
            ac_db_json_bool(item, "mlo") || runtime)
            goto done;
        runtime = item;
    }
    if (!runtime)
        goto done;
    if (desired_out) *desired_out = json_object_get(selected);
    if (runtime_out) *runtime_out = json_object_get(runtime);
    reason = NULL;
done:
    json_object_put(snapshot);
    return reason;
}

/* Controller-only adoption: no config job, password write or radio reload. */
struct json_object *ac_db_ssid_adopt_json(
    const char *ssid_id, const char *site_id, const char *name,
    const char *group_id, struct json_object *bindings, int64_t now)
{
    struct json_object *result = json_object_new_object();
    struct json_object *resolved = json_object_new_array();
    sqlite3_stmt *st = NULL;
    const char *reason = "database_error";
    size_t i, j, count;
    int transaction = 0;

    if (!g_ac_db || !ac_uuid_valid(ssid_id) ||
        !site_id || !ac_config_candidate_value_valid(site_id) ||
        !name || strlen(name) > AC_SSID_NAME_MAX ||
        !ac_config_candidate_value_valid(name) ||
        !group_id || !ac_config_candidate_value_valid(group_id) ||
        !bindings || !json_object_is_type(bindings, json_type_array) ||
        !(count = json_object_array_length(bindings)) ||
        count > AC_SSID_BINDINGS_MAX) {
        reason = "invalid_request";
        goto done;
    }
    for (i = 0; i < count; i++) {
        struct json_object *binding = json_object_array_get_idx(bindings, i);
        struct json_object *desired = NULL, *runtime = NULL;
        const char *ap_id = ac_db_json_string(binding, "ap_id");
        const char *radio_id = ac_db_json_string(binding, "radio_id");
        const char *section = ac_db_json_string(binding, "section_name");
        const char *bssid = ac_db_json_string(binding, "bssid");

        if (!ap_id || !ac_uuid_valid(ap_id) || !radio_id ||
            !ac_config_candidate_name_valid(radio_id)) {
            reason = "ssid_binding_invalid";
            goto done;
        }
        reason = ac_ssid_existing_binding(ap_id, radio_id, section, bssid,
                                          name, now, &desired, &runtime);
        if (reason)
            goto done;
        json_object_put(desired);
        for (j = 0; j < i; j++) {
            struct json_object *prior = json_object_array_get_idx(bindings, j);
            if (!strcmp(ap_id, ac_db_json_string(prior, "ap_id")) &&
                (!strcmp(radio_id, ac_db_json_string(prior, "radio_id")) ||
                 !strcmp(section, ac_db_json_string(prior, "section_name")))) {
                json_object_put(runtime);
                reason = "ssid_binding_duplicate";
                goto done;
            }
        }
        json_object_array_add(resolved, runtime);
    }
    reason = "database_error";
    if (ac_exec("BEGIN IMMEDIATE") != 0)
        goto done;
    transaction = 1;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT 1 FROM ac_ssids WHERE ssid_id=?1", -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, ssid_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        reason = "ssid_already_managed";
        goto done;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT site_id FROM ac_ap_groups WHERE group_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, group_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW &&
        strcmp(site_id, (const char *)sqlite3_column_text(st, 0))) {
        reason = "ap_group_site_mismatch";
        goto done;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_ssids(ssid_id,site_id,name,config_json,revision,"
            "enabled,updated_at) VALUES(?1,?2,?3,"
            "'{\"origin\":\"adopted_existing\",\"credentials\":\"ap_local_unchanged\"}',"
            "1,1,?4)", -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, ssid_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, site_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, now);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT OR IGNORE INTO ac_ap_groups(group_id,site_id,name,revision,"
            "updated_at) VALUES(?1,?2,?1,1,?3)", -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, group_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, site_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, now);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    for (i = 0; i < count; i++) {
        struct json_object *binding = json_object_array_get_idx(bindings, i);
        const char *ap_id = ac_db_json_string(binding, "ap_id");

        if (sqlite3_prepare_v2(g_ac_db,
                "SELECT 1 FROM ac_aps a JOIN ac_ap_runtime r ON r.ap_id=a.ap_id "
                "WHERE a.ap_id=?1 AND a.site_id=?2 AND a.adoption_state='adopted' "
                "AND a.last_seen_at>=?3 AND r.session_connected=1",
                -1, &st, NULL) != SQLITE_OK)
            goto done;
        sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, site_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, now - AC_AP_ONLINE_TIMEOUT_SECONDS);
        if (sqlite3_step(st) != SQLITE_ROW) {
            reason = "ssid_ap_not_adopted_online_in_site";
            goto done;
        }
        sqlite3_finalize(st);
        st = NULL;
        if (sqlite3_prepare_v2(g_ac_db,
                "SELECT 1 FROM ac_ssid_bindings WHERE ap_id=?1 AND "
                "(section_name=?2 OR bssid=?3 COLLATE NOCASE)",
                -1, &st, NULL) != SQLITE_OK)
            goto done;
        sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, ac_db_json_string(binding, "section_name"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, ac_db_json_string(binding, "bssid"), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            reason = "ssid_binding_already_managed";
            goto done;
        }
        sqlite3_finalize(st);
        st = NULL;
        if (sqlite3_prepare_v2(g_ac_db,
                "INSERT INTO ac_ssid_bindings(ssid_id,ap_id,radio_id,section_name,"
                "bssid,state,desired_revision,applied_revision,updated_at) "
                "VALUES(?1,?2,?3,?4,?5,'adopted_existing',1,1,?6)",
                -1, &st, NULL) != SQLITE_OK)
            goto done;
        sqlite3_bind_text(st, 1, ssid_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, ap_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, ac_db_json_string(binding, "radio_id"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, ac_db_json_string(binding, "section_name"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, ac_db_json_string(binding, "bssid"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 6, now);
        if (sqlite3_step(st) != SQLITE_DONE)
            goto done;
        sqlite3_finalize(st);
        st = NULL;
        if (sqlite3_prepare_v2(g_ac_db,
                "INSERT OR IGNORE INTO ac_ap_group_members(group_id,ap_id) "
                "VALUES(?1,?2)", -1, &st, NULL) != SQLITE_OK)
            goto done;
        sqlite3_bind_text(st, 1, group_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, ap_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE)
            goto done;
        sqlite3_finalize(st);
        st = NULL;
        if (sqlite3_prepare_v2(g_ac_db,
                "UPDATE ac_station_sessions SET ssid_id=?1 WHERE ap_id=?2 "
                "AND radio_id=?3 AND ssid_id=?4",
                -1, &st, NULL) != SQLITE_OK)
            goto done;
        sqlite3_bind_text(st, 1, ssid_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, ap_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, ac_db_json_string(binding, "radio_id"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, ac_db_json_string(
            json_object_array_get_idx(resolved, i), "id"), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE)
            goto done;
        sqlite3_finalize(st);
        st = NULL;
    }
    if (ac_exec("COMMIT") != 0)
        goto done;
    transaction = 0;
    reason = NULL;
    json_object_object_add(result, "ssid_id", json_object_new_string(ssid_id));
    json_object_object_add(result, "ap_group_id", json_object_new_string(group_id));
    json_object_object_add(result, "binding_count", json_object_new_int64(count));
    json_object_object_add(result, "wireless_changed", json_object_new_boolean(0));
    json_object_object_add(result, "credentials_verified", json_object_new_boolean(0));
done:
    sqlite3_finalize(st);
    if (transaction) ac_exec("ROLLBACK");
    json_object_put(resolved);
    json_object_object_add(result, "ok", json_object_new_boolean(!reason));
    if (reason)
        json_object_object_add(result, "error", json_object_new_string(reason));
    return result;
}

/* Vet the caller's option object, returning the refusal reason or NULL.
 *
 * Checked here rather than left to ac_config_candidate_validate because that
 * runs inside the transaction, after the desired state has been written: a
 * caller would get `target_invalid` back for a request that never had a chance,
 * and the row would sit there claiming an SSID that no AP was ever asked for.
 */
static const char *ac_ssid_options_reason(struct json_object *options)
{
    struct json_object *value = NULL;

    if (!options || !json_object_is_type(options, json_type_object))
        return "ssid_options_invalid";
    json_object_object_foreach(options, key, entry) {
        if (!ac_config_candidate_name_valid(key))
            return "ssid_option_name_invalid";
        /* device / ssid / disabled / mode are derived from the SSID record
         * itself, so a caller cannot restate them and disagree with it. */
        if (!strcmp(key, "device") || !strcmp(key, "ssid") ||
            !strcmp(key, "disabled") || !strcmp(key, "mode"))
            return "ssid_option_reserved";
        if (!json_object_is_type(entry, json_type_string))
            return "ssid_option_value_not_string";
        if (ac_config_candidate_option_secret(key))
            return "candidate_option_secret_not_supported";
        if (!ac_config_candidate_option_allowed(key))
            return "candidate_option_not_allowed";
        if (!ac_config_candidate_value_valid(json_object_get_string(entry)))
            return "ssid_option_value_invalid";
    }
    /* A VAP with no `network` comes up broadcasting and bridged nowhere.  Each
     * AP reports its own bridge names, so a caller can name one; this side will
     * not guess `lan` on its behalf and hand back an SSID that carries no
     * traffic while every status field says it applied. */
    if (!json_object_object_get_ex(options, "network", &value))
        return "ssid_network_required";
    /* Every mode past these two needs key material, and `key` /
     * `wpa_passphrase` are refused by both sides' option filters (see
     * ac_config_candidate_option_secret).  Sending psk2 with no key does not
     * fail safe -- hostapd refuses the BSS at start-up and can take the radio
     * down with it -- so refuse here instead, naming the same gap that
     * capability password_rotation still reports as
     * phase2_secret_safe_apply_pending. */
    if (json_object_object_get_ex(options, "encryption", &value)) {
        const char *mode = json_object_get_string(value);

        if (strcmp(mode, "none") && strcmp(mode, "owe"))
            return "ssid_encryption_requires_secret";
    }
    return NULL;
}

/* The sections array of the candidate for `ap_id`, creating the target on first
 * use.  One AP is one target because one AP is one /etc/config/wireless. */
static struct json_object *ac_ssid_target_sections(struct json_object *targets,
                                                   const char *ap_id)
{
    struct json_object *target = NULL;
    struct json_object *candidate = NULL;
    struct json_object *sections = NULL;
    size_t i;

    if (!targets || !ap_id)
        return NULL;
    for (i = 0; i < json_object_array_length(targets); i++) {
        const char *existing;

        target = json_object_array_get_idx(targets, i);
        existing = ac_db_json_string(target, "ap_id");
        if (existing && !strcmp(existing, ap_id) &&
            json_object_object_get_ex(target, "candidate", &candidate) &&
            json_object_object_get_ex(candidate, "sections", &sections))
            return sections;
    }
    if (json_object_array_length(targets) >= AC_WIFI_TX_TARGETS_MAX)
        return NULL;
    target = json_object_new_object();
    candidate = json_object_new_object();
    sections = json_object_new_array();
    if (!target || !candidate || !sections) {
        json_object_put(target);
        json_object_put(candidate);
        json_object_put(sections);
        return NULL;
    }
    json_object_object_add(candidate, "format",
        json_object_new_string(AC_CONFIG_CANDIDATE_FORMAT));
    json_object_object_add(candidate, "sections", sections);
    json_object_object_add(target, "ap_id", json_object_new_string(ap_id));
    json_object_object_add(target, "candidate", candidate);
    json_object_array_add(targets, target);
    return sections;
}

/* Seal every candidate with its digest.
 *
 * Last, and over the finished sections array: the transaction refuses a target
 * that has no digest (`target_invalid`, which is how both roaming dispatchers
 * silently never landed), and both sides hash the full array, so it cannot be
 * accumulated section by section as they are appended. */
static int ac_ssid_targets_seal(struct json_object *targets)
{
    size_t i;

    for (i = 0; i < json_object_array_length(targets); i++) {
        struct json_object *target = json_object_array_get_idx(targets, i);
        struct json_object *candidate = NULL;
        struct json_object *sections = NULL;
        char digest[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1];

        if (!json_object_object_get_ex(target, "candidate", &candidate) ||
            !json_object_object_get_ex(candidate, "sections", &sections) ||
            json_object_array_length(sections) == 0 ||
            json_object_array_length(sections) >
                AC_CONFIG_CANDIDATE_SECTIONS_MAX ||
            ac_config_candidate_digest(sections, digest) != 0)
            return -1;
        json_object_object_add(candidate, "candidate_digest",
                               json_object_new_string(digest));
        json_object_object_add(target, "candidate_digest",
                               json_object_new_string(digest));
    }
    return 0;
}

/* One wifi-iface section for a put. */
static int ac_ssid_append_put_section(struct json_object *sections,
                                      const char *section_name,
                                      const char *device, const char *name,
                                      int enabled, struct json_object *options)
{
    struct json_object *section = json_object_new_object();
    struct json_object *out = json_object_new_object();

    if (!sections || !section || !out) {
        json_object_put(section);
        json_object_put(out);
        return -1;
    }
    /* `create` on every put, including an update of a section that certainly
     * exists.
     *
     * apd_config_section_create_live is idempotent -- `uci set
     * wireless.<name>=wifi-iface` against a section that already has that type
     * changes nothing -- while apd_config_capture_previous still records
     * existed=true and each named option's previous value, so a rollback of an
     * update restores values and only drops the section when it created it.
     * That makes always-create both reversible and self-healing: a plain `set`
     * against a section the AP has since lost to a config reset or a manual
     * edit would fail `uci_set_failed` forever, with no way back except
     * deleting the SSID and building it again. */
    json_object_object_add(section, "section",
                           json_object_new_string(section_name));
    json_object_object_add(section, "operation",
                           json_object_new_string("create"));
    json_object_object_add(section, "section_type",
                           json_object_new_string("wifi-iface"));
    json_object_object_add(out, "device", json_object_new_string(device));
    json_object_object_add(out, "mode", json_object_new_string("ap"));
    json_object_object_add(out, "ssid", json_object_new_string(name));
    /* UCI spells the negative, and hostapd reads `disabled`. */
    json_object_object_add(out, "disabled",
                           json_object_new_string(enabled ? "0" : "1"));
    json_object_object_foreach(options, key, entry)
        json_object_object_add(out, key,
            json_object_new_string(json_object_get_string(entry)));
    json_object_object_add(section, "options", out);
    json_object_array_add(sections, section);
    return 0;
}

/* One wifi-iface removal.
 *
 * `options` is present and empty, not absent: the contract requires the key on
 * every section, and apd_config_candidate_check exempts only a delete from the
 * "at least one option" floor. */
static int ac_ssid_append_delete_section(struct json_object *sections,
                                         const char *section_name)
{
    struct json_object *section = json_object_new_object();
    struct json_object *options = json_object_new_object();

    if (!sections || !section || !options) {
        json_object_put(section);
        json_object_put(options);
        return -1;
    }
    json_object_object_add(section, "section",
                           json_object_new_string(section_name));
    json_object_object_add(section, "operation",
                           json_object_new_string("delete"));
    json_object_object_add(section, "options", options);
    json_object_array_add(sections, section);
    return 0;
}

/* Stamp a dispatch refusal on every binding of an SSID. */
static void ac_ssid_bindings_fail(const char *ssid_id, const char *error,
                                  int64_t now)
{
    sqlite3_stmt *st = NULL;

    if (!g_ac_db || !ssid_id)
        return;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_ssid_bindings SET state='failed',error_code=?2,"
            "updated_at=?3 WHERE ssid_id=?1", -1, &st, NULL) != SQLITE_OK)
        return;
    sqlite3_bind_text(st, 1, ssid_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, error && error[0] ? error : "dispatch_refused", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, now);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

/* Create or update a managed SSID and push it to every AP it is bound to.
 *
 * `base_revision` is the optimistic-concurrency claim against ac_ssids.revision:
 * 0 creates, anything else must match the stored revision exactly.  The desired
 * state is written first and kept even when the transaction refuses -- the row
 * plus its per-binding error_code is the record of what was asked for, and the
 * same reasoning as the Phase 4 audit row applies: state discarded on the
 * failure path is state nobody can query afterwards. */
int ac_db_ssid_put(const char *ssid_id, const char *site_id, const char *name,
                   int enabled, struct json_object *options,
                   struct json_object *bindings, int64_t base_revision,
                   const char *actor, int64_t now,
                   char ssid_id_out[AC_RADIO_JOB_ID_LEN + 1],
                   char transaction_id_out[AC_RADIO_JOB_ID_LEN + 1],
                   char *error_out, size_t error_len)
{
    char generated[AC_RADIO_JOB_ID_LEN + 1];
    char actor_id[AC_RADIO_JOB_ID_LEN + 1];
    char transaction_id[AC_RADIO_JOB_ID_LEN + 1];
    char idempotency_key[AC_RADIO_JOB_IDEMPOTENCY_MAX + 1];
    char error_buf[160];
    const char *id = ssid_id;
    const char *reason = NULL;
    struct json_object *targets = NULL;
    struct json_object *resolved = NULL;
    sqlite3_stmt *st = NULL;
    int64_t revision = 0;
    int exists = 0;
    size_t count;
    size_t i;
    size_t j;
    int rc = AC_CONFIG_JOB_ERROR;

    if (ssid_id_out)
        ssid_id_out[0] = '\0';
    if (transaction_id_out)
        transaction_id_out[0] = '\0';
    ac_wifi_tx_error(error_out, error_len, "database_error");
    if (!g_ac_db)
        return AC_CONFIG_JOB_ERROR;
    if (!site_id || !ac_config_candidate_value_valid(site_id) ||
        !name || strlen(name) > AC_SSID_NAME_MAX ||
        !ac_config_candidate_value_valid(name) ||
        (enabled != 0 && enabled != 1) || base_revision < 0 ||
        !bindings || !json_object_is_type(bindings, json_type_array) ||
        json_object_array_length(bindings) > AC_SSID_BINDINGS_MAX) {
        ac_wifi_tx_error(error_out, error_len, "invalid_request");
        return AC_CONFIG_JOB_INVALID;
    }
    reason = ac_ssid_options_reason(options);
    if (reason) {
        ac_wifi_tx_error(error_out, error_len, reason);
        return AC_CONFIG_JOB_INVALID;
    }
    if (!id || !id[0]) {
        /* A create carries no id and has to claim revision 0.  Anything else is
         * a caller that believes it is editing a row which does not exist. */
        if (base_revision != 0 || ac_generate_uuid(generated) != 0) {
            ac_wifi_tx_error(error_out, error_len, "invalid_request");
            return AC_CONFIG_JOB_INVALID;
        }
        id = generated;
    } else if (!ac_uuid_valid(id)) {
        ac_wifi_tx_error(error_out, error_len, "invalid_request");
        return AC_CONFIG_JOB_INVALID;
    }
    /* Resolve every binding before touching the database.  A radio this side
     * cannot name is a refusal, never a partial write. */
    targets = json_object_new_array();
    resolved = json_object_new_array();
    if (!targets || !resolved)
        goto refuse;
    count = json_object_array_length(bindings);
    for (i = 0; i < count; i++) {
        struct json_object *binding = json_object_array_get_idx(bindings, i);
        struct json_object *entry = NULL;
        struct json_object *sections = NULL;
        const char *ap_id = ac_db_json_string(binding, "ap_id");
        const char *radio_id = ac_db_json_string(binding, "radio_id");
        char device[AC_CONFIG_CANDIDATE_NAME_MAX + 1];
        char section_name[AC_CONFIG_CANDIDATE_NAME_MAX + 1];

        if (!ap_id || !ac_uuid_valid(ap_id) || !radio_id ||
            !ac_config_candidate_name_valid(radio_id)) {
            reason = "ssid_binding_invalid";
            goto refuse;
        }
        if (ac_ssid_uci_device(ap_id, radio_id, now, device) != 0) {
            reason = "ssid_radio_unresolved";
            goto refuse;
        }
        if (ac_ssid_section_name(id, device, section_name) != 0) {
            reason = "ssid_section_name_invalid";
            goto refuse;
        }
        /* Two bindings landing on one section would have the second silently
         * overwrite the first here and collide on the bindings primary key
         * below.  Compared on the resolved section rather than on radio_id,
         * because two radio_ids that map to one wifi-device are the same
         * collision arriving by a different route. */
        for (j = 0; j < json_object_array_length(resolved); j++) {
            struct json_object *prior = json_object_array_get_idx(resolved, j);
            const char *prior_ap = ac_db_json_string(prior, "ap_id");
            const char *prior_section = ac_db_json_string(prior, "section");

            if (prior_ap && prior_section && !strcmp(prior_ap, ap_id) &&
                !strcmp(prior_section, section_name)) {
                reason = "ssid_binding_duplicate";
                goto refuse;
            }
        }
        sections = ac_ssid_target_sections(targets, ap_id);
        if (!sections ||
            ac_ssid_append_put_section(sections, section_name, device, name,
                                       enabled, options) != 0) {
            reason = "ssid_targets_bounds";
            goto refuse;
        }
        entry = json_object_new_object();
        if (!entry)
            goto refuse;
        json_object_object_add(entry, "ap_id", json_object_new_string(ap_id));
        json_object_object_add(entry, "radio_id",
                               json_object_new_string(radio_id));
        json_object_object_add(entry, "section",
                               json_object_new_string(section_name));
        json_object_array_add(resolved, entry);
    }
    if (ac_exec("BEGIN IMMEDIATE") != 0)
        goto refuse;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT revision,COALESCE(json_extract(config_json,'$.origin'),'') "
            "FROM ac_ssids WHERE ssid_id=?1", -1, &st,
            NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        exists = 1;
        revision = sqlite3_column_int64(st, 0);
        if (!strcmp((const char *)sqlite3_column_text(st, 1), "adopted_existing")) {
            reason = "adopted_ssid_requires_existing_section_update";
            rc = AC_CONFIG_JOB_INVALID;
            goto rollback;
        }
    }
    sqlite3_finalize(st);
    st = NULL;
    if ((exists && revision != base_revision) ||
        (!exists && base_revision != 0)) {
        rc = AC_CONFIG_JOB_CONFLICT;
        reason = "revision_conflict";
        goto rollback;
    }
    if (exists) {
        int secret_busy = ac_db_secret_rotation_busy(id);

        if (secret_busy != 0) {
            rc = secret_busy > 0 ? AC_CONFIG_JOB_CONFLICT :
                                   AC_CONFIG_JOB_ERROR;
            reason = secret_busy > 0 ? "secret_rotation_in_progress" :
                                       "secret_rotation_state_unavailable";
            goto rollback;
        }
    }
    /* Sections this SSID used to own and no longer does.
     *
     * A binding dropped from the list, or one whose radio was renamed on the
     * AP, leaves a wifi-iface behind that keeps broadcasting.  Nothing else
     * would ever remove it -- the next put addresses the new name and never
     * mentions the old one -- so the removals ride in the same candidates as
     * the writes, which also makes them roll back together. */
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT ap_id,section_name FROM ac_ssid_bindings WHERE ssid_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *old_ap = sqlite3_column_text(st, 0);
        const unsigned char *old_section = sqlite3_column_text(st, 1);
        struct json_object *sections = NULL;
        int still_used = 0;

        if (!old_ap || !old_section || !old_section[0])
            continue;
        for (j = 0; j < json_object_array_length(resolved); j++) {
            struct json_object *entry = json_object_array_get_idx(resolved, j);
            const char *entry_ap = ac_db_json_string(entry, "ap_id");
            const char *entry_section = ac_db_json_string(entry, "section");

            if (entry_ap && entry_section &&
                !strcmp(entry_ap, (const char *)old_ap) &&
                !strcmp(entry_section, (const char *)old_section)) {
                still_used = 1;
                break;
            }
        }
        if (still_used)
            continue;
        sections = ac_ssid_target_sections(targets, (const char *)old_ap);
        if (!sections ||
            ac_ssid_append_delete_section(sections,
                                          (const char *)old_section) != 0) {
            reason = "ssid_targets_bounds";
            goto rollback;
        }
    }
    sqlite3_finalize(st);
    st = NULL;
    if (ac_ssid_targets_seal(targets) != 0) {
        reason = "candidate_sections_bounds";
        goto rollback;
    }
    revision = base_revision + 1;
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_ssids(ssid_id,site_id,name,config_json,secret_id,"
            "revision,enabled,updated_at,secret_present)"
            " VALUES(?1,?2,?3,?4,'',?5,?6,?7,0)"
            " ON CONFLICT(ssid_id) DO UPDATE SET site_id=excluded.site_id,"
            "name=excluded.name,config_json=excluded.config_json,"
            "revision=excluded.revision,enabled=excluded.enabled,"
            "updated_at=excluded.updated_at", -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, site_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4,
        json_object_to_json_string_ext(options, JSON_C_TO_STRING_PLAIN), -1,
        SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 5, revision);
    sqlite3_bind_int(st, 6, enabled);
    sqlite3_bind_int64(st, 7, now);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    /* Bindings are replaced wholesale: the request carries the complete list,
     * and merging would keep rows for bindings the caller just removed -- the
     * same rows whose sections were queued for deletion a moment ago. */
    if (sqlite3_prepare_v2(g_ac_db,
            "DELETE FROM ac_ssid_bindings WHERE ssid_id=?1", -1, &st,
            NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    for (i = 0; i < json_object_array_length(resolved); i++) {
        struct json_object *entry = json_object_array_get_idx(resolved, i);

        if (sqlite3_prepare_v2(g_ac_db,
                "INSERT INTO ac_ssid_bindings(ssid_id,ap_id,radio_id,"
                "desired_revision,applied_revision,state,bssid,error_code,"
                "updated_at,section_name)"
                " VALUES(?1,?2,?3,?4,0,'pending','','',?5,?6)",
                -1, &st, NULL) != SQLITE_OK)
            goto rollback;
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, ac_db_json_string(entry, "ap_id"), -1,
                          SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, ac_db_json_string(entry, "radio_id"), -1,
                          SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 4, revision);
        sqlite3_bind_int64(st, 5, now);
        sqlite3_bind_text(st, 6, ac_db_json_string(entry, "section"), -1,
                          SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE)
            goto rollback;
        sqlite3_finalize(st);
        st = NULL;
    }
    if (ac_exec("COMMIT") != 0)
        goto rollback;
    if (ssid_id_out)
        snprintf(ssid_id_out, AC_RADIO_JOB_ID_LEN + 1, "%s", id);
    json_object_put(resolved);
    resolved = NULL;
    /* Nothing to push.  An SSID may legitimately be defined before it is
     * deployed anywhere, and that is not a failure to report. */
    if (json_object_array_length(targets) == 0) {
        json_object_put(targets);
        ac_wifi_tx_error(error_out, error_len, "");
        return AC_CONFIG_JOB_OK;
    }
    ac_generate_uuid(actor_id);
    /* The revision is in the key, so a retried put of the same revision dedupes
     * onto the same transaction instead of queueing a second identical write. */
    snprintf(idempotency_key, sizeof(idempotency_key), "ssid-put:%s:%lld", id,
             (long long)revision);
    rc = ac_db_wifi_transaction_apply(
        actor && actor[0] ? actor : actor_id, idempotency_key, "per_target",
        AC_WIFI_TX_BASE_REVISION_CURRENT,
        json_object_to_json_string_ext(targets, JSON_C_TO_STRING_PLAIN), now,
        transaction_id, error_buf, sizeof(error_buf));
    json_object_put(targets);
    targets = NULL;
    if (rc == AC_CONFIG_JOB_OK || rc == AC_CONFIG_JOB_IDEMPOTENT) {
        if (transaction_id_out)
            snprintf(transaction_id_out, AC_RADIO_JOB_ID_LEN + 1, "%s",
                     transaction_id);
        ac_wifi_tx_error(error_out, error_len, "");
        return rc;
    }
    /* Refused after the desired state landed.  The row stays -- it is the
     * record of what was asked for -- and the reason is stamped on every
     * binding, so a later status read explains itself without the caller having
     * had to keep this return value. */
    ac_ssid_bindings_fail(id, error_buf, now);
    ac_wifi_tx_error(error_out, error_len, error_buf);
    return rc;
rollback:
    sqlite3_finalize(st);
    ac_exec("ROLLBACK");
    json_object_put(targets);
    json_object_put(resolved);
    ac_wifi_tx_error(error_out, error_len, reason ? reason : "database_error");
    if (rc == AC_CONFIG_JOB_CONFLICT)
        return AC_CONFIG_JOB_CONFLICT;
    return reason ? AC_CONFIG_JOB_INVALID : AC_CONFIG_JOB_ERROR;
refuse:
    json_object_put(targets);
    json_object_put(resolved);
    ac_wifi_tx_error(error_out, error_len, reason ? reason : "database_error");
    return reason ? AC_CONFIG_JOB_INVALID : AC_CONFIG_JOB_ERROR;
}

/* Remove a managed SSID and every wifi-iface it owns.
 *
 * The section names come from ac_ssid_bindings.section_name -- what was written
 * -- and never from re-deriving them: the derivation reads the AP's current
 * radio names, so a radio renamed since the create would produce a name for a
 * section that does not exist, `uci delete` would report nothing to remove, and
 * the real VAP would stay up while this side reported a clean removal.
 *
 * The controller rows go last, after the transaction is accepted.  Removing
 * them first and then being refused would leave no record that anything was
 * ever asked for, and the SSID would keep broadcasting with nothing left in the
 * database to retry from.  A duplicate delete is harmless in the other
 * direction: apd_config_apply_prepared probes the section type first and skips
 * a section that is already gone.
 */
int ac_db_ssid_delete(const char *ssid_id, int64_t base_revision,
                      const char *actor, int64_t now,
                      char transaction_id_out[AC_RADIO_JOB_ID_LEN + 1],
                      char *error_out, size_t error_len)
{
    char actor_id[AC_RADIO_JOB_ID_LEN + 1];
    char transaction_id[AC_RADIO_JOB_ID_LEN + 1];
    char idempotency_key[AC_RADIO_JOB_IDEMPOTENCY_MAX + 1];
    char error_buf[160];
    const char *reason = NULL;
    struct json_object *targets = NULL;
    sqlite3_stmt *st = NULL;
    int64_t revision = 0;
    int exists = 0;
    int rc = AC_CONFIG_JOB_ERROR;

    if (transaction_id_out)
        transaction_id_out[0] = '\0';
    ac_wifi_tx_error(error_out, error_len, "database_error");
    if (!g_ac_db)
        return AC_CONFIG_JOB_ERROR;
    if (!ssid_id || !ac_uuid_valid(ssid_id) || base_revision < 0) {
        ac_wifi_tx_error(error_out, error_len, "invalid_request");
        return AC_CONFIG_JOB_INVALID;
    }
    targets = json_object_new_array();
    if (!targets)
        return AC_CONFIG_JOB_ERROR;
    if (ac_exec("BEGIN IMMEDIATE") != 0)
        goto fail;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT revision FROM ac_ssids WHERE ssid_id=?1", -1, &st,
            NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, ssid_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        exists = 1;
        revision = sqlite3_column_int64(st, 0);
    }
    sqlite3_finalize(st);
    st = NULL;
    if (!exists) {
        rc = AC_CONFIG_JOB_NOT_FOUND;
        reason = "not_found";
        goto rollback;
    }
    if (revision != base_revision) {
        rc = AC_CONFIG_JOB_CONFLICT;
        reason = "revision_conflict";
        goto rollback;
    }
    {
        int secret_busy = ac_db_secret_rotation_busy(ssid_id);

        if (secret_busy != 0) {
            rc = secret_busy > 0 ? AC_CONFIG_JOB_CONFLICT :
                                   AC_CONFIG_JOB_ERROR;
            reason = secret_busy > 0 ? "secret_rotation_in_progress" :
                                       "secret_rotation_state_unavailable";
            goto rollback;
        }
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT ap_id,section_name FROM ac_ssid_bindings WHERE ssid_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, ssid_id, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *ap_id = sqlite3_column_text(st, 0);
        const unsigned char *section = sqlite3_column_text(st, 1);
        struct json_object *sections = NULL;

        if (!ap_id || !section || !section[0]) {
            reason = "ssid_binding_section_unknown";
            rc = AC_CONFIG_JOB_INVALID;
            goto rollback;
        }
        sections = ac_ssid_target_sections(targets, (const char *)ap_id);
        if (!sections ||
            ac_ssid_append_delete_section(sections,
                                          (const char *)section) != 0) {
            reason = "ssid_targets_bounds";
            rc = AC_CONFIG_JOB_INVALID;
            goto rollback;
        }
    }
    sqlite3_finalize(st);
    st = NULL;
    if (ac_ssid_targets_seal(targets) != 0) {
        reason = "candidate_sections_bounds";
        rc = AC_CONFIG_JOB_INVALID;
        goto rollback;
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_ssid_bindings SET state='deleting',error_code='',"
            "updated_at=?2 WHERE ssid_id=?1", -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, ssid_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (ac_exec("COMMIT") != 0)
        goto rollback;
    if (json_object_array_length(targets) > 0) {
        ac_generate_uuid(actor_id);
        snprintf(idempotency_key, sizeof(idempotency_key),
                 "ssid-delete:%s:%lld", ssid_id, (long long)revision);
        rc = ac_db_wifi_transaction_apply(
            actor && actor[0] ? actor : actor_id, idempotency_key, "per_target",
            AC_WIFI_TX_BASE_REVISION_CURRENT,
            json_object_to_json_string_ext(targets, JSON_C_TO_STRING_PLAIN),
            now, transaction_id, error_buf, sizeof(error_buf));
        if (rc != AC_CONFIG_JOB_OK && rc != AC_CONFIG_JOB_IDEMPOTENT) {
            /* Nothing was removed.  The SSID, its bindings and the reason all
             * stay queryable, and the caller can retry with the same
             * base_revision. */
            ac_ssid_bindings_fail(ssid_id, error_buf, now);
            reason = error_buf;
            goto fail;
        }
        if (transaction_id_out)
            snprintf(transaction_id_out, AC_RADIO_JOB_ID_LEN + 1, "%s",
                     transaction_id);
    }
    json_object_put(targets);
    targets = NULL;
    if (ac_exec("BEGIN IMMEDIATE") != 0)
        goto fail;
    /* Guarded on the revision that was dispatched.  A put that raced in between
     * the two transactions bumped it and queued its own create, so dropping the
     * rows here would leave the AP with VAPs that nothing on this side owns. */
    if (sqlite3_prepare_v2(g_ac_db,
            "DELETE FROM ac_ssids WHERE ssid_id=?1 AND revision=?2", -1, &st,
            NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, ssid_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, revision);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_changes(g_ac_db) != 1) {
        /* Distinct from the pre-dispatch conflict on purpose: the removal is
         * already queued against the APs, which a plain revision_conflict would
         * not tell the caller. */
        reason = "revision_conflict_after_dispatch";
        rc = AC_CONFIG_JOB_CONFLICT;
        goto rollback;
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "DELETE FROM ac_ssid_bindings WHERE ssid_id=?1", -1, &st,
            NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, ssid_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (ac_exec("COMMIT") != 0)
        goto rollback;
    ac_wifi_tx_error(error_out, error_len, "");
    return AC_CONFIG_JOB_OK;
rollback:
    sqlite3_finalize(st);
    st = NULL;
    ac_exec("ROLLBACK");
    /* Reached after a successful dispatch only when the bookkeeping failed.
     * The AP-side removal is queued and will happen; the controller rows
     * survive, and re-running the delete dedupes onto the same transaction and
     * clears them. */
    if (rc == AC_CONFIG_JOB_OK || rc == AC_CONFIG_JOB_IDEMPOTENT)
        rc = AC_CONFIG_JOB_ERROR;
fail:
    json_object_put(targets);
    ac_wifi_tx_error(error_out, error_len, reason ? reason : "database_error");
    return rc;
}

/* Desired-state view of the managed SSIDs, each with its bindings.
 *
 * Desired state only, deliberately: ac_ssid_runtime holds what the APs report,
 * and merging the two here would hide the difference between "asked for" and
 * "running" -- which is the only thing a caller checking on a write wants to
 * see.  `revision` is what a put or delete has to echo back as base_revision. */
struct json_object *ac_db_ssids_json(void)
{
    struct json_object *root = json_object_new_object();
    struct json_object *items = json_object_new_array();
    sqlite3_stmt *st = NULL;
    int count = 0;

    /* {ok, items, count} like ac_db_roaming_domains_json, not a bare array:
     * a caller has to be able to tell "no SSIDs" from "the query failed", and
     * an empty array says both. */
    if (!g_ac_db || sqlite3_prepare_v2(g_ac_db,
            "SELECT ssid_id,site_id,name,config_json,revision,enabled,"
            "updated_at FROM ac_ssids ORDER BY name,ssid_id", -1, &st,
            NULL) != SQLITE_OK)
        goto error;
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *item = json_object_new_object();
        struct json_object *bindings = json_object_new_array();
        struct json_object *options = NULL;
        const unsigned char *ssid_id = sqlite3_column_text(st, 0);
        const unsigned char *text;
        sqlite3_stmt *bs = NULL;

        if (!item || !bindings || !ssid_id) {
            json_object_put(item);
            json_object_put(bindings);
            continue;
        }
        json_object_object_add(item, "ssid_id",
            json_object_new_string((const char *)ssid_id));
        text = sqlite3_column_text(st, 1);
        json_object_object_add(item, "site_id",
            json_object_new_string(text ? (const char *)text : ""));
        text = sqlite3_column_text(st, 2);
        json_object_object_add(item, "name",
            json_object_new_string(text ? (const char *)text : ""));
        text = sqlite3_column_text(st, 3);
        options = text ? json_tokener_parse((const char *)text) : NULL;
        if (!options || !json_object_is_type(options, json_type_object)) {
            json_object_put(options);
            options = json_object_new_object();
        }
        json_object_object_add(item, "options", options);
        json_object_object_add(item, "revision",
            json_object_new_int64(sqlite3_column_int64(st, 4)));
        json_object_object_add(item, "enabled",
            json_object_new_boolean(sqlite3_column_int(st, 5) != 0));
        json_object_object_add(item, "updated_at",
            json_object_new_int64(sqlite3_column_int64(st, 6)));
        if (sqlite3_prepare_v2(g_ac_db,
                "SELECT ap_id,radio_id,section_name,desired_revision,"
                "applied_revision,state,bssid,error_code,updated_at"
                " FROM ac_ssid_bindings WHERE ssid_id=?1"
                " ORDER BY ap_id,radio_id", -1, &bs, NULL) == SQLITE_OK) {
            sqlite3_bind_text(bs, 1, (const char *)ssid_id, -1,
                              SQLITE_TRANSIENT);
            while (sqlite3_step(bs) == SQLITE_ROW) {
                struct json_object *entry = json_object_new_object();
                static const char *const columns[] = {
                    "ap_id", "radio_id", "section_name", NULL, NULL,
                    "state", "bssid", "error_code",
                };
                size_t c;

                if (!entry)
                    continue;
                for (c = 0; c < sizeof(columns) / sizeof(columns[0]); c++) {
                    if (!columns[c])
                        continue;
                    text = sqlite3_column_text(bs, (int)c);
                    json_object_object_add(entry, columns[c],
                        json_object_new_string(text ? (const char *)text : ""));
                }
                json_object_object_add(entry, "desired_revision",
                    json_object_new_int64(sqlite3_column_int64(bs, 3)));
                json_object_object_add(entry, "applied_revision",
                    json_object_new_int64(sqlite3_column_int64(bs, 4)));
                json_object_object_add(entry, "updated_at",
                    json_object_new_int64(sqlite3_column_int64(bs, 8)));
                json_object_array_add(bindings, entry);
            }
        }
        sqlite3_finalize(bs);
        json_object_object_add(item, "bindings", bindings);
        json_object_array_add(items, item);
        count++;
    }
    sqlite3_finalize(st);
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "items", items);
    json_object_object_add(root, "count", json_object_new_int(count));
    return root;
error:
    sqlite3_finalize(st);
    json_object_put(items);
    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "error",
                           json_object_new_string("database_error"));
    return root;
}

struct ac_survey_counter_sample {
    const char *interface;
    int frequency_mhz;
    int64_t active_ms;
    int64_t busy_ms;
    int64_t receive_ms;
    int64_t transmit_ms;
    int noise_dbm;
    int receive_present;
    int transmit_present;
    int noise_present;
};

static int ac_db_json_int64(struct json_object *object, const char *name,
                            int64_t *out, int required)
{
    struct json_object *value = NULL;

    if (!object || !out || !json_object_object_get_ex(object, name, &value) ||
        !value || json_object_is_type(value, json_type_null))
        return required ? -1 : 0;
    if (!json_object_is_type(value, json_type_int) ||
        json_object_get_int64(value) < 0)
        return -1;
    *out = json_object_get_int64(value);
    return 1;
}

static int ac_db_survey_parse(struct json_object *radio,
                              struct ac_survey_counter_sample *sample)
{
    struct json_object *survey = NULL;
    struct json_object *value = NULL;
    int result;

    if (!radio || !sample ||
        !json_object_object_get_ex(radio, "survey", &survey) || !survey ||
        !json_object_is_type(survey, json_type_object) ||
        !json_object_object_get_ex(survey, "complete", &value) || !value ||
        !json_object_is_type(value, json_type_boolean) ||
        !json_object_get_boolean(value))
        return 0;
    memset(sample, 0, sizeof(*sample));
    sample->interface = ac_db_json_string(survey, "interface");
    if (!sample->interface)
        sample->interface = "";
    if (ac_db_json_int64(survey, "frequency_mhz", &sample->active_ms, 1) != 1 ||
        sample->active_ms < 2300 || sample->active_ms > 7200)
        return 0;
    sample->frequency_mhz = (int)sample->active_ms;
    if (ac_db_json_int64(survey, "channel_active_time_ms", &sample->active_ms,
                         1) != 1 ||
        ac_db_json_int64(survey, "channel_busy_time_ms", &sample->busy_ms,
                         1) != 1 ||
        sample->active_ms <= 0 || sample->busy_ms > sample->active_ms)
        return 0;
    result = ac_db_json_int64(survey, "channel_receive_time_ms",
                              &sample->receive_ms, 0);
    if (result < 0)
        return 0;
    sample->receive_present = result == 1;
    result = ac_db_json_int64(survey, "channel_transmit_time_ms",
                              &sample->transmit_ms, 0);
    if (result < 0)
        return 0;
    sample->transmit_present = result == 1;
    if (json_object_object_get_ex(survey, "noise_dbm", &value) && value &&
        !json_object_is_type(value, json_type_null)) {
        if (!json_object_is_type(value, json_type_int) ||
            json_object_get_int(value) < -200 || json_object_get_int(value) > 0)
            return 0;
        sample->noise_dbm = json_object_get_int(value);
        sample->noise_present = 1;
    }
    return 1;
}

static const char *ac_db_survey_source(struct json_object *radio)
{
    struct json_object *survey = NULL;
    struct json_object *value = NULL;

    if (!radio || !json_object_object_get_ex(radio, "survey", &survey) ||
        !survey || !json_object_is_type(survey, json_type_object) ||
        !json_object_object_get_ex(survey, "source", &value) || !value ||
        !json_object_is_type(value, json_type_string) ||
        !json_object_get_string(value)[0])
        return "iw_survey";
    return json_object_get_string(value);
}

static int ac_db_survey_bucket_upsert(const char *ap_id, const char *radio_id,
                                      int resolution_seconds,
                                      int64_t received_at,
                                      int64_t active_delta,
                                      int64_t busy_delta,
                                      int receive_present,
                                      int64_t receive_delta,
                                      int transmit_present,
                                      int64_t transmit_delta,
                                      int noise_present, int noise_dbm,
                                      const char *source)
{
    static const char sql[] =
        "INSERT INTO ac_radio_survey_bucket(ap_id,radio_id,resolution_seconds,"
        "bucket_start,first_received_at,last_received_at,sample_count,active_delta_ms,"
        "busy_delta_ms,receive_delta_ms,transmit_delta_ms,utilization_pct,noise_dbm,source) "
        "VALUES(?1,?2,?3,?4,?5,?5,1,?6,?7,?8,?9,CAST(?7 AS REAL)*100.0/?6,?10,?11) "
        "ON CONFLICT(ap_id,radio_id,resolution_seconds,bucket_start) DO UPDATE SET "
        "first_received_at=MIN(ac_radio_survey_bucket.first_received_at,excluded.first_received_at),"
        "last_received_at=MAX(ac_radio_survey_bucket.last_received_at,excluded.last_received_at),"
        "sample_count=ac_radio_survey_bucket.sample_count+1,"
        "active_delta_ms=ac_radio_survey_bucket.active_delta_ms+excluded.active_delta_ms,"
        "busy_delta_ms=ac_radio_survey_bucket.busy_delta_ms+excluded.busy_delta_ms,"
        "receive_delta_ms=CASE WHEN ac_radio_survey_bucket.receive_delta_ms IS NOT NULL "
        "AND excluded.receive_delta_ms IS NOT NULL THEN ac_radio_survey_bucket.receive_delta_ms+excluded.receive_delta_ms ELSE NULL END,"
        "transmit_delta_ms=CASE WHEN ac_radio_survey_bucket.transmit_delta_ms IS NOT NULL "
        "AND excluded.transmit_delta_ms IS NOT NULL THEN ac_radio_survey_bucket.transmit_delta_ms+excluded.transmit_delta_ms ELSE NULL END,"
        "utilization_pct=CAST(ac_radio_survey_bucket.busy_delta_ms+excluded.busy_delta_ms AS REAL)*100.0/"
        "(ac_radio_survey_bucket.active_delta_ms+excluded.active_delta_ms),"
        "noise_dbm=COALESCE(excluded.noise_dbm,ac_radio_survey_bucket.noise_dbm),"
        "source=excluded.source,complete=1";
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (sqlite3_prepare_v2(g_ac_db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, radio_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, resolution_seconds);
    sqlite3_bind_int64(st, 4, received_at - received_at % resolution_seconds);
    sqlite3_bind_int64(st, 5, received_at);
    sqlite3_bind_int64(st, 6, active_delta);
    sqlite3_bind_int64(st, 7, busy_delta);
    if (receive_present) sqlite3_bind_int64(st, 8, receive_delta);
    else sqlite3_bind_null(st, 8);
    if (transmit_present) sqlite3_bind_int64(st, 9, transmit_delta);
    else sqlite3_bind_null(st, 9);
    if (noise_present) sqlite3_bind_int(st, 10, noise_dbm);
    else sqlite3_bind_null(st, 10);
    sqlite3_bind_text(st, 11, source && source[0] ? source : "iw_survey_delta",
                      -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE)
        rc = 0;
    sqlite3_finalize(st);
    return rc;
}

static int ac_db_survey_prune_target(const char *ap_id, const char *radio_id,
                                     int resolution_seconds, int64_t now,
                                     int retention_seconds, int retention_rows)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (sqlite3_prepare_v2(g_ac_db,
            "DELETE FROM ac_radio_survey_bucket WHERE ap_id=?1 AND radio_id=?2 "
            "AND resolution_seconds=?3 AND last_received_at<?4", -1, &st,
            NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, radio_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, resolution_seconds);
    sqlite3_bind_int64(st, 4, now - retention_seconds);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "DELETE FROM ac_radio_survey_bucket WHERE ap_id=?1 AND radio_id=?2 "
            "AND resolution_seconds=?3 AND sample_id NOT IN (SELECT sample_id "
            "FROM ac_radio_survey_bucket WHERE ap_id=?1 AND radio_id=?2 "
            "AND resolution_seconds=?3 ORDER BY bucket_start DESC,sample_id DESC LIMIT ?4)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, radio_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, resolution_seconds);
    sqlite3_bind_int(st, 4, retention_rows);
    if (sqlite3_step(st) == SQLITE_DONE)
        rc = 0;
done:
    sqlite3_finalize(st);
    return rc;
}

static int ac_db_survey_cursor_write(const char *ap_id, const char *radio_id,
                                     const char *session_epoch,
                                     int64_t observed_at, int64_t received_at,
                                     const struct ac_survey_counter_sample *sample,
                                     const char *source)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_radio_survey_cursor(ap_id,radio_id,interface,frequency_mhz,"
            "observed_at,received_at,session_epoch,source,active_ms,busy_ms,receive_ms,transmit_ms,noise_dbm) "
            "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13) ON CONFLICT(ap_id,radio_id) "
            "DO UPDATE SET interface=excluded.interface,frequency_mhz=excluded.frequency_mhz,"
            "observed_at=excluded.observed_at,received_at=excluded.received_at,session_epoch=excluded.session_epoch,source=excluded.source,"
            "active_ms=excluded.active_ms,busy_ms=excluded.busy_ms,receive_ms=excluded.receive_ms,"
            "transmit_ms=excluded.transmit_ms,noise_dbm=excluded.noise_dbm", -1,
            &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, radio_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, sample->interface, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 4, sample->frequency_mhz);
    sqlite3_bind_int64(st, 5, observed_at);
    sqlite3_bind_int64(st, 6, received_at);
    sqlite3_bind_text(st, 7, session_epoch, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, source && source[0] ? source : "iw_survey", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 9, sample->active_ms);
    sqlite3_bind_int64(st, 10, sample->busy_ms);
    if (sample->receive_present) sqlite3_bind_int64(st, 11, sample->receive_ms);
    else sqlite3_bind_null(st, 11);
    if (sample->transmit_present) sqlite3_bind_int64(st, 12, sample->transmit_ms);
    else sqlite3_bind_null(st, 12);
    if (sample->noise_present) sqlite3_bind_int(st, 13, sample->noise_dbm);
    else sqlite3_bind_null(st, 13);
    if (sqlite3_step(st) == SQLITE_DONE)
        rc = 0;
    sqlite3_finalize(st);
    return rc;
}

static int ac_db_survey_ingest(const char *ap_id, const char *radio_id,
                               const char *session_epoch, int64_t observed_at,
                               int64_t received_at, struct json_object *radio)
{
    struct ac_survey_counter_sample current;
    sqlite3_stmt *st = NULL;
    const char *previous_interface = NULL;
    const char *previous_epoch = NULL;
    int64_t previous_received = 0;
    int64_t previous_active = 0;
    int64_t previous_busy = 0;
    int64_t previous_receive = 0;
    int64_t previous_transmit = 0;
    int previous_frequency = 0;
    const char *previous_source = NULL;
    const char *current_source;
    int previous_receive_present = 0;
    int previous_transmit_present = 0;
    int have_previous = 0;
    int reset = 0;
    int64_t interval;
    int64_t active_delta;
    int64_t busy_delta;
    int64_t receive_delta = 0;
    int64_t transmit_delta = 0;
    int receive_delta_present = 0;
    int transmit_delta_present = 0;

    if (ac_db_survey_parse(radio, &current) != 1)
        return 0;
    current_source = ac_db_survey_source(radio);
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT interface,frequency_mhz,received_at,session_epoch,source,active_ms,busy_ms,"
            "receive_ms,transmit_ms FROM ac_radio_survey_cursor WHERE ap_id=?1 AND radio_id=?2",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, radio_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        have_previous = 1;
        previous_interface = (const char *)sqlite3_column_text(st, 0);
        previous_frequency = sqlite3_column_int(st, 1);
        previous_received = sqlite3_column_int64(st, 2);
        previous_epoch = (const char *)sqlite3_column_text(st, 3);
        previous_source = (const char *)sqlite3_column_text(st, 4);
        previous_active = sqlite3_column_int64(st, 5);
        previous_busy = sqlite3_column_int64(st, 6);
        previous_receive_present = sqlite3_column_type(st, 7) != SQLITE_NULL;
        previous_receive = sqlite3_column_int64(st, 7);
        previous_transmit_present = sqlite3_column_type(st, 8) != SQLITE_NULL;
        previous_transmit = sqlite3_column_int64(st, 8);
        previous_interface = previous_interface ? strdup(previous_interface) : strdup("");
        previous_epoch = previous_epoch ? strdup(previous_epoch) : strdup("");
        previous_source = previous_source ? strdup(previous_source) : strdup("iw_survey");
        if (!previous_interface || !previous_epoch || !previous_source) {
            free((void *)previous_interface);
            free((void *)previous_epoch);
            free((void *)previous_source);
            sqlite3_finalize(st);
            return -1;
        }
    }
    sqlite3_finalize(st);
    st = NULL;
    if (!have_previous)
        return ac_db_survey_cursor_write(ap_id, radio_id, session_epoch,
                                         observed_at, received_at, &current,
                                         current_source);
    interval = received_at - previous_received;
    reset = interval <= 0 || interval > AC_SURVEY_SAMPLE_GAP_SECONDS ||
            strcmp(previous_epoch, session_epoch) ||
            strcmp(previous_source, current_source) ||
            strcmp(previous_interface, current.interface) ||
            previous_frequency != current.frequency_mhz ||
            current.active_ms < previous_active || current.busy_ms < previous_busy;
    free((void *)previous_interface);
    free((void *)previous_epoch);
    free((void *)previous_source);
    if (!reset && interval < AC_SURVEY_SAMPLE_MIN_SECONDS)
        return 0;
    if (reset)
        return ac_db_survey_cursor_write(ap_id, radio_id, session_epoch,
                                         observed_at, received_at, &current,
                                         current_source);
    active_delta = current.active_ms - previous_active;
    busy_delta = current.busy_ms - previous_busy;
    if (active_delta <= 0 || busy_delta < 0 || busy_delta > active_delta)
        return ac_db_survey_cursor_write(ap_id, radio_id, session_epoch,
                                         observed_at, received_at, &current,
                                         current_source);
    if (current.receive_present && previous_receive_present &&
        current.receive_ms >= previous_receive) {
        receive_delta = current.receive_ms - previous_receive;
        receive_delta_present = 1;
    }
    if (current.transmit_present && previous_transmit_present &&
        current.transmit_ms >= previous_transmit) {
        transmit_delta = current.transmit_ms - previous_transmit;
        transmit_delta_present = 1;
    }
    if (ac_db_survey_bucket_upsert(ap_id, radio_id,
            AC_SURVEY_FINE_RESOLUTION_SECONDS, received_at, active_delta,
            busy_delta, receive_delta_present, receive_delta,
            transmit_delta_present, transmit_delta, current.noise_present,
            current.noise_dbm, current_source) != 0 ||
        ac_db_survey_bucket_upsert(ap_id, radio_id,
            AC_SURVEY_HOUR_RESOLUTION_SECONDS, received_at, active_delta,
            busy_delta, receive_delta_present, receive_delta,
            transmit_delta_present, transmit_delta, current.noise_present,
            current.noise_dbm, current_source) != 0 ||
        ac_db_survey_prune_target(ap_id, radio_id,
            AC_SURVEY_FINE_RESOLUTION_SECONDS, received_at,
            AC_SURVEY_FINE_RETENTION_SECONDS,
            AC_SURVEY_FINE_RETENTION_ROWS) != 0 ||
        ac_db_survey_prune_target(ap_id, radio_id,
            AC_SURVEY_HOUR_RESOLUTION_SECONDS, received_at,
            AC_SURVEY_HOUR_RETENTION_SECONDS,
            AC_SURVEY_HOUR_RETENTION_ROWS) != 0)
        return -1;
    return ac_db_survey_cursor_write(ap_id, radio_id, session_epoch,
                                     observed_at, received_at, &current,
                                     current_source);
}

struct ac_tx_retry_counter_sample {
    const char *source;
    int64_t tx_total;
    int64_t tx_retries;
};

static int ac_db_tx_retry_parse(struct json_object *radio,
                                struct ac_tx_retry_counter_sample *sample)
{
    struct json_object *survey = NULL;
    struct json_object *air = NULL;
    struct json_object *value = NULL;
    const char *semantics;
    int result;

    if (!radio || !sample ||
        !json_object_object_get_ex(radio, "survey", &survey) || !survey ||
        !json_object_is_type(survey, json_type_object) ||
        !json_object_object_get_ex(survey, "air_stats", &air) || !air ||
        !json_object_is_type(air, json_type_object))
        return 0;
    if (json_object_object_get_ex(air, "tx_retry_available", &value) && value &&
        json_object_is_type(value, json_type_boolean) &&
        !json_object_get_boolean(value))
        return 0;
    if (!json_object_object_get_ex(air, "tx_retry_counter_semantics", &value) ||
        !value || !json_object_is_type(value, json_type_string))
        return 0;
    semantics = json_object_get_string(value);
    if (!semantics || strcmp(semantics, "cumulative"))
        return 0;
    if (ac_db_json_int64(air, "tx_total", &sample->tx_total, 1) != 1 ||
        ac_db_json_int64(air, "tx_retries", &sample->tx_retries, 1) != 1 ||
        sample->tx_total < 0 || sample->tx_retries < 0)
        return 0;
    result = 0;
    if (json_object_object_get_ex(air, "tx_retry_source", &value) && value &&
        json_object_is_type(value, json_type_string) &&
        json_object_get_string(value)[0])
        sample->source = json_object_get_string(value);
    else if (json_object_object_get_ex(air, "source", &value) && value &&
             json_object_is_type(value, json_type_string) &&
             json_object_get_string(value)[0])
        sample->source = json_object_get_string(value);
    else
        sample->source = "unknown";
    return result == 0 ? 1 : 0;
}

static int ac_db_tx_retry_cursor_write(const char *ap_id, const char *radio_id,
                                       const char *source,
                                       const char *session_epoch,
                                       int64_t observed_at, int64_t received_at,
                                       const struct ac_tx_retry_counter_sample *sample)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_radio_tx_retry_cursor(ap_id,radio_id,source,session_epoch,"
            "observed_at,received_at,tx_total,tx_retries) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) "
            "ON CONFLICT(ap_id,radio_id) DO UPDATE SET source=excluded.source,"
            "session_epoch=excluded.session_epoch,observed_at=excluded.observed_at,"
            "received_at=excluded.received_at,tx_total=excluded.tx_total,"
            "tx_retries=excluded.tx_retries", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, radio_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, source && source[0] ? source : "unknown", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, session_epoch, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 5, observed_at);
    sqlite3_bind_int64(st, 6, received_at);
    sqlite3_bind_int64(st, 7, sample->tx_total);
    sqlite3_bind_int64(st, 8, sample->tx_retries);
    if (sqlite3_step(st) == SQLITE_DONE)
        rc = 0;
    sqlite3_finalize(st);
    return rc;
}

static int ac_db_tx_retry_bucket_upsert(const char *ap_id, const char *radio_id,
                                        const char *source, int64_t received_at,
                                        int64_t total_delta, int64_t retry_delta)
{
    static const char sql[] =
        "INSERT INTO ac_radio_tx_retry_bucket(ap_id,radio_id,resolution_seconds,"
        "bucket_start,first_received_at,last_received_at,sample_count,tx_total_delta,"
        "tx_retries_delta,retry_rate_pct,source) VALUES(?1,?2,300,?3,?4,?4,1,?5,?6,"
        "CAST(?6 AS REAL)*100.0/?5,?7) ON CONFLICT(ap_id,radio_id,resolution_seconds,"
        "bucket_start) DO UPDATE SET first_received_at=MIN(first_received_at,excluded.first_received_at),"
        "last_received_at=MAX(last_received_at,excluded.last_received_at),"
        "sample_count=sample_count+1,tx_total_delta=tx_total_delta+excluded.tx_total_delta,"
        "tx_retries_delta=tx_retries_delta+excluded.tx_retries_delta,"
        "retry_rate_pct=CAST((tx_retries_delta+excluded.tx_retries_delta) AS REAL)*100.0/"
        "(tx_total_delta+excluded.tx_total_delta),source=excluded.source,complete=1";
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (total_delta <= 0 || retry_delta < 0 ||
        sqlite3_prepare_v2(g_ac_db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, radio_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, received_at - received_at % 300);
    sqlite3_bind_int64(st, 4, received_at);
    sqlite3_bind_int64(st, 5, total_delta);
    sqlite3_bind_int64(st, 6, retry_delta);
    sqlite3_bind_text(st, 7, source && source[0] ? source : "unknown", -1,
                      SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE)
        rc = 0;
    sqlite3_finalize(st);
    return rc;
}

static int ac_db_tx_retry_prune(const char *ap_id, const char *radio_id,
                                int64_t now)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (sqlite3_prepare_v2(g_ac_db,
            "DELETE FROM ac_radio_tx_retry_bucket WHERE ap_id=?1 AND radio_id=?2 "
            "AND last_received_at<?3", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, radio_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, now - AC_TX_RETRY_FINE_RETENTION_SECONDS);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "DELETE FROM ac_radio_tx_retry_bucket WHERE ap_id=?1 AND radio_id=?2 "
            "AND sample_id NOT IN (SELECT sample_id FROM ac_radio_tx_retry_bucket "
            "WHERE ap_id=?1 AND radio_id=?2 ORDER BY bucket_start DESC,sample_id DESC LIMIT ?3)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, radio_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, AC_TX_RETRY_FINE_RETENTION_ROWS);
    if (sqlite3_step(st) == SQLITE_DONE)
        rc = 0;
done:
    sqlite3_finalize(st);
    return rc;
}

static int ac_db_tx_retry_ingest(const char *ap_id, const char *radio_id,
                                 const char *session_epoch, int64_t observed_at,
                                 int64_t received_at, struct json_object *radio)
{
    struct ac_tx_retry_counter_sample current;
    sqlite3_stmt *st = NULL;
    char previous_source[128] = { 0 };
    char previous_epoch[AC_RADIO_JOB_SESSION_EPOCH_MAX + 1] = { 0 };
    int64_t previous_received = 0;
    int64_t previous_total = 0;
    int64_t previous_retries = 0;
    int have_previous = 0;
    int64_t interval;
    int64_t total_delta;
    int64_t retry_delta;

    if (ac_db_tx_retry_parse(radio, &current) != 1)
        return 0;
    if (!current.source || !current.source[0])
        return 0;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT source,session_epoch,received_at,tx_total,tx_retries FROM "
            "ac_radio_tx_retry_cursor WHERE ap_id=?1 AND radio_id=?2", -1,
            &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, radio_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *source = (const char *)sqlite3_column_text(st, 0);
        const char *epoch = (const char *)sqlite3_column_text(st, 1);

        snprintf(previous_source, sizeof(previous_source), "%s", source ? source : "");
        snprintf(previous_epoch, sizeof(previous_epoch), "%s", epoch ? epoch : "");
        previous_received = sqlite3_column_int64(st, 2);
        previous_total = sqlite3_column_int64(st, 3);
        previous_retries = sqlite3_column_int64(st, 4);
        have_previous = 1;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (!have_previous)
        return ac_db_tx_retry_cursor_write(ap_id, radio_id, current.source,
                                           session_epoch, observed_at,
                                           received_at, &current);
    interval = received_at - previous_received;
    if (interval <= 0 || interval > AC_SURVEY_SAMPLE_GAP_SECONDS ||
        strcmp(previous_epoch, session_epoch) ||
        strcmp(previous_source, current.source) ||
        current.tx_total < previous_total || current.tx_retries < previous_retries)
        return ac_db_tx_retry_cursor_write(ap_id, radio_id, current.source,
                                           session_epoch, observed_at,
                                           received_at, &current);
    if (interval < AC_SURVEY_SAMPLE_MIN_SECONDS)
        return 0;
    total_delta = current.tx_total - previous_total;
    retry_delta = current.tx_retries - previous_retries;
    if (total_delta <= 0 || retry_delta < 0)
        return ac_db_tx_retry_cursor_write(ap_id, radio_id, current.source,
                                           session_epoch, observed_at,
                                           received_at, &current);
    if (ac_db_tx_retry_bucket_upsert(ap_id, radio_id, current.source, received_at,
                                     total_delta, retry_delta) != 0 ||
        ac_db_tx_retry_prune(ap_id, radio_id, received_at) != 0)
        return -1;
    return ac_db_tx_retry_cursor_write(ap_id, radio_id, current.source,
                                       session_epoch, observed_at, received_at,
                                       &current);
}

int ac_db_ap_telemetry_store(const char *ap_id, const char *session_epoch,
                             int64_t sequence,
                             int64_t observed_at, int64_t received_at,
                             const char *snapshot_id,
                             const struct ac_device_model_report *report,
                             struct json_object *snapshot)
{
    static const char radio_sql[] =
        "INSERT INTO ac_radio_runtime(radio_id,ap_id,observed_at,runtime_json,stale) "
        "VALUES(?1,?2,?4,?5,0)";
    static const char ssid_sql[] =
        "INSERT INTO ac_ssid_runtime(ssid_id,ap_id,radio_id,observed_at,runtime_json,stale) "
        "VALUES(?1,?2,?3,?4,?5,0)";
    struct json_object *radios = NULL;
    struct json_object *ssids = NULL;
    struct json_object *stations = NULL;
    sqlite3_stmt *st = NULL;
    const char *runtime;
    size_t i;
    int rc = -1;
    int epoch_current = 0;
    int64_t previous_observed_at = 0;
    int64_t previous_sequence = -1;
    char previous_snapshot_id[72] = {0};
    struct json_object *previous_snapshot = NULL;

    if (!g_ac_db || !ac_uuid_valid(ap_id) ||
        !ac_db_session_epoch_valid(session_epoch) || sequence < 0 || observed_at <= 0 ||
        received_at <= 0 || !snapshot_id || !snapshot_id[0] ||
        !ac_db_model_report_valid(report) || !snapshot ||
        !json_object_is_type(snapshot, json_type_object) ||
        !json_object_object_get_ex(snapshot, "radios", &radios) ||
        !json_object_object_get_ex(snapshot, "ssids", &ssids) ||
        !json_object_object_get_ex(snapshot, "stations", &stations) ||
        !json_object_is_type(radios, json_type_array) ||
        !json_object_is_type(ssids, json_type_array) ||
        !json_object_is_type(stations, json_type_array) ||
        !(runtime = json_object_to_json_string_ext(snapshot,
                                                   JSON_C_TO_STRING_PLAIN)))
        return ac_db_telemetry_error("validate");
    if (ac_exec("BEGIN IMMEDIATE") != 0)
        return ac_db_telemetry_error("begin");
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT observed_at,snapshot_id,telemetry_sequence,runtime_json "
            "FROM ac_ap_runtime "
            "WHERE ap_id=?1 AND boot_id=?2", -1, &st, NULL) != SQLITE_OK) {
        ac_db_telemetry_error("read_previous_prepare");
        goto rollback;
    }
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, session_epoch, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *stored_id = sqlite3_column_text(st, 1);
        const unsigned char *stored_runtime = sqlite3_column_text(st, 3);

        epoch_current = 1;
        previous_observed_at = sqlite3_column_int64(st, 0);
        previous_sequence = sqlite3_column_int64(st, 2);
        if (stored_id)
            snprintf(previous_snapshot_id, sizeof(previous_snapshot_id), "%s",
                     stored_id);
        if (stored_runtime && stored_runtime[0]) {
            previous_snapshot = json_tokener_parse(
                (const char *)stored_runtime);
            if (previous_snapshot &&
                !json_object_is_type(previous_snapshot, json_type_object)) {
                json_object_put(previous_snapshot);
                previous_snapshot = NULL;
            }
        }
    }
    sqlite3_finalize(st);
    st = NULL;
    if (!epoch_current) {
        ac_db_telemetry_error("epoch_not_current");
        goto rollback;
    }
    if (previous_observed_at == observed_at && previous_sequence == sequence &&
        strcmp(previous_snapshot_id, snapshot_id) == 0) {
        json_object_put(previous_snapshot);
        if (ac_exec("COMMIT") == 0)
            return 0;
        return ac_db_telemetry_error("duplicate_commit");
    }
    if (previous_sequence >= 0 &&
        (observed_at <= previous_observed_at || sequence <= previous_sequence)) {
        ac_db_telemetry_error("ordering");
        goto rollback;
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_aps SET last_seen_at=MAX(last_seen_at,?1),"
            "reported_model=?2,board_name=?3,model_source=?4,model_available=?5,"
            "model_reason=?6 WHERE ap_id=?7 AND adoption_state='adopted'",
            -1, &st, NULL) != SQLITE_OK) {
        ac_db_telemetry_error("ap_identity_prepare");
        goto rollback;
    }
    sqlite3_bind_int64(st, 1, received_at);
    sqlite3_bind_text(st, 2, report->model, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, report->board_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, report->model_source, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 5, report->model_available);
    sqlite3_bind_text(st, 6, report->reason, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1) {
        ac_db_telemetry_error("ap_identity_write");
        goto rollback;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_ap_runtime(ap_id,boot_id,observed_at,received_at,snapshot_id,runtime_json,stale,telemetry_sequence) "
            "VALUES(?1,?2,?3,?4,?5,?6,0,?7) ON CONFLICT(ap_id) DO UPDATE SET "
            "observed_at=excluded.observed_at,received_at=excluded.received_at,"
            "snapshot_id=excluded.snapshot_id,runtime_json=excluded.runtime_json,"
            "stale=0,telemetry_sequence=excluded.telemetry_sequence "
            "WHERE ac_ap_runtime.boot_id=excluded.boot_id",
            -1, &st, NULL) != SQLITE_OK) {
        ac_db_telemetry_error("ap_runtime_prepare");
        goto rollback;
    }
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, session_epoch, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, observed_at);
    sqlite3_bind_int64(st, 4, received_at);
    sqlite3_bind_text(st, 5, snapshot_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, runtime, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 7, sequence);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1) {
        ac_db_telemetry_error("ap_runtime_write");
        goto rollback;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "DELETE FROM ac_radio_runtime WHERE ap_id=?1;",
            -1, &st, NULL) != SQLITE_OK) {
        ac_db_telemetry_error("radio_delete_prepare");
        goto rollback;
    }
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        ac_db_telemetry_error("radio_delete");
        goto rollback;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "DELETE FROM ac_ssid_runtime WHERE ap_id=?1;",
            -1, &st, NULL) != SQLITE_OK) {
        ac_db_telemetry_error("ssid_delete_prepare");
        goto rollback;
    }
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        ac_db_telemetry_error("ssid_delete");
        goto rollback;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "DELETE FROM ac_station_sessions WHERE ap_id=?1;",
            -1, &st, NULL) != SQLITE_OK) {
        ac_db_telemetry_error("station_delete_prepare");
        goto rollback;
    }
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        ac_db_telemetry_error("station_delete");
        goto rollback;
    }
    sqlite3_finalize(st);
    st = NULL;
    for (i = 0; i < json_object_array_length(radios); i++) {
        struct json_object *item = json_object_array_get_idx(radios, i);
        const char *id = ac_db_json_string(item, "id");
        if (!id || ac_db_survey_ingest(ap_id, id, session_epoch, observed_at,
                                       received_at, item) != 0 ||
            ac_db_tx_retry_ingest(ap_id, id, session_epoch, observed_at,
                                  received_at, item) != 0 ||
            ac_db_runtime_item_store(radio_sql, id, ap_id, "",
                                            observed_at, item) != 0) {
            ac_db_telemetry_error("radio_write");
            goto rollback;
        }
    }
    for (i = 0; i < json_object_array_length(ssids); i++) {
        struct json_object *item = json_object_array_get_idx(ssids, i);
        const char *id = ac_db_json_string(item, "id");
        const char *radio_id = ac_db_json_string(item, "radio_id");
        if (!id || ac_db_runtime_item_store(ssid_sql, id, ap_id,
                                            radio_id ? radio_id : "",
                                            observed_at, item) != 0) {
            ac_db_telemetry_error("ssid_write");
            goto rollback;
        }
    }
    for (i = 0; i < json_object_array_length(stations); i++) {
        struct json_object *item = json_object_array_get_idx(stations, i);
        const char *mac = ac_db_json_string(item, "mac");
        const char *interface = ac_db_json_string(item, "interface");
        const char *ssid_id;
        const char *radio_id;
        char association_id[160];
        char managed_ssid[37];
        const char *item_json;
        int64_t connected_at = observed_at;
        struct json_object *connected = NULL;

        if (!mac || !interface ||
            snprintf(association_id, sizeof(association_id), "%s/%s/%s",
                     ap_id, mac, interface) >= (int)sizeof(association_id) ||
            !(item_json = json_object_to_json_string_ext(
                item, JSON_C_TO_STRING_PLAIN))) {
            ac_db_telemetry_error("station_validate");
            goto rollback;
        }
        radio_id = ac_db_station_radio(ssids, interface, &ssid_id);
        if (ac_db_station_managed_ssid(ap_id, radio_id, ssids, interface,
                                       managed_ssid) < 0)
            goto rollback;
        if (managed_ssid[0])
            ssid_id = managed_ssid;
        if (json_object_object_get_ex(item, "connected_time_seconds", &connected) &&
            connected && json_object_is_type(connected, json_type_int) &&
            json_object_get_int64(connected) >= 0 &&
            json_object_get_int64(connected) <= observed_at)
            connected_at = observed_at - json_object_get_int64(connected);
        if (sqlite3_prepare_v2(g_ac_db,
                "INSERT INTO ac_station_sessions(association_id,ap_id,radio_id,ssid_id,mac,"
                "connected_at,disconnected_at,last_seen_at,runtime_json) "
                "VALUES(?1,?2,?3,?4,?5,?6,0,?7,?8)",
                -1, &st, NULL) != SQLITE_OK) {
            ac_db_telemetry_error("station_prepare");
            goto rollback;
        }
        sqlite3_bind_text(st, 1, association_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, ap_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, radio_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, ssid_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, mac, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 6, connected_at);
        sqlite3_bind_int64(st, 7, observed_at);
        sqlite3_bind_text(st, 8, item_json, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE) {
            ac_db_telemetry_error("station_write");
            goto rollback;
        }
        sqlite3_finalize(st);
        st = NULL;
    }
    if (ac_client_history_ingest(g_ac_db, ap_id, session_epoch,
                                 observed_at, received_at, snapshot) != 0) {
        ac_db_telemetry_error("client_history");
        goto rollback;
    }
    if (previous_sequence >= 0 &&
        ac_db_ap_traffic_ingest(ap_id, previous_snapshot, snapshot,
                                previous_observed_at, observed_at,
                                received_at) != 0) {
        ac_db_telemetry_error("ap_traffic");
        goto rollback;
    }
    if (previous_sequence >= 0 &&
        ac_db_station_events_ingest(ap_id, previous_snapshot, snapshot,
                                    previous_observed_at, observed_at,
                                    received_at) != 0) {
        ac_db_telemetry_error("station_events");
        goto rollback;
    }
    if (ac_db_auth_failures_ingest(ap_id, snapshot, observed_at,
                                   received_at) != 0) {
        ac_db_telemetry_error("auth_failures");
        goto rollback;
    }
    json_object_put(previous_snapshot);
    previous_snapshot = NULL;
    if (ac_exec("COMMIT") != 0) {
        ac_db_telemetry_error("commit");
        goto rollback_after_commit;
    }
    return 0;

rollback:
    sqlite3_finalize(st);
rollback_after_commit:
    json_object_put(previous_snapshot);
    ac_exec("ROLLBACK");
    return rc;
}

#if !defined(AC_DB_TEST_STANDALONE) || defined(AC_DB_TELEMETRY_TEST_STANDALONE)
/*
 * Per-AP capability block for aps_list.  This is the surface a caller reads to
 * pick a target, so it must be gated on *this* AP's session rather than mirror
 * the controller-wide answer in ac_capabilities_json(): with two APs online and
 * one write-capable, the global bit is true for both and would send a write at
 * the AP that cannot take it.
 *
 * `wifi_write` is computed by the caller from the same three columns the write
 * dispatcher checks (session_connected, control_protocol_version == 3,
 * write_capable), so a capability reported here cannot disagree with what
 * ac_db_wifi_transaction_apply() will accept.
 */
static int ac_db_secret_rotation_available(const char *ap_id)
{
#ifdef AC_DB_TEST_STANDALONE
    (void)ap_id;
    return 0;
#else
    return ac_secret_rotation_ap_available(ap_id);
#endif
}

static struct json_object *ac_db_ap_capabilities(const char *ap_id,
                                                 int scan_execution,
                                                 int wifi_write)
{
    struct json_object *value = json_object_new_object();

    json_object_object_add(value, "remote_telemetry", json_object_new_boolean(1));
    json_object_object_add(value, "scan_dispatch",
                           json_object_new_boolean(scan_execution));
    json_object_object_add(value, "scan_execution",
                           json_object_new_boolean(scan_execution));
    json_object_object_add(value, "ssid_create", json_object_new_boolean(wifi_write));
    json_object_object_add(value, "ssid_update", json_object_new_boolean(wifi_write));
    json_object_object_add(value, "ssid_delete", json_object_new_boolean(wifi_write));
    json_object_object_add(value, "ssid_secret_apply", json_object_new_boolean(
        ac_db_secret_rotation_available(ap_id)));
    json_object_object_add(value, "password_rotation", json_object_new_boolean(
        ac_db_secret_rotation_available(ap_id)));
    json_object_object_add(value, "radio_update", json_object_new_boolean(wifi_write));
    json_object_object_add(value, "ap_actions", json_object_new_boolean(wifi_write));
    return value;
}

/*
 * Is this AP already adopted inventory?
 *
 * Discovery uses this to keep an adopted AP out of the candidate list. The
 * authority is ac_aps.adoption_state, which every other adoption-gated query in
 * this file tests the same way ('adopted' vs the 'pending_pairing' default), and
 * which the adoption transition flips at the same time it stamps
 * ac_enrollments.adopted_at. Reading ac_aps rather than the enrollment row keeps
 * one source of truth: an enrollment can be claimed or mtls_pending while the AP
 * is not yet adopted, and a re-enrolment leaves historical enrollment rows behind.
 *
 * Returns 1 only on a definite adopted row. An unopened database, an invalid
 * ap_id, or a failed query returns 0, which for the caller means "treat as a
 * candidate": that direction shows a duplicate in a read-only list, whereas the
 * opposite default would silently hide a real AP from discovery.
 */
int ac_db_ap_is_adopted(const char *ap_id)
{
    sqlite3_stmt *st = NULL;
    int adopted = 0;

    if (!g_ac_db || !ac_uuid_valid(ap_id) ||
        sqlite3_prepare_v2(g_ac_db,
            "SELECT 1 FROM ac_aps WHERE ap_id=?1 "
            "AND adoption_state='adopted' LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    adopted = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return adopted;
}

struct json_object *ac_db_aps_list_json(int64_t observed_at,
                                        int64_t online_since)
{
    struct json_object *root = json_object_new_object();
    struct json_object *items = json_object_new_array();
    sqlite3_stmt *st = NULL;
    int count = 0;
    int online_count = 0;

    if (!g_ac_db || observed_at <= 0 || online_since <= 0 ||
        sqlite3_prepare_v2(g_ac_db,
            "SELECT a.ap_id,a.site_id,a.name,a.adoption_state,a.last_seen_at,"
            "a.reported_model,a.board_name,a.model_source,a.model_available,a.model_reason,"
            "a.model_override,r.observed_at,r.received_at,COALESCE(r.snapshot_id,''),r.runtime_json,r.stale,"
            "COALESCE(r.control_protocol_version,0),COALESCE(r.session_connected,0),"
            "COALESCE(r.write_capable,0) "
            "FROM ac_aps a LEFT JOIN ac_ap_runtime r ON r.ap_id=a.ap_id "
            "WHERE a.adoption_state='adopted' ORDER BY a.ap_id",
            -1, &st, NULL) != SQLITE_OK)
        goto fail;
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *item = json_object_new_object();
        struct json_object *runtime = json_object_new_object();
        struct json_object *snapshot = NULL;
        const char *reported = (const char *)sqlite3_column_text(st, 5);
        const char *override = (const char *)sqlite3_column_text(st, 10);
        const char *runtime_json = (const char *)sqlite3_column_text(st, 14);
        int64_t last_seen = sqlite3_column_int64(st, 4);
        int64_t runtime_observed = sqlite3_column_int64(st, 11);
        int64_t runtime_received = sqlite3_column_int64(st, 12);
        int runtime_available = runtime_json && runtime_observed > 0 &&
                                runtime_received > 0 &&
                                sqlite3_column_type(st, 14) != SQLITE_NULL;
        int online = last_seen >= online_since;
        int protocol_version = sqlite3_column_int(st, 16);
        int session_connected = sqlite3_column_int(st, 17) != 0;
        int write_capable = sqlite3_column_int(st, 18) != 0;
        /*
         * `>= 2`, not `== 2`: the two predicates that actually decide a scan
         * dispatch (ac_db_survey_schedule_due_radios and
         * ac_db_scan_execution_available) both accept >= 2, so pinning this to
         * exactly 2 reported scan_execution:false for a v3 AP the dispatcher
         * would happily have used.
         */
        int scan_execution = online && session_connected && protocol_version >= 2;
        /*
         * Exactly the write dispatcher's condition (ac_radio_job_session_current
         * and ac_db_wifi_write_execution_available): v3 *and* write_capable.
         * Written as == 3 rather than >= 3 on purpose -- a future v4 must change
         * the dispatcher and this together, and >= would claim the capability
         * before the dispatcher would honour it.
         */
        int wifi_write = online && session_connected &&
                         protocol_version == 3 && write_capable;
        int stale = !online || !runtime_available || sqlite3_column_int(st, 15) != 0 ||
                    runtime_received < observed_at - AC_TELEMETRY_STALE_TIMEOUT_SECONDS;
        int complete = 0;
        const char *reason = runtime_available ? NULL : "telemetry_not_received";
        struct json_object *value = NULL;

        if (runtime_available) {
            snapshot = json_tokener_parse(runtime_json);
            if (!snapshot || !json_object_is_type(snapshot, json_type_object)) {
                json_object_put(snapshot);
                snapshot = NULL;
                runtime_available = 0;
                stale = 1;
                reason = "telemetry_snapshot_invalid";
            }
        }
        if (snapshot && json_object_object_get_ex(snapshot, "complete", &value) &&
            value && json_object_is_type(value, json_type_boolean))
            complete = json_object_get_boolean(value);
        if (runtime_available && stale)
            reason = "telemetry_stale";
        else if (runtime_available && snapshot &&
                 json_object_object_get_ex(snapshot, "reason", &value) && value &&
                 json_object_is_type(value, json_type_string))
            reason = json_object_get_string(value);

#define AC_DB_ADD_TEXT(name_, column_) \
        json_object_object_add(item, (name_), json_object_new_string( \
            (const char *)sqlite3_column_text(st, (column_))))
        AC_DB_ADD_TEXT("ap_id", 0);
        AC_DB_ADD_TEXT("site_id", 1);
        AC_DB_ADD_TEXT("name", 2);
        AC_DB_ADD_TEXT("adoption_state", 3);
#undef AC_DB_ADD_TEXT
        json_object_object_add(item, "online", json_object_new_boolean(online));
        json_object_object_add(item, "stale", json_object_new_boolean(stale));
        json_object_object_add(item, "last_seen_at", json_object_new_int64(last_seen));
        json_object_object_add(item, "capabilities",
                               ac_db_ap_capabilities(
                                   (const char *)sqlite3_column_text(st, 0),
                                   scan_execution, wifi_write));
        json_object_object_add(item, "control_protocol_version",
                               json_object_new_int(protocol_version));
        json_object_object_add(item, "control_protocol", json_object_new_string(
            protocol_version == 3 ? "ap-control.v3" :
            protocol_version == 2 ? "ap-control.v2" :
            protocol_version == 1 ? "ap-control.v1" : ""));
        json_object_object_add(item, "session_connected",
                               json_object_new_boolean(session_connected));
        json_object_object_add(item, "write_capable",
                               json_object_new_boolean(write_capable));
        json_object_object_add(item, "wifi_write_execution",
                               json_object_new_boolean(wifi_write));
        json_object_object_add(item, "scan_execution",
                               json_object_new_boolean(scan_execution));
        json_object_object_add(item, "reported_model",
                               json_object_new_string(reported ? reported : ""));
        json_object_object_add(item, "model_override",
                               json_object_new_string(override ? override : ""));
        /* True now that ac_db_ap_update() provides a write path. The override
         * is controller-side inventory metadata, so it does not depend on the
         * transactional apply work that gates the AP-facing capabilities. */
        json_object_object_add(item, "override_supported",
                               json_object_new_boolean(1));
        json_object_object_add(item, "model", json_object_new_string(
            override && override[0] ? override : (reported ? reported : "")));
        json_object_object_add(item, "board_name", json_object_new_string(
            (const char *)sqlite3_column_text(st, 6)));
        json_object_object_add(item, "model_source", json_object_new_string(
            (const char *)sqlite3_column_text(st, 7)));
        json_object_object_add(item, "model_available",
                               json_object_new_boolean(sqlite3_column_int(st, 8)));
        json_object_object_add(item, "model_reason", json_object_new_string(
            (const char *)sqlite3_column_text(st, 9)));
        json_object_object_add(runtime, "available",
                               json_object_new_boolean(runtime_available));
        json_object_object_add(runtime, "complete", json_object_new_boolean(complete));
        json_object_object_add(runtime, "stale", json_object_new_boolean(stale));
        json_object_object_add(runtime, "reason", reason ?
                               json_object_new_string(reason) : json_object_new_null());
        json_object_object_add(runtime, "observed_at",
                               json_object_new_int64(runtime_observed));
        json_object_object_add(runtime, "received_at",
                               json_object_new_int64(runtime_received));
        json_object_object_add(runtime, "snapshot_id", json_object_new_string(
            (const char *)sqlite3_column_text(st, 13)));
        json_object_object_add(runtime, "snapshot", snapshot ? snapshot :
                               json_object_new_null());
        json_object_object_add(item, "runtime", runtime);
        json_object_array_add(items, item);
        count++;
        online_count += online;
    }
    sqlite3_finalize(st);
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "contract_version",
                           json_object_new_string(AC_CONTRACT_VERSION));
    json_object_object_add(root, "observed_at", json_object_new_int64(observed_at));
    json_object_object_add(root, "items", items);
    json_object_object_add(root, "count", json_object_new_int(count));
    json_object_object_add(root, "online", json_object_new_int(online_count));
    return root;
fail:
    sqlite3_finalize(st);
    json_object_put(items);
    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "contract_version",
                           json_object_new_string(AC_CONTRACT_VERSION));
    json_object_object_add(root, "observed_at", json_object_new_int64(observed_at));
    json_object_object_add(root, "items", json_object_new_array());
    json_object_object_add(root, "count", json_object_new_int(0));
    json_object_object_add(root, "online", json_object_new_int(0));
    return root;
}
#endif
#endif

static int ac_uuid_valid(const char *value)
{
    static const int hyphen[] = {8, 13, 18, 23};
    size_t i;
    int h = 0;

    if (!value || strlen(value) != AC_PAIRING_TOKEN_ID_LEN || value[14] != '4' ||
        (value[19] != '8' && value[19] != '9' && value[19] != 'a' && value[19] != 'b'))
        return 0;
    for (i = 0; i < AC_PAIRING_TOKEN_ID_LEN; i++) {
        if (h < 4 && (int)i == hyphen[h]) {
            if (value[i] != '-')
                return 0;
            h++;
        } else if (!((value[i] >= '0' && value[i] <= '9') ||
                     (value[i] >= 'a' && value[i] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static int ac_generate_uuid(char out[AC_PAIRING_TOKEN_ID_LEN + 1])
{
    unsigned char raw[16];

    if (RAND_bytes(raw, sizeof(raw)) != 1)
        return -1;
    raw[6] = (raw[6] & 0x0f) | 0x40;
    raw[8] = (raw[8] & 0x3f) | 0x80;
    snprintf(out, AC_PAIRING_TOKEN_ID_LEN + 1,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
             raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]);
    OPENSSL_cleanse(raw, sizeof(raw));
    return 0;
}

static int ac_generate_token(char out[AC_PAIRING_TOKEN_LEN + 1])
{
    unsigned char raw[32];
    unsigned char encoded[48];
    int encoded_len;
    int i;

    memset(encoded, 0, sizeof(encoded));
    if (RAND_bytes(raw, sizeof(raw)) != 1)
        return -1;
    encoded_len = EVP_EncodeBlock(encoded, raw, sizeof(raw));
    OPENSSL_cleanse(raw, sizeof(raw));
    if (encoded_len != 44 || encoded[43] != '=') {
        OPENSSL_cleanse(encoded, sizeof(encoded));
        return -1;
    }
    for (i = 0; i < AC_PAIRING_TOKEN_LEN; i++) {
        if (encoded[i] == '+')
            encoded[i] = '-';
        else if (encoded[i] == '/')
            encoded[i] = '_';
        out[i] = (char)encoded[i];
    }
    out[AC_PAIRING_TOKEN_LEN] = '\0';
    OPENSSL_cleanse(encoded, sizeof(encoded));
    return 0;
}

static int ac_site_id_normalize(const char *input,
                                char out[AC_PAIRING_SITE_ID_LEN + 1])
{
    size_t i;
    size_t len = input ? strlen(input) : 0;

    if (len > AC_PAIRING_SITE_ID_LEN)
        return -1;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)input[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' ||
              c == ':' || c == '-'))
            return -1;
    }
    memcpy(out, input ? input : "", len);
    out[len] = '\0';
    return 0;
}

static int ac_hardware_digest_normalize(
    const char *input, char out[AC_PAIRING_HARDWARE_DIGEST_LEN + 1])
{
    const char *hex = input;
    size_t len = input ? strlen(input) : 0;
    size_t i;

    if (len == 0) {
        out[0] = '\0';
        return 0;
    }
    if (len == AC_PAIRING_HARDWARE_DIGEST_LEN && strncmp(input, "sha256:", 7) == 0)
        hex = input + 7;
    else if (len != 64)
        return -1;
    memcpy(out, "sha256:", 7);
    for (i = 0; i < 64; i++) {
        char c = hex[i];
        if (c >= 'A' && c <= 'F')
            c = (char)(c - 'A' + 'a');
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return -1;
        out[7 + i] = c;
    }
    out[AC_PAIRING_HARDWARE_DIGEST_LEN] = '\0';
    return 0;
}

static int ac_token_valid(const char *token)
{
    size_t i;

    if (!token || strlen(token) != AC_PAIRING_TOKEN_LEN)
        return 0;
    for (i = 0; i < AC_PAIRING_TOKEN_LEN; i++) {
        unsigned char c = (unsigned char)token[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_'))
            return 0;
    }
    return 1;
}

static void ac_u32be(unsigned char out[4], uint32_t value)
{
    out[0] = (unsigned char)(value >> 24);
    out[1] = (unsigned char)(value >> 16);
    out[2] = (unsigned char)(value >> 8);
    out[3] = (unsigned char)value;
}

static void ac_u64be(unsigned char out[8], uint64_t value)
{
    size_t i;
    for (i = 0; i < 8; i++)
        out[7 - i] = (unsigned char)(value >> (i * 8));
}

static int ac_token_digest(const char *token_id, const char *token,
                           int64_t expires_at, int max_attempts,
                           const char *site_id, const char *hardware_digest,
                           unsigned char out[AC_PAIRING_DIGEST_LEN])
{
    EVP_MD_CTX *ctx = NULL;
    unsigned char expires[8];
    unsigned char attempts[4];
    unsigned char lengths[4];
    unsigned int out_len = 0;
    size_t site_len = strlen(site_id);
    size_t hardware_len = strlen(hardware_digest);
    int rc = -1;

    ac_u64be(expires, (uint64_t)expires_at);
    ac_u32be(attempts, (uint32_t)max_attempts);
    ac_u32be(lengths, (uint32_t)site_len);
    ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, AC_PAIRING_DOMAIN, sizeof(AC_PAIRING_DOMAIN)) != 1 ||
        EVP_DigestUpdate(ctx, token_id, strlen(token_id)) != 1 ||
        EVP_DigestUpdate(ctx, expires, sizeof(expires)) != 1 ||
        EVP_DigestUpdate(ctx, attempts, sizeof(attempts)) != 1 ||
        EVP_DigestUpdate(ctx, lengths, sizeof(lengths)) != 1 ||
        EVP_DigestUpdate(ctx, site_id, site_len) != 1)
        goto done;
    ac_u32be(lengths, (uint32_t)hardware_len);
    if (EVP_DigestUpdate(ctx, lengths, sizeof(lengths)) != 1 ||
        EVP_DigestUpdate(ctx, hardware_digest, hardware_len) != 1 ||
        EVP_DigestUpdate(ctx, token, strlen(token)) != 1 ||
        EVP_DigestFinal_ex(ctx, out, &out_len) != 1 ||
        out_len != AC_PAIRING_DIGEST_LEN)
        goto done;
    rc = 0;
done:
    OPENSSL_cleanse(expires, sizeof(expires));
    OPENSSL_cleanse(attempts, sizeof(attempts));
    OPENSSL_cleanse(lengths, sizeof(lengths));
    EVP_MD_CTX_free(ctx);
    return rc;
}

static void ac_status_state(struct ac_pairing_token_status *status, int64_t now)
{
    const char *state = "active";

    if (status->revoked_at > 0)
        state = "revoked";
    else if (status->consumed_at > 0)
        state = "consumed";
    else if (status->claimed_at > 0)
        state = "claimed";
    else if (status->expires_at <= now)
        state = "expired";
    else if (status->attempts >= status->max_attempts)
        state = "exhausted";
    snprintf(status->state, sizeof(status->state), "%s", state);
}

static int ac_status_from_stmt(sqlite3_stmt *st,
                               struct ac_pairing_token_status *out)
{
    const unsigned char *token_id = sqlite3_column_text(st, 0);
    const unsigned char *site_id = sqlite3_column_text(st, 1);
    const unsigned char *hardware_digest = sqlite3_column_text(st, 2);

    if (!out || !token_id || !site_id || !hardware_digest ||
        !ac_uuid_valid((const char *)token_id) ||
        strlen((const char *)site_id) > AC_PAIRING_SITE_ID_LEN ||
        (hardware_digest[0] &&
         strlen((const char *)hardware_digest) != AC_PAIRING_HARDWARE_DIGEST_LEN))
        return -1;
    memset(out, 0, sizeof(*out));
    snprintf(out->token_id, sizeof(out->token_id), "%s", token_id);
    snprintf(out->site_id, sizeof(out->site_id), "%s", site_id);
    out->hardware_bound = hardware_digest[0] != '\0';
    out->attempts = sqlite3_column_int(st, 3);
    out->max_attempts = sqlite3_column_int(st, 4);
    out->created_at = sqlite3_column_int64(st, 5);
    out->expires_at = sqlite3_column_int64(st, 6);
    out->consumed_at = sqlite3_column_int64(st, 7);
    out->revoked_at = sqlite3_column_int64(st, 8);
    out->claimed_at = sqlite3_column_int64(st, 9);
    if (out->attempts < 0 || out->max_attempts < 1 ||
        out->max_attempts > AC_PAIRING_TOKEN_ATTEMPTS_MAX)
        return -1;
    ac_status_state(out, ac_now_s());
    return 0;
}

static const char ac_status_select[] =
    "SELECT token_id,site_id,hardware_digest,attempts,max_attempts,created_at,"
    "expires_at,consumed_at,revoked_at,claimed_at FROM ac_pairing_tokens";

int ac_db_pairing_token_create(int64_t ttl_seconds, int max_attempts,
                               const char *site_id,
                               const char *hardware_digest,
                               struct ac_pairing_token_secret *out)
{
    sqlite3_stmt *st = NULL;
    char normalized_site[AC_PAIRING_SITE_ID_LEN + 1];
    char normalized_hardware[AC_PAIRING_HARDWARE_DIGEST_LEN + 1];
    unsigned char digest[AC_PAIRING_DIGEST_LEN];
    int rc = -1;

    if (!g_ac_db || !out || ttl_seconds < AC_PAIRING_TOKEN_TTL_MIN ||
        ttl_seconds > AC_PAIRING_TOKEN_TTL_MAX || max_attempts < 1 ||
        max_attempts > AC_PAIRING_TOKEN_ATTEMPTS_MAX ||
        ac_site_id_normalize(site_id, normalized_site) != 0 ||
        ac_hardware_digest_normalize(hardware_digest, normalized_hardware) != 0)
        return -1;
    memset(out, 0, sizeof(*out));
    if (ac_generate_uuid(out->token_id) != 0 || ac_generate_token(out->token) != 0)
        goto done;
    out->created_at = ac_now_s();
    out->expires_at = out->created_at + ttl_seconds;
    out->max_attempts = max_attempts;
    if (ac_token_digest(out->token_id, out->token, out->expires_at,
                        max_attempts, normalized_site, normalized_hardware,
                        digest) != 0 || ac_exec("BEGIN IMMEDIATE") != 0)
        goto done;
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_pairing_tokens(token_id,token_hash,digest_version,created_at,"
            "expires_at,max_attempts,attempts,consumed_at,revoked_at,site_id,hardware_digest,scope_json) "
            "VALUES(?1,?2,?3,?4,?5,?6,0,0,0,?7,?8,'{}')",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, out->token_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, digest, sizeof(digest), SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, AC_PAIRING_DIGEST_VERSION);
    sqlite3_bind_int64(st, 4, out->created_at);
    sqlite3_bind_int64(st, 5, out->expires_at);
    sqlite3_bind_int(st, 6, max_attempts);
    sqlite3_bind_text(st, 7, normalized_site, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, normalized_hardware, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (ac_exec("COMMIT") != 0)
        goto rollback;
    rc = 0;
    goto done;
rollback:
    sqlite3_finalize(st);
    st = NULL;
    ac_exec("ROLLBACK");
done:
    sqlite3_finalize(st);
    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_cleanse(normalized_hardware, sizeof(normalized_hardware));
    if (rc != 0)
        OPENSSL_cleanse(out, sizeof(*out));
    return rc;
}

int ac_db_pairing_token_status(const char *token_id,
                               struct ac_pairing_token_status *out)
{
    sqlite3_stmt *st = NULL;
    char sql[384];
    int rc = -1;

    if (!g_ac_db || !ac_uuid_valid(token_id) || !out ||
        snprintf(sql, sizeof(sql), "%s WHERE token_id=?1", ac_status_select) >=
            (int)sizeof(sql) ||
        sqlite3_prepare_v2(g_ac_db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, token_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        rc = ac_status_from_stmt(st, out);
    sqlite3_finalize(st);
    return rc;
}

int ac_db_pairing_token_list(ac_pairing_token_visit_fn visit, void *opaque)
{
    sqlite3_stmt *st = NULL;
    struct ac_pairing_token_status status;
    char sql[384];
    int rows = 0;

    if (!g_ac_db || !visit ||
        snprintf(sql, sizeof(sql), "%s ORDER BY created_at DESC,token_id", ac_status_select) >=
            (int)sizeof(sql) ||
        sqlite3_prepare_v2(g_ac_db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    while (sqlite3_step(st) == SQLITE_ROW) {
        if (ac_status_from_stmt(st, &status) != 0 || visit(&status, opaque) != 0) {
            sqlite3_finalize(st);
            return -1;
        }
        rows++;
    }
    sqlite3_finalize(st);
    return rows;
}

/*
 * Operator-supplied AP label. Rejects control characters and enforces a length
 * bound; the value is inventory metadata only and is never handed to a shell or
 * pushed to the AP.
 */
int ac_db_ap_label_valid(const char *value)
{
    size_t len;

    if (!value)
        return 0;
    len = strlen(value);
    if (len > 64)
        return 0;
    for (; *value; value++)
        if ((unsigned char)*value < 0x20 || (unsigned char)*value == 0x7f)
            return 0;
    return 1;
}

/*
 * Updates the mutable inventory fields of an adopted AP. Both fields live only
 * in the controller database: renaming does not require a session with the AP,
 * which is why this is available while the transactional apply capabilities
 * remain closed. Passing NULL leaves a field untouched.
 *
 * Returns 0 on success, AC_AP_UPDATE_INVALID for a rejected argument,
 * AC_AP_UPDATE_NOT_FOUND when no adopted AP carries that ap_id, and
 * AC_AP_UPDATE_DB_ERROR for a store failure, so the caller can map each to a
 * distinct HTTP status instead of one opaque 400.
 */
int ac_db_ap_update(const char *ap_id, const char *name,
                    const char *model_override)
{
    sqlite3_stmt *st = NULL;
    int rc = AC_AP_UPDATE_DB_ERROR;

    if (!g_ac_db || !ac_uuid_valid(ap_id))
        return AC_AP_UPDATE_INVALID;
    if (!name && !model_override)
        return AC_AP_UPDATE_INVALID;
    if (name && !ac_db_ap_label_valid(name))
        return AC_AP_UPDATE_INVALID;
    if (model_override && !ac_db_ap_label_valid(model_override))
        return AC_AP_UPDATE_INVALID;
    if (ac_exec("BEGIN IMMEDIATE") != 0)
        return AC_AP_UPDATE_DB_ERROR;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_aps SET "
            "name=CASE WHEN ?2 IS NULL THEN name ELSE ?2 END,"
            "model_override=CASE WHEN ?3 IS NULL THEN model_override ELSE ?3 END "
            "WHERE ap_id=?1 AND adoption_state='adopted'",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    if (name)
        sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(st, 2);
    if (model_override)
        sqlite3_bind_text(st, 3, model_override, -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(st, 3);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    /* SQLite counts rows matched by the UPDATE, not rows whose stored value
     * differed, so a rename to the identical name still reports one change.
     * Zero changes therefore means no adopted AP carries this ap_id. */
    if (sqlite3_changes(g_ac_db) != 1) {
        rc = AC_AP_UPDATE_NOT_FOUND;
        goto done;
    }
    rc = 0;
done:
    if (st)
        sqlite3_finalize(st);
    ac_exec(rc == 0 ? "COMMIT" : "ROLLBACK");
    return rc;
}

/* Phase 1 roaming-domain persistence and preflight implementation belongs
 * here, adjacent to the other controller-owned inventory mutations. Active
 * station steering remains deliberately out of scope. */

static int ac_roaming_domain_text_valid(const char *value, size_t max_len,
                                        int allow_empty)
{
    size_t length;

    if (!value)
        return 0;
    length = strlen(value);
    if ((!allow_empty && length == 0) || length > max_len)
        return 0;
    for (; *value; value++)
        if ((unsigned char)*value < 0x20 || (unsigned char)*value == 0x7f)
            return 0;
    return 1;
}

static int ac_roaming_domain_hex_valid(const char *value, size_t length)
{
    size_t i;

    if (!value || strlen(value) != length)
        return 0;
    for (i = 0; i < length; i++)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f') ||
              (value[i] >= 'A' && value[i] <= 'F')))
            return 0;
    return 1;
}

static int ac_roaming_domain_ids_valid(const char *text)
{
    struct json_object *array = NULL;
    size_t i;
    int valid = 0;

    if (!text || strlen(text) > AC_WIFI_TX_CANDIDATE_MAX_BYTES)
        return 0;
    array = json_tokener_parse(text);
    if (!array || !json_object_is_type(array, json_type_array) ||
        json_object_array_length(array) > AC_WIFI_TX_TARGETS_MAX)
        goto done;
    for (i = 0; i < json_object_array_length(array); i++) {
        struct json_object *entry = json_object_array_get_idx(array, i);
        const char *value;

        if (!entry || !json_object_is_type(entry, json_type_string))
            goto done;
        value = json_object_get_string(entry);
        if (!ac_roaming_domain_text_valid(value, 64, 0))
            goto done;
    }
    valid = 1;
done:
    json_object_put(array);
    return valid;
}

static struct json_object *ac_roaming_domain_from_stmt(sqlite3_stmt *st)
{
    struct json_object *item = json_object_new_object();
    struct json_object *ssid_ids = json_tokener_parse(
        (const char *)sqlite3_column_text(st, 2));
    struct json_object *ap_group_ids = json_tokener_parse(
        (const char *)sqlite3_column_text(st, 3));

    if (!ssid_ids || !json_object_is_type(ssid_ids, json_type_array)) {
        json_object_put(ssid_ids);
        ssid_ids = json_object_new_array();
    }
    if (!ap_group_ids ||
        !json_object_is_type(ap_group_ids, json_type_array)) {
        json_object_put(ap_group_ids);
        ap_group_ids = json_object_new_array();
    }
    json_object_object_add(item, "domain_id", json_object_new_string(
        (const char *)sqlite3_column_text(st, 0)));
    json_object_object_add(item, "name", json_object_new_string(
        (const char *)sqlite3_column_text(st, 1)));
    json_object_object_add(item, "ssid_ids", ssid_ids);
    json_object_object_add(item, "ap_group_ids", ap_group_ids);
    json_object_object_add(item, "security_profile_id", json_object_new_string(
        (const char *)sqlite3_column_text(st, 4)));
    json_object_object_add(item, "mobility_domain", json_object_new_string(
        (const char *)sqlite3_column_text(st, 5)));
    json_object_object_add(item, "ft_enabled",
                           json_object_new_boolean(sqlite3_column_int(st, 6)));
    json_object_object_add(item, "ft_mode", json_object_new_string(
        (const char *)sqlite3_column_text(st, 7)));
    json_object_object_add(item, "key_revision",
                           json_object_new_int64(sqlite3_column_int64(st, 8)));
    json_object_object_add(item, "neighbor_report_enabled",
                           json_object_new_boolean(sqlite3_column_int(st, 9)));
    json_object_object_add(item, "bss_transition_enabled",
                           json_object_new_boolean(sqlite3_column_int(st, 10)));
    json_object_object_add(item, "deauth_enabled",
                           json_object_new_boolean(sqlite3_column_int(st, 11)));
    json_object_object_add(item, "revision",
                           json_object_new_int64(sqlite3_column_int64(st, 12)));
    json_object_object_add(item, "updated_at",
                           json_object_new_int64(sqlite3_column_int64(st, 13)));
    json_object_object_add(item, "updated_by", json_object_new_string(
        (const char *)sqlite3_column_text(st, 14)));
    return item;
}

#define AC_ROAMING_DOMAIN_COLUMNS \
    "domain_id,name,ssid_ids_json,ap_group_ids_json,security_profile_id," \
    "mobility_domain,ft_enabled,ft_mode,key_revision," \
    "neighbor_report_enabled,bss_transition_enabled,deauth_enabled," \
    "revision,updated_at,updated_by"

struct json_object *ac_db_roaming_domains_json(void)
{
    struct json_object *root = json_object_new_object();
    struct json_object *items = json_object_new_array();
    sqlite3_stmt *st = NULL;
    int count = 0;

    if (!g_ac_db || sqlite3_prepare_v2(g_ac_db,
            "SELECT " AC_ROAMING_DOMAIN_COLUMNS
            " FROM ac_roaming_domains ORDER BY name,domain_id",
            -1, &st, NULL) != SQLITE_OK)
        goto error;
    while (sqlite3_step(st) == SQLITE_ROW) {
        json_object_array_add(items, ac_roaming_domain_from_stmt(st));
        count++;
    }
    sqlite3_finalize(st);
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "items", items);
    json_object_object_add(root, "count", json_object_new_int(count));
    return root;
error:
    sqlite3_finalize(st);
    json_object_put(items);
    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "error",
                           json_object_new_string("database_error"));
    return root;
}

struct json_object *ac_db_roaming_domain_json(const char *domain_id)
{
    struct json_object *root = json_object_new_object();
    sqlite3_stmt *st = NULL;

    if (!g_ac_db || !ac_uuid_valid(domain_id)) {
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "error",
                               json_object_new_string("invalid_domain_id"));
        return root;
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT " AC_ROAMING_DOMAIN_COLUMNS
            " FROM ac_roaming_domains WHERE domain_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        goto database_error;
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "error",
                               json_object_new_string("not_found"));
        return root;
    }
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "domain", ac_roaming_domain_from_stmt(st));
    sqlite3_finalize(st);
    return root;
database_error:
    sqlite3_finalize(st);
    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "error",
                           json_object_new_string("database_error"));
    return root;
}

int ac_db_roaming_domain_put(const char *domain_id, const char *name,
                             const char *ssid_ids_json,
                             const char *ap_group_ids_json,
                             const char *security_profile_id,
                             const char *mobility_domain,
                             int ft_enabled, const char *ft_mode,
                             int neighbor_report_enabled,
                             int bss_transition_enabled,
                             int deauth_enabled,
                             const char *deauth_confirmation,
                             int64_t base_revision,
                             const char *updated_by,
                             char domain_id_out[AC_RADIO_JOB_ID_LEN + 1])
{
    sqlite3_stmt *st = NULL;
    char generated_id[AC_RADIO_JOB_ID_LEN + 1] = { 0 };
    const char *id = domain_id;
    int exists = 0;
    int64_t revision = 0;
    int rc = AC_ROAMING_DOMAIN_DB_ERROR;

    if (!g_ac_db || !ac_roaming_domain_text_valid(name, 64, 0) ||
        !ac_roaming_domain_ids_valid(ssid_ids_json) ||
        !ac_roaming_domain_ids_valid(ap_group_ids_json) ||
        !ac_roaming_domain_text_valid(security_profile_id, 64, 1) ||
        !ac_roaming_domain_text_valid(updated_by, 64, 0) ||
        (ft_enabled != 0 && ft_enabled != 1) ||
        (neighbor_report_enabled != 0 && neighbor_report_enabled != 1) ||
        (bss_transition_enabled != 0 && bss_transition_enabled != 1) ||
        (deauth_enabled != 0 && deauth_enabled != 1) || base_revision < 0 ||
        (!ft_mode || (strcmp(ft_mode, "over_air") &&
                      strcmp(ft_mode, "over_ds"))) ||
        (ft_enabled && !ac_roaming_domain_hex_valid(mobility_domain, 4)) ||
        (!ft_enabled &&
         !ac_roaming_domain_text_valid(mobility_domain, 4, 1)))
        return AC_ROAMING_DOMAIN_INVALID;
    /* Phase 4 authorisation gate.
     *
     * Turning on forced deauth is the one setting in this table that can throw
     * a user's device off the network, so it is not a normal field write:
     *
     *   - it needs an explicit confirmation token, so a client that PUTs a
     *     whole domain object back cannot flip it as a side effect of echoing
     *     fields it never meant to change;
     *   - it cannot be set while creating a domain, only as a deliberate edit
     *     to one that already exists;
     *   - it requires 11v BTM to be enabled, because deauth is the fallback
     *     for a BTM that did not take, never a substitute for trying politely
     *     first.
     *
     * Leaving it at 0 needs no confirmation -- turning it off must never be
     * harder than turning it on. */
    if (deauth_enabled &&
        (!deauth_confirmation ||
         strcmp(deauth_confirmation, "enable-forced-deauth") ||
         !bss_transition_enabled || !domain_id || !domain_id[0]))
        return AC_ROAMING_DOMAIN_INVALID;
    if (!id || !id[0]) {
        if (base_revision != 0 || ac_generate_uuid(generated_id) != 0)
            return AC_ROAMING_DOMAIN_INVALID;
        id = generated_id;
    } else if (!ac_uuid_valid(id)) {
        return AC_ROAMING_DOMAIN_INVALID;
    }
    if (ac_exec("BEGIN IMMEDIATE") != 0)
        return AC_ROAMING_DOMAIN_DB_ERROR;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT revision FROM ac_roaming_domains WHERE domain_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        exists = 1;
        revision = sqlite3_column_int64(st, 0);
    }
    sqlite3_finalize(st);
    st = NULL;
    if ((exists && revision != base_revision) || (!exists && base_revision != 0)) {
        rc = AC_ROAMING_DOMAIN_CONFLICT;
        goto done;
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_roaming_domains(domain_id,name,ssid_ids_json,"
            "ap_group_ids_json,security_profile_id,mobility_domain,ft_enabled,"
            "ft_mode,key_revision,neighbor_report_enabled,"
            "bss_transition_enabled,deauth_enabled,revision,updated_at,updated_by)"
            " VALUES(?1,?2,?3,?4,?5,?6,?7,?8,0,?9,?10,?13,1,?11,?12)"
            " ON CONFLICT(domain_id) DO UPDATE SET name=excluded.name,"
            "ssid_ids_json=excluded.ssid_ids_json,"
            "ap_group_ids_json=excluded.ap_group_ids_json,"
            "security_profile_id=excluded.security_profile_id,"
            "mobility_domain=excluded.mobility_domain,"
            "ft_enabled=excluded.ft_enabled,ft_mode=excluded.ft_mode,"
            "neighbor_report_enabled=excluded.neighbor_report_enabled,"
            "bss_transition_enabled=excluded.bss_transition_enabled,"
            "deauth_enabled=excluded.deauth_enabled,"
            "revision=ac_roaming_domains.revision+1,"
            "updated_at=excluded.updated_at,updated_by=excluded.updated_by",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, ssid_ids_json, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, ap_group_ids_json, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, security_profile_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, mobility_domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 7, ft_enabled);
    sqlite3_bind_text(st, 8, ft_mode, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 9, neighbor_report_enabled);
    sqlite3_bind_int(st, 10, bss_transition_enabled);
    sqlite3_bind_int(st, 13, deauth_enabled);
    sqlite3_bind_int64(st, 11, ac_now_s());
    sqlite3_bind_text(st, 12, updated_by, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    rc = 0;
done:
    sqlite3_finalize(st);
    if (rc == 0 && ac_exec("COMMIT") == 0) {
        if (domain_id_out)
            snprintf(domain_id_out, AC_RADIO_JOB_ID_LEN + 1, "%s", id);
        return 0;
    }
    ac_exec("ROLLBACK");
    return rc;
}

int ac_db_roaming_domain_delete(const char *domain_id,
                                int64_t base_revision)
{
    sqlite3_stmt *st = NULL;
    int rc = AC_ROAMING_DOMAIN_DB_ERROR;

    if (!g_ac_db || !ac_uuid_valid(domain_id) || base_revision <= 0)
        return AC_ROAMING_DOMAIN_INVALID;
    if (ac_exec("BEGIN IMMEDIATE") != 0)
        return AC_ROAMING_DOMAIN_DB_ERROR;
    if (sqlite3_prepare_v2(g_ac_db,
            "DELETE FROM ac_roaming_domain_members WHERE domain_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "DELETE FROM ac_roaming_domains WHERE domain_id=?1 AND revision=?2",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, base_revision);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    rc = sqlite3_changes(g_ac_db) == 1 ? 0 : AC_ROAMING_DOMAIN_CONFLICT;
    if (rc == 0) {
        const char *cleanup[] = {
            "DELETE FROM ac_neighbor_sync_domains WHERE domain_id=?1",
            "DELETE FROM ac_neighbor_sync_state WHERE domain_id=?1",
            "DELETE FROM ac_roaming_domain_action_state WHERE domain_id=?1",
        };
        size_t i;

        /* Recreating the UUID must not inherit a previous opt-in. */
        for (i = 0; i < sizeof(cleanup) / sizeof(cleanup[0]); i++) {
            sqlite3_finalize(st);
            st = NULL;
            if (sqlite3_prepare_v2(g_ac_db, cleanup[i], -1, &st, NULL) != SQLITE_OK) {
                rc = AC_ROAMING_DOMAIN_DB_ERROR;
                goto done;
            }
            sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(st) != SQLITE_DONE) {
                rc = AC_ROAMING_DOMAIN_DB_ERROR;
                goto done;
            }
        }
    }
done:
    sqlite3_finalize(st);
    if (rc == 0 && ac_exec("COMMIT") == 0)
        return 0;
    ac_exec("ROLLBACK");
    return rc;
}

/* ---- Phase 2: cooldown, exclusions, candidate scoring, audit ---- */

static int64_t ac_db_roaming_cooldown_check(const char *domain_id,
                                             const char *station_mac,
                                             int64_t now)
{
    sqlite3_stmt *st = NULL;
    int64_t until = 0;

    if (!g_ac_db || !domain_id || !station_mac)
        return 0;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT cooldown_until FROM ac_roaming_cooldowns "
            "WHERE domain_id=?1 AND station_mac=?2",
            -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, station_mac, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        until = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return until > now ? until : 0;
}

static int __attribute__((unused)) ac_db_roaming_cooldown_record(const char *domain_id,
                                          const char *station_mac,
                                          int duration_sec,
                                          const char *reason,
                                          int64_t now)
{
    sqlite3_stmt *st = NULL;

    if (!g_ac_db || !domain_id || !station_mac || duration_sec <= 0)
        return -1;
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_roaming_cooldowns(domain_id,station_mac,"
            "cooldown_until,reason,created_at) VALUES(?1,?2,?3,?4,?5) "
            "ON CONFLICT(domain_id,station_mac) DO UPDATE SET "
            "cooldown_until=excluded.cooldown_until,"
            "reason=excluded.reason,created_at=excluded.created_at",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, station_mac, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, now + duration_sec);
    sqlite3_bind_text(st, 4, reason ? reason : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 5, now);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    return 0;
}

/* Returns exclusion label if station matches any exclusion rule, NULL otherwise.
 * Writes the matched rule_type into *rule_type_out if non-NULL. */
static const char *ac_db_roaming_exclusion_check(const char *domain_id,
                                                   const char *station_mac,
                                                   const char *ssid_id,
                                                   char *rule_type_out,
                                                   size_t rule_type_sz)
{
    sqlite3_stmt *st = NULL;
    const char *result = NULL;

    if (rule_type_out && rule_type_sz > 0)
        rule_type_out[0] = 0;
    if (!g_ac_db || !domain_id || !station_mac)
        return NULL;
    /* Check MAC exclusions. */
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT label FROM ac_roaming_exclusions "
            "WHERE domain_id=?1 AND rule_type='mac' AND pattern=?2 "
            "LIMIT 1",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, station_mac, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            result = (const char *)sqlite3_column_text(st, 0);
            if (rule_type_out)
                snprintf(rule_type_out, rule_type_sz, "mac");
            /* strdup since we finalize below */
            static char excl_buf[128];
            snprintf(excl_buf, sizeof(excl_buf), "%s", result ? result : "excluded_mac");
            sqlite3_finalize(st);
            return excl_buf;
        }
        sqlite3_finalize(st);
        st = NULL;
    }
    /* Check SSID exclusions. */
    if (ssid_id && sqlite3_prepare_v2(g_ac_db,
            "SELECT label FROM ac_roaming_exclusions "
            "WHERE domain_id=?1 AND rule_type='ssid' AND pattern=?2 "
            "LIMIT 1",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, ssid_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            result = (const char *)sqlite3_column_text(st, 0);
            if (rule_type_out)
                snprintf(rule_type_out, rule_type_sz, "ssid");
            static char excl_buf2[128];
            snprintf(excl_buf2, sizeof(excl_buf2), "%s", result ? result : "excluded_ssid");
            sqlite3_finalize(st);
            return excl_buf2;
        }
        sqlite3_finalize(st);
        st = NULL;
    }
    /* Check station_group exclusions: pattern is a group_id, station must be
     * a member of that group. We check via ac_station_sessions -> ap_id -> 
     * ac_ap_group_members. */
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT e.label FROM ac_roaming_exclusions e "
            "WHERE e.domain_id=?1 AND e.rule_type='station_group' "
            "AND EXISTS(SELECT 1 FROM ac_station_sessions s "
            "JOIN ac_ap_group_members gm ON gm.ap_id=s.ap_id "
            "WHERE s.mac=?2 AND s.disconnected_at=0 AND gm.group_id=e.pattern) "
            "LIMIT 1",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, station_mac, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            result = (const char *)sqlite3_column_text(st, 0);
            if (rule_type_out)
                snprintf(rule_type_out, rule_type_sz, "station_group");
            static char excl_buf3[128];
            snprintf(excl_buf3, sizeof(excl_buf3), "%s", result ? result : "excluded_group");
            sqlite3_finalize(st);
            return excl_buf3;
        }
        sqlite3_finalize(st);
        st = NULL;
    }
    return NULL;
}

int ac_db_roaming_exclusion_put(const char *exclusion_id,
                                        const char *domain_id,
                                        const char *rule_type,
                                        const char *pattern,
                                        const char *label,
                                        int64_t now)
{
    sqlite3_stmt *st = NULL;

    if (!g_ac_db || !exclusion_id || !domain_id || !rule_type || !pattern)
        return AC_ROAMING_DOMAIN_INVALID;
    if (strcmp(rule_type, "mac") && strcmp(rule_type, "station_group") &&
        strcmp(rule_type, "ssid"))
        return AC_ROAMING_DOMAIN_INVALID;
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_roaming_exclusions(exclusion_id,domain_id,"
            "rule_type,pattern,label,created_at,updated_at) "
            "VALUES(?1,?2,?3,?4,?5,?6,?6) "
            "ON CONFLICT(exclusion_id) DO UPDATE SET "
            "rule_type=excluded.rule_type,pattern=excluded.pattern,"
            "label=excluded.label,updated_at=excluded.updated_at",
            -1, &st, NULL) != SQLITE_OK)
        return AC_ROAMING_DOMAIN_DB_ERROR;
    sqlite3_bind_text(st, 1, exclusion_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, domain_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, rule_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, pattern, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, label ? label : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, now);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return AC_ROAMING_DOMAIN_DB_ERROR;
    }
    sqlite3_finalize(st);
    return 0;
}

int ac_db_roaming_exclusion_delete(const char *exclusion_id)
{
    sqlite3_stmt *st = NULL;

    if (!g_ac_db || !exclusion_id)
        return -1;
    if (sqlite3_prepare_v2(g_ac_db,
            "DELETE FROM ac_roaming_exclusions WHERE exclusion_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, exclusion_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    return 0;
}

struct json_object *ac_db_roaming_exclusions_json(const char *domain_id)
{
    struct json_object *root = json_object_new_object();
    struct json_object *exclusions = json_object_new_array();
    sqlite3_stmt *st = NULL;

    if (!g_ac_db || !domain_id) {
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "exclusions", exclusions);
        return root;
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT exclusion_id,rule_type,pattern,label,created_at,updated_at "
            "FROM ac_roaming_exclusions WHERE domain_id=?1 ORDER BY created_at",
            -1, &st, NULL) != SQLITE_OK) {
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "exclusions", exclusions);
        return root;
    }
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *entry = json_object_new_object();
        json_object_object_add(entry, "exclusion_id",
            json_object_new_string((const char *)sqlite3_column_text(st, 0)));
        json_object_object_add(entry, "rule_type",
            json_object_new_string((const char *)sqlite3_column_text(st, 1)));
        json_object_object_add(entry, "pattern",
            json_object_new_string((const char *)sqlite3_column_text(st, 2)));
        json_object_object_add(entry, "label",
            json_object_new_string((const char *)sqlite3_column_text(st, 3)));
        json_object_object_add(entry, "created_at",
            json_object_new_int64(sqlite3_column_int64(st, 4)));
        json_object_object_add(entry, "updated_at",
            json_object_new_int64(sqlite3_column_int64(st, 5)));
        json_object_array_add(exclusions, entry);
    }
    sqlite3_finalize(st);
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "domain_id", json_object_new_string(domain_id));
    json_object_object_add(root, "exclusions", exclusions);
    return root;
}

/* Record an audit entry for a roaming decision. */
static int ac_db_roaming_audit_record(const char *domain_id,
                                       const char *station_mac,
                                       int64_t observed_at,
                                       const char *current_ap_id,
                                       const char *current_bssid,
                                       int current_signal_dbm,
                                       struct json_object *candidates_json,
                                       const char *decision,
                                       const char *reason,
                                       int64_t policy_revision,
                                       struct json_object *capability_snapshot)
{
    sqlite3_stmt *st = NULL;
    const char *candidates_str = NULL;
    const char *snapshot_str = NULL;

    if (!g_ac_db || !domain_id || !station_mac)
        return -1;
    candidates_str = candidates_json ?
        json_object_to_json_string(candidates_json) : "[]";
    snapshot_str = capability_snapshot ?
        json_object_to_json_string(capability_snapshot) : "{}";
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_roaming_audit(domain_id,station_mac,observed_at,"
            "current_ap_id,current_bssid,current_signal_dbm,"
            "candidates_json,decision,reason,policy_revision,"
            "capability_snapshot_json) "
            "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, station_mac, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, observed_at);
    sqlite3_bind_text(st, 4, current_ap_id ? current_ap_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, current_bssid ? current_bssid : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 6, current_signal_dbm);
    sqlite3_bind_text(st, 7, candidates_str, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, decision ? decision : "no_action", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, reason ? reason : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 10, policy_revision);
    sqlite3_bind_text(st, 11, snapshot_str, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    return 0;
}

struct json_object *ac_db_roaming_audit_json(const char *domain_id,
                                              const char *station_mac,
                                              int limit)
{
    struct json_object *root = json_object_new_object();
    struct json_object *entries = json_object_new_array();
    sqlite3_stmt *st = NULL;

    if (!g_ac_db || !domain_id) {
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "entries", entries);
        return root;
    }
    if (limit <= 0 || limit > 500)
        limit = 50;
    if (station_mac && station_mac[0]) {
        if (sqlite3_prepare_v2(g_ac_db,
                "SELECT audit_id,station_mac,observed_at,"
                "current_ap_id,current_bssid,current_signal_dbm,"
                "candidates_json,decision,reason,policy_revision,"
                "capability_snapshot_json "
                "FROM ac_roaming_audit WHERE domain_id=?1 AND station_mac=?2 "
                "ORDER BY observed_at DESC LIMIT ?3",
                -1, &st, NULL) != SQLITE_OK) {
            json_object_object_add(root, "ok", json_object_new_boolean(0));
            json_object_object_add(root, "entries", entries);
            return root;
        }
        sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, station_mac, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, limit);
    } else {
        if (sqlite3_prepare_v2(g_ac_db,
                "SELECT audit_id,station_mac,observed_at,"
                "current_ap_id,current_bssid,current_signal_dbm,"
                "candidates_json,decision,reason,policy_revision,"
                "capability_snapshot_json "
                "FROM ac_roaming_audit WHERE domain_id=?1 "
                "ORDER BY observed_at DESC LIMIT ?2",
                -1, &st, NULL) != SQLITE_OK) {
            json_object_object_add(root, "ok", json_object_new_boolean(0));
            json_object_object_add(root, "entries", entries);
            return root;
        }
        sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, limit);
    }
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *entry = json_object_new_object();
        const char *candidates_text = (const char *)sqlite3_column_text(st, 6);
        const char *snapshot_text = (const char *)sqlite3_column_text(st, 10);
        struct json_object *candidates_parsed = candidates_text ?
            json_tokener_parse(candidates_text) : json_object_new_array();
        struct json_object *snapshot_parsed = snapshot_text ?
            json_tokener_parse(snapshot_text) : json_object_new_object();

        json_object_object_add(entry, "audit_id",
            json_object_new_int64(sqlite3_column_int64(st, 0)));
        json_object_object_add(entry, "station_mac",
            json_object_new_string((const char *)sqlite3_column_text(st, 1)));
        json_object_object_add(entry, "observed_at",
            json_object_new_int64(sqlite3_column_int64(st, 2)));
        json_object_object_add(entry, "current_ap_id",
            json_object_new_string((const char *)sqlite3_column_text(st, 3)));
        json_object_object_add(entry, "current_bssid",
            json_object_new_string((const char *)sqlite3_column_text(st, 4)));
        json_object_object_add(entry, "current_signal_dbm",
            json_object_new_int(sqlite3_column_int(st, 5)));
        json_object_object_add(entry, "candidates",
            candidates_parsed ? candidates_parsed : json_object_new_array());
        json_object_object_add(entry, "decision",
            json_object_new_string((const char *)sqlite3_column_text(st, 7)));
        json_object_object_add(entry, "reason",
            json_object_new_string((const char *)sqlite3_column_text(st, 8)));
        json_object_object_add(entry, "policy_revision",
            json_object_new_int64(sqlite3_column_int64(st, 9)));
        json_object_object_add(entry, "capability_snapshot",
            snapshot_parsed ? snapshot_parsed : json_object_new_object());
        json_object_array_add(entries, entry);
    }
    sqlite3_finalize(st);
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "domain_id", json_object_new_string(domain_id));
    json_object_object_add(root, "entries", entries);
    return root;
}

/* Multi-factor candidate scoring.
 *
 * Scores each eligible member against the current station session.
 * Factors:
 *   1. Estimated signal quality at candidate (station RSSI adjusted by path loss delta)
 *   2. Candidate AP load (station count from traffic buckets)
 *   3. Candidate radio channel utilization (from survey data)
 *   4. Station capability: BTM support, band compatibility
 *
 * Returns a JSON array of scored candidates sorted by score descending.
 * Each entry: {ap_id, radio_id, ssid_id, bssid, score, signal_estimate_dbm,
 *              station_count, channel_utilization_pct, btm_capable, reason}
 */
/* Phase 2: the station's own measurement of a candidate BSS.
 *
 * This is the reading that makes candidate scoring honest.  The serving AP
 * cannot measure a BSS it is not on, and the candidate AP cannot see a client
 * associated elsewhere -- only the station can, via an 802.11k beacon report,
 * which APD collects and publishes under sources.hostapd.beacon_reports[].
 *
 * Scans the APs rather than taking a serving-AP hint: the measurement lands in
 * whichever AP asked for it, and a wrong hint would silently degrade scoring
 * back to the station's own RSSI.  Only fresh, non-stale snapshots count.
 *
 * Returns 1 and sets *dbm_out when a usable measurement exists. */
static int ac_roaming_beacon_signal(const char *station_mac, const char *bssid,
                                    int64_t now, int *dbm_out, int *cached_out,
                                    int64_t *observed_out)
{
    sqlite3_stmt *st = NULL;
    int found = 0;
    int64_t newest = 0;

    if (cached_out)
        *cached_out = 0;
    if (observed_out)
        *observed_out = 0;
    if (!g_ac_db || !station_mac || !bssid || !bssid[0] || !dbm_out)
        return 0;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT runtime_json FROM ac_ap_runtime "
            "WHERE stale=0 AND observed_at>=?1", -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_int64(st, 1, now - AC_TELEMETRY_STALE_TIMEOUT_SECONDS);
    while (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *text = sqlite3_column_text(st, 0);
        struct json_object *snapshot = text ?
            json_tokener_parse((const char *)text) : NULL;
        struct json_object *sources = NULL;
        struct json_object *hostapd = NULL;
        struct json_object *reports = NULL;
        size_t i;

        if (snapshot &&
            json_object_object_get_ex(snapshot, "sources", &sources) &&
            json_object_object_get_ex(sources, "hostapd", &hostapd) &&
            json_object_object_get_ex(hostapd, "beacon_reports", &reports) &&
            json_object_is_type(reports, json_type_array)) {
            for (i = 0; i < json_object_array_length(reports); i++) {
                struct json_object *r = json_object_array_get_idx(reports, i);
                const char *r_mac = ac_db_json_string(r, "station_mac");
                const char *r_bssid = ac_db_json_string(r, "bssid");
                struct json_object *value = NULL;
                int64_t measured_at = json_object_get_int64(
                    json_object_object_get(r, "observed_at"));

                if (!r_mac || !r_bssid || strcasecmp(r_mac, station_mac) ||
                    strcasecmp(r_bssid, bssid))
                    continue;
                if (!json_object_object_get_ex(r, "rcpi_dbm", &value) ||
                    !value || !json_object_is_type(value, json_type_int) ||
                    measured_at < now - 120 || measured_at > now + 5 ||
                    measured_at < newest ||
                    json_object_get_int(value) < -110 ||
                    json_object_get_int(value) > 0)
                    continue;
                *dbm_out = json_object_get_int(value);
                if (cached_out) {
                    const char *mode = ac_db_json_string(r, "measurement_mode");

                    *cached_out = ac_db_json_bool(r, "cached") ||
                        (mode && !strcmp(mode, "table"));
                }
                if (observed_out)
                    *observed_out = measured_at;
                newest = measured_at;
                found = 1;
            }
        }
        json_object_put(snapshot);
    }
    sqlite3_finalize(st);
    return found;
}

/* AP-side uplink evidence.  Probe observations are only attributable when the
 * AP heard the exact station address being evaluated.  A locally administered
 * address is therefore not rejected by itself: Apple's per-SSID randomized
 * address is still a usable identity once it matches the live station session.
 * Unknown/random addresses never enter this lookup. */
static int ac_roaming_probe_signal(const char *station_mac, const char *bssid,
                                   int64_t now, int *dbm_out,
                                   int *randomized_out, int64_t *observed_out)
{
    sqlite3_stmt *st = NULL;
    int found = 0;
    int64_t newest = 0;

    if (randomized_out)
        *randomized_out = 0;
    if (observed_out)
        *observed_out = 0;
    if (!g_ac_db || !station_mac || !bssid || !bssid[0] || !dbm_out)
        return 0;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT r.observed_at,r.runtime_json FROM ac_ap_runtime r "
            "JOIN ac_ssid_bindings b ON b.ap_id=r.ap_id "
            "WHERE b.bssid=?2 COLLATE NOCASE AND r.stale=0 "
            "AND r.observed_at>=?1", -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_int64(st, 1, now - AC_TELEMETRY_STALE_TIMEOUT_SECONDS);
    sqlite3_bind_text(st, 2, bssid, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *text = sqlite3_column_text(st, 1);
        struct json_object *snapshot = text ?
            json_tokener_parse((const char *)text) : NULL;
        struct json_object *sources = NULL;
        struct json_object *hostapd = NULL;
        struct json_object *observations = NULL;
        struct json_object *bss_list = NULL;
        size_t i;

        if (snapshot &&
            json_object_object_get_ex(snapshot, "sources", &sources) &&
            json_object_object_get_ex(sources, "hostapd", &hostapd) &&
            json_object_object_get_ex(hostapd, "probe_observations",
                                      &observations) &&
            json_object_object_get_ex(hostapd, "bss", &bss_list) &&
            json_object_is_type(bss_list, json_type_array) &&
            json_object_is_type(observations, json_type_array)) {
            for (i = 0; i < json_object_array_length(observations); i++) {
                struct json_object *entry =
                    json_object_array_get_idx(observations, i);
                const char *entry_mac = ac_db_json_string(entry, "station_mac");
                const char *entry_bssid = ac_db_json_string(entry, "bssid");
                const char *frame_type = ac_db_json_string(entry, "frame_type");
                const char *direction = ac_db_json_string(entry, "direction");
                const char *source = ac_db_json_string(entry, "source");
                const char *interface = ac_db_json_string(entry, "interface");
                struct json_object *value = NULL;
                int64_t measured_at = json_object_get_int64(
                    json_object_object_get(entry, "observed_at"));

                size_t bi;
                int attributed = 0;

                if (!entry_mac || !entry_bssid || !interface ||
                    !frame_type || !direction ||
                    !source || strcmp(frame_type, "probe_request") ||
                    strcmp(direction, "uplink") ||
                    strcmp(source, "hostapd_control_event") ||
                    strcasecmp(entry_mac, station_mac) ||
                    strcasecmp(entry_bssid, bssid))
                    continue;
                for (bi = 0; bi < json_object_array_length(bss_list); bi++) {
                    struct json_object *bss = json_object_array_get_idx(bss_list, bi);
                    const char *bss_bssid = ac_db_json_string(bss, "bssid");
                    const char *bss_interface = ac_db_json_string(bss, "interface");

                    if (bss_bssid && bss_interface &&
                        !strcasecmp(bss_bssid, bssid) &&
                        !strcmp(bss_interface, interface) &&
                        ac_db_json_bool(bss, "complete") &&
                        ac_db_json_bool(hostapd, "available")) {
                        attributed = 1;
                        break;
                    }
                }
                if (!attributed)
                    continue;
                if (!json_object_object_get_ex(entry, "rssi_dbm", &value) ||
                    !value || !json_object_is_type(value, json_type_int) ||
                    measured_at < now - AC_ROAMING_PROBE_TTL_SECONDS ||
                    measured_at > now + 5 || measured_at < newest ||
                    json_object_get_int(value) < -110 ||
                    json_object_get_int(value) > 0)
                    continue;
                *dbm_out = json_object_get_int(value);
                if (randomized_out)
                    *randomized_out = ac_db_json_bool(entry, "mac_randomized");
                if (observed_out)
                    *observed_out = measured_at;
                newest = measured_at;
                found = 1;
            }
        }
        json_object_put(snapshot);
    }
    sqlite3_finalize(st);
    return found;
}

static const char *ac_roaming_signal_direction(const char *source)
{
    if (!source)
        return "unknown";
    if (!strncmp(source, "ieee80211k_", strlen("ieee80211k_")))
        return "downlink";
    if (!strcmp(source, "ap_probe_request") ||
        !strcmp(source, "ap_station_signal"))
        return "uplink";
    return "unknown";
}

static int ac_roaming_iphone_probe_scope(const char *station_mac,
                                          const char *ssid_id)
{
    sqlite3_stmt *st = NULL;
    int scoped = 0;

    if (!g_ac_db || !station_mac || !ssid_id ||
        strcasecmp(station_mac, "d2:76:c1:3e:34:6c") ||
        sqlite3_prepare_v2(g_ac_db,
            "SELECT 1 FROM ac_ssids WHERE ssid_id=?1 AND name='Xiaomi_DE23' "
            "LIMIT 1", -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, ssid_id, -1, SQLITE_TRANSIENT);
    scoped = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return scoped;
}

static int ac_roaming_station_btm_capable(struct json_object *runtime)
{
    struct json_object *value = NULL;

    if (!runtime || !json_object_is_type(runtime, json_type_object))
        return 0;
    if (!json_object_object_get_ex(runtime, "station_btm_capable", &value))
        json_object_object_get_ex(runtime, "btm_capable", &value);
    return value && json_object_is_type(value, json_type_boolean) &&
           json_object_get_boolean(value);
}

static struct json_object *ac_db_roaming_candidates_score(
    const char *domain_id,
    const char *station_mac,
    struct json_object *members,
    struct json_object *station_runtime,
    int current_signal_dbm,
    int allow_probe, int high_band_steer_enabled,
    int64_t now)
{
    struct json_object *candidates = json_object_new_array();
    (void)domain_id;
    size_t i, count;
    int btm_capable = ac_roaming_station_btm_capable(station_runtime);

    if (!members || !json_object_is_type(members, json_type_array))
        return candidates;

    count = json_object_array_length(members);
    for (i = 0; i < count; i++) {
        struct json_object *member = json_object_array_get_idx(members, i);
        struct json_object *candidate = json_object_new_object();
        const char *ap_id, *radio_id, *ssid_id, *bssid, *elig_reason;
        int eligible;
        int score = 0;
        int signal_estimate = current_signal_dbm;
        int signal_measured = 0;
        int signal_cached = 0;
        int signal_randomized = 0;
        int64_t signal_observed_at = 0;
        const char *signal_source = "station_current_rssi_fallback";
        int station_count = -1;
        double channel_util = -1.0;
        int frequency = json_object_get_int(
            json_object_object_get(member, "frequency_mhz"));
        int band_bonus = frequency >= 5955 ? 12 : frequency >= 4900 ? 8 : 0;
        sqlite3_stmt *st = NULL;

        if (!member) {
            json_object_put(candidate);
            continue;
        }
        ap_id = ac_db_json_string(member, "ap_id");
        radio_id = ac_db_json_string(member, "radio_id");
        ssid_id = ac_db_json_string(member, "ssid_id");
        bssid = ac_db_json_string(member, "bssid");
        eligible = json_object_get_boolean(
            json_object_object_get(member, "eligible"));
        elig_reason = ac_db_json_string(member, "reason");

        /* Skip ineligible members. */
        if (!eligible) {
            json_object_object_add(candidate, "ap_id",
                json_object_new_string(ap_id ? ap_id : ""));
            json_object_object_add(candidate, "radio_id",
                json_object_new_string(radio_id ? radio_id : ""));
            json_object_object_add(candidate, "bssid",
                json_object_new_string(bssid ? bssid : ""));
            json_object_object_add(candidate, "score", json_object_new_int(0));
            json_object_object_add(candidate, "eligible", json_object_new_boolean(0));
            json_object_object_add(candidate, "reason",
                json_object_new_string(elig_reason ? elig_reason : "ineligible"));
            json_object_array_add(candidates, candidate);
            continue;
        }

        /* Prefer the station's own 802.11k report. Fallback values are for
         * display only; steering requires measured serving and target BSS. */
        {
            int measured = 0;

            signal_estimate = current_signal_dbm;
            signal_measured = 0;
            if (station_mac && bssid &&
                ac_roaming_beacon_signal(station_mac, bssid, now, &measured,
                                         &signal_cached,
                                         &signal_observed_at)) {
                signal_estimate = measured;
                signal_measured = 1;
                signal_source = signal_cached ? "ieee80211k_beacon_table" :
                                                "ieee80211k_beacon_report";
            } else if (allow_probe && station_mac && bssid &&
                       ac_roaming_probe_signal(station_mac, bssid, now,
                                               &measured, &signal_randomized,
                                               &signal_observed_at)) {
                signal_estimate = measured;
                signal_measured = 1;
                signal_source = "ap_probe_request";
            }
        }

        /* Factor 2: Candidate AP station count from latest traffic bucket. */
        if (ap_id && sqlite3_prepare_v2(g_ac_db,
                "SELECT CAST(SUM(station_count_sum) AS REAL)/SUM(sample_count) "
                "FROM ac_ap_traffic_bucket WHERE ap_id=?1 "
                "AND bucket_start>=?2 ORDER BY bucket_start DESC LIMIT 1",
                -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 2, now - 600);
            if (sqlite3_step(st) == SQLITE_ROW &&
                sqlite3_column_type(st, 0) != SQLITE_NULL)
                station_count = (int)sqlite3_column_double(st, 0);
            sqlite3_finalize(st);
            st = NULL;
        }

        /* Factor 3: Channel utilization from survey bucket. */
        if (ap_id && radio_id && sqlite3_prepare_v2(g_ac_db,
                "SELECT utilization_pct FROM ac_radio_survey_bucket "
                "WHERE ap_id=?1 AND radio_id=?2 AND bucket_start>=?3 "
                "ORDER BY bucket_start DESC LIMIT 1",
                -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, radio_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 3, now - AC_TELEMETRY_STALE_TIMEOUT_SECONDS);
            if (sqlite3_step(st) == SQLITE_ROW &&
                sqlite3_column_type(st, 0) != SQLITE_NULL)
                channel_util = sqlite3_column_double(st, 0);
            sqlite3_finalize(st);
            st = NULL;
        }

        /* Compute composite score. Higher is better.
         * Base: signal_estimate (dBm, negative, so less negative = better)
         * Penalty for load: -2 per station above 10
         * Penalty for channel util: -1 per 5% above 25%
         * Bonus for BTM capable station: +5 */
        /* Above -55 dBm, extra signal is not extra capacity. Saturating that
         * term prevents a nearby 2.4 GHz BSS from beating a strong 5/6 GHz BSS
         * solely because lower frequencies have less path loss. */
        score = (signal_estimate > -55 ? -55 : signal_estimate) +
            (high_band_steer_enabled ? band_bonus : 0);
        if (station_count > 10)
            score -= (station_count - 10) * 2;
        if (channel_util > 25.0)
            score -= (int)((channel_util - 25.0) / 5.0);
        if (btm_capable)
            score += 5;

        json_object_object_add(candidate, "ap_id",
            json_object_new_string(ap_id ? ap_id : ""));
        json_object_object_add(candidate, "radio_id",
            json_object_new_string(radio_id ? radio_id : ""));
        json_object_object_add(candidate, "ssid_id",
            json_object_new_string(ssid_id ? ssid_id : ""));
        json_object_object_add(candidate, "bssid",
            json_object_new_string(bssid ? bssid : ""));
        json_object_object_add(candidate, "score", json_object_new_int(score));
        json_object_object_add(candidate, "frequency_mhz", json_object_new_int(frequency));
        json_object_object_add(candidate, "band_bonus", json_object_new_int(band_bonus));
        json_object_object_add(candidate, "signal_estimate_dbm",
            json_object_new_int(signal_estimate));
        json_object_object_add(candidate, "station_count",
            json_object_new_int(station_count));
        json_object_object_add(candidate, "channel_utilization_pct",
            channel_util >= 0 ? json_object_new_double(channel_util) :
            json_object_new_null());
        json_object_object_add(candidate, "btm_capable",
            json_object_new_boolean(btm_capable));
        json_object_object_add(candidate, "eligible", json_object_new_boolean(1));
        /* Say plainly whether the score rests on a real measurement of this
         * candidate or on the fallback.  Without this an operator reading the
         * audit cannot tell a scored candidate from an unmeasured one. */
        json_object_object_add(candidate, "signal_source",
            json_object_new_string(signal_source));
        json_object_object_add(candidate, "signal_direction",
            json_object_new_string(ac_roaming_signal_direction(signal_source)));
        json_object_object_add(candidate, "signal_observed_at",
            signal_observed_at > 0 ? json_object_new_int64(signal_observed_at) :
                                     json_object_new_null());
        json_object_object_add(candidate, "signal_randomized",
            json_object_new_boolean(signal_randomized));
        json_object_object_add(candidate, "signal_measured",
            json_object_new_boolean(signal_measured));
        json_object_object_add(candidate, "signal_cached",
            json_object_new_boolean(signal_cached));
        json_object_object_add(candidate, "reason",
            json_object_new_string(signal_measured ? "scored" :
                                   "scored_unmeasured"));
        json_object_array_add(candidates, candidate);
    }
    return candidates;
}

/* Record one deauth attempt with the evidence that justified it.
 *
 * Written before the frame goes out, not after, so an attempt that crashes or
 * times out mid-flight still leaves a row.  `sent_ok` is updated afterwards;
 * a row stuck at sent_ok=0 is exactly the AP-control failure the breaker
 * counts, so losing it would hide the failure it exists to catch.
 *
 * Returns the new deauth_id, or 0 on failure. */
static int64_t ac_roam_deauth_record(const char *domain_id,
                                     const char *station_mac,
                                     const char *ap_id,
                                     const char *source_bssid,
                                     const char *target_bssid,
                                     const char *target_bssid_2,
                                     const char *trigger_source,
                                     const char *triggered_by,
                                     int signal_dbm,
                                     const char *candidate_json,
                                     const char *btm_history_json,
                                     int64_t policy_revision,
                                     int64_t now)
{
    sqlite3_stmt *st = NULL;
    int64_t deauth_id = 0;

    if (!g_ac_db || !domain_id || !station_mac)
        return 0;
    if (!trigger_source || (strcmp(trigger_source, "policy") &&
                            strcmp(trigger_source, "manual")))
        return 0;
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_deauth_actions(domain_id,station_mac,ap_id,"
            "source_bssid,target_bssid,target_bssid_2,trigger_source,triggered_by,signal_dbm,"
            "candidate_json,btm_history_json,policy_revision,sent_at,sent_ok,"
            "outcome,created_at) "
            "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,0,'pending',?13)",
            -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, station_mac, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, ap_id ? ap_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, source_bssid ? source_bssid : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, target_bssid ? target_bssid : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, target_bssid_2 ? target_bssid_2 : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, trigger_source, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, triggered_by ? triggered_by : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 9, signal_dbm);
    sqlite3_bind_text(st, 10, candidate_json ? candidate_json : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 11, btm_history_json ? btm_history_json : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 12, policy_revision);
    sqlite3_bind_int64(st, 13, now);
    if (sqlite3_step(st) == SQLITE_DONE)
        deauth_id = sqlite3_last_insert_rowid(g_ac_db);
    sqlite3_finalize(st);
    return deauth_id;
}

/* Mark whether the frame actually reached hostapd. */
static void ac_roam_deauth_mark_sent(int64_t deauth_id, int sent_ok,
                                     const char *failure_reason)
{
    sqlite3_stmt *st = NULL;

    if (!g_ac_db || deauth_id <= 0)
        return;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_deauth_actions SET sent_ok=?2,"
            "outcome=CASE WHEN ?2=1 THEN outcome ELSE 'blocked' END,"
            "outcome_reason=CASE WHEN ?2=1 THEN outcome_reason ELSE ?3 END "
            "WHERE deauth_id=?1", -1, &st, NULL) != SQLITE_OK)
        return;
    sqlite3_bind_int64(st, 1, deauth_id);
    sqlite3_bind_int(st, 2, sent_ok ? 1 : 0);
    sqlite3_bind_text(st, 3, failure_reason ? failure_reason : "send_failed",
                      -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

/* Resolve where the station ended up after a deauth.
 *
 * Success is never "we sent it".  It is the station being associated to a
 * different BSSID afterwards -- and coming back to the BSSID we pushed it off
 * is recorded as 'returned' rather than 'not_roamed', because that is the
 * ping-pong the breaker must see. */
static void ac_roam_deauth_resolve_outcome(int64_t deauth_id,
                                           const char *current_bssid,
                                           int64_t now)
{
    sqlite3_stmt *st = NULL;
    char source_bssid[32] = { 0 };
    char target_bssid[32] = { 0 };
    char target_bssid_2[32] = { 0 };
    const char *outcome;
    const char *reason;

    if (!g_ac_db || deauth_id <= 0)
        return;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT source_bssid,target_bssid,target_bssid_2 FROM ac_deauth_actions "
            "WHERE deauth_id=?1 AND outcome='pending' AND sent_ok=1",
            -1, &st, NULL) != SQLITE_OK)
        return;
    sqlite3_bind_int64(st, 1, deauth_id);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        return;
    }
    ac_radio_job_copy_text(source_bssid, sizeof(source_bssid),
                           sqlite3_column_text(st, 0));
    ac_radio_job_copy_text(target_bssid, sizeof(target_bssid),
                           sqlite3_column_text(st, 1));
    ac_radio_job_copy_text(target_bssid_2, sizeof(target_bssid_2),
                           sqlite3_column_text(st, 2));
    sqlite3_finalize(st);
    st = NULL;

    if (!current_bssid || !current_bssid[0]) {
        outcome = "not_roamed";
        reason = "station_not_associated";
    } else if (source_bssid[0] && !strcasecmp(current_bssid, source_bssid)) {
        outcome = "returned";
        reason = "station_returned_to_source_bssid";
    } else if ((target_bssid[0] && !strcasecmp(current_bssid, target_bssid)) ||
               (target_bssid_2[0] && !strcasecmp(current_bssid, target_bssid_2))) {
        outcome = "roamed";
        reason = "station_associated_to_target";
    } else {
        outcome = "not_roamed";
        reason = "station_associated_elsewhere";
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_deauth_actions SET outcome=?2,outcome_bssid=?3,"
            "outcome_at=?4,outcome_reason=?5 WHERE deauth_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        return;
    sqlite3_bind_int64(st, 1, deauth_id);
    sqlite3_bind_text(st, 2, outcome, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, current_bssid ? current_bssid : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, now);
    sqlite3_bind_text(st, 5, reason, -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

/* Resolve every pending deauth in a domain against where its station is now.
 *
 * Mirrors ac_roam_btm_check_outcomes(): "sent" is not an outcome, so a row
 * stays pending until the station is observed somewhere, or the window runs
 * out.  Without this the breaker's rate checks would divide by zero forever
 * and forced actions would never auto-disable. */
#if !defined(AC_DB_TEST_STANDALONE) || defined(AC_DB_ROAMING_ACTIONS_TEST)
static int ac_roaming_expire_queued_action(const char *transaction_id, int64_t now);
#endif

static void ac_roam_deauth_check_outcomes(const char *domain_id, int64_t now)
{
    sqlite3_stmt *st = NULL;

    if (!g_ac_db || !domain_id)
        return;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT d.deauth_id,d.station_mac,d.created_at,d.sent_at,d.sent_ok,"
            "d.transaction_id,d.block_duration_sec,d.target_bssid,d.target_bssid_2,"
            "t.state,t.updated_at,"
            "json_extract(NULLIF(j.readback_json,''),'$.evidence_type'),"
            "json_extract(NULLIF(j.readback_json,''),'$.ok') "
            "FROM ac_deauth_actions d LEFT JOIN ac_transaction_targets t "
            "ON t.transaction_id=d.transaction_id AND t.ap_id=d.ap_id "
            "LEFT JOIN ac_config_jobs j ON j.transaction_id=d.transaction_id AND j.ap_id=d.ap_id "
            "WHERE d.domain_id=?1 AND d.outcome='pending' ORDER BY d.created_at LIMIT 64",
            -1, &st, NULL) != SQLITE_OK)
        return;
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(st) == SQLITE_ROW) {
        int64_t id = sqlite3_column_int64(st, 0);
        const char *mac = (const char *)sqlite3_column_text(st, 1);
        int64_t created = sqlite3_column_int64(st, 2);
        int64_t sent = sqlite3_column_int64(st, 3);
        int sent_ok = sqlite3_column_int(st, 4);
        const char *tx = (const char *)sqlite3_column_text(st, 5);
        int duration = sqlite3_column_int(st, 6);
        const char *target = (const char *)sqlite3_column_text(st, 7);
        const char *target_2 = (const char *)sqlite3_column_text(st, 8);
        const char *state = (const char *)sqlite3_column_text(st, 9);
        const char *evidence = (const char *)sqlite3_column_text(st, 11);
        int window = duration ? duration + 20 : 120;
        char current_bssid[32] = { 0 };
        sqlite3_stmt *query = NULL;
        int64_t connected = 0;
        int target_associated;

        if (!sent_ok && tx && tx[0]) {
            if (state && !strcmp(state, "applied") && evidence &&
                !strcmp(evidence, duration ? "hostapd_temporary_reassociation_block" :
                                            "hostapd_command_ack") &&
                sqlite3_column_int(st, 12)) {
                sent = sqlite3_column_int64(st, 10);
                if (sqlite3_prepare_v2(g_ac_db,
                        "UPDATE ac_deauth_actions SET sent_ok=1,sent_at=?2,"
                        "outcome_reason='hostapd_action_confirmed' WHERE deauth_id=?1",
                        -1, &query, NULL) == SQLITE_OK) {
                    sqlite3_bind_int64(query, 1, id);
                    sqlite3_bind_int64(query, 2, sent);
                    sent_ok = sqlite3_step(query) == SQLITE_DONE;
                    sqlite3_finalize(query);
                    query = NULL;
                }
            } else if ((state && (!strcmp(state, "failed") ||
                        !strcmp(state, "cancelled") || !strcmp(state, "rolled_back"))) ||
                       now - created >= (duration ? 30 : 120)) {
#if !defined(AC_DB_TEST_STANDALONE) || defined(AC_DB_ROAMING_ACTIONS_TEST)
                if (ac_roaming_expire_queued_action(tx, now) != 0)
                    continue;
#endif
                ac_roam_deauth_mark_sent(id, 0, "hostapd_action_not_confirmed");
            }
        }
        if (!sent_ok)
            continue;
        if (sqlite3_prepare_v2(g_ac_db,
                "SELECT b.bssid,s.connected_at FROM ac_station_sessions s "
                "LEFT JOIN ac_ssid_bindings b ON b.ssid_id=s.ssid_id "
                "AND b.ap_id=s.ap_id AND b.radio_id=s.radio_id "
                "WHERE s.mac=?1 COLLATE NOCASE AND s.disconnected_at=0 "
                "AND s.last_seen_at>=?2 "
                "ORDER BY s.last_seen_at DESC LIMIT 1",
                -1, &query, NULL) == SQLITE_OK) {
            sqlite3_bind_text(query, 1, mac, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(query, 2, now - AC_TELEMETRY_STALE_TIMEOUT_SECONDS);
            if (sqlite3_step(query) == SQLITE_ROW) {
                ac_radio_job_copy_text(current_bssid, sizeof(current_bssid),
                                       sqlite3_column_text(query, 0));
                connected = sqlite3_column_int64(query, 1);
            }
            sqlite3_finalize(query);
        }
        target_associated = (target && target[0] &&
            !strcasecmp(target, current_bssid)) ||
            (target_2 && target_2[0] &&
             !strcasecmp(target_2, current_bssid));
        if ((target_associated && connected >= created &&
             now >= sent + duration) || now >= sent + window)
            ac_roam_deauth_resolve_outcome(id, current_bssid, now);
    }
    sqlite3_finalize(st);
}

/* Disable a domain's forced actions and record why.
 *
 * One writer for every trip reason, so the audit trail and the alert text are
 * produced the same way no matter which condition fired. */
static void ac_roam_forced_action_disable(const char *domain_id,
                                          const char *reason, int64_t now)
{
    sqlite3_stmt *st = NULL;

    if (!g_ac_db || !domain_id || !reason)
        return;
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_roaming_domain_action_state"
            "(domain_id,steering_enabled,disabled_reason,disabled_at) "
            "VALUES(?1,0,?2,?3) "
            "ON CONFLICT(domain_id) DO UPDATE SET steering_enabled=0,"
            "disabled_reason=excluded.disabled_reason,"
            "disabled_at=excluded.disabled_at",
            -1, &st, NULL) != SQLITE_OK)
        return;
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, reason, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, now);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

int ac_roam_steering_enable_scoped(const char *domain_id,
                                  const char *station_mac, int64_t now)
{
    sqlite3_stmt *st = NULL;
    int exists = 0;
    int rc;

    /* Deliberately not stamped anywhere.  The only free timestamp column is
     * last_action_at, which feeds the domain_action_rate_limit window -- so
     * writing `now` there would charge the operator's manual reset as if it
     * were a steering action and stall the next real one. */
    (void)now;
    if (!g_ac_db || !ac_uuid_valid(domain_id) ||
        (station_mac && !ac_radio_job_mac_valid(station_mac)))
        return AC_ROAMING_DOMAIN_INVALID;
    /* Refuse to write action state for a domain that does not exist.  This is
     * the operator's manual reset after the circuit breaker trips, so an
     * unchecked INSERT would leave a row carrying steering_enabled=1 and an
     * empty disabled_reason keyed to a domain_id nobody has created yet -- and
     * a domain later created with that id would come up with its breaker
     * already cleared.  A breaker a caller can pre-disarm is not a breaker. */
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT 1 FROM ac_roaming_domains WHERE domain_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        return AC_ROAMING_DOMAIN_DB_ERROR;
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    exists = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    st = NULL;
    if (!exists)
        return AC_ROAMING_DOMAIN_NOT_FOUND;
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_roaming_domain_action_state"
            "(domain_id,steering_enabled,disabled_reason,disabled_at,last_action_at,"
            "steering_station_mac) VALUES(?1,1,'',0,0,?2) "
            "ON CONFLICT(domain_id) DO UPDATE SET "
            "steering_enabled=1,disabled_reason='',disabled_at=0,"
            "steering_station_mac=excluded.steering_station_mac",
            -1, &st, NULL) != SQLITE_OK)
        return AC_ROAMING_DOMAIN_DB_ERROR;
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, station_mac ? station_mac : "", -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : AC_ROAMING_DOMAIN_DB_ERROR;
}

int ac_roam_steering_enable(const char *domain_id, int64_t now)
{
    return ac_roam_steering_enable_scoped(domain_id, NULL, now);
}

/* Phase 4 circuit breaker.
 *
 * The handoff lists four independent trip conditions and requires any one of
 * them to disable the domain's forced actions and raise an alert.  They are
 * genuinely different failure shapes, so none can substitute for another:
 *
 *   1. deauth failure rate    -- the action does not work here
 *   2. return-to-source rate  -- it works, and the station comes straight back
 *                                (ping-pong: the worst outcome, because each
 *                                 round trip is another dropped connection)
 *   3. consecutive send failures -- the AP control path is broken
 *   4. candidate unreachable  -- we are steering at a target that is not there
 *
 * Returns 1 when forced actions are disabled on exit (whether this call
 * tripped it or it was already off), 0 while they remain enabled. */
static int ac_roam_deauth_auto_disable_check(const char *domain_id,
                                             int64_t now)
{
    static const double AC_DEAUTH_FAILURE_THRESHOLD = 0.5;
    static const double AC_DEAUTH_RETURN_THRESHOLD = 0.3;
    static const int AC_DEAUTH_MIN_ACTIONS = 3;
    static const int AC_DEAUTH_MAX_CONSECUTIVE_SEND_FAILURES = 3;
    static const int AC_DEAUTH_WINDOW_HOURS = 24;
    sqlite3_stmt *st = NULL;
    char reason[192];
    int64_t since;
    int total = 0;
    int failed = 0;
    int returned = 0;
    int consecutive = 0;
    int tripped = 0;

    if (!g_ac_db || !domain_id)
        return 0;
    /* Read the current state directly rather than via ac_roam_steering_enabled():
     * keeping this block free of guard-only helpers is what lets the breaker be
     * covered by the host fixture, and an untested circuit breaker is worth
     * very little. */
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT steering_enabled FROM ac_roaming_domain_action_state "
            "WHERE domain_id=?1", -1, &st, NULL) == SQLITE_OK) {
        int enabled = 1;

        sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW)
            enabled = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
        st = NULL;
        if (!enabled)
            return 1;
    }
    since = now - (int64_t)AC_DEAUTH_WINDOW_HOURS * 3600;

    /* Conditions 1 and 2 share one pass over the resolved actions. */
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT COUNT(*),"
            "SUM(CASE WHEN outcome IN ('timed_out','not_roamed') THEN 1 ELSE 0 END),"
            "SUM(CASE WHEN outcome='returned' THEN 1 ELSE 0 END) "
            "FROM ac_deauth_actions WHERE domain_id=?1 AND sent_ok=1 "
            "AND sent_at>=?2 AND outcome<>'pending'",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, since);
        if (sqlite3_step(st) == SQLITE_ROW) {
            total = sqlite3_column_int(st, 0);
            failed = sqlite3_column_int(st, 1);
            returned = sqlite3_column_int(st, 2);
        }
        sqlite3_finalize(st);
        st = NULL;
    }
    if (total >= AC_DEAUTH_MIN_ACTIONS) {
        double failure_rate = (double)failed / (double)total;
        double return_rate = (double)returned / (double)total;

        if (failure_rate >= AC_DEAUTH_FAILURE_THRESHOLD) {
            snprintf(reason, sizeof(reason),
                     "deauth_failure_rate_%.0f_pct_of_%d_actions",
                     failure_rate * 100.0, total);
            tripped = 1;
        } else if (return_rate >= AC_DEAUTH_RETURN_THRESHOLD) {
            snprintf(reason, sizeof(reason),
                     "deauth_station_returned_%.0f_pct_of_%d_actions",
                     return_rate * 100.0, total);
            tripped = 1;
        }
    }

    /* Condition 3: consecutive send failures, newest first.  Counted over
     * dispatch attempts rather than outcomes, because a control path that
     * cannot deliver the frame never produces an outcome at all -- so the
     * rate checks above would stay silent while nothing works. */
    if (!tripped && sqlite3_prepare_v2(g_ac_db,
            "SELECT sent_ok,outcome_reason FROM ac_deauth_actions "
            "WHERE domain_id=?1 AND sent_at>=?2 AND (sent_ok=1 OR outcome<>'pending') "
            "ORDER BY sent_at DESC,"
            "deauth_id DESC LIMIT ?3",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, since);
        sqlite3_bind_int(st, 3, AC_DEAUTH_MAX_CONSECUTIVE_SEND_FAILURES);
        while (sqlite3_step(st) == SQLITE_ROW) {
            if (sqlite3_column_int(st, 0))
                break;
            consecutive++;
        }
        sqlite3_finalize(st);
        st = NULL;
        if (consecutive >= AC_DEAUTH_MAX_CONSECUTIVE_SEND_FAILURES) {
            snprintf(reason, sizeof(reason),
                     "deauth_ap_control_failed_%d_consecutive", consecutive);
            tripped = 1;
        }
    }

    /* Condition 4: the target we steered at was not reachable.  A single
     * occurrence trips this one -- unlike a station declining to move, an
     * unreachable candidate means the decision itself was made on bad data,
     * and repeating it just drops the client again. */
    if (!tripped && sqlite3_prepare_v2(g_ac_db,
            "SELECT COUNT(*) FROM ac_deauth_actions WHERE domain_id=?1 "
            "AND sent_at>=?2 AND outcome_reason='candidate_unreachable'",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, since);
        if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_int(st, 0) > 0) {
            snprintf(reason, sizeof(reason),
                     "deauth_candidate_unreachable_%d_times",
                     sqlite3_column_int(st, 0));
            tripped = 1;
        }
        sqlite3_finalize(st);
    }
    if (!tripped)
        return 0;
    ac_roam_forced_action_disable(domain_id, reason, now);
    return 1;
}


#ifdef AC_DB_TEST_STANDALONE
/* Test-only surface for the Phase 4 audit and circuit breaker.
 *
 * These exist solely so the host fixture can drive the breaker through each
 * of its four trip conditions.  They are compiled out of the target build, so
 * nothing here widens the production API. */
int64_t ac_db_test_deauth_record(const char *domain_id, const char *station_mac,
                                 const char *ap_id, const char *source_bssid,
                                 const char *target_bssid, int64_t now)
{
    return ac_roam_deauth_record(domain_id, station_mac, ap_id, source_bssid,
                                 target_bssid, "", "policy", "", -80, "", "", 1,
                                 now);
}

void ac_db_test_deauth_mark_sent(int64_t deauth_id, int sent_ok,
                                 const char *failure_reason)
{
    ac_roam_deauth_mark_sent(deauth_id, sent_ok, failure_reason);
}

void ac_db_test_deauth_resolve(int64_t deauth_id, const char *current_bssid,
                               int64_t now)
{
    ac_roam_deauth_resolve_outcome(deauth_id, current_bssid, now);
}

void ac_db_test_deauth_check_outcomes(const char *domain_id, int64_t now)
{
    ac_roam_deauth_check_outcomes(domain_id, now);
}

int ac_db_test_deauth_breaker(const char *domain_id, int64_t now)
{
    return ac_roam_deauth_auto_disable_check(domain_id, now);
}

const char *ac_db_test_forced_action_reason(const char *domain_id)
{
    static char reason[192];
    sqlite3_stmt *st = NULL;

    reason[0] = '\0';
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT disabled_reason FROM ac_roaming_domain_action_state "
            "WHERE domain_id=?1 AND steering_enabled=0",
            -1, &st, NULL) != SQLITE_OK)
        return reason;
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        snprintf(reason, sizeof(reason), "%s", sqlite3_column_text(st, 0));
    sqlite3_finalize(st);
    return reason;
}
#endif /* AC_DB_TEST_STANDALONE */

/* ---- Phase 1: per-BSS capability readback -----------------------------------
 *
 * APD already publishes, per BSS, exactly the readback the Phase 1 handoff asks
 * for -- ft_supported / ft_over_ds / neighbor_report_80211k /
 * bss_transition_80211v / client_deauth, plus the resolved hostapd interface,
 * channel and station count -- and it is stored verbatim in
 * ac_ap_runtime.runtime_json under sources.hostapd.bss[].  Nothing read it,
 * which is why every member stayed at eligible=false forever.
 *
 * Everything here fails closed: an absent, stale or incomplete snapshot leaves
 * `found` at 0 and the member stays ineligible.  A member must never be
 * promoted because we could not find evidence against it. */

struct ac_roaming_bss_capability {
    int found;
    int ft_supported;
    int ft_over_ds;
    int neighbor_report_80211k;
    int bss_transition_80211v;
    int client_deauth;
    int reassoc_block;
    int station_count;
    int channel;
    int frequency_mhz;
    int hostapd_ctrl_reachable;
    int runtime_actions;
    char interface[64];
};

static void ac_roaming_bss_capability(const char *ap_id, const char *bssid,
                                      int64_t now,
                                      struct ac_roaming_bss_capability *out)
{
    sqlite3_stmt *st = NULL;
    struct json_object *snapshot = NULL;
    struct json_object *sources = NULL;
    struct json_object *hostapd = NULL;
    struct json_object *bss_list = NULL;
    const unsigned char *text;
    int64_t observed_at;
    size_t i;

    memset(out, 0, sizeof(*out));
    out->station_count = -1;
    if (!g_ac_db || !ap_id || !bssid || !bssid[0])
        return;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT observed_at,runtime_json,stale FROM ac_ap_runtime "
            "WHERE ap_id=?1", -1, &st, NULL) != SQLITE_OK)
        return;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        return;
    }
    observed_at = sqlite3_column_int64(st, 0);
    text = sqlite3_column_text(st, 1);
    snapshot = text ? json_tokener_parse((const char *)text) : NULL;
    if (sqlite3_column_int(st, 2) != 0 ||
        observed_at < now - AC_TELEMETRY_STALE_TIMEOUT_SECONDS) {
        sqlite3_finalize(st);
        json_object_put(snapshot);
        return;
    }
    sqlite3_finalize(st);
    /* A complete ordinary BSS remains usable when an unrelated MLO BSS
     * makes the aggregate partial. Missing or partial BSS evidence stays out. */
    if (!json_object_object_get_ex(snapshot, "sources", &sources) ||
        !json_object_object_get_ex(sources, "hostapd", &hostapd) ||
        !ac_db_json_bool(hostapd, "available") ||
        !json_object_object_get_ex(hostapd, "bss", &bss_list) ||
        !json_object_is_type(bss_list, json_type_array)) {
        json_object_put(snapshot);
        return;
    }
    for (i = 0; i < json_object_array_length(bss_list); i++) {
        struct json_object *bss = json_object_array_get_idx(bss_list, i);
        const char *entry_bssid = ac_db_json_string(bss, "bssid");
        const char *state = ac_db_json_string(bss, "state");
        struct json_object *value = NULL;

        if (!entry_bssid || strcasecmp(entry_bssid, bssid) ||
            (state && strcmp(state, "ENABLED")) ||
            (!ac_db_snapshot_hostapd_authoritative(snapshot) &&
             !ac_db_json_bool(bss, "complete")))
            continue;
        out->ft_supported = ac_db_json_bool(bss, "ft_supported");
        out->ft_over_ds = ac_db_json_bool(bss, "ft_over_ds");
        out->neighbor_report_80211k =
            ac_db_json_bool(bss, "neighbor_report_80211k");
        out->bss_transition_80211v =
            ac_db_json_bool(bss, "bss_transition_80211v");
        out->client_deauth = ac_db_json_bool(bss, "client_deauth");
        out->reassoc_block = ac_db_json_bool(bss, "reassoc_block");
        out->hostapd_ctrl_reachable =
            ac_db_json_bool(bss, "hostapd_ctrl_reachable");
        out->runtime_actions = ac_db_json_bool(hostapd, "runtime_actions");
        if (json_object_object_get_ex(bss, "station_count", &value) && value &&
            json_object_is_type(value, json_type_int))
            out->station_count = json_object_get_int(value);
        if (json_object_object_get_ex(bss, "channel", &value) && value &&
            json_object_is_type(value, json_type_int))
            out->channel = json_object_get_int(value);
        if (json_object_object_get_ex(bss, "frequency_mhz", &value) && value &&
            json_object_is_type(value, json_type_int))
            out->frequency_mhz = json_object_get_int(value);
        ac_radio_job_copy_text(out->interface, sizeof(out->interface),
            (const unsigned char *)ac_db_json_string(bss, "interface"));
        out->found = 1;
        break;
    }
    json_object_put(snapshot);
}

struct json_object *ac_db_roaming_domain_preflight_json(
    const char *domain_id, int64_t now)
{
    struct json_object *root = ac_db_roaming_domain_json(domain_id);
    struct json_object *domain = NULL;
    struct json_object *members = json_object_new_array();
    sqlite3_stmt *st = NULL;
    int eligible = 0;
    int excluded = 0;
    int domain_ft_enabled = 0;
    int domain_neighbor_enabled = 0;
    int domain_bss_transition_enabled = 0;

    if (!json_object_object_get_ex(root, "domain", &domain)) {
        json_object_put(members);
        return root;
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT DISTINCT a.ap_id,b.radio_id,b.ssid_id,b.bssid,"
            "a.adoption_state,a.last_seen_at,"
            "COALESCE(r.session_connected,0),COALESCE(r.write_capable,0),"
            "COALESCE(r.control_protocol_version,0),b.section_name,s.name "
            "FROM ac_roaming_domains d "
            "JOIN json_each(d.ap_group_ids_json) groups "
            "JOIN ac_ap_group_members gm ON gm.group_id=groups.value "
            "JOIN ac_aps a ON a.ap_id=gm.ap_id "
            "JOIN ac_ssid_bindings b ON b.ap_id=a.ap_id "
            "LEFT JOIN ac_ssids s ON s.ssid_id=b.ssid_id "
            "JOIN json_each(d.ssid_ids_json) ssids ON ssids.value=b.ssid_id "
            "LEFT JOIN ac_ap_runtime r ON r.ap_id=a.ap_id "
            "WHERE d.domain_id=?1 "
            "ORDER BY a.ap_id,b.radio_id,b.ssid_id",
            -1, &st, NULL) != SQLITE_OK) {
        json_object_put(root);
        json_object_put(members);
        root = json_object_new_object();
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "error",
                               json_object_new_string("database_error"));
        return root;
    }
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    domain_ft_enabled = ac_db_json_bool(domain, "ft_enabled");
    domain_neighbor_enabled = ac_db_json_bool(domain, "neighbor_report_enabled");
    domain_bss_transition_enabled =
        ac_db_json_bool(domain, "bss_transition_enabled");
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *member = json_object_new_object();
        const char *adoption_state = (const char *)sqlite3_column_text(st, 4);
        int64_t last_seen_at = sqlite3_column_int64(st, 5);
        const char *bssid = (const char *)sqlite3_column_text(st, 3);
        const char *reason = NULL;
        struct ac_roaming_bss_capability cap;
        int member_eligible = 0;

        memset(&cap, 0, sizeof(cap));
        if (!adoption_state || strcmp(adoption_state, "adopted"))
            reason = "ap_not_adopted";
        else if (last_seen_at < now - AC_AP_ONLINE_TIMEOUT_SECONDS ||
                 !sqlite3_column_int(st, 6))
            reason = "ap_offline";
        else if (sqlite3_column_int(st, 8) != 3 ||
                 !sqlite3_column_int(st, 7))
            reason = "write_capable_session_unavailable";
        else if (!bssid || !bssid[0])
            reason = "bssid_readback_unavailable";
        else {
            /* Per-BSS capability readback.  Each feature the domain turns on
             * must be supported by this BSS; a member that cannot do what the
             * domain asks is excluded by name rather than silently carried,
             * because an unsupported member still in the pool is what makes an
             * action look dispatched while doing nothing. */
            ac_roaming_bss_capability(
                (const char *)sqlite3_column_text(st, 0), bssid, now, &cap);
            if (!cap.found)
                reason = "roaming_capability_readback_pending";
            else if (!cap.hostapd_ctrl_reachable)
                reason = "hostapd_ctrl_unreachable";
            else if (domain_ft_enabled && !cap.ft_supported)
                reason = "ft_unsupported_by_member";
            else if (domain_neighbor_enabled && !cap.neighbor_report_80211k)
                reason = "neighbor_report_unsupported_by_member";
            else if (domain_bss_transition_enabled &&
                     !cap.bss_transition_80211v)
                reason = "bss_transition_unsupported_by_member";
            else {
                reason = ac_ssid_existing_binding(
                    (const char *)sqlite3_column_text(st, 0),
                    (const char *)sqlite3_column_text(st, 1),
                    (const char *)sqlite3_column_text(st, 9),
                    bssid, (const char *)sqlite3_column_text(st, 10),
                    now, NULL, NULL);
                if (!reason) {
                    reason = "capability_verified";
                    member_eligible = 1;
                }
            }
        }
        json_object_object_add(member, "ap_id", json_object_new_string(
            (const char *)sqlite3_column_text(st, 0)));
        json_object_object_add(member, "radio_id", json_object_new_string(
            (const char *)sqlite3_column_text(st, 1)));
        json_object_object_add(member, "ssid_id", json_object_new_string(
            (const char *)sqlite3_column_text(st, 2)));
        json_object_object_add(member, "bssid",
            json_object_new_string(bssid ? bssid : ""));
        json_object_object_add(member, "section_name", json_object_new_string(
            (const char *)sqlite3_column_text(st, 9)));
        json_object_object_add(member, "eligible",
                               json_object_new_boolean(member_eligible));
        /* Capability facts travel with the member so downstream stages do not
         * re-derive them: the FT fan-out gates ft_over_ds on this, Phase 2
         * scores on station_count, and Phase 4 gates deauth on client_deauth. */
        json_object_object_add(member, "ft_over_ds_capable",
                               json_object_new_boolean(cap.ft_over_ds));
        json_object_object_add(member, "client_deauth_capable",
                               json_object_new_boolean(cap.client_deauth));
        json_object_object_add(member, "station_count",
                               json_object_new_int(cap.station_count));
        json_object_object_add(member, "channel",
                               json_object_new_int(cap.channel));
        json_object_object_add(member, "frequency_mhz",
                               json_object_new_int(cap.frequency_mhz));
        json_object_object_add(member, "interface",
                               json_object_new_string(cap.interface));
        json_object_object_add(member, "reason", json_object_new_string(reason));
        json_object_object_add(member, "source",
                               json_object_new_string("ac_runtime_preflight"));
        json_object_array_add(members, member);
        if (member_eligible)
            eligible++;
        else
            excluded++;
    }
    sqlite3_finalize(st);
    json_object_object_add(root, "members", members);
    json_object_object_add(root, "eligible_count", json_object_new_int(eligible));
    json_object_object_add(root, "excluded_count", json_object_new_int(excluded));
    /* `valid` used to be a hardcoded false, which was honest while no member
     * could ever be cleared but is now wrong: it reports whether the domain has
     * anything to act on.  It stays false when the member set is empty, so an
     * empty domain is still not "valid". */
    json_object_object_add(root, "valid",
                           json_object_new_boolean(eligible > 0));
    json_object_object_add(root, "reason", json_object_new_string(
        eligible > 0 ?
            (excluded ? "partial_member_capability" : "all_members_verified") :
            (excluded ? "member_capability_readback_required" : "no_members")));
    json_object_object_add(root, "impact",
                           json_object_new_string("configuration_only"));
    json_object_object_add(root, "active_station_action",
                           json_object_new_boolean(0));
    return root;
}

/* forward declarations for Phase 3 static helpers (guarded for standalone test) */
#if !defined(AC_DB_TEST_STANDALONE) || defined(AC_DB_ROAMING_ACTIONS_TEST)
static int ac_roam_steering_enabled(const char *domain_id, const char *station_mac);
static int ac_roam_btm_check_outcomes(const char *domain_id, int64_t now, int outcome_window_sec);
static void ac_roam_deauth_check_outcomes(const char *domain_id, int64_t now);
static int ac_roam_btm_auto_disable_check(const char *domain_id, double failure_threshold, int min_actions, int window_hours, int64_t now);
static int ac_roam_btm_dispatch(const char *domain_id, const char *station_mac,
    const char *source_ap_id, const char *source_bssid,
    const char *target_bssid, const char *target_bssid_2,
    const char *bss_interface, int ft_enabled, int disassoc_imminent,
    int64_t now, char transaction_id[37]);
static int64_t ac_roam_btm_record(const char *domain_id, const char *station_mac,
    const char *ap_id, const char *source_bssid, const char *target_bssid,
    const char *target_bssid_2, const char *transaction_id, int64_t now);
static const char *ac_roaming_btm_limit_reason(const char *domain_id,
    const char *station_mac, struct json_object *policy, int64_t now);
static int ac_roaming_source_busy(const char *ap_id);
#endif /* !AC_DB_TEST_STANDALONE */

struct json_object *ac_db_roaming_domain_observe_json(
    const char *domain_id, const char *station_mac, const char *mode, int64_t now)
{
    struct json_object *root = ac_db_roaming_domain_preflight_json(domain_id, now);
    struct json_object *domain = NULL;
    struct json_object *station = json_object_new_object();
    struct json_object *members = NULL;
    struct json_object *candidates = NULL;
    struct json_object *audit_candidates = NULL;
    struct json_object *capability_snapshot = json_object_new_object();
    struct json_object *policy_json = NULL;
    struct json_object *policy = NULL;
    sqlite3_stmt *st = NULL;
    const char *reason = "station_not_observed";
    const char *decision = "no_action";
    int current_signal_dbm = 0;
    int signal_present = 0;
    int64_t policy_revision = 0;
    const char *steering_preference = "stability";
    int weak_rssi_dbm = -75;
    int minimum_candidate_gain_db = 10;
    int candidate_min_rssi_dbm = -67;
    int high_band_steer_enabled = 0;
    int lower_band_block_enabled = 0;
    int band_steer_mode = 0;
    int band_steer_min_rssi_dbm = -70;
    int band_steer_selected = 0;
    int comparison_signal_dbm = 0;
    int comparison_signal_measured = 0;
    int comparison_signal_cached = 0;
    int64_t comparison_signal_observed_at = 0;
    const char *comparison_signal_source = "unavailable";
    const char *comparison_signal_direction = "unknown";
    int weak_signal_observed = 0;
    int active_mode = mode && (!strcmp(mode, "active") ||
                               !strcmp(mode, "automatic"));
    char *current_ap_id = NULL;
    char *current_bssid = NULL;
    char *current_ssid_id = NULL;
    int64_t last_seen_at = 0;
    int station_observed = 0;
    char exclusion_rule_type[32] = {0};
    const char *exclusion_label = NULL;

    if (!json_object_object_get_ex(root, "domain", &domain))
        goto done;
    if (!ac_radio_job_mac_valid(station_mac)) {
        json_object_put(root);
        json_object_put(station);
        json_object_put(capability_snapshot);
        root = json_object_new_object();
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "error",
                               json_object_new_string("invalid_station_mac"));
        return root;
    }

    /* Load policy for scoring thresholds. */
    policy_json = ac_db_roaming_policy_json(domain_id);
    if (policy_json && json_object_get_boolean(
            json_object_object_get(policy_json, "ok"))) {
        policy = json_object_object_get(policy_json, "policy");
        if (policy) {
            struct json_object *v;
            v = json_object_object_get(policy, "revision");
            if (v) policy_revision = json_object_get_int64(v);
            v = json_object_object_get(policy, "weak_rssi_dbm");
            if (v) weak_rssi_dbm = json_object_get_int(v);
            v = json_object_object_get(policy, "minimum_candidate_gain_db");
            if (v) minimum_candidate_gain_db = json_object_get_int(v);
            v = json_object_object_get(policy, "candidate_min_rssi_dbm");
            if (v) candidate_min_rssi_dbm = json_object_get_int(v);
            v = json_object_object_get(policy, "steering_preference");
            if (v && json_object_get_string(v))
                steering_preference = json_object_get_string(v);
        }
    }
    high_band_steer_enabled = policy && json_object_get_boolean(
        json_object_object_get(policy, "high_band_steer_enabled"));
    lower_band_block_enabled = policy && json_object_get_boolean(
        json_object_object_get(policy, "lower_band_block_enabled"));
    if (policy) {
        struct json_object *bsv;
        bsv = json_object_object_get(policy, "band_steer_mode");
        if (bsv) band_steer_mode = json_object_get_int(bsv);
        bsv = json_object_object_get(policy, "band_steer_min_rssi_dbm");
        if (bsv) band_steer_min_rssi_dbm = json_object_get_int(bsv);
    }
    json_object_object_add(root, "steering_preference",
                           json_object_new_string(steering_preference));
    json_object_object_add(root, "high_band_steer_enabled",
        json_object_new_boolean(high_band_steer_enabled));
    json_object_object_add(root, "lower_band_block_enabled",
                           json_object_new_boolean(lower_band_block_enabled));

    /* Check exclusions first. */
    exclusion_label = ac_db_roaming_exclusion_check(
        domain_id, station_mac, NULL, exclusion_rule_type, sizeof(exclusion_rule_type));
    if (exclusion_label) {
        reason = exclusion_label;
        decision = "excluded";
        goto record;
    }

    /* Look up station session. */
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT s.ap_id,s.radio_id,s.ssid_id,s.connected_at,s.last_seen_at,"
            "s.runtime_json,b.bssid FROM ac_station_sessions s "
            "JOIN ac_ssid_bindings b ON b.ap_id=s.ap_id AND b.radio_id=s.radio_id "
            "AND b.ssid_id=s.ssid_id "
            "JOIN ac_roaming_domains d ON d.domain_id=?1 "
            "JOIN json_each(d.ssid_ids_json) ssids ON ssids.value=s.ssid_id "
            "JOIN json_each(d.ap_group_ids_json) groups "
            "JOIN ac_ap_group_members gm ON gm.group_id=groups.value "
            "AND gm.ap_id=s.ap_id "
            "WHERE s.mac=?2 AND s.disconnected_at=0 "
            "ORDER BY s.last_seen_at DESC LIMIT 1",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, station_mac, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *runtime_text =
                (const char *)sqlite3_column_text(st, 5);
            struct json_object *runtime = runtime_text ?
                json_tokener_parse(runtime_text) : NULL;
            const char *ap_str = (const char *)sqlite3_column_text(st, 0);
            const char *ssid_str = (const char *)sqlite3_column_text(st, 2);
            const char *bssid_str = (const char *)sqlite3_column_text(st, 6);

            current_ap_id = ap_str ? strdup(ap_str) : NULL;
            current_ssid_id = ssid_str ? strdup(ssid_str) : NULL;
            current_bssid = bssid_str ? strdup(bssid_str) : NULL;
            last_seen_at = sqlite3_column_int64(st, 4);
            signal_present = runtime &&
                json_object_is_type(runtime, json_type_object) &&
                ac_db_station_signal(runtime, &current_signal_dbm);
            station_observed = 1;

            json_object_object_add(station, "observed",
                                   json_object_new_boolean(1));
            json_object_object_add(station, "ap_id", json_object_new_string(
                current_ap_id ? current_ap_id : ""));
            json_object_object_add(station, "radio_id", json_object_new_string(
                (const char *)sqlite3_column_text(st, 1)));
            json_object_object_add(station, "ssid_id", json_object_new_string(
                current_ssid_id ? current_ssid_id : ""));
            json_object_object_add(station, "bssid", json_object_new_string(
                current_bssid ? current_bssid : ""));
            json_object_object_add(station, "connected_at",
                                   json_object_new_int64(
                                       sqlite3_column_int64(st, 3)));
            json_object_object_add(station, "last_seen_at",
                                   json_object_new_int64(last_seen_at));
            json_object_object_add(station, "complete",
                json_object_new_boolean(last_seen_at >=
                    now - AC_TELEMETRY_STALE_TIMEOUT_SECONDS));
            if (signal_present)
                json_object_object_add(station, "signal_dbm",
                                       json_object_new_int(current_signal_dbm));
            else
                json_object_object_add(station, "signal_dbm",
                                       json_object_new_null());
            json_object_object_add(station, "signal_source",
                json_object_new_string(signal_present ?
                    "station_runtime" : "unavailable"));
            json_object_object_add(station, "source",
                                   json_object_new_string("ac_station_sessions"));
            if (runtime && json_object_is_type(runtime, json_type_object)) {
                json_object_object_add(station, "runtime",
                    json_object_get(runtime));
                json_object_object_add(capability_snapshot, "station_runtime",
                    json_object_get(runtime));
                json_object_put(runtime);
            }
        }
    }
    sqlite3_finalize(st);
    st = NULL;

    if (!station_observed) {
        reason = "station_not_observed";
        decision = "no_action";
        goto record;
    }
    exclusion_label = ac_db_roaming_exclusion_check(
        domain_id, station_mac, current_ssid_id,
        exclusion_rule_type, sizeof(exclusion_rule_type));
    if (exclusion_label) {
        reason = exclusion_label;
        decision = "excluded";
        goto record;
    }

    /* Reason: telemetry stale. */
    if (last_seen_at < now - AC_TELEMETRY_STALE_TIMEOUT_SECONDS) {
        reason = "telemetry_stale";
        decision = "no_action";
        goto record;
    }

    /* Reason: telemetry incomplete (no signal data). */
    if (!signal_present) {
        reason = "telemetry_incomplete";
        decision = "no_action";
        goto record;
    }

#if !defined(AC_DB_TEST_STANDALONE) || defined(AC_DB_ROAMING_ACTIONS_TEST)
    if (active_mode) {
        struct ac_roaming_bss_capability owner;
        const char *limit_reason;

        ac_roam_btm_check_outcomes(domain_id, now, 120);
        ac_roam_btm_auto_disable_check(domain_id, 0.5, 3, 24, now);
        if (!policy) {
            reason = "roaming_policy_missing";
            goto record;
        }
        if (!ac_roam_steering_enabled(domain_id, station_mac) ||
            !ac_db_json_bool(domain, "bss_transition_enabled")) {
            reason = "steering_not_enabled";
            goto record;
        }
        if (!ac_roaming_station_btm_capable(
                json_object_object_get(station, "runtime"))) {
            reason = "station_btm_not_capable";
            goto record;
        }
        ac_roaming_bss_capability(current_ap_id, current_bssid, now, &owner);
        if (!owner.found || !owner.runtime_actions ||
            !owner.hostapd_ctrl_reachable || !owner.bss_transition_80211v) {
            reason = "source_runtime_actions_unavailable";
            goto record;
        }
        limit_reason = ac_roaming_btm_limit_reason(
            domain_id, station_mac, policy, now);
        if (limit_reason) {
            reason = limit_reason;
            goto record;
        }
        if (ac_roaming_source_busy(current_ap_id)) {
            reason = "source_action_busy";
            goto record;
        }
    }
#endif

    /* Check cooldown. */
    {
        int64_t cooldown_until = ac_db_roaming_cooldown_check(
            domain_id, station_mac, now);
        if (cooldown_until > 0) {
            reason = "cooldown_active";
            decision = "no_action";
            goto record;
        }
    }

    /* Check platform capability: all members must have capability readback. */
    members = json_object_object_get(root, "members");
    if (!members || !json_object_is_type(members, json_type_array) ||
        json_object_array_length(members) == 0) {
        reason = "no_members";
        decision = "no_action";
        goto record;
    }

    /* Check member eligibility reasons. */
    {
        size_t mi;
        int has_eligible = 0;
        for (mi = 0; mi < json_object_array_length(members); mi++) {
            struct json_object *m = json_object_array_get_idx(members, mi);
            const char *m_reason = ac_db_json_string(m, "reason");
            int m_eligible = json_object_get_boolean(
                json_object_object_get(m, "eligible"));
            if (m_eligible)
                has_eligible = 1;
            (void)m_reason;
        }
        if (!has_eligible) {
            struct json_object *first_member = json_object_array_get_idx(members, 0);
            const char *first_reason = ac_db_json_string(first_member, "reason");
            if (first_reason && !strcmp(first_reason, "ap_offline")) {
                reason = "target_offline";
            } else if (first_reason && !strcmp(first_reason, "ap_not_adopted")) {
                reason = "ownership_missing";
            } else if (first_reason &&
                       !strcmp(first_reason, "write_capable_session_unavailable")) {
                reason = "platform_capability_false";
            } else {
                reason = "no_qualified_candidates";
            }
            decision = "no_action";
            goto record;
        }
    }

    /* Score candidates. */
    candidates = ac_db_roaming_candidates_score(
        domain_id, station_mac, members, json_object_object_get(station, "runtime"),
        current_signal_dbm,
        ac_roaming_iphone_probe_scope(station_mac, current_ssid_id),
        high_band_steer_enabled, now);
    if (!candidates || json_object_array_length(candidates) == 0) {
        reason = "no_qualified_candidates";
        decision = "no_action";
        goto record;
    }
    comparison_signal_measured = ac_roaming_beacon_signal(
        station_mac, current_bssid, now, &comparison_signal_dbm,
        &comparison_signal_cached, &comparison_signal_observed_at);
    if (comparison_signal_measured) {
        comparison_signal_source = comparison_signal_cached ?
            "ieee80211k_beacon_table" : "ieee80211k_beacon_report";
        comparison_signal_direction = "downlink";
    } else if (signal_present &&
               ac_roaming_iphone_probe_scope(station_mac, current_ssid_id)) {
        comparison_signal_dbm = current_signal_dbm;
        comparison_signal_measured = 1;
        comparison_signal_observed_at = last_seen_at;
        comparison_signal_source = "ap_station_signal";
        comparison_signal_direction = "uplink";
    }
    weak_signal_observed = comparison_signal_measured &&
        (!strcmp(steering_preference, "performance") ||
         comparison_signal_dbm <= weak_rssi_dbm);
    json_object_object_add(root, "comparison_signal_source",
        json_object_new_string(comparison_signal_source));
    json_object_object_add(root, "comparison_signal_direction",
        json_object_new_string(comparison_signal_direction));
    json_object_object_add(root, "comparison_signal_cached",
        json_object_new_boolean(comparison_signal_cached));
    json_object_object_add(root, "comparison_signal_observed_at",
        comparison_signal_observed_at > 0 ?
            json_object_new_int64(comparison_signal_observed_at) :
            json_object_new_null());
    json_object_object_add(root, "comparison_signal_measured",
                           json_object_new_boolean(comparison_signal_measured));
    json_object_object_add(root, "comparison_signal_dbm",
        comparison_signal_measured ? json_object_new_int(comparison_signal_dbm) :
                                     json_object_new_null());
    json_object_object_add(root, "weak_signal_observed",
                           json_object_new_boolean(weak_signal_observed));
    if (!strcmp(steering_preference, "stability") &&
        ac_roaming_iphone_probe_scope(station_mac, current_ssid_id) &&
        !weak_signal_observed) {
        reason = "signal_above_threshold";
        decision = "no_action";
        goto record;
    }

    /* Find best eligible candidate. */
    {
        size_t ci;
        size_t mi;
        int best_score[2] = { INT_MIN, INT_MIN };
        struct json_object *best[2] = { NULL, NULL };
        int eligible_count = 0;
        int measured_count = 0;
        int same_direction_count = 0;
        int strong_count = 0;
        int overloaded = 0;
        int source_band = 0;

        /* Determine the source BSS band for lower-band blocking and band steering. */
        source_band = 0;
        if ((lower_band_block_enabled || band_steer_mode) && members && current_bssid) {
            for (mi = 0; mi < json_object_array_length(members); mi++) {
                struct json_object *m = json_object_array_get_idx(members, mi);
                const char *m_bssid = ac_db_json_string(m, "bssid");
                if (m_bssid && !strcasecmp(m_bssid, current_bssid)) {
                    int m_freq = json_object_get_int(
                        json_object_object_get(m, "frequency_mhz"));
                    source_band = m_freq >= 5925 ? 3 :
                                  m_freq >= 4900 ? 2 :
                                  m_freq >= 2400 ? 1 : 0;
                    break;
                }
            }
        }
        for (ci = 0; ci < json_object_array_length(candidates); ci++) {
            struct json_object *c = json_object_array_get_idx(candidates, ci);
            int elig = json_object_get_boolean(
                json_object_object_get(c, "eligible"));
            int sc = json_object_get_int(json_object_object_get(c, "score"));
            const char *bssid = ac_db_json_string(c, "bssid");
            const char *ssid = ac_db_json_string(c, "ssid_id");
            const char *ap_id = ac_db_json_string(c, "ap_id");
            const char *direction = ac_db_json_string(c, "signal_direction");

            if (elig && bssid && current_bssid &&
                strcasecmp(bssid, current_bssid) &&
                ssid && current_ssid_id && !strcmp(ssid, current_ssid_id)) {
                int signal;

        eligible_count++;
        /* Lower-band block: when enabled, reject candidates on a band
         * below the source BSS's band (e.g. 2.4 GHz source blocks 2.4 GHz
         * targets; 5 GHz source also blocks 2.4 GHz targets). */
        if (lower_band_block_enabled) {
            int c_freq = json_object_get_int(
                json_object_object_get(c, "frequency_mhz"));
            int candidate_band = c_freq >= 5925 ? 3 :
                                 c_freq >= 4900 ? 2 :
                                 c_freq >= 2400 ? 1 : 0;
            if (source_band > 0 && candidate_band > 0 &&
                candidate_band < source_band) {
                eligible_count--;
                continue;
            }
        }
                if (!ac_db_json_bool(c, "signal_measured"))
                    continue;
                measured_count++;
                if (!comparison_signal_measured)
                    continue;
                if (!direction || strcmp(direction, comparison_signal_direction))
                    continue;
                same_direction_count++;
                signal = json_object_get_int(
                    json_object_object_get(c, "signal_estimate_dbm"));
                if (signal < candidate_min_rssi_dbm)
                    continue;
                strong_count++;
                if (signal - comparison_signal_dbm < minimum_candidate_gain_db)
                    continue;
                if (json_object_get_int(json_object_object_get(
                        c, "station_count")) > 50) {
                    overloaded = 1;
                    continue;
                }
                if (sc > best_score[0]) {
                    if (!best[0] || !ap_id ||
                        strcmp(ap_id, ac_db_json_string(best[0], "ap_id"))) {
                        best_score[1] = best_score[0];
                        best[1] = best[0];
                    }
                    best_score[0] = sc;
                    best[0] = c;
                } else if ((!best[0] || !ap_id ||
                            strcmp(ap_id, ac_db_json_string(best[0], "ap_id"))) &&
                           sc > best_score[1]) {
                    best_score[1] = sc;
                    best[1] = c;
                }
            }
        }

        /* UniFi-style band steering (BTM). When no MEASURED roam candidate
         * qualifies (e.g. the client never returns 802.11k measurements), a
         * station that is strong on a low band while THIS SAME physical AP
         * also offers a higher band can still be steered up: co-location
         * proves the higher band is reachable, so no client measurement is
         * needed. Gated behind band_steer_mode (default 0=off) and the same
         * steering-enabled master gate, so observe-only domains are untouched. */
        if (!best[0] && band_steer_mode && active_mode &&
            source_band > 0 && comparison_signal_measured &&
            comparison_signal_dbm >= band_steer_min_rssi_dbm &&
            ac_roam_steering_enabled(domain_id, station_mac)) {
            size_t bi;
            int bs_band = source_band;
            for (bi = 0; bi < json_object_array_length(candidates); bi++) {
                struct json_object *c = json_object_array_get_idx(candidates, bi);
                const char *c_bssid = ac_db_json_string(c, "bssid");
                const char *c_ap = ac_db_json_string(c, "ap_id");
                const char *c_ssid = ac_db_json_string(c, "ssid_id");
                int c_freq, c_band;
                if (!json_object_get_boolean(
                        json_object_object_get(c, "eligible")))
                    continue;
                if (!c_bssid || !current_bssid ||
                    !strcasecmp(c_bssid, current_bssid))
                    continue;
                if (!c_ap || !current_ap_id || strcmp(c_ap, current_ap_id))
                    continue;  /* same physical AP only */
                if (!c_ssid || !current_ssid_id ||
                    strcmp(c_ssid, current_ssid_id))
                    continue;
                c_freq = json_object_get_int(
                    json_object_object_get(c, "frequency_mhz"));
                c_band = c_freq >= 5925 ? 3 : c_freq >= 4900 ? 2 :
                         c_freq >= 2400 ? 1 : 0;
                if (c_band <= source_band)
                    continue;  /* only steer up */
                if (c_band > bs_band) {  /* prefer the highest available band */
                    bs_band = c_band;
                    best[0] = c;
                    best_score[0] = json_object_get_int(
                        json_object_object_get(c, "score"));
                    band_steer_selected = 1;
                }
            }
        }

        if (!best[0]) {
            reason = !eligible_count ? "no_qualified_candidates" :
                     !measured_count ? "candidate_measurements_missing" :
                     !comparison_signal_measured ? "serving_measurement_missing" :
                     !same_direction_count ? "candidate_signal_direction_mismatch" :
                     !strong_count ? "candidate_below_minimum_rssi" :
                     overloaded ? "target_overloaded" : "gain_insufficient";
            decision = "no_action";
            goto record;
        }

        /* All checks passed.  In observe-only mode we still don't act.
         * In active mode, dispatch BTM if steering is enabled. */
#if !defined(AC_DB_TEST_STANDALONE) || defined(AC_DB_ROAMING_ACTIONS_TEST)
        if (active_mode &&
            ac_roam_steering_enabled(domain_id, station_mac)) {
            const char *target_ap_id = ac_db_json_string(best[0], "ap_id");
            const char *target_bssid_best = ac_db_json_string(best[0], "bssid");
            const char *target_bssid_second = best[1] &&
                ac_roaming_iphone_probe_scope(station_mac, current_ssid_id) ?
                ac_db_json_string(best[1], "bssid") : NULL;
            int64_t btm_id;
            int dispatch_rc;
            char transaction_id[37] = {0};

            btm_id = ac_roam_btm_record(
                domain_id, station_mac, current_ap_id,
                current_bssid, target_bssid_best, target_bssid_second, "", now);
            if (btm_id <= 0) {
                reason = "btm_audit_failed";
                goto record;
            }
            /* Dispatch BTM via wifi transaction channel.
             *
             * The BSS interface must be the real hostapd interface name
             * (ath0, wlan0-1, ...): APD turns this section identifier into a
             * control-socket path.  Passing NULL made it fall back to the AP
             * UUID, which can never resolve to a socket, so every dispatch
             * would fail at the AP while the controller recorded a send. */
            {
                struct ac_roaming_bss_capability owner_cap;

                ac_roaming_bss_capability(current_ap_id, current_bssid, now,
                                          &owner_cap);
                dispatch_rc = ac_roam_btm_dispatch(
                    domain_id, station_mac, current_ap_id,
                    current_bssid, target_bssid_best, target_bssid_second,
                    owner_cap.found && owner_cap.interface[0] ?
                        owner_cap.interface : NULL,
                    ac_db_json_bool(domain, "ft_enabled"),
                    ac_roaming_iphone_probe_scope(station_mac, current_ssid_id) ?
                        1 : 0, now,
                    transaction_id);
            }
            if (sqlite3_prepare_v2(g_ac_db,
                    "UPDATE ac_btm_actions SET transaction_id=?2,"
                    "outcome_reason=?3 WHERE btm_id=?1", -1, &st, NULL) == SQLITE_OK) {
                sqlite3_bind_int64(st, 1, btm_id);
                sqlite3_bind_text(st, 2, transaction_id, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(st, 3, dispatch_rc == 0 ?
                    "config_job_queued" : "config_dispatch_failed", -1, SQLITE_STATIC);
                sqlite3_step(st);
                sqlite3_finalize(st);
                st = NULL;
            }
            if (dispatch_rc == 0) {
                reason = band_steer_selected ? "band_steer_btm_queued" : "btm_queued";
                decision = "roam";
                ac_db_roaming_cooldown_record(domain_id, station_mac,
                    json_object_get_int(json_object_object_get(
                        policy, "post_roam_cooldown_sec")), "btm_queued", now);
                json_object_object_add(root, "btm_id",
                    json_object_new_int64(btm_id));
                json_object_object_add(root, "transaction_id",
                    json_object_new_string(transaction_id));
                json_object_object_add(root, "target_ap_id",
                    json_object_new_string(target_ap_id ?
                        target_ap_id : ""));
                json_object_object_add(root, "target_bssid",
                    json_object_new_string(target_bssid_best ?
                        target_bssid_best : ""));
                json_object_object_add(root, "target_bssid_2",
                    json_object_new_string(target_bssid_second ?
                        target_bssid_second : ""));
                json_object_object_add(root, "btm_disassoc_imminent",
                    json_object_new_boolean(
                        ac_roaming_iphone_probe_scope(station_mac,
                                                      current_ssid_id)));
            } else {
                reason = "btm_dispatch_failed";
                decision = "no_action";
                json_object_object_add(root, "btm_id",
                    json_object_new_int64(btm_id));
            }
        } else
#endif /* !AC_DB_TEST_STANDALONE */
        {
            reason = "observe_only_no_action";
            decision = "would_roam";
        }
    }

record:
    /* Build audit candidates array. */
    audit_candidates = json_object_new_array();
    if (candidates) {
        size_t ci;
        for (ci = 0; ci < json_object_array_length(candidates); ci++) {
            struct json_object *c = json_object_array_get_idx(candidates, ci);
            struct json_object *ac_entry = json_object_new_object();
            struct json_object *tmp;
            tmp = json_object_object_get(c, "ap_id");
            json_object_object_add(ac_entry, "ap_id", tmp ? json_object_get(tmp) : json_object_new_string(""));
            tmp = json_object_object_get(c, "bssid");
            json_object_object_add(ac_entry, "bssid", tmp ? json_object_get(tmp) : json_object_new_string(""));
            tmp = json_object_object_get(c, "score");
            json_object_object_add(ac_entry, "score", tmp ? json_object_get(tmp) : json_object_new_int(0));
            tmp = json_object_object_get(c, "eligible");
            json_object_object_add(ac_entry, "eligible", tmp ? json_object_get(tmp) : json_object_new_boolean(0));
            tmp = json_object_object_get(c, "reason");
            json_object_object_add(ac_entry, "reason", tmp ? json_object_get(tmp) : json_object_new_string(""));
            json_object_array_add(audit_candidates, ac_entry);
        }
    }

    /* Automatic polling records changed decisions and an hourly checkpoint,
     * not a growing copy of the same no-action result every timer tick. */
    {
        int record_audit = 1;

        if (mode && !strcmp(mode, "automatic") && strcmp(decision, "roam") &&
            sqlite3_prepare_v2(g_ac_db,
                "SELECT decision,reason,current_bssid,observed_at "
                "FROM ac_roaming_audit WHERE domain_id=?1 AND station_mac=?2 "
                "ORDER BY audit_id DESC LIMIT 1", -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, station_mac, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(st) == SQLITE_ROW)
                record_audit = strcmp((const char *)sqlite3_column_text(st, 0), decision) ||
                    strcmp((const char *)sqlite3_column_text(st, 1), reason) ||
                    strcmp((const char *)sqlite3_column_text(st, 2),
                           current_bssid ? current_bssid : "") ||
                    sqlite3_column_int64(st, 3) < now - 3600;
            sqlite3_finalize(st);
            st = NULL;
        }
        if (record_audit)
            ac_db_roaming_audit_record(domain_id, station_mac, now,
                current_ap_id, current_bssid, current_signal_dbm,
                audit_candidates, decision, reason, policy_revision,
                capability_snapshot);
    }

    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT s.last_evaluated_at,s.last_measurement_at,"
            "s.measurement_transaction_id,t.state,t.error_code "
            "FROM ac_roaming_station_state s LEFT JOIN ac_transaction_targets t "
            "ON t.transaction_id=s.measurement_transaction_id "
            "WHERE s.domain_id=?1 AND s.station_mac=?2 LIMIT 1",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, station_mac, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *measurement = json_object_new_object();

            json_object_object_add(measurement, "last_evaluated_at",
                json_object_new_int64(sqlite3_column_int64(st, 0)));
            json_object_object_add(measurement, "requested_at",
                json_object_new_int64(sqlite3_column_int64(st, 1)));
            json_object_object_add(measurement, "transaction_id",
                json_object_new_string((const char *)sqlite3_column_text(st, 2)));
            json_object_object_add(measurement, "state",
                json_object_new_string(sqlite3_column_text(st, 3) ?
                    (const char *)sqlite3_column_text(st, 3) : "not_requested"));
            json_object_object_add(measurement, "error",
                json_object_new_string(sqlite3_column_text(st, 4) ?
                    (const char *)sqlite3_column_text(st, 4) : ""));
            json_object_object_add(root, "measurement", measurement);
        }
        sqlite3_finalize(st);
        st = NULL;
    }

    /* Assemble response. */
    if (!json_object_object_length(station)) {
        json_object_object_add(station, "observed",
                               json_object_new_boolean(0));
        json_object_object_add(station, "complete",
                               json_object_new_boolean(0));
        json_object_object_add(station, "source",
                               json_object_new_string("ac_station_sessions"));
    }
    json_object_object_add(root, "station_mac",
                           json_object_new_string(station_mac));
    json_object_object_add(root, "station", station);
    station = NULL;
    json_object_object_add(root, "mode",
                           json_object_new_string(mode ? mode : "observe_only"));
    json_object_object_add(root, "actionable",
        json_object_new_boolean(active_mode &&
            !strcmp(decision, "roam")));
    json_object_object_add(root, "reason",
                           json_object_new_string(reason));
    json_object_object_add(root, "proposal", json_object_new_null());
    json_object_object_add(root, "simulated_outcome",
                           json_object_new_string("no_action"));
    json_object_object_add(root, "active_station_action",
                           json_object_new_boolean(0));
    json_object_object_add(root, "source",
                           json_object_new_string(active_mode ?
                               (mode && !strcmp(mode, "automatic") ?
                                "ac_automatic_steering" : "ac_active_steering") :
                               "ac_observe_only"));
    json_object_object_add(root, "observed_at", json_object_new_int64(now));
    json_object_object_add(root, "candidates",
        candidates ? candidates : json_object_new_array());
    json_object_object_add(root, "policy_revision",
                           json_object_new_int64(policy_revision));
    json_object_object_add(root, "decision",
                           json_object_new_string(decision));
done:
    sqlite3_finalize(st);
    json_object_put(station);
    json_object_put(audit_candidates);
    json_object_put(capability_snapshot);
    json_object_put(policy_json);
    free(current_ap_id);
    free(current_bssid);
    free(current_ssid_id);
    return root;
}


/* ---- Phase 3: neighbour report RF descriptors -------------------------------
 *
 * A hostapd SET_NEIGHBOR needs the neighbour's real operating class, channel
 * and PHY type, because they go into the Neighbor Report element the station
 * actually receives.  The previous code emitted a fixed opclass 115 with
 * channel 0 and a comment claiming APD would resolve it; APD has no such
 * resolution and passed both straight through, so every neighbour was
 * advertised as "5 GHz U-NII-1, channel 0" regardless of where it really was.
 *
 * The controller is the only side that knows every member's radio, so the
 * descriptor is resolved here and APD is left to assemble the wire format. */

struct ac_roaming_neighbor_rf {
    int op_class;
    int channel;
    int phy_type;
    char ssid[64];
    int resolved;
};

/* IEEE 802.11 Annex E global operating classes, 20 MHz entries only.  A
 * neighbour report advertises the primary channel, so the wider-bandwidth
 * classes are deliberately not used here.
 *
 * Not static: the fixture exercises the mapping directly.  Getting a class
 * wrong sends the station scanning the wrong band, and the only place that
 * shows up otherwise is on real hardware. */
int ac_roaming_global_op_class(const char *band, int channel)
{
    if (!band || channel <= 0)
        return 0;
    if (!strcmp(band, "2.4GHz"))
        return channel == 14 ? 82 : (channel <= 13 ? 81 : 0);
    if (!strcmp(band, "5GHz")) {
        if (channel >= 36 && channel <= 48) return 115;
        if (channel >= 52 && channel <= 64) return 118;
        if (channel >= 100 && channel <= 144) return 121;
        if (channel >= 149 && channel <= 169) return 125;
        return 0;
    }
    if (!strcmp(band, "6GHz"))
        return (channel >= 1 && channel <= 233) ? 131 : 0;
    return 0;
}

/* dot11PHYType, per src/common/ieee802_11_defs.h.  Derived from the band
 * rather than from a per-radio capability readback, which the controller does
 * not collect yet: the value is advisory to the station, and being one
 * generation conservative is harmless where claiming a wrong channel is not. */
int ac_roaming_phy_type(const char *band)
{
    if (!band)
        return 0;
    if (!strcmp(band, "6GHz"))
        return 14;  /* PHY_TYPE_HE -- 6 GHz cannot be anything older. */
    if (!strcmp(band, "5GHz"))
        return 9;   /* PHY_TYPE_VHT */
    if (!strcmp(band, "2.4GHz"))
        return 7;   /* PHY_TYPE_HT */
    return 0;
}

#if !defined(AC_DB_TEST_STANDALONE) || defined(AC_DB_ROAMING_ACTIONS_TEST)
/* Resolve one member's neighbour descriptor from stored radio runtime plus the
 * configured SSID name.  Leaves out->resolved at 0 when anything is missing so
 * callers drop the neighbour instead of advertising a fabricated one. */
static void ac_roaming_neighbor_rf(const char *ap_id, const char *radio_id,
                                   const char *ssid_id, int64_t now,
                                   struct ac_roaming_neighbor_rf *out)
{
    sqlite3_stmt *st = NULL;
    struct ac_roaming_bss_capability cap;
    char bssid[18] = {0};
    const char *band;

    memset(out, 0, sizeof(*out));
    if (!g_ac_db || !ap_id || !radio_id)
        return;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT b.bssid,s.name FROM ac_ssid_bindings b "
            "JOIN ac_ssids s ON s.ssid_id=b.ssid_id "
            "WHERE b.ap_id=?1 AND b.radio_id=?2 AND b.ssid_id=?3",
            -1, &st, NULL) != SQLITE_OK)
        return;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, radio_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, ssid_id ? ssid_id : "", -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        ac_radio_job_copy_text(bssid, sizeof(bssid), sqlite3_column_text(st, 0));
        ac_radio_job_copy_text(out->ssid, sizeof(out->ssid),
                               sqlite3_column_text(st, 1));
    }
    sqlite3_finalize(st);
    /* A shared wiphy's radio row can describe a different active link.
     * The target BSS's hostapd STATUS is the authoritative RF descriptor. */
    ac_roaming_bss_capability(ap_id, bssid, now, &cap);
    if (!cap.found || !cap.hostapd_ctrl_reachable || !out->ssid[0])
        return;
    band = cap.frequency_mhz >= 5955 && cap.frequency_mhz <= 7115 ? "6GHz" :
           cap.frequency_mhz >= 4900 && cap.frequency_mhz < 5925 ? "5GHz" :
           cap.frequency_mhz >= 2412 && cap.frequency_mhz <= 2484 ? "2.4GHz" : NULL;
    out->channel = cap.channel;
    out->op_class = ac_roaming_global_op_class(band, out->channel);
    out->phy_type = ac_roaming_phy_type(band);
    if (out->op_class <= 0 || out->channel <= 0 || out->phy_type <= 0)
        return;

    out->resolved = 1;
}

static struct json_object *ac_roaming_neighbor_section(
    struct json_object *owner, struct json_object *peer, int checked,
    int64_t now)
{
    const char *bssid = ac_db_json_string(peer, "bssid");
    struct ac_roaming_neighbor_rf rf;
    struct json_object *section, *options;
    char number[12];

    if (!bssid || !bssid[0] ||
        !strcasecmp(bssid, ac_db_json_string(owner, "bssid")) ||
        strcmp(ac_db_json_string(owner, "ssid_id"),
               ac_db_json_string(peer, "ssid_id")))
        return NULL;
    ac_roaming_neighbor_rf(ac_db_json_string(peer, "ap_id"),
        ac_db_json_string(peer, "radio_id"), ac_db_json_string(peer, "ssid_id"),
        now, &rf);
    if (!rf.resolved)
        return NULL;
    section = json_object_new_object();
    options = json_object_new_object();
    json_object_object_add(options, "hostapd_action_type",
                           json_object_new_string("set_neighbor"));
    json_object_object_add(options, "neighbor_bssid", json_object_new_string(bssid));
    json_object_object_add(options, "neighbor_ssid", json_object_new_string(rf.ssid));
    snprintf(number, sizeof(number), "%d", rf.op_class);
    json_object_object_add(options, "neighbor_opclass", json_object_new_string(number));
    snprintf(number, sizeof(number), "%d", rf.channel);
    json_object_object_add(options, "neighbor_channel", json_object_new_string(number));
    snprintf(number, sizeof(number), "%d", rf.phy_type);
    json_object_object_add(options, "neighbor_phy", json_object_new_string(number));
    if (checked) {
        json_object_object_add(options, "source_bssid",
            json_object_new_string(ac_db_json_string(owner, "bssid")));
        json_object_object_add(options, "source_ssid", json_object_new_string(rf.ssid));
    }
    json_object_object_add(section, "section", json_object_new_string(
        ac_db_json_string(owner, checked ? "interface" : "bssid")));
    json_object_object_add(section, "options", options);
    return section;
}
#endif /* !AC_DB_TEST_STANDALONE */

/* ---- Phase 1: FT (802.11r) key material ------------------------------------
 *
 * hostapd wants one line per peer:
 *
 *     r0kh=<MAC> <R0KH-ID> <256-bit key as hex>
 *     r1kh=<MAC> <R1KH-ID> <256-bit key as hex>
 *
 * Two properties this code has to get right, both of which are easy to get
 * silently wrong:
 *
 * 1. The fields are SPACE separated.  hostapd's add_r0kh()/add_r1kh() split on
 *    ' ' and reject the line outright when there is none, so a comma-separated
 *    line is not "mostly right", it is dropped with "Invalid R0KH MAC address".
 *
 * 2. The key is per ORDERED PAIR, not per AP.  The PMK-R0 holder X and the
 *    PMK-R1 holder Y must present the same secret for the link X->Y: it appears
 *    in Y's r0kh list (as "fetch from X with this key") and in X's r1kh list (as
 *    "answer Y with this key").  Deriving from ("self", "other") instead of the
 *    ordered pair yields two different keys for one link and FT fails at the
 *    first roam, with nothing in the logs pointing here.
 *
 * The master secret is per domain and lives in the encrypted secret store
 * (ac_secrets.c), versioned by the domain's key_revision -- so bumping
 * key_revision and re-applying rotates every link key in the domain at once.
 * There is deliberately no fallback constant: with no secret store we fail the
 * apply rather than fan out a guessable key. */

#define AC_ROAMING_FT_MASTER_BYTES 32
#define AC_ROAMING_FT_KEY_BYTES    32
#define AC_ROAMING_FT_KEY_HEX_LEN  (AC_ROAMING_FT_KEY_BYTES * 2)
#define AC_ROAMING_FT_SECRET_PREFIX "roaming-ft/"

static struct ac_secrets *g_ac_roaming_secrets;

/* Injected once at startup from ac_main.c; NULL in unit tests that do not
 * exercise the FT path, which makes those paths fail closed rather than
 * silently derive from nothing. */
void ac_db_set_secrets(struct ac_secrets *secrets)
{
    g_ac_roaming_secrets = secrets;
}

static void ac_roaming_ft_hex(const unsigned char *bytes, size_t len,
                              char *out)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++) {
        out[i * 2] = digits[bytes[i] >> 4];
        out[i * 2 + 1] = digits[bytes[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

/* Fetch (or create on first use) the domain's FT master secret for this
 * key_revision.  Returns 0 on success; caller releases via ac_secrets_clear. */
static int ac_roaming_ft_master(const char *domain_id, int64_t key_revision,
                                unsigned char **out, size_t *out_len)
{
    char secret_id[AC_SECRET_ID_MAX];
    unsigned char fresh[AC_ROAMING_FT_MASTER_BYTES];
    /* ac_secrets enforces CHECK(version > 0) while key_revision starts at 0,
     * so the store version is always key_revision + 1.  Keep the two in step:
     * reading with a different offset than the write silently regenerates the
     * master and invalidates every key in the domain. */
    uint64_t version;
    int written;
    int rc;

    if (!g_ac_roaming_secrets || !domain_id || !out || !out_len ||
        key_revision < 0)
        return -1;
    version = (uint64_t)key_revision + 1;
    written = snprintf(secret_id, sizeof(secret_id), "%s%s",
                       AC_ROAMING_FT_SECRET_PREFIX, domain_id);
    if (written < 0 || (size_t)written >= sizeof(secret_id))
        return -1;

    rc = ac_secrets_get(g_ac_roaming_secrets, secret_id, version,
                        out, out_len);
    if (rc == AC_SECRETS_OK && *out && *out_len >= AC_ROAMING_FT_MASTER_BYTES)
        return 0;
    if (rc == AC_SECRETS_OK && *out) {
        /* Present but too short to be usable -- refuse rather than stretch it. */
        ac_secrets_clear(*out, *out_len);
        *out = NULL;
        return -1;
    }

    if (RAND_bytes(fresh, sizeof(fresh)) != 1)
        return -1;
    rc = ac_secrets_put(g_ac_roaming_secrets, secret_id, version,
                        fresh, sizeof(fresh));
    OPENSSL_cleanse(fresh, sizeof(fresh));
    if (rc != AC_SECRETS_OK)
        return -1;
    if (ac_secrets_get(g_ac_roaming_secrets, secret_id, version,
                       out, out_len) != AC_SECRETS_OK ||
        !*out || *out_len < AC_ROAMING_FT_MASTER_BYTES)
        return -1;
    return 0;
}

/* Derive the shared key for the directed link r0kh_id -> r1kh_id.  Both APs
 * compute this identically because the input is the ordered pair, not their
 * own role. */
static int ac_roaming_ft_link_key(const unsigned char *master,
                                  size_t master_len,
                                  const char *r0kh_id, const char *r1kh_id,
                                  char out_hex[AC_ROAMING_FT_KEY_HEX_LEN + 1])
{
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;
    unsigned char message[256];
    int written;

    if (!master || master_len == 0 || !r0kh_id || !r1kh_id)
        return -1;
    written = snprintf((char *)message, sizeof(message),
                       "dreamingwrt-ft-link|%s|%s", r0kh_id, r1kh_id);
    if (written < 0 || (size_t)written >= sizeof(message))
        return -1;
    if (!HMAC(EVP_sha256(), master, (int)master_len, message,
              (size_t)written, mac, &mac_len) ||
        mac_len < AC_ROAMING_FT_KEY_BYTES)
        return -1;
    ac_roaming_ft_hex(mac, AC_ROAMING_FT_KEY_BYTES, out_hex);
    OPENSSL_cleanse(mac, sizeof(mac));
    return 0;
}

/* Phase 1: Apply roaming-domain configuration to all eligible members.
 * Builds per-AP candidates with 11r/k/v options and FT key material,
 * then dispatches via the existing wifi transaction channel. */
struct json_object *ac_db_roaming_domain_apply_json(
    const char *domain_id, const char *consistency, int64_t now)
{
    struct json_object *root = json_object_new_object();
    struct json_object *preflight = NULL;
    struct json_object *domain = NULL;
    struct json_object *members = NULL;
    struct json_object *targets = json_object_new_array();
    sqlite3_stmt *st = NULL;
    char transaction_id[AC_RADIO_JOB_ID_LEN + 1] = { 0 };
    char error_buf[128] = { 0 };
    int64_t key_revision;
    int ft_enabled;
    /* Copied out of the statement rather than held as sqlite3_column_text()
     * pointers: those are owned by the statement and are freed by the
     * sqlite3_finalize() below, and both values are read much further down
     * while building each member's options. */
    char ft_mode[32] = { 0 };
    char mobility_domain[32] = { 0 };
    unsigned char *ft_master = NULL;
    size_t ft_master_len = 0;
    int neighbor_report_enabled;
    int bss_transition_enabled;
    size_t i;
    size_t eligible_count;
    int apply_rc;

    if (!g_ac_db || !ac_uuid_valid(domain_id)) {
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "error",
                               json_object_new_string("invalid_domain_id"));
        json_object_put(targets);
        return root;
    }
    if (!consistency ||
        (strcmp(consistency, "all_or_nothing") &&
         strcmp(consistency, "per_target"))) {
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "error",
                               json_object_new_string("invalid_consistency"));
        json_object_put(targets);
        return root;
    }
    /* Get domain config. */
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT revision,ft_enabled,ft_mode,mobility_domain,"
            "neighbor_report_enabled,bss_transition_enabled,key_revision "
            "FROM ac_roaming_domains WHERE domain_id=?1",
            -1, &st, NULL) != SQLITE_OK) {
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "error",
                               json_object_new_string("database_error"));
        json_object_put(targets);
        return root;
    }
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "error",
                               json_object_new_string("domain_not_found"));
        json_object_put(targets);
        return root;
    }
    /* Column 0 (`revision`) is read but deliberately unused as a transaction
     * base revision: that is the *domain's* revision, while
     * ac_db_wifi_transaction_apply() compares base_revision against
     * ac_db_wifi_desired_revision() -- a different sequence entirely (the max
     * over ac_radio_desired, ac_ssids and ac_transactions).  Passing it made
     * the second apply of any domain fail with `revision_conflict`, because
     * the first apply bumps the global counter while leaving the domain row
     * untouched.  There is also no caller claim to honour here: this function
     * takes no revision argument, so surfacing one would mean a new ubus
     * parameter and a frontend change.  Dispatch below opts out explicitly. */
    ft_enabled = sqlite3_column_int(st, 1);
    ac_radio_job_copy_text(ft_mode, sizeof(ft_mode),
                           sqlite3_column_text(st, 2));
    ac_radio_job_copy_text(mobility_domain, sizeof(mobility_domain),
                           sqlite3_column_text(st, 3));
    neighbor_report_enabled = sqlite3_column_int(st, 4);
    bss_transition_enabled = sqlite3_column_int(st, 5);
    key_revision = sqlite3_column_int64(st, 6);
    sqlite3_finalize(st);
    st = NULL;
    /* Run preflight to get eligible members. */
    preflight = ac_db_roaming_domain_preflight_json(domain_id, now);
    if (!json_object_object_get_ex(preflight, "domain", &domain)) {
        json_object_put(preflight);
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "error",
                               json_object_new_string("preflight_failed"));
        json_object_put(targets);
        return root;
    }
    members = json_object_object_get(preflight, "members");
    if (!members || !json_object_is_type(members, json_type_array)) {
        json_object_put(preflight);
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "error",
                               json_object_new_string("no_members"));
        json_object_put(targets);
        return root;
    }
    if (!strcmp(consistency, "all_or_nothing") &&
        json_object_get_int(json_object_object_get(preflight, "excluded_count")) > 0) {
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "error",
            json_object_new_string("roaming_members_not_ready"));
        json_object_object_add(root, "preflight", preflight);
        json_object_put(targets);
        return root;
    }
    /* Keep only members preflight actually cleared.  This used to take the
     * whole array length, which quietly undid the fail-closed gate: preflight
     * marks a member ineligible when adoption, session, write capability or
     * BSSID readback is missing, and apply then pushed 11r/k/v config plus FT
     * key material to it anyway.  The two bugs cancelled into something that
     * looked like it worked. */
    {
        struct json_object *cleared = json_object_new_array();
        size_t m;

        for (m = 0; m < json_object_array_length(members); m++) {
            struct json_object *member = json_object_array_get_idx(members, m);

            if (ac_db_json_bool(member, "eligible"))
                json_object_array_add(cleared, json_object_get(member));
        }
        json_object_object_add(preflight, "apply_members", cleared);
        members = cleared;
    }
    eligible_count = json_object_array_length(members);
    if (eligible_count == 0) {
        json_object_put(preflight);
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "error",
                               json_object_new_string("no_eligible_members"));
        json_object_put(targets);
        return root;
    }
    for (i = 0; i < eligible_count; i++) {
        struct json_object *member = json_object_array_get_idx(members, i);
        size_t j;

        for (j = 0; j < i; j++) {
            struct json_object *prior = json_object_array_get_idx(members, j);
            if (!strcmp(ac_db_json_string(member, "ap_id"),
                        ac_db_json_string(prior, "ap_id")) &&
                !strcmp(ac_db_json_string(member, "section_name"),
                        ac_db_json_string(prior, "section_name"))) {
                json_object_object_add(root, "ok", json_object_new_boolean(0));
                json_object_object_add(root, "error",
                    json_object_new_string("roaming_binding_section_duplicate"));
                json_object_put(preflight);
                json_object_put(targets);
                return root;
            }
        }
    }
    /* FT prerequisites, checked once for the whole domain before anything is
     * dispatched, so a domain that cannot produce sound key material fails as
     * a unit instead of half-configuring the members. */
    if (ft_enabled) {
        /* nas_identifier doubles as the R0KH-ID/R1KH-ID and must be unique
         * within the mobility domain.  It is the member BSSID, which is empty
         * whenever readback has not landed (bssid_readback_unavailable) -- two
         * such members would silently share an identity and FT would misroute
         * PMK-R1 requests with nothing in the logs pointing here. */
        size_t a;
        size_t b;

        for (a = 0; a < eligible_count; a++) {
            const char *id_a = ac_db_json_string(
                json_object_array_get_idx(members, a), "bssid");

            if (!id_a || !id_a[0]) {
                json_object_put(preflight);
                json_object_object_add(root, "ok", json_object_new_boolean(0));
                json_object_object_add(root, "error",
                    json_object_new_string("nas_identifier_unavailable"));
                json_object_put(targets);
                return root;
            }
            for (b = a + 1; b < eligible_count; b++) {
                const char *id_b = ac_db_json_string(
                    json_object_array_get_idx(members, b), "bssid");

                if (id_b && !strcasecmp(id_a, id_b)) {
                    json_object_put(preflight);
                    json_object_object_add(root, "ok",
                                           json_object_new_boolean(0));
                    json_object_object_add(root, "error",
                        json_object_new_string("nas_identifier_conflict"));
                    json_object_object_add(root, "conflict_nas_identifier",
                                           json_object_new_string(id_a));
                    json_object_put(targets);
                    return root;
                }
            }
        }
        if (ac_roaming_ft_master(domain_id, key_revision,
                                 &ft_master, &ft_master_len) != 0) {
            json_object_put(preflight);
            json_object_object_add(root, "ok", json_object_new_boolean(0));
            json_object_object_add(root, "error",
                json_object_new_string("ft_key_material_unavailable"));
            json_object_put(targets);
            return root;
        }
    }
    /* Build per-AP candidates with roaming options. */
    for (i = 0; i < eligible_count; i++) {
        struct json_object *member = json_object_array_get_idx(members, i);
        struct json_object *sections;
        struct json_object *section = json_object_new_object();
        struct json_object *options = json_object_new_object();
        struct json_object *list_options = json_object_new_object();
        const char *ap_id;
        const char *bssid;

        ap_id = json_object_get_string(
            json_object_object_get(member, "ap_id"));
        sections = ac_ssid_target_sections(targets, ap_id);
        if (!sections) {
            json_object_put(section);
            json_object_put(options);
            json_object_put(list_options);
            snprintf(error_buf, sizeof(error_buf), "roaming_targets_bounds");
            goto candidate_failed;
        }
        bssid = json_object_get_string(
            json_object_object_get(member, "bssid"));
        /* Build section options. */
        json_object_object_add(options, "ieee80211r",
            json_object_new_string(ft_enabled ? "1" : "0"));
        json_object_object_add(options, "ieee80211k",
            json_object_new_string(neighbor_report_enabled ? "1" : "0"));
        json_object_object_add(options, "ieee80211v",
            json_object_new_string(bss_transition_enabled ? "1" : "0"));
        json_object_object_add(options, "bss_transition",
            json_object_new_string(bss_transition_enabled ? "1" : "0"));
        json_object_object_add(options, "rrm_neighbor_report",
            json_object_new_string(neighbor_report_enabled ? "1" : "0"));
        if (ft_enabled) {
            json_object_object_add(options, "mobility_domain",
                json_object_new_string(mobility_domain));
            /* ft_over_ds is a per-member property, not a domain switch: it may
             * only be turned on for members that actually reported support in
             * their readback.  Forcing the domain's ft_mode onto every member
             * is what the Phase 1 handoff calls out as "不得全局硬开" -- a
             * member that cannot do FT-over-DS would advertise a capability it
             * does not have, and its FT associations fail in a way that looks
             * like a client bug. */
            json_object_object_add(options, "ft_over_ds",
                json_object_new_string(
                    (!strcmp(ft_mode, "over_ds") &&
                     ac_db_json_bool(member, "ft_over_ds_capable")) ?
                        "1" : "0"));
            json_object_object_add(options, "nas_identifier",
                json_object_new_string(bssid));
            /* Build R0KH/R1KH entries for all other eligible members. */
            {
                struct json_object *r0kh_list = json_object_new_array();
                struct json_object *r1kh_list = json_object_new_array();
                size_t j;

                for (j = 0; j < eligible_count; j++) {
                    struct json_object *other =
                        json_object_array_get_idx(members, j);
                    const char *other_ap_id;
                    const char *other_bssid;
                    char link_key[AC_ROAMING_FT_KEY_HEX_LEN + 1];
                    char r0kh_entry[256];
                    char r1kh_entry[256];

                    other_ap_id = json_object_get_string(
                        json_object_object_get(other, "ap_id"));
                    other_bssid = json_object_get_string(
                        json_object_object_get(other, "bssid"));
                    if (!other_ap_id || !other_bssid ||
                        !strcmp(ap_id, other_ap_id))
                        continue;
                    /* r0kh: the peer holds PMK-R0, we are its R1KH, so the key
                     * is the one for the directed link other -> self. */
                    if (ac_roaming_ft_link_key(ft_master, ft_master_len,
                                               other_bssid, bssid,
                                               link_key) != 0)
                        continue;
                    /* Fields are space separated: hostapd's add_r0kh() splits
                     * on ' ' and rejects the whole line when there is none. */
                    snprintf(r0kh_entry, sizeof(r0kh_entry), "%s %s %s",
                             other_bssid, other_bssid, link_key);
                    json_object_array_add(r0kh_list,
                        json_object_new_string(r0kh_entry));
                    /* r1kh: we hold PMK-R0 and the peer is our R1KH, so the
                     * directed link is self -> other.  The peer derives the
                     * same value for its own r0kh entry pointing back at us. */
                    if (ac_roaming_ft_link_key(ft_master, ft_master_len,
                                               bssid, other_bssid,
                                               link_key) != 0)
                        continue;
                    snprintf(r1kh_entry, sizeof(r1kh_entry), "%s %s %s",
                             other_bssid, other_bssid, link_key);
                    json_object_array_add(r1kh_list,
                        json_object_new_string(r1kh_entry));
                }
                if (json_object_array_length(r0kh_list) > 0)
                    json_object_object_add(list_options, "r0kh", r0kh_list);
                else
                    json_object_put(r0kh_list);
                if (json_object_array_length(r1kh_list) > 0)
                    json_object_object_add(list_options, "r1kh", r1kh_list);
                else
                    json_object_put(r1kh_list);
            }
        }
        /* Build section. */
        json_object_object_add(section, "section",
            json_object_new_string(ac_db_json_string(member, "section_name")));
        json_object_object_add(section, "operation", json_object_new_string("set"));
        json_object_object_add(section, "options", options);
        if (json_object_object_length(list_options) > 0)
            json_object_object_add(section, "list_options", list_options);
        else
            json_object_put(list_options);
        json_object_array_add(sections, section);
        /* Build candidate. */
#ifndef AC_DB_TEST_STANDALONE
        /* Phase 3: Add SET_NEIGHBOR hostapd action sections for 11k.
         * Each neighbor section targets the current AP's BSSID as the hostapd
         * socket identifier. The APD resolves BSSID to its ctrl_path. */
        if (neighbor_report_enabled) {
            /* Config apply reloads hostapd: replay each BSS's neighbor table
             * even when its contents have not changed since the last apply. */
            size_t ni;
            for (ni = 0; ni < eligible_count; ni++) {
                struct json_object *nm = json_object_array_get_idx(members, ni);
                struct json_object *nb_section =
                    ac_roaming_neighbor_section(member, nm, 0, now);

                if (nb_section)
                    json_object_array_add(sections, nb_section);
            }
        }
#endif /* !AC_DB_TEST_STANDALONE */
    }
    if (ac_ssid_targets_seal(targets) != 0) {
        snprintf(error_buf, sizeof(error_buf), "roaming_candidate_bounds");
        goto candidate_failed;
    }
    json_object_put(preflight);
    if (ft_master) {
        ac_secrets_clear(ft_master, ft_master_len);
        ft_master = NULL;
        ft_master_len = 0;
    }
    /* Dispatch via wifi transaction channel. */
    {
        const char *targets_json = json_object_to_json_string_ext(
            targets, JSON_C_TO_STRING_PLAIN);
        char actor_id[AC_RADIO_JOB_ID_LEN + 1];
        char idempotency_key[AC_RADIO_JOB_IDEMPOTENCY_MAX + 1];

        ac_generate_uuid(actor_id);
        snprintf(idempotency_key, sizeof(idempotency_key),
                 "roaming-apply:%s:%ld", domain_id, (long)now);
        apply_rc = ac_db_wifi_transaction_apply(
            actor_id, idempotency_key, consistency,
            AC_WIFI_TX_BASE_REVISION_CURRENT,
            targets_json, now, transaction_id, error_buf, sizeof(error_buf));
    }
    json_object_put(targets);
    if (apply_rc == AC_CONFIG_JOB_OK ||
        apply_rc == AC_CONFIG_JOB_IDEMPOTENT) {
        json_object_object_add(root, "ok", json_object_new_boolean(1));
        json_object_object_add(root, "transaction_id",
            json_object_new_string(transaction_id));
        json_object_object_add(root, "consistency",
            json_object_new_string(consistency));
        json_object_object_add(root, "member_count",
            json_object_new_int64(eligible_count));
    } else {
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "error",
            json_object_new_string(error_buf[0] ? error_buf :
                                   "transaction_failed"));
        json_object_object_add(root, "error_code",
            json_object_new_int(apply_rc));
    }
    return root;
candidate_failed:
    json_object_put(targets);
    json_object_put(preflight);
    if (ft_master)
        ac_secrets_clear(ft_master, ft_master_len);
    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "error", json_object_new_string(error_buf));
    return root;
}


#if !defined(AC_DB_TEST_STANDALONE) || defined(AC_DB_ROAMING_ACTIONS_TEST)
/* ---- Phase 3: roaming steering — BTM actions and neighbor sync ---- */

static int ac_roaming_source_busy(const char *ap_id)
{
    sqlite3_stmt *st = NULL;
    int busy;

    if (!ap_id || sqlite3_prepare_v2(g_ac_db,
            "SELECT 1 FROM ac_config_jobs WHERE ap_id=?1 "
            "AND state IN ('queued','leased','running') LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
        return 1;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    busy = sqlite3_step(st) != SQLITE_DONE;
    sqlite3_finalize(st);
    return busy;
}

static const char *ac_roaming_btm_limit_reason(const char *domain_id,
    const char *station_mac, struct json_object *policy, int64_t now)
{
    sqlite3_stmt *st = NULL;
    int max_attempts = json_object_get_int(json_object_object_get(
        policy, "max_btm_attempts_per_hour"));
    int interval = json_object_get_int(json_object_object_get(
        policy, "decision_min_interval_sec"));
    int domain_limit = json_object_get_int(json_object_object_get(
        policy, "domain_action_rate_limit"));
    const char *reason = "roaming_rate_state_unavailable";

    if (max_attempts <= 0 || domain_limit <= 0)
        return "btm_rate_limit_disabled";
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT COUNT(*),MAX(created_at),"
            "SUM(CASE WHEN outcome='pending' THEN 1 ELSE 0 END) "
            "FROM ac_btm_actions WHERE domain_id=?1 AND station_mac=?2 "
            "AND created_at>?3", -1, &st, NULL) != SQLITE_OK)
        return reason;
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, station_mac, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, now - 3600);
    if (sqlite3_step(st) == SQLITE_ROW) {
        reason = sqlite3_column_int(st, 2) > 0 ? "btm_pending" :
                 sqlite3_column_int(st, 0) >= max_attempts ? "station_btm_rate_limit" :
                 (sqlite3_column_int(st, 0) > 0 &&
                  sqlite3_column_int64(st, 1) + interval > now) ?
                 "decision_interval_active" : NULL;
    }
    sqlite3_finalize(st);
    if (reason)
        return reason;
    /* Domain limit is the maximum number of BTM requests per rolling minute. */
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT (SELECT COUNT(*) FROM ac_btm_actions "
            "WHERE domain_id=?1 AND created_at>?2)+"
            "(SELECT COUNT(*) FROM ac_deauth_actions "
            "WHERE domain_id=?1 AND created_at>?2)", -1, &st, NULL) != SQLITE_OK)
        return "roaming_rate_state_unavailable";
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now - 60);
    if (sqlite3_step(st) != SQLITE_ROW)
        reason = "roaming_rate_state_unavailable";
    else if (sqlite3_column_int(st, 0) >= domain_limit)
        reason = "domain_btm_rate_limit";
    sqlite3_finalize(st);
    return reason;
}

/* Record a BTM action in ac_btm_actions. Returns the btm_id on success, -1 on failure. */
static int64_t ac_roam_btm_record(const char *domain_id, const char *station_mac,
                                   const char *ap_id, const char *source_bssid,
                                   const char *target_bssid,
                                   const char *target_bssid_2,
                                   const char *transaction_id, int64_t now)
{
    sqlite3_stmt *st = NULL;
    int64_t btm_id = -1;

    if (!g_ac_db || !domain_id || !station_mac || !target_bssid)
        return -1;
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_btm_actions(domain_id,station_mac,ap_id,"
            "source_bssid,target_bssid,target_bssid_2,sent_at,sent_ok,outcome,created_at,"
            "transaction_id,policy_revision) VALUES(?1,?2,?3,?4,?5,?6,0,0,'pending',?7,?8,"
            "COALESCE((SELECT revision FROM ac_roaming_policies WHERE domain_id=?1),0))",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, station_mac, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, ap_id ? ap_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, source_bssid ? source_bssid : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, target_bssid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, target_bssid_2 ? target_bssid_2 : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 7, now);
    sqlite3_bind_text(st, 8, transaction_id ? transaction_id : "",
                     -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE)
        btm_id = sqlite3_last_insert_rowid(g_ac_db);
    sqlite3_finalize(st);
    return btm_id;
}

/* Update BTM action outcome. */
static int ac_roam_btm_update_outcome(int64_t btm_id, const char *outcome,
                                       const char *reason, int64_t now)
{
    sqlite3_stmt *st = NULL;

    if (!g_ac_db || btm_id <= 0 || !outcome)
        return -1;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_btm_actions SET outcome=?1,outcome_at=?2,outcome_reason=?3 "
            "WHERE btm_id=?4 AND outcome='pending'",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, outcome, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now);
    sqlite3_bind_text(st, 3, reason ? reason : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, btm_id);
    sqlite3_step(st);
    sqlite3_finalize(st);
    st = NULL;
    /* An opted-in failed suggestion ends its observation wait, not an actual
     * post-roam cooldown. The decision interval still precedes escalation. */
    if ((!strcmp(outcome, "not_roamed") || !strcmp(outcome, "timed_out")) &&
        sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_roaming_cooldowns SET cooldown_until=MIN(cooldown_until,"
            "(SELECT b.created_at+p.decision_min_interval_sec FROM ac_btm_actions b "
            "JOIN ac_roaming_policies p ON p.domain_id=b.domain_id WHERE b.btm_id=?1)),"
            "reason='btm_failed_observation' WHERE reason='btm_queued' "
            "AND EXISTS (SELECT 1 FROM ac_btm_actions b "
            "JOIN ac_roaming_policies p ON p.domain_id=b.domain_id "
            "JOIN ac_roaming_domains d ON d.domain_id=b.domain_id "
            "WHERE b.btm_id=?1 AND b.domain_id=ac_roaming_cooldowns.domain_id "
            "AND b.station_mac=ac_roaming_cooldowns.station_mac "
            "AND b.created_at=ac_roaming_cooldowns.created_at "
            "AND p.reassoc_block_enabled=1 AND d.deauth_enabled=1)",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, btm_id);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
    return 0;
}

static int ac_roaming_btm_response_status(const char *ap_id,
    const char *source_bssid, const char *station_mac, int64_t since, int64_t now,
    char target[18])
{
    struct ac_roaming_bss_capability cap;
    sqlite3_stmt *st = NULL;
    int status = -1;

    target[0] = '\0';
    ac_roaming_bss_capability(ap_id, source_bssid, now, &cap);
    if (!cap.found || !cap.interface[0])
        return -1;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT json_extract(e.value,'$.status_code'),"
            "json_extract(e.value,'$.target_bssid') "
            "FROM ac_ap_runtime r,"
            "json_each(r.runtime_json,'$.sources.hostapd.btm_responses') e "
            "WHERE r.ap_id=?1 AND r.stale=0 AND r.observed_at>=?2 "
            "AND json_extract(e.value,'$.station_mac')=?3 COLLATE NOCASE "
            "AND json_extract(e.value,'$.interface')=?4 "
            "AND json_extract(e.value,'$.observed_at') BETWEEN ?5 AND ?6 "
            "AND json_type(e.value,'$.status_code')='integer' "
            "ORDER BY json_extract(e.value,'$.observed_at') DESC LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now - AC_TELEMETRY_STALE_TIMEOUT_SECONDS);
    sqlite3_bind_text(st, 3, station_mac, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, cap.interface, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 5, since);
    sqlite3_bind_int64(st, 6, now + 5);
    if (sqlite3_step(st) == SQLITE_ROW) {
        status = sqlite3_column_int(st, 0);
        ac_radio_job_copy_text(target, 18, sqlite3_column_text(st, 1));
        if (!ac_radio_job_mac_valid(target))
            target[0] = '\0';
    }
    sqlite3_finalize(st);
    return status >= 0 && status <= 255 ? status : -1;
}

static int ac_roaming_expire_queued_action(const char *transaction_id, int64_t now)
{
    sqlite3_stmt *st = NULL;
    int changed;

    if (ac_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_transaction_targets SET state='failed',"
            "error_code='roaming_action_expired',updated_at=?2 "
            "WHERE transaction_id=?1 AND EXISTS (SELECT 1 FROM ac_config_jobs j "
            "WHERE j.transaction_id=?1 AND j.ap_id=ac_transaction_targets.ap_id "
            "AND j.state IN ('queued','leased'))", -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, transaction_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto fail;
    changed = sqlite3_changes(g_ac_db);
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_config_jobs SET state='cancelled',"
            "error_code='roaming_action_expired',lease_expires_at=0,updated_at=?2 "
            "WHERE transaction_id=?1 AND state IN ('queued','leased')",
            -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, transaction_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(st);
    st = NULL;
    if (changed && ac_wifi_tx_refresh_locked(transaction_id, now) != 0)
        goto fail;
    if (ac_exec("COMMIT") == 0)
        return 0;
fail:
    sqlite3_finalize(st);
    ac_exec("ROLLBACK");
    return -1;
}

/* A queued config job is not a sent BTM. Confirm its hostapd ACK first, then
 * distinguish the station's response from an actual target association. */
static int ac_roam_btm_check_outcomes(const char *domain_id, int64_t now,
                                       int outcome_window_sec)
{
    sqlite3_stmt *st = NULL;
    int checked = 0;

    if (!g_ac_db || !domain_id || outcome_window_sec <= 0)
        return 0;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT b.btm_id,b.station_mac,b.target_bssid,b.target_bssid_2,b.created_at,"
            "b.sent_ok,b.sent_at,b.transaction_id,t.state,t.error_code,"
            "t.updated_at,b.ap_id,b.source_bssid,"
            "json_extract(NULLIF(j.readback_json,''),'$.evidence_type') "
            "FROM ac_btm_actions b "
            "LEFT JOIN ac_transaction_targets t ON t.transaction_id=b.transaction_id "
            "AND t.ap_id=b.ap_id "
            "LEFT JOIN ac_config_jobs j ON j.transaction_id=b.transaction_id "
            "AND j.ap_id=b.ap_id "
            "WHERE b.domain_id=?1 AND b.outcome='pending'",
            -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(st) == SQLITE_ROW) {
        int64_t btm_id = sqlite3_column_int64(st, 0);
        const char *station_mac = (const char *)sqlite3_column_text(st, 1);
        const char *target_bssid = (const char *)sqlite3_column_text(st, 2);
        const char *target_bssid_2 = (const char *)sqlite3_column_text(st, 3);
        int64_t queued_at = sqlite3_column_int64(st, 4);
        int sent_ok = sqlite3_column_int(st, 5);
        int64_t sent_at = sqlite3_column_int64(st, 6);
        const char *tx = (const char *)sqlite3_column_text(st, 7);
        const char *state = (const char *)sqlite3_column_text(st, 8);
        const char *error = (const char *)sqlite3_column_text(st, 9);
        int64_t ack_at = sqlite3_column_int64(st, 10);
        const char *ap_id = (const char *)sqlite3_column_text(st, 11);
        const char *source_bssid = (const char *)sqlite3_column_text(st, 12);
        const char *evidence = (const char *)sqlite3_column_text(st, 13);
        sqlite3_stmt *ev_st = NULL;
        int roamed = 0;
        int client_status;
        char reason[128];
        char response_target[18];

        if (!sent_ok && state && !strcmp(state, "applied") &&
            evidence && !strcmp(evidence, "hostapd_command_ack")) {
            if (sqlite3_prepare_v2(g_ac_db,
                    "UPDATE ac_btm_actions SET sent_ok=1,sent_at=?2,"
                    "outcome_reason='hostapd_command_accepted' WHERE btm_id=?1",
                    -1, &ev_st, NULL) == SQLITE_OK) {
                sqlite3_bind_int64(ev_st, 1, btm_id);
                sqlite3_bind_int64(ev_st, 2, ack_at);
                if (sqlite3_step(ev_st) == SQLITE_DONE) {
                    sent_ok = 1;
                    sent_at = ack_at;
                }
                sqlite3_finalize(ev_st);
                ev_st = NULL;
            }
        }
        if (!sent_ok) {
            if (!tx || !tx[0] ||
                (state && (!strcmp(state, "failed") ||
                           !strcmp(state, "rolled_back") ||
                           !strcmp(state, "cancelled")))) {
                ac_roam_btm_update_outcome(btm_id, "not_roamed",
                    error && error[0] ? error : "config_dispatch_failed", now);
                checked++;
            } else if (now - queued_at >= outcome_window_sec) {
                /* Do not leave a stale, unexecuted suggestion in the queue. */
                if (ac_roaming_expire_queued_action(tx, now) != 0)
                    continue;
                ac_roam_btm_update_outcome(btm_id, "timed_out",
                    "hostapd_dispatch_not_confirmed", now);
                checked++;
            }
            continue;
        }

        if (sqlite3_prepare_v2(g_ac_db,
                "SELECT 1 FROM ac_station_events "
                "WHERE station_mac=?1 COLLATE NOCASE AND event IN ('roam','connect') "
                "AND (to_bssid=?2 COLLATE NOCASE OR "
                "(?3<>'' AND to_bssid=?3 COLLATE NOCASE)) "
                "AND observed_at BETWEEN ?4 AND ?5 "
                "UNION ALL SELECT 1 FROM ac_station_sessions s "
                "JOIN ac_ssid_bindings b ON b.ap_id=s.ap_id AND b.radio_id=s.radio_id "
                "AND b.ssid_id=s.ssid_id WHERE s.mac=?1 COLLATE NOCASE "
                "AND (b.bssid=?2 COLLATE NOCASE OR "
                "(?3<>'' AND b.bssid=?3 COLLATE NOCASE)) "
                "AND s.disconnected_at=0 "
                "AND s.connected_at>=?4 AND s.last_seen_at>=?6 LIMIT 1",
                -1, &ev_st, NULL) == SQLITE_OK) {
            sqlite3_bind_text(ev_st, 1, station_mac, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ev_st, 2, target_bssid, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ev_st, 3, target_bssid_2 ? target_bssid_2 : "", -1,
                              SQLITE_TRANSIENT);
            sqlite3_bind_int64(ev_st, 4, queued_at);
            sqlite3_bind_int64(ev_st, 5, sent_at + outcome_window_sec);
            sqlite3_bind_int64(ev_st, 6, now - AC_TELEMETRY_STALE_TIMEOUT_SECONDS);
            if (sqlite3_step(ev_st) == SQLITE_ROW)
                roamed = 1;
            sqlite3_finalize(ev_st);
            ev_st = NULL;
        }
        if (roamed) {
            int cooldown = 300;

            ac_roam_btm_update_outcome(btm_id, "roamed",
                                        "target_association_observed", now);
            if (sqlite3_prepare_v2(g_ac_db,
                    "SELECT post_roam_cooldown_sec FROM ac_roaming_policies "
                    "WHERE domain_id=?1", -1, &ev_st, NULL) == SQLITE_OK) {
                sqlite3_bind_text(ev_st, 1, domain_id, -1, SQLITE_TRANSIENT);
                if (sqlite3_step(ev_st) == SQLITE_ROW)
                    cooldown = sqlite3_column_int(ev_st, 0);
                sqlite3_finalize(ev_st);
            }
            ac_db_roaming_cooldown_record(domain_id, station_mac,
                cooldown, "target_association_observed", now);
            checked++;
            continue;
        }
        client_status = ac_roaming_btm_response_status(
            ap_id, source_bssid, station_mac, queued_at, now, response_target);
        if (client_status > 0) {
            snprintf(reason, sizeof(reason), "station_rejected_btm_status_%d",
                     client_status);
            ac_roam_btm_update_outcome(btm_id, "not_roamed", reason, now);
            checked++;
        } else if (client_status == 0 && response_target[0] &&
                   strcasecmp(response_target, target_bssid) &&
                   (!target_bssid_2 || !target_bssid_2[0] ||
                    strcasecmp(response_target, target_bssid_2)) &&
                   now - sent_at >= 15) {
            ac_roam_btm_update_outcome(btm_id, "not_roamed",
                "station_selected_other_bssid", now);
            checked++;
        } else if (now - sent_at >= outcome_window_sec) {
            ac_roam_btm_update_outcome(btm_id, "timed_out", client_status == 0 ?
                "station_accepted_but_no_roam" : "no_station_response_or_roam", now);
            checked++;
        } else if (client_status == 0 && sqlite3_prepare_v2(g_ac_db,
                "UPDATE ac_btm_actions SET "
                "outcome_reason='station_accepted_btm_waiting_for_roam' "
                "WHERE btm_id=?1", -1, &ev_st, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(ev_st, 1, btm_id);
            sqlite3_step(ev_st);
            sqlite3_finalize(ev_st);
        }
    }
    sqlite3_finalize(st);
    return checked;
}

/* Compute BTM failure rate for a domain over the last N actions under the
 * current policy revision. A deliberate policy change starts a new safety
 * window without deleting the historical action audit. 
 * Returns the fraction of failed actions (0.0 to 1.0), or 0.0 if no data. */
static double ac_roam_btm_failure_rate(const char *domain_id, int window_hours,
                                        int min_actions, int64_t now)
{
    sqlite3_stmt *st = NULL;
    int total = 0, failed = 0;

    if (!g_ac_db || !domain_id || window_hours <= 0)
        return 0.0;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT COUNT(*),"
            "SUM(CASE WHEN outcome IN ('timed_out','not_roamed') THEN 1 ELSE 0 END) "
            "FROM ac_btm_actions "
            "WHERE domain_id=?1 "
            "AND policy_revision=COALESCE((SELECT revision FROM "
            "ac_roaming_policies WHERE domain_id=?1),0) "
            "AND created_at>=?2 AND outcome<>'pending'",
            -1, &st, NULL) != SQLITE_OK)
        return 0.0;
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now - (int64_t)window_hours * 3600);
    if (sqlite3_step(st) == SQLITE_ROW) {
        total = sqlite3_column_int(st, 0);
        failed = sqlite3_column_int(st, 1);
    }
    sqlite3_finalize(st);
    if (total < min_actions)
        return 0.0;
    return (double)failed / (double)total;
}

/* Check if domain steering should be auto-disabled due to high failure rate.
 * Returns 1 if steering was disabled, 0 if still enabled. */
static int ac_roam_btm_auto_disable_check(const char *domain_id,
                                            double failure_threshold,
                                            int min_actions,
                                            int window_hours,
                                            int64_t now)
{
    sqlite3_stmt *st = NULL;
    int steering_enabled = 1;

    if (!g_ac_db || !domain_id)
        return 0;
    /* Check current state. */
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT steering_enabled FROM ac_roaming_domain_action_state "
            "WHERE domain_id=?1",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW)
            steering_enabled = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
        st = NULL;
    }
    if (!steering_enabled)
        return 1; /* Already disabled. */
    /* Check failure rate. */
    {
        double rate = ac_roam_btm_failure_rate(domain_id, window_hours,
                                                min_actions, now);
        if (rate >= failure_threshold && min_actions > 0) {
            if (sqlite3_prepare_v2(g_ac_db,
                    "INSERT INTO ac_roaming_domain_action_state"
                    "(domain_id,steering_enabled,disabled_reason,disabled_at) "
                    "VALUES(?1,0,?2,?3) "
                    "ON CONFLICT(domain_id) DO UPDATE SET "
                    "steering_enabled=0,disabled_reason=excluded.disabled_reason,"
                    "disabled_at=excluded.disabled_at",
                    -1, &st, NULL) == SQLITE_OK) {
                char reason[128];
                snprintf(reason, sizeof(reason),
                         "btm_failure_rate_%.0f_pct_exceeds_%.0f_pct_min_%d",
                         rate * 100.0, failure_threshold * 100.0, min_actions);
                sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(st, 2, reason, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(st, 3, now);
                sqlite3_step(st);
                sqlite3_finalize(st);
            }
            return 1;
        }
    }
    return 0;
}

/* An optional station scope restricts both explicit and periodic actions. */
static int ac_roam_steering_enabled(const char *domain_id, const char *station_mac)
{
    sqlite3_stmt *st = NULL;
    int enabled = 0;

    if (!g_ac_db || !domain_id)
        return 0;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT steering_enabled,steering_station_mac "
            "FROM ac_roaming_domain_action_state "
            "WHERE domain_id=?1",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *scope = (const char *)sqlite3_column_text(st, 1);

            enabled = sqlite3_column_int(st, 0) &&
                (!scope[0] || (station_mac && !strcasecmp(scope, station_mac)));
        }
        sqlite3_finalize(st);
    }
    return enabled;
}

struct ac_neighbor_replay_state {
    char hash[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1];
    char epoch[AC_RADIO_JOB_SESSION_EPOCH_MAX + 1];
    char transaction[37];
    int attempts;
    int64_t attempted_at;
    int64_t synced_at;
};

static int ac_neighbor_replay_record(const char *domain, const char *ap,
    const struct ac_neighbor_replay_state *state, const char *reason)
{
    sqlite3_stmt *st = NULL;
    int rc;

    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_neighbor_sync_state(domain_id,ap_id,neighbor_hash,"
            "synced_at,session_epoch,attempted_at,attempts,transaction_id,reason) "
            "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) "
            "ON CONFLICT(domain_id,ap_id) DO UPDATE SET "
            "neighbor_hash=excluded.neighbor_hash,synced_at=excluded.synced_at,"
            "session_epoch=excluded.session_epoch,attempted_at=excluded.attempted_at,"
            "attempts=excluded.attempts,transaction_id=excluded.transaction_id,"
            "reason=excluded.reason",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, ap, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, state->hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, state->synced_at);
    sqlite3_bind_text(st, 5, state->epoch, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, state->attempted_at);
    sqlite3_bind_int(st, 7, state->attempts);
    sqlite3_bind_text(st, 8, state->transaction, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, reason, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int ac_neighbor_replay_load(const char *domain, const char *ap,
                                   struct ac_neighbor_replay_state *state)
{
    sqlite3_stmt *st = NULL;
    int rc;

    memset(state, 0, sizeof(*state));
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT neighbor_hash,synced_at,session_epoch,attempted_at,"
            "attempts,transaction_id FROM ac_neighbor_sync_state "
            "WHERE domain_id=?1 AND ap_id=?2",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, ap, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        ac_radio_job_copy_text(state->hash, sizeof(state->hash), sqlite3_column_text(st, 0));
        state->synced_at = sqlite3_column_int64(st, 1);
        ac_radio_job_copy_text(state->epoch, sizeof(state->epoch), sqlite3_column_text(st, 2));
        state->attempted_at = sqlite3_column_int64(st, 3);
        state->attempts = sqlite3_column_int(st, 4);
        ac_radio_job_copy_text(state->transaction, sizeof(state->transaction), sqlite3_column_text(st, 5));
    }
    sqlite3_finalize(st);
    return rc == SQLITE_ROW || rc == SQLITE_DONE ? 0 : -1;
}

struct json_object *ac_db_roaming_neighbor_sync_json(const char *domain_id,
                                                    int64_t now)
{
    struct json_object *root = ac_db_roaming_domain_json(domain_id);
    struct json_object *domain = json_object_object_get(root, "domain");
    struct json_object *entries;
    sqlite3_stmt *st = NULL;
    int enabled = 0;

    if (!domain)
        return root;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT enabled FROM ac_neighbor_sync_domains WHERE domain_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        enabled = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT ap_id,neighbor_hash,synced_at,attempted_at,attempts,"
            "transaction_id,reason FROM ac_neighbor_sync_state "
            "WHERE domain_id=?1 ORDER BY ap_id", -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    entries = json_object_new_array();
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *entry = json_object_new_object();
        int64_t synced = sqlite3_column_int64(st, 2);
        const char *reason = (const char *)sqlite3_column_text(st, 6);

        json_object_object_add(entry, "ap_id",
            json_object_new_string((const char *)sqlite3_column_text(st, 0)));
        json_object_object_add(entry, "desired_digest",
            json_object_new_string((const char *)sqlite3_column_text(st, 1)));
        json_object_object_add(entry, "verified_at", json_object_new_int64(synced));
        json_object_object_add(entry, "verified", json_object_new_boolean(
            enabled && ac_db_json_bool(domain, "neighbor_report_enabled") &&
            synced > 0 && synced <= now &&
            synced >= now - AC_TELEMETRY_STALE_TIMEOUT_SECONDS &&
            !strcmp(reason, "verified")));
        json_object_object_add(entry, "attempted_at",
            json_object_new_int64(sqlite3_column_int64(st, 3)));
        json_object_object_add(entry, "attempts",
            json_object_new_int(sqlite3_column_int(st, 4)));
        json_object_object_add(entry, "transaction_id",
            json_object_new_string((const char *)sqlite3_column_text(st, 5)));
        json_object_object_add(entry, "reason", json_object_new_string(reason));
        json_object_array_add(entries, entry);
    }
    sqlite3_finalize(st);
    json_object_object_add(root, "enabled", json_object_new_boolean(enabled));
    json_object_object_add(root, "entries", entries);
    json_object_object_add(root, "source", json_object_new_string("hostapd_neighbor_readback"));
    json_object_object_add(root, "active_station_action", json_object_new_boolean(0));
    return root;
fail:
    sqlite3_finalize(st);
    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "error", json_object_new_string("database_error"));
    return root;
}

struct json_object *ac_db_roaming_neighbor_sync_set_json(const char *domain_id,
    int enabled, int64_t now)
{
    struct json_object *root = ac_db_roaming_domain_json(domain_id);
    struct json_object *domain = json_object_object_get(root, "domain");
    sqlite3_stmt *st = NULL;
    char transactions[64][37];
    size_t count = 0, i;

    if (!domain)
        return root;
    if (enabled && !ac_db_json_bool(domain, "neighbor_report_enabled")) {
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "error", json_object_new_string("neighbor_report_disabled"));
        return root;
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_neighbor_sync_domains(domain_id,enabled,updated_at) "
            "VALUES(?1,?2,?3) ON CONFLICT(domain_id) DO UPDATE SET "
            "enabled=excluded.enabled,updated_at=excluded.updated_at",
            -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, !!enabled);
    sqlite3_bind_int64(st, 3, now);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(st);
    st = NULL;
    if (enabled) {
        if (sqlite3_prepare_v2(g_ac_db,
                "UPDATE ac_neighbor_sync_state SET attempts=0,attempted_at=0 "
                "WHERE domain_id=?1", -1, &st, NULL) != SQLITE_OK)
            goto fail;
        sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE)
            goto fail;
    } else {
        if (sqlite3_prepare_v2(g_ac_db,
                "SELECT transaction_id FROM ac_neighbor_sync_state "
                "WHERE domain_id=?1 AND transaction_id<>'' LIMIT 64",
                -1, &st, NULL) != SQLITE_OK)
            goto fail;
        sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
        while (count < 64 && sqlite3_step(st) == SQLITE_ROW)
            ac_radio_job_copy_text(transactions[count++], 37, sqlite3_column_text(st, 0));
    }
    sqlite3_finalize(st);
    st = NULL;
    for (i = 0; i < count; i++)
        if (ac_roaming_expire_queued_action(transactions[i], now) != 0)
            goto fail;
    json_object_put(root);
    return ac_db_roaming_neighbor_sync_json(domain_id, now);
fail:
    sqlite3_finalize(st);
    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "error", json_object_new_string("database_error"));
    return root;
}

/* -1 means incomplete/unavailable, 0 means drift, 1 means every managed peer
 * is present. Unmanaged entries and hostapd's self entries are never removed. */
static int ac_neighbor_replay_readback(struct json_object *snapshot,
                                       struct json_object *sections)
{
    struct json_object *hostapd = json_object_object_get(
        json_object_object_get(snapshot, "sources"), "hostapd");
    struct json_object *bsses = json_object_object_get(hostapd, "bss");
    size_t i, j, k;
    int matched = 1;

    if (!ac_db_json_bool(hostapd, "runtime_actions") ||
        !bsses || !json_object_is_type(bsses, json_type_array))
        return -1;
    for (i = 0; i < json_object_array_length(sections); i++) {
        struct json_object *section = json_object_array_get_idx(sections, i);
        struct json_object *options = json_object_object_get(section, "options");
        struct json_object *owner = NULL, *neighbors;
        const char *ssid = ac_db_json_string(options, "source_ssid");
        char ssid_hex[65];
        int found = 0;

        if (!ssid || strlen(ssid) > 32)
            return -1;
        ac_roaming_ft_hex((const unsigned char *)ssid, strlen(ssid), ssid_hex);
        for (j = 0; j < json_object_array_length(bsses); j++) {
            struct json_object *bss = json_object_array_get_idx(bsses, j);
            const char *interface = ac_db_json_string(bss, "interface");
            const char *bssid = ac_db_json_string(bss, "bssid");
            const char *name = ac_db_json_string(bss, "broadcast_name");

            if (interface && bssid && name &&
                !strcmp(interface, ac_db_json_string(section, "section")) &&
                !strcasecmp(bssid,
                            ac_db_json_string(options, "source_bssid")) &&
                !strcmp(name, ssid)) {
                owner = bss;
                break;
            }
        }
        neighbors = json_object_object_get(owner, "neighbors");
        if (!ac_db_json_bool(owner, "neighbors_complete") ||
            !neighbors || !json_object_is_type(neighbors, json_type_array))
            return -1;
        for (k = 0; k < json_object_array_length(neighbors); k++) {
            struct json_object *row = json_object_array_get_idx(neighbors, k);
            const char *report = ac_db_json_string(row, "report");
            const char *bssid = ac_db_json_string(row, "bssid");
            const char *name = ac_db_json_string(row, "ssid_hex");
            unsigned opclass, channel, phy;

            if (!bssid || !name || !report ||
                strcasecmp(bssid, ac_db_json_string(options, "neighbor_bssid")) ||
                strcmp(name, ssid_hex) ||
                strlen(report) != 26 ||
                sscanf(report + 20, "%2x%2x%2x", &opclass, &channel, &phy) != 3)
                continue;
            if ((int)opclass == json_object_get_int(json_object_object_get(options, "neighbor_opclass")) &&
                (int)channel == json_object_get_int(json_object_object_get(options, "neighbor_channel")) &&
                (int)phy == json_object_get_int(json_object_object_get(options, "neighbor_phy")))
                found = 1;
        }
        if (!found)
            matched = 0;
    }
    return matched;
}

static int ac_neighbor_replay_target(const char *domain,
    struct json_object *target, int64_t now, int *dispatched)
{
    const char *ap = ac_db_json_string(target, "ap_id");
    struct ac_neighbor_replay_state state;
    struct json_object *single = json_object_new_array();
    struct json_object *candidate, *snapshot = NULL;
    sqlite3_stmt *st = NULL;
    char epoch[AC_RADIO_JOB_SESSION_EPOCH_MAX + 1] = {0};
    char key[AC_RADIO_JOB_IDEMPOTENCY_MAX + 1], error[128] = {0};
    const char *reason = "runtime_unavailable", *digest;
    int64_t readback_at = 0;
    int match, rc = -1;

    if (ac_neighbor_replay_load(domain, ap, &state) != 0)
        goto done;
    json_object_array_add(single, json_object_get(target));
    if (ac_ssid_targets_seal(single) != 0) {
        reason = "neighbor_candidate_bounds";
        goto record;
    }
    candidate = json_object_object_get(target, "candidate");
    digest = ac_db_json_string(candidate, "candidate_digest");
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT boot_id,received_at,runtime_json FROM ac_ap_runtime "
            "WHERE ap_id=?1 AND stale=0 AND session_connected=1 AND write_capable=1 "
            "AND received_at>=?2", -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, ap, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now - AC_TELEMETRY_STALE_TIMEOUT_SECONDS);
    if (sqlite3_step(st) == SQLITE_ROW) {
        ac_radio_job_copy_text(epoch, sizeof(epoch), sqlite3_column_text(st, 0));
        readback_at = sqlite3_column_int64(st, 1);
        snapshot = json_tokener_parse((const char *)sqlite3_column_text(st, 2));
    }
    sqlite3_finalize(st);
    st = NULL;
    if (!snapshot)
        goto record;
    if (strcmp(state.hash, digest) || strcmp(state.epoch, epoch)) {
        if (state.transaction[0] &&
            ac_roaming_expire_queued_action(state.transaction, now) != 0)
            goto done;
        memset(&state, 0, sizeof(state));
        snprintf(state.hash, sizeof(state.hash), "%s", digest);
        snprintf(state.epoch, sizeof(state.epoch), "%s", epoch);
    }
    match = ac_neighbor_replay_readback(snapshot,
        json_object_object_get(candidate, "sections"));
    if (match < 0) {
        reason = "neighbor_readback_unavailable";
        goto record;
    }
    if (match) {
        state.synced_at = readback_at;
        state.attempts = 0;
        reason = "verified";
        goto record;
    }
    state.synced_at = 0;
    if (state.transaction[0] && state.attempted_at <= now - 120 &&
        ac_roaming_expire_queued_action(state.transaction, now) != 0)
        goto done;
    if (ac_roaming_source_busy(ap)) {
        reason = "source_action_busy";
        goto record;
    }
    if (state.attempts >= 3) {
        reason = "retry_exhausted";
        goto record;
    }
    if (state.attempts &&
        now - state.attempted_at < 60 * (1 << (state.attempts - 1))) {
        reason = "retry_backoff";
        goto record;
    }
    if (*dispatched >= 4) {
        reason = "dispatch_budget";
        goto record;
    }
    state.attempts++;
    state.attempted_at = now;
    state.transaction[0] = '\0';
    rc = snprintf(key, sizeof(key), "neighbors:%s:%s:%lld",
                  domain, ap, (long long)now);
    if (rc < 0 || (size_t)rc >= sizeof(key)) {
        reason = "neighbor_candidate_bounds";
        goto record;
    }
    rc = ac_db_wifi_transaction_apply(domain, key, "per_target",
        AC_WIFI_TX_BASE_REVISION_CURRENT,
        json_object_to_json_string_ext(single, JSON_C_TO_STRING_PLAIN), now,
        state.transaction, error, sizeof(error));
    if (rc == AC_CONFIG_JOB_OK || rc == AC_CONFIG_JOB_IDEMPOTENT) {
        (*dispatched)++;
        reason = "awaiting_readback";
    } else {
        reason = error[0] ? error : "neighbor_dispatch_failed";
    }
record:
    rc = ac_neighbor_replay_record(domain, ap, &state, reason);
done:
    sqlite3_finalize(st);
    json_object_put(snapshot);
    json_object_put(single);
    return rc;
}

static int ac_neighbor_replay_tick(int64_t now, int *dispatched)
{
    char domains[64][37];
    sqlite3_stmt *st = NULL;
    size_t count = 0, d;

    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT n.domain_id FROM ac_neighbor_sync_domains n "
            "JOIN ac_roaming_domains d ON d.domain_id=n.domain_id "
            "WHERE n.enabled=1 AND d.neighbor_report_enabled=1 "
            "ORDER BY n.domain_id LIMIT 64", -1, &st, NULL) != SQLITE_OK)
        return -1;
    while (count < 64 && sqlite3_step(st) == SQLITE_ROW)
        ac_radio_job_copy_text(domains[count++], 37, sqlite3_column_text(st, 0));
    sqlite3_finalize(st);
    for (d = 0; d < count; d++) {
        struct json_object *preflight = ac_db_roaming_domain_preflight_json(domains[d], now);
        struct json_object *members = json_object_object_get(preflight, "members");
        struct json_object *targets = json_object_new_array();
        size_t i, j;
        int rc = 0;

        for (i = 0; members && i < json_object_array_length(members); i++) {
            struct json_object *owner = json_object_array_get_idx(members, i);

            if (!ac_db_json_bool(owner, "eligible"))
                continue;
            for (j = 0; j < json_object_array_length(members); j++) {
                struct json_object *peer = json_object_array_get_idx(members, j);
                struct json_object *section, *sections;

                if (!ac_db_json_bool(peer, "eligible"))
                    continue;
                section = ac_roaming_neighbor_section(owner, peer, 1, now);
                if (!section)
                    continue;
                sections = ac_ssid_target_sections(targets, ac_db_json_string(owner, "ap_id"));
                if (!sections) {
                    json_object_put(section);
                    rc = -1;
                    break;
                }
                json_object_array_add(sections, section);
            }
            if (rc != 0)
                break;
        }
        for (i = 0; rc == 0 && i < json_object_array_length(targets); i++)
            rc = ac_neighbor_replay_target(domains[d],
                json_object_array_get_idx(targets, i), now, dispatched);
        json_object_put(targets);
        json_object_put(preflight);
        if (rc != 0)
            return rc;
    }
    return 0;
}

/* Query BTM action history for a domain. Returns a JSON object with "entries" array.
 * Caller owns the returned object. */
struct json_object *ac_roam_btm_history_json(const char *domain_id,
                                                      const char *station_mac,
                                                      int limit, int64_t now)
{
    struct json_object *root = json_object_new_object();
    struct json_object *entries = json_object_new_array();
    sqlite3_stmt *st = NULL;
    (void)now;

    if (!g_ac_db || !domain_id) {
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "entries", entries);
        return root;
    }
    if (limit <= 0 || limit > 200)
        limit = 50;
    if (station_mac && station_mac[0]) {
        if (sqlite3_prepare_v2(g_ac_db,
                "SELECT btm_id,station_mac,ap_id,source_bssid,target_bssid,target_bssid_2,"
                "sent_at,sent_ok,outcome,outcome_at,outcome_reason,"
                "transaction_id,created_at "
                "FROM ac_btm_actions WHERE domain_id=?1 AND station_mac=?2 "
                "ORDER BY created_at DESC LIMIT ?3",
                -1, &st, NULL) != SQLITE_OK) {
            json_object_object_add(root, "ok", json_object_new_boolean(0));
            json_object_object_add(root, "entries", entries);
            return root;
        }
        sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, station_mac, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, limit);
    } else {
        if (sqlite3_prepare_v2(g_ac_db,
                "SELECT btm_id,station_mac,ap_id,source_bssid,target_bssid,target_bssid_2,"
                "sent_at,sent_ok,outcome,outcome_at,outcome_reason,"
                "transaction_id,created_at "
                "FROM ac_btm_actions WHERE domain_id=?1 "
                "ORDER BY created_at DESC LIMIT ?2",
                -1, &st, NULL) != SQLITE_OK) {
            json_object_object_add(root, "ok", json_object_new_boolean(0));
            json_object_object_add(root, "entries", entries);
            return root;
        }
        sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, limit);
    }
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *entry = json_object_new_object();

        json_object_object_add(entry, "btm_id",
            json_object_new_int64(sqlite3_column_int64(st, 0)));
        json_object_object_add(entry, "station_mac",
            json_object_new_string((const char *)sqlite3_column_text(st, 1)));
        json_object_object_add(entry, "ap_id",
            json_object_new_string((const char *)sqlite3_column_text(st, 2)));
        json_object_object_add(entry, "source_bssid",
            json_object_new_string((const char *)sqlite3_column_text(st, 3)));
        json_object_object_add(entry, "target_bssid",
            json_object_new_string((const char *)sqlite3_column_text(st, 4)));
        json_object_object_add(entry, "target_bssid_2",
            json_object_new_string((const char *)sqlite3_column_text(st, 5)));
        json_object_object_add(entry, "sent_at",
            json_object_new_int64(sqlite3_column_int64(st, 6)));
        json_object_object_add(entry, "sent_ok",
            json_object_new_boolean(sqlite3_column_int(st, 7)));
        json_object_object_add(entry, "outcome",
            json_object_new_string((const char *)sqlite3_column_text(st, 8)));
        json_object_object_add(entry, "outcome_at",
            json_object_new_int64(sqlite3_column_int64(st, 9)));
        json_object_object_add(entry, "outcome_reason",
            json_object_new_string((const char *)sqlite3_column_text(st, 10)));
        json_object_object_add(entry, "transaction_id",
            json_object_new_string((const char *)sqlite3_column_text(st, 11)));
        json_object_object_add(entry, "queued_at",
            json_object_new_int64(sqlite3_column_int64(st, 12)));
        json_object_object_add(entry, "dispatch_evidence",
            json_object_new_string(sqlite3_column_int(st, 7) ?
                "hostapd_command_ack" : "not_confirmed"));
        json_object_array_add(entries, entry);
    }
    sqlite3_finalize(st);
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "domain_id", json_object_new_string(domain_id));
    json_object_object_add(root, "entries", entries);
    return root;
}

/* Dispatch a BTM request for a specific station in a domain.
 * Builds a config candidate with hostapd action sections and dispatches
 * via the wifi transaction channel. Returns 0 on success. */
/* Same as ac_roaming_neighbor_rf(), but keyed on the BSSID -- the BTM path
 * only knows which BSSID it wants the station to move to. */
static void ac_roaming_neighbor_rf_by_bssid(const char *bssid, int64_t now,
                                            struct ac_roaming_neighbor_rf *out)
{
    sqlite3_stmt *st = NULL;
    char ap_id[AC_RADIO_JOB_ID_LEN + 1] = { 0 };
    char radio_id[64] = { 0 };
    char ssid_id[64] = { 0 };

    memset(out, 0, sizeof(*out));
    if (!g_ac_db || !bssid || !bssid[0])
        return;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT ap_id,radio_id,ssid_id FROM ac_ssid_bindings "
            "WHERE bssid=?1 COLLATE NOCASE LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
        return;
    sqlite3_bind_text(st, 1, bssid, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        ac_radio_job_copy_text(ap_id, sizeof(ap_id),
                               sqlite3_column_text(st, 0));
        ac_radio_job_copy_text(radio_id, sizeof(radio_id),
                               sqlite3_column_text(st, 1));
        ac_radio_job_copy_text(ssid_id, sizeof(ssid_id),
                               sqlite3_column_text(st, 2));
    }
    sqlite3_finalize(st);
    if (!ap_id[0] || !radio_id[0])
        return;
    ac_roaming_neighbor_rf(ap_id, radio_id, ssid_id, now, out);
}

static int ac_roam_btm_dispatch(const char *domain_id,
                                  const char *station_mac,
                                  const char *source_ap_id,
                                  const char *source_bssid,
                                  const char *target_bssid,
                                  const char *target_bssid_2,
                                  const char *bss_interface,
                                  int ft_enabled, int disassoc_imminent,
                                  int64_t now,
                                  char transaction_id[37])
{
    struct json_object *target_arr = json_object_new_array();
    struct json_object *target = json_object_new_object();
    struct json_object *candidate = json_object_new_object();
    struct json_object *sections = json_object_new_array();
    struct json_object *section = json_object_new_object();
    struct json_object *options = json_object_new_object();
    struct ac_roaming_neighbor_rf rf, rf_2;
    char candidate_digest[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1];
    char number[12];
    char idempotency_key[AC_RADIO_JOB_IDEMPOTENCY_MAX + 1];
    char error_buf[128] = { 0 };
    int rc;

    transaction_id[0] = '\0';
    if (!domain_id || !station_mac || !source_ap_id ||
        !target_bssid || !source_bssid || !bss_interface || !bss_interface[0] ||
        !strcasecmp(source_bssid, target_bssid))
        goto refuse;
    /* A BTM request without a candidate list is a request to leave with
     * nowhere to go: hostapd accepts it and answers OK, so the failure would
     * be recorded as a successful steer.  Refuse before dispatching when the
     * target cannot be described. */
    ac_roaming_neighbor_rf_by_bssid(target_bssid, now, &rf);
    if (!rf.resolved)
        goto refuse;
    memset(&rf_2, 0, sizeof(rf_2));
    if (target_bssid_2 && target_bssid_2[0]) {
        if (!strcasecmp(target_bssid, target_bssid_2))
            goto refuse;
        ac_roaming_neighbor_rf_by_bssid(target_bssid_2, now, &rf_2);
        if (!rf_2.resolved)
            goto refuse;
    }
    /* Build the hostapd action section.  Every value goes down as a string:
     * the candidate contract admits no other option type (see
     * ac_config_candidate_validate), and APD reads these back with
     * json_object_get_int(), which parses a numeric string. */
    json_object_object_add(options, "hostapd_action_type",
                           json_object_new_string("btm_request"));
    json_object_object_add(options, "station_mac",
                           json_object_new_string(station_mac));
    json_object_object_add(options, "target_bssid",
                           json_object_new_string(target_bssid));
    snprintf(number, sizeof(number), "%d", rf.op_class);
    json_object_object_add(options, "target_opclass",
                           json_object_new_string(number));
    snprintf(number, sizeof(number), "%d", rf.channel);
    json_object_object_add(options, "target_channel",
                           json_object_new_string(number));
    snprintf(number, sizeof(number), "%d", rf.phy_type);
    json_object_object_add(options, "target_phy",
                           json_object_new_string(number));
    json_object_object_add(options, "target_ft",
                           json_object_new_string(ft_enabled ? "1" : "0"));
    json_object_object_add(options, "btm_validity",
                           json_object_new_string("100"));
    if (rf_2.resolved) {
        json_object_object_add(options, "target_bssid_2",
                               json_object_new_string(target_bssid_2));
        snprintf(number, sizeof(number), "%d", rf_2.op_class);
        json_object_object_add(options, "target_opclass_2",
                               json_object_new_string(number));
        snprintf(number, sizeof(number), "%d", rf_2.channel);
        json_object_object_add(options, "target_channel_2",
                               json_object_new_string(number));
        snprintf(number, sizeof(number), "%d", rf_2.phy_type);
        json_object_object_add(options, "target_phy_2",
                               json_object_new_string(number));
        json_object_object_add(options, "target_ft_2",
                               json_object_new_string(ft_enabled ? "1" : "0"));
    }
    json_object_object_add(options, "btm_disassoc_imminent",
                           json_object_new_string(disassoc_imminent ? "1" : "0"));
    json_object_object_add(options, "btm_disassoc_timer",
                           json_object_new_string(disassoc_imminent ? "10" : "0"));
    json_object_object_add(section, "section",
        json_object_new_string(bss_interface));
    json_object_object_add(section, "options", options);
    json_object_array_add(sections, section);
    /* Build candidate.  The digest is not decoration: the transaction rejects
     * any target whose candidate lacks one, so omitting it failed every steer
     * with `target_invalid` no matter what the radios did. */
    json_object_object_add(candidate, "format",
        json_object_new_string(AC_CONFIG_CANDIDATE_FORMAT));
    json_object_object_add(candidate, "sections", sections);
    if (ac_config_candidate_digest(sections, candidate_digest) != 0) {
        json_object_put(target_arr);
        json_object_put(target);
        json_object_put(candidate);
        return -1;
    }
    json_object_object_add(candidate, "candidate_digest",
        json_object_new_string(candidate_digest));
    /* Build target. */
    json_object_object_add(target, "ap_id",
        json_object_new_string(source_ap_id));
    json_object_object_add(target, "candidate", candidate);
    json_object_object_add(target, "candidate_digest",
        json_object_new_string(candidate_digest));
    json_object_array_add(target_arr, target);
    /* Dispatch. */
    snprintf(idempotency_key, sizeof(idempotency_key),
             "btm-steer:%s:%s:%ld", domain_id, station_mac, (long)now);
    rc = ac_db_wifi_transaction_apply(
        domain_id, idempotency_key, "per_target",
        AC_WIFI_TX_BASE_REVISION_CURRENT,
        json_object_to_json_string_ext(target_arr, JSON_C_TO_STRING_PLAIN),
        now, transaction_id, error_buf, sizeof(error_buf));
    json_object_put(target_arr);
    return (rc == AC_CONFIG_JOB_OK || rc == AC_CONFIG_JOB_IDEMPOTENT) ? 0 : -1;
refuse:
    /* Nothing has been parented yet on this path, so each object is released
     * on its own. */
    json_object_put(target_arr);
    json_object_put(target);
    json_object_put(candidate);
    json_object_put(sections);
    json_object_put(section);
    json_object_put(options);
    return -1;
}

static int ac_roaming_measure_request(const char *domain_id,
    const char *station_mac, struct json_object *observation, int64_t now,
    char transaction_id[37])
{
    struct json_object *station = json_object_object_get(observation, "station");
    struct json_object *members = json_object_object_get(observation, "members");
    const char *source_ap = ac_db_json_string(station, "ap_id");
    const char *source_bssid = ac_db_json_string(station, "bssid");
    const char *ssid_id = ac_db_json_string(station, "ssid_id");
    struct ac_roaming_bss_capability owner;
    struct json_object *targets = json_object_new_array();
    struct json_object *sections;
    int classes[AC_CONFIG_CANDIDATE_SECTIONS_MAX];
    int channels[AC_CONFIG_CANDIDATE_SECTIONS_MAX];
    char bssids[AC_CONFIG_CANDIDATE_SECTIONS_MAX][18];
    size_t count = 0, i;
    char key[AC_RADIO_JOB_IDEMPOTENCY_MAX + 1];
    char error[128];
    int rc = -1;

    transaction_id[0] = '\0';
    ac_roaming_bss_capability(source_ap, source_bssid, now, &owner);
    if (!owner.found || !owner.runtime_actions ||
        !owner.neighbor_report_80211k || !owner.interface[0] ||
        !ssid_id || !members || ac_roaming_source_busy(source_ap))
        goto done;
    sections = ac_ssid_target_sections(targets, source_ap);
    if (!sections)
        goto done;
    for (i = 0; i < json_object_array_length(members) &&
                count < AC_CONFIG_CANDIDATE_SECTIONS_MAX; i++) {
        struct json_object *member = json_object_array_get_idx(members, i);
        struct ac_roaming_neighbor_rf rf;
        struct json_object *section, *options;
        const char *member_ssid = ac_db_json_string(member, "ssid_id");
        char number[16];
        size_t j;

        if (!ac_db_json_bool(member, "eligible") || !member_ssid ||
            strcmp(member_ssid, ssid_id))
            continue;
        ac_roaming_neighbor_rf(ac_db_json_string(member, "ap_id"),
            ac_db_json_string(member, "radio_id"), member_ssid, now, &rf);
        if (!rf.resolved)
            continue;
        for (j = 0; j < count; j++)
            if (classes[j] == rf.op_class && channels[j] == rf.channel &&
                !strcasecmp(bssids[j], ac_db_json_string(member, "bssid")))
                break;
        if (j < count)
            continue;
        classes[count] = rf.op_class;
        channels[count++] = rf.channel;
        snprintf(bssids[count - 1], sizeof(bssids[count - 1]), "%s",
                 ac_db_json_string(member, "bssid") ?
                     ac_db_json_string(member, "bssid") : "");
        section = json_object_new_object();
        options = json_object_new_object();
        json_object_object_add(options, "hostapd_action_type",
                               json_object_new_string("beacon_request"));
        json_object_object_add(options, "station_mac",
                               json_object_new_string(station_mac));
        snprintf(number, sizeof(number), "%d", rf.op_class);
        json_object_object_add(options, "measure_opclass", json_object_new_string(number));
        snprintf(number, sizeof(number), "%d", rf.channel);
        json_object_object_add(options, "measure_channel", json_object_new_string(number));
        json_object_object_add(options, "measure_duration_tu", json_object_new_string("50"));
        json_object_object_add(options, "measure_bssid",
                               json_object_new_string(bssids[count - 1]));
        json_object_object_add(options, "measure_ssid", json_object_new_string(rf.ssid));
        json_object_object_add(section, "section", json_object_new_string(owner.interface));
        json_object_object_add(section, "options", options);
        json_object_array_add(sections, section);
    }
    if (!count || ac_ssid_targets_seal(targets) != 0)
        goto done;
    {
        int key_len = snprintf(key, sizeof(key), "roam-measure:%s:%s:%lld",
                               domain_id, station_mac, (long long)now);

        if (key_len < 0 || (size_t)key_len >= sizeof(key))
            goto done;
    }
    rc = ac_db_wifi_transaction_apply(domain_id, key, "per_target",
        AC_WIFI_TX_BASE_REVISION_CURRENT,
        json_object_to_json_string_ext(targets, JSON_C_TO_STRING_PLAIN),
        now, transaction_id, error, sizeof(error));
    rc = rc == AC_CONFIG_JOB_OK || rc == AC_CONFIG_JOB_IDEMPOTENT ? 0 : -1;
done:
    json_object_put(targets);
    return rc;
}

/* Neighbor maintenance and steering are independent opt-ins. Neither domain
 * metadata nor neighbor recovery enables station actions. */
static struct json_object *ac_roam_deauth_evaluate(const char *domain_id,
    const char *station_mac, const char *triggered_by, int execute, int64_t now);

int ac_db_roaming_schedule_tick(int64_t now, int *dispatched)
{
    struct {
        char domain[37];
        char mac[18];
        int interval;
        int block_enabled;
        int64_t last_measurement;
    } due[64];
    char expired_measurements[64][37];
    sqlite3_stmt *st = NULL;
    size_t count = 0, expired_count = 0, i;

    if (!g_ac_db || !dispatched || now <= 0)
        return -1;
    *dispatched = 0;
    if (ac_neighbor_replay_tick(now, dispatched) != 0)
        return -1;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT DISTINCT x.measurement_transaction_id "
            "FROM ac_roaming_station_state x JOIN ac_config_jobs j "
            "ON j.transaction_id=x.measurement_transaction_id "
            "WHERE x.last_measurement_at<=?1 AND j.state IN ('queued','leased') "
            "LIMIT 64", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, now - 120);
    while (expired_count < 64 && sqlite3_step(st) == SQLITE_ROW) {
        ac_radio_job_copy_text(expired_measurements[expired_count++], 37,
                               sqlite3_column_text(st, 0));
    }
    sqlite3_finalize(st);
    st = NULL;
    for (i = 0; i < expired_count; i++)
        if (ac_roaming_expire_queued_action(expired_measurements[i], now) != 0)
            return -1;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT domain_id FROM ac_roaming_domains", -1, &st, NULL) != SQLITE_OK)
        return -1;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *domain = (const char *)sqlite3_column_text(st, 0);

        ac_roam_btm_check_outcomes(domain, now, 120);
        ac_roam_deauth_check_outcomes(domain, now);
        ac_roam_btm_auto_disable_check(domain, 0.5, 3, 24, now);
    }
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT DISTINCT d.domain_id,s.mac,p.decision_min_interval_sec,"
            "COALESCE(x.last_measurement_at,0),COALESCE(x.last_evaluated_at,0),"
            "p.reassoc_block_enabled "
            "FROM ac_roaming_domains d "
            "JOIN ac_roaming_policies p ON p.domain_id=d.domain_id "
            "JOIN ac_roaming_domain_action_state a ON a.domain_id=d.domain_id "
            "JOIN json_each(d.ssid_ids_json) ssids "
            "JOIN json_each(d.ap_group_ids_json) groups "
            "JOIN ac_ap_group_members gm ON gm.group_id=groups.value "
            "JOIN ac_station_sessions s ON s.ap_id=gm.ap_id AND s.ssid_id=ssids.value "
            "LEFT JOIN ac_roaming_station_state x ON x.domain_id=d.domain_id "
            "AND x.station_mac=s.mac WHERE d.bss_transition_enabled=1 "
            "AND a.steering_enabled=1 AND p.max_btm_attempts_per_hour>0 "
            "AND (a.steering_station_mac='' OR "
            "a.steering_station_mac=s.mac COLLATE NOCASE) "
            "AND p.domain_action_rate_limit>0 AND s.disconnected_at=0 "
            "AND NOT EXISTS (SELECT 1 FROM ac_config_jobs j WHERE j.ap_id=s.ap_id "
            "AND j.state IN ('queued','leased','running')) "
            "AND s.last_seen_at>=?1 AND (x.last_evaluated_at IS NULL "
            "OR x.last_evaluated_at<=?2-p.decision_min_interval_sec "
            "OR (x.last_measurement_at>0 AND x.last_evaluated_at<=x.last_measurement_at "
            "AND x.last_measurement_at<=?2-30)) "
            "ORDER BY COALESCE(x.last_evaluated_at,0),s.mac LIMIT 64",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, now - AC_TELEMETRY_STALE_TIMEOUT_SECONDS);
    sqlite3_bind_int64(st, 2, now);
    while (count < 64 && sqlite3_step(st) == SQLITE_ROW) {
        ac_radio_job_copy_text(due[count].domain, sizeof(due[count].domain),
                               sqlite3_column_text(st, 0));
        ac_radio_job_copy_text(due[count].mac, sizeof(due[count].mac),
                               sqlite3_column_text(st, 1));
        due[count].interval = sqlite3_column_int(st, 2);
        due[count].last_measurement = sqlite3_column_int64(st, 3);
        due[count].block_enabled = sqlite3_column_int(st, 5);
        count++;
    }
    sqlite3_finalize(st);
    st = NULL;
    for (i = 0; i < count && *dispatched < 4; i++) {
        struct json_object *forced = due[i].block_enabled ?
            ac_roam_deauth_evaluate(due[i].domain, due[i].mac, "automatic", 1, now) :
            NULL;
        const char *force_reason = ac_db_json_string(forced, "reason");
        int force_queued = ac_db_json_bool(forced, "queued");
        int measure_for_force = force_reason &&
            (!strcmp(force_reason, "serving_measurement_missing") ||
             !strcmp(force_reason, "candidate_measurements_missing"));
        struct json_object *observation = force_queued ? json_object_get(forced) :
            ac_db_roaming_domain_observe_json(due[i].domain, due[i].mac,
                measure_for_force ? "observe_only" : "automatic", now);
        const char *reason = ac_db_json_string(observation, "reason");
        int64_t measurement_at = 0;
        char transaction_id[37] = {0};

        json_object_put(forced);
        if (reason && !strcmp(reason, "source_action_busy")) {
            json_object_put(observation);
            continue;
        }
        if (force_queued) {
            (*dispatched)++;
            fprintf(stderr, "[roaming] automatic temporary block station=%s target=%s\n",
                    due[i].mac, ac_db_json_string(observation, "target_bssid"));
        } else if (reason && (!strcmp(reason, "candidate_measurements_missing") ||
                       !strcmp(reason, "serving_measurement_missing")) &&
            ac_db_json_bool(json_object_object_get(observation, "domain"),
                             "neighbor_report_enabled")) {
            if ((due[i].last_measurement > 0 &&
                 now - due[i].last_measurement < 90) || *dispatched >= 4) {
                json_object_put(observation);
                continue;
            }
            if (due[i].last_measurement == 0 ||
                now - due[i].last_measurement >= due[i].interval) {
                measurement_at = now;
                if (ac_roaming_measure_request(due[i].domain, due[i].mac,
                        observation, now, transaction_id) == 0) {
                    (*dispatched)++;
                    fprintf(stderr, "[roaming] automatic measurement station=%s transaction=%s\n",
                            due[i].mac, transaction_id);
                }
            }
        } else if (reason && !strcmp(reason, "btm_queued")) {
            (*dispatched)++;
            fprintf(stderr, "[roaming] automatic BTM station=%s target=%s\n",
                due[i].mac, ac_db_json_string(observation, "target_bssid"));
        }
        if (sqlite3_prepare_v2(g_ac_db,
                "INSERT INTO ac_roaming_station_state(domain_id,station_mac,"
                "last_evaluated_at,last_measurement_at,measurement_transaction_id) "
                "VALUES(?1,?2,?3,?4,?5) ON CONFLICT(domain_id,station_mac) "
                "DO UPDATE SET last_evaluated_at=excluded.last_evaluated_at,"
                "last_measurement_at=CASE WHEN ?4>0 THEN ?4 ELSE last_measurement_at END,"
                "measurement_transaction_id=CASE WHEN ?4>0 THEN ?5 "
                "ELSE measurement_transaction_id END", -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_text(st, 1, due[i].domain, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, due[i].mac, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 3, now);
            sqlite3_bind_int64(st, 4, measurement_at);
            sqlite3_bind_text(st, 5, transaction_id, -1, SQLITE_TRANSIENT);
            sqlite3_step(st);
            sqlite3_finalize(st);
            st = NULL;
        }
        json_object_put(observation);
    }
    return 0;
}

/* Push one DEAUTHENTICATE down the per-AP config transaction channel.
 *
 * Uses the same route as every other hostapd action so the deauth inherits the
 * existing journal, lease and idempotency handling instead of opening a second
 * control path that nothing else audits.
 *
 * `bss_identifier` is the owning BSS's hostapd interface when the capability
 * readback resolved one, else its BSSID -- APD accepts either
 * (apd_phase3_ctrl_path resolves a BSSID by scanning sockets and matching
 * STATUS), but never an AP UUID. */
static int ac_roam_deauth_dispatch(const char *domain_id,
                                   const char *station_mac,
                                   const char *source_ap_id,
                                   const char *bss_identifier,
                                   const char *source_bssid,
                                   const char *source_ssid,
                                   const char *target_bssid,
                                   int target_frequency_mhz,
                                   const char *block_scope, int block_seconds,
                                   int64_t now, char transaction_id[37])
{
    struct json_object *target_arr = json_object_new_array();
    struct json_object *target = json_object_new_object();
    struct json_object *candidate = json_object_new_object();
    struct json_object *sections = json_object_new_array();
    struct json_object *section = json_object_new_object();
    struct json_object *options = json_object_new_object();
    char candidate_digest[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1];
    char actor_id[AC_RADIO_JOB_ID_LEN + 1];
    char idempotency_key[AC_RADIO_JOB_IDEMPOTENCY_MAX + 1];
    char error_buf[128] = { 0 };
    int rc;

    transaction_id[0] = '\0';
    if (!domain_id || !station_mac || !source_ap_id || !bss_identifier ||
        !bss_identifier[0]) {
        json_object_put(target_arr);
        json_object_put(target);
        json_object_put(candidate);
        json_object_put(sections);
        json_object_put(section);
        json_object_put(options);
        return -1;
    }
    json_object_object_add(options, "hostapd_action_type",
                           json_object_new_string(block_seconds ?
                               "reassoc_block" : "deauth_request"));
    json_object_object_add(options, "station_mac",
                           json_object_new_string(station_mac));
    /* Reason 5 (DISASSOC_AP_BUSY) rather than hostapd's default 2
     * (PREV_AUTH_NOT_VALID): 2 tells the client its authentication is stale,
     * which drives some supplicants into a full reauth against the same BSS --
     * the opposite of the intended move.
     *
     * A string, like every other candidate value; APD parses it back with
     * json_object_get_int(). */
    json_object_object_add(options, "deauth_reason",
                           json_object_new_string("5"));
    if (block_seconds) {
        char number[32];

        json_object_object_add(options, "source_bssid",
                               json_object_new_string(source_bssid));
        json_object_object_add(options, "source_ssid",
                               json_object_new_string(source_ssid));
        json_object_object_add(options, "target_bssid",
                               json_object_new_string(target_bssid));
        json_object_object_add(options, "block_scope",
                               json_object_new_string(block_scope));
        if (!strcmp(block_scope, "lower")) {
            snprintf(number, sizeof(number), "%d", target_frequency_mhz);
            json_object_object_add(options, "target_frequency_mhz",
                                   json_object_new_string(number));
        }
        snprintf(number, sizeof(number), "%d", block_seconds);
        json_object_object_add(options, "block_duration_sec",
                               json_object_new_string(number));
        snprintf(number, sizeof(number), "%lld", (long long)now + 30);
        json_object_object_add(options, "block_not_after",
                               json_object_new_string(number));
    }
    json_object_object_add(section, "section",
                           json_object_new_string(bss_identifier));
    json_object_object_add(section, "options", options);
    json_object_array_add(sections, section);
    json_object_object_add(candidate, "format",
        json_object_new_string(AC_CONFIG_CANDIDATE_FORMAT));
    json_object_object_add(candidate, "sections", sections);
    if (ac_config_candidate_digest(sections, candidate_digest) != 0) {
        json_object_put(target_arr);
        json_object_put(target);
        json_object_put(candidate);
        return -1;
    }
    json_object_object_add(candidate, "candidate_digest",
        json_object_new_string(candidate_digest));
    json_object_object_add(target, "ap_id",
                           json_object_new_string(source_ap_id));
    json_object_object_add(target, "candidate", candidate);
    json_object_object_add(target, "candidate_digest",
        json_object_new_string(candidate_digest));
    json_object_array_add(target_arr, target);
    ac_generate_uuid(actor_id);
    snprintf(idempotency_key, sizeof(idempotency_key),
             "deauth-steer:%s:%s:%ld", domain_id, station_mac, (long)now);
    rc = ac_db_wifi_transaction_apply(
        actor_id, idempotency_key, "per_target",
        AC_WIFI_TX_BASE_REVISION_CURRENT,
        json_object_to_json_string_ext(target_arr, JSON_C_TO_STRING_PLAIN),
        now, transaction_id, error_buf, sizeof(error_buf));
    json_object_put(target_arr);
    return (rc == AC_CONFIG_JOB_OK || rc == AC_CONFIG_JOB_IDEMPOTENT) ? 0 : -1;
}

static int ac_roam_recent_btm_failures(const char *domain, const char *mac,
    const char *ap, const char *bssid, const char *ssid, const char *target,
    const char *scope, int64_t revision, int64_t now)
{
    sqlite3_stmt *st = NULL;
    int failures = 0;

    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT b.sent_ok,b.ap_id,b.source_bssid,b.target_bssid,b.target_bssid_2,"
            "b.outcome,b.created_at,b.policy_revision,"
            "EXISTS(SELECT 1 FROM ac_ssid_bindings x WHERE x.ap_id=b.ap_id "
            "AND x.bssid=b.source_bssid COLLATE NOCASE AND x.ssid_id=?3) "
            "FROM ac_btm_actions b WHERE b.domain_id=?1 "
            "AND b.station_mac=?2 COLLATE NOCASE AND b.created_at>"
            "COALESCE((SELECT MAX(created_at) FROM ac_deauth_actions "
            "WHERE domain_id=?1 AND station_mac=?2 COLLATE NOCASE),0) "
            "ORDER BY b.created_at DESC,b.btm_id DESC LIMIT 10",
            -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, mac, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, ssid, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *outcome = (const char *)sqlite3_column_text(st, 5);

        if (!sqlite3_column_int(st, 0) ||
            strcmp((const char *)sqlite3_column_text(st, 1), ap) ||
            (!strcmp(scope, "ap") ? !sqlite3_column_int(st, 8) :
             strcasecmp((const char *)sqlite3_column_text(st, 2), bssid)) ||
            (strcasecmp((const char *)sqlite3_column_text(st, 3), target) &&
             strcasecmp((const char *)sqlite3_column_text(st, 4), target)) ||
            (strcmp(outcome, "not_roamed") && strcmp(outcome, "timed_out")) ||
            sqlite3_column_int64(st, 6) < now - 300 ||
            sqlite3_column_int64(st, 6) > now ||
            sqlite3_column_int64(st, 7) != revision)
            break;
        failures++;
    }
    sqlite3_finalize(st);
    return failures;
}

/* Phase 4: evaluate whether a forced deauth is permitted for one station.
 *
 * The handoff requires every one of these to hold at once, so each is checked
 * separately and reports its own reason -- a single "not allowed" would make
 * the audit useless for working out why nothing happened.  The order runs
 * cheapest-and-most-decisive first, and every unknown is a refusal.
 *
 * `execute` is deliberately a parameter rather than implied: the whole chain
 * is useful as a dry run, and the default caller path evaluates without
 * sending so a domain can be observed before anything is ever dispatched. */
static struct json_object *ac_roam_deauth_evaluate(const char *domain_id,
                                                   const char *station_mac,
                                                   const char *triggered_by,
                                                   int execute, int64_t now)
{
    struct json_object *result = json_object_new_object();
    struct json_object *domain_root = NULL;
    struct json_object *domain = NULL;
    struct json_object *preflight = NULL;
    struct json_object *members = NULL;
    struct json_object *btm_history = NULL;
    struct json_object *station_runtime = NULL;
    struct json_object *candidates = NULL;
    struct ac_roaming_bss_capability cap;
    struct ac_roaming_neighbor_rf source_rf;
    sqlite3_stmt *st = NULL;
    char rule_type[64] = { 0 };
    char source_bssid[32] = { 0 };
    char source_ap_id[AC_RADIO_JOB_ID_LEN + 1] = { 0 };
    char ssid_id[AC_RADIO_JOB_ID_LEN + 1] = { 0 };
    char bss_interface[64] = { 0 };
    char source_radio[64] = { 0 };
    char block_scope[6] = "bss";
    const char *reason = NULL;
    const char *exclusion_label;
    int signal_dbm = 0;
    int have_signal = 0;
    int btm_failures = 0;
    int weak_rssi_dbm = -75;
    char steering_preference[12] = "stability";
    int deauth_after_btm_failures = 1;
    int minimum_gain = 10, minimum_rssi = -67, deauth_cooldown = 900;
    int domain_limit = 0, block_seconds = 0, block_enabled = 0;
    int comparison_signal = 0, cached = 0;
    int high_band_steer_enabled = 0;
    int force_disassoc_on_reject = 0;
    int lower_band_block_enabled = 0;
    const char *comparison_direction = "unknown";
    const char *comparison_source = "unavailable";
    int matching_direction = 0;
    int64_t policy_revision = 0;
    int64_t cooldown_until;
    int64_t deauth_id = 0;
    size_t i;

    json_object_object_add(result, "domain_id",
        json_object_new_string(domain_id ? domain_id : ""));
    json_object_object_add(result, "station_mac",
        json_object_new_string(station_mac ? station_mac : ""));
    json_object_object_add(result, "executed", json_object_new_boolean(0));
    if (!g_ac_db || !ac_uuid_valid(domain_id) ||
        !ac_radio_job_mac_valid(station_mac)) {
        json_object_object_add(result, "allowed", json_object_new_boolean(0));
        json_object_object_add(result, "reason",
                               json_object_new_string("invalid_request"));
        return result;
    }

    /* 1. The domain's forced actions must not be auto-disabled.  Checked
     *    first because a tripped breaker overrides every other consideration,
     *    and because the check itself re-evaluates the trip conditions. */
    if (ac_roam_deauth_auto_disable_check(domain_id, now)) {
        reason = "forced_actions_disabled";
        goto refuse;
    }

    /* 2. The domain must have deauth explicitly enabled. */
    domain_root = ac_db_roaming_domain_json(domain_id);
    if (!domain_root ||
        !json_object_object_get_ex(domain_root, "domain", &domain) ||
        !ac_db_json_bool(domain, "deauth_enabled")) {
        reason = "deauth_not_enabled";
        goto refuse;
    }

    /* 3. The station must currently be associated somewhere in this domain,
     *    and only the AP actually holding that association may act. */
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT s.ap_id,s.ssid_id,b.bssid,s.runtime_json,s.radio_id "
            "FROM ac_station_sessions s "
            "JOIN ac_ssid_bindings b ON b.ssid_id=s.ssid_id "
            "AND b.ap_id=s.ap_id AND b.radio_id=s.radio_id "
            "JOIN ac_roaming_domains d ON d.domain_id=?2 "
            "JOIN json_each(d.ssid_ids_json) ssids ON ssids.value=s.ssid_id "
            "JOIN json_each(d.ap_group_ids_json) groups "
            "JOIN ac_ap_group_members gm ON gm.group_id=groups.value AND gm.ap_id=s.ap_id "
            "WHERE s.mac=?1 COLLATE NOCASE AND s.disconnected_at=0 AND s.last_seen_at>=?3 "
            "ORDER BY s.last_seen_at DESC LIMIT 1",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, station_mac, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, domain_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, now - AC_TELEMETRY_STALE_TIMEOUT_SECONDS);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const unsigned char *text;

            ac_radio_job_copy_text(source_ap_id, sizeof(source_ap_id),
                                   sqlite3_column_text(st, 0));
            ac_radio_job_copy_text(ssid_id, sizeof(ssid_id),
                                   sqlite3_column_text(st, 1));
            ac_radio_job_copy_text(source_bssid, sizeof(source_bssid),
                                   sqlite3_column_text(st, 2));
            ac_radio_job_copy_text(source_radio, sizeof(source_radio),
                                   sqlite3_column_text(st, 4));
            text = sqlite3_column_text(st, 3);
            station_runtime = text ? json_tokener_parse((const char *)text) : NULL;
            have_signal = ac_db_station_signal(station_runtime, &signal_dbm);
        }
        sqlite3_finalize(st);
        st = NULL;
    }
    if (!source_ap_id[0] || !source_bssid[0]) {
        reason = "station_bssid_ownership_unknown";
        goto refuse;
    }

    /* 4. Protection list.  Named rule, not a generic "excluded", so an
     *    operator can tell which rule saved the device. */
    exclusion_label = ac_db_roaming_exclusion_check(domain_id, station_mac,
                                                    ssid_id, rule_type,
                                                    sizeof(rule_type));
    if (exclusion_label) {
        json_object_object_add(result, "exclusion_rule_type",
                               json_object_new_string(rule_type));
        json_object_object_add(result, "exclusion_label",
                               json_object_new_string(exclusion_label));
        reason = "station_protected";
        goto refuse;
    }
    if (!ac_roam_steering_enabled(domain_id, station_mac)) {
        reason = "steering_not_enabled";
        goto refuse;
    }

    /* 5. Policy-driven thresholds.  Read the three fields this decision needs
     *    directly: a domain with no policy row falls back to the schema
     *    defaults, which are the conservative ones. */
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT weak_rssi_dbm,deauth_after_btm_failures,revision,"
            "minimum_candidate_gain_db,candidate_min_rssi_dbm,deauth_cooldown_sec,"
            "domain_action_rate_limit,reassoc_block_enabled,reassoc_block_sec,"
            "reassoc_block_scope,steering_preference,"
            "high_band_steer_enabled,force_disassoc_on_reject,lower_band_block_enabled "
            "FROM ac_roaming_policies WHERE domain_id=?1",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            weak_rssi_dbm = sqlite3_column_int(st, 0);
            deauth_after_btm_failures = sqlite3_column_int(st, 1);
            policy_revision = sqlite3_column_int64(st, 2);
            minimum_gain = sqlite3_column_int(st, 3);
            minimum_rssi = sqlite3_column_int(st, 4);
            deauth_cooldown = sqlite3_column_int(st, 5);
            domain_limit = sqlite3_column_int(st, 6);
            block_enabled = sqlite3_column_int(st, 7);
            block_seconds = block_enabled ? sqlite3_column_int(st, 8) : 0;
            if (block_enabled)
                ac_radio_job_copy_text(block_scope, sizeof(block_scope),
                                       sqlite3_column_text(st, 9));
            ac_radio_job_copy_text(steering_preference,
                                   sizeof(steering_preference),
                                   sqlite3_column_text(st, 10));
            high_band_steer_enabled = sqlite3_column_int(st, 11);
            force_disassoc_on_reject = sqlite3_column_int(st, 12);
            lower_band_block_enabled = sqlite3_column_int(st, 13);
        }
        sqlite3_finalize(st);
        st = NULL;
    }
    json_object_object_add(result, "policy_revision",
                           json_object_new_int64(policy_revision));
    json_object_object_add(result, "reassoc_block_enabled",
                           json_object_new_boolean(block_enabled));
    json_object_object_add(result, "steering_preference",
                           json_object_new_string(steering_preference));
    json_object_object_add(result, "force_disassoc_on_reject",
                           json_object_new_boolean(force_disassoc_on_reject));
    if (!policy_revision || domain_limit <= 0) {
        reason = "forced_action_rate_limit_disabled";
        goto refuse;
    }
    if (triggered_by && !strcmp(triggered_by, "automatic") &&
        !force_disassoc_on_reject) {
        reason = "force_disassoc_disabled";
        goto refuse;
    }
    if (triggered_by && !strcmp(triggered_by, "automatic") && !block_enabled) {
        reason = "reassoc_block_not_enabled";
        goto refuse;
    }

    cooldown_until = ac_db_roaming_cooldown_check(domain_id, station_mac, now);
    if (cooldown_until > 0) {
        json_object_object_add(result, "cooldown_until",
                               json_object_new_int64(cooldown_until));
        reason = "cooldown_active";
        goto refuse;
    }
    if (ac_roaming_source_busy(source_ap_id)) {
        reason = "source_action_busy";
        goto refuse;
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT (SELECT COUNT(*) FROM ac_deauth_actions WHERE domain_id=?1 "
            "AND station_mac=?2 COLLATE NOCASE AND created_at>?3),"
            "(SELECT COUNT(*) FROM ac_btm_actions WHERE domain_id=?1 AND created_at>?4)+"
            "(SELECT COUNT(*) FROM ac_deauth_actions WHERE domain_id=?1 AND created_at>?4)",
            -1, &st, NULL) != SQLITE_OK) {
        reason = "roaming_rate_state_unavailable";
        goto refuse;
    }
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, station_mac, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, now - deauth_cooldown);
    sqlite3_bind_int64(st, 4, now - 60);
    if (sqlite3_step(st) != SQLITE_ROW)
        reason = "roaming_rate_state_unavailable";
    else if (sqlite3_column_int(st, 0) > 0)
        reason = "deauth_cooldown_active";
    else if (sqlite3_column_int(st, 1) >= domain_limit)
        reason = "domain_action_rate_limit";
    sqlite3_finalize(st);
    st = NULL;
    if (reason)
        goto refuse;

    /* 6. The signal must actually be bad.  No reading at all is a refusal,
     *    not a pass -- deauthing on missing telemetry is exactly the
     *    "device mysteriously dropped" failure this phase must avoid. */
    if (!have_signal) {
        reason = "station_signal_unknown";
        goto refuse;
    }
    json_object_object_add(result, "signal_dbm",
                           json_object_new_int(signal_dbm));
    if (!strcmp(steering_preference, "stability") &&
        signal_dbm > weak_rssi_dbm) {
        reason = "signal_above_threshold";
        goto refuse;
    }

    /* 7. A verified, reachable, better candidate must exist.  Reuses the
     *    preflight capability readback so "reachable" means a real per-BSS
     *    readback, not merely a configured member. */
    preflight = ac_db_roaming_domain_preflight_json(domain_id, now);
    if (!preflight ||
        !json_object_object_get_ex(preflight, "members", &members)) {
        reason = "no_verified_candidate";
        goto refuse;
    }
    ac_roaming_bss_capability(source_ap_id, source_bssid, now, &cap);
    if (!cap.found || !cap.runtime_actions || !cap.hostapd_ctrl_reachable ||
        !cap.client_deauth || (block_enabled && !cap.reassoc_block)) {
        reason = "forced_action_capability_unavailable";
        goto refuse;
    }
    {
        int64_t comparison_observed_at = 0;

        if (ac_roaming_beacon_signal(station_mac, source_bssid, now,
                                     &comparison_signal, &cached,
                                     &comparison_observed_at)) {
            comparison_direction = "downlink";
            comparison_source = cached ? "ieee80211k_beacon_table" :
                                         "ieee80211k_beacon_report";
        } else if (have_signal &&
                   ac_roaming_iphone_probe_scope(station_mac, ssid_id)) {
            comparison_signal = signal_dbm;
            cached = 0;
            comparison_direction = "uplink";
            comparison_source = "ap_station_signal";
        } else {
            reason = "serving_measurement_missing";
            goto refuse;
        }
    }
    if (!strcmp(steering_preference, "stability") &&
        ac_roaming_iphone_probe_scope(station_mac, ssid_id) &&
        comparison_signal > weak_rssi_dbm) {
        reason = "signal_above_threshold";
        goto refuse;
    }
    json_object_object_add(result, "comparison_signal_source",
                           json_object_new_string(comparison_source));
    json_object_object_add(result, "comparison_signal_direction",
                           json_object_new_string(comparison_direction));
    candidates = ac_db_roaming_candidates_score(domain_id, station_mac, members,
        station_runtime, signal_dbm,
        ac_roaming_iphone_probe_scope(station_mac, ssid_id),
        high_band_steer_enabled, now);
    {
        struct json_object *best[2] = { NULL, NULL };
        int best_score[2] = { INT_MIN, INT_MIN };
        int measured = 0;

        for (i = 0; candidates && i < json_object_array_length(candidates); i++) {
            struct json_object *m = json_object_array_get_idx(candidates, i);
            const char *m_bssid = ac_db_json_string(m, "bssid");
            const char *m_ap = ac_db_json_string(m, "ap_id");
            const char *m_ssid = ac_db_json_string(m, "ssid_id");
            int candidate_signal = json_object_get_int(
                json_object_object_get(m, "signal_estimate_dbm"));
            int score = json_object_get_int(json_object_object_get(m, "score"));

            if (!ac_db_json_bool(m, "eligible") || !m_bssid || !m_ap ||
                !m_ssid || strcmp(m_ssid, ssid_id) ||
                !strcasecmp(m_bssid, source_bssid))
                continue;
            if (block_enabled && !strcmp(m_ap, source_ap_id)) {
                struct ac_roaming_bss_capability target_cap;

                if (!strcmp(block_scope, "ap"))
                continue;
                ac_roaming_bss_capability(m_ap, m_bssid, now, &target_cap);
                if (!strcmp(block_scope, "band") &&
                (!target_cap.found ||
                 (target_cap.frequency_mhz < 2500 && cap.frequency_mhz < 2500) ||
                 (target_cap.frequency_mhz >= 4900 && target_cap.frequency_mhz < 5925 &&
                  cap.frequency_mhz >= 4900 && cap.frequency_mhz < 5925) ||
                 (target_cap.frequency_mhz >= 5925 && cap.frequency_mhz >= 5925)))
                continue;
            }
            /* lower_band_block_enabled: reject candidates on a band lower
             * than the source BSS's band. This is a policy-level flag
             * independent of the reassoc block lease. */
            if (lower_band_block_enabled) {
                struct ac_roaming_bss_capability target_freq_cap;
                int source_b, candidate_b;

                ac_roaming_bss_capability(source_ap_id, source_bssid, now, &cap);
                source_b = cap.frequency_mhz >= 5925 ? 3 :
                           cap.frequency_mhz >= 4900 ? 2 :
                           cap.frequency_mhz >= 2400 ? 1 : 0;
                ac_roaming_bss_capability(m_ap, m_bssid, now, &target_freq_cap);
                candidate_b = target_freq_cap.frequency_mhz >= 5925 ? 3 :
                              target_freq_cap.frequency_mhz >= 4900 ? 2 :
                              target_freq_cap.frequency_mhz >= 2400 ? 1 : 0;
                if (source_b > 0 && candidate_b > 0 && candidate_b < source_b)
                    continue;
            }
            if (!ac_db_json_bool(m, "signal_measured"))
                continue;
            measured++;
            if (!ac_db_json_string(m, "signal_direction") ||
                strcmp(ac_db_json_string(m, "signal_direction"),
                       comparison_direction))
                continue;
            matching_direction++;
            if (candidate_signal < minimum_rssi ||
                candidate_signal - comparison_signal < minimum_gain ||
                json_object_get_int(json_object_object_get(m, "station_count")) > 50)
                continue;
            if (score > best_score[0]) {
                if (!best[0] || strcmp(m_ap,
                       ac_db_json_string(best[0], "ap_id"))) {
                    best_score[1] = best_score[0];
                    best[1] = best[0];
                }
                best_score[0] = score;
                best[0] = m;
            } else if ((!best[0] || strcmp(m_ap,
                        ac_db_json_string(best[0], "ap_id"))) &&
                       score > best_score[1]) {
                best_score[1] = score;
                best[1] = m;
            }
        }
        if (!best[0]) {
            reason = !measured ? "candidate_measurements_missing" :
                     !matching_direction ? "candidate_signal_direction_mismatch" :
                     "no_verified_better_candidate";
            goto refuse;
        }
        json_object_object_add(result, "target_bssid", json_object_new_string(
            ac_db_json_string(best[0], "bssid")));
        json_object_object_add(result, "target_bssid_2", json_object_new_string(
            best[1] ? ac_db_json_string(best[1], "bssid") : ""));
        json_object_object_add(result, "target_ap_id", json_object_new_string(
            ac_db_json_string(best[0], "ap_id")));
        json_object_object_add(result, "candidate", json_object_get(best[0]));
        json_object_object_add(result, "comparison_signal_dbm",
                               json_object_new_int(comparison_signal));
        if (lower_band_block_enabled && block_enabled) {
            int source_band = cap.frequency_mhz >= 5925 ? 3 :
                              cap.frequency_mhz >= 4900 ? 2 :
                              cap.frequency_mhz >= 2400 ? 1 : 0;
            int target_frequency = json_object_get_int(
                json_object_object_get(best[0], "frequency_mhz"));
            int target_band = target_frequency >= 5925 ? 3 :
                              target_frequency >= 4900 ? 2 :
                              target_frequency >= 2400 ? 1 : 0;

            if (source_band > 0 && target_band > source_band)
                snprintf(block_scope, sizeof(block_scope), "lower");
        }
    }

    /* 8. BTM must have been tried and must not have worked.  Deauth is the
     *    fallback for a station that ignored a polite request, never the
     *    first thing it is shown. */
    btm_history = ac_roam_btm_history_json(domain_id, station_mac, 20, now);
    btm_failures = ac_roam_recent_btm_failures(domain_id, station_mac,
        source_ap_id, source_bssid, ssid_id, ac_db_json_string(result, "target_bssid"),
        block_scope, policy_revision, now);
    json_object_object_add(result, "btm_failures",
                           json_object_new_int(btm_failures));
    if (btm_failures < deauth_after_btm_failures ||
        deauth_after_btm_failures <= 0) {
        reason = "btm_not_exhausted";
        goto refuse;
    }

    /* 9. The owning BSS must report the capability.  Never inferred, never
     *    assumed true for an unsupported platform. */
    ac_roaming_neighbor_rf(source_ap_id, source_radio, ssid_id, now, &source_rf);
    if (block_enabled && !source_rf.resolved) {
        reason = "source_ssid_readback_unavailable";
        goto refuse;
    }
    ac_radio_job_copy_text(bss_interface, sizeof(bss_interface),
                           (const unsigned char *)cap.interface);

    json_object_object_add(result, "allowed", json_object_new_boolean(1));
    json_object_object_add(result, "reason",
                           json_object_new_string("all_conditions_met"));
    json_object_object_add(result, "source_bssid",
                           json_object_new_string(source_bssid));
    json_object_object_add(result, "bss_interface",
                           json_object_new_string(bss_interface));
    json_object_object_add(result, "block_scope", json_object_new_string(block_scope));
    json_object_object_add(result, "block_duration_sec", json_object_new_int(block_seconds));

    if (execute) {
        /* Audit first, dispatch second.  A row written before the frame goes
         * out survives a crash mid-dispatch; one written afterwards would
         * lose exactly the failures the circuit breaker counts. */
        deauth_id = ac_roam_deauth_record(domain_id, station_mac, source_ap_id,
            source_bssid, ac_db_json_string(result, "target_bssid"),
            ac_roaming_iphone_probe_scope(station_mac, ssid_id) ?
                ac_db_json_string(result, "target_bssid_2") : "",
            triggered_by && triggered_by[0] && strcmp(triggered_by, "automatic") ?
                "manual" : "policy",
            triggered_by, signal_dbm,
            candidates ? json_object_to_json_string_ext(
                candidates, JSON_C_TO_STRING_PLAIN) : "",
            btm_history ? json_object_to_json_string_ext(
                btm_history, JSON_C_TO_STRING_PLAIN) : "",
            policy_revision, now);
        json_object_object_add(result, "deauth_id",
                               json_object_new_int64(deauth_id));
        if (deauth_id > 0) {
            char transaction_id[37];
            int dispatch_rc = ac_roam_deauth_dispatch(
                domain_id, station_mac, source_ap_id,
                bss_interface[0] ? bss_interface : source_bssid,
                source_bssid, source_rf.ssid, ac_db_json_string(result, "target_bssid"),
                json_object_get_int(json_object_object_get(
                    json_object_object_get(result, "candidate"),
                    "frequency_mhz")),
                block_scope, block_seconds, now, transaction_id);

            if (dispatch_rc != 0)
                ac_roam_deauth_mark_sent(deauth_id, 0, "ap_control_dispatch_failed");
            if (sqlite3_prepare_v2(g_ac_db,
                    "UPDATE ac_deauth_actions SET transaction_id=?2,block_scope=?3,"
                    "block_duration_sec=?4 WHERE deauth_id=?1",
                    -1, &st, NULL) == SQLITE_OK) {
                sqlite3_bind_int64(st, 1, deauth_id);
                sqlite3_bind_text(st, 2, transaction_id, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(st, 3, block_seconds ? block_scope : "",
                                  -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(st, 4, block_seconds);
                sqlite3_step(st);
                sqlite3_finalize(st);
                st = NULL;
            }
            json_object_object_add(result, "queued",
                                   json_object_new_boolean(dispatch_rc == 0));
            json_object_object_add(result, "transaction_id",
                                   json_object_new_string(transaction_id));
            ac_db_roaming_cooldown_record(domain_id, station_mac, deauth_cooldown,
                                          "forced_action_queued", now);
            if (dispatch_rc != 0)
                json_object_object_add(result, "dispatch_error",
                    json_object_new_string("ap_control_dispatch_failed"));
            /* Re-run the breaker straight away: a dispatch that just failed
             * may be the third in a row, and the next caller should already
             * see the domain disabled rather than trying again first. */
            ac_roam_deauth_auto_disable_check(domain_id, now);
        } else {
            json_object_object_add(result, "executed",
                                   json_object_new_boolean(0));
        }
    }
    json_object_put(domain_root);
    json_object_put(preflight);
    json_object_put(btm_history);
    json_object_put(station_runtime);
    json_object_put(candidates);
    return result;

refuse:
    json_object_object_add(result, "allowed", json_object_new_boolean(0));
    json_object_object_add(result, "reason", json_object_new_string(reason));
    json_object_put(domain_root);
    json_object_put(preflight);
    json_object_put(btm_history);
    json_object_put(station_runtime);
    json_object_put(candidates);
    return result;
}

/* Public entry point for the Phase 4 gate.
 *
 * `execute` requires its own confirmation token, distinct from the
 * "enable-forced-deauth" one that arms the capability on a domain.  The two
 * authorise different things -- one a config change, the other a frame aimed
 * at a live station -- so sharing a string would mean whoever enabled the
 * feature could also fire it, and the second confirmation would not be a
 * second confirmation at all. */
struct json_object *ac_db_roaming_deauth_evaluate_json(const char *domain_id,
                                                       const char *station_mac,
                                                       const char *triggered_by,
                                                       int execute,
                                                       const char *confirmation,
                                                       int64_t now)
{
    int may_execute = execute &&
        confirmation && !strcmp(confirmation, "execute-forced-deauth");
    struct json_object *result;

    if (execute && !may_execute) {
        result = json_object_new_object();
        json_object_object_add(result, "allowed", json_object_new_boolean(0));
        json_object_object_add(result, "executed", json_object_new_boolean(0));
        json_object_object_add(result, "reason",
            json_object_new_string("execute_confirmation_required"));
        return result;
    }
    result = ac_roam_deauth_evaluate(domain_id, station_mac, triggered_by,
                                     may_execute, now);
    /* Resolving outcomes here keeps the audit self-healing: any pending row
     * from an earlier dispatch gets closed the next time the domain is
     * consulted, without needing a separate timer. */
    ac_roam_deauth_check_outcomes(domain_id, now);
    return result;
}
#endif /* !AC_DB_TEST_STANDALONE */
static int ac_roaming_policy_valid(const struct ac_roaming_policy *policy)
{
    return policy &&
        policy->weak_rssi_dbm >= -100 && policy->weak_rssi_dbm <= -40 &&
        policy->minimum_candidate_gain_db >= 1 &&
        policy->minimum_candidate_gain_db <= 40 &&
        policy->candidate_min_rssi_dbm >= -100 &&
        policy->candidate_min_rssi_dbm <= -40 &&
        policy->decision_min_interval_sec >= 30 &&
        policy->decision_min_interval_sec <= 3600 &&
        policy->post_roam_cooldown_sec >= 60 &&
        policy->post_roam_cooldown_sec <= 86400 &&
        policy->max_btm_attempts_per_hour >= 0 &&
        policy->max_btm_attempts_per_hour <= 12 &&
        policy->deauth_after_btm_failures >= 0 &&
        policy->deauth_after_btm_failures <= 10 &&
        policy->deauth_cooldown_sec >= 300 &&
        policy->deauth_cooldown_sec <= 86400 &&
        policy->domain_action_rate_limit >= 0 &&
        policy->domain_action_rate_limit <= 60 &&
        (policy->reassoc_block_enabled == 0 || policy->reassoc_block_enabled == 1) &&
        policy->reassoc_block_sec >= 0 && policy->reassoc_block_sec <= 30 &&
        (!policy->reassoc_block_scope[0] ||
         !strcmp(policy->reassoc_block_scope, "bss") ||
         !strcmp(policy->reassoc_block_scope, "ap") ||
         !strcmp(policy->reassoc_block_scope, "band") ||
         !strcmp(policy->reassoc_block_scope, "lower")) &&
        (!policy->steering_preference[0] ||
         !strcmp(policy->steering_preference, "stability") ||
         !strcmp(policy->steering_preference, "performance")) &&
        (policy->high_band_steer_enabled == 0 || policy->high_band_steer_enabled == 1) &&
        (policy->force_disassoc_on_reject == 0 || policy->force_disassoc_on_reject == 1) &&
        (policy->lower_band_block_enabled == 0 || policy->lower_band_block_enabled == 1) &&
        (policy->band_steer_mode >= 0 && policy->band_steer_mode <= 2) &&
        (policy->band_steer_min_rssi_dbm >= -100 && policy->band_steer_min_rssi_dbm <= -40) &&
        ac_roaming_domain_text_valid(policy->updated_by, 64, 0);
}

struct json_object *ac_db_roaming_policy_json(const char *domain_id)
{
    struct json_object *root = json_object_new_object();
    struct json_object *policy = json_object_new_object();
    sqlite3_stmt *st = NULL;

    if (!g_ac_db || !ac_uuid_valid(domain_id))
        goto invalid;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT weak_rssi_dbm,minimum_candidate_gain_db,"
            "candidate_min_rssi_dbm,decision_min_interval_sec,"
            "post_roam_cooldown_sec,max_btm_attempts_per_hour,"
            "deauth_after_btm_failures,deauth_cooldown_sec,"
            "domain_action_rate_limit,revision,updated_at,updated_by,"
            "reassoc_block_enabled,reassoc_block_sec,reassoc_block_scope,"
            "steering_preference,high_band_steer_enabled,force_disassoc_on_reject,lower_band_block_enabled,"
            "band_steer_mode,band_steer_min_rssi_dbm "
            "FROM ac_roaming_policies WHERE domain_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        goto database_error;
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        json_object_put(policy);
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        json_object_object_add(root, "error", json_object_new_string("not_found"));
        return root;
    }
    json_object_object_add(policy, "weak_rssi_dbm",
                           json_object_new_int(sqlite3_column_int(st, 0)));
    json_object_object_add(policy, "minimum_candidate_gain_db",
                           json_object_new_int(sqlite3_column_int(st, 1)));
    json_object_object_add(policy, "candidate_min_rssi_dbm",
                           json_object_new_int(sqlite3_column_int(st, 2)));
    json_object_object_add(policy, "decision_min_interval_sec",
                           json_object_new_int(sqlite3_column_int(st, 3)));
    json_object_object_add(policy, "post_roam_cooldown_sec",
                           json_object_new_int(sqlite3_column_int(st, 4)));
    json_object_object_add(policy, "max_btm_attempts_per_hour",
                           json_object_new_int(sqlite3_column_int(st, 5)));
    json_object_object_add(policy, "deauth_after_btm_failures",
                           json_object_new_int(sqlite3_column_int(st, 6)));
    json_object_object_add(policy, "deauth_cooldown_sec",
                           json_object_new_int(sqlite3_column_int(st, 7)));
    json_object_object_add(policy, "domain_action_rate_limit",
                           json_object_new_int(sqlite3_column_int(st, 8)));
    json_object_object_add(policy, "revision",
                           json_object_new_int64(sqlite3_column_int64(st, 9)));
    json_object_object_add(policy, "updated_at",
                           json_object_new_int64(sqlite3_column_int64(st, 10)));
    json_object_object_add(policy, "updated_by", json_object_new_string(
        (const char *)sqlite3_column_text(st, 11)));
    json_object_object_add(policy, "reassoc_block_enabled",
                           json_object_new_boolean(sqlite3_column_int(st, 12)));
    json_object_object_add(policy, "reassoc_block_sec",
                           json_object_new_int(sqlite3_column_int(st, 13)));
    json_object_object_add(policy, "reassoc_block_scope", json_object_new_string(
        (const char *)sqlite3_column_text(st, 14)));
    json_object_object_add(policy, "steering_preference", json_object_new_string(
        (const char *)sqlite3_column_text(st, 15)));
    json_object_object_add(policy, "high_band_steer_enabled",
                           json_object_new_boolean(sqlite3_column_int(st, 16)));
    json_object_object_add(policy, "force_disassoc_on_reject",
                           json_object_new_boolean(sqlite3_column_int(st, 17)));
    json_object_object_add(policy, "lower_band_block_enabled",
                           json_object_new_boolean(sqlite3_column_int(st, 18)));
    json_object_object_add(policy, "band_steer_mode",
                           json_object_new_int(sqlite3_column_int(st, 19)));
    json_object_object_add(policy, "band_steer_min_rssi_dbm",
                           json_object_new_int(sqlite3_column_int(st, 20)));
    sqlite3_finalize(st);
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "domain_id", json_object_new_string(domain_id));
    {
        /* Report the true enforcement state instead of a hardcoded label:
         * the periodic scheduler enforces on ac_roaming_domain_action_state
         * .steering_enabled (default 1) gated by the domain BTM/deauth flags,
         * so the old literal "observe_only" lied whenever steering was live. */
        sqlite3_stmt *ms = NULL;
        int steering_enabled = 1, btm_enabled = 0, deauth_enabled = 0;
        if (sqlite3_prepare_v2(g_ac_db,
                "SELECT COALESCE(a.steering_enabled,1),d.bss_transition_enabled,"
                "d.deauth_enabled FROM ac_roaming_domains d "
                "LEFT JOIN ac_roaming_domain_action_state a "
                "ON a.domain_id=d.domain_id WHERE d.domain_id=?1",
                -1, &ms, NULL) == SQLITE_OK) {
            sqlite3_bind_text(ms, 1, domain_id, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(ms) == SQLITE_ROW) {
                steering_enabled = sqlite3_column_int(ms, 0);
                btm_enabled = sqlite3_column_int(ms, 1);
                deauth_enabled = sqlite3_column_int(ms, 2);
            }
        }
        sqlite3_finalize(ms);
        json_object_object_add(root, "mode", json_object_new_string(
            (steering_enabled && (btm_enabled || deauth_enabled)) ?
            "automatic" : "observe_only"));
    }
    json_object_object_add(root, "policy", policy);
    return root;
invalid:
    json_object_put(policy);
    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "error", json_object_new_string("invalid_domain_id"));
    return root;
database_error:
    sqlite3_finalize(st);
    json_object_put(policy);
    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "error", json_object_new_string("database_error"));
    return root;
}

int ac_db_roaming_policy_put(const char *domain_id,
                             const struct ac_roaming_policy *policy,
                             int64_t base_revision)
{
    sqlite3_stmt *st = NULL;
    int exists = 0;
    int domain_exists = 0;
    int64_t revision = 0;
    int rc = AC_ROAMING_DOMAIN_DB_ERROR;

    if (!g_ac_db || !ac_uuid_valid(domain_id) || base_revision < 0 ||
        !ac_roaming_policy_valid(policy))
        return AC_ROAMING_DOMAIN_INVALID;
    if (ac_exec("BEGIN IMMEDIATE") != 0)
        return AC_ROAMING_DOMAIN_DB_ERROR;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT EXISTS(SELECT 1 FROM ac_roaming_domains WHERE domain_id=?1),"
            "COALESCE((SELECT revision FROM ac_roaming_policies WHERE domain_id=?1),0),"
            "EXISTS(SELECT 1 FROM ac_roaming_policies WHERE domain_id=?1)",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW)
        goto done;
    domain_exists = sqlite3_column_int(st, 0);
    revision = sqlite3_column_int64(st, 1);
    exists = sqlite3_column_int(st, 2);
    sqlite3_finalize(st);
    st = NULL;
    if (!domain_exists) {
        rc = AC_ROAMING_DOMAIN_NOT_FOUND;
        goto done;
    }
    if ((exists && revision != base_revision) || (!exists && base_revision != 0)) {
        rc = AC_ROAMING_DOMAIN_CONFLICT;
        goto done;
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_roaming_policies(domain_id,weak_rssi_dbm,"
            "minimum_candidate_gain_db,candidate_min_rssi_dbm,"
            "decision_min_interval_sec,post_roam_cooldown_sec,"
            "max_btm_attempts_per_hour,deauth_after_btm_failures,"
            "deauth_cooldown_sec,domain_action_rate_limit,revision,updated_at,updated_by,"
            "reassoc_block_enabled,reassoc_block_sec,reassoc_block_scope,"
            "steering_preference,high_band_steer_enabled,force_disassoc_on_reject,lower_band_block_enabled,"
            "band_steer_mode,band_steer_min_rssi_dbm) "
            "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,1,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21) "
            "ON CONFLICT(domain_id) DO UPDATE SET weak_rssi_dbm=excluded.weak_rssi_dbm,"
            "minimum_candidate_gain_db=excluded.minimum_candidate_gain_db,"
            "candidate_min_rssi_dbm=excluded.candidate_min_rssi_dbm,"
            "decision_min_interval_sec=excluded.decision_min_interval_sec,"
            "post_roam_cooldown_sec=excluded.post_roam_cooldown_sec,"
            "max_btm_attempts_per_hour=excluded.max_btm_attempts_per_hour,"
            "deauth_after_btm_failures=excluded.deauth_after_btm_failures,"
            "deauth_cooldown_sec=excluded.deauth_cooldown_sec,"
            "domain_action_rate_limit=excluded.domain_action_rate_limit,"
            "reassoc_block_enabled=excluded.reassoc_block_enabled,"
            "reassoc_block_sec=excluded.reassoc_block_sec,"
            "reassoc_block_scope=excluded.reassoc_block_scope,"
            "steering_preference=excluded.steering_preference,"
            "high_band_steer_enabled=excluded.high_band_steer_enabled,"
            "force_disassoc_on_reject=excluded.force_disassoc_on_reject,"
            "lower_band_block_enabled=excluded.lower_band_block_enabled,"
            "band_steer_mode=excluded.band_steer_mode,"
            "band_steer_min_rssi_dbm=excluded.band_steer_min_rssi_dbm,"
            "revision=ac_roaming_policies.revision+1,updated_at=excluded.updated_at,"
            "updated_by=excluded.updated_by",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, domain_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, policy->weak_rssi_dbm);
    sqlite3_bind_int(st, 3, policy->minimum_candidate_gain_db);
    sqlite3_bind_int(st, 4, policy->candidate_min_rssi_dbm);
    sqlite3_bind_int(st, 5, policy->decision_min_interval_sec);
    sqlite3_bind_int(st, 6, policy->post_roam_cooldown_sec);
    sqlite3_bind_int(st, 7, policy->max_btm_attempts_per_hour);
    sqlite3_bind_int(st, 8, policy->deauth_after_btm_failures);
    sqlite3_bind_int(st, 9, policy->deauth_cooldown_sec);
    sqlite3_bind_int(st, 10, policy->domain_action_rate_limit);
    sqlite3_bind_int64(st, 11, ac_now_s());
    sqlite3_bind_text(st, 12, policy->updated_by, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 13, policy->reassoc_block_enabled);
    sqlite3_bind_int(st, 14, policy->reassoc_block_sec ? policy->reassoc_block_sec : 10);
    sqlite3_bind_text(st, 15, policy->reassoc_block_scope[0] ?
                      policy->reassoc_block_scope : "ap", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 16, policy->steering_preference[0] ?
                      policy->steering_preference : "stability", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 17, policy->high_band_steer_enabled);
    sqlite3_bind_int(st, 18, policy->force_disassoc_on_reject);
    sqlite3_bind_int(st, 19, policy->lower_band_block_enabled);
    sqlite3_bind_int(st, 20, policy->band_steer_mode);
    sqlite3_bind_int(st, 21, policy->band_steer_min_rssi_dbm);
    if (sqlite3_step(st) == SQLITE_DONE)
        rc = 0;
done:
    sqlite3_finalize(st);
    if (rc == 0 && ac_exec("COMMIT") == 0)
        return 0;
    ac_exec("ROLLBACK");
    return rc;
}

int ac_db_pairing_token_revoke(const char *token_id)
{
    sqlite3_stmt *st = NULL;
    int64_t now = ac_now_s();
    int rc = -1;

    if (!g_ac_db || !ac_uuid_valid(token_id) || ac_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_pairing_tokens SET revoked_at=?1 WHERE token_id=?2 "
            "AND revoked_at=0 AND (consumed_at=0 OR EXISTS(SELECT 1 FROM ac_enrollments e "
            "WHERE e.token_id=ac_pairing_tokens.token_id AND e.state IN ('claimed','mtls_pending')))",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, token_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_enrollments SET state='revoked',failure_code='token_revoked',"
            "activation_challenge_hash=NULL,activation_expires_at=0,updated_at=?1 "
            "WHERE token_id=?2 AND state IN ('claimed','mtls_pending')",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, token_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_device_certificates SET state='revoked',revoked_at=?1 "
            "WHERE certificate_id IN (SELECT certificate_id FROM ac_enrollments WHERE token_id=?2) "
            "AND state='pending_activation'", -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, token_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE)
        rc = 0;
done:
    sqlite3_finalize(st);
    if (rc == 0 && ac_exec("COMMIT") == 0)
        return 0;
    ac_exec("ROLLBACK");
    return -1;
}

int ac_db_pairing_token_redeem(const char *token_id, const char *token,
                               const char *site_id,
                               const char *hardware_digest,
                               struct ac_pairing_token_status *out)
{
    sqlite3_stmt *st = NULL;
    struct ac_pairing_token_status status;
    char normalized_site[AC_PAIRING_SITE_ID_LEN + 1];
    char normalized_hardware[AC_PAIRING_HARDWARE_DIGEST_LEN + 1];
    char stored_site[AC_PAIRING_SITE_ID_LEN + 1];
    char stored_hardware[AC_PAIRING_HARDWARE_DIGEST_LEN + 1];
    unsigned char digest[AC_PAIRING_DIGEST_LEN];
    unsigned char stored_digest[AC_PAIRING_DIGEST_LEN];
    static const char invalid_token[AC_PAIRING_TOKEN_LEN + 1] =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const char *digest_token = token;
    int digest_version;
    int candidate_valid = 1;
    int matched;
    int already_claimed = 0;
    int rc = AC_PAIRING_REDEEM_ERROR;
    int64_t now = ac_now_s();

    memset(&status, 0, sizeof(status));
    memset(stored_digest, 0, sizeof(stored_digest));
    memset(normalized_site, 0, sizeof(normalized_site));
    memset(normalized_hardware, 0, sizeof(normalized_hardware));
    if (!g_ac_db || !ac_uuid_valid(token_id))
        goto done;
    if (!ac_token_valid(token)) {
        candidate_valid = 0;
        digest_token = invalid_token;
    }
    if (ac_site_id_normalize(site_id, normalized_site) != 0) {
        candidate_valid = 0;
        normalized_site[0] = '\0';
    }
    if (ac_hardware_digest_normalize(hardware_digest, normalized_hardware) != 0) {
        candidate_valid = 0;
        normalized_hardware[0] = '\0';
    }
    if (ac_exec("BEGIN IMMEDIATE") != 0)
        goto done;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT token_hash,digest_version,site_id,hardware_digest,attempts,max_attempts,"
            "created_at,expires_at,consumed_at,revoked_at,claimed_enrollment_id "
            "FROM ac_pairing_tokens WHERE token_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, token_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW)
        goto invalid_no_row;
    if (sqlite3_column_bytes(st, 0) != AC_PAIRING_DIGEST_LEN ||
        !sqlite3_column_blob(st, 0) || !sqlite3_column_text(st, 2) ||
        !sqlite3_column_text(st, 3))
        goto rollback;
    memcpy(stored_digest, sqlite3_column_blob(st, 0), sizeof(stored_digest));
    digest_version = sqlite3_column_int(st, 1);
    if (ac_site_id_normalize((const char *)sqlite3_column_text(st, 2),
                             stored_site) != 0 ||
        ac_hardware_digest_normalize((const char *)sqlite3_column_text(st, 3),
                                     stored_hardware) != 0)
        goto rollback;
    snprintf(status.token_id, sizeof(status.token_id), "%s", token_id);
    snprintf(status.site_id, sizeof(status.site_id), "%s", stored_site);
    status.hardware_bound = stored_hardware[0] != '\0';
    status.attempts = sqlite3_column_int(st, 4);
    status.max_attempts = sqlite3_column_int(st, 5);
    status.created_at = sqlite3_column_int64(st, 6);
    status.expires_at = sqlite3_column_int64(st, 7);
    status.consumed_at = sqlite3_column_int64(st, 8);
    status.revoked_at = sqlite3_column_int64(st, 9);
    already_claimed = sqlite3_column_text(st, 10) &&
                      sqlite3_column_text(st, 10)[0];
    sqlite3_finalize(st);
    st = NULL;
    if (digest_version != AC_PAIRING_DIGEST_VERSION)
        rc = AC_PAIRING_REDEEM_REVOKED;
    else if (status.revoked_at > 0)
        rc = AC_PAIRING_REDEEM_REVOKED;
    else if (status.consumed_at > 0)
        rc = AC_PAIRING_REDEEM_CONSUMED;
    else if (already_claimed)
        rc = AC_PAIRING_REDEEM_CONSUMED;
    else if (status.expires_at <= now)
        rc = AC_PAIRING_REDEEM_EXPIRED;
    else if (status.attempts >= status.max_attempts)
        rc = AC_PAIRING_REDEEM_EXHAUSTED;
    if (rc != AC_PAIRING_REDEEM_ERROR)
        goto commit;
    if (ac_token_digest(token_id, digest_token, status.expires_at, status.max_attempts,
                        stored_site, stored_hardware, digest) != 0)
        goto rollback;
    matched = candidate_valid &&
              CRYPTO_memcmp(stored_digest, digest, sizeof(digest)) == 0 &&
              (!stored_site[0] || strcmp(stored_site, normalized_site) == 0) &&
              (!stored_hardware[0] ||
               strcmp(stored_hardware, normalized_hardware) == 0);
    if (sqlite3_prepare_v2(g_ac_db, matched ?
            "UPDATE ac_pairing_tokens SET consumed_at=?1 WHERE token_id=?2 AND digest_version=?3 "
            "AND consumed_at=0 AND revoked_at=0 AND claimed_enrollment_id='' "
            "AND expires_at>?1 AND attempts<max_attempts" :
            "UPDATE ac_pairing_tokens SET attempts=attempts+1 WHERE token_id=?2 AND digest_version=?3 "
            "AND consumed_at=0 AND revoked_at=0 AND claimed_enrollment_id='' "
            "AND expires_at>?1 AND attempts<max_attempts",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, token_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, AC_PAIRING_DIGEST_VERSION);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto rollback;
    status.consumed_at = matched ? now : 0;
    if (!matched)
        status.attempts++;
    rc = matched ? AC_PAIRING_REDEEM_OK : AC_PAIRING_REDEEM_INVALID;
    goto commit;
invalid_no_row:
    sqlite3_finalize(st);
    st = NULL;
    rc = AC_PAIRING_REDEEM_INVALID;
commit:
    sqlite3_finalize(st);
    st = NULL;
    if (ac_exec("COMMIT") != 0) {
        rc = AC_PAIRING_REDEEM_ERROR;
        ac_exec("ROLLBACK");
        goto done;
    }
    ac_status_state(&status, now);
    if (out && status.token_id[0])
        *out = status;
    goto done;
rollback:
    sqlite3_finalize(st);
    st = NULL;
    ac_exec("ROLLBACK");
done:
    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_cleanse(stored_digest, sizeof(stored_digest));
    OPENSSL_cleanse(normalized_hardware, sizeof(normalized_hardware));
    OPENSSL_cleanse(stored_hardware, sizeof(stored_hardware));
    return rc;
}

static int ac_key_id_valid(const char *value)
{
    size_t i;

    if (!value || strlen(value) != AC_ENROLLMENT_KEY_ID_LEN ||
        strncmp(value, "sha256:", 7) != 0)
        return 0;
    for (i = 7; i < AC_ENROLLMENT_KEY_ID_LEN; i++)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f')))
            return 0;
    return 1;
}

static int ac_serial_valid(const char *value)
{
    size_t i;
    size_t len = value ? strlen(value) : 0;

    if (len == 0 || len > 128)
        return 0;
    for (i = 0; i < len; i++)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f')))
            return 0;
    return 1;
}

static int ac_enrollment_record_from_stmt(sqlite3_stmt *st,
                                           struct ac_enrollment_record *out)
{
    const unsigned char *enrollment_id;
    const unsigned char *token_id;
    const unsigned char *ap_id;
    const unsigned char *site_id;
    const unsigned char *key_id;
    const unsigned char *certificate_id;
    const unsigned char *state;

    if (!st || !out)
        return -1;
    enrollment_id = sqlite3_column_text(st, 0);
    token_id = sqlite3_column_text(st, 1);
    ap_id = sqlite3_column_text(st, 2);
    site_id = sqlite3_column_text(st, 3);
    key_id = sqlite3_column_text(st, 4);
    certificate_id = sqlite3_column_text(st, 5);
    state = sqlite3_column_text(st, 6);
    if (!enrollment_id || !token_id || !ap_id || !site_id || !key_id ||
        !certificate_id || !state || !ac_uuid_valid((const char *)enrollment_id) ||
        !ac_uuid_valid((const char *)token_id) || !ac_uuid_valid((const char *)ap_id) ||
        !ac_key_id_valid((const char *)key_id) ||
        (certificate_id[0] && !ac_uuid_valid((const char *)certificate_id)) ||
        strlen((const char *)site_id) > AC_PAIRING_SITE_ID_LEN ||
        strlen((const char *)state) >= sizeof(out->state))
        return -1;
    memset(out, 0, sizeof(*out));
    snprintf(out->enrollment_id, sizeof(out->enrollment_id), "%s", enrollment_id);
    snprintf(out->token_id, sizeof(out->token_id), "%s", token_id);
    snprintf(out->ap_id, sizeof(out->ap_id), "%s", ap_id);
    snprintf(out->site_id, sizeof(out->site_id), "%s", site_id);
    snprintf(out->key_id, sizeof(out->key_id), "%s", key_id);
    snprintf(out->certificate_id, sizeof(out->certificate_id), "%s",
             certificate_id);
    snprintf(out->state, sizeof(out->state), "%s", state);
    out->claim_expires_at = sqlite3_column_int64(st, 7);
    out->created_at = sqlite3_column_int64(st, 8);
    out->updated_at = sqlite3_column_int64(st, 9);
    out->adopted_at = sqlite3_column_int64(st, 10);
    return 0;
}

static const char ac_enrollment_record_select[] =
    "SELECT enrollment_id,token_id,ap_id,site_id,key_id,certificate_id,state,"
    "claim_expires_at,created_at,updated_at,adopted_at FROM ac_enrollments";

static int ac_enrollment_record_get(const char *enrollment_id,
                                    struct ac_enrollment_record *out)
{
    sqlite3_stmt *st = NULL;
    char sql[512];
    int rc = -1;

    if (!ac_uuid_valid(enrollment_id) || !out ||
        snprintf(sql, sizeof(sql), "%s WHERE enrollment_id=?1",
                 ac_enrollment_record_select) >= (int)sizeof(sql) ||
        sqlite3_prepare_v2(g_ac_db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, enrollment_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        rc = ac_enrollment_record_from_stmt(st, out);
    sqlite3_finalize(st);
    return rc;
}

int ac_db_enrollment_challenge_create(
    int64_t ttl_seconds, struct ac_enrollment_challenge *out)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!g_ac_db || !out || ttl_seconds < AC_ENROLLMENT_CHALLENGE_TTL_MIN ||
        ttl_seconds > AC_ENROLLMENT_CHALLENGE_TTL_MAX)
        return -1;
    memset(out, 0, sizeof(*out));
    if (ac_generate_uuid(out->challenge_id) != 0 ||
        RAND_bytes(out->server_nonce, sizeof(out->server_nonce)) != 1)
        goto done;
    out->created_at = ac_now_s();
    out->expires_at = out->created_at + ttl_seconds;
    if (ac_exec("BEGIN IMMEDIATE") != 0)
        goto done;
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_enrollment_challenges(challenge_id,server_nonce,created_at,expires_at,consumed_at) "
            "VALUES(?1,?2,?3,?4,0)", -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, out->challenge_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, out->server_nonce, sizeof(out->server_nonce),
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, out->created_at);
    sqlite3_bind_int64(st, 4, out->expires_at);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (ac_exec("COMMIT") != 0)
        goto rollback;
    rc = 0;
    goto done;
rollback:
    sqlite3_finalize(st);
    st = NULL;
    ac_exec("ROLLBACK");
done:
    sqlite3_finalize(st);
    if (rc != 0)
        OPENSSL_cleanse(out, sizeof(*out));
    return rc;
}

int ac_db_enrollment_challenge_get(
    const char *challenge_id, struct ac_enrollment_challenge *out)
{
    sqlite3_stmt *st = NULL;
    const void *nonce;
    int rc = -1;

    if (!g_ac_db || !ac_uuid_valid(challenge_id) || !out)
        return -1;
    memset(out, 0, sizeof(*out));
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT server_nonce,created_at,expires_at FROM ac_enrollment_challenges "
            "WHERE challenge_id=?1 AND consumed_at=0 AND expires_at>?2",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, challenge_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, ac_now_s());
    if (sqlite3_step(st) != SQLITE_ROW ||
        sqlite3_column_bytes(st, 0) != AC_ENROLLMENT_NONCE_LEN ||
        !(nonce = sqlite3_column_blob(st, 0)))
        goto done;
    snprintf(out->challenge_id, sizeof(out->challenge_id), "%s", challenge_id);
    memcpy(out->server_nonce, nonce, sizeof(out->server_nonce));
    out->created_at = sqlite3_column_int64(st, 1);
    out->expires_at = sqlite3_column_int64(st, 2);
    rc = 0;
done:
    sqlite3_finalize(st);
    return rc;
}

static int ac_claim_shape_valid(const struct ac_enrollment_claim *claim)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned char key_digest[SHA256_DIGEST_LENGTH];
    char expected_key_id[AC_ENROLLMENT_KEY_ID_LEN + 1];
    char normalized_site[AC_PAIRING_SITE_ID_LEN + 1];
    char normalized_hardware[AC_PAIRING_HARDWARE_DIGEST_LEN + 1];
    static const char digits[] = "0123456789abcdef";
    size_t i;
    int valid = 0;

    memset(expected_key_id, 0, sizeof(expected_key_id));
    if (!claim || !ac_uuid_valid(claim->challenge_id) ||
        !ac_uuid_valid(claim->enrollment_id) || !ac_uuid_valid(claim->token_id) ||
        !ac_uuid_valid(claim->ap_id) || !ac_key_id_valid(claim->key_id) ||
        !claim->csr_der || claim->csr_der_len == 0 ||
        claim->csr_der_len > AC_ENROLLMENT_CSR_MAX ||
        ac_site_id_normalize(claim->site_id, normalized_site) != 0 ||
        ac_hardware_digest_normalize(claim->hardware_digest,
                                     normalized_hardware) != 0 ||
        !SHA256(claim->csr_der, claim->csr_der_len, digest) ||
        CRYPTO_memcmp(digest, claim->csr_sha256, sizeof(digest)) != 0 ||
        !SHA256(claim->public_key, sizeof(claim->public_key), key_digest))
        goto done;
    memcpy(expected_key_id, "sha256:", 7);
    for (i = 0; i < sizeof(key_digest); i++) {
        expected_key_id[7 + i * 2] = digits[key_digest[i] >> 4];
        expected_key_id[7 + i * 2 + 1] = digits[key_digest[i] & 15];
    }
    valid = CRYPTO_memcmp(expected_key_id, claim->key_id,
                         AC_ENROLLMENT_KEY_ID_LEN) == 0;
done:
    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_cleanse(key_digest, sizeof(key_digest));
    OPENSSL_cleanse(expected_key_id, sizeof(expected_key_id));
    OPENSSL_cleanse(normalized_hardware, sizeof(normalized_hardware));
    return valid;
}

static int ac_claim_existing_matches(sqlite3_stmt *st,
                                     const struct ac_enrollment_claim *claim)
{
    const void *public_key = sqlite3_column_blob(st, 0);
    const void *csr_sha256 = sqlite3_column_blob(st, 1);
    const void *client_nonce = sqlite3_column_blob(st, 2);

    const char *expected_site = claim->site_id[0] ? claim->site_id : "default";
    char normalized_hardware[AC_PAIRING_HARDWARE_DIGEST_LEN + 1];
    int matched;

    if (ac_hardware_digest_normalize(claim->hardware_digest,
                                     normalized_hardware) != 0)
        return 0;
    matched = public_key && csr_sha256 && client_nonce &&
        sqlite3_column_bytes(st, 0) == AC_ENROLLMENT_PUBLIC_KEY_LEN &&
        sqlite3_column_bytes(st, 1) == SHA256_DIGEST_LENGTH &&
        sqlite3_column_bytes(st, 2) == AC_ENROLLMENT_NONCE_LEN &&
        sqlite3_column_text(st, 3) && sqlite3_column_text(st, 4) &&
        sqlite3_column_text(st, 5) && sqlite3_column_text(st, 6) &&
        sqlite3_column_text(st, 7) && sqlite3_column_text(st, 8) &&
        CRYPTO_memcmp(public_key, claim->public_key,
                      AC_ENROLLMENT_PUBLIC_KEY_LEN) == 0 &&
        CRYPTO_memcmp(csr_sha256, claim->csr_sha256,
                      SHA256_DIGEST_LENGTH) == 0 &&
        CRYPTO_memcmp(client_nonce, claim->client_nonce,
                      AC_ENROLLMENT_NONCE_LEN) == 0 &&
        strcmp((const char *)sqlite3_column_text(st, 3), claim->token_id) == 0 &&
        strcmp((const char *)sqlite3_column_text(st, 4), claim->ap_id) == 0 &&
        strcmp((const char *)sqlite3_column_text(st, 5), expected_site) == 0 &&
        strcmp((const char *)sqlite3_column_text(st, 6), claim->key_id) == 0 &&
        strcmp((const char *)sqlite3_column_text(st, 7), normalized_hardware) == 0 &&
        strcmp((const char *)sqlite3_column_text(st, 8), claim->challenge_id) == 0;
    OPENSSL_cleanse(normalized_hardware, sizeof(normalized_hardware));
    return matched;
}

static int ac_claim_recovery_get(const struct ac_enrollment_claim *claim,
                                 struct ac_enrollment_record *out)
{
    sqlite3_stmt *st = NULL;
    const void *stored_hash;
    const void *public_key;
    const void *csr_sha256;
    unsigned char candidate_hash[AC_PAIRING_DIGEST_LEN];
    char stored_site[AC_PAIRING_SITE_ID_LEN + 1];
    char stored_hardware[AC_PAIRING_HARDWARE_DIGEST_LEN + 1];
    char normalized_site[AC_PAIRING_SITE_ID_LEN + 1];
    char normalized_hardware[AC_PAIRING_HARDWARE_DIGEST_LEN + 1];
    char enrollment_id[AC_ENROLLMENT_ID_LEN + 1];
    int max_attempts;
    int64_t expires_at;
    int rc = -1;

    memset(candidate_hash, 0, sizeof(candidate_hash));
    memset(stored_site, 0, sizeof(stored_site));
    memset(stored_hardware, 0, sizeof(stored_hardware));
    memset(normalized_site, 0, sizeof(normalized_site));
    memset(normalized_hardware, 0, sizeof(normalized_hardware));
    memset(enrollment_id, 0, sizeof(enrollment_id));
    if (!claim || !out || !ac_token_valid(claim->token) ||
        ac_site_id_normalize(claim->site_id, normalized_site) != 0 ||
        ac_hardware_digest_normalize(claim->hardware_digest,
                                     normalized_hardware) != 0 ||
        sqlite3_prepare_v2(g_ac_db,
            "SELECT t.token_hash,t.site_id,t.hardware_digest,t.expires_at,t.max_attempts,"
            "e.enrollment_id,e.public_key,e.csr_sha256,e.ap_id,e.key_id,e.site_id,e.hardware_digest "
            "FROM ac_pairing_tokens t JOIN ac_enrollments e "
            "ON e.enrollment_id=t.consumed_enrollment_id "
            "WHERE t.token_id=?1 AND t.consumed_at>0 AND t.revoked_at=0 "
            "AND t.consumed_enrollment_id<>'' AND e.state IN ('mtls_pending','adopted')",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, claim->token_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW ||
        sqlite3_column_bytes(st, 0) != AC_PAIRING_DIGEST_LEN ||
        !(stored_hash = sqlite3_column_blob(st, 0)) ||
        !sqlite3_column_text(st, 1) || !sqlite3_column_text(st, 2) ||
        !sqlite3_column_text(st, 5) ||
        sqlite3_column_bytes(st, 6) != AC_ENROLLMENT_PUBLIC_KEY_LEN ||
        !(public_key = sqlite3_column_blob(st, 6)) ||
        sqlite3_column_bytes(st, 7) != SHA256_DIGEST_LENGTH ||
        !(csr_sha256 = sqlite3_column_blob(st, 7)) ||
        !sqlite3_column_text(st, 8) || !sqlite3_column_text(st, 9) ||
        !sqlite3_column_text(st, 10) || !sqlite3_column_text(st, 11))
        goto done;
    snprintf(stored_site, sizeof(stored_site), "%s", sqlite3_column_text(st, 1));
    snprintf(stored_hardware, sizeof(stored_hardware), "%s",
             sqlite3_column_text(st, 2));
    expires_at = sqlite3_column_int64(st, 3);
    max_attempts = sqlite3_column_int(st, 4);
    snprintf(enrollment_id, sizeof(enrollment_id), "%s",
             sqlite3_column_text(st, 5));
    if (expires_at <= ac_now_s() ||
        ac_token_digest(claim->token_id, claim->token, expires_at,
                        max_attempts, stored_site, stored_hardware,
                        candidate_hash) != 0 ||
        CRYPTO_memcmp(stored_hash, candidate_hash,
                      sizeof(candidate_hash)) != 0 ||
        CRYPTO_memcmp(public_key, claim->public_key,
                      AC_ENROLLMENT_PUBLIC_KEY_LEN) != 0 ||
        CRYPTO_memcmp(csr_sha256, claim->csr_sha256,
                      SHA256_DIGEST_LENGTH) != 0 ||
        strcmp((const char *)sqlite3_column_text(st, 8), claim->ap_id) != 0 ||
        strcmp((const char *)sqlite3_column_text(st, 9), claim->key_id) != 0 ||
        strcmp((const char *)sqlite3_column_text(st, 10),
               normalized_site[0] ? normalized_site : "default") != 0 ||
        strcmp((const char *)sqlite3_column_text(st, 11),
               normalized_hardware) != 0 ||
        ac_enrollment_record_get(enrollment_id, out) != 0)
        goto done;
    rc = 0;
done:
    sqlite3_finalize(st);
    OPENSSL_cleanse(candidate_hash, sizeof(candidate_hash));
    OPENSSL_cleanse(stored_site, sizeof(stored_site));
    OPENSSL_cleanse(stored_hardware, sizeof(stored_hardware));
    OPENSSL_cleanse(normalized_site, sizeof(normalized_site));
    OPENSSL_cleanse(normalized_hardware, sizeof(normalized_hardware));
    OPENSSL_cleanse(enrollment_id, sizeof(enrollment_id));
    return rc;
}

int ac_db_enrollment_claim(const struct ac_enrollment_claim *claim,
                           struct ac_enrollment_record *out)
{
    sqlite3_stmt *st = NULL;
    char normalized_site[AC_PAIRING_SITE_ID_LEN + 1];
    char normalized_hardware[AC_PAIRING_HARDWARE_DIGEST_LEN + 1];
    char stored_site[AC_PAIRING_SITE_ID_LEN + 1];
    char stored_hardware[AC_PAIRING_HARDWARE_DIGEST_LEN + 1];
    char effective_site[AC_PAIRING_SITE_ID_LEN + 1];
    unsigned char stored_digest[AC_PAIRING_DIGEST_LEN];
    unsigned char candidate_digest[AC_PAIRING_DIGEST_LEN];
    const void *server_nonce;
    const char *digest_token;
    static const char invalid_token[AC_PAIRING_TOKEN_LEN + 1] =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    int candidate_valid;
    int max_attempts;
    int attempts;
    int64_t expires_at;
    int64_t now = ac_now_s();
    int rc = AC_ENROLLMENT_ERROR;

    memset(stored_digest, 0, sizeof(stored_digest));
    memset(candidate_digest, 0, sizeof(candidate_digest));
    if (!g_ac_db || !out || !ac_claim_shape_valid(claim))
        goto done;
    memset(out, 0, sizeof(*out));
    if (ac_site_id_normalize(claim->site_id, normalized_site) != 0 ||
        ac_hardware_digest_normalize(claim->hardware_digest,
                                     normalized_hardware) != 0)
        goto done;
    candidate_valid = ac_token_valid(claim->token);
    digest_token = candidate_valid ? claim->token : invalid_token;
    if (ac_exec("BEGIN IMMEDIATE") != 0)
        goto done;

    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT public_key,csr_sha256,client_nonce,token_id,ap_id,site_id,key_id,"
            "hardware_digest,challenge_id FROM ac_enrollments WHERE enrollment_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, claim->enrollment_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        int matched = ac_claim_existing_matches(st, claim);
        sqlite3_finalize(st);
        st = NULL;
        if (!matched || ac_enrollment_record_get(claim->enrollment_id, out) != 0)
            rc = AC_ENROLLMENT_CONFLICT;
        else
            rc = AC_ENROLLMENT_IDEMPOTENT;
        goto commit;
    }
    sqlite3_finalize(st);
    st = NULL;

    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT server_nonce,expires_at,consumed_at FROM ac_enrollment_challenges "
            "WHERE challenge_id=?1", -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, claim->challenge_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW ||
        sqlite3_column_bytes(st, 0) != AC_ENROLLMENT_NONCE_LEN ||
        !(server_nonce = sqlite3_column_blob(st, 0))) {
        rc = AC_ENROLLMENT_INVALID;
        goto commit;
    }
    expires_at = sqlite3_column_int64(st, 1);
    if (sqlite3_column_int64(st, 2) > 0) {
        rc = AC_ENROLLMENT_CONFLICT;
        goto commit;
    }
    if (expires_at <= now || claim->challenge_expires_at != expires_at) {
        rc = AC_ENROLLMENT_EXPIRED;
        goto commit;
    }
    if (CRYPTO_memcmp(server_nonce, claim->server_nonce,
                      AC_ENROLLMENT_NONCE_LEN) != 0) {
        rc = AC_ENROLLMENT_INVALID;
        goto commit;
    }
    sqlite3_finalize(st);
    st = NULL;

    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_enrollment_challenges SET consumed_at=?1 WHERE challenge_id=?2 "
            "AND consumed_at=0 AND expires_at>?1", -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, claim->challenge_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;

    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT token_hash,digest_version,site_id,hardware_digest,attempts,max_attempts,"
            "expires_at,consumed_at,revoked_at,claimed_enrollment_id FROM ac_pairing_tokens "
            "WHERE token_id=?1", -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, claim->token_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW ||
        sqlite3_column_bytes(st, 0) != AC_PAIRING_DIGEST_LEN ||
        !sqlite3_column_blob(st, 0) || sqlite3_column_int(st, 1) !=
            AC_PAIRING_DIGEST_VERSION || !sqlite3_column_text(st, 2) ||
        !sqlite3_column_text(st, 3)) {
        rc = AC_ENROLLMENT_INVALID;
        goto commit;
    }
    memcpy(stored_digest, sqlite3_column_blob(st, 0), sizeof(stored_digest));
    if (ac_site_id_normalize((const char *)sqlite3_column_text(st, 2),
                             stored_site) != 0 ||
        ac_hardware_digest_normalize((const char *)sqlite3_column_text(st, 3),
                                     stored_hardware) != 0)
        goto rollback;
    attempts = sqlite3_column_int(st, 4);
    max_attempts = sqlite3_column_int(st, 5);
    expires_at = sqlite3_column_int64(st, 6);
    if (sqlite3_column_int64(st, 8) > 0) {
        rc = AC_ENROLLMENT_REVOKED;
        goto commit;
    }
    if (sqlite3_column_int64(st, 7) > 0 ||
        (sqlite3_column_text(st, 9) && sqlite3_column_text(st, 9)[0])) {
        sqlite3_finalize(st);
        st = NULL;
        rc = ac_claim_recovery_get(claim, out) == 0 ?
             AC_ENROLLMENT_IDEMPOTENT : AC_ENROLLMENT_CONFLICT;
        goto commit;
    }
    if (expires_at <= now) {
        rc = AC_ENROLLMENT_EXPIRED;
        goto commit;
    }
    if (attempts >= max_attempts) {
        rc = AC_ENROLLMENT_EXHAUSTED;
        goto commit;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (ac_token_digest(claim->token_id, digest_token, expires_at, max_attempts,
                        stored_site, stored_hardware, candidate_digest) != 0)
        goto rollback;
    candidate_valid = candidate_valid &&
        CRYPTO_memcmp(stored_digest, candidate_digest,
                      sizeof(stored_digest)) == 0 &&
        (!stored_site[0] || strcmp(stored_site, normalized_site) == 0) &&
        (!stored_hardware[0] ||
         strcmp(stored_hardware, normalized_hardware) == 0);

    if (!candidate_valid) {
        if (sqlite3_prepare_v2(g_ac_db,
                "UPDATE ac_pairing_tokens SET attempts=attempts+1 WHERE token_id=?1 "
                "AND consumed_at=0 AND revoked_at=0 AND claimed_enrollment_id='' "
                "AND expires_at>?2 AND attempts<max_attempts", -1, &st, NULL) != SQLITE_OK)
            goto rollback;
        sqlite3_bind_text(st, 1, claim->token_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, now);
        if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
            goto rollback;
        rc = AC_ENROLLMENT_INVALID;
        goto commit;
    }

    snprintf(effective_site, sizeof(effective_site), "%s",
             stored_site[0] ? stored_site :
             (normalized_site[0] ? normalized_site : "default"));
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_enrollments(enrollment_id,token_id,ap_id,site_id,key_id,public_key,"
            "csr_der,csr_sha256,hardware_digest,client_nonce,challenge_id,state,attempts,"
            "claim_expires_at,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,"
            "?11,'claimed',0,?12,?13,?13)", -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, claim->enrollment_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, claim->token_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, claim->ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, effective_site, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, claim->key_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 6, claim->public_key, sizeof(claim->public_key),
                      SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 7, claim->csr_der, (int)claim->csr_der_len,
                      SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 8, claim->csr_sha256, sizeof(claim->csr_sha256),
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, normalized_hardware, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 10, claim->client_nonce, sizeof(claim->client_nonce),
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 11, claim->challenge_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 12, now + AC_ENROLLMENT_CLAIM_TTL);
    sqlite3_bind_int64(st, 13, now);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;

    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_pairing_tokens SET claimed_enrollment_id=?1,claimed_at=?2 "
            "WHERE token_id=?3 AND consumed_at=0 AND revoked_at=0 AND claimed_enrollment_id='' "
            "AND expires_at>?2 AND attempts<max_attempts", -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, claim->enrollment_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now);
    sqlite3_bind_text(st, 3, claim->token_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_aps(ap_id,site_id,adoption_state,last_seen_at,capability_json) "
            "VALUES(?1,?2,'pending_pairing',0,'{}') ON CONFLICT(ap_id) DO UPDATE SET "
            "site_id=excluded.site_id WHERE ac_aps.adoption_state='pending_pairing'",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, claim->ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, effective_site, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto rollback;
    if (ac_enrollment_record_get(claim->enrollment_id, out) != 0)
        goto rollback;
    rc = AC_ENROLLMENT_OK;
commit:
    sqlite3_finalize(st);
    st = NULL;
    if (ac_exec("COMMIT") != 0) {
        ac_exec("ROLLBACK");
        rc = AC_ENROLLMENT_ERROR;
    }
    goto done;
rollback:
    sqlite3_finalize(st);
    ac_exec("ROLLBACK");
    rc = AC_ENROLLMENT_ERROR;
done:
    OPENSSL_cleanse(stored_digest, sizeof(stored_digest));
    OPENSSL_cleanse(candidate_digest, sizeof(candidate_digest));
    OPENSSL_cleanse(normalized_hardware, sizeof(normalized_hardware));
    OPENSSL_cleanse(stored_hardware, sizeof(stored_hardware));
    return rc;
}

int ac_db_enrollment_certificate_commit(
    const struct ac_enrollment_certificate *certificate,
    struct ac_enrollment_record *out)
{
    sqlite3_stmt *st = NULL;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    const void *stored_der;
    const void *stored_fingerprint;
    char ap_id[AC_ENROLLMENT_ID_LEN + 1];
    char key_id[AC_ENROLLMENT_KEY_ID_LEN + 1];
    char token_id[AC_PAIRING_TOKEN_ID_LEN + 1];
    char state[32];
    char stored_certificate_id[AC_ENROLLMENT_ID_LEN + 1];
    int64_t now = ac_now_s();
    int rc = AC_ENROLLMENT_ERROR;

    memset(digest, 0, sizeof(digest));
    if (!g_ac_db || !certificate || !out ||
        !ac_uuid_valid(certificate->enrollment_id) ||
        !ac_uuid_valid(certificate->certificate_id) ||
        !ac_serial_valid(certificate->serial) ||
        !ac_key_id_valid(certificate->issuer_key_id) ||
        !certificate->certificate_der || certificate->certificate_der_len == 0 ||
        certificate->certificate_der_len > AC_ENROLLMENT_CERT_MAX ||
        certificate->not_before > now || certificate->not_after <= now ||
        !SHA256(certificate->certificate_der, certificate->certificate_der_len,
                digest) ||
        CRYPTO_memcmp(digest, certificate->fingerprint_sha256,
                      sizeof(digest)) != 0)
        goto done;
    memset(out, 0, sizeof(*out));
    if (ac_exec("BEGIN IMMEDIATE") != 0)
        goto done;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT ap_id,key_id,token_id,state,claim_expires_at,certificate_id "
            "FROM ac_enrollments WHERE enrollment_id=?1", -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, certificate->enrollment_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW || !sqlite3_column_text(st, 0) ||
        !sqlite3_column_text(st, 1) || !sqlite3_column_text(st, 2) ||
        !sqlite3_column_text(st, 3) || !sqlite3_column_text(st, 5)) {
        rc = AC_ENROLLMENT_INVALID;
        goto commit;
    }
    snprintf(ap_id, sizeof(ap_id), "%s", sqlite3_column_text(st, 0));
    snprintf(key_id, sizeof(key_id), "%s", sqlite3_column_text(st, 1));
    snprintf(token_id, sizeof(token_id), "%s", sqlite3_column_text(st, 2));
    snprintf(state, sizeof(state), "%s", sqlite3_column_text(st, 3));
    if (strcmp(state, "mtls_pending") == 0) {
        snprintf(stored_certificate_id, sizeof(stored_certificate_id), "%s",
                 sqlite3_column_text(st, 5));
        sqlite3_finalize(st);
        st = NULL;
        if (strcmp(stored_certificate_id, certificate->certificate_id) != 0 ||
            sqlite3_prepare_v2(g_ac_db,
                "SELECT certificate_der,fingerprint_sha256,serial,issuer_key_id,not_before,not_after "
                "FROM ac_device_certificates WHERE certificate_id=?1 AND state='pending_activation'",
                -1, &st, NULL) != SQLITE_OK)
            goto conflict;
        sqlite3_bind_text(st, 1, certificate->certificate_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_ROW ||
            !(stored_der = sqlite3_column_blob(st, 0)) ||
            !(stored_fingerprint = sqlite3_column_blob(st, 1)) ||
            sqlite3_column_bytes(st, 0) != (int)certificate->certificate_der_len ||
            sqlite3_column_bytes(st, 1) != SHA256_DIGEST_LENGTH ||
            CRYPTO_memcmp(stored_der, certificate->certificate_der,
                          certificate->certificate_der_len) != 0 ||
            CRYPTO_memcmp(stored_fingerprint, certificate->fingerprint_sha256,
                          SHA256_DIGEST_LENGTH) != 0 ||
            !sqlite3_column_text(st, 2) || !sqlite3_column_text(st, 3) ||
            strcmp((const char *)sqlite3_column_text(st, 2), certificate->serial) != 0 ||
            strcmp((const char *)sqlite3_column_text(st, 3),
                   certificate->issuer_key_id) != 0 ||
            sqlite3_column_int64(st, 4) != certificate->not_before ||
            sqlite3_column_int64(st, 5) != certificate->not_after)
            goto conflict;
        sqlite3_finalize(st);
        st = NULL;
        if (ac_enrollment_record_get(certificate->enrollment_id, out) != 0)
            goto rollback;
        rc = AC_ENROLLMENT_IDEMPOTENT;
        goto commit;
    }
    if (strcmp(state, "claimed") != 0) {
        rc = AC_ENROLLMENT_CONFLICT;
        goto commit;
    }
    if (sqlite3_column_int64(st, 4) <= now) {
        sqlite3_finalize(st);
        st = NULL;
        if (sqlite3_prepare_v2(g_ac_db,
                "UPDATE ac_enrollments SET state='expired',failure_code='claim_expired',"
                "updated_at=?1 WHERE enrollment_id=?2 AND state='claimed'",
                -1, &st, NULL) != SQLITE_OK)
            goto rollback;
        sqlite3_bind_int64(st, 1, now);
        sqlite3_bind_text(st, 2, certificate->enrollment_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE)
            goto rollback;
        rc = AC_ENROLLMENT_EXPIRED;
        goto commit;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_device_certificates(certificate_id,ap_id,serial,key_id,not_before,"
            "not_after,state,revoked_at,certificate_der,fingerprint_sha256,issuer_key_id,issued_at,"
            "activated_at) VALUES(?1,?2,?3,?4,?5,?6,'pending_activation',0,?7,?8,?9,?10,0)",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, certificate->certificate_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, certificate->serial, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, key_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 5, certificate->not_before);
    sqlite3_bind_int64(st, 6, certificate->not_after);
    sqlite3_bind_blob(st, 7, certificate->certificate_der,
                      (int)certificate->certificate_der_len, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 8, certificate->fingerprint_sha256,
                      sizeof(certificate->fingerprint_sha256), SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, certificate->issuer_key_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 10, now);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_enrollments SET state='mtls_pending',certificate_id=?1,updated_at=?2 "
            "WHERE enrollment_id=?3 AND state='claimed' AND certificate_id=''",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, certificate->certificate_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now);
    sqlite3_bind_text(st, 3, certificate->enrollment_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_pairing_tokens SET consumed_at=?1,consumed_enrollment_id=?2 "
            "WHERE token_id=?3 AND claimed_enrollment_id=?2 AND consumed_at=0 AND revoked_at=0",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, certificate->enrollment_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, token_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto rollback;
    if (ac_enrollment_record_get(certificate->enrollment_id, out) != 0)
        goto rollback;
    rc = AC_ENROLLMENT_OK;
    goto commit;
conflict:
    rc = AC_ENROLLMENT_CONFLICT;
commit:
    sqlite3_finalize(st);
    st = NULL;
    if (ac_exec("COMMIT") != 0) {
        ac_exec("ROLLBACK");
        rc = AC_ENROLLMENT_ERROR;
    }
    goto done;
rollback:
    sqlite3_finalize(st);
    ac_exec("ROLLBACK");
done:
    OPENSSL_cleanse(digest, sizeof(digest));
    return rc;
}

int ac_db_enrollment_certificate_get(
    const char *enrollment_id, struct ac_enrollment_certificate *out,
    unsigned char **owned_der)
{
    sqlite3_stmt *st = NULL;
    const void *der;
    const void *fingerprint;
    int der_len;
    int rc = -1;

    if (!g_ac_db || !out || !owned_der || !ac_uuid_valid(enrollment_id))
        return -1;
    memset(out, 0, sizeof(*out));
    *owned_der = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT e.certificate_id,c.serial,c.issuer_key_id,c.certificate_der,"
            "c.fingerprint_sha256,c.not_before,c.not_after "
            "FROM ac_enrollments e JOIN ac_device_certificates c "
            "ON c.certificate_id=e.certificate_id AND c.ap_id=e.ap_id "
            "WHERE e.enrollment_id=?1 AND e.state IN ('mtls_pending','adopted') "
            "AND c.state IN ('pending_activation','active')",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, enrollment_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW || !sqlite3_column_text(st, 0) ||
        !sqlite3_column_text(st, 1) || !sqlite3_column_text(st, 2) ||
        !(der = sqlite3_column_blob(st, 3)) ||
        (der_len = sqlite3_column_bytes(st, 3)) <= 0 ||
        der_len > AC_ENROLLMENT_CERT_MAX ||
        !(fingerprint = sqlite3_column_blob(st, 4)) ||
        sqlite3_column_bytes(st, 4) != SHA256_DIGEST_LENGTH ||
        !(*owned_der = malloc((size_t)der_len)))
        goto done;
    memcpy(*owned_der, der, (size_t)der_len);
    snprintf(out->enrollment_id, sizeof(out->enrollment_id), "%s", enrollment_id);
    snprintf(out->certificate_id, sizeof(out->certificate_id), "%s",
             sqlite3_column_text(st, 0));
    snprintf(out->serial, sizeof(out->serial), "%s", sqlite3_column_text(st, 1));
    snprintf(out->issuer_key_id, sizeof(out->issuer_key_id), "%s",
             sqlite3_column_text(st, 2));
    out->certificate_der = *owned_der;
    out->certificate_der_len = (size_t)der_len;
    memcpy(out->fingerprint_sha256, fingerprint, SHA256_DIGEST_LENGTH);
    out->not_before = sqlite3_column_int64(st, 5);
    out->not_after = sqlite3_column_int64(st, 6);
    rc = 0;
done:
    sqlite3_finalize(st);
    if (rc != 0 && *owned_der) {
        OPENSSL_cleanse(*owned_der, out->certificate_der_len);
        free(*owned_der);
        *owned_der = NULL;
        memset(out, 0, sizeof(*out));
    }
    return rc;
}

int ac_db_certificate_peer_authorize(
    const char *certificate_id, const char *ap_id,
    const unsigned char fingerprint_sha256[32], int require_active)
{
    sqlite3_stmt *st = NULL;
    int64_t now = ac_now_s();
    int authorized = 0;

    if (!g_ac_db || !ac_uuid_valid(certificate_id) || !ac_uuid_valid(ap_id) ||
        !fingerprint_sha256 ||
        sqlite3_prepare_v2(g_ac_db,
            "SELECT 1 FROM ac_device_certificates c WHERE c.certificate_id=?1 "
            "AND c.ap_id=?2 AND c.fingerprint_sha256=?3 AND c.revoked_at=0 "
            "AND c.not_before<=?4 AND c.not_after>?4 AND c.state=?5 "
            "AND EXISTS(SELECT 1 FROM ac_enrollments e WHERE e.ap_id=c.ap_id "
            "AND e.key_id=c.key_id AND e.state=?6 "
            "AND (?5='active' OR e.certificate_id=c.certificate_id))",
            -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, certificate_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 3, fingerprint_sha256, SHA256_DIGEST_LENGTH,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, now);
    sqlite3_bind_text(st, 5, require_active ? "active" : "pending_activation",
                      -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 6, require_active ? "adopted" : "mtls_pending",
                      -1, SQLITE_STATIC);
    authorized = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return authorized;
}

int ac_db_enrollment_activation_begin(
    const char *enrollment_id, const char *certificate_id,
    unsigned char challenge[AC_ENROLLMENT_NONCE_LEN])
{
    sqlite3_stmt *st = NULL;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    int64_t now = ac_now_s();
    int rc = -1;

    memset(digest, 0, sizeof(digest));
    if (!g_ac_db || !ac_uuid_valid(enrollment_id) ||
        !ac_uuid_valid(certificate_id) || !challenge ||
        RAND_bytes(challenge, AC_ENROLLMENT_NONCE_LEN) != 1 ||
        !SHA256(challenge, AC_ENROLLMENT_NONCE_LEN, digest) ||
        ac_exec("BEGIN IMMEDIATE") != 0)
        goto done;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_enrollments SET activation_challenge_hash=?1,activation_expires_at=?2,"
            "updated_at=?3 WHERE enrollment_id=?4 AND certificate_id=?5 "
            "AND state='mtls_pending' AND EXISTS(SELECT 1 FROM ac_device_certificates c "
            "WHERE c.certificate_id=?5 AND c.ap_id=ac_enrollments.ap_id "
            "AND c.state='pending_activation' AND c.not_before<=?3 AND c.not_after>?3) "
            "AND attempts<?6",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_blob(st, 1, digest, sizeof(digest), SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now + AC_ENROLLMENT_ACTIVATION_TTL);
    sqlite3_bind_int64(st, 3, now);
    sqlite3_bind_text(st, 4, enrollment_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, certificate_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 6, AC_ENROLLMENT_ACTIVATION_ATTEMPTS);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (ac_exec("COMMIT") != 0)
        goto rollback;
    rc = 0;
    goto done;
rollback:
    sqlite3_finalize(st);
    st = NULL;
    ac_exec("ROLLBACK");
done:
    sqlite3_finalize(st);
    OPENSSL_cleanse(digest, sizeof(digest));
    if (rc != 0)
        OPENSSL_cleanse(challenge, AC_ENROLLMENT_NONCE_LEN);
    return rc;
}

int ac_db_enrollment_activate(
    const char *enrollment_id, const char *certificate_id,
    const unsigned char peer_fingerprint_sha256[32],
    const unsigned char *challenge, size_t challenge_len,
    struct ac_enrollment_record *out)
{
    sqlite3_stmt *st = NULL;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned char stored[SHA256_DIGEST_LENGTH];
    char ap_id[AC_ENROLLMENT_ID_LEN + 1];
    const void *stored_blob;
    int attempts;
    int matched;
    int64_t expires_at;
    int64_t now = ac_now_s();
    int rc = AC_ENROLLMENT_ERROR;

    memset(digest, 0, sizeof(digest));
    memset(stored, 0, sizeof(stored));
    if (!g_ac_db || !out || !ac_uuid_valid(enrollment_id) ||
        !ac_uuid_valid(certificate_id) || !peer_fingerprint_sha256 || !challenge ||
        challenge_len != AC_ENROLLMENT_NONCE_LEN ||
        !SHA256(challenge, challenge_len, digest) ||
        ac_exec("BEGIN IMMEDIATE") != 0)
        goto done;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT e.activation_challenge_hash,e.activation_expires_at,e.attempts,e.ap_id "
            "FROM ac_enrollments e JOIN ac_device_certificates c "
            "ON c.certificate_id=e.certificate_id AND c.ap_id=e.ap_id "
            "WHERE e.enrollment_id=?1 AND e.certificate_id=?2 AND e.state='mtls_pending' "
            "AND c.state='pending_activation' AND c.fingerprint_sha256=?3",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, enrollment_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, certificate_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 3, peer_fingerprint_sha256, SHA256_DIGEST_LENGTH,
                      SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW ||
        !(stored_blob = sqlite3_column_blob(st, 0)) ||
        sqlite3_column_bytes(st, 0) != SHA256_DIGEST_LENGTH ||
        !sqlite3_column_text(st, 3)) {
        rc = AC_ENROLLMENT_INVALID;
        goto commit;
    }
    memcpy(stored, stored_blob, sizeof(stored));
    expires_at = sqlite3_column_int64(st, 1);
    attempts = sqlite3_column_int(st, 2);
    snprintf(ap_id, sizeof(ap_id), "%s", sqlite3_column_text(st, 3));
    sqlite3_finalize(st);
    st = NULL;
    if (expires_at <= now) {
        rc = AC_ENROLLMENT_EXPIRED;
        goto commit;
    }
    if (attempts >= AC_ENROLLMENT_ACTIVATION_ATTEMPTS) {
        rc = AC_ENROLLMENT_EXHAUSTED;
        goto commit;
    }
    matched = CRYPTO_memcmp(stored, digest, sizeof(digest)) == 0;
    if (!matched) {
        if (sqlite3_prepare_v2(g_ac_db,
                "UPDATE ac_enrollments SET attempts=attempts+1,state=CASE WHEN attempts+1>=?1 "
                "THEN 'failed' ELSE state END,failure_code=CASE WHEN attempts+1>=?1 "
                "THEN 'activation_attempts_exhausted' ELSE failure_code END,"
                "activation_challenge_hash=CASE WHEN attempts+1>=?1 THEN NULL ELSE activation_challenge_hash END,"
                "updated_at=?2 WHERE enrollment_id=?3 AND certificate_id=?4 AND state='mtls_pending'",
                -1, &st, NULL) != SQLITE_OK)
            goto rollback;
        sqlite3_bind_int(st, 1, AC_ENROLLMENT_ACTIVATION_ATTEMPTS);
        sqlite3_bind_int64(st, 2, now);
        sqlite3_bind_text(st, 3, enrollment_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, certificate_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
            goto rollback;
        rc = AC_ENROLLMENT_INVALID;
        goto commit;
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_device_certificates SET state='active',activated_at=?1 "
            "WHERE certificate_id=?2 AND ap_id=?3 AND state='pending_activation' "
            "AND not_before<=?1 AND not_after>?1", -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, certificate_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_enrollments SET state='adopted',adopted_at=?1,updated_at=?1,"
            "activation_challenge_hash=NULL,activation_expires_at=0,failure_code='' "
            "WHERE enrollment_id=?2 AND certificate_id=?3 AND state='mtls_pending'",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, enrollment_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, certificate_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_aps SET adoption_state='adopted',last_seen_at=?1 WHERE ap_id=?2 "
            "AND adoption_state='pending_pairing'", -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto rollback;
    if (ac_enrollment_record_get(enrollment_id, out) != 0)
        goto rollback;
    rc = AC_ENROLLMENT_OK;
commit:
    sqlite3_finalize(st);
    st = NULL;
    if (ac_exec("COMMIT") != 0) {
        ac_exec("ROLLBACK");
        rc = AC_ENROLLMENT_ERROR;
    }
    goto done;
rollback:
    sqlite3_finalize(st);
    ac_exec("ROLLBACK");
done:
    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_cleanse(stored, sizeof(stored));
    return rc;
}

/* ── AP Binding schema and CRUD ── */

int ac_db_binding_schema_init(void)
{
    static const char schema[] =
        "CREATE TABLE IF NOT EXISTS ac_binding_requests ("
        " binding_id TEXT PRIMARY KEY,"
        " bootstrap_id TEXT NOT NULL,"
        " key_fingerprint TEXT NOT NULL,"
        " ticket_nonce TEXT NOT NULL,"
        " ticket_expires_at INTEGER NOT NULL,"
        " ticket_consumed_at INTEGER NOT NULL DEFAULT 0,"
        " controller_id TEXT NOT NULL,"
        " site_id TEXT NOT NULL DEFAULT 'default',"
        " state TEXT NOT NULL DEFAULT 'identified'"
        "  CHECK(state IN ('identified','awaiting_confirmation',"
        "   'binding_requested','enrollment_pending',"
        "   'certificate_pending','activating',"
        "   'adopted','online','failed','cancelled','expired')),"
        " enrollment_id TEXT NOT NULL DEFAULT '',"
        " pairing_token_id TEXT NOT NULL DEFAULT '',"
        " idempotency_key TEXT NOT NULL DEFAULT '',"
        " client_info TEXT NOT NULL DEFAULT '{}',"
        " error_code TEXT NOT NULL DEFAULT '',"
        " failure_code TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL,"
        " updated_at INTEGER NOT NULL,"
        " expires_at INTEGER NOT NULL);"
        "CREATE INDEX IF NOT EXISTS idx_ac_binding_bootstrap"
        " ON ac_binding_requests(bootstrap_id,state);"
        "CREATE INDEX IF NOT EXISTS idx_ac_binding_nonce"
        " ON ac_binding_requests(ticket_nonce,ticket_expires_at);"
        "CREATE INDEX IF NOT EXISTS idx_ac_binding_idempotency"
        " ON ac_binding_requests(idempotency_key);"
        "CREATE TABLE IF NOT EXISTS ac_binding_nonces ("
        " nonce TEXT PRIMARY KEY,"
        " first_seen_at INTEGER NOT NULL,"
        " binding_id TEXT NOT NULL);";

    return ac_exec(schema);
}

static int ac_uuid_v4(char *out, size_t out_size)
{
    unsigned char buf[16];
    int i;

    if (out_size < 37)
        return -1;
    if (RAND_bytes(buf, sizeof(buf)) != 1)
        return -1;
    /* Set version 4 and variant bits. */
    buf[6] = (unsigned char)((buf[6] & 0x0f) | 0x40);
    buf[8] = (unsigned char)((buf[8] & 0x3f) | 0x80);
    for (i = 0; i < 16; i++) {
        static const char hex[] = "0123456789abcdef";
        int pos = i * 2 + (i >= 4 ? 1 : 0) + (i >= 6 ? 1 : 0) +
                  (i >= 8 ? 1 : 0) + (i >= 10 ? 1 : 0);

        if (i == 4 || i == 6 || i == 8 || i == 10)
            out[pos - 1] = '-';
        out[pos] = hex[buf[i] >> 4];
        out[pos + 1] = hex[buf[i] & 0x0f];
    }
    out[36] = '\0';
    return 0;
}

static void ac_binding_row_read(sqlite3_stmt *st, struct ac_binding_request *out)
{
    memset(out, 0, sizeof(*out));
    strncpy(out->binding_id, (const char *)sqlite3_column_text(st, 0),
            sizeof(out->binding_id) - 1);
    strncpy(out->bootstrap_id, (const char *)sqlite3_column_text(st, 1),
            sizeof(out->bootstrap_id) - 1);
    strncpy(out->key_fingerprint, (const char *)sqlite3_column_text(st, 2),
            sizeof(out->key_fingerprint) - 1);
    strncpy(out->ticket_nonce, (const char *)sqlite3_column_text(st, 3),
            sizeof(out->ticket_nonce) - 1);
    out->ticket_expires_at = sqlite3_column_int64(st, 4);
    out->ticket_consumed_at = sqlite3_column_int64(st, 5);
    strncpy(out->controller_id, (const char *)sqlite3_column_text(st, 6),
            sizeof(out->controller_id) - 1);
    strncpy(out->site_id, (const char *)sqlite3_column_text(st, 7),
            sizeof(out->site_id) - 1);
    strncpy(out->state, (const char *)sqlite3_column_text(st, 8),
            sizeof(out->state) - 1);
    strncpy(out->enrollment_id, (const char *)sqlite3_column_text(st, 9),
            sizeof(out->enrollment_id) - 1);
    strncpy(out->pairing_token_id, (const char *)sqlite3_column_text(st, 10),
            sizeof(out->pairing_token_id) - 1);
    strncpy(out->idempotency_key, (const char *)sqlite3_column_text(st, 11),
            sizeof(out->idempotency_key) - 1);
    strncpy(out->client_info, (const char *)sqlite3_column_text(st, 12),
            sizeof(out->client_info) - 1);
    strncpy(out->error_code, (const char *)sqlite3_column_text(st, 13),
            sizeof(out->error_code) - 1);
    strncpy(out->failure_code, (const char *)sqlite3_column_text(st, 14),
            sizeof(out->failure_code) - 1);
    out->created_at = sqlite3_column_int64(st, 15);
    out->updated_at = sqlite3_column_int64(st, 16);
    out->expires_at = sqlite3_column_int64(st, 17);
}

#define AC_BINDING_COLUMNS \
    "binding_id,bootstrap_id,key_fingerprint,ticket_nonce," \
    "ticket_expires_at,ticket_consumed_at,controller_id,site_id,state," \
    "enrollment_id,pairing_token_id,idempotency_key,client_info," \
    "error_code,failure_code,created_at,updated_at,expires_at"

int ac_db_binding_create(const char *bootstrap_id, const char *key_fingerprint,
                         const char *ticket_nonce, int64_t ticket_expires_at,
                         const char *controller_id, const char *site_id,
                         const char *idempotency_key, const char *client_info,
                         struct ac_binding_request *out)
{
    sqlite3_stmt *st = NULL;
    int64_t now = ac_now_s();
    char binding_id[AC_BINDING_ID_LEN + 1];

    if (!bootstrap_id || !key_fingerprint || !ticket_nonce ||
        !controller_id || !site_id || !out)
        return AC_BINDING_ERR_QR;

    if (ac_uuid_v4(binding_id, sizeof(binding_id)) != 0)
        return AC_BINDING_ERR_DB;

    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_binding_requests"
            "(binding_id,bootstrap_id,key_fingerprint,ticket_nonce,"
            "ticket_expires_at,controller_id,site_id,state,"
            "idempotency_key,client_info,created_at,updated_at,expires_at)"
            " VALUES(?1,?2,?3,?4,?5,?6,?7,'awaiting_confirmation',"
            "?8,?9,?10,?10,?11)",
            -1, &st, NULL) != SQLITE_OK)
        return AC_BINDING_ERR_DB;

    sqlite3_bind_text(st, 1, binding_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, bootstrap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, key_fingerprint, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, ticket_nonce, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 5, ticket_expires_at);
    sqlite3_bind_text(st, 6, controller_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, site_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, idempotency_key ? idempotency_key : "",
                      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, client_info ? client_info : "{}",
                      -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 10, now);
    sqlite3_bind_int64(st, 11, now + AC_BINDING_REQUEST_TTL);

    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return AC_BINDING_ERR_DB;
    }
    sqlite3_finalize(st);

    return ac_db_binding_get(binding_id, out);
}

int ac_db_binding_get(const char *binding_id, struct ac_binding_request *out)
{
    sqlite3_stmt *st = NULL;

    if (!binding_id || !out)
        return AC_BINDING_ERR_NOT_FOUND;

    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT " AC_BINDING_COLUMNS
            " FROM ac_binding_requests WHERE binding_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        return AC_BINDING_ERR_NOT_FOUND;

    sqlite3_bind_text(st, 1, binding_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        return AC_BINDING_ERR_NOT_FOUND;
    }
    ac_binding_row_read(st, out);
    sqlite3_finalize(st);
    return AC_BINDING_OK;
}

int ac_db_binding_pending(const char *bootstrap_id,
                          const char *exclude_binding_id)
{
    sqlite3_stmt *st = NULL;
    int pending = 0;

    if (!bootstrap_id || !bootstrap_id[0])
        return 0;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT 1 FROM ac_binding_requests WHERE bootstrap_id=?1 "
            "AND binding_id<>?2 AND ((state='awaiting_confirmation' "
            "AND ticket_expires_at>=?3) OR (state IN ('binding_requested',"
            "'enrollment_pending','certificate_pending','activating') "
            "AND expires_at>=?3)) LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
        return 1;
    sqlite3_bind_text(st, 1, bootstrap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, exclude_binding_id ? exclude_binding_id : "",
                      -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, ac_now_s());
    if (sqlite3_step(st) == SQLITE_ROW)
        pending = 1;
    sqlite3_finalize(st);
    return pending;
}

int ac_db_binding_update_state(const char *binding_id, const char *new_state,
                               const char *enrollment_id,
                               const char *pairing_token_id,
                               const char *error_code,
                               const char *failure_code)
{
    sqlite3_stmt *st = NULL;
    int64_t now = ac_now_s();

    if (!binding_id || !new_state)
        return AC_BINDING_ERR_DB;

    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_binding_requests SET state=?1,enrollment_id=?2,"
            "pairing_token_id=?3,error_code=?4,failure_code=?5,"
            "updated_at=?6 WHERE binding_id=?7",
            -1, &st, NULL) != SQLITE_OK)
        return AC_BINDING_ERR_DB;

    sqlite3_bind_text(st, 1, new_state, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, enrollment_id ? enrollment_id : "",
                      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, pairing_token_id ? pairing_token_id : "",
                      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, error_code ? error_code : "",
                      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, failure_code ? failure_code : "",
                      -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, now);
    sqlite3_bind_text(st, 7, binding_id, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1) {
        sqlite3_finalize(st);
        return AC_BINDING_ERR_NOT_FOUND;
    }
    sqlite3_finalize(st);
    return AC_BINDING_OK;
}

int ac_db_binding_consume_ticket(const char *binding_id)
{
    sqlite3_stmt *st = NULL;
    int64_t now = ac_now_s();

    if (!binding_id)
        return AC_BINDING_ERR_DB;

    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_binding_requests SET ticket_consumed_at=?1,"
            "updated_at=?1 WHERE binding_id=?2 AND ticket_consumed_at=0",
            -1, &st, NULL) != SQLITE_OK)
        return AC_BINDING_ERR_DB;

    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, binding_id, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1) {
        sqlite3_finalize(st);
        return AC_BINDING_ERR_CONSUMED;
    }
    sqlite3_finalize(st);
    return AC_BINDING_OK;
}

int ac_db_binding_activate(const char *binding_id,
                           const char *pairing_token_id,
                           const char *ticket_nonce)
{
    sqlite3_stmt *st = NULL;
    int64_t now = ac_now_s();
    int rc = AC_BINDING_ERR_DB;

    if (!binding_id || !pairing_token_id || !pairing_token_id[0] ||
        !ticket_nonce || !ticket_nonce[0] ||
        ac_exec("BEGIN IMMEDIATE") != 0)
        return AC_BINDING_ERR_DB;
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_binding_nonces"
            "(nonce,first_seen_at,binding_id) VALUES(?1,?2,?3)",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, ticket_nonce, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now);
    sqlite3_bind_text(st, 3, binding_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        rc = sqlite3_errcode(g_ac_db) == SQLITE_CONSTRAINT ?
            AC_BINDING_ERR_REPLAYED : AC_BINDING_ERR_DB;
        goto done;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_binding_requests SET ticket_consumed_at=?1,"
            "state='enrollment_pending',pairing_token_id=?2,updated_at=?1,"
            "expires_at=?5 "
            "WHERE binding_id=?3 AND state='awaiting_confirmation' "
            "AND ticket_consumed_at=0 AND ticket_expires_at>=?1 "
            "AND ticket_nonce=?4",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, pairing_token_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, binding_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, ticket_nonce, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 5, now + AC_BINDING_REQUEST_TTL);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    rc = sqlite3_changes(g_ac_db) == 1 ?
        AC_BINDING_OK : AC_BINDING_ERR_CONSUMED;
done:
    sqlite3_finalize(st);
    if (rc == AC_BINDING_OK && ac_exec("COMMIT") == 0)
        return AC_BINDING_OK;
    ac_exec("ROLLBACK");
    return rc == AC_BINDING_OK ? AC_BINDING_ERR_DB : rc;
}

int ac_db_binding_cancel(const char *binding_id)
{
    sqlite3_stmt *st = NULL;
    char state[32] = { 0 };
    char token_id[AC_PAIRING_TOKEN_ID_LEN + 1] = { 0 };
    int64_t now = ac_now_s();
    int rc = AC_BINDING_ERR_DB;

    if (!binding_id || ac_exec("BEGIN IMMEDIATE") != 0)
        return AC_BINDING_ERR_DB;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT state,pairing_token_id FROM ac_binding_requests "
            "WHERE binding_id=?1", -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, binding_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) {
        rc = AC_BINDING_ERR_NOT_FOUND;
        goto done;
    }
    snprintf(state, sizeof(state), "%s",
             (const char *)sqlite3_column_text(st, 0));
    snprintf(token_id, sizeof(token_id), "%s",
             (const char *)sqlite3_column_text(st, 1));
    sqlite3_finalize(st);
    st = NULL;
    if (strcmp(state, "identified") &&
        strcmp(state, "awaiting_confirmation") &&
        strcmp(state, "binding_requested") &&
        strcmp(state, "enrollment_pending") &&
        strcmp(state, "certificate_pending") &&
        strcmp(state, "activating")) {
        rc = AC_BINDING_ERR_NOT_CANCELLABLE;
        goto done;
    }

    if (token_id[0]) {
        if (sqlite3_prepare_v2(g_ac_db,
                "UPDATE ac_pairing_tokens SET revoked_at="
                "CASE WHEN revoked_at=0 THEN ?1 ELSE revoked_at END "
                "WHERE token_id=?2", -1, &st, NULL) != SQLITE_OK)
            goto done;
        sqlite3_bind_int64(st, 1, now);
        sqlite3_bind_text(st, 2, token_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE)
            goto done;
        sqlite3_finalize(st);
        st = NULL;
        if (sqlite3_prepare_v2(g_ac_db,
                "UPDATE ac_enrollments SET state='revoked',"
                "failure_code='binding_cancelled',"
                "activation_challenge_hash=NULL,activation_expires_at=0,"
                "updated_at=?1 WHERE token_id=?2 AND state IN "
                "('claimed','mtls_pending')", -1, &st, NULL) != SQLITE_OK)
            goto done;
        sqlite3_bind_int64(st, 1, now);
        sqlite3_bind_text(st, 2, token_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE)
            goto done;
        sqlite3_finalize(st);
        st = NULL;
        if (sqlite3_prepare_v2(g_ac_db,
                "UPDATE ac_device_certificates SET state='revoked',"
                "revoked_at=?1 WHERE certificate_id IN "
                "(SELECT certificate_id FROM ac_enrollments WHERE token_id=?2) "
                "AND state='pending_activation'", -1, &st, NULL) != SQLITE_OK)
            goto done;
        sqlite3_bind_int64(st, 1, now);
        sqlite3_bind_text(st, 2, token_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE)
            goto done;
        sqlite3_finalize(st);
        st = NULL;
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_binding_requests SET state='cancelled',updated_at=?1 "
            "WHERE binding_id=?2 AND state IN ('identified',"
            "'awaiting_confirmation','binding_requested',"
            "'enrollment_pending','certificate_pending','activating')",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, binding_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto done;
    rc = AC_BINDING_OK;
done:
    sqlite3_finalize(st);
    if (rc == AC_BINDING_OK && ac_exec("COMMIT") == 0)
        return AC_BINDING_OK;
    ac_exec("ROLLBACK");
    return rc == AC_BINDING_OK ? AC_BINDING_ERR_DB : rc;
}

int ac_db_binding_check_idempotency(const char *idempotency_key,
                                     const char *bootstrap_id,
                                     const char *controller_id,
                                     const char *site_id,
                                     struct ac_binding_request *out)
{
    sqlite3_stmt *st = NULL;

    if (!idempotency_key || !idempotency_key[0])
        return AC_BINDING_OK; /* no idempotency key, proceed normally */

    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT " AC_BINDING_COLUMNS
            " FROM ac_binding_requests WHERE idempotency_key=?1",
            -1, &st, NULL) != SQLITE_OK)
        return AC_BINDING_ERR_DB;

    sqlite3_bind_text(st, 1, idempotency_key, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        return AC_BINDING_OK; /* not found, proceed */
    }
    ac_binding_row_read(st, out);
    sqlite3_finalize(st);

    /* Same key, same params → idempotent hit. */
    if (!strcmp(out->bootstrap_id, bootstrap_id) &&
        !strcmp(out->controller_id, controller_id) &&
        !strcmp(out->site_id, site_id))
        return AC_BINDING_ERR_IDEMPOTENCY; /* caller returns existing */

    /* Same key, different params → conflict. */
    return AC_BINDING_ERR_IDEMPOTENCY;
}

int ac_db_binding_expire_stale(void)
{
    int64_t now = ac_now_s();
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (ac_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_pairing_tokens SET revoked_at=?1 "
            "WHERE revoked_at=0 AND token_id IN ("
            " SELECT pairing_token_id FROM ac_binding_requests"
            " WHERE state IN ('binding_requested','enrollment_pending',"
            " 'certificate_pending','activating')"
            " AND expires_at<?1 AND expires_at>0)",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_int64(st, 1, now);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_enrollments SET state='expired',"
            "failure_code='binding_expired',activation_challenge_hash=NULL,"
            "activation_expires_at=0,updated_at=?1 WHERE state IN "
            "('claimed','mtls_pending') AND token_id IN ("
            " SELECT pairing_token_id FROM ac_binding_requests"
            " WHERE state IN ('binding_requested','enrollment_pending',"
            " 'certificate_pending','activating')"
            " AND expires_at<?1 AND expires_at>0)",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_int64(st, 1, now);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_device_certificates SET state='revoked',revoked_at=?1 "
            "WHERE certificate_id IN (SELECT e.certificate_id "
            "FROM ac_enrollments e JOIN ac_binding_requests b "
            "ON b.pairing_token_id=e.token_id WHERE b.state IN "
            "('binding_requested','enrollment_pending','certificate_pending',"
            "'activating') "
            "AND b.expires_at<?1 AND b.expires_at>0) "
            "AND state='pending_activation'", -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_int64(st, 1, now);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_binding_requests SET state='expired',updated_at=?1 "
            "WHERE (state IN ('identified','awaiting_confirmation') "
            "AND ticket_expires_at<?1) OR (state IN ('binding_requested',"
            "'enrollment_pending','certificate_pending','activating') "
            "AND expires_at<?1 AND expires_at>0)",
            -1, &st, NULL) != SQLITE_OK)
        goto done;

    sqlite3_bind_int64(st, 1, now);
    if (sqlite3_step(st) == SQLITE_DONE)
        rc = 0;
done:
    sqlite3_finalize(st);
    if (rc == 0 && ac_exec("COMMIT") == 0)
        return 0;
    ac_exec("ROLLBACK");
    return -1;
}

int ac_db_binding_cleanup_nonces(void)
{
    int64_t cutoff = ac_now_s() - AC_BINDING_NONCE_RETAIN;
    sqlite3_stmt *st = NULL;

    if (sqlite3_prepare_v2(g_ac_db,
            "DELETE FROM ac_binding_nonces WHERE first_seen_at<?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;

    sqlite3_bind_int64(st, 1, cutoff);
    sqlite3_step(st);
    sqlite3_finalize(st);
    return 0;
}

// SPDX-License-Identifier: GPL-2.0-or-later
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
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <json-c/json.h>
#include <sqlite3.h>
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
#define AC_SCHEMA_VERSION 12
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
#endif
void ac_db_close(void);
#else
#include "ac_internal.h"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
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
#ifndef AC_DB_TEST_STANDALONE
struct ubus_context *g_ac_ubus;
struct blob_buf g_ac_blob;
#endif
int64_t g_ac_started_at;

static int ac_uuid_valid(const char *value);
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
    size_t i;

    if (!radio_id || strncmp(radio_id, "phy", 3) != 0 || !radio_id[3] ||
        strlen(radio_id) > AC_RADIO_JOB_RADIO_ID_MAX)
        return 0;
    for (i = 3; radio_id[i]; i++)
        if (radio_id[i] < '0' || radio_id[i] > '9')
            return 0;
    return 1;
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
                 sqlite3_column_int(st, 1) == 2 &&
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
        !ac_secure_owner(st.st_uid) || (st.st_mode & 0777) != 0600) {
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
        " session_connected INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS ac_radio_runtime ("
        " radio_id TEXT NOT NULL,ap_id TEXT NOT NULL,observed_at INTEGER NOT NULL DEFAULT 0,"
        " runtime_json TEXT NOT NULL DEFAULT '{}',stale INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(ap_id,radio_id));"
        "CREATE TABLE IF NOT EXISTS ac_radio_survey_cursor ("
        " ap_id TEXT NOT NULL,radio_id TEXT NOT NULL,interface TEXT NOT NULL DEFAULT '',"
        " frequency_mhz INTEGER NOT NULL,observed_at INTEGER NOT NULL,received_at INTEGER NOT NULL,"
        " session_epoch TEXT NOT NULL,active_ms INTEGER NOT NULL,busy_ms INTEGER NOT NULL,"
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
        "CREATE TABLE IF NOT EXISTS ac_transactions ("
        " transaction_id TEXT PRIMARY KEY,actor_id TEXT NOT NULL,idempotency_key TEXT NOT NULL,base_revision INTEGER NOT NULL,"
        " desired_revision INTEGER NOT NULL,state TEXT NOT NULL,consistency TEXT NOT NULL,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);"
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_ac_transactions_idempotency ON ac_transactions(actor_id,idempotency_key);"
        "CREATE TABLE IF NOT EXISTS ac_transaction_targets ("
        " transaction_id TEXT NOT NULL,ap_id TEXT NOT NULL,state TEXT NOT NULL,candidate_digest TEXT NOT NULL DEFAULT '',"
        " previous_digest TEXT NOT NULL DEFAULT '',readback_digest TEXT NOT NULL DEFAULT '',error_code TEXT NOT NULL DEFAULT '',"
        " updated_at INTEGER NOT NULL,PRIMARY KEY(transaction_id,ap_id));"
        "CREATE TABLE IF NOT EXISTS ac_events ("
        " event_id TEXT PRIMARY KEY,ap_id TEXT NOT NULL DEFAULT '',topic TEXT NOT NULL,seq INTEGER NOT NULL,"
        " observed_at INTEGER NOT NULL,received_at INTEGER NOT NULL,severity TEXT NOT NULL,entity_type TEXT NOT NULL,"
        " entity_id TEXT NOT NULL,payload_json TEXT NOT NULL DEFAULT '{}');"
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_ac_events_topic_seq ON ac_events(topic,seq);"
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
        " created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);"
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_ac_config_jobs_idempotency"
        " ON ac_config_jobs(ap_id,idempotency_key);"
        "CREATE INDEX IF NOT EXISTS idx_ac_config_jobs_dispatch"
        " ON ac_config_jobs(ap_id,state,created_at);";
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (ac_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (ac_exec(schema) != 0 ||
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
        ac_add_column("ac_ap_runtime", "session_connected", "INTEGER NOT NULL DEFAULT 0") != 0 ||
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
            "c.state<>'active' OR c.ap_id<>e.ap_id OR a.adoption_state<>'adopted')) OR "
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
        ac_enrollment_state_validate() != 0 ||
        ac_radio_jobs_recover_after_restart() != 0 ||
#if !defined(AC_DB_TEST_STANDALONE) || defined(AC_DB_TELEMETRY_TEST_STANDALONE)
        ac_db_config_jobs_recover(ac_now_s()) != AC_CONFIG_JOB_OK ||
#endif
#ifndef AC_DB_TEST_STANDALONE
        ac_exec("UPDATE ac_ap_runtime SET session_connected=0") != 0 ||
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

int ac_db_ap_session_begin(const char *ap_id, const char *session_epoch,
                           int protocol_version, int64_t received_at)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!g_ac_db || !ac_uuid_valid(ap_id) ||
        !ac_db_session_epoch_valid(session_epoch) ||
        (protocol_version != 1 && protocol_version != 2) || received_at <= 0)
        return -1;
    if (ac_exec("BEGIN IMMEDIATE") != 0)
        return -1;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_aps SET last_seen_at=MAX(last_seen_at,?1) "
            "WHERE ap_id=?2 AND adoption_state='adopted'",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_int64(st, 1, received_at);
    sqlite3_bind_text(st, 2, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_ac_db) != 1)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_ap_runtime(ap_id,boot_id,stale,telemetry_sequence,"
            "control_protocol_version,session_connected) "
            "VALUES(?1,?2,1,-1,?3,1) ON CONFLICT(ap_id) DO UPDATE SET "
            "boot_id=excluded.boot_id,stale=1,telemetry_sequence=-1,"
            "control_protocol_version=excluded.control_protocol_version,"
            "session_connected=1",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, session_epoch, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, protocol_version);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto rollback;
    sqlite3_finalize(st);
    st = NULL;
    if (ac_exec("COMMIT") != 0)
        goto rollback_no_transaction;
    return 0;

rollback:
    sqlite3_finalize(st);
    ac_exec("ROLLBACK");
rollback_no_transaction:
    return rc;
}

int ac_db_ap_session_end(const char *ap_id, const char *session_epoch)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!g_ac_db || !ac_uuid_valid(ap_id) ||
        !ac_db_session_epoch_valid(session_epoch) ||
        sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_ap_runtime SET session_connected=0 "
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
            "AND r.control_protocol_version=2",
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
    size_t i;

    if (!value || strncmp(value, "phy", 3) != 0 || !value[3] ||
        strlen(value) > 31)
        return 0;
    for (i = 3; value[i]; i++)
        if (value[i] < '0' || value[i] > '9')
            return 0;
    return 1;
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

static int64_t ac_db_wifi_desired_revision(void)
{
    static const char sql[] =
        "SELECT MAX(revision) FROM ("
        "SELECT COALESCE(MAX(revision),0) AS revision FROM ac_radio_desired "
        "UNION ALL SELECT COALESCE(MAX(revision),0) FROM ac_ssids)";
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

/* ---- Phase W2b: config job store.  Dispatch side of the write
 * transaction; rows are created by the (future W3) orchestration and by
 * fixtures — no ubus/REST surface reaches these yet, and the write
 * capabilities stay false. ---- */

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
    "dispatch_generation,request_digest,finish_id,outcome,error_code"

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
    const char *attempt_id, int64_t dispatch_generation,
    char out[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1])
{
    char input[512];
    int length;

    length = snprintf(input, sizeof(input),
        "ac-config-job-request-v1\n%s\n%s\n%s\n%s\n%lld\n",
        job_id, ap_id, candidate_digest, attempt_id,
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
    int64_t now = ac_now_s();

    if (!g_ac_db || !ac_uuid_valid(ap_id) || !candidate_json ||
        !candidate_json[0] ||
        strlen(candidate_json) > AC_CONFIG_JOB_CANDIDATE_MAX_BYTES ||
        !ac_radio_job_digest_valid(candidate_digest) ||
        !ac_config_job_idempotency_valid(idempotency_key))
        return AC_CONFIG_JOB_INVALID;
    if (ac_exec("BEGIN IMMEDIATE") != 0)
        return AC_CONFIG_JOB_ERROR;
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
    sqlite3_bind_text(st, 4, candidate_json, -1, SQLITE_TRANSIENT);
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
    return AC_CONFIG_JOB_OK;
fail:
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
    if (!ac_db_ap_session_is_current_locked(ap_id, session_epoch))
        goto fail;
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT q.job_id,q.candidate_digest,q.dispatch_generation,"
            "q.candidate_json FROM ac_config_jobs q "
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
    sqlite3_finalize(st);
    st = NULL;
    if (!candidate || !ac_uuid_valid(job_id) ||
        ac_generate_uuid(attempt_id) != 0 ||
        ac_config_job_request_digest(job_id, ap_id, candidate_digest,
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
    if (!ac_config_job_binding_matches(&job, attempt_id,
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
    const char *terminal;
    int rc;

    if (!g_ac_db || !ac_uuid_valid(job_id) || !ac_uuid_valid(attempt_id) ||
        dispatch_generation <= 0 ||
        !ac_radio_job_digest_valid(request_digest) ||
        !ac_uuid_valid(ap_id) || !ac_uuid_valid(finish_id) || now <= 0)
        return AC_CONFIG_JOB_INVALID;
    if (!outcome)
        return AC_CONFIG_JOB_INVALID;
    if (!strcmp(outcome, "applied"))
        terminal = "applied";
    else if (!strcmp(outcome, "failed"))
        terminal = "failed";
    else if (!strcmp(outcome, "rolled_back"))
        terminal = "rolled_back";
    else
        return AC_CONFIG_JOB_INVALID;
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
    if (!ac_config_job_binding_matches(&job, attempt_id,
                                       dispatch_generation, request_digest,
                                       ap_id, session_epoch)) {
        ac_exec("ROLLBACK");
        return AC_CONFIG_JOB_CONFLICT;
    }
    if (job.finish_id[0]) {
        ac_exec("ROLLBACK");
        if (!strcmp(job.finish_id, finish_id) &&
            !strcmp(job.outcome, outcome)) {
            if (out)
                *out = job;
            return AC_CONFIG_JOB_IDEMPOTENT;
        }
        return AC_CONFIG_JOB_CONFLICT;
    }
    if (strcmp(job.state, "leased") != 0 &&
        strcmp(job.state, "running") != 0) {
        ac_exec("ROLLBACK");
        return AC_CONFIG_JOB_CONFLICT;
    }
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_config_jobs SET state=?2,finish_id=?3,outcome=?4,"
            "error_code=?5,readback_json=?6,updated_at=?7 WHERE job_id=?1",
            -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, job_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, terminal, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, finish_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, outcome, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, error_code ? error_code : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, readback_json ? readback_json : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 7, now);
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

int ac_db_config_jobs_recover(int64_t now)
{
    sqlite3_stmt *st = NULL;

    if (!g_ac_db || now <= 0)
        return AC_CONFIG_JOB_INVALID;
    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_config_jobs SET state='queued',updated_at=?1 "
            "WHERE state='leased' AND lease_expires_at<?1",
            -1, &st, NULL) != SQLITE_OK)
        return AC_CONFIG_JOB_ERROR;
    sqlite3_bind_int64(st, 1, now);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return AC_CONFIG_JOB_ERROR;
    }
    sqlite3_finalize(st);
    return AC_CONFIG_JOB_OK;
}

/* ---- Phase W3: wifi transaction orchestration.  Fans one apply out to a
 * transaction, per-AP targets and per-AP queued config jobs — all in one
 * IMMEDIATE transaction so a partial fan-out never persists.  Dormant:
 * the config jobs stay queued (no APD leases them) and the caller only
 * reaches this after a capability gate that is false until W4. ---- */

static int ac_wifi_tx_consistency_valid(const char *value)
{
    return value && (!strcmp(value, "all_or_nothing") ||
                     !strcmp(value, "per_target"));
}

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
    size_t i;
    int rc = AC_CONFIG_JOB_ERROR;

    if (error_out && error_len)
        error_out[0] = '\0';
    if (!g_ac_db || !ac_uuid_valid(actor_id) ||
        !ac_config_job_idempotency_valid(idempotency_key) ||
        !ac_wifi_tx_consistency_valid(consistency) || base_revision < 0 ||
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
    current_revision = ac_db_wifi_desired_revision();
    if (base_revision != current_revision) {
        ac_exec("ROLLBACK");
        json_object_put(targets);
        if (error_out && error_len)
            snprintf(error_out, error_len, "%s", "revision_conflict");
        return AC_CONFIG_JOB_CONFLICT;
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
    if (ac_generate_uuid(transaction_id) != 0)
        goto fail;
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_transactions(transaction_id,actor_id,"
            "idempotency_key,base_revision,desired_revision,state,"
            "consistency,created_at,updated_at) "
            "VALUES(?1,?2,?3,?4,?4,'pending',?5,?6,?6)",
            -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, transaction_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, actor_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, idempotency_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, base_revision);
    sqlite3_bind_text(st, 5, consistency, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, now);
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

        if (!target || !json_object_is_type(target, json_type_object) ||
            !json_object_object_get_ex(target, "ap_id", &field) ||
            !field || !(ap_id = json_object_get_string(field)) ||
            !ac_uuid_valid(ap_id) ||
            !json_object_object_get_ex(target, "candidate", &field) ||
            !field || !(candidate = json_object_get_string(field)) ||
            !json_object_object_get_ex(target, "candidate_digest",
                                       &field) || !field ||
            !(candidate_digest = json_object_get_string(field)) ||
            !ac_radio_job_digest_valid(candidate_digest) ||
            strlen(candidate) > AC_WIFI_TX_CANDIDATE_MAX_BYTES) {
            if (error_out && error_len)
                snprintf(error_out, error_len, "%s", "target_invalid");
            goto rollback_invalid;
        }
        /* One queued config job per target, keyed to the transaction so a
         * replay of this apply is idempotent at the job layer too. */
        if (ac_generate_uuid(job_id) != 0)
            goto fail;
        snprintf(job_key, sizeof(job_key), "wifitx:%s:%s", transaction_id,
                 ap_id);
        if (sqlite3_prepare_v2(g_ac_db,
                "INSERT INTO ac_config_jobs(job_id,ap_id,state,"
                "idempotency_key,candidate_json,candidate_digest,"
                "transaction_id,created_at,updated_at) "
                "VALUES(?1,?2,'queued',?3,?4,?5,?6,?7,?7)",
                -1, &st, NULL) != SQLITE_OK)
            goto fail;
        sqlite3_bind_text(st, 1, job_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, ap_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, job_key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, candidate, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, candidate_digest, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, transaction_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 7, now);
        if (sqlite3_step(st) != SQLITE_DONE) {
            /* Duplicate AP in one apply collides on the unique
             * (ap_id, idempotency_key); reject the whole fan-out. */
            sqlite3_finalize(st);
            st = NULL;
            if (error_out && error_len)
                snprintf(error_out, error_len, "%s",
                         "target_duplicate_or_busy");
            goto rollback_invalid;
        }
        sqlite3_finalize(st);
        st = NULL;
        if (sqlite3_prepare_v2(g_ac_db,
                "INSERT INTO ac_transaction_targets(transaction_id,ap_id,"
                "state,candidate_digest,updated_at) "
                "VALUES(?1,?2,'queued',?3,?4)",
                -1, &st, NULL) != SQLITE_OK)
            goto fail;
        sqlite3_bind_text(st, 1, transaction_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, ap_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, candidate_digest, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 4, now);
        if (sqlite3_step(st) != SQLITE_DONE)
            goto fail;
        sqlite3_finalize(st);
        st = NULL;
    }
    json_object_put(targets);
    if (ac_exec("COMMIT") != 0)
        return AC_CONFIG_JOB_ERROR;
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
    (void)rc;
    return AC_CONFIG_JOB_ERROR;
}

struct json_object *ac_db_wifi_transaction_status_json(
    const char *transaction_id)
{
    struct json_object *root = json_object_new_object();
    struct json_object *targets_array = json_object_new_array();
    sqlite3_stmt *st = NULL;
    int found = 0;

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
            "WHERE transaction_id=?1", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, transaction_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
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
        }
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
    /* Per-target state joined with the live config job outcome; readback
     * digest surfaces once a job reports one (never today, dormant). */
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT t.ap_id,t.state,t.candidate_digest,t.readback_digest,"
            "t.error_code,j.state,j.outcome,j.error_code "
            "FROM ac_transaction_targets t LEFT JOIN ac_config_jobs j "
            "ON j.transaction_id=t.transaction_id AND j.ap_id=t.ap_id "
            "WHERE t.transaction_id=?1 ORDER BY t.ap_id",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, transaction_id, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *entry = json_object_new_object();
            const unsigned char *job_state = sqlite3_column_text(st, 5);
            const unsigned char *job_outcome = sqlite3_column_text(st, 6);

            json_object_object_add(entry, "ap_id", json_object_new_string(
                (const char *)sqlite3_column_text(st, 0)));
            json_object_object_add(entry, "state", json_object_new_string(
                (const char *)sqlite3_column_text(st, 1)));
            json_object_object_add(entry, "candidate_digest",
                json_object_new_string(
                    (const char *)sqlite3_column_text(st, 2)));
            json_object_object_add(entry, "job_state",
                job_state && job_state[0] ?
                json_object_new_string((const char *)job_state) : NULL);
            json_object_object_add(entry, "job_outcome",
                job_outcome && job_outcome[0] ?
                json_object_new_string((const char *)job_outcome) : NULL);
            json_object_array_add(targets_array, entry);
        }
    }
    sqlite3_finalize(st);
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "transaction_id",
                           json_object_new_string(transaction_id));
    json_object_object_add(root, "targets", targets_array);
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

static int ac_db_survey_bucket_upsert(const char *ap_id, const char *radio_id,
                                      int resolution_seconds,
                                      int64_t received_at,
                                      int64_t active_delta,
                                      int64_t busy_delta,
                                      int receive_present,
                                      int64_t receive_delta,
                                      int transmit_present,
                                      int64_t transmit_delta,
                                      int noise_present, int noise_dbm)
{
    static const char sql[] =
        "INSERT INTO ac_radio_survey_bucket(ap_id,radio_id,resolution_seconds,"
        "bucket_start,first_received_at,last_received_at,sample_count,active_delta_ms,"
        "busy_delta_ms,receive_delta_ms,transmit_delta_ms,utilization_pct,noise_dbm) "
        "VALUES(?1,?2,?3,?4,?5,?5,1,?6,?7,?8,?9,CAST(?7 AS REAL)*100.0/?6,?10) "
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
        "noise_dbm=COALESCE(excluded.noise_dbm,ac_radio_survey_bucket.noise_dbm),complete=1";
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
                                     const struct ac_survey_counter_sample *sample)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_radio_survey_cursor(ap_id,radio_id,interface,frequency_mhz,"
            "observed_at,received_at,session_epoch,active_ms,busy_ms,receive_ms,transmit_ms,noise_dbm) "
            "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12) ON CONFLICT(ap_id,radio_id) "
            "DO UPDATE SET interface=excluded.interface,frequency_mhz=excluded.frequency_mhz,"
            "observed_at=excluded.observed_at,received_at=excluded.received_at,session_epoch=excluded.session_epoch,"
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
    sqlite3_bind_int64(st, 8, sample->active_ms);
    sqlite3_bind_int64(st, 9, sample->busy_ms);
    if (sample->receive_present) sqlite3_bind_int64(st, 10, sample->receive_ms);
    else sqlite3_bind_null(st, 10);
    if (sample->transmit_present) sqlite3_bind_int64(st, 11, sample->transmit_ms);
    else sqlite3_bind_null(st, 11);
    if (sample->noise_present) sqlite3_bind_int(st, 12, sample->noise_dbm);
    else sqlite3_bind_null(st, 12);
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
    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT interface,frequency_mhz,received_at,session_epoch,active_ms,busy_ms,"
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
        previous_active = sqlite3_column_int64(st, 4);
        previous_busy = sqlite3_column_int64(st, 5);
        previous_receive_present = sqlite3_column_type(st, 6) != SQLITE_NULL;
        previous_receive = sqlite3_column_int64(st, 6);
        previous_transmit_present = sqlite3_column_type(st, 7) != SQLITE_NULL;
        previous_transmit = sqlite3_column_int64(st, 7);
        previous_interface = previous_interface ? strdup(previous_interface) : strdup("");
        previous_epoch = previous_epoch ? strdup(previous_epoch) : strdup("");
        if (!previous_interface || !previous_epoch) {
            free((void *)previous_interface);
            free((void *)previous_epoch);
            sqlite3_finalize(st);
            return -1;
        }
    }
    sqlite3_finalize(st);
    st = NULL;
    if (!have_previous)
        return ac_db_survey_cursor_write(ap_id, radio_id, session_epoch,
                                         observed_at, received_at, &current);
    interval = received_at - previous_received;
    reset = interval <= 0 || interval > AC_SURVEY_SAMPLE_GAP_SECONDS ||
            strcmp(previous_epoch, session_epoch) ||
            strcmp(previous_interface, current.interface) ||
            previous_frequency != current.frequency_mhz ||
            current.active_ms < previous_active || current.busy_ms < previous_busy;
    free((void *)previous_interface);
    free((void *)previous_epoch);
    if (!reset && interval < AC_SURVEY_SAMPLE_MIN_SECONDS)
        return 0;
    if (reset)
        return ac_db_survey_cursor_write(ap_id, radio_id, session_epoch,
                                         observed_at, received_at, &current);
    active_delta = current.active_ms - previous_active;
    busy_delta = current.busy_ms - previous_busy;
    if (active_delta <= 0 || busy_delta < 0 || busy_delta > active_delta)
        return ac_db_survey_cursor_write(ap_id, radio_id, session_epoch,
                                         observed_at, received_at, &current);
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
            current.noise_dbm) != 0 ||
        ac_db_survey_bucket_upsert(ap_id, radio_id,
            AC_SURVEY_HOUR_RESOLUTION_SECONDS, received_at, active_delta,
            busy_delta, receive_delta_present, receive_delta,
            transmit_delta_present, transmit_delta, current.noise_present,
            current.noise_dbm) != 0 ||
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
                                     observed_at, received_at, &current);
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
    if (previous_sequence >= 0 &&
        ac_db_station_events_ingest(ap_id, previous_snapshot, snapshot,
                                    previous_observed_at, observed_at,
                                    received_at) != 0) {
        ac_db_telemetry_error("station_events");
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
static struct json_object *ac_db_ap_capabilities(int scan_execution)
{
    struct json_object *value = json_object_new_object();

    json_object_object_add(value, "remote_telemetry", json_object_new_boolean(1));
    json_object_object_add(value, "scan_dispatch",
                           json_object_new_boolean(scan_execution));
    json_object_object_add(value, "scan_execution",
                           json_object_new_boolean(scan_execution));
    json_object_object_add(value, "ssid_create", json_object_new_boolean(0));
    json_object_object_add(value, "ssid_update", json_object_new_boolean(0));
    json_object_object_add(value, "ssid_delete", json_object_new_boolean(0));
    json_object_object_add(value, "password_rotation", json_object_new_boolean(0));
    json_object_object_add(value, "radio_update", json_object_new_boolean(0));
    json_object_object_add(value, "ap_actions", json_object_new_boolean(0));
    return value;
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
            "COALESCE(r.control_protocol_version,0),COALESCE(r.session_connected,0) "
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
        int scan_execution = online && session_connected && protocol_version == 2;
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
                               ac_db_ap_capabilities(scan_execution));
        json_object_object_add(item, "control_protocol_version",
                               json_object_new_int(protocol_version));
        json_object_object_add(item, "control_protocol", json_object_new_string(
            protocol_version == 2 ? "ap-control.v2" :
            protocol_version == 1 ? "ap-control.v1" : ""));
        json_object_object_add(item, "session_connected",
                               json_object_new_boolean(session_connected));
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
            "SELECT 1 FROM ac_device_certificates WHERE certificate_id=?1 "
            "AND ap_id=?2 AND fingerprint_sha256=?3 AND revoked_at=0 "
            "AND not_before<=?4 AND not_after>?4 AND state=?5",
            -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, certificate_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 3, fingerprint_sha256, SHA256_DIGEST_LENGTH,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, now);
    sqlite3_bind_text(st, 5, require_active ? "active" : "pending_activation",
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

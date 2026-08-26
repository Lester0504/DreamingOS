// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* The W2c config job executor and journal contracts are self-contained
 * (json-c/stdint only); include them for both the production and the
 * standalone-test builds so the config wire step compiles either way. */
#include "apd_config_executor.h"
#include "apd_config_job_journal.h"
#include "apd_config_recovery.h"

#ifndef APD_CONFIG_UCI_PATH
#define APD_CONFIG_UCI_PATH "/sbin/uci"
#endif
#ifndef APD_CONFIG_WIFI_PATH
#define APD_CONFIG_WIFI_PATH "/sbin/wifi"
#endif
#ifndef APD_CONFIG_CONFIG_DIR
#define APD_CONFIG_CONFIG_DIR "/etc/config"
#endif
#ifndef APD_CONFIG_STAGING_DIR
#define APD_CONFIG_STAGING_DIR "/tmp/dreamingwrt-apd-config-candidate"
#endif

#ifdef APD_TRANSPORT_TEST_STANDALONE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <json-c/json.h>
#define APD_AP_ID_LEN 36
#define APD_ED25519_KEY_LEN 32
#define APD_ED25519_SIGNATURE_LEN 64
#define APD_KEY_ID_LEN 71
#define APD_ENROLLMENT_CHALLENGE_ID_MAX 36
#define APD_ENROLLMENT_ID_MAX 36
#define APD_ENROLLMENT_TOKEN_ID_MAX 36
#define APD_ENROLLMENT_TOKEN_LEN 43
#define APD_ENROLLMENT_SITE_ID_MAX 64
#define APD_ENROLLMENT_HARDWARE_DIGEST_MAX 71
#define APD_ENROLLMENT_CSR_DER_MAX 2048
#define APD_DEVICE_MODEL_MAX 255
#define APD_DEVICE_BOARD_NAME_MAX 127
#define APD_DEVICE_MODEL_SOURCE_MAX 63
#define APD_DEVICE_MODEL_REASON_MAX 127
struct apd_node_identity {
    char ap_id[APD_AP_ID_LEN + 1];
    char key_id[APD_KEY_ID_LEN + 1];
    unsigned char public_key[APD_ED25519_KEY_LEN];
    int64_t created_at;
};
struct apd_device_model {
    char model[APD_DEVICE_MODEL_MAX + 1];
    char board_name[APD_DEVICE_BOARD_NAME_MAX + 1];
    char model_source[APD_DEVICE_MODEL_SOURCE_MAX + 1];
    char reason[APD_DEVICE_MODEL_REASON_MAX + 1];
    int model_available;
};
struct apd_backend_ops {
    const char *name;
    int snapshot_supported;
    int (*probe)(struct json_object **out);
    int (*snapshot)(struct json_object **out);
    int (*validate)(struct json_object *candidate, struct json_object **out);
    int (*stage)(struct json_object *candidate, struct json_object **out);
    int (*apply)(struct json_object *candidate, struct json_object **out);
    int (*readback)(struct json_object **out);
    int (*rollback)(struct json_object *rollback_ref, struct json_object **out);
};
#define APD_RADIO_JOB_UUID_LEN 36
#define APD_RADIO_JOB_AP_ID_LEN 36
#define APD_RADIO_JOB_SESSION_EPOCH_LEN 64
#define APD_RADIO_JOB_DIGEST_LEN 71
#define APD_RADIO_JOB_RADIO_ID_MAX 63
#define APD_RADIO_JOB_MODE_MAX 31
#define APD_RADIO_JOB_ERROR_MAX 127
#define APD_RADIO_JOB_STATE_MAX 31
#define APD_RADIO_JOB_OUTCOME_MAX 15
enum apd_radio_job_journal_result {
    APD_RADIO_JOB_JOURNAL_ERROR = -1,
    APD_RADIO_JOB_JOURNAL_OK = 0,
    APD_RADIO_JOB_JOURNAL_IDEMPOTENT = 1,
    APD_RADIO_JOB_JOURNAL_NOT_FOUND = 2,
    APD_RADIO_JOB_JOURNAL_CONFLICT = 3,
    APD_RADIO_JOB_JOURNAL_INVALID = 4,
    APD_RADIO_JOB_JOURNAL_LIMIT = 5,
};
struct apd_radio_job_assignment {
    char job_id[APD_RADIO_JOB_UUID_LEN + 1];
    char attempt_id[APD_RADIO_JOB_UUID_LEN + 1];
    int64_t dispatch_generation;
    char request_digest[APD_RADIO_JOB_DIGEST_LEN + 1];
    char ap_id[APD_RADIO_JOB_AP_ID_LEN + 1];
    char session_epoch[APD_RADIO_JOB_SESSION_EPOCH_LEN + 1];
    char radio_id[APD_RADIO_JOB_RADIO_ID_MAX + 1];
    char mode[APD_RADIO_JOB_MODE_MAX + 1];
};
struct apd_radio_job_finish {
    struct apd_radio_job_assignment assignment;
    char finish_id[APD_RADIO_JOB_UUID_LEN + 1];
    char outcome[APD_RADIO_JOB_OUTCOME_MAX + 1];
    char error_code[APD_RADIO_JOB_ERROR_MAX + 1];
    int64_t observed_at;
    const char *result_json;
    int result_complete;
};
struct apd_radio_job_journal_entry {
    struct apd_radio_job_assignment assignment;
    char state[APD_RADIO_JOB_STATE_MAX + 1];
    char finish_id[APD_RADIO_JOB_UUID_LEN + 1];
    char outcome[APD_RADIO_JOB_OUTCOME_MAX + 1];
    char error_code[APD_RADIO_JOB_ERROR_MAX + 1];
    int64_t observed_at;
    int result_count;
    int64_t result_bytes;
    int result_complete;
    int finish_acked;
    int64_t created_at;
    int64_t updated_at;
};
struct apd_radio_job_pending_reconcile {
    struct apd_radio_job_journal_entry entry;
    char *result_json;
};
struct apd_radio_job_pending_finish {
    struct apd_radio_job_journal_entry entry;
    char *result_json;
};
int apd_radio_job_offer_store(const struct apd_radio_job_assignment *, int64_t,
                              struct apd_radio_job_journal_entry *);
int apd_radio_job_mark_running(const struct apd_radio_job_assignment *, int64_t,
                               struct apd_radio_job_journal_entry *);
int apd_radio_job_finish_store(const struct apd_radio_job_finish *, int64_t,
                               struct apd_radio_job_journal_entry *);
int apd_radio_job_pending_reconcile_get(
    const char *, struct apd_radio_job_pending_reconcile *);
void apd_radio_job_pending_reconcile_free(
    struct apd_radio_job_pending_reconcile *);
int apd_radio_job_pending_finish_get(const char *,
                                     struct apd_radio_job_pending_finish *);
void apd_radio_job_pending_finish_free(struct apd_radio_job_pending_finish *);
int apd_radio_job_session_rebind(
    const struct apd_radio_job_assignment *, const char *, int64_t,
    struct apd_radio_job_journal_entry *);
int apd_radio_job_finish_ack(const struct apd_radio_job_assignment *,
                             const char *, int64_t,
                             struct apd_radio_job_journal_entry *);
int apd_radio_job_cancel_requested(const struct apd_radio_job_assignment *,
                                   int64_t,
                                   struct apd_radio_job_journal_entry *);
int apd_backend_neighbor_scan(const char *, struct json_object **);
int apd_backend_survey_scan(const char *, struct json_object **);
struct apd_pairing_status {
    char state[32];
    char controller_id[129];
    char request_id[129];
    int challenge_present;
    int attempts;
    int64_t expires_at;
    int64_t updated_at;
};
struct apd_enrollment_field {
    const unsigned char *data;
    size_t len;
};
struct apd_enrollment_transcript_v1 {
    struct apd_enrollment_field challenge_id;
    unsigned char server_nonce[32];
    unsigned char client_nonce[32];
    struct apd_enrollment_field enrollment_id;
    struct apd_enrollment_field token_id;
    struct apd_enrollment_field token;
    struct apd_enrollment_field ap_id;
    struct apd_enrollment_field key_id;
    unsigned char public_key[APD_ED25519_KEY_LEN];
    struct apd_enrollment_field site_id;
    struct apd_enrollment_field hardware_digest;
    unsigned char csr_sha256[SHA256_DIGEST_LENGTH];
    uint64_t challenge_expires_at;
};
int64_t apd_now_s(void);
int apd_db_identity_get(struct apd_node_identity *out);
EVP_PKEY *apd_identity_key_open(void);
int apd_db_pairing_status_get(struct apd_pairing_status *out);
int apd_db_pairing_begin(const char *controller_id, const char *request_id,
                         int64_t expires_at);
int apd_db_pairing_set_challenge(const char *request_id,
                                 const unsigned char *challenge,
                                 size_t challenge_len);
int apd_db_pairing_verify_challenge(const char *request_id,
                                    const unsigned char *challenge,
                                    size_t challenge_len);
int apd_db_pairing_reset(const char *request_id);
int apd_enrollment_csr_create(unsigned char *csr_der, size_t csr_der_size,
                              size_t *csr_der_len,
                              unsigned char csr_sha256[SHA256_DIGEST_LENGTH]);
int apd_enrollment_transcript_sign_v1(
    const struct apd_enrollment_transcript_v1 *input,
    unsigned char signature[APD_ED25519_SIGNATURE_LEN]);
const struct apd_backend_ops *apd_backend(void);
int apd_backend_device_model_collect(struct apd_device_model *out);
#else
#include "apd_internal.h"
#include <arpa/inet.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/socket.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#endif

#include "../ap_control_wire.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define APD_TRANSPORT_PROTOCOL_V1 "ap-control.v1"
#define APD_TRANSPORT_PROTOCOL_V2 "ap-control.v2"
#define APD_TRANSPORT_CERT_FILE "client-cert.der"
#define APD_TRANSPORT_CERT_DER_MAX 16384U
#define APD_TRANSPORT_CA_PEM_MAX 65536U
#ifndef APD_TRANSPORT_HEARTBEAT_SECONDS
#define APD_TRANSPORT_HEARTBEAT_SECONDS 30
#endif
#ifndef APD_TRANSPORT_BACKOFF_MIN_SECONDS
#define APD_TRANSPORT_BACKOFF_MIN_SECONDS 1
#endif
#ifndef APD_TRANSPORT_BACKOFF_MAX_SECONDS
#define APD_TRANSPORT_BACKOFF_MAX_SECONDS 60
#endif
#ifndef APD_TELEMETRY_REFRESH_SECONDS
#define APD_TELEMETRY_REFRESH_SECONDS 300
#endif
#if APD_TELEMETRY_REFRESH_SECONDS < 300
#error "APD full telemetry refresh must be at least 300 seconds"
#endif
#define APD_TRANSPORT_REASON_MAX 128U
#define APD_TELEMETRY_SCHEMA "apd-backend.snapshot"
#define APD_TELEMETRY_VERSION 1

#ifdef APD_TRANSPORT_TEST_STANDALONE
#define APD_CREDENTIALS_UUID_LEN 36
#define APD_CREDENTIALS_TOKEN_LEN 43
#define APD_CREDENTIALS_SITE_MAX 64
#define APD_CREDENTIALS_HOST_MAX 253
#define APD_CREDENTIALS_DIGEST_LEN 71
#define APD_CREDENTIALS_SERIAL_MAX 256

struct apd_bootstrap_config {
    int version;
    char controller_host[APD_CREDENTIALS_HOST_MAX + 1];
    uint16_t controller_port;
    int controller_id_present;
    char controller_id[APD_CREDENTIALS_UUID_LEN + 1];
    char token_id[APD_CREDENTIALS_UUID_LEN + 1];
    char token[APD_CREDENTIALS_TOKEN_LEN + 1];
    char site_id[APD_CREDENTIALS_SITE_MAX + 1];
    char hardware_digest[APD_CREDENTIALS_DIGEST_LEN + 1];
    char ca_cert_pem_path[PATH_MAX];
};

struct apd_credentials_certificate_input {
    const unsigned char *certificate_der;
    size_t certificate_der_len;
    char controller_id[APD_CREDENTIALS_UUID_LEN + 1];
    char enrollment_id[APD_CREDENTIALS_UUID_LEN + 1];
    char certificate_id[APD_CREDENTIALS_UUID_LEN + 1];
};

struct apd_enrollment_metadata {
    int version;
    char controller_id[APD_CREDENTIALS_UUID_LEN + 1];
    char controller_host[APD_CREDENTIALS_HOST_MAX + 1];
    uint16_t controller_port;
    char enrollment_id[APD_CREDENTIALS_UUID_LEN + 1];
    char certificate_id[APD_CREDENTIALS_UUID_LEN + 1];
    char ap_id[APD_AP_ID_LEN + 1];
    char serial[APD_CREDENTIALS_SERIAL_MAX + 1];
    int64_t not_before;
    int64_t not_after;
    char certificate_fingerprint[APD_CREDENTIALS_DIGEST_LEN + 1];
    char ca_fingerprint[APD_CREDENTIALS_DIGEST_LEN + 1];
    char ca_cert_pem_path[PATH_MAX];
    char state[16];
};

enum apd_credentials_activate_result {
    APD_CREDENTIALS_ACTIVATE_OK = 0,
    APD_CREDENTIALS_ACTIVATE_CONTROLLER_INVALID = -1,
    APD_CREDENTIALS_ACTIVATE_ENROLLMENT_INVALID = -2,
    APD_CREDENTIALS_ACTIVATE_CERTIFICATE_INVALID = -3,
    APD_CREDENTIALS_ACTIVATE_FINGERPRINT_MISSING = -4,
    APD_CREDENTIALS_ACTIVATE_LOCK_FAILED = -5,
    APD_CREDENTIALS_ACTIVATE_VALIDATE_FAILED = -6,
    APD_CREDENTIALS_ACTIVATE_BINDING_MISMATCH = -7,
    APD_CREDENTIALS_ACTIVATE_BOOTSTRAP_REMOVE_FAILED = -8,
    APD_CREDENTIALS_ACTIVATE_METADATA_COMMIT_FAILED = -9,
};

const char *apd_credentials_pki_dir(void);
int apd_credentials_bootstrap_load(struct apd_bootstrap_config *out);
int apd_credentials_certificate_store(
    const struct apd_credentials_certificate_input *input,
    struct apd_enrollment_metadata *out);
int apd_credentials_validate_startup(struct apd_enrollment_metadata *out);
int apd_credentials_activate(
    const char *controller_id, const char *enrollment_id,
    const char *certificate_id,
    const unsigned char fingerprint[SHA256_DIGEST_LENGTH],
    struct apd_enrollment_metadata *out);
void apd_credentials_bootstrap_cleanse(struct apd_bootstrap_config *config);
void apd_credentials_metadata_cleanse(struct apd_enrollment_metadata *metadata);
#endif

static const char *const apd_fields_enrollment_hello[] = {
    "protocol", "kind", "ap_id", "key_id", "public_key", "model",
    "board_name", "model_source", "model_available", "model_reason"
};
static const char *const apd_fields_enrollment_challenge[] = {
    "protocol", "kind", "controller_id", "challenge_id", "server_nonce",
    "expires_at"
};
static const char *const apd_fields_enrollment_claim[] = {
    "protocol", "kind", "challenge_id", "server_nonce", "client_nonce",
    "enrollment_id", "token_id", "token", "ap_id", "key_id",
    "public_key", "site_id", "hardware_digest", "csr_der", "csr_sha256",
    "challenge_expires_at", "signature"
};
static const char *const apd_fields_enrollment_certificate[] = {
    "protocol", "kind", "controller_id", "enrollment_id", "certificate_id",
    "certificate_der", "certificate_fingerprint", "ca_fingerprint"
};
static const char *const apd_fields_activation_hello[] = {
    "protocol", "kind", "controller_id", "enrollment_id", "certificate_id",
    "ap_id"
};
static const char *const apd_fields_activation_challenge[] = {
    "protocol", "kind", "enrollment_id", "certificate_id", "challenge"
};
static const char *const apd_fields_activation_response[] = {
    "protocol", "kind", "enrollment_id", "certificate_id", "challenge"
};
static const char *const apd_fields_activation_complete[] = {
    "protocol", "kind", "controller_id", "enrollment_id", "certificate_id",
    "certificate_fingerprint", "adopted"
};
static const char *const apd_fields_session_hello[] = {
    "protocol", "kind", "controller_id", "certificate_id", "ap_id"
};
static const char *const apd_fields_session_hello_v3[] = {
    "protocol", "kind", "controller_id", "certificate_id", "ap_id", "capabilities"
};
static const char *const apd_fields_session_ready[] = {
    "protocol", "kind", "controller_id", "certificate_id", "ap_id",
    "session_epoch"
};
static const char *const apd_fields_session_ready_v3[] = {
    "protocol", "kind", "controller_id", "certificate_id", "ap_id", "session_epoch", "capabilities"
};
static const char *const apd_fields_heartbeat[] = {
    "protocol", "kind", "ap_id", "session_epoch", "sequence", "timestamp"
};
static const char *const apd_fields_heartbeat_ack[] = {
    "protocol", "kind", "ap_id", "session_epoch", "sequence"
};
static const char *const apd_fields_telemetry_snapshot[] = {
    "protocol", "kind", "schema", "version", "ap_id", "session_epoch",
    "sequence", "observed_at", "snapshot"
};
static const char *const apd_fields_telemetry_ack[] = {
    "protocol", "kind", "ap_id", "session_epoch", "sequence", "accepted"
};
static const char *const apd_fields_radio_job_reconcile[] = {
    "protocol", "kind", "ap_id", "session_epoch", "sequence", "job_id",
    "attempt_id", "dispatch_generation", "request_digest", "radio_id",
    "mode", "state", "finish_id", "outcome", "error_code", "observed_at",
    "result_complete", "result"
};
static const char *const apd_fields_radio_job_reconcile_ack[] = {
    "protocol", "kind", "ap_id", "session_epoch", "reply_to",
    "job_id", "attempt_id", "dispatch_generation", "request_digest",
    "controller_state", "cancel_requested", "result_complete", "error_code"
};
static const char *const apd_fields_radio_job_poll[] = {
    "protocol", "kind", "ap_id", "session_epoch", "sequence"
};
static const char *const apd_fields_radio_job_idle[] = {
    "protocol", "kind", "ap_id", "session_epoch", "reply_to"
};
static const char *const apd_fields_radio_job_offer[] = {
    "protocol", "kind", "ap_id", "session_epoch", "reply_to",
    "job_id", "attempt_id", "dispatch_generation", "request_digest",
    "radio_id", "mode", "expected_impact", "controller_state",
    "cancel_requested"
};
static const char *const apd_fields_radio_job_accept[] = {
    "protocol", "kind", "ap_id", "session_epoch", "sequence", "job_id",
    "attempt_id", "dispatch_generation", "request_digest"
};
static const char *const apd_fields_radio_job_accept_ack[] = {
    "protocol", "kind", "ap_id", "session_epoch", "reply_to",
    "job_id", "attempt_id", "dispatch_generation", "request_digest",
    "controller_state", "cancel_requested"
};
static const char *const apd_fields_radio_job_start[] = {
    "protocol", "kind", "ap_id", "session_epoch", "sequence", "job_id",
    "attempt_id", "dispatch_generation", "request_digest"
};
static const char *const apd_fields_radio_job_start_ack[] = {
    "protocol", "kind", "ap_id", "session_epoch", "reply_to",
    "job_id", "attempt_id", "dispatch_generation", "request_digest",
    "controller_state", "cancel_requested"
};
static const char *const apd_fields_radio_job_finish[] = {
    "protocol", "kind", "ap_id", "session_epoch", "sequence", "job_id",
    "attempt_id", "dispatch_generation", "request_digest", "finish_id",
    "outcome", "error_code", "result_complete", "result"
};
static const char *const apd_fields_radio_job_finish_ack[] = {
    "protocol", "kind", "ap_id", "session_epoch", "reply_to",
    "job_id", "attempt_id", "dispatch_generation", "request_digest",
    "finish_id", "controller_state", "cancel_requested", "result_complete",
    "error_code"
};
static const char *const apd_fields_error[] = {
    "protocol", "kind", "error", "reason"
};

#define APD_ARRAY_SIZE(value) (sizeof(value) / sizeof((value)[0]))

struct apd_transport_endpoint {
    int present;
    char host[APD_CREDENTIALS_HOST_MAX + 1];
    uint16_t port;
    char ca_path[PATH_MAX];
};

struct apd_tls_connection {
    int fd;
    int protocol_version;
    SSL_CTX *context;
    SSL *ssl;
};

struct apd_telemetry_gate {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    int digest_present;
    int64_t sent_at;
};

struct apd_transport_state {
    pthread_mutex_t lock;
    pthread_cond_t condition;
    pthread_t thread;
    int running;
    int stop;
    int connected;
    int write_capable;
    int active_fd;
    uint64_t sequence;
    char reason[64];
    struct apd_transport_endpoint endpoint;
};

static struct apd_transport_state g_apd_transport = {
    PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, (pthread_t)0,
    0, 0, 0, 0, -1, 0, "not_started", {0, {0}, 0, {0}}
};
static _Thread_local const char *g_apd_wire_protocol = APD_TRANSPORT_PROTOCOL_V1;

static _Thread_local char g_apd_transport_reason_copy[64];

static void apd_transport_log(const char *event)
{
    if (event)
        fprintf(stderr, "[dreamingwrt-apd] transport event=%s\n", event);
}

static void apd_transport_log_stage(const char *event, const char *stage)
{
    if (event && stage)
        fprintf(stderr, "[dreamingwrt-apd] transport event=%s stage=%s\n",
                event, stage);
}

static int64_t apd_transport_monotonic_ms(void)
{
    struct timespec value;

    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
        return -1;
    return (int64_t)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}

static int64_t apd_transport_monotonic_s(void)
{
    int64_t milliseconds = apd_transport_monotonic_ms();

    return milliseconds < 0 ? -1 : milliseconds / 1000;
}

static int apd_telemetry_should_send(
    const struct apd_telemetry_gate *gate,
    const unsigned char digest[SHA256_DIGEST_LENGTH], int force,
    int64_t now)
{
    if (!gate || !digest || now < 0)
        return 0;
    if (force || !gate->digest_present ||
        CRYPTO_memcmp(gate->digest, digest, SHA256_DIGEST_LENGTH) != 0)
        return 1;
    return gate->sent_at <= now &&
           now - gate->sent_at >= APD_TELEMETRY_REFRESH_SECONDS;
}

static int apd_telemetry_volatile_key(const char *name)
{
    static const char *const volatile_keys[] = {
        "observed_at", "rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
        "inactive_time_ms", "connected_time_seconds", "signal_dbm", NULL
    };
    size_t i;

    for (i = 0; volatile_keys[i]; i++)
        if (!strcmp(name, volatile_keys[i]))
            return 1;
    return 0;
}

static int apd_telemetry_json_compare(const void *left, const void *right)
{
    struct json_object *const *left_object = left;
    struct json_object *const *right_object = right;
    const char *left_text = json_object_to_json_string_ext(
        *left_object, JSON_C_TO_STRING_PLAIN);
    const char *right_text = json_object_to_json_string_ext(
        *right_object, JSON_C_TO_STRING_PLAIN);

    if (!left_text || !right_text)
        return left_text ? 1 : right_text ? -1 : 0;
    return strcmp(left_text, right_text);
}

static struct json_object *apd_telemetry_stable_copy(struct json_object *value)
{
    struct json_object *copy;
    size_t i;

    if (!value)
        return NULL;
    if (json_object_is_type(value, json_type_object)) {
        copy = json_object_new_object();
        if (!copy)
            return NULL;
        json_object_object_foreach(value, name, child) {
            struct json_object *child_copy;

            if (!strcmp(name, "sources") || !strcmp(name, "survey") ||
                apd_telemetry_volatile_key(name))
                continue;
            if (!child) {
                json_object_object_add(copy, name, NULL);
                continue;
            }
            child_copy = apd_telemetry_stable_copy(child);
            if (!child_copy) {
                json_object_put(copy);
                return NULL;
            }
            json_object_object_add(copy, name, child_copy);
        }
        return copy;
    }
    if (json_object_is_type(value, json_type_array)) {
        copy = json_object_new_array();
        if (!copy)
            return NULL;
        for (i = 0; i < json_object_array_length(value); i++) {
            struct json_object *child = json_object_array_get_idx(value, i);
            struct json_object *child_copy;

            if (!child) {
                json_object_array_add(copy, NULL);
                continue;
            }
            child_copy = apd_telemetry_stable_copy(child);
            if (!child_copy) {
                json_object_put(copy);
                return NULL;
            }
            json_object_array_add(copy, child_copy);
        }
        json_object_array_sort(copy, apd_telemetry_json_compare);
        return copy;
    }
    return json_object_get(value);
}

static int apd_telemetry_digest(
    struct json_object *snapshot,
    unsigned char digest[SHA256_DIGEST_LENGTH])
{
    struct json_object *stable = apd_telemetry_stable_copy(snapshot);
    const char *encoded;
    int rc = -1;

    if (stable && (encoded = json_object_to_json_string_ext(
            stable, JSON_C_TO_STRING_PLAIN)) &&
        SHA256((const unsigned char *)encoded, strlen(encoded), digest))
        rc = 0;
    json_object_put(stable);
    return rc;
}

static int apd_transport_stopping(void)
{
    int stopping;

    pthread_mutex_lock(&g_apd_transport.lock);
    stopping = g_apd_transport.stop;
    pthread_mutex_unlock(&g_apd_transport.lock);
    return stopping;
}

static void apd_transport_set_connected(int connected)
{
    pthread_mutex_lock(&g_apd_transport.lock);
    g_apd_transport.connected = connected ? 1 : 0;
    if (!connected)
        g_apd_transport.write_capable = 0;
    pthread_mutex_unlock(&g_apd_transport.lock);
}

static void apd_transport_set_reason(const char *reason)
{
    pthread_mutex_lock(&g_apd_transport.lock);
    snprintf(g_apd_transport.reason, sizeof(g_apd_transport.reason), "%s",
             reason && reason[0] ? reason : "unknown");
    pthread_mutex_unlock(&g_apd_transport.lock);
}

static int apd_transport_active_fd_set(int fd)
{
    int rc = 0;

    pthread_mutex_lock(&g_apd_transport.lock);
    if (g_apd_transport.stop)
        rc = -1;
    else
        g_apd_transport.active_fd = fd;
    pthread_mutex_unlock(&g_apd_transport.lock);
    return rc;
}

static void apd_transport_active_fd_clear(int fd)
{
    pthread_mutex_lock(&g_apd_transport.lock);
    if (g_apd_transport.active_fd == fd)
        g_apd_transport.active_fd = -1;
    pthread_mutex_unlock(&g_apd_transport.lock);
}

static int apd_transport_wait_seconds(unsigned int seconds)
{
    int64_t start = apd_transport_monotonic_ms();
    int64_t duration;
    int64_t deadline;

    if (start < 0 || seconds > (unsigned int)(INT64_MAX / 1000))
        return -1;
    duration = (int64_t)seconds * 1000;
    if (start > INT64_MAX - duration)
        return -1;
    deadline = start + duration;
    for (;;) {
        struct timespec pause;
        int64_t now;
        int64_t remaining;

        if (apd_transport_stopping())
            return -1;
        now = apd_transport_monotonic_ms();
        if (now < 0)
            return -1;
        if (now >= deadline)
            return 0;
        remaining = deadline - now;
        if (remaining > 100)
            remaining = 100;
        pause.tv_sec = 0;
        pause.tv_nsec = remaining * 1000000;
        while (nanosleep(&pause, &pause) != 0 && errno == EINTR) {
            if (apd_transport_stopping())
                return -1;
        }
    }
}

static int apd_transport_endpoint_values_set(const char *host, uint16_t port,
                                             const char *ca_path)
{
    if (!host || !host[0] || !port || !ca_path || !ca_path[0])
        return -1;
    pthread_mutex_lock(&g_apd_transport.lock);
    snprintf(g_apd_transport.endpoint.host,
             sizeof(g_apd_transport.endpoint.host), "%s", host);
    snprintf(g_apd_transport.endpoint.ca_path,
             sizeof(g_apd_transport.endpoint.ca_path), "%s", ca_path);
    g_apd_transport.endpoint.port = port;
    g_apd_transport.endpoint.present = 1;
    pthread_mutex_unlock(&g_apd_transport.lock);
    return 0;
}

static int apd_transport_endpoint_set_bootstrap(
    const struct apd_bootstrap_config *config)
{
    return config ? apd_transport_endpoint_values_set(
        config->controller_host, config->controller_port,
        config->ca_cert_pem_path) : -1;
}

static int apd_transport_endpoint_set_metadata(
    const struct apd_enrollment_metadata *metadata)
{
    return metadata ? apd_transport_endpoint_values_set(
        metadata->controller_host, metadata->controller_port,
        metadata->ca_cert_pem_path) : -1;
}

static int apd_transport_endpoint_consistent(
    const struct apd_bootstrap_config *bootstrap,
    const struct apd_enrollment_metadata *metadata)
{
    return bootstrap && metadata &&
        strcmp(bootstrap->controller_host, metadata->controller_host) == 0 &&
        bootstrap->controller_port == metadata->controller_port &&
        strcmp(bootstrap->ca_cert_pem_path, metadata->ca_cert_pem_path) == 0;
}

static int apd_transport_endpoint_get(struct apd_transport_endpoint *out)
{
    int present;

    if (!out)
        return -1;
    pthread_mutex_lock(&g_apd_transport.lock);
    *out = g_apd_transport.endpoint;
    present = out->present;
    pthread_mutex_unlock(&g_apd_transport.lock);
    return present ? 0 : -1;
}

static int apd_json_add_string(struct json_object *object, const char *name,
                               const char *value)
{
    struct json_object *member;

    if (!object || !name || !value || !(member = json_object_new_string(value)))
        return -1;
    json_object_object_add(object, name, member);
    return 0;
}

static int apd_json_add_int64(struct json_object *object, const char *name,
                              int64_t value)
{
    struct json_object *member;

    if (!object || !name || !(member = json_object_new_int64(value)))
        return -1;
    json_object_object_add(object, name, member);
    return 0;
}

static int apd_json_add_hex(struct json_object *object, const char *name,
                            const unsigned char *data, size_t length)
{
    char *encoded;
    int rc = -1;

    if ((!data && length) || length > AP_CONTROL_FRAME_MAX / 2 ||
        !(encoded = malloc(length * 2 + 1)))
        return -1;
    if (ap_control_hex_encode(data, length, encoded, length * 2 + 1) ==
            AP_CONTROL_WIRE_OK)
        rc = apd_json_add_string(object, name, encoded);
    OPENSSL_cleanse(encoded, length * 2 + 1);
    free(encoded);
    return rc;
}

static struct json_object *apd_message_new(const char *kind)
{
    struct json_object *object = json_object_new_object();

    if (!object || apd_json_add_string(object, "protocol",
                                      g_apd_wire_protocol) != 0 ||
        apd_json_add_string(object, "kind", kind) != 0) {
        json_object_put(object);
        return NULL;
    }
    return object;
}

static int apd_message_is_error(struct json_object *object)
{
    const char *protocol = NULL;
    const char *kind = NULL;
    const char *code = NULL;
    const char *reason = NULL;

    if (ap_control_json_object_exact(object, apd_fields_error,
            APD_ARRAY_SIZE(apd_fields_error), apd_fields_error,
            APD_ARRAY_SIZE(apd_fields_error)) != AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(object, "protocol", &protocol,
                                   strlen(g_apd_wire_protocol),
                                   strlen(g_apd_wire_protocol)) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(object, "kind", &kind, 5, 5) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(object, "error", &code, 1, 64) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(object, "reason", &reason, 1,
                                   APD_TRANSPORT_REASON_MAX) !=
            AP_CONTROL_WIRE_OK)
        return 0;
    (void)code;
    (void)reason;
    return strcmp(protocol, g_apd_wire_protocol) == 0 &&
           strcmp(kind, "error") == 0;
}

static int apd_message_expect(struct json_object *object,
                              const char *const *fields, size_t field_count,
                              const char *kind)
{
    const char *protocol = NULL;
    const char *actual_kind = NULL;

    if (!object || !kind || apd_message_is_error(object) ||
        ap_control_json_object_exact(object, fields, field_count, fields,
                                     field_count) != AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(object, "protocol", &protocol,
                                   strlen(g_apd_wire_protocol),
                                   strlen(g_apd_wire_protocol)) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(object, "kind", &actual_kind,
                                   strlen(kind), strlen(kind)) !=
            AP_CONTROL_WIRE_OK)
        return -1;
    return strcmp(protocol, g_apd_wire_protocol) == 0 &&
           strcmp(actual_kind, kind) == 0 ? 0 : -1;
}

static int apd_message_receive(SSL *ssl, const char *const *fields,
                               size_t field_count, const char *kind,
                               struct json_object **out)
{
    struct json_object *object = NULL;

    if (!out || ap_control_ssl_read_json(ssl, AP_CONTROL_IO_TIMEOUT_MS,
                                         &object) != AP_CONTROL_WIRE_OK)
        return -1;
    if (apd_message_is_error(object)) {
        apd_transport_log("remote_error");
        json_object_put(object);
        return -1;
    }
    if (apd_message_expect(object, fields, field_count, kind) != 0) {
        json_object_put(object);
        return -1;
    }
    *out = object;
    return 0;
}

static int apd_json_get_hex_exact(struct json_object *object, const char *name,
                                  unsigned char *out, size_t length)
{
    const char *encoded = NULL;
    size_t decoded = 0;

    if (ap_control_json_get_string(object, name, &encoded, length * 2,
                                   length * 2) != AP_CONTROL_WIRE_OK ||
        ap_control_hex_decode(encoded, out, length, &decoded) !=
            AP_CONTROL_WIRE_OK || decoded != length) {
        OPENSSL_cleanse(out, length);
        return -1;
    }
    return 0;
}

static int apd_uuid4_valid(const char *value)
{
    static const int hyphens[] = {8, 13, 18, 23};
    size_t i;
    int h = 0;

    if (!value || strlen(value) != 36 || value[14] != '4' ||
        (value[19] != '8' && value[19] != '9' &&
         value[19] != 'a' && value[19] != 'b'))
        return 0;
    for (i = 0; i < 36; i++) {
        if (h < 4 && (int)i == hyphens[h]) {
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

static int apd_json_get_hex_alloc(struct json_object *object, const char *name,
                                  size_t maximum, unsigned char **out,
                                  size_t *out_length)
{
    const char *encoded = NULL;
    unsigned char *decoded = NULL;
    size_t text_length;
    size_t decoded_length = 0;

    if (!out || !out_length ||
        ap_control_json_get_string(object, name, &encoded, 2,
                                   maximum * 2) != AP_CONTROL_WIRE_OK ||
        (text_length = strlen(encoded)) == 0 || (text_length & 1U) ||
        !(decoded = malloc(text_length / 2)) ||
        ap_control_hex_decode(encoded, decoded, text_length / 2,
                              &decoded_length) != AP_CONTROL_WIRE_OK ||
        decoded_length == 0 || decoded_length > maximum) {
        if (decoded) {
            OPENSSL_cleanse(decoded, text_length / 2);
            free(decoded);
        }
        return -1;
    }
    *out = decoded;
    *out_length = decoded_length;
    return 0;
}

static int apd_secure_read(const char *path, size_t maximum,
                           unsigned char **out, size_t *out_length)
{
    struct stat status;
    unsigned char *data = NULL;
    size_t offset = 0;
    int fd = -1;
    int rc = -1;

    if (!path || path[0] != '/' || !out || !out_length || maximum == 0)
        return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_uid != geteuid() || status.st_nlink != 1 ||
        (status.st_mode & 0777) != 0600 || status.st_size <= 0 ||
        (uint64_t)status.st_size > maximum ||
        !(data = malloc((size_t)status.st_size)))
        goto done;
    while (offset < (size_t)status.st_size) {
        ssize_t count = read(fd, data + offset, (size_t)status.st_size - offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            goto done;
        offset += (size_t)count;
    }
    if (read(fd, &(unsigned char){0}, 1) != 0)
        goto done;
    *out = data;
    *out_length = offset;
    data = NULL;
    rc = 0;
done:
    if (fd >= 0)
        close(fd);
    if (data) {
        OPENSSL_cleanse(data, offset);
        free(data);
    }
    return rc;
}

static X509 *apd_ca_load_secure(const char *path,
                                unsigned char fingerprint[SHA256_DIGEST_LENGTH])
{
    unsigned char *pem = NULL;
    unsigned char *der = NULL;
    unsigned char *cursor;
    size_t pem_length = 0;
    BIO *bio = NULL;
    X509 *certificate = NULL;
    int der_length;

    if (apd_secure_read(path, APD_TRANSPORT_CA_PEM_MAX, &pem,
                        &pem_length) != 0 ||
        !(bio = BIO_new_mem_buf(pem, (int)pem_length)) ||
        !(certificate = PEM_read_bio_X509(bio, NULL, NULL, NULL)) ||
        X509_check_ca(certificate) <= 0 ||
        (der_length = i2d_X509(certificate, NULL)) <= 0 ||
        !(der = malloc((size_t)der_length)))
        goto fail;
    cursor = der;
    if (i2d_X509(certificate, &cursor) != der_length ||
        !SHA256(der, (size_t)der_length, fingerprint))
        goto fail;
    BIO_free(bio);
    OPENSSL_cleanse(pem, pem_length);
    free(pem);
    OPENSSL_cleanse(der, (size_t)der_length);
    free(der);
    return certificate;
fail:
    X509_free(certificate);
    BIO_free(bio);
    if (pem) {
        OPENSSL_cleanse(pem, pem_length);
        free(pem);
    }
    if (der) {
        OPENSSL_cleanse(der, der_length > 0 ? (size_t)der_length : 0);
        free(der);
    }
    OPENSSL_cleanse(fingerprint, SHA256_DIGEST_LENGTH);
    return NULL;
}

static int apd_client_certificate_load(SSL_CTX *context)
{
    unsigned char *der = NULL;
    const unsigned char *cursor;
    size_t der_length = 0;
    char path[PATH_MAX];
    X509 *certificate = NULL;
    EVP_PKEY *key = NULL;
    int rc = -1;

    if (!context || snprintf(path, sizeof(path), "%s/%s",
                             apd_credentials_pki_dir(),
                             APD_TRANSPORT_CERT_FILE) >= (int)sizeof(path) ||
        apd_secure_read(path, APD_TRANSPORT_CERT_DER_MAX, &der,
                        &der_length) != 0)
        goto done;
    cursor = der;
    certificate = d2i_X509(NULL, &cursor, (long)der_length);
    key = apd_identity_key_open();
    if (!certificate || cursor != der + der_length || !key ||
        SSL_CTX_use_certificate(context, certificate) != 1 ||
        SSL_CTX_use_PrivateKey(context, key) != 1 ||
        SSL_CTX_check_private_key(context) != 1)
        goto done;
    rc = 0;
done:
    X509_free(certificate);
    EVP_PKEY_free(key);
    if (der) {
        OPENSSL_cleanse(der, der_length);
        free(der);
    }
    return rc;
}

static SSL_CTX *apd_tls_context_new(const char *ca_path, int client_auth)
{
    unsigned char ca_fingerprint[SHA256_DIGEST_LENGTH] = {0};
    SSL_CTX *context = NULL;
    X509 *ca = NULL;
    X509_STORE *store;

    context = SSL_CTX_new(TLS_client_method());
    ca = apd_ca_load_secure(ca_path, ca_fingerprint);
    if (!context || !ca ||
        SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(context, TLS1_3_VERSION) != 1)
        goto fail;
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(context, 2);
    store = SSL_CTX_get_cert_store(context);
    if (!store || X509_STORE_add_cert(store, ca) != 1 ||
        (client_auth && apd_client_certificate_load(context) != 0))
        goto fail;
    X509_free(ca);
    OPENSSL_cleanse(ca_fingerprint, sizeof(ca_fingerprint));
    return context;
fail:
    X509_free(ca);
    SSL_CTX_free(context);
    OPENSSL_cleanse(ca_fingerprint, sizeof(ca_fingerprint));
    return NULL;
}

static int apd_tcp_connect(const char *host, uint16_t port)
{
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    struct addrinfo *address;
    char service[6];
    int64_t deadline;
    int fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    snprintf(service, sizeof(service), "%u", (unsigned int)port);
    deadline = apd_transport_monotonic_ms();
    if (!host || !host[0] || !port || deadline < 0 ||
        getaddrinfo(host, service, &hints, &addresses) != 0)
        return -1;
    deadline += AP_CONTROL_IO_TIMEOUT_MS;
    for (address = addresses; address && !apd_transport_stopping();
         address = address->ai_next) {
        struct pollfd descriptor;
        int flags;
        int error = 0;
        socklen_t error_length = sizeof(error);
        int64_t now;
        int timeout;

        fd = socket(address->ai_family, address->ai_socktype,
                    address->ai_protocol);
        if (fd < 0 || (flags = fcntl(fd, F_GETFL, 0)) < 0 ||
            fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0 ||
            fcntl(fd, F_SETFD, FD_CLOEXEC) != 0 ||
            apd_transport_active_fd_set(fd) != 0)
            goto next;
        if (connect(fd, address->ai_addr, address->ai_addrlen) == 0)
            break;
        if (errno != EINPROGRESS)
            goto next;
        now = apd_transport_monotonic_ms();
        if (now < 0 || now >= deadline)
            goto next;
        timeout = (int)(deadline - now);
        descriptor.fd = fd;
        descriptor.events = POLLOUT;
        descriptor.revents = 0;
        do {
            error = poll(&descriptor, 1, timeout);
        } while (error < 0 && errno == EINTR);
        if (error <= 0 || (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) ||
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_length) != 0 ||
            error != 0)
            goto next;
        break;
next:
        if (fd >= 0) {
            apd_transport_active_fd_clear(fd);
            close(fd);
            fd = -1;
        }
    }
    freeaddrinfo(addresses);
    return fd;
}

static int apd_tls_peer_name(SSL *ssl, const char *host)
{
    unsigned char address[sizeof(struct in6_addr)];
    X509_VERIFY_PARAM *parameters;

    if (!ssl || !host || !(parameters = SSL_get0_param(ssl)))
        return -1;
    X509_VERIFY_PARAM_set_hostflags(parameters, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (inet_pton(AF_INET, host, address) == 1 ||
        inet_pton(AF_INET6, host, address) == 1)
        return X509_VERIFY_PARAM_set1_ip_asc(parameters, host) == 1 ? 0 : -1;
    return SSL_set_tlsext_host_name(ssl, host) == 1 &&
           SSL_set1_host(ssl, host) == 1 ? 0 : -1;
}

static int apd_tls_open(const struct apd_transport_endpoint *endpoint,
                        int client_auth, int offer_v2,
                        struct apd_tls_connection *out)
{
    static const unsigned char alpn_v1[] = "\x10" AP_CONTROL_ALPN_V1;
    static const unsigned char alpn_v3[] =
        "\x10" AP_CONTROL_ALPN_V3 "\x10" AP_CONTROL_ALPN_V2 "\x10" AP_CONTROL_ALPN_V1;
    const unsigned char *alpn = offer_v2 ? alpn_v3 : alpn_v1;
    size_t alpn_length = offer_v2 ? sizeof(alpn_v3) - 1 : sizeof(alpn_v1) - 1;
    struct apd_tls_connection connection;

    memset(&connection, 0, sizeof(connection));
    connection.fd = -1;
    if (!endpoint || !out || !endpoint->present ||
        !(connection.context = apd_tls_context_new(endpoint->ca_path,
                                                   client_auth)) ||
        (connection.fd = apd_tcp_connect(endpoint->host, endpoint->port)) < 0 ||
        !(connection.ssl = SSL_new(connection.context)) ||
        SSL_set_fd(connection.ssl, connection.fd) != 1 ||
        SSL_set_alpn_protos(connection.ssl, alpn, (unsigned int)alpn_length) != 0 ||
        apd_tls_peer_name(connection.ssl, endpoint->host) != 0 ||
        ap_control_ssl_handshake(connection.ssl, 0,
                                 AP_CONTROL_IO_TIMEOUT_MS) !=
            AP_CONTROL_WIRE_OK ||
        SSL_get_verify_result(connection.ssl) != X509_V_OK ||
        !ap_control_ssl_selected_alpn(connection.ssl)) {
        SSL_free(connection.ssl);
        SSL_CTX_free(connection.context);
        if (connection.fd >= 0) {
            apd_transport_active_fd_clear(connection.fd);
            close(connection.fd);
        }
        return -1;
    }
    *out = connection;
    out->protocol_version = ap_control_ssl_selected_alpn_version(connection.ssl);
    apd_transport_set_connected(1);
    return 0;
}

static void apd_tls_close(struct apd_tls_connection *connection)
{
    if (!connection)
        return;
    apd_transport_set_connected(0);
    SSL_free(connection->ssl);
    SSL_CTX_free(connection->context);
    if (connection->fd >= 0) {
        apd_transport_active_fd_clear(connection->fd);
        close(connection->fd);
    }
    memset(connection, 0, sizeof(*connection));
    connection->fd = -1;
}

static struct json_object *apd_enrollment_hello_new(
    const struct apd_node_identity *identity)
{
    struct json_object *object = apd_message_new("enrollment_hello");
    struct apd_device_model device;

    memset(&device, 0, sizeof(device));
    apd_backend_device_model_collect(&device);
    if (!object || apd_json_add_string(object, "ap_id", identity->ap_id) != 0 ||
        apd_json_add_string(object, "key_id", identity->key_id) != 0 ||
        apd_json_add_hex(object, "public_key", identity->public_key,
                         sizeof(identity->public_key)) != 0 ||
        apd_json_add_string(object, "model", device.model) != 0 ||
        apd_json_add_string(object, "board_name", device.board_name) != 0 ||
        apd_json_add_string(object, "model_source", device.model_source) != 0 ||
        apd_json_add_string(object, "model_reason", device.reason) != 0)
        goto fail;
    json_object_object_add(object, "model_available",
                           json_object_new_boolean(device.model_available));
    return object;
fail:
    json_object_put(object);
    return NULL;
}

static struct json_object *apd_enrollment_claim_new(
    const struct apd_enrollment_transcript_v1 *transcript,
    const unsigned char *csr_der, size_t csr_der_length,
    const unsigned char signature[APD_ED25519_SIGNATURE_LEN])
{
    struct json_object *object = apd_message_new("enrollment_claim");

#define APD_ADD_FIELD(name_, field_) \
    apd_json_add_string(object, (name_), \
        (const char *)(field_).data)
    if (!object ||
        APD_ADD_FIELD("challenge_id", transcript->challenge_id) != 0 ||
        apd_json_add_hex(object, "server_nonce", transcript->server_nonce,
                         sizeof(transcript->server_nonce)) != 0 ||
        apd_json_add_hex(object, "client_nonce", transcript->client_nonce,
                         sizeof(transcript->client_nonce)) != 0 ||
        APD_ADD_FIELD("enrollment_id", transcript->enrollment_id) != 0 ||
        APD_ADD_FIELD("token_id", transcript->token_id) != 0 ||
        APD_ADD_FIELD("token", transcript->token) != 0 ||
        APD_ADD_FIELD("ap_id", transcript->ap_id) != 0 ||
        APD_ADD_FIELD("key_id", transcript->key_id) != 0 ||
        apd_json_add_hex(object, "public_key", transcript->public_key,
                         sizeof(transcript->public_key)) != 0 ||
        APD_ADD_FIELD("site_id", transcript->site_id) != 0 ||
        APD_ADD_FIELD("hardware_digest", transcript->hardware_digest) != 0 ||
        apd_json_add_hex(object, "csr_der", csr_der, csr_der_length) != 0 ||
        apd_json_add_hex(object, "csr_sha256", transcript->csr_sha256,
                         sizeof(transcript->csr_sha256)) != 0 ||
        apd_json_add_int64(object, "challenge_expires_at",
                           (int64_t)transcript->challenge_expires_at) != 0 ||
        apd_json_add_hex(object, "signature", signature,
                         APD_ED25519_SIGNATURE_LEN) != 0)
        goto fail;
#undef APD_ADD_FIELD
    return object;
fail:
#undef APD_ADD_FIELD
    json_object_put(object);
    return NULL;
}

static int apd_pairing_prepare(const char *controller_id,
                               const char *challenge_id,
                               const unsigned char server_nonce[32],
                               int64_t expires_at)
{
    struct apd_pairing_status status;

    memset(&status, 0, sizeof(status));
    if (apd_db_pairing_status_get(&status) == 0 &&
        strcmp(status.state, "unpaired") != 0 && status.request_id[0] &&
        apd_db_pairing_reset(status.request_id) != 0)
        return -1;
    return apd_db_pairing_begin(controller_id, challenge_id, expires_at) == 0 &&
        apd_db_pairing_set_challenge(challenge_id, server_nonce, 32) == 0 &&
        apd_db_pairing_verify_challenge(challenge_id, server_nonce, 32) == 0 ?
        0 : -1;
}

static int apd_enrollment_run(const struct apd_bootstrap_config *bootstrap,
                              struct apd_enrollment_metadata *stored)
{
    struct apd_transport_endpoint endpoint;
    struct apd_tls_connection connection;
    struct apd_node_identity identity;
    struct apd_enrollment_transcript_v1 transcript;
    struct apd_credentials_certificate_input certificate_input;
    struct json_object *request = NULL;
    struct json_object *response = NULL;
    unsigned char csr_der[APD_ENROLLMENT_CSR_DER_MAX];
    unsigned char signature[APD_ED25519_SIGNATURE_LEN];
    unsigned char certificate_fingerprint[SHA256_DIGEST_LENGTH];
    unsigned char actual_certificate_fingerprint[SHA256_DIGEST_LENGTH];
    unsigned char expected_ca_fingerprint[SHA256_DIGEST_LENGTH];
    unsigned char response_ca_fingerprint[SHA256_DIGEST_LENGTH];
    unsigned char *certificate_der = NULL;
    size_t certificate_der_length = 0;
    size_t csr_der_length = 0;
    const char *controller_id = NULL;
    const char *challenge_id = NULL;
    const char *response_enrollment_id = NULL;
    const char *certificate_id = NULL;
    int64_t expires_at = 0;
    X509 *ca = NULL;
    char challenge_id_copy[37];
    char controller_id_copy[37];
    char enrollment_id[37];
    int rc = -1;

    memset(&connection, 0, sizeof(connection));
    connection.fd = -1;
    memset(&identity, 0, sizeof(identity));
    memset(&transcript, 0, sizeof(transcript));
    memset(&certificate_input, 0, sizeof(certificate_input));
    memset(csr_der, 0, sizeof(csr_der));
    memset(signature, 0, sizeof(signature));
    memset(certificate_fingerprint, 0, sizeof(certificate_fingerprint));
    memset(actual_certificate_fingerprint, 0,
           sizeof(actual_certificate_fingerprint));
    memset(expected_ca_fingerprint, 0, sizeof(expected_ca_fingerprint));
    memset(response_ca_fingerprint, 0, sizeof(response_ca_fingerprint));
    memset(challenge_id_copy, 0, sizeof(challenge_id_copy));
    memset(controller_id_copy, 0, sizeof(controller_id_copy));
    memset(enrollment_id, 0, sizeof(enrollment_id));
    apd_transport_set_reason("enrollment_connecting");
    if (!bootstrap || !stored || apd_transport_endpoint_get(&endpoint) != 0 ||
        apd_db_identity_get(&identity) != 0 ||
        apd_tls_open(&endpoint, 0, 0, &connection) != 0 ||
        !(request = apd_enrollment_hello_new(&identity)) ||
        ap_control_json_object_exact(request, apd_fields_enrollment_hello,
                APD_ARRAY_SIZE(apd_fields_enrollment_hello),
                apd_fields_enrollment_hello,
                APD_ARRAY_SIZE(apd_fields_enrollment_hello)) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_ssl_write_json(connection.ssl, AP_CONTROL_IO_TIMEOUT_MS,
                                  request) != AP_CONTROL_WIRE_OK)
        goto done;
    json_object_put(request);
    request = NULL;
    if (apd_message_receive(connection.ssl, apd_fields_enrollment_challenge,
            APD_ARRAY_SIZE(apd_fields_enrollment_challenge),
            "enrollment_challenge", &response) != 0 ||
        ap_control_json_get_string(response, "controller_id", &controller_id,
                                   36, 36) != AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(response, "challenge_id", &challenge_id,
                                   36, 36) != AP_CONTROL_WIRE_OK ||
        apd_json_get_hex_exact(response, "server_nonce",
                               transcript.server_nonce,
                               sizeof(transcript.server_nonce)) != 0 ||
        ap_control_json_get_int64(response, "expires_at", apd_now_s() + 1,
                                  apd_now_s() + 600, &expires_at) !=
            AP_CONTROL_WIRE_OK ||
        (bootstrap->controller_id_present &&
         strcmp(bootstrap->controller_id, controller_id) != 0) ||
        snprintf(controller_id_copy, sizeof(controller_id_copy), "%s",
                 controller_id) >= (int)sizeof(controller_id_copy) ||
        snprintf(challenge_id_copy, sizeof(challenge_id_copy), "%s",
                 challenge_id) >= (int)sizeof(challenge_id_copy) ||
        apd_pairing_prepare(controller_id, challenge_id,
                            transcript.server_nonce, expires_at) != 0 ||
        ap_control_uuid4(enrollment_id) != AP_CONTROL_WIRE_OK ||
        RAND_bytes(transcript.client_nonce,
                   sizeof(transcript.client_nonce)) != 1 ||
        apd_enrollment_csr_create(csr_der, sizeof(csr_der), &csr_der_length,
                                  transcript.csr_sha256) != 0)
        goto done;
    transcript.challenge_id.data = (const unsigned char *)challenge_id_copy;
    transcript.challenge_id.len = strlen(challenge_id_copy);
    transcript.enrollment_id.data = (const unsigned char *)enrollment_id;
    transcript.enrollment_id.len = strlen(enrollment_id);
    transcript.token_id.data = (const unsigned char *)bootstrap->token_id;
    transcript.token_id.len = strlen(bootstrap->token_id);
    transcript.token.data = (const unsigned char *)bootstrap->token;
    transcript.token.len = strlen(bootstrap->token);
    transcript.ap_id.data = (const unsigned char *)identity.ap_id;
    transcript.ap_id.len = strlen(identity.ap_id);
    transcript.key_id.data = (const unsigned char *)identity.key_id;
    transcript.key_id.len = strlen(identity.key_id);
    memcpy(transcript.public_key, identity.public_key,
           sizeof(transcript.public_key));
    transcript.site_id.data = (const unsigned char *)bootstrap->site_id;
    transcript.site_id.len = strlen(bootstrap->site_id);
    transcript.hardware_digest.data =
        (const unsigned char *)bootstrap->hardware_digest;
    transcript.hardware_digest.len = strlen(bootstrap->hardware_digest);
    transcript.challenge_expires_at = (uint64_t)expires_at;
    if (apd_enrollment_transcript_sign_v1(&transcript, signature) != 0)
        goto done;
    json_object_put(response);
    response = NULL;
    request = apd_enrollment_claim_new(&transcript, csr_der, csr_der_length,
                                       signature);
    if (!request || ap_control_json_object_exact(request,
            apd_fields_enrollment_claim,
            APD_ARRAY_SIZE(apd_fields_enrollment_claim),
            apd_fields_enrollment_claim,
            APD_ARRAY_SIZE(apd_fields_enrollment_claim)) !=
                AP_CONTROL_WIRE_OK ||
        ap_control_ssl_write_json(connection.ssl, AP_CONTROL_IO_TIMEOUT_MS,
                                  request) != AP_CONTROL_WIRE_OK)
        goto done;
    json_object_put(request);
    request = NULL;
    if (apd_message_receive(connection.ssl, apd_fields_enrollment_certificate,
            APD_ARRAY_SIZE(apd_fields_enrollment_certificate),
            "enrollment_certificate", &response) != 0 ||
        ap_control_json_get_string(response, "controller_id", &controller_id,
                                   36, 36) != AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(response, "enrollment_id",
                                   &response_enrollment_id, 36, 36) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(response, "certificate_id", &certificate_id,
                                   36, 36) != AP_CONTROL_WIRE_OK ||
        !apd_uuid4_valid(response_enrollment_id) ||
        strcmp(controller_id_copy, controller_id) != 0 ||
        apd_json_get_hex_alloc(response, "certificate_der",
                               APD_TRANSPORT_CERT_DER_MAX, &certificate_der,
                               &certificate_der_length) != 0 ||
        apd_json_get_hex_exact(response, "certificate_fingerprint",
                               certificate_fingerprint,
                               sizeof(certificate_fingerprint)) != 0 ||
        apd_json_get_hex_exact(response, "ca_fingerprint",
                               response_ca_fingerprint,
                               sizeof(response_ca_fingerprint)) != 0 ||
        !SHA256(certificate_der, certificate_der_length,
                actual_certificate_fingerprint) ||
        CRYPTO_memcmp(actual_certificate_fingerprint, certificate_fingerprint,
                      sizeof(certificate_fingerprint)) != 0 ||
        !(ca = apd_ca_load_secure(bootstrap->ca_cert_pem_path,
                                  expected_ca_fingerprint)) ||
        CRYPTO_memcmp(expected_ca_fingerprint, response_ca_fingerprint,
                      sizeof(expected_ca_fingerprint)) != 0)
        goto done;
    certificate_input.certificate_der = certificate_der;
    certificate_input.certificate_der_len = certificate_der_length;
    snprintf(certificate_input.controller_id,
             sizeof(certificate_input.controller_id), "%s", controller_id);
    snprintf(certificate_input.enrollment_id,
             sizeof(certificate_input.enrollment_id), "%s",
             response_enrollment_id);
    snprintf(certificate_input.certificate_id,
             sizeof(certificate_input.certificate_id), "%s", certificate_id);
    if (apd_credentials_certificate_store(&certificate_input, stored) != 0)
        goto done;
    apd_transport_set_reason("certificate_stored");
    rc = 0;
done:
    X509_free(ca);
    json_object_put(request);
    json_object_put(response);
    apd_tls_close(&connection);
    if (certificate_der) {
        OPENSSL_cleanse(certificate_der, certificate_der_length);
        free(certificate_der);
    }
    OPENSSL_cleanse(csr_der, sizeof(csr_der));
    OPENSSL_cleanse(signature, sizeof(signature));
    OPENSSL_cleanse(certificate_fingerprint,
                    sizeof(certificate_fingerprint));
    OPENSSL_cleanse(actual_certificate_fingerprint,
                    sizeof(actual_certificate_fingerprint));
    OPENSSL_cleanse(expected_ca_fingerprint,
                    sizeof(expected_ca_fingerprint));
    OPENSSL_cleanse(response_ca_fingerprint,
                    sizeof(response_ca_fingerprint));
    OPENSSL_cleanse(&transcript, sizeof(transcript));
    OPENSSL_cleanse(&certificate_input, sizeof(certificate_input));
    OPENSSL_cleanse(&identity, sizeof(identity));
    OPENSSL_cleanse(challenge_id_copy, sizeof(challenge_id_copy));
    OPENSSL_cleanse(controller_id_copy, sizeof(controller_id_copy));
    OPENSSL_cleanse(enrollment_id, sizeof(enrollment_id));
    return rc;
}

static struct json_object *apd_identity_message_new(
    const char *kind, const struct apd_enrollment_metadata *metadata,
    int include_enrollment)
{
    struct json_object *object = apd_message_new(kind);

    if (!object ||
        apd_json_add_string(object, "controller_id",
                            metadata->controller_id) != 0 ||
        (include_enrollment &&
         apd_json_add_string(object, "enrollment_id",
                             metadata->enrollment_id) != 0) ||
        apd_json_add_string(object, "certificate_id",
                            metadata->certificate_id) != 0 ||
        apd_json_add_string(object, "ap_id", metadata->ap_id) != 0) {
        json_object_put(object);
        return NULL;
    }
    return object;
}

static int apd_metadata_fingerprint(
    const struct apd_enrollment_metadata *metadata,
    unsigned char out[SHA256_DIGEST_LENGTH])
{
    size_t length = 0;

    if (!metadata || strncmp(metadata->certificate_fingerprint,
                             "sha256:", 7) != 0 ||
        ap_control_hex_decode(metadata->certificate_fingerprint + 7, out,
                              SHA256_DIGEST_LENGTH, &length) !=
            AP_CONTROL_WIRE_OK || length != SHA256_DIGEST_LENGTH) {
        OPENSSL_cleanse(out, SHA256_DIGEST_LENGTH);
        return -1;
    }
    return 0;
}

static int apd_activation_complete_apply(
    struct json_object *response, struct apd_enrollment_metadata *metadata,
    const unsigned char fingerprint[SHA256_DIGEST_LENGTH])
{
    unsigned char response_fingerprint[SHA256_DIGEST_LENGTH];
    const char *text = NULL;
    struct json_object *adopted = NULL;
    int activate_result;
    int rc = -1;

    memset(response_fingerprint, 0, sizeof(response_fingerprint));
    if (!response || !metadata || !fingerprint) {
        apd_transport_set_reason("activation_complete_input_invalid");
        goto done;
    }
    if (apd_message_expect(response, apd_fields_activation_complete,
                APD_ARRAY_SIZE(apd_fields_activation_complete),
                "activation_complete") != 0) {
        apd_transport_set_reason("activation_complete_contract_invalid");
        goto done;
    }
    if (ap_control_json_get_string(response, "controller_id", &text, 36, 36) !=
            AP_CONTROL_WIRE_OK || strcmp(text, metadata->controller_id) != 0) {
        apd_transport_set_reason("activation_controller_mismatch");
        goto done;
    }
    if (ap_control_json_get_string(response, "enrollment_id", &text, 36, 36) !=
            AP_CONTROL_WIRE_OK || strcmp(text, metadata->enrollment_id) != 0) {
        apd_transport_set_reason("activation_enrollment_mismatch");
        goto done;
    }
    if (ap_control_json_get_string(response, "certificate_id", &text, 36, 36) !=
            AP_CONTROL_WIRE_OK || strcmp(text, metadata->certificate_id) != 0) {
        apd_transport_set_reason("activation_certificate_mismatch");
        goto done;
    }
    if (apd_json_get_hex_exact(response, "certificate_fingerprint",
                               response_fingerprint,
                               sizeof(response_fingerprint)) != 0 ||
        CRYPTO_memcmp(fingerprint, response_fingerprint,
                      sizeof(response_fingerprint)) != 0) {
        apd_transport_set_reason("activation_fingerprint_mismatch");
        goto done;
    }
    if (!json_object_object_get_ex(response, "adopted", &adopted) || !adopted ||
        !json_object_is_type(adopted, json_type_boolean) ||
        !json_object_get_boolean(adopted)) {
        apd_transport_set_reason("activation_not_adopted");
        goto done;
    }
    activate_result = apd_credentials_activate(metadata->controller_id,
                                               metadata->enrollment_id,
                                               metadata->certificate_id,
                                               fingerprint, metadata);
    if (activate_result != APD_CREDENTIALS_ACTIVATE_OK) {
        switch (activate_result) {
        case APD_CREDENTIALS_ACTIVATE_CONTROLLER_INVALID:
            apd_transport_set_reason("activation_controller_id_invalid");
            break;
        case APD_CREDENTIALS_ACTIVATE_ENROLLMENT_INVALID:
            apd_transport_set_reason("activation_enrollment_id_invalid");
            break;
        case APD_CREDENTIALS_ACTIVATE_CERTIFICATE_INVALID:
            apd_transport_set_reason("activation_certificate_id_invalid");
            break;
        case APD_CREDENTIALS_ACTIVATE_FINGERPRINT_MISSING:
            apd_transport_set_reason("activation_fingerprint_missing");
            break;
        case APD_CREDENTIALS_ACTIVATE_LOCK_FAILED:
            apd_transport_set_reason("activation_credentials_lock_failed");
            break;
        case APD_CREDENTIALS_ACTIVATE_VALIDATE_FAILED:
            apd_transport_set_reason("activation_credentials_validate_failed");
            break;
        case APD_CREDENTIALS_ACTIVATE_BINDING_MISMATCH:
            apd_transport_set_reason("activation_credentials_binding_mismatch");
            break;
        case APD_CREDENTIALS_ACTIVATE_BOOTSTRAP_REMOVE_FAILED:
            apd_transport_set_reason("activation_bootstrap_remove_failed");
            break;
        case APD_CREDENTIALS_ACTIVATE_METADATA_COMMIT_FAILED:
            apd_transport_set_reason("activation_metadata_commit_failed");
            break;
        default:
            apd_transport_set_reason("activation_credentials_result_unknown");
            break;
        }
        goto done;
    }
    apd_transport_set_reason("adopted");
    rc = 0;
done:
    OPENSSL_cleanse(response_fingerprint, sizeof(response_fingerprint));
    return rc;
}

static int apd_activation_run(struct apd_enrollment_metadata *metadata)
{
    struct apd_transport_endpoint endpoint;
    struct apd_tls_connection connection;
    struct json_object *request = NULL;
    struct json_object *response = NULL;
    unsigned char challenge[32];
    unsigned char fingerprint[SHA256_DIGEST_LENGTH];
    const char *text = NULL;
    int rc = -1;

    memset(&connection, 0, sizeof(connection));
    connection.fd = -1;
    memset(challenge, 0, sizeof(challenge));
    memset(fingerprint, 0, sizeof(fingerprint));
    apd_transport_set_reason("activation_connecting");
    if (!metadata) {
        apd_transport_set_reason("activation_metadata_missing");
        goto done;
    }
    if (apd_transport_endpoint_get(&endpoint) != 0) {
        apd_transport_set_reason("activation_endpoint_unavailable");
        goto done;
    }
    if (apd_metadata_fingerprint(metadata, fingerprint) != 0) {
        apd_transport_set_reason("activation_metadata_fingerprint_invalid");
        goto done;
    }
    if (apd_tls_open(&endpoint, 1, 0, &connection) != 0) {
        apd_transport_set_reason("activation_tls_open_failed");
        goto done;
    }
    request = apd_identity_message_new("activation_hello", metadata, 1);
    if (!request ||
        ap_control_json_object_exact(request, apd_fields_activation_hello,
                APD_ARRAY_SIZE(apd_fields_activation_hello),
                apd_fields_activation_hello,
                APD_ARRAY_SIZE(apd_fields_activation_hello)) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_ssl_write_json(connection.ssl, AP_CONTROL_IO_TIMEOUT_MS,
                                  request) != AP_CONTROL_WIRE_OK) {
        apd_transport_set_reason("activation_hello_write_failed");
        goto done;
    }
    json_object_put(request);
    request = NULL;
    if (ap_control_ssl_read_json(connection.ssl, AP_CONTROL_IO_TIMEOUT_MS,
                                 &response) != AP_CONTROL_WIRE_OK) {
        apd_transport_set_reason("activation_first_frame_read_failed");
        goto done;
    }
    if (apd_message_is_error(response)) {
        apd_transport_set_reason("activation_remote_error");
        goto done;
    }
    if (apd_message_expect(response, apd_fields_activation_complete,
            APD_ARRAY_SIZE(apd_fields_activation_complete),
            "activation_complete") == 0) {
        rc = apd_activation_complete_apply(response, metadata, fingerprint);
        goto done;
    }
    if (apd_message_expect(response, apd_fields_activation_challenge,
            APD_ARRAY_SIZE(apd_fields_activation_challenge),
            "activation_challenge") != 0 ||
        ap_control_json_get_string(response, "enrollment_id", &text, 36, 36) !=
            AP_CONTROL_WIRE_OK || strcmp(text, metadata->enrollment_id) != 0 ||
        ap_control_json_get_string(response, "certificate_id", &text, 36, 36) !=
            AP_CONTROL_WIRE_OK || strcmp(text, metadata->certificate_id) != 0 ||
        apd_json_get_hex_exact(response, "challenge", challenge,
                               sizeof(challenge)) != 0) {
        apd_transport_set_reason("activation_first_frame_invalid");
        goto done;
    }
    json_object_put(response);
    response = NULL;
    request = apd_message_new("activation_response");
    if (!request ||
        apd_json_add_string(request, "enrollment_id",
                            metadata->enrollment_id) != 0 ||
        apd_json_add_string(request, "certificate_id",
                            metadata->certificate_id) != 0 ||
        apd_json_add_hex(request, "challenge", challenge,
                         sizeof(challenge)) != 0 ||
        ap_control_json_object_exact(request, apd_fields_activation_response,
                APD_ARRAY_SIZE(apd_fields_activation_response),
                apd_fields_activation_response,
                APD_ARRAY_SIZE(apd_fields_activation_response)) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_ssl_write_json(connection.ssl, AP_CONTROL_IO_TIMEOUT_MS,
                                  request) != AP_CONTROL_WIRE_OK) {
        apd_transport_set_reason("activation_response_write_failed");
        goto done;
    }
    json_object_put(request);
    request = NULL;
    if (apd_message_receive(connection.ssl, apd_fields_activation_complete,
            APD_ARRAY_SIZE(apd_fields_activation_complete),
            "activation_complete", &response) != 0) {
        apd_transport_set_reason("activation_complete_read_failed");
        goto done;
    }
    if (apd_activation_complete_apply(response, metadata, fingerprint) != 0)
        goto done;
    rc = 0;
done:
    json_object_put(request);
    json_object_put(response);
    apd_tls_close(&connection);
    OPENSSL_cleanse(challenge, sizeof(challenge));
    OPENSSL_cleanse(fingerprint, sizeof(fingerprint));
    return rc;
}

static uint64_t apd_transport_next_sequence(void)
{
    uint64_t value;

    pthread_mutex_lock(&g_apd_transport.lock);
    value = ++g_apd_transport.sequence;
    pthread_mutex_unlock(&g_apd_transport.lock);
    return value;
}

static int apd_session_heartbeat(SSL *ssl,
                                 const struct apd_enrollment_metadata *metadata,
                                 const char *session_epoch)
{
    struct json_object *request = NULL;
    struct json_object *response = NULL;
    const char *ap_id = NULL;
    int64_t sequence = (int64_t)apd_transport_next_sequence();
    int64_t acknowledged = 0;
    int rc = -1;

    request = apd_message_new("heartbeat");
    if (!request || apd_json_add_string(request, "ap_id", metadata->ap_id) != 0 ||
        apd_json_add_string(request, "session_epoch", session_epoch) != 0 ||
        apd_json_add_int64(request, "sequence", sequence) != 0 ||
        apd_json_add_int64(request, "timestamp", apd_now_s()) != 0 ||
        ap_control_json_object_exact(request, apd_fields_heartbeat,
                APD_ARRAY_SIZE(apd_fields_heartbeat), apd_fields_heartbeat,
                APD_ARRAY_SIZE(apd_fields_heartbeat)) != AP_CONTROL_WIRE_OK ||
        ap_control_ssl_write_json(ssl, AP_CONTROL_IO_TIMEOUT_MS, request) !=
            AP_CONTROL_WIRE_OK)
        goto done;
    if (apd_message_receive(ssl, apd_fields_heartbeat_ack,
            APD_ARRAY_SIZE(apd_fields_heartbeat_ack), "heartbeat_ack",
            &response) != 0 ||
        ap_control_json_get_string(response, "ap_id", &ap_id, 36, 36) !=
            AP_CONTROL_WIRE_OK ||
        strcmp(ap_id, metadata->ap_id) != 0 ||
        ap_control_json_get_string(response, "session_epoch", &ap_id, 64, 64) !=
            AP_CONTROL_WIRE_OK || strcmp(ap_id, session_epoch) != 0 ||
        ap_control_json_get_int64(response, "sequence", sequence, sequence,
                                  &acknowledged) != AP_CONTROL_WIRE_OK)
        goto done;
    rc = 0;
done:
    json_object_put(request);
    json_object_put(response);
    return rc;
}

static int apd_session_telemetry(SSL *ssl,
                                 const struct apd_enrollment_metadata *metadata,
                                 const char *session_epoch,
                                 struct apd_telemetry_gate *gate, int force)
{
    const struct apd_backend_ops *backend = apd_backend();
    struct json_object *snapshot = NULL;
    struct json_object *request = NULL;
    struct json_object *response = NULL;
    struct json_object *accepted = NULL;
    struct json_object *snapshot_observed = NULL;
    unsigned char *encoded = NULL;
    size_t encoded_len = 0;
    const char *ap_id = NULL;
    int64_t sequence;
    int64_t observed_at;
    int64_t acknowledged = 0;
    int64_t now;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    int rc = 1;

    memset(digest, 0, sizeof(digest));
    if (!gate || !backend || !backend->snapshot_supported ||
        !backend->snapshot) {
        apd_transport_log_stage("telemetry_failed", "backend");
        goto done;
    }
    if (backend->snapshot(&snapshot) != 0 || !snapshot ||
        !json_object_is_type(snapshot, json_type_object)) {
        apd_transport_log_stage("telemetry_failed", "snapshot");
        goto done;
    }
    now = apd_transport_monotonic_s();
    if (now < 0 || apd_telemetry_digest(snapshot, digest) != 0) {
        apd_transport_log_stage("telemetry_failed", "digest");
        goto done;
    }
    if (!apd_telemetry_should_send(gate, digest, force, now)) {
        rc = 1;
        goto done;
    }
    if (!json_object_object_get_ex(snapshot, "observed_at", &snapshot_observed) ||
        !snapshot_observed || !json_object_is_type(snapshot_observed, json_type_int) ||
        (observed_at = json_object_get_int64(snapshot_observed)) <= 0) {
        apd_transport_log_stage("telemetry_failed", "observed_at");
        goto done;
    }
    sequence = (int64_t)apd_transport_next_sequence();
    request = apd_message_new("telemetry_snapshot");
    if (!request ||
        apd_json_add_string(request, "schema", APD_TELEMETRY_SCHEMA) != 0 ||
        apd_json_add_int64(request, "version", APD_TELEMETRY_VERSION) != 0 ||
        apd_json_add_string(request, "ap_id", metadata->ap_id) != 0 ||
        apd_json_add_string(request, "session_epoch", session_epoch) != 0 ||
        apd_json_add_int64(request, "sequence", sequence) != 0 ||
        apd_json_add_int64(request, "observed_at", observed_at) != 0) {
        apd_transport_log_stage("telemetry_failed", "request");
        goto done;
    }
    json_object_object_add(request, "snapshot", json_object_get(snapshot));
    if (ap_control_json_object_exact(request, apd_fields_telemetry_snapshot,
            APD_ARRAY_SIZE(apd_fields_telemetry_snapshot),
            apd_fields_telemetry_snapshot,
            APD_ARRAY_SIZE(apd_fields_telemetry_snapshot)) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_frame_encode(request, &encoded, &encoded_len) !=
            AP_CONTROL_WIRE_OK) {
        apd_transport_log_stage("telemetry_failed", "frame");
        goto done;
    }
    free(encoded);
    encoded = NULL;
    if (ap_control_ssl_write_json(ssl, AP_CONTROL_IO_TIMEOUT_MS, request) !=
            AP_CONTROL_WIRE_OK) {
        apd_transport_log_stage("telemetry_failed", "write");
        rc = -1;
        goto done;
    }
    if (apd_message_receive(ssl, apd_fields_telemetry_ack,
            APD_ARRAY_SIZE(apd_fields_telemetry_ack), "telemetry_ack",
            &response) != 0) {
        apd_transport_log_stage("telemetry_failed", "ack_read");
        rc = -1;
        goto done;
    }
    if (ap_control_json_get_string(response, "ap_id", &ap_id, 36, 36) !=
            AP_CONTROL_WIRE_OK || strcmp(ap_id, metadata->ap_id) != 0 ||
        ap_control_json_get_string(response, "session_epoch", &ap_id, 64, 64) !=
            AP_CONTROL_WIRE_OK || strcmp(ap_id, session_epoch) != 0 ||
        ap_control_json_get_int64(response, "sequence", sequence, sequence,
                                  &acknowledged) != AP_CONTROL_WIRE_OK ||
        !json_object_object_get_ex(response, "accepted", &accepted) ||
        !accepted || !json_object_is_type(accepted, json_type_boolean) ||
        !json_object_get_boolean(accepted)) {
        apd_transport_log_stage("telemetry_failed", "ack_validate");
        rc = -1;
        goto done;
    }
    memcpy(gate->digest, digest, sizeof(gate->digest));
    gate->digest_present = 1;
    gate->sent_at = now;
    rc = 0;
done:
    free(encoded);
    json_object_put(snapshot);
    json_object_put(request);
    json_object_put(response);
    OPENSSL_cleanse(digest, sizeof(digest));
    return rc;
}

static int apd_v2_boolean(struct json_object *object, const char *name,
                          int *out)
{
    struct json_object *value = NULL;

    if (!object || !name || !out ||
        !json_object_object_get_ex(object, name, &value) || !value ||
        !json_object_is_type(value, json_type_boolean))
        return -1;
    *out = json_object_get_boolean(value) ? 1 : 0;
    return 0;
}

static int apd_v2_copy_string(struct json_object *object, const char *name,
                              char *out, size_t size, size_t minimum)
{
    const char *value = NULL;

    if (!out || size < 2 ||
        ap_control_json_get_string(object, name, &value, minimum, size - 1) !=
            AP_CONTROL_WIRE_OK ||
        snprintf(out, size, "%s", value) >= (int)size)
        return -1;
    return 0;
}

static int apd_v2_response_identity(struct json_object *response,
                                    const struct apd_enrollment_metadata *metadata,
                                    const char *session_epoch,
                                    int64_t request_sequence)
{
    const char *value = NULL;
    int64_t reply_to = 0;

    return response && metadata && session_epoch && request_sequence > 0 &&
        ap_control_json_get_string(response, "ap_id", &value, 36, 36) ==
            AP_CONTROL_WIRE_OK && strcmp(value, metadata->ap_id) == 0 &&
        ap_control_json_get_string(response, "session_epoch", &value, 64, 64) ==
            AP_CONTROL_WIRE_OK && strcmp(value, session_epoch) == 0 &&
        ap_control_json_get_int64(response, "reply_to", request_sequence,
                                  request_sequence, &reply_to) ==
            AP_CONTROL_WIRE_OK ? 0 : -1;
}

static int apd_v2_assignment_add(struct json_object *object,
                                 const struct apd_radio_job_assignment *job)
{
    return object && job &&
        apd_json_add_string(object, "job_id", job->job_id) == 0 &&
        apd_json_add_string(object, "attempt_id", job->attempt_id) == 0 &&
        apd_json_add_int64(object, "dispatch_generation",
                           job->dispatch_generation) == 0 &&
        apd_json_add_string(object, "request_digest", job->request_digest) == 0
            ? 0 : -1;
}

static int apd_v2_assignment_parse(
    struct json_object *object, const struct apd_enrollment_metadata *metadata,
    const char *session_epoch, struct apd_radio_job_assignment *out)
{
    int64_t generation = 0;

    if (!object || !metadata || !session_epoch || !out)
        return -1;
    memset(out, 0, sizeof(*out));
    if (apd_v2_copy_string(object, "job_id", out->job_id,
                           sizeof(out->job_id), 36) != 0 ||
        !apd_uuid4_valid(out->job_id) ||
        apd_v2_copy_string(object, "attempt_id", out->attempt_id,
                           sizeof(out->attempt_id), 36) != 0 ||
        !apd_uuid4_valid(out->attempt_id) ||
        ap_control_json_get_int64(object, "dispatch_generation", 1, INT64_MAX,
                                  &generation) != AP_CONTROL_WIRE_OK ||
        apd_v2_copy_string(object, "request_digest", out->request_digest,
                           sizeof(out->request_digest), 71) != 0 ||
        strncmp(out->request_digest, "sha256:", 7) != 0 ||
        apd_v2_copy_string(object, "radio_id", out->radio_id,
                           sizeof(out->radio_id), 1) != 0 ||
        apd_v2_copy_string(object, "mode", out->mode,
                           sizeof(out->mode), 1) != 0)
        return -1;
    out->dispatch_generation = generation;
    snprintf(out->ap_id, sizeof(out->ap_id), "%s", metadata->ap_id);
    snprintf(out->session_epoch, sizeof(out->session_epoch), "%s",
             session_epoch);
    return 0;
}

static int apd_v2_assignment_matches(
    struct json_object *object, const struct apd_radio_job_assignment *job)
{
    const char *value = NULL;
    int64_t generation = 0;

    return object && job &&
        ap_control_json_get_string(object, "job_id", &value, 36, 36) ==
            AP_CONTROL_WIRE_OK && strcmp(value, job->job_id) == 0 &&
        ap_control_json_get_string(object, "attempt_id", &value, 36, 36) ==
            AP_CONTROL_WIRE_OK && strcmp(value, job->attempt_id) == 0 &&
        ap_control_json_get_int64(object, "dispatch_generation",
                                  job->dispatch_generation,
                                  job->dispatch_generation, &generation) ==
            AP_CONTROL_WIRE_OK &&
        ap_control_json_get_string(object, "request_digest", &value, 71, 71) ==
            AP_CONTROL_WIRE_OK && strcmp(value, job->request_digest) == 0;
}

static int apd_v2_request_base(
    struct json_object *request, const struct apd_enrollment_metadata *metadata,
    const char *session_epoch, int64_t *sequence)
{
    if (!request || !metadata || !session_epoch || !sequence)
        return -1;
    *sequence = (int64_t)apd_transport_next_sequence();
    return *sequence > 0 &&
        apd_json_add_string(request, "ap_id", metadata->ap_id) == 0 &&
        apd_json_add_string(request, "session_epoch", session_epoch) == 0 &&
        apd_json_add_int64(request, "sequence", *sequence) == 0 ? 0 : -1;
}

static int apd_v2_finish_id(char out[APD_RADIO_JOB_UUID_LEN + 1])
{
    unsigned char bytes[16];

    if (!out || RAND_bytes(bytes, sizeof(bytes)) != 1)
        return -1;
    bytes[6] = (unsigned char)((bytes[6] & 0x0fU) | 0x40U);
    bytes[8] = (unsigned char)((bytes[8] & 0x3fU) | 0x80U);
    snprintf(out, APD_RADIO_JOB_UUID_LEN + 1,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
             "%02x%02x%02x%02x%02x%02x",
             bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
             bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
             bytes[12], bytes[13], bytes[14], bytes[15]);
    OPENSSL_cleanse(bytes, sizeof(bytes));
    return 0;
}

/* Never emit a radio job frame the controller will refuse: a journaled
 * result can exceed the frame budget (recorded under an older bound) or
 * contain bytes the strict wire parser rejects (e.g. a neighbor SSID with
 * raw non-ASCII UTF-8). Either would wedge the session in a resend loop.
 * Self-check the serialized request with the same shared parser the AC
 * uses and drop result entries until it passes, reporting
 * result_complete=false for anything dropped. */
static int apd_v2_result_fit_wire(struct json_object *request)
{
    const size_t budget = AP_CONTROL_FRAME_MAX - 1024;
    struct json_object *result = NULL;
    const char *serialized;
    size_t length;
    int dropped = 0;

    if (!request ||
        !json_object_object_get_ex(request, "result", &result) || !result ||
        !json_object_is_type(result, json_type_array))
        return -1;
    for (;;) {
        int acceptable = 0;

        serialized = json_object_to_json_string_ext(request,
                                                    JSON_C_TO_STRING_PLAIN);
        if (!serialized)
            return -1;
        length = strlen(serialized);
        if (length <= budget) {
            struct json_object *echo = NULL;
            size_t i;

            /* The controller's json-c build rejects raw non-ASCII bytes;
             * the local library may not, so check bytes directly instead
             * of trusting a local parse. */
            acceptable = 1;
            for (i = 0; i < length; i++) {
                if ((unsigned char)serialized[i] >= 0x80U) {
                    acceptable = 0;
                    break;
                }
            }
            if (acceptable) {
                acceptable = ap_control_json_parse_strict(
                    (const unsigned char *)serialized, length, &echo) ==
                    AP_CONTROL_WIRE_OK;
                json_object_put(echo);
            }
        }
        if (acceptable)
            break;
        if (json_object_array_length(result) == 0)
            return -1;
        json_object_array_del_idx(result,
                                  json_object_array_length(result) - 1, 1);
        dropped = 1;
    }
    if (dropped) {
        json_object_object_add(request, "result_complete",
                               json_object_new_boolean(0));
        apd_transport_log_stage("radio_job_result_truncated", "wire_budget");
    }
    return 0;
}

static int apd_v2_finish_send(
    SSL *ssl, const struct apd_enrollment_metadata *metadata,
    const char *session_epoch, const struct apd_radio_job_journal_entry *entry,
    const char *result_json)
{
    struct json_object *request = NULL;
    struct json_object *response = NULL;
    struct json_object *result = NULL;
    const char *finish_id = NULL;
    const char *controller_state = NULL;
    int journal_result;
    int64_t sequence = 0;
    int rc = -1;

    result = json_tokener_parse(result_json ? result_json : "[]");
    request = apd_message_new("radio_job_finish");
    if (!result || !json_object_is_type(result, json_type_array) || !request ||
        apd_v2_request_base(request, metadata, session_epoch, &sequence) != 0 ||
        apd_v2_assignment_add(request, &entry->assignment) != 0 ||
        apd_json_add_string(request, "finish_id", entry->finish_id) != 0 ||
        apd_json_add_string(request, "outcome", entry->outcome) != 0 ||
        apd_json_add_string(request, "error_code", entry->error_code) != 0)
        goto done;
    json_object_object_add(request, "result_complete",
                           json_object_new_boolean(entry->result_complete));
    json_object_object_add(request, "result", json_object_get(result));
    if (apd_v2_result_fit_wire(request) != 0 ||
        ap_control_json_object_exact(request, apd_fields_radio_job_finish,
            APD_ARRAY_SIZE(apd_fields_radio_job_finish),
            apd_fields_radio_job_finish,
            APD_ARRAY_SIZE(apd_fields_radio_job_finish)) != AP_CONTROL_WIRE_OK ||
        ap_control_ssl_write_json(ssl, AP_CONTROL_IO_TIMEOUT_MS, request) !=
            AP_CONTROL_WIRE_OK ||
        apd_message_receive(ssl, apd_fields_radio_job_finish_ack,
            APD_ARRAY_SIZE(apd_fields_radio_job_finish_ack),
            "radio_job_finish_ack", &response) != 0 ||
        apd_v2_response_identity(response, metadata, session_epoch, sequence) != 0 ||
        !apd_v2_assignment_matches(response, &entry->assignment) ||
        ap_control_json_get_string(response, "finish_id", &finish_id, 36, 36) !=
            AP_CONTROL_WIRE_OK || strcmp(finish_id, entry->finish_id) != 0 ||
        ap_control_json_get_string(response, "controller_state",
                                   &controller_state, 6, 31) !=
            AP_CONTROL_WIRE_OK ||
        (strcmp(controller_state, "completed") != 0 &&
         strcmp(controller_state, "failed") != 0 &&
         strcmp(controller_state, "cancelled") != 0))
        goto done;
    journal_result = apd_radio_job_finish_ack(&entry->assignment,
                                               entry->finish_id,
                                               apd_now_s(), NULL);
    if (journal_result != APD_RADIO_JOB_JOURNAL_OK &&
        journal_result != APD_RADIO_JOB_JOURNAL_IDEMPOTENT)
        goto done;
    rc = 0;
done:
    json_object_put(result);
    json_object_put(request);
    json_object_put(response);
    return rc;
}

static int apd_v2_pending_finish_replay(
    SSL *ssl, const struct apd_enrollment_metadata *metadata,
    const char *session_epoch)
{
    struct apd_radio_job_pending_finish pending;
    int result;

    memset(&pending, 0, sizeof(pending));
    result = apd_radio_job_pending_finish_get(metadata->ap_id, &pending);
    if (result == APD_RADIO_JOB_JOURNAL_NOT_FOUND)
        return 0;
    if (result != APD_RADIO_JOB_JOURNAL_OK)
        return -1;
    if (strcmp(pending.entry.state, "completed") != 0 &&
        strcmp(pending.entry.state, "failed") != 0 &&
        strcmp(pending.entry.state, "cancelled") != 0 &&
        strcmp(pending.entry.state, "interrupted") != 0) {
        apd_radio_job_pending_finish_free(&pending);
        return 0;
    }
    result = apd_v2_finish_send(ssl, metadata, session_epoch, &pending.entry,
                                pending.result_json);
    apd_radio_job_pending_finish_free(&pending);
    return result;
}

static int apd_v2_finish_store(
    const struct apd_radio_job_assignment *job, const char *outcome,
    const char *error_code, struct json_object *items, int complete,
    struct apd_radio_job_journal_entry *out)
{
    struct apd_radio_job_finish finish;
    const char *payload;
    int result;

    if (!job || !outcome || !error_code || !items ||
        !json_object_is_type(items, json_type_array))
        return -1;
    memset(&finish, 0, sizeof(finish));
    finish.assignment = *job;
    if (apd_v2_finish_id(finish.finish_id) != 0)
        return -1;
    snprintf(finish.outcome, sizeof(finish.outcome), "%s", outcome);
    snprintf(finish.error_code, sizeof(finish.error_code), "%s", error_code);
    finish.observed_at = apd_now_s();
    finish.result_complete = complete ? 1 : 0;
    payload = json_object_to_json_string_ext(items, JSON_C_TO_STRING_PLAIN);
    finish.result_json = payload;
    result = apd_radio_job_finish_store(&finish, apd_now_s(), out);
    return result == APD_RADIO_JOB_JOURNAL_OK ||
           result == APD_RADIO_JOB_JOURNAL_IDEMPOTENT ? 0 : -1;
}

static int apd_v2_cancel_finish(
    const struct apd_radio_job_assignment *job,
    struct apd_radio_job_journal_entry *out)
{
    struct json_object *items = json_object_new_array();
    int rc;

    if (!items)
        return -1;
    rc = apd_v2_finish_store(job, "cancelled", "controller_cancelled", items,
                             1, out);
    json_object_put(items);
    return rc;
}

static int apd_v2_reconcile(
    SSL *ssl, const struct apd_enrollment_metadata *metadata,
    const char *session_epoch, int *finish_handled)
{
    struct apd_radio_job_pending_reconcile pending;
    struct json_object *request = NULL;
    struct json_object *response = NULL;
    struct json_object *result = NULL;
    const char *controller_state = NULL;
    const char *finish_id = NULL;
    int cancel_requested = 0;
    struct apd_radio_job_journal_entry rebound;
    int64_t sequence = 0;
    int journal_result;
    int rc = -1;

    if (!finish_handled)
        return -1;
    *finish_handled = 0;
    memset(&pending, 0, sizeof(pending));
    journal_result = apd_radio_job_pending_reconcile_get(metadata->ap_id,
                                                          &pending);
    if (journal_result == APD_RADIO_JOB_JOURNAL_NOT_FOUND)
        return 0;
    if (journal_result != APD_RADIO_JOB_JOURNAL_OK)
        return -1;
    result = json_tokener_parse(pending.result_json ? pending.result_json : "[]");
    request = apd_message_new("radio_job_reconcile");
    if (!result || !json_object_is_type(result, json_type_array) || !request ||
        apd_v2_request_base(request, metadata, session_epoch, &sequence) != 0 ||
        apd_v2_assignment_add(request, &pending.entry.assignment) != 0 ||
        apd_json_add_string(request, "radio_id",
                            pending.entry.assignment.radio_id) != 0 ||
        apd_json_add_string(request, "mode", pending.entry.assignment.mode) != 0 ||
        apd_json_add_string(request, "state", pending.entry.state) != 0 ||
        apd_json_add_string(request, "finish_id", pending.entry.finish_id) != 0 ||
        apd_json_add_string(request, "outcome", pending.entry.outcome) != 0 ||
        apd_json_add_string(request, "error_code", pending.entry.error_code) != 0 ||
        apd_json_add_int64(request, "observed_at", pending.entry.observed_at) != 0)
        goto done;
    json_object_object_add(request, "result_complete",
                           json_object_new_boolean(pending.entry.result_complete));
    json_object_object_add(request, "result", json_object_get(result));
    if (apd_v2_result_fit_wire(request) != 0 ||
        ap_control_json_object_exact(request, apd_fields_radio_job_reconcile,
            APD_ARRAY_SIZE(apd_fields_radio_job_reconcile),
            apd_fields_radio_job_reconcile,
            APD_ARRAY_SIZE(apd_fields_radio_job_reconcile)) != AP_CONTROL_WIRE_OK ||
        ap_control_ssl_write_json(ssl, AP_CONTROL_IO_TIMEOUT_MS, request) !=
            AP_CONTROL_WIRE_OK)
        goto done;
    if (pending.entry.finish_id[0]) {
        if (apd_message_receive(ssl, apd_fields_radio_job_finish_ack,
                APD_ARRAY_SIZE(apd_fields_radio_job_finish_ack),
                "radio_job_finish_ack", &response) != 0 ||
            apd_v2_response_identity(response, metadata, session_epoch,
                                     sequence) != 0 ||
            !apd_v2_assignment_matches(response, &pending.entry.assignment) ||
            ap_control_json_get_string(response, "finish_id", &finish_id,
                36, 36) != AP_CONTROL_WIRE_OK ||
            strcmp(finish_id, pending.entry.finish_id) != 0 ||
            ap_control_json_get_string(response, "controller_state",
                &controller_state, 6, 31) != AP_CONTROL_WIRE_OK ||
            (strcmp(controller_state, "completed") &&
             strcmp(controller_state, "failed") &&
             strcmp(controller_state, "cancelled")))
            goto done;
        memset(&rebound, 0, sizeof(rebound));
        journal_result = apd_radio_job_session_rebind(
            &pending.entry.assignment, session_epoch, apd_now_s(), &rebound);
        if (journal_result != APD_RADIO_JOB_JOURNAL_OK &&
            journal_result != APD_RADIO_JOB_JOURNAL_IDEMPOTENT)
            goto done;
        journal_result = apd_radio_job_finish_ack(&rebound.assignment,
            rebound.finish_id, apd_now_s(), NULL);
        rc = journal_result == APD_RADIO_JOB_JOURNAL_OK ||
             journal_result == APD_RADIO_JOB_JOURNAL_IDEMPOTENT ? 0 : -1;
        if (rc == 0)
            *finish_handled = 1;
        goto done;
    }
    if (apd_message_receive(ssl, apd_fields_radio_job_reconcile_ack,
            APD_ARRAY_SIZE(apd_fields_radio_job_reconcile_ack),
            "radio_job_reconcile_ack", &response) != 0 ||
        apd_v2_response_identity(response, metadata, session_epoch, sequence) != 0 ||
        !apd_v2_assignment_matches(response, &pending.entry.assignment) ||
        ap_control_json_get_string(response, "controller_state",
                                   &controller_state, 6, 31) !=
            AP_CONTROL_WIRE_OK ||
        apd_v2_boolean(response, "cancel_requested", &cancel_requested) != 0)
        goto done;
    memset(&rebound, 0, sizeof(rebound));
    journal_result = apd_radio_job_session_rebind(&pending.entry.assignment,
                                                   session_epoch, apd_now_s(),
                                                   &rebound);
    if (journal_result != APD_RADIO_JOB_JOURNAL_OK &&
        journal_result != APD_RADIO_JOB_JOURNAL_IDEMPOTENT)
        goto done;
    if (cancel_requested && !rebound.finish_id[0]) {
        struct apd_radio_job_journal_entry terminal;
        journal_result = apd_radio_job_cancel_requested(
            &rebound.assignment, apd_now_s(), NULL);
        if ((journal_result == APD_RADIO_JOB_JOURNAL_OK ||
             journal_result == APD_RADIO_JOB_JOURNAL_IDEMPOTENT) &&
            apd_v2_cancel_finish(&rebound.assignment, &terminal) == 0)
            rc = apd_v2_finish_send(ssl, metadata, session_epoch, &terminal,
                                    "[]");
        if (rc == 0)
            *finish_handled = 1;
    } else if (!strcmp(controller_state, "leased") ||
               !strcmp(controller_state, "running")) {
        rc = 0;
    }
done:
    json_object_put(result);
    json_object_put(request);
    json_object_put(response);
    apd_radio_job_pending_reconcile_free(&pending);
    return rc;
}

static int apd_v2_poll(SSL *ssl,
                       const struct apd_enrollment_metadata *metadata,
                       const char *session_epoch);

static int apd_config_executor_enabled(void)
{
    return apd_config_executor_available_default();
}

static int apd_config_wire_step(
    SSL *ssl, const struct apd_enrollment_metadata *metadata,
    const char *session_epoch);
static void apd_config_paths_default(struct apd_config_paths *paths);

static int apd_v2_jobs_step(
    SSL *ssl, const struct apd_enrollment_metadata *metadata,
    const char *session_epoch)
{
    int finish_handled = 0;

    if (apd_v2_reconcile(ssl, metadata, session_epoch, &finish_handled) != 0)
        return -1;
    if (!finish_handled &&
        apd_v2_pending_finish_replay(ssl, metadata, session_epoch) != 0)
        return -1;
    if (apd_v2_poll(ssl, metadata, session_epoch) != 0)
        return -1;
    return 0;
}

static int apd_v2_accept_or_start(
    SSL *ssl, const struct apd_enrollment_metadata *metadata,
    const char *session_epoch, const char *kind, const char *ack_kind,
    const char *const *fields, size_t field_count,
    const char *const *ack_fields, size_t ack_field_count,
    const struct apd_radio_job_assignment *job, int *cancel_requested)
{
    struct json_object *request = apd_message_new(kind);
    struct json_object *response = NULL;
    const char *controller_state = NULL;
    int64_t sequence = 0;
    int rc = -1;

    if (!cancel_requested || !request ||
        apd_v2_request_base(request, metadata, session_epoch, &sequence) != 0 ||
        apd_v2_assignment_add(request, job) != 0 ||
        ap_control_json_object_exact(request, fields, field_count, fields,
                                     field_count) != AP_CONTROL_WIRE_OK ||
        ap_control_ssl_write_json(ssl, AP_CONTROL_IO_TIMEOUT_MS, request) !=
            AP_CONTROL_WIRE_OK ||
        apd_message_receive(ssl, ack_fields, ack_field_count, ack_kind,
                            &response) != 0 ||
        apd_v2_response_identity(response, metadata, session_epoch, sequence) != 0 ||
        !apd_v2_assignment_matches(response, job) ||
        ap_control_json_get_string(response, "controller_state",
                                   &controller_state, 6, 31) !=
            AP_CONTROL_WIRE_OK ||
        apd_v2_boolean(response, "cancel_requested", cancel_requested) != 0)
        goto done;
    rc = 0;
done:
    json_object_put(request);
    json_object_put(response);
    return rc;
}

static int apd_v2_execute(
    SSL *ssl, const struct apd_enrollment_metadata *metadata,
    const char *session_epoch, const struct apd_radio_job_assignment *job)
{
    struct apd_radio_job_journal_entry terminal;
    struct json_object *backend_result = NULL;
    struct json_object *items = NULL;
    struct json_object *value = NULL;
    const char *error_code = "";
    const char *payload = "[]";
    int backend_rc = -1;
    int complete = 0;
    int truncated = 0;
    int items_owned = 0;

    if (!strcmp(job->mode, "neighbor"))
        backend_rc = apd_backend_neighbor_scan(job->radio_id, &backend_result);
    else if (!strcmp(job->mode, "survey"))
        backend_rc = apd_backend_survey_scan(job->radio_id, &backend_result);
    else {
        backend_result = json_object_new_object();
        json_object_object_add(backend_result, "items", json_object_new_array());
        json_object_object_add(backend_result, "complete",
                               json_object_new_boolean(0));
        json_object_object_add(backend_result, "truncated",
                               json_object_new_boolean(0));
        json_object_object_add(backend_result, "error_code",
                               json_object_new_string("radio_job_mode_unsupported"));
    }
    if (!backend_result || !json_object_is_type(backend_result, json_type_object) ||
        !json_object_object_get_ex(backend_result, "items", &items) || !items ||
        !json_object_is_type(items, json_type_array))
        goto failed;
    if (json_object_object_get_ex(backend_result, "complete", &value) && value &&
        json_object_is_type(value, json_type_boolean))
        complete = json_object_get_boolean(value) ? 1 : 0;
    value = NULL;
    if (json_object_object_get_ex(backend_result, "truncated", &value) && value &&
        json_object_is_type(value, json_type_boolean))
        truncated = json_object_get_boolean(value) ? 1 : 0;
    value = NULL;
    if (json_object_object_get_ex(backend_result, "error_code", &value) && value &&
        json_object_is_type(value, json_type_string))
        error_code = json_object_get_string(value);
    if (backend_rc == 0) {
        if (apd_v2_finish_store(job, "completed", "", items,
                                complete && !truncated, &terminal) != 0)
            goto done;
    } else {
failed:
        if (!items || !json_object_is_type(items, json_type_array)) {
            items = json_object_new_array();
            items_owned = 1;
        }
        if (!error_code || !error_code[0])
            error_code = !strcmp(job->mode, "survey") ?
                "survey_scan_execution_failed" :
                "neighbor_scan_execution_failed";
        if (apd_v2_finish_store(job, "failed", error_code, items, 0,
                                &terminal) != 0)
            goto done;
    }
    payload = json_object_to_json_string_ext(items, JSON_C_TO_STRING_PLAIN);
    backend_rc = apd_v2_finish_send(ssl, metadata, session_epoch, &terminal,
                                    payload);
done:
    if (items_owned)
        json_object_put(items);
    json_object_put(backend_result);
    return backend_rc;
}

static int apd_v2_poll(SSL *ssl,
                       const struct apd_enrollment_metadata *metadata,
                       const char *session_epoch)
{
    struct json_object *request = apd_message_new("radio_job_poll");
    struct json_object *response = NULL;
    struct apd_radio_job_assignment job;
    struct apd_radio_job_journal_entry terminal;
    const char *kind = NULL;
    int64_t sequence = 0;
    int cancel_requested = 0;
    int journal_result;
    int rc = -1;

    if (!request ||
        apd_v2_request_base(request, metadata, session_epoch, &sequence) != 0 ||
        ap_control_json_object_exact(request, apd_fields_radio_job_poll,
            APD_ARRAY_SIZE(apd_fields_radio_job_poll), apd_fields_radio_job_poll,
            APD_ARRAY_SIZE(apd_fields_radio_job_poll)) != AP_CONTROL_WIRE_OK ||
        ap_control_ssl_write_json(ssl, AP_CONTROL_IO_TIMEOUT_MS, request) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_ssl_read_json(ssl, AP_CONTROL_IO_TIMEOUT_MS, &response) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(response, "kind", &kind, 1, 64) !=
            AP_CONTROL_WIRE_OK)
        goto done;
    if (!strcmp(kind, "radio_job_idle")) {
        if (apd_message_expect(response, apd_fields_radio_job_idle,
                APD_ARRAY_SIZE(apd_fields_radio_job_idle), kind) != 0 ||
            apd_v2_response_identity(response, metadata, session_epoch,
                                     sequence) != 0)
            goto done;
        rc = 0;
        goto done;
    }
    if (strcmp(kind, "radio_job_offer") != 0 ||
        apd_message_expect(response, apd_fields_radio_job_offer,
            APD_ARRAY_SIZE(apd_fields_radio_job_offer), kind) != 0 ||
        apd_v2_response_identity(response, metadata, session_epoch, sequence) != 0 ||
        apd_v2_assignment_parse(response, metadata, session_epoch, &job) != 0)
        goto done;
    journal_result = apd_radio_job_offer_store(&job, apd_now_s(), NULL);
    if (journal_result != APD_RADIO_JOB_JOURNAL_OK &&
        journal_result != APD_RADIO_JOB_JOURNAL_IDEMPOTENT)
        goto done;
    if (apd_v2_accept_or_start(ssl, metadata, session_epoch, "radio_job_accept",
            "radio_job_accept_ack", apd_fields_radio_job_accept,
            APD_ARRAY_SIZE(apd_fields_radio_job_accept),
            apd_fields_radio_job_accept_ack,
            APD_ARRAY_SIZE(apd_fields_radio_job_accept_ack), &job,
            &cancel_requested) != 0)
        goto done;
    if (cancel_requested) {
        journal_result = apd_radio_job_cancel_requested(&job, apd_now_s(), NULL);
        if ((journal_result != APD_RADIO_JOB_JOURNAL_OK &&
             journal_result != APD_RADIO_JOB_JOURNAL_IDEMPOTENT) ||
            apd_v2_cancel_finish(&job, &terminal) != 0)
            goto done;
        rc = apd_v2_finish_send(ssl, metadata, session_epoch, &terminal, "[]");
        goto done;
    }
    journal_result = apd_radio_job_mark_running(&job, apd_now_s(), NULL);
    if (journal_result != APD_RADIO_JOB_JOURNAL_OK &&
        journal_result != APD_RADIO_JOB_JOURNAL_IDEMPOTENT)
        goto done;
    if (apd_v2_accept_or_start(ssl, metadata, session_epoch, "radio_job_start",
            "radio_job_start_ack", apd_fields_radio_job_start,
            APD_ARRAY_SIZE(apd_fields_radio_job_start),
            apd_fields_radio_job_start_ack,
            APD_ARRAY_SIZE(apd_fields_radio_job_start_ack), &job,
            &cancel_requested) != 0)
        goto done;
    if (cancel_requested) {
        journal_result = apd_radio_job_cancel_requested(&job, apd_now_s(), NULL);
        if ((journal_result != APD_RADIO_JOB_JOURNAL_OK &&
             journal_result != APD_RADIO_JOB_JOURNAL_IDEMPOTENT) ||
            apd_v2_cancel_finish(&job, &terminal) != 0)
            goto done;
        rc = apd_v2_finish_send(ssl, metadata, session_epoch, &terminal, "[]");
        goto done;
    }
    rc = apd_v2_execute(ssl, metadata, session_epoch, &job);
done:
    json_object_put(request);
    json_object_put(response);
    return rc;
}

/* ---- Phase W2c config job wire client (dormant, see the gate above).
 * Mirrors the radio job poll/offer/accept lease and then drives the
 * config executor stage -> applying(previous durable) -> apply ->
 * readback -> finish sequence.  A readback mismatch (or any executor
 * failure) rolls back and reports outcome=rolled_back — never
 * applied=true. ---- */

static const char *const apd_fields_config_job_poll[] = {
    "protocol", "kind", "ap_id", "session_epoch", "sequence"
};
static const char *const apd_fields_config_job_identity[] = {
    "protocol", "kind", "ap_id", "session_epoch", "sequence", "job_id",
    "attempt_id", "dispatch_generation", "request_digest"
};
static const char *const apd_fields_config_job_finish[] = {
    "protocol", "kind", "ap_id", "session_epoch", "sequence", "job_id",
    "attempt_id", "dispatch_generation", "request_digest", "finish_id",
    "outcome", "error_code", "readback"
};
static const char *const apd_fields_config_job_idle[] = {
    "protocol", "kind", "ap_id", "session_epoch", "reply_to"
};
static const char *const apd_fields_config_job_offer[] = {
    "protocol", "kind", "ap_id", "session_epoch", "reply_to", "job_id",
    "attempt_id", "dispatch_generation", "request_digest",
    "candidate_digest", "candidate", "controller_state"
};
static const char *const apd_fields_config_job_ack[] = {
    "protocol", "kind", "ap_id", "session_epoch", "reply_to", "job_id",
    "attempt_id", "dispatch_generation", "request_digest",
    "controller_state"
};
static const char *const apd_fields_config_job_finish_ack[] = {
    "protocol", "kind", "ap_id", "session_epoch", "reply_to", "job_id",
    "attempt_id", "dispatch_generation", "request_digest", "finish_id",
    "controller_state"
};

static void apd_config_paths_default(struct apd_config_paths *paths)
{
    paths->uci = APD_CONFIG_UCI_PATH;
    paths->wifi = APD_CONFIG_WIFI_PATH;
    paths->config_dir = APD_CONFIG_CONFIG_DIR;
    paths->staging_dir = APD_CONFIG_STAGING_DIR;
}

int apd_config_restart_recover_default(int *recovered)
{
    struct apd_config_paths paths;

    apd_config_paths_default(&paths);
    return apd_config_jobs_restart_recover(&paths, apd_now_s(),
                                           apd_v2_finish_id, recovered);
}

static int apd_config_assignment_parse(
    struct json_object *response,
    const struct apd_enrollment_metadata *metadata, const char *session_epoch,
    struct apd_config_job_assignment *job, char **candidate_out)
{
    const char *job_id = NULL;
    const char *attempt_id = NULL;
    const char *request_digest = NULL;
    const char *candidate_digest = NULL;
    const char *candidate = NULL;
    int64_t dispatch_generation = 0;

    memset(job, 0, sizeof(*job));
    *candidate_out = NULL;
    if (ap_control_json_get_string(response, "job_id", &job_id, 36, 36) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(response, "attempt_id", &attempt_id, 36,
            36) != AP_CONTROL_WIRE_OK ||
        ap_control_json_get_int64(response, "dispatch_generation", 1,
            INT64_MAX, &dispatch_generation) != AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(response, "request_digest",
            &request_digest, APD_CONFIG_JOB_DIGEST_LEN,
            APD_CONFIG_JOB_DIGEST_LEN) != AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(response, "candidate_digest",
            &candidate_digest, APD_CONFIG_JOB_DIGEST_LEN,
            APD_CONFIG_JOB_DIGEST_LEN) != AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(response, "candidate", &candidate, 1,
            APD_CONFIG_JOB_CANDIDATE_MAX_BYTES) != AP_CONTROL_WIRE_OK)
        return -1;
    snprintf(job->job_id, sizeof(job->job_id), "%s", job_id);
    snprintf(job->attempt_id, sizeof(job->attempt_id), "%s", attempt_id);
    job->dispatch_generation = dispatch_generation;
    snprintf(job->request_digest, sizeof(job->request_digest), "%s",
             request_digest);
    snprintf(job->candidate_digest, sizeof(job->candidate_digest), "%s",
             candidate_digest);
    snprintf(job->ap_id, sizeof(job->ap_id), "%s", metadata->ap_id);
    snprintf(job->session_epoch, sizeof(job->session_epoch), "%s",
             session_epoch);
    *candidate_out = strdup(candidate);
    return *candidate_out ? 0 : -1;
}

static int apd_config_assignment_add(struct json_object *request,
                                     const struct apd_config_job_assignment *job)
{
    return apd_json_add_string(request, "job_id", job->job_id) == 0 &&
           apd_json_add_string(request, "attempt_id", job->attempt_id) == 0 &&
           apd_json_add_int64(request, "dispatch_generation",
                              job->dispatch_generation) == 0 &&
           apd_json_add_string(request, "request_digest",
                               job->request_digest) == 0 ? 0 : -1;
}

static int apd_config_assignment_matches(
    struct json_object *response,
    const struct apd_config_job_assignment *job)
{
    const char *value = NULL;
    int64_t generation = 0;

    return ap_control_json_get_string(response, "job_id", &value, 36, 36) ==
               AP_CONTROL_WIRE_OK && !strcmp(value, job->job_id) &&
           ap_control_json_get_string(response, "attempt_id", &value, 36,
               36) == AP_CONTROL_WIRE_OK && !strcmp(value, job->attempt_id) &&
           ap_control_json_get_int64(response, "dispatch_generation", 1,
               INT64_MAX, &generation) == AP_CONTROL_WIRE_OK &&
           generation == job->dispatch_generation &&
           ap_control_json_get_string(response, "request_digest", &value,
               APD_CONFIG_JOB_DIGEST_LEN, APD_CONFIG_JOB_DIGEST_LEN) ==
               AP_CONTROL_WIRE_OK && !strcmp(value, job->request_digest);
}

static int apd_config_accept(
    SSL *ssl, const struct apd_enrollment_metadata *metadata,
    const char *session_epoch, const struct apd_config_job_assignment *job)
{
    struct json_object *request = apd_message_new("config_job_accept");
    struct json_object *response = NULL;
    const char *controller_state = NULL;
    int64_t sequence = 0;
    int rc = -1;

    if (!request ||
        apd_v2_request_base(request, metadata, session_epoch, &sequence) != 0 ||
        apd_config_assignment_add(request, job) != 0 ||
        ap_control_json_object_exact(request, apd_fields_config_job_identity,
            APD_ARRAY_SIZE(apd_fields_config_job_identity),
            apd_fields_config_job_identity,
            APD_ARRAY_SIZE(apd_fields_config_job_identity)) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_ssl_write_json(ssl, AP_CONTROL_IO_TIMEOUT_MS, request) !=
            AP_CONTROL_WIRE_OK ||
        apd_message_receive(ssl, apd_fields_config_job_ack,
            APD_ARRAY_SIZE(apd_fields_config_job_ack),
            "config_job_accept_ack", &response) != 0 ||
        apd_v2_response_identity(response, metadata, session_epoch,
                                 sequence) != 0 ||
        !apd_config_assignment_matches(response, job) ||
        ap_control_json_get_string(response, "controller_state",
            &controller_state, 6, 31) != AP_CONTROL_WIRE_OK ||
        strcmp(controller_state, "running") != 0)
        goto done;
    rc = 0;
done:
    json_object_put(request);
    json_object_put(response);
    return rc;
}

static int apd_config_finish_send(
    SSL *ssl, const struct apd_enrollment_metadata *metadata,
    const char *session_epoch, const struct apd_config_job_assignment *job,
    const char *finish_id, const char *outcome, const char *error_code,
    const char *readback)
{
    struct json_object *request = apd_message_new("config_job_finish");
    struct json_object *response = NULL;
    const char *value = NULL;
    int64_t sequence = 0;
    int rc = -1;

    if (!request ||
        apd_v2_request_base(request, metadata, session_epoch, &sequence) != 0 ||
        apd_config_assignment_add(request, job) != 0 ||
        apd_json_add_string(request, "finish_id", finish_id) != 0 ||
        apd_json_add_string(request, "outcome", outcome) != 0 ||
        apd_json_add_string(request, "error_code",
                            error_code ? error_code : "") != 0 ||
        apd_json_add_string(request, "readback",
                            readback ? readback : "") != 0 ||
        ap_control_json_object_exact(request, apd_fields_config_job_finish,
            APD_ARRAY_SIZE(apd_fields_config_job_finish),
            apd_fields_config_job_finish,
            APD_ARRAY_SIZE(apd_fields_config_job_finish)) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_ssl_write_json(ssl, AP_CONTROL_IO_TIMEOUT_MS, request) !=
            AP_CONTROL_WIRE_OK ||
        apd_message_receive(ssl, apd_fields_config_job_finish_ack,
            APD_ARRAY_SIZE(apd_fields_config_job_finish_ack),
            "config_job_finish_ack", &response) != 0 ||
        apd_v2_response_identity(response, metadata, session_epoch,
                                 sequence) != 0 ||
        !apd_config_assignment_matches(response, job) ||
        ap_control_json_get_string(response, "finish_id", &value, 36, 36) !=
            AP_CONTROL_WIRE_OK || strcmp(value, finish_id) != 0)
        goto done;
    rc = 0;
done:
    json_object_put(request);
    json_object_put(response);
    return rc;
}

static int apd_config_pending_finish_replay(
    SSL *ssl, const struct apd_enrollment_metadata *metadata,
    const char *session_epoch)
{
    struct apd_config_job_pending_reconcile pending;
    struct apd_config_job_journal_entry rebound;
    int result;
    int rc = -1;

    memset(&pending, 0, sizeof(pending));
    memset(&rebound, 0, sizeof(rebound));
    result = apd_config_job_pending_reconcile_get(metadata->ap_id, &pending);
    if (result == APD_CONFIG_JOB_JOURNAL_NOT_FOUND)
        return 0;
    if (result != APD_CONFIG_JOB_JOURNAL_OK)
        return -1;
    result = apd_config_job_session_rebind(&pending.entry.assignment,
                                           session_epoch, apd_now_s(),
                                           &rebound);
    if (result != APD_CONFIG_JOB_JOURNAL_OK &&
        result != APD_CONFIG_JOB_JOURNAL_IDEMPOTENT)
        goto done;
    if (apd_config_finish_send(ssl, metadata, session_epoch,
            &rebound.assignment, rebound.finish_id, rebound.outcome,
            rebound.error_code, pending.readback_json) != 0)
        goto done;
    result = apd_config_job_finish_ack(&rebound.assignment,
        rebound.finish_id, apd_now_s(), &rebound);
    if (result != APD_CONFIG_JOB_JOURNAL_OK &&
        result != APD_CONFIG_JOB_JOURNAL_IDEMPOTENT)
        goto done;
    rc = 0;
done:
    apd_config_job_pending_reconcile_free(&pending);
    return rc;
}

/* Execute the leased candidate through the durable state machine.  Any
 * failure after 'applying' rolls back and reports rolled_back; readback
 * mismatch is treated the same.  The finish outcome is recorded in the
 * config job journal before the wire finish so a crash mid-finish
 * replays it. */
static int apd_config_execute(
    SSL *ssl, const struct apd_enrollment_metadata *metadata,
    const char *session_epoch, const struct apd_config_job_assignment *job,
    const char *candidate_json)
{
    struct apd_config_paths paths;
    struct json_object *candidate = json_tokener_parse(candidate_json);
    struct json_object *result = NULL;
    struct apd_config_job_finish finish;
    struct apd_config_job_journal_entry entry;
    const char *outcome = "failed";
    const char *error_code = "";
    char *previous_json = NULL;
    char *readback_json = NULL;
    char finish_id[APD_RADIO_JOB_UUID_LEN + 1];
    int rc = -1;

    apd_config_paths_default(&paths);
    memset(&finish, 0, sizeof(finish));
    if (!candidate) {
        error_code = "candidate_unparseable";
        goto finish;
    }
    /* stage into the private candidate directory. */
    if (apd_config_stage(&paths, candidate, &result) != 0) {
        error_code = "stage_failed";
        json_object_put(result);
        result = NULL;
        goto finish;
    }
    json_object_put(result);
    result = NULL;
    /* Capture is read-only. Persist its rollback reference before the
     * first live UCI mutation. */
    if (apd_config_capture_previous(&paths, candidate, &result) != 0) {
        error_code = "previous_capture_failed";
        json_object_put(result);
        result = NULL;
        goto finish;
    }
    {
        struct json_object *previous = NULL;

        if (json_object_object_get_ex(result, "previous", &previous))
            previous_json = strdup(json_object_to_json_string_ext(
                previous, JSON_C_TO_STRING_PLAIN));
    }
    json_object_put(result);
    result = NULL;
    if (!previous_json ||
        apd_config_job_mark_applying(job, previous_json, apd_now_s(),
                                     &entry) < 0) {
        error_code = "journal_applying_failed";
        goto finish;
    }
    {
        struct json_object *previous = json_tokener_parse(previous_json);
        int apply_rc = previous ?
            apd_config_apply_prepared(&paths, candidate, previous, &result) :
            -1;

        json_object_put(previous);
        if (apply_rc != 0) {
            struct json_object *rolled = NULL;

            outcome = "rolled_back";
            error_code = "apply_failed";
            if (result &&
                json_object_object_get_ex(result, "rolled_back", &rolled) &&
                json_object_get_boolean(rolled))
                error_code = "apply_failed_rolled_back";
            json_object_put(result);
            result = NULL;
            goto finish;
        }
    }
    json_object_put(result);
    result = NULL;
    if (apd_config_job_mark_applied(job, apd_now_s(), &entry) < 0) {
        error_code = "journal_applied_failed";
        goto rollback;
    }
    /* readback: mismatch -> rollback -> rolled_back. */
    if (apd_config_readback(&paths, candidate, &result) != 0) {
        error_code = "readback_failed";
        json_object_put(result);
        result = NULL;
        goto rollback;
    }
    {
        struct json_object *match = NULL;

        readback_json = strdup(json_object_to_json_string_ext(
            result, JSON_C_TO_STRING_PLAIN));
        if (!json_object_object_get_ex(result, "match", &match) ||
            !json_object_get_boolean(match)) {
            json_object_put(result);
            result = NULL;
            error_code = "readback_mismatch";
            goto rollback;
        }
    }
    json_object_put(result);
    result = NULL;
    outcome = "applied";
    error_code = "";
    goto finish;
rollback:
    {
        struct json_object *previous = previous_json ?
            json_tokener_parse(previous_json) : NULL;
        struct json_object *rollback_result = NULL;

        outcome = "rolled_back";
        if (previous)
            apd_config_rollback(&paths, previous, &rollback_result);
        json_object_put(previous);
        json_object_put(rollback_result);
    }
finish:
    if (apd_v2_finish_id(finish_id) != 0)
        goto done;
    finish.assignment = *job;
    snprintf(finish.finish_id, sizeof(finish.finish_id), "%s", finish_id);
    snprintf(finish.outcome, sizeof(finish.outcome), "%s", outcome);
    snprintf(finish.error_code, sizeof(finish.error_code), "%s", error_code);
    finish.observed_at = apd_now_s();
    finish.readback_json = readback_json;
    if (apd_config_job_finish_store(&finish, apd_now_s(), &entry) < 0)
        goto done;
    rc = apd_config_finish_send(ssl, metadata, session_epoch, job, finish_id,
                                outcome, error_code, readback_json);
    if (rc == 0)
        apd_config_job_finish_ack(job, finish_id, apd_now_s(), &entry);
done:
    json_object_put(candidate);
    free(previous_json);
    free(readback_json);
    return rc;
}

static int apd_config_wire_step(
    SSL *ssl, const struct apd_enrollment_metadata *metadata,
    const char *session_epoch)
{
    struct json_object *request = apd_message_new("config_job_poll");
    struct json_object *response = NULL;
    struct apd_config_job_assignment job;
    char *candidate = NULL;
    const char *kind = NULL;
    int64_t sequence = 0;
    int rc = -1;

    if (!request ||
        apd_v2_request_base(request, metadata, session_epoch, &sequence) != 0 ||
        ap_control_json_object_exact(request, apd_fields_config_job_poll,
            APD_ARRAY_SIZE(apd_fields_config_job_poll),
            apd_fields_config_job_poll,
            APD_ARRAY_SIZE(apd_fields_config_job_poll)) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_ssl_write_json(ssl, AP_CONTROL_IO_TIMEOUT_MS, request) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_ssl_read_json(ssl, AP_CONTROL_IO_TIMEOUT_MS,
                                 &response) != AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(response, "kind", &kind, 1, 64) !=
            AP_CONTROL_WIRE_OK)
        goto done;
    if (!strcmp(kind, "config_job_idle")) {
        rc = apd_message_expect(response, apd_fields_config_job_idle,
                APD_ARRAY_SIZE(apd_fields_config_job_idle), kind) == 0 &&
             apd_v2_response_identity(response, metadata, session_epoch,
                                      sequence) == 0 ? 0 : -1;
        goto done;
    }
    if (strcmp(kind, "config_job_offer") != 0 ||
        apd_message_expect(response, apd_fields_config_job_offer,
            APD_ARRAY_SIZE(apd_fields_config_job_offer), kind) != 0 ||
        apd_v2_response_identity(response, metadata, session_epoch,
                                 sequence) != 0 ||
        apd_config_assignment_parse(response, metadata, session_epoch, &job,
                                    &candidate) != 0)
        goto done;
    if (apd_config_job_offer_store(&job, candidate, apd_now_s(), NULL) < 0 ||
        apd_config_job_mark_staged(&job, apd_now_s(), NULL) < 0 ||
        apd_config_accept(ssl, metadata, session_epoch, &job) != 0)
        goto done;
    rc = apd_config_execute(ssl, metadata, session_epoch, &job, candidate);
done:
    json_object_put(request);
    json_object_put(response);
    free(candidate);
    return rc;
}

static int apd_session_run(const struct apd_enrollment_metadata *metadata)
{
    struct apd_transport_endpoint endpoint;
    struct apd_tls_connection connection;
    struct json_object *request = NULL;
    struct json_object *response = NULL;
    const char *text = NULL;
    const char *session_epoch_text = NULL;
    char session_epoch[65] = {0};
    int ready = 0;
    int rc = -1;
    struct apd_telemetry_gate telemetry_gate;
    struct ap_control_capabilities peer_capabilities = {0};
    struct ap_control_capabilities local_capabilities = {0};

    memset(&connection, 0, sizeof(connection));
    connection.fd = -1;
    memset(&telemetry_gate, 0, sizeof(telemetry_gate));
    apd_transport_set_reason("session_connecting");
    if (!metadata || apd_transport_endpoint_get(&endpoint) != 0 ||
        apd_tls_open(&endpoint, 1, 1, &connection) != 0)
        goto done;
    g_apd_wire_protocol = connection.protocol_version == 3 ?
        AP_CONTROL_PROTOCOL_V3 :
        (connection.protocol_version == 2 ? APD_TRANSPORT_PROTOCOL_V2 : APD_TRANSPORT_PROTOCOL_V1);
    if (connection.protocol_version == 3) {
        local_capabilities.config_executor = apd_config_executor_enabled();
        local_capabilities.validate = local_capabilities.config_executor;
        local_capabilities.stage = local_capabilities.config_executor;
        local_capabilities.apply = local_capabilities.config_executor;
        local_capabilities.readback = local_capabilities.config_executor;
        local_capabilities.rollback = local_capabilities.config_executor;
    }
    if (!(request = apd_identity_message_new("session_hello", metadata, 0)) ||
        (connection.protocol_version == 3 &&
         ap_control_capabilities_add(request, &local_capabilities) != AP_CONTROL_WIRE_OK) ||
        ap_control_json_object_exact(request,
                connection.protocol_version == 3 ? apd_fields_session_hello_v3 : apd_fields_session_hello,
                connection.protocol_version == 3 ? APD_ARRAY_SIZE(apd_fields_session_hello_v3) : APD_ARRAY_SIZE(apd_fields_session_hello),
                connection.protocol_version == 3 ? apd_fields_session_hello_v3 : apd_fields_session_hello,
                connection.protocol_version == 3 ? APD_ARRAY_SIZE(apd_fields_session_hello_v3) : APD_ARRAY_SIZE(apd_fields_session_hello)) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_ssl_write_json(connection.ssl, AP_CONTROL_IO_TIMEOUT_MS,
                                  request) != AP_CONTROL_WIRE_OK)
        goto done;
    json_object_put(request);
    request = NULL;
    if (apd_message_receive(connection.ssl,
            connection.protocol_version == 3 ? apd_fields_session_ready_v3 : apd_fields_session_ready,
            connection.protocol_version == 3 ? APD_ARRAY_SIZE(apd_fields_session_ready_v3) : APD_ARRAY_SIZE(apd_fields_session_ready), "session_ready",
            &response) != 0 ||
        ap_control_json_get_string(response, "controller_id", &text, 36, 36) !=
            AP_CONTROL_WIRE_OK || strcmp(text, metadata->controller_id) != 0 ||
        ap_control_json_get_string(response, "certificate_id", &text, 36, 36) !=
            AP_CONTROL_WIRE_OK || strcmp(text, metadata->certificate_id) != 0 ||
        ap_control_json_get_string(response, "ap_id", &text, 36, 36) !=
            AP_CONTROL_WIRE_OK || strcmp(text, metadata->ap_id) != 0 ||
        ap_control_json_get_string(response, "session_epoch", &session_epoch_text,
                                   64, 64) != AP_CONTROL_WIRE_OK ||
        snprintf(session_epoch, sizeof(session_epoch), "%s", session_epoch_text) >=
            (int)sizeof(session_epoch))
        goto done;
    if (connection.protocol_version == 3) {
        struct json_object *capabilities = NULL;

        if (!json_object_object_get_ex(response, "capabilities", &capabilities) ||
            ap_control_capabilities_parse(capabilities, &peer_capabilities) != AP_CONTROL_WIRE_OK)
            goto done;
    }
    pthread_mutex_lock(&g_apd_transport.lock);
    g_apd_transport.write_capable =
        connection.protocol_version == 3 &&
        ap_control_capabilities_all_true(&local_capabilities) &&
        ap_control_capabilities_all_true(&peer_capabilities);
    pthread_mutex_unlock(&g_apd_transport.lock);
    json_object_put(response);
    response = NULL;
    ready = 1;
    apd_transport_set_reason("session_ready");
    if (apd_session_telemetry(connection.ssl, metadata, session_epoch,
                              &telemetry_gate, 1) < 0) {
        rc = 1;
        goto done;
    }
    if (connection.protocol_version == 2 &&
        apd_v2_jobs_step(connection.ssl, metadata, session_epoch) != 0) {
        rc = 1;
        goto done;
    }
    if (connection.protocol_version == 3 && g_apd_transport.write_capable &&
        apd_config_pending_finish_replay(connection.ssl, metadata,
                                         session_epoch) != 0) {
        rc = 1;
        goto done;
    }
    if (connection.protocol_version == 3 && g_apd_transport.write_capable &&
        apd_config_wire_step(connection.ssl, metadata, session_epoch) != 0) {
        rc = 1;
        goto done;
    }
    while (!apd_transport_stopping()) {
        if (apd_transport_wait_seconds(APD_TRANSPORT_HEARTBEAT_SECONDS) != 0)
            break;
        if (apd_session_heartbeat(connection.ssl, metadata, session_epoch) != 0) {
            rc = 1;
            goto done;
        }
        if (apd_session_telemetry(connection.ssl, metadata, session_epoch,
                                  &telemetry_gate, 0) < 0) {
            rc = 1;
            goto done;
        }
        if (connection.protocol_version == 2 &&
            apd_v2_jobs_step(connection.ssl, metadata, session_epoch) != 0) {
            rc = 1;
            goto done;
        }
        if (connection.protocol_version == 3 &&
            g_apd_transport.write_capable &&
            apd_config_wire_step(connection.ssl, metadata, session_epoch) != 0) {
            rc = 1;
            goto done;
        }
    }
    rc = apd_transport_stopping() ? 0 : (ready ? 1 : -1);
done:
    json_object_put(request);
    json_object_put(response);
    apd_tls_close(&connection);
    g_apd_wire_protocol = APD_TRANSPORT_PROTOCOL_V1;
    OPENSSL_cleanse(session_epoch, sizeof(session_epoch));
    return rc;
}

static int apd_transport_cycle(void)
{
    struct apd_bootstrap_config bootstrap;
    struct apd_enrollment_metadata metadata;
    int has_metadata;
    int has_bootstrap;
    int rc = -1;

    memset(&bootstrap, 0, sizeof(bootstrap));
    memset(&metadata, 0, sizeof(metadata));
    has_metadata = apd_credentials_validate_startup(&metadata) == 0;
    has_bootstrap = apd_credentials_bootstrap_load(&bootstrap) == 0;
    if (has_metadata && apd_transport_endpoint_set_metadata(&metadata) != 0) {
        apd_transport_set_reason("metadata_endpoint_invalid");
        goto done;
    }
    if (has_metadata && has_bootstrap &&
        !apd_transport_endpoint_consistent(&bootstrap, &metadata)) {
        apd_transport_set_reason("endpoint_binding_mismatch");
        goto done;
    }
    if (!has_metadata && has_bootstrap &&
        apd_transport_endpoint_set_bootstrap(&bootstrap) != 0) {
        apd_transport_set_reason("bootstrap_endpoint_invalid");
        goto done;
    }
    if (!has_metadata) {
        if (!has_bootstrap) {
            apd_transport_set_reason("credentials_unavailable");
            goto done;
        }
        if (apd_enrollment_run(&bootstrap, &metadata) != 0) {
            apd_transport_set_reason("enrollment_failed");
            goto done;
        }
        has_metadata = 1;
    }
    if (strcmp(metadata.state, "mtls_pending") == 0) {
        if (apd_activation_run(&metadata) != 0)
            goto done;
    }
    if (strcmp(metadata.state, "adopted") != 0) {
        apd_transport_set_reason("credentials_state_invalid");
        goto done;
    }
    /* Adopted startup reconstructs this endpoint from validated metadata. */
    if (apd_transport_endpoint_get(&(struct apd_transport_endpoint){0}) != 0) {
        apd_transport_set_reason("adopted_endpoint_unavailable");
        goto done;
    }
    rc = apd_session_run(&metadata);
    if (rc != 0)
        apd_transport_set_reason("session_disconnected");
done:
    apd_credentials_bootstrap_cleanse(&bootstrap);
    apd_credentials_metadata_cleanse(&metadata);
    return rc;
}

static void *apd_transport_worker(void *opaque)
{
    unsigned int backoff = APD_TRANSPORT_BACKOFF_MIN_SECONDS;

    (void)opaque;
    while (!apd_transport_stopping()) {
        int rc = apd_transport_cycle();

        apd_transport_set_connected(0);
        if (apd_transport_stopping())
            break;
        if (rc > 0)
            backoff = APD_TRANSPORT_BACKOFF_MIN_SECONDS;
        apd_transport_log(rc >= 0 ? "session_closed" : "connect_retry");
        if (apd_transport_wait_seconds(backoff) != 0)
            break;
        if (rc < 0 && backoff < APD_TRANSPORT_BACKOFF_MAX_SECONDS) {
            backoff *= 2;
            if (backoff > APD_TRANSPORT_BACKOFF_MAX_SECONDS)
                backoff = APD_TRANSPORT_BACKOFF_MAX_SECONDS;
        }
    }
    return NULL;
}

int apd_transport_start(void)
{
    int rc;

    pthread_mutex_lock(&g_apd_transport.lock);
    if (g_apd_transport.running) {
        pthread_mutex_unlock(&g_apd_transport.lock);
        return 0;
    }
    g_apd_transport.stop = 0;
    g_apd_transport.connected = 0;
    g_apd_transport.active_fd = -1;
    g_apd_transport.sequence = 0;
    snprintf(g_apd_transport.reason, sizeof(g_apd_transport.reason),
             "%s", "starting");
    rc = pthread_create(&g_apd_transport.thread, NULL,
                        apd_transport_worker, NULL);
    if (rc == 0)
        g_apd_transport.running = 1;
    pthread_mutex_unlock(&g_apd_transport.lock);
    return rc == 0 ? 0 : -1;
}

void apd_transport_stop(void)
{
    pthread_t thread;
    int join = 0;

    pthread_mutex_lock(&g_apd_transport.lock);
    if (g_apd_transport.running) {
        g_apd_transport.stop = 1;
        g_apd_transport.connected = 0;
        if (g_apd_transport.active_fd >= 0)
            shutdown(g_apd_transport.active_fd, SHUT_RDWR);
        pthread_cond_broadcast(&g_apd_transport.condition);
        thread = g_apd_transport.thread;
        join = 1;
    }
    pthread_mutex_unlock(&g_apd_transport.lock);
    if (join)
        pthread_join(thread, NULL);
    pthread_mutex_lock(&g_apd_transport.lock);
    if (join) {
        g_apd_transport.running = 0;
        g_apd_transport.active_fd = -1;
        snprintf(g_apd_transport.reason, sizeof(g_apd_transport.reason),
                 "%s", "stopped");
    }
    pthread_mutex_unlock(&g_apd_transport.lock);
}

int apd_transport_connected(void)
{
    int connected;

    pthread_mutex_lock(&g_apd_transport.lock);
    connected = g_apd_transport.connected;
    pthread_mutex_unlock(&g_apd_transport.lock);
    return connected;
}

int apd_transport_adopted(void)
{
    struct apd_enrollment_metadata metadata;
    int adopted;

    memset(&metadata, 0, sizeof(metadata));
    adopted = apd_credentials_validate_startup(&metadata) == 0 &&
        strcmp(metadata.state, "adopted") == 0;
    apd_credentials_metadata_cleanse(&metadata);
    return adopted;
}

const char *apd_transport_reason(void)
{
    pthread_mutex_lock(&g_apd_transport.lock);
    snprintf(g_apd_transport_reason_copy,
             sizeof(g_apd_transport_reason_copy), "%s",
             g_apd_transport.reason[0] ? g_apd_transport.reason : "unknown");
    pthread_mutex_unlock(&g_apd_transport.lock);
    return g_apd_transport_reason_copy;
}

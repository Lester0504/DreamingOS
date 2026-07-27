// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef AC_TRANSPORT_TEST_STANDALONE
#include "ac_internal.h"
#endif
#include "../ap_control_wire.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <json-c/json.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define AC_TRANSPORT_PROTOCOL_V1 "ap-control.v1"
#define AC_TRANSPORT_PROTOCOL_V2 "ap-control.v2"
#define AC_TRANSPORT_BACKLOG 16
#define AC_TRANSPORT_QUEUE_MAX AC_TRANSPORT_WORKERS_MAX
#define AC_TRANSPORT_ACCEPT_BURST 16U
#define AC_TRANSPORT_ACCEPT_PER_SECOND 8U
#define AC_TRANSPORT_HEARTBEAT_IDLE_MS 45000
#define AC_TRANSPORT_REASON_MAX 128U
#define AC_TRANSPORT_URI_PREFIX "urn:dreamingwrt:ap:"

#define AC_ARRAY_SIZE(value) (sizeof(value) / sizeof((value)[0]))

static const char *const ac_fields_enrollment_hello[] = {
    "protocol", "kind", "ap_id", "key_id", "public_key", "model",
    "board_name", "model_source", "model_available", "model_reason"
};
static const char *const ac_fields_enrollment_challenge[] = {
    "protocol", "kind", "controller_id", "challenge_id", "server_nonce",
    "expires_at"
};
static const char *const ac_fields_enrollment_claim[] = {
    "protocol", "kind", "challenge_id", "server_nonce", "client_nonce",
    "enrollment_id", "token_id", "token", "ap_id", "key_id",
    "public_key", "site_id", "hardware_digest", "csr_der", "csr_sha256",
    "challenge_expires_at", "signature"
};
static const char *const ac_fields_enrollment_certificate[] = {
    "protocol", "kind", "controller_id", "enrollment_id", "certificate_id",
    "certificate_der", "certificate_fingerprint", "ca_fingerprint"
};
static const char *const ac_fields_activation_hello[] = {
    "protocol", "kind", "controller_id", "enrollment_id", "certificate_id",
    "ap_id"
};
static const char *const ac_fields_activation_challenge[] = {
    "protocol", "kind", "enrollment_id", "certificate_id", "challenge"
};
static const char *const ac_fields_activation_response[] = {
    "protocol", "kind", "enrollment_id", "certificate_id", "challenge"
};
static const char *const ac_fields_activation_complete[] = {
    "protocol", "kind", "controller_id", "enrollment_id", "certificate_id",
    "certificate_fingerprint", "adopted"
};
static const char *const ac_fields_session_hello[] = {
    "protocol", "kind", "controller_id", "certificate_id", "ap_id"
};
static const char *const ac_fields_session_ready[] = {
    "protocol", "kind", "controller_id", "certificate_id", "ap_id",
    "session_epoch"
};
static const char *const ac_fields_heartbeat[] = {
    "protocol", "kind", "ap_id", "session_epoch", "sequence", "timestamp"
};
static const char *const ac_fields_heartbeat_ack[] = {
    "protocol", "kind", "ap_id", "session_epoch", "sequence"
};
static const char *const ac_fields_telemetry_snapshot[] = {
    "protocol", "kind", "schema", "version", "ap_id", "session_epoch",
    "sequence", "observed_at", "snapshot"
};
static const char *const ac_fields_telemetry_ack[] = {
    "protocol", "kind", "ap_id", "session_epoch", "sequence", "accepted"
};
static const char *const ac_fields_radio_job_poll[] = {
    "protocol", "kind", "ap_id", "session_epoch", "sequence"
};
static const char *const ac_fields_radio_job_identity[] = {
    "protocol", "kind", "ap_id", "session_epoch", "sequence", "job_id",
    "attempt_id", "dispatch_generation", "request_digest"
};
static const char *const ac_fields_radio_job_reconcile[] = {
    "protocol", "kind", "ap_id", "session_epoch", "sequence", "job_id",
    "attempt_id", "dispatch_generation", "request_digest", "radio_id",
    "mode", "state", "finish_id", "outcome", "error_code", "observed_at",
    "result_complete", "result"
};
static const char *const ac_fields_radio_job_finish[] = {
    "protocol", "kind", "ap_id", "session_epoch", "sequence", "job_id",
    "attempt_id", "dispatch_generation", "request_digest", "finish_id",
    "outcome", "error_code", "result_complete", "result"
};
static const char *const ac_fields_radio_job_idle[] = {
    "protocol", "kind", "ap_id", "session_epoch", "reply_to"
};
static const char *const ac_fields_radio_job_offer[] = {
    "protocol", "kind", "ap_id", "session_epoch", "reply_to", "job_id",
    "attempt_id", "dispatch_generation", "request_digest", "radio_id",
    "mode", "expected_impact", "controller_state", "cancel_requested"
};
static const char *const ac_fields_radio_job_ack[] = {
    "protocol", "kind", "ap_id", "session_epoch", "reply_to", "job_id",
    "attempt_id", "dispatch_generation", "request_digest",
    "controller_state", "cancel_requested"
};
static const char *const ac_fields_radio_job_reconcile_ack[] = {
    "protocol", "kind", "ap_id", "session_epoch", "reply_to", "job_id",
    "attempt_id", "dispatch_generation", "request_digest",
    "controller_state", "cancel_requested", "result_complete", "error_code"
};
static const char *const ac_fields_radio_job_finish_ack[] = {
    "protocol", "kind", "ap_id", "session_epoch", "reply_to", "job_id",
    "attempt_id", "dispatch_generation", "request_digest", "finish_id",
    "controller_state", "cancel_requested", "result_complete", "error_code"
};
static const char *const ac_fields_radio_job_error[] = {
    "protocol", "kind", "ap_id", "session_epoch", "reply_to", "error",
    "reason"
};
/* Phase W2c config job wire: same envelope/identity discipline as the
 * radio job family; the candidate travels as a JSON string whose
 * printable-ASCII bound is enforced by the candidate contract. */
static const char *const ac_fields_config_job_poll[] = {
    "protocol", "kind", "ap_id", "session_epoch", "sequence"
};
static const char *const ac_fields_config_job_identity[] = {
    "protocol", "kind", "ap_id", "session_epoch", "sequence", "job_id",
    "attempt_id", "dispatch_generation", "request_digest"
};
static const char *const ac_fields_config_job_finish[] = {
    "protocol", "kind", "ap_id", "session_epoch", "sequence", "job_id",
    "attempt_id", "dispatch_generation", "request_digest", "finish_id",
    "outcome", "error_code", "readback"
};
static const char *const ac_fields_config_job_idle[] = {
    "protocol", "kind", "ap_id", "session_epoch", "reply_to"
};
static const char *const ac_fields_config_job_offer[] = {
    "protocol", "kind", "ap_id", "session_epoch", "reply_to", "job_id",
    "attempt_id", "dispatch_generation", "request_digest",
    "candidate_digest", "candidate", "controller_state"
};
static const char *const ac_fields_config_job_ack[] = {
    "protocol", "kind", "ap_id", "session_epoch", "reply_to", "job_id",
    "attempt_id", "dispatch_generation", "request_digest",
    "controller_state"
};
static const char *const ac_fields_config_job_finish_ack[] = {
    "protocol", "kind", "ap_id", "session_epoch", "reply_to", "job_id",
    "attempt_id", "dispatch_generation", "request_digest", "finish_id",
    "controller_state"
};
static const char *const ac_fields_wireless_snapshot[] = {
    "ok", "contract_version", "snapshot_version", "source", "backend",
    "observed_at", "complete", "stale", "reason", "wireless_present",
    "phy_count", "radio_count", "ssid_count", "station_count", "model",
    "board_name", "model_source", "model_available", "model_reason",
    "radios", "ssids", "stations", "desired", "sources", "system"
};
static const char *const ac_required_wireless_snapshot[] = {
    "ok", "contract_version", "snapshot_version", "source", "backend",
    "observed_at", "complete", "stale", "wireless_present", "phy_count",
    "radio_count", "ssid_count", "station_count", "model", "board_name",
    "model_source", "model_available", "model_reason", "radios", "ssids",
    "stations", "desired", "sources"
};
static const char *const ac_fields_error[] = {
    "protocol", "kind", "error", "reason"
};

struct ac_transport_peer {
    int certificate_present;
    char ap_id[AC_ENROLLMENT_ID_LEN + 1];
    unsigned char fingerprint[SHA256_DIGEST_LENGTH];
};

struct ac_transport_state {
    pthread_mutex_t lock;
    pthread_mutex_t pki_lock;
    pthread_t accept_thread;
    pthread_t workers[AC_TRANSPORT_WORKERS_MAX];
    int worker_started[AC_TRANSPORT_WORKERS_MAX];
    int worker_fd[AC_TRANSPORT_WORKERS_MAX];
    int queue[AC_TRANSPORT_QUEUE_MAX];
    size_t queue_head;
    size_t queue_count;
    pthread_cond_t queue_changed;
    int listen_fd;
    int running;
    int listening;
    int stopping;
    int port;
    const char *reason;
    char controller_id[AC_ENROLLMENT_ID_LEN + 1];
    SSL_CTX *ssl_context;
    struct ac_pki *pki;
};

static struct ac_transport_state g_ac_transport = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .pki_lock = PTHREAD_MUTEX_INITIALIZER,
    .queue_changed = PTHREAD_COND_INITIALIZER,
    .listen_fd = -1,
    .reason = "not_started",
};

static _Thread_local char g_ac_transport_reason_copy[AC_TRANSPORT_REASON_MAX];
static _Thread_local char
    g_ac_transport_controller_id_copy[AC_ENROLLMENT_ID_LEN + 1];
static _Thread_local const char *g_ac_wire_protocol = AC_TRANSPORT_PROTOCOL_V1;

static int64_t ac_transport_monotonic_ms(void)
{
    struct timespec value;

    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
        return -1;
    return (int64_t)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}

static void ac_transport_log(const char *event)
{
    if (event)
        fprintf(stderr, "[%s] transport event=%s\n", AC_SERVICE_NAME, event);
}

static void ac_transport_log_stage(const char *event, const char *stage)
{
    if (event && stage)
        fprintf(stderr, "[%s] transport event=%s stage=%s\n",
                AC_SERVICE_NAME, event, stage);
}

static void ac_transport_set_reason(const char *reason)
{
    pthread_mutex_lock(&g_ac_transport.lock);
    g_ac_transport.reason = reason ? reason : "transport_error";
    pthread_mutex_unlock(&g_ac_transport.lock);
}

static int ac_transport_stopping(void)
{
    int stopping;

    pthread_mutex_lock(&g_ac_transport.lock);
    stopping = g_ac_transport.stopping;
    pthread_mutex_unlock(&g_ac_transport.lock);
    return stopping;
}

static int ac_uuid_version_valid(const char *value, char version)
{
    static const size_t hyphens[] = {8, 13, 18, 23};
    size_t i;
    size_t h = 0;

    if (!value || strlen(value) != AC_ENROLLMENT_ID_LEN ||
        value[14] != version ||
        (value[19] != '8' && value[19] != '9' &&
         value[19] != 'a' && value[19] != 'b'))
        return 0;
    for (i = 0; i < AC_ENROLLMENT_ID_LEN; i++) {
        if (h < AC_ARRAY_SIZE(hyphens) && i == hyphens[h]) {
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

static int ac_uuid_valid(const char *value)
{
    return ac_uuid_version_valid(value, '4');
}

static int ac_controller_id_valid(const char *value)
{
    return ac_uuid_version_valid(value, '5');
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

static int ac_json_add_string(struct json_object *object, const char *name,
                              const char *value)
{
    struct json_object *member;

    if (!object || !name || !value || !(member = json_object_new_string(value)))
        return -1;
    json_object_object_add(object, name, member);
    return 0;
}

static int ac_json_add_int64(struct json_object *object, const char *name,
                             int64_t value)
{
    struct json_object *member;

    if (!object || !name || !(member = json_object_new_int64(value)))
        return -1;
    json_object_object_add(object, name, member);
    return 0;
}

static int ac_json_add_boolean(struct json_object *object, const char *name,
                               int value)
{
    struct json_object *member;

    if (!object || !name || !(member = json_object_new_boolean(value)))
        return -1;
    json_object_object_add(object, name, member);
    return 0;
}

static int ac_json_add_hex(struct json_object *object, const char *name,
                           const unsigned char *data, size_t length)
{
    char *encoded;
    int rc = -1;

    if ((!data && length) || length > AP_CONTROL_FRAME_MAX / 2 ||
        !(encoded = malloc(length * 2 + 1)))
        return -1;
    if (ap_control_hex_encode(data, length, encoded, length * 2 + 1) ==
            AP_CONTROL_WIRE_OK)
        rc = ac_json_add_string(object, name, encoded);
    OPENSSL_cleanse(encoded, length * 2 + 1);
    free(encoded);
    return rc;
}

static struct json_object *ac_message_new(const char *kind)
{
    struct json_object *object = json_object_new_object();

    if (!object || ac_json_add_string(object, "protocol",
                                      g_ac_wire_protocol) != 0 ||
        ac_json_add_string(object, "kind", kind) != 0) {
        json_object_put(object);
        return NULL;
    }
    return object;
}

static int ac_message_expect(struct json_object *object,
                             const char *const *fields, size_t field_count,
                             const char *kind)
{
    const char *protocol = NULL;
    const char *actual_kind = NULL;

    if (!object || !kind ||
        ap_control_json_object_exact(object, fields, field_count, fields,
                                     field_count) != AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(object, "protocol", &protocol,
                                   strlen(g_ac_wire_protocol),
                                   strlen(g_ac_wire_protocol)) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(object, "kind", &actual_kind,
                                   strlen(kind), strlen(kind)) !=
            AP_CONTROL_WIRE_OK)
        return -1;
    return strcmp(protocol, g_ac_wire_protocol) == 0 &&
           strcmp(actual_kind, kind) == 0 ? 0 : -1;
}

static int ac_message_kind(struct json_object *object, const char **kind)
{
    const char *protocol = NULL;

    if (!object || !kind ||
        ap_control_json_get_string(object, "protocol", &protocol,
                                   strlen(g_ac_wire_protocol),
                                   strlen(g_ac_wire_protocol)) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(object, "kind", kind, 1, 64) !=
            AP_CONTROL_WIRE_OK)
        return -1;
    return strcmp(protocol, g_ac_wire_protocol) == 0 ? 0 : -1;
}

static int ac_send_error(SSL *ssl, const char *error, const char *reason)
{
    struct json_object *object = ac_message_new("error");
    int rc = -1;

    if (object && ac_json_add_string(object, "error",
                                     error ? error : "request_rejected") == 0 &&
        ac_json_add_string(object, "reason",
                           reason ? reason : "request_rejected") == 0 &&
        ap_control_json_object_exact(object, ac_fields_error,
                AC_ARRAY_SIZE(ac_fields_error), ac_fields_error,
                AC_ARRAY_SIZE(ac_fields_error)) == AP_CONTROL_WIRE_OK &&
        ap_control_ssl_write_json(ssl, AP_CONTROL_IO_TIMEOUT_MS, object) ==
            AP_CONTROL_WIRE_OK)
        rc = 0;
    json_object_put(object);
    return rc;
}

static int ac_json_get_hex_exact(struct json_object *object, const char *name,
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

static int ac_json_get_hex_alloc(struct json_object *object, const char *name,
                                 size_t maximum, unsigned char **out,
                                 size_t *out_length)
{
    const char *encoded = NULL;
    unsigned char *decoded = NULL;
    size_t text_length = 0;
    size_t decoded_length = 0;

    if (!out || !out_length || maximum > AP_CONTROL_FRAME_MAX / 2 ||
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

static int ac_json_copy_string(struct json_object *object, const char *name,
                               char *out, size_t out_size,
                               size_t minimum, size_t maximum)
{
    const char *value = NULL;
    size_t length;

    if (!out || out_size == 0 || maximum >= out_size ||
        ap_control_json_get_string(object, name, &value, minimum, maximum) !=
            AP_CONTROL_WIRE_OK || (length = strlen(value)) >= out_size)
        return -1;
    memcpy(out, value, length + 1);
    return 0;
}

static int ac_json_copy_boolean(struct json_object *object, const char *name,
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

static int ac_model_report_parse(struct json_object *object,
                                 struct ac_device_model_report *out)
{
    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    if (ac_json_copy_string(object, "model", out->model, sizeof(out->model),
                            0, AC_DEVICE_MODEL_MAX) != 0 ||
        ac_json_copy_string(object, "board_name", out->board_name,
                            sizeof(out->board_name), 0,
                            AC_DEVICE_BOARD_NAME_MAX) != 0 ||
        ac_json_copy_string(object, "model_source", out->model_source,
                            sizeof(out->model_source), 1,
                            AC_DEVICE_MODEL_SOURCE_MAX) != 0 ||
        ac_json_copy_string(object, "model_reason", out->reason,
                            sizeof(out->reason), 0,
                            AC_DEVICE_MODEL_REASON_MAX) != 0 ||
        ac_json_copy_boolean(object, "model_available",
                             &out->model_available) != 0 ||
        (out->model_available && !out->model[0]) ||
        (!out->model_available && out->model[0]))
        return -1;
    return 0;
}

static int ac_snapshot_array_items_valid(struct json_object *array,
                                         const char *identity,
                                         size_t maximum)
{
    size_t i;

    if (!array || !identity || !json_object_is_type(array, json_type_array) ||
        json_object_array_length(array) > maximum)
        return 0;
    for (i = 0; i < json_object_array_length(array); i++) {
        struct json_object *item = json_object_array_get_idx(array, i);
        struct json_object *value = NULL;

        if (!item || !json_object_is_type(item, json_type_object) ||
            !json_object_object_get_ex(item, identity, &value) || !value ||
            !json_object_is_type(value, json_type_string) ||
            json_object_get_string_len(value) <= 0 ||
            json_object_get_string_len(value) > 255)
            return 0;
    }
    return 1;
}

static int ac_telemetry_snapshot_parse(
    struct json_object *message, const char *authenticated_ap_id,
    const char *session_epoch, int64_t previous_sequence, int64_t *sequence_out,
    int64_t *observed_at_out, char snapshot_id[72],
    struct ac_device_model_report *report_out,
    struct json_object **snapshot_out)
{
    struct json_object *snapshot = NULL;
    struct json_object *value = NULL;
    struct json_object *radios = NULL;
    struct json_object *ssids = NULL;
    struct json_object *stations = NULL;
    const char *text = NULL;
    const char *serialized;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    char encoded[SHA256_DIGEST_LENGTH * 2 + 1];
    int64_t version = 0;
    int64_t sequence = 0;
    int64_t observed_at = 0;
    int64_t snapshot_observed_at = 0;
    int complete;
    int stale;
    int wireless_present;
    int rc = -1;

    memset(digest, 0, sizeof(digest));
    memset(encoded, 0, sizeof(encoded));
    if (!message || !authenticated_ap_id || !session_epoch || !sequence_out ||
        !observed_at_out || !snapshot_id || !report_out || !snapshot_out) {
        ac_transport_log_stage("telemetry_rejected", "arguments");
        goto done;
    }
    if (ac_message_expect(message, ac_fields_telemetry_snapshot,
            AC_ARRAY_SIZE(ac_fields_telemetry_snapshot),
            "telemetry_snapshot") != 0) {
        ac_transport_log_stage("telemetry_rejected", "envelope");
        goto done;
    }
    if (ap_control_json_get_string(message, "schema", &text,
            strlen(AC_TELEMETRY_SCHEMA), strlen(AC_TELEMETRY_SCHEMA)) !=
            AP_CONTROL_WIRE_OK || strcmp(text, AC_TELEMETRY_SCHEMA) != 0 ||
        ap_control_json_get_int64(message, "version", AC_TELEMETRY_VERSION,
            AC_TELEMETRY_VERSION, &version) != AP_CONTROL_WIRE_OK) {
        ac_transport_log_stage("telemetry_rejected", "schema");
        goto done;
    }
    if (ap_control_json_get_string(message, "ap_id", &text, 36, 36) !=
            AP_CONTROL_WIRE_OK || strcmp(text, authenticated_ap_id) != 0) {
        ac_transport_log_stage("telemetry_rejected", "identity");
        goto done;
    }
    if (ap_control_json_get_string(message, "session_epoch", &text, 64, 64) !=
            AP_CONTROL_WIRE_OK || strcmp(text, session_epoch) != 0) {
        ac_transport_log_stage("telemetry_rejected", "session_epoch");
        goto done;
    }
    if (ap_control_json_get_int64(message, "sequence", 0, INT64_MAX,
            &sequence) != AP_CONTROL_WIRE_OK || sequence < previous_sequence) {
        ac_transport_log_stage("telemetry_rejected", "sequence");
        goto done;
    }
    if (ap_control_json_get_int64(message, "observed_at", 1, INT64_MAX,
            &observed_at) != AP_CONTROL_WIRE_OK ||
        !json_object_object_get_ex(message, "snapshot", &snapshot) ||
        !snapshot) {
        ac_transport_log_stage("telemetry_rejected", "snapshot_missing");
        goto done;
    }
    if (ap_control_json_object_exact(snapshot, ac_fields_wireless_snapshot,
            AC_ARRAY_SIZE(ac_fields_wireless_snapshot),
            ac_required_wireless_snapshot,
            AC_ARRAY_SIZE(ac_required_wireless_snapshot)) != AP_CONTROL_WIRE_OK) {
        ac_transport_log_stage("telemetry_rejected", "snapshot_schema");
        goto done;
    }
    if (!json_object_object_get_ex(snapshot, "ok", &value) || !value ||
        !json_object_is_type(value, json_type_boolean) ||
        !json_object_get_boolean(value) ||
        ap_control_json_get_string(snapshot, "contract_version", &text,
            strlen(AC_CONTRACT_VERSION), strlen(AC_CONTRACT_VERSION)) !=
            AP_CONTROL_WIRE_OK || strcmp(text, AC_CONTRACT_VERSION) != 0 ||
        ap_control_json_get_string(snapshot, "snapshot_version", &text,
            strlen("wireless-snapshot.v1"), strlen("wireless-snapshot.v1")) !=
            AP_CONTROL_WIRE_OK || strcmp(text, "wireless-snapshot.v1") != 0 ||
        ap_control_json_get_int64(snapshot, "observed_at", 1, INT64_MAX,
            &snapshot_observed_at) != AP_CONTROL_WIRE_OK ||
        snapshot_observed_at != observed_at ||
        ac_json_copy_boolean(snapshot, "complete", &complete) != 0 ||
        ac_json_copy_boolean(snapshot, "stale", &stale) != 0 || stale ||
        ac_json_copy_boolean(snapshot, "wireless_present", &wireless_present) != 0 ||
        ac_model_report_parse(snapshot, report_out) != 0) {
        ac_transport_log_stage("telemetry_rejected", "snapshot_fields");
        goto done;
    }
    if (!json_object_object_get_ex(snapshot, "radios", &radios) ||
        !json_object_object_get_ex(snapshot, "ssids", &ssids) ||
        !json_object_object_get_ex(snapshot, "stations", &stations) ||
        !ac_snapshot_array_items_valid(radios, "id", 64) ||
        !ac_snapshot_array_items_valid(ssids, "id", 256) ||
        !ac_snapshot_array_items_valid(stations, "mac", 1024)) {
        ac_transport_log_stage("telemetry_rejected", "snapshot_arrays");
        goto done;
    }
    /* Optional AP system facts: absent on pre-2026-07-26 APDs. */
    if (json_object_object_get_ex(snapshot, "system", &value) &&
        (!value || !json_object_is_type(value, json_type_object))) {
        ac_transport_log_stage("telemetry_rejected", "snapshot_system");
        goto done;
    }
    if (!(serialized = json_object_to_json_string_ext(
            snapshot, JSON_C_TO_STRING_PLAIN)) ||
        !SHA256((const unsigned char *)serialized, strlen(serialized), digest) ||
        ap_control_hex_encode(digest, sizeof(digest), encoded,
                              sizeof(encoded)) != AP_CONTROL_WIRE_OK) {
        ac_transport_log_stage("telemetry_rejected", "snapshot_digest");
        goto done;
    }
    (void)complete;
    (void)wireless_present;
    if (snprintf(snapshot_id, 72, "sha256:%s", encoded) >= 72) {
        ac_transport_log_stage("telemetry_rejected", "snapshot_id");
        goto done;
    }
    *sequence_out = sequence;
    *observed_at_out = observed_at;
    *snapshot_out = snapshot;
    rc = 0;
done:
    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_cleanse(encoded, sizeof(encoded));
    return rc;
}

static void ac_db_enter(void)
{
#ifndef AC_TRANSPORT_TEST_STANDALONE
    if (g_ac_db)
        sqlite3_mutex_enter(sqlite3_db_mutex(g_ac_db));
#endif
}

static void ac_db_leave(void)
{
#ifndef AC_TRANSPORT_TEST_STANDALONE
    if (g_ac_db)
        sqlite3_mutex_leave(sqlite3_db_mutex(g_ac_db));
#endif
}

static int ac_alpn_select(SSL *ssl, const unsigned char **out,
                          unsigned char *out_length,
                          const unsigned char *input,
                          unsigned int input_length, void *opaque)
{
    unsigned int offset = 0;

    (void)ssl;
    (void)opaque;
    /* Prefer v2 when the AP explicitly offers it; v1 remains compatible. */
    while (offset < input_length) {
        unsigned int length = input[offset++];

        if (length > input_length - offset)
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        if (length == sizeof(AP_CONTROL_ALPN_V2) - 1 &&
            CRYPTO_memcmp(input + offset, AP_CONTROL_ALPN_V2, length) == 0) {
            *out = (const unsigned char *)AP_CONTROL_ALPN_V2;
            *out_length = (unsigned char)length;
            return SSL_TLSEXT_ERR_OK;
        }
        offset += length;
    }
    offset = 0;
    while (offset < input_length) {
        unsigned int length = input[offset++];

        if (length > input_length - offset)
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        if (length == sizeof(AP_CONTROL_ALPN_V1) - 1 &&
            CRYPTO_memcmp(input + offset, AP_CONTROL_ALPN_V1, length) == 0) {
            *out = (const unsigned char *)AP_CONTROL_ALPN_V1;
            *out_length = (unsigned char)length;
            return SSL_TLSEXT_ERR_OK;
        }
        offset += length;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

static SSL_CTX *ac_tls_context_new(struct ac_pki *pki)
{
    SSL_CTX *context = NULL;
    X509 *server_certificate = NULL;
    X509 *ca_certificate = NULL;
    EVP_PKEY *server_key = NULL;
    X509_STORE *store;

    context = SSL_CTX_new(TLS_server_method());
    server_certificate = ac_pki_server_certificate_dup(pki);
    ca_certificate = ac_pki_ca_certificate_dup(pki);
    server_key = ac_pki_server_private_key_dup(pki);
    if (!context || !server_certificate || !ca_certificate || !server_key ||
        SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(context, TLS1_3_VERSION) != 1 ||
        SSL_CTX_use_certificate(context, server_certificate) != 1 ||
        SSL_CTX_use_PrivateKey(context, server_key) != 1 ||
        SSL_CTX_check_private_key(context) != 1 ||
        !(store = SSL_CTX_get_cert_store(context)) ||
        X509_STORE_add_cert(store, ca_certificate) != 1)
        goto fail;
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, NULL);
    SSL_CTX_set_verify_depth(context, 2);
    SSL_CTX_set_session_cache_mode(context, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(context, SSL_OP_NO_COMPRESSION | SSL_OP_NO_TICKET);
    SSL_CTX_set_alpn_select_cb(context, ac_alpn_select, NULL);
    X509_free(server_certificate);
    X509_free(ca_certificate);
    EVP_PKEY_free(server_key);
    return context;
fail:
    X509_free(server_certificate);
    X509_free(ca_certificate);
    EVP_PKEY_free(server_key);
    SSL_CTX_free(context);
    return NULL;
}

static int ac_peer_identity(SSL *ssl, struct ac_transport_peer *out)
{
    X509 *certificate = NULL;
    GENERAL_NAMES *names = NULL;
    GENERAL_NAME *name;
    const ASN1_IA5STRING *uri;
    const unsigned char *value;
    const char *uuid;
    unsigned int fingerprint_length = 0;
    int san_index;
    BASIC_CONSTRAINTS *constraints = NULL;
    EXTENDED_KEY_USAGE *usage = NULL;
    int client_auth = 0;
    int i;
    int rc = -1;

    if (!ssl || !out)
        return -1;
    memset(out, 0, sizeof(*out));
    certificate = SSL_get_peer_certificate(ssl);
    if (!certificate)
        return 0;
    out->certificate_present = 1;
    constraints = X509_get_ext_d2i(certificate, NID_basic_constraints,
                                   NULL, NULL);
    usage = X509_get_ext_d2i(certificate, NID_ext_key_usage, NULL, NULL);
    if (!constraints || constraints->ca || !usage ||
        sk_ASN1_OBJECT_num(usage) != 1)
        goto done;
    for (i = 0; i < sk_ASN1_OBJECT_num(usage); i++)
        if (OBJ_obj2nid(sk_ASN1_OBJECT_value(usage, i)) == NID_client_auth)
            client_auth++;
    if (client_auth != 1)
        goto done;
    san_index = X509_get_ext_by_NID(certificate, NID_subject_alt_name, -1);
    if (san_index < 0 ||
        X509_get_ext_by_NID(certificate, NID_subject_alt_name, san_index) >= 0 ||
        !(names = X509_get_ext_d2i(certificate, NID_subject_alt_name,
                                   NULL, NULL)) ||
        sk_GENERAL_NAME_num(names) != 1 ||
        !(name = sk_GENERAL_NAME_value(names, 0)) || name->type != GEN_URI ||
        !(uri = name->d.uniformResourceIdentifier) ||
        ASN1_STRING_type(uri) != V_ASN1_IA5STRING ||
        ASN1_STRING_length(uri) !=
            (int)(sizeof(AC_TRANSPORT_URI_PREFIX) - 1 + AC_ENROLLMENT_ID_LEN) ||
        !(value = ASN1_STRING_get0_data(uri)) ||
        memchr(value, '\0', (size_t)ASN1_STRING_length(uri)) ||
        CRYPTO_memcmp(value, AC_TRANSPORT_URI_PREFIX,
                      sizeof(AC_TRANSPORT_URI_PREFIX) - 1) != 0)
        goto done;
    uuid = (const char *)value + sizeof(AC_TRANSPORT_URI_PREFIX) - 1;
    memcpy(out->ap_id, uuid, AC_ENROLLMENT_ID_LEN);
    out->ap_id[AC_ENROLLMENT_ID_LEN] = '\0';
    if (!ac_uuid_valid(out->ap_id) ||
        X509_digest(certificate, EVP_sha256(), out->fingerprint,
                    &fingerprint_length) != 1 ||
        fingerprint_length != SHA256_DIGEST_LENGTH)
        goto done;
    rc = 0;
done:
    EXTENDED_KEY_USAGE_free(usage);
    BASIC_CONSTRAINTS_free(constraints);
    GENERAL_NAMES_free(names);
    X509_free(certificate);
    if (rc != 0)
        OPENSSL_cleanse(out, sizeof(*out));
    return rc;
}

static int ac_peer_authorize(const char *certificate_id, const char *ap_id,
                             const struct ac_transport_peer *peer,
                             int require_active)
{
    int authorized;

    if (!peer || !peer->certificate_present || !ac_uuid_valid(certificate_id) ||
        !ac_uuid_valid(ap_id) || strcmp(ap_id, peer->ap_id) != 0)
        return 0;
    ac_db_enter();
    authorized = ac_db_certificate_peer_authorize(
        certificate_id, ap_id, peer->fingerprint, require_active);
    ac_db_leave();
    return authorized;
}

static int ac_enrollment_claim_parse(
    struct json_object *object, struct ac_enrollment_signed_request *request,
    char owned_token[AC_PAIRING_TOKEN_LEN + 1], unsigned char **owned_csr)
{
    const char *token = NULL;
    size_t csr_length = 0;
    int64_t expires_at = 0;

    if (!object || !request || !owned_token || !owned_csr ||
        ac_message_expect(object, ac_fields_enrollment_claim,
                AC_ARRAY_SIZE(ac_fields_enrollment_claim),
                "enrollment_claim") != 0)
        return -1;
    memset(request, 0, sizeof(*request));
    *owned_csr = NULL;
    if (ac_json_copy_string(object, "challenge_id", request->claim.challenge_id,
                sizeof(request->claim.challenge_id), AC_ENROLLMENT_ID_LEN,
                AC_ENROLLMENT_ID_LEN) != 0 ||
        ac_json_get_hex_exact(object, "server_nonce",
                              request->claim.server_nonce,
                              sizeof(request->claim.server_nonce)) != 0 ||
        ac_json_get_hex_exact(object, "client_nonce",
                              request->claim.client_nonce,
                              sizeof(request->claim.client_nonce)) != 0 ||
        ac_json_copy_string(object, "enrollment_id",
                request->claim.enrollment_id,
                sizeof(request->claim.enrollment_id), AC_ENROLLMENT_ID_LEN,
                AC_ENROLLMENT_ID_LEN) != 0 ||
        ac_json_copy_string(object, "token_id", request->claim.token_id,
                sizeof(request->claim.token_id), AC_PAIRING_TOKEN_ID_LEN,
                AC_PAIRING_TOKEN_ID_LEN) != 0 ||
        ap_control_json_get_string(object, "token", &token,
                AC_PAIRING_TOKEN_LEN, AC_PAIRING_TOKEN_LEN) !=
            AP_CONTROL_WIRE_OK ||
        ac_json_copy_string(object, "ap_id", request->claim.ap_id,
                sizeof(request->claim.ap_id), AC_ENROLLMENT_ID_LEN,
                AC_ENROLLMENT_ID_LEN) != 0 ||
        ac_json_copy_string(object, "key_id", request->claim.key_id,
                sizeof(request->claim.key_id), AC_ENROLLMENT_KEY_ID_LEN,
                AC_ENROLLMENT_KEY_ID_LEN) != 0 ||
        ac_json_get_hex_exact(object, "public_key", request->claim.public_key,
                              sizeof(request->claim.public_key)) != 0 ||
        ac_json_copy_string(object, "site_id", request->claim.site_id,
                sizeof(request->claim.site_id), 0,
                AC_PAIRING_SITE_ID_LEN) != 0 ||
        ac_json_copy_string(object, "hardware_digest",
                request->claim.hardware_digest,
                sizeof(request->claim.hardware_digest), 0,
                AC_PAIRING_HARDWARE_DIGEST_LEN) != 0 ||
        ac_json_get_hex_alloc(object, "csr_der", AC_ENROLLMENT_CSR_MAX,
                              owned_csr, &csr_length) != 0 ||
        ac_json_get_hex_exact(object, "csr_sha256",
                              request->claim.csr_sha256,
                              sizeof(request->claim.csr_sha256)) != 0 ||
        ap_control_json_get_int64(object, "challenge_expires_at", 1,
                                  INT64_MAX, &expires_at) !=
            AP_CONTROL_WIRE_OK ||
        ac_json_get_hex_exact(object, "signature", request->signature,
                              sizeof(request->signature)) != 0 ||
        !ac_uuid_valid(request->claim.challenge_id) ||
        !ac_uuid_valid(request->claim.enrollment_id) ||
        !ac_uuid_valid(request->claim.token_id) ||
        !ac_uuid_valid(request->claim.ap_id) ||
        !ac_key_id_valid(request->claim.key_id))
        goto fail;
    memcpy(owned_token, token, AC_PAIRING_TOKEN_LEN);
    owned_token[AC_PAIRING_TOKEN_LEN] = '\0';
    request->claim.token = owned_token;
    request->claim.csr_der = *owned_csr;
    request->claim.csr_der_len = csr_length;
    request->claim.challenge_expires_at = expires_at;
    return 0;
fail:
    if (*owned_csr) {
        OPENSSL_cleanse(*owned_csr, csr_length);
        free(*owned_csr);
        *owned_csr = NULL;
    }
    OPENSSL_cleanse(request, sizeof(*request));
    return -1;
}

static void ac_enrollment_claim_cleanse(
    struct ac_enrollment_signed_request *request,
    char owned_token[AC_PAIRING_TOKEN_LEN + 1], unsigned char *owned_csr,
    struct json_object *object)
{
    if (owned_token)
        OPENSSL_cleanse(owned_token, AC_PAIRING_TOKEN_LEN + 1);
    if (owned_csr) {
        size_t length = request ? request->claim.csr_der_len : 0;

        OPENSSL_cleanse(owned_csr, length);
        free(owned_csr);
    }
    if (request)
        OPENSSL_cleanse(request, sizeof(*request));
    json_object_put(object);
}

static int ac_enrollment_certificate_send(
    SSL *ssl, const char *enrollment_id, const char *certificate_id,
    const unsigned char *certificate_der, size_t certificate_der_length,
    const unsigned char fingerprint[SHA256_DIGEST_LENGTH])
{
    struct json_object *response = ac_message_new("enrollment_certificate");
    int rc = -1;

    if (response && ac_json_add_string(response, "controller_id",
                ac_pki_controller_id(g_ac_transport.pki)) == 0 &&
        ac_json_add_string(response, "enrollment_id", enrollment_id) == 0 &&
        ac_json_add_string(response, "certificate_id", certificate_id) == 0 &&
        ac_json_add_hex(response, "certificate_der", certificate_der,
                        certificate_der_length) == 0 &&
        ac_json_add_hex(response, "certificate_fingerprint", fingerprint,
                        SHA256_DIGEST_LENGTH) == 0 &&
        ac_json_add_hex(response, "ca_fingerprint",
                        ac_pki_ca_fingerprint_sha256(g_ac_transport.pki),
                        SHA256_DIGEST_LENGTH) == 0 &&
        ap_control_json_object_exact(response,
                ac_fields_enrollment_certificate,
                AC_ARRAY_SIZE(ac_fields_enrollment_certificate),
                ac_fields_enrollment_certificate,
                AC_ARRAY_SIZE(ac_fields_enrollment_certificate)) ==
            AP_CONTROL_WIRE_OK &&
        ap_control_ssl_write_json(ssl, AP_CONTROL_IO_TIMEOUT_MS, response) ==
            AP_CONTROL_WIRE_OK)
        rc = 0;
    json_object_put(response);
    return rc;
}

static int ac_enrollment_issue(SSL *ssl,
                               const struct ac_enrollment_signed_request *request,
                               const struct ac_enrollment_record *record,
                               int claim_result)
{
    struct ac_pki_issued_certificate *issued = NULL;
    struct ac_enrollment_certificate certificate;
    struct ac_enrollment_record committed;
    unsigned char *stored_der = NULL;
    const unsigned char *issued_der;
    const unsigned char *issued_fingerprint;
    size_t issued_der_length = 0;
    int commit_result;
    int rc = -1;

    memset(&certificate, 0, sizeof(certificate));
    memset(&committed, 0, sizeof(committed));
    if (claim_result == AC_ENROLLMENT_IDEMPOTENT) {
        ac_db_enter();
        commit_result = ac_db_enrollment_certificate_get(
            record && record->enrollment_id[0] ? record->enrollment_id :
            request->claim.enrollment_id, &certificate, &stored_der);
        ac_db_leave();
        if (commit_result == 0) {
            rc = ac_enrollment_certificate_send(
                ssl, certificate.enrollment_id, certificate.certificate_id,
                certificate.certificate_der, certificate.certificate_der_len,
                certificate.fingerprint_sha256);
            goto done;
        }
        if (!record || strcmp(record->state, "claimed") != 0)
            goto done;
    }
    pthread_mutex_lock(&g_ac_transport.pki_lock);
    commit_result = ac_pki_issue_ap_certificate(
        g_ac_transport.pki, request->claim.ap_id, request->claim.public_key,
        request->claim.csr_der, request->claim.csr_der_len, &issued);
    pthread_mutex_unlock(&g_ac_transport.pki_lock);
    if (commit_result != 0 || !issued ||
        !(issued_der = ac_pki_issued_certificate_der(issued,
                                                     &issued_der_length)) ||
        !issued_der_length ||
        !(issued_fingerprint =
            ac_pki_issued_certificate_fingerprint_sha256(issued)) ||
        ap_control_uuid4(certificate.certificate_id) != AP_CONTROL_WIRE_OK)
        goto done;
    snprintf(certificate.enrollment_id, sizeof(certificate.enrollment_id),
             "%s", request->claim.enrollment_id);
    snprintf(certificate.serial, sizeof(certificate.serial), "%s",
             ac_pki_issued_certificate_serial(issued));
    snprintf(certificate.issuer_key_id, sizeof(certificate.issuer_key_id),
             "%s", ac_pki_issued_certificate_issuer_key_id(issued));
    certificate.certificate_der = issued_der;
    certificate.certificate_der_len = issued_der_length;
    memcpy(certificate.fingerprint_sha256, issued_fingerprint,
           sizeof(certificate.fingerprint_sha256));
    certificate.not_before = ac_pki_issued_certificate_not_before(issued);
    certificate.not_after = ac_pki_issued_certificate_not_after(issued);
    ac_db_enter();
    commit_result = ac_db_enrollment_certificate_commit(&certificate,
                                                        &committed);
    ac_db_leave();
    if (commit_result != AC_ENROLLMENT_OK &&
        commit_result != AC_ENROLLMENT_IDEMPOTENT) {
        struct ac_enrollment_certificate existing;

        memset(&existing, 0, sizeof(existing));
        ac_db_enter();
        commit_result = ac_db_enrollment_certificate_get(
            request->claim.enrollment_id, &existing, &stored_der);
        ac_db_leave();
        if (commit_result != 0)
            goto done;
        rc = ac_enrollment_certificate_send(
            ssl, existing.enrollment_id, existing.certificate_id,
            existing.certificate_der, existing.certificate_der_len,
            existing.fingerprint_sha256);
        certificate.certificate_der_len = existing.certificate_der_len;
        OPENSSL_cleanse(&existing, sizeof(existing));
        goto done;
    }
    rc = ac_enrollment_certificate_send(
        ssl, certificate.enrollment_id, certificate.certificate_id,
        certificate.certificate_der, certificate.certificate_der_len,
        certificate.fingerprint_sha256);
done:
    if (stored_der) {
        OPENSSL_cleanse(stored_der, certificate.certificate_der_len);
        free(stored_der);
    }
    ac_pki_issued_certificate_free(issued);
    OPENSSL_cleanse(&certificate, sizeof(certificate));
    OPENSSL_cleanse(&committed, sizeof(committed));
    return rc;
}

static int ac_handle_enrollment(SSL *ssl, struct json_object *hello,
                                const struct ac_transport_peer *peer)
{
    struct ac_enrollment_challenge challenge;
    struct ac_enrollment_signed_request request;
    struct ac_enrollment_record record;
    struct json_object *response = NULL;
    struct json_object *claim = NULL;
    unsigned char hello_public_key[AC_ENROLLMENT_PUBLIC_KEY_LEN];
    unsigned char *owned_csr = NULL;
    char owned_token[AC_PAIRING_TOKEN_LEN + 1];
    char hello_ap_id[AC_ENROLLMENT_ID_LEN + 1];
    char hello_key_id[AC_ENROLLMENT_KEY_ID_LEN + 1];
    struct ac_device_model_report model_report;
    int claim_result = AC_ENROLLMENT_ERROR;
    int rc = -1;

    memset(&challenge, 0, sizeof(challenge));
    memset(&request, 0, sizeof(request));
    memset(&record, 0, sizeof(record));
    memset(hello_public_key, 0, sizeof(hello_public_key));
    memset(hello_ap_id, 0, sizeof(hello_ap_id));
    memset(hello_key_id, 0, sizeof(hello_key_id));
    memset(owned_token, 0, sizeof(owned_token));
    memset(&model_report, 0, sizeof(model_report));
    if (!ssl || !hello || !peer || peer->certificate_present ||
        ac_message_expect(hello, ac_fields_enrollment_hello,
                AC_ARRAY_SIZE(ac_fields_enrollment_hello),
                "enrollment_hello") != 0 ||
        ac_json_copy_string(hello, "ap_id", hello_ap_id,
                sizeof(hello_ap_id), AC_ENROLLMENT_ID_LEN,
                AC_ENROLLMENT_ID_LEN) != 0 ||
        ac_json_copy_string(hello, "key_id", hello_key_id,
                sizeof(hello_key_id), AC_ENROLLMENT_KEY_ID_LEN,
                AC_ENROLLMENT_KEY_ID_LEN) != 0 ||
        ac_json_get_hex_exact(hello, "public_key", hello_public_key,
                              sizeof(hello_public_key)) != 0 ||
        ac_model_report_parse(hello, &model_report) != 0 ||
        !ac_uuid_valid(hello_ap_id) || !ac_key_id_valid(hello_key_id))
        goto rejected;
    ac_db_enter();
    rc = ac_db_enrollment_challenge_create(120, &challenge);
    ac_db_leave();
    if (rc != 0)
        goto unavailable;
    response = ac_message_new("enrollment_challenge");
    if (!response || ac_json_add_string(response, "controller_id",
                ac_pki_controller_id(g_ac_transport.pki)) != 0 ||
        ac_json_add_string(response, "challenge_id", challenge.challenge_id) != 0 ||
        ac_json_add_hex(response, "server_nonce", challenge.server_nonce,
                        sizeof(challenge.server_nonce)) != 0 ||
        ac_json_add_int64(response, "expires_at", challenge.expires_at) != 0 ||
        ap_control_json_object_exact(response, ac_fields_enrollment_challenge,
                AC_ARRAY_SIZE(ac_fields_enrollment_challenge),
                ac_fields_enrollment_challenge,
                AC_ARRAY_SIZE(ac_fields_enrollment_challenge)) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_ssl_write_json(ssl, AP_CONTROL_IO_TIMEOUT_MS, response) !=
            AP_CONTROL_WIRE_OK)
        goto done;
    json_object_put(response);
    response = NULL;
    if (ap_control_ssl_read_json(ssl, AP_CONTROL_IO_TIMEOUT_MS, &claim) !=
            AP_CONTROL_WIRE_OK ||
        ac_enrollment_claim_parse(claim, &request, owned_token,
                                  &owned_csr) != 0 ||
        strcmp(request.claim.challenge_id, challenge.challenge_id) != 0 ||
        CRYPTO_memcmp(request.claim.server_nonce, challenge.server_nonce,
                      sizeof(challenge.server_nonce)) != 0 ||
        request.claim.challenge_expires_at != challenge.expires_at ||
        strcmp(request.claim.ap_id, hello_ap_id) != 0 ||
        strcmp(request.claim.key_id, hello_key_id) != 0 ||
        CRYPTO_memcmp(request.claim.public_key, hello_public_key,
                      sizeof(hello_public_key)) != 0)
        goto rejected;
    ac_db_enter();
    claim_result = ac_enrollment_verify_and_claim(&request, &record);
    ac_db_leave();
    if (claim_result != AC_ENROLLMENT_OK &&
        claim_result != AC_ENROLLMENT_IDEMPOTENT)
        goto denied;
    ac_db_enter();
    if (ac_db_ap_identity_report(hello_ap_id, &model_report) != 0) {
        ac_db_leave();
        goto unavailable;
    }
    ac_db_leave();
    if (ac_enrollment_issue(ssl, &request, &record, claim_result) != 0)
        goto unavailable;
    rc = 0;
    goto done;
rejected:
    ac_send_error(ssl, "invalid_request", "enrollment_request_rejected");
    goto done;
denied:
    ac_send_error(ssl, "enrollment_denied", "enrollment_not_authorized");
    goto done;
unavailable:
    ac_send_error(ssl, "temporarily_unavailable", "enrollment_unavailable");
done:
    json_object_put(response);
    ac_enrollment_claim_cleanse(&request, owned_token, owned_csr, claim);
    OPENSSL_cleanse(&challenge, sizeof(challenge));
    OPENSSL_cleanse(&record, sizeof(record));
    OPENSSL_cleanse(hello_public_key, sizeof(hello_public_key));
    OPENSSL_cleanse(hello_ap_id, sizeof(hello_ap_id));
    OPENSSL_cleanse(hello_key_id, sizeof(hello_key_id));
    OPENSSL_cleanse(&model_report, sizeof(model_report));
    return rc;
}

static int ac_identity_hello_parse(struct json_object *object,
                                   const char *const *fields,
                                   size_t field_count, const char *kind,
                                   int include_enrollment,
                                   char controller_id[37],
                                   char enrollment_id[37],
                                   char certificate_id[37], char ap_id[37])
{
    if (ac_message_expect(object, fields, field_count, kind) != 0 ||
        ac_json_copy_string(object, "controller_id", controller_id, 37,
                            36, 36) != 0 ||
        (include_enrollment &&
         ac_json_copy_string(object, "enrollment_id", enrollment_id, 37,
                             36, 36) != 0) ||
        ac_json_copy_string(object, "certificate_id", certificate_id, 37,
                            36, 36) != 0 ||
        ac_json_copy_string(object, "ap_id", ap_id, 37, 36, 36) != 0 ||
        !ac_controller_id_valid(controller_id) ||
        (include_enrollment && !ac_uuid_valid(enrollment_id)) ||
        !ac_uuid_valid(certificate_id) || !ac_uuid_valid(ap_id) ||
        strcmp(controller_id, ac_pki_controller_id(g_ac_transport.pki)) != 0)
        return -1;
    return 0;
}

static int ac_activation_complete_send(
    SSL *ssl, const char *enrollment_id, const char *certificate_id,
    const unsigned char fingerprint[SHA256_DIGEST_LENGTH])
{
    struct json_object *response = ac_message_new("activation_complete");
    int rc = -1;

    if (response && ac_json_add_string(response, "controller_id",
                ac_pki_controller_id(g_ac_transport.pki)) == 0 &&
        ac_json_add_string(response, "enrollment_id", enrollment_id) == 0 &&
        ac_json_add_string(response, "certificate_id", certificate_id) == 0 &&
        ac_json_add_hex(response, "certificate_fingerprint", fingerprint,
                        SHA256_DIGEST_LENGTH) == 0 &&
        ac_json_add_boolean(response, "adopted", 1) == 0 &&
        ap_control_json_object_exact(response, ac_fields_activation_complete,
                AC_ARRAY_SIZE(ac_fields_activation_complete),
                ac_fields_activation_complete,
                AC_ARRAY_SIZE(ac_fields_activation_complete)) ==
            AP_CONTROL_WIRE_OK &&
        ap_control_ssl_write_json(ssl, AP_CONTROL_IO_TIMEOUT_MS, response) ==
            AP_CONTROL_WIRE_OK)
        rc = 0;
    json_object_put(response);
    return rc;
}

static int ac_activation_already_complete(
    const char *enrollment_id, const char *certificate_id,
    const char *ap_id, const struct ac_transport_peer *peer)
{
    struct ac_enrollment_certificate certificate;
    unsigned char *owned_der = NULL;
    int matched = 0;

    memset(&certificate, 0, sizeof(certificate));
    if (!ac_peer_authorize(certificate_id, ap_id, peer, 1))
        return 0;
    ac_db_enter();
    if (ac_db_enrollment_certificate_get(enrollment_id, &certificate,
                                         &owned_der) == 0 &&
        strcmp(certificate.certificate_id, certificate_id) == 0 &&
        CRYPTO_memcmp(certificate.fingerprint_sha256, peer->fingerprint,
                      SHA256_DIGEST_LENGTH) == 0)
        matched = 1;
    ac_db_leave();
    if (owned_der) {
        OPENSSL_cleanse(owned_der, certificate.certificate_der_len);
        free(owned_der);
    }
    OPENSSL_cleanse(&certificate, sizeof(certificate));
    return matched;
}

static int ac_handle_activation(SSL *ssl, struct json_object *hello,
                                const struct ac_transport_peer *peer)
{
    struct json_object *response = NULL;
    struct json_object *request = NULL;
    struct ac_enrollment_record record;
    unsigned char challenge[AC_ENROLLMENT_NONCE_LEN];
    unsigned char returned[AC_ENROLLMENT_NONCE_LEN];
    char controller_id[37] = {0};
    char enrollment_id[37] = {0};
    char certificate_id[37] = {0};
    char ap_id[37] = {0};
    char response_enrollment_id[37] = {0};
    char response_certificate_id[37] = {0};
    int activation_result;
    int rc = -1;

    memset(&record, 0, sizeof(record));
    memset(challenge, 0, sizeof(challenge));
    memset(returned, 0, sizeof(returned));
    if (ac_identity_hello_parse(hello, ac_fields_activation_hello,
            AC_ARRAY_SIZE(ac_fields_activation_hello), "activation_hello", 1,
            controller_id, enrollment_id, certificate_id, ap_id) != 0)
        goto denied;
    if (!ac_peer_authorize(certificate_id, ap_id, peer, 0)) {
        if (!ac_activation_already_complete(enrollment_id, certificate_id,
                                            ap_id, peer))
            goto denied;
        rc = ac_activation_complete_send(ssl, enrollment_id, certificate_id,
                                         peer->fingerprint);
        goto done;
    }
    ac_db_enter();
    activation_result = ac_db_enrollment_activation_begin(
        enrollment_id, certificate_id, challenge);
    ac_db_leave();
    if (activation_result != 0)
        goto denied;
    response = ac_message_new("activation_challenge");
    if (!response ||
        ac_json_add_string(response, "enrollment_id", enrollment_id) != 0 ||
        ac_json_add_string(response, "certificate_id", certificate_id) != 0 ||
        ac_json_add_hex(response, "challenge", challenge,
                        sizeof(challenge)) != 0 ||
        ap_control_json_object_exact(response, ac_fields_activation_challenge,
                AC_ARRAY_SIZE(ac_fields_activation_challenge),
                ac_fields_activation_challenge,
                AC_ARRAY_SIZE(ac_fields_activation_challenge)) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_ssl_write_json(ssl, AP_CONTROL_IO_TIMEOUT_MS, response) !=
            AP_CONTROL_WIRE_OK)
        goto unavailable;
    json_object_put(response);
    response = NULL;
    if (ap_control_ssl_read_json(ssl, AP_CONTROL_IO_TIMEOUT_MS, &request) !=
            AP_CONTROL_WIRE_OK ||
        ac_message_expect(request, ac_fields_activation_response,
                AC_ARRAY_SIZE(ac_fields_activation_response),
                "activation_response") != 0 ||
        ac_json_copy_string(request, "enrollment_id", response_enrollment_id,
                            sizeof(response_enrollment_id), 36, 36) != 0 ||
        ac_json_copy_string(request, "certificate_id", response_certificate_id,
                            sizeof(response_certificate_id), 36, 36) != 0 ||
        ac_json_get_hex_exact(request, "challenge", returned,
                              sizeof(returned)) != 0 ||
        strcmp(response_enrollment_id, enrollment_id) != 0 ||
        strcmp(response_certificate_id, certificate_id) != 0 ||
        !ac_peer_authorize(certificate_id, ap_id, peer, 0))
        goto denied;
    ac_db_enter();
    activation_result = ac_db_enrollment_activate(
        enrollment_id, certificate_id, peer->fingerprint,
        returned, sizeof(returned), &record);
    ac_db_leave();
    if (activation_result != AC_ENROLLMENT_OK &&
        activation_result != AC_ENROLLMENT_IDEMPOTENT)
        goto denied;
    if (ac_activation_complete_send(ssl, enrollment_id, certificate_id,
                                    peer->fingerprint) != 0)
        goto unavailable;
    rc = 0;
    goto done;
denied:
    ac_send_error(ssl, "activation_denied", "certificate_not_authorized");
    goto done;
unavailable:
    ac_send_error(ssl, "temporarily_unavailable", "activation_unavailable");
done:
    json_object_put(request);
    json_object_put(response);
    OPENSSL_cleanse(&record, sizeof(record));
    OPENSSL_cleanse(challenge, sizeof(challenge));
    OPENSSL_cleanse(returned, sizeof(returned));
    return rc;
}

static int ac_wait_for_frame(SSL *ssl, int timeout_ms)
{
    struct pollfd descriptor;
    int result;

    if (!ssl || timeout_ms <= 0)
        return -1;
    if (SSL_pending(ssl) > 0)
        return 0;
    descriptor.fd = SSL_get_fd(ssl);
    descriptor.events = POLLIN;
    descriptor.revents = 0;
    if (descriptor.fd < 0)
        return -1;
    do {
        result = poll(&descriptor, 1, timeout_ms);
    } while (result < 0 && errno == EINTR && !ac_transport_stopping());
    if (result <= 0 ||
        (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)))
        return -1;
    return descriptor.revents & POLLIN ? 0 : -1;
}

struct ac_radio_job_request {
    int64_t sequence;
    char job_id[AC_RADIO_JOB_ID_LEN + 1];
    char attempt_id[AC_RADIO_JOB_ID_LEN + 1];
    int64_t dispatch_generation;
    char request_digest[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1];
};

struct ac_radio_job_replay {
    int valid;
    int64_t sequence;
    unsigned char request_sha256[SHA256_DIGEST_LENGTH];
    struct json_object *response;
};

static int ac_radio_digest_valid(const char *value)
{
    size_t i;

    if (!value || strlen(value) != AC_RADIO_JOB_RESULT_DIGEST_MAX ||
        strncmp(value, "sha256:", 7))
        return 0;
    for (i = 7; i < AC_RADIO_JOB_RESULT_DIGEST_MAX; i++)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f')))
            return 0;
    return 1;
}

static int ac_radio_request_sha256(struct json_object *message,
                                   unsigned char out[SHA256_DIGEST_LENGTH])
{
    const char *serialized;

    if (!message || !out || !(serialized = json_object_to_json_string_ext(
            message, JSON_C_TO_STRING_PLAIN)) ||
        !SHA256((const unsigned char *)serialized, strlen(serialized), out))
        return -1;
    return 0;
}

static int ac_radio_common_parse(struct json_object *message,
                                 const char *const *fields,
                                 size_t field_count, const char *kind,
                                 const char *ap_id, const char *session_epoch,
                                 int with_job,
                                 struct ac_radio_job_request *request)
{
    const char *value = NULL;

    if (!request || ac_message_expect(message, fields, field_count, kind) != 0 ||
        ap_control_json_get_string(message, "ap_id", &value, 36, 36) !=
            AP_CONTROL_WIRE_OK || strcmp(value, ap_id) ||
        ap_control_json_get_string(message, "session_epoch", &value, 64, 64) !=
            AP_CONTROL_WIRE_OK || strcmp(value, session_epoch) ||
        ap_control_json_get_int64(message, "sequence", 1, INT64_MAX,
                                  &request->sequence) != AP_CONTROL_WIRE_OK)
        return -1;
    if (!with_job)
        return 0;
    if (ac_json_copy_string(message, "job_id", request->job_id,
                            sizeof(request->job_id), 36, 36) != 0 ||
        !ac_uuid_valid(request->job_id) ||
        ac_json_copy_string(message, "attempt_id", request->attempt_id,
                            sizeof(request->attempt_id), 36, 36) != 0 ||
        !ac_uuid_valid(request->attempt_id) ||
        ap_control_json_get_int64(message, "dispatch_generation", 1,
                                  INT64_MAX,
                                  &request->dispatch_generation) !=
            AP_CONTROL_WIRE_OK ||
        ac_json_copy_string(message, "request_digest", request->request_digest,
                            sizeof(request->request_digest), 71, 71) != 0 ||
        !ac_radio_digest_valid(request->request_digest))
        return -1;
    return 0;
}

static int ac_radio_job_matches(const struct ac_radio_job *job,
                                const struct ac_radio_job_request *request,
                                const char *ap_id, const char *session_epoch)
{
    return job && request && !strcmp(job->job_id, request->job_id) &&
        !strcmp(job->attempt_id, request->attempt_id) &&
        job->dispatch_generation == request->dispatch_generation &&
        !strcmp(job->request_digest, request->request_digest) &&
        !strcmp(job->ap_id, ap_id) &&
        !strcmp(job->session_epoch, session_epoch);
}

static int ac_radio_response_envelope(struct json_object *response,
                                      const char *ap_id,
                                      const char *session_epoch,
                                      int64_t reply_to)
{
    return !response || ac_json_add_string(response, "ap_id", ap_id) != 0 ||
        ac_json_add_string(response, "session_epoch", session_epoch) != 0 ||
        ac_json_add_int64(response, "reply_to", reply_to) != 0 ? -1 : 0;
}

static struct json_object *ac_radio_error_new(const char *ap_id,
                                               const char *session_epoch,
                                               int64_t reply_to,
                                               const char *error,
                                               const char *reason)
{
    struct json_object *response = ac_message_new("radio_job_error");

    if (!response || ac_radio_response_envelope(response, ap_id, session_epoch,
            reply_to) != 0 || ac_json_add_string(response, "error", error) != 0 ||
        ac_json_add_string(response, "reason", reason) != 0 ||
        ap_control_json_object_exact(response, ac_fields_radio_job_error,
            AC_ARRAY_SIZE(ac_fields_radio_job_error), ac_fields_radio_job_error,
            AC_ARRAY_SIZE(ac_fields_radio_job_error)) != AP_CONTROL_WIRE_OK) {
        json_object_put(response);
        return NULL;
    }
    return response;
}

static int ac_radio_job_identity_add(struct json_object *response,
                                     const struct ac_radio_job *job)
{
    return !job || ac_json_add_string(response, "job_id", job->job_id) != 0 ||
        ac_json_add_string(response, "attempt_id", job->attempt_id) != 0 ||
        ac_json_add_int64(response, "dispatch_generation",
                          job->dispatch_generation) != 0 ||
        ac_json_add_string(response, "request_digest", job->request_digest) != 0
        ? -1 : 0;
}

static struct json_object *ac_radio_ack_new(
    const char *kind, const char *ap_id, const char *session_epoch,
    int64_t reply_to, const struct ac_radio_job *job,
    const char *const *fields, size_t field_count, int result_fields,
    const char *finish_id)
{
    struct json_object *response = ac_message_new(kind);
    int cancel_requested = job && !strcmp(job->state, "cancel_requested");

    if (!response || ac_radio_response_envelope(response, ap_id, session_epoch,
            reply_to) != 0 || ac_radio_job_identity_add(response, job) != 0 ||
        (finish_id && ac_json_add_string(response, "finish_id", finish_id) != 0) ||
        ac_json_add_string(response, "controller_state", job->state) != 0 ||
        ac_json_add_boolean(response, "cancel_requested", cancel_requested) != 0 ||
        (result_fields &&
         (ac_json_add_boolean(response, "result_complete",
                              job->result_complete) != 0 ||
          ac_json_add_string(response, "error_code", job->error_code) != 0)) ||
        ap_control_json_object_exact(response, fields, field_count, fields,
                                    field_count) != AP_CONTROL_WIRE_OK) {
        json_object_put(response);
        return NULL;
    }
    return response;
}

static int ac_radio_job_status_exact(const struct ac_radio_job_request *request,
                                     const char *ap_id,
                                     const char *session_epoch,
                                     struct ac_radio_job *job)
{
    int result;

    ac_db_enter();
    result = ac_db_ap_session_is_current(ap_id, session_epoch);
    if (result)
        result = ac_db_radio_job_status(request->job_id, job);
    ac_db_leave();
    return result == AC_RADIO_JOB_OK &&
           ac_radio_job_matches(job, request, ap_id, session_epoch) ? 0 : -1;
}

static struct json_object *ac_radio_poll_handle(
    const char *ap_id, const char *session_epoch,
    const struct ac_radio_job_request *request)
{
    struct ac_radio_job job;
    struct json_object *response = NULL;
    int result;

    memset(&job, 0, sizeof(job));
    ac_db_enter();
    result = ac_db_ap_session_is_current(ap_id, session_epoch) ?
        ac_db_radio_job_lease_next(ap_id, session_epoch, ac_now_s(), &job) :
        AC_RADIO_JOB_INVALID_TARGET;
    ac_db_leave();
    if (result == AC_RADIO_JOB_NOT_FOUND) {
        response = ac_message_new("radio_job_idle");
        if (!response || ac_radio_response_envelope(response, ap_id,
                session_epoch, request->sequence) != 0 ||
            ap_control_json_object_exact(response, ac_fields_radio_job_idle,
                AC_ARRAY_SIZE(ac_fields_radio_job_idle),
                ac_fields_radio_job_idle,
                AC_ARRAY_SIZE(ac_fields_radio_job_idle)) != AP_CONTROL_WIRE_OK) {
            json_object_put(response);
            return NULL;
        }
        return response;
    }
    if (result != AC_RADIO_JOB_OK)
        return ac_radio_error_new(ap_id, session_epoch, request->sequence,
                                  "invalid_session", "session_not_current");
    response = ac_message_new("radio_job_offer");
    if (!response || ac_radio_response_envelope(response, ap_id, session_epoch,
            request->sequence) != 0 || ac_radio_job_identity_add(response, &job) != 0 ||
        ac_json_add_string(response, "radio_id", job.radio_id) != 0 ||
        ac_json_add_string(response, "mode", job.mode) != 0 ||
        ac_json_add_string(response, "expected_impact", job.expected_impact) != 0 ||
        ac_json_add_string(response, "controller_state", job.state) != 0 ||
        ac_json_add_boolean(response, "cancel_requested",
                            !strcmp(job.state, "cancel_requested")) != 0 ||
        ap_control_json_object_exact(response, ac_fields_radio_job_offer,
            AC_ARRAY_SIZE(ac_fields_radio_job_offer), ac_fields_radio_job_offer,
            AC_ARRAY_SIZE(ac_fields_radio_job_offer)) != AP_CONTROL_WIRE_OK) {
        json_object_put(response);
        return NULL;
    }
    return response;
}

static struct json_object *ac_radio_accept_handle(
    const char *ap_id, const char *session_epoch,
    const struct ac_radio_job_request *request)
{
    struct ac_radio_job job;
    int result;

    memset(&job, 0, sizeof(job));
    if (ac_radio_job_status_exact(request, ap_id, session_epoch, &job) != 0 ||
        (strcmp(job.state, "leased") && strcmp(job.state, "running") &&
         strcmp(job.state, "cancel_requested")))
        return ac_radio_error_new(ap_id, session_epoch, request->sequence,
                                  "job_conflict", "job_assignment_not_current");
    if (!strcmp(job.state, "leased")) {
        ac_db_enter();
        result = ac_db_radio_job_reconcile(request->job_id, request->attempt_id,
            request->dispatch_generation, request->request_digest, ap_id,
            session_epoch, "leased", ac_now_s(), &job);
        ac_db_leave();
        if (result != AC_RADIO_JOB_OK && result != AC_RADIO_JOB_IDEMPOTENT)
            return ac_radio_error_new(ap_id, session_epoch, request->sequence,
                                      "job_conflict", "job_accept_rejected");
    }
    return ac_radio_ack_new("radio_job_accept_ack", ap_id, session_epoch,
        request->sequence, &job, ac_fields_radio_job_ack,
        AC_ARRAY_SIZE(ac_fields_radio_job_ack), 0, NULL);
}

static struct json_object *ac_radio_start_handle(
    const char *ap_id, const char *session_epoch,
    const struct ac_radio_job_request *request)
{
    struct ac_radio_job job;
    int result;

    memset(&job, 0, sizeof(job));
    ac_db_enter();
    result = ac_db_radio_job_mark_running(request->job_id, request->attempt_id,
        request->dispatch_generation, request->request_digest, ap_id,
        session_epoch, &job);
    ac_db_leave();
    if (result != AC_RADIO_JOB_OK && result != AC_RADIO_JOB_IDEMPOTENT) {
        if (ac_radio_job_status_exact(request, ap_id, session_epoch, &job) != 0 ||
            strcmp(job.state, "cancel_requested"))
            return ac_radio_error_new(ap_id, session_epoch, request->sequence,
                                      "job_conflict", "job_start_rejected");
    }
    return ac_radio_ack_new("radio_job_start_ack", ap_id, session_epoch,
        request->sequence, &job, ac_fields_radio_job_ack,
        AC_ARRAY_SIZE(ac_fields_radio_job_ack), 0, NULL);
}

static struct json_object *ac_radio_reconcile_handle(
    struct json_object *message, const char *ap_id, const char *session_epoch,
    const struct ac_radio_job_request *request)
{
    struct ac_radio_job job;
    struct json_object *result_value = NULL;
    const char *state = NULL;
    const char *radio_id = NULL;
    const char *mode = NULL;
    const char *finish_id = NULL;
    const char *outcome = NULL;
    const char *error_code = NULL;
    const char *result_json = NULL;
    const char *db_state;
    int result_complete = 0;
    int64_t observed_at = 0;
    int result;

    if (ap_control_json_get_string(message, "radio_id", &radio_id, 1,
            AC_RADIO_JOB_RADIO_ID_MAX) != AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(message, "mode", &mode, 6, 8) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(message, "state", &state, 6, 16) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(message, "finish_id", &finish_id, 0, 36) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(message, "outcome", &outcome, 0, 9) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(message, "error_code", &error_code, 0,
            AC_RADIO_JOB_ERROR_MAX) != AP_CONTROL_WIRE_OK ||
        ap_control_json_get_int64(message, "observed_at", 0, INT64_MAX,
            &observed_at) != AP_CONTROL_WIRE_OK ||
        ac_json_copy_boolean(message, "result_complete", &result_complete) != 0 ||
        !json_object_object_get_ex(message, "result", &result_value) ||
        !result_value || !json_object_is_type(result_value, json_type_array))
        return ac_radio_error_new(ap_id, session_epoch, request->sequence,
                                  "invalid_request", "reconcile_payload_invalid");
    memset(&job, 0, sizeof(job));
    ac_db_enter();
    result = ac_db_radio_job_status(request->job_id, &job);
    ac_db_leave();
    if (result != AC_RADIO_JOB_OK ||
        strcmp(job.attempt_id, request->attempt_id) ||
        job.dispatch_generation != request->dispatch_generation ||
        strcmp(job.request_digest, request->request_digest) ||
        strcmp(job.ap_id, ap_id) || strcmp(job.radio_id, radio_id) ||
        strcmp(job.mode, mode))
        return ac_radio_error_new(ap_id, session_epoch, request->sequence,
                                  "job_conflict", "job_assignment_not_current");
    db_state = !strcmp(state, "offered") ? "leased" :
               !strcmp(state, "cancel_requested") ? "running" : state;
    if (strcmp(db_state, "leased") && strcmp(db_state, "running") &&
        strcmp(db_state, "interrupted") && strcmp(db_state, "cancelled"))
        if (strcmp(db_state, "completed") && strcmp(db_state, "failed"))
            return ac_radio_error_new(ap_id, session_epoch, request->sequence,
                                      "invalid_request", "state_invalid");
    if (!strcmp(db_state, "leased") || !strcmp(db_state, "running")) {
        if (finish_id[0] || outcome[0] || error_code[0] || observed_at != 0 ||
            json_object_array_length(result_value) != 0 || result_complete)
            return ac_radio_error_new(ap_id, session_epoch, request->sequence,
                                      "invalid_request", "nonterminal_has_result");
        ac_db_enter();
        result = ac_db_radio_job_reconcile(request->job_id, request->attempt_id,
            request->dispatch_generation, request->request_digest, ap_id,
            session_epoch, db_state, ac_now_s(), &job);
        ac_db_leave();
        if (result != AC_RADIO_JOB_OK && result != AC_RADIO_JOB_IDEMPOTENT)
            return ac_radio_error_new(ap_id, session_epoch, request->sequence,
                                      "job_conflict", "job_reconcile_rejected");
        return ac_radio_ack_new("radio_job_reconcile_ack", ap_id,
            session_epoch, request->sequence, &job,
            ac_fields_radio_job_reconcile_ack,
            AC_ARRAY_SIZE(ac_fields_radio_job_reconcile_ack), 1, NULL);
    }
    if (!finish_id[0] || !ac_uuid_valid(finish_id) || observed_at <= 0 ||
        (!strcmp(db_state, "completed") && strcmp(outcome, "completed")) ||
        (!strcmp(db_state, "failed") && strcmp(outcome, "failed")) ||
        (!strcmp(db_state, "cancelled") && strcmp(outcome, "cancelled")) ||
        (!strcmp(db_state, "interrupted") && strcmp(outcome, "failed")) ||
        (!strcmp(outcome, "completed") ? error_code[0] != '\0' :
                                         error_code[0] == '\0') ||
        !(result_json = json_object_to_json_string_ext(
              result_value, JSON_C_TO_STRING_PLAIN)))
        return ac_radio_error_new(ap_id, session_epoch, request->sequence,
                                  "invalid_request", "terminal_result_invalid");
    /* Rebind a live execution to this current session before terminal commit. */
    if (!job.finish_id[0] && strcmp(job.state, "completed") &&
        strcmp(job.state, "failed") && strcmp(job.state, "cancelled")) {
        ac_db_enter();
        result = ac_db_radio_job_reconcile(request->job_id,
            request->attempt_id, request->dispatch_generation,
            request->request_digest, ap_id, session_epoch, "running",
            ac_now_s(), &job);
        ac_db_leave();
        if (result != AC_RADIO_JOB_OK && result != AC_RADIO_JOB_IDEMPOTENT)
            return ac_radio_error_new(ap_id, session_epoch, request->sequence,
                                      "job_conflict", "job_reconcile_rejected");
    }
    ac_db_enter();
    result = ac_db_radio_job_finish(request->job_id, request->attempt_id,
        request->dispatch_generation, request->request_digest, ap_id,
        session_epoch, finish_id, outcome, error_code, result_json,
        !result_complete, &job);
    ac_db_leave();
    if (result != AC_RADIO_JOB_OK && result != AC_RADIO_JOB_IDEMPOTENT)
        return ac_radio_error_new(ap_id, session_epoch, request->sequence,
                                  "job_conflict", "job_finish_rejected");
    return ac_radio_ack_new("radio_job_finish_ack", ap_id, session_epoch,
        request->sequence, &job, ac_fields_radio_job_finish_ack,
        AC_ARRAY_SIZE(ac_fields_radio_job_finish_ack), 1, finish_id);
}

static struct json_object *ac_radio_finish_handle(
    struct json_object *message, const char *ap_id, const char *session_epoch,
    const struct ac_radio_job_request *request)
{
    struct ac_radio_job job;
    struct json_object *result_value = NULL;
    const char *finish_id = NULL;
    const char *outcome = NULL;
    const char *error_code = NULL;
    const char *result_json;
    int result_complete;
    int db_result;

    if (ap_control_json_get_string(message, "finish_id", &finish_id, 36, 36) !=
            AP_CONTROL_WIRE_OK || !ac_uuid_valid(finish_id) ||
        ap_control_json_get_string(message, "outcome", &outcome, 6, 9) !=
            AP_CONTROL_WIRE_OK ||
        (strcmp(outcome, "completed") && strcmp(outcome, "failed") &&
         strcmp(outcome, "cancelled")) ||
        ap_control_json_get_string(message, "error_code", &error_code, 0,
            AC_RADIO_JOB_ERROR_MAX) != AP_CONTROL_WIRE_OK ||
        (!strcmp(outcome, "completed") ? error_code[0] != '\0' :
                                         error_code[0] == '\0') ||
        ac_json_copy_boolean(message, "result_complete", &result_complete) != 0 ||
        !json_object_object_get_ex(message, "result", &result_value) ||
        !result_value || !json_object_is_type(result_value, json_type_array) ||
        !(result_json = json_object_to_json_string_ext(
              result_value, JSON_C_TO_STRING_PLAIN)))
        return ac_radio_error_new(ap_id, session_epoch, request->sequence,
                                  "invalid_request", "job_finish_invalid");
    memset(&job, 0, sizeof(job));
    ac_db_enter();
    db_result = ac_db_radio_job_finish(request->job_id, request->attempt_id,
        request->dispatch_generation, request->request_digest, ap_id,
        session_epoch, finish_id, outcome, error_code,
        result_json, !result_complete, &job);
    ac_db_leave();
    if (db_result != AC_RADIO_JOB_OK && db_result != AC_RADIO_JOB_IDEMPOTENT)
        return ac_radio_error_new(ap_id, session_epoch, request->sequence,
                                  "job_conflict", "job_finish_rejected");
    return ac_radio_ack_new("radio_job_finish_ack", ap_id, session_epoch,
        request->sequence, &job, ac_fields_radio_job_finish_ack,
        AC_ARRAY_SIZE(ac_fields_radio_job_finish_ack), 1, finish_id);
}

/* ---- Phase W2c: config job wire handlers.  Dormant end to end until
 * the APD flips apd_config_executor_enabled() behind the W3 capability
 * gates: no production APD ever sends these kinds today. ---- */

static int ac_config_job_identity_add(struct json_object *response,
                                      const struct ac_config_job *job)
{
    return !job ||
        ac_json_add_string(response, "job_id", job->job_id) != 0 ||
        ac_json_add_string(response, "attempt_id", job->attempt_id) != 0 ||
        ac_json_add_int64(response, "dispatch_generation",
                          job->dispatch_generation) != 0 ||
        ac_json_add_string(response, "request_digest",
                           job->request_digest) != 0 ? -1 : 0;
}

static struct json_object *ac_config_ack_new(
    const char *kind, const char *ap_id, const char *session_epoch,
    int64_t reply_to, const struct ac_config_job *job,
    const char *const *fields, size_t field_count, const char *finish_id)
{
    struct json_object *response = ac_message_new(kind);

    if (!response ||
        ac_radio_response_envelope(response, ap_id, session_epoch,
                                   reply_to) != 0 ||
        ac_config_job_identity_add(response, job) != 0 ||
        (finish_id &&
         ac_json_add_string(response, "finish_id", finish_id) != 0) ||
        ac_json_add_string(response, "controller_state", job->state) != 0 ||
        ap_control_json_object_exact(response, fields, field_count, fields,
                                     field_count) != AP_CONTROL_WIRE_OK) {
        json_object_put(response);
        return NULL;
    }
    return response;
}

static struct json_object *ac_config_poll_handle(
    const char *ap_id, const char *session_epoch,
    const struct ac_radio_job_request *request)
{
    struct ac_config_job job;
    struct json_object *response = NULL;
    char *candidate = NULL;
    int result;

    memset(&job, 0, sizeof(job));
    ac_db_enter();
    result = ac_db_ap_session_is_current(ap_id, session_epoch) ?
        ac_db_config_job_lease_next(ap_id, session_epoch, ac_now_s(), &job,
                                    &candidate) :
        AC_CONFIG_JOB_INVALID;
    ac_db_leave();
    if (result == AC_CONFIG_JOB_NOT_FOUND) {
        response = ac_message_new("config_job_idle");
        if (!response ||
            ac_radio_response_envelope(response, ap_id, session_epoch,
                                       request->sequence) != 0 ||
            ap_control_json_object_exact(response,
                ac_fields_config_job_idle,
                AC_ARRAY_SIZE(ac_fields_config_job_idle),
                ac_fields_config_job_idle,
                AC_ARRAY_SIZE(ac_fields_config_job_idle)) !=
                AP_CONTROL_WIRE_OK) {
            json_object_put(response);
            return NULL;
        }
        return response;
    }
    if (result != AC_CONFIG_JOB_OK)
        return ac_radio_error_new(ap_id, session_epoch, request->sequence,
                                  "invalid_session", "session_not_current");
    response = ac_message_new("config_job_offer");
    if (!response ||
        ac_radio_response_envelope(response, ap_id, session_epoch,
                                   request->sequence) != 0 ||
        ac_config_job_identity_add(response, &job) != 0 ||
        ac_json_add_string(response, "candidate_digest",
                           job.candidate_digest) != 0 ||
        ac_json_add_string(response, "candidate", candidate) != 0 ||
        ac_json_add_string(response, "controller_state", job.state) != 0 ||
        ap_control_json_object_exact(response, ac_fields_config_job_offer,
            AC_ARRAY_SIZE(ac_fields_config_job_offer),
            ac_fields_config_job_offer,
            AC_ARRAY_SIZE(ac_fields_config_job_offer)) !=
            AP_CONTROL_WIRE_OK) {
        json_object_put(response);
        free(candidate);
        return NULL;
    }
    free(candidate);
    return response;
}

static struct json_object *ac_config_accept_handle(
    const char *ap_id, const char *session_epoch,
    const struct ac_radio_job_request *request)
{
    struct ac_config_job job;
    int result;

    memset(&job, 0, sizeof(job));
    ac_db_enter();
    result = ac_db_config_job_mark_running(request->job_id,
        request->attempt_id, request->dispatch_generation,
        request->request_digest, ap_id, session_epoch, ac_now_s(), &job);
    ac_db_leave();
    if (result != AC_CONFIG_JOB_OK && result != AC_CONFIG_JOB_IDEMPOTENT)
        return ac_radio_error_new(ap_id, session_epoch, request->sequence,
                                  "job_conflict",
                                  "config_job_assignment_not_current");
    return ac_config_ack_new("config_job_accept_ack", ap_id, session_epoch,
        request->sequence, &job, ac_fields_config_job_ack,
        AC_ARRAY_SIZE(ac_fields_config_job_ack), NULL);
}

static struct json_object *ac_config_finish_handle(
    struct json_object *message, const char *ap_id,
    const char *session_epoch, const struct ac_radio_job_request *request)
{
    struct ac_config_job job;
    const char *finish_id = NULL;
    const char *outcome = NULL;
    const char *error_code = NULL;
    const char *readback = NULL;
    int result;

    memset(&job, 0, sizeof(job));
    if (ap_control_json_get_string(message, "finish_id", &finish_id, 36,
            36) != AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(message, "outcome", &outcome, 6, 11) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(message, "error_code", &error_code, 0,
            AC_RADIO_JOB_ERROR_MAX) != AP_CONTROL_WIRE_OK ||
        ap_control_json_get_string(message, "readback", &readback, 0,
            AC_CONFIG_JOB_READBACK_MAX_BYTES) != AP_CONTROL_WIRE_OK)
        return NULL;
    ac_db_enter();
    result = ac_db_config_job_finish(request->job_id, request->attempt_id,
        request->dispatch_generation, request->request_digest, ap_id,
        session_epoch, finish_id, outcome, error_code, readback,
        ac_now_s(), &job);
    ac_db_leave();
    if (result != AC_CONFIG_JOB_OK && result != AC_CONFIG_JOB_IDEMPOTENT)
        return ac_radio_error_new(ap_id, session_epoch, request->sequence,
                                  "job_conflict",
                                  "config_job_finish_rejected");
    return ac_config_ack_new("config_job_finish_ack", ap_id, session_epoch,
        request->sequence, &job, ac_fields_config_job_finish_ack,
        AC_ARRAY_SIZE(ac_fields_config_job_finish_ack), job.finish_id);
}

static struct json_object *ac_radio_message_handle(
    struct json_object *message, const char *kind, const char *ap_id,
    const char *session_epoch, struct ac_radio_job_request *request)
{
    if (!strcmp(kind, "radio_job_poll")) {
        if (ac_radio_common_parse(message, ac_fields_radio_job_poll,
                AC_ARRAY_SIZE(ac_fields_radio_job_poll), kind, ap_id,
                session_epoch, 0, request) != 0)
            return NULL;
        return ac_radio_poll_handle(ap_id, session_epoch, request);
    }
    if (!strcmp(kind, "radio_job_accept") || !strcmp(kind, "radio_job_start")) {
        if (ac_radio_common_parse(message, ac_fields_radio_job_identity,
                AC_ARRAY_SIZE(ac_fields_radio_job_identity), kind, ap_id,
                session_epoch, 1, request) != 0)
            return NULL;
        return !strcmp(kind, "radio_job_accept") ?
            ac_radio_accept_handle(ap_id, session_epoch, request) :
            ac_radio_start_handle(ap_id, session_epoch, request);
    }
    if (!strcmp(kind, "radio_job_reconcile")) {
        if (ac_radio_common_parse(message, ac_fields_radio_job_reconcile,
                AC_ARRAY_SIZE(ac_fields_radio_job_reconcile), kind, ap_id,
                session_epoch, 1, request) != 0)
            return NULL;
        return ac_radio_reconcile_handle(message, ap_id, session_epoch, request);
    }
    if (!strcmp(kind, "radio_job_finish")) {
        if (ac_radio_common_parse(message, ac_fields_radio_job_finish,
                AC_ARRAY_SIZE(ac_fields_radio_job_finish), kind, ap_id,
                session_epoch, 1, request) != 0)
            return NULL;
        return ac_radio_finish_handle(message, ap_id, session_epoch, request);
    }
    if (!strcmp(kind, "config_job_poll")) {
        if (ac_radio_common_parse(message, ac_fields_config_job_poll,
                AC_ARRAY_SIZE(ac_fields_config_job_poll), kind, ap_id,
                session_epoch, 0, request) != 0)
            return NULL;
        return ac_config_poll_handle(ap_id, session_epoch, request);
    }
    if (!strcmp(kind, "config_job_accept")) {
        if (ac_radio_common_parse(message, ac_fields_config_job_identity,
                AC_ARRAY_SIZE(ac_fields_config_job_identity), kind, ap_id,
                session_epoch, 1, request) != 0)
            return NULL;
        return ac_config_accept_handle(ap_id, session_epoch, request);
    }
    if (!strcmp(kind, "config_job_finish")) {
        if (ac_radio_common_parse(message, ac_fields_config_job_finish,
                AC_ARRAY_SIZE(ac_fields_config_job_finish), kind, ap_id,
                session_epoch, 1, request) != 0)
            return NULL;
        return ac_config_finish_handle(message, ap_id, session_epoch,
                                       request);
    }
    return NULL;
}

static void ac_radio_replay_clear(struct ac_radio_job_replay *replay)
{
    if (!replay)
        return;
    json_object_put(replay->response);
    OPENSSL_cleanse(replay, sizeof(*replay));
}

static int ac_handle_session(SSL *ssl, struct json_object *hello,
                             const struct ac_transport_peer *peer)
{
    struct json_object *response = NULL;
    struct json_object *message = NULL;
    struct json_object *snapshot = NULL;
    const char *kind = NULL;
    const char *message_epoch = NULL;
    char controller_id[37] = {0};
    char enrollment_id[37] = {0};
    char certificate_id[37] = {0};
    char ap_id[37] = {0};
    char heartbeat_ap_id[37] = {0};
    char session_epoch[65] = {0};
    char snapshot_id[72] = {0};
    unsigned char session_epoch_raw[32];
    struct ac_device_model_report model_report;
    struct ac_radio_job_replay radio_replay;
    int64_t sequence = 0;
    int64_t previous_sequence = -1;
    int64_t observed_at = 0;
    int64_t timestamp = 0;
    int rc = -1;

    memset(&model_report, 0, sizeof(model_report));
    memset(&radio_replay, 0, sizeof(radio_replay));
    memset(session_epoch_raw, 0, sizeof(session_epoch_raw));

    if (ac_identity_hello_parse(hello, ac_fields_session_hello,
            AC_ARRAY_SIZE(ac_fields_session_hello), "session_hello", 0,
            controller_id, enrollment_id, certificate_id, ap_id) != 0) {
        ac_transport_log_stage("session_rejected", "hello");
        goto denied;
    }
    if (!ac_peer_authorize(certificate_id, ap_id, peer, 1)) {
        ac_transport_log_stage("session_rejected", "authorize");
        goto denied;
    }
    if (RAND_bytes(session_epoch_raw, sizeof(session_epoch_raw)) != 1 ||
        ap_control_hex_encode(session_epoch_raw, sizeof(session_epoch_raw),
                              session_epoch, sizeof(session_epoch)) !=
            AP_CONTROL_WIRE_OK) {
        ac_transport_log_stage("session_rejected", "epoch_generate");
        goto done;
    }
    ac_db_enter();
    if (ac_db_ap_session_begin(ap_id, session_epoch,
            !strcmp(g_ac_wire_protocol, AC_TRANSPORT_PROTOCOL_V2) ? 2 : 1,
            ac_now_s()) != 0) {
        ac_db_leave();
        ac_transport_log_stage("session_rejected", "epoch_store");
        goto done;
    }
    ac_db_leave();
    response = ac_message_new("session_ready");
    if (!response || ac_json_add_string(response, "controller_id",
                ac_pki_controller_id(g_ac_transport.pki)) != 0 ||
        ac_json_add_string(response, "certificate_id", certificate_id) != 0 ||
        ac_json_add_string(response, "ap_id", ap_id) != 0 ||
        ac_json_add_string(response, "session_epoch", session_epoch) != 0 ||
        ap_control_json_object_exact(response, ac_fields_session_ready,
                AC_ARRAY_SIZE(ac_fields_session_ready),
                ac_fields_session_ready,
                AC_ARRAY_SIZE(ac_fields_session_ready)) !=
            AP_CONTROL_WIRE_OK ||
        ap_control_ssl_write_json(ssl, AP_CONTROL_IO_TIMEOUT_MS, response) !=
            AP_CONTROL_WIRE_OK) {
        ac_transport_log_stage("session_rejected", "ready_write");
        goto done;
    }
    json_object_put(response);
    response = NULL;
    while (!ac_transport_stopping()) {
        if (ac_wait_for_frame(ssl, AC_TRANSPORT_HEARTBEAT_IDLE_MS) != 0) {
            ac_transport_log_stage("session_closed", "frame_wait");
            goto done;
        }
        if (ap_control_ssl_read_json(ssl, AP_CONTROL_IO_TIMEOUT_MS,
                                     &message) != AP_CONTROL_WIRE_OK) {
            ac_transport_log_stage("session_closed", "frame_read");
            goto done;
        }
        if (ac_message_kind(message, &kind) != 0) {
            ac_transport_log_stage("session_closed", "frame_kind");
            goto done;
        }
        if (!strcmp(g_ac_wire_protocol, AC_TRANSPORT_PROTOCOL_V2) &&
            (!strncmp(kind, "radio_job_", strlen("radio_job_")) ||
             !strncmp(kind, "config_job_", strlen("config_job_")))) {
            struct ac_radio_job_request radio_request;
            unsigned char request_sha256[SHA256_DIGEST_LENGTH];
            const char *envelope_ap_id = NULL;
            const char *envelope_epoch = NULL;
            int duplicate;

            memset(&radio_request, 0, sizeof(radio_request));
            memset(request_sha256, 0, sizeof(request_sha256));
            if (ac_radio_request_sha256(message, request_sha256) != 0 ||
                ap_control_json_get_int64(message, "sequence", 1, INT64_MAX,
                    &radio_request.sequence) != AP_CONTROL_WIRE_OK) {
                ac_transport_log_stage("radio_job_rejected", "sequence");
                goto denied;
            }
            if (ap_control_json_get_string(message, "ap_id", &envelope_ap_id,
                    36, 36) != AP_CONTROL_WIRE_OK ||
                ap_control_json_get_string(message, "session_epoch",
                    &envelope_epoch, 64, 64) != AP_CONTROL_WIRE_OK ||
                strcmp(envelope_ap_id, ap_id) ||
                strcmp(envelope_epoch, session_epoch)) {
                response = ac_radio_error_new(ap_id, session_epoch,
                    radio_request.sequence, "invalid_session",
                    "session_not_current");
                if (!response || ap_control_ssl_write_json(ssl,
                        AP_CONTROL_IO_TIMEOUT_MS, response) !=
                            AP_CONTROL_WIRE_OK) {
                    OPENSSL_cleanse(request_sha256,
                                    sizeof(request_sha256));
                    goto done;
                }
                OPENSSL_cleanse(request_sha256, sizeof(request_sha256));
                goto done;
            }
            if (!ac_peer_authorize(certificate_id, ap_id, peer, 1)) {
                response = ac_radio_error_new(ap_id, session_epoch,
                    radio_request.sequence, "invalid_session",
                    "certificate_not_authorized");
                if (response)
                    (void)ap_control_ssl_write_json(
                        ssl, AP_CONTROL_IO_TIMEOUT_MS, response);
                OPENSSL_cleanse(request_sha256, sizeof(request_sha256));
                goto done;
            }
            duplicate = radio_replay.valid &&
                radio_request.sequence == radio_replay.sequence;
            if (duplicate) {
                if (CRYPTO_memcmp(request_sha256, radio_replay.request_sha256,
                                  sizeof(request_sha256)) != 0) {
                    response = ac_radio_error_new(ap_id, session_epoch,
                        radio_request.sequence, "sequence_conflict",
                        "sequence_payload_changed");
                    if (response)
                        (void)ap_control_ssl_write_json(
                            ssl, AP_CONTROL_IO_TIMEOUT_MS, response);
                    OPENSSL_cleanse(request_sha256, sizeof(request_sha256));
                    goto done;
                }
                if (!radio_replay.response ||
                    ap_control_ssl_write_json(ssl, AP_CONTROL_IO_TIMEOUT_MS,
                                              radio_replay.response) !=
                        AP_CONTROL_WIRE_OK) {
                    ac_transport_log_stage("radio_job_rejected",
                                           "sequence_conflict");
                    goto denied;
                }
                json_object_put(message);
                message = NULL;
                OPENSSL_cleanse(request_sha256, sizeof(request_sha256));
                continue;
            }
            if (radio_request.sequence <= previous_sequence) {
                ac_transport_log_stage("radio_job_rejected",
                                       "sequence_rollback");
                response = ac_radio_error_new(ap_id, session_epoch,
                    radio_request.sequence, "sequence_rollback",
                    "sequence_must_increase");
                if (response)
                    (void)ap_control_ssl_write_json(
                        ssl, AP_CONTROL_IO_TIMEOUT_MS, response);
                OPENSSL_cleanse(request_sha256, sizeof(request_sha256));
                goto done;
            }
            response = ac_radio_message_handle(message, kind, ap_id,
                                               session_epoch, &radio_request);
            if (!response) {
                response = ac_radio_error_new(ap_id, session_epoch,
                    radio_request.sequence, "invalid_request",
                    "radio_job_request_rejected");
            }
            if (!response ||
                ap_control_ssl_write_json(ssl, AP_CONTROL_IO_TIMEOUT_MS,
                                          response) != AP_CONTROL_WIRE_OK) {
                OPENSSL_cleanse(request_sha256, sizeof(request_sha256));
                goto done;
            }
            ac_radio_replay_clear(&radio_replay);
            radio_replay.valid = 1;
            radio_replay.sequence = radio_request.sequence;
            memcpy(radio_replay.request_sha256, request_sha256,
                   sizeof(request_sha256));
            radio_replay.response = json_object_get(response);
            previous_sequence = radio_request.sequence;
            json_object_put(message);
            json_object_put(response);
            message = NULL;
            response = NULL;
            OPENSSL_cleanse(request_sha256, sizeof(request_sha256));
            continue;
        }
        memset(heartbeat_ap_id, 0, sizeof(heartbeat_ap_id));
        if (!strcmp(kind, "telemetry_snapshot")) {
            memset(snapshot_id, 0, sizeof(snapshot_id));
            memset(&model_report, 0, sizeof(model_report));
            if (ac_telemetry_snapshot_parse(message, ap_id, session_epoch,
                    previous_sequence,
                    &sequence, &observed_at, snapshot_id, &model_report,
                    &snapshot) != 0)
                goto denied;
            if (!ac_peer_authorize(certificate_id, ap_id, peer, 1)) {
                ac_transport_log_stage("telemetry_rejected", "authorize");
                goto denied;
            }
            ac_db_enter();
            if (ac_db_ap_telemetry_store(ap_id, session_epoch, sequence,
                    observed_at,
                    ac_now_s(), snapshot_id, &model_report, snapshot) != 0) {
                ac_db_leave();
                ac_transport_log_stage("telemetry_rejected", "store");
                goto done;
            }
            ac_db_leave();
            previous_sequence = sequence;
            json_object_put(message);
            message = NULL;
            snapshot = NULL;
            response = ac_message_new("telemetry_ack");
            if (!response || ac_json_add_string(response, "ap_id", ap_id) != 0 ||
                ac_json_add_string(response, "session_epoch", session_epoch) != 0 ||
                ac_json_add_int64(response, "sequence", sequence) != 0) {
                ac_transport_log_stage("telemetry_rejected", "ack_build");
                goto done;
            }
            json_object_object_add(response, "accepted",
                                   json_object_new_boolean(1));
            if (ap_control_json_object_exact(response, ac_fields_telemetry_ack,
                    AC_ARRAY_SIZE(ac_fields_telemetry_ack),
                    ac_fields_telemetry_ack,
                    AC_ARRAY_SIZE(ac_fields_telemetry_ack)) !=
                    AP_CONTROL_WIRE_OK ||
                ap_control_ssl_write_json(ssl, AP_CONTROL_IO_TIMEOUT_MS,
                                          response) != AP_CONTROL_WIRE_OK) {
                ac_transport_log_stage("telemetry_rejected", "ack_write");
                goto done;
            }
            json_object_put(response);
            response = NULL;
            continue;
        }
        if (strcmp(kind, "heartbeat") != 0 ||
            ac_message_expect(message, ac_fields_heartbeat,
                AC_ARRAY_SIZE(ac_fields_heartbeat), "heartbeat") != 0 ||
            ac_json_copy_string(message, "ap_id", heartbeat_ap_id,
                                sizeof(heartbeat_ap_id), 36, 36) != 0 ||
            strcmp(heartbeat_ap_id, ap_id) != 0 ||
            ap_control_json_get_string(message, "session_epoch", &message_epoch,
                64, 64) != AP_CONTROL_WIRE_OK ||
            strcmp(message_epoch, session_epoch) != 0 ||
            ap_control_json_get_int64(message, "sequence", 0, INT64_MAX,
                                      &sequence) != AP_CONTROL_WIRE_OK ||
            ap_control_json_get_int64(message, "timestamp", 1, INT64_MAX,
                                      &timestamp) != AP_CONTROL_WIRE_OK ||
            sequence <= previous_sequence ||
            !ac_peer_authorize(certificate_id, ap_id, peer, 1))
            goto denied;
        /* AP clocks are not authoritative for controller-side liveness. */
        (void)timestamp;
        ac_db_enter();
        if (ac_db_ap_heartbeat(ap_id, session_epoch, ac_now_s()) != 0) {
            ac_db_leave();
            goto done;
        }
        ac_db_leave();
        previous_sequence = sequence;
        json_object_put(message);
        message = NULL;
        response = ac_message_new("heartbeat_ack");
        if (!response || ac_json_add_string(response, "ap_id", ap_id) != 0 ||
            ac_json_add_string(response, "session_epoch", session_epoch) != 0 ||
            ac_json_add_int64(response, "sequence", sequence) != 0 ||
            ap_control_json_object_exact(response, ac_fields_heartbeat_ack,
                    AC_ARRAY_SIZE(ac_fields_heartbeat_ack),
                    ac_fields_heartbeat_ack,
                    AC_ARRAY_SIZE(ac_fields_heartbeat_ack)) !=
                AP_CONTROL_WIRE_OK ||
            ap_control_ssl_write_json(ssl, AP_CONTROL_IO_TIMEOUT_MS,
                                      response) != AP_CONTROL_WIRE_OK)
            goto done;
        json_object_put(response);
        response = NULL;
    }
    rc = 0;
    goto done;
denied:
    ac_send_error(ssl, "session_denied", "certificate_not_authorized");
done:
    if (ap_id[0] && session_epoch[0]) {
        ac_db_enter();
        (void)ac_db_ap_session_end(ap_id, session_epoch);
        ac_db_leave();
    }
    json_object_put(message);
    json_object_put(response);
    ac_radio_replay_clear(&radio_replay);
    OPENSSL_cleanse(&model_report, sizeof(model_report));
    OPENSSL_cleanse(session_epoch_raw, sizeof(session_epoch_raw));
    OPENSSL_cleanse(session_epoch, sizeof(session_epoch));
    return rc;
}

static void ac_connection_run(int fd)
{
    struct ac_transport_peer peer;
    struct json_object *message = NULL;
    const char *kind = NULL;
    SSL *ssl = NULL;

    memset(&peer, 0, sizeof(peer));
    ssl = SSL_new(g_ac_transport.ssl_context);
    if (!ssl) {
        ac_transport_log_stage("connection_rejected", "ssl_new");
        goto done;
    }
    if (SSL_set_fd(ssl, fd) != 1) {
        ac_transport_log_stage("connection_rejected", "ssl_fd");
        goto done;
    }
    if (ap_control_ssl_handshake(ssl, 1, AP_CONTROL_IO_TIMEOUT_MS) !=
            AP_CONTROL_WIRE_OK) {
        ac_transport_log_stage("connection_rejected", "tls_handshake");
        goto done;
    }
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        ac_transport_log_stage("connection_rejected", "tls_verify");
        goto done;
    }
    if (!ap_control_ssl_selected_alpn(ssl)) {
        ac_transport_log_stage("connection_rejected", "alpn");
        goto done;
    }
    g_ac_wire_protocol = ap_control_ssl_selected_alpn_version(ssl) == 2 ?
        AC_TRANSPORT_PROTOCOL_V2 : AC_TRANSPORT_PROTOCOL_V1;
    if (ac_peer_identity(ssl, &peer) != 0) {
        ac_transport_log_stage("connection_rejected", "peer_identity");
        goto done;
    }
    if (ap_control_ssl_read_json(ssl, AP_CONTROL_IO_TIMEOUT_MS, &message) !=
            AP_CONTROL_WIRE_OK) {
        ac_transport_log_stage("connection_rejected", "hello_read");
        goto done;
    }
    if (ac_message_kind(message, &kind) != 0) {
        ac_transport_log_stage("connection_rejected", "hello_kind");
        goto done;
    }
    if (!strcmp(g_ac_wire_protocol, AC_TRANSPORT_PROTOCOL_V2) &&
        strcmp(kind, "session_hello"))
        ac_send_error(ssl, "invalid_request", "v2_requires_adopted_session");
    else if (!strcmp(kind, "enrollment_hello"))
        ac_handle_enrollment(ssl, message, &peer);
    else if (!strcmp(kind, "activation_hello") && peer.certificate_present)
        ac_handle_activation(ssl, message, &peer);
    else if (!strcmp(kind, "session_hello") && peer.certificate_present)
        ac_handle_session(ssl, message, &peer);
    else
        ac_send_error(ssl, "invalid_request", "message_kind_not_allowed");
done:
    json_object_put(message);
    if (ssl)
        SSL_shutdown(ssl);
    SSL_free(ssl);
    g_ac_wire_protocol = AC_TRANSPORT_PROTOCOL_V1;
    OPENSSL_cleanse(&peer, sizeof(peer));
}

static void *ac_worker_main(void *opaque)
{
    size_t index = (size_t)(uintptr_t)opaque;

    for (;;) {
        int fd = -1;

        pthread_mutex_lock(&g_ac_transport.lock);
        while (!g_ac_transport.stopping && g_ac_transport.queue_count == 0)
            pthread_cond_wait(&g_ac_transport.queue_changed,
                              &g_ac_transport.lock);
        if (g_ac_transport.stopping) {
            pthread_mutex_unlock(&g_ac_transport.lock);
            break;
        }
        fd = g_ac_transport.queue[g_ac_transport.queue_head];
        g_ac_transport.queue_head =
            (g_ac_transport.queue_head + 1) % AC_TRANSPORT_QUEUE_MAX;
        g_ac_transport.queue_count--;
        g_ac_transport.worker_fd[index] = fd;
        pthread_mutex_unlock(&g_ac_transport.lock);

        ac_connection_run(fd);
        close(fd);
        pthread_mutex_lock(&g_ac_transport.lock);
        if (g_ac_transport.worker_fd[index] == fd)
            g_ac_transport.worker_fd[index] = -1;
        pthread_mutex_unlock(&g_ac_transport.lock);
    }
    return NULL;
}

static int ac_accept_rate_allowed(unsigned int *tokens, int64_t *updated_ms)
{
    int64_t now = ac_transport_monotonic_ms();
    uint64_t elapsed;
    uint64_t refill;

    if (!tokens || !updated_ms || now < 0)
        return 0;
    if (*updated_ms <= 0)
        *updated_ms = now;
    elapsed = now > *updated_ms ? (uint64_t)(now - *updated_ms) : 0;
    refill = elapsed * AC_TRANSPORT_ACCEPT_PER_SECOND / 1000U;
    if (refill > 0) {
        uint64_t available = *tokens + refill;

        *tokens = available > AC_TRANSPORT_ACCEPT_BURST ?
            AC_TRANSPORT_ACCEPT_BURST : (unsigned int)available;
        *updated_ms = now;
    }
    if (*tokens == 0)
        return 0;
    (*tokens)--;
    return 1;
}

static int ac_socket_nonblocking(int fd)
{
    int flags;

    if (fd < 0 || (flags = fcntl(fd, F_GETFL, 0)) < 0 ||
        fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0 ||
        fcntl(fd, F_SETFD, FD_CLOEXEC) != 0)
        return -1;
    return 0;
}

static void *ac_accept_main(void *opaque)
{
    unsigned int tokens = AC_TRANSPORT_ACCEPT_BURST;
    int64_t updated_ms = ac_transport_monotonic_ms();

    (void)opaque;
    while (!ac_transport_stopping()) {
        struct pollfd descriptor;
        int listen_fd;
        int result;
        int fd;

        pthread_mutex_lock(&g_ac_transport.lock);
        listen_fd = g_ac_transport.listen_fd;
        pthread_mutex_unlock(&g_ac_transport.lock);
        if (listen_fd < 0)
            break;
        descriptor.fd = listen_fd;
        descriptor.events = POLLIN;
        descriptor.revents = 0;
        do {
            result = poll(&descriptor, 1, 1000);
        } while (result < 0 && errno == EINTR && !ac_transport_stopping());
        if (result == 0)
            continue;
        if (result < 0 || (descriptor.revents & (POLLERR | POLLNVAL))) {
            if (!ac_transport_stopping()) {
                pthread_mutex_lock(&g_ac_transport.lock);
                g_ac_transport.listening = 0;
                g_ac_transport.reason = "accept_failed";
                pthread_mutex_unlock(&g_ac_transport.lock);
            }
            break;
        }
        fd = accept(listen_fd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            if (!ac_transport_stopping()) {
                pthread_mutex_lock(&g_ac_transport.lock);
                g_ac_transport.listening = 0;
                g_ac_transport.reason = "accept_failed";
                pthread_mutex_unlock(&g_ac_transport.lock);
            }
            break;
        }
        if (ac_socket_nonblocking(fd) != 0 ||
            !ac_accept_rate_allowed(&tokens, &updated_ms)) {
            close(fd);
            continue;
        }
        pthread_mutex_lock(&g_ac_transport.lock);
        if (g_ac_transport.stopping ||
            g_ac_transport.queue_count >= AC_TRANSPORT_QUEUE_MAX) {
            pthread_mutex_unlock(&g_ac_transport.lock);
            close(fd);
            continue;
        }
        g_ac_transport.queue[(g_ac_transport.queue_head +
                              g_ac_transport.queue_count) %
                             AC_TRANSPORT_QUEUE_MAX] = fd;
        g_ac_transport.queue_count++;
        pthread_cond_signal(&g_ac_transport.queue_changed);
        pthread_mutex_unlock(&g_ac_transport.lock);
    }
    return NULL;
}

static int ac_listen_port_parse(void)
{
    const char *value = getenv("DREAMINGWRT_AC_LISTEN_PORT");
    char *end = NULL;
    long port;

    if (!value || !value[0])
        return AC_TRANSPORT_DEFAULT_PORT;
    errno = 0;
    port = strtol(value, &end, 10);
    if (errno || !end || *end || port < 0 || port > 65535)
        return -1;
    return (int)port;
}

static int ac_listener_open(int requested_port, int *actual_port)
{
    const char *configured = getenv("DREAMINGWRT_AC_LISTEN_ADDR");
    const char *address = configured && configured[0] ? configured : "0.0.0.0";
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    struct addrinfo *candidate;
    char service[6];
    int fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
    snprintf(service, sizeof(service), "%d", requested_port);
    if (requested_port < 0 || !actual_port ||
        getaddrinfo(address, service, &hints, &addresses) != 0)
        return -1;
    for (candidate = addresses; candidate; candidate = candidate->ai_next) {
        int reuse = 1;

        fd = socket(candidate->ai_family, candidate->ai_socktype,
                    candidate->ai_protocol);
        if (fd < 0)
            continue;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse,
                       sizeof(reuse)) != 0 ||
            ac_socket_nonblocking(fd) != 0 ||
            bind(fd, candidate->ai_addr, candidate->ai_addrlen) != 0 ||
            listen(fd, AC_TRANSPORT_BACKLOG) != 0) {
            close(fd);
            fd = -1;
            continue;
        }
        break;
    }
    freeaddrinfo(addresses);
    if (fd >= 0) {
        struct sockaddr_storage bound;
        socklen_t bound_length = sizeof(bound);

        if (getsockname(fd, (struct sockaddr *)&bound, &bound_length) != 0) {
            close(fd);
            return -1;
        }
        if (bound.ss_family == AF_INET)
            *actual_port = ntohs(((struct sockaddr_in *)&bound)->sin_port);
        else if (bound.ss_family == AF_INET6)
            *actual_port = ntohs(((struct sockaddr_in6 *)&bound)->sin6_port);
        else {
            close(fd);
            return -1;
        }
    }
    return fd;
}

static void ac_transport_threads_stop(size_t worker_count, int accept_started)
{
    size_t i;

    pthread_mutex_lock(&g_ac_transport.lock);
    g_ac_transport.stopping = 1;
    g_ac_transport.listening = 0;
    if (g_ac_transport.listen_fd >= 0)
        shutdown(g_ac_transport.listen_fd, SHUT_RDWR);
    for (i = 0; i < AC_TRANSPORT_WORKERS_MAX; i++)
        if (g_ac_transport.worker_fd[i] >= 0)
            shutdown(g_ac_transport.worker_fd[i], SHUT_RDWR);
    while (g_ac_transport.queue_count > 0) {
        int fd = g_ac_transport.queue[g_ac_transport.queue_head];

        g_ac_transport.queue_head =
            (g_ac_transport.queue_head + 1) % AC_TRANSPORT_QUEUE_MAX;
        g_ac_transport.queue_count--;
        close(fd);
    }
    pthread_cond_broadcast(&g_ac_transport.queue_changed);
    pthread_mutex_unlock(&g_ac_transport.lock);
    if (accept_started)
        pthread_join(g_ac_transport.accept_thread, NULL);
    for (i = 0; i < worker_count; i++)
        if (g_ac_transport.worker_started[i])
            pthread_join(g_ac_transport.workers[i], NULL);
}

int ac_transport_start(void)
{
    struct ac_pki *pki = NULL;
    SSL_CTX *context = NULL;
    const char *controller_id;
    int requested_port;
    int actual_port = 0;
    int listen_fd = -1;
    size_t workers_started = 0;
    int accept_started = 0;
    size_t i;

    pthread_mutex_lock(&g_ac_transport.lock);
    if (g_ac_transport.running) {
        pthread_mutex_unlock(&g_ac_transport.lock);
        return 0;
    }
    g_ac_transport.reason = "starting";
    pthread_mutex_unlock(&g_ac_transport.lock);
    requested_port = ac_listen_port_parse();
    if (requested_port < 0) {
        ac_transport_set_reason("invalid_listen_port");
        return -1;
    }
    if (ac_pki_init(&pki) != 0 ||
        !(controller_id = ac_pki_controller_id(pki)) ||
        !ac_controller_id_valid(controller_id)) {
        ac_pki_free(pki);
        ac_transport_set_reason("pki_init_failed");
        return -1;
    }
    context = ac_tls_context_new(pki);
    if (!context) {
        ac_pki_free(pki);
        ac_transport_set_reason("tls_context_failed");
        return -1;
    }
    listen_fd = ac_listener_open(requested_port, &actual_port);
    if (listen_fd < 0) {
        SSL_CTX_free(context);
        ac_pki_free(pki);
        ac_transport_set_reason("listen_failed");
        return -1;
    }
    signal(SIGPIPE, SIG_IGN);
    pthread_mutex_lock(&g_ac_transport.lock);
    g_ac_transport.pki = pki;
    g_ac_transport.ssl_context = context;
    g_ac_transport.listen_fd = listen_fd;
    g_ac_transport.port = actual_port;
    g_ac_transport.queue_head = 0;
    g_ac_transport.queue_count = 0;
    g_ac_transport.stopping = 0;
    g_ac_transport.listening = 0;
    for (i = 0; i < AC_TRANSPORT_WORKERS_MAX; i++) {
        g_ac_transport.worker_fd[i] = -1;
        g_ac_transport.worker_started[i] = 0;
    }
    snprintf(g_ac_transport.controller_id,
             sizeof(g_ac_transport.controller_id), "%s", controller_id);
    pthread_mutex_unlock(&g_ac_transport.lock);
    for (i = 0; i < AC_TRANSPORT_WORKERS_MAX; i++) {
        if (pthread_create(&g_ac_transport.workers[i], NULL,
                           ac_worker_main, (void *)(uintptr_t)i) != 0)
            goto thread_fail;
        pthread_mutex_lock(&g_ac_transport.lock);
        g_ac_transport.worker_started[i] = 1;
        pthread_mutex_unlock(&g_ac_transport.lock);
        workers_started++;
    }
    if (pthread_create(&g_ac_transport.accept_thread, NULL,
                       ac_accept_main, NULL) != 0)
        goto thread_fail;
    accept_started = 1;
    pthread_mutex_lock(&g_ac_transport.lock);
    g_ac_transport.running = 1;
    g_ac_transport.listening = 1;
    g_ac_transport.reason = "listening";
    pthread_mutex_unlock(&g_ac_transport.lock);
    ac_transport_log("listening");
    return 0;

thread_fail:
    ac_transport_set_reason("worker_start_failed");
    ac_transport_threads_stop(workers_started, accept_started);
    close(listen_fd);
    pthread_mutex_lock(&g_ac_transport.lock);
    g_ac_transport.listen_fd = -1;
    g_ac_transport.port = 0;
    g_ac_transport.ssl_context = NULL;
    g_ac_transport.pki = NULL;
    pthread_mutex_unlock(&g_ac_transport.lock);
    SSL_CTX_free(context);
    ac_pki_free(pki);
    return -1;
}

void ac_transport_stop(void)
{
    SSL_CTX *context;
    struct ac_pki *pki;
    int listen_fd;
    int running;

    pthread_mutex_lock(&g_ac_transport.lock);
    running = g_ac_transport.running;
    if (running)
        g_ac_transport.reason = "stopping";
    pthread_mutex_unlock(&g_ac_transport.lock);
    if (!running)
        return;
    ac_transport_threads_stop(AC_TRANSPORT_WORKERS_MAX, 1);
    pthread_mutex_lock(&g_ac_transport.lock);
    listen_fd = g_ac_transport.listen_fd;
    context = g_ac_transport.ssl_context;
    pki = g_ac_transport.pki;
    g_ac_transport.listen_fd = -1;
    g_ac_transport.ssl_context = NULL;
    g_ac_transport.pki = NULL;
    g_ac_transport.running = 0;
    g_ac_transport.listening = 0;
    g_ac_transport.stopping = 0;
    g_ac_transport.port = 0;
    g_ac_transport.reason = "stopped";
    pthread_mutex_unlock(&g_ac_transport.lock);
    if (listen_fd >= 0)
        close(listen_fd);
    SSL_CTX_free(context);
    ac_pki_free(pki);
    ac_transport_log("stopped");
}

int ac_transport_listening(void)
{
    int listening;

    pthread_mutex_lock(&g_ac_transport.lock);
    listening = g_ac_transport.listening;
    pthread_mutex_unlock(&g_ac_transport.lock);
    return listening;
}

const char *ac_transport_reason(void)
{
    pthread_mutex_lock(&g_ac_transport.lock);
    snprintf(g_ac_transport_reason_copy, sizeof(g_ac_transport_reason_copy),
             "%s", g_ac_transport.reason ? g_ac_transport.reason : "unknown");
    pthread_mutex_unlock(&g_ac_transport.lock);
    return g_ac_transport_reason_copy;
}

int ac_transport_port(void)
{
    int port;

    pthread_mutex_lock(&g_ac_transport.lock);
    port = g_ac_transport.listening ? g_ac_transport.port : 0;
    pthread_mutex_unlock(&g_ac_transport.lock);
    return port;
}

const char *ac_transport_controller_id(void)
{
    pthread_mutex_lock(&g_ac_transport.lock);
    if (g_ac_transport.listening && g_ac_transport.controller_id[0]) {
        snprintf(g_ac_transport_controller_id_copy,
                 sizeof(g_ac_transport_controller_id_copy), "%s",
                 g_ac_transport.controller_id);
    } else {
        g_ac_transport_controller_id_copy[0] = '\0';
    }
    pthread_mutex_unlock(&g_ac_transport.lock);
    return g_ac_transport_controller_id_copy;
}

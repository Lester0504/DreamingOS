// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_APD_INTERNAL_H
#define DREAMINGWRT_APD_INTERNAL_H

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <sqlite3.h>
#include <uci.h>

#include "apd_radio_job_journal.h"
#include "apd_config_executor.h"
#include "apd_ble.h"
#include "apd_ble_db.h"

#define APD_DB_PATH "/etc/dreamingwrt/apd.db"
#define APD_CONTRACT_VERSION "ap-control.v1"
#define APD_SNAPSHOT_VERSION "wireless-snapshot.v1"
#define APD_SCHEMA_VERSION 3
#define APD_SERVICE_NAME "dreamingwrt-apd"
#define APD_NODE_TRANSPORT_ENABLED 1
#define APD_IDENTITY_KEY_PATH "/etc/dreamingwrt/apd-pki/identity.ed25519"
#define APD_AP_ID_LEN 36
#define APD_ED25519_KEY_LEN 32
#define APD_ED25519_SIGNATURE_LEN 64
#define APD_KEY_ID_LEN 71
#define APD_PAIRING_VALUE_LEN 128
#define APD_ENROLLMENT_CHALLENGE_ID_MAX 36
#define APD_ENROLLMENT_ID_MAX 36
#define APD_ENROLLMENT_TOKEN_ID_MAX 36
#define APD_ENROLLMENT_TOKEN_LEN 43
#define APD_ENROLLMENT_SITE_ID_MAX 64
#define APD_ENROLLMENT_HARDWARE_DIGEST_MAX 71
#define APD_ENROLLMENT_TRANSCRIPT_MAX 1024
#define APD_ENROLLMENT_CSR_DER_MAX 2048
#define APD_CREDENTIALS_UUID_LEN 36
#define APD_CREDENTIALS_TOKEN_LEN 43
#define APD_CREDENTIALS_SITE_MAX 64
#define APD_CREDENTIALS_HOST_MAX 253
#define APD_CREDENTIALS_DIGEST_LEN 71
#define APD_CREDENTIALS_SERIAL_MAX 256
#define APD_DEVICE_MODEL_MAX 255
#define APD_DEVICE_BOARD_NAME_MAX 127
#define APD_DEVICE_MODEL_SOURCE_MAX 63
#define APD_DEVICE_MODEL_REASON_MAX 127
#ifndef APD_UBUS_SOCKET_PATH
#define APD_UBUS_SOCKET_PATH NULL
#endif

int apd_reassoc_block_worker(int fd);
int apd_reassoc_block_release(const char *station_mac);

struct apd_backend_ops {
    const char *name;
    int snapshot_supported;
    int (*probe)(struct json_object **out);
    int (*snapshot)(struct json_object **out);
    /*
     * out is always an object with items[], complete, truncated and
     * error_code. Item field names are the stable neighbor-scan ABI declared
     * by apd_backend_neighbor_scan(), never raw iw keys.
     */
    int (*neighbor_scan)(const char *radio_id, struct json_object **out);
    int (*validate)(struct json_object *candidate, struct json_object **out);
    int (*stage)(struct json_object *candidate, struct json_object **out);
    int (*apply)(struct json_object *candidate, struct json_object **out);
    int (*readback)(struct json_object *candidate, struct json_object **out);
    int (*rollback)(struct json_object *rollback_ref, struct json_object **out);
};

struct apd_device_model {
    char model[APD_DEVICE_MODEL_MAX + 1];
    char board_name[APD_DEVICE_BOARD_NAME_MAX + 1];
    char model_source[APD_DEVICE_MODEL_SOURCE_MAX + 1];
    char reason[APD_DEVICE_MODEL_REASON_MAX + 1];
    int model_available;
};

extern sqlite3 *g_apd_db;
extern struct ubus_context *g_apd_ubus;
extern struct blob_buf g_apd_blob;
extern int64_t g_apd_started_at;

struct apd_node_identity {
    char ap_id[APD_AP_ID_LEN + 1];
    char key_id[APD_KEY_ID_LEN + 1];
    unsigned char public_key[APD_ED25519_KEY_LEN];
    int64_t created_at;
};

struct apd_pairing_status {
    char state[32];
    char controller_id[APD_PAIRING_VALUE_LEN + 1];
    char request_id[APD_PAIRING_VALUE_LEN + 1];
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
    char ca_cert_pem_path[4096];
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
    char ca_cert_pem_path[4096];
    char state[16];
};

int64_t apd_now_s(void);
const char *apd_db_path(void);
int apd_config_restart_recover_default(int *recovered);
const char *apd_identity_key_path(void);
int apd_db_init(void);
void apd_db_close(void);
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
int apd_db_pairing_clear(void);

int apd_ble_db_init(void);
int apd_ble_db_recover(void);

int apd_enrollment_csr_create(unsigned char *csr_der, size_t csr_der_size,
                              size_t *csr_der_len,
                              unsigned char csr_sha256[SHA256_DIGEST_LENGTH]);
int apd_enrollment_transcript_encode_v1(
    const struct apd_enrollment_transcript_v1 *input,
    unsigned char *out, size_t out_size, size_t *out_len);
int apd_enrollment_transcript_sign_v1(
    const struct apd_enrollment_transcript_v1 *input,
    unsigned char signature[APD_ED25519_SIGNATURE_LEN]);
const char *apd_credentials_pki_dir(void);
int apd_credentials_rotation_install(const char *task_id, const char *certificate_id,
    const unsigned char *der, size_t der_len, const char *trust_pem, size_t trust_len);
int apd_credentials_rotation_trust_commit(const char *trust_pem, size_t length);
int apd_credentials_trust_fingerprint(unsigned char out[32]);
int apd_credentials_bootstrap_load(struct apd_bootstrap_config *out);
int apd_credentials_bootstrap_store(const struct apd_bootstrap_config *config);
int apd_credentials_certificate_store(
    const struct apd_credentials_certificate_input *input,
    struct apd_enrollment_metadata *out);
int apd_credentials_validate_startup(struct apd_enrollment_metadata *out);
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
int apd_credentials_activate(
    const char *controller_id, const char *enrollment_id,
    const char *certificate_id,
    const unsigned char certificate_fingerprint[SHA256_DIGEST_LENGTH],
    struct apd_enrollment_metadata *out);

/* Which files an unpair actually destroyed, so callers can report the truth
 * rather than assuming a full teardown happened. */
struct apd_credentials_unpair_report {
    int certificate_removed;
    int enrollment_removed;
    int bootstrap_removed;
};

enum apd_credentials_unpair_result {
    APD_CREDENTIALS_UNPAIR_OK = 0,
    APD_CREDENTIALS_UNPAIR_LOCK_FAILED = -1,
    APD_CREDENTIALS_UNPAIR_CERTIFICATE_FAILED = -2,
    APD_CREDENTIALS_UNPAIR_METADATA_FAILED = -3,
    APD_CREDENTIALS_UNPAIR_BOOTSTRAP_FAILED = -4,
};
int apd_credentials_unpair(struct apd_credentials_unpair_report *out);
void apd_credentials_bootstrap_cleanse(struct apd_bootstrap_config *config);
void apd_credentials_metadata_cleanse(struct apd_enrollment_metadata *metadata);

const struct apd_backend_ops *apd_backend(void);
const struct apd_backend_ops *apd_backend_openwrt(void);
const struct apd_backend_ops *apd_backend_mac80211(void);
int apd_backend_mac80211_detect(void);
int apd_backend_device_model_collect(struct apd_device_model *out);
int apd_backend_neighbor_scan(const char *radio_id, struct json_object **out);
int apd_backend_survey_scan(const char *radio_id, struct json_object **out);
/*
 * Attaches an `iw phy` channel catalogue to each radio, scoped by band.
 *
 * Needed by the mac80211 backend, whose radios all share one wiphy and so
 * cannot be matched by the per-wiphy name the openwrt backend uses. Without a
 * catalogue the controller refuses every radio write with
 * channel_catalog_missing.
 */
void apd_collect_channel_catalogs_by_band(struct json_object *radios,
                                          int64_t observed_at);
struct json_object *apd_backend_disabled(const char *operation,
                                         const char *reason);

struct json_object *apd_local_error(const char *operation, const char *reason);
struct json_object *apd_capabilities_json(void);
struct json_object *apd_status_json(void);
struct json_object *apd_snapshot_json(void);
struct json_object *apd_identity_json(void);
struct json_object *apd_pairing_status_json(void);
struct json_object *apd_write_disabled_json(const char *operation,
                                            const char *reason);
struct json_object *apd_unpair_json(int confirmed);
struct json_object *apd_txpower_mode_json(void);
struct json_object *apd_txpower_mode_set_json(const char *mode,
                                              int confirmed);
int apd_txpower_mode_restore_persisted(void);
int apd_txpower_mode_restore_start(void);
void apd_txpower_mode_restore_stop(void);
int apd_protocol_init(void);
void apd_protocol_close(void);

int apd_transport_start(void);
void apd_transport_stop(void);
int apd_transport_connected(void);
int apd_transport_audit_ready(void);
void apd_transport_wake(void);
int apd_transport_adopted(void);
const char *apd_transport_reason(void);

int apd_ubus_start(void);
void apd_ubus_stop(void);
/* Item 6: subscribe to hostapd key-mismatch (SAE + PSK auth failures). */
int apd_hostapd_keymismatch_subscribe_start(struct ubus_context *ctx);

#endif

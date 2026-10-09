// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_APD_BLE_H
#define DREAMINGWRT_APD_BLE_H

#include <stddef.h>
#include <stdint.h>

#define APD_BLE_PROTOCOL_VERSION 1
#define APD_BLE_SERVICE_UUID "4414ef94-5e5c-468a-bd55-712ac311845a"
#define APD_BLE_DEVICE_INFO_UUID "9074e826-cef1-4af5-9e14-6104cbd435fa"
#define APD_BLE_CONTROL_UUID "c1ac411b-995a-4ef6-81ba-2b1e9cc6912c"
#define APD_BLE_EVENTS_UUID "41227bd1-5ea8-4238-9595-9678dde4a8aa"
#define APD_BLE_TTY_DEFAULT "/dev/ttyS1"
#define APD_BLE_BAUD_DEFAULT 115200U

#define APD_BLE_SESSION_ID_LEN 16U
#define APD_BLE_REQUEST_ID_LEN 16U
#define APD_BLE_X25519_KEY_LEN 32U
#define APD_BLE_NONCE_LEN 12U
#define APD_BLE_BOOTSTRAP_NONCE_LEN 32U
#define APD_BLE_KEY_LEN 32U
#define APD_BLE_TAG_LEN 16U
#define APD_BLE_MTU 247U
#define APD_BLE_MAX_FRAME 244U
#define APD_BLE_FRAME_HEADER_LEN 66U
#define APD_BLE_MAX_FRAGMENT_PLAINTEXT \
    (APD_BLE_MAX_FRAME - APD_BLE_FRAME_HEADER_LEN - APD_BLE_TAG_LEN)
#define APD_BLE_MAX_REQUEST 16384U
#define APD_BLE_MAX_FRAGMENTS \
    ((APD_BLE_MAX_REQUEST + APD_BLE_MAX_FRAGMENT_PLAINTEXT - 1U) / \
     APD_BLE_MAX_FRAGMENT_PLAINTEXT)

/* GATT control-plane commands.  These are deliberately separate from the
 * encrypted DWBL frame: DWBG creates the session on the AP reached by BLE,
 * and DWHS binds the app key before any credentials are accepted. */
#define APD_BLE_GATT_BEGIN_MAGIC "DWBG"
#define APD_BLE_GATT_RESPONSE_MAGIC "DWBR"
#define APD_BLE_GATT_PHYSICAL_CONFIRM_MAGIC "DWPC"
#define APD_BLE_GATT_COMMIT_MAGIC "DWCM"
#define APD_BLE_GATT_CANCEL_MAGIC "DWCA"
#define APD_BLE_GATT_STATUS_MAGIC "DWST"
#define APD_BLE_GATT_PHYSICAL_PROOF_DOMAIN \
    "DreamingWrt-BLE-physical-confirm-v1"
#define APD_BLE_GATT_RESPONSE_HEADER_LEN 8U
#define APD_BLE_GATT_RESPONSE_BEGIN_COMMAND 1U
#define APD_BLE_GATT_RESPONSE_PHYSICAL_CONFIRM_COMMAND 2U
#define APD_BLE_GATT_RESPONSE_STATUS_COMMAND 3U
#define APD_BLE_GATT_RESPONSE_COMMIT_COMMAND 4U
#define APD_BLE_GATT_RESPONSE_CANCEL_COMMAND 5U
#define APD_BLE_GATT_RESPONSE_OK 0U
#define APD_BLE_GATT_BEGIN_RESPONSE_CHALLENGE_LEN 32U
#define APD_BLE_GATT_PHYSICAL_PROOF_LEN 32U
#define APD_BLE_GATT_STATUS_INVALID_ARGUMENT 1U
#define APD_BLE_GATT_STATUS_IDENTITY_UNAVAILABLE 2U
#define APD_BLE_GATT_STATUS_BUSY 3U
#define APD_BLE_GATT_STATUS_TARGET_MISMATCH 4U
#define APD_BLE_GATT_STATUS_PHYSICAL_AUTH_REQUIRED 5U
#define APD_BLE_GATT_STATUS_SETUP_CODE_INVALID 6U
#define APD_BLE_GATT_STATUS_SESSION_NOT_FOUND 7U
#define APD_BLE_GATT_STATUS_SESSION_EXPIRED 8U
#define APD_BLE_GATT_STATUS_OPERATION_REJECTED 9U
#define APD_BLE_GATT_STATUS_UNAVAILABLE 10U
#define APD_BLE_GATT_STATUS_INTERNAL 11U
#define APD_BLE_GATT_STATE_IDLE 0U
#define APD_BLE_GATT_STATE_FACTORY 1U
#define APD_BLE_GATT_STATE_UNBOUND 2U
#define APD_BLE_GATT_STATE_PROVISIONING 3U
#define APD_BLE_GATT_STATE_COMPLETE 4U
#define APD_BLE_GATT_STATE_FAILED 5U
#define APD_BLE_GATT_STATE_CANCELLED 6U
#define APD_BLE_GATT_STATE_EXPIRED 7U
#define APD_BLE_GATT_BEGIN_LEN (4U + 1U + 1U + APD_BLE_REQUEST_ID_LEN + \
                               APD_BLE_X25519_KEY_LEN)
#define APD_BLE_GATT_BEGIN_RESPONSE_LEN \
    (APD_BLE_GATT_RESPONSE_HEADER_LEN + APD_BLE_SESSION_ID_LEN + \
     APD_BLE_REQUEST_ID_LEN + APD_BLE_REQUEST_ID_LEN + \
     APD_BLE_X25519_KEY_LEN + APD_BLE_BOOTSTRAP_NONCE_LEN + \
     APD_BLE_GATT_BEGIN_RESPONSE_CHALLENGE_LEN + 8U)
#define APD_BLE_GATT_BEGIN_RESPONSE_PHYSICAL_REQUIRED 0x01U
#define APD_BLE_GATT_ACTION_LEN \
    (4U + 1U + 1U + APD_BLE_SESSION_ID_LEN)
#define APD_BLE_GATT_PHYSICAL_CONFIRM_LEN \
    (APD_BLE_GATT_ACTION_LEN + APD_BLE_GATT_PHYSICAL_PROOF_LEN)
#define APD_BLE_GATT_ACTION_RESPONSE_LEN \
    (APD_BLE_GATT_RESPONSE_HEADER_LEN + APD_BLE_SESSION_ID_LEN)
#define APD_BLE_GATT_STATUS_RESPONSE_LEN \
    (APD_BLE_GATT_RESPONSE_HEADER_LEN + APD_BLE_SESSION_ID_LEN + 1U + 1U + 8U)

enum apd_ble_result {
    APD_BLE_OK = 0,
    APD_BLE_ERR_ARGUMENT = -1,
    APD_BLE_ERR_CRYPTO = -2,
    APD_BLE_ERR_FRAME = -3,
    APD_BLE_ERR_AUTH = -4,
    APD_BLE_ERR_REPLAY = -5,
    APD_BLE_ERR_EXPIRED = -6,
    APD_BLE_ERR_PHYSICAL_AUTH_REQUIRED = -7,
    APD_BLE_ERR_BUSY = -8,
    APD_BLE_ERR_CONFLICT = -9,
    APD_BLE_ERR_NOT_FOUND = -10,
    APD_BLE_ERR_INVALID_REQUEST = -11,
    APD_BLE_ERR_UNAVAILABLE = -12,
};

/* X25519 and HKDF-SHA256 are kept in this standalone layer so the wire
 * contract can be tested without booting APD or touching a live database. */
int apd_ble_x25519_keypair(unsigned char private_key[APD_BLE_X25519_KEY_LEN],
                           unsigned char public_key[APD_BLE_X25519_KEY_LEN]);
int apd_ble_derive_key(const unsigned char private_key[APD_BLE_X25519_KEY_LEN],
                       const unsigned char peer_public[APD_BLE_X25519_KEY_LEN],
                       const char *bootstrap_id,
                       const unsigned char bootstrap_nonce[APD_BLE_BOOTSTRAP_NONCE_LEN],
                       unsigned char out_key[APD_BLE_KEY_LEN]);

/* UUID text is canonical 8-4-4-4-12 lower/upper hex; binary form is RFC 4122
 * byte order, independent of the BLE NCP's little-endian UUID encoding. */
int apd_ble_uuid_parse(const char *text,
                       unsigned char out[APD_BLE_REQUEST_ID_LEN]);
void apd_ble_hex(const unsigned char *data, size_t len, char *out,
                 size_t out_size);
int apd_ble_hex_decode(const char *text, unsigned char *out, size_t out_size,
                       size_t *written);

size_t apd_ble_fragment_count(size_t plaintext_len);

/* The frame carries its own nonce and authenticated header. direction 0 is
 * phone -> AP; direction 1 is AP -> phone. */
int apd_ble_seal_fragment(const unsigned char key[APD_BLE_KEY_LEN],
                          const unsigned char session_id[APD_BLE_SESSION_ID_LEN],
                          const unsigned char request_id[APD_BLE_REQUEST_ID_LEN],
                          uint64_t sequence, uint8_t direction,
                          uint16_t fragment_index, uint16_t fragment_count,
                          const unsigned char *plaintext, size_t plaintext_len,
                          unsigned char *out, size_t out_size, size_t *out_len);
int apd_ble_open_fragment(const unsigned char key[APD_BLE_KEY_LEN],
                          const unsigned char expected_session_id[APD_BLE_SESSION_ID_LEN],
                          uint8_t expected_direction, uint64_t *last_sequence,
                          const unsigned char *frame, size_t frame_len,
                          unsigned char *plaintext, size_t plaintext_size,
                          size_t *plaintext_len,
                          unsigned char request_id[APD_BLE_REQUEST_ID_LEN],
                          uint16_t *fragment_index, uint16_t *fragment_count);

/* APD lifecycle and UBus-facing state machine. */
int apd_ble_init(void);
int apd_ble_loop_start(void);
void apd_ble_loop_stop(void);
void apd_ble_close(void);
int apd_ble_available(void);
const char *apd_ble_reason(void);

struct json_object;
struct apd_ble_begin_result;

struct apd_ble_begin_result {
    char bootstrap_id[65];
    char request_id[65];
    unsigned char session_id[APD_BLE_SESSION_ID_LEN];
    unsigned char public_key[APD_BLE_X25519_KEY_LEN];
    unsigned char bootstrap_nonce[APD_BLE_BOOTSTRAP_NONCE_LEN];
    int64_t expires_at;
};

struct json_object *apd_ble_begin_json(const char *bootstrap_id,
                                       const char *request_id);
struct json_object *apd_ble_begin_json_ex(const char *bootstrap_id,
                                          const char *request_id,
                                          const char *app_public_key_hex,
                                          const char *ble_peripheral_id);
struct json_object *apd_ble_begin_gatt_json(const char *request_id,
                                            const char *app_public_key_hex,
                                            uint8_t connection_handle);
struct json_object *apd_ble_physical_confirm_json(
    const char *session_id_hex);
struct json_object *apd_ble_physical_confirm_json_ex(
    const char *session_id_hex, const char *setup_code);
struct json_object *apd_ble_stage_json(const char *session_id_hex,
                                       const char *peer_public_hex,
                                       const char *frame_hex);
struct json_object *apd_ble_commit_json(const char *session_id_hex);
struct json_object *apd_ble_status_json(void);
struct json_object *apd_ble_cancel_json(const char *session_id_hex);

#endif /* DREAMINGWRT_APD_BLE_H */

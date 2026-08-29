// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_APD_BLE_DB_H
#define DREAMINGWRT_APD_BLE_DB_H

#include <stdint.h>

#include "apd_ble.h"

struct apd_ble_db_status {
    char state[24];
    char bootstrap_id[65];
    char request_id[65];
    int64_t expires_at;
    int physical_confirmed;
    uint64_t last_sequence;
    int staged;
};

enum apd_ble_db_result {
    APD_BLE_DB_ERROR = -1,
    APD_BLE_DB_OK = 0,
    APD_BLE_DB_IDEMPOTENT = 1,
    APD_BLE_DB_BUSY = 2,
    APD_BLE_DB_NOT_FOUND = 3,
    APD_BLE_DB_CONFLICT = 4,
};

int apd_ble_db_init(void);
int apd_ble_db_recover(void);
int apd_ble_db_expire(void);
int apd_ble_db_begin(const char *bootstrap_id, const char *request_id,
                     const unsigned char session_id[APD_BLE_SESSION_ID_LEN],
                     const unsigned char public_key[APD_BLE_X25519_KEY_LEN],
                     const unsigned char bootstrap_nonce[APD_BLE_BOOTSTRAP_NONCE_LEN],
                     int64_t expires_at, int physical_confirmed);
int apd_ble_db_stage(const unsigned char session_id[APD_BLE_SESSION_ID_LEN],
                     const char *request_id, const unsigned char digest[32],
                     uint64_t last_sequence);
int apd_ble_db_sequence(const unsigned char session_id[APD_BLE_SESSION_ID_LEN],
                        uint64_t last_sequence);
int apd_ble_db_physical_confirm(
    const unsigned char session_id[APD_BLE_SESSION_ID_LEN]);
int apd_ble_db_status(struct apd_ble_db_status *out);
int apd_ble_db_cancel(const unsigned char session_id[APD_BLE_SESSION_ID_LEN]);
int apd_ble_db_commit_started(const unsigned char session_id[APD_BLE_SESSION_ID_LEN]);
int apd_ble_db_failed(const unsigned char session_id[APD_BLE_SESSION_ID_LEN]);

#endif /* DREAMINGWRT_APD_BLE_DB_H */

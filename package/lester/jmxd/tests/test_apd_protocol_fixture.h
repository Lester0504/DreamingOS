// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_APD_INTERNAL_H
#define DREAMINGWRT_APD_INTERNAL_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/crypto.h>
#include <json-c/json.h>

#define APD_CONTRACT_VERSION "ap-control.v1"
#define APD_SCHEMA_VERSION 3
#define APD_SERVICE_NAME "dreamingwrt-apd"
#define APD_ED25519_KEY_LEN 32
#define APD_AP_ID_LEN 36
#define APD_KEY_ID_LEN 71
#define APD_PAIRING_VALUE_LEN 128
#define APD_NODE_TRANSPORT_ENABLED 1

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

struct apd_backend_ops {
    const char *name;
    int snapshot_supported;
    int (*probe)(struct json_object **out);
    int (*snapshot)(struct json_object **out);
};

extern int64_t g_apd_started_at;
int64_t apd_now_s(void);
const struct apd_backend_ops *apd_backend(void);
struct json_object *apd_backend_disabled(const char *operation,
                                         const char *reason);
int apd_transport_connected(void);
int apd_transport_adopted(void);
const char *apd_transport_reason(void);
int apd_db_identity_get(struct apd_node_identity *out);
int apd_db_pairing_status_get(struct apd_pairing_status *out);

#endif

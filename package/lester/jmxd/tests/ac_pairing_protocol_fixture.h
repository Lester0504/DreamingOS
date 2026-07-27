// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_AC_INTERNAL_H
#define DREAMINGWRT_AC_INTERNAL_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/crypto.h>
#include <json-c/json.h>

#define AC_CONTRACT_VERSION "ap-control.v1"
#define AC_SCHEMA_VERSION 4
#define AC_SERVICE_NAME "dreamingwrt-ac"
#define AC_PAIRING_TOKEN_ID_LEN 36
#define AC_PAIRING_TOKEN_LEN 43
#define AC_PAIRING_SITE_ID_LEN 64
#define AC_AP_ONLINE_TIMEOUT_SECONDS 45

enum ac_pairing_redeem_result {
    AC_PAIRING_REDEEM_ERROR = -1,
    AC_PAIRING_REDEEM_OK = 0,
    AC_PAIRING_REDEEM_INVALID = 1,
    AC_PAIRING_REDEEM_EXPIRED = 2,
    AC_PAIRING_REDEEM_REVOKED = 3,
    AC_PAIRING_REDEEM_CONSUMED = 4,
    AC_PAIRING_REDEEM_EXHAUSTED = 5,
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

typedef int (*ac_pairing_token_visit_fn)(
    const struct ac_pairing_token_status *status, void *opaque);

extern int64_t g_ac_started_at;
int64_t ac_now_s(void);
int ac_transport_listening(void);
const char *ac_transport_reason(void);
int ac_transport_port(void);
const char *ac_transport_controller_id(void);
int ac_db_managed_ap_counts(int64_t online_after, int *count, int *online);
int ac_db_count(const char *table);
int ac_db_pairing_token_create(int64_t ttl_seconds, int max_attempts,
                               const char *site_id,
                               const char *hardware_digest,
                               struct ac_pairing_token_secret *out);
int ac_db_pairing_token_status(const char *token_id,
                               struct ac_pairing_token_status *out);
int ac_db_pairing_token_list(ac_pairing_token_visit_fn visit, void *opaque);
int ac_db_pairing_token_revoke(const char *token_id);
int ac_db_pairing_token_redeem(const char *token_id, const char *token,
                               const char *site_id,
                               const char *hardware_digest,
                               struct ac_pairing_token_status *out);

#endif

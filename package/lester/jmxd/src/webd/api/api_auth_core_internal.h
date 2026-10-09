/* SPDX-License-Identifier: GPL-2.0-or-later */
/* AUTH-CORE surface split from jmx_app_api.c (phase 7T). Behavior-preserving. */
#ifndef JMX_WEBD_API_AUTH_CORE_INTERNAL_H
#define JMX_WEBD_API_AUTH_CORE_INTERNAL_H

#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

struct json_object;

/* Cross-TU helpers defined in jmx_app_api.c. */
extern sqlite3 *g_config_db;
sqlite3_stmt *app_prepare(const char *sql);
sqlite3_stmt *config_prepare(const char *sql);
int app_step_done(sqlite3_stmt *st);
int config_db_exec_checked(const char *sql);

/* Promoted from jmx_app_api.c (WEBD_TOTP_SECRET_MAX must be in scope before include). */
enum webd_otp_gate_result {
    WEBD_OTP_GATE_OK = 0,
    /* The caller is not a web session, so no TOTP can ever be supplied. */
    WEBD_OTP_GATE_CHANNEL_FORBIDDEN,
    WEBD_OTP_GATE_NOT_BOUND,
    WEBD_OTP_GATE_CODE_MISSING,
    WEBD_OTP_GATE_CODE_INVALID,
    WEBD_OTP_GATE_UNAVAILABLE,
};

struct webd_twofa_state {
    int enabled;
    char secret[WEBD_TOTP_SECRET_MAX + 1];
    int step_s;
    int digits;
    int window;
    int64_t bound_at;
    int64_t last_counter;
};

/* AUTH-CORE functions (defined in api/api_auth_core.c). */
int app_insert_token(const char *token, const char *device_id, const char *type, int64_t created_at, int64_t expires_at);
int gen_random_hex_checked(char *out, int len);
int ct_str_equal(const char *a, const char *b);
int webd_token_sha256(const char *token, char out[65]);
int webd_password_hash(const char *password, char *out, size_t out_len);
int webd_password_verify(const char *password, const char *stored);
int webd_username_ok(const char *username);
int webd_role_ok(const char *role);
int webd_sqlite_step_row(sqlite3_stmt *st, int *state);
int webd_twofa_qr_available(void);
struct json_object *webd_twofa_public_status(const char *username);
int webd_auth_precheck(const char *username, const char *ip, struct json_object **err_out);
void webd_auth_clear_success(const char *username, const char *ip);
struct json_object *webd_auth_record_unavailable_response(void);
int webd_auth_record_failure(const char *username, const char *ip, const char *reason);
void bytes_to_hex(const unsigned char *in, size_t in_len, char *out, size_t out_len);
int webd_totp_verify_secret(const char *secret_b32, const char *code, int step_s, int digits, int window, int64_t last_counter, int64_t *matched_counter);
int webd_user_twofa_get_ex(const char *username, struct webd_twofa_state *out, int *state);
int webd_user_twofa_touch_counter(const char *username, int64_t counter);
enum webd_otp_gate_result webd_otp_gate_check(const char *identity, struct json_object *body, char *username_out, size_t username_len);
struct json_object *webd_otp_gate_error(enum webd_otp_gate_result result, const char *operation, int *http_status);
struct json_object *webd_twofa_prepare(const char *username);
struct json_object *webd_twofa_enable(const char *username, struct json_object *body);
struct json_object *webd_twofa_disable(const char *username, struct json_object *body);
struct json_object *webd_auth_settings_json(void);
int webd_auth_settings_update(struct json_object *body);
struct json_object *webd_auth_failures_json(void);
struct json_object *webd_auth_failures_clear(struct json_object *body);
int webd_user_count(void);

#endif /* JMX_WEBD_API_AUTH_CORE_INTERNAL_H */

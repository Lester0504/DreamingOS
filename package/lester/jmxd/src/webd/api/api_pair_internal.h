// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_PAIR_INTERNAL_H
#define WEBD_API_PAIR_INTERNAL_H
/* Phase 7E: app pairing / session / device / login subsystem moved out
 * of jmx_app_api.c (behavior-preserving). Routes are unchanged and still
 * dispatched from handle_client() in the main TU; only the function
 * definitions moved here. The 11 public entry points stay declared in
 * ../jmx_app_api.h; jmx_app_validate_token_mode in api_realtime_internal.h. */
struct json_object;
struct http_req;

/* Defined in api_pair.c, still reached from the main TU. */
struct json_object *jmx_app_pair_init_ex(struct json_object *req, const char *client_ip, int *http_status);
struct json_object *jmx_app_pair_error(const char *error, const char *message);
struct json_object *jmx_app_pair_confirm_ex(struct json_object *req, const char *client_ip, int *http_status);
struct json_object *jmx_app_login_ex(struct json_object *req, const char *client_ip, int *http_status);
struct json_object *jmx_app_refresh_ex(struct json_object *req, int *http_status, const char **error_code);
struct json_object *jmx_app_logout_ex(struct json_object *req, int *http_status);
struct json_object *jmx_app_session_ex(const char *token, int *state);
char *jmx_app_validate_token_ex(const char *token, int *state);
struct json_object *jmx_app_pair_status(const char *pair_id, const char *status_token, int owner_authenticated);
struct json_object *jmx_app_pair_approve(const char *pair_id, const char *actor, int approve, int *http_status);
struct json_object *jmx_app_pair_approve_by_code(const char *code, const char *actor, int approve, const char *client_ip, int *http_status);
int jmx_app_device_patch_atomic(const char *device_id, const char *new_role, int has_enabled, int new_enabled, int has_relay_access, int new_relay_access, jmx_role_t actor_role, const char *actor_identity, int *role_changed, int *enabled_changed, int *relay_access_changed);
int jmx_app_device_delete_atomic(const char *device_id, jmx_role_t actor_role, const char *actor_identity);

/* Pairing-code and relay-identity helpers, defined in api_pair.c (moved out
 * of jmx_app_api.c in phase 7Z); only this TU calls them. */
int gen_pair_code(char *out);
int app_pair_device_id_ok(const char *device_id);
int app_pair_cleanup_expired(void);
int app_pair_pending_count_except(const char *device_id);
int app_pair_existing_device_count(int *count_out);
int app_pair_web_owner_count(int *count_out);
void app_attach_relay_identity(struct json_object *resp);

/* Borrowed from jmx_app_api.c (definitions stay there, de-static'd). */
extern sqlite3 *g_app_db;
extern sqlite3 *g_config_db;
int app_insert_token(const char *token, const char *device_id, const char *type, int64_t created_at, int64_t expires_at);
int ct_str_equal(const char *a, const char *b);
int webd_token_sha256(const char *token, char out[65]);
int webd_password_verify(const char *password, const char *stored);
int webd_sqlite_step_row(sqlite3_stmt *st, int *state);
int webd_auth_precheck(const char *username, const char *ip, struct json_object **err_out);
void webd_auth_clear_success(const char *username, const char *ip);
struct json_object *webd_auth_record_unavailable_response(void);
int webd_auth_record_failure(const char *username, const char *ip, const char *reason);
int webd_user_get_role(const char *username, char *role, size_t role_len);
void webd_identity(char *out, size_t out_len, const char *username);
sqlite3_stmt *app_prepare(const char *sql);
int app_db_exec_checked(const char *sql);
sqlite3_stmt *config_prepare(const char *sql);
int app_step_done(sqlite3_stmt *st);
int gen_random_hex_checked(char *out, int len);
int webd_password_hash(const char *password, char *out, size_t out_len);
int webd_identity_is_user(const char *identity);
const char *webd_identity_username(const char *identity);

#endif

// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_DIRECTORY_INTERNAL_H
#define WEBD_API_DIRECTORY_INTERNAL_H
/* Phase 7D: user-directory / groups / roles / activity subsystem moved
 * out of jmx_app_api.c (behavior-preserving). Routes are unchanged and
 * still dispatched from handle_client() in the main TU; only the
 * function definitions moved here. */
struct json_object;
struct http_req;

/* Defined in api_directory.c, still reached from the main TU. */
struct json_object *webd_user_from_token(const char *token);
int webd_group_permission_allows(const char *identity, jmx_risk_t risk, const char *native_permission);
int webd_directory_revoke_sessions(const char *username);
int webd_ipam_job_path_id(const char *path, char *out, size_t out_len);
struct json_object *webd_directory_users_list(int *http_status);
struct json_object *webd_directory_user_get(const char *username, int *http_status);
struct json_object *webd_directory_user_activity(const char *username, const struct http_req *req, const char *caller_username, const char *caller_role, int *http_status);
int webd_user_activity_path_name(const char *path, char *out, size_t out_len);
struct json_object *webd_directory_user_create(struct json_object *body, const char *actor_role, int *http_status);
struct json_object *webd_directory_user_update(const char *username, struct json_object *body, const char *actor, const char *actor_role, int *http_status);
struct json_object *webd_directory_user_delete(const char *username, const char *actor, const char *actor_role, int *http_status);
struct json_object *webd_directory_groups_list(int *http_status);
struct json_object *webd_directory_group_write(const char *path_id, struct json_object *body, int update, int *http_status);
struct json_object *webd_directory_group_delete(const char *id, int *http_status);
struct json_object *webd_directory_roles_list(void);
int webd_directory_username_exists(const char *username);
struct json_object *webd_directory_users_import(struct json_object *body, int *http_status);
struct json_object *webd_directory_users_export(const struct http_req *req, int *http_status);

/* Borrowed from jmx_app_api.c (definitions stay there, de-static'd). */
extern sqlite3 *g_config_db;
int webd_password_hash(const char *password, char *out, size_t out_len);
int webd_username_ok(const char *username);
int webd_role_ok(const char *role);
struct json_object *webd_permissions_for_role(jmx_role_t role);
int webd_permission_array_has(struct json_object *permissions, const char *required);
int app_parse_positive_int_segment(const char *s, int *out);
sqlite3_stmt *app_prepare(const char *sql);
sqlite3_stmt *config_prepare(const char *sql);
int gen_random_hex_checked(char *out, int len);
int webd_identity_is_user(const char *identity);
const char *webd_identity_username(const char *identity);
int webd_safe_token(const char *s);

#endif

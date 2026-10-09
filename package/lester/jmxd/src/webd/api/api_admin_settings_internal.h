// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_ADMIN_SETTINGS_INTERNAL_H
#define WEBD_API_ADMIN_SETTINGS_INTERNAL_H
/* Phase 7F: admin / system-settings settings-transaction subsystem moved
 * out of jmx_app_api.c (behavior-preserving). Routes are unchanged and
 * still dispatched from handle_client() in the main TU; only the function
 * definitions moved here. */
struct json_object;
struct http_req;

/* Defined in api_admin_settings.c, still reached from the main TU. */
int webd_admin_avatar_persist_from_response(const char *username, struct json_object *response, char *avatar_url, size_t avatar_url_len);
int webd_system_settings_has_admin_write(struct json_object *body);
int webd_system_settings_admin_targets_current(struct json_object *body, const char *current_username);
struct json_object *webd_system_settings_save_response(struct json_object *body, const char *device_id, int *status);

/* Borrowed from jmx_app_api.c (definitions stay there, de-static'd). */
extern sqlite3 *g_app_db;
extern sqlite3 *g_config_db;
void webd_system_settings_scrub_sensitive(struct json_object *o);
int webd_web_user_name_ok(const char *username);
sqlite3_stmt *app_prepare(const char *sql);
sqlite3_stmt *config_prepare(const char *sql);
int webd_password_hash(const char *password, char *out, size_t out_len);
int webd_username_ok(const char *username);
const char *webd_identity_username(const char *identity);
int webd_b64_val(char c);
int webd_data_url_main_mime(const char *data_url, const char *base64_marker, char *out, size_t out_len);

#endif

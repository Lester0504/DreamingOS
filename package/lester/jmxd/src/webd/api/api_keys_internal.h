// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_KEYS_INTERNAL_H
#define WEBD_API_KEYS_INTERNAL_H

/*
 * API-Key management subsystem contract (Phase 6W), extracted from
 * jmx_app_api.c into api_keys.c.
 *
 * jmx_role_t (jmx_app_perms.h) and the sqlite3 / sqlite3_stmt types
 * (<sqlite3.h>) are named below by include-order discipline: every includer of
 * this header (jmx_app_api.c and api_keys.c) includes both before this header,
 * exactly as api_capture_internal.h names size_t.
 */
struct json_object;
struct http_req;

/* Entry points reached from jmx_app_api.c (handle_client dispatches these five
 * response builders and uses the path-id helper in the route match; none are
 * jmx_api_route table rows). */
struct json_object *webd_api_keys_list_response(jmx_role_t role,
                                                int *http_status);
struct json_object *webd_api_keys_create_response(struct json_object *body,
                                                  const char *created_by,
                                                  char *key_id_out,
                                                  size_t key_id_out_len,
                                                  int *http_status);
struct json_object *webd_api_keys_revoke_response(const char *key_id,
                                                  int *http_status);
struct json_object *webd_api_keys_delete_response(const char *key_id,
                                                  int *http_status);
struct json_object *webd_api_keys_audit_response(const char *key_id,
                                                 const struct http_req *req,
                                                 int *http_status);
int webd_api_key_path_id(const char *path, const char *suffix,
                         char *out, size_t out_len);

/*
 * Borrowed from jmx_app_api.c (definitions stay there, de-static'd): the app-db
 * handle main owns and uses at 20+ sites, and the prepared-statement helper the
 * key code shares with the rest of main.
 */
extern sqlite3 *g_app_db;
sqlite3_stmt *app_prepare(const char *sql);

/*
 * Non-static helpers defined in jmx_app_api.c and reused by the api-key code.
 * Redeclared here (rather than cross-including a sibling domain's internal
 * header) so this TU owns its full contract: the positive-int segment parser,
 * the config-db prepared-statement helper, and the identity kind/username
 * helpers.
 */
int app_parse_positive_int_segment(const char *s, int *out);
sqlite3_stmt *config_prepare(const char *sql);
int webd_identity_is_user(const char *identity);
const char *webd_identity_username(const char *identity);

#endif /* WEBD_API_KEYS_INTERNAL_H */

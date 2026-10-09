// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_CONFIG_APPLY_INTERNAL_H
#define WEBD_API_CONFIG_APPLY_INTERNAL_H
/* Phase 7C: config-apply/rollback/snapshot + task-list subsystem moved
 * out of jmx_app_api.c (behavior-preserving). The jmx_config and
 * jmx_tasks entry points keep their jmx_app_api.h prototypes and are
 * still dispatched from handle_client() in the main TU. */
struct json_object;

/* Defined in api_config_apply.c, still reached from the main TU. */
int jmx_task_is_port_scope(const char *scope);
struct json_object *jmx_tasks_list_filtered(const char *scope_filter, int port_only, int limit);
struct json_object *jmx_tasks_delete_rejected(int task_id, int *http_status);

/* Config-file helpers, defined in api_config_apply.c (moved out of
 * jmx_app_api.c in phase 7Z). api_fingerprint.c also calls
 * webd_mkdir_p_simple. */
int webd_mkdir_p_simple(const char *path, mode_t mode);
int app_sha256_file(const char *path, char out[65]);
struct json_object *app_config_changed_paths(struct json_object *changes);
int jmx_config_pending_task_id(void);
int webd_copy_file_simple(const char *src, const char *dst, char *err, size_t err_len);

/* Borrowed from jmx_app_api.c (definitions stay there, de-static'd). */
extern sqlite3 *g_app_db;
sqlite3_stmt *app_prepare(const char *sql);
int app_step_done(sqlite3_stmt *st);

/* Defined in api_auth_core.c. */
void bytes_to_hex(const unsigned char *in, size_t in_len, char *out, size_t out_len);

#endif

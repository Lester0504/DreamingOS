// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * DreamingWrt Web Console BFF/API (/api/v1/...)
 * Lightweight REST layer on top of existing jmxd ubus/SQLite backend.
 */
#ifndef __JMX_APP_API_H__
#define __JMX_APP_API_H__

#include <json-c/json.h>

/* ── Lifecycle ── */
int  jmx_app_api_init(const char *bind_addr, int port); /* bind_addr NULL/empty = 0.0.0.0; port 0 = 12517 */
void jmx_app_api_done(void);       /* shutdown */

/* ── Auth / Pairing ── */
struct json_object *jmx_app_pair_init(struct json_object *req);
struct json_object *jmx_app_pair_confirm(struct json_object *req);
struct json_object *jmx_app_pair_cancel(struct json_object *req);
struct json_object *jmx_app_login(struct json_object *req);
struct json_object *jmx_app_refresh(struct json_object *req);
struct json_object *jmx_app_logout(struct json_object *req);
struct json_object *jmx_app_session(const char *token);
struct json_object *jmx_app_devices_list(void);
int  jmx_app_device_delete(const char *id);
int  jmx_app_device_set_role(const char *device_id, const char *role);

/* ── Config Transaction ── */
struct json_object *jmx_config_snapshot(struct json_object *req);
struct json_object *jmx_config_validate(struct json_object *req);
struct json_object *jmx_config_apply(struct json_object *req);
struct json_object *jmx_config_confirm(struct json_object *req);
struct json_object *jmx_config_rollback(struct json_object *req);
struct json_object *jmx_config_last_apply(void);

/* ── Tasks ── */
struct json_object *jmx_tasks_list(void);
struct json_object *jmx_tasks_get(int task_id);
int  jmx_tasks_delete(int task_id);

/* ── Audit ── */
/* Write an API audit log entry. */
void jmx_app_audit_log(const char *actor, const char *app_device_id,
                       const char *action, const char *risk,
                       const char *target, const char *before_hash,
                       const char *after_hash);
void jmx_app_audit_log_ex(const char *actor, const char *device_id,
                          const char *action, const char *risk,
                          const char *target, const char *client_ip,
                          const char *result, const char *reason);

void jmx_app_audit_log_task(const char *actor, const char *device_id,
                            const char *action, const char *risk, const char *target,
                            const char *source_ip, const char *result, const char *reason,
                            const char *task_id);
void jmx_app_audit_log_response(const char *actor, const char *device_id,
                              const char *action, const char *risk, const char *target,
                              const char *source_ip, struct json_object *response,
                              int http_status);

/* ── Token validation (internal) ── */
/* Returns app_device_id on success, NULL on failure.
 * Caller must free(). */
char *jmx_app_validate_token(const char *token);

/* Internal core RPC used by forked webd workers. Caller owns the result. */
struct json_object *jmx_app_core_invoke(const char *method,
                                        struct json_object *params,
                                        int timeout_ms);


/* Phase 6M macro follow-up: shared with the extracted insights core
 * (api_insights_core.c).  config.db is opened by app_db_init /
 * app_db_open_runtime here; the logo URL prefix is emitted by the icon
 * and vendor-logo responders here and by the insights dataset builders
 * there.  One home, included by both. */
#define APP_CONFIG_DB_PATH    "/etc/dreamingwrt/config.db"
#define WEBD_LOGO_URL_PREFIX "/static/images/logo/"


/* Phase 6U: shared with the extracted realtime core (api_realtime.c).
 * The access-token lifetime and the auth-DB state enum are read by
 * both the session/auth paths in jmx_app_api.c and the WebSocket
 * session loop; one home, included by both. */
#define ACCESS_TTL_S          900     /* 15 min */

enum webd_auth_db_state {
    WEBD_AUTH_DB_OK = 0,
    WEBD_AUTH_DB_INVALID = 1,
    WEBD_AUTH_DB_FAILED = 2,
    WEBD_AUTH_DB_IDLE_TIMEOUT = 3,
};


/* Phase 6X: shared with the extracted port/VLAN manager (api_ports.c).
 * The network-backup dir and the /etc/config/network path are read by the
 * snapshot/restore helpers in jmx_app_api.c and by the port write transaction
 * there; the port-batch cap bounds the batch endpoint in both. One home,
 * included by both. */
#define WEBD_NETWORK_BACKUP_DIR "/etc/dreamingwrt/network-backup"
#define WEBD_NETWORK_CONFIG_PATH "/etc/config/network"
#define WEBD_PORT_BATCH_MAX 64

#endif

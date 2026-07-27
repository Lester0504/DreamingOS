// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Mobile App HTTP API (/api/v1/...)
 * Lightweight REST layer on top of existing jmxd ubus/SQLite backend.
 */
#ifndef __JMX_APP_API_H__
#define __JMX_APP_API_H__

#include <json-c/json.h>
#include <libubox/uloop.h>

/* ── Lifecycle ── */
int  jmx_app_api_init(int port);   /* start HTTP listener on this port; 0 = default 9898 */
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

/* ── Events (SSE) ── */
int  jmx_events_fd_add(int fd);    /* register SSE client fd */
void jmx_events_fd_remove(int fd);
void jmx_events_emit(const char *topic, const char *type, struct json_object *data);

/* ── Audit ── */
/* Write an API audit log entry. */
void jmx_app_audit_log(const char *actor, const char *app_device_id,
                       const char *action, const char *risk,
                       const char *target, const char *before_hash,
                       const char *after_hash);

/* ── Token validation (internal) ── */
/* Returns app_device_id on success, NULL on failure.
 * Caller must free(). */
char *jmx_app_validate_token(const char *token);

#endif

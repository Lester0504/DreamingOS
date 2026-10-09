// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * TVHome persistent control store (Package A).
 *
 * Pattern-B module: this logic links into the webd executable (WEBD_OBJS) and is
 * called directly by api_tvhome.c through the plain-C API below. It owns its own
 * SQLite tables in the shared config DB, exactly as terminal_groups.c /
 * webd_api_keys.c / webd_backup_store.c already do. See api_tvhome.c header
 * comment for why this is not a new dreamingwrt.<x> ubus object.
 *
 * Every function returns a caller-owned "data" json_object on success (err->
 * http_status == 0), or NULL with err populated on failure. api_tvhome.c wraps
 * the data in webd_envelope() / the error in webd_error() and sets ctx->status.
 *
 * Naming: envelope/params snake_case; theme spec.* stays camelCase (contract 8).
 * Four independent version numbers (schema 1): spec.version(int=1),
 * schema_version, per-theme revision, whole-config config_version (persisted,
 * monotonic across restart -- never process time).
 */
#ifndef JMX_TVHOME_STORE_H
#define JMX_TVHOME_STORE_H

#include <json-c/json.h>

#define TVHOME_SCHEMA_VERSION 1

/* Failure detail. http_status 0 means success. */
struct tvhome_err {
    int  http_status;
    char code[48];
    char field[160];
    char message[192];
};

/* ---- A management surface ---- */
struct json_object *tvhome_overview(struct tvhome_err *err);
struct json_object *tvhome_settings_get(struct tvhome_err *err);
struct json_object *tvhome_settings_put(struct json_object *body, struct tvhome_err *err);

struct json_object *tvhome_themes_list(struct tvhome_err *err);
struct json_object *tvhome_theme_get(const char *id, struct tvhome_err *err);
struct json_object *tvhome_theme_create(struct json_object *body, struct tvhome_err *err);
/* preview==0 => validate only; both are side-effect free (schema rule 9). */
struct json_object *tvhome_theme_check(struct json_object *body, int preview,
                                       struct tvhome_err *err);
struct json_object *tvhome_theme_update(const char *id, struct json_object *body,
                                        struct tvhome_err *err);
struct json_object *tvhome_theme_delete(const char *id, struct tvhome_err *err);
struct json_object *tvhome_theme_set_default(const char *id, struct tvhome_err *err);
struct json_object *tvhome_theme_duplicate(const char *id, struct json_object *body,
                                           struct tvhome_err *err);

struct json_object *tvhome_terminals_list(struct tvhome_err *err);
struct json_object *tvhome_terminal_update(const char *id, struct json_object *body,
                                           struct tvhome_err *err);
struct json_object *tvhome_terminal_delete(const char *id, struct tvhome_err *err);
struct json_object *tvhome_terminal_display_get(const char *id, struct tvhome_err *err);
struct json_object *tvhome_terminal_display_put(const char *id, struct json_object *body,
                                                struct tvhome_err *err);

struct json_object *tvhome_groups_list(struct tvhome_err *err);
struct json_object *tvhome_group_create(struct json_object *body, struct tvhome_err *err);
struct json_object *tvhome_group_update(const char *id, struct json_object *body,
                                        struct tvhome_err *err);
struct json_object *tvhome_group_delete(const char *id, struct tvhome_err *err);
struct json_object *tvhome_group_display_put(const char *id, struct json_object *body,
                                             struct tvhome_err *err);

/* ---- T terminal surface (D1 stub identity) ---- */
struct json_object *tvhome_ping(struct tvhome_err *err);
struct json_object *tvhome_session_create(struct json_object *body, struct tvhome_err *err);
struct json_object *tvhome_session_delete(const char *token, struct tvhome_err *err);
/* token borrowed from the TV session bearer; never an admin token (contract 5). */
struct json_object *tvhome_bootstrap(const char *token, struct tvhome_err *err);
struct json_object *tvhome_theme_resolved(const char *token, struct tvhome_err *err);
struct json_object *tvhome_heartbeat(const char *token, struct json_object *body,
                                     struct tvhome_err *err);

struct json_object *tvhome_activation_request(struct json_object *body, struct tvhome_err *err);
struct json_object *tvhome_activations(const char *id, const char *poll_token, struct tvhome_err *err);
struct json_object *tvhome_activation_decide(const char *id, int approve, struct json_object *body, struct tvhome_err *err);
struct json_object *tvhome_session_refresh(const char *token, struct tvhome_err *err);
struct json_object *tvhome_terminal_action(const char *id, const char *action, struct tvhome_err *err);
struct json_object *tvhome_group_display_get(const char *, struct tvhome_err *);
struct json_object *tvhome_theme_export(const char *, struct tvhome_err *);
struct json_object *tvhome_theme_import(struct json_object *, struct tvhome_err *);
struct json_object *tvhome_theme_reset(const char *, struct json_object *, struct tvhome_err *);
#endif /* JMX_TVHOME_STORE_H */

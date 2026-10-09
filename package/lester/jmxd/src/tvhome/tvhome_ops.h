// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TVHOME_OPS_H
#define TVHOME_OPS_H
#include "tvhome_internal.h"
int tvhome_ops_schema(sqlite3 *db);
struct json_object *tvhome_notice_get(struct tvhome_err *);
struct json_object *tvhome_notice_put(struct json_object *,struct tvhome_err *);
struct json_object *tvhome_notice_for_terminal(sqlite3 *,const char *);
struct json_object *tvhome_commands_for_terminal(sqlite3 *,const char *);
struct json_object *tvhome_commands_get(const char *,struct tvhome_err *);
struct json_object *tvhome_command_create(struct json_object *,struct tvhome_err *);
struct json_object *tvhome_command_stop(const char *,struct tvhome_err *);
struct json_object *tvhome_command_ack(const char *,const char *,struct json_object *,struct tvhome_err *);
struct json_object *tvhome_event_create(const char *,struct json_object *,struct tvhome_err *);
struct json_object *tvhome_events_get(struct json_object *,struct tvhome_err *);
int tvhome_target_matches(struct json_object *,const char *,const char *);
struct json_object *tvhome_target_members(sqlite3 *,struct json_object *,struct tvhome_err *);
#endif

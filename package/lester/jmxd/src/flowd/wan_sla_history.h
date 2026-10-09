// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef FLOWD_WAN_SLA_HISTORY_H
#define FLOWD_WAN_SLA_HISTORY_H
#include <json-c/json.h>
#include <sqlite3.h>
#include <stdint.h>
#define WAN_SLA_HISTORY_PATH "/etc/dreamingwrt/wan-sla.db"
int wan_sla_history_open(const char *path, sqlite3 **db);
int wan_sla_history_record(sqlite3 *db, struct json_object *runtime,
                           struct json_object *samples, struct json_object *events);
int wan_sla_history_prune(sqlite3 *db, int64_t now, int64_t byte_cap,
                          int raw_cap, int rollup_cap, int event_cap);
struct json_object *wan_sla_history_query(const char *path, struct json_object *request);
struct json_object *wan_sla_history_restore(sqlite3 *db, const char *id);
#endif

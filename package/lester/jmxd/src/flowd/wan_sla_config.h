// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef FLOWD_WAN_SLA_CONFIG_H
#define FLOWD_WAN_SLA_CONFIG_H
#include <json-c/json.h>
#include <sqlite3.h>
struct json_object *wan_sla_config_load(sqlite3 *db, const char *id);
void wan_sla_config_digest(struct json_object *rule, char out[17]);
#endif

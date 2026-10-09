// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef FLOWD_WAN_SLA_RUNTIME_H
#define FLOWD_WAN_SLA_RUNTIME_H
#include <json-c/json.h>

int flowd_wan_sla_runtime_start(void);
void flowd_wan_sla_runtime_stop(void);
int flowd_wan_sla_shadow_ready(void);
void flowd_wan_sla_config_changed(void);
int flowd_wan_sla_dry_probe_matches(struct json_object *plan);
struct json_object *flowd_wan_sla_runtime_item(const char *id);
struct json_object *flowd_wan_sla_runtime_json(struct json_object *body);
struct json_object *flowd_wan_sla_test(struct json_object *body);
struct json_object *flowd_wan_sla_history(struct json_object *body);

#endif

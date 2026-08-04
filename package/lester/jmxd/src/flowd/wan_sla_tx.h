// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_FLOWD_WAN_SLA_TX_H
#define DREAMINGWRT_FLOWD_WAN_SLA_TX_H

#include <json-c/json.h>

struct json_object *flowd_wan_sla_list(struct json_object *body);
struct json_object *flowd_wan_sla_preview(struct json_object *body);
struct json_object *flowd_wan_sla_commit(struct json_object *body);

#endif

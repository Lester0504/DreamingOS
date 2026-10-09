// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef WAN_SLA_ROUTE_GUARD_H
#define WAN_SLA_ROUTE_GUARD_H

#include <stddef.h>
#include <stdint.h>
#include <json-c/json.h>

enum wan_sla_route_guard_verdict {
    WAN_SLA_ROUTE_REJECT = -1,
    WAN_SLA_ROUTE_ALLOW = 0,
    WAN_SLA_ROUTE_SUPPRESS = 1,
};

int wan_sla_route_guard_validate(struct json_object *request,
                                 struct json_object *current_config,
                                 int64_t now,
                                 int eligible_alternatives,
                                 char *reason, size_t reason_len);

#endif

// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_FLOWD_TC_APPLY_H
#define DREAMINGWRT_FLOWD_TC_APPLY_H

#include <stdint.h>

#include <json-c/json.h>
#include <sqlite3.h>

#include "flowd_internal.h"

#define FLOWD_TC_BINARY "/sbin/tc"
#define FLOWD_IP_BINARY "/sbin/ip"
#define FLOWD_TC_OWNER "dreamingwrt-flowd"
#define FLOWD_TC_STATE_TABLE "flowd_tc_apply_state"
#define FLOWD_TC_RESOURCE_TABLE "flowd_tc_resources"

struct flowd_tc_runtime_state {
    int present;
    int runtime_applied;
    int rollback_ok;
    int64_t applied_at;
    char phase[64];
    char reason[128];
    char generation[96];
};

int flowd_tc_apply_executor_available(void);
int flowd_tc_runtime_state_read(struct flowd_tc_runtime_state *out);
void flowd_tc_runtime_contract_state(struct flowd_runtime_contract_input *input);
struct json_object *flowd_tc_apply(const struct flowd_settings *settings);
int flowd_tc_runtime_json_add(sqlite3 *db, struct json_object *response,
                              struct json_object *tables, struct json_object *summary,
                              struct json_object *errors, int *ok, int limit);

#endif

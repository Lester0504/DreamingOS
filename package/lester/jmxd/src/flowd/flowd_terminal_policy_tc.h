// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_FLOWD_TERMINAL_POLICY_TC_H
#define DREAMINGWRT_FLOWD_TERMINAL_POLICY_TC_H

#include "flowd_internal.h"

int flowd_terminal_policy_tc_executor_available(void);
struct json_object *flowd_terminal_policy_tc_apply(const struct flowd_settings *settings);
int flowd_terminal_policy_tc_restore_previous(void);
struct json_object *flowd_terminal_policy_tc_runtime(void);

#endif

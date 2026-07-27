// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_SYSTEM_POWER_H
#define DREAMINGWRT_SYSTEM_POWER_H

#include <stdint.h>
#include <json-c/json.h>

#define JMX_SYSTEM_POWER_CONTRACT_VERSION "system-power.v1"

/* All functions return a complete DreamingWrt code/data envelope. */
struct json_object *jmx_system_power_get(void);

/* A NULL or empty schedule_id creates a schedule; otherwise it updates one. */
struct json_object *jmx_system_power_schedule_upsert(
    const char *schedule_id, struct json_object *request);

struct json_object *jmx_system_power_schedule_delete(
    const char *schedule_id, struct json_object *request);

/*
 * Internal scheduler ABI. now_epoch <= 0 uses the current wall clock.
 * execute == 0 is a non-mutating preview for core diagnostics/harnesses only.
 */
struct json_object *jmx_system_power_scheduler_tick(
    int64_t now_epoch, int execute);

/* action is restricted to "reboot" or "shutdown". */
struct json_object *jmx_system_power_immediate_action(
    const char *action, struct json_object *request);

#endif /* DREAMINGWRT_SYSTEM_POWER_H */

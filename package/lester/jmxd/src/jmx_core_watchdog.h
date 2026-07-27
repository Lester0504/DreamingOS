// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DreamingWrt core observer-only watchdog and ubus/main-loop telemetry.
 * This module never restarts services and never calls ubus from the observer
 * thread; it only records fixed-size diagnostics for core_status.
 */
#ifndef __JMX_CORE_WATCHDOG_H__
#define __JMX_CORE_WATCHDOG_H__

#include <stdint.h>
#include <json-c/json.h>

#define JMX_CORE_WATCHDOG_CONTRACT_VERSION "1.0"
#ifndef JMX_CORE_UBUS_SLOW_THRESHOLD_MS
#define JMX_CORE_UBUS_SLOW_THRESHOLD_MS 1000LL
#endif
#ifndef JMX_CORE_UBUS_STUCK_THRESHOLD_MS
#define JMX_CORE_UBUS_STUCK_THRESHOLD_MS 5000LL
#endif
#ifndef JMX_CORE_LOOP_HEARTBEAT_INTERVAL_MS
#define JMX_CORE_LOOP_HEARTBEAT_INTERVAL_MS 1000LL
#endif
#ifndef JMX_CORE_LOOP_STALL_THRESHOLD_MS
#define JMX_CORE_LOOP_STALL_THRESHOLD_MS 5000LL
#endif
/*
 * Hard recovery: if the control plane stays stalled this long the observer
 * thread abort()s so the supervisor respawns a fresh core, recovering from a
 * wedged/livelocked main loop. Default-on; override the ms via
 * DREAMINGWRT_CORE_WATCHDOG_HARD_RECOVER_MS (0 disables, restoring pure
 * observer mode). The min-uptime grace keeps a slow first-boot (e.g. large
 * signature compile that briefly blocks uloop) from tripping a false restart.
 */
#ifndef JMX_CORE_HARD_RECOVER_DEFAULT_MS
#define JMX_CORE_HARD_RECOVER_DEFAULT_MS 30000LL
#endif
#ifndef JMX_CORE_HARD_RECOVER_MIN_UPTIME_MS
#define JMX_CORE_HARD_RECOVER_MIN_UPTIME_MS 60000LL
#endif

int jmx_core_watchdog_start(void);
void jmx_core_watchdog_stop(void);
void jmx_core_watchdog_append_status(struct json_object *data);

uint64_t jmx_core_ubus_dispatch_enter(const char *object_name,
                                      const char *method_name);
void jmx_core_ubus_dispatch_update(uint64_t call_id, const char *object_name,
                                   const char *method_name);
void jmx_core_ubus_dispatch_update_current(const char *object_name,
                                           const char *method_name);
void jmx_core_ubus_dispatch_leave(uint64_t call_id, int status_code);

#endif

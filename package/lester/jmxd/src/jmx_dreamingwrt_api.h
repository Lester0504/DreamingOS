/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jmx_dreamingwrt_api.h - DreamingWrt unified API for luci-app-dreamingwrt
 *
 * Endpoints registered under ubus object "dreamingwrt":
 *   summary   - GET /cgi-bin/luci/admin/dreamingwrt/summary
 *   topology  - GET /cgi-bin/luci/admin/dreamingwrt/topology
 *   devices   - GET /cgi-bin/luci/admin/dreamingwrt/devices
 *   apps      - GET /cgi-bin/luci/admin/dreamingwrt/apps
 *   ping      - GET /cgi-bin/luci/admin/dreamingwrt/ping
 *   activity  - GET /cgi-bin/luci/admin/dreamingwrt/activity
 */
#ifndef JMX_DREAMINGWRT_API_H
#define JMX_DREAMINGWRT_API_H

#include <json-c/json.h>
#include <libubus.h>

/* Register both core ubus names atomically (call from jmx_ubus_init). */
int dreamingwrt_ubus_register(struct ubus_context *ctx);
void dreamingwrt_ubus_unregister(struct ubus_context *ctx);

void dw_refresh_wan_state(void);
void dw_update_wan_health(void);
void dw_collect_ipv6_load(void);
void dw_update_wan_profiles(void);
struct json_object *jmx_dreamingwrt_topology_flow_get(void);
struct json_object *jmx_dreamingwrt_topology_infrastructure_get(void);
struct json_object *jmx_dreamingwrt_realtime_snapshot_get(struct json_object *req);

/* Appends _metrics_tick cost/deferral counters to a core_status payload. */
void jmx_dreamingwrt_metrics_tick_append_status(struct json_object *data);

/* Appends the dw_build_wans_internal() phase breakdown to a core_status
 * payload, so the cost of the tick's slowest step can be attributed to a
 * phase (procfs, ubus, SQLite, JSON) instead of only to the step. */
void jmx_dreamingwrt_wan_phase_append_status(struct json_object *data);
/* Appends immutable WAN producer freshness/single-flight state. */
void jmx_dreamingwrt_wan_refresh_append_status(struct json_object *data);

/* One IM presence beat (洞察 → 活动 → IM 在线).  Reads af_active_app /
 * af_active_host and ages an in-memory presence table; no DB writes. */
void jmx_dreamingwrt_im_presence_tick(void);

/* Work mode APIs (jmx_dreamingwrt_work_mode.c) */
struct json_object *dw_work_mode_get(struct json_object *req);
struct json_object *dw_work_mode_preview(struct json_object *req);
struct json_object *dw_work_mode_apply(struct json_object *req);
struct json_object *dw_work_mode_rollback(struct json_object *req);

/*
 * One-shot CLI worker (dw_api_maintenance.c) for the fs-heavy
 * SYSTEM_STATUS_EVENT sub-tick. Runs in a fork()+exec()'d child so unbounded
 * filesystem I/O (statvfs on a hung mount) can never block core's single
 * control-plane thread. Dispatched from main() before uloop_init(); returns a
 * process exit code and never returns to the caller's control loop.
 */
int dw_maintenance_io_worker_main(void);

#endif

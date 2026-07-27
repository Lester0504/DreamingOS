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

/* Work mode APIs (jmx_dreamingwrt_work_mode.c) */
struct json_object *dw_work_mode_get(struct json_object *req);
struct json_object *dw_work_mode_preview(struct json_object *req);
struct json_object *dw_work_mode_apply(struct json_object *req);
struct json_object *dw_work_mode_rollback(struct json_object *req);

#endif

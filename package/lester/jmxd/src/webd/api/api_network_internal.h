// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_NETWORK_INTERNAL_H
#define WEBD_API_NETWORK_INTERNAL_H
/* Phase 7M: network status / WAN / VPN response builders moved out of
 * jmx_app_api.c (behavior-preserving). handle_client() and other main-side
 * callers dispatch these; the WAN-fetch kind is promoted here verbatim so
 * both TUs (main keeps struct webd_wan_fetch_task + the fetch helpers) see
 * the same enumerators. */
struct json_object;

enum webd_wan_fetch_kind {
    WEBD_WAN_FETCH_BASE = 0,
    WEBD_WAN_FETCH_HEALTH,
    WEBD_WAN_FETCH_LOAD,
    WEBD_WAN_FETCH_SUMMARY,
    WEBD_WAN_FETCH_TOPOLOGY,
};

/* De-static'd response builders (definitions now live in api_network.c). */
void webd_merge_network_wans_runtime(struct json_object *wan_data,
                                            struct json_object *line_health_data,
                                            struct json_object *line_load_data,
                                            struct json_object *summary_data,
                                            struct json_object *topology_flow_data);
struct json_object *webd_network_wans_response(int *status);
struct json_object *webd_network_overview_response(int *status);
struct json_object *webd_vpn_management_response(const char *resource,
                                                        int *status);
struct json_object *webd_vpn_write_disabled_response(int *status);

/* Network settings builders (Phase 8A), defined in api_network.c and
 * dispatched by handle_client in the main TU. */
struct json_object *webd_port_preferences_response(const char *identity,
                                                   struct json_object *body,
                                                   int write, int *status);
struct json_object *webd_network_settings_overview_response(int *status);
struct json_object *webd_interfaces_response(int *status);

#endif /* WEBD_API_NETWORK_INTERNAL_H */

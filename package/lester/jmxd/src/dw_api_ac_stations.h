// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
/*
 * dw_api_ac_stations.h - bridge the dreamingwrt.ac per-AP station roster into
 * the unified terminal inventory (/api/v1/clients) and the topology graph
 * (/api/v1/topology).  A wireless station associated on a remote managed AP is
 * surfaced as a terminal "attached to the AC/gateway", following the UniFi
 * attribution model (ownership is a reported claim, not a forwarding path).
 *
 * See todo/2026-09-19/Handoff/PM-to-Backend-ac-ap-stations-as-terminals.md.
 */
#ifndef DW_API_AC_STATIONS_H
#define DW_API_AC_STATIONS_H

struct json_object;

/*
 * Merge AC-reported AP stations into an existing device/client JSON array.
 *
 * For each fresh (within TTL) station the AC reports:
 *  - if its MAC already exists in `devices`, the existing entry is enriched in
 *    place with wireless attribution fields (identity join, no duplicate row);
 *  - otherwise a synthesized wireless terminal is appended (mac + AP + ssid +
 *    band + signal + rx/tx + connected_time), online regardless of whether any
 *    traffic ever crossed this gateway.
 *
 * The array is modified in place; ownership of appended entries transfers to
 * the array.  Safe to call from a worker thread (uses its own ubus context).
 */
void dw_ac_merge_station_devices(struct json_object *devices);

/*
 * Add AP vertices, per-station CLIENT vertices, and the WIRELESS edges that
 * attach each station to its AP (and each AP to the gateway) into an existing
 * topology vertices/edges pair.  Also stamps per-AP num_sta / num_sta_total.
 * Must be called after the gateway vertex exists.
 */
void dw_ac_stations_add_topology(struct json_object *vertices,
                                 struct json_object *edges,
                                 const char *gateway_mac);

#endif /* DW_API_AC_STATIONS_H */

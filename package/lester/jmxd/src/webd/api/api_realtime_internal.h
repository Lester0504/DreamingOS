// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_REALTIME_INTERNAL_H
#define WEBD_API_REALTIME_INTERNAL_H

/*
 * Realtime / WebSocket subsystem contract (Phase 6U), extracted from
 * jmx_app_api.c into api_realtime.c.
 */
struct json_object;
struct http_req;

/* WS child-pool cap. Moved here from jmx_app_api.c's preamble: it is a WS-domain
 * constant, still read by main's worker accounting, so both TUs need it. */
#define WEBD_WS_MAX_CHILDREN 8

/*
 * The realtime topic mask. Moved here from jmx_app_api.c because main
 * (webd_dashboard_live_response) declares `webd_ws_topics_t topics = {0};`
 * by value, so the full type must be visible to both TUs.
 */
typedef struct {
    int dashboard_metrics;
    int dashboard_throughput;
    int topology_flow;
    int wan_metrics;
    int route_status;
    int clients_metrics;
    int apps_metrics;
    int client_detail;
    int client_overview;
    int client_protocols;
    int client_connections;
    int client_conntrack;
    int notifications;
    int logs_events;
    int web_appearance;
    int insights_flows_summary;
    int insights_flows_geo;
    int insights_activity_rate;
    int insights_activity_traffic;
    int insights_status;
} webd_ws_topics_t;

/* Entry points reached from jmx_app_api.c: the WebSocket upgrade loop
 * (handle_client, inline on upgrade) and the snapshot builder that the live
 * dashboard response reuses. */
struct json_object *webd_ws_snapshot_data(const webd_ws_topics_t *topics,
                                          struct json_object *params);
void webd_realtime_ws_session(int fd, const struct http_req *req,
                              const char *device_id);

/*
 * Borrowed from jmx_app_api.c (definitions stay there, de-static'd — each has
 * callers that remain in main): the token validator, the public appearance
 * snapshot, and the WAN route-status response builder.
 */
char *jmx_app_validate_token_mode(const char *token, int *state,
                                  int record_activity);
struct json_object *webd_public_appearance_data(void);
struct json_object *webd_route_status_response(struct json_object *params,
                                               int *status);

/* Dashboard + topology builders (Phase 8B), defined in api_realtime.c and
 * dispatched by handle_client in the main TU. */
struct json_object *webd_dashboard_snapshot_response(int *status);
struct json_object *webd_dashboard_live_response(int *status);
struct json_object *webd_topology_node_detail_response(const struct http_req *req,
                                                       struct json_object *body,
                                                       int *http_status);

/* Borrowed by the topology builder; defined in jmx_app_api.c. */
int webd_safe_token(const char *s);

/* Shared framing used by the TVHome WS worker; no admin identity is shared. */
#include <stddef.h>
int webd_ws_accept_key(const char *, char *, size_t);
int webd_ws_send_frame(int, int, const char *);
int webd_ws_send_close(int, int, const char *);
int webd_ws_send_json(int, struct json_object *);
int webd_ws_read_frame(int, char *, size_t, int *);
#endif /* WEBD_API_REALTIME_INTERNAL_H */

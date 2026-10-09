// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_PORTS_INTERNAL_H
#define WEBD_API_PORTS_INTERNAL_H

/*
 * Port / VLAN manager subsystem contract (Phase 6X), extracted from
 * jmx_app_api.c into api_ports.c. struct http_req / struct json_object are
 * named below by include-order discipline: every includer of this header
 * (jmx_app_api.c and api_ports.c) includes webd_http_req.h and <json-c/json.h>
 * before this header.
 */
struct json_object;
struct http_req;

struct json_object *webd_port_vlan_resources(void);
struct json_object *webd_port_vlan_snapshot(const char *ifname, int *http_status);
struct json_object *webd_port_vlan_request(const struct http_req *req,
                                         struct json_object *body, int apply,
                                         int *http_status);

/* Entry points reached from jmx_app_api.c (handle_client dispatches these
 * response builders / uses them in the route match; none are jmx_api_route
 * table rows). Prototypes are the exact de-static'd definition signatures. */
int webd_port_manager_changes_need_vlan_runtime(struct json_object *changes);
struct json_object *webd_port_manager_apply_network_transaction(struct json_object *changes,
                                                                       const char *snapshot_path,
                                                                       int dry_run);
struct json_object *webd_port_transaction_preview_from_plan(struct json_object *plan,
                                                                   struct json_object *body,
                                                                   const char *device_id);
int webd_port_profiles_path(const char *path, char *id, size_t id_len);
struct json_object *webd_topology_port_profiles_response(const struct http_req *req,
                                                                struct json_object *body,
                                                                int *http_status);
struct json_object *webd_topology_port_plan_response(const struct http_req *req,
                                                           struct json_object *body,
                                                           int apply,
                                                           const char *device_id,
                                                           int *http_status);
struct json_object *webd_topology_port_batch_response(const struct http_req *req,
                                                             struct json_object *body,
                                                             int apply,
                                                             const char *device_id,
                                                             int *http_status);
struct json_object *webd_topology_port_transaction_validate_response(const struct http_req *req,
                                                                           struct json_object *body,
                                                                           int *http_status);
struct json_object *webd_topology_node_ports_response(const struct http_req *req,
                                                             struct json_object *body,
                                                             int *http_status);

/* Port-manager response builders (Phase 7W), moved out of jmx_app_api.c into
 * api_ports.c. handle_client dispatches these; capabilities() is also reached
 * by the transactions-query response builder still in jmx_app_api.c. */
struct json_object *webd_port_manager_capabilities(void);
struct json_object *webd_port_manager_status_response(void);
struct json_object *webd_port_manager_transaction_get_response(int task_id,
                                                                      int *http_status);
struct json_object *webd_port_manager_transaction_action_response(int task_id,
                                                                         int rollback,
                                                                         struct json_object *body,
                                                                         int *http_status);
struct json_object *webd_port_manager_transaction_create_response(const struct http_req *req,
                                                                         struct json_object *body,
                                                                         const char *device_id,
                                                                         int *http_status);
struct json_object *webd_port_manager_transaction_preview_response(const struct http_req *req,
                                                                          struct json_object *body,
                                                                          const char *device_id,
                                                                          int *http_status);

/*
 * Borrowed from jmx_app_api.c (definitions stay there): the network
 * snapshot-restore / reload-runtime / local-reachability-probe helpers and
 * the shared non-empty string compare are de-static'd there; the safe-token
 * and MAC-normalize helpers are already non-static. Redeclared here (rather
 * than cross-including a sibling domain's internal header) so this TU owns
 * its full contract.
 */
int webd_network_config_restore(const char *snapshot_path, char *err, size_t err_len);
int webd_network_reload_runtime(char *err, size_t err_len);
struct json_object *webd_network_local_reachability_probe(void);
int webd_str_eq_nonempty(const char *a, const char *b);
int webd_safe_token(const char *s);
int webd_normalize_mac_text(const char *in, char *out, size_t out_len);

/* Task-scope helpers defined in api_config_apply.c, called by the moved
 * port-manager transaction builders. Redeclared here (not cross-including a
 * sibling's internal header) so this TU owns its full contract. */
int jmx_task_is_port_scope(const char *scope);
struct json_object *jmx_tasks_list_filtered(const char *scope_filter, int port_only, int limit);

/* Phase 8C: the transactions query builder, defined in api_ports.c and
 * dispatched by handle_client; it borrows app_parse_positive_int_segment,
 * defined in jmx_app_api.c. */
struct json_object *webd_port_manager_transactions_query_response(const struct http_req *req,
                                                                  int *http_status);
int app_parse_positive_int_segment(const char *s, int *out);

#endif /* WEBD_API_PORTS_INTERNAL_H */

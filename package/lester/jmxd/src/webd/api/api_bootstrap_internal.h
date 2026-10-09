/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef WEBD_API_API_BOOTSTRAP_INTERNAL_H
#define WEBD_API_API_BOOTSTRAP_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct http_req;
struct json_object;

/* Entry points defined in api_bootstrap.c and used from the main TU. */
struct json_object *webd_capabilities_data(void);
struct json_object *webd_menu_data(jmx_role_t role);
struct json_object *webd_dynamic_menu_data(jmx_role_t role);
struct json_object *webd_dashboard_traffic_history_response(const struct http_req *req,
                                                                   struct json_object *body,
                                                                   int *http_status);
struct json_object *webd_system_health_history_response(const struct http_req *req,
                                                               struct json_object *body,
                                                               int *http_status);
struct json_object *webd_network_probe_response(const struct http_req *req,
                                                       struct json_object *body,
                                                       const char *path_wan_id,
                                                       int *http_status);
struct json_object *webd_wan_slas_response(const char *id, int *http_status);
struct json_object *webd_monitor_ubus_response(const char *method,
                                                      const char *source);
struct json_object *webd_kernel_runtime_response(void);
struct json_object *webd_native_plugins_data(void);
struct json_object *webd_bootstrap_response(const char *token,
                                                   const struct http_req *req);

#endif /* WEBD_API_API_BOOTSTRAP_INTERNAL_H */

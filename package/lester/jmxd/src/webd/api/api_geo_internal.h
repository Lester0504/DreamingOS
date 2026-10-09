// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_GEO_INTERNAL_H
#define WEBD_API_GEO_INTERNAL_H
/* Phase 7N: Aegis Geo runtime/counters and firewall geo-block response
 * builders moved out of jmx_app_api.c (behavior-preserving). handle_client()
 * dispatches these; the definitions now live in api_geo.c. */
struct json_object;

/* De-static'd response builders (definitions now live in api_geo.c). */
struct json_object *webd_geo_runtime_invoke(const char *operation,
                                            struct json_object *body);
struct json_object *webd_geo_runtime_response(int *http_status);
struct json_object *webd_geo_counters_response(int *http_status);
struct json_object *webd_geo_block_response(int *http_status);
struct json_object *webd_geo_block_save(struct json_object *body, int *http_status);

#endif /* WEBD_API_GEO_INTERNAL_H */

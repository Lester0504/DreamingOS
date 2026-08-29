// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_TOPOLOGY_H
#define WEBD_API_TOPOLOGY_H

#include "api_router.h"

extern const struct jmx_api_route topology_api_routes[];

/* Port reads/writes still live in jmx_app_api.c and share this cache. */
struct json_object *webd_topology_infrastructure_cached_response(int *status);
void webd_topology_infrastructure_cache_invalidate(void);

#endif /* WEBD_API_TOPOLOGY_H */

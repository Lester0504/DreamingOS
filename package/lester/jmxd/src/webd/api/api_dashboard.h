// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_DASHBOARD_H
#define WEBD_API_DASHBOARD_H

#include <json-c/json.h>

#include "api_router.h"

extern const struct jmx_api_route dashboard_api_routes[];

/* Dashboard status shares the line-health cache with legacy WAN readers. */
struct json_object *webd_cached_line_health(void);

/* Companion line-load cache reader, borrowed by the flowd status/runtime
 * adapters in api_flowd.c (both live in jmx_app_api.c). */
struct json_object *webd_cached_line_load(void);

#endif /* WEBD_API_DASHBOARD_H */

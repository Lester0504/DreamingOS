// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
/*
 * Insights traffic flow read-only routes (Phase 4A).
 *
 * This module owns only the route table and thin ctx-to-legacy adapters.
 * All SQL, GeoIP, cache, async fetch, and /proc read logic stays in
 * jmx_app_api.c. The response helpers are declared here so api_insights.c
 * can call them, but they are defined in the legacy file.
 */
#ifndef WEBD_API_INSIGHTS_H
#define WEBD_API_INSIGHTS_H

#include "api_router.h"

extern const struct jmx_api_route insights_api_routes[];

#endif /* WEBD_API_INSIGHTS_H */

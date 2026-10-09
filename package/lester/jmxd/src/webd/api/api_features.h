// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Feature registry REST adapter — route table declaration.
 *
 * The handlers live in api_features.c and forward to the pure functions in
 * jmxd/src/webd/jmx_feature_registry.c (feature_registry_list/status), then
 * project each feature's permissions{} map onto the requesting role instead of
 * the registry's hardcoded true. Registered in api_router.c's g_route_tables[]
 * after tvhome_api_routes. See PM-to-Backend-mobile-roceos-capabilities.md
 * §8.1 (B01-b) for the mobile bootstrap projection this HTTP surface backs.
 */
#ifndef WEBD_API_FEATURES_H
#define WEBD_API_FEATURES_H

#include "api_router.h"

extern const struct jmx_api_route feature_api_routes[];

#endif /* WEBD_API_FEATURES_H */

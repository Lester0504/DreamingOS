// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * TVHome REST adapter (Package A) — route table declaration.
 *
 * The handlers live in api_tvhome.c and forward to the Pattern-B store in
 * jmxd/src/tvhome/. Registered in api_router.c's g_route_tables[] after
 * ota_remote_api_routes. See api_tvhome.c for the T (preauth) vs A
 * (admin) split and PM-tvhome-package-a-contract.md §3 for the frozen surface.
 */
#ifndef WEBD_API_TVHOME_H
#define WEBD_API_TVHOME_H

#include "api_router.h"

extern const struct jmx_api_route tvhome_api_routes[];

#endif /* WEBD_API_TVHOME_H */

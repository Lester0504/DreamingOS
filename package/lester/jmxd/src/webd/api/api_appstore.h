// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * App Store REST surface.
 *
 * Implements the device-facing contract in
 * todo/2026-09-23/Handoff/PM-to-Backend-appstore-remote-catalog-apk-feed-v1.md
 * §7: signed-catalog browse (§7.1), installed inventory + per-app status +
 * task polling (§7.2), install/update/uninstall/rollback orchestration (§7.3),
 * stable error codes (§7.4) and a pre-install port-conflict probe (§7.5).
 *
 * There is no package manager here. This module is a thin client: it resolves
 * requests against the signed catalog, writes a task spec, and spawns a
 * standalone worker (/usr/bin/dwrt-appstore-worker) that owns all network,
 * crypto and filesystem mutation. Status is answered by reading the on-disk
 * app registry and worker task-state files.
 *
 * The route table is registered by hand in api_router.c's g_route_tables[],
 * like every other module here. All rows are post-auth: the App Store needs an
 * authenticated session, and the permission/CSRF gates in jmx_app_api.c run
 * before dispatch, so a POST under /api/v1/appstore/apps/ is already role- and
 * same-origin-checked by the time a handler sees it.
 */
#ifndef WEBD_API_APPSTORE_H
#define WEBD_API_APPSTORE_H

#include "api_router.h"

extern const struct jmx_api_route appstore_api_routes[];

#endif /* WEBD_API_APPSTORE_H */

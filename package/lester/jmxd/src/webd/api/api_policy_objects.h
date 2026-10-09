// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
/*
 * Policy Engine zones, zone matrix and composite objects (Phase 5B).
 *
 * Only the route table is exported here, so api_router.c can register the
 * module without pulling in <uci.h> or <sqlite3.h>. The helpers this module
 * shares with the policy-table write path that stays in jmx_app_api.c are
 * declared in api_policy_objects_internal.h instead.
 */
#ifndef WEBD_API_POLICY_OBJECTS_H
#define WEBD_API_POLICY_OBJECTS_H

#include "api_router.h"

extern const struct jmx_api_route policy_objects_api_routes[];

#endif /* WEBD_API_POLICY_OBJECTS_H */

// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_VM_H
#define WEBD_API_VM_H

#include "api_router.h"

/* The /api/v1/vm/ gateway routes. Always compiled into webd, even on a build
 * without the dreamingos-vm package: when the daemon's ubus object is absent,
 * status/capabilities still answer 200 with installed:false and every other
 * route answers 503, so the frontend degrades cleanly instead of 404-ing. */
extern const struct jmx_api_route vm_api_routes[];

#endif /* WEBD_API_VM_H */

// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_SYSTEM_MONITOR_H
#define WEBD_API_SYSTEM_MONITOR_H

#include "api_router.h"

/*
 * Read-only resource-manager monitoring surface (processes, per-core CPU + CPU
 * model, per-interface throughput, startup items) plus the one write route,
 * process signal delivery.
 *
 * Every reader runs in the webd pool worker that serves the request, never on
 * core's single uloop control-plane thread: an unbounded /proc walk on that
 * thread is what froze the box (see the maintenance-io-worker fix). Rate
 * figures are produced by in-request double sampling (read, sleep, read, diff),
 * so the sample window is deterministic regardless of which pool worker handled
 * the previous poll -- webd's 16 persistent workers share no memory, so a
 * cross-request last-snapshot is not reliable.
 */
extern const struct jmx_api_route system_monitor_api_routes[];

#endif /* WEBD_API_SYSTEM_MONITOR_H */

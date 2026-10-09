// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Route table and dispatcher for the webd REST surface.
 *
 * The dispatch chain in handle_client() is an ordered if-else list where the
 * first match wins, and prefix branches deliberately shadow longer siblings.
 * That order is behaviour, not style, so the table reproduces it exactly:
 * declaration order inside a module's array, then module order in
 * g_route_tables[]. jmxd/tests/test_route_inventory_stability.py locks the
 * order against the extracted inventory.
 *
 * Two deliberate choices:
 *
 *   - No linker-section auto-registration. OpenWrt link flags vary by target
 *     and --gc-sections silently drops a section, which presents as "this whole
 *     group of routes 404s" long after the build that caused it.
 *     g_route_tables[] in api_router.c is written out by hand instead.
 *
 *   - `methods` is a comma-separated string with "" meaning any method, which
 *     is the same shape as struct route_risk in jmx_app_perms.c. Keeping them
 *     identical lets the risk-table drift test compare two tables rather than
 *     parse dispatch source text.
 */
#ifndef WEBD_API_ROUTER_H
#define WEBD_API_ROUTER_H

#include <json-c/json.h>

#include "api_context.h"

#define JMX_API_EXACT     0u        /* whole-string match */
#define JMX_API_PREFIX    (1u << 0) /* prefix match, for /{id} subtrees */
#define JMX_API_PREAUTH   (1u << 1) /* answered before the permission gate */
#define JMX_API_RAW_FD    (1u << 2) /* handler writes the socket; returns NULL */
#define JMX_API_NO_BODY   (1u << 3) /* binary upload; body is not parsed as JSON */
#define JMX_API_PREDICATE_ONLY (1u << 4) /* skip fixed path; predicate owns matching */
#define JMX_API_PREDICATE_MIXED (1u << 5) /* fixed path plus predicate subpaths */

/*
 * original_seq is deliberately a preprocessing-only migration annotation.
 * The route inventory extractor reads it to merge table rows back into the
 * legacy chain's original order; the compiler sees the same four-field
 * initializer as before. Predicate rows use the companion macro: the fixed
 * path is tried first, then the predicate may accept a structured alias such
 * as /v2/api/site/{site}/topology without weakening it to a broad prefix.
 *
 * original_seq must be positive and unique across every module. A row moved
 * out of the legacy chain keeps its position from the committed inventory. A
 * brand-new route has no legacy position: give it the next unused number above
 * every existing one (the 9xx append block), never 0 and never a mid-list
 * number. The extractor pins each seq to that absolute slot, so a mid-list
 * insert shifts every later legacy row past the pinned migrated rows and reads
 * as spurious reordering.
 */
#define JMX_API_ROUTE(original_seq, path, methods, flags, handler) \
    { path, methods, flags, handler, NULL }
#define JMX_API_PREDICATE_ROUTE(original_seq, path, methods, flags, predicate, handler) \
    { path, methods, flags, handler, predicate }
#define JMX_API_ROUTE_END { NULL, NULL, 0u, NULL, NULL }

struct jmx_api_route {
    const char *path;
    const char *methods;
    unsigned    flags;
    struct json_object *(*handler)(struct jmx_api_ctx *ctx);
    int (*predicate)(const char *path);
};

/*
 * Dispatch outcome. The caller cannot infer this from the returned object,
 * because a handled request may legitimately produce no object (RAW_FD), and a
 * miss must fall through to the legacy chain rather than answer 404 here.
 */
enum jmx_api_dispatch_result {
    JMX_API_DISPATCH_MISS = 0,   /* no route matched; caller continues */
    JMX_API_DISPATCH_HANDLED,    /* handler ran; *out holds its response or NULL */
};

/*
 * Match ctx->req against the table and run the first matching handler.
 *
 * preauth selects which half of the table is eligible: nonzero matches only
 * JMX_API_PREAUTH rows, zero matches only the rest. The two dispatch points in
 * handle_client() sit on either side of the permission gate, and a post-auth
 * route must never be reachable from the pre-auth point.
 */
enum jmx_api_dispatch_result jmx_api_router_dispatch(struct jmx_api_ctx *ctx,
                                                    int preauth,
                                                    struct json_object **out);

/* Number of registered routes. Used by tests and by the startup self-check. */
unsigned jmx_api_router_route_count(void);

/*
 * Ordered read-only access to the table, for the contract tests that compare
 * the table against the extracted route inventory.
 */
const struct jmx_api_route *jmx_api_router_route_at(unsigned index);

#endif /* WEBD_API_ROUTER_H */

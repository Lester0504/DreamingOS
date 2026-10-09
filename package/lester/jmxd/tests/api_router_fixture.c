// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Drives jmx_api_router_dispatch() against tables the fixture owns.
 *
 * The matcher is exercised against tables this fixture supplies through the
 * JMX_API_ROUTER_TEST_STANDALONE hook, the same pattern ac_transport.c uses,
 * so a matcher defect surfaces now rather than being read later as "the route
 * that was just migrated is broken".
 *
 * json-c is never called here: struct json_object is opaque to the router, so
 * handlers return small sentinel pointers and nothing is allocated.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "api_router.h"

/* Opaque to the router, so a distinguishable non-NULL value is enough. */
#define RESP(n) ((struct json_object *)(uintptr_t)(0x1000 + (n)))

static struct {
    const char *handler;
    int fd_seen;
    int calls;
} g_log;

static int g_failures;

static void check(int condition, const char *what)
{
    if (!condition) {
        printf("FAIL: %s\n", what);
        g_failures++;
    }
}

static struct json_object *record(struct jmx_api_ctx *ctx, const char *name,
                                  int response)
{
    g_log.handler = name;
    g_log.fd_seen = ctx->fd;
    g_log.calls++;
    return RESP(response);
}

static struct json_object *h_exact(struct jmx_api_ctx *ctx)
{
    return record(ctx, "exact", 1);
}

static struct json_object *h_prefix(struct jmx_api_ctx *ctx)
{
    return record(ctx, "prefix", 2);
}

static struct json_object *h_shadowed(struct jmx_api_ctx *ctx)
{
    return record(ctx, "shadowed", 3);
}

static struct json_object *h_preauth(struct jmx_api_ctx *ctx)
{
    return record(ctx, "preauth", 4);
}

static struct json_object *h_raw(struct jmx_api_ctx *ctx)
{
    record(ctx, "raw", 5);
    /* A RAW_FD handler writes the socket itself and returns nothing. */
    return NULL;
}

static struct json_object *h_any_method(struct jmx_api_ctx *ctx)
{
    return record(ctx, "any_method", 6);
}

static struct json_object *h_get_post(struct jmx_api_ctx *ctx)
{
    return record(ctx, "get_post", 7);
}

static struct json_object *h_second_table(struct jmx_api_ctx *ctx)
{
    return record(ctx, "second_table", 8);
}

static struct json_object *h_mutates_ctx(struct jmx_api_ctx *ctx)
{
    ctx->body = RESP(99);
    ctx->status = 404;
    return record(ctx, "mutates_ctx", 9);
}

static struct json_object *h_predicate(struct jmx_api_ctx *ctx)
{
    return record(ctx, "predicate", 10);
}

static struct json_object *h_predicate_only(struct jmx_api_ctx *ctx)
{
    return record(ctx, "predicate_only", 15);
}

static struct json_object *h_predicate_mixed(struct jmx_api_ctx *ctx)
{
    return record(ctx, "predicate_mixed", 16);
}

static int match_fixture_alias(const char *path)
{
    return path && !strcmp(path, "/fixture/alias");
}

/*
 * Phase 5B shapes. A PREDICATE_ONLY row owns matching outright, so its fixed
 * path string must not match on its own; a PREDICATE_MIXED row keeps the fixed
 * collection path and adds subresources through the predicate.
 */
static int match_fixture_id_only(const char *path)
{
    const char *base = "/fixture/zones/";
    const char *tail;

    if (!path || strncmp(path, base, strlen(base)) != 0)
        return 0;
    tail = path + strlen(base);
    return tail[0] && !strchr(tail, '/');
}

static int match_fixture_mixed(const char *path)
{
    const char *base = "/fixture/objects/";

    if (!path)
        return 0;
    return !strcmp(path, "/fixture/objects") ||
           (!strncmp(path, base, strlen(base)) && path[strlen(base)]);
}

#define END_OF_TABLE JMX_API_ROUTE_END

/*
 * api_router.c references the real module symbols in production. The matcher
 * fixture does not link their implementations, so these shape-compatible
 * stand-ins prove table wiring and order without importing module dependencies.
 */
static struct json_object *h_dashboard(struct jmx_api_ctx *ctx)
{
    return record(ctx, "dashboard", 11);
}

static struct json_object *h_insights(struct jmx_api_ctx *ctx)
{
    return record(ctx, "insights", 12);
}

static struct json_object *h_ble_provision(struct jmx_api_ctx *ctx)
{
    return record(ctx, "ble_provision", 13);
}

static struct json_object *h_policy_objects(struct jmx_api_ctx *ctx)
{
    return record(ctx, "policy_objects", 14);
}

static struct json_object *h_routing(struct jmx_api_ctx *ctx)
{
    return record(ctx, "routing", 17);
}

static struct json_object *h_clients_list(struct jmx_api_ctx *ctx)
{
    return record(ctx, "clients_list", 18);
}


/* Newer modules are represented by unique fixture rows. Full production
 * paths and methods are locked by test_route_inventory_stability.py. */
const struct jmx_api_route support_api_routes[] = {
    JMX_API_ROUTE(1, "/fixture/support_api_routes", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

const struct jmx_api_route community_api_routes[] = {
    JMX_API_ROUTE(1, "/fixture/community_api_routes", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

const struct jmx_api_route ad_analyzer_api_routes[] = {
    JMX_API_ROUTE(1, "/fixture/ad_analyzer_api_routes", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

const struct jmx_api_route audit_log_api_routes[] = {
    JMX_API_ROUTE(1, "/fixture/audit_log_api_routes", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

const struct jmx_api_route system_monitor_api_routes[] = {
    JMX_API_ROUTE(1, "/fixture/system_monitor_api_routes", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

const struct jmx_api_route tvhome_api_routes[] = {
    JMX_API_ROUTE(1, "/fixture/tvhome_api_routes", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

const struct jmx_api_route iptv_api_routes[] = {
    JMX_API_ROUTE(1, "/fixture/iptv_api_routes", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

const struct jmx_api_route vm_api_routes[] = {
    JMX_API_ROUTE(1, "/fixture/vm_api_routes", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

const struct jmx_api_route feature_api_routes[] = {
    JMX_API_ROUTE(1, "/fixture/feature_api_routes", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

const struct jmx_api_route netboot_api_routes[] = {
    JMX_API_ROUTE(1, "/fixture/netboot_api_routes", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

const struct jmx_api_route tasks_api_routes[] = {
    JMX_API_ROUTE(1, "/fixture/tasks_api_routes", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};


const struct jmx_api_route desktop_api_routes[] = {
    JMX_API_ROUTE(9613, "/api/v1/desktop/apps", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

const struct jmx_api_route insights_api_routes[] = {
    JMX_API_ROUTE(215, "/api/v1/insights/flows/risk", "GET", JMX_API_EXACT, h_insights),
    JMX_API_ROUTE(216, "/api/v1/insights/flows/activity", "GET", JMX_API_EXACT, h_insights),
    JMX_API_ROUTE_END,
};

const struct jmx_api_route dashboard_api_routes[] = {
    JMX_API_ROUTE(305, "/api/v1/dashboard/status", "GET", JMX_API_EXACT, h_dashboard),
    JMX_API_ROUTE_END,
};

const struct jmx_api_route topology_api_routes[] = {
    JMX_API_PREDICATE_ROUTE(331, "/api/v1/topology", "GET", JMX_API_EXACT,
                            match_fixture_alias, h_predicate),
    JMX_API_ROUTE(332, "/api/v1/topology/flow", "GET", JMX_API_EXACT, h_exact),
    JMX_API_PREDICATE_ROUTE(333, "[helper:webd_topology_history_path]", "GET",
                            JMX_API_EXACT, match_fixture_alias, h_predicate),
    JMX_API_PREDICATE_ROUTE(334, "/api/v1/topology/infrastructure", "GET",
                            JMX_API_EXACT, match_fixture_alias, h_predicate),
    JMX_API_PREDICATE_ROUTE(
        335, "[helper:webd_is_unifi_digital_twin_layout_path]", "GET",
        JMX_API_EXACT, match_fixture_alias, h_predicate),
    JMX_API_ROUTE_END,
};

const struct jmx_api_route policy_read_api_routes[] = {
    JMX_API_ROUTE(140, "/api/v1/policy-engine/policy-table", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(141, "/api/v1/policy-engine/policy-table/", "GET", JMX_API_PREFIX, h_prefix),
    JMX_API_ROUTE(143, "/api/v1/policy-engine/catalog", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

const struct jmx_api_route policy_write_api_routes[] = {
    JMX_API_ROUTE(142, "/api/v1/policy-engine/policy-table", "POST,PUT,PATCH,DELETE",
                  JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

/*
 * Phase 5B stand-in. The seven rows mirror the production module's shape:
 * two exact collection rows, two PREDICATE_ONLY detail rows, the zone matrix,
 * and two PREDICATE_MIXED object rows.
 */
const struct jmx_api_route policy_objects_api_routes[] = {
    JMX_API_ROUTE(144, "/api/v1/policy-engine/zones", "GET", JMX_API_EXACT, h_policy_objects),
    JMX_API_ROUTE(145, "/api/v1/policy-engine/zones", "POST", JMX_API_EXACT, h_policy_objects),
    JMX_API_PREDICATE_ROUTE(146, "/api/v1/policy-engine/zones/", "GET",
                            JMX_API_PREDICATE_ONLY, match_fixture_id_only,
                            h_policy_objects),
    JMX_API_PREDICATE_ROUTE(147, "/api/v1/policy-engine/zones/", "PUT,PATCH,DELETE",
                            JMX_API_PREDICATE_ONLY, match_fixture_id_only,
                            h_policy_objects),
    JMX_API_ROUTE(148, "/api/v1/policy-engine/zone-matrix", "GET", JMX_API_EXACT, h_policy_objects),
    JMX_API_PREDICATE_ROUTE(149, "/api/v1/policy-engine/objects", "GET",
                            JMX_API_PREDICATE_MIXED, match_fixture_mixed,
                            h_policy_objects),
    JMX_API_PREDICATE_ROUTE(150, "/api/v1/policy-engine/objects",
                            "POST,PUT,PATCH,DELETE", JMX_API_PREDICATE_MIXED,
                            match_fixture_mixed, h_policy_objects),
    JMX_API_ROUTE_END,
};

const struct jmx_api_route routing_api_routes[] = {
    JMX_API_ROUTE(490, "/api/v1/routing", "GET", JMX_API_EXACT, h_routing),
    JMX_API_ROUTE(515, "/api/v1/routing/external-policies", "GET", JMX_API_EXACT, h_routing),
    JMX_API_ROUTE_END,
};

const struct jmx_api_route clients_list_api_routes[] = {
    JMX_API_ROUTE(586, "/api/v1/clients", "", JMX_API_EXACT, h_clients_list),
    JMX_API_ROUTE_END,
};

const struct jmx_api_route client_control_api_routes[] = {
    JMX_API_ROUTE(588, "/api/v1/client_control_rules", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(589, "/api/v1/client_control_rule", "POST", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(590, "/api/v1/client_control_rule/update", "POST", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(591, "/api/v1/client_control_rule/toggle", "POST", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(592, "/api/v1/client_control_rule/delete", "POST", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

const struct jmx_api_route client_connections_api_routes[] = {
    JMX_API_ROUTE(593, "/api/v1/client_connections/clear", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(594, "/api/v1/client_connections/close", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(595, "/api/v1/client_protocol_control", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

const struct jmx_api_route client_profile_api_routes[] = {
    JMX_API_ROUTE(587, "/api/v1/client_profile", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

/* Phase 6E flowd control-plane module. The real array carries 61 exact rows;
 * this stand-in keeps a representative span (the three richer readers plus a
 * proxy) with real seqs so the table-of-tables links and module-order checks
 * pass without flowd's ubus dependencies. */
const struct jmx_api_route flowd_api_routes[] = {
    JMX_API_ROUTE(232, "/api/v1/flowd/status", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(259, "/api/v1/flowd/wan-health", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(303, "/api/v1/flowd/runtime", "GET,POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

/* Phase 6F aegis security-intelligence module. The real array carries 46 exact
 * rows (8 of them predicate-backed); this stand-in keeps a representative span
 * with real seqs so the table-of-tables links and module-order checks pass
 * without aegis's ubus dependencies. */
const struct jmx_api_route aegis_api_routes[] = {
    JMX_API_ROUTE(155, "/api/v1/aegis/status", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(164, "/api/v1/aegis/events", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(206, "/api/v1/aegis/signatures/unsuppress", "POST", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

const struct jmx_api_route toolkit_api_routes[] = {
    JMX_API_ROUTE(596, "/api/v1/toolkit", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(597, "/api/v1/toolkit/router-check", "GET,POST", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(598, "/api/v1/toolkit/port-mirror", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(599, "/api/v1/toolkit/port-mirror", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(600, "/api/v1/toolkit/port-mirror", "DELETE", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(602, "/api/v1/toolkit/ddns", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(603, "/api/v1/toolkit/ddns", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(605, "/api/v1/toolkit/ddns/update", "POST", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(606, "/api/v1/toolkit/wake-on-lan", "POST", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(607, "/api/v1/toolkit/throughput", "POST", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(608, "/api/v1/toolkit/throughput/status", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(609, "/api/v1/toolkit/throughput/stop", "POST", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(610, "/api/v1/diagnostics/ping", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(611, "/api/v1/diagnostics/traceroute", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(612, "/api/v1/diagnostics/nslookup", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(613, "/api/v1/diagnostics/speedtest", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(960, "/api/v1/diagnostics/port-scan", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(961, "/api/v1/diagnostics/port-check", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(962, "/api/v1/diagnostics/tcp-udp-test", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(963, "/api/v1/diagnostics/ssl-check", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(964, "/api/v1/diagnostics/http-request", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(965, "/api/v1/diagnostics/headers", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(966, "/api/v1/diagnostics/website-check", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(967, "/api/v1/diagnostics/local-ports", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(968, "/api/v1/diagnostics/local-info", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(969, "/api/v1/diagnostics/arp-scan", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(970, "/api/v1/diagnostics/mtu-detect", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(971, "/api/v1/diagnostics/latency-monitor", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(972, "/api/v1/diagnostics/whois", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(973, "/api/v1/diagnostics/dns-query", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(974, "/api/v1/diagnostics/public-ip", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(975, "/api/v1/diagnostics/ip-geo", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(976, "/api/v1/diagnostics/mac-lookup", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(977, "/api/v1/diagnostics/speedtest/status", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(978, "/api/v1/diagnostics/speedtest/stop", "POST", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(981, "/api/v1/diagnostics/mdns", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

/* The production router now registers BLE provisioning after toolkit. Keep a
 * shape-compatible stand-in so module-order checks link without APD objects. */
const struct jmx_api_route ble_provision_api_routes[] = {
    JMX_API_ROUTE(753, "/api/v1/ac/ble-provision/begin", "POST", JMX_API_EXACT, h_ble_provision),
    JMX_API_ROUTE(754, "/api/v1/ac/ble-provision/physical-confirm", "POST", JMX_API_EXACT, h_ble_provision),
    JMX_API_ROUTE(755, "/api/v1/ac/ble-provision/status", "GET", JMX_API_EXACT, h_ble_provision),
    JMX_API_ROUTE(756, "/api/v1/ac/ble-provision/commit", "POST", JMX_API_EXACT, h_ble_provision),
    JMX_API_ROUTE(757, "/api/v1/ac/ble-provision/cancel", "POST", JMX_API_EXACT, h_ble_provision),
    JMX_API_ROUTE_END,
};

/* Phase 6G registers the WiFi module between aegis and toolkit. Shape-compatible
 * stand-in sampling the edges + middle of the 14 migrated seq-630..644 rows so
 * the table-of-tables link and module-order check pass without ubus objects. */
const struct jmx_api_route wifi_api_routes[] = {
    JMX_API_ROUTE(630, "/api/v1/wifi/config", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(638, "/api/v1/wifi/transactions", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(644, "/api/v1/wifi/scan/jobs", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

/* Phase 6H registers the logd event-backend module between wifi and toolkit.
 * Shape-compatible stand-in sampling the edges + middle of the 11 migrated
 * seq-106..116 rows so the table-of-tables link and module-order check pass
 * without the dreamingwrt.logd ubus object. */
const struct jmx_api_route logd_api_routes[] = {
    JMX_API_ROUTE(106, "/api/v1/logd/status", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(113, "/api/v1/logd/events", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(116, "/api/v1/logd/events/clear", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

/* Phase 6I registers the notifyd delivery-backend module between logd and
 * toolkit. Shape-compatible stand-in sampling the edges + the rich
 * preferences/me row of the 16 migrated seq-117..135 exact rows (the 3 prefix
 * branches — channels/, routes/, outbox/ — stay in the legacy chain). Lets the
 * table-of-tables link and module-order check pass without dreamingwrt.notifyd. */
const struct jmx_api_route notifyd_api_routes[] = {
    JMX_API_ROUTE(117, "/api/v1/notifyd/status", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(121, "/api/v1/notifyd/preferences/me", "GET,POST,PUT,PATCH", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(135, "/api/v1/notifyd/deliver-due", "POST", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

/* Phase 6J registers the audit BFF module between notifyd and toolkit. Shape-
 * compatible stand-in sampling the exact edge (status seq207), a prefix detail
 * row (protocols/ seq228), and the exact tail (apps seq231) of the 9 migrated
 * seq-207..231 rows, so the table-of-tables link and module-order check pass
 * without the audit ubus/db dependencies. The 2 prefix rows carry no single-
 * segment guard — the detail handlers extract the tail token internally — so a
 * plain JMX_API_PREFIX route reproduces the legacy strncmp faithfully. */
const struct jmx_api_route audit_api_routes[] = {
    JMX_API_ROUTE(207, "/api/v1/audit/status", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(228, "/api/v1/audit/protocols/", "GET", JMX_API_PREFIX, h_prefix),
    JMX_API_ROUTE(231, "/api/v1/audit/apps", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

/* Phase 6K registers the WAN-policy BFF module between audit and toolkit. The
 * wan-policies row matched `exact "/api/v1/network/wan-policies" OR strncmp of
 * the ".../wan-policies/" transaction subtree`, so it is ONE PREDICATE_MIXED
 * row: the matcher keeps the fixed collection path and wan_policies_path()
 * supplies the strncmp half. wan-policy and wan-rules are plain exact rows. This
 * shape-compatible stand-in lets the table-of-tables link and module-order check
 * pass without the flowd/route-config dependencies. */
static int wan_policies_path(const char *path)
{
    return path && !strncmp(path, "/api/v1/network/wan-policies/", 29);
}

const struct jmx_api_route wan_api_routes[] = {
    JMX_API_PREDICATE_ROUTE(152, "/api/v1/network/wan-policies", "GET,POST,PATCH,DELETE", JMX_API_PREDICATE_MIXED, wan_policies_path, h_prefix),
    JMX_API_ROUTE(153, "/api/v1/network/wan-policy", "GET,PUT,POST", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(154, "/api/v1/network/wan-rules", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

/* Phase 6L registers the authentication / captive-portal BFF module between wan
 * and toolkit. The real array carries 27 rows (26 exact seq-79..105 plus the one
 * notifications realtime|expiry|expired PUT PREDICATE_ONLY row at seq 96); the 7
 * `sizeof()-1` id-detail prefix branches stay inline in the monolith. This shape-
 * compatible stand-in samples the exact edges (seq 79 collection, seq 105 vouchers/
 * expired) plus the seq-96 predicate row, so the table-of-tables link and module-
 * order check pass without the dreamingwrt.authd ubus object. */
static int auth_notifications_kind_path(const char *path)
{
    return path &&
           (!strcmp(path, "/api/v1/authentication/notifications/realtime") ||
            !strcmp(path, "/api/v1/authentication/notifications/expiry") ||
            !strcmp(path, "/api/v1/authentication/notifications/expired"));
}

const struct jmx_api_route authentication_api_routes[] = {
    JMX_API_ROUTE(79, "/api/v1/authentication", "GET", JMX_API_EXACT, h_exact),
    JMX_API_PREDICATE_ROUTE(96, "/api/v1/authentication/notifications/realtime", "PUT", JMX_API_PREDICATE_ONLY, auth_notifications_kind_path, h_predicate_only),
    JMX_API_ROUTE(105, "/api/v1/authentication/vouchers/expired", "DELETE", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

/* Phase 6N registers the log-center BFF module between authentication and
 * toolkit. The real array carries 30 exact rows (seq 672-682, 688-705, 719); the
 * one RAW_FD download branch (seq 38) stays inline in the monolith. Four paths
 * carry a GET reader and a POST/PUT writer (warning-rules/channels/settings/
 * syslog-certs) as distinct path+method rows — no predicate. This shape-
 * compatible stand-in samples the exact edges (seq 672 query, seq 719 bare
 * collection) plus a same-path/different-method pair (settings GET vs POST,PUT),
 * so the table-of-tables link and module-order check pass without dreamingwrt.logd. */
const struct jmx_api_route logs_api_routes[] = {
    JMX_API_ROUTE(672, "/api/v1/logs/query", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(689, "/api/v1/logs/settings", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(690, "/api/v1/logs/settings", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(719, "/api/v1/logs", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

/* Phase 6O registers the network-control / terminal-control BFF module between
 * logs and toolkit. The real array carries 20 rows (seq 410-429): 15 exact and
 * 5 prefix (JMX_API_PREFIX, reproducing the legacy strncmp whose numeric length
 * equals strlen(path)). Several paths carry more than one method row (matched on
 * path+method, no predicate); a prefix trailing-slash route's handler slug gets
 * a "_detail" infix so it never collides with the exact stem. This shape-
 * compatible stand-in samples the collection GET (seq 410), an exact/prefix pair
 * on the same stem (seq 411 terminal-limits GET exact vs seq 413 terminal-limits/
 * PUT,PATCH prefix), and the runtime-before-prefix precedence edge (seq 415
 * terminal-policies/runtime exact vs seq 418 terminal-policies/ GET prefix), so
 * the table link and module-order check pass without routed/tc. */
const struct jmx_api_route netcontrol_api_routes[] = {
    JMX_API_ROUTE(410, "/api/v1/network-control", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(411, "/api/v1/network-control/terminal-limits", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(413, "/api/v1/network-control/terminal-limits/", "PUT,PATCH", JMX_API_PREFIX, h_prefix),
    JMX_API_ROUTE(415, "/api/v1/network-control/terminal-policies/runtime", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(418, "/api/v1/network-control/terminal-policies/", "GET", JMX_API_PREFIX, h_prefix),
    JMX_API_ROUTE_END,
};

/* Phase 6P first-run setup wizard BFF. The production module carries 20 routes
 * (18 single-exact + 2 multi-exact detect-wan alias predicate routes); this
 * shape-compatible stand-in samples the exact stems plus one JMX_API_PREDICATE_ONLY
 * alias route (detect-wan/start|detect_wan/start) so the shared fixture links
 * against the shipped api_router.c and exercises the predicate slot. */
static int setup_stub_detect_wan_start_path(const char *path)
{
    return path &&
           (!strcmp(path, "/api/v1/setup/detect-wan/start") ||
            !strcmp(path, "/api/v1/setup/detect_wan/start"));
}
const struct jmx_api_route setup_api_routes[] = {
    JMX_API_ROUTE(48, "/api/v1/setup/status", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(57, "/api/v1/setup/finish", "POST", JMX_API_EXACT, h_exact),
    JMX_API_PREDICATE_ROUTE(60, "/api/v1/setup/detect-wan/start", "POST", JMX_API_PREDICATE_ONLY, setup_stub_detect_wan_start_path, h_exact),
    JMX_API_ROUTE(68, "/api/v1/setup/oauth/start", "POST", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

/* Phase 6Q storage management BFF. The production module carries 9 routes (8
 * single-exact + 1 multi-exact raid|raids alias predicate route); this
 * shape-compatible stand-in samples the exact stems plus the JMX_API_PREDICATE_ONLY
 * raid alias so the shared fixture links against the shipped api_router.c. */
static int storage_stub_raid_path(const char *path)
{
    return path &&
           (!strcmp(path, "/api/v1/storage/raid") ||
            !strcmp(path, "/api/v1/storage/raids"));
}
const struct jmx_api_route storage_api_routes[] = {
    JMX_API_ROUTE(401, "/api/v1/storage/overview", "GET", JMX_API_EXACT, h_exact),
    JMX_API_PREDICATE_ROUTE(404, "/api/v1/storage/raid", "GET", JMX_API_PREDICATE_ONLY, storage_stub_raid_path, h_exact),
    JMX_API_ROUTE(408, "/api/v1/storage/files/mutate", "POST", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(409, "/api/v1/storage/file-services", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

/* Phase 6R bulk-IP / IPAM management BFF. The production module carries 8
 * single-exact routes; this shape-compatible stand-in samples a few so the
 * shared fixture links against the shipped api_router.c. */
const struct jmx_api_route bulkip_api_routes[] = {
    JMX_API_ROUTE(526, "/api/v1/bulk-ip", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(529, "/api/v1/bulk-ip/reserve", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(533, "/api/v1/bulk-ip/import/commit", "POST", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

/* Phase 6S transactional config BFF. The production module carries 6 single-exact
 * routes (snapshot / last-apply are any-method, methods=""); this shape-compatible
 * stand-in samples a few so the shared fixture links against the shipped
 * api_router.c and exercises an any-method exact route. */
const struct jmx_api_route config_api_routes[] = {
    JMX_API_ROUTE(557, "/api/v1/config/snapshot", "", JMX_API_EXACT, h_any_method),
    JMX_API_ROUTE(559, "/api/v1/config/apply", "POST", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(562, "/api/v1/config/last-apply", "", JMX_API_EXACT, h_any_method),
    JMX_API_ROUTE_END,
};

/* Phase 6T cloud enrollment BFF. The production module carries 5 single-exact
 * routes; this shape-compatible stand-in samples a few so the shared fixture
 * links against the shipped api_router.c. */
const struct jmx_api_route cloud_api_routes[] = {
    JMX_API_ROUTE(683, "/api/v1/cloud/status", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(685, "/api/v1/cloud/config", "POST,PUT", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(687, "/api/v1/cloud/disable", "POST", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

/* The production router registers the App Store module last (after BLE). The
 * appstore phase wired it into production on both trees but left no fixture
 * stub; this shape-compatible stand-in lets the shared fixture link against the
 * shipped api_router.c. Its routes are table-native (seq 0), invisible to the
 * merged route inventory. */
const struct jmx_api_route appstore_api_routes[] = {
    JMX_API_ROUTE(0, "/api/v1/appstore/catalog", "GET,HEAD", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(0, "/api/v1/appstore/apps/", "", JMX_API_PREFIX, h_prefix),
    JMX_API_ROUTE_END,
};

/* OTA remote fetch (T3) is registered last in production, after the App Store.
 * Like the appstore stand-in above, this shape-compatible stub lets the shared
 * fixture link against the shipped api_router.c: g_route_tables[] references
 * ota_remote_api_routes as an extern under JMX_API_ROUTER_TEST_STANDALONE. Both
 * routes are table-native (seq 0), invisible to the merged route inventory. */
const struct jmx_api_route ota_remote_api_routes[] = {
    JMX_API_ROUTE(0, "/api/v1/system/ota/check", "POST", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(0, "/api/v1/system/ota/download", "POST", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

/* Certificate lifecycle rows use local string macros in production. */
const struct jmx_api_route wifi_certificate_api_routes[] = {
    JMX_API_ROUTE(9618, "/api/v1/wifi/certificates/tasks", "GET", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(9619, "/api/v1/wifi/certificates/tasks/", "GET,POST", JMX_API_PREFIX, h_prefix),
    JMX_API_ROUTE(9620, "/api/v1/wifi/certificates/server-renew", "POST", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(9621, "/api/v1/wifi/certificates/ap-renew", "POST", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(9622, "/api/v1/wifi/certificates/ca-rotate", "POST", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(9623, "/api/v1/wifi/certificates/revoke", "POST", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE_END,
};

const struct jmx_api_route people_api_routes[] = {
    JMX_API_ROUTE(9624, "/api/v1/people", "GET,POST", JMX_API_EXACT, h_exact),
    JMX_API_ROUTE(9625, "/api/v1/people/", "GET,PUT,DELETE", JMX_API_PREFIX, h_prefix),
    JMX_API_ROUTE(9626, "/api/v1/people-bindings/", "GET,PUT,DELETE", JMX_API_PREFIX, h_prefix),
    JMX_API_ROUTE_END,
};

static const struct jmx_api_route k_routes_main[] = {
    { "/api/v1/exact",        "GET",       JMX_API_EXACT,   h_exact, NULL },
    { "/api/v1/methods/any",  "",          JMX_API_EXACT,   h_any_method, NULL },
    { "/api/v1/methods/two",  "GET,POST",  JMX_API_EXACT,   h_get_post, NULL },
    /*
     * The prefix row is declared before the longer exact path it covers, which
     * is how the if-else chain shadows today. Declaration order is the
     * contract, not a detail.
     */
    { "/api/v1/things/",      "",          JMX_API_PREFIX,  h_prefix, NULL },
    { "/api/v1/things/exact", "",          JMX_API_EXACT,   h_shadowed, NULL },
    { "/api/v1/preauth",      "",          JMX_API_PREAUTH, h_preauth, NULL },
    { "/api/v1/raw",          "GET",       JMX_API_RAW_FD,  h_raw, NULL },
    { "/api/v1/ctx",          "POST",      JMX_API_EXACT,   h_mutates_ctx, NULL },
    JMX_API_PREDICATE_ROUTE(0, "/api/v1/predicate", "GET", JMX_API_EXACT,
                            match_fixture_alias, h_predicate),
    /*
     * Phase 5B: a PREDICATE_ONLY row must not match its own fixed path, so the
     * bare collection-with-slash form falls through instead of being taken as a
     * detail request with an empty id.
     */
    JMX_API_PREDICATE_ROUTE(0, "/fixture/zones/", "GET", JMX_API_PREDICATE_ONLY,
                            match_fixture_id_only, h_predicate_only),
    /* A PREDICATE_MIXED row keeps its fixed path and adds subresources. */
    JMX_API_PREDICATE_ROUTE(0, "/fixture/objects", "GET",
                            JMX_API_PREDICATE_MIXED, match_fixture_mixed,
                            h_predicate_mixed),
    /* A row with no handler must be skipped, not treated as a match. */
    { "/api/v1/handlerless",  "",          JMX_API_EXACT,   NULL, NULL },
    { "/api/v1/handlerless",  "",          JMX_API_EXACT,   h_exact, NULL },
    END_OF_TABLE,
};

static const struct jmx_api_route k_routes_second[] = {
    { "/api/v1/second",       "",          JMX_API_EXACT,   h_second_table, NULL },
    /* Already shadowed by the prefix row in the first table. */
    { "/api/v1/things/later", "",          JMX_API_EXACT,   h_second_table, NULL },
    END_OF_TABLE,
};

static const struct jmx_api_route k_routes_empty[] = {
    END_OF_TABLE,
};

static const struct jmx_api_route *const k_tables_two[] = {
    k_routes_main,
    k_routes_second,
    NULL
};

static const struct jmx_api_route *const k_tables_empty[] = {
    NULL
};

static const struct jmx_api_route *const k_tables_empty_module[] = {
    k_routes_empty,
    NULL
};

static const struct jmx_api_route *const *g_tables = k_tables_two;

const struct jmx_api_route *const *jmx_api_router_test_tables(void)
{
    return g_tables;
}

/* Exported by api_router.c only under JMX_API_ROUTER_TEST_STANDALONE. */
const struct jmx_api_route *const *jmx_api_router_production_tables(void);

struct outcome {
    enum jmx_api_dispatch_result result;
    struct json_object *response;
    const char *handler;
    int fd_seen;
    int status;
    struct json_object *body;
};

static struct outcome dispatch(const char *method, const char *path,
                               int preauth, int fd)
{
    struct http_req req;
    struct jmx_api_ctx ctx;
    struct json_object *out = RESP(0);
    struct outcome outcome;

    memset(&req, 0, sizeof(req));
    memset(&ctx, 0, sizeof(ctx));
    memset(&g_log, 0, sizeof(g_log));

    snprintf(req.method, sizeof(req.method), "%s", method);
    snprintf(req.path, sizeof(req.path), "%s", path);

    ctx.req = &req;
    ctx.body = RESP(50);
    ctx.status = 200;
    ctx.fd = fd;

    outcome.result = jmx_api_router_dispatch(&ctx, preauth, &out);
    outcome.response = out;
    outcome.handler = g_log.handler;
    outcome.fd_seen = g_log.fd_seen;
    outcome.status = ctx.status;
    outcome.body = ctx.body;
    return outcome;
}

static int hit(struct outcome outcome, const char *handler)
{
    return outcome.result == JMX_API_DISPATCH_HANDLED && outcome.handler &&
           !strcmp(outcome.handler, handler);
}

static int missed(struct outcome outcome)
{
    /*
     * A miss must leave *out untouched: the caller keeps its own object there
     * and a router that blanked it would drop a response.
     */
    return outcome.result == JMX_API_DISPATCH_MISS && outcome.handler == NULL &&
           outcome.response == RESP(0);
}

static void case_exact_match(void)
{
    check(hit(dispatch("GET", "/api/v1/exact", 0, 7), "exact"),
          "exact path with the declared method must be handled");
    check(missed(dispatch("GET", "/api/v1/exact/", 0, 7)),
          "exact route must not match a trailing slash");
    check(missed(dispatch("GET", "/api/v1/exactly", 0, 7)),
          "exact route must not match a longer path sharing its prefix");
    check(missed(dispatch("GET", "/api/v1/exac", 0, 7)),
          "exact route must not match a truncated path");
}

static void case_prefix_match(void)
{
    check(hit(dispatch("GET", "/api/v1/things/abc", 0, 7), "prefix"),
          "prefix route must match a subresource path");
    check(hit(dispatch("DELETE", "/api/v1/things/abc/members/1", 0, 7),
              "prefix"),
          "prefix route must match a deeper subresource path");
    check(missed(dispatch("GET", "/api/v1/things", 0, 7)),
          "prefix route ending in / must not match the bare collection path");
}

static void case_predicate_match(void)
{
    check(hit(dispatch("GET", "/api/v1/predicate", 0, 7), "predicate"),
          "a predicate route must still match its fixed exact path");
    check(hit(dispatch("GET", "/fixture/alias", 0, 7), "predicate"),
          "a predicate route must accept a structured alias");
    check(missed(dispatch("POST", "/fixture/alias", 0, 7)),
          "predicate matching must not bypass the method filter");
    check(missed(dispatch("GET", "/fixture/alias/extra", 0, 7)),
          "the predicate, not a broad prefix, decides alias boundaries");
    check(missed(dispatch("GET", "/fixture/alias", 1, 7)),
          "predicate matching must not bypass pre-auth isolation");
}

static void case_predicate_only_and_mixed(void)
{
    /*
     * PREDICATE_ONLY exists because the migrated zone-detail rows carry the
     * collection prefix as their documented path. Matching that string
     * directly would answer /zones/ as a detail request whose id is empty,
     * which the if-else chain it replaces refuses.
     */
    check(missed(dispatch("GET", "/fixture/zones/", 0, 7)),
          "a PREDICATE_ONLY row must not match its own fixed path");
    check(hit(dispatch("GET", "/fixture/zones/lan", 0, 7), "predicate_only"),
          "a PREDICATE_ONLY row must match what its predicate accepts");
    check(missed(dispatch("GET", "/fixture/zones/lan/members", 0, 7)),
          "a PREDICATE_ONLY row must not reach deeper subresources");
    check(missed(dispatch("POST", "/fixture/zones/lan", 0, 7)),
          "PREDICATE_ONLY must not bypass the method filter");
    check(missed(dispatch("GET", "/fixture/zones/lan", 1, 7)),
          "PREDICATE_ONLY must not bypass pre-auth isolation");

    check(hit(dispatch("GET", "/fixture/objects", 0, 7), "predicate_mixed"),
          "a PREDICATE_MIXED row must still match its fixed collection path");
    check(hit(dispatch("GET", "/fixture/objects/7", 0, 7), "predicate_mixed"),
          "a PREDICATE_MIXED row must match a subresource its predicate accepts");
    check(missed(dispatch("GET", "/fixture/objects/", 0, 7)),
          "a PREDICATE_MIXED row must refuse an empty subresource id, as the "
          "chain branch it replaces does");
    check(missed(dispatch("GET", "/fixture/objectsx", 0, 7)),
          "a PREDICATE_MIXED row must not degrade into a prefix match");
    check(missed(dispatch("DELETE", "/fixture/objects", 0, 7)),
          "PREDICATE_MIXED must not bypass the method filter");
}

static void case_first_match_wins(void)
{
    check(hit(dispatch("GET", "/api/v1/things/exact", 0, 7), "prefix"),
          "an earlier prefix row must shadow a later exact row, as the chain does");
    check(hit(dispatch("GET", "/api/v1/things/later", 0, 7), "prefix"),
          "an earlier module's prefix row must shadow a later module's route");
    check(hit(dispatch("GET", "/api/v1/second", 0, 7), "second_table"),
          "a later module's own route must still be reachable");
}

static void case_method_filter(void)
{
    check(hit(dispatch("GET", "/api/v1/methods/two", 0, 7), "get_post"),
          "first entry of a comma list must match");
    check(hit(dispatch("POST", "/api/v1/methods/two", 0, 7), "get_post"),
          "last entry of a comma list must match");
    check(missed(dispatch("DELETE", "/api/v1/methods/two", 0, 7)),
          "a method outside the comma list must not match");
    check(missed(dispatch("GE", "/api/v1/methods/two", 0, 7)),
          "a method that is a prefix of a listed one must not match");
    check(missed(dispatch("GETX", "/api/v1/methods/two", 0, 7)),
          "a method that extends a listed one must not match");
    check(hit(dispatch("PATCH", "/api/v1/methods/any", 0, 7), "any_method"),
          "an empty methods string must mean any method");
    /*
     * A chain branch written as `if (!strcmp(req.path, ...))` never looks at
     * the method, so an unparsed method still reaches its handler today. The
     * router matches that: "" on the route means the method is not consulted.
     * A route that does list methods must still refuse it.
     */
    check(hit(dispatch("", "/api/v1/methods/any", 0, 7), "any_method"),
          "an any-method route must not start consulting the method, since the "
          "chain branch it replaces does not either");
    check(missed(dispatch("", "/api/v1/methods/two", 0, 7)),
          "a request with no method must not match a route that lists methods");
    check(missed(dispatch("", "/api/v1/exact", 0, 7)),
          "a request with no method must not match a single-method route");
}

static void case_preauth_isolation(void)
{
    check(hit(dispatch("GET", "/api/v1/preauth", 1, 7), "preauth"),
          "a PREAUTH route must be reachable from the pre-auth point");
    check(missed(dispatch("GET", "/api/v1/preauth", 0, 7)),
          "a PREAUTH route must not be reachable from the post-auth point");
    check(missed(dispatch("GET", "/api/v1/exact", 1, 7)),
          "a post-auth route must never run from the pre-auth point, which is "
          "before the permission gate");
    check(missed(dispatch("GET", "/api/v1/things/abc", 1, 7)),
          "a post-auth prefix route must not leak into the pre-auth half");
}

static void case_fd_visibility(void)
{
    struct outcome raw = dispatch("GET", "/api/v1/raw", 0, 7);

    check(raw.result == JMX_API_DISPATCH_HANDLED && raw.response == NULL,
          "a RAW_FD handler returning NULL must still report HANDLED");
    check(raw.fd_seen == 7, "a RAW_FD handler must see the real descriptor");

    check(dispatch("GET", "/api/v1/exact", 0, 7).fd_seen == -1,
          "a handler without RAW_FD must see fd == -1, so a stray write fails "
          "instead of landing on an unrelated descriptor");
    check(dispatch("GET", "/api/v1/things/abc", 0, 7).fd_seen == -1,
          "the fd is withheld from prefix handlers too");
}

static void case_ctx_ownership(void)
{
    struct outcome outcome = dispatch("POST", "/api/v1/ctx", 0, 7);

    check(hit(outcome, "mutates_ctx"), "the ctx-mutating route must be handled");
    check(outcome.body == RESP(99),
          "a body the handler swapped in must survive dispatch, so the caller "
          "frees the current object rather than the original");
    check(outcome.status == 404,
          "a status the handler set must not be reset by the router");
}

static void case_handlerless_row(void)
{
    check(hit(dispatch("GET", "/api/v1/handlerless", 0, 7), "exact"),
          "a row with a NULL handler must be skipped so a later row can match");
}

static void case_empty_tables(void)
{
    g_tables = k_tables_empty;
    check(missed(dispatch("GET", "/api/v1/exact", 0, 7)),
          "an empty table of tables must miss, which is the Phase 1 no-op");
    check(jmx_api_router_route_count() == 0,
          "an empty table of tables must count zero routes");
    check(jmx_api_router_route_at(0) == NULL,
          "route_at() must return NULL past the end of an empty table");

    g_tables = k_tables_empty_module;
    check(missed(dispatch("GET", "/api/v1/exact", 1, 7)),
          "a registered but empty module table must miss");
    check(jmx_api_router_route_count() == 0,
          "a registered but empty module table must count zero routes");

    g_tables = k_tables_two;
}

static void case_guards(void)
{
    struct http_req req;
    struct jmx_api_ctx ctx;
    struct json_object *out = RESP(0);

    memset(&req, 0, sizeof(req));
    memset(&ctx, 0, sizeof(ctx));
    memset(&g_log, 0, sizeof(g_log));
    snprintf(req.method, sizeof(req.method), "%s", "GET");
    snprintf(req.path, sizeof(req.path), "%s", "/api/v1/exact");

    check(jmx_api_router_dispatch(NULL, 0, &out) == JMX_API_DISPATCH_MISS,
          "a NULL ctx must miss rather than crash");

    ctx.req = NULL;
    check(jmx_api_router_dispatch(&ctx, 0, &out) == JMX_API_DISPATCH_MISS,
          "a ctx with no parsed request must miss");

    ctx.req = &req;
    check(jmx_api_router_dispatch(&ctx, 0, NULL) == JMX_API_DISPATCH_MISS,
          "a NULL out pointer must miss rather than be written through");
    check(g_log.calls == 0,
          "no handler may run while the arguments are being validated");
}

static void case_route_enumeration(void)
{
    unsigned main_len = 0;
    unsigned expected = 0;
    unsigned count;
    unsigned index;
    const struct jmx_api_route *route;

    for (route = k_routes_main; route->path; route++)
        main_len++;
    expected = main_len;
    for (route = k_routes_second; route->path; route++)
        expected++;

    count = jmx_api_router_route_count();
    check(count == expected,
          "route_count() must count every row across every module table");

    /*
     * route_at() must walk in dispatch order: the stability test compares that
     * order against the extracted inventory, so an out-of-order walk would
     * report false drift instead of a real reordering.
     */
    for (index = 0; index < count; index++) {
        const struct jmx_api_route *want =
            index < main_len ? &k_routes_main[index]
                             : &k_routes_second[index - main_len];

        if (jmx_api_router_route_at(index) != want) {
            printf("FAIL: route_at(%u) is out of dispatch order\n", index);
            g_failures++;
            break;
        }
    }

    check(jmx_api_router_route_at(count) == NULL,
          "route_at() must return NULL one past the last route");
    check(jmx_api_router_route_at(count + 100) == NULL,
          "route_at() must return NULL well past the end");
}

static void case_production_tables_have_current_modules(void)
{
    const struct jmx_api_route *const *tables =
        jmx_api_router_production_tables();
    const struct jmx_api_route *route;
    unsigned count = 0;

    /*
     * This is the first live migration. Lock the table-of-tables pointer and
     * each row's path/method/flags rather than accepting an accidentally empty,
     * truncated or different module.
     */
    check(tables != NULL, "the production table of tables must exist");
    check(tables && tables[0] == policy_read_api_routes &&
          tables[1] == policy_write_api_routes &&
          tables[2] == policy_objects_api_routes &&
          tables[3] == insights_api_routes &&
          tables[4] == dashboard_api_routes &&
          tables[5] == topology_api_routes &&
          tables[6] == routing_api_routes &&
          tables[7] == clients_list_api_routes &&
          tables[8] == client_control_api_routes &&
          tables[9] == client_connections_api_routes &&
          tables[10] == client_profile_api_routes &&
          tables[11] == flowd_api_routes &&
          tables[12] == aegis_api_routes &&
          tables[13] == wifi_api_routes &&
          tables[14] == wifi_certificate_api_routes &&
          tables[15] == logd_api_routes &&
          tables[16] == notifyd_api_routes &&
          tables[17] == audit_api_routes &&
          tables[18] == wan_api_routes &&
          tables[19] == authentication_api_routes &&
          tables[20] == logs_api_routes &&
          tables[21] == netcontrol_api_routes &&
          tables[22] == setup_api_routes &&
          tables[23] == storage_api_routes &&
          tables[24] == bulkip_api_routes &&
          tables[25] == config_api_routes &&
          tables[26] == cloud_api_routes &&
          tables[27] == support_api_routes &&
          tables[28] == community_api_routes &&
          tables[29] == ad_analyzer_api_routes &&
          tables[30] == audit_log_api_routes &&
          tables[31] == toolkit_api_routes &&
          tables[32] == ble_provision_api_routes &&
          tables[33] == appstore_api_routes &&
          tables[34] == system_monitor_api_routes &&
          tables[35] == ota_remote_api_routes &&
          tables[36] == tvhome_api_routes &&
          tables[37] == iptv_api_routes &&
          tables[38] == vm_api_routes &&
          tables[39] == feature_api_routes &&
          tables[40] == netboot_api_routes &&
          tables[41] == tasks_api_routes &&
          tables[42] == desktop_api_routes &&
          tables[43] == people_api_routes &&
          tables[44] == NULL,
          "the production tables must preserve the current module order");
    count = 0;
    for (route = policy_read_api_routes; route->path; route++)
        count++;
    check(count == 3, "the Phase 5A policy read module must contain three routes");
    check(!strcmp(policy_read_api_routes[0].path,
                  "/api/v1/policy-engine/policy-table") &&
          !strcmp(policy_read_api_routes[0].methods, "GET") &&
          policy_read_api_routes[0].flags == JMX_API_EXACT,
          "the first policy read row must retain seq 140 semantics");
    count = 0;
    for (route = policy_objects_api_routes; route->path; route++)
        count++;
    check(count == 7,
          "the Phase 5B policy objects module must contain seven routes");
    check(!strcmp(policy_objects_api_routes[0].path,
                  "/api/v1/policy-engine/zones") &&
          !strcmp(policy_objects_api_routes[0].methods, "GET") &&
          policy_objects_api_routes[0].flags == JMX_API_EXACT,
          "the first policy objects row must retain seq 144 semantics");
    check(policy_objects_api_routes[2].flags == JMX_API_PREDICATE_ONLY &&
          policy_objects_api_routes[2].predicate != NULL &&
          policy_objects_api_routes[3].flags == JMX_API_PREDICATE_ONLY &&
          policy_objects_api_routes[3].predicate != NULL,
          "the zone detail rows must stay predicate-owned so /zones/ with an "
          "empty id is not answered as a detail request");
    check(!strcmp(policy_objects_api_routes[4].path,
                  "/api/v1/policy-engine/zone-matrix") &&
          policy_objects_api_routes[4].flags == JMX_API_EXACT,
          "the zone matrix row must stay an exact GET, seq 148");
    check(policy_objects_api_routes[5].flags == JMX_API_PREDICATE_MIXED &&
          policy_objects_api_routes[5].predicate != NULL &&
          policy_objects_api_routes[6].flags == JMX_API_PREDICATE_MIXED &&
          !strcmp(policy_objects_api_routes[6].methods,
                  "POST,PUT,PATCH,DELETE"),
          "the object rows must keep the collection path plus predicate "
          "subresources, and the write row its four methods");
    count = 0;
    for (route = topology_api_routes; route->path; route++)
        count++;
    check(count == 5, "the topology production module must contain five routes");
    check(!strcmp(topology_api_routes[0].path, "/api/v1/topology") &&
          topology_api_routes[0].predicate != NULL,
          "the first Phase 3B row must retain its local path and UniFi predicate");
    check(topology_api_routes[1].predicate == NULL,
          "the exact topology flow row must not acquire a broader matcher");
    count = 0;
    for (route = clients_list_api_routes; route->path; route++)
        count++;
    check(count == 1, "the client-list production module must contain one route");
    check(!strcmp(clients_list_api_routes[0].path, "/api/v1/clients") &&
          !strcmp(clients_list_api_routes[0].methods, "") &&
          clients_list_api_routes[0].flags == JMX_API_EXACT,
          "the client-list route must remain exact, post-auth, and ANY-method");
    count = 0;
    for (route = toolkit_api_routes; route->path; route++)
        count++;
    check(count == 36, "the toolkit production module must contain 36 routes");
    check(!strcmp(toolkit_api_routes[0].path, "/api/v1/toolkit") &&
          !strcmp(toolkit_api_routes[0].methods, "GET") &&
          toolkit_api_routes[0].flags == JMX_API_EXACT,
          "the first production row must retain seq 596 semantics");
    check(!strcmp(toolkit_api_routes[15].path, "/api/v1/diagnostics/speedtest") &&
          !strcmp(toolkit_api_routes[15].methods, "POST,PUT") &&
          toolkit_api_routes[15].flags == JMX_API_EXACT,
          "seq 613 speedtest must keep its position and shape after the net-tool append");
    check(!strcmp(toolkit_api_routes[34].path, "/api/v1/diagnostics/speedtest/stop") &&
          !strcmp(toolkit_api_routes[34].methods, "POST") &&
          toolkit_api_routes[34].flags == JMX_API_EXACT,
          "seq 978 speedtest/stop must retain its position after the mdns append");
    check(!strcmp(toolkit_api_routes[35].path, "/api/v1/diagnostics/mdns") &&
          !strcmp(toolkit_api_routes[35].methods, "POST,PUT") &&
          toolkit_api_routes[35].flags == JMX_API_EXACT,
          "the final production row must retain seq 981 mdns semantics");
}

int main(void)
{
    case_exact_match();
    case_prefix_match();
    case_predicate_match();
    case_predicate_only_and_mixed();
    case_first_match_wins();
    case_method_filter();
    case_preauth_isolation();
    case_fd_visibility();
    case_ctx_ownership();
    case_handlerless_row();
    case_empty_tables();
    case_guards();
    case_route_enumeration();
    case_production_tables_have_current_modules();

    if (g_failures) {
        printf("%d router check(s) failed\n", g_failures);
        return 1;
    }
    printf("ok: matcher honours order, methods, prefixes, the pre-auth split, "
           "fd withholding and ctx ownership\n");
    return 0;
}

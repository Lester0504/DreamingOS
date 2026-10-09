// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Route matcher and dispatcher.
 *
 * Phase 3A registered the first production module table. The remaining routes
 * still miss here and fall through to handle_client()'s legacy chain; moved
 * routes are deleted from that chain rather than kept as dead duplicates.
 */
#include <string.h>

#include "api_router.h"
#include "api_dashboard.h"
#include "api_topology.h"
#include "api_toolkit.h"
#include "api_insights.h"
#include "api_policy_read.h"
#include "api_policy_write.h"
#include "api_policy_objects.h"
#include "api_ble_provision.h"
#include "api_routing.h"
#include "api_clients_list.h"
#include "api_client_control.h"
#include "api_client_connections.h"
#include "api_client_profile.h"
#include "api_flowd.h"
#include "api_aegis.h"
#include "api_wifi.h"
#include "api_logd.h"
#include "api_notifyd.h"
#include "api_audit.h"
#include "api_wan.h"
#include "api_authentication.h"
#include "api_logs.h"
#include "api_netcontrol.h"
#include "api_setup.h"
#include "api_storage.h"
#include "api_bulkip.h"
#include "api_config.h"
#include "api_cloud.h"
#include "api_support.h"
#include "api_community.h"
#include "api_ad_analyzer.h"
#include "api_audit_log.h"
#include "api_appstore.h"
#include "api_system_monitor.h"
#include "api_ota_remote.h"
#include "api_vm.h"
#include "api_tvhome.h"
#include "api_iptv.h"
#include "api_features.h"
#include "api_netboot.h"
#include "api_tasks.h"
#include "api_desktop.h"
#include "api_wifi_certificates.h"
#include "api_people.h"

/*
 * Table of tables, in dispatch order. Module arrays are appended here as each
 * migration phase lands, and the order of this list is part of the routing
 * contract: a prefix route in an earlier module shadows a longer path in a
 * later one, exactly as the if-else chain does today.
 *
 * The NULL terminator is the sentinel; the array is never zero-length, which
 * is not valid C.
 */
static const struct jmx_api_route *const g_route_tables[] = {
    policy_read_api_routes,
    policy_write_api_routes,
    policy_objects_api_routes,
    insights_api_routes,
    dashboard_api_routes,
    topology_api_routes,
    routing_api_routes,
    clients_list_api_routes,
    client_control_api_routes,
    client_connections_api_routes,
    client_profile_api_routes,
    flowd_api_routes,
    aegis_api_routes,
    wifi_api_routes,
    wifi_certificate_api_routes,
    logd_api_routes,
    notifyd_api_routes,
    audit_api_routes,
    wan_api_routes,
    authentication_api_routes,
    logs_api_routes,
    netcontrol_api_routes,
    setup_api_routes,
    storage_api_routes,
    bulkip_api_routes,
    config_api_routes,
    cloud_api_routes,
    support_api_routes,
    community_api_routes,
    ad_analyzer_api_routes,
    audit_log_api_routes,
    toolkit_api_routes,
    ble_provision_api_routes,
    appstore_api_routes,
    system_monitor_api_routes,
    ota_remote_api_routes,
    tvhome_api_routes,
    iptv_api_routes,
    vm_api_routes,
    feature_api_routes,
    netboot_api_routes,
    tasks_api_routes,
    desktop_api_routes,
    people_api_routes,
    NULL
};

/*
 * The fixture supplies its own matcher tables, following the
 * AC_TRANSPORT_TEST_STANDALONE pattern already used in ac_transport.c. It also
 * links small stand-ins for the production module arrays so the compiled
 * table can be inspected without linking their real dependencies.
 */
#ifdef JMX_API_ROUTER_TEST_STANDALONE
const struct jmx_api_route *const *jmx_api_router_test_tables(void);
#define JMX_API_ROUTER_TABLES jmx_api_router_test_tables()

/*
 * The fixture also needs the real table so it can assert that the expected
 * production module is registered. Parsing the source text alone would not
 * prove g_route_tables[] actually points at it.
 */
const struct jmx_api_route *const *jmx_api_router_production_tables(void)
{
    return g_route_tables;
}
#else
#define JMX_API_ROUTER_TABLES g_route_tables
#endif

static int method_matches(const char *method, const char *methods)
{
    size_t method_len;
    const char *p;

    /* Empty means "any method", the same convention as struct route_risk. */
    if (!methods || !methods[0])
        return 1;
    if (!method || !method[0])
        return 0;

    method_len = strlen(method);
    p = methods;
    while (*p) {
        const char *end = strchr(p, ',');
        size_t len = end ? (size_t)(end - p) : strlen(p);

        if (method_len == len && !strncmp(method, p, len))
            return 1;
        p += len;
        if (*p == ',')
            p++;
    }
    return 0;
}

static int path_matches(const struct jmx_api_route *route, const char *path)
{
    int fixed_match;

    if (!route->path || !path)
        return 0;
    if (!(route->flags & JMX_API_PREDICATE_ONLY)) {
        if (route->flags & JMX_API_PREFIX)
            fixed_match = !strncmp(path, route->path, strlen(route->path));
        else
            fixed_match = !strcmp(path, route->path);
        if (fixed_match)
            return 1;
    }
    return route->predicate ? route->predicate(path) : 0;
}

enum jmx_api_dispatch_result jmx_api_router_dispatch(struct jmx_api_ctx *ctx,
                                                     int preauth,
                                                     struct json_object **out)
{
    const struct jmx_api_route *const *tables = JMX_API_ROUTER_TABLES;
    size_t table;

    if (!ctx || !ctx->req || !out)
        return JMX_API_DISPATCH_MISS;

    for (table = 0; tables[table]; table++) {
        const struct jmx_api_route *route;

        for (route = tables[table]; route->path; route++) {
            int route_preauth = (route->flags & JMX_API_PREAUTH) ? 1 : 0;

            /*
             * The two dispatch points are on opposite sides of the permission
             * gate. A post-auth route reached from the pre-auth point would run
             * without a role check, so the halves are strictly separated rather
             * than merely ordered.
             */
            if (route_preauth != (preauth ? 1 : 0))
                continue;
            if (!path_matches(route, ctx->req->path))
                continue;
            if (!method_matches(ctx->req->method, route->methods))
                continue;
            if (!route->handler)
                continue;

            /*
             * Only a RAW_FD handler may touch the socket. Every other handler
             * sees -1, so a stray write fails instead of landing on whatever
             * descriptor happened to be there.
             */
            if (!(route->flags & JMX_API_RAW_FD))
                ctx->fd = -1;
            *out = route->handler(ctx);
            return JMX_API_DISPATCH_HANDLED;
        }
    }

    return JMX_API_DISPATCH_MISS;
}

unsigned jmx_api_router_route_count(void)
{
    const struct jmx_api_route *const *tables = JMX_API_ROUTER_TABLES;
    unsigned count = 0;
    size_t table;

    for (table = 0; tables[table]; table++) {
        const struct jmx_api_route *route;

        for (route = tables[table]; route->path; route++)
            count++;
    }
    return count;
}

const struct jmx_api_route *jmx_api_router_route_at(unsigned index)
{
    const struct jmx_api_route *const *tables = JMX_API_ROUTER_TABLES;
    unsigned seen = 0;
    size_t table;

    for (table = 0; tables[table]; table++) {
        const struct jmx_api_route *route;

        for (route = tables[table]; route->path; route++) {
            if (seen == index)
                return route;
            seen++;
        }
    }
    return NULL;
}

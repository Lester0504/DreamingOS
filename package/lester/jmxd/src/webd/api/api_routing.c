// SPDX-License-Identifier: GPL-2.0-or-later
/* Routing REST adapters. Execution remains in core and routed. */
#include <string.h>

#include "api_routing.h"
#include "api_error.h"
#include "api_json.h"
#include "api_ubus.h"

static struct json_object *routing_snapshot_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp;

    resp = app_routed_call("snapshot", NULL);
    ctx->status = app_routed_http_status(resp, ctx->status);
    return resp;
}

static struct json_object *routing_snapshot_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp;

    ctx->status = 409;
    resp = webd_error("read_only_projection",
                      "Use Policy Table and the independent routing sub-resource APIs",
                      "/api/v1/policy-engine/policy-table",
                      "webd.routing");
    return resp;
}

static struct json_object *routing_apply_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp;

    resp = app_ubus_invoke("route_reload", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *routing_static_routes_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp;

    resp = app_routed_call("static_routes_list", NULL);
    ctx->status = app_routed_http_status(resp, ctx->status);
    return resp;
}

static struct json_object *routing_static_routes_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp;

    ctx->status = 409;
    resp = webd_error("read_only_projection", "Static routes are written through Policy Table",
                      "/api/v1/policy-engine/policy-table", "webd.routing");
    return resp;
}

static int routing_static_routes_delete_path(const char *path)
{
    const char *base = "/api/v1/routing/static-routes/";
    const char *tail;

    if (!path || strncmp(path, base, strlen(base)) != 0)
        return 0;
    tail = path + strlen(base);
    return tail[0] && !strchr(tail, '/');
}

static struct json_object *routing_static_routes_delete(struct jmx_api_ctx *ctx)
{
    struct json_object *resp;

    ctx->status = 409;
    resp = webd_error("read_only_projection", "Static routes are deleted through Policy Table",
                      "/api/v1/policy-engine/policy-table", "webd.routing");
    return resp;
}

static struct json_object *routing_policy_rules_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp;

    resp = app_routed_call("policy_rules_list", NULL);
    ctx->status = app_routed_http_status(resp, ctx->status);
    return resp;
}

static struct json_object *routing_policy_rules_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp;

    ctx->status = 409;
    resp = webd_error("read_only_projection", "Policy routes are written through Policy Table",
                      "/api/v1/policy-engine/policy-table", "webd.routing");
    return resp;
}

static int routing_policy_rules_delete_path(const char *path)
{
    const char *base = "/api/v1/routing/policy-rules/";
    const char *tail;

    if (!path || strncmp(path, base, strlen(base)) != 0)
        return 0;
    tail = path + strlen(base);
    return tail[0] && !strchr(tail, '/');
}

static struct json_object *routing_policy_rules_delete(struct jmx_api_ctx *ctx)
{
    struct json_object *resp;

    ctx->status = 409;
    resp = webd_error("read_only_projection", "Policy routes are deleted through Policy Table",
                      "/api/v1/policy-engine/policy-table", "webd.routing");
    return resp;
}

static struct json_object *routing_tables_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp;

    resp = app_routed_call("tables_list", NULL);
    ctx->status = app_routed_http_status(resp, ctx->status);
    return resp;
}

static struct json_object *routing_tables_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp;

    resp = app_routed_call("table_set", ctx->body);
    ctx->status = app_routed_http_status(resp, ctx->status);
    return resp;
}

static int routing_tables_delete_path(const char *path)
{
    const char *base = "/api/v1/routing/tables/";
    const char *tail;

    if (!path || strncmp(path, base, strlen(base)) != 0)
        return 0;
    tail = path + strlen(base);
    return tail[0] && !strchr(tail, '/');
}

static struct json_object *routing_tables_delete(struct jmx_api_ctx *ctx)
{
    struct json_object *resp;

    struct json_object *params = app_json_id_param(ctx->req->path + 23);
    resp = app_routed_call("table_delete", params);
    ctx->status = app_routed_http_status(resp, ctx->status);
    json_object_put(params);
    return resp;
}

static struct json_object *routing_objects_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp;

    resp = app_routed_call("objects_list", NULL);
    ctx->status = app_routed_http_status(resp, ctx->status);
    return resp;
}

static struct json_object *routing_objects_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp;

    resp = app_routed_call("object_set", ctx->body);
    ctx->status = app_routed_http_status(resp, ctx->status);
    return resp;
}

static int routing_objects_delete_path(const char *path)
{
    const char *base = "/api/v1/routing/objects/";
    const char *tail;

    if (!path || strncmp(path, base, strlen(base)) != 0)
        return 0;
    tail = path + strlen(base);
    return tail[0] && !strchr(tail, '/');
}

static struct json_object *routing_objects_delete(struct jmx_api_ctx *ctx)
{
    struct json_object *resp;

    struct json_object *params = app_json_id_param(ctx->req->path + 24);
    resp = app_routed_call("object_delete", params);
    ctx->status = app_routed_http_status(resp, ctx->status);
    json_object_put(params);
    return resp;
}

static struct json_object *routing_cross_services_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp;

    resp = app_routed_call("cross_services_list", NULL);
    ctx->status = app_routed_http_status(resp, ctx->status);
    return resp;
}

static struct json_object *routing_cross_services_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp;

    resp = app_routed_call("cross_service_set", ctx->body);
    ctx->status = app_routed_http_status(resp, ctx->status);
    return resp;
}

static int routing_cross_services_delete_path(const char *path)
{
    const char *base = "/api/v1/routing/cross-services/";
    const char *tail;

    if (!path || strncmp(path, base, strlen(base)) != 0)
        return 0;
    tail = path + strlen(base);
    return tail[0] && !strchr(tail, '/');
}

static struct json_object *routing_cross_services_delete(struct jmx_api_ctx *ctx)
{
    struct json_object *resp;

    struct json_object *params = app_json_id_param(ctx->req->path + 31);
    resp = app_routed_call("cross_service_delete", params);
    ctx->status = app_routed_http_status(resp, ctx->status);
    json_object_put(params);
    return resp;
}

static struct json_object *routing_policy_rules_reorder_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp;

    resp = app_routed_call("policy_rules_reorder", ctx->body);
    ctx->status = app_routed_http_status(resp, ctx->status);
    return resp;
}

static struct json_object *routing_runtime_resolve_post(struct jmx_api_ctx *ctx)
{
    struct json_object *resp;

    resp = app_routed_call("runtime_resolve", ctx->body);
    ctx->status = app_routed_http_status(resp, ctx->status);
    return resp;
}

static struct json_object *routing_external_policies_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp;

    resp = app_routed_call("external_policies", NULL);
    ctx->status = app_routed_http_status(resp, ctx->status);
    return resp;
}

const struct jmx_api_route routing_api_routes[] = {
    JMX_API_ROUTE(490, "/api/v1/routing", "GET", JMX_API_EXACT, routing_snapshot_get),
    JMX_API_ROUTE(491, "/api/v1/routing", "POST,PUT", JMX_API_EXACT, routing_snapshot_post),
    JMX_API_ROUTE(492, "/api/v1/routing/apply", "POST", JMX_API_EXACT, routing_apply_post),
    JMX_API_ROUTE(498, "/api/v1/routing/static-routes", "GET", JMX_API_EXACT, routing_static_routes_get),
    JMX_API_ROUTE(499, "/api/v1/routing/static-routes", "POST,PUT", JMX_API_EXACT, routing_static_routes_post),
    JMX_API_PREDICATE_ROUTE(500, "/api/v1/routing/static-routes/", "DELETE", JMX_API_PREDICATE_ONLY, routing_static_routes_delete_path, routing_static_routes_delete),
    JMX_API_ROUTE(501, "/api/v1/routing/policy-rules", "GET", JMX_API_EXACT, routing_policy_rules_get),
    JMX_API_ROUTE(502, "/api/v1/routing/policy-rules", "POST,PUT", JMX_API_EXACT, routing_policy_rules_post),
    JMX_API_PREDICATE_ROUTE(503, "/api/v1/routing/policy-rules/", "DELETE", JMX_API_PREDICATE_ONLY, routing_policy_rules_delete_path, routing_policy_rules_delete),
    JMX_API_ROUTE(504, "/api/v1/routing/tables", "GET", JMX_API_EXACT, routing_tables_get),
    JMX_API_ROUTE(505, "/api/v1/routing/tables", "POST,PUT", JMX_API_EXACT, routing_tables_post),
    JMX_API_PREDICATE_ROUTE(506, "/api/v1/routing/tables/", "DELETE", JMX_API_PREDICATE_ONLY, routing_tables_delete_path, routing_tables_delete),
    JMX_API_ROUTE(507, "/api/v1/routing/objects", "GET", JMX_API_EXACT, routing_objects_get),
    JMX_API_ROUTE(508, "/api/v1/routing/objects", "POST,PUT", JMX_API_EXACT, routing_objects_post),
    JMX_API_PREDICATE_ROUTE(509, "/api/v1/routing/objects/", "DELETE", JMX_API_PREDICATE_ONLY, routing_objects_delete_path, routing_objects_delete),
    JMX_API_ROUTE(510, "/api/v1/routing/cross-services", "GET", JMX_API_EXACT, routing_cross_services_get),
    JMX_API_ROUTE(511, "/api/v1/routing/cross-services", "POST,PUT", JMX_API_EXACT, routing_cross_services_post),
    JMX_API_PREDICATE_ROUTE(512, "/api/v1/routing/cross-services/", "DELETE", JMX_API_PREDICATE_ONLY, routing_cross_services_delete_path, routing_cross_services_delete),
    JMX_API_ROUTE(513, "/api/v1/routing/policy-rules/reorder", "POST", JMX_API_EXACT, routing_policy_rules_reorder_post),
    JMX_API_ROUTE(514, "/api/v1/routing/runtime-resolve", "POST", JMX_API_EXACT, routing_runtime_resolve_post),
    JMX_API_ROUTE(515, "/api/v1/routing/external-policies", "GET", JMX_API_EXACT, routing_external_policies_get),
    JMX_API_ROUTE_END,
};

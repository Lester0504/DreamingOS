// SPDX-License-Identifier: GPL-2.0-or-later
/* Run the production router and routing handlers; stub only their services. */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "api_router.h"
#include "api_routing.h"
#include "api_error.h"
#include "api_json.h"
#include "api_ubus.h"

#define EMPTY_TABLE(name) \
    const struct jmx_api_route name[] = { JMX_API_ROUTE_END }
EMPTY_TABLE(policy_read_api_routes);
EMPTY_TABLE(policy_write_api_routes);
EMPTY_TABLE(policy_objects_api_routes);
EMPTY_TABLE(insights_api_routes);
EMPTY_TABLE(dashboard_api_routes);
EMPTY_TABLE(topology_api_routes);
EMPTY_TABLE(toolkit_api_routes);
EMPTY_TABLE(ble_provision_api_routes);

enum destination { MISS, ROUTED, CORE, READ_ONLY };
enum payload_kind { NO_ARGS, BODY, ID };

static enum destination called;
static enum payload_kind payload;
static const char *method_called;
static char captured_id[256];
static struct json_object *request_body;
static int status_calls, reply_status, expected_initial, id_objects;
static unsigned cases;

static void id_freed(struct json_object *obj, void *data)
{
    (void)obj;
    (void)data;
    id_objects--;
}

struct json_object *app_json_id_param(const char *id)
{
    struct json_object *params = json_object_new_object();
    json_object_object_add(params, "id", json_object_new_string(id));
    json_object_set_userdata(params, NULL, id_freed);
    id_objects++;
    return params;
}

static struct json_object *service_call(enum destination target,
                                        const char *method,
                                        struct json_object *params)
{
    struct json_object *id = NULL;
    assert(called == MISS);
    called = target;
    method_called = method;
    if (!params) {
        payload = NO_ARGS;
    } else if (params == request_body) {
        payload = BODY;
    } else {
        payload = ID;
        assert(json_object_object_get_ex(params, "id", &id));
        snprintf(captured_id, sizeof(captured_id), "%s",
                 json_object_get_string(id));
        assert(json_object_object_length(params) == 1);
    }
    return json_object_new_object();
}

struct json_object *app_routed_call(const char *method,
                                    struct json_object *params)
{
    return service_call(ROUTED, method, params);
}

struct json_object *app_ubus_invoke(const char *method,
                                   struct json_object *params)
{
    return service_call(CORE, method, params);
}

int app_routed_http_status(struct json_object *resp, int current_status)
{
    assert(resp && called == ROUTED && current_status == expected_initial);
    status_calls++;
    return reply_status;
}

int app_response_status(struct json_object *resp, int current_status)
{
    assert(resp && called == CORE && current_status == expected_initial);
    status_calls++;
    return reply_status;
}

struct json_object *webd_error(const char *code, const char *message,
                               const char *next_action, const char *source)
{
    assert(called == MISS);
    called = READ_ONLY;
    method_called = message;
    assert(!strcmp(code, "read_only_projection"));
    assert(!strcmp(next_action, "/api/v1/policy-engine/policy-table"));
    assert(!strcmp(source, "webd.routing"));
    return json_object_new_object();
}

#ifdef ROUTING_LEGACY_EQUIVALENCE
enum jmx_api_dispatch_result legacy_dispatch(struct jmx_api_ctx *ctx,
                                             int preauth,
                                             struct json_object **out);
#endif

static void check(const char *path, const char *method, int preauth,
                  enum destination expected, const char *operation,
                  enum payload_kind args, const char *id)
{
    struct http_req req = {0};
    struct json_object *sentinel = json_object_new_object();
    struct json_object *out = sentinel;
    struct jmx_api_ctx ctx = {0};
    enum jmx_api_dispatch_result result;
    int body_alive = 0;
    struct json_object *body_value = NULL;

    snprintf(req.path, sizeof(req.path), "%s", path);
    snprintf(req.method, sizeof(req.method), "%s", method);
    request_body = json_object_new_object();
    json_object_object_add(request_body, "keep", json_object_new_int(42));
    /* A spare reference lets the assertion detect a wrongly consumed body. */
    json_object_get(request_body);
    ctx.req = &req;
    ctx.body = request_body;
    ctx.status = expected_initial = 202;
    ctx.fd = 91;
    called = MISS;
    method_called = NULL;
    payload = NO_ARGS;
    captured_id[0] = '\0';
    status_calls = 0;
    assert(id_objects == 0);

#ifdef ROUTING_LEGACY_EQUIVALENCE
    result = legacy_dispatch(&ctx, preauth, &out);
#else
    result = jmx_api_router_dispatch(&ctx, preauth, &out);
#endif
    assert(called == expected);
    assert(id_objects == 0);
    assert(ctx.body == request_body);
    body_alive = json_object_object_get_ex(ctx.body, "keep", &body_value);
    assert(body_alive && json_object_get_int(body_value) == 42);
    assert(json_object_put(request_body) == 0);
    assert(json_object_put(request_body) == 1);
    if (expected == MISS) {
        assert(result == JMX_API_DISPATCH_MISS && out == sentinel);
        assert(ctx.status == expected_initial && status_calls == 0);
        assert(ctx.fd == 91);
    } else {
        assert(result == JMX_API_DISPATCH_HANDLED && out != sentinel);
#ifndef ROUTING_LEGACY_EQUIVALENCE
        assert(ctx.fd == -1);
#endif
        assert(!strcmp(method_called, operation));
        if (expected == READ_ONLY) {
            assert(ctx.status == 409 && status_calls == 0);
        } else {
            assert(ctx.status == reply_status && status_calls == 1);
            assert(payload == args);
            if (args == ID)
                assert(!strcmp(captured_id, id));
        }
        json_object_put(out);
    }
    json_object_put(sentinel);
    cases++;
}

struct route_case {
    const char *path, *methods;
    enum destination destination;
    const char *operation;
    enum payload_kind args;
};

static const struct route_case routes[] = {
    {"/api/v1/routing", "GET", ROUTED, "snapshot", NO_ARGS},
    {"/api/v1/routing", "POST,PUT", READ_ONLY,
     "Use Policy Table and the independent routing sub-resource APIs", NO_ARGS},
    {"/api/v1/routing/apply", "POST", CORE, "route_reload", BODY},
    {"/api/v1/routing/static-routes", "GET", ROUTED, "static_routes_list", NO_ARGS},
    {"/api/v1/routing/static-routes", "POST,PUT", READ_ONLY,
     "Static routes are written through Policy Table", NO_ARGS},
    {"/api/v1/routing/static-routes/id-7", "DELETE", READ_ONLY,
     "Static routes are deleted through Policy Table", NO_ARGS},
    {"/api/v1/routing/policy-rules", "GET", ROUTED, "policy_rules_list", NO_ARGS},
    {"/api/v1/routing/policy-rules", "POST,PUT", READ_ONLY,
     "Policy routes are written through Policy Table", NO_ARGS},
    {"/api/v1/routing/policy-rules/id-7", "DELETE", READ_ONLY,
     "Policy routes are deleted through Policy Table", NO_ARGS},
    {"/api/v1/routing/tables", "GET", ROUTED, "tables_list", NO_ARGS},
    {"/api/v1/routing/tables", "POST,PUT", ROUTED, "table_set", BODY},
    {"/api/v1/routing/tables/id-7", "DELETE", ROUTED, "table_delete", ID},
    {"/api/v1/routing/objects", "GET", ROUTED, "objects_list", NO_ARGS},
    {"/api/v1/routing/objects", "POST,PUT", ROUTED, "object_set", BODY},
    {"/api/v1/routing/objects/id-7", "DELETE", ROUTED, "object_delete", ID},
    {"/api/v1/routing/cross-services", "GET", ROUTED, "cross_services_list", NO_ARGS},
    {"/api/v1/routing/cross-services", "POST,PUT", ROUTED, "cross_service_set", BODY},
    {"/api/v1/routing/cross-services/id-7", "DELETE", ROUTED, "cross_service_delete", ID},
    {"/api/v1/routing/policy-rules/reorder", "POST", ROUTED, "policy_rules_reorder", BODY},
    {"/api/v1/routing/runtime-resolve", "POST", ROUTED, "runtime_resolve", BODY},
    {"/api/v1/routing/external-policies", "GET", ROUTED, "external_policies", NO_ARGS},
};

int main(void)
{
    const char *methods[] = {"GET", "POST", "PUT", "DELETE", "PATCH",
                             "HEAD", "OPTIONS", "GETTING", "get", ""};
    const char *collections[] = {"static-routes", "policy-rules", "tables",
                                 "objects", "cross-services"};
    size_t i, j;
    int failure;

    assert(sizeof(routes) / sizeof(routes[0]) == 21);
    assert(jmx_api_router_route_count() == 21);
    for (failure = 0; failure < 2; failure++) {
        reply_status = failure ? 503 : 200;
        for (i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
            for (j = 0; j < sizeof(methods) / sizeof(methods[0]); j++) {
                const struct route_case *expected = NULL;
                size_t k;
                for (k = 0; k < sizeof(routes) / sizeof(routes[0]); k++) {
                    if (strcmp(routes[k].path, routes[i].path))
                        continue;
                    if (!strcmp(routes[k].methods, methods[j]) ||
                        (!strcmp(routes[k].methods, "POST,PUT") &&
                         (!strcmp(methods[j], "POST") || !strcmp(methods[j], "PUT")))) {
                        expected = &routes[k];
                        break;
                    }
                }
                /* "reorder" is also a valid single ID for the DELETE branch. */
                if (!strcmp(routes[i].path, "/api/v1/routing/policy-rules/reorder")
                    && !strcmp(methods[j], "DELETE"))
                    expected = &routes[8];
                check(routes[i].path, methods[j], 0,
                      expected ? expected->destination : MISS,
                      expected ? expected->operation : NULL,
                      expected ? expected->args : NO_ARGS, "id-7");
                check(routes[i].path, methods[j], 1, MISS, NULL, NO_ARGS, NULL);
            }
        }
    }
    for (i = 0; i < sizeof(collections) / sizeof(collections[0]); i++) {
        const char *tails[] = {"", "/", "/id-7/extra", "//", "/id-7/"};
        for (j = 0; j < sizeof(tails) / sizeof(tails[0]); j++) {
            char path[256];
            snprintf(path, sizeof(path), "/api/v1/routing/%s%s",
                     collections[i], tails[j]);
            check(path, "DELETE", 0, MISS, NULL, NO_ARGS, NULL);
        }
    }
    check("/api/v1/routing-extra", "GET", 0, MISS, NULL, NO_ARGS, NULL);
    check("/api/v1/routing/", "GET", 0, MISS, NULL, NO_ARGS, NULL);
    check("/api/v1/routing/apply/extra", "POST", 0, MISS, NULL, NO_ARGS, NULL);
    printf("ok: routing 21 branches, %u dispatch cases\n", cases);
    return 0;
}

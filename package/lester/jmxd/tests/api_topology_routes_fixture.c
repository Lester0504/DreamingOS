// SPDX-License-Identifier: GPL-2.0-or-later
/* Runtime fixture for the production Phase 3B Topology route handlers. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "api_topology.h"

#define INFRA_CACHE "/tmp/dreamingwrt/topology-infrastructure.json"
#define INFRA_LOCK "/tmp/dreamingwrt/topology-infrastructure.lock"

static int failures;
static const char *ubus_method;
static int ubus_timeout;
static struct json_object *ubus_params;
static int ubus_available = 1;

static void check(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        failures++;
    }
}

const char *app_nc_json_str(struct json_object *o, const char *key,
                            const char *def)
{
    struct json_object *v = NULL;

    if (!o || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    return json_object_get_string(v);
}

int app_nc_json_bool(struct json_object *o, const char *key, int def)
{
    struct json_object *v = NULL;

    if (!o || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    return json_object_get_boolean(v);
}

struct json_object *webd_meta(const char *source)
{
    struct json_object *meta = json_object_new_object();

    json_object_object_add(meta, "source",
                           json_object_new_string(source ? source : ""));
    return meta;
}

struct json_object *webd_envelope(struct json_object *data, const char *source)
{
    struct json_object *root = json_object_new_object();

    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "data", data ? data : json_object_new_object());
    json_object_object_add(root, "meta", webd_meta(source));
    return root;
}

struct json_object *webd_error(const char *code, const char *message,
                               const char *missing, const char *source)
{
    struct json_object *root = json_object_new_object();
    struct json_object *error = json_object_new_object();

    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(error, "code",
                           json_object_new_string(code ? code : ""));
    json_object_object_add(error, "message",
                           json_object_new_string(message ? message : ""));
    json_object_object_add(error, "missing",
                           json_object_new_string(missing ? missing : ""));
    json_object_object_add(error, "source",
                           json_object_new_string(source ? source : ""));
    json_object_object_add(root, "error", error);
    return root;
}

struct json_object *webd_json_clone(struct json_object *src)
{
    return src ? json_tokener_parse(json_object_to_json_string_ext(
                     src, JSON_C_TO_STRING_PLAIN)) : NULL;
}

void webd_mark_cached_response_stale(struct json_object *resp, int age_ms,
                                     const char *source_error)
{
    struct json_object *meta = NULL;

    if (!resp)
        return;
    if (!json_object_object_get_ex(resp, "meta", &meta) || !meta) {
        meta = json_object_new_object();
        json_object_object_add(resp, "meta", meta);
    }
    json_object_object_add(meta, "stale", json_object_new_boolean(1));
    json_object_object_add(meta, "cache_age_ms", json_object_new_int(age_ms));
    json_object_object_add(meta, "source_error",
                           json_object_new_string(source_error ? source_error : ""));
}

struct json_object *jmx_cache_get_allow_stale(const char *key,
                                              int max_age_seconds,
                                              int *age_ms,
                                              int *is_stale)
{
    (void)key;
    (void)max_age_seconds;
    if (age_ms)
        *age_ms = 0;
    if (is_stale)
        *is_stale = 0;
    return NULL;
}

void jmx_cache_put_with_stale(const char *key, struct json_object *val,
                              int ttl_seconds, int stale_seconds)
{
    (void)key;
    (void)val;
    (void)ttl_seconds;
    (void)stale_seconds;
}

void jmx_cache_invalidate(const char *key)
{
    (void)key;
}

int64_t webd_now_ms(void)
{
    return 1000000;
}

int64_t webd_ws_file_mtime_ms(const struct stat *st)
{
    (void)st;
    return 0;
}

int webd_write_all(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    size_t off = 0;

    while (off < len) {
        ssize_t wrote = write(fd, p + off, len - off);
        if (wrote <= 0)
            return -1;
        off += (size_t)wrote;
    }
    return 0;
}

struct json_object *app_ubus_invoke_timeout(const char *method,
                                            struct json_object *params,
                                            int timeout_ms)
{
    struct json_object *data;

    ubus_method = method;
    ubus_timeout = timeout_ms;
    if (ubus_params)
        json_object_put(ubus_params);
    ubus_params = params ? json_object_get(params) : NULL;
    if (!ubus_available)
        return NULL;
    data = json_object_new_object();
    if (!strcmp(method, "topology_infrastructure")) {
        struct json_object *infra = json_object_new_object();
        json_object_object_add(infra, "fixture", json_object_new_boolean(1));
        json_object_object_add(data, "infrastructure", infra);
    } else {
        json_object_object_add(data, "fixture", json_object_new_boolean(1));
    }
    return data;
}

static const char *error_code(struct json_object *resp)
{
    struct json_object *error = NULL;
    struct json_object *code = NULL;

    if (!resp || !json_object_object_get_ex(resp, "error", &error) || !error ||
        !json_object_object_get_ex(error, "code", &code) || !code)
        return "";
    return json_object_get_string(code);
}

static const char *response_source(struct json_object *resp)
{
    struct json_object *meta = NULL;
    struct json_object *source = NULL;

    if (!resp || !json_object_object_get_ex(resp, "meta", &meta) || !meta ||
        !json_object_object_get_ex(meta, "source", &source) || !source)
        return "";
    return json_object_get_string(source);
}

static struct json_object *call_route(unsigned index, const char *path,
                                      const char *query, int *status)
{
    struct http_req req;
    struct jmx_api_ctx ctx;

    memset(&req, 0, sizeof(req));
    memset(&ctx, 0, sizeof(ctx));
    snprintf(req.method, sizeof(req.method), "%s", "GET");
    snprintf(req.path, sizeof(req.path), "%s", path);
    snprintf(req.query, sizeof(req.query), "%s", query ? query : "");
    ctx.req = &req;
    ctx.status = 200;
    ubus_method = NULL;
    ubus_timeout = 0;
    if (ubus_params)
        json_object_put(ubus_params);
    ubus_params = NULL;
    {
        struct json_object *resp = topology_api_routes[index].handler(&ctx);
        if (status)
            *status = ctx.status;
        return resp;
    }
}

static void check_predicates(void)
{
    check(topology_api_routes[0].predicate &&
          topology_api_routes[0].predicate("/v2/api/site/default/topology"),
          "Topology predicate must accept a non-empty UniFi site alias");
    check(!topology_api_routes[0].predicate("/v2/api/site//topology"),
          "Topology predicate must reject an empty UniFi site");
    check(!topology_api_routes[0].predicate(
              "/v2/api/site/default/topology/extra"),
          "Topology predicate must reject a trailing subresource");
    check(topology_api_routes[2].predicate &&
          topology_api_routes[2].predicate(
              "/api/v1/topology/infrastructure/history/timeline"),
          "History predicate must accept the local timeline route");
    check(topology_api_routes[2].predicate(
              "/v2/api/site/default/infrastructure/history/at/not-a-number"),
          "History predicate must route an invalid timestamp to its 400 handler");
    check(!topology_api_routes[2].predicate(
              "/v2/api/site//infrastructure/history/timeline"),
          "History predicate must reject an empty UniFi site");
    check(topology_api_routes[3].predicate &&
          topology_api_routes[3].predicate(
              "/v2/api/site/default/infrastructure"),
          "Infrastructure predicate must accept its UniFi alias");
    check(topology_api_routes[4].predicate &&
          topology_api_routes[4].predicate(
              "/v2/api/site/default/digital-twin/layout"),
          "Digital-twin predicate must accept its exact UniFi alias");
}

static void check_overview_and_flow(void)
{
    struct json_object *resp;
    int status;

    resp = call_route(0, "/api/v1/topology", "", &status);
    check(resp && status == 200, "Topology overview must return a response");
    check(ubus_method && !strcmp(ubus_method, "topology_unifi") &&
          ubus_timeout == 3000 && ubus_params == NULL,
          "Topology overview changed its ubus method, timeout, or parameters");
    check(!strcmp(response_source(resp), "jmxd.topology_unifi"),
          "Topology overview changed its envelope source");
    json_object_put(resp);

    resp = call_route(1, "/api/v1/topology/flow", "", &status);
    check(resp && status == 200, "Topology flow must return a response");
    check(ubus_method && !strcmp(ubus_method, "topology_flow") &&
          ubus_timeout == 3000 && ubus_params == NULL,
          "Topology flow changed its ubus method, timeout, or parameters");
    check(!strcmp(response_source(resp), "jmxd.topology_flow"),
          "Topology flow changed its envelope source");
    json_object_put(resp);
}

static void check_history(void)
{
    struct json_object *resp;
    struct json_object *value = NULL;
    int status;

    resp = call_route(2,
        "/api/v1/topology/infrastructure/history/timeline",
        "start=1000&end=2000", &status);
    check(resp && status == 200, "Timeline history must return HTTP 200");
    check(ubus_method &&
          !strcmp(ubus_method, "topology_infrastructure_history_timeline") &&
          ubus_timeout == 3000,
          "Timeline history changed its ubus method or timeout");
    check(ubus_params && json_object_object_get_ex(ubus_params, "start", &value) &&
          json_object_get_int64(value) == 1000,
          "Timeline history did not forward start");
    check(ubus_params && json_object_object_get_ex(ubus_params, "end", &value) &&
          json_object_get_int64(value) == 2000,
          "Timeline history did not forward end");
    json_object_put(resp);

    resp = call_route(2,
        "/v2/api/site/default/infrastructure/history/at/12345", "", &status);
    check(resp && status == 200 && ubus_method &&
          !strcmp(ubus_method, "topology_infrastructure_history_at"),
          "Historical at route changed its ubus method or status");
    check(ubus_params && json_object_object_get_ex(ubus_params, "timestamp", &value) &&
          json_object_get_int64(value) == 12345,
          "Historical at route did not forward its timestamp");
    json_object_put(resp);

    resp = call_route(2,
        "/api/v1/topology/infrastructure/history/at/not-a-number", "", &status);
    check(resp && status == 400 && !strcmp(error_code(resp), "invalid_timestamp"),
          "Invalid historical timestamp must remain HTTP 400");
    check(ubus_method == NULL,
          "Invalid historical timestamp must fail before a ubus call");
    json_object_put(resp);

    resp = call_route(2,
        "/api/v1/topology/infrastructure/history/timestamps",
        "start=2000&end=1000", &status);
    check(resp && status == 400 && !strcmp(error_code(resp), "invalid_time_range"),
          "Reversed history range must remain HTTP 400");
    check(ubus_method == NULL,
          "Invalid history range must fail before a ubus call");
    json_object_put(resp);
}

static void check_infrastructure_and_layout(void)
{
    struct json_object *resp;
    struct json_object *data = NULL;
    struct json_object *value = NULL;
    int status;

    unlink(INFRA_CACHE);
    unlink(INFRA_LOCK);
    resp = call_route(3, "/api/v1/topology/infrastructure", "", &status);
    check(resp && status == 200 && ubus_method &&
          !strcmp(ubus_method, "topology_infrastructure") &&
          ubus_timeout == 3000,
          "Infrastructure route changed its ubus method, timeout, or status");
    check(resp && json_object_object_get_ex(resp, "data", &data) && data &&
          json_object_object_get_ex(data, "infrastructure", &value) && value,
          "Infrastructure route lost its required envelope shape");
    json_object_put(resp);
    webd_topology_infrastructure_cache_invalidate();
    check(access(INFRA_CACHE, F_OK) != 0,
          "Exported cache invalidation must remove the shared snapshot");

    resp = call_route(4, "/v2/api/site/default/digital-twin/layout", "", &status);
    check(resp && status == 200 &&
          !strcmp(response_source(resp), "webd.unifi_digital_twin_layout_empty"),
          "Digital-twin empty contract changed its source or status");
    check(resp && json_object_object_get_ex(resp, "data", &data) && data &&
          json_object_object_get_ex(data, "available", &value) &&
          !json_object_get_boolean(value),
          "Digital-twin empty contract must remain explicitly unavailable");
    json_object_put(resp);
    unlink(INFRA_CACHE);
    unlink(INFRA_LOCK);
}

int main(void)
{
    unsigned count = 0;

    while (topology_api_routes[count].path)
        count++;
    check(count == 5, "Topology production table must contain five routes");
    check_predicates();
    check_overview_and_flow();
    check_history();
    check_infrastructure_and_layout();
    if (ubus_params)
        json_object_put(ubus_params);

    if (failures) {
        fprintf(stderr, "%d Topology fixture check(s) failed\n", failures);
        return 1;
    }
    printf("ok: five production Topology handlers and predicates\n");
    return 0;
}

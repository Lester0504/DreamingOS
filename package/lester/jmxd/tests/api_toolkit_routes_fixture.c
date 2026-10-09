// SPDX-License-Identifier: GPL-2.0-or-later
/* Runtime fixture for the production Phase 3A route handlers. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api_toolkit.h"

static int failures;
static const char *ubus_object;
static const char *ubus_method;
static int ubus_timeout;
static struct json_object *ubus_body;

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

struct json_object *webd_error(const char *code, const char *message,
                               const char *missing, const char *source)
{
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "ok", json_object_new_boolean(0));
    json_object_object_add(o, "error", json_object_new_string(code ? code : ""));
    json_object_object_add(o, "message", json_object_new_string(message ? message : ""));
    json_object_object_add(o, "missing", json_object_new_string(missing ? missing : ""));
    json_object_object_add(o, "source", json_object_new_string(source ? source : ""));
    return o;
}

struct json_object *app_ubus_route_or_error(const char *object,
                                             const char *method,
                                             struct json_object *params,
                                             int timeout_ms,
                                             int *http_status)
{
    ubus_object = object;
    ubus_method = method;
    ubus_timeout = timeout_ms;
    ubus_body = params;
    if (http_status)
        *http_status = 299;
    return json_object_new_object();
}

static void check_toolkit_route(unsigned index, const char *command,
                                const char *query)
{
    struct http_req req;
    struct jmx_api_ctx ctx;
    struct json_object *body = json_object_new_object();
    struct json_object *resp;
    struct json_object *value = NULL;
    struct json_object *payload = NULL;

    memset(&req, 0, sizeof(req));
    memset(&ctx, 0, sizeof(ctx));
    snprintf(req.query, sizeof(req.query), "%s", query ? query : "");
    json_object_object_add(body, "fixture", json_object_new_string("body"));
    ctx.req = &req;
    ctx.body = body;
    ctx.status = 500;
    ctx.device_id = "fixture-actor";

    resp = toolkit_api_routes[index].handler(&ctx);
    check(resp != NULL, "Toolkit handler must return the fake binary response");
    check(ctx.status == 200, "Toolkit ok response must map to HTTP 200");
    check(resp && json_object_object_get_ex(resp, "command", &value) &&
          !strcmp(json_object_get_string(value), command),
          "Toolkit handler selected the wrong one-shot command");
    check(resp && json_object_object_get_ex(resp, "payload", &payload) && payload,
          "Toolkit fake binary did not receive a JSON payload");
    check(payload && json_object_object_get_ex(payload, "actor", &value) &&
          !strcmp(json_object_get_string(value), "fixture-actor"),
          "Toolkit bridge did not replace actor with the authenticated device id");
    if (query) {
        check(payload && json_object_object_get_ex(payload, "id", &value) &&
              !strcmp(json_object_get_string(value), "job+1"),
              "throughput status did not URL-decode the id query");
    } else {
        check(payload && json_object_object_get_ex(payload, "fixture", &value) &&
              !strcmp(json_object_get_string(value), "body"),
              "Toolkit route did not forward the request body");
    }
    if (resp)
        json_object_put(resp);
    json_object_put(body);
}

static void check_diagnostics_route(unsigned index, const char *method,
                                    int timeout_ms)
{
    struct http_req req;
    struct jmx_api_ctx ctx;
    struct json_object *body = json_object_new_object();
    struct json_object *resp;

    memset(&req, 0, sizeof(req));
    memset(&ctx, 0, sizeof(ctx));
    ctx.req = &req;
    ctx.body = body;
    ctx.status = 500;
    ubus_object = NULL;
    ubus_method = NULL;
    ubus_timeout = 0;
    ubus_body = NULL;

    resp = toolkit_api_routes[index].handler(&ctx);
    check(resp != NULL, "Diagnostics handler must return the ubus response");
    check(ctx.status == 299, "Diagnostics handler must preserve ubus HTTP status");
    check(ubus_object && !strcmp(ubus_object, "dreamingwrt"),
          "Diagnostics handler used the wrong ubus object");
    check(ubus_method && !strcmp(ubus_method, method),
          "Diagnostics handler used the wrong ubus method");
    check(ubus_timeout == timeout_ms,
          "Diagnostics handler changed its route-specific timeout");
    check(ubus_body == body, "Diagnostics handler did not forward the request body");
    if (resp)
        json_object_put(resp);
    json_object_put(body);
}

int main(void)
{
    static const char *const commands[] = {
        "status", "router-check", "port-mirror-list", "port-mirror-set",
        "port-mirror-delete", "ddns-list", "ddns-set", "ddns-update",
        "wake-on-lan", "throughput-start", "throughput-status",
        "throughput-stop",
    };
    unsigned i;

    for (i = 0; i < 12; i++)
        check_toolkit_route(i, commands[i], i == 10 ? "id=job%2B1" : NULL);
    check_diagnostics_route(12, "ping", 4000);
    check_diagnostics_route(13, "traceroute", 30000);
    check_diagnostics_route(14, "nslookup", 10000);
    /* 613: speedtest rewired from the ubus stub to the toolkit async job. */
    check_toolkit_route(15, "speedtest-start", NULL);
    /* 960-978,981: RoceOS-parity network diagnostics via the toolkit one-shot. */
    check_toolkit_route(16, "port-scan", NULL);
    check_toolkit_route(17, "port-check", NULL);
    check_toolkit_route(18, "tcp-udp-test", NULL);
    check_toolkit_route(19, "ssl-check", NULL);
    check_toolkit_route(20, "http-request", NULL);
    check_toolkit_route(21, "headers", NULL);
    check_toolkit_route(22, "website-check", NULL);
    check_toolkit_route(23, "local-ports", NULL);
    check_toolkit_route(24, "local-info", NULL);
    check_toolkit_route(25, "arp-scan", NULL);
    check_toolkit_route(26, "mtu-detect", NULL);
    check_toolkit_route(27, "latency-monitor", NULL);
    check_toolkit_route(28, "whois", NULL);
    check_toolkit_route(29, "dns-query", NULL);
    check_toolkit_route(30, "public-ip", NULL);
    check_toolkit_route(31, "ip-geo", NULL);
    check_toolkit_route(32, "mac-lookup", NULL);
    check_toolkit_route(33, "speedtest-status", "id=job%2B1");
    check_toolkit_route(34, "speedtest-stop", NULL);
    check_toolkit_route(35, "mdns", NULL);

    if (failures)
        return 1;
    puts("ok: 36 production Toolkit/Diagnostics handlers preserve commands, actor, query, ubus methods and timeouts");
    return 0;
}

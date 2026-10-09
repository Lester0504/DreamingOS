// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
#include "api_ad_analyzer.h"
#include "../ad_analyzer.h"
#include "api_error.h"
#include "api_ubus.h"
#include "../../jmx_dataset_path.h"
#include "api_request.h"
#include <libubox/uloop.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static struct uloop_timeout timer;
static int recovering = 1;
static struct json_object *provider(void *unused, const char *operation, struct json_object *request) {
    (void)unused;
    struct json_object *b=request?json_tokener_parse(json_object_to_json_string(request)):json_object_new_object();
    json_object_object_add(b,"operation",json_object_new_string(operation));
    struct json_object *payload=json_object_new_object();json_object_object_add(payload,"payload",b);
    struct json_object *r=app_ubus_invoke_object_timeout("dreamingwrt.aegis","ad_dns",payload,3000);
    json_object_put(payload);return r;
}
static struct ada_environment environment(void) {
    return (struct ada_environment){"/etc/dreamingwrt/ad_analyzer.db",
                                    "/var/run/dreamingwrt/ad-dns/queries.log", "/tmp/dhcp.leases",
                                    time(NULL),provider,NULL,"/proc/net/nf_conntrack",jmx_dataset_child("audit","audit.db")};
}
static void tick(struct uloop_timeout *t) {
    struct ada_environment e = environment();
    if (ada_tick(&e, recovering))
        fprintf(stderr, "[ad-analyzer] snapshot update deferred\n");
    else
        recovering = 0;
    uloop_timeout_set(t, 5000);
}
void ad_analyzer_start(void) {
    struct ada_environment e = environment();
    recovering = ada_tick(&e, 1) != 0;
    timer.cb = tick;
    uloop_timeout_set(&timer, 5000);
}
void ad_analyzer_stop(void) { uloop_timeout_cancel(&timer); }
static struct json_object *dispatch(struct jmx_api_ctx *ctx) {
    if (strcmp(ctx->req->method, "GET") && ctx->req->auth_via_cookie &&
        strcmp(ctx->req->sec_fetch_site, "same-origin")) {
        ctx->status = 403;
        return webd_error("same_origin_required", "请从设备页面提交操作", "", "webd.ad_analyzer");
    }
    struct ada_environment e = environment();
    struct json_object *query = json_object_new_object();
    char value[256];
    const char *keys[] = {"q", "level", "blocked", "connection", "parent", "device_ip", "mode", "offset", "limit", NULL};
    for (int i = 0; keys[i]; i++)
        if (webd_query_get(ctx->req->query, keys[i], value, sizeof(value)))
            json_object_object_add(query, keys[i], json_object_new_string(value));
    struct json_object *r =
        ada_handle(&e, ctx->device_id, ctx->role == JMX_ROLE_ADMIN || ctx->role == JMX_ROLE_OWNER,
                   ctx->req->method, ctx->req->path + strlen("/api/v1/diagnostics/ad-analyzer/"),
                   query, ctx->body, &ctx->status);
    json_object_put(query);
    return webd_envelope(r, "webd.ad_analyzer");
}
const struct jmx_api_route ad_analyzer_api_routes[] = {
    JMX_API_ROUTE(1126, "/api/v1/diagnostics/ad-analyzer/", "GET,POST,PUT,PATCH,DELETE",
                  JMX_API_PREFIX, dispatch),
    JMX_API_ROUTE_END};

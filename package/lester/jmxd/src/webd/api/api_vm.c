// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * webd gateway for the VM control plane (the /api/v1/vm/ subtree).
 *
 * This module links NO libvirt. It is a thin, always-present forwarder to the
 * `dreamingos.vm` ubus object that the optional dreamingos-vm daemon registers.
 * The daemon holds the persistent truth and speaks the frozen vm.v1 contract;
 * this file only marshals HTTP <-> ubus and adds the response `meta`.
 *
 * Transport: the daemon's methods take one string field `req` (a JSON document)
 * and reply { http_status:int, body:"<json string>" }. body is the vm.v1 body
 * ({ok,data|error}) serialized opaquely, so JSON null / int64 / nested objects
 * survive the ubus hop. We parse it back, splice in meta = webd_meta("webd.vm")
 * WITHOUT re-enveloping (the daemon already produced the {ok,...} shell), and
 * set ctx->status from http_status.
 *
 * Absent daemon (lean build or stopped service): §3 requires GET /status and
 * GET /capabilities to answer 200 with installed:false explanatory data, which
 * we build locally with webd_envelope(); every other route is 503.
 *
 * Only the backed operations the daemon actually backs are routed. Contracted-but-
 * unimplemented paths (PATCH, snapshots, clone, metrics, console-ticket,
 * volumes, images, imports, exports, hardware, devices, settings,
 * service) are intentionally answered not_found in this build rather than faked.
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>

#include "api_vm.h"
#include "../jmx_app_api.h"
#include "api_error.h"
#include "api_json.h"
#include "api_ubus.h"
#include "webd_http_req.h"

#define VM_UBUS_OBJECT   "dreamingos.vm"
#define VM_SOURCE_NAME   "webd.vm"
/* Submit/read calls are quick; a synchronous lifecycle action or a libvirt list
 * on the daemon's single thread can take a beat. One generous ceiling. */
#define VM_UBUS_TIMEOUT_MS 15000

#define VM_PREFIX      "/api/v1/vm"
#define VM_INSTANCES   "/api/v1/vm/instances"
#define VM_TASKS       "/api/v1/vm/tasks"
static int vm_hex(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Percent-decode src[0..srclen) into the bounded, NUL-terminated dst; '+' maps
 * to space. A stray '%' with no two hex digits behind it is passed through. */
static void vm_urldecode(char *dst, size_t dstsz, const char *src, size_t srclen)
{
    size_t di = 0, i;

    for (i = 0; i < srclen && di + 1 < dstsz; i++) {
        int c = (unsigned char)src[i];

        if (c == '+') {
            dst[di++] = ' ';
        } else if (c == '%' && i + 2 < srclen) {
            int hi = vm_hex((unsigned char)src[i + 1]);
            int lo = vm_hex((unsigned char)src[i + 2]);

            if (hi >= 0 && lo >= 0) { dst[di++] = (char)((hi << 4) | lo); i += 2; }
            else dst[di++] = (char)c;
        } else {
            dst[di++] = (char)c;
        }
    }
    dst[di] = '\0';
}

/* The four §10 list params, decoded from the raw query string. page/page_size
 * are ints; q/state are strings; anything else is ignored. Never NULL. */
static struct json_object *vm_query_params(const char *query)
{
    struct json_object *p = json_object_new_object();
    char buf[512], *save = NULL, *tok;

    if (!query || !*query)
        return p;
    snprintf(buf, sizeof buf, "%s", query);
    for (tok = strtok_r(buf, "&", &save); tok; tok = strtok_r(NULL, "&", &save)) {
        char *eq = strchr(tok, '=');
        char key[64], val[256];

        if (!eq)
            continue;
        *eq = '\0';
        vm_urldecode(key, sizeof key, tok, strlen(tok));
        vm_urldecode(val, sizeof val, eq + 1, strlen(eq + 1));
        if (!strcmp(key, "page") || !strcmp(key, "page_size"))
            json_object_object_add(p, key, json_object_new_int(atoi(val)));
        else if (!strcmp(key, "q") || !strcmp(key, "state"))
            json_object_object_add(p, key, json_object_new_string(val));
    }
    return p;
}
/* Shape a 503 the way the daemon would, for paths that cannot degrade to a 200
 * explanatory body. */
static struct json_object *vm_gw_unavailable(struct jmx_api_ctx *ctx)
{
    ctx->status = 503;
    return webd_error("service_unavailable",
                      "virtualization service is unavailable", "", VM_SOURCE_NAME);
}

/* A path under our prefix this build does not back. not_found keeps the vm.v1
 * error shape rather than leaking webd's generic 404. */
static struct json_object *vm_gw_not_found(struct jmx_api_ctx *ctx)
{
    ctx->status = 404;
    return webd_error("not_found", "route not available in this build", "",
                      VM_SOURCE_NAME);
}

/* Forward one call to the daemon and adapt the reply. Takes ownership of params
 * (may be NULL). Any transport failure reads as unavailable (503). On success
 * the daemon's {ok,data|error} body is returned verbatim with meta spliced in
 * and ctx->status set from the daemon's http_status. */
static struct json_object *vm_gw_call_raw(struct jmx_api_ctx *ctx, const char *method,
                                      struct json_object *params)
{
    struct json_object *call = json_object_new_object();
    struct json_object *reply, *v, *vmbody;
    const char *body_str = NULL;
    int http = 502;

    json_object_object_add(call, "req",
        json_object_new_string(params ? json_object_to_json_string(params) : "{}"));
    json_object_put(params);

    reply = app_ubus_invoke_object_timeout(VM_UBUS_OBJECT, method, call,
                                           VM_UBUS_TIMEOUT_MS);
    json_object_put(call);
    if (!reply)
        return vm_gw_unavailable(ctx);

    if (json_object_object_get_ex(reply, "http_status", &v))
        http = json_object_get_int(v);
    if (!json_object_object_get_ex(reply, "body", &v) ||
        !(body_str = json_object_get_string(v)) || !*body_str) {
        json_object_put(reply);
        return vm_gw_unavailable(ctx);
    }
    vmbody = json_tokener_parse(body_str);
    json_object_put(reply);
    if (!vmbody || !json_object_is_type(vmbody, json_type_object)) {
        if (vmbody)
            json_object_put(vmbody);
        return vm_gw_unavailable(ctx);
    }
    /* The daemon body carries {ok,data|error} but no meta; add ours, do NOT
     * re-envelope (that would nest the body inside a second data object). */
    json_object_object_add(vmbody, "meta", webd_meta(VM_SOURCE_NAME));
    ctx->status = http;
    return vmbody;
}

/* Read methods and validation do not create operation audit records. */
static struct json_object *vm_gw_call(struct jmx_api_ctx *ctx, const char *method,
                                     struct json_object *params)
{
    int write = !strcmp(method, "instance_create") || !strcmp(method, "instance_delete") ||
                !strcmp(method, "instance_action") || !strcmp(method, "task_cancel");
    char target[256], action[96];
    snprintf(target, sizeof(target), "%s", app_nc_json_str(params, "id",
             app_nc_json_str(params, "task_id", app_nc_json_str(params, "name", ""))));
    snprintf(action, sizeof(action), "vm.%s", method);
    if (write && params) {
        struct json_object *v = NULL;
        if (!strcmp(method, "instance_create") && !json_object_object_get_ex(params, "config", &v)) {
            struct json_object *wrapped = json_object_new_object();
            if (json_object_object_get_ex(params, "request_id", &v)) json_object_object_add(wrapped, "request_id", json_object_get(v));
            json_object_object_add(wrapped, "config", params); params = wrapped;
        }
        struct json_object *context = json_object_new_object();
        json_object_object_add(context, "actor", json_object_new_string(ctx->device_id));
        json_object_object_add(context, "source_ip", json_object_new_string(ctx->req->client_ip));
        json_object_object_add(params, "_log_context", context);
    }
    struct json_object *reply = vm_gw_call_raw(ctx, method, params);
    if (write)
        jmx_app_audit_log_response(ctx->device_id, ctx->device_id, action, "medium",
                                  target, ctx->req->client_ip, reply, ctx->status);
    return reply;
}

/* Split a "/{id}[/rest]" tail: copy {id} into id[], point *rest at the "/rest"
 * remainder (or ""). Returns -1 when there is no non-empty id segment. */
static int vm_parse_id(const char *tail, char *id, size_t idsz, const char **rest)
{
    size_t n = 0;

    if (*tail != '/')
        return -1;
    tail++;
    while (tail[n] && tail[n] != '/')
        n++;
    if (n == 0 || n + 1 > idsz)
        return -1;
    memcpy(id, tail, n);
    id[n] = '\0';
    *rest = tail + n;
    return 0;
}
/* §3 status when the daemon's ubus object is absent (package not installed or
 * service down): 200 with an explanatory data object, never a 404/503. */
static struct json_object *vm_gw_absent_status(struct jmx_api_ctx *ctx)
{
    struct json_object *data = json_object_new_object();
    struct json_object *dep = json_object_new_object();

    json_object_object_add(data, "schema", json_object_new_string("vm.v1"));
    json_object_object_add(data, "installed", json_object_new_boolean(0));
    json_object_object_add(data, "enabled", json_object_new_boolean(0));
    json_object_object_add(data, "service_state",
                           json_object_new_string("not_installed"));
    json_object_object_add(dep, "libvirt", json_object_new_string("unknown"));
    json_object_object_add(dep, "qemu", json_object_new_string("unknown"));
    json_object_object_add(dep, "kvm", json_object_new_string("unknown"));
    json_object_object_add(data, "dependency_state", dep);
    json_object_object_add(data, "reason",
                           json_object_new_string("package_not_installed"));
    ctx->status = 200;
    return webd_envelope(data, VM_SOURCE_NAME);
}

/* §5 capabilities when absent: 200, installed:false, creation unavailable. */
static struct json_object *vm_gw_absent_capabilities(struct jmx_api_ctx *ctx)
{
    struct json_object *data = json_object_new_object();
    struct json_object *caps = json_object_new_object();

    json_object_object_add(data, "schema", json_object_new_string("vm.v1"));
    json_object_object_add(data, "installed", json_object_new_boolean(0));
    json_object_object_add(data, "enabled", json_object_new_boolean(0));
    json_object_object_add(data, "service_state",
                           json_object_new_string("not_installed"));
    json_object_object_add(caps, "create", json_object_new_boolean(0));
    json_object_object_add(data, "capabilities", caps);
    json_object_object_add(data, "reason",
                           json_object_new_string("package_not_installed"));
    ctx->status = 200;
    return webd_envelope(data, VM_SOURCE_NAME);
}
static struct json_object *vm_gw_status(struct jmx_api_ctx *ctx)
{
    if (!app_ubus_object_available(VM_UBUS_OBJECT))
        return vm_gw_absent_status(ctx);
    return vm_gw_call(ctx, "status", NULL);
}

static struct json_object *vm_gw_capabilities(struct jmx_api_ctx *ctx)
{
    if (!app_ubus_object_available(VM_UBUS_OBJECT))
        return vm_gw_absent_capabilities(ctx);
    return vm_gw_call(ctx, "capabilities", NULL);
}

static struct json_object *vm_gw_overview(struct jmx_api_ctx *ctx)
{
    /* Not an always-answer route: absent or degraded is 503, per §3/§4. */
    return vm_gw_call(ctx, "overview", NULL);
}
static struct json_object *vm_gw_instances(struct jmx_api_ctx *ctx)
{
    const char *tail = ctx->req->path + strlen(VM_INSTANCES);
    const char *m = ctx->req->method;
    const char *rest = NULL;
    char id[128];
    struct json_object *p;

    /* Collection root: GET list (query params) or POST create (forward body). */
    if (!*tail || !strcmp(tail, "/")) {
        if (!strcmp(m, "GET"))
            return vm_gw_call(ctx, "instance_list", vm_query_params(ctx->req->query));
        if (!strcmp(m, "POST")) {
            p = ctx->body ? webd_json_clone(ctx->body) : json_object_new_object();
            return vm_gw_call(ctx, "instance_create", p);
        }
        return vm_gw_not_found(ctx);
    }

    /* Synchronous pre-check; the daemon unwraps a {config:{...}} wrapper or
     * accepts a bare config, so the body is forwarded verbatim. */
    if (!strcmp(tail, "/validate") && !strcmp(m, "POST")) {
        p = ctx->body ? webd_json_clone(ctx->body) : json_object_new_object();
        return vm_gw_call(ctx, "instance_validate", p);
    }

    if (vm_parse_id(tail, id, sizeof id, &rest) != 0)
        return vm_gw_not_found(ctx);

    if (!*rest && !strcmp(m, "GET")) {
        p = json_object_new_object();
        json_object_object_add(p, "id", json_object_new_string(id));
        return vm_gw_call(ctx, "instance_get", p);
    }
    if (!strcmp(rest, "/actions") && !strcmp(m, "POST")) {
        p = ctx->body ? webd_json_clone(ctx->body) : json_object_new_object();
        json_object_object_add(p, "id", json_object_new_string(id));
        return vm_gw_call(ctx, "instance_action", p);
    }
    if (!strcmp(rest, "/delete") && !strcmp(m, "POST")) {
        p = ctx->body ? webd_json_clone(ctx->body) : json_object_new_object();
        json_object_object_add(p, "id", json_object_new_string(id));
        return vm_gw_call(ctx, "instance_delete", p);
    }
    /* PATCH /{id}, /{id}/snapshots, /clone, /metrics, /console-ticket,
     * /devices/... — contracted but not backed in this build. */
    return vm_gw_not_found(ctx);
}
static struct json_object *vm_gw_tasks(struct jmx_api_ctx *ctx)
{
    const char *tail = ctx->req->path + strlen(VM_TASKS);
    const char *m = ctx->req->method;
    const char *rest = NULL;
    char id[128];
    struct json_object *p;

    if (!*tail || !strcmp(tail, "/")) {
        if (!strcmp(m, "GET"))
            return vm_gw_call(ctx, "task_list", NULL);
        return vm_gw_not_found(ctx);
    }
    if (vm_parse_id(tail, id, sizeof id, &rest) != 0)
        return vm_gw_not_found(ctx);
    if (!*rest && !strcmp(m, "GET")) {
        p = json_object_new_object();
        json_object_object_add(p, "task_id", json_object_new_string(id));
        return vm_gw_call(ctx, "task_get", p);
    }
    if (!strcmp(rest, "/cancel") && !strcmp(m, "POST")) {
        p = json_object_new_object();
        json_object_object_add(p, "task_id", json_object_new_string(id));
        return vm_gw_call(ctx, "task_cancel", p);
    }
    return vm_gw_not_found(ctx);
}

static struct json_object *vm_gw_pools(struct jmx_api_ctx *ctx)
{
    return vm_gw_call(ctx, "pool_list", vm_query_params(ctx->req->query));
}
static struct json_object *vm_gw_networks(struct jmx_api_ctx *ctx)
{
    return vm_gw_call(ctx, "network_list", vm_query_params(ctx->req->query));
}

/*
 * Only the backed operations are routed. Sequence numbers continue the 9xx
 * append block (max existing seq was 949, taken by the tv-home module).
 * status/capabilities/overview are EXACT; instances/tasks are PREFIX subtrees dispatched inside their handlers.
 * PATCH/DELETE and every unbacked verb fall through to the legacy 404 rather
 * than being claimed here.
 */
const struct jmx_api_route vm_api_routes[] = {
    JMX_API_ROUTE(950, "/api/v1/vm/status",       "GET",      JMX_API_EXACT,  vm_gw_status),
    JMX_API_ROUTE(951, "/api/v1/vm/capabilities", "GET",      JMX_API_EXACT,  vm_gw_capabilities),
    JMX_API_ROUTE(952, "/api/v1/vm/overview",     "GET",      JMX_API_EXACT,  vm_gw_overview),
    JMX_API_ROUTE(953, "/api/v1/vm/instances",    "GET,POST", JMX_API_PREFIX, vm_gw_instances),
    JMX_API_ROUTE(954, "/api/v1/vm/tasks",        "GET,POST", JMX_API_PREFIX, vm_gw_tasks),
    JMX_API_ROUTE(9609, "/api/v1/vm/pools", "GET", JMX_API_EXACT, vm_gw_pools),
    JMX_API_ROUTE(9610, "/api/v1/vm/networks", "GET", JMX_API_EXACT, vm_gw_networks),
    JMX_API_ROUTE_END,
};






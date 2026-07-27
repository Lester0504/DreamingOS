// SPDX-License-Identifier: GPL-2.0-or-later
/* DreamingWrt route scheduler daemon. */
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubus.h>

#include "routed_control.h"

#define ROUTED_INTERVAL_MS 30000
#define ROUTED_INITIAL_DELAY_MS 1000
#define ROUTED_RETRY_DELAY_MS 3000
#define JMX_ROUTE_PROC "/proc/dreamingwrt/jmx/jmx_route"

static struct ubus_context *route_ubus;
static struct blob_buf route_blob;
static struct uloop_timeout route_timer;
static time_t route_last_warn;
static int route_runtime_loaded;

struct route_invoke_result {
    int received;
    int ok;
};

static void route_invoke_result_cb(struct ubus_request *req, int type,
                                   struct blob_attr *msg)
{
    struct route_invoke_result *result = req ? req->priv : NULL;
    struct blob_attr *tb[2] = {0};
    static const struct blobmsg_policy policy[] = {
        { .name = "code", .type = BLOBMSG_TYPE_INT32 },
        { .name = "data", .type = BLOBMSG_TYPE_TABLE },
    };

    (void)type;
    if (!result || !msg)
        return;
    result->received = 1;
    blobmsg_parse(policy, 2, tb, blob_data(msg), blob_len(msg));
    result->ok = tb[0] && blobmsg_get_u32(tb[0]) == 2000;
}

static void route_warn_throttled(const char *msg, int rc)
{
    time_t now = time(NULL);

    if (now - route_last_warn < 30)
        return;
    route_last_warn = now;
    fprintf(stderr, "[dreamingwrt-routed] %s rc=%d\n", msg, rc);
}

static void route_ubus_close(void)
{
    if (route_ubus) {
        ubus_free(route_ubus);
        route_ubus = NULL;
    }
}

static int route_ubus_ensure(void)
{
    if (route_ubus)
        return 0;
    route_ubus = ubus_connect(NULL);
    if (route_ubus)
        ubus_add_uloop(route_ubus);
    return route_ubus ? 0 : -1;
}

static int route_invoke_tick(void)
{
    struct ubus_context *tick_ubus;
    uint32_t id = 0;
    int rc;

    tick_ubus = ubus_connect(NULL);
    if (!tick_ubus) {
        route_warn_throttled("ubus connect failed", -1);
        return -1;
    }

    rc = ubus_lookup_id(tick_ubus, "dreamingwrt", &id);
    if (rc != UBUS_STATUS_OK) {
        route_warn_throttled("dreamingwrt ubus object not ready", rc);
        ubus_free(tick_ubus);
        return -1;
    }

    blob_buf_init(&route_blob, 0);
    blobmsg_add_u32(&route_blob, "health", 1);
    rc = ubus_invoke(tick_ubus, id, "_route_tick", route_blob.head,
                     NULL, NULL, 30000);
    blob_buf_free(&route_blob);
    ubus_free(tick_ubus);

    if (rc != UBUS_STATUS_OK) {
        route_warn_throttled("_route_tick invoke failed", rc);
        return -1;
    }
    return 0;
}

static int route_proc_has_wan(void)
{
    FILE *fp = fopen(JMX_ROUTE_PROC, "r");
    char line[256];
    int in_wans = 0;

    if (!fp)
        return 0;
    while (fgets(line, sizeof(line), fp)) {
        unsigned id;
        char name[32];

        if (!strncmp(line, "WANs:", 5)) {
            in_wans = 1;
            continue;
        }
        if (!strncmp(line, "Rules:", 6))
            break;
        if (in_wans && sscanf(line, "%u %31s", &id, name) == 2 && id > 0) {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

static int route_invoke_reload(void)
{
    struct ubus_context *ctx;
    struct route_invoke_result result = {0};
    struct blob_buf b = {0};
    uint32_t id = 0;
    int rc;

    ctx = ubus_connect(NULL);
    if (!ctx)
        return -1;
    rc = ubus_lookup_id(ctx, "dreamingwrt", &id);
    if (rc != UBUS_STATUS_OK) {
        ubus_free(ctx);
        return -1;
    }
    blob_buf_init(&b, 0);
    rc = ubus_invoke(ctx, id, "route_reload", b.head,
                     route_invoke_result_cb, &result, 30000);
    blob_buf_free(&b);
    ubus_free(ctx);
    if (rc != UBUS_STATUS_OK || !result.received || !result.ok ||
        !route_proc_has_wan()) {
        route_warn_throttled("route_reload startup replay failed", rc);
        return -1;
    }
    route_runtime_loaded = 1;
    return 0;
}

static void route_tick_cb(struct uloop_timeout *t)
{
    if (!route_runtime_loaded || !route_proc_has_wan()) {
        route_runtime_loaded = 0;
        if (route_invoke_reload() != 0) {
            uloop_timeout_set(t, ROUTED_RETRY_DELAY_MS);
            return;
        }
    }
    if (route_invoke_tick() != 0)
        route_runtime_loaded = route_proc_has_wan();
    uloop_timeout_set(t, route_runtime_loaded ? ROUTED_INTERVAL_MS : ROUTED_RETRY_DELAY_MS);
}

static void route_handle_signal(int signo)
{
    (void)signo;
    uloop_end();
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    signal(SIGINT, route_handle_signal);
    signal(SIGTERM, route_handle_signal);

    uloop_init();
    if (route_ubus_ensure() != 0 || routed_control_start(route_ubus) != 0) {
        route_ubus_close();
        uloop_done();
        return 1;
    }
    route_timer.cb = route_tick_cb;
    uloop_timeout_set(&route_timer, ROUTED_INITIAL_DELAY_MS);
    uloop_run();

    uloop_timeout_cancel(&route_timer);
    routed_control_stop(route_ubus);
    route_ubus_close();
    uloop_done();
    return 0;
}

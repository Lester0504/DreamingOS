// SPDX-License-Identifier: GPL-2.0-or-later
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>

static struct ubus_context *fixture_ubus;
static struct blob_buf fixture_blob;
static int fixture_initialized;
static char fixture_finished_by[96];

enum {
    FIXTURE_FINISH_COMPLETED_BY,
    FIXTURE_FINISH_ACTOR,
    __FIXTURE_FINISH_MAX,
};

static const struct blobmsg_policy fixture_finish_policy[__FIXTURE_FINISH_MAX] = {
    [FIXTURE_FINISH_COMPLETED_BY] = {
        .name = "completed_by", .type = BLOBMSG_TYPE_STRING,
    },
    [FIXTURE_FINISH_ACTOR] = {
        .name = "actor", .type = BLOBMSG_TYPE_STRING,
    },
};

static void fixture_stop(int signo)
{
    (void)signo;
    uloop_end();
}

static int fixture_reply(struct ubus_context *ctx,
                         struct ubus_request_data *req,
                         const char *json)
{
    blob_buf_init(&fixture_blob, 0);
    if (!blobmsg_add_json_from_string(&fixture_blob, json)) {
        blob_buf_free(&fixture_blob);
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    ubus_send_reply(ctx, req, fixture_blob.head);
    blob_buf_free(&fixture_blob);
    return UBUS_STATUS_OK;
}

static int fixture_setup_status(struct ubus_context *ctx,
                                struct ubus_object *obj,
                                struct ubus_request_data *req,
                                const char *method,
                                struct blob_attr *msg)
{
    (void)obj;
    (void)method;
    (void)msg;
    char response[512];

    snprintf(response, sizeof(response),
        "{\"code\":2000,\"data\":{\"ok\":true,\"initialized\":%s,"
        "\"setup_finished_at\":%lld,\"setup_finished_by\":\"%s\","
        "\"setup_version\":\"%s\"}}",
        fixture_initialized ? "true" : "false",
        fixture_initialized ? 1784678400LL : 0LL,
        fixture_initialized ? fixture_finished_by : "",
        fixture_initialized ? "fixture-1" : "");
    return fixture_reply(ctx, req, response);
}

static int fixture_setup_finish(struct ubus_context *ctx,
                                struct ubus_object *obj,
                                struct ubus_request_data *req,
                                const char *method,
                                struct blob_attr *msg)
{
    struct blob_attr *tb[__FIXTURE_FINISH_MAX];
    const char *completed_by = "";
    const char *actor = "";

    (void)obj;
    (void)method;
    memset(tb, 0, sizeof(tb));
    if (msg)
        blobmsg_parse(fixture_finish_policy, __FIXTURE_FINISH_MAX, tb,
                      blob_data(msg), blob_len(msg));
    if (tb[FIXTURE_FINISH_COMPLETED_BY])
        completed_by = blobmsg_get_string(tb[FIXTURE_FINISH_COMPLETED_BY]);
    if (tb[FIXTURE_FINISH_ACTOR])
        actor = blobmsg_get_string(tb[FIXTURE_FINISH_ACTOR]);
    if (!completed_by[0] || strcmp(completed_by, actor))
        return fixture_reply(ctx, req,
            "{\"code\":4000,\"data\":{\"ok\":false,"
            "\"error\":\"fixture_actor_mismatch\"}}");
    snprintf(fixture_finished_by, sizeof(fixture_finished_by), "%s",
             completed_by);
    fixture_initialized = 1;
    return fixture_reply(ctx, req,
        "{\"code\":2000,\"data\":{\"ok\":true,"
        "\"initialized\":true}}");
}

static int fixture_setup_write(struct ubus_context *ctx,
                               struct ubus_object *obj,
                               struct ubus_request_data *req,
                               const char *method,
                               struct blob_attr *msg)
{
    char response[256];

    (void)obj;
    (void)msg;
    snprintf(response, sizeof(response),
             "{\"code\":2000,\"data\":{\"ok\":true,\"method\":\"%s\"}}",
             method ? method : "");
    return fixture_reply(ctx, req, response);
}

static const struct ubus_method fixture_methods[] = {
    UBUS_METHOD_NOARG("setup_status", fixture_setup_status),
    UBUS_METHOD_NOARG("setup_start", fixture_setup_write),
    UBUS_METHOD_NOARG("setup_save_device", fixture_setup_write),
    UBUS_METHOD("setup_finish", fixture_setup_finish, fixture_finish_policy),
};

static struct ubus_object_type fixture_type =
    UBUS_OBJECT_TYPE("dreamingwrt.setup-session-fixture", fixture_methods);

static struct ubus_object fixture_object = {
    .name = "dreamingwrt",
    .type = &fixture_type,
    .methods = fixture_methods,
    .n_methods = ARRAY_SIZE(fixture_methods),
};

int main(void)
{
    const char *ready_path;
    int rc;

    signal(SIGINT, fixture_stop);
    signal(SIGTERM, fixture_stop);
    if (uloop_init() != 0)
        return 1;
    fixture_ubus = ubus_connect(NULL);
    if (!fixture_ubus) {
        uloop_done();
        return 1;
    }
    ubus_add_uloop(fixture_ubus);
    rc = ubus_add_object(fixture_ubus, &fixture_object);
    if (rc != UBUS_STATUS_OK) {
        ubus_free(fixture_ubus);
        uloop_done();
        return 1;
    }
    ready_path = getenv("WEBD_SETUP_TEST_FIXTURE_READY");
    if (ready_path && ready_path[0]) {
        FILE *ready = fopen(ready_path, "w");

        if (!ready) {
            ubus_remove_object(fixture_ubus, &fixture_object);
            ubus_free(fixture_ubus);
            uloop_done();
            return 1;
        }
        fputs("ready\n", ready);
        fclose(ready);
    }
    uloop_run();
    ubus_remove_object(fixture_ubus, &fixture_object);
    ubus_free(fixture_ubus);
    uloop_done();
    return 0;
}

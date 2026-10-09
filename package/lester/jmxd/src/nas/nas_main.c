// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
#ifdef NAS_NVR
#include "nvr.h"
#define nas_init nvr_init
#define nas_close nvr_close
#define nas_tick nvr_tick
#define nas_request nvr_request
#define SERVICE_NAME "dreamingwrt.nvr"
#define CONFIG_PATH "/etc/dreamingwrt/nvr.json"
#else
#include "nas.h"
#define SERVICE_NAME "dreamingos.nas"
#define CONFIG_PATH "/etc/dreamingwrt/nas.json"
#endif
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef NAS_STDIN
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubus.h>
static struct ubus_context *bus;
static void tick(struct uloop_timeout *timer) {
    nas_tick();
    uloop_timeout_set(timer, 1000);
}
static struct uloop_timeout ticker = {.cb = tick};
static const struct blobmsg_policy policy[] = {{.name = "req", .type = BLOBMSG_TYPE_STRING}};
static int handle(struct ubus_context *ctx, struct ubus_object *obj,
                  struct ubus_request_data *request, const char *method, struct blob_attr *msg) {
    (void)obj;
    (void)method;
    struct blob_attr *fields[1];
    blobmsg_parse(policy, 1, fields, blob_data(msg), blob_len(msg));
    if (!fields[0])
        return UBUS_STATUS_INVALID_ARGUMENT;
    struct json_object *input = json_tokener_parse(blobmsg_get_string(fields[0])), *m = NULL,
                       *r = NULL, *p = NULL;
    if (!input || !json_object_is_type(input, json_type_object) ||
        !json_object_object_get_ex(input, "method", &m) ||
        !json_object_is_type(m, json_type_string) ||
        !json_object_object_get_ex(input, "route", &r) ||
        !json_object_is_type(r, json_type_string) ||
        (json_object_object_get_ex(input, "params", &p) &&
         !json_object_is_type(p, json_type_object))) {
        if (input)
            json_object_put(input);
        return UBUS_STATUS_INVALID_ARGUMENT;
    }
    json_object_object_get_ex(input, "params", &p);
    int status;
    struct json_object *body =
        nas_request(json_object_get_string(m), json_object_get_string(r), p, &status);
    struct blob_buf out = {0};
    blob_buf_init(&out, 0);
    blobmsg_add_u32(&out, "http_status", status);
    blobmsg_add_string(&out, "body", json_object_to_json_string_ext(body, JSON_C_TO_STRING_PLAIN));
    ubus_send_reply(ctx, request, out.head);
    blob_buf_free(&out);
    json_object_put(body);
    json_object_put(input);
    return 0;
}
static const struct ubus_method methods[] = {UBUS_METHOD("request", handle, policy)};
static struct ubus_object_type type = UBUS_OBJECT_TYPE(SERVICE_NAME, methods);
static struct ubus_object object = {
    .name = SERVICE_NAME, .type = &type, .methods = methods, .n_methods = 1};
static void lost(struct ubus_context *ctx) {
    (void)ctx;
    uloop_end();
}
#endif
// storage_files is shared code; this binary owns no core control-plane symbols.
struct json_object *jmx_gen_api_response_data(int code, struct json_object *data) {
    struct json_object *out = json_object_new_object();
    json_object_object_add(out, "code", json_object_new_int(code));
    json_object_object_add(out, "data", data);
    return out;
}
int main(int argc, char **argv) {
    const char *config = argc > 1 ? argv[1] : CONFIG_PATH;
    nas_init(config);
#ifdef NAS_STDIN
    setvbuf(stdin, NULL, _IONBF, 0);
    char *line = NULL;
    size_t capacity = 0;
    for (;;) {
        struct pollfd input_fd = {.fd = STDIN_FILENO, .events = POLLIN};
        int polled = poll(&input_fd, 1, 1000);
        nas_tick();
        if (!polled) continue;
        if (polled < 0) { if (errno == EINTR) continue; break; }
        if (getline(&line, &capacity, stdin) <= 0) break;
        struct json_object *input = json_tokener_parse(line), *m = NULL, *r = NULL, *p = NULL;
        if (!input)
            continue;
        json_object_object_get_ex(input, "method", &m);
        json_object_object_get_ex(input, "route", &r);
        json_object_object_get_ex(input, "params", &p);
        if (m && r) {
            int status;
            struct json_object *reply =
                nas_request(json_object_get_string(m), json_object_get_string(r), p, &status);
            json_object_object_add(reply, "http_status", json_object_new_int(status));
            puts(json_object_to_json_string_ext(reply, JSON_C_TO_STRING_PLAIN));
            fflush(stdout);
            json_object_put(reply);
        }
        json_object_put(input);
    }
    free(line);
#else
    /* nas.c owns waitpid and persists worker results. uloop's global SIGCHLD
     * reaper must not consume those children, including during ubus_connect. */
    uloop_handle_sigchld = false;
    signal(SIGCHLD, SIG_DFL);
    uloop_init();
    bus = ubus_connect(argc > 2 ? argv[2] : NULL);
    if (!bus) {
        fprintf(stderr, "nas: ubus connection failed: %s\n", strerror(errno));
        nas_close();
        return 1;
    }
    bus->connection_lost = lost;
    ubus_add_uloop(bus);
    int registered = ubus_add_object(bus, &object);
    if (registered) {
        fprintf(stderr, "nas: ubus registration failed: %s\n", ubus_strerror(registered));
        ubus_free(bus);
        nas_close();
        return 1;
    }
    uloop_timeout_set(&ticker, 1000);
    uloop_run();
    uloop_timeout_cancel(&ticker);
    ubus_free(bus);
    uloop_done();
#endif
    nas_close();
    return 0;
}

/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef AP_CONTROL_LOG_RPC_H
#define AP_CONTROL_LOG_RPC_H
#include "ap_control_log.h"
#include "ap_control_wire.h"

static inline int ap_log_capabilities_add(struct json_object *o, const struct ap_control_capabilities *caps)
{
    int rc = ap_control_capabilities_add(o, caps);
    if (rc == AP_CONTROL_WIRE_OK)
        json_object_object_add(json_object_object_get(o, "capabilities"),
                               AP_LOG_CAPABILITY, json_object_new_boolean(1));
    return rc;
}

#if defined(AP_LOG_TEST_RPC)
struct json_object *ap_log_rpc(const char *method, struct json_object *body);
#elif defined(APD_TRANSPORT_TEST_STANDALONE) || defined(AC_TRANSPORT_TEST_STANDALONE)
static inline struct json_object *ap_log_rpc(const char *method, struct json_object *body)
{
    (void)method; (void)body;
    return NULL;
}
#else
#include <stdlib.h>
#include <libubus.h>
#include <libubox/blobmsg_json.h>
static void ap_log_rpc_reply(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct json_object **out = req->priv;
    char *text;
    (void)type;
    if (!msg || !out) return;
    text = blobmsg_format_json(msg, true);
    if (text) {
        json_object_put(*out);
        *out = json_tokener_parse(text);
        free(text);
    }
}
/* Each transport thread owns this short-lived ubus socket. Never uses the
 * main-loop context, and never invokes a shell with event contents. */
static inline struct json_object *ap_log_rpc(const char *method, struct json_object *body)
{
    struct ubus_context *ctx = ubus_connect(NULL);
    struct blob_buf b = {0};
    struct json_object *out = NULL;
    uint32_t id;
    if (!ctx) return NULL;
    blob_buf_init(&b, 0);
    if (ubus_lookup_id(ctx, "dreamingwrt.logd", &id) == 0 &&
        (!body || blobmsg_add_json_from_string(&b,
            json_object_to_json_string_ext(body, JSON_C_TO_STRING_PLAIN)))) {
        if (ubus_invoke(ctx, id, method, b.head, ap_log_rpc_reply, &out, 1500) != 0) {
            json_object_put(out);
            out = NULL;
        }
    }
    blob_buf_free(&b);
    ubus_free(ctx);
    return out;
}
#endif
#endif

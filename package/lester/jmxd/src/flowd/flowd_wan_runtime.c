// SPDX-License-Identifier: GPL-2.0-or-later
#include "flowd_wan_runtime.h"
#include "flowd_internal.h"

#include <net/if.h>

struct flowd_wan_ubus_reply {
    struct json_object *json;
};

static void flowd_wan_ubus_reply_cb(struct ubus_request *req, int type,
                                    struct blob_attr *msg)
{
    struct flowd_wan_ubus_reply *reply = req ? req->priv : NULL;
    char *text;

    (void)type;
    if (!reply || !msg)
        return;
    text = blobmsg_format_json(msg, true);
    if (!text)
        return;
    if (reply->json)
        json_object_put(reply->json);
    reply->json = json_tokener_parse(text);
    free(text);
}

static int flowd_wan_ubus_l3_device(const char *wan, char *out,
                                    size_t out_len)
{
    struct flowd_wan_ubus_reply reply = {0};
    struct ubus_context *ctx = NULL;
    struct json_object *value = NULL;
    char object[128];
    uint32_t object_id = 0;
    int rc = -1;

    if (!wan || !wan[0] || !out || out_len == 0 ||
        snprintf(object, sizeof(object), "network.interface.%s", wan) >=
        (int)sizeof(object))
        return -1;
    ctx = ubus_connect(NULL);
    if (!ctx || ubus_lookup_id(ctx, object, &object_id) != UBUS_STATUS_OK)
        goto done;
    if (ubus_invoke(ctx, object_id, "status", NULL, flowd_wan_ubus_reply_cb,
                    &reply, 2500) != UBUS_STATUS_OK || !reply.json ||
        !json_object_object_get_ex(reply.json, "l3_device", &value) ||
        !value || !json_object_is_type(value, json_type_string) ||
        json_object_get_string_len(value) == 0 ||
        json_object_get_string_len(value) >= out_len ||
        !if_nametoindex(json_object_get_string(value)))
        goto done;
    snprintf(out, out_len, "%s", json_object_get_string(value));
    rc = 0;

done:
    if (reply.json)
        json_object_put(reply.json);
    if (ctx)
        ubus_free(ctx);
    return rc;
}

int flowd_wan_resolve_ifname(const char *wan, char *out, size_t out_len)
{
    char candidate[IFNAMSIZ];

    if (!wan || !wan[0] || !out || out_len == 0)
        return -1;
    out[0] = '\0';
    if (flowd_wan_ubus_l3_device(wan, out, out_len) == 0)
        return 0;
    if (snprintf(candidate, sizeof(candidate), "pppoe-%s", wan) <
        (int)sizeof(candidate) && if_nametoindex(candidate)) {
        snprintf(out, out_len, "%s", candidate);
        return 0;
    }
    if (strlen(wan) < out_len && if_nametoindex(wan)) {
        snprintf(out, out_len, "%s", wan);
        return 0;
    }
    return -1;
}

int flowd_wan_resolve_l3_ifname(const char *wan, char *out, size_t out_len)
{
    if (!out || !out_len) return -1;
    out[0] = '\0';
    return flowd_wan_ubus_l3_device(wan, out, out_len);
}

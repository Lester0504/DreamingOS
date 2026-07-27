// SPDX-License-Identifier: GPL-2.0-or-later
/* Runtime hooks used when API code runs outside dreamingwrt-core. */
#include <stdint.h>
#include <stdlib.h>
#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

int jmx_runtime_reload_signature_db(const char *path)
{
    struct ubus_context *ctx;
    struct blob_buf b = {0};
    uint32_t id;
    int rc;

    ctx = ubus_connect(NULL);
    if (!ctx)
        return -1;
    if (ubus_lookup_id(ctx, "jmx", &id) != UBUS_STATUS_OK) {
        ubus_free(ctx);
        return -1;
    }

    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "api", "reload_rules");
    if (path && path[0]) {
        struct json_object *req = json_object_new_object();
        const char *s;

        if (!req) {
            blob_buf_free(&b);
            ubus_free(ctx);
            return -1;
        }
        json_object_object_add(req, "signature_db", json_object_new_string(path));
        s = json_object_to_json_string(req);
        if (s)
            blobmsg_add_json_from_string(&b, s);
        json_object_put(req);
    }

    rc = ubus_invoke(ctx, id, "common", b.head, NULL, NULL, 5000);
    blob_buf_free(&b);
    ubus_free(ctx);
    return rc == UBUS_STATUS_OK ? 0 : -1;
}

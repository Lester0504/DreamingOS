// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_GATEWAY_PORTS_H
#define DREAMINGWRT_GATEWAY_PORTS_H

#include <json-c/json.h>
#include <libubus.h>

struct json_object *gateway_ports_get(struct ubus_context *ctx);
struct json_object *gateway_ports_preview(struct ubus_context *ctx,
                                          struct json_object *body);
struct json_object *gateway_ports_apply(struct ubus_context *ctx,
                                        struct json_object *body);

#endif

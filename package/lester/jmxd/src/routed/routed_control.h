// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_ROUTED_CONTROL_H
#define DREAMINGWRT_ROUTED_CONTROL_H

#include <libubus.h>

int routed_control_start(struct ubus_context *ctx);
void routed_control_stop(struct ubus_context *ctx);

#endif

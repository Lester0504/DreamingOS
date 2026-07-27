// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __WEBD_SYSTEM_TTYD_H__
#define __WEBD_SYSTEM_TTYD_H__

#include <json-c/json.h>

/*
 * Standalone ttyd UCI control plane.  REST routing and the /terminal/
 * WebSocket proxy are intentionally owned by the webd integration layer.
 */
struct json_object *system_ttyd_get(int *http_status);
struct json_object *system_ttyd_validate(struct json_object *request,
                                         int *http_status);
struct json_object *system_ttyd_apply(struct json_object *request,
                                      int *http_status);

#endif

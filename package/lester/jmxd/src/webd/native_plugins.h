// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __DREAMINGWRT_WEBD_NATIVE_PLUGINS_H__
#define __DREAMINGWRT_WEBD_NATIVE_PLUGINS_H__

#include <stddef.h>
#include <json-c/json.h>

#define WEBD_NATIVE_API_PREFIX "/api/v1/plugins/native/"

struct json_object *webd_native_plugins_scan(void);
void webd_native_plugins_merge_menu(struct json_object *menu);
const char *webd_native_required_permission(const char *method, const char *path);
int webd_native_proxy_json(int client_fd,
                           const char *method,
                           const char *path,
                           const char *query,
                           const void *body,
                           size_t body_len,
                           const char *actor,
                           const char *client_ip,
                           const char *request_id,
                           struct json_object *permissions);

#endif

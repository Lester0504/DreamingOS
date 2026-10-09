// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef WEBD_TERMINAL_MANAGER_BRIDGE_H
#define WEBD_TERMINAL_MANAGER_BRIDGE_H
#include "api/webd_http_req.h"
#include <json-c/json.h>
/* Called only after webd validates session, role and ordinary request permissions. */
int webd_terminal_manager_handle(int fd, const struct http_req *req,
    struct json_object *body, const char *owner, int manage, int api_key);
#endif

// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef WEBD_SYSTEM_WEB_ACCESS_H
#define WEBD_SYSTEM_WEB_ACCESS_H

#include <json-c/json.h>

struct json_object *webd_system_web_access_data(int *http_status);
struct json_object *webd_system_web_access_write(struct json_object *body,
                                                 const char *owner_id,
                                                 int *http_status);

#endif

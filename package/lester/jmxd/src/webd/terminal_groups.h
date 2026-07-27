// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __WEBD_TERMINAL_GROUPS_H__
#define __WEBD_TERMINAL_GROUPS_H__

#include <json-c/json.h>

int webd_terminal_groups_init(void);
int webd_terminal_groups_path(const char *path);
struct json_object *webd_terminal_groups_handle(const char *method,
                                                const char *path,
                                                const char *query,
                                                struct json_object *body,
                                                const char *actor,
                                                int *http_status);

#endif

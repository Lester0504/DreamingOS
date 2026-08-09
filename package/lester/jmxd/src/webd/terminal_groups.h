// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __WEBD_TERMINAL_GROUPS_H__
#define __WEBD_TERMINAL_GROUPS_H__

#include <json-c/json.h>

int webd_terminal_groups_init(void);
int webd_terminal_groups_path(const char *path);
/*
 * Group-id checks for the MAC ACL write path: a rule may bind to a terminal
 * group instead of a single MAC, and a binding to a non-existent group would
 * render no nft rule at all.
 */
int webd_terminal_group_id_ok(const char *id);
int webd_terminal_group_exists(const char *id);
/* Members that carry a MAC, i.e. how many nft rules the group will expand to.
 * Negative when the store cannot be read; 0 is a real, empty group. */
int webd_terminal_group_member_count(const char *id);
struct json_object *webd_terminal_groups_handle(const char *method,
                                                const char *path,
                                                const char *query,
                                                struct json_object *body,
                                                const char *actor,
                                                int *http_status);

#endif

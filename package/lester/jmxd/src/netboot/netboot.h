// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_NETBOOT_H
#define DREAMINGWRT_NETBOOT_H

#include <json-c/json.h>
#include <sqlite3.h>
#include <uci.h>

/* The management adapter owns authentication; the core owns config and runtime.
 * Reads never create the database, mount an image, or change client policy. */
struct json_object *jmx_netboot_request(const char *method, const char *resource,
                                      const char *id, const char *action,
                                      struct json_object *body);
void jmx_netboot_startup(void);
int jmx_netboot_dhcp_project(struct uci_context *ctx, struct uci_package *pkg);

#endif

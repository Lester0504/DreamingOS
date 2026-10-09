// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef WEBD_API_CLIENT_CONTROL_H
#define WEBD_API_CLIENT_CONTROL_H

#include "api_router.h"

extern const struct jmx_api_route client_control_api_routes[];
/* webd_client_profile_response() in the monolith still renders the per-client
 * control view, so it keeps calling these two. Nothing else escapes. */
struct json_object *webd_client_control_rules_load(const char *mac);
void webd_client_control_add_capabilities(struct json_object *cap);

#endif

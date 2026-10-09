// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef WEBD_API_CLIENT_CONNECTIONS_H
#define WEBD_API_CLIENT_CONNECTIONS_H

#include "api_router.h"

extern const struct jmx_api_route client_connections_api_routes[];
/* The /clients kick action in the monolith still flushes conntrack through this
 * raw-netlink primitive, which now lives in this module. */
int app_run_conntrack_delete(const char *direction, const char *ip);

#endif

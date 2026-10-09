// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef WEBD_API_CLIENTS_LIST_H
#define WEBD_API_CLIENTS_LIST_H

#include "api_router.h"

extern const struct jmx_api_route clients_list_api_routes[];
struct json_object *webd_clients_response(int *http_status, int with_apps,
                                         int include_stale);

#endif

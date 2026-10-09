// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef WEBD_API_CLIENT_PROFILE_H
#define WEBD_API_CLIENT_PROFILE_H

#include "api_router.h"

struct http_req;
struct json_object;

extern const struct jmx_api_route client_profile_api_routes[];

/* The WebSocket read model in the monolith still renders a client profile
 * through this builder. */
struct json_object *webd_client_profile_response(const struct http_req *req);

/* The monolith's insights code still labels connection services through these. */
const char *webd_connection_service_field_label(const char *service);
const char *webd_connection_service_label(const char *proto, int port, int *is_p2p);

#endif

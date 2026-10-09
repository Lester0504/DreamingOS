// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Per-request context handed to a route handler.
 *
 * handle_client() keeps ~12 locals alive across the dispatch chain: the parsed
 * request, the parsed body, the resolved identity and role, and two scratch
 * buffers that route matching itself fills in. Passing those individually to
 * 700+ handlers is not workable, so they travel in one struct.
 *
 * Ownership, because getting this wrong leaks or double-frees:
 *   req        borrowed. Handlers must not write through it.
 *   body       owned by the router. A handler may replace it, and must put the
 *              value it replaces. The router puts whatever is there at the end.
 *   status     handler writes; 200 unless set otherwise.
 *   fd         only meaningful for a JMX_API_RAW_FD handler, which writes the
 *              socket itself and returns NULL. -1 for every other handler, so a
 *              handler that reaches for it by mistake fails loudly instead of
 *              writing into an unrelated descriptor.
 *   device_id  borrowed; the router owns and frees it.
 *
 * A handler returns the response object and transfers it to the router, or
 * returns NULL after having written the socket itself (RAW_FD only).
 */
#ifndef WEBD_API_CONTEXT_H
#define WEBD_API_CONTEXT_H

#include <json-c/json.h>

#include "../jmx_app_perms.h"
#include "../webd_api_keys.h"
#include "webd_http_req.h"

struct jmx_api_ctx {
    const struct http_req *req;
    struct json_object    *body;
    int                    status;
    int                    fd;
    const char            *device_id;
    jmx_role_t             role;
    jmx_risk_t             risk;
    const char            *authenticated_role;
    /*
     * Filled by the route match itself, not by the handler: an id embedded in
     * the path is parsed once during matching rather than re-parsed by each
     * handler that needs it.
     */
    char                   api_key_path_id[WEBD_API_KEY_ID_LEN + 1];
    char                   user_activity_name[80];
};

#endif /* WEBD_API_CONTEXT_H */

// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __WEBD_SYSTEM_TTYD_PROXY_H__
#define __WEBD_SYSTEM_TTYD_PROXY_H__

#include <stddef.h>

/*
 * The parent webd route owns session validation, RBAC and the concurrent
 * connection counter.  The proxy repeats the owner/admin and permit checks so
 * a future route cannot accidentally expose ttyd without those gates.
 */
enum system_ttyd_proxy_access {
    SYSTEM_TTYD_PROXY_ACCESS_NONE = 0,
    SYSTEM_TTYD_PROXY_ACCESS_ADMIN,
    SYSTEM_TTYD_PROXY_ACCESS_OWNER,
};

struct system_ttyd_proxy_request {
    int client_fd;
    const void *raw_request;
    size_t raw_request_len;

    /* Values derived by the authenticated parent route, not untrusted headers. */
    const char *external_host;
    const char *external_proto;
    enum system_ttyd_proxy_access access;

    /* Must be set only after the parent worker has acquired a connection slot. */
    int parent_connection_permit;
    unsigned int idle_timeout_ms;
};

struct system_ttyd_proxy_result {
    int http_status;
    int upstream_status;
    int upstream_connected;
    int websocket_upgraded;
    int idle_timeout;
    char error_code[64];
};

/*
 * Handles one already-authenticated /terminal or /terminal/... request.
 * The function is synchronous and does not close request->client_fd.  It never
 * inspects WebSocket frames or logs request/response payloads.  The parent may
 * use the result for connection-open/close auditing without terminal content.
 */
int system_ttyd_proxy_handle_authenticated(
    const struct system_ttyd_proxy_request *request,
    struct system_ttyd_proxy_result *result);

#endif

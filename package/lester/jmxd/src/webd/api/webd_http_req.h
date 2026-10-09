// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * The parsed HTTP request, shared between jmx_app_api.c and the api/ route
 * modules.
 *
 * This type was file-static in jmx_app_api.c. It is the one existing type the
 * decomposition has to make visible: every route handler reads req.path,
 * req.method and the header fields, so a handler cannot move out of that file
 * until the struct is declared somewhere both sides can include.
 *
 * Nothing else moved with it. The two token-length macros below came along only
 * because two members are sized by them.
 */
#ifndef WEBD_HTTP_REQ_H
#define WEBD_HTTP_REQ_H

/* Relative: the api/ modules sit one level below webd/, and the build's -I set
 * does not include webd/ itself. */
#include "../webd_api_keys.h"

/* Session access/refresh token, hex. */
#define TOKEN_LEN                    64
/* First-run setup session cookie, hex. Same width, different lifecycle. */
#define WEBD_SETUP_SESSION_TOKEN_LEN 64

struct http_req {
    char method[8];
    char path[512];
    char query[512];
    const char *body;
    int body_len;
    char auth_token[TOKEN_LEN + 1];
    char setup_session[WEBD_SETUP_SESSION_TOKEN_LEN + 1];
    char if_none_match[64]; /* ETag for conditional requests */
    /*
     * Range as sent, unparsed. Needed by the raw storage byte stream: <video>
     * cannot seek without it, and a player that gets 200 for a range request
     * falls back to downloading the whole file before it will scrub.
     */
    char range[128];
    char client_ip[64];
    /*
     * TCP peer address, never overwritten by any header. client_ip may be
     * replaced by a trusted forwarded value, which loses the real origin; audit
     * records need both so a local process cannot erase where it actually came
     * from. ip_source says which of the two client_ip currently holds.
     */
    char peer_ip[64];
    char ip_source[12];
    char sec_fetch_site[24];
    char content_type[96];
    char host[256];
    char forwarded_proto[8];
    /*
     * User-Agent as sent, truncated. Kept for the audit trail: "which client
     * did this" is unanswerable without it. Attacker-controlled, so it is only
     * ever bound as a SQL parameter and escaped on output.
     */
    char user_agent[257];
    /* Raw credential presented via X-API-Key, when that header is used. */
    char api_key_header[WEBD_API_KEY_PLAIN_MAX + 1];
    int auth_via_cookie;
    int accepts_gzip;
    int websocket;
    char ws_key[128];
    char origin[320]; /* App WebSocket same-origin gate; appended to preserve existing offsets. */
};

#endif /* WEBD_HTTP_REQ_H */

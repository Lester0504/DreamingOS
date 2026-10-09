// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_CAPTURE_INTERNAL_H
#define WEBD_API_CAPTURE_INTERNAL_H

/*
 * Packet-capture subsystem contract (Phase 6V), extracted from jmx_app_api.c
 * into api_capture.c.
 */
struct json_object;
struct http_req;

/* Entry points reached from jmx_app_api.c (handle_client dispatches these two
 * response builders; they are not jmx_api_route table rows). */
struct json_object *webd_topology_capture_response(const struct http_req *req,
                                                   struct json_object *body,
                                                   const char *actor_identity,
                                                   int *http_status);
int webd_topology_capture_download_response(int fd, const struct http_req *req);

/*
 * Borrowed from jmx_app_api.c (definitions stay there, de-static'd — each has
 * callers that remain in main): the first-line file reader and the path-suffix
 * test.
 */
void app_read_first_line(const char *path, char *buf, size_t len);
int webd_path_ends_with(const char *path, const char *suffix);

/*
 * Non-static helpers defined in jmx_app_api.c and reused by the capture code.
 * Redeclared here (rather than cross-including a sibling domain's internal
 * header) so this TU owns its full contract: the positive-int segment parser,
 * the identity kind/username helpers, and the token sanitiser.
 */
int app_parse_positive_int_segment(const char *s, int *out);
int webd_identity_is_user(const char *identity);
const char *webd_identity_username(const char *identity);
int webd_safe_token(const char *s);

#endif /* WEBD_API_CAPTURE_INTERNAL_H */

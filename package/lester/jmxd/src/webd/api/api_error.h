// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Response envelopes and the upstream-error to HTTP-status mapping.
 *
 * app_response_status() is the single place that decides what a core failure looks
 * like over HTTP, and it is ~240 lines of error-code table. Keeping it next to
 * webd_error(), webd_envelope() and webd_meta() means a new error code is added in
 * one file and a route module gets the mapping from one header.
 *
 * ai_envelope_diag() reads struct app_ubus_call_diag. api_error.h only forward
 * declares that type; the full definition is in api_ubus.h, included from this .c,
 * so the two headers do not include each other.
 */
#ifndef WEBD_API_ERROR_H
#define WEBD_API_ERROR_H

#include <json-c/json.h>

/*
 * The response-code contract, moved here from jmx_app_api.c rather than
 * duplicated. Every consumer of these two codes also needs
 * app_response_status() or app_jmx_response_data(), so one definition next to
 * the status mapping serves all of them -- including jmx_app_api.c, which still
 * has ~60 uses and picks them up by including this header.
 */
#define APP_API_CODE_SUCCESS 2000
#define APP_API_CODE_ERROR 4000

/* Defined in api_ubus.h. Declared incomplete here so the error and ubus
 * headers do not include each other; only pointers to it appear below. */
struct app_ubus_call_diag;

struct json_object *app_jmx_response_data(int code, struct json_object *data_obj);
int app_response_status(struct json_object *resp, int current_status);
struct json_object *ai_envelope_diag(struct json_object *resp, int default_code,
                                            const struct app_ubus_call_diag *diag);
struct json_object *ai_envelope(struct json_object *resp, int default_code);
int app_jmx_response_http_status(struct json_object *resp, int default_status);
int app_routed_http_status(struct json_object *resp, int current_status);
struct json_object *webd_meta(const char *source);
struct json_object *webd_envelope(struct json_object *data, const char *source);
void webd_mark_cached_response_stale(struct json_object *resp, int age_ms,
                                            const char *source_error);
struct json_object *webd_error(const char *code, const char *message,
                                      const char *missing, const char *source);

#endif /* WEBD_API_ERROR_H */

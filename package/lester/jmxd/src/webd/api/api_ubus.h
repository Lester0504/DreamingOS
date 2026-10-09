// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Every ubus call webd makes to a jmxd daemon.
 *
 * One reusable ubus context per thread plus a watchdog thread per call. Both are
 * load-bearing and were the subject of two production defects, so the comments on
 * context lifetime and the atfork handler are kept verbatim from the original.
 *
 * The per-thread context and the frame-build mutex are file-static here: every
 * function that touches them moved together, so nothing outside this translation
 * unit can reach them any more. jmx_app_api_init() still runs the pthread_once
 * that arms the atfork handler, which is why app_ubus_atfork_register() is the one
 * of the four atfork functions that is not static.
 */
#ifndef WEBD_API_UBUS_H
#define WEBD_API_UBUS_H

#include <json-c/json.h>

/* Which stage of a ubus call failed. Declared up here because callers far above
 * the implementation need to tell "object not registered" from "object there but
 * the call did not land". */
struct app_ubus_call_diag {
    int rc;             /* ubus status of the failing stage, -1 otherwise */
    const char *stage;  /* "connect" | "lookup" | "invoke" | NULL on success */
};

int app_ubus_validation_errors(const char *method, struct json_object *params,
                                      struct json_object **errors_out);
void app_ubus_atfork_register(void);
void app_ubus_context_drop(void);
void app_ubus_context_drop_in_child(void);
void app_ubus_context_close(void);
struct json_object *app_ubus_invoke_object_diag(const char *object, const char *method,
                                                       struct json_object *params, int timeout_ms,
                                                       struct app_ubus_call_diag *diag);
struct json_object *app_ubus_invoke_object_timeout(const char *object, const char *method,
                                                         struct json_object *params, int timeout_ms);
struct json_object *app_ubus_invoke_object(const char *object, const char *method, struct json_object *params);
struct json_object *app_ubus_invoke_timeout(const char *method, struct json_object *params,
                                                   int timeout_ms);
struct json_object *app_ubus_invoke(const char *method, struct json_object *params);
int app_ubus_object_available(const char *object);
struct json_object *app_ubus_or_error(const char *method, struct json_object *params);
struct json_object *app_ubus_object_or_error(const char *object, const char *method, struct json_object *params);
struct json_object *app_ubus_object_or_error_timeout(const char *object,
                                                            const char *method,
                                                            struct json_object *params,
                                                            int timeout_ms,
                                                            int *http_status);
struct json_object *app_ubus_route_or_error(const char *object,
                                                   const char *method,
                                                   struct json_object *params,
                                                   int timeout_ms,
                                                   int *http_status);
struct json_object *app_ubus_core_route(const char *method,
                                               struct json_object *params,
                                               int timeout_ms,
                                               int *http_status);
/* Same diagnosis as app_ubus_core_route(), with the reporting source named by
 * the caller and an invoke-stage timeout reported as `dependency_timeout`/504
 * rather than as an unavailable source. */
struct json_object *app_ubus_core_route_source(const char *method,
                                               struct json_object *params,
                                               int timeout_ms,
                                               int *http_status,
                                               const char *source);
int app_ubus_response_ok(struct json_object *upstream);
const char *app_ubus_response_error_code(struct json_object *upstream);
struct json_object *app_ubus_ok_only(const char *method, struct json_object *params);
struct json_object *app_ubus_ai_ok_envelope(const char *method, struct json_object *params);
struct json_object *app_ubus_data_or_error(const char *method, struct json_object *params);
int app_ubus_call_ok(const char *method, struct json_object *params);

struct json_object *app_routed_call(const char *method, struct json_object *params);

#endif /* WEBD_API_UBUS_H */

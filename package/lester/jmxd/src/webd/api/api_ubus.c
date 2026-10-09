// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
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
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

#include "api_ubus.h"
#include "api_error.h"
#include "api_json.h"
#include "api_util.h"

#define WEBD_UBUS_DEFAULT_TIMEOUT_MS 2000
#define WEBD_UBUS_CANCEL_GRACE_MS 250

/* ── ubus invoke helper for HTTP API ── */
struct ubus_invoke_resp {
    struct json_object *json;
    int rc;
};

/*
 * libubus/libubox are not safe to call concurrently through one context.
 * The BFF fan-out deliberately uses pthreads, so a process-wide context and
 * mutex would make every source wait behind the slowest sibling. Keep one
 * reusable context per calling thread instead: persistent workers retain it
 * across requests, while independent BFF fetchers get independent sockets and
 * can make progress in parallel without sharing libubus state.
 */
static __thread struct ubus_context *g_app_ubus_thread_context;
/* libubus keeps one process-global blob buffer for lookup/invoke frames. Each
 * caller owns its socket, but frame construction must still be serialized. */
static pthread_mutex_t g_app_ubus_request_build_lock = PTHREAD_MUTEX_INITIALIZER;

struct app_ubus_deadline_guard {
    pthread_t thread;
    pthread_mutex_t lock;
    pthread_cond_t done_cv;
    struct timespec deadline;
    const char *stage;
    int ubus_fd;
    int started;
    int done;
    int timed_out;
};

int app_ubus_validation_errors(const char *method, struct json_object *params,
                                      struct json_object **errors_out)
{
    struct json_object *upstream = app_ubus_invoke(method, params);
    struct json_object *data = NULL;
    struct json_object *errors = NULL;

    if (errors_out)
        *errors_out = NULL;
    if (!upstream)
        return -1;
    if (json_object_object_get_ex(upstream, "data", &data) && data &&
        json_object_object_get_ex(data, "errors", &errors) && errors &&
        json_object_is_type(errors, json_type_array) && json_object_array_length(errors) > 0) {
        if (errors_out)
            *errors_out = json_object_get(errors);
        json_object_put(upstream);
        return 1;
    }
    json_object_put(upstream);
    return 0;
}

static void app_ubus_atfork_prepare(void)
{
    pthread_mutex_lock(&g_app_ubus_request_build_lock);
}

static void app_ubus_atfork_unlock(void)
{
    pthread_mutex_unlock(&g_app_ubus_request_build_lock);
}

void app_ubus_atfork_register(void)
{
    pthread_atfork(app_ubus_atfork_prepare, app_ubus_atfork_unlock,
                   app_ubus_atfork_unlock);
}

static int app_ubus_request_build_lock_until(const struct timespec *deadline)
{
    int rc;

    if (!deadline)
        return -1;
    do {
        rc = pthread_mutex_timedlock(&g_app_ubus_request_build_lock,
                                     deadline);
    } while (rc == EINTR);
    return rc == 0 ? 0 : -1;
}

static int app_ubus_deadline_init(struct timespec *deadline, int timeout_ms)
{
    if (!deadline)
        return -1;
    if (timeout_ms <= 0)
        timeout_ms = WEBD_UBUS_DEFAULT_TIMEOUT_MS;
    if (clock_gettime(CLOCK_REALTIME, deadline) != 0)
        return -1;
    webd_timespec_add_ms(deadline, timeout_ms);
    return 0;
}

void app_ubus_context_drop(void)
{
    if (g_app_ubus_thread_context) {
        struct ubus_context *uctx = g_app_ubus_thread_context;
        struct timespec cleanup_deadline;

        g_app_ubus_thread_context = NULL;
        if (app_ubus_deadline_init(&cleanup_deadline,
                                   WEBD_UBUS_CANCEL_GRACE_MS) == 0 &&
            app_ubus_request_build_lock_until(&cleanup_deadline) == 0) {
            ubus_free(uctx);
            pthread_mutex_unlock(&g_app_ubus_request_build_lock);
            return;
        }
        /* Never turn error cleanup into another worker black hole. The socket
         * is thread-private, so closing it is safe; the small context object is
         * reclaimed when this bounded-lifetime worker exits. */
        if (uctx->sock.fd >= 0)
            close(uctx->sock.fd);
    }
}

/* Only call from a freshly forked child. Do not take a pthread mutex or call
 * ubus_free() here: fork can inherit another thread while it owns libubus
 * state. Closing the inherited socket is async-signal-safe; the child then
 * opens its own context lazily and the inherited allocation dies at _exit(). */
void app_ubus_context_drop_in_child(void)
{
    if (g_app_ubus_thread_context && g_app_ubus_thread_context->sock.fd >= 0)
        close(g_app_ubus_thread_context->sock.fd);
    g_app_ubus_thread_context = NULL;
}

void app_ubus_context_close(void)
{
    app_ubus_context_drop();
}

static int app_ubus_transport_failed(int rc)
{
    return rc == UBUS_STATUS_CONNECTION_FAILED ||
           rc == UBUS_STATUS_SYSTEM_ERROR;
}

static struct ubus_context *app_ubus_context_get_until(
    const struct timespec *deadline)
{
    if (!g_app_ubus_thread_context) {
        if (app_ubus_request_build_lock_until(deadline) != 0)
            return NULL;
        g_app_ubus_thread_context = ubus_connect(NULL);
        pthread_mutex_unlock(&g_app_ubus_request_build_lock);
    }
    return g_app_ubus_thread_context;
}

static void ubus_invoke_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct ubus_invoke_resp *r = req->priv;
    if (!msg) return;
    char *s = blobmsg_format_json(msg, true);
    if (s) {
        r->json = json_tokener_parse(s);
        free(s);
    }
}

static void app_ubus_deadline_guard_stage(struct app_ubus_deadline_guard *guard,
                                          const char *stage)
{
    pthread_mutex_lock(&guard->lock);
    guard->stage = stage;
    pthread_mutex_unlock(&guard->lock);
}

static void *app_ubus_deadline_guard_thread(void *opaque)
{
    struct app_ubus_deadline_guard *guard = opaque;
    struct timespec grace_deadline;
    const char *stage;
    int fd = -1;
    int wait_rc = 0;
    int completed;

    pthread_mutex_lock(&guard->lock);
    while (!guard->done && wait_rc == 0)
        wait_rc = pthread_cond_timedwait(&guard->done_cv, &guard->lock,
                                         &guard->deadline);
    if (!guard->done) {
        guard->timed_out = 1;
        fd = guard->ubus_fd;
    }
    pthread_mutex_unlock(&guard->lock);
    if (fd >= 0)
        shutdown(fd, SHUT_RDWR);
    if (fd < 0)
        return NULL;

    if (clock_gettime(CLOCK_REALTIME, &grace_deadline) != 0)
        grace_deadline = guard->deadline;
    webd_timespec_add_ms(&grace_deadline, WEBD_UBUS_CANCEL_GRACE_MS);
    wait_rc = 0;
    pthread_mutex_lock(&guard->lock);
    while (!guard->done && wait_rc == 0)
        wait_rc = pthread_cond_timedwait(&guard->done_cv, &guard->lock,
                                         &grace_deadline);
    completed = guard->done;
    stage = guard->stage ? guard->stage : "connect";
    pthread_mutex_unlock(&guard->lock);
    /* This helper runs inside the persistent worker. If the request thread
     * stayed inside libubus after the socket shutdown grace period, keeping the
     * worker alive would preserve the exact black-hole that this guard exists
     * to break. The parent owns the listener and will replace this slot after
     * the worker exits. */
    if (!completed) {
        fprintf(stderr,
                "[dreamingwrt-webd] UBus call deadline exceeded stage=%s action=replace-worker\n",
                stage);
        _exit(124);
    }
    return NULL;
}

static int app_ubus_deadline_guard_start(
    struct app_ubus_deadline_guard *guard, int ubus_fd,
    const struct timespec *deadline)
{
    memset(guard, 0, sizeof(*guard));
    guard->ubus_fd = ubus_fd;
    if (!deadline)
        return -1;
    if (pthread_mutex_init(&guard->lock, NULL) != 0)
        return -1;
    if (pthread_cond_init(&guard->done_cv, NULL) != 0) {
        pthread_mutex_destroy(&guard->lock);
        return -1;
    }
    guard->deadline = *deadline;
    if (pthread_create(&guard->thread, NULL,
                       app_ubus_deadline_guard_thread, guard) != 0) {
        pthread_cond_destroy(&guard->done_cv);
        pthread_mutex_destroy(&guard->lock);
        return -1;
    }
    guard->started = 1;
    return 0;
}

static int app_ubus_deadline_guard_finish(struct app_ubus_deadline_guard *guard)
{
    int timed_out;

    if (!guard || !guard->started)
        return 1;
    pthread_mutex_lock(&guard->lock);
    guard->done = 1;
    timed_out = guard->timed_out;
    pthread_cond_broadcast(&guard->done_cv);
    pthread_mutex_unlock(&guard->lock);
    pthread_join(guard->thread, NULL);
    pthread_cond_destroy(&guard->done_cv);
    pthread_mutex_destroy(&guard->lock);
    guard->started = 0;
    return timed_out;
}

/* Optional per-call failure diagnosis so REST handlers can distinguish a
 * transport that is really unavailable (connect/lookup failed, timeout)
 * from an upstream daemon that answered and rejected the arguments.  A
 * NULL response with stage=="invoke" and a concrete ubus rc means the
 * source WAS reachable; reporting that as "source unavailable" hides the
 * true failure from operators. */
struct json_object *app_ubus_invoke_object_diag(const char *object, const char *method,
                                                       struct json_object *params, int timeout_ms,
                                                       struct app_ubus_call_diag *diag)
{
    struct json_object *result = NULL;
    struct ubus_context *uctx;
    struct blob_buf b = {};
    struct ubus_invoke_resp resp = { .json = NULL, .rc = -1 };
    struct app_ubus_deadline_guard guard;
    struct timespec call_deadline;
    struct ubus_request req;
    uint32_t id;
    int remaining_ms;
    int timed_out;
    int rc;

    if (diag) {
        diag->rc = -1;
        diag->stage = NULL;
    }
    if (!object || !object[0] || !method || !method[0]) {
        if (diag) diag->stage = "connect";
        return NULL;
    }
    if (app_ubus_deadline_init(&call_deadline, timeout_ms) != 0) {
        if (diag) {
            diag->rc = UBUS_STATUS_TIMEOUT;
            diag->stage = "connect";
        }
        return NULL;
    }
    uctx = app_ubus_context_get_until(&call_deadline);
    if (!uctx || app_ubus_deadline_guard_start(
            &guard, uctx->sock.fd, &call_deadline) != 0) {
        if (uctx)
            app_ubus_context_drop();
        if (diag) {
            diag->rc = UBUS_STATUS_TIMEOUT;
            diag->stage = "connect";
        }
        return NULL;
    }

    app_ubus_deadline_guard_stage(&guard, "lookup");
    if (app_ubus_request_build_lock_until(&guard.deadline) != 0) {
        rc = UBUS_STATUS_TIMEOUT;
        goto done;
    }
    rc = ubus_lookup_id(uctx, object, &id);
    pthread_mutex_unlock(&g_app_ubus_request_build_lock);
    if (rc != UBUS_STATUS_OK)
        goto done;
    remaining_ms = webd_timespec_remaining_ms(&guard.deadline);
    if (remaining_ms <= 0) {
        rc = UBUS_STATUS_TIMEOUT;
        goto done;
    }
    blob_buf_init(&b, 0);
    if (params) {
        const char *s = json_object_to_json_string(params);
        if (s && s[0])
            blobmsg_add_json_from_string(&b, s);
    }
    app_ubus_deadline_guard_stage(&guard, "invoke");
    if (app_ubus_request_build_lock_until(&guard.deadline) != 0) {
        rc = UBUS_STATUS_TIMEOUT;
        blob_buf_free(&b);
        goto done;
    }
    rc = ubus_invoke_async(uctx, id, method, b.head, &req);
    pthread_mutex_unlock(&g_app_ubus_request_build_lock);
    blob_buf_free(&b);
    if (rc != UBUS_STATUS_OK)
        goto done;
    req.data_cb = ubus_invoke_cb;
    req.priv = &resp;
    remaining_ms = webd_timespec_remaining_ms(&guard.deadline);
    if (remaining_ms <= 0) {
        ubus_abort_request(uctx, &req);
        rc = UBUS_STATUS_TIMEOUT;
        goto done;
    }
    rc = ubus_complete_request(uctx, &req, remaining_ms);
done:
    timed_out = app_ubus_deadline_guard_finish(&guard);
    if (timed_out)
        rc = UBUS_STATUS_TIMEOUT;
    if (rc != UBUS_STATUS_OK) {
        if (resp.json)
            json_object_put(resp.json);
        if (timed_out || app_ubus_transport_failed(rc))
            app_ubus_context_drop();
        if (diag) {
            diag->rc = rc;
            diag->stage = guard.stage ? guard.stage : "connect";
        }
        return NULL;
    }
    result = resp.json;
    return result;
}

struct json_object *app_ubus_invoke_object_timeout(const char *object, const char *method,
                                                         struct json_object *params, int timeout_ms)
{
    return app_ubus_invoke_object_diag(object, method, params, timeout_ms, NULL);
}

struct json_object *app_ubus_invoke_object(const char *object, const char *method, struct json_object *params)
{
    return app_ubus_invoke_object_timeout(object, method, params, 2000);
}

struct json_object *app_ubus_invoke_timeout(const char *method, struct json_object *params,
                                                   int timeout_ms)
{
    return app_ubus_invoke_object_timeout("dreamingwrt", method, params, timeout_ms);
}

struct json_object *app_ubus_invoke(const char *method, struct json_object *params)
{
    return app_ubus_invoke_object("dreamingwrt", method, params);
}

int app_ubus_object_available(const char *object)
{
    struct ubus_context *uctx;
    struct app_ubus_deadline_guard guard;
    struct timespec call_deadline;
    uint32_t id;
    int rc;
    int timed_out;

    if (!object || !object[0])
        return 0;
    if (app_ubus_deadline_init(&call_deadline,
                               WEBD_UBUS_DEFAULT_TIMEOUT_MS) != 0)
        return 0;
    uctx = app_ubus_context_get_until(&call_deadline);
    if (!uctx || app_ubus_deadline_guard_start(
            &guard, uctx->sock.fd, &call_deadline) != 0) {
        if (uctx)
            app_ubus_context_drop();
        return 0;
    }
    app_ubus_deadline_guard_stage(&guard, "lookup");
    if (app_ubus_request_build_lock_until(&guard.deadline) != 0) {
        rc = UBUS_STATUS_TIMEOUT;
        goto done;
    }
    rc = ubus_lookup_id(uctx, object, &id);
    pthread_mutex_unlock(&g_app_ubus_request_build_lock);
done:
    timed_out = app_ubus_deadline_guard_finish(&guard);
    if (timed_out || app_ubus_transport_failed(rc))
        app_ubus_context_drop();
    return !timed_out && rc == UBUS_STATUS_OK;
}

struct json_object *app_ubus_or_error(const char *method, struct json_object *params)
{
    /*
     * Failures here are not interchangeable, and reporting them as one code
     * cost a full ubus-level investigation to disprove a single sentence.
     *
     * Every failure used to answer `backend_starting_or_unavailable` with
     * `retryable: true`. When the daemon is up but never registered the
     * method, that sentence is false in the worst way: the client waits out a
     * state that will never arrive. `/api/v1/system/advanced/net-tuning`
     * answered exactly that for a method missing from the build, and settling
     * it needed `ubus -v list dreamingwrt`.
     *
     * The invoke stage returning METHOD_NOT_FOUND means the object resolved
     * and the method did not, so that case becomes `method_not_registered`
     * with `retryable: false`; the lookup stage keeps the old "starting"
     * reading, which is true there. Timeouts stay retryable: the method
     * exists and answered late.
     */
    struct app_ubus_call_diag diag = { .rc = -1, .stage = NULL };
    struct json_object *resp = app_ubus_invoke_object_diag("dreamingwrt", method,
                                                          params, 2000, &diag);
    struct json_object *data;
    int method_missing;

    if (resp)
        return resp;
    method_missing = diag.stage && !strcmp(diag.stage, "invoke") &&
                     diag.rc == UBUS_STATUS_METHOD_NOT_FOUND;
    data = json_object_new_object();
    json_object_object_add(data, "ok", json_object_new_boolean(0));
    json_object_object_add(data, "error",
                           json_object_new_string(method_missing ?
                               "method_not_registered" : "source_unavailable"));
    json_object_object_add(data, "reason",
                           json_object_new_string(method_missing ?
                               "ubus_method_not_registered" :
                               "backend_starting_or_unavailable"));
    json_object_object_add(data, "message",
                           json_object_new_string(method_missing ?
                               "dreamingwrt is running but this build did not register the method; retrying will not help" :
                               "dreamingwrt ubus source is not available or did not answer in time"));
    json_object_object_add(data, "ubus_object", json_object_new_string("dreamingwrt"));
    json_object_object_add(data, "ubus_method", json_object_new_string(method ? method : ""));
    json_object_object_add(data, "retryable", json_object_new_boolean(method_missing ? 0 : 1));
    if (diag.stage)
        json_object_object_add(data, "failed_stage", json_object_new_string(diag.stage));
    if (diag.rc >= 0)
        json_object_object_add(data, "ubus_status", json_object_new_int(diag.rc));
    json_object_object_add(data, "ts", json_object_new_int64(now_s()));
    return app_jmx_response_data(APP_API_CODE_ERROR, data);
}

struct json_object *app_ubus_object_or_error(const char *object, const char *method, struct json_object *params)
{
    struct json_object *resp = app_ubus_invoke_object(object, method, params);
    char dependency[128];
    char source[128];

    if (resp)
        return resp;
    snprintf(dependency, sizeof(dependency), "%s %s", object ? object : "", method ? method : "");
    snprintf(source, sizeof(source), "webd.%s", object ? object : "ubus");
    return webd_error("source_unavailable", "ubus source is not available", dependency, source);
}

/*
 * Same as app_ubus_object_or_error(), but with an explicit budget and a
 * timeout that does not lie.
 *
 * app_ubus_object_or_error() collapses "no ubus socket", "object not
 * registered" and "the call did not finish in time" into one
 * `source_unavailable`, which sent operators looking for a dead daemon when
 * the daemon was healthy and merely slow.  The stage/rc that
 * app_ubus_invoke_object_diag() already reports is enough to tell them apart:
 * UBUS_STATUS_TIMEOUT at the invoke stage becomes `dependency_timeout` with
 * HTTP 504, so the UI can say "still applying, refresh shortly" instead of
 * reporting the backend as down.
 */
struct json_object *app_ubus_object_or_error_timeout(const char *object,
                                                            const char *method,
                                                            struct json_object *params,
                                                            int timeout_ms,
                                                            int *http_status)
{
    struct app_ubus_call_diag diag = { .rc = -1, .stage = NULL };
    struct json_object *resp;
    char dependency[128];
    char source[128];

    resp = app_ubus_invoke_object_diag(object, method, params,
                                       timeout_ms > 0 ? timeout_ms : 2000,
                                       &diag);
    if (resp)
        return resp;
    snprintf(dependency, sizeof(dependency), "%s %s",
             object ? object : "", method ? method : "");
    snprintf(source, sizeof(source), "webd.%s", object ? object : "ubus");

    if (diag.stage && !strcmp(diag.stage, "invoke") &&
        diag.rc == UBUS_STATUS_TIMEOUT) {
        if (http_status)
            *http_status = 504;
        return webd_error("dependency_timeout",
                          "backend accepted the request but did not answer in time; "
                          "it may still be applying",
                          dependency, source);
    }
    if (http_status)
        *http_status = 503;
    return webd_error("source_unavailable", "ubus source is not available",
                      dependency, source);
}

/* Same call, but a method the daemon never registered is reported as such
 * instead of as an unavailable source. The two need different HTTP statuses:
 * a 503 tells the client to retry, while a route wired to a method that does
 * not exist will never succeed and must read as "not implemented" so the UI
 * can say so rather than blaming the network. */
struct json_object *app_ubus_route_or_error(const char *object,
                                                   const char *method,
                                                   struct json_object *params,
                                                   int timeout_ms,
                                                   int *http_status)
{
    struct app_ubus_call_diag diag = { .rc = -1, .stage = NULL };
    struct json_object *resp;
    char dependency[128];
    char source[128];

    resp = app_ubus_invoke_object_diag(object, method, params,
                                       timeout_ms > 0 ? timeout_ms : 2000,
                                       &diag);
    if (resp) {
        if (http_status)
            *http_status = app_jmx_response_http_status(resp, *http_status);
        return resp;
    }
    snprintf(dependency, sizeof(dependency), "%s %s",
             object ? object : "", method ? method : "");
    snprintf(source, sizeof(source), "webd.%s", object ? object : "ubus");

    /* ubus reports both a missing object and a missing method as NOT_FOUND at
     * the invoke stage; the object resolved here, so the method is missing. */
    if (diag.stage && !strcmp(diag.stage, "invoke") &&
        diag.rc == UBUS_STATUS_METHOD_NOT_FOUND) {
        if (http_status)
            *http_status = 501;
        return webd_error("method_not_registered",
                          "backend method is not registered on this build",
                          dependency, source);
    }
    if (diag.stage && !strcmp(diag.stage, "lookup")) {
        if (http_status)
            *http_status = 503;
        return webd_error("source_unavailable",
                          "backend daemon is not registered on ubus",
                          dependency, source);
    }
    if (http_status)
        *http_status = 503;
    return webd_error("source_unavailable", "ubus source is not available",
                      dependency, source);
}

/*
 * Core-object call that keeps app_response_status()'s error mapping but stops
 * reporting a missing method as a generic failure.
 *
 * app_ubus_invoke() returns NULL for every kind of failure, and the dispatcher
 * turns NULL into 500 "backend returned no JSON response". For flash routes
 * that reads as "the server broke" when the truth is "this build never wired
 * the method up", which is exactly the ambiguity that made an implemented
 * factory reset look absent. app_ubus_route_or_error() solves the same problem
 * but re-maps success payloads through a coarser status table, so these routes
 * keep their own mapping and only borrow the diagnosis.
 */
struct json_object *app_ubus_core_route_source(const char *method,
                                               struct json_object *params,
                                               int timeout_ms,
                                               int *http_status,
                                               const char *source)
{
    struct app_ubus_call_diag diag = { .rc = -1, .stage = NULL };
    struct json_object *resp;
    char dependency[128];

    if (!source || !source[0])
        source = "webd.ubus";
    resp = app_ubus_invoke_object_diag("dreamingwrt", method, params,
                                       timeout_ms > 0 ? timeout_ms : 2000,
                                       &diag);
    if (resp) {
        if (http_status)
            *http_status = app_response_status(resp, *http_status);
        return resp;
    }
    snprintf(dependency, sizeof(dependency), "dreamingwrt %s",
             method ? method : "");
    /* ubus reports a missing object and a missing method alike as NOT_FOUND;
     * reaching the invoke stage means the object resolved, so it is the method. */
    if (diag.stage && !strcmp(diag.stage, "invoke") &&
        diag.rc == UBUS_STATUS_METHOD_NOT_FOUND) {
        if (http_status)
            *http_status = 501;
        return webd_error("method_not_registered",
                          "backend method is not registered on this build",
                          dependency, source);
    }
    /*
     * A call that reached the invoke stage and then ran out of budget is a slow
     * handler, not an absent daemon.  Reporting it as `source_unavailable` is
     * what made a healthy core look dead: `wifi_config_apply` legitimately
     * spends seconds waiting on the UCI and beacon readback, and the caller was
     * told "dreamingwrt ubus source is not available or did not answer in time"
     * while the very same call succeeded from the shell.  504 keeps the two
     * apart so the UI can say "still applying" instead of blaming the backend.
     */
    if (diag.stage && !strcmp(diag.stage, "invoke") &&
        diag.rc == UBUS_STATUS_TIMEOUT) {
        if (http_status)
            *http_status = 504;
        return webd_error("dependency_timeout",
                          "backend accepted the request but did not answer in "
                          "time; it may still be applying",
                          dependency, source);
    }
    if (http_status)
        *http_status = 503;
    return webd_error("source_unavailable",
                      diag.stage && !strcmp(diag.stage, "lookup") ?
                          "backend daemon is not registered on ubus" :
                          "ubus source is not available",
                      dependency, source);
}

struct json_object *app_ubus_core_route(const char *method,
                                               struct json_object *params,
                                               int timeout_ms,
                                               int *http_status)
{
    return app_ubus_core_route_source(method, params, timeout_ms, http_status,
                                      "webd.flash");
}

int app_ubus_response_ok(struct json_object *upstream)
{
    struct json_object *data = NULL;
    struct json_object *ok_obj = NULL;
    struct json_object *code_obj = NULL;

    if (!upstream)
        return 0;
    if (json_object_object_get_ex(upstream, "data", &data) && data &&
        json_object_object_get_ex(data, "ok", &ok_obj) && ok_obj)
        return json_object_get_boolean(ok_obj);
    if (json_object_object_get_ex(upstream, "ok", &ok_obj) && ok_obj)
        return json_object_get_boolean(ok_obj);
    if (json_object_object_get_ex(upstream, "code", &code_obj) && code_obj)
        return json_object_get_int(code_obj) == APP_API_CODE_SUCCESS;
    /* ubus methods may return their data object directly, without the JMX
     * code/data envelope. A non-null object with no explicit failure marker
     * is therefore a successful response. */
    return json_object_is_type(upstream, json_type_object);
}

const char *app_ubus_response_error_code(struct json_object *upstream)
{
    struct json_object *data = NULL;
    struct json_object *error = NULL;
    struct json_object *code = NULL;

    if (upstream && json_object_object_get_ex(upstream, "data", &data) && data &&
        json_object_object_get_ex(data, "error", &error) && error &&
        json_object_is_type(error, json_type_string))
        return json_object_get_string(error);
    if (upstream && json_object_object_get_ex(upstream, "error", &error) && error) {
        if (json_object_is_type(error, json_type_string))
            return json_object_get_string(error);
        if (json_object_is_type(error, json_type_object) &&
            json_object_object_get_ex(error, "code", &code) && code &&
            json_object_is_type(code, json_type_string))
            return json_object_get_string(code);
    }
    return "backend_rejected";
}

struct json_object *app_ubus_ok_only(const char *method, struct json_object *params)
{
    struct json_object *upstream = app_ubus_or_error(method, params);
    struct json_object *resp = json_object_new_object();
    int ok = app_ubus_response_ok(upstream);

    if (!ok && upstream) {
        json_object_put(resp);
        return upstream;
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    if (upstream)
        json_object_put(upstream);
    return resp;
}

struct json_object *app_ubus_ai_ok_envelope(const char *method, struct json_object *params)
{
    struct json_object *upstream = app_ubus_or_error(method, params);
    int ok = app_ubus_response_ok(upstream);
    struct json_object *resp = NULL;

    if (upstream) {
        resp = ai_envelope(upstream, ok ? 200 : 400);
    } else {
        struct json_object *data = json_object_new_object();

        json_object_object_add(data, "ok", json_object_new_boolean(0));
        resp = ai_envelope(app_jmx_response_data(APP_API_CODE_ERROR, data), 400);
    }
    return resp;
}

struct json_object *app_ubus_data_or_error(const char *method, struct json_object *params)
{
    struct json_object *upstream = app_ubus_or_error(method, params);
    struct json_object *code_obj = NULL;
    struct json_object *data_obj = NULL;

    if (!upstream)
        return app_jmx_response_data(APP_API_CODE_ERROR, NULL);

    if (json_object_object_get_ex(upstream, "code", &code_obj) && code_obj &&
        json_object_get_int(code_obj) == APP_API_CODE_SUCCESS &&
        json_object_object_get_ex(upstream, "data", &data_obj) && data_obj) {
        struct json_object *out = json_object_get(data_obj);
        json_object_put(upstream);
        return out;
    }

    return upstream;
}

int app_ubus_call_ok(const char *method, struct json_object *params)
{
    struct json_object *upstream = app_ubus_or_error(method, params);
    int ok = app_ubus_response_ok(upstream);

    if (upstream)
        json_object_put(upstream);
    return ok;
}

struct json_object *app_routed_call(const char *method, struct json_object *params)
{
    struct json_object *resp = app_ubus_invoke_object_timeout(
        "dreamingwrt.routed", method, params, 8000);

    if (resp)
        return resp;
    return webd_error("source_unavailable", "dreamingwrt-routed is not available",
                      method ? method : "", "webd.routing");
}

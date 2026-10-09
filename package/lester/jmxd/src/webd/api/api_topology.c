// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../jmx_app_cache.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_topology.h"
#include "api_ubus.h"
#include "api_util.h"

#define WEBD_TOPOLOGY_TTL_SEC 2
#define WEBD_TOPOLOGY_STALE_SEC 30
#define WEBD_TOPOLOGY_TIMEOUT_MS 3000
#define WEBD_TOPOLOGY_INFRA_CACHE_PATH "/tmp/dreamingwrt/topology-infrastructure.json"
#define WEBD_TOPOLOGY_INFRA_LOCK_PATH "/tmp/dreamingwrt/topology-infrastructure.lock"
#define WEBD_TOPOLOGY_INFRA_CACHE_MAX_BYTES (8U * 1024U * 1024U)

enum {
    WEBD_TOPOLOGY_HISTORY_NONE = 0,
    WEBD_TOPOLOGY_HISTORY_TIMELINE,
    WEBD_TOPOLOGY_HISTORY_TIMESTAMPS,
    WEBD_TOPOLOGY_HISTORY_AT
};

static int webd_is_unifi_topology_path(const char *path)
{
    static const char prefix[] = "/v2/api/site/";
    const char *site;
    const char *suffix;

    if (!path || strncmp(path, prefix, sizeof(prefix) - 1) != 0)
        return 0;
    site = path + sizeof(prefix) - 1;
    suffix = strstr(site, "/topology");
    return suffix && suffix != site && strcmp(suffix, "/topology") == 0;
}

static int webd_is_unifi_infrastructure_path(const char *path)
{
    static const char prefix[] = "/v2/api/site/";
    const char *site;
    const char *suffix;

    if (!path || strncmp(path, prefix, sizeof(prefix) - 1) != 0)
        return 0;
    site = path + sizeof(prefix) - 1;
    suffix = strstr(site, "/infrastructure");
    return suffix && suffix != site && strcmp(suffix, "/infrastructure") == 0;
}

static int webd_parse_epoch_ms(const char *s, int64_t *out)
{
    char *endp = NULL;
    unsigned long long value;
    const char *p;

    if (out)
        *out = 0;
    if (!s || !s[0] || !out)
        return 0;
    for (p = s; *p; p++)
        if (!isdigit((unsigned char)*p))
            return 0;
    errno = 0;
    value = strtoull(s, &endp, 10);
    if (errno || !endp || *endp || value == 0 || value > INT64_MAX)
        return 0;
    *out = (int64_t)value;
    return 1;
}

static int webd_topology_history_parse(const char *path, int *kind,
                                       int64_t *timestamp_ms,
                                       int *timestamp_valid)
{
    static const char local_prefix[] = "/api/v1/topology/infrastructure/history/";
    static const char unifi_prefix[] = "/v2/api/site/";
    static const char marker[] = "/infrastructure/history/";
    const char *tail = NULL;
    const char *site = NULL;
    const char *found = NULL;

    if (kind)
        *kind = WEBD_TOPOLOGY_HISTORY_NONE;
    if (timestamp_ms)
        *timestamp_ms = 0;
    if (timestamp_valid)
        *timestamp_valid = 1;
    if (!path)
        return 0;
    if (!strncmp(path, local_prefix, sizeof(local_prefix) - 1)) {
        tail = path + sizeof(local_prefix) - 1;
    } else if (!strncmp(path, unifi_prefix, sizeof(unifi_prefix) - 1)) {
        site = path + sizeof(unifi_prefix) - 1;
        found = strstr(site, marker);
        if (!found || found == site)
            return 0;
        tail = found + sizeof(marker) - 1;
    } else {
        return 0;
    }
    if (!strcmp(tail, "timeline")) {
        if (kind)
            *kind = WEBD_TOPOLOGY_HISTORY_TIMELINE;
        return 1;
    }
    if (!strcmp(tail, "timestamps")) {
        if (kind)
            *kind = WEBD_TOPOLOGY_HISTORY_TIMESTAMPS;
        return 1;
    }
    if (!strncmp(tail, "at/", 3)) {
        int valid = webd_parse_epoch_ms(tail + 3, timestamp_ms);

        if (kind)
            *kind = WEBD_TOPOLOGY_HISTORY_AT;
        if (timestamp_valid)
            *timestamp_valid = valid;
        return 1;
    }
    return 0;
}

static int webd_topology_history_path(const char *path)
{
    return webd_topology_history_parse(path, NULL, NULL, NULL);
}

static int webd_is_unifi_digital_twin_layout_path(const char *path)
{
    static const char prefix[] = "/v2/api/site/";
    const char *site;
    const char *suffix;

    if (!path || strncmp(path, prefix, sizeof(prefix) - 1) != 0)
        return 0;
    site = path + sizeof(prefix) - 1;
    suffix = strstr(site, "/digital-twin/layout");
    return suffix && suffix != site &&
           strcmp(suffix, "/digital-twin/layout") == 0;
}

static struct json_object *webd_topology_history_response(
    const struct http_req *req, int *status)
{
    struct json_object *params = json_object_new_object();
    struct json_object *upstream;
    char value[64];
    const char *method;
    const char *source;
    int64_t parsed;
    int64_t timestamp_ms = 0;
    int64_t start_ms = 0;
    int64_t end_ms = 0;
    int kind = WEBD_TOPOLOGY_HISTORY_NONE;
    int timestamp_valid = 1;
    int have_start = 0;
    int have_end = 0;

    if (!req || !webd_topology_history_parse(req->path, &kind, &timestamp_ms,
                                              &timestamp_valid)) {
        if (params)
            json_object_put(params);
        if (status)
            *status = 404;
        return webd_error("not_found", "topology history route not found",
                          req ? req->path : "", "webd.topology_history");
    }
    if (kind == WEBD_TOPOLOGY_HISTORY_AT && !timestamp_valid) {
        if (params)
            json_object_put(params);
        if (status)
            *status = 400;
        return webd_error(
            "invalid_timestamp",
            "historical timestamp must be a positive epoch timestamp in milliseconds",
            "timestamp", "webd.topology_history");
    }
    if (!params) {
        if (status)
            *status = 500;
        return webd_error("allocation_failed",
                          "topology history request allocation failed",
                          "history", "webd.topology_history");
    }
    if (kind == WEBD_TOPOLOGY_HISTORY_AT) {
        method = "topology_infrastructure_history_at";
        source = "jmxd.topology_infrastructure_history_at";
        json_object_object_add(params, "timestamp",
                               json_object_new_int64(timestamp_ms));
    } else {
        method = kind == WEBD_TOPOLOGY_HISTORY_TIMELINE ?
                 "topology_infrastructure_history_timeline" :
                 "topology_infrastructure_history_timestamps";
        source = kind == WEBD_TOPOLOGY_HISTORY_TIMELINE ?
                 "jmxd.topology_infrastructure_history_timeline" :
                 "jmxd.topology_infrastructure_history_timestamps";
        if (webd_query_get(req->query, "start", value, sizeof(value))) {
            if (!webd_parse_epoch_ms(value, &parsed)) {
                json_object_put(params);
                if (status)
                    *status = 400;
                return webd_error(
                    "invalid_start",
                    "start must be a positive epoch timestamp in milliseconds",
                    "start", "webd.topology_history");
            }
            start_ms = parsed;
            have_start = 1;
            json_object_object_add(params, "start",
                                   json_object_new_int64(parsed));
        }
        if (webd_query_get(req->query, "end", value, sizeof(value))) {
            if (!webd_parse_epoch_ms(value, &parsed)) {
                json_object_put(params);
                if (status)
                    *status = 400;
                return webd_error(
                    "invalid_end",
                    "end must be a positive epoch timestamp in milliseconds",
                    "end", "webd.topology_history");
            }
            end_ms = parsed;
            have_end = 1;
            json_object_object_add(params, "end", json_object_new_int64(parsed));
        }
        if (have_start && have_end && start_ms > end_ms) {
            json_object_put(params);
            if (status)
                *status = 400;
            return webd_error("invalid_time_range",
                              "start must not be greater than end",
                              "start,end", "webd.topology_history");
        }
    }
    upstream = app_ubus_invoke_timeout(method, params, 3000);
    json_object_put(params);
    if (!upstream) {
        if (status)
            *status = 503;
        return webd_error("source_unavailable",
                          "topology history source is not available",
                          method, source);
    }
    {
        struct json_object *available = NULL;
        struct json_object *reason_obj = NULL;

        if (json_object_object_get_ex(upstream, "available", &available) &&
            available && !json_object_get_boolean(available)) {
            const char *reason = "history_source_unavailable";
            const char *message = "topology history source is not available";
            int error_status = 503;
            struct json_object *error;

            if (json_object_object_get_ex(upstream, "reason", &reason_obj) &&
                reason_obj && json_object_get_string(reason_obj))
                reason = json_object_get_string(reason_obj);
            if (!strcmp(reason, "no_historical_snapshot")) {
                error_status = 404;
                message = "no historical infrastructure snapshot is available";
            } else if (!strcmp(reason, "invalid_timestamp") ||
                       !strcmp(reason, "invalid_time_range")) {
                error_status = 400;
                message = "invalid topology history time range";
            }
            error = webd_error(reason, message, reason, source);
            json_object_put(upstream);
            if (status)
                *status = error_status;
            return error;
        }
    }
    if (status)
        *status = 200;
    return webd_envelope(upstream, source);
}

static struct json_object *webd_cached_ubus_envelope_response(
    const char *cache_key, const char *method, const char *source,
    const char *error_message, const char *dependency,
    const char *stale_reason, int fresh_sec, int stale_sec, int timeout_ms,
    int *status)
{
    int cache_age_ms = 0;
    int cache_stale = 0;
    struct json_object *cached;
    struct json_object *data;
    struct json_object *resp;

    cached = jmx_cache_get_allow_stale(cache_key, stale_sec, &cache_age_ms,
                                       &cache_stale);
    if (cached && !cache_stale)
        return cached;
    data = app_ubus_invoke_timeout(method, NULL, timeout_ms);
    if (data) {
        resp = webd_envelope(data, source);
        if (resp)
            jmx_cache_put_with_stale(cache_key, resp, fresh_sec, stale_sec);
        if (cached)
            json_object_put(cached);
        return resp;
    }
    if (cached) {
        resp = webd_json_clone(cached);
        json_object_put(cached);
        if (resp) {
            webd_mark_cached_response_stale(resp, cache_age_ms, stale_reason);
            return resp;
        }
    }
    if (status)
        *status = 503;
    return webd_error("source_unavailable", error_message, dependency, "webd");
}

static int webd_topology_infrastructure_envelope_valid(struct json_object *resp)
{
    struct json_object *data = NULL;
    struct json_object *infrastructure = NULL;

    return resp && json_object_is_type(resp, json_type_object) &&
           app_nc_json_bool(resp, "ok", 0) &&
           json_object_object_get_ex(resp, "data", &data) && data &&
           json_object_is_type(data, json_type_object) &&
           json_object_object_get_ex(data, "infrastructure", &infrastructure) &&
           infrastructure && json_object_is_type(infrastructure, json_type_object);
}

static struct json_object *webd_topology_infrastructure_shared_cache_read(
    int max_age_sec, int *age_ms)
{
    struct stat st;
    int64_t age;
    struct json_object *resp;

    if (age_ms)
        *age_ms = 0;
    if (max_age_sec <= 0 || stat(WEBD_TOPOLOGY_INFRA_CACHE_PATH, &st) != 0 ||
        !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        st.st_size > (off_t)WEBD_TOPOLOGY_INFRA_CACHE_MAX_BYTES)
        return NULL;
    age = webd_now_ms() - webd_ws_file_mtime_ms(&st);
    if (age < 0 || age >= (int64_t)max_age_sec * 1000)
        return NULL;
    resp = json_object_from_file(WEBD_TOPOLOGY_INFRA_CACHE_PATH);
    if (!webd_topology_infrastructure_envelope_valid(resp)) {
        if (resp)
            json_object_put(resp);
        return NULL;
    }
    if (age_ms)
        *age_ms = (int)age;
    return resp;
}

static void webd_topology_infrastructure_shared_cache_write(
    struct json_object *resp)
{
    char tmp[256];
    const char *json;
    int fd;

    if (!webd_topology_infrastructure_envelope_valid(resp))
        return;
    if (mkdir("/tmp/dreamingwrt", 0755) != 0 && errno != EEXIST)
        return;
    if (snprintf(tmp, sizeof(tmp), "%s.tmp.%ld",
                 WEBD_TOPOLOGY_INFRA_CACHE_PATH, (long)getpid()) >=
        (int)sizeof(tmp))
        return;
    json = json_object_to_json_string_ext(resp, JSON_C_TO_STRING_PLAIN);
    if (!json || strlen(json) > WEBD_TOPOLOGY_INFRA_CACHE_MAX_BYTES)
        return;
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return;
    if (webd_write_all(fd, json, strlen(json)) != 0 || close(fd) != 0) {
        unlink(tmp);
        return;
    }
    if (rename(tmp, WEBD_TOPOLOGY_INFRA_CACHE_PATH) != 0)
        unlink(tmp);
}

void webd_topology_infrastructure_cache_invalidate(void)
{
    int lock_fd = -1;

    if (mkdir("/tmp/dreamingwrt", 0755) == 0 || errno == EEXIST)
        lock_fd = open(WEBD_TOPOLOGY_INFRA_LOCK_PATH,
                       O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock_fd >= 0 && flock(lock_fd, LOCK_EX) != 0) {
        close(lock_fd);
        lock_fd = -1;
    }
    jmx_cache_invalidate("topology_infrastructure");
    unlink(WEBD_TOPOLOGY_INFRA_CACHE_PATH);
    if (lock_fd >= 0) {
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
    }
}

struct json_object *webd_topology_infrastructure_cached_response(
    int *status)
{
    struct json_object *cached = NULL;
    struct json_object *data = NULL;
    struct json_object *resp = NULL;
    int cache_age_ms = 0;
    int lock_fd = -1;
    int lock_held = 0;

    cached = webd_topology_infrastructure_shared_cache_read(
        WEBD_TOPOLOGY_STALE_SEC, &cache_age_ms);
    if (cached && cache_age_ms < WEBD_TOPOLOGY_TTL_SEC * 1000)
        return cached;
    if (mkdir("/tmp/dreamingwrt", 0755) == 0 || errno == EEXIST)
        lock_fd = open(WEBD_TOPOLOGY_INFRA_LOCK_PATH,
                       O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock_fd >= 0 && flock(lock_fd, LOCK_EX) == 0) {
        struct json_object *fresh;
        int fresh_age_ms = 0;

        lock_held = 1;
        fresh = webd_topology_infrastructure_shared_cache_read(
            WEBD_TOPOLOGY_STALE_SEC, &fresh_age_ms);
        if (fresh && fresh_age_ms < WEBD_TOPOLOGY_TTL_SEC * 1000) {
            if (cached)
                json_object_put(cached);
            flock(lock_fd, LOCK_UN);
            close(lock_fd);
            return fresh;
        }
        if (fresh) {
            if (cached)
                json_object_put(cached);
            cached = fresh;
            cache_age_ms = fresh_age_ms;
        }
    }
    data = app_ubus_invoke_timeout("topology_infrastructure", NULL,
                                   WEBD_TOPOLOGY_TIMEOUT_MS);
    if (data) {
        resp = webd_envelope(data, "jmxd.topology_infrastructure");
        if (webd_topology_infrastructure_envelope_valid(resp)) {
            webd_topology_infrastructure_shared_cache_write(resp);
            jmx_cache_put_with_stale("topology_infrastructure", resp,
                                     WEBD_TOPOLOGY_TTL_SEC,
                                     WEBD_TOPOLOGY_STALE_SEC);
            if (cached)
                json_object_put(cached);
            cached = NULL;
        } else {
            if (resp)
                json_object_put(resp);
            resp = NULL;
        }
    }
    if (!resp && cached) {
        resp = cached;
        cached = NULL;
        webd_mark_cached_response_stale(
            resp, cache_age_ms,
            data ? "topology_infrastructure_invalid_response_stale_cache" :
                   "topology_infrastructure_timeout_stale_cache");
    } else if (!resp) {
        if (status)
            *status = data ? 502 : 503;
        resp = webd_error(
            data ? "invalid_source_response" : "source_unavailable",
            data ? "topology infrastructure source returned an invalid contract" :
                   "topology infrastructure source is not available",
            "dreamingwrt topology_infrastructure", "webd");
    }
    if (lock_fd >= 0 && lock_held)
        flock(lock_fd, LOCK_UN);
    if (lock_fd >= 0)
        close(lock_fd);
    if (cached)
        json_object_put(cached);
    return resp;
}

static struct json_object *topology_overview(struct jmx_api_ctx *ctx)
{
    return webd_cached_ubus_envelope_response(
        "topology_unifi", "topology_unifi", "jmxd.topology_unifi",
        "topology source is not available", "dreamingwrt topology_unifi",
        "topology_timeout_stale_cache", WEBD_TOPOLOGY_TTL_SEC,
        WEBD_TOPOLOGY_STALE_SEC, WEBD_TOPOLOGY_TIMEOUT_MS, &ctx->status);
}

static struct json_object *topology_flow(struct jmx_api_ctx *ctx)
{
    return webd_cached_ubus_envelope_response(
        "topology_flow", "topology_flow", "jmxd.topology_flow",
        "topology flow source is not available", "dreamingwrt topology_flow",
        "topology_flow_timeout_stale_cache", WEBD_TOPOLOGY_TTL_SEC,
        WEBD_TOPOLOGY_STALE_SEC, WEBD_TOPOLOGY_TIMEOUT_MS, &ctx->status);
}

static struct json_object *topology_history(struct jmx_api_ctx *ctx)
{
    return webd_topology_history_response(ctx->req, &ctx->status);
}

static struct json_object *topology_infrastructure(struct jmx_api_ctx *ctx)
{
    return webd_topology_infrastructure_cached_response(&ctx->status);
}

static struct json_object *topology_digital_twin_layout(struct jmx_api_ctx *ctx)
{
    struct json_object *layout = json_object_new_object();
    struct json_object *diagnostics = json_object_new_object();

    (void)ctx;
    json_object_object_add(layout, "available", json_object_new_boolean(0));
    json_object_object_add(layout, "layout", json_object_new_array());
    json_object_object_add(layout, "nodes", json_object_new_array());
    json_object_object_add(layout, "edges", json_object_new_array());
    json_object_object_add(
        layout, "reason",
        json_object_new_string("digital_twin_layout_source_unavailable"));
    json_object_object_add(diagnostics, "complete", json_object_new_boolean(0));
    json_object_object_add(
        diagnostics, "missing",
        json_object_new_string("real_switch_layout_and_port_coordinates"));
    json_object_object_add(layout, "diagnostics", diagnostics);
    return webd_envelope(layout, "webd.unifi_digital_twin_layout_empty");
}

const struct jmx_api_route topology_api_routes[] = {
    JMX_API_PREDICATE_ROUTE(331, "/api/v1/topology", "GET", JMX_API_EXACT, webd_is_unifi_topology_path, topology_overview),
    JMX_API_ROUTE(332, "/api/v1/topology/flow", "GET", JMX_API_EXACT, topology_flow),
    JMX_API_PREDICATE_ROUTE(333, "[helper:webd_topology_history_path]", "GET", JMX_API_EXACT, webd_topology_history_path, topology_history),
    JMX_API_PREDICATE_ROUTE(334, "/api/v1/topology/infrastructure", "GET", JMX_API_EXACT, webd_is_unifi_infrastructure_path, topology_infrastructure),
    JMX_API_PREDICATE_ROUTE(335, "[helper:webd_is_unifi_digital_twin_layout_path]", "GET", JMX_API_EXACT, webd_is_unifi_digital_twin_layout_path, topology_digital_twin_layout),
    JMX_API_ROUTE_END,
};

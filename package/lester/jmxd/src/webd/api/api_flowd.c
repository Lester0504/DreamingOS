// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * flowd control-plane REST adapters (Phase 6E). The /api/v1/flowd/* surface is
 * the GeoIP / country-routing / QoS / rule / runtime control plane; almost every
 * route is a thin proxy onto the dreamingwrt.flowd ubus object, with three richer
 * readers (status, wan-health, runtime) that fall back to core runtime sources
 * when the flowd worker is unregistered. Bodies are moved verbatim from
 * jmx_app_api.c; no second implementation remains there.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>

#include <json-c/json.h>

#include "api_flowd.h"
#include "api_flowd_internal.h"
#include "api_dashboard.h"
#include "api_error.h"
#include "api_json.h"
#include "api_shared_json.h"
#include "api_ubus.h"
#include "api_util.h"

/* Single-flight shared-cache paths and windows for the status reader. Private to
 * this module: the only reader of these was webd_flowd_status_response(). */
#define WEBD_FLOWD_STATUS_SHARED_CACHE_PATH "/tmp/dreamingwrt/flowd-status.json"
#define WEBD_FLOWD_STATUS_SHARED_LOCK_PATH "/tmp/dreamingwrt/flowd-status.lock"
#define WEBD_FLOWD_STATUS_SHARED_FRESH_MS 1000
#define WEBD_FLOWD_STATUS_SHARED_STALE_MS 5000
#define WEBD_FLOWD_STATUS_SHARED_MAX_BYTES (128U * 1024U)

static int webd_flowd_runtime_empty(struct json_object *resp);
static int webd_flowd_wan_health_empty(struct json_object *resp);
static void webd_flowd_status_mark_cache(struct json_object *resp, int age_ms,
                                         int stale, const char *reason);
static struct json_object *webd_flowd_status_response(int *http_status);
static int webd_runtime_entry_is_configured_wan(struct json_object *entry,
                                                struct json_object *configured_wans);
static struct json_object *webd_filter_runtime_wans(struct json_object *items,
                                                    struct json_object *configured_wans);
static struct json_object *webd_flowd_wan_health_response(struct json_object *body);
static struct json_object *webd_flowd_runtime_response(struct json_object *body);

static int webd_flowd_runtime_empty(struct json_object *resp)
{
    struct json_object *v = NULL;

    if (!resp)
        return 1;
    if (json_object_object_get_ex(resp, "worker_available", &v) && v && !json_object_get_boolean(v))
        return 1;
    if (json_object_object_get_ex(resp, "available", &v) && v && !json_object_get_boolean(v))
        return 1;
    if (json_object_object_get_ex(resp, "runtime_db_present", &v) && v)
        return !json_object_get_boolean(v);
    if (json_object_object_get_ex(resp, "error", &v) && v) {
        const char *err = json_object_get_string(v);
        if (err && (!strcmp(err, "runtime_db_missing") || !strcmp(err, "source_unavailable")))
            return 1;
    }
    return 0;
}

static int webd_flowd_wan_health_empty(struct json_object *resp)
{
    struct json_object *checks = NULL;
    struct json_object *total = NULL;

    if (!resp)
        return 1;
    if (json_object_object_get_ex(resp, "checks", &checks) && checks &&
        json_object_is_type(checks, json_type_array) && json_object_array_length(checks) > 0)
        return 0;
    if (json_object_object_get_ex(resp, "wans", &checks) && checks &&
        json_object_is_type(checks, json_type_array) && json_object_array_length(checks) > 0)
        return 0;
    if (json_object_object_get_ex(resp, "total", &total) && total && json_object_get_int(total) > 0)
        return 0;
    return 1;
}

static void webd_flowd_status_mark_cache(struct json_object *resp, int age_ms,
                                         int stale, const char *reason)
{
    struct json_object *meta = NULL;

    if (!resp || !json_object_is_type(resp, json_type_object))
        return;
    if (!json_object_object_get_ex(resp, "meta", &meta) || !meta ||
        !json_object_is_type(meta, json_type_object)) {
        meta = webd_meta("webd.flowd_status_shared_cache");
        json_object_object_add(resp, "meta", meta);
    }
    json_object_object_add(meta, "cache_hit", json_object_new_boolean(1));
    json_object_object_add(meta, "cache_age_ms", json_object_new_int(age_ms));
    json_object_object_add(meta, "stale", json_object_new_boolean(stale));
    if (stale) {
        json_object_object_add(meta, "refreshing", json_object_new_boolean(1));
        json_object_object_add(meta, "degraded", json_object_new_boolean(1));
        json_object_object_add(meta, "source_error", json_object_new_string(
            reason && reason[0] ? reason : "flowd_status_refresh_failed"));
    }
}

/* flowd serializes status calls internally. A fixed-affinity burst therefore
 * formed a queue even after the route moved to the least-loaded WebD lane.
 * Share one sub-second snapshot across workers and make the refresh
 * single-flight. A concurrent refresh may serve a clearly marked five-second
 * last-known-good response; a truly cold start waits for the first owner. */
static struct json_object *webd_flowd_status_response(int *http_status)
{
    struct json_object *fresh = NULL;
    struct json_object *stale = NULL;
    struct json_object *upstream = NULL;
    int fresh_age_ms = 0;
    int stale_age_ms = 0;
    int lock_fd = -1;
    int lock_busy = 0;
    int status;

    if (http_status)
        *http_status = 200;
    fresh = webd_shared_json_read(WEBD_FLOWD_STATUS_SHARED_CACHE_PATH,
                                  WEBD_FLOWD_STATUS_SHARED_FRESH_MS,
                                  WEBD_FLOWD_STATUS_SHARED_MAX_BYTES,
                                  &fresh_age_ms);
    if (fresh) {
        webd_flowd_status_mark_cache(fresh, fresh_age_ms, 0, NULL);
        return fresh;
    }
    stale = webd_shared_json_read(WEBD_FLOWD_STATUS_SHARED_CACHE_PATH,
                                  WEBD_FLOWD_STATUS_SHARED_STALE_MS,
                                  WEBD_FLOWD_STATUS_SHARED_MAX_BYTES,
                                  &stale_age_ms);

    if (mkdir("/tmp/dreamingwrt", 0755) != 0 && errno != EEXIST)
        goto direct;
    lock_fd = open(WEBD_FLOWD_STATUS_SHARED_LOCK_PATH,
                   O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock_fd < 0)
        goto direct;
    if (flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        lock_busy = errno == EWOULDBLOCK || errno == EAGAIN;
        if (lock_busy && stale) {
            webd_flowd_status_mark_cache(stale, stale_age_ms, 1,
                                         "flowd_status_refresh_in_flight");
            close(lock_fd);
            return stale;
        }
        if (flock(lock_fd, LOCK_EX) != 0)
            goto direct;
    }

    fresh = webd_shared_json_read(WEBD_FLOWD_STATUS_SHARED_CACHE_PATH,
                                  WEBD_FLOWD_STATUS_SHARED_FRESH_MS,
                                  WEBD_FLOWD_STATUS_SHARED_MAX_BYTES,
                                  &fresh_age_ms);
    if (fresh) {
        webd_flowd_status_mark_cache(fresh, fresh_age_ms, 0, NULL);
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
        if (stale)
            json_object_put(stale);
        return fresh;
    }

    upstream = app_ubus_object_or_error("dreamingwrt.flowd", "status", NULL);
    status = app_response_status(upstream, 200);
    if (status < 400 && upstream) {
        (void)webd_shared_json_write_locked(
            WEBD_FLOWD_STATUS_SHARED_CACHE_PATH,
            WEBD_FLOWD_STATUS_SHARED_MAX_BYTES, upstream, lock_fd);
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
        if (stale)
            json_object_put(stale);
        if (http_status)
            *http_status = status;
        return upstream;
    }
    if (stale) {
        webd_flowd_status_mark_cache(stale, stale_age_ms, 1,
                                     "flowd_status_refresh_failed");
        if (upstream)
            json_object_put(upstream);
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
        return stale;
    }
    flock(lock_fd, LOCK_UN);
    close(lock_fd);
    if (http_status)
        *http_status = status;
    return upstream;

direct:
    if (lock_fd >= 0)
        close(lock_fd);
    upstream = app_ubus_object_or_error("dreamingwrt.flowd", "status", NULL);
    status = app_response_status(upstream, 200);
    if (status >= 400 && stale) {
        webd_flowd_status_mark_cache(stale, stale_age_ms, 1,
                                     "flowd_status_refresh_failed");
        if (upstream)
            json_object_put(upstream);
        return stale;
    }
    if (stale)
        json_object_put(stale);
    if (http_status)
        *http_status = status;
    return upstream;
}

static int webd_runtime_entry_is_configured_wan(struct json_object *entry, struct json_object *configured_wans)
{
    int i, n;

    if (!entry)
        return 0;
    if (!configured_wans || !json_object_is_type(configured_wans, json_type_array))
        return 1;
    n = json_object_array_length(configured_wans);
    if (n <= 0)
        return 1;

    for (i = 0; i < n; i++) {
        struct json_object *wan = json_object_array_get_idx(configured_wans, i);
        if (webd_runtime_entry_matches_configured_wan(entry, wan))
            return 1;
    }
    return 0;
}

static struct json_object *webd_filter_runtime_wans(struct json_object *items,
                                                    struct json_object *configured_wans)
{
    struct json_object *filtered;
    int i, n;

    if (!items || !json_object_is_type(items, json_type_array))
        return NULL;

    filtered = json_object_new_array();
    if (!filtered)
        return NULL;

    n = json_object_array_length(items);
    for (i = 0; i < n; i++) {
        struct json_object *item = json_object_array_get_idx(items, i);
        if (webd_runtime_entry_is_configured_wan(item, configured_wans))
            json_object_array_add(filtered, json_object_get(item));
    }
    return filtered;
}

static struct json_object *webd_flowd_wan_health_response(struct json_object *body)
{
    struct json_object *upstream;
    struct json_object *core;
    struct json_object *wan_list = NULL;
    struct json_object *data = NULL;
    struct json_object *wan_data = NULL;
    struct json_object *configured_wans = NULL;
    struct json_object *out;
    struct json_object *resp;
    struct json_object *v = NULL;

    upstream = app_ubus_invoke_object("dreamingwrt.flowd", "wan_health_get", body);
    if (upstream && !webd_flowd_wan_health_empty(upstream))
        return upstream;
    if (upstream) {
        json_object_put(upstream);
        upstream = NULL;
    }

    core = webd_cached_line_health();
    data = webd_data_from_jmx_response(core);
    if (!data) {
        if (core)
            json_object_put(core);
        return webd_error("source_unavailable", "WAN health source is not available",
                          "dreamingwrt.flowd wan_health_get or dreamingwrt line_health",
                          "webd.flowd");
    }
    wan_list = app_ubus_invoke("wan_list", NULL);
    wan_data = webd_data_from_jmx_response(wan_list);
    if (wan_data)
        json_object_object_get_ex(wan_data, "wans", &configured_wans);

    out = json_object_new_object();
    json_object_object_add(out, "worker_available", json_object_new_boolean(0));
    json_object_object_add(out, "degraded", json_object_new_boolean(1));
    json_object_object_add(out, "source", json_object_new_string("dreamingwrt.line_health"));
    json_object_object_add(out, "message", json_object_new_string("flowd worker is not registered; using core WAN health runtime"));
    if (json_object_object_get_ex(data, "ts", &v) && v)
        json_object_object_add(out, "ts", json_object_get(v));
    if (json_object_object_get_ex(data, "wans", &v) && v) {
        struct json_object *filtered = webd_filter_runtime_wans(v, configured_wans);
        json_object_object_add(out, "wans", filtered ? filtered : json_object_get(v));
    }
    json_object_object_add(out, "upstream", json_object_get(core));
    resp = webd_envelope(out, "jmxd.line_health");
    json_object_object_add(resp, "code", json_object_new_int(APP_API_CODE_SUCCESS));

    if (wan_data)
        json_object_put(wan_data);
    if (wan_list)
        json_object_put(wan_list);
    json_object_put(data);
    json_object_put(core);
    return resp;
}

static struct json_object *webd_flowd_runtime_response(struct json_object *body)
{
    struct json_object *upstream;
    struct json_object *summary;
    struct json_object *wan_list;
    struct json_object *line_load;
    struct json_object *line_health;
    struct json_object *wan_data;
    struct json_object *line_load_data;
    struct json_object *line_health_data;
    struct json_object *out;
    struct json_object *resp;
    struct json_object *v = NULL;
    struct json_object *configured_wans = NULL;
    struct json_object *upstream_caps = NULL;
    int upstream_worker_available = 0;
    int upstream_worker_known = 0;
    int upstream_runtime_db_present = 0;
    int upstream_runtime_db_known = 0;
    int upstream_snapshot_available = 0;
    int upstream_snapshot_known = 0;
    int upstream_runtime_applied = 0;
    int upstream_runtime_applied_known = 0;
    int upstream_db_openable = 0;
    int upstream_db_openable_known = 0;
    int upstream_populated = 0;
    int upstream_populated_known = 0;
    char upstream_reason[128] = "";
    char upstream_error[128] = "";

    upstream = app_ubus_invoke_object("dreamingwrt.flowd", "runtime", body);
    if (upstream && !webd_flowd_runtime_empty(upstream))
        return upstream;
    if (upstream) {
        if (json_object_object_get_ex(upstream, "worker_available", &v) && v) {
            upstream_worker_known = 1;
            upstream_worker_available = json_object_get_boolean(v);
        }
        if (json_object_object_get_ex(upstream, "runtime_db_present", &v) && v) {
            upstream_runtime_db_known = 1;
            upstream_runtime_db_present = json_object_get_boolean(v);
        }
        if (json_object_object_get_ex(upstream, "runtime_snapshot_available", &v) && v) {
            upstream_snapshot_known = 1;
            upstream_snapshot_available = json_object_get_boolean(v);
        }
        if (json_object_object_get_ex(upstream, "runtime_applied", &v) && v) {
            upstream_runtime_applied_known = 1;
            upstream_runtime_applied = json_object_get_boolean(v);
        }
        if (json_object_object_get_ex(upstream, "runtime_db_openable", &v) && v) {
            upstream_db_openable_known = 1;
            upstream_db_openable = json_object_get_boolean(v);
        }
        if (json_object_object_get_ex(upstream, "runtime_populated", &v) && v) {
            upstream_populated_known = 1;
            upstream_populated = json_object_get_boolean(v);
        }
        if (json_object_object_get_ex(upstream, "runtime_reason", &v) && v)
            snprintf(upstream_reason, sizeof(upstream_reason), "%s",
                     json_object_get_string(v));
        if (json_object_object_get_ex(upstream, "error", &v) && v)
            snprintf(upstream_error, sizeof(upstream_error), "%s",
                     json_object_get_string(v));
        if (json_object_object_get_ex(upstream, "capabilities", &v) && v)
            upstream_caps = json_object_get(v);
        json_object_put(upstream);
        upstream = NULL;
    }

    summary = app_ubus_invoke("summary", NULL);
    wan_list = app_ubus_invoke("wan_list", NULL);
    line_load = webd_cached_line_load();
    line_health = webd_cached_line_health();
    wan_data = webd_data_from_jmx_response(wan_list);
    line_load_data = webd_data_from_jmx_response(line_load);
    line_health_data = webd_data_from_jmx_response(line_health);
    if (wan_data)
        json_object_object_get_ex(wan_data, "wans", &configured_wans);

    if (!summary && !line_load_data && !line_health_data) {
        if (wan_list) json_object_put(wan_list);
        if (wan_data) json_object_put(wan_data);
        if (line_load) json_object_put(line_load);
        if (line_health) json_object_put(line_health);
        if (upstream_caps) json_object_put(upstream_caps);
        return webd_error("source_unavailable", "flow runtime source is not available",
                          "dreamingwrt.flowd runtime or dreamingwrt summary/line_load/line_health",
                          "webd.flowd");
    }

    out = json_object_new_object();
    json_object_object_add(out, "service", json_object_new_string("dreamingwrt-flowd"));
    json_object_object_add(out, "worker_available", json_object_new_boolean(
        upstream_worker_known ? upstream_worker_available : 0));
    json_object_object_add(out, "runtime_db_present", json_object_new_boolean(
        upstream_runtime_db_known && upstream_runtime_db_present));
    json_object_object_add(out, "runtime_snapshot_available", json_object_new_boolean(
        upstream_snapshot_known && upstream_snapshot_available));
    json_object_object_add(out, "runtime_db_openable", json_object_new_boolean(
        upstream_db_openable_known && upstream_db_openable));
    json_object_object_add(out, "runtime_populated", json_object_new_boolean(
        upstream_populated_known && upstream_populated));
    json_object_object_add(out, "runtime_applied", json_object_new_boolean(
        upstream_runtime_applied_known && upstream_runtime_applied));
    json_object_object_add(out, "runtime_reason", json_object_new_string(
        upstream_error[0] ? upstream_error :
        (upstream_reason[0] && strcmp(upstream_reason, "runtime_state_missing") ?
         upstream_reason :
         (upstream_worker_known && upstream_worker_available ?
          "runtime_db_missing" : "flowd_worker_unavailable"))));
    json_object_object_add(out, "degraded", json_object_new_boolean(1));
    json_object_object_add(out, "source", json_object_new_string("dreamingwrt.core_runtime"));
    json_object_object_add(out, "message", json_object_new_string(
        upstream_worker_known && upstream_worker_available ?
        "flowd worker is registered but runtime snapshot is unavailable; using core runtime read-only sources" :
        "flowd worker is not registered; using core runtime read-only sources"));
    if (upstream_error[0])
        json_object_object_add(out, "error", json_object_new_string(upstream_error));
    if (upstream_caps) {
        const char *cap_reason = upstream_error[0] ? upstream_error :
                                 (upstream_reason[0] &&
                                  strcmp(upstream_reason, "runtime_state_missing") ?
                                  upstream_reason :
                                  (upstream_worker_known && upstream_worker_available ?
                                   "runtime_db_missing" : "flowd_worker_unavailable"));
        json_object_object_del(upstream_caps, "flow_engine_apply");
        json_object_object_add(upstream_caps, "flow_engine_apply",
                               json_object_new_boolean(0));
        json_object_object_del(upstream_caps, "flow_engine_apply_ready");
        json_object_object_add(upstream_caps, "flow_engine_apply_ready",
                               json_object_new_boolean(0));
        json_object_object_del(upstream_caps, "flow_engine_runtime_readback");
        json_object_object_add(upstream_caps, "flow_engine_runtime_readback",
                               json_object_new_boolean(0));
        json_object_object_del(upstream_caps, "reasons");
        {
            struct json_object *reasons = json_object_new_object();
            json_object_object_add(reasons, "flow_engine_apply",
                                   json_object_new_string(cap_reason));
            json_object_object_add(reasons, "flow_engine_runtime_readback",
                                   json_object_new_string(cap_reason));
            json_object_object_add(upstream_caps, "reasons", reasons);
        }
        json_object_object_add(out, "capabilities", upstream_caps);
    }
    if (summary) {
        json_object_object_add(out, "summary", json_object_get(summary));
        if (!json_object_object_get_ex(summary, "risk_cache", &v))
            json_object_object_add(summary, "risk_cache", json_object_new_int(0));
        if (json_object_object_get_ex(summary, "traffic", &v) && v)
            json_object_object_add(out, "traffic", json_object_get(v));
        if (json_object_object_get_ex(summary, "apps", &v) && v)
            json_object_object_add(out, "apps", json_object_get(v));
        if (json_object_object_get_ex(summary, "apps_online", &v) && v)
            json_object_object_add(out, "apps_online", json_object_get(v));
    } else {
        struct json_object *fallback_summary = json_object_new_object();
        json_object_object_add(fallback_summary, "risk_cache", json_object_new_int(0));
        json_object_object_add(out, "summary", fallback_summary);
    }
    json_object_object_add(out, "risk_cache", json_object_new_array());
    if (line_load_data && json_object_object_get_ex(line_load_data, "interfaces", &v) && v) {
        struct json_object *filtered = webd_filter_runtime_wans(v, configured_wans);
        json_object_object_add(out, "interfaces", filtered ? filtered : json_object_get(v));
    }
    if (line_health_data && json_object_object_get_ex(line_health_data, "wans", &v) && v) {
        struct json_object *filtered = webd_filter_runtime_wans(v, configured_wans);
        if (filtered) {
            json_object_object_add(out, "wans", json_object_get(filtered));
            json_object_object_add(out, "wan_health", filtered);
        } else {
            json_object_object_add(out, "wans", json_object_get(v));
            json_object_object_add(out, "wan_health", json_object_get(v));
        }
    }
    if (summary)
        json_object_object_add(out, "summary_upstream", json_object_get(summary));
    if (line_load)
        json_object_object_add(out, "line_load_upstream", json_object_get(line_load));
    if (line_health)
        json_object_object_add(out, "line_health_upstream", json_object_get(line_health));

    resp = webd_envelope(out, "jmxd.core_runtime");
    json_object_object_add(resp, "code", json_object_new_int(APP_API_CODE_SUCCESS));

    if (wan_data) json_object_put(wan_data);
    if (line_load_data) json_object_put(line_load_data);
    if (line_health_data) json_object_put(line_health_data);
    if (summary) json_object_put(summary);
    if (wan_list) json_object_put(wan_list);
    if (line_load) json_object_put(line_load);
    if (line_health) json_object_put(line_health);
    return resp;
}

/* ── flowd route handlers (thin dreamingwrt.flowd proxies + rich readers) ── */

static struct json_object *flowd_status_get(struct jmx_api_ctx *ctx)
{
    return webd_flowd_status_response(&ctx->status);
}

static struct json_object *flowd_settings_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "settings_get", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_settings_set(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "settings_set", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_geoip_sources_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "geoip_sources_get", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_geoip_source_set(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "geoip_source_set", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_geoip_source_delete(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "geoip_source_delete", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_geoip_import_status(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "geoip_import_status", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_geoip_import(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "geoip_import", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_geoip_update_check(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "geoip_update_check", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_country_policies_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "country_policies_get", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_country_policy_set(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "country_policy_set", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_country_policy_delete(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "country_policy_delete", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_country_sets_generate(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "country_sets_generate", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_objects_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "objects_get", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_object_set(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "object_set", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_object_delete(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "object_delete", ctx->body);
    ctx->status = app_routed_http_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_export_settings_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "export_settings_get", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_export_settings_set(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "export_settings_set", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_custom_protocols_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "custom_protocols_get", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_custom_protocol_set(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "custom_protocol_set", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_custom_protocol_delete(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "custom_protocol_delete", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_route_groups_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "route_groups_get", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_route_group_set(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "route_group_set", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_route_group_delete(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "route_group_delete", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_wan_capacity_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "wan_capacity_get", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_wan_capacity_set(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "wan_capacity_set", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_wan_capacity_delete(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "wan_capacity_delete", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_wan_health_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = webd_flowd_wan_health_response(ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_wan_health_set(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "wan_health_set", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_wan_health_delete(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "wan_health_delete", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_split_rules_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "split_rules_get", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_split_rule_set(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "split_rule_set", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_split_rule_delete(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "split_rule_delete", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_domain_rules_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "domain_rules_get", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_domain_rule_set(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "domain_rule_set", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_domain_rule_delete(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "domain_rule_delete", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_qos_settings_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "qos_settings_get", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_qos_settings_set(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "qos_settings_set", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_qos_classes_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "qos_classes_get", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_qos_class_set(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "qos_class_set", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_qos_class_delete(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "qos_class_delete", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_qos_rules_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "qos_rules_get", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_qos_rule_set(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "qos_rule_set", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_qos_rule_delete(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "qos_rule_delete", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_smart_qos_categories_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "smart_qos_categories_get", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_smart_qos_category_set(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "smart_qos_category_set", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_smart_qos_category_delete(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "smart_qos_category_delete", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_quota_rules_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "quota_rules_get", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_quota_rule_set(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "quota_rule_set", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_quota_rule_delete(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "quota_rule_delete", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_conn_limit_rules_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "conn_limit_rules_get", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_conn_limit_rule_set(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "conn_limit_rule_set", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_conn_limit_rule_delete(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "conn_limit_rule_delete", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_app_rules_get(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "app_rules_get", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_app_rule_set(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "app_rule_set", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_app_rule_delete(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "app_rule_delete", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_compile(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "compile", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_nft_revision_status(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "nft_revision_status", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_nft_revision_apply(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "nft_revision_apply", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_apply_jobs(struct jmx_api_ctx *ctx)
{
    struct json_object *resp = app_ubus_object_or_error("dreamingwrt.flowd", "apply_jobs", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

static struct json_object *flowd_runtime(struct jmx_api_ctx *ctx)
{
    struct json_object *resp;

    if (!strcmp(ctx->req->method, "GET"))
        resp = webd_flowd_runtime_response(ctx->body);
    else
        resp = app_ubus_object_or_error("dreamingwrt.flowd", "runtime", ctx->body);
    ctx->status = app_response_status(resp, ctx->status);
    return resp;
}

const struct jmx_api_route flowd_api_routes[] = {
    JMX_API_ROUTE(232, "/api/v1/flowd/status", "GET", JMX_API_EXACT, flowd_status_get),
    JMX_API_ROUTE(233, "/api/v1/flowd/settings", "GET", JMX_API_EXACT, flowd_settings_get),
    JMX_API_ROUTE(234, "/api/v1/flowd/settings", "POST,PUT,PATCH", JMX_API_EXACT, flowd_settings_set),
    JMX_API_ROUTE(235, "/api/v1/flowd/geoip/sources", "GET", JMX_API_EXACT, flowd_geoip_sources_get),
    JMX_API_ROUTE(236, "/api/v1/flowd/geoip/sources", "POST,PUT,PATCH", JMX_API_EXACT, flowd_geoip_source_set),
    JMX_API_ROUTE(237, "/api/v1/flowd/geoip/sources/delete", "POST,PUT", JMX_API_EXACT, flowd_geoip_source_delete),
    JMX_API_ROUTE(238, "/api/v1/flowd/geoip/import/status", "GET", JMX_API_EXACT, flowd_geoip_import_status),
    JMX_API_ROUTE(239, "/api/v1/flowd/geoip/import", "POST", JMX_API_EXACT, flowd_geoip_import),
    JMX_API_ROUTE(240, "/api/v1/flowd/geoip/update/check", "POST", JMX_API_EXACT, flowd_geoip_update_check),
    JMX_API_ROUTE(241, "/api/v1/flowd/country-policies", "GET", JMX_API_EXACT, flowd_country_policies_get),
    JMX_API_ROUTE(242, "/api/v1/flowd/country-policies", "POST,PUT,PATCH", JMX_API_EXACT, flowd_country_policy_set),
    JMX_API_ROUTE(243, "/api/v1/flowd/country-policies/delete", "POST,PUT", JMX_API_EXACT, flowd_country_policy_delete),
    JMX_API_ROUTE(244, "/api/v1/flowd/country-sets/generate", "POST", JMX_API_EXACT, flowd_country_sets_generate),
    JMX_API_ROUTE(245, "/api/v1/flowd/objects", "GET", JMX_API_EXACT, flowd_objects_get),
    JMX_API_ROUTE(246, "/api/v1/flowd/objects", "POST,PUT,PATCH", JMX_API_EXACT, flowd_object_set),
    JMX_API_ROUTE(247, "/api/v1/flowd/objects/delete", "POST,PUT", JMX_API_EXACT, flowd_object_delete),
    JMX_API_ROUTE(248, "/api/v1/flowd/export-settings", "GET", JMX_API_EXACT, flowd_export_settings_get),
    JMX_API_ROUTE(249, "/api/v1/flowd/export-settings", "POST,PUT,PATCH", JMX_API_EXACT, flowd_export_settings_set),
    JMX_API_ROUTE(250, "/api/v1/flowd/custom-protocols", "GET", JMX_API_EXACT, flowd_custom_protocols_get),
    JMX_API_ROUTE(251, "/api/v1/flowd/custom-protocols", "POST,PUT,PATCH", JMX_API_EXACT, flowd_custom_protocol_set),
    JMX_API_ROUTE(252, "/api/v1/flowd/custom-protocols/delete", "POST,PUT", JMX_API_EXACT, flowd_custom_protocol_delete),
    JMX_API_ROUTE(253, "/api/v1/flowd/route-groups", "GET", JMX_API_EXACT, flowd_route_groups_get),
    JMX_API_ROUTE(254, "/api/v1/flowd/route-groups", "POST,PUT,PATCH", JMX_API_EXACT, flowd_route_group_set),
    JMX_API_ROUTE(255, "/api/v1/flowd/route-groups/delete", "POST,PUT", JMX_API_EXACT, flowd_route_group_delete),
    JMX_API_ROUTE(256, "/api/v1/flowd/wan-capacity", "GET", JMX_API_EXACT, flowd_wan_capacity_get),
    JMX_API_ROUTE(257, "/api/v1/flowd/wan-capacity", "POST,PUT,PATCH", JMX_API_EXACT, flowd_wan_capacity_set),
    JMX_API_ROUTE(258, "/api/v1/flowd/wan-capacity/delete", "POST,PUT", JMX_API_EXACT, flowd_wan_capacity_delete),
    JMX_API_ROUTE(259, "/api/v1/flowd/wan-health", "GET", JMX_API_EXACT, flowd_wan_health_get),
    JMX_API_ROUTE(264, "/api/v1/flowd/wan-health", "POST,PUT,PATCH", JMX_API_EXACT, flowd_wan_health_set),
    JMX_API_ROUTE(265, "/api/v1/flowd/wan-health/delete", "POST,PUT", JMX_API_EXACT, flowd_wan_health_delete),
    JMX_API_ROUTE(273, "/api/v1/flowd/split-rules", "GET", JMX_API_EXACT, flowd_split_rules_get),
    JMX_API_ROUTE(274, "/api/v1/flowd/split-rules", "POST,PUT,PATCH", JMX_API_EXACT, flowd_split_rule_set),
    JMX_API_ROUTE(275, "/api/v1/flowd/split-rules/delete", "POST,PUT", JMX_API_EXACT, flowd_split_rule_delete),
    JMX_API_ROUTE(276, "/api/v1/flowd/domain-rules", "GET", JMX_API_EXACT, flowd_domain_rules_get),
    JMX_API_ROUTE(277, "/api/v1/flowd/domain-rules", "POST,PUT,PATCH", JMX_API_EXACT, flowd_domain_rule_set),
    JMX_API_ROUTE(278, "/api/v1/flowd/domain-rules/delete", "POST,PUT", JMX_API_EXACT, flowd_domain_rule_delete),
    JMX_API_ROUTE(279, "/api/v1/flowd/qos/settings", "GET", JMX_API_EXACT, flowd_qos_settings_get),
    JMX_API_ROUTE(280, "/api/v1/flowd/qos/settings", "POST,PUT,PATCH", JMX_API_EXACT, flowd_qos_settings_set),
    JMX_API_ROUTE(281, "/api/v1/flowd/qos/classes", "GET", JMX_API_EXACT, flowd_qos_classes_get),
    JMX_API_ROUTE(282, "/api/v1/flowd/qos/classes", "POST,PUT,PATCH", JMX_API_EXACT, flowd_qos_class_set),
    JMX_API_ROUTE(283, "/api/v1/flowd/qos/classes/delete", "POST,PUT", JMX_API_EXACT, flowd_qos_class_delete),
    JMX_API_ROUTE(284, "/api/v1/flowd/qos/rules", "GET", JMX_API_EXACT, flowd_qos_rules_get),
    JMX_API_ROUTE(285, "/api/v1/flowd/qos/rules", "POST,PUT,PATCH", JMX_API_EXACT, flowd_qos_rule_set),
    JMX_API_ROUTE(286, "/api/v1/flowd/qos/rules/delete", "POST,PUT", JMX_API_EXACT, flowd_qos_rule_delete),
    JMX_API_ROUTE(287, "/api/v1/flowd/smart-qos/categories", "GET", JMX_API_EXACT, flowd_smart_qos_categories_get),
    JMX_API_ROUTE(288, "/api/v1/flowd/smart-qos/categories", "POST,PUT,PATCH", JMX_API_EXACT, flowd_smart_qos_category_set),
    JMX_API_ROUTE(289, "/api/v1/flowd/smart-qos/categories/delete", "POST,PUT", JMX_API_EXACT, flowd_smart_qos_category_delete),
    JMX_API_ROUTE(290, "/api/v1/flowd/quota-rules", "GET", JMX_API_EXACT, flowd_quota_rules_get),
    JMX_API_ROUTE(291, "/api/v1/flowd/quota-rules", "POST,PUT,PATCH", JMX_API_EXACT, flowd_quota_rule_set),
    JMX_API_ROUTE(292, "/api/v1/flowd/quota-rules/delete", "POST,PUT", JMX_API_EXACT, flowd_quota_rule_delete),
    JMX_API_ROUTE(293, "/api/v1/flowd/conn-limit-rules", "GET", JMX_API_EXACT, flowd_conn_limit_rules_get),
    JMX_API_ROUTE(294, "/api/v1/flowd/conn-limit-rules", "POST,PUT,PATCH", JMX_API_EXACT, flowd_conn_limit_rule_set),
    JMX_API_ROUTE(295, "/api/v1/flowd/conn-limit-rules/delete", "POST,PUT", JMX_API_EXACT, flowd_conn_limit_rule_delete),
    JMX_API_ROUTE(296, "/api/v1/flowd/app-rules", "GET", JMX_API_EXACT, flowd_app_rules_get),
    JMX_API_ROUTE(297, "/api/v1/flowd/app-rules", "POST,PUT,PATCH", JMX_API_EXACT, flowd_app_rule_set),
    JMX_API_ROUTE(298, "/api/v1/flowd/app-rules/delete", "POST,PUT", JMX_API_EXACT, flowd_app_rule_delete),
    JMX_API_ROUTE(299, "/api/v1/flowd/compile", "POST", JMX_API_EXACT, flowd_compile),
    JMX_API_ROUTE(300, "/api/v1/flowd/nft-revision", "GET", JMX_API_EXACT, flowd_nft_revision_status),
    JMX_API_ROUTE(301, "/api/v1/flowd/nft-revision", "POST", JMX_API_EXACT, flowd_nft_revision_apply),
    JMX_API_ROUTE(302, "/api/v1/flowd/apply-jobs", "GET,POST,PUT", JMX_API_EXACT, flowd_apply_jobs),
    JMX_API_ROUTE(303, "/api/v1/flowd/runtime", "GET,POST,PUT", JMX_API_EXACT, flowd_runtime),
    JMX_API_ROUTE_END,
};

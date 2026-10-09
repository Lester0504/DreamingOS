// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * WAN policy / rules BFF (Phase 6K). The /api/v1/network/wan-policies (+ per-id
 * transaction subtree), /api/v1/network/wan-policy and /api/v1/network/wan-rules
 * read/write surface. The entire WAN-policy BFF subsystem — member validation,
 * the atomic route-config apply (webd_route_config_set + its lock/fsync helpers),
 * smart-path activation, flowd status shaping and the 3 response builders — moves
 * here VERBATIM from jmx_app_api.c and stays file-static; only the 3 dispatch
 * delegations become route handlers. Behavior is preserved: each response fn takes
 * a const struct http_req *, so passing ctx->req directly equals the legacy &req
 * read-only copy, and the two audit-logging branches are reproduced faithfully.
 *
 * The wan-policies branch matched `exact OR strncmp(".../wan-policies/", 29)`, so
 * it is one JMX_API_PREDICATE_ROUTE with JMX_API_PREDICATE_MIXED: the matcher
 * tries the fixed path, and wan_policies_path() supplies the strncmp half — one
 * physical row, one inventory 'mixed' route (net-zero).
 *
 * Borrowed from jmx_app_api.c (declared in api_wan_internal.h; definitions stay in
 * main with their other callers): webd_put_int and webd_ws_semantic_hash
 * (de-static'd) and the already-extern gen_random_hex_checked (prototype only).
 */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <json-c/json.h>
#include <libubus.h>

#include "api_wan.h"
#include "api_wan_internal.h"
#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_ubus.h"
#include "api_util.h"
#include "webd_http_req.h"
#include "../../jmx_strbuf.h"
#include "../jmx_app_api.h"

/* smart-path + runtime-dir macros (cluster-local; macros are per-TU) */
#define WEBD_RUNTIME_DIR "/run/dreamingwrt"
#define WEBD_SMART_PATH_ENABLE_PATH "/etc/dreamingwrt/smart-path.enabled"
#define WEBD_SMART_PATH_CONFIRM_PATH "/etc/dreamingwrt/smart-path.confirmed"
#define WEBD_SMART_PATH_LOCK_PATH "/run/dreamingwrt/wan-policy.lock"
#define WEBD_SMART_PATH_ACTIVATE_TIMEOUT_MS 8000
#define WEBD_SMART_PATH_POLL_MS 250

/* intra-cluster forward declarations (call-before-def) */
static struct json_object *webd_wan_policy_flowd_status(void);
static struct json_object *webd_wan_policy_response(const struct http_req *req,
                                                    struct json_object *body,
                                                    int *status);

/* ── WAN policy/rules BFF subsystem (moved verbatim from jmx_app_api.c) ── */

static int webd_wan_policy_validate_members(struct json_object *body)
{
    struct json_object *wan_ids = NULL;
    unsigned char seen[256] = {0};
    int i;

    if (!body || !json_object_object_get_ex(body, "wan_ids", &wan_ids) ||
        !wan_ids || !json_object_is_type(wan_ids, json_type_array) ||
        json_object_array_length(wan_ids) < 2 ||
        json_object_array_length(wan_ids) > 8)
        return -1;
    for (i = 0; i < json_object_array_length(wan_ids); i++) {
        struct json_object *value = json_object_array_get_idx(wan_ids, i);
        int id;

        if (!value || !json_object_is_type(value, json_type_int) ||
            (id = json_object_get_int(value)) <= 0 || id > 8 || seen[id])
            return -1;
        seen[id] = 1;
    }
    return 0;
}

static int webd_wan_policy_set_file(const char *path, int present)
{
    char tmp[PATH_MAX];
    char dir[PATH_MAX];
    char *slash;
    int fd = -1;
    int dirfd = -1;

    if (!path || !path[0]) {
        errno = EINVAL;
        return -1;
    }
    if (!present) {
        if (unlink(path) != 0 && errno != ENOENT)
            return -1;
    } else {
        if (snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid()) >=
            (int)sizeof(tmp)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
        if (fd < 0)
            return -1;
        if (fsync(fd) != 0) {
            close(fd);
            fd = -1;
            unlink(tmp);
            return -1;
        }
        if (close(fd) != 0) {
            fd = -1;
            unlink(tmp);
            return -1;
        }
        fd = -1;
        if (rename(tmp, path) != 0) {
            unlink(tmp);
            return -1;
        }
    }

    if (snprintf(dir, sizeof(dir), "%s", path) >= (int)sizeof(dir))
        return 0;
    slash = strrchr(dir, '/');
    if (!slash)
        return 0;
    *slash = '\0';
    dirfd = open(dir[0] ? dir : "/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd >= 0) {
        (void)fsync(dirfd);
        close(dirfd);
    }
    return 0;
}

static int webd_wan_policy_open_lock(void)
{
    int fd;

    (void)mkdir(WEBD_RUNTIME_DIR, 0755);
    fd = open(WEBD_SMART_PATH_LOCK_PATH,
              O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0 || flock(fd, LOCK_EX | LOCK_NB) != 0) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    return fd;
}

static time_t webd_wan_policy_last_transition_at;
static time_t webd_wan_policy_last_success_readback_at;
static char webd_wan_policy_failure_stage[64];
static char webd_wan_policy_last_error[160];

static int64_t webd_wan_policy_monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (int64_t)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static void webd_wan_policy_transition(const char *stage, const char *error)
{
    webd_wan_policy_last_transition_at = time(NULL);
    snprintf(webd_wan_policy_failure_stage,
             sizeof(webd_wan_policy_failure_stage), "%s", stage ? stage : "");
    snprintf(webd_wan_policy_last_error,
             sizeof(webd_wan_policy_last_error), "%s", error ? error : "");
}

static int webd_wan_policy_smart_truth(struct json_object **smart_out,
                                       char *reason, size_t reason_len)
{
    struct json_object *upstream = NULL;
    struct json_object *data = NULL;
    struct json_object *smart = NULL;
    int active = 0;

    if (smart_out)
        *smart_out = NULL;
    if (reason && reason_len)
        reason[0] = '\0';
    upstream = webd_wan_policy_flowd_status();
    data = webd_data_or_self_from_jmx_response(upstream);
    if (!data || !json_object_is_type(data, json_type_object) ||
        !json_object_object_get_ex(data, "smart_path", &smart) || !smart ||
        !json_object_is_type(smart, json_type_object)) {
        if (reason && reason_len)
            snprintf(reason, reason_len, "%s", "flowd_status_unavailable");
        goto out;
    }
    /* enabled_requested is flowd's aggregate: some policy is explicitly
     * `enabled`, or is `inherit` while /etc/dreamingwrt/smart-path.enabled
     * exists.  global_enabled_requested is ONLY that sentinel -- the default an
     * `inherit` policy picks up -- so it is false on a per-policy deployment.
     * Reading the sentinel first made this mean "is the global default on", and
     * because flowd always emits the key the fallback was never reached. */
    active = (app_nc_json_bool(smart, "enabled_requested", 0) ||
              app_nc_json_bool(smart, "global_enabled_requested", 0)) &&
             app_nc_json_bool(smart, "scheduler_active", 0) &&
             app_nc_json_bool(smart, "nft_active", 0) &&
             app_nc_json_bool(smart, "nft_readback_ok", 0);
    if (reason && reason_len)
        snprintf(reason, reason_len, "%s",
                 app_nc_json_str(smart, "unavailable_reason",
                     app_nc_json_str(smart, "last_error", "")));
    if (smart_out)
        *smart_out = json_object_get(smart);
out:
    if (data)
        json_object_put(data);
    if (upstream)
        json_object_put(upstream);
    return active;
}

static int webd_wan_policy_wait_smart(struct json_object **smart_out,
                                      char *reason, size_t reason_len)
{
    int64_t deadline = webd_wan_policy_monotonic_ms() +
                       WEBD_SMART_PATH_ACTIVATE_TIMEOUT_MS;

    if (smart_out)
        *smart_out = NULL;
    do {
        struct json_object *smart = NULL;

        if (webd_wan_policy_smart_truth(&smart, reason, reason_len)) {
            webd_wan_policy_last_success_readback_at = time(NULL);
            if (smart_out)
                *smart_out = smart;
            else if (smart)
                json_object_put(smart);
            return 0;
        }
        if (smart)
            json_object_put(smart);
        usleep(WEBD_SMART_PATH_POLL_MS * 1000);
    } while (webd_wan_policy_monotonic_ms() < deadline);
    return -1;
}

static struct json_object *webd_wan_policy_route_request(struct json_object *body,
                                                         const char *base_mode,
                                                         int legacy_adaptive)
{
    struct json_object *request = json_object_new_object();
    struct json_object *wan_ids = NULL;
    struct json_object *adaptive = NULL;

    if (!request)
        return NULL;
    if (legacy_adaptive)
        json_object_object_add(request, "mode",
                               json_object_new_string("adaptive_penalty_sticky"));
    else
        json_object_object_add(request, "base_mode", json_object_new_string(base_mode));
    json_object_object_add(request, "carrier_neutral", json_object_new_boolean(1));
    if (body && json_object_object_get_ex(body, "wan_ids", &wan_ids) && wan_ids)
        json_object_object_add(request, "wan_ids", json_object_get(wan_ids));
    if (body && json_object_object_get_ex(body, "enable_adaptive_penalty_sticky",
                                           &adaptive) && adaptive &&
        json_object_is_type(adaptive, json_type_boolean))
        json_object_object_add(request, "enable_adaptive_penalty_sticky",
                               json_object_get(adaptive));
    return request;
}

/*
 * route_config_set rebuilds every policy rule and re-syncs the kernel, forking
 * ~50 `ip` commands.  It was called on the 2 s default ubus budget while really
 * taking 5-10 s, so every multi-WAN write "failed": webd stopped waiting, and
 * because a ubus client timeout does not cancel the server-side handler, the
 * transaction then committed seconds after the user had been told that
 * validation failed and nothing had changed.
 *
 * The routed-side poll fix (JMX_ROUTE_CMD_POLL_MIN_US) takes a normal apply back
 * under a second, but the budget has to be sized for the work rather than for
 * the best case, so keep the same 20 s used for the dnsmasq apply above and for
 * the same reason: each request is served in its own forked child, so blocking
 * here cannot stall other clients.
 */
#define WEBD_ROUTE_CONFIG_APPLY_TIMEOUT_MS 20000

/* Every route_config_set call goes through here so none of them can silently
 * inherit the 2 s default again.  `diag` is optional: callers that only check
 * ok/not-ok pass NULL, callers that must tell "no reply" from "rejected" pass a
 * diag and hand it to webd_wan_policies_route_error(). */
static struct json_object *webd_route_config_set(struct json_object *config,
                                                 struct app_ubus_call_diag *diag)
{
    struct app_ubus_call_diag local = { .rc = -1, .stage = NULL };

    return app_ubus_invoke_object_diag("dreamingwrt", "route_config_set", config,
                                       WEBD_ROUTE_CONFIG_APPLY_TIMEOUT_MS,
                                       diag ? diag : &local);
}

static struct json_object *webd_wan_policy_apply(struct json_object *body,
                                                 const char *base_mode,
                                                 int legacy_adaptive,
                                                 int *status)
{
    struct json_object *request = NULL;
    struct json_object *upstream = NULL;
    struct json_object *data = NULL;
    struct json_object *previous_config_upstream = NULL;
    struct json_object *previous_config = NULL;
    struct json_object *route_restore = NULL;
    struct json_object *smart_status = NULL;
    char smart_reason[160] = "";
    int previous_enabled;
    int previous_confirmed;
    int enabling_smart;
    int smart_field_present;
    const char *route_apply_mode;
    struct json_object *smart_enabled_obj = NULL;
    int lockfd;

    if (webd_wan_policy_validate_members(body) != 0) {
        if (status) *status = 400;
        return webd_error("invalid_members", "至少选择两条且不能重复的 WAN 线路",
                          "wan_ids", "webd.network.wan_policy");
    }
    smart_field_present = body &&
        json_object_object_get_ex(body, "enable_smart_path", &smart_enabled_obj);
    enabling_smart = smart_field_present && smart_enabled_obj &&
        json_object_is_type(smart_enabled_obj, json_type_boolean) ?
        json_object_get_boolean(smart_enabled_obj) : 0;
    route_apply_mode = base_mode;
    lockfd = webd_wan_policy_open_lock();
    if (lockfd < 0) {
        if (status) *status = 503;
        return webd_error("policy_lock_unavailable", "WAN 策略正忙或运行目录不可用",
                          WEBD_SMART_PATH_LOCK_PATH, "webd.network.wan_policy");
    }
    previous_enabled = access(WEBD_SMART_PATH_ENABLE_PATH, F_OK) == 0;
    previous_confirmed = access(WEBD_SMART_PATH_CONFIRM_PATH, F_OK) == 0;
    if (!smart_field_present)
        enabling_smart = previous_enabled || previous_confirmed;
    previous_config_upstream = app_ubus_invoke("route_config_get", NULL);
    previous_config = webd_data_from_jmx_response(previous_config_upstream);
    if (!previous_config) {
        if (status) *status = 503;
        upstream = webd_error("rollback_snapshot_unavailable",
                              "无法取得 WAN 策略回滚快照，本次未修改",
                              "dreamingwrt route_config_get",
                              "webd.network.wan_policy");
        goto out;
    }

    if (smart_field_present && !enabling_smart) {
        webd_wan_policy_transition("disabling_smart_path", "");
        if (webd_wan_policy_set_file(WEBD_SMART_PATH_ENABLE_PATH, 0) != 0 ||
            webd_wan_policy_set_file(WEBD_SMART_PATH_CONFIRM_PATH, 0) != 0) {
            if (status) *status = 500;
            upstream = webd_error("smart_path_disable_failed", "无法停用智能路径",
                                  WEBD_SMART_PATH_ENABLE_PATH,
                                  "webd.network.wan_policy");
            goto restore_files;
        }
    }

    request = webd_wan_policy_route_request(body, route_apply_mode,
                                             legacy_adaptive);
    if (!request) {
        if (status) *status = 500;
        upstream = webd_error("allocation_failed", "WAN 策略请求创建失败",
                              "memory", "webd.network.wan_policy");
        goto restore_files;
    }
    upstream = app_ubus_invoke("route_policy_set", request);
    if (!upstream || !app_ubus_response_ok(upstream)) {
        if (status) *status = upstream ? app_response_status(upstream, 400) : 503;
        if (!upstream)
            upstream = webd_error("source_unavailable", "WAN 策略运行态不可用",
                                  "dreamingwrt route_policy_set",
                                  "webd.network.wan_policy");
        goto restore_files;
    }

    if (enabling_smart &&
        webd_wan_policy_set_file(WEBD_SMART_PATH_ENABLE_PATH, 1) != 0) {
        if (status) *status = 500;
        json_object_put(upstream);
        upstream = webd_error("smart_path_enable_failed", "无法启用智能路径",
                              WEBD_SMART_PATH_ENABLE_PATH,
                              "webd.network.wan_policy");
        route_restore = webd_route_config_set(previous_config, NULL);
        json_object_object_add(upstream, "route_rollback_ok",
                               json_object_new_boolean(
                                   app_ubus_response_ok(route_restore)));
        goto restore_files;
    }
    if (enabling_smart) {
        webd_wan_policy_transition("waiting_smart_path_readback", "");
        if (webd_wan_policy_wait_smart(&smart_status, smart_reason,
                                       sizeof(smart_reason)) != 0) {
            int rollback_ok;

            if (status) *status = 503;
            json_object_put(upstream);
            upstream = webd_error("smart_path_activation_failed",
                                  "智能路径未通过运行态回读，已回滚",
                                  smart_reason[0] ? smart_reason : "activation_timeout",
                                  "webd.network.wan_policy");
            route_restore = webd_route_config_set(previous_config, NULL);
            rollback_ok = app_ubus_response_ok(route_restore);
            json_object_object_add(upstream, "route_rollback_ok",
                                   json_object_new_boolean(rollback_ok));
            json_object_object_add(upstream, "failure_stage",
                                   json_object_new_string("smart_path_readback"));
            json_object_object_add(upstream, "requested_mode",
                                   json_object_new_string("smart_path"));
            json_object_object_add(upstream, "effective_mode",
                                   json_object_new_string(route_apply_mode));
            webd_wan_policy_transition("smart_path_readback",
                smart_reason[0] ? smart_reason : "activation_timeout");
            goto restore_files;
        }
        if (webd_wan_policy_set_file(WEBD_SMART_PATH_CONFIRM_PATH, 1) != 0) {
            int rollback_ok;

            if (status) *status = 500;
            json_object_put(upstream);
            upstream = webd_error("smart_path_confirm_failed",
                                  "智能路径确认标记写入失败，已回滚",
                                  WEBD_SMART_PATH_CONFIRM_PATH,
                                  "webd.network.wan_policy");
            route_restore = webd_route_config_set(previous_config, NULL);
            rollback_ok = app_ubus_response_ok(route_restore);
            json_object_object_add(upstream, "route_rollback_ok",
                                   json_object_new_boolean(rollback_ok));
            webd_wan_policy_transition("smart_path_confirm",
                                       "confirm_file_write_failed");
            goto restore_files;
        }
        webd_wan_policy_transition("active", "");
    } else {
        webd_wan_policy_last_success_readback_at = time(NULL);
        webd_wan_policy_transition("active", "");
    }
    data = webd_data_or_self_from_jmx_response(upstream);
    if (data && json_object_is_type(data, json_type_object)) {
        json_object_object_add(data, "requested_mode", json_object_new_string(route_apply_mode));
        json_object_object_add(data, "configured_mode", json_object_new_string(route_apply_mode));
        json_object_object_add(data, "effective_mode", json_object_new_string(route_apply_mode));
        json_object_object_add(data, "selected_mode", json_object_new_string(route_apply_mode));
        json_object_object_add(data, "fallback_mode", json_object_new_string(
            route_apply_mode));
        json_object_object_add(data, "base_mode",
                               json_object_new_string(route_apply_mode));
        json_object_object_add(data, "configured_base_mode",
                               json_object_new_string(route_apply_mode));
        json_object_object_add(data, "effective_base_mode",
                               json_object_new_string(route_apply_mode));
        if (legacy_adaptive) {
            json_object_object_add(data, "legacy_mode",
                                   json_object_new_string("adaptive_penalty_sticky"));
            json_object_object_add(data, "migration_required",
                                   json_object_new_boolean(1));
        }
        json_object_object_add(data, "smart_path_requested",
                               json_object_new_boolean(enabling_smart));
        json_object_object_add(data, "existing_connections",
                               json_object_new_string("unchanged"));
        json_object_object_add(data, "activation_state",
                               json_object_new_string("active"));
        json_object_object_add(data, "last_transition_at",
                               json_object_new_int64((int64_t)webd_wan_policy_last_transition_at));
        json_object_object_add(data, "last_success_readback_at",
                               json_object_new_int64((int64_t)webd_wan_policy_last_success_readback_at));
    }
    if (data) json_object_put(data);
    if (status) *status = 200;
    goto out;

restore_files:
    if (webd_wan_policy_set_file(WEBD_SMART_PATH_ENABLE_PATH,
                                 previous_enabled) != 0 ||
        webd_wan_policy_set_file(WEBD_SMART_PATH_CONFIRM_PATH,
                                 previous_confirmed) != 0) {
        if (upstream && json_object_is_type(upstream, json_type_object))
            json_object_object_add(upstream, "rollback_warning",
                                   json_object_new_string("smart_path_file_restore_failed"));
    }
out:
    if (request) json_object_put(request);
    if (smart_status) json_object_put(smart_status);
    if (route_restore) json_object_put(route_restore);
    if (previous_config) json_object_put(previous_config);
    if (previous_config_upstream) json_object_put(previous_config_upstream);
    flock(lockfd, LOCK_UN);
    close(lockfd);
    return upstream;
}

static struct json_object *webd_wan_policy_flowd_status(void)
{
    return app_ubus_invoke_object_timeout("dreamingwrt.flowd", "status", NULL, 500);
}

static int webd_wan_policy_sticky_mode(const char *mode)
{
    if (!mode || !mode[0]) return -1;
    if (!strcmp(mode, "weighted_new_flow_rr") || !strcmp(mode, "new_conn") ||
        !strcmp(mode, "load_balance")) return 0;
    if (!strcmp(mode, "hash_src") || !strcmp(mode, "sip")) return 1;
    if (!strcmp(mode, "hash_src_sport") || !strcmp(mode, "sip_sport") ||
        !strcmp(mode, "sip+sport")) return 2;
    if (!strcmp(mode, "hash_src_dst") || !strcmp(mode, "sip_dip") ||
        !strcmp(mode, "sip+dip")) return 3;
    if (!strcmp(mode, "hash_src_dst_dport") || !strcmp(mode, "sip_dip_dport") ||
        !strcmp(mode, "sip+dip+dport")) return 4;
    if (!strcmp(mode, "five_tuple") || !strcmp(mode, "5tuple")) return 5;
    if (!strcmp(mode, "primary_backup") || !strcmp(mode, "primary-backup")) return 6;
    if (!strcmp(mode, "least_rx_load_normalized") || !strcmp(mode, "download")) return 7;
    if (!strcmp(mode, "least_active_conn_normalized") || !strcmp(mode, "conn_cnt") ||
        !strcmp(mode, "conn-count") || !strcmp(mode, "connection_count")) return 8;
    if (!strcmp(mode, "adaptive_penalty_sticky") ||
        !strcmp(mode, "adaptive-penalty-sticky")) return 9;
    return -1;
}

static const char *webd_wan_policy_base_mode_name(int mode)
{
    static const char *const names[] = {
        "weighted_new_flow_rr", "hash_src", "hash_src_sport", "hash_src_dst",
        "hash_src_dst_dport", "five_tuple", "primary_backup",
        "least_rx_load_normalized", "least_active_conn_normalized"
    };

    return mode >= 0 && mode < (int)(sizeof(names) / sizeof(names[0])) ?
        names[mode] : NULL;
}

static int webd_wan_policy_resolve_base_mode(struct json_object *body,
                                              const char **base_mode,
                                              int *legacy_adaptive,
                                              const char **error_code,
                                              char *error, size_t error_len)
{
    static const char *const fields[] = {
        "base_mode", "mode", "algorithm", "sticky_mode"
    };
    int selected = -1;
    int saw_base = 0;
    int saw_legacy_adaptive = 0;
    size_t i;

    if (base_mode)
        *base_mode = NULL;
    if (legacy_adaptive)
        *legacy_adaptive = 0;
    if (error_code)
        *error_code = "invalid_base_mode";
    for (i = 0; body && i < sizeof(fields) / sizeof(fields[0]); i++) {
        struct json_object *value = NULL;
        const char *name;
        int mode;

        if (!json_object_object_get_ex(body, fields[i], &value))
            continue;
        if (!value || !json_object_is_type(value, json_type_string)) {
            snprintf(error, error_len, "%s must be a string", fields[i]);
            return -1;
        }
        name = json_object_get_string(value);
        mode = webd_wan_policy_sticky_mode(name);
        if (mode < 0) {
            snprintf(error, error_len, "unsupported WAN policy base mode: %s", name);
            return -1;
        }
        if (i == 0)
            saw_base = 1;
        if (mode == 9) {
            if (i == 0) {
                if (error_code) *error_code = "base_mode_conflict";
                snprintf(error, error_len,
                         "adaptive_penalty_sticky is an enhancement, not a base_mode");
                return -1;
            }
            saw_legacy_adaptive = 1;
            continue;
        }
        if (selected >= 0 && selected != mode) {
            if (error_code) *error_code = "base_mode_conflict";
            snprintf(error, error_len,
                     "base_mode, mode, algorithm, and sticky_mode must agree");
            return -1;
        }
        selected = mode;
    }
    if (saw_legacy_adaptive) {
        if (saw_base || selected >= 0) {
            if (error_code) *error_code = "base_mode_conflict";
            snprintf(error, error_len,
                     "legacy adaptive mode cannot be combined with another base mode");
            return -1;
        }
        selected = 0;
    }
    if (selected < 0) {
        snprintf(error, error_len, "%s", "base_mode is required");
        return -1;
    }
    if (base_mode)
        *base_mode = webd_wan_policy_base_mode_name(selected);
    if (legacy_adaptive)
        *legacy_adaptive = saw_legacy_adaptive;
    return 0;
}

static const char *webd_wan_policy_payload_error_code(const char *error)
{
    if (error && !strncmp(error, "base_mode_conflict", 18))
        return "base_mode_conflict";
    if (error && (strstr(error, "must be boolean") ||
                  strstr(error, "must be {enabled:boolean}") ||
                  strstr(error, "must be null or {enabled:boolean}")))
        return "invalid_enhancement_type";
    if (error && (strstr(error, "base mode") ||
                  strstr(error, "base_mode") ||
                  strstr(error, "WAN policy mode")))
        return "invalid_base_mode";
    return "invalid_payload";
}

static int webd_wan_policy_runtime_rule_matches_mode(
    struct json_object *configured_rule, struct json_object *runtime_rule,
    struct json_object *status_data)
{
    int expected_mode;
    int adaptive;
    int abi_v2;
    int expected_enhancements;

    if (!configured_rule || !runtime_rule)
        return 0;
    expected_mode = webd_wan_policy_sticky_mode(app_nc_json_str(
        configured_rule, "base_mode", app_nc_json_str(configured_rule, "algorithm",
            app_nc_json_str(configured_rule, "sticky_mode", ""))));
    adaptive = app_nc_json_bool(configured_rule, "adaptive_penalty_sticky", 0);
    abi_v2 = status_data && app_nc_json_int(status_data, "route_rule_abi", 0) >= 2;
    if (!abi_v2 && adaptive &&
        app_nc_json_bool(configured_rule, "migration_required", 0))
        expected_mode = 9;
    expected_enhancements = abi_v2 && adaptive ? 1 : 0;
    return expected_mode >= 0 &&
        app_nc_json_int(runtime_rule, "sticky_mode", -1) == expected_mode &&
        app_nc_json_int(runtime_rule, "enhancements", 0) == expected_enhancements;
}

static int webd_wan_policy_runtime_members_match(struct json_object *expected,
                                                  const char *actual)
{
    unsigned char expected_seen[256] = {0};
    unsigned char actual_seen[256] = {0};
    char copy[128];
    char *saveptr = NULL;
    char *token;
    int expected_count = 0;
    int actual_count = 0;
    int i;

    if (!expected || !json_object_is_type(expected, json_type_array) ||
        !actual || !actual[0] ||
        snprintf(copy, sizeof(copy), "%s", actual) >= (int)sizeof(copy))
        return 0;
    for (i = 0; i < json_object_array_length(expected); i++) {
        struct json_object *value = json_object_array_get_idx(expected, i);
        int id;

        if (!value || !json_object_is_type(value, json_type_int) ||
            (id = json_object_get_int(value)) <= 0 || id > 255 ||
            expected_seen[id])
            return 0;
        expected_seen[id] = 1;
        expected_count++;
    }
    for (token = strtok_r(copy, ",", &saveptr); token;
         token = strtok_r(NULL, ",", &saveptr)) {
        char *end = NULL;
        unsigned long id;

        errno = 0;
        id = strtoul(token, &end, 10);
        if (errno || end == token || *end || id == 0 || id > 255 ||
            actual_seen[id])
            return 0;
        actual_seen[id] = 1;
        actual_count++;
    }
    return expected_count == actual_count &&
           memcmp(expected_seen, actual_seen, sizeof(expected_seen)) == 0;
}

/*
 * Whether the kernel runtime reports per-member weights for a rule.  A
 * weight-aware jmx.ko prints "id:weight" pairs (route_parse_proc_status fills
 * wan_weights with the parsed values, all >= 1); an older module prints ids
 * only, so wan_weights comes back as "0,0,...".  The configured weight_ratio is
 * always authoritative in config.db; this only tells the UI if the data plane
 * is actually steering by that ratio yet.
 */
static int webd_wan_policy_runtime_weights_enforced(struct json_object *runtime_rule)
{
    const char *weights;
    char copy[128];
    char *saveptr = NULL;
    char *token;

    if (!runtime_rule)
        return 0;
    weights = app_nc_json_str(runtime_rule, "wan_weights", "");
    if (!weights[0] ||
        snprintf(copy, sizeof(copy), "%s", weights) >= (int)sizeof(copy))
        return 0;
    for (token = strtok_r(copy, ",", &saveptr); token;
         token = strtok_r(NULL, ",", &saveptr)) {
        char *end = NULL;
        unsigned long weight;

        errno = 0;
        weight = strtoul(token, &end, 10);
        if (errno || end == token || *end)
            return 0;
        if (weight > 0)
            return 1;
    }
    return 0;
}

static int webd_wan_policy_route_runtime_matches(struct json_object *configured_rule,
                                                  struct json_object *status_data)
{
    struct json_object *runtime_rules = NULL;
    struct json_object *expected_ids = NULL;
    int expected_prio;
    int i;

    if (!configured_rule || !status_data ||
        !app_nc_json_bool(status_data, "available", 0) ||
        !json_object_object_get_ex(configured_rule, "wan_ids", &expected_ids) ||
        !expected_ids || !json_object_is_type(expected_ids, json_type_array) ||
        !json_object_object_get_ex(status_data, "rules", &runtime_rules) ||
        !runtime_rules || !json_object_is_type(runtime_rules, json_type_array))
        return 0;
    expected_prio = app_nc_json_int(configured_rule, "prio", 0);
    if (expected_prio <= 0)
        return 0;
    for (i = 0; i < json_object_array_length(runtime_rules); i++) {
        struct json_object *runtime_rule = json_object_array_get_idx(runtime_rules, i);

        if (!runtime_rule ||
            app_nc_json_int(runtime_rule, "prio", 0) != expected_prio)
            continue;
        return app_nc_json_bool(runtime_rule, "enabled", 0) &&
               webd_wan_policy_runtime_rule_matches_mode(
                   configured_rule, runtime_rule, status_data) &&
               webd_wan_policy_runtime_members_match(expected_ids,
                   app_nc_json_str(runtime_rule, "wan_ids", ""));
    }
    return 0;
}

static int webd_wan_policy_id_valid(const char *value)
{
    size_t i;

    if (!value || !value[0] || strlen(value) > 64)
        return 0;
    for (i = 0; value[i]; i++) {
        unsigned char c = (unsigned char)value[i];

        if (isalnum(c) || c == '_' || c == '-' || c == '.')
            continue;
        return 0;
    }
    return 1;
}

static int webd_wan_policy_carrier_id(const char *carrier)
{
    char *end = NULL;
    unsigned long value;

    if (!carrier || !carrier[0] || !strcasecmp(carrier, "any")) return 0;
    if (!strcasecmp(carrier, "telecom") || !strcasecmp(carrier, "ctcc")) return 1;
    if (!strcasecmp(carrier, "unicom") || !strcasecmp(carrier, "cucc")) return 2;
    if (!strcasecmp(carrier, "mobile") || !strcasecmp(carrier, "cmcc")) return 3;
    if (!strcasecmp(carrier, "edu") || !strcasecmp(carrier, "cernet")) return 4;
    if (!strcasecmp(carrier, "other")) return 5;
    errno = 0;
    value = strtoul(carrier, &end, 0);
    return !errno && end != carrier && !*end && value <= 255 ? (int)value : -1;
}

static struct json_object *webd_wan_policy_find_rule(struct json_object *rules,
                                                      const char *policy_id,
                                                      int *position)
{
    int i;

    if (position)
        *position = -1;
    if (!rules || !json_object_is_type(rules, json_type_array) ||
        !policy_id || !policy_id[0])
        return NULL;
    for (i = 0; i < (int)json_object_array_length(rules); i++) {
        struct json_object *rule = json_object_array_get_idx(rules, i);

        if (!strcmp(app_nc_json_str(rule, "policy_id", ""), policy_id)) {
            if (position)
                *position = i;
            return rule;
        }
    }
    return NULL;
}

static void webd_wan_policies_revision_string(struct json_object *rules,
                                               char *out, size_t out_len)
{
    snprintf(out, out_len, "%llu",
             (unsigned long long)webd_ws_semantic_hash(1469598103934665603ULL,
                                                       rules));
}

static int webd_wan_policy_runtime_state(struct json_object *configured_rule,
                                         struct json_object *status_data,
                                         struct json_object **runtime_rule_out,
                                         int *present_out)
{
    struct json_object *runtime_rules = NULL;
    struct json_object *expected_ids = NULL;
    struct json_object *runtime_rule = NULL;
    const char *carrier;
    int expected_prio;
    int enabled;
    int i;

    if (runtime_rule_out)
        *runtime_rule_out = NULL;
    if (present_out)
        *present_out = 0;
    if (!configured_rule || !status_data ||
        !app_nc_json_bool(status_data, "available", 0) ||
        !json_object_object_get_ex(status_data, "rules", &runtime_rules) ||
        !runtime_rules || !json_object_is_type(runtime_rules, json_type_array))
        return 0;
    expected_prio = app_nc_json_int(configured_rule, "prio", 0);
    for (i = 0; i < (int)json_object_array_length(runtime_rules); i++) {
        struct json_object *candidate = json_object_array_get_idx(runtime_rules, i);

        if (app_nc_json_int(candidate, "prio", 0) == expected_prio) {
            runtime_rule = candidate;
            break;
        }
    }
    if (runtime_rule) {
        if (present_out)
            *present_out = 1;
        if (runtime_rule_out)
            *runtime_rule_out = runtime_rule;
    }
    enabled = app_nc_json_bool(configured_rule, "enabled", 1);
    if (!enabled)
        return runtime_rule == NULL;
    if (!runtime_rule || !app_nc_json_bool(runtime_rule, "enabled", 0))
        return 0;
    if (!webd_wan_policy_runtime_rule_matches_mode(
            configured_rule, runtime_rule, status_data))
        return 0;
    if (json_object_object_get_ex(configured_rule, "wan_ids", &expected_ids) &&
        expected_ids && json_object_is_type(expected_ids, json_type_array) &&
        json_object_array_length(expected_ids) > 0)
        return webd_wan_policy_runtime_members_match(expected_ids,
            app_nc_json_str(runtime_rule, "wan_ids", ""));
    carrier = app_nc_json_str(configured_rule, "carrier", "");
    return webd_wan_policy_carrier_id(carrier) >= 0 &&
           app_nc_json_int(runtime_rule, "carrier_id", -1) ==
               webd_wan_policy_carrier_id(carrier);
}

static struct json_object *webd_wan_policy_member_array_from_ids(
    struct json_object *ids, struct json_object *old_members)
{
    struct json_object *members = json_object_new_array();
    int i;

    if (!members || !ids || !json_object_is_type(ids, json_type_array))
        return members;
    for (i = 0; i < (int)json_object_array_length(ids); i++) {
        struct json_object *value = json_object_array_get_idx(ids, i);
        struct json_object *member = json_object_new_object();
        int wan_id = value && json_object_is_type(value, json_type_int) ?
                     json_object_get_int(value) : 0;
        int weight = 1;
        int j;

        if (!member)
            continue;
        for (j = 0; old_members &&
                    j < (int)json_object_array_length(old_members); j++) {
            struct json_object *old = json_object_array_get_idx(old_members, j);

            if (app_nc_json_int(old, "wan_id", 0) == wan_id) {
                weight = app_nc_json_int(old, "weight", 1);
                break;
            }
        }
        json_object_object_add(member, "wan_id", json_object_new_int(wan_id));
        json_object_object_add(member, "weight", json_object_new_int(weight > 0 ? weight : 1));
        json_object_array_add(members, member);
    }
    return members;
}

static int webd_wan_policy_replace_members(struct json_object *rule,
                                           struct json_object *body,
                                           char *error, size_t error_len)
{
    struct json_object *members = NULL;
    struct json_object *ids = NULL;
    struct json_object *old_members = NULL;
    struct json_object *new_ids = NULL;
    struct json_object *new_members = NULL;
    int i;

    if (!json_object_object_get_ex(body, "members", &members) &&
        !json_object_object_get_ex(body, "wan_ids", &ids))
        return 0;
    json_object_object_get_ex(rule, "members", &old_members);
    if (members) {
        if (!json_object_is_type(members, json_type_array)) {
            snprintf(error, error_len, "%s", "members must be an array");
            return -1;
        }
        new_ids = json_object_new_array();
        new_members = webd_json_clone(members);
        if (!new_ids || !new_members)
            goto nomem;
        for (i = 0; i < (int)json_object_array_length(members); i++) {
            struct json_object *member = json_object_array_get_idx(members, i);
            struct json_object *wan_id = NULL;

            if (!member || !json_object_is_type(member, json_type_object) ||
                !json_object_object_get_ex(member, "wan_id", &wan_id) ||
                !wan_id || !json_object_is_type(wan_id, json_type_int)) {
                snprintf(error, error_len, "%s",
                         "members must contain integer wan_id values");
                goto invalid;
            }
            json_object_array_add(new_ids, json_object_get(wan_id));
        }
        if (ids && (!json_object_is_type(ids, json_type_array) ||
                    !json_object_equal(ids, new_ids))) {
            snprintf(error, error_len, "%s",
                     "members must match wan_ids in order");
            goto invalid;
        }
    } else {
        if (!ids || !json_object_is_type(ids, json_type_array)) {
            snprintf(error, error_len, "%s", "wan_ids must be an array");
            return -1;
        }
        new_ids = webd_json_clone(ids);
        new_members = webd_wan_policy_member_array_from_ids(ids, old_members);
        if (!new_ids || !new_members)
            goto nomem;
    }
    json_object_object_del(rule, "wan_ids");
    json_object_object_del(rule, "members");
    json_object_object_del(rule, "dangling_wan_ids");
    json_object_object_add(rule, "wan_ids", new_ids);
    json_object_object_add(rule, "members", new_members);
    return 0;

nomem:
    snprintf(error, error_len, "%s", "could not allocate WAN policy members");
invalid:
    if (new_ids) json_object_put(new_ids);
    if (new_members) json_object_put(new_members);
    return -1;
}

static void webd_wan_policy_merge_optional(struct json_object *rule,
                                           struct json_object *body,
                                           const char *key)
{
    struct json_object *value = NULL;

    if (!json_object_object_get_ex(body, key, &value))
        return;
    json_object_object_del(rule, key);
    if (value && !json_object_is_type(value, json_type_null))
        json_object_object_add(rule, key, json_object_get(value));
}

/* Smart Path is a policy-scoped overlay.  Keep the three-state value in the
 * route config so an omitted field means inherit, while false remains an
 * explicit per-policy disable. */
static int webd_wan_policy_merge_smart_path(struct json_object *rule,
                                            struct json_object *body,
                                            char *error, size_t error_len)
{
    struct json_object *smart = NULL;
    struct json_object *enabled = NULL;
    const char *mode = "inherit";

    if (!json_object_object_get_ex(body, "smart_path", &smart))
        return 0;
    if (smart && json_object_is_type(smart, json_type_object) &&
        json_object_object_get_ex(smart, "enabled", &enabled) && enabled &&
        json_object_is_type(enabled, json_type_boolean))
        mode = json_object_get_boolean(enabled) ? "enabled" : "disabled";
    else if (smart && !json_object_is_type(smart, json_type_null)) {
        snprintf(error, error_len, "%s",
                 "smart_path must be null or {enabled:boolean}");
        return -1;
    }
    json_object_object_del(rule, "smart_path_mode");
    json_object_object_add(rule, "smart_path_mode", json_object_new_string(mode));
    return 0;
}

static int webd_wan_policy_merge_adaptive(struct json_object *rule,
                                          struct json_object *body,
                                          char *error, size_t error_len)
{
    struct json_object *adaptive = NULL;
    struct json_object *enabled = NULL;

    if (!json_object_object_get_ex(body, "adaptive_penalty_sticky", &adaptive))
        return 0;
    if (!adaptive || !json_object_is_type(adaptive, json_type_object) ||
        !json_object_object_get_ex(adaptive, "enabled", &enabled) || !enabled ||
        !json_object_is_type(enabled, json_type_boolean)) {
        snprintf(error, error_len, "%s",
                 "adaptive_penalty_sticky must be {enabled:boolean}");
        return -1;
    }
    json_object_object_del(rule, "adaptive_penalty_sticky");
    json_object_object_add(rule, "adaptive_penalty_sticky",
                           json_object_new_boolean(json_object_get_boolean(enabled)));
    json_object_object_del(rule, "legacy_mode");
    json_object_object_del(rule, "migration_required");
    json_object_object_add(rule, "migration_required", json_object_new_boolean(0));
    return 0;
}

static int webd_wan_policy_merge_rule(struct json_object *rule,
                                      struct json_object *body,
                                      int creating,
                                      char *error, size_t error_len)
{
    static const char *const fields[] = {
        "name", "carrier", "proto", "src_addr", "src_mask", "dst_addr",
        "dst_mask", "appid", "dst_port", "reinstate_dangling"
    };
    struct json_object *value = NULL;
    struct json_object *id_obj = NULL;
    struct json_object *policy_id_obj = NULL;
    const char *existing_id = app_nc_json_str(rule, "policy_id", "");
    const char *requested_id = NULL;
    const char *mode = NULL;
    const char *mode_error_code = NULL;
    int legacy_adaptive = 0;
    int has_mode_field = 0;
    size_t i;

    if (!body || !json_object_is_type(body, json_type_object)) {
        snprintf(error, error_len, "%s", "WAN policy must be a JSON object");
        return -1;
    }
    json_object_object_get_ex(body, "id", &id_obj);
    json_object_object_get_ex(body, "policy_id", &policy_id_obj);
    if (id_obj) {
        if (!json_object_is_type(id_obj, json_type_string)) {
            snprintf(error, error_len, "%s", "id must be a string");
            return -1;
        }
        requested_id = json_object_get_string(id_obj);
    }
    if (policy_id_obj) {
        if (!json_object_is_type(policy_id_obj, json_type_string)) {
            snprintf(error, error_len, "%s", "policy_id must be a string");
            return -1;
        }
        const char *value_id = json_object_get_string(policy_id_obj);

        if (requested_id && strcmp(requested_id, value_id)) {
            snprintf(error, error_len, "%s", "id and policy_id must match");
            return -1;
        }
        requested_id = value_id;
    }
    if (requested_id) {
        if (!webd_wan_policy_id_valid(requested_id)) {
            snprintf(error, error_len, "%s", "invalid WAN policy id");
            return -1;
        }
        if (!creating && strcmp(existing_id, requested_id)) {
            snprintf(error, error_len, "%s", "policy_id is immutable");
            return -1;
        }
        json_object_object_del(rule, "policy_id");
        json_object_object_add(rule, "policy_id", json_object_new_string(requested_id));
    }
    for (i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
        webd_wan_policy_merge_optional(rule, body, fields[i]);
    webd_wan_policy_merge_optional(rule, body, "fallback_policy_id");
    if (webd_wan_policy_merge_smart_path(rule, body, error, error_len) != 0)
        return -1;
    if (json_object_object_get_ex(body, "enabled", &value)) {
        if (!value || !json_object_is_type(value, json_type_boolean)) {
            snprintf(error, error_len, "%s", "enabled must be boolean");
            return -1;
        }
        json_object_object_del(rule, "enabled");
        json_object_object_add(rule, "enabled",
                               json_object_new_boolean(json_object_get_boolean(value)));
    } else if (json_object_object_get_ex(body, "active", &value)) {
        if (!value || !json_object_is_type(value, json_type_boolean)) {
            snprintf(error, error_len, "%s", "active must be boolean");
            return -1;
        }
        json_object_object_del(rule, "enabled");
        json_object_object_add(rule, "enabled",
                               json_object_new_boolean(json_object_get_boolean(value)));
    }
    if (json_object_object_get_ex(body, "priority", &value) ||
        json_object_object_get_ex(body, "prio", &value)) {
        json_object_object_del(rule, "prio");
        json_object_object_add(rule, "prio", json_object_get(value));
    }
    has_mode_field = json_object_object_get_ex(body, "base_mode", &value) ||
        json_object_object_get_ex(body, "mode", &value) ||
        json_object_object_get_ex(body, "algorithm", &value) ||
        json_object_object_get_ex(body, "sticky_mode", &value);
    if (has_mode_field &&
        webd_wan_policy_resolve_base_mode(body, &mode, &legacy_adaptive,
                                          &mode_error_code,
                                          error, error_len) != 0) {
        if (mode_error_code && !strcmp(mode_error_code, "base_mode_conflict")) {
            char detail[192];

            JMX_STRBUF_COPY(detail, error);
            (void)snprintf(error, error_len, "base_mode_conflict: %.170s", detail);
        }
        return -1;
    }
    if (mode) {
        json_object_object_del(rule, "sticky_mode");
        json_object_object_del(rule, "algorithm");
        json_object_object_del(rule, "base_mode");
        json_object_object_add(rule, "sticky_mode", json_object_new_string(mode));
        json_object_object_add(rule, "algorithm", json_object_new_string(mode));
        json_object_object_add(rule, "base_mode", json_object_new_string(mode));
    }
    if (webd_wan_policy_merge_adaptive(rule, body, error, error_len) != 0)
        return -1;
    if (legacy_adaptive) {
        struct json_object *adaptive = NULL;
        struct json_object *enabled = NULL;

        if (json_object_object_get_ex(body, "adaptive_penalty_sticky", &adaptive) &&
            adaptive && json_object_is_type(adaptive, json_type_object) &&
            json_object_object_get_ex(adaptive, "enabled", &enabled) && enabled &&
            !json_object_get_boolean(enabled)) {
            snprintf(error, error_len, "%s",
                     "base_mode_conflict: legacy adaptive mode conflicts with disabled enhancement");
            return -1;
        }
        json_object_object_del(rule, "adaptive_penalty_sticky");
        json_object_object_add(rule, "adaptive_penalty_sticky",
                               json_object_new_boolean(1));
        json_object_object_del(rule, "legacy_mode");
        json_object_object_add(rule, "legacy_mode",
                               json_object_new_string("adaptive_penalty_sticky"));
        json_object_object_del(rule, "migration_required");
        json_object_object_add(rule, "migration_required",
                               json_object_new_boolean(1));
    } else if (has_mode_field) {
        json_object_object_del(rule, "legacy_mode");
        json_object_object_del(rule, "migration_required");
        json_object_object_add(rule, "migration_required",
                               json_object_new_boolean(0));
    }
    return webd_wan_policy_replace_members(rule, body, error, error_len);
}

static int webd_wan_policy_next_priority(struct json_object *rules)
{
    int priority;

    for (priority = 1000; priority <= 65535; priority++) {
        int used = 0;
        int i;

        for (i = 0; rules && i < (int)json_object_array_length(rules); i++) {
            if (app_nc_json_int(json_object_array_get_idx(rules, i), "prio", 0) ==
                priority) {
                used = 1;
                break;
            }
        }
        if (!used)
            return priority;
    }
    return -1;
}

static struct json_object *webd_wan_policy_new_rule(struct json_object *body,
                                                     struct json_object *rules,
                                                     char *error, size_t error_len)
{
    struct json_object *rule = json_object_new_object();
    struct json_object *value = NULL;
    char generated[40];
    char random_id[17];
    int64_t created_at;
    int priority;

    if (!rule)
        return NULL;
    if (!json_object_object_get_ex(body, "id", &value) &&
        !json_object_object_get_ex(body, "policy_id", &value)) {
        if (gen_random_hex_checked(random_id, 16) != 0) {
            snprintf(error, error_len, "%s", "strong randomness is unavailable");
            json_object_put(rule);
            return NULL;
        }
        snprintf(generated, sizeof(generated), "wan-policy-%s", random_id);
        json_object_object_add(rule, "policy_id", json_object_new_string(generated));
    }
    priority = webd_wan_policy_next_priority(rules);
    if (priority < 0) {
        snprintf(error, error_len, "%s", "no WAN policy priority is available");
        json_object_put(rule);
        return NULL;
    }
    json_object_object_add(rule, "name", json_object_new_string(""));
    json_object_object_add(rule, "enabled", json_object_new_boolean(1));
    json_object_object_add(rule, "prio", json_object_new_int(priority));
    json_object_object_add(rule, "appid", json_object_new_int(0));
    json_object_object_add(rule, "proto", json_object_new_string("any"));
    json_object_object_add(rule, "dst_port", json_object_new_int(0));
    json_object_object_add(rule, "reinstate_dangling", json_object_new_int(1));
    json_object_object_add(rule, "sticky_mode",
                           json_object_new_string("weighted_new_flow_rr"));
    json_object_object_add(rule, "algorithm",
                           json_object_new_string("weighted_new_flow_rr"));
    json_object_object_add(rule, "base_mode",
                           json_object_new_string("weighted_new_flow_rr"));
    json_object_object_add(rule, "adaptive_penalty_sticky",
                           json_object_new_boolean(0));
    json_object_object_add(rule, "migration_required",
                           json_object_new_boolean(0));
    json_object_object_add(rule, "wan_ids", json_object_new_array());
    json_object_object_add(rule, "members", json_object_new_array());
    if (webd_wan_policy_merge_rule(rule, body, 1, error, error_len) != 0) {
        json_object_put(rule);
        return NULL;
    }
    if (!app_nc_json_str(rule, "name", "")[0]) {
        const char *policy_id = app_nc_json_str(rule, "policy_id", "");

        json_object_object_del(rule, "name");
        json_object_object_add(rule, "name", json_object_new_string(policy_id));
    }
    created_at = now_s();
    json_object_object_add(rule, "created_at", json_object_new_int64(created_at));
    json_object_object_add(rule, "updated_at", json_object_new_int64(created_at));
    return rule;
}

static int webd_wan_policy_is_fallback(struct json_object *rules,
                                       const char *policy_id,
                                       struct json_object *fallback_for)
{
    int found = 0;
    int i;

    for (i = 0; rules && i < (int)json_object_array_length(rules); i++) {
        struct json_object *rule = json_object_array_get_idx(rules, i);

        if (strcmp(app_nc_json_str(rule, "fallback_policy_id", ""), policy_id))
            continue;
        found = 1;
        if (fallback_for)
            json_object_array_add(fallback_for, json_object_new_string(
                app_nc_json_str(rule, "policy_id", "")));
    }
    return found;
}

static struct json_object *webd_wan_policy_contract_item(struct json_object *rule,
                                                         struct json_object *rules,
                                                         struct json_object *status_data,
                                                         struct json_object *flowd_data)
{
    struct json_object *item = json_object_new_object();
    struct json_object *value = NULL;
    struct json_object *fallback_for = json_object_new_array();
    struct json_object *runtime_rule = NULL;
    const char *policy_id = app_nc_json_str(rule, "policy_id", "");
    int enabled = app_nc_json_bool(rule, "enabled", 1);
    int runtime_present = 0;
    int64_t created_at = app_nc_json_int64(rule, "created_at", 0);
    int64_t updated_at = app_nc_json_int64(rule, "updated_at", 0);
    int runtime_applied = webd_wan_policy_runtime_state(rule, status_data,
                                                        &runtime_rule,
                                                        &runtime_present);
    int effective = enabled && runtime_applied;
    const char *smart_mode = app_nc_json_str(rule, "smart_path_mode", "inherit");
    struct json_object *smart_status = NULL;
    struct json_object *policy_runtime = NULL;
    int smart_supported = 0;
    int global_smart_requested = 0;
    int smart_requested;
    int smart_effective = 0;
    int smart_runtime_applied = 0;
    const char *smart_reason = "policy_smart_path_executor_unavailable";
    int adaptive_configured = app_nc_json_bool(rule, "adaptive_penalty_sticky", 0);
    int adaptive_effective = adaptive_configured && runtime_applied;
    int adaptive_runtime_applied = !adaptive_configured || adaptive_effective;
    const char *base_mode = app_nc_json_str(rule, "base_mode",
        app_nc_json_str(rule, "algorithm",
            app_nc_json_str(rule, "sticky_mode", "hash_src")));
    int i;

    if (flowd_data && json_object_is_type(flowd_data, json_type_object) &&
        json_object_object_get_ex(flowd_data, "smart_path", &smart_status) &&
        smart_status && json_object_is_type(smart_status, json_type_object)) {
        struct json_object *capabilities = NULL;

        /* The sentinel alone.  This feeds the `inherit` branch below, and an
         * `inherit` policy must not inherit "some *other* policy turned smart
         * path on" -- which is exactly what enabled_requested means.  The old
         * fallback was both wrong and unreachable. */
        global_smart_requested = app_nc_json_bool(smart_status,
                                                  "global_enabled_requested", 0);
        smart_supported = app_nc_json_bool(smart_status, "policy_scoped", 0);
        if (json_object_object_get_ex(smart_status, "capabilities", &capabilities) &&
            capabilities && json_object_is_type(capabilities, json_type_object))
            smart_supported = smart_supported ||
                app_nc_json_bool(capabilities, "policy_scoped", 0);
        json_object_object_get_ex(smart_status, "policy_runtime", &policy_runtime);
    }
    /* `status` nests the executor state under smart_path, while the explicit
     * reconcile method returns that same state at the root.  Both are valid
     * readback sources for this collection response. */
    if (!policy_runtime && flowd_data &&
        json_object_is_type(flowd_data, json_type_object) &&
        json_object_object_get_ex(flowd_data, "policy_runtime", &policy_runtime)) {
        smart_supported = app_nc_json_bool(flowd_data, "policy_scoped", 0) ||
            app_nc_json_bool(flowd_data, "policy_config_ready", 0);
        global_smart_requested = app_nc_json_bool(flowd_data,
                                                  "global_enabled_requested", 0);
    }
    smart_requested = !strcmp(smart_mode, "enabled") ||
        (!strcmp(smart_mode, "inherit") && global_smart_requested);
    if (!strcmp(smart_mode, "disabled"))
        smart_reason = "disabled_as_configured";
    else if (!smart_requested)
        smart_reason = !strcmp(smart_mode, "inherit") ?
            "global_smart_path_disabled" : "disabled_as_configured";
    for (i = 0; policy_runtime && i < (int)json_object_array_length(policy_runtime); i++) {
        struct json_object *candidate = json_object_array_get_idx(policy_runtime, i);

        if (app_nc_json_int(candidate, "prio", 0) !=
            app_nc_json_int(rule, "prio", 0))
            continue;
        smart_effective = app_nc_json_bool(candidate, "effective", 0);
        smart_runtime_applied = app_nc_json_bool(candidate, "runtime_applied", 0);
        smart_reason = app_nc_json_str(candidate, "runtime_reason", smart_reason);
        break;
    }
    if (smart_requested && !smart_effective && smart_supported &&
        !policy_runtime)
        smart_reason = "policy_runtime_pending";

    if (!item || !fallback_for) {
        if (item) json_object_put(item);
        if (fallback_for) json_object_put(fallback_for);
        return NULL;
    }
    json_object_object_add(item, "id", json_object_new_string(policy_id));
    json_object_object_add(item, "policy_id", json_object_new_string(policy_id));
    json_object_object_add(item, "name", json_object_new_string(
        app_nc_json_str(rule, "name", policy_id)));
    json_object_object_add(item, "enabled", json_object_new_boolean(enabled));
    json_object_object_add(item, "active", json_object_new_boolean(effective));
    json_object_object_add(item, "status", json_object_new_string(
        !enabled ? "disabled" : (effective ? "active" : "degraded")));
    json_object_object_add(item, "priority", json_object_new_int(
        app_nc_json_int(rule, "prio", 0)));
    json_object_object_add(item, "prio", json_object_new_int(
        app_nc_json_int(rule, "prio", 0)));
    json_object_object_add(item, "mode", json_object_new_string(
        base_mode));
    json_object_object_add(item, "algorithm", json_object_new_string(
        base_mode));
    json_object_object_add(item, "base_mode", json_object_new_string(base_mode));
    json_object_object_add(item, "configured_base_mode", json_object_new_string(base_mode));
    json_object_object_add(item, "effective_base_mode", json_object_new_string(
        runtime_applied ? base_mode : ""));
    webd_copy_field_if_present(item, rule, "legacy_mode");
    json_object_object_add(item, "migration_required", json_object_new_boolean(
        app_nc_json_bool(rule, "migration_required", 0)));
    json_object_object_add(item, "carrier", json_object_new_string(
        app_nc_json_str(rule, "carrier", "")));
    json_object_object_add(item, "fallback_policy_id", json_object_new_string(
        app_nc_json_str(rule, "fallback_policy_id", "")));
    json_object_object_add(item, "configured", json_object_new_boolean(1));
    json_object_object_add(item, "effective", json_object_new_boolean(effective));
    json_object_object_add(item, "runtime_applied",
                           json_object_new_boolean(runtime_applied));
    json_object_object_add(item, "runtime_reason", json_object_new_string(
        !status_data ? "route_status_unavailable" :
        (!enabled && runtime_applied ? "disabled_as_configured" :
         (runtime_applied ? "kernel_readback_matches" :
          (runtime_present ? "kernel_readback_mismatch" : "kernel_rule_missing")))));
    json_object_object_add(item, "existing_connections",
                           json_object_new_string("unchanged"));
    json_object_object_add(item, "apply_disruption",
                           json_object_new_string("new_connections_only"));
    json_object_object_add(item, "is_fallback", json_object_new_boolean(
        webd_wan_policy_is_fallback(rules, policy_id, fallback_for)));
    json_object_object_add(item, "fallback_for", fallback_for);
    if (json_object_object_get_ex(rule, "wan_ids", &value) && value)
        json_object_object_add(item, "wan_ids", json_object_get(value));
    else
        json_object_object_add(item, "wan_ids", json_object_new_array());
    if (json_object_object_get_ex(rule, "members", &value) && value)
        json_object_object_add(item, "members", json_object_get(value));
    else
        json_object_object_add(item, "members", json_object_new_array());
    json_object_object_add(item, "weight_ratio", json_object_new_string(
        app_nc_json_str(rule, "weight_ratio", "")));
    json_object_object_add(item, "member_weights_explicit",
                           json_object_new_boolean(
                               app_nc_json_bool(rule, "member_weights_explicit", 0)));
    {
        int weights_enforced = runtime_rule ?
            webd_wan_policy_runtime_weights_enforced(runtime_rule) : 0;
        int has_explicit = app_nc_json_bool(rule, "member_weights_explicit", 0);

        json_object_object_add(item, "weight_runtime_enforced",
                               json_object_new_boolean(weights_enforced));
        json_object_object_add(item, "weight_runtime_reason",
            json_object_new_string(
                !status_data ? "route_status_unavailable" :
                (!runtime_rule ? "kernel_rule_missing" :
                 (weights_enforced ? "kernel_reports_per_member_weights" :
                  (has_explicit ?
                   "kernel_module_ids_only_weight_ratio_configured_not_enforced" :
                   "uniform_weights_no_ratio_to_enforce")))));
    }
    webd_copy_field_if_present(item, rule, "wan_selection");
    webd_copy_field_if_present(item, rule, "dangling_wan_ids");
    webd_copy_field_if_present(item, rule, "proto");
    webd_copy_field_if_present(item, rule, "appid");
    webd_copy_field_if_present(item, rule, "src_addr");
    webd_copy_field_if_present(item, rule, "src_mask");
    webd_copy_field_if_present(item, rule, "dst_addr");
    webd_copy_field_if_present(item, rule, "dst_mask");
    webd_copy_field_if_present(item, rule, "dst_port");
    if (runtime_rule) {
        webd_copy_field_if_present(item, runtime_rule, "hit_count");
        webd_copy_field_if_present(item, runtime_rule, "last_hit_seconds_ago");
    }
    json_object_object_add(item, "created_at", created_at > 0 ?
                           json_object_new_int64(created_at) : json_object_new_null());
    json_object_object_add(item, "updated_at", updated_at > 0 ?
                           json_object_new_int64(updated_at) : json_object_new_null());
    json_object_object_add(item, "timestamps_known",
                           json_object_new_boolean(created_at > 0 && updated_at > 0));
    json_object_object_add(item, "timestamps_supported", json_object_new_boolean(1));
    {
        struct json_object *smart = json_object_new_object();

        json_object_object_add(smart, "scope",
                               json_object_new_string("per_policy"));
        json_object_object_add(smart, "supported",
                               json_object_new_boolean(smart_supported));
        json_object_object_add(smart, "configured",
                               json_object_new_boolean(strcmp(smart_mode, "inherit") != 0));
        json_object_object_add(smart, "requested",
                               json_object_new_boolean(smart_requested));
        json_object_object_add(smart, "effective",
                               json_object_new_boolean(smart_effective));
        json_object_object_add(smart, "runtime_applied",
                               json_object_new_boolean(smart_runtime_applied));
        json_object_object_add(smart, "runtime_reason",
                               json_object_new_string(smart_reason));
        json_object_object_add(smart, "mode",
                               json_object_new_string(smart_mode));
        json_object_object_add(smart, "base_mode",
                               json_object_new_string(base_mode));
        json_object_object_add(smart, "overlay_mode",
                               json_object_new_string("smart_path"));
        json_object_object_add(smart, "existing_connections",
                               json_object_new_string("unchanged"));
        json_object_object_add(smart, "apply_disruption",
                               json_object_new_string("new_connections_only"));
        json_object_object_add(item, "smart_path", smart);
    }
    {
        struct json_object *adaptive = json_object_new_object();

        json_object_object_add(adaptive, "scope", json_object_new_string("per_policy"));
        json_object_object_add(adaptive, "available", json_object_new_boolean(1));
        json_object_object_add(adaptive, "writable", json_object_new_boolean(1));
        json_object_object_add(adaptive, "is_base_mode", json_object_new_boolean(0));
        json_object_object_add(adaptive, "can_overlay_any_base_mode",
                               json_object_new_boolean(1));
        json_object_object_add(adaptive, "conflicts_with", json_object_new_array());
        json_object_object_add(adaptive, "requested",
                               json_object_new_boolean(adaptive_configured));
        json_object_object_add(adaptive, "configured",
                               json_object_new_boolean(adaptive_configured));
        json_object_object_add(adaptive, "effective",
                               json_object_new_boolean(adaptive_effective));
        json_object_object_add(adaptive, "runtime_applied",
                               json_object_new_boolean(adaptive_runtime_applied));
        json_object_object_add(adaptive, "runtime_reason", json_object_new_string(
            !status_data ? "route_status_unavailable" :
            (!adaptive_configured ? "disabled_as_configured" :
             (adaptive_effective ? "adaptive_penalty_ready" :
                                   "adaptive_penalty_readback_mismatch"))));
        json_object_object_add(adaptive, "existing_connections",
                               json_object_new_string("unchanged"));
        json_object_object_add(adaptive, "apply_disruption",
                               json_object_new_string("new_connections_only"));
        json_object_object_add(item, "adaptive_penalty_sticky", adaptive);
    }
    return item;
}

static struct json_object *webd_wan_policies_collection_data(
    struct json_object *config, struct json_object *status_data,
    struct json_object *flowd_data)
{
    struct json_object *rules = NULL;
    struct json_object *out = json_object_new_object();
    struct json_object *policies = json_object_new_array();
    struct json_object *routes = json_object_new_array();
    char revision[32];
    int all_runtime_applied = status_data != NULL;
    int any_weighted_policy = 0;
    int all_weighted_enforced = 1;
    int i;

    if (!out || !policies || !routes) {
        if (out) json_object_put(out);
        if (policies) json_object_put(policies);
        if (routes) json_object_put(routes);
        return NULL;
    }
    json_object_object_get_ex(config, "rules", &rules);
    for (i = 0; rules && i < (int)json_object_array_length(rules); i++) {
        struct json_object *item = webd_wan_policy_contract_item(
            json_object_array_get_idx(rules, i), rules, status_data, flowd_data);

        if (item) {
            if (!app_nc_json_bool(item, "runtime_applied", 0))
                all_runtime_applied = 0;
            if (app_nc_json_bool(item, "member_weights_explicit", 0) ||
                strcmp(app_nc_json_str(item, "weight_ratio", ""), "") != 0) {
                const char *reason = app_nc_json_str(item,
                    "weight_runtime_reason", "");
                if (!strcmp(reason,
                    "kernel_module_ids_only_weight_ratio_configured_not_enforced")) {
                    any_weighted_policy = 1;
                    all_weighted_enforced = 0;
                } else if (app_nc_json_bool(item, "weight_runtime_enforced", 0)) {
                    any_weighted_policy = 1;
                }
            }
            json_object_array_add(policies, item);
        }
    }
    webd_wan_policies_revision_string(rules, revision, sizeof(revision));
    json_object_array_add(routes, json_object_new_string("POST /api/v1/network/wan-policies"));
    json_object_array_add(routes, json_object_new_string("PATCH /api/v1/network/wan-policies/{policy_id}"));
    json_object_array_add(routes, json_object_new_string("DELETE /api/v1/network/wan-policies/{policy_id}"));
    json_object_array_add(routes, json_object_new_string("POST /api/v1/network/wan-policies/{policy_id}/quality-check"));
    json_object_object_add(out, "contract_version",
                           json_object_new_string("wan-policies.v1"));
    json_object_object_add(out, "policies", policies);
    json_object_object_add(out, "policy_count",
                           json_object_new_int(rules ?
                               (int)json_object_array_length(rules) : 0));
    json_object_object_add(out, "config_revision", json_object_new_string(revision));
    json_object_object_add(out, "configured", json_object_new_boolean(1));
    json_object_object_add(out, "effective", json_object_new_boolean(all_runtime_applied));
    json_object_object_add(out, "runtime_applied", json_object_new_boolean(all_runtime_applied));
    json_object_object_add(out, "runtime_reason", json_object_new_string(
        !status_data ? "route_status_unavailable" :
        (all_runtime_applied ? "all_policy_readbacks_match" :
                               "one_or_more_policy_readbacks_mismatch")));
    json_object_object_add(out, "write_supported", json_object_new_boolean(1));
    json_object_object_add(out, "write_routes", routes);
    json_object_object_add(out, "transactional_apply", json_object_new_boolean(1));
    json_object_object_add(out, "config_authority", json_object_new_string("config.db"));
    json_object_object_add(out, "existing_connections",
                           json_object_new_string("unchanged"));
    json_object_object_add(out, "timestamps_supported", json_object_new_boolean(1));
    json_object_object_add(out, "smart_path_scope",
                           json_object_new_string("per_policy"));
    json_object_object_add(out, "smart_path_global_precedence",
                           json_object_new_string(
                               "explicit_policy_enabled_or_disabled_overrides_global;inherit_follows_global"));
    json_object_object_add(out, "smart_path_write_supported",
                           json_object_new_boolean(1));
    json_object_object_add(out, "smart_path_contract_version",
                           json_object_new_string("wan-policies.smart-path.v1"));
    json_object_object_add(out, "adaptive_penalty_scope",
                           json_object_new_string("per_policy"));
    json_object_object_add(out, "adaptive_penalty_write_supported",
                           json_object_new_boolean(1));
    json_object_object_add(out, "enhancement_order", json_object_new_string(
        "health_eligibility;adaptive_penalty_hysteresis;smart_path_quality_cache_new_connections;base_selector_fallback_or_tie"));
    /*
     * Data-plane weighting is a property of the loaded jmx.ko, not of the
     * config.  Expose it once at the collection level so the UI can show a
     * single honest banner ("ratio configured, kernel enforces ids only")
     * instead of guessing per policy.  weight_ratio in config.db stays
     * authoritative regardless.
     */
    json_object_object_add(out, "weight_runtime_enforced",
                           json_object_new_boolean(any_weighted_policy ?
                               all_weighted_enforced : 1));
    json_object_object_add(out, "weight_runtime_reason", json_object_new_string(
        !status_data ? "route_status_unavailable" :
        (!any_weighted_policy ? "no_weighted_policy_configured" :
         (all_weighted_enforced ? "kernel_reports_per_member_weights" :
          "kernel_module_ids_only_weight_ratio_configured_not_enforced"))));
    return out;
}

static struct json_object *webd_wan_policies_route_error(struct json_object *upstream,
                                                         struct app_ubus_call_diag *diag,
                                                         int *status)
{
    struct json_object *data = NULL;
    struct json_object *response;
    struct json_object *rollback;
    const char *reason = "route_config_set rejected the transaction";
    const char *failure_stage = "route_config_set";
    const char *code = "invalid_payload";
    int rollback_attempted = 0;
    int route_rollback_ok = 0;
    int http_status = 400;

    /*
     * No reply at all is not a rejected payload.  Reporting it as one used to
     * emit `invalid_payload` plus configured/effective/runtime_applied=false and
     * a rollback block claiming the previous config was preserved -- every one of
     * those fabricated, because the handler was still running and usually went on
     * to commit.  The UI rendered that as "配置校验未通过，配置未改动" for a delete
     * that had in fact succeeded.
     *
     * Report the timeout as such, and say nothing about a state we cannot see:
     * the state keys and the rollback block are omitted rather than set false,
     * so the client re-reads instead of trusting an invented answer.
     */
    if (!upstream && diag && diag->stage && !strcmp(diag->stage, "invoke") &&
        diag->rc == UBUS_STATUS_TIMEOUT) {
        response = webd_error("dependency_timeout",
                             "route_config_set did not answer within "
                             "the apply budget; it may still be applying, "
                             "so re-read the policy list before retrying",
                             "route_config_set", "webd.network.wan_policies");
        json_object_object_add(response, "failure_stage",
                               json_object_new_string("route_config_set_timeout"));
        json_object_object_add(response, "state_unknown",
                               json_object_new_boolean(1));
        if (status)
            *status = 504;
        return response;
    }
    if (upstream)
        json_object_object_get_ex(upstream, "data", &data);
    if (data) {
        reason = app_nc_json_str(data, "error", reason);
        failure_stage = app_nc_json_str(data, "failure_stage", failure_stage);
        rollback_attempted = app_nc_json_bool(data, "rollback_attempted", 0);
        route_rollback_ok = app_nc_json_bool(data, "route_rollback_ok", 0);
    }
    if (strstr(reason, "duplicate")) {
        code = "conflict";
        http_status = 409;
    } else if (strstr(reason, "fallback")) {
        code = "invalid_fallback";
        http_status = strstr(reason, "does not exist") || strstr(reason, "cycle") ? 409 : 400;
    } else if (strstr(reason, "runtime apply") || strstr(reason, "readback")) {
        code = "runtime_apply_failed";
        http_status = 502;
    } else if (strstr(reason, "commit")) {
        code = "persistence_failed";
        http_status = 500;
    }
    response = webd_error(code, "WAN policy transaction failed", reason,
                          "webd.network.wan_policies");
    json_object_object_add(response, "configured", json_object_new_boolean(0));
    json_object_object_add(response, "effective", json_object_new_boolean(0));
    json_object_object_add(response, "runtime_applied", json_object_new_boolean(0));
    json_object_object_add(response, "runtime_reason", json_object_new_string(reason));
    json_object_object_add(response, "failure_stage",
                           json_object_new_string(failure_stage));
    json_object_object_add(response, "rollback_attempted",
                           json_object_new_boolean(rollback_attempted));
    json_object_object_add(response, "route_rollback_ok",
                           json_object_new_boolean(route_rollback_ok));
    rollback = json_object_new_object();
    json_object_object_add(rollback, "configured",
                           json_object_new_string(route_rollback_ok ?
                               "previous_config_preserved" :
                               (rollback_attempted ? "restore_failed" : "unknown")));
    json_object_object_add(rollback, "runtime",
                           json_object_new_string(route_rollback_ok ?
                               (rollback_attempted ? "previous_config_restored" :
                                                     "not_modified") :
                               (rollback_attempted ? "restore_failed" : "unknown")));
    json_object_object_add(response, "rollback", rollback);
    if (status)
        *status = http_status;
    if (upstream)
        json_object_put(upstream);
    return response;
}

/* The route daemon commits config.db and applies the kernel rule, but flowd
 * owns the Smart Path overlay.  A named-policy write is not complete until
 * flowd has rebuilt its policy table and published the target prio readback.
 * Keep this check separate from route_status so a stale route readback cannot
 * make a policy-scoped overlay look applied. */
static int webd_wan_policy_smart_runtime_matches(struct json_object *flowd_data,
                                                  int target_prio,
                                                  int target_deleted,
                                                  char *reason,
                                                  size_t reason_len)
{
    struct json_object *policy_runtime = NULL;
    struct json_object *candidate = NULL;
    int i;

    if (reason && reason_len)
        reason[0] = '\0';
    if (!flowd_data || !json_object_is_type(flowd_data, json_type_object)) {
        if (reason && reason_len)
            snprintf(reason, reason_len, "%s", "flowd_status_unavailable");
        return 0;
    }
    if (!app_nc_json_bool(flowd_data, "reconcile_ok", 0)) {
        if (reason && reason_len)
            snprintf(reason, reason_len, "%s",
                     app_nc_json_str(flowd_data, "reconcile_reason",
                         app_nc_json_str(flowd_data, "last_error",
                             "smart_path_reconcile_failed")));
        return 0;
    }
    if (!json_object_object_get_ex(flowd_data, "policy_runtime", &policy_runtime) ||
        !policy_runtime || !json_object_is_type(policy_runtime, json_type_array)) {
        if (reason && reason_len)
            snprintf(reason, reason_len, "%s", "policy_runtime_missing");
        return 0;
    }
    for (i = 0; i < (int)json_object_array_length(policy_runtime); i++) {
        struct json_object *item = json_object_array_get_idx(policy_runtime, i);

        if (app_nc_json_int(item, "prio", 0) == target_prio) {
            candidate = item;
            break;
        }
    }
    if (target_deleted) {
        if (candidate) {
            if (reason && reason_len)
                snprintf(reason, reason_len, "%s", "deleted_policy_still_in_runtime");
            return 0;
        }
        return 1;
    }
    if (!candidate) {
        if (reason && reason_len)
            snprintf(reason, reason_len, "%s", "target_policy_missing_from_runtime");
        return 0;
    }
    if (!app_nc_json_bool(candidate, "runtime_applied", 0)) {
        if (reason && reason_len)
            snprintf(reason, reason_len, "%s",
                     app_nc_json_str(candidate, "runtime_reason",
                         "target_policy_runtime_not_applied"));
        return 0;
    }
    return 1;
}

static struct json_object *webd_wan_policies_runtime_error(const char *code,
                                                           const char *reason,
                                                           int *status,
                                                           int rollback_attempted,
                                                           int route_rollback_ok,
                                                           int smart_path_rollback_ok)
{
    struct json_object *response;
    struct json_object *rollback;
    int http_status = !strcmp(code ? code : "", "executor_unavailable") ? 503 : 502;

    response = webd_error(code ? code : "runtime_apply_failed",
                          "WAN policy Smart Path runtime apply failed",
                          reason ? reason : "smart_path_reconcile_failed",
                          "webd.network.wan_policies");
    json_object_object_add(response, "configured", json_object_new_boolean(0));
    json_object_object_add(response, "effective", json_object_new_boolean(0));
    json_object_object_add(response, "runtime_applied", json_object_new_boolean(0));
    json_object_object_add(response, "runtime_reason", json_object_new_string(
                               reason ? reason : "smart_path_reconcile_failed"));
    json_object_object_add(response, "failure_stage",
                           json_object_new_string("smart_path_reconcile"));
    json_object_object_add(response, "rollback_attempted",
                           json_object_new_boolean(rollback_attempted));
    json_object_object_add(response, "route_rollback_ok",
                           json_object_new_boolean(route_rollback_ok));
    json_object_object_add(response, "smart_path_rollback_ok",
                           json_object_new_boolean(smart_path_rollback_ok));
    json_object_object_add(response, "existing_connections",
                           json_object_new_string("unchanged"));
    json_object_object_add(response, "apply_disruption",
                           json_object_new_string("new_connections_only"));
    rollback = json_object_new_object();
    json_object_object_add(rollback, "configured",
                           json_object_new_string(route_rollback_ok ?
                               "previous_config_restored" :
                               (rollback_attempted ? "restore_failed" : "unknown")));
    json_object_object_add(rollback, "runtime",
                           json_object_new_string(smart_path_rollback_ok ?
                               "previous_runtime_restored" :
                               (rollback_attempted ? "readback_unconfirmed" : "unknown")));
    json_object_object_add(response, "rollback", rollback);
    if (status)
        *status = http_status;
    return response;
}

static const char *webd_wan_policies_request_revision(const struct http_req *req,
                                                       struct json_object *body,
                                                       char *query_revision,
                                                       size_t query_revision_len)
{
    struct json_object *value = NULL;

    if (body && json_object_object_get_ex(body, "config_revision", &value) && value)
        return json_object_get_string(value);
    if (req && webd_query_get(req->query, "config_revision", query_revision,
                             query_revision_len) && query_revision[0])
        return query_revision;
    return "";
}

static int webd_wan_policies_parse_path(const char *path, char *policy_id,
                                        size_t policy_id_len, int *quality_check)
{
    static const char prefix[] = "/api/v1/network/wan-policies/";
    static const char suffix[] = "/quality-check";
    const char *rest;
    size_t len;

    if (quality_check)
        *quality_check = 0;
    if (!path || strncmp(path, prefix, sizeof(prefix) - 1))
        return 0;
    rest = path + sizeof(prefix) - 1;
    len = strlen(rest);
    if (len > sizeof(suffix) - 1 &&
        !strcmp(rest + len - (sizeof(suffix) - 1), suffix)) {
        len -= sizeof(suffix) - 1;
        if (quality_check)
            *quality_check = 1;
    } else if (strchr(rest, '/')) {
        return -1;
    }
    if (!len || len >= policy_id_len)
        return -1;
    memcpy(policy_id, rest, len);
    policy_id[len] = '\0';
    return webd_wan_policy_id_valid(policy_id) ? 1 : -1;
}

static struct json_object *webd_wan_policy_quality_response(const char *policy_id,
                                                            int *status)
{
    struct json_object *config_upstream = app_ubus_invoke("route_config_get", NULL);
    struct json_object *config = webd_data_from_jmx_response(config_upstream);
    struct json_object *status_upstream = NULL;
    struct json_object *status_data = NULL;
    struct json_object *rules = NULL;
    struct json_object *rule;
    struct json_object *runtime_rule = NULL;
    struct json_object *runtime_wans = NULL;
    struct json_object *ids = NULL;
    struct json_object *members = NULL;
    struct json_object *checks = NULL;
    struct json_object *out = NULL;
    int runtime_present = 0;
    int runtime_applied;
    int passed = 1;
    int i;

    if (!config) {
        if (status) *status = app_response_status(config_upstream, 503);
        return config_upstream ? config_upstream : webd_error("source_unavailable",
            "WAN route configuration is unavailable", "dreamingwrt route_config_get",
            "webd.network.wan_policies");
    }
    json_object_object_get_ex(config, "rules", &rules);
    rule = webd_wan_policy_find_rule(rules, policy_id, NULL);
    if (!rule) {
        json_object_put(config);
        json_object_put(config_upstream);
        if (status) *status = 404;
        return webd_error("not_found", "WAN policy was not found", policy_id,
                          "webd.network.wan_policies");
    }
    status_upstream = app_ubus_invoke("route_status", NULL);
    status_data = webd_data_from_jmx_response(status_upstream);
    runtime_applied = webd_wan_policy_runtime_state(rule, status_data,
                                                    &runtime_rule,
                                                    &runtime_present);
    checks = json_object_new_array();
    out = json_object_new_object();
    if (!checks || !out) {
        if (checks) json_object_put(checks);
        if (out) json_object_put(out);
        json_object_put(config);
        json_object_put(config_upstream);
        if (status_data) json_object_put(status_data);
        if (status_upstream) json_object_put(status_upstream);
        if (status) *status = 500;
        return webd_error("allocation_failed", "WAN policy quality response failed",
                          "memory", "webd.network.wan_policies");
    }
    if (status_data)
        json_object_object_get_ex(status_data, "wans", &runtime_wans);
    json_object_object_get_ex(rule, "wan_ids", &ids);
    json_object_object_get_ex(rule, "members", &members);
    for (i = 0; ids && i < (int)json_object_array_length(ids); i++) {
        int wan_id = json_object_get_int(json_object_array_get_idx(ids, i));
        struct json_object *check = json_object_new_object();
        struct json_object *runtime_wan = NULL;
        int j;
        int weight = 1;

        for (j = 0; runtime_wans &&
                    j < (int)json_object_array_length(runtime_wans); j++) {
            struct json_object *candidate = json_object_array_get_idx(runtime_wans, j);
            if (app_nc_json_int(candidate, "id", 0) == wan_id) {
                runtime_wan = candidate;
                break;
            }
        }
        if (members && i < (int)json_object_array_length(members))
            weight = app_nc_json_int(json_object_array_get_idx(members, i),
                                     "weight", 1);
        json_object_object_add(check, "wan_id", json_object_new_int(wan_id));
        json_object_object_add(check, "weight", json_object_new_int(weight));
        json_object_object_add(check, "present", json_object_new_boolean(runtime_wan != NULL));
        json_object_object_add(check, "healthy", json_object_new_boolean(
            runtime_wan && app_nc_json_bool(runtime_wan, "health", 0)));
        json_object_object_add(check, "reason", json_object_new_string(
            !runtime_wan ? "wan_missing_from_runtime" :
            (app_nc_json_bool(runtime_wan, "health", 0) ? "healthy" : "unhealthy")));
        if (!runtime_wan || !app_nc_json_bool(runtime_wan, "health", 0))
            passed = 0;
        json_object_array_add(checks, check);
    }
    if (!status_data || !runtime_applied || !app_nc_json_bool(rule, "enabled", 1))
        passed = 0;
    json_object_object_add(out, "policy_id", json_object_new_string(policy_id));
    json_object_object_add(out, "passed", json_object_new_boolean(passed));
    json_object_object_add(out, "configured", json_object_new_boolean(1));
    json_object_object_add(out, "effective", json_object_new_boolean(
        app_nc_json_bool(rule, "enabled", 1) && runtime_applied));
    json_object_object_add(out, "runtime_applied", json_object_new_boolean(runtime_applied));
    json_object_object_add(out, "runtime_reason", json_object_new_string(
        !status_data ? "route_status_unavailable" :
        (runtime_applied ? "kernel_readback_matches" :
         (runtime_present ? "kernel_readback_mismatch" : "kernel_rule_missing"))));
    json_object_object_add(out, "member_checks", checks);
    json_object_object_add(out, "check_source", json_object_new_string("route_status"));
    json_object_object_add(out, "probe_triggered", json_object_new_boolean(0));
    json_object_object_add(out, "existing_connections",
                           json_object_new_string("unchanged"));
    json_object_put(config);
    json_object_put(config_upstream);
    if (status_data) json_object_put(status_data);
    if (status_upstream) json_object_put(status_upstream);
    if (status) *status = 200;
    return app_jmx_response_data(APP_API_CODE_SUCCESS, out);
}

static struct json_object *webd_wan_policies_response(const struct http_req *req,
                                                       struct json_object *body,
                                                       int *status)
{
    struct json_object *config_upstream = NULL;
    struct json_object *config_data = NULL;
    struct json_object *previous_config = NULL;
    struct json_object *config = NULL;
    struct json_object *rules = NULL;
    struct json_object *rule = NULL;
    struct json_object *apply = NULL;
    struct json_object *applied_config = NULL;
    struct app_ubus_call_diag apply_diag = { .rc = -1, .stage = NULL };
    struct json_object *status_upstream = NULL;
    struct json_object *status_data = NULL;
    struct json_object *flowd_upstream = NULL;
    struct json_object *flowd_data = NULL;
    struct json_object *route_restore = NULL;
    struct json_object *flowd_rollback_upstream = NULL;
    struct json_object *flowd_rollback_data = NULL;
    struct json_object *out = NULL;
    struct json_object *policies = NULL;
    struct json_object *policy = NULL;
    char policy_id[80] = "";
    char query_revision[64] = "";
    char current_revision[32];
    char generated_id[80] = "";
    char error[192] = "";
    const char *requested_revision;
    int quality_check = 0;
    int path_kind;
    int position = -1;
    int lockfd = -1;
    int target_prio = 0;
    int rollback_prio = 0;
    int target_deleted = 0;
    int rollback_target_deleted = 0;
    int smart_runtime_ok = 0;
    int route_rollback_ok = 0;
    int smart_path_rollback_ok = 0;
    char runtime_reason[192] = "";
    int i;

    if (!req) {
        if (status) *status = 500;
        return webd_error("internal_error", "WAN policy request is missing", NULL,
                          "webd.network.wan_policies");
    }
    path_kind = webd_wan_policies_parse_path(req->path, policy_id,
                                             sizeof(policy_id), &quality_check);
    if (path_kind < 0) {
        if (status) *status = 404;
        return webd_error("not_found", "WAN policy route was not found", req->path,
                          "webd.network.wan_policies");
    }
    if (quality_check) {
        if (strcmp(req->method, "POST")) {
            if (status) *status = 405;
            return webd_error("method_not_allowed", "quality-check requires POST",
                              req->path, "webd.network.wan_policies");
        }
        return webd_wan_policy_quality_response(policy_id, status);
    }
    if (!path_kind && !strcmp(req->method, "GET")) {
        struct json_object *flowd_upstream = NULL;
        struct json_object *flowd_data = NULL;

        config_upstream = app_ubus_invoke("route_config_get", NULL);
        config_data = webd_data_from_jmx_response(config_upstream);
        if (!config_data) {
            if (status) *status = app_response_status(config_upstream, 503);
            return config_upstream ? config_upstream : webd_error("source_unavailable",
                "WAN route configuration is unavailable", "dreamingwrt route_config_get",
                "webd.network.wan_policies");
        }
        status_upstream = app_ubus_invoke("route_status", NULL);
        status_data = webd_data_from_jmx_response(status_upstream);
        flowd_upstream = app_ubus_invoke_object_timeout("dreamingwrt.flowd",
                                                        "status", NULL, 500);
        flowd_data = webd_data_or_self_from_jmx_response(flowd_upstream);
        out = webd_wan_policies_collection_data(config_data, status_data, flowd_data);
        json_object_put(config_data);
        json_object_put(config_upstream);
        if (status_data) json_object_put(status_data);
        if (status_upstream) json_object_put(status_upstream);
        if (flowd_data) json_object_put(flowd_data);
        if (flowd_upstream) json_object_put(flowd_upstream);
        if (!out) {
            if (status) *status = 500;
            return webd_error("allocation_failed", "WAN policy collection failed",
                              "memory", "webd.network.wan_policies");
        }
        if (status) *status = 200;
        return app_jmx_response_data(APP_API_CODE_SUCCESS, out);
    }
    if ((!path_kind && strcmp(req->method, "POST")) ||
        (path_kind && strcmp(req->method, "PATCH") &&
         strcmp(req->method, "DELETE"))) {
        if (status) *status = 405;
        return webd_error("method_not_allowed", "WAN policy route method is not allowed",
                          req->path, "webd.network.wan_policies");
    }
    if (strcmp(req->method, "DELETE") &&
        (!body || !json_object_is_type(body, json_type_object))) {
        if (status) *status = 400;
        return webd_error("invalid_payload", "WAN policy must be a JSON object",
                          "body", "webd.network.wan_policies");
    }
    requested_revision = webd_wan_policies_request_revision(
        req, body, query_revision, sizeof(query_revision));
    if (!requested_revision[0]) {
        if (status) *status = 428;
        return webd_error("config_revision_required",
                          "config_revision from GET /api/v1/network/wan-policies is required",
                          "config_revision", "webd.network.wan_policies");
    }
    lockfd = webd_wan_policy_open_lock();
    if (lockfd < 0) {
        if (status) *status = 409;
        return webd_error("policy_busy", "another WAN policy transaction is active",
                          WEBD_SMART_PATH_LOCK_PATH, "webd.network.wan_policies");
    }
    config_upstream = app_ubus_invoke("route_config_get", NULL);
    config_data = webd_data_from_jmx_response(config_upstream);
    if (!config_data) {
        if (status) *status = app_response_status(config_upstream, 503);
        out = config_upstream ? config_upstream : webd_error("source_unavailable",
            "WAN route configuration is unavailable", "dreamingwrt route_config_get",
            "webd.network.wan_policies");
        config_upstream = NULL;
        goto done;
    }
    config = webd_json_clone(config_data);
    previous_config = webd_json_clone(config_data);
    json_object_put(config_data);
    config_data = NULL;
    if (!config || !previous_config ||
        !json_object_object_get_ex(config, "rules", &rules) ||
        !rules || !json_object_is_type(rules, json_type_array)) {
        if (status) *status = 503;
        out = webd_error("source_unavailable", "WAN route rule list is unavailable",
                         "rules", "webd.network.wan_policies");
        goto done;
    }
    webd_wan_policies_revision_string(rules, current_revision,
                                      sizeof(current_revision));
    if (strcmp(requested_revision, current_revision)) {
        if (status) *status = 409;
        out = webd_error("revision_conflict",
                         "WAN policy configuration changed; refresh and retry",
                         current_revision, "webd.network.wan_policies");
        goto done;
    }
    if (!strcmp(req->method, "POST")) {
        rule = webd_wan_policy_new_rule(body, rules, error, sizeof(error));
        if (!rule) {
            if (status) *status = 400;
            out = webd_error(webd_wan_policy_payload_error_code(error),
                             "WAN policy create payload is invalid",
                             error, "webd.network.wan_policies");
            goto done;
        }
        snprintf(generated_id, sizeof(generated_id), "%s",
                 app_nc_json_str(rule, "policy_id", ""));
        if (webd_wan_policy_find_rule(rules, generated_id, NULL)) {
            if (status) *status = 409;
            out = webd_error("conflict", "WAN policy id already exists", generated_id,
                             "webd.network.wan_policies");
            json_object_put(rule);
            rule = NULL;
            goto done;
        }
        json_object_array_add(rules, rule);
        rule = NULL;
        target_prio = app_nc_json_int(
            json_object_array_get_idx(rules, (int)json_object_array_length(rules) - 1),
            "prio", 0);
        rollback_prio = target_prio;
        rollback_target_deleted = 1;
    } else {
        rule = webd_wan_policy_find_rule(rules, policy_id, &position);
        if (!rule) {
            if (status) *status = 404;
            out = webd_error("not_found", "WAN policy was not found", policy_id,
                             "webd.network.wan_policies");
            goto done;
        }
        snprintf(generated_id, sizeof(generated_id), "%s", policy_id);
        target_prio = app_nc_json_int(rule, "prio", 0);
        rollback_prio = target_prio;
        if (!strcmp(req->method, "PATCH")) {
            struct json_object *replacement = webd_json_clone(rule);

            if (!replacement || webd_wan_policy_merge_rule(replacement, body, 0,
                                                            error, sizeof(error)) != 0) {
                if (replacement) json_object_put(replacement);
                if (status) *status = 400;
                out = webd_error(webd_wan_policy_payload_error_code(error),
                                 "WAN policy patch payload is invalid",
                                 error, "webd.network.wan_policies");
                goto done;
            }
            json_object_object_del(replacement, "updated_at");
            json_object_object_add(replacement, "updated_at",
                                   json_object_new_int64(now_s()));
            if (json_object_array_put_idx(rules, position, replacement) != 0) {
                json_object_put(replacement);
                if (status) *status = 500;
                out = webd_error("allocation_failed", "WAN policy patch failed",
                                 "rules", "webd.network.wan_policies");
                goto done;
            }
            target_prio = app_nc_json_int(
                json_object_array_get_idx(rules, position), "prio", target_prio);
        } else {
            for (i = 0; i < (int)json_object_array_length(rules); i++) {
                struct json_object *candidate = json_object_array_get_idx(rules, i);

                if (i != position &&
                    !strcmp(app_nc_json_str(candidate, "fallback_policy_id", ""),
                            policy_id)) {
                    if (status) *status = 409;
                    out = webd_error("reference_conflict",
                                     "WAN policy is referenced as a fallback",
                                     app_nc_json_str(candidate, "policy_id", ""),
                                     "webd.network.wan_policies");
                    goto done;
                }
            }
            json_object_array_del_idx(rules, position, 1);
            target_deleted = 1;
        }
    }
    if (target_prio <= 0) {
        if (status) *status = 400;
        out = webd_error("invalid_payload", "WAN policy priority is invalid",
                         "prio", "webd.network.wan_policies");
        goto done;
    }
    apply = webd_route_config_set(config, &apply_diag);
    if (!apply || !app_ubus_response_ok(apply)) {
        out = webd_wan_policies_route_error(apply, &apply_diag, status);
        apply = NULL;
        goto done;
    }
    applied_config = webd_data_from_jmx_response(apply);
    if (!applied_config) {
        route_restore = webd_route_config_set(previous_config, NULL);
        route_rollback_ok = app_ubus_response_ok(route_restore);
        if (route_rollback_ok) {
            flowd_rollback_upstream = app_ubus_invoke_object_timeout(
                "dreamingwrt.flowd", "smart_path_reconcile", NULL, 1500);
            flowd_rollback_data = webd_data_or_self_from_jmx_response(
                flowd_rollback_upstream);
            smart_path_rollback_ok = webd_wan_policy_smart_runtime_matches(
                flowd_rollback_data, rollback_prio, rollback_target_deleted,
                runtime_reason, sizeof(runtime_reason));
        }
        out = webd_wan_policies_runtime_error(
            "runtime_apply_failed", "route_config_set returned no readback payload",
            status, 1, route_rollback_ok, smart_path_rollback_ok);
        goto done;
    }
    flowd_upstream = app_ubus_invoke_object_timeout(
        "dreamingwrt.flowd", "smart_path_reconcile", NULL, 1500);
    flowd_data = webd_data_or_self_from_jmx_response(flowd_upstream);
    if (!flowd_upstream) {
        snprintf(runtime_reason, sizeof(runtime_reason), "%s",
                 "smart_path_executor_unavailable");
    } else {
        smart_runtime_ok = webd_wan_policy_smart_runtime_matches(
            flowd_data, target_prio, target_deleted,
            runtime_reason, sizeof(runtime_reason));
        if (!smart_runtime_ok && !runtime_reason[0])
            snprintf(runtime_reason, sizeof(runtime_reason), "%s",
                     "target_policy_runtime_not_applied");
    }
    if (!flowd_upstream || !smart_runtime_ok) {
        route_restore = webd_route_config_set(previous_config, NULL);
        route_rollback_ok = app_ubus_response_ok(route_restore);
        if (route_rollback_ok) {
            flowd_rollback_upstream = app_ubus_invoke_object_timeout(
                "dreamingwrt.flowd", "smart_path_reconcile", NULL, 1500);
            flowd_rollback_data = webd_data_or_self_from_jmx_response(
                flowd_rollback_upstream);
            smart_path_rollback_ok = webd_wan_policy_smart_runtime_matches(
                flowd_rollback_data, rollback_prio, rollback_target_deleted,
                runtime_reason, sizeof(runtime_reason));
        }
        out = webd_wan_policies_runtime_error(
            flowd_upstream ? "runtime_apply_failed" : "executor_unavailable",
            runtime_reason[0] ? runtime_reason : "smart_path_reconcile_failed",
            status, 1, route_rollback_ok, smart_path_rollback_ok);
        goto done;
    }
    status_upstream = app_ubus_invoke("route_status", NULL);
    status_data = webd_data_from_jmx_response(status_upstream);
    out = webd_wan_policies_collection_data(applied_config, status_data,
                                            flowd_data);
    if (!out) {
        if (status) *status = 500;
        out = webd_error("allocation_failed", "WAN policy response failed",
                         "memory", "webd.network.wan_policies");
        goto done;
    }
    json_object_object_add(out, "smart_path_reconciled", json_object_new_boolean(1));
    json_object_object_add(out, "smart_path_runtime",
                           flowd_data ? json_object_get(flowd_data) :
                           json_object_new_object());
    json_object_object_add(out, "operation", json_object_new_string(
        !strcmp(req->method, "POST") ? "created" :
        (!strcmp(req->method, "PATCH") ? "updated" : "deleted")));
    json_object_object_add(out, "policy_id", json_object_new_string(generated_id));
    if (strcmp(req->method, "DELETE") &&
        json_object_object_get_ex(out, "policies", &policies) && policies) {
        for (i = 0; i < (int)json_object_array_length(policies); i++) {
            struct json_object *candidate = json_object_array_get_idx(policies, i);

            if (!strcmp(app_nc_json_str(candidate, "policy_id", ""), generated_id)) {
                policy = candidate;
                break;
            }
        }
        if (policy)
            json_object_object_add(out, "policy", json_object_get(policy));
    }
    if (status)
        *status = !strcmp(req->method, "POST") ? 201 : 200;
    {
        struct json_object *wrapped = app_jmx_response_data(APP_API_CODE_SUCCESS, out);
        out = wrapped;
    }

done:
    if (flowd_rollback_data) json_object_put(flowd_rollback_data);
    if (flowd_rollback_upstream) json_object_put(flowd_rollback_upstream);
    if (route_restore) json_object_put(route_restore);
    if (flowd_data) json_object_put(flowd_data);
    if (flowd_upstream) json_object_put(flowd_upstream);
    if (applied_config) json_object_put(applied_config);
    if (status_data) json_object_put(status_data);
    if (status_upstream) json_object_put(status_upstream);
    if (apply) json_object_put(apply);
    if (config) json_object_put(config);
    if (previous_config) json_object_put(previous_config);
    if (config_data) json_object_put(config_data);
    if (config_upstream) json_object_put(config_upstream);
    flock(lockfd, LOCK_UN);
    close(lockfd);
    return out;
}

static int webd_wan_policy_has_extended_fields(struct json_object *body)
{
    static const char *const keys[] = {
        "members", "carrier", "priority", "prio", "policy_id",
        "fallback_policy_id", "smart_path", "adaptive_penalty_sticky"
    };
    struct json_object *value = NULL;
    size_t i;

    for (i = 0; body && i < sizeof(keys) / sizeof(keys[0]); i++)
        if (json_object_object_get_ex(body, keys[i], &value))
            return 1;
    return 0;
}

static struct json_object *webd_wan_policy_extended_apply(struct json_object *body,
                                                          int *status)
{
    struct json_object *config_upstream = NULL;
    struct json_object *config_data = NULL;
    struct json_object *config = NULL;
    struct json_object *rules = NULL;
    struct json_object *rule = NULL;
    struct json_object *replacement = NULL;
    struct json_object *apply = NULL;
    struct app_ubus_call_diag apply_diag = { .rc = -1, .stage = NULL };
    struct json_object *out = NULL;
    struct json_object *value = NULL;
    struct http_req read_req;
    const char *policy_id = app_nc_json_str(body, "policy_id", "");
    char error[192] = "";
    int position = -1;
    int lockfd;
    int i;

    if (json_object_object_get_ex(body, "enable_smart_path", &value) ||
        json_object_object_get_ex(body, "enable_adaptive_penalty_sticky", &value) ||
        !strcmp(app_nc_json_str(body, "mode", ""), "smart_path")) {
        if (status) *status = 400;
        return webd_error("mode_conflict",
                          "smart_path metadata updates require separate transactions",
                          "global enhancement fields", "webd.network.wan_policy");
    }
    lockfd = webd_wan_policy_open_lock();
    if (lockfd < 0) {
        if (status) *status = 409;
        return webd_error("policy_busy", "another WAN policy transaction is active",
                          WEBD_SMART_PATH_LOCK_PATH, "webd.network.wan_policy");
    }
    config_upstream = app_ubus_invoke("route_config_get", NULL);
    config_data = webd_data_from_jmx_response(config_upstream);
    config = webd_json_clone(config_data);
    if (!config || !json_object_object_get_ex(config, "rules", &rules) ||
        !rules || !json_object_is_type(rules, json_type_array)) {
        if (status) *status = 503;
        out = webd_error("source_unavailable", "WAN route rule list is unavailable",
                         "dreamingwrt route_config_get", "webd.network.wan_policy");
        goto done;
    }
    if (policy_id[0])
        rule = webd_wan_policy_find_rule(rules, policy_id, &position);
    else {
        for (i = 0; i < (int)json_object_array_length(rules); i++) {
            struct json_object *candidate = json_object_array_get_idx(rules, i);
            struct json_object *ids = NULL;

            if (app_nc_json_int(candidate, "prio", 0) < 1000 ||
                !json_object_object_get_ex(candidate, "wan_ids", &ids) ||
                !ids || json_object_array_length(ids) < 2)
                continue;
            rule = candidate;
            position = i;
            break;
        }
    }
    if (!rule) {
        if (status) *status = 404;
        out = webd_error("not_found", "WAN policy was not found", policy_id,
                         "webd.network.wan_policy");
        goto done;
    }
    replacement = webd_json_clone(rule);
    if (!replacement || webd_wan_policy_merge_rule(replacement, body, 0,
                                                    error, sizeof(error)) != 0) {
        if (status) *status = 400;
        out = webd_error(webd_wan_policy_payload_error_code(error),
                         "WAN policy payload is invalid", error,
                         "webd.network.wan_policy");
        goto done;
    }
    json_object_object_del(replacement, "updated_at");
    json_object_object_add(replacement, "updated_at",
                           json_object_new_int64(now_s()));
    if (json_object_array_put_idx(rules, position, replacement) != 0) {
        if (status) *status = 500;
        out = webd_error("allocation_failed", "WAN policy update failed", "rules",
                         "webd.network.wan_policy");
        goto done;
    }
    replacement = NULL;
    apply = webd_route_config_set(config, &apply_diag);
    if (!apply || !app_ubus_response_ok(apply)) {
        out = webd_wan_policies_route_error(apply, &apply_diag, status);
        apply = NULL;
        goto done;
    }
    flock(lockfd, LOCK_UN);
    close(lockfd);
    lockfd = -1;
    memset(&read_req, 0, sizeof(read_req));
    snprintf(read_req.method, sizeof(read_req.method), "%s", "GET");
    snprintf(read_req.path, sizeof(read_req.path), "%s", "/api/v1/network/wan-policy");
    out = webd_wan_policy_response(&read_req, NULL, status);

done:
    if (replacement) json_object_put(replacement);
    if (apply) json_object_put(apply);
    if (config) json_object_put(config);
    if (config_data) json_object_put(config_data);
    if (config_upstream) json_object_put(config_upstream);
    if (lockfd >= 0) {
        flock(lockfd, LOCK_UN);
        close(lockfd);
    }
    return out;
}

static struct json_object *webd_wan_policy_response(const struct http_req *req,
                                                    struct json_object *body,
                                                    int *status)
{
    static const char *const ids[] = {
        "hash_src_dst_dport", "hash_src_dst", "weighted_new_flow_rr",
        "least_rx_load_normalized", "least_active_conn_normalized",
        "hash_src", "hash_src_sport"
    };
    static const char *const labels[] = {
        "源IP+目的IP+目的端口", "源IP+目的IP", "新建连接数", "实时流量",
        "实时连接数", "源IP", "源IP+源端口"
    };
    static const char *const descriptions[] = {
        "同一五元组中的目标端口保持同一路线，适合需要稳定会话的应用。",
        "同一源和目标之间保持同一路线，减少站点访问时的出口变化。",
        "每个新连接按权重轮转；已有连接不会迁移。",
        "按线路瞬时接收速率选择新连接，可能随流量波动切换。",
        "按线路当前连接数选择新连接，不等同于按字节流量均衡。",
        "同一源 IP 固定到同一路线，适合需要出口稳定的终端。",
        "同一源 IP 与源端口固定到同一路线。"
    };
    struct json_object *upstream = NULL;
    struct json_object *status_upstream = NULL;
    struct json_object *flowd_upstream = NULL;
    struct json_object *data = NULL;
    struct json_object *status_data = NULL;
    struct json_object *flowd_data = NULL;
    struct json_object *smart_path = NULL;
    struct json_object *rules = NULL;
    struct json_object *configured_rule = NULL;
    struct json_object *wans = NULL;
    struct json_object *out = NULL;
    struct json_object *modes = NULL;
    const char *method = req ? req->method : "GET";
    const char *route_mode = "weighted_new_flow_rr";
    const char *activation_state;
    const char *smart_unavailable_reason = "flowd_status_unavailable";
    const char *failure_stage = webd_wan_policy_failure_stage;
    const char *last_error = webd_wan_policy_last_error;
    int smart_enable_file;
    int smart_confirm_file;
    int smart_enabled = 0;
    int smart_confirmed = 0;
    int smart_scheduler = 0;
    int smart_nft = 0;
    int smart_readback = 0;
    int smart_active = 0;
    int smart_requested;
    int smart_configured;
    int smart_selectable = 0;
    int route_runtime_applied = 0;
    int runtime_applied = 0;
    int adaptive_requested = 0;
    int adaptive_configured = 0;
    int adaptive_effective = 0;
    int adaptive_runtime_applied = 0;
    int legacy_migration_required = 0;
    const char *legacy_mode = "";
    int i;

    if (!strcmp(method, "PUT") || !strcmp(method, "POST")) {
        if (!body || !json_object_is_type(body, json_type_object)) {
            if (status) *status = 400;
            return webd_error("invalid_payload", "WAN 策略必须是 JSON 对象",
                              "mode", "webd.network.wan_policy");
        }
        if (webd_wan_policy_has_extended_fields(body))
            return webd_wan_policy_extended_apply(body, status);
        {
            const char *mode = NULL;
            const char *mode_error_code = NULL;
            struct json_object *smart_obj = NULL;
            struct json_object *adaptive_obj = NULL;
            int enable_smart_path = -1;
            int enable_adaptive_penalty = -1;
            int legacy_adaptive = 0;
            char error[192] = "";

            if (json_object_object_get_ex(body, "enable_smart_path", &smart_obj)) {
                if (!smart_obj || !json_object_is_type(smart_obj, json_type_boolean)) {
                    if (status) *status = 400;
                    return webd_error("invalid_enhancement_type",
                        "enable_smart_path must be boolean",
                        "enable_smart_path", "webd.network.wan_policy");
                }
                enable_smart_path = json_object_get_boolean(smart_obj);
            }
            if (json_object_object_get_ex(body, "enable_adaptive_penalty_sticky", &adaptive_obj)) {
                if (!adaptive_obj || !json_object_is_type(adaptive_obj, json_type_boolean)) {
                    if (status) *status = 400;
                    return webd_error("invalid_enhancement_type",
                        "enable_adaptive_penalty_sticky must be boolean",
                        "enable_adaptive_penalty_sticky", "webd.network.wan_policy");
                }
                enable_adaptive_penalty = json_object_get_boolean(adaptive_obj);
            }
            if (webd_wan_policy_resolve_base_mode(body, &mode, &legacy_adaptive,
                                                  &mode_error_code,
                                                  error, sizeof(error)) != 0) {
                if (status) *status = 400;
                return webd_error(mode_error_code, "WAN policy base mode is invalid",
                                   error, "webd.network.wan_policy");
            }
            if (legacy_adaptive) {
                if (enable_adaptive_penalty == 0) {
                    if (status) *status = 400;
                    return webd_error("base_mode_conflict",
                        "legacy adaptive mode conflicts with disabled enhancement",
                        "enable_adaptive_penalty_sticky", "webd.network.wan_policy");
                }
                enable_adaptive_penalty = 1;
            }
            (void)enable_smart_path;
            (void)enable_adaptive_penalty;
            return webd_wan_policy_apply(body, mode, legacy_adaptive, status);
        }
    }
    if (strcmp(method, "GET")) {
        if (status) *status = 405;
        return webd_error("method_not_allowed", "WAN 策略只支持 GET 和 PUT",
                          "/api/v1/network/wan-policy", "webd.network.wan_policy");
    }

    upstream = app_ubus_invoke("route_config_get", NULL);
    data = webd_data_from_jmx_response(upstream);
    if (!data) {
        if (status) *status = app_response_status(upstream, 503);
        return upstream ? upstream : webd_error("source_unavailable",
            "WAN 路由配置不可用", "dreamingwrt route_config_get", "webd.network.wan_policy");
    }
    json_object_object_get_ex(data, "rules", &rules);
    for (i = 0; rules && i < json_object_array_length(rules); i++) {
        struct json_object *rule = json_object_array_get_idx(rules, i);
        struct json_object *ids_obj = NULL;
        int prio = app_nc_json_int(rule, "prio", 0);
        if (prio < 1000 || !json_object_object_get_ex(rule, "wan_ids", &ids_obj) ||
            !json_object_is_type(ids_obj, json_type_array) ||
            json_object_array_length(ids_obj) < 2) continue;
        route_mode = app_nc_json_str(rule, "base_mode",
            app_nc_json_str(rule, "algorithm",
                app_nc_json_str(rule, "sticky_mode", route_mode)));
        configured_rule = rule;
        break;
    }
    out = json_object_new_object();
    modes = json_object_new_array();
    if (!out || !modes) {
        if (out) json_object_put(out);
        if (modes) json_object_put(modes);
        json_object_put(data);
        json_object_put(upstream);
        if (status) *status = 500;
        return webd_error("allocation_failed", "WAN 策略响应创建失败", "memory", "webd.network.wan_policy");
    }
    for (i = 0; i < (int)(sizeof(ids) / sizeof(ids[0])); i++) {
        struct json_object *mode = json_object_new_object();
        json_object_object_add(mode, "id", json_object_new_string(ids[i]));
        json_object_object_add(mode, "algorithm", json_object_new_string(ids[i]));
        json_object_object_add(mode, "label", json_object_new_string(labels[i]));
        json_object_object_add(mode, "description", json_object_new_string(descriptions[i]));
        json_object_array_add(modes, mode);
    }
    smart_enable_file = access(WEBD_SMART_PATH_ENABLE_PATH, F_OK) == 0;
    smart_confirm_file = access(WEBD_SMART_PATH_CONFIRM_PATH, F_OK) == 0;
    flowd_upstream = webd_wan_policy_flowd_status();
    flowd_data = webd_data_or_self_from_jmx_response(flowd_upstream);
    if (flowd_data && json_object_is_type(flowd_data, json_type_object) &&
        json_object_object_get_ex(flowd_data, "smart_path", &smart_path) &&
        smart_path && json_object_is_type(smart_path, json_type_object)) {
        /* Aggregate first, sentinel as the fallback -- see
         * webd_wan_policy_smart_truth().  With the sentinel read first,
         * smart_active was permanently 0 on a per-policy deployment, so this
         * route answered activation_state "disabled" and
         * runtime_reason "disabled_as_configured" while the nft data plane was
         * live and reconciling. */
        smart_enabled = app_nc_json_bool(smart_path, "enabled_requested", 0) ||
                        app_nc_json_bool(smart_path, "global_enabled_requested", 0);
        smart_confirmed = app_nc_json_bool(smart_path, "confirmed", 0);
        smart_scheduler = app_nc_json_bool(smart_path, "scheduler_active", 0);
        smart_nft = app_nc_json_bool(smart_path, "nft_active", 0);
        smart_readback = app_nc_json_bool(smart_path, "nft_readback_ok", 0);
        smart_active = smart_enabled && smart_scheduler && smart_nft && smart_readback;
        smart_unavailable_reason = app_nc_json_str(smart_path, "unavailable_reason",
            app_nc_json_str(smart_path, "last_error", ""));
        smart_selectable = smart_active ||
            (app_nc_json_bool(smart_path, "foundation_ready", 0) &&
             app_nc_json_bool(smart_path, "city_mmdb_mapped", 0) &&
             app_nc_json_bool(smart_path, "asn_mmdb_mapped", 0));
        if (smart_selectable && !smart_enabled)
            smart_unavailable_reason = "";
    }
    smart_requested = smart_enable_file || smart_enabled;
    smart_configured = smart_confirm_file || smart_confirmed || smart_enabled;
    activation_state = smart_active ? "active" :
        ((smart_requested || smart_configured) ? "fallback" : "disabled");
    if (!strcmp(activation_state, "fallback")) {
        if (!failure_stage[0])
            failure_stage = "smart_path_readback";
        if (!last_error[0])
            last_error = smart_unavailable_reason;
    }
    status_upstream = app_ubus_invoke("route_status", NULL);
    status_data = webd_data_from_jmx_response(status_upstream);
    route_runtime_applied = webd_wan_policy_route_runtime_matches(
        configured_rule, status_data);
    adaptive_requested = configured_rule &&
        app_nc_json_bool(configured_rule, "adaptive_penalty_sticky", 0);
    adaptive_configured = adaptive_requested;
    adaptive_effective = adaptive_configured && route_runtime_applied;
    adaptive_runtime_applied = !adaptive_configured || adaptive_effective;
    legacy_mode = configured_rule ?
        app_nc_json_str(configured_rule, "legacy_mode", "") : "";
    legacy_migration_required = configured_rule &&
        app_nc_json_bool(configured_rule, "migration_required", 0);
    runtime_applied = route_runtime_applied &&
        (!smart_requested && !smart_configured ? 1 : smart_active);
    if (status_data) {
        struct json_object *runtime_wans = NULL;
        if (json_object_object_get_ex(status_data, "wans", &runtime_wans) &&
            runtime_wans && json_object_is_type(runtime_wans, json_type_array) &&
            json_object_array_length(runtime_wans) > 0) {
            for (i = 0; i < json_object_array_length(runtime_wans); i++) {
                struct json_object *wan = json_object_array_get_idx(runtime_wans, i);
                struct json_object *active = NULL;

                /*
                 * route_status carries the kernel's route-binding gauge, which
                 * routed itself publishes as active_flows with an explicit
                 * "cumulative, not live" note (jmx_route.c:2884). Copying it to
                 * `connections` stripped that note and produced a third
                 * connection count -- on 30.1 that gauge reached 35x the global
                 * conntrack total, so the WAN policy page was showing a number
                 * roughly two orders of magnitude too large.
                 *
                 * `connections` means conntrack attribution everywhere, so the
                 * gauge keeps the name routed gave it and carries its semantics.
                 */
                if (wan && json_object_object_get_ex(wan, "active_conn", &active) &&
                    active && (json_object_is_type(active, json_type_int) ||
                               json_object_is_type(active, json_type_double))) {
                    webd_put_int(wan, "route_bound_conn", json_object_get_int(active));
                    webd_obj_add_str(wan, "route_bound_conn_semantics",
                                     "cumulative_route_binding_gauge_not_live_connections");
                    webd_obj_add_str(wan, "connections_source",
                                     "unavailable_use_monitor_line_load");
                    json_object_object_del(wan, "active_conn");
                }
            }
            wans = runtime_wans;
        }
    }
    if (!wans)
        json_object_object_get_ex(data, "wans", &wans);
    for (i = 0; i < json_object_array_length(modes); i++) {
        struct json_object *mode = json_object_array_get_idx(modes, i);
        json_object_object_add(mode, "selectable", json_object_new_boolean(1));
        json_object_object_add(mode, "unavailable_reason",
                               json_object_new_string(""));
    }
    json_object_object_add(out, "mode", json_object_new_string(route_mode));
    json_object_object_add(out, "algorithm", json_object_new_string(route_mode));
    json_object_object_add(out, "base_mode", json_object_new_string(route_mode));
    json_object_object_add(out, "requested_base_mode", json_object_new_string(route_mode));
    json_object_object_add(out, "configured_base_mode", json_object_new_string(route_mode));
    json_object_object_add(out, "effective_base_mode", json_object_new_string(
        route_runtime_applied ? route_mode : ""));
    json_object_object_add(out, "requested_mode", json_object_new_string(route_mode));
    json_object_object_add(out, "configured_mode", json_object_new_string(route_mode));
    json_object_object_add(out, "effective_mode", json_object_new_string(
        route_runtime_applied ? route_mode : ""));
    json_object_object_add(out, "fallback_mode", json_object_new_string(route_mode));
    if (legacy_mode[0])
        json_object_object_add(out, "legacy_mode", json_object_new_string(legacy_mode));
    json_object_object_add(out, "migration_required",
                           json_object_new_boolean(legacy_migration_required));
    json_object_object_add(out, "activation_state", json_object_new_string(activation_state));
    json_object_object_add(out, "failure_stage", json_object_new_string(failure_stage));
    json_object_object_add(out, "last_transition_at",
                           json_object_new_int64((int64_t)webd_wan_policy_last_transition_at));
    json_object_object_add(out, "last_success_readback_at",
                           json_object_new_int64((int64_t)webd_wan_policy_last_success_readback_at));
    json_object_object_add(out, "last_error", json_object_new_string(last_error));
    json_object_object_add(out, "available_modes", modes);
    json_object_object_add(out, "wans", wans ? json_object_get(wans) : json_object_new_array());
    json_object_object_add(out, "wan_ids", json_object_new_array());
    for (i = 0; rules && i < json_object_array_length(rules); i++) {
        struct json_object *rule = json_object_array_get_idx(rules, i);
        struct json_object *ids_obj = NULL;
        int prio = app_nc_json_int(rule, "prio", 0);
        if (prio < 1000 || !json_object_object_get_ex(rule, "wan_ids", &ids_obj) ||
            !json_object_is_type(ids_obj, json_type_array) ||
            json_object_array_length(ids_obj) < 2) continue;
        json_object_object_add(out, "wan_ids", json_object_get(ids_obj));
        break;
    }
    if (configured_rule) {
        struct json_object *value = NULL;

        json_object_object_add(out, "policy_id", json_object_new_string(
            app_nc_json_str(configured_rule, "policy_id", "")));
        json_object_object_add(out, "priority", json_object_new_int(
            app_nc_json_int(configured_rule, "prio", 0)));
        json_object_object_add(out, "prio", json_object_new_int(
            app_nc_json_int(configured_rule, "prio", 0)));
        json_object_object_add(out, "carrier", json_object_new_string(
            app_nc_json_str(configured_rule, "carrier", "")));
        json_object_object_add(out, "fallback_policy_id", json_object_new_string(
            app_nc_json_str(configured_rule, "fallback_policy_id", "")));
        if (json_object_object_get_ex(configured_rule, "members", &value) && value)
            json_object_object_add(out, "members", json_object_get(value));
        else
            json_object_object_add(out, "members", json_object_new_array());
        json_object_object_add(out, "weight_ratio", json_object_new_string(
            app_nc_json_str(configured_rule, "weight_ratio", "")));
    } else {
        json_object_object_add(out, "policy_id", json_object_new_string(""));
        json_object_object_add(out, "priority", json_object_new_int(0));
        json_object_object_add(out, "prio", json_object_new_int(0));
        json_object_object_add(out, "carrier", json_object_new_string(""));
        json_object_object_add(out, "fallback_policy_id", json_object_new_string(""));
        json_object_object_add(out, "members", json_object_new_array());
        json_object_object_add(out, "weight_ratio", json_object_new_string(""));
    }
    json_object_object_add(out, "runtime_applied", json_object_new_boolean(runtime_applied));
    json_object_object_add(out, "configured", json_object_new_boolean(configured_rule != NULL));
    json_object_object_add(out, "effective", json_object_new_boolean(runtime_applied));
    json_object_object_add(out, "runtime_reason", json_object_new_string(
        !status_data ? "route_status_unavailable" :
        (runtime_applied ? "kernel_readback_matches" : "kernel_readback_mismatch")));
    json_object_object_add(out, "fallback_runtime_applied",
                           json_object_new_boolean(route_runtime_applied));
    json_object_object_add(out, "write_supported", json_object_new_boolean(1));
    json_object_object_add(out, "member_selection", json_object_new_boolean(1));
    json_object_object_add(out, "existing_connections", json_object_new_string("unchanged"));
    json_object_object_add(out, "config_authority", json_object_new_string("config.db"));
    json_object_object_add(out, "carrier_neutral", json_object_new_boolean(1));
    {
        struct json_object *smart_out = json_object_new_object();

        json_object_object_add(smart_out, "scope", json_object_new_string("global"));
        json_object_object_add(smart_out, "available",
                               json_object_new_boolean(smart_selectable));
        json_object_object_add(smart_out, "writable", json_object_new_boolean(1));
        json_object_object_add(smart_out, "is_base_mode", json_object_new_boolean(0));
        json_object_object_add(smart_out, "requested",
                               json_object_new_boolean(smart_requested));
        json_object_object_add(smart_out, "configured",
                               json_object_new_boolean(smart_configured));
        json_object_object_add(smart_out, "effective",
                               json_object_new_boolean(smart_active));
        json_object_object_add(smart_out, "runtime_applied",
                               json_object_new_boolean(!smart_requested || smart_active));
        json_object_object_add(smart_out, "runtime_reason", json_object_new_string(
            !smart_requested ? "disabled_as_configured" :
            (smart_active ? "smart_path_ready" : smart_unavailable_reason)));
        json_object_object_add(smart_out, "enabled_requested",
                               json_object_new_boolean(smart_requested));
        json_object_object_add(smart_out, "enable_file_present",
                               json_object_new_boolean(smart_enable_file));
        json_object_object_add(smart_out, "confirmed",
                               json_object_new_boolean(smart_confirmed || smart_confirm_file));
        json_object_object_add(smart_out, "scheduler_active",
                               json_object_new_boolean(smart_scheduler));
        json_object_object_add(smart_out, "nft_active",
                               json_object_new_boolean(smart_nft));
        json_object_object_add(smart_out, "nft_readback_ok",
                               json_object_new_boolean(smart_readback));
        json_object_object_add(smart_out, "active",
                               json_object_new_boolean(smart_active));
        json_object_object_add(smart_out, "selectable",
                               json_object_new_boolean(smart_selectable));
        json_object_object_add(smart_out, "unavailable_reason",
                               json_object_new_string(smart_unavailable_reason));
        if (smart_path) {
            json_object_object_add(smart_out, "last_error", json_object_new_string(
                app_nc_json_str(smart_path, "last_error", "")));
            json_object_object_add(smart_out, "wan_path_count", json_object_new_int(
                app_nc_json_int(smart_path, "wan_path_count", 0)));
        }
        json_object_object_add(out, "smart_path", smart_out);
    }
    {
        struct json_object *enhancements = json_object_new_object();
        struct json_object *smart_enh = json_object_new_object();
        struct json_object *adaptive_enh = json_object_new_object();

        json_object_object_add(smart_enh, "available", json_object_new_boolean(smart_selectable));
        json_object_object_add(smart_enh, "writable", json_object_new_boolean(1));
        json_object_object_add(smart_enh, "scope", json_object_new_string("global"));
        json_object_object_add(smart_enh, "conflicts_with", json_object_new_array());
        json_object_object_add(smart_enh, "can_overlay_any_base_mode", json_object_new_boolean(1));
        /* smart_path is an overlay, never a base mode: the frontend keys off
         * this boolean rather than parsing the human note. */
        json_object_object_add(smart_enh, "is_base_mode", json_object_new_boolean(0));
        json_object_object_add(smart_enh, "requires_flowd", json_object_new_boolean(1));
        json_object_object_add(smart_enh, "requested", json_object_new_boolean(smart_requested));
        json_object_object_add(smart_enh, "configured", json_object_new_boolean(smart_configured));
        json_object_object_add(smart_enh, "effective", json_object_new_boolean(smart_active));
        json_object_object_add(smart_enh, "runtime_applied",
                               json_object_new_boolean(!smart_requested || smart_active));
        json_object_object_add(smart_enh, "runtime_reason", json_object_new_string(
            !smart_requested ? "disabled_as_configured" :
            (smart_active ? "smart_path_ready" : smart_unavailable_reason)));
        json_object_object_add(smart_enh, "unavailable_reason",
                               json_object_new_string(smart_unavailable_reason));
        json_object_object_add(adaptive_enh, "available", json_object_new_boolean(1));
        json_object_object_add(adaptive_enh, "writable", json_object_new_boolean(1));
        json_object_object_add(adaptive_enh, "scope", json_object_new_string("global"));
        json_object_object_add(adaptive_enh, "conflicts_with", json_object_new_array());
        json_object_object_add(adaptive_enh, "is_base_mode", json_object_new_boolean(0));
        json_object_object_add(adaptive_enh, "can_overlay_any_base_mode", json_object_new_boolean(1));
        json_object_object_add(adaptive_enh, "requested", json_object_new_boolean(adaptive_requested));
        json_object_object_add(adaptive_enh, "configured", json_object_new_boolean(adaptive_configured));
        json_object_object_add(adaptive_enh, "effective", json_object_new_boolean(adaptive_effective));
        json_object_object_add(adaptive_enh, "runtime_applied",
                               json_object_new_boolean(adaptive_runtime_applied));
        json_object_object_add(adaptive_enh, "runtime_reason", json_object_new_string(
            !status_data ? "route_status_unavailable" :
            (!adaptive_configured ? "disabled_as_configured" :
             (adaptive_effective ? "adaptive_penalty_ready" :
                                   "adaptive_penalty_readback_mismatch"))));
        json_object_object_add(adaptive_enh, "unavailable_reason", json_object_new_string(""));
        json_object_object_add(adaptive_enh, "note",
            json_object_new_string("自适应惩罚与粘性独立叠加在基础算法上，只影响新连接的线路选择。"));
        json_object_object_add(enhancements, "smart_path", smart_enh);
        json_object_object_add(enhancements, "adaptive_penalty_sticky", adaptive_enh);
        json_object_object_add(out, "enhancements", enhancements);
        json_object_object_add(out, "adaptive_penalty_sticky",
                               json_object_get(adaptive_enh));
    }
    json_object_put(data);
    json_object_put(upstream);
    if (flowd_data) json_object_put(flowd_data);
    if (flowd_upstream) json_object_put(flowd_upstream);
    if (status_data) json_object_put(status_data);
    if (status_upstream) json_object_put(status_upstream);
    return app_jmx_response_data(APP_API_CODE_SUCCESS, out);
}

/*
 * Per-rule WAN steering, exposed for the "different load-balancing per line
 * group" requirement.
 *
 * The engine has carried this per rule all along (route_rule.sticky_mode plus a
 * route_rule_wan member table); only HTTP flattened it into one global mode.
 * This reads the rule list out as-is.
 *
 * Two properties of the upstream shape drive the contract here:
 *
 *  - route_config_get() deliberately does not export rule_id (jmx_route_db.c
 *    reads it only to look up wan_ids). And route_config_set() replaces the
 *    whole table, so rule_id is reassigned on every write anyway. Rules are
 *    therefore addressed by array position, never by a database id.
 *  - Because position is not a stable identity either, every write must carry
 *    the config_revision returned here. It is a semantic hash of the rule list;
 *    a stale value means someone else wrote in between and the request is
 *    refused rather than silently clobbering their rule.
 */
static const char *const webd_wan_rule_modes[] = {
    "weighted_new_flow_rr", "hash_src", "hash_src_sport", "hash_src_dst",
    "hash_src_dst_dport", "five_tuple", "primary_backup",
    "least_rx_load_normalized", "least_active_conn_normalized"
};

static uint64_t webd_wan_rules_revision(struct json_object *rules)
{
    return webd_ws_semantic_hash(1469598103934665603ULL, rules);
}

static struct json_object *webd_wan_rules_response(const struct http_req *req,
                                                   int *status)
{
    struct json_object *upstream;
    struct json_object *data;
    struct json_object *rules = NULL;
    struct json_object *out;
    struct json_object *list;
    struct json_object *modes;
    char revision[32];
    int i;

    if (!req || strcmp(req->method, "GET")) {
        if (status) *status = 405;
        return webd_error("method_not_allowed",
                          "按线路组负载暂时只支持 GET",
                          "/api/v1/network/wan-rules", "webd.network.wan_rules");
    }
    upstream = app_ubus_invoke("route_config_get", NULL);
    data = webd_data_from_jmx_response(upstream);
    if (!data) {
        if (status) *status = app_response_status(upstream, 503);
        return upstream ? upstream : webd_error("source_unavailable",
            "WAN 路由配置不可用", "dreamingwrt route_config_get",
            "webd.network.wan_rules");
    }
    json_object_object_get_ex(data, "rules", &rules);
    out = json_object_new_object();
    list = json_object_new_array();
    modes = json_object_new_array();
    if (!out || !list || !modes) {
        if (out) json_object_put(out);
        if (list) json_object_put(list);
        if (modes) json_object_put(modes);
        json_object_put(data);
        json_object_put(upstream);
        if (status) *status = 500;
        return webd_error("allocation_failed", "按线路组负载响应创建失败",
                          "memory", "webd.network.wan_rules");
    }
    for (i = 0; rules && i < (int)json_object_array_length(rules); i++) {
        struct json_object *rule = json_object_array_get_idx(rules, i);
        struct json_object *ids = NULL;
        struct json_object *item = json_object_new_object();

        if (!item)
            continue;
        /* position is this rule's index, and is what the write methods take. */
        json_object_object_add(item, "position", json_object_new_int(i));
        json_object_object_add(item, "name", json_object_new_string(
            app_nc_json_str(rule, "name", "")));
        json_object_object_add(item, "enabled", json_object_new_boolean(
            app_nc_json_int(rule, "enabled", 0) ? 1 : 0));
        json_object_object_add(item, "prio", json_object_new_int(
            app_nc_json_int(rule, "prio", 0)));
        json_object_object_add(item, "carrier", json_object_new_string(
            app_nc_json_str(rule, "carrier", "")));
        json_object_object_add(item, "proto", json_object_new_string(
            app_nc_json_str(rule, "proto", "any")));
        json_object_object_add(item, "sticky_mode", json_object_new_string(
            app_nc_json_str(rule, "sticky_mode", "hash_src")));
        json_object_object_add(item, "algorithm", json_object_new_string(
            app_nc_json_str(rule, "algorithm",
                            app_nc_json_str(rule, "sticky_mode", "hash_src"))));
        json_object_object_add(item, "policy_id", json_object_new_string(
            app_nc_json_str(rule, "policy_id", "")));
        json_object_object_add(item, "fallback_policy_id", json_object_new_string(
            app_nc_json_str(rule, "fallback_policy_id", "")));
        json_object_object_add(item, "wan_selection", json_object_new_string(
            app_nc_json_str(rule, "wan_selection", "auto_carrier")));
        if (json_object_object_get_ex(rule, "wan_ids", &ids) &&
            json_object_is_type(ids, json_type_array))
            json_object_object_add(item, "wan_ids", json_object_get(ids));
        else
            json_object_object_add(item, "wan_ids", json_object_new_array());
        if (json_object_object_get_ex(rule, "members", &ids) &&
            json_object_is_type(ids, json_type_array))
            json_object_object_add(item, "members", json_object_get(ids));
        else
            json_object_object_add(item, "members", json_object_new_array());
        json_object_object_add(item, "weight_ratio", json_object_new_string(
            app_nc_json_str(rule, "weight_ratio", "")));
        /* Members naming a line that no longer exists are forwarded separately
         * so the UI can mark them stale instead of drawing them as real lines.
         * Dropping them here would hide a database inconsistency the operator
         * needs to see; wan_selection reads "explicit_unresolved" when a pinned
         * rule has lost every line it named. */
        if (json_object_object_get_ex(rule, "dangling_wan_ids", &ids) &&
            json_object_is_type(ids, json_type_array) &&
            json_object_array_length(ids) > 0)
            json_object_object_add(item, "dangling_wan_ids", json_object_get(ids));
        json_object_array_add(list, item);
    }
    for (i = 0; i < (int)(sizeof(webd_wan_rule_modes) /
                          sizeof(webd_wan_rule_modes[0])); i++)
        json_object_array_add(modes,
                              json_object_new_string(webd_wan_rule_modes[i]));

    snprintf(revision, sizeof(revision), "%llu",
             (unsigned long long)webd_wan_rules_revision(rules));
    json_object_object_add(out, "contract_version",
                           json_object_new_string("wan-rules.v1"));
    json_object_object_add(out, "rules", list);
    json_object_object_add(out, "rule_count",
                           json_object_new_int(rules ?
                               (int)json_object_array_length(rules) : 0));
    json_object_object_add(out, "config_revision",
                           json_object_new_string(revision));
    /* Per-rule modes are the kernel selectors. smart_path is deliberately not
     * among them: it is a webd-level toggle that falls back to a real selector,
     * so offering it here would let the UI submit a value routed rejects. */
    json_object_object_add(out, "available_modes", modes);
    json_object_object_add(out, "per_rule_mode_supported",
                           json_object_new_boolean(1));
    /* The global mode only rewrites the default rule -- carrier-less, spanning
     * more than one WAN, and silent about its own algorithm (jmx_route.c:4872).
     * A rule that states an algorithm keeps it. */
    json_object_object_add(out, "global_mode_overrides_default_rule_only",
                           json_object_new_boolean(1));
    json_object_object_add(out, "write_supported",
                           json_object_new_boolean(1));
    json_object_object_add(out, "write_route",
                           json_object_new_string("/api/v1/network/wan-policies"));
    json_object_object_add(out, "write_contract_version",
                           json_object_new_string("wan-policies.v1"));
    json_object_put(data);
    json_object_put(upstream);
    if (status) *status = 200;
    return app_jmx_response_data(APP_API_CODE_SUCCESS, out);
}

/* ── WAN route handlers (ctx adapters over the verbatim response builders) ── */

static int wan_policies_path(const char *path)
{
    return path && !strncmp(path, "/api/v1/network/wan-policies/", 29);
}

static struct json_object *wan_policies(struct jmx_api_ctx *ctx)
{
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;
    struct json_object *resp = webd_wan_policies_response(ctx->req, body_json, &status);
    if (strcmp(ctx->req->method, "GET") && !strstr(ctx->req->path, "/quality-check"))
        jmx_app_audit_log(device_id && device_id[0] ? device_id : "http", device_id,
                          "network.wan_policies.transaction", "medium", ctx->req->path,
                          ctx->authenticated_role,
                          app_ubus_response_ok(resp) ? "success" : "failed");
    ctx->status = status;
    return resp;
}

static struct json_object *wan_policy(struct jmx_api_ctx *ctx)
{
    int status = ctx->status;
    struct json_object *body_json = ctx->body;
    const char *device_id = ctx->device_id;
    struct json_object *resp = webd_wan_policy_response(ctx->req, body_json, &status);
    if (!strcmp(ctx->req->method, "PUT") || !strcmp(ctx->req->method, "POST"))
        jmx_app_audit_log(device_id && device_id[0] ? device_id : "http", device_id,
                          "network.wan_policy.apply", "medium", ctx->req->path,
                          ctx->authenticated_role,
                          app_ubus_response_ok(resp) ? "success" : "failed");
    ctx->status = status;
    return resp;
}

static struct json_object *wan_rules(struct jmx_api_ctx *ctx)
{
    int status = ctx->status;
    struct json_object *resp = webd_wan_rules_response(ctx->req, &status);
    ctx->status = status;
    return resp;
}

const struct jmx_api_route wan_api_routes[] = {
    JMX_API_PREDICATE_ROUTE(152, "/api/v1/network/wan-policies", "GET,POST,PATCH,DELETE", JMX_API_PREDICATE_MIXED, wan_policies_path, wan_policies),
    JMX_API_ROUTE(153, "/api/v1/network/wan-policy", "GET,PUT,POST", JMX_API_EXACT, wan_policy),
    JMX_API_ROUTE(154, "/api/v1/network/wan-rules", "GET", JMX_API_EXACT, wan_rules),
    JMX_API_ROUTE_END,
};

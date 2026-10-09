/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Included by jmx_netconfig_db.c: uses the canonical settings DB/transaction. */
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#ifndef DW_MP_APPS_DIR
#define DW_MP_APPS_DIR "/overlay/dreamingos-appstore/apps"
#endif
static struct json_object *nc_mp_blocked_apps(const struct dw_memory_profile *p, int *known)
{
    struct json_object *items = json_object_new_array();
    DIR *dir = opendir(DW_MP_APPS_DIR);
    *known = dir || errno == ENOENT;
    if (!dir) return items;
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (entry->d_name[0] == '.') continue;
        char path[1024];
        snprintf(path, sizeof(path), DW_MP_APPS_DIR "/%s/current/manifest.json", entry->d_name);
        struct stat st;
        struct json_object *mf = NULL, *req = NULL, *peaks = NULL, *v = NULL;
        const char *reason = NULL;
        if (stat(path, &st) == 0 && st.st_size <= 256 * 1024) mf = json_object_from_file(path);
        if (!mf) reason = "manifest_unavailable";
        else {
            json_object_object_get_ex(mf, "requires", &req);
            if (req && json_object_object_get_ex(req, "minMemoryBytes", &v) &&
                json_object_is_type(v, json_type_int) && json_object_get_int64(v) > 0 &&
                (uint64_t)json_object_get_int64(v) > p->total_bytes) reason = "insufficient_memory";
            else if (p->compact) {
                if (req) json_object_object_get_ex(req, "incrementalPeakBytes", &peaks);
                if (!peaks || !json_object_object_get_ex(peaks, "start", &v) ||
                    !json_object_is_type(v, json_type_int) || json_object_get_int64(v) < 0)
                    reason = "resource_peak_unknown";
                else if (!p->available_known) reason = "memory_available_unknown";
                else if (p->available_bytes < 64 * DW_MP_MIB ||
                         (uint64_t)json_object_get_int64(v) > p->available_bytes - 64 * DW_MP_MIB)
                    reason = "insufficient_memory";
            }
        }
        if (reason) {
            struct json_object *app = json_object_new_object();
            json_object_object_add(app, "id", json_object_new_string(entry->d_name));
            json_object_object_add(app, "reason", json_object_new_string(reason));
            json_object_object_add(app, "stage", json_object_new_string("next_start"));
            json_object_object_add(app, "running_service_preserved", json_object_new_boolean(1));
            json_object_array_add(items, app);
        }
        if (mf) json_object_put(mf);
    }
    closedir(dir);
    return items;
}

static int nc_mp_read(struct dw_memory_profile *p)
{
    sqlite3_stmt *st = NULL;
    struct dw_memory_profile mem = {0};
    char board[256] = "";
    nc_sys_read_first_line("/tmp/sysinfo/board_name", board, sizeof(board));
    dw_mp_memory("/proc/meminfo", &mem);
    if (nc_prepare(&st, "SELECT memory_mode,memory_revision,memory_activated_at "
                        "FROM system_settings WHERE id=1") != 0) return -1;
    int rc = -1;
    if (sqlite3_step(st) == SQLITE_ROW &&
        dw_mp_select((const char *)sqlite3_column_text(st, 0), board, mem.total_bytes, p) == 0) {
        p->revision = sqlite3_column_int64(st, 1);
        p->activated_at = sqlite3_column_int64(st, 2);
        p->available_bytes = mem.available_bytes; p->available_known = mem.available_known;
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

static void nc_mp_boot_publish(void)
{
    struct dw_memory_profile p;
    if (nc_mp_read(&p) == 0 && dw_mp_publish(&p) != 0)
        LOG_WARN("memory profile runtime projection unavailable\n");
}

static struct json_object *nc_mp_error(const char *code, int status)
{
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "ok", json_object_new_boolean(0));
    json_object_object_add(o, "error", json_object_new_string(code));
    json_object_object_add(o, "http_status", json_object_new_int(status));
    json_object_object_add(o, "retryable", json_object_new_boolean(status == 503));
    return jmx_gen_api_response_data(API_CODE_ERROR, o);
}

static void nc_mp_effect(struct json_object *a, const char *component,
                         const char *description, const char *state)
{
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "component", json_object_new_string(component));
    json_object_object_add(o, "description", json_object_new_string(description));
    json_object_object_add(o, "state", json_object_new_string(state));
    json_object_object_add(o, "restart_required", json_object_new_boolean(0));
    json_object_array_add(a, o);
}

static struct json_object *nc_mp_receipt(const struct dw_memory_profile *p)
{
    struct json_object *o = dw_mp_json(p), *effects = json_object_new_array();
    struct json_object *running = json_object_new_object();
    struct json_object *ack = json_object_from_file(DW_MP_RUN_DIR "/memory-webd.json"), *v;
    int active = 0;
    if (ack && json_object_object_get_ex(ack, "config_revision", &v) &&
        json_object_get_int64(v) == p->revision &&
        json_object_object_get_ex(ack, "settled", &v) && json_object_get_boolean(v)) active = 1;
    char boot_id[64] = "";
    nc_sys_read_first_line("/proc/sys/kernel/random/boot_id", boot_id, sizeof(boot_id));
    struct timespec monotonic; clock_gettime(CLOCK_MONOTONIC, &monotonic);
    active = active && boot_id[0] && json_object_object_get_ex(ack, "boot_id", &v) &&
             !strcmp(json_object_get_string(v), boot_id) &&
             json_object_object_get_ex(ack, "updated_monotonic", &v) &&
             json_object_get_int64(v) <= monotonic.tv_sec && monotonic.tv_sec - json_object_get_int64(v) <= 15;
    if (ack) json_object_object_add(running, "webd", ack);
    else json_object_object_add(running, "webd", NULL);
    struct json_object *models = dw_rm_registry_status_json(), *resources = NULL;
    int core_active = 0;
    if (models && json_object_object_get_ex(models, "resources", &resources)) {
        for (size_t i = 0; i < json_object_array_length(resources); i++) {
            struct json_object *r = json_object_array_get_idx(resources, i), *name = NULL;
            if (json_object_object_get_ex(r, "name", &name) &&
                !strcmp(json_object_get_string(name), "client_connections")) {
                json_object_object_add(running, "connections", json_object_get(r));
                core_active = json_object_object_get_ex(r, "memory_profile_revision", &v) &&
                              json_object_get_int64(v) == p->revision;
            }
        }
    }
    if (models) json_object_put(models);
    active = active && core_active;
    json_object_object_add(o, "running", running);
    struct dw_memory_profile projected;
    dw_mp_load(&projected);
    int projection_ready = projected.revision == p->revision && !strcmp(projected.requested, p->requested);
    json_object_object_add(o, "apply_state", json_object_new_string(!projection_ready ? "pending_runtime" : active ? "active" : "applying"));
    json_object_object_add(o, "ok", json_object_new_boolean(1));
    nc_mp_effect(effects, "webd", p->compact ?
        "管理请求使用 3 个普通进程和 1 个重查询进程；多余进程处理完已接收的请求后退出。" :
        "恢复 16 个管理进程，其中 2 个处理重查询。", "implemented");
    nc_mp_effect(effects, "connections", p->compact ?
        "连接统计前台每 2 秒、无前台读取时每 5 秒更新；差量保留 16 槽、最多 4 MiB，连接总表保持完整。" :
        "连接统计恢复每 750 毫秒更新，差量保留 64 槽、最多 128 MiB。", "implemented");
    nc_mp_effect(effects, "app_admission", p->compact ?
        "应用商店安装、升级和新启动须保留至少 64 MiB 可用内存；未知峰值的应用暂不放行，已有服务继续运行。" :
        "应用商店恢复标准模式准入，仍检查应用的最低内存要求。", "implemented");
    nc_mp_effect(effects, "geoip", p->compact ?
        "普通统计优先读取国家信息；城市库由城市查询或已启用的 QoE 策略按需加载。" :
        "恢复标准模式的地理信息读取。", "implemented");
    nc_mp_effect(effects, "audit", p->compact ?
        "新明细日志保留 24 小时，日志数据库限制增长到 128 MiB；旧历史沿用原保留规则。" :
        "新日志恢复原保留规则；此前小内存模式记录的明细仍按原到期时间清理。", "implemented");
    nc_mp_effect(effects, "board_profile", "设备级内存压缩与完整资源预算尚未验证。", "pending_build");
    json_object_object_add(o, "effects", effects);
    int apps_known = 0;
    json_object_object_add(o, "blocked_apps", nc_mp_blocked_apps(p, &apps_known));
    json_object_object_add(o, "blocked_apps_known", json_object_new_boolean(apps_known));
    json_object_object_add(o, "application_scope", json_object_new_string("appstore_dapp"));
    json_object_object_add(o, "admission_rechecked_at_start", json_object_new_boolean(1));
    json_object_object_add(o, "restart_required", json_object_new_boolean(0));
    json_object_object_add(o, "drain_required", json_object_new_boolean(1));
    json_object_object_add(o, "history_deleted", json_object_new_boolean(0));
    return o;
}

struct json_object *jmx_system_memory_profile_get(void)
{
    struct dw_memory_profile p;
    if (jmx_netconfig_db_init() != 0 || nc_mp_read(&p) != 0)
        return nc_mp_error("source_unavailable", 503);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, nc_mp_receipt(&p));
}

struct json_object *jmx_system_memory_profile_change(struct json_object *req, int apply)
{
    struct dw_memory_profile before, after;
    struct json_object *mode = NULL, *revision = NULL;
    sqlite3_stmt *st = NULL;
    char board[256] = "";
    if (!req || !json_object_is_type(req, json_type_object) ||
        !json_object_object_get_ex(req, "requested_mode", &mode) ||
        !json_object_is_type(mode, json_type_string) ||
        !json_object_object_get_ex(req, "config_revision", &revision) ||
        !json_object_is_type(revision, json_type_int)) return nc_mp_error("invalid_request", 422);
    json_object_object_foreach(req, key, value) {
        (void)value;
        if (strcmp(key, "requested_mode") && strcmp(key, "config_revision"))
            return nc_mp_error("invalid_request", 422);
    }
    if (jmx_netconfig_db_init() != 0) return nc_mp_error("source_unavailable", 503);
    if (apply && nc_txn_begin() != 0) return nc_mp_error("active_operation_conflict", 503);
    const char *error = NULL; int status = 503;
    if (nc_mp_read(&before) != 0) { error = "source_unavailable"; goto fail; }
    if (before.revision != json_object_get_int64(revision)) {
        error = "config_revision_mismatch"; status = 409; goto fail;
    }
    nc_sys_read_first_line("/tmp/sysinfo/board_name", board, sizeof(board));
    if (dw_mp_select(json_object_get_string(mode), board, before.total_bytes, &after) != 0) {
        error = "invalid_mode"; status = 422; goto fail;
    }
    if (!after.supported) { error = "profile_unsupported"; status = 422; goto fail; }
    after.revision = before.revision;
    after.activated_at = before.activated_at;
    after.available_bytes = before.available_bytes; after.available_known = before.available_known;
    int changed = strcmp(before.requested, after.requested) != 0;
    if (apply && changed) {
        after.revision++;
        after.activated_at = nc_now_s();
        if (nc_prepare(&st, "UPDATE system_settings SET memory_mode=?,memory_revision=?,"
                            "memory_activated_at=? WHERE id=1") != 0) {
            error = "storage_error"; goto fail;
        }
        sqlite3_bind_text(st, 1, after.requested, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, after.revision);
        sqlite3_bind_int64(st, 3, after.activated_at);
        int rc = nc_step_done(st); sqlite3_finalize(st); st = NULL;
        if (rc != 0) { error = "storage_error"; goto fail; }
        /* Publish only after commit. Readers cannot see an uncommitted mode. */
    }
    if (apply && nc_txn_end(0) != 0) {
        nc_exec("ROLLBACK"); return nc_mp_error("storage_error", 503);
    }
    if (apply && dw_mp_publish(&after) != 0) {
        /* Config is durable; report pending, never pretend runtime was applied.
         * Reapplying the same revision retries projection without losing data. */
        struct json_object *o = nc_mp_receipt(&after);
        json_object_object_add(o, "apply_state", json_object_new_string("pending_runtime"));
        json_object_object_add(o, "error", json_object_new_string("runtime_projection_failed"));
        json_object_object_add(o, "http_status", json_object_new_int(503));
        json_object_object_add(o, "ok", json_object_new_boolean(0));
        return jmx_gen_api_response_data(API_CODE_ERROR, o);
    }
    struct json_object *o = nc_mp_receipt(&after);
    json_object_object_add(o, "preview", json_object_new_boolean(!apply));
    json_object_object_add(o, "changed", json_object_new_boolean(changed));
    json_object_object_add(o, "previous_mode", json_object_new_string(before.requested));
    json_object_object_add(o, "rollback_mode", json_object_new_string(before.requested));
    json_object_object_add(o, "before", dw_mp_json(&before));
    json_object_object_add(o, "after", dw_mp_json(&after));
    json_object_object_add(o, "drain_required", json_object_new_boolean(before.compact != after.compact && after.compact));
    if (!apply && before.compact == after.compact)
        json_object_object_add(o, "effects", json_object_new_array());
    if (apply) {
        char task[64]; snprintf(task, sizeof(task), "memory-profile-%lld", (long long)after.revision);
        json_object_object_add(o, "task_id", json_object_new_string(task));
    }
    return jmx_gen_api_response_data(API_CODE_SUCCESS, o);
fail:
    if (st) sqlite3_finalize(st);
    if (apply) nc_txn_end(-1);
    return nc_mp_error(error, status);
}

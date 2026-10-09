// SPDX-License-Identifier: GPL-2.0-or-later
#define _POSIX_C_SOURCE 200809L

#include "system_kernel_controls.h"

#include <ctype.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KC_LINE_MAX 4096U
#define KC_GRAPH_MAX 256U
#define KC_USERS_MAX 32U

struct kc_module {
    char name[JMX_KERNEL_CONTROLS_NAME_MAX];
    char users[KC_USERS_MAX][JMX_KERNEL_CONTROLS_NAME_MAX];
    size_t user_count;
    int loaded;
};

static void kc_copy(char *out, size_t out_len, const char *value)
{
    size_t i;
    if (!out || !out_len)
        return;
    if (!value)
        value = "";
    for (i = 0; i + 1U < out_len && value[i]; i++)
        out[i] = value[i];
    out[i] = 0;
}

static void kc_fail(char *stage, size_t stage_len, char *error,
                    size_t error_len, const char *where, const char *message)
{
    kc_copy(stage, stage_len, where);
    kc_copy(error, error_len, message);
}

static int kc_name_valid(const char *name)
{
    size_t i, length;
    if (!name || !(length = strlen(name)) || length >= JMX_KERNEL_CONTROLS_NAME_MAX)
        return 0;
    for (i = 0; i < length; i++)
        if (!(isalnum((unsigned char)name[i]) || name[i] == '_'))
            return 0;
    return 1;
}

static int kc_list_has(const char *const *list, size_t count, const char *value)
{
    size_t i;
    if (!list || !value)
        return 0;
    for (i = 0; i < count; i++)
        if (list[i] && strcmp(list[i], value) == 0)
            return 1;
    return 0;
}

static int kc_default_protected(const char *name)
{
    static const char *const exact[] = {
        "jmx", "bridge", "br_netfilter", "cfg80211", "mac80211",
        "overlay", "squashfs", "ext4", "f2fs", "xfs", "btrfs",
        "loop", "dm_mod", "usb_storage", "nvme", "sd_mod", "fat", "vfat",
        "nls_base", "fuse", "jbd2", "mbcache", "ubifs", "jffs2", "erofs",
        "nfs", "nfsd", "cifs", "9p", "virtio_blk", "virtio_net", "tun",
        "tap", "ppp_generic", "pppoe", "pppox", "vxlan", "bonding",
        "8021q", "veth"
    };
    static const char *const prefix[] = {
        "nf_", "nft_", "xt_", "ip_", "ip6_", "sch_", "cls_", "act_",
        "crypto_", "cryptd", "aes", "sha", "crc", "dm_", "md_", "scsi_",
        "usb_", "ath", "mt7", "mt8", "iwl", "rtl", "r81", "qca", "wireguard"
    };
    size_t i;
    for (i = 0; i < sizeof(exact) / sizeof(exact[0]); i++)
        if (strcmp(name, exact[i]) == 0)
            return 1;
    for (i = 0; i < sizeof(prefix) / sizeof(prefix[0]); i++)
        if (strncmp(name, prefix[i], strlen(prefix[i])) == 0)
            return 1;
    return 0;
}

static int kc_find(struct kc_module *modules, size_t count, const char *name)
{
    size_t i;
    for (i = 0; i < count; i++)
        if (strcmp(modules[i].name, name) == 0)
            return (int)i;
    return -1;
}

static int kc_parse_modules(const char *path, struct kc_module *modules,
                            size_t *count)
{
    FILE *fp;
    char line[KC_LINE_MAX];
    size_t used = 0;
    if (!path || !modules || !count || !(fp = fopen(path, "r")))
        return -1;
    while (fgets(line, sizeof(line), fp)) {
        char name[JMX_KERNEL_CONTROLS_NAME_MAX], users[KC_LINE_MAX];
        char *cursor, *token, *save = NULL;
        unsigned long size, refs;
        struct kc_module *module;
        if (used >= KC_GRAPH_MAX ||
            sscanf(line, "%63s %lu %lu %4095s", name, &size, &refs, users) != 4 ||
            !kc_name_valid(name)) {
            fclose(fp);
            return -1;
        }
        (void)size;
        (void)refs;
        module = &modules[used++];
        memset(module, 0, sizeof(*module));
        kc_copy(module->name, sizeof(module->name), name);
        module->loaded = 1;
        if (strcmp(users, "-") == 0)
            continue;
        cursor = users;
        for (token = strtok_r(cursor, ",", &save); token;
             token = strtok_r(NULL, ",", &save)) {
            if (!kc_name_valid(token) ||
                module->user_count >= KC_USERS_MAX) {
                fclose(fp);
                return -1;
            }
            kc_copy(module->users[module->user_count++],
                    JMX_KERNEL_CONTROLS_NAME_MAX, token);
        }
    }
    if (ferror(fp) || fclose(fp) != 0)
        return -1;
    *count = used;
    return 0;
}

static int kc_reaches_protected(struct kc_module *modules, size_t count,
                                int index, const struct jmx_kernel_module_options *o,
                                unsigned char *visited)
{
    size_t i;
    if (index < 0 || (size_t)index >= count || visited[index])
        return 0;
    visited[index] = 1;
    if (kc_default_protected(modules[index].name) ||
        kc_list_has(o->protected_roots, o->protected_root_count,
                    modules[index].name))
        return 1;
    for (i = 0; i < modules[index].user_count; i++) {
        int user = kc_find(modules, count, modules[index].users[i]);
        if (user < 0 || kc_reaches_protected(modules, count, user, o, visited))
            return 1;
    }
    return 0;
}

static int kc_runner_ok(jmx_kernel_command_runner_fn runner, void *context,
                        const char *path, const char *module, int timeout_ms)
{
    struct jmx_kernel_command_result result;
    char *argv[] = { (char *)path, (char *)module, NULL };
    memset(&result, 0, sizeof(result));
    if (!runner || runner(context, path, argv, timeout_ms, &result) != 0)
        return 0;
    return result.exit_code == 0 && result.term_signal == 0 && !result.timed_out;
}

static int kc_module_loaded(const struct jmx_kernel_module_options *o,
                            const char *name)
{
    struct kc_module *modules;
    size_t count = 0;
    int loaded;
    modules = calloc(KC_GRAPH_MAX, sizeof(*modules));
    if (!modules)
        return -1;
    if (kc_parse_modules(o->proc_modules_path, modules, &count) != 0) {
        free(modules);
        return -1;
    }
    loaded = kc_find(modules, count, name) >= 0;
    free(modules);
    return loaded;
}

int jmx_kernel_module_capabilities(
    const struct jmx_kernel_module_options *o,
    struct jmx_kernel_module_result *result)
{
    if (!result)
        return JMX_KERNEL_CONTROLS_ERR_INVALID;
    memset(result, 0, sizeof(*result));
    result->persistent_available = 0;
    if (!o || !o->proc_modules_path || !o->rmmod_path || !o->modprobe_path ||
        !o->allowlist || !o->allowlist_count || !o->protected_roots ||
        !o->protected_root_count || !o->runner || !o->snapshot ||
        !o->restore || !o->rescue_ready) {
        kc_copy(result->capability_reason, sizeof(result->capability_reason),
                "temporary_preconditions_missing");
        return JMX_KERNEL_CONTROLS_OK;
    }
    result->temporary_available = 1;
    kc_copy(result->capability_reason, sizeof(result->capability_reason),
            "temporary_only_persistence_requires_separate_high_risk_executor");
    return JMX_KERNEL_CONTROLS_OK;
}

static int kc_kernel_module_apply_graph(
    const struct jmx_kernel_module_options *o,
    const struct jmx_kernel_module_request *request,
    struct jmx_kernel_module_result *result, struct kc_module *modules)
{
    int indexes[JMX_KERNEL_CONTROLS_MAX_MODULES];
    char snapshots[JMX_KERNEL_CONTROLS_MAX_MODULES]
                  [JMX_KERNEL_CONTROLS_SNAPSHOT_MAX];
    unsigned char requested[KC_GRAPH_MAX];
    unsigned char remaining[KC_GRAPH_MAX];
    size_t count = 0, i, ordered = 0, changed_count = 0;
    int status = JMX_KERNEL_CONTROLS_OK;
    if (!result)
        return JMX_KERNEL_CONTROLS_ERR_INVALID;
    jmx_kernel_module_capabilities(o, result);
    if (!o || !request || !request->modules || !request->module_count ||
        request->module_count > JMX_KERNEL_CONTROLS_MAX_MODULES ||
        !result->temporary_available) {
        kc_fail(result->failure_stage, sizeof(result->failure_stage), result->error,
                sizeof(result->error), "preflight", "temporary_executor_unavailable");
        return JMX_KERNEL_CONTROLS_ERR_INVALID;
    }
    if (request->persistent) {
        kc_fail(result->failure_stage, sizeof(result->failure_stage), result->error,
                sizeof(result->error), "preflight_persistence",
                request->persistent_confirmation ?
                "persistent_executor_not_implemented" :
                "persistent_high_risk_confirmation_required");
        return JMX_KERNEL_CONTROLS_ERR_FORBIDDEN;
    }
    if (kc_parse_modules(o->proc_modules_path, modules, &count) != 0) {
        kc_fail(result->failure_stage, sizeof(result->failure_stage), result->error,
                sizeof(result->error), "snapshot", "module_graph_probe_failed");
        return JMX_KERNEL_CONTROLS_ERR_PROBE;
    }
    memset(requested, 0, sizeof(requested));
    memset(remaining, 0, sizeof(remaining));
    for (i = 0; i < request->module_count; i++) {
        unsigned char visited[KC_GRAPH_MAX] = {0};
        int index;
        if (!kc_name_valid(request->modules[i]) ||
            !kc_list_has(o->allowlist, o->allowlist_count, request->modules[i])) {
            kc_fail(result->failure_stage, sizeof(result->failure_stage), result->error,
                    sizeof(result->error), "preflight_allowlist", "module_not_allowlisted");
            return JMX_KERNEL_CONTROLS_ERR_FORBIDDEN;
        }
        index = kc_find(modules, count, request->modules[i]);
        if (index < 0) {
            kc_fail(result->failure_stage, sizeof(result->failure_stage), result->error,
                    sizeof(result->error), "preflight_target", "module_not_loaded");
            return JMX_KERNEL_CONTROLS_ERR_INVALID;
        }
        if (remaining[index]) {
            kc_fail(result->failure_stage, sizeof(result->failure_stage), result->error,
                    sizeof(result->error), "preflight_target", "duplicate_module");
            return JMX_KERNEL_CONTROLS_ERR_INVALID;
        }
        if (kc_reaches_protected(modules, count, index, o, visited)) {
            kc_fail(result->failure_stage, sizeof(result->failure_stage), result->error,
                    sizeof(result->error), "preflight_protected", "protected_dependency_chain");
            return JMX_KERNEL_CONTROLS_ERR_FORBIDDEN;
        }
        requested[index] = 1;
        remaining[index] = 1;
    }
    while (ordered < request->module_count) {
        int selected = -1;
        for (i = 0; i < count; i++) {
            size_t u;
            int has_requested_user = 0, has_external_user = 0;
            if (!remaining[i])
                continue;
            for (u = 0; u < modules[i].user_count; u++) {
                int user = kc_find(modules, count, modules[i].users[u]);
                if (user < 0 || !requested[user])
                    has_external_user = 1;
                else if (remaining[user])
                    has_requested_user = 1;
            }
            if (has_external_user) {
                kc_fail(result->failure_stage, sizeof(result->failure_stage), result->error,
                        sizeof(result->error), "preflight_dependencies",
                        "module_has_external_user");
                return JMX_KERNEL_CONTROLS_ERR_BUSY;
            }
            if (!has_requested_user) {
                selected = (int)i;
                break;
            }
        }
        if (selected < 0) {
            kc_fail(result->failure_stage, sizeof(result->failure_stage), result->error,
                    sizeof(result->error), "preflight_dependencies", "module_dependency_cycle");
            return JMX_KERNEL_CONTROLS_ERR_BUSY;
        }
        indexes[ordered++] = selected;
        remaining[selected] = 0;
    }
    memset(snapshots, 0, sizeof(snapshots));
    for (i = 0; i < ordered; i++) {
        if (o->snapshot(o->runner_context, modules[indexes[i]].name,
                        snapshots[i], sizeof(snapshots[i])) != 0) {
            kc_fail(result->failure_stage, sizeof(result->failure_stage), result->error,
                    sizeof(result->error), "snapshot",
                    "module_runtime_snapshot_failed");
            return JMX_KERNEL_CONTROLS_ERR_PROBE;
        }
    }
    result->snapshot_captured = 1;
    result->step_count = ordered;
    for (i = 0; i < ordered; i++) {
        struct jmx_kernel_module_step *step = &result->steps[i];
        int loaded;
        kc_copy(step->module, sizeof(step->module), modules[indexes[i]].name);
        if (!kc_runner_ok(o->runner, o->runner_context, o->rmmod_path,
                          step->module, o->command_timeout_ms)) {
            loaded = kc_module_loaded(o, step->module);
            if (loaded <= 0) {
                step->changed = 1;
                changed_count = i + 1U;
            }
            status = JMX_KERNEL_CONTROLS_ERR_EXEC;
            kc_fail(result->failure_stage, sizeof(result->failure_stage), result->error,
                    sizeof(result->error), "unload",
                    loaded < 0 ? "module_unload_failed_state_unknown" :
                                 "module_unload_failed");
            break;
        }
        step->changed = 1;
        changed_count = i + 1U;
        loaded = kc_module_loaded(o, step->module);
        if (loaded != 0) {
            status = loaded < 0 ? JMX_KERNEL_CONTROLS_ERR_PROBE :
                                  JMX_KERNEL_CONTROLS_ERR_READBACK;
            kc_fail(result->failure_stage, sizeof(result->failure_stage), result->error,
                    sizeof(result->error), "unload_readback",
                    loaded < 0 ? "module_readback_failed" : "module_still_loaded");
            break;
        }
        step->readback_ok = 1;
    }
    if (status == JMX_KERNEL_CONTROLS_OK) {
        result->applied = 1;
        return status;
    }
    result->rollback_attempted = 1;
    result->rollback_ok = 1;
    i = changed_count;
    while (i > 0) {
        struct jmx_kernel_module_step *step = &result->steps[--i];
        struct jmx_kernel_command_result restore_result;
        if (!step->changed)
            continue;
        step->rollback_attempted = 1;
        memset(&restore_result, 0, sizeof(restore_result));
        if (o->restore(o->runner_context, o->modprobe_path, step->module,
                       snapshots[i], o->command_timeout_ms,
                       &restore_result) != 0 || restore_result.exit_code != 0 ||
            restore_result.term_signal != 0 || restore_result.timed_out ||
            kc_module_loaded(o, step->module) != 1) {
            step->rollback_ok = 0;
            result->rollback_ok = 0;
        } else {
            step->rollback_ok = 1;
        }
    }
    if (!result->rollback_ok) {
        kc_copy(result->failure_stage, sizeof(result->failure_stage), "rollback");
        kc_copy(result->error, sizeof(result->error), "module_rollback_failed");
        return JMX_KERNEL_CONTROLS_ERR_ROLLBACK;
    }
    return status;
}

int jmx_kernel_module_apply(
    const struct jmx_kernel_module_options *o,
    const struct jmx_kernel_module_request *request,
    struct jmx_kernel_module_result *result)
{
    struct kc_module *modules;
    int status;
    if (!result)
        return JMX_KERNEL_CONTROLS_ERR_INVALID;
    modules = calloc(KC_GRAPH_MAX, sizeof(*modules));
    if (!modules) {
        memset(result, 0, sizeof(*result));
        kc_fail(result->failure_stage, sizeof(result->failure_stage), result->error,
                sizeof(result->error), "snapshot", "module_graph_allocation_failed");
        return JMX_KERNEL_CONTROLS_ERR_PROBE;
    }
    status = kc_kernel_module_apply_graph(o, request, result, modules);
    free(modules);
    return status;
}

static const struct jmx_scheduler_service *kc_service(
    const struct jmx_scheduler_options *o, const char *service_id)
{
    size_t i;
    if (!o || !service_id)
        return NULL;
    for (i = 0; i < o->service_count; i++)
        if (o->services[i].service_id &&
            strcmp(o->services[i].service_id, service_id) == 0)
            return &o->services[i];
    return NULL;
}

int jmx_scheduler_capabilities(const struct jmx_scheduler_options *o,
                               struct jmx_scheduler_result *result)
{
    if (!result)
        return JMX_KERNEL_CONTROLS_ERR_INVALID;
    memset(result, 0, sizeof(*result));
    if (o && o->services && o->service_count && o->resolve && o->threads &&
        o->get && o->set) {
        result->nice_available = 1;
        kc_copy(result->nice_reason, sizeof(result->nice_reason), "available");
    } else {
        kc_copy(result->nice_reason, sizeof(result->nice_reason),
                "service_resolver_or_thread_runner_missing");
    }
    if (result->nice_available && o->rt_enabled && o->preflight) {
        result->rt_available = 1;
        kc_copy(result->rt_reason, sizeof(result->rt_reason), "available_with_preflight");
    } else {
        kc_copy(result->rt_reason, sizeof(result->rt_reason),
                o && o->rt_enabled ? "rt_preflight_missing" : "rt_disabled_by_default");
    }
    return JMX_KERNEL_CONTROLS_OK;
}

static int kc_sched_equal(const struct jmx_scheduler_thread_state *a,
                          const struct jmx_scheduler_thread_state *b,
                          enum jmx_scheduler_mode mode)
{
    if (mode == JMX_SCHEDULER_MODE_NICE)
        return a->nice == b->nice && a->policy == b->policy &&
               a->rt_priority == b->rt_priority;
    return a->policy == b->policy && a->rt_priority == b->rt_priority &&
           a->nice == b->nice;
}

int jmx_scheduler_apply(const struct jmx_scheduler_options *o,
                        const struct jmx_scheduler_request *request,
                        struct jmx_scheduler_binding *binding,
                        struct jmx_scheduler_result *result)
{
    const struct jmx_scheduler_service *service;
    struct jmx_scheduler_thread_state before[JMX_KERNEL_CONTROLS_MAX_TARGETS];
    struct jmx_scheduler_thread_state desired[JMX_KERNEL_CONTROLS_MAX_TARGETS];
    pid_t tids[JMX_KERNEL_CONTROLS_MAX_TARGETS], pid;
    unsigned long generation = 0;
    size_t preflight_thread_count = 0;
    size_t count = 0, i, changed_count = 0;
    int status = JMX_KERNEL_CONTROLS_OK;
    if (!result)
        return JMX_KERNEL_CONTROLS_ERR_INVALID;
    jmx_scheduler_capabilities(o, result);
    service = request ? kc_service(o, request->service_id) : NULL;
    if (!request || !service || !result->nice_available) {
        kc_fail(result->failure_stage, sizeof(result->failure_stage), result->error,
                sizeof(result->error), "preflight_service", "service_id_not_allowlisted");
        return JMX_KERNEL_CONTROLS_ERR_FORBIDDEN;
    }
    if (request->mode == JMX_SCHEDULER_MODE_NICE) {
        if (request->nice < service->min_nice || request->nice > service->max_nice) {
            kc_fail(result->failure_stage, sizeof(result->failure_stage), result->error,
                    sizeof(result->error), "preflight_nice", "nice_out_of_service_range");
            return JMX_KERNEL_CONTROLS_ERR_FORBIDDEN;
        }
    } else if (request->mode == JMX_SCHEDULER_MODE_RT) {
        struct jmx_scheduler_preflight preflight;
        if (!result->rt_available || !service->allow_rt ||
            (request->policy != SCHED_FIFO && request->policy != SCHED_RR) ||
            request->rt_priority < 1 ||
            request->rt_priority > service->max_rt_priority) {
            kc_fail(result->failure_stage, sizeof(result->failure_stage), result->error,
                    sizeof(result->error), "preflight_rt", "rt_not_available_or_out_of_range");
            return JMX_KERNEL_CONTROLS_ERR_FORBIDDEN;
        }
        memset(&preflight, 0, sizeof(preflight));
        if (o->resolve(o->context, request->service_id, &pid, &generation) != 0)
            goto target_gone;
        if (o->preflight(o->context, request->service_id, pid, &preflight) != 0 ||
            !preflight.watchdog_ok || !preflight.cpu_quota_ok ||
            !preflight.affinity_ok || !preflight.rollback_runner_ok ||
            !preflight.thread_count ||
            preflight.thread_count > (o->max_threads ? o->max_threads :
                                      JMX_KERNEL_CONTROLS_MAX_TARGETS)) {
            result->rt_available = 0;
            kc_copy(result->rt_reason, sizeof(result->rt_reason),
                    "rt_preconditions_not_met");
            kc_fail(result->failure_stage, sizeof(result->failure_stage), result->error,
                    sizeof(result->error), "preflight_rt",
                    "rt_watchdog_quota_threads_affinity_or_rollback_precondition_failed");
            return JMX_KERNEL_CONTROLS_ERR_FORBIDDEN;
        }
        preflight_thread_count = preflight.thread_count;
    } else {
        kc_fail(result->failure_stage, sizeof(result->failure_stage), result->error,
                sizeof(result->error), "preflight_mode", "scheduler_mode_invalid");
        return JMX_KERNEL_CONTROLS_ERR_INVALID;
    }
    if (request->mode != JMX_SCHEDULER_MODE_RT &&
        o->resolve(o->context, request->service_id, &pid, &generation) != 0)
        goto target_gone;
    if (o->threads(o->context, pid, tids, JMX_KERNEL_CONTROLS_MAX_TARGETS, &count) != 0 ||
        !count || count > JMX_KERNEL_CONTROLS_MAX_TARGETS ||
        (o->max_threads && count > o->max_threads)) {
        kc_fail(result->failure_stage, sizeof(result->failure_stage), result->error,
                sizeof(result->error), "snapshot_threads", "thread_enumeration_failed_or_exceeded");
        return JMX_KERNEL_CONTROLS_ERR_PROBE;
    }
    if (request->mode == JMX_SCHEDULER_MODE_RT &&
        count != preflight_thread_count) {
        result->rt_available = 0;
        kc_copy(result->rt_reason, sizeof(result->rt_reason),
                "rt_thread_set_changed_after_preflight");
        kc_fail(result->failure_stage, sizeof(result->failure_stage), result->error,
                sizeof(result->error), "snapshot_threads",
                "rt_thread_count_changed_after_preflight");
        return JMX_KERNEL_CONTROLS_ERR_TARGET_GONE;
    }
    result->target_count = count;
    for (i = 0; i < count; i++) {
        if (o->get(o->context, tids[i], &before[i]) != 0) {
            kc_fail(result->failure_stage, sizeof(result->failure_stage), result->error,
                    sizeof(result->error), "snapshot_threads", "thread_state_probe_failed");
            return JMX_KERNEL_CONTROLS_ERR_PROBE;
        }
        desired[i] = before[i];
        result->targets[i].tid = tids[i];
        if (request->mode == JMX_SCHEDULER_MODE_NICE)
            desired[i].nice = request->nice;
        else {
            desired[i].policy = request->policy;
            desired[i].rt_priority = request->rt_priority;
        }
    }
    {
        pid_t current_pid;
        unsigned long current_generation;
        if (o->resolve(o->context, request->service_id, &current_pid,
                       &current_generation) != 0 || current_pid != pid ||
            current_generation != generation) {
            kc_fail(result->failure_stage, sizeof(result->failure_stage), result->error,
                    sizeof(result->error), "pre_apply_identity",
                    "service_restarted_before_apply");
            return JMX_KERNEL_CONTROLS_ERR_TARGET_GONE;
        }
    }
    for (i = 0; i < count; i++) {
        struct jmx_scheduler_thread_state readback;
        if (o->set(o->context, tids[i], &desired[i]) != 0) {
            if (o->get(o->context, tids[i], &readback) != 0 ||
                !kc_sched_equal(&readback, &before[i], request->mode)) {
                result->targets[i].changed = 1;
                changed_count = i + 1U;
            }
            status = JMX_KERNEL_CONTROLS_ERR_EXEC;
            kc_fail(result->failure_stage, sizeof(result->failure_stage), result->error,
                    sizeof(result->error), "scheduler_apply", "thread_update_failed");
            break;
        }
        result->targets[i].changed = 1;
        changed_count = i + 1U;
        if (o->get(o->context, tids[i], &readback) != 0 ||
            !kc_sched_equal(&readback, &desired[i], request->mode)) {
            status = JMX_KERNEL_CONTROLS_ERR_READBACK;
            kc_fail(result->failure_stage, sizeof(result->failure_stage), result->error,
                    sizeof(result->error), "scheduler_readback", "thread_readback_failed");
            break;
        }
        result->targets[i].readback_ok = 1;
    }
    if (status == JMX_KERNEL_CONTROLS_OK) {
        result->applied = 1;
        if (binding) {
            struct jmx_scheduler_request saved = *request;
            char service_id[JMX_KERNEL_CONTROLS_NAME_MAX];
            kc_copy(service_id, sizeof(service_id), request->service_id);
            memset(binding, 0, sizeof(*binding));
            binding->active = 1;
            binding->generation = generation;
            kc_copy(binding->service_id, sizeof(binding->service_id), service_id);
            saved.service_id = binding->service_id;
            binding->request = saved;
        }
        return status;
    }
    result->rollback_attempted = 1;
    result->rollback_ok = 1;
    i = changed_count;
    while (i > 0) {
        struct jmx_scheduler_thread_state readback;
        size_t index = --i;
        if (!result->targets[index].changed)
            continue;
        result->targets[index].rollback_attempted = 1;
        if (o->set(o->context, tids[index], &before[index]) != 0 ||
            o->get(o->context, tids[index], &readback) != 0 ||
            !kc_sched_equal(&readback, &before[index], request->mode)) {
            result->targets[index].rollback_ok = 0;
            result->rollback_ok = 0;
        } else {
            result->targets[index].rollback_ok = 1;
        }
    }
    if (!result->rollback_ok) {
        kc_copy(result->failure_stage, sizeof(result->failure_stage), "scheduler_rollback");
        kc_copy(result->error, sizeof(result->error), "thread_rollback_failed");
        return JMX_KERNEL_CONTROLS_ERR_ROLLBACK;
    }
    return status;
target_gone:
    kc_fail(result->failure_stage, sizeof(result->failure_stage), result->error,
            sizeof(result->error), "resolve_service", "service_target_gone");
    return JMX_KERNEL_CONTROLS_ERR_TARGET_GONE;
}

int jmx_scheduler_reconcile(const struct jmx_scheduler_options *o,
                            struct jmx_scheduler_binding *binding,
                            struct jmx_scheduler_result *result)
{
    pid_t pid;
    unsigned long generation;
    if (!result || !binding || !binding->active)
        return JMX_KERNEL_CONTROLS_ERR_INVALID;
    if (!o || !o->resolve ||
        o->resolve(o->context, binding->request.service_id, &pid, &generation) != 0) {
        memset(result, 0, sizeof(*result));
        result->binding_cleared = 1;
        binding->active = 0;
        kc_copy(result->failure_stage, sizeof(result->failure_stage), "reconcile_exit");
        kc_copy(result->error, sizeof(result->error), "service_exited_binding_cleared");
        return JMX_KERNEL_CONTROLS_ERR_TARGET_GONE;
    }
    if (generation == binding->generation) {
        jmx_scheduler_capabilities(o, result);
        return JMX_KERNEL_CONTROLS_OK;
    }
    if (!binding->request.persistent) {
        jmx_scheduler_capabilities(o, result);
        result->target_restarted = 1;
        result->binding_cleared = 1;
        binding->active = 0;
        return JMX_KERNEL_CONTROLS_OK;
    }
    {
        struct jmx_scheduler_request request = binding->request;
        char service_id[JMX_KERNEL_CONTROLS_NAME_MAX];
        kc_copy(service_id, sizeof(service_id), binding->service_id);
        request.service_id = service_id;
        int rc = jmx_scheduler_apply(o, &request, binding, result);
        result->target_restarted = 1;
        return rc;
    }
}

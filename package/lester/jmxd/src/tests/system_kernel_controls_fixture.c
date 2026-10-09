// SPDX-License-Identifier: GPL-2.0-or-later
#define _POSIX_C_SOURCE 200809L

#include "system/system_kernel_controls.h"

#include <assert.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct fixture {
    char proc_modules[1024];
    int safe_base;
    int safe_leaf;
    int candidate;
    int protected_net;
    int outsider;
    int external_user;
    int protected_user;
    int fail_unload_base;
    int fail_unload_base_after_effect;
    int stale_unload_base;
    int fail_rescue_leaf;
    int fail_snapshot_candidate;
    pid_t pid;
    unsigned long generation;
    int resolve_missing;
    struct jmx_scheduler_thread_state threads[3];
    int fail_set_tid;
    int fail_set_after_effect_tid;
    int fail_rollback_tid;
    int fail_get_after_set_tid;
    int get_failure_armed;
    struct jmx_scheduler_preflight preflight;
};

static void modules_write(struct fixture *f)
{
    FILE *fp = fopen(f->proc_modules, "w");
    assert(fp);
    if (f->safe_leaf)
        fprintf(fp, "safe_leaf 1 0 -\n");
    if (f->safe_base)
        fprintf(fp, "safe_base 1 %d %s\n", f->safe_leaf ? 1 : 0,
                f->safe_leaf ? "safe_leaf," : "-");
    if (f->protected_net)
        fprintf(fp, "protected_net 1 0 -\n");
    if (f->outsider)
        fprintf(fp, "outsider 1 0 -\n");
    if (f->candidate) {
        const char *user = f->protected_user ? "protected_net," :
                           f->external_user ? "outsider," : "-";
        fprintf(fp, "candidate 1 %d %s\n", strcmp(user, "-") ? 1 : 0, user);
    }
    assert(fclose(fp) == 0);
}

static void fixture_reset(struct fixture *f, const char *root)
{
    size_t i;
    memset(f, 0, sizeof(*f));
    snprintf(f->proc_modules, sizeof(f->proc_modules), "%s/proc-modules", root);
    f->safe_base = 1;
    f->safe_leaf = 1;
    f->candidate = 1;
    f->protected_net = 1;
    f->outsider = 1;
    f->pid = 500;
    f->generation = 1;
    for (i = 0; i < 3; i++) {
        f->threads[i].tid = (pid_t)(101 + i);
        f->threads[i].nice = 0;
        f->threads[i].policy = 0;
        f->threads[i].rt_priority = 0;
    }
    f->preflight.watchdog_ok = 1;
    f->preflight.cpu_quota_ok = 1;
    f->preflight.affinity_ok = 1;
    f->preflight.rollback_runner_ok = 1;
    f->preflight.thread_count = 3;
    modules_write(f);
}

static int module_runner(void *context, const char *path, char *const argv[],
                         int timeout_ms, struct jmx_kernel_command_result *result)
{
    struct fixture *f = context;
    const char *module = argv[1];
    (void)timeout_ms;
    memset(result, 0, sizeof(*result));
    if (strstr(path, "rmmod")) {
        if (!strcmp(module, "safe_base") && f->fail_unload_base) {
            result->exit_code = 1;
            return 0;
        }
        if (!strcmp(module, "safe_leaf"))
            f->safe_leaf = 0;
        else if (!strcmp(module, "safe_base") && !f->stale_unload_base)
            f->safe_base = 0;
        else if (!strcmp(module, "candidate"))
            f->candidate = 0;
        if (!strcmp(module, "safe_base") && f->fail_unload_base_after_effect)
            result->exit_code = 1;
    } else if (strstr(path, "modprobe")) {
        if (!strcmp(module, "safe_leaf") && f->fail_rescue_leaf) {
            result->exit_code = 1;
            return 0;
        }
        if (!strcmp(module, "safe_leaf"))
            f->safe_leaf = 1;
        else if (!strcmp(module, "safe_base"))
            f->safe_base = 1;
        else if (!strcmp(module, "candidate"))
            f->candidate = 1;
    } else {
        result->exit_code = 127;
        return 0;
    }
    modules_write(f);
    return 0;
}

static int module_snapshot(void *context, const char *module, char *snapshot,
                           size_t snapshot_len)
{
    struct fixture *f = context;
    int loaded = !strcmp(module, "safe_base") ? f->safe_base :
                 !strcmp(module, "safe_leaf") ? f->safe_leaf :
                 !strcmp(module, "candidate") ? f->candidate : 0;
    if (!strcmp(module, "candidate") && f->fail_snapshot_candidate)
        return -1;
    if (!loaded || snprintf(snapshot, snapshot_len, "loaded=1;params=fixture") >=
                   (int)snapshot_len)
        return -1;
    return 0;
}

static int module_restore(void *context, const char *rescue_path,
                          const char *module, const char *snapshot,
                          int timeout_ms,
                          struct jmx_kernel_command_result *result)
{
    char *argv[] = { (char *)rescue_path, (char *)module, NULL };
    if (strcmp(snapshot, "loaded=1;params=fixture"))
        return -1;
    return module_runner(context, rescue_path, argv, timeout_ms, result);
}

static struct jmx_kernel_module_options module_options(struct fixture *f)
{
    static const char *const allowlist[] = { "safe_base", "safe_leaf", "candidate" };
    static const char *const protected_roots[] = { "protected_net" };
    struct jmx_kernel_module_options o;
    memset(&o, 0, sizeof(o));
    o.proc_modules_path = f->proc_modules;
    o.rmmod_path = "/fake/rmmod";
    o.modprobe_path = "/rescue/modprobe";
    o.allowlist = allowlist;
    o.allowlist_count = 3;
    o.protected_roots = protected_roots;
    o.protected_root_count = 1;
    o.command_timeout_ms = 100;
    o.rescue_ready = 1;
    o.runner = module_runner;
    o.snapshot = module_snapshot;
    o.restore = module_restore;
    o.runner_context = f;
    return o;
}

static void test_module_capabilities_and_fail_closed(const char *root)
{
    struct fixture f;
    struct jmx_kernel_module_options o;
    struct jmx_kernel_module_result result;
    const char *unknown[] = { "not_allowed" };
    const char *candidate[] = { "candidate" };
    struct jmx_kernel_module_request request = { unknown, 1, 0, 0 };
    fixture_reset(&f, root);
    o = module_options(&f);
    assert(jmx_kernel_module_capabilities(&o, &result) == 0);
    assert(result.temporary_available && !result.persistent_available);
    assert(strstr(result.capability_reason, "temporary_only"));
    assert(jmx_kernel_module_apply(&o, &request, &result) ==
           JMX_KERNEL_CONTROLS_ERR_FORBIDDEN);
    request.modules = candidate;
    request.persistent = 1;
    assert(jmx_kernel_module_apply(&o, &request, &result) ==
           JMX_KERNEL_CONTROLS_ERR_FORBIDDEN);
    assert(!strcmp(result.failure_stage, "preflight_persistence"));
}

static void test_module_protection_and_external_users(const char *root)
{
    struct fixture f;
    struct jmx_kernel_module_options o;
    struct jmx_kernel_module_result result;
    const char *candidate[] = { "candidate" };
    struct jmx_kernel_module_request request = { candidate, 1, 0, 0 };
    fixture_reset(&f, root);
    o = module_options(&f);
    f.protected_user = 1;
    modules_write(&f);
    assert(jmx_kernel_module_apply(&o, &request, &result) ==
           JMX_KERNEL_CONTROLS_ERR_FORBIDDEN);
    assert(!strcmp(result.failure_stage, "preflight_protected"));
    f.protected_user = 0;
    f.external_user = 1;
    modules_write(&f);
    assert(jmx_kernel_module_apply(&o, &request, &result) ==
           JMX_KERNEL_CONTROLS_ERR_BUSY);
    assert(!strcmp(result.failure_stage, "preflight_dependencies"));

    f.external_user = 0;
    f.fail_snapshot_candidate = 1;
    modules_write(&f);
    assert(jmx_kernel_module_apply(&o, &request, &result) ==
           JMX_KERNEL_CONTROLS_ERR_PROBE);
    assert(!strcmp(result.failure_stage, "snapshot"));
    assert(f.candidate);
}

static void test_module_success_and_rollback(const char *root)
{
    struct fixture f;
    struct jmx_kernel_module_options o;
    struct jmx_kernel_module_result result;
    const char *pair[] = { "safe_base", "safe_leaf" };
    struct jmx_kernel_module_request request = { pair, 2, 0, 0 };
    fixture_reset(&f, root);
    o = module_options(&f);
    assert(jmx_kernel_module_apply(&o, &request, &result) == 0);
    assert(result.applied && result.step_count == 2);
    assert(!strcmp(result.steps[0].module, "safe_leaf"));
    assert(!strcmp(result.steps[1].module, "safe_base"));
    assert(!f.safe_leaf && !f.safe_base);

    fixture_reset(&f, root);
    o = module_options(&f);
    f.fail_unload_base = 1;
    assert(jmx_kernel_module_apply(&o, &request, &result) ==
           JMX_KERNEL_CONTROLS_ERR_EXEC);
    assert(result.rollback_attempted && result.rollback_ok);
    assert(f.safe_leaf && f.safe_base);
    assert(result.steps[0].rollback_attempted && result.steps[0].rollback_ok);

    fixture_reset(&f, root);
    o = module_options(&f);
    f.stale_unload_base = 1;
    assert(jmx_kernel_module_apply(&o, &request, &result) ==
           JMX_KERNEL_CONTROLS_ERR_READBACK);
    assert(result.rollback_attempted && result.rollback_ok);
    assert(f.safe_leaf && f.safe_base);
    assert(result.steps[1].rollback_attempted && result.steps[1].rollback_ok);

    fixture_reset(&f, root);
    o = module_options(&f);
    f.fail_unload_base_after_effect = 1;
    assert(jmx_kernel_module_apply(&o, &request, &result) ==
           JMX_KERNEL_CONTROLS_ERR_EXEC);
    assert(result.rollback_attempted && result.rollback_ok);
    assert(f.safe_leaf && f.safe_base);

    fixture_reset(&f, root);
    o = module_options(&f);
    f.fail_unload_base = 1;
    f.fail_rescue_leaf = 1;
    assert(jmx_kernel_module_apply(&o, &request, &result) ==
           JMX_KERNEL_CONTROLS_ERR_ROLLBACK);
    assert(result.rollback_attempted && !result.rollback_ok);
    assert(!f.safe_leaf && f.safe_base);
}

static int scheduler_resolve(void *context, const char *service_id, pid_t *pid,
                             unsigned long *generation)
{
    struct fixture *f = context;
    if (strcmp(service_id, "core") || f->resolve_missing)
        return -1;
    *pid = f->pid;
    *generation = f->generation;
    return 0;
}

static int scheduler_threads(void *context, pid_t pid, pid_t *tids,
                             size_t capacity, size_t *count)
{
    struct fixture *f = context;
    size_t i;
    if (pid != f->pid || capacity < 3)
        return -1;
    for (i = 0; i < 3; i++)
        tids[i] = f->threads[i].tid;
    *count = 3;
    return 0;
}

static int thread_index(struct fixture *f, pid_t tid)
{
    size_t i;
    for (i = 0; i < 3; i++)
        if (f->threads[i].tid == tid)
            return (int)i;
    return -1;
}

static int scheduler_get(void *context, pid_t tid,
                         struct jmx_scheduler_thread_state *state)
{
    struct fixture *f = context;
    int index = thread_index(f, tid);
    if (index < 0)
        return -1;
    if (f->get_failure_armed && f->fail_get_after_set_tid == tid) {
        f->get_failure_armed = 0;
        f->fail_get_after_set_tid = 0;
        return -1;
    }
    *state = f->threads[index];
    return 0;
}

static int scheduler_set(void *context, pid_t tid,
                         const struct jmx_scheduler_thread_state *state)
{
    struct fixture *f = context;
    int index = thread_index(f, tid);
    if (index < 0 || f->fail_set_tid == tid ||
        (f->fail_rollback_tid == tid && state->nice == 0))
        return -1;
    f->threads[index] = *state;
    if (f->fail_set_after_effect_tid == tid) {
        f->fail_set_after_effect_tid = 0;
        return -1;
    }
    if (f->fail_get_after_set_tid == tid)
        f->get_failure_armed = 1;
    return 0;
}

static int scheduler_preflight(void *context, const char *service_id, pid_t pid,
                               struct jmx_scheduler_preflight *preflight)
{
    struct fixture *f = context;
    if (strcmp(service_id, "core") || pid != f->pid)
        return -1;
    *preflight = f->preflight;
    return 0;
}

static struct jmx_scheduler_options scheduler_options(struct fixture *f,
                                                       int rt_enabled)
{
    static const struct jmx_scheduler_service services[] = {
        { "core", -5, 10, 1, 20 }
    };
    struct jmx_scheduler_options o;
    memset(&o, 0, sizeof(o));
    o.services = services;
    o.service_count = 1;
    o.max_threads = 8;
    o.rt_enabled = rt_enabled;
    o.resolve = scheduler_resolve;
    o.threads = scheduler_threads;
    o.get = scheduler_get;
    o.set = scheduler_set;
    o.preflight = scheduler_preflight;
    o.context = f;
    return o;
}

static void test_scheduler_capabilities_and_validation(const char *root)
{
    struct fixture f;
    struct jmx_scheduler_options o;
    struct jmx_scheduler_result result;
    struct jmx_scheduler_binding binding;
    struct jmx_scheduler_request request = { "pid:500", JMX_SCHEDULER_MODE_NICE,
                                             5, 0, 0, 0 };
    fixture_reset(&f, root);
    o = scheduler_options(&f, 0);
    assert(jmx_scheduler_capabilities(&o, &result) == 0);
    assert(result.nice_available && !result.rt_available);
    assert(!strcmp(result.rt_reason, "rt_disabled_by_default"));
    assert(jmx_scheduler_apply(&o, &request, &binding, &result) ==
           JMX_KERNEL_CONTROLS_ERR_FORBIDDEN);
    request.service_id = "core";
    request.nice = -6;
    assert(jmx_scheduler_apply(&o, &request, &binding, &result) ==
           JMX_KERNEL_CONTROLS_ERR_FORBIDDEN);
}

static void test_scheduler_nice_rollback_and_target_gone(const char *root)
{
    struct fixture f;
    struct jmx_scheduler_options o;
    struct jmx_scheduler_result result;
    struct jmx_scheduler_binding binding;
    struct jmx_scheduler_request request = { "core", JMX_SCHEDULER_MODE_NICE,
                                             5, 0, 0, 0 };
    fixture_reset(&f, root);
    o = scheduler_options(&f, 0);
    memset(&binding, 0, sizeof(binding));
    f.fail_get_after_set_tid = 102;
    assert(jmx_scheduler_apply(&o, &request, &binding, &result) ==
           JMX_KERNEL_CONTROLS_ERR_READBACK);
    assert(result.rollback_attempted && result.rollback_ok);
    assert(f.threads[0].nice == 0 && f.threads[1].nice == 0 && f.threads[2].nice == 0);
    assert(result.targets[1].rollback_attempted && result.targets[1].rollback_ok);

    fixture_reset(&f, root);
    o = scheduler_options(&f, 0);
    f.fail_set_tid = 102;
    assert(jmx_scheduler_apply(&o, &request, &binding, &result) ==
           JMX_KERNEL_CONTROLS_ERR_EXEC);
    assert(result.rollback_attempted && result.rollback_ok);
    assert(f.threads[0].nice == 0 && f.threads[1].nice == 0);

    fixture_reset(&f, root);
    o = scheduler_options(&f, 0);
    f.fail_set_tid = 102;
    f.fail_rollback_tid = 101;
    assert(jmx_scheduler_apply(&o, &request, &binding, &result) ==
           JMX_KERNEL_CONTROLS_ERR_ROLLBACK);
    assert(result.rollback_attempted && !result.rollback_ok);
    assert(f.threads[0].nice == 5);

    fixture_reset(&f, root);
    o = scheduler_options(&f, 0);
    f.fail_set_after_effect_tid = 102;
    assert(jmx_scheduler_apply(&o, &request, &binding, &result) ==
           JMX_KERNEL_CONTROLS_ERR_EXEC);
    assert(result.rollback_attempted && result.rollback_ok);
    assert(f.threads[0].nice == 0 && f.threads[1].nice == 0);

    f.fail_get_after_set_tid = 0;
    f.resolve_missing = 1;
    assert(jmx_scheduler_apply(&o, &request, &binding, &result) ==
           JMX_KERNEL_CONTROLS_ERR_TARGET_GONE);
}

static void test_scheduler_rt_preflight_and_restart(const char *root)
{
    struct fixture f;
    struct jmx_scheduler_options o;
    struct jmx_scheduler_result result;
    struct jmx_scheduler_binding binding;
    struct jmx_scheduler_request request = { "core", JMX_SCHEDULER_MODE_RT,
                                             0, SCHED_FIFO, 10, 0 };
    fixture_reset(&f, root);
    o = scheduler_options(&f, 1);
    f.preflight.watchdog_ok = 0;
    assert(jmx_scheduler_apply(&o, &request, &binding, &result) ==
           JMX_KERNEL_CONTROLS_ERR_FORBIDDEN);
    assert(!strcmp(result.failure_stage, "preflight_rt"));
    assert(result.nice_available && !result.rt_available);
    assert(!strcmp(result.rt_reason, "rt_preconditions_not_met"));
    f.preflight.watchdog_ok = 1;
    f.preflight.cpu_quota_ok = 0;
    assert(jmx_scheduler_apply(&o, &request, &binding, &result) ==
           JMX_KERNEL_CONTROLS_ERR_FORBIDDEN);
    f.preflight.cpu_quota_ok = 1;
    f.preflight.affinity_ok = 0;
    assert(jmx_scheduler_apply(&o, &request, &binding, &result) ==
           JMX_KERNEL_CONTROLS_ERR_FORBIDDEN);
    f.preflight.affinity_ok = 1;
    f.preflight.rollback_runner_ok = 0;
    assert(jmx_scheduler_apply(&o, &request, &binding, &result) ==
           JMX_KERNEL_CONTROLS_ERR_FORBIDDEN);
    f.preflight.rollback_runner_ok = 1;
    f.preflight.thread_count = 99;
    assert(jmx_scheduler_apply(&o, &request, &binding, &result) ==
           JMX_KERNEL_CONTROLS_ERR_FORBIDDEN);
    f.preflight.thread_count = 3;
    request.policy = 0;
    assert(jmx_scheduler_apply(&o, &request, &binding, &result) ==
           JMX_KERNEL_CONTROLS_ERR_FORBIDDEN);
    request.policy = SCHED_FIFO;
    f.preflight.thread_count = 2;
    assert(jmx_scheduler_apply(&o, &request, &binding, &result) ==
           JMX_KERNEL_CONTROLS_ERR_TARGET_GONE);
    assert(!strcmp(result.rt_reason, "rt_thread_set_changed_after_preflight"));
    f.preflight.thread_count = 3;
    f.preflight.watchdog_ok = 1;
    assert(jmx_scheduler_apply(&o, &request, &binding, &result) == 0);
    assert(result.applied && binding.active);
    assert(f.threads[0].policy == SCHED_FIFO && f.threads[0].rt_priority == 10);
    f.generation++;
    assert(jmx_scheduler_reconcile(&o, &binding, &result) == 0);
    assert(result.target_restarted && result.binding_cleared && !binding.active);

    fixture_reset(&f, root);
    o = scheduler_options(&f, 1);
    request.persistent = 1;
    assert(jmx_scheduler_apply(&o, &request, &binding, &result) == 0);
    f.generation++;
    assert(jmx_scheduler_reconcile(&o, &binding, &result) == 0);
    assert(result.target_restarted && result.applied && binding.active);
    assert(binding.generation == f.generation);
    f.resolve_missing = 1;
    assert(jmx_scheduler_reconcile(&o, &binding, &result) ==
           JMX_KERNEL_CONTROLS_ERR_TARGET_GONE);
    assert(result.binding_cleared && !binding.active);
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    test_module_capabilities_and_fail_closed(argv[1]);
    test_module_protection_and_external_users(argv[1]);
    test_module_success_and_rollback(argv[1]);
    test_scheduler_capabilities_and_validation(argv[1]);
    test_scheduler_nice_rollback_and_target_gone(argv[1]);
    test_scheduler_rt_preflight_and_restart(argv[1]);
    puts("system_kernel_controls: PASS");
    return 0;
}

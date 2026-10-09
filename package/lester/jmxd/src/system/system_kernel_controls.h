// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_SYSTEM_KERNEL_CONTROLS_H
#define DREAMINGWRT_SYSTEM_KERNEL_CONTROLS_H

#include <stddef.h>
#include <sys/types.h>

#define JMX_KERNEL_CONTROLS_CONTRACT_VERSION "system-kernel-controls.v1"
#define JMX_KERNEL_CONTROLS_MAX_MODULES 64U
#define JMX_KERNEL_CONTROLS_MAX_TARGETS 128U
#define JMX_KERNEL_CONTROLS_NAME_MAX 64U
#define JMX_KERNEL_CONTROLS_ERROR_MAX 192U
#define JMX_KERNEL_CONTROLS_SNAPSHOT_MAX 512U

enum jmx_kernel_controls_status {
    JMX_KERNEL_CONTROLS_OK = 0,
    JMX_KERNEL_CONTROLS_ERR_INVALID = -1,
    JMX_KERNEL_CONTROLS_ERR_FORBIDDEN = -2,
    JMX_KERNEL_CONTROLS_ERR_PROBE = -3,
    JMX_KERNEL_CONTROLS_ERR_BUSY = -4,
    JMX_KERNEL_CONTROLS_ERR_EXEC = -5,
    JMX_KERNEL_CONTROLS_ERR_READBACK = -6,
    JMX_KERNEL_CONTROLS_ERR_ROLLBACK = -7,
    JMX_KERNEL_CONTROLS_ERR_TARGET_GONE = -8
};

struct jmx_kernel_command_result {
    int exit_code;
    int term_signal;
    int timed_out;
};

typedef int (*jmx_kernel_command_runner_fn)(
    void *context, const char *path, char *const argv[], int timeout_ms,
    struct jmx_kernel_command_result *result);
typedef int (*jmx_kernel_module_snapshot_fn)(
    void *context, const char *module, char *snapshot, size_t snapshot_len);
typedef int (*jmx_kernel_module_restore_fn)(
    void *context, const char *rescue_path, const char *module,
    const char *snapshot, int timeout_ms,
    struct jmx_kernel_command_result *result);

struct jmx_kernel_module_options {
    const char *proc_modules_path;
    const char *rmmod_path;
    const char *modprobe_path;
    const char *const *allowlist;
    size_t allowlist_count;
    const char *const *protected_roots;
    size_t protected_root_count;
    int command_timeout_ms;
    int rescue_ready;
    jmx_kernel_command_runner_fn runner;
    jmx_kernel_module_snapshot_fn snapshot;
    jmx_kernel_module_restore_fn restore;
    void *runner_context;
};

struct jmx_kernel_module_request {
    const char *const *modules;
    size_t module_count;
    int persistent;
    int persistent_confirmation;
};

struct jmx_kernel_module_step {
    char module[JMX_KERNEL_CONTROLS_NAME_MAX];
    int changed;
    int readback_ok;
    int rollback_attempted;
    int rollback_ok;
};

struct jmx_kernel_module_result {
    int temporary_available;
    int persistent_available;
    int snapshot_captured;
    int applied;
    int rollback_attempted;
    int rollback_ok;
    char capability_reason[JMX_KERNEL_CONTROLS_ERROR_MAX];
    char failure_stage[48];
    char error[JMX_KERNEL_CONTROLS_ERROR_MAX];
    size_t step_count;
    struct jmx_kernel_module_step steps[JMX_KERNEL_CONTROLS_MAX_MODULES];
};

int jmx_kernel_module_capabilities(
    const struct jmx_kernel_module_options *options,
    struct jmx_kernel_module_result *result);
int jmx_kernel_module_apply(
    const struct jmx_kernel_module_options *options,
    const struct jmx_kernel_module_request *request,
    struct jmx_kernel_module_result *result);

enum jmx_scheduler_mode {
    JMX_SCHEDULER_MODE_NICE = 1,
    JMX_SCHEDULER_MODE_RT = 2
};

struct jmx_scheduler_service {
    const char *service_id;
    int min_nice;
    int max_nice;
    int allow_rt;
    int max_rt_priority;
};

struct jmx_scheduler_thread_state {
    pid_t tid;
    int nice;
    int policy;
    int rt_priority;
};

struct jmx_scheduler_preflight {
    int watchdog_ok;
    int cpu_quota_ok;
    int affinity_ok;
    int rollback_runner_ok;
    size_t thread_count;
};

typedef int (*jmx_scheduler_resolve_fn)(
    void *context, const char *service_id, pid_t *pid, unsigned long *generation);
typedef int (*jmx_scheduler_threads_fn)(
    void *context, pid_t pid, pid_t *tids, size_t capacity, size_t *count);
typedef int (*jmx_scheduler_get_fn)(
    void *context, pid_t tid, struct jmx_scheduler_thread_state *state);
typedef int (*jmx_scheduler_set_fn)(
    void *context, pid_t tid, const struct jmx_scheduler_thread_state *state);
typedef int (*jmx_scheduler_preflight_fn)(
    void *context, const char *service_id, pid_t pid,
    struct jmx_scheduler_preflight *preflight);

struct jmx_scheduler_options {
    const struct jmx_scheduler_service *services;
    size_t service_count;
    size_t max_threads;
    int rt_enabled;
    jmx_scheduler_resolve_fn resolve;
    jmx_scheduler_threads_fn threads;
    jmx_scheduler_get_fn get;
    jmx_scheduler_set_fn set;
    jmx_scheduler_preflight_fn preflight;
    void *context;
};

struct jmx_scheduler_request {
    const char *service_id;
    enum jmx_scheduler_mode mode;
    int nice;
    int policy;
    int rt_priority;
    int persistent;
};

struct jmx_scheduler_target_result {
    pid_t tid;
    int changed;
    int readback_ok;
    int rollback_attempted;
    int rollback_ok;
};

struct jmx_scheduler_binding {
    int active;
    unsigned long generation;
    char service_id[JMX_KERNEL_CONTROLS_NAME_MAX];
    struct jmx_scheduler_request request;
};

struct jmx_scheduler_result {
    int nice_available;
    int rt_available;
    char nice_reason[JMX_KERNEL_CONTROLS_ERROR_MAX];
    char rt_reason[JMX_KERNEL_CONTROLS_ERROR_MAX];
    int applied;
    int rollback_attempted;
    int rollback_ok;
    int target_restarted;
    int binding_cleared;
    char failure_stage[48];
    char error[JMX_KERNEL_CONTROLS_ERROR_MAX];
    size_t target_count;
    struct jmx_scheduler_target_result targets[JMX_KERNEL_CONTROLS_MAX_TARGETS];
};

int jmx_scheduler_capabilities(const struct jmx_scheduler_options *options,
                               struct jmx_scheduler_result *result);
int jmx_scheduler_apply(const struct jmx_scheduler_options *options,
                        const struct jmx_scheduler_request *request,
                        struct jmx_scheduler_binding *binding,
                        struct jmx_scheduler_result *result);
int jmx_scheduler_reconcile(const struct jmx_scheduler_options *options,
                            struct jmx_scheduler_binding *binding,
                            struct jmx_scheduler_result *result);

#endif

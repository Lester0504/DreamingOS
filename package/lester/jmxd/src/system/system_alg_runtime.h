// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_SYSTEM_ALG_RUNTIME_H
#define DREAMINGWRT_SYSTEM_ALG_RUNTIME_H

#include <stddef.h>

#define JMX_SYSTEM_ALG_CONTRACT_VERSION "system-alg-runtime.v1"
#define JMX_SYSTEM_ALG_PORTS_MAX 128
#define JMX_SYSTEM_ALG_ERROR_MAX 160
#define JMX_SYSTEM_ALG_COMMAND_OUTPUT_MAX (256U * 1024U)

enum jmx_system_alg_helper {
    JMX_SYSTEM_ALG_FTP = 0,
    JMX_SYSTEM_ALG_TFTP,
    JMX_SYSTEM_ALG_SIP,
    JMX_SYSTEM_ALG_H323,
    JMX_SYSTEM_ALG_HELPER_COUNT
};

enum jmx_system_alg_status {
    JMX_SYSTEM_ALG_OK = 0,
    JMX_SYSTEM_ALG_ERR_INVALID = -1,
    JMX_SYSTEM_ALG_ERR_UNSUPPORTED = -2,
    JMX_SYSTEM_ALG_ERR_NOT_FOUND = -3,
    JMX_SYSTEM_ALG_ERR_BUSY = -4,
    JMX_SYSTEM_ALG_ERR_IO = -5,
    JMX_SYSTEM_ALG_ERR_EXEC = -6,
    JMX_SYSTEM_ALG_ERR_READBACK = -7,
    JMX_SYSTEM_ALG_ERR_ROLLBACK = -8,
    JMX_SYSTEM_ALG_ERR_PROBE = -9
};

struct jmx_system_alg_command_result {
    char *output;
    size_t output_len;
    int exit_code;
    int term_signal;
    int timed_out;
    int truncated;
};

typedef int (*jmx_system_alg_runner_fn)(
    void *context, const char *path, char *const argv[], size_t output_limit,
    int timeout_ms, struct jmx_system_alg_command_result *result);

typedef void (*jmx_system_alg_runner_free_fn)(
    void *context, struct jmx_system_alg_command_result *result);

struct jmx_system_alg_options {
    const char *sys_module_root;
    const char *module_root;
    const char *proc_modules_path;
    const char *conntrack_path;
    const char *auto_helper_path;
    const char *modules_dir;
    const char *modprobe_path;
    const char *rmmod_path;
    const char *nft_path;
    int command_timeout_ms;
    jmx_system_alg_runner_fn runner;
    jmx_system_alg_runner_free_fn runner_free;
    void *runner_context;
};

struct jmx_system_alg_state {
    enum jmx_system_alg_helper helper;
    char name[16];
    char conntrack_module[48];
    char nat_module[48];
    int conntrack_available;
    int nat_available;
    int conntrack_loaded;
    int nat_loaded;
    unsigned int conntrack_refcount;
    unsigned int nat_refcount;
    unsigned int external_module_users;
    int nft_probe_ok;
    int nft_declared;
    int nft_assigned;
    int conntrack_probe_ok;
    unsigned int conntrack_active;
    int auto_helper_known;
    int auto_helper_enabled;
    int running_known;
    int running;
    int ports_supported;
    int ports_writable;
    char ports[JMX_SYSTEM_ALG_PORTS_MAX];
    int persisted_known;
    int persisted;
    int persisted_partial;
    char persisted_ports[JMX_SYSTEM_ALG_PORTS_MAX];
};

struct jmx_system_alg_request {
    enum jmx_system_alg_helper helper;
    int enabled;
    /* NULL means preserve the current/persisted value. H323 accepts only NULL. */
    const char *ports;
};

struct jmx_system_alg_result {
    int persisted;
    int applied;
    int running;
    int running_known;
    int reboot_required;
    int rollback_attempted;
    int rollback_succeeded;
    char failure_stage[48];
    char error[JMX_SYSTEM_ALG_ERROR_MAX];
    struct jmx_system_alg_state before;
    struct jmx_system_alg_state after;
};

const char *jmx_system_alg_helper_name(enum jmx_system_alg_helper helper);
int jmx_system_alg_helper_parse(const char *name,
                                enum jmx_system_alg_helper *helper_out);

int jmx_system_alg_probe(const struct jmx_system_alg_options *options,
                         enum jmx_system_alg_helper helper,
                         struct jmx_system_alg_state *state,
                         char *error, size_t error_len);

/*
 * Applies runtime and startup state as one transaction. A successful return may
 * still report applied=0 with reboot_required=1 when a loaded module exposes a
 * read-only ports parameter; the requested port is then persisted for next load.
 */
int jmx_system_alg_apply(const struct jmx_system_alg_options *options,
                         const struct jmx_system_alg_request *request,
                         struct jmx_system_alg_result *result);

void jmx_system_alg_command_result_free(
    struct jmx_system_alg_command_result *result);

#endif /* DREAMINGWRT_SYSTEM_ALG_RUNTIME_H */

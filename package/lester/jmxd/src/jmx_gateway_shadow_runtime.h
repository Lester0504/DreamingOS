// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * jmx_gateway_shadow_runtime.h - Gateway Shadow daemon runtime helpers
 *
 * This module is intentionally independent from the Gateway Shadow database
 * and API control plane.  Callers provide an already assembled configuration;
 * this module validates it again before any file or process operation.
 */
#ifndef __JMX_GATEWAY_SHADOW_RUNTIME_H__
#define __JMX_GATEWAY_SHADOW_RUNTIME_H__

#include <limits.h>
#include <stddef.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

enum jmx_gateway_shadow_runtime_code {
    JMX_GS_RUNTIME_OK = 0,
    JMX_GS_RUNTIME_INVALID_ARGUMENT = -1,
    JMX_GS_RUNTIME_INVALID_ROLE = -2,
    JMX_GS_RUNTIME_INVALID_INTERFACE = -3,
    JMX_GS_RUNTIME_INVALID_HEARTBEAT_ADDRESS = -4,
    JMX_GS_RUNTIME_INVALID_VIRTUAL_ADDRESS = -5,
    JMX_GS_RUNTIME_INVALID_VRRP = -6,
    JMX_GS_RUNTIME_PREEMPT_UNSUPPORTED = -7,
    JMX_GS_RUNTIME_DIRECTORY_ERROR = -20,
    JMX_GS_RUNTIME_WRITE_ERROR = -21,
    JMX_GS_RUNTIME_COMMIT_ERROR = -22,
    JMX_GS_RUNTIME_EXEC_ERROR = -30,
    JMX_GS_RUNTIME_CHILD_FAILED = -31,
    JMX_GS_RUNTIME_UNSUPPORTED = -32
};

enum jmx_gateway_shadow_daemon {
    JMX_GS_DAEMON_KEEPALIVED = 1,
    JMX_GS_DAEMON_CONNTRACKD = 2
};

enum jmx_gateway_shadow_daemon_action {
    JMX_GS_DAEMON_START = 1,
    JMX_GS_DAEMON_RELOAD = 2,
    JMX_GS_DAEMON_STOP = 3
};

struct jmx_gateway_shadow_runtime_config {
    const char *role;                 /* primary or secondary */
    const char *lan_interface;
    const char *heartbeat_interface;
    const char *heartbeat_local_ip;   /* dedicated 169.254/16 address */
    const char *heartbeat_peer_ip;    /* dedicated 169.254/16 peer */
    const char *virtual_ipv4;         /* address/prefix */
    unsigned int virtual_router_id;   /* 1..255 */
    unsigned int priority;            /* 1..254 */
    unsigned int advert_interval_seconds; /* 1..60 */
    int preempt;                      /* phase one requires false */
    int connection_sync;
};

struct jmx_gateway_shadow_runtime_result {
    int code;
    int system_errno;
    int child_exit_status;
    char message[256];
    char child_output[512];
    char keepalived_path[PATH_MAX];
    char conntrackd_path[PATH_MAX];
};

/* Validate all fields without touching the filesystem. */
int jmx_gateway_shadow_runtime_validate(
    const struct jmx_gateway_shadow_runtime_config *config,
    struct jmx_gateway_shadow_runtime_result *result);

/*
 * Render keepalived.conf and conntrackd.conf into output_directory.  Both
 * files are mode 0600 and are staged, fsync'd, then transactionally replaced.
 * output_directory must already exist and must not be a symlink.
 */
int jmx_gateway_shadow_runtime_render(
    const struct jmx_gateway_shadow_runtime_config *config,
    const char *output_directory,
    struct jmx_gateway_shadow_runtime_result *result);

/*
 * Run a daemon's non-starting configuration check with fork+execv.
 * Keepalived is invoked as: keepalived -t -f <config>.  Conntrackd has no
 * non-starting config-test mode and therefore returns RUNTIME_UNSUPPORTED.
 */
int jmx_gateway_shadow_runtime_config_test(
    enum jmx_gateway_shadow_daemon daemon,
    const char *binary_path,
    const char *config_path,
    struct jmx_gateway_shadow_runtime_result *result);

/*
 * Control the dedicated Shadow daemon instance without any OpenWrt init
 * script.  Keepalived uses its own parent/VRRP pidfiles and the supplied -f
 * configuration.  Conntrackd always receives -C with the supplied Shadow
 * configuration.  Conntrackd reload is explicitly unsupported; callers must
 * transactionally stop and start it instead.
 */
int jmx_gateway_shadow_runtime_daemon_control(
    enum jmx_gateway_shadow_daemon daemon,
    enum jmx_gateway_shadow_daemon_action action,
    const char *binary_path,
    const char *config_path,
    struct jmx_gateway_shadow_runtime_result *result);

#endif /* __JMX_GATEWAY_SHADOW_RUNTIME_H__ */

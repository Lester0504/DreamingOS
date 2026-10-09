// SPDX-License-Identifier: GPL-2.0-or-later
/* DreamingWrt logd: durable normalized event store and collector daemon. */
#include "logd_internal.h"
#include "../storage/storage_binding.h"

/*
 * A persisted "log" binding (storage migration, or --work_dir= materialized
 * by dreamingwrt-init from /etc/dreamingos_features) must survive a restart;
 * before this, only the runtime storage_reopen path honoured it and every
 * restart fell back to the flash default. An unusable external path is a
 * hard start failure, as it is for auditd/aegisxd, so the supervisor retries
 * instead of silently writing a fresh log.db to flash.
 */
static int logd_load_storage_assignment(void)
{
    char active_path[sizeof(g_logd_db_path)] = "";
    char reason[96] = "";

    if (logd_ap_mode()) {
        snprintf(g_logd_db_path, sizeof(g_logd_db_path), ":memory:");
        return 0;
    }
    if (jmx_storage_binding_read("log", NULL, 0, active_path, sizeof(active_path),
                                 NULL, 0, reason, sizeof(reason)) != 0)
        return -1;
    if (!active_path[0])
        return 0;
    if (!jmx_storage_binding_path_ready(active_path, 0)) {
        fprintf(stderr, "[dreamingwrt-logd] external_storage_unavailable path=%s reason=%s\n",
                active_path, reason);
        return -1;
    }
    snprintf(g_logd_db_path, sizeof(g_logd_db_path), "%s", active_path);
    return 0;
}

static void logd_handle_signal(int signo)
{
    (void)signo;
    uloop_end();
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    signal(SIGINT, logd_handle_signal);
    signal(SIGTERM, logd_handle_signal);

    if (logd_load_storage_assignment() != 0 ||
        logd_db_init() != 0 || logd_config_db_init() != 0)
        return 1;
    logd_collector_state_prune();
    uloop_init();
    if (logd_ubus_start() != 0) {
        uloop_done();
        logd_db_close();
        return 1;
    }

    fprintf(stderr, "[dreamingwrt-logd] started db=%s\n", g_logd_db_path);
    logd_collectors_start();
    uloop_run();

    logd_collectors_stop();
    logd_ubus_stop();
    uloop_done();
    logd_db_close();
    return 0;
}

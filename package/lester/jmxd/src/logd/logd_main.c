// SPDX-License-Identifier: GPL-2.0-or-later
/* DreamingWrt logd: durable normalized event store and collector daemon. */
#include "logd_internal.h"

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

    if (logd_db_init() != 0 || logd_config_db_init() != 0)
        return 1;
    logd_collector_state_prune();
    uloop_init();
    if (logd_ubus_start() != 0) {
        uloop_done();
        logd_db_close();
        return 1;
    }

    fprintf(stderr, "[dreamingwrt-logd] started db=%s\n", LOGD_DB_PATH);
    logd_collectors_start();
    uloop_run();

    logd_collectors_stop();
    logd_ubus_stop();
    uloop_done();
    logd_db_close();
    return 0;
}

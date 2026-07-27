// SPDX-License-Identifier: GPL-2.0-or-later
/* DreamingWrt authentication session and portal control-plane daemon. */
#include "authd_internal.h"

static void authd_handle_signal(int signo)
{
    (void)signo;
    uloop_end();
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    signal(SIGINT, authd_handle_signal);
    signal(SIGTERM, authd_handle_signal);

    g_authd_started_at = authd_now_s();
    if (authd_db_init() != 0)
        return 1;
    uloop_init();
    if (authd_ubus_start() != 0) {
        uloop_done();
        authd_db_close();
        return 1;
    }

    fprintf(stderr, "[dreamingwrt-authd] started config=%s schema=%d\n",
            AUTHD_CONFIG_DB_PATH, AUTHD_SCHEMA_VERSION);
    uloop_run();

    authd_ubus_stop();
    uloop_done();
    authd_db_close();
    return 0;
}

// SPDX-License-Identifier: GPL-2.0-or-later
/* DreamingWrt notifyd: notification routing, outbox, and delivery boundary. */
#include "notifyd_internal.h"

#include <curl/curl.h>

static void notifyd_handle_signal(int signo)
{
    (void)signo;
    uloop_end();
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    signal(SIGINT, notifyd_handle_signal);
    signal(SIGTERM, notifyd_handle_signal);

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
        return 1;
    if (notifyd_db_init() != 0)
        goto fail_curl;
    uloop_init();
    if (notifyd_ubus_start() != 0) {
        uloop_done();
        notifyd_db_close();
        goto fail_curl;
    }

    fprintf(stderr, "[dreamingwrt-notifyd] started db=%s config=%s\n",
            NOTIFYD_DB_PATH, NOTIFYD_CONFIG_DB_PATH);
    notifyd_prune_if_needed();
    notifyd_delivery_start();
    uloop_run();

    notifyd_delivery_stop();
    notifyd_ubus_stop();
    uloop_done();
    notifyd_db_close();
    curl_global_cleanup();
    return 0;

fail_curl:
    curl_global_cleanup();
    return 1;
}

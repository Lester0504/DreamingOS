// SPDX-License-Identifier: GPL-2.0-or-later
/* DreamingWrt aegisxd: security intelligence and policy control-plane daemon. */
#include "aegisxd_internal.h"

static void aegisxd_handle_signal(int signo)
{
    (void)signo;
    uloop_end();
}

int main(int argc, char **argv)
{
    signal(SIGINT, aegisxd_handle_signal);
    signal(SIGTERM, aegisxd_handle_signal);
    signal(SIGCHLD, SIG_IGN);

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
        return 1;
    if (argc >= 2 && !strcmp(argv[1], "--feed-import-worker")) {
        const char *job_id = argc >= 3 ? argv[2] : "";
        const char *feed_id = argc >= 4 ? argv[3] : "";
        int rc;

        rc = aegisxd_feed_import_worker_main(job_id, feed_id);
        curl_global_cleanup();
        return rc;
    }
    if (argc >= 2 && !strcmp(argv[1], "--feed-update-worker")) {
        const char *job_id = argc >= 3 ? argv[2] : "";
        const char *feed_id = argc >= 4 ? argv[3] : "";
        int dry_run = argc >= 5 ? atoi(argv[4]) : 1;
        int rc;

        rc = aegisxd_feed_update_worker_main(job_id, feed_id, dry_run);
        curl_global_cleanup();
        return rc;
    }
    if (aegisxd_db_init() != 0)
        goto fail_curl;
    uloop_init();
    if (aegisxd_ubus_start() != 0) {
        uloop_done();
        aegisxd_db_close();
        goto fail_curl;
    }
    if (aegisxd_honeypot_reconcile() != 0)
        fprintf(stderr, "[dreamingwrt-aegisxd] honeypot runtime reconciliation failed\n");
    aegisxd_hit_producer_start();

    fprintf(stderr, "[dreamingwrt-aegisxd] started config=%s db=%s dataplane=disabled\n",
            AEGISXD_CONFIG_DB_PATH, AEGISXD_DB_PATH);
    uloop_run();

    aegisxd_hit_producer_stop();
    aegisxd_ubus_stop();
    uloop_done();
    aegisxd_db_close();
    curl_global_cleanup();
    return 0;

fail_curl:
    curl_global_cleanup();
    return 1;
}

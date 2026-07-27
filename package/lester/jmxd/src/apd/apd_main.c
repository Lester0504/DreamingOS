// SPDX-License-Identifier: GPL-2.0-or-later
/* DreamingWrt AP node agent. */
#include "apd_config_job_journal.h"
#include "apd_internal.h"

static void apd_handle_signal(int signo)
{
    (void)signo;
    uloop_end();
}

int main(int argc, char **argv)
{
    struct sigaction child_action;
    int interrupted_jobs = 0;

    (void)argc;
    (void)argv;

    memset(&child_action, 0, sizeof(child_action));
    child_action.sa_handler = SIG_DFL;
    sigemptyset(&child_action.sa_mask);
    if (sigaction(SIGCHLD, &child_action, NULL) != 0) {
        fprintf(stderr, "[%s] startup failed stage=sigchld errno=%d\n",
                APD_SERVICE_NAME, errno);
        return 1;
    }
    signal(SIGINT, apd_handle_signal);
    signal(SIGTERM, apd_handle_signal);
    g_apd_started_at = apd_now_s();

    if (apd_db_init() != 0) {
        fprintf(stderr, "[%s] startup failed stage=db_init\n",
                APD_SERVICE_NAME);
        return 1;
    }
    if (apd_radio_job_journal_init() != APD_RADIO_JOB_JOURNAL_OK ||
        apd_radio_job_restart_recover(apd_now_s(), &interrupted_jobs) !=
            APD_RADIO_JOB_JOURNAL_OK) {
        fprintf(stderr, "[%s] startup failed stage=radio_job_recovery\n",
                APD_SERVICE_NAME);
        goto fail_db;
    }
    /* The config job journal table is created up front so crash recovery
     * has a definite surface, even though the executor stays dormant. */
    if (apd_config_job_journal_init() != APD_CONFIG_JOB_JOURNAL_OK) {
        fprintf(stderr, "[%s] startup failed stage=config_job_journal\n",
                APD_SERVICE_NAME);
        goto fail_db;
    }
    if (interrupted_jobs > 0)
        fprintf(stderr, "[%s] radio jobs recovered interrupted=%d\n",
                APD_SERVICE_NAME, interrupted_jobs);
    if (apd_protocol_init() != 0) {
        fprintf(stderr, "[%s] startup failed stage=protocol_init\n",
                APD_SERVICE_NAME);
        goto fail_db;
    }
    if (uloop_init() != 0) {
        fprintf(stderr, "[%s] startup failed stage=uloop_init\n",
                APD_SERVICE_NAME);
        goto fail_protocol;
    }
    if (apd_ubus_start() != 0) {
        fprintf(stderr, "[%s] startup failed stage=ubus_start\n",
                APD_SERVICE_NAME);
        goto fail_uloop;
    }
    if (apd_transport_start() != 0) {
        fprintf(stderr, "[%s] startup failed stage=transport_start reason=%s\n",
                APD_SERVICE_NAME, apd_transport_reason());
        goto fail_ubus;
    }

    fprintf(stderr,
            "[%s] started contract=%s schema=%d transport=%s\n",
            APD_SERVICE_NAME, APD_CONTRACT_VERSION, APD_SCHEMA_VERSION,
            apd_transport_reason());
    uloop_run();

    apd_transport_stop();
    apd_ubus_stop();
    uloop_done();
    apd_protocol_close();
    apd_db_close();
    return 0;

fail_ubus:
    apd_ubus_stop();
fail_uloop:
    uloop_done();
fail_protocol:
    apd_protocol_close();
fail_db:
    apd_db_close();
    return 1;
}

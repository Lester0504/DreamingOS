// SPDX-License-Identifier: GPL-2.0-or-later
/* DreamingWrt AP node agent. */
#include "apd_config_job_journal.h"
#include "apd_internal.h"
#include "apd_beacon.h"
#include "apd_audit_forward.h"
#include "apd_secret_executor.h"
#include "apd_rrm_forward.h"

static void apd_handle_signal(int signo)
{
    (void)signo;
    uloop_end();
}

int main(int argc, char **argv)
{
    struct sigaction child_action;
    int interrupted_jobs = 0;
    int recovered_config_jobs = 0;

    if (argc == 3 && !strcmp(argv[1], "--reassoc-block-worker"))
        return apd_reassoc_block_worker(atoi(argv[2]));
    if (argc == 3 && !strcmp(argv[1], "--reassoc-block-release"))
        return apd_reassoc_block_release(argv[2]);
    if (argc == 2 && !strcmp(argv[1], "--rrm-forward-restore"))
        return apd_rrm_forward_restore();

    memset(&child_action, 0, sizeof(child_action));
    child_action.sa_handler = SIG_DFL;
    sigemptyset(&child_action.sa_mask);
    if (sigaction(SIGCHLD, &child_action, NULL) != 0) {
        fprintf(stderr, "[%s] startup failed stage=sigchld errno=%d\n",
                APD_SERVICE_NAME, errno);
        return 1;
    }
    /*
     * uloop_init() installs its own SIGCHLD handler and uloop_run() then
     * reaps with waitpid(-1, WNOHANG) on behalf of uloop_process users.
     * apd registers no uloop_process, but its transport worker forks `iw`
     * through apd_readonly_command_bounded(): the loop thread reaped those
     * children first, the worker's waitpid(child) returned ECHILD, and every
     * command came back exit_status -1 with an empty stderr.  That is where
     * `iw_neighbor_scan_command_failed_exit_-1` and the intermittent
     * telemetry_failed stage=snapshot came from.  Opt out of the reaper.
     */
    uloop_handle_sigchld = false;
    signal(SIGINT, apd_handle_signal);
    signal(SIGTERM, apd_handle_signal);
    g_apd_started_at = apd_now_s();

    if (apd_db_init() != 0) {
        fprintf(stderr, "[%s] startup failed stage=db_init\n",
                APD_SERVICE_NAME);
        return 1;
    }
    if (apd_ble_init() != 0)
        fprintf(stderr, "[%s] BLE provisioning unavailable reason=%s\n",
                APD_SERVICE_NAME, apd_ble_reason());
    if (apd_ble_available() && apd_ble_loop_start() != 0)
        fprintf(stderr, "[%s] BLE loop start failed reason=%s\n",
                APD_SERVICE_NAME, apd_ble_reason());
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
    if (apd_config_restart_recover_default(&recovered_config_jobs) != 0) {
        fprintf(stderr, "[%s] startup failed stage=config_job_recovery\n",
                APD_SERVICE_NAME);
        goto fail_db;
    }
    if (apd_secret_executor_init() != 0) {
        fprintf(stderr, "[%s] startup failed stage=secret_executor\n",
                APD_SERVICE_NAME);
        goto fail_db;
    }
    if (interrupted_jobs > 0)
        fprintf(stderr, "[%s] radio jobs recovered interrupted=%d\n",
                APD_SERVICE_NAME, interrupted_jobs);
    if (recovered_config_jobs > 0)
        fprintf(stderr, "[%s] config jobs recovered interrupted=%d\n",
                APD_SERVICE_NAME, recovered_config_jobs);
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
    if (apd_audit_forward_init() != 0) {
        fprintf(stderr, "[%s] startup failed stage=audit_forward_init\n",
                APD_SERVICE_NAME);
        goto fail_ubus;
    }
    if (apd_transport_start() != 0) {
        fprintf(stderr, "[%s] startup failed stage=transport_start reason=%s\n",
                APD_SERVICE_NAME, apd_transport_reason());
        goto fail_audit;
    }

    if (apd_txpower_mode_restore_start() != 0)
        fprintf(stderr,
                "[%s] persisted 6 GHz txpower mode replay could not start\n",
                APD_SERVICE_NAME);

    if (apd_rrm_forward_start() != 0)
        fprintf(stderr, "[%s] QSDK RRM forwarding manager could not start\n",
                APD_SERVICE_NAME);

    /* Discovery beacon is optional; a failure here must not stop the AP
     * agent from serving its normal duties. */
    if (apd_beacon_start() != 0)
        fprintf(stderr, "[%s] beacon unavailable reason=%s\n",
                APD_SERVICE_NAME, apd_beacon_reason());

    fprintf(stderr,
            "[%s] started contract=%s schema=%d transport=%s\n",
            APD_SERVICE_NAME, APD_CONTRACT_VERSION, APD_SCHEMA_VERSION,
            apd_transport_reason());
    uloop_run();

    apd_rrm_forward_stop();
    apd_txpower_mode_restore_stop();
    apd_beacon_stop();
    apd_audit_forward_close();
    apd_transport_stop();
    apd_ubus_stop();
    uloop_done();
    apd_protocol_close();
    apd_ble_close();
    apd_db_close();
    return 0;

fail_audit:
    apd_audit_forward_close();
fail_ubus:
    apd_ubus_stop();
fail_uloop:
    uloop_done();
fail_protocol:
    apd_protocol_close();
    apd_ble_close();
fail_db:
    apd_db_close();
    return 1;
}

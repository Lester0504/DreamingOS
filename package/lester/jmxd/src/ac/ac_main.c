// SPDX-License-Identifier: GPL-2.0-or-later
/* DreamingWrt centralized AP controller. */
#include "ac_internal.h"
#include "ac_discovery.h"

static void ac_handle_signal(int signo)
{
    (void)signo;
    uloop_end();
}

/*
 * Periodic survey collection.
 *
 * The tick itself is cheap and fixed at 30s; whether anything is dispatched is
 * decided by ac_survey_schedule (disabled by default, interval 60..3600s). The
 * timer runs regardless so that enabling the schedule takes effect without a
 * restart, and so a disabled schedule costs one DB read per half minute.
 *
 * Only survey jobs are created here. Neighbour scans do leave the working
 * channel, so scheduling them would interrupt associated clients; they stay a
 * manual action.
 */
static struct uloop_timeout ac_survey_schedule_timer;

#define AC_SURVEY_SCHEDULE_TICK_MS 30000

static void ac_survey_schedule_tick_cb(struct uloop_timeout *t)
{
    int dispatched = 0;

    if (ac_db_survey_schedule_tick(ac_now_s(), &dispatched) == 0 && dispatched > 0)
        fprintf(stderr, "[%s] survey schedule dispatched jobs=%d\n",
                AC_SERVICE_NAME, dispatched);
    uloop_timeout_set(t, AC_SURVEY_SCHEDULE_TICK_MS);
}

int main(int argc, char **argv)
{
    struct ac_secrets *secrets = NULL;
    const char *secrets_key_path;
    (void)argc;
    (void)argv;

    signal(SIGINT, ac_handle_signal);
    signal(SIGTERM, ac_handle_signal);
    g_ac_started_at = ac_now_s();

    if (ac_db_init() != 0) {
        fprintf(stderr, "[%s] startup failed stage=db_init\n",
                AC_SERVICE_NAME);
        return 1;
    }
    secrets_key_path = getenv("DREAMINGWRT_AC_SECRETS_KEY_PATH");
    if (!secrets_key_path || !secrets_key_path[0])
        secrets_key_path = AC_SECRETS_KEY_PATH;
    if (ac_secrets_open_or_create(g_ac_db, secrets_key_path, &secrets) !=
            AC_SECRETS_OK) {
        fprintf(stderr, "[%s] startup failed stage=secrets_init\n",
                AC_SERVICE_NAME);
        goto fail_db;
    }
    if (ac_protocol_init() != 0) {
        fprintf(stderr, "[%s] startup failed stage=protocol_init\n",
                AC_SERVICE_NAME);
        goto fail_db;
    }
    if (uloop_init() != 0) {
        fprintf(stderr, "[%s] startup failed stage=uloop_init\n",
                AC_SERVICE_NAME);
        goto fail_protocol;
    }
    if (ac_ubus_start() != 0) {
        fprintf(stderr, "[%s] startup failed stage=ubus_start\n",
                AC_SERVICE_NAME);
        goto fail_uloop;
    }
    if (ac_transport_start() != 0) {
        fprintf(stderr, "[%s] startup failed stage=transport_start reason=%s\n",
                AC_SERVICE_NAME, ac_transport_reason());
        goto fail_ubus;
    }

    /*
     * Discovery is best-effort: if the beacon port cannot be bound the
     * controller still runs and simply reports the capability as
     * unavailable with a reason. Failing startup over an optional
     * convenience feature would be the wrong trade.
     */
    if (ac_discovery_start() != 0)
        fprintf(stderr, "[%s] discovery unavailable reason=%s\n",
                AC_SERVICE_NAME, ac_discovery_reason());

    ac_survey_schedule_timer.cb = ac_survey_schedule_tick_cb;
    uloop_timeout_set(&ac_survey_schedule_timer, AC_SURVEY_SCHEDULE_TICK_MS);

    fprintf(stderr,
            "[%s] started contract=%s schema=%d transport=%s port=%d\n",
            AC_SERVICE_NAME, AC_CONTRACT_VERSION, AC_SCHEMA_VERSION,
            ac_transport_listening() ? "listening" : "unavailable",
            ac_transport_port());
    uloop_run();

    uloop_timeout_cancel(&ac_survey_schedule_timer);
    ac_discovery_stop();
    ac_transport_stop();
    ac_ubus_stop();
    uloop_done();
    ac_protocol_close();
    ac_secrets_close(secrets);
    ac_db_close();
    return 0;

fail_ubus:
    ac_ubus_stop();
fail_uloop:
    uloop_done();
fail_protocol:
    ac_protocol_close();
fail_db:
    ac_secrets_close(secrets);
    ac_db_close();
    return 1;
}

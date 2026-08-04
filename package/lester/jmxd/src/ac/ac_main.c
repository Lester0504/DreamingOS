// SPDX-License-Identifier: GPL-2.0-or-later
/* DreamingWrt centralized AP controller. */
#include "ac_internal.h"

static void ac_handle_signal(int signo)
{
    (void)signo;
    uloop_end();
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

    fprintf(stderr,
            "[%s] started contract=%s schema=%d transport=%s port=%d\n",
            AC_SERVICE_NAME, AC_CONTRACT_VERSION, AC_SCHEMA_VERSION,
            ac_transport_listening() ? "listening" : "unavailable",
            ac_transport_port());
    uloop_run();

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

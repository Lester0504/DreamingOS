// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * dreamingos-cloud entry point.
 *
 * Startup order matters: the identity has to exist before anything can answer
 * webd's identity query, and the tunnel must not dial out before the identity
 * is loaded because router_id comes from it.
 *
 * A disabled or unconfigured relay is a normal state, not a failure. The daemon
 * stays up serving status so an operator can see why it is idle instead of
 * finding a dead process.
 */
#include "cloud_internal.h"

int64_t g_cloud_started_at;

int64_t cloud_now_s(void)
{
    return (int64_t)time(NULL);
}

int64_t cloud_monotonic_ms(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static void cloud_handle_signal(int signo)
{
    (void)signo;
    uloop_end();
}

static void cloud_usage(FILE *out)
{
    fprintf(out,
        "Usage: " CLOUD_SERVICE_NAME " [--identity|--version]\n"
        "  (no arguments)  run the relay agent\n"
        "  --identity      print the router relay identity as JSON and exit\n"
        "  --version       print the contract version and exit\n");
}

int main(int argc, char **argv)
{
    struct cloud_config config;
    int rc = 1;

    if (argc > 2) {
        cloud_usage(stderr);
        return 2;
    }
    if (argc == 2) {
        if (!strcmp(argv[1], "--version")) {
            printf("%s %s (protocol %s/%d)\n", CLOUD_SERVICE_NAME,
                   CLOUD_CONTRACT_VERSION, CLOUD_PROTOCOL,
                   CLOUD_PROTOCOL_VERSION);
            return 0;
        }
        /* Diagnostic path: prints the same values ubus `identity` returns, so
         * an operator can read the fingerprint without a running daemon. */
        if (!strcmp(argv[1], "--identity")) {
            struct json_object *identity;

            if (cloud_identity_load(NULL) != 0) {
                fprintf(stderr, "%s: identity unavailable\n",
                        CLOUD_SERVICE_NAME);
                return 1;
            }
            identity = cloud_identity_json();
            if (!identity)
                return 1;
            printf("%s\n", json_object_to_json_string_ext(
                       identity, JSON_C_TO_STRING_PRETTY));
            json_object_put(identity);
            return 0;
        }
        cloud_usage(!strcmp(argv[1], "--help") ? stdout : stderr);
        return strcmp(argv[1], "--help") ? 2 : 0;
    }

    /* SIGPIPE would otherwise kill the process when the relay or webd hangs up
     * mid-write; both paths already check their return values. */
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, cloud_handle_signal);
    signal(SIGTERM, cloud_handle_signal);
    g_cloud_started_at = cloud_now_s();

    if (cloud_identity_load(NULL) != 0) {
        fprintf(stderr, "[%s] startup failed stage=identity\n",
                CLOUD_SERVICE_NAME);
        return 1;
    }
    if (cloud_config_load(&config) != 0) {
        fprintf(stderr, "[%s] startup failed stage=config\n",
                CLOUD_SERVICE_NAME);
        return 1;
    }

    if (uloop_init() != 0) {
        fprintf(stderr, "[%s] startup failed stage=uloop_init\n",
                CLOUD_SERVICE_NAME);
        goto done;
    }
    if (cloud_ubus_start() != 0) {
        fprintf(stderr, "[%s] startup failed stage=ubus_start\n",
                CLOUD_SERVICE_NAME);
        goto fail_uloop;
    }
    if (cloud_tunnel_start(&config) != 0) {
        fprintf(stderr, "[%s] startup failed stage=tunnel_start\n",
                CLOUD_SERVICE_NAME);
        goto fail_ubus;
    }

    fprintf(stderr, "[%s] started state=%s\n", CLOUD_SERVICE_NAME,
            cloud_tunnel_state());
    uloop_run();
    rc = 0;

    cloud_tunnel_stop();
fail_ubus:
    cloud_ubus_stop();
fail_uloop:
    uloop_done();
done:
    cloud_config_cleanse(&config);
    return rc;
}

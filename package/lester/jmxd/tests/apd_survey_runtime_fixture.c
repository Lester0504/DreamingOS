// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
#define APD_HOSTAPD_STANDALONE_TEST 1
#define APD_SURVEY_STANDALONE_TEST 1

#include "../src/apd/apd_backend_openwrt.c"

#include <math.h>

static int fixture_iw(int argc, char **argv)
{
    const char *mode = getenv("APD_SURVEY_FIXTURE_MODE");

    if (argc != 5 || strcmp(argv[1], "dev") || strcmp(argv[2], "wlan0") ||
        strcmp(argv[3], "survey") || strcmp(argv[4], "dump"))
        return 90;
    if (!mode)
        return 91;
    if (!strcmp(mode, "failure"))
        return 95;
    if (!strcmp(mode, "unsupported"))
        return 0;
    if (!strcmp(mode, "missing-frequency")) {
        fputs("Survey data from wlan0\n"
              "\tfrequency: 2412 MHz\n"
              "\tnoise: -96 dBm\n"
              "\tchannel active time: 100 ms\n"
              "\tchannel busy time: 10 ms\n", stdout);
        return ferror(stdout) ? 92 : 0;
    }
    if (!strcmp(mode, "busy-exceeds-active")) {
        fputs("Survey data from wlan0\n"
              "\tfrequency: 2437 MHz [in use]\n"
              "\tnoise: -93 dBm\n"
              "\tchannel active time: 50 ms\n"
              "\tchannel busy time: 51 ms\n"
              "\tchannel receive time: 30 ms\n"
              "\tchannel transmit time: 12 ms\n", stdout);
        return ferror(stdout) ? 93 : 0;
    }
    if (!strcmp(mode, "zero-active")) {
        fputs("Survey data from wlan0\n"
              "\tfrequency: 2437 MHz [in use]\n"
              "\tchannel active time: 0 ms\n"
              "\tchannel busy time: 0 ms\n", stdout);
        return ferror(stdout) ? 94 : 0;
    }
    if (strcmp(mode, "success"))
        return 96;
    fputs("Survey data from wlan0\n"
          "\tfrequency: 2412 MHz\n"
          "\tnoise: -97 dBm\n"
          "\tchannel active time: 500 ms\n"
          "\tchannel busy time: 25 ms\n"
          "Survey data from wlan0\n"
          "\tfrequency: 2437 MHz [in use]\n"
          "\tnoise: -91 dBm\n"
          "\tchannel active time: 400 ms\n"
          "\tchannel busy time: 100 ms\n"
          "\tchannel receive time: 55 ms\n"
          "\tchannel transmit time: 20 ms\n", stdout);
    return ferror(stdout) ? 97 : 0;
}

static int fixture_expect_success(const char *path)
{
    struct apd_survey_sample sample;
    double utilization = 0.0;

    setenv("APD_SURVEY_FIXTURE_MODE", "success", 1);
    if (apd_survey_collect_raw(path, "wlan0", 2437, &sample) != 0 ||
        !sample.complete || sample.frequency_mhz != 2437 || !sample.in_use ||
        !sample.has_noise || sample.noise_dbm != -91 ||
        !sample.has_active_time || sample.active_time_ms != 400 ||
        !sample.has_busy_time || sample.busy_time_ms != 100 ||
        !sample.has_receive_time || sample.receive_time_ms != 55 ||
        !sample.has_transmit_time || sample.transmit_time_ms != 20 ||
        sample.reason[0] || apd_survey_utilization(&sample, &utilization) != 0 ||
        fabs(utilization - 25.0) > 0.0001)
        return 10;
    return 0;
}

static int fixture_expect_failure_states(const char *path)
{
    struct apd_survey_sample sample;
    double utilization = 0.0;

    setenv("APD_SURVEY_FIXTURE_MODE", "unsupported", 1);
    if (apd_survey_collect_raw(path, "wlan0", 2437, &sample) == 0 ||
        sample.complete || strcmp(sample.reason, "iw_survey_unsupported"))
        return 20;

    setenv("APD_SURVEY_FIXTURE_MODE", "failure", 1);
    if (apd_survey_collect_raw(path, "wlan0", 2437, &sample) == 0 ||
        sample.complete ||
        strcmp(sample.reason, "iw_survey_failed_or_unsupported"))
        return 21;

    setenv("APD_SURVEY_FIXTURE_MODE", "missing-frequency", 1);
    if (apd_survey_collect_raw(path, "wlan0", 2437, &sample) == 0 ||
        sample.complete ||
        strcmp(sample.reason, "iw_survey_current_frequency_missing"))
        return 22;

    setenv("APD_SURVEY_FIXTURE_MODE", "busy-exceeds-active", 1);
    if (apd_survey_collect_raw(path, "wlan0", 2437, &sample) == 0 ||
        sample.complete || sample.active_time_ms != 50 || sample.busy_time_ms != 51 ||
        strcmp(sample.reason, "iw_survey_busy_exceeds_active") ||
        apd_survey_utilization(&sample, &utilization) == 0)
        return 23;

    setenv("APD_SURVEY_FIXTURE_MODE", "zero-active", 1);
    if (apd_survey_collect_raw(path, "wlan0", 2437, &sample) != 0 ||
        !sample.complete || sample.active_time_ms != 0 || sample.busy_time_ms != 0 ||
        sample.reason[0] || apd_survey_utilization(&sample, &utilization) == 0)
        return 24;

    if (apd_survey_collect_raw(path, "wlan0;reboot", 2437, &sample) == 0 ||
        sample.complete || strcmp(sample.reason, "iw_survey_interface_invalid"))
        return 25;
    if (apd_survey_collect_raw(path, NULL, 2437, &sample) == 0 ||
        sample.complete ||
        strcmp(sample.reason, "iw_survey_ap_interface_unavailable"))
        return 26;
    if (apd_survey_collect_raw(path, "wlan0", 0, &sample) == 0 ||
        sample.complete ||
        strcmp(sample.reason, "iw_survey_current_frequency_unavailable"))
        return 27;
    return 0;
}

int main(int argc, char **argv)
{
    int rc;

    if (argc > 1 && !strcmp(argv[1], "dev"))
        return fixture_iw(argc, argv);
    if (argc != 1)
        return 2;
    rc = fixture_expect_success(argv[0]);
    if (!rc)
        rc = fixture_expect_failure_states(argv[0]);
    if (rc)
        return rc;
    puts("ok: APD passive iw survey parser and bounded argv collection");
    return 0;
}

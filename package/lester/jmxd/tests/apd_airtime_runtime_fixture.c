// SPDX-License-Identifier: GPL-2.0-or-later
/* Exercises APD's production `apstats` airtime fallback.
 *
 * The sample body is the verbatim, unedited output of `apstats -r -i wifi1`
 * captured from 31.31 (QWRT / QCA driver) on 2026-08-04, including its per-AC
 * sub-blocks, its `lithium_cycle_cnt:` rows and the `<DISABLED>` markers. It is
 * pasted as captured on purpose: the parent station fallback shipped a fixture
 * whose columns had been tidied, and the tidying is what hid a real parsing bug
 * from the test.
 *
 * Covers the Acceptance finding that `iw ... survey dump` yields an empty body
 * on these drivers while `apstats` carries the airtime counters. */
#define _GNU_SOURCE
#define APD_HOSTAPD_STANDALONE_TEST 1
#define APD_SURVEY_STANDALONE_TEST 1
/* The airtime collector lives beside the station fallback, inside the
 * neighbor-scan guarded region. */
#define APD_NEIGHBOR_SCAN_STANDALONE_TEST 1

static unsigned int fixture_if_nametoindex(const char *name);
#define APD_NEIGHBOR_IF_NAMETOINDEX(name) fixture_if_nametoindex(name)

#include "../src/apd/apd_backend_openwrt.c"

#include <sys/stat.h>

static unsigned int fixture_if_nametoindex(const char *name)
{
    if (!strcmp(name, "ath11"))
        return 12;
    if (!strcmp(name, "wifi1"))
        return 25;
    return 0;
}

/* Verbatim `apstats -r -i wifi1` from 31.31. Not reformatted. */
static int fixture_apstats_radio_body(void)
{
    fputs("Radio Level Stats: wifi1\n"
          "Tx Data Packets                 = 21916982\n"
          "Tx Data Bytes                   = 21429547845\n"
          "Rx Data Packets                 = 25366541\n"
          "Rx Data Bytes                   = 26689096804\n"
          "Tx Unicast Data Packets         = 21389791\n"
          "Tx Multi/Broadcast Data Packets = 527191\n"
          "Tx Data Packets per AC:\n"
          " Best effort                    = 39720408\n"
          " Background                     = 90862\n"
          " Video                          = 217850\n"
          " Voice                          = 2768188\n"
          "Rx Data Packets per AC:\n"
          " Best effort                    = 46108520\n"
          " Background                     = 285730\n"
          " Video                          = 1942192\n"
          " Voice                          = 3279178\n"
          "Channel Utilization (0-255)     = <DISABLED>\n"
          "Tx Beacon Frames                = 4454780\n"
          "Tx Mgmt Frames                  = 283176\n"
          "Rx Mgmt Frames                  = 15654\n"
          "Rx Mgmt Frames dropped(RSSI too low) = 0\n"
          "Tx Ctl Frames                   = 0\n"
          "Rx Ctl Frames                   = 0\n"
          "Rx RSSI                         = 53\n"
          "Rx PHY errors                   = 3687\n"
          "Rx CRC errors                   = 0\n"
          "Rx MIC errors                   = 0\n"
          "Rx Decryption errors            = 0\n"
          "Rx PN errors                    = 0\n"
          "Rx errors                       = 0\n"
          "Tx failures                     = 4132\n"
          "Tx Dropped                      = 24\n"
          "Connections refuse Radio limit  = 0\n"
          "Connections refuse Vap limit    = 0\n"
          "802.11 Auth Attempts            = 55\n"
          "802.11 Auth Success             = 54\n"
          "MLME Authorize Attempts         = 36\n"
          "MLME Authorize Success          = 30\n"
          "Self BSS chan util              = 7\n"
          "OBSS chan util                  = 6\n"
          "lithium_cycle_counts:\n"
          "lithium_cycle_cnt: Chan NF (BDF averaged NF_dBm) = -90\n"
          "lithium_cycle_cnt: Tx Frame Cnt = 642013509\n"
          "lithium_cycle_cnt: Rx Frame Cnt = 744157828\n"
          "lithium_cycle_cnt: Rx Clear Cnt = 1592244804\n"
          "lithium_cycle_cnt: Cycle Cnt    = 2989230580\n"
          "lithium_cycle_cnt: Phy Err Cnt  = 3687\n"
          "lithium_cycle_cnt: Chan Tx Pwr  = 54\n"
          "Number of Active Vaps           = 6\n"
          "Throughput (kbps)               = <DISABLED>\n"
          "PER over configured period (%)  = <DISABLED>\n"
          "Total PER (%)                   = 0\n"
          "Co-located RNR stats:\n"
          " Created vap:                   = 2\n"
          " Active vap:                    = 2\n"
          " RNR count:                     = 2\n"
          " 6GHz SoC status:               = 0\n",
          stdout);
    return ferror(stdout) ? 70 : 0;
}

static int fixture_apstats(int argc, char **argv)
{
    const char *mode = getenv("APD_AIRTIME_FIXTURE_MODE");

    /* VAP level is a separate bounded argv. It carries `Retries`, which the
     * radio level never prints, so the retry aggregate has to come from here. */
    if (argc == 4 && !strcmp(argv[1], "-v") && !strcmp(argv[2], "-i")) {
        const char *vap_mode = getenv("APD_AIRTIME_FIXTURE_VAP_MODE");

        if (!vap_mode)
            return 71;
        if (!strcmp(vap_mode, "fail-ath12") && !strcmp(argv[3], "ath12"))
            return 72;
        if (!strcmp(vap_mode, "no-retries")) {
            fputs("VAP Level Stats: ath11 (under radio wifi1)\n"
                  "Tx Data Packets                 = 2329451\n",
                  stdout);
            return ferror(stdout) ? 73 : 0;
        }
        if (!strcmp(argv[3], "ath11")) {
            fputs("VAP Level Stats: ath11 (under radio wifi1)\n"
                  "Tx Data Packets                 = 2329451\n"
                  "Retries                         = 152002\n"
                  "Excessive retries per AC:\n"
                  " Best effort                    = 7\n",
                  stdout);
            return ferror(stdout) ? 74 : 0;
        }
        if (!strcmp(argv[3], "ath12")) {
            fputs("VAP Level Stats: ath12 (under radio wifi1)\n"
                  "Tx Data Packets                 = 1000000\n"
                  "Retries                         = 48000\n",
                  stdout);
            return ferror(stdout) ? 75 : 0;
        }
        if (!strcmp(argv[3], "ath0")) {
            fputs("VAP Level Stats: ath0 (under radio wifi0)\n"
                  "Tx Data Packets                 = 7\n"
                  "Retries                         = 1\n",
                  stdout);
            return ferror(stdout) ? 76 : 0;
        }
        return 77;
    }

    /* Only the bounded radio-level argv is accepted; anything else is a
     * regression in the production call site. */
    if (argc != 4 || strcmp(argv[1], "-r") || strcmp(argv[2], "-i"))
        return 60;
    if (!mode)
        return 61;
    if (!strcmp(mode, "failure"))
        return 65;
    if (!strcmp(mode, "empty"))
        return 0;
    if (!strcmp(mode, "banner-only")) {
        fputs("Radio Level Stats: wifi1\n"
              "lithium_cycle_counts:\n"
              "Co-located RNR stats:\n", stdout);
        return ferror(stdout) ? 66 : 0;
    }
    if (strcmp(mode, "success"))
        return 67;
    return fixture_apstats_radio_body();
}

static int fixture_expect_success(const char *path)
{
    struct apd_airtime_stats stats;
    double value = 0.0;

    setenv("APD_AIRTIME_FIXTURE_MODE", "success", 1);
    if (apd_airtime_collect(path, "wifi1", &stats) != 0)
        return 10;
    if (stats.reason[0])
        return 11;

    /* Counters the handoff requires to be non-null, matching the capture. */
    if (!stats.has_tx_packets || stats.tx_packets != 21916982ULL ||
        !stats.has_rx_packets || stats.rx_packets != 25366541ULL)
        return 12;
    /* 64-bit byte counters must not be truncated to 32 bits. */
    if (!stats.has_tx_bytes || stats.tx_bytes != 21429547845ULL ||
        !stats.has_rx_bytes || stats.rx_bytes != 26689096804ULL)
        return 13;
    if (!stats.has_tx_failures || stats.tx_failures != 4132ULL ||
        !stats.has_tx_dropped || stats.tx_dropped != 24ULL)
        return 14;
    if (!stats.has_rx_phy_errors || stats.rx_phy_errors != 3687ULL)
        return 15;

    /* `Total PER (%) = 0` and `Rx CRC errors = 0` are measured zeros: present
     * with value 0, never null. This is the distinction the handoff calls out. */
    if (!stats.has_total_per || stats.total_per_pct != 0)
        return 16;
    if (!stats.has_rx_crc_errors || stats.rx_crc_errors != 0ULL)
        return 17;

    /* `<DISABLED>` must be recorded as disabled, not parsed as a number. */
    if (!stats.channel_util_disabled || !stats.throughput_disabled)
        return 18;

    /* Radio level prints no `Retries` row; it must stay absent rather than 0. */
    if (stats.has_retries)
        return 19;

    /* The per-AC sub-rows must not overwrite the radio totals: `Best effort`
     * under "Tx Data Packets per AC" is larger than Tx Data Packets itself. */
    if (stats.tx_packets == 39720408ULL || stats.rx_packets == 46108520ULL)
        return 20;
    /* Same hazard where it can actually shadow a counter we read: VAP level
     * prints `Retries`, then an `Excessive retries per AC:` block whose
     * indented `Best effort` row would otherwise land on top of it. Verified
     * against the real `apstats -v -i ath11` layout from 31.31. */
    {
        struct apd_airtime_stats vap;
        char body[] =
            "VAP Level Stats: ath11 (under radio wifi1)\n"
            "Tx Data Packets                 = 2329451\n"
            "Retries                         = 152002\n"
            "Excessive retries per AC:\n"
            " Best effort                    = 7\n"
            " Background                     = 0\n"
            " Video                          = 0\n"
            " Voice                          = 0\n";
        char *line;
        char *saved = NULL;

        memset(&vap, 0, sizeof(vap));
        for (line = strtok_r(body, "\n", &saved); line;
             line = strtok_r(NULL, "\n", &saved)) {
            char *trimmed = apd_survey_trim(line);

            if (trimmed && trimmed[0])
                apd_airtime_parse_line(trimmed, &vap);
        }
        if (!vap.has_retries || vap.retries != 152002ULL)
            return 25;
        if (!vap.has_tx_packets || vap.tx_packets != 2329451ULL)
            return 26;
    }
    /* An idle radio on 31.31 reports `Chan NF ... = 32674`, which is garbage
     * rather than a noise floor. Out-of-range values must be dropped so the UI
     * shows "not measured" instead of a nonsense dBm. Captured from
     * `apstats -r -i wifi2` on 2026-08-04. */
    {
        struct apd_airtime_stats idle;
        char body[] =
            "Radio Level Stats: wifi2\n"
            "Tx Data Packets                 = 3960\n"
            "Rx PHY errors                   = 0\n"
            "Tx failures                     = 0\n"
            "Self BSS chan util              = 0\n"
            "OBSS chan util                  = 4\n"
            "lithium_cycle_cnt: Chan NF (BDF averaged NF_dBm) = 32674\n"
            "Total PER (%)                   = 0\n";
        char *line;
        char *saved = NULL;

        memset(&idle, 0, sizeof(idle));
        for (line = strtok_r(body, "\n", &saved); line;
             line = strtok_r(NULL, "\n", &saved)) {
            char *trimmed = apd_survey_trim(line);

            if (trimmed && trimmed[0])
                apd_airtime_parse_line(trimmed, &idle);
        }
        if (idle.has_noise_floor)
            return 27;
        /* A genuinely idle radio still reports real zeros, which stay 0. */
        if (!idle.has_tx_failures || idle.tx_failures != 0ULL)
            return 28;
        if (!idle.has_self_bss_util || idle.self_bss_util_pct != 0)
            return 29;
    }

    if (!stats.has_self_bss_util || stats.self_bss_util_pct != 7 ||
        !stats.has_obss_util || stats.obss_util_pct != 6)
        return 21;
    /* Negative noise floor from the lithium_cycle_cnt row. */
    if (!stats.has_noise_floor || stats.noise_floor_dbm != -90)
        return 22;

    /* Derived utilization is the sum of the two live chan-util counters. */
    if (apd_airtime_utilization_pct(&stats, &value) != 0 ||
        value < 12.999 || value > 13.001)
        return 23;
    /* Retry rate falls back to Tx failures / Tx packets at radio level. */
    if (apd_airtime_retry_pct(&stats, &value) != 0 ||
        value <= 0.0 || value > 1.0)
        return 24;
    return 0;
}

static int fixture_expect_reason(const char *path, const char *mode,
                                 const char *expected, int base)
{
    struct apd_airtime_stats stats;

    setenv("APD_AIRTIME_FIXTURE_MODE", mode, 1);
    if (apd_airtime_collect(path, "wifi1", &stats) == 0)
        return base;
    if (strcmp(stats.reason, expected))
        return base + 1;
    /* A failed collection must not leave a fabricated value behind. */
    if (stats.has_tx_packets || stats.has_total_per)
        return base + 2;
    return 0;
}

static int fixture_expect_guards(const char *path)
{
    struct apd_airtime_stats stats;

    /* Absence of the binary is its own reason, distinct from "ran but gave
     * nothing", which is the criterion the handoff asks for. */
    if (apd_airtime_collect(NULL, "wifi1", &stats) == 0 ||
        strcmp(stats.reason, "apstats_binary_unavailable"))
        return 40;
    if (apd_airtime_collect(path, NULL, &stats) == 0 ||
        strcmp(stats.reason, "apstats_radio_netdev_unavailable"))
        return 41;
    /* Shell metacharacters must be rejected before exec, not quoted. */
    if (apd_airtime_collect(path, "wifi1; reboot", &stats) == 0 ||
        strcmp(stats.reason, "apstats_radio_netdev_invalid"))
        return 42;
    if (apd_airtime_collect(path, "../../bin/sh", &stats) == 0 ||
        strcmp(stats.reason, "apstats_radio_netdev_invalid"))
        return 43;
    return 0;
}

/* The radio netdev must be found by sysfs content (ARPHRD 801), not by
 * assuming the `phyN` -> `wifiN` spelling. */
static int fixture_expect_netdev_mapping(void)
{
    char name[IFNAMSIZ] = { 0 };

    if (apd_airtime_radio_netdev(2, 0, 0, name, sizeof(name)) != 0)
        return 50;
    if (strcmp(name, "wifi3"))
        return 51;
    /* phy1 exists in the fixture tree but only as a VAP (type 1), so it must
     * not resolve to a radio netdev. */
    if (apd_airtime_radio_netdev(1, 0, 0, name, sizeof(name)) == 0)
        return 52;
    if (apd_airtime_radio_netdev(77, 0, 0, name, sizeof(name)) == 0)
        return 53;
    /* Several QSDK radio netdevs share phy0. The logical selector must choose
     * wifi1 exactly instead of returning an ambiguous wiphy result. */
    if (apd_airtime_radio_netdev(0, 1, 1, name, sizeof(name)) != 0 ||
        strcmp(name, "wifi1"))
        return 54;
    return 0;
}

/* The retry aggregate has to sum every VAP under one wiphy, refuse a partial
 * sum, and never substitute `Tx failures` for `Retries`. */
static int fixture_expect_tx_retry(const char *path)
{
    struct apd_tx_retry_stats stats;
    struct apd_airtime_stats radio;
    struct json_object *air;
    struct json_object *field = NULL;
    int rc = 0;

    setenv("APD_AIRTIME_FIXTURE_MODE", "success", 1);
    setenv("APD_AIRTIME_FIXTURE_VAP_MODE", "success", 1);
    /* phy2 owns wifi1 (ARPHRD 801, skipped) plus ath11 and ath12. */
    if (apd_tx_retry_collect(path, 2, 0, 0, &stats) != 0)
        return 100;
    if (!stats.available || stats.vap_count != 2)
        return 101;
    if (stats.tx_total != 2329451ULL + 1000000ULL)
        return 102;
    if (stats.tx_retries != 152002ULL + 48000ULL)
        return 103;
    if (stats.reason[0])
        return 104;

    /* One unreadable VAP invalidates the whole radio: a partial sum would
     * understate the retry rate by dropping that VAP's traffic. */
    setenv("APD_AIRTIME_FIXTURE_VAP_MODE", "fail-ath12", 1);
    if (apd_tx_retry_collect(path, 2, 0, 0, &stats) == 0)
        return 105;
    if (stats.available ||
        strcmp(stats.reason, "apstats_vap_failed_or_unsupported"))
        return 106;

    /* A VAP that prints Tx totals but no `Retries` is unsupported, not zero. */
    setenv("APD_AIRTIME_FIXTURE_VAP_MODE", "no-retries", 1);
    if (apd_tx_retry_collect(path, 2, 0, 0, &stats) == 0)
        return 107;
    if (strcmp(stats.reason, "apstats_vap_retries_absent"))
        return 108;

    /* A wiphy with no VAP at all reports its own reason. */
    setenv("APD_AIRTIME_FIXTURE_VAP_MODE", "success", 1);
    if (apd_tx_retry_collect(path, 77, 0, 0, &stats) == 0 ||
        strcmp(stats.reason, "apstats_no_vap_for_wiphy"))
        return 109;
    if (apd_tx_retry_collect(NULL, 2, 0, 0, &stats) == 0 ||
        strcmp(stats.reason, "apstats_binary_unavailable"))
        return 110;

    /* Emitted contract: the AC only differences counters flagged cumulative. */
    if (apd_tx_retry_collect(path, 2, 0, 0, &stats) != 0)
        return 111;
    memset(&radio, 0, sizeof(radio));
    if (apd_airtime_collect(path, "wifi1", &radio) != 0)
        return 112;
    air = apd_airtime_json(&radio, 1, "wifi1");
    if (!air)
        return 113;
    apd_tx_retry_decorate(air, &stats);
    if (!json_object_object_get_ex(air, "tx_retry_available", &field) ||
        !json_object_get_boolean(field))
        rc = 114;
    else if (!json_object_object_get_ex(air, "tx_retry_counter_semantics",
                                        &field) ||
             strcmp(json_object_get_string(field), "cumulative"))
        rc = 115;
    else if (!json_object_object_get_ex(air, "tx_retry_source", &field) ||
             strcmp(json_object_get_string(field), "apstats_vap_aggregate"))
        rc = 116;
    else if (!json_object_object_get_ex(air, "tx_total", &field) ||
             json_object_get_int64(field) != 3329451LL)
        rc = 117;
    else if (!json_object_object_get_ex(air, "tx_retries", &field) ||
             json_object_get_int64(field) != 200002LL)
        rc = 118;
    /* The radio-level `retries` stays null: it is a different counter and must
     * not be back-filled from the VAP sum. */
    else if (!json_object_object_get_ex(air, "retries", &field) ||
             !json_object_is_type(field, json_type_null))
        rc = 119;
    json_object_put(air);
    if (rc)
        return rc;

    /* Unavailable retry data must emit an explicit false plus reason, and must
     * not leave the cumulative counters in the payload at all. */
    setenv("APD_AIRTIME_FIXTURE_VAP_MODE", "fail-ath12", 1);
    (void)apd_tx_retry_collect(path, 2, 0, 0, &stats);
    air = apd_airtime_json(&radio, 1, "wifi1");
    if (!air)
        return 120;
    apd_tx_retry_decorate(air, &stats);
    if (!json_object_object_get_ex(air, "tx_retry_available", &field) ||
        json_object_get_boolean(field))
        rc = 121;
    else if (json_object_object_get_ex(air, "tx_total", &field))
        rc = 122;
    else if (json_object_object_get_ex(air, "tx_retries", &field))
        rc = 123;
    else if (!json_object_object_get_ex(air, "tx_retry_reason", &field) ||
             strcmp(json_object_get_string(field),
                    "apstats_vap_failed_or_unsupported"))
        rc = 124;
    json_object_put(air);
    unsetenv("APD_AIRTIME_FIXTURE_VAP_MODE");
    return rc;
}

static int fixture_expect_json_nulls(const char *path)
{
    struct apd_airtime_stats stats;
    struct json_object *air;
    struct json_object *field = NULL;
    int rc = 0;

    setenv("APD_AIRTIME_FIXTURE_MODE", "failure", 1);
    (void)apd_airtime_collect(path, "wifi1", &stats);
    air = apd_airtime_json(&stats, 0, "wifi1");
    if (!air)
        return 55;
    /* Unavailable means null plus a reason across the board, never 0. */
    if (!json_object_object_get_ex(air, "tx_packets", &field) ||
        !json_object_is_type(field, json_type_null))
        rc = 56;
    else if (!json_object_object_get_ex(air, "total_per_pct", &field) ||
             !json_object_is_type(field, json_type_null))
        rc = 57;
    else if (!json_object_object_get_ex(air, "retry_rate_pct", &field) ||
             !json_object_is_type(field, json_type_null))
        rc = 58;
    else if (!json_object_object_get_ex(air, "reason", &field) ||
             !json_object_is_type(field, json_type_string))
        rc = 59;
    json_object_put(air);
    if (rc)
        return rc;

    setenv("APD_AIRTIME_FIXTURE_MODE", "success", 1);
    if (apd_airtime_collect(path, "wifi1", &stats) != 0)
        return 30;
    air = apd_airtime_json(&stats, 1, "wifi1");
    if (!air)
        return 31;
    /* A measured zero survives into JSON as 0, not as null. */
    if (!json_object_object_get_ex(air, "total_per_pct", &field) ||
        !json_object_is_type(field, json_type_int) ||
        json_object_get_int(field) != 0)
        rc = 32;
    /* Firmware-disabled counters are reported unavailable, not zero. */
    else if (!json_object_object_get_ex(air, "retries", &field) ||
             !json_object_is_type(field, json_type_null))
        rc = 33;
    else if (!json_object_object_get_ex(air, "tx_bytes", &field) ||
             json_object_get_int64(field) != 21429547845LL)
        rc = 34;
    else if (!json_object_object_get_ex(air,
                 "firmware_disabled_channel_utilization", &field) ||
             !json_object_get_boolean(field))
        rc = 35;
    else if (!json_object_object_get_ex(air, "utilization_pct", &field) ||
             !json_object_is_type(field, json_type_double))
        rc = 36;
    json_object_put(air);
    return rc;
}

int main(int argc, char **argv)
{
    const char *self = argv[0];
    int rc;

    /* The binary doubles as the stub `apstats`. */
    if (argc > 1)
        return fixture_apstats(argc, argv);

    rc = fixture_expect_netdev_mapping();
    if (rc)
        goto fail;
    rc = fixture_expect_success(self);
    if (rc)
        goto fail;
    rc = fixture_expect_guards(self);
    if (rc)
        goto fail;
    rc = fixture_expect_reason(self, "failure",
                               "apstats_failed_or_unsupported", 70);
    if (rc)
        goto fail;
    rc = fixture_expect_reason(self, "empty", "apstats_no_output", 80);
    if (rc)
        goto fail;
    /* Ran fine but produced no counters: a distinct reason from "no output",
     * because the criterion is whether data arrived. */
    rc = fixture_expect_reason(self, "banner-only",
                               "apstats_no_counters_parsed", 90);
    if (rc)
        goto fail;
    rc = fixture_expect_json_nulls(self);
    if (rc)
        goto fail;
    rc = fixture_expect_tx_retry(self);
    if (rc)
        goto fail;
    fputs("ok: APD apstats airtime fallback parser and bounded argv collection\n",
          stdout);
    return 0;
fail:
    fprintf(stdout, "fail: apstats airtime fixture check %d\n", rc);
    return 1;
}

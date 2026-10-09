// SPDX-License-Identifier: GPL-2.0-or-later
/* Exercises APD's production `wlanconfig <if> list` station fallback.
 *
 * The sample rows are the real output captured from 31.31 (QWRT / Linux
 * 5.4.213 / QCA driver) and recorded in
 * todo/2026-08-04/Handoff/Acceptance-to-Backend-wireless-station-source-needs-fallback.md,
 * where `iw dev <if> station dump` returns zero stations while
 * `wlanconfig <if> list` returns the association table. */
#define _GNU_SOURCE
#define APD_HOSTAPD_STANDALONE_TEST 1
#define APD_SURVEY_STANDALONE_TEST 1
/* The station fallback lives beside apd_survey_scan_collect, inside the
 * neighbor-scan guarded region, so this fixture opts into the same region the
 * production caller is compiled in. */
#define APD_NEIGHBOR_SCAN_STANDALONE_TEST 1

static unsigned int fixture_if_nametoindex(const char *name);
#define APD_NEIGHBOR_IF_NAMETOINDEX(name) fixture_if_nametoindex(name)

#include "../src/apd/apd_backend_openwrt.c"

#include <sys/stat.h>

static unsigned int fixture_if_nametoindex(const char *name)
{
    if (!strcmp(name, "ath11"))
        return 12;
    return 0;
}

/* `iw dev` works on these drivers even though its station/survey subcommands
 * return nothing, so the radio mapping still comes from `iw dev`. */
static int fixture_iw(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "dev")) {
        fputs("phy#1\n"
              "\tInterface ath11\n"
              "\t\tifindex 12\n"
              "\t\tssid Main\n"
              "\t\ttype AP\n"
              "\t\tchannel 36 (5180 MHz), width: 80 MHz\n",
              stdout);
        return ferror(stdout) ? 80 : 0;
    }
    /* survey dump: empty body, exactly as observed on 31.31. */
    if (argc == 5 && !strcmp(argv[3], "survey") && !strcmp(argv[4], "dump"))
        return 0;
    return 81;
}

static int fixture_wlanconfig(int argc, char **argv)
{
    const char *mode = getenv("APD_VENDOR_FIXTURE_MODE");

    if (argc != 3 || strcmp(argv[2], "list"))
        return 90;
    if (!mode)
        return 91;
    if (!strcmp(mode, "failure"))
        return 95;
    if (!strcmp(mode, "empty"))
        return 0;
    if (!strcmp(mode, "header-only")) {
        fputs("ADDR               AID CHAN TXRATE RXRATE RSSI MINRSSI MAXRSSI "
              "IDLE  TXSEQ  RXSEQ  CAPS        ACAPS     ERP    "
              "STATE MAXRATE(DOT11) HTCAPS VHTCAPS ASSOCTIME    IEs   "
              "MODE                    RXNSS TXNSS PSMODE\n", stdout);
        return ferror(stdout) ? 92 : 0;
    }
    if (!strcmp(mode, "malformed")) {
        fputs("ADDR               AID CHAN TXRATE RXRATE RSSI\n"
              "not-a-mac           1   36  433M   292M  -65\n"
              "4c:c6:4c:zz:6c:73   1   36  433M   292M  -65\n", stdout);
        return ferror(stdout) ? 93 : 0;
    }
    if (strcmp(mode, "success"))
        return 96;
    /*
     * Two associated stations in the column order 31.31 actually emits:
     * MODE RXNSS TXNSS PSMODE, with PSMODE last and 0 for a non-power-saving
     * station. The earlier revision of this sample listed PSMODE before the NSS
     * pair, which happened to make "read the last two tokens" correct and hid a
     * real defect -- on hardware the last two tokens are TXNSS and PSMODE, and
     * PSMODE=0 caused both NSS values to be rejected together.
     *
     * Kept deliberately untidy for the same reason: a large RXSEQ (65535), the
     * trailing note line the tool prints, and trailing blanks on a data row are
     * all present in real output, so the parser is exercised against them.
     */
    fputs("ADDR               AID CHAN TXRATE RXRATE RSSI MINRSSI MAXRSSI "
          "IDLE  TXSEQ  RXSEQ  CAPS        ACAPS     ERP    "
          "STATE MAXRATE(DOT11) HTCAPS VHTCAPS ASSOCTIME    IEs   "
          "MODE                      RXNSS TXNSS PSMODE\n"
          "4c:c6:4c:18:6c:73   1   36  433M   292M  -65    -72     -52     "
          "0     0      65535  EPS         0         0      "
          "0     0              AWPS   BVMS    03:24:17     RSN   "
          "IEEE80211_MODE_11AC_VHT80 1     1     0   \n"
          "a8:5e:45:22:11:04   2   36  866M   780M  -48    -55     -41     "
          "12    0      65535  EPS         0         0      "
          "0     0              AWPS   BVMS    01:02:03     RSN   "
          "IEEE80211_MODE_11AC_VHT80 2     2     0\n"
          "RSSI is combined over chains in dBm\n", stdout);
    return ferror(stdout) ? 97 : 0;
}

static int fixture_expect_success(const char *path)
{
    struct apd_vendor_station_set set;

    setenv("APD_VENDOR_FIXTURE_MODE", "success", 1);
    if (apd_vendor_station_collect(path, "ath11", &set) != 0)
        return 10;
    if (set.count != 2 || set.truncated || set.reason[0])
        return 11;

    /* Station 1: every field the frontend showed as `--` must be present. */
    if (strcmp(set.items[0].mac, "4c:c6:4c:18:6c:73") ||
        set.items[0].aid != 1 ||
        !set.items[0].has_channel || set.items[0].channel != 36 ||
        !set.items[0].has_rssi || set.items[0].rssi != -65 ||
        !set.items[0].has_min_rssi || set.items[0].min_rssi != -72 ||
        !set.items[0].has_max_rssi || set.items[0].max_rssi != -52 ||
        !set.items[0].has_idle || set.items[0].idle_ms != 0)
        return 12;
    /* 433M -> kbps, so the JSON contract carries one integer unit. */
    if (!set.items[0].has_tx_rate || set.items[0].tx_rate_kbps != 433000 ||
        !set.items[0].has_rx_rate || set.items[0].rx_rate_kbps != 292000)
        return 13;
    if (strcmp(set.items[0].mode, "IEEE80211_MODE_11AC_VHT80"))
        return 14;
    if (!set.items[0].has_rx_nss || set.items[0].rx_nss != 1 ||
        !set.items[0].has_tx_nss || set.items[0].tx_nss != 1)
        return 15;

    /* Station 2 proves 2x2 MIMO and a nonzero idle are read per-row. */
    if (strcmp(set.items[1].mac, "a8:5e:45:22:11:04") ||
        set.items[1].aid != 2 ||
        set.items[1].tx_rate_kbps != 866000 ||
        set.items[1].rx_rate_kbps != 780000 ||
        set.items[1].rssi != -48 ||
        set.items[1].idle_ms != 12 ||
        set.items[1].rx_nss != 2 || set.items[1].tx_nss != 2)
        return 16;
    return 0;
}

static int fixture_expect_failure_states(const char *path)
{
    struct apd_vendor_station_set set;

    /* No output at all: must report a reason, never a fabricated zero. */
    setenv("APD_VENDOR_FIXTURE_MODE", "empty", 1);
    if (apd_vendor_station_collect(path, "ath11", &set) == 0 ||
        set.count != 0 || strcmp(set.reason, "wlanconfig_no_output"))
        return 20;

    setenv("APD_VENDOR_FIXTURE_MODE", "failure", 1);
    if (apd_vendor_station_collect(path, "ath11", &set) == 0 ||
        set.count != 0 ||
        strcmp(set.reason, "wlanconfig_failed_or_unsupported"))
        return 21;

    /* Header with no rows is a real "no clients", distinct from tool failure. */
    setenv("APD_VENDOR_FIXTURE_MODE", "header-only", 1);
    if (apd_vendor_station_collect(path, "ath11", &set) == 0 ||
        set.count != 0 || strcmp(set.reason, "wlanconfig_no_stations"))
        return 22;

    /* Unparsable rows are dropped, not guessed at. */
    setenv("APD_VENDOR_FIXTURE_MODE", "malformed", 1);
    if (apd_vendor_station_collect(path, "ath11", &set) == 0 ||
        set.count != 0 || strcmp(set.reason, "wlanconfig_no_stations"))
        return 23;

    setenv("APD_VENDOR_FIXTURE_MODE", "success", 1);
    if (apd_vendor_station_collect(path, "ath11;reboot", &set) == 0 ||
        strcmp(set.reason, "wlanconfig_interface_invalid"))
        return 24;
    if (apd_vendor_station_collect(path, NULL, &set) == 0 ||
        strcmp(set.reason, "wlanconfig_interface_unavailable"))
        return 25;
    if (apd_vendor_station_collect(NULL, "ath11", &set) == 0 ||
        strcmp(set.reason, "wlanconfig_binary_unavailable"))
        return 26;
    return 0;
}

static int fixture_expect_rate_units(void)
{
    unsigned int kbps = 0;

    if (apd_vendor_parse_rate_kbps("433M", &kbps) != 0 || kbps != 433000)
        return 30;
    if (apd_vendor_parse_rate_kbps("1.5G", &kbps) != 0 || kbps != 1500000)
        return 31;
    /* A bare number is Mbps in wlanconfig output. */
    if (apd_vendor_parse_rate_kbps("54", &kbps) != 0 || kbps != 54000)
        return 32;
    if (apd_vendor_parse_rate_kbps("", &kbps) == 0 ||
        apd_vendor_parse_rate_kbps("abc", &kbps) == 0 ||
        apd_vendor_parse_rate_kbps("-5M", &kbps) == 0)
        return 33;
    return 0;
}

static struct json_object *fixture_field(struct json_object *root,
                                         const char *key)
{
    struct json_object *value = NULL;

    if (!root || !json_object_object_get_ex(root, key, &value))
        return NULL;
    return value;
}

/* End-to-end: `survey dump` is empty but stations must still be reported, and
 * station_source must name wlanconfig rather than the tool that returned
 * nothing. */
static int fixture_expect_emitter(const char *path)
{
    struct json_object *result = NULL;
    struct json_object *stations = NULL;
    struct json_object *first = NULL;
    int rc = 0;

    setenv("APD_VENDOR_FIXTURE_MODE", "success", 1);
    /* Survey fails (empty), so the collector returns non-zero overall. */
    if (apd_survey_scan_collect(path, "phy1", &result) == 0 || !result)
        return 40;
    if (json_object_get_boolean(fixture_field(result, "complete")))
        rc = 41;
    else if (json_object_get_int(fixture_field(result, "station_count")) != 2)
        rc = 42;
    else if (strcmp(json_object_get_string(
                        fixture_field(result, "station_source")),
                    "wlanconfig_list"))
        rc = 43;
    else if (!json_object_is_type(fixture_field(result, "station_reason"),
                                 json_type_null))
        rc = 44;
    if (rc) {
        fprintf(stderr, "emitter: %s\n",
                json_object_to_json_string_ext(result, JSON_C_TO_STRING_PLAIN));
        json_object_put(result);
        return rc;
    }
    stations = fixture_field(result, "stations");
    if (!stations || json_object_array_length(stations) != 2) {
        json_object_put(result);
        return 45;
    }
    first = json_object_array_get_idx(stations, 0);
    if (strcmp(json_object_get_string(fixture_field(first, "mac")),
               "4c:c6:4c:18:6c:73") ||
        json_object_get_int(fixture_field(first, "rssi_dbm")) != -65 ||
        json_object_get_int64(fixture_field(first, "tx_rate_kbps")) != 433000 ||
        json_object_get_int(fixture_field(first, "tx_nss")) != 1 ||
        strcmp(json_object_get_string(fixture_field(first, "wifi_standard")),
               "IEEE80211_MODE_11AC_VHT80") ||
        strcmp(json_object_get_string(fixture_field(first, "interface")),
               "ath11")) {
        fprintf(stderr, "station: %s\n",
                json_object_to_json_string_ext(first, JSON_C_TO_STRING_PLAIN));
        json_object_put(result);
        return 46;
    }
    json_object_put(result);

    /* When wlanconfig also yields nothing, the reason must be reported and
     * station_source must stay null instead of naming a tool that failed. */
    setenv("APD_VENDOR_FIXTURE_MODE", "empty", 1);
    result = NULL;
    if (apd_survey_scan_collect(path, "phy1", &result) == 0 || !result)
        return 47;
    if (!json_object_is_type(fixture_field(result, "station_source"),
                            json_type_null) ||
        json_object_get_int(fixture_field(result, "station_count")) != 0 ||
        strcmp(json_object_get_string(fixture_field(result, "station_reason")),
               "wlanconfig_no_output")) {
        fprintf(stderr, "empty-case: %s\n",
                json_object_to_json_string_ext(result, JSON_C_TO_STRING_PLAIN));
        json_object_put(result);
        return 48;
    }
    json_object_put(result);
    return 0;
}

int main(int argc, char **argv)
{
    int rc;

    if (argc == 2 && !strcmp(argv[1], "dev"))
        return fixture_iw(argc, argv);
    if (argc == 5 && !strcmp(argv[3], "survey"))
        return fixture_iw(argc, argv);
    if (argc == 3 && !strcmp(argv[2], "list"))
        return fixture_wlanconfig(argc, argv);
    if (argc != 1)
        return 2;
    rc = fixture_expect_success(argv[0]);
    if (!rc)
        rc = fixture_expect_failure_states(argv[0]);
    if (!rc)
        rc = fixture_expect_rate_units();
    if (!rc)
        rc = fixture_expect_emitter(argv[0]);
    if (rc)
        return rc;
    puts("ok: APD wlanconfig station fallback parser and bounded argv collection");
    return 0;
}

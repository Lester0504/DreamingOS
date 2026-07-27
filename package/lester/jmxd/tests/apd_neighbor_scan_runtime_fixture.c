// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
#define APD_HOSTAPD_STANDALONE_TEST 1
#define APD_NEIGHBOR_SCAN_STANDALONE_TEST 1
#define APD_SURVEY_STANDALONE_TEST 1
#define APD_NEIGHBOR_SCAN_TIMEOUT_MS 120

static unsigned int fixture_if_nametoindex(const char *name);
#define APD_NEIGHBOR_IF_NAMETOINDEX(name) fixture_if_nametoindex(name)

#include "../src/apd/apd_backend_openwrt.c"

#include <sys/stat.h>

static unsigned int fixture_if_nametoindex(const char *name)
{
    if (!strcmp(name, "wifi0")) return 11;
    if (!strcmp(name, "ath0")) return 12;
    if (!strcmp(name, "MLD1")) return 20;
    return 0;
}

static int fixture_iw_inventory(const char *mode)
{
    fputs("phy#0\n"
          "\tInterface MLD1\n"
          "\t\tifindex 20\n"
          "\t\ttype AP\n"
          "phy#1\n"
          "\tInterface ath0\n"
          "\t\tifindex ",
          stdout);
    fprintf(stdout, "%s\n", !strcmp(mode, "mapping-mismatch") ? "98" : "12");
    fputs(
          "\t\tssid Main\n"
          "\t\ttype AP\n"
          "\t\tchannel 36 (5180 MHz), width: 80 MHz\n"
          "\tInterface wifi0\n",
          stdout);
    fprintf(stdout, "\t\tifindex %s\n", !strcmp(mode, "mapping-mismatch") ?
            "99" : "11");
    fputs("\t\ttype AP\n"
          "\t\tchannel 36 (5180 MHz), width: 80 MHz\n",
          stdout);
    return ferror(stdout) ? 1 : 0;
}

static void fixture_print_bss(unsigned int index, int long_ssid)
{
    unsigned int a = (index >> 16) & 0xff;
    unsigned int b = (index >> 8) & 0xff;
    unsigned int c = index & 0xff;

    fprintf(stdout,
            "BSS 00:11:22:%02x:%02x:%02x(on ath0)\n"
            "\tfreq: 5180\n"
            "\tcapability: ESS Privacy (0x0011)\n"
            "\tsignal: -%u.00 dBm\n"
            "\tlast seen: %u ms ago\n"
            "\tSSID: %s%u\n"
            "\tRSN:\t * Version: 1\n"
            "\t\t * Authentication suites: PSK SAE\n"
            "\tVHT operation:\n"
            "\t\t * channel width: 1 (80 MHz)\n",
            a, b, c, 30 + (index % 60), index,
            long_ssid ? "fixture-net-" : "n", index);
}

static int fixture_iw_scan(const char *mode)
{
    if (!strcmp(mode, "timeout")) {
        usleep(500000);
        return 0;
    }
    if (!strcmp(mode, "failure"))
        return 95;
    if (!strcmp(mode, "failure-unsupported")) {
        fputs("command failed: Operation not supported (-95)\n", stderr);
        return 1;
    }
    if (!strcmp(mode, "failure-busy")) {
        fputs("command failed: Device or resource busy (-16)\n", stderr);
        return 1;
    }
    if (!strcmp(mode, "failure-down")) {
        fputs("command failed: Network is down (-100)\n", stderr);
        return 1;
    }
    if (!strcmp(mode, "failure-perm")) {
        fputs("command failed: Operation not permitted (-1)\n", stderr);
        return 1;
    }
    if (!strcmp(mode, "failure-inval")) {
        fputs("command failed: Invalid argument (-22)\n", stderr);
        return 1;
    }
    if (!strcmp(mode, "failure-nodev")) {
        fputs("command failed: No such device (-19)\n", stderr);
        return 1;
    }
    if (!strcmp(mode, "failure-text")) {
        fputs("scan not supported on this interface\n", stderr);
        return 1;
    }
    if (!strcmp(mode, "output-limit")) {
        char block[4096];
        memset(block, 'x', sizeof(block));
        for (int i = 0; i < 300; i++)
            fwrite(block, 1, sizeof(block), stdout);
        return ferror(stdout) ? 1 : 0;
    }
    if (!strcmp(mode, "many")) {
        for (unsigned int i = 0; i < 180; i++)
            fixture_print_bss(i, 1);
        return ferror(stdout) ? 1 : 0;
    }
    fputs("BSS 02:aa:bb:cc:dd:01(on ath0)\n"
          "\tfreq: 5180\n"
          "\tcapability: ESS Privacy (0x1531)\n"
          "\tsignal: -42.50 dBm\n"
          "\tlast seen: 20 ms ago\n"
          "\tSSID: \\xe5\\x91\\xa8\\xe5\\xb0\\x8f\\xe5\\xa8\\x9f\n"
          "\tRSN:\t * Version: 1\n"
          "\t\t * Group cipher: CCMP\n"
          "\t\t * Pairwise ciphers: CCMP\n"
          "\t\t * Authentication suites: PSK SAE\n"
          "\tVHT operation:\n"
          "\t\t * channel width: 1 (80 MHz)\n"
          "BSS 00:aa:bb:cc:dd:02(on ath0)\n"
          "\tfreq: 5180\n"
          "\tsignal: -65.00 dBm\n"
          "\tlast seen: 50 ms ago\n"
          "\tSSID: \n"
          "\tHT operation:\n"
          "\t\t * secondary channel offset: no secondary\n",
          stdout);
    if (!strcmp(mode, "partial"))
        fputs("BSS 01:aa:bb:cc:dd:03(on ath0)\n"
              "\tfreq: 5180\n"
              "\tsignal: -10.00 dBm\n"
              "\tSSID: multicast-invalid\n",
              stdout);
    return ferror(stdout) ? 1 : 0;
}

static int fixture_iw_survey(const char *mode)
{
    if (!strcmp(mode, "survey-failure"))
        return 95;
    fputs("Survey data from ath0\n"
          "\tfrequency: 5180 MHz [in use]\n"
          "\tnoise: -94 dBm\n"
          "\tchannel active time: 1000 ms\n"
          "\tchannel busy time: 175 ms\n"
          "\tchannel receive time: 90 ms\n"
          "\tchannel transmit time: 35 ms\n", stdout);
    return ferror(stdout) ? 1 : 0;
}

static int fixture_iw(int argc, char **argv)
{
    const char *mode = getenv("APD_NEIGHBOR_FIXTURE_MODE");

    if (!mode)
        return 90;
    if (argc == 2 && !strcmp(argv[1], "dev"))
        return fixture_iw_inventory(mode);
    if (argc == 7 && !strcmp(argv[1], "dev") && !strcmp(argv[2], "ath0") &&
        !strcmp(argv[3], "scan") && !strcmp(argv[4], "ap-force") &&
        !strcmp(argv[5], "flush") && !strcmp(argv[6], "passive") &&
        argv[7] == NULL)
        return fixture_iw_scan(mode);
    if (argc == 5 && !strcmp(argv[1], "dev") && !strcmp(argv[2], "ath0") &&
        !strcmp(argv[3], "survey") && !strcmp(argv[4], "dump") &&
        argv[5] == NULL)
        return fixture_iw_survey(mode);
    return 91;
}

static struct json_object *fixture_field(struct json_object *object,
                                         const char *name)
{
    struct json_object *value = NULL;
    return json_object_object_get_ex(object, name, &value) ? value : NULL;
}

static int fixture_item_contract(struct json_object *item)
{
    static const char *const fields[] = {
        "bssid", "locally_administered", "ssid", "ssid_hex", "ssid_hidden",
        "rssi_dbm", "age_ms", "frequency_mhz", "channel", "width_mhz",
        "width_mode", "standard", "security", "vendor", "vendor_reason",
        "complete", "missing_fields"
    };
    size_t count = 0;
    json_object_object_foreach(item, key, value) {
        int known = 0;

        (void)value;
        count++;
        for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
            known |= strcmp(key, fields[i]) == 0;
        if (!known)
            return 0;
    }
    return count == sizeof(fields) / sizeof(fields[0]) &&
           json_object_is_type(fixture_field(item, "bssid"), json_type_string) &&
           json_object_is_type(fixture_field(item, "ssid_hidden"), json_type_boolean) &&
           json_object_is_type(fixture_field(item, "security"), json_type_string) &&
           json_object_is_type(fixture_field(item, "missing_fields"), json_type_array);
}

static int fixture_expect_success(const char *path)
{
    struct json_object *result = NULL;
    struct json_object *items;
    struct json_object *first;
    struct json_object *second;

    setenv("APD_NEIGHBOR_FIXTURE_MODE", "success", 1);
    if (apd_neighbor_scan_collect(path, "phy1", &result) != 0 || !result ||
        !json_object_get_boolean(fixture_field(result, "ok")) ||
        !json_object_get_boolean(fixture_field(result, "complete")) ||
        json_object_get_boolean(fixture_field(result, "truncated")) ||
        strcmp(json_object_get_string(fixture_field(result, "error_code")), "") ||
        strcmp(json_object_get_string(fixture_field(result, "scanner_interface")),
               "ath0")) {
        if (result)
            fprintf(stderr, "neighbor result: %s\n",
                    json_object_to_json_string_ext(result,
                                                   JSON_C_TO_STRING_PLAIN));
        return 10;
    }
    items = fixture_field(result, "items");
    if (!items || json_object_array_length(items) != 2)
        return 11;
    first = json_object_array_get_idx(items, 0);
    second = json_object_array_get_idx(items, 1);
    if (!fixture_item_contract(first) || !fixture_item_contract(second) ||
        strcmp(json_object_get_string(fixture_field(first, "bssid")),
               "02:aa:bb:cc:dd:01") ||
        !json_object_get_boolean(fixture_field(first, "locally_administered")) ||
        !json_object_is_type(fixture_field(first, "ssid"), json_type_null) ||
        strcmp(json_object_get_string(fixture_field(first, "ssid_hex")),
               "e591a8e5b08fe5a89f") ||
        strcmp(json_object_get_string(fixture_field(first, "standard")),
               "802.11ac") ||
        strcmp(json_object_get_string(fixture_field(first, "security")),
               "wpa2-wpa3-personal") ||
        strcmp(json_object_get_string(fixture_field(first, "vendor_reason")),
               "locally_administered_bssid") ||
        json_object_get_int(fixture_field(first, "channel")) != 36 ||
        json_object_get_int(fixture_field(first, "width_mhz")) != 80) {
        fprintf(stderr, "first item: %s\n",
                json_object_to_json_string_ext(first, JSON_C_TO_STRING_PLAIN));
        return 12;
    }
    if (!json_object_get_boolean(fixture_field(second, "ssid_hidden")) ||
        strcmp(json_object_get_string(fixture_field(second, "security")), "open") ||
        json_object_get_int(fixture_field(second, "width_mhz")) != 20)
        return 13;
    json_object_put(result);
    return 0;
}

static int fixture_expect_failure(const char *path, const char *mode,
                                  const char *radio_id, const char *error)
{
    struct json_object *result = NULL;
    struct json_object *items;

    setenv("APD_NEIGHBOR_FIXTURE_MODE", mode, 1);
    if (apd_neighbor_scan_collect(path, radio_id, &result) == 0 || !result ||
        json_object_get_boolean(fixture_field(result, "ok")) ||
        json_object_get_boolean(fixture_field(result, "complete")) ||
        json_object_get_boolean(fixture_field(result, "truncated")) ||
        strcmp(json_object_get_string(fixture_field(result, "error_code")), error)) {
        if (result)
            fprintf(stderr, "failure expected=%s actual=%s\n", error,
                    json_object_to_json_string_ext(result,
                                                   JSON_C_TO_STRING_PLAIN));
        return 20;
    }
    items = fixture_field(result, "items");
    if (!items || json_object_array_length(items) != 0)
        return 21;
    json_object_put(result);
    return 0;
}

static int fixture_expect_partial(const char *path)
{
    struct json_object *result = NULL;
    struct json_object *items;

    setenv("APD_NEIGHBOR_FIXTURE_MODE", "partial", 1);
    if (apd_neighbor_scan_collect(path, "phy1", &result) != 0 || !result ||
        !json_object_get_boolean(fixture_field(result, "ok")) ||
        json_object_get_boolean(fixture_field(result, "complete")) ||
        json_object_get_boolean(fixture_field(result, "truncated")) ||
        strcmp(json_object_get_string(fixture_field(result, "error_code")),
               "scan_output_parse_partial"))
        return 25;
    items = fixture_field(result, "items");
    if (!items || json_object_array_length(items) != 2 ||
        json_object_get_int64(fixture_field(result, "malformed_count")) != 1)
        return 26;
    json_object_put(result);
    return 0;
}

static int fixture_expect_limits(const char *path)
{
    struct json_object *result = NULL;
    struct json_object *items;
    int64_t frame_bytes;

    setenv("APD_NEIGHBOR_FIXTURE_MODE", "many", 1);
    if (apd_neighbor_scan_collect(path, "phy1", &result) != 0 || !result ||
        !json_object_get_boolean(fixture_field(result, "ok")) ||
        json_object_get_boolean(fixture_field(result, "complete")) ||
        !json_object_get_boolean(fixture_field(result, "truncated")) ||
        strcmp(json_object_get_string(fixture_field(result, "error_code")),
               "scan_result_limited"))
        return 30;
    items = fixture_field(result, "items");
    frame_bytes = json_object_get_int64(fixture_field(result, "frame_bytes"));
    if (!items || json_object_array_length(items) > 128 || frame_bytes > 24 * 1024 ||
        frame_bytes != (int64_t)strlen(json_object_to_json_string_ext(
            result, JSON_C_TO_STRING_PLAIN)))
        return 31;
    json_object_put(result);

    setenv("APD_NEIGHBOR_FIXTURE_MODE", "output-limit", 1);
    if (apd_neighbor_scan_collect(path, "phy1", &result) != 0 || !result ||
        !json_object_get_boolean(fixture_field(result, "ok")) ||
        json_object_get_boolean(fixture_field(result, "complete")) ||
        !json_object_get_boolean(fixture_field(result, "truncated")) ||
        strcmp(json_object_get_string(fixture_field(result, "error_code")),
               "scan_output_limited"))
        return 32;
    json_object_put(result);
    return 0;
}

static int fixture_expect_survey(const char *path)
{
    struct json_object *result = NULL;
    struct json_object *items;
    struct json_object *sample;

    setenv("APD_NEIGHBOR_FIXTURE_MODE", "success", 1);
    if (apd_survey_scan_collect(path, "phy1", &result) != 0 || !result ||
        !json_object_get_boolean(fixture_field(result, "ok")) ||
        !json_object_get_boolean(fixture_field(result, "complete")) ||
        json_object_get_boolean(fixture_field(result, "truncated")) ||
        strcmp(json_object_get_string(fixture_field(result, "error_code")), ""))
        return 40;
    items = fixture_field(result, "items");
    sample = items && json_object_array_length(items) == 1 ?
        json_object_array_get_idx(items, 0) : NULL;
    if (!sample || strcmp(json_object_get_string(fixture_field(sample, "radio_id")),
                          "phy1") ||
        strcmp(json_object_get_string(fixture_field(sample, "interface")),
               "ath0") ||
        strcmp(json_object_get_string(fixture_field(sample, "wiphy_name")),
               "phy1") ||
        json_object_get_int(fixture_field(sample, "frequency_mhz")) != 5180 ||
        json_object_get_int(fixture_field(sample, "noise_dbm")) != -94 ||
        json_object_get_double(fixture_field(sample, "utilization_pct")) != 17.5)
        return 41;
    json_object_put(result);
    return 0;
}

static int fixture_expect_channel_catalog(void)
{
    static const char text[] =
        "Wiphy phy1\n"
        "\tmax # scan SSIDs: 16\n"
        "\tBand 1:\n"
        "\t\tCapabilities: 0x19e7\n"
        "\t\t\tHT20/HT40\n"
        "\t\tVHT Capabilities (0x338b7992):\n"
        "\t\t\tSupported Channel Width: neither 160 nor 80+80\n"
        "\t\tHE Iftypes: AP\n"
        "\t\t\tHE PHY Capabilities: (0x026040890fc39f1c110e00):\n"
        "\t\t\t\tHE40/2.4GHz\n"
        "\t\t\tEHT PHY Capabilities: (0xe2ffdbe01877d83e00):\n"
        "\t\t\t\t320 MHz in 6 GHz Support\n"
        "\t\tFrequencies:\n"
        "\t\t\t* 2412 MHz [1] (20.0 dBm)\n"
        "\t\t\t* 2467 MHz [12] (20.0 dBm) (no IR)\n"
        "\t\t\t* 5260 MHz [52] (23.0 dBm) (radar detection)\n"
        "\t\t\t  DFS state: usable (for 87360 sec)\n"
        "\t\t\t  DFS CAC time: 60000 ms\n"
        "\t\t\t* 5825 MHz [165] (disabled)\n"
        "Wiphy phy7\n"
        "\tBand 2:\n"
        "\t\tCapabilities: 0x19e7\n"
        "\t\t\tHT20/HT40\n"
        "\t\tVHT Capabilities (0x338bf9f6):\n"
        "\t\t\tSupported Channel Width: 160 MHz\n"
        "\t\t\tHE PHY Capabilities: (0x1c634089ffdb9f1c110e00):\n"
        "\t\t\t\tHE40/HE80/5GHz\n"
        "\t\t\t\tHE160/5GHz\n"
        "\t\tFrequencies:\n"
        "\t\t\t* 5180 MHz [36] (22.0 dBm)\n";
    struct json_object *radios = json_object_new_array();
    struct json_object *radio = json_object_new_object();
    struct json_object *catalog;
    struct json_object *channels;
    struct json_object *entry;
    int rc = 60;

    json_object_object_add(radio, "id", json_object_new_string("phy1"));
    json_object_array_add(radios, radio);
    apd_channel_catalog_parse(text, radios, "CN", 123);
    catalog = fixture_field(radio, "channel_catalog");
    if (!catalog ||
        !json_object_get_boolean(fixture_field(catalog, "complete")) ||
        strcmp(json_object_get_string(fixture_field(catalog, "source")),
               "iw_phy") ||
        strcmp(json_object_get_string(fixture_field(catalog, "regdomain")),
               "CN") ||
        json_object_get_int64(fixture_field(catalog, "observed_at")) != 123)
        goto done;
    rc = 61;
    channels = fixture_field(catalog, "channels");
    if (!channels || json_object_array_length(channels) != 4)
        goto done;
    rc = 62;
    entry = json_object_array_get_idx(channels, 0);
    if (json_object_get_int(fixture_field(entry, "channel")) != 1 ||
        json_object_get_int(fixture_field(entry, "frequency_mhz")) != 2412 ||
        json_object_get_boolean(fixture_field(entry, "disabled")) ||
        json_object_get_boolean(fixture_field(entry, "no_ir")))
        goto done;
    rc = 63;
    entry = json_object_array_get_idx(channels, 1);
    if (!json_object_get_boolean(fixture_field(entry, "no_ir")))
        goto done;
    rc = 64;
    entry = json_object_array_get_idx(channels, 2);
    if (!json_object_get_boolean(fixture_field(entry, "radar_detection")) ||
        !fixture_field(entry, "dfs_state") ||
        strcmp(json_object_get_string(fixture_field(entry, "dfs_state")),
               "usable"))
        goto done;
    rc = 65;
    entry = json_object_array_get_idx(channels, 3);
    if (!json_object_get_boolean(fixture_field(entry, "disabled")) ||
        fixture_field(entry, "dfs_state") != NULL)
        goto done;
    rc = 66;
    /* Width evidence: HT20/HT40 + HE40 only — the 2.4 GHz vendor-VHT
     * "neither 160 nor 80+80" line must NOT produce 80/160, and the
     * band-qualified "320 MHz in 6 GHz Support" marker must NOT produce
     * 320 on a wiphy without 6 GHz frequencies. */
    entry = fixture_field(catalog, "supported_widths_mhz");
    if (!entry || json_object_array_length(entry) != 2 ||
        json_object_get_int(json_object_array_get_idx(entry, 0)) != 20 ||
        json_object_get_int(json_object_array_get_idx(entry, 1)) != 40)
        goto done;
    rc = 67;
    /* AP-usable channels exclude disabled and no-IR entries. */
    entry = fixture_field(catalog, "supported_channels");
    if (!entry || json_object_array_length(entry) != 2 ||
        json_object_get_int(json_object_array_get_idx(entry, 0)) != 1 ||
        json_object_get_int(json_object_array_get_idx(entry, 1)) != 52)
        goto done;
    rc = 68;
    entry = fixture_field(catalog, "tx_power_range_dbm");
    if (!entry ||
        json_object_get_double(fixture_field(entry, "min")) != 20.0 ||
        json_object_get_double(fixture_field(entry, "max")) != 23.0)
        goto done;
    rc = 0;
done:
    json_object_put(radios);
    return rc;
}

static int fixture_expect_failure_evidence(const char *path)
{
    struct json_object *result = NULL;
    struct json_object *evidence;
    struct json_object *value;

    setenv("APD_NEIGHBOR_FIXTURE_MODE", "failure-busy", 1);
    if (apd_neighbor_scan_collect(path, "phy1", &result) == 0 || !result)
        return 50;
    evidence = fixture_field(result, "error_evidence");
    if (!evidence || !json_object_is_type(evidence, json_type_object))
        return 51;
    value = fixture_field(evidence, "exit_status");
    if (!value || json_object_get_int(value) != 1)
        return 52;
    value = fixture_field(evidence, "stderr_excerpt");
    if (!value ||
        !strstr(json_object_get_string(value), "Device or resource busy") ||
        !strstr(json_object_get_string(value), "(-16)"))
        return 53;
    value = fixture_field(evidence, "stderr_truncated");
    if (!value || json_object_get_boolean(value))
        return 54;
    json_object_put(result);
    return 0;
}

int main(int argc, char **argv)
{
    int rc = 0;

    if (argc > 1)
        return fixture_iw(argc, argv);
    rc = fixture_expect_success(argv[0]);
    if (!rc) rc = fixture_expect_failure(argv[0], "success", "phy0",
                                          "radio_not_scannable");
    if (!rc) rc = fixture_expect_failure(argv[0], "success", "phy01",
                                          "radio_id_invalid");
    if (!rc) rc = fixture_expect_failure(argv[0], "mapping-mismatch", "phy1",
                                          "radio_not_scannable");
    if (!rc) rc = fixture_expect_failure(argv[0], "timeout", "phy1",
                                          "iw_neighbor_scan_timeout");
    /* The former catch-all is split into diagnosable reasons.  A raw
     * nonzero exit without stderr evidence must preserve the exit status
     * instead of guessing "unsupported". */
    if (!rc) rc = fixture_expect_failure(argv[0], "failure", "phy1",
                                          "iw_neighbor_scan_command_failed_exit_95");
    if (!rc) rc = fixture_expect_failure(argv[0], "failure-unsupported", "phy1",
                                          "iw_neighbor_scan_not_supported");
    if (!rc) rc = fixture_expect_failure(argv[0], "failure-busy", "phy1",
                                          "iw_neighbor_scan_interface_busy");
    if (!rc) rc = fixture_expect_failure(argv[0], "failure-down", "phy1",
                                          "iw_neighbor_scan_interface_down");
    if (!rc) rc = fixture_expect_failure(argv[0], "failure-perm", "phy1",
                                          "iw_neighbor_scan_permission_denied");
    if (!rc) rc = fixture_expect_failure(argv[0], "failure-inval", "phy1",
                                          "iw_neighbor_scan_driver_rejected");
    if (!rc) rc = fixture_expect_failure(argv[0], "failure-nodev", "phy1",
                                          "iw_neighbor_scan_interface_missing");
    if (!rc) rc = fixture_expect_failure(argv[0], "failure-text", "phy1",
                                          "iw_neighbor_scan_not_supported");
    if (!rc) rc = fixture_expect_failure_evidence(argv[0]);
    if (!rc) rc = fixture_expect_channel_catalog();
    if (!rc) rc = fixture_expect_partial(argv[0]);
    if (!rc) rc = fixture_expect_limits(argv[0]);
    if (!rc) rc = fixture_expect_survey(argv[0]);
    if (rc)
        return rc;
    puts("ok: APD neighbor scan fixed argv, strict mapping/parser, and honest limits");
    return 0;
}

#!/usr/bin/env python3
"""Air-statistics passthrough contract for the Wi-Fi aggregation layer.

The collector writes air statistics onto `radio.survey.air_stats`, but the
wireless page reads `radio.air_stats`. Without the republish the vendor
collector works and the table still shows nothing, which is the defect this
covers.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apd_test_deps  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]

HARNESS = r'''
#include <assert.h>
#include <json-c/json.h>
#include <stdio.h>
#include <string.h>
#include "webd_wifi_aggregate.h"

static struct json_object *parse(const char *text)
{
    struct json_object *value = json_tokener_parse(text);
    assert(value != NULL);
    return value;
}

static struct json_object *child(struct json_object *obj, const char *key)
{
    struct json_object *value = NULL;
    if (!obj || !json_object_object_get_ex(obj, key, &value) || !value) {
        fprintf(stderr, "missing JSON key: %s\n", key);
        abort();
    }
    return value;
}

static int is_null(struct json_object *obj, const char *key)
{
    struct json_object *value = NULL;

    return obj && json_object_object_get_ex(obj, key, &value) &&
           (value == NULL || json_object_is_type(value, json_type_null));
}

static struct json_object *first_radio(struct json_object *data)
{
    struct json_object *radios = child(data, "radios");

    assert(json_object_array_length(radios) >= 1);
    return json_object_array_get_idx(radios, 0);
}

/*
 * A managed AP whose `iw survey dump` produced nothing, so apd supplied the
 * sample from vendor counters and rewrote the survey source to apstats_radio.
 * Note total_per_pct = 0: a real measured zero, which must survive as 0.
 * retries and rx_crc_errors are null: radio-level apstats never prints them.
 */
static const char *ap_with_air_stats =
"{\"items\":[{\"ap_id\":\"ap-1\",\"name\":\"AP One\",\"online\":true,"
"\"snapshot\":{\"fresh\":true,\"complete\":true,"
"\"radios\":[{\"radio_id\":\"phy1\",\"band\":\"5g\",\"channel\":36,"
"\"survey\":{\"source\":\"apstats_radio\",\"complete\":true,"
"\"utilization_pct\":37.5,\"noise_dbm\":-96,"
"\"air_stats\":{\"source\":\"apstats_radio\",\"available\":true,"
"\"interface\":\"wifi1\",\"reason\":null,"
"\"tx_packets\":881234,\"tx_bytes\":992345678,"
"\"rx_packets\":771234,\"rx_bytes\":882345678,"
"\"tx_failures\":4132,\"dropped\":17,\"retries\":null,"
"\"rx_phy_errors\":22,\"rx_crc_errors\":null,"
"\"total_per_pct\":0,\"retry_rate_pct\":2.75,"
"\"self_bss_util_pct\":12,\"obss_util_pct\":5,"
"\"noise_floor_dbm\":-96,"
"\"firmware_disabled_channel_utilization\":false,"
"\"firmware_disabled_throughput\":true}}}]}}]}";

/* Same AP but the survey carries no air_stats block at all. */
static const char *ap_without_air_stats =
"{\"items\":[{\"ap_id\":\"ap-1\",\"name\":\"AP One\",\"online\":true,"
"\"snapshot\":{\"fresh\":true,\"complete\":true,"
"\"radios\":[{\"radio_id\":\"phy1\",\"band\":\"5g\",\"channel\":36,"
"\"survey\":{\"source\":\"iw_survey\",\"complete\":true,"
"\"utilization_pct\":10.0,\"noise_dbm\":-95}}]}}]}";

static const char *empty_local = "{\"radios\":[],\"ssids\":[]}";

static void air_stats_reach_the_radio(void)
{
    struct json_object *local = parse(empty_local);
    struct json_object *ac = parse(ap_with_air_stats);
    struct json_object *data = webd_wifi_aggregate_data(local, ac, 1);
    struct json_object *radio = first_radio(data);
    struct json_object *air = child(radio, "air_stats");

    /* The six columns the table renders. */
    assert(json_object_get_int64(child(air, "tx_packets")) == 881234);
    assert(json_object_get_int64(child(air, "tx_bytes")) == 992345678);
    assert(json_object_get_int64(child(air, "rx_packets")) == 771234);
    assert(json_object_get_int64(child(air, "rx_bytes")) == 882345678);
    assert(json_object_get_int64(child(air, "dropped")) == 17);

    /*
     * A measured zero stays zero. Turning it into null would claim the counter
     * was never read, which is a different fact.
     */
    assert(!is_null(air, "total_per_pct"));
    assert(json_object_get_int(child(air, "total_per_pct")) == 0);

    /*
     * `retries` is null because radio-level apstats does not report it, and
     * tx_failures must NOT be substituted: a transmit failure is not a retry.
     */
    assert(is_null(air, "retries"));
    assert(json_object_get_int64(child(air, "tx_failures")) == 4132);
    assert(is_null(air, "rx_crc_errors"));

    /* Provenance travels with the numbers. */
    assert(!strcmp(json_object_get_string(child(air, "source")), "apstats_radio"));
    assert(json_object_get_boolean(child(air, "available")) == 1);
    assert(!strcmp(json_object_get_string(child(air, "interface")), "wifi1"));
    assert(json_object_get_boolean(
        child(air, "firmware_disabled_throughput")) == 1);

    /* Flat retry_rate the page also reads. */
    assert(json_object_get_double(child(radio, "retry_rate")) > 2.7);
    assert(json_object_get_double(child(radio, "retry_rate")) < 2.8);

    /*
     * The reported source must be the one that produced the data. Hardcoding
     * "iw_survey" while the numbers came from apstats is what made an empty
     * page look like an empty environment.
     */
    assert(!strcmp(json_object_get_string(
        child(radio, "channel_utilization_source")), "apstats_radio"));
    assert(!strcmp(json_object_get_string(
        child(radio, "noise_source")), "apstats_radio"));

    json_object_put(data);
    json_object_put(ac);
    json_object_put(local);
}

static void absent_air_stats_stay_absent(void)
{
    struct json_object *local = parse(empty_local);
    struct json_object *ac = parse(ap_without_air_stats);
    struct json_object *data = webd_wifi_aggregate_data(local, ac, 1);
    struct json_object *radio = first_radio(data);

    /* No block means null plus a reason, never an object full of zeros. */
    assert(is_null(radio, "air_stats"));
    assert(is_null(radio, "retry_rate"));
    assert(strlen(json_object_get_string(child(radio, "air_stats_reason"))) > 0);

    /* A genuine iw survey still reports itself as iw_survey. */
    assert(!strcmp(json_object_get_string(
        child(radio, "channel_utilization_source")), "iw_survey"));

    json_object_put(data);
    json_object_put(ac);
    json_object_put(local);
}

int main(void)
{
    air_stats_reach_the_radio();
    absent_air_stats_stay_absent();
    printf("ok: wifi air-stats passthrough contract\n");
    return 0;
}
'''


def json_c_flags() -> list[str]:
    # 31.6 ships no json-c .pc file; the shared resolver falls back to the
    # staging_dir prefix instead of raising CalledProcessError.
    return apd_test_deps.package_flags("json-c")


def main() -> None:
    flags = json_c_flags()
    with tempfile.TemporaryDirectory(prefix="wifi-air-stats-") as tmp:
        source = Path(tmp) / "harness.c"
        source.write_text(HARNESS, encoding="utf-8")
        executable = Path(tmp) / "harness"
        subprocess.run(
            [
                os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra",
                "-Werror", "-I", str(ROOT / "src/webd"), str(source),
                str(ROOT / "src/webd/webd_wifi_aggregate.c"), *flags,
                "-o", str(executable),
            ],
            check=True,
        )
        subprocess.run([str(executable)], check=True)


if __name__ == "__main__":
    main()

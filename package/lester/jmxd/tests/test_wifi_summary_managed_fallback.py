#!/usr/bin/env python3
"""Summary airtime aggregates must fall back to managed AP radios.

On an x86 router with no wireless card the local channel survey can never
produce a sample, so `avg_utilization` / `avg_retry_rate` / `worst_noise` were
published as null with `airtime_reason: local_survey_source_unavailable` even
though the managed AP's radios sat in the same response carrying real values.
That reason is true about the local source and wrong as the summary's answer.

Also covered: `interface_count` / `phy_count` count local phys only and read as
a contradiction next to `radio_count`, and a reason describing the local hostapd
control channel must not stand as the explanation for an empty remote client
list.
"""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


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

static const char *text(struct json_object *obj, const char *key)
{
    return json_object_get_string(child(obj, key));
}

/*
 * 30.1 as deployed: x86, no phy, and the local chain has already written the
 * nulls plus `local_survey_source_unavailable` that this contract replaces.
 */
static const char *local_no_phy =
"{\"code\":2000,\"data\":{\"capabilities\":{\"wifi\":false},"
"\"radios\":[],\"runtime_radios\":[],\"ssids\":[],\"stations\":[],"
"\"summary\":{\"interface_count\":0,\"phy_count\":0,\"avg_signal\":null,"
"\"avg_utilization\":null,\"avg_retry_rate\":null,\"worst_noise\":null,"
"\"airtime_reason\":\"local_survey_source_unavailable\"},"
"\"runtime\":{\"available\":false,\"complete\":false,"
"\"reason\":\"no_phy_detected\"}}}";

/*
 * Three managed radios carrying the values apstats supplied on the BE10000:
 * utilization from Self BSS + OBSS chan util, noise from the BDF-averaged floor.
 * Stations are empty and hostapd is complete, i.e. genuinely no clients.
 */
static const char *managed_with_airtime =
"{\"ok\":true,\"items\":[{\"ap_id\":\"ap-1\",\"name\":\"Living AP\","
"\"online\":true,\"stale\":false,\"runtime\":{\"available\":true,"
"\"snapshot\":{\"fresh\":true,\"complete\":true,"
"\"radios\":["
"{\"id\":\"phy1\",\"band\":\"2.4GHz\",\"channel\":10,"
"\"survey\":{\"source\":\"apstats_radio\",\"complete\":true,"
"\"utilization_pct\":30.0,\"noise_dbm\":-90,"
"\"air_stats\":{\"available\":true,\"tx_packets\":1000,"
"\"retry_rate_pct\":4.0}}},"
"{\"id\":\"phy2\",\"band\":\"5GHz\",\"channel\":36,"
"\"survey\":{\"source\":\"apstats_radio\",\"complete\":true,"
"\"utilization_pct\":12.0,\"noise_dbm\":-96,"
"\"air_stats\":{\"available\":true,\"tx_packets\":1000,"
"\"retry_rate_pct\":2.0}}},"
"{\"id\":\"phy3\",\"band\":\"6GHz\",\"channel\":33,"
"\"survey\":{\"source\":\"apstats_radio\",\"complete\":true,"
"\"utilization_pct\":6.0,\"noise_dbm\":-99,"
"\"air_stats\":{\"available\":true,\"tx_packets\":1000,"
"\"retry_rate_pct\":0.0}}}],"
"\"ssids\":[],\"stations\":[],"
"\"sources\":{\"hostapd\":{\"available\":true,\"complete\":true,"
"\"reason\":\"available\"}}}}}]}";

/* Same AP, but its station source failed. The reason belongs to the AP. */
static const char *managed_station_source_down =
"{\"ok\":true,\"items\":[{\"ap_id\":\"ap-1\",\"name\":\"Living AP\","
"\"online\":true,\"stale\":false,\"runtime\":{\"available\":true,"
"\"snapshot\":{\"fresh\":true,\"complete\":false,"
"\"radios\":[{\"id\":\"phy1\",\"band\":\"2.4GHz\",\"channel\":10}],"
"\"ssids\":[],\"stations\":[],"
"\"sources\":{\"hostapd\":{\"available\":false,\"complete\":false,"
"\"reason\":\"per_interface_control_unavailable\"}}}}}]}";

static void airtime_falls_back_to_managed(void)
{
    struct json_object *local = parse(local_no_phy);
    struct json_object *ac = parse(managed_with_airtime);
    struct json_object *data = webd_wifi_aggregate_data(local, ac, 1);
    struct json_object *summary = child(data, "summary");
    double utilization;

    /* Mean of 30 / 12 / 6 is 16. Null here was the defect. */
    assert(!is_null(summary, "avg_utilization"));
    utilization = json_object_get_double(child(summary, "avg_utilization"));
    assert(utilization > 15.9 && utilization < 16.1);

    /* Mean of 4 / 2 / 0 is 2. */
    assert(!is_null(summary, "avg_retry_rate"));
    assert(json_object_get_double(child(summary, "avg_retry_rate")) > 1.9);
    assert(json_object_get_double(child(summary, "avg_retry_rate")) < 2.1);

    /* Worst noise is the noisiest floor, the least negative: -90, not -99. */
    assert(!is_null(summary, "worst_noise"));
    assert(json_object_get_double(child(summary, "worst_noise")) > -90.5);
    assert(json_object_get_double(child(summary, "worst_noise")) < -89.5);

    /* The stale local reason must be gone, and the source named. */
    assert(strcmp(text(summary, "airtime_reason"),
                  "local_survey_source_unavailable") != 0);
    assert(!strcmp(text(summary, "airtime_reason"), "available"));
    assert(!strcmp(text(summary, "airtime_source"), "managed_ap_radios"));
    assert(json_object_get_int(child(summary, "airtime_radio_samples")) == 3);

    /*
     * With no associated station there is no signal to average. Null is the
     * honest value; 0 dBm would be a fabricated reading.
     */
    assert(is_null(summary, "avg_signal"));

    /* Local-only counts get explicit names so they stop contradicting
     * radio_count, and the bare names are labelled with their scope. */
    assert(json_object_get_int(child(summary, "radio_count")) == 3);
    assert(json_object_get_int(child(summary, "local_phy_count")) == 0);
    assert(json_object_get_int(child(summary, "local_interface_count")) == 0);
    assert(!strcmp(text(summary, "phy_count_scope"), "local_only"));
    assert(!strcmp(text(summary, "interface_count_scope"), "local_only"));

    json_object_put(data);
    json_object_put(ac);
    json_object_put(local);
}

static void no_samples_reports_what_was_tried(void)
{
    struct json_object *local = parse(local_no_phy);
    struct json_object *ac = parse(managed_station_source_down);
    struct json_object *data = webd_wifi_aggregate_data(local, ac, 1);
    struct json_object *summary = child(data, "summary");

    /* Nothing sampled anywhere, so the aggregates stay null -- but the reason
     * must not blame a local survey on a box that has no radio to survey. */
    assert(is_null(summary, "avg_utilization"));
    assert(is_null(summary, "worst_noise"));
    assert(strcmp(text(summary, "airtime_reason"),
                  "local_survey_source_unavailable") != 0);
    assert(is_null(summary, "airtime_source"));
    assert(json_object_get_int(child(summary, "airtime_radio_samples")) == 0);

    json_object_put(data);
    json_object_put(ac);
    json_object_put(local);
}

static void station_reason_names_its_owner(void)
{
    struct json_object *local = parse(local_no_phy);
    struct json_object *ac = parse(managed_station_source_down);
    struct json_object *data = webd_wifi_aggregate_data(local, ac, 1);
    struct json_object *summary = child(data, "summary");
    struct json_object *capabilities = child(data, "capabilities");
    struct json_object *scopes = child(capabilities, "reason_scopes");

    /*
     * The station source that failed is the AP's. Attributing it to the local
     * side told the user "control unavailable" about a router that has no
     * wireless control channel to begin with.
     */
    assert(!strcmp(text(scopes, "station_inventory"), "managed_ap"));
    assert(!strcmp(text(summary, "station_count_reason_scope"), "managed_ap"));
    assert(is_null(summary, "station_count"));

    json_object_put(data);
    json_object_put(ac);
    json_object_put(local);
}

static void local_only_deployment_keeps_local_scope(void)
{
    /* A router that does have radios must still report local failures as
     * local; the fix above must not relabel everything as managed. */
    static const char *local_with_phy =
    "{\"code\":2000,\"data\":{\"capabilities\":{\"wifi\":true,"
    "\"station_inventory\":false,"
    "\"reasons\":{\"station_inventory\":\"control_sockets_unavailable\"}},"
    "\"radios\":[{\"id\":\"phy0\",\"band\":\"5g\"}],"
    "\"runtime_radios\":[{\"id\":\"phy0\",\"band\":\"5g\"}],"
    "\"ssids\":[{\"id\":\"wlan0\",\"name\":\"L\"}],\"stations\":[],"
    "\"runtime\":{\"available\":true,\"complete\":true,"
    "\"reason\":\"available\"}}}";
    struct json_object *local = parse(local_with_phy);
    struct json_object *data = webd_wifi_aggregate_data(local, NULL, 1);
    struct json_object *capabilities = child(data, "capabilities");
    struct json_object *scopes = child(capabilities, "reason_scopes");

    assert(!strcmp(text(scopes, "station_inventory"), "local"));

    json_object_put(data);
    json_object_put(local);
}

static void local_reason_never_explains_a_missing_local_radio(void)
{
    /*
     * The narrow case the override exists for: no local radio at all, yet the
     * local capabilities carry a hostapd reason. Publishing that string as the
     * summary's answer is what showed the user "per-interface control
     * unavailable" on a router with no wireless hardware. There is no managed
     * AP here either, so nothing else can supply a reason -- it must still not
     * be the local hostapd one.
     */
    static const char *local_no_phy_with_hostapd_reason =
    "{\"code\":2000,\"data\":{\"capabilities\":{\"wifi\":false,"
    "\"station_inventory\":false,"
    "\"reasons\":{\"station_inventory\":"
    "\"per_interface_control_unavailable\"}},"
    "\"radios\":[],\"runtime_radios\":[],\"ssids\":[],\"stations\":[],"
    "\"runtime\":{\"available\":false,\"complete\":false,"
    "\"reason\":\"no_phy_detected\"}}}";
    struct json_object *local = parse(local_no_phy_with_hostapd_reason);
    struct json_object *data = webd_wifi_aggregate_data(local, NULL, 1);
    struct json_object *summary = child(data, "summary");
    struct json_object *capabilities = child(data, "capabilities");
    struct json_object *scopes = child(capabilities, "reason_scopes");

    assert(strcmp(text(summary, "station_count_reason"),
                  "per_interface_control_unavailable") != 0);
    assert(strcmp(text(scopes, "station_inventory"), "local") != 0);

    json_object_put(data);
    json_object_put(local);
}

int main(void)
{
    airtime_falls_back_to_managed();
    no_samples_reports_what_was_tried();
    station_reason_names_its_owner();
    local_only_deployment_keeps_local_scope();
    local_reason_never_explains_a_missing_local_radio();
    printf("ok: wifi summary managed-AP airtime fallback and reason scoping\n");
    return 0;
}
'''


def json_c_flags() -> list[str]:
    result = subprocess.run(
        ["pkg-config", "--cflags", "--libs", "json-c"], text=True,
        capture_output=True, check=True,
    )
    return shlex.split(result.stdout)


def main() -> None:
    flags = json_c_flags()
    with tempfile.TemporaryDirectory(prefix="wifi-summary-fallback-") as tmp:
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

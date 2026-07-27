#!/usr/bin/env python3
"""Executable local/managed/mixed Wi-Fi aggregation contracts."""

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
        fprintf(stderr, "missing JSON key: %s in %s\n", key,
                obj ? json_object_to_json_string_ext(
                    obj, JSON_C_TO_STRING_PLAIN) : "null");
        abort();
    }
    return value;
}

static int boolean(struct json_object *obj, const char *key)
{
    return json_object_get_boolean(child(obj, key));
}

static long count(struct json_object *obj, const char *key)
{
    return (long)json_object_array_length(child(obj, key));
}

static const char *string(struct json_object *obj, const char *key)
{
    return json_object_get_string(child(obj, key));
}

static int is_null(struct json_object *obj, const char *key)
{
    struct json_object *value = (struct json_object *)0x1;

    return obj && json_object_object_get_ex(obj, key, &value) &&
           (!value || json_object_is_type(value, json_type_null));
}

static void assert_ids(struct json_object *data, const char *key,
                       const char *first, const char *second)
{
    struct json_object *items = child(data, key);
    assert(json_object_array_length(items) == (second ? 2U : 1U));
    assert(!strcmp(string(json_object_array_get_idx(items, 0), "id"), first));
    if (second)
        assert(!strcmp(string(json_object_array_get_idx(items, 1), "id"), second));
}

static const char *local_config =
    "{\"code\":2000,\"data\":{\"contract_version\":\"wifi-management.v1\","
    "\"capabilities\":{\"wifi\":true,\"save_config\":false,\"apply_config\":false},"
    "\"radios\":[{\"id\":\"phy0\",\"band\":\"5g\",\"enabled\":true}],"
    "\"ssids\":[{\"id\":\"main\",\"name\":\"Local WiFi\",\"enabled\":true}]}}";

static const char *local_status =
    "{\"code\":2000,\"data\":{\"capabilities\":{},"
    "\"radios\":[{\"id\":\"phy0\",\"band\":\"5g\",\"enabled\":true}],"
    "\"runtime_radios\":[{\"id\":\"phy0\",\"band\":\"5g\",\"enabled\":true}],"
    "\"ssids\":[{\"id\":\"wlan0\",\"name\":\"Local WiFi\",\"enabled\":true}],"
    "\"stations\":[],\"runtime\":{\"available\":true,\"complete\":true,\"reason\":\"available\"}}}";

static const char *empty_local =
    "{\"code\":2000,\"data\":{\"capabilities\":{\"wifi\":false},"
    "\"radios\":[],\"runtime_radios\":[],\"ssids\":[],\"stations\":[],"
    "\"runtime\":{\"available\":false,\"complete\":false,\"reason\":\"no_phy_detected\"}}}";

static const char *online_ap =
    "{\"ok\":true,\"items\":[{\"ap_id\":\"ap-1\",\"name\":\"Living AP\","
    "\"reported_model\":\"Xiaomi Router BE10000 (Wi-Fi 7)\",\"model_source\":\"ubus_system_board\","
    "\"online\":true,\"stale\":false,\"adoption_state\":\"adopted\","
    "\"control_protocol\":\"ap-control.v2\",\"control_protocol_version\":2,"
    "\"session_connected\":true,\"scan_execution\":true,"
    "\"runtime\":{\"available\":true,\"complete\":false,\"stale\":false,"
    "\"snapshot\":{\"observed_at\":123,\"complete\":false,\"reason\":\"partial_runtime_sources\","
    "\"system\":{\"source\":\"apd_local_readonly\",\"uptime_seconds\":90061,"
    "\"uptime_source\":\"proc_uptime\",\"firmware_version\":\"QWRT 19.07-based\","
    "\"firmware_source\":\"etc_openwrt_release\",\"management_interface\":\"br-lan\","
    "\"mac\":\"aa:bb:cc:dd:ee:ff\",\"ip\":null,\"ip_reason\":\"interface_ipv4_unavailable\"},"
    "\"radios\":[{\"id\":\"phy0\",\"enabled\":true},{\"id\":\"phy1\",\"band\":\"5GHz\",\"channel\":149,\"width_mhz\":160,\"enabled\":true,"
    "\"channel_catalog\":{\"source\":\"iw_phy\",\"complete\":true,\"regdomain\":\"CN\","
    "\"channels\":[{\"channel\":149,\"frequency_mhz\":5745,\"disabled\":false,\"no_ir\":false,"
    "\"radar_detection\":false}]}}],"
    "\"ssids\":[{\"id\":\"wlan5\",\"radio_id\":\"phy1\",\"broadcast_name\":\"Remote WiFi\",\"band\":\"5GHz\",\"enabled\":true}],"
    "\"stations\":[{\"mac\":\"00:11:22:33:44:55\",\"interface\":\"wlan5\",\"radio_id\":\"phy1\",\"signal_dbm\":-51,\"enabled\":true}],"
    "\"sources\":{\"hostapd\":{\"available\":true,\"complete\":true,\"reason\":\"available\"}},"
    "\"desired\":{\"radios\":[{\"id\":\"radio1\",\"band\":\"5g\",\"enabled\":true}],"
    "\"ssids\":[{\"id\":\"cfg5\",\"radio_id\":\"radio1\",\"broadcast_name\":\"Remote WiFi\",\"enabled\":true}]}}}}]}";

static const char *stale_ap =
    "{\"ok\":true,\"items\":[{\"ap_id\":\"ap-1\",\"name\":\"Living AP\","
    "\"online\":false,\"stale\":true,\"runtime\":{\"available\":true,\"stale\":true,"
    "\"snapshot\":{\"complete\":true,\"radios\":[{\"id\":\"phy1\",\"band\":\"5g\",\"channel\":149,\"enabled\":true}],"
    "\"ssids\":[],\"stations\":[{\"mac\":\"00:11:22:33:44:99\",\"radio_id\":\"phy1\"}],"
    "\"sources\":{\"hostapd\":{\"available\":true,\"complete\":true,\"reason\":\"available\"}},"
    "\"desired\":{\"radios\":[],\"ssids\":[]}}}}]}";

static const char *partial_station_ap =
    "{\"ok\":true,\"items\":[{\"ap_id\":\"ap-3\",\"name\":\"Partial AP\","
    "\"online\":true,\"stale\":false,\"runtime\":{\"available\":true,"
    "\"snapshot\":{\"complete\":false,\"radios\":[{\"id\":\"phy1\",\"band\":\"5g\"}],"
    "\"ssids\":[],\"stations\":[{\"mac\":\"00:11:22:33:44:77\",\"radio_id\":\"phy1\"}],"
    "\"sources\":{\"hostapd\":{\"available\":true,\"complete\":false,"
    "\"reason\":\"hostapd_station_count_mismatch\"}}}}}]}";

static const char *unavailable_station_ap =
    "{\"ok\":true,\"items\":[{\"ap_id\":\"ap-2\",\"name\":\"\","
    "\"reported_model\":\"Xiaomi Router BE10000 (Wi-Fi 7)\","
    "\"online\":true,\"stale\":false,\"runtime\":{\"available\":true,"
    "\"snapshot\":{\"complete\":false,\"reason\":\"partial_runtime_sources\","
    "\"radios\":[{\"id\":\"phy1\",\"band\":\"2.4GHz\",\"channel\":10,"
    "\"interfaces\":[{\"txpower_dbm\":28}]}],\"ssids\":[],\"stations\":[],"
    "\"sources\":{\"hostapd\":{\"available\":false,\"complete\":false,"
    "\"reason\":\"per_interface_control_unavailable\"}}}}}]}";

static const char *survey_ap =
    "{\"ok\":true,\"items\":[{\"ap_id\":\"ap-4\",\"name\":\"Survey AP\","
    "\"online\":true,\"stale\":false,\"runtime\":{\"available\":true,"
    "\"snapshot\":{\"complete\":true,\"radios\":[{\"id\":\"phy1\","
    "\"band\":\"5g\",\"channel\":149,\"survey\":{\"source\":\"iw_survey\","
    "\"sample_time\":1234,\"complete\":true,\"stale\":false,"
    "\"frequency_mhz\":5745,\"utilization_pct\":12.5,"
    "\"channel_busy_time_ms\":100,\"channel_active_time_ms\":800}}],"
    "\"ssids\":[],\"stations\":[],\"sources\":{\"hostapd\":{"
    "\"available\":false,\"complete\":false,"
    "\"reason\":\"per_interface_control_unavailable\"}}}}}]}";

static int resolve_image(const char *model, char *url, size_t url_len,
                         char *matched, size_t matched_len)
{
    if (strcmp(model, "Xiaomi Router BE10000"))
        return -1;
    snprintf(url, url_len,
             "/luci-static/dreamingwrt/fingerprint/images/engine-9000/9000007/257x257.png");
    snprintf(matched, matched_len, "Xiaomi Router BE10000");
    return 0;
}

static void local_only(void)
{
    struct json_object *local = parse(local_config);
    struct json_object *data = webd_wifi_aggregate_data(local, NULL, 0);
    assert(!strcmp(string(data, "contract_version"), "wifi-management.v2"));
    assert_ids(data, "radios", "local:radio:phy0", NULL);
    assert_ids(data, "ssids", "local:ssid:main", NULL);
    assert(boolean(child(data, "capabilities"), "wifi"));
    assert(!boolean(child(data, "managed_aps"), "available"));
    json_object_put(data);
    json_object_put(local);
}

static void ap_only(void)
{
    struct json_object *local = parse(empty_local);
    struct json_object *ac = parse(online_ap);
    struct json_object *data = webd_wifi_aggregate_data_with_resolver(
        local, ac, 1, resolve_image);
    struct json_object *radio;
    struct json_object *ssid;
    assert(count(data, "radios") == 1); /* MLD pseudo-PHY is diagnostic only. */
    assert_ids(data, "radios", "ap:ap-1:radio:phy1", NULL);
    assert_ids(data, "ssids", "ap:ap-1:ssid:wlan5", NULL);
    assert_ids(data, "stations", "ap:ap-1:station:00:11:22:33:44:55@wlan5", NULL);
    radio = json_object_array_get_idx(child(data, "radios"), 0);
    ssid = json_object_array_get_idx(child(data, "ssids"), 0);
    assert(!strcmp(string(radio, "ap_name"), "Living AP"));
    assert(!strcmp(string(radio, "model"), "Xiaomi Router BE10000 (Wi-Fi 7)"));
    assert(!strcmp(string(radio, "image_source"), "fingerprint_model_catalog"));
    assert(!strcmp(string(radio, "image_model_match"), "Xiaomi Router BE10000"));
    assert(!strcmp(string(ssid, "name"), "Remote WiFi"));
    assert(!strcmp(string(ssid, "radio_id"), "ap:ap-1:radio:phy1"));
    assert(boolean(child(data, "runtime"), "available"));
    assert(boolean(child(data, "capabilities"), "remote_telemetry"));
    assert(boolean(child(data, "capabilities"), "station_inventory"));
    assert(boolean(child(data, "capabilities"), "station_metrics"));
    assert(boolean(child(data, "capabilities"), "ap_radio_mapping"));
    assert(boolean(child(data, "capabilities"), "wifi"));
    assert(webd_wifi_managed_available(ac));
    assert(json_object_get_int(child(child(data, "managed_aps"), "online")) == 1);
    {
        struct json_object *ap = json_object_array_get_idx(
            child(child(data, "managed_aps"), "items"), 0);
        assert(!strcmp(string(ap, "control_protocol"), "ap-control.v2"));
        assert(json_object_get_int(child(ap, "control_protocol_version")) == 2);
        assert(boolean(ap, "session_connected"));
        assert(boolean(ap, "scan_execution"));
        /* AP-details facts pass through only with APD evidence; missing
         * evidence stays null with the APD reason. */
        assert(json_object_get_int64(child(ap, "uptime_seconds")) == 90061);
        assert(!strcmp(string(ap, "firmware_version"), "QWRT 19.07-based"));
        assert(!strcmp(string(ap, "mac"), "aa:bb:cc:dd:ee:ff"));
        assert(is_null(ap, "ip"));
        assert(!strcmp(string(ap, "ip_reason"), "interface_ipv4_unavailable"));
    }
    {
        /* The iw-phy channel catalog rides through per radio and flips
         * only the read-only channel_catalog capability. */
        struct json_object *catalog = child(radio, "channel_catalog");
        assert(boolean(catalog, "complete"));
        assert(!strcmp(string(catalog, "regdomain"), "CN"));
        assert(count(catalog, "channels") == 1);
        assert(boolean(child(data, "capabilities"), "channel_catalog"));
        assert(!boolean(child(data, "capabilities"), "channel_plan"));
        assert(!strcmp(string(child(child(data, "capabilities"), "reasons"),
                              "channel_catalog"), "iw_phy_channel_catalog"));
    }
    json_object_put(data);
    json_object_put(ac);
    json_object_put(local);
}

static void station_events_capability_flip(void)
{
    struct json_object *local = parse(empty_local);
    struct json_object *ac = parse(online_ap);
    struct json_object *with_store = parse(
        "{\"ok\":true,\"capabilities\":{\"station_event_store\":true}}");
    struct json_object *without_store = parse(
        "{\"ok\":true,\"capabilities\":{\"remote_telemetry\":true}}");
    struct json_object *data = webd_wifi_aggregate_data(local, ac, 1);
    struct json_object *capabilities = child(data, "capabilities");

    /* Default stays fail-closed with the pending reason. */
    assert(!boolean(capabilities, "connectivity_events"));
    assert(!boolean(capabilities, "roaming_history"));
    webd_wifi_merge_station_events_capability(data, without_store);
    assert(!boolean(capabilities, "connectivity_events"));
    assert(!strcmp(string(child(capabilities, "reasons"),
                          "connectivity_events"),
                   "wifi_connectivity_event_store_pending"));
    /* The AC-declared bounded store flips it with an explicit source. */
    webd_wifi_merge_station_events_capability(data, with_store);
    assert(boolean(capabilities, "connectivity_events"));
    assert(boolean(capabilities, "roaming_history"));
    assert(!strcmp(string(capabilities, "connectivity_events_source"),
                   "ac_snapshot_diff"));
    assert(!strcmp(string(capabilities, "connectivity_events_endpoint"),
                   "/api/v1/wifi/connectivity/events"));
    assert(!strcmp(string(child(capabilities, "reasons"),
                          "connectivity_events"), "available"));
    assert(!strcmp(string(child(capabilities, "reasons"),
                          "roaming_history"), "available"));
    json_object_put(data);
    json_object_put(with_store);
    json_object_put(without_store);
    json_object_put(ac);
    json_object_put(local);
}

static void managed_capability_status_contract(void)
{
    struct json_object *present = parse(
        "{\"ok\":true,\"managed_aps\":{\"available\":true,\"count\":1,\"online\":1}}");
    struct json_object *offline = parse(
        "{\"ok\":true,\"managed_aps\":{\"available\":false,\"count\":1,\"online\":0}}");
    struct json_object *empty = parse(
        "{\"ok\":true,\"managed_aps\":{\"available\":false,\"count\":0,\"online\":0}}");
    struct json_object *failed = parse("{\"ok\":false,\"error\":\"source_unavailable\"}");

    assert(webd_wifi_managed_available(present));
    assert(webd_wifi_managed_available(offline));
    assert(!webd_wifi_managed_available(empty));
    assert(!webd_wifi_managed_available(failed));
    json_object_put(failed);
    json_object_put(empty);
    json_object_put(offline);
    json_object_put(present);
}

static void local_source_failure_does_not_poison_ap_only(void)
{
    struct json_object *local = parse(
        "{\"code\":4000,\"data\":{\"ok\":false,\"error\":\"source_unavailable\"}}");
    struct json_object *ac = parse(online_ap);
    struct json_object *data = webd_wifi_aggregate_data(local, ac, 1);
    struct json_object *ignored = NULL;
    assert(!json_object_object_get_ex(data, "ok", &ignored));
    assert(!json_object_object_get_ex(data, "error", &ignored));
    assert_ids(data, "radios", "ap:ap-1:radio:phy1", NULL);
    assert(!boolean(child(data, "local_wifi"), "source_available"));
    assert(boolean(child(data, "runtime"), "available"));
    json_object_put(data);
    json_object_put(ac);
    json_object_put(local);
}

static void mixed_and_duplicate_ids(void)
{
    struct json_object *local = parse(local_status);
    struct json_object *ac = parse(online_ap);
    struct json_object *data = webd_wifi_aggregate_data(local, ac, 1);
    assert_ids(data, "radios", "local:radio:phy0", "ap:ap-1:radio:phy1");
    assert(boolean(child(data, "capabilities"), "mixed_source"));
    assert(json_object_get_int(child(child(data, "summary"), "radio_count")) == 2);
    json_object_put(data);
    json_object_put(ac);
    json_object_put(local);
}

static void ac_unavailable_preserves_local(void)
{
    struct json_object *local = parse(local_status);
    struct json_object *ac = parse("{\"ok\":false,\"error\":\"source_unavailable\"}");
    struct json_object *data = webd_wifi_aggregate_data(local, ac, 1);
    assert_ids(data, "radios", "local:radio:phy0", NULL);
    assert(boolean(child(data, "runtime"), "available"));
    assert(!boolean(child(data, "managed_aps"), "available"));
    json_object_put(data);
    json_object_put(ac);
    json_object_put(local);
}

static void stale_ap_is_not_live_runtime(void)
{
    struct json_object *local = parse(empty_local);
    struct json_object *ac = parse(stale_ap);
    struct json_object *data = webd_wifi_aggregate_data(local, ac, 1);
    struct json_object *radio = json_object_array_get_idx(child(data, "radios"), 0);
    assert(!boolean(radio, "online"));
    assert(boolean(radio, "stale"));
    assert(!boolean(radio, "enabled"));
    assert(boolean(radio, "configured_enabled"));
    assert(!boolean(child(data, "runtime"), "available"));
    assert(!boolean(child(data, "capabilities"), "runtime_status"));
    assert(count(data, "stations") == 0);
    assert(is_null(child(data, "summary"), "station_count"));
    assert(!strcmp(string(child(child(data, "capabilities"), "reasons"),
                          "station_inventory"), "telemetry_stale"));
    assert(!strcmp(string(child(data, "summary"), "station_count_reason"),
                   "telemetry_stale"));
    {
        /* Pre-system-facts APD builds omit snapshot.system entirely; the
         * AP summary must stay null with an explicit reason. */
        struct json_object *ap = json_object_array_get_idx(
            child(child(data, "managed_aps"), "items"), 0);
        assert(is_null(ap, "ip") && is_null(ap, "mac"));
        assert(is_null(ap, "firmware_version") && is_null(ap, "uptime_seconds"));
        assert(!strcmp(string(ap, "ip_reason"), "ap_system_facts_not_reported"));
        assert(!strcmp(string(ap, "uptime_reason"),
                       "ap_system_facts_not_reported"));
    }
    json_object_put(data);
    json_object_put(ac);
    json_object_put(local);
}

static void partial_station_source_is_not_authoritative(void)
{
    struct json_object *local = parse(empty_local);
    struct json_object *ac = parse(partial_station_ap);
    struct json_object *data = webd_wifi_aggregate_data(local, ac, 1);
    struct json_object *capabilities = child(data, "capabilities");
    struct json_object *reasons = child(capabilities, "reasons");

    assert(!boolean(capabilities, "station_inventory"));
    assert(!boolean(capabilities, "station_metrics"));
    assert(!strcmp(string(reasons, "station_inventory"),
                   "hostapd_station_count_mismatch"));
    assert(!strcmp(string(reasons, "station_metrics"),
                   "hostapd_station_count_mismatch"));
    assert(count(data, "stations") == 0);
    assert(is_null(child(data, "summary"), "station_count"));
    json_object_put(data);
    json_object_put(ac);
    json_object_put(local);
}

static void config_uses_desired_and_disables_writes(void)
{
    struct json_object *local = parse(empty_local);
    struct json_object *ac = parse(online_ap);
    struct json_object *data = webd_wifi_aggregate_data(local, ac, 0);
    struct json_object *radio = json_object_array_get_idx(child(data, "radios"), 0);
    struct json_object *ssid = json_object_array_get_idx(child(data, "ssids"), 0);
    assert(!strcmp(string(radio, "id"), "ap:ap-1:radio:radio1"));
    assert(!strcmp(string(ssid, "id"), "ap:ap-1:ssid:cfg5"));
    assert(!strcmp(string(ssid, "configuration_source"), "apd_desired_read_only"));
    assert(!boolean(child(data, "capabilities"), "save_config"));
    assert(!boolean(child(data, "capabilities"), "apply_config"));
    json_object_put(data);
    json_object_put(ac);
    json_object_put(local);
}

static void unavailable_station_source_is_not_zero_clients(void)
{
    struct json_object *local = parse(empty_local);
    struct json_object *ac = parse(unavailable_station_ap);
    struct json_object *data = webd_wifi_aggregate_data_with_resolver(
        local, ac, 1, resolve_image);
    struct json_object *capabilities = child(data, "capabilities");
    struct json_object *radio = json_object_array_get_idx(child(data, "radios"), 0);
    struct json_object *summary = child(data, "summary");
    struct json_object *ap = json_object_array_get_idx(
        child(child(data, "managed_aps"), "items"), 0);

    assert(!boolean(capabilities, "station_inventory"));
    assert(!boolean(capabilities, "station_metrics"));
    assert(is_null(radio, "clients"));
    assert(!strcmp(string(radio, "clients_reason"),
                   "per_interface_control_unavailable"));
    assert(is_null(summary, "station_count"));
    assert(!strcmp(string(ap, "name"), "Xiaomi Router BE10000 (Wi-Fi 7)"));
    assert(!strcmp(string(ap, "name_source"), "model_fallback"));
    assert(!strcmp(string(ap, "image_model_match"), "Xiaomi Router BE10000"));
    assert(json_object_get_double(child(radio, "tx_power_dbm")) == 28.0);
    assert(is_null(radio, "supported_channels"));
    json_object_put(data);
    json_object_put(ac);
    json_object_put(local);
}

static void survey_is_exposed_without_being_fft_or_neighbor_scan(void)
{
    struct json_object *local = parse(empty_local);
    struct json_object *ac = parse(survey_ap);
    struct json_object *data = webd_wifi_aggregate_data(local, ac, 1);
    struct json_object *environment = child(data, "environment");
    struct json_object *channel = child(environment, "channel_survey");
    struct json_object *capabilities = child(data, "capabilities");
    struct json_object *reasons = child(capabilities, "reasons");
    struct json_object *radio = json_object_array_get_idx(child(data, "radios"), 0);

    assert(boolean(capabilities, "channel_survey"));
    assert(!boolean(capabilities, "survey_history"));
    assert(!boolean(capabilities, "neighbor_scan"));
    assert(!boolean(capabilities, "spectral_fft"));
    assert(count(channel, "samples") == 1);
    assert(json_object_get_int(child(channel, "sample_count")) == 1);
    assert(json_object_get_double(child(radio, "channel_utilization_pct")) == 12.5);
    assert(!strcmp(string(radio, "channel_utilization_source"), "iw_survey"));
    assert(!strcmp(string(reasons, "neighbor_scan"),
                   "neighbor_bssid_scan_producer_pending"));
    assert(!strcmp(string(reasons, "spectral_fft"),
                   "spectral_fft_driver_producer_pending"));
    json_object_put(data);
    json_object_put(ac);
    json_object_put(local);
}

static void managed_neighbor_scan_merges_with_stable_radio_ids(void)
{
    struct json_object *local = parse(empty_local);
    struct json_object *ac = parse(online_ap);
    struct json_object *data = webd_wifi_aggregate_data(local, ac, 1);
    struct json_object *results = parse(
        "{\"ok\":true,\"samples\":[{\"job_id\":\"job-1\","
        "\"ap_id\":\"ap-1\",\"radio_id\":\"phy1\",\"sample_time\":99,"
        "\"item_count\":1,\"complete\":false,\"truncated\":true,"
        "\"items\":[{\"bssid\":\"02:00:00:00:00:01\",\"rssi_dbm\":-50}]}]}"
    );
    struct json_object *ac_capabilities = parse(
        "{\"ok\":true,\"capabilities\":{\"scan_job_control_plane\":true,"
        "\"scan_dispatch\":true,\"scan_execution\":true}}"
    );
    struct json_object *environment;
    struct json_object *neighbor;
    struct json_object *sample;
    struct json_object *capabilities;
    struct json_object *interference;
    struct json_object *row;

    webd_wifi_merge_environment_scan(data, results, ac_capabilities);
    environment = child(data, "environment");
    neighbor = child(environment, "neighbor_scan");
    capabilities = child(data, "capabilities");
    assert(boolean(neighbor, "supported"));
    assert(json_object_get_int(child(neighbor, "sample_count")) == 1);
    assert(!boolean(neighbor, "complete"));
    assert(!strcmp(string(neighbor, "reason"),
                   "available_with_truncated_samples"));
    assert(boolean(capabilities, "neighbor_scan"));
    assert(boolean(capabilities, "environment_scan"));
    assert(boolean(capabilities, "airview_realtime"));
    assert(boolean(capabilities, "scan_jobs"));
    assert(boolean(capabilities, "scan_dispatch"));
    assert(boolean(capabilities, "scan_execution"));
    assert(!strcmp(string(capabilities, "airview_mode"),
                   "latest_neighbor_scan"));
    sample = json_object_array_get_idx(child(neighbor, "samples"), 0);
    assert(!strcmp(string(sample, "radio_id"), "ap:ap-1:radio:phy1"));
    assert(!strcmp(string(sample, "local_radio_id"), "phy1"));
    assert(!strcmp(string(sample, "source"), "dreamingwrt-ac.radio_job"));
    assert(boolean(sample, "truncated"));
    interference = child(data, "interference");
    assert(json_object_array_length(interference) == 1);
    row = json_object_array_get_idx(interference, 0);
    assert(!strcmp(string(row, "radio_id"), "ap:ap-1:radio:phy1"));
    assert(!strcmp(string(row, "local_radio_id"), "phy1"));
    assert(!strcmp(string(row, "bssid"), "02:00:00:00:00:01"));
    assert(json_object_get_double(child(row, "signal")) == -50.0);
    assert(!strcmp(string(row, "source_mode"), "latest_neighbor_scan"));
    assert(boolean(row, "sample_truncated"));

    json_object_put(ac_capabilities);
    json_object_put(results);
    json_object_put(data);
    json_object_put(ac);
    json_object_put(local);
}

static void managed_neighbor_scan_empty_state_is_truthful(void)
{
    struct json_object *local = parse(empty_local);
    struct json_object *ac = parse(online_ap);
    struct json_object *data = webd_wifi_aggregate_data(local, ac, 1);
    struct json_object *results = parse("{\"ok\":true,\"samples\":[]}");
    struct json_object *ac_capabilities = parse(
        "{\"ok\":true,\"capabilities\":{\"scan_job_control_plane\":true,"
        "\"scan_dispatch\":true,\"scan_execution\":true}}"
    );
    struct json_object *neighbor;
    struct json_object *capabilities;
    struct json_object *reasons;

    webd_wifi_merge_environment_scan(data, results, ac_capabilities);
    neighbor = child(child(data, "environment"), "neighbor_scan");
    capabilities = child(data, "capabilities");
    reasons = child(capabilities, "reasons");
    assert(boolean(neighbor, "supported"));
    assert(boolean(neighbor, "execution_available"));
    assert(!boolean(neighbor, "sample_available"));
    assert(!boolean(neighbor, "complete"));
    assert(json_object_get_int(child(neighbor, "sample_count")) == 0);
    assert(!strcmp(string(neighbor, "reason"), "scan_not_yet_run"));
    assert(boolean(capabilities, "scan_jobs"));
    assert(boolean(capabilities, "scan_dispatch"));
    assert(boolean(capabilities, "scan_execution"));
    assert(!boolean(capabilities, "neighbor_scan"));
    assert(!boolean(capabilities, "environment_scan"));
    assert(!boolean(capabilities, "airview_realtime"));
    assert(!strcmp(string(capabilities, "airview_mode"), "unavailable"));
    assert(!strcmp(string(reasons, "neighbor_scan"), "scan_not_yet_run"));
    assert(!strcmp(string(reasons, "airview_realtime"), "scan_not_yet_run"));

    json_object_put(ac_capabilities);
    json_object_put(results);
    json_object_put(data);
    json_object_put(ac);
    json_object_put(local);
}

static void survey_history_maps_and_sorts_namespaced_radios(void)
{
    struct json_object *local = parse(empty_local);
    struct json_object *ac = parse(survey_ap);
    struct json_object *data = webd_wifi_aggregate_data(local, ac, 1);
    struct json_object *response = parse(
        "{\"ok\":true,\"points\":["
        "{\"sample_id\":3,\"ap_id\":\"ap-4\",\"radio_id\":\"phy1\","
        "\"timestamp\":300,\"value\":30.0,\"utilization_pct\":30.0,"
        "\"complete\":true,\"source\":\"ac.survey_history\"},"
        "{\"sample_id\":1,\"ap_id\":\"ap-4\",\"radio_id\":\"phy1\","
        "\"timestamp\":100,\"value\":10.0,\"utilization_pct\":10.0,"
        "\"complete\":true,\"source\":\"ac.survey_history\"},"
        "{\"sample_id\":2,\"ap_id\":\"ap-4\",\"radio_id\":\"phy1\","
        "\"timestamp\":200,\"value\":20.0,\"utilization_pct\":20.0,"
        "\"complete\":false,\"source\":\"ac.survey_history\"},"
        "{\"sample_id\":4,\"ap_id\":\"other-ap\",\"radio_id\":\"phy1\","
        "\"timestamp\":400,\"value\":40.0,\"utilization_pct\":40.0,"
        "\"complete\":true,\"source\":\"ac.survey_history\"},"
        "{\"sample_id\":5,\"ap_id\":\"ap-4\",\"radio_id\":\"phy1\","
        "\"timestamp\":500,\"complete\":true,"
        "\"source\":\"ac.survey_history\"}"
        "] ,\"resolution_seconds\":300,\"count\":5,\"limited\":false,"
        "\"reason\":\"available\"}"
    );
    struct json_object *radio;
    struct json_object *history;
    struct json_object *capabilities;
    struct json_object *first;
    struct json_object *second;
    struct json_object *third;

    webd_wifi_merge_survey_history(data, response);
    radio = json_object_array_get_idx(child(data, "radios"), 0);
    history = child(radio, "channel_history");
    capabilities = child(data, "capabilities");
    assert(!strcmp(string(radio, "id"), "ap:ap-4:radio:phy1"));
    assert(json_object_array_length(history) == 3);
    first = json_object_array_get_idx(history, 0);
    second = json_object_array_get_idx(history, 1);
    third = json_object_array_get_idx(history, 2);
    assert(json_object_get_int64(child(first, "timestamp")) == 100);
    assert(json_object_get_int64(child(second, "timestamp")) == 200);
    assert(json_object_get_int64(child(third, "timestamp")) == 300);
    assert(json_object_get_double(child(first, "value")) == 10.0);
    assert(json_object_get_double(child(first, "utilization")) == 10.0);
    assert(!strcmp(string(first, "source"), "ac.survey_history"));
    assert(boolean(first, "complete"));
    assert(!boolean(second, "complete"));
    assert(boolean(capabilities, "survey_history"));
    assert(boolean(capabilities, "airview_history"));
    assert(!strcmp(string(child(capabilities, "reasons"), "survey_history"),
                   "available"));

    json_object_put(response);
    json_object_put(data);
    json_object_put(ac);
    json_object_put(local);
}

static void survey_history_empty_state_is_truthful(void)
{
    struct json_object *local = parse(empty_local);
    struct json_object *ac = parse(survey_ap);
    struct json_object *data = webd_wifi_aggregate_data(local, ac, 1);
    struct json_object *response = parse(
        "{\"ok\":true,\"points\":[],\"resolution_seconds\":300,"
        "\"count\":0,\"limited\":false,\"reason\":\"warming_up\"}"
    );
    struct json_object *radio;
    struct json_object *capabilities;

    webd_wifi_merge_survey_history(data, response);
    radio = json_object_array_get_idx(child(data, "radios"), 0);
    capabilities = child(data, "capabilities");
    assert(count(radio, "channel_history") == 0);
    assert(!boolean(capabilities, "survey_history"));
    assert(!boolean(capabilities, "airview_history"));
    assert(!strcmp(string(child(capabilities, "reasons"), "survey_history"),
                   "warming_up"));
    assert(!strcmp(string(child(capabilities, "reasons"), "airview_history"),
                   "warming_up"));

    json_object_put(response);
    json_object_put(data);
    json_object_put(ac);
    json_object_put(local);
}

static void survey_history_single_point_does_not_open_capability(void)
{
    struct json_object *local = parse(empty_local);
    struct json_object *ac = parse(survey_ap);
    struct json_object *data = webd_wifi_aggregate_data(local, ac, 1);
    struct json_object *response = parse(
        "{\"ok\":true,\"points\":[{\"sample_id\":1,"
        "\"ap_id\":\"ap-4\",\"radio_id\":\"phy1\",\"timestamp\":100,"
        "\"value\":12.5,\"utilization_pct\":12.5,\"complete\":true,"
        "\"source\":\"ac.survey_history\"}],\"resolution_seconds\":300,"
        "\"count\":1,\"limited\":false,\"reason\":\"available\"}"
    );
    struct json_object *radio;
    struct json_object *capabilities;

    webd_wifi_merge_survey_history(data, response);
    radio = json_object_array_get_idx(child(data, "radios"), 0);
    capabilities = child(data, "capabilities");
    assert(count(radio, "channel_history") == 1);
    assert(!boolean(capabilities, "survey_history"));
    assert(!boolean(capabilities, "airview_history"));
    assert(!strcmp(string(child(capabilities, "reasons"), "survey_history"),
                   "insufficient_complete_numeric_points"));

    json_object_put(response);
    json_object_put(data);
    json_object_put(ac);
    json_object_put(local);
}

int main(void)
{
    local_only();
    ap_only();
    managed_capability_status_contract();
    local_source_failure_does_not_poison_ap_only();
    mixed_and_duplicate_ids();
    ac_unavailable_preserves_local();
    stale_ap_is_not_live_runtime();
    station_events_capability_flip();
    partial_station_source_is_not_authoritative();
    config_uses_desired_and_disables_writes();
    unavailable_station_source_is_not_zero_clients();
    survey_is_exposed_without_being_fft_or_neighbor_scan();
    managed_neighbor_scan_merges_with_stable_radio_ids();
    managed_neighbor_scan_empty_state_is_truthful();
    survey_history_maps_and_sorts_namespaced_radios();
    survey_history_empty_state_is_truthful();
    survey_history_single_point_does_not_open_capability();
    puts("ok: local/AP/mixed Wi-Fi aggregation runtime contract");
    return 0;
}
'''


def json_c_flags() -> list[str]:
    explicit = os.environ.get("WEBD_WIFI_TEST_FLAGS", "").strip()
    if explicit:
        return shlex.split(explicit)
    candidates = [Path("/opt/homebrew/opt/json-c")]
    candidates.extend(Path("/opt/homebrew/var/homebrew/tmp/.cellar/json-c").glob("*"))
    for prefix in candidates:
        header = prefix / "include/json-c/json.h"
        static = prefix / "lib/libjson-c.a"
        dynamic = prefix / "lib/libjson-c.dylib"
        if header.is_file() and static.is_file():
            return [f"-I{prefix / 'include'}", str(static)]
        if header.is_file() and dynamic.is_file():
            return [f"-I{prefix / 'include'}", f"-L{prefix / 'lib'}", "-ljson-c"]
    output = subprocess.check_output(
        ["pkg-config", "--cflags", "--libs", "json-c"], text=True
    )
    return shlex.split(output)


def main() -> None:
    flags = json_c_flags()
    with tempfile.TemporaryDirectory(prefix="wifi-aggregate-") as raw:
        directory = Path(raw)
        source = directory / "harness.c"
        executable = directory / "harness"
        source.write_text(HARNESS, encoding="utf-8")
        subprocess.run(
            [
                os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-I", str(ROOT / "src/webd"), str(source),
                str(ROOT / "src/webd/webd_wifi_aggregate.c"), *flags,
                "-o", str(executable),
            ],
            check=True,
        )
        subprocess.run([str(executable)], check=True)


if __name__ == "__main__":
    main()

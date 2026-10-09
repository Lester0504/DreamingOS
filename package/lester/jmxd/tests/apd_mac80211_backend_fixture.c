// SPDX-License-Identifier: GPL-2.0-or-later
#define APD_MAC80211_STANDALONE_TEST 1

#include "../src/apd/apd_backend_mac80211.c"

#define FIELD(object, name) apd_mac80211_child((object), (name))

static const char network_status_json[] =
    "{"
    "\"radio0\":{\"config\":{\"type\":\"mac80211\",\"band\":\"2g\","
    "\"channel\":\"1\",\"radio\":0},\"interfaces\":["
    "{\"config\":{\"mode\":\"ap\",\"ssid\":\"OpenWrt2G\","
    "\"encryption\":\"sae+ccmp\"},\"ifname\":\"phy0.0-ap0\"},"
    "{\"config\":{\"mode\":\"ap\",\"ssid\":\"OpenWrt-MLO\","
    "\"encryption\":\"sae\",\"mlo\":true,\"radios\":[0,1,2]},"
    "\"ifname\":\"ap-mld0\"}]},"
    "\"radio1\":{\"config\":{\"type\":\"mac80211\",\"band\":\"5g\","
    "\"channel\":\"48\",\"radio\":1},\"interfaces\":["
    "{\"config\":{\"mode\":\"ap\",\"ssid\":\"OpenWrt5G\","
    "\"encryption\":\"sae+ccmp\"},\"ifname\":\"phy0.1-ap0\"},"
    "{\"config\":{\"mode\":\"ap\",\"ssid\":\"OpenWrt-MLO\","
    "\"encryption\":\"sae\",\"mlo\":true,\"radios\":[0,1,2]},"
    "\"ifname\":\"ap-mld0\"}]},"
    "\"radio2\":{\"config\":{\"type\":\"mac80211\",\"band\":\"6g\","
    "\"channel\":\"1\",\"radio\":2},\"interfaces\":["
    "{\"config\":{\"mode\":\"ap\",\"ssid\":\"OpenWrt6G\","
    "\"encryption\":\"sae+ccmp\"},\"ifname\":\"phy0.2-ap0\"},"
    "{\"config\":{\"mode\":\"ap\",\"ssid\":\"OpenWrt-MLO\","
    "\"encryption\":\"sae\",\"mlo\":true,\"radios\":[0,1,2]},"
    "\"ifname\":\"ap-mld0\"}]}"
    "}";

/* Reproduces the Acceptance-era gap: only 6 GHz carries a channel/SSID line.
 * Radios:N remains the stable per-interface radio selector. */
static const char iw_dev_text[] =
    "phy#0\n"
    "\tInterface phy0.2-ap0\n"
    "\t\taddr 00:58:28:09:22:ca\n"
    "\t\tssid OpenWrt6G\n"
    "\t\ttype AP\n"
    "\t\tchannel 1 (5955 MHz), width: 320 MHz\n"
    "\t\ttxpower 28.00 dBm\n"
    "\t\tRadios: 2\n"
    "\tInterface phy0.1-ap0\n"
    "\t\taddr 00:58:28:09:22:ba\n"
    "\t\ttype AP\n"
    "\t\ttxpower 23.00 dBm\n"
    "\t\tRadios: 1\n"
    "\tInterface phy0.0-ap0\n"
    "\t\taddr 02:58:28:09:22:aa\n"
    "\t\ttype AP\n"
    "\t\ttxpower 28.00 dBm\n"
    "\t\tRadios: 0\n"
    "\tInterface ap-mld0\n"
    "\t\taddr 00:58:28:09:22:aa\n"
    "\t\tssid OpenWrt-MLO\n"
    "\t\ttype AP\n"
    "\t\tMLD with links:\n"
    "\t\tRadios: 0 1 2\n";

static const char station_5g[] =
    "Station 02:00:00:00:00:01 (on phy0.1-ap0)\n"
    "\trx bytes:\t12000\n"
    "\ttx bytes:\t24000\n"
    "\ttx packets:\t200\n"
    "\ttx retries:\t10\n"
    "\tsignal:\t-51 [-51] dBm\n"
    "\tconnected time:\t120 seconds\n";

static const char *fixture_station(const char *interface, void *opaque)
{
    (void)opaque;
    return !strcmp(interface, "phy0.1-ap0") ? station_5g : "";
}

static struct json_object *fixture_survey(const char *radio_id, void *opaque)
{
    struct json_object *root = json_object_new_object();
    struct json_object *items = json_object_new_array();
    struct json_object *sample = json_object_new_object();
    int frequency = 0;
    int channel = 0;

    (void)opaque;
    if (!strcmp(radio_id, "phy0r0")) {
        frequency = 2412;
        channel = 1;
    } else if (!strcmp(radio_id, "phy0r1")) {
        frequency = 5220;
        channel = 44;
    } else if (!strcmp(radio_id, "phy0r2")) {
        frequency = 5955;
        channel = 1;
    }
    json_object_object_add(sample, "radio_id",
                           json_object_new_string(radio_id));
    json_object_object_add(sample, "source",
                           json_object_new_string("iw_survey"));
    json_object_object_add(sample, "complete", json_object_new_boolean(1));
    json_object_object_add(sample, "frequency_mhz",
                           json_object_new_int(frequency));
    json_object_object_add(sample, "channel", json_object_new_int(channel));
    json_object_object_add(sample, "channel_active_time_ms",
                           json_object_new_int64(1000));
    json_object_object_add(sample, "channel_busy_time_ms",
                           json_object_new_int64(100));
    json_object_array_add(items, sample);
    json_object_object_add(root, "items", items);
    return root;
}

static int fixture_hostapd(const char *interface, void *opaque)
{
    (void)opaque;
    return strcmp(interface, "phy0.0-ap0") != 0;
}

static struct json_object *object_by_id(struct json_object *array,
                                        const char *id)
{
    size_t i;

    for (i = 0; array && i < json_object_array_length(array); i++) {
        struct json_object *item = json_object_array_get_idx(array, i);
        const char *value = apd_mac80211_string(item, "id");

        if (value && !strcmp(value, id))
            return item;
    }
    return NULL;
}

static int expect_radio(struct json_object *radios, const char *id,
                        const char *band, const char *desired,
                        int channel, int frequency)
{
    struct json_object *radio = object_by_id(radios, id);

    return radio && !strcmp(apd_mac80211_string(radio, "band"), band) &&
        !strcmp(apd_mac80211_string(radio, "desired_channel"), desired) &&
        json_object_get_int(FIELD(radio, "channel")) == channel &&
        json_object_get_int(FIELD(radio, "frequency_mhz")) == frequency;
}

static int verify_station_btm(struct apd_mac80211_inputs *inputs)
{
    struct json_object *peers = json_tokener_parse(
        "[{\"mac\":\"02:00:00:00:00:01\",\"interface\":\"phy0.2-ap0\","
        "\"source\":\"hostapd_control\",\"station_btm_capable\":true,"
        "\"station_btm_reason\":\"wrong_interface\"},"
        "{\"mac\":\"02:00:00:00:00:02\",\"interface\":\"phy0.1-ap0\","
        "\"source\":\"hostapd_control\",\"station_btm_capable\":true,"
        "\"station_btm_reason\":\"wrong_station\"},"
        "{\"mac\":\"02:00:00:00:00:01\",\"interface\":\"phy0.1-ap0\","
        "\"source\":\"hostapd_control\",\"stale\":true,"
        "\"station_btm_capable\":true,\"station_btm_reason\":\"stale\"},"
        "{\"mac\":\"02:00:00:00:00:01\",\"interface\":\"phy0.1-ap0\","
        "\"source\":\"hostapd_control\",\"station_btm_capable\":true,"
        "\"station_btm_reason\":\"station_extended_capabilities_btm_supported\"}]");
    struct json_object *radios = NULL, *ssids = NULL, *stations = NULL;
    struct json_object *sources = NULL;
    struct json_object *station, *peer;
    int complete = 0;
    int rc = -1;

    inputs->hostapd_stations = peers;
    if (!peers || apd_mac80211_build_runtime(inputs, 1787572800,
            &radios, &ssids, &stations, &sources, &complete) != 0)
        goto done;
    station = json_object_array_get_idx(stations, 0);
    if (!apd_mac80211_boolean(station, "station_btm_capable") ||
        strcmp(apd_mac80211_string(station, "station_btm_reason"),
               "station_extended_capabilities_btm_supported") ||
        strcmp(apd_mac80211_string(station, "source"), "iw_station_dump") ||
        json_object_get_int64(FIELD(station, "tx_packets")) != 200 ||
        json_object_get_int64(FIELD(station, "tx_retries")) != 10 ||
        json_object_get_int(FIELD(station, "signal_dbm")) != -51)
        goto done;
    peer = json_object_array_get_idx(peers, 3);
    json_object_object_add(peer, "station_btm_capable",
                           json_object_new_boolean(0));
    json_object_object_add(peer, "station_btm_reason",
        json_object_new_string("station_extended_capabilities_btm_not_supported"));
    apd_mac80211_merge_station_btm(stations, peers);
    if (apd_mac80211_boolean(station, "station_btm_capable") ||
        strcmp(apd_mac80211_string(station, "station_btm_reason"),
               "station_extended_capabilities_btm_not_supported"))
        goto done;
    json_object_object_add(peer, "source", json_object_new_string("iw_station_dump"));
    json_object_object_add(peer, "station_btm_capable", json_object_new_boolean(1));
    apd_mac80211_merge_station_btm(stations, peers);
    if (apd_mac80211_boolean(station, "station_btm_capable"))
        goto done;
    rc = 0;
done:
    inputs->hostapd_stations = NULL;
    json_object_put(peers);
    json_object_put(radios);
    json_object_put(ssids);
    json_object_put(stations);
    json_object_put(sources);
    return rc;
}

int main(void)
{
    struct json_object *status = json_tokener_parse(network_status_json);
    struct json_object *radios = NULL;
    struct json_object *ssids = NULL;
    struct json_object *stations = NULL;
    struct json_object *sources = NULL;
    struct json_object *mlo;
    struct json_object *two;
    struct json_object *hostapd;
    struct json_object *missing;
    struct json_object *five;
    struct json_object *air;
    struct json_object *station;
    struct apd_mac80211_inputs inputs = {
        .network_status = status,
        .iw_dev = iw_dev_text,
        .station_dump = fixture_station,
        .survey = fixture_survey,
        .hostapd_present = fixture_hostapd,
    };
    int complete = 1;
    int rc = 1;

    if (!status || apd_mac80211_build_runtime(&inputs, 1787572800,
            &radios, &ssids, &stations, &sources, &complete) != 0)
        goto done;
    if (complete || json_object_array_length(radios) != 3 ||
        json_object_array_length(ssids) != 4 ||
        json_object_array_length(stations) != 1)
        goto done;
    station = json_object_array_get_idx(stations, 0);
    if (!station || json_object_get_boolean(
            FIELD(station, "station_btm_capable")) ||
        strcmp(apd_mac80211_string(station, "station_btm_reason"),
               "station_extended_capabilities_not_reported"))
        goto done;
    if (!expect_radio(radios, "phy0r0", "2g", "1", 1, 2412) ||
        !expect_radio(radios, "phy0r1", "5g", "48", 44, 5220) ||
        !expect_radio(radios, "phy0r2", "6g", "1", 1, 5955))
        goto done;
    if (!object_by_id(ssids, "phy0.0-ap0") ||
        strcmp(apd_mac80211_string(object_by_id(ssids, "phy0.0-ap0"),
                                   "broadcast_name"), "OpenWrt2G") ||
        !object_by_id(ssids, "phy0.1-ap0") ||
        strcmp(apd_mac80211_string(object_by_id(ssids, "phy0.1-ap0"),
                                   "broadcast_name"), "OpenWrt5G"))
        goto done;
    mlo = object_by_id(ssids, "ap-mld0");
    if (!mlo || !json_object_get_boolean(FIELD(mlo, "mlo")) ||
        json_object_array_length(FIELD(mlo, "radio_ids")) != 3 ||
        object_by_id(radios, "ap-mld0"))
        goto done;
    two = object_by_id(ssids, "phy0.0-ap0");
    if (!two || json_object_get_boolean(
            FIELD(FIELD(two, "runtime"), "complete")) ||
        strcmp(apd_mac80211_string(FIELD(two, "runtime"), "reason"),
               "hostapd_interface_control_missing"))
        goto done;
    hostapd = FIELD(sources, "hostapd");
    missing = FIELD(hostapd, "missing_interfaces");
    if (!hostapd || json_object_get_boolean(FIELD(hostapd, "complete")) ||
        !missing || json_object_array_length(missing) != 1 ||
        strcmp(json_object_get_string(json_object_array_get_idx(missing, 0)),
               "phy0.0-ap0"))
        goto done;
    five = object_by_id(radios, "phy0r1");
    air = FIELD(FIELD(five, "survey"), "air_stats");
    if (!air || !json_object_get_boolean(FIELD(air, "tx_retry_available")) ||
        json_object_get_int64(FIELD(air, "tx_total")) != 200 ||
        json_object_get_int64(FIELD(air, "tx_retries")) != 10 ||
        strcmp(apd_mac80211_string(air, "tx_retry_source"),
               "iw_station_dump"))
        goto done;
    if (verify_station_btm(&inputs) != 0)
        goto done;
    puts("ok: mac80211 mapping, SSID/MLO, counters and matched hostapd BTM capability");
    rc = 0;
done:
    if (rc && radios)
        fprintf(stderr, "%s\n", json_object_to_json_string_ext(radios,
            JSON_C_TO_STRING_PRETTY));
    json_object_put(status);
    json_object_put(radios);
    json_object_put(ssids);
    json_object_put(stations);
    json_object_put(sources);
    return rc;
}

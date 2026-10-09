// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef APD_MAC80211_STANDALONE_TEST
#include "apd_internal.h"
#include "apd_readonly_command.h"
#else
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <json-c/json.h>
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif
#endif

#include <ctype.h>
#include <limits.h>
#include <net/if.h>

#include "../ap_radio_id.h"

#define APD_MAC80211_IW_IFACE_MAX 64U
#define APD_MAC80211_RADIOS_MAX 8U

#ifndef APD_HOSTAPD_RUN_DIR
#define APD_HOSTAPD_RUN_DIR "/var/run/hostapd"
#endif
#ifndef APD_IW_PATH
#define APD_IW_PATH ""
#endif

struct apd_mac80211_iw_iface {
    char name[IFNAMSIZ];
    char bssid[18];
    char ssid[128];
    unsigned int wiphy_index;
    unsigned int radios[APD_MAC80211_RADIOS_MAX];
    size_t radio_count;
    int type_ap;
    int channel;
    int frequency_mhz;
    int width_mhz;
    int has_txpower;
    double txpower_dbm;
    int mlo;
};

struct apd_mac80211_iw_inventory {
    struct apd_mac80211_iw_iface items[APD_MAC80211_IW_IFACE_MAX];
    size_t count;
    int truncated;
};

struct apd_mac80211_station_totals {
    uint64_t tx_packets;
    uint64_t tx_retries;
    size_t sample_count;
};

struct apd_mac80211_inputs {
    struct json_object *network_status;
    struct json_object *hostapd_stations;
    const char *iw_dev;
    const char *(*station_dump)(const char *interface, void *opaque);
    struct json_object *(*survey)(const char *radio_id, void *opaque);
    int (*hostapd_present)(const char *interface, void *opaque);
    void *opaque;
};

static char *apd_mac80211_trim(char *line)
{
    char *end;

    while (*line && isspace((unsigned char)*line))
        line++;
    end = line + strlen(line);
    while (end > line && isspace((unsigned char)end[-1]))
        *--end = '\0';
    return line;
}

static struct json_object *apd_mac80211_child(
    struct json_object *object, const char *name)
{
    struct json_object *value = NULL;

    return object && json_object_is_type(object, json_type_object) &&
           json_object_object_get_ex(object, name, &value) ? value : NULL;
}

static const char *apd_mac80211_string(struct json_object *object,
                                       const char *name)
{
    struct json_object *value = apd_mac80211_child(object, name);

    return value && json_object_is_type(value, json_type_string) ?
        json_object_get_string(value) : NULL;
}

static int apd_mac80211_integer(struct json_object *object, const char *name,
                                int *out)
{
    struct json_object *value = apd_mac80211_child(object, name);

    if (!value || !json_object_is_type(value, json_type_int) || !out)
        return -1;
    *out = json_object_get_int(value);
    return 0;
}

static int apd_mac80211_boolean(struct json_object *object, const char *name)
{
    struct json_object *value = apd_mac80211_child(object, name);

    return value && json_object_get_boolean(value);
}

static void apd_mac80211_nullable_string(struct json_object *object,
                                         const char *name, const char *value)
{
    json_object_object_add(object, name, value && value[0] ?
        json_object_new_string(value) : json_object_new_null());
}

static void apd_mac80211_replace_source(struct json_object *sources,
                                        const char *name,
                                        struct json_object *replacement)
{
    if (!sources || !name || !replacement)
        return;
    json_object_object_del(sources, name);
    json_object_object_add(sources, name, json_object_get(replacement));
}

/*
 * The generic OpenWrt backend owns the authoritative hostapd control-socket
 * collector.  Its object contains the per-BSS capability rows used by AC
 * roaming preflight (11k/11v/FT/deauth and the resolved control path).  The
 * mac80211 topology layer only needs to add its logical-interface coverage;
 * replacing the whole object here used to discard `bss[]` on W1700K.
 */
static void apd_mac80211_merge_hostapd_source(
    struct json_object *sources, struct json_object *runtime_hostapd)
{
    struct json_object *hostapd = apd_mac80211_child(sources, "hostapd");
    struct json_object *value = NULL;
    struct json_object *missing = NULL;
    int base_available;
    int base_complete;
    int logical_available;
    int logical_complete;
    const char *selected_reason = NULL;
    char reason[128] = { 0 };

    if (!runtime_hostapd)
        return;
    if (!hostapd || !json_object_is_type(hostapd, json_type_object)) {
        apd_mac80211_replace_source(sources, "hostapd", runtime_hostapd);
        return;
    }

    base_available = apd_mac80211_boolean(hostapd, "available");
    base_complete = apd_mac80211_boolean(hostapd, "complete");
    logical_available = apd_mac80211_boolean(runtime_hostapd, "available");
    logical_complete = apd_mac80211_boolean(runtime_hostapd, "complete");
    json_object_object_del(hostapd, "available");
    json_object_object_add(hostapd, "available",
        json_object_new_boolean(base_available && logical_available));
    json_object_object_del(hostapd, "complete");
    json_object_object_add(hostapd, "complete",
        json_object_new_boolean(base_complete && logical_complete));

    value = apd_mac80211_child(runtime_hostapd, "missing_interfaces");
    if (value && json_object_is_type(value, json_type_array))
        missing = value;
    json_object_object_del(hostapd, "missing_interfaces");
    json_object_object_add(hostapd, "missing_interfaces", missing ?
        json_object_get(missing) : json_object_new_array());

    if (!base_complete)
        selected_reason = apd_mac80211_string(hostapd, "reason");
    if (!selected_reason && !logical_complete)
        selected_reason = apd_mac80211_string(runtime_hostapd, "reason");
    if (selected_reason)
        snprintf(reason, sizeof(reason), "%s", selected_reason);
    json_object_object_del(hostapd, "reason");
    apd_mac80211_nullable_string(hostapd, "reason", reason);
}

static struct json_object *apd_mac80211_source(const char *source,
                                               int available, int complete,
                                               const char *reason,
                                               int64_t observed_at)
{
    struct json_object *state = json_object_new_object();

    json_object_object_add(state, "source", json_object_new_string(source));
    json_object_object_add(state, "scope", json_object_new_string("runtime"));
    json_object_object_add(state, "available", json_object_new_boolean(available));
    json_object_object_add(state, "complete", json_object_new_boolean(complete));
    json_object_object_add(state, "stale", json_object_new_boolean(0));
    apd_mac80211_nullable_string(state, "reason", reason);
    json_object_object_add(state, "observed_at",
                           json_object_new_int64(observed_at));
    return state;
}

static int apd_mac80211_radio_list(const char *text, unsigned int *radios,
                                   size_t *count)
{
    const char *cursor = text;

    *count = 0;
    while (cursor && *cursor) {
        char *end = NULL;
        unsigned long value;

        while (*cursor && isspace((unsigned char)*cursor))
            cursor++;
        if (!*cursor)
            break;
        errno = 0;
        value = strtoul(cursor, &end, 10);
        if (errno == ERANGE || !end || end == cursor || value > UINT_MAX)
            return -1;
        if (*count < APD_MAC80211_RADIOS_MAX)
            radios[(*count)++] = (unsigned int)value;
        cursor = end;
    }
    return *count ? 0 : -1;
}

static int apd_mac80211_parse_iw_dev(
    const char *text, struct apd_mac80211_iw_inventory *inventory)
{
    char *copy = strdup(text ? text : "");
    char *line;
    char *saveptr = NULL;
    struct apd_mac80211_iw_iface *item = NULL;
    unsigned int wiphy_index = UINT_MAX;

    if (!copy || !inventory) {
        free(copy);
        return -1;
    }
    memset(inventory, 0, sizeof(*inventory));
    for (line = strtok_r(copy, "\n", &saveptr); line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        char *value = apd_mac80211_trim(line);

        if (!strncmp(value, "phy#", 4)) {
            char *end = NULL;
            unsigned long parsed = strtoul(value + 4, &end, 10);

            item = NULL;
            wiphy_index = end && !*end && parsed <= UINT_MAX ?
                (unsigned int)parsed : UINT_MAX;
            continue;
        }
        if (!strncmp(value, "Interface ", 10) && wiphy_index != UINT_MAX) {
            if (inventory->count >= APD_MAC80211_IW_IFACE_MAX) {
                inventory->truncated = 1;
                item = NULL;
                continue;
            }
            item = &inventory->items[inventory->count++];
            memset(item, 0, sizeof(*item));
            item->wiphy_index = wiphy_index;
            snprintf(item->name, sizeof(item->name), "%s", value + 10);
            continue;
        }
        if (!item)
            continue;
        if (!strncmp(value, "addr ", 5))
            snprintf(item->bssid, sizeof(item->bssid), "%s", value + 5);
        else if (!strncmp(value, "ssid ", 5))
            snprintf(item->ssid, sizeof(item->ssid), "%s", value + 5);
        else if (!strcmp(value, "type AP"))
            item->type_ap = 1;
        else if (!strncmp(value, "channel ", 8)) {
            int channel = 0;
            int frequency = 0;
            int width = 0;

            if (sscanf(value, "channel %d (%d MHz), width: %d MHz",
                       &channel, &frequency, &width) >= 2) {
                item->channel = channel;
                item->frequency_mhz = frequency;
                item->width_mhz = width;
            }
        } else if (!strncmp(value, "txpower ", 8)) {
            char *end = NULL;
            double parsed = strtod(value + 8, &end);

            if (end && end != value + 8) {
                item->has_txpower = 1;
                item->txpower_dbm = parsed;
            }
        } else if (!strncmp(value, "Radios:", 7)) {
            (void)apd_mac80211_radio_list(value + 7, item->radios,
                                          &item->radio_count);
        } else if (!strcmp(value, "MLD with links:")) {
            item->mlo = 1;
        }
    }
    free(copy);
    return inventory->count ? 0 : -1;
}

static int apd_mac80211_iface_has_radio(
    const struct apd_mac80211_iw_iface *item, unsigned int radio_index)
{
    size_t i;

    for (i = 0; item && i < item->radio_count; i++)
        if (item->radios[i] == radio_index)
            return 1;
    return 0;
}

static const struct apd_mac80211_iw_iface *apd_mac80211_iw_iface(
    const struct apd_mac80211_iw_inventory *inventory, const char *name)
{
    size_t i;

    for (i = 0; inventory && name && i < inventory->count; i++)
        if (!strcmp(inventory->items[i].name, name))
            return &inventory->items[i];
    return NULL;
}

static const struct apd_mac80211_iw_iface *apd_mac80211_radio_iface(
    const struct apd_mac80211_iw_inventory *inventory,
    struct json_object *interfaces, unsigned int radio_index)
{
    size_t i;

    for (i = 0; interfaces && i < json_object_array_length(interfaces); i++) {
        struct json_object *entry = json_object_array_get_idx(interfaces, i);
        const char *name = apd_mac80211_string(entry, "ifname");
        struct json_object *config = apd_mac80211_child(entry, "config");
        const struct apd_mac80211_iw_iface *item;

        if (!name || apd_mac80211_boolean(config, "mlo"))
            continue;
        item = apd_mac80211_iw_iface(inventory, name);
        if (item && apd_mac80211_iface_has_radio(item, radio_index))
            return item;
    }
    for (i = 0; inventory && i < inventory->count; i++)
        if (!inventory->items[i].mlo &&
            apd_mac80211_iface_has_radio(&inventory->items[i], radio_index))
            return &inventory->items[i];
    return NULL;
}

static const char *apd_mac80211_band_from_frequency(int frequency)
{
    if (frequency >= 2400 && frequency < 2500)
        return "2g";
    if (frequency >= 4900 && frequency < 5925)
        return "5g";
    if (frequency >= 5925 && frequency < 7125)
        return "6g";
    return NULL;
}

static int apd_mac80211_channel_from_frequency(int frequency)
{
    if (frequency == 2484)
        return 14;
    if (frequency >= 2412 && frequency <= 2472 &&
        (frequency - 2407) % 5 == 0)
        return (frequency - 2407) / 5;
    if (frequency >= 4910 && frequency < 5925 &&
        (frequency - 5000) % 5 == 0)
        return (frequency - 5000) / 5;
    if (frequency >= 5955 && frequency <= 7115 &&
        (frequency - 5950) % 5 == 0)
        return (frequency - 5950) / 5;
    return 0;
}

static struct json_object *apd_mac80211_runtime_meta(
    int complete, const char *reason, int64_t observed_at)
{
    struct json_object *state = apd_mac80211_source(
        "ubus_network_wireless+iw_dev", 1, complete, reason, observed_at);

    return state;
}

static int apd_mac80211_station_u64(const char *line, const char *label,
                                    uint64_t *out)
{
    const char *value;
    char *end = NULL;
    unsigned long long parsed;

    if (strncmp(line, label, strlen(label)))
        return 0;
    value = line + strlen(label);
    while (*value && isspace((unsigned char)*value))
        value++;
    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno == ERANGE || !end || end == value)
        return -1;
    *out = (uint64_t)parsed;
    return 1;
}

static void apd_mac80211_station_finish(
    struct json_object *station, struct json_object *stations,
    const char *interface, const char *radio_id, int64_t observed_at)
{
    if (!station)
        return;
    json_object_object_add(station, "interface",
                           json_object_new_string(interface));
    json_object_object_add(station, "radio_id",
                           json_object_new_string(radio_id));
    json_object_object_add(station, "source",
                           json_object_new_string("iw_station_dump"));
    json_object_object_add(station, "station_btm_capable",
                           json_object_new_boolean(0));
    json_object_object_add(station, "station_btm_reason",
                           json_object_new_string(
                               "station_extended_capabilities_not_reported"));
    json_object_object_add(station, "stale", json_object_new_boolean(0));
    json_object_object_add(station, "observed_at",
                           json_object_new_int64(observed_at));
    json_object_array_add(stations, station);
}

static void apd_mac80211_merge_station_btm(
    struct json_object *stations, struct json_object *hostapd_stations)
{
    size_t i, j;

    if (!hostapd_stations ||
        !json_object_is_type(hostapd_stations, json_type_array))
        return;
    /* iw supplies live counters, but only hostapd has association capabilities. */
    for (i = 0; i < json_object_array_length(stations); i++) {
        struct json_object *station = json_object_array_get_idx(stations, i);
        const char *mac = apd_mac80211_string(station, "mac");
        const char *interface = apd_mac80211_string(station, "interface");

        if (!mac || !interface)
            continue;
        for (j = 0; j < json_object_array_length(hostapd_stations); j++) {
            struct json_object *peer =
                json_object_array_get_idx(hostapd_stations, j);
            const char *peer_mac = apd_mac80211_string(peer, "mac");
            const char *peer_interface = apd_mac80211_string(peer, "interface");
            const char *source = apd_mac80211_string(peer, "source");
            struct json_object *capable =
                apd_mac80211_child(peer, "station_btm_capable");
            struct json_object *reason =
                apd_mac80211_child(peer, "station_btm_reason");

            if (!peer_mac || strcmp(mac, peer_mac) ||
                !peer_interface || strcmp(interface, peer_interface) ||
                !source || strcmp(source, "hostapd_control") ||
                apd_mac80211_boolean(peer, "stale") ||
                !capable || !json_object_is_type(capable, json_type_boolean) ||
                !reason || !json_object_is_type(reason, json_type_string))
                continue;
            json_object_object_add(station, "station_btm_capable",
                                   json_object_get(capable));
            json_object_object_add(station, "station_btm_reason",
                                   json_object_get(reason));
            break;
        }
    }
}

static int apd_mac80211_parse_station_dump(
    const char *text, const char *interface, const char *radio_id,
    int64_t observed_at, struct json_object *stations,
    struct apd_mac80211_station_totals *totals)
{
    char *copy = strdup(text ? text : "");
    char *line;
    char *saveptr = NULL;
    struct json_object *station = NULL;
    int parsed = 0;

    if (!copy)
        return -1;
    for (line = strtok_r(copy, "\n", &saveptr); line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        char *value = apd_mac80211_trim(line);
        uint64_t number;
        int match;

        if (!strncmp(value, "Station ", 8)) {
            char mac[18] = { 0 };

            apd_mac80211_station_finish(station, stations, interface,
                                        radio_id, observed_at);
            station = NULL;
            if (sscanf(value + 8, "%17s", mac) != 1)
                continue;
            station = json_object_new_object();
            json_object_object_add(station, "mac", json_object_new_string(mac));
            parsed++;
            continue;
        }
        if (!station)
            continue;
        match = apd_mac80211_station_u64(value, "rx bytes:", &number);
        if (match == 1)
            json_object_object_add(station, "rx_bytes",
                                   json_object_new_int64((int64_t)number));
        else if ((match = apd_mac80211_station_u64(
                      value, "tx bytes:", &number)) == 1)
            json_object_object_add(station, "tx_bytes",
                                   json_object_new_int64((int64_t)number));
        else if ((match = apd_mac80211_station_u64(
                      value, "tx packets:", &number)) == 1) {
            json_object_object_add(station, "tx_packets",
                                   json_object_new_int64((int64_t)number));
            totals->tx_packets += number;
        } else if ((match = apd_mac80211_station_u64(
                      value, "tx retries:", &number)) == 1) {
            json_object_object_add(station, "tx_retries",
                                   json_object_new_int64((int64_t)number));
            totals->tx_retries += number;
            totals->sample_count++;
        } else if ((match = apd_mac80211_station_u64(
                      value, "connected time:", &number)) == 1)
            json_object_object_add(station, "connected_time_seconds",
                                   json_object_new_int64((int64_t)number));
        else if (!strncmp(value, "signal:", 7)) {
            int signal;

            if (sscanf(value + 7, "%d", &signal) == 1)
                json_object_object_add(station, "signal_dbm",
                                       json_object_new_int(signal));
        }
    }
    apd_mac80211_station_finish(station, stations, interface, radio_id,
                                observed_at);
    free(copy);
    return parsed;
}

static int apd_mac80211_json_array_contains(struct json_object *array,
                                            const char *value)
{
    size_t i;

    for (i = 0; array && i < json_object_array_length(array); i++) {
        struct json_object *entry = json_object_array_get_idx(array, i);

        if (entry && json_object_is_type(entry, json_type_string) &&
            !strcmp(json_object_get_string(entry), value))
            return 1;
    }
    return 0;
}

static int apd_mac80211_object_array_has_id(struct json_object *array,
                                            const char *id)
{
    size_t i;

    for (i = 0; array && id && i < json_object_array_length(array); i++) {
        struct json_object *entry = json_object_array_get_idx(array, i);
        const char *existing = apd_mac80211_string(entry, "id");

        if (existing && !strcmp(existing, id))
            return 1;
    }
    return 0;
}

static struct json_object *apd_mac80211_radio_ids(
    struct json_object *config, unsigned int wiphy_index)
{
    struct json_object *ids = json_object_new_array();
    struct json_object *radios = apd_mac80211_child(config, "radios");
    size_t i;

    for (i = 0; radios && i < json_object_array_length(radios); i++) {
        struct json_object *entry = json_object_array_get_idx(radios, i);
        int index = json_object_get_int(entry);
        char id[32];

        if (index < 0)
            continue;
        snprintf(id, sizeof(id), "phy%ur%d", wiphy_index, index);
        json_object_array_add(ids, json_object_new_string(id));
    }
    return ids;
}

/*
 * Wi-Fi generation from the UCI htmode the radio is actually running.
 *
 * netifd's htmode is the operating mode hostapd was configured with, so an
 * EHT320 radio is a Wi-Fi 7 radio -- there is nothing to infer. Before this
 * the snapshot carried no `standard` at all and the wireless page printed
 * "驱动未上报 Wi-Fi 标准" for a radio whose mode was sitting in
 * /etc/config/wireless.
 */
static const char *apd_mac80211_standard_from_htmode(const char *htmode)
{
    if (!htmode || !htmode[0])
        return NULL;
    if (!strncmp(htmode, "EHT", 3))
        return "802.11be";
    if (!strncmp(htmode, "HE", 2))
        return "802.11ax";
    if (!strncmp(htmode, "VHT", 3))
        return "802.11ac";
    if (!strncmp(htmode, "HT", 2))
        return "802.11n";
    if (!strcmp(htmode, "NOHT"))
        return "802.11a/b/g";
    return NULL;
}

static void apd_mac80211_attach_retry(
    struct json_object *survey, const struct apd_mac80211_station_totals *totals)
{
    struct json_object *air = apd_mac80211_child(survey, "air_stats");

    if (!air || !json_object_is_type(air, json_type_object)) {
        air = json_object_new_object();
        json_object_object_add(survey, "air_stats", air);
    }
    json_object_object_add(air, "tx_retry_available",
                           json_object_new_boolean(totals->sample_count > 0));
    json_object_object_add(air, "tx_retry_source", totals->sample_count ?
        json_object_new_string("iw_station_dump") : json_object_new_null());
    json_object_object_add(air, "tx_retry_counter_semantics", totals->sample_count ?
        json_object_new_string("cumulative") : json_object_new_null());
    json_object_object_add(air, "tx_retry_reason", totals->sample_count ?
        json_object_new_null() :
        json_object_new_string("iw_station_dump_no_station_samples"));
    json_object_object_add(air, "tx_total", totals->sample_count ?
        json_object_new_int64((int64_t)totals->tx_packets) :
        json_object_new_null());
    json_object_object_add(air, "tx_retries", totals->sample_count ?
        json_object_new_int64((int64_t)totals->tx_retries) :
        json_object_new_null());
}

static int apd_mac80211_build_runtime(
    const struct apd_mac80211_inputs *inputs, int64_t observed_at,
    struct json_object **radios_out, struct json_object **ssids_out,
    struct json_object **stations_out, struct json_object **sources_out,
    int *complete_out)
{
    struct apd_mac80211_iw_inventory iw;
    struct json_object *radios = json_object_new_array();
    struct json_object *ssids = json_object_new_array();
    struct json_object *stations = json_object_new_array();
    struct json_object *sources = json_object_new_object();
    struct json_object *hostapd_missing = json_object_new_array();
    struct json_object *collected_interfaces = json_object_new_array();
    struct apd_mac80211_station_totals totals[APD_MAC80211_RADIOS_MAX];
    int complete = 1;
    int radio_count = 0;
    int hostapd_checked = 0;
    int hostapd_complete = 1;

    if (!inputs || !inputs->network_status || !inputs->iw_dev || !radios ||
        !ssids || !stations || !sources || !hostapd_missing ||
        !collected_interfaces ||
        apd_mac80211_parse_iw_dev(inputs->iw_dev, &iw) != 0)
        goto fail;
    memset(totals, 0, sizeof(totals));
    json_object_object_foreach(inputs->network_status, config_id, entry) {
        struct json_object *config = apd_mac80211_child(entry, "config");
        struct json_object *interfaces = apd_mac80211_child(entry, "interfaces");
        const char *type = apd_mac80211_string(config, "type");
        const char *band = apd_mac80211_string(config, "band");
        const char *desired_channel = apd_mac80211_string(config, "channel");
        const struct apd_mac80211_iw_iface *iw_radio;
        struct json_object *radio;
        struct json_object *runtime_interfaces;
        struct json_object *survey_result = NULL;
        struct json_object *survey = NULL;
        int radio_index = -1;
        unsigned int wiphy_index;
        char radio_id[32];
        size_t i;

        if (!type || strcmp(type, "mac80211") ||
            apd_mac80211_integer(config, "radio", &radio_index) != 0 ||
            radio_index < 0 || radio_index >= (int)APD_MAC80211_RADIOS_MAX)
            continue;
        iw_radio = apd_mac80211_radio_iface(&iw, interfaces,
                                            (unsigned int)radio_index);
        if (!iw_radio) {
            complete = 0;
            continue;
        }
        wiphy_index = iw_radio->wiphy_index;
        snprintf(radio_id, sizeof(radio_id), "phy%ur%d", wiphy_index,
                 radio_index);
        radio = json_object_new_object();
        runtime_interfaces = json_object_new_array();
        json_object_object_add(radio, "id", json_object_new_string(radio_id));
        json_object_object_add(radio, "phy", json_object_new_string_len(
            radio_id, (int)(strchr(radio_id, 'r') - radio_id)));
        json_object_object_add(radio, "radio_index",
                               json_object_new_int(radio_index));
        json_object_object_add(radio, "config_id",
                               json_object_new_string(config_id));
        if (band)
            json_object_object_add(radio, "band", json_object_new_string(band));
        else if (apd_mac80211_band_from_frequency(iw_radio->frequency_mhz))
            json_object_object_add(radio, "band", json_object_new_string(
                apd_mac80211_band_from_frequency(iw_radio->frequency_mhz)));
        apd_mac80211_nullable_string(radio, "desired_channel", desired_channel);
        if (iw_radio->channel > 0) {
            json_object_object_add(radio, "channel",
                                   json_object_new_int(iw_radio->channel));
            json_object_object_add(radio, "operating_channel",
                                   json_object_new_int(iw_radio->channel));
        }
        if (iw_radio->frequency_mhz > 0)
            json_object_object_add(radio, "frequency_mhz",
                                   json_object_new_int(iw_radio->frequency_mhz));
        if (iw_radio->width_mhz > 0)
            json_object_object_add(radio, "width_mhz",
                                   json_object_new_int(iw_radio->width_mhz));
        if (iw_radio->has_txpower)
            json_object_object_add(radio, "txpower_dbm",
                json_object_new_double(iw_radio->txpower_dbm));
        {
            const char *htmode = apd_mac80211_string(config, "htmode");
            const char *standard =
                apd_mac80211_standard_from_htmode(htmode);
            const char *txpower = apd_mac80211_string(config, "txpower");

            if (htmode)
                json_object_object_add(radio, "htmode",
                                       json_object_new_string(htmode));
            if (standard) {
                json_object_object_add(radio, "standard",
                                       json_object_new_string(standard));
                json_object_object_add(radio, "standard_source",
                    json_object_new_string("uci_wireless_htmode"));
            }
            /*
             * Transmit power mode is a property of the configuration, not of
             * the driver: netifd runs `iw phy set txpower auto` when the UCI
             * option is absent and `... fixed <n>` when it is set. Reporting it
             * from here is what lets the射频 page show a mode instead of
             * "当前 AP 未上报发射功率模式" while the effective dBm was visible
             * one row above.
             */
            json_object_object_add(radio, "tx_power_mode",
                json_object_new_string(txpower && txpower[0] ? "custom" :
                                                               "auto"));
            json_object_object_add(radio, "tx_power_mode_source",
                json_object_new_string("uci_wireless_txpower"));
            if (txpower && txpower[0])
                json_object_object_add(radio, "tx_power_custom",
                                       json_object_new_string(txpower));
            {
                struct json_object *modes = json_object_new_array();

                json_object_array_add(modes, json_object_new_string("auto"));
                json_object_array_add(modes, json_object_new_string("custom"));
                json_object_object_add(radio, "supported_tx_power_modes",
                                       modes);
            }
        }
        {
            struct json_object *reference = json_object_new_object();

            json_object_object_add(reference, "interface",
                                   json_object_new_string(config_id));
            json_object_object_add(reference, "type",
                json_object_new_string("configuration_reference"));
            json_object_object_add(reference, "source",
                json_object_new_string("ubus_network_wireless"));
            json_object_object_add(reference, "runtime_interface",
                                   json_object_new_boolean(0));
            json_object_array_add(runtime_interfaces, reference);
        }
        for (i = 0; interfaces && i < json_object_array_length(interfaces); i++) {
            struct json_object *iface_entry = json_object_array_get_idx(interfaces, i);
            struct json_object *iface_config = apd_mac80211_child(iface_entry,
                                                                  "config");
            const char *ifname = apd_mac80211_string(iface_entry, "ifname");
            const struct apd_mac80211_iw_iface *iw_iface;
            struct json_object *iface;
            struct json_object *ssid;
            const char *ssid_name;
            const char *mode;
            const char *encryption;
            int mlo;
            int hostapd_present;
            int collect_interface;
            const char *station_text;

            if (!ifname || !ifname[0])
                continue;
            iw_iface = apd_mac80211_iw_iface(&iw, ifname);
            mlo = apd_mac80211_boolean(iface_config, "mlo");
            iface = json_object_new_object();
            json_object_object_add(iface, "interface",
                                   json_object_new_string(ifname));
            json_object_object_add(iface, "type", json_object_new_string("AP"));
            json_object_object_add(iface, "mlo", json_object_new_boolean(mlo));
            if (iw_iface && iw_iface->bssid[0])
                json_object_object_add(iface, "bssid",
                                       json_object_new_string(iw_iface->bssid));
            ssid_name = apd_mac80211_string(iface_config, "ssid");
            if (!ssid_name && iw_iface && iw_iface->ssid[0])
                ssid_name = iw_iface->ssid;
            if (ssid_name)
                json_object_object_add(iface, "broadcast_name",
                                       json_object_new_string(ssid_name));
            if (iw_iface && iw_iface->frequency_mhz > 0) {
                json_object_object_add(iface, "channel",
                                       json_object_new_int(iw_iface->channel));
                json_object_object_add(iface, "frequency_mhz",
                    json_object_new_int(iw_iface->frequency_mhz));
                if (iw_iface->width_mhz > 0)
                    json_object_object_add(iface, "width_mhz",
                        json_object_new_int(iw_iface->width_mhz));
            }
            json_object_array_add(runtime_interfaces, iface);

            hostapd_present = inputs->hostapd_present ?
                inputs->hostapd_present(ifname, inputs->opaque) : 0;

            if (!apd_mac80211_object_array_has_id(ssids, ifname)) {
                    ssid = json_object_new_object();
                    json_object_object_add(ssid, "id",
                        json_object_new_string(ifname));
                    json_object_object_add(ssid, "radio_id",
                        json_object_new_string(radio_id));
                    json_object_object_add(ssid, "interface",
                        json_object_new_string(ifname));
                    if (ssid_name)
                        json_object_object_add(ssid, "broadcast_name",
                            json_object_new_string(ssid_name));
                    mode = apd_mac80211_string(iface_config, "mode");
                    json_object_object_add(ssid, "mode",
                        json_object_new_string(mode ? mode : "ap"));
                    encryption = apd_mac80211_string(iface_config, "encryption");
                    if (encryption)
                        json_object_object_add(ssid, "security_mode",
                            json_object_new_string(encryption));
                    json_object_object_add(ssid, "mlo",
                        json_object_new_boolean(mlo));
                    if (mlo)
                        json_object_object_add(ssid, "radio_ids",
                            apd_mac80211_radio_ids(iface_config, wiphy_index));
                    if (iw_iface && iw_iface->bssid[0])
                        json_object_object_add(ssid, "bssid",
                            json_object_new_string(iw_iface->bssid));
                    if (iw_iface && iw_iface->frequency_mhz > 0) {
                        json_object_object_add(ssid, "channel",
                            json_object_new_int(iw_iface->channel));
                        json_object_object_add(ssid, "frequency_mhz",
                            json_object_new_int(iw_iface->frequency_mhz));
                    }
                    json_object_object_add(ssid, "runtime",
                        apd_mac80211_runtime_meta(hostapd_present,
                            hostapd_present ? NULL :
                                "hostapd_interface_control_missing",
                            observed_at));
                    json_object_array_add(ssids, ssid);
            }
            collect_interface = !apd_mac80211_json_array_contains(
                collected_interfaces, ifname);
            if (collect_interface) {
                json_object_array_add(collected_interfaces,
                                      json_object_new_string(ifname));
                hostapd_checked++;
                if (!hostapd_present) {
                    hostapd_complete = 0;
                    json_object_array_add(hostapd_missing,
                                          json_object_new_string(ifname));
                }
                station_text = inputs->station_dump ?
                    inputs->station_dump(ifname, inputs->opaque) : NULL;
                if (station_text)
                    (void)apd_mac80211_parse_station_dump(station_text, ifname,
                        radio_id, observed_at, stations, &totals[radio_index]);
            }
        }
        json_object_object_add(radio, "interfaces", runtime_interfaces);
        json_object_object_add(radio, "runtime",
            apd_mac80211_runtime_meta(1, NULL, observed_at));
        if (inputs->survey)
            survey_result = inputs->survey(radio_id, inputs->opaque);
        if (survey_result) {
            struct json_object *items = apd_mac80211_child(survey_result, "items");

            if (items && json_object_array_length(items) > 0)
                survey = json_object_get(json_object_array_get_idx(items, 0));
        }
        if (!survey) {
            survey = json_object_new_object();
            json_object_object_add(survey, "source",
                                   json_object_new_string("iw_survey"));
            json_object_object_add(survey, "complete",
                                   json_object_new_boolean(0));
            json_object_object_add(survey, "reason",
                json_object_new_string("iw_survey_unavailable"));
            complete = 0;
        }
        {
            struct json_object *value = apd_mac80211_child(survey,
                                                            "frequency_mhz");
            struct json_object *channel = apd_mac80211_child(survey,
                                                              "channel");
            int frequency = value && json_object_is_type(value, json_type_int) ?
                json_object_get_int(value) : 0;
            int derived_channel = apd_mac80211_channel_from_frequency(frequency);

            if (!channel && derived_channel > 0) {
                json_object_object_add(survey, "channel",
                                       json_object_new_int(derived_channel));
                channel = apd_mac80211_child(survey, "channel");
            }

            if (!apd_mac80211_child(radio, "frequency_mhz") && value &&
                json_object_is_type(value, json_type_int))
                json_object_object_add(radio, "frequency_mhz",
                                       json_object_get(value));
            if (!apd_mac80211_child(radio, "channel") && channel &&
                json_object_is_type(channel, json_type_int)) {
                json_object_object_add(radio, "channel",
                                       json_object_get(channel));
                json_object_object_add(radio, "operating_channel",
                                       json_object_get(channel));
            }
            if (!json_object_get_boolean(apd_mac80211_child(survey,
                                                             "complete")))
                complete = 0;
        }
        apd_mac80211_attach_retry(survey, &totals[radio_index]);
        json_object_object_add(radio, "survey", survey);
        json_object_array_add(radios, radio);
        if (survey_result)
            json_object_put(survey_result);
        radio_count++;
    }
    if (!radio_count)
        complete = 0;
    if (iw.truncated)
        complete = 0;
    if (!hostapd_complete)
        complete = 0;
#ifndef APD_MAC80211_STANDALONE_TEST
    /*
     * Channel evidence, attached after the radios exist.
     *
     * The base backend builds catalogues per wiphy name, which never matches a
     * radio id here (phy0r0/r1/r2 all live on phy0), and this backend replaces
     * the radios array wholesale -- so before this call every managed radio
     * reached the controller without a channel_catalog and the AC refused each
     * write with channel_catalog_missing. Band-scoped so a 2.4 GHz radio is
     * never offered a 5/6 GHz channel.
     */
    apd_collect_channel_catalogs_by_band(radios, observed_at);
#endif
    {
        struct json_object *netifd = apd_mac80211_source(
            "ubus_network_wireless", 1, radio_count > 0,
            radio_count > 0 ? NULL : "empty_mac80211_radio_inventory",
            observed_at);
        struct json_object *iw_source = apd_mac80211_source(
            "iw_dev", 1, iw.count > 0 && !iw.truncated,
            iw.truncated ? "iw_interface_inventory_truncated" : NULL,
            observed_at);
        struct json_object *hostapd = apd_mac80211_source(
            "hostapd_control", hostapd_checked > 0, hostapd_complete,
            hostapd_complete ? NULL : "hostapd_interface_control_missing",
            observed_at);

        json_object_object_add(netifd, "radio_entries",
                               json_object_new_int(radio_count));
        json_object_object_add(iw_source, "interface_count",
                               json_object_new_int((int)iw.count));
        json_object_object_add(hostapd, "missing_interfaces", hostapd_missing);
        hostapd_missing = NULL;
        json_object_object_add(sources, "netifd", netifd);
        json_object_object_add(sources, "iw", iw_source);
        json_object_object_add(sources, "hostapd", hostapd);
    }
    apd_mac80211_merge_station_btm(stations, inputs->hostapd_stations);
    *radios_out = radios;
    *ssids_out = ssids;
    *stations_out = stations;
    *sources_out = sources;
    *complete_out = complete;
    json_object_put(collected_interfaces);
    return 0;

fail:
    json_object_put(radios);
    json_object_put(ssids);
    json_object_put(stations);
    json_object_put(sources);
    json_object_put(hostapd_missing);
    json_object_put(collected_interfaces);
    return -1;
}

#ifndef APD_MAC80211_STANDALONE_TEST

struct apd_mac80211_ubus_result {
    struct json_object *json;
};

static void apd_mac80211_ubus_callback(struct ubus_request *request, int type,
                                       struct blob_attr *message)
{
    struct apd_mac80211_ubus_result *result = request->priv;
    char *text;

    (void)type;
    if (!result || !message)
        return;
    text = blobmsg_format_json(message, true);
    if (text) {
        result->json = json_tokener_parse(text);
        free(text);
    }
}

static struct json_object *apd_mac80211_network_status(void)
{
    struct ubus_context *ctx = ubus_connect(APD_UBUS_SOCKET_PATH);
    struct apd_mac80211_ubus_result result = { 0 };
    uint32_t object_id;

    if (!ctx)
        return NULL;
    if (ubus_lookup_id(ctx, "network.wireless", &object_id) == UBUS_STATUS_OK)
        (void)ubus_invoke(ctx, object_id, "status", NULL,
            apd_mac80211_ubus_callback, &result, 2500);
    ubus_free(ctx);
    return result.json;
}

static const char *apd_mac80211_iw_path(void)
{
    static const char *const paths[] = {
        "/usr/sbin/iw", "/usr/bin/iw", "/sbin/iw", NULL
    };
    size_t i;

    if (APD_IW_PATH[0] && access(APD_IW_PATH, X_OK) == 0)
        return APD_IW_PATH;
    for (i = 0; paths[i]; i++)
        if (access(paths[i], X_OK) == 0)
            return paths[i];
    return NULL;
}

struct apd_mac80211_live {
    const char *iw;
    struct apd_command_result station;
};

static const char *apd_mac80211_live_station(const char *interface,
                                             void *opaque)
{
    struct apd_mac80211_live *live = opaque;
    char *const argv[] = {
        (char *)live->iw, "dev", (char *)interface, "station", "dump", NULL
    };

    apd_command_result_free(&live->station);
    return apd_readonly_command(live->iw, argv, &live->station) == 0 ?
        live->station.text : NULL;
}

static struct json_object *apd_mac80211_live_survey(const char *radio_id,
                                                     void *opaque)
{
    struct json_object *result = NULL;

    (void)opaque;
    (void)apd_backend_survey_scan(radio_id, &result);
    return result;
}

static int apd_mac80211_live_hostapd(const char *interface, void *opaque)
{
    char path[PATH_MAX];
    struct stat st;

    (void)opaque;
    return snprintf(path, sizeof(path), "%s/%s", APD_HOSTAPD_RUN_DIR,
                    interface) < (int)sizeof(path) &&
           lstat(path, &st) == 0 && S_ISSOCK(st.st_mode);
}

static int apd_mac80211_snapshot(struct json_object **out)
{
    const struct apd_backend_ops *base = apd_backend_openwrt();
    struct json_object *root = NULL;
    struct json_object *network_status = NULL;
    struct json_object *radios = NULL;
    struct json_object *ssids = NULL;
    struct json_object *stations = NULL;
    struct json_object *runtime_sources = NULL;
    struct json_object *sources = NULL;
    const char *iw = apd_mac80211_iw_path();
    struct apd_command_result iw_dev = { 0 };
    struct apd_mac80211_live live = { 0 };
    struct apd_mac80211_inputs inputs;
    int64_t observed_at = apd_now_s();
    int complete = 0;
    int rc = -1;

    if (!out || !base || !base->snapshot || base->snapshot(&root) != 0 ||
        !root || !iw)
        goto done;
    network_status = apd_mac80211_network_status();
    if (!network_status || json_object_object_length(network_status) == 0)
        goto done;
    {
        char *const argv[] = { (char *)iw, "dev", NULL };

        if (apd_readonly_command(iw, argv, &iw_dev) != 0)
            goto done;
    }
    memset(&inputs, 0, sizeof(inputs));
    live.iw = iw;
    inputs.network_status = network_status;
    inputs.hostapd_stations = apd_mac80211_child(root, "stations");
    inputs.iw_dev = iw_dev.text;
    inputs.station_dump = apd_mac80211_live_station;
    inputs.survey = apd_mac80211_live_survey;
    inputs.hostapd_present = apd_mac80211_live_hostapd;
    inputs.opaque = &live;
    if (apd_mac80211_build_runtime(&inputs, observed_at, &radios, &ssids,
            &stations, &runtime_sources, &complete) != 0)
        goto done;
    json_object_object_del(root, "backend");
    json_object_object_add(root, "backend",
        json_object_new_string("openwrt-mac80211-nl80211"));
    json_object_object_del(root, "observed_at");
    json_object_object_add(root, "observed_at",
                           json_object_new_int64(observed_at));
    json_object_object_del(root, "complete");
    json_object_object_add(root, "complete", json_object_new_boolean(complete));
    json_object_object_del(root, "reason");
    apd_mac80211_nullable_string(root, "reason",
        complete ? NULL : "partial_mac80211_runtime_sources");
    json_object_object_del(root, "radios");
    json_object_object_add(root, "radios", radios);
    radios = NULL;
    json_object_object_del(root, "ssids");
    json_object_object_add(root, "ssids", ssids);
    ssids = NULL;
    json_object_object_del(root, "stations");
    json_object_object_add(root, "stations", stations);
    stations = NULL;
    json_object_object_del(root, "radio_count");
    json_object_object_add(root, "radio_count", json_object_new_int(
        (int)json_object_array_length(apd_mac80211_child(root, "radios"))));
    json_object_object_del(root, "ssid_count");
    json_object_object_add(root, "ssid_count", json_object_new_int(
        (int)json_object_array_length(apd_mac80211_child(root, "ssids"))));
    json_object_object_del(root, "station_count");
    json_object_object_add(root, "station_count", json_object_new_int(
        (int)json_object_array_length(apd_mac80211_child(root, "stations"))));
    sources = apd_mac80211_child(root, "sources");
    if (!sources || !json_object_is_type(sources, json_type_object)) {
        sources = json_object_new_object();
        json_object_object_add(root, "sources", sources);
    }
    json_object_object_foreach(runtime_sources, name, value) {
        if (!strcmp(name, "hostapd"))
            apd_mac80211_merge_hostapd_source(sources, value);
        else
            apd_mac80211_replace_source(sources, name, value);
    }
    *out = root;
    root = NULL;
    rc = 0;
done:
    json_object_put(root);
    json_object_put(network_status);
    json_object_put(radios);
    json_object_put(ssids);
    json_object_put(stations);
    json_object_put(runtime_sources);
    apd_command_result_free(&iw_dev);
    apd_command_result_free(&live.station);
    return rc;
}

static int apd_mac80211_probe(struct json_object **out)
{
    struct json_object *status = apd_mac80211_network_status();
    struct json_object *probe = json_object_new_object();
    int count = status ? json_object_object_length(status) : 0;

    if (!out || !probe) {
        json_object_put(status);
        json_object_put(probe);
        return -1;
    }
    json_object_object_add(probe, "backend",
        json_object_new_string("openwrt-mac80211-nl80211"));
    json_object_object_add(probe, "snapshot_supported",
                           json_object_new_boolean(1));
    json_object_object_add(probe, "network_wireless_radio_entries",
                           json_object_new_int(count));
    json_object_object_add(probe, "iw_available",
                           json_object_new_boolean(apd_mac80211_iw_path() != NULL));
    *out = probe;
    json_object_put(status);
    return 0;
}

int apd_backend_mac80211_detect(void)
{
    struct uci_context *ctx = NULL;
    struct uci_package *package = NULL;
    struct uci_element *element;
    struct json_object *status = NULL;
    int mac80211 = 0;
    int vendor = access("/usr/sbin/apstats", X_OK) == 0 ||
                 access("/usr/bin/apstats", X_OK) == 0 ||
                 access("/sbin/apstats", X_OK) == 0 ||
                 access("/usr/sbin/wlanconfig", X_OK) == 0 ||
                 access("/usr/bin/wlanconfig", X_OK) == 0 ||
                 access("/sbin/wlanconfig", X_OK) == 0;

    ctx = uci_alloc_context();
    if (!ctx)
        return 0;
    if (uci_load(ctx, "wireless", &package) == UCI_OK && package) {
        uci_foreach_element(&package->sections, element) {
            struct uci_section *section = uci_to_section(element);
            const char *type;

            if (strcmp(section->type, "wifi-device"))
                continue;
            type = uci_lookup_option_string(ctx, section, "type");
            if (type && !strcmp(type, "qcawificfg80211"))
                vendor = 1;
            if (type && !strcmp(type, "mac80211"))
                mac80211 = 1;
        }
    }
    if (package)
        uci_unload(ctx, package);
    uci_free_context(ctx);
    if (vendor || !mac80211)
        return 0;
    status = apd_mac80211_network_status();
    mac80211 = status && json_object_is_type(status, json_type_object) &&
               json_object_object_length(status) > 0;
    json_object_put(status);
    return mac80211;
}

static int apd_mac80211_validate(struct json_object *candidate,
                                 struct json_object **out)
{
    return apd_backend_openwrt()->validate(candidate, out);
}

static int apd_mac80211_stage(struct json_object *candidate,
                              struct json_object **out)
{
    return apd_backend_openwrt()->stage(candidate, out);
}

static int apd_mac80211_apply(struct json_object *candidate,
                              struct json_object **out)
{
    return apd_backend_openwrt()->apply(candidate, out);
}

static int apd_mac80211_readback(struct json_object *candidate,
                                 struct json_object **out)
{
    return apd_backend_openwrt()->readback(candidate, out);
}

static int apd_mac80211_rollback(struct json_object *rollback_ref,
                                 struct json_object **out)
{
    return apd_backend_openwrt()->rollback(rollback_ref, out);
}

static const struct apd_backend_ops mac80211_backend = {
    .name = "openwrt-mac80211-nl80211",
    .snapshot_supported = 1,
    .probe = apd_mac80211_probe,
    .snapshot = apd_mac80211_snapshot,
    .neighbor_scan = apd_backend_neighbor_scan,
    .validate = apd_mac80211_validate,
    .stage = apd_mac80211_stage,
    .apply = apd_mac80211_apply,
    .readback = apd_mac80211_readback,
    .rollback = apd_mac80211_rollback,
};

const struct apd_backend_ops *apd_backend_mac80211(void)
{
    return &mac80211_backend;
}

#endif

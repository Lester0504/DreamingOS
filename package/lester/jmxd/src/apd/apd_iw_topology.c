// SPDX-License-Identifier: GPL-2.0-or-later
#include "apd_iw_topology.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>

#define APD_IW_RADIO_LIMIT 16U

static char *apd_iw_trim(char *line)
{
    char *end;

    while (*line == ' ' || *line == '\t')
        line++;
    end = line + strlen(line);
    while (end > line && (end[-1] == ' ' || end[-1] == '\t' ||
                          end[-1] == '\r'))
        *--end = '\0';
    return line;
}

static const char *apd_iw_band_from_frequency(int frequency)
{
    if (frequency >= 2400 && frequency < 2500)
        return "2.4GHz";
    if (frequency >= 4900 && frequency < 5925)
        return "5GHz";
    if (frequency >= 5925 && frequency < 7125)
        return "6GHz";
    return "unknown";
}

static struct json_object *apd_iw_runtime_meta(int complete,
                                                const char *reason,
                                                int64_t observed_at)
{
    struct json_object *state = json_object_new_object();

    json_object_object_add(state, "source", json_object_new_string("iw_dev"));
    json_object_object_add(state, "scope", json_object_new_string("runtime"));
    json_object_object_add(state, "available", json_object_new_boolean(1));
    json_object_object_add(state, "complete",
                           json_object_new_boolean(complete));
    json_object_object_add(state, "stale", json_object_new_boolean(0));
    json_object_object_add(state, "reason", reason ?
                           json_object_new_string(reason) :
                           json_object_new_null());
    json_object_object_add(state, "observed_at",
                           json_object_new_int64(observed_at));
    return state;
}

static void apd_iw_copy_channel(struct json_object *radio,
                                struct json_object *interface)
{
    struct json_object *existing = NULL;
    struct json_object *value = NULL;
    static const char *const keys[] = {
        "channel", "frequency_mhz", "width_mhz", "band", NULL
    };
    size_t i;

    if (json_object_object_get_ex(radio, "channel", &existing))
        return;
    for (i = 0; keys[i]; i++)
        if (json_object_object_get_ex(interface, keys[i], &value))
            json_object_object_add(radio, keys[i], json_object_get(value));
}

static int apd_iw_uint(const char *text, unsigned int *out)
{
    char *end = NULL;
    unsigned long value;

    if (!text || !text[0] || !out || (text[0] == '0' && text[1]))
        return -1;
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno == ERANGE || !end || end == text || *end || value > UINT_MAX)
        return -1;
    *out = (unsigned int)value;
    return 0;
}

static int apd_iw_radio_netdev(const char *name, unsigned int *index)
{
    return name && !strncmp(name, "wifi", 4) &&
           apd_iw_uint(name + 4, index) == 0;
}

static const char *apd_iw_string(struct json_object *object, const char *key)
{
    struct json_object *value = NULL;

    return object && json_object_object_get_ex(object, key, &value) && value &&
           json_object_is_type(value, json_type_string) ?
           json_object_get_string(value) : NULL;
}

static int apd_iw_int(struct json_object *object, const char *key, int *out)
{
    struct json_object *value = NULL;

    if (!object || !out || !json_object_object_get_ex(object, key, &value) ||
        !value || !json_object_is_type(value, json_type_int))
        return -1;
    *out = json_object_get_int(value);
    return 0;
}

static int apd_iw_array_has_int(struct json_object *array, unsigned int value)
{
    size_t i;

    for (i = 0; array && i < json_object_array_length(array); i++) {
        struct json_object *entry = json_object_array_get_idx(array, i);

        if (entry && json_object_get_int64(entry) == (int64_t)value)
            return 1;
    }
    return 0;
}

static void apd_iw_parse_radios(const char *text, struct json_object *interface)
{
    struct json_object *indexes = json_object_new_array();
    const char *cursor = text;

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
            break;
        if (!apd_iw_array_has_int(indexes, (unsigned int)value))
            json_object_array_add(indexes, json_object_new_int64(value));
        cursor = end;
    }
    if (json_object_array_length(indexes))
        json_object_object_add(interface, "radio_indexes", indexes);
    else
        json_object_put(indexes);
}

static void apd_iw_parse_channel(const char *value,
                                 struct json_object *target)
{
    int channel = 0;
    int frequency = 0;
    int width = 0;

    if (!target || sscanf(value, "channel %d (%d MHz), width: %d MHz",
                          &channel, &frequency, &width) < 2)
        return;
    json_object_object_add(target, "channel", json_object_new_int(channel));
    json_object_object_add(target, "frequency_mhz",
                           json_object_new_int(frequency));
    json_object_object_add(target, "band",
        json_object_new_string(apd_iw_band_from_frequency(frequency)));
    if (width > 0)
        json_object_object_add(target, "width_mhz",
                               json_object_new_int(width));
}

static struct json_object *apd_iw_radio_new(const char *phy,
                                            unsigned int radio_index,
                                            int logical,
                                            int64_t observed_at)
{
    struct json_object *radio = json_object_new_object();
    struct json_object *interfaces = json_object_new_array();
    char id[64];

    snprintf(id, sizeof(id), logical ? "%sr%u" : "%s", phy, radio_index);
    json_object_object_add(radio, "id", json_object_new_string(id));
    json_object_object_add(radio, "phy", json_object_new_string(phy));
    if (logical)
        json_object_object_add(radio, "radio_index",
                               json_object_new_int64(radio_index));
    json_object_object_add(radio, "interfaces", interfaces);
    json_object_object_add(radio, "runtime",
                           apd_iw_runtime_meta(1, NULL, observed_at));
    return radio;
}

static struct json_object *apd_iw_logical_radio(struct json_object *radios,
                                                unsigned int index)
{
    size_t i;

    for (i = 0; radios && i < json_object_array_length(radios); i++) {
        struct json_object *radio = json_object_array_get_idx(radios, i);
        int observed = -1;

        if (apd_iw_int(radio, "radio_index", &observed) == 0 &&
            observed >= 0 && (unsigned int)observed == index)
            return radio;
    }
    return NULL;
}

static int apd_iw_interface_radio(struct json_object *interface,
                                  struct json_object *logical_radios,
                                  unsigned int *radio_index)
{
    const char *name = apd_iw_string(interface, "interface");
    struct json_object *explicit_indexes = NULL;
    const char *band = apd_iw_string(interface, "band");
    unsigned int parsed = 0;
    size_t i;
    int matches = 0;

    if (apd_iw_radio_netdev(name, &parsed) &&
        apd_iw_logical_radio(logical_radios, parsed)) {
        *radio_index = parsed;
        return 0;
    }
    if (json_object_object_get_ex(interface, "radio_indexes",
                                  &explicit_indexes) &&
        json_object_array_length(explicit_indexes) == 1) {
        int64_t value = json_object_get_int64(
            json_object_array_get_idx(explicit_indexes, 0));

        if (value >= 0 && value <= UINT_MAX &&
            apd_iw_logical_radio(logical_radios, (unsigned int)value)) {
            *radio_index = (unsigned int)value;
            return 0;
        }
    }
    for (i = 0; band && i < json_object_array_length(logical_radios); i++) {
        struct json_object *radio = json_object_array_get_idx(logical_radios, i);
        const char *radio_band = apd_iw_string(radio, "band");
        int index = -1;

        if (!radio_band || strcmp(radio_band, band) ||
            apd_iw_int(radio, "radio_index", &index) != 0 || index < 0)
            continue;
        *radio_index = (unsigned int)index;
        matches++;
    }
    return matches == 1 ? 0 : -1;
}

static void apd_iw_add_normal_ssid(struct json_object *ssids,
                                   struct json_object *interface,
                                   struct json_object *radio,
                                   int64_t observed_at)
{
    struct json_object *item;
    struct json_object *value = NULL;
    const char *type = apd_iw_string(interface, "type");
    const char *name = apd_iw_string(interface, "interface");
    const char *ssid = apd_iw_string(interface, "broadcast_name");
    const char *radio_id = apd_iw_string(radio, "id");
    static const char *const keys[] = {
        "bssid", "channel", "frequency_mhz", "width_mhz",
        "band", "txpower_dbm", NULL
    };
    size_t i;

    if (!type || strcmp(type, "AP") || !name || !ssid || !ssid[0] ||
        !radio_id)
        return;
    item = json_object_new_object();
    json_object_object_add(item, "id", json_object_new_string(name));
    json_object_object_add(item, "radio_id", json_object_new_string(radio_id));
    json_object_object_add(item, "interface", json_object_new_string(name));
    json_object_object_add(item, "broadcast_name", json_object_new_string(ssid));
    json_object_object_add(item, "mode", json_object_new_string("ap"));
    json_object_object_add(item, "mlo", json_object_new_boolean(0));
    for (i = 0; keys[i]; i++)
        if (json_object_object_get_ex(interface, keys[i], &value))
            json_object_object_add(item, keys[i], json_object_get(value));
    json_object_object_add(item, "runtime",
                           apd_iw_runtime_meta(1, NULL, observed_at));
    json_object_array_add(ssids, item);
}

static void apd_iw_add_mlo_ssid(struct json_object *ssids,
                                struct json_object *interface,
                                const char *phy,
                                struct json_object *logical_radios,
                                int64_t observed_at)
{
    struct json_object *item;
    struct json_object *links = NULL;
    struct json_object *radio_ids = json_object_new_array();
    struct json_object *value = NULL;
    const char *name = apd_iw_string(interface, "interface");
    const char *ssid = apd_iw_string(interface, "broadcast_name");
    size_t i;

    if (!name || !ssid || !ssid[0] ||
        !json_object_object_get_ex(interface, "links", &links) ||
        !json_object_array_length(links)) {
        json_object_put(radio_ids);
        return;
    }
    for (i = 0; i < json_object_array_length(links); i++) {
        struct json_object *link = json_object_array_get_idx(links, i);
        int link_id = -1;
        char radio_id[64];

        if (apd_iw_int(link, "link_id", &link_id) != 0 || link_id < 0 ||
            !apd_iw_logical_radio(logical_radios, (unsigned int)link_id))
            continue;
        snprintf(radio_id, sizeof(radio_id), "%sr%d", phy, link_id);
        json_object_object_add(link, "radio_id",
                               json_object_new_string(radio_id));
        json_object_array_add(radio_ids, json_object_new_string(radio_id));
    }
    if (!json_object_array_length(radio_ids)) {
        json_object_put(radio_ids);
        return;
    }
    item = json_object_new_object();
    json_object_object_add(item, "id", json_object_new_string(name));
    json_object_object_add(item, "interface", json_object_new_string(name));
    json_object_object_add(item, "broadcast_name", json_object_new_string(ssid));
    json_object_object_add(item, "mode", json_object_new_string("ap"));
    json_object_object_add(item, "mlo", json_object_new_boolean(1));
    json_object_object_add(item, "radio_ids", radio_ids);
    json_object_object_add(item, "radio_id", json_object_get(
        json_object_array_get_idx(radio_ids, 0)));
    json_object_object_add(item, "links", json_object_get(links));
    if (json_object_object_get_ex(interface, "bssid", &value))
        json_object_object_add(item, "bssid", json_object_get(value));
    json_object_object_add(item, "runtime",
                           apd_iw_runtime_meta(1, NULL, observed_at));
    json_object_array_add(ssids, item);
}

static void apd_iw_emit_wiphy(struct json_object *parsed,
                              struct json_object *radios,
                              struct json_object *ssids,
                              int64_t observed_at)
{
    struct json_object *interfaces = NULL;
    struct json_object *logical = json_object_new_array();
    const char *phy = apd_iw_string(parsed, "id");
    unsigned int anchor_count = 0;
    size_t i;

    if (!phy || !json_object_object_get_ex(parsed, "interfaces", &interfaces))
        goto done;
    for (i = 0; i < json_object_array_length(interfaces); i++) {
        struct json_object *interface = json_object_array_get_idx(interfaces, i);
        const char *name = apd_iw_string(interface, "interface");
        unsigned int index;

        if (apd_iw_radio_netdev(name, &index) && index < APD_IW_RADIO_LIMIT)
            anchor_count++;
    }
    if (anchor_count < 2) {
        struct json_object *radio = apd_iw_radio_new(phy, 0, 0, observed_at);
        struct json_object *target = NULL;

        json_object_object_get_ex(radio, "interfaces", &target);
        for (i = 0; i < json_object_array_length(interfaces); i++) {
            struct json_object *interface = json_object_array_get_idx(interfaces, i);

            json_object_array_add(target, json_object_get(interface));
            apd_iw_copy_channel(radio, interface);
            apd_iw_add_normal_ssid(ssids, interface, radio, observed_at);
        }
        json_object_array_add(radios, radio);
        goto done;
    }
    for (i = 0; i < json_object_array_length(interfaces); i++) {
        struct json_object *interface = json_object_array_get_idx(interfaces, i);
        const char *name = apd_iw_string(interface, "interface");
        unsigned int index;
        struct json_object *radio;

        if (!apd_iw_radio_netdev(name, &index) ||
            index >= APD_IW_RADIO_LIMIT ||
            apd_iw_logical_radio(logical, index))
            continue;
        radio = apd_iw_radio_new(phy, index, 1, observed_at);
        json_object_object_add(radio, "radio_netdev",
                               json_object_new_string(name));
        apd_iw_copy_channel(radio, interface);
        json_object_array_add(logical, radio);
    }
    for (i = 0; i < json_object_array_length(interfaces); i++) {
        struct json_object *interface = json_object_array_get_idx(interfaces, i);
        struct json_object *links = NULL;
        struct json_object *radio;
        struct json_object *target = NULL;
        unsigned int index;

        if (json_object_object_get_ex(interface, "links", &links) &&
            json_object_array_length(links)) {
            apd_iw_add_mlo_ssid(ssids, interface, phy, logical, observed_at);
            continue;
        }
        if (apd_iw_interface_radio(interface, logical, &index) != 0 ||
            !(radio = apd_iw_logical_radio(logical, index)))
            continue;
        json_object_object_get_ex(radio, "interfaces", &target);
        json_object_array_add(target, json_object_get(interface));
        apd_iw_copy_channel(radio, interface);
        apd_iw_add_normal_ssid(ssids, interface, radio, observed_at);
    }
    while (json_object_array_length(logical)) {
        struct json_object *radio = json_object_array_get_idx(logical, 0);

        json_object_array_add(radios, json_object_get(radio));
        json_object_array_del_idx(logical, 0, 1);
    }
done:
    json_object_put(logical);
}

int apd_iw_topology_parse(const char *text, struct json_object *radios,
                          struct json_object *ssids, int64_t observed_at)
{
    char *copy = strdup(text ? text : "");
    char *line;
    char *saveptr = NULL;
    struct json_object *wiphys = json_object_new_array();
    struct json_object *wiphy = NULL;
    struct json_object *interfaces = NULL;
    struct json_object *interface = NULL;
    struct json_object *link = NULL;
    size_t i;

    if (!copy || !wiphys || !radios || !ssids) {
        free(copy);
        json_object_put(wiphys);
        return -1;
    }
    for (line = strtok_r(copy, "\n", &saveptr); line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        char *value = apd_iw_trim(line);

        if (!strncmp(value, "phy#", 4)) {
            char id[64];
            unsigned int index;

            interface = NULL;
            link = NULL;
            if (apd_iw_uint(value + 4, &index) != 0) {
                wiphy = NULL;
                continue;
            }
            snprintf(id, sizeof(id), "phy%u", index);
            wiphy = json_object_new_object();
            interfaces = json_object_new_array();
            json_object_object_add(wiphy, "id", json_object_new_string(id));
            json_object_object_add(wiphy, "interfaces", interfaces);
            json_object_array_add(wiphys, wiphy);
            continue;
        }
        if (!wiphy)
            continue;
        if (!strncmp(value, "Interface ", 10)) {
            if (!value[10])
                continue;
            interface = json_object_new_object();
            link = NULL;
            json_object_object_add(interface, "interface",
                                   json_object_new_string(value + 10));
            json_object_array_add(interfaces, interface);
            continue;
        }
        if (!interface)
            continue;
        if (!strncmp(value, "link ", 5) && strchr(value, ':')) {
            int link_id = -1;
            struct json_object *links = NULL;

            if (sscanf(value, "link %d:", &link_id) != 1 || link_id < 0)
                continue;
            if (!json_object_object_get_ex(interface, "links", &links)) {
                links = json_object_new_array();
                json_object_object_add(interface, "links", links);
            }
            link = json_object_new_object();
            json_object_object_add(link, "link_id",
                                   json_object_new_int(link_id));
            json_object_array_add(links, link);
            continue;
        }
        if (!strcmp(value, "MLD with links:")) {
            struct json_object *links = NULL;

            if (!json_object_object_get_ex(interface, "links", &links))
                json_object_object_add(interface, "links",
                                       json_object_new_array());
            continue;
        }
        if (!strncmp(value, "addr ", 5))
            json_object_object_add(link ? link : interface, "bssid",
                                   json_object_new_string(value + 5));
        else if (!strncmp(value, "type ", 5))
            json_object_object_add(interface, "type",
                                   json_object_new_string(value + 5));
        else if (!strncmp(value, "ssid ", 5))
            json_object_object_add(interface, "broadcast_name",
                                   json_object_new_string(value + 5));
        else if (!strncmp(value, "wdev ", 5))
            json_object_object_add(interface, "wdev",
                                   json_object_new_string(value + 5));
        else if (!strncmp(value, "ifindex ", 8))
            json_object_object_add(interface, "ifindex",
                                   json_object_new_int(atoi(value + 8)));
        else if (!strncmp(value, "channel ", 8))
            apd_iw_parse_channel(value, link ? link : interface);
        else if (!strncmp(value, "txpower ", 8))
            json_object_object_add(link ? link : interface, "txpower_dbm",
                                   json_object_new_double(
                                       strtod(value + 8, NULL)));
        else if (!strncmp(value, "Radios:", 7))
            apd_iw_parse_radios(value + 7, interface);
    }
    for (i = 0; i < json_object_array_length(wiphys); i++)
        apd_iw_emit_wiphy(json_object_array_get_idx(wiphys, i), radios, ssids,
                          observed_at);
    json_object_put(wiphys);
    free(copy);
    return 0;
}

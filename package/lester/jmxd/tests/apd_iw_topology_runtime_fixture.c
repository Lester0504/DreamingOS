// SPDX-License-Identifier: GPL-2.0-or-later
#include "../src/apd/apd_iw_topology.h"

#include <stdio.h>
#include <string.h>
#include <json-c/json.h>

static struct json_object *object_by_id(struct json_object *array,
                                        const char *id)
{
    size_t i;

    for (i = 0; array && i < json_object_array_length(array); i++) {
        struct json_object *item = json_object_array_get_idx(array, i);
        struct json_object *value = NULL;

        if (item && json_object_object_get_ex(item, "id", &value) &&
            value && !strcmp(json_object_get_string(value), id))
            return item;
    }
    return NULL;
}

static struct json_object *field(struct json_object *object, const char *name)
{
    struct json_object *value = NULL;

    return object && json_object_object_get_ex(object, name, &value) ? value : NULL;
}

static int expect_qsdk(void)
{
    static const char iw[] =
        "phy#0\n"
        "\tInterface ath2\n\t\tifindex 25\n\t\taddr 46:00:00:00:00:27\n"
        "\t\tssid Main\n\t\ttype AP\n"
        "\t\tchannel 33 (6115 MHz), width: 320 MHz\n\t\ttxpower 24.00 dBm\n"
        "\tInterface ath1\n\t\tifindex 24\n\t\taddr 44:00:00:00:00:25\n"
        "\t\tssid Main\n\t\ttype AP\n"
        "\t\tchannel 36 (5180 MHz), width: 160 MHz\n\t\ttxpower 28.00 dBm\n"
        "\tInterface ath0\n\t\tifindex 23\n\t\taddr 44:00:00:00:00:26\n"
        "\t\tssid Main\n\t\ttype AP\n"
        "\t\tchannel 10 (2457 MHz), width: 20 MHz\n\t\ttxpower 28.00 dBm\n"
        "\tInterface MLD1\n\t\tifindex 20\n\t\taddr 02:00:00:00:00:2e\n"
        "\t\tssid Main-MLO\n\t\ttype AP\n\t\tMLD with links:\n"
        "\t\tlink 0:\n\t\t  addr 5a:00:00:00:00:26\n"
        "\t\t  channel 10 (2457 MHz), width: 20 MHz\n\t\t  txpower 28.00 dBm\n"
        "\t\tlink 1:\n\t\t  addr 5a:00:00:00:00:25\n"
        "\t\t  channel 36 (5180 MHz), width: 160 MHz\n\t\t  txpower 28.00 dBm\n"
        "\t\tlink 2:\n\t\t  addr 46:00:00:00:00:28\n"
        "\t\t  channel 33 (6115 MHz), width: 320 MHz\n\t\t  txpower 24.00 dBm\n"
        "\tInterface wifi2\n\t\tifindex 14\n\t\ttype AP\n"
        "\t\tchannel 33 (6115 MHz), width: 320 MHz\n"
        "\tInterface wifi1\n\t\tifindex 13\n\t\ttype AP\n"
        "\t\tchannel 36 (5180 MHz), width: 160 MHz\n"
        "\tInterface wifi0\n\t\tifindex 11\n\t\ttype AP\n"
        "\t\tchannel 10 (2457 MHz), width: 20 MHz\n";
    struct json_object *radios = json_object_new_array();
    struct json_object *ssids = json_object_new_array();
    struct json_object *mlo;
    struct json_object *radio;
    int rc = 1;

    if (!radios || !ssids || apd_iw_topology_parse(iw, radios, ssids, 123) != 0 ||
        json_object_array_length(radios) != 3 ||
        json_object_array_length(ssids) != 4)
        goto done;
    radio = object_by_id(radios, "phy0r0");
    if (!radio || json_object_get_int(field(radio, "frequency_mhz")) != 2457 ||
        strcmp(json_object_get_string(field(radio, "radio_netdev")), "wifi0") ||
        json_object_array_length(field(radio, "interfaces")) != 2)
        goto done;
    radio = object_by_id(radios, "phy0r1");
    if (!radio || json_object_get_int(field(radio, "width_mhz")) != 160 ||
        json_object_array_length(field(radio, "interfaces")) != 2)
        goto done;
    radio = object_by_id(radios, "phy0r2");
    if (!radio || json_object_get_int(field(radio, "width_mhz")) != 320 ||
        json_object_array_length(field(radio, "interfaces")) != 2)
        goto done;
    mlo = object_by_id(ssids, "MLD1");
    if (!mlo || !json_object_get_boolean(field(mlo, "mlo")) ||
        json_object_array_length(field(mlo, "radio_ids")) != 3 ||
        json_object_array_length(field(mlo, "links")) != 3 ||
        strcmp(json_object_get_string(field(mlo, "broadcast_name")),
               "Main-MLO"))
        goto done;
    rc = 0;
done:
    if (rc) {
        fprintf(stderr, "radios=%s\nssids=%s\n",
            json_object_to_json_string_ext(radios, JSON_C_TO_STRING_PRETTY),
            json_object_to_json_string_ext(ssids, JSON_C_TO_STRING_PRETTY));
    }
    json_object_put(radios);
    json_object_put(ssids);
    return rc;
}

static int expect_legacy(void)
{
    static const char iw[] =
        "phy#7\n\tInterface wlan0\n\t\tifindex 9\n"
        "\t\tssid Legacy\n\t\ttype AP\n"
        "\t\tchannel 1 (2412 MHz), width: 40 MHz\n";
    struct json_object *radios = json_object_new_array();
    struct json_object *ssids = json_object_new_array();
    struct json_object *radio;
    int rc = 1;

    if (apd_iw_topology_parse(iw, radios, ssids, 456) != 0 ||
        json_object_array_length(radios) != 1 ||
        json_object_array_length(ssids) != 1)
        goto done;
    radio = object_by_id(radios, "phy7");
    if (!radio || field(radio, "radio_index") ||
        json_object_get_int(field(radio, "channel")) != 1)
        goto done;
    rc = 0;
done:
    json_object_put(radios);
    json_object_put(ssids);
    return rc;
}

int main(void)
{
    if (expect_qsdk() || expect_legacy())
        return 1;
    puts("ok: APD iw topology maps QSDK logical radios, one MLO SSID, and legacy wiphys");
    return 0;
}

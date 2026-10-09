// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <json-c/json.h>
#include <sqlite3.h>

#define AP_A "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
#define AP_B "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
#define EPOCH_A "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define EPOCH_B "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

struct ac_device_model_report {
    char model[256];
    char board_name[128];
    char model_source[64];
    char reason[128];
    int model_available;
};

extern sqlite3 *g_ac_db;
int ac_db_init(void);
void ac_db_close(void);
int ac_db_ap_session_begin(const char *, const char *, int, int64_t);
int ac_db_ap_telemetry_store(const char *, const char *, int64_t, int64_t,
                             int64_t, const char *,
                             const struct ac_device_model_report *,
                             struct json_object *);
struct json_object *ac_db_ap_traffic_history_json(const char *, const char *);

static struct json_object *snapshot(int64_t observed_at, const char *interface,
                                    int64_t connected_time_seconds,
                                    int64_t rx_bytes, int64_t tx_bytes)
{
    struct json_object *root = json_object_new_object();
    struct json_object *radios = json_object_new_array();
    struct json_object *ssids = json_object_new_array();
    struct json_object *stations = json_object_new_array();
    struct json_object *sources = json_object_new_object();
    struct json_object *hostapd = json_object_new_object();
    struct json_object *radio = json_object_new_object();
    struct json_object *ssid = json_object_new_object();
    struct json_object *station = json_object_new_object();

    json_object_object_add(root, "observed_at",
                           json_object_new_int64(observed_at));
    json_object_object_add(root, "complete", json_object_new_boolean(1));
    json_object_object_add(radio, "id", json_object_new_string("phy0"));
    json_object_array_add(radios, radio);
    json_object_object_add(ssid, "id", json_object_new_string(interface));
    json_object_object_add(ssid, "radio_id", json_object_new_string("phy0"));
    json_object_object_add(ssid, "interface", json_object_new_string(interface));
    json_object_array_add(ssids, ssid);
    json_object_object_add(station, "mac",
                           json_object_new_string("02:00:00:00:00:01"));
    json_object_object_add(station, "interface",
                           json_object_new_string(interface));
    json_object_object_add(station, "connected_time_seconds",
                           json_object_new_int64(connected_time_seconds));
    json_object_object_add(station, "rx_bytes",
                           json_object_new_int64(rx_bytes));
    json_object_object_add(station, "tx_bytes",
                           json_object_new_int64(tx_bytes));
    json_object_array_add(stations, station);
    json_object_object_add(hostapd, "available", json_object_new_boolean(1));
    json_object_object_add(hostapd, "complete", json_object_new_boolean(1));
    json_object_object_add(sources, "hostapd", hostapd);
    json_object_object_add(root, "radios", radios);
    json_object_object_add(root, "ssids", ssids);
    json_object_object_add(root, "stations", stations);
    json_object_object_add(root, "sources", sources);
    return root;
}

static int store_pair(const char *ap_id, const char *epoch, int64_t now,
                      int64_t first_rx, int64_t first_tx,
                      int64_t second_rx, int64_t second_tx)
{
    struct ac_device_model_report report = {0};
    struct json_object *first = snapshot(now - 120, "wlan0", 60,
                                         first_rx, first_tx);
    struct json_object *second = snapshot(now - 60, "wlan0", 120,
                                          second_rx, second_tx);
    int rc;

    snprintf(report.model, sizeof(report.model), "Fixture AP");
    snprintf(report.board_name, sizeof(report.board_name), "fixture,ap");
    snprintf(report.model_source, sizeof(report.model_source), "fixture");
    report.model_available = 1;
    rc = ac_db_ap_session_begin(ap_id, epoch, 2, now - 125) ||
         ac_db_ap_telemetry_store(ap_id, epoch, 1, now - 120, now - 119,
             "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
             &report, first) ||
         ac_db_ap_telemetry_store(ap_id, epoch, 2, now - 60, now - 59,
             "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
             &report, second);
    json_object_put(first);
    json_object_put(second);
    return rc;
}

static struct json_object *point(struct json_object *root)
{
    struct json_object *points = NULL;

    if (!root || !json_object_object_get_ex(root, "points", &points) ||
        json_object_array_length(points) != 1)
        return NULL;
    return json_object_array_get_idx(points, 0);
}

static int64_t value_i64(struct json_object *object, const char *name)
{
    struct json_object *value = NULL;

    return object && json_object_object_get_ex(object, name, &value) ?
        json_object_get_int64(value) : -1;
}

static const char *value_string(struct json_object *object, const char *name)
{
    struct json_object *value = NULL;

    return object && json_object_object_get_ex(object, name, &value) ?
        json_object_get_string(value) : "";
}

static int rates_at_most(struct json_object *root, int64_t max_up,
                         int64_t max_down)
{
    struct json_object *points = NULL;
    size_t i;

    if (!root || !json_object_object_get_ex(root, "points", &points) ||
        !json_object_is_type(points, json_type_array) ||
        json_object_array_length(points) == 0)
        return 0;
    for (i = 0; i < json_object_array_length(points); i++) {
        struct json_object *item = json_object_array_get_idx(points, i);
        int64_t up = value_i64(item, "up_rate");
        int64_t down = value_i64(item, "down_rate");

        if (up < 0 || down < 0 || up > max_up || down > max_down)
            return 0;
    }
    return 1;
}

int main(void)
{
    struct ac_device_model_report report = {0};
    struct json_object *all = NULL;
    struct json_object *single = NULL;
    struct json_object *online_all = NULL;
    struct json_object *offline_single = NULL;
    struct json_object *reset = NULL;
    struct json_object *roam = NULL;
    struct json_object *reconnect = NULL;
    struct json_object *reset_snapshot = NULL;
    struct json_object *roam_snapshot = NULL;
    struct json_object *reconnect_snapshot = NULL;
    struct json_object *range_history = NULL;
    struct json_object *p;
    const char *ranges[] = {"1d", "1w", "1m"};
    size_t i;
    int64_t now = time(NULL);
    int rc = 1;

    snprintf(report.model, sizeof(report.model), "Fixture AP");
    snprintf(report.board_name, sizeof(report.board_name), "fixture,ap");
    snprintf(report.model_source, sizeof(report.model_source), "fixture");
    report.model_available = 1;
    if (ac_db_init() != 0 || sqlite3_exec(g_ac_db,
            "INSERT INTO ac_aps(ap_id,site_id,name,adoption_state,last_seen_at) VALUES"
            "('" AP_A "','default','AP A','adopted',1),"
            "('" AP_B "','default','AP B','adopted',1)",
            NULL, NULL, NULL) != SQLITE_OK ||
        store_pair(AP_A, EPOCH_A, now - 120, 1000, 2000, 7000, 14000) != 0 ||
        store_pair(AP_B, EPOCH_B, now - 120, 500, 800, 3500, 6800) != 0 ||
        sqlite3_exec(g_ac_db,
            "UPDATE ac_aps SET last_seen_at=CAST(strftime('%s','now') AS INTEGER)",
            NULL, NULL, NULL) != SQLITE_OK)
        goto done;
    all = ac_db_ap_traffic_history_json("1h", "all");
    single = ac_db_ap_traffic_history_json("1h", AP_A);
    p = point(all);
    if (!p || value_i64(p, "up_rate") != 150 ||
        value_i64(p, "down_rate") != 300 ||
        value_i64(p, "ap_count") != 2 ||
        strcmp(value_string(all, "scope"), "ap") ||
        strcmp(value_string(all, "direction"), "wireless_station") ||
        strcmp(value_string(all, "reason"), "available"))
        goto done;
    p = point(single);
    if (!p || value_i64(p, "up_rate") != 100 ||
        value_i64(p, "down_rate") != 200 || value_i64(p, "ap_count") != 1)
        goto done;

    if (sqlite3_exec(g_ac_db,
            "UPDATE ac_aps SET last_seen_at="
            "CAST(strftime('%s','now') AS INTEGER)-46 WHERE ap_id='" AP_B "'",
            NULL, NULL, NULL) != SQLITE_OK)
        goto done;
    online_all = ac_db_ap_traffic_history_json("1h", "all");
    offline_single = ac_db_ap_traffic_history_json("1h", AP_B);
    p = point(online_all);
    if (!p || value_i64(p, "up_rate") != 100 ||
        value_i64(p, "down_rate") != 200 || value_i64(p, "ap_count") != 1)
        goto done;
    p = point(offline_single);
    if (!p || value_i64(p, "up_rate") != 50 ||
        value_i64(p, "down_rate") != 100 || value_i64(p, "ap_count") != 1)
        goto done;

    reset_snapshot = snapshot(now - 120, "wlan0", 180, 10, 20);
    if (ac_db_ap_telemetry_store(AP_A, EPOCH_A, 3, now - 120, now - 119,
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            &report, reset_snapshot) != 0)
        goto done;
    reset = ac_db_ap_traffic_history_json("1h", AP_A);
    if (value_i64(reset, "counter_reset_count") != 1)
        goto done;
    if (!rates_at_most(reset, 100, 200))
        goto done;

    roam_snapshot = snapshot(now - 60, "wlan1", 30,
                             900000000, 900000000);
    if (ac_db_ap_telemetry_store(AP_A, EPOCH_A, 4, now - 60, now - 59,
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            &report, roam_snapshot) != 0)
        goto done;
    roam = ac_db_ap_traffic_history_json("1h", AP_A);
    if (!rates_at_most(roam, 100, 200))
        goto done;
    reconnect_snapshot = snapshot(now - 1, "wlan1", 10,
                                  1800000000, 1800000000);
    if (ac_db_ap_telemetry_store(AP_A, EPOCH_A, 5, now - 1, now,
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            &report, reconnect_snapshot) != 0)
        goto done;
    reconnect = ac_db_ap_traffic_history_json("1h", AP_A);
    if (value_i64(reconnect, "counter_reset_count") != 2 ||
        !rates_at_most(reconnect, 100, 200))
        goto done;
    for (i = 0; i < sizeof(ranges) / sizeof(ranges[0]); i++) {
        range_history = ac_db_ap_traffic_history_json(ranges[i], AP_A);
        if (!range_history || strcmp(value_string(range_history, "scope"), "ap") ||
            strcmp(value_string(range_history, "range"), ranges[i]))
            goto done;
        json_object_put(range_history);
        range_history = NULL;
    }
    printf("all_up=150 all_down=300 single_up=100 single_down=200 "
           "resets=2 roam_spike=0 reconnect_spike=0 "
           "ranges=1h,1d,1w,1m schema=stable\n");
    rc = 0;
done:
    json_object_put(all);
    json_object_put(single);
    json_object_put(online_all);
    json_object_put(offline_single);
    json_object_put(reset);
    json_object_put(roam);
    json_object_put(reconnect);
    json_object_put(reset_snapshot);
    json_object_put(roam_snapshot);
    json_object_put(reconnect_snapshot);
    json_object_put(range_history);
    ac_db_close();
    return rc;
}

// SPDX-License-Identifier: GPL-2.0-or-later
/* Runtime contract for the AC station connectivity event store fed by the
 * snapshot-diff producer (source=ac_snapshot_diff).  Verifies:
 *   - connect/roam/disconnect derivation from consecutive authoritative
 *     hostapd inventories in one session epoch;
 *   - no events across non-authoritative or over-wide observation windows
 *     (degraded collection must not fabricate disconnects);
 *   - stable event_id cursor, filters, pagination and bounded retention.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>
#include <sqlite3.h>

#define AP_ID "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
#define EPOCH "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define BASE 10000000

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
struct json_object *ac_db_station_events_json(const char *, const char *,
                                              int64_t, int64_t, int,
                                              int64_t);

static int scalar(const char *sql)
{
    sqlite3_stmt *st = NULL;
    int result = -1;

    if (sqlite3_prepare_v2(g_ac_db, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        result = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return result;
}

static void snapshot_add_ssid(struct json_object *ssids, const char *id,
                              const char *interface, const char *radio_id,
                              const char *bssid)
{
    struct json_object *item = json_object_new_object();

    json_object_object_add(item, "id", json_object_new_string(id));
    json_object_object_add(item, "interface",
                           json_object_new_string(interface));
    json_object_object_add(item, "radio_id",
                           json_object_new_string(radio_id));
    json_object_object_add(item, "bssid", json_object_new_string(bssid));
    json_object_array_add(ssids, item);
}

static void snapshot_add_station(struct json_object *stations,
                                 const char *mac, const char *interface,
                                 int signal_dbm)
{
    struct json_object *item = json_object_new_object();

    json_object_object_add(item, "mac", json_object_new_string(mac));
    json_object_object_add(item, "interface",
                           json_object_new_string(interface));
    json_object_object_add(item, "signal_dbm",
                           json_object_new_int(signal_dbm));
    json_object_array_add(stations, item);
}

static struct json_object *snapshot_new(int64_t observed_at,
                                        int hostapd_authoritative)
{
    struct json_object *root = json_object_new_object();
    struct json_object *radios = json_object_new_array();
    struct json_object *radio = json_object_new_object();
    struct json_object *ssids = json_object_new_array();
    struct json_object *sources = json_object_new_object();
    struct json_object *hostapd = json_object_new_object();

    json_object_object_add(root, "observed_at",
                           json_object_new_int64(observed_at));
    json_object_object_add(root, "complete", json_object_new_boolean(1));
    json_object_object_add(radio, "id", json_object_new_string("phy0"));
    json_object_array_add(radios, radio);
    json_object_object_add(root, "radios", radios);
    snapshot_add_ssid(ssids, "main0", "wlan0", "phy0", "02:aa:00:00:00:01");
    snapshot_add_ssid(ssids, "main1", "wlan1", "phy1", "02:aa:00:00:00:02");
    json_object_object_add(root, "ssids", ssids);
    json_object_object_add(root, "stations", json_object_new_array());
    json_object_object_add(hostapd, "available",
                           json_object_new_boolean(1));
    json_object_object_add(hostapd, "complete",
                           json_object_new_boolean(hostapd_authoritative));
    json_object_object_add(sources, "hostapd", hostapd);
    json_object_object_add(root, "sources", sources);
    return root;
}

static struct json_object *snapshot_stations(struct json_object *snapshot)
{
    struct json_object *stations = NULL;

    json_object_object_get_ex(snapshot, "stations", &stations);
    return stations;
}

static int store_snapshot(const struct ac_device_model_report *report,
                          int64_t sequence, int64_t observed_at,
                          struct json_object *snapshot)
{
    char snapshot_id[80];
    int rc;

    snprintf(snapshot_id, sizeof(snapshot_id), "fixture-%lld",
             (long long)sequence);
    rc = ac_db_ap_telemetry_store(AP_ID, EPOCH, sequence, observed_at,
                                  observed_at, snapshot_id, report, snapshot);
    json_object_put(snapshot);
    return rc;
}

static const char *item_string(struct json_object *item, const char *key)
{
    struct json_object *value = NULL;

    if (!json_object_object_get_ex(item, key, &value) || !value)
        return "";
    return json_object_get_string(value);
}

static int events_contract(void)
{
    struct ac_device_model_report report = {0};
    struct json_object *snapshot;
    struct json_object *page = NULL;
    struct json_object *items = NULL;
    struct json_object *value = NULL;
    struct json_object *item;
    int64_t cursor;
    int rc = -1;

    snprintf(report.model, sizeof(report.model), "Fixture AP");
    snprintf(report.board_name, sizeof(report.board_name), "fixture,ap");
    snprintf(report.model_source, sizeof(report.model_source), "fixture");
    report.model_available = 1;
    if (sqlite3_exec(g_ac_db,
            "INSERT INTO ac_aps(ap_id,site_id,name,adoption_state,last_seen_at) "
            "VALUES('" AP_ID "','default','Fixture AP','adopted',10000000)",
            NULL, NULL, NULL) != SQLITE_OK ||
        ac_db_ap_session_begin(AP_ID, EPOCH, 2, BASE) != 0)
        return -1;

    /* seq 1: A@wlan0.  First snapshot in the epoch: no diff basis. */
    snapshot = snapshot_new(BASE, 1);
    snapshot_add_station(snapshot_stations(snapshot),
                         "00:11:22:33:44:aa", "wlan0", -48);
    if (store_snapshot(&report, 1, BASE, snapshot) != 0 ||
        scalar("SELECT COUNT(*) FROM ac_station_events") != 0)
        return -1;

    /* seq 2: A@wlan0 + B@wlan0 -> one connect for B. */
    snapshot = snapshot_new(BASE + 300, 1);
    snapshot_add_station(snapshot_stations(snapshot),
                         "00:11:22:33:44:aa", "wlan0", -49);
    snapshot_add_station(snapshot_stations(snapshot),
                         "00:11:22:33:44:bb", "wlan0", -60);
    if (store_snapshot(&report, 2, BASE + 300, snapshot) != 0 ||
        scalar("SELECT COUNT(*) FROM ac_station_events") != 1 ||
        scalar("SELECT COUNT(*) FROM ac_station_events "
               "WHERE event='connect' AND station_mac='00:11:22:33:44:bb' "
               "AND to_bssid='02:aa:00:00:00:01' AND signal_dbm=-60 "
               "AND window_started_at=10000000") != 1)
        return -1;

    /* seq 3: A moves wlan0 -> wlan1 -> one roam, no fake disconnect. */
    snapshot = snapshot_new(BASE + 600, 1);
    snapshot_add_station(snapshot_stations(snapshot),
                         "00:11:22:33:44:aa", "wlan1", -55);
    snapshot_add_station(snapshot_stations(snapshot),
                         "00:11:22:33:44:bb", "wlan0", -61);
    if (store_snapshot(&report, 3, BASE + 600, snapshot) != 0 ||
        scalar("SELECT COUNT(*) FROM ac_station_events") != 2 ||
        scalar("SELECT COUNT(*) FROM ac_station_events WHERE event='roam' "
               "AND station_mac='00:11:22:33:44:aa' "
               "AND from_interface='wlan0' AND interface='wlan1' "
               "AND from_bssid='02:aa:00:00:00:01' "
               "AND to_bssid='02:aa:00:00:00:02' "
               "AND previous_signal_dbm=-49 AND signal_dbm=-55") != 1)
        return -1;

    /* seq 4: A gone -> one disconnect with last known signal. */
    snapshot = snapshot_new(BASE + 900, 1);
    snapshot_add_station(snapshot_stations(snapshot),
                         "00:11:22:33:44:bb", "wlan0", -62);
    if (store_snapshot(&report, 4, BASE + 900, snapshot) != 0 ||
        scalar("SELECT COUNT(*) FROM ac_station_events") != 3 ||
        scalar("SELECT COUNT(*) FROM ac_station_events "
               "WHERE event='disconnect' "
               "AND station_mac='00:11:22:33:44:aa' "
               "AND from_interface='wlan1' AND previous_signal_dbm=-55 "
               "AND signal_dbm IS NULL") != 1)
        return -1;

    /* seq 5: degraded hostapd collection with an empty station list must
     * not fabricate a disconnect for B. */
    snapshot = snapshot_new(BASE + 1200, 0);
    if (store_snapshot(&report, 5, BASE + 1200, snapshot) != 0 ||
        scalar("SELECT COUNT(*) FROM ac_station_events") != 3)
        return -1;

    /* seq 6: authoritative again, but the previous snapshot was not, so
     * the diff basis is rejected and nothing is invented. */
    snapshot = snapshot_new(BASE + 1500, 1);
    snapshot_add_station(snapshot_stations(snapshot),
                         "00:11:22:33:44:bb", "wlan0", -63);
    if (store_snapshot(&report, 6, BASE + 1500, snapshot) != 0 ||
        scalar("SELECT COUNT(*) FROM ac_station_events") != 3)
        return -1;

    /* seq 7: an over-wide observation window is skipped even when both
     * sides are authoritative. */
    snapshot = snapshot_new(BASE + 1500 + 7200, 1);
    if (store_snapshot(&report, 7, BASE + 1500 + 7200, snapshot) != 0 ||
        scalar("SELECT COUNT(*) FROM ac_station_events") != 3)
        return -1;

    /* Query contract: full window, event filter, cursor pagination. */
    page = ac_db_station_events_json("", "", BASE - 1, BASE + 20000, 256, 0);
    if (!page || !json_object_object_get_ex(page, "ok", &value) ||
        !json_object_get_boolean(value) ||
        !json_object_object_get_ex(page, "items", &items) ||
        json_object_array_length(items) != 3 ||
        !json_object_object_get_ex(page, "source", &value) ||
        strcmp(json_object_get_string(value), "ac_snapshot_diff"))
        goto done;
    item = json_object_array_get_idx(items, 0);
    if (strcmp(item_string(item, "event"), "connect") ||
        strcmp(item_string(item, "ap_id"), AP_ID))
        goto done;
    json_object_put(page);
    page = ac_db_station_events_json(AP_ID, "roam", BASE - 1, BASE + 20000,
                                     256, 0);
    if (!page || !json_object_object_get_ex(page, "items", &items) ||
        json_object_array_length(items) != 1 ||
        strcmp(item_string(json_object_array_get_idx(items, 0), "event"),
               "roam"))
        goto done;
    json_object_put(page);
    page = ac_db_station_events_json("", "", BASE - 1, BASE + 20000, 1, 0);
    if (!page || !json_object_object_get_ex(page, "limited", &value) ||
        !json_object_get_boolean(value) ||
        !json_object_object_get_ex(page, "next_after_id", &value))
        goto done;
    cursor = json_object_get_int64(value);
    json_object_put(page);
    page = ac_db_station_events_json("", "", BASE - 1, BASE + 20000, 256,
                                     cursor);
    if (!page || !json_object_object_get_ex(page, "items", &items) ||
        json_object_array_length(items) != 2 ||
        !json_object_object_get_ex(page, "limited", &value) ||
        json_object_get_boolean(value))
        goto done;
    json_object_put(page);
    page = ac_db_station_events_json("", "", BASE + 19000, BASE + 20000,
                                     256, 0);
    if (!page || !json_object_object_get_ex(page, "items", &items) ||
        json_object_array_length(items) != 0 ||
        !json_object_object_get_ex(page, "reason", &value) ||
        strcmp(json_object_get_string(value), "no_events"))
        goto done;
    json_object_put(page);
    page = NULL;

    /* Bounded retention: flood the table, then one more authoritative
     * diff pass must trim to the newest 4096 rows for this AP. */
    if (sqlite3_exec(g_ac_db,
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n "
            "WHERE x<5000) INSERT INTO ac_station_events(ap_id,event,"
            "station_mac,observed_at,window_started_at,created_at) "
            "SELECT '" AP_ID "','connect','00:11:22:33:44:cc',"
            "10003000+x,10003000+x,10003000+x FROM n;",
            NULL, NULL, NULL) != SQLITE_OK)
        return -1;
    snapshot = snapshot_new(BASE + 1500 + 7500, 1);
    if (store_snapshot(&report, 8, BASE + 1500 + 7500, snapshot) != 0 ||
        scalar("SELECT COUNT(*) FROM ac_station_events "
               "WHERE ap_id='" AP_ID "'") != 4096)
        return -1;

    printf("schema=%d diff_events=3 gated=1 window_bounded=1 "
           "pagination=1 retention=%d\n",
           scalar("SELECT version FROM ac_schema_meta WHERE singleton=1"),
           scalar("SELECT COUNT(*) FROM ac_station_events "
                  "WHERE ap_id='" AP_ID "'"));
    rc = 0;
done:
    json_object_put(page);
    return rc;
}

int main(int argc, char **argv)
{
    int rc;

    if (ac_db_init() != 0)
        return 2;
    if (argc == 2 && !strcmp(argv[1], "init-only")) {
        ac_db_close();
        return 0;
    }
    rc = events_contract();
    ac_db_close();
    return rc == 0 ? 0 : 1;
}

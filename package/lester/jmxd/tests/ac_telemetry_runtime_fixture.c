// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>
#include <sqlite3.h>

#define AP_ID "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
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
int ac_db_ap_session_begin(const char *ap_id, const char *session_epoch,
                           int protocol_version, int64_t received_at);
int ac_db_ap_session_end(const char *ap_id, const char *session_epoch);
int ac_db_scan_execution_available(int64_t online_since, int *ap_count);
int ac_db_ap_telemetry_store(const char *ap_id, const char *session_epoch,
                             int64_t sequence,
                             int64_t observed_at, int64_t received_at,
                             const char *snapshot_id,
                             const struct ac_device_model_report *report,
                             struct json_object *snapshot);
struct json_object *ac_db_aps_list_json(int64_t observed_at,
                                        int64_t online_since);

static int writes;

static void write_hook(void *opaque, int operation, const char *database,
                       const char *table, sqlite3_int64 rowid)
{
    (void)opaque;
    (void)operation;
    (void)database;
    (void)table;
    (void)rowid;
    writes++;
}

static int scalar(const char *sql)
{
    sqlite3_stmt *statement = NULL;
    int value = -1;

    if (sqlite3_prepare_v2(g_ac_db, sql, -1, &statement, NULL) == SQLITE_OK &&
        sqlite3_step(statement) == SQLITE_ROW)
        value = sqlite3_column_int(statement, 0);
    sqlite3_finalize(statement);
    return value;
}

static struct json_object *snapshot_new(int64_t observed_at,
                                        const char *ssid)
{
    struct json_object *root = json_object_new_object();
    struct json_object *radios = json_object_new_array();
    struct json_object *ssids = json_object_new_array();
    struct json_object *stations = json_object_new_array();
    struct json_object *radio = json_object_new_object();
    struct json_object *network = json_object_new_object();
    struct json_object *station = json_object_new_object();

    if (!root || !radios || !ssids || !stations || !radio || !network ||
        !station)
        goto fail;
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "contract_version",
                           json_object_new_string("ap-control.v1"));
    json_object_object_add(root, "snapshot_version",
                           json_object_new_string("wireless-snapshot.v1"));
    json_object_object_add(root, "source",
                           json_object_new_string("dreamingwrt-apd"));
    json_object_object_add(root, "backend", json_object_new_string("fixture"));
    json_object_object_add(root, "observed_at",
                           json_object_new_int64(observed_at));
    json_object_object_add(root, "complete", json_object_new_boolean(1));
    json_object_object_add(root, "stale", json_object_new_boolean(0));
    json_object_object_add(root, "reason", NULL);
    json_object_object_add(root, "wireless_present", json_object_new_boolean(1));
    json_object_object_add(root, "phy_count", json_object_new_int(1));
    json_object_object_add(root, "radio_count", json_object_new_int(1));
    json_object_object_add(root, "ssid_count", json_object_new_int(1));
    json_object_object_add(root, "station_count", json_object_new_int(1));
    json_object_object_add(root, "model", json_object_new_string("Fixture AP 1"));
    json_object_object_add(root, "board_name",
                           json_object_new_string("fixture,ap1"));
    json_object_object_add(root, "model_source",
                           json_object_new_string("ubus_system_board"));
    json_object_object_add(root, "model_available", json_object_new_boolean(1));
    json_object_object_add(root, "model_reason", json_object_new_string(""));
    json_object_object_add(radio, "id", json_object_new_string("phy0"));
    json_object_object_add(radio, "band", json_object_new_string("5GHz"));
    json_object_array_add(radios, radio);
    radio = NULL;
    json_object_object_add(network, "id", json_object_new_string("wlan0"));
    json_object_object_add(network, "radio_id", json_object_new_string("phy0"));
    json_object_object_add(network, "interface", json_object_new_string("wlan0"));
    json_object_object_add(network, "broadcast_name", json_object_new_string(ssid));
    json_object_array_add(ssids, network);
    network = NULL;
    json_object_object_add(station, "mac",
                           json_object_new_string("02:00:00:00:00:01"));
    json_object_object_add(station, "interface", json_object_new_string("wlan0"));
    json_object_object_add(station, "connected_time_seconds",
                           json_object_new_int(60));
    json_object_array_add(stations, station);
    station = NULL;
    json_object_object_add(root, "radios", radios);
    json_object_object_add(root, "ssids", ssids);
    json_object_object_add(root, "stations", stations);
    json_object_object_add(root, "desired", json_object_new_object());
    json_object_object_add(root, "sources", json_object_new_object());
    return root;
fail:
    json_object_put(radio);
    json_object_put(network);
    json_object_put(station);
    json_object_put(radios);
    json_object_put(ssids);
    json_object_put(stations);
    json_object_put(root);
    return NULL;
}

static int aps_list_valid(struct json_object *root)
{
    struct json_object *items = NULL;
    struct json_object *item = NULL;
    struct json_object *runtime = NULL;
    struct json_object *snapshot = NULL;
    struct json_object *capabilities = NULL;
    struct json_object *value = NULL;

    if (!root || !json_object_is_type(root, json_type_object) ||
        !json_object_object_get_ex(root, "ok", &value) ||
        !json_object_get_boolean(value) ||
        !json_object_object_get_ex(root, "contract_version", &value) ||
        strcmp(json_object_get_string(value), "ap-control.v1") != 0 ||
        !json_object_object_get_ex(root, "count", &value) ||
        json_object_get_int(value) != 1 ||
        !json_object_object_get_ex(root, "online", &value) ||
        json_object_get_int(value) != 1 ||
        !json_object_object_get_ex(root, "items", &items) ||
        json_object_array_length(items) != 1 ||
        !(item = json_object_array_get_idx(items, 0)) ||
        !json_object_object_get_ex(item, "reported_model", &value) ||
        strcmp(json_object_get_string(value), "Fixture AP 1") != 0 ||
        !json_object_object_get_ex(item, "model", &value) ||
        strcmp(json_object_get_string(value), "Fixture AP 1") != 0 ||
        !json_object_object_get_ex(item, "override_supported", &value) ||
        json_object_get_boolean(value) ||
        !json_object_object_get_ex(item, "capabilities", &capabilities) ||
        !json_object_object_get_ex(capabilities, "remote_telemetry", &value) ||
        !json_object_get_boolean(value) ||
        !json_object_object_get_ex(item, "control_protocol", &value) ||
        strcmp(json_object_get_string(value), "ap-control.v2") != 0 ||
        !json_object_object_get_ex(item, "session_connected", &value) ||
        !json_object_get_boolean(value) ||
        !json_object_object_get_ex(item, "scan_execution", &value) ||
        !json_object_get_boolean(value) ||
        !json_object_object_get_ex(capabilities, "scan_execution", &value) ||
        !json_object_get_boolean(value) ||
        !json_object_object_get_ex(capabilities, "ssid_create", &value) ||
        json_object_get_boolean(value) ||
        !json_object_object_get_ex(item, "runtime", &runtime) ||
        !json_object_object_get_ex(runtime, "available", &value) ||
        !json_object_get_boolean(value) ||
        !json_object_object_get_ex(runtime, "complete", &value) ||
        !json_object_get_boolean(value) ||
        !json_object_object_get_ex(runtime, "stale", &value) ||
        json_object_get_boolean(value) ||
        !json_object_object_get_ex(runtime, "received_at", &value) ||
        json_object_get_int64(value) != 5110 ||
        !json_object_object_get_ex(runtime, "reason", &value) || value ||
        !json_object_object_get_ex(runtime, "snapshot", &snapshot) ||
        !snapshot ||
        !json_object_object_get_ex(snapshot, "radios", &value) ||
        json_object_array_length(value) != 1 ||
        !json_object_object_get_ex(snapshot, "ssids", &value) ||
        json_object_array_length(value) != 1 ||
        !json_object_object_get_ex(snapshot, "stations", &value) ||
        json_object_array_length(value) != 1)
        return 0;
    return 1;
}

int main(void)
{
    static const char snapshot_a[] =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static const char snapshot_b[] =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    static const char snapshot_c[] =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    struct ac_device_model_report report;
    struct json_object *first = NULL;
    struct json_object *changed = NULL;
    struct json_object *list = NULL;
    int first_writes;
    int changed_writes;
    int session_b_writes;
    int scan_ap_count = 0;
    int rc = 1;

    memset(&report, 0, sizeof(report));
    snprintf(report.model, sizeof(report.model), "%s", "Fixture AP 1");
    snprintf(report.board_name, sizeof(report.board_name), "%s", "fixture,ap1");
    snprintf(report.model_source, sizeof(report.model_source), "%s",
             "ubus_system_board");
    report.model_available = 1;
    if (ac_db_init() != 0 ||
        sqlite3_exec(g_ac_db,
            "INSERT INTO ac_aps(ap_id,site_id,name,adoption_state,last_seen_at) "
            "VALUES('" AP_ID "','default','Fixture AP','adopted',900)",
            NULL, NULL, NULL) != SQLITE_OK ||
        !(first = snapshot_new(1000, "Fixture")) ||
        !(changed = snapshot_new(1300, "Fixture Changed")))
        goto done;
    sqlite3_update_hook(g_ac_db, write_hook, NULL);
    if (ac_db_ap_session_begin(AP_ID, EPOCH_A, 1, 1005) != 0)
        goto done;
    writes = 0;
    if (ac_db_ap_telemetry_store(AP_ID, EPOCH_A, 10, 1000, 1010, snapshot_a,
                                 &report, first) != 0)
        goto done;
    first_writes = writes;
    if (first_writes <= 0 || scalar("SELECT COUNT(*) FROM ac_radio_runtime") != 1 ||
        scalar("SELECT COUNT(*) FROM ac_ssid_runtime") != 1 ||
        scalar("SELECT COUNT(*) FROM ac_station_sessions") != 1)
        goto done;
    writes = 0;
    if (ac_db_ap_telemetry_store(AP_ID, EPOCH_A, 10, 1000, 9999, snapshot_a,
                                 &report, first) != 0 || writes != 0)
        goto done;
    if (ac_db_ap_telemetry_store(AP_ID, EPOCH_A, 10, 1000, 9999, snapshot_c,
                                 &report, first) == 0 || writes != 0 ||
        ac_db_ap_telemetry_store(AP_ID, EPOCH_A, 9, 1100, 1110, snapshot_c,
                                 &report, first) == 0 || writes != 0)
        goto done;
    writes = 0;
    if (ac_db_ap_telemetry_store(AP_ID, EPOCH_A, 11, 1300, 5010, snapshot_b,
                                 &report, changed) != 0)
        goto done;
    changed_writes = writes;
    if (changed_writes <= 0)
        goto done;
    writes = 0;
    if (ac_db_ap_telemetry_store(AP_ID, EPOCH_A, 12, 1200, 5020, snapshot_c,
                                 &report, changed) == 0 || writes != 0)
        goto done;
    if (ac_db_ap_session_begin(AP_ID, EPOCH_B, 2, 5100) != 0)
        goto done;
    writes = 0;
    if (ac_db_ap_telemetry_store(AP_ID, EPOCH_B, 1, 900, 5110, snapshot_c,
                                 &report, first) != 0)
        goto done;
    session_b_writes = writes;
    /* A new APD session must accept a reset sequence and older AP clock. */
    if (session_b_writes <= 0 ||
        scalar("SELECT telemetry_sequence FROM ac_ap_runtime WHERE ap_id='" AP_ID "'") != 1 ||
        scalar("SELECT observed_at FROM ac_ap_runtime WHERE ap_id='" AP_ID "'") != 900 ||
        scalar("SELECT session_connected FROM ac_ap_runtime WHERE ap_id='" AP_ID "'") != 1)
        goto done;
    writes = 0;
    if (ac_db_ap_telemetry_store(AP_ID, EPOCH_A, 99, 1400, 5120, snapshot_c,
                                 &report, changed) == 0 || writes != 0)
        goto done;
    if (sqlite3_exec(g_ac_db,
            "UPDATE ac_aps SET last_seen_at=5250 WHERE ap_id='" AP_ID "'",
            NULL, NULL, NULL) != SQLITE_OK)
        goto done;
    /* AP time is old and telemetry is older than the heartbeat timeout, but
     * still inside the documented 300-second reporting cadence. */
    list = ac_db_aps_list_json(5250, 5205);
    if (!aps_list_valid(list) ||
        ac_db_scan_execution_available(5205, &scan_ap_count) != 1 ||
        scan_ap_count != 1 ||
        ac_db_ap_session_end(AP_ID, EPOCH_A) != 0 ||
        (json_object_put(list), list = ac_db_aps_list_json(5250, 5205),
         !aps_list_valid(list)) ||
        ac_db_scan_execution_available(5205, &scan_ap_count) != 1 ||
        scan_ap_count != 1 ||
        ac_db_ap_session_end(AP_ID, EPOCH_B) != 0 ||
        ac_db_scan_execution_available(5205, &scan_ap_count) != 0 ||
        scan_ap_count != 0)
        goto done;
    printf("first_writes=%d duplicate_writes=0 changed_writes=%d "
           "epoch_handoff=ok old_epoch_rejected=ok old_disconnect=ok "
           "radio=1 ssid=1 station=1 aps_list=ok\n",
           first_writes, changed_writes);
    rc = 0;
done:
    json_object_put(list);
    json_object_put(first);
    json_object_put(changed);
    ac_db_close();
    return rc;
}

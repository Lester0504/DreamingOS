// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>
#include <sqlite3.h>

extern sqlite3 *g_ac_db;
int ac_db_init(void);
void ac_db_close(void);
int ac_db_roaming_domain_put(const char *, const char *, const char *,
    const char *, const char *, const char *, int, const char *, int, int, int,
    const char *, int64_t, const char *, char *);
int ac_roam_steering_enable(const char *, int64_t);
int ac_roam_steering_enable_scoped(const char *, const char *, int64_t);
int ac_db_roaming_schedule_tick(int64_t, int *);
int ac_db_roaming_domain_delete(const char *, int64_t);
struct json_object *ac_db_roaming_neighbor_sync_json(const char *, int64_t);
struct json_object *ac_db_roaming_neighbor_sync_set_json(const char *, int, int64_t);
struct json_object *ac_db_roaming_domain_observe_json(
    const char *, const char *, const char *, int64_t);
struct json_object *ac_roam_btm_history_json(const char *, const char *, int, int64_t);
int ac_db_roaming_exclusion_put(const char *, const char *, const char *,
                               const char *, const char *, int64_t);
struct ac_roaming_policy {
    int weak_rssi_dbm, minimum_candidate_gain_db, candidate_min_rssi_dbm;
    int decision_min_interval_sec, post_roam_cooldown_sec;
    int max_btm_attempts_per_hour, deauth_after_btm_failures;
    int deauth_cooldown_sec, domain_action_rate_limit;
    int64_t revision, updated_at;
    char updated_by[65];
    int reassoc_block_enabled, reassoc_block_sec;
    char reassoc_block_scope[6];
    char steering_preference[16];
    int high_band_steer_enabled;
    int force_disassoc_on_reject;
    int lower_band_block_enabled;
};
int ac_db_roaming_policy_put(const char *, const struct ac_roaming_policy *, int64_t);

#define AP_A "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
#define AP_B "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
#define STA "44:71:47:35:e7:b3"
#define PROTECTED "5c:e9:1e:c3:2f:f9"
#define OTHER "02:11:22:33:44:55"
#define SOURCE "02:00:00:00:10:01"
#define TARGET "02:00:00:00:20:01"
#define TARGET_2G "02:00:00:00:20:02"
#define CHECK(label, expression) do { \
    if (!(expression)) { fprintf(stderr, "FAIL %s\n", label); return 1; } \
} while (0)

static struct json_object *field(struct json_object *object, const char *name)
{
    return json_object_object_get(object, name);
}

static int sql(const char *format, ...)
{
    va_list args;
    char *query, *error = NULL;
    int rc;

    va_start(args, format);
    query = sqlite3_vmprintf(format, args);
    va_end(args);
    rc = sqlite3_exec(g_ac_db, query, NULL, NULL, &error);
    if (rc != SQLITE_OK)
        fprintf(stderr, "SQL: %s\n%s\n", error, query);
    sqlite3_free(query);
    sqlite3_free(error);
    return rc == SQLITE_OK;
}

static int scalar(const char *query)
{
    sqlite3_stmt *statement = NULL;
    int value = -1;

    if (sqlite3_prepare_v2(g_ac_db, query, -1, &statement, NULL) == SQLITE_OK &&
        sqlite3_step(statement) == SQLITE_ROW)
        value = sqlite3_column_int(statement, 0);
    sqlite3_finalize(statement);
    return value;
}

static struct json_object *snapshot(void)
{
    return json_tokener_parse(
        "{\"desired\":{\"radios\":[],\"ssids\":[]},\"ssids\":[],"
        "\"sources\":{\"hostapd\":{\"available\":true,\"complete\":true,"
        "\"runtime_actions\":true,\"bss\":[]}}}");
}

static void add_bss(struct json_object *root, const char *radio,
    const char *section, const char *interface, const char *bssid, int frequency,
    int channel)
{
    struct json_object *desired = field(root, "desired");
    struct json_object *r = json_object_new_object();
    struct json_object *d = json_object_new_object();
    struct json_object *s = json_object_new_object();
    struct json_object *b = json_tokener_parse(
        "{\"ft_supported\":false,\"ft_over_ds\":false,"
        "\"neighbor_report_80211k\":true,\"bss_transition_80211v\":true,"
        "\"hostapd_ctrl_reachable\":true,\"client_deauth\":true,"
        "\"complete\":true,\"state\":\"ENABLED\",\"station_count\":1}");

    json_object_object_add(r, "id", json_object_new_string(radio));
    json_object_object_add(r, "phy", json_object_new_string(radio));
    json_object_array_add(field(desired, "radios"), r);
    json_object_object_add(d, "id", json_object_new_string(section));
    json_object_object_add(d, "radio_id", json_object_new_string(radio));
    json_object_object_add(d, "broadcast_name", json_object_new_string("Office"));
    json_object_array_add(field(desired, "ssids"), d);
    json_object_object_add(s, "id", json_object_new_string(interface));
    json_object_object_add(s, "interface", json_object_new_string(interface));
    json_object_object_add(s, "radio_id", json_object_new_string(radio));
    json_object_object_add(s, "bssid", json_object_new_string(bssid));
    json_object_object_add(s, "broadcast_name", json_object_new_string("Office"));
    json_object_array_add(field(root, "ssids"), s);
    json_object_object_add(b, "interface", json_object_new_string(interface));
    json_object_object_add(b, "bssid", json_object_new_string(bssid));
    json_object_object_add(b, "broadcast_name", json_object_new_string("Office"));
    json_object_object_add(b, "neighbors_complete", json_object_new_boolean(1));
    json_object_object_add(b, "neighbors", json_object_new_array());
    json_object_object_add(b, "frequency_mhz", json_object_new_int(frequency));
    json_object_object_add(b, "channel", json_object_new_int(channel));
    json_object_array_add(field(field(field(root, "sources"), "hostapd"), "bss"), b);
}

static int store_snapshot(const char *ap, struct json_object *root, int64_t now)
{
    return sql("UPDATE ac_ap_runtime SET runtime_json=%Q,observed_at=%lld,"
        "received_at=%lld WHERE ap_id=%Q",
        json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN), now, now, ap);
}

static int refresh(int64_t now)
{
    return sql("UPDATE ac_aps SET last_seen_at=%lld;"
        "UPDATE ac_ap_runtime SET observed_at=%lld,received_at=%lld;"
        "UPDATE ac_station_sessions SET last_seen_at=%lld WHERE disconnected_at=0",
        now, now, now, now);
}

static void measurements(struct json_object *root, int64_t now)
{
    const char *bssids[] = { SOURCE, TARGET, TARGET_2G };
    int signals[] = { -61, -34, -20 };
    struct json_object *reports = json_object_new_array();
    size_t i;

    for (i = 0; i < 3; i++) {
        struct json_object *r = json_object_new_object();
        json_object_object_add(r, "station_mac", json_object_new_string(STA));
        json_object_object_add(r, "bssid", json_object_new_string(bssids[i]));
        json_object_object_add(r, "rcpi_dbm", json_object_new_int(signals[i]));
        json_object_object_add(r, "observed_at", json_object_new_int64(now));
        json_object_object_add(r, "measurement_mode", json_object_new_string("table"));
        json_object_object_add(r, "cached", json_object_new_boolean(1));
        json_object_array_add(reports, r);
    }
    json_object_object_add(field(field(root, "sources"), "hostapd"),
                           "beacon_reports", reports);
}

static int acknowledge(int64_t now)
{
    return sql("UPDATE ac_transaction_targets SET state='applied',updated_at=%lld;"
        "UPDATE ac_config_jobs SET state='applied',updated_at=%lld,"
        "readback_json='{\"ok\":true,\"match\":true,"
        "\"evidence_type\":\"hostapd_command_ack\"}'", now, now);
}

static void client_response(struct json_object *root, int code, int64_t now)
{
    struct json_object *responses = json_object_new_array();
    struct json_object *response = json_object_new_object();

    json_object_object_add(response, "station_mac", json_object_new_string(STA));
    json_object_object_add(response, "interface", json_object_new_string("ath0"));
    json_object_object_add(response, "target_bssid", json_object_new_string(TARGET));
    json_object_object_add(response, "status_code", json_object_new_int(code));
    json_object_object_add(response, "observed_at", json_object_new_int64(now));
    json_object_array_add(responses, response);
    json_object_object_add(field(field(root, "sources"), "hostapd"),
                           "btm_responses", responses);
}

static struct json_object *bss_at(struct json_object *root, size_t index)
{
    return json_object_array_get_idx(field(field(field(root, "sources"), "hostapd"), "bss"),
                                     index);
}

static int neighbor_readback(const char *ap, struct json_object *root, int64_t now)
{
    sqlite3_stmt *st = NULL;
    struct json_object *candidate, *sections;
    size_t i, j;

    if (sqlite3_prepare_v2(g_ac_db,
            "SELECT candidate_json FROM ac_config_jobs WHERE ap_id=?1 "
            "ORDER BY created_at DESC LIMIT 1", -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, ap, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        return 0;
    }
    candidate = json_tokener_parse((const char *)sqlite3_column_text(st, 0));
    sqlite3_finalize(st);
    sections = field(candidate, "sections");
    for (i = 0; i < json_object_array_length(sections); i++) {
        struct json_object *section = json_object_array_get_idx(sections, i);
        struct json_object *options = field(section, "options");
        const char *bssid = json_object_get_string(field(options, "neighbor_bssid"));
        char report[27], mac_hex[13];
        size_t n = 0;

        for (j = 0; bssid[j]; j++)
            if (bssid[j] != ':')
                mac_hex[n++] = bssid[j];
        mac_hex[n] = '\0';
        snprintf(report, sizeof(report), "%s" "ef180000%02x%02x%02x", mac_hex,
            json_object_get_int(field(options, "neighbor_opclass")),
            json_object_get_int(field(options, "neighbor_channel")),
            json_object_get_int(field(options, "neighbor_phy")));
        for (j = 0; bss_at(root, j); j++) {
            struct json_object *owner = bss_at(root, j);
            struct json_object *row;

            if (strcmp(json_object_get_string(field(owner, "interface")),
                       json_object_get_string(field(section, "section"))))
                continue;
            row = json_object_new_object();
            json_object_object_add(row, "bssid", json_object_new_string(bssid));
            json_object_object_add(row, "ssid_hex", json_object_new_string("4f6666696365"));
            json_object_object_add(row, "report", json_object_new_string(report));
            json_object_array_add(field(owner, "neighbors"), row);
        }
    }
    json_object_put(candidate);
    return store_snapshot(ap, root, now);
}

int main(void)
{
    char domain[37];
    struct json_object *a = snapshot(), *b = snapshot(), *result, *entry;
    struct ac_roaming_policy policy = {
        .weak_rssi_dbm = -75, .minimum_candidate_gain_db = 10,
        .candidate_min_rssi_dbm = -67, .decision_min_interval_sec = 120,
        .post_roam_cooldown_sec = 300, .max_btm_attempts_per_hour = 2,
        .deauth_after_btm_failures = 1, .deauth_cooldown_sec = 900,
        .domain_action_rate_limit = 2, .updated_by = "fixture",
    };
    int dispatched;

    CHECK("init", ac_db_init() == 0);
    CHECK("domain", ac_db_roaming_domain_put(NULL, "Office",
        "[\"ssid-main\"]", "[\"floor-one\"]", "ap-local-existing", "",
        0, "over_air", 1, 1, 0, NULL, 0, "fixture", domain) == 0);
    CHECK("seed", sql(
        "INSERT INTO ac_ap_groups(group_id,site_id,name,revision,updated_at)"
        " VALUES('floor-one','default','one',1,10000);"
        "INSERT INTO ac_ssids(ssid_id,site_id,name,revision,enabled,updated_at)"
        " VALUES('ssid-main','default','Office',1,1,10000);"
        "INSERT INTO ac_aps(ap_id,site_id,name,adoption_state,last_seen_at)"
        " VALUES('" AP_A "','default','A','adopted',10000),"
        "('" AP_B "','default','B','adopted',10000);"
        "INSERT INTO ac_ap_group_members(group_id,ap_id)"
        " VALUES('floor-one','" AP_A "'),('floor-one','" AP_B "');"
        "INSERT INTO ac_ap_runtime(ap_id,observed_at,received_at,"
        "control_protocol_version,write_capable,session_connected,stale)"
        " VALUES('" AP_A "',10000,10000,3,1,1,0),"
        "('" AP_B "',10000,10000,3,1,1,0);"
        "INSERT INTO ac_ssid_bindings(ssid_id,ap_id,radio_id,state,bssid,section_name)"
        " VALUES('ssid-main','" AP_A "','radio0','applied','" SOURCE "','vap0'),"
        "('ssid-main','" AP_B "','radio0','applied','" TARGET "','vap6'),"
        "('ssid-main','" AP_B "','radio1','applied','" TARGET_2G "','vap2');"
        "INSERT INTO ac_station_sessions(association_id,ap_id,radio_id,ssid_id,"
        "mac,connected_at,last_seen_at,runtime_json) VALUES"
        "('phone','" AP_A "','radio0','ssid-main','" STA "',9000,10000,"
        "'{\"signal_dbm\":-61,\"station_btm_capable\":true}'),"
        "('protected','" AP_A "','radio0','ssid-main','" PROTECTED "',9000,10000,"
        "'{\"signal_dbm\":-70,\"station_btm_capable\":true}'),"
        "('other','" AP_A "','radio0','ssid-main','" OTHER "',9000,10000,"
        "'{\"signal_dbm\":-70,\"station_btm_capable\":true}'),"
        "('iot','" AP_A "','radio0','ssid-iot','00:00:00:00:01:01',9000,10000,"
        "'{\"signal_dbm\":-80,\"station_btm_capable\":true}')"));
    add_bss(a, "radio0", "vap0", "ath0", SOURCE, 5180, 36);
    add_bss(b, "radio0", "vap6", "phy0.2-ap0", TARGET, 6775, 165);
    add_bss(b, "radio1", "vap2", "phy0.0-ap0", TARGET_2G, 2417, 2);
    CHECK("snapshots", store_snapshot(AP_A, a, 10000) &&
          store_snapshot(AP_B, b, 10000));
    CHECK("protected station", ac_db_roaming_exclusion_put(
        "protect", domain, "mac", PROTECTED, "workstation", 10000) == 0);
    CHECK("default no timer actions", ac_db_roaming_schedule_tick(10000, &dispatched) == 0 &&
          dispatched == 0);
    CHECK("policy", ac_db_roaming_policy_put(domain, &policy, 0) == 0);
    CHECK("policy alone does not arm", ac_db_roaming_schedule_tick(10001, &dispatched) == 0 &&
          dispatched == 0);
    CHECK("invalid scope cannot arm", ac_roam_steering_enable_scoped(
        domain, "not-a-mac", 10002) != 0 &&
        scalar("SELECT COUNT(*) FROM ac_roaming_domain_action_state") == 0);
    CHECK("explicit station arm", ac_roam_steering_enable_scoped(
        domain, STA, 10002) == 0);
    result = ac_db_roaming_domain_observe_json(domain, OTHER, "active", 10002);
    CHECK("explicit steer respects station scope", !strcmp(
        json_object_get_string(field(result, "reason")), "steering_not_enabled"));
    json_object_put(result);
    CHECK("automatic measurement", ac_db_roaming_schedule_tick(10002, &dispatched) == 0 &&
          dispatched == 1);
    CHECK("only one job and no btm", scalar("SELECT COUNT(*) FROM ac_config_jobs") == 1 &&
          scalar("SELECT COUNT(*) FROM ac_btm_actions") == 0);
    CHECK("unselected clients never enter periodic state", scalar(
        "SELECT COUNT(*) FROM ac_roaming_station_state WHERE station_mac='" OTHER "'") == 0);
    CHECK("only transient measurement sections", scalar(
        "SELECT COUNT(*) FROM ac_config_jobs j,json_each(j.candidate_json,'$.sections') s "
        "WHERE json_extract(s.value,'$.section')='ath0' AND "
        "json_extract(s.value,'$.options.hostapd_action_type')='beacon_request' "
        "AND json_extract(s.value,'$.options.station_mac')='" STA "'") == 3);
    CHECK("measurements are directed per BSSID", scalar(
        "SELECT COUNT(*) FROM ac_config_jobs j,json_each(j.candidate_json,'$.sections') s "
        "WHERE json_extract(s.value,'$.options.hostapd_action_type')='beacon_request' "
        "AND json_extract(s.value,'$.options.measure_bssid') IN "
        "('" SOURCE "','" TARGET "','" TARGET_2G "')") == 3);
    CHECK("no repeat while awaiting report", ac_db_roaming_schedule_tick(
        10017, &dispatched) == 0 && dispatched == 0);
    ac_db_close();
    CHECK("restart retains station scope", ac_db_init() == 0 && scalar(
        "SELECT COUNT(*) FROM ac_roaming_domain_action_state "
        "WHERE steering_station_mac='" STA "'") == 1);
    CHECK("other client leaves test", sql(
        "UPDATE ac_station_sessions SET disconnected_at=10018 WHERE association_id='other'"));
    measurements(a, 10020);
    CHECK("measurement delivered", acknowledge(10020) && store_snapshot(AP_A, a, 10020) &&
          refresh(10032));
    json_object_array_del_idx(field(field(field(a, "sources"), "hostapd"),
                                   "beacon_reports"), 0, 1);
    CHECK("candidate-only reports", store_snapshot(AP_A, a, 10032));
    result = ac_db_roaming_domain_observe_json(domain, STA, "active", 10032);
    CHECK("candidate downlink cannot be compared with serving uplink",
        !strcmp(json_object_get_string(field(result, "reason")),
                "serving_measurement_missing") &&
        !strcmp(json_object_get_string(field(result, "decision")), "no_action") &&
        scalar("SELECT COUNT(*) FROM ac_btm_actions") == 0);
    CHECK("missing comparison is explicit",
        !json_object_get_boolean(field(result, "comparison_signal_measured")) &&
        json_object_is_type(field(result, "comparison_signal_dbm"), json_type_null));
    json_object_put(result);
    measurements(a, 10020);
    entry = json_object_array_get_idx(field(field(field(a, "sources"), "hostapd"),
                                           "beacon_reports"), 0);
    json_object_object_add(entry, "rcpi_dbm", json_object_new_int(-20));
    CHECK("strong serving downlink", store_snapshot(AP_A, a, 10032));
    result = ac_db_roaming_domain_observe_json(domain, STA, "active", 10032);
    CHECK("weak uplink does not displace strong serving downlink",
        !strcmp(json_object_get_string(field(result, "reason")), "gain_insufficient") &&
        scalar("SELECT COUNT(*) FROM ac_btm_actions") == 0);
    json_object_put(result);
    json_object_object_add(entry, "observed_at", json_object_new_int64(9900));
    CHECK("stale serving report", store_snapshot(AP_A, a, 10032));
    result = ac_db_roaming_domain_observe_json(domain, STA, "active", 10032);
    CHECK("fresh candidate cannot revive stale serving report",
        !strcmp(json_object_get_string(field(result, "reason")),
                "serving_measurement_missing") &&
        scalar("SELECT COUNT(*) FROM ac_btm_actions") == 0);
    json_object_put(result);
    measurements(a, 10020);
    CHECK("restore paired measurements", store_snapshot(AP_A, a, 10032));
    result = ac_db_roaming_domain_observe_json(domain, STA, "observe_only", 10032);
    CHECK("table comparison labeled", !strcmp(json_object_get_string(
        field(result, "comparison_signal_source")), "ieee80211k_beacon_table") &&
        json_object_get_boolean(field(result, "comparison_signal_cached")));
    entry = json_object_array_get_idx(field(result, "candidates"), 1);
    CHECK("table candidate labeled", entry && !strcmp(json_object_get_string(
        field(entry, "signal_source")), "ieee80211k_beacon_table") &&
        json_object_get_boolean(field(entry, "signal_cached")));
    json_object_put(result);
    CHECK("timer queues btm", ac_db_roaming_schedule_tick(10032, &dispatched) == 0 &&
          dispatched == 1);
    result = ac_roam_btm_history_json(domain, STA, 10, 10032);
    entry = json_object_array_get_idx(field(result, "entries"), 0);
    CHECK("27 dB stronger 6G beats stronger 2G", entry && !strcmp(
        json_object_get_string(field(entry, "target_bssid")), TARGET));
    CHECK("queue is not sent", !json_object_get_boolean(field(entry, "sent_ok")) &&
          json_object_get_int64(field(entry, "sent_at")) == 0);
    json_object_put(result);
    CHECK("RF and FT truthful", scalar(
        "SELECT COUNT(*) FROM ac_config_jobs j,json_each(j.candidate_json,'$.sections') s "
        "WHERE json_extract(s.value,'$.options.hostapd_action_type')='btm_request' "
        "AND json_extract(s.value,'$.options.target_opclass')='131' "
        "AND json_extract(s.value,'$.options.target_channel')='165' "
        "AND json_extract(s.value,'$.options.target_ft')='0'") == 1);
    CHECK("no duplicate tick", ac_db_roaming_schedule_tick(10033, &dispatched) == 0 &&
          dispatched == 0 && scalar("SELECT COUNT(*) FROM ac_btm_actions") == 1);
    CHECK("AP ack", acknowledge(10040));
    CHECK("AP ack alone no roam", ac_db_roaming_schedule_tick(10047, &dispatched) == 0 &&
          scalar("SELECT COUNT(*) FROM ac_btm_actions WHERE sent_ok=1 "
                 "AND outcome='pending'") == 1);
    client_response(a, 7, 10048);
    CHECK("rejection telemetry", store_snapshot(AP_A, a, 10048));
    CHECK("client rejection", ac_db_roaming_schedule_tick(10050, &dispatched) == 0 &&
          scalar("SELECT COUNT(*) FROM ac_btm_actions WHERE outcome='not_roamed' "
                 "AND outcome_reason='station_rejected_btm_status_7'") == 1);
    CHECK("cooldown survives outcomes", scalar(
        "SELECT COUNT(*) FROM ac_roaming_cooldowns WHERE cooldown_until>10200") == 1);
    CHECK("refresh for stale report", refresh(10400));
    result = ac_db_roaming_domain_observe_json(domain, STA, NULL, 10400);
    CHECK("fresh snapshot cannot renew stale beacon report", !strcmp(
        json_object_get_string(field(result, "reason")), "candidate_measurements_missing"));
    json_object_put(result);
    CHECK("second recent attempt", sql(
        "INSERT INTO ac_btm_actions(domain_id,station_mac,ap_id,source_bssid,target_bssid,"
        "sent_at,sent_ok,outcome,created_at) VALUES(%Q,'" STA "','" AP_A "',"
        "'" SOURCE "','" TARGET "',10350,1,'not_roamed',10350)", domain));
    CHECK("refresh for rate limit", refresh(10560));
    result = ac_db_roaming_domain_observe_json(domain, STA, "active", 10560);
    CHECK("hourly client rate enforced", !strcmp(
        json_object_get_string(field(result, "reason")), "station_btm_rate_limit"));
    json_object_put(result);
    CHECK("disable", sql("UPDATE ac_roaming_domain_action_state SET steering_enabled=0"));
    CHECK("fresh while disabled", refresh(14000));
    CHECK("disabled timer does nothing", ac_db_roaming_schedule_tick(14000, &dispatched) == 0 &&
          dispatched == 0);
    CHECK("re-arm", ac_roam_steering_enable(domain, 14001) == 0);
    CHECK("explicit domain arm clears prior station scope", scalar(
        "SELECT COUNT(*) FROM ac_roaming_domain_action_state "
        "WHERE steering_station_mac=''") == 1);
    CHECK("canonical false overrides legacy true", sql(
        "UPDATE ac_station_sessions SET runtime_json="
        "'{\"signal_dbm\":-61,\"station_btm_capable\":false,\"btm_capable\":true}' "
        "WHERE mac='" STA "'"));
    result = ac_db_roaming_domain_observe_json(domain, STA, "active", 14001);
    CHECK("canonical capability", !strcmp(json_object_get_string(field(result, "reason")),
          "station_btm_not_capable"));
    json_object_put(result);
    CHECK("capability restore", sql(
        "UPDATE ac_station_sessions SET runtime_json="
        "'{\"signal_dbm\":-61,\"station_btm_capable\":true}' WHERE mac='" STA "';"
        "UPDATE ac_roaming_station_state SET last_evaluated_at=0,last_measurement_at=0"));
    measurements(a, 14010);
    CHECK("fresh candidate", store_snapshot(AP_A, a, 14010) && refresh(14010));
    CHECK("new automatic btm", ac_db_roaming_schedule_tick(14010, &dispatched) == 0 &&
          dispatched == 1);
    CHECK("second AP ack", acknowledge(14011));
    client_response(a, 0, 14012);
    CHECK("client accept telemetry", store_snapshot(AP_A, a, 14012));
    CHECK("accept is not association", ac_db_roaming_schedule_tick(14015, &dispatched) == 0 &&
          scalar("SELECT COUNT(*) FROM ac_btm_actions WHERE outcome='pending' "
          "AND outcome_reason='station_accepted_btm_waiting_for_roam'") == 1);
    CHECK("actual target association", sql(
        "UPDATE ac_station_sessions SET disconnected_at=14016 WHERE association_id='phone';"
        "INSERT INTO ac_station_sessions(association_id,ap_id,radio_id,ssid_id,mac,"
        "connected_at,last_seen_at,runtime_json) VALUES('target-phone','" AP_B "',"
        "'radio0','ssid-main','" STA "',14016,14020,"
        "'{\"signal_dbm\":-34,\"station_btm_capable\":true}')"));
    CHECK("association resolves success", ac_db_roaming_schedule_tick(14020, &dispatched) == 0 &&
          scalar("SELECT COUNT(*) FROM ac_btm_actions WHERE outcome='roamed'") == 1);
    CHECK("no forced disconnect ever", scalar(
        "SELECT COUNT(*) FROM ac_config_jobs j,json_each(j.candidate_json,'$.sections') s "
        "WHERE json_extract(s.value,'$.options.hostapd_action_type')='deauth_request'") == 0);
    CHECK("post-association cooldown", scalar(
        "SELECT cooldown_until FROM ac_roaming_cooldowns WHERE station_mac='" STA "'") == 14320);

    CHECK("return to source much later", sql(
        "UPDATE ac_station_sessions SET disconnected_at=200000 "
        "WHERE association_id='target-phone';"
        "UPDATE ac_station_sessions SET disconnected_at=0,connected_at=200000 "
        "WHERE association_id='phone'"));
    measurements(a, 200000);
    CHECK("fresh source", store_snapshot(AP_A, a, 200000) && refresh(200000));
    CHECK("enable expiry scenario", ac_roam_steering_enable(domain, 200000) == 0);
    CHECK("queue before AP stops responding", ac_db_roaming_schedule_tick(
        200000, &dispatched) == 0 && dispatched == 1);
    CHECK("expire unconfirmed BTM", ac_db_roaming_schedule_tick(
        200121, &dispatched) == 0);
    CHECK("expired BTM closes job and transaction", scalar(
        "SELECT COUNT(*) FROM ac_btm_actions b JOIN ac_config_jobs j "
        "ON j.transaction_id=b.transaction_id JOIN ac_transaction_targets t "
        "ON t.transaction_id=j.transaction_id JOIN ac_transactions x "
        "ON x.transaction_id=j.transaction_id WHERE b.created_at=200000 "
        "AND b.outcome='timed_out' AND b.sent_ok=0 AND j.state='cancelled' "
        "AND t.state='failed' AND x.state='failed'") == 1);
    json_object_object_add(field(field(a, "sources"), "hostapd"),
                           "beacon_reports", json_object_new_array());
    CHECK("measurement after expired BTM", store_snapshot(AP_A, a, 200500) &&
          refresh(200500) && ac_db_roaming_schedule_tick(
              200500, &dispatched) == 0 && dispatched == 1);
    CHECK("disable with queued measurement", sql(
        "UPDATE ac_roaming_domain_action_state SET steering_enabled=0"));
    CHECK("expire measurement even while disarmed", ac_db_roaming_schedule_tick(
        200621, &dispatched) == 0 && dispatched == 0);
    CHECK("expired measurement closes job and transaction", scalar(
        "SELECT COUNT(*) FROM ac_roaming_station_state s JOIN ac_config_jobs j "
        "ON j.transaction_id=s.measurement_transaction_id JOIN ac_transaction_targets t "
        "ON t.transaction_id=j.transaction_id JOIN ac_transactions x "
        "ON x.transaction_id=j.transaction_id WHERE s.station_mac='" STA "' "
        "AND j.state='cancelled' AND t.state='failed' AND x.state='failed'") == 1);

    measurements(a, 200800);
    json_object_array_del_idx(field(field(field(a, "sources"), "hostapd"),
                                   "beacon_reports"), 0, 1);
    CHECK("partial-report retry setup", store_snapshot(AP_A, a, 200800) &&
          refresh(200800) &&
          ac_roam_steering_enable_scoped(domain, STA, 200800) == 0 &&
          sql("UPDATE ac_roaming_station_state SET last_evaluated_at=0,"
              "last_measurement_at=0 WHERE station_mac='" STA "'"));
    CHECK("timer requests missing serving measurement",
          ac_db_roaming_schedule_tick(200800, &dispatched) == 0 && dispatched == 1 &&
          scalar("SELECT COUNT(*) FROM ac_config_jobs j,"
              "json_each(j.candidate_json,'$.sections') s WHERE j.created_at=200800 "
              "AND json_extract(s.value,'$.options.hostapd_action_type')='beacon_request'") == 3 &&
          scalar("SELECT COUNT(*) FROM ac_btm_actions WHERE created_at=200800") == 0);
    CHECK("finish partial-report fixture", acknowledge(200801) &&
          sql("UPDATE ac_roaming_domain_action_state SET steering_enabled=0"));

    CHECK("neighbor fixture disarms all station actions", sql(
        "UPDATE ac_roaming_policies SET max_btm_attempts_per_hour=0,"
        "domain_action_rate_limit=0,deauth_after_btm_failures=0"));
    CHECK("neighbor fixture freshness", refresh(300000) &&
          store_snapshot(AP_A, a, 300000) && store_snapshot(AP_B, b, 300000));
    CHECK("metadata never starts neighbor writes",
          ac_db_roaming_schedule_tick(300000, &dispatched) == 0 && dispatched == 0);
    result = ac_db_roaming_neighbor_sync_set_json(domain, 1, 300000);
    CHECK("explicit independent neighbor enable", json_object_get_boolean(field(result, "ok")) &&
          json_object_get_boolean(field(result, "enabled")));
    json_object_put(result);
    CHECK("neighbor-only replay to both APs",
          ac_db_roaming_schedule_tick(300000, &dispatched) == 0 && dispatched == 2);
    CHECK("no UCI or IoT writes", scalar(
        "SELECT COUNT(*) FROM ac_config_jobs j,json_each(j.candidate_json,'$.sections') s "
        "WHERE j.created_at>=300000 AND ("
        "json_extract(s.value,'$.options.hostapd_action_type')<>'set_neighbor' OR "
        "json_extract(s.value,'$.options.source_ssid')<>'Office' OR "
        "json_extract(s.value,'$.options.source_bssid') IS NULL)") == 0);
    CHECK("ACK without readback stays unverified", acknowledge(300001) &&
          ac_db_roaming_schedule_tick(300001, &dispatched) == 0 && dispatched == 0 &&
          scalar("SELECT COUNT(*) FROM ac_neighbor_sync_state WHERE synced_at>0") == 0);
    CHECK("actual tables", neighbor_readback(AP_A, a, 300002) &&
          neighbor_readback(AP_B, b, 300002));
    CHECK("actual readback verifies both APs",
          ac_db_roaming_schedule_tick(300002, &dispatched) == 0 && dispatched == 0 &&
          scalar("SELECT COUNT(*) FROM ac_neighbor_sync_state WHERE reason='verified'") == 2);
    ac_db_close();
    CHECK("AC restart", ac_db_init() == 0);
    CHECK("replay policy survives restart without duplicate writes",
          ac_db_roaming_schedule_tick(300003, &dispatched) == 0 && dispatched == 0);
    json_object_object_add(bss_at(a, 0), "neighbors", json_object_new_array());
    CHECK("hostapd loses table without AP session change", store_snapshot(AP_A, a, 300004) &&
          ac_db_roaming_schedule_tick(300004, &dispatched) == 0 && dispatched == 1);
    result = ac_db_roaming_neighbor_sync_set_json(domain, 0, 300005);
    CHECK("disable cancels queued replay", json_object_get_boolean(field(result, "ok")) &&
          !json_object_get_boolean(field(result, "enabled")) &&
          scalar("SELECT COUNT(*) FROM ac_config_jobs WHERE created_at=300004 "
                 "AND state='cancelled'") == 1);
    json_object_put(result);
    CHECK("disabled replay stays quiet", refresh(300010) &&
          ac_db_roaming_schedule_tick(300010, &dispatched) == 0 && dispatched == 0);
    result = ac_db_roaming_neighbor_sync_set_json(domain, 1, 300020);
    json_object_put(result);
    CHECK("explicit rearm", refresh(300020) &&
          ac_db_roaming_schedule_tick(300020, &dispatched) == 0 && dispatched == 1);
    CHECK("no retry flood", acknowledge(300021) && refresh(300079) &&
          ac_db_roaming_schedule_tick(300079, &dispatched) == 0 && dispatched == 0);
    CHECK("first bounded retry", refresh(300080) &&
          ac_db_roaming_schedule_tick(300080, &dispatched) == 0 && dispatched == 1);
    CHECK("second retry backoff", acknowledge(300081) && refresh(300199) &&
          ac_db_roaming_schedule_tick(300199, &dispatched) == 0 && dispatched == 0);
    CHECK("last bounded retry", refresh(300200) &&
          ac_db_roaming_schedule_tick(300200, &dispatched) == 0 && dispatched == 1);
    CHECK("three failures stop", acknowledge(300201) && refresh(300400) &&
          ac_db_roaming_schedule_tick(300400, &dispatched) == 0 && dispatched == 0 &&
          scalar("SELECT attempts FROM ac_neighbor_sync_state WHERE ap_id='" AP_A "'") == 3 &&
          scalar("SELECT COUNT(*) FROM ac_neighbor_sync_state WHERE reason='retry_exhausted'") == 1);
    CHECK("new AP session", sql("UPDATE ac_ap_runtime SET boot_id="
        "'1111111111111111111111111111111111111111111111111111111111111111'"
        " WHERE ap_id='" AP_A "'") && refresh(300401));
    CHECK("reboot gets a fresh recovery budget",
          ac_db_roaming_schedule_tick(300401, &dispatched) == 0 && dispatched == 1);
    CHECK("recovery readback", acknowledge(300402) && neighbor_readback(AP_A, a, 300402) &&
          ac_db_roaming_schedule_tick(300402, &dispatched) == 0 && dispatched == 0);
    json_object_object_add(bss_at(a, 0), "neighbors_complete", json_object_new_boolean(0));
    CHECK("partial tables do not trigger writes", store_snapshot(AP_A, a, 300403) &&
          ac_db_roaming_schedule_tick(300403, &dispatched) == 0 && dispatched == 0 &&
          scalar("SELECT COUNT(*) FROM ac_neighbor_sync_state "
                 "WHERE reason='neighbor_readback_unavailable'") == 1);
    json_object_object_add(bss_at(a, 0), "neighbors_complete", json_object_new_boolean(1));
    json_object_object_add(bss_at(a, 0), "broadcast_name", json_object_new_string("IoT"));
    CHECK("runtime SSID mismatch stays read-only", store_snapshot(AP_A, a, 300404) &&
          ac_db_roaming_schedule_tick(300404, &dispatched) == 0 && dispatched == 0);
    CHECK("neighbor enable never arms steering", scalar(
        "SELECT COUNT(*) FROM ac_roaming_domain_action_state WHERE steering_enabled=1") == 0 &&
        scalar("SELECT COUNT(*) FROM ac_config_jobs j,json_each(j.candidate_json,'$.sections') s "
        "WHERE j.created_at>=300000 AND json_extract(s.value,'$.options.hostapd_action_type')"
        " IN ('btm_request','beacon_request','deauth_request')") == 0);
    CHECK("failed domain deletion preserves replay opt-in",
          ac_db_roaming_domain_delete(domain, 99) != 0 &&
          scalar("SELECT COUNT(*) FROM ac_neighbor_sync_domains WHERE enabled=1") == 1);
    CHECK("domain deletion clears only its replay state",
          ac_db_roaming_domain_delete(domain, 1) == 0 &&
          scalar("SELECT COUNT(*) FROM ac_neighbor_sync_domains") == 0 &&
          scalar("SELECT COUNT(*) FROM ac_neighbor_sync_state") == 0 &&
          scalar("SELECT COUNT(*) FROM ac_roaming_domain_action_state") == 0);
    CHECK("recreate same domain UUID", ac_db_roaming_domain_put(domain, "Office",
        "[\"ssid-main\"]", "[\"floor-one\"]", "ap-local-existing", "",
        0, "over_air", 1, 1, 0, NULL, 0, "fixture", NULL) == 0);
    CHECK("recreated metadata cannot resume replay",
          ac_db_roaming_schedule_tick(300405, &dispatched) == 0 && dispatched == 0);
    json_object_put(a);
    json_object_put(b);
    ac_db_close();
    puts("ok");
    return 0;
}

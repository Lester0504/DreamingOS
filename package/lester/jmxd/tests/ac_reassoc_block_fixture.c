// SPDX-License-Identifier: GPL-2.0-or-later
#define main ac_automatic_baseline_main
#include "ac_roaming_automatic_fixture.c"
#undef main

struct json_object *ac_db_roaming_deauth_evaluate_json(const char *, const char *,
    const char *, int, const char *, int64_t);
struct json_object *ac_db_roaming_policy_json(const char *);
void ac_db_test_deauth_resolve(int64_t, const char *, int64_t);

#define SOURCE_2G "02:00:00:00:10:02"

static int gate(const char *domain, const char *mac, int64_t now,
                 const char *reason)
{
    struct json_object *r = ac_db_roaming_deauth_evaluate_json(
        domain, mac, "fixture", 0, NULL, now);
    const char *got = json_object_get_string(field(r, "reason"));
    int ok = got && !strcmp(got, reason);

    if (!ok)
        fprintf(stderr, "gate wanted %s, got %s\n", reason, got ? got : "(null)");
    json_object_put(r);
    return ok;
}

static void source_2g_report(struct json_object *a, int64_t now)
{
    struct json_object *report = json_object_new_object();

    json_object_object_add(report, "station_mac", json_object_new_string(STA));
    json_object_object_add(report, "bssid", json_object_new_string(SOURCE_2G));
    json_object_object_add(report, "rcpi_dbm", json_object_new_int(-64));
    json_object_object_add(report, "observed_at", json_object_new_int64(now));
    json_object_array_add(field(field(field(a, "sources"), "hostapd"),
                               "beacon_reports"), report);
}

int main(void)
{
    char domain[37];
    struct json_object *a = snapshot(), *b = snapshot(), *r, *entry;
    struct ac_roaming_policy policy = {
        .weak_rssi_dbm = -75, .minimum_candidate_gain_db = 10,
        .candidate_min_rssi_dbm = -67, .decision_min_interval_sec = 30,
        .post_roam_cooldown_sec = 300, .max_btm_attempts_per_hour = 2,
        .deauth_after_btm_failures = 1, .deauth_cooldown_sec = 300,
        .domain_action_rate_limit = 2, .updated_by = "fixture",
        .reassoc_block_enabled = 1, .reassoc_block_sec = 10,
        .reassoc_block_scope = "ap", .force_disassoc_on_reject = 1
    };
    int dispatched;

    CHECK("init", ac_db_init() == 0);
    CHECK("domain create", ac_db_roaming_domain_put(NULL, "Office",
        "[\"ssid-main\"]", "[\"floor-one\"]", "ap-local-existing", "",
        0, "over_air", 1, 1, 0, NULL, 0, "fixture", domain) == 0);
    CHECK("domain opt in", ac_db_roaming_domain_put(domain, "Office",
        "[\"ssid-main\"]", "[\"floor-one\"]", "ap-local-existing", "",
        0, "over_air", 1, 1, 1, "enable-forced-deauth", 1, "fixture", NULL) == 0);
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
        "('ssid-main','" AP_A "','radio1','applied','" SOURCE_2G "','vap2'),"
        "('ssid-main','" AP_B "','radio0','applied','" TARGET "','vap6');"
        "INSERT INTO ac_station_sessions(association_id,ap_id,radio_id,ssid_id,"
        "mac,connected_at,last_seen_at,runtime_json) VALUES"
        "('phone','" AP_A "','radio0','ssid-main','" STA "',9000,10000,"
        "'{\"signal_dbm\":-80,\"station_btm_capable\":true}'),"
        "('protected','" AP_A "','radio0','ssid-main','" PROTECTED "',9000,10000,"
        "'{\"signal_dbm\":-80,\"station_btm_capable\":true}'),"
        "('other','" AP_A "','radio0','ssid-main','" OTHER "',9000,10000,"
        "'{\"signal_dbm\":-80,\"station_btm_capable\":true}')"));
    add_bss(a, "radio0", "vap0", "ath0", SOURCE, 5180, 36);
    add_bss(a, "radio1", "vap2", "ath2", SOURCE_2G, 2417, 2);
    add_bss(b, "radio0", "vap6", "phy0.2-ap0", TARGET, 6775, 165);
    json_object_object_add(bss_at(a, 0), "reassoc_block", json_object_new_boolean(1));
    json_object_object_add(bss_at(a, 1), "reassoc_block", json_object_new_boolean(1));
    measurements(a, 10000);
    source_2g_report(a, 10000);
    CHECK("snapshots", store_snapshot(AP_A, a, 10000) &&
          store_snapshot(AP_B, b, 10000));
    CHECK("policy", ac_db_roaming_policy_put(domain, &policy, 0) == 0);
    r = ac_db_roaming_policy_json(domain);
    CHECK("policy roundtrip", json_object_get_boolean(field(
        field(r, "policy"), "reassoc_block_enabled")) &&
        json_object_get_int(field(field(r, "policy"), "reassoc_block_sec")) == 10);
    json_object_put(r);
    CHECK("scope", ac_roam_steering_enable_scoped(domain, STA, 10000) == 0);
    CHECK("protection", ac_db_roaming_exclusion_put(
        "protect", domain, "mac", PROTECTED, "workstation", 10000) == 0);
    CHECK("protected", gate(domain, PROTECTED, 10000, "station_protected"));
    CHECK("other station excluded", gate(domain, OTHER, 10000, "steering_not_enabled"));
    CHECK("BTM first", gate(domain, STA, 10000, "btm_not_exhausted"));
    CHECK("weak RSSI guard", sql("UPDATE ac_station_sessions SET runtime_json="
        "'{\"signal_dbm\":-61,\"station_btm_capable\":true}' WHERE mac='" STA "'") &&
        gate(domain, STA, 10000, "signal_above_threshold"));
    CHECK("restore weak fixture", sql("UPDATE ac_station_sessions SET runtime_json="
        "'{\"signal_dbm\":-80,\"station_btm_capable\":true}' WHERE mac='" STA "'"));
    CHECK("recent failed BTM", sql(
        "INSERT INTO ac_btm_actions(domain_id,station_mac,ap_id,source_bssid,target_bssid,"
        "sent_at,sent_ok,outcome,created_at,policy_revision) VALUES(%Q,'" STA "','" AP_A "',"
        "'" SOURCE "','" TARGET "',9990,1,'not_roamed',9990,1)", domain));
    CHECK("all gates pass", gate(domain, STA, 10000, "all_conditions_met"));
    CHECK("old failures excluded", sql("UPDATE ac_btm_actions SET created_at=9000") &&
          gate(domain, STA, 10000, "btm_not_exhausted"));
    CHECK("other policy excluded", sql("UPDATE ac_btm_actions SET created_at=9990,"
          "policy_revision=0") && gate(domain, STA, 10000, "btm_not_exhausted"));
    CHECK("other AP excluded", sql("UPDATE ac_btm_actions SET policy_revision=1,ap_id='"
          AP_B "'") && gate(domain, STA, 10000, "btm_not_exhausted"));
    CHECK("other target excluded", sql("UPDATE ac_btm_actions SET ap_id='" AP_A
          "',target_bssid='" SOURCE_2G "'") &&
          gate(domain, STA, 10000, "btm_not_exhausted"));
    CHECK("pending never exhausted", sql("UPDATE ac_btm_actions SET target_bssid='"
          TARGET "',outcome='pending'") && gate(domain, STA, 10000, "btm_not_exhausted"));
    CHECK("restore failure", sql("UPDATE ac_btm_actions SET outcome='not_roamed'"));
    entry = json_object_array_get_idx(field(field(field(a, "sources"), "hostapd"),
                                           "beacon_reports"), 0);
    json_object_object_add(entry, "rcpi_dbm", json_object_new_int(-20));
    CHECK("candidate must be better", store_snapshot(AP_A, a, 10000) &&
          gate(domain, STA, 10000, "no_verified_better_candidate"));
    json_object_object_add(entry, "rcpi_dbm", json_object_new_int(-61));
    json_object_object_add(entry, "observed_at", json_object_new_int64(9800));
    CHECK("serving measurement fresh", store_snapshot(AP_A, a, 10000) &&
          gate(domain, STA, 10000, "serving_measurement_missing"));
    measurements(a, 9800);
    source_2g_report(a, 10000);
    entry = json_object_array_get_idx(field(field(field(a, "sources"), "hostapd"),
                                           "beacon_reports"), 0);
    json_object_object_add(entry, "observed_at", json_object_new_int64(10000));
    CHECK("candidate measurement fresh", store_snapshot(AP_A, a, 10000) &&
          gate(domain, STA, 10000, "candidate_measurements_missing"));
    measurements(a, 10000);
    source_2g_report(a, 10000);
    CHECK("restore measurements", store_snapshot(AP_A, a, 10000));
    CHECK("shared domain rate limit", sql(
        "INSERT INTO ac_deauth_actions(domain_id,station_mac,created_at,sent_at,outcome) "
        "VALUES(%Q,'" OTHER "',9995,9995,'blocked')", domain) &&
        gate(domain, STA, 10000, "domain_action_rate_limit"));
    CHECK("drop synthetic rate row", sql("DELETE FROM ac_deauth_actions"));
    CHECK("force cooldown", sql(
        "INSERT INTO ac_roaming_cooldowns(domain_id,station_mac,cooldown_until,reason,created_at) "
        "VALUES(%Q,'" STA "',10500,'target_association_observed',9995)", domain) &&
        gate(domain, STA, 10000, "cooldown_active"));
    CHECK("reset fixture rows", sql("DELETE FROM ac_roaming_cooldowns;"
                                    "DELETE FROM ac_btm_actions"));

    measurements(a, 11000);
    source_2g_report(a, 11000);
    CHECK("automatic setup", store_snapshot(AP_A, a, 11000) && refresh(11000));
    CHECK("automatic BTM", ac_db_roaming_schedule_tick(11000, &dispatched) == 0 &&
          dispatched == 1 && scalar("SELECT COUNT(*) FROM ac_btm_actions") == 1);
    CHECK("BTM ACK", acknowledge(11001));
    client_response(a, 0, 11002);
    entry = json_object_array_get_idx(field(field(field(a, "sources"), "hostapd"),
                                           "btm_responses"), 0);
    json_object_object_add(entry, "target_bssid", json_object_new_string(SOURCE_2G));
    CHECK("wrong target response", store_snapshot(AP_A, a, 11002) &&
          ac_db_roaming_schedule_tick(11016, &dispatched) == 0 &&
          scalar("SELECT COUNT(*) FROM ac_btm_actions WHERE outcome='not_roamed' "
                 "AND outcome_reason='station_selected_other_bssid'") == 1);
    CHECK("observation wait ends but interval remains", scalar(
        "SELECT cooldown_until FROM ac_roaming_cooldowns WHERE station_mac='" STA "'") == 11030);
    CHECK("same AP band escape", sql("UPDATE ac_station_sessions SET radio_id='radio1',"
        "connected_at=11016 WHERE association_id='phone'") && refresh(11030));
    CHECK("automatic AP-wide escalation", ac_db_roaming_schedule_tick(
        11030, &dispatched) == 0 && dispatched == 1);
    CHECK("only selected SSID/station and exact lease options", scalar(
        "SELECT COUNT(*) FROM ac_config_jobs j,json_each(j.candidate_json,'$.sections') s "
        "WHERE j.created_at=11030 AND json_extract(s.value,'$.section')='ath2' AND "
        "json_extract(s.value,'$.options.hostapd_action_type')='reassoc_block' AND "
        "json_extract(s.value,'$.options.station_mac')='" STA "' AND "
        "json_extract(s.value,'$.options.source_ssid')='Office' AND "
        "json_extract(s.value,'$.options.source_bssid')='" SOURCE_2G "' AND "
        "json_extract(s.value,'$.options.block_scope')='ap' AND "
        "json_extract(s.value,'$.options.block_duration_sec')='10' AND "
        "json_extract(s.value,'$.options.block_not_after')='11060'") == 1);
    CHECK("queue is not delivery", scalar("SELECT COUNT(*) FROM ac_deauth_actions "
        "WHERE sent_ok=0 AND outcome='pending' AND transaction_id<>''") == 1);
    CHECK("no duplicate", ac_db_roaming_schedule_tick(11031, &dispatched) == 0 &&
          dispatched == 0);
    CHECK("generic ACK cannot prove lease", acknowledge(11032) &&
        ac_db_roaming_schedule_tick(11032, &dispatched) == 0 &&
        scalar("SELECT sent_ok FROM ac_deauth_actions") == 0);
    CHECK("lease receipt", sql("UPDATE ac_config_jobs SET readback_json="
        "'{\"ok\":true,\"match\":true,\"evidence_type\":"
        "\"hostapd_temporary_reassociation_block\"}',updated_at=11033 "
        "WHERE created_at=11030;"
        "UPDATE ac_transaction_targets SET updated_at=11033 WHERE transaction_id IN "
        "(SELECT transaction_id FROM ac_config_jobs WHERE created_at=11030)") &&
        ac_db_roaming_schedule_tick(11034, &dispatched) == 0);
    CHECK("lease is not roam", scalar("SELECT COUNT(*) FROM ac_deauth_actions "
        "WHERE sent_ok=1 AND outcome='pending'") == 1);
    CHECK("actual target", sql("UPDATE ac_station_sessions SET ap_id='" AP_B
        "',radio_id='radio0',connected_at=11035,last_seen_at=11044 "
        "WHERE association_id='phone'") && refresh(11044) &&
        ac_db_roaming_schedule_tick(11044, &dispatched) == 0);
    CHECK("target confirmed after lease window", scalar(
        "SELECT COUNT(*) FROM ac_deauth_actions WHERE outcome='roamed' "
        "AND outcome_bssid='" TARGET "'") == 1);
    CHECK("forced cooldown retained", scalar(
        "SELECT cooldown_until FROM ac_roaming_cooldowns WHERE station_mac='" STA "'") == 11330);
    CHECK("same failed BTM cannot be reused", sql("DELETE FROM ac_roaming_cooldowns;"
        "UPDATE ac_station_sessions SET ap_id='" AP_A "',radio_id='radio0' "
        "WHERE association_id='phone'") &&
        gate(domain, STA, 11045, "deauth_cooldown_active"));
    CHECK("reopen outcome fixture", sql("UPDATE ac_deauth_actions SET outcome='pending'"));
    ac_db_test_deauth_resolve(scalar("SELECT deauth_id FROM ac_deauth_actions"),
                             SOURCE, 11060);
    CHECK("wrong association is never success", scalar(
        "SELECT COUNT(*) FROM ac_deauth_actions WHERE outcome='not_roamed'") == 1);
    json_object_put(a);
    json_object_put(b);
    ac_db_close();
    puts("ok");
    return 0;
}

// SPDX-License-Identifier: GPL-2.0-or-later
#define main ac_baseline_unused_main
#include "ac_roaming_automatic_fixture.c"
#undef main

#define IPHONE "d2:76:c1:3e:34:6c"
#define UNKNOWN "e2:76:c1:3e:34:6d"
#define AP_C "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
#define TARGET_C "02:00:00:00:30:01"

struct json_object *ac_db_roaming_deauth_evaluate_json(const char *, const char *,
    const char *, int, const char *, int64_t);

static void retitle(struct json_object *root)
{
    struct json_object *arrays[] = {
        field(field(root, "desired"), "ssids"), field(root, "ssids"),
        field(field(field(root, "sources"), "hostapd"), "bss")
    };
    size_t ai, i;

    for (ai = 0; ai < sizeof(arrays) / sizeof(arrays[0]); ai++)
        for (i = 0; i < json_object_array_length(arrays[ai]); i++)
            json_object_object_add(json_object_array_get_idx(arrays[ai], i),
                "broadcast_name", json_object_new_string("Xiaomi_DE23"));
}

static void probe(struct json_object *root, const char *mac,
                  const char *interface, const char *bssid,
                  int dbm, int64_t observed_at)
{
    struct json_object *hostapd = field(field(root, "sources"), "hostapd");
    struct json_object *array = field(hostapd, "probe_observations");
    struct json_object *entry = json_object_new_object();

    if (!array) {
        array = json_object_new_array();
        json_object_object_add(hostapd, "probe_observations", array);
    }
    json_object_object_add(entry, "station_mac", json_object_new_string(mac));
    json_object_object_add(entry, "interface", json_object_new_string(interface));
    json_object_object_add(entry, "bssid", json_object_new_string(bssid));
    json_object_object_add(entry, "rssi_dbm", json_object_new_int(dbm));
    json_object_object_add(entry, "observed_at",
                           json_object_new_int64(observed_at));
    json_object_object_add(entry, "mac_randomized", json_object_new_boolean(1));
    json_object_object_add(entry, "frame_type",
                           json_object_new_string("probe_request"));
    json_object_object_add(entry, "direction", json_object_new_string("uplink"));
    json_object_object_add(entry, "source",
                           json_object_new_string("hostapd_control_event"));
    json_object_array_add(array, entry);
}

static void response(struct json_object *root, int code, const char *target,
                     int64_t now)
{
    struct json_object *hostapd = field(field(root, "sources"), "hostapd");
    struct json_object *responses = json_object_new_array();
    struct json_object *entry = json_object_new_object();

    json_object_object_add(entry, "station_mac", json_object_new_string(IPHONE));
    json_object_object_add(entry, "interface", json_object_new_string("ath0"));
    json_object_object_add(entry, "target_bssid", json_object_new_string(target));
    json_object_object_add(entry, "status_code", json_object_new_int(code));
    json_object_object_add(entry, "observed_at", json_object_new_int64(now));
    json_object_array_add(responses, entry);
    json_object_object_add(hostapd, "btm_responses", responses);
}

static void beacon(struct json_object *root, const char *bssid,
                   int dbm, int64_t now)
{
    struct json_object *report = json_object_new_object();
    struct json_object *reports = json_object_new_array();

    json_object_object_add(report, "station_mac", json_object_new_string(IPHONE));
    json_object_object_add(report, "bssid", json_object_new_string(bssid));
    json_object_object_add(report, "rcpi_dbm", json_object_new_int(dbm));
    json_object_object_add(report, "observed_at", json_object_new_int64(now));
    json_object_array_add(reports, report);
    json_object_object_add(field(field(root, "sources"), "hostapd"),
                           "beacon_reports", reports);
}

static int reason_is(const char *domain, int64_t now, const char *wanted)
{
    struct json_object *result = ac_db_roaming_domain_observe_json(
        domain, IPHONE, "observe_only", now);
    const char *reason = json_object_get_string(field(result, "reason"));
    int matches = reason && !strcmp(reason, wanted);

    if (!matches)
        fprintf(stderr, "wanted %s, observed %s\n", wanted,
                reason ? reason : "(null)");
    json_object_put(result);
    return matches;
}

int main(void)
{
    char domain[37];
    struct json_object *a = snapshot(), *b = snapshot(), *c = snapshot();
    struct json_object *result, *entry;
    struct ac_roaming_policy policy = {
        .weak_rssi_dbm = -75, .minimum_candidate_gain_db = 10,
        .candidate_min_rssi_dbm = -67, .decision_min_interval_sec = 30,
        .post_roam_cooldown_sec = 300, .max_btm_attempts_per_hour = 2,
        .deauth_after_btm_failures = 1, .deauth_cooldown_sec = 300,
        .domain_action_rate_limit = 2, .updated_by = "fixture",
        .reassoc_block_enabled = 1, .reassoc_block_sec = 10,
        .reassoc_block_scope = "ap", .steering_preference = "stability",
        .high_band_steer_enabled = 1, .force_disassoc_on_reject = 1,
        .lower_band_block_enabled = 1
    };
    int dispatched = 0;

    CHECK("init", ac_db_init() == 0);
    CHECK("domain", ac_db_roaming_domain_put(NULL, "Xiaomi_DE23",
        "[\"ssid-main\"]", "[\"floor-one\"]", "ap-local-existing", "",
        0, "over_air", 1, 1, 0, NULL, 0,
        "fixture", domain) == 0);
    CHECK("separate force opt-in", ac_db_roaming_domain_put(domain,
        "Xiaomi_DE23", "[\"ssid-main\"]", "[\"floor-one\"]",
        "ap-local-existing", "", 0, "over_air", 1, 1, 1,
        "enable-forced-deauth", 1, "fixture", NULL) == 0);
    CHECK("three APs and exact station session", sql(
        "INSERT INTO ac_ap_groups(group_id,site_id,name,revision,updated_at) "
        "VALUES('floor-one','default','one',1,5000);"
        "INSERT INTO ac_ssids(ssid_id,site_id,name,revision,enabled,updated_at) "
        "VALUES('ssid-main','default','Xiaomi_DE23',1,1,5000);"
        "INSERT INTO ac_aps(ap_id,site_id,name,adoption_state,last_seen_at) "
        "VALUES('" AP_A "','default','A','adopted',5000),"
        "('" AP_B "','default','B','adopted',5000),"
        "('" AP_C "','default','C','adopted',5000);"
        "INSERT INTO ac_ap_group_members(group_id,ap_id) VALUES"
        "('floor-one','" AP_A "'),('floor-one','" AP_B "'),"
        "('floor-one','" AP_C "');"
        "INSERT INTO ac_ap_runtime(ap_id,observed_at,received_at,"
        "control_protocol_version,write_capable,session_connected,stale) "
        "VALUES('" AP_A "',5000,5000,3,1,1,0),"
        "('" AP_B "',5000,5000,3,1,1,0),"
        "('" AP_C "',5000,5000,3,1,1,0);"
        "INSERT INTO ac_ssid_bindings(ssid_id,ap_id,radio_id,state,bssid,section_name) "
        "VALUES('ssid-main','" AP_A "','radio0','applied','" SOURCE "','vap0'),"
        "('ssid-main','" AP_B "','radio0','applied','" TARGET "','vap6'),"
        "('ssid-main','" AP_C "','radio0','applied','" TARGET_C "','vap0');"
        "INSERT INTO ac_station_sessions(association_id,ap_id,radio_id,ssid_id,"
        "mac,connected_at,last_seen_at,runtime_json) VALUES"
        "('phone','" AP_A "','radio0','ssid-main','" IPHONE "',4900,5000,"
        "'{\"signal_dbm\":-80,\"station_btm_capable\":true}')"));
    add_bss(a, "radio0", "vap0", "ath0", SOURCE, 5180, 36);
    add_bss(b, "radio0", "vap6", "phy0.2-ap0", TARGET, 6775, 165);
    add_bss(c, "radio0", "vap0", "ath0", TARGET_C, 5180, 36);
    retitle(a);
    retitle(b);
    retitle(c);
    json_object_object_add(bss_at(a, 0), "reassoc_block",
                           json_object_new_boolean(1));
    CHECK("base snapshots", store_snapshot(AP_A, a, 5000) &&
        store_snapshot(AP_B, b, 5000) && store_snapshot(AP_C, c, 5000));
    CHECK("policy", ac_db_roaming_policy_put(domain, &policy, 0) == 0);
    CHECK("scoped steering", ac_roam_steering_enable_scoped(
        domain, IPHONE, 5000) == 0);
    CHECK("no Probe never steers", reason_is(domain, 5000,
        "candidate_measurements_missing"));

    probe(b, UNKNOWN, "phy0.2-ap0", TARGET, -40, 5000);
    CHECK("unknown random MAC is not the iPhone", store_snapshot(AP_B, b, 5000) &&
        reason_is(domain, 5000, "candidate_measurements_missing"));
    json_object_object_add(field(field(b, "sources"), "hostapd"),
                           "probe_observations", json_object_new_array());
    probe(b, IPHONE, "wrong-interface", TARGET, -40, 5000);
    CHECK("unattributed Probe rejected", store_snapshot(AP_B, b, 5000) &&
        reason_is(domain, 5000, "candidate_measurements_missing"));
    json_object_object_add(field(field(b, "sources"), "hostapd"),
                           "probe_observations", json_object_new_array());
    probe(b, IPHONE, "phy0.2-ap0", TARGET, -50, 4800);
    CHECK("expired Probe rejected", store_snapshot(AP_B, b, 5000) &&
        reason_is(domain, 5000, "candidate_measurements_missing"));

    json_object_object_add(field(field(b, "sources"), "hostapd"),
                           "probe_observations", json_object_new_array());
    probe(b, IPHONE, "phy0.2-ap0", TARGET, -50, 5000);
    probe(c, IPHONE, "ath0", TARGET_C, -53, 5000);
    CHECK("fresh two-AP uplink", store_snapshot(AP_B, b, 5000) &&
        store_snapshot(AP_C, c, 5000) &&
        reason_is(domain, 5000, "observe_only_no_action"));
    result = ac_db_roaming_domain_observe_json(domain, IPHONE,
                                                "observe_only", 5000);
    CHECK("serving uplink explicitly labeled", !strcmp(
        json_object_get_string(field(result, "comparison_signal_direction")),
        "uplink") && json_object_get_int(
        field(result, "comparison_signal_dbm")) == -80);
    json_object_put(result);

    beacon(b, TARGET, -34, 5000);
    CHECK("Beacon downlink never mixes with serving uplink",
        store_snapshot(AP_B, b, 5000) &&
        reason_is(domain, 5000, "observe_only_no_action"));
    entry = json_object_array_get_idx(field(field(field(b, "sources"), "hostapd"),
                                            "beacon_reports"), 0);
    CHECK("mixed candidate is excluded", entry && !strcmp(
        json_object_get_string(field(entry, "bssid")), TARGET));
    json_object_object_add(field(field(c, "sources"), "hostapd"),
                           "probe_observations", json_object_new_array());
    CHECK("only mixed measurement refuses", store_snapshot(AP_C, c, 5000) &&
        reason_is(domain, 5000, "candidate_signal_direction_mismatch"));
    json_object_object_add(field(field(b, "sources"), "hostapd"),
                           "beacon_reports", json_object_new_array());
    probe(c, IPHONE, "ath0", TARGET_C, -53, 5000);
    CHECK("restore paired uplink", store_snapshot(AP_B, b, 5000) &&
        store_snapshot(AP_C, c, 5000));

    CHECK("strong source blocks force", sql(
        "UPDATE ac_station_sessions SET runtime_json="
        "'{\"signal_dbm\":-61,\"station_btm_capable\":true}' "
        "WHERE mac='" IPHONE "'") &&
        reason_is(domain, 5000, "signal_above_threshold"));
    snprintf(policy.steering_preference,
             sizeof(policy.steering_preference), "performance");
    CHECK("performance policy", ac_db_roaming_policy_put(domain, &policy, 1) == 0);
    result = ac_db_roaming_domain_observe_json(domain, IPHONE,
                                                "observe_only", 5000);
    CHECK("performance mode considers better AP above threshold",
        !strcmp(json_object_get_string(field(result, "reason")),
                "observe_only_no_action") &&
        !strcmp(json_object_get_string(field(result, "steering_preference")),
                "performance"));
    json_object_put(result);
    snprintf(policy.steering_preference,
             sizeof(policy.steering_preference), "stability");
    CHECK("restore stability policy", ac_db_roaming_policy_put(domain, &policy, 2) == 0);
    CHECK("restore weak source", sql(
        "UPDATE ac_station_sessions SET runtime_json="
        "'{\"signal_dbm\":-80,\"station_btm_capable\":true}' "
        "WHERE mac='" IPHONE "'"));

    result = ac_db_roaming_domain_observe_json(domain, IPHONE, "active", 5000);
    CHECK("BTM queued", !strcmp(json_object_get_string(
        field(result, "reason")), "btm_queued"));
    CHECK("two distinct AP targets", !strcmp(json_object_get_string(
        field(result, "target_bssid")), TARGET) && !strcmp(
        json_object_get_string(field(result, "target_bssid_2")), TARGET_C));
    json_object_put(result);
    CHECK("compact RF/imminent transaction", scalar(
        "SELECT COUNT(*) FROM ac_config_jobs j,json_each(j.candidate_json,'$.sections') s "
        "WHERE j.created_at=5000 AND "
        "json_extract(s.value,'$.options.hostapd_action_type')='btm_request' "
        "AND json_extract(s.value,'$.options.target_bssid_2')='" TARGET_C "' "
        "AND json_extract(s.value,'$.options.target_opclass_2')='115' "
        "AND json_extract(s.value,'$.options.target_channel_2')='36' "
        "AND json_extract(s.value,'$.options.btm_disassoc_imminent')='1' "
        "AND json_extract(s.value,'$.options.btm_disassoc_timer')='10'") == 1);
    CHECK("AP ACK", acknowledge(5001));
    response(a, 7, TARGET, 5002);
    CHECK("client Reject observed", store_snapshot(AP_A, a, 5002) &&
        ac_db_roaming_schedule_tick(5002, &dispatched) == 0 &&
        scalar("SELECT COUNT(*) FROM ac_btm_actions WHERE station_mac='" IPHONE "' "
               "AND outcome='not_roamed' AND sent_ok=1") == 1);
    result = ac_db_roaming_deauth_evaluate_json(domain, IPHONE, "fixture",
                                                0, NULL, 5030);
    CHECK("Reject permits short source lease only after interval",
        !strcmp(json_object_get_string(field(result, "reason")),
                "all_conditions_met") &&
        !strcmp(json_object_get_string(field(result, "target_bssid_2")),
                TARGET_C));
    json_object_put(result);
    result = ac_db_roaming_deauth_evaluate_json(domain, IPHONE, "fixture",
                                                1, "execute-forced-deauth", 5030);
    CHECK("lease blocks lower bands while preserving target", json_object_get_boolean(
        field(result, "queued")) && scalar(
        "SELECT COUNT(*) FROM ac_config_jobs j,json_each(j.candidate_json,'$.sections') s "
        "WHERE j.created_at=5030 AND "
        "json_extract(s.value,'$.options.hostapd_action_type')='reassoc_block' "
        "AND json_extract(s.value,'$.options.station_mac')='" IPHONE "' "
        "AND json_extract(s.value,'$.options.block_scope')='lower' "
        "AND json_extract(s.value,'$.options.block_duration_sec')='10'") == 1);
    json_object_put(result);
    CHECK("lease receipt", acknowledge(5031) && sql(
        "UPDATE ac_config_jobs SET readback_json="
        "'{\"ok\":true,\"match\":true,\"evidence_type\":"
        "\"hostapd_temporary_reassociation_block\"}' "
        "WHERE created_at=5030"));
    CHECK("second target association", sql(
        "UPDATE ac_station_sessions SET ap_id='" AP_C "',radio_id='radio0',"
        "connected_at=5032,last_seen_at=5043 WHERE mac='" IPHONE "'") &&
        refresh(5043) && ac_db_roaming_schedule_tick(5043, &dispatched) == 0 &&
        scalar("SELECT COUNT(*) FROM ac_deauth_actions WHERE station_mac='" IPHONE "' "
               "AND outcome='roamed' AND outcome_bssid='" TARGET_C "'") == 1);
    CHECK("no repeated kick at qualified target", scalar(
        "SELECT COUNT(*) FROM ac_deauth_actions WHERE station_mac='" IPHONE "'") == 1);

    json_object_put(a);
    json_object_put(b);
    json_object_put(c);
    ac_db_close();
    puts("ok");
    return 0;
}

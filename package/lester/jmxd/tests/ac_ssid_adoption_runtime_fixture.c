// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <json-c/json.h>
#include <sqlite3.h>

extern sqlite3 *g_ac_db;
int ac_db_init(void);
void ac_db_close(void);
struct json_object *ac_db_ssid_adopt_json(const char *, const char *,
    const char *, const char *, struct json_object *, int64_t);
struct json_object *ac_db_roaming_domain_preflight_json(const char *, int64_t);
struct json_object *ac_db_roaming_domain_apply_json(const char *, const char *, int64_t);
int ac_db_roaming_domain_put(const char *, const char *, const char *,
    const char *, const char *, const char *, int, const char *, int, int,
    int, const char *, int64_t, const char *, char *);

#define AP "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
#define SSID "11111111-1111-4111-8111-111111111111"
#define OTHER "22222222-2222-4222-8222-222222222222"
#define CHECK(name, expr) do { if (!(expr)) { \
    fprintf(stderr, "FAIL: %s (%s)\n", name, sqlite3_errmsg(g_ac_db)); \
    return 1; } } while (0)

static int sql(const char *text)
{
    return sqlite3_exec(g_ac_db, text, NULL, NULL, NULL) == SQLITE_OK;
}

static struct json_object *field(struct json_object *o, const char *key)
{
    return json_object_object_get(o, key);
}

static int scalar(const char *text)
{
    sqlite3_stmt *st = NULL;
    int result = -1;
    if (sqlite3_prepare_v2(g_ac_db, text, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        result = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return result;
}

static int expect_error(struct json_object *result, const char *reason)
{
    const char *error = json_object_get_string(field(result, "error"));
    int ok = !json_object_get_boolean(field(result, "ok")) &&
        error && !strcmp(error, reason);
    if (!ok)
        fprintf(stderr, "Unexpected response: %s\n", json_object_to_json_string(result));
    json_object_put(result);
    return ok;
}

int main(void)
{
    const char *snapshot =
        "{\"desired\":{\"radios\":[{\"id\":\"radio0\"},{\"id\":\"wifi1\"}],"
        "\"ssids\":[{\"id\":\"vap24\",\"radio_id\":\"radio0\",\"mode\":\"ap\","
        "\"broadcast_name\":\"Mesh\",\"security_mode\":\"sae+ccmp\",\"password_present\":true},"
        "{\"id\":\"vap5\",\"radio_id\":\"wifi1\",\"mode\":\"ap\","
        "\"broadcast_name\":\"Mesh\",\"security_mode\":\"sae+ccmp\",\"password_present\":true}]},"
        "\"radios\":[{\"id\":\"phy0r0\",\"interfaces\":[{\"interface\":\"radio0\"}]},"
        "{\"id\":\"phy0r1\",\"interfaces\":[{\"interface\":\"wifi1\"}]}],"
        "\"ssids\":[{\"id\":\"ath0\",\"interface\":\"ath0\",\"radio_id\":\"phy0r0\","
        "\"broadcast_name\":\"Mesh\",\"bssid\":\"02:00:00:00:00:10\"},"
        "{\"id\":\"ath1\",\"interface\":\"ath1\",\"radio_id\":\"phy0r1\","
        "\"broadcast_name\":\"Mesh\",\"bssid\":\"02:00:00:00:00:11\"}],"
        "\"sources\":{\"hostapd\":{\"available\":true,\"complete\":false,"
        "\"bss\":[{\"interface\":\"ath0\",\"bssid\":\"02:00:00:00:00:10\","
        "\"complete\":true,\"hostapd_ctrl_reachable\":true,\"neighbor_report_80211k\":true},"
        "{\"interface\":\"ath1\",\"bssid\":\"02:00:00:00:00:11\","
        "\"complete\":true,\"hostapd_ctrl_reachable\":true,\"neighbor_report_80211k\":true}]}}}";
    struct json_object *bindings = json_tokener_parse(
        "[{\"ap_id\":\"" AP "\",\"radio_id\":\"phy0r0\",\"section_name\":\"vap24\","
        "\"bssid\":\"02:00:00:00:00:10\"},"
        "{\"ap_id\":\"" AP "\",\"radio_id\":\"phy0r1\",\"section_name\":\"vap5\","
        "\"bssid\":\"02:00:00:00:00:11\"}]");
    struct json_object *result;
    char domain[37];
    sqlite3_stmt *st = NULL;

    CHECK("init", ac_db_init() == 0);
    CHECK("seed AP", sql(
        "INSERT INTO ac_aps(ap_id,site_id,adoption_state,last_seen_at) "
        "VALUES('" AP "','default','adopted',1999);"
        "INSERT INTO ac_ap_runtime(ap_id,observed_at,received_at,stale,"
        "control_protocol_version,write_capable,session_connected) "
        "VALUES('" AP "',1999,1999,0,3,1,1);"
        "INSERT INTO ac_station_sessions(association_id,ap_id,radio_id,ssid_id,mac,"
        "connected_at,last_seen_at) VALUES('station','" AP "','phy0r0','ath0',"
        "'02:00:00:00:01:01',1990,1999);"));
    CHECK("snapshot prepare", sqlite3_prepare_v2(g_ac_db,
        "UPDATE ac_ap_runtime SET runtime_json=?1", -1, &st, NULL) == SQLITE_OK);
    sqlite3_bind_text(st, 1, snapshot, -1, SQLITE_TRANSIENT);
    CHECK("snapshot", sqlite3_step(st) == SQLITE_DONE);
    sqlite3_finalize(st);

    CHECK("name mismatch", expect_error(ac_db_ssid_adopt_json(
        SSID, "default", "Wrong", "mesh", bindings, 2000),
        "roaming_binding_section_unavailable"));
    CHECK("no side effects", scalar("SELECT COUNT(*) FROM ac_ssids") == 0);
    CHECK("stale seed", sql("UPDATE ac_ap_runtime SET stale=1"));
    CHECK("stale refusal", expect_error(ac_db_ssid_adopt_json(
        SSID, "default", "Mesh", "mesh", bindings, 2000),
        "roaming_binding_section_stale"));
    CHECK("restore fresh", sql("UPDATE ac_ap_runtime SET stale=0"));
    CHECK("site isolation", expect_error(ac_db_ssid_adopt_json(
        SSID, "other-site", "Mesh", "mesh", bindings, 2000),
        "ssid_ap_not_adopted_online_in_site"));
    CHECK("atomic site refusal", scalar("SELECT COUNT(*) FROM ac_ap_groups") == 0 &&
          scalar("SELECT COUNT(*) FROM ac_ssids") == 0);
    result = ac_db_ssid_adopt_json(SSID, "default", "Mesh", "mesh", bindings, 2000);
    CHECK("adopt encrypted", json_object_get_boolean(field(result, "ok")));
    CHECK("no wireless writes", !json_object_get_boolean(field(result, "wireless_changed")));
    CHECK("credentials not claimed verified", !json_object_get_boolean(
        field(result, "credentials_verified")));
    json_object_put(result);
    CHECK("bindings", scalar("SELECT COUNT(*) FROM ac_ssid_bindings") == 2);
    CHECK("group single AP", scalar("SELECT COUNT(*) FROM ac_ap_group_members") == 1);
    CHECK("no jobs", scalar("SELECT COUNT(*) FROM ac_config_jobs") == 0);
    CHECK("station mapped", scalar("SELECT COUNT(*) FROM ac_station_sessions "
        "WHERE ssid_id='" SSID "'") == 1);
    CHECK("no duplicate owner", expect_error(ac_db_ssid_adopt_json(
        OTHER, "default", "Mesh", "mesh", bindings, 2000), "ssid_binding_already_managed"));
    CHECK("no partial ownership", scalar("SELECT COUNT(*) FROM ac_ssids") == 1);
    CHECK("domain", ac_db_roaming_domain_put(NULL, "Mesh test", "[\"" SSID "\"]",
        "[\"mesh\"]", "ap-local-existing", "", 0, "over_air", 0, 0, 0, NULL,
        0, "test", domain) == 0);
    result = ac_db_roaming_domain_preflight_json(domain, 2000);
    CHECK("partial aggregate complete BSS allowed",
        json_object_get_int(field(result, "eligible_count")) == 2);
    CHECK("persisted section", !strcmp(json_object_get_string(field(
        json_object_array_get_idx(field(result, "members"), 0), "section_name")), "vap24"));
    json_object_put(result);

    CHECK("rename section", sql("UPDATE ac_ssid_bindings SET section_name='gone' "
        "WHERE radio_id='phy0r0'"));
    CHECK("all-or-nothing fails before dispatch", expect_error(
        ac_db_roaming_domain_apply_json(domain, "all_or_nothing", 2000),
        "roaming_members_not_ready"));
    CHECK("still no jobs", scalar("SELECT COUNT(*) FROM ac_config_jobs") == 0);
    CHECK("restore section", sql("UPDATE ac_ssid_bindings SET section_name='vap24' "
        "WHERE radio_id='phy0r0'"));
    result = ac_db_roaming_domain_apply_json(domain, "all_or_nothing", 2001);
    if (!json_object_get_boolean(field(result, "ok")))
        fprintf(stderr, "Apply response: %s\n", json_object_to_json_string(result));
    CHECK("apply queues", json_object_get_boolean(field(result, "ok")));
    json_object_put(result);
    CHECK("one target per AP", scalar("SELECT COUNT(*) FROM ac_transaction_targets") == 1);
    CHECK("one job", scalar("SELECT COUNT(*) FROM ac_config_jobs") == 1);
    CHECK("two real sections", scalar(
        "SELECT json_array_length(candidate_json,'$.sections') FROM ac_config_jobs") == 2);
    CHECK("no radio section", scalar(
        "SELECT COUNT(*) FROM ac_config_jobs,json_each(candidate_json,'$.sections') e "
        "WHERE json_extract(e.value,'$.section') IN ('vap24','vap5') "
        "AND json_extract(e.value,'$.operation')='set' "
        "AND json_type(e.value,'$.section_type') IS NULL") == 2);
    CHECK("no password or create", scalar(
        "SELECT COUNT(*) FROM ac_config_jobs WHERE candidate_json LIKE '%\"key\"%' "
        "OR candidate_json LIKE '%\"create\"%'") == 0);
    json_object_put(bindings);
    ac_db_close();
    puts("ok");
    return 0;
}

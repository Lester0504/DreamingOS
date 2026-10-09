// SPDX-License-Identifier: GPL-2.0-or-later
/* Phase 1/2 roaming-domain contract: CRUD, optimistic revision control,
 * member isolation, fail-closed observe-only decisions, and the Deauth gate. */
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>
#include <sqlite3.h>

#include "ac_secrets.h"

extern sqlite3 *g_ac_db;
int ac_db_init(void);
void ac_db_close(void);
void ac_db_set_secrets(struct ac_secrets *);
int ac_db_roaming_domain_put(const char *, const char *, const char *,
                             const char *, const char *, const char *, int,
                             const char *, int, int, int, const char *,
                             int64_t, const char *, char *);
int64_t ac_db_test_deauth_record(const char *, const char *, const char *,
                                 const char *, const char *, int64_t);
void ac_db_test_deauth_mark_sent(int64_t, int, const char *);
void ac_db_test_deauth_resolve(int64_t, const char *, int64_t);
void ac_db_test_deauth_check_outcomes(const char *, int64_t);
int ac_db_test_deauth_breaker(const char *, int64_t);
int ac_roam_steering_enable(const char *, int64_t);
const char *ac_db_test_forced_action_reason(const char *);
int ac_db_roaming_domain_delete(const char *, int64_t);
struct json_object *ac_db_roaming_domain_json(const char *);
struct json_object *ac_db_roaming_domain_preflight_json(const char *, int64_t);
struct json_object *ac_db_roaming_domain_observe_json(
    const char *, const char *, const char *, int64_t);
struct ac_roaming_policy {
    int weak_rssi_dbm;
    int minimum_candidate_gain_db;
    int candidate_min_rssi_dbm;
    int decision_min_interval_sec;
    int post_roam_cooldown_sec;
    int max_btm_attempts_per_hour;
    int deauth_after_btm_failures;
    int deauth_cooldown_sec;
    int domain_action_rate_limit;
    int64_t revision;
    int64_t updated_at;
    char updated_by[65];
    int reassoc_block_enabled, reassoc_block_sec;
    char reassoc_block_scope[6];
    char steering_preference[16];
    int high_band_steer_enabled;
    int force_disassoc_on_reject;
    int lower_band_block_enabled;
};
struct json_object *ac_db_roaming_policy_json(const char *);
int ac_db_roaming_policy_put(const char *,
                             const struct ac_roaming_policy *, int64_t);
int ac_db_roaming_exclusion_put(const char *, const char *, const char *,
                                const char *, const char *, int64_t);
int ac_db_roaming_exclusion_delete(const char *);
struct json_object *ac_db_roaming_exclusions_json(const char *);
struct json_object *ac_db_roaming_audit_json(const char *, const char *, int);
int ac_roaming_global_op_class(const char *, int);
int ac_roaming_phy_type(const char *);


#define CHECK(name, condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: %s\n", name); \
        ac_db_close(); \
        return 1; \
    } \
} while (0)

enum {
    AC_ROAMING_DOMAIN_INVALID = -1,
    AC_ROAMING_DOMAIN_CONFLICT = -3,
};

static struct json_object *field(struct json_object *object, const char *name)
{
    struct json_object *value = NULL;

    return object && json_object_object_get_ex(object, name, &value) ?
        value : NULL;
}

#define SELECTED_BINDING_SNAPSHOT \
    "{\"desired\":{\"radios\":[{\"id\":\"radio0\",\"phy\":\"radio0\"}]," \
    "\"ssids\":[{\"id\":\"vap0\",\"radio_id\":\"radio0\"," \
    "\"broadcast_name\":\"Office\"}]}," \
    "\"ssids\":[{\"id\":\"ath0\",\"radio_id\":\"radio0\"," \
    "\"interface\":\"ath0\",\"bssid\":\"02:00:00:00:10:01\"," \
    "\"broadcast_name\":\"Office\"}],"

/* Small SQL scalar reader used by the Phase 4 audit assertions. */
static const char *scalar_text(const char *sql_fmt, ...)
{
    static char out[192];
    char sql[512];
    sqlite3_stmt *st = NULL;
    va_list ap;

    out[0] = 0;
    va_start(ap, sql_fmt);
    vsnprintf(sql, sizeof(sql), sql_fmt, ap);
    va_end(ap);
    if (sqlite3_prepare_v2(g_ac_db, sql, -1, &st, NULL) != SQLITE_OK)
        return out;
    if (sqlite3_step(st) == SQLITE_ROW)
        snprintf(out, sizeof(out), "%s", sqlite3_column_text(st, 0));
    sqlite3_finalize(st);
    return out;
}

int main(int argc, char **argv)
{
    char domain_id[37] = {0};
    struct json_object *response;
    struct ac_secrets *secrets = NULL;
    struct ac_roaming_policy policy = {
        .weak_rssi_dbm = -75,
        .minimum_candidate_gain_db = 10,
        .candidate_min_rssi_dbm = -67,
        .decision_min_interval_sec = 120,
        .post_roam_cooldown_sec = 300,
        .max_btm_attempts_per_hour = 2,
        .deauth_after_btm_failures = 1,
        .deauth_cooldown_sec = 900,
        .domain_action_rate_limit = 2,
        .updated_by = "acceptance",
    };

    CHECK("init", ac_db_init() == 0);
    if (argc > 1 && !strcmp(argv[1], "migration-only")) {
        CHECK("legacy band steering migrated", !strcmp(scalar_text(
                  "SELECT high_band_steer_enabled FROM ac_roaming_policies"
                  " WHERE domain_id='legacy-domain'"), "1"));
        ac_db_close();
        puts("ok");
        return 0;
    }
    /* The FT fan-out derives R0KH/R1KH material through the secret store and
     * fails closed without one, so the fixture stands up a real store in the
     * test temp dir rather than stubbing it. */
    CHECK("secrets open", ac_secrets_open_or_create(
              g_ac_db,
              getenv("DREAMINGWRT_AC_SECRETS_KEY_PATH"),
              &secrets) == AC_SECRETS_OK);
    ac_db_set_secrets(secrets);
    CHECK("create", ac_db_roaming_domain_put(NULL, "Office roaming",
              "[\"ssid-main\"]", "[\"floor-one\"]", "wpa3-main",
              "a1b2", 1, "over_air", 1, 1, 0, NULL, 0, "acceptance",
              domain_id) == 0);
    CHECK("generated id", strlen(domain_id) == 36);

    response = ac_db_roaming_domain_json(domain_id);
    CHECK("get ok", json_object_get_boolean(field(response, "ok")));
    CHECK("revision one", json_object_get_int64(field(
              field(response, "domain"), "revision")) == 1);
    CHECK("deauth false", !json_object_get_boolean(field(
              field(response, "domain"), "deauth_enabled")));
    json_object_put(response);

    CHECK("stale revision rejected", ac_db_roaming_domain_put(domain_id,
              "Office roaming stale", "[\"ssid-main\"]",
              "[\"floor-one\"]", "wpa3-main", "a1b2", 1,
              "over_air", 1, 1, 0, NULL, 0, "acceptance", NULL) ==
          AC_ROAMING_DOMAIN_CONFLICT);
    /* ---- Phase 4 authorisation gate ----
     * Enabling forced deauth without the confirmation token must fail, and
     * must keep failing for each individual precondition. */
    CHECK("deauth without confirmation rejected", ac_db_roaming_domain_put(
              domain_id, "Office roaming", "[\"ssid-main\"]",
              "[\"floor-one\"]", "wpa3-main", "a1b2", 1, "over_air", 1, 1, 1,
              NULL, 1, "acceptance", NULL) == AC_ROAMING_DOMAIN_INVALID);
    CHECK("deauth with wrong token rejected", ac_db_roaming_domain_put(
              domain_id, "Office roaming", "[\"ssid-main\"]",
              "[\"floor-one\"]", "wpa3-main", "a1b2", 1, "over_air", 1, 1, 1,
              "yes", 1, "acceptance", NULL) == AC_ROAMING_DOMAIN_INVALID);
    /* Deauth is BTM's fallback, so it cannot be enabled with 11v off. */
    CHECK("deauth without btm rejected", ac_db_roaming_domain_put(
              domain_id, "Office roaming", "[\"ssid-main\"]",
              "[\"floor-one\"]", "wpa3-main", "a1b2", 1, "over_air", 1, 0, 1,
              "enable-forced-deauth", 1, "acceptance", NULL) ==
          AC_ROAMING_DOMAIN_INVALID);
    /* A domain cannot be born with it on -- it must be a deliberate edit. */
    CHECK("deauth on create rejected", ac_db_roaming_domain_put(
              NULL, "Born hostile", "[\"ssid-main\"]", "[\"floor-one\"]",
              "wpa3-main", "a1b2", 1, "over_air", 1, 1, 1,
              "enable-forced-deauth", 0, "acceptance", NULL) ==
          AC_ROAMING_DOMAIN_INVALID);
    CHECK("update", ac_db_roaming_domain_put(domain_id, "Office roaming v2",
              "[\"ssid-main\"]", "[\"floor-one\"]", "wpa3-main",
              "a1b2", 1, "over_air", 1, 1, 0, NULL, 1, "acceptance",
              NULL) == 0);

    /* With every precondition met it is accepted and actually persists. */
    CHECK("deauth accepted with token", ac_db_roaming_domain_put(domain_id,
              "Office roaming v2", "[\"ssid-main\"]", "[\"floor-one\"]",
              "wpa3-main", "a1b2", 1, "over_air", 1, 1, 1,
              "enable-forced-deauth", 2, "acceptance", NULL) == 0);
    response = ac_db_roaming_domain_json(domain_id);
    CHECK("deauth now true", json_object_get_boolean(field(
              field(response, "domain"), "deauth_enabled")));
    json_object_put(response);
    /* Turning it back off must not require the token: disabling a dangerous
     * feature can never be harder than enabling it. */
    CHECK("deauth off needs no token", ac_db_roaming_domain_put(domain_id,
              "Office roaming v2", "[\"ssid-main\"]", "[\"floor-one\"]",
              "wpa3-main", "a1b2", 1, "over_air", 1, 1, 0, NULL, 3,
              "acceptance", NULL) == 0);
    response = ac_db_roaming_domain_json(domain_id);
    CHECK("deauth off again", !json_object_get_boolean(field(
              field(response, "domain"), "deauth_enabled")));
    json_object_put(response);

    CHECK("seed selected group", sqlite3_exec(g_ac_db,
              "INSERT INTO ac_ap_groups(group_id,site_id,name,revision,updated_at) "
              "VALUES('floor-one','default','Floor one',1,1000);"
              "INSERT INTO ac_aps(ap_id,site_id,name,adoption_state,last_seen_at) "
              "VALUES('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','default','selected',"
              "'adopted',1999);"
              "INSERT INTO ac_ap_group_members(group_id,ap_id) VALUES(" 
              "'floor-one','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');"
              "INSERT INTO ac_ssid_bindings(ssid_id,ap_id,radio_id,state,bssid,section_name) "
              "VALUES('ssid-main','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',"
              "'radio0','applied','02:00:00:00:10:01','vap0');"
              "INSERT INTO ac_ap_runtime(ap_id,observed_at,received_at,"
              "control_protocol_version,write_capable,session_connected,stale) "
              "VALUES('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',1999,1999,3,1,1,0);"
              "INSERT INTO ac_station_sessions(association_id,ap_id,radio_id,"
              "ssid_id,mac,connected_at,disconnected_at,last_seen_at,runtime_json) "
              "VALUES('selected-station','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',"
              "'radio0','ssid-main','02:00:00:00:00:01',1900,0,1999,"
              "'{\"mac\":\"02:00:00:00:00:01\",\"interface\":\"wlan0\"}');",
              NULL, NULL, NULL) == SQLITE_OK);
    CHECK("seed unrelated ap", sqlite3_exec(g_ac_db,
              "INSERT INTO ac_aps(ap_id,site_id,name,adoption_state,last_seen_at) "
              "VALUES('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','default','unrelated',"
              "'adopted',1999);"
              "INSERT INTO ac_ssid_bindings(ssid_id,ap_id,radio_id,state,bssid) "
              "VALUES('ssid-main','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',"
              "'radio0','applied','02:00:00:00:20:01');",
              NULL, NULL, NULL) == SQLITE_OK);

    response = ac_db_roaming_domain_preflight_json(domain_id, 2000);
    CHECK("preflight ok", json_object_get_boolean(field(response, "ok")));
    CHECK("preflight fail closed", !json_object_get_boolean(
              field(response, "valid")));
    CHECK("no active action", !json_object_get_boolean(
              field(response, "active_station_action")));
    CHECK("selected member only", json_object_array_length(
              field(response, "members")) == 1);
    CHECK("selected member id", !strcmp(json_object_get_string(field(
              json_object_array_get_idx(field(response, "members"), 0),
              "ap_id")), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"));
    CHECK("capability remains excluded", !json_object_get_boolean(field(
              json_object_array_get_idx(field(response, "members"), 0),
              "eligible")));
    CHECK("capability pending reason", !strcmp(json_object_get_string(field(
              json_object_array_get_idx(field(response, "members"), 0),
              "reason")), "roaming_capability_readback_pending"));
    json_object_put(response);

    CHECK("expire selected evidence", sqlite3_exec(g_ac_db,
              "UPDATE ac_aps SET last_seen_at=1000 WHERE "
              "ap_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';",
              NULL, NULL, NULL) == SQLITE_OK);
    response = ac_db_roaming_domain_preflight_json(domain_id, 2000);
    CHECK("stale preflight ok", json_object_get_boolean(field(response, "ok")));
    CHECK("stale member excluded", !json_object_get_boolean(field(
              json_object_array_get_idx(field(response, "members"), 0),
              "eligible")));
    CHECK("stale evidence reason", !strcmp(json_object_get_string(field(
              json_object_array_get_idx(field(response, "members"), 0),
              "reason")), "ap_offline"));
    json_object_put(response);

    CHECK("restore selected AP online evidence", sqlite3_exec(g_ac_db,
              "UPDATE ac_aps SET last_seen_at=1999 WHERE "
              "ap_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';",
              NULL, NULL, NULL) == SQLITE_OK);

    response = ac_db_roaming_domain_observe_json(
        domain_id, "02:00:00:00:00:01", NULL, 2000);
    CHECK("observe ok", json_object_get_boolean(field(response, "ok")));
    CHECK("observe only", !strcmp(json_object_get_string(
              field(response, "mode")), "observe_only"));
    CHECK("observe not actionable", !json_object_get_boolean(
              field(response, "actionable")));
    CHECK("telemetry incomplete (no signal)", !strcmp(json_object_get_string(
              field(response, "reason")), "telemetry_incomplete"));
    CHECK("observe proposal null", json_object_is_type(
              field(response, "proposal"), json_type_null));
    CHECK("observe no action", !strcmp(json_object_get_string(
              field(response, "simulated_outcome")), "no_action"));
    CHECK("observe active action false", !json_object_get_boolean(
              field(response, "active_station_action")));
    json_object_put(response);

    CHECK("seed current station signal", sqlite3_exec(g_ac_db,
              "UPDATE ac_station_sessions SET runtime_json='{\"mac\":\"02:00:00:00:00:01\",\"interface\":\"wlan0\",\"signal_dbm\":-78}' "
              "WHERE mac='02:00:00:00:00:01';",
              NULL, NULL, NULL) == SQLITE_OK);
    response = ac_db_roaming_domain_observe_json(
        domain_id, "02:00:00:00:00:01", NULL, 2000);
    CHECK("signal alone remains not actionable", !json_object_get_boolean(
              field(response, "actionable")));
    CHECK("current signal read from station runtime", json_object_get_int(
              field(field(response, "station"), "signal_dbm")) == -78);
    CHECK("current signal source", !strcmp(json_object_get_string(
              field(field(response, "station"), "signal_source")),
              "station_runtime"));
    CHECK("signal alone has no proposal", json_object_is_type(
              field(response, "proposal"), json_type_null));
    CHECK("signal alone keeps no_qualified_candidates", !strcmp(
              json_object_get_string(field(response, "reason")),
              "no_qualified_candidates"));
    json_object_put(response);

    response = ac_db_roaming_domain_observe_json(
        domain_id, "not-a-mac", NULL, 2000);
    CHECK("invalid station mac rejected", !json_object_get_boolean(
              field(response, "ok")));
    CHECK("invalid station mac reason", !strcmp(json_object_get_string(
              field(response, "error")), "invalid_station_mac"));
    json_object_put(response);

    CHECK("policy create", ac_db_roaming_policy_put(domain_id, &policy, 0) == 0);
    response = ac_db_roaming_policy_json(domain_id);
    CHECK("policy get ok", json_object_get_boolean(field(response, "ok")));
    CHECK("policy observe only", !strcmp(json_object_get_string(
              field(response, "mode")), "observe_only"));
    CHECK("policy revision one", json_object_get_int64(field(
              field(response, "policy"), "revision")) == 1);
    CHECK("policy weak rssi", json_object_get_int(field(
              field(response, "policy"), "weak_rssi_dbm")) == -75);
    json_object_put(response);

    CHECK("policy stale revision rejected",
          ac_db_roaming_policy_put(domain_id, &policy, 0) ==
          AC_ROAMING_DOMAIN_CONFLICT);
    policy.minimum_candidate_gain_db = 12;
    CHECK("policy update", ac_db_roaming_policy_put(domain_id, &policy, 1) == 0);
    response = ac_db_roaming_policy_json(domain_id);
    CHECK("policy revision two", json_object_get_int64(field(
              field(response, "policy"), "revision")) == 2);
    CHECK("policy update readback", json_object_get_int(field(
              field(response, "policy"), "minimum_candidate_gain_db")) == 12);
    json_object_put(response);

    policy.weak_rssi_dbm = -101;
    CHECK("policy range rejected",
          ac_db_roaming_policy_put(domain_id, &policy, 2) ==
          AC_ROAMING_DOMAIN_INVALID);

    CHECK("delete stale revision", ac_db_roaming_domain_delete(domain_id, 1) ==
          AC_ROAMING_DOMAIN_CONFLICT);
    CHECK("delete current revision", ac_db_roaming_domain_delete(domain_id, 4) == 0);
    response = ac_db_roaming_domain_json(domain_id);
    CHECK("deleted", !json_object_get_boolean(field(response, "ok")));
    json_object_put(response);


    /* ---- Phase 2: exclusions, cooldown, audit, candidate scoring ---- */

    /* Re-create domain for Phase 2 tests. */
    CHECK("p2 create domain", ac_db_roaming_domain_put(NULL, "Phase 2 test",
              "[\"ssid-main\"]", "[\"floor-one\"]", "wpa3-main",
              "a1b2", 1, "over_air", 1, 1, 0, NULL, 0, "acceptance",
              domain_id) == 0);

    /* Re-create policy. */
    policy.weak_rssi_dbm = -75;
    policy.minimum_candidate_gain_db = 10;
    policy.candidate_min_rssi_dbm = -67;
    policy.post_roam_cooldown_sec = 300;
    CHECK("p2 policy create", ac_db_roaming_policy_put(domain_id, &policy, 0) == 0);

    /* Test exclusion CRUD. */
    CHECK("exclusion put mac", ac_db_roaming_exclusion_put(
              "excl-001", domain_id, "mac", "02:00:00:00:00:01",
              "IoT sensor", 2000) == 0);
    CHECK("exclusion put ssid", ac_db_roaming_exclusion_put(
              "excl-002", domain_id, "ssid", "iot-guest",
              "IoT guest network", 2000) == 0);
    response = ac_db_roaming_exclusions_json(domain_id);
    CHECK("exclusions list ok", json_object_get_boolean(field(response, "ok")));
    CHECK("exclusions count", json_object_array_length(
              field(response, "exclusions")) == 2);
    json_object_put(response);

    /* Test observe with MAC exclusion. */
    response = ac_db_roaming_domain_observe_json(
        domain_id, "02:00:00:00:00:01", NULL, 2000);
    CHECK("excluded observe ok", json_object_get_boolean(field(response, "ok")));
    CHECK("excluded reason", !strcmp(json_object_get_string(
              field(response, "reason")), "IoT sensor"));
    CHECK("excluded decision", !strcmp(json_object_get_string(
              field(response, "decision")), "excluded"));
    CHECK("excluded not actionable", !json_object_get_boolean(
              field(response, "actionable")));
    CHECK("excluded active action false", !json_object_get_boolean(
              field(response, "active_station_action")));
    json_object_put(response);

    /* Remove MAC exclusion and test SSID exclusion. */
    CHECK("exclusion delete mac", ac_db_roaming_exclusion_delete("excl-001") == 0);
    response = ac_db_roaming_domain_observe_json(
        domain_id, "02:00:00:00:00:01", NULL, 2000);
    /* Station is on ssid-main, not iot-guest, so should not be excluded by SSID. */
    CHECK("non-excluded observe", strcmp(json_object_get_string(
              field(response, "reason")), "IoT sensor") != 0);
    json_object_put(response);

    /* Remove SSID exclusion. */
    CHECK("exclusion delete ssid", ac_db_roaming_exclusion_delete("excl-002") == 0);

    /* Test telemetry stale reason. */
    CHECK("seed stale station", sqlite3_exec(g_ac_db,
              "UPDATE ac_station_sessions SET last_seen_at=100 "
              "WHERE mac='02:00:00:00:00:01';",
              NULL, NULL, NULL) == SQLITE_OK);
    response = ac_db_roaming_domain_observe_json(
        domain_id, "02:00:00:00:00:01", NULL, 2000);
    CHECK("telemetry stale reason", !strcmp(json_object_get_string(
              field(response, "reason")), "telemetry_stale"));
    CHECK("telemetry stale decision", !strcmp(json_object_get_string(
              field(response, "decision")), "no_action"));
    json_object_put(response);

    /* Restore station and test telemetry incomplete (no signal). */
    CHECK("restore station", sqlite3_exec(g_ac_db,
              "UPDATE ac_station_sessions SET last_seen_at=1999,"
              "runtime_json='{\"mac\":\"02:00:00:00:00:01\",\"interface\":\"wlan0\"}' "
              "WHERE mac='02:00:00:00:00:01';",
              NULL, NULL, NULL) == SQLITE_OK);
    response = ac_db_roaming_domain_observe_json(
        domain_id, "02:00:00:00:00:01", NULL, 2000);
    CHECK("telemetry incomplete reason", !strcmp(json_object_get_string(
              field(response, "reason")), "telemetry_incomplete"));
    json_object_put(response);

    /* Restore signal and test platform_capability_false. */
    CHECK("restore signal", sqlite3_exec(g_ac_db,
              "UPDATE ac_station_sessions SET runtime_json='{\"mac\":\"02:00:00:00:00:01\",\"interface\":\"wlan0\",\"signal_dbm\":-78}' "
              "WHERE mac='02:00:00:00:00:01';",
              NULL, NULL, NULL) == SQLITE_OK);
    response = ac_db_roaming_domain_observe_json(
        domain_id, "02:00:00:00:00:01", NULL, 2000);
    /* Members have roaming_capability_readback_pending, which means
     * write_capable_session_unavailable check won't trigger because
     * the member reason is "roaming_capability_readback_pending".
     * The observe function should return no_qualified_candidates since
     * no members are eligible. */
    CHECK("no eligible members reason", !strcmp(json_object_get_string(
              field(response, "reason")), "no_qualified_candidates"));
    CHECK("observe has candidates field", field(response, "candidates") != NULL);
    CHECK("observe has policy_revision", field(response, "policy_revision") != NULL);
    CHECK("observe has decision field", field(response, "decision") != NULL);
    json_object_put(response);

    /* Test audit trail. */
    response = ac_db_roaming_audit_json(domain_id, "02:00:00:00:00:01", 10);
    CHECK("audit ok", json_object_get_boolean(field(response, "ok")));
    CHECK("audit has entries", json_object_array_length(
              field(response, "entries")) > 0);
    {
        struct json_object *first_entry = json_object_array_get_idx(
            field(response, "entries"), 0);
        CHECK("audit entry has station_mac", field(first_entry, "station_mac") != NULL);
        CHECK("audit entry has reason", field(first_entry, "reason") != NULL);
        CHECK("audit entry has decision", field(first_entry, "decision") != NULL);
        CHECK("audit entry has candidates", field(first_entry, "candidates") != NULL);
    }
    json_object_put(response);

    /* Test audit for all stations. */
    response = ac_db_roaming_audit_json(domain_id, "", 10);
    CHECK("audit all ok", json_object_get_boolean(field(response, "ok")));
    CHECK("audit all has entries", json_object_array_length(
              field(response, "entries")) > 0);
    json_object_put(response);

    /* Test cooldown: seed a cooldown and verify it blocks. */
    CHECK("refresh station for cooldown", sqlite3_exec(g_ac_db,
              "UPDATE ac_station_sessions SET last_seen_at=2499 "
              "WHERE mac='02:00:00:00:00:01';",
              NULL, NULL, NULL) == SQLITE_OK);
    /* Seed cooldown using prepared statement (domain_id needs binding). */
    {
        sqlite3_stmt *cdst = NULL;
        CHECK("cooldown insert", sqlite3_prepare_v2(g_ac_db,
                  "INSERT OR REPLACE INTO ac_roaming_cooldowns(domain_id,station_mac,"
                  "cooldown_until,reason,created_at) "
                  "VALUES(?1,'02:00:00:00:00:01',3000,'test_cooldown',2000)",
                  -1, &cdst, NULL) == SQLITE_OK);
        sqlite3_bind_text(cdst, 1, domain_id, -1, SQLITE_TRANSIENT);
        sqlite3_step(cdst);
        sqlite3_finalize(cdst);
    }
    response = ac_db_roaming_domain_observe_json(
        domain_id, "02:00:00:00:00:01", NULL, 2500);
    CHECK("cooldown active reason", !strcmp(json_object_get_string(
              field(response, "reason")), "cooldown_active"));
    CHECK("cooldown active decision", !strcmp(json_object_get_string(
              field(response, "decision")), "no_action"));
    json_object_put(response);

    /* Test cooldown expired. */
    response = ac_db_roaming_domain_observe_json(
        domain_id, "02:00:00:00:00:01", NULL, 3500);
    CHECK("cooldown expired reason", strcmp(json_object_get_string(
              field(response, "reason")), "cooldown_active") != 0);
    json_object_put(response);

    /* Test active_station_action is always false. */
    response = ac_db_roaming_domain_observe_json(
        domain_id, "02:00:00:00:00:01", NULL, 3500);
    CHECK("always observe only", !json_object_get_boolean(
              field(response, "active_station_action")));
    CHECK("always not actionable", !json_object_get_boolean(
              field(response, "actionable")));
    CHECK("always no_action simulated", !strcmp(json_object_get_string(
              field(response, "simulated_outcome")), "no_action"));
    CHECK("always null proposal", json_object_is_type(
              field(response, "proposal"), json_type_null));
    json_object_put(response);

    /* ---- Phase 2: member-derived no-action reasons ----
     *
     * These two are reachable today.  gain_insufficient and target_overloaded
     * are deliberately NOT covered here: both sit behind has_eligible in
     * ac_db_roaming_domain_observe_json(), and preflight has no code path that
     * ever sets a member eligible, so they are unreachable until the per-member
     * capability readback (Phase 1 handoff item 2) exists.  Asserting them with
     * a hand-forged member would test the fixture, not the product. */
    /* Clear state the earlier cooldown/exclusion cases left behind, so these
     * assertions pin the branch under test rather than an earlier one. */
    CHECK("reset cooldowns", sqlite3_exec(g_ac_db,
              "DELETE FROM ac_roaming_cooldowns;", NULL, NULL, NULL)
          == SQLITE_OK);
    CHECK("reset exclusions", sqlite3_exec(g_ac_db,
              "DELETE FROM ac_roaming_exclusions;", NULL, NULL, NULL)
          == SQLITE_OK);
    CHECK("ap not adopted", sqlite3_exec(g_ac_db,
              "UPDATE ac_aps SET adoption_state='pending' "
              "WHERE ap_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';",
              NULL, NULL, NULL) == SQLITE_OK);
    response = ac_db_roaming_domain_observe_json(
        domain_id, "02:00:00:00:00:01", NULL, 2000);
    CHECK("ownership_missing reason", !strcmp(json_object_get_string(
              field(response, "reason")), "ownership_missing"));
    CHECK("ownership_missing no action", !strcmp(json_object_get_string(
              field(response, "decision")), "no_action"));
    CHECK("ownership_missing not actionable", !json_object_get_boolean(
              field(response, "actionable")));
    json_object_put(response);

    CHECK("ap readopted", sqlite3_exec(g_ac_db,
              "UPDATE ac_aps SET adoption_state='adopted' "
              "WHERE ap_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';",
              NULL, NULL, NULL) == SQLITE_OK);
    /* Reverse control: with adoption restored the reason must change, so the
     * assertion above is pinned to adoption rather than passing by default. */
    response = ac_db_roaming_domain_observe_json(
        domain_id, "02:00:00:00:00:01", NULL, 2000);
    CHECK("ownership_missing clears", strcmp(json_object_get_string(
              field(response, "reason")), "ownership_missing") != 0);
    json_object_put(response);

    CHECK("ap session down", sqlite3_exec(g_ac_db,
              "UPDATE ac_ap_runtime SET session_connected=0 "
              "WHERE ap_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';",
              NULL, NULL, NULL) == SQLITE_OK);
    response = ac_db_roaming_domain_observe_json(
        domain_id, "02:00:00:00:00:01", NULL, 2000);
    CHECK("target_offline reason", !strcmp(json_object_get_string(
              field(response, "reason")), "target_offline"));
    CHECK("target_offline no action", !strcmp(json_object_get_string(
              field(response, "decision")), "no_action"));
    json_object_put(response);

    CHECK("ap session up", sqlite3_exec(g_ac_db,
              "UPDATE ac_ap_runtime SET session_connected=1 "
              "WHERE ap_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';",
              NULL, NULL, NULL) == SQLITE_OK);
    response = ac_db_roaming_domain_observe_json(
        domain_id, "02:00:00:00:00:01", NULL, 2000);
    CHECK("target_offline clears", strcmp(json_object_get_string(
              field(response, "reason")), "target_offline") != 0);
    json_object_put(response);

    /* ---- Phase 2: cooldown survives a controller restart ----
     * Cooldown is the main anti-ping-pong device, so a cooldown that lives
     * only in memory is the same as no cooldown at all after a crash. */
    CHECK("seed persistent cooldown", sqlite3_exec(g_ac_db,
              "INSERT OR REPLACE INTO ac_roaming_cooldowns"
              "(domain_id,station_mac,cooldown_until,reason,created_at) "
              "SELECT domain_id,'02:00:00:00:00:01',9999,'test',2000 "
              "FROM ac_roaming_domains LIMIT 1;",
              NULL, NULL, NULL) == SQLITE_OK);
    ac_db_set_secrets(NULL);
    ac_secrets_close(secrets);
    secrets = NULL;
    ac_db_close();
    CHECK("reopen after restart", ac_db_init() == 0);
    CHECK("secrets reopen", ac_secrets_open_or_create(
              g_ac_db, getenv("DREAMINGWRT_AC_SECRETS_KEY_PATH"),
              &secrets) == AC_SECRETS_OK);
    ac_db_set_secrets(secrets);
    response = ac_db_roaming_domain_observe_json(
        domain_id, "02:00:00:00:00:01", NULL, 2000);
    CHECK("cooldown survives restart", !strcmp(json_object_get_string(
              field(response, "reason")), "cooldown_active"));
    json_object_put(response);
    CHECK("clear cooldown", sqlite3_exec(g_ac_db,
              "DELETE FROM ac_roaming_cooldowns "
              "WHERE station_mac='02:00:00:00:00:01';",
              NULL, NULL, NULL) == SQLITE_OK);
    /* Reverse control: once cleared the reason must move off cooldown_active,
     * so the assertion above cannot pass on a stale row. */
    response = ac_db_roaming_domain_observe_json(
        domain_id, "02:00:00:00:00:01", NULL, 2000);
    CHECK("cooldown clears after delete", strcmp(json_object_get_string(
              field(response, "reason")), "cooldown_active") != 0);
    json_object_put(response);

    /* ---- Phase 1: per-BSS capability readback drives eligibility ----
     *
     * Until this landed, preflight wrote eligible=false unconditionally and
     * nothing could ever clear a member.  Seed the hostapd snapshot APD really
     * publishes and check the member is promoted. */
    CHECK("seed hostapd snapshot", sqlite3_exec(g_ac_db,
              "UPDATE ac_ap_runtime SET observed_at=1999,stale=0,runtime_json='"
              SELECTED_BINDING_SNAPSHOT
              "\"sources\":{\"hostapd\":{\"available\":true,\"complete\":true,"
              "\"bss\":[{\"bssid\":\"02:00:00:00:10:01\",\"interface\":\"ath0\","
              "\"ft_supported\":true,\"ft_over_ds\":false,"
              "\"neighbor_report_80211k\":true,\"bss_transition_80211v\":true,"
              "\"client_deauth\":true,\"hostapd_ctrl_reachable\":true,"
              "\"station_count\":3,\"channel\":36,\"frequency_mhz\":5180}]}}}' "
              "WHERE ap_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';",
              NULL, NULL, NULL) == SQLITE_OK);
    response = ac_db_roaming_domain_preflight_json(domain_id, 2000);
    CHECK("member now eligible", json_object_get_boolean(field(
              json_object_array_get_idx(field(response, "members"), 0),
              "eligible")));
    CHECK("capability_verified reason", !strcmp(json_object_get_string(field(
              json_object_array_get_idx(field(response, "members"), 0),
              "reason")), "capability_verified"));
    CHECK("preflight now valid", json_object_get_boolean(
              field(response, "valid")));
    CHECK("eligible_count one", json_object_get_int(
              field(response, "eligible_count")) == 1);
    /* Capability facts must travel with the member; the FT fan-out and the
     * Phase 4 deauth gate both read them from here. */
    CHECK("ft_over_ds_capable false", !json_object_get_boolean(field(
              json_object_array_get_idx(field(response, "members"), 0),
              "ft_over_ds_capable")));
    CHECK("client_deauth_capable true", json_object_get_boolean(field(
              json_object_array_get_idx(field(response, "members"), 0),
              "client_deauth_capable")));
    CHECK("member carries interface", !strcmp(json_object_get_string(field(
              json_object_array_get_idx(field(response, "members"), 0),
              "interface")), "ath0"));
    CHECK("preflight still no station action", !json_object_get_boolean(
              field(response, "active_station_action")));
    json_object_put(response);

    /* gain_insufficient is reachable now that a member can be eligible.  The
     * candidate signal estimate is still the station's own RSSI (see the
     * comment in ac_db_roaming_candidates_score), so the gain is always 0 and
     * any policy threshold rejects it -- which is the correct fail-closed
     * outcome while no real per-candidate measurement exists. */
    response = ac_db_roaming_domain_observe_json(
        domain_id, "02:00:00:00:00:01", NULL, 2000);
    CHECK("serving BSS is not a roaming candidate", !strcmp(json_object_get_string(
              field(response, "reason")), "no_qualified_candidates"));
    CHECK("gain_insufficient no action", !strcmp(json_object_get_string(
              field(response, "decision")), "no_action"));
    CHECK("gain_insufficient not actionable", !json_object_get_boolean(
              field(response, "actionable")));
    CHECK("still no station action", !json_object_get_boolean(
              field(response, "active_station_action")));
    json_object_put(response);

    /* ---- Phase 2: 802.11k beacon report drives the candidate score ----
     *
     * Without a measurement the estimate falls back to the station's own RSSI,
     * the gain computes as zero and the decision is gain_insufficient (asserted
     * above).  Publish a real measurement of the candidate and the score must
     * switch to it. */
    CHECK("seed beacon report", sqlite3_exec(g_ac_db,
              "UPDATE ac_ap_runtime SET observed_at=1999,stale=0,runtime_json='"
              SELECTED_BINDING_SNAPSHOT
              "\"sources\":{\"hostapd\":{\"available\":true,"
              "\"complete\":true,"
              "\"bss\":[{\"bssid\":\"02:00:00:00:10:01\","
              "\"interface\":\"ath0\",\"ft_supported\":true,"
              "\"ft_over_ds\":false,\"neighbor_report_80211k\":true,"
              "\"bss_transition_80211v\":true,\"client_deauth\":true,"
              "\"hostapd_ctrl_reachable\":true,\"station_count\":3,"
              "\"channel\":36,\"frequency_mhz\":5180}],"
              "\"beacon_reports\":[{\"station_mac\":\"02:00:00:00:00:01\","
              "\"bssid\":\"02:00:00:00:10:01\",\"rcpi_dbm\":-52,"
              "\"channel\":36,\"op_class\":115,\"observed_at\":1999}]}}}' "
              "WHERE ap_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';",
              NULL, NULL, NULL) == SQLITE_OK);
    response = ac_db_roaming_domain_observe_json(
        domain_id, "02:00:00:00:00:01", NULL, 2000);
    {
        struct json_object *cands = field(response, "candidates");
        struct json_object *c0 = cands && json_object_is_type(
            cands, json_type_array) && json_object_array_length(cands) ?
            json_object_array_get_idx(cands, 0) : NULL;

        CHECK("candidate present", c0 != NULL);
        CHECK("signal came from beacon report", c0 && !strcmp(
                  json_object_get_string(field(c0, "signal_source")),
                  "ieee80211k_beacon_report"));
        CHECK("signal_measured true", c0 &&
              json_object_get_boolean(field(c0, "signal_measured")));
    }
    json_object_put(response);

    /* Reverse control: a measurement for a DIFFERENT station must not be
     * borrowed -- otherwise one client's reading would steer another. */
    CHECK("beacon report for other station", sqlite3_exec(g_ac_db,
              "UPDATE ac_ap_runtime SET runtime_json=replace(runtime_json,"
              "'\"station_mac\":\"02:00:00:00:00:01\"',"
              "'\"station_mac\":\"02:00:00:00:00:99\"') "
              "WHERE ap_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';",
              NULL, NULL, NULL) == SQLITE_OK);
    response = ac_db_roaming_domain_observe_json(
        domain_id, "02:00:00:00:00:01", NULL, 2000);
    {
        struct json_object *cands = field(response, "candidates");
        struct json_object *c0 = cands && json_object_is_type(
            cands, json_type_array) && json_object_array_length(cands) ?
            json_object_array_get_idx(cands, 0) : NULL;

        CHECK("other station's reading not borrowed", c0 && !strcmp(
                  json_object_get_string(field(c0, "signal_source")),
                  "station_current_rssi_fallback"));
    }
    json_object_put(response);

    /* Reverse control: withdraw the FT capability the domain requires and the
     * member must drop back out of the pool by name. */
    CHECK("withdraw ft support", sqlite3_exec(g_ac_db,
              "UPDATE ac_ap_runtime SET runtime_json='"
              SELECTED_BINDING_SNAPSHOT
              "\"sources\":{\"hostapd\":{\"available\":true,\"complete\":true,"
              "\"bss\":[{\"bssid\":\"02:00:00:00:10:01\",\"interface\":\"ath0\","
              "\"ft_supported\":false,\"ft_over_ds\":false,"
              "\"neighbor_report_80211k\":true,\"bss_transition_80211v\":true,"
              "\"client_deauth\":true,\"hostapd_ctrl_reachable\":true,"
              "\"station_count\":3,\"channel\":36,\"frequency_mhz\":5180}]}}}' "
              "WHERE ap_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';",
              NULL, NULL, NULL) == SQLITE_OK);
    response = ac_db_roaming_domain_preflight_json(domain_id, 2000);
    CHECK("ft_unsupported_by_member", !strcmp(json_object_get_string(field(
              json_object_array_get_idx(field(response, "members"), 0),
              "reason")), "ft_unsupported_by_member"));
    CHECK("ineligible again", !json_object_get_boolean(field(
              json_object_array_get_idx(field(response, "members"), 0),
              "eligible")));
    CHECK("valid false again", !json_object_get_boolean(
              field(response, "valid")));
    json_object_put(response);

    /* Reverse control: an incomplete hostapd collection must not read as
     * "unsupported" -- absent evidence is not evidence of absence, so the
     * member falls back to readback_pending rather than a capability verdict. */
    CHECK("incomplete snapshot", sqlite3_exec(g_ac_db,
              "UPDATE ac_ap_runtime SET runtime_json='"
              "{\"sources\":{\"hostapd\":{\"available\":true,\"complete\":false,"
              "\"bss\":[{\"bssid\":\"02:00:00:00:10:01\",\"ft_supported\":true}]"
              "}}}' WHERE ap_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';",
              NULL, NULL, NULL) == SQLITE_OK);
    response = ac_db_roaming_domain_preflight_json(domain_id, 2000);
    CHECK("incomplete stays pending", !strcmp(json_object_get_string(field(
              json_object_array_get_idx(field(response, "members"), 0),
              "reason")), "roaming_capability_readback_pending"));
    json_object_put(response);

    /* ---- Phase 3: neighbour report RF descriptors ----
     * These feed the Operating Class and Channel octets of the Neighbor Report
     * element.  A wrong class points the station at the wrong band, and the
     * only place that surfaces otherwise is on real hardware. */
    CHECK("opclass 2.4 lower", ac_roaming_global_op_class("2.4GHz", 1) == 81);
    CHECK("opclass 2.4 upper", ac_roaming_global_op_class("2.4GHz", 13) == 81);
    CHECK("opclass 2.4 ch14", ac_roaming_global_op_class("2.4GHz", 14) == 82);
    CHECK("opclass 5 unii1", ac_roaming_global_op_class("5GHz", 36) == 115);
    CHECK("opclass 5 unii2a", ac_roaming_global_op_class("5GHz", 52) == 118);
    CHECK("opclass 5 unii2c", ac_roaming_global_op_class("5GHz", 100) == 121);
    CHECK("opclass 5 unii3", ac_roaming_global_op_class("5GHz", 149) == 125);
    CHECK("opclass 6", ac_roaming_global_op_class("6GHz", 37) == 131);
    /* Reverse controls: anything unmappable must return 0 so the caller drops
     * the neighbour rather than emitting a fabricated descriptor.  The old
     * code hardcoded class 115 with channel 0 for every neighbour, which is
     * exactly what these reject. */
    CHECK("opclass rejects channel 0",
          ac_roaming_global_op_class("5GHz", 0) == 0);
    CHECK("opclass rejects 5GHz gap",
          ac_roaming_global_op_class("5GHz", 70) == 0);
    CHECK("opclass rejects 2.4 overflow",
          ac_roaming_global_op_class("2.4GHz", 15) == 0);
    CHECK("opclass rejects unknown band",
          ac_roaming_global_op_class("60GHz", 36) == 0);
    CHECK("opclass rejects null band",
          ac_roaming_global_op_class(NULL, 36) == 0);
    CHECK("phy 2.4 is HT", ac_roaming_phy_type("2.4GHz") == 7);
    CHECK("phy 5 is VHT", ac_roaming_phy_type("5GHz") == 9);
    CHECK("phy 6 is HE", ac_roaming_phy_type("6GHz") == 14);
    CHECK("phy rejects unknown", ac_roaming_phy_type("60GHz") == 0);
    CHECK("phy rejects null", ac_roaming_phy_type(NULL) == 0);


    /* ---- Phase 4: deauth audit + circuit breaker ----
     *
     * Driven through the test-only shim because the real callers sit behind
     * the ubus layer.  Each of the four trip conditions gets its own domain so
     * one cannot mask another. */
    {
        const char *d1 = "11111111-1111-4111-8111-111111111111";
        const char *d2 = "22222222-2222-4222-8222-222222222222";
        const char *d3 = "33333333-3333-4333-8333-333333333333";
        const char *d4 = "44444444-4444-4444-8444-444444444444";
        const char *d5 = "55555555-5555-4555-8555-555555555555";
        int64_t id;
        int i;

        /* Audit: a sent deauth whose station lands on the target is 'roamed'. */
        id = ac_db_test_deauth_record(d1, "02:00:00:00:00:aa", "ap-1",
                                      "02:00:00:00:10:01", "02:00:00:00:10:02",
                                      5000);
        CHECK("deauth audit row created", id > 0);
        ac_db_test_deauth_mark_sent(id, 1, NULL);
        ac_db_test_deauth_resolve(id, "02:00:00:00:10:02", 5100);
        CHECK("deauth roamed", !strcmp(scalar_text(
                  "SELECT outcome FROM ac_deauth_actions WHERE deauth_id=%lld",
                  (long long)id), "roamed"));

        /* A station that comes back to the BSSID we pushed it off is
         * 'returned', not 'not_roamed' -- the breaker keys on that. */
        id = ac_db_test_deauth_record(d1, "02:00:00:00:00:bb", "ap-1",
                                      "02:00:00:00:10:01", "02:00:00:00:10:02",
                                      5000);
        ac_db_test_deauth_mark_sent(id, 1, NULL);
        ac_db_test_deauth_resolve(id, "02:00:00:00:10:01", 5100);
        CHECK("deauth returned", !strcmp(scalar_text(
                  "SELECT outcome FROM ac_deauth_actions WHERE deauth_id=%lld",
                  (long long)id), "returned"));

        /* A failed send is 'blocked' and never counts as an outcome. */
        id = ac_db_test_deauth_record(d1, "02:00:00:00:00:cc", "ap-1",
                                      "02:00:00:00:10:01", "02:00:00:00:10:02",
                                      5000);
        ac_db_test_deauth_mark_sent(id, 0, "ap_control_unreachable");
        CHECK("failed send blocked", !strcmp(scalar_text(
                  "SELECT outcome FROM ac_deauth_actions WHERE deauth_id=%lld",
                  (long long)id), "blocked"));

        /* Trip 1: failure rate. Three resolved actions, all not_roamed. */
        for (i = 0; i < 3; i++) {
            id = ac_db_test_deauth_record(d2, "02:00:00:00:00:01", "ap-1",
                                          "02:00:00:00:10:01",
                                          "02:00:00:00:10:02", 5000);
            ac_db_test_deauth_mark_sent(id, 1, NULL);
            ac_db_test_deauth_resolve(id, "", 5100);
        }
        CHECK("breaker trips on failure rate",
              ac_db_test_deauth_breaker(d2, 5200) == 1);
        CHECK("failure reason recorded",
              strstr(ac_db_test_forced_action_reason(d2),
                     "deauth_failure_rate") != NULL);

        /* Trip 2: ping-pong. All three return to the source BSSID. */
        for (i = 0; i < 3; i++) {
            id = ac_db_test_deauth_record(d3, "02:00:00:00:00:02", "ap-1",
                                          "02:00:00:00:10:01",
                                          "02:00:00:00:10:02", 5000);
            ac_db_test_deauth_mark_sent(id, 1, NULL);
            ac_db_test_deauth_resolve(id, "02:00:00:00:10:01", 5100);
        }
        CHECK("breaker trips on return rate",
              ac_db_test_deauth_breaker(d3, 5200) == 1);
        CHECK("return reason recorded",
              strstr(ac_db_test_forced_action_reason(d3),
                     "station_returned") != NULL);

        /* Trip 3: consecutive send failures -- the control path is broken, so
         * no outcome is ever produced and the rate checks above stay silent. */
        for (i = 0; i < 3; i++) {
            id = ac_db_test_deauth_record(d4, "02:00:00:00:00:03", "ap-1",
                                          "02:00:00:00:10:01",
                                          "02:00:00:00:10:02", 5000 + i);
            ac_db_test_deauth_mark_sent(id, 0, "ap_control_unreachable");
        }
        CHECK("breaker trips on consecutive send failures",
              ac_db_test_deauth_breaker(d4, 5200) == 1);
        CHECK("ap control reason recorded",
              strstr(ac_db_test_forced_action_reason(d4),
                     "ap_control_failed") != NULL);

        /* Reverse control: a healthy domain must NOT trip.  Without this the
         * four assertions above would pass even if the breaker always fired. */
        for (i = 0; i < 3; i++) {
            id = ac_db_test_deauth_record(d5, "02:00:00:00:00:04", "ap-1",
                                          "02:00:00:00:10:01",
                                          "02:00:00:00:10:02", 5000);
            ac_db_test_deauth_mark_sent(id, 1, NULL);
            ac_db_test_deauth_resolve(id, "02:00:00:00:10:02", 5100);
        }
        CHECK("healthy domain does not trip",
              ac_db_test_deauth_breaker(d5, 5200) == 0);
        CHECK("healthy domain has no reason",
              ac_db_test_forced_action_reason(d5)[0] == 0);

        /* Exercise the sweep path so a pending row is closed without an
         * explicit resolve call. */
        ac_db_test_deauth_check_outcomes(d1, 6000);

        /* Re-enabling steering is the operator's manual reset after a trip,
         * so it must refuse a domain that does not exist.  d1..d5 only ever
         * appear in ac_deauth_actions, never in ac_roaming_domains, which is
         * exactly the phantom-id case: an unchecked INSERT would leave
         * steering_enabled=1 and an empty disabled_reason waiting for whoever
         * later creates that id, handing them a pre-cleared breaker. */
        CHECK("steering enable rejects unknown domain",
              ac_roam_steering_enable(d1, 6100) != 0);
        CHECK("unknown domain wrote no action state", !strcmp(scalar_text(
                  "SELECT COUNT(*) FROM ac_roaming_domain_action_state"
                  " WHERE domain_id='%s'", d1), "0"));
        /* Reverse control: the check must not reject a domain that is real. */
        CHECK("steering enable accepts real domain",
              ac_roam_steering_enable(domain_id, 6100) == 0);
        CHECK("real domain wrote action state", !strcmp(scalar_text(
                  "SELECT steering_enabled FROM ac_roaming_domain_action_state"
                  " WHERE domain_id='%s'", domain_id), "1"));
    }

    ac_db_set_secrets(NULL);
    ac_secrets_close(secrets);
    ac_db_close();
    puts("ok");
    return 0;
}

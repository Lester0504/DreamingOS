/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>
#include <json-c/json.h>

#include "../src/jmx_observability.h"

static sqlite3 *fact_db;
static sqlite3 *jmx_db_handle(void) { return fact_db; }
#include "observability_online_bridge.inc"

#define CHECK(name, condition) do { \
    if (!(condition)) { fprintf(stderr, "FAIL %s\n", name); return 1; } \
} while (0)

static int object_int(struct json_object *obj, const char *key)
{
    struct json_object *value = NULL;
    if (!json_object_object_get_ex(obj, key, &value))
        return -1;
    return json_object_get_int(value);
}

static int64_t object_int64(struct json_object *obj, const char *key)
{
    struct json_object *value = NULL;
    if (!json_object_object_get_ex(obj, key, &value))
        return -1;
    return json_object_get_int64(value);
}

static int object_is_null(struct json_object *obj, const char *key)
{
    char needle[96];
    const char *json;

    if (!obj || !key || snprintf(needle, sizeof(needle), "\"%s\":null", key) >=
        (int)sizeof(needle))
        return 0;
    json = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN);
    return json && strstr(json, needle) != NULL;
}

static const char *object_string(struct json_object *obj, const char *key)
{
    struct json_object *value = NULL;
    if (!json_object_object_get_ex(obj, key, &value) || !value ||
        json_object_is_type(value, json_type_null))
        return NULL;
    return json_object_get_string(value);
}

static struct json_object *object_object(struct json_object *obj, const char *key)
{
    struct json_object *value = NULL;
    if (!obj || !key || !json_object_object_get_ex(obj, key, &value) || !value ||
        !json_object_is_type(value, json_type_object))
        return NULL;
    return value;
}

int main(void)
{
    sqlite3 *db = NULL;
    struct jmx_obs_event event;
    struct jmx_obs_port_input input;
    struct jmx_obs_detector detector;
    struct json_object *evidence = json_object_new_object();
    struct json_object *event_json;
    struct json_object *score;
    struct json_object *unsupported;
    struct json_object *timeline;
    struct json_object *storage;
    struct json_object *connectivity;
    struct json_object *timeline_events;
    sqlite3 *audit_db = NULL;
    sqlite3_stmt *st = NULL;
    int coalesced = 0;
    struct jmx_obs_event pinned_event;
    struct jmx_obs_event old_event;
    struct jmx_obs_retention_profile profile;
    struct jmx_obs_retention_profile prune_profile;
    char profile_db_path[160];
    sqlite3 *profile_db = NULL;

    jmx_obs_retention_profile_default(&profile);
    CHECK("default profile", !strcmp(profile.name, JMX_OBS_RETENTION_PROFILE) &&
          profile.version == 1 && profile.age_ms == 90LL * 86400000LL &&
          profile.row_cap == 65536 && profile.byte_cap == 268435456LL &&
          profile.configured == 0);
    snprintf(profile_db_path, sizeof(profile_db_path),
             "/tmp/observability-profile-%ld.db", (long)getpid());
    unlink(profile_db_path);
    CHECK("profile db", sqlite3_open(profile_db_path, &profile_db) == SQLITE_OK);
    CHECK("profile schema", sqlite3_exec(profile_db,
          "CREATE TABLE observability_retention_profile("
          "id INTEGER PRIMARY KEY,profile_name TEXT,version INTEGER,"
          "age_days INTEGER,row_cap INTEGER,byte_cap INTEGER,updated_at INTEGER);"
          "INSERT INTO observability_retention_profile VALUES(1,'fixture-profile',2,7,2048,33554432,0)",
          NULL, NULL, NULL) == SQLITE_OK);
    sqlite3_close(profile_db);
    profile_db = NULL;
    CHECK("configured profile load",
          jmx_obs_retention_profile_load(profile_db_path, &profile) == 0 &&
          !strcmp(profile.name, "fixture-profile") && profile.version == 2 &&
          profile.age_ms == 7LL * 86400000LL && profile.row_cap == 2048 &&
          profile.byte_cap == 33554432LL && profile.configured == 1);
    CHECK("profile reopen", sqlite3_open(profile_db_path, &profile_db) == SQLITE_OK);
    CHECK("invalid profile fixture", sqlite3_exec(profile_db,
          "UPDATE observability_retention_profile SET age_days=0,row_cap=1,byte_cap=1 WHERE id=1",
          NULL, NULL, NULL) == SQLITE_OK);
    sqlite3_close(profile_db);
    profile_db = NULL;
    CHECK("invalid profile fallback",
          jmx_obs_retention_profile_load(profile_db_path, &profile) == 1 &&
          !strcmp(profile.name, JMX_OBS_RETENTION_PROFILE) &&
          profile.version == 1 && profile.configured == 0);
    unlink(profile_db_path);

    json_object_object_add(evidence, "token", json_object_new_string("secret-value"));
    memset(&event, 0, sizeof(event));
    event.event_type = "PORT_LINK_FLAP";
    event.category = "TRAFFIC_PATH_HEALTH";
    event.state = "active";
    event.severity = "warning";
    event.confidence = "measured";
    event.observed_at = 100000;
    event.first_seen = 90000;
    event.last_seen = 100000;
    event.duration_ms = 10000;
    event.count = 1;
    event.source = "fixture";
    event.device_id = "sw-1";
    event.port_id = "eth3";
    event.event_id = "topology:fixture:port-link-flap:1";
    event.evidence = evidence;
    event.retention_class = "anomaly_90d";
    event.detector_revision = "fixture-v1";
    event_json = jmx_obs_event_json(&event);
    CHECK("event json", event_json != NULL);
    CHECK("redaction", strstr(json_object_to_json_string(event_json), "secret-value") == NULL);
    CHECK("event id", json_object_object_get(event_json, "event_id") != NULL);
    CHECK("sqlite", sqlite3_open(":memory:", &db) == SQLITE_OK);
    CHECK("store init", jmx_obs_event_store_init(db) == 0);
    fact_db = db;
    CHECK("append", jmx_obs_event_append(db, &event, &coalesced) == 0 && !coalesced);
    CHECK("dedupe", jmx_obs_event_append(db, &event, &coalesced) == 0 && coalesced);
    timeline = jmx_obs_event_timeline(db, 95000, 96000, "port", "eth3", &profile);
    CHECK("timeline overlap", object_int(timeline, "event_count") == 1);
    CHECK("timeline metadata", object_int(timeline, "available") == 1 &&
          object_int(timeline, "supported") == 1 &&
          object_int(timeline, "degraded") == 0 &&
          object_string(timeline, "source") != NULL &&
          object_string(timeline, "observed_at") != NULL &&
          object_string(timeline, "retention_profile") != NULL);
    timeline_events = json_object_object_get(timeline, "events");
    CHECK("canonical event id", timeline_events &&
          !strcmp(object_string(json_object_array_get_idx(timeline_events, 0), "event_id"),
                 event.event_id));
    storage = jmx_obs_storage_status(db, NULL, &profile);
    CHECK("storage metadata", object_int(storage, "available") == 1 &&
          object_int(storage, "supported") == 1 &&
          object_int(storage, "degraded") == 0 &&
          object_string(storage, "source") != NULL &&
          object_string(storage, "observed_at") != NULL &&
          !strcmp(object_string(storage, "retention_profile"), JMX_OBS_RETENTION_PROFILE) &&
          object_int(storage, "retention_version") == 1 &&
          object_int(storage, "retention_configured") == 0);
    CHECK("storage status counters", object_int64(storage, "coalesced_events") >= 1 &&
          object_int64(storage, "pruned_row_count") == 0);

    memset(&pinned_event, 0, sizeof(pinned_event));
    pinned_event.event_type = "CONFIG_SNAPSHOT_PINNED";
    pinned_event.category = "SYSTEM_STORAGE";
    pinned_event.state = "observed";
    pinned_event.severity = "notice";
    pinned_event.confidence = "measured";
    pinned_event.observed_at = 80000;
    pinned_event.first_seen = 80000;
    pinned_event.last_seen = 80000;
    pinned_event.count = 1;
    pinned_event.source = "fixture";
    pinned_event.device_id = "router";
    pinned_event.event_id = "storage:pinned:fixture";
    pinned_event.retention_class = "pinned_config_transaction";
    pinned_event.detector_revision = "fixture-v1";
    CHECK("pinned append", jmx_obs_event_append(db, &pinned_event, NULL) == 0);
    prune_profile = profile;
    prune_profile.age_ms = 100000;
    CHECK("pinned age prune", jmx_obs_event_prune(db, 500000, &prune_profile) >= 0);
    {
        struct json_object *pinned = jmx_obs_event_timeline(
            db, 79000, 81000, "device", "router", &profile);
        CHECK("pinned survives age", pinned && object_int(pinned, "event_count") == 1);
        json_object_put(pinned);
    }
    prune_profile = profile;
    prune_profile.row_cap = 1;
    CHECK("pinned row prune", jmx_obs_event_prune(db, 500000, &prune_profile) >= 0);
    {
        struct json_object *pinned = jmx_obs_event_timeline(
            db, 79000, 81000, "device", "router", &profile);
        CHECK("pinned survives row cap", pinned && object_int(pinned, "event_count") == 1);
        json_object_put(pinned);
    }

    memset(&old_event, 0, sizeof(old_event));
    old_event.event_type = "PORT_LINK_FLAP";
    old_event.category = "TRAFFIC_PATH_HEALTH";
    old_event.state = "active";
    old_event.severity = "warning";
    old_event.confidence = "measured";
    old_event.observed_at = 1000;
    old_event.first_seen = 1000;
    old_event.last_seen = 1000;
    old_event.count = 1;
    old_event.source = "fixture";
    old_event.device_id = "sw-2";
    old_event.port_id = "eth2";
    old_event.event_id = "storage:old:fixture";
    old_event.retention_class = "anomaly_90d";
    old_event.detector_revision = "fixture-v1";
    CHECK("old append", jmx_obs_event_append(db, &old_event, NULL) == 0);
    prune_profile = profile;
    prune_profile.byte_cap = 1;
    CHECK("byte prune", jmx_obs_event_prune(db, 500000, &prune_profile) >= 1);
    {
        struct json_object *old = jmx_obs_event_timeline(
            db, 900, 1100, "port", "eth2", &profile);
        CHECK("old event removed", old && object_int(old, "event_count") == 0);
        json_object_put(old);
    }
    {
        struct json_object *pinned = jmx_obs_event_timeline(
            db, 79000, 81000, "device", "router", &profile);
        CHECK("pinned survives byte cap", pinned && object_int(pinned, "event_count") == 1);
        json_object_put(pinned);
    }
    json_object_put(storage);
    storage = jmx_obs_storage_status(db, NULL, &profile);
    CHECK("prune system event", object_int64(storage, "prune_event_count") >= 1 &&
          object_int64(storage, "pruned_row_count") >= 1);

    memset(&detector, 0, sizeof(detector));
    detector.event_code = "PORT_LINK_FLAP";
    detector.category = JMX_OBS_LOOP_BROADCAST_FLOOD;
    detector.weight = 30;
    detector.severity_factor = 1;
    detector.recurrence_factor = 1;
    detector.count = 8;
    detector.duration_ms = 600123;
    detector.evidence = json_object_new_object();
    memset(&input, 0, sizeof(input));
    input.device_id = "sw-1";
    input.port_id = "eth3";
    input.identity_stable = 1;
    input.producer_complete = 1;
    input.window_start = 1;
    input.window_end = 86401;
    input.detectors = &detector;
    input.detector_count = 1;
    score = jmx_obs_port_anomaly_score(&input);
    CHECK("score", object_int(score, "score") == 30);
    CHECK("profile", strstr(json_object_to_json_string(score), JMX_OBS_SCORING_PROFILE) != NULL);
    input.identity_stable = 0;
    input.unsupported_reason = "topology_event_port_identity_not_stable_enough_for_scoring";
    unsupported = jmx_obs_port_anomaly_score(&input);
    CHECK("unsupported", object_int(unsupported, "supported") == 0);
    CHECK("unsupported reason", strstr(json_object_to_json_string(unsupported), input.unsupported_reason) != NULL);
    CHECK("unsupported score null", object_is_null(unsupported, "score"));
    CHECK("unsupported status unknown", object_string(unsupported, "status") &&
          !strcmp(object_string(unsupported, "status"), "UNKNOWN"));
    CHECK("unsupported category unknown",
          object_string(object_object(object_object(unsupported, "categories"), "CABLE_POWER"), "status") &&
          !strcmp(object_string(object_object(object_object(unsupported, "categories"), "CABLE_POWER"), "status"), "UNKNOWN") &&
          object_string(object_object(object_object(unsupported, "categories"), "LOOP_BROADCAST_FLOOD"), "status") &&
          !strcmp(object_string(object_object(object_object(unsupported, "categories"), "LOOP_BROADCAST_FLOOD"), "status"), "UNKNOWN") &&
          object_string(object_object(object_object(unsupported, "categories"), "MULTICAST_DISCOVERY"), "status") &&
          !strcmp(object_string(object_object(object_object(unsupported, "categories"), "MULTICAST_DISCOVERY"), "status"), "UNKNOWN") &&
          object_string(object_object(object_object(unsupported, "categories"), "TRAFFIC_PATH_HEALTH"), "status") &&
          !strcmp(object_string(object_object(object_object(unsupported, "categories"), "TRAFFIC_PATH_HEALTH"), "status"), "UNKNOWN"));
    CHECK("online append", jmx_obs_online_event_append(db, 1788528600,
          "online", "aa:bb:cc:dd:ee:ff", "192.0.2.10", "phone",
          "br-lan", "lan", "100", "wifi", "ap-1", -48, 120, "fixture", 0) == 0);
    connectivity = jmx_obs_event_timeline(db, 1788528599000LL, 1788528601000LL,
                                          "client", "aa:bb:cc:dd:ee:ff",
                                          &profile);
    {
        struct json_object *events = connectivity ?
            json_object_object_get(connectivity, "events") : NULL;
        struct json_object *online = events && json_object_array_length(events) ?
            json_object_array_get_idx(events, 0) : NULL;
        struct json_object *evidence = object_object(online, "evidence");
        CHECK("online event mapping", online &&
              object_string(online, "event_type") &&
              !strcmp(object_string(online, "event_type"), "CLIENT_CONNECTED") &&
              object_string(online, "client_id") &&
              !strcmp(object_string(online, "client_id"), "aa:bb:cc:dd:ee:ff") &&
              object_int64(online, "observed_at") == 1788528600000LL &&
              object_string(evidence, "ip") &&
              !strcmp(object_string(evidence, "ip"), "192.0.2.10"));
    }
    CHECK("audit sqlite", sqlite3_open(":memory:", &audit_db) == SQLITE_OK);
    CHECK("legacy audit schema", sqlite3_exec(audit_db,
          "CREATE TABLE audit_online_event(ts INTEGER,event_type TEXT,mac TEXT,ip TEXT,"
          "hostname TEXT,ifname TEXT,network TEXT,vlan TEXT,connection TEXT,ap_id TEXT,"
          "signal_dbm INTEGER,lease_time INTEGER,source TEXT,duration INTEGER)",
          NULL, NULL, NULL) == SQLITE_OK);
    {
        static const char *const legacy[] = { "online", "offline", "roam" };
        static const char *const types[] = {
            "CLIENT_CONNECTED", "CLIENT_DISCONNECTED", "CLIENT_ROAMED"
        };
        size_t i;
        struct json_object *projection, *events;
        for (i = 0; i < 3; i++)
            CHECK("bridge insert", dw_audit_online_event_insert(audit_db,
                  1788528600 + (int64_t)i, legacy[i], "11:22:33:44:55:66",
                  NULL, NULL, "wlan0", NULL, NULL, "wifi", "ap-1",
                  -51, 0, "wifi", 0) == 0);
        projection = jmx_obs_event_timeline(fact_db, 1788528599000LL,
                     1788528603000LL, "client", "11:22:33:44:55:66", &profile);
        CHECK("bridge query canonical db", object_int(projection, "event_count") == 3);
        events = json_object_object_get(projection, "events");
        for (i = 0; i < 3; i++)
            CHECK("bridge event mapping", !strcmp(
                object_string(json_object_array_get_idx(events, i), "event_type"), types[i]));
        json_object_put(projection);
    }
    CHECK("audit no separate facts prepare", sqlite3_prepare_v2(audit_db,
          "SELECT COUNT(*) FROM sqlite_master WHERE name='structured_events'",
          -1, &st, NULL) == SQLITE_OK);
    CHECK("audit no separate facts", sqlite3_step(st) == SQLITE_ROW &&
          sqlite3_column_int(st, 0) == 0);
    sqlite3_finalize(st);
    sqlite3_close(audit_db);
    json_object_put(event_json);
    json_object_put(score);
    json_object_put(unsupported);
    json_object_put(timeline);
    json_object_put(storage);
    json_object_put(connectivity);
    json_object_put(detector.evidence);
    json_object_put(evidence);
    sqlite3_close(db);
    puts("ok: observability event envelope, dedupe, redaction, and fail-closed scoring");
    return 0;
}

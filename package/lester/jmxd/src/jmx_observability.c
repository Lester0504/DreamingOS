/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "jmx_observability.h"

#include <openssl/sha.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define OBS_RETENTION_MS (90LL * 24LL * 60LL * 60LL * 1000LL)
#define OBS_DEFAULT_ROW_CAP 65536
#define OBS_DEFAULT_BYTE_CAP (256LL * 1024LL * 1024LL)
#define OBS_EVENT_ROW_OVERHEAD_BYTES_STR "288"
#define OBS_MIN_AGE_DAYS 1
#define OBS_MAX_AGE_DAYS 730
#define OBS_MIN_ROW_CAP 1024
#define OBS_MAX_ROW_CAP 1000000
#define OBS_MIN_BYTE_CAP (16LL * 1024LL * 1024LL)
#define OBS_MAX_BYTE_CAP (2LL * 1024LL * 1024LL * 1024LL)

static int64_t obs_now_ms(void);

void jmx_obs_retention_profile_default(struct jmx_obs_retention_profile *profile)
{
    if (!profile)
        return;
    memset(profile, 0, sizeof(*profile));
    snprintf(profile->name, sizeof(profile->name), "%s",
             JMX_OBS_RETENTION_PROFILE);
    profile->version = 1;
    profile->age_ms = OBS_RETENTION_MS;
    profile->row_cap = OBS_DEFAULT_ROW_CAP;
    profile->byte_cap = OBS_DEFAULT_BYTE_CAP;
}

int jmx_obs_retention_profile_load(const char *config_db_path,
                                   struct jmx_obs_retention_profile *profile)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    const char *name;
    int version;
    int age_days;
    int row_cap;
    int64_t byte_cap;
    int rc = 1;

    if (!profile)
        return -1;
    jmx_obs_retention_profile_default(profile);
    if (!config_db_path || !config_db_path[0])
        return rc;
    if (sqlite3_open_v2(config_db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        goto out;
    if (sqlite3_prepare_v2(db,
        "SELECT profile_name,version,age_days,row_cap,byte_cap "
        "FROM observability_retention_profile WHERE id=1",
        -1, &st, NULL) != SQLITE_OK || sqlite3_step(st) != SQLITE_ROW)
        goto out;
    name = (const char *)sqlite3_column_text(st, 0);
    version = sqlite3_column_int(st, 1);
    age_days = sqlite3_column_int(st, 2);
    row_cap = sqlite3_column_int(st, 3);
    byte_cap = sqlite3_column_int64(st, 4);
    if (!name || !name[0] || strlen(name) >= sizeof(profile->name) ||
        version < 1 || version > 1000 ||
        age_days < OBS_MIN_AGE_DAYS || age_days > OBS_MAX_AGE_DAYS ||
        row_cap < OBS_MIN_ROW_CAP || row_cap > OBS_MAX_ROW_CAP ||
        byte_cap < OBS_MIN_BYTE_CAP || byte_cap > OBS_MAX_BYTE_CAP)
        goto out;
    snprintf(profile->name, sizeof(profile->name), "%s", name);
    profile->version = version;
    profile->age_ms = (int64_t)age_days * 24LL * 60LL * 60LL * 1000LL;
    profile->row_cap = row_cap;
    profile->byte_cap = byte_cap;
    profile->configured = 1;
    rc = 0;
out:
    sqlite3_finalize(st);
    if (db)
        sqlite3_close(db);
    return rc;
}

static const char *obs_str(const char *value)
{
    return value ? value : "";
}

static void obs_projection_meta(struct json_object *root, int available,
                                int supported, int degraded,
                                const char *reason, const char *source,
                                int64_t observed_at,
                                const char *retention_profile)
{
    json_object_object_add(root, "available", json_object_new_boolean(available));
    json_object_object_add(root, "supported", json_object_new_boolean(supported));
    json_object_object_add(root, "degraded", json_object_new_boolean(degraded));
    json_object_object_add(root, "reason", json_object_new_string(obs_str(reason)));
    json_object_object_add(root, "source", json_object_new_string(obs_str(source)));
    json_object_object_add(root, "observed_at", json_object_new_int64(observed_at));
    json_object_object_add(root, "retention_profile",
                           json_object_new_string(obs_str(retention_profile)));
}

static void obs_event_id(const struct jmx_obs_event *event, char out[65])
{
    char seed[1024];
    unsigned char digest[SHA256_DIGEST_LENGTH];
    size_t i;

    snprintf(seed, sizeof(seed), "%s|%s|%s|%s|%lld|%s",
             obs_str(event->device_id), obs_str(event->port_id),
             obs_str(event->event_type), obs_str(event->detector_revision),
             (long long)(event->first_seen / 60000LL), obs_str(event->client_id));
    SHA256((const unsigned char *)seed, strlen(seed), digest);
    for (i = 0; i < sizeof(digest); i++)
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    out[64] = '\0';
}

static struct json_object *obs_redact_copy(struct json_object *value,
                                           const char *key)
{
    enum json_type type;

    if (!value)
        return json_object_new_null();
    if (key && (!strcasecmp(key, "password") || !strcasecmp(key, "token") ||
                !strcasecmp(key, "psk") || !strcasecmp(key, "secret") ||
                !strcasecmp(key, "private_key") || !strcasecmp(key, "shared_secret")))
        return json_object_new_string("[REDACTED]");
    type = json_object_get_type(value);
    if (type == json_type_object) {
        struct json_object *copy = json_object_new_object();
        json_object_object_foreach(value, child_key, child_value) {
            json_object_object_add(copy, child_key,
                                   obs_redact_copy(child_value, child_key));
        }
        return copy;
    }
    if (type == json_type_array) {
        struct json_object *copy = json_object_new_array();
        size_t i;
        for (i = 0; i < json_object_array_length(value); i++)
            json_object_array_add(copy, obs_redact_copy(
                json_object_array_get_idx(value, i), NULL));
        return copy;
    }
    return json_object_get(value);
}

struct json_object *jmx_obs_event_json(const struct jmx_obs_event *event)
{
    struct json_object *root;
    struct json_object *evidence;
    char event_id[65];

    if (!event || !event->event_type)
        return NULL;
    if (event->event_id && event->event_id[0])
        snprintf(event_id, sizeof(event_id), "%s", event->event_id);
    else
        obs_event_id(event, event_id);
    root = json_object_new_object();
    evidence = obs_redact_copy(event->evidence, NULL);
    json_object_object_add(root, "event_id", json_object_new_string(event_id));
    json_object_object_add(root, "schema_version", json_object_new_int(JMX_OBS_SCHEMA_VERSION));
    json_object_object_add(root, "event_type", json_object_new_string(obs_str(event->event_type)));
    json_object_object_add(root, "category", json_object_new_string(obs_str(event->category)));
    json_object_object_add(root, "state", json_object_new_string(obs_str(event->state)));
    json_object_object_add(root, "severity", json_object_new_string(obs_str(event->severity)));
    json_object_object_add(root, "confidence", json_object_new_string(obs_str(event->confidence)));
    json_object_object_add(root, "observed_at", json_object_new_int64(event->observed_at));
    json_object_object_add(root, "first_seen", json_object_new_int64(event->first_seen));
    json_object_object_add(root, "last_seen", json_object_new_int64(event->last_seen));
    json_object_object_add(root, "duration_ms", json_object_new_int64(event->duration_ms));
    json_object_object_add(root, "count", json_object_new_int(event->count > 0 ? event->count : 1));
    json_object_object_add(root, "source", json_object_new_string(obs_str(event->source)));
    json_object_object_add(root, "site_id", json_object_new_string(obs_str(event->site_id)));
    json_object_object_add(root, "device_id", json_object_new_string(obs_str(event->device_id)));
    json_object_object_add(root, "port_id", json_object_new_string(obs_str(event->port_id)));
    json_object_object_add(root, "client_id", event->client_id ?
                           json_object_new_string(event->client_id) : json_object_new_null());
    json_object_object_add(root, "radio_id", event->radio_id ?
                           json_object_new_string(event->radio_id) : json_object_new_null());
    json_object_object_add(root, "correlation_id", json_object_new_string(obs_str(event->correlation_id)));
    json_object_object_add(root, "before_digest", json_object_new_string(obs_str(event->before_digest)));
    json_object_object_add(root, "after_digest", json_object_new_string(obs_str(event->after_digest)));
    json_object_object_add(root, "evidence", evidence);
    json_object_object_add(root, "coalesced_count", json_object_new_int(0));
    json_object_object_add(root, "display_suppressed", json_object_new_boolean(event->display_suppressed));
    json_object_object_add(root, "retention_class", json_object_new_string(obs_str(event->retention_class)));
    json_object_object_add(root, "detector_revision", json_object_new_string(obs_str(event->detector_revision)));
    return root;
}

int jmx_obs_event_store_init(sqlite3 *db)
{
    static const char *schema =
        "CREATE TABLE IF NOT EXISTS structured_events("
        "event_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL,"
        "event_type TEXT NOT NULL, category TEXT NOT NULL DEFAULT '', state TEXT NOT NULL DEFAULT '',"
        "severity TEXT NOT NULL DEFAULT '', confidence TEXT NOT NULL DEFAULT '',"
        "observed_at INTEGER NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,"
        "duration_ms INTEGER NOT NULL DEFAULT 0, count INTEGER NOT NULL DEFAULT 1,"
        "source TEXT NOT NULL DEFAULT '', site_id TEXT NOT NULL DEFAULT '',"
        "device_id TEXT NOT NULL DEFAULT '', port_id TEXT NOT NULL DEFAULT '',"
        "client_id TEXT, radio_id TEXT, correlation_id TEXT NOT NULL DEFAULT '',"
        "before_digest TEXT NOT NULL DEFAULT '', after_digest TEXT NOT NULL DEFAULT '',"
        "evidence_json TEXT NOT NULL DEFAULT '{}', coalesced_count INTEGER NOT NULL DEFAULT 0,"
        "display_suppressed INTEGER NOT NULL DEFAULT 0, retention_class TEXT NOT NULL DEFAULT '',"
        "detector_revision TEXT NOT NULL DEFAULT '');"
        "CREATE INDEX IF NOT EXISTS idx_structured_events_observed"
        " ON structured_events(observed_at);"
        "CREATE INDEX IF NOT EXISTS idx_structured_events_entity"
        " ON structured_events(device_id,port_id,client_id);"
        "CREATE INDEX IF NOT EXISTS idx_structured_events_timeline"
        " ON structured_events(first_seen,event_id);"
        "CREATE INDEX IF NOT EXISTS idx_structured_events_client_timeline"
        " ON structured_events(client_id COLLATE NOCASE,first_seen,event_id);";
    char *err = NULL;
    int rc;

    if (!db)
        return -1;
    /* SQLite rejects changing journal_mode while a collector transaction is
     * active.  Keep the WAL preference for autocommit callers, but let
     * collectors initialize the schema safely before BEGIN IMMEDIATE. */
    if (sqlite3_get_autocommit(db) &&
        sqlite3_exec(db, "PRAGMA journal_mode=WAL", NULL, NULL, &err) != SQLITE_OK) {
        sqlite3_free(err);
        err = NULL;
    }
    rc = sqlite3_exec(db, schema, NULL, NULL, &err);
    sqlite3_free(err);
    return rc == SQLITE_OK ? 0 : -1;
}

int jmx_obs_event_append(sqlite3 *db, const struct jmx_obs_event *event,
                         int *coalesced)
{
    struct json_object *payload;
    const char *payload_s;
    const char *event_id;
    sqlite3_stmt *st = NULL;
    sqlite3_stmt *exists = NULL;
    int already_present = 0;
    int rc;

    if (coalesced)
        *coalesced = 0;
    if (!db || !event || !event->event_type || jmx_obs_event_store_init(db) != 0)
        return -1;
    payload = jmx_obs_event_json(event);
    if (!payload)
        return -1;
    event_id = json_object_get_string(json_object_object_get(payload, "event_id"));
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM structured_events WHERE event_id=?1",
                           -1, &exists, NULL) == SQLITE_OK) {
        sqlite3_bind_text(exists, 1, event_id, -1, SQLITE_TRANSIENT);
        already_present = sqlite3_step(exists) == SQLITE_ROW;
    }
    sqlite3_finalize(exists);
    payload_s = json_object_to_json_string_ext(json_object_object_get(payload, "evidence"),
                                               JSON_C_TO_STRING_PLAIN);
    rc = sqlite3_prepare_v2(db,
        "INSERT INTO structured_events(event_id,schema_version,event_type,category,state,severity,confidence,"
        "observed_at,first_seen,last_seen,duration_ms,count,source,site_id,device_id,port_id,client_id,radio_id,"
        "correlation_id,before_digest,after_digest,evidence_json,coalesced_count,display_suppressed,retention_class,detector_revision) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(event_id) DO UPDATE SET last_seen=excluded.last_seen,"
        "duration_ms=MAX(structured_events.duration_ms,excluded.duration_ms),"
        "count=structured_events.count+excluded.count,"
        "coalesced_count=structured_events.coalesced_count+1", -1, &st, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(st, 1, event_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, JMX_OBS_SCHEMA_VERSION);
        sqlite3_bind_text(st, 3, obs_str(event->event_type), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, obs_str(event->category), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, obs_str(event->state), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, obs_str(event->severity), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, obs_str(event->confidence), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 8, event->observed_at);
        sqlite3_bind_int64(st, 9, event->first_seen);
        sqlite3_bind_int64(st, 10, event->last_seen);
        sqlite3_bind_int64(st, 11, event->duration_ms);
        sqlite3_bind_int(st, 12, event->count > 0 ? event->count : 1);
        sqlite3_bind_text(st, 13, obs_str(event->source), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 14, obs_str(event->site_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 15, obs_str(event->device_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 16, obs_str(event->port_id), -1, SQLITE_TRANSIENT);
        if (event->client_id) sqlite3_bind_text(st, 17, event->client_id, -1, SQLITE_TRANSIENT); else sqlite3_bind_null(st, 17);
        if (event->radio_id) sqlite3_bind_text(st, 18, event->radio_id, -1, SQLITE_TRANSIENT); else sqlite3_bind_null(st, 18);
        sqlite3_bind_text(st, 19, obs_str(event->correlation_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 20, obs_str(event->before_digest), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 21, obs_str(event->after_digest), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 22, payload_s ? payload_s : "{}", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 23, 0);
        sqlite3_bind_int(st, 24, event->display_suppressed ? 1 : 0);
        sqlite3_bind_text(st, 25, obs_str(event->retention_class), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 26, obs_str(event->detector_revision), -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(st);
        if (rc == SQLITE_DONE && coalesced)
            *coalesced = already_present;
    }
    sqlite3_finalize(st);
    json_object_put(payload);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int64_t obs_event_store_bytes(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    int64_t bytes = 0;

    if (!db)
        return 0;
    if (sqlite3_prepare_v2(db,
        "SELECT COALESCE(SUM(" OBS_EVENT_ROW_OVERHEAD_BYTES_STR
        "+length(event_id)+length(event_type)+length(category)+length(state)"
        "+length(severity)+length(confidence)+length(source)+length(site_id)"
        "+length(device_id)+length(port_id)+COALESCE(length(client_id),0)"
        "+COALESCE(length(radio_id),0)+length(correlation_id)+length(before_digest)"
        "+length(after_digest)+length(evidence_json)+length(retention_class)"
        "+length(detector_revision)),0) FROM structured_events",
        -1, &st, NULL) != SQLITE_OK) {
        sqlite3_finalize(st);
        return 0;
    }
    if (sqlite3_step(st) == SQLITE_ROW)
        bytes = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return bytes;
}

static void obs_storage_prune_event(sqlite3 *db, int64_t now_ms,
                                    const struct jmx_obs_retention_profile *profile,
                                    int removed,
                                    int64_t bytes_before,
                                    int64_t bytes_after)
{
    struct jmx_obs_event event;
    struct json_object *evidence;
    char event_id[96];

    if (!db || removed <= 0)
        return;
    evidence = json_object_new_object();
    json_object_object_add(evidence, "removed_rows", json_object_new_int(removed));
    json_object_object_add(evidence, "retention_profile",
                           json_object_new_string(profile->name));
    json_object_object_add(evidence, "retention_version",
                           json_object_new_int(profile->version));
    json_object_object_add(evidence, "age_ms", json_object_new_int64(profile->age_ms));
    json_object_object_add(evidence, "row_cap", json_object_new_int(profile->row_cap));
    json_object_object_add(evidence, "byte_cap", json_object_new_int64(profile->byte_cap));
    json_object_object_add(evidence, "estimated_bytes_before",
                           json_object_new_int64(bytes_before));
    json_object_object_add(evidence, "estimated_bytes_after",
                           json_object_new_int64(bytes_after));
    json_object_object_add(evidence, "pinned_protected", json_object_new_boolean(1));

    memset(&event, 0, sizeof(event));
    snprintf(event_id, sizeof(event_id), "storage:prune:%lld",
             (long long)(now_ms / 60000LL));
    event.event_id = event_id;
    event.event_type = "STORAGE_PRUNED";
    event.category = "SYSTEM_STORAGE";
    event.state = "observed";
    event.severity = "notice";
    event.confidence = "measured";
    event.observed_at = now_ms;
    event.first_seen = now_ms;
    event.last_seen = now_ms;
    event.count = removed;
    event.source = "jmx_obs_event_prune";
    event.site_id = "default";
    event.evidence = evidence;
    event.retention_class = "system_storage_90d";
    event.detector_revision = "observability-storage-v1";
    (void)jmx_obs_event_append(db, &event, NULL);
    json_object_put(evidence);
}

int jmx_obs_event_prune(sqlite3 *db, int64_t now_ms,
                        const struct jmx_obs_retention_profile *profile)
{
    sqlite3_stmt *st = NULL;
    int removed = 0;
    int64_t bytes_before = 0;
    struct jmx_obs_retention_profile defaults;

    if (!db || jmx_obs_event_store_init(db) != 0)
        return -1;
    if (!profile) {
        jmx_obs_retention_profile_default(&defaults);
        profile = &defaults;
    }
    bytes_before = obs_event_store_bytes(db);
    /* Age prune: ignore pinned events (retention_class starting with 'pinned_') */
    if (sqlite3_prepare_v2(db,
        "DELETE FROM structured_events WHERE last_seen < ?1 "
        "AND (retention_class NOT LIKE 'pinned_%' OR retention_class='')",
        -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, now_ms - profile->age_ms);
    if (sqlite3_step(st) != SQLITE_DONE) { sqlite3_finalize(st); return -1; }
    removed += sqlite3_changes(db);
    sqlite3_finalize(st);
    st = NULL;
    /* Row cap prune: exclude pinned */
    if (sqlite3_prepare_v2(db,
        "DELETE FROM structured_events "
        "WHERE (retention_class NOT LIKE 'pinned_%' OR retention_class='') "
        "AND event_id NOT IN "
        "(SELECT event_id FROM structured_events "
        "WHERE (retention_class NOT LIKE 'pinned_%' OR retention_class='') "
        "ORDER BY last_seen DESC,event_id DESC LIMIT ?1)",
        -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(st, 1, profile->row_cap);
    if (sqlite3_step(st) != SQLITE_DONE) { sqlite3_finalize(st); return -1; }
    removed += sqlite3_changes(db);
    sqlite3_finalize(st);
    /* Byte cap is an estimate of this table's logical payload plus row
     * overhead.  The core DB is shared, so its file size must not cause event
     * rows from another projection to be deleted. */
    if (profile->byte_cap > 0) {
        int64_t total_bytes = obs_event_store_bytes(db);

        while (total_bytes > profile->byte_cap) {
            int batch_removed = 0;
            /* Drop oldest 100 non-pinned events per iteration */
            if (sqlite3_prepare_v2(db,
                "DELETE FROM structured_events WHERE event_id IN "
                "(SELECT event_id FROM structured_events "
                "WHERE (retention_class NOT LIKE 'pinned_%' OR retention_class='') "
                "ORDER BY last_seen ASC LIMIT 100)",
                -1, &st, NULL) != SQLITE_OK)
                break;
            if (sqlite3_step(st) != SQLITE_DONE) { sqlite3_finalize(st); break; }
            batch_removed = sqlite3_changes(db);
            sqlite3_finalize(st);
            if (batch_removed == 0) break; /* No more non-pinned events */
            removed += batch_removed;
            total_bytes = obs_event_store_bytes(db);
        }
        obs_storage_prune_event(db, now_ms, profile, removed,
                                bytes_before, total_bytes);
    }
    return removed;
}

struct json_object *jmx_obs_storage_status(sqlite3 *db, const char *db_path,
                         const struct jmx_obs_retention_profile *profile)
{
    struct json_object *root = json_object_new_object();
    sqlite3_stmt *st = NULL;
    struct stat sb;
    char wal_path[1024];
    int64_t count = 0, oldest = 0, newest = 0, db_bytes = 0, wal_bytes = 0, total_bytes = 0;
    int64_t event_bytes = 0;
    int64_t total_coalesced = 0, suppressed_count = 0, pruned_events = 0;
    int64_t pruned_rows = 0;
    int row_pressure = 0, byte_pressure = 0;
    const char *pressure_level = "normal";
    struct jmx_obs_retention_profile defaults;

    if (!profile) {
        jmx_obs_retention_profile_default(&defaults);
        profile = &defaults;
    }

    if (!db || jmx_obs_event_store_init(db) != 0) {
        obs_projection_meta(root, 0, 0, 1, "event_store_unavailable",
                            "structured_events", 0, profile->name);
        return root;
    }
    if (sqlite3_prepare_v2(db,
        "SELECT COUNT(*),COALESCE(MIN(first_seen),0),COALESCE(MAX(last_seen),0),"
        "COALESCE(SUM(coalesced_count),0),COALESCE(SUM(CASE WHEN display_suppressed=1 THEN 1 ELSE 0 END),0) "
        "FROM structured_events",
        -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW) {
        count = sqlite3_column_int64(st, 0);
        oldest = sqlite3_column_int64(st, 1);
        newest = sqlite3_column_int64(st, 2);
        total_coalesced = sqlite3_column_int64(st, 3);
        suppressed_count = sqlite3_column_int64(st, 4);
    }
    sqlite3_finalize(st);
    event_bytes = obs_event_store_bytes(db);
    if (sqlite3_prepare_v2(db,
        "SELECT COUNT(*),COALESCE(SUM(count),0) FROM structured_events "
        "WHERE event_type='STORAGE_PRUNED' AND retention_class='system_storage_90d'",
        -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW) {
        pruned_events = sqlite3_column_int64(st, 0);
        pruned_rows = sqlite3_column_int64(st, 1);
    }
    sqlite3_finalize(st);
    if (db_path && stat(db_path, &sb) == 0) db_bytes = sb.st_size;
    if (db_path && snprintf(wal_path, sizeof(wal_path), "%s-wal", db_path) < (int)sizeof(wal_path) &&
        stat(wal_path, &sb) == 0) wal_bytes = sb.st_size;
    total_bytes = db_bytes + wal_bytes;
    /* Row pressure: 90% of cap is warning, 100% is critical */
    if (count >= profile->row_cap)
        row_pressure = 2;
    else if (count >= (profile->row_cap * 9LL / 10LL))
        row_pressure = 1;
    if (event_bytes >= profile->byte_cap)
        byte_pressure = 2;
    else if (event_bytes >= (profile->byte_cap * 9LL / 10LL))
        byte_pressure = 1;
    if (row_pressure >= 2 || byte_pressure >= 2)
        pressure_level = "critical";
    else if (row_pressure == 1 || byte_pressure == 1)
        pressure_level = "warning";
    obs_projection_meta(root, 1, 1, row_pressure > 0 || byte_pressure > 0,
                        row_pressure > 0 || byte_pressure > 0 ? "storage_pressure" : "",
                        "structured_events", obs_now_ms(),
                        profile->name);
    json_object_object_add(root, "retention_ms", json_object_new_int64(profile->age_ms));
    json_object_object_add(root, "retention_version", json_object_new_int(profile->version));
    json_object_object_add(root, "retention_configured",
                           json_object_new_boolean(profile->configured));
    json_object_object_add(root, "event_count", json_object_new_int64(count));
    json_object_object_add(root, "coalesced_events", json_object_new_int64(total_coalesced));
    json_object_object_add(root, "suppressed_events", json_object_new_int64(suppressed_count));
    json_object_object_add(root, "oldest_timestamp", json_object_new_int64(oldest));
    json_object_object_add(root, "newest_timestamp", json_object_new_int64(newest));
    json_object_object_add(root, "database_bytes", json_object_new_int64(db_bytes));
    json_object_object_add(root, "wal_bytes", json_object_new_int64(wal_bytes));
    json_object_object_add(root, "total_bytes", json_object_new_int64(total_bytes));
    json_object_object_add(root, "estimated_event_bytes", json_object_new_int64(event_bytes));
    json_object_object_add(root, "row_cap", json_object_new_int(profile->row_cap));
    json_object_object_add(root, "row_pressure", json_object_new_int(row_pressure));
    json_object_object_add(root, "byte_pressure", json_object_new_int(byte_pressure));
    json_object_object_add(root, "storage_pressure", json_object_new_string(pressure_level));
    json_object_object_add(root, "byte_cap", json_object_new_int64(profile->byte_cap));
    json_object_object_add(root, "byte_threshold_warning",
                           json_object_new_int64(profile->byte_cap * 9LL / 10LL));
    json_object_object_add(root, "byte_threshold_critical",
                           json_object_new_int64(profile->byte_cap));
    json_object_object_add(root, "prune_event_count", json_object_new_int64(pruned_events));
    json_object_object_add(root, "pruned_row_count", json_object_new_int64(pruned_rows));
    return root;
}

static int64_t obs_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return (int64_t)time(NULL) * 1000LL;
    return (int64_t)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

int jmx_obs_event_append_json(sqlite3 *db, struct json_object *payload,
                              int *coalesced)
{
    struct jmx_obs_event event;
    struct json_object *value = NULL;
    const char *s;

    memset(&event, 0, sizeof(event));
    if (!payload || !json_object_is_type(payload, json_type_object))
        return -1;
#define OBS_JSON_STR(field, key) do { \
    event.field = json_object_object_get_ex(payload, key, &value) && value ? \
        json_object_get_string(value) : ""; \
} while (0)
#define OBS_JSON_STR_OPTIONAL(field, key) do { \
    event.field = json_object_object_get_ex(payload, key, &value) && value ? \
        json_object_get_string(value) : NULL; \
} while (0)
    OBS_JSON_STR_OPTIONAL(event_id, "event_id");
    OBS_JSON_STR(event_type, "event_type");
    OBS_JSON_STR(category, "category");
    OBS_JSON_STR(state, "state");
    OBS_JSON_STR(severity, "severity");
    OBS_JSON_STR(confidence, "confidence");
    OBS_JSON_STR(source, "source");
    OBS_JSON_STR(site_id, "site_id");
    OBS_JSON_STR(device_id, "device_id");
    OBS_JSON_STR(port_id, "port_id");
    OBS_JSON_STR(correlation_id, "correlation_id");
    OBS_JSON_STR(before_digest, "before_digest");
    OBS_JSON_STR(after_digest, "after_digest");
    OBS_JSON_STR(retention_class, "retention_class");
    OBS_JSON_STR(detector_revision, "detector_revision");
#undef OBS_JSON_STR
#undef OBS_JSON_STR_OPTIONAL
    if (json_object_object_get_ex(payload, "client_id", &value) && value &&
        !json_object_is_type(value, json_type_null))
        event.client_id = json_object_get_string(value);
    if (json_object_object_get_ex(payload, "radio_id", &value) && value &&
        !json_object_is_type(value, json_type_null))
        event.radio_id = json_object_get_string(value);
    if (json_object_object_get_ex(payload, "evidence", &value))
        event.evidence = value;
    if (json_object_object_get_ex(payload, "observed_at", &value) && value)
        event.observed_at = json_object_get_int64(value);
    if (json_object_object_get_ex(payload, "first_seen", &value) && value)
        event.first_seen = json_object_get_int64(value);
    if (json_object_object_get_ex(payload, "last_seen", &value) && value)
        event.last_seen = json_object_get_int64(value);
    if (json_object_object_get_ex(payload, "duration_ms", &value) && value)
        event.duration_ms = json_object_get_int64(value);
    if (json_object_object_get_ex(payload, "count", &value) && value)
        event.count = json_object_get_int(value);
    if (json_object_object_get_ex(payload, "display_suppressed", &value) && value)
        event.display_suppressed = json_object_get_boolean(value);
    if (event.observed_at <= 0)
        event.observed_at = obs_now_ms();
    if (event.first_seen <= 0)
        event.first_seen = event.observed_at;
    if (event.last_seen <= 0)
        event.last_seen = event.observed_at;
    s = event.event_type;
    if (!s || !s[0])
        return -1;
    return jmx_obs_event_append(db, &event, coalesced);
}

int jmx_obs_online_event_append(sqlite3 *db, int64_t observed_at,
                                const char *legacy_event_type,
                                const char *mac, const char *ip,
                                const char *hostname, const char *ifname,
                                const char *network, const char *vlan,
                                const char *connection, const char *ap_id,
                                int signal_dbm, int lease_time,
                                const char *source, int duration)
{
    struct jmx_obs_event event;
    struct json_object *evidence;
    const char *event_type;
    int64_t ts = observed_at;
    int coalesced = 0;

    if (!db || !mac || !mac[0])
        return -1;
    if (ts > 0 && ts < 100000000000LL)
        ts *= 1000LL;
    if (ts <= 0)
        ts = obs_now_ms();
    if (!legacy_event_type)
        legacy_event_type = "";
    if (!strcmp(legacy_event_type, "online"))
        event_type = "CLIENT_CONNECTED";
    else if (!strcmp(legacy_event_type, "offline"))
        event_type = "CLIENT_DISCONNECTED";
    else if (!strcmp(legacy_event_type, "roam"))
        event_type = "CLIENT_ROAMED";
    else if (!strcmp(legacy_event_type, "auth_failure"))
        event_type = "CLIENT_AUTH_FAILED";
    else
        event_type = legacy_event_type[0] ? legacy_event_type : "CLIENT_STATE_CHANGED";

    evidence = json_object_new_object();
    json_object_object_add(evidence, "ip", json_object_new_string(obs_str(ip)));
    json_object_object_add(evidence, "hostname", json_object_new_string(obs_str(hostname)));
    json_object_object_add(evidence, "ifname", json_object_new_string(obs_str(ifname)));
    json_object_object_add(evidence, "network", json_object_new_string(obs_str(network)));
    json_object_object_add(evidence, "vlan", json_object_new_string(obs_str(vlan)));
    json_object_object_add(evidence, "connection", json_object_new_string(obs_str(connection)));
    json_object_object_add(evidence, "ap_id", json_object_new_string(obs_str(ap_id)));
    json_object_object_add(evidence, "signal_dbm", json_object_new_int(signal_dbm));
    json_object_object_add(evidence, "lease_time", json_object_new_int(lease_time));
    json_object_object_add(evidence, "source", json_object_new_string(obs_str(source)));
    json_object_object_add(evidence, "duration_ms",
                           json_object_new_int64(duration > 0 ? (int64_t)duration * 1000LL : 0));

    memset(&event, 0, sizeof(event));
    event.event_type = event_type;
    event.category = "CLIENT_DEVICES";
    event.state = !strcmp(event_type, "CLIENT_DISCONNECTED") ? "recovered" : "active";
    event.severity = !strcmp(event_type, "CLIENT_AUTH_FAILED") ? "warning" : "notice";
    event.confidence = "measured";
    event.observed_at = ts;
    event.first_seen = ts;
    event.last_seen = ts;
    event.duration_ms = duration > 0 ? (int64_t)duration * 1000LL : 0;
    event.count = 1;
    event.source = source;
    event.client_id = mac;
    event.evidence = evidence;
    event.retention_class = "client_connectivity_90d";
    event.detector_revision = "online-connectivity-v1";
    if (jmx_obs_event_append(db, &event, &coalesced) != 0) {
        json_object_put(evidence);
        return -1;
    }
    json_object_put(evidence);
    return 0;
}

static struct json_object *obs_event_timeline_query(sqlite3 *db, int64_t start_ms,
                                           int64_t end_ms,
                                           const char *entity_type,
                                           const char *entity_id,
                         const struct jmx_obs_retention_profile *profile,
                         int paged, int limit, int64_t cursor_first_seen,
                         const char *cursor_event_id)
{
    struct json_object *root = json_object_new_object();
    struct json_object *events = json_object_new_array();
    sqlite3_stmt *st = NULL;
    int64_t now = obs_now_ms();
    int64_t count = 0;
    int rc, has_more = 0;
    const char *filter = "";
    char sql[2048];
    struct jmx_obs_retention_profile defaults;

    if (!profile) {
        jmx_obs_retention_profile_default(&defaults);
        profile = &defaults;
    }

    if (paged && (limit < 0 || cursor_first_seen < 0 ||
        (cursor_event_id && (!cursor_event_id[0] || strlen(cursor_event_id) > 64)) ||
        (!cursor_event_id && cursor_first_seen != 0))) {
        obs_projection_meta(root, 0, 1, 1, "invalid_pagination",
                            "structured_events", now, profile->name);
        json_object_put(events);
        return root;
    }
    if (paged) {
        if (!limit) limit = JMX_OBS_TIMELINE_PAGE_DEFAULT;
        if (limit > JMX_OBS_TIMELINE_PAGE_MAX) limit = JMX_OBS_TIMELINE_PAGE_MAX;
    }

    if (!db || jmx_obs_event_store_init(db) != 0) {
        obs_projection_meta(root, 0, 0, 1, "event_store_unavailable",
                            "structured_events", now, profile->name);
        json_object_put(events);
        return root;
    }
    if (end_ms <= 0 || end_ms > now + 60000)
        end_ms = now;
    if (start_ms <= 0 || start_ms < end_ms - profile->age_ms)
        start_ms = end_ms - profile->age_ms;
    if (start_ms > end_ms) {
        obs_projection_meta(root, 0, 1, 1, "invalid_time_range",
                            "structured_events", now, profile->name);
        json_object_put(events);
        return root;
    }
    if (obs_str(entity_id)[0]) {
        if (!strcmp(obs_str(entity_type), "client"))
            filter = paged ? " AND client_id=?3 COLLATE NOCASE" : " AND client_id=?3";
        else if (!strcmp(obs_str(entity_type), "device")) filter = " AND device_id=?3";
        else if (!strcmp(obs_str(entity_type), "port")) filter = " AND port_id=?3";
        else if (!strcmp(obs_str(entity_type), "radio")) filter = " AND radio_id=?3";
        else filter = " AND 0";
    }
    snprintf(sql, sizeof(sql),
        "SELECT event_id,schema_version,event_type,category,state,severity,confidence,"
        "observed_at,first_seen,last_seen,duration_ms,count,source,site_id,device_id,port_id,"
        "client_id,radio_id,correlation_id,before_digest,after_digest,evidence_json,"
        "coalesced_count,display_suppressed,retention_class,detector_revision "
        "FROM structured_events WHERE last_seen >= ?1 AND first_seen <= ?2%s%s "
        "ORDER BY first_seen ASC,event_id ASC%s", filter,
        paged && cursor_event_id ?
            " AND first_seen>=?4 AND (first_seen>?4 OR event_id>?5)" : "",
        paged ? " LIMIT ?6" : "");
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        obs_projection_meta(root, 0, 1, 1, "event_query_failed",
                            "structured_events", now, profile->name);
        json_object_put(events);
        return root;
    }
    sqlite3_bind_int64(st, 1, start_ms);
    sqlite3_bind_int64(st, 2, end_ms);
    sqlite3_bind_text(st, 3, obs_str(entity_id), -1, SQLITE_TRANSIENT);
    if (paged) {
        if (cursor_event_id) {
            sqlite3_bind_int64(st, 4, cursor_first_seen);
            sqlite3_bind_text(st, 5, cursor_event_id, -1, SQLITE_TRANSIENT);
        }
        sqlite3_bind_int(st, 6, limit + 1);
    }
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        struct json_object *event;
        const char *evidence_s;
        struct json_object *evidence;
        if (paged && count == limit) {
            has_more = 1;
            break;
        }
        event = json_object_new_object();
        evidence_s = (const char *)sqlite3_column_text(st, 21);
        evidence = evidence_s ? json_tokener_parse(evidence_s) : NULL;
        json_object_object_add(event, "event_id", json_object_new_string(obs_str((const char *)sqlite3_column_text(st, 0))));
        json_object_object_add(event, "schema_version", json_object_new_int(sqlite3_column_int(st, 1)));
        json_object_object_add(event, "event_type", json_object_new_string(obs_str((const char *)sqlite3_column_text(st, 2))));
        json_object_object_add(event, "category", json_object_new_string(obs_str((const char *)sqlite3_column_text(st, 3))));
        json_object_object_add(event, "state", json_object_new_string(obs_str((const char *)sqlite3_column_text(st, 4))));
        json_object_object_add(event, "severity", json_object_new_string(obs_str((const char *)sqlite3_column_text(st, 5))));
        json_object_object_add(event, "confidence", json_object_new_string(obs_str((const char *)sqlite3_column_text(st, 6))));
        json_object_object_add(event, "observed_at", json_object_new_int64(sqlite3_column_int64(st, 7)));
        json_object_object_add(event, "first_seen", json_object_new_int64(sqlite3_column_int64(st, 8)));
        json_object_object_add(event, "last_seen", json_object_new_int64(sqlite3_column_int64(st, 9)));
        json_object_object_add(event, "duration_ms", json_object_new_int64(sqlite3_column_int64(st, 10)));
        json_object_object_add(event, "count", json_object_new_int(sqlite3_column_int(st, 11)));
        json_object_object_add(event, "source", json_object_new_string(obs_str((const char *)sqlite3_column_text(st, 12))));
        json_object_object_add(event, "site_id", json_object_new_string(obs_str((const char *)sqlite3_column_text(st, 13))));
        json_object_object_add(event, "device_id", json_object_new_string(obs_str((const char *)sqlite3_column_text(st, 14))));
        json_object_object_add(event, "port_id", json_object_new_string(obs_str((const char *)sqlite3_column_text(st, 15))));
        if (sqlite3_column_type(st, 16) == SQLITE_NULL) json_object_object_add(event, "client_id", json_object_new_null());
        else json_object_object_add(event, "client_id", json_object_new_string((const char *)sqlite3_column_text(st, 16)));
        if (sqlite3_column_type(st, 17) == SQLITE_NULL) json_object_object_add(event, "radio_id", json_object_new_null());
        else json_object_object_add(event, "radio_id", json_object_new_string((const char *)sqlite3_column_text(st, 17)));
        json_object_object_add(event, "correlation_id", json_object_new_string(obs_str((const char *)sqlite3_column_text(st, 18))));
        json_object_object_add(event, "before_digest", json_object_new_string(obs_str((const char *)sqlite3_column_text(st, 19))));
        json_object_object_add(event, "after_digest", json_object_new_string(obs_str((const char *)sqlite3_column_text(st, 20))));
        json_object_object_add(event, "evidence", evidence ? evidence : json_object_new_object());
        json_object_object_add(event, "coalesced_count", json_object_new_int(sqlite3_column_int(st, 22)));
        json_object_object_add(event, "display_suppressed", json_object_new_boolean(sqlite3_column_int(st, 23)));
        json_object_object_add(event, "retention_class", json_object_new_string(obs_str((const char *)sqlite3_column_text(st, 24))));
        json_object_object_add(event, "detector_revision", json_object_new_string(obs_str((const char *)sqlite3_column_text(st, 25))));
        json_object_array_add(events, event);
        count++;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE && !has_more) {
        obs_projection_meta(root, 0, 1, 1, "event_query_failed",
                            "structured_events", now, profile->name);
        json_object_put(events);
        return root;
    }
    obs_projection_meta(root, 1, 1, 0,
                        paged && !count ? (end_ms < now - profile->age_ms ?
                            "outside_retention" : "no_samples") : "",
                        "structured_events", now,
                        profile->name);
    json_object_object_add(root, "retention_ms", json_object_new_int64(profile->age_ms));
    json_object_object_add(root, "retention_version", json_object_new_int(profile->version));
    json_object_object_add(root, "retention_configured",
                           json_object_new_boolean(profile->configured));
    json_object_object_add(root, "start", json_object_new_int64(start_ms));
    json_object_object_add(root, "end", json_object_new_int64(end_ms));
    json_object_object_add(root, "event_count", json_object_new_int64(count));
    json_object_object_add(root, "events", events);
    if (paged) {
        struct json_object *cursor = NULL;
        if (has_more && count) {
            struct json_object *last = json_object_array_get_idx(events, count - 1);
            cursor = json_object_new_object();
            json_object_object_add(cursor, "first_seen", json_object_get(
                json_object_object_get(last, "first_seen")));
            json_object_object_add(cursor, "event_id", json_object_get(
                json_object_object_get(last, "event_id")));
        }
        json_object_object_add(root, "limit", json_object_new_int(limit));
        json_object_object_add(root, "has_more", json_object_new_boolean(has_more));
        json_object_object_add(root, "next_cursor", cursor);
    }
    return root;
}

struct json_object *jmx_obs_event_timeline(sqlite3 *db, int64_t start_ms,
                         int64_t end_ms, const char *entity_type,
                         const char *entity_id,
                         const struct jmx_obs_retention_profile *profile)
{
    return obs_event_timeline_query(db, start_ms, end_ms, entity_type, entity_id,
                                    profile, 0, 0, 0, NULL);
}

struct json_object *jmx_obs_event_timeline_page(sqlite3 *db, int64_t start_ms,
                         int64_t end_ms, const char *entity_type,
                         const char *entity_id,
                         const struct jmx_obs_retention_profile *profile,
                         int limit, int64_t cursor_first_seen,
                         const char *cursor_event_id)
{
    return obs_event_timeline_query(db, start_ms, end_ms, entity_type, entity_id,
                                    profile, 1, limit, cursor_first_seen, cursor_event_id);
}

static const char *obs_category_name(enum jmx_obs_category category)
{
    static const char *const names[JMX_OBS_CATEGORY_COUNT] = {
        "CABLE_POWER", "LOOP_BROADCAST_FLOOD", "MULTICAST_DISCOVERY",
        "TRAFFIC_PATH_HEALTH"
    };
    return category >= 0 && category < JMX_OBS_CATEGORY_COUNT ? names[category] : "UNKNOWN";
}

static double obs_clamp(double value, double low, double high)
{
    if (value < low) return low;
    if (value > high) return high;
    return value;
}

struct json_object *jmx_obs_port_anomaly_score(const struct jmx_obs_port_input *input)
{
    struct json_object *root = json_object_new_object();
    struct json_object *categories = json_object_new_object();
    struct json_object *items = json_object_new_array();
    struct json_object *category_items[JMX_OBS_CATEGORY_COUNT] = {0};
    double category_scores[JMX_OBS_CATEGORY_COUNT] = {0};
    size_t i;
    double total = 0;
    int complete;

    if (!input) {
        json_object_object_add(root, "ok", json_object_new_boolean(0));
        obs_projection_meta(root, 0, 0, 1, "input_missing",
                            "structured_port_producer", obs_now_ms(),
                            "anomaly_90d");
        json_object_object_add(root, "score", json_object_new_null());
        json_object_object_add(root, "status", json_object_new_string("UNKNOWN"));
        return root;
    }
    complete = input->identity_stable && input->producer_complete;
    json_object_object_add(root, "ok", json_object_new_boolean(complete));
    json_object_object_add(root, "available", json_object_new_boolean(complete));
    json_object_object_add(root, "supported", json_object_new_boolean(complete));
    json_object_object_add(root, "degraded", json_object_new_boolean(!complete));
    json_object_object_add(root, "reason", json_object_new_string(complete ? "" :
                           obs_str(input->unsupported_reason)[0] ? input->unsupported_reason :
                           "port_identity_or_producer_incomplete"));
    json_object_object_add(root, "window_start", json_object_new_int64(input->window_start));
    json_object_object_add(root, "window_end", json_object_new_int64(input->window_end));
    json_object_object_add(root, "sample_source", json_object_new_string(obs_str(input->sample_source)));
    json_object_object_add(root, "source", json_object_new_string(
        obs_str(input->sample_source)[0] ? input->sample_source :
        "structured_port_producer"));
    json_object_object_add(root, "observed_at", json_object_new_int64(obs_now_ms()));
    json_object_object_add(root, "retention_profile", json_object_new_string("anomaly_90d"));
    json_object_object_add(root, "scoring_profile", json_object_new_string(JMX_OBS_SCORING_PROFILE));
    json_object_object_add(root, "scoring_profile_version", json_object_new_int(JMX_OBS_SCHEMA_VERSION));
    json_object_object_add(root, "critical_threshold", json_object_new_int(50));
    if (input->device_id || input->port_id) {
        struct json_object *port = json_object_new_object();
        json_object_object_add(port, "device_id", json_object_new_string(obs_str(input->device_id)));
        json_object_object_add(port, "port_id", json_object_new_string(obs_str(input->port_id)));
        json_object_object_add(port, "identity_confidence", json_object_new_string(input->identity_stable ? "measured" : "unknown"));
        json_object_object_add(root, "port", port);
    }
    if (complete) {
        for (i = 0; i < JMX_OBS_CATEGORY_COUNT; i++)
            category_items[i] = json_object_new_array();
        for (i = 0; i < input->detector_count; i++) {
            const struct jmx_obs_detector *det = &input->detectors[i];
            double contribution = obs_clamp(det->weight, 0, 100) *
                obs_clamp(det->severity_factor, 0, 1) *
                obs_clamp(det->recurrence_factor > 0 ? det->recurrence_factor : 1, 0, 1);
            struct json_object *item = json_object_new_object();
            if (det->category < 0 || det->category >= JMX_OBS_CATEGORY_COUNT) {
                json_object_put(item);
                continue;
            }
            category_scores[det->category] = obs_clamp(category_scores[det->category] + contribution, 0, 100);
            json_object_object_add(item, "event_code", json_object_new_string(obs_str(det->event_code)));
            json_object_object_add(item, "alert_event", json_object_new_string(obs_str(det->event_code)));
            json_object_object_add(item, "anomaly_category", json_object_new_string(obs_category_name(det->category)));
            json_object_object_add(item, "weight", json_object_new_double(det->weight));
            json_object_object_add(item, "contribution", json_object_new_double(contribution));
            json_object_object_add(item, "first_seen", json_object_new_int64(det->first_seen));
            json_object_object_add(item, "last_seen", json_object_new_int64(det->last_seen));
            json_object_object_add(item, "count", json_object_new_int(det->count > 0 ? det->count : 1));
            json_object_object_add(item, "duration_ms", json_object_new_int64(det->duration_ms));
            json_object_object_add(item, "evidence", obs_redact_copy(det->evidence, NULL));
            json_object_array_add(items, item);
            json_object_array_add(category_items[det->category], json_object_get(item));
        }
    }
    for (i = 0; i < JMX_OBS_CATEGORY_COUNT; i++) {
        struct json_object *category = json_object_new_object();
        const char *status = !complete ? "UNKNOWN" :
                             category_scores[i] >= 50 ? "CRITICAL" :
                             category_scores[i] > 0 ? "DEGRADED" : "NONE";
        if (complete)
            json_object_object_add(category, "score", json_object_new_double(category_scores[i]));
        else
            json_object_object_add(category, "score", json_object_new_null());
        json_object_object_add(category, "status", json_object_new_string(status));
        json_object_object_add(category, "items", category_items[i] ? category_items[i] : json_object_new_array());
        json_object_object_add(categories, obs_category_name((enum jmx_obs_category)i), category);
        total += category_scores[i];
    }
    if (complete) {
        json_object_object_add(root, "score", json_object_new_double(obs_clamp(total, 0, 100)));
        json_object_object_add(root, "status", json_object_new_string(
            total >= 50 ? "CRITICAL" : total > 0 ? "DEGRADED" : "NONE"));
    } else {
        json_object_object_add(root, "score", json_object_new_null());
        json_object_object_add(root, "status", json_object_new_string("UNKNOWN"));
    }
    json_object_object_add(root, "categories", categories);
    json_object_object_add(root, "items", items);
    {
        struct json_object *caps = json_object_new_object();
        struct json_object *missing = json_object_new_array();
        json_object_object_add(caps, "complete", json_object_new_boolean(complete));
        if (!input->identity_stable)
            json_object_array_add(missing, json_object_new_string("stable_port_identity"));
        if (!input->producer_complete)
            json_object_array_add(missing, json_object_new_string("structured_port_producer"));
        json_object_object_add(caps, "missing", missing);
        json_object_object_add(root, "capabilities", caps);
    }
    return root;
}

/*
 * Autonomous port-anomaly producer.
 *
 * The scorer above is a pure function of a detector array; nothing today feeds
 * it real detectors, so every live query fails closed to UNKNOWN. This half
 * samples the sysfs-backed counters into a durable table and, at read time,
 * turns the recent samples into detectors for the families the hardware
 * actually exposes. Everything the hardware does NOT expose (PoE/SFP, L2
 * broadcast-storm counters, a defensible multicast-storm baseline) is reported
 * unsupported and never scored as a healthy zero.
 */

#define OBS_PORT_SAMPLE_MAX_AGE_MS   (24LL * 60LL * 60LL * 1000LL)
#define OBS_PORT_SAMPLE_ROW_CAP      512   /* per port_key */
#define OBS_PORT_SCORE_WINDOW_MS     (60LL * 60LL * 1000LL)
#define OBS_PORT_SCORE_MAX_SAMPLES   256
#define OBS_PORT_DETECTOR_REVISION   "port-anomaly-v1"
#define OBS_PORT_RETENTION_CLASS     "port_anomaly_90d"

/* Rate at which a supported error/drop detector reaches full weight (100).
 * Below the floor the detector does not fire (checked, no anomaly). */
#define OBS_PORT_RATE_FLOOR          0.0005   /* 0.05% */
#define OBS_PORT_RATE_CRITICAL       0.02     /* 2% -> weight 100 */
/*
 * Minimum forwarded-packet volume over the window before an error/drop RATE is
 * meaningful. A near-idle or down port that forwards almost nothing yet logs a
 * handful of drops would otherwise saturate a small-denominator ratio to 100%
 * and go CRITICAL on trivial absolute volume (the §6.4 artifact: never treat a
 * raw pps/byte handful as an anomaly). 1000 packets is a deliberately modest
 * floor: any genuinely active uplink clears it within one 60s sample interval
 * (a 10 Mbit link does ~1000 min-size pkts in well under a second), while a
 * down/idle port stays below it and is reported "insufficient traffic to
 * assess" (detector absent/unknown), never a healthy zero and never red.
 */
#define OBS_PORT_MIN_PACKETS_FOR_RATE 1000LL
#define OBS_PORT_FLAP_SATURATION     6.0      /* flaps for recurrence 1.0 */
#define OBS_PORT_FLAP_MIN_RECURRENCE 0.25
#define OBS_PORT_FLAP_WEIGHT         60.0
#define OBS_PORT_SPEED_WEIGHT        45.0

int jmx_obs_port_sample_store_init(sqlite3 *db)
{
    static const char *schema =
        "CREATE TABLE IF NOT EXISTS port_anomaly_samples("
        "id INTEGER PRIMARY KEY, port_key TEXT NOT NULL, ifname TEXT NOT NULL DEFAULT '',"
        "sample_ms INTEGER NOT NULL,"
        "rx_errors INTEGER NOT NULL DEFAULT -1, tx_errors INTEGER NOT NULL DEFAULT -1,"
        "rx_dropped INTEGER NOT NULL DEFAULT -1, tx_dropped INTEGER NOT NULL DEFAULT -1,"
        "rx_packets INTEGER NOT NULL DEFAULT -1, tx_packets INTEGER NOT NULL DEFAULT -1,"
        "rx_multicast INTEGER NOT NULL DEFAULT -1, speed_mbps INTEGER NOT NULL DEFAULT -1,"
        "carrier INTEGER NOT NULL DEFAULT -1, phys_port_id TEXT NOT NULL DEFAULT '');"
        "CREATE INDEX IF NOT EXISTS idx_port_anomaly_key_time"
        " ON port_anomaly_samples(port_key,sample_ms);"
        "CREATE INDEX IF NOT EXISTS idx_port_anomaly_ifname"
        " ON port_anomaly_samples(ifname);";
    char *err = NULL;
    int rc;

    if (!db)
        return -1;
    if (sqlite3_get_autocommit(db) &&
        sqlite3_exec(db, "PRAGMA journal_mode=WAL", NULL, NULL, &err) != SQLITE_OK) {
        sqlite3_free(err);
        err = NULL;
    }
    rc = sqlite3_exec(db, schema, NULL, NULL, &err);
    sqlite3_free(err);
    return rc == SQLITE_OK ? 0 : -1;
}

static void obs_port_sample_prune(sqlite3 *db, const char *port_key, int64_t now_ms)
{
    sqlite3_stmt *st = NULL;

    if (!db || !port_key || !port_key[0])
        return;
    if (sqlite3_prepare_v2(db,
        "DELETE FROM port_anomaly_samples WHERE port_key=?1 AND sample_ms < ?2",
        -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, port_key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, now_ms - OBS_PORT_SAMPLE_MAX_AGE_MS);
        sqlite3_step(st);
    }
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(db,
        "DELETE FROM port_anomaly_samples WHERE port_key=?1 AND id NOT IN "
        "(SELECT id FROM port_anomaly_samples WHERE port_key=?1 "
        "ORDER BY sample_ms DESC,id DESC LIMIT ?2)",
        -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, port_key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, OBS_PORT_SAMPLE_ROW_CAP);
        sqlite3_step(st);
    }
    sqlite3_finalize(st);
}

int jmx_obs_port_sample_append(sqlite3 *db,
                               const struct jmx_obs_port_reading *reading,
                               int64_t now_ms)
{
    sqlite3_stmt *st = NULL;
    int rc;

    if (!db || !reading || !reading->port_key || !reading->port_key[0])
        return -1;
    if (jmx_obs_port_sample_store_init(db) != 0)
        return -1;
    if (now_ms <= 0)
        now_ms = obs_now_ms();
    rc = sqlite3_prepare_v2(db,
        "INSERT INTO port_anomaly_samples(port_key,ifname,sample_ms,rx_errors,tx_errors,"
        "rx_dropped,tx_dropped,rx_packets,tx_packets,rx_multicast,speed_mbps,carrier,phys_port_id) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)", -1, &st, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_bind_text(st, 1, reading->port_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, obs_str(reading->ifname), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, now_ms);
    sqlite3_bind_int64(st, 4, reading->rx_errors);
    sqlite3_bind_int64(st, 5, reading->tx_errors);
    sqlite3_bind_int64(st, 6, reading->rx_dropped);
    sqlite3_bind_int64(st, 7, reading->tx_dropped);
    sqlite3_bind_int64(st, 8, reading->rx_packets);
    sqlite3_bind_int64(st, 9, reading->tx_packets);
    sqlite3_bind_int64(st, 10, reading->rx_multicast);
    sqlite3_bind_int(st, 11, reading->speed_mbps);
    sqlite3_bind_int(st, 12, reading->carrier);
    sqlite3_bind_text(st, 13, obs_str(reading->phys_port_id), -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return -1;
    obs_port_sample_prune(db, reading->port_key, now_ms);
    return 0;
}

/* One decoded sample row, loaded oldest-first for delta arithmetic. */
struct obs_port_row {
    int64_t sample_ms;
    int64_t rx_errors, tx_errors, rx_dropped, tx_dropped;
    int64_t rx_packets, tx_packets, rx_multicast;
    int speed_mbps;
    int carrier;
    char phys_port_id[128];
    char port_key[288];
};

/*
 * Identity tiers for a stored port_key. Only a hardware-position tier
 * (physid: or physname:) is stable enough to score; a MAC- or ifname-only key
 * belongs to an uplink/CPU port with no switch-port label and stays UNKNOWN.
 */
enum obs_port_identity_tier {
    OBS_PORT_IDENTITY_NONE = 0,   /* mac: / if: / empty -> not stable */
    OBS_PORT_IDENTITY_INFERRED,   /* physname: (DSA port label, e.g. p0) */
    OBS_PORT_IDENTITY_MEASURED    /* physid: (driver-reported phys_port_id) */
};

static enum obs_port_identity_tier obs_port_key_tier(const char *port_key)
{
    if (!port_key)
        return OBS_PORT_IDENTITY_NONE;
    if (!strncmp(port_key, "physid:", 7))
        return OBS_PORT_IDENTITY_MEASURED;
    if (!strncmp(port_key, "physname:", 9))
        return OBS_PORT_IDENTITY_INFERRED;
    return OBS_PORT_IDENTITY_NONE;
}

/* Maps an anomaly rate (fraction) onto a bounded [floor..100] weight. Below the
 * floor the caller does not fire the detector at all. */
static double obs_port_rate_weight(double rate)
{
    double w;

    if (rate < OBS_PORT_RATE_FLOOR)
        return 0;
    w = (rate / OBS_PORT_RATE_CRITICAL) * 100.0;
    return obs_clamp(w, 10.0, 100.0);
}

/*
 * Builds one error/drop detector from a monotonic counter pair over the window.
 * Returns 1 and fills det and evidence_out when the detector fires, 0 when the
 * counter is supported but shows no anomaly, and -1 when the counter is
 * unsupported or reset/rolled-back (so the caller records it as unknown, never
 * as a healthy zero).
 */
static int obs_port_rate_detector(const char *event_code,
                                  enum jmx_obs_category category,
                                  int64_t first_err, int64_t last_err,
                                  int64_t first_pkt, int64_t last_pkt,
                                  int64_t first_seen, int64_t last_seen,
                                  struct jmx_obs_detector *det,
                                  struct json_object **evidence_out)
{
    int64_t err_delta, pkt_delta;
    double rate;
    struct json_object *evidence;

    *evidence_out = NULL;
    /* -1 means the kernel never reported the counter for this port. */
    if (first_err < 0 || last_err < 0 || first_pkt < 0 || last_pkt < 0)
        return -1;
    err_delta = last_err - first_err;
    pkt_delta = last_pkt - first_pkt;
    /* A cumulative counter that went backwards is a reset/rollback: the delta
     * is meaningless, so this detector is unknown, not zero. */
    if (err_delta < 0 || pkt_delta < 0)
        return -1;
    /* Small-denominator guard (§6.4): require a minimum absolute forwarded
     * packet volume before a rate is assessable. A down/idle port with zero
     * (or a trivial handful of) forwarded packets but a few drops must NOT go
     * red -- its rate is not meaningful. Below the floor the detector is
     * unknown (absent from items), never a healthy zero and never CRITICAL.
     * The denominator is the forwarded-packet delta ONLY, so pkt_delta<=0 can
     * never yield a positive rate. */
    if (pkt_delta < OBS_PORT_MIN_PACKETS_FOR_RATE)
        return -1;
    rate = (double)err_delta / (double)pkt_delta;
    if (rate < OBS_PORT_RATE_FLOOR)
        return 0;   /* enough traffic, below the floor -> checked, healthy */

    evidence = json_object_new_object();
    json_object_object_add(evidence, "error_delta", json_object_new_int64(err_delta));
    json_object_object_add(evidence, "packet_delta", json_object_new_int64(pkt_delta));
    json_object_object_add(evidence, "rate", json_object_new_double(rate));
    json_object_object_add(evidence, "rate_basis", json_object_new_string("delta_over_forwarded_packets"));
    json_object_object_add(evidence, "min_packets_for_rate",
                           json_object_new_int64(OBS_PORT_MIN_PACKETS_FOR_RATE));
    json_object_object_add(evidence, "rate_floor", json_object_new_double(OBS_PORT_RATE_FLOOR));
    json_object_object_add(evidence, "rate_critical", json_object_new_double(OBS_PORT_RATE_CRITICAL));

    memset(det, 0, sizeof(*det));
    det->event_code = event_code;
    det->category = category;
    det->weight = obs_port_rate_weight(rate);
    det->severity_factor = 1.0;
    det->recurrence_factor = 1.0;
    det->first_seen = first_seen;
    det->last_seen = last_seen;
    det->count = 1;
    det->duration_ms = last_seen - first_seen;
    det->evidence = evidence;
    *evidence_out = evidence;
    return 1;
}

/*
 * Rewrites the category entry produced by the scorer for a family the hardware
 * cannot support: score -> null, status -> "UNSUPPORTED", with the reason. This
 * is what stops a category no sysfs counter can drive from rendering as a
 * healthy zero once identity/producer are otherwise complete.
 */
static void obs_port_mark_category_unsupported(struct json_object *categories,
                                               const char *name,
                                               const char *reason)
{
    struct json_object *cat = NULL;

    if (!categories || !json_object_object_get_ex(categories, name, &cat) || !cat)
        return;
    json_object_object_add(cat, "score", json_object_new_null());
    json_object_object_add(cat, "status", json_object_new_string("UNSUPPORTED"));
    json_object_object_add(cat, "supported", json_object_new_boolean(0));
    json_object_object_add(cat, "reason", json_object_new_string(obs_str(reason)));
}

static void obs_port_bridge_event(sqlite3 *db, const char *device_id,
                                  const char *port_id, const char *category,
                                  const char *status, double score,
                                  int64_t first_seen, int64_t last_seen,
                                  struct json_object *category_node)
{
    struct jmx_obs_event event;
    struct json_object *evidence;
    struct json_object *items = NULL;
    char event_type[64];

    if (!db || !category || !status)
        return;
    if (strcmp(status, "DEGRADED") && strcmp(status, "CRITICAL"))
        return;

    evidence = json_object_new_object();
    json_object_object_add(evidence, "category", json_object_new_string(category));
    json_object_object_add(evidence, "score", json_object_new_double(score));
    json_object_object_add(evidence, "scoring_profile",
                           json_object_new_string(JMX_OBS_SCORING_PROFILE));
    if (category_node &&
        json_object_object_get_ex(category_node, "items", &items) && items)
        json_object_object_add(evidence, "detectors", json_object_get(items));

    snprintf(event_type, sizeof(event_type), "PORT_ANOMALY_%s", category);
    memset(&event, 0, sizeof(event));
    event.event_type = event_type;
    event.category = category;
    event.state = "active";
    event.severity = !strcmp(status, "CRITICAL") ? "critical" : "warning";
    event.confidence = "measured";
    event.observed_at = last_seen;
    event.first_seen = first_seen;
    event.last_seen = last_seen;
    event.duration_ms = last_seen - first_seen;
    event.count = 1;
    event.source = "jmx_obs_port_anomaly_producer";
    event.device_id = obs_str(device_id);
    event.port_id = obs_str(port_id);
    event.evidence = evidence;
    event.retention_class = OBS_PORT_RETENTION_CLASS;
    event.detector_revision = OBS_PORT_DETECTOR_REVISION;
    (void)jmx_obs_event_append(db, &event, NULL);
    json_object_put(evidence);
}

struct json_object *jmx_obs_port_anomaly_producer_score(sqlite3 *db,
                               const char *device_id, const char *port_id,
                               int64_t now_ms)
{
    struct obs_port_row *rows = NULL;
    size_t row_count = 0, row_cap = 0;
    sqlite3_stmt *st = NULL;
    struct jmx_obs_port_input input;
    struct jmx_obs_detector detectors[8];
    struct json_object *evidence_owned[8] = {0};
    size_t detector_count = 0, i;
    struct json_object *result;
    struct json_object *categories = NULL;
    int identity_stable = 0, producer_complete = 0;
    int key_consistent = 1;
    const char *key_ref = NULL;
    enum obs_port_identity_tier identity_tier = OBS_PORT_IDENTITY_NONE;
    int64_t window_start, first_seen = 0, last_seen = 0;
    int flap_count = 0, last_carrier = -1;
    const char *unsupported_reason = "";

    if (now_ms <= 0)
        now_ms = obs_now_ms();
    window_start = now_ms - OBS_PORT_SCORE_WINDOW_MS;

    memset(&input, 0, sizeof(input));
    input.device_id = obs_str(device_id);
    input.port_id = obs_str(port_id);
    input.window_start = window_start;
    input.window_end = now_ms;
    input.sample_source = "structured_port_producer";

    if (!db || jmx_obs_port_sample_store_init(db) != 0) {
        input.unsupported_reason = "port_sample_store_unavailable";
        result = jmx_obs_port_anomaly_score(&input);
        goto annotate;
    }

    /* Match the requested identity against any stored identity token: the read
     * path forwards whatever the UI holds (usually the ifname), while the
     * sampler keys on the highest-confidence port identity available (a
     * phys_port_id, else a DSA phys_port_name). */
    if (sqlite3_prepare_v2(db,
        "SELECT sample_ms,rx_errors,tx_errors,rx_dropped,tx_dropped,rx_packets,"
        "tx_packets,rx_multicast,speed_mbps,carrier,phys_port_id,port_key "
        "FROM port_anomaly_samples "
        "WHERE (port_key=?1 OR ifname=?1 OR phys_port_id=?1) AND sample_ms>=?2 "
        "ORDER BY sample_ms ASC,id ASC LIMIT ?3", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, obs_str(port_id), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, window_start);
        sqlite3_bind_int(st, 3, OBS_PORT_SCORE_MAX_SAMPLES);
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct obs_port_row *r;
            const char *phys;
            if (row_count == row_cap) {
                size_t next = row_cap ? row_cap * 2 : 16;
                struct obs_port_row *grown = realloc(rows, next * sizeof(*rows));
                if (!grown)
                    break;
                rows = grown;
                row_cap = next;
            }
            r = &rows[row_count++];
            memset(r, 0, sizeof(*r));
            r->sample_ms = sqlite3_column_int64(st, 0);
            r->rx_errors = sqlite3_column_int64(st, 1);
            r->tx_errors = sqlite3_column_int64(st, 2);
            r->rx_dropped = sqlite3_column_int64(st, 3);
            r->tx_dropped = sqlite3_column_int64(st, 4);
            r->rx_packets = sqlite3_column_int64(st, 5);
            r->tx_packets = sqlite3_column_int64(st, 6);
            r->rx_multicast = sqlite3_column_int64(st, 7);
            r->speed_mbps = sqlite3_column_int(st, 8);
            r->carrier = sqlite3_column_int(st, 9);
            phys = (const char *)sqlite3_column_text(st, 10);
            snprintf(r->phys_port_id, sizeof(r->phys_port_id), "%s", phys ? phys : "");
            {
                const char *pk = (const char *)sqlite3_column_text(st, 11);
                snprintf(r->port_key, sizeof(r->port_key), "%s", pk ? pk : "");
            }
        }
    }
    sqlite3_finalize(st);

    /* Identity: every loaded sample must share ONE consistent port_key, and
     * that key must be a hardware-position tier (physid: from a driver, or
     * physname: from a DSA switch-port label). A mac:/if:-only key belongs to
     * an uplink or CPU port with no port label and is not stable enough, so it
     * fails closed to UNKNOWN. Real lab hardware (BPI-R4 DSA switch) exposes no
     * phys_port_id at all but stable phys_port_name p0..p3, so gating on
     * phys_port_id alone would make the producer inert. */
    for (i = 0; i < row_count; i++) {
        if (!key_ref)
            key_ref = rows[i].port_key;
        else if (strcmp(key_ref, rows[i].port_key) != 0) {
            key_consistent = 0;
            break;
        }
    }
    identity_tier = (row_count > 0 && key_consistent) ?
        obs_port_key_tier(key_ref) : OBS_PORT_IDENTITY_NONE;
    identity_stable = identity_tier != OBS_PORT_IDENTITY_NONE;
    producer_complete = row_count >= 2;
    if (!identity_stable)
        unsupported_reason = "port_stable_identity_absent_or_unstable";
    else if (!producer_complete)
        unsupported_reason = row_count == 0 ?
            "no_port_samples_in_window" : "cold_start_insufficient_samples";

    if (identity_stable && producer_complete) {
        const struct obs_port_row *first = &rows[0];
        const struct obs_port_row *last = &rows[row_count - 1];
        int fired;

        first_seen = first->sample_ms;
        last_seen = last->sample_ms;

        /* LINK_FLAP: carrier transitions across consecutive samples, with a
         * one-step hysteresis (unknown carrier readings do not count). */
        for (i = 0; i < row_count; i++) {
            int c = rows[i].carrier;
            if (c != 0 && c != 1)
                continue;               /* unknown -> ignored, no phantom flap */
            if (last_carrier >= 0 && c != last_carrier)
                flap_count++;
            last_carrier = c;
        }

        /* TRAFFIC_PATH_HEALTH: RX/TX error and drop rates. */
        fired = obs_port_rate_detector("PORT_RX_ERRORS", JMX_OBS_TRAFFIC_PATH_HEALTH,
                                       first->rx_errors, last->rx_errors,
                                       first->rx_packets, last->rx_packets,
                                       first_seen, last_seen,
                                       &detectors[detector_count],
                                       &evidence_owned[detector_count]);
        if (fired == 1)
            detector_count++;
        fired = obs_port_rate_detector("PORT_TX_ERRORS", JMX_OBS_TRAFFIC_PATH_HEALTH,
                                       first->tx_errors, last->tx_errors,
                                       first->tx_packets, last->tx_packets,
                                       first_seen, last_seen,
                                       &detectors[detector_count],
                                       &evidence_owned[detector_count]);
        if (fired == 1)
            detector_count++;
        {
            int64_t fdrop = -1, ldrop = -1;
            if (first->rx_dropped >= 0 && first->tx_dropped >= 0)
                fdrop = first->rx_dropped + first->tx_dropped;
            if (last->rx_dropped >= 0 && last->tx_dropped >= 0)
                ldrop = last->rx_dropped + last->tx_dropped;
            {
                int64_t fpkt = (first->rx_packets >= 0 && first->tx_packets >= 0) ?
                    first->rx_packets + first->tx_packets : -1;
                int64_t lpkt = (last->rx_packets >= 0 && last->tx_packets >= 0) ?
                    last->rx_packets + last->tx_packets : -1;
                fired = obs_port_rate_detector("PORT_DROPPED_TRAFFIC",
                                               JMX_OBS_TRAFFIC_PATH_HEALTH,
                                               fdrop, ldrop, fpkt, lpkt,
                                               first_seen, last_seen,
                                               &detectors[detector_count],
                                               &evidence_owned[detector_count]);
                if (fired == 1)
                    detector_count++;
            }
        }

        /* LOW_UPLINK_SPEED: only a genuine downgrade against a previously
         * observed higher speed is defensible; no universal absolute baseline
         * exists, so we do not invent one. */
        {
            int max_speed = 0;
            for (i = 0; i < row_count; i++)
                if (rows[i].speed_mbps > max_speed)
                    max_speed = rows[i].speed_mbps;
            if (last->speed_mbps > 0 && max_speed > 0 && last->speed_mbps < max_speed) {
                struct json_object *evidence = json_object_new_object();
                double ratio = (double)last->speed_mbps / (double)max_speed;
                json_object_object_add(evidence, "current_mbps",
                                       json_object_new_int(last->speed_mbps));
                json_object_object_add(evidence, "observed_peak_mbps",
                                       json_object_new_int(max_speed));
                memset(&detectors[detector_count], 0, sizeof(detectors[0]));
                detectors[detector_count].event_code = "PORT_LOW_UPLINK_SPEED";
                detectors[detector_count].category = JMX_OBS_TRAFFIC_PATH_HEALTH;
                detectors[detector_count].weight = OBS_PORT_SPEED_WEIGHT;
                detectors[detector_count].severity_factor =
                    obs_clamp(1.0 - ratio, 0.0, 1.0);
                detectors[detector_count].recurrence_factor = 1.0;
                detectors[detector_count].first_seen = first_seen;
                detectors[detector_count].last_seen = last_seen;
                detectors[detector_count].count = 1;
                detectors[detector_count].evidence = evidence;
                evidence_owned[detector_count] = evidence;
                detector_count++;
            }
        }

        if (flap_count > 0) {
            struct json_object *evidence = json_object_new_object();
            double recurrence = obs_clamp((double)flap_count / OBS_PORT_FLAP_SATURATION,
                                          OBS_PORT_FLAP_MIN_RECURRENCE, 1.0);
            json_object_object_add(evidence, "flap_count", json_object_new_int(flap_count));
            json_object_object_add(evidence, "samples", json_object_new_int((int)row_count));
            json_object_object_add(evidence, "saturation",
                                   json_object_new_double(OBS_PORT_FLAP_SATURATION));
            memset(&detectors[detector_count], 0, sizeof(detectors[0]));
            detectors[detector_count].event_code = "PORT_LINK_FLAP";
            detectors[detector_count].category = JMX_OBS_LOOP_BROADCAST_FLOOD;
            detectors[detector_count].weight = OBS_PORT_FLAP_WEIGHT;
            detectors[detector_count].severity_factor = 1.0;
            detectors[detector_count].recurrence_factor = recurrence;
            detectors[detector_count].first_seen = first_seen;
            detectors[detector_count].last_seen = last_seen;
            detectors[detector_count].count = flap_count;
            detectors[detector_count].duration_ms = last_seen - first_seen;
            detectors[detector_count].evidence = evidence;
            evidence_owned[detector_count] = evidence;
            detector_count++;
        }
    }

    input.identity_stable = identity_stable;
    input.producer_complete = producer_complete;
    input.unsupported_reason = unsupported_reason;
    input.detectors = detector_count ? detectors : NULL;
    input.detector_count = detector_count;
    result = jmx_obs_port_anomaly_score(&input);

annotate:
    /* Mark the families no sysfs counter can drive. This must happen even when
     * complete, so an unsupported category is never left rendering a healthy
     * zero score. */
    if (json_object_object_get_ex(result, "categories", &categories) && categories) {
        obs_port_mark_category_unsupported(categories, "CABLE_POWER",
            "no_poe_or_sfp_telemetry_on_this_hardware");
        obs_port_mark_category_unsupported(categories, "MULTICAST_DISCOVERY",
            "no_defensible_multicast_storm_baseline_from_rx_multicast_alone");
    }
    /* Grade identity confidence honestly: the scorer only sees a boolean, so a
     * physname:-tier (DSA port label) identity would otherwise read "measured".
     * A driver-reported phys_port_id is "measured"; a switch-port label is
     * "inferred". Set it on the response rather than widening the scorer API. */
    {
        struct json_object *port = NULL;
        if (json_object_object_get_ex(result, "port", &port) && port) {
            json_object_object_add(port, "identity_confidence",
                json_object_new_string(
                    identity_tier == OBS_PORT_IDENTITY_MEASURED ? "measured" :
                    identity_tier == OBS_PORT_IDENTITY_INFERRED ? "inferred" :
                    "unknown"));
            json_object_object_add(port, "identity_tier",
                json_object_new_string(
                    identity_tier == OBS_PORT_IDENTITY_MEASURED ? "phys_port_id" :
                    identity_tier == OBS_PORT_IDENTITY_INFERRED ? "phys_port_name" :
                    "none"));
            if (key_ref && key_ref[0])
                json_object_object_add(port, "port_key",
                                       json_object_new_string(key_ref));
        }
    }
    {
        struct json_object *caps = NULL, *missing = NULL, *unsupported = NULL;
        static const char *const families[] = {
            "CABLE_POWER", "BROADCAST_STORM", "MULTICAST_DISCOVERY"
        };
        size_t f;
        if (json_object_object_get_ex(result, "capabilities", &caps) && caps) {
            unsupported = json_object_new_array();
            if (!json_object_object_get_ex(caps, "missing", &missing) || !missing) {
                missing = json_object_new_array();
                json_object_object_add(caps, "missing", missing);
            }
            for (f = 0; f < sizeof(families) / sizeof(families[0]); f++) {
                json_object_array_add(missing, json_object_new_string(families[f]));
                json_object_array_add(unsupported, json_object_new_string(families[f]));
            }
            json_object_object_add(caps, "unsupported_families", unsupported);
            json_object_object_add(caps, "supported_families",
                                   json_object_new_string(
                "TRAFFIC_PATH_HEALTH(rx/tx errors,dropped,low_uplink_speed);"
                "LOOP_BROADCAST_FLOOD(link_flap)"));
        }
    }
    json_object_object_add(result, "sample_count", json_object_new_int((int)row_count));
    json_object_object_add(result, "detector_count", json_object_new_int((int)detector_count));
    json_object_object_add(result, "detector_revision",
                           json_object_new_string(OBS_PORT_DETECTOR_REVISION));

    /* Bridge scored categories onto the structured-event timeline (one raw
     * event per DEGRADED/CRITICAL category, coalesced by the deterministic
     * event id) so the score is also visible on the history surface. */
    if (identity_stable && producer_complete && categories) {
        json_object_object_foreach(categories, cat_name, cat_node) {
            const char *status = NULL;
            struct json_object *status_obj = NULL, *score_obj = NULL;
            if (json_object_object_get_ex(cat_node, "status", &status_obj))
                status = json_object_get_string(status_obj);
            if (!status)
                continue;
            (void)json_object_object_get_ex(cat_node, "score", &score_obj);
            obs_port_bridge_event(db, device_id, port_id, cat_name, status,
                                  score_obj ? json_object_get_double(score_obj) : 0,
                                  first_seen ? first_seen : now_ms,
                                  last_seen ? last_seen : now_ms, cat_node);
        }
    }

    for (i = 0; i < detector_count; i++)
        if (evidence_owned[i])
            json_object_put(evidence_owned[i]);
    free(rows);
    return result;
}

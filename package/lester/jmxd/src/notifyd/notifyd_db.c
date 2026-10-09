// SPDX-License-Identifier: GPL-2.0-or-later
#include "notifyd_internal.h"

#define WORKER_STATUS_VERSION "1.0"

static int notifyd_email_address_ok(const char *email);

static const char *notifyd_storage_path(void)
{
    /* A changed assignment does not move an already-open SQLite handle. */
    const char *path = g_notify_db ? sqlite3_db_filename(g_notify_db, "main") : NULL;

    return path && path[0] ? path : NOTIFYD_DB_PATH;
}

struct notifyd_route_contract {
    char channel_id[NOTIFYD_MAX_ID];
    char min_severity[32];
    struct json_object *options;
};

static int notifyd_global_mute_normalize(struct json_object *input,
                                         struct json_object **normalized_out,
                                         struct json_object **error_out);
static int notifyd_global_mute_active(const struct notifyd_settings *settings,
                                      int64_t now, const char **reason);

static struct json_object *notifyd_route_error(const char *error, const char *feature,
                                               const char *field, int action_index)
{
    struct json_object *resp = json_object_new_object();

    json_object_object_add(resp, "ok", json_object_new_boolean(0));
    json_object_object_add(resp, "error", json_object_new_string(error ? error : "invalid_route"));
    if (feature && feature[0])
        json_object_object_add(resp, "feature", json_object_new_string(feature));
    if (field && field[0])
        json_object_object_add(resp, "field", json_object_new_string(field));
    if (action_index >= 0)
        json_object_object_add(resp, "action_index", json_object_new_int(action_index));
    return resp;
}

static int notifyd_severity_valid(const char *severity)
{
    return severity && (!strcmp(severity, "debug") || !strcmp(severity, "info") ||
        !strcmp(severity, "notice") || !strcmp(severity, "warning") ||
        !strcmp(severity, "error") || !strcmp(severity, "critical"));
}

static int notifyd_route_email_ok(const char *email)
{
    return notifyd_email_address_ok(email);
}

static int notifyd_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc;

    if (!db || !sql)
        return -1;
    rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-notifyd] sqlite exec failed: %s sql=%s\n",
                err ? err : sqlite3_errmsg(db), sql);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

sqlite3_stmt *notifyd_prepare(const char *sql)
{
    sqlite3_stmt *st = NULL;

    if (!g_notify_db || !sql)
        return NULL;
    if (sqlite3_prepare_v2(g_notify_db, sql, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-notifyd] sqlite prepare failed: %s sql=%s\n",
                sqlite3_errmsg(g_notify_db), sql);
        return NULL;
    }
    return st;
}

sqlite3_stmt *notifyd_config_prepare(const char *sql)
{
    sqlite3_stmt *st = NULL;

    if (!g_notify_config_db || !sql)
        return NULL;
    if (sqlite3_prepare_v2(g_notify_config_db, sql, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-notifyd] config sqlite prepare failed: %s sql=%s\n",
                sqlite3_errmsg(g_notify_config_db), sql);
        return NULL;
    }
    return st;
}

static int notifyd_table_has_column(sqlite3 *db, const char *table, const char *column)
{
    sqlite3_stmt *st = NULL;
    char sql[160];
    int found = 0;

    if (!db || !table || !column)
        return 0;
    snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table);
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(st, 1);
        if (name && !strcmp(name, column)) {
            found = 1;
            break;
        }
    }
    sqlite3_finalize(st);
    return found;
}

static void notifyd_response_set_ok(struct json_object *resp, int ok)
{
    if (!resp)
        return;
    json_object_object_del(resp, "ok");
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
}

static void notifyd_response_set_first_error(struct json_object *resp, const char *error)
{
    struct json_object *existing = NULL;

    if (!resp || !error || !error[0])
        return;
    if (json_object_object_get_ex(resp, "error", &existing) && existing)
        return;
    json_object_object_add(resp, "error", json_object_new_string(error));
}

/* Catalog metadata, rendering keys, and recovery semantics come from the same
 * definition table linked into logd and notifyd. This prevents the two daemons
 * from accepting different event sets after an incremental update. */

static void notifyd_event_ids_json(struct json_object *cap)
{
    struct json_object *available = json_object_new_array();
    struct json_object *pending = json_object_new_array();
    size_t i;

    for (i = 0; i < dw_event_definitions_count; i++) {
        const struct dw_event_definition *def = &dw_event_definitions[i];
        json_object_array_add(def->available ? available : pending,
                              json_object_new_string(def->id));
    }
    json_object_object_add(cap, "event_ids", available);
    json_object_object_add(cap, "pending_event_ids", pending);
}

/*
 * Enqueue used to accept any "event" string, so a typo in a producer's event
 * constant produced ok:true, exit code 0, and a delivered notification carrying
 * an id nothing downstream recognises. The producer only ever sees the exit
 * code, so nothing along the chain could report the mistake.
 *
 * Lookup covers pending definitions too: an event whose producer is not wired
 * up yet is still a real catalog id, and rejecting it would turn "not collected
 * yet" into "rejected", which is a different and more confusing failure.
 */
static const struct dw_event_definition *notifyd_event_definition_find(const char *id)
{
    return dw_event_definition_find(id);
}

struct json_object *notifyd_event_catalog_json(void)
{
    static const struct { const char *id; const char *label; } categories[] = {
        { "SYSTEM", "System" },
        { "INTERNET_AND_WAN", "Internet and WAN" },
        { "CLIENT_DEVICES", "Client Devices" },
        { "DEVICES", "Infrastructure Devices" },
        { "ADMIN", "Admin" },
        { "SECURITY", "Security" },
        { "VPN", "VPN" },
        /* Owned by the out-of-tree dreamingproxy plugin, not by notifyd. */
        { "PROXY", "Proxy" },
    };
    struct json_object *resp = json_object_new_object();
    struct json_object *category_array = json_object_new_array();
    struct json_object *event_array = json_object_new_array();
    size_t i;

    for (i = 0; i < sizeof(categories) / sizeof(categories[0]); i++) {
        struct json_object *category = json_object_new_object();
        json_object_object_add(category, "id", json_object_new_string(categories[i].id));
        json_object_object_add(category, "label", json_object_new_string(categories[i].label));
        json_object_array_add(category_array, category);
    }
    for (i = 0; i < dw_event_definitions_count; i++) {
        const struct dw_event_definition *def = &dw_event_definitions[i];
        struct json_object *event = json_object_new_object();

        json_object_object_add(event, "id", json_object_new_string(def->id));
        json_object_object_add(event, "category", json_object_new_string(def->category));
        json_object_object_add(event, "label", json_object_new_string(def->label_en));
        json_object_object_add(event, "label_zh", json_object_new_string(def->label_zh));
        json_object_object_add(event, "message_key", json_object_new_string(def->message_key));
        json_object_object_add(event, "message_version", json_object_new_int((int)def->message_version));
        json_object_object_add(event, "available", json_object_new_boolean(def->available));
        json_object_object_add(event, "producer", json_object_new_string(def->producer));
        json_object_object_add(event, "recovery_event", json_object_new_string(def->recovery_event));
        json_object_object_add(event, "recovers_event", json_object_new_string(def->recovers_event));
        json_object_object_add(event, "severity_exempt", json_object_new_boolean(def->recovers_event[0] != 0));
        json_object_object_add(event, "default_severity", json_object_new_string(def->default_severity));
        if (def->unavailable_reason[0])
            json_object_object_add(event, "reason", json_object_new_string(def->unavailable_reason));
        json_object_array_add(event_array, event);
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "categories", category_array);
    json_object_object_add(resp, "events", event_array);
    json_object_object_add(resp, "source", json_object_new_string("dreamingwrt.notifyd.event_catalog"));
    json_object_object_add(resp, "generated_at", json_object_new_int64(notifyd_now_s()));
    return resp;
}

int notifyd_db_init(void)
{
    mkdir("/etc/dreamingwrt", 0755);
    if (sqlite3_open(NOTIFYD_DB_PATH, &g_notify_db) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-notifyd] open %s failed\n", NOTIFYD_DB_PATH);
        notifyd_db_close();
        return -1;
    }
    sqlite3_busy_timeout(g_notify_db, 3000);
    if (sqlite3_open(NOTIFYD_CONFIG_DB_PATH, &g_notify_config_db) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-notifyd] open %s failed\n", NOTIFYD_CONFIG_DB_PATH);
        notifyd_db_close();
        return -1;
    }
    sqlite3_busy_timeout(g_notify_config_db, 3000);

    if (notifyd_exec(g_notify_db, "PRAGMA journal_mode=WAL") != 0 ||
        notifyd_exec(g_notify_db, "PRAGMA foreign_keys=ON") != 0 ||
        notifyd_exec(g_notify_config_db, "PRAGMA journal_mode=WAL") != 0 ||
        notifyd_exec(g_notify_config_db, "PRAGMA foreign_keys=ON") != 0)
        goto fail;

    if (notifyd_exec(g_notify_config_db,
        "CREATE TABLE IF NOT EXISTS notifyd_settings ("
        " id INTEGER PRIMARY KEY CHECK(id=1),"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " default_channel_id TEXT NOT NULL DEFAULT 'local',"
        " max_attempts INTEGER NOT NULL DEFAULT 3,"
        " retry_base_s INTEGER NOT NULL DEFAULT 60,"
        " retry_max_s INTEGER NOT NULL DEFAULT 3600,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        goto fail;
    if (!notifyd_table_has_column(g_notify_config_db, "notifyd_settings", "smtp_host") &&
        notifyd_exec(g_notify_config_db, "ALTER TABLE notifyd_settings ADD COLUMN smtp_host TEXT NOT NULL DEFAULT ''") != 0) goto fail;
    if (!notifyd_table_has_column(g_notify_config_db, "notifyd_settings", "smtp_port") &&
        notifyd_exec(g_notify_config_db, "ALTER TABLE notifyd_settings ADD COLUMN smtp_port INTEGER NOT NULL DEFAULT 465") != 0) goto fail;
    if (!notifyd_table_has_column(g_notify_config_db, "notifyd_settings", "smtp_security") &&
        notifyd_exec(g_notify_config_db, "ALTER TABLE notifyd_settings ADD COLUMN smtp_security TEXT NOT NULL DEFAULT 'ssl'") != 0) goto fail;
    if (!notifyd_table_has_column(g_notify_config_db, "notifyd_settings", "smtp_from") &&
        notifyd_exec(g_notify_config_db, "ALTER TABLE notifyd_settings ADD COLUMN smtp_from TEXT NOT NULL DEFAULT ''") != 0) goto fail;
    if (!notifyd_table_has_column(g_notify_config_db, "notifyd_settings", "smtp_username") &&
        notifyd_exec(g_notify_config_db, "ALTER TABLE notifyd_settings ADD COLUMN smtp_username TEXT NOT NULL DEFAULT ''") != 0) goto fail;
    if (!notifyd_table_has_column(g_notify_config_db, "notifyd_settings", "smtp_password") &&
        notifyd_exec(g_notify_config_db, "ALTER TABLE notifyd_settings ADD COLUMN smtp_password TEXT NOT NULL DEFAULT ''") != 0) goto fail;
    if (!notifyd_table_has_column(g_notify_config_db, "notifyd_settings", "mute_schedule_json") &&
        notifyd_exec(g_notify_config_db,
            "ALTER TABLE notifyd_settings ADD COLUMN mute_schedule_json TEXT NOT NULL DEFAULT '{\"enabled\":false}'") != 0) goto fail;
    if (notifyd_exec(g_notify_config_db,
        "INSERT OR IGNORE INTO notifyd_settings(id,enabled,default_channel_id,max_attempts,retry_base_s,retry_max_s,updated_at) "
        "VALUES(1,1,'local',3,60,3600,0)") != 0)
        goto fail;

    if (notifyd_exec(g_notify_config_db,
        "CREATE TABLE IF NOT EXISTS notifyd_channels ("
        " id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " type TEXT NOT NULL DEFAULT 'noop',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " options_json TEXT NOT NULL DEFAULT '{}',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        goto fail;
    if (notifyd_exec(g_notify_config_db,
        "INSERT OR IGNORE INTO notifyd_channels(id,name,type,enabled,options_json,created_at,updated_at) "
        "VALUES('local','Local outbox','noop',1,'{}',0,0)") != 0)
        goto fail;

    if (notifyd_exec(g_notify_config_db,
        "CREATE TABLE IF NOT EXISTS notifyd_routes ("
        " id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " channel_id TEXT NOT NULL DEFAULT 'local',"
        " min_severity TEXT NOT NULL DEFAULT 'warning',"
        " category TEXT NOT NULL DEFAULT '',"
        " event TEXT NOT NULL DEFAULT '',"
        " source TEXT NOT NULL DEFAULT '',"
        " options_json TEXT NOT NULL DEFAULT '{}',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        goto fail;
    if (notifyd_exec(g_notify_config_db,
        "INSERT OR IGNORE INTO notifyd_routes(id,name,enabled,channel_id,min_severity,category,event,source,options_json,created_at,updated_at) "
        "VALUES('default-warning','Default warnings',1,'local','warning','','','','{}',0,0)") != 0)
        goto fail;

    /*
     * Per-user notification preference. Separate from notifyd_settings on
     * purpose: settings.enabled is the service switch and applies to every
     * route and recipient, while this table only decides whether one user
     * receives what a route already produced.
     *
     * Keyed by web_users.username, but without a foreign key: notifyd starts
     * independently of webd, and web_users may not exist yet on a fresh unit.
     * Existence is checked on write instead, where the directory is reachable
     * and a rejection can be reported to the caller.
     */
    if (notifyd_exec(g_notify_config_db,
        "CREATE TABLE IF NOT EXISTS notifyd_user_preferences ("
        " username TEXT PRIMARY KEY,"
        " muted INTEGER NOT NULL DEFAULT 0,"
        " muted_until INTEGER NOT NULL DEFAULT 0,"
        " channel_ids_json TEXT NOT NULL DEFAULT '[]',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        goto fail;

    if (notifyd_exec(g_notify_db,
        "CREATE TABLE IF NOT EXISTS notify_meta ("
        " key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '')") != 0)
        goto fail;
    if (notifyd_exec(g_notify_db,
        "CREATE TABLE IF NOT EXISTS notify_outbox ("
        " id TEXT PRIMARY KEY,"
        " created_at INTEGER NOT NULL,"
        " updated_at INTEGER NOT NULL,"
        " next_attempt_at INTEGER NOT NULL,"
        " channel_id TEXT NOT NULL,"
        " route_id TEXT NOT NULL DEFAULT '',"
        " event_id TEXT NOT NULL DEFAULT '',"
        " severity TEXT NOT NULL DEFAULT 'info',"
        " category TEXT NOT NULL DEFAULT '',"
        " event TEXT NOT NULL DEFAULT '',"
        " source TEXT NOT NULL DEFAULT '',"
        " title TEXT NOT NULL DEFAULT '',"
        " payload_json TEXT NOT NULL DEFAULT '{}',"
        " state TEXT NOT NULL DEFAULT 'pending',"
        " attempts INTEGER NOT NULL DEFAULT 0,"
        " max_attempts INTEGER NOT NULL DEFAULT 3,"
        " first_seen INTEGER NOT NULL DEFAULT 0,"
        " last_seen INTEGER NOT NULL DEFAULT 0,"
        " count INTEGER NOT NULL DEFAULT 1,"
        " last_error TEXT NOT NULL DEFAULT '',"
        " last_http_status INTEGER NOT NULL DEFAULT 0)") != 0)
        goto fail;
    if (notifyd_exec(g_notify_db, "CREATE INDEX IF NOT EXISTS idx_notify_outbox_state_next ON notify_outbox(state,next_attempt_at)") != 0 ||
        notifyd_exec(g_notify_db, "CREATE INDEX IF NOT EXISTS idx_notify_outbox_created ON notify_outbox(created_at DESC)") != 0)
        goto fail;
    if (!notifyd_table_has_column(g_notify_db, "notify_outbox", "dedupe_key") &&
        notifyd_exec(g_notify_db, "ALTER TABLE notify_outbox ADD COLUMN dedupe_key TEXT NOT NULL DEFAULT ''") != 0)
        goto fail;
    if (!notifyd_table_has_column(g_notify_db, "notify_outbox", "first_seen") &&
        notifyd_exec(g_notify_db, "ALTER TABLE notify_outbox ADD COLUMN first_seen INTEGER NOT NULL DEFAULT 0") != 0)
        goto fail;
    if (!notifyd_table_has_column(g_notify_db, "notify_outbox", "last_seen") &&
        notifyd_exec(g_notify_db, "ALTER TABLE notify_outbox ADD COLUMN last_seen INTEGER NOT NULL DEFAULT 0") != 0)
        goto fail;
    if (!notifyd_table_has_column(g_notify_db, "notify_outbox", "count") &&
        notifyd_exec(g_notify_db, "ALTER TABLE notify_outbox ADD COLUMN count INTEGER NOT NULL DEFAULT 1") != 0)
        goto fail;
    if (!notifyd_table_has_column(g_notify_db, "notify_outbox", "action_index") &&
        notifyd_exec(g_notify_db, "ALTER TABLE notify_outbox ADD COLUMN action_index INTEGER NOT NULL DEFAULT 0") != 0)
        goto fail;
    if (!notifyd_table_has_column(g_notify_db, "notify_outbox", "dedupe_group") &&
        notifyd_exec(g_notify_db, "ALTER TABLE notify_outbox ADD COLUMN dedupe_group TEXT NOT NULL DEFAULT ''") != 0)
        goto fail;
    if (!notifyd_table_has_column(g_notify_db, "notify_outbox", "delivery_options_json") &&
        notifyd_exec(g_notify_db, "ALTER TABLE notify_outbox ADD COLUMN delivery_options_json TEXT NOT NULL DEFAULT '{}'") != 0)
        goto fail;
    if (!notifyd_table_has_column(g_notify_db, "notify_outbox", "producer_dedupe_key") &&
        notifyd_exec(g_notify_db, "ALTER TABLE notify_outbox ADD COLUMN producer_dedupe_key TEXT NOT NULL DEFAULT ''") != 0)
        goto fail;
    if (!notifyd_table_has_column(g_notify_db, "notify_outbox", "route_dedupe_key") &&
        notifyd_exec(g_notify_db, "ALTER TABLE notify_outbox ADD COLUMN route_dedupe_key TEXT NOT NULL DEFAULT ''") != 0)
        goto fail;
    if (!notifyd_table_has_column(g_notify_db, "notify_outbox", "last_warning") &&
        notifyd_exec(g_notify_db, "ALTER TABLE notify_outbox ADD COLUMN last_warning TEXT NOT NULL DEFAULT ''") != 0)
        goto fail;
    if (notifyd_exec(g_notify_db,
        "UPDATE notify_outbox SET first_seen=created_at WHERE first_seen=0") != 0 ||
        notifyd_exec(g_notify_db,
        "UPDATE notify_outbox SET last_seen=updated_at WHERE last_seen=0") != 0 ||
        notifyd_exec(g_notify_db,
        "UPDATE notify_outbox SET count=1 WHERE count<1") != 0)
        goto fail;
    if (notifyd_exec(g_notify_db,
        "UPDATE notify_outbox SET producer_dedupe_key=dedupe_key "
        "WHERE producer_dedupe_key='' AND dedupe_key<>''") != 0)
        goto fail;
    if (notifyd_exec(g_notify_db, "CREATE INDEX IF NOT EXISTS idx_notify_outbox_dedupe ON notify_outbox(channel_id,route_id,dedupe_key,state)") != 0)
        goto fail;
    if (notifyd_exec(g_notify_db, "CREATE INDEX IF NOT EXISTS idx_notify_outbox_route_action_dedupe ON notify_outbox(channel_id,route_id,action_index,dedupe_group,route_dedupe_key,last_seen)") != 0 ||
        notifyd_exec(g_notify_db, "CREATE INDEX IF NOT EXISTS idx_notify_outbox_producer_action_dedupe ON notify_outbox(channel_id,route_id,action_index,producer_dedupe_key,updated_at)") != 0)
        goto fail;

    if (notifyd_exec(g_notify_db,
        "CREATE TABLE IF NOT EXISTS notify_route_suppressions ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " route_id TEXT NOT NULL,"
        " ts INTEGER NOT NULL,"
        " reason TEXT NOT NULL,"
        " event TEXT NOT NULL DEFAULT '',"
        " source TEXT NOT NULL DEFAULT '',"
        " target TEXT NOT NULL DEFAULT '',"
        " payload_json TEXT NOT NULL DEFAULT '{}')") != 0 ||
        notifyd_exec(g_notify_db,
        "CREATE INDEX IF NOT EXISTS idx_notify_route_suppressions_route_ts "
        "ON notify_route_suppressions(route_id,ts DESC)") != 0)
        goto fail;

    if (notifyd_exec(g_notify_db,
        "CREATE TABLE IF NOT EXISTS notify_route_triggers ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " route_id TEXT NOT NULL,"
        " event TEXT NOT NULL DEFAULT '',"
        " severity TEXT NOT NULL DEFAULT 'info',"
        " source TEXT NOT NULL DEFAULT '',"
        " triggered_at INTEGER NOT NULL,"
        " result TEXT NOT NULL DEFAULT 'enqueued',"
        " reason TEXT NOT NULL DEFAULT '',"
        " dedupe_result TEXT NOT NULL DEFAULT 'not_applicable',"
        " mute_result TEXT NOT NULL DEFAULT 'not_muted')") != 0 ||
        notifyd_exec(g_notify_db,
            "CREATE INDEX IF NOT EXISTS idx_notify_route_triggers_route_id "
            "ON notify_route_triggers(route_id,id DESC)") != 0 ||
        notifyd_exec(g_notify_db,
            "CREATE INDEX IF NOT EXISTS idx_notify_route_triggers_time "
            "ON notify_route_triggers(triggered_at DESC,id DESC)") != 0)
        goto fail;

    if (notifyd_exec(g_notify_db,
        "CREATE TABLE IF NOT EXISTS notify_deliveries ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " outbox_id TEXT NOT NULL,"
        " channel_id TEXT NOT NULL,"
        " ts INTEGER NOT NULL,"
        " ok INTEGER NOT NULL DEFAULT 0,"
        " http_status INTEGER NOT NULL DEFAULT 0,"
        " error TEXT NOT NULL DEFAULT '')") != 0)
        goto fail;
    if (!notifyd_table_has_column(g_notify_db, "notify_deliveries", "duration_ms") &&
        notifyd_exec(g_notify_db, "ALTER TABLE notify_deliveries ADD COLUMN duration_ms INTEGER NOT NULL DEFAULT 0") != 0)
        goto fail;
    if (!notifyd_table_has_column(g_notify_db, "notify_deliveries", "warning") &&
        notifyd_exec(g_notify_db, "ALTER TABLE notify_deliveries ADD COLUMN warning TEXT NOT NULL DEFAULT ''") != 0)
        goto fail;
    /*
     * `ok` stays two-valued for older readers, so suppression records ok=1 --
     * it is not a failure. `outcome` is what tells delivered and suppressed
     * apart, and `suppressed_recipients` counts the muted addresses that were
     * skipped on an otherwise successful send.
     */
    if (!notifyd_table_has_column(g_notify_db, "notify_deliveries", "outcome") &&
        notifyd_exec(g_notify_db, "ALTER TABLE notify_deliveries ADD COLUMN outcome TEXT NOT NULL DEFAULT ''") != 0)
        goto fail;
    if (!notifyd_table_has_column(g_notify_db, "notify_deliveries", "suppressed_recipients") &&
        notifyd_exec(g_notify_db, "ALTER TABLE notify_deliveries ADD COLUMN suppressed_recipients INTEGER NOT NULL DEFAULT 0") != 0)
        goto fail;
    if (notifyd_exec(g_notify_db, "CREATE INDEX IF NOT EXISTS idx_notify_deliveries_outbox ON notify_deliveries(outbox_id,ts DESC)") != 0 ||
        notifyd_exec(g_notify_db, "INSERT OR IGNORE INTO notify_meta(key,value) VALUES('schema_version','1')") != 0)
        goto fail;
    return 0;

fail:
    notifyd_db_close();
    return -1;
}

void notifyd_db_close(void)
{
    if (g_notify_db) {
        sqlite3_close(g_notify_db);
        g_notify_db = NULL;
    }
    if (g_notify_config_db) {
        sqlite3_close(g_notify_config_db);
        g_notify_config_db = NULL;
    }
}

int notifyd_settings_load(struct notifyd_settings *out)
{
    sqlite3_stmt *st;

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    out->enabled = 1;
    snprintf(out->default_channel_id, sizeof(out->default_channel_id), "%s", "local");
    out->max_attempts = 3;
    out->retry_base_s = 60;
    out->retry_max_s = 3600;
    snprintf(out->mute_schedule_json, sizeof(out->mute_schedule_json),
             "%s", "{\"enabled\":false}");
    st = notifyd_config_prepare("SELECT enabled,default_channel_id,max_attempts,retry_base_s,retry_max_s,"
                                "smtp_host,smtp_port,smtp_security,smtp_from,smtp_username,smtp_password,"
                                "mute_schedule_json "
                                "FROM notifyd_settings WHERE id=1");
    if (!st)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        out->enabled = sqlite3_column_int(st, 0);
        snprintf(out->default_channel_id, sizeof(out->default_channel_id), "%s",
                 sqlite3_column_text(st, 1) ? (const char *)sqlite3_column_text(st, 1) : "local");
        out->max_attempts = sqlite3_column_int(st, 2);
        out->retry_base_s = sqlite3_column_int(st, 3);
        out->retry_max_s = sqlite3_column_int(st, 4);
        snprintf(out->smtp_host, sizeof(out->smtp_host), "%s", notifyd_sqlite_text(st, 5, ""));
        out->smtp_port = sqlite3_column_int(st, 6);
        snprintf(out->smtp_security, sizeof(out->smtp_security), "%s", notifyd_sqlite_text(st, 7, "ssl"));
        snprintf(out->smtp_from, sizeof(out->smtp_from), "%s", notifyd_sqlite_text(st, 8, ""));
        snprintf(out->smtp_username, sizeof(out->smtp_username), "%s", notifyd_sqlite_text(st, 9, ""));
        snprintf(out->smtp_password, sizeof(out->smtp_password), "%s", notifyd_sqlite_text(st, 10, ""));
        snprintf(out->mute_schedule_json, sizeof(out->mute_schedule_json), "%s",
                 notifyd_sqlite_text(st, 11, "{\"enabled\":false}"));
    }
    sqlite3_finalize(st);
    if (out->max_attempts < 1) out->max_attempts = 1;
    if (out->max_attempts > 20) out->max_attempts = 20;
    if (out->retry_base_s < 1) out->retry_base_s = 60;
    if (out->retry_max_s < out->retry_base_s) out->retry_max_s = out->retry_base_s;
    if (out->smtp_port < 1 || out->smtp_port > 65535) out->smtp_port = 465;
    if (strcmp(out->smtp_security, "ssl") && strcmp(out->smtp_security, "starttls") && strcmp(out->smtp_security, "none"))
        snprintf(out->smtp_security, sizeof(out->smtp_security), "%s", "ssl");
    return 0;
}

struct json_object *notifyd_status_json(void)
{
    struct notifyd_settings s;
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    struct json_object *dependencies = json_object_new_object();
    struct json_object *datasets = json_object_new_object();
    struct json_object *outbox = json_object_new_object();
    char last_error[NOTIFYD_MAX_TEXT] = "";
    int pending = 0, retry = 0, failed = 0, delivered = 0, channels = 0, routes = 0;
    int suppressed_state = 0;
    int schema_version = 0;
    int64_t updated_at = 0;
    int ok = 1;
    int degraded;
    int rc;
    struct jmx_storage_guard_stats storage_guard;

    memset(&storage_guard, 0, sizeof(storage_guard));
    jmx_storage_guard_get_stats(&storage_guard);
    (void)jmx_storage_guard_check(notifyd_storage_path(), &storage_guard.state);

    memset(&s, 0, sizeof(s));
    s.smtp_port = 465;
    snprintf(s.smtp_security, sizeof(s.smtp_security), "%s", "ssl");
    if (notifyd_settings_load(&s) != 0) {
        ok = 0;
        notifyd_response_set_first_error(resp, "settings_load_failed");
    }
    st = notifyd_prepare("SELECT state,COUNT(*) FROM notify_outbox GROUP BY state");
    if (st) {
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            const char *state = (const char *)sqlite3_column_text(st, 0);
            int n = sqlite3_column_int(st, 1);
            if (state && !strcmp(state, "pending")) pending = n;
            else if (state && !strcmp(state, "retry")) retry = n;
            else if (state && !strcmp(state, "failed")) failed = n;
            else if (state && !strcmp(state, "delivered")) delivered = n;
            else if (state && !strcmp(state, "suppressed")) suppressed_state = n;
        }
        if (rc != SQLITE_DONE) {
            ok = 0;
            notifyd_response_set_first_error(resp, "outbox_summary_query_failed");
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
        notifyd_response_set_first_error(resp, "outbox_summary_query_failed");
    }
    st = notifyd_config_prepare("SELECT COUNT(*) FROM notifyd_channels WHERE enabled=1");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) channels = sqlite3_column_int(st, 0);
        else if (rc != SQLITE_DONE) {
            ok = 0;
            notifyd_response_set_first_error(resp, "channels_count_query_failed");
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
        notifyd_response_set_first_error(resp, "channels_count_query_failed");
    }
    st = notifyd_config_prepare("SELECT COUNT(*) FROM notifyd_routes WHERE enabled=1");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) routes = sqlite3_column_int(st, 0);
        else if (rc != SQLITE_DONE) {
            ok = 0;
            notifyd_response_set_first_error(resp, "routes_count_query_failed");
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
        notifyd_response_set_first_error(resp, "routes_count_query_failed");
    }
    st = notifyd_prepare("SELECT CAST(value AS INTEGER) FROM notify_meta WHERE key='schema_version'");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW)
            schema_version = sqlite3_column_int(st, 0);
        else {
            ok = 0;
            notifyd_response_set_first_error(resp, "schema_version_unavailable");
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
        notifyd_response_set_first_error(resp, "schema_version_unavailable");
    }
    st = notifyd_prepare(
        "SELECT last_error,updated_at FROM notify_outbox WHERE last_error<>'' "
        "ORDER BY updated_at DESC LIMIT 1");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            snprintf(last_error, sizeof(last_error), "%s", notifyd_sqlite_text(st, 0, ""));
            updated_at = sqlite3_column_int64(st, 1);
        } else if (rc != SQLITE_DONE) {
            ok = 0;
            notifyd_response_set_first_error(resp, "last_error_query_failed");
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
        notifyd_response_set_first_error(resp, "last_error_query_failed");
    }
    st = notifyd_prepare("SELECT COALESCE(MAX(updated_at),0) FROM notify_outbox");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW && sqlite3_column_int64(st, 0) > updated_at)
            updated_at = sqlite3_column_int64(st, 0);
        else if (rc != SQLITE_ROW) {
            ok = 0;
            notifyd_response_set_first_error(resp, "updated_at_query_failed");
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
        notifyd_response_set_first_error(resp, "updated_at_query_failed");
    }
    if (!ok && !last_error[0])
        snprintf(last_error, sizeof(last_error), "%s", "status_query_failed");
    degraded = !ok || failed > 0 || last_error[0];
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "service", json_object_new_string("dreamingwrt-notifyd"));
    json_object_object_add(resp, "version", json_object_new_string(WORKER_STATUS_VERSION));
    json_object_object_add(resp, "schema_version", json_object_new_int(schema_version));
    json_object_object_add(resp, "schema_source",
                           json_object_new_string("notify.db:notify_meta.schema_version"));
    json_object_object_add(resp, "migration_state", json_object_new_string(
        schema_version == NOTIFYD_SCHEMA_VERSION ? "current" :
        (schema_version > 0 ? "version_mismatch" : "unknown")));
    json_object_object_add(resp, "state", json_object_new_string(degraded ? "degraded" :
                           (s.enabled ? "running" : "disabled")));
    json_object_object_add(resp, "degraded", json_object_new_boolean(degraded));
    json_object_object_add(resp, "last_error", json_object_new_string(last_error));
    json_object_object_add(resp, "updated_at", json_object_new_int64(updated_at));
    json_object_object_add(resp, "enabled", json_object_new_boolean(s.enabled));
    json_object_object_add(resp, "default_channel_id", json_object_new_string(s.default_channel_id));
    json_object_object_add(resp, "active_channels", json_object_new_int(channels));
    json_object_object_add(resp, "active_routes", json_object_new_int(routes));
    json_object_object_add(resp, "pending", json_object_new_int(pending));
    json_object_object_add(resp, "retry", json_object_new_int(retry));
    json_object_object_add(resp, "failed", json_object_new_int(failed));
    json_object_object_add(resp, "delivered", json_object_new_int(delivered));
    /*
     * Kept out of `degraded` above: these rows were silenced by a user's own
     * preference, which is an intended outcome rather than a service problem.
     */
    json_object_object_add(resp, "suppressed", json_object_new_int(suppressed_state));
    json_object_object_add(resp, "storage_pressure",
                           json_object_new_string(jmx_storage_pressure_name(storage_guard.state.pressure)));
    json_object_object_add(resp, "storage_reason", json_object_new_string(storage_guard.state.reason));
    json_object_object_add(resp, "storage_total_bytes",
                           json_object_new_int64((int64_t)storage_guard.state.total_bytes));
    json_object_object_add(resp, "storage_available_bytes",
                           json_object_new_int64((int64_t)storage_guard.state.available_bytes));
    json_object_object_add(resp, "storage_used_pct",
                           json_object_new_int((int)storage_guard.state.used_pct));
    json_object_object_add(resp, "storage_checked_at",
                           json_object_new_int64(storage_guard.state.checked_at));
    json_object_object_add(resp, "storage_suppressed_writes",
                           json_object_new_int64((int64_t)g_notify_storage_suppressed));
    json_object_object_add(resp, "storage_last_suppressed_at",
                           json_object_new_int64(g_notify_storage_last_suppressed_at));
    json_object_object_add(dependencies, "outbox_db", json_object_new_boolean(g_notify_db != NULL));
    json_object_object_add(dependencies, "config_db", json_object_new_boolean(g_notify_config_db != NULL));
    json_object_object_add(resp, "dependencies", dependencies);
    json_object_object_add(outbox, "pending", json_object_new_int(pending));
    json_object_object_add(outbox, "retry", json_object_new_int(retry));
    json_object_object_add(outbox, "failed", json_object_new_int(failed));
    json_object_object_add(outbox, "delivered", json_object_new_int(delivered));
    json_object_object_add(outbox, "suppressed", json_object_new_int(suppressed_state));
    json_object_object_add(datasets, "outbox", outbox);
    json_object_object_add(datasets, "active_channels", json_object_new_int(channels));
    json_object_object_add(datasets, "active_routes", json_object_new_int(routes));
    json_object_object_add(resp, "datasets", datasets);
    {
        struct json_object *cap = json_object_new_object();
        struct json_object *types = json_object_new_array();
        struct json_object *route_features = json_object_new_object();
        struct json_object *action_types = json_object_new_array();
        struct json_object *receiver_modes = json_object_new_array();
        struct json_object *content_modes = json_object_new_array();

        json_object_array_add(types, json_object_new_string("noop"));
        json_object_array_add(types, json_object_new_string("webhook"));
        json_object_array_add(types, json_object_new_string("email"));
        json_object_object_add(cap, "channel_types", types);
        json_object_object_add(cap, "delete_channel", json_object_new_boolean(1));
        json_object_object_add(cap, "delete_route", json_object_new_boolean(1));
        json_object_object_add(cap, "secret_redaction", json_object_new_boolean(1));
        json_object_object_add(cap, "smtp_secret_redaction", json_object_new_boolean(1));
        json_object_object_add(cap, "email_user_directory", json_object_new_boolean(1));
        json_object_object_add(cap, "smtp_configured", json_object_new_boolean(s.smtp_host[0] && s.smtp_from[0]));
        json_object_object_add(cap, "outbox_cursor", json_object_new_boolean(1));
        json_object_object_add(cap, "outbox_search", json_object_new_boolean(1));
        json_object_object_add(cap, "outbox_total", json_object_new_boolean(1));
        json_object_object_add(cap, "outbox_detail", json_object_new_boolean(1));
        json_object_object_add(cap, "delivery_attempts", json_object_new_boolean(1));
        json_object_object_add(cap, "delivery_duration_ms", json_object_new_boolean(1));
        json_object_object_add(cap, "test_send", json_object_new_boolean(1));
        json_object_object_add(cap, "retry", json_object_new_boolean(1));
        json_object_object_add(cap, "event_catalog", json_object_new_boolean(1));
        json_object_object_add(cap, "mute_schedule_supported", json_object_new_boolean(1));
        json_object_object_add(cap, "route_trigger_summary", json_object_new_boolean(1));
        json_object_object_add(cap, "trigger_timeline", json_object_new_boolean(1));
        json_object_object_add(cap, "trigger_timeline_cursor", json_object_new_boolean(1));
        json_object_object_add(cap, "mobile_push", json_object_new_boolean(0));
        json_object_object_add(cap, "mobile_push_reason",
                               json_object_new_string("device_token_provider_not_configured"));
        {
            /*
             * Personal mute. Advertised as its own capability so the frontend
             * can enable the control without probing a write, and so the
             * per-channel scope is discoverable: only channels that address a
             * named user (email today) can be muted for one person without
             * affecting the other recipients on the same channel.
             */
            struct json_object *mute = json_object_new_object();
            struct json_object *addressable = json_object_new_array();

            json_object_array_add(addressable, json_object_new_string("email"));
            json_object_object_add(mute, "schema_version", json_object_new_int(1));
            json_object_object_add(mute, "permanent", json_object_new_boolean(1));
            json_object_object_add(mute, "scheduled", json_object_new_boolean(1));
            json_object_object_add(mute, "per_channel", json_object_new_boolean(1));
            json_object_object_add(mute, "max_duration_s",
                                   json_object_new_int(NOTIFYD_USER_MUTE_MAX_DURATION_S));
            json_object_object_add(mute, "max_channels",
                                   json_object_new_int(NOTIFYD_MAX_PREF_CHANNELS));
            json_object_object_add(mute, "revision_guard", json_object_new_boolean(1));
            json_object_object_add(mute, "addressable_channel_types", addressable);
            json_object_object_add(cap, "user_mute_preference", mute);
            json_object_object_add(cap, "outbox_suppressed_state", json_object_new_boolean(1));
        }
        json_object_array_add(action_types, json_object_new_string("notify"));
        json_object_array_add(receiver_modes, json_object_new_string("channel"));
        json_object_array_add(receiver_modes, json_object_new_string("admins"));
        json_object_array_add(receiver_modes, json_object_new_string("users"));
        json_object_array_add(receiver_modes, json_object_new_string("emails"));
        json_object_array_add(content_modes, json_object_new_string("default"));
        json_object_array_add(content_modes, json_object_new_string("custom"));
        json_object_object_add(route_features, "schema_version",
                               json_object_new_int(NOTIFYD_ROUTE_SCHEMA_VERSION));
        json_object_object_add(route_features, "schedule", json_object_new_boolean(1));
        json_object_object_add(route_features, "multi_action", json_object_new_boolean(1));
        json_object_object_add(route_features, "rule_receivers", json_object_new_boolean(1));
        json_object_object_add(route_features, "custom_content", json_object_new_boolean(1));
        json_object_object_add(route_features, "route_dedupe", json_object_new_boolean(1));
        json_object_object_add(route_features, "action_types", action_types);
        json_object_object_add(route_features, "receiver_modes", receiver_modes);
        json_object_object_add(route_features, "content_modes", content_modes);
        json_object_object_add(cap, "route_features", route_features);
        notifyd_event_ids_json(cap);
        json_object_object_add(resp, "capabilities", cap);
    }
    json_object_object_add(resp, "ts", json_object_new_int64(notifyd_now_s()));
    memset(s.smtp_password, 0, sizeof(s.smtp_password));
    return resp;
}

struct json_object *notifyd_settings_json(void)
{
    struct notifyd_settings s;
    struct json_object *resp = json_object_new_object();
    int ok;

    memset(&s, 0, sizeof(s));
    s.smtp_port = 465;
    snprintf(s.smtp_security, sizeof(s.smtp_security), "%s", "ssl");
    ok = notifyd_settings_load(&s) == 0;
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("settings_load_failed"));
    json_object_object_add(resp, "enabled", json_object_new_boolean(s.enabled));
    json_object_object_add(resp, "default_channel_id", json_object_new_string(s.default_channel_id));
    json_object_object_add(resp, "max_attempts", json_object_new_int(s.max_attempts));
    json_object_object_add(resp, "retry_base_s", json_object_new_int(s.retry_base_s));
    json_object_object_add(resp, "retry_max_s", json_object_new_int(s.retry_max_s));
    {
        struct json_object *smtp = json_object_new_object();
        json_object_object_add(smtp, "host", json_object_new_string(s.smtp_host));
        json_object_object_add(smtp, "port", json_object_new_int(s.smtp_port));
        json_object_object_add(smtp, "security", json_object_new_string(s.smtp_security));
        json_object_object_add(smtp, "from", json_object_new_string(s.smtp_from));
        json_object_object_add(smtp, "username", json_object_new_string(s.smtp_username));
        json_object_object_add(smtp, "password_present", json_object_new_boolean(s.smtp_password[0]));
        json_object_object_add(resp, "smtp", smtp);
    }
    {
        struct json_object *stored_mute = notifyd_json_parse_or_object(s.mute_schedule_json);
        struct json_object *mute = NULL;
        struct json_object *mute_error = NULL;
        struct json_object *capabilities = json_object_new_object();

        if (!notifyd_global_mute_normalize(stored_mute, &mute, &mute_error)) {
            if (mute_error)
                json_object_put(mute_error);
            mute = json_object_new_object();
            json_object_object_add(mute, "enabled", json_object_new_boolean(0));
            json_object_object_add(mute, "timezone", json_object_new_string("Asia/Shanghai"));
            json_object_object_add(mute, "windows", json_object_new_array());
        }
        json_object_put(stored_mute);
        json_object_object_add(resp, "mute_schedule", mute);
        json_object_object_add(resp, "mute_schedule_supported", json_object_new_boolean(1));
        json_object_object_add(resp, "mobile_push", json_object_new_boolean(0));
        json_object_object_add(resp, "mobile_push_supported", json_object_new_boolean(0));
        json_object_object_add(resp, "mobile_push_reason",
                               json_object_new_string("device_token_provider_not_configured"));
        json_object_object_add(capabilities, "mute_schedule_supported",
                               json_object_new_boolean(1));
        json_object_object_add(capabilities, "mobile_push_supported",
                               json_object_new_boolean(0));
        json_object_object_add(capabilities, "mobile_push_reason",
                               json_object_new_string("device_token_provider_not_configured"));
        json_object_object_add(resp, "capabilities", capabilities);
    }
    memset(s.smtp_password, 0, sizeof(s.smtp_password));
    return resp;
}

static int notifyd_smtp_host_ok(const char *host)
{
    const unsigned char *p;

    if (!host || strlen(host) > 255)
        return 0;
    if (!host[0])
        return 1;
    for (p = (const unsigned char *)host; *p; p++) {
        if (!(isalnum(*p) || *p == '.' || *p == '-' || *p == ':' || *p == '[' || *p == ']'))
            return 0;
    }
    return 1;
}

struct json_object *notifyd_settings_update(struct json_object *body)
{
    struct notifyd_settings s;
    sqlite3_stmt *st;
    struct json_object *resp;
    const char *channel;
    char channel_copy[sizeof(s.default_channel_id)];
    int ok;
    struct json_object *smtp = NULL;
    struct json_object *mute_schedule = NULL;
    struct json_object *normalized_mute = NULL;
    struct json_object *feature_error = NULL;
    struct json_object *mobile_push = NULL;
    const char *smtp_host, *smtp_security, *smtp_from, *smtp_username, *password_replace;
    int smtp_port, password_delete;

    if (notifyd_settings_load(&s) != 0) {
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("settings_load_failed"));
        return resp;
    }
    if (!body || !json_object_is_type(body, json_type_object))
        body = NULL;
    if (body && json_object_object_get_ex(body, "mobile_push", &mobile_push)) {
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("feature_unsupported"));
        json_object_object_add(resp, "feature", json_object_new_string("mobile_push"));
        json_object_object_add(resp, "reason",
                               json_object_new_string("device_token_provider_not_configured"));
        return resp;
    }
    if (body && json_object_object_get_ex(body, "mute_schedule", &mute_schedule) &&
        !notifyd_global_mute_normalize(mute_schedule, &normalized_mute, &feature_error))
        return feature_error;
    s.enabled = notifyd_json_bool(body, "enabled", s.enabled);
    channel = notifyd_json_str(body, "default_channel_id", s.default_channel_id);
    if (channel && channel[0] && notifyd_id_ok(channel)) {
        /* channel may point into s.default_channel_id when the field is omitted. */
        snprintf(channel_copy, sizeof(channel_copy), "%s", channel);
        snprintf(s.default_channel_id, sizeof(s.default_channel_id), "%s", channel_copy);
    }
    s.max_attempts = notifyd_json_int(body, "max_attempts", s.max_attempts);
    s.retry_base_s = notifyd_json_int(body, "retry_base_s", s.retry_base_s);
    s.retry_max_s = notifyd_json_int(body, "retry_max_s", s.retry_max_s);
    if (body) json_object_object_get_ex(body, "smtp", &smtp);
    smtp_host = notifyd_json_str(smtp, "host", s.smtp_host);
    smtp_port = notifyd_json_int(smtp, "port", s.smtp_port);
    smtp_security = notifyd_json_str(smtp, "security", s.smtp_security);
    smtp_from = notifyd_json_str(smtp, "from", s.smtp_from);
    smtp_username = notifyd_json_str(smtp, "username", s.smtp_username);
    password_replace = notifyd_json_str(smtp, "password_replace", NULL);
    password_delete = notifyd_json_bool(smtp, "password_delete", 0);
    if (s.max_attempts < 1 || s.max_attempts > 20 || s.retry_base_s < 1 ||
        s.retry_base_s > 86400 || s.retry_max_s < s.retry_base_s || s.retry_max_s > 86400 ||
        smtp_port < 1 || smtp_port > 65535 ||
        (strcmp(smtp_security, "ssl") && strcmp(smtp_security, "starttls") && strcmp(smtp_security, "none")) ||
        !notifyd_smtp_host_ok(smtp_host) ||
        (smtp_from[0] && !notifyd_email_address_ok(smtp_from)) ||
        !notifyd_text_ok(smtp_username, 255) || strchr(smtp_username, '\r') || strchr(smtp_username, '\n') ||
        (smtp_username[0] && !strcmp(smtp_security, "none")) ||
        (password_replace && (!notifyd_text_ok(password_replace, 511) || strchr(password_replace, '\r') ||
                              strchr(password_replace, '\n') || !strcmp(password_replace, "__redacted__")))) {
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_settings"));
        if (normalized_mute)
            json_object_put(normalized_mute);
        return resp;
    }
    st = notifyd_config_prepare(
        "UPDATE notifyd_settings SET enabled=?1,default_channel_id=?2,max_attempts=?3,retry_base_s=?4,retry_max_s=?5,updated_at=?6,"
        "smtp_host=?7,smtp_port=?8,smtp_security=?9,smtp_from=?10,smtp_username=?11,smtp_password=?12,"
        "mute_schedule_json=?13 WHERE id=1");
    ok = 0;
    if (st) {
        sqlite3_bind_int(st, 1, s.enabled);
        sqlite3_bind_text(st, 2, s.default_channel_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, s.max_attempts);
        sqlite3_bind_int(st, 4, s.retry_base_s);
        sqlite3_bind_int(st, 5, s.retry_max_s);
        sqlite3_bind_int64(st, 6, notifyd_now_s());
        sqlite3_bind_text(st, 7, smtp_host, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 8, smtp_port);
        sqlite3_bind_text(st, 9, smtp_security, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 10, smtp_from, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 11, smtp_username, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 12, password_delete ? "" : (password_replace ? password_replace : s.smtp_password), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 13,
            normalized_mute ? json_object_to_json_string_ext(normalized_mute, JSON_C_TO_STRING_PLAIN) :
                              s.mute_schedule_json,
            -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    if (normalized_mute)
        json_object_put(normalized_mute);
    resp = notifyd_settings_json();
    notifyd_response_set_ok(resp, ok);
    json_object_object_add(resp, "saved", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("save_failed"));
    return resp;
}

static struct json_object *notifyd_channel_options_public(const char *options_s)
{
    struct json_object *options = notifyd_json_parse_or_object(options_s);
    struct json_object *headers = NULL;
    struct json_object *public_headers = json_object_new_object();
    struct json_object *header_names = json_object_new_array();
    int count = 0;

    if (!options || !public_headers || !header_names)
        goto done;
    if (json_object_object_get_ex(options, "headers", &headers) && headers &&
        json_object_is_type(headers, json_type_object)) {
        json_object_object_foreach(headers, key, value) {
            (void)value;
            json_object_object_add(public_headers, key,
                                   json_object_new_string("__redacted__"));
            json_object_array_add(header_names, json_object_new_string(key));
            count++;
        }
    }
    json_object_object_del(options, "headers");
    if (count > 0) {
        json_object_object_add(options, "headers", public_headers);
        public_headers = NULL;
    }
    json_object_object_add(options, "headers_present", json_object_new_boolean(count > 0));
    json_object_object_add(options, "header_names", header_names);
    header_names = NULL;
done:
    if (public_headers) json_object_put(public_headers);
    if (header_names) json_object_put(header_names);
    return options ? options : json_object_new_object();
}

static void notifyd_channel_row_json(struct json_object *arr, sqlite3_stmt *st)
{
    const char *options_s = notifyd_sqlite_text(st, 4, "{}");
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "id", json_object_new_string(notifyd_sqlite_text(st, 0, "")));
    json_object_object_add(o, "name", json_object_new_string(notifyd_sqlite_text(st, 1, "")));
    json_object_object_add(o, "type", json_object_new_string(notifyd_sqlite_text(st, 2, "noop")));
    json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 3)));
    json_object_object_add(o, "options", notifyd_channel_options_public(options_s));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 5)));
    json_object_array_add(arr, o);
}

struct json_object *notifyd_channels_json(void)
{
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    int ok = 1;
    int rc;

    st = notifyd_config_prepare("SELECT id,name,type,enabled,options_json,updated_at FROM notifyd_channels ORDER BY id");
    if (st) {
        while ((rc = sqlite3_step(st)) == SQLITE_ROW)
            notifyd_channel_row_json(arr, st);
        if (rc != SQLITE_DONE)
            ok = 0;
        sqlite3_finalize(st);
    } else {
        ok = 0;
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("channels_query_failed"));
    json_object_object_add(resp, "channels", arr);
    return resp;
}

static int notifyd_webhook_options_ok(struct json_object *options)
{
    const char *url;
    const char *method;
    int timeout_ms;
    struct json_object *headers = NULL;

    if (!options || !json_object_is_type(options, json_type_object))
        return 0;
    url = notifyd_json_str(options, "url", "");
    method = notifyd_json_str(options, "method", "POST");
    timeout_ms = notifyd_json_int(options, "timeout_ms", 10000);
    if (!notifyd_url_ok(url))
        return 0;
    if (strcmp(method, "POST") && strcmp(method, "PUT") && strcmp(method, "PATCH"))
        return 0;
    if (timeout_ms < 1000 || timeout_ms > 60000)
        return 0;
    if (json_object_object_get_ex(options, "headers", &headers) && headers) {
        if (!json_object_is_type(headers, json_type_object))
            return 0;
        json_object_object_foreach(headers, key, val) {
            const char *value;

            if (!json_object_is_type(val, json_type_string))
                return 0;
            value = json_object_get_string(val);
            if (!strcmp(value ? value : "", "__redacted__"))
                return 0;
            if (!notifyd_text_ok(key, 96) || !notifyd_text_ok(value, 512))
                return 0;
            if (!key[0] || strchr(key, '\n') || strchr(key, '\r') || strchr(key, ':'))
                return 0;
            if (value && (strchr(value, '\n') || strchr(value, '\r')))
                return 0;
        }
    }
    return 1;
}

static int notifyd_email_address_ok(const char *email)
{
    const char *at;
    const unsigned char *p;

    if (!email || !email[0] || strlen(email) > 254)
        return 0;
    at = strchr(email, '@');
    if (!at || at == email || !at[1] || !strchr(at + 1, '.'))
        return 0;
    for (p = (const unsigned char *)email; *p; p++) {
        if (*p <= 0x20 || *p == 0x7f || *p == '<' || *p == '>' || *p == ',' || *p == ';')
            return 0;
    }
    return 1;
}

static int notifyd_email_array_ok(struct json_object *options, const char *key,
                                  int usernames)
{
    struct json_object *values = NULL;
    int i;

    if (!json_object_object_get_ex(options, key, &values))
        return 1;
    if (!values || !json_object_is_type(values, json_type_array) ||
        json_object_array_length(values) > 64)
        return 0;
    for (i = 0; i < (int)json_object_array_length(values); i++) {
        struct json_object *value = json_object_array_get_idx(values, i);
        const char *text;

        if (!value || !json_object_is_type(value, json_type_string))
            return 0;
        text = json_object_get_string(value);
        if (usernames ? !notifyd_token_ok(text, 64) : !notifyd_email_address_ok(text))
            return 0;
    }
    return 1;
}

static int notifyd_email_options_ok(struct json_object *options)
{
    const char *prefix;
    const char *reply_to;
    struct json_object *users = NULL, *recipients = NULL;
    size_t total = 0;

    if (!options || !json_object_is_type(options, json_type_object) ||
        !notifyd_email_array_ok(options, "user_ids", 1) ||
        !notifyd_email_array_ok(options, "recipients", 0))
        return 0;
    if (json_object_object_get_ex(options, "user_ids", &users) && users)
        total += json_object_array_length(users);
    if (json_object_object_get_ex(options, "recipients", &recipients) && recipients)
        total += json_object_array_length(recipients);
    if (total < 1 || total > 64)
        return 0;
    prefix = notifyd_json_str(options, "subject_prefix", "[DreamingWrt]");
    reply_to = notifyd_json_str(options, "reply_to", "");
    if (!notifyd_text_ok(prefix, 96) || strchr(prefix, '\r') || strchr(prefix, '\n'))
        return 0;
    if (reply_to[0] && !notifyd_email_address_ok(reply_to))
        return 0;
    return 1;
}

static int notifyd_config_revision_matches(const char *sql, const char *id,
                                           int64_t expected, int64_t *current)
{
    sqlite3_stmt *st;
    int64_t value = 0;

    if (current) *current = 0;
    st = notifyd_config_prepare(sql);
    if (!st)
        return 0;
    sqlite3_bind_text(st, 1, id ? id : "", -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        value = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    if (current) *current = value;
    return expected < 0 || value == expected;
}

static struct json_object *notifyd_channel_options_existing(const char *id)
{
    sqlite3_stmt *st;
    struct json_object *options = NULL;

    st = notifyd_config_prepare("SELECT options_json FROM notifyd_channels WHERE id=?1");
    if (!st)
        return json_object_new_object();
    sqlite3_bind_text(st, 1, id ? id : "", -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        options = notifyd_json_parse_or_object(notifyd_sqlite_text(st, 0, "{}"));
    sqlite3_finalize(st);
    return options ? options : json_object_new_object();
}

static int notifyd_channel_options_merge_headers(const char *id,
                                                 struct json_object *body,
                                                 struct json_object *options)
{
    struct json_object *existing = NULL, *headers = NULL, *replace = NULL;
    int delete_headers = notifyd_json_bool(body, "headers_delete", 0) ||
                         notifyd_json_bool(options, "headers_delete", 0);

    if (!options || !json_object_is_type(options, json_type_object))
        return 0;
    json_object_object_del(options, "headers_present");
    json_object_object_del(options, "header_names");
    json_object_object_del(options, "headers_delete");
    json_object_object_get_ex(body, "headers_replace", &replace);
    if (replace)
        replace = json_object_get(replace);
    else if (json_object_object_get_ex(options, "headers_replace", &replace) && replace)
        replace = json_object_get(replace);
    json_object_object_del(options, "headers_replace");
    if (replace) {
        if (!json_object_is_type(replace, json_type_object)) {
            json_object_put(replace);
            return 0;
        }
        json_object_object_add(options, "headers", replace);
        return 1;
    }
    if (delete_headers) {
        json_object_object_del(options, "headers");
        return 1;
    }
    if (json_object_object_get_ex(options, "headers", &headers) && headers) {
        if (!json_object_is_type(headers, json_type_object))
            return 0;
        if (json_object_object_length(headers) > 0)
            return 1;
        json_object_object_del(options, "headers");
    }
    existing = notifyd_channel_options_existing(id);
    if (existing && json_object_object_get_ex(existing, "headers", &headers) && headers &&
        json_object_is_type(headers, json_type_object))
        json_object_object_add(options, "headers", json_object_get(headers));
    if (existing) json_object_put(existing);
    return 1;
}

struct json_object *notifyd_channels_update(struct json_object *body)
{
    const char *id = notifyd_json_str(body, "id", "");
    const char *name = notifyd_json_str(body, "name", "");
    const char *type = notifyd_json_str(body, "type", "noop");
    int enabled = notifyd_json_bool(body, "enabled", 1);
    struct json_object *options = NULL;
    const char *options_s;
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    int ok = 0;
    int64_t now = notifyd_now_s();
    int64_t expected_updated_at = notifyd_json_i64(body, "expected_updated_at", -1);
    int64_t current_updated_at = 0;

    json_object_object_get_ex(body, "options", &options);
    if (options)
        options = json_object_get(options);
    else
        options = json_object_new_object();
    if (!id[0] || !notifyd_id_ok(id) || !notifyd_token_ok(type, 31) ||
        !notifyd_text_ok(name, 127) || !notifyd_json_fits(options, NOTIFYD_MAX_JSON - 1)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_channel"));
        json_object_put(options);
        return resp;
    }
    if (strcmp(type, "noop") && strcmp(type, "webhook") && strcmp(type, "email")) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("unsupported_channel_type"));
        json_object_put(options);
        return resp;
    }
    if (!notifyd_config_revision_matches(
            "SELECT updated_at FROM notifyd_channels WHERE id=?1", id,
            expected_updated_at, &current_updated_at)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("revision_conflict"));
        json_object_object_add(resp, "current_updated_at",
                               json_object_new_int64(current_updated_at));
        json_object_put(options);
        return resp;
    }
    if (!strcmp(type, "webhook") &&
        !notifyd_channel_options_merge_headers(id, body, options)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error",
                               json_object_new_string("invalid_webhook_headers_action"));
        json_object_put(options);
        return resp;
    }
    if (!strcmp(type, "webhook") && !notifyd_webhook_options_ok(options)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_webhook_options"));
        json_object_put(options);
        return resp;
    }
    if (!strcmp(type, "email") && !notifyd_email_options_ok(options)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_email_options"));
        json_object_put(options);
        return resp;
    }
    options_s = options ? json_object_to_json_string(options) : "{}";
    st = notifyd_config_prepare(
        "INSERT INTO notifyd_channels(id,name,type,enabled,options_json,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?6) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name,type=excluded.type,enabled=excluded.enabled,"
        "options_json=excluded.options_json,updated_at=excluded.updated_at");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, type, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 4, enabled);
        sqlite3_bind_text(st, 5, options_s ? options_s : "{}", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 6, now);
        ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "id", json_object_new_string(id));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("save_failed"));
    json_object_put(options);
    return resp;
}

struct json_object *notifyd_channels_delete(struct json_object *body)
{
    const char *id = notifyd_json_str(body, "id", "");
    struct json_object *resp = json_object_new_object();
    sqlite3_stmt *st;
    int routes = 0, pending = 0, is_default = 0, ok = 0;

    if (!notifyd_id_ok(id)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_channel_id"));
        return resp;
    }
    if (!strcmp(id, "local")) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("builtin_channel_protected"));
        return resp;
    }
    st = notifyd_config_prepare(
        "SELECT channel_id,options_json FROM notifyd_routes");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *top_channel = notifyd_sqlite_text(st, 0, "local");
            struct json_object *stored_options;
            struct json_object *actions = NULL;
            size_t i;
            int referenced = !strcmp(top_channel, id);

            if (!referenced) {
                stored_options = notifyd_json_parse_or_object(
                    notifyd_sqlite_text(st, 1, "{}"));
                if (json_object_object_get_ex(stored_options, "actions", &actions) &&
                    actions && json_object_is_type(actions, json_type_array)) {
                    for (i = 0; i < json_object_array_length(actions); i++) {
                        struct json_object *action = json_object_array_get_idx(actions, i);
                        if (!strcmp(notifyd_json_str(action, "channel_id", ""), id)) {
                            referenced = 1;
                            break;
                        }
                    }
                }
                json_object_put(stored_options);
            }
            if (referenced)
                routes++;
        }
        sqlite3_finalize(st);
    }
    st = notifyd_config_prepare("SELECT COUNT(*) FROM notifyd_settings WHERE id=1 AND default_channel_id=?1");
    if (st) { sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT); if (sqlite3_step(st) == SQLITE_ROW) is_default = sqlite3_column_int(st, 0); sqlite3_finalize(st); }
    st = notifyd_prepare("SELECT COUNT(*) FROM notify_outbox WHERE channel_id=?1 AND state IN ('pending','retry')");
    if (st) { sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT); if (sqlite3_step(st) == SQLITE_ROW) pending = sqlite3_column_int(st, 0); sqlite3_finalize(st); }
    if (routes || is_default || pending) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("channel_in_use"));
        json_object_object_add(resp, "route_references", json_object_new_int(routes));
        json_object_object_add(resp, "default_channel", json_object_new_boolean(is_default));
        json_object_object_add(resp, "pending_deliveries", json_object_new_int(pending));
        return resp;
    }
    st = notifyd_config_prepare("DELETE FROM notifyd_channels WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_notify_config_db) == 1;
        sqlite3_finalize(st);
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "id", json_object_new_string(id));
    if (!ok) json_object_object_add(resp, "error", json_object_new_string("channel_not_found"));
    return resp;
}

static int notifyd_route_object_key_allowed(const char *key,
                                            const char *const *allowed,
                                            size_t allowed_count)
{
    size_t i;

    for (i = 0; i < allowed_count; i++)
        if (!strcmp(key, allowed[i]))
            return 1;
    return 0;
}

static int notifyd_route_object_keys_ok(struct json_object *object,
                                        const char *const *allowed,
                                        size_t allowed_count,
                                        const char **bad_key)
{
    if (bad_key)
        *bad_key = "";
    if (!object || !json_object_is_type(object, json_type_object))
        return 0;
    json_object_object_foreach(object, key, value) {
        (void)value;
        if (!notifyd_route_object_key_allowed(key, allowed, allowed_count)) {
            if (bad_key)
                *bad_key = key;
            return 0;
        }
    }
    return 1;
}

static int notifyd_route_device_timezone(char *out, size_t out_len)
{
    sqlite3_stmt *st;

    if (!out || out_len == 0)
        return 0;
    snprintf(out, out_len, "%s", "Asia/Shanghai");
    st = notifyd_config_prepare("SELECT timezone FROM system_settings WHERE id=1");
    if (!st)
        return 1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *timezone = notifyd_sqlite_text(st, 0, "Asia/Shanghai");
        if (timezone[0] && strlen(timezone) < out_len)
            snprintf(out, out_len, "%s", timezone);
    }
    sqlite3_finalize(st);
    return 1;
}

static int notifyd_route_timezone_ok(const char *timezone)
{
    char path[256];
    struct stat st;
    const unsigned char *p;

    if (!timezone || !timezone[0] || strlen(timezone) > 96 || timezone[0] == '/' ||
        strstr(timezone, "..") || strchr(timezone, '\\'))
        return 0;
    for (p = (const unsigned char *)timezone; *p; p++)
        if (!(isalnum(*p) || *p == '_' || *p == '-' || *p == '+' || *p == '/'))
            return 0;
    snprintf(path, sizeof(path), "/usr/share/zoneinfo/%s", timezone);
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static int notifyd_route_hhmm(const char *value)
{
    int hour, minute;

    if (!value || strlen(value) != 5 || value[2] != ':' ||
        !isdigit((unsigned char)value[0]) || !isdigit((unsigned char)value[1]) ||
        !isdigit((unsigned char)value[3]) || !isdigit((unsigned char)value[4]))
        return -1;
    hour = (value[0] - '0') * 10 + value[1] - '0';
    minute = (value[3] - '0') * 10 + value[4] - '0';
    if (hour > 23 || minute > 59)
        return -1;
    return hour * 60 + minute;
}

static int notifyd_route_template_ok(const char *text, size_t max_len)
{
    static const char *const variables[] = {
        "event", "category", "severity", "source", "target", "detail", "title", "ts"
    };
    const char *p;

    if (!text || !notifyd_text_ok(text, max_len) || strchr(text, '\r'))
        return 0;
    for (p = text; *p; p++) {
        const char *end;
        size_t len;
        size_t i;
        int known = 0;

        if (*p == '}')
            return 0;
        if (*p != '{')
            continue;
        end = strchr(p + 1, '}');
        if (!end || end == p + 1)
            return 0;
        len = (size_t)(end - p - 1);
        for (i = 0; i < sizeof(variables) / sizeof(variables[0]); i++)
            if (strlen(variables[i]) == len && !strncmp(p + 1, variables[i], len)) {
                known = 1;
                break;
            }
        if (!known)
            return 0;
        p = end;
    }
    return 1;
}

static int notifyd_route_subject_ok(const char *text)
{
    return notifyd_route_template_ok(text, NOTIFYD_MAX_TEMPLATE_SUBJECT) &&
        !strchr(text, '\n') && !strchr(text, '\t');
}

static struct json_object *notifyd_route_options_clone(struct json_object *options)
{
    struct json_object *copy = NULL;
    const char *serialized;

    if (!options || !json_object_is_type(options, json_type_object))
        return json_object_new_object();
    serialized = json_object_to_json_string(options);
    if (serialized)
        copy = json_tokener_parse(serialized);
    if (!copy || !json_object_is_type(copy, json_type_object)) {
        if (copy)
            json_object_put(copy);
        copy = json_object_new_object();
    }
    return copy;
}

static struct json_object *notifyd_global_mute_error(const char *reason,
                                                     const char *field)
{
    struct json_object *resp = json_object_new_object();

    json_object_object_add(resp, "ok", json_object_new_boolean(0));
    json_object_object_add(resp, "error", json_object_new_string("invalid_settings"));
    json_object_object_add(resp, "feature", json_object_new_string("mute_schedule"));
    json_object_object_add(resp, "reason",
                           json_object_new_string(reason ? reason : "mute_schedule_invalid"));
    if (field && field[0])
        json_object_object_add(resp, "field", json_object_new_string(field));
    return resp;
}

static int notifyd_global_mute_normalize(struct json_object *input,
                                         struct json_object **normalized_out,
                                         struct json_object **error_out)
{
    static const char *const mute_keys[] = { "enabled", "timezone", "windows" };
    static const char *const window_keys[] = { "days", "start", "end" };
    struct json_object *normalized = NULL, *windows = NULL, *value = NULL;
    struct json_object *windows_copy = NULL;
    const char *bad_key = "";
    const char *timezone;
    char device_timezone[128];
    int enabled;
    int ranges[7][NOTIFYD_MAX_ROUTE_WINDOWS][2];
    int range_count[7] = {0};
    size_t i, j;

    if (normalized_out)
        *normalized_out = NULL;
    if (error_out)
        *error_out = NULL;
    if (!input || !json_object_is_type(input, json_type_object)) {
        if (error_out)
            *error_out = notifyd_global_mute_error("mute_schedule_object_required",
                                                   "mute_schedule");
        return 0;
    }
    if (!notifyd_route_object_keys_ok(input, mute_keys,
            sizeof(mute_keys) / sizeof(mute_keys[0]), &bad_key)) {
        if (error_out)
            *error_out = notifyd_global_mute_error("mute_schedule_field_unsupported",
                                                   bad_key);
        return 0;
    }
    if (json_object_object_get_ex(input, "enabled", &value) &&
        !json_object_is_type(value, json_type_boolean)) {
        if (error_out)
            *error_out = notifyd_global_mute_error("mute_schedule_enabled_invalid",
                                                   "mute_schedule.enabled");
        return 0;
    }
    enabled = notifyd_json_bool(input, "enabled", 0);
    notifyd_route_device_timezone(device_timezone, sizeof(device_timezone));
    timezone = notifyd_json_str(input, "timezone", device_timezone);
    if ((json_object_object_get_ex(input, "timezone", &value) &&
         !json_object_is_type(value, json_type_string)) ||
        !notifyd_route_timezone_ok(timezone)) {
        if (error_out)
            *error_out = notifyd_global_mute_error("mute_schedule_timezone_invalid",
                                                   "mute_schedule.timezone");
        return 0;
    }
    normalized = json_object_new_object();
    windows_copy = json_object_new_array();
    if (!normalized || !windows_copy)
        goto oom;
    if (json_object_object_get_ex(input, "windows", &windows)) {
        if (!windows || !json_object_is_type(windows, json_type_array) ||
            json_object_array_length(windows) > NOTIFYD_MAX_ROUTE_WINDOWS) {
            if (error_out)
                *error_out = notifyd_global_mute_error("mute_schedule_windows_invalid",
                                                       "mute_schedule.windows");
            goto fail;
        }
    }
    if (enabled && (!windows || json_object_array_length(windows) == 0)) {
        if (error_out)
            *error_out = notifyd_global_mute_error("mute_schedule_windows_required",
                                                   "mute_schedule.windows");
        goto fail;
    }
    for (i = 0; windows && i < json_object_array_length(windows); i++) {
        struct json_object *window = json_object_array_get_idx(windows, i);
        struct json_object *days = NULL;
        int start, end;
        char field[96];

        if (!window || !json_object_is_type(window, json_type_object) ||
            !notifyd_route_object_keys_ok(window, window_keys,
                sizeof(window_keys) / sizeof(window_keys[0]), &bad_key)) {
            snprintf(field, sizeof(field), "mute_schedule.windows[%zu]", i);
            if (error_out)
                *error_out = notifyd_global_mute_error("mute_schedule_window_invalid", field);
            goto fail;
        }
        start = notifyd_route_hhmm(notifyd_json_str(window, "start", ""));
        end = notifyd_route_hhmm(notifyd_json_str(window, "end", ""));
        if (start < 0 || end <= start ||
            !json_object_object_get_ex(window, "days", &days) || !days ||
            !json_object_is_type(days, json_type_array) ||
            json_object_array_length(days) == 0 || json_object_array_length(days) > 7) {
            snprintf(field, sizeof(field), "mute_schedule.windows[%zu]", i);
            if (error_out)
                *error_out = notifyd_global_mute_error("mute_schedule_window_invalid", field);
            goto fail;
        }
        for (j = 0; j < json_object_array_length(days); j++) {
            struct json_object *day_value = json_object_array_get_idx(days, j);
            int day;
            int k;

            if (!day_value || !json_object_is_type(day_value, json_type_int) ||
                (day = json_object_get_int(day_value)) < 1 || day > 7) {
                snprintf(field, sizeof(field), "mute_schedule.windows[%zu].days[%zu]", i, j);
                if (error_out)
                    *error_out = notifyd_global_mute_error("mute_schedule_day_invalid", field);
                goto fail;
            }
            for (k = 0; k < range_count[day - 1]; k++)
                if (start < ranges[day - 1][k][1] && end > ranges[day - 1][k][0]) {
                    snprintf(field, sizeof(field), "mute_schedule.windows[%zu]", i);
                    if (error_out)
                        *error_out = notifyd_global_mute_error("mute_schedule_window_overlap", field);
                    goto fail;
                }
            ranges[day - 1][range_count[day - 1]][0] = start;
            ranges[day - 1][range_count[day - 1]][1] = end;
            range_count[day - 1]++;
        }
        json_object_array_add(windows_copy, notifyd_route_options_clone(window));
    }
    json_object_object_add(normalized, "enabled", json_object_new_boolean(enabled));
    json_object_object_add(normalized, "timezone", json_object_new_string(timezone));
    json_object_object_add(normalized, "windows", windows_copy);
    if (!notifyd_json_fits(normalized, NOTIFYD_MAX_JSON - 1)) {
        if (error_out)
            *error_out = notifyd_global_mute_error("mute_schedule_too_large",
                                                   "mute_schedule");
        json_object_put(normalized);
        return 0;
    }
    if (normalized_out)
        *normalized_out = normalized;
    else
        json_object_put(normalized);
    return 1;

oom:
    if (error_out)
        *error_out = notifyd_global_mute_error("allocation_failed", "mute_schedule");
fail:
    if (windows_copy)
        json_object_put(windows_copy);
    if (normalized)
        json_object_put(normalized);
    return 0;
}

static int notifyd_route_contract_build(struct json_object *input,
                                        const char *top_channel,
                                        const char *top_severity,
                                        int top_channel_present,
                                        int top_severity_present,
                                        int strict,
                                        struct notifyd_route_contract *out,
                                        struct json_object **error_out)
{
    static const char *const option_keys[] = {
        "schema_version", "schedule", "actions", "receivers", "content", "dedupe"
    };
    static const char *const schedule_keys[] = { "mode", "timezone", "windows" };
    static const char *const window_keys[] = { "days", "start", "end" };
    static const char *const action_keys[] = { "type", "channel_id", "min_severity" };
    static const char *const receiver_keys[] = { "mode", "user_ids", "recipients" };
    static const char *const content_keys[] = { "mode", "subject", "body" };
    static const char *const dedupe_keys[] = { "enabled", "window_seconds", "key_fields" };
    static const char *const dedupe_fields[] = { "event", "source", "target", "category", "severity" };
    struct json_object *canonical = notifyd_route_options_clone(strict ? NULL : input);
    struct json_object *schedule = NULL, *actions = NULL, *receivers = NULL;
    struct json_object *content = NULL, *dedupe = NULL, *value = NULL;
    struct json_object *normalized;
    const char *bad_key = "";
    char device_timezone[128];
    size_t i, j;

#define ROUTE_FAIL(code, feature_name, field_name, action_no) do { \
    if (error_out) *error_out = notifyd_route_error((code), (feature_name), (field_name), (action_no)); \
    json_object_put(canonical); \
    return 0; \
} while (0)

    if (error_out)
        *error_out = NULL;
    if (!out)
        ROUTE_FAIL("invalid_route", "", "options", -1);
    memset(out, 0, sizeof(*out));
    snprintf(out->channel_id, sizeof(out->channel_id), "%s",
             top_channel && top_channel[0] ? top_channel : "local");
    snprintf(out->min_severity, sizeof(out->min_severity), "%s",
             top_severity && top_severity[0] ? top_severity : "warning");
    if (strict && input && !json_object_is_type(input, json_type_object))
        ROUTE_FAIL("invalid_route", "", "options", -1);
    if (!input || !json_object_is_type(input, json_type_object))
        input = NULL;
    if (strict && input && !notifyd_route_object_keys_ok(input, option_keys,
            sizeof(option_keys) / sizeof(option_keys[0]), &bad_key))
        ROUTE_FAIL("route_feature_unsupported", bad_key, bad_key, -1);
    if (input && json_object_object_get_ex(input, "schema_version", &value)) {
        if (!json_object_is_type(value, json_type_int) ||
            json_object_get_int(value) != NOTIFYD_ROUTE_SCHEMA_VERSION)
            ROUTE_FAIL("route_feature_unsupported", "schema_version", "options.schema_version", -1);
    }
    json_object_object_add(canonical, "schema_version",
                           json_object_new_int(NOTIFYD_ROUTE_SCHEMA_VERSION));

    if (input)
        json_object_object_get_ex(input, "schedule", &schedule);
    normalized = json_object_new_object();
    if (!schedule || !json_object_is_type(schedule, json_type_object)) {
        if (strict && schedule)
            ROUTE_FAIL("schedule_invalid", "schedule", "options.schedule", -1);
        json_object_object_add(normalized, "mode", json_object_new_string("always"));
    } else {
        const char *mode = notifyd_json_str(schedule, "mode", "always");
        if (json_object_object_get_ex(schedule, "mode", &value) &&
            !json_object_is_type(value, json_type_string))
            ROUTE_FAIL("schedule_invalid", "schedule", "options.schedule.mode", -1);
        if (strict && !notifyd_route_object_keys_ok(schedule, schedule_keys,
                sizeof(schedule_keys) / sizeof(schedule_keys[0]), &bad_key))
            ROUTE_FAIL("schedule_invalid", "schedule", bad_key, -1);
        if (strcmp(mode, "always") && strcmp(mode, "custom"))
            ROUTE_FAIL("schedule_invalid", "schedule", "options.schedule.mode", -1);
        json_object_object_add(normalized, "mode", json_object_new_string(mode));
        if (!strcmp(mode, "custom")) {
            struct json_object *windows = NULL;
            const char *timezone = notifyd_json_str(schedule, "timezone", "");
            int ranges[7][NOTIFYD_MAX_ROUTE_WINDOWS][2];
            int range_count[7] = {0};

            if (!timezone[0]) {
                notifyd_route_device_timezone(device_timezone, sizeof(device_timezone));
                timezone = device_timezone;
            }
            if (json_object_object_get_ex(schedule, "timezone", &value) &&
                !json_object_is_type(value, json_type_string))
                ROUTE_FAIL("schedule_invalid", "schedule", "options.schedule.timezone", -1);
            if (!notifyd_route_timezone_ok(timezone))
                ROUTE_FAIL("schedule_invalid", "schedule", "options.schedule.timezone", -1);
            if (!json_object_object_get_ex(schedule, "windows", &windows) || !windows ||
                !json_object_is_type(windows, json_type_array) ||
                json_object_array_length(windows) == 0 ||
                json_object_array_length(windows) > NOTIFYD_MAX_ROUTE_WINDOWS)
                ROUTE_FAIL("schedule_window_invalid", "schedule", "options.schedule.windows", -1);
            json_object_object_add(normalized, "timezone", json_object_new_string(timezone));
            {
                struct json_object *windows_copy = json_object_new_array();
                for (i = 0; i < json_object_array_length(windows); i++) {
                    struct json_object *window = json_object_array_get_idx(windows, i);
                    struct json_object *days = NULL;
                    int start, end;
                    char field[96];

                    if (!window || !json_object_is_type(window, json_type_object) ||
                        (strict && !notifyd_route_object_keys_ok(window, window_keys,
                            sizeof(window_keys) / sizeof(window_keys[0]), &bad_key))) {
                        snprintf(field, sizeof(field), "options.schedule.windows[%zu]", i);
                        ROUTE_FAIL("schedule_window_invalid", "schedule", field, -1);
                    }
                    start = notifyd_route_hhmm(notifyd_json_str(window, "start", ""));
                    end = notifyd_route_hhmm(notifyd_json_str(window, "end", ""));
                    if (start < 0 || end <= start ||
                        !json_object_object_get_ex(window, "days", &days) || !days ||
                        !json_object_is_type(days, json_type_array) ||
                        json_object_array_length(days) == 0 || json_object_array_length(days) > 7) {
                        snprintf(field, sizeof(field), "options.schedule.windows[%zu]", i);
                        ROUTE_FAIL("schedule_window_invalid", "schedule", field, -1);
                    }
                    for (j = 0; j < json_object_array_length(days); j++) {
                        struct json_object *day_value = json_object_array_get_idx(days, j);
                        int day;
                        int k;
                        if (!day_value || !json_object_is_type(day_value, json_type_int) ||
                            (day = json_object_get_int(day_value)) < 1 || day > 7) {
                            snprintf(field, sizeof(field), "options.schedule.windows[%zu].days[%zu]", i, j);
                            ROUTE_FAIL("schedule_window_invalid", "schedule", field, -1);
                        }
                        for (k = 0; k < range_count[day - 1]; k++)
                            if (start < ranges[day - 1][k][1] && end > ranges[day - 1][k][0]) {
                                snprintf(field, sizeof(field), "options.schedule.windows[%zu]", i);
                                ROUTE_FAIL("schedule_window_invalid", "schedule", field, -1);
                            }
                        ranges[day - 1][range_count[day - 1]][0] = start;
                        ranges[day - 1][range_count[day - 1]][1] = end;
                        range_count[day - 1]++;
                    }
                    json_object_array_add(windows_copy, notifyd_route_options_clone(window));
                }
                json_object_object_add(normalized, "windows", windows_copy);
            }
        } else if (strict &&
                   (json_object_object_get_ex(schedule, "timezone", &value) ||
                    json_object_object_get_ex(schedule, "windows", &value))) {
            ROUTE_FAIL("schedule_invalid", "schedule", "options.schedule", -1);
        }
    }
    json_object_object_add(canonical, "schedule", normalized);

    if (input)
        json_object_object_get_ex(input, "actions", &actions);
    normalized = json_object_new_array();
    if (!actions) {
        struct notifyd_channel channel;
        struct json_object *action = json_object_new_object();

        if (strict && (!notifyd_channel_get(out->channel_id, &channel) || !channel.enabled)) {
            json_object_put(action);
            ROUTE_FAIL("action_invalid", "multi_action", "channel_id", 0);
        }
        if (strict && strcmp(channel.type, "noop") && strcmp(channel.type, "webhook") &&
            strcmp(channel.type, "email")) {
            json_object_put(action);
            ROUTE_FAIL("channel_incompatible", "multi_action", "channel_id", 0);
        }
        json_object_object_add(action, "type", json_object_new_string("notify"));
        json_object_object_add(action, "channel_id", json_object_new_string(out->channel_id));
        json_object_object_add(action, "min_severity", json_object_new_string(out->min_severity));
        json_object_array_add(normalized, action);
    } else {
        if (!json_object_is_type(actions, json_type_array) ||
            json_object_array_length(actions) == 0 ||
            json_object_array_length(actions) > NOTIFYD_MAX_ROUTE_ACTIONS)
            ROUTE_FAIL("action_invalid", "multi_action", "options.actions", -1);
        for (i = 0; i < json_object_array_length(actions); i++) {
            struct json_object *action = json_object_array_get_idx(actions, i);
            struct notifyd_channel channel;
            const char *type, *channel_id, *min_severity;
            struct json_object *action_copy;

            if (!action || !json_object_is_type(action, json_type_object) ||
                (strict && !notifyd_route_object_keys_ok(action, action_keys,
                    sizeof(action_keys) / sizeof(action_keys[0]), &bad_key)))
                ROUTE_FAIL("action_invalid", "multi_action", "options.actions", (int)i);
            type = notifyd_json_str(action, "type", "");
            channel_id = notifyd_json_str(action, "channel_id", "");
            min_severity = notifyd_json_str(action, "min_severity", "");
            if (strcmp(type, "notify") || !notifyd_id_ok(channel_id) ||
                !notifyd_severity_valid(min_severity))
                ROUTE_FAIL("action_invalid", "multi_action", "options.actions", (int)i);
            if (strict && (!notifyd_channel_get(channel_id, &channel) || !channel.enabled))
                ROUTE_FAIL("action_invalid", "multi_action", "options.actions.channel_id", (int)i);
            if (strict && strcmp(channel.type, "noop") && strcmp(channel.type, "webhook") &&
                strcmp(channel.type, "email"))
                ROUTE_FAIL("channel_incompatible", "multi_action", "options.actions.channel_id", (int)i);
            for (j = 0; j < i; j++) {
                struct json_object *previous = json_object_array_get_idx(normalized, j);
                if (!strcmp(channel_id, notifyd_json_str(previous, "channel_id", "")))
                    ROUTE_FAIL("duplicate_action", "multi_action", "options.actions.channel_id", (int)i);
            }
            if (i == 0) {
                if ((top_channel_present && strcmp(out->channel_id, channel_id)) ||
                    (top_severity_present && strcmp(out->min_severity, min_severity)))
                    ROUTE_FAIL("route_action_conflict", "multi_action", "options.actions[0]", 0);
                snprintf(out->channel_id, sizeof(out->channel_id), "%s", channel_id);
                snprintf(out->min_severity, sizeof(out->min_severity), "%s", min_severity);
            }
            action_copy = json_object_new_object();
            json_object_object_add(action_copy, "type", json_object_new_string("notify"));
            json_object_object_add(action_copy, "channel_id", json_object_new_string(channel_id));
            json_object_object_add(action_copy, "min_severity", json_object_new_string(min_severity));
            json_object_array_add(normalized, action_copy);
        }
    }
    json_object_object_add(canonical, "actions", normalized);

    if (input)
        json_object_object_get_ex(input, "receivers", &receivers);
    normalized = json_object_new_object();
    if (!receivers || !json_object_is_type(receivers, json_type_object)) {
        if (strict && receivers)
            ROUTE_FAIL("receiver_invalid", "rule_receivers", "options.receivers", -1);
        json_object_object_add(normalized, "mode", json_object_new_string("channel"));
    } else {
        const char *mode = notifyd_json_str(receivers, "mode", "channel");
        struct json_object *items = NULL;
        int has_user_ids = json_object_object_get_ex(receivers, "user_ids", &value);
        int has_recipients = json_object_object_get_ex(receivers, "recipients", &value);
        if (json_object_object_get_ex(receivers, "mode", &value) &&
            !json_object_is_type(value, json_type_string))
            ROUTE_FAIL("receiver_invalid", "rule_receivers", "options.receivers.mode", -1);
        if (strict && !notifyd_route_object_keys_ok(receivers, receiver_keys,
                sizeof(receiver_keys) / sizeof(receiver_keys[0]), &bad_key))
            ROUTE_FAIL("receiver_invalid", "rule_receivers", bad_key, -1);
        if (strcmp(mode, "channel") && strcmp(mode, "admins") &&
            strcmp(mode, "users") && strcmp(mode, "emails"))
            ROUTE_FAIL("receiver_invalid", "rule_receivers", "options.receivers.mode", -1);
        if (strict && ((!strcmp(mode, "users") && has_recipients) ||
                       (!strcmp(mode, "emails") && has_user_ids) ||
                       ((!strcmp(mode, "channel") || !strcmp(mode, "admins")) &&
                        (has_user_ids || has_recipients))))
            ROUTE_FAIL("receiver_invalid", "rule_receivers", "options.receivers", -1);
        json_object_object_add(normalized, "mode", json_object_new_string(mode));
        if (!strcmp(mode, "users")) {
            struct json_object *copy = json_object_new_array();
            if (!json_object_object_get_ex(receivers, "user_ids", &items) || !items ||
                !json_object_is_type(items, json_type_array) ||
                json_object_array_length(items) == 0 ||
                json_object_array_length(items) > NOTIFYD_MAX_ROUTE_RECEIVERS)
                ROUTE_FAIL("receiver_invalid", "rule_receivers", "options.receivers.user_ids", -1);
            for (i = 0; i < json_object_array_length(items); i++) {
                struct json_object *item = json_object_array_get_idx(items, i);
                const char *id = item && json_object_is_type(item, json_type_string) ?
                    json_object_get_string(item) : "";
                if (!notifyd_id_ok(id))
                    ROUTE_FAIL("receiver_invalid", "rule_receivers", "options.receivers.user_ids", -1);
                for (j = 0; j < i; j++)
                    if (!strcmp(id, json_object_get_string(json_object_array_get_idx(copy, j))))
                        ROUTE_FAIL("receiver_invalid", "rule_receivers", "options.receivers.user_ids", -1);
                json_object_array_add(copy, json_object_new_string(id));
            }
            json_object_object_add(normalized, "user_ids", copy);
        } else if (!strcmp(mode, "emails")) {
            struct json_object *copy = json_object_new_array();
            if (!json_object_object_get_ex(receivers, "recipients", &items) || !items ||
                !json_object_is_type(items, json_type_array) ||
                json_object_array_length(items) == 0 ||
                json_object_array_length(items) > NOTIFYD_MAX_ROUTE_RECEIVERS)
                ROUTE_FAIL("receiver_invalid", "rule_receivers", "options.receivers.recipients", -1);
            for (i = 0; i < json_object_array_length(items); i++) {
                struct json_object *item = json_object_array_get_idx(items, i);
                const char *email = item && json_object_is_type(item, json_type_string) ?
                    json_object_get_string(item) : "";
                if (!notifyd_route_email_ok(email))
                    ROUTE_FAIL("receiver_invalid", "rule_receivers", "options.receivers.recipients", -1);
                for (j = 0; j < i; j++)
                    if (!strcasecmp(email, json_object_get_string(json_object_array_get_idx(copy, j))))
                        ROUTE_FAIL("receiver_invalid", "rule_receivers", "options.receivers.recipients", -1);
                json_object_array_add(copy, json_object_new_string(email));
            }
            json_object_object_add(normalized, "recipients", copy);
        }
    }
    if (strcmp(notifyd_json_str(normalized, "mode", "channel"), "channel")) {
        struct json_object *canonical_actions = NULL;
        json_object_object_get_ex(canonical, "actions", &canonical_actions);
        for (i = 0; canonical_actions && i < json_object_array_length(canonical_actions); i++) {
            struct notifyd_channel channel;
            struct json_object *action = json_object_array_get_idx(canonical_actions, i);
            if (notifyd_channel_get(notifyd_json_str(action, "channel_id", ""), &channel) &&
                strcmp(channel.type, "email"))
                ROUTE_FAIL("receiver_mode_incompatible", "rule_receivers",
                           "options.receivers.mode", (int)i);
        }
    }
    json_object_object_add(canonical, "receivers", normalized);

    if (input)
        json_object_object_get_ex(input, "content", &content);
    normalized = json_object_new_object();
    if (!content || !json_object_is_type(content, json_type_object)) {
        if (strict && content)
            ROUTE_FAIL("content_template_invalid", "custom_content", "options.content", -1);
        json_object_object_add(normalized, "mode", json_object_new_string("default"));
    } else {
        const char *mode = notifyd_json_str(content, "mode", "default");
        int has_subject = json_object_object_get_ex(content, "subject", &value);
        int has_body = json_object_object_get_ex(content, "body", &value);
        if (json_object_object_get_ex(content, "mode", &value) &&
            !json_object_is_type(value, json_type_string))
            ROUTE_FAIL("content_template_invalid", "custom_content", "options.content.mode", -1);
        if (strict && !notifyd_route_object_keys_ok(content, content_keys,
                sizeof(content_keys) / sizeof(content_keys[0]), &bad_key))
            ROUTE_FAIL("content_template_invalid", "custom_content", bad_key, -1);
        if (strcmp(mode, "default") && strcmp(mode, "custom"))
            ROUTE_FAIL("content_template_invalid", "custom_content", "options.content.mode", -1);
        if (strict && !strcmp(mode, "default") && (has_subject || has_body))
            ROUTE_FAIL("content_template_invalid", "custom_content", "options.content", -1);
        json_object_object_add(normalized, "mode", json_object_new_string(mode));
        if (!strcmp(mode, "custom")) {
            const char *subject = notifyd_json_str(content, "subject", "");
            const char *template_body = notifyd_json_str(content, "body", "");
            if (!subject[0] || !template_body[0] ||
                !notifyd_route_subject_ok(subject) ||
                !notifyd_route_template_ok(template_body, NOTIFYD_MAX_TEMPLATE_BODY))
                ROUTE_FAIL("content_template_invalid", "custom_content", "options.content", -1);
            json_object_object_add(normalized, "subject", json_object_new_string(subject));
            json_object_object_add(normalized, "body", json_object_new_string(template_body));
        }
    }
    json_object_object_add(canonical, "content", normalized);

    if (input)
        json_object_object_get_ex(input, "dedupe", &dedupe);
    normalized = json_object_new_object();
    if (!dedupe || !json_object_is_type(dedupe, json_type_object)) {
        if (strict && dedupe)
            ROUTE_FAIL("dedupe_window_invalid", "route_dedupe", "options.dedupe", -1);
        json_object_object_add(normalized, "enabled", json_object_new_boolean(0));
        json_object_object_add(normalized, "window_seconds", json_object_new_int(0));
    } else {
        int enabled = notifyd_json_bool(dedupe, "enabled", 0);
        int window = notifyd_json_int(dedupe, "window_seconds", 0);
        struct json_object *fields = NULL;
        struct json_object *copy = json_object_new_array();
        if (json_object_object_get_ex(dedupe, "enabled", &value) &&
            !json_object_is_type(value, json_type_boolean)) {
            json_object_put(copy);
            ROUTE_FAIL("dedupe_window_invalid", "route_dedupe", "options.dedupe.enabled", -1);
        }
        if (json_object_object_get_ex(dedupe, "window_seconds", &value) &&
            !json_object_is_type(value, json_type_int)) {
            json_object_put(copy);
            ROUTE_FAIL("dedupe_window_invalid", "route_dedupe", "options.dedupe.window_seconds", -1);
        }
        if (strict && !notifyd_route_object_keys_ok(dedupe, dedupe_keys,
                sizeof(dedupe_keys) / sizeof(dedupe_keys[0]), &bad_key))
            ROUTE_FAIL("dedupe_key_invalid", "route_dedupe", bad_key, -1);
        if (!enabled || window == 0) {
            enabled = 0;
            window = 0;
        } else if (window < 1 || window > NOTIFYD_MAX_DEDUPE_WINDOW) {
            json_object_put(copy);
            ROUTE_FAIL("dedupe_window_invalid", "route_dedupe", "options.dedupe.window_seconds", -1);
        }
        if (enabled) {
            if (!json_object_object_get_ex(dedupe, "key_fields", &fields) || !fields ||
                !json_object_is_type(fields, json_type_array) ||
                json_object_array_length(fields) == 0 ||
                json_object_array_length(fields) > sizeof(dedupe_fields) / sizeof(dedupe_fields[0])) {
                json_object_put(copy);
                ROUTE_FAIL("dedupe_key_invalid", "route_dedupe", "options.dedupe.key_fields", -1);
            }
            for (i = 0; i < json_object_array_length(fields); i++) {
                struct json_object *field_value = json_object_array_get_idx(fields, i);
                const char *field = field_value && json_object_is_type(field_value, json_type_string) ?
                    json_object_get_string(field_value) : "";
                if (!notifyd_route_object_key_allowed(field, dedupe_fields,
                        sizeof(dedupe_fields) / sizeof(dedupe_fields[0]))) {
                    json_object_put(copy);
                    ROUTE_FAIL("dedupe_key_invalid", "route_dedupe", "options.dedupe.key_fields", -1);
                }
                for (j = 0; j < i; j++)
                    if (!strcmp(field, json_object_get_string(json_object_array_get_idx(copy, j)))) {
                        json_object_put(copy);
                        ROUTE_FAIL("dedupe_key_invalid", "route_dedupe", "options.dedupe.key_fields", -1);
                    }
                json_object_array_add(copy, json_object_new_string(field));
            }
        }
        json_object_object_add(normalized, "enabled", json_object_new_boolean(enabled));
        json_object_object_add(normalized, "window_seconds", json_object_new_int(window));
        if (enabled)
            json_object_object_add(normalized, "key_fields", copy);
        else
            json_object_put(copy);
    }
    json_object_object_add(canonical, "dedupe", normalized);

    if (!notifyd_json_fits(canonical, NOTIFYD_MAX_JSON - 1))
        ROUTE_FAIL("invalid_route", "", "options", -1);
    out->options = canonical;
    return 1;
#undef ROUTE_FAIL
}

static void notifyd_route_contract_clear(struct notifyd_route_contract *contract)
{
    if (contract && contract->options) {
        json_object_put(contract->options);
        contract->options = NULL;
    }
}

static void notifyd_route_row_json(struct json_object *arr, sqlite3_stmt *st)
{
    const char *options_s = notifyd_sqlite_text(st, 8, "{}");
    struct json_object *stored_options = notifyd_json_parse_or_object(options_s);
    struct notifyd_route_contract contract;
    struct json_object *o = json_object_new_object();

    memset(&contract, 0, sizeof(contract));
    (void)notifyd_route_contract_build(stored_options,
        notifyd_sqlite_text(st, 3, "local"),
        notifyd_sqlite_text(st, 4, "warning"), 1, 1, 0, &contract, NULL);

    json_object_object_add(o, "id", json_object_new_string(notifyd_sqlite_text(st, 0, "")));
    json_object_object_add(o, "name", json_object_new_string(notifyd_sqlite_text(st, 1, "")));
    json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 2)));
    json_object_object_add(o, "channel_id", json_object_new_string(notifyd_sqlite_text(st, 3, "")));
    json_object_object_add(o, "min_severity", json_object_new_string(notifyd_sqlite_text(st, 4, "warning")));
    json_object_object_add(o, "category", json_object_new_string(notifyd_sqlite_text(st, 5, "")));
    json_object_object_add(o, "event", json_object_new_string(notifyd_sqlite_text(st, 6, "")));
    json_object_object_add(o, "source", json_object_new_string(notifyd_sqlite_text(st, 7, "")));
    json_object_object_add(o, "options", contract.options ?
                           json_object_get(contract.options) : json_object_get(stored_options));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 9)));
    {
        sqlite3_stmt *trigger = notifyd_prepare(
            "SELECT COUNT(*),COALESCE(MAX(triggered_at),0) FROM notify_route_triggers "
            "WHERE route_id=?1");
        sqlite3_stmt *outbox = notifyd_prepare(
            "SELECT COUNT(*) FROM notify_outbox WHERE route_id=?1");
        sqlite3_stmt *deliveries = notifyd_prepare(
            "SELECT COUNT(*) FROM notify_deliveries d JOIN notify_outbox o "
            "ON o.id=d.outbox_id WHERE o.route_id=?1");
        int64_t trigger_count = 0, last_triggered_at = 0;
        int64_t outbox_count = 0, delivery_count = 0;
        const char *route_id = notifyd_sqlite_text(st, 0, "");

        if (trigger) {
            sqlite3_bind_text(trigger, 1, route_id, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(trigger) == SQLITE_ROW) {
                trigger_count = sqlite3_column_int64(trigger, 0);
                last_triggered_at = sqlite3_column_int64(trigger, 1);
            }
            sqlite3_finalize(trigger);
        }
        if (outbox) {
            sqlite3_bind_text(outbox, 1, route_id, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(outbox) == SQLITE_ROW)
                outbox_count = sqlite3_column_int64(outbox, 0);
            sqlite3_finalize(outbox);
        }
        if (deliveries) {
            sqlite3_bind_text(deliveries, 1, route_id, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(deliveries) == SQLITE_ROW)
                delivery_count = sqlite3_column_int64(deliveries, 0);
            sqlite3_finalize(deliveries);
        }
        json_object_object_add(o, "trigger_count", json_object_new_int64(trigger_count));
        json_object_object_add(o, "last_triggered_at", json_object_new_int64(last_triggered_at));
        json_object_object_add(o, "outbox_count", json_object_new_int64(outbox_count));
        json_object_object_add(o, "delivery_count", json_object_new_int64(delivery_count));
    }
    {
        sqlite3_stmt *suppression = notifyd_prepare(
            "SELECT COUNT(*),COALESCE(MAX(ts),0) FROM notify_route_suppressions "
            "WHERE route_id=?1");
        sqlite3_stmt *last = notifyd_prepare(
            "SELECT reason,event FROM notify_route_suppressions "
            "WHERE route_id=?1 ORDER BY ts DESC,id DESC LIMIT 1");
        int count = 0;
        int64_t last_at = 0;

        json_object_object_add(o, "last_suppression_reason",
                               json_object_new_string(""));
        json_object_object_add(o, "last_suppressed_event",
                               json_object_new_string(""));

        if (suppression) {
            sqlite3_bind_text(suppression, 1, notifyd_sqlite_text(st, 0, ""),
                              -1, SQLITE_TRANSIENT);
            if (sqlite3_step(suppression) == SQLITE_ROW) {
                count = sqlite3_column_int(suppression, 0);
                last_at = sqlite3_column_int64(suppression, 1);
            }
            sqlite3_finalize(suppression);
        }
        if (last) {
            sqlite3_bind_text(last, 1, notifyd_sqlite_text(st, 0, ""),
                              -1, SQLITE_TRANSIENT);
            if (sqlite3_step(last) == SQLITE_ROW) {
                json_object_object_add(o, "last_suppression_reason",
                                       json_object_new_string(
                                           notifyd_sqlite_text(last, 0, "")));
                json_object_object_add(o, "last_suppressed_event",
                                       json_object_new_string(
                                           notifyd_sqlite_text(last, 1, "")));
            }
            sqlite3_finalize(last);
        }
        json_object_object_add(o, "suppression_count", json_object_new_int(count));
        json_object_object_add(o, "last_suppressed_at", json_object_new_int64(last_at));
    }
    json_object_array_add(arr, o);
    notifyd_route_contract_clear(&contract);
    json_object_put(stored_options);
}

struct json_object *notifyd_routes_json(void)
{
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    int ok = 1;
    int rc;

    st = notifyd_config_prepare("SELECT id,name,enabled,channel_id,min_severity,category,event,source,options_json,updated_at FROM notifyd_routes ORDER BY id");
    if (st) {
        while ((rc = sqlite3_step(st)) == SQLITE_ROW)
            notifyd_route_row_json(arr, st);
        if (rc != SQLITE_DONE)
            ok = 0;
        sqlite3_finalize(st);
    } else {
        ok = 0;
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("routes_query_failed"));
    json_object_object_add(resp, "routes", arr);
    return resp;
}

struct json_object *notifyd_routes_update(struct json_object *body)
{
    const char *id = notifyd_json_str(body, "id", "");
    const char *name = notifyd_json_str(body, "name", "");
    const char *channel = notifyd_json_str(body, "channel_id", "local");
    const char *min_sev = notifyd_json_str(body, "min_severity", "warning");
    const char *category = notifyd_json_str(body, "category", "");
    const char *event = notifyd_json_str(body, "event", "");
    const char *source = notifyd_json_str(body, "source", "");
    int enabled = notifyd_json_bool(body, "enabled", 1);
    struct json_object *options = NULL;
    struct json_object *value = NULL;
    struct json_object *error_resp = NULL;
    struct notifyd_route_contract contract;
    const char *options_s;
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    int ok = 0;
    int64_t now = notifyd_now_s();
    int64_t expected_updated_at = notifyd_json_i64(body, "expected_updated_at", -1);
    int64_t current_updated_at = 0;

    int top_channel_present = body && json_object_object_get_ex(body, "channel_id", &value);
    int top_severity_present = body && json_object_object_get_ex(body, "min_severity", &value);

    memset(&contract, 0, sizeof(contract));
    if (!body || !json_object_is_type(body, json_type_object)) {
        json_object_put(resp);
        return notifyd_route_error("invalid_route", "", "body", -1);
    }
    json_object_object_get_ex(body, "options", &options);
    if (!id[0] || !notifyd_id_ok(id) || !notifyd_id_ok(channel) ||
        !notifyd_text_ok(name, 127) || !notifyd_text_ok(category, 64) ||
        !notifyd_text_ok(event, 128) || !notifyd_text_ok(source, 128) ||
        !notifyd_severity_valid(min_sev) || !notifyd_json_fits(options, NOTIFYD_MAX_JSON - 1)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_route"));
        return resp;
    }
    if (json_object_object_get_ex(body, "schedule", &value) ||
        json_object_object_get_ex(body, "actions", &value) ||
        json_object_object_get_ex(body, "receivers", &value) ||
        json_object_object_get_ex(body, "content", &value) ||
        json_object_object_get_ex(body, "dedupe", &value)) {
        json_object_put(resp);
        return notifyd_route_error("route_feature_unsupported", "options_required",
                                   "options", -1);
    }
    if (!notifyd_route_contract_build(options, channel, min_sev,
            top_channel_present, top_severity_present, 1, &contract, &error_resp)) {
        json_object_put(resp);
        return error_resp ? error_resp :
            notifyd_route_error("invalid_route", "", "options", -1);
    }
    channel = contract.channel_id;
    min_sev = contract.min_severity;
    if (notifyd_exec(g_notify_config_db, "BEGIN IMMEDIATE") != 0) {
        notifyd_route_contract_clear(&contract);
        json_object_put(resp);
        return notifyd_route_error("transaction_busy", "", "options", -1);
    }
    if (!notifyd_config_revision_matches(
            "SELECT updated_at FROM notifyd_routes WHERE id=?1", id,
            expected_updated_at, &current_updated_at)) {
        (void)notifyd_exec(g_notify_config_db, "ROLLBACK");
        notifyd_route_contract_clear(&contract);
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("revision_conflict"));
        json_object_object_add(resp, "current_updated_at",
                               json_object_new_int64(current_updated_at));
        return resp;
    }
    if (now <= current_updated_at)
        now = current_updated_at + 1;
    options_s = json_object_to_json_string(contract.options);
    st = notifyd_config_prepare(
        "INSERT INTO notifyd_routes(id,name,enabled,channel_id,min_severity,category,event,source,options_json,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name,enabled=excluded.enabled,channel_id=excluded.channel_id,"
        "min_severity=excluded.min_severity,category=excluded.category,event=excluded.event,source=excluded.source,"
        "options_json=excluded.options_json,updated_at=excluded.updated_at");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, enabled);
        sqlite3_bind_text(st, 4, channel, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, min_sev, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, category, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, event, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, source, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, options_s ? options_s : "{}", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 10, now);
        ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    if (ok)
        ok = notifyd_exec(g_notify_config_db, "COMMIT") == 0;
    if (!ok)
        (void)notifyd_exec(g_notify_config_db, "ROLLBACK");
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "id", json_object_new_string(id));
    if (ok) {
        json_object_object_add(resp, "channel_id", json_object_new_string(channel));
        json_object_object_add(resp, "min_severity", json_object_new_string(min_sev));
        json_object_object_add(resp, "options", json_object_get(contract.options));
        json_object_object_add(resp, "updated_at", json_object_new_int64(now));
    }
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("save_failed"));
    notifyd_route_contract_clear(&contract);
    return resp;
}

struct json_object *notifyd_routes_delete(struct json_object *body)
{
    const char *id = notifyd_json_str(body, "id", "");
    struct json_object *resp = json_object_new_object();
    sqlite3_stmt *st;
    int ok = 0;

    if (!notifyd_id_ok(id)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_route_id"));
        return resp;
    }
    if (!strcmp(id, "default-warning")) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("builtin_route_protected"));
        return resp;
    }
    st = notifyd_config_prepare("DELETE FROM notifyd_routes WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_notify_config_db) == 1;
        sqlite3_finalize(st);
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "id", json_object_new_string(id));
    if (!ok) json_object_object_add(resp, "error", json_object_new_string("route_not_found"));
    return resp;
}

/* ── Per-user notification preference ───────────────────────────────────────
 *
 * Scope: whether one authenticated user receives the notifications a route has
 * already produced. Nothing here disables a route, a channel, or the notifyd
 * service, and one user's mute never changes what another recipient of the same
 * event receives.
 *
 * The identity always arrives from webd, which derives it from the session
 * ("web:<username>") and overwrites whatever the client sent. notifyd still
 * validates it: ubus is reachable by root-local callers as well.
 */

static struct json_object *notifyd_preference_error(const char *error,
                                                    const char *field,
                                                    const char *reason)
{
    struct json_object *resp = json_object_new_object();

    json_object_object_add(resp, "ok", json_object_new_boolean(0));
    json_object_object_add(resp, "error",
                           json_object_new_string(error ? error :
                               "notification_preference_invalid"));
    if (field && field[0])
        json_object_object_add(resp, "field", json_object_new_string(field));
    if (reason && reason[0])
        json_object_object_add(resp, "reason", json_object_new_string(reason));
    return resp;
}

/*
 * web_users.username, same character set webd enforces when it creates the
 * account. Deliberately stricter than notifyd_token_ok(), which also admits
 * ':' and '/' and would let an identity string such as "web:lester" through as
 * if it were a username.
 */
static int notifyd_pref_username_ok(const char *username)
{
    const unsigned char *p;

    if (!username || !username[0] || strlen(username) > 64)
        return 0;
    for (p = (const unsigned char *)username; *p; p++) {
        if (!(isalnum(*p) || *p == '_' || *p == '-' || *p == '.'))
            return 0;
    }
    return 1;
}

static int notifyd_pref_user_exists(const char *username, int *db_ok)
{
    sqlite3_stmt *st;
    int found = 0;

    if (db_ok) *db_ok = 0;
    st = notifyd_config_prepare(
        "SELECT 1 FROM web_users WHERE username=?1 AND status='enabled'");
    if (!st)
        return 0;
    if (db_ok) *db_ok = 1;
    sqlite3_bind_text(st, 1, username, -1, SQLITE_TRANSIENT);
    found = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return found;
}

/*
 * A mute may only name channels that can address one user. An email channel
 * resolves per-recipient, so muting it silences that user alone; a webhook or a
 * noop channel has a single destination shared by everyone the route notifies,
 * so "mute it for me" would in fact mute it for all of them. Refused rather
 * than silently widened.
 */
static int notifyd_pref_channel_addressable(const char *channel_id,
                                            const char **reason)
{
    struct notifyd_channel channel;

    if (!notifyd_channel_get(channel_id, &channel)) {
        if (reason) *reason = "channel_not_found";
        return 0;
    }
    if (strcmp(channel.type, "email")) {
        if (reason) *reason = "channel_type_not_user_addressable";
        return 0;
    }
    return 1;
}

static struct json_object *notifyd_pref_channels_normalize(
    struct json_object *input, struct json_object **error_out)
{
    struct json_object *out = json_object_new_array();
    size_t i, n;

    if (error_out) *error_out = NULL;
    if (!input || json_object_is_type(input, json_type_null))
        return out;
    if (!json_object_is_type(input, json_type_array)) {
        json_object_put(out);
        if (error_out)
            *error_out = notifyd_preference_error("notification_preference_invalid",
                                                  "channel_ids", "not_an_array");
        return NULL;
    }
    n = json_object_array_length(input);
    if (n > NOTIFYD_MAX_PREF_CHANNELS) {
        json_object_put(out);
        if (error_out)
            *error_out = notifyd_preference_error("notification_preference_invalid",
                                                  "channel_ids", "too_many_channels");
        return NULL;
    }
    for (i = 0; i < n; i++) {
        struct json_object *item = json_object_array_get_idx(input, i);
        const char *channel_id;
        const char *reason = "channel_invalid";
        size_t j;
        int duplicate = 0;

        if (!item || !json_object_is_type(item, json_type_string)) {
            json_object_put(out);
            if (error_out)
                *error_out = notifyd_preference_error(
                    "notification_preference_channel_invalid",
                    "channel_ids", "not_a_string");
            return NULL;
        }
        channel_id = json_object_get_string(item);
        if (!notifyd_id_ok(channel_id)) {
            json_object_put(out);
            if (error_out)
                *error_out = notifyd_preference_error(
                    "notification_preference_channel_invalid",
                    "channel_ids", "channel_id_invalid");
            return NULL;
        }
        if (!notifyd_pref_channel_addressable(channel_id, &reason)) {
            json_object_put(out);
            if (error_out)
                *error_out = notifyd_preference_error(
                    "notification_preference_channel_invalid",
                    "channel_ids", reason);
            return NULL;
        }
        for (j = 0; j < json_object_array_length(out); j++) {
            if (!strcmp(json_object_get_string(json_object_array_get_idx(out, j)),
                        channel_id)) {
                duplicate = 1;
                break;
            }
        }
        if (!duplicate)
            json_object_array_add(out, json_object_new_string(channel_id));
    }
    return out;
}

struct notifyd_user_preference {
    char username[72];
    int muted;
    int64_t muted_until;
    char channel_ids_json[NOTIFYD_MAX_JSON];
    int64_t created_at;
    int64_t updated_at;
    int stored;
};

static int notifyd_pref_load(const char *username,
                             struct notifyd_user_preference *out, int *db_ok)
{
    sqlite3_stmt *st;
    int rc;

    if (!out)
        return 0;
    memset(out, 0, sizeof(*out));
    snprintf(out->username, sizeof(out->username), "%s", username ? username : "");
    snprintf(out->channel_ids_json, sizeof(out->channel_ids_json), "%s", "[]");
    if (db_ok) *db_ok = 0;
    st = notifyd_config_prepare(
        "SELECT muted,muted_until,channel_ids_json,created_at,updated_at "
        "FROM notifyd_user_preferences WHERE username=?1");
    if (!st)
        return 0;
    if (db_ok) *db_ok = 1;
    sqlite3_bind_text(st, 1, username ? username : "", -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        out->muted = sqlite3_column_int(st, 0) ? 1 : 0;
        out->muted_until = sqlite3_column_int64(st, 1);
        snprintf(out->channel_ids_json, sizeof(out->channel_ids_json), "%s",
                 notifyd_sqlite_text(st, 2, "[]"));
        out->created_at = sqlite3_column_int64(st, 3);
        out->updated_at = sqlite3_column_int64(st, 4);
        out->stored = 1;
    } else if (rc != SQLITE_DONE) {
        if (db_ok) *db_ok = 0;
    }
    sqlite3_finalize(st);
    return out->stored;
}

/*
 * Effective mute at time `now`. An expired window reads as not muted without
 * any row being rewritten, so recovery does not depend on a timer firing, on
 * the browser staying open, or on the client's clock.
 */
static int notifyd_pref_mute_effective(const struct notifyd_user_preference *pref,
                                       int64_t now)
{
    if (!pref || !pref->muted)
        return 0;
    if (pref->muted_until > 0 && pref->muted_until <= now)
        return 0;
    return 1;
}

static struct json_object *notifyd_pref_json(const struct notifyd_user_preference *pref)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *channels;
    int64_t now = notifyd_now_s();
    int effective;

    channels = pref ? json_tokener_parse(pref->channel_ids_json) : NULL;
    if (!channels || !json_object_is_type(channels, json_type_array)) {
        if (channels) json_object_put(channels);
        channels = json_object_new_array();
    }
    effective = notifyd_pref_mute_effective(pref, now);

    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "schema_version", json_object_new_int(1));
    json_object_object_add(resp, "username",
                           json_object_new_string(pref ? pref->username : ""));
    json_object_object_add(resp, "muted", json_object_new_boolean(effective));
    /*
     * `muted_stored` keeps the saved intent visible next to the effective
     * answer: a lapsed timed mute reports muted=false with muted_stored=true,
     * so the UI can say "expired" instead of "you never set this".
     */
    json_object_object_add(resp, "muted_stored",
                           json_object_new_boolean(pref && pref->muted));
    json_object_object_add(resp, "muted_until",
                           json_object_new_int64(pref ? pref->muted_until : 0));
    json_object_object_add(resp, "mute_mode", json_object_new_string(
        !effective ? "off" : (pref->muted_until > 0 ? "until" : "permanent")));
    json_object_object_add(resp, "expired", json_object_new_boolean(
        pref && pref->muted && pref->muted_until > 0 && !effective));
    json_object_object_add(resp, "channel_ids", channels);
    json_object_object_add(resp, "scope", json_object_new_string(
        json_object_array_length(channels) ? "channels" : "all_channels"));
    json_object_object_add(resp, "stored",
                           json_object_new_boolean(pref && pref->stored));
    json_object_object_add(resp, "created_at",
                           json_object_new_int64(pref ? pref->created_at : 0));
    json_object_object_add(resp, "updated_at",
                           json_object_new_int64(pref ? pref->updated_at : 0));
    json_object_object_add(resp, "max_duration_s",
                           json_object_new_int(NOTIFYD_USER_MUTE_MAX_DURATION_S));
    json_object_object_add(resp, "now", json_object_new_int64(now));
    json_object_object_add(resp, "source",
                           json_object_new_string("config.db:notifyd_user_preferences"));
    return resp;
}

struct json_object *notifyd_preferences_get(struct json_object *body)
{
    struct notifyd_user_preference pref;
    const char *username = notifyd_json_str(body, "username", "");
    struct json_object *resp;
    int db_ok = 0;

    if (!notifyd_pref_username_ok(username))
        return notifyd_preference_error("notification_preference_forbidden",
                                        "username", "session_identity_required");
    notifyd_pref_load(username, &pref, &db_ok);
    if (!db_ok)
        return notifyd_preference_error("notification_preference_invalid",
                                        "", "preferences_query_failed");
    /*
     * No row is a definite answer, not a missing one: the user has never set a
     * preference, so they are not muted. Returned as ok:true with stored=false
     * rather than a 404, which a client would otherwise have to interpret.
     */
    resp = notifyd_pref_json(&pref);
    return resp;
}

struct json_object *notifyd_preferences_update(struct json_object *body)
{
    struct notifyd_user_preference pref;
    struct json_object *resp;
    struct json_object *channels_input = NULL;
    struct json_object *channels = NULL;
    struct json_object *channel_error = NULL;
    const char *username = notifyd_json_str(body, "username", "");
    const char *channels_s;
    sqlite3_stmt *st;
    int64_t expected_updated_at = notifyd_json_i64(body, "expected_updated_at", -1);
    int64_t current_updated_at = 0;
    int64_t now = notifyd_now_s();
    int64_t muted_until;
    int muted;
    int db_ok = 0;
    int user_db_ok = 0;
    int ok = 0;

    if (!body || !json_object_is_type(body, json_type_object))
        return notifyd_preference_error("notification_preference_invalid", "body",
                                        "object_required");
    if (!notifyd_pref_username_ok(username))
        return notifyd_preference_error("notification_preference_forbidden",
                                        "username", "session_identity_required");
    if (!notifyd_pref_user_exists(username, &user_db_ok)) {
        return notifyd_preference_error("notification_preference_forbidden",
                                        "username",
                                        user_db_ok ? "user_not_eligible" :
                                                     "user_directory_unavailable");
    }
    {
        struct json_object *muted_o = NULL;

        if (!json_object_object_get_ex(body, "muted", &muted_o) || !muted_o)
            return notifyd_preference_error("notification_preference_invalid",
                                            "muted", "field_required");
        if (!json_object_is_type(muted_o, json_type_boolean))
            return notifyd_preference_error("notification_preference_invalid",
                                            "muted", "boolean_required");
        muted = json_object_get_boolean(muted_o) ? 1 : 0;
    }
    muted_until = notifyd_json_i64(body, "muted_until", 0);
    if (muted_until < 0)
        return notifyd_preference_error("notification_preference_invalid",
                                        "muted_until", "negative");
    if (!muted) {
        /*
         * Unmuting clears the window instead of preserving it. Keeping a stale
         * expiry would make a later "mute me" silently inherit a deadline the
         * user did not choose this time.
         */
        muted_until = 0;
    } else if (muted_until > 0) {
        if (muted_until <= now)
            return notifyd_preference_error("notification_preference_invalid",
                                            "muted_until", "already_elapsed");
        if (muted_until - now > NOTIFYD_USER_MUTE_MAX_DURATION_S)
            return notifyd_preference_error("notification_preference_invalid",
                                            "muted_until", "exceeds_max_duration");
    }
    if (json_object_object_get_ex(body, "channel_ids", &channels_input)) {
        channels = notifyd_pref_channels_normalize(channels_input, &channel_error);
        if (!channels)
            return channel_error ? channel_error :
                notifyd_preference_error("notification_preference_channel_invalid",
                                         "channel_ids", "channel_invalid");
    } else {
        /* Omitted means "keep what is stored", so an unmute does not silently
         * widen a channel-scoped mute back to every channel. */
        struct notifyd_user_preference existing;

        notifyd_pref_load(username, &existing, &db_ok);
        channels = json_tokener_parse(existing.channel_ids_json);
        if (!channels || !json_object_is_type(channels, json_type_array)) {
            if (channels) json_object_put(channels);
            channels = json_object_new_array();
        }
    }
    channels_s = json_object_to_json_string(channels);
    if (!channels_s || strlen(channels_s) >= NOTIFYD_MAX_JSON) {
        json_object_put(channels);
        return notifyd_preference_error("notification_preference_invalid",
                                        "channel_ids", "too_large");
    }

    if (notifyd_exec(g_notify_config_db, "BEGIN IMMEDIATE") != 0) {
        json_object_put(channels);
        return notifyd_preference_error("notification_preference_invalid", "",
                                        "transaction_busy");
    }
    if (!notifyd_config_revision_matches(
            "SELECT updated_at FROM notifyd_user_preferences WHERE username=?1",
            username, expected_updated_at, &current_updated_at)) {
        (void)notifyd_exec(g_notify_config_db, "ROLLBACK");
        json_object_put(channels);
        resp = notifyd_preference_error("notification_preference_revision_conflict",
                                        "expected_updated_at", "stale_revision");
        json_object_object_add(resp, "current_updated_at",
                               json_object_new_int64(current_updated_at));
        return resp;
    }
    if (now <= current_updated_at)
        now = current_updated_at + 1;
    st = notifyd_config_prepare(
        "INSERT INTO notifyd_user_preferences(username,muted,muted_until,channel_ids_json,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?5) "
        "ON CONFLICT(username) DO UPDATE SET muted=excluded.muted,"
        "muted_until=excluded.muted_until,channel_ids_json=excluded.channel_ids_json,"
        "updated_at=excluded.updated_at");
    if (st) {
        sqlite3_bind_text(st, 1, username, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, muted);
        sqlite3_bind_int64(st, 3, muted_until);
        sqlite3_bind_text(st, 4, channels_s, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 5, now);
        ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    if (ok)
        ok = notifyd_exec(g_notify_config_db, "COMMIT") == 0;
    if (!ok)
        (void)notifyd_exec(g_notify_config_db, "ROLLBACK");
    json_object_put(channels);
    if (!ok)
        return notifyd_preference_error("notification_preference_invalid", "",
                                        "save_failed");
    notifyd_pref_load(username, &pref, &db_ok);
    if (!db_ok)
        return notifyd_preference_error("notification_preference_invalid", "",
                                        "preferences_query_failed");
    resp = notifyd_pref_json(&pref);
    json_object_object_add(resp, "saved", json_object_new_boolean(1));
    return resp;
}

int notifyd_user_mute_active(const char *username, const char *channel_id)
{
    struct notifyd_user_preference pref;
    struct json_object *channels;
    size_t i, n;
    int db_ok = 0;
    int scoped_hit = 0;

    if (!notifyd_pref_username_ok(username))
        return 0;
    if (!notifyd_pref_load(username, &pref, &db_ok) || !db_ok)
        return 0;
    if (!notifyd_pref_mute_effective(&pref, notifyd_now_s()))
        return 0;
    channels = json_tokener_parse(pref.channel_ids_json);
    if (!channels || !json_object_is_type(channels, json_type_array)) {
        if (channels) json_object_put(channels);
        return 1;               /* no channel scope: mute applies everywhere */
    }
    n = json_object_array_length(channels);
    if (n == 0) {
        json_object_put(channels);
        return 1;
    }
    for (i = 0; i < n && !scoped_hit; i++) {
        const char *id = json_object_get_string(json_object_array_get_idx(channels, i));

        if (id && channel_id && !strcmp(id, channel_id))
            scoped_hit = 1;
    }
    json_object_put(channels);
    return scoped_hit;
}

int notifyd_channel_get(const char *id, struct notifyd_channel *out)
{
    sqlite3_stmt *st;
    int found = 0;

    if (!id || !id[0] || !out)
        return 0;
    memset(out, 0, sizeof(*out));
    st = notifyd_config_prepare("SELECT id,name,type,enabled,options_json FROM notifyd_channels WHERE id=?1");
    if (!st)
        return 0;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        snprintf(out->id, sizeof(out->id), "%s", sqlite3_column_text(st, 0) ? (const char *)sqlite3_column_text(st, 0) : "");
        snprintf(out->name, sizeof(out->name), "%s", sqlite3_column_text(st, 1) ? (const char *)sqlite3_column_text(st, 1) : "");
        snprintf(out->type, sizeof(out->type), "%s", sqlite3_column_text(st, 2) ? (const char *)sqlite3_column_text(st, 2) : "noop");
        out->enabled = sqlite3_column_int(st, 3);
        snprintf(out->options_json, sizeof(out->options_json), "%s", sqlite3_column_text(st, 4) ? (const char *)sqlite3_column_text(st, 4) : "{}");
        found = 1;
    }
    sqlite3_finalize(st);
    return found;
}

/*
 * A recovery event is exempt from min_severity, because the pair is asymmetric
 * in severity but symmetric in usefulness: WAN_DOWN is warning and passes, its
 * clearing event WAN_RESTORED is notice and did not, so the only live route
 * (default-warning) delivered "internet is down" and never "it came back".
 * The user was left holding an alarm nothing could clear.
 *
 * Exemption is deliberately narrow. It keys off recovers_event, so it covers
 * only the half of a pair that clears a prior alarm, and it never lowers the
 * threshold for ordinary low-severity chatter (SYSTEM_LOG, DHCP_EVENT and the
 * other notice/info events stay filtered). category/event/source selectors are
 * still applied, so an operator scoping a route to one category keeps that
 * scope. The catalog reports this per event as severity_exempt.
 */
static int notifyd_event_is_recovery(const char *event_id)
{
    const struct dw_event_definition *def;

    if (!event_id || !event_id[0])
        return 0;
    def = notifyd_event_definition_find(event_id);
    return def && def->recovers_event[0] ? 1 : 0;
}

static int notifyd_route_matches(sqlite3_stmt *st, struct json_object *body)
{
    const char *category = (const char *)sqlite3_column_text(st, 5);
    const char *event = (const char *)sqlite3_column_text(st, 6);
    const char *source = (const char *)sqlite3_column_text(st, 7);
    const char *ev_category = notifyd_json_str(body, "category", "");
    const char *ev_event = notifyd_json_str(body, "event", "");
    const char *ev_source = notifyd_json_str(body, "source", "");

    if (category && category[0] && strcmp(category, ev_category))
        return 0;
    if (event && event[0] && strcmp(event, ev_event))
        return 0;
    if (source && source[0] && strcmp(source, ev_source))
        return 0;
    return 1;
}

static int notifyd_route_schedule_allows(struct json_object *options, int64_t now,
                                         const char **reason)
{
    struct json_object *schedule = NULL, *windows = NULL;
    const char *mode;
    const char *timezone;
    const char *previous_tz = getenv("TZ");
    char *saved_tz = previous_tz ? strdup(previous_tz) : NULL;
    struct tm local_tm;
    time_t wall_time = (time_t)now;
    int iso_day;
    int minute;
    size_t i, j;
    int allowed = 0;

    if (reason)
        *reason = "schedule_outside_window";
    if (!options || !json_object_object_get_ex(options, "schedule", &schedule) ||
        !schedule || !json_object_is_type(schedule, json_type_object))
        return 1;
    mode = notifyd_json_str(schedule, "mode", "always");
    if (!strcmp(mode, "always"))
        return 1;
    timezone = notifyd_json_str(schedule, "timezone", "Asia/Shanghai");
    if (setenv("TZ", timezone, 1) != 0) {
        free(saved_tz);
        if (reason)
            *reason = "schedule_timezone_unavailable";
        return 0;
    }
    tzset();
    if (!localtime_r(&wall_time, &local_tm)) {
        if (saved_tz)
            setenv("TZ", saved_tz, 1);
        else
            unsetenv("TZ");
        tzset();
        free(saved_tz);
        if (reason)
            *reason = "schedule_time_unavailable";
        return 0;
    }
    iso_day = local_tm.tm_wday == 0 ? 7 : local_tm.tm_wday;
    minute = local_tm.tm_hour * 60 + local_tm.tm_min;
    if (json_object_object_get_ex(schedule, "windows", &windows) && windows &&
        json_object_is_type(windows, json_type_array)) {
        for (i = 0; i < json_object_array_length(windows) && !allowed; i++) {
            struct json_object *window = json_object_array_get_idx(windows, i);
            struct json_object *days = NULL;
            int start = notifyd_route_hhmm(notifyd_json_str(window, "start", ""));
            int end = notifyd_route_hhmm(notifyd_json_str(window, "end", ""));

            if (start < 0 || end <= start || minute < start || minute >= end ||
                !json_object_object_get_ex(window, "days", &days) || !days ||
                !json_object_is_type(days, json_type_array))
                continue;
            for (j = 0; j < json_object_array_length(days); j++)
                if (json_object_get_int(json_object_array_get_idx(days, j)) == iso_day) {
                    allowed = 1;
                    break;
                }
        }
    }
    if (saved_tz)
        setenv("TZ", saved_tz, 1);
    else
        unsetenv("TZ");
    tzset();
    free(saved_tz);
    return allowed;
}

static int notifyd_global_mute_active(const struct notifyd_settings *settings,
                                      int64_t now, const char **reason)
{
    struct json_object *mute;
    struct json_object *schedule;
    struct json_object *options;
    int active;
    const char *evaluation_reason = "schedule_outside_window";

    if (reason)
        *reason = "global_mute_schedule_active";
    if (!settings || !settings->mute_schedule_json[0])
        return 0;
    mute = notifyd_json_parse_or_object(settings->mute_schedule_json);
    if (!notifyd_json_bool(mute, "enabled", 0)) {
        json_object_put(mute);
        return 0;
    }
    schedule = notifyd_route_options_clone(mute);
    json_object_object_del(schedule, "enabled");
    json_object_object_add(schedule, "mode", json_object_new_string("custom"));
    options = json_object_new_object();
    json_object_object_add(options, "schedule", schedule);
    active = notifyd_route_schedule_allows(options, now, &evaluation_reason);
    json_object_put(options);
    json_object_put(mute);
    if (active)
        return 1;
    if (strcmp(evaluation_reason, "schedule_outside_window")) {
        if (reason)
            *reason = "global_mute_schedule_unavailable";
        return 1;
    }
    return 0;
}

static int notifyd_route_eligible_actions(struct json_object *options,
                                          struct json_object *body)
{
    struct json_object *actions = NULL;
    size_t i;
    int eligible = 0;
    const char *severity = notifyd_json_str(body, "severity", "info");
    const char *event = notifyd_json_str(body, "event", "");

    if (!options || !json_object_object_get_ex(options, "actions", &actions) ||
        !actions || !json_object_is_type(actions, json_type_array))
        return 0;
    for (i = 0; i < json_object_array_length(actions); i++) {
        struct json_object *action = json_object_array_get_idx(actions, i);
        const char *minimum = notifyd_json_str(action, "min_severity", "warning");

        if (notifyd_severity_rank(severity) >= notifyd_severity_rank(minimum) ||
            notifyd_event_is_recovery(event))
            eligible++;
    }
    return eligible;
}

static void notifyd_route_trigger_record(const char *route_id,
                                         struct json_object *body,
                                         const char *result,
                                         const char *reason,
                                         const char *dedupe_result,
                                         const char *mute_result)
{
    static unsigned int prune_counter;
    sqlite3_stmt *st = notifyd_prepare(
        "INSERT INTO notify_route_triggers(route_id,event,severity,source,triggered_at,"
        "result,reason,dedupe_result,mute_result) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)");

    if (!st)
        return;
    sqlite3_bind_text(st, 1, route_id ? route_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, notifyd_json_str(body, "event", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, notifyd_json_str(body, "severity", "info"), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, notifyd_json_str(body, "source", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 5, notifyd_now_s());
    sqlite3_bind_text(st, 6, result ? result : "unknown", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, reason ? reason : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, dedupe_result ? dedupe_result : "not_applicable", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, mute_result ? mute_result : "not_muted", -1,
                      SQLITE_TRANSIENT);
    (void)sqlite3_step(st);
    sqlite3_finalize(st);
    if ((++prune_counter & 255U) == 0U)
        (void)notifyd_exec(g_notify_db,
            "DELETE FROM notify_route_triggers WHERE id IN ("
            "SELECT id FROM notify_route_triggers ORDER BY id DESC LIMIT -1 OFFSET 20000)");
}

static void notifyd_route_suppression_record(const char *route_id,
                                             struct json_object *body,
                                             const char *reason)
{
    sqlite3_stmt *st;
    const char *payload = body ? json_object_to_json_string(body) : "{}";

    st = notifyd_prepare(
        "INSERT INTO notify_route_suppressions(route_id,ts,reason,event,source,target,payload_json) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7)");
    if (!st)
        return;
    sqlite3_bind_text(st, 1, route_id ? route_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, notifyd_now_s());
    sqlite3_bind_text(st, 3, reason ? reason : "schedule_outside_window", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, notifyd_json_str(body, "event", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, notifyd_json_str(body, "source", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, notifyd_json_str(body, "target", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, payload ? payload : "{}", -1, SQLITE_TRANSIENT);
    (void)sqlite3_step(st);
    sqlite3_finalize(st);
    (void)notifyd_exec(g_notify_db,
        "DELETE FROM notify_route_suppressions WHERE id IN ("
        "SELECT id FROM notify_route_suppressions ORDER BY ts DESC,id DESC LIMIT -1 OFFSET 5000)");
}

static const char *notifyd_route_template_value(struct json_object *body,
                                                const char *key,
                                                char *buffer, size_t buffer_len)
{
    struct json_object *value = NULL;

    if (!strcmp(key, "ts")) {
        snprintf(buffer, buffer_len, "%lld",
                 (long long)notifyd_json_i64(body, "ts", notifyd_now_s()));
        return buffer;
    }
    if (body && json_object_object_get_ex(body, key, &value) && value) {
        if (json_object_is_type(value, json_type_string))
            return json_object_get_string(value);
        snprintf(buffer, buffer_len, "%s", json_object_to_json_string(value));
        return buffer;
    }
    if (!strcmp(key, "detail"))
        return notifyd_json_str(body, "message", "");
    return "";
}

static char *notifyd_route_template_render(const char *template_text,
                                           struct json_object *body,
                                           size_t max_len)
{
    char *out;
    size_t used = 0;
    const char *p;

    out = calloc(1, max_len + 1);
    if (!out)
        return NULL;
    for (p = template_text ? template_text : ""; *p;) {
        if (*p == '{') {
            const char *end = strchr(p + 1, '}');
            char key[32];
            char value_buffer[4096];
            const char *value;
            size_t key_len;
            size_t value_len;

            if (!end || (key_len = (size_t)(end - p - 1)) == 0 || key_len >= sizeof(key))
                goto fail;
            memcpy(key, p + 1, key_len);
            key[key_len] = '\0';
            value = notifyd_route_template_value(body, key, value_buffer, sizeof(value_buffer));
            value_len = strlen(value ? value : "");
            if (used + value_len > max_len)
                goto fail;
            memcpy(out + used, value ? value : "", value_len);
            used += value_len;
            p = end + 1;
        } else {
            if (used + 1 > max_len)
                goto fail;
            out[used++] = *p++;
        }
    }
    out[used] = '\0';
    return out;
fail:
    free(out);
    return NULL;
}

static struct json_object *notifyd_route_payload_render(struct json_object *body,
                                                        struct json_object *options,
                                                        int action_index,
                                                        char *error, size_t error_len)
{
    struct json_object *payload = notifyd_route_options_clone(body);
    struct json_object *content = NULL;
    struct json_object *metadata = json_object_new_object();
    const char *mode = "default";

    if (json_object_object_get_ex(options, "content", &content) && content &&
        json_object_is_type(content, json_type_object))
        mode = notifyd_json_str(content, "mode", "default");
    if (!strcmp(mode, "default")) {
        const char *locale = notifyd_json_str(content, "locale",
                             notifyd_json_str(body, "locale", "zh-CN"));

        if (!dw_event_payload_present(payload, locale)) {
            json_object_put(metadata);
            json_object_put(payload);
            snprintf(error, error_len, "%s", "content_render_failed");
            return NULL;
        }
    } else if (!strcmp(mode, "custom")) {
        char *title = notifyd_route_template_render(
            notifyd_json_str(content, "subject", ""), body, NOTIFYD_MAX_TEMPLATE_SUBJECT);
        char *message = notifyd_route_template_render(
            notifyd_json_str(content, "body", ""), body, NOTIFYD_MAX_TEMPLATE_BODY);
        struct json_object *rendered = json_object_new_object();

        if (!title || !message) {
            free(title);
            free(message);
            json_object_put(rendered);
            json_object_put(metadata);
            json_object_put(payload);
            snprintf(error, error_len, "%s", "content_render_failed");
            return NULL;
        }
        json_object_object_add(payload, "title", json_object_new_string(title));
        json_object_object_add(payload, "message", json_object_new_string(message));
        json_object_object_add(rendered, "title", json_object_new_string(title));
        json_object_object_add(rendered, "body", json_object_new_string(message));
        json_object_object_add(payload, "rendered_content", rendered);
        free(title);
        free(message);
    }
    json_object_object_add(metadata, "schema_version",
                           json_object_new_int(NOTIFYD_ROUTE_SCHEMA_VERSION));
    json_object_object_add(metadata, "action_index", json_object_new_int(action_index));
    json_object_object_add(metadata, "content_mode", json_object_new_string(mode));
    json_object_object_add(payload, "notify_route", metadata);
    if (!notifyd_json_fits(payload, NOTIFYD_MAX_JSON - 1)) {
        json_object_put(payload);
        snprintf(error, error_len, "%s", "content_render_failed");
        return NULL;
    }
    if (error && error_len)
        error[0] = '\0';
    return payload;
}

static uint64_t notifyd_route_dedupe_hash_part(uint64_t hash,
                                               const char *field,
                                               const char *value)
{
    const unsigned char *p;

    for (p = (const unsigned char *)(field ? field : ""); *p; p++) {
        hash ^= *p;
        hash *= UINT64_C(1099511628211);
    }
    hash ^= UINT64_C(0xff);
    hash *= UINT64_C(1099511628211);
    for (p = (const unsigned char *)(value ? value : "unknown"); *p; p++) {
        hash ^= *p;
        hash *= UINT64_C(1099511628211);
    }
    hash ^= 0;
    hash *= UINT64_C(1099511628211);
    return hash;
}

static int notifyd_route_dedupe_contract(struct json_object *options,
                                         struct json_object *body,
                                         char *key, size_t key_len,
                                         char *group, size_t group_len,
                                         int *window_seconds)
{
    struct json_object *dedupe = NULL, *fields = NULL;
    const struct dw_event_definition *definition;
    const char *event;
    const char *pair_event;
    size_t i;
    uint64_t key_hash = UINT64_C(14695981039346656037);
    uint64_t group_hash = UINT64_C(14695981039346656037);

    if (key && key_len)
        key[0] = '\0';
    if (group && group_len)
        group[0] = '\0';
    if (window_seconds)
        *window_seconds = 0;
    if (!options || !json_object_object_get_ex(options, "dedupe", &dedupe) || !dedupe ||
        !json_object_is_type(dedupe, json_type_object) ||
        !notifyd_json_bool(dedupe, "enabled", 0))
        return 0;
    if (window_seconds)
        *window_seconds = notifyd_json_int(dedupe, "window_seconds", 0);
    if (!json_object_object_get_ex(dedupe, "key_fields", &fields) || !fields ||
        !json_object_is_type(fields, json_type_array))
        return 0;
    event = notifyd_json_str(body, "event", "unknown");
    if (!event[0])
        event = "unknown";
    definition = notifyd_event_definition_find(event);
    /*
     * Use the recovery event as the family key. This keeps a simple pair
     * together and also covers several alarms cleared by one recovery event,
     * such as WAN_QUALITY_DEGRADED/WAN_QUALITY_CRITICAL ->
     * WAN_QUALITY_RECOVERED.
     */
    if (definition && definition->recovers_event[0])
        pair_event = event;
    else if (definition && definition->recovery_event[0])
        pair_event = definition->recovery_event;
    else
        pair_event = event;
    group_hash = notifyd_route_dedupe_hash_part(group_hash, "event_pair", pair_event);
    for (i = 0; i < json_object_array_length(fields); i++) {
        const char *field = json_object_get_string(json_object_array_get_idx(fields, i));
        const char *value = notifyd_json_str(body, field, "unknown");

        if (!value || !value[0])
            value = "unknown";
        key_hash = notifyd_route_dedupe_hash_part(key_hash, field, value);
        if (strcmp(field, "event") && strcmp(field, "severity"))
            group_hash = notifyd_route_dedupe_hash_part(group_hash, field, value);
    }
    if (snprintf(key, key_len, "v1-%016" PRIx64, key_hash) >= (int)key_len ||
        snprintf(group, group_len, "g1-%016" PRIx64, group_hash) >= (int)group_len) {
        key[0] = '\0';
        group[0] = '\0';
        return 0;
    }
    return 1;
}

static const char *notifyd_dedupe_key(struct json_object *body)
{
    const char *key;

    key = notifyd_json_str(body, "dedupe_key", "");
    if (key && key[0] && notifyd_text_ok(key, 256))
        return key;
    return "";
}

static int notifyd_coalesce_outbox(const char *channel_id, const char *route_id,
                                   int action_index, struct json_object *body,
                                   const char *delivery_options_json,
                                   const char *producer_dedupe_key,
                                   const char *route_dedupe_key,
                                   const char *dedupe_group,
                                   int dedupe_window_seconds, int max_attempts,
                                   char *out_id, size_t out_id_len)
{
    sqlite3_stmt *st;
    const char *payload = body ? json_object_to_json_string(body) : "{}";
    int64_t now = notifyd_now_s();
    int64_t route_floor = now - (dedupe_window_seconds > 0 ? dedupe_window_seconds : 0);
    char candidate_id[NOTIFYD_MAX_ID] = "";
    int match_mode = 0;
    int rc;

    if ((!producer_dedupe_key || !producer_dedupe_key[0]) &&
        (!route_dedupe_key || !route_dedupe_key[0]))
        return 0;
    st = notifyd_prepare(
        "SELECT id,CASE WHEN (?5<>'' AND route_dedupe_key=?5 AND dedupe_group=?7 AND last_seen>=?6) "
        "THEN 2 ELSE 1 END FROM notify_outbox "
        "WHERE channel_id=?1 AND route_id=?2 AND action_index=?3 "
        "AND state IN ('pending','retry','failed','delivered') AND ("
        " (?4<>'' AND producer_dedupe_key=?4) OR "
        " (?5<>'' AND route_dedupe_key=?5 AND dedupe_group=?7 AND last_seen>=?6)) "
        "ORDER BY CASE WHEN (?5<>'' AND route_dedupe_key=?5 AND dedupe_group=?7 AND last_seen>=?6) "
        "THEN 0 ELSE 1 END,updated_at DESC,id DESC LIMIT 1");
    if (!st)
        return 0;
    sqlite3_bind_text(st, 1, channel_id ? channel_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, route_id ? route_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, action_index);
    sqlite3_bind_text(st, 4, producer_dedupe_key ? producer_dedupe_key : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, route_dedupe_key ? route_dedupe_key : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, route_floor);
    sqlite3_bind_text(st, 7, dedupe_group ? dedupe_group : "", -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        snprintf(candidate_id, sizeof(candidate_id), "%s", notifyd_sqlite_text(st, 0, ""));
        match_mode = sqlite3_column_int(st, 1);
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW || !candidate_id[0] || (match_mode != 1 && match_mode != 2))
        return 0;
    st = notifyd_prepare(
        "UPDATE notify_outbox SET updated_at=?1,"
        "next_attempt_at=CASE WHEN ?2=1 THEN ?1 ELSE next_attempt_at END,"
        "event_id=?3,severity=?4,category=?5,event=?6,source=?7,title=?8,"
        "payload_json=?9,state=CASE WHEN ?2=1 THEN 'pending' ELSE state END,"
        "attempts=CASE WHEN ?2=1 THEN 0 ELSE attempts END,"
        "max_attempts=CASE WHEN ?2=1 THEN ?10 ELSE max_attempts END,"
        "last_seen=?1,count=count+1,"
        "last_error=CASE WHEN ?2=1 THEN '' ELSE last_error END,"
        "last_warning=CASE WHEN ?2=1 THEN '' ELSE last_warning END,"
        "last_http_status=CASE WHEN ?2=1 THEN 0 ELSE last_http_status END,"
        "delivery_options_json=?11,dedupe_group=?12,"
        "dedupe_key=CASE WHEN ?2=1 THEN ?13 ELSE dedupe_key END,"
        "producer_dedupe_key=CASE WHEN ?2=1 THEN ?14 ELSE producer_dedupe_key END,"
        "route_dedupe_key=?15 WHERE id=?16");
    if (!st)
        return 0;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_int(st, 2, match_mode);
    sqlite3_bind_text(st, 3, notifyd_json_str(body, "id", notifyd_json_str(body, "event_id", "")), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, notifyd_severity(notifyd_json_str(body, "severity", "info")), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, notifyd_json_str(body, "category", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, notifyd_json_str(body, "event", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, notifyd_json_str(body, "source", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, notifyd_json_str(body, "title", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, payload ? payload : "{}", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 10, max_attempts);
    sqlite3_bind_text(st, 11, delivery_options_json ? delivery_options_json : "{}", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 12, dedupe_group ? dedupe_group : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 13, producer_dedupe_key ? producer_dedupe_key : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 14, producer_dedupe_key ? producer_dedupe_key : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 15, route_dedupe_key ? route_dedupe_key : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 16, candidate_id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE || sqlite3_changes(g_notify_db) != 1)
        return 0;
    if (out_id && out_id_len > 0)
        snprintf(out_id, out_id_len, "%s", candidate_id);
    return match_mode;
}

static int notifyd_insert_outbox_ex(const char *channel_id, const char *route_id,
                                    int action_index, struct json_object *body,
                                    struct json_object *delivery_options,
                                    const char *producer_dedupe_key,
                                    const char *route_dedupe_key,
                                    const char *dedupe_group,
                                    int dedupe_window_seconds, int max_attempts,
                                    char *out_id, size_t out_id_len)
{
    sqlite3_stmt *st;
    char id[NOTIFYD_MAX_ID];
    const char *payload = body ? json_object_to_json_string(body) : "{}";
    const char *delivery_options_json = delivery_options ?
        json_object_to_json_string(delivery_options) : "{}";
    int64_t now = notifyd_now_s();
    int ok = 0;
    const char *severity = notifyd_severity(notifyd_json_str(body, "severity", "info"));
    /* The persistent outbox must leave the critical recovery reserve intact. */
    enum jmx_storage_write_priority priority = !strcmp(severity, "critical") ?
        JMX_STORAGE_WRITE_IMPORTANT : (!strcmp(severity, "warning") || !strcmp(severity, "error") ?
        JMX_STORAGE_WRITE_IMPORTANT : JMX_STORAGE_WRITE_BULK);

    if (!jmx_storage_guard_allow(notifyd_storage_path(), priority, NULL)) {
        g_notify_storage_suppressed++;
        g_notify_storage_last_suppressed_at = now;
        return 0;
    }

    {
        int coalesced = notifyd_coalesce_outbox(channel_id, route_id, action_index, body,
            delivery_options_json, producer_dedupe_key, route_dedupe_key,
            dedupe_group, dedupe_window_seconds,
            max_attempts, out_id, out_id_len);
        if (coalesced)
            return coalesced;
    }
    notifyd_make_id("ntf", id, sizeof(id));
    if (out_id && out_id_len > 0)
        snprintf(out_id, out_id_len, "%s", id);
    st = notifyd_prepare(
        "INSERT INTO notify_outbox(id,created_at,updated_at,next_attempt_at,channel_id,route_id,event_id,severity,category,event,source,title,payload_json,state,attempts,max_attempts,dedupe_key,first_seen,last_seen,count,action_index,dedupe_group,delivery_options_json,producer_dedupe_key,route_dedupe_key) "
        "VALUES(?1,?2,?2,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,'pending',0,?12,?13,?2,?2,1,?14,?15,?16,?17,?18)");
    if (!st)
        return 0;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now);
    sqlite3_bind_text(st, 3, channel_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, route_id ? route_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, notifyd_json_str(body, "id", notifyd_json_str(body, "event_id", "")), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, notifyd_severity(notifyd_json_str(body, "severity", "info")), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, notifyd_json_str(body, "category", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, notifyd_json_str(body, "event", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, notifyd_json_str(body, "source", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 10, notifyd_json_str(body, "title", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 11, payload ? payload : "{}", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 12, max_attempts);
    sqlite3_bind_text(st, 13, producer_dedupe_key ? producer_dedupe_key : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 14, action_index);
    sqlite3_bind_text(st, 15, dedupe_group ? dedupe_group : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 16, delivery_options_json ? delivery_options_json : "{}", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 17, producer_dedupe_key ? producer_dedupe_key : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 18, route_dedupe_key ? route_dedupe_key : "", -1, SQLITE_TRANSIENT);
    ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (ok)
        notifyd_prune_if_needed();
    return ok;
}

static int notifyd_insert_outbox(const char *channel_id, const char *route_id,
                                 struct json_object *body, int max_attempts,
                                 char *out_id, size_t out_id_len)
{
    const char *dedupe_key = notifyd_dedupe_key(body);

    return notifyd_insert_outbox_ex(channel_id, route_id, 0, body, NULL,
                                    dedupe_key, "", dedupe_key, 0, max_attempts,
                                    out_id, out_id_len);
}

static void notifyd_route_recovery_clear(const char *route_id, int action_index,
                                         const char *dedupe_group)
{
    sqlite3_stmt *st;

    if (!route_id || !route_id[0] || !dedupe_group || !dedupe_group[0])
        return;
    st = notifyd_prepare(
        "UPDATE notify_outbox SET route_dedupe_key='',updated_at=?1 "
        "WHERE route_id=?2 AND action_index=?3 AND dedupe_group=?4");
    if (!st)
        return;
    sqlite3_bind_int64(st, 1, notifyd_now_s());
    sqlite3_bind_text(st, 2, route_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, action_index);
    sqlite3_bind_text(st, 4, dedupe_group, -1, SQLITE_TRANSIENT);
    (void)sqlite3_step(st);
    sqlite3_finalize(st);
}

int notifyd_prune_if_needed(void)
{
    sqlite3_stmt *st;
    int64_t now = notifyd_now_s();
    int rc;

    st = notifyd_prepare(
        "DELETE FROM notify_outbox "
        "WHERE state IN ('delivered','failed','suppressed') AND updated_at<?1");
    if (!st)
        return -1;
    sqlite3_bind_int64(st, 1, now - NOTIFYD_OUTBOX_DONE_RETENTION_SEC);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return -1;

    st = notifyd_prepare(
        "DELETE FROM notify_outbox "
        "WHERE state IN ('pending','retry') AND created_at<?1");
    if (!st)
        return -1;
    sqlite3_bind_int64(st, 1, now - NOTIFYD_OUTBOX_PENDING_RETENTION_SEC);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return -1;

    st = notifyd_prepare(
        "DELETE FROM notify_outbox WHERE id IN ("
        " SELECT id FROM notify_outbox ORDER BY updated_at DESC LIMIT -1 OFFSET ?1)");
    if (!st)
        return -1;
    sqlite3_bind_int(st, 1, NOTIFYD_OUTBOX_MAX_ROWS);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return -1;

    st = notifyd_prepare(
        "DELETE FROM notify_deliveries WHERE id IN ("
        " SELECT id FROM notify_deliveries ORDER BY ts DESC LIMIT -1 OFFSET ?1)");
    if (!st)
        return -1;
    sqlite3_bind_int(st, 1, NOTIFYD_DELIVERIES_MAX_ROWS);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return -1;

    st = notifyd_prepare(
        "DELETE FROM notify_route_triggers WHERE id IN ("
        " SELECT id FROM notify_route_triggers ORDER BY id DESC LIMIT -1 OFFSET ?1)");
    if (!st)
        return -1;
    sqlite3_bind_int(st, 1, NOTIFYD_DELIVERIES_MAX_ROWS);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return -1;

    notifyd_exec(g_notify_db, "PRAGMA wal_checkpoint(PASSIVE)");
    return 0;
}

struct json_object *notifyd_enqueue_event(struct json_object *body)
{
    struct notifyd_settings s;
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    int enqueued = 0, deduped = 0, matched = 0;
    int matched_routes = 0, suppressed = 0, render_failed = 0;
    const char *last_suppression_reason = "";
    struct json_object *render_failed_actions = json_object_new_array();
    int route_query_ok = 1;
    int rc;

    if (notifyd_settings_load(&s) != 0) {
        json_object_put(render_failed_actions);
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("settings_load_failed"));
        return resp;
    }
    if (!s.enabled) {
        json_object_object_add(resp, "ok", json_object_new_boolean(1));
        json_object_object_add(resp, "enabled", json_object_new_boolean(0));
        json_object_object_add(resp, "enqueued", json_object_new_int(0));
        json_object_put(render_failed_actions);
        return resp;
    }
    if (!body || !notifyd_json_fits(body, NOTIFYD_MAX_JSON - 1)) {
        json_object_put(render_failed_actions);
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_payload"));
        return resp;
    }
    /*
     * Validated before any route is consulted, so a bad id cannot reach the
     * outbox. The two failures are reported separately because they need
     * different fixes: a missing field is a malformed call, an unknown id is
     * usually a typo'd or stale event constant.
     */
    {
        const char *event_id = notifyd_json_str(body, "event", "");

        if (!event_id[0]) {
            json_object_put(render_failed_actions);
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("event_required"));
            return resp;
        }
        if (!notifyd_event_definition_find(event_id)) {
            json_object_put(render_failed_actions);
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("event_unknown"));
            json_object_object_add(resp, "event", json_object_new_string(event_id));
            return resp;
        }
    }
    st = notifyd_config_prepare("SELECT id,name,enabled,channel_id,min_severity,category,event,source,options_json FROM notifyd_routes WHERE enabled=1 ORDER BY id");
    if (st) {
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            const char *route_id = (const char *)sqlite3_column_text(st, 0);
            const char *top_channel = notifyd_sqlite_text(st, 3, "local");
            const char *top_severity = notifyd_sqlite_text(st, 4, "warning");
            struct json_object *stored_options;
            struct json_object *actions = NULL, *receivers = NULL;
            struct notifyd_route_contract contract;
            const char *schedule_reason = "schedule_outside_window";
            const char *global_mute_reason = "global_mute_schedule_active";
            int eligible_actions;
            int route_enqueued_before = enqueued;
            int route_deduped_before = deduped;
            int route_render_failed_before = render_failed;
            size_t action_index;

            if (!notifyd_route_matches(st, body))
                continue;
            stored_options = notifyd_json_parse_or_object(notifyd_sqlite_text(st, 8, "{}"));
            memset(&contract, 0, sizeof(contract));
            if (!notifyd_route_contract_build(stored_options, top_channel, top_severity,
                    1, 1, 0, &contract, NULL) || !contract.options) {
                json_object_put(stored_options);
                route_query_ok = 0;
                break;
            }
            eligible_actions = notifyd_route_eligible_actions(contract.options, body);
            if (eligible_actions == 0) {
                notifyd_route_contract_clear(&contract);
                json_object_put(stored_options);
                continue;
            }
            matched_routes++;
            if (!notifyd_route_schedule_allows(contract.options, notifyd_now_s(),
                                                &schedule_reason)) {
                suppressed++;
                last_suppression_reason = schedule_reason ? schedule_reason :
                    "schedule_outside_window";
                notifyd_route_suppression_record(route_id, body, schedule_reason);
                notifyd_route_trigger_record(route_id, body, "muted", schedule_reason,
                                             "not_applicable", "route_schedule");
                notifyd_route_contract_clear(&contract);
                json_object_put(stored_options);
                continue;
            }
            if (notifyd_global_mute_active(&s, notifyd_now_s(), &global_mute_reason)) {
                suppressed++;
                last_suppression_reason = global_mute_reason;
                notifyd_route_trigger_record(route_id, body, "muted", global_mute_reason,
                                             "not_applicable", "global_schedule");
                notifyd_route_contract_clear(&contract);
                json_object_put(stored_options);
                continue;
            }
            json_object_object_get_ex(contract.options, "actions", &actions);
            json_object_object_get_ex(contract.options, "receivers", &receivers);
            for (action_index = 0; actions && action_index < json_object_array_length(actions);
                 action_index++) {
                struct json_object *action = json_object_array_get_idx(actions, action_index);
                const char *channel = notifyd_json_str(action, "channel_id", "");
                const char *min_severity = notifyd_json_str(action, "min_severity", "warning");
                const char *producer_key = notifyd_dedupe_key(body);
                const char *effective_producer_key = producer_key;
                char route_key[1024] = "";
                char dedupe_group[1024] = "";
                char render_error[64] = "";
                int dedupe_window = 0;
                struct json_object *payload;
                struct json_object *delivery_options = json_object_new_object();

                if (notifyd_severity_rank(notifyd_json_str(body, "severity", "info")) <
                        notifyd_severity_rank(min_severity) &&
                    !notifyd_event_is_recovery(notifyd_json_str(body, "event", ""))) {
                    json_object_put(delivery_options);
                    continue;
                }
                matched++;
                payload = notifyd_route_payload_render(body, contract.options,
                    (int)action_index, render_error, sizeof(render_error));
                if (!payload) {
                    struct json_object *failure = json_object_new_object();
                    render_failed++;
                    json_object_object_add(failure, "route_id",
                                           json_object_new_string(route_id ? route_id : ""));
                    json_object_object_add(failure, "action_index",
                                           json_object_new_int((int)action_index));
                    json_object_object_add(failure, "error",
                                           json_object_new_string(render_error[0] ?
                                               render_error : "content_render_failed"));
                    json_object_array_add(render_failed_actions, failure);
                    json_object_put(delivery_options);
                    continue;
                }
                if (receivers)
                    json_object_object_add(delivery_options, "receivers", json_object_get(receivers));
                (void)notifyd_route_dedupe_contract(contract.options, body,
                    route_key, sizeof(route_key), dedupe_group, sizeof(dedupe_group),
                    &dedupe_window);
                if (notifyd_event_is_recovery(notifyd_json_str(body, "event", ""))) {
                    notifyd_route_recovery_clear(route_id, (int)action_index, dedupe_group);
                    if (route_key[0])
                        effective_producer_key = "";
                }
                if (channel[0]) {
                    int insert_result = notifyd_insert_outbox_ex(channel, route_id,
                        (int)action_index, payload, delivery_options,
                        effective_producer_key, route_key, dedupe_group,
                        dedupe_window, s.max_attempts, NULL, 0);
                    if (insert_result == 2)
                        deduped++;
                    else if (insert_result == 1)
                        enqueued++;
                }
                json_object_put(delivery_options);
                json_object_put(payload);
            }
            if (deduped > route_deduped_before && enqueued == route_enqueued_before)
                notifyd_route_trigger_record(route_id, body, "deduped", "route_or_producer_dedupe",
                                             "deduped", "not_muted");
            else if (enqueued > route_enqueued_before)
                notifyd_route_trigger_record(route_id, body, "enqueued", "",
                                             deduped > route_deduped_before ? "partial" : "not_deduped",
                                             "not_muted");
            else if (render_failed > route_render_failed_before)
                notifyd_route_trigger_record(route_id, body, "render_failed",
                                             "content_render_failed", "not_applicable",
                                             "not_muted");
            else
                notifyd_route_trigger_record(route_id, body, "enqueue_failed",
                                             "outbox_insert_failed", "not_applicable",
                                             "not_muted");
            notifyd_route_contract_clear(&contract);
            json_object_put(stored_options);
        }
        if (rc != SQLITE_DONE)
            route_query_ok = 0;
        sqlite3_finalize(st);
    } else {
        route_query_ok = 0;
    }
    if (!route_query_ok) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "matched", json_object_new_int(matched));
        json_object_object_add(resp, "matched_routes", json_object_new_int(matched_routes));
        json_object_object_add(resp, "enqueued", json_object_new_int(enqueued));
        json_object_object_add(resp, "deduped", json_object_new_int(deduped));
        json_object_object_add(resp, "render_failures", render_failed_actions);
        json_object_object_add(resp, "error", json_object_new_string("routes_query_failed"));
        return resp;
    }
    /*
     * Same recovery exemption as notifyd_route_matches(). Without it the
     * fallback reintroduces the drop whenever no route matched at all, e.g.
     * every route disabled or scoped elsewhere.
     */
    if (!matched_routes && !suppressed && s.default_channel_id[0] &&
        (notifyd_severity_rank(notifyd_json_str(body, "severity", "info")) >= notifyd_severity_rank("warning") ||
         notifyd_event_is_recovery(notifyd_json_str(body, "event", "")))) {
        if (notifyd_global_mute_active(&s, notifyd_now_s(), NULL)) {
            suppressed++;
            last_suppression_reason = "global_mute_schedule_active";
            notifyd_route_trigger_record("default", body, "muted",
                                         "global_mute_schedule_active", "not_applicable",
                                         "global_schedule");
        } else {
            struct json_object *payload = notifyd_route_options_clone(body);
            int inserted = payload && dw_event_payload_present(
                payload, notifyd_json_str(body, "locale", "zh-CN")) &&
                notifyd_insert_outbox(s.default_channel_id, "default", payload,
                                      s.max_attempts, NULL, 0);

            if (payload)
                json_object_put(payload);
            if (inserted) {
            matched = 1;
            enqueued = 1;
            notifyd_route_trigger_record("default", body, "enqueued", "",
                                         "not_deduped", "not_muted");
            } else {
                matched = 1;
                notifyd_route_trigger_record("default", body, "enqueue_failed",
                                             "outbox_insert_failed", "not_applicable",
                                             "not_muted");
            }
        }
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(
        !matched || enqueued + deduped == matched));
    json_object_object_add(resp, "matched", json_object_new_int(matched));
    json_object_object_add(resp, "matched_routes", json_object_new_int(matched_routes));
    json_object_object_add(resp, "enqueued", json_object_new_int(enqueued));
    json_object_object_add(resp, "deduped", json_object_new_int(deduped));
    json_object_object_add(resp, "suppressed", json_object_new_int(suppressed));
    json_object_object_add(resp, "render_failed", json_object_new_int(render_failed));
    json_object_object_add(resp, "render_failures", render_failed_actions);
    if (suppressed)
        json_object_object_add(resp, "suppression_reason",
                               json_object_new_string(last_suppression_reason[0] ?
                                   last_suppression_reason : "schedule_outside_window"));
    if (matched && enqueued + deduped == 0 && !suppressed)
        json_object_object_add(resp, "error", json_object_new_string(
            render_failed ? "content_render_failed" : "enqueue_failed"));
    else if (matched && enqueued + deduped < matched)
        json_object_object_add(resp, "error", json_object_new_string("partial_enqueue_failed"));
    return resp;
}

struct json_object *notifyd_triggers_json(struct json_object *body)
{
    const char *route_id = notifyd_json_str(body, "route_id", "");
    const char *cursor = notifyd_json_str(body, "cursor", "");
    int limit = notifyd_json_int(body, "limit", NOTIFYD_DEFAULT_LIMIT);
    int64_t cursor_id = INT64_MAX;
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    struct json_object *items = json_object_new_array();
    int rc = SQLITE_DONE;
    int returned = 0;
    int has_more = 0;
    int64_t last_id = 0;

    if (limit <= 0 || limit > NOTIFYD_MAX_LIMIT)
        limit = NOTIFYD_DEFAULT_LIMIT;
    if (route_id[0] && !notifyd_id_ok(route_id)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_route_id"));
        json_object_object_add(resp, "items", items);
        return resp;
    }
    if (cursor[0]) {
        char *end = NULL;

        errno = 0;
        cursor_id = strtoll(cursor, &end, 10);
        if (errno || !end || *end || cursor_id <= 0) {
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("invalid_cursor"));
            json_object_object_add(resp, "items", items);
            return resp;
        }
    }
    st = notifyd_prepare(
        "SELECT id,route_id,event,severity,source,triggered_at,result,reason,"
        "dedupe_result,mute_result FROM notify_route_triggers "
        "WHERE (?1='' OR route_id=?1) AND (?2=0 OR id<?2) "
        "ORDER BY id DESC LIMIT ?3");
    if (!st) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("triggers_query_failed"));
        json_object_object_add(resp, "items", items);
        return resp;
    }
    sqlite3_bind_text(st, 1, route_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, cursor[0] ? cursor_id : 0);
    sqlite3_bind_int(st, 3, limit + 1);
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        struct json_object *item;

        if (returned == limit) {
            has_more = 1;
            break;
        }
        item = json_object_new_object();
        last_id = sqlite3_column_int64(st, 0);
        json_object_object_add(item, "id", json_object_new_int64(last_id));
        json_object_object_add(item, "route_id",
                               json_object_new_string(notifyd_sqlite_text(st, 1, "")));
        json_object_object_add(item, "event",
                               json_object_new_string(notifyd_sqlite_text(st, 2, "")));
        json_object_object_add(item, "severity",
                               json_object_new_string(notifyd_sqlite_text(st, 3, "info")));
        json_object_object_add(item, "source",
                               json_object_new_string(notifyd_sqlite_text(st, 4, "")));
        json_object_object_add(item, "triggered_at",
                               json_object_new_int64(sqlite3_column_int64(st, 5)));
        json_object_object_add(item, "result",
                               json_object_new_string(notifyd_sqlite_text(st, 6, "")));
        json_object_object_add(item, "reason",
                               json_object_new_string(notifyd_sqlite_text(st, 7, "")));
        json_object_object_add(item, "dedupe_result",
                               json_object_new_string(notifyd_sqlite_text(st, 8, "not_applicable")));
        json_object_object_add(item, "mute_result",
                               json_object_new_string(notifyd_sqlite_text(st, 9, "not_muted")));
        json_object_array_add(items, item);
        returned++;
    }
    if (rc != SQLITE_DONE && !has_more) {
        sqlite3_finalize(st);
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("triggers_query_failed"));
        json_object_object_add(resp, "items", items);
        return resp;
    }
    sqlite3_finalize(st);
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "items", items);
    json_object_object_add(resp, "route_id", json_object_new_string(route_id));
    json_object_object_add(resp, "cursor", json_object_new_string(cursor));
    json_object_object_add(resp, "limit", json_object_new_int(limit));
    json_object_object_add(resp, "has_more", json_object_new_boolean(has_more));
    if (has_more && last_id > 0) {
        char next_cursor[32];
        snprintf(next_cursor, sizeof(next_cursor), "%lld", (long long)last_id);
        json_object_object_add(resp, "next_cursor", json_object_new_string(next_cursor));
    } else {
        json_object_object_add(resp, "next_cursor", json_object_new_string(""));
    }
    json_object_object_add(resp, "order", json_object_new_string("id_desc"));
    return resp;
}

struct json_object *notifyd_enqueue_direct(struct json_object *body)
{
    struct notifyd_settings s;
    struct notifyd_channel channel;
    struct json_object *resp = json_object_new_object();
    const char *channel_id = notifyd_json_str(body, "channel_id", "");
    struct json_object *payload = NULL;
    char outbox_id[NOTIFYD_MAX_ID] = {0};
    int ok;

    if (notifyd_settings_load(&s) != 0) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("settings_load_failed"));
        return resp;
    }
    if (!s.enabled) {
        json_object_object_add(resp, "ok", json_object_new_boolean(1));
        json_object_object_add(resp, "enabled", json_object_new_boolean(0));
        json_object_object_add(resp, "enqueued", json_object_new_int(0));
        return resp;
    }
    if (!channel_id[0])
        channel_id = s.default_channel_id;
    if (!notifyd_id_ok(channel_id) || !notifyd_channel_get(channel_id, &channel)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("channel_not_found"));
        return resp;
    }
    if (!body || !notifyd_json_fits(body, NOTIFYD_MAX_JSON - 1)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_payload"));
        return resp;
    }
    payload = json_tokener_parse(json_object_to_json_string_ext(body,
                                                                JSON_C_TO_STRING_PLAIN));
    if (!payload || !json_object_is_type(payload, json_type_object)) {
        if (payload)
            json_object_put(payload);
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_payload"));
        return resp;
    }
    {
        const char *event_id = notifyd_json_str(payload, "event", "");
        const char *title = notifyd_json_str(payload, "title", "");
        const char *message = notifyd_json_str(payload, "message", "");

        if (event_id[0] && !title[0] && !message[0] &&
            dw_event_definition_find(event_id))
            dw_event_payload_present(payload,
                notifyd_json_str(payload, "locale", "zh-CN"));
    }
    ok = notifyd_insert_outbox(channel_id, notifyd_json_str(payload, "route_id", "direct"),
                               payload, s.max_attempts, outbox_id, sizeof(outbox_id));
    json_object_put(payload);
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "enqueued", json_object_new_int(ok ? 1 : 0));
    if (ok && outbox_id[0])
        json_object_object_add(resp, "id", json_object_new_string(outbox_id));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("enqueue_failed"));
    return resp;
}

static int notifyd_contains_ci(const char *haystack, const char *needle)
{
    size_t needle_len;

    if (!haystack || !needle || !needle[0])
        return 0;
    needle_len = strlen(needle);
    for (; *haystack; haystack++)
        if (!strncasecmp(haystack, needle, needle_len))
            return 1;
    return 0;
}

static int notifyd_event_is(const char *event, const char *wanted)
{
    return event && wanted && !strcasecmp(event, wanted);
}

static int notifyd_json_bool_override(struct json_object *obj, const char *key,
                                      int *present)
{
    struct json_object *value = NULL;

    if (present)
        *present = 0;
    if (!obj || !key || !json_object_object_get_ex(obj, key, &value) || !value)
        return 0;
    if (present)
        *present = 1;
    return json_object_get_boolean(value) ? 1 : 0;
}

static int notifyd_browser_interrupt_policy(const char *payload_s,
                                            const char *severity,
                                            const char *category,
                                            const char *event,
                                            const char **reason)
{
    struct json_object *payload = notifyd_json_parse_or_object(payload_s);
    struct json_object *detail = NULL;
    const char *metric = "";
    const char *action = "";
    const char *message = "";
    int explicit_present = 0;
    int explicit_value;
    int rank = notifyd_severity_rank(severity);
    int allow = 0;

    if (reason)
        *reason = "not_interrupt_worthy";
    explicit_value = notifyd_json_bool_override(payload, "browser_interrupt",
                                                &explicit_present);
    if (!explicit_present &&
        json_object_object_get_ex(payload, "detail_json", &detail) && detail &&
        json_object_is_type(detail, json_type_object))
        explicit_value = notifyd_json_bool_override(detail, "browser_interrupt",
                                                    &explicit_present);
    /* Producers may suppress a browser interruption, but cannot bypass the
     * central emergency allowlist by setting browser_interrupt=true. */
    if (explicit_present && !explicit_value) {
        if (reason)
            *reason = "producer_suppressed";
        json_object_put(payload);
        return 0;
    }

    if (!detail && json_object_object_get_ex(payload, "detail", &detail) &&
        (!detail || !json_object_is_type(detail, json_type_object)))
        detail = NULL;
    if (detail) {
        metric = notifyd_json_str(detail, "metric", "");
        action = notifyd_json_str(detail, "action", "");
        message = notifyd_json_str(detail, "message",
                  notifyd_json_str(detail, "line", ""));
    }
    if (!action[0])
        action = notifyd_json_str(payload, "action", "");

    if (rank >= notifyd_severity_rank("warning") &&
        (notifyd_event_is(event, "wan_down") ||
         notifyd_event_is(event, "internet_down") ||
         notifyd_event_is(event, "connectivity_lost") ||
         notifyd_event_is(event, "all_wans_down"))) {
        allow = 1;
        if (reason) *reason = "confirmed_connectivity_loss";
    } else if (rank >= notifyd_severity_rank("critical") &&
               category && !strcasecmp(category, "resource") &&
               (notifyd_event_is(event, "threshold_exceeded") ||
                notifyd_event_is(event, "temperature_critical") ||
                notifyd_event_is(event, "thermal_critical"))) {
        allow = 1;
        if (reason)
            *reason = (notifyd_contains_ci(metric, "temp") ||
                       notifyd_contains_ci(metric, "thermal")) ?
                      "critical_temperature" : "critical_resource_pressure";
    } else if (rank >= notifyd_severity_rank("warning") &&
               ((category && (!strcasecmp(category, "security") ||
                              !strcasecmp(category, "aegis"))) ||
                notifyd_event_is(event, "security_detection")) &&
               (rank >= notifyd_severity_rank("error") ||
                notifyd_contains_ci(event, "anomaly") ||
                notifyd_contains_ci(event, "attack") ||
                notifyd_contains_ci(event, "threat") ||
                notifyd_contains_ci(event, "intrusion") ||
                notifyd_contains_ci(event, "malware") ||
                notifyd_contains_ci(event, "blocked") ||
                notifyd_contains_ci(action, "block") ||
                notifyd_contains_ci(action, "drop") ||
                notifyd_contains_ci(action, "deny"))) {
        allow = 1;
        if (reason) *reason = "confirmed_security_event";
    } else if (rank >= notifyd_severity_rank("critical") &&
               (notifyd_event_is(event, "oom") ||
                notifyd_event_is(event, "out_of_memory") ||
                notifyd_event_is(event, "kernel_panic") ||
                notifyd_event_is(event, "thermal_shutdown") ||
                notifyd_contains_ci(message, "out of memory") ||
                notifyd_contains_ci(message, "oom-killer") ||
                notifyd_contains_ci(message, "kernel panic") ||
                notifyd_contains_ci(message, "thermal shutdown"))) {
        allow = 1;
        if (reason) *reason = "critical_system_failure";
    }

    if (!allow && explicit_present && explicit_value && reason)
        *reason = "producer_request_not_whitelisted";

    json_object_put(payload);
    return allow;
}

static int notifyd_outbox_row_browser_interrupt(sqlite3_stmt *st,
                                                const char **reason)
{
    return notifyd_browser_interrupt_policy(
        notifyd_sqlite_text(st, 12, "{}"),
        notifyd_sqlite_text(st, 7, "info"),
        notifyd_sqlite_text(st, 8, ""),
        notifyd_sqlite_text(st, 9, ""), reason);
}

static void notifyd_outbox_row_json(struct json_object *arr, sqlite3_stmt *st)
{
    const char *payload_s = notifyd_sqlite_text(st, 12, "{}");
    const char *interrupt_reason = "not_interrupt_worthy";
    int browser_interrupt = notifyd_outbox_row_browser_interrupt(st,
                                                                 &interrupt_reason);
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "id", json_object_new_string(notifyd_sqlite_text(st, 0, "")));
    json_object_object_add(o, "created_at", json_object_new_int64(sqlite3_column_int64(st, 1)));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 2)));
    json_object_object_add(o, "next_attempt_at", json_object_new_int64(sqlite3_column_int64(st, 3)));
    json_object_object_add(o, "channel_id", json_object_new_string(notifyd_sqlite_text(st, 4, "")));
    json_object_object_add(o, "route_id", json_object_new_string(notifyd_sqlite_text(st, 5, "")));
    json_object_object_add(o, "event_id", json_object_new_string(notifyd_sqlite_text(st, 6, "")));
    json_object_object_add(o, "severity", json_object_new_string(notifyd_sqlite_text(st, 7, "info")));
    json_object_object_add(o, "category", json_object_new_string(notifyd_sqlite_text(st, 8, "")));
    json_object_object_add(o, "event", json_object_new_string(notifyd_sqlite_text(st, 9, "")));
    json_object_object_add(o, "source", json_object_new_string(notifyd_sqlite_text(st, 10, "")));
    json_object_object_add(o, "title", json_object_new_string(notifyd_sqlite_text(st, 11, "")));
    json_object_object_add(o, "payload", notifyd_json_parse_or_object(payload_s));
    json_object_object_add(o, "state", json_object_new_string(notifyd_sqlite_text(st, 13, "pending")));
    json_object_object_add(o, "attempts", json_object_new_int(sqlite3_column_int(st, 14)));
    json_object_object_add(o, "max_attempts", json_object_new_int(sqlite3_column_int(st, 15)));
    json_object_object_add(o, "last_error", json_object_new_string(notifyd_sqlite_text(st, 16, "")));
    json_object_object_add(o, "last_http_status", json_object_new_int(sqlite3_column_int(st, 17)));
    json_object_object_add(o, "first_seen", json_object_new_int64(sqlite3_column_int64(st, 18)));
    json_object_object_add(o, "last_seen", json_object_new_int64(sqlite3_column_int64(st, 19)));
    json_object_object_add(o, "count", json_object_new_int(sqlite3_column_int(st, 20)));
    json_object_object_add(o, "action_index", json_object_new_int(sqlite3_column_int(st, 21)));
    json_object_object_add(o, "last_warning", json_object_new_string(
        notifyd_sqlite_text(st, 22, "")));
    json_object_object_add(o, "browser_interrupt", json_object_new_boolean(browser_interrupt));
    json_object_object_add(o, "interrupt_reason", json_object_new_string(interrupt_reason));
    json_object_array_add(arr, o);
}

struct json_object *notifyd_outbox_list(struct json_object *body)
{
    const char *state = notifyd_json_str(body, "state", "");
    const char *search = notifyd_json_str(body, "search", "");
    const char *cursor = notifyd_json_str(body, "cursor", "");
    int interrupt_only = notifyd_json_bool(body, "interrupt_only", 0);
    int64_t since = notifyd_json_i64(body, "since", 0);
    int limit = notifyd_json_int(body, "limit", NOTIFYD_DEFAULT_LIMIT);
    sqlite3_stmt *st;
    sqlite3_stmt *count_st;
    struct json_object *resp = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    int ok = 1;
    int rc;
    int64_t cursor_ts = INT64_MAX;
    char cursor_id[NOTIFYD_MAX_ID] = "";
    char search_like[600] = "";
    int total = -1;
    int returned = 0;
    int has_more = 0;
    int suppressed = 0;
    int candidates = 0;
    int i;

    if (limit <= 0 || limit > NOTIFYD_MAX_LIMIT)
        limit = NOTIFYD_DEFAULT_LIMIT;
    if (state[0] && strcmp(state, "pending") && strcmp(state, "retry") &&
        strcmp(state, "failed") && strcmp(state, "delivered") &&
        strcmp(state, "suppressed")) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_state"));
        json_object_object_add(resp, "items", arr);
        return resp;
    }
    if (!notifyd_text_ok(search, 256)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_search"));
        json_object_object_add(resp, "items", arr);
        return resp;
    }
    if (since < 0) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_since"));
        json_object_object_add(resp, "items", arr);
        return resp;
    }
    if (cursor[0]) {
        const char *colon = strchr(cursor, ':');
        char ts_buf[32];
        char *end = NULL;
        size_t n;

        if (!colon || colon == cursor || !colon[1] || (n = (size_t)(colon - cursor)) >= sizeof(ts_buf)) {
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("invalid_cursor"));
            json_object_object_add(resp, "items", arr);
            return resp;
        }
        memcpy(ts_buf, cursor, n); ts_buf[n] = '\0';
        errno = 0;
        cursor_ts = strtoll(ts_buf, &end, 10);
        if (errno || !end || *end || cursor_ts < 0 || !notifyd_id_ok(colon + 1)) {
            json_object_object_add(resp, "ok", json_object_new_boolean(0));
            json_object_object_add(resp, "error", json_object_new_string("invalid_cursor"));
            json_object_object_add(resp, "items", arr);
            return resp;
        }
        snprintf(cursor_id, sizeof(cursor_id), "%s", colon + 1);
    }
    if (search[0]) {
        size_t o = 0;
        search_like[o++] = '%';
        for (i = 0; search[i] && o + 3 < sizeof(search_like); i++) {
            if (search[i] == '%' || search[i] == '_' || search[i] == '\\')
                search_like[o++] = '\\';
            search_like[o++] = search[i];
        }
        search_like[o++] = '%'; search_like[o] = '\0';
    }
    count_st = notifyd_prepare(
        "SELECT COUNT(*) FROM notify_outbox WHERE (?1='' OR state=?1) AND "
        "(?2='' OR title LIKE ?2 ESCAPE '\\' OR event LIKE ?2 ESCAPE '\\' OR "
        "category LIKE ?2 ESCAPE '\\' OR source LIKE ?2 ESCAPE '\\' OR "
        "channel_id LIKE ?2 ESCAPE '\\' OR route_id LIKE ?2 ESCAPE '\\') AND "
        "(?3=0 OR last_seen>=?3)");
    if (count_st) {
        sqlite3_bind_text(count_st, 1, state, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(count_st, 2, search_like, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(count_st, 3, since);
        if (sqlite3_step(count_st) == SQLITE_ROW) total = sqlite3_column_int(count_st, 0);
        sqlite3_finalize(count_st);
    }
    st = notifyd_prepare(
        "SELECT id,created_at,updated_at,next_attempt_at,channel_id,route_id,event_id,severity,category,event,source,title,payload_json,state,attempts,max_attempts,last_error,last_http_status,first_seen,last_seen,count,action_index,last_warning "
        "FROM notify_outbox WHERE (?1='' OR state=?1) AND "
        "(?2='' OR title LIKE ?2 ESCAPE '\\' OR event LIKE ?2 ESCAPE '\\' OR category LIKE ?2 ESCAPE '\\' OR source LIKE ?2 ESCAPE '\\' OR channel_id LIKE ?2 ESCAPE '\\' OR route_id LIKE ?2 ESCAPE '\\') AND "
        "(?3=0 OR last_seen>=?3) AND "
        "(?4='' OR created_at<?5 OR (created_at=?5 AND id<?4)) "
        "ORDER BY CASE WHEN ?7=1 THEN last_seen ELSE created_at END DESC,"
        "created_at DESC,id DESC LIMIT ?6");
    if (st) {
        sqlite3_bind_text(st, 1, state, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, search_like, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, since);
        sqlite3_bind_text(st, 4, cursor_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 5, cursor_ts);
        sqlite3_bind_int(st, 6, interrupt_only ? NOTIFYD_MAX_LIMIT : limit + 1);
        sqlite3_bind_int(st, 7, interrupt_only);
    }
    if (st) {
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            candidates++;
            if (interrupt_only && !notifyd_outbox_row_browser_interrupt(st, NULL)) {
                suppressed++;
                continue;
            }
            if (returned < limit) {
                notifyd_outbox_row_json(arr, st);
                returned++;
            } else {
                has_more = 1;
            }
        }
        if (rc != SQLITE_DONE)
            ok = 0;
        sqlite3_finalize(st);
    } else {
        ok = 0;
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("outbox_query_failed"));
    json_object_object_add(resp, "items", arr);
    json_object_object_add(resp, "total", json_object_new_int(
        interrupt_only ? returned + (has_more ? 1 : 0) : (total < 0 ? 0 : total)));
    json_object_object_add(resp, "limit", json_object_new_int(limit));
    json_object_object_add(resp, "has_more", json_object_new_boolean(has_more));
    json_object_object_add(resp, "cursor", json_object_new_string(cursor));
    if (has_more && returned > 0) {
        struct json_object *last = json_object_array_get_idx(arr, returned - 1);
        char next_cursor[160];
        snprintf(next_cursor, sizeof(next_cursor), "%lld:%s",
                 (long long)notifyd_json_i64(last, "created_at", 0),
                 notifyd_json_str(last, "id", ""));
        json_object_object_add(resp, "next_cursor", json_object_new_string(next_cursor));
    } else {
        json_object_object_add(resp, "next_cursor", json_object_new_string(""));
    }
    json_object_object_add(resp, "search", json_object_new_string(search));
    json_object_object_add(resp, "state", json_object_new_string(state));
    json_object_object_add(resp, "since", json_object_new_int64(since));
    json_object_object_add(resp, "interrupt_only", json_object_new_boolean(interrupt_only));
    json_object_object_add(resp, "suppressed", json_object_new_int(suppressed));
    json_object_object_add(resp, "candidate_count", json_object_new_int(candidates));
    json_object_object_add(resp, "total_exact", json_object_new_boolean(!interrupt_only));
    json_object_object_add(resp, "interrupt_policy", json_object_new_string(
        "central_allowlist_confirmed_connectivity_loss_or_critical_resource_or_confirmed_security_or_critical_system_failure"));
    return resp;
}

struct json_object *notifyd_outbox_get(struct json_object *body)
{
    const char *id = notifyd_json_str(body, "id", "");
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    struct json_object *items = json_object_new_array();
    struct json_object *attempts = json_object_new_array();

    if (!notifyd_id_ok(id)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_id"));
        json_object_object_add(resp, "attempts", attempts);
        json_object_put(items);
        return resp;
    }
    st = notifyd_prepare(
        "SELECT id,created_at,updated_at,next_attempt_at,channel_id,route_id,event_id,severity,category,event,source,title,payload_json,state,attempts,max_attempts,last_error,last_http_status,first_seen,last_seen,count,action_index,last_warning "
        "FROM notify_outbox WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW)
            notifyd_outbox_row_json(items, st);
        sqlite3_finalize(st);
    }
    if (json_object_array_length(items) == 0) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("outbox_not_found"));
        json_object_object_add(resp, "attempts", attempts);
        json_object_put(items);
        return resp;
    }
    st = notifyd_prepare(
        "SELECT id,ts,ok,http_status,error,duration_ms,warning,outcome,suppressed_recipients "
        "FROM notify_deliveries WHERE outbox_id=?1 ORDER BY ts DESC,id DESC");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *attempt = json_object_new_object();
            const char *outcome = notifyd_sqlite_text(st, 7, "");

            json_object_object_add(attempt, "id", json_object_new_int64(sqlite3_column_int64(st, 0)));
            json_object_object_add(attempt, "ts", json_object_new_int64(sqlite3_column_int64(st, 1)));
            json_object_object_add(attempt, "ok", json_object_new_boolean(sqlite3_column_int(st, 2)));
            json_object_object_add(attempt, "http_status", json_object_new_int(sqlite3_column_int(st, 3)));
            json_object_object_add(attempt, "error", json_object_new_string(notifyd_sqlite_text(st, 4, "")));
            json_object_object_add(attempt, "duration_ms", json_object_new_int(sqlite3_column_int(st, 5)));
            json_object_object_add(attempt, "warning", json_object_new_string(
                notifyd_sqlite_text(st, 6, "")));
            /* Rows written before the suppression outcome existed have an empty
             * `outcome`; derive it from `ok` so old attempts still classify. */
            json_object_object_add(attempt, "outcome", json_object_new_string(
                outcome[0] ? outcome :
                (sqlite3_column_int(st, 2) ? "delivered" : "failed")));
            json_object_object_add(attempt, "suppressed",
                json_object_new_boolean(!strcmp(outcome, "suppressed")));
            json_object_object_add(attempt, "suppressed_recipients",
                json_object_new_int(sqlite3_column_int(st, 8)));
            json_object_array_add(attempts, attempt);
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "item", json_object_get(json_object_array_get_idx(items, 0)));
    json_object_object_add(resp, "attempts", attempts);
    json_object_object_add(resp, "attempt_count", json_object_new_int((int)json_object_array_length(attempts)));
    json_object_object_add(resp, "source", json_object_new_string("notify.db:notify_outbox+notify_deliveries"));
    json_object_put(items);
    return resp;
}

struct json_object *notifyd_outbox_retry(struct json_object *body)
{
    const char *id = notifyd_json_str(body, "id", "");
    sqlite3_stmt *st;
    struct json_object *resp = json_object_new_object();
    int ok = 0;

    if (!notifyd_id_ok(id)) {
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
        json_object_object_add(resp, "error", json_object_new_string("invalid_id"));
        return resp;
    }
    st = notifyd_prepare("UPDATE notify_outbox SET state='pending',next_attempt_at=?1,updated_at=?1,last_error='',last_warning='' WHERE id=?2");
    if (st) {
        sqlite3_bind_int64(st, 1, notifyd_now_s());
        sqlite3_bind_text(st, 2, id, -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_notify_db) > 0;
        sqlite3_finalize(st);
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "id", json_object_new_string(id));
    if (!ok)
        json_object_object_add(resp, "error", json_object_new_string("not_found"));
    return resp;
}

int notifyd_delivery_record(const char *outbox_id, const char *channel_id,
                            int outcome, long http_status, const char *error,
                            int duration_ms, int suppressed_recipients)
{
    sqlite3_stmt *st;
    int suppressed = outcome == NOTIFYD_DELIVERY_SUPPRESSED;
    int ok = outcome != NOTIFYD_DELIVERY_FAILED;
    int rc = 0;

    if (!jmx_storage_guard_allow(notifyd_storage_path(), JMX_STORAGE_WRITE_BULK, NULL)) {
        g_notify_storage_suppressed++;
        g_notify_storage_last_suppressed_at = notifyd_now_s();
        return 0;
    }
    st = notifyd_prepare(
        "INSERT INTO notify_deliveries(outbox_id,channel_id,ts,ok,http_status,error,duration_ms,warning,outcome,suppressed_recipients) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)");
    if (!st)
        return 0;
    sqlite3_bind_text(st, 1, outbox_id ? outbox_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, channel_id ? channel_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, notifyd_now_s());
    sqlite3_bind_int(st, 4, ok);
    sqlite3_bind_int(st, 5, (int)http_status);
    sqlite3_bind_text(st, 6, !ok && error ? error : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 7, duration_ms < 0 ? 0 : duration_ms);
    sqlite3_bind_text(st, 8, ok && error ? error : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9,
                      suppressed ? "suppressed" : (ok ? "delivered" : "failed"),
                      -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 10, suppressed_recipients < 0 ? 0 : suppressed_recipients);
    rc = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return rc;
}

int notifyd_mark_delivery_result(const struct notifyd_outbox_item *item,
                                 int outcome, long http_status, const char *error,
                                 int duration_ms, int suppressed_recipients)
{
    struct notifyd_settings s;
    sqlite3_stmt *st;
    int suppressed = outcome == NOTIFYD_DELIVERY_SUPPRESSED;
    int ok = outcome != NOTIFYD_DELIVERY_FAILED;
    int attempts;
    int64_t now = notifyd_now_s();
    int64_t next = now;
    const char *state;
    char warning[256];
    int rc = 0;

    if (!item)
        return 0;
    if (notifyd_settings_load(&s) != 0)
        return 0;
    /*
     * A suppressed send never touched a transport, so it must not consume an
     * attempt: were the user to unmute and retry the row, an exhausted counter
     * would push it straight to `failed`.
     */
    attempts = suppressed ? item->attempts : item->attempts + 1;
    if (suppressed) {
        state = "suppressed";
    } else if (ok) {
        state = "delivered";
    } else if (attempts >= item->max_attempts) {
        state = "failed";
    } else {
        int delay = s.retry_base_s;
        int i;

        for (i = 1; i < attempts; i++) {
            if (delay < s.retry_max_s / 2) delay *= 2;
            else { delay = s.retry_max_s; break; }
        }
        if (delay > s.retry_max_s) delay = s.retry_max_s;
        next = now + delay;
        state = "retry";
    }
    /*
     * Suppression detail rides in `last_warning`, never `last_error`: status
     * counts non-empty `last_error` rows as delivery faults, and a mute the
     * user asked for is not one. Only the count is recorded -- putting the
     * muted address here would leak one user's email into another's view.
     */
    warning[0] = '\0';
    if (suppressed) {
        snprintf(warning, sizeof(warning), "%s",
                 error && error[0] ? error : "preference_suppressed_all_recipients");
    } else if (ok && suppressed_recipients > 0 && error && error[0]) {
        snprintf(warning, sizeof(warning), "%s;preference_suppressed_recipients:%d",
                 error, suppressed_recipients);
    } else if (ok && suppressed_recipients > 0) {
        snprintf(warning, sizeof(warning), "preference_suppressed_recipients:%d",
                 suppressed_recipients);
    } else if (ok && error) {
        snprintf(warning, sizeof(warning), "%s", error);
    }
    st = notifyd_prepare(
        "UPDATE notify_outbox SET state=?1,attempts=?2,next_attempt_at=?3,updated_at=?4,"
        "last_error=?5,last_http_status=?6,last_warning=?7 WHERE id=?8");
    if (st) {
        sqlite3_bind_text(st, 1, state, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, attempts);
        sqlite3_bind_int64(st, 3, next);
        sqlite3_bind_int64(st, 4, now);
        sqlite3_bind_text(st, 5, !ok && error ? error : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 6, (int)http_status);
        sqlite3_bind_text(st, 7, warning, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, item->id, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
    }
    notifyd_delivery_record(item->id, item->channel_id, outcome, http_status,
                            suppressed ? warning : error, duration_ms,
                            suppressed_recipients);
    return rc;
}

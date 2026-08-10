// SPDX-License-Identifier: GPL-2.0-or-later
#include "aegisxd_internal.h"

static int aegisxd_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc;

    if (!db || !sql)
        return -1;
    rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-aegisxd] sqlite exec failed: %s sql=%s\n",
                err ? err : sqlite3_errmsg(db), sql);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static int aegisxd_column_exists(sqlite3 *db, const char *table, const char *column)
{
    sqlite3_stmt *st = NULL;
    char sql[160];
    int exists = 0;

    if (!db || !table || !column)
        return 0;
    snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table);
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(st, 1);

        if (name && !strcmp((const char *)name, column)) {
            exists = 1;
            break;
        }
    }
    sqlite3_finalize(st);
    return exists;
}

static int aegisxd_add_column_if_missing(sqlite3 *db, const char *table,
                                         const char *column, const char *sql)
{
    if (aegisxd_column_exists(db, table, column))
        return 0;
    return aegisxd_exec(db, sql);
}

static int aegisxd_pcdn_mode_constraint_migrate(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    int rc;

    if (!db || sqlite3_exec(db, "SAVEPOINT aegis_pcdn_mode_probe", NULL, NULL, NULL) != SQLITE_OK)
        return -1;
    rc = sqlite3_prepare_v2(db,
        "UPDATE aegis_pcdn_settings SET mode='monitor' WHERE id=1", -1, &st, NULL);
    if (rc == SQLITE_OK)
        rc = sqlite3_step(st);
    if (st)
        sqlite3_finalize(st);
    sqlite3_exec(db, "ROLLBACK TO aegis_pcdn_mode_probe", NULL, NULL, NULL);
    sqlite3_exec(db, "RELEASE aegis_pcdn_mode_probe", NULL, NULL, NULL);
    if (rc == SQLITE_DONE)
        return 0;

    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        return -1;
    if (aegisxd_exec(db, "DROP TABLE IF EXISTS aegis_pcdn_settings_v2") != 0 ||
        aegisxd_exec(db,
        "CREATE TABLE aegis_pcdn_settings_v2 ("
        " id INTEGER PRIMARY KEY CHECK(id=1),"
        " enabled INTEGER NOT NULL DEFAULT 0,"
        " mode TEXT NOT NULL DEFAULT 'block' CHECK(mode IN ('block','monitor')),"
        " source_id TEXT NOT NULL DEFAULT 'openhosts-pcdn',"
        " revision INTEGER NOT NULL DEFAULT 1,"
        " apply_state TEXT NOT NULL DEFAULT 'disabled',"
        " last_error TEXT NOT NULL DEFAULT '',"
        " sync_state TEXT NOT NULL DEFAULT 'never',"
        " sync_error TEXT NOT NULL DEFAULT '',"
        " artifact_path TEXT NOT NULL DEFAULT '',"
        " artifact_sha256 TEXT NOT NULL DEFAULT '',"
        " rule_count INTEGER NOT NULL DEFAULT 0,"
        " rejected_count INTEGER NOT NULL DEFAULT 0,"
        " last_sync_at INTEGER NOT NULL DEFAULT 0,"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0 ||
        aegisxd_exec(db,
        "INSERT INTO aegis_pcdn_settings_v2("
        "id,enabled,mode,source_id,revision,apply_state,last_error,sync_state,sync_error,"
        "artifact_path,artifact_sha256,rule_count,rejected_count,last_sync_at,created_at,updated_at) "
        "SELECT id,enabled,CASE WHEN mode='monitor' THEN 'monitor' ELSE 'block' END,source_id,"
        "revision,apply_state,last_error,sync_state,sync_error,artifact_path,artifact_sha256,"
        "rule_count,rejected_count,last_sync_at,created_at,updated_at FROM aegis_pcdn_settings") != 0 ||
        aegisxd_exec(db, "DROP TABLE aegis_pcdn_settings") != 0 ||
        aegisxd_exec(db, "ALTER TABLE aegis_pcdn_settings_v2 RENAME TO aegis_pcdn_settings") != 0 ||
        sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        return -1;
    }
    return 0;
}

sqlite3_stmt *aegisxd_config_prepare(const char *sql)
{
    sqlite3_stmt *st = NULL;

    if (!g_aegisxd_config_db || !sql)
        return NULL;
    if (sqlite3_prepare_v2(g_aegisxd_config_db, sql, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-aegisxd] config prepare failed: %s sql=%s\n",
                sqlite3_errmsg(g_aegisxd_config_db), sql);
        return NULL;
    }
    return st;
}

sqlite3_stmt *aegisxd_prepare(const char *sql)
{
    sqlite3_stmt *st = NULL;

    if (!g_aegisxd_db || !sql)
        return NULL;
    if (sqlite3_prepare_v2(g_aegisxd_db, sql, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-aegisxd] prepare failed: %s sql=%s\n",
                sqlite3_errmsg(g_aegisxd_db), sql);
        return NULL;
    }
    return st;
}

static int aegisxd_db_init_fail(void)
{
    if (g_aegisxd_config_db) {
        sqlite3_close(g_aegisxd_config_db);
        g_aegisxd_config_db = NULL;
    }
    if (g_aegisxd_db) {
        sqlite3_close(g_aegisxd_db);
        g_aegisxd_db = NULL;
    }
    return -1;
}

static int aegisxd_state_set(const char *key, const char *value)
{
    sqlite3_stmt *st;
    int rc;

    if (!key || !value || !g_aegisxd_db)
        return -1;
    st = aegisxd_prepare(
        "INSERT INTO aegis_state(key,value,updated_at) VALUES(?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, value, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, aegisxd_now_s());
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int aegisxd_copy_file(const char *src, const char *dst)
{
    FILE *in;
    FILE *out;
    char buf[8192];
    size_t n;
    int rc = -1;

    if (!src || !dst || !src[0] || !dst[0])
        return -1;
    in = fopen(src, "rb");
    if (!in)
        return -1;
    out = fopen(dst, "wb");
    if (!out) {
        fclose(in);
        return -1;
    }
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n)
            goto out;
    }
    if (!ferror(in) && fflush(out) == 0)
        rc = 0;
out:
    fclose(out);
    fclose(in);
    if (rc != 0)
        unlink(dst);
    return rc;
}

static int aegisxd_migrate_legacy_feed_artifacts(void)
{
    sqlite3_stmt *st;
    sqlite3_stmt *up = NULL;
    int migrated = 0;
    int failed = 0;

    if (!g_aegisxd_db)
        return -1;
    if (aegisxd_mkdir_p(AEGISXD_FEED_DIR, 0755) != 0)
        return -1;
    st = aegisxd_prepare(
        "SELECT feed_id,artifact_path FROM aegis_feeds "
        "WHERE artifact_path LIKE '/tmp/dreamingwrt-aegisxd/feeds/%'");
    if (!st)
        return -1;
    up = aegisxd_prepare("UPDATE aegis_feeds SET artifact_path=?,updated_at=? WHERE feed_id=?");
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *feed_id = aegisxd_sqlite_text(st, 0, "");
        const char *old_path = aegisxd_sqlite_text(st, 1, "");
        const char *base = old_path ? strrchr(old_path, '/') : NULL;
        char new_path[AEGISXD_MAX_PATH];

        if (!feed_id[0] || !old_path[0] || !base || !base[1])
            continue;
        snprintf(new_path, sizeof(new_path), "%s/%s", AEGISXD_FEED_DIR, base + 1);
        if (access(old_path, R_OK) == 0) {
            if (aegisxd_copy_file(old_path, new_path) != 0) {
                failed++;
                continue;
            }
        } else if (access(new_path, R_OK) != 0) {
            failed++;
            continue;
        }
        if (up) {
            sqlite3_reset(up);
            sqlite3_clear_bindings(up);
            sqlite3_bind_text(up, 1, new_path, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(up, 2, aegisxd_now_s());
            sqlite3_bind_text(up, 3, feed_id, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(up) == SQLITE_DONE)
                migrated++;
            else
                failed++;
        }
    }
    sqlite3_finalize(st);
    if (up)
        sqlite3_finalize(up);
    if (migrated > 0) {
        char nbuf[32];

        snprintf(nbuf, sizeof(nbuf), "%d", migrated);
        aegisxd_state_set("feed_artifact_migrated_count", nbuf);
        aegisxd_state_set("feed_artifact_storage", AEGISXD_FEED_DIR);
    }
    if (failed > 0) {
        char nbuf[32];

        snprintf(nbuf, sizeof(nbuf), "%d", failed);
        aegisxd_state_set("feed_artifact_migrate_failed_count", nbuf);
    }
    return failed == 0 ? 0 : -1;
}

int aegisxd_db_init(void)
{
    char schema[16];

    if (g_aegisxd_config_db && g_aegisxd_db)
        return 0;
    if (aegisxd_mkdir_p(AEGISXD_CONFIG_DIR, 0755) != 0) {
        fprintf(stderr, "[dreamingwrt-aegisxd] create %s failed\n", AEGISXD_CONFIG_DIR);
        return -1;
    }
    if (aegisxd_mkdir_p(AEGISXD_WORK_DIR, 0755) != 0) {
        fprintf(stderr, "[dreamingwrt-aegisxd] create %s failed\n", AEGISXD_WORK_DIR);
        return -1;
    }
    if (aegisxd_mkdir_p(AEGISXD_FEED_DIR, 0755) != 0) {
        fprintf(stderr, "[dreamingwrt-aegisxd] create %s failed\n", AEGISXD_FEED_DIR);
        return -1;
    }
    if (aegisxd_mkdir_p(AEGISXD_RUNTIME_DIR, 0755) != 0) {
        fprintf(stderr, "[dreamingwrt-aegisxd] create %s failed\n", AEGISXD_RUNTIME_DIR);
        return -1;
    }
    if (sqlite3_open(AEGISXD_CONFIG_DB_PATH, &g_aegisxd_config_db) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-aegisxd] open %s failed\n", AEGISXD_CONFIG_DB_PATH);
        return aegisxd_db_init_fail();
    }
    sqlite3_busy_timeout(g_aegisxd_config_db, 3000);
    if (sqlite3_open(AEGISXD_DB_PATH, &g_aegisxd_db) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-aegisxd] open %s failed\n", AEGISXD_DB_PATH);
        return aegisxd_db_init_fail();
    }
    sqlite3_busy_timeout(g_aegisxd_db, 3000);
    if (aegisxd_exec(g_aegisxd_config_db, "PRAGMA journal_mode=WAL") != 0 ||
        aegisxd_exec(g_aegisxd_config_db, "PRAGMA foreign_keys=ON") != 0 ||
        aegisxd_exec(g_aegisxd_db, "PRAGMA journal_mode=WAL") != 0 ||
        aegisxd_exec(g_aegisxd_db, "PRAGMA foreign_keys=ON") != 0)
        return aegisxd_db_init_fail();

    if (aegisxd_exec(g_aegisxd_config_db,
        "CREATE TABLE IF NOT EXISTS aegis_settings ("
        " id INTEGER PRIMARY KEY CHECK(id=1),"
        " enabled INTEGER NOT NULL DEFAULT 0,"
        " mode TEXT NOT NULL DEFAULT 'off',"
        " source_level TEXT NOT NULL DEFAULT 'open',"
        " suricata_version TEXT NOT NULL DEFAULT 'auto',"
        " default_action TEXT NOT NULL DEFAULT 'alert',"
        " logging_enabled INTEGER NOT NULL DEFAULT 1,"
        " suricata_interface TEXT NOT NULL DEFAULT '',"
        " suricata_queue_num INTEGER NOT NULL DEFAULT 0,"
        " suricata_fail_open INTEGER NOT NULL DEFAULT 1,"
        /*
         * Traffic-log collection scope. 'all' keeps every security event,
         * 'blocked' keeps only the ones that were actually stopped. This is a
         * filter over security events (policy / DNS / reputation hits), not
         * over forwarded traffic, so its volume is hit count and not throughput.
         *
         * The three source toggles decide whether a class of event joins the
         * log at all; they carry no scope of their own, because the scope is a
         * single global choice over the combined set.
         */
        " traffic_log_scope TEXT NOT NULL DEFAULT 'all'"
        "   CHECK(traffic_log_scope IN ('all','blocked')),"
        " traffic_log_gateway_dns INTEGER NOT NULL DEFAULT 1,"
        " traffic_log_aegisx_service INTEGER NOT NULL DEFAULT 1,"
        " traffic_log_device_admin INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        return aegisxd_db_init_fail();
    if (aegisxd_add_column_if_missing(g_aegisxd_config_db, "aegis_settings",
        "suricata_interface",
        "ALTER TABLE aegis_settings ADD COLUMN suricata_interface TEXT NOT NULL DEFAULT ''") != 0 ||
        aegisxd_add_column_if_missing(g_aegisxd_config_db, "aegis_settings",
        "suricata_queue_num",
        "ALTER TABLE aegis_settings ADD COLUMN suricata_queue_num INTEGER NOT NULL DEFAULT 0") != 0 ||
        aegisxd_add_column_if_missing(g_aegisxd_config_db, "aegis_settings",
        "suricata_fail_open",
        "ALTER TABLE aegis_settings ADD COLUMN suricata_fail_open INTEGER NOT NULL DEFAULT 1") != 0)
        return aegisxd_db_init_fail();
    /*
     * Existing installs already have the table, so the columns above only
     * reach them through these migrations. ALTER TABLE ADD COLUMN cannot carry
     * the CHECK constraint, so the write path validates the value instead;
     * a fresh install gets both, an upgraded one gets the validation.
     */
    if (aegisxd_add_column_if_missing(g_aegisxd_config_db, "aegis_settings",
        "traffic_log_scope",
        "ALTER TABLE aegis_settings ADD COLUMN traffic_log_scope TEXT NOT NULL DEFAULT 'all'") != 0 ||
        aegisxd_add_column_if_missing(g_aegisxd_config_db, "aegis_settings",
        "traffic_log_gateway_dns",
        "ALTER TABLE aegis_settings ADD COLUMN traffic_log_gateway_dns INTEGER NOT NULL DEFAULT 1") != 0 ||
        aegisxd_add_column_if_missing(g_aegisxd_config_db, "aegis_settings",
        "traffic_log_aegisx_service",
        "ALTER TABLE aegis_settings ADD COLUMN traffic_log_aegisx_service INTEGER NOT NULL DEFAULT 1") != 0 ||
        aegisxd_add_column_if_missing(g_aegisxd_config_db, "aegis_settings",
        "traffic_log_device_admin",
        "ALTER TABLE aegis_settings ADD COLUMN traffic_log_device_admin INTEGER NOT NULL DEFAULT 0") != 0)
        return aegisxd_db_init_fail();
    if (aegisxd_exec(g_aegisxd_config_db,
        "CREATE TABLE IF NOT EXISTS aegis_honeypots ("
        " id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " enabled INTEGER NOT NULL DEFAULT 0,"
        " network_id TEXT NOT NULL,"
        " interface TEXT NOT NULL,"
        " address TEXT NOT NULL UNIQUE,"
        " profile TEXT NOT NULL DEFAULT 'linux_server',"
        " services_json TEXT NOT NULL DEFAULT '[]',"
        " max_connections INTEGER NOT NULL DEFAULT 128,"
        " max_per_source INTEGER NOT NULL DEFAULT 8,"
        " capture_bytes INTEGER NOT NULL DEFAULT 4096,"
        " idle_timeout INTEGER NOT NULL DEFAULT 20,"
        " session_timeout INTEGER NOT NULL DEFAULT 60,"
        " apply_state TEXT NOT NULL DEFAULT 'disabled',"
        " last_error TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0 ||
        aegisxd_exec(g_aegisxd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_aegis_honeypots_network "
        "ON aegis_honeypots(network_id,enabled,address)") != 0)
        return aegisxd_db_init_fail();
    if (aegisxd_exec(g_aegisxd_config_db,
        "CREATE TABLE IF NOT EXISTS aegis_content_policies ("
        " id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " mode TEXT NOT NULL DEFAULT 'basic',"
        " scope_json TEXT NOT NULL DEFAULT '{\"type\":\"all\",\"devices\":[],\"networks\":[]}',"
        " ad_block INTEGER NOT NULL DEFAULT 0,"
        " safe_search_json TEXT NOT NULL DEFAULT '{\"google\":false,\"bing\":false,\"youtube\":false}',"
        " categories_json TEXT NOT NULL DEFAULT '[]',"
        " schedule_json TEXT NOT NULL DEFAULT '{\"type\":\"always\"}',"
        " revision INTEGER NOT NULL DEFAULT 1,"
        " apply_state TEXT NOT NULL DEFAULT 'pending',"
        " last_error TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0 ||
        aegisxd_exec(g_aegisxd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_aegis_content_policies_enabled "
        "ON aegis_content_policies(enabled,mode,updated_at)") != 0 ||
        aegisxd_exec(g_aegisxd_config_db,
        "CREATE TABLE IF NOT EXISTS aegis_domain_overrides ("
        " id TEXT PRIMARY KEY,"
        " policy_id TEXT NOT NULL DEFAULT '',"
        " domain TEXT NOT NULL,"
        " action TEXT NOT NULL,"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " note TEXT NOT NULL DEFAULT '',"
        " apply_state TEXT NOT NULL DEFAULT 'pending',"
        " last_error TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0,"
        " UNIQUE(policy_id,domain))") != 0 ||
        aegisxd_exec(g_aegisxd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_aegis_domain_overrides_action "
        "ON aegis_domain_overrides(enabled,action,domain)") != 0 ||
        aegisxd_exec(g_aegisxd_config_db,
        "CREATE TABLE IF NOT EXISTS aegis_content_meta ("
        " id INTEGER PRIMARY KEY CHECK(id=1),"
        " managed INTEGER NOT NULL DEFAULT 0,"
        " revision INTEGER NOT NULL DEFAULT 0,"
        " last_apply_state TEXT NOT NULL DEFAULT 'legacy',"
        " last_error TEXT NOT NULL DEFAULT '',"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0 ||
        aegisxd_exec(g_aegisxd_config_db,
        "INSERT OR IGNORE INTO aegis_content_meta"
        "(id,managed,revision,last_apply_state,last_error,updated_at) "
        "VALUES(1,0,0,'legacy','',0)") != 0)
        return aegisxd_db_init_fail();
    if (aegisxd_exec(g_aegisxd_config_db,
        "CREATE TABLE IF NOT EXISTS aegis_pcdn_settings ("
        " id INTEGER PRIMARY KEY CHECK(id=1),"
        " enabled INTEGER NOT NULL DEFAULT 0,"
        " mode TEXT NOT NULL DEFAULT 'block' CHECK(mode IN ('block','monitor')),"
        " source_id TEXT NOT NULL DEFAULT 'openhosts-pcdn',"
        " revision INTEGER NOT NULL DEFAULT 1,"
        " apply_state TEXT NOT NULL DEFAULT 'disabled',"
        " last_error TEXT NOT NULL DEFAULT '',"
        " sync_state TEXT NOT NULL DEFAULT 'never',"
        " sync_error TEXT NOT NULL DEFAULT '',"
        " artifact_path TEXT NOT NULL DEFAULT '',"
        " artifact_sha256 TEXT NOT NULL DEFAULT '',"
        " rule_count INTEGER NOT NULL DEFAULT 0,"
        " rejected_count INTEGER NOT NULL DEFAULT 0,"
        " last_sync_at INTEGER NOT NULL DEFAULT 0,"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0 ||
        aegisxd_exec(g_aegisxd_config_db,
        "INSERT OR IGNORE INTO aegis_pcdn_settings"
        "(id,enabled,mode,source_id,revision,apply_state,sync_state,created_at,updated_at) "
        "VALUES(1,0,'block','openhosts-pcdn',1,'disabled','never',0,0)") != 0 ||
        aegisxd_add_column_if_missing(g_aegisxd_config_db, "aegis_pcdn_settings",
        "artifact_path", "ALTER TABLE aegis_pcdn_settings ADD COLUMN artifact_path TEXT NOT NULL DEFAULT ''") != 0 ||
        aegisxd_add_column_if_missing(g_aegisxd_config_db, "aegis_pcdn_settings",
        "artifact_sha256", "ALTER TABLE aegis_pcdn_settings ADD COLUMN artifact_sha256 TEXT NOT NULL DEFAULT ''") != 0 ||
        aegisxd_pcdn_mode_constraint_migrate(g_aegisxd_config_db) != 0 ||
        aegisxd_exec(g_aegisxd_config_db,
        "DROP TABLE IF EXISTS aegis_pcdn_rules") != 0)
        return aegisxd_db_init_fail();
    if (aegisxd_exec(g_aegisxd_config_db,
        "CREATE TABLE IF NOT EXISTS aegis_signature_policy_overrides ("
        " gid INTEGER NOT NULL DEFAULT 1 CHECK(gid=1),"
        " sid INTEGER NOT NULL,"
        " target_rev INTEGER NOT NULL,"
        " enabled_override INTEGER NOT NULL DEFAULT -1 CHECK(enabled_override IN (-1,0,1)),"
        " action TEXT NOT NULL DEFAULT 'inherit' CHECK(action IN ('inherit','alert','drop','reject','pass')),"
        " suppressed INTEGER NOT NULL DEFAULT 0,"
        " reason TEXT NOT NULL DEFAULT '',"
        " revision INTEGER NOT NULL DEFAULT 1,"
        " apply_state TEXT NOT NULL DEFAULT 'apply_required',"
        " last_error TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0,"
        " PRIMARY KEY(gid,sid))") != 0 ||
        aegisxd_exec(g_aegisxd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_aegis_signature_policy_apply "
        "ON aegis_signature_policy_overrides(apply_state,updated_at)") != 0 ||
        aegisxd_exec(g_aegisxd_config_db,
        "CREATE INDEX IF NOT EXISTS idx_aegis_signature_policy_suppressed "
        "ON aegis_signature_policy_overrides(suppressed,enabled_override,action)") != 0)
        return aegisxd_db_init_fail();

    if (aegisxd_exec(g_aegisxd_config_db,
        "INSERT OR IGNORE INTO aegis_settings"
        "(id,enabled,mode,source_level,suricata_version,default_action,logging_enabled,updated_at) "
        "VALUES(1,0,'off','open','auto','alert',1,0)") != 0)
        return aegisxd_db_init_fail();
    if (aegisxd_certificate_schema_init() != 0)
        return aegisxd_db_init_fail();

    if (aegisxd_exec(g_aegisxd_db,
        "CREATE TABLE IF NOT EXISTS aegis_state ("
        " key TEXT PRIMARY KEY,"
        " value TEXT NOT NULL DEFAULT '',"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        return aegisxd_db_init_fail();
    if (aegisxd_exec(g_aegisxd_db,
        "CREATE TABLE IF NOT EXISTS aegis_feeds ("
        " feed_id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " kind TEXT NOT NULL DEFAULT '',"
        " url TEXT NOT NULL DEFAULT '',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " format TEXT NOT NULL DEFAULT '',"
        " version TEXT NOT NULL DEFAULT '',"
        " etag TEXT NOT NULL DEFAULT '',"
        " last_modified TEXT NOT NULL DEFAULT '',"
        " content_type TEXT NOT NULL DEFAULT '',"
        " sha256 TEXT NOT NULL DEFAULT '',"
        " last_success_at INTEGER NOT NULL DEFAULT 0,"
        " last_error TEXT NOT NULL DEFAULT '',"
        " item_count INTEGER NOT NULL DEFAULT 0,"
        " artifact_path TEXT NOT NULL DEFAULT '',"
        " meta_json TEXT NOT NULL DEFAULT '{}',"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0)
        return aegisxd_db_init_fail();
    if (aegisxd_add_column_if_missing(g_aegisxd_db, "aegis_feeds", "format",
        "ALTER TABLE aegis_feeds ADD COLUMN format TEXT NOT NULL DEFAULT ''") != 0 ||
        aegisxd_add_column_if_missing(g_aegisxd_db, "aegis_feeds", "etag",
        "ALTER TABLE aegis_feeds ADD COLUMN etag TEXT NOT NULL DEFAULT ''") != 0 ||
        aegisxd_add_column_if_missing(g_aegisxd_db, "aegis_feeds", "last_modified",
        "ALTER TABLE aegis_feeds ADD COLUMN last_modified TEXT NOT NULL DEFAULT ''") != 0 ||
        aegisxd_add_column_if_missing(g_aegisxd_db, "aegis_feeds", "content_type",
        "ALTER TABLE aegis_feeds ADD COLUMN content_type TEXT NOT NULL DEFAULT ''") != 0 ||
        aegisxd_add_column_if_missing(g_aegisxd_db, "aegis_feeds", "sha256",
        "ALTER TABLE aegis_feeds ADD COLUMN sha256 TEXT NOT NULL DEFAULT ''") != 0 ||
        aegisxd_add_column_if_missing(g_aegisxd_db, "aegis_feeds", "artifact_path",
        "ALTER TABLE aegis_feeds ADD COLUMN artifact_path TEXT NOT NULL DEFAULT ''") != 0 ||
        aegisxd_add_column_if_missing(g_aegisxd_db, "aegis_feeds", "meta_json",
        "ALTER TABLE aegis_feeds ADD COLUMN meta_json TEXT NOT NULL DEFAULT '{}'") != 0)
        return aegisxd_db_init_fail();
    if (aegisxd_exec(g_aegisxd_db,
        "CREATE INDEX IF NOT EXISTS idx_aegis_feeds_kind "
        "ON aegis_feeds(kind,enabled,feed_id)") != 0)
        return aegisxd_db_init_fail();
    if (aegisxd_exec(g_aegisxd_db,
        "CREATE TABLE IF NOT EXISTS aegis_artifacts ("
        " artifact_id TEXT PRIMARY KEY,"
        " kind TEXT NOT NULL DEFAULT '',"
        " path TEXT NOT NULL DEFAULT '',"
        " sha256 TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0,"
        " applied_at INTEGER NOT NULL DEFAULT 0,"
        " meta_json TEXT NOT NULL DEFAULT '{}')") != 0)
        return aegisxd_db_init_fail();
    if (aegisxd_exec(g_aegisxd_db,
        "CREATE TABLE IF NOT EXISTS aegis_events ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " ts INTEGER NOT NULL DEFAULT 0,"
        " event_type TEXT NOT NULL DEFAULT '',"
        " level TEXT NOT NULL DEFAULT 'info',"
        " action TEXT NOT NULL DEFAULT '',"
        " policy_id TEXT NOT NULL DEFAULT '',"
        " policy_name TEXT NOT NULL DEFAULT '',"
        " policy_type TEXT NOT NULL DEFAULT '',"
        " rule_id TEXT NOT NULL DEFAULT '',"
        " rule_name TEXT NOT NULL DEFAULT '',"
        " risk TEXT NOT NULL DEFAULT '',"
        " risk_category TEXT NOT NULL DEFAULT '',"
        " source_ip TEXT NOT NULL DEFAULT '',"
        " source_mac TEXT NOT NULL DEFAULT '',"
        " source_port INTEGER NOT NULL DEFAULT 0,"
        " destination_ip TEXT NOT NULL DEFAULT '',"
        " destination_host TEXT NOT NULL DEFAULT '',"
        " destination_port INTEGER NOT NULL DEFAULT 0,"
        " protocol TEXT NOT NULL DEFAULT '',"
        " app_id TEXT NOT NULL DEFAULT '',"
        " app_name TEXT NOT NULL DEFAULT '',"
        " in_interface TEXT NOT NULL DEFAULT '',"
        " out_interface TEXT NOT NULL DEFAULT '',"
        " rx_bytes INTEGER NOT NULL DEFAULT 0,"
        " tx_bytes INTEGER NOT NULL DEFAULT 0,"
        " flow_id TEXT NOT NULL DEFAULT '',"
        " reason TEXT NOT NULL DEFAULT '',"
        " source TEXT NOT NULL DEFAULT '',"
        " occurrence_count INTEGER NOT NULL DEFAULT 1,"
        " first_seen INTEGER NOT NULL DEFAULT 0,"
        " last_seen INTEGER NOT NULL DEFAULT 0,"
        " meta_json TEXT NOT NULL DEFAULT '{}')") != 0 ||
        aegisxd_exec(g_aegisxd_db,
        "CREATE INDEX IF NOT EXISTS idx_aegis_events_ts "
        "ON aegis_events(ts DESC,id DESC)") != 0 ||
        aegisxd_exec(g_aegisxd_db,
        "CREATE INDEX IF NOT EXISTS idx_aegis_events_policy "
        "ON aegis_events(policy_id,ts DESC)") != 0 ||
        aegisxd_exec(g_aegisxd_db,
        "CREATE INDEX IF NOT EXISTS idx_aegis_events_action "
        "ON aegis_events(action,ts DESC)") != 0)
        return aegisxd_db_init_fail();
    if (aegisxd_add_column_if_missing(g_aegisxd_db, "aegis_events", "occurrence_count",
        "ALTER TABLE aegis_events ADD COLUMN occurrence_count INTEGER NOT NULL DEFAULT 1") != 0 ||
        aegisxd_add_column_if_missing(g_aegisxd_db, "aegis_events", "first_seen",
        "ALTER TABLE aegis_events ADD COLUMN first_seen INTEGER NOT NULL DEFAULT 0") != 0 ||
        aegisxd_add_column_if_missing(g_aegisxd_db, "aegis_events", "last_seen",
        "ALTER TABLE aegis_events ADD COLUMN last_seen INTEGER NOT NULL DEFAULT 0") != 0)
        return aegisxd_db_init_fail();
    if (aegisxd_exec(g_aegisxd_db,
        "CREATE INDEX IF NOT EXISTS idx_aegis_events_honeypot "
        "ON aegis_events(policy_type,source_ip,ts DESC)") != 0)
        return aegisxd_db_init_fail();
    if (aegisxd_exec(g_aegisxd_db,
        "CREATE INDEX IF NOT EXISTS idx_aegis_events_dns_aggregate "
        "ON aegis_events(policy_type,policy_id,source,destination_host,source_ip,last_seen DESC)") != 0)
        return aegisxd_db_init_fail();
    if (aegisxd_exec(g_aegisxd_db,
        "CREATE TABLE IF NOT EXISTS aegis_suricata_rules ("
        " sid INTEGER PRIMARY KEY,"
        " rev INTEGER NOT NULL DEFAULT 0,"
        " category TEXT NOT NULL DEFAULT '',"
        " classtype TEXT NOT NULL DEFAULT '',"
        " severity INTEGER NOT NULL DEFAULT 0,"
        " action TEXT NOT NULL DEFAULT '',"
        " protocol TEXT NOT NULL DEFAULT '',"
        " msg TEXT NOT NULL DEFAULT '',"
        " enabled_default INTEGER NOT NULL DEFAULT 1,"
        " rule_text TEXT NOT NULL DEFAULT '',"
        " source_feed TEXT NOT NULL DEFAULT '',"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0 ||
        aegisxd_exec(g_aegisxd_db,
        "CREATE INDEX IF NOT EXISTS idx_aegis_suricata_category "
        "ON aegis_suricata_rules(category,enabled_default)") != 0 ||
        aegisxd_exec(g_aegisxd_db,
        "CREATE TABLE IF NOT EXISTS aegis_signature_metadata ("
        " sid INTEGER PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " description TEXT NOT NULL DEFAULT '',"
        " cve TEXT NOT NULL DEFAULT '',"
        " mitre_tags TEXT NOT NULL DEFAULT '',"
        " affected_products TEXT NOT NULL DEFAULT '',"
        " attack_target TEXT NOT NULL DEFAULT '',"
        " malware_family TEXT NOT NULL DEFAULT '',"
        " source_feed TEXT NOT NULL DEFAULT '',"
        " updated_at INTEGER NOT NULL DEFAULT 0)") != 0 ||
        aegisxd_exec(g_aegisxd_db,
        "CREATE TABLE IF NOT EXISTS aegis_domain_categories ("
        " domain TEXT NOT NULL,"
        " category TEXT NOT NULL,"
        " source_feed TEXT NOT NULL,"
        " confidence INTEGER NOT NULL DEFAULT 50,"
        " first_seen INTEGER NOT NULL DEFAULT 0,"
        " last_seen INTEGER NOT NULL DEFAULT 0,"
        " PRIMARY KEY(domain,category,source_feed))") != 0 ||
        aegisxd_exec(g_aegisxd_db,
        "CREATE INDEX IF NOT EXISTS idx_aegis_domain_category "
        "ON aegis_domain_categories(category,domain)") != 0 ||
        aegisxd_exec(g_aegisxd_db,
        "CREATE TABLE IF NOT EXISTS aegis_reputation_items ("
        " kind TEXT NOT NULL,"
        " value TEXT NOT NULL,"
        " category TEXT NOT NULL DEFAULT '',"
        " severity INTEGER NOT NULL DEFAULT 0,"
        " confidence INTEGER NOT NULL DEFAULT 50,"
        " source_feed TEXT NOT NULL,"
        " expires_at INTEGER NOT NULL DEFAULT 0,"
        " first_seen INTEGER NOT NULL DEFAULT 0,"
        " last_seen INTEGER NOT NULL DEFAULT 0,"
        " PRIMARY KEY(kind,value,source_feed))") != 0 ||
        aegisxd_exec(g_aegisxd_db,
        "CREATE INDEX IF NOT EXISTS idx_aegis_reputation_kind_value "
        "ON aegis_reputation_items(kind,value)") != 0 ||
        aegisxd_exec(g_aegisxd_db,
        "CREATE TABLE IF NOT EXISTS aegis_import_state ("
        " feed_id TEXT PRIMARY KEY,"
        " state TEXT NOT NULL DEFAULT 'idle',"
        " last_started_at INTEGER NOT NULL DEFAULT 0,"
        " last_finished_at INTEGER NOT NULL DEFAULT 0,"
        " last_error TEXT NOT NULL DEFAULT '',"
        " imported_count INTEGER NOT NULL DEFAULT 0,"
        " skipped_count INTEGER NOT NULL DEFAULT 0,"
        " artifact_sha256 TEXT NOT NULL DEFAULT '',"
        " meta_json TEXT NOT NULL DEFAULT '{}')") != 0)
        return aegisxd_db_init_fail();
    if (aegisxd_exec(g_aegisxd_db,
        "CREATE TABLE IF NOT EXISTS aegis_job_state ("
        " job_id TEXT PRIMARY KEY,"
        " op TEXT NOT NULL DEFAULT '',"
        " feed_id TEXT NOT NULL DEFAULT '',"
        " state TEXT NOT NULL DEFAULT 'idle',"
        " dry_run INTEGER NOT NULL DEFAULT 1,"
        " pid INTEGER NOT NULL DEFAULT 0,"
        " started_at INTEGER NOT NULL DEFAULT 0,"
        " finished_at INTEGER NOT NULL DEFAULT 0,"
        " ok_count INTEGER NOT NULL DEFAULT 0,"
        " fail_count INTEGER NOT NULL DEFAULT 0,"
        " last_error TEXT NOT NULL DEFAULT '',"
        " result_json TEXT NOT NULL DEFAULT '{}')") != 0 ||
        aegisxd_exec(g_aegisxd_db,
        "CREATE INDEX IF NOT EXISTS idx_aegis_job_state_state "
        "ON aegis_job_state(state,started_at)") != 0)
        return aegisxd_db_init_fail();

    snprintf(schema, sizeof(schema), "%d", AEGISXD_SCHEMA_VERSION);
    aegisxd_state_set("schema_version", schema);
    aegisxd_state_set("state", "idle");
    aegisxd_state_set("feed_artifact_storage", AEGISXD_FEED_DIR);
    if (aegisxd_seed_builtin_feeds() != 0)
        return aegisxd_db_init_fail();
    (void)aegisxd_migrate_legacy_feed_artifacts();
    return 0;
}

void aegisxd_db_close(void)
{
    if (g_aegisxd_config_db) {
        sqlite3_close(g_aegisxd_config_db);
        g_aegisxd_config_db = NULL;
    }
    if (g_aegisxd_db) {
        sqlite3_close(g_aegisxd_db);
        g_aegisxd_db = NULL;
    }
}

int aegisxd_settings_load(struct aegisxd_settings *out)
{
    sqlite3_stmt *st;
    int rc;

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    out->enabled = 0;
    snprintf(out->mode, sizeof(out->mode), "%s", "off");
    snprintf(out->source_level, sizeof(out->source_level), "%s", "open");
    snprintf(out->suricata_version, sizeof(out->suricata_version), "%s", "auto");
    snprintf(out->default_action, sizeof(out->default_action), "%s", "alert");
    out->logging_enabled = 1;
    out->suricata_interface[0] = '\0';
    out->suricata_queue_num = 0;
    out->suricata_fail_open = 1;
    snprintf(out->traffic_log_scope, sizeof(out->traffic_log_scope), "%s", "all");
    out->traffic_log_gateway_dns = 1;
    out->traffic_log_aegisx_service = 1;
    out->traffic_log_device_admin = 0;

    st = aegisxd_config_prepare(
        "SELECT enabled,mode,source_level,suricata_version,default_action,logging_enabled,"
        "suricata_interface,suricata_queue_num,suricata_fail_open,"
        "traffic_log_scope,traffic_log_gateway_dns,traffic_log_aegisx_service,"
        "traffic_log_device_admin "
        "FROM aegis_settings WHERE id=1");
    if (!st)
        return -1;
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        out->enabled = sqlite3_column_int(st, 0) ? 1 : 0;
        snprintf(out->mode, sizeof(out->mode), "%s", aegisxd_sqlite_text(st, 1, "off"));
        snprintf(out->source_level, sizeof(out->source_level), "%s",
                 aegisxd_sqlite_text(st, 2, "open"));
        snprintf(out->suricata_version, sizeof(out->suricata_version), "%s",
                 aegisxd_sqlite_text(st, 3, "auto"));
        snprintf(out->default_action, sizeof(out->default_action), "%s",
                 aegisxd_sqlite_text(st, 4, "alert"));
        out->logging_enabled = sqlite3_column_int(st, 5) ? 1 : 0;
        snprintf(out->suricata_interface, sizeof(out->suricata_interface), "%s",
                 aegisxd_sqlite_text(st, 6, ""));
        out->suricata_queue_num = sqlite3_column_int(st, 7);
        out->suricata_fail_open = sqlite3_column_int(st, 8) ? 1 : 0;
        snprintf(out->traffic_log_scope, sizeof(out->traffic_log_scope), "%s",
                 aegisxd_sqlite_text(st, 9, "all"));
        out->traffic_log_gateway_dns = sqlite3_column_int(st, 10) ? 1 : 0;
        out->traffic_log_aegisx_service = sqlite3_column_int(st, 11) ? 1 : 0;
        out->traffic_log_device_admin = sqlite3_column_int(st, 12) ? 1 : 0;
        /* A row written before the CHECK existed, or by hand, must not be
         * handed onward as a third value the rest of the code cannot read. */
        if (strcmp(out->traffic_log_scope, "all") &&
            strcmp(out->traffic_log_scope, "blocked"))
            snprintf(out->traffic_log_scope, sizeof(out->traffic_log_scope),
                     "%s", "all");
    }
    sqlite3_finalize(st);
    return rc == SQLITE_ROW || rc == SQLITE_DONE ? 0 : -1;
}

int aegisxd_traffic_log_scope_valid(const char *scope)
{
    return scope && (!strcmp(scope, "all") || !strcmp(scope, "blocked"));
}

/*
 * Persist the traffic-log settings.
 *
 * Every field is optional: NULL scope or a negative flag means "leave this one
 * alone", so a caller that only wants to flip one toggle does not have to
 * resend the rest and cannot blank a value by omitting it. Returns 0 on
 * success, -1 on a storage failure and -2 on an invalid scope.
 */
int aegisxd_traffic_log_settings_save(const char *scope, int gateway_dns,
                                      int aegisx_service, int device_admin)
{
    sqlite3_stmt *st;
    int rc;

    if (scope && !aegisxd_traffic_log_scope_valid(scope))
        return -2;
    if (!g_aegisxd_config_db)
        return -1;
    st = aegisxd_config_prepare(
        "UPDATE aegis_settings SET "
        "traffic_log_scope=COALESCE(?1,traffic_log_scope),"
        "traffic_log_gateway_dns=CASE WHEN ?2<0 THEN traffic_log_gateway_dns ELSE ?2 END,"
        "traffic_log_aegisx_service=CASE WHEN ?3<0 THEN traffic_log_aegisx_service ELSE ?3 END,"
        "traffic_log_device_admin=CASE WHEN ?4<0 THEN traffic_log_device_admin ELSE ?4 END,"
        "updated_at=?5 WHERE id=1");
    if (!st)
        return -1;
    if (scope)
        sqlite3_bind_text(st, 1, scope, -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(st, 1);
    sqlite3_bind_int(st, 2, gateway_dns);
    sqlite3_bind_int(st, 3, aegisx_service);
    sqlite3_bind_int(st, 4, device_admin);
    sqlite3_bind_int64(st, 5, (sqlite3_int64)time(NULL));
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

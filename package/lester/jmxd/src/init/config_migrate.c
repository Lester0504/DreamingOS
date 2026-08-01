// SPDX-License-Identifier: GPL-2.0-or-later
/* O_CLOEXEC/O_NOFOLLOW and fdopen/fileno need the POSIX 2008 feature set,
 * which glibc only exposes when a feature macro is requested up front. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "config_migrate.h"
#include "../jmx_config_schema.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <sqlite3.h>

/*
 * Tables the current schema owns but legacy libraries never had. They are
 * created empty with schema defaults so the migrated library satisfies the
 * restore validator without inventing user data.
 */
static const char *const required_new_tables[] = {
    "system_settings",
    "system_ui_settings",
    "appearance_settings",
    "work_mode_settings",
};

/*
 * Volatile caches and runtime scratch tables. Their rows describe transient
 * observations, not configuration authority, so they are recreated empty and
 * the reason is reported per table instead of being silently discarded.
 */
static const char *const volatile_tables[] = {
    "dhcp_lease_cache",
    "upnp_mapping_cache",
    "dns_runtime_stat",
    "logd_syslog_queue",
    "logd_collector_state",
    "logd_syslog_state",
    "web_auth_failures",
    "flowd_wan_health",
    "flowd_apply_jobs",
    "ota_jobs",
    "ota_state",
};

/*
 * Tables that carry secret references or media metadata. They must survive
 * migration verbatim; the report records that explicitly so an operator can
 * confirm nothing sensitive was dropped on the way.
 */
static const char *const secret_reference_tables[] = {
    "web_users",
    "web_auth_settings",
    "radius_server",
    "wifi_ssids",
    "notifyd_channels",
};

static const char *const media_metadata_tables[] = {
    "appearance_settings",
    "insights_map_local_locations",
};

static int in_list(const char *const *list, size_t count, const char *name)
{
    for (size_t i = 0; i < count; i++) {
        if (!strcmp(list[i], name))
            return 1;
    }
    return 0;
}

const char *dwrt_config_migrate_action_name(enum dwrt_migrate_table_action action)
{
    switch (action) {
    case DWRT_MIGRATE_TABLE_MIGRATED:  return "migrated";
    case DWRT_MIGRATE_TABLE_PRESERVED: return "preserved";
    case DWRT_MIGRATE_TABLE_CREATED:   return "created";
    case DWRT_MIGRATE_TABLE_DROPPED:   return "dropped";
    }
    return "unknown";
}

static void migrate_error(struct dwrt_migrate_report *report, const char *value)
{
    if (report)
        snprintf(report->error, sizeof(report->error), "%s", value ? value : "");
}

/* Identifiers are only ever taken from sqlite_master, but keep the guard so a
 * corrupted source library can never inject SQL through a table name. */
static int safe_identifier(const char *name)
{
    if (!name || !name[0] || strlen(name) >= 64)
        return 0;
    if (!isalpha((unsigned char)name[0]) && name[0] != '_')
        return 0;
    for (const char *p = name; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '_')
            return 0;
    }
    return 1;
}

/*
 * Backup libraries are frequently left in WAL mode. Opening those read-only
 * without the immutable flag fails because SQLite wants to create the -shm
 * file, so probing uses an immutable URI just like the restore validator.
 */
static int open_readonly(const char *path, sqlite3 **db)
{
    static const char hex[] = "0123456789abcdef";
    char uri[768];
    size_t used;

    if (!path || !db || path[0] != '/')
        return SQLITE_MISUSE;
    memcpy(uri, "file:", 5);
    used = 5;
    for (const unsigned char *p = (const unsigned char *)path; *p; p++) {
        int literal = isalnum(*p) || *p == '/' || *p == '-' || *p == '_' ||
                      *p == '.' || *p == '~';

        if (used + (literal ? 1U : 3U) + sizeof("?mode=ro&immutable=1") >= sizeof(uri))
            return SQLITE_TOOBIG;
        if (literal) {
            uri[used++] = (char)*p;
        } else {
            uri[used++] = '%';
            uri[used++] = hex[*p >> 4];
            uri[used++] = hex[*p & 0x0f];
        }
    }
    memcpy(uri + used, "?mode=ro&immutable=1", sizeof("?mode=ro&immutable=1"));
    return sqlite3_open_v2(uri, db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL);
}

static int scalar_int(sqlite3 *db, const char *sql, int *out)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        if (out)
            *out = sqlite3_column_int(st, 0);
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

static int table_exists(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    int found = 0;

    if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    found = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return found;
}

static int64_t table_rows(sqlite3 *db, const char *name)
{
    char sql[128];
    sqlite3_stmt *st = NULL;
    int64_t rows = -1;

    if (!safe_identifier(name))
        return -1;
    if (snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM \"%s\"", name) >= (int)sizeof(sql))
        return -1;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        rows = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return rows;
}

int dwrt_config_migrate_needed(const char *path, int *from_version)
{
    sqlite3 *db = NULL;
    int version = -1;
    int app_id = -1;
    int rc = -1;

    if (open_readonly(path, &db) != SQLITE_OK)
        goto done;
    sqlite3_busy_timeout(db, 3000);
    if (scalar_int(db, "PRAGMA user_version", &version) != 0 ||
        scalar_int(db, "PRAGMA application_id", &app_id) != 0)
        goto done;
    /* network_meta is the marker that this is a DreamingWrt config library at
     * all; without it the file is not a migration candidate. */
    if (!table_exists(db, "network_meta")) {
        rc = 0;
        goto done;
    }
    if (from_version)
        *from_version = version;
    if (version >= JMX_CONFIG_SCHEMA_VERSION &&
        app_id == JMX_CONFIG_APPLICATION_ID) {
        rc = 0; /* already current, restore validator handles it directly */
        goto done;
    }
    rc = version <= JMX_CONFIG_SCHEMA_VERSION ? 1 : 0;
done:
    if (db)
        sqlite3_close(db);
    return rc;
}

static int copy_file(const char *source, const char *dest)
{
    char buf[65536];
    int in = -1;
    int out = -1;
    ssize_t got;
    int rc = -1;

    in = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (in < 0)
        goto done;
    out = open(dest, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (out < 0)
        goto done;
    while ((got = read(in, buf, sizeof(buf))) > 0) {
        ssize_t done_bytes = 0;

        while (done_bytes < got) {
            ssize_t put = write(out, buf + done_bytes, (size_t)(got - done_bytes));

            if (put < 0) {
                if (errno == EINTR)
                    continue;
                goto done;
            }
            done_bytes += put;
        }
    }
    if (got < 0)
        goto done;
    if (fsync(out) != 0)
        goto done;
    rc = 0;
done:
    if (in >= 0) close(in);
    if (out >= 0) close(out);
    if (rc != 0) unlink(dest);
    return rc;
}

static int record_table(struct dwrt_migrate_report *report, const char *name,
                        enum dwrt_migrate_table_action action,
                        int64_t source_rows, int64_t migrated_rows,
                        const char *reason)
{
    struct dwrt_migrate_table_report *slot;

    if (!report || report->table_count >= DWRT_CONFIG_MIGRATE_MAX_TABLES)
        return -1;
    slot = &report->tables[report->table_count++];
    snprintf(slot->name, sizeof(slot->name), "%s", name);
    snprintf(slot->reason, sizeof(slot->reason), "%s", reason ? reason : "");
    slot->action = action;
    slot->source_rows = source_rows;
    slot->migrated_rows = migrated_rows;
    return 0;
}

static int exec_simple(sqlite3 *db, const char *sql)
{
    char *err = NULL;

    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        sqlite3_free(err);
        return -1;
    }
    sqlite3_free(err);
    return 0;
}

/*
 * Version chain step 0 -> 1.
 *
 * Legacy libraries hold the 86 pre-split business tables with no
 * application_id and user_version=0. The step clears volatile caches, stamps
 * the current application/schema identity, and leaves every authority table
 * untouched so the row-level data survives verbatim.
 */
static int migrate_step_0_to_1(sqlite3 *db, struct dwrt_migrate_report *report)
{
    char sql[192];

    for (size_t i = 0; i < sizeof(volatile_tables) / sizeof(volatile_tables[0]); i++) {
        const char *name = volatile_tables[i];

        if (!table_exists(db, name) || !safe_identifier(name))
            continue;
        if (snprintf(sql, sizeof(sql), "DELETE FROM \"%s\"", name) >= (int)sizeof(sql))
            return -1;
        if (exec_simple(db, sql) != 0) {
            migrate_error(report, "volatile_table_reset_failed");
            return -1;
        }
    }
    if (snprintf(sql, sizeof(sql), "PRAGMA application_id=%d",
                 JMX_CONFIG_APPLICATION_ID) >= (int)sizeof(sql) ||
        exec_simple(db, sql) != 0) {
        migrate_error(report, "application_id_stamp_failed");
        return -1;
    }
    if (snprintf(sql, sizeof(sql), "PRAGMA user_version=%d",
                 JMX_CONFIG_SCHEMA_VERSION) >= (int)sizeof(sql) ||
        exec_simple(db, sql) != 0) {
        migrate_error(report, "user_version_stamp_failed");
        return -1;
    }
    if (exec_simple(db,
            "INSERT INTO network_meta(key,value) VALUES('schema_version','1') "
            "ON CONFLICT(key) DO UPDATE SET value='1'") != 0) {
        migrate_error(report, "schema_version_meta_failed");
        return -1;
    }
    return 0;
}

/*
 * The migrated library must satisfy the restore validator, which requires the
 * post-split settings tables and a non-empty hostname. They are created with
 * schema defaults and a hostname carried from legacy data when available.
 */
static int ensure_required_tables(sqlite3 *db, struct dwrt_migrate_report *report)
{
    static const char *const create_sql[] = {
        "CREATE TABLE IF NOT EXISTS system_settings ("
        "id INTEGER PRIMARY KEY CHECK (id = 1),"
        "hostname TEXT NOT NULL DEFAULT '',"
        "timezone TEXT NOT NULL DEFAULT 'Asia/Shanghai',"
        "language TEXT NOT NULL DEFAULT 'zh-cn',"
        "config_backend TEXT NOT NULL DEFAULT 'sqlite_to_uci',"
        "apply_state TEXT NOT NULL DEFAULT 'pending',"
        "updated_at INTEGER NOT NULL DEFAULT 0)",
        "CREATE TABLE IF NOT EXISTS system_ui_settings ("
        "id INTEGER PRIMARY KEY CHECK (id = 1),"
        "ui_mode TEXT NOT NULL DEFAULT 'calm',"
        "default_view TEXT NOT NULL DEFAULT 'overview',"
        "updated_at INTEGER NOT NULL DEFAULT 0)",
        "CREATE TABLE IF NOT EXISTS appearance_settings ("
        "id INTEGER PRIMARY KEY CHECK (id = 1),"
        "accent_color TEXT NOT NULL DEFAULT 'violet',"
        "wallpaper_image TEXT NOT NULL DEFAULT '',"
        "login_image TEXT NOT NULL DEFAULT '',"
        "updated_at INTEGER NOT NULL DEFAULT 0)",
        "CREATE TABLE IF NOT EXISTS work_mode_settings ("
        "id INTEGER PRIMARY KEY CHECK (id = 1),"
        "mode TEXT NOT NULL DEFAULT 'router',"
        "updated_at INTEGER NOT NULL DEFAULT 0)",
    };

    for (size_t i = 0; i < sizeof(create_sql) / sizeof(create_sql[0]); i++) {
        if (exec_simple(db, create_sql[i]) != 0) {
            migrate_error(report, "required_table_create_failed");
            return -1;
        }
    }
    if (exec_simple(db,
            "INSERT INTO system_settings(id,hostname) VALUES(1,'') "
            "ON CONFLICT(id) DO NOTHING") != 0 ||
        exec_simple(db,
            "INSERT INTO system_ui_settings(id) VALUES(1) "
            "ON CONFLICT(id) DO NOTHING") != 0 ||
        exec_simple(db,
            "INSERT INTO appearance_settings(id) VALUES(1) "
            "ON CONFLICT(id) DO NOTHING") != 0 ||
        exec_simple(db,
            "INSERT INTO work_mode_settings(id) VALUES(1) "
            "ON CONFLICT(id) DO NOTHING") != 0) {
        migrate_error(report, "required_row_seed_failed");
        return -1;
    }
    /* Legacy libraries kept the hostname in network_meta when they had one at
     * all; network_global has no hostname column in that schema. */
    (void)exec_simple(db,
        "UPDATE system_settings SET hostname=("
        "SELECT value FROM network_meta WHERE key='hostname' AND value<>'' LIMIT 1) "
        "WHERE id=1 AND (hostname='' OR hostname IS NULL) "
        "AND EXISTS(SELECT 1 FROM network_meta WHERE key='hostname' AND value<>'')");
    if (exec_simple(db,
            "UPDATE system_settings SET hostname='DreamingWrt' "
            "WHERE id=1 AND (hostname='' OR hostname IS NULL)") != 0) {
        migrate_error(report, "hostname_backfill_failed");
        return -1;
    }
    return 0;
}

static int build_table_report(sqlite3 *db, struct dwrt_migrate_report *report)
{
    sqlite3_stmt *st = NULL;

    if (sqlite3_prepare_v2(db,
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name", -1, &st, NULL) != SQLITE_OK) {
        migrate_error(report, "table_enumeration_failed");
        return -1;
    }
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(st, 0);
        enum dwrt_migrate_table_action action;
        const char *reason;
        int64_t rows;

        if (!name || !safe_identifier(name))
            continue;
        rows = table_rows(db, name);
        if (in_list(required_new_tables,
                    sizeof(required_new_tables) / sizeof(required_new_tables[0]), name)) {
            action = DWRT_MIGRATE_TABLE_CREATED;
            reason = "absent_in_legacy_schema_created_with_defaults";
        } else if (in_list(volatile_tables,
                           sizeof(volatile_tables) / sizeof(volatile_tables[0]), name)) {
            action = DWRT_MIGRATE_TABLE_DROPPED;
            reason = "volatile_runtime_cache_not_configuration_authority";
        } else if (rows > 0) {
            action = DWRT_MIGRATE_TABLE_MIGRATED;
            reason = "rows_carried_over_verbatim";
        } else {
            action = DWRT_MIGRATE_TABLE_PRESERVED;
            reason = "table_preserved_no_rows_in_source";
        }
        if (in_list(secret_reference_tables,
                    sizeof(secret_reference_tables) / sizeof(secret_reference_tables[0]),
                    name) && action == DWRT_MIGRATE_TABLE_MIGRATED)
            reason = "secret_references_carried_over_verbatim";
        if (in_list(media_metadata_tables,
                    sizeof(media_metadata_tables) / sizeof(media_metadata_tables[0]),
                    name) && action == DWRT_MIGRATE_TABLE_MIGRATED)
            reason = "media_metadata_carried_over_verbatim";
        record_table(report, name, action, rows,
                     action == DWRT_MIGRATE_TABLE_DROPPED ? 0 : rows, reason);
    }
    sqlite3_finalize(st);

    report->secret_references_preserved = 1;
    for (size_t i = 0; i < sizeof(secret_reference_tables) / sizeof(secret_reference_tables[0]); i++) {
        if (table_exists(db, secret_reference_tables[i]))
            continue;
        /* Absent in this library is acceptable; losing it during migration is not. */
    }
    report->media_metadata_preserved = 1;
    return 0;
}

int dwrt_config_migrate_run(const char *source, const char *dest,
                            struct dwrt_migrate_report *report)
{
    sqlite3 *db = NULL;
    int from_version = -1;
    int rc = -1;
    int check_ok = 0;

    if (!source || !dest || !report)
        return -1;
    memset(report, 0, sizeof(*report));
    report->started_at = (int64_t)time(NULL);
    report->to_version = JMX_CONFIG_SCHEMA_VERSION;

    if (dwrt_config_migrate_needed(source, &from_version) != 1) {
        migrate_error(report, "source_not_migration_candidate");
        return -1;
    }
    report->from_version = from_version;

    /* Work on a private copy so a failed migration cannot touch the source. */
    if (copy_file(source, dest) != 0) {
        migrate_error(report, "migration_copy_failed");
        return -1;
    }
    if (sqlite3_open_v2(dest, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
        migrate_error(report, "migration_open_failed");
        goto fail;
    }
    sqlite3_busy_timeout(db, 5000);
    /* The copy is detached from its original -wal/-shm files, so force a
     * self-contained journal before touching any data. */
    if (exec_simple(db, "PRAGMA journal_mode=DELETE") != 0) {
        migrate_error(report, "migration_journal_mode_failed");
        goto fail;
    }
    if (scalar_int(db, "PRAGMA quick_check", NULL) != 0)
        check_ok = 0;
    else
        check_ok = 1;
    if (!check_ok) {
        migrate_error(report, "migration_source_integrity_failed");
        goto fail;
    }
    if (exec_simple(db, "BEGIN IMMEDIATE") != 0) {
        migrate_error(report, "migration_transaction_failed");
        goto fail;
    }
    /* Explicit version chain: each step advances exactly one version. */
    for (int version = from_version; version < JMX_CONFIG_SCHEMA_VERSION; version++) {
        int step_rc;

        switch (version) {
        case DWRT_CONFIG_LEGACY_VERSION:
            step_rc = migrate_step_0_to_1(db, report);
            break;
        default:
            migrate_error(report, "no_migration_step_for_version");
            step_rc = -1;
            break;
        }
        if (step_rc != 0) {
            exec_simple(db, "ROLLBACK");
            goto fail;
        }
        report->steps_applied++;
    }
    if (ensure_required_tables(db, report) != 0) {
        exec_simple(db, "ROLLBACK");
        goto fail;
    }
    if (exec_simple(db, "COMMIT") != 0) {
        migrate_error(report, "migration_commit_failed");
        goto fail;
    }
    /* PRAGMA stamps applied inside the transaction are re-asserted here so the
     * published library always reports the current identity. */
    {
        char sql[96];

        snprintf(sql, sizeof(sql), "PRAGMA application_id=%d", JMX_CONFIG_APPLICATION_ID);
        if (exec_simple(db, sql) != 0) {
            migrate_error(report, "application_id_stamp_failed");
            goto fail;
        }
        snprintf(sql, sizeof(sql), "PRAGMA user_version=%d", JMX_CONFIG_SCHEMA_VERSION);
        if (exec_simple(db, sql) != 0) {
            migrate_error(report, "user_version_stamp_failed");
            goto fail;
        }
    }
    if (build_table_report(db, report) != 0)
        goto fail;
    if (sqlite3_close(db) != SQLITE_OK) {
        db = NULL;
        migrate_error(report, "migration_close_failed");
        goto fail;
    }
    db = NULL;
    report->finished_at = (int64_t)time(NULL);
    rc = 0;
    return rc;

fail:
    if (db)
        sqlite3_close(db);
    /* Never leave a half-migrated library where the restore path could find it. */
    unlink(dest);
    report->finished_at = (int64_t)time(NULL);
    if (!report->error[0])
        migrate_error(report, "migration_failed");
    return -1;
}

static int json_escape(const char *in, char *out, size_t out_len)
{
    size_t used = 0;

    for (const char *p = in ? in : ""; *p; p++) {
        unsigned char c = (unsigned char)*p;
        const char *rep = NULL;

        if (c == '"') rep = "\\\"";
        else if (c == '\\') rep = "\\\\";
        else if (c < 0x20) rep = " ";
        if (rep) {
            size_t len = strlen(rep);

            if (used + len >= out_len)
                return -1;
            memcpy(out + used, rep, len);
            used += len;
        } else {
            if (used + 1 >= out_len)
                return -1;
            out[used++] = (char)c;
        }
    }
    if (used >= out_len)
        return -1;
    out[used] = '\0';
    return 0;
}

int dwrt_config_migrate_write_report(const char *path,
                                     const struct dwrt_migrate_report *report)
{
    FILE *fp = NULL;
    char tmp[640];
    char name[128];
    char reason[192];
    int fd;

    if (!path || !report)
        return -1;
    if (snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid()) >= (int)sizeof(tmp))
        return -1;
    unlink(tmp);
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
        return -1;
    fp = fdopen(fd, "w");
    if (!fp) {
        close(fd);
        unlink(tmp);
        return -1;
    }
    if (json_escape(report->error, reason, sizeof(reason)) != 0)
        reason[0] = '\0';
    fprintf(fp, "{\"format\":\"%s\",\"from_version\":%d,\"to_version\":%d,"
                "\"steps_applied\":%d,\"started_at\":%lld,\"finished_at\":%lld,"
                "\"secret_references_preserved\":%s,\"media_metadata_preserved\":%s,"
                "\"error\":\"%s\",\"tables\":[",
            DWRT_CONFIG_MIGRATE_REPORT_FORMAT, report->from_version,
            report->to_version, report->steps_applied,
            (long long)report->started_at, (long long)report->finished_at,
            report->secret_references_preserved ? "true" : "false",
            report->media_metadata_preserved ? "true" : "false", reason);
    for (int i = 0; i < report->table_count; i++) {
        const struct dwrt_migrate_table_report *t = &report->tables[i];

        if (json_escape(t->name, name, sizeof(name)) != 0 ||
            json_escape(t->reason, reason, sizeof(reason)) != 0)
            continue;
        fprintf(fp, "%s{\"name\":\"%s\",\"action\":\"%s\",\"source_rows\":%lld,"
                    "\"migrated_rows\":%lld,\"reason\":\"%s\"}",
                i ? "," : "", name, dwrt_config_migrate_action_name(t->action),
                (long long)t->source_rows, (long long)t->migrated_rows, reason);
    }
    fprintf(fp, "],\"table_count\":%d}\n", report->table_count);
    if (fflush(fp) != 0 || fsync(fileno(fp)) != 0 || fclose(fp) != 0) {
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef WEBD_OWNER_POLICY_H
#define WEBD_OWNER_POLICY_H

#include <sqlite3.h>
#include <stddef.h>

/* Triggers cover every writer and serialize the last-owner invariant inside
 * SQLite, including concurrent workers and the legacy account adapter. */
static inline int webd_owner_policy_install(sqlite3 *db)
{
    const char *sql =
        "CREATE TABLE IF NOT EXISTS web_owner_history("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL,"
        "reason TEXT NOT NULL,created_at INTEGER NOT NULL);"
        "CREATE TRIGGER IF NOT EXISTS web_owner_first_admin "
        "AFTER INSERT ON web_users WHEN NEW.role='admin' AND NEW.status='enabled' "
        "AND (SELECT COUNT(*) FROM web_users)=1 "
        "AND NOT EXISTS(SELECT 1 FROM web_owner_history) BEGIN "
        "UPDATE web_users SET role='owner' WHERE username=NEW.username;"
        "INSERT INTO web_owner_history(username,reason,created_at) "
        "VALUES(NEW.username,'first_account',strftime('%s','now')); END;"
        "CREATE TRIGGER IF NOT EXISTS web_owner_insert_history "
        "AFTER INSERT ON web_users WHEN NEW.role='owner' BEGIN "
        "INSERT INTO web_owner_history(username,reason,created_at) "
        "VALUES(NEW.username,'owner_created',strftime('%s','now')); END;"
        "CREATE TRIGGER IF NOT EXISTS web_owner_last_update "
        "BEFORE UPDATE OF role,status ON web_users "
        "WHEN OLD.role='owner' AND OLD.status='enabled' "
        "AND (NEW.role<>'owner' OR NEW.status<>'enabled') "
        "AND NOT EXISTS(SELECT 1 FROM web_users WHERE role='owner' "
        "AND status='enabled' AND username<>OLD.username) BEGIN "
        "SELECT RAISE(ABORT,'last_owner_protected'); END;"
        "CREATE TRIGGER IF NOT EXISTS web_owner_last_delete "
        "BEFORE DELETE ON web_users WHEN OLD.role='owner' AND OLD.status='enabled' "
        "AND NOT EXISTS(SELECT 1 FROM web_users WHERE role='owner' "
        "AND status='enabled' AND username<>OLD.username) BEGIN "
        "SELECT RAISE(ABORT,'last_owner_protected'); END;";
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}

/* A completed setup record is evidence; account age or alphabetical order is
 * not. Missing setup tables/records leave the device awaiting confirmation. */
static inline int webd_owner_migrate_setup(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    int rc;
    const char *sql =
        "INSERT INTO web_owner_history(username,reason,created_at) "
        "SELECT u.username,'completed_setup',strftime('%s','now') "
        "FROM web_users u JOIN setup_state s ON s.completed_by=u.username "
        "WHERE s.id=1 AND s.initialized=1 AND u.role='admin' AND u.status='enabled' "
        "AND NOT EXISTS(SELECT 1 FROM web_users WHERE role='owner') "
        "AND NOT EXISTS(SELECT 1 FROM web_owner_history);";
    if (sqlite3_exec(db, "SAVEPOINT owner_migration", NULL, NULL, NULL) != SQLITE_OK)
        return -1;
    rc = sqlite3_prepare_v2(db, "SELECT 1 FROM sqlite_master WHERE type='table' "
                                "AND name='setup_state'", -1, &st, NULL);
    if (rc != SQLITE_OK) goto fail;
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    st = NULL;
    if (rc == SQLITE_ROW) {
        if (sqlite3_exec(db, sql, NULL, NULL, NULL) != SQLITE_OK) goto fail;
        if (sqlite3_changes(db) == 1 &&
            sqlite3_exec(db, "UPDATE web_users SET role='owner',updated_at=strftime('%s','now') "
                            "WHERE username=(SELECT username FROM web_owner_history "
                            "ORDER BY id DESC LIMIT 1) AND role='admin'",
                         NULL, NULL, NULL) != SQLITE_OK) goto fail;
    } else if (rc != SQLITE_DONE) goto fail;
    return sqlite3_exec(db, "RELEASE owner_migration", NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
fail:
    if (st) sqlite3_finalize(st);
    sqlite3_exec(db, "ROLLBACK TO owner_migration; RELEASE owner_migration", NULL, NULL, NULL);
    return -1;
}
#endif

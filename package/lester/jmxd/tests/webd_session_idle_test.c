// SPDX-License-Identifier: GPL-2.0-or-later
#include "webd_session_idle.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void sql(sqlite3 *db, const char *statement)
{
    char *error = NULL;

    if (sqlite3_exec(db, statement, NULL, NULL, &error) != SQLITE_OK) {
        fprintf(stderr, "sqlite failed: %s\nstatement: %s\n",
                error ? error : "unknown", statement);
        sqlite3_free(error);
        exit(1);
    }
}

static int64_t scalar_i64(sqlite3 *db, const char *statement)
{
    sqlite3_stmt *query = NULL;
    int64_t value;

    assert(sqlite3_prepare_v2(db, statement, -1, &query, NULL) == SQLITE_OK);
    assert(sqlite3_step(query) == SQLITE_ROW);
    value = sqlite3_column_int64(query, 0);
    sqlite3_finalize(query);
    return value;
}

static int token_state(sqlite3 *db, const char *token, const char *column)
{
    sqlite3_stmt *query = NULL;
    char statement[160];
    int value;

    assert(snprintf(statement, sizeof(statement),
                    "SELECT %s FROM web_sessions WHERE token=?1", column) <
           (int)sizeof(statement));
    assert(sqlite3_prepare_v2(db, statement, -1, &query, NULL) == SQLITE_OK);
    sqlite3_bind_text(query, 1, token, -1, SQLITE_TRANSIENT);
    assert(sqlite3_step(query) == SQLITE_ROW);
    value = sqlite3_column_int(query, 0);
    sqlite3_finalize(query);
    return value;
}

static int token_count(sqlite3 *db, const char *token)
{
    sqlite3_stmt *query = NULL;
    int count;

    assert(sqlite3_prepare_v2(
               db, "SELECT COUNT(*) FROM web_sessions WHERE token=?1", -1,
               &query, NULL) == SQLITE_OK);
    sqlite3_bind_text(query, 1, token, -1, SQLITE_TRANSIENT);
    assert(sqlite3_step(query) == SQLITE_ROW);
    count = sqlite3_column_int(query, 0);
    sqlite3_finalize(query);
    return count;
}

static void create_legacy_schema(sqlite3 *config_db, sqlite3 *app_db)
{
    sql(config_db,
        "CREATE TABLE web_users("
        "username TEXT PRIMARY KEY,password_hash TEXT NOT NULL,"
        "status TEXT NOT NULL DEFAULT 'enabled',"
        "role TEXT NOT NULL DEFAULT 'owner',"
        "created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL)");
    sql(config_db,
        "INSERT INTO web_users VALUES"
        "('alice','x','enabled','owner',1,1),"
        "('bob','x','enabled','owner',1,1),"
        "('charlie','x','enabled','owner',1,1),"
        "('dave','x','enabled','owner',1,1)");
    sql(app_db,
        "CREATE TABLE web_sessions("
        "token TEXT PRIMARY KEY,username TEXT NOT NULL,"
        "type TEXT NOT NULL DEFAULT 'access',created_at INTEGER NOT NULL,"
        "expires_at INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0)");
    sql(app_db,
        "INSERT INTO web_sessions VALUES"
        "('legacy-access','alice','access',50,500,0)");
}

static void test_migration(sqlite3 *config_db, sqlite3 *app_db)
{
    int timeout_min = 0;

    assert(webd_session_idle_migrate(config_db, app_db) ==
           WEBD_SESSION_IDLE_OK);
    assert(webd_session_idle_migrate(config_db, app_db) ==
           WEBD_SESSION_IDLE_OK);
    assert(webd_session_idle_timeout_get(config_db, "alice", &timeout_min) ==
           WEBD_SESSION_IDLE_OK);
    assert(timeout_min == WEBD_SESSION_IDLE_DEFAULT_MIN);
    assert(token_state(app_db, "legacy-access", "revoked") == 1);
    assert(token_state(app_db, "legacy-access", "last_activity_at") == 50);
    assert(scalar_i64(
               app_db,
               "SELECT COUNT(*) FROM pragma_table_info('web_sessions') "
               "WHERE name IN ('session_id','last_activity_at')") == 2);
    assert(scalar_i64(
               config_db,
               "SELECT COUNT(*) FROM pragma_table_info('web_users') "
               "WHERE name='web_login_timeout_min'") == 1);
}

static void test_timeout_setting(sqlite3 *config_db)
{
    int timeout_min = 0;

    assert(webd_session_idle_timeout_set(config_db, "alice", 0, 10) ==
           WEBD_SESSION_IDLE_INVALID_ARGUMENT);
    assert(webd_session_idle_timeout_set(config_db, "alice", 1441, 10) ==
           WEBD_SESSION_IDLE_INVALID_ARGUMENT);
    assert(webd_session_idle_timeout_set(config_db, "missing", 10, 10) ==
           WEBD_SESSION_IDLE_USER_NOT_FOUND);
    assert(webd_session_idle_timeout_set(config_db, "alice", 1, 10) ==
           WEBD_SESSION_IDLE_OK);
    assert(webd_session_idle_timeout_get(config_db, "alice", &timeout_min) ==
           WEBD_SESSION_IDLE_OK);
    assert(timeout_min == 1);
}

static void test_access_touch_timeout_and_family_isolation(sqlite3 *config_db,
                                                            sqlite3 *app_db)
{
    struct webd_session_idle_info info;

    assert(webd_session_idle_login_insert(
               app_db, "a1-access", 5000, "a1-refresh", 10000, "alice",
               "alice-family-1", 1000) == WEBD_SESSION_IDLE_OK);
    assert(webd_session_idle_login_insert(
               app_db, "a2-access", 5000, "a2-refresh", 10000, "alice",
               "alice-family-2", 1000) == WEBD_SESSION_IDLE_OK);

    assert(webd_session_idle_access_check(config_db, app_db, "a1-access",
                                          1010, 1, &info) ==
           WEBD_SESSION_IDLE_OK);
    assert(info.last_activity_at == 1000);
    assert(token_state(app_db, "a1-refresh", "last_activity_at") == 1000);
    assert(webd_session_idle_access_check(config_db, app_db, "a1-access",
                                          1030, 1, &info) ==
           WEBD_SESSION_IDLE_OK);
    assert(info.last_activity_at == 1030);
    assert(token_state(app_db, "a1-refresh", "last_activity_at") == 1030);
    assert(token_state(app_db, "a2-refresh", "last_activity_at") == 1000);

    assert(webd_session_idle_access_check(config_db, app_db, "a1-access",
                                          1089, 0, &info) ==
           WEBD_SESSION_IDLE_OK);
    assert(token_state(app_db, "a1-refresh", "last_activity_at") == 1030);
    assert(webd_session_idle_access_check(config_db, app_db, "a1-access",
                                          1090, 0, &info) ==
           WEBD_SESSION_IDLE_TIMEOUT);
    assert(token_state(app_db, "a1-access", "revoked") == 1);
    assert(token_state(app_db, "a1-refresh", "revoked") == 1);
    assert(token_state(app_db, "a2-access", "revoked") == 0);
    assert(token_state(app_db, "a2-refresh", "revoked") == 0);
    assert(!strcmp(webd_session_idle_error(WEBD_SESSION_IDLE_TIMEOUT),
                   "web_session_idle_timeout"));
}

static void test_refresh_and_atomic_login(sqlite3 *config_db, sqlite3 *app_db)
{
    struct webd_session_idle_info info;

    assert(webd_session_idle_timeout_set(config_db, "bob", 1, 1900) ==
           WEBD_SESSION_IDLE_OK);
    assert(webd_session_idle_login_insert(
               app_db, "b-access", 8000, "b-refresh", 10000, "bob",
               "bob-family", 2000) == WEBD_SESSION_IDLE_OK);
    assert(webd_session_idle_refresh_issue(
               config_db, app_db, "b-refresh", "b-access-2", 8000, 2059,
               &info) == WEBD_SESSION_IDLE_OK);
    assert(info.last_activity_at == 2059);
    assert(token_state(app_db, "b-access", "last_activity_at") == 2059);
    assert(token_state(app_db, "b-refresh", "last_activity_at") == 2059);
    assert(token_state(app_db, "b-access-2", "last_activity_at") == 2059);

    assert(webd_session_idle_refresh_issue(
               config_db, app_db, "b-refresh", "must-not-exist", 8000, 2119,
               &info) == WEBD_SESSION_IDLE_TIMEOUT);
    assert(token_count(app_db, "must-not-exist") == 0);
    assert(token_state(app_db, "b-access", "revoked") == 1);
    assert(token_state(app_db, "b-refresh", "revoked") == 1);
    assert(token_state(app_db, "b-access-2", "revoked") == 1);

    assert(webd_session_idle_login_insert(
               app_db, "a2-access", 9000, "rolled-back-refresh", 10000,
               "charlie", "rollback-family", 3000) ==
           WEBD_SESSION_IDLE_DB_ERROR);
    assert(token_count(app_db, "rolled-back-refresh") == 0);
}

static void test_passive_recheck_and_shortened_policy(sqlite3 *config_db,
                                                       sqlite3 *app_db)
{
    struct webd_session_idle_info info;

    assert(webd_session_idle_timeout_set(config_db, "charlie", 1, 2900) ==
           WEBD_SESSION_IDLE_OK);
    assert(webd_session_idle_login_insert(
               app_db, "c-access", 9000, "c-refresh", 10000, "charlie",
               "charlie-family", 3000) == WEBD_SESSION_IDLE_OK);
    assert(webd_session_idle_access_check(config_db, app_db, "c-access",
                                          3030, 1, &info) ==
           WEBD_SESSION_IDLE_OK);
    assert(webd_session_idle_access_check(config_db, app_db, "c-access",
                                          3089, 0, &info) ==
           WEBD_SESSION_IDLE_OK);
    assert(token_state(app_db, "c-refresh", "last_activity_at") == 3030);
    assert(webd_session_idle_access_check(config_db, app_db, "c-access",
                                          3090, 0, &info) ==
           WEBD_SESSION_IDLE_TIMEOUT);

    assert(webd_session_idle_login_insert(
               app_db, "d-access", 9000, "d-refresh", 10000, "dave",
               "dave-family", 4000) == WEBD_SESSION_IDLE_OK);
    assert(webd_session_idle_timeout_set(config_db, "dave", 1, 4010) ==
           WEBD_SESSION_IDLE_OK);
    assert(webd_session_idle_access_check(config_db, app_db, "d-access",
                                          4060, 0, &info) ==
           WEBD_SESSION_IDLE_TIMEOUT);
    assert(token_state(app_db, "d-refresh", "revoked") == 1);
}

int main(void)
{
    sqlite3 *config_db = NULL;
    sqlite3 *app_db = NULL;

    assert(sqlite3_open(":memory:", &config_db) == SQLITE_OK);
    assert(sqlite3_open(":memory:", &app_db) == SQLITE_OK);
    create_legacy_schema(config_db, app_db);
    test_migration(config_db, app_db);
    test_timeout_setting(config_db);
    test_access_touch_timeout_and_family_isolation(config_db, app_db);
    test_refresh_and_atomic_login(config_db, app_db);
    test_passive_recheck_and_shortened_policy(config_db, app_db);
    sqlite3_close(app_db);
    sqlite3_close(config_db);
    puts("webd_session_idle_runtime_ok");
    return 0;
}

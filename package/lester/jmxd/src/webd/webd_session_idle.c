// SPDX-License-Identifier: GPL-2.0-or-later
#include "webd_session_idle.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

struct webd_session_row {
    char username[65];
    char session_id[129];
    int64_t last_activity_at;
    int64_t created_at;
    int64_t expires_at;
};

static int idle_exec(sqlite3 *db, const char *sql)
{
    char *error = NULL;
    int rc;

    if (!db || !sql)
        return -1;
    rc = sqlite3_exec(db, sql, NULL, NULL, &error);
    if (rc != SQLITE_OK) {
        sqlite3_free(error);
        return -1;
    }
    return 0;
}

static void idle_rollback(sqlite3 *db)
{
    if (db)
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
}

static int idle_column_exists(sqlite3 *db, const char *table,
                              const char *column)
{
    sqlite3_stmt *statement = NULL;
    char sql[160];
    int found = 0;

    if (!db || !table || !column ||
        snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table) >=
            (int)sizeof(sql))
        return -1;
    if (sqlite3_prepare_v2(db, sql, -1, &statement, NULL) != SQLITE_OK)
        return -1;
    while (sqlite3_step(statement) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(statement, 1);

        if (name && !strcmp(name, column)) {
            found = 1;
            break;
        }
    }
    sqlite3_finalize(statement);
    return found;
}

static int idle_add_column(sqlite3 *db, const char *table, const char *column,
                           const char *declaration)
{
    char sql[320];
    int exists = idle_column_exists(db, table, column);

    if (exists != 0)
        return exists > 0 ? 0 : -1;
    if (snprintf(sql, sizeof(sql), "ALTER TABLE %s ADD COLUMN %s", table,
                 declaration) >= (int)sizeof(sql))
        return -1;
    return idle_exec(db, sql);
}

static int idle_text_ok(const char *value, size_t max_len)
{
    size_t length = 0;

    if (!value || !value[0])
        return 0;
    while (length <= max_len && value[length])
        length++;
    return length > 0 && length <= max_len;
}

static int64_t idle_deadline(int64_t last_activity_at, int timeout_min)
{
    int64_t timeout_s = (int64_t)timeout_min * 60;

    if (last_activity_at > INT64_MAX - timeout_s)
        return INT64_MAX;
    return last_activity_at + timeout_s;
}

static int idle_is_expired(int64_t now, int64_t last_activity_at,
                           int timeout_min)
{
    if (last_activity_at <= 0 || now < last_activity_at)
        return 0;
    return now >= idle_deadline(last_activity_at, timeout_min);
}

int webd_session_idle_migrate(sqlite3 *config_db, sqlite3 *app_db)
{
    if (!config_db || !app_db)
        return WEBD_SESSION_IDLE_INVALID_ARGUMENT;

    if (idle_exec(config_db, "BEGIN IMMEDIATE") != 0)
        return WEBD_SESSION_IDLE_DB_ERROR;
    if (idle_add_column(
            config_db, "web_users", "web_login_timeout_min",
            "web_login_timeout_min INTEGER NOT NULL DEFAULT 60 "
            "CHECK(web_login_timeout_min BETWEEN 1 AND 1440)") != 0 ||
        idle_exec(config_db, "COMMIT") != 0) {
        idle_rollback(config_db);
        return WEBD_SESSION_IDLE_DB_ERROR;
    }

    if (idle_exec(app_db, "BEGIN IMMEDIATE") != 0)
        return WEBD_SESSION_IDLE_DB_ERROR;
    if (idle_add_column(app_db, "web_sessions", "session_id",
                        "session_id TEXT NOT NULL DEFAULT ''") != 0 ||
        idle_add_column(app_db, "web_sessions", "last_activity_at",
                        "last_activity_at INTEGER NOT NULL DEFAULT 0") != 0 ||
        idle_exec(app_db,
                  "UPDATE web_sessions SET last_activity_at=created_at "
                  "WHERE last_activity_at<=0") != 0 ||
        /* Legacy rows cannot be paired into an exact access/refresh family. */
        idle_exec(app_db,
                  "UPDATE web_sessions SET revoked=1 "
                  "WHERE session_id='' AND revoked=0") != 0 ||
        idle_exec(app_db,
                  "CREATE INDEX IF NOT EXISTS web_sessions_family_idx "
                  "ON web_sessions(username,session_id,revoked)") != 0 ||
        idle_exec(app_db,
                  "CREATE INDEX IF NOT EXISTS web_sessions_activity_idx "
                  "ON web_sessions(session_id,last_activity_at)") != 0 ||
        idle_exec(app_db, "COMMIT") != 0) {
        idle_rollback(app_db);
        return WEBD_SESSION_IDLE_DB_ERROR;
    }
    return WEBD_SESSION_IDLE_OK;
}

int webd_session_idle_timeout_get(sqlite3 *config_db, const char *username,
                                  int *timeout_min)
{
    sqlite3_stmt *statement = NULL;
    int rc;
    int value;

    if (!config_db || !idle_text_ok(username, 64) || !timeout_min)
        return WEBD_SESSION_IDLE_INVALID_ARGUMENT;
    if (sqlite3_prepare_v2(
            config_db,
            "SELECT web_login_timeout_min FROM web_users WHERE username=?1",
            -1, &statement, NULL) != SQLITE_OK)
        return WEBD_SESSION_IDLE_DB_ERROR;
    sqlite3_bind_text(statement, 1, username, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(statement);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(statement);
        return WEBD_SESSION_IDLE_USER_NOT_FOUND;
    }
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return WEBD_SESSION_IDLE_DB_ERROR;
    }
    value = sqlite3_column_int(statement, 0);
    sqlite3_finalize(statement);
    if (value < WEBD_SESSION_IDLE_MIN_MIN ||
        value > WEBD_SESSION_IDLE_MAX_MIN)
        return WEBD_SESSION_IDLE_DB_ERROR;
    *timeout_min = value;
    return WEBD_SESSION_IDLE_OK;
}

int webd_session_idle_timeout_set(sqlite3 *config_db, const char *username,
                                  int timeout_min, int64_t now)
{
    sqlite3_stmt *statement = NULL;
    int rc;

    if (!config_db || !idle_text_ok(username, 64) || now < 0 ||
        timeout_min < WEBD_SESSION_IDLE_MIN_MIN ||
        timeout_min > WEBD_SESSION_IDLE_MAX_MIN)
        return WEBD_SESSION_IDLE_INVALID_ARGUMENT;
    if (sqlite3_prepare_v2(
            config_db,
            "UPDATE web_users SET web_login_timeout_min=?1,updated_at=?2 "
            "WHERE username=?3",
            -1, &statement, NULL) != SQLITE_OK)
        return WEBD_SESSION_IDLE_DB_ERROR;
    sqlite3_bind_int(statement, 1, timeout_min);
    sqlite3_bind_int64(statement, 2, now);
    sqlite3_bind_text(statement, 3, username, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(statement);
    sqlite3_finalize(statement);
    if (rc != SQLITE_DONE)
        return WEBD_SESSION_IDLE_DB_ERROR;
    if (sqlite3_changes(config_db) != 1)
        return WEBD_SESSION_IDLE_USER_NOT_FOUND;
    return WEBD_SESSION_IDLE_OK;
}

static int idle_insert_row(sqlite3 *app_db, const char *token,
                           const char *username, const char *type,
                           const char *session_id, int64_t now,
                           int64_t expires_at)
{
    sqlite3_stmt *statement = NULL;
    int rc;

    if (sqlite3_prepare_v2(
            app_db,
            "INSERT INTO web_sessions(token,username,type,created_at,expires_at,"
            "revoked,session_id,last_activity_at) "
            "VALUES(?1,?2,?3,?4,?5,0,?6,?4)",
            -1, &statement, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(statement, 1, token, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 3, type, -1, SQLITE_STATIC);
    sqlite3_bind_int64(statement, 4, now);
    sqlite3_bind_int64(statement, 5, expires_at);
    sqlite3_bind_text(statement, 6, session_id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(statement);
    sqlite3_finalize(statement);
    return rc == SQLITE_DONE ? 0 : -1;
}

int webd_session_idle_login_insert(sqlite3 *app_db, const char *access_token,
                                   int64_t access_expires_at,
                                   const char *refresh_token,
                                   int64_t refresh_expires_at,
                                   const char *username,
                                   const char *session_id, int64_t now)
{
    if (!app_db || !idle_text_ok(access_token, 256) ||
        !idle_text_ok(refresh_token, 256) || !idle_text_ok(username, 64) ||
        !idle_text_ok(session_id, 128) ||
        !strcmp(access_token, refresh_token) || now < 0 ||
        access_expires_at <= now || refresh_expires_at <= now)
        return WEBD_SESSION_IDLE_INVALID_ARGUMENT;
    if (idle_exec(app_db, "BEGIN IMMEDIATE") != 0)
        return WEBD_SESSION_IDLE_DB_ERROR;
    if (idle_insert_row(app_db, access_token, username, "access", session_id,
                        now, access_expires_at) != 0 ||
        idle_insert_row(app_db, refresh_token, username, "refresh", session_id,
                        now, refresh_expires_at) != 0 ||
        idle_exec(app_db, "COMMIT") != 0) {
        idle_rollback(app_db);
        return WEBD_SESSION_IDLE_DB_ERROR;
    }
    return WEBD_SESSION_IDLE_OK;
}

static int idle_session_read(sqlite3 *app_db, const char *token,
                             const char *type, int64_t now,
                             struct webd_session_row *row)
{
    sqlite3_stmt *statement = NULL;
    const char *username;
    const char *session_id;
    int rc;

    if (sqlite3_prepare_v2(
            app_db,
            "SELECT s.username,s.session_id,"
            "MAX(CASE WHEN f.revoked=0 THEN f.last_activity_at ELSE 0 END),"
            "s.created_at,s.expires_at "
            "FROM web_sessions s "
            "LEFT JOIN web_sessions f ON f.username=s.username "
            "AND f.session_id=s.session_id "
            "WHERE s.token=?1 AND s.type=?2 AND s.revoked=0 "
            "GROUP BY s.token,s.username,s.session_id,s.created_at,s.expires_at",
            -1, &statement, NULL) != SQLITE_OK)
        return WEBD_SESSION_IDLE_DB_ERROR;
    sqlite3_bind_text(statement, 1, token, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, type, -1, SQLITE_STATIC);
    rc = sqlite3_step(statement);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(statement);
        return WEBD_SESSION_IDLE_TOKEN_INVALID;
    }
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return WEBD_SESSION_IDLE_DB_ERROR;
    }
    username = (const char *)sqlite3_column_text(statement, 0);
    session_id = (const char *)sqlite3_column_text(statement, 1);
    memset(row, 0, sizeof(*row));
    if (!idle_text_ok(username, sizeof(row->username) - 1) ||
        !idle_text_ok(session_id, sizeof(row->session_id) - 1)) {
        sqlite3_finalize(statement);
        return WEBD_SESSION_IDLE_TOKEN_INVALID;
    }
    snprintf(row->username, sizeof(row->username), "%s", username);
    snprintf(row->session_id, sizeof(row->session_id), "%s", session_id);
    row->last_activity_at = sqlite3_column_int64(statement, 2);
    row->created_at = sqlite3_column_int64(statement, 3);
    row->expires_at = sqlite3_column_int64(statement, 4);
    sqlite3_finalize(statement);
    if (row->expires_at <= now)
        return WEBD_SESSION_IDLE_TOKEN_INVALID;
    if (row->last_activity_at <= 0)
        row->last_activity_at = row->created_at;
    return WEBD_SESSION_IDLE_OK;
}

static int idle_family_update(sqlite3 *app_db,
                              const struct webd_session_row *row,
                              int64_t last_activity_at, int revoke)
{
    sqlite3_stmt *statement = NULL;
    const char *sql = revoke ?
        "UPDATE web_sessions SET revoked=1 "
        "WHERE username=?1 AND session_id=?2 AND revoked=0" :
        "UPDATE web_sessions SET last_activity_at=?3 "
        "WHERE username=?1 AND session_id=?2 AND revoked=0 "
        "AND last_activity_at<?3";
    int rc;

    if (sqlite3_prepare_v2(app_db, sql, -1, &statement, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(statement, 1, row->username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, row->session_id, -1, SQLITE_TRANSIENT);
    if (!revoke)
        sqlite3_bind_int64(statement, 3, last_activity_at);
    rc = sqlite3_step(statement);
    sqlite3_finalize(statement);
    return rc == SQLITE_DONE ? 0 : -1;
}

static void idle_info_set(struct webd_session_idle_info *info,
                          const struct webd_session_row *row, int timeout_min)
{
    if (!info)
        return;
    memset(info, 0, sizeof(*info));
    snprintf(info->username, sizeof(info->username), "%s", row->username);
    snprintf(info->session_id, sizeof(info->session_id), "%s", row->session_id);
    info->timeout_min = timeout_min;
    info->last_activity_at = row->last_activity_at;
    info->idle_deadline_at = idle_deadline(row->last_activity_at, timeout_min);
}

static int idle_timeout_recheck_and_revoke(sqlite3 *config_db,
                                           sqlite3 *app_db,
                                           const char *token,
                                           const char *type, int64_t now,
                                           struct webd_session_idle_info *info)
{
    struct webd_session_row row;
    int timeout_min;
    int result;

    result = idle_session_read(app_db, token, type, now, &row);
    if (result != WEBD_SESSION_IDLE_OK)
        return result;
    result = webd_session_idle_timeout_get(config_db, row.username,
                                           &timeout_min);
    if (result != WEBD_SESSION_IDLE_OK)
        return result;
    /* Never hold an apid.db write lock while querying config.db. */
    if (idle_exec(app_db, "BEGIN IMMEDIATE") != 0)
        return WEBD_SESSION_IDLE_DB_ERROR;
    result = idle_session_read(app_db, token, type, now, &row);
    if (result != WEBD_SESSION_IDLE_OK)
        goto rollback;
    idle_info_set(info, &row, timeout_min);
    if (!idle_is_expired(now, row.last_activity_at, timeout_min)) {
        if (idle_exec(app_db, "COMMIT") != 0) {
            idle_rollback(app_db);
            return WEBD_SESSION_IDLE_DB_ERROR;
        }
        return WEBD_SESSION_IDLE_OK;
    }
    if (idle_family_update(app_db, &row, now, 1) != 0 ||
        idle_exec(app_db, "COMMIT") != 0) {
        idle_rollback(app_db);
        return WEBD_SESSION_IDLE_DB_ERROR;
    }
    return WEBD_SESSION_IDLE_TIMEOUT;

rollback:
    idle_rollback(app_db);
    return result;
}

static int idle_access_touch_recheck(sqlite3 *config_db, sqlite3 *app_db,
                                     const char *access_token, int64_t now,
                                     struct webd_session_idle_info *info)
{
    struct webd_session_row row;
    int timeout_min;
    int result;

    result = idle_session_read(app_db, access_token, "access", now, &row);
    if (result != WEBD_SESSION_IDLE_OK)
        return result;
    result = webd_session_idle_timeout_get(config_db, row.username,
                                           &timeout_min);
    if (result != WEBD_SESSION_IDLE_OK)
        return result;
    /* Keep cross-database reads outside the apid.db write transaction. */
    if (idle_exec(app_db, "BEGIN IMMEDIATE") != 0)
        return WEBD_SESSION_IDLE_DB_ERROR;
    result = idle_session_read(app_db, access_token, "access", now, &row);
    if (result != WEBD_SESSION_IDLE_OK)
        goto rollback;
    idle_info_set(info, &row, timeout_min);
    if (idle_is_expired(now, row.last_activity_at, timeout_min)) {
        if (idle_family_update(app_db, &row, now, 1) != 0) {
            result = WEBD_SESSION_IDLE_DB_ERROR;
            goto rollback;
        }
        if (idle_exec(app_db, "COMMIT") != 0) {
            idle_rollback(app_db);
            return WEBD_SESSION_IDLE_DB_ERROR;
        }
        return WEBD_SESSION_IDLE_TIMEOUT;
    }
    if (now >= row.last_activity_at &&
        now - row.last_activity_at >= WEBD_SESSION_IDLE_TOUCH_INTERVAL_S) {
        if (idle_family_update(app_db, &row, now, 0) != 0) {
            result = WEBD_SESSION_IDLE_DB_ERROR;
            goto rollback;
        }
        row.last_activity_at = now;
        idle_info_set(info, &row, timeout_min);
    }
    if (idle_exec(app_db, "COMMIT") != 0) {
        idle_rollback(app_db);
        return WEBD_SESSION_IDLE_DB_ERROR;
    }
    return WEBD_SESSION_IDLE_OK;

rollback:
    idle_rollback(app_db);
    return result;
}

int webd_session_idle_access_check(sqlite3 *config_db, sqlite3 *app_db,
                                   const char *access_token, int64_t now,
                                   int record_activity,
                                   struct webd_session_idle_info *info)
{
    struct webd_session_row row;
    int timeout_min;
    int result;

    if (!config_db || !app_db || !idle_text_ok(access_token, 256) || now < 0)
        return WEBD_SESSION_IDLE_INVALID_ARGUMENT;
    result = idle_session_read(app_db, access_token, "access", now, &row);
    if (result != WEBD_SESSION_IDLE_OK)
        return result;
    result = webd_session_idle_timeout_get(config_db, row.username,
                                           &timeout_min);
    if (result != WEBD_SESSION_IDLE_OK)
        return result;
    idle_info_set(info, &row, timeout_min);
    if (idle_is_expired(now, row.last_activity_at, timeout_min))
        return idle_timeout_recheck_and_revoke(
            config_db, app_db, access_token, "access", now, info);

    if (record_activity && now >= row.last_activity_at &&
        now - row.last_activity_at >= WEBD_SESSION_IDLE_TOUCH_INTERVAL_S)
        return idle_access_touch_recheck(config_db, app_db, access_token, now,
                                         info);
    return WEBD_SESSION_IDLE_OK;
}

int webd_session_idle_refresh_issue(sqlite3 *config_db, sqlite3 *app_db,
                                    const char *refresh_token,
                                    const char *new_access_token,
                                    int64_t access_expires_at, int64_t now,
                                    struct webd_session_idle_info *info)
{
    struct webd_session_row row;
    int timeout_min;
    int result;

    if (!config_db || !app_db || !idle_text_ok(refresh_token, 256) ||
        !idle_text_ok(new_access_token, 256) ||
        !strcmp(refresh_token, new_access_token) || now < 0 ||
        access_expires_at <= now)
        return WEBD_SESSION_IDLE_INVALID_ARGUMENT;
    result = idle_session_read(app_db, refresh_token, "refresh", now, &row);
    if (result != WEBD_SESSION_IDLE_OK)
        return result;
    result = webd_session_idle_timeout_get(config_db, row.username,
                                           &timeout_min);
    if (result != WEBD_SESSION_IDLE_OK)
        return result;
    /* Keep lock ordering one-way: read config.db before locking apid.db. */
    if (idle_exec(app_db, "BEGIN IMMEDIATE") != 0)
        return WEBD_SESSION_IDLE_DB_ERROR;
    result = idle_session_read(app_db, refresh_token, "refresh", now, &row);
    if (result != WEBD_SESSION_IDLE_OK)
        goto rollback;
    idle_info_set(info, &row, timeout_min);
    if (idle_is_expired(now, row.last_activity_at, timeout_min)) {
        if (idle_family_update(app_db, &row, now, 1) != 0) {
            result = WEBD_SESSION_IDLE_DB_ERROR;
            goto rollback;
        }
        if (idle_exec(app_db, "COMMIT") != 0) {
            idle_rollback(app_db);
            return WEBD_SESSION_IDLE_DB_ERROR;
        }
        return WEBD_SESSION_IDLE_TIMEOUT;
    }
    if (idle_family_update(app_db, &row, now, 0) != 0 ||
        idle_insert_row(app_db, new_access_token, row.username, "access",
                        row.session_id, now, access_expires_at) != 0) {
        result = WEBD_SESSION_IDLE_DB_ERROR;
        goto rollback;
    }
    if (idle_exec(app_db, "COMMIT") != 0) {
        idle_rollback(app_db);
        return WEBD_SESSION_IDLE_DB_ERROR;
    }
    row.last_activity_at = now;
    idle_info_set(info, &row, timeout_min);
    return WEBD_SESSION_IDLE_OK;

rollback:
    idle_rollback(app_db);
    return result;
}

const char *webd_session_idle_error(int result)
{
    switch (result) {
    case WEBD_SESSION_IDLE_TIMEOUT:
        return WEBD_SESSION_IDLE_ERROR;
    case WEBD_SESSION_IDLE_TOKEN_INVALID:
        return "invalid_web_session";
    case WEBD_SESSION_IDLE_USER_NOT_FOUND:
        return "web_user_not_found";
    case WEBD_SESSION_IDLE_DB_ERROR:
        return "web_session_state_unavailable";
    case WEBD_SESSION_IDLE_INVALID_ARGUMENT:
        return "invalid_web_session_idle_request";
    default:
        return "";
    }
}

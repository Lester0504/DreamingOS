// SPDX-License-Identifier: GPL-2.0-or-later
/* Non-secret BLE session metadata. Credentials stay in volatile APD memory. */
#include "apd_internal.h"
#include "apd_ble_db.h"

#include <string.h>

static const char apd_ble_schema[] =
    "CREATE TABLE IF NOT EXISTS apd_ble_session ("
    "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
    "bootstrap_id TEXT NOT NULL,request_id TEXT NOT NULL,"
    "session_id BLOB NOT NULL CHECK(length(session_id)=16),"
    "public_key BLOB CHECK(public_key IS NULL OR length(public_key)=32),"
    "bootstrap_nonce BLOB CHECK(bootstrap_nonce IS NULL OR length(bootstrap_nonce)=32),"
    "state TEXT NOT NULL CHECK(state IN ('created','staged','committing',"
    "'complete','failed','cancelled','expired')),"
    "expires_at INTEGER NOT NULL,physical_confirmed INTEGER NOT NULL "
    "CHECK(physical_confirmed IN (0,1)),last_sequence INTEGER NOT NULL "
    "DEFAULT 0,request_digest BLOB CHECK(request_digest IS NULL OR length(request_digest)=32),"
    "updated_at INTEGER NOT NULL);";

static int exec_sql(const char *sql)
{
    return g_apd_db && sqlite3_exec(g_apd_db, sql, NULL, NULL, NULL) == SQLITE_OK ?
           0 : -1;
}

static int bind_session(sqlite3_stmt *statement, int index,
                        const unsigned char session_id[APD_BLE_SESSION_ID_LEN])
{
    return sqlite3_bind_blob(statement, index, session_id,
                             APD_BLE_SESSION_ID_LEN, SQLITE_TRANSIENT) ==
           SQLITE_OK ? 0 : -1;
}

static int ble_sequence_sqlite_safe(uint64_t sequence)
{
    return sequence <= (uint64_t)INT64_MAX;
}

static int apd_ble_db_expire_in_transaction(void)
{
    sqlite3_stmt *statement = NULL;
    int rc = APD_BLE_DB_ERROR;

    if (!g_apd_db || sqlite3_prepare_v2(g_apd_db,
            "UPDATE apd_ble_session SET state='expired',public_key=NULL,"
            "bootstrap_nonce=NULL,request_digest=NULL,updated_at=?1 WHERE singleton=1 "
            "AND state IN ('created','staged','committing') AND expires_at<=?1",
            -1, &statement, NULL) != SQLITE_OK)
        return rc;
    sqlite3_bind_int64(statement, 1, apd_now_s());
    if (sqlite3_step(statement) == SQLITE_DONE)
        rc = APD_BLE_DB_OK;
    sqlite3_finalize(statement);
    return rc;
}

int apd_ble_db_init(void)
{
    return exec_sql(apd_ble_schema) == 0 ? APD_BLE_DB_OK : APD_BLE_DB_ERROR;
}

int apd_ble_db_recover(void)
{
    /* The ephemeral private key is intentionally never persisted. Any
     * non-terminal row found after APD restart is therefore unusable. */
    return exec_sql(
        "UPDATE apd_ble_session SET state='failed',public_key=NULL,"
        "bootstrap_nonce=NULL,request_digest=NULL,updated_at=strftime('%s','now') "
        "WHERE state IN ('created','staged','committing')") == 0 ?
        APD_BLE_DB_OK : APD_BLE_DB_ERROR;
}

int apd_ble_db_expire(void)
{
    sqlite3_stmt *statement = NULL;
    int rc = APD_BLE_DB_ERROR;

    if (!g_apd_db || sqlite3_prepare_v2(g_apd_db,
            "UPDATE apd_ble_session SET state='expired',public_key=NULL,"
            "bootstrap_nonce=NULL,request_digest=NULL,updated_at=?1 WHERE singleton=1 "
            "AND state IN ('created','staged','committing') AND expires_at<=?1",
            -1, &statement, NULL) != SQLITE_OK)
        return rc;
    sqlite3_bind_int64(statement, 1, apd_now_s());
    if (sqlite3_step(statement) == SQLITE_DONE)
        rc = APD_BLE_DB_OK;
    sqlite3_finalize(statement);
    return rc;
}

int apd_ble_db_begin(const char *bootstrap_id, const char *request_id,
                     const unsigned char session_id[APD_BLE_SESSION_ID_LEN],
                     const unsigned char public_key[APD_BLE_X25519_KEY_LEN],
                     const unsigned char bootstrap_nonce[APD_BLE_BOOTSTRAP_NONCE_LEN],
                     int64_t expires_at, int physical_confirmed)
{
    sqlite3_stmt *statement = NULL;
    sqlite3_stmt *existing = NULL;
    int rc = APD_BLE_DB_ERROR;

    if (!g_apd_db || !bootstrap_id || !request_id || !session_id || !public_key ||
        !bootstrap_nonce || expires_at <= apd_now_s() ||
        expires_at > apd_now_s() + 300 ||
        exec_sql("BEGIN IMMEDIATE") != 0)
        return APD_BLE_DB_ERROR;
    if (apd_ble_db_expire_in_transaction() != APD_BLE_DB_OK)
        goto done;
    if (sqlite3_prepare_v2(g_apd_db,
            "SELECT state,request_id FROM apd_ble_session WHERE singleton=1",
            -1, &existing, NULL) != SQLITE_OK)
        goto done;
    if (sqlite3_step(existing) == SQLITE_ROW) {
        const char *state = (const char *)sqlite3_column_text(existing, 0);
        const char *old_request = (const char *)sqlite3_column_text(existing, 1);
        if (state && (!strcmp(state, "created") || !strcmp(state, "staged") ||
                      !strcmp(state, "committing"))) {
            rc = old_request && !strcmp(old_request, request_id) ?
                 APD_BLE_DB_IDEMPOTENT : APD_BLE_DB_BUSY;
            goto done;
        }
    }
    sqlite3_finalize(existing);
    existing = NULL;
    if (sqlite3_prepare_v2(g_apd_db,
            "INSERT INTO apd_ble_session(singleton,bootstrap_id,request_id,session_id,"
            "public_key,bootstrap_nonce,state,expires_at,physical_confirmed,"
            "last_sequence,updated_at) VALUES(1,?1,?2,?3,?4,?5,'created',?6,?7,0,?8) "
            "ON CONFLICT(singleton) DO UPDATE SET bootstrap_id=excluded.bootstrap_id,"
            "request_id=excluded.request_id,session_id=excluded.session_id,"
            "public_key=excluded.public_key,bootstrap_nonce=excluded.bootstrap_nonce,"
            "state='created',expires_at=excluded.expires_at,physical_confirmed=excluded.physical_confirmed,"
            "last_sequence=0,request_digest=NULL,updated_at=excluded.updated_at",
            -1, &statement, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(statement, 1, bootstrap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, request_id, -1, SQLITE_TRANSIENT);
    bind_session(statement, 3, session_id);
    sqlite3_bind_blob(statement, 4, public_key, APD_BLE_X25519_KEY_LEN,
                      SQLITE_TRANSIENT);
    sqlite3_bind_blob(statement, 5, bootstrap_nonce, APD_BLE_BOOTSTRAP_NONCE_LEN,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 6, expires_at);
    sqlite3_bind_int(statement, 7, physical_confirmed ? 1 : 0);
    sqlite3_bind_int64(statement, 8, apd_now_s());
    if (sqlite3_step(statement) == SQLITE_DONE)
        rc = APD_BLE_DB_OK;
done:
    sqlite3_finalize(statement);
    sqlite3_finalize(existing);
    if (rc == APD_BLE_DB_OK || rc == APD_BLE_DB_IDEMPOTENT) {
        if (exec_sql("COMMIT") != 0)
            return APD_BLE_DB_ERROR;
    } else {
        exec_sql("ROLLBACK");
    }
    return rc;
}

int apd_ble_db_stage(const unsigned char session_id[APD_BLE_SESSION_ID_LEN],
                     const char *request_id, const unsigned char digest[32],
                     uint64_t last_sequence)
{
    sqlite3_stmt *statement = NULL;
    int rc = APD_BLE_DB_ERROR;

    if (!g_apd_db || !session_id || !request_id || !digest ||
        !ble_sequence_sqlite_safe(last_sequence) ||
        exec_sql("BEGIN IMMEDIATE") != 0)
        return APD_BLE_DB_ERROR;
    if (sqlite3_prepare_v2(g_apd_db,
            "UPDATE apd_ble_session SET state='staged',request_digest=?1,"
            "last_sequence=?2,updated_at=?3 WHERE singleton=1 AND session_id=?4 "
            "AND request_id=?5 AND state='created' AND expires_at>?3",
            -1, &statement, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_blob(statement, 1, digest, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 2, (sqlite3_int64)last_sequence);
    sqlite3_bind_int64(statement, 3, apd_now_s());
    bind_session(statement, 4, session_id);
    sqlite3_bind_text(statement, 5, request_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(statement) == SQLITE_DONE && sqlite3_changes(g_apd_db) == 1)
        rc = APD_BLE_DB_OK;
done:
    sqlite3_finalize(statement);
    if (rc == APD_BLE_DB_OK)
        exec_sql("COMMIT");
    else
        exec_sql("ROLLBACK");
    return rc;
}

int apd_ble_db_sequence(const unsigned char session_id[APD_BLE_SESSION_ID_LEN],
                        uint64_t last_sequence)
{
    sqlite3_stmt *statement = NULL;
    int rc = APD_BLE_DB_ERROR;

    if (!g_apd_db || !session_id || !ble_sequence_sqlite_safe(last_sequence) ||
        sqlite3_prepare_v2(g_apd_db,
            "UPDATE apd_ble_session SET last_sequence=?1,updated_at=?2 "
            "WHERE singleton=1 AND session_id=?3 AND expires_at>?2",
            -1, &statement, NULL) != SQLITE_OK)
        return rc;
    sqlite3_bind_int64(statement, 1, (sqlite3_int64)last_sequence);
    sqlite3_bind_int64(statement, 2, apd_now_s());
    bind_session(statement, 3, session_id);
    if (sqlite3_step(statement) == SQLITE_DONE && sqlite3_changes(g_apd_db) == 1)
        rc = APD_BLE_DB_OK;
    sqlite3_finalize(statement);
    return rc;
}

int apd_ble_db_physical_confirm(
    const unsigned char session_id[APD_BLE_SESSION_ID_LEN])
{
    sqlite3_stmt *statement = NULL;
    int rc = APD_BLE_DB_ERROR;

    if (!g_apd_db || !session_id || exec_sql("BEGIN IMMEDIATE") != 0)
        return rc;
    if (sqlite3_prepare_v2(g_apd_db,
            "UPDATE apd_ble_session SET physical_confirmed=1,updated_at=?1 "
            "WHERE singleton=1 AND session_id=?2 AND state='created' "
            "AND expires_at>?1",
            -1, &statement, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_int64(statement, 1, apd_now_s());
    bind_session(statement, 2, session_id);
    if (sqlite3_step(statement) == SQLITE_DONE && sqlite3_changes(g_apd_db) == 1)
        rc = APD_BLE_DB_OK;
done:
    sqlite3_finalize(statement);
    if (rc == APD_BLE_DB_OK)
        exec_sql("COMMIT");
    else
        exec_sql("ROLLBACK");
    return rc;
}

int apd_ble_db_status(struct apd_ble_db_status *out)
{
    sqlite3_stmt *statement = NULL;
    int rc = APD_BLE_DB_NOT_FOUND;

    if (!g_apd_db || !out)
        return APD_BLE_DB_ERROR;
    memset(out, 0, sizeof(*out));
    apd_ble_db_expire();
    if (sqlite3_prepare_v2(g_apd_db,
            "SELECT state,bootstrap_id,request_id,expires_at,physical_confirmed,"
            "last_sequence,request_digest IS NOT NULL,session_id FROM apd_ble_session WHERE singleton=1",
            -1, &statement, NULL) != SQLITE_OK)
        return APD_BLE_DB_ERROR;
    if (sqlite3_step(statement) == SQLITE_ROW) {
        snprintf(out->state, sizeof(out->state), "%s",
                 sqlite3_column_text(statement, 0));
        snprintf(out->bootstrap_id, sizeof(out->bootstrap_id), "%s",
                 sqlite3_column_text(statement, 1));
        snprintf(out->request_id, sizeof(out->request_id), "%s",
                 sqlite3_column_text(statement, 2));
        out->expires_at = sqlite3_column_int64(statement, 3);
        out->physical_confirmed = sqlite3_column_int(statement, 4) != 0;
        out->last_sequence = (uint64_t)sqlite3_column_int64(statement, 5);
        out->staged = sqlite3_column_int(statement, 6) != 0;
        if (sqlite3_column_bytes(statement, 7) == APD_BLE_SESSION_ID_LEN)
            apd_ble_hex((const unsigned char *)sqlite3_column_blob(statement, 7),
                        APD_BLE_SESSION_ID_LEN, out->session_id,
                        sizeof(out->session_id));
        rc = APD_BLE_DB_OK;
    }
    sqlite3_finalize(statement);
    return rc;
}

static int set_terminal(const unsigned char session_id[APD_BLE_SESSION_ID_LEN],
                        const char *state)
{
    sqlite3_stmt *statement = NULL;
    int rc = APD_BLE_DB_ERROR;

    if (!g_apd_db || !session_id || !state || exec_sql("BEGIN IMMEDIATE") != 0)
        return rc;
    if (sqlite3_prepare_v2(g_apd_db,
            "UPDATE apd_ble_session SET state=?1,public_key=NULL,"
            "bootstrap_nonce=NULL,request_digest=NULL,updated_at=?2 "
            "WHERE singleton=1 AND session_id=?3 AND state IN ('created','staged','committing')",
            -1, &statement, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(statement, 1, state, -1, SQLITE_STATIC);
    sqlite3_bind_int64(statement, 2, apd_now_s());
    bind_session(statement, 3, session_id);
    if (sqlite3_step(statement) == SQLITE_DONE && sqlite3_changes(g_apd_db) == 1)
        rc = APD_BLE_DB_OK;
done:
    sqlite3_finalize(statement);
    if (rc == APD_BLE_DB_OK)
        exec_sql("COMMIT");
    else
        exec_sql("ROLLBACK");
    return rc;
}

int apd_ble_db_cancel(const unsigned char session_id[APD_BLE_SESSION_ID_LEN])
{
    return set_terminal(session_id, "cancelled");
}

int apd_ble_db_commit_started(const unsigned char session_id[APD_BLE_SESSION_ID_LEN])
{
    sqlite3_stmt *statement = NULL;
    int rc = APD_BLE_DB_ERROR;

    if (!g_apd_db || !session_id || exec_sql("BEGIN IMMEDIATE") != 0)
        return rc;
    if (sqlite3_prepare_v2(g_apd_db,
            "UPDATE apd_ble_session SET state='committing',updated_at=?1 "
            "WHERE singleton=1 AND session_id=?2 AND state='staged' AND expires_at>?1",
            -1, &statement, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_int64(statement, 1, apd_now_s());
    bind_session(statement, 2, session_id);
    if (sqlite3_step(statement) == SQLITE_DONE && sqlite3_changes(g_apd_db) == 1)
        rc = APD_BLE_DB_OK;
done:
    sqlite3_finalize(statement);
    if (rc == APD_BLE_DB_OK)
        exec_sql("COMMIT");
    else
        exec_sql("ROLLBACK");
    return rc;
}

int apd_ble_db_failed(const unsigned char session_id[APD_BLE_SESSION_ID_LEN])
{
    return set_terminal(session_id, "failed");
}

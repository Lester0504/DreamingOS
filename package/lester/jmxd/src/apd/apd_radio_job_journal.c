// SPDX-License-Identifier: GPL-2.0-or-later
#include "apd_radio_job_journal.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>
#include <sqlite3.h>

extern sqlite3 *g_apd_db;

static int journal_tx_begin(void);
static int journal_tx_commit(void);
static void journal_tx_rollback(void);

static const char apd_radio_job_schema[] =
    "CREATE TABLE IF NOT EXISTS apd_radio_job_journal ("
    "job_id TEXT PRIMARY KEY,"
    "attempt_id TEXT NOT NULL UNIQUE,"
    "dispatch_generation INTEGER NOT NULL CHECK(dispatch_generation>0),"
    "request_digest TEXT NOT NULL,"
    "ap_id TEXT NOT NULL,"
    "session_epoch TEXT NOT NULL,"
    "radio_id TEXT NOT NULL,"
    "mode TEXT NOT NULL,"
    "state TEXT NOT NULL CHECK(state IN "
    "('offered','running','cancel_requested','completed','failed','cancelled','interrupted')),"
    "finish_id TEXT NOT NULL DEFAULT '',"
    "outcome TEXT NOT NULL DEFAULT '' CHECK(outcome IN ('','completed','failed','cancelled')),"
    "error_code TEXT NOT NULL DEFAULT '',"
    "observed_at INTEGER NOT NULL DEFAULT 0,"
    "result_json TEXT NOT NULL DEFAULT '[]',"
    "result_count INTEGER NOT NULL DEFAULT 0 CHECK(result_count BETWEEN 0 AND 128),"
    "result_bytes INTEGER NOT NULL DEFAULT 2 CHECK(result_bytes BETWEEN 0 AND 49152),"
    "result_complete INTEGER NOT NULL DEFAULT 0 CHECK(result_complete IN (0,1)),"
    "finish_acked INTEGER NOT NULL DEFAULT 0 CHECK(finish_acked IN (0,1)),"
    "finish_acked_at INTEGER NOT NULL DEFAULT 0,"
    "created_at INTEGER NOT NULL,"
    "updated_at INTEGER NOT NULL);"
    "CREATE INDEX IF NOT EXISTS idx_apd_radio_job_reconcile "
    "ON apd_radio_job_journal(state,updated_at);"
    "CREATE INDEX IF NOT EXISTS idx_apd_radio_job_pending_finish "
    "ON apd_radio_job_journal(ap_id,finish_acked,updated_at) "
    "WHERE finish_id<>'';"
    "CREATE INDEX IF NOT EXISTS idx_apd_radio_job_retention "
    "ON apd_radio_job_journal(ap_id,finish_acked,state,updated_at,job_id);";

static int journal_exec(const char *sql)
{
    return g_apd_db && sqlite3_exec(g_apd_db, sql, NULL, NULL, NULL) == SQLITE_OK
        ? 0 : -1;
}

static int journal_prune_locked(int64_t now)
{
    sqlite3_stmt *statement = NULL;
    int changed;

    if (!g_apd_db)
        return -1;
    if (now <= APD_RADIO_JOB_RETENTION_SECONDS)
        return 0;
    if (sqlite3_prepare_v2(g_apd_db,
            "DELETE FROM apd_radio_job_journal WHERE finish_acked=1 "
            "AND state IN ('completed','failed','cancelled','interrupted') "
            "AND updated_at<?1 AND (SELECT COUNT(*) FROM apd_radio_job_journal newer "
            "WHERE newer.ap_id=apd_radio_job_journal.ap_id "
            "AND newer.finish_acked=1 "
            "AND newer.state IN ('completed','failed','cancelled','interrupted') "
            "AND (newer.updated_at>apd_radio_job_journal.updated_at OR "
            "(newer.updated_at=apd_radio_job_journal.updated_at AND "
            "newer.job_id>apd_radio_job_journal.job_id)))>=?2",
            -1, &statement, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(statement, 1, now - APD_RADIO_JOB_RETENTION_SECONDS);
    sqlite3_bind_int(statement, 2, APD_RADIO_JOB_RETENTION_MIN);
    if (sqlite3_step(statement) != SQLITE_DONE) {
        sqlite3_finalize(statement);
        return -1;
    }
    changed = sqlite3_changes(g_apd_db);
    sqlite3_finalize(statement);
    return changed;
}

int apd_radio_job_journal_prune(int64_t now)
{
    int changed;

    if (now <= 0 || journal_tx_begin() != 0)
        return APD_RADIO_JOB_JOURNAL_ERROR;
    changed = journal_prune_locked(now);
    if (changed < 0) {
        journal_tx_rollback();
        return APD_RADIO_JOB_JOURNAL_ERROR;
    }
    if (journal_tx_commit() != 0)
        return APD_RADIO_JOB_JOURNAL_ERROR;
    return changed;
}

static int journal_tx_begin(void)
{
    sqlite3_mutex *mutex;

    if (!g_apd_db)
        return -1;
    mutex = sqlite3_db_mutex(g_apd_db);
    sqlite3_mutex_enter(mutex);
    if (journal_exec("BEGIN IMMEDIATE") != 0) {
        sqlite3_mutex_leave(mutex);
        return -1;
    }
    return 0;
}

static int journal_tx_commit(void)
{
    sqlite3_mutex *mutex = sqlite3_db_mutex(g_apd_db);
    int rc = journal_exec("COMMIT");

    if (rc != 0)
        journal_exec("ROLLBACK");
    sqlite3_mutex_leave(mutex);
    return rc;
}

static void journal_tx_rollback(void)
{
    sqlite3_mutex *mutex = sqlite3_db_mutex(g_apd_db);

    journal_exec("ROLLBACK");
    sqlite3_mutex_leave(mutex);
}

static int is_lower_hex(const char *value, size_t length)
{
    size_t i;

    if (!value || strlen(value) != length)
        return 0;
    for (i = 0; i < length; i++) {
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f')))
            return 0;
    }
    return 1;
}

static int uuid_v4_valid(const char *value)
{
    static const size_t hyphens[] = {8, 13, 18, 23};
    size_t i;
    size_t h = 0;

    if (!value || strlen(value) != APD_RADIO_JOB_UUID_LEN ||
        value[14] != '4' || !strchr("89ab", value[19]))
        return 0;
    for (i = 0; i < APD_RADIO_JOB_UUID_LEN; i++) {
        if (h < sizeof(hyphens) / sizeof(hyphens[0]) && i == hyphens[h]) {
            if (value[i] != '-')
                return 0;
            h++;
        } else if (!((value[i] >= '0' && value[i] <= '9') ||
                     (value[i] >= 'a' && value[i] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static int safe_name(const char *value, size_t maximum)
{
    size_t i;
    size_t length = value ? strlen(value) : 0;

    if (length == 0 || length > maximum)
        return 0;
    for (i = 0; i < length; i++) {
        unsigned char c = (unsigned char)value[i];
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.' || c == ':'))
            return 0;
    }
    return 1;
}

static int digest_valid(const char *value)
{
    return value && strncmp(value, "sha256:", 7) == 0 &&
           is_lower_hex(value + 7, 64);
}

static int assignment_valid(const struct apd_radio_job_assignment *assignment)
{
    return assignment && uuid_v4_valid(assignment->job_id) &&
           uuid_v4_valid(assignment->attempt_id) &&
           assignment->dispatch_generation > 0 &&
           digest_valid(assignment->request_digest) &&
           uuid_v4_valid(assignment->ap_id) &&
           is_lower_hex(assignment->session_epoch,
                        APD_RADIO_JOB_SESSION_EPOCH_LEN) &&
           safe_name(assignment->radio_id, APD_RADIO_JOB_RADIO_ID_MAX) &&
           safe_name(assignment->mode, APD_RADIO_JOB_MODE_MAX);
}

static int assignment_equal(const struct apd_radio_job_assignment *left,
                            const struct apd_radio_job_assignment *right)
{
    return strcmp(left->job_id, right->job_id) == 0 &&
           strcmp(left->attempt_id, right->attempt_id) == 0 &&
           left->dispatch_generation == right->dispatch_generation &&
           strcmp(left->request_digest, right->request_digest) == 0 &&
           strcmp(left->ap_id, right->ap_id) == 0 &&
           strcmp(left->session_epoch, right->session_epoch) == 0 &&
           strcmp(left->radio_id, right->radio_id) == 0 &&
           strcmp(left->mode, right->mode) == 0;
}

static void copy_text(char *target, size_t size, const unsigned char *value)
{
    snprintf(target, size, "%s", value ? (const char *)value : "");
}

static int entry_from_statement(sqlite3_stmt *statement,
                                struct apd_radio_job_journal_entry *out)
{
    if (!statement || !out)
        return -1;
    memset(out, 0, sizeof(*out));
    copy_text(out->assignment.job_id, sizeof(out->assignment.job_id),
              sqlite3_column_text(statement, 0));
    copy_text(out->assignment.attempt_id, sizeof(out->assignment.attempt_id),
              sqlite3_column_text(statement, 1));
    out->assignment.dispatch_generation = sqlite3_column_int64(statement, 2);
    copy_text(out->assignment.request_digest,
              sizeof(out->assignment.request_digest),
              sqlite3_column_text(statement, 3));
    copy_text(out->assignment.ap_id, sizeof(out->assignment.ap_id),
              sqlite3_column_text(statement, 4));
    copy_text(out->assignment.session_epoch,
              sizeof(out->assignment.session_epoch),
              sqlite3_column_text(statement, 5));
    copy_text(out->assignment.radio_id, sizeof(out->assignment.radio_id),
              sqlite3_column_text(statement, 6));
    copy_text(out->assignment.mode, sizeof(out->assignment.mode),
              sqlite3_column_text(statement, 7));
    copy_text(out->state, sizeof(out->state), sqlite3_column_text(statement, 8));
    copy_text(out->finish_id, sizeof(out->finish_id),
              sqlite3_column_text(statement, 9));
    copy_text(out->outcome, sizeof(out->outcome),
              sqlite3_column_text(statement, 10));
    copy_text(out->error_code, sizeof(out->error_code),
              sqlite3_column_text(statement, 11));
    out->observed_at = sqlite3_column_int64(statement, 12);
    out->result_count = sqlite3_column_int(statement, 13);
    out->result_bytes = sqlite3_column_int64(statement, 14);
    out->result_complete = sqlite3_column_int(statement, 15);
    out->finish_acked = sqlite3_column_int(statement, 16);
    out->created_at = sqlite3_column_int64(statement, 17);
    out->updated_at = sqlite3_column_int64(statement, 18);
    return 0;
}

static const char entry_columns[] =
    "job_id,attempt_id,dispatch_generation,request_digest,ap_id,session_epoch,"
    "radio_id,mode,state,finish_id,outcome,error_code,observed_at,result_count,"
    "result_bytes,result_complete,finish_acked,created_at,updated_at";

static int get_entry(const char *job_id,
                     struct apd_radio_job_journal_entry *out)
{
    sqlite3_stmt *statement = NULL;
    char sql[512];
    int result = APD_RADIO_JOB_JOURNAL_ERROR;

    if (!g_apd_db || !job_id || !out ||
        snprintf(sql, sizeof(sql), "SELECT %s FROM apd_radio_job_journal "
                 "WHERE job_id=?1", entry_columns) >= (int)sizeof(sql) ||
        sqlite3_prepare_v2(g_apd_db, sql, -1, &statement, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(statement, 1, job_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(statement) == SQLITE_ROW &&
        entry_from_statement(statement, out) == 0)
        result = APD_RADIO_JOB_JOURNAL_OK;
    else if (sqlite3_errcode(g_apd_db) == SQLITE_OK ||
             sqlite3_errcode(g_apd_db) == SQLITE_DONE)
        result = APD_RADIO_JOB_JOURNAL_NOT_FOUND;
done:
    sqlite3_finalize(statement);
    return result;
}

static int bind_assignment(sqlite3_stmt *statement,
                           const struct apd_radio_job_assignment *assignment,
                           int first)
{
    return sqlite3_bind_text(statement, first, assignment->job_id, -1,
                             SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_text(statement, first + 1, assignment->attempt_id, -1,
                             SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_int64(statement, first + 2,
                              assignment->dispatch_generation) == SQLITE_OK &&
           sqlite3_bind_text(statement, first + 3, assignment->request_digest,
                             -1, SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_text(statement, first + 4, assignment->ap_id, -1,
                             SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_text(statement, first + 5, assignment->session_epoch,
                             -1, SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_text(statement, first + 6, assignment->radio_id, -1,
                             SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_text(statement, first + 7, assignment->mode, -1,
                             SQLITE_TRANSIENT) == SQLITE_OK ? 0 : -1;
}

int apd_radio_job_journal_init(void)
{
    if (journal_tx_begin() != 0)
        return APD_RADIO_JOB_JOURNAL_ERROR;
    if (journal_exec(apd_radio_job_schema) != 0) {
        journal_tx_rollback();
        return APD_RADIO_JOB_JOURNAL_ERROR;
    }
    return journal_tx_commit() == 0 ? APD_RADIO_JOB_JOURNAL_OK
                                    : APD_RADIO_JOB_JOURNAL_ERROR;
}

int apd_radio_job_offer_store(const struct apd_radio_job_assignment *assignment,
                              int64_t now,
                              struct apd_radio_job_journal_entry *out)
{
    sqlite3_stmt *statement = NULL;
    struct apd_radio_job_journal_entry existing;
    int result = APD_RADIO_JOB_JOURNAL_ERROR;

    if (!assignment_valid(assignment) || now <= 0)
        return APD_RADIO_JOB_JOURNAL_INVALID;
    if (journal_tx_begin() != 0)
        return result;
    result = get_entry(assignment->job_id, &existing);
    if (result == APD_RADIO_JOB_JOURNAL_OK) {
        result = assignment_equal(assignment, &existing.assignment)
            ? APD_RADIO_JOB_JOURNAL_IDEMPOTENT
            : APD_RADIO_JOB_JOURNAL_CONFLICT;
        if (out)
            *out = existing;
        goto commit;
    }
    if (result != APD_RADIO_JOB_JOURNAL_NOT_FOUND)
        goto rollback;
    if (sqlite3_prepare_v2(g_apd_db,
            "INSERT INTO apd_radio_job_journal("
            "job_id,attempt_id,dispatch_generation,request_digest,ap_id,"
            "session_epoch,radio_id,mode,state,created_at,updated_at) "
            "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'offered',?9,?9)",
            -1, &statement, NULL) != SQLITE_OK ||
        bind_assignment(statement, assignment, 1) != 0 ||
        sqlite3_bind_int64(statement, 9, now) != SQLITE_OK ||
        sqlite3_step(statement) != SQLITE_DONE) {
        if ((sqlite3_extended_errcode(g_apd_db) & 0xff) == SQLITE_CONSTRAINT)
            result = APD_RADIO_JOB_JOURNAL_CONFLICT;
        goto rollback;
    }
    sqlite3_finalize(statement);
    statement = NULL;
    result = get_entry(assignment->job_id, &existing);
    if (result != APD_RADIO_JOB_JOURNAL_OK)
        goto rollback;
    if (out)
        *out = existing;
commit:
    sqlite3_finalize(statement);
    if (journal_tx_commit() != 0)
        return APD_RADIO_JOB_JOURNAL_ERROR;
    return result;
rollback:
    sqlite3_finalize(statement);
    journal_tx_rollback();
    return result;
}

static int assignment_transition(
    const struct apd_radio_job_assignment *assignment, const char *from_a,
    const char *from_b, const char *to, int64_t now,
    struct apd_radio_job_journal_entry *out)
{
    sqlite3_stmt *statement = NULL;
    struct apd_radio_job_journal_entry existing;
    int result = APD_RADIO_JOB_JOURNAL_ERROR;

    if (!assignment_valid(assignment) || now <= 0)
        return APD_RADIO_JOB_JOURNAL_INVALID;
    if (journal_tx_begin() != 0)
        return result;
    result = get_entry(assignment->job_id, &existing);
    if (result != APD_RADIO_JOB_JOURNAL_OK)
        goto commit;
    if (!assignment_equal(assignment, &existing.assignment)) {
        result = APD_RADIO_JOB_JOURNAL_CONFLICT;
        goto commit;
    }
    if (strcmp(existing.state, to) == 0) {
        result = APD_RADIO_JOB_JOURNAL_IDEMPOTENT;
        if (out)
            *out = existing;
        goto commit;
    }
    if (strcmp(existing.state, from_a) != 0 &&
        (!from_b || strcmp(existing.state, from_b) != 0)) {
        result = APD_RADIO_JOB_JOURNAL_CONFLICT;
        goto commit;
    }
    if (sqlite3_prepare_v2(g_apd_db,
            "UPDATE apd_radio_job_journal SET state=?1,updated_at=?2 "
            "WHERE job_id=?3 AND attempt_id=?4 AND dispatch_generation=?5 "
            "AND request_digest=?6 AND session_epoch=?7", -1, &statement,
            NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(statement, 1, to, -1, SQLITE_STATIC);
    sqlite3_bind_int64(statement, 2, now);
    sqlite3_bind_text(statement, 3, assignment->job_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 4, assignment->attempt_id, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 5, assignment->dispatch_generation);
    sqlite3_bind_text(statement, 6, assignment->request_digest, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 7, assignment->session_epoch, -1,
                      SQLITE_TRANSIENT);
    if (sqlite3_step(statement) != SQLITE_DONE || sqlite3_changes(g_apd_db) != 1)
        goto rollback;
    sqlite3_finalize(statement);
    statement = NULL;
    result = get_entry(assignment->job_id, &existing);
    if (result != APD_RADIO_JOB_JOURNAL_OK)
        goto rollback;
    if (out)
        *out = existing;
commit:
    sqlite3_finalize(statement);
    if (journal_tx_commit() != 0)
        return APD_RADIO_JOB_JOURNAL_ERROR;
    return result;
rollback:
    sqlite3_finalize(statement);
    journal_tx_rollback();
    return APD_RADIO_JOB_JOURNAL_ERROR;
}

int apd_radio_job_mark_running(const struct apd_radio_job_assignment *assignment,
                               int64_t now,
                               struct apd_radio_job_journal_entry *out)
{
    return assignment_transition(assignment, "offered", NULL, "running", now,
                                 out);
}

int apd_radio_job_cancel_requested(
    const struct apd_radio_job_assignment *assignment, int64_t now,
    struct apd_radio_job_journal_entry *out)
{
    return assignment_transition(assignment, "offered", "running",
                                 "cancel_requested", now, out);
}

int apd_radio_job_session_rebind(
    const struct apd_radio_job_assignment *assignment,
    const char *new_session_epoch, int64_t now,
    struct apd_radio_job_journal_entry *out)
{
    sqlite3_stmt *statement = NULL;
    struct apd_radio_job_journal_entry existing;
    int result = APD_RADIO_JOB_JOURNAL_ERROR;

    if (!assignment_valid(assignment) ||
        !is_lower_hex(new_session_epoch, APD_RADIO_JOB_SESSION_EPOCH_LEN) ||
        now <= 0)
        return APD_RADIO_JOB_JOURNAL_INVALID;
    if (journal_tx_begin() != 0)
        return result;
    result = get_entry(assignment->job_id, &existing);
    if (result != APD_RADIO_JOB_JOURNAL_OK)
        goto commit;
    if (!assignment_equal(assignment, &existing.assignment) ||
        existing.finish_acked) {
        result = APD_RADIO_JOB_JOURNAL_CONFLICT;
        goto commit;
    }
    if (!strcmp(existing.assignment.session_epoch, new_session_epoch)) {
        if (out)
            *out = existing;
        result = APD_RADIO_JOB_JOURNAL_IDEMPOTENT;
        goto commit;
    }
    if (sqlite3_prepare_v2(g_apd_db,
            "UPDATE apd_radio_job_journal SET session_epoch=?1,updated_at=?2 "
            "WHERE job_id=?3 AND attempt_id=?4 AND dispatch_generation=?5 "
            "AND request_digest=?6 AND ap_id=?7 AND session_epoch=?8 "
            "AND finish_acked=0", -1, &statement, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(statement, 1, new_session_epoch, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 2, now);
    sqlite3_bind_text(statement, 3, assignment->job_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 4, assignment->attempt_id, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 5, assignment->dispatch_generation);
    sqlite3_bind_text(statement, 6, assignment->request_digest, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 7, assignment->ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 8, assignment->session_epoch, -1,
                      SQLITE_TRANSIENT);
    if (sqlite3_step(statement) != SQLITE_DONE || sqlite3_changes(g_apd_db) != 1)
        goto rollback;
    sqlite3_finalize(statement);
    statement = NULL;
    result = get_entry(assignment->job_id, &existing);
    if (result != APD_RADIO_JOB_JOURNAL_OK)
        goto rollback;
    if (out)
        *out = existing;
commit:
    sqlite3_finalize(statement);
    if (journal_tx_commit() != 0)
        return APD_RADIO_JOB_JOURNAL_ERROR;
    return result;
rollback:
    sqlite3_finalize(statement);
    journal_tx_rollback();
    return APD_RADIO_JOB_JOURNAL_ERROR;
}

static int result_validate(const struct apd_radio_job_finish *finish,
                           int *item_count, int64_t *result_bytes)
{
    struct json_tokener *tokener = NULL;
    struct json_object *object = NULL;
    enum json_tokener_error error;
    size_t length;
    int result = APD_RADIO_JOB_JOURNAL_INVALID;

    if (!finish || !finish->result_json)
        return result;
    length = strlen(finish->result_json);
    if (length > APD_RADIO_JOB_RESULT_MAX_BYTES)
        return APD_RADIO_JOB_JOURNAL_LIMIT;
    tokener = json_tokener_new();
    if (!tokener)
        return APD_RADIO_JOB_JOURNAL_ERROR;
    object = json_tokener_parse_ex(tokener, finish->result_json, (int)length);
    error = json_tokener_get_error(tokener);
    if (error != json_tokener_success ||
        json_tokener_get_parse_end(tokener) != length || !object ||
        !json_object_is_type(object, json_type_array))
        goto done;
    if (json_object_array_length(object) > APD_RADIO_JOB_RESULT_MAX_ITEMS) {
        result = APD_RADIO_JOB_JOURNAL_LIMIT;
        goto done;
    }
    *item_count = (int)json_object_array_length(object);
    *result_bytes = (int64_t)length;
    result = APD_RADIO_JOB_JOURNAL_OK;
done:
    json_object_put(object);
    json_tokener_free(tokener);
    return result;
}

static int finish_valid(const struct apd_radio_job_finish *finish,
                        int *item_count, int64_t *result_bytes)
{
    if (!finish || !assignment_valid(&finish->assignment) ||
        !uuid_v4_valid(finish->finish_id) || finish->observed_at <= 0 ||
        (finish->result_complete != 0 && finish->result_complete != 1) ||
        (strcmp(finish->outcome, "completed") != 0 &&
         strcmp(finish->outcome, "failed") != 0 &&
         strcmp(finish->outcome, "cancelled") != 0) ||
        strlen(finish->error_code) > APD_RADIO_JOB_ERROR_MAX ||
        (finish->error_code[0] &&
         !safe_name(finish->error_code, APD_RADIO_JOB_ERROR_MAX)))
        return APD_RADIO_JOB_JOURNAL_INVALID;
    return result_validate(finish, item_count, result_bytes);
}

static int stored_finish_equal(sqlite3_stmt *statement,
                               const struct apd_radio_job_finish *finish,
                               int count, int64_t bytes)
{
    const unsigned char *result_json = sqlite3_column_text(statement, 5);

    return strcmp((const char *)sqlite3_column_text(statement, 0),
                  finish->finish_id) == 0 &&
           strcmp((const char *)sqlite3_column_text(statement, 1),
                  finish->outcome) == 0 &&
           strcmp((const char *)sqlite3_column_text(statement, 2),
                  finish->error_code) == 0 &&
           sqlite3_column_int64(statement, 3) == finish->observed_at &&
           sqlite3_column_int(statement, 4) == finish->result_complete &&
           result_json && strcmp((const char *)result_json,
                                 finish->result_json) == 0 &&
           sqlite3_column_int(statement, 6) == count &&
           sqlite3_column_int64(statement, 7) == bytes;
}

int apd_radio_job_finish_store(const struct apd_radio_job_finish *finish,
                               int64_t now,
                               struct apd_radio_job_journal_entry *out)
{
    sqlite3_stmt *statement = NULL;
    struct apd_radio_job_journal_entry existing;
    int count = 0;
    int64_t bytes = 0;
    int result = finish_valid(finish, &count, &bytes);

    if (result != APD_RADIO_JOB_JOURNAL_OK || now <= 0)
        return result == APD_RADIO_JOB_JOURNAL_OK
            ? APD_RADIO_JOB_JOURNAL_INVALID : result;
    if (journal_tx_begin() != 0)
        return APD_RADIO_JOB_JOURNAL_ERROR;
    result = get_entry(finish->assignment.job_id, &existing);
    if (result != APD_RADIO_JOB_JOURNAL_OK)
        goto commit;
    if (!assignment_equal(&finish->assignment, &existing.assignment)) {
        result = APD_RADIO_JOB_JOURNAL_CONFLICT;
        goto commit;
    }
    if (existing.finish_id[0]) {
        if (sqlite3_prepare_v2(g_apd_db,
                "SELECT finish_id,outcome,error_code,observed_at,result_complete,"
                "result_json,result_count,result_bytes FROM apd_radio_job_journal "
                "WHERE job_id=?1", -1, &statement, NULL) != SQLITE_OK)
            goto rollback;
        sqlite3_bind_text(statement, 1, finish->assignment.job_id, -1,
                          SQLITE_TRANSIENT);
        if (sqlite3_step(statement) != SQLITE_ROW)
            goto rollback;
        result = stored_finish_equal(statement, finish, count, bytes)
            ? APD_RADIO_JOB_JOURNAL_IDEMPOTENT
            : APD_RADIO_JOB_JOURNAL_CONFLICT;
        sqlite3_finalize(statement);
        statement = NULL;
        if (out)
            *out = existing;
        goto commit;
    }
    if (strcmp(existing.state, "running") != 0 &&
        strcmp(existing.state, "cancel_requested") != 0 &&
        strcmp(existing.state, "interrupted") != 0 &&
        !(strcmp(existing.state, "offered") == 0 &&
          strcmp(finish->outcome, "cancelled") == 0)) {
        result = APD_RADIO_JOB_JOURNAL_CONFLICT;
        goto commit;
    }
    if (strcmp(existing.state, "interrupted") == 0 &&
        strcmp(finish->outcome, "failed") != 0) {
        result = APD_RADIO_JOB_JOURNAL_CONFLICT;
        goto commit;
    }
    if (sqlite3_prepare_v2(g_apd_db,
            "UPDATE apd_radio_job_journal SET state=?1,finish_id=?2,outcome=?1,"
            "error_code=?3,observed_at=?4,result_json=?5,result_count=?6,"
            "result_bytes=?7,result_complete=?8,finish_acked=0,finish_acked_at=0,"
            "updated_at=?9 WHERE job_id=?10", -1, &statement, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(statement, 1, finish->outcome, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, finish->finish_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 3, finish->error_code, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 4, finish->observed_at);
    sqlite3_bind_text(statement, 5, finish->result_json, (int)bytes,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 6, count);
    sqlite3_bind_int64(statement, 7, bytes);
    sqlite3_bind_int(statement, 8, finish->result_complete);
    sqlite3_bind_int64(statement, 9, now);
    sqlite3_bind_text(statement, 10, finish->assignment.job_id, -1,
                      SQLITE_TRANSIENT);
    if (sqlite3_step(statement) != SQLITE_DONE || sqlite3_changes(g_apd_db) != 1)
        goto rollback;
    sqlite3_finalize(statement);
    statement = NULL;
    result = get_entry(finish->assignment.job_id, &existing);
    if (result != APD_RADIO_JOB_JOURNAL_OK)
        goto rollback;
    if (out)
        *out = existing;
commit:
    sqlite3_finalize(statement);
    if (journal_tx_commit() != 0)
        return APD_RADIO_JOB_JOURNAL_ERROR;
    return result;
rollback:
    sqlite3_finalize(statement);
    journal_tx_rollback();
    return APD_RADIO_JOB_JOURNAL_ERROR;
}

int apd_radio_job_pending_finish_get(const char *ap_id,
                                     struct apd_radio_job_pending_finish *out)
{
    sqlite3_stmt *statement = NULL;
    char sql[640];
    const unsigned char *payload;
    int payload_bytes;
    int result = APD_RADIO_JOB_JOURNAL_ERROR;

    if (!g_apd_db || !uuid_v4_valid(ap_id) || !out)
        return APD_RADIO_JOB_JOURNAL_INVALID;
    memset(out, 0, sizeof(*out));
    if (snprintf(sql, sizeof(sql), "SELECT %s,result_json FROM "
                 "apd_radio_job_journal WHERE ap_id=?1 AND finish_id<>'' AND "
                 "finish_acked=0 ORDER BY updated_at,job_id LIMIT 1",
                 entry_columns) >= (int)sizeof(sql) ||
        sqlite3_prepare_v2(g_apd_db, sql, -1, &statement, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(statement, 1, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(statement) != SQLITE_ROW) {
        result = APD_RADIO_JOB_JOURNAL_NOT_FOUND;
        goto done;
    }
    if (entry_from_statement(statement, &out->entry) != 0)
        goto done;
    payload = sqlite3_column_text(statement, 19);
    payload_bytes = sqlite3_column_bytes(statement, 19);
    if (!payload || payload_bytes < 0 ||
        !(out->result_json = malloc((size_t)payload_bytes + 1U)))
        goto done;
    memcpy(out->result_json, payload, (size_t)payload_bytes);
    out->result_json[payload_bytes] = '\0';
    result = APD_RADIO_JOB_JOURNAL_OK;
done:
    if (result != APD_RADIO_JOB_JOURNAL_OK)
        apd_radio_job_pending_finish_free(out);
    sqlite3_finalize(statement);
    return result;
}

void apd_radio_job_pending_finish_free(
    struct apd_radio_job_pending_finish *pending)
{
    if (!pending)
        return;
    free(pending->result_json);
    memset(pending, 0, sizeof(*pending));
}

int apd_radio_job_pending_reconcile_get(
    const char *ap_id, struct apd_radio_job_pending_reconcile *out)
{
    sqlite3_stmt *statement = NULL;
    char sql[768];
    const unsigned char *payload;
    int payload_bytes;
    int result = APD_RADIO_JOB_JOURNAL_ERROR;

    if (!g_apd_db || !uuid_v4_valid(ap_id) || !out)
        return APD_RADIO_JOB_JOURNAL_INVALID;
    memset(out, 0, sizeof(*out));
    if (snprintf(sql, sizeof(sql), "SELECT %s,result_json FROM "
                 "apd_radio_job_journal WHERE ap_id=?1 AND finish_acked=0 "
                 "AND state IN ('offered','running','cancel_requested',"
                 "'interrupted','completed','failed','cancelled') "
                 "ORDER BY updated_at,job_id LIMIT 1", entry_columns) >=
            (int)sizeof(sql) ||
        sqlite3_prepare_v2(g_apd_db, sql, -1, &statement, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(statement, 1, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(statement) != SQLITE_ROW) {
        result = APD_RADIO_JOB_JOURNAL_NOT_FOUND;
        goto done;
    }
    if (entry_from_statement(statement, &out->entry) != 0)
        goto done;
    payload = sqlite3_column_text(statement, 19);
    payload_bytes = sqlite3_column_bytes(statement, 19);
    if (!payload || payload_bytes < 0 ||
        !(out->result_json = malloc((size_t)payload_bytes + 1U)))
        goto done;
    memcpy(out->result_json, payload, (size_t)payload_bytes);
    out->result_json[payload_bytes] = '\0';
    result = APD_RADIO_JOB_JOURNAL_OK;
done:
    if (result != APD_RADIO_JOB_JOURNAL_OK)
        apd_radio_job_pending_reconcile_free(out);
    sqlite3_finalize(statement);
    return result;
}

void apd_radio_job_pending_reconcile_free(
    struct apd_radio_job_pending_reconcile *pending)
{
    if (!pending)
        return;
    free(pending->result_json);
    memset(pending, 0, sizeof(*pending));
}

int apd_radio_job_finish_ack(const struct apd_radio_job_assignment *assignment,
                             const char *finish_id,
                             int64_t now,
                             struct apd_radio_job_journal_entry *out)
{
    sqlite3_stmt *statement = NULL;
    struct apd_radio_job_journal_entry existing;
    int result = APD_RADIO_JOB_JOURNAL_ERROR;

    if (!assignment_valid(assignment) || !uuid_v4_valid(finish_id) || now <= 0)
        return APD_RADIO_JOB_JOURNAL_INVALID;
    if (journal_tx_begin() != 0)
        return result;
    result = get_entry(assignment->job_id, &existing);
    if (result != APD_RADIO_JOB_JOURNAL_OK)
        goto commit;
    if (!assignment_equal(assignment, &existing.assignment) ||
        strcmp(existing.finish_id, finish_id) != 0) {
        result = APD_RADIO_JOB_JOURNAL_CONFLICT;
        goto commit;
    }
    if (existing.finish_acked) {
        result = APD_RADIO_JOB_JOURNAL_IDEMPOTENT;
        if (out)
            *out = existing;
        goto commit;
    }
    if (sqlite3_prepare_v2(g_apd_db,
            "UPDATE apd_radio_job_journal SET finish_acked=1,"
            "finish_acked_at=?1,updated_at=?1 WHERE job_id=?2 AND finish_id=?3",
            -1, &statement, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_int64(statement, 1, now);
    sqlite3_bind_text(statement, 2, assignment->job_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 3, finish_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(statement) != SQLITE_DONE || sqlite3_changes(g_apd_db) != 1)
        goto rollback;
    sqlite3_finalize(statement);
    statement = NULL;
    result = get_entry(assignment->job_id, &existing);
    if (result != APD_RADIO_JOB_JOURNAL_OK)
        goto rollback;
    if (out)
        *out = existing;
    if (journal_prune_locked(now) < 0)
        goto rollback;
commit:
    sqlite3_finalize(statement);
    if (journal_tx_commit() != 0)
        return APD_RADIO_JOB_JOURNAL_ERROR;
    return result;
rollback:
    sqlite3_finalize(statement);
    journal_tx_rollback();
    return APD_RADIO_JOB_JOURNAL_ERROR;
}

int apd_radio_job_restart_recover(int64_t now, int *interrupted_count)
{
    sqlite3_stmt *statement = NULL;
    int changed;

    if (now <= 0)
        return APD_RADIO_JOB_JOURNAL_INVALID;
    if (journal_tx_begin() != 0)
        return APD_RADIO_JOB_JOURNAL_ERROR;
    if (sqlite3_prepare_v2(g_apd_db,
            "UPDATE apd_radio_job_journal SET state='interrupted',"
            "outcome='failed',error_code='apd_restarted_during_execution',"
            "observed_at=?1,result_json='[]',result_count=0,result_bytes=2,"
            "result_complete=0,finish_id=substr(job_id,1,35)||CASE "
            "substr(job_id,36,1) "
            "WHEN '0' THEN '8' WHEN '1' THEN '9' WHEN '2' THEN 'a' "
            "WHEN '3' THEN 'b' WHEN '4' THEN 'c' WHEN '5' THEN 'd' "
            "WHEN '6' THEN 'e' WHEN '7' THEN 'f' WHEN '8' THEN '0' "
            "WHEN '9' THEN '1' WHEN 'a' THEN '2' WHEN 'b' THEN '3' "
            "WHEN 'c' THEN '4' WHEN 'd' THEN '5' WHEN 'e' THEN '6' "
            "WHEN 'f' THEN '7' END,finish_acked=0,finish_acked_at=0,"
            "updated_at=?1 WHERE state IN ('running','cancel_requested')",
            -1, &statement, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_int64(statement, 1, now);
    if (sqlite3_step(statement) != SQLITE_DONE)
        goto rollback;
    changed = sqlite3_changes(g_apd_db);
    sqlite3_finalize(statement);
    statement = NULL;
    if (journal_tx_commit() != 0)
        return APD_RADIO_JOB_JOURNAL_ERROR;
    if (interrupted_count)
        *interrupted_count = changed;
    return APD_RADIO_JOB_JOURNAL_OK;
rollback:
    sqlite3_finalize(statement);
    journal_tx_rollback();
    return APD_RADIO_JOB_JOURNAL_ERROR;
}

int apd_radio_job_journal_get(const char *job_id,
                              struct apd_radio_job_journal_entry *out)
{
    if (!uuid_v4_valid(job_id))
        return APD_RADIO_JOB_JOURNAL_INVALID;
    return get_entry(job_id, out);
}

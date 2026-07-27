// SPDX-License-Identifier: GPL-2.0-or-later
#include "apd_config_job_journal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sqlite3.h>

extern sqlite3 *g_apd_db;

static const char apd_config_job_schema[] =
    "CREATE TABLE IF NOT EXISTS apd_config_job_journal ("
    "job_id TEXT PRIMARY KEY,"
    "attempt_id TEXT NOT NULL UNIQUE,"
    "dispatch_generation INTEGER NOT NULL CHECK(dispatch_generation>0),"
    "request_digest TEXT NOT NULL,"
    "candidate_digest TEXT NOT NULL,"
    "ap_id TEXT NOT NULL,"
    "session_epoch TEXT NOT NULL,"
    "state TEXT NOT NULL CHECK(state IN "
    "('offered','staged','applying','applied',"
    "'completed','failed','rolled_back')),"
    "candidate_json TEXT NOT NULL,"
    "previous_json TEXT NOT NULL DEFAULT '',"
    "readback_json TEXT NOT NULL DEFAULT '',"
    "finish_id TEXT NOT NULL DEFAULT '',"
    "outcome TEXT NOT NULL DEFAULT '' "
    "CHECK(outcome IN ('','applied','failed','rolled_back')),"
    "error_code TEXT NOT NULL DEFAULT '',"
    "observed_at INTEGER NOT NULL DEFAULT 0,"
    "finish_acked INTEGER NOT NULL DEFAULT 0 CHECK(finish_acked IN (0,1)),"
    "finish_acked_at INTEGER NOT NULL DEFAULT 0,"
    "created_at INTEGER NOT NULL,"
    "updated_at INTEGER NOT NULL);"
    "CREATE INDEX IF NOT EXISTS idx_apd_config_job_recovery "
    "ON apd_config_job_journal(state,updated_at);"
    "CREATE INDEX IF NOT EXISTS idx_apd_config_job_pending "
    "ON apd_config_job_journal(ap_id,finish_acked,updated_at) "
    "WHERE finish_id<>'';";

static int config_tx_begin(void)
{
    return g_apd_db && sqlite3_exec(g_apd_db, "BEGIN IMMEDIATE", NULL, NULL,
                                    NULL) == SQLITE_OK ? 0 : -1;
}

static int config_tx_commit(void)
{
    return g_apd_db && sqlite3_exec(g_apd_db, "COMMIT", NULL, NULL,
                                    NULL) == SQLITE_OK ? 0 : -1;
}

static void config_tx_rollback(void)
{
    if (g_apd_db)
        sqlite3_exec(g_apd_db, "ROLLBACK", NULL, NULL, NULL);
}

static int config_uuid_valid(const char *value)
{
    size_t i;

    if (!value || strlen(value) != APD_CONFIG_JOB_UUID_LEN)
        return 0;
    for (i = 0; i < APD_CONFIG_JOB_UUID_LEN; i++) {
        char c = value[i];

        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-')
                return 0;
        } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return 0;
    }
    return 1;
}

static int config_epoch_valid(const char *value)
{
    size_t i;

    if (!value || strlen(value) != APD_CONFIG_JOB_SESSION_EPOCH_LEN)
        return 0;
    for (i = 0; i < APD_CONFIG_JOB_SESSION_EPOCH_LEN; i++) {
        char c = value[i];

        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return 0;
    }
    return 1;
}

static int config_digest_valid(const char *value)
{
    size_t i;

    if (!value || strlen(value) != APD_CONFIG_JOB_DIGEST_LEN ||
        strncmp(value, "sha256:", 7) != 0)
        return 0;
    for (i = 7; value[i]; i++) {
        char c = value[i];

        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return 0;
    }
    return 1;
}

static int config_assignment_valid(
    const struct apd_config_job_assignment *assignment)
{
    return assignment && config_uuid_valid(assignment->job_id) &&
           config_uuid_valid(assignment->attempt_id) &&
           assignment->dispatch_generation > 0 &&
           config_digest_valid(assignment->request_digest) &&
           config_digest_valid(assignment->candidate_digest) &&
           config_uuid_valid(assignment->ap_id) &&
           config_epoch_valid(assignment->session_epoch);
}

static void config_copy(char *out, size_t size, const char *value)
{
    snprintf(out, size, "%s", value ? value : "");
}

/* Column order shared by every SELECT that materializes an entry. */
#define APD_CONFIG_JOB_COLUMNS \
    "job_id,attempt_id,dispatch_generation,request_digest," \
    "candidate_digest,ap_id,session_epoch,state,finish_id,outcome," \
    "error_code,observed_at,finish_acked,created_at,updated_at"

static void config_entry_from_statement(
    sqlite3_stmt *statement, struct apd_config_job_journal_entry *out)
{
    memset(out, 0, sizeof(*out));
    config_copy(out->assignment.job_id, sizeof(out->assignment.job_id),
                (const char *)sqlite3_column_text(statement, 0));
    config_copy(out->assignment.attempt_id,
                sizeof(out->assignment.attempt_id),
                (const char *)sqlite3_column_text(statement, 1));
    out->assignment.dispatch_generation = sqlite3_column_int64(statement, 2);
    config_copy(out->assignment.request_digest,
                sizeof(out->assignment.request_digest),
                (const char *)sqlite3_column_text(statement, 3));
    config_copy(out->assignment.candidate_digest,
                sizeof(out->assignment.candidate_digest),
                (const char *)sqlite3_column_text(statement, 4));
    config_copy(out->assignment.ap_id, sizeof(out->assignment.ap_id),
                (const char *)sqlite3_column_text(statement, 5));
    config_copy(out->assignment.session_epoch,
                sizeof(out->assignment.session_epoch),
                (const char *)sqlite3_column_text(statement, 6));
    config_copy(out->state, sizeof(out->state),
                (const char *)sqlite3_column_text(statement, 7));
    config_copy(out->finish_id, sizeof(out->finish_id),
                (const char *)sqlite3_column_text(statement, 8));
    config_copy(out->outcome, sizeof(out->outcome),
                (const char *)sqlite3_column_text(statement, 9));
    config_copy(out->error_code, sizeof(out->error_code),
                (const char *)sqlite3_column_text(statement, 10));
    out->observed_at = sqlite3_column_int64(statement, 11);
    out->finish_acked = sqlite3_column_int(statement, 12);
    out->created_at = sqlite3_column_int64(statement, 13);
    out->updated_at = sqlite3_column_int64(statement, 14);
}

static int config_entry_load(const char *job_id,
                             struct apd_config_job_journal_entry *out)
{
    sqlite3_stmt *statement = NULL;
    int rc = APD_CONFIG_JOB_JOURNAL_ERROR;

    if (sqlite3_prepare_v2(g_apd_db,
            "SELECT " APD_CONFIG_JOB_COLUMNS
            " FROM apd_config_job_journal WHERE job_id=?1",
            -1, &statement, NULL) != SQLITE_OK)
        return APD_CONFIG_JOB_JOURNAL_ERROR;
    sqlite3_bind_text(statement, 1, job_id, -1, SQLITE_TRANSIENT);
    switch (sqlite3_step(statement)) {
    case SQLITE_ROW:
        if (out)
            config_entry_from_statement(statement, out);
        rc = APD_CONFIG_JOB_JOURNAL_OK;
        break;
    case SQLITE_DONE:
        rc = APD_CONFIG_JOB_JOURNAL_NOT_FOUND;
        break;
    default:
        break;
    }
    sqlite3_finalize(statement);
    return rc;
}

static int config_assignment_matches(
    const struct apd_config_job_journal_entry *entry,
    const struct apd_config_job_assignment *assignment)
{
    return !strcmp(entry->assignment.attempt_id, assignment->attempt_id) &&
           entry->assignment.dispatch_generation ==
               assignment->dispatch_generation &&
           !strcmp(entry->assignment.request_digest,
                   assignment->request_digest) &&
           !strcmp(entry->assignment.candidate_digest,
                   assignment->candidate_digest) &&
           !strcmp(entry->assignment.ap_id, assignment->ap_id);
}

int apd_config_job_journal_init(void)
{
    return g_apd_db && sqlite3_exec(g_apd_db, apd_config_job_schema, NULL,
                                    NULL, NULL) == SQLITE_OK ?
           APD_CONFIG_JOB_JOURNAL_OK : APD_CONFIG_JOB_JOURNAL_ERROR;
}

int apd_config_job_offer_store(
    const struct apd_config_job_assignment *assignment,
    const char *candidate_json, int64_t now,
    struct apd_config_job_journal_entry *out)
{
    struct apd_config_job_journal_entry existing;
    sqlite3_stmt *statement = NULL;
    int rc;

    if (!g_apd_db || !config_assignment_valid(assignment) ||
        !candidate_json || !candidate_json[0] ||
        strlen(candidate_json) > APD_CONFIG_JOB_CANDIDATE_MAX_BYTES ||
        now <= 0)
        return APD_CONFIG_JOB_JOURNAL_INVALID;
    if (config_tx_begin() != 0)
        return APD_CONFIG_JOB_JOURNAL_ERROR;
    rc = config_entry_load(assignment->job_id, &existing);
    if (rc == APD_CONFIG_JOB_JOURNAL_OK) {
        config_tx_rollback();
        if (!config_assignment_matches(&existing, assignment))
            return APD_CONFIG_JOB_JOURNAL_CONFLICT;
        if (out)
            *out = existing;
        return APD_CONFIG_JOB_JOURNAL_IDEMPOTENT;
    }
    if (rc != APD_CONFIG_JOB_JOURNAL_NOT_FOUND) {
        config_tx_rollback();
        return APD_CONFIG_JOB_JOURNAL_ERROR;
    }
    if (sqlite3_prepare_v2(g_apd_db,
            "INSERT INTO apd_config_job_journal(job_id,attempt_id,"
            "dispatch_generation,request_digest,candidate_digest,ap_id,"
            "session_epoch,state,candidate_json,created_at,updated_at) "
            "VALUES(?1,?2,?3,?4,?5,?6,?7,'offered',?8,?9,?9)",
            -1, &statement, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(statement, 1, assignment->job_id, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, assignment->attempt_id, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 3, assignment->dispatch_generation);
    sqlite3_bind_text(statement, 4, assignment->request_digest, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 5, assignment->candidate_digest, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 6, assignment->ap_id, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 7, assignment->session_epoch, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 8, candidate_json, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 9, now);
    if (sqlite3_step(statement) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(statement);
    statement = NULL;
    if (config_entry_load(assignment->job_id, out) !=
        APD_CONFIG_JOB_JOURNAL_OK)
        goto fail;
    if (config_tx_commit() != 0)
        goto fail;
    return APD_CONFIG_JOB_JOURNAL_OK;
fail:
    sqlite3_finalize(statement);
    config_tx_rollback();
    return APD_CONFIG_JOB_JOURNAL_ERROR;
}

/* Shared guarded transition: from_state -> to_state for the exact
 * assignment; already in to_state is idempotent. */
static int config_transition(
    const struct apd_config_job_assignment *assignment,
    const char *from_state, const char *to_state,
    const char *previous_json, int64_t now,
    struct apd_config_job_journal_entry *out)
{
    struct apd_config_job_journal_entry existing;
    sqlite3_stmt *statement = NULL;
    int rc;

    if (!g_apd_db || !config_assignment_valid(assignment) || now <= 0)
        return APD_CONFIG_JOB_JOURNAL_INVALID;
    if (previous_json &&
        (!previous_json[0] ||
         strlen(previous_json) > APD_CONFIG_JOB_PREVIOUS_MAX_BYTES))
        return APD_CONFIG_JOB_JOURNAL_INVALID;
    if (config_tx_begin() != 0)
        return APD_CONFIG_JOB_JOURNAL_ERROR;
    rc = config_entry_load(assignment->job_id, &existing);
    if (rc != APD_CONFIG_JOB_JOURNAL_OK) {
        config_tx_rollback();
        return rc == APD_CONFIG_JOB_JOURNAL_NOT_FOUND ?
               APD_CONFIG_JOB_JOURNAL_NOT_FOUND :
               APD_CONFIG_JOB_JOURNAL_ERROR;
    }
    if (!config_assignment_matches(&existing, assignment)) {
        config_tx_rollback();
        return APD_CONFIG_JOB_JOURNAL_CONFLICT;
    }
    if (!strcmp(existing.state, to_state)) {
        config_tx_rollback();
        if (out)
            *out = existing;
        return APD_CONFIG_JOB_JOURNAL_IDEMPOTENT;
    }
    if (strcmp(existing.state, from_state) != 0) {
        config_tx_rollback();
        return APD_CONFIG_JOB_JOURNAL_CONFLICT;
    }
    if (sqlite3_prepare_v2(g_apd_db,
            previous_json ?
            "UPDATE apd_config_job_journal SET state=?2,updated_at=?3,"
            "previous_json=?4 WHERE job_id=?1" :
            "UPDATE apd_config_job_journal SET state=?2,updated_at=?3 "
            "WHERE job_id=?1",
            -1, &statement, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(statement, 1, assignment->job_id, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, to_state, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 3, now);
    if (previous_json)
        sqlite3_bind_text(statement, 4, previous_json, -1,
                          SQLITE_TRANSIENT);
    if (sqlite3_step(statement) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(statement);
    statement = NULL;
    if (config_entry_load(assignment->job_id, out) !=
        APD_CONFIG_JOB_JOURNAL_OK)
        goto fail;
    if (config_tx_commit() != 0)
        goto fail;
    return APD_CONFIG_JOB_JOURNAL_OK;
fail:
    sqlite3_finalize(statement);
    config_tx_rollback();
    return APD_CONFIG_JOB_JOURNAL_ERROR;
}

int apd_config_job_mark_staged(
    const struct apd_config_job_assignment *assignment, int64_t now,
    struct apd_config_job_journal_entry *out)
{
    return config_transition(assignment, "offered", "staged", NULL, now,
                             out);
}

int apd_config_job_mark_applying(
    const struct apd_config_job_assignment *assignment,
    const char *previous_json, int64_t now,
    struct apd_config_job_journal_entry *out)
{
    if (!previous_json || !previous_json[0])
        return APD_CONFIG_JOB_JOURNAL_INVALID;
    return config_transition(assignment, "staged", "applying",
                             previous_json, now, out);
}

int apd_config_job_mark_applied(
    const struct apd_config_job_assignment *assignment, int64_t now,
    struct apd_config_job_journal_entry *out)
{
    return config_transition(assignment, "applying", "applied", NULL, now,
                             out);
}

int apd_config_job_finish_store(const struct apd_config_job_finish *finish,
                                int64_t now,
                                struct apd_config_job_journal_entry *out)
{
    struct apd_config_job_journal_entry existing;
    sqlite3_stmt *statement = NULL;
    const char *terminal;
    int rc;

    if (!g_apd_db || !finish ||
        !config_assignment_valid(&finish->assignment) ||
        !config_uuid_valid(finish->finish_id) || finish->observed_at <= 0 ||
        now <= 0)
        return APD_CONFIG_JOB_JOURNAL_INVALID;
    if (!strcmp(finish->outcome, "applied"))
        terminal = "completed";
    else if (!strcmp(finish->outcome, "failed"))
        terminal = "failed";
    else if (!strcmp(finish->outcome, "rolled_back"))
        terminal = "rolled_back";
    else
        return APD_CONFIG_JOB_JOURNAL_INVALID;
    if (finish->readback_json &&
        strlen(finish->readback_json) > APD_CONFIG_JOB_READBACK_MAX_BYTES)
        return APD_CONFIG_JOB_JOURNAL_INVALID;
    if (config_tx_begin() != 0)
        return APD_CONFIG_JOB_JOURNAL_ERROR;
    rc = config_entry_load(finish->assignment.job_id, &existing);
    if (rc != APD_CONFIG_JOB_JOURNAL_OK) {
        config_tx_rollback();
        return rc == APD_CONFIG_JOB_JOURNAL_NOT_FOUND ?
               APD_CONFIG_JOB_JOURNAL_NOT_FOUND :
               APD_CONFIG_JOB_JOURNAL_ERROR;
    }
    if (!config_assignment_matches(&existing, &finish->assignment)) {
        config_tx_rollback();
        return APD_CONFIG_JOB_JOURNAL_CONFLICT;
    }
    if (existing.finish_id[0]) {
        config_tx_rollback();
        if (!strcmp(existing.finish_id, finish->finish_id) &&
            !strcmp(existing.outcome, finish->outcome)) {
            if (out)
                *out = existing;
            return APD_CONFIG_JOB_JOURNAL_IDEMPOTENT;
        }
        return APD_CONFIG_JOB_JOURNAL_CONFLICT;
    }
    if (sqlite3_prepare_v2(g_apd_db,
            "UPDATE apd_config_job_journal SET state=?2,finish_id=?3,"
            "outcome=?4,error_code=?5,observed_at=?6,readback_json=?7,"
            "updated_at=?8 WHERE job_id=?1",
            -1, &statement, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(statement, 1, finish->assignment.job_id, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, terminal, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 3, finish->finish_id, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 4, finish->outcome, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 5, finish->error_code, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 6, finish->observed_at);
    sqlite3_bind_text(statement, 7,
                      finish->readback_json ? finish->readback_json : "",
                      -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 8, now);
    if (sqlite3_step(statement) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(statement);
    statement = NULL;
    if (config_entry_load(finish->assignment.job_id, out) !=
        APD_CONFIG_JOB_JOURNAL_OK)
        goto fail;
    if (config_tx_commit() != 0)
        goto fail;
    return APD_CONFIG_JOB_JOURNAL_OK;
fail:
    sqlite3_finalize(statement);
    config_tx_rollback();
    return APD_CONFIG_JOB_JOURNAL_ERROR;
}

int apd_config_job_finish_ack(
    const struct apd_config_job_assignment *assignment,
    const char *finish_id, int64_t now,
    struct apd_config_job_journal_entry *out)
{
    struct apd_config_job_journal_entry existing;
    sqlite3_stmt *statement = NULL;
    int rc;

    if (!g_apd_db || !config_assignment_valid(assignment) ||
        !config_uuid_valid(finish_id) || now <= 0)
        return APD_CONFIG_JOB_JOURNAL_INVALID;
    if (config_tx_begin() != 0)
        return APD_CONFIG_JOB_JOURNAL_ERROR;
    rc = config_entry_load(assignment->job_id, &existing);
    if (rc != APD_CONFIG_JOB_JOURNAL_OK) {
        config_tx_rollback();
        return rc == APD_CONFIG_JOB_JOURNAL_NOT_FOUND ?
               APD_CONFIG_JOB_JOURNAL_NOT_FOUND :
               APD_CONFIG_JOB_JOURNAL_ERROR;
    }
    if (!config_assignment_matches(&existing, assignment) ||
        !existing.finish_id[0] ||
        strcmp(existing.finish_id, finish_id) != 0) {
        config_tx_rollback();
        return APD_CONFIG_JOB_JOURNAL_CONFLICT;
    }
    if (existing.finish_acked) {
        config_tx_rollback();
        if (out)
            *out = existing;
        return APD_CONFIG_JOB_JOURNAL_IDEMPOTENT;
    }
    if (sqlite3_prepare_v2(g_apd_db,
            "UPDATE apd_config_job_journal SET finish_acked=1,"
            "finish_acked_at=?2,updated_at=?2 WHERE job_id=?1",
            -1, &statement, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(statement, 1, assignment->job_id, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 2, now);
    if (sqlite3_step(statement) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(statement);
    statement = NULL;
    if (config_entry_load(assignment->job_id, out) !=
        APD_CONFIG_JOB_JOURNAL_OK)
        goto fail;
    if (config_tx_commit() != 0)
        goto fail;
    return APD_CONFIG_JOB_JOURNAL_OK;
fail:
    sqlite3_finalize(statement);
    config_tx_rollback();
    return APD_CONFIG_JOB_JOURNAL_ERROR;
}

static char *config_column_dup(sqlite3_stmt *statement, int column)
{
    const unsigned char *value = sqlite3_column_text(statement, column);

    return strdup(value ? (const char *)value : "");
}

int apd_config_job_recovery_next(struct apd_config_job_recovery *out)
{
    sqlite3_stmt *statement = NULL;
    int rc = APD_CONFIG_JOB_JOURNAL_ERROR;

    if (!g_apd_db || !out)
        return APD_CONFIG_JOB_JOURNAL_INVALID;
    memset(out, 0, sizeof(*out));
    if (sqlite3_prepare_v2(g_apd_db,
            "SELECT " APD_CONFIG_JOB_COLUMNS ",candidate_json,previous_json"
            " FROM apd_config_job_journal WHERE state IN "
            "('offered','staged','applying','applied') "
            "ORDER BY updated_at,job_id LIMIT 1",
            -1, &statement, NULL) != SQLITE_OK)
        return APD_CONFIG_JOB_JOURNAL_ERROR;
    switch (sqlite3_step(statement)) {
    case SQLITE_ROW:
        config_entry_from_statement(statement, &out->entry);
        out->candidate_json = config_column_dup(statement, 15);
        out->previous_json = config_column_dup(statement, 16);
        rc = out->candidate_json && out->previous_json ?
             APD_CONFIG_JOB_JOURNAL_OK : APD_CONFIG_JOB_JOURNAL_ERROR;
        break;
    case SQLITE_DONE:
        rc = APD_CONFIG_JOB_JOURNAL_NOT_FOUND;
        break;
    default:
        break;
    }
    sqlite3_finalize(statement);
    if (rc != APD_CONFIG_JOB_JOURNAL_OK &&
        rc != APD_CONFIG_JOB_JOURNAL_NOT_FOUND)
        apd_config_job_recovery_free(out);
    return rc;
}

void apd_config_job_recovery_free(struct apd_config_job_recovery *recovery)
{
    if (!recovery)
        return;
    free(recovery->candidate_json);
    free(recovery->previous_json);
    memset(recovery, 0, sizeof(*recovery));
}

int apd_config_job_pending_reconcile_get(
    const char *ap_id, struct apd_config_job_pending_reconcile *out)
{
    sqlite3_stmt *statement = NULL;
    int rc = APD_CONFIG_JOB_JOURNAL_ERROR;

    if (!g_apd_db || !config_uuid_valid(ap_id) || !out)
        return APD_CONFIG_JOB_JOURNAL_INVALID;
    memset(out, 0, sizeof(*out));
    if (sqlite3_prepare_v2(g_apd_db,
            "SELECT " APD_CONFIG_JOB_COLUMNS ",readback_json"
            " FROM apd_config_job_journal WHERE ap_id=?1 AND "
            "finish_acked=0 AND finish_id<>'' "
            "ORDER BY updated_at,job_id LIMIT 1",
            -1, &statement, NULL) != SQLITE_OK)
        return APD_CONFIG_JOB_JOURNAL_ERROR;
    sqlite3_bind_text(statement, 1, ap_id, -1, SQLITE_TRANSIENT);
    switch (sqlite3_step(statement)) {
    case SQLITE_ROW:
        config_entry_from_statement(statement, &out->entry);
        out->readback_json = config_column_dup(statement, 15);
        rc = out->readback_json ? APD_CONFIG_JOB_JOURNAL_OK :
             APD_CONFIG_JOB_JOURNAL_ERROR;
        break;
    case SQLITE_DONE:
        rc = APD_CONFIG_JOB_JOURNAL_NOT_FOUND;
        break;
    default:
        break;
    }
    sqlite3_finalize(statement);
    if (rc != APD_CONFIG_JOB_JOURNAL_OK &&
        rc != APD_CONFIG_JOB_JOURNAL_NOT_FOUND)
        apd_config_job_pending_reconcile_free(out);
    return rc;
}

void apd_config_job_pending_reconcile_free(
    struct apd_config_job_pending_reconcile *pending)
{
    if (!pending)
        return;
    free(pending->readback_json);
    memset(pending, 0, sizeof(*pending));
}

int apd_config_job_session_rebind(
    const struct apd_config_job_assignment *assignment,
    const char *new_session_epoch, int64_t now,
    struct apd_config_job_journal_entry *out)
{
    struct apd_config_job_journal_entry existing;
    sqlite3_stmt *statement = NULL;
    int rc;

    if (!g_apd_db || !config_assignment_valid(assignment) ||
        !config_epoch_valid(new_session_epoch) || now <= 0)
        return APD_CONFIG_JOB_JOURNAL_INVALID;
    if (config_tx_begin() != 0)
        return APD_CONFIG_JOB_JOURNAL_ERROR;
    rc = config_entry_load(assignment->job_id, &existing);
    if (rc != APD_CONFIG_JOB_JOURNAL_OK) {
        config_tx_rollback();
        return rc == APD_CONFIG_JOB_JOURNAL_NOT_FOUND ?
               APD_CONFIG_JOB_JOURNAL_NOT_FOUND :
               APD_CONFIG_JOB_JOURNAL_ERROR;
    }
    if (!config_assignment_matches(&existing, assignment)) {
        config_tx_rollback();
        return APD_CONFIG_JOB_JOURNAL_CONFLICT;
    }
    if (!strcmp(existing.assignment.session_epoch, new_session_epoch)) {
        config_tx_rollback();
        if (out)
            *out = existing;
        return APD_CONFIG_JOB_JOURNAL_IDEMPOTENT;
    }
    if (sqlite3_prepare_v2(g_apd_db,
            "UPDATE apd_config_job_journal SET session_epoch=?2,"
            "updated_at=?3 WHERE job_id=?1",
            -1, &statement, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(statement, 1, assignment->job_id, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, new_session_epoch, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 3, now);
    if (sqlite3_step(statement) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(statement);
    statement = NULL;
    if (config_entry_load(assignment->job_id, out) !=
        APD_CONFIG_JOB_JOURNAL_OK)
        goto fail;
    if (config_tx_commit() != 0)
        goto fail;
    return APD_CONFIG_JOB_JOURNAL_OK;
fail:
    sqlite3_finalize(statement);
    config_tx_rollback();
    return APD_CONFIG_JOB_JOURNAL_ERROR;
}

int apd_config_job_journal_get(const char *job_id,
                               struct apd_config_job_journal_entry *out)
{
    if (!g_apd_db || !config_uuid_valid(job_id))
        return APD_CONFIG_JOB_JOURNAL_INVALID;
    return config_entry_load(job_id, out);
}

int apd_config_job_journal_prune(int64_t now)
{
    sqlite3_stmt *statement = NULL;

    if (!g_apd_db || now <= 0)
        return APD_CONFIG_JOB_JOURNAL_INVALID;
    if (sqlite3_prepare_v2(g_apd_db,
            "DELETE FROM apd_config_job_journal WHERE finish_acked=1 "
            "AND updated_at<?1 AND job_id NOT IN ("
            "SELECT job_id FROM apd_config_job_journal "
            "ORDER BY updated_at DESC,job_id LIMIT ?2)",
            -1, &statement, NULL) != SQLITE_OK)
        return APD_CONFIG_JOB_JOURNAL_ERROR;
    sqlite3_bind_int64(statement, 1, now - APD_CONFIG_JOB_RETENTION_SECONDS);
    sqlite3_bind_int(statement, 2, APD_CONFIG_JOB_RETENTION_MIN);
    if (sqlite3_step(statement) != SQLITE_DONE) {
        sqlite3_finalize(statement);
        return APD_CONFIG_JOB_JOURNAL_ERROR;
    }
    sqlite3_finalize(statement);
    return APD_CONFIG_JOB_JOURNAL_OK;
}

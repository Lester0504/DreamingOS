// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sqlite3.h>

#include "../src/apd/apd_radio_job_journal.h"

sqlite3 *g_apd_db;

#define EXPECT(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "expectation failed at %s:%d: %s\n", \
                __FILE__, __LINE__, #condition); \
        return -1; \
    } \
} while (0)

static const char *const AP_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
static const char *const RECONCILE_AP_ID =
    "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
static const char *const RETENTION_AP_ID =
    "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
static const char *const EPOCH =
    "1111111111111111111111111111111111111111111111111111111111111111";
static const char *const DIGEST =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

static int open_database(const char *path)
{
    if (sqlite3_open_v2(path, &g_apd_db,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
            NULL) != SQLITE_OK)
        return -1;
    sqlite3_busy_timeout(g_apd_db, 3000);
    sqlite3_extended_result_codes(g_apd_db, 1);
    return apd_radio_job_journal_init() == APD_RADIO_JOB_JOURNAL_OK ? 0 : -1;
}

static void close_database(void)
{
    sqlite3_close(g_apd_db);
    g_apd_db = NULL;
}

static struct apd_radio_job_assignment assignment(const char *job_id,
                                                  const char *attempt_id,
                                                  int64_t generation)
{
    struct apd_radio_job_assignment value;

    memset(&value, 0, sizeof(value));
    snprintf(value.job_id, sizeof(value.job_id), "%s", job_id);
    snprintf(value.attempt_id, sizeof(value.attempt_id), "%s", attempt_id);
    value.dispatch_generation = generation;
    snprintf(value.request_digest, sizeof(value.request_digest), "%s", DIGEST);
    snprintf(value.ap_id, sizeof(value.ap_id), "%s", AP_ID);
    snprintf(value.session_epoch, sizeof(value.session_epoch), "%s", EPOCH);
    snprintf(value.radio_id, sizeof(value.radio_id), "phy1");
    snprintf(value.mode, sizeof(value.mode), "neighbor");
    return value;
}

static struct apd_radio_job_assignment assignment_for_ap(
    const char *job_id, const char *attempt_id, int64_t generation,
    const char *ap_id)
{
    struct apd_radio_job_assignment value =
        assignment(job_id, attempt_id, generation);

    snprintf(value.ap_id, sizeof(value.ap_id), "%s", ap_id);
    return value;
}

static struct apd_radio_job_finish finish_for(
    const struct apd_radio_job_assignment *job, const char *finish_id,
    const char *outcome, const char *error_code, const char *result_json,
    int complete)
{
    struct apd_radio_job_finish value;

    memset(&value, 0, sizeof(value));
    value.assignment = *job;
    snprintf(value.finish_id, sizeof(value.finish_id), "%s", finish_id);
    snprintf(value.outcome, sizeof(value.outcome), "%s", outcome);
    snprintf(value.error_code, sizeof(value.error_code), "%s", error_code);
    value.observed_at = 1003;
    value.result_json = result_json;
    value.result_complete = complete;
    return value;
}

static int test_offer_and_running(void)
{
    struct apd_radio_job_assignment job = assignment(
        "10000000-0000-4000-8000-000000000001",
        "20000000-0000-4000-8000-000000000001", 1);
    struct apd_radio_job_assignment changed = job;
    struct apd_radio_job_assignment reused_attempt = assignment(
        "10000000-0000-4000-8000-000000000099",
        "20000000-0000-4000-8000-000000000001", 99);
    struct apd_radio_job_journal_entry entry;

    EXPECT(apd_radio_job_offer_store(&job, 1000, &entry) ==
           APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(strcmp(entry.state, "offered") == 0);
    EXPECT(apd_radio_job_offer_store(&job, 1001, &entry) ==
           APD_RADIO_JOB_JOURNAL_IDEMPOTENT);
    changed.dispatch_generation++;
    EXPECT(apd_radio_job_offer_store(&changed, 1001, &entry) ==
           APD_RADIO_JOB_JOURNAL_CONFLICT);
    EXPECT(apd_radio_job_offer_store(&reused_attempt, 1001, &entry) ==
           APD_RADIO_JOB_JOURNAL_CONFLICT);
    EXPECT(apd_radio_job_mark_running(&job, 1002, &entry) ==
           APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(strcmp(entry.state, "running") == 0);
    EXPECT(apd_radio_job_mark_running(&job, 1003, &entry) ==
           APD_RADIO_JOB_JOURNAL_IDEMPOTENT);
    EXPECT(apd_radio_job_mark_running(&changed, 1003, &entry) ==
           APD_RADIO_JOB_JOURNAL_CONFLICT);
    return 0;
}

static int test_finish_and_ack(void)
{
    struct apd_radio_job_assignment job = assignment(
        "10000000-0000-4000-8000-000000000001",
        "20000000-0000-4000-8000-000000000001", 1);
    struct apd_radio_job_finish finish = finish_for(
        &job, "30000000-0000-4000-8000-000000000001", "completed", "",
        "[{\"bssid\":\"02:00:00:00:00:01\"}]", 1);
    struct apd_radio_job_finish changed = finish;
    struct apd_radio_job_journal_entry entry;
    struct apd_radio_job_pending_finish pending;

    EXPECT(apd_radio_job_finish_store(&finish, 1004, &entry) ==
           APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(strcmp(entry.state, "completed") == 0 && entry.result_count == 1 &&
           entry.result_complete == 1 && entry.finish_acked == 0);
    EXPECT(apd_radio_job_finish_store(&finish, 1005, &entry) ==
           APD_RADIO_JOB_JOURNAL_IDEMPOTENT);
    changed.observed_at++;
    EXPECT(apd_radio_job_finish_store(&changed, 1005, &entry) ==
           APD_RADIO_JOB_JOURNAL_CONFLICT);
    EXPECT(apd_radio_job_pending_finish_get(AP_ID, &pending) ==
           APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(strcmp(pending.entry.finish_id, finish.finish_id) == 0 &&
           strcmp(pending.result_json, finish.result_json) == 0);
    apd_radio_job_pending_finish_free(&pending);
    EXPECT(apd_radio_job_finish_ack(&job, finish.finish_id, 1006, &entry) ==
           APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(entry.finish_acked == 1);
    EXPECT(apd_radio_job_finish_ack(&job, finish.finish_id, 1007, &entry) ==
           APD_RADIO_JOB_JOURNAL_IDEMPOTENT);
    EXPECT(apd_radio_job_pending_finish_get(AP_ID, &pending) ==
           APD_RADIO_JOB_JOURNAL_NOT_FOUND);
    return 0;
}

static int test_cancel(void)
{
    struct apd_radio_job_assignment job = assignment(
        "10000000-0000-4000-8000-000000000002",
        "20000000-0000-4000-8000-000000000002", 2);
    struct apd_radio_job_finish finish = finish_for(
        &job, "30000000-0000-4000-8000-000000000002", "cancelled",
        "cancelled_by_controller", "[]", 1);
    struct apd_radio_job_journal_entry entry;

    EXPECT(apd_radio_job_offer_store(&job, 1010, &entry) ==
           APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(apd_radio_job_cancel_requested(&job, 1011, &entry) ==
           APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(strcmp(entry.state, "cancel_requested") == 0);
    EXPECT(apd_radio_job_cancel_requested(&job, 1012, &entry) ==
           APD_RADIO_JOB_JOURNAL_IDEMPOTENT);
    EXPECT(apd_radio_job_finish_store(&finish, 1013, &entry) ==
           APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(strcmp(entry.state, "cancelled") == 0);
    return 0;
}

static int test_limits(void)
{
    struct apd_radio_job_assignment item_limit_job = assignment(
        "10000000-0000-4000-8000-000000000003",
        "20000000-0000-4000-8000-000000000003", 3);
    struct apd_radio_job_assignment byte_limit_job = assignment(
        "10000000-0000-4000-8000-000000000004",
        "20000000-0000-4000-8000-000000000004", 4);
    struct apd_radio_job_assignment item_exact_job = assignment(
        "10000000-0000-4000-8000-000000000007",
        "20000000-0000-4000-8000-000000000007", 7);
    struct apd_radio_job_assignment byte_exact_job = assignment(
        "10000000-0000-4000-8000-000000000008",
        "20000000-0000-4000-8000-000000000008", 8);
    struct apd_radio_job_journal_entry entry;
    struct apd_radio_job_finish finish;
    char *items;
    char *bytes;
    size_t offset = 0;
    int i;

    EXPECT(apd_radio_job_offer_store(&item_limit_job, 1020, NULL) ==
           APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(apd_radio_job_mark_running(&item_limit_job, 1021, NULL) ==
           APD_RADIO_JOB_JOURNAL_OK);
    items = calloc(1, 1024);
    EXPECT(items != NULL);
    items[offset++] = '[';
    for (i = 0; i < 129; i++)
        offset += (size_t)snprintf(items + offset, 1024 - offset,
                                  "%s{}", i ? "," : "");
    items[offset++] = ']';
    items[offset] = '\0';
    finish = finish_for(&item_limit_job,
        "30000000-0000-4000-8000-000000000003", "completed", "", items, 1);
    EXPECT(apd_radio_job_finish_store(&finish, 1022, &entry) ==
           APD_RADIO_JOB_JOURNAL_LIMIT);
    free(items);

    EXPECT(apd_radio_job_offer_store(&byte_limit_job, 1030, NULL) ==
           APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(apd_radio_job_mark_running(&byte_limit_job, 1031, NULL) ==
           APD_RADIO_JOB_JOURNAL_OK);
    bytes = malloc(APD_RADIO_JOB_RESULT_MAX_BYTES + 2U);
    EXPECT(bytes != NULL);
    bytes[0] = '[';
    memset(bytes + 1, ' ', APD_RADIO_JOB_RESULT_MAX_BYTES - 1U);
    bytes[APD_RADIO_JOB_RESULT_MAX_BYTES] = ']';
    bytes[APD_RADIO_JOB_RESULT_MAX_BYTES + 1U] = '\0';
    finish = finish_for(&byte_limit_job,
        "30000000-0000-4000-8000-000000000004", "completed", "", bytes, 1);
    EXPECT(apd_radio_job_finish_store(&finish, 1032, &entry) ==
           APD_RADIO_JOB_JOURNAL_LIMIT);
    free(bytes);

    EXPECT(apd_radio_job_offer_store(&item_exact_job, 1033, NULL) ==
           APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(apd_radio_job_mark_running(&item_exact_job, 1034, NULL) ==
           APD_RADIO_JOB_JOURNAL_OK);
    items = calloc(1, 1024);
    EXPECT(items != NULL);
    offset = 0;
    items[offset++] = '[';
    for (i = 0; i < APD_RADIO_JOB_RESULT_MAX_ITEMS; i++)
        offset += (size_t)snprintf(items + offset, 1024 - offset,
                                  "%s{}", i ? "," : "");
    items[offset++] = ']';
    items[offset] = '\0';
    finish = finish_for(&item_exact_job,
        "30000000-0000-4000-8000-000000000007", "completed", "", items, 1);
    EXPECT(apd_radio_job_finish_store(&finish, 1035, &entry) ==
           APD_RADIO_JOB_JOURNAL_OK && entry.result_count == 128);
    free(items);

    EXPECT(apd_radio_job_offer_store(&byte_exact_job, 1036, NULL) ==
           APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(apd_radio_job_mark_running(&byte_exact_job, 1037, NULL) ==
           APD_RADIO_JOB_JOURNAL_OK);
    bytes = malloc(APD_RADIO_JOB_RESULT_MAX_BYTES + 1U);
    EXPECT(bytes != NULL);
    bytes[0] = '[';
    bytes[1] = '"';
    memset(bytes + 2, 'x', APD_RADIO_JOB_RESULT_MAX_BYTES - 4U);
    bytes[APD_RADIO_JOB_RESULT_MAX_BYTES - 2U] = '"';
    bytes[APD_RADIO_JOB_RESULT_MAX_BYTES - 1U] = ']';
    bytes[APD_RADIO_JOB_RESULT_MAX_BYTES] = '\0';
    finish = finish_for(&byte_exact_job,
        "30000000-0000-4000-8000-000000000008", "completed", "", bytes, 1);
    EXPECT(apd_radio_job_finish_store(&finish, 1038, &entry) ==
           APD_RADIO_JOB_JOURNAL_OK &&
           entry.result_bytes == APD_RADIO_JOB_RESULT_MAX_BYTES);
    free(bytes);
    return 0;
}

static int seed_restart_jobs(void)
{
    struct apd_radio_job_assignment offered = assignment(
        "10000000-0000-4000-8000-000000000005",
        "20000000-0000-4000-8000-000000000005", 5);
    struct apd_radio_job_assignment running = assignment(
        "10000000-0000-4000-8000-000000000006",
        "20000000-0000-4000-8000-000000000006", 6);

    EXPECT(apd_radio_job_offer_store(&offered, 1040, NULL) ==
           APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(apd_radio_job_offer_store(&running, 1041, NULL) ==
           APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(apd_radio_job_mark_running(&running, 1042, NULL) ==
           APD_RADIO_JOB_JOURNAL_OK);
    return 0;
}

static int seed_reconcile_restart_job(void)
{
    struct apd_radio_job_assignment job = assignment_for_ap(
        "10000000-0000-4000-8000-000000000009",
        "20000000-0000-4000-8000-000000000009", 9, RECONCILE_AP_ID);
    struct apd_radio_job_pending_reconcile pending;

    EXPECT(apd_radio_job_offer_store(&job, 1043, NULL) ==
           APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(apd_radio_job_pending_reconcile_get(RECONCILE_AP_ID, &pending) ==
           APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(strcmp(pending.entry.state, "offered") == 0 &&
           strcmp(pending.result_json, "[]") == 0);
    apd_radio_job_pending_reconcile_free(&pending);
    EXPECT(apd_radio_job_mark_running(&job, 1044, NULL) ==
           APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(apd_radio_job_pending_reconcile_get(RECONCILE_AP_ID, &pending) ==
           APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(strcmp(pending.entry.state, "running") == 0);
    apd_radio_job_pending_reconcile_free(&pending);
    EXPECT(apd_radio_job_cancel_requested(&job, 1045, NULL) ==
           APD_RADIO_JOB_JOURNAL_OK);
    {
        struct apd_radio_job_assignment old = job;
        struct apd_radio_job_assignment wrong = job;
        struct apd_radio_job_journal_entry rebound;
        const char *new_epoch =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        wrong.dispatch_generation++;
        EXPECT(apd_radio_job_session_rebind(&wrong, new_epoch, 1046, &rebound) ==
               APD_RADIO_JOB_JOURNAL_CONFLICT);
        EXPECT(apd_radio_job_session_rebind(&old, new_epoch, 1046, &rebound) ==
               APD_RADIO_JOB_JOURNAL_OK);
        EXPECT(strcmp(rebound.assignment.session_epoch, new_epoch) == 0);
        job = rebound.assignment;
        EXPECT(apd_radio_job_session_rebind(&job, new_epoch, 1047, &rebound) ==
               APD_RADIO_JOB_JOURNAL_IDEMPOTENT);
    }
    EXPECT(apd_radio_job_pending_reconcile_get(RECONCILE_AP_ID, &pending) ==
           APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(strcmp(pending.entry.state, "cancel_requested") == 0 &&
           !strcmp(pending.entry.assignment.session_epoch,
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    apd_radio_job_pending_reconcile_free(&pending);
    return 0;
}

static int test_restart_recovery(void)
{
    struct apd_radio_job_journal_entry offered;
    struct apd_radio_job_journal_entry running;
    struct apd_radio_job_journal_entry recovered;
    struct apd_radio_job_journal_entry recovered_again;
    struct apd_radio_job_pending_reconcile reconcile;
    struct apd_radio_job_pending_finish finish;
    struct apd_radio_job_assignment reconcile_job = assignment_for_ap(
        "10000000-0000-4000-8000-000000000009",
        "20000000-0000-4000-8000-000000000009", 9, RECONCILE_AP_ID);
    int interrupted = -1;

    EXPECT(apd_radio_job_restart_recover(1050, &interrupted) ==
           APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(interrupted == 4);
    EXPECT(apd_radio_job_journal_get(
        "10000000-0000-4000-8000-000000000005", &offered) ==
        APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(strcmp(offered.state, "offered") == 0);
    EXPECT(apd_radio_job_journal_get(
        "10000000-0000-4000-8000-000000000006", &running) ==
        APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(strcmp(running.state, "interrupted") == 0 &&
           strcmp(running.outcome, "failed") == 0 &&
           strcmp(running.error_code, "apd_restarted_during_execution") == 0 &&
           running.finish_id[0] != '\0');
    EXPECT(apd_radio_job_journal_get(reconcile_job.job_id, &recovered) ==
           APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(strcmp(recovered.state, "interrupted") == 0 &&
           strcmp(recovered.outcome, "failed") == 0 &&
           strcmp(recovered.error_code,
                  "apd_restarted_during_execution") == 0 &&
           strcmp(recovered.finish_id,
                  "10000000-0000-4000-8000-000000000001") == 0 &&
           recovered.observed_at == 1050 && recovered.result_count == 0 &&
           recovered.result_bytes == 2 && recovered.result_complete == 0 &&
           recovered.finish_acked == 0);
    EXPECT(apd_radio_job_pending_reconcile_get(RECONCILE_AP_ID, &reconcile) ==
           APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(strcmp(reconcile.entry.finish_id, recovered.finish_id) == 0 &&
           strcmp(reconcile.result_json, "[]") == 0);
    apd_radio_job_pending_reconcile_free(&reconcile);
    EXPECT(apd_radio_job_pending_finish_get(RECONCILE_AP_ID, &finish) ==
           APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(strcmp(finish.entry.finish_id, recovered.finish_id) == 0 &&
           strcmp(finish.result_json, "[]") == 0);
    apd_radio_job_pending_finish_free(&finish);
    EXPECT(apd_radio_job_restart_recover(1051, &interrupted) ==
           APD_RADIO_JOB_JOURNAL_OK && interrupted == 0);
    EXPECT(apd_radio_job_journal_get(reconcile_job.job_id, &recovered_again) ==
           APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(strcmp(recovered_again.finish_id, recovered.finish_id) == 0 &&
           recovered_again.observed_at == recovered.observed_at &&
           recovered_again.updated_at == recovered.updated_at);
    EXPECT(apd_radio_job_finish_ack(&reconcile_job, recovered.finish_id, 1052,
                                    &recovered_again) ==
           APD_RADIO_JOB_JOURNAL_CONFLICT);
    reconcile_job = recovered.assignment;
    EXPECT(apd_radio_job_finish_ack(&reconcile_job, recovered.finish_id, 1052,
                                    &recovered_again) ==
           APD_RADIO_JOB_JOURNAL_OK);
    EXPECT(apd_radio_job_pending_reconcile_get(RECONCILE_AP_ID, &reconcile) ==
           APD_RADIO_JOB_JOURNAL_NOT_FOUND);
    return 0;
}

static int test_retention(void)
{
    sqlite3_stmt *statement = NULL;
    char job_id[APD_RADIO_JOB_UUID_LEN + 1];
    char attempt_id[APD_RADIO_JOB_UUID_LEN + 1];
    int index;

    EXPECT(sqlite3_exec(g_apd_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK);
    EXPECT(sqlite3_prepare_v2(g_apd_db,
        "INSERT INTO apd_radio_job_journal(job_id,attempt_id,dispatch_generation,"
        "request_digest,ap_id,session_epoch,radio_id,mode,state,finish_id,outcome,"
        "result_json,result_count,result_bytes,result_complete,finish_acked,"
        "finish_acked_at,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,"
        "'phy0','neighbor','completed','90000000-0000-4000-8000-000000000001',"
        "'completed','[]',0,2,1,1,?7,?7,?7)",
        -1, &statement, NULL) == SQLITE_OK);
    for (index = 0; index < 140; index++) {
        snprintf(job_id, sizeof(job_id),
                 "80000000-0000-4000-8000-%012d", index);
        snprintf(attempt_id, sizeof(attempt_id),
                 "81000000-0000-4000-8000-%012d", index);
        sqlite3_reset(statement);
        sqlite3_clear_bindings(statement);
        sqlite3_bind_text(statement, 1, job_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, attempt_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(statement, 3, index + 1);
        sqlite3_bind_text(statement, 4, DIGEST, -1, SQLITE_STATIC);
        sqlite3_bind_text(statement, 5, RETENTION_AP_ID, -1, SQLITE_STATIC);
        sqlite3_bind_text(statement, 6, EPOCH, -1, SQLITE_STATIC);
        sqlite3_bind_int64(statement, 7, 1000 + index);
        EXPECT(sqlite3_step(statement) == SQLITE_DONE);
    }
    sqlite3_finalize(statement);
    statement = NULL;
    EXPECT(sqlite3_prepare_v2(g_apd_db,
        "INSERT INTO apd_radio_job_journal(job_id,attempt_id,dispatch_generation,"
        "request_digest,ap_id,session_epoch,radio_id,mode,state,finish_id,outcome,"
        "result_json,result_count,result_bytes,result_complete,finish_acked,"
        "created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,'phy0','neighbor',"
        "?7,?8,?9,'[]',0,2,?10,0,?11,?11)",
        -1, &statement, NULL) == SQLITE_OK);
    for (index = 0; index < 2; index++) {
        sqlite3_reset(statement);
        sqlite3_clear_bindings(statement);
        sqlite3_bind_text(statement, 1,
            index ? "82000000-0000-4000-8000-000000000002" :
                    "82000000-0000-4000-8000-000000000001", -1, SQLITE_STATIC);
        sqlite3_bind_text(statement, 2,
            index ? "83000000-0000-4000-8000-000000000002" :
                    "83000000-0000-4000-8000-000000000001", -1, SQLITE_STATIC);
        sqlite3_bind_int(statement, 3, 201 + index);
        sqlite3_bind_text(statement, 4, DIGEST, -1, SQLITE_STATIC);
        sqlite3_bind_text(statement, 5, RETENTION_AP_ID, -1, SQLITE_STATIC);
        sqlite3_bind_text(statement, 6, EPOCH, -1, SQLITE_STATIC);
        sqlite3_bind_text(statement, 7, index ? "running" : "completed", -1,
                          SQLITE_STATIC);
        sqlite3_bind_text(statement, 8,
            index ? "" : "84000000-0000-4000-8000-000000000001", -1,
            SQLITE_STATIC);
        sqlite3_bind_text(statement, 9, index ? "" : "completed", -1,
                          SQLITE_STATIC);
        sqlite3_bind_int(statement, 10, index ? 0 : 1);
        sqlite3_bind_int64(statement, 11, 90 + index);
        EXPECT(sqlite3_step(statement) == SQLITE_DONE);
    }
    sqlite3_finalize(statement);
    statement = NULL;
    EXPECT(sqlite3_exec(g_apd_db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK);

    EXPECT(apd_radio_job_journal_prune(200000) == 12);
    EXPECT(sqlite3_prepare_v2(g_apd_db,
        "SELECT COUNT(*) FROM apd_radio_job_journal WHERE ap_id=?1",
        -1, &statement, NULL) == SQLITE_OK);
    sqlite3_bind_text(statement, 1, RETENTION_AP_ID, -1, SQLITE_STATIC);
    EXPECT(sqlite3_step(statement) == SQLITE_ROW &&
           sqlite3_column_int(statement, 0) == 130);
    sqlite3_finalize(statement);
    statement = NULL;
    EXPECT(apd_radio_job_journal_prune(200000) == 0);
    EXPECT(sqlite3_prepare_v2(g_apd_db,
        "SELECT COUNT(*) FROM apd_radio_job_journal WHERE ap_id=?1 "
        "AND ((finish_acked=0 AND state='completed') OR state='running')",
        -1, &statement, NULL) == SQLITE_OK);
    sqlite3_bind_text(statement, 1, RETENTION_AP_ID, -1, SQLITE_STATIC);
    EXPECT(sqlite3_step(statement) == SQLITE_ROW &&
           sqlite3_column_int(statement, 0) == 2);
    sqlite3_finalize(statement);
    return 0;
}

static int selftest(const char *path)
{
    if (open_database(path) != 0)
        return -1;
    if (test_offer_and_running() != 0 || test_finish_and_ack() != 0 ||
        test_cancel() != 0 || test_limits() != 0 ||
        seed_restart_jobs() != 0 || seed_reconcile_restart_job() != 0) {
        close_database();
        return -1;
    }
    close_database();
    if (open_database(path) != 0)
        return -1;
    if (test_restart_recovery() != 0 || test_retention() != 0) {
        close_database();
        return -1;
    }
    close_database();
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    if (selftest(argv[1]) != 0)
        return 1;
    puts("journal=ok idempotency=ok conflict=ok restart=ok reconcile=ok finish_ack=ok limits=ok");
    return 0;
}

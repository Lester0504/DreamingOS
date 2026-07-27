// SPDX-License-Identifier: GPL-2.0-or-later
/* Runtime contract for the W2b config job journal: durable state machine
 * (offered -> staged -> applying[previous durable] -> applied ->
 * terminal), idempotent replays, finish ack, restart recovery surface,
 * reconcile queue, session rebind and pruning. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sqlite3.h>

#include "../src/apd/apd_config_job_journal.h"

sqlite3 *g_apd_db = NULL;

#define AP_ID "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
#define EPOCH_A \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define EPOCH_B \
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define DIGEST \
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define JOB_1 "11111111-1111-4111-8111-111111111111"
#define JOB_2 "22222222-2222-4222-8222-222222222222"
#define ATTEMPT_1 "33333333-3333-4333-8333-333333333333"
#define ATTEMPT_2 "44444444-4444-4444-8444-444444444444"
#define FINISH_1 "55555555-5555-4555-8555-555555555555"
#define FINISH_2 "66666666-6666-4666-8666-666666666666"

static struct apd_config_job_assignment assignment_new(const char *job,
                                                       const char *attempt)
{
    struct apd_config_job_assignment assignment;

    memset(&assignment, 0, sizeof(assignment));
    snprintf(assignment.job_id, sizeof(assignment.job_id), "%s", job);
    snprintf(assignment.attempt_id, sizeof(assignment.attempt_id), "%s",
             attempt);
    assignment.dispatch_generation = 1;
    snprintf(assignment.request_digest, sizeof(assignment.request_digest),
             "%s", DIGEST);
    snprintf(assignment.candidate_digest,
             sizeof(assignment.candidate_digest), "%s", DIGEST);
    snprintf(assignment.ap_id, sizeof(assignment.ap_id), "%s", AP_ID);
    snprintf(assignment.session_epoch, sizeof(assignment.session_epoch),
             "%s", EPOCH_A);
    return assignment;
}

#define CHECK(label, expr) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "FAIL %s\n", label); \
            return 1; \
        } \
    } while (0)

int main(int argc, char **argv)
{
    struct apd_config_job_assignment job1 = assignment_new(JOB_1, ATTEMPT_1);
    struct apd_config_job_assignment job2 = assignment_new(JOB_2, ATTEMPT_2);
    struct apd_config_job_journal_entry entry;
    struct apd_config_job_finish finish;
    struct apd_config_job_recovery recovery;
    struct apd_config_job_pending_reconcile pending;
    char path[512];

    if (argc != 2) {
        fprintf(stderr, "usage: fixture <tempdir>\n");
        return 2;
    }
    snprintf(path, sizeof(path), "%s/apd.db", argv[1]);
    CHECK("open", sqlite3_open(path, &g_apd_db) == SQLITE_OK);
    CHECK("init", apd_config_job_journal_init() ==
                  APD_CONFIG_JOB_JOURNAL_OK);

    /* Offer: durable, idempotent on exact replay, conflict on drift. */
    CHECK("offer", apd_config_job_offer_store(&job1, "{\"c\":1}", 1000,
                                              &entry) ==
                   APD_CONFIG_JOB_JOURNAL_OK);
    CHECK("offer state", !strcmp(entry.state, "offered"));
    CHECK("offer replay", apd_config_job_offer_store(&job1, "{\"c\":1}",
                                                     1001, &entry) ==
                          APD_CONFIG_JOB_JOURNAL_IDEMPOTENT);
    {
        struct apd_config_job_assignment drift = job1;

        snprintf(drift.attempt_id, sizeof(drift.attempt_id), "%s",
                 ATTEMPT_2);
        CHECK("offer drift", apd_config_job_offer_store(&drift, "{}",
                                                        1002, NULL) ==
                             APD_CONFIG_JOB_JOURNAL_CONFLICT);
    }

    /* State machine order is enforced; previous_json is mandatory for
     * applying (the durable rollback reference). */
    CHECK("skip to applying", apd_config_job_mark_applying(&job1,
              "{\"p\":1}", 1003, NULL) == APD_CONFIG_JOB_JOURNAL_CONFLICT);
    CHECK("staged", apd_config_job_mark_staged(&job1, 1004, &entry) ==
                    APD_CONFIG_JOB_JOURNAL_OK);
    CHECK("staged state", !strcmp(entry.state, "staged"));
    CHECK("applying no previous", apd_config_job_mark_applying(&job1, "",
              1005, NULL) == APD_CONFIG_JOB_JOURNAL_INVALID);
    CHECK("applying", apd_config_job_mark_applying(&job1, "{\"p\":1}",
              1006, &entry) == APD_CONFIG_JOB_JOURNAL_OK);
    CHECK("applying state", !strcmp(entry.state, "applying"));
    CHECK("applying replay", apd_config_job_mark_applying(&job1,
              "{\"p\":1}", 1007, &entry) ==
          APD_CONFIG_JOB_JOURNAL_IDEMPOTENT);
    CHECK("applied", apd_config_job_mark_applied(&job1, 1008, &entry) ==
                     APD_CONFIG_JOB_JOURNAL_OK);

    /* Restart recovery surfaces the non-terminal row with its durable
     * candidate and rollback reference. */
    CHECK("recovery", apd_config_job_recovery_next(&recovery) ==
                      APD_CONFIG_JOB_JOURNAL_OK);
    CHECK("recovery job", !strcmp(recovery.entry.assignment.job_id, JOB_1));
    CHECK("recovery state", !strcmp(recovery.entry.state, "applied"));
    CHECK("recovery previous", !strcmp(recovery.previous_json,
                                       "{\"p\":1}"));
    CHECK("recovery candidate", !strcmp(recovery.candidate_json,
                                        "{\"c\":1}"));
    apd_config_job_recovery_free(&recovery);

    /* Finish: terminal state by outcome, replay idempotent, conflicting
     * finish rejected, ack idempotent. */
    memset(&finish, 0, sizeof(finish));
    finish.assignment = job1;
    snprintf(finish.finish_id, sizeof(finish.finish_id), "%s", FINISH_1);
    snprintf(finish.outcome, sizeof(finish.outcome), "applied");
    finish.observed_at = 1009;
    finish.readback_json = "{\"match\":true}";
    CHECK("finish", apd_config_job_finish_store(&finish, 1010, &entry) ==
                    APD_CONFIG_JOB_JOURNAL_OK);
    CHECK("finish state", !strcmp(entry.state, "completed"));
    CHECK("finish replay", apd_config_job_finish_store(&finish, 1011,
              &entry) == APD_CONFIG_JOB_JOURNAL_IDEMPOTENT);
    snprintf(finish.finish_id, sizeof(finish.finish_id), "%s", FINISH_2);
    CHECK("finish drift", apd_config_job_finish_store(&finish, 1012,
              NULL) == APD_CONFIG_JOB_JOURNAL_CONFLICT);

    /* Reconcile queue holds the unacked finish, then drains on ack. */
    CHECK("pending", apd_config_job_pending_reconcile_get(AP_ID,
              &pending) == APD_CONFIG_JOB_JOURNAL_OK);
    CHECK("pending readback", !strcmp(pending.readback_json,
                                      "{\"match\":true}"));
    apd_config_job_pending_reconcile_free(&pending);
    CHECK("ack wrong id", apd_config_job_finish_ack(&job1, FINISH_2, 1013,
              NULL) == APD_CONFIG_JOB_JOURNAL_CONFLICT);
    CHECK("ack", apd_config_job_finish_ack(&job1, FINISH_1, 1014,
              &entry) == APD_CONFIG_JOB_JOURNAL_OK);
    CHECK("ack replay", apd_config_job_finish_ack(&job1, FINISH_1, 1015,
              &entry) == APD_CONFIG_JOB_JOURNAL_IDEMPOTENT);
    CHECK("pending drained", apd_config_job_pending_reconcile_get(AP_ID,
              &pending) == APD_CONFIG_JOB_JOURNAL_NOT_FOUND);
    CHECK("recovery drained", apd_config_job_recovery_next(&recovery) ==
                              APD_CONFIG_JOB_JOURNAL_NOT_FOUND);

    /* Session rebind for a job surviving an epoch change. */
    CHECK("offer 2", apd_config_job_offer_store(&job2, "{\"c\":2}", 2000,
                                                &entry) ==
                     APD_CONFIG_JOB_JOURNAL_OK);
    CHECK("rebind", apd_config_job_session_rebind(&job2, EPOCH_B, 2001,
              &entry) == APD_CONFIG_JOB_JOURNAL_OK);
    CHECK("rebind epoch", !strcmp(entry.assignment.session_epoch,
                                  EPOCH_B));
    job2 = entry.assignment;
    CHECK("rebind replay", apd_config_job_session_rebind(&job2, EPOCH_B,
              2002, &entry) == APD_CONFIG_JOB_JOURNAL_IDEMPOTENT);

    /* Interrupted job resolves through finish(rolled_back). */
    CHECK("staged 2", apd_config_job_mark_staged(&job2, 2003, NULL) ==
                      APD_CONFIG_JOB_JOURNAL_OK);
    CHECK("applying 2", apd_config_job_mark_applying(&job2, "{\"p\":2}",
              2004, NULL) == APD_CONFIG_JOB_JOURNAL_OK);
    CHECK("recovery 2", apd_config_job_recovery_next(&recovery) ==
                        APD_CONFIG_JOB_JOURNAL_OK);
    CHECK("recovery 2 state", !strcmp(recovery.entry.state, "applying"));
    apd_config_job_recovery_free(&recovery);
    memset(&finish, 0, sizeof(finish));
    finish.assignment = job2;
    snprintf(finish.finish_id, sizeof(finish.finish_id), "%s", FINISH_2);
    snprintf(finish.outcome, sizeof(finish.outcome), "rolled_back");
    snprintf(finish.error_code, sizeof(finish.error_code),
             "interrupted_apply");
    finish.observed_at = 2005;
    CHECK("finish 2", apd_config_job_finish_store(&finish, 2006, &entry) ==
                      APD_CONFIG_JOB_JOURNAL_OK);
    CHECK("finish 2 state", !strcmp(entry.state, "rolled_back"));
    CHECK("ack 2", apd_config_job_finish_ack(&job2, FINISH_2, 2007,
              NULL) == APD_CONFIG_JOB_JOURNAL_OK);

    /* Prune removes acked history beyond retention but keeps the
     * retention floor. */
    CHECK("prune", apd_config_job_journal_prune(
              2008 + APD_CONFIG_JOB_RETENTION_SECONDS + 1) ==
          APD_CONFIG_JOB_JOURNAL_OK);
    CHECK("floor kept", apd_config_job_journal_get(JOB_1, &entry) ==
                        APD_CONFIG_JOB_JOURNAL_OK);

    sqlite3_close(g_apd_db);
    printf("ok\n");
    return 0;
}

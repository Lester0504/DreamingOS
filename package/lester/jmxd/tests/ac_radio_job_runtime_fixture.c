// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <json-c/json.h>
#include <sqlite3.h>

#define AC_RADIO_JOB_ID_LEN 36
#define AC_ENROLLMENT_ID_LEN 36
#define AC_RADIO_JOB_RADIO_ID_MAX 31
#define AC_RADIO_JOB_IDEMPOTENCY_MAX 128
#define AC_RADIO_JOB_SESSION_EPOCH_MAX 64
#define AC_RADIO_JOB_RESULT_DIGEST_MAX 71
#define AC_RADIO_JOB_ERROR_MAX 127
#define AC_RADIO_JOB_IMPACT_MAX 95
#define AC_RADIO_JOB_LIST_LIMIT 128
#define FIXTURE_SESSION_EPOCH \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

enum ac_radio_job_result {
    AC_RADIO_JOB_ERROR = -1,
    AC_RADIO_JOB_OK = 0,
    AC_RADIO_JOB_IDEMPOTENT = 1,
    AC_RADIO_JOB_NOT_FOUND = 2,
    AC_RADIO_JOB_CONFLICT = 3,
    AC_RADIO_JOB_INVALID_TARGET = 4,
    AC_RADIO_JOB_UNAVAILABLE = 5,
};

struct ac_radio_job {
    char job_id[AC_RADIO_JOB_ID_LEN + 1];
    char ap_id[AC_ENROLLMENT_ID_LEN + 1];
    char radio_id[AC_RADIO_JOB_RADIO_ID_MAX + 1];
    char mode[9];
    char state[17];
    char idempotency_key[AC_RADIO_JOB_IDEMPOTENCY_MAX + 1];
    int64_t created_at;
    int64_t updated_at;
    char lease_owner[AC_ENROLLMENT_ID_LEN + 1];
    int64_t lease_expires_at;
    char session_epoch[AC_RADIO_JOB_SESSION_EPOCH_MAX + 1];
    char attempt_id[AC_RADIO_JOB_ID_LEN + 1];
    int64_t dispatch_generation;
    char request_digest[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1];
    char finish_id[AC_RADIO_JOB_ID_LEN + 1];
    char finish_digest[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1];
    int64_t last_progress_at;
    int64_t reconcile_deadline;
    int result_count;
    int64_t result_bytes;
    char result_digest[AC_RADIO_JOB_RESULT_DIGEST_MAX + 1];
    int result_complete;
    char error_code[AC_RADIO_JOB_ERROR_MAX + 1];
    char expected_impact[AC_RADIO_JOB_IMPACT_MAX + 1];
};

typedef int (*ac_radio_job_visit_fn)(const struct ac_radio_job *job,
                                    void *opaque);

extern sqlite3 *g_ac_db;
int ac_db_init(void);
void ac_db_close(void);
int ac_db_radio_job_create(const char *, const char *, const char *, const char *,
                           struct ac_radio_job *);
int ac_db_radio_job_status(const char *, struct ac_radio_job *);
int ac_db_radio_job_list(const char *, ac_radio_job_visit_fn, void *, int *);
int ac_db_radio_jobs_prune(int64_t);
int ac_db_radio_job_cancel(const char *, struct ac_radio_job *);
int ac_db_radio_job_result_metadata(const char *, struct ac_radio_job *);
int ac_db_radio_job_lease_next(const char *, const char *, int64_t,
                               struct ac_radio_job *);
int ac_db_radio_job_mark_running(const char *, const char *, int64_t,
                                 const char *, const char *, const char *,
                                 struct ac_radio_job *);
int ac_db_radio_job_reconcile(const char *, const char *, int64_t,
                              const char *, const char *, const char *,
                              const char *, int64_t, struct ac_radio_job *);
int ac_db_radio_job_finish(const char *, const char *, int64_t, const char *,
                           const char *, const char *, const char *, const char *,
                           const char *, const char *, int,
                           struct ac_radio_job *);
int ac_db_radio_jobs_reconcile_expired(int64_t);
int ac_db_radio_job_result_payload(const char *, char **);
struct json_object *ac_db_radio_job_latest_results_json(void);

static void print_job(const struct ac_radio_job *job)
{
    printf("job_id=%s ap_id=%s radio_id=%s mode=%s state=%s key=%s "
           "attempt_id=%s generation=%lld request_digest=%s finish_id=%s "
           "last_progress_at=%lld reconcile_deadline=%lld result_count=%d "
           "result_bytes=%lld result_complete=%d error=%s impact=%s\n",
           job->job_id, job->ap_id, job->radio_id, job->mode, job->state,
           job->idempotency_key, job->attempt_id,
           (long long)job->dispatch_generation, job->request_digest,
           job->finish_id, (long long)job->last_progress_at,
           (long long)job->reconcile_deadline, job->result_count,
           (long long)job->result_bytes,
           job->result_complete, job->error_code, job->expected_impact);
}

static int set_session(const char *ap_id, const char *session_epoch)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_ap_runtime(ap_id,boot_id,observed_at,received_at," 
            "snapshot_id,runtime_json,stale,telemetry_sequence,"
            "control_protocol_version,session_connected) "
            "VALUES(?1,?2,1,1,'fixture','{}',0,0,2,1) "
            "ON CONFLICT(ap_id) DO UPDATE SET boot_id=excluded.boot_id," 
            "observed_at=1,received_at=1,stale=0,"
            "control_protocol_version=2,session_connected=1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, session_epoch, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE)
        rc = 0;
    sqlite3_finalize(st);
    if (rc == 0) {
        sqlite3_stmt *touch = NULL;

        if (sqlite3_prepare_v2(g_ac_db,
                "UPDATE ac_aps SET last_seen_at=?1 WHERE ap_id=?2",
                -1, &touch, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_int64(touch, 1, time(NULL));
        sqlite3_bind_text(touch, 2, ap_id, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(touch) == SQLITE_DONE ? 0 : -1;
        sqlite3_finalize(touch);
    }
    return rc;
}

static int list_job(const struct ac_radio_job *job, void *opaque)
{
    int *count = opaque;
    (*count)++;
    print_job(job);
    return 0;
}

static int seed_target(const char *ap_id, const char *radio_id)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (sqlite3_exec(g_ac_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_aps(ap_id,site_id,adoption_state,last_seen_at) "
            "VALUES(?1,'default','adopted',?2) ON CONFLICT(ap_id) DO UPDATE SET "
            "adoption_state='adopted',last_seen_at=excluded.last_seen_at", -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, time(NULL));
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_ap_runtime(ap_id,boot_id,observed_at,received_at,"
            "snapshot_id,runtime_json,stale,telemetry_sequence,"
            "control_protocol_version,session_connected) "
            "VALUES(?1,?2,1,1,'fixture','{}',0,0,2,1) "
            "ON CONFLICT(ap_id) DO UPDATE SET boot_id=excluded.boot_id,"
            "control_protocol_version=2,session_connected=1",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, FIXTURE_SESSION_EPOCH, -1, SQLITE_STATIC);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(g_ac_db,
            "INSERT INTO ac_radio_runtime(radio_id,ap_id,observed_at,runtime_json,stale) "
            "VALUES(?1,?2,1,'{}',0) ON CONFLICT(ap_id,radio_id) DO UPDATE SET "
            "observed_at=1,stale=0", -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, radio_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_exec(g_ac_db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK)
        return 0;
done:
    sqlite3_finalize(st);
    sqlite3_exec(g_ac_db, "ROLLBACK", NULL, NULL, NULL);
    return rc;
}

static int set_state(const char *job_id, const char *state, const char *error,
                     int complete)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (sqlite3_prepare_v2(g_ac_db,
            "UPDATE ac_radio_jobs SET state=?1,lease_owner='fixture-owner',"
            "lease_expires_at=9999999999,session_epoch=?2,result_count=7,"
            "attempt_id='30000000-0000-4000-8000-000000000001',"
            "dispatch_generation=1,"
            "request_digest='sha256:0000000000000000000000000000000000000000000000000000000000000000',"
            "last_progress_at=1,reconcile_deadline=9999999999,"
            "result_bytes=1234,result_digest='sha256:fixture',result_complete=?3,"
            "error_code=?4 WHERE job_id=?5", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, state, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 3, complete);
    sqlite3_bind_text(st, 4, error, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, job_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_ac_db) == 1)
        rc = 0;
    sqlite3_finalize(st);
    return rc;
}

int main(int argc, char **argv)
{
    struct ac_radio_job job;
    const char *command;
    int count = 0;
    int result;
    int rc = 1;

    if (argc < 2 || ac_db_init() != 0)
        return 2;
    command = argv[1];
    if (!strcmp(command, "init")) {
        rc = 0;
    } else if (!strcmp(command, "seed") && argc == 4) {
        rc = seed_target(argv[2], argv[3]) == 0 ? 0 : 1;
    } else if (!strcmp(command, "create") && argc == 6) {
        result = ac_db_radio_job_create(argv[2], argv[3], argv[4], argv[5], &job);
        printf("result=%d ", result);
        if (result == AC_RADIO_JOB_OK || result == AC_RADIO_JOB_IDEMPOTENT ||
            result == AC_RADIO_JOB_CONFLICT)
            print_job(&job);
        else
            printf("\n");
        rc = result == AC_RADIO_JOB_ERROR ? 1 : 0;
    } else if (!strcmp(command, "status") && argc == 3) {
        result = ac_db_radio_job_status(argv[2], &job);
        printf("result=%d ", result);
        if (result == AC_RADIO_JOB_OK)
            print_job(&job);
        else
            printf("\n");
        rc = result == AC_RADIO_JOB_OK ? 0 : 1;
    } else if (!strcmp(command, "list") && argc == 3) {
        int limited = 0;
        result = ac_db_radio_job_list(argv[2], list_job, &count, &limited);
        printf("result=%d count=%d limited=%d limit=%d\n", result, count,
               limited, AC_RADIO_JOB_LIST_LIMIT);
        rc = result >= 0 ? 0 : 1;
    } else if (!strcmp(command, "prune") && argc == 3) {
        result = ac_db_radio_jobs_prune(atoll(argv[2]));
        printf("result=%d\n", result);
        rc = result < 0 ? 1 : 0;
    } else if (!strcmp(command, "cancel") && argc == 3) {
        result = ac_db_radio_job_cancel(argv[2], &job);
        printf("result=%d ", result);
        if (result == AC_RADIO_JOB_OK)
            print_job(&job);
        else
            printf("\n");
        rc = result == AC_RADIO_JOB_OK ? 0 : 1;
    } else if (!strcmp(command, "result") && argc == 3) {
        result = ac_db_radio_job_result_metadata(argv[2], &job);
        printf("result=%d ", result);
        if (result == AC_RADIO_JOB_OK)
            print_job(&job);
        else
            printf("\n");
        rc = result == AC_RADIO_JOB_OK ? 0 : 1;
    } else if (!strcmp(command, "lease") && argc == 5) {
        result = ac_db_radio_job_lease_next(argv[2], argv[3], atoll(argv[4]), &job);
        printf("result=%d ", result);
        if (result == AC_RADIO_JOB_OK)
            print_job(&job);
        else
            printf("\n");
        rc = result == AC_RADIO_JOB_OK || result == AC_RADIO_JOB_NOT_FOUND ? 0 : 1;
    } else if (!strcmp(command, "expire") && argc == 3) {
        result = ac_db_radio_jobs_reconcile_expired(atoll(argv[2]));
        printf("result=%d\n", result);
        rc = result < 0 ? 1 : 0;
    } else if (!strcmp(command, "payload") && argc == 3) {
        char *payload = NULL;
        result = ac_db_radio_job_result_payload(argv[2], &payload);
        printf("result=%d payload=%s\n", result, payload ? payload : "null");
        free(payload);
        rc = result == AC_RADIO_JOB_OK ? 0 : 1;
    } else if (!strcmp(command, "latest") && argc == 2) {
        struct json_object *latest = ac_db_radio_job_latest_results_json();

        if (latest) {
            puts(json_object_to_json_string_ext(latest, JSON_C_TO_STRING_PLAIN));
            json_object_put(latest);
            rc = 0;
        }
    } else if (!strcmp(command, "lifecycle") && argc == 7) {
        char *payload = NULL;
        struct ac_radio_job next;
        const char *ap_id = argv[2];
        const char *epoch = argv[3];
        const char *other_epoch = argv[4];
        const char *first_job = argv[5];
        const char *second_job = argv[6];
        const char *finish_id = "40000000-0000-4000-8000-000000000001";
        int64_t now = time(NULL);

        rc = set_session(ap_id, epoch) == 0 &&
             ac_db_radio_job_lease_next(ap_id, epoch, now, &job) == AC_RADIO_JOB_OK &&
             strcmp(job.job_id, first_job) == 0 && !strcmp(job.state, "leased") &&
             ac_db_radio_job_mark_running(first_job, job.attempt_id,
                 job.dispatch_generation, job.request_digest, ap_id, other_epoch,
                 &next) ==
                 AC_RADIO_JOB_CONFLICT &&
             ac_db_radio_job_mark_running(first_job, job.attempt_id,
                 job.dispatch_generation, job.request_digest, ap_id, epoch,
                 &job) ==
                 AC_RADIO_JOB_OK && !strcmp(job.state, "running") &&
             ac_db_radio_job_mark_running(first_job, job.attempt_id,
                 job.dispatch_generation, job.request_digest, ap_id, epoch,
                 &next) == AC_RADIO_JOB_IDEMPOTENT &&
             ac_db_radio_job_finish(first_job, job.attempt_id,
                 job.dispatch_generation, job.request_digest, ap_id, other_epoch,
                 finish_id, "completed", "", "[]", 0, &next) == AC_RADIO_JOB_CONFLICT &&
             ac_db_radio_job_finish(first_job, job.attempt_id,
                 job.dispatch_generation, job.request_digest, ap_id, epoch,
                 finish_id, "completed", "",
                 "[{\"bssid\":\"02:00:00:00:00:01\"}]", 0, &job) ==
                 AC_RADIO_JOB_OK &&
             !strcmp(job.state, "completed") && job.result_complete == 1 &&
             ac_db_radio_job_finish(first_job, job.attempt_id,
                 job.dispatch_generation, job.request_digest, ap_id, epoch,
                 finish_id, "completed", "",
                 "[{\"bssid\":\"02:00:00:00:00:01\"}]", 0, &next) ==
                 AC_RADIO_JOB_IDEMPOTENT &&
             ac_db_radio_job_result_payload(first_job, &payload) == AC_RADIO_JOB_OK &&
             payload && strstr(payload, "02:00:00:00:00:01") &&
             ac_db_radio_job_lease_next(ap_id, epoch, now + 1, &next) ==
                 AC_RADIO_JOB_OK && !strcmp(next.job_id, second_job) &&
             !strcmp(next.state, "leased") ? 0 : 1;
        printf("lifecycle=%s first_state=%s next_job=%s payload=%s\n",
               rc == 0 ? "ok" : "failed", job.state, next.job_id,
               payload ? payload : "null");
        free(payload);
    } else if (!strcmp(command, "interrupted-replay") && argc == 7) {
        struct ac_radio_job rebound;
        struct ac_radio_job finished;
        const char *ap_id = argv[2];
        const char *first_epoch = argv[3];
        const char *second_epoch = argv[4];
        const char *third_epoch = argv[5];
        const char *job_id = argv[6];
        const char *finish_id = "40000000-0000-4000-8000-000000000099";
        const char *payload = "[{\"bssid\":\"02:00:00:00:00:99\"}]";
        int64_t now = time(NULL);
        int replay_result = AC_RADIO_JOB_ERROR;
        int changed_result = AC_RADIO_JOB_ERROR;
        int changed_error_result = AC_RADIO_JOB_ERROR;
        int changed_identity_result = AC_RADIO_JOB_ERROR;
        int stale_result = AC_RADIO_JOB_ERROR;

        rc = set_session(ap_id, first_epoch) == 0 &&
             ac_db_radio_job_lease_next(ap_id, first_epoch, now, &job) ==
                 AC_RADIO_JOB_OK && !strcmp(job.job_id, job_id) &&
             ac_db_radio_job_mark_running(job_id, job.attempt_id,
                 job.dispatch_generation, job.request_digest, ap_id,
                 first_epoch, &job) == AC_RADIO_JOB_OK &&
             set_session(ap_id, second_epoch) == 0 &&
             ac_db_radio_job_reconcile(job_id, job.attempt_id,
                 job.dispatch_generation, job.request_digest, ap_id,
                 second_epoch, "running", now + 1, &rebound) ==
                 AC_RADIO_JOB_OK && !strcmp(rebound.state, "running") &&
             !strcmp(rebound.lease_owner, ap_id) &&
             !strcmp(rebound.session_epoch, second_epoch) &&
             ac_db_radio_job_finish(job_id, job.attempt_id,
                 job.dispatch_generation, job.request_digest, ap_id,
                 second_epoch, finish_id, "failed",
                 "apd_restarted_during_execution", payload, 1, &finished) ==
                 AC_RADIO_JOB_OK && !strcmp(finished.state, "failed") &&
             !strcmp(finished.finish_id, finish_id) &&
             set_session(ap_id, third_epoch) == 0 &&
             (stale_result = ac_db_radio_job_finish(job_id, job.attempt_id,
                 job.dispatch_generation, job.request_digest, ap_id,
                 second_epoch, finish_id, "failed",
                 "apd_restarted_during_execution", payload, 1, &rebound)) ==
                 AC_RADIO_JOB_CONFLICT ? 0 : 1;
        if (rc == 0) {
            replay_result = ac_db_radio_job_finish(job_id, job.attempt_id,
                job.dispatch_generation, job.request_digest, ap_id,
                third_epoch, finish_id, "failed",
                "apd_restarted_during_execution", payload, 1, &rebound);
            changed_result = ac_db_radio_job_finish(job_id, job.attempt_id,
                job.dispatch_generation, job.request_digest, ap_id,
                third_epoch, finish_id, "failed",
                "apd_restarted_during_execution", "[]", 1, &rebound);
            changed_error_result = ac_db_radio_job_finish(job_id,
                job.attempt_id, job.dispatch_generation, job.request_digest,
                ap_id, third_epoch, finish_id, "failed",
                "apd_restarted_with_changed_error", payload, 1, &rebound);
            changed_identity_result = ac_db_radio_job_finish(job_id,
                "50000000-0000-4000-8000-000000000099",
                job.dispatch_generation, job.request_digest, ap_id,
                third_epoch, finish_id, "failed",
                "apd_restarted_during_execution", payload, 1, &rebound);
            if (replay_result != AC_RADIO_JOB_IDEMPOTENT ||
                changed_result != AC_RADIO_JOB_CONFLICT ||
                changed_error_result != AC_RADIO_JOB_CONFLICT ||
                changed_identity_result != AC_RADIO_JOB_CONFLICT)
                rc = 1;
        }
        printf("interrupted_replay=%s stale_result=%d replay_result=%d "
               "changed_result=%d changed_error_result=%d "
               "changed_identity_result=%d state=%s finish_id=%s\n",
               rc == 0 ? "ok" : "failed", stale_result, replay_result,
               changed_result, changed_error_result, changed_identity_result,
               finished.state, finished.finish_id);
    } else if (!strcmp(command, "cancelled-finish") && argc == 5) {
        const char *ap_id = argv[2];
        const char *epoch = argv[3];
        const char *job_id = argv[4];
        const char *finish_id = "40000000-0000-4000-8000-000000000098";
        int64_t now = time(NULL);

        rc = set_session(ap_id, epoch) == 0 &&
             ac_db_radio_job_lease_next(ap_id, epoch, now, &job) ==
                 AC_RADIO_JOB_OK && !strcmp(job.job_id, job_id) &&
             ac_db_radio_job_cancel(job_id, &job) == AC_RADIO_JOB_OK &&
             !strcmp(job.state, "cancel_requested") &&
             ac_db_radio_job_finish(job_id, job.attempt_id,
                 job.dispatch_generation, job.request_digest, ap_id, epoch,
                 finish_id, "cancelled", "controller_cancelled", "[]", 0,
                 &job) == AC_RADIO_JOB_OK &&
             !strcmp(job.state, "cancelled") && job.result_complete == 1 &&
             ac_db_radio_job_finish(job_id, job.attempt_id,
                 job.dispatch_generation, job.request_digest, ap_id, epoch,
                 finish_id, "cancelled", "controller_cancelled", "[]", 0,
                 &job) == AC_RADIO_JOB_IDEMPOTENT ? 0 : 1;
        printf("cancelled_finish=%s state=%s result_complete=%d error=%s\n",
               rc == 0 ? "ok" : "failed", job.state, job.result_complete,
               job.error_code);
    } else if (!strcmp(command, "set-state") && argc == 6) {
        rc = set_state(argv[2], argv[3], argv[4], atoi(argv[5])) == 0 ? 0 : 1;
    }
    ac_db_close();
    return rc;
}

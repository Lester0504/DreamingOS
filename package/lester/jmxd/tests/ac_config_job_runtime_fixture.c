// SPDX-License-Identifier: GPL-2.0-or-later
/* Runtime contract for the W2b AC config job store: idempotent creation,
 * session-gated leasing with per-AP serialization, bound-checked running
 * and finish transitions with idempotent replay, and lease expiry
 * recovery. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sqlite3.h>

extern sqlite3 *g_ac_db;

#define AP_ID "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
#define EPOCH \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define DIGEST \
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define DIGEST_B \
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define FINISH_1 "55555555-5555-4555-8555-555555555555"

enum ac_config_job_result {
    AC_CONFIG_JOB_ERROR = -1,
    AC_CONFIG_JOB_OK = 0,
    AC_CONFIG_JOB_IDEMPOTENT = 1,
    AC_CONFIG_JOB_NOT_FOUND = 2,
    AC_CONFIG_JOB_CONFLICT = 3,
    AC_CONFIG_JOB_INVALID = 4,
};

struct ac_config_job {
    char job_id[37];
    char ap_id[37];
    char state[17];
    char idempotency_key[129];
    char candidate_digest[72];
    int64_t created_at;
    int64_t updated_at;
    int64_t lease_expires_at;
    char session_epoch[65];
    char attempt_id[37];
    int64_t dispatch_generation;
    char request_digest[72];
    char finish_id[37];
    char outcome[15];
    char error_code[128];
};

int ac_db_init(void);
void ac_db_close(void);
int ac_db_ap_session_begin(const char *, const char *, int, int64_t);
int ac_db_config_job_create(const char *, const char *, const char *,
                            const char *, struct ac_config_job *);
int ac_db_config_job_status(const char *, struct ac_config_job *);
int ac_db_config_job_lease_next(const char *, const char *, int64_t,
                                struct ac_config_job *, char **);
int ac_db_config_job_mark_running(const char *, const char *, int64_t,
                                  const char *, const char *, const char *,
                                  int64_t, struct ac_config_job *);
int ac_db_config_job_finish(const char *, const char *, int64_t,
                            const char *, const char *, const char *,
                            const char *, const char *, const char *,
                            const char *, int64_t, struct ac_config_job *);
int ac_db_config_jobs_recover(int64_t);

#define CHECK(label, expr) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "FAIL %s\n", label); \
            return 1; \
        } \
    } while (0)

int main(void)
{
    struct ac_config_job job;
    struct ac_config_job leased;
    struct ac_config_job second;
    char *candidate = NULL;

    CHECK("init", ac_db_init() == 0);

    /* Creation is idempotent by (ap_id, idempotency_key); a different
     * candidate under the same key is a conflict, not a replacement. */
    CHECK("create", ac_db_config_job_create(AP_ID, "{\"c\":1}", DIGEST,
              "web.apply.1", &job) == AC_CONFIG_JOB_OK);
    CHECK("create state", !strcmp(job.state, "queued"));
    CHECK("create replay", ac_db_config_job_create(AP_ID, "{\"c\":1}",
              DIGEST, "web.apply.1", &job) == AC_CONFIG_JOB_IDEMPOTENT);
    CHECK("create drift", ac_db_config_job_create(AP_ID, "{\"c\":2}",
              DIGEST_B, "web.apply.1", NULL) == AC_CONFIG_JOB_CONFLICT);

    /* Leasing requires the current v2 session and serializes per AP. */
    CHECK("lease no session", ac_db_config_job_lease_next(AP_ID, EPOCH,
              1000, &leased, &candidate) == AC_CONFIG_JOB_ERROR);
    CHECK("adopt", sqlite3_exec(g_ac_db,
              "INSERT INTO ac_aps(ap_id,site_id,name,adoption_state,"
              "last_seen_at) VALUES('" AP_ID "','default','Fixture AP',"
              "'adopted',1000)", NULL, NULL, NULL) == SQLITE_OK);
    CHECK("session", ac_db_ap_session_begin(AP_ID, EPOCH, 2, 1000) == 0);
    CHECK("lease", ac_db_config_job_lease_next(AP_ID, EPOCH, 1001,
              &leased, &candidate) == AC_CONFIG_JOB_OK);
    CHECK("lease state", !strcmp(leased.state, "leased"));
    CHECK("lease generation", leased.dispatch_generation == 1);
    CHECK("lease candidate", candidate && !strcmp(candidate, "{\"c\":1}"));
    free(candidate);
    candidate = NULL;
    CHECK("create 2", ac_db_config_job_create(AP_ID, "{\"c\":3}", DIGEST_B,
              "web.apply.2", &second) == AC_CONFIG_JOB_OK);
    CHECK("serialized", ac_db_config_job_lease_next(AP_ID, EPOCH, 1002,
              &job, &candidate) == AC_CONFIG_JOB_NOT_FOUND);

    /* Running and finish are bound to the exact dispatch identity. */
    CHECK("run bad digest", ac_db_config_job_mark_running(leased.job_id,
              leased.attempt_id, leased.dispatch_generation, DIGEST_B,
              AP_ID, EPOCH, 1003, NULL) == AC_CONFIG_JOB_CONFLICT);
    CHECK("run", ac_db_config_job_mark_running(leased.job_id,
              leased.attempt_id, leased.dispatch_generation,
              leased.request_digest, AP_ID, EPOCH, 1004, &job) ==
          AC_CONFIG_JOB_OK);
    CHECK("run state", !strcmp(job.state, "running"));
    CHECK("run replay", ac_db_config_job_mark_running(leased.job_id,
              leased.attempt_id, leased.dispatch_generation,
              leased.request_digest, AP_ID, EPOCH, 1005, &job) ==
          AC_CONFIG_JOB_IDEMPOTENT);
    CHECK("finish bad outcome", ac_db_config_job_finish(leased.job_id,
              leased.attempt_id, leased.dispatch_generation,
              leased.request_digest, AP_ID, EPOCH, FINISH_1, "exploded",
              "", "{}", 1006, NULL) == AC_CONFIG_JOB_INVALID);
    CHECK("finish", ac_db_config_job_finish(leased.job_id,
              leased.attempt_id, leased.dispatch_generation,
              leased.request_digest, AP_ID, EPOCH, FINISH_1, "applied", "",
              "{\"match\":true}", 1007, &job) == AC_CONFIG_JOB_OK);
    CHECK("finish state", !strcmp(job.state, "applied"));
    CHECK("finish replay", ac_db_config_job_finish(leased.job_id,
              leased.attempt_id, leased.dispatch_generation,
              leased.request_digest, AP_ID, EPOCH, FINISH_1, "applied", "",
              "{\"match\":true}", 1008, &job) ==
          AC_CONFIG_JOB_IDEMPOTENT);

    /* Terminal state releases the per-AP serialization; an expired lease
     * recovers back to queued. */
    CHECK("lease 2", ac_db_config_job_lease_next(AP_ID, EPOCH, 2000,
              &leased, &candidate) == AC_CONFIG_JOB_OK);
    CHECK("lease 2 job", !strcmp(leased.job_id, second.job_id));
    free(candidate);
    candidate = NULL;
    CHECK("recover", ac_db_config_jobs_recover(
              2000 + 61) == AC_CONFIG_JOB_OK);
    CHECK("recover state", ac_db_config_job_status(second.job_id, &job) ==
          AC_CONFIG_JOB_OK && !strcmp(job.state, "queued"));

    ac_db_close();
    printf("ok\n");
    return 0;
}

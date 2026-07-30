// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>
#include <sqlite3.h>

#include "../src/apd/apd_config_recovery.h"

sqlite3 *g_apd_db = NULL;
static int rollback_calls;
static int rollback_fail;
static unsigned int finish_counter;

#define AP_ID "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
#define EPOCH "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define DIGEST "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

#define CHECK(label, expression) do { \
    if (!(expression)) { fprintf(stderr, "FAIL %s\n", label); return 1; } \
} while (0)

static struct apd_config_job_assignment assignment(unsigned int number)
{
    struct apd_config_job_assignment value;

    memset(&value, 0, sizeof(value));
    snprintf(value.job_id, sizeof(value.job_id),
             "%08x-1111-4111-8111-111111111111", number);
    snprintf(value.attempt_id, sizeof(value.attempt_id),
             "%08x-2222-4222-8222-222222222222", number);
    value.dispatch_generation = 1;
    snprintf(value.request_digest, sizeof(value.request_digest), "%s", DIGEST);
    snprintf(value.candidate_digest, sizeof(value.candidate_digest), "%s", DIGEST);
    snprintf(value.ap_id, sizeof(value.ap_id), "%s", AP_ID);
    snprintf(value.session_epoch, sizeof(value.session_epoch), "%s", EPOCH);
    return value;
}

static int finish_id(char out[APD_CONFIG_JOB_UUID_LEN + 1])
{
    finish_counter++;
    snprintf(out, APD_CONFIG_JOB_UUID_LEN + 1,
             "%08x-3333-4333-8333-333333333333", finish_counter);
    return 0;
}

int apd_config_rollback(const struct apd_config_paths *paths,
                        struct json_object *previous,
                        struct json_object **out)
{
    (void)paths;
    rollback_calls++;
    *out = json_object_new_object();
    json_object_object_add(*out, "ok", json_object_new_boolean(!rollback_fail));
    return previous && json_object_is_type(previous, json_type_array) &&
           !rollback_fail ? 0 : -1;
}

static int prepare(const struct apd_config_job_assignment *job,
                   const char *state, int64_t now)
{
    if (apd_config_job_offer_store(job, "{\"candidate\":true}", now,
                                   NULL) != APD_CONFIG_JOB_JOURNAL_OK)
        return -1;
    if (!strcmp(state, "offered"))
        return 0;
    if (apd_config_job_mark_staged(job, now + 1, NULL) !=
        APD_CONFIG_JOB_JOURNAL_OK)
        return -1;
    if (!strcmp(state, "staged"))
        return 0;
    if (apd_config_job_mark_applying(job, "[]", now + 2, NULL) !=
        APD_CONFIG_JOB_JOURNAL_OK)
        return -1;
    if (!strcmp(state, "applying"))
        return 0;
    return apd_config_job_mark_applied(job, now + 3, NULL) ==
        APD_CONFIG_JOB_JOURNAL_OK ? 0 : -1;
}

int main(void)
{
    struct apd_config_paths paths = { "uci", "wifi", "config", "stage" };
    struct apd_config_job_assignment jobs[5];
    struct apd_config_job_journal_entry entry;
    int recovered = 0;
    int i;

    CHECK("db", sqlite3_open(":memory:", &g_apd_db) == SQLITE_OK);
    CHECK("schema", apd_config_job_journal_init() == APD_CONFIG_JOB_JOURNAL_OK);
    for (i = 0; i < 5; i++)
        jobs[i] = assignment((unsigned int)i + 1);
    CHECK("offer", prepare(&jobs[0], "offered", 100) == 0);
    CHECK("stage", prepare(&jobs[1], "staged", 200) == 0);
    CHECK("applying", prepare(&jobs[2], "applying", 300) == 0);
    CHECK("applied", prepare(&jobs[3], "applied", 400) == 0);
    CHECK("recover", apd_config_jobs_restart_recover(
        &paths, 1000, finish_id, &recovered) == 0);
    CHECK("count", recovered == 4);
    CHECK("rollbacks", rollback_calls == 2);
    for (i = 0; i < 4; i++) {
        CHECK("load terminal", apd_config_job_journal_get(jobs[i].job_id,
            &entry) == APD_CONFIG_JOB_JOURNAL_OK);
        CHECK("pre-apply failed", i >= 2 || !strcmp(entry.state, "failed"));
        CHECK("mutated rolled back", i < 2 ||
              !strcmp(entry.state, "rolled_back"));
        CHECK("finish pending", entry.finish_id[0] && !entry.finish_acked);
    }

    CHECK("prepare failure", prepare(&jobs[4], "applying", 500) == 0);
    rollback_fail = 1;
    recovered = 99;
    CHECK("fail closed", apd_config_jobs_restart_recover(
        &paths, 1100, finish_id, &recovered) != 0);
    CHECK("not counted", recovered == 0);
    CHECK("still applying", apd_config_job_journal_get(jobs[4].job_id,
        &entry) == APD_CONFIG_JOB_JOURNAL_OK &&
        !strcmp(entry.state, "applying") && !entry.finish_id[0]);

    sqlite3_close(g_apd_db);
    puts("ok");
    return 0;
}

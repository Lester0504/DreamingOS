// SPDX-License-Identifier: GPL-2.0-or-later
#include "apd_config_recovery.h"

#include <stdio.h>
#include <string.h>

static int apd_config_recovery_finish(
    const struct apd_config_job_recovery *recovery, int64_t now,
    apd_config_finish_id_fn finish_id, const char *outcome,
    const char *error_code)
{
    struct apd_config_job_finish finish;
    int rc;

    memset(&finish, 0, sizeof(finish));
    finish.assignment = recovery->entry.assignment;
    if (finish_id(finish.finish_id) != 0)
        return -1;
    snprintf(finish.outcome, sizeof(finish.outcome), "%s", outcome);
    snprintf(finish.error_code, sizeof(finish.error_code), "%s",
             error_code);
    finish.observed_at = now;
    rc = apd_config_job_finish_store(&finish, now, NULL);
    return rc == APD_CONFIG_JOB_JOURNAL_OK ||
           rc == APD_CONFIG_JOB_JOURNAL_IDEMPOTENT ? 0 : -1;
}

int apd_config_jobs_restart_recover(
    const struct apd_config_paths *paths, int64_t now,
    apd_config_finish_id_fn finish_id, int *recovered)
{
    int count = 0;

    if (!paths || !paths->uci || !paths->wifi || !paths->config_dir ||
        !finish_id || now <= 0 || !recovered)
        return -1;
    *recovered = 0;
    for (;;) {
        struct apd_config_job_recovery recovery;
        int rc = apd_config_job_recovery_next(&recovery);

        if (rc == APD_CONFIG_JOB_JOURNAL_NOT_FOUND)
            break;
        if (rc != APD_CONFIG_JOB_JOURNAL_OK)
            return -1;
        if (!strcmp(recovery.entry.state, "offered") ||
            !strcmp(recovery.entry.state, "staged")) {
            rc = apd_config_recovery_finish(&recovery, now, finish_id,
                "failed", "interrupted_before_apply");
        } else {
            struct json_object *previous = recovery.previous_json &&
                recovery.previous_json[0] ?
                json_tokener_parse(recovery.previous_json) : NULL;
            struct json_object *result = NULL;

            if (!previous || apd_config_rollback(paths, previous, &result) != 0)
                rc = -1;
            else
                rc = apd_config_recovery_finish(&recovery, now, finish_id,
                    "rolled_back", "interrupted_apply");
            json_object_put(previous);
            json_object_put(result);
        }
        apd_config_job_recovery_free(&recovery);
        if (rc != 0)
            return -1;
        count++;
    }
    *recovered = count;
    return 0;
}

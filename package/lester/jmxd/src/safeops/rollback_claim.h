/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef JMX_SAFEOPS_ROLLBACK_CLAIM_H
#define JMX_SAFEOPS_ROLLBACK_CLAIM_H

#include <stdint.h>
#include <sqlite3.h>

#define SAFEOPS_ROLLBACK_LEASE_SECONDS 120

/* Claim before touching live configuration. The revision and digest predicates
 * keep an old watchdog from acting on a later transaction with similar data. */
static inline int safeops_rollback_claim(sqlite3 *db, int task_id,
                                         int64_t config_revision,
                                         const char *applied_digest,
                                         const char *owner, int64_t now)
{
    sqlite3_stmt *st = NULL;
    int rc;

    if (!db || task_id <= 0 || !owner || !owner[0])
        return -1;
    rc = sqlite3_prepare_v2(db,
        "UPDATE config_apply_tasks SET state='rolling_back',"
        "rollback_owner=?1,rollback_claimed_at=?2,rollback_claim_revision=?3 "
        "WHERE id=?4 AND config_revision=?3 AND applied_digest=?5 AND "
        "(state='pending' OR (state='rolling_back' AND rollback_claimed_at<=?6))",
        -1, &st, NULL);
    if (rc != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, owner, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now);
    sqlite3_bind_int64(st, 3, config_revision);
    sqlite3_bind_int(st, 4, task_id);
    sqlite3_bind_text(st, 5, applied_digest ? applied_digest : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, now - SAFEOPS_ROLLBACK_LEASE_SECONDS);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return -1;
    return sqlite3_changes(db) == 1 ? 1 : 0;
}

/* Only the current lease owner may publish the terminal rollback result. */
static inline int safeops_rollback_finish(sqlite3 *db, int task_id,
                                          int64_t config_revision,
                                          const char *owner,
                                          const char *state,
                                          int64_t finished_at,
                                          const char *error,
                                          int rollback_applied,
                                          const char *rollback_error,
                                          const char *rollback_reason)
{
    sqlite3_stmt *st = NULL;
    int rc;

    if (!db || task_id <= 0 || !owner || !owner[0] || !state || !state[0])
        return -1;
    rc = sqlite3_prepare_v2(db,
        "UPDATE config_apply_tasks SET state=?1,finished_at=?2,error=?3,"
        "rollback_applied=?4,rollback_error=?5,rollback_reason=?6 "
        "WHERE id=?7 AND state='rolling_back' AND config_revision=?8 "
        "AND rollback_claim_revision=?8 AND rollback_owner=?9",
        -1, &st, NULL);
    if (rc != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, state, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, finished_at);
    sqlite3_bind_text(st, 3, error ? error : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 4, rollback_applied);
    sqlite3_bind_text(st, 5, rollback_error ? rollback_error : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, rollback_reason ? rollback_reason : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 7, task_id);
    sqlite3_bind_int64(st, 8, config_revision);
    sqlite3_bind_text(st, 9, owner, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return -1;
    return sqlite3_changes(db) == 1 ? 1 : 0;
}

#endif

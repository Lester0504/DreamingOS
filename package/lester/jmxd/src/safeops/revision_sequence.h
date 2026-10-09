/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef JMX_SAFEOPS_REVISION_SEQUENCE_H
#define JMX_SAFEOPS_REVISION_SEQUENCE_H

#include <stdint.h>
#include <sqlite3.h>

enum safeops_revision_begin_result {
    SAFEOPS_REVISION_ERROR = -1,
    SAFEOPS_REVISION_READY = 1,
    SAFEOPS_REVISION_REPLAY = 2,
    SAFEOPS_REVISION_ACTIVE = 3,
};

/* READY leaves BEGIN IMMEDIATE open so the caller can insert the task and
 * commit atomically with the sequence increment. Other results close it. */
static inline int safeops_revision_begin(sqlite3 *db,
                                         const char *idempotency_key,
                                         int *existing_id,
                                         int *active_id,
                                         int64_t *revision)
{
    sqlite3_stmt *st = NULL;
    int rc;

    if (existing_id)
        *existing_id = 0;
    if (active_id)
        *active_id = 0;
    if (revision)
        *revision = 0;
    if (!db || !existing_id || !active_id || !revision)
        return SAFEOPS_REVISION_ERROR;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        return SAFEOPS_REVISION_ERROR;

    if (idempotency_key && idempotency_key[0]) {
        rc = sqlite3_prepare_v2(db,
            "SELECT id FROM config_apply_tasks WHERE idempotency_key=?1 "
            "ORDER BY id DESC LIMIT 1", -1, &st, NULL);
        if (rc != SQLITE_OK)
            goto fail;
        sqlite3_bind_text(st, 1, idempotency_key, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW)
            *existing_id = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
        st = NULL;
        if (*existing_id > 0) {
            sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
            return SAFEOPS_REVISION_REPLAY;
        }
    }

    rc = sqlite3_prepare_v2(db,
        "SELECT id FROM config_apply_tasks WHERE state IN ('pending','rolling_back') "
        "ORDER BY id DESC LIMIT 1", -1, &st, NULL);
    if (rc != SQLITE_OK)
        goto fail;
    if (sqlite3_step(st) == SQLITE_ROW)
        *active_id = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    st = NULL;
    if (*active_id > 0) {
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        return SAFEOPS_REVISION_ACTIVE;
    }

    rc = sqlite3_prepare_v2(db,
        "SELECT next_revision FROM config_apply_revision_sequence WHERE id=1",
        -1, &st, NULL);
    if (rc != SQLITE_OK || sqlite3_step(st) != SQLITE_ROW)
        goto fail;
    *revision = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    st = NULL;
    if (*revision <= 0 || sqlite3_exec(db,
            "UPDATE config_apply_revision_sequence "
            "SET next_revision=next_revision+1 WHERE id=1",
            NULL, NULL, NULL) != SQLITE_OK || sqlite3_changes(db) != 1)
        goto fail;
    return SAFEOPS_REVISION_READY;

fail:
    if (st)
        sqlite3_finalize(st);
    sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    return SAFEOPS_REVISION_ERROR;
}

#endif

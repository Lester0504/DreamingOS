// SPDX-License-Identifier: GPL-2.0-or-later
#include "webd_admin_transaction.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void txn_result_init(struct webd_admin_txn_result *result)
{
    if (!result)
        return;
    memset(result, 0, sizeof(*result));
    result->status = WEBD_ADMIN_TXN_INVALID;
    result->failed_step_index = SIZE_MAX;
}

static void txn_result_failure(struct webd_admin_txn_result *result, int status,
                               enum webd_admin_txn_phase phase, size_t index,
                               const char *name, const char *error)
{
    if (!result)
        return;
    result->status = status;
    result->phase = phase;
    result->failed_step_index = index;
    snprintf(result->failed_step, sizeof(result->failed_step), "%s",
             name ? name : "");
    snprintf(result->error, sizeof(result->error), "%s",
             error && error[0] ? error : webd_admin_txn_status_error(status));
}

static int txn_name_ok(const char *name)
{
    size_t length = 0;

    if (!name || !name[0])
        return 0;
    while (length < WEBD_ADMIN_TXN_NAME_MAX && name[length])
        length++;
    return length > 0 && length < WEBD_ADMIN_TXN_NAME_MAX;
}

static int txn_validate(const struct webd_admin_txn_step *steps,
                        size_t step_count,
                        struct webd_admin_txn_result *result)
{
    size_t irreversible_count = 0;
    size_t i;

    if (!steps || step_count == 0 || step_count > WEBD_ADMIN_TXN_MAX_STEPS)
        return WEBD_ADMIN_TXN_INVALID;
    for (i = 0; i < step_count; i++) {
        const struct webd_admin_txn_step *step = &steps[i];

        if (!txn_name_ok(step->name) || !step->apply ||
            (step->flags & ~WEBD_ADMIN_TXN_IRREVERSIBLE)) {
            txn_result_failure(result, WEBD_ADMIN_TXN_INVALID,
                               WEBD_ADMIN_TXN_PHASE_NONE, i, step->name,
                               "invalid_transaction_step");
            return WEBD_ADMIN_TXN_INVALID;
        }
        if (step->flags & WEBD_ADMIN_TXN_IRREVERSIBLE) {
            irreversible_count++;
            if (i + 1 != step_count || irreversible_count > 1 ||
                step->snapshot || step->restore) {
                txn_result_failure(result,
                                   WEBD_ADMIN_TXN_IRREVERSIBLE_ORDER,
                                   WEBD_ADMIN_TXN_PHASE_NONE, i, step->name,
                                   "irreversible_step_must_be_unique_and_last");
                return WEBD_ADMIN_TXN_IRREVERSIBLE_ORDER;
            }
        } else if (!step->snapshot || !step->restore ||
                   !step->snapshot_free) {
            txn_result_failure(result, WEBD_ADMIN_TXN_INVALID,
                               WEBD_ADMIN_TXN_PHASE_NONE, i, step->name,
                               "reversible_step_requires_snapshot_restore_free");
            return WEBD_ADMIN_TXN_INVALID;
        }
    }
    return WEBD_ADMIN_TXN_OK;
}

static void txn_snapshots_free(const struct webd_admin_txn_step *steps,
                               void **snapshots, size_t step_count)
{
    size_t i = step_count;

    while (i > 0) {
        const struct webd_admin_txn_step *step;

        i--;
        step = &steps[i];
        if (!(step->flags & WEBD_ADMIN_TXN_IRREVERSIBLE) && snapshots[i])
            step->snapshot_free(step->context, snapshots[i]);
        snapshots[i] = NULL;
    }
}

static int txn_rollback(const struct webd_admin_txn_step *steps,
                        void **snapshots, size_t attempted_count,
                        struct webd_admin_txn_result *result)
{
    char first_error[WEBD_ADMIN_TXN_ERROR_MAX] = "";
    char error[WEBD_ADMIN_TXN_ERROR_MAX];
    size_t first_failed = SIZE_MAX;
    size_t i = attempted_count;

    if (result)
        result->phase = WEBD_ADMIN_TXN_PHASE_ROLLBACK;
    while (i > 0) {
        const struct webd_admin_txn_step *step;

        i--;
        step = &steps[i];
        if (step->flags & WEBD_ADMIN_TXN_IRREVERSIBLE)
            continue;
        if (result)
            result->rollback_attempted++;
        error[0] = '\0';
        if (step->restore(step->context, snapshots[i], error,
                          sizeof(error)) != 0) {
            if (result)
                result->rollback_failed++;
            if (first_failed == SIZE_MAX) {
                first_failed = i;
                snprintf(first_error, sizeof(first_error), "%s",
                         error[0] ? error : "step_restore_failed");
                if (result) {
                    snprintf(result->rollback_failed_step,
                             sizeof(result->rollback_failed_step), "%s",
                             step->name);
                    snprintf(result->rollback_error,
                             sizeof(result->rollback_error), "%s",
                             first_error);
                }
            }
        }
    }
    if (first_failed != SIZE_MAX) {
        txn_result_failure(result, WEBD_ADMIN_TXN_ROLLBACK_FAILED,
                           WEBD_ADMIN_TXN_PHASE_ROLLBACK, first_failed,
                           steps[first_failed].name, first_error);
        return WEBD_ADMIN_TXN_ROLLBACK_FAILED;
    }
    return WEBD_ADMIN_TXN_OK;
}

int webd_admin_txn_execute(const struct webd_admin_txn_step *steps,
                           size_t step_count,
                           struct webd_admin_txn_result *result)
{
    void *snapshots[WEBD_ADMIN_TXN_MAX_STEPS] = {0};
    char error[WEBD_ADMIN_TXN_ERROR_MAX];
    size_t i;
    int rc;

    txn_result_init(result);
    rc = txn_validate(steps, step_count, result);
    if (rc != WEBD_ADMIN_TXN_OK)
        return rc;

    for (i = 0; i < step_count; i++) {
        if (!steps[i].preflight)
            continue;
        if (result)
            result->phase = WEBD_ADMIN_TXN_PHASE_PREFLIGHT;
        error[0] = '\0';
        if (steps[i].preflight(steps[i].context, error, sizeof(error)) != 0) {
            txn_result_failure(result, WEBD_ADMIN_TXN_PREFLIGHT_FAILED,
                               WEBD_ADMIN_TXN_PHASE_PREFLIGHT, i,
                               steps[i].name, error);
            return WEBD_ADMIN_TXN_PREFLIGHT_FAILED;
        }
    }

    for (i = 0; i < step_count; i++) {
        if (steps[i].flags & WEBD_ADMIN_TXN_IRREVERSIBLE)
            continue;
        if (result)
            result->phase = WEBD_ADMIN_TXN_PHASE_SNAPSHOT;
        error[0] = '\0';
        if (steps[i].snapshot(steps[i].context, &snapshots[i], error,
                              sizeof(error)) != 0 || !snapshots[i]) {
            txn_result_failure(result, WEBD_ADMIN_TXN_SNAPSHOT_FAILED,
                               WEBD_ADMIN_TXN_PHASE_SNAPSHOT, i,
                               steps[i].name, error);
            txn_snapshots_free(steps, snapshots, step_count);
            return WEBD_ADMIN_TXN_SNAPSHOT_FAILED;
        }
    }

    for (i = 0; i < step_count; i++) {
        if (result) {
            result->phase = WEBD_ADMIN_TXN_PHASE_APPLY;
            result->apply_attempted++;
            if (steps[i].flags & WEBD_ADMIN_TXN_IRREVERSIBLE)
                result->irreversible_attempted = 1;
        }
        error[0] = '\0';
        if (steps[i].apply(steps[i].context, error, sizeof(error)) != 0) {
            char apply_error[WEBD_ADMIN_TXN_ERROR_MAX];
            int rollback_rc;

            snprintf(apply_error, sizeof(apply_error), "%s",
                     error[0] ? error : "step_apply_failed");
            if (result) {
                snprintf(result->apply_failed_step,
                         sizeof(result->apply_failed_step), "%s",
                         steps[i].name);
                snprintf(result->apply_error, sizeof(result->apply_error),
                         "%s", apply_error);
            }
            rollback_rc = txn_rollback(steps, snapshots,
                (steps[i].flags & WEBD_ADMIN_TXN_IRREVERSIBLE) ? i : i + 1,
                result);
            if (rollback_rc == WEBD_ADMIN_TXN_OK)
                txn_result_failure(result, WEBD_ADMIN_TXN_APPLY_FAILED,
                                   WEBD_ADMIN_TXN_PHASE_APPLY, i,
                                   steps[i].name, apply_error);
            txn_snapshots_free(steps, snapshots, step_count);
            return rollback_rc == WEBD_ADMIN_TXN_OK ?
                WEBD_ADMIN_TXN_APPLY_FAILED : rollback_rc;
        }
        if (result)
            result->applied_steps++;
    }

    txn_snapshots_free(steps, snapshots, step_count);
    if (result) {
        result->status = WEBD_ADMIN_TXN_OK;
        result->phase = WEBD_ADMIN_TXN_PHASE_DONE;
        result->failed_step_index = SIZE_MAX;
        result->failed_step[0] = '\0';
        result->error[0] = '\0';
    }
    return WEBD_ADMIN_TXN_OK;
}

const char *webd_admin_txn_status_error(int status)
{
    switch (status) {
    case WEBD_ADMIN_TXN_PREFLIGHT_FAILED:
        return "admin_transaction_preflight_failed";
    case WEBD_ADMIN_TXN_SNAPSHOT_FAILED:
        return "admin_transaction_snapshot_failed";
    case WEBD_ADMIN_TXN_APPLY_FAILED:
        return "admin_transaction_apply_failed";
    case WEBD_ADMIN_TXN_ROLLBACK_FAILED:
        return "admin_transaction_rollback_failed";
    case WEBD_ADMIN_TXN_IRREVERSIBLE_ORDER:
        return "admin_transaction_irreversible_order";
    case WEBD_ADMIN_TXN_INVALID:
        return "admin_transaction_invalid";
    default:
        return "";
    }
}

// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __DREAMINGWRT_WEBD_ADMIN_TRANSACTION_H__
#define __DREAMINGWRT_WEBD_ADMIN_TRANSACTION_H__

#include <stddef.h>

#define WEBD_ADMIN_TXN_MAX_STEPS 8
#define WEBD_ADMIN_TXN_NAME_MAX 48
#define WEBD_ADMIN_TXN_ERROR_MAX 160

#define WEBD_ADMIN_TXN_IRREVERSIBLE (1U << 0)

enum webd_admin_txn_status {
    WEBD_ADMIN_TXN_OK = 0,
    WEBD_ADMIN_TXN_INVALID = -1,
    WEBD_ADMIN_TXN_PREFLIGHT_FAILED = -2,
    WEBD_ADMIN_TXN_SNAPSHOT_FAILED = -3,
    WEBD_ADMIN_TXN_APPLY_FAILED = -4,
    WEBD_ADMIN_TXN_ROLLBACK_FAILED = -5,
    WEBD_ADMIN_TXN_IRREVERSIBLE_ORDER = -6,
};

enum webd_admin_txn_phase {
    WEBD_ADMIN_TXN_PHASE_NONE = 0,
    WEBD_ADMIN_TXN_PHASE_PREFLIGHT,
    WEBD_ADMIN_TXN_PHASE_SNAPSHOT,
    WEBD_ADMIN_TXN_PHASE_APPLY,
    WEBD_ADMIN_TXN_PHASE_ROLLBACK,
    WEBD_ADMIN_TXN_PHASE_DONE,
};

typedef int (*webd_admin_txn_preflight_fn)(void *context, char *error,
                                            size_t error_len);
typedef int (*webd_admin_txn_snapshot_fn)(void *context, void **snapshot,
                                          char *error, size_t error_len);
typedef int (*webd_admin_txn_apply_fn)(void *context, char *error,
                                       size_t error_len);
typedef int (*webd_admin_txn_restore_fn)(void *context, void *snapshot,
                                         char *error, size_t error_len);
typedef void (*webd_admin_txn_snapshot_free_fn)(void *context, void *snapshot);

struct webd_admin_txn_step {
    const char *name;
    unsigned int flags;
    void *context;
    webd_admin_txn_preflight_fn preflight;
    webd_admin_txn_snapshot_fn snapshot;
    webd_admin_txn_apply_fn apply;
    webd_admin_txn_restore_fn restore;
    webd_admin_txn_snapshot_free_fn snapshot_free;
};

struct webd_admin_txn_result {
    int status;
    enum webd_admin_txn_phase phase;
    size_t failed_step_index;
    char failed_step[WEBD_ADMIN_TXN_NAME_MAX];
    char error[WEBD_ADMIN_TXN_ERROR_MAX];
    char apply_failed_step[WEBD_ADMIN_TXN_NAME_MAX];
    char apply_error[WEBD_ADMIN_TXN_ERROR_MAX];
    char rollback_failed_step[WEBD_ADMIN_TXN_NAME_MAX];
    char rollback_error[WEBD_ADMIN_TXN_ERROR_MAX];
    size_t apply_attempted;
    size_t applied_steps;
    size_t rollback_attempted;
    size_t rollback_failed;
    int irreversible_attempted;
};

/*
 * Preflight callbacks must be side-effect free. Snapshot callbacks must
 * capture every resource their matching apply callback can mutate.
 *
 * An irreversible step is optional, but when present it must be the only one
 * and the final step. Its apply callback must be internally atomic: failure
 * must leave its owned resources unchanged. No callback runs after it succeeds.
 */
int webd_admin_txn_execute(const struct webd_admin_txn_step *steps,
                           size_t step_count,
                           struct webd_admin_txn_result *result);

const char *webd_admin_txn_status_error(int status);

#endif

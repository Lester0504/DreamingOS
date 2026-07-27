// SPDX-License-Identifier: GPL-2.0-or-later
#include "otad_inventory_transaction.h"

#include <stdio.h>

static void transaction_error(char *error, size_t error_len,
                              const char *value)
{
    if (error && error_len)
        snprintf(error, error_len, "%s", value ? value : "");
}

int otad_inventory_run_transaction(sqlite3 *db,
                                   otad_inventory_transaction_work work,
                                   void *opaque, int *inventory_unchanged,
                                   char *error, size_t error_len)
{
    if (!db || !work || !inventory_unchanged) {
        transaction_error(error, error_len, "invalid_argument");
        return -1;
    }
    *inventory_unchanged = 1;
    transaction_error(error, error_len, "");
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        transaction_error(error, error_len, "inventory_transaction_failed");
        return -1;
    }
    if (work(opaque) != 0) {
        if (sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK) {
            *inventory_unchanged = 0;
            transaction_error(error, error_len, "inventory_rollback_failed");
        } else {
            transaction_error(error, error_len, "inventory_scan_rolled_back");
        }
        return -1;
    }
    if (sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        if (sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK) {
            *inventory_unchanged = 0;
            transaction_error(error, error_len, "inventory_rollback_failed");
        } else {
            transaction_error(error, error_len, "inventory_commit_rolled_back");
        }
        return -1;
    }
    *inventory_unchanged = 0;
    return 0;
}

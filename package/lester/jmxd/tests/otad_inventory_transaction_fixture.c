// SPDX-License-Identifier: GPL-2.0-or-later
#include "otad/otad_inventory_transaction.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct work_state {
    sqlite3 *db;
    int fail;
    int called;
};

static int mutate(void *opaque)
{
    struct work_state *state = opaque;

    state->called++;
    assert(sqlite3_exec(state->db, "DELETE FROM inventory", NULL, NULL, NULL) ==
           SQLITE_OK);
    assert(sqlite3_exec(state->db,
                        "INSERT INTO inventory(value) VALUES('replacement')",
                        NULL, NULL, NULL) == SQLITE_OK);
    return state->fail ? -1 : 0;
}

static int count_value(sqlite3 *db, const char *value)
{
    sqlite3_stmt *statement;
    int count;

    assert(sqlite3_prepare_v2(db,
                              "SELECT COUNT(*) FROM inventory WHERE value=?1",
                              -1, &statement, NULL) == SQLITE_OK);
    sqlite3_bind_text(statement, 1, value, -1, SQLITE_STATIC);
    assert(sqlite3_step(statement) == SQLITE_ROW);
    count = sqlite3_column_int(statement, 0);
    sqlite3_finalize(statement);
    return count;
}

int main(void)
{
    sqlite3 *db;
    sqlite3 *locker;
    struct work_state state;
    char path[] = "/tmp/otad-inventory-transaction-XXXXXX";
    char error[64];
    int unchanged;
    int fd;

    fd = mkstemp(path);
    assert(fd >= 0);
    close(fd);
    assert(sqlite3_open(path, &db) == SQLITE_OK);
    assert(sqlite3_exec(db, "CREATE TABLE inventory(value TEXT NOT NULL)",
                        NULL, NULL, NULL) == SQLITE_OK);
    assert(sqlite3_exec(db, "INSERT INTO inventory VALUES('sentinel')",
                        NULL, NULL, NULL) == SQLITE_OK);

    memset(&state, 0, sizeof(state));
    state.db = db;
    state.fail = 1;
    assert(otad_inventory_run_transaction(db, mutate, &state, &unchanged,
                                          error, sizeof(error)) != 0);
    assert(state.called == 1);
    assert(unchanged == 1);
    assert(!strcmp(error, "inventory_scan_rolled_back"));
    assert(count_value(db, "sentinel") == 1);
    assert(count_value(db, "replacement") == 0);

    state.fail = 0;
    assert(otad_inventory_run_transaction(db, mutate, &state, &unchanged,
                                          error, sizeof(error)) == 0);
    assert(unchanged == 0);
    assert(count_value(db, "sentinel") == 0);
    assert(count_value(db, "replacement") == 1);

    assert(sqlite3_open(path, &locker) == SQLITE_OK);
    assert(sqlite3_exec(locker, "BEGIN IMMEDIATE", NULL, NULL, NULL) ==
           SQLITE_OK);
    sqlite3_busy_timeout(db, 1);
    state.called = 0;
    assert(otad_inventory_run_transaction(db, mutate, &state, &unchanged,
                                          error, sizeof(error)) != 0);
    assert(state.called == 0);
    assert(unchanged == 1);
    assert(!strcmp(error, "inventory_transaction_failed"));
    assert(count_value(db, "replacement") == 1);
    assert(sqlite3_exec(locker, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK);

    sqlite3_close(locker);
    sqlite3_close(db);
    assert(unlink(path) == 0);
    puts("ok: otad inventory transaction rollback fixture");
    return 0;
}

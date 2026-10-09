// SPDX-License-Identifier: GPL-2.0-or-later
/* Real SQLite journal + production projection; no OTA execution or device I/O. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sqlite3.h>
#include <json-c/json.h>
#define DREAMINGWRT_OTAD_INTERNAL_H
static sqlite3 *db;
static int64_t clock_s = 200000;
static int64_t otad_now_s(void) { return clock_s; }
static sqlite3_stmt *otad_inventory_prepare(const char *sql)
{
    sqlite3_stmt *st = NULL;
    assert(sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK);
    return st;
}
#include "../src/otad/otad_task_projection.c"

static void emit(const char *state, int64_t done)
{
    sqlite3_stmt *st = otad_inventory_prepare(
        "UPDATE ota_operations SET state=?1,completed_at=?2");
    sqlite3_bind_text(st, 1, state, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, done);
    assert(sqlite3_step(st) == SQLITE_DONE);
    sqlite3_finalize(st);
    struct json_object *result = otad_task_projection_get();
    puts(json_object_to_json_string_ext(result, JSON_C_TO_STRING_PLAIN));
    json_object_put(result);
}
int main(void)
{
    assert(sqlite3_open(":memory:", &db) == SQLITE_OK);
    assert(sqlite3_exec(db,
        "CREATE TABLE ota_operations(operation_id,kind,state,progress,"
        "started_at,completed_at,from_version,to_version,error_code,error_message,created_at);"
        "INSERT INTO ota_operations VALUES('ota-real','firmware','writing',60,"
        "100000,0,'v1','v2','E_TEST','test failure',90000);", NULL, NULL, NULL) == SQLITE_OK);
    emit("writing", 0);
    emit("success", 199900);
    emit("success", 199000);
    emit("failed", 199000);
    emit("rolled_back", 199000);
    emit("success", 100000);
    assert(sqlite3_close(db) == SQLITE_OK);
    return 0;
}

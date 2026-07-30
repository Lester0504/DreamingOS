#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_netconfig_db.c").read_text()


def function_source(signature: str) -> str:
    start = SOURCE.index(signature)
    brace = SOURCE.index("{", start)
    depth = 0
    for index in range(brace, len(SOURCE)):
        if SOURCE[index] == "{":
            depth += 1
        elif SOURCE[index] == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[start:index + 1]
    raise AssertionError(f"unterminated function: {signature}")


REPLACE_GROUP = function_source("static int nc_fw_replace_group(")
FINISH_TRANSACTION = function_source("static int nc_fw_finish_transaction(")


FIXTURE = r'''
#include <json-c/json.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

static sqlite3 *g_netconfig_db;
typedef int (*nc_fw_bind_row_fn)(sqlite3_stmt *, struct json_object *, int);

static int nc_exec(const char *sql)
{
    return sqlite3_exec(g_netconfig_db, sql, NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}

static int nc_prepare(sqlite3_stmt **st, const char *sql)
{
    return sqlite3_prepare_v2(g_netconfig_db, sql, -1, st, NULL) == SQLITE_OK ? 0 : -1;
}

static int nc_step_done(sqlite3_stmt *st)
{
    return sqlite3_step(st) == SQLITE_DONE ? 0 : -1;
}

__REPLACE_GROUP__

__FINISH_TRANSACTION__

static int bind_row(sqlite3_stmt *st, struct json_object *row, int order)
{
    struct json_object *value = NULL;
    const char *text;

    (void)order;
    if (!json_object_object_get_ex(row, "value", &value))
        return -1;
    text = json_object_get_string(value);
    return sqlite3_bind_text(st, 1, text, -1, SQLITE_TRANSIENT) == SQLITE_OK ? 0 : -1;
}

static int deny_delete(void *ctx, int action, const char *arg1,
                       const char *arg2, const char *db, const char *trigger)
{
    (void)ctx; (void)arg2; (void)db; (void)trigger;
    if (action == SQLITE_DELETE && arg1 && strcmp(arg1, "firewall_rule") == 0)
        return SQLITE_DENY;
    return SQLITE_OK;
}

static int reject_commit(void *ctx)
{
    (void)ctx;
    return 1;
}

static int row_count(const char *value)
{
    sqlite3_stmt *st = NULL;
    int count = -1;

    if (sqlite3_prepare_v2(g_netconfig_db,
            "SELECT count(*) FROM firewall_rule WHERE value=?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, value, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        count = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return count;
}

static int run_case(const char *name)
{
    struct json_object *rows = json_object_new_array();
    struct json_object *first = json_object_new_object();
    struct json_object *second = json_object_new_object();
    const char *insert_sql = "INSERT INTO firewall_rule(value) VALUES(?1)";
    int rc;

    json_object_object_add(first, "value", json_object_new_string("new"));
    json_object_array_add(rows, first);
    if (strcmp(name, "insert") == 0) {
        json_object_object_add(second, "value", json_object_new_string("new"));
        json_object_array_add(rows, second);
    } else {
        json_object_put(second);
    }

    if (nc_exec("BEGIN IMMEDIATE") != 0)
        return 10;
    if (strcmp(name, "prepare") == 0)
        insert_sql = "INSERT INTO firewall_rule(missing_column) VALUES(?1)";
    if (strcmp(name, "delete") == 0)
        sqlite3_set_authorizer(g_netconfig_db, deny_delete, NULL);
    if (strcmp(name, "commit") == 0)
        sqlite3_commit_hook(g_netconfig_db, reject_commit, NULL);

    rc = nc_fw_replace_group(rows, "DELETE FROM firewall_rule", insert_sql, bind_row);
    sqlite3_set_authorizer(g_netconfig_db, NULL, NULL);
    if (strcmp(name, "commit") != 0 && rc == 0)
        rc = -2;
    rc = nc_fw_finish_transaction(rc);
    sqlite3_commit_hook(g_netconfig_db, NULL, NULL);
    json_object_put(rows);

    if (rc == 0 || row_count("old") != 1 || row_count("new") != 0)
        return 20;
    return 0;
}

int main(void)
{
    static const char *cases[] = { "prepare", "delete", "insert", "commit" };

    if (sqlite3_open(":memory:", &g_netconfig_db) != SQLITE_OK)
        return 2;
    if (nc_exec("CREATE TABLE firewall_rule(value TEXT PRIMARY KEY)") != 0)
        return 3;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (nc_exec("DELETE FROM firewall_rule") != 0 ||
            nc_exec("INSERT INTO firewall_rule(value) VALUES('old')") != 0)
            return 4;
        int rc = run_case(cases[i]);
        if (rc != 0) {
            fprintf(stderr, "%s failed: %d (%s)\n", cases[i], rc,
                    sqlite3_errmsg(g_netconfig_db));
            return rc;
        }
    }
    sqlite3_close(g_netconfig_db);
    puts("ok: firewall replace rolls back prepare/delete/insert/commit failures");
    return 0;
}
'''


def main():
    setter = function_source("int jmx_firewall_service_set(")
    assert 'if(nc_exec("BEGIN IMMEDIATE")!=0)return -1;' in setter
    assert "nc_fw_replace_group" in setter
    assert "goto rollback" in setter
    assert 'if (nc_exec("COMMIT") != 0)' in setter
    assert 'nc_exec("ROLLBACK")' in setter
    assert "return nc_fw_finish_transaction(-1)" in setter

    source = FIXTURE.replace("__REPLACE_GROUP__", REPLACE_GROUP).replace(
        "__FINISH_TRANSACTION__", FINISH_TRANSACTION
    )
    with tempfile.TemporaryDirectory(prefix="firewall-set-txn-") as tmp:
        tmp_path = Path(tmp)
        fixture = tmp_path / "fixture.c"
        binary = tmp_path / "fixture"
        fixture.write_text(source)
        cflags = subprocess.check_output(
            ["pkg-config", "--cflags", "sqlite3", "json-c"], text=True
        ).split()
        libs = subprocess.check_output(
            ["pkg-config", "--libs", "sqlite3", "json-c"], text=True
        ).split()
        cc = os.environ.get("CC", "cc")
        subprocess.run(
            [cc, "-std=c11", "-Wall", "-Wextra", "-Werror", *cflags,
             str(fixture), "-o", str(binary), *libs], check=True
        )
        result = subprocess.run([str(binary)], check=True, text=True,
                                capture_output=True)
        print(result.stdout.strip())


if __name__ == "__main__":
    main()

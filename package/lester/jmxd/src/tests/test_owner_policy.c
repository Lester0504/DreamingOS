#include "../webd/webd_owner_policy.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void sql(sqlite3 *db, const char *s)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, s, NULL, NULL, &err);
    if (rc != SQLITE_OK) fprintf(stderr, "%s: %s\n", s, err);
    sqlite3_free(err);
    assert(rc == SQLITE_OK);
}

static int number(sqlite3 *db, const char *s)
{
    sqlite3_stmt *st;
    assert(sqlite3_prepare_v2(db, s, -1, &st, NULL) == SQLITE_OK);
    assert(sqlite3_step(st) == SQLITE_ROW);
    int n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

static sqlite3 *fresh(void)
{
    sqlite3 *db;
    assert(sqlite3_open(":memory:", &db) == SQLITE_OK);
    sql(db, "CREATE TABLE web_users(username TEXT PRIMARY KEY,role TEXT,status TEXT,updated_at INTEGER);"
            "CREATE TABLE setup_state(id INTEGER PRIMARY KEY,initialized INTEGER,completed_by TEXT);");
    return db;
}

int main(void)
{
    sqlite3 *db = fresh();
    assert(webd_owner_policy_install(db) == 0);
    sql(db, "INSERT INTO web_users VALUES('first','admin','enabled',0);"
            "INSERT INTO web_users VALUES('second','admin','enabled',0);");
    assert(number(db, "SELECT COUNT(*) FROM web_users WHERE role='owner'") == 1);
    const char *blocked[] = {
        "UPDATE web_users SET role='admin' WHERE username='first'",
        "UPDATE web_users SET status='disabled' WHERE username='first'",
        "DELETE FROM web_users WHERE username='first'"
    };
    for (unsigned i = 0; i < sizeof(blocked)/sizeof(blocked[0]); i++) {
        assert(sqlite3_exec(db, blocked[i], NULL, NULL, NULL) != SQLITE_OK);
        assert(strstr(sqlite3_errmsg(db), "last_owner_protected"));
    }
    sql(db, "UPDATE web_users SET role='owner' WHERE username='second';"
            "UPDATE web_users SET role='admin' WHERE username='first';");
    assert(sqlite3_exec(db, "UPDATE web_users SET role='admin' WHERE username='second'",
                        NULL, NULL, NULL) != SQLITE_OK);
    assert(webd_owner_policy_install(db) == 0);
    assert(webd_owner_migrate_setup(db) == 0);
    sqlite3_close(db);

    db = fresh();
    sql(db, "INSERT INTO web_users VALUES('old','admin','enabled',0);"
            "INSERT INTO web_users VALUES('other','admin','enabled',0);");
    assert(webd_owner_policy_install(db) == 0);
    assert(webd_owner_migrate_setup(db) == 0);
    assert(number(db, "SELECT COUNT(*) FROM web_users WHERE role='owner'") == 0);
    sql(db, "INSERT INTO setup_state VALUES(1,1,'old');");
    assert(webd_owner_migrate_setup(db) == 0);
    assert(number(db, "SELECT COUNT(*) FROM web_users WHERE username='old' AND role='owner'") == 1);
    assert(number(db, "SELECT COUNT(*) FROM web_users WHERE username='other' AND role='admin'") == 1);
    assert(webd_owner_migrate_setup(db) == 0);
    assert(number(db, "SELECT COUNT(*) FROM web_owner_history") == 1);
    sqlite3_close(db);

    const char *ineligible[] = {
        "INSERT INTO setup_state VALUES(1,0,'old')",
        "INSERT INTO setup_state VALUES(1,1,'missing')",
        "INSERT INTO setup_state VALUES(1,1,'old'); UPDATE web_users SET status='disabled'",
        "DROP TABLE setup_state"
    };
    for (unsigned i = 0; i < sizeof(ineligible)/sizeof(ineligible[0]); i++) {
        db = fresh();
        sql(db, "INSERT INTO web_users VALUES('old','admin','enabled',0)");
        sql(db, ineligible[i]);
        assert(webd_owner_policy_install(db) == 0);
        assert(webd_owner_migrate_setup(db) == 0);
        assert(number(db, "SELECT COUNT(*) FROM web_users WHERE role='owner'") == 0);
        sqlite3_close(db);
    }
    db = fresh();
    assert(webd_owner_policy_install(db) == 0);
    sql(db, "INSERT INTO web_users VALUES('first','owner','enabled',0);"
            "INSERT INTO web_users VALUES('second','owner','enabled',0);");
    /* A bulk write cannot demote/delete both owners in one statement. */
    assert(sqlite3_exec(db, "UPDATE web_users SET role='admin'", NULL, NULL, NULL) != SQLITE_OK);
    assert(number(db, "SELECT COUNT(*) FROM web_users WHERE role='owner'") == 2);
    assert(sqlite3_exec(db, "DELETE FROM web_users", NULL, NULL, NULL) != SQLITE_OK);
    assert(number(db, "SELECT COUNT(*) FROM web_users") == 2);
    sql(db, "UPDATE web_users SET status='disabled' WHERE username='second'");
    assert(sqlite3_exec(db, "DELETE FROM web_users WHERE username='first'", NULL, NULL, NULL) != SQLITE_OK);
    sqlite3_close(db);
    puts("owner policy: first account, legacy evidence, no guessing, transfer, last-owner guards PASS");
    return 0;
}

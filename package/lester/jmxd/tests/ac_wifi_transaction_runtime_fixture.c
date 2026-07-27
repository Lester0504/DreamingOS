// SPDX-License-Identifier: GPL-2.0-or-later
/* Runtime contract for the W3 wifi transaction orchestration: one apply
 * fans out atomically to a transaction, per-AP targets and per-AP queued
 * config jobs; revision conflict and invalid targets roll back the whole
 * fan-out; replay by (actor, idempotency_key) is idempotent; status joins
 * targets with config jobs. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>
#include <sqlite3.h>

extern sqlite3 *g_ac_db;
int ac_db_init(void);
void ac_db_close(void);
int ac_db_wifi_transaction_apply(const char *, const char *, const char *,
                                 int64_t, const char *, int64_t, char *,
                                 char *, size_t);
struct json_object *ac_db_wifi_transaction_status_json(const char *);

enum {
    AC_CONFIG_JOB_ERROR = -1,
    AC_CONFIG_JOB_OK = 0,
    AC_CONFIG_JOB_IDEMPOTENT = 1,
    AC_CONFIG_JOB_NOT_FOUND = 2,
    AC_CONFIG_JOB_CONFLICT = 3,
    AC_CONFIG_JOB_INVALID = 4,
};

#define ACTOR "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
#define AP_A "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
#define AP_B "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
#define DIGEST \
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define DIGEST_B \
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

#define CHECK(label, expr) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "FAIL %s\n", label); \
            return 1; \
        } \
    } while (0)

static int scalar(const char *sql)
{
    sqlite3_stmt *st = NULL;
    int value = -1;

    if (sqlite3_prepare_v2(g_ac_db, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        value = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return value;
}

static struct json_object *field(struct json_object *o, const char *n)
{
    struct json_object *v = NULL;

    return o && json_object_object_get_ex(o, n, &v) ? v : NULL;
}

int main(void)
{
    char tx[37] = { 0 };
    char err[64] = { 0 };
    struct json_object *status;
    struct json_object *targets;

    CHECK("init", ac_db_init() == 0);

    /* Two-target apply creates 1 transaction, 2 targets, 2 queued jobs. */
    const char *body =
        "[{\"ap_id\":\"" AP_A "\",\"candidate\":\"{\\\"c\\\":1}\","
        "\"candidate_digest\":\"" DIGEST "\"},"
        "{\"ap_id\":\"" AP_B "\",\"candidate\":\"{\\\"c\\\":2}\","
        "\"candidate_digest\":\"" DIGEST_B "\"}]";
    CHECK("apply", ac_db_wifi_transaction_apply(ACTOR, "web.tx.1",
              "all_or_nothing", 0, body, 1000, tx, err, sizeof(err)) ==
          AC_CONFIG_JOB_OK);
    CHECK("tx uuid", strlen(tx) == 36);
    CHECK("one transaction", scalar("SELECT COUNT(*) FROM ac_transactions")
          == 1);
    CHECK("two targets",
          scalar("SELECT COUNT(*) FROM ac_transaction_targets") == 2);
    CHECK("two jobs queued", scalar("SELECT COUNT(*) FROM ac_config_jobs "
              "WHERE state='queued' AND transaction_id<>''") == 2);

    /* Replay by (actor, key) returns the same transaction, no new rows. */
    char tx2[37] = { 0 };
    CHECK("replay", ac_db_wifi_transaction_apply(ACTOR, "web.tx.1",
              "all_or_nothing", 0, body, 1001, tx2, err, sizeof(err)) ==
          AC_CONFIG_JOB_IDEMPOTENT);
    CHECK("replay same tx", !strcmp(tx, tx2));
    CHECK("still one transaction",
          scalar("SELECT COUNT(*) FROM ac_transactions") == 1);

    /* Revision conflict rolls back with no side effects. */
    CHECK("revision", ac_db_wifi_transaction_apply(ACTOR, "web.tx.2",
              "per_target", 99, body, 1002, tx2, err, sizeof(err)) ==
          AC_CONFIG_JOB_CONFLICT);
    CHECK("revision error", !strcmp(err, "revision_conflict"));
    CHECK("no new transaction",
          scalar("SELECT COUNT(*) FROM ac_transactions") == 1);

    /* Invalid target (bad digest) rolls back the entire fan-out — the
     * first valid target must not leak a config job. */
    const char *bad =
        "[{\"ap_id\":\"" AP_A "\",\"candidate\":\"{}\","
        "\"candidate_digest\":\"" DIGEST "\"},"
        "{\"ap_id\":\"" AP_B "\",\"candidate\":\"{}\","
        "\"candidate_digest\":\"not-a-digest\"}]";
    CHECK("bad target", ac_db_wifi_transaction_apply(ACTOR, "web.tx.3",
              "all_or_nothing", 0, bad, 1003, tx2, err, sizeof(err)) ==
          AC_CONFIG_JOB_INVALID);
    CHECK("atomic rollback",
          scalar("SELECT COUNT(*) FROM ac_transactions") == 1);
    CHECK("no partial jobs", scalar("SELECT COUNT(*) FROM ac_config_jobs")
          == 2);

    /* Bad consistency rejected. */
    CHECK("bad consistency", ac_db_wifi_transaction_apply(ACTOR, "web.tx.4",
              "whenever", 0, body, 1004, tx2, err, sizeof(err)) ==
          AC_CONFIG_JOB_INVALID);

    /* Status joins targets with jobs; jobs are queued, no outcome yet. */
    status = ac_db_wifi_transaction_status_json(tx);
    CHECK("status ok", json_object_get_boolean(field(status, "ok")));
    CHECK("status state", !strcmp(json_object_get_string(
              field(status, "state")), "pending"));
    targets = field(status, "targets");
    CHECK("status targets", targets &&
          json_object_array_length(targets) == 2);
    {
        struct json_object *first = json_object_array_get_idx(targets, 0);

        CHECK("target job_state", !strcmp(json_object_get_string(
                  field(first, "job_state")), "queued"));
        CHECK("target job_outcome null", json_object_is_type(
                  field(first, "job_outcome"), json_type_null));
    }
    json_object_put(status);

    status = ac_db_wifi_transaction_status_json(
        "ffffffff-ffff-4fff-8fff-ffffffffffff");
    CHECK("missing status", !json_object_get_boolean(field(status, "ok")));
    json_object_put(status);

    ac_db_close();
    printf("ok\n");
    return 0;
}

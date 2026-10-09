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

struct ac_config_job {
    char job_id[37];
    char ap_id[37];
    char state[17];
    char idempotency_key[129];
    char candidate_digest[72];
    int64_t created_at;
    int64_t updated_at;
    int64_t lease_expires_at;
    char session_epoch[65];
    char attempt_id[37];
    int64_t dispatch_generation;
    char request_digest[72];
    char finish_id[37];
    char outcome[15];
    char error_code[128];
    char operation[9];
    char rollback_of_job_id[37];
};
int ac_db_config_job_lease_next(const char *, const char *, int64_t,
                                struct ac_config_job *, char **);
int ac_db_config_job_mark_running(const char *, const char *, int64_t,
                                  const char *, const char *, const char *,
                                  int64_t, struct ac_config_job *);
int ac_db_config_job_finish(const char *, const char *, int64_t,
                            const char *, const char *, const char *,
                            const char *, const char *, const char *,
                            const char *, int64_t, struct ac_config_job *);

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
#define EPOCH_A \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define EPOCH_B \
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define BASE_CURRENT ((int64_t)-1)
#define DIGEST \
    "sha256:405485f4df88d2e869ec5a360ce2073e00f17a8c1b8614d8d51445984a6d53f3"
#define DIGEST_B \
    "sha256:500c76731b9453afce2fc9c18ab290ea8015fee781a3749c224de29f58895564"
#define CANDIDATE_A \
    "{\"format\":\"uci-wireless-candidate.v1\",\"candidate_digest\":\"" \
    DIGEST "\",\"sections\":[{\"section\":\"radio0\",\"options\":" \
    "{\"channel\":\"36\"}}]}"
#define CANDIDATE_B \
    "{\"format\":\"uci-wireless-candidate.v1\",\"candidate_digest\":\"" \
    DIGEST_B "\",\"sections\":[{\"section\":\"radio1\",\"options\":" \
    "{\"channel\":\"44\"}}]}"
#define READBACK_A \
    "{\"ok\":true,\"match\":true,\"candidate_digest\":\"" DIGEST \
    "\",\"readback_digest\":\"" DIGEST "\"}"
#define READBACK_B \
    "{\"ok\":true,\"match\":true,\"candidate_digest\":\"" DIGEST_B \
    "\",\"readback_digest\":\"" DIGEST_B "\"}"
#define ROLLBACK_READBACK \
    "{\"ok\":true,\"operation\":\"rollback_readback\"," \
    "\"match\":true,\"mismatches\":[]}"
#define ROLLBACK_BAD_READBACK \
    "{\"ok\":false,\"operation\":\"rollback_readback\"," \
    "\"match\":false,\"mismatches\":[{\"section\":\"radio0\"}]}"
#define FINISH_A "11111111-aaaa-4aaa-8aaa-111111111111"
#define FINISH_B "22222222-bbbb-4bbb-8bbb-222222222222"
#define FINISH_ROLLBACK_A "33333333-aaaa-4aaa-8aaa-333333333333"
#define FINISH_SUCCESS_A "44444444-aaaa-4aaa-8aaa-444444444444"
#define FINISH_SUCCESS_B "55555555-bbbb-4bbb-8bbb-555555555555"
#define FINISH_DIVERGE_A "66666666-aaaa-4aaa-8aaa-666666666666"
#define FINISH_DIVERGE_B "77777777-bbbb-4bbb-8bbb-777777777777"
#define FINISH_ROLLBACK_FAIL_A "88888888-aaaa-4aaa-8aaa-888888888888"

#ifdef AC_DB_WIFI_FAILURE_TEST
static int wifi_events;
int ac_wifi_failure_test_send(struct json_object *event)
{
    struct json_object *detail = NULL, *value = NULL;
    const char *wire = json_object_to_json_string(event);
    if (strstr(wire, "candidate_json") || strstr(wire, "sections") ||
        strstr(wire, "readback_json")) abort();
    if (!json_object_object_get_ex(event, "detail_json", &detail) ||
        !json_object_object_get_ex(detail, "actor", &value) ||
        strcmp(json_object_get_string(value), ACTOR) ||
        !json_object_object_get_ex(detail, "ap_id", &value) ||
        strlen(json_object_get_string(value)) != 36 ||
        !json_object_object_get_ex(detail, "failure_stage", &value) ||
        strcmp(json_object_get_string(value), "ac.wifi.transaction")) abort();
    ++wifi_events;
    return 0;
}
#endif

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

static int text_value(const char *sql, char *out, size_t out_len)
{
    sqlite3_stmt *st = NULL;
    int ok = 0;

    if (out && out_len)
        out[0] = '\0';
    if (sqlite3_prepare_v2(g_ac_db, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW && sqlite3_column_text(st, 0)) {
        snprintf(out, out_len, "%s", sqlite3_column_text(st, 0));
        ok = 1;
    }
    sqlite3_finalize(st);
    return ok;
}

static int run_job(const char *ap_id, const char *epoch, int64_t now,
                   struct ac_config_job *job, char **candidate)
{
    int rc = ac_db_config_job_lease_next(ap_id, epoch, now, job, candidate);

    if (rc != AC_CONFIG_JOB_OK)
        return rc;
    return ac_db_config_job_mark_running(job->job_id, job->attempt_id,
        job->dispatch_generation, job->request_digest, ap_id, epoch,
        now + 1, job);
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
    CHECK("adopt targets", sqlite3_exec(g_ac_db,
              "INSERT INTO ac_aps(ap_id,site_id,name,adoption_state,"
              "last_seen_at,readback_digest) VALUES"
              "('" AP_A "','default','AP A','adopted',1000,'" DIGEST "'),"
              "('" AP_B "','default','AP B','adopted',1000,'" DIGEST_B "')",
              NULL, NULL, NULL) == SQLITE_OK);
    CHECK("write sessions", sqlite3_exec(g_ac_db,
              "INSERT INTO ac_ap_runtime(ap_id,boot_id,control_protocol_version,"
              "write_capable,session_connected) VALUES"
              "('" AP_A "','" EPOCH_A "',3,1,1),"
              "('" AP_B "','" EPOCH_B "',3,1,1)",
              NULL, NULL, NULL) == SQLITE_OK);

    /* Two-target apply creates 1 transaction, 2 targets, 2 queued jobs. */
    const char *body =
        "[{\"ap_id\":\"" AP_A "\",\"candidate\":"
        "\"{\\\"format\\\":\\\"uci-wireless-candidate.v1\\\","
        "\\\"candidate_digest\\\":\\\"" DIGEST "\\\","
        "\\\"sections\\\":[{\\\"section\\\":\\\"radio0\\\","
        "\\\"options\\\":{\\\"channel\\\":\\\"36\\\"}}]}\","
        "\"candidate_digest\":\"" DIGEST "\"},"
        "{\"ap_id\":\"" AP_B "\",\"candidate\":"
        "\"{\\\"format\\\":\\\"uci-wireless-candidate.v1\\\","
        "\\\"candidate_digest\\\":\\\"" DIGEST_B "\\\","
        "\\\"sections\\\":[{\\\"section\\\":\\\"radio1\\\","
        "\\\"options\\\":{\\\"channel\\\":\\\"44\\\"}}]}\","
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
              "per_target", 0, body, 1001, tx2, err, sizeof(err)) ==
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
        "[{\"ap_id\":\"" AP_A "\",\"candidate\":\"" CANDIDATE_A "\","
        "\"candidate_digest\":\"not-a-digest\"}]";
    CHECK("bad target", ac_db_wifi_transaction_apply(ACTOR, "web.tx.3",
              "all_or_nothing", 1, bad, 1003, tx2, err, sizeof(err)) ==
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
        CHECK("target previous digest", field(first, "previous_digest") != NULL);
        CHECK("target readback digest", field(first, "readback_digest") != NULL);
        CHECK("target error", field(first, "error_code") != NULL);
        CHECK("target readback null", json_object_is_type(
                  field(first, "readback"), json_type_null));
    }
    json_object_put(status);

    status = ac_db_wifi_transaction_status_json(
        "ffffffff-ffff-4fff-8fff-ffffffffffff");
    CHECK("missing status", !json_object_get_boolean(field(status, "ok")));
    json_object_put(status);

    /* AP A applies, AP B fails, so A receives a separate compensation job
     * bound to the original apply journal. The transaction closes only after
     * compensation readback proves A returned to its previous state. */
    {
        struct ac_config_job a = { 0 };
        struct ac_config_job b = { 0 };
        struct ac_config_job rollback = { 0 };
        char *candidate = NULL;
        char tx_state[32];
        char tx_replay[37] = { 0 };

        CHECK("lease A", run_job(AP_A, EPOCH_A, 1100, &a, &candidate) ==
              AC_CONFIG_JOB_OK && !strcmp(a.operation, "apply"));
        free(candidate);
        candidate = NULL;
        CHECK("finish A applied", ac_db_config_job_finish(a.job_id,
              a.attempt_id, a.dispatch_generation, a.request_digest, AP_A,
              EPOCH_A, FINISH_A, "applied", "", READBACK_A, 1102, &a) ==
              AC_CONFIG_JOB_OK);
        CHECK("lease B", run_job(AP_B, EPOCH_B, 1110, &b, &candidate) ==
              AC_CONFIG_JOB_OK && !strcmp(b.operation, "apply"));
        free(candidate);
        candidate = NULL;
        CHECK("finish B failed", ac_db_config_job_finish(b.job_id,
              b.attempt_id, b.dispatch_generation, b.request_digest, AP_B,
              EPOCH_B, FINISH_B, "failed", "readback_failed", "", 1112,
              &b) == AC_CONFIG_JOB_OK);
#ifdef AC_DB_WIFI_FAILURE_TEST
        CHECK("async failure published", wifi_events == 1);
        CHECK("async failure centrally audited", scalar(
              "SELECT COUNT(*) FROM ac_ap_audit_events WHERE ap_id='" AP_B
              "' AND action='WIFI_CONFIG_APPLY_FAILED' AND result='failed' "
              "AND failure_reason='readback_failed'") == 1);
        CHECK("async receipt replay", ac_db_config_job_finish(b.job_id,
              b.attempt_id, b.dispatch_generation, b.request_digest, AP_B,
              EPOCH_B, FINISH_B, "failed", "readback_failed", "", 1112,
              &b) == AC_CONFIG_JOB_IDEMPOTENT && wifi_events == 1);
#endif
        CHECK("one compensation queued", scalar(
              "SELECT COUNT(*) FROM ac_config_jobs WHERE operation='rollback' "
              "AND state='queued'") == 1);
        CHECK("transaction rolling back", text_value(
              "SELECT state FROM ac_transactions WHERE idempotency_key='web.tx.1'",
              tx_state, sizeof(tx_state)) && !strcmp(tx_state, "rolling_back"));
        CHECK("lease rollback A", run_job(AP_A, EPOCH_A, 1120, &rollback,
              &candidate) == AC_CONFIG_JOB_OK &&
              !strcmp(rollback.operation, "rollback") &&
              !strcmp(rollback.rollback_of_job_id, a.job_id));
        free(candidate);
        candidate = NULL;
        CHECK("finish rollback A", ac_db_config_job_finish(rollback.job_id,
              rollback.attempt_id, rollback.dispatch_generation,
              rollback.request_digest, AP_A, EPOCH_A, FINISH_ROLLBACK_A,
              "rolled_back", "transaction_peer_failed", ROLLBACK_READBACK,
              1122, &rollback) == AC_CONFIG_JOB_OK);
        CHECK("transaction rolled back", text_value(
              "SELECT state FROM ac_transactions WHERE idempotency_key='web.tx.1'",
              tx_state, sizeof(tx_state)) && !strcmp(tx_state, "rolled_back"));
        CHECK("terminal replay", ac_db_wifi_transaction_apply(ACTOR,
              "web.tx.1", "all_or_nothing", 0, body, 1123, tx_replay, err,
              sizeof(err)) == AC_CONFIG_JOB_IDEMPOTENT);
        CHECK("terminal replay identity", !strcmp(tx_replay, tx));
        CHECK("terminal replay no second writes", scalar(
              "SELECT COUNT(*) FROM ac_config_jobs WHERE transaction_id=("
              "SELECT transaction_id FROM ac_transactions WHERE "
              "idempotency_key='web.tx.1')") == 3);
        CHECK("target evidence", scalar(
              "SELECT COUNT(*) FROM ac_transaction_targets WHERE "
              "transaction_id=(SELECT transaction_id FROM ac_transactions "
              "WHERE idempotency_key='web.tx.1') AND "
              "((ap_id='" AP_A "' AND state='rolled_back' AND rollback_job_id<>'') "
              "OR (ap_id='" AP_B "' AND state='failed'))") == 2);
        CHECK("control state restored", scalar(
              "SELECT COUNT(*) FROM ac_aps WHERE ap_id IN ('" AP_A "','" AP_B
              "') AND desired_revision=0 AND applied_revision=0") == 2);
        status = ac_db_wifi_transaction_status_json(tx);
        CHECK("rolled back status", !strcmp(json_object_get_string(
                  field(status, "state")), "rolled_back"));
        CHECK("rolled back status targets", json_object_array_length(
                  field(status, "targets")) == 2);
        json_object_put(status);
    }

    /* A second two-AP transaction proves the happy path reaches applied. */
    {
        struct ac_config_job a = { 0 };
        struct ac_config_job b = { 0 };
        char *candidate = NULL;
        char tx_success[37] = { 0 };
        char tx_state[32];

        CHECK("success refresh targets", sqlite3_exec(g_ac_db,
              "UPDATE ac_aps SET last_seen_at=1200 WHERE ap_id IN ('" AP_A
              "','" AP_B "')", NULL, NULL, NULL) == SQLITE_OK);
        CHECK("success apply", ac_db_wifi_transaction_apply(ACTOR,
              "web.tx.success", "all_or_nothing", BASE_CURRENT, body, 1200,
              tx_success, err, sizeof(err)) == AC_CONFIG_JOB_OK);
        CHECK("success run A", run_job(AP_A, EPOCH_A, 1201, &a,
              &candidate) == AC_CONFIG_JOB_OK);
        free(candidate);
        candidate = NULL;
        CHECK("success finish A", ac_db_config_job_finish(a.job_id,
              a.attempt_id, a.dispatch_generation, a.request_digest, AP_A,
              EPOCH_A, FINISH_SUCCESS_A, "applied", "", READBACK_A, 1203,
              &a) == AC_CONFIG_JOB_OK);
        CHECK("success run B", run_job(AP_B, EPOCH_B, 1204, &b,
              &candidate) == AC_CONFIG_JOB_OK);
        free(candidate);
        candidate = NULL;
        CHECK("success finish B", ac_db_config_job_finish(b.job_id,
              b.attempt_id, b.dispatch_generation, b.request_digest, AP_B,
              EPOCH_B, FINISH_SUCCESS_B, "applied", "", READBACK_B, 1206,
              &b) == AC_CONFIG_JOB_OK);
        CHECK("success transaction applied", text_value(
              "SELECT state FROM ac_transactions WHERE idempotency_key="
              "'web.tx.success'", tx_state, sizeof(tx_state)) &&
              !strcmp(tx_state, "applied"));
        CHECK("success has no rollback jobs", scalar(
              "SELECT COUNT(*) FROM ac_config_jobs WHERE transaction_id=("
              "SELECT transaction_id FROM ac_transactions WHERE "
              "idempotency_key='web.tx.success') AND operation='rollback'") == 0);
    }

    /* A failed compensation readback leaves an explicit divergent terminal
     * state and preserves per-AP evidence instead of claiming atomicity. */
    {
        struct ac_config_job a = { 0 };
        struct ac_config_job b = { 0 };
        struct ac_config_job rollback = { 0 };
        char *candidate = NULL;
        char tx_diverge[37] = { 0 };
        char tx_state[32];

        CHECK("diverge refresh targets", sqlite3_exec(g_ac_db,
              "UPDATE ac_aps SET last_seen_at=1300 WHERE ap_id IN ('" AP_A
              "','" AP_B "')", NULL, NULL, NULL) == SQLITE_OK);
        CHECK("diverge apply", ac_db_wifi_transaction_apply(ACTOR,
              "web.tx.diverge", "all_or_nothing", BASE_CURRENT, body, 1300,
              tx_diverge, err, sizeof(err)) == AC_CONFIG_JOB_OK);
        CHECK("diverge run A", run_job(AP_A, EPOCH_A, 1301, &a,
              &candidate) == AC_CONFIG_JOB_OK);
        free(candidate);
        candidate = NULL;
        CHECK("diverge finish A", ac_db_config_job_finish(a.job_id,
              a.attempt_id, a.dispatch_generation, a.request_digest, AP_A,
              EPOCH_A, FINISH_DIVERGE_A, "applied", "", READBACK_A, 1303,
              &a) == AC_CONFIG_JOB_OK);
        CHECK("diverge run B", run_job(AP_B, EPOCH_B, 1304, &b,
              &candidate) == AC_CONFIG_JOB_OK);
        free(candidate);
        candidate = NULL;
        CHECK("diverge finish B", ac_db_config_job_finish(b.job_id,
              b.attempt_id, b.dispatch_generation, b.request_digest, AP_B,
              EPOCH_B, FINISH_DIVERGE_B, "failed", "readback_failed", "",
              1306, &b) == AC_CONFIG_JOB_OK);
        CHECK("diverge run rollback", run_job(AP_A, EPOCH_A, 1307,
              &rollback, &candidate) == AC_CONFIG_JOB_OK &&
              !strcmp(rollback.operation, "rollback"));
        free(candidate);
        candidate = NULL;
        CHECK("diverge rollback finish", ac_db_config_job_finish(
              rollback.job_id, rollback.attempt_id,
              rollback.dispatch_generation, rollback.request_digest, AP_A,
              EPOCH_A, FINISH_ROLLBACK_FAIL_A, "failed", "rollback_failed",
              ROLLBACK_BAD_READBACK, 1309, &rollback) == AC_CONFIG_JOB_OK);
        CHECK("transaction rollback failed", text_value(
              "SELECT state FROM ac_transactions WHERE idempotency_key="
              "'web.tx.diverge'", tx_state, sizeof(tx_state)) &&
              !strcmp(tx_state, "rollback_failed"));
        CHECK("divergent target visible", scalar(
              "SELECT COUNT(*) FROM ac_transaction_targets WHERE "
              "transaction_id=(SELECT transaction_id FROM ac_transactions "
              "WHERE idempotency_key='web.tx.diverge') AND ap_id='" AP_A
              "' AND state='rollback_failed' AND error_code="
              "'rollback_readback_verification_failed'") == 1);
    }

    /* An MLO merge carries `dreamingwrt_mlo_members`: the JSON record of what
     * each wifi-iface was bound to before the merge, so turning MLO off can put
     * them back instead of leaving them disabled.  Its value holds double
     * quotes and is far longer than the 64-byte scalar limit every other option
     * lives under, which is what made the page's MLO toggle fail with
     * candidate_value_invalid after the option name had already been allowed.
     * APD applies the identical check from ../src/ap_mlo_members.h. */
    {
        static const char members[] =
            "{\"version\":1,\"members\":[{\"section\":\"wifi0\","
            "\"device\":[\"radio0\",\"radio1\",\"radio2\"],"
            "\"disabled\":\"0\"}]}";
        static const char digest[] = "sha256:"
            "e40e1a0ae79ab79952e981d668e375cf30378dc255f6d3ae131e5aad865b68b0";
        struct json_object *candidate = json_object_new_object();
        struct json_object *sections = json_object_new_array();
        struct json_object *entry = json_object_new_object();
        struct json_object *options = json_object_new_object();
        struct json_object *body_array = json_object_new_array();
        struct json_object *target = json_object_new_object();
        char tx_mlo[37] = { 0 };
        int rc;

        json_object_object_add(options, "dreamingwrt_mlo_members",
                               json_object_new_string(members));
        json_object_object_add(entry, "section",
                               json_object_new_string("wifi0"));
        json_object_object_add(entry, "options", options);
        json_object_array_add(sections, entry);
        json_object_object_add(candidate, "format",
            json_object_new_string("uci-wireless-candidate.v1"));
        json_object_object_add(candidate, "candidate_digest",
                               json_object_new_string(digest));
        json_object_object_add(candidate, "sections", sections);
        json_object_object_add(target, "ap_id", json_object_new_string(AP_A));
        json_object_object_add(target, "candidate",
            json_object_new_string(json_object_to_json_string_ext(
                candidate, JSON_C_TO_STRING_PLAIN)));
        json_object_object_add(target, "candidate_digest",
                               json_object_new_string(digest));
        json_object_array_add(body_array, target);
        rc = ac_db_wifi_transaction_apply(ACTOR, "web.tx.mlo",
                "per_target", BASE_CURRENT,
                json_object_to_json_string_ext(body_array,
                                               JSON_C_TO_STRING_PLAIN),
                1005, tx_mlo, err, sizeof(err));
        if (rc != AC_CONFIG_JOB_OK)
            fprintf(stderr, "mlo members apply error: %s\n", err);
        CHECK("mlo members accepted", rc == AC_CONFIG_JOB_OK);
        CHECK("mlo members job queued",
              scalar("SELECT COUNT(*) FROM ac_config_jobs WHERE "
                     "candidate_json LIKE '%dreamingwrt_mlo_members%'") == 1);
        json_object_put(body_array);
        json_object_put(candidate);
    }

    ac_db_close();
    printf("ok\n");
    return 0;
}

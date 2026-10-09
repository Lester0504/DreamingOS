/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sqlite3.h>
#include "safeops/port_snapshot.h"
#include "safeops/rollback_claim.h"
#include "safeops/revision_sequence.h"
#include "safeops/network_rollback_rpc.h"

#define WEBD_NETWORK_CONFIG_PATH "/fixture/network"
#define DWRT_NETWORK_CONFIG WEBD_NETWORK_CONFIG_PATH
static sqlite3 *g_app_db;
static int fail_stage, calls[3], port_calls, digest_failed;
static struct json_object *port_payload;
static int g_pending_apply_id;
static int64_t fixture_now = 2000;
struct uloop_timeout { int cancelled; };
static struct uloop_timeout g_rollback_timer;

struct rollback_scan_result {
    int rolled_back, failed, skipped;
    char error[256];
};

static sqlite3_stmt *app_prepare(const char *sql)
{
    sqlite3_stmt *st = NULL;
    assert(sqlite3_prepare_v2(g_app_db, sql, -1, &st, NULL) == SQLITE_OK);
    return st;
}

static struct json_object *webd_obj_child_obj(struct json_object *obj,
                                             const char *key)
{
    struct json_object *value = NULL;
    if (obj && json_object_object_get_ex(obj, key, &value) &&
        json_object_is_type(value, json_type_object))
        return value;
    return NULL;
}

static int app_sha256_file(const char *path, char *out)
{
    (void)path;
    if (digest_failed)
        return -1;
    memset(out, 'a', 64);
    out[64] = '\0';
    return 0;
}

static int rollback_sha256_file(const char *path, char *out)
{
    if (app_sha256_file(path, out) != 0)
        return -1;
    memmove(out + 7, out, 65);
    memcpy(out, "sha256:", 7);
    return 0;
}

static int64_t now_s(void) { return fixture_now; }
static int app_nc_json_int(struct json_object *obj, const char *key, int fallback)
{
    struct json_object *value = NULL;
    return obj && json_object_object_get_ex(obj, key, &value) && value ?
        json_object_get_int(value) : fallback;
}
static int app_step_done(sqlite3_stmt *st)
{
    return sqlite3_step(st) == SQLITE_DONE ? 0 : -1;
}
static void uloop_timeout_cancel(struct uloop_timeout *t) { t->cancelled = 1; }

static int stage(int n, char *err, size_t len)
{
    calls[n - 1]++;
    if (fail_stage != n)
        return 0;
    snprintf(err, len, "stage_%d_failed", n);
    return -1;
}

static int webd_network_config_restore(const char *path, char *err, size_t len)
{
    (void)path;
    return stage(1, err, len);
}

static int webd_network_reload_runtime(char *err, size_t len)
{
    return stage(2, err, len);
}

static int webd_port_config_restore_task(int task_id, char *err, size_t len)
{
    (void)task_id;
    return stage(3, err, len);
}

static int restore_network_snapshot(const char *path, char *err, size_t len)
{
    return webd_network_config_restore(path, err, len);
}

static int init_run_network_reload(char *err, size_t len)
{
    return webd_network_reload_runtime(err, len);
}

static int init_ubus_port_restore(const char *payload, char *err, size_t len)
{
    port_calls++;
    if (port_payload)
        json_object_put(port_payload);
    port_payload = json_tokener_parse(payload);
    return stage(3, err, len);
}

/* Extracted production functions; all hardware/system calls above are stubs. */
#include "safeops_rollback_impl.inc"

static void reset_task(const char *changes)
{
    sqlite3_stmt *st;
    assert(sqlite3_exec(g_app_db, "DELETE FROM config_apply_tasks", NULL, NULL, NULL)
           == SQLITE_OK);
    st = app_prepare("INSERT INTO config_apply_tasks(id,state,snapshot_path,"
                     "applied_digest,changes_json,config_revision) "
                     "VALUES(1,'pending','/fixture/snapshot','',?1,1)");
    sqlite3_bind_text(st, 1, changes, -1, SQLITE_TRANSIENT);
    assert(sqlite3_step(st) == SQLITE_DONE);
    sqlite3_finalize(st);
    memset(calls, 0, sizeof(calls));
    port_calls = 0;
    digest_failed = 0;
}

static void test_payload(void)
{
    struct json_object *changes, *payload, *value;
    changes = json_tokener_parse(
        "{\"ifname\":\"eth3\",\"plan\":{\"current_port\":{\"native_vlan\":20}}}");
    payload = safeops_port_restore_payload(changes);
    assert(payload);
    assert(json_object_object_length(payload) == 2);
    assert(!json_object_object_get_ex(payload, "configured_speed_mbps", &value));
    assert(!json_object_object_get_ex(payload, "configured_autoneg", &value));
    assert(!json_object_object_get_ex(payload, "tagged_vlans", &value));
    assert(!json_object_object_get_ex(payload, "display_name", &value));
    json_object_put(payload);
    json_object_put(changes);
    changes = json_tokener_parse(
        "{\"plan\":{\"ifname\":\"eth3\",\"current_port\":{"
        "\"display_name\":\"LAN 3\",\"alias\":\"\","
        "\"configured_speed_mbps\":100,\"config\":{"
        "\"configured_speed_mbps\":0,\"configured_duplex\":\"\","
        "\"configured_autoneg\":-1,\"sort_order\":0,\"tagged_vlans\":[],"
        "\"poe_enabled\":false}}}}");
    payload = safeops_port_restore_payload(changes);
    assert(payload);
    assert(json_object_object_get_ex(payload, "configured_speed_mbps", &value));
    assert(json_object_get_int(value) == 0);
    assert(json_object_object_get_ex(payload, "configured_autoneg", &value));
    assert(json_object_get_int(value) == -1);
    assert(json_object_object_get_ex(payload, "display_name", &value));
    assert(!strcmp(json_object_get_string(value), ""));
    assert(!json_object_object_get_ex(payload, "poe_enabled", &value));
    json_object_put(payload);
    json_object_put(changes);
    assert(!safeops_port_restore_payload(NULL));
}

static void test_rollback_stages(void)
{
    const char *changes = "{\"ifname\":\"eth3\",\"plan\":{"
        "\"vlan_profile_present\":true,\"current_port\":{\"native_vlan\":20}}}";
    int i;

    for (i = 0; i <= 3; i++) {
        struct webd_rollback_result result;
        struct rollback_scan_result scan = {0};
        sqlite3_stmt *st;
        fail_stage = i;
        reset_task(changes);
        assert((webd_config_rollback_execute(1, "timeout", &result) == 0) == (i == 0));
        assert(result.success == (i == 0));
        assert(calls[0] == 1 && calls[1] == (i != 1) &&
               calls[2] == (i != 1 && i != 2));
        reset_task(changes);
        assert((auto_rollback_one(g_app_db, 1, 1, "", "/fixture/snapshot", &scan) == 0)
               == (i == 0));
        assert(scan.rolled_back == (i == 0) && scan.failed == (i != 0));
        st = app_prepare("SELECT state,rollback_applied,rollback_reason "
                         "FROM config_apply_tasks WHERE id=1");
        assert(sqlite3_step(st) == SQLITE_ROW);
        assert(!strcmp((const char *)sqlite3_column_text(st, 0),
                       i == 0 ? "rolled_back" : "rollback_failed"));
        assert(sqlite3_column_int(st, 1) == (i == 0));
        assert(sqlite3_column_bytes(st, 2) > 0);
        sqlite3_finalize(st);
    }
}

static void test_missing_port_snapshot(void)
{
    char err[160];
    fail_stage = 0;
    reset_task("{}");
    assert(init_restore_physical_port(g_app_db, 1, err, sizeof(err)) == 0);
    assert(!port_calls);
    reset_task("{\"plan\":{\"speed_present\":true}}");
    assert(init_restore_physical_port(g_app_db, 1, err, sizeof(err)) == -1);
    assert(!strcmp(err, "port_config_payload_missing") && !port_calls);
    reset_task("invalid-json");
    assert(init_restore_physical_port(g_app_db, 1, err, sizeof(err)) == -1);
    assert(!port_calls);
}

static void test_evidence_arrays(void)
{
    struct json_object *tx = json_tokener_parse(
        "{\"health\":{\"limited\":true},\"bridge_vlan_readback\":{\"ok\":true}}");
    sqlite3_stmt *st;
    int i;
    reset_task("{}");
    webd_config_task_store_runtime_evidence(1, tx);
    st = app_prepare("SELECT health_checks_json,readback_json "
                     "FROM config_apply_tasks WHERE id=1");
    assert(sqlite3_step(st) == SQLITE_ROW);
    for (i = 0; i < 2; i++) {
        struct json_object *a = json_tokener_parse(
            (const char *)sqlite3_column_text(st, i));
        assert(json_object_is_type(a, json_type_array));
        assert(json_object_array_length(a) == 1);
        json_object_put(a);
    }
    sqlite3_finalize(st);
    json_object_put(tx);
    tx = webd_config_evidence_array(NULL, "health");
    assert(json_object_array_length(tx) == 0);
    json_object_put(tx);
}

static void test_confirm_deadline(void)
{
    struct json_object *req = json_tokener_parse("{\"task_id\":1}");
    int offset;
    for (offset = -1; offset <= 1; offset++) {
        sqlite3_stmt *st;
        struct json_object *response;
        reset_task("{}");
        st = app_prepare("UPDATE config_apply_tasks SET rollback_deadline=?1");
        sqlite3_bind_int64(st, 1, fixture_now + offset);
        assert(sqlite3_step(st) == SQLITE_DONE);
        sqlite3_finalize(st);
        g_pending_apply_id = 1;
        g_rollback_timer.cancelled = 0;
        response = jmx_config_confirm(req);
        assert(app_nc_json_int(response, "ok", -1) == (offset > 0));
        assert(g_rollback_timer.cancelled == (offset > 0));
        if (offset <= 0)
            assert(!strcmp(json_object_get_string(json_object_object_get(response, "error")),
                           "confirmation_deadline_expired"));
        json_object_put(response);
    }
    reset_task("{}");
    assert(sqlite3_exec(g_app_db,
        "UPDATE config_apply_tasks SET rollback_deadline=0,started_at=1990,"
        "rollback_timeout=90", NULL, NULL, NULL) == SQLITE_OK);
    {
        struct json_object *response = jmx_config_confirm(req);
        assert(app_nc_json_int(response, "ok", -1) == 1);
        json_object_put(response);
    }
    reset_task("{}");
    assert(sqlite3_exec(g_app_db,
        "UPDATE config_apply_tasks SET rollback_deadline=2090,"
        "apply_executor='netconfig_guarded_v1',applied_digest='',readback_json='[]'",
        NULL, NULL, NULL) == SQLITE_OK);
    {
        struct json_object *response = jmx_config_confirm(req);
        assert(app_nc_json_int(response, "ok", -1) == 0);
        assert(!strcmp(json_object_get_string(json_object_object_get(response, "error")),
                       "apply_evidence_unavailable"));
        json_object_put(response);
    }
    assert(sqlite3_exec(g_app_db,
        "UPDATE config_apply_tasks SET applied_digest='sha256:after',"
        "readback_json='[{\"applied\":true}]'", NULL, NULL, NULL) == SQLITE_OK);
    {
        struct json_object *response = jmx_config_confirm(req);
        assert(app_nc_json_int(response, "ok", -1) == 1);
        json_object_put(response);
    }
    json_object_put(req);
}

static void test_digest_guard(void)
{
    int unavailable;
    for (unavailable = 0; unavailable <= 1; unavailable++) {
        struct webd_rollback_result result;
        struct rollback_scan_result scan = {0};
        reset_task("{}");
        assert(sqlite3_exec(g_app_db,
            "UPDATE config_apply_tasks SET applied_digest='sha256:different'",
            NULL, NULL, NULL) == SQLITE_OK);
        digest_failed = unavailable;
        assert(webd_config_rollback_execute(1, "timeout", &result) == -1);
        assert(result.stale && !result.success);
        assert(!calls[0] && !calls[1] && !calls[2]);
        assert(strstr(result.reason, unavailable ? "digest_unavailable" : "digest_mismatch"));
        assert(webd_config_rollback_finish(1, &result, "", "stale", "ok", "stale") == 1);
        reset_task("{}");
        assert(sqlite3_exec(g_app_db,
            "UPDATE config_apply_tasks SET applied_digest='sha256:different'",
            NULL, NULL, NULL) == SQLITE_OK);
        assert(auto_rollback_one(g_app_db, 1, 1, "sha256:different",
                                 "/fixture/snapshot", &scan) == -1);
        assert(scan.skipped == 1);
    }
}

static void test_claim_cas_and_confirm_race(void)
{
    struct json_object *req = json_tokener_parse("{\"task_id\":1}");
    struct json_object *response;

    reset_task("{}");
    assert(safeops_rollback_claim(g_app_db, 1, 1, "", "owner-a", fixture_now) == 1);
    assert(safeops_rollback_claim(g_app_db, 1, 1, "", "owner-b", fixture_now) == 0);
    {
        struct webd_rollback_result result;
        assert(webd_config_rollback_execute(1, "second-webd", &result) == -1);
        assert(result.busy && !result.claimed);
        assert(!strcmp(result.reason, "rollback_in_progress"));
        assert(!calls[0] && !calls[1] && !calls[2]);
    }
    response = jmx_config_confirm(req);
    assert(app_nc_json_int(response, "ok", -1) == 0);
    assert(!strcmp(json_object_get_string(json_object_object_get(response, "error")),
                   "rollback_in_progress"));
    json_object_put(response);

    fixture_now += SAFEOPS_ROLLBACK_LEASE_SECONDS + 1;
    assert(safeops_rollback_claim(g_app_db, 1, 1, "", "owner-b", fixture_now) == 1);
    assert(safeops_rollback_finish(g_app_db, 1, 1, "owner-a", "rolled_back",
                                   fixture_now, "", 1, "", "old-owner") == 0);
    assert(safeops_rollback_finish(g_app_db, 1, 1, "owner-b", "rolled_back",
                                   fixture_now, "", 1, "", "lease-recovered") == 1);

    reset_task("{}");
    assert(sqlite3_exec(g_app_db,
        "UPDATE config_apply_tasks SET config_revision=2,applied_digest='same'",
        NULL, NULL, NULL) == SQLITE_OK);
    assert(safeops_rollback_claim(g_app_db, 1, 1, "same", "old-revision",
                                  fixture_now) == 0);
    assert(safeops_rollback_claim(g_app_db, 1, 2, "same", "current-revision",
                                  fixture_now) == 1);
    json_object_put(req);
}

static void test_revision_sequence(void)
{
    int existing_id, active_id;
    int64_t revision;

    reset_task("{}");
    assert(sqlite3_exec(g_app_db,
        "UPDATE config_apply_tasks SET state='confirmed',idempotency_key='old-key';"
        "DELETE FROM config_apply_revision_sequence;"
        "INSERT INTO config_apply_revision_sequence VALUES(1,2)",
        NULL, NULL, NULL) == SQLITE_OK);
    assert(safeops_revision_begin(g_app_db, "old-key", &existing_id,
                                  &active_id, &revision) == SAFEOPS_REVISION_REPLAY);
    assert(existing_id == 1 && revision == 0);
    assert(safeops_revision_begin(g_app_db, "new-key", &existing_id,
                                  &active_id, &revision) == SAFEOPS_REVISION_READY);
    assert(revision == 2);
    assert(sqlite3_exec(g_app_db,
        "INSERT INTO config_apply_tasks(id,state,config_revision,idempotency_key) "
        "VALUES(2,'pending',2,'new-key');COMMIT",
        NULL, NULL, NULL) == SQLITE_OK);
    assert(safeops_revision_begin(g_app_db, "other-key", &existing_id,
                                  &active_id, &revision) == SAFEOPS_REVISION_ACTIVE);
    assert(active_id == 2);
    assert(sqlite3_exec(g_app_db,
        "UPDATE config_apply_tasks SET state='confirmed' WHERE id=2",
        NULL, NULL, NULL) == SQLITE_OK);
    assert(safeops_revision_begin(g_app_db, "third-key", &existing_id,
                                  &active_id, &revision) == SAFEOPS_REVISION_READY);
    assert(revision == 3);
    assert(sqlite3_exec(g_app_db, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK);
}

static void test_port_restore_response(void)
{
    static const char *const replies[] = {
        "null", "{}", "{\"code\":1}", "{\"data\":{}}",
        "{\"ok\":false}", "{\"ok\":true,\"data\":{\"ok\":false}}",
        "{\"code\":0,\"data\":{\"ok\":true}}", "{\"ok\":true}"
    };
    size_t i;
    for (i = 0; i < sizeof(replies) / sizeof(replies[0]); i++) {
        struct json_object *reply = json_tokener_parse(replies[i]);
        assert(init_port_restore_response_ok(reply) == (i >= 6));
        if (reply)
            json_object_put(reply);
    }
}

int main(void)
{
    assert(sqlite3_open(":memory:", &g_app_db) == SQLITE_OK);
    assert(sqlite3_exec(g_app_db,
        "CREATE TABLE config_apply_tasks(id INTEGER PRIMARY KEY,state TEXT,"
        "snapshot_path TEXT,applied_digest TEXT,changes_json TEXT,finished_at INTEGER,"
        "error TEXT,rollback_applied INTEGER,rollback_error TEXT,rollback_reason TEXT,"
        "health_checks_json TEXT,readback_json TEXT,rollback_deadline INTEGER,"
        "started_at INTEGER,rollback_timeout INTEGER,confirmed_at INTEGER,"
        "config_revision INTEGER,apply_executor TEXT DEFAULT '',idempotency_key TEXT DEFAULT '',rollback_owner TEXT DEFAULT '',"
        "rollback_claimed_at INTEGER DEFAULT 0,rollback_claim_revision INTEGER DEFAULT 0)",
        NULL, NULL, NULL) == SQLITE_OK);
    assert(sqlite3_exec(g_app_db,
        "CREATE TABLE config_apply_revision_sequence(id INTEGER PRIMARY KEY,"
        "next_revision INTEGER NOT NULL);"
        "INSERT INTO config_apply_revision_sequence VALUES(1,1)",
        NULL, NULL, NULL) == SQLITE_OK);
    test_payload();
    test_rollback_stages();
    test_missing_port_snapshot();
    test_evidence_arrays();
    test_confirm_deadline();
    test_digest_guard();
    test_claim_cas_and_confirm_race();
    test_revision_sequence();
    test_port_restore_response();
    if (port_payload)
        json_object_put(port_payload);
    sqlite3_close(g_app_db);
    puts("ok: SafeOps rollback stages, saved port fields and evidence arrays");
    return 0;
}

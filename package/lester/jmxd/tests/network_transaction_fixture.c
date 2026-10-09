// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <json-c/json.h>
#include <sqlite3.h>
#include "../src/ac/ac_secrets.h"
#include "../src/safeops/network_snapshot.h"
#include "../src/safeops/task_projection.h"

static sqlite3 *g_netconfig_db;
static char app_path[PATH_MAX], config_path[PATH_MAX], config_dir[256];
static int apply_calls, fail_apply, fail_reload;
static const char *crash_point;
static int journal_written, restore_intent_written, fail_publish;
#define NC_TX_APP_DB app_path
#define NC_TX_CONFIG_DIR config_dir

static void crash_at(const char *point)
{
    if (crash_point && !strcmp(crash_point, point)) raise(SIGSTOP);
}
static int nc_exec(const char *sql)
{
    int rc = sqlite3_exec(g_netconfig_db, sql, NULL, NULL, NULL);
    if (rc == SQLITE_OK && !strcmp(sql, "COMMIT")) {
        crash_at("config_committed");
        crash_at("restore_config_committed");
    }
    return rc == SQLITE_OK ? 0 : -1;
}
static int jmx_netconfig_db_init(void) { return 0; }
static int64_t nc_now_s(void) { return (int64_t)time(NULL); }
static const char *nc_json_str(struct json_object *o, const char *key, const char *fallback)
{
    struct json_object *v = NULL;
    return json_object_object_get_ex(o, key, &v) && v ? json_object_get_string(v) : fallback;
}
static int nc_json_int(struct json_object *o, const char *key, int fallback)
{
    struct json_object *v = NULL;
    return json_object_object_get_ex(o, key, &v) && v ? json_object_get_int(v) : fallback;
}
static int nc_json_bool(struct json_object *o, const char *key, int fallback)
{ return nc_json_int(o, key, fallback); }
static int nc_uci_section_name_ok(const char *id)
{ return id && id[0] && strspn(id, "abcdefghijklmnopqrstuvwxyz0123456789_") == strlen(id); }
static int nc_is_valid_ip(const char *ip) { struct in_addr a; return ip && inet_pton(AF_INET, ip, &a) == 1; }
static void nc_add_field_error(struct json_object *errors, const char *field, const char *reason, const char *message)
{
    struct json_object *e = json_object_new_object();
    json_object_object_add(e, "field", json_object_new_string(field));
    json_object_object_add(e, "reason", json_object_new_string(reason));
    json_object_object_add(e, "message", json_object_new_string(message));
    json_object_array_add(errors, e);
}
static struct json_object *get_config(const char *domain, const char *id)
{
    struct json_object *rows = safeops_network_rows(g_netconfig_db, domain, id), *parents = NULL;
    struct json_object *out = json_object_new_object(), *data = json_object_new_object();
    if (rows && json_object_object_get_ex(rows, domain, &parents))
        json_object_object_add(data, domain, json_object_get(json_object_array_get_idx(parents, 0)));
    json_object_object_add(out, "data", data);
    if (rows) json_object_put(rows);
    return out;
}
static struct json_object *jmx_netconfig_wan_get(const char *id) { return get_config("wan", id); }
static struct json_object *jmx_netconfig_lan_get(const char *id) { return get_config("lan", id); }
static struct json_object *jmx_netconfig_wan_validate(struct json_object *cfg) { (void)cfg; return NULL; }
static struct json_object *jmx_netconfig_lan_validate(struct json_object *cfg) { (void)cfg; return NULL; }
static int save_config(const char *domain, struct json_object *cfg)
{
    sqlite3_stmt *st = NULL;
    char sql[128];
    int rc;
    snprintf(sql, sizeof(sql), "UPDATE %s SET name=?1 WHERE id=?2", domain);
    assert(sqlite3_prepare_v2(g_netconfig_db, sql, -1, &st, NULL) == SQLITE_OK);
    sqlite3_bind_text(st, 1, nc_json_str(cfg, "name", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, nc_json_str(cfg, "id", ""), -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}
static int jmx_netconfig_wan_set(struct json_object *cfg) { return save_config("wan", cfg); }
static int jmx_netconfig_lan_set(struct json_object *cfg) { return save_config("lan", cfg); }
static void write_config(const char *name, const char *text)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", config_dir, name);
    FILE *f = fopen(path, "w");
    assert(f);
    assert(fputs(text, f) >= 0);
    assert(fclose(f) == 0);
}
static int apply_config(const char *id, struct json_object *prepared)
{
    (void)id;
    apply_calls++;
    assert(prepared);
    json_object_object_add(prepared, "network", json_object_new_string("new network"));
    json_object_object_add(prepared, "dhcp", json_object_new_string("new dhcp"));
    json_object_object_add(prepared, "firewall", json_object_new_string("new firewall"));
    return fail_apply ? -1 : 0;
}
static int nc_apply_wan_scoped(const char *id, struct json_object *prepared)
{ return apply_config(id, prepared); }
static int nc_apply_lan_scoped(const char *id, int full, struct json_object *prepared)
{ assert(!full); return apply_config(id, prepared); }
static int nc_reload_network_stack(int dhcp, int firewall, const char *log)
{ (void)dhcp; (void)firewall; (void)log; return fail_reload ? -1 : 0; }
static int nc_prepare(sqlite3_stmt **st, const char *sql)
{ return sqlite3_prepare_v2(g_netconfig_db, sql, -1, st, NULL) == SQLITE_OK ? 0 : -1; }
static int nc_step_done(sqlite3_stmt *st) { return sqlite3_step(st) == SQLITE_DONE ? 0 : -1; }
#define nc_json_str_def nc_json_str
#define nc_json_int_def nc_json_int
#define nc_json_bool_def nc_json_bool
#define nc_valid_name nc_uci_section_name_ok
#include "network_dhcp_impl.inc"
#include "network_dns_impl.inc"
static int nc_dhcp_apply_scoped(const char *id, struct json_object *patch, struct json_object *prepared)
{
    assert(!strcmp(id, "lan") && patch);
    apply_calls++;
    json_object_object_add(prepared, "dhcp", json_object_new_string("new dhcp lease"));
    return fail_apply ? -1 : 0;
}
static int nc_dnsmasq_restart(const char *log) { (void)log; return fail_reload ? -1 : 0; }
static int nc_dns_runtime_ready(int port, int wait) { (void)port; (void)wait; return !fail_reload; }
static int nc_dns_service_apply_scoped(struct json_object *patch, struct json_object *prepared)
{
    assert(patch && json_object_object_length(patch));
    apply_calls++;
    json_object_object_add(prepared, "dhcp", json_object_new_string("new dns"));
    nc_dns_apply_state_set("applied", "");
    return fail_apply ? -1 : 0;
}
static int test_vault(sqlite3 *db, const char *path, struct ac_secrets **out)
{
    unsigned char key[32] = {1, 2, 3};
    (void)path;
    return ac_secrets_open_with_key(db, key, out);
}
#define ac_secrets_open_or_create test_vault
#define ac_secrets_open test_vault
static int test_rename(const char *from, const char *to)
{
    if (fail_publish && strstr(to, "/dhcp")) {
        fail_publish = 0;
        errno = EIO;
        return -1;
    }
    int rc = rename(from, to);
    if (!rc && strstr(to, "/network")) {
        crash_at("partial_files");
        crash_at("restore_partial");
    }
    if (!rc && strstr(to, "/firewall")) crash_at("all_files");
    return rc;
}
static int test_sqlite3_exec(sqlite3 *db, const char *sql,
                            int (*callback)(void *, int, char **, char **),
                            void *context, char **error)
{
    int rc = sqlite3_exec(db, sql, callback, context, error);
    if (!rc && !strcmp(sql, "COMMIT") && db != g_netconfig_db) {
        sqlite3_stmt *st = NULL;
        assert(sqlite3_prepare_v2(db, "SELECT applied_digest FROM config_apply_tasks "
            "WHERE state='pending' ORDER BY id DESC LIMIT 1", -1, &st, NULL) == SQLITE_OK);
        if (sqlite3_step(st) == SQLITE_ROW) {
            if (journal_written && !sqlite3_column_bytes(st, 0)) crash_at("journal_durable");
            crash_at(sqlite3_column_bytes(st, 0) ? "evidence_committed" : "task_durable");
        }
        sqlite3_finalize(st);
        if (restore_intent_written) crash_at("restore_intent_durable");
    }
    return rc;
}
static int test_secret_put(struct ac_secrets *vault, const char *id, uint64_t version,
                           const unsigned char *bytes, size_t length)
{
    int rc = ac_secrets_put(vault, id, version, bytes, length);
    struct json_object *value = json_tokener_parse((const char *)bytes);
    if (value && json_object_object_get(value, "prepared")) {
        if (nc_json_bool(value, "restoring", 0)) {
            restore_intent_written = 1;
            crash_at("restore_intent_precommit");
        } else {
            journal_written = 1;
            crash_at("journal_precommit");
        }
    }
    if (value) json_object_put(value);
    return rc;
}
#define rename test_rename
#define sqlite3_exec test_sqlite3_exec
#define ac_secrets_put test_secret_put
#define NC_IPTV_PLATFORM_FIXTURE 1
static int nc_iptv_prepare(struct json_object *config, const char *operation, struct json_object *prepared)
;
static void nc_iptv_platform_check(struct json_object *config, struct json_object *request, struct json_object *errors)
{ (void)config; (void)request; (void)errors; }
static struct json_object *nc_iptv_runtime(const char *id)
{ (void)id; return json_object_new_object(); }
static int nc_iptv_reconnect(const char *id) { (void)id; return 0; }
#include "../src/netconfig/040_nc_network_transaction.c"
#undef ac_secrets_put
#undef sqlite3_exec
#undef rename
#undef ac_secrets_open_or_create
#undef ac_secrets_open

static int scalar(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *st = NULL;
    assert(sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK);
    assert(sqlite3_step(st) == SQLITE_ROW);
    int n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}
#include "iptv_network_fixture.inc"
static struct json_object *request(const char *key, const char *name)
{
    struct json_object *req = json_object_new_object(), *patch = json_object_new_object();
    json_object_object_add(req, "domain", json_object_new_string("wan"));
    json_object_object_add(req, "id", json_object_new_string("wan"));
    struct json_object *canonical = nc_tx_get(req);
    assert(nc_json_bool(canonical, "ok", 0));
    json_object_object_add(req, "if_revision", json_object_new_string(nc_json_str(canonical, "revision", "")));
    json_object_put(canonical);
    json_object_object_add(req, "idempotency_key", json_object_new_string(key));
    json_object_object_add(req, "confirm_risk", json_object_new_boolean(1));
    json_object_object_add(patch, "name", json_object_new_string(name));
    json_object_object_add(req, "config", patch);
    return req;
}
static void check_original(void)
{
    const char *files[] = {"network", "dhcp", "firewall"};
    for (int i = 0; i < 3; i++) {
        char path[PATH_MAX], text[32];
        snprintf(path, sizeof(path), "%s/%s", config_dir, files[i]);
        FILE *f = fopen(path, "r");
        assert(f && fgets(text, sizeof(text), f));
        fclose(f);
        assert(!strcmp(text, "original"));
    }
    assert(scalar(g_netconfig_db, "SELECT name='original' FROM wan WHERE id='wan'"));
}

static void kill_stopped_child(pid_t child)
{
    int status = 0;
    assert(waitpid(child, &status, WUNTRACED) == child);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "child missed crash point %s (status=%d)\n", crash_point, status);
        abort();
    }
    assert(kill(child, SIGKILL) == 0);
    assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    crash_point = NULL;
}

static void crash_test(sqlite3 *app, const char *point, const char *drift, int iptv_create)
{
    if (iptv_create) iptv_fixture_schema();
    struct json_object *req = iptv_create ? iptv_test_request("create", "crash-original-uuid",
        "{\"name\":\"IPTV\",\"device\":\"eth9\",\"access_mode\":\"dhcp\"}") : request("crash-original-uuid", "changed"), *resp;
    int recovery = !strncmp(point, "restore_", 8);
    if (recovery) {
        resp = nc_tx_apply(req);
        assert(nc_json_bool(resp, "ok", 0));
        json_object_put(resp);
        assert(sqlite3_exec(app, "UPDATE config_apply_tasks SET state='rolling_back'",
                           NULL, NULL, NULL) == SQLITE_OK);
    }
    assert(sqlite3_close(app) == SQLITE_OK);
    assert(sqlite3_close(g_netconfig_db) == SQLITE_OK);
    g_netconfig_db = NULL;
    crash_point = point;
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        assert(sqlite3_open(config_path, &g_netconfig_db) == SQLITE_OK);
        if (recovery) {
            struct json_object *rollback = json_tokener_parse("{\"task_id\":1}");
            resp = nc_tx_rollback(rollback);
            assert(nc_json_bool(resp, "rollback_applied", 0));
            crash_at("restore_complete");
        } else {
            resp = nc_tx_apply(req);
        }
        fprintf(stderr, "unexpected return: %s\n", json_object_to_json_string(resp));
        _exit(1);
    }
    kill_stopped_child(child);
    assert(sqlite3_open(config_path, &g_netconfig_db) == SQLITE_OK);
    assert(sqlite3_open(app_path, &app) == SQLITE_OK);
    assert(scalar(app, "SELECT count(*) FROM config_apply_tasks") == 1);
    assert(scalar(app, "SELECT snapshot_ok=1 FROM config_apply_tasks"));
    if (!strcmp(point, "config_committed"))
        assert(scalar(g_netconfig_db, iptv_create ? "SELECT count(*) FROM wan WHERE id='iptv_ab12'" : "SELECT name='changed' FROM wan"));
    int calls_before = apply_calls;
    resp = nc_tx_apply(req);
    assert(nc_json_bool(resp, "idempotent_replay", 0) && nc_json_int(resp, "task_id", 0) == 1);
    assert(apply_calls == calls_before);
    json_object_put(resp);
    assert(sqlite3_exec(app, "UPDATE config_apply_tasks SET state='rolling_back'",
                       NULL, NULL, NULL) == SQLITE_OK);
    if (!strcmp(drift, "file")) write_config("dhcp", "external edit");
    if (!strcmp(drift, "preimage")) write_config("dhcp", "original");
    if (!strcmp(drift, "row")) assert(nc_exec("UPDATE wan SET name='external edit'") == 0);
    struct json_object *before = nc_tx_snapshot(iptv_create ? "iptv" : "wan", iptv_create ? "iptv_ab12" : "wan");
    struct json_object *rollback = json_tokener_parse("{\"task_id\":1}");
    resp = nc_tx_rollback(rollback);
    if (drift[0]) {
        assert(!strcmp(nc_json_str(resp, "error", ""), "stale_watchdog_digest_mismatch"));
        struct json_object *after = nc_tx_snapshot(iptv_create ? "iptv" : "wan", iptv_create ? "iptv_ab12" : "wan");
        assert(json_object_equal(before, after));
        json_object_put(after);
    } else {
        if (!nc_json_bool(resp, "rollback_applied", 0))
            fprintf(stderr, "crash %s: %s\n", point, json_object_to_json_string(resp));
        assert(nc_json_bool(resp, "rollback_applied", 0));
        check_original();
        if (iptv_create) assert(!scalar(g_netconfig_db, "SELECT count(*) FROM wan WHERE id='iptv_ab12'"));
    }
    json_object_put(before); json_object_put(rollback); json_object_put(resp); json_object_put(req);
    sqlite3_close(app); sqlite3_close(g_netconfig_db);
    printf("ok: crash %s drift=%s\n", point, drift);
}

int main(int argc, char **argv)
{
    char dir[] = "/tmp/dw-nettx-XXXXXX";
    assert(mkdtemp(dir));
    snprintf(config_dir, sizeof(config_dir), "%s/config", dir);
    snprintf(app_path, sizeof(app_path), "%s/apid.db", dir);
    snprintf(config_path, sizeof(config_path), "%s/config.db", dir);
    assert(mkdir(config_dir, 0700) == 0);
    assert(sqlite3_open(config_path, &g_netconfig_db) == SQLITE_OK);
    if (argc > 2 && !strcmp(argv[2], "wal")) assert(nc_exec("PRAGMA journal_mode=WAL") == 0);
    assert(nc_exec("CREATE TABLE wan(id TEXT PRIMARY KEY,name TEXT,access_mode TEXT,password_ref TEXT);"
                   "INSERT INTO wan VALUES('wan','original','dhcp','private-test-secret');"
                   "CREATE TABLE wan_address(id TEXT PRIMARY KEY,wan_id TEXT,ip TEXT);"
                   "INSERT INTO wan_address VALUES('a','wan','192.0.2.2');"
                   "CREATE TABLE wan_advanced(wan_id TEXT PRIMARY KEY,value INTEGER);"
                   "CREATE TABLE wan_bond(wan_id TEXT PRIMARY KEY,value INTEGER);"
                   "CREATE TABLE wan_dns_policy(id INTEGER PRIMARY KEY,wan_id TEXT,value TEXT);"
                   "CREATE TABLE hybrid_line(id TEXT PRIMARY KEY,parent_wan_id TEXT,value TEXT);"
                   "CREATE TABLE lan(id TEXT PRIMARY KEY,name TEXT,parent_lan_id TEXT);"
                   "INSERT INTO lan VALUES('lan','original','parent');"
                   "CREATE TABLE lan_port(lan_id TEXT,port_id TEXT);"
                   "CREATE TABLE lan_address(id TEXT PRIMARY KEY,lan_id TEXT,ip TEXT);"
                   "CREATE TABLE lan_dhcp(lan_id TEXT PRIMARY KEY,pool_start TEXT,pool_end TEXT);"
                   "INSERT INTO lan_dhcp VALUES('lan','100','199');"
                   "CREATE TABLE lan_ipv6(lan_id TEXT PRIMARY KEY,enabled INTEGER);") == 0);
    sqlite3 *app = NULL;
    assert(sqlite3_open(app_path, &app) == SQLITE_OK);
    if (argc > 2 && !strcmp(argv[2], "wal"))
        assert(sqlite3_exec(app, "PRAGMA journal_mode=WAL", NULL, NULL, NULL) == SQLITE_OK);
    assert(sqlite3_exec(app,
        "CREATE TABLE config_apply_revision_sequence(id INTEGER PRIMARY KEY,next_revision INTEGER);"
        "INSERT INTO config_apply_revision_sequence VALUES(1,1);"
        "CREATE TABLE config_apply_tasks(id INTEGER PRIMARY KEY AUTOINCREMENT,scope TEXT,changes_json TEXT,"
        "state TEXT,rollback_timeout INTEGER,started_at INTEGER,snapshot_path TEXT,snapshot_at INTEGER,"
        "snapshot_ok INTEGER,apply_executor TEXT,config_revision INTEGER,before_digest TEXT,"
        "idempotency_key TEXT,rollback_deadline INTEGER,changed_paths_json TEXT,preflight_json TEXT,"
        "applied_digest TEXT DEFAULT '',target_digest TEXT,readback_json TEXT,error TEXT,"
        "rollback_applied INTEGER,rollback_error TEXT,finished_at INTEGER);",
        NULL, NULL, NULL) == SQLITE_OK);
    write_config("network", "original"); write_config("dhcp", "original"); write_config("firewall", "original");
    if (argc > 1) {
        if (!strcmp(argv[1], "iptv-serve")) {
            iptv_fixture_serve(app);
            return 0;
        }
        if (!strcmp(argv[1], "iptv")) {
            iptv_fixture(app);
            sqlite3_close(app); sqlite3_close(g_netconfig_db);
            puts("ok: IPTV input transaction preflight, creation, deletion, replay and rollback");
            return 0;
        }
        if (!strcmp(argv[1], "publish_failure")) {
            struct json_object *req = request("publish-failure", "changed");
            fail_publish = 1;
            struct json_object *resp = nc_tx_apply(req);
            assert(!nc_json_bool(resp, "ok", 1));
            assert(scalar(app, "SELECT state='rolled_back' AND rollback_applied=1 FROM config_apply_tasks"));
            check_original();
            json_object_put(req); json_object_put(resp);
            sqlite3_close(app); sqlite3_close(g_netconfig_db);
            puts("ok: atomic file replacement failure restores published files and database");
            return 0;
        }
        crash_test(app, argv[1], argc > 3 ? argv[3] : "", argc > 4 && !strcmp(argv[4], "iptv-create"));
        return 0;
    }

    struct json_object *req = request("first", "changed");
    struct json_object *canonical = nc_tx_get(req), *config = NULL, *secret = NULL;
    assert(json_object_object_get_ex(canonical, "config", &config));
    assert(!json_object_object_get_ex(config, "password_ref", &secret));
    assert(!json_object_object_get_ex(config, "password", &secret));
    struct json_object *addresses = NULL;
    assert(json_object_object_get_ex(config, "addresses", &addresses));
    assert(json_object_array_length(addresses) == 1);
    assert(!strcmp(nc_json_str(json_object_array_get_idx(addresses, 0), "ip", ""), "192.0.2.2"));
    json_object_put(canonical);
    struct json_object *resp = nc_tx_validate(req, NULL);
    assert(nc_json_bool(resp, "valid", 0) && apply_calls == 0);
    json_object_put(resp);
    assert(scalar(app, "SELECT count(*) FROM config_apply_tasks") == 0);
    const char *invalid[] = {
        "{\"enabled\":\"false\"}", "{\"mtu\":true}", "{\"addresses\":[\"invalid\"]}",
        "{\"addresses\":[{\"ip\":\"192.0.2.1\",\"prefix\":\"24\",\"primary\":true}]}",
        "{\"dns\":[123]}", "{\"password\":\"private\"}", "{\"device\":\"eth9\"}", "{\"dhcp\":{}}"
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        struct json_object *bad = request("invalid", "changed");
        json_object_object_add(bad, "config", json_tokener_parse(invalid[i]));
        resp = nc_tx_apply(bad);
        assert(!nc_json_bool(resp, "ok", 1) && nc_json_int(resp, "code", 0) == 400);
        assert(apply_calls == 0);
        json_object_put(resp); json_object_put(bad);
    }
    json_object_object_add(req, "if_revision", json_object_new_string("stale"));
    resp = nc_tx_apply(req);
    assert(nc_json_int(resp, "code", 0) == 409 && apply_calls == 0);
    assert(scalar(app, "SELECT next_revision FROM config_apply_revision_sequence") == 1);
    assert(scalar(app, "SELECT count(*) FROM config_apply_tasks") == 0);
    json_object_put(resp); json_object_put(req);

    req = request("first", "changed");
    resp = nc_tx_apply(req);
    assert(nc_json_bool(resp, "ok", 0) && nc_json_int(resp, "task_id", 0) == 1 && apply_calls == 1);
    assert(scalar(app, "SELECT instr(readback_json,'private-test-secret')=0 FROM config_apply_tasks WHERE id=1"));
    json_object_put(resp);
    assert(sqlite3_exec(app, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK);
    resp = nc_tx_apply(req);
    assert(nc_json_bool(resp, "idempotent_replay", 0) && apply_calls == 1);
    json_object_put(resp);
    struct json_object *other = request("second", "other");
    resp = nc_tx_apply(other);
    assert(!strcmp(nc_json_str(resp, "error", ""), "transaction_pending") && apply_calls == 1);
    json_object_put(resp); json_object_put(other);
    assert(sqlite3_exec(app, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK);
    assert(sqlite3_exec(app, "UPDATE config_apply_tasks SET state='rolling_back' WHERE id=1", NULL, NULL, NULL) == SQLITE_OK);
    struct json_object *rollback = json_tokener_parse("{\"task_id\":1}");
    resp = nc_tx_rollback(rollback);
    assert(nc_json_bool(resp, "rollback_applied", 0));
    json_object_put(resp);
    check_original();
    assert(sqlite3_exec(app, "UPDATE config_apply_tasks SET state='rolled_back' WHERE id=1", NULL, NULL, NULL) == SQLITE_OK);
    json_object_put(req);

    fail_apply = 1;
    req = request("failure", "broken");
    resp = nc_tx_apply(req);
    assert(!nc_json_bool(resp, "ok", 1));
    assert(scalar(app, "SELECT state='rolled_back' FROM config_apply_tasks WHERE id=2"));
    check_original();
    json_object_put(resp); json_object_put(req);
    fail_apply = 0;
    req = request("drift", "third");
    resp = nc_tx_apply(req);
    assert(nc_json_bool(resp, "ok", 0));
    json_object_put(resp);
    assert(sqlite3_exec(app, "UPDATE config_apply_tasks SET state='rolling_back' WHERE id=3", NULL, NULL, NULL) == SQLITE_OK);
    write_config("dhcp", "concurrent change");
    json_object_object_add(rollback, "task_id", json_object_new_int(3));
    resp = nc_tx_rollback(rollback);
    assert(!strcmp(nc_json_str(resp, "error", ""), "stale_watchdog_digest_mismatch"));
    assert(scalar(g_netconfig_db, "SELECT name='third' FROM wan WHERE id='wan'"));
    json_object_put(resp); json_object_put(req); json_object_put(rollback);

    assert(sqlite3_exec(app, "UPDATE config_apply_tasks SET state='rollback_failed' WHERE id=3", NULL, NULL, NULL) == SQLITE_OK);
    req = request("lan", "changed lan");
    json_object_object_add(req, "domain", json_object_new_string("lan"));
    json_object_object_add(req, "id", json_object_new_string("lan"));
    canonical = nc_tx_get(req);
    json_object_object_add(req, "if_revision", json_object_new_string(nc_json_str(canonical, "revision", "")));
    json_object_object_get_ex(canonical, "config", &config);
    assert(!strcmp(nc_json_str(config, "parent", ""), "parent"));
    json_object_put(canonical);
    resp = nc_tx_apply(req);
    assert(nc_json_bool(resp, "ok", 0));
    int lan_task = nc_json_int(resp, "task_id", 0);
    json_object_put(resp); json_object_put(req);
    assert(scalar(g_netconfig_db, "SELECT name='changed lan' FROM lan WHERE id='lan'"));
    assert(scalar(g_netconfig_db, "SELECT pool_start='100' AND pool_end='199' FROM lan_dhcp WHERE lan_id='lan'"));
    assert(sqlite3_exec(app, "UPDATE config_apply_tasks SET state='rolling_back' WHERE id=4", NULL, NULL, NULL) == SQLITE_OK);
    rollback = json_object_new_object();
    json_object_object_add(rollback, "task_id", json_object_new_int(lan_task));
    fail_reload = 1;
    resp = nc_tx_rollback(rollback);
    assert(!nc_json_bool(resp, "ok", 1));
    assert(!strcmp(nc_json_str(resp, "error", ""), "network_restore_failed"));
    assert(scalar(g_netconfig_db, "SELECT name='original' FROM lan WHERE id='lan'"));
    json_object_put(resp); json_object_put(rollback);

    assert(sqlite3_exec(app, "UPDATE config_apply_tasks SET state='rollback_failed' WHERE id=4", NULL, NULL, NULL) == SQLITE_OK);
    fail_reload = 0;
    assert(nc_exec(
        "ALTER TABLE lan ADD COLUMN enabled INTEGER DEFAULT 1;"
        "CREATE TABLE dns_service(id INTEGER PRIMARY KEY,enabled INTEGER,mode TEXT,"
        "listen_port INTEGER,cache_enabled INTEGER,cache_size INTEGER,local_domain TEXT,"
        "rebind_protection INTEGER,hijack_protection INTEGER,edns_client_subnet INTEGER,"
        "ipv6_dns INTEGER,updated_at INTEGER);"
        "INSERT INTO dns_service VALUES(1,1,'proxy',53,1,4096,'lan',1,0,0,0,123);"
        "CREATE TABLE dns_listen_interface(service_id INTEGER,lan_id TEXT);"
        "INSERT INTO dns_listen_interface VALUES(1,'lan');"
        "CREATE TABLE dns_upstream(id TEXT PRIMARY KEY,name TEXT,address TEXT,port INTEGER,"
        "protocol TEXT,group_name TEXT,enabled INTEGER,sort_order INTEGER);"
        "INSERT INTO dns_upstream VALUES('up1','upstream','192.0.2.53',53,'udp','default',1,0);"
        "CREATE TABLE dns_rule(id TEXT PRIMARY KEY,domain TEXT,type TEXT,target TEXT,remark TEXT,"
        "enabled INTEGER,sort_order INTEGER);"
        "INSERT INTO dns_rule VALUES('rule1','example.test','block','','keep',0,7);"
        "CREATE TABLE network_meta(key TEXT PRIMARY KEY,value TEXT);"
        "INSERT INTO network_meta VALUES('dns_service.apply_state','applied|123|'),('other','preserve');"
    ) == 0);
    req = json_tokener_parse("{\"domain\":\"dns\",\"id\":\"1\",\"idempotency_key\":\"dns\","
        "\"confirm_risk\":true,\"config\":{\"cache_size\":8192}}");
    canonical = nc_tx_get(req);
    assert(nc_json_bool(canonical, "ok", 0));
    json_object_object_add(req, "if_revision", json_object_get(json_object_object_get(canonical, "revision")));
    struct json_object *before_dns = nc_tx_snapshot("dns", "1");
    char before_digest[72], after_digest[72];
    assert(nc_tx_digest(before_dns, before_digest) == 0);
    struct json_object *merged_dns = NULL;
    resp = nc_tx_validate(req, &merged_dns);
    assert(nc_json_bool(resp, "valid", 0));
    json_object_put(resp);
    assert(nc_exec("BEGIN IMMEDIATE") == 0);
    assert(jmx_dns_service_set(merged_dns) == 0);
    assert(!sqlite3_get_autocommit(g_netconfig_db));
    assert(nc_exec("ROLLBACK") == 0);
    json_object_put(merged_dns);
    const char *invalid_dns[] = {
        "{\"cache_size\":true}", "{\"listen_port\":0}", "{\"local_domain\":\"bad domain\"}",
        "{\"listen_interfaces\":[]}", "{\"upstreams\":[{\"id\":\"a\",\"address\":\"192.0.2.53\",\"protocol\":\"doh\"}]}",
        "{\"upstreams\":[{\"id\":\"a\",\"address\":\"192.0.2.53\",\"protocol\":\"tcp\"}]}",
        "{\"upstreams\":[{\"id\":\"a\",\"address\":\"192.0.2.53\"},{\"id\":\"a\",\"address\":\"192.0.2.54\"}]}",
        "{\"rules\":[]}"
    };
    for (size_t i = 0; i < sizeof(invalid_dns) / sizeof(invalid_dns[0]); i++) {
        struct json_object *bad = json_tokener_parse(json_object_to_json_string(req));
        json_object_object_add(bad, "config", json_tokener_parse(invalid_dns[i]));
        resp = nc_tx_validate(bad, NULL);
        assert(!nc_json_bool(resp, "valid", 1) && nc_json_int(resp, "code", 0) == 400);
        json_object_put(resp); json_object_put(bad);
    }
    struct json_object *after_dns = nc_tx_snapshot("dns", "1");
    assert(nc_tx_digest(after_dns, after_digest) == 0 && !strcmp(before_digest, after_digest));
    json_object_put(after_dns);
    resp = nc_tx_apply(req);
    assert(nc_json_bool(resp, "ok", 0));
    int dns_task = nc_json_int(resp, "task_id", 0);
    assert(dns_task == 5);
    json_object_put(resp);
    assert(scalar(g_netconfig_db, "SELECT cache_size=8192 FROM dns_service WHERE id=1"));
    assert(scalar(g_netconfig_db, "SELECT enabled=0 AND remark='keep' FROM dns_rule WHERE id='rule1'"));
    resp = nc_tx_apply(req);
    assert(nc_json_bool(resp, "idempotent_replay", 0));
    json_object_put(resp);
    assert(sqlite3_exec(app, "UPDATE config_apply_tasks SET state='rolling_back' WHERE id=5", NULL, NULL, NULL) == SQLITE_OK);
    rollback = json_object_new_object();
    json_object_object_add(rollback, "task_id", json_object_new_int(dns_task));
    resp = nc_tx_rollback(rollback);
    assert(nc_json_bool(resp, "rollback_applied", 0));
    after_dns = nc_tx_snapshot("dns", "1");
    assert(nc_tx_digest(after_dns, after_digest) == 0 && !strcmp(before_digest, after_digest));
    assert(scalar(g_netconfig_db, "SELECT value='preserve' FROM network_meta WHERE key='other'"));
    assert(sqlite3_exec(app, "UPDATE config_apply_tasks SET state='rolled_back' WHERE id=5", NULL, NULL, NULL) == SQLITE_OK);
    json_object_put(after_dns); json_object_put(before_dns);
    json_object_put(resp); json_object_put(rollback); json_object_put(req); json_object_put(canonical);

    assert(nc_exec(
        "ALTER TABLE lan_address ADD COLUMN prefix INTEGER DEFAULT 24;"
        "ALTER TABLE lan_address ADD COLUMN is_primary INTEGER DEFAULT 1;"
        "INSERT INTO lan_address(id,lan_id,ip) VALUES('a','lan','192.0.2.1');"
        "ALTER TABLE lan_dhcp ADD COLUMN enabled INTEGER DEFAULT 0;"
        "ALTER TABLE lan_dhcp ADD COLUMN tagname TEXT DEFAULT '';"
        "ALTER TABLE lan_dhcp ADD COLUMN exclude_pool_json TEXT DEFAULT '[]';"
        "ALTER TABLE lan_dhcp ADD COLUMN gateway TEXT DEFAULT '';"
        "ALTER TABLE lan_dhcp ADD COLUMN dns_json TEXT DEFAULT '[\"192.0.2.53\"]';"
        "ALTER TABLE lan_dhcp ADD COLUMN lease_minutes INTEGER DEFAULT 120;"
        "CREATE TABLE dhcp_scope(id TEXT PRIMARY KEY,lan_id TEXT UNIQUE,enabled INTEGER,tagname TEXT,"
        "pool_start TEXT,pool_end TEXT,exclude_pool TEXT,gateway TEXT,netmask TEXT,dns1 TEXT,dns2 TEXT,"
        "lease_minutes INTEGER,domain TEXT,updated_at INTEGER);"
    ) == 0);
    req = json_tokener_parse("{\"domain\":\"dhcp\",\"id\":\"lan\",\"idempotency_key\":\"dhcp\","
        "\"confirm_risk\":true,\"config\":{\"lease_minutes\":180}}");
    canonical = nc_tx_get(req);
    assert(nc_json_bool(canonical, "write_supported", 0));
    json_object_object_add(req, "if_revision", json_object_get(json_object_object_get(canonical, "revision")));
    resp = nc_tx_validate(req, NULL);
    assert(nc_json_bool(resp, "valid", 0));
    assert(scalar(g_netconfig_db, "SELECT count(*) FROM dhcp_scope") == 0);
    json_object_put(resp);
    const char *invalid_dhcp[] = {"{\"lease_minutes\":0}", "{\"enabled\":1}",
        "{\"pool_start\":\"192.0.3.100\"}", "{\"gateway\":\"bad\"}", "{\"reservations\":[]}"};
    for (size_t i = 0; i < sizeof(invalid_dhcp) / sizeof(invalid_dhcp[0]); i++) {
        struct json_object *bad = json_tokener_parse(json_object_to_json_string(req));
        json_object_object_add(bad, "config", json_tokener_parse(invalid_dhcp[i]));
        resp = nc_tx_validate(bad, NULL);
        assert(!nc_json_bool(resp, "valid", 1));
        json_object_put(resp); json_object_put(bad);
    }
    resp = nc_tx_apply(req);
    assert(nc_json_bool(resp, "ok", 0));
    int dhcp_task = nc_json_int(resp, "task_id", 0);
    assert(scalar(g_netconfig_db, "SELECT lease_minutes=180 AND enabled=0 AND dns1='192.0.2.53' FROM dhcp_scope"));
    assert(scalar(g_netconfig_db, "SELECT lease_minutes=180 AND enabled=0 FROM lan_dhcp"));
    json_object_put(resp);
    assert(sqlite3_exec(app, "UPDATE config_apply_tasks SET state='rolling_back' WHERE state='pending'", NULL, NULL, NULL) == SQLITE_OK);
    rollback = json_object_new_object();
    json_object_object_add(rollback, "task_id", json_object_new_int(dhcp_task));
    resp = nc_tx_rollback(rollback);
    assert(nc_json_bool(resp, "rollback_applied", 0));
    assert(scalar(g_netconfig_db, "SELECT count(*) FROM dhcp_scope") == 0);
    assert(scalar(g_netconfig_db, "SELECT lease_minutes=120 FROM lan_dhcp"));
    json_object_put(resp); json_object_put(rollback); json_object_put(req); json_object_put(canonical);
    struct json_object *legacy = json_tokener_parse("{\"lease\":240}");
    assert(nc_dhcp_legacy_set("lan", legacy) == 0);
    assert(scalar(g_netconfig_db, "SELECT lease_minutes=240 FROM dhcp_scope"));
    assert(scalar(g_netconfig_db, "SELECT lease_minutes=240 FROM lan_dhcp"));
    assert(nc_exec("UPDATE lan_dhcp SET lease_minutes=1,dns_json='[\"203.0.113.1\"]'") == 0);
    config = nc_dhcp_base_get("lan");
    assert(nc_json_int(config, "lease_minutes", 0) == 240);
    assert(!strcmp(nc_json_str(config, "dns1", ""), "192.0.2.53"));
    assert(nc_exec("BEGIN IMMEDIATE") == 0);
    assert(nc_dhcp_base_set(config) == 0 && !sqlite3_get_autocommit(g_netconfig_db));
    assert(nc_exec("ROLLBACK") == 0);
    assert(scalar(g_netconfig_db, "SELECT lease_minutes=1 FROM lan_dhcp"));
    json_object_put(config); json_object_put(legacy);
    assert(nc_exec("UPDATE dhcp_scope SET id='custom_scope'") == 0);
    legacy = json_tokener_parse("{\"lease\":300,\"dns\":[\"6,192.0.2.54,192.0.2.55\"],"
        "\"exclude_pool\":\"[\\\"192.0.2.120\\\",\\\"192.0.2.121\\\"]\"}");
    assert(nc_dhcp_legacy_set("lan", legacy) == 0);
    assert(scalar(g_netconfig_db, "SELECT id='custom_scope' AND lease_minutes=300 AND "
        "exclude_pool='192.0.2.120,192.0.2.121' AND dns1='192.0.2.54' AND dns2='192.0.2.55' FROM dhcp_scope"));
    assert(scalar(g_netconfig_db, "SELECT json_array_length(exclude_pool_json)=2 AND "
        "json_array_length(dns_json)=2 FROM lan_dhcp"));
    struct json_object *lan_projection = json_object_new_object();
    nc_lan_load_dhcp("lan", lan_projection);
    struct json_object *legacy_dhcp = json_object_object_get(lan_projection, "dhcp");
    struct json_object *exclude_list = json_object_object_get(legacy_dhcp, "exclude_pool_list");
    assert(json_object_array_length(exclude_list) == 2);
    assert(!strcmp(json_object_get_string(json_object_array_get_idx(exclude_list, 0)), "192.0.2.120"));
    assert(nc_json_int(legacy_dhcp, "lease", 0) == 300);
    json_object_put(lan_projection);
    json_object_put(legacy);
    legacy = json_tokener_parse("{\"dns\":[]}");
    assert(nc_dhcp_legacy_set("lan", legacy) == 0);
    config = nc_dhcp_base_get("lan");
    assert(!strcmp(nc_json_str(config, "dns1", "missing"), ""));
    assert(scalar(g_netconfig_db, "SELECT dns_json='[]' FROM lan_dhcp"));
    json_object_put(config); json_object_put(legacy);
    assert(nc_exec("BEGIN IMMEDIATE") == 0);
    assert(nc_ipam_scope_exclude_store("custom_scope", "192.0.2.122") == 0);
    assert(scalar(g_netconfig_db, "SELECT exclude_pool='192.0.2.122' FROM dhcp_scope"));
    assert(scalar(g_netconfig_db, "SELECT exclude_pool_json='[\"192.0.2.122\"]' FROM lan_dhcp"));
    assert(!sqlite3_get_autocommit(g_netconfig_db));
    assert(nc_exec("ROLLBACK") == 0);
    assert(scalar(g_netconfig_db, "SELECT json_array_length(exclude_pool_json)=2 FROM lan_dhcp"));

    struct json_object *task = json_tokener_parse("{\"state\":\"pending\",\"rollback_deadline\":200}");
    safeops_task_clock(task, 150);
    assert(nc_json_int(task, "seconds_left", -1) == 50);
    safeops_task_clock(task, 175);
    assert(nc_json_int(task, "seconds_left", -1) == 25);
    safeops_task_clock(task, 205);
    assert(nc_json_int(task, "seconds_left", -1) == 0);
    json_object_put(task);
    task = json_tokener_parse("{\"state\":\"rollback_failed\",\"apply_executor\":\"netconfig_guarded_v1\"}");
    safeops_task_clock(task, 150);
    struct json_object *applied = NULL;
    assert(json_object_object_get_ex(task, "applied", &applied) && applied == NULL);
    assert(json_object_object_get_ex(task, "persisted", &applied) && applied == NULL);
    json_object_put(task);
    sqlite3_close(app); sqlite3_close(g_netconfig_db);
    printf("ok: WAN/LAN/DNS validate/types/redaction/conflict/apply/replay/busy/full rollback/reload failure/drift/server clock (%s)\n", dir);
    return 0;
}

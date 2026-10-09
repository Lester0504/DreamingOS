// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Drive webd_ai_runtime_status() against a real config.db.
 *
 * The whole point of the endpoint is that the App can tell four situations
 * apart before it renders a chat entry point, and none of them can be shown by
 * reading source text: each is a function of rows in ai_config / ai_provider
 * plus the persisted last_check verdict. So this builds the schema, writes the
 * rows, calls the production function and reads the JSON back.
 *
 * AI_CONFIG_DB is redefined by the harness, so nothing here can reach a real
 * router database.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>
#include <sqlite3.h>

#include "ai_runtime.h"

#ifndef AI_TEST_DB
#error "AI_TEST_DB must be defined by the harness"
#endif

/* Referenced by ai_runtime.c but unreachable from the status path. */
struct json_object *jmx_app_core_invoke(const char *method,
                                        struct json_object *params);
struct json_object *jmx_app_core_invoke(const char *method,
                                        struct json_object *params)
{
    (void)method;
    (void)params;
    return NULL;
}

void jmx_app_audit_log(const char *actor, const char *device_id,
                       const char *action, const char *risk,
                       const char *resource, const char *detail,
                       const char *result);
void jmx_app_audit_log(const char *actor, const char *device_id,
                       const char *action, const char *risk,
                       const char *resource, const char *detail,
                       const char *result)
{
    (void)actor;
    (void)device_id;
    (void)action;
    (void)risk;
    (void)resource;
    (void)detail;
    (void)result;
}

/* Streaming transport, reachable only from the SSE paths. */
int http_send_json(int fd, int status, struct json_object *resp);
int http_send_json(int fd, int status, struct json_object *resp)
{
    (void)fd;
    (void)status;
    (void)resp;
    fprintf(stderr, "FAIL http_send_json reached from the status path\n");
    exit(2);
}

int http_send_sse_header(int fd);
int http_send_sse_header(int fd)
{
    (void)fd;
    fprintf(stderr, "FAIL http_send_sse_header reached from the status path\n");
    exit(2);
}

static int failures;

static void fail(const char *what, const char *expected, const char *got)
{
    fprintf(stderr, "FAIL %s: expected %s, got %s\n", what, expected,
            got ? got : "(null)");
    failures++;
}

static void exec_or_die(sqlite3 *db, const char *sql)
{
    char *err = NULL;

    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "sqlite error: %s\nsql: %s\n", err ? err : "?", sql);
        exit(2);
    }
}

/*
 * Only the columns the status path reads. Kept as literal DDL rather than
 * lifted from jmx_netconfig_db.c because that schema is built by nc_exec()
 * fragments plus nc_add_column_if_missing() migrations; the column set is
 * asserted separately by the Python side against the production source.
 */
static void build_schema(sqlite3 *db)
{
    exec_or_die(db,
        "CREATE TABLE ai_config ("
        "id INTEGER PRIMARY KEY,"
        "enabled INTEGER NOT NULL DEFAULT 0,"
        "provider TEXT NOT NULL DEFAULT 'openai',"
        "api_base TEXT NOT NULL DEFAULT '',"
        "api_key TEXT NOT NULL DEFAULT '',"
        "model TEXT NOT NULL DEFAULT '',"
        "temperature REAL NOT NULL DEFAULT 0.7,"
        "max_tokens INTEGER NOT NULL DEFAULT 4096,"
        "system_prompt TEXT NOT NULL DEFAULT '',"
        "tool_policy TEXT NOT NULL DEFAULT 'confirm_medium',"
        "reasoning_effort TEXT NOT NULL DEFAULT 'auto',"
        "reasoning_api_shape TEXT NOT NULL DEFAULT 'chat_completions',"
        "auth_mode TEXT NOT NULL DEFAULT 'api_key');");
    exec_or_die(db,
        "CREATE TABLE ai_provider ("
        "id TEXT PRIMARY KEY,"
        "provider TEXT NOT NULL DEFAULT 'openai',"
        "display_name TEXT NOT NULL DEFAULT '',"
        "api_base TEXT NOT NULL DEFAULT '',"
        "api_key TEXT NOT NULL DEFAULT '',"
        "auth_mode TEXT NOT NULL DEFAULT 'api_key',"
        "default_model TEXT NOT NULL DEFAULT '',"
        "role TEXT NOT NULL DEFAULT 'standby',"
        "priority INTEGER NOT NULL DEFAULT 100,"
        "weight INTEGER NOT NULL DEFAULT 1,"
        "enabled INTEGER NOT NULL DEFAULT 0,"
        "reasoning_effort TEXT NOT NULL DEFAULT 'auto',"
        "reasoning_api_shape TEXT NOT NULL DEFAULT 'chat_completions',"
        "last_check_ts INTEGER NOT NULL DEFAULT 0,"
        "last_check_ok INTEGER NOT NULL DEFAULT -1,"
        "last_check_latency_ms INTEGER NOT NULL DEFAULT -1,"
        "last_check_error TEXT NOT NULL DEFAULT '',"
        "updated_at INTEGER NOT NULL DEFAULT 0);");
    exec_or_die(db,
        "CREATE TABLE ai_dispatch_policy ("
        "id INTEGER PRIMARY KEY,"
        "strategy TEXT NOT NULL DEFAULT 'single',"
        "failover_timeout_ms INTEGER NOT NULL DEFAULT 20000,"
        "failover_max_attempts INTEGER NOT NULL DEFAULT 2,"
        "lb_cursor INTEGER NOT NULL DEFAULT 0);");
}

static sqlite3 *open_db(void)
{
    sqlite3 *db = NULL;

    if (sqlite3_open(AI_TEST_DB, &db) != SQLITE_OK) {
        fprintf(stderr, "cannot open %s\n", AI_TEST_DB);
        exit(2);
    }
    return db;
}

static void reset(sqlite3 *db)
{
    exec_or_die(db, "DELETE FROM ai_config");
    exec_or_die(db, "DELETE FROM ai_provider");
    exec_or_die(db, "DELETE FROM ai_dispatch_policy");
}

static struct json_object *status_data(int *http_status)
{
    struct json_object *response = webd_ai_runtime_status(http_status);
    struct json_object *data = NULL;

    if (!response) {
        fprintf(stderr, "FAIL status returned NULL\n");
        exit(2);
    }
    if (!json_object_object_get_ex(response, "data", &data) || !data) {
        fprintf(stderr, "FAIL status response has no data object\n");
        exit(2);
    }
    json_object_get(data);
    json_object_put(response);
    return data;
}

static const char *str_of(struct json_object *data, const char *key)
{
    struct json_object *v = NULL;

    if (!json_object_object_get_ex(data, key, &v) || !v)
        return NULL;
    return json_object_get_string(v);
}

static int bool_of(struct json_object *data, const char *key, int fallback)
{
    struct json_object *v = NULL;

    if (!json_object_object_get_ex(data, key, &v) || !v)
        return fallback;
    return json_object_get_boolean(v) ? 1 : 0;
}

static int has_key(struct json_object *data, const char *key)
{
    struct json_object *v = NULL;

    return json_object_object_get_ex(data, key, &v) ? 1 : 0;
}

static void expect_str(struct json_object *data, const char *key,
                       const char *want, const char *scenario)
{
    const char *got = str_of(data, key);
    char what[192];

    snprintf(what, sizeof(what), "%s: %s", scenario, key);
    if (!got || strcmp(got, want))
        fail(what, want, got);
}

static void expect_bool(struct json_object *data, const char *key, int want,
                        const char *scenario)
{
    int got = bool_of(data, key, -1);
    char what[192];

    snprintf(what, sizeof(what), "%s: %s", scenario, key);
    if (got != want)
        fail(what, want ? "true" : "false",
             got < 0 ? "(absent)" : (got ? "true" : "false"));
}

/* 1. Nothing configured: the shape the App sees on a fresh router today. */
static void case_not_configured(sqlite3 *db)
{
    struct json_object *data;
    int http = 0;

    reset(db);
    exec_or_die(db,
        "INSERT INTO ai_config(id,enabled,provider,model,api_key,auth_mode) "
        "VALUES(1,1,'openai','gpt-4o','','api_key')");
    data = status_data(&http);

    if (http != 200)
        fail("not_configured: http", "200", http == 0 ? "(unset)" : "other");
    expect_bool(data, "ready", 0, "not_configured");
    expect_str(data, "state", "not_configured", "not_configured");
    expect_str(data, "reason", "credentials_missing", "not_configured");
    expect_str(data, "next_action", "configure_credentials", "not_configured");
    /* enabled=true with no key is exactly the pair the App could not read. */
    expect_bool(data, "enabled", 1, "not_configured");
    expect_bool(data, "credentials_set", 0, "not_configured");
    /* The descriptive fields must survive an unready verdict, or the App has
     * nothing to pick a credential form with. */
    expect_str(data, "auth_mode", "api_key", "not_configured");
    expect_str(data, "provider", "openai", "not_configured");
    expect_str(data, "model", "gpt-4o", "not_configured");
    json_object_put(data);
}

/* 2. A relay ("zhongzhuanzhan") setup: API key plus custom api_base, no oauth. */
static void case_ready_api_key_relay(sqlite3 *db)
{
    struct json_object *data;
    int http = 0;

    reset(db);
    exec_or_die(db,
        "INSERT INTO ai_config(id,enabled,provider,model,api_key,api_base,auth_mode) "
        "VALUES(1,1,'openai-compatible','gpt-4o','sk-relay-key',"
        "'https://relay.example.com/v1','api_key')");
    data = status_data(&http);

    expect_bool(data, "ready", 1, "relay_ready");
    expect_str(data, "state", "ready", "relay_ready");
    expect_str(data, "next_action", "open_chat", "relay_ready");
    expect_bool(data, "credentials_set", 1, "relay_ready");
    expect_bool(data, "api_base_set", 1, "relay_ready");
    expect_str(data, "auth_mode", "api_key", "relay_ready");
    expect_str(data, "api_base", "https://relay.example.com/v1", "relay_ready");
    /* A ready verdict must not imply anyone verified the key. */
    expect_bool(data, "credentials_verified", 0, "relay_ready");
    expect_str(data, "credential_check_source", "never_checked", "relay_ready");
    /* No reason belongs on a ready response. */
    if (has_key(data, "reason"))
        fail("relay_ready: reason", "(absent)", str_of(data, "reason"));
    /* The key itself must never appear anywhere in the payload. */
    if (strstr(json_object_to_json_string(data), "sk-relay-key"))
        fail("relay_ready: payload", "no api_key material", "key leaked");
    json_object_put(data);
}

/* 3. Complete credentials that the provider rejected: 401 recorded. */
static void case_credentials_invalid(sqlite3 *db)
{
    struct json_object *data;
    int http = 0;

    reset(db);
    exec_or_die(db,
        "INSERT INTO ai_config(id,enabled,provider,model,api_key,auth_mode) "
        "VALUES(1,1,'openai','gpt-4o','sk-stale','api_key')");
    exec_or_die(db,
        "INSERT INTO ai_dispatch_policy(id,strategy) VALUES(1,'single')");
    exec_or_die(db,
        "INSERT INTO ai_provider(id,provider,api_key,default_model,role,enabled,"
        "auth_mode,last_check_ts,last_check_ok,last_check_latency_ms,last_check_error) "
        "VALUES('p1','openai','sk-stale','gpt-4o','primary',1,'api_key',"
        "1750000000,0,-1,'http_401')");
    data = status_data(&http);

    /* Credentials present but rejected must not read as ready: otherwise the
     * App opens a chat whose first send fails. */
    expect_bool(data, "ready", 0, "credentials_invalid");
    expect_str(data, "state", "credentials_invalid", "credentials_invalid");
    expect_str(data, "reason", "http_401", "credentials_invalid");
    expect_str(data, "next_action", "reconfigure_credentials",
               "credentials_invalid");
    expect_bool(data, "credentials_set", 1, "credentials_invalid");
    expect_bool(data, "credentials_verified", 0, "credentials_invalid");
    expect_str(data, "credential_check_source", "last_provider_test",
               "credentials_invalid");
    expect_str(data, "provider_id", "p1", "credentials_invalid");
    json_object_put(data);
}

/* 4. Credentials fine, network not: transport failure recorded. */
static void case_endpoint_unreachable(sqlite3 *db)
{
    struct json_object *data;
    int http = 0;

    reset(db);
    exec_or_die(db,
        "INSERT INTO ai_config(id,enabled,provider,model,api_key,auth_mode) "
        "VALUES(1,1,'openai','gpt-4o','sk-ok','api_key')");
    exec_or_die(db,
        "INSERT INTO ai_dispatch_policy(id,strategy) VALUES(1,'single')");
    exec_or_die(db,
        "INSERT INTO ai_provider(id,provider,api_key,default_model,role,enabled,"
        "auth_mode,last_check_ts,last_check_ok,last_check_latency_ms,last_check_error) "
        "VALUES('p1','openai','sk-ok','gpt-4o','primary',1,'api_key',"
        "1750000000,0,-1,'dns_failed')");
    data = status_data(&http);

    expect_bool(data, "ready", 0, "endpoint_unreachable");
    expect_str(data, "state", "endpoint_unreachable", "endpoint_unreachable");
    expect_str(data, "reason", "dns_failed", "endpoint_unreachable");
    expect_str(data, "next_action", "check_network_or_api_base",
               "endpoint_unreachable");
    /* This is the distinction the handoff asked for: the key is not the
     * problem here, so the App must not tell the user to re-enter it. */
    expect_bool(data, "credentials_set", 1, "endpoint_unreachable");
    json_object_put(data);
}

/* 5. A verified provider reports ready and says so. */
static void case_ready_verified(sqlite3 *db)
{
    struct json_object *data;
    int http = 0;

    reset(db);
    exec_or_die(db,
        "INSERT INTO ai_config(id,enabled,provider,model,api_key,auth_mode) "
        "VALUES(1,1,'openai','gpt-4o','sk-ok','api_key')");
    exec_or_die(db,
        "INSERT INTO ai_dispatch_policy(id,strategy) VALUES(1,'single')");
    exec_or_die(db,
        "INSERT INTO ai_provider(id,provider,api_key,default_model,role,enabled,"
        "auth_mode,last_check_ts,last_check_ok,last_check_latency_ms,last_check_error) "
        "VALUES('p1','openai','sk-ok','gpt-4o','primary',1,'api_key',"
        "1750000000,1,412,'')");
    data = status_data(&http);

    expect_bool(data, "ready", 1, "ready_verified");
    expect_str(data, "state", "ready", "ready_verified");
    expect_bool(data, "credentials_verified", 1, "ready_verified");
    expect_str(data, "credential_check_source", "last_provider_test",
               "ready_verified");
    json_object_put(data);
}

/* 6. AI switched off entirely: a distinct reason from "no credentials". */
static void case_disabled(sqlite3 *db)
{
    struct json_object *data;
    int http = 0;

    reset(db);
    exec_or_die(db,
        "INSERT INTO ai_config(id,enabled,provider,model,api_key,auth_mode) "
        "VALUES(1,0,'openai','gpt-4o','sk-present','api_key')");
    data = status_data(&http);

    expect_bool(data, "ready", 0, "disabled");
    expect_str(data, "state", "not_configured", "disabled");
    expect_str(data, "reason", "ai_disabled", "disabled");
    expect_str(data, "next_action", "enable_ai_and_configure_credentials",
               "disabled");
    json_object_put(data);
}

/*
 * 7. oauth selected but no grant stored.
 *
 * ai_config_load() blanks api_key and refills it from the oauth store for
 * auth_mode='oauth', so with no token the key is empty and the App must be told
 * to start the authorization flow rather than to type a key it does not have.
 */
static void case_oauth_not_connected(sqlite3 *db)
{
    struct json_object *data;
    int http = 0;

    reset(db);
    exec_or_die(db,
        "INSERT INTO ai_config(id,enabled,provider,model,api_key,auth_mode) "
        "VALUES(1,1,'openai','gpt-4o','sk-should-be-ignored','oauth')");
    data = status_data(&http);

    expect_bool(data, "ready", 0, "oauth_not_connected");
    expect_str(data, "state", "not_configured", "oauth_not_connected");
    expect_str(data, "reason", "oauth_not_connected", "oauth_not_connected");
    expect_str(data, "next_action", "start_oauth", "oauth_not_connected");
    expect_str(data, "auth_mode", "oauth", "oauth_not_connected");
    /* The stored api_key column is not a credential under oauth, so it must
     * not be reported as one, and it must not leak either. */
    expect_bool(data, "credentials_set", 0, "oauth_not_connected");
    if (strstr(json_object_to_json_string(data), "sk-should-be-ignored"))
        fail("oauth_not_connected: payload", "no api_key material",
             "key leaked");
    json_object_put(data);
}

/* 8. Dispatch set to single with no enabled primary is its own failure. */
static void case_single_without_primary(sqlite3 *db)
{
    struct json_object *data;
    int http = 0;

    reset(db);
    exec_or_die(db,
        "INSERT INTO ai_config(id,enabled,provider,model,api_key,auth_mode) "
        "VALUES(1,1,'openai','gpt-4o','sk-ok','api_key')");
    exec_or_die(db,
        "INSERT INTO ai_dispatch_policy(id,strategy) VALUES(1,'single')");
    exec_or_die(db,
        "INSERT INTO ai_provider(id,provider,api_key,default_model,role,enabled,"
        "auth_mode) VALUES('p1','openai','sk-ok','gpt-4o','standby',1,'api_key')");
    data = status_data(&http);

    expect_bool(data, "ready", 0, "single_without_primary");
    expect_str(data, "reason", "dispatch_strategy_single_without_primary",
               "single_without_primary");
    expect_str(data, "next_action", "configure_primary_provider",
               "single_without_primary");
    json_object_put(data);
}

/* 9. Route literals must be reported so the App never probes over HTTP: an
 * unregistered write answers 403 for a viewer exactly like a forbidden one. */
static void case_endpoint_literals(sqlite3 *db)
{
    struct json_object *data;
    int http = 0;

    reset(db);
    exec_or_die(db,
        "INSERT INTO ai_config(id,enabled,provider,model,api_key,auth_mode) "
        "VALUES(1,1,'openai','gpt-4o','sk-ok','api_key')");
    data = status_data(&http);

    expect_str(data, "chat_endpoint", "/api/v1/ai/chat", "literals");
    expect_str(data, "stream_endpoint", "/api/v1/ai/chat/stream", "literals");
    expect_str(data, "tool_resume_endpoint", "/api/v1/ai/tool-resume",
               "literals");
    expect_str(data, "provider_test_endpoint", "/api/v1/ai/provider/test",
               "literals");
    /* Status must never dial out: it is a viewer-readable GET. */
    expect_bool(data, "live_probe_performed", 0, "literals");
    json_object_put(data);
}

/*
 * 10. A pure read: calling status must not write to the database.
 *
 * This matters because status is JMX_RISK_LOW. If it recorded a check or
 * advanced the load-balancer cursor, a read-only token would be a write.
 */
static void case_status_does_not_write(sqlite3 *db)
{
    struct json_object *data;
    sqlite3_stmt *st = NULL;
    int http = 0;
    long long before = 0, after = 0;

    reset(db);
    exec_or_die(db,
        "INSERT INTO ai_config(id,enabled,provider,model,api_key,auth_mode) "
        "VALUES(1,1,'openai','gpt-4o','sk-ok','api_key')");
    exec_or_die(db,
        "INSERT INTO ai_dispatch_policy(id,strategy,lb_cursor) VALUES(1,'single',7)");
    exec_or_die(db,
        "INSERT INTO ai_provider(id,provider,api_key,default_model,role,enabled,"
        "auth_mode,last_check_ts,last_check_ok) "
        "VALUES('p1','openai','sk-ok','gpt-4o','primary',1,'api_key',1750000000,1)");

    if (sqlite3_prepare_v2(db, "SELECT total_changes()", -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        before = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    st = NULL;

    data = status_data(&http);
    json_object_put(data);

    /* Re-read the row values themselves: another connection's writes would not
     * show up in this connection's total_changes(). */
    if (sqlite3_prepare_v2(db,
            "SELECT lb_cursor FROM ai_dispatch_policy WHERE id=1", -1, &st,
            NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
        after = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    if (after != 7)
        fail("no_write: lb_cursor", "7 (untouched)", "advanced");

    st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT last_check_ts FROM ai_provider WHERE id='p1'", -1, &st,
            NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
        after = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    if (after != 1750000000LL)
        fail("no_write: last_check_ts", "1750000000 (untouched)", "rewritten");
    (void)before;
}

int main(void)
{
    sqlite3 *db;

    db = open_db();
    build_schema(db);

    case_not_configured(db);
    case_ready_api_key_relay(db);
    case_credentials_invalid(db);
    case_endpoint_unreachable(db);
    case_ready_verified(db);
    case_disabled(db);
    case_oauth_not_connected(db);
    case_single_without_primary(db);
    case_endpoint_literals(db);
    case_status_does_not_write(db);

    /* An explicit local request is refused before any provider selection. */
    struct json_object *local = webd_ai_local_status(1), *ld = NULL, *items = NULL;
    if (!json_object_object_get_ex(local, "data", &ld) ||
        json_object_get_boolean(json_object_object_get(ld, "ready")))
        fail("local.ready", "false without verified profile", "true/missing");
    if (!json_object_object_get_ex(ld, "items", &items) || json_object_array_length(items))
        fail("local.models", "empty verified catalog", "nonempty/missing");
    json_object_put(local);
    struct json_object *request = json_tokener_parse("{\"execution_backend\":\"local\",\"messages\":[{\"role\":\"user\",\"content\":\"test\"}]}");
    int status = 0;
    local = webd_ai_runtime_chat(request, "user:test", &status);
    if (status != 409) fail("explicit local gate", "409", "other");
    json_object_put(local); json_object_put(request);

    sqlite3_close(db);
    if (failures) {
        fprintf(stderr, "%d assertion(s) failed\n", failures);
        return 1;
    }
    printf("ok: ai status reports ready/not_configured/credentials_invalid/"
           "endpoint_unreachable from real rows without writing\n");
    return 0;
}

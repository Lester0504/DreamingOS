// SPDX-License-Identifier: GPL-2.0-or-later
#include "authd_internal.h"

#define AUTHD_SOURCE "config.db:user_authentication+dreamingwrt-authd"

static int authd_exec(const char *sql)
{
    char *error = NULL;
    int rc;

    rc = sqlite3_exec(g_authd_db, sql, NULL, NULL, &error);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-authd] sqlite failed: %s\n",
                error ? error : sqlite3_errmsg(g_authd_db));
        sqlite3_free(error);
        return -1;
    }
    return 0;
}

static int authd_ensure_column(const char *table, const char *column,
                               const char *definition)
{
    char sql[256];
    sqlite3_stmt *st = NULL;
    int found = 0;

    snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table);
    if (sqlite3_prepare_v2(g_authd_db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    while (sqlite3_step(st) == SQLITE_ROW) {
        if (!strcmp(authd_sqlite_text(st, 1, ""), column)) {
            found = 1;
            break;
        }
    }
    sqlite3_finalize(st);
    if (found)
        return 0;
    snprintf(sql, sizeof(sql), "ALTER TABLE %s ADD COLUMN %s %s",
             table, column, definition);
    return authd_exec(sql);
}

static sqlite3_stmt *authd_prepare(const char *sql)
{
    sqlite3_stmt *st = NULL;

    if (!g_authd_db || !sql || sqlite3_prepare_v2(g_authd_db, sql, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-authd] prepare failed: %s\n",
                g_authd_db ? sqlite3_errmsg(g_authd_db) : "database unavailable");
        return NULL;
    }
    return st;
}

static struct json_object *authd_parse_json(const char *text, enum json_type type)
{
    struct json_object *value = NULL;

    if (text && text[0])
        value = json_tokener_parse(text);
    if (!value || !json_object_is_type(value, type)) {
        if (value)
            json_object_put(value);
        return type == json_type_array ? json_object_new_array() : json_object_new_object();
    }
    return value;
}

static int authd_query_int(const char *sql)
{
    sqlite3_stmt *st = authd_prepare(sql);
    int value = 0;

    if (st && sqlite3_step(st) == SQLITE_ROW)
        value = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return value;
}

static int authd_query_limit(struct json_object *query)
{
    struct json_object *value = NULL;
    int limit = AUTHD_DEFAULT_LIMIT;

    if (query && json_object_object_get_ex(query, "limit", &value))
        limit = json_object_get_int(value);
    if (limit < 1)
        limit = AUTHD_DEFAULT_LIMIT;
    if (limit > AUTHD_MAX_LIMIT)
        limit = AUTHD_MAX_LIMIT;
    return limit;
}

static int authd_query_offset(struct json_object *query)
{
    struct json_object *value = NULL;
    int offset = 0;

    if (query && json_object_object_get_ex(query, "offset", &value))
        offset = json_object_get_int(value);
    return offset < 0 ? 0 : offset;
}

static void authd_format_duration(int64_t seconds, char *out, size_t out_len)
{
    if (seconds <= 0)
        out[0] = '\0';
    else if (seconds % 86400 == 0)
        snprintf(out, out_len, "%lld 天", (long long)(seconds / 86400));
    else if (seconds % 3600 == 0)
        snprintf(out, out_len, "%lld 小时", (long long)(seconds / 3600));
    else if (seconds % 60 == 0)
        snprintf(out, out_len, "%lld 分钟", (long long)(seconds / 60));
    else
        snprintf(out, out_len, "%lld 秒", (long long)seconds);
}

static void authd_format_rate(int64_t bps, char *out, size_t out_len)
{
    if (bps <= 0)
        out[0] = '\0';
    else if (bps % 1000000000LL == 0)
        snprintf(out, out_len, "%lld Gbps", (long long)(bps / 1000000000LL));
    else if (bps % 1000000LL == 0)
        snprintf(out, out_len, "%lld Mbps", (long long)(bps / 1000000LL));
    else if (bps % 1000LL == 0)
        snprintf(out, out_len, "%lld Kbps", (long long)(bps / 1000LL));
    else
        snprintf(out, out_len, "%lld bps", (long long)bps);
}

static void authd_format_datetime_local(int64_t epoch, char *out, size_t out_len)
{
    time_t value = (time_t)epoch;
    struct tm tmv;

    if (epoch <= 0 || !localtime_r(&value, &tmv)) {
        if (out_len) out[0] = '\0';
        return;
    }
    strftime(out, out_len, "%Y-%m-%dT%H:%M", &tmv);
}

static void authd_add_source_capabilities(struct json_object *data)
{
    json_object_object_add(data, "source", json_object_new_string(AUTHD_SOURCE));
    json_object_object_add(data, "capabilities", authd_capabilities_json());
}

int authd_db_init(void)
{
    static const char *schema =
        "BEGIN IMMEDIATE;"
        "CREATE TABLE IF NOT EXISTS authentication_schema_meta ("
        " id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL DEFAULT 1,"
        " migrated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS authentication_settings ("
        " id INTEGER PRIMARY KEY CHECK(id=1), enabled INTEGER NOT NULL DEFAULT 0,"
        " default_auth_type TEXT NOT NULL DEFAULT 'free',"
        " default_authorization_minutes INTEGER NOT NULL DEFAULT 60,"
        " idle_timeout_seconds INTEGER NOT NULL DEFAULT 900,"
        " password_policy_json TEXT NOT NULL DEFAULT '{}',"
        " config_json TEXT NOT NULL DEFAULT '{}',"
        " created_at INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS authentication_portal ("
        " id INTEGER PRIMARY KEY CHECK(id=1), published_version INTEGER NOT NULL DEFAULT 0,"
        " title TEXT NOT NULL DEFAULT '', welcome_text TEXT NOT NULL DEFAULT '',"
        " auth_prompt TEXT NOT NULL DEFAULT '', success_message TEXT NOT NULL DEFAULT '',"
        " button_text TEXT NOT NULL DEFAULT '', language TEXT NOT NULL DEFAULT 'zh-CN',"
        " public_config_json TEXT NOT NULL DEFAULT '{}', secret_config_cipher TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS authentication_access_rules ("
        " id TEXT PRIMARY KEY, rule_type TEXT NOT NULL DEFAULT 'pre_auth_allow',"
        " target_type TEXT NOT NULL DEFAULT 'domain', target_value TEXT NOT NULL DEFAULT '',"
        " enabled INTEGER NOT NULL DEFAULT 1, priority INTEGER NOT NULL DEFAULT 1000,"
        " note TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS authentication_packages ("
        " id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', validity_seconds INTEGER NOT NULL DEFAULT 0,"
        " price_minor INTEGER NOT NULL DEFAULT 0, currency TEXT NOT NULL DEFAULT 'CNY',"
        " download_bps INTEGER NOT NULL DEFAULT 0, upload_bps INTEGER NOT NULL DEFAULT 0,"
        " enabled INTEGER NOT NULL DEFAULT 1, note TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS authentication_accounts ("
        " id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL DEFAULT '',"
        " auth_type TEXT NOT NULL DEFAULT 'web', package_id TEXT NOT NULL DEFAULT '',"
        " password_hash TEXT NOT NULL DEFAULT '', expires_at INTEGER NOT NULL DEFAULT 0,"
        " online_seconds INTEGER NOT NULL DEFAULT 0, offline_seconds INTEGER NOT NULL DEFAULT 0,"
        " contact TEXT NOT NULL DEFAULT '', bound_mac TEXT NOT NULL DEFAULT '',"
        " allowed_source TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'enabled',"
        " note TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS authentication_account_sources ("
        " id TEXT PRIMARY KEY, account_id TEXT NOT NULL, source_type TEXT NOT NULL DEFAULT '',"
        " source_ref TEXT NOT NULL DEFAULT '', secret_cipher TEXT NOT NULL DEFAULT '',"
        " enabled INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS authentication_ledger ("
        " id TEXT PRIMARY KEY, account_id TEXT NOT NULL DEFAULT '', charged_at INTEGER NOT NULL DEFAULT 0,"
        " account_username TEXT NOT NULL DEFAULT '', account_display_name TEXT NOT NULL DEFAULT '',"
        " operator TEXT NOT NULL DEFAULT '', amount_minor INTEGER NOT NULL DEFAULT 0,"
        " currency TEXT NOT NULL DEFAULT 'CNY', description TEXT NOT NULL DEFAULT '',"
        " note TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL DEFAULT 0,"
        " updated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS authentication_vouchers ("
        " id TEXT PRIMARY KEY, batch_id TEXT NOT NULL DEFAULT '', code_digest TEXT NOT NULL DEFAULT '',"
        " code_cipher TEXT NOT NULL DEFAULT '', display_hint TEXT NOT NULL DEFAULT '',"
        " package_id TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'unused',"
        " expires_at INTEGER NOT NULL DEFAULT 0, duration_seconds INTEGER NOT NULL DEFAULT 0,"
        " max_uses INTEGER NOT NULL DEFAULT 1, used_count INTEGER NOT NULL DEFAULT 0,"
        " download_bps INTEGER NOT NULL DEFAULT 0, upload_bps INTEGER NOT NULL DEFAULT 0,"
        " note TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS authentication_sessions ("
        " id TEXT PRIMARY KEY, account_id TEXT NOT NULL DEFAULT '', username TEXT NOT NULL DEFAULT '',"
        " display_name TEXT NOT NULL DEFAULT '', auth_type TEXT NOT NULL DEFAULT '',"
        " ip TEXT NOT NULL DEFAULT '', ipv6 TEXT NOT NULL DEFAULT '', mac TEXT NOT NULL DEFAULT '',"
        " started_at INTEGER NOT NULL DEFAULT 0, last_seen_at INTEGER NOT NULL DEFAULT 0,"
        " authorized_until INTEGER NOT NULL DEFAULT 0, ended_at INTEGER NOT NULL DEFAULT 0,"
        " interface TEXT NOT NULL DEFAULT '', delegated_account TEXT NOT NULL DEFAULT '',"
        " contact TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',"
        " state TEXT NOT NULL DEFAULT 'pending', accounting_session_id TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS authentication_delegated_services ("
        " id TEXT PRIMARY KEY, line_name TEXT NOT NULL DEFAULT '', username TEXT NOT NULL DEFAULT '',"
        " password_cipher TEXT NOT NULL DEFAULT '', interface TEXT NOT NULL DEFAULT '',"
        " delegated_account TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 0,"
        " state TEXT NOT NULL DEFAULT 'disabled', note TEXT NOT NULL DEFAULT '',"
        " created_at INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS authentication_notifications ("
        " id TEXT PRIMARY KEY, kind TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 0,"
        " config_json TEXT NOT NULL DEFAULT '{}', created_at INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS authentication_notification_schedules ("
        " id TEXT PRIMARY KEY, notification_id TEXT NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '',"
        " audience_json TEXT NOT NULL DEFAULT '[]', schedule_json TEXT NOT NULL DEFAULT '{}',"
        " content_json TEXT NOT NULL DEFAULT '{}', enabled INTEGER NOT NULL DEFAULT 0,"
        " created_at INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE INDEX IF NOT EXISTS idx_auth_sessions_state ON authentication_sessions(state,ended_at);"
        "CREATE INDEX IF NOT EXISTS idx_auth_accounts_status ON authentication_accounts(status);"
        "CREATE INDEX IF NOT EXISTS idx_auth_vouchers_status ON authentication_vouchers(status,expires_at);"
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_voucher_digest ON authentication_vouchers(code_digest) WHERE code_digest<>'';"
        "INSERT OR IGNORE INTO authentication_schema_meta(id,schema_version,migrated_at) VALUES(1,1,strftime('%s','now'));"
        "UPDATE authentication_schema_meta SET schema_version=2,migrated_at=strftime('%s','now') WHERE id=1 AND schema_version<2;"
        "INSERT OR IGNORE INTO authentication_settings(id) VALUES(1);"
        "INSERT OR IGNORE INTO authentication_portal(id) VALUES(1);"
        "INSERT OR IGNORE INTO authentication_notifications(id,kind) VALUES('realtime','realtime');"
        "INSERT OR IGNORE INTO authentication_notifications(id,kind) VALUES('expiry','expiry');"
        "INSERT OR IGNORE INTO authentication_notifications(id,kind) VALUES('expired','expired');"
        "COMMIT;";

    if (sqlite3_open_v2(AUTHD_CONFIG_DB_PATH, &g_authd_db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                        NULL) != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-authd] open %s failed: %s\n",
                AUTHD_CONFIG_DB_PATH, g_authd_db ? sqlite3_errmsg(g_authd_db) : "unknown");
        authd_db_close();
        return -1;
    }
    sqlite3_busy_timeout(g_authd_db, 5000);
    if (authd_exec("PRAGMA foreign_keys=ON") != 0 || authd_exec(schema) != 0 ||
        authd_ensure_column("authentication_ledger", "account_username",
                            "TEXT NOT NULL DEFAULT ''") != 0 ||
        authd_ensure_column("authentication_ledger", "account_display_name",
                            "TEXT NOT NULL DEFAULT ''") != 0 ||
        authd_ensure_column("authentication_ledger", "updated_at",
                            "INTEGER NOT NULL DEFAULT 0") != 0 ||
        authd_ensure_column("authentication_settings", "config_json",
                            "TEXT NOT NULL DEFAULT '{}'") != 0 ||
        authd_exec("UPDATE authentication_ledger SET "
                   "account_username=COALESCE(NULLIF(account_username,''),"
                   "(SELECT username FROM authentication_accounts a WHERE a.id=authentication_ledger.account_id),''),"
                   "account_display_name=COALESCE(NULLIF(account_display_name,''),"
                   "(SELECT display_name FROM authentication_accounts a WHERE a.id=authentication_ledger.account_id),'')") != 0 ||
        authd_exec("UPDATE authentication_schema_meta SET schema_version=4,"
                   "migrated_at=strftime('%s','now') WHERE id=1 AND schema_version<4") != 0) {
        authd_db_close();
        return -1;
    }
    return 0;
}

void authd_db_close(void)
{
    if (g_authd_db)
        sqlite3_close(g_authd_db);
    g_authd_db = NULL;
}

struct json_object *authd_status_json(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *tables = json_object_new_object();

    authd_add_source_capabilities(data);
    json_object_object_add(data, "service", json_object_new_string("dreamingwrt-authd"));
    json_object_object_add(data, "status", json_object_new_string("running"));
    json_object_object_add(data, "schema_version", json_object_new_int(AUTHD_SCHEMA_VERSION));
    json_object_object_add(data, "started_at", json_object_new_int64(g_authd_started_at));
    json_object_object_add(data, "uptime_seconds",
                           json_object_new_int64(authd_now_s() - g_authd_started_at));
    json_object_object_add(tables, "accounts",
                           json_object_new_int(authd_query_int("SELECT COUNT(*) FROM authentication_accounts")));
    json_object_object_add(tables, "sessions",
                           json_object_new_int(authd_query_int("SELECT COUNT(*) FROM authentication_sessions")));
    json_object_object_add(tables, "active_sessions", json_object_new_int(authd_query_int(
        "SELECT COUNT(*) FROM authentication_sessions WHERE ended_at=0 AND state IN ('authorized','online')")));
    json_object_object_add(tables, "vouchers",
                           json_object_new_int(authd_query_int("SELECT COUNT(*) FROM authentication_vouchers")));
    json_object_object_add(data, "rows", tables);
    return authd_envelope(data);
}

static struct json_object *authd_web_data(void)
{
    struct json_object *web = json_object_new_object();
    struct json_object *portal = json_object_new_object();
    struct json_object *rules = json_object_new_array();
    struct json_object *policy = json_object_new_object();
    struct json_object *pre_authorization = json_object_new_array();
    struct json_object *post_authorization = json_object_new_array();
    struct json_object *restricted_dns = json_object_new_array();
    sqlite3_stmt *st;

    st = authd_prepare("SELECT enabled,default_auth_type,default_authorization_minutes,"
                       "idle_timeout_seconds,password_policy_json,config_json,updated_at "
                       "FROM authentication_settings WHERE id=1");
    if (st && sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *config = authd_parse_json(authd_sqlite_text(st, 5, "{}"), json_type_object);
        const char *expiration_unit = "minutes";
        struct json_object *unit_value = NULL;
        int expiration_value = sqlite3_column_int(st, 2);
        if (json_object_object_get_ex(config, "expiration_unit", &unit_value) && unit_value &&
            json_object_is_type(unit_value, json_type_string))
            expiration_unit = json_object_get_string(unit_value);
        if (!strcmp(expiration_unit, "hours") && expiration_value % 60 == 0)
            expiration_value /= 60;
        else if (!strcmp(expiration_unit, "days") && expiration_value % 1440 == 0)
            expiration_value /= 1440;
        else if (strcmp(expiration_unit, "minutes"))
            expiration_unit = "minutes";
        json_object_object_add(web, "enabled", json_object_new_boolean(sqlite3_column_int(st, 0)));
        json_object_object_add(web, "default_auth_type", json_object_new_string(authd_sqlite_text(st, 1, "free")));
        json_object_object_add(web, "default_authorization_minutes", json_object_new_int(sqlite3_column_int(st, 2)));
        json_object_object_add(web, "default_expiration", json_object_new_int(expiration_value));
        json_object_object_add(web, "expiration_unit", json_object_new_string(expiration_unit));
        json_object_object_add(web, "idle_timeout_seconds", json_object_new_int(sqlite3_column_int(st, 3)));
        json_object_object_add(web, "idle_timeout", json_object_new_int(sqlite3_column_int(st, 3) / 60));
        policy = authd_parse_json(authd_sqlite_text(st, 4, "{}"), json_type_object);
        json_object_object_foreach(config, key, value) {
            if (strcmp(key, "guest_password") && strcmp(key, "secret_config") &&
                strcmp(key, "password") && strcmp(key, "shared_secret"))
                json_object_object_add(web, key, json_object_get(value));
        }
        json_object_put(config);
        json_object_object_add(web, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 6)));
    }
    sqlite3_finalize(st);

    st = authd_prepare("SELECT published_version,title,welcome_text,auth_prompt,success_message,"
                       "button_text,language,public_config_json,(secret_config_cipher<>''),updated_at "
                       "FROM authentication_portal WHERE id=1");
    if (st && sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *appearance = authd_parse_json(authd_sqlite_text(st, 7, "{}"), json_type_object);
        json_object_object_add(portal, "published_version", json_object_new_int(sqlite3_column_int(st, 0)));
        json_object_object_add(portal, "title", json_object_new_string(authd_sqlite_text(st, 1, "")));
        json_object_object_add(portal, "welcome_text", json_object_new_string(authd_sqlite_text(st, 2, "")));
        json_object_object_add(portal, "auth_prompt", json_object_new_string(authd_sqlite_text(st, 3, "")));
        json_object_object_add(portal, "authentication_text", json_object_new_string(authd_sqlite_text(st, 3, "")));
        json_object_object_add(portal, "success_message", json_object_new_string(authd_sqlite_text(st, 4, "")));
        json_object_object_add(portal, "success_text", json_object_new_string(authd_sqlite_text(st, 4, "")));
        json_object_object_add(portal, "button_text", json_object_new_string(authd_sqlite_text(st, 5, "")));
        json_object_object_add(portal, "language", json_object_new_string(authd_sqlite_text(st, 6, "zh-CN")));
        json_object_object_foreach(appearance, key, value)
            json_object_object_add(portal, key, json_object_get(value));
        json_object_object_add(portal, "appearance", appearance);
        json_object_object_add(web, "has_guest_password", json_object_new_boolean(sqlite3_column_int(st, 8)));
        json_object_object_add(portal, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 9)));
    }
    sqlite3_finalize(st);

    st = authd_prepare("SELECT id,rule_type,target_type,target_value,enabled,priority,note,updated_at "
                       "FROM authentication_access_rules ORDER BY priority,id");
    while (st && sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *item = json_object_new_object();
        json_object_object_add(item, "id", json_object_new_string(authd_sqlite_text(st, 0, "")));
        json_object_object_add(item, "rule_type", json_object_new_string(authd_sqlite_text(st, 1, "")));
        json_object_object_add(item, "scope", json_object_new_string(authd_sqlite_text(st, 1, "")));
        json_object_object_add(item, "target_type", json_object_new_string(authd_sqlite_text(st, 2, "")));
        json_object_object_add(item, "type", json_object_new_string(authd_sqlite_text(st, 2, "")));
        json_object_object_add(item, "target_value", json_object_new_string(authd_sqlite_text(st, 3, "")));
        json_object_object_add(item, "value", json_object_new_string(authd_sqlite_text(st, 3, "")));
        json_object_object_add(item, "enabled", json_object_new_boolean(sqlite3_column_int(st, 4)));
        json_object_object_add(item, "priority", json_object_new_int(sqlite3_column_int(st, 5)));
        json_object_object_add(item, "note", json_object_new_string(authd_sqlite_text(st, 6, "")));
        json_object_object_add(item, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 7)));
        json_object_array_add(rules, item);
        if (!strcmp(authd_sqlite_text(st, 1, ""), "pre_authorization"))
            json_object_array_add(pre_authorization, json_object_get(item));
        else if (!strcmp(authd_sqlite_text(st, 1, ""), "post_authorization"))
            json_object_array_add(post_authorization, json_object_get(item));
        else if (!strcmp(authd_sqlite_text(st, 1, ""), "restricted_dns"))
            json_object_array_add(restricted_dns,
                json_object_new_string(authd_sqlite_text(st, 3, "")));
    }
    sqlite3_finalize(st);
    json_object_object_add(web, "portal", portal);
    json_object_object_add(web, "access_rules", rules);
    json_object_object_add(web, "pre_authorization", pre_authorization);
    json_object_object_add(web, "post_authorization", post_authorization);
    json_object_object_add(web, "restricted_dns_servers", restricted_dns);
    json_object_object_add(web, "restricted_dns_enabled",
                           json_object_new_boolean(json_object_array_length(restricted_dns) > 0));
    json_object_object_add(web, "password_policy", policy);
    return web;
}

static struct json_object *authd_sessions_array(int limit, int offset)
{
    struct json_object *items = json_object_new_array();
    sqlite3_stmt *st = authd_prepare(
        "SELECT id,account_id,username,display_name,auth_type,ip,ipv6,mac,started_at,last_seen_at,"
        "authorized_until,interface,delegated_account,contact,note,state,accounting_session_id,updated_at "
        "FROM authentication_sessions WHERE ended_at=0 AND state IN ('authorized','online') "
        "ORDER BY last_seen_at DESC,id LIMIT ?1 OFFSET ?2");

    if (st) {
        sqlite3_bind_int(st, 1, limit);
        sqlite3_bind_int(st, 2, offset);
    }
    while (st && sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *item = json_object_new_object();
        json_object_object_add(item, "id", json_object_new_string(authd_sqlite_text(st, 0, "")));
        json_object_object_add(item, "account_id", json_object_new_string(authd_sqlite_text(st, 1, "")));
        json_object_object_add(item, "username", json_object_new_string(authd_sqlite_text(st, 2, "")));
        json_object_object_add(item, "name", json_object_new_string(authd_sqlite_text(st, 3, "")));
        json_object_object_add(item, "auth_type", json_object_new_string(authd_sqlite_text(st, 4, "")));
        json_object_object_add(item, "ip", json_object_new_string(authd_sqlite_text(st, 5, "")));
        json_object_object_add(item, "ipv6", json_object_new_string(authd_sqlite_text(st, 6, "")));
        json_object_object_add(item, "mac", json_object_new_string(authd_sqlite_text(st, 7, "")));
        json_object_object_add(item, "started_at", json_object_new_int64(sqlite3_column_int64(st, 8)));
        json_object_object_add(item, "last_seen_at", json_object_new_int64(sqlite3_column_int64(st, 9)));
        json_object_object_add(item, "authorized_until", json_object_new_int64(sqlite3_column_int64(st, 10)));
        json_object_object_add(item, "interface", json_object_new_string(authd_sqlite_text(st, 11, "")));
        json_object_object_add(item, "delegated_account", json_object_new_string(authd_sqlite_text(st, 12, "")));
        json_object_object_add(item, "contact", json_object_new_string(authd_sqlite_text(st, 13, "")));
        json_object_object_add(item, "note", json_object_new_string(authd_sqlite_text(st, 14, "")));
        json_object_object_add(item, "state", json_object_new_string(authd_sqlite_text(st, 15, "")));
        json_object_object_add(item, "accounting_session_id", json_object_new_string(authd_sqlite_text(st, 16, "")));
        json_object_object_add(item, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 17)));
        json_object_array_add(items, item);
    }
    sqlite3_finalize(st);
    return items;
}

static struct json_object *authd_packages_array(int limit, int offset)
{
    struct json_object *items = json_object_new_array();
    sqlite3_stmt *st = authd_prepare(
        "SELECT id,name,validity_seconds,price_minor,currency,download_bps,upload_bps,enabled,note,updated_at "
        "FROM authentication_packages ORDER BY name,id LIMIT ?1 OFFSET ?2");

    if (st) { sqlite3_bind_int(st, 1, limit); sqlite3_bind_int(st, 2, offset); }
    while (st && sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *item = json_object_new_object();
        char validity[64], down_rate[64], up_rate[64];
        authd_format_duration(sqlite3_column_int64(st, 2), validity, sizeof(validity));
        authd_format_rate(sqlite3_column_int64(st, 5), down_rate, sizeof(down_rate));
        authd_format_rate(sqlite3_column_int64(st, 6), up_rate, sizeof(up_rate));
        json_object_object_add(item, "id", json_object_new_string(authd_sqlite_text(st, 0, "")));
        json_object_object_add(item, "name", json_object_new_string(authd_sqlite_text(st, 1, "")));
        json_object_object_add(item, "validity_seconds", json_object_new_int64(sqlite3_column_int64(st, 2)));
        json_object_object_add(item, "validity", json_object_new_string(validity));
        json_object_object_add(item, "price_minor", json_object_new_int64(sqlite3_column_int64(st, 3)));
        json_object_object_add(item, "price", json_object_new_double((double)sqlite3_column_int64(st, 3) / 100.0));
        json_object_object_add(item, "currency", json_object_new_string(authd_sqlite_text(st, 4, "CNY")));
        json_object_object_add(item, "download_bps", json_object_new_int64(sqlite3_column_int64(st, 5)));
        json_object_object_add(item, "upload_bps", json_object_new_int64(sqlite3_column_int64(st, 6)));
        json_object_object_add(item, "down_rate", json_object_new_string(down_rate));
        json_object_object_add(item, "up_rate", json_object_new_string(up_rate));
        json_object_object_add(item, "enabled", json_object_new_boolean(sqlite3_column_int(st, 7)));
        json_object_object_add(item, "note", json_object_new_string(authd_sqlite_text(st, 8, "")));
        json_object_object_add(item, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 9)));
        json_object_array_add(items, item);
    }
    sqlite3_finalize(st);
    return items;
}

static struct json_object *authd_accounts_array(int limit, int offset)
{
    struct json_object *items = json_object_new_array();
    sqlite3_stmt *st = authd_prepare(
        "SELECT id,username,display_name,auth_type,package_id,expires_at,online_seconds,offline_seconds,"
        "contact,bound_mac,allowed_source,status,note,(password_hash<>''),created_at,updated_at "
        "FROM authentication_accounts ORDER BY username,id LIMIT ?1 OFFSET ?2");

    if (st) { sqlite3_bind_int(st, 1, limit); sqlite3_bind_int(st, 2, offset); }
    while (st && sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *item = json_object_new_object();
        char expires_at[32];
        authd_format_datetime_local(sqlite3_column_int64(st, 5), expires_at, sizeof(expires_at));
        json_object_object_add(item, "id", json_object_new_string(authd_sqlite_text(st, 0, "")));
        json_object_object_add(item, "username", json_object_new_string(authd_sqlite_text(st, 1, "")));
        json_object_object_add(item, "account", json_object_new_string(authd_sqlite_text(st, 1, "")));
        json_object_object_add(item, "name", json_object_new_string(authd_sqlite_text(st, 2, "")));
        json_object_object_add(item, "auth_type", json_object_new_string(authd_sqlite_text(st, 3, "")));
        json_object_object_add(item, "package_id", json_object_new_string(authd_sqlite_text(st, 4, "")));
        json_object_object_add(item, "expires_at", json_object_new_string(expires_at));
        json_object_object_add(item, "expires_at_epoch", json_object_new_int64(sqlite3_column_int64(st, 5)));
        json_object_object_add(item, "online_seconds", json_object_new_int64(sqlite3_column_int64(st, 6)));
        json_object_object_add(item, "offline_seconds", json_object_new_int64(sqlite3_column_int64(st, 7)));
        json_object_object_add(item, "contact", json_object_new_string(authd_sqlite_text(st, 8, "")));
        json_object_object_add(item, "phone", json_object_new_string(authd_sqlite_text(st, 8, "")));
        json_object_object_add(item, "bound_mac", json_object_new_string(authd_sqlite_text(st, 9, "")));
        json_object_object_add(item, "mac", json_object_new_string(authd_sqlite_text(st, 9, "")));
        json_object_object_add(item, "allowed_source", json_object_new_string(authd_sqlite_text(st, 10, "")));
        json_object_object_add(item, "source_addresses",
                               authd_parse_json(authd_sqlite_text(st, 10, "[]"), json_type_array));
        json_object_object_add(item, "status", json_object_new_string(authd_sqlite_text(st, 11, "")));
        json_object_object_add(item, "enabled",
                               json_object_new_boolean(!strcmp(authd_sqlite_text(st, 11, ""), "enabled")));
        json_object_object_add(item, "note", json_object_new_string(authd_sqlite_text(st, 12, "")));
        json_object_object_add(item, "has_password", json_object_new_boolean(sqlite3_column_int(st, 13)));
        json_object_object_add(item, "created_at", json_object_new_int64(sqlite3_column_int64(st, 14)));
        json_object_object_add(item, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 15)));
        json_object_array_add(items, item);
    }
    sqlite3_finalize(st);
    return items;
}

static struct json_object *authd_ledger_array(int limit, int offset)
{
    struct json_object *items = json_object_new_array();
    sqlite3_stmt *st = authd_prepare(
        "SELECT l.id,l.account_id,"
        "COALESCE(NULLIF(l.account_username,''),a.username,l.account_id),"
        "COALESCE(NULLIF(l.account_display_name,''),a.display_name,''),"
        "l.charged_at,l.operator,l.amount_minor,l.currency,l.description,l.note,l.created_at,l.updated_at "
        "FROM authentication_ledger l LEFT JOIN authentication_accounts a ON a.id=l.account_id "
        "ORDER BY l.charged_at DESC,l.id LIMIT ?1 OFFSET ?2");

    if (st) { sqlite3_bind_int(st, 1, limit); sqlite3_bind_int(st, 2, offset); }
    while (st && sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *item = json_object_new_object();
        char charged_at[32], amount[64];
        int64_t amount_minor = sqlite3_column_int64(st, 6);
        authd_format_datetime_local(sqlite3_column_int64(st, 4), charged_at, sizeof(charged_at));
        snprintf(amount, sizeof(amount), "%lld.%02lld",
                 (long long)(amount_minor / 100), (long long)(amount_minor % 100));
        json_object_object_add(item, "id", json_object_new_string(authd_sqlite_text(st, 0, "")));
        json_object_object_add(item, "account_id", json_object_new_string(authd_sqlite_text(st, 1, "")));
        json_object_object_add(item, "account", json_object_new_string(authd_sqlite_text(st, 2, "")));
        json_object_object_add(item, "username", json_object_new_string(authd_sqlite_text(st, 2, "")));
        json_object_object_add(item, "name", json_object_new_string(authd_sqlite_text(st, 3, "")));
        json_object_object_add(item, "charged_at", json_object_new_string(charged_at));
        json_object_object_add(item, "charged_at_epoch", json_object_new_int64(sqlite3_column_int64(st, 4)));
        json_object_object_add(item, "operator", json_object_new_string(authd_sqlite_text(st, 5, "")));
        json_object_object_add(item, "amount_minor", json_object_new_int64(amount_minor));
        json_object_object_add(item, "amount", json_object_new_string(amount));
        json_object_object_add(item, "currency", json_object_new_string(authd_sqlite_text(st, 7, "CNY")));
        json_object_object_add(item, "description", json_object_new_string(authd_sqlite_text(st, 8, "")));
        json_object_object_add(item, "note", json_object_new_string(authd_sqlite_text(st, 9, "")));
        json_object_object_add(item, "created_at", json_object_new_int64(sqlite3_column_int64(st, 10)));
        json_object_object_add(item, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 11)));
        json_object_array_add(items, item);
    }
    sqlite3_finalize(st);
    return items;
}

static struct json_object *authd_vouchers_array(int limit, int offset)
{
    struct json_object *items = json_object_new_array();
    sqlite3_stmt *st = authd_prepare(
        "SELECT id,batch_id,display_hint,package_id,status,expires_at,duration_seconds,max_uses,used_count,"
        "download_bps,upload_bps,note,(code_digest<>'' OR code_cipher<>''),created_at,updated_at "
        "FROM authentication_vouchers ORDER BY created_at DESC,id LIMIT ?1 OFFSET ?2");

    if (st) { sqlite3_bind_int(st, 1, limit); sqlite3_bind_int(st, 2, offset); }
    while (st && sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *item = json_object_new_object();
        char expires_at[32], duration[64], down_rate[64], up_rate[64];
        authd_format_datetime_local(sqlite3_column_int64(st, 5), expires_at, sizeof(expires_at));
        authd_format_duration(sqlite3_column_int64(st, 6), duration, sizeof(duration));
        authd_format_rate(sqlite3_column_int64(st, 9), down_rate, sizeof(down_rate));
        authd_format_rate(sqlite3_column_int64(st, 10), up_rate, sizeof(up_rate));
        json_object_object_add(item, "id", json_object_new_string(authd_sqlite_text(st, 0, "")));
        json_object_object_add(item, "batch_id", json_object_new_string(authd_sqlite_text(st, 1, "")));
        json_object_object_add(item, "display_hint", json_object_new_string(authd_sqlite_text(st, 2, "")));
        json_object_object_add(item, "code_redacted", json_object_new_boolean(1));
        json_object_object_add(item, "package_id", json_object_new_string(authd_sqlite_text(st, 3, "")));
        json_object_object_add(item, "status", json_object_new_string(authd_sqlite_text(st, 4, "")));
        json_object_object_add(item, "used", json_object_new_boolean(sqlite3_column_int(st, 8) > 0));
        json_object_object_add(item, "expired", json_object_new_boolean(
            !strcmp(authd_sqlite_text(st, 4, ""), "expired") ||
            (sqlite3_column_int64(st, 5) > 0 && sqlite3_column_int64(st, 5) <= authd_now_s())));
        json_object_object_add(item, "expires_at", json_object_new_string(expires_at));
        json_object_object_add(item, "expires_at_epoch", json_object_new_int64(sqlite3_column_int64(st, 5)));
        json_object_object_add(item, "duration_seconds", json_object_new_int64(sqlite3_column_int64(st, 6)));
        json_object_object_add(item, "duration", json_object_new_string(duration));
        json_object_object_add(item, "max_uses", json_object_new_int(sqlite3_column_int(st, 7)));
        json_object_object_add(item, "used_count", json_object_new_int(sqlite3_column_int(st, 8)));
        json_object_object_add(item, "download_bps", json_object_new_int64(sqlite3_column_int64(st, 9)));
        json_object_object_add(item, "upload_bps", json_object_new_int64(sqlite3_column_int64(st, 10)));
        json_object_object_add(item, "down_rate", json_object_new_string(down_rate));
        json_object_object_add(item, "up_rate", json_object_new_string(up_rate));
        json_object_object_add(item, "note", json_object_new_string(authd_sqlite_text(st, 11, "")));
        json_object_object_add(item, "has_code", json_object_new_boolean(sqlite3_column_int(st, 12)));
        json_object_object_add(item, "created_at", json_object_new_int64(sqlite3_column_int64(st, 13)));
        json_object_object_add(item, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 14)));
        json_object_array_add(items, item);
    }
    sqlite3_finalize(st);
    return items;
}

static struct json_object *authd_delegated_array(int limit, int offset)
{
    struct json_object *items = json_object_new_array();
    sqlite3_stmt *st = authd_prepare(
        "SELECT id,line_name,username,interface,delegated_account,enabled,state,note,(password_cipher<>''),created_at,updated_at "
        "FROM authentication_delegated_services ORDER BY line_name,id LIMIT ?1 OFFSET ?2");

    if (st) { sqlite3_bind_int(st, 1, limit); sqlite3_bind_int(st, 2, offset); }
    while (st && sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *item = json_object_new_object();
        json_object_object_add(item, "id", json_object_new_string(authd_sqlite_text(st, 0, "")));
        json_object_object_add(item, "line_name", json_object_new_string(authd_sqlite_text(st, 1, "")));
        json_object_object_add(item, "name", json_object_new_string(authd_sqlite_text(st, 1, "")));
        json_object_object_add(item, "username", json_object_new_string(authd_sqlite_text(st, 2, "")));
        json_object_object_add(item, "account", json_object_new_string(authd_sqlite_text(st, 2, "")));
        json_object_object_add(item, "interface", json_object_new_string(authd_sqlite_text(st, 3, "")));
        json_object_object_add(item, "delegated_account", json_object_new_string(authd_sqlite_text(st, 4, "")));
        json_object_object_add(item, "enabled", json_object_new_boolean(sqlite3_column_int(st, 5)));
        json_object_object_add(item, "state", json_object_new_string(authd_sqlite_text(st, 6, "")));
        json_object_object_add(item, "note", json_object_new_string(authd_sqlite_text(st, 7, "")));
        json_object_object_add(item, "has_password", json_object_new_boolean(sqlite3_column_int(st, 8)));
        json_object_object_add(item, "created_at", json_object_new_int64(sqlite3_column_int64(st, 9)));
        json_object_object_add(item, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 10)));
        json_object_array_add(items, item);
    }
    sqlite3_finalize(st);
    return items;
}

/*
 * Enumerate the WANs a delegated service may dial over.
 *
 * The write path only accepts a value matching wan.id / ifname / device of an
 * enabled line, so the UI needs the same list to build a picker instead of a
 * free-text box. Ordering matches route preference (metric, then priority),
 * which makes the first entry the sensible default.
 */
struct json_object *authd_delegated_interface_options(void)
{
    struct json_object *items = json_object_new_array();
    sqlite3_stmt *st = authd_prepare(
        "SELECT id,name,ifname,device,metric,priority,role FROM wan WHERE enabled=1 "
        "ORDER BY metric, priority, id");

    while (st && sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *item = json_object_new_object();
        const char *id = authd_sqlite_text(st, 0, "");
        const char *name = authd_sqlite_text(st, 1, "");
        const char *ifname = authd_sqlite_text(st, 2, "");

        json_object_object_add(item, "value", json_object_new_string(id));
        json_object_object_add(item, "label",
                               json_object_new_string(name[0] ? name : id));
        json_object_object_add(item, "ifname", json_object_new_string(ifname));
        json_object_object_add(item, "device", json_object_new_string(authd_sqlite_text(st, 3, "")));
        json_object_object_add(item, "metric", json_object_new_int(sqlite3_column_int(st, 4)));
        json_object_object_add(item, "priority", json_object_new_int(sqlite3_column_int(st, 5)));
        json_object_object_add(item, "role", json_object_new_string(authd_sqlite_text(st, 6, "")));
        json_object_array_add(items, item);
    }
    sqlite3_finalize(st);
    return items;
}

/*
 * Resolve the interface a delegated service gets when the caller leaves the
 * field empty: the most preferred enabled WAN. Returns 1 when one was written
 * to out, 0 when no enabled WAN exists, -1 when the table is unreadable.
 */
int authd_delegated_interface_default(char *out, size_t out_len)
{
    sqlite3_stmt *st;
    int found = 0;

    if (!out || !out_len)
        return -1;
    out[0] = '\0';
    if (!g_authd_db)
        return -1;
    if (sqlite3_prepare_v2(g_authd_db,
                           "SELECT id FROM wan WHERE enabled=1 "
                           "ORDER BY metric, priority, id LIMIT 1",
                           -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        snprintf(out, out_len, "%s", authd_sqlite_text(st, 0, ""));
        found = out[0] ? 1 : 0;
    }
    sqlite3_finalize(st);
    return found;
}

static struct json_object *authd_notifications_data(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *periodic = json_object_new_array();
    sqlite3_stmt *st = authd_prepare(
        "SELECT kind,enabled,config_json,updated_at FROM authentication_notifications ORDER BY kind");

    json_object_object_add(data, "realtime", json_object_new_object());
    json_object_object_add(data, "expiry", json_object_new_object());
    json_object_object_add(data, "expired", json_object_new_object());
    while (st && sqlite3_step(st) == SQLITE_ROW) {
        const char *kind = authd_sqlite_text(st, 0, "");
        struct json_object *item = authd_parse_json(authd_sqlite_text(st, 2, "{}"), json_type_object);
        json_object_object_add(item, "enabled", json_object_new_boolean(sqlite3_column_int(st, 1)));
        json_object_object_add(item, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 3)));
        if (!strcmp(kind, "realtime") || !strcmp(kind, "expiry") || !strcmp(kind, "expired")) {
            json_object_object_del(data, kind);
            json_object_object_add(data, kind, item);
        } else {
            json_object_put(item);
        }
    }
    sqlite3_finalize(st);
    st = authd_prepare("SELECT id,notification_id,name,audience_json,schedule_json,content_json,enabled,created_at,updated_at "
                       "FROM authentication_notification_schedules ORDER BY name,id");
    while (st && sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *item = json_object_new_object();
        struct json_object *audience = authd_parse_json(authd_sqlite_text(st, 3, "{}"), json_type_object);
        struct json_object *schedule = authd_parse_json(authd_sqlite_text(st, 4, "{}"), json_type_object);
        struct json_object *content = authd_parse_json(authd_sqlite_text(st, 5, "{}"), json_type_object);
        json_object_object_add(item, "id", json_object_new_string(authd_sqlite_text(st, 0, "")));
        json_object_object_add(item, "notification_id", json_object_new_string(authd_sqlite_text(st, 1, "")));
        json_object_object_add(item, "name", json_object_new_string(authd_sqlite_text(st, 2, "")));
        {
            json_object_object_foreach(audience, key, value)
                json_object_object_add(item, key, json_object_get(value));
        }
        {
            json_object_object_foreach(schedule, key, value)
                json_object_object_add(item, key, json_object_get(value));
        }
        {
            json_object_object_foreach(content, key, value)
                json_object_object_add(item, key, json_object_get(value));
        }
        json_object_object_add(item, "audience", audience);
        json_object_object_add(item, "schedule_config", schedule);
        json_object_object_add(item, "content_config", content);
        json_object_object_add(item, "enabled", json_object_new_boolean(sqlite3_column_int(st, 6)));
        json_object_object_add(item, "created_at", json_object_new_int64(sqlite3_column_int64(st, 7)));
        json_object_object_add(item, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 8)));
        json_object_array_add(periodic, item);
    }
    sqlite3_finalize(st);
    json_object_object_add(data, "periodic", periodic);
    return data;
}

static struct json_object *authd_page(struct json_object *items, int total, int limit, int offset)
{
    struct json_object *data = json_object_new_object();

    authd_add_source_capabilities(data);
    json_object_object_add(data, "items", items);
    json_object_object_add(data, "total", json_object_new_int(total));
    json_object_object_add(data, "limit", json_object_new_int(limit));
    json_object_object_add(data, "offset", json_object_new_int(offset));
    return authd_envelope(data);
}

struct json_object *authd_web_json(void)
{
    struct json_object *data = authd_web_data();
    authd_add_source_capabilities(data);
    return authd_envelope(data);
}

struct json_object *authd_portal_json(void)
{
    struct json_object *web = authd_web_data();
    struct json_object *portal = NULL;
    struct json_object *data = json_object_new_object();

    authd_add_source_capabilities(data);
    if (json_object_object_get_ex(web, "portal", &portal) && portal)
        json_object_object_add(data, "portal", json_object_get(portal));
    else
        json_object_object_add(data, "portal", json_object_new_object());
    json_object_put(web);
    return authd_envelope(data);
}

struct json_object *authd_online_users_json(struct json_object *query)
{
    int limit = authd_query_limit(query), offset = authd_query_offset(query);
    return authd_page(authd_sessions_array(limit, offset), authd_query_int(
        "SELECT COUNT(*) FROM authentication_sessions WHERE ended_at=0 AND state IN ('authorized','online')"),
        limit, offset);
}

struct json_object *authd_packages_json(struct json_object *query)
{
    int limit = authd_query_limit(query), offset = authd_query_offset(query);
    return authd_page(authd_packages_array(limit, offset),
                      authd_query_int("SELECT COUNT(*) FROM authentication_packages"), limit, offset);
}

struct json_object *authd_accounts_json(struct json_object *query)
{
    int limit = authd_query_limit(query), offset = authd_query_offset(query);
    return authd_page(authd_accounts_array(limit, offset),
                      authd_query_int("SELECT COUNT(*) FROM authentication_accounts"), limit, offset);
}

struct json_object *authd_ledger_json(struct json_object *query)
{
    int limit = authd_query_limit(query), offset = authd_query_offset(query);
    return authd_page(authd_ledger_array(limit, offset),
                      authd_query_int("SELECT COUNT(*) FROM authentication_ledger"),
                      limit, offset);
}

struct json_object *authd_account_management_json(struct json_object *query)
{
    struct json_object *data = json_object_new_object();
    struct json_object *totals = json_object_new_object();
    struct json_object *web = authd_web_data();
    struct json_object *password_policy = NULL;
    int limit = authd_query_limit(query), offset = authd_query_offset(query);

    authd_add_source_capabilities(data);
    if (json_object_object_get_ex(web, "password_policy", &password_policy))
        json_object_get(password_policy);
    else
        password_policy = json_object_new_object();
    json_object_object_add(data, "packages", authd_packages_array(limit, offset));
    json_object_object_add(data, "accounts", authd_accounts_array(limit, offset));
    json_object_object_add(data, "password_policy", password_policy);
    json_object_object_add(data, "ledger", authd_ledger_array(limit, offset));
    json_object_object_add(data, "vouchers", authd_vouchers_array(limit, offset));
    json_object_object_add(totals, "packages",
                           json_object_new_int(authd_query_int("SELECT COUNT(*) FROM authentication_packages")));
    json_object_object_add(totals, "accounts",
                           json_object_new_int(authd_query_int("SELECT COUNT(*) FROM authentication_accounts")));
    json_object_object_add(totals, "ledger",
                           json_object_new_int(authd_query_int("SELECT COUNT(*) FROM authentication_ledger")));
    json_object_object_add(totals, "vouchers",
                           json_object_new_int(authd_query_int("SELECT COUNT(*) FROM authentication_vouchers")));
    json_object_object_add(data, "totals", totals);
    json_object_put(web);
    return authd_envelope(data);
}

struct json_object *authd_vouchers_json(struct json_object *query)
{
    int limit = authd_query_limit(query), offset = authd_query_offset(query);
    return authd_page(authd_vouchers_array(limit, offset),
                      authd_query_int("SELECT COUNT(*) FROM authentication_vouchers"), limit, offset);
}

struct json_object *authd_delegated_json(struct json_object *query)
{
    struct json_object *root;
    struct json_object *data;
    int limit = authd_query_limit(query), offset = authd_query_offset(query);

    root = authd_page(authd_delegated_array(limit, offset),
                      authd_query_int("SELECT COUNT(*) FROM authentication_delegated_services"),
                      limit, offset);
    if (json_object_object_get_ex(root, "data", &data)) {
        json_object_object_add(data, "online", json_object_new_array());
        json_object_object_add(data, "interface_options",
                               authd_delegated_interface_options());
    }
    return root;
}

struct json_object *authd_notifications_json(void)
{
    struct json_object *data = authd_notifications_data();
    authd_add_source_capabilities(data);
    return authd_envelope(data);
}

struct json_object *authd_aggregate_json(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *accounts = json_object_new_object();
    struct json_object *delegated = json_object_new_object();
    struct json_object *web = authd_web_data();
    struct json_object *password_policy = NULL;

    authd_add_source_capabilities(data);
    if (json_object_object_get_ex(web, "password_policy", &password_policy))
        json_object_get(password_policy);
    else
        password_policy = json_object_new_object();
    json_object_object_add(data, "web", web);
    json_object_object_add(data, "online_users", authd_sessions_array(AUTHD_MAX_LIMIT, 0));
    json_object_object_add(accounts, "packages", authd_packages_array(AUTHD_MAX_LIMIT, 0));
    json_object_object_add(accounts, "accounts", authd_accounts_array(AUTHD_MAX_LIMIT, 0));
    json_object_object_add(accounts, "password_policy", password_policy);
    json_object_object_add(accounts, "ledger", authd_ledger_array(AUTHD_MAX_LIMIT, 0));
    json_object_object_add(accounts, "vouchers", authd_vouchers_array(AUTHD_MAX_LIMIT, 0));
    json_object_object_add(data, "account_management", accounts);
    json_object_object_add(delegated, "services", authd_delegated_array(AUTHD_MAX_LIMIT, 0));
    json_object_object_add(delegated, "online", json_object_new_array());
    json_object_object_add(delegated, "interface_options",
                           authd_delegated_interface_options());
    json_object_object_add(data, "delegated", delegated);
    json_object_object_add(data, "notifications", authd_notifications_data());
    json_object_object_add(data, "aggregate_limit", json_object_new_int(AUTHD_MAX_LIMIT));
    json_object_object_add(data, "aggregate_truncated", json_object_new_boolean(
        authd_query_int("SELECT CASE WHEN "
                        "(SELECT COUNT(*) FROM authentication_sessions)>500 OR "
                        "(SELECT COUNT(*) FROM authentication_packages)>500 OR "
                        "(SELECT COUNT(*) FROM authentication_accounts)>500 OR "
                        "(SELECT COUNT(*) FROM authentication_ledger)>500 OR "
                        "(SELECT COUNT(*) FROM authentication_vouchers)>500 OR "
                        "(SELECT COUNT(*) FROM authentication_delegated_services)>500 "
                        "THEN 1 ELSE 0 END")));
    return authd_envelope(data);
}

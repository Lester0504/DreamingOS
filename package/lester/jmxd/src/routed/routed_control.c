// SPDX-License-Identifier: GPL-2.0-or-later
/* Independent transactional control plane for DreamingWrt routing metadata. */
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <json-c/json.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include <sqlite3.h>
#include <uci.h>

#include "routed_control.h"
#include "gateway_ports.h"

#define ROUTED_DB_PATH "/etc/dreamingwrt/config.db"
#define ROUTED_OBJECT_NAME "dreamingwrt.routed"
#define ROUTED_ALIAS_OBJECT_NAME "dreamingos.routed"
#define ROUTED_DB_TIMEOUT_MS 5000
#define ROUTED_CORE_TIMEOUT_MS 8000
#define ROUTED_MAX_ID 96
#define ROUTED_MAX_TEXT 512
#define WORKER_STATUS_VERSION "1.0"
#define ROUTED_CONTRACT_VERSION "routing.v1"

static struct ubus_object routed_object;
static struct ubus_object routed_alias_object;
static struct blob_buf routed_blob;

static int64_t routed_now(void)
{
    return (int64_t)time(NULL);
}

static const char *routed_text(sqlite3_stmt *st, int col)
{
    const unsigned char *s = sqlite3_column_text(st, col);
    return s ? (const char *)s : "";
}

static const char *routed_json_str(struct json_object *o, const char *key,
                                   const char *def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v ||
        !json_object_is_type(v, json_type_string))
        return def;
    return json_object_get_string(v) ? json_object_get_string(v) : def;
}

static int routed_json_int(struct json_object *o, const char *key, int def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    return json_object_get_int(v);
}

static int routed_json_bool(struct json_object *o, const char *key, int def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    return json_object_get_boolean(v) ? 1 : 0;
}

static int routed_id_ok(const char *s)
{
    const unsigned char *p;

    if (!s || !s[0] || strlen(s) > ROUTED_MAX_ID)
        return 0;
    for (p = (const unsigned char *)s; *p; p++)
        if (!(isalnum(*p) || *p == '_' || *p == '-' || *p == '.'))
            return 0;
    return 1;
}

static int routed_text_ok(const char *s, size_t max_len)
{
    const unsigned char *p;

    if (!s || strlen(s) > max_len)
        return 0;
    for (p = (const unsigned char *)s; *p; p++)
        if (*p < 0x20 && *p != '\t')
            return 0;
    return 1;
}

/* Custom table numbers only: 253/254/255 are default/main/local. */
static int routed_table_id_ok(int table_id)
{
    return table_id > 0 && table_id < 32768 &&
           table_id != 253 && table_id != 254 && table_id != 255;
}

static struct json_object *routed_error(const char *code, const char *message,
                                        int http_status)
{
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "ok", json_object_new_boolean(0));
    json_object_object_add(o, "error", json_object_new_string(code ? code : "error"));
    json_object_object_add(o, "message", json_object_new_string(message ? message : ""));
    json_object_object_add(o, "http_status", json_object_new_int(http_status));
    json_object_object_add(o, "source", json_object_new_string(ROUTED_OBJECT_NAME));
    json_object_object_add(o, "contract_version", json_object_new_string(ROUTED_CONTRACT_VERSION));
    json_object_object_add(o, "ts", json_object_new_int64(routed_now()));
    return o;
}

static struct json_object *routed_ok(void)
{
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "ok", json_object_new_boolean(1));
    json_object_object_add(o, "source", json_object_new_string(ROUTED_OBJECT_NAME));
    json_object_object_add(o, "contract_version", json_object_new_string(ROUTED_CONTRACT_VERSION));
    json_object_object_add(o, "ts", json_object_new_int64(routed_now()));
    return o;
}

static struct json_object *routed_capabilities(void)
{
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "source_of_truth", json_object_new_string("policy_table"));
    json_object_object_add(o, "static_route_source", json_object_new_string("uci:/etc/config/network route/route6"));
    json_object_object_add(o, "pbr_source", json_object_new_string("config.db:policy_route_rule"));
    json_object_object_add(o, "advanced_static_routes_write", json_object_new_boolean(0));
    json_object_object_add(o, "advanced_policy_rules_write", json_object_new_boolean(0));
    json_object_object_add(o, "advanced_projection_read_only", json_object_new_boolean(1));
    json_object_object_add(o, "static_route_projection_source", json_object_new_string("uci:/etc/config/network route/route6"));
    json_object_object_add(o, "legacy_static_route_table_projected", json_object_new_boolean(0));
    json_object_object_add(o, "legacy_adv_tables_write", json_object_new_boolean(0));
    json_object_object_add(o, "table_crud", json_object_new_boolean(1));
    json_object_object_add(o, "object_crud", json_object_new_boolean(1));
    /*
     * object_crud is routed's OWN object catalog (config.db:route_object), written
     * through object_set/object_delete and reloaded via dreamingwrt.route_reload.
     * It is NOT the policy-engine composite object catalog, which is a different
     * resource in a different component and reports objects_crud=false. The two
     * booleans were read as contradicting each other, so both sides now publish
     * an explicit scope string.
     */
    json_object_object_add(o, "object_crud_scope", json_object_new_string("routed:route_object"));
    json_object_object_add(o, "object_crud_write_endpoint", json_object_new_string("/api/v1/routing/objects"));
    json_object_object_add(o, "composite_object_crud", json_object_new_boolean(0));
    json_object_object_add(o, "composite_object_crud_owner", json_object_new_string("policy_engine"));
    json_object_object_add(o, "composite_object_crud_scope",
                           json_object_new_string("policy_engine:composite_object"));
    json_object_object_add(o, "cross_service_crud", json_object_new_boolean(1));
    json_object_object_add(o, "cross_service_config_crud", json_object_new_boolean(1));
    json_object_object_add(o, "cross_service_runtime", json_object_new_boolean(0));
    json_object_object_add(o, "cross_service_runtime_reason", json_object_new_string("runtime_consumer_not_implemented"));
    /*
     * The reason above applies to cross_services only. It was being rendered as a
     * whole-page conclusion for the routing table, which made tables and route
     * objects look unusable when they are not. resource_reasons carries one reason
     * per resource; a resource absent from the map has no blocking reason at all.
     */
    json_object_object_add(o, "cross_service_runtime_reason_scope",
                           json_object_new_string("cross_services"));
    {
        struct json_object *reasons = json_object_new_object();
        struct json_object *writable = json_object_new_array();

        json_object_object_add(reasons, "cross_services_runtime",
                               json_object_new_string("runtime_consumer_not_implemented"));
        json_object_object_add(reasons, "static_routes",
                               json_object_new_string("uci_network_projection_read_only"));
        json_object_object_add(reasons, "policy_rules",
                               json_object_new_string("policy_table_owns_write_path"));
        json_object_object_add(reasons, "external_policies",
                               json_object_new_string("external_policy_files_read_only"));
        json_object_object_add(o, "resource_reasons", reasons);

        json_object_array_add(writable, json_object_new_string("tables"));
        json_object_array_add(writable, json_object_new_string("objects"));
        json_object_array_add(writable, json_object_new_string("cross_services_config"));
        json_object_array_add(writable, json_object_new_string("policy_rules_order"));
        json_object_object_add(o, "writable_resources", writable);
    }
    json_object_object_add(o, "reference_conflict", json_object_new_boolean(1));
    json_object_object_add(o, "policy_reorder", json_object_new_boolean(1));
    json_object_object_add(o, "external_policies_read_only", json_object_new_boolean(1));
    json_object_object_add(o, "runtime_resolve", json_object_new_boolean(1));
    json_object_object_add(o, "runtime_writer", json_object_new_string("dreamingwrt.route_reload"));
    json_object_object_add(o, "pending_confirm_worker", json_object_new_boolean(0));
    return o;
}

static int routed_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-routed] sqlite failed: %s sql=%s\n",
                err ? err : sqlite3_errmsg(db), sql ? sql : "");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static void routed_sync_wan_tables(sqlite3 *db);

static int routed_db_open(sqlite3 **out)
{
    static const char *schema =
        "CREATE TABLE IF NOT EXISTS advanced_routing_global("
        "id INTEGER PRIMARY KEY CHECK(id=1),enabled INTEGER NOT NULL DEFAULT 1,"
        "engine TEXT NOT NULL DEFAULT 'policy table -> route_reload',apply_state TEXT NOT NULL DEFAULT 'draft',"
        "last_apply_at INTEGER NOT NULL DEFAULT 0,default_table TEXT NOT NULL DEFAULT 'main',"
        "object_revision INTEGER NOT NULL DEFAULT 0,health_aware INTEGER NOT NULL DEFAULT 1,"
        "log_policy_hits INTEGER NOT NULL DEFAULT 1,updated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS route_table(id TEXT PRIMARY KEY,name TEXT NOT NULL,"
        "table_id INTEGER NOT NULL UNIQUE,role TEXT NOT NULL DEFAULT '',gateway TEXT NOT NULL DEFAULT '',"
        "metric INTEGER NOT NULL DEFAULT 0,enabled INTEGER NOT NULL DEFAULT 1,updated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS static_route(id TEXT PRIMARY KEY,enabled INTEGER NOT NULL DEFAULT 1,"
        "name TEXT NOT NULL,family TEXT NOT NULL DEFAULT 'ipv4',destination TEXT NOT NULL,"
        "gateway TEXT NOT NULL DEFAULT '',interface TEXT NOT NULL DEFAULT '',route_table TEXT NOT NULL DEFAULT 'main',"
        "metric INTEGER NOT NULL DEFAULT 0,mtu INTEGER NOT NULL DEFAULT 1500,route_type TEXT NOT NULL DEFAULT 'unicast',"
        "comment TEXT NOT NULL DEFAULT '',updated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS route_object(id TEXT PRIMARY KEY,enabled INTEGER NOT NULL DEFAULT 1,"
        "name TEXT NOT NULL UNIQUE,object_type TEXT NOT NULL,family TEXT NOT NULL DEFAULT 'mixed',"
        "value TEXT NOT NULL DEFAULT '',comment TEXT NOT NULL DEFAULT '',updated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS route_object_member(id INTEGER PRIMARY KEY AUTOINCREMENT,object_id TEXT NOT NULL,"
        "value TEXT NOT NULL,label TEXT NOT NULL DEFAULT '',sort_order INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS cross_l3_service(id TEXT PRIMARY KEY,enabled INTEGER NOT NULL DEFAULT 1,"
        "name TEXT NOT NULL,service_type TEXT NOT NULL DEFAULT 'snmp',server_ip TEXT NOT NULL DEFAULT '',"
        "scope TEXT NOT NULL DEFAULT '',listen_port TEXT NOT NULL DEFAULT '161',version TEXT NOT NULL DEFAULT 'V2',"
        "access_rate TEXT NOT NULL DEFAULT '',remark TEXT NOT NULL DEFAULT '',updated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS policy_route_rule(id TEXT PRIMARY KEY,enabled INTEGER NOT NULL DEFAULT 1,"
        "priority INTEGER NOT NULL,name TEXT NOT NULL,source_object TEXT NOT NULL DEFAULT '',"
        "dest_object TEXT NOT NULL DEFAULT '',proto TEXT NOT NULL DEFAULT 'all',ports TEXT NOT NULL DEFAULT 'any',"
        "action TEXT NOT NULL DEFAULT 'route_table',target TEXT NOT NULL DEFAULT '',route_table TEXT NOT NULL DEFAULT '',"
        "schedule TEXT NOT NULL DEFAULT 'always',sticky INTEGER NOT NULL DEFAULT 1,comment TEXT NOT NULL DEFAULT '',"
        "hit_count INTEGER NOT NULL DEFAULT 0,last_hit INTEGER NOT NULL DEFAULT 0,updated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE INDEX IF NOT EXISTS idx_route_object_member_object ON route_object_member(object_id,sort_order,id);"
        "INSERT OR IGNORE INTO advanced_routing_global(id) VALUES(1);";
    sqlite3 *db = NULL;

    if (!out)
        return -1;
    *out = NULL;
    if (sqlite3_open_v2(ROUTED_DB_PATH, &db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        return -1;
    }
    sqlite3_busy_timeout(db, ROUTED_DB_TIMEOUT_MS);
    if (routed_exec(db, schema) != 0) {
        sqlite3_close(db);
        return -1;
    }
    routed_sync_wan_tables(db);
    *out = db;
    return 0;
}

static struct json_object *routed_json_from_blob(struct blob_attr *msg)
{
    struct json_object *o = NULL;
    char *s;

    if (!msg)
        return json_object_new_object();
    s = blobmsg_format_json(msg, true);
    if (s) {
        o = json_tokener_parse(s);
        free(s);
    }
    return o ? o : json_object_new_object();
}

static struct json_object *routed_payload(struct json_object *o)
{
    struct json_object *v = NULL;

    if (o && json_object_object_get_ex(o, "payload", &v) && v &&
        json_object_is_type(v, json_type_object))
        return v;
    return o;
}

static int routed_send(struct ubus_context *ctx, struct ubus_request_data *req,
                       struct json_object *o)
{
    const char *s = o ? json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN) : "{}";

    blob_buf_init(&routed_blob, 0);
    if (!blobmsg_add_json_from_string(&routed_blob, s)) {
        blob_buf_free(&routed_blob);
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    ubus_send_reply(ctx, req, routed_blob.head);
    blob_buf_free(&routed_blob);
    return UBUS_STATUS_OK;
}

struct routed_invoke_result {
    struct json_object *json;
};

static void routed_invoke_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct routed_invoke_result *r = req ? req->priv : NULL;
    char *s;

    (void)type;
    if (!r || !msg)
        return;
    s = blobmsg_format_json(msg, true);
    if (!s)
        return;
    r->json = json_tokener_parse(s);
    free(s);
}

static int routed_core_reload(struct ubus_context *ctx, struct json_object **detail)
{
    struct ubus_context *call_ctx = NULL;
    struct routed_invoke_result result = {0};
    struct blob_buf b = {};
    struct json_object *code = NULL, *data = NULL, *ok = NULL;
    uint32_t id = 0;
    int rc;

    if (detail)
        *detail = NULL;
    (void)ctx;
    call_ctx = ubus_connect(NULL);
    if (!call_ctx || ubus_lookup_id(call_ctx, "dreamingwrt", &id) != UBUS_STATUS_OK) {
        if (call_ctx)
            ubus_free(call_ctx);
        return -1;
    }
    blob_buf_init(&b, 0);
    rc = ubus_invoke(call_ctx, id, "route_reload", b.head, routed_invoke_cb, &result,
                     ROUTED_CORE_TIMEOUT_MS);
    blob_buf_free(&b);
    ubus_free(call_ctx);
    if (detail)
        *detail = result.json;
    if (rc != UBUS_STATUS_OK || !result.json)
        return -1;
    if (json_object_object_get_ex(result.json, "code", &code) && code &&
        json_object_get_int(code) != 2000)
        return -1;
    if (json_object_object_get_ex(result.json, "data", &data) && data &&
        json_object_object_get_ex(data, "ok", &ok) && ok && !json_object_get_boolean(ok))
        return -1;
    return 0;
}

static void routed_touch_revision(sqlite3 *db)
{
    routed_exec(db, "UPDATE advanced_routing_global SET object_revision=object_revision+1,"
                    "apply_state='draft',updated_at=strftime('%s','now') WHERE id=1");
}

static sqlite3_int64 routed_object_revision(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    sqlite3_int64 revision = 0;

    if (db && sqlite3_prepare_v2(db,
            "SELECT object_revision FROM advanced_routing_global WHERE id=1",
            -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
        revision = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return revision;
}

static int routed_backup_table_row(sqlite3 *db, const char *id)
{
    sqlite3_stmt *st = NULL;

    if (routed_exec(db, "DROP TABLE IF EXISTS temp.routed_backup_route_table") != 0 ||
        routed_exec(db, "CREATE TEMP TABLE routed_backup_route_table AS SELECT * FROM route_table WHERE 0") != 0 ||
        sqlite3_prepare_v2(db,
            "INSERT INTO routed_backup_route_table SELECT * FROM route_table WHERE id=?",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    return 0;
}

static int routed_restore_table_row(sqlite3 *db, const char *id)
{
    sqlite3_stmt *st = NULL;

    if (routed_exec(db, "BEGIN IMMEDIATE") != 0 ||
        sqlite3_prepare_v2(db, "DELETE FROM route_table WHERE id=?", -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(st); st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO route_table SELECT * FROM routed_backup_route_table WHERE id=?",
            -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(st); st = NULL;
    routed_touch_revision(db);
    return routed_exec(db, "COMMIT");
fail:
    sqlite3_finalize(st);
    routed_exec(db, "ROLLBACK");
    return -1;
}

static int routed_backup_object_row(sqlite3 *db, const char *id)
{
    sqlite3_stmt *st = NULL;

    if (routed_exec(db, "DROP TABLE IF EXISTS temp.routed_backup_route_object") != 0 ||
        routed_exec(db, "DROP TABLE IF EXISTS temp.routed_backup_route_object_member") != 0 ||
        routed_exec(db, "CREATE TEMP TABLE routed_backup_route_object AS SELECT * FROM route_object WHERE 0") != 0 ||
        routed_exec(db, "CREATE TEMP TABLE routed_backup_route_object_member AS SELECT * FROM route_object_member WHERE 0") != 0 ||
        sqlite3_prepare_v2(db,
            "INSERT INTO routed_backup_route_object SELECT * FROM route_object WHERE id=?",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(st); st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO routed_backup_route_object_member SELECT * FROM route_object_member WHERE object_id=?",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(st);
    return 0;
fail:
    sqlite3_finalize(st);
    return -1;
}

static int routed_restore_object_row(sqlite3 *db, const char *id)
{
    sqlite3_stmt *st = NULL;

    if (routed_exec(db, "BEGIN IMMEDIATE") != 0 ||
        sqlite3_prepare_v2(db, "DELETE FROM route_object_member WHERE object_id=?", -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(st); st = NULL;
    if (sqlite3_prepare_v2(db, "DELETE FROM route_object WHERE id=?", -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(st); st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO route_object SELECT * FROM routed_backup_route_object WHERE id=?",
            -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(st); st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO route_object_member SELECT * FROM routed_backup_route_object_member WHERE object_id=?",
            -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(st); st = NULL;
    routed_touch_revision(db);
    return routed_exec(db, "COMMIT");
fail:
    sqlite3_finalize(st);
    routed_exec(db, "ROLLBACK");
    return -1;
}

static struct json_object *routed_runtime_rollback_error(sqlite3 *db,
                                                         const char *kind,
                                                         const char *id,
                                                         int restore_rc,
                                                         struct json_object *core)
{
    struct json_object *o = routed_error(
        restore_rc == 0 ? "runtime_apply_failed" : "runtime_apply_and_rollback_failed",
        restore_rc == 0 ? "route_reload failed; configuration was restored" :
                          "route_reload failed and scoped configuration restore also failed",
        restore_rc == 0 ? 502 : 500);

    (void)db;
    json_object_object_add(o, "resource", json_object_new_string(kind ? kind : ""));
    json_object_object_add(o, "id", json_object_new_string(id ? id : ""));
    json_object_object_add(o, "rolled_back", json_object_new_boolean(restore_rc == 0));
    if (core)
        json_object_object_add(o, "runtime", core);
    return o;
}

static struct json_object *routed_table_refs(sqlite3 *db, const char *id)
{
    struct json_object *refs = json_object_new_array();
    sqlite3_stmt *st = NULL;
    char table_id_text[32] = "";
    char generated_name[128] = "";

    if (sqlite3_prepare_v2(db, "SELECT table_id FROM route_table WHERE id=?",
                           -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW)
            snprintf(table_id_text, sizeof(table_id_text), "%d", sqlite3_column_int(st, 0));
    }
    sqlite3_finalize(st); st = NULL;
    snprintf(generated_name, sizeof(generated_name), "dwrt_%s", id ? id : "");

    if (sqlite3_prepare_v2(db,
            "SELECT 'static_route',id,name FROM static_route WHERE route_table=? "
            "UNION ALL SELECT 'policy_route_rule',id,name FROM policy_route_rule "
            "WHERE route_table=? OR target=? ORDER BY 1,2", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, id, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            json_object_object_add(o, "type", json_object_new_string(routed_text(st, 0)));
            json_object_object_add(o, "id", json_object_new_string(routed_text(st, 1)));
            json_object_object_add(o, "name", json_object_new_string(routed_text(st, 2)));
            json_object_array_add(refs, o);
        }
    }
    sqlite3_finalize(st);
    {
        struct uci_context *ctx = uci_alloc_context();
        struct uci_package *pkg = NULL;
        struct uci_element *e;

        if (ctx && uci_load(ctx, "network", &pkg) == UCI_OK && pkg) {
            uci_foreach_element(&pkg->sections, e) {
                struct uci_section *s = uci_to_section(e);
                const char *table;

                if (strcmp(s->type, "route") && strcmp(s->type, "route6"))
                    continue;
                table = uci_lookup_option_string(ctx, s, "table");
                if (!table || (strcmp(table, id) && strcmp(table, table_id_text) &&
                               strcmp(table, generated_name)))
                    continue;
                {
                    struct json_object *o = json_object_new_object();
                    const char *name = uci_lookup_option_string(ctx, s, "name");
                    const char *target = uci_lookup_option_string(ctx, s, "target");
                    const char *display = name && name[0] ? name :
                        (target && target[0] ? target : (s->e.name ? s->e.name : ""));
                    json_object_object_add(o, "type", json_object_new_string("uci_static_route"));
                    json_object_object_add(o, "id", json_object_new_string(s->e.name ? s->e.name : ""));
                    json_object_object_add(o, "name", json_object_new_string(display));
                    json_object_object_add(o, "source", json_object_new_string("uci:/etc/config/network"));
                    json_object_array_add(refs, o);
                }
            }
            uci_unload(ctx, pkg);
        }
        if (ctx)
            uci_free_context(ctx);
    }
    return refs;
}

static struct json_object *routed_object_refs(sqlite3 *db, const char *id)
{
    struct json_object *refs = json_object_new_array();
    sqlite3_stmt *st = NULL;

    if (sqlite3_prepare_v2(db,
            "SELECT id,name,CASE WHEN source_object=? THEN 'source_object' ELSE 'dest_object' END "
            "FROM policy_route_rule WHERE source_object=? OR dest_object=? ORDER BY priority,id",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, id, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            json_object_object_add(o, "type", json_object_new_string("policy_route_rule"));
            json_object_object_add(o, "id", json_object_new_string(routed_text(st, 0)));
            json_object_object_add(o, "name", json_object_new_string(routed_text(st, 1)));
            json_object_object_add(o, "field", json_object_new_string(routed_text(st, 2)));
            json_object_array_add(refs, o);
        }
    }
    sqlite3_finalize(st);
    return refs;
}

static struct json_object *routed_tables_json(sqlite3 *db)
{
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;

    if (sqlite3_prepare_v2(db,
            "SELECT id,name,table_id,role,gateway,metric,enabled,updated_at FROM route_table ORDER BY table_id,id",
            -1, &st, NULL) != SQLITE_OK)
        return arr;
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *o = json_object_new_object();
        struct json_object *refs = routed_table_refs(db, routed_text(st, 0));
        json_object_object_add(o, "id", json_object_new_string(routed_text(st, 0)));
        json_object_object_add(o, "name", json_object_new_string(routed_text(st, 1)));
        json_object_object_add(o, "table_id", json_object_new_int(sqlite3_column_int(st, 2)));
        json_object_object_add(o, "role", json_object_new_string(routed_text(st, 3)));
        json_object_object_add(o, "gateway", json_object_new_string(routed_text(st, 4)));
        json_object_object_add(o, "metric", json_object_new_int(sqlite3_column_int(st, 5)));
        json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 6)));
        json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 7)));
        json_object_object_add(o, "ref_count", json_object_new_int(json_object_array_length(refs)));
        json_object_object_add(o, "references", refs);
        json_object_array_add(arr, o);
    }
    sqlite3_finalize(st);
    return arr;
}

static struct json_object *routed_objects_json(sqlite3 *db)
{
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;

    if (sqlite3_prepare_v2(db,
            "SELECT id,enabled,name,object_type,family,value,comment,updated_at FROM route_object ORDER BY name,id",
            -1, &st, NULL) != SQLITE_OK)
        return arr;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *id = routed_text(st, 0);
        struct json_object *o = json_object_new_object();
        struct json_object *members = json_object_new_array();
        struct json_object *refs = routed_object_refs(db, id);
        sqlite3_stmt *ms = NULL;
        json_object_object_add(o, "id", json_object_new_string(id));
        json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 1)));
        json_object_object_add(o, "name", json_object_new_string(routed_text(st, 2)));
        json_object_object_add(o, "type", json_object_new_string(routed_text(st, 3)));
        json_object_object_add(o, "family", json_object_new_string(routed_text(st, 4)));
        json_object_object_add(o, "value", json_object_new_string(routed_text(st, 5)));
        json_object_object_add(o, "comment", json_object_new_string(routed_text(st, 6)));
        json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 7)));
        if (sqlite3_prepare_v2(db,
                "SELECT value,label,sort_order FROM route_object_member WHERE object_id=? ORDER BY sort_order,id",
                -1, &ms, NULL) == SQLITE_OK) {
            sqlite3_bind_text(ms, 1, id, -1, SQLITE_TRANSIENT);
            while (sqlite3_step(ms) == SQLITE_ROW) {
                struct json_object *m = json_object_new_object();
                json_object_object_add(m, "value", json_object_new_string(routed_text(ms, 0)));
                json_object_object_add(m, "label", json_object_new_string(routed_text(ms, 1)));
                json_object_object_add(m, "sort_order", json_object_new_int(sqlite3_column_int(ms, 2)));
                json_object_array_add(members, m);
            }
        }
        sqlite3_finalize(ms);
        json_object_object_add(o, "members", members);
        json_object_object_add(o, "ref_count", json_object_new_int(json_object_array_length(refs)));
        json_object_object_add(o, "references", refs);
        json_object_array_add(arr, o);
    }
    sqlite3_finalize(st);
    return arr;
}

static struct json_object *routed_cross_json(sqlite3 *db)
{
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;

    if (sqlite3_prepare_v2(db,
            "SELECT id,enabled,name,service_type,server_ip,scope,listen_port,version,access_rate,remark,updated_at "
            "FROM cross_l3_service ORDER BY name,id", -1, &st, NULL) != SQLITE_OK)
        return arr;
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *o = json_object_new_object();
        json_object_object_add(o, "id", json_object_new_string(routed_text(st, 0)));
        json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 1)));
        json_object_object_add(o, "name", json_object_new_string(routed_text(st, 2)));
        json_object_object_add(o, "service_type", json_object_new_string(routed_text(st, 3)));
        json_object_object_add(o, "server_ip", json_object_new_string(routed_text(st, 4)));
        json_object_object_add(o, "scope", json_object_new_string(routed_text(st, 5)));
        json_object_object_add(o, "listen_port", json_object_new_string(routed_text(st, 6)));
        json_object_object_add(o, "version", json_object_new_string(routed_text(st, 7)));
        json_object_object_add(o, "access_rate", json_object_new_string(routed_text(st, 8)));
        json_object_object_add(o, "remark", json_object_new_string(routed_text(st, 9)));
        json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 10)));
        json_object_object_add(o, "runtime_supported", json_object_new_boolean(0));
        json_object_array_add(arr, o);
    }
    sqlite3_finalize(st);
    return arr;
}

static struct json_object *routed_rules_projection(sqlite3 *db)
{
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;

    if (sqlite3_prepare_v2(db,
            "SELECT id,enabled,priority,name,source_object,dest_object,proto,ports,action,target,route_table,"
            "schedule,sticky,comment,hit_count,last_hit,updated_at FROM policy_route_rule ORDER BY priority,id",
            -1, &st, NULL) != SQLITE_OK)
        return arr;
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *o = json_object_new_object();
        json_object_object_add(o, "id", json_object_new_string(routed_text(st, 0)));
        json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 1)));
        json_object_object_add(o, "priority", json_object_new_int(sqlite3_column_int(st, 2)));
        json_object_object_add(o, "name", json_object_new_string(routed_text(st, 3)));
        json_object_object_add(o, "source_object", json_object_new_string(routed_text(st, 4)));
        json_object_object_add(o, "dest_object", json_object_new_string(routed_text(st, 5)));
        json_object_object_add(o, "proto", json_object_new_string(routed_text(st, 6)));
        json_object_object_add(o, "ports", json_object_new_string(routed_text(st, 7)));
        json_object_object_add(o, "action", json_object_new_string(routed_text(st, 8)));
        json_object_object_add(o, "target", json_object_new_string(routed_text(st, 9)));
        json_object_object_add(o, "route_table", json_object_new_string(routed_text(st, 10)));
        json_object_object_add(o, "schedule", json_object_new_string(routed_text(st, 11)));
        json_object_object_add(o, "sticky", json_object_new_boolean(sqlite3_column_int(st, 12)));
        json_object_object_add(o, "comment", json_object_new_string(routed_text(st, 13)));
        json_object_object_add(o, "hit_count", json_object_new_int64(sqlite3_column_int64(st, 14)));
        json_object_object_add(o, "last_hit", json_object_new_int64(sqlite3_column_int64(st, 15)));
        json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 16)));
        json_object_object_add(o, "read_only", json_object_new_boolean(1));
        json_object_object_add(o, "write_api", json_object_new_string("/api/v1/policy-engine/policy-table"));
        json_object_array_add(arr, o);
    }
    sqlite3_finalize(st);
    return arr;
}

static int routed_uci_disabled(const char *value)
{
    return value && value[0] && strcmp(value, "0") &&
           strcasecmp(value, "false") && strcasecmp(value, "no") &&
           strcasecmp(value, "off");
}

static void routed_json_add_uci_option(struct json_object *o, const char *key,
                                       struct uci_context *ctx,
                                       struct uci_section *s,
                                       const char *option)
{
    const char *value = uci_lookup_option_string(ctx, s, option);

    json_object_object_add(o, key,
        json_object_new_string(value ? value : ""));
}

static struct json_object *routed_static_projection(sqlite3 *db)
{
    struct json_object *arr = json_object_new_array();
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_element *e;
    int section_no = 0;

    (void)db;
    ctx = uci_alloc_context();
    if (!ctx)
        return arr;
    if (uci_load(ctx, "network", &pkg) != UCI_OK || !pkg) {
        uci_free_context(ctx);
        return arr;
    }
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        const char *target;
        const char *display_name;
        const char *disabled;
        char id[384];
        char fallback_name[640];
        struct json_object *o = json_object_new_object();

        if (!s || !s->type || (strcmp(s->type, "route") && strcmp(s->type, "route6"))) {
            json_object_put(o);
            continue;
        }
        section_no++;
        target = uci_lookup_option_string(ctx, s, "target");
        display_name = uci_lookup_option_string(ctx, s, "name");
        disabled = uci_lookup_option_string(ctx, s, "disabled");
        snprintf(id, sizeof(id), "uci-network-%s-%s-%d", s->type,
                 s->e.name ? s->e.name : "anon", section_no);
        snprintf(fallback_name, sizeof(fallback_name), "%s %s",
                 !strcmp(s->type, "route6") ? "IPv6 static route" : "Static route",
                 target && target[0] ? target : (s->e.name ? s->e.name : ""));
        json_object_object_add(o, "id", json_object_new_string(id));
        json_object_object_add(o, "section_id", json_object_new_string(s->e.name ? s->e.name : ""));
        json_object_object_add(o, "section_type", json_object_new_string(s->type));
        json_object_object_add(o, "enabled", json_object_new_boolean(!routed_uci_disabled(disabled)));
        json_object_object_add(o, "name", json_object_new_string(
            display_name && display_name[0] ? display_name : fallback_name));
        json_object_object_add(o, "family", json_object_new_string(
            !strcmp(s->type, "route6") ? "ipv6" : "ipv4"));
        routed_json_add_uci_option(o, "destination", ctx, s, "target");
        routed_json_add_uci_option(o, "target", ctx, s, "target");
        routed_json_add_uci_option(o, "netmask", ctx, s, "netmask");
        routed_json_add_uci_option(o, "gateway", ctx, s, "gateway");
        routed_json_add_uci_option(o, "interface", ctx, s, "interface");
        routed_json_add_uci_option(o, "route_table", ctx, s, "table");
        routed_json_add_uci_option(o, "metric", ctx, s, "metric");
        routed_json_add_uci_option(o, "mtu", ctx, s, "mtu");
        routed_json_add_uci_option(o, "type", ctx, s, "type");
        routed_json_add_uci_option(o, "source_prefix", ctx, s, "source");
        routed_json_add_uci_option(o, "comment", ctx, s, "comment");
        json_object_object_add(o, "source", json_object_new_string("uci:/etc/config/network"));
        json_object_object_add(o, "source_of_truth", json_object_new_boolean(1));
        json_object_object_add(o, "read_only", json_object_new_boolean(1));
        json_object_object_add(o, "write_api", json_object_new_string("/api/v1/policy-engine/policy-table"));
        json_object_array_add(arr, o);
    }
    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    return arr;
}

static void routed_external_file(struct json_object *arr, const char *source,
                                 const char *path)
{
    FILE *fp = fopen(path, "r");
    char line[1024];
    int section = 0;

    if (!fp)
        return;
    while (fgets(line, sizeof(line), fp)) {
        char type[96] = "", name[160] = "";
        char *p = line;

        while (isspace((unsigned char)*p)) p++;
        if (strncmp(p, "config ", 7) != 0)
            continue;
        if (sscanf(p + 7, "%95s '%159[^']'", type, name) < 1 &&
            sscanf(p + 7, "%95s \"%159[^\"]\"", type, name) < 1)
            continue;
        if (strcmp(type, "policy") && strcmp(type, "rule") &&
            strcmp(type, "member") && strcmp(type, "interface"))
            continue;
        {
            struct json_object *o = json_object_new_object();
            char id[256];
            snprintf(id, sizeof(id), "%s:%s:%d", source, name[0] ? name : type, ++section);
            json_object_object_add(o, "id", json_object_new_string(id));
            json_object_object_add(o, "name", json_object_new_string(name[0] ? name : type));
            json_object_object_add(o, "section_type", json_object_new_string(type));
            json_object_object_add(o, "source", json_object_new_string(source));
            json_object_object_add(o, "path", json_object_new_string(path));
            json_object_object_add(o, "read_only", json_object_new_boolean(1));
            json_object_array_add(arr, o);
        }
    }
    fclose(fp);
}

static struct json_object *routed_external_json(void)
{
    struct json_object *o = routed_ok();
    struct json_object *items = json_object_new_array();

    routed_external_file(items, "pbr", "/etc/config/pbr");
    routed_external_file(items, "mwan3", "/etc/config/mwan3");
    json_object_object_add(o, "items", items);
    json_object_object_add(o, "total", json_object_new_int(json_object_array_length(items)));
    json_object_object_add(o, "read_only", json_object_new_boolean(1));
    return o;
}

static struct json_object *routed_list_response(const char *kind)
{
    sqlite3 *db = NULL;
    struct json_object *o;
    struct json_object *items;

    if (routed_db_open(&db) != 0)
        return routed_error("storage_error", "cannot open config.db", 500);
    if (!strcmp(kind, "tables"))
        items = routed_tables_json(db);
    else if (!strcmp(kind, "objects"))
        items = routed_objects_json(db);
    else if (!strcmp(kind, "static_routes"))
        items = routed_static_projection(db);
    else if (!strcmp(kind, "policy_rules"))
        items = routed_rules_projection(db);
    else
        items = routed_cross_json(db);
    o = routed_ok();
    json_object_object_add(o, "revision", json_object_new_int64(routed_object_revision(db)));
    sqlite3_close(db);
    json_object_object_add(o, "items", items);
    json_object_object_add(o, "total", json_object_new_int(json_object_array_length(items)));
    json_object_object_add(o, "capabilities", routed_capabilities());
    return o;
}

static int routed_collision(sqlite3 *db, const char *sql, const char *a,
                            const char *b, int n)
{
    sqlite3_stmt *st = NULL;
    int found = 0;

    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, a ? a : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, b ? b : "", -1, SQLITE_TRANSIENT);
    if (sqlite3_bind_parameter_count(st) >= 3)
        sqlite3_bind_int(st, 3, n);
    found = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return found;
}

static int routed_table_present(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    int found = 0;

    if (!db || !name ||
        sqlite3_prepare_v2(db,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    found = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return found;
}

/*
 * Mirror the configured WANs into route_table.
 *
 * route_table was written by explicit CRUD only, so a second WAN never got a
 * row: "send lan2 out wan2" had no legal `target` to name, even though the data
 * plane was already carrying that table. The table number comes from
 * route_wan.table_id, the same value jmx_route programs into the kernel
 * (fwmark 0x10000+id -> table 100+id). Allocating a fresh number here would
 * create an empty table that rules match and then find no route in, which looks
 * like a successful config and behaves like a dead link.
 *
 * Runs on every routed_db_open() and fills in only what is missing, so adding
 * wan3 later needs no migration. Operator-owned rows are preserved: the UPDATE
 * branch is restricted to rows this function could have created (role='wan'),
 * and a name or table number already claimed by another id is skipped rather
 * than stolen.
 */
static void routed_sync_wan_tables(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    int changed = 0;

    if (!db || !routed_table_present(db, "route_wan"))
        return;
    if (sqlite3_prepare_v2(db,
            "SELECT name,table_id FROM route_wan ORDER BY position",
            -1, &st, NULL) != SQLITE_OK)
        return;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *name = routed_text(st, 0);
        int table_id = sqlite3_column_int(st, 1);
        sqlite3_stmt *ins = NULL;

        if (!routed_id_ok(name) || !routed_table_id_ok(table_id))
            continue;
        if (routed_collision(db,
                "SELECT 1 FROM route_table WHERE id<>? AND (name=? OR table_id=?3) LIMIT 1",
                name, name, table_id) == 1)
            continue;
        if (sqlite3_prepare_v2(db,
                "INSERT INTO route_table(id,name,table_id,role,gateway,metric,enabled,updated_at) "
                "VALUES(?1,?1,?2,'wan','',0,1,?3) "
                "ON CONFLICT(id) DO UPDATE SET table_id=excluded.table_id,"
                "updated_at=excluded.updated_at "
                "WHERE route_table.role='wan' AND route_table.table_id<>excluded.table_id",
                -1, &ins, NULL) == SQLITE_OK) {
            sqlite3_bind_text(ins, 1, name, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(ins, 2, table_id);
            sqlite3_bind_int64(ins, 3, routed_now());
            if (sqlite3_step(ins) == SQLITE_DONE && sqlite3_changes(db) > 0)
                changed = 1;
        }
        sqlite3_finalize(ins);
    }
    sqlite3_finalize(st);
    if (changed)
        routed_touch_revision(db);
}

static struct json_object *routed_table_set(struct ubus_context *ctx,
                                            struct json_object *body)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *core = NULL;
    struct json_object *o;
    const char *id = routed_json_str(body, "id", "");
    const char *name = routed_json_str(body, "name", id);
    const char *role = routed_json_str(body, "role", "");
    const char *gateway = routed_json_str(body, "gateway", "");
    int table_id = routed_json_int(body, "table_id", 0);
    int rc = -1;

    if (!routed_id_ok(id) || !routed_text_ok(name, 128) || !name[0] ||
        !routed_text_ok(role, 64) || !routed_text_ok(gateway, 128) ||
        table_id <= 0 || table_id >= 32768 || table_id == 253 ||
        table_id == 254 || table_id == 255)
        return routed_error("invalid_request", "valid id/name and custom table_id 1..32767 are required", 400);
    if (routed_db_open(&db) != 0)
        return routed_error("storage_error", "cannot open config.db", 500);
    if (routed_collision(db,
            "SELECT 1 FROM route_table WHERE id<>? AND (name=? OR table_id=?3) LIMIT 1",
            id, name, table_id) == 1) {
        sqlite3_close(db);
        return routed_error("conflict", "route table id, name and table_id must be unique", 409);
    }
    if (routed_backup_table_row(db, id) != 0)
        goto out;
    if (routed_exec(db, "BEGIN IMMEDIATE") != 0)
        goto out;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO route_table(id,name,table_id,role,gateway,metric,enabled,updated_at) VALUES(?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET name=excluded.name,table_id=excluded.table_id,role=excluded.role,"
            "gateway=excluded.gateway,metric=excluded.metric,enabled=excluded.enabled,updated_at=excluded.updated_at",
            -1, &st, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, table_id);
    sqlite3_bind_text(st, 4, role, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, gateway, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 6, routed_json_int(body, "metric", 0));
    sqlite3_bind_int(st, 7, routed_json_bool(body, "enabled", 1));
    sqlite3_bind_int64(st, 8, routed_now());
    if (sqlite3_step(st) != SQLITE_DONE)
        goto rollback;
    sqlite3_finalize(st); st = NULL;
    routed_touch_revision(db);
    if (routed_exec(db, "COMMIT") != 0)
        goto out;
    rc = routed_core_reload(ctx, &core);
    if (rc != 0) {
        int restore_rc = routed_restore_table_row(db, id);
        o = routed_runtime_rollback_error(db, "route_table", id, restore_rc, core);
        sqlite3_close(db);
        return o;
    }
    o = routed_ok();
    json_object_object_add(o, "revision", json_object_new_int64(routed_object_revision(db)));
    json_object_object_add(o, "id", json_object_new_string(id));
    json_object_object_add(o, "runtime_reloaded", json_object_new_boolean(rc == 0));
    if (core) json_object_object_add(o, "runtime", core);
    sqlite3_close(db);
    return o;
rollback:
    sqlite3_finalize(st);
    routed_exec(db, "ROLLBACK");
out:
    sqlite3_close(db);
    return routed_error("storage_error", "route table transaction failed", 500);
}

static struct json_object *routed_table_delete(struct ubus_context *ctx,
                                               struct json_object *body)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *refs;
    struct json_object *core = NULL;
    struct json_object *o;
    const char *id = routed_json_str(body, "id", "");

    if (!routed_id_ok(id))
        return routed_error("invalid_request", "route table id is required", 400);
    if (routed_db_open(&db) != 0)
        return routed_error("storage_error", "cannot open config.db", 500);
    refs = routed_table_refs(db, id);
    if (json_object_array_length(refs) > 0) {
        o = routed_error("reference_conflict", "route table is still referenced", 409);
        json_object_object_add(o, "ref_count", json_object_new_int(json_object_array_length(refs)));
        json_object_object_add(o, "references", refs);
        sqlite3_close(db);
        return o;
    }
    json_object_put(refs);
    if (routed_backup_table_row(db, id) != 0)
        goto fail;
    if (routed_exec(db, "BEGIN IMMEDIATE") != 0 ||
        sqlite3_prepare_v2(db, "DELETE FROM route_table WHERE id=?", -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(db) != 1)
        goto not_found;
    sqlite3_finalize(st); st = NULL;
    routed_touch_revision(db);
    if (routed_exec(db, "COMMIT") != 0)
        goto fail;
    if (routed_core_reload(ctx, &core) != 0) {
        int restore_rc = routed_restore_table_row(db, id);
        o = routed_runtime_rollback_error(db, "route_table", id, restore_rc, core);
        sqlite3_close(db);
        return o;
    }
    o = routed_ok();
    json_object_object_add(o, "id", json_object_new_string(id));
    json_object_object_add(o, "runtime_reloaded", json_object_new_boolean(1));
    if (core) json_object_object_add(o, "runtime", core);
    sqlite3_close(db);
    return o;
not_found:
    sqlite3_finalize(st); st = NULL;
    routed_exec(db, "ROLLBACK");
    sqlite3_close(db);
    return routed_error("not_found", "route table not found", 404);
fail:
    sqlite3_finalize(st);
    routed_exec(db, "ROLLBACK");
    sqlite3_close(db);
    return routed_error("storage_error", "route table delete failed", 500);
}

static int routed_family_ok(const char *s)
{
    return s && (!strcmp(s, "ipv4") || !strcmp(s, "ipv6") || !strcmp(s, "mixed"));
}

static struct json_object *routed_object_set(struct ubus_context *ctx,
                                             struct json_object *body)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *members = NULL, *core = NULL, *o;
    const char *id = routed_json_str(body, "id", "");
    const char *name = routed_json_str(body, "name", id);
    const char *type = routed_json_str(body, "type", routed_json_str(body, "object_type", "ip_group"));
    const char *family = routed_json_str(body, "family", "mixed");
    int i, n = 0;

    if (!routed_id_ok(id) || !name[0] || !routed_text_ok(name, 128) ||
        !routed_id_ok(type) || !routed_family_ok(family) ||
        !routed_text_ok(routed_json_str(body, "value", ""), ROUTED_MAX_TEXT) ||
        !routed_text_ok(routed_json_str(body, "comment", ""), ROUTED_MAX_TEXT))
        return routed_error("invalid_request", "invalid route object fields", 400);
    if (routed_db_open(&db) != 0)
        return routed_error("storage_error", "cannot open config.db", 500);
    if (routed_collision(db, "SELECT 1 FROM route_object WHERE id<>? AND name=? LIMIT 1",
                         id, name, 0) == 1) {
        sqlite3_close(db);
        return routed_error("conflict", "route object id and name must be unique", 409);
    }
    if (routed_backup_object_row(db, id) != 0)
        goto fail;
    if (routed_exec(db, "BEGIN IMMEDIATE") != 0 ||
        sqlite3_prepare_v2(db,
            "INSERT INTO route_object(id,enabled,name,object_type,family,value,comment,updated_at) VALUES(?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled,name=excluded.name,object_type=excluded.object_type,"
            "family=excluded.family,value=excluded.value,comment=excluded.comment,updated_at=excluded.updated_at",
            -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, routed_json_bool(body, "enabled", 1));
    sqlite3_bind_text(st, 3, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, family, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, routed_json_str(body, "value", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, routed_json_str(body, "comment", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 8, routed_now());
    if (sqlite3_step(st) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(st); st = NULL;
    if (sqlite3_prepare_v2(db, "DELETE FROM route_object_member WHERE object_id=?", -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(st); st = NULL;
    if (json_object_object_get_ex(body, "members", &members) && members &&
        json_object_is_type(members, json_type_array))
        n = json_object_array_length(members);
    if (n > 1024)
        goto invalid;
    for (i = 0; i < n; i++) {
        struct json_object *m = json_object_array_get_idx(members, i);
        const char *value, *label;
        if (json_object_is_type(m, json_type_string)) {
            value = json_object_get_string(m);
            label = value;
        } else {
            value = routed_json_str(m, "value", "");
            label = routed_json_str(m, "label", value);
        }
        if (!value[0] || !routed_text_ok(value, ROUTED_MAX_TEXT) ||
            !routed_text_ok(label, 128))
            goto invalid;
        if (sqlite3_prepare_v2(db,
                "INSERT INTO route_object_member(object_id,value,label,sort_order) VALUES(?,?,?,?)",
                -1, &st, NULL) != SQLITE_OK)
            goto fail;
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, value, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, label, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 4, i);
        if (sqlite3_step(st) != SQLITE_DONE)
            goto fail;
        sqlite3_finalize(st); st = NULL;
    }
    routed_touch_revision(db);
    if (routed_exec(db, "COMMIT") != 0)
        goto fail;
    if (routed_core_reload(ctx, &core) != 0) {
        int restore_rc = routed_restore_object_row(db, id);
        o = routed_runtime_rollback_error(db, "route_object", id, restore_rc, core);
        sqlite3_close(db);
        return o;
    }
    o = routed_ok();
    json_object_object_add(o, "id", json_object_new_string(id));
    json_object_object_add(o, "runtime_reloaded", json_object_new_boolean(1));
    if (core) json_object_object_add(o, "runtime", core);
    sqlite3_close(db);
    return o;
invalid:
    sqlite3_finalize(st);
    routed_exec(db, "ROLLBACK");
    sqlite3_close(db);
    return routed_error("invalid_request", "members must contain at most 1024 valid values", 400);
fail:
    sqlite3_finalize(st);
    routed_exec(db, "ROLLBACK");
    sqlite3_close(db);
    return routed_error("storage_error", "route object transaction failed", 500);
}

static struct json_object *routed_object_delete(struct ubus_context *ctx,
                                                struct json_object *body)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *refs, *o, *core = NULL;
    const char *id = routed_json_str(body, "id", "");

    if (!routed_id_ok(id))
        return routed_error("invalid_request", "route object id is required", 400);
    if (routed_db_open(&db) != 0)
        return routed_error("storage_error", "cannot open config.db", 500);
    refs = routed_object_refs(db, id);
    if (json_object_array_length(refs) > 0) {
        o = routed_error("reference_conflict", "route object is still referenced", 409);
        json_object_object_add(o, "ref_count", json_object_new_int(json_object_array_length(refs)));
        json_object_object_add(o, "references", refs);
        sqlite3_close(db);
        return o;
    }
    json_object_put(refs);
    if (routed_backup_object_row(db, id) != 0)
        goto fail;
    if (routed_exec(db, "BEGIN IMMEDIATE") != 0 ||
        sqlite3_prepare_v2(db, "DELETE FROM route_object_member WHERE object_id=?", -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(st); st = NULL;
    if (sqlite3_prepare_v2(db, "DELETE FROM route_object WHERE id=?", -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(db) != 1)
        goto missing;
    sqlite3_finalize(st); st = NULL;
    routed_touch_revision(db);
    if (routed_exec(db, "COMMIT") != 0)
        goto fail;
    if (routed_core_reload(ctx, &core) != 0) {
        int restore_rc = routed_restore_object_row(db, id);
        o = routed_runtime_rollback_error(db, "route_object", id, restore_rc, core);
        sqlite3_close(db);
        return o;
    }
    o = routed_ok();
    json_object_object_add(o, "id", json_object_new_string(id));
    json_object_object_add(o, "runtime_reloaded", json_object_new_boolean(1));
    if (core) json_object_object_add(o, "runtime", core);
    sqlite3_close(db);
    return o;
missing:
    sqlite3_finalize(st); st = NULL;
    routed_exec(db, "ROLLBACK");
    sqlite3_close(db);
    return routed_error("not_found", "route object not found", 404);
fail:
    sqlite3_finalize(st);
    routed_exec(db, "ROLLBACK");
    sqlite3_close(db);
    return routed_error("storage_error", "route object delete failed", 500);
}

static struct json_object *routed_cross_set(struct json_object *body)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *o;
    const char *id = routed_json_str(body, "id", "");
    const char *name = routed_json_str(body, "name", id);
    const char *service_type = routed_json_str(body, "service_type", "snmp");

    if (!routed_id_ok(id) || !name[0] || !routed_text_ok(name, 128) ||
        !routed_id_ok(service_type) ||
        !routed_text_ok(routed_json_str(body, "server_ip", ""), 128) ||
        !routed_text_ok(routed_json_str(body, "scope", ""), ROUTED_MAX_TEXT) ||
        !routed_text_ok(routed_json_str(body, "remark", ""), ROUTED_MAX_TEXT))
        return routed_error("invalid_request", "invalid cross-layer service fields", 400);
    if (routed_db_open(&db) != 0)
        return routed_error("storage_error", "cannot open config.db", 500);
    if (routed_exec(db, "BEGIN IMMEDIATE") != 0 ||
        sqlite3_prepare_v2(db,
            "INSERT INTO cross_l3_service(id,enabled,name,service_type,server_ip,scope,listen_port,version,access_rate,remark,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled,name=excluded.name,"
            "service_type=excluded.service_type,server_ip=excluded.server_ip,scope=excluded.scope,"
            "listen_port=excluded.listen_port,version=excluded.version,access_rate=excluded.access_rate,"
            "remark=excluded.remark,updated_at=excluded.updated_at", -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, routed_json_bool(body, "enabled", 1));
    sqlite3_bind_text(st, 3, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, service_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, routed_json_str(body, "server_ip", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, routed_json_str(body, "scope", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, routed_json_str(body, "listen_port", "161"), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, routed_json_str(body, "version", "V2"), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, routed_json_str(body, "access_rate", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 10, routed_json_str(body, "remark", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 11, routed_now());
    if (sqlite3_step(st) != SQLITE_DONE)
        goto fail;
    sqlite3_finalize(st); st = NULL;
    routed_touch_revision(db);
    if (routed_exec(db, "COMMIT") != 0)
        goto fail;
    sqlite3_close(db);
    o = routed_ok();
    json_object_object_add(o, "id", json_object_new_string(id));
    json_object_object_add(o, "runtime_supported", json_object_new_boolean(0));
    return o;
fail:
    sqlite3_finalize(st);
    routed_exec(db, "ROLLBACK");
    sqlite3_close(db);
    return routed_error("storage_error", "cross-layer service transaction failed", 500);
}

static struct json_object *routed_cross_delete(struct json_object *body)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    const char *id = routed_json_str(body, "id", "");
    struct json_object *o;

    if (!routed_id_ok(id))
        return routed_error("invalid_request", "cross-layer service id is required", 400);
    if (routed_db_open(&db) != 0)
        return routed_error("storage_error", "cannot open config.db", 500);
    if (routed_exec(db, "BEGIN IMMEDIATE") != 0 ||
        sqlite3_prepare_v2(db, "DELETE FROM cross_l3_service WHERE id=?", -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto fail;
    if (sqlite3_changes(db) != 1) {
        sqlite3_finalize(st); st = NULL;
        routed_exec(db, "ROLLBACK");
        sqlite3_close(db);
        return routed_error("not_found", "cross-layer service not found", 404);
    }
    sqlite3_finalize(st); st = NULL;
    routed_touch_revision(db);
    if (routed_exec(db, "COMMIT") != 0)
        goto fail;
    sqlite3_close(db);
    o = routed_ok();
    json_object_object_add(o, "id", json_object_new_string(id));
    return o;
fail:
    sqlite3_finalize(st);
    routed_exec(db, "ROLLBACK");
    sqlite3_close(db);
    return routed_error("storage_error", "cross-layer service delete failed", 500);
}

static struct json_object *routed_reorder(struct ubus_context *ctx,
                                          struct json_object *body)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *ids = NULL, *core = NULL, *o;
    int i, n, base, step;

    if (!json_object_object_get_ex(body, "ids", &ids) || !ids ||
        !json_object_is_type(ids, json_type_array) ||
        (n = json_object_array_length(ids)) <= 0 || n > 4096)
        return routed_error("invalid_request", "ids must be a non-empty array", 400);
    base = routed_json_int(body, "base_priority", 1000);
    step = routed_json_int(body, "step", 10);
    if (base < 1 || step < 1 || base + (n - 1) * step > 65535)
        return routed_error("invalid_request", "priority range must fit 1..65535", 400);
    if (routed_db_open(&db) != 0)
        return routed_error("storage_error", "cannot open config.db", 500);
    if (routed_exec(db, "DROP TABLE IF EXISTS temp.routed_backup_priority") != 0 ||
        routed_exec(db, "CREATE TEMP TABLE routed_backup_priority(id TEXT PRIMARY KEY,priority INTEGER NOT NULL)") != 0)
        goto fail;
    if (routed_exec(db, "BEGIN IMMEDIATE") != 0)
        goto fail;
    for (i = 0; i < n; i++) {
        struct json_object *v = json_object_array_get_idx(ids, i);
        const char *id = v && json_object_is_type(v, json_type_string) ? json_object_get_string(v) : "";
        if (!routed_id_ok(id) || sqlite3_prepare_v2(db,
                "INSERT OR IGNORE INTO routed_backup_priority SELECT id,priority FROM policy_route_rule WHERE id=?",
                -1, &st, NULL) != SQLITE_OK)
            goto invalid;
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(db) != 1)
            goto invalid;
        sqlite3_finalize(st); st = NULL;
        if (sqlite3_prepare_v2(db,
                "UPDATE policy_route_rule SET priority=?,updated_at=? WHERE id=?", -1, &st, NULL) != SQLITE_OK)
            goto invalid;
        sqlite3_bind_int(st, 1, base + i * step);
        sqlite3_bind_int64(st, 2, routed_now());
        sqlite3_bind_text(st, 3, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(db) != 1)
            goto invalid;
        sqlite3_finalize(st); st = NULL;
    }
    routed_touch_revision(db);
    if (routed_exec(db, "COMMIT") != 0)
        goto fail;
    if (routed_core_reload(ctx, &core) != 0) {
        int restore_rc;
        if (routed_exec(db, "BEGIN IMMEDIATE") != 0)
            restore_rc = -1;
        else {
            restore_rc = routed_exec(db,
                "UPDATE policy_route_rule SET priority=(SELECT priority FROM routed_backup_priority b "
                "WHERE b.id=policy_route_rule.id),updated_at=strftime('%s','now') "
                "WHERE id IN (SELECT id FROM routed_backup_priority)");
            if (restore_rc == 0) {
                routed_touch_revision(db);
                restore_rc = routed_exec(db, "COMMIT");
            } else {
                routed_exec(db, "ROLLBACK");
            }
        }
        o = routed_runtime_rollback_error(db, "policy_route_rule.priority", "ordered-set",
                                          restore_rc, core);
        sqlite3_close(db);
        return o;
    }
    o = routed_ok();
    json_object_object_add(o, "updated", json_object_new_int(n));
    json_object_object_add(o, "runtime_reloaded", json_object_new_boolean(1));
    if (core) json_object_object_add(o, "runtime", core);
    sqlite3_close(db);
    return o;
invalid:
    sqlite3_finalize(st);
    routed_exec(db, "ROLLBACK");
    sqlite3_close(db);
    return routed_error("invalid_request", "all ids must reference existing policy_route_rule rows", 400);
fail:
    sqlite3_finalize(st);
    routed_exec(db, "ROLLBACK");
    sqlite3_close(db);
    return routed_error("storage_error", "policy reorder transaction failed", 500);
}

static struct json_object *routed_runtime_resolve(struct json_object *body)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *o;
    const char *rule_id = routed_json_str(body, "rule_id", "");
    const char *requested_table = routed_json_str(body, "route_table", "");
    char table[128] = "main", action[64] = "main", rule[128] = "";
    char gateway[128] = "", ifname[128] = "";
    int table_id = 254, enabled = 1;

    if (rule_id[0] && !routed_id_ok(rule_id))
        return routed_error("invalid_request", "invalid rule_id", 400);
    if (requested_table[0] && !routed_id_ok(requested_table))
        return routed_error("invalid_request", "invalid route_table", 400);
    if (routed_db_open(&db) != 0)
        return routed_error("storage_error", "cannot open config.db", 500);
    if (rule_id[0] && sqlite3_prepare_v2(db,
            "SELECT id,enabled,action,CASE WHEN route_table<>'' THEN route_table ELSE target END "
            "FROM policy_route_rule WHERE id=?", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, rule_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            snprintf(rule, sizeof(rule), "%s", routed_text(st, 0));
            enabled = sqlite3_column_int(st, 1);
            snprintf(action, sizeof(action), "%s", routed_text(st, 2));
            if (routed_text(st, 3)[0]) snprintf(table, sizeof(table), "%s", routed_text(st, 3));
        } else {
            sqlite3_finalize(st);
            sqlite3_close(db);
            return routed_error("not_found", "policy route rule not found", 404);
        }
    } else if (requested_table[0]) {
        snprintf(table, sizeof(table), "%s", requested_table);
        snprintf(action, sizeof(action), "route_table");
    }
    sqlite3_finalize(st); st = NULL;
    if (!strcmp(table, "main"))
        table_id = 254;
    else if (!strcmp(table, "default"))
        table_id = 253;
    else if (!strcmp(table, "local"))
        table_id = 255;
    else if (sqlite3_prepare_v2(db,
            "SELECT table_id,gateway,enabled FROM route_table WHERE id=?", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, table, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            table_id = sqlite3_column_int(st, 0);
            snprintf(gateway, sizeof(gateway), "%s", routed_text(st, 1));
            enabled = enabled && sqlite3_column_int(st, 2);
        } else {
            table_id = 0;
        }
    }
    sqlite3_finalize(st); st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT gateway,interface FROM static_route WHERE route_table=? AND enabled=1 "
            "ORDER BY metric,id LIMIT 1", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, table, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            if (!gateway[0]) snprintf(gateway, sizeof(gateway), "%s", routed_text(st, 0));
            snprintf(ifname, sizeof(ifname), "%s", routed_text(st, 1));
        }
    }
    sqlite3_finalize(st);
    sqlite3_close(db);
    o = routed_ok();
    json_object_object_add(o, "rule_id", json_object_new_string(rule));
    json_object_object_add(o, "action", json_object_new_string(action));
    json_object_object_add(o, "route_table", json_object_new_string(table));
    json_object_object_add(o, "table_id", json_object_new_int(table_id));
    json_object_object_add(o, "gateway", json_object_new_string(gateway));
    json_object_object_add(o, "interface", json_object_new_string(ifname));
    json_object_object_add(o, "resolved", json_object_new_boolean(enabled && table_id > 0));
    json_object_object_add(o, "reason", json_object_new_string(
        !enabled ? "rule_or_table_disabled" : table_id <= 0 ? "route_table_not_found" :
        rule[0] ? "policy_route_rule_selected" : "explicit_route_table_selected"));
    json_object_object_add(o, "runtime_validation", json_object_new_string("configured_resolution_not_per_flow_conntrack_decision"));
    return o;
}

static struct json_object *routed_snapshot(void)
{
    sqlite3 *db = NULL;
    struct json_object *o;
    struct json_object *external;
    struct json_object *external_items = NULL;

    if (routed_db_open(&db) != 0)
        return routed_error("storage_error", "cannot open config.db", 500);
    o = routed_ok();
    json_object_object_add(o, "revision", json_object_new_int64(routed_object_revision(db)));
    json_object_object_add(o, "tables", routed_tables_json(db));
    json_object_object_add(o, "route_objects", routed_objects_json(db));
    json_object_object_add(o, "cross_services", routed_cross_json(db));
    json_object_object_add(o, "static_routes", routed_static_projection(db));
    json_object_object_add(o, "policy_rules", routed_rules_projection(db));
    external = routed_external_json();
    if (json_object_object_get_ex(external, "items", &external_items) && external_items)
        json_object_object_add(o, "external_policies", json_object_get(external_items));
    else
        json_object_object_add(o, "external_policies", json_object_new_array());
    json_object_put(external);
    json_object_object_add(o, "capabilities", routed_capabilities());
    sqlite3_close(db);
    return o;
}

static struct json_object *routed_status_json(void)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *resp = json_object_new_object();
    struct json_object *dependencies = json_object_new_object();
    struct json_object *datasets = json_object_new_object();
    char last_error[ROUTED_MAX_TEXT] = "";
    char apply_state[32] = "unknown";
    int64_t updated_at = 0;
    int ok = 1;
    int rc;

    rc = sqlite3_open_v2(ROUTED_DB_PATH, &db, SQLITE_OPEN_READONLY, NULL);
    if (rc != SQLITE_OK) {
        snprintf(last_error, sizeof(last_error), "%s",
                 db ? sqlite3_errmsg(db) : "cannot open config.db read-only");
        ok = 0;
    }
    json_object_object_add(dependencies, "config_db_read_only", json_object_new_boolean(ok));
    if (ok) {
        sqlite3_busy_timeout(db, ROUTED_DB_TIMEOUT_MS);
        rc = sqlite3_prepare_v2(db,
            "SELECT apply_state,updated_at FROM advanced_routing_global WHERE id=1",
            -1, &st, NULL);
        if (rc == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW) {
            snprintf(apply_state, sizeof(apply_state), "%s", routed_text(st, 0));
            updated_at = sqlite3_column_int64(st, 1);
        } else {
            snprintf(last_error, sizeof(last_error), "%s", sqlite3_errmsg(db));
            ok = 0;
        }
        sqlite3_finalize(st);
        st = NULL;
    }
    if (ok) {
        rc = sqlite3_prepare_v2(db,
            "SELECT (SELECT COUNT(*) FROM route_table),"
            "(SELECT COUNT(*) FROM route_object),"
            "(SELECT COUNT(*) FROM cross_l3_service),"
            "(SELECT COUNT(*) FROM static_route),"
            "(SELECT COUNT(*) FROM policy_route_rule)",
            -1, &st, NULL);
        if (rc == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW) {
            json_object_object_add(datasets, "route_tables", json_object_new_int(sqlite3_column_int(st, 0)));
            json_object_object_add(datasets, "route_objects", json_object_new_int(sqlite3_column_int(st, 1)));
            json_object_object_add(datasets, "cross_services", json_object_new_int(sqlite3_column_int(st, 2)));
            json_object_object_add(datasets, "static_routes", json_object_new_int(sqlite3_column_int(st, 3)));
            json_object_object_add(datasets, "policy_rules", json_object_new_int(sqlite3_column_int(st, 4)));
        } else {
            snprintf(last_error, sizeof(last_error), "%s", sqlite3_errmsg(db));
            ok = 0;
        }
        sqlite3_finalize(st);
    }
    if (db)
        sqlite3_close(db);
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "service", json_object_new_string("dreamingwrt-routed"));
    json_object_object_add(resp, "contract_version", json_object_new_string(ROUTED_CONTRACT_VERSION));
    json_object_object_add(resp, "version", json_object_new_string(WORKER_STATUS_VERSION));
    json_object_object_add(resp, "schema_version", json_object_new_int(0));
    json_object_object_add(resp, "schema_source",
                           json_object_new_string("none:unversioned routed tables in shared config.db"));
    json_object_object_add(resp, "migration_state", json_object_new_string("not_tracked"));
    json_object_object_add(resp, "state", json_object_new_string(ok ? "running" : "degraded"));
    json_object_object_add(resp, "degraded", json_object_new_boolean(!ok));
    json_object_object_add(resp, "last_error", json_object_new_string(last_error));
    json_object_object_add(resp, "updated_at", json_object_new_int64(updated_at));
    json_object_object_add(resp, "apply_state", json_object_new_string(apply_state));
    json_object_object_add(resp, "object", json_object_new_string(ROUTED_OBJECT_NAME));
    json_object_object_add(resp, "config_db", json_object_new_string(ROUTED_DB_PATH));
    json_object_object_add(resp, "dependencies", dependencies);
    json_object_object_add(resp, "datasets", datasets);
    json_object_object_add(resp, "capabilities", routed_capabilities());
    json_object_object_add(resp, "ts", json_object_new_int64(routed_now()));
    return resp;
}

static int routed_handle(struct ubus_context *ctx, struct ubus_object *obj,
                         struct ubus_request_data *req, const char *method,
                         struct blob_attr *msg)
{
    struct json_object *raw = routed_json_from_blob(msg);
    struct json_object *body = routed_payload(raw);
    struct json_object *resp;
    (void)obj;
    if (!strcmp(method, "status")) {
        resp = routed_status_json();
    } else if (!strcmp(method, "snapshot")) resp = routed_snapshot();
    else if (!strcmp(method, "tables_list")) resp = routed_list_response("tables");
    else if (!strcmp(method, "table_set")) resp = routed_table_set(ctx, body);
    else if (!strcmp(method, "table_delete")) resp = routed_table_delete(ctx, body);
    else if (!strcmp(method, "objects_list")) resp = routed_list_response("objects");
    else if (!strcmp(method, "static_routes_list")) resp = routed_list_response("static_routes");
    else if (!strcmp(method, "policy_rules_list")) resp = routed_list_response("policy_rules");
    else if (!strcmp(method, "object_set")) resp = routed_object_set(ctx, body);
    else if (!strcmp(method, "object_delete")) resp = routed_object_delete(ctx, body);
    else if (!strcmp(method, "cross_services_list")) resp = routed_list_response("cross");
    else if (!strcmp(method, "cross_service_set")) resp = routed_cross_set(body);
    else if (!strcmp(method, "cross_service_delete")) resp = routed_cross_delete(body);
    else if (!strcmp(method, "policy_rules_reorder")) resp = routed_reorder(ctx, body);
    else if (!strcmp(method, "runtime_resolve")) resp = routed_runtime_resolve(body);
    else if (!strcmp(method, "external_policies")) resp = routed_external_json();
    else if (!strcmp(method, "gateway_ports_get")) resp = gateway_ports_get(ctx);
    else if (!strcmp(method, "gateway_ports_preview")) resp = gateway_ports_preview(ctx, body);
    else if (!strcmp(method, "gateway_ports_apply")) resp = gateway_ports_apply(ctx, body);
    else resp = routed_error("unsupported_operation", "unsupported routed operation", 400);
    routed_send(ctx, req, resp);
    json_object_put(resp);
    json_object_put(raw);
    return UBUS_STATUS_OK;
}

static const struct blobmsg_policy routed_any_policy[] = {
    { .name = "payload", .type = BLOBMSG_TYPE_UNSPEC },
};

#define ROUTED_METHOD(_name) UBUS_METHOD((_name), routed_handle, routed_any_policy)

static const struct ubus_method routed_methods[] = {
    ROUTED_METHOD("status"),
    ROUTED_METHOD("snapshot"),
    ROUTED_METHOD("tables_list"),
    ROUTED_METHOD("table_set"),
    ROUTED_METHOD("table_delete"),
    ROUTED_METHOD("objects_list"),
    ROUTED_METHOD("static_routes_list"),
    ROUTED_METHOD("policy_rules_list"),
    ROUTED_METHOD("object_set"),
    ROUTED_METHOD("object_delete"),
    ROUTED_METHOD("cross_services_list"),
    ROUTED_METHOD("cross_service_set"),
    ROUTED_METHOD("cross_service_delete"),
    ROUTED_METHOD("policy_rules_reorder"),
    ROUTED_METHOD("runtime_resolve"),
    ROUTED_METHOD("external_policies"),
    ROUTED_METHOD("gateway_ports_get"),
    ROUTED_METHOD("gateway_ports_preview"),
    ROUTED_METHOD("gateway_ports_apply"),
};

#undef ROUTED_METHOD

static struct ubus_object_type routed_object_type =
    UBUS_OBJECT_TYPE("dreamingwrt_routed", routed_methods);

int routed_control_start(struct ubus_context *ctx)
{
    sqlite3 *db = NULL;
    int rc;

    if (!ctx || routed_db_open(&db) != 0)
        return -1;
    sqlite3_close(db);
    memset(&routed_object, 0, sizeof(routed_object));
    routed_object.name = ROUTED_OBJECT_NAME;
    routed_object.type = &routed_object_type;
    routed_object.methods = routed_methods;
    routed_object.n_methods = ARRAY_SIZE(routed_methods);
    memset(&routed_alias_object, 0, sizeof(routed_alias_object));
    routed_alias_object.name = ROUTED_ALIAS_OBJECT_NAME;
    routed_alias_object.type = &routed_object_type;
    routed_alias_object.methods = routed_methods;
    routed_alias_object.n_methods = ARRAY_SIZE(routed_methods);
    rc = ubus_add_object(ctx, &routed_object);
    if (rc != UBUS_STATUS_OK) {
        fprintf(stderr, "[dreamingwrt-routed] ubus object register failed rc=%d\n", rc);
        return -1;
    }
    rc = ubus_add_object(ctx, &routed_alias_object);
    if (rc != UBUS_STATUS_OK) {
        fprintf(stderr, "[dreamingwrt-routed] ubus alias register failed rc=%d\n", rc);
        ubus_remove_object(ctx, &routed_object);
        return -1;
    }
    return 0;
}

void routed_control_stop(struct ubus_context *ctx)
{
    if (ctx && routed_alias_object.id)
        ubus_remove_object(ctx, &routed_alias_object);
    if (ctx && routed_object.id)
        ubus_remove_object(ctx, &routed_object);
}

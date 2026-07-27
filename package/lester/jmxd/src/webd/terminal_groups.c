// SPDX-License-Identifier: GPL-2.0-or-later
/* Persistent terminal groups for the policy engine. */
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "jmx_app_api.h"
#include "terminal_groups.h"

#define TG_DB_PATH "/etc/dreamingwrt/config.db"
#define TG_BASE_PATH "/api/v1/policy-engine/terminal-groups"
#define TG_MAX_GROUPS 1000
#define TG_MAX_MEMBERS_PER_GROUP 5000
#define TG_MAX_MEMBERS_TOTAL 50000
#define TG_MAX_ID 96
#define TG_MAX_NAME 128
#define TG_MAX_DESCRIPTION 1024
#define TG_MAX_COLOR 32
#define TG_MAX_DISPLAY_NAME 256

static const char *tg_schema_sql =
    "CREATE TABLE IF NOT EXISTS terminal_group ("
    " id TEXT PRIMARY KEY,"
    " name TEXT NOT NULL COLLATE NOCASE UNIQUE,"
    " description TEXT NOT NULL DEFAULT '',"
    " color TEXT NOT NULL DEFAULT '',"
    " created_at INTEGER NOT NULL,"
    " updated_at INTEGER NOT NULL);"
    "CREATE TABLE IF NOT EXISTS terminal_group_member ("
    " group_id TEXT NOT NULL,"
    " member_key TEXT NOT NULL,"
    " mac TEXT NOT NULL DEFAULT '',"
    " ip TEXT NOT NULL DEFAULT '',"
    " display_name TEXT NOT NULL DEFAULT '',"
    " position INTEGER NOT NULL DEFAULT 0,"
    " added_at INTEGER NOT NULL,"
    " PRIMARY KEY(group_id,member_key),"
    " FOREIGN KEY(group_id) REFERENCES terminal_group(id) ON DELETE CASCADE,"
    " CHECK(mac<>'' OR ip<>''));"
    "CREATE INDEX IF NOT EXISTS terminal_group_member_mac_idx "
    " ON terminal_group_member(mac) WHERE mac<>'';"
    "CREATE INDEX IF NOT EXISTS terminal_group_member_ip_idx "
    " ON terminal_group_member(ip) WHERE ip<>'';";

static int64_t tg_now(void)
{
    return (int64_t)time(NULL);
}

static const char *tg_text(sqlite3_stmt *st, int col)
{
    const unsigned char *value = st ? sqlite3_column_text(st, col) : NULL;
    return value ? (const char *)value : "";
}

static int tg_exec(sqlite3 *db, const char *sql)
{
    char *error = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &error);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-webd] terminal group sqlite rc=%d err=%s\n",
                rc, error ? error : "");
        sqlite3_free(error);
        return -1;
    }
    return 0;
}

static int tg_open(sqlite3 **out)
{
    sqlite3 *db = NULL;

    if (!out)
        return -1;
    *out = NULL;
    if (sqlite3_open(TG_DB_PATH, &db) != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        return -1;
    }
    sqlite3_busy_timeout(db, 3000);
    sqlite3_exec(db, "PRAGMA foreign_keys=ON", NULL, NULL, NULL);
    if (tg_exec(db, tg_schema_sql) != 0) {
        sqlite3_close(db);
        return -1;
    }
    *out = db;
    return 0;
}

int webd_terminal_groups_init(void)
{
    sqlite3 *db = NULL;
    int rc = tg_open(&db);

    if (db)
        sqlite3_close(db);
    return rc;
}

int webd_terminal_groups_path(const char *path)
{
    size_t n = strlen(TG_BASE_PATH);

    return path && !strncmp(path, TG_BASE_PATH, n) &&
           (path[n] == '\0' || path[n] == '/');
}

static struct json_object *tg_meta(const char *source)
{
    struct json_object *meta = json_object_new_object();

    json_object_object_add(meta, "source", json_object_new_string(source));
    json_object_object_add(meta, "generated_at", json_object_new_int64(tg_now()));
    return meta;
}

static struct json_object *tg_envelope(struct json_object *data, const char *source)
{
    struct json_object *root = json_object_new_object();

    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "data", data ? data : json_object_new_object());
    json_object_object_add(root, "meta", tg_meta(source));
    return root;
}

static struct json_object *tg_error(const char *code, const char *message,
                                    const char *field, int status)
{
    struct json_object *root = json_object_new_object();
    struct json_object *error = json_object_new_object();
    struct json_object *details = json_object_new_object();

    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "code", json_object_new_int(status));
    json_object_object_add(error, "code", json_object_new_string(code));
    json_object_object_add(error, "message", json_object_new_string(message));
    if (field && field[0])
        json_object_object_add(details, "field", json_object_new_string(field));
    json_object_object_add(error, "details", details);
    json_object_object_add(root, "error", error);
    json_object_object_add(root, "meta", tg_meta("config.db:terminal_group"));
    return root;
}

static struct json_object *tg_reference_error(const char *message,
                                              const char *group_id,
                                              struct json_object *references)
{
    struct json_object *root = tg_error("terminal_group_in_use", message,
                                        "references", 409);
    struct json_object *error = NULL;
    struct json_object *details = NULL;

    json_object_object_get_ex(root, "error", &error);
    json_object_object_get_ex(error, "details", &details);
    if (group_id && group_id[0])
        json_object_object_add(details, "group_id",
                               json_object_new_string(group_id));
    json_object_object_add(details, "references",
                           references ? references : json_object_new_array());
    return root;
}

static const char *tg_json_string(struct json_object *obj, const char *key,
                                  const char *fallback)
{
    struct json_object *value = NULL;

    if (obj && json_object_object_get_ex(obj, key, &value) && value &&
        json_object_is_type(value, json_type_string))
        return json_object_get_string(value);
    return fallback ? fallback : "";
}

static int tg_copy_trimmed(const char *input, char *out, size_t out_len,
                           size_t max_len, int required)
{
    const unsigned char *start = (const unsigned char *)(input ? input : "");
    const unsigned char *end;
    size_t len;

    if (!out || out_len == 0)
        return -1;
    while (*start && isspace(*start))
        start++;
    end = start + strlen((const char *)start);
    while (end > start && isspace(end[-1]))
        end--;
    len = (size_t)(end - start);
    if ((required && len == 0) || len > max_len || len + 1 > out_len)
        return -1;
    for (size_t i = 0; i < len; i++) {
        if (start[i] < 0x20 && start[i] != '\t')
            return -1;
    }
    memcpy(out, start, len);
    out[len] = '\0';
    return 0;
}

static int tg_id_ok(const char *id)
{
    size_t len;

    if (!id || !id[0])
        return 0;
    len = strlen(id);
    if (len > TG_MAX_ID || id[0] == '-')
        return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)id[i];
        if (!(isalnum(c) || c == '-' || c == '_' || c == '.' || c == ':'))
            return 0;
    }
    return 1;
}

static int tg_mac_normalize(const char *input, char out[18])
{
    char hex[13];
    int count = 0;

    if (!input || !input[0]) {
        out[0] = '\0';
        return 0;
    }
    for (size_t i = 0; input[i]; i++) {
        unsigned char c = (unsigned char)input[i];
        if (isxdigit(c)) {
            if (count >= 12)
                return -1;
            hex[count++] = (char)tolower(c);
        } else if (c != ':' && c != '-' && c != '.' && !isspace(c)) {
            return -1;
        }
    }
    if (count != 12)
        return -1;
    snprintf(out, 18, "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",
             hex[0], hex[1], hex[2], hex[3], hex[4], hex[5],
             hex[6], hex[7], hex[8], hex[9], hex[10], hex[11]);
    return 0;
}

static int tg_ip_normalize(const char *input, char *out, size_t out_len)
{
    unsigned char buffer[sizeof(struct in6_addr)];
    int family;

    if (!input || !input[0]) {
        out[0] = '\0';
        return 0;
    }
    if (strlen(input) >= out_len || strchr(input, '%'))
        return -1;
    family = strchr(input, ':') ? AF_INET6 : AF_INET;
    if (inet_pton(family, input, buffer) != 1)
        return -1;
    if (!inet_ntop(family, buffer, out, (socklen_t)out_len))
        return -1;
    return 0;
}

static struct json_object *tg_normalize_member(struct json_object *input, int position,
                                                char *error, size_t error_len)
{
    const char *raw_mac = tg_json_string(input, "mac",
                           tg_json_string(input, "client_mac",
                           tg_json_string(input, "hwaddr", "")));
    const char *raw_ip = tg_json_string(input, "ip",
                          tg_json_string(input, "ipv4",
                          tg_json_string(input, "address", "")));
    const char *raw_name = tg_json_string(input, "name",
                            tg_json_string(input, "display_name",
                            tg_json_string(input, "hostname", "")));
    char mac[18] = "";
    char ip[INET6_ADDRSTRLEN] = "";
    char name[TG_MAX_DISPLAY_NAME + 1] = "";
    char key[INET6_ADDRSTRLEN + 4];
    struct json_object *member;

    if (!input || !json_object_is_type(input, json_type_object)) {
        snprintf(error, error_len, "member must be an object");
        return NULL;
    }
    if (tg_mac_normalize(raw_mac, mac) != 0) {
        snprintf(error, error_len, "invalid member MAC");
        return NULL;
    }
    if (tg_ip_normalize(raw_ip, ip, sizeof(ip)) != 0) {
        snprintf(error, error_len, "invalid member IP");
        return NULL;
    }
    if (!mac[0] && !ip[0]) {
        snprintf(error, error_len, "member requires MAC or IP");
        return NULL;
    }
    if (tg_copy_trimmed(raw_name, name, sizeof(name), TG_MAX_DISPLAY_NAME, 0) != 0) {
        snprintf(error, error_len, "member display name is too long");
        return NULL;
    }
    snprintf(key, sizeof(key), "%s%s", mac[0] ? "" : "ip:", mac[0] ? mac : ip);
    member = json_object_new_object();
    json_object_object_add(member, "member_key", json_object_new_string(key));
    json_object_object_add(member, "mac", json_object_new_string(mac));
    json_object_object_add(member, "ip", json_object_new_string(ip));
    json_object_object_add(member, "name", json_object_new_string(name));
    json_object_object_add(member, "order", json_object_new_int(position));
    return member;
}

static int tg_array_has_member(struct json_object *members, const char *member_key)
{
    int n = members && json_object_is_type(members, json_type_array) ?
            json_object_array_length(members) : 0;

    for (int i = 0; i < n; i++) {
        struct json_object *member = json_object_array_get_idx(members, i);
        if (!strcmp(tg_json_string(member, "member_key", ""), member_key))
            return 1;
    }
    return 0;
}

static struct json_object *tg_normalize_group(struct json_object *input, int allow_empty_id,
                                               char *error, size_t error_len)
{
    struct json_object *raw_members = NULL;
    struct json_object *members = json_object_new_array();
    struct json_object *group = json_object_new_object();
    char id[TG_MAX_ID + 1] = "";
    char name[TG_MAX_NAME + 1] = "";
    char description[TG_MAX_DESCRIPTION + 1] = "";
    char color[TG_MAX_COLOR + 1] = "";
    int count = 0;

    if (!input || !json_object_is_type(input, json_type_object)) {
        snprintf(error, error_len, "group must be an object");
        goto fail;
    }
    if (tg_copy_trimmed(tg_json_string(input, "id", ""), id, sizeof(id), TG_MAX_ID, 0) != 0 ||
        (id[0] && !tg_id_ok(id)) || (!allow_empty_id && !id[0])) {
        snprintf(error, error_len, "invalid group id");
        goto fail;
    }
    if (tg_copy_trimmed(tg_json_string(input, "name", ""), name, sizeof(name), TG_MAX_NAME, 1) != 0) {
        snprintf(error, error_len, "group name is required and must not exceed %d bytes", TG_MAX_NAME);
        goto fail;
    }
    if (tg_copy_trimmed(tg_json_string(input, "description", ""), description,
                        sizeof(description), TG_MAX_DESCRIPTION, 0) != 0 ||
        tg_copy_trimmed(tg_json_string(input, "color", ""), color,
                        sizeof(color), TG_MAX_COLOR, 0) != 0) {
        snprintf(error, error_len, "group description or color is too long");
        goto fail;
    }
    if (json_object_object_get_ex(input, "members", &raw_members) && raw_members) {
        if (!json_object_is_type(raw_members, json_type_array)) {
            snprintf(error, error_len, "members must be an array");
            goto fail;
        }
        count = json_object_array_length(raw_members);
        if (count > TG_MAX_MEMBERS_PER_GROUP) {
            snprintf(error, error_len, "group exceeds %d members", TG_MAX_MEMBERS_PER_GROUP);
            goto fail;
        }
        for (int i = 0; i < count; i++) {
            struct json_object *member = tg_normalize_member(
                json_object_array_get_idx(raw_members, i),
                json_object_array_length(members), error, error_len);
            const char *key;

            if (!member)
                goto fail;
            key = tg_json_string(member, "member_key", "");
            if (tg_array_has_member(members, key)) {
                json_object_put(member);
                continue;
            }
            json_object_array_add(members, member);
        }
    }
    json_object_object_add(group, "id", json_object_new_string(id));
    json_object_object_add(group, "name", json_object_new_string(name));
    json_object_object_add(group, "description", json_object_new_string(description));
    json_object_object_add(group, "color", json_object_new_string(color));
    json_object_object_add(group, "members", members);
    return group;

fail:
    json_object_put(members);
    json_object_put(group);
    return NULL;
}

static int tg_table_exists(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    int exists = 0;

    if (sqlite3_prepare_v2(db,
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
        -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
        exists = sqlite3_step(st) == SQLITE_ROW;
    }
    sqlite3_finalize(st);
    return exists;
}

static int tg_reference_exists(struct json_object *references,
                               const char *table, const char *id)
{
    int n = json_object_array_length(references);

    for (int i = 0; i < n; i++) {
        struct json_object *ref = json_object_array_get_idx(references, i);
        if (!strcmp(tg_json_string(ref, "table", ""), table) &&
            !strcmp(tg_json_string(ref, "id", ""), id))
            return 1;
    }
    return 0;
}

static void tg_reference_query(sqlite3 *db, struct json_object *references,
                               const char *table, const char *sql,
                               const char *field, const char *id)
{
    sqlite3_stmt *st = NULL;
    char canonical[TG_MAX_ID + 24];

    if (!tg_table_exists(db, table) ||
        sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return;
    snprintf(canonical, sizeof(canonical), "terminal_group:%s", id);
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, canonical, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *policy_id = tg_text(st, 0);
        struct json_object *ref;

        if (!policy_id[0] || tg_reference_exists(references, table, policy_id))
            continue;
        ref = json_object_new_object();
        json_object_object_add(ref, "type", json_object_new_string("policy"));
        json_object_object_add(ref, "table", json_object_new_string(table));
        json_object_object_add(ref, "id", json_object_new_string(policy_id));
        json_object_object_add(ref, "name", json_object_new_string(tg_text(st, 1)));
        json_object_object_add(ref, "field", json_object_new_string(field));
        json_object_array_add(references, ref);
    }
    sqlite3_finalize(st);
}

static struct json_object *tg_references(sqlite3 *db, const char *id)
{
    struct json_object *refs = json_object_new_array();

    tg_reference_query(db, refs, "flow_client_limits",
        "SELECT id,COALESCE(client,id) FROM flow_client_limits "
        "WHERE device_group=?1 OR device_group=?2", "device_group", id);
    tg_reference_query(db, refs, "policy_route_rule",
        "SELECT id,COALESCE(name,id) FROM policy_route_rule "
        "WHERE source_object IN (?1,?2) OR dest_object IN (?1,?2)",
        "source_object|dest_object", id);
    tg_reference_query(db, refs, "flow_rules",
        "SELECT id,COALESCE(name,id) FROM flow_rules "
        "WHERE source IN (?1,?2) OR destination IN (?1,?2)",
        "source|destination", id);
    tg_reference_query(db, refs, "network_control_rule",
        "SELECT id,COALESCE(name,id) FROM network_control_rule "
        "WHERE source IN (?1,?2)", "source", id);
    return refs;
}

static struct json_object *tg_capabilities(void)
{
    struct json_object *cap = json_object_new_object();
    struct json_object *sources = json_object_new_array();

    json_object_object_add(cap, "create", json_object_new_boolean(1));
    json_object_object_add(cap, "update", json_object_new_boolean(1));
    json_object_object_add(cap, "delete", json_object_new_boolean(1));
    json_object_object_add(cap, "import", json_object_new_boolean(1));
    json_object_object_add(cap, "replace_import", json_object_new_boolean(1));
    json_object_object_add(cap, "export", json_object_new_boolean(1));
    json_object_object_add(cap, "server_json_export", json_object_new_boolean(1));
    json_object_object_add(cap, "policy_reference_count", json_object_new_boolean(1));
    json_object_object_add(cap, "delete_reference_protection", json_object_new_boolean(1));
    json_object_object_add(cap, "force_delete", json_object_new_boolean(0));
    json_object_object_add(cap, "current_client_overlay", json_object_new_boolean(0));
    json_object_object_add(cap, "max_groups", json_object_new_int(TG_MAX_GROUPS));
    json_object_object_add(cap, "max_members_per_group", json_object_new_int(TG_MAX_MEMBERS_PER_GROUP));
    json_object_object_add(cap, "max_members_total", json_object_new_int(TG_MAX_MEMBERS_TOTAL));
    json_object_array_add(sources, json_object_new_string("flow_client_limits.device_group"));
    json_object_array_add(sources, json_object_new_string("policy_route_rule.source_object|dest_object"));
    json_object_array_add(sources, json_object_new_string("flow_rules.source|destination"));
    json_object_array_add(sources, json_object_new_string("network_control_rule.source"));
    json_object_object_add(cap, "policy_reference_sources", sources);
    return cap;
}

static struct json_object *tg_group_json(sqlite3 *db, const char *id, int include_members)
{
    sqlite3_stmt *st = NULL;
    struct json_object *group = NULL;

    if (sqlite3_prepare_v2(db,
        "SELECT id,name,description,color,created_at,updated_at "
        "FROM terminal_group WHERE id=?1", -1, &st, NULL) != SQLITE_OK)
        return NULL;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *refs = tg_references(db, id);
        group = json_object_new_object();
        json_object_object_add(group, "id", json_object_new_string(tg_text(st, 0)));
        json_object_object_add(group, "name", json_object_new_string(tg_text(st, 1)));
        json_object_object_add(group, "description", json_object_new_string(tg_text(st, 2)));
        json_object_object_add(group, "color", json_object_new_string(tg_text(st, 3)));
        json_object_object_add(group, "created_at", json_object_new_int64(sqlite3_column_int64(st, 4)));
        json_object_object_add(group, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 5)));
        json_object_object_add(group, "policy_count", json_object_new_int(json_object_array_length(refs)));
        json_object_object_add(group, "references", refs);
    }
    sqlite3_finalize(st);
    if (!group)
        return NULL;

    if (sqlite3_prepare_v2(db,
        "SELECT COUNT(*) FROM terminal_group_member WHERE group_id=?1",
        -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW)
            json_object_object_add(group, "member_count",
                                   json_object_new_int(sqlite3_column_int(st, 0)));
    }
    sqlite3_finalize(st);
    if (include_members) {
        struct json_object *members = json_object_new_array();
        if (sqlite3_prepare_v2(db,
            "SELECT mac,ip,display_name,position,added_at,member_key "
            "FROM terminal_group_member WHERE group_id=?1 ORDER BY position,member_key",
            -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
            while (sqlite3_step(st) == SQLITE_ROW) {
                struct json_object *member = json_object_new_object();
                json_object_object_add(member, "mac", json_object_new_string(tg_text(st, 0)));
                json_object_object_add(member, "ip", json_object_new_string(tg_text(st, 1)));
                json_object_object_add(member, "name", json_object_new_string(tg_text(st, 2)));
                json_object_object_add(member, "display_name", json_object_new_string(tg_text(st, 2)));
                json_object_object_add(member, "order", json_object_new_int(sqlite3_column_int(st, 3)));
                json_object_object_add(member, "position", json_object_new_int(sqlite3_column_int(st, 3)));
                json_object_object_add(member, "added_at", json_object_new_int64(sqlite3_column_int64(st, 4)));
                json_object_object_add(member, "member_key", json_object_new_string(tg_text(st, 5)));
                json_object_array_add(members, member);
            }
        }
        sqlite3_finalize(st);
        json_object_object_add(group, "members", members);
    }
    return group;
}

static struct json_object *tg_list_data(sqlite3 *db, int include_members)
{
    sqlite3_stmt *st = NULL;
    struct json_object *data = json_object_new_object();
    struct json_object *groups = json_object_new_array();

    if (sqlite3_prepare_v2(db,
        "SELECT id FROM terminal_group ORDER BY name COLLATE NOCASE,id",
        -1, &st, NULL) == SQLITE_OK) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *group = tg_group_json(db, tg_text(st, 0), include_members);
            if (group)
                json_object_array_add(groups, group);
        }
    }
    sqlite3_finalize(st);
    json_object_object_add(data, "source",
                           json_object_new_string("config.db:terminal_group+terminal_group_member"));
    json_object_object_add(data, "writable", json_object_new_boolean(1));
    json_object_object_add(data, "schema_version", json_object_new_int(1));
    json_object_object_add(data, "groups", groups);
    json_object_object_add(data, "total", json_object_new_int(json_object_array_length(groups)));
    json_object_object_add(data, "capabilities", tg_capabilities());
    return data;
}

static int tg_group_exists(sqlite3 *db, const char *id)
{
    sqlite3_stmt *st = NULL;
    int exists = 0;

    if (sqlite3_prepare_v2(db, "SELECT 1 FROM terminal_group WHERE id=?1",
                           -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        exists = sqlite3_step(st) == SQLITE_ROW;
    }
    sqlite3_finalize(st);
    return exists;
}

static int64_t tg_count(sqlite3 *db, const char *sql, const char *id)
{
    sqlite3_stmt *st = NULL;
    int64_t count = -1;

    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        if (id)
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW)
            count = sqlite3_column_int64(st, 0);
    }
    sqlite3_finalize(st);
    return count;
}

static int tg_validate_projected_limits(sqlite3 *db, struct json_object *groups,
                                        int replace, char *error, size_t error_len)
{
    int64_t group_count = replace ? 0 :
        tg_count(db, "SELECT COUNT(*) FROM terminal_group", NULL);
    int64_t member_count = replace ? 0 :
        tg_count(db, "SELECT COUNT(*) FROM terminal_group_member", NULL);

    if (group_count < 0 || member_count < 0) {
        snprintf(error, error_len, "could not read terminal group capacity");
        return -1;
    }
    for (int i = 0; groups && i < json_object_array_length(groups); i++) {
        struct json_object *group = json_object_array_get_idx(groups, i);
        struct json_object *members = NULL;
        const char *id = tg_json_string(group, "id", "");
        int exists = id[0] && tg_group_exists(db, id);
        int64_t old_members = 0;

        json_object_object_get_ex(group, "members", &members);
        if (!replace && exists) {
            old_members = tg_count(db,
                "SELECT COUNT(*) FROM terminal_group_member WHERE group_id=?1", id);
            if (old_members < 0) {
                snprintf(error, error_len, "could not read terminal group member capacity");
                return -1;
            }
        } else {
            group_count++;
        }
        member_count -= old_members;
        member_count += members ? json_object_array_length(members) : 0;
    }
    if (group_count > TG_MAX_GROUPS) {
        snprintf(error, error_len, "terminal group store exceeds %d groups", TG_MAX_GROUPS);
        return -2;
    }
    if (member_count > TG_MAX_MEMBERS_TOTAL) {
        snprintf(error, error_len, "terminal group store exceeds %d total members",
                 TG_MAX_MEMBERS_TOTAL);
        return -2;
    }
    return 0;
}

static int tg_id_by_name(sqlite3 *db, const char *name, char *out, size_t out_len)
{
    sqlite3_stmt *st = NULL;
    int found = 0;

    out[0] = '\0';
    if (sqlite3_prepare_v2(db,
        "SELECT id FROM terminal_group WHERE name=?1 COLLATE NOCASE",
        -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            snprintf(out, out_len, "%s", tg_text(st, 0));
            found = 1;
        }
    }
    sqlite3_finalize(st);
    return found;
}

static int tg_random_id(sqlite3 *db, char *out, size_t out_len)
{
    unsigned char random_bytes[10];
    FILE *fp;

    for (int attempt = 0; attempt < 8; attempt++) {
        fp = fopen("/dev/urandom", "rb");
        if (!fp)
            return -1;
        if (fread(random_bytes, 1, sizeof(random_bytes), fp) != sizeof(random_bytes)) {
            fclose(fp);
            return -1;
        }
        fclose(fp);
        snprintf(out, out_len,
                 "tg-%08llx-%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                 (unsigned long long)tg_now(), random_bytes[0], random_bytes[1],
                 random_bytes[2], random_bytes[3], random_bytes[4], random_bytes[5],
                 random_bytes[6], random_bytes[7], random_bytes[8], random_bytes[9]);
        if (!tg_group_exists(db, out))
            return 0;
    }
    return -1;
}

static int tg_name_conflict(sqlite3 *db, const char *id, const char *name)
{
    sqlite3_stmt *st = NULL;
    int conflict = 0;

    if (sqlite3_prepare_v2(db,
        "SELECT 1 FROM terminal_group WHERE name=?1 COLLATE NOCASE AND id<>?2",
        -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, id ? id : "", -1, SQLITE_TRANSIENT);
        conflict = sqlite3_step(st) == SQLITE_ROW;
    }
    sqlite3_finalize(st);
    return conflict;
}

static int tg_save_group(sqlite3 *db, struct json_object *group, int create,
                         char *error, size_t error_len)
{
    sqlite3_stmt *st = NULL;
    struct json_object *members = NULL;
    const char *id = tg_json_string(group, "id", "");
    const char *name = tg_json_string(group, "name", "");
    int64_t now = tg_now();
    int rc;

    if (tg_name_conflict(db, id, name)) {
        snprintf(error, error_len, "terminal_group_name_conflict");
        return -2;
    }
    if (create) {
        rc = sqlite3_prepare_v2(db,
            "INSERT INTO terminal_group(id,name,description,color,created_at,updated_at) "
            "VALUES(?1,?2,?3,?4,?5,?5)", -1, &st, NULL);
    } else {
        rc = sqlite3_prepare_v2(db,
            "UPDATE terminal_group SET name=?2,description=?3,color=?4,updated_at=?5 WHERE id=?1",
            -1, &st, NULL);
    }
    if (rc != SQLITE_OK) {
        snprintf(error, error_len, "prepare group write failed: %s", sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, tg_json_string(group, "description", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, tg_json_string(group, "color", ""), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 5, now);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE || (!create && sqlite3_changes(db) == 0)) {
        snprintf(error, error_len, "group write failed: %s", sqlite3_errmsg(db));
        return -1;
    }
    if (sqlite3_prepare_v2(db, "DELETE FROM terminal_group_member WHERE group_id=?1",
                           -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return -1;

    json_object_object_get_ex(group, "members", &members);
    for (int i = 0; members && i < json_object_array_length(members); i++) {
        struct json_object *member = json_object_array_get_idx(members, i);
        if (sqlite3_prepare_v2(db,
            "INSERT INTO terminal_group_member(group_id,member_key,mac,ip,display_name,position,added_at) "
            "VALUES(?1,?2,?3,?4,?5,?6,?7)", -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, tg_json_string(member, "member_key", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, tg_json_string(member, "mac", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, tg_json_string(member, "ip", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, tg_json_string(member, "name", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 6, i);
        sqlite3_bind_int64(st, 7, now);
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) {
            snprintf(error, error_len, "member write failed: %s", sqlite3_errmsg(db));
            return -1;
        }
    }
    return 0;
}

static int tg_group_matches(sqlite3 *db, struct json_object *group)
{
    struct json_object *stored = tg_group_json(db, tg_json_string(group, "id", ""), 1);
    struct json_object *incoming_members = NULL;
    struct json_object *stored_members = NULL;
    int matches = 0;

    if (!stored)
        return 0;
    json_object_object_get_ex(group, "members", &incoming_members);
    json_object_object_get_ex(stored, "members", &stored_members);
    matches = !strcmp(tg_json_string(group, "name", ""), tg_json_string(stored, "name", "")) &&
              !strcmp(tg_json_string(group, "description", ""), tg_json_string(stored, "description", "")) &&
              !strcmp(tg_json_string(group, "color", ""), tg_json_string(stored, "color", "")) &&
              json_object_array_length(incoming_members) == json_object_array_length(stored_members);
    for (int i = 0; matches && i < json_object_array_length(incoming_members); i++) {
        struct json_object *a = json_object_array_get_idx(incoming_members, i);
        struct json_object *b = json_object_array_get_idx(stored_members, i);
        matches = !strcmp(tg_json_string(a, "member_key", ""), tg_json_string(b, "member_key", "")) &&
                  !strcmp(tg_json_string(a, "mac", ""), tg_json_string(b, "mac", "")) &&
                  !strcmp(tg_json_string(a, "ip", ""), tg_json_string(b, "ip", "")) &&
                  !strcmp(tg_json_string(a, "name", ""), tg_json_string(b, "name", ""));
    }
    json_object_put(stored);
    return matches;
}

static struct json_object *tg_create_or_update(sqlite3 *db, struct json_object *body,
                                                const char *path_id, int update,
                                                const char *actor, int *status)
{
    char error[256] = "";
    char id[TG_MAX_ID + 1] = "";
    struct json_object *group = tg_normalize_group(body, 1, error, sizeof(error));
    struct json_object *groups = NULL;
    struct json_object *result;
    int rc;

    if (!group) {
        *status = 400;
        return tg_error("terminal_group_validation_failed", error, "group", 400);
    }
    snprintf(id, sizeof(id), "%s", path_id && path_id[0] ? path_id : tg_json_string(group, "id", ""));
    if (update) {
        if (!tg_id_ok(id) || !tg_group_exists(db, id)) {
            json_object_put(group);
            *status = 404;
            return tg_error("terminal_group_not_found", "terminal group was not found", "id", 404);
        }
    } else if (!id[0] && tg_random_id(db, id, sizeof(id)) != 0) {
        json_object_put(group);
        *status = 500;
        return tg_error("terminal_group_id_generation_failed", "could not generate group id", "id", 500);
    } else if (id[0] && (!tg_id_ok(id) || tg_group_exists(db, id))) {
        json_object_put(group);
        *status = tg_id_ok(id) ? 409 : 400;
        return tg_error(tg_id_ok(id) ? "terminal_group_id_conflict" : "terminal_group_validation_failed",
                        tg_id_ok(id) ? "terminal group id already exists" : "invalid terminal group id",
                        "id", *status);
    }
    json_object_object_add(group, "id", json_object_new_string(id));
    if (tg_exec(db, "BEGIN IMMEDIATE") != 0) {
        json_object_put(group);
        *status = 503;
        return tg_error("terminal_group_store_busy", "terminal group store is busy", "config.db", 503);
    }
    groups = json_object_new_array();
    json_object_array_add(groups, json_object_get(group));
    rc = tg_validate_projected_limits(db, groups, 0, error, sizeof(error));
    json_object_put(groups);
    if (rc != 0) {
        tg_exec(db, "ROLLBACK");
        json_object_put(group);
        *status = rc == -2 ? 409 : 500;
        return tg_error(rc == -2 ? "terminal_group_capacity_exceeded" :
                        "terminal_group_capacity_check_failed", error,
                        "members", *status);
    }
    rc = tg_save_group(db, group, !update, error, sizeof(error));
    if (rc != 0) {
        tg_exec(db, "ROLLBACK");
        json_object_put(group);
        *status = rc == -2 ? 409 : 500;
        return tg_error(rc == -2 ? "terminal_group_name_conflict" : "terminal_group_write_failed",
                        rc == -2 ? "terminal group name already exists" : error,
                        rc == -2 ? "name" : "config.db", *status);
    }
    if (tg_exec(db, "COMMIT") != 0) {
        tg_exec(db, "ROLLBACK");
        json_object_put(group);
        *status = 500;
        return tg_error("terminal_group_commit_failed",
                        "could not commit terminal group transaction",
                        "config.db", 500);
    }
    json_object_put(group);
    result = tg_group_json(db, id, 1);
    jmx_app_audit_log(actor, actor, update ? "terminal_group.update" : "terminal_group.create",
                      "medium", id, "", "status=success");
    *status = update ? 200 : 201;
    return tg_envelope(result, "config.db:terminal_group");
}

static struct json_object *tg_delete(sqlite3 *db, const char *id,
                                     const char *actor, int *status)
{
    sqlite3_stmt *st = NULL;
    struct json_object *refs;
    int rc;

    if (!tg_id_ok(id) || !tg_group_exists(db, id)) {
        *status = 404;
        return tg_error("terminal_group_not_found", "terminal group was not found", "id", 404);
    }
    if (tg_exec(db, "BEGIN IMMEDIATE") != 0) {
        *status = 503;
        return tg_error("terminal_group_delete_failed",
                        "could not start delete transaction", "config.db", 503);
    }
    refs = tg_references(db, id);
    if (json_object_array_length(refs) > 0) {
        tg_exec(db, "ROLLBACK");
        *status = 409;
        return tg_reference_error(
            "terminal group is referenced by one or more policies", id, refs);
    }
    json_object_put(refs);
    if (sqlite3_prepare_v2(db, "DELETE FROM terminal_group WHERE id=?1",
                           -1, &st, NULL) != SQLITE_OK) {
        tg_exec(db, "ROLLBACK");
        *status = 500;
        return tg_error("terminal_group_delete_failed",
                        "could not prepare terminal group deletion", "config.db", 500);
    }
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        tg_exec(db, "ROLLBACK");
        *status = 500;
        return tg_error("terminal_group_delete_failed", sqlite3_errmsg(db), "config.db", 500);
    }
    if (tg_exec(db, "COMMIT") != 0) {
        tg_exec(db, "ROLLBACK");
        *status = 500;
        return tg_error("terminal_group_delete_failed",
                        "could not commit terminal group deletion",
                        "config.db", 500);
    }
    {
        struct json_object *data = json_object_new_object();
        json_object_object_add(data, "id", json_object_new_string(id));
        json_object_object_add(data, "deleted", json_object_new_boolean(1));
        jmx_app_audit_log(actor, actor, "terminal_group.delete", "medium", id, "", "status=success");
        *status = 200;
        return tg_envelope(data, "config.db:terminal_group");
    }
}

static int tg_batch_duplicate(struct json_object *groups, struct json_object *candidate)
{
    const char *id = tg_json_string(candidate, "id", "");
    const char *name = tg_json_string(candidate, "name", "");

    for (int i = 0; i < json_object_array_length(groups); i++) {
        struct json_object *existing = json_object_array_get_idx(groups, i);
        if (!strcasecmp(name, tg_json_string(existing, "name", "")) ||
            (id[0] && !strcmp(id, tg_json_string(existing, "id", ""))))
            return 1;
    }
    return 0;
}

static int tg_keep_has(struct json_object *keep, const char *id)
{
    for (int i = 0; keep && i < json_object_array_length(keep); i++) {
        if (!strcmp(json_object_get_string(json_object_array_get_idx(keep, i)), id))
            return 1;
    }
    return 0;
}

static struct json_object *tg_import(sqlite3 *db, struct json_object *body,
                                     const char *actor, int *status)
{
    struct json_object *raw_groups = NULL;
    struct json_object *groups = json_object_new_array();
    struct json_object *keep = json_object_new_array();
    struct json_object *warnings = json_object_new_array();
    struct json_object *conflict_refs = NULL;
    char conflict_id[TG_MAX_ID + 1] = "";
    const char *mode = tg_json_string(body, "mode", "merge");
    char error[256] = "";
    int total_members = 0;
    int created = 0, updated = 0, unchanged = 0, deleted = 0;

    if (strcmp(mode, "merge") && strcmp(mode, "replace")) {
        *status = 400;
        goto invalid_mode;
    }
    if (!body || !json_object_object_get_ex(body, "groups", &raw_groups) ||
        !raw_groups || !json_object_is_type(raw_groups, json_type_array) ||
        json_object_array_length(raw_groups) <= 0 ||
        json_object_array_length(raw_groups) > TG_MAX_GROUPS) {
        snprintf(error, sizeof(error), "groups must contain 1-%d items", TG_MAX_GROUPS);
        *status = 400;
        goto invalid;
    }
    for (int i = 0; i < json_object_array_length(raw_groups); i++) {
        struct json_object *group = tg_normalize_group(json_object_array_get_idx(raw_groups, i),
                                                       1, error, sizeof(error));
        struct json_object *members = NULL;
        if (!group || tg_batch_duplicate(groups, group)) {
            if (group)
                json_object_put(group);
            if (!error[0])
                snprintf(error, sizeof(error), "duplicate group id or name in import batch");
            *status = 400;
            goto invalid;
        }
        json_object_object_get_ex(group, "members", &members);
        total_members += json_object_array_length(members);
        if (total_members > TG_MAX_MEMBERS_TOTAL) {
            json_object_put(group);
            snprintf(error, sizeof(error), "import exceeds %d total members", TG_MAX_MEMBERS_TOTAL);
            *status = 400;
            goto invalid;
        }
        json_object_array_add(groups, group);
    }
    if (tg_exec(db, "BEGIN IMMEDIATE") != 0) {
        *status = 503;
        snprintf(error, sizeof(error), "terminal group store is busy");
        goto invalid;
    }

    /* Resolve stable IDs before any mutation. */
    for (int i = 0; i < json_object_array_length(groups); i++) {
        struct json_object *group = json_object_array_get_idx(groups, i);
        const char *raw_id = tg_json_string(group, "id", "");
        char resolved[TG_MAX_ID + 1] = "";

        if (raw_id[0])
            snprintf(resolved, sizeof(resolved), "%s", raw_id);
        else if (!tg_id_by_name(db, tg_json_string(group, "name", ""), resolved, sizeof(resolved)) &&
                 tg_random_id(db, resolved, sizeof(resolved)) != 0) {
            snprintf(error, sizeof(error), "could not generate imported group id");
            goto rollback;
        }
        json_object_object_add(group, "id", json_object_new_string(resolved));
        if (tg_keep_has(keep, resolved)) {
            snprintf(error, sizeof(error), "multiple imported groups resolve to the same id");
            goto rollback;
        }
        json_object_array_add(keep, json_object_new_string(resolved));
    }
    {
        int limit_rc = tg_validate_projected_limits(db, groups,
                            !strcmp(mode, "replace"), error, sizeof(error));
        if (limit_rc != 0) {
            *status = limit_rc == -2 ? 409 : 500;
            goto rollback;
        }
    }

    if (!strcmp(mode, "replace")) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(db, "SELECT id FROM terminal_group", -1, &st, NULL) != SQLITE_OK)
            goto rollback;
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *old_id = tg_text(st, 0);
            if (!tg_keep_has(keep, old_id)) {
                struct json_object *refs = tg_references(db, old_id);
                if (json_object_array_length(refs) > 0) {
                    snprintf(conflict_id, sizeof(conflict_id), "%s", old_id);
                    conflict_refs = refs;
                    snprintf(error, sizeof(error),
                             "terminal group %s is referenced by one or more policies",
                             old_id);
                    sqlite3_finalize(st);
                    *status = 409;
                    goto rollback;
                }
                json_object_put(refs);
            }
        }
        sqlite3_finalize(st);
        if (sqlite3_prepare_v2(db, "SELECT id FROM terminal_group", -1, &st, NULL) != SQLITE_OK)
            goto rollback;
        {
            struct json_object *remove = json_object_new_array();
            while (sqlite3_step(st) == SQLITE_ROW) {
                if (!tg_keep_has(keep, tg_text(st, 0)))
                    json_object_array_add(remove, json_object_new_string(tg_text(st, 0)));
            }
            sqlite3_finalize(st);
            for (int i = 0; i < json_object_array_length(remove); i++) {
                sqlite3_stmt *del = NULL;
                if (sqlite3_prepare_v2(db, "DELETE FROM terminal_group WHERE id=?1",
                                       -1, &del, NULL) != SQLITE_OK) {
                    json_object_put(remove);
                    goto rollback;
                }
                sqlite3_bind_text(del, 1,
                    json_object_get_string(json_object_array_get_idx(remove, i)), -1, SQLITE_TRANSIENT);
                if (sqlite3_step(del) != SQLITE_DONE) {
                    sqlite3_finalize(del);
                    json_object_put(remove);
                    goto rollback;
                }
                sqlite3_finalize(del);
                deleted++;
            }
            json_object_put(remove);
        }
    }

    for (int i = 0; i < json_object_array_length(groups); i++) {
        struct json_object *group = json_object_array_get_idx(groups, i);
        const char *id = tg_json_string(group, "id", "");
        int exists = tg_group_exists(db, id);
        int rc;

        if (exists && tg_group_matches(db, group)) {
            unchanged++;
            continue;
        }
        rc = tg_save_group(db, group, !exists, error, sizeof(error));
        if (rc != 0) {
            if (rc == -2)
                *status = 409;
            goto rollback;
        }
        if (exists)
            updated++;
        else
            created++;
    }
    if (tg_exec(db, "COMMIT") != 0) {
        tg_exec(db, "ROLLBACK");
        goto rollback_no_tx;
    }
    {
        struct json_object *data = tg_list_data(db, 1);
        json_object_object_add(data, "mode", json_object_new_string(mode));
        json_object_object_add(data, "created", json_object_new_int(created));
        json_object_object_add(data, "updated", json_object_new_int(updated));
        json_object_object_add(data, "unchanged", json_object_new_int(unchanged));
        json_object_object_add(data, "deleted", json_object_new_int(deleted));
        json_object_object_add(data, "warnings", warnings);
        json_object_put(groups);
        json_object_put(keep);
        jmx_app_audit_log(actor, actor, "terminal_group.import", "medium", mode, "",
                          "status=success");
        *status = 200;
        return tg_envelope(data, "config.db:terminal_group.import");
    }

rollback:
    tg_exec(db, "ROLLBACK");
rollback_no_tx:
    if (!error[0])
        snprintf(error, sizeof(error), "terminal group import failed: %s", sqlite3_errmsg(db));
    json_object_put(groups);
    json_object_put(keep);
    json_object_put(warnings);
    if (*status == 200)
        *status = 500;
    if (*status == 409 && conflict_refs)
        return tg_reference_error(error, conflict_id, conflict_refs);
    if (conflict_refs)
        json_object_put(conflict_refs);
    return tg_error(*status == 409 && !strcmp(error, "terminal_group_name_conflict") ?
                    "terminal_group_name_conflict" :
                    (*status == 409 ? "terminal_group_capacity_exceeded" :
                     "terminal_group_import_failed"),
                    error, "groups", *status);

invalid_mode:
    snprintf(error, sizeof(error), "mode must be merge or replace");
invalid:
    json_object_put(groups);
    json_object_put(keep);
    json_object_put(warnings);
    return tg_error("terminal_group_import_validation_failed", error, "groups", *status);
}

static int tg_query_true(const char *query, const char *key, int fallback)
{
    const char *p = query ? query : "";
    size_t key_len = strlen(key);

    while (*p) {
        if (!strncmp(p, key, key_len) && p[key_len] == '=') {
            const char *value = p + key_len + 1;
            return strncmp(value, "0", 1) && strncasecmp(value, "false", 5);
        }
        p = strchr(p, '&');
        if (!p)
            break;
        p++;
    }
    return fallback;
}

struct json_object *webd_terminal_groups_handle(const char *method,
                                                const char *path,
                                                const char *query,
                                                struct json_object *body,
                                                const char *actor,
                                                int *http_status)
{
    sqlite3 *db = NULL;
    struct json_object *response = NULL;
    const char *tail;
    char id[TG_MAX_ID + 1] = "";

    if (http_status)
        *http_status = 200;
    if (!webd_terminal_groups_path(path) || tg_open(&db) != 0) {
        if (http_status)
            *http_status = 503;
        return tg_error("terminal_group_store_unavailable",
                        "terminal group store is unavailable", "config.db", 503);
    }
    tail = path + strlen(TG_BASE_PATH);
    if (!tail[0] && !strcmp(method, "GET")) {
        response = tg_envelope(tg_list_data(db, tg_query_true(query, "include_members", 1)),
                               "config.db:terminal_group");
    } else if (!tail[0] && !strcmp(method, "POST")) {
        response = tg_create_or_update(db, body, NULL, 0, actor, http_status);
    } else if (!strcmp(tail, "/import") && !strcmp(method, "POST")) {
        response = tg_import(db, body, actor, http_status);
    } else if (!strcmp(tail, "/export") && !strcmp(method, "GET")) {
        struct json_object *data = tg_list_data(db, 1);
        json_object_object_add(data, "schema",
                               json_object_new_string("dreamingwrt-terminal-groups-v1"));
        json_object_object_add(data, "exported_at", json_object_new_int64(tg_now()));
        response = tg_envelope(data, "config.db:terminal_group.export");
    } else if (tail[0] == '/' && !strchr(tail + 1, '/') && strlen(tail + 1) <= TG_MAX_ID) {
        snprintf(id, sizeof(id), "%s", tail + 1);
        if (!strcmp(method, "GET")) {
            struct json_object *group = tg_id_ok(id) ? tg_group_json(db, id, 1) : NULL;
            if (!group) {
                *http_status = 404;
                response = tg_error("terminal_group_not_found", "terminal group was not found", "id", 404);
            } else {
                response = tg_envelope(group, "config.db:terminal_group");
            }
        } else if (!strcmp(method, "PATCH") || !strcmp(method, "PUT")) {
            response = tg_create_or_update(db, body, id, 1, actor, http_status);
        } else if (!strcmp(method, "DELETE")) {
            response = tg_delete(db, id, actor, http_status);
        }
    }
    if (!response) {
        *http_status = 404;
        response = tg_error("terminal_group_route_not_found",
                            "terminal group route was not found", path, 404);
    }
    sqlite3_close(db);
    return response;
}

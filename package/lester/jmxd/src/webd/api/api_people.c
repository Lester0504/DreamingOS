// SPDX-License-Identifier: GPL-2.0-or-later
/* Local people are descriptive records, never authentication identities.
 * config.db is the sole store; MAC bindings describe current ownership only. */
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "api_people.h"
#include "api_error.h"
#include "api_json.h"
#include "../jmx_app_api.h"

extern sqlite3 *g_config_db;

int webd_people_init(sqlite3 *db)
{
    if (!db) return -1;
    return sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS local_person("
        "id TEXT PRIMARY KEY,name TEXT NOT NULL,created_at INTEGER NOT NULL,"
        "updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS local_person_device("
        "mac TEXT PRIMARY KEY COLLATE NOCASE,person_id TEXT NOT NULL,"
        "updated_at INTEGER NOT NULL,"
        "FOREIGN KEY(person_id) REFERENCES local_person(id) ON DELETE RESTRICT);"
        "CREATE INDEX IF NOT EXISTS local_person_device_person_idx "
        "ON local_person_device(person_id);", NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}

static const char *text_at(sqlite3_stmt *st, int col)
{
    const unsigned char *s = sqlite3_column_text(st, col);
    return s ? (const char *)s : "";
}

static void add_text(struct json_object *o, const char *key, const char *value)
{
    json_object_object_add(o, key, json_object_new_string(value));
}

static int person_id_valid(const char *s)
{
    if (!s || strlen(s) != 39 || strncmp(s, "person-", 7)) return 0;
    for (int i = 7; i < 39; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return 0;
    return 1;
}

static int normalize_mac(const char *s, char out[18])
{
    if (!s || strlen(s) != 17) return 0;
    for (int i = 0; i < 17; i++) {
        if (i % 3 == 2) {
            if (s[i] != ':') return 0;
            out[i] = ':';
        } else {
            if (!isxdigit((unsigned char)s[i])) return 0;
            out[i] = (char)tolower((unsigned char)s[i]);
        }
    }
    out[17] = 0;
    return 1;
}

static struct json_object *person_row(sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();
    add_text(o, "id", text_at(st, 0));
    add_text(o, "name", text_at(st, 1));
    json_object_object_add(o, "avatar_url", NULL);
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 2)));
    return o;
}

struct json_object *webd_people_for_mac(sqlite3 *db, const char *mac)
{
    struct json_object *out = json_object_new_object();
    sqlite3_stmt *st = NULL;
    char normalized[18];
    int rc = SQLITE_ERROR;
    add_text(out, "source", "local_person_device");
    add_text(out, "scope", "current_assignment");
    if (db && normalize_mac(mac, normalized) && sqlite3_prepare_v2(db,
        "SELECT p.id,p.name,p.updated_at FROM local_person_device d "
        "JOIN local_person p ON p.id=d.person_id WHERE d.mac=?", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, normalized, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            struct json_object *p = person_row(st);
            json_object_object_foreach(p, key, value)
                json_object_object_add(out, key, json_object_get(value));
            json_object_put(p);
        }
    }
    sqlite3_finalize(st);
    json_object_object_add(out, "available", json_object_new_boolean(rc == SQLITE_ROW));
    json_object_object_add(out, "supported", json_object_new_boolean(rc == SQLITE_ROW || rc == SQLITE_DONE));
    add_text(out, "reason", rc == SQLITE_ROW ? "" : rc == SQLITE_DONE ? "unassigned" : "person_store_unavailable");
    return out;
}

void webd_people_project_clients(struct json_object *response)
{
    struct json_object *data = NULL, *clients = NULL, *bindings = NULL;
    sqlite3_stmt *st = NULL;
    if (!response) return;
    if (!json_object_object_get_ex(response, "data", &data)) data = response;
    if (!json_object_object_get_ex(data, "clients", &clients) ||
        !json_object_is_type(clients, json_type_array)) return;
    bindings = json_object_new_object();
    int rc = SQLITE_ERROR;
    if (g_config_db && sqlite3_prepare_v2(g_config_db,
        "SELECT p.id,p.name,p.updated_at,d.mac FROM local_person_device d "
        "JOIN local_person p ON p.id=d.person_id", -1, &st, NULL) == SQLITE_OK) {
        while ((rc = sqlite3_step(st)) == SQLITE_ROW)
            json_object_object_add(bindings, text_at(st, 3), person_row(st));
    }
    sqlite3_finalize(st);
    for (size_t i = 0; i < json_object_array_length(clients); i++) {
        struct json_object *client = json_object_array_get_idx(clients, i), *mac = NULL, *person = NULL;
        char normalized[18];
        json_object_object_del(client, "person_id");
        json_object_object_del(client, "person_name");
        if (rc == SQLITE_DONE && json_object_object_get_ex(client, "mac", &mac) &&
            normalize_mac(json_object_get_string(mac), normalized) &&
            json_object_object_get_ex(bindings, normalized, &person)) {
            json_object_object_add(client, "person_id", json_object_get(json_object_object_get(person, "id")));
            json_object_object_add(client, "person_name", json_object_get(json_object_object_get(person, "name")));
        }
    }
    json_object_object_add(data, "person_directory_available", json_object_new_boolean(rc == SQLITE_DONE));
    json_object_put(bindings);
}

static struct json_object *people_error(struct jmx_api_ctx *ctx, int status, const char *code)
{
    ctx->status = status;
    return webd_error(code, code, "people", "webd.people");
}

static struct json_object *people_list(struct jmx_api_ctx *ctx, const char *id)
{
    sqlite3_stmt *st = NULL;
    struct json_object *data = json_object_new_object(), *items = json_object_new_array();
    const char *sql = id ?
        "SELECT p.id,p.name,p.updated_at,(SELECT count(*) FROM local_person_device d WHERE d.person_id=p.id) FROM local_person p WHERE p.id=?" :
        "SELECT p.id,p.name,p.updated_at,(SELECT count(*) FROM local_person_device d WHERE d.person_id=p.id) FROM local_person p ORDER BY p.name COLLATE NOCASE,p.id";
    int rc = g_config_db ? sqlite3_prepare_v2(g_config_db, sql, -1, &st, NULL) : SQLITE_ERROR;
    if (rc == SQLITE_OK) {
        if (id) sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            struct json_object *p = person_row(st);
            json_object_object_add(p, "device_count", json_object_new_int(sqlite3_column_int(st, 3)));
            json_object_array_add(items, p);
        }
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE || (id && !json_object_array_length(items))) {
        json_object_put(data); json_object_put(items);
        return people_error(ctx, rc == SQLITE_DONE ? 404 : 503,
            rc == SQLITE_DONE ? "person_not_found" : "person_store_unavailable");
    }
    json_object_object_add(data, "people", items);
    json_object_object_add(data, "can_write", json_object_new_boolean(jmx_perm_check(ctx->role, JMX_RISK_MEDIUM)));
    add_text(data, "source", "local_person_directory");
    add_text(data, "scope", "current_assignment");
    ctx->status = 200;
    return webd_envelope(data, "webd.people");
}

static int body_string(struct json_object *body, const char *key, char *out, size_t cap, int trim)
{
    struct json_object *value = NULL;
    if (!body || !json_object_is_type(body, json_type_object) ||
        json_object_object_length(body) != 1 || !json_object_object_get_ex(body, key, &value) ||
        !json_object_is_type(value, json_type_string)) return 0;
    const char *s = json_object_get_string(value);
    size_t n = (size_t)json_object_get_string_len(value);
    if (strlen(s) != n) return 0;
    if (trim) {
        while (n && isspace((unsigned char)*s)) { s++; n--; }
        while (n && isspace((unsigned char)s[n-1])) n--;
    }
    if (!n || n >= cap) return 0;
    for (size_t i = 0; i < n; i++) if ((unsigned char)s[i] < 32 || s[i] == 127) return 0;
    memcpy(out, s, n); out[n] = 0;
    return 1;
}

static struct json_object *people_route(struct jmx_api_ctx *ctx)
{
    const char *path = ctx->req->path, *method = ctx->req->method;
    const char *id = NULL, *binding = NULL;
    char mac[18] = "", name[129] = "", assigned[40] = "", created[40] = "";
    int read = !strcmp(method, "GET") || !strcmp(method, "HEAD");
    sqlite3_stmt *st = NULL;
    if (!jmx_perm_check(ctx->role, read ? JMX_RISK_LOW : JMX_RISK_MEDIUM))
        return people_error(ctx, 403, "forbidden");
    if (!strncmp(path, "/api/v1/people-bindings/", sizeof("/api/v1/people-bindings/") - 1)) {
        binding = path + sizeof("/api/v1/people-bindings/") - 1;
        if (!normalize_mac(binding, mac)) return people_error(ctx, 400, "invalid_mac");
    } else if (!strncmp(path, "/api/v1/people/", sizeof("/api/v1/people/") - 1)) {
        id = path + sizeof("/api/v1/people/") - 1;
        if (!person_id_valid(id)) return people_error(ctx, 404, "person_not_found");
    } else if (strcmp(path, "/api/v1/people")) {
        return people_error(ctx, 404, "resource_not_found");
    }
    if (read) {
        if (!binding) return people_list(ctx, id);
        struct json_object *p = webd_people_for_mac(g_config_db, mac);
        ctx->status = json_object_get_boolean(json_object_object_get(p, "supported")) ? 200 : 503;
        return webd_envelope(p, "webd.people");
    }
    int create = !binding && !id && !strcmp(method, "POST");
    int update = !strcmp(method, "PUT") && (binding || id);
    int remove = !strcmp(method, "DELETE") && (binding || id);
    if (!create && !update && !remove) return people_error(ctx, 405, "method_not_allowed");
    if ((create || (update && id)) && !body_string(ctx->body, "name", name, sizeof(name), 1))
        return people_error(ctx, 400, "invalid_person_name");
    if (update && binding && (!body_string(ctx->body, "person_id", assigned, sizeof(assigned), 0) || !person_id_valid(assigned)))
        return people_error(ctx, 400, "invalid_person_id");
    if (!g_config_db || sqlite3_exec(g_config_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        return people_error(ctx, 503, "person_store_unavailable");
    int status = 200, rc = SQLITE_ERROR;
    const char *error = "person_store_unavailable", *sql = NULL;
    if (remove && id) {
        if (sqlite3_prepare_v2(g_config_db,
            "SELECT 1 FROM local_person_device WHERE person_id=? LIMIT 1", -1, &st, NULL) != SQLITE_OK) goto rollback;
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) { status = 409; error = "person_has_devices"; goto rollback; }
        if (rc != SQLITE_DONE) goto rollback;
        sqlite3_finalize(st); st = NULL;
    }
    if (create) {
        if (sqlite3_prepare_v2(g_config_db,
            "SELECT 'person-'||lower(hex(randomblob(16))),count(*) FROM local_person", -1, &st, NULL) != SQLITE_OK ||
            sqlite3_step(st) != SQLITE_ROW) goto rollback;
        snprintf(created, sizeof(created), "%s", text_at(st, 0));
        if (sqlite3_column_int(st, 1) >= 1000) { status = 409; error = "person_limit_reached"; goto rollback; }
        sqlite3_finalize(st); st = NULL; id = created;
        sql = "INSERT INTO local_person(id,name,created_at,updated_at) VALUES(?,?,?,?)";
    } else if (update && id) sql = "UPDATE local_person SET name=?,updated_at=? WHERE id=?";
    else if (remove && id) sql = "DELETE FROM local_person WHERE id=?";
    else if (remove) sql = "DELETE FROM local_person_device WHERE mac=?";
    else sql = "INSERT INTO local_person_device(mac,person_id,updated_at) VALUES(?,?,?) "
        "ON CONFLICT(mac) DO UPDATE SET person_id=excluded.person_id,updated_at=excluded.updated_at";
    if (sqlite3_prepare_v2(g_config_db, sql, -1, &st, NULL) != SQLITE_OK) goto rollback;
    int64_t now = (int64_t)time(NULL) * 1000;
    if (create) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, now); sqlite3_bind_int64(st, 4, now);
    } else if (update && id) {
        sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, now); sqlite3_bind_text(st, 3, id, -1, SQLITE_TRANSIENT);
    } else if (remove) sqlite3_bind_text(st, 1, id ? id : mac, -1, SQLITE_TRANSIENT);
    else {
        sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, assigned, -1, SQLITE_TRANSIENT); sqlite3_bind_int64(st, 3, now);
    }
    rc = sqlite3_step(st);
    if (rc != SQLITE_DONE) {
        if (sqlite3_extended_errcode(g_config_db) == SQLITE_CONSTRAINT_FOREIGNKEY) {
            status = remove ? 409 : 404; error = remove ? "person_has_devices" : "person_not_found";
        }
        goto rollback;
    }
    if (id && !create && sqlite3_changes(g_config_db) == 0) { status = 404; error = "person_not_found"; goto rollback; }
    sqlite3_finalize(st); st = NULL;
    if (sqlite3_exec(g_config_db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) goto rollback;
    struct json_object *data = json_object_new_object();
    if (id) add_text(data, "id", id);
    if (binding) add_text(data, "mac", mac);
    add_text(data, "source", "local_person_directory");
    ctx->status = create ? 201 : 200;
    struct json_object *out = webd_envelope(data, "webd.people");
    jmx_app_audit_log_response(ctx->device_id, ctx->device_id,
        binding ? (remove ? "people.unbind" : "people.bind") : create ? "people.create" : remove ? "people.delete" : "people.rename",
        "medium", id ? id : mac, ctx->req->client_ip, out, ctx->status);
    return out;
rollback:
    sqlite3_finalize(st);
    sqlite3_exec(g_config_db, "ROLLBACK", NULL, NULL, NULL);
    return people_error(ctx, status == 200 ? 503 : status, error);
}

const struct jmx_api_route people_api_routes[] = {
    JMX_API_ROUTE(9624, "/api/v1/people", "GET,POST", JMX_API_EXACT, people_route),
    JMX_API_ROUTE(9625, "/api/v1/people/", "GET,PUT,DELETE", JMX_API_PREFIX, people_route),
    JMX_API_ROUTE(9626, "/api/v1/people-bindings/", "GET,PUT,DELETE", JMX_API_PREFIX, people_route),
    JMX_API_ROUTE_END
};

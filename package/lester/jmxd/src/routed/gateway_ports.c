// SPDX-License-Identifier: GPL-2.0-or-later
/* Revision-guarded gateway port assignment orchestration. */
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <json-c/json.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include <sqlite3.h>

#include "gateway_ports.h"

#define GP_DB_PATH "/etc/dreamingwrt/config.db"
#define GP_CORE_OBJECT "dreamingwrt"
#define GP_TIMEOUT_MS 30000
#define GP_MAX_PORTS 64

struct gp_call_result {
    struct json_object *json;
};

struct gp_snapshot {
    struct json_object *assignments;
    struct json_object *lan_owners;
    struct json_object *wans;
    int64_t revision;
    char state_digest[17];
};

static int64_t gp_now(void)
{
    return (int64_t)time(NULL);
}

static struct json_object *gp_error(const char *code, const char *message, int status)
{
    struct json_object *out = json_object_new_object();

    json_object_object_add(out, "ok", json_object_new_boolean(0));
    json_object_object_add(out, "error", json_object_new_string(code ? code : "error"));
    json_object_object_add(out, "message", json_object_new_string(message ? message : ""));
    json_object_object_add(out, "http_status", json_object_new_int(status));
    json_object_object_add(out, "source", json_object_new_string("dreamingwrt.routed"));
    json_object_object_add(out, "contract_version",
                           json_object_new_string("gateway-ports.v2"));
    json_object_object_add(out, "ts", json_object_new_int64(gp_now()));
    return out;
}

static struct json_object *gp_ok(void)
{
    struct json_object *out = json_object_new_object();

    json_object_object_add(out, "ok", json_object_new_boolean(1));
    json_object_object_add(out, "source", json_object_new_string("dreamingwrt.routed"));
    json_object_object_add(out, "contract_version",
                           json_object_new_string("gateway-ports.v2"));
    json_object_object_add(out, "ts", json_object_new_int64(gp_now()));
    return out;
}

static void gp_call_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct gp_call_result *result = req ? req->priv : NULL;
    char *text;

    (void)type;
    if (!result || !msg)
        return;
    text = blobmsg_format_json(msg, true);
    if (!text)
        return;
    result->json = json_tokener_parse(text);
    free(text);
}

static struct json_object *gp_core_call(const char *method, struct json_object *payload)
{
    struct ubus_context *ctx = NULL;
    struct gp_call_result result = {0};
    struct blob_buf buf = {0};
    const char *text = payload ?
        json_object_to_json_string_ext(payload, JSON_C_TO_STRING_PLAIN) : "{}";
    uint32_t object_id = 0;
    int rc;

    ctx = ubus_connect(NULL);
    if (!ctx || ubus_lookup_id(ctx, GP_CORE_OBJECT, &object_id) != UBUS_STATUS_OK)
        goto fail;
    blob_buf_init(&buf, 0);
    if (!blobmsg_add_json_from_string(&buf, text))
        goto fail_buf;
    rc = ubus_invoke(ctx, object_id, method, buf.head, gp_call_cb, &result,
                     GP_TIMEOUT_MS);
    blob_buf_free(&buf);
    ubus_free(ctx);
    if (rc == UBUS_STATUS_OK)
        return result.json;
    if (result.json)
        json_object_put(result.json);
    return NULL;

fail_buf:
    blob_buf_free(&buf);
fail:
    if (ctx)
        ubus_free(ctx);
    return NULL;
}

static struct json_object *gp_response_data(struct json_object *response)
{
    struct json_object *code = NULL, *data = NULL;

    if (!response || !json_object_object_get_ex(response, "code", &code) ||
        !code || json_object_get_int(code) != 2000 ||
        !json_object_object_get_ex(response, "data", &data) || !data)
        return NULL;
    return data;
}

static uint64_t gp_hash_update(uint64_t hash, const char *text)
{
    const unsigned char *p = (const unsigned char *)(text ? text : "");

    while (*p) {
        hash ^= *p++;
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static void gp_hash_text(uint64_t hash, char out[17])
{
    snprintf(out, 17, "%016" PRIx64, hash);
}

static int gp_exec(sqlite3 *db, const char *sql)
{
    char *error = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &error);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "[dreamingwrt-routed] gateway port sqlite: %s\n",
                error ? error : sqlite3_errmsg(db));
        sqlite3_free(error);
        return -1;
    }
    return 0;
}

static int gp_db_open(sqlite3 **out)
{
    sqlite3 *db = NULL;

    if (!out || sqlite3_open_v2(GP_DB_PATH, &db,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        return -1;
    }
    sqlite3_busy_timeout(db, 5000);
    if (gp_exec(db,
        "CREATE TABLE IF NOT EXISTS gateway_port_transaction_meta("
        "id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL DEFAULT 1,"
        "state_digest TEXT NOT NULL DEFAULT '',updated_at INTEGER NOT NULL DEFAULT 0);"
        "INSERT OR IGNORE INTO gateway_port_transaction_meta"
        "(id,revision,state_digest,updated_at) VALUES(1,1,'',0)") != 0) {
        sqlite3_close(db);
        return -1;
    }
    *out = db;
    return 0;
}

static void gp_snapshot_clear(struct gp_snapshot *snapshot)
{
    if (!snapshot)
        return;
    if (snapshot->assignments)
        json_object_put(snapshot->assignments);
    if (snapshot->lan_owners)
        json_object_put(snapshot->lan_owners);
    if (snapshot->wans)
        json_object_put(snapshot->wans);
    memset(snapshot, 0, sizeof(*snapshot));
}

static int gp_snapshot_load(sqlite3 *db, struct gp_snapshot *snapshot)
{
    sqlite3_stmt *st = NULL;
    uint64_t hash = UINT64_C(1469598103934665603);
    int rc;

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->assignments = json_object_new_object();
    snapshot->lan_owners = json_object_new_object();
    snapshot->wans = json_object_new_array();
    if (!snapshot->assignments || !snapshot->lan_owners || !snapshot->wans)
        goto fail;
    rc = sqlite3_prepare_v2(db,
        "SELECT id,COALESCE(device,''),enabled,COALESCE(name,''),COALESCE(role,'') "
        "FROM wan ORDER BY id", -1, &st, NULL);
    if (rc != SQLITE_OK)
        goto fail;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const char *id = (const char *)sqlite3_column_text(st, 0);
        const char *device = (const char *)sqlite3_column_text(st, 1);
        struct json_object *wan = json_object_new_object();
        char enabled[8];

        if (!id || !wan)
            goto fail;
        device = device ? device : "";
        snprintf(enabled, sizeof(enabled), "%d", sqlite3_column_int(st, 2));
        hash = gp_hash_update(hash, id);
        hash = gp_hash_update(hash, "=");
        hash = gp_hash_update(hash, device);
        hash = gp_hash_update(hash, "/");
        hash = gp_hash_update(hash, enabled);
        json_object_object_add(snapshot->assignments, id,
                               json_object_new_string(device));
        json_object_object_add(wan, "id", json_object_new_string(id));
        json_object_object_add(wan, "device", json_object_new_string(device));
        json_object_object_add(wan, "enabled",
                               json_object_new_boolean(sqlite3_column_int(st, 2)));
        json_object_object_add(wan, "name", json_object_new_string(
            sqlite3_column_text(st, 3) ? (const char *)sqlite3_column_text(st, 3) : ""));
        json_object_object_add(wan, "role", json_object_new_string(
            sqlite3_column_text(st, 4) ? (const char *)sqlite3_column_text(st, 4) : ""));
        json_object_array_add(snapshot->wans, wan);
    }
    sqlite3_finalize(st);
    st = NULL;
    if (rc != SQLITE_DONE)
        goto fail;
    rc = sqlite3_prepare_v2(db,
        "SELECT port,lan_id FROM lan_port ORDER BY port,lan_id", -1, &st, NULL);
    if (rc != SQLITE_OK)
        goto fail;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const char *port = (const char *)sqlite3_column_text(st, 0);
        const char *lan = (const char *)sqlite3_column_text(st, 1);
        struct json_object *existing = NULL;

        if (!port || !lan)
            continue;
        hash = gp_hash_update(hash, ";");
        hash = gp_hash_update(hash, port);
        hash = gp_hash_update(hash, "=");
        hash = gp_hash_update(hash, lan);
        if (!json_object_object_get_ex(snapshot->lan_owners, port, &existing))
            json_object_object_add(snapshot->lan_owners, port,
                                   json_object_new_string(lan));
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        goto fail;
    gp_hash_text(hash, snapshot->state_digest);
    return 0;

fail:
    sqlite3_finalize(st);
    gp_snapshot_clear(snapshot);
    return -1;
}

static int gp_revision_sync(sqlite3 *db, struct gp_snapshot *snapshot)
{
    sqlite3_stmt *st = NULL;
    char previous[17] = "";
    int64_t revision = 1;
    int rc = -1;

    if (gp_exec(db, "BEGIN IMMEDIATE") != 0)
        return -1;
    if (sqlite3_prepare_v2(db,
            "SELECT revision,state_digest FROM gateway_port_transaction_meta WHERE id=1",
            -1, &st, NULL) != SQLITE_OK || sqlite3_step(st) != SQLITE_ROW)
        goto done;
    revision = sqlite3_column_int64(st, 0);
    snprintf(previous, sizeof(previous), "%s",
             sqlite3_column_text(st, 1) ? (const char *)sqlite3_column_text(st, 1) : "");
    sqlite3_finalize(st);
    st = NULL;
    if (previous[0] && strcmp(previous, snapshot->state_digest))
        revision++;
    if (sqlite3_prepare_v2(db,
            "UPDATE gateway_port_transaction_meta SET revision=?1,state_digest=?2,"
            "updated_at=?3 WHERE id=1", -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_int64(st, 1, revision);
    sqlite3_bind_text(st, 2, snapshot->state_digest, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, gp_now());
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    sqlite3_finalize(st);
    st = NULL;
    if (gp_exec(db, "COMMIT") != 0)
        return -1;
    snapshot->revision = revision;
    return 0;

done:
    sqlite3_finalize(st);
    gp_exec(db, "ROLLBACK");
    return rc;
}

static int gp_state(sqlite3 **db_out, struct gp_snapshot *snapshot)
{
    sqlite3 *db = NULL;

    if (gp_db_open(&db) != 0 || gp_snapshot_load(db, snapshot) != 0 ||
        gp_revision_sync(db, snapshot) != 0) {
        if (db)
            sqlite3_close(db);
        gp_snapshot_clear(snapshot);
        return -1;
    }
    *db_out = db;
    return 0;
}

static struct json_object *gp_capabilities(int executor_available)
{
    struct json_object *caps = json_object_new_object();

    json_object_object_add(caps, "gateway_port_assignment_preview",
                           json_object_new_boolean(executor_available));
    json_object_object_add(caps, "gateway_port_assignment_atomic_apply",
                           json_object_new_boolean(executor_available));
    json_object_object_add(caps, "gateway_port_assignment_revision_guard",
                           json_object_new_boolean(1));
    json_object_object_add(caps, "gateway_port_assignment_plan_digest",
                           json_object_new_boolean(1));
    json_object_object_add(caps, "gateway_port_assignment_runtime_readback",
                           json_object_new_boolean(executor_available));
    json_object_object_add(caps, "gateway_port_assignment_rollback",
                           json_object_new_boolean(executor_available));
    if (!executor_available)
        json_object_object_add(caps, "reason",
            json_object_new_string("core_gateway_port_executor_unavailable"));
    return caps;
}

static struct json_object *gp_normalized_request(const struct gp_snapshot *snapshot,
                                                 struct json_object *body)
{
    struct json_object *requested = NULL, *migrations = NULL;
    struct json_object *normalized = json_object_new_object();
    struct json_object *assignments = json_object_new_object();
    struct json_object *ordered_migrations = json_object_new_array();
    int i, n;

    if (!body || !json_object_object_get_ex(body, "assignments", &requested) ||
        !requested || !json_object_is_type(requested, json_type_object))
        goto fail;
    n = (int)json_object_array_length(snapshot->wans);
    for (i = 0; i < n; i++) {
        struct json_object *wan = json_object_array_get_idx(snapshot->wans, i);
        struct json_object *value = NULL, *id_value = NULL;
        const char *id;

        if (!wan || !json_object_object_get_ex(wan, "id", &id_value) ||
            !id_value || !json_object_is_type(id_value, json_type_string))
            goto fail;
        id = json_object_get_string(id_value);

        if (!json_object_object_get_ex(requested, id, &value) || !value ||
            json_object_is_type(value, json_type_null))
            json_object_object_get_ex(snapshot->assignments, id, &value);
        if (!value || !json_object_is_type(value, json_type_string))
            goto fail;
        json_object_object_add(assignments, id, json_object_get(value));
    }
    if (json_object_object_get_ex(body, "migrations", &migrations) && migrations) {
        int used[GP_MAX_PORTS] = {0};

        if (!json_object_is_type(migrations, json_type_array) ||
            json_object_array_length(migrations) > GP_MAX_PORTS)
            goto fail;
        for (;;) {
            int best = -1;
            const char *best_name = NULL;
            int count = (int)json_object_array_length(migrations);

            for (i = 0; i < count; i++) {
                struct json_object *item = json_object_array_get_idx(migrations, i);
                struct json_object *name_obj = NULL;
                const char *name;

                if (used[i] || !item || !json_object_is_type(item, json_type_object) ||
                    !json_object_object_get_ex(item, "ifname", &name_obj) ||
                    !name_obj || !json_object_is_type(name_obj, json_type_string))
                    continue;
                name = json_object_get_string(name_obj);
                if (best < 0 || strcmp(name, best_name) < 0) {
                    best = i;
                    best_name = name;
                }
            }
            if (best < 0)
                break;
            used[best] = 1;
            json_object_array_add(ordered_migrations,
                                  json_object_get(json_object_array_get_idx(migrations, best)));
        }
    }
    json_object_object_add(normalized, "assignments", assignments);
    json_object_object_add(normalized, "migrations", ordered_migrations);
    return normalized;

fail:
    json_object_put(assignments);
    json_object_put(ordered_migrations);
    json_object_put(normalized);
    return NULL;
}

static void gp_plan_digest(int64_t revision, struct json_object *normalized,
                           struct json_object *changes, char out[17])
{
    char revision_text[32];
    uint64_t hash = UINT64_C(1469598103934665603);

    snprintf(revision_text, sizeof(revision_text), "%" PRId64, revision);
    hash = gp_hash_update(hash, revision_text);
    hash = gp_hash_update(hash, "|");
    hash = gp_hash_update(hash, json_object_to_json_string_ext(
        normalized, JSON_C_TO_STRING_PLAIN));
    hash = gp_hash_update(hash, "|");
    hash = gp_hash_update(hash, json_object_to_json_string_ext(
        changes, JSON_C_TO_STRING_PLAIN));
    gp_hash_text(hash, out);
}

static struct json_object *gp_preview_internal(struct json_object *body,
                                               struct gp_snapshot *snapshot,
                                               struct json_object **normalized_out)
{
    struct json_object *core = NULL, *data, *changes = NULL, *normalized = NULL;
    struct json_object *out;
    char digest[17];

    normalized = gp_normalized_request(snapshot, body);
    if (!normalized)
        return gp_error("invalid_request",
                        "assignments and migrations are invalid", 400);
    core = gp_core_call("gateway_ports_preview", body);
    data = gp_response_data(core);
    if (!data) {
        json_object_put(normalized);
        if (core)
            return core;
        return gp_error("source_unavailable",
                        "core gateway port executor is unavailable", 503);
    }
    if (!json_object_object_get_ex(data, "ready", &changes) ||
        !json_object_get_boolean(changes)) {
        json_object_put(normalized);
        return core;
    }
    if (!json_object_object_get_ex(data, "changes", &changes) || !changes) {
        json_object_put(normalized);
        json_object_put(core);
        return gp_error("invalid_executor_response",
                        "core preview did not return changes", 502);
    }
    gp_plan_digest(snapshot->revision, normalized, changes, digest);
    out = gp_ok();
    json_object_object_add(out, "ready", json_object_new_boolean(1));
    json_object_object_add(out, "expected_revision",
                           json_object_new_int64(snapshot->revision));
    json_object_object_add(out, "state_digest",
                           json_object_new_string(snapshot->state_digest));
    json_object_object_add(out, "plan_digest", json_object_new_string(digest));
    json_object_object_add(out, "plan", json_object_get(normalized));
    json_object_object_add(out, "changes", json_object_get(changes));
    json_object_object_add(out, "requires_confirm", json_object_new_boolean(1));
    json_object_object_add(out, "capabilities", gp_capabilities(1));
    if (normalized_out)
        *normalized_out = normalized;
    else
        json_object_put(normalized);
    json_object_put(core);
    return out;
}

struct json_object *gateway_ports_get(struct ubus_context *ctx)
{
    sqlite3 *db = NULL;
    struct gp_snapshot snapshot;
    struct json_object *core = NULL, *data = NULL, *out;

    (void)ctx;
    if (gp_state(&db, &snapshot) != 0)
        return gp_error("source_unavailable", "gateway port state is unavailable", 503);
    core = gp_core_call("gateway_ports_get", NULL);
    data = gp_response_data(core);
    if (!data) {
        sqlite3_close(db);
        gp_snapshot_clear(&snapshot);
        if (core)
            json_object_put(core);
        out = gp_error("source_unavailable",
                       "core gateway port executor is unavailable", 503);
        json_object_object_add(out, "capabilities", gp_capabilities(0));
        return out;
    }
    out = gp_ok();
    json_object_object_add(out, "revision", json_object_new_int64(snapshot.revision));
    json_object_object_add(out, "state_digest",
                           json_object_new_string(snapshot.state_digest));
    json_object_object_add(out, "assignments", json_object_get(snapshot.assignments));
    json_object_object_add(out, "wans", json_object_get(snapshot.wans));
    if (json_object_object_get_ex(data, "ports", &data) && data)
        json_object_object_add(out, "ports", json_object_get(data));
    else
        json_object_object_add(out, "ports", json_object_new_array());
    json_object_object_add(out, "capabilities", gp_capabilities(1));
    json_object_put(core);
    sqlite3_close(db);
    gp_snapshot_clear(&snapshot);
    return out;
}

struct json_object *gateway_ports_preview(struct ubus_context *ctx,
                                          struct json_object *body)
{
    sqlite3 *db = NULL;
    struct gp_snapshot snapshot;
    struct json_object *out;

    (void)ctx;
    if (gp_state(&db, &snapshot) != 0)
        return gp_error("source_unavailable", "gateway port state is unavailable", 503);
    out = gp_preview_internal(body, &snapshot, NULL);
    sqlite3_close(db);
    gp_snapshot_clear(&snapshot);
    return out;
}

static int gp_assignments_equal(struct json_object *expected, struct json_object *actual)
{
    if (!expected || !actual || !json_object_is_type(expected, json_type_object) ||
        !json_object_is_type(actual, json_type_object))
        return 0;
    json_object_object_foreach(expected, key, expected_value) {
        struct json_object *actual_value = NULL;
        if (!json_object_object_get_ex(actual, key, &actual_value) || !actual_value ||
            strcmp(json_object_get_string(expected_value),
                   json_object_get_string(actual_value)))
            return 0;
    }
    return 1;
}

static struct json_object *gp_rollback_payload(const struct gp_snapshot *before,
                                               struct json_object *current_assignments);

static int gp_response_applied(struct json_object *response)
{
    struct json_object *data = gp_response_data(response);
    struct json_object *applied = NULL;

    return data && json_object_object_get_ex(data, "applied", &applied) &&
           applied && json_object_get_boolean(applied);
}

static int gp_compensate(const struct gp_snapshot *before,
                         struct json_object *current_assignments,
                         struct json_object **rollback_detail)
{
    struct json_object *empty = NULL;
    struct json_object *payload;
    struct json_object *apply;
    struct json_object *readback;
    struct json_object *readback_data;
    struct json_object *actual = NULL;
    int ok;

    if (!current_assignments) {
        empty = json_object_new_object();
        current_assignments = empty;
    }
    payload = gp_rollback_payload(before, current_assignments);
    apply = gp_core_call("gateway_ports_apply", payload);
    json_object_put(payload);
    if (empty)
        json_object_put(empty);
    if (!gp_response_applied(apply)) {
        if (rollback_detail)
            *rollback_detail = apply;
        else if (apply)
            json_object_put(apply);
        return 0;
    }
    readback = gp_core_call("gateway_ports_get", NULL);
    readback_data = gp_response_data(readback);
    if (readback_data)
        json_object_object_get_ex(readback_data, "assignments", &actual);
    ok = gp_assignments_equal(before->assignments, actual);
    if (rollback_detail) {
        struct json_object *detail = json_object_new_object();
        json_object_object_add(detail, "apply", apply ? apply : json_object_new_object());
        json_object_object_add(detail, "readback",
                               readback ? readback : json_object_new_object());
        json_object_object_add(detail, "verified", json_object_new_boolean(ok));
        *rollback_detail = detail;
    } else {
        if (apply) json_object_put(apply);
        if (readback) json_object_put(readback);
    }
    return ok;
}

static struct json_object *gp_rollback_payload(const struct gp_snapshot *before,
                                               struct json_object *current_assignments)
{
    struct json_object *payload = json_object_new_object();
    struct json_object *migrations = json_object_new_array();

    json_object_object_foreach(current_assignments, ignored_wan, current_port) {
        struct json_object *old_owner = NULL;
        int previously_wan = 0;

        (void)ignored_wan;
        json_object_object_foreach(before->assignments, old_wan, old_port) {
            (void)old_wan;
            if (!strcmp(json_object_get_string(old_port),
                        json_object_get_string(current_port))) {
                previously_wan = 1;
                break;
            }
        }
        if (!previously_wan &&
            json_object_object_get_ex(before->lan_owners,
                                      json_object_get_string(current_port), &old_owner) &&
            old_owner) {
            struct json_object *migration = json_object_new_object();
            json_object_object_add(migration, "ifname", json_object_get(current_port));
            json_object_object_add(migration, "target_owner_type",
                                   json_object_new_string("lan"));
            json_object_object_add(migration, "target_owner_id",
                                   json_object_get(old_owner));
            json_object_array_add(migrations, migration);
        }
    }
    json_object_object_add(payload, "assignments", json_object_get(before->assignments));
    json_object_object_add(payload, "migrations", migrations);
    json_object_object_add(payload, "confirm", json_object_new_boolean(1));
    return payload;
}

struct json_object *gateway_ports_apply(struct ubus_context *ctx,
                                        struct json_object *body)
{
    sqlite3 *db = NULL;
    struct gp_snapshot before, current, after;
    struct json_object *preview = NULL, *normalized = NULL, *expected_assignments = NULL;
    struct json_object *core = NULL, *core_data = NULL, *readback = NULL, *readback_data = NULL;
    struct json_object *actual_assignments = NULL, *rollback = NULL;
    struct json_object *out;
    struct json_object *value = NULL, *submitted_plan = NULL, *execute = NULL;
    const char *provided_digest = "", *computed_digest = "";
    int64_t expected_revision = 0;
    int rollback_ok = 0;

    (void)ctx;
    if (!body || !json_object_is_type(body, json_type_object))
        return gp_error("invalid_request", "request body must be an object", 400);
    if (!json_object_object_get_ex(body, "expected_revision", &value) || !value ||
        !json_object_is_type(value, json_type_int) ||
        (expected_revision = json_object_get_int64(value)) < 1)
        return gp_error("expected_revision_required",
                        "expected_revision is required", 422);
    if (!json_object_object_get_ex(body, "plan_digest", &value) || !value ||
        !json_object_is_type(value, json_type_string) ||
        !(provided_digest = json_object_get_string(value))[0])
        return gp_error("plan_digest_required", "plan_digest is required", 422);
    if (!json_object_object_get_ex(body, "plan", &submitted_plan) || !submitted_plan ||
        !json_object_is_type(submitted_plan, json_type_object))
        return gp_error("plan_required",
                        "the canonical plan returned by preview is required", 422);
    if (!json_object_object_get_ex(body, "confirm", &value) || !value ||
        !json_object_get_boolean(value))
        return gp_error("confirmation_required", "confirm=true is required", 409);
    if (gp_state(&db, &before) != 0)
        return gp_error("source_unavailable", "gateway port state is unavailable", 503);
    if (expected_revision != before.revision) {
        out = gp_error("revision_conflict",
                       "gateway port assignments changed after preview", 409);
        json_object_object_add(out, "expected_revision",
                               json_object_new_int64(expected_revision));
        json_object_object_add(out, "current_revision",
                               json_object_new_int64(before.revision));
        goto done;
    }
    preview = gp_preview_internal(submitted_plan, &before, &normalized);
    if (!preview || !json_object_object_get_ex(preview, "ok", &value) ||
        !json_object_get_boolean(value)) {
        out = preview ? json_object_get(preview) :
            gp_error("preview_failed", "gateway port preview failed", 409);
        goto done;
    }
    if (!json_object_object_get_ex(preview, "plan_digest", &value) || !value ||
        !json_object_is_type(value, json_type_string)) {
        out = gp_error("invalid_preview", "preview omitted plan_digest", 502);
        goto done;
    }
    computed_digest = json_object_get_string(value);
    if (!computed_digest || strcmp(provided_digest, computed_digest)) {
        out = gp_error("plan_conflict",
                       "submitted plan does not match current preview", 409);
        json_object_object_add(out, "current_plan_digest",
                               json_object_new_string(computed_digest ? computed_digest : ""));
        goto done;
    }
    if (!json_object_equal(submitted_plan, normalized)) {
        out = gp_error("plan_not_canonical",
                       "submitted plan differs from the canonical preview plan", 409);
        goto done;
    }
    memset(&current, 0, sizeof(current));
    if (gp_snapshot_load(db, &current) != 0 || gp_revision_sync(db, &current) != 0) {
        gp_snapshot_clear(&current);
        out = gp_error("source_unavailable",
                       "gateway port state could not be rechecked before apply", 503);
        goto done;
    }
    if (current.revision != before.revision ||
        strcmp(current.state_digest, before.state_digest)) {
        out = gp_error("revision_conflict",
                       "gateway port assignments changed before apply", 409);
        json_object_object_add(out, "expected_revision",
                               json_object_new_int64(before.revision));
        json_object_object_add(out, "current_revision",
                               json_object_new_int64(current.revision));
        gp_snapshot_clear(&current);
        goto done;
    }
    gp_snapshot_clear(&current);
    json_object_object_get_ex(normalized, "assignments", &expected_assignments);
    execute = json_object_get(normalized);
    json_object_object_add(execute, "confirm", json_object_new_boolean(1));
    core = gp_core_call("gateway_ports_apply", execute);
    core_data = gp_response_data(core);
    if (!core_data || !json_object_object_get_ex(core_data, "applied", &value) ||
        !json_object_get_boolean(value)) {
        out = core ? json_object_get(core) :
            gp_error("source_unavailable", "gateway port executor is unavailable", 503);
        goto done;
    }
    readback = gp_core_call("gateway_ports_get", NULL);
    readback_data = gp_response_data(readback);
    if (readback_data)
        json_object_object_get_ex(readback_data, "assignments", &actual_assignments);
    if (!gp_assignments_equal(expected_assignments, actual_assignments)) {
        rollback_ok = gp_compensate(&before, actual_assignments, &rollback);
        out = gp_error(rollback_ok ? "runtime_readback_mismatch" :
                                    "runtime_readback_and_rollback_failed",
            rollback_ok ? "runtime readback differed; previous assignments were restored" :
                          "runtime readback differed and compensating rollback failed",
            rollback_ok ? 502 : 500);
        json_object_object_add(out, "applied", json_object_new_boolean(0));
        json_object_object_add(out, "rolled_back", json_object_new_boolean(rollback_ok));
        if (readback_data)
            json_object_object_add(out, "readback", json_object_get(readback_data));
        goto done;
    }
    memset(&after, 0, sizeof(after));
    if (gp_snapshot_load(db, &after) != 0 || gp_revision_sync(db, &after) != 0) {
        gp_snapshot_clear(&after);
        rollback_ok = gp_compensate(&before, actual_assignments, &rollback);
        out = gp_error(rollback_ok ? "post_commit_revision_failed" :
                                    "post_commit_revision_and_rollback_failed",
            rollback_ok ? "revision persistence failed; previous assignments were restored" :
                          "revision persistence failed and compensating rollback failed",
            500);
        json_object_object_add(out, "applied", json_object_new_boolean(0));
        json_object_object_add(out, "rolled_back", json_object_new_boolean(rollback_ok));
        goto done;
    }
    out = gp_ok();
    json_object_object_add(out, "applied", json_object_new_boolean(1));
    json_object_object_add(out, "rolled_back", json_object_new_boolean(0));
    json_object_object_add(out, "previous_revision",
                           json_object_new_int64(before.revision));
    json_object_object_add(out, "revision", json_object_new_int64(after.revision));
    json_object_object_add(out, "plan_digest", json_object_new_string(provided_digest));
    json_object_object_add(out, "readback", json_object_get(readback_data));
    json_object_object_add(out, "capabilities", gp_capabilities(1));
    gp_snapshot_clear(&after);

done:
    if (execute) json_object_put(execute);
    if (rollback) json_object_put(rollback);
    if (readback) json_object_put(readback);
    if (core) json_object_put(core);
    if (normalized) json_object_put(normalized);
    if (preview) json_object_put(preview);
    sqlite3_close(db);
    gp_snapshot_clear(&before);
    return out;
}

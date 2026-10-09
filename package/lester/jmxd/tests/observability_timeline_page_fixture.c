/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/jmx_observability.h"

struct ubus_context;
struct ubus_object;
struct ubus_request_data;
struct blob_attr;
#define JMX_NETCONFIG_DB_PATH_DEFAULT "/nonexistent-observability-page-fixture.db"

static sqlite3 *fixture_db;
static struct json_object *fixture_payload, *fixture_response;
static char *fixture_query;
static int fixture_rows;

static sqlite3 *jmx_db_handle(void) { return fixture_db; }
static struct json_object *dw_parse_payload(struct blob_attr *msg, char **raw,
                                            struct json_object **in)
{
    (void)msg;
    *raw = NULL;
    *in = json_object_get(fixture_payload);
    return *in;
}
static int64_t dw_json_get_int64(struct json_object *obj, const char *key, int64_t fallback)
{
    struct json_object *value = NULL;
    return json_object_object_get_ex(obj, key, &value) ?
        json_object_get_int64(value) : fallback;
}
static const char *dw_json_get_string(struct json_object *obj, const char *key,
                                       const char *fallback)
{
    struct json_object *value = NULL;
    return json_object_object_get_ex(obj, key, &value) ?
        json_object_get_string(value) : fallback;
}
static void dw_send_json(struct ubus_context *ctx, struct ubus_request_data *req,
                         struct json_object *response)
{
    (void)ctx; (void)req;
    fixture_response = json_object_get(response);
}

#include "observability_timeline_handler.inc"

static int record_query(unsigned type, void *unused, void *statement, void *detail)
{
    sqlite3_stmt *st = statement;
    const char *sql = sqlite3_sql(st);
    (void)unused; (void)detail;
    if (sql && !strncmp(sql, "SELECT event_id,schema_version", 29)) {
        if (type == SQLITE_TRACE_STMT) {
            sqlite3_free(fixture_query);
            fixture_query = sqlite3_expanded_sql(st);
        } else if (type == SQLITE_TRACE_ROW) fixture_rows++;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct json_object *output;
    if (argc != 4 || sqlite3_open(argv[1], &fixture_db) != SQLITE_OK) return 2;
    fixture_payload = json_tokener_parse(argv[2]);
    if (!fixture_payload) return 3;
    if (jmx_obs_event_store_init(fixture_db) != 0) return 4;
    sqlite3_trace_v2(fixture_db, SQLITE_TRACE_STMT | SQLITE_TRACE_ROW, record_query, NULL);
    if (!strcmp(argv[3], "page")) {
        struct jmx_obs_retention_profile profile;
        struct json_object *cursor = json_object_object_get(fixture_payload, "cursor");
        jmx_obs_retention_profile_default(&profile);
        fixture_response = jmx_obs_event_timeline_page(fixture_db,
            dw_json_get_int64(fixture_payload, "start", 0),
            dw_json_get_int64(fixture_payload, "end", 0),
            dw_json_get_string(fixture_payload, "entity_type", ""),
            dw_json_get_string(fixture_payload, "entity_id", ""), &profile,
            (int)dw_json_get_int64(fixture_payload, "limit", 0),
            dw_json_get_int64(cursor, "first_seen", 0),
            dw_json_get_string(cursor, "event_id", NULL));
    } else if (!strcmp(argv[3], "prune")) {
        struct jmx_obs_retention_profile profile;
        jmx_obs_retention_profile_default(&profile);
        if (jmx_obs_event_prune(fixture_db,
            dw_json_get_int64(fixture_payload, "now", 0), &profile) < 0) return 5;
        fixture_response = json_object_new_object();
    } else {
        dw_handle_observability_timeline(NULL, NULL, NULL, "observability_timeline", NULL);
    }
    output = json_object_new_object();
    json_object_object_add(output, "result", fixture_response);
    json_object_object_add(output, "query", fixture_query ?
        json_object_new_string(fixture_query) : NULL);
    json_object_object_add(output, "rows_read", json_object_new_int(fixture_rows));
    puts(json_object_to_json_string_ext(output, JSON_C_TO_STRING_PLAIN));
    sqlite3_free(fixture_query);
    json_object_put(output);
    json_object_put(fixture_payload);
    sqlite3_close(fixture_db);
    return 0;
}

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <json-c/json.h>
#include <sqlite3.h>

#include "client_protocol_history.h"

static void exec_sql(sqlite3 *db, const char *sql)
{
    char *error = NULL;

    if (sqlite3_exec(db, sql, NULL, NULL, &error) != SQLITE_OK) {
        fprintf(stderr, "sqlite: %s\n", error ? error : "unknown");
        sqlite3_free(error);
        exit(2);
    }
}

static struct json_object *field(struct json_object *object, const char *name)
{
    struct json_object *value = NULL;

    assert(json_object_object_get_ex(object, name, &value));
    return value;
}

static struct json_object *find_item(struct json_object *points, int64_t ts, int app_id)
{
    int i;

    for (i = 0; i < (int)json_object_array_length(points); i++) {
        struct json_object *point = json_object_array_get_idx(points, i);
        struct json_object *items;
        int j;

        if (json_object_get_int64(field(point, "ts")) != ts)
            continue;
        items = field(point, "items");
        for (j = 0; j < (int)json_object_array_length(items); j++) {
            struct json_object *item = json_object_array_get_idx(items, j);

            if (json_object_get_int(field(item, "app_id")) == app_id)
                return item;
        }
    }
    return NULL;
}

static void add_dense_samples(sqlite3 *db)
{
    sqlite3_stmt *statement = NULL;
    int i;

    assert(sqlite3_prepare_v2(db,
        "INSERT INTO audit_flow_sample VALUES(?1,'dense-flow','tcp','tcp','https',"
        "404,'Dense','dense.example','',?2,?3,'22:33:44:55:66:77')",
        -1, &statement, NULL) == SQLITE_OK);
    for (i = 0; i <= 80; i++) {
        sqlite3_bind_int64(statement, 1, 1700 + (i * 3));
        sqlite3_bind_int64(statement, 2, 1000 + (i * 300));
        sqlite3_bind_int64(statement, 3, 2000 + (i * 600));
        assert(sqlite3_step(statement) == SQLITE_DONE);
        sqlite3_reset(statement);
        sqlite3_clear_bindings(statement);
    }
    sqlite3_finalize(statement);
}

int main(void)
{
    char path[] = "/tmp/client-protocol-history-XXXXXX";
    sqlite3 *db = NULL;
    struct json_object *result;
    struct json_object *points;
    struct json_object *fallback;
    struct json_object *item;
    int fd = mkstemp(path);

    assert(fd >= 0);
    close(fd);
    assert(sqlite3_open(path, &db) == SQLITE_OK);
    exec_sql(db,
        "CREATE TABLE audit_flow_sample ("
        "ts INTEGER,flow_id TEXT,protocol TEXT,proto TEXT,service TEXT,"
        "destination_app_id INTEGER,destination_app_name TEXT,"
        "destination_host TEXT,host TEXT,tx_bytes INTEGER,rx_bytes INTEGER,client_mac TEXT)");
    exec_sql(db,
        "INSERT INTO audit_flow_sample VALUES"
        "(700,'flow-a','tcp','tcp','https',101,'Video','video.example', '',1000,2000,'aa:bb:cc:dd:ee:ff'),"
        "(760,'flow-a','tcp','tcp','https',101,'Video','video.example', '',7000,14000,'aa:bb:cc:dd:ee:ff'),"
        "(820,'flow-a','tcp','tcp','https',101,'Video','video.example', '',10000,20000,'aa:bb:cc:dd:ee:ff'),"
        "(760,'flow-b','udp','udp','quic',202,'Chat','chat.example', '',500,1000,'aa:bb:cc:dd:ee:ff'),"
        "(820,'flow-b','udp','udp','quic',202,'Chat','chat.example', '',1700,2800,'aa:bb:cc:dd:ee:ff'),"
        "(880,'flow-a','tcp','tcp','https',101,'Video','video.example', '',50,70,'aa:bb:cc:dd:ee:ff'),"
        "(820,'other','tcp','tcp','https',303,'Other','other.example','',9999,9999,'11:22:33:44:55:66')");
    add_dense_samples(db);
    sqlite3_close(db);

    result = jmx_client_protocol_history_query(path, "AA:BB:CC:DD:EE:FF", 900, 300);
    assert(!json_object_get_boolean(field(result, "available")));
    assert(!json_object_get_boolean(field(result, "supported")));
    assert(!json_object_get_boolean(field(result, "complete")));
    assert(!json_object_get_boolean(field(result, "first_sample_counted")));
    assert(!json_object_get_boolean(field(result, "counter_reset_counted")));
    fallback = field(result, "fallback");
    assert(json_object_get_boolean(field(fallback, "available")));
    assert(!json_object_get_boolean(field(fallback, "supported")));
    points = field(fallback, "points");
    assert(json_object_array_length(points) == 2);

    item = find_item(points, 760, 101);
    assert(item);
    assert(json_object_get_int64(field(item, "up_rate")) == 100);
    assert(json_object_get_int64(field(item, "down_rate")) == 200);
    item = find_item(points, 820, 101);
    assert(item);
    assert(json_object_get_int64(field(item, "up_rate")) == 50);
    assert(json_object_get_int64(field(item, "down_rate")) == 100);
    item = find_item(points, 820, 202);
    assert(item);
    assert(json_object_get_int64(field(item, "up_rate")) == 20);
    assert(json_object_get_int64(field(item, "down_rate")) == 30);
    assert(find_item(points, 880, 101) == NULL);
    json_object_put(result);

    result = jmx_client_protocol_history_query(path, "22:33:44:55:66:77", 2000, 300);
    assert(!json_object_get_boolean(field(result, "supported")));
    fallback = field(result, "fallback");
    assert(json_object_get_boolean(field(fallback, "available")));
    points = field(fallback, "points");
    assert(json_object_array_length(points) == JMX_CLIENT_PROTOCOL_HISTORY_MAX_POINTS);
    assert(json_object_get_int64(field(json_object_array_get_idx(points, 0), "ts")) == 1727);
    assert(json_object_get_int64(field(json_object_array_get_idx(
        points, JMX_CLIENT_PROTOCOL_HISTORY_MAX_POINTS - 1), "ts")) == 1940);
    json_object_put(result);

    result = jmx_client_protocol_history_query(path, "invalid", 900, 300);
    assert(!json_object_get_boolean(field(result, "supported")));
    assert(!strcmp(json_object_get_string(field(result, "reason")), "invalid_client_mac"));
    json_object_put(result);
    unlink(path);
    puts("ok: client protocol history runtime fixture");
    return 0;
}

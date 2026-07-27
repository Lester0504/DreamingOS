// SPDX-License-Identifier: GPL-2.0-or-later
#include "jmx_topology_history.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sqlite3.h>

static struct json_object *make_snapshot(int online, int64_t up_rate)
{
    struct json_object *root = json_object_new_object();
    struct json_object *infra = json_object_new_object();
    struct json_object *gateways = json_object_new_array();
    struct json_object *clients = json_object_new_array();
    struct json_object *wans = json_object_new_array();
    struct json_object *links = json_object_new_array();
    struct json_object *ports = json_object_new_array();
    struct json_object *client = json_object_new_object();

    json_object_object_add(root, "ts", json_object_new_int64(1000 + up_rate));
    json_object_object_add(client, "id", json_object_new_string("client:1"));
    json_object_object_add(client, "mac", json_object_new_string("00:11:22:33:44:55"));
    json_object_object_add(client, "name", json_object_new_string("test-client"));
    json_object_object_add(client, "state", json_object_new_string(online ? "online" : "offline"));
    json_object_object_add(client, "up_rate", json_object_new_int64(up_rate));
    json_object_object_add(client, "updated_at", json_object_new_int64(1000 + up_rate));
    json_object_array_add(clients, client);
    json_object_object_add(infra, "gateways", gateways);
    json_object_object_add(infra, "clients", clients);
    json_object_object_add(infra, "switches", json_object_new_array());
    json_object_object_add(infra, "aps", json_object_new_array());
    json_object_object_add(infra, "wans", wans);
    json_object_object_add(infra, "links", links);
    json_object_object_add(infra, "ports", ports);
    json_object_object_add(root, "infrastructure", infra);
    return root;
}

static struct json_object *field(struct json_object *obj, const char *key)
{
    struct json_object *value = NULL;

    assert(obj != NULL);
    assert(json_object_object_get_ex(obj, key, &value));
    assert(value != NULL);
    return value;
}

int main(void)
{
    const char *db = "/tmp/dreamingwrt-topology-history-test.db";
    char sidecar[256];
    struct json_object *snapshot;
    struct json_object *result = NULL;
    struct json_object *timestamps;
    struct json_object *timeline;
    struct json_object *at;
    struct json_object *infra;
    struct json_object *clients;
    int64_t first_ts;
    int64_t second_ts;

    snprintf(sidecar, sizeof(sidecar), "%s-wal", db); unlink(sidecar);
    snprintf(sidecar, sizeof(sidecar), "%s-shm", db); unlink(sidecar);
    unlink(db);
    assert(setenv("DREAMINGWRT_TOPOLOGY_HISTORY_DB", db, 1) == 0);

    snapshot = make_snapshot(1, 10);
    assert(jmx_topology_history_capture(snapshot, 0, &result) == 0);
    assert(json_object_get_boolean(field(result, "captured")));
    assert(json_object_get_int(field(result, "events_created")) == 0);
    first_ts = json_object_get_int64(field(result, "timestamp"));
    json_object_put(result); result = NULL;
    json_object_put(snapshot);

    snapshot = make_snapshot(1, 999999);
    assert(jmx_topology_history_capture(snapshot, 0, &result) == 0);
    assert(!json_object_get_boolean(field(result, "captured")));
    assert(!strcmp(json_object_get_string(field(result, "reason")),
                   "unchanged_before_anchor"));
    json_object_put(result); result = NULL;
    json_object_put(snapshot);

    snapshot = make_snapshot(0, 123456);
    assert(jmx_topology_history_capture(snapshot, 0, &result) == 0);
    assert(json_object_get_boolean(field(result, "captured")));
    assert(json_object_get_int(field(result, "events_created")) == 1);
    second_ts = json_object_get_int64(field(result, "timestamp"));
    assert(second_ts > first_ts);
    json_object_put(result); result = NULL;
    json_object_put(snapshot);

    timestamps = jmx_topology_history_timestamps(first_ts - 1, second_ts + 1);
    assert(json_object_array_length(field(timestamps, "timestamps")) == 2);
    json_object_put(timestamps);

    timeline = jmx_topology_history_timeline(first_ts - 1, second_ts + 1);
    assert(json_object_array_length(field(timeline, "events")) == 1);
    assert(!strcmp(json_object_get_string(field(
        json_object_array_get_idx(field(timeline, "events"), 0), "type")),
        "DEVICE_OFFLINE"));
    json_object_put(timeline);

    at = jmx_topology_history_at(first_ts);
    assert(json_object_get_int64(field(at, "resolved_timestamp")) == first_ts);
    infra = field(at, "infrastructure");
    clients = field(infra, "clients");
    assert(json_object_array_length(clients) == 1);
    assert(!strcmp(json_object_get_string(field(json_object_array_get_idx(clients, 0), "state")),
                   "online"));
    assert(json_object_get_int64(field(json_object_array_get_idx(clients, 0), "up_rate")) == 10);
    json_object_put(at);

    /* Age the existing rows out, then ensure the next write prunes both tables. */
    jmx_topology_history_close();
    {
        sqlite3 *sql = NULL;
        char *error = NULL;

        assert(sqlite3_open(db, &sql) == SQLITE_OK);
        assert(sqlite3_exec(sql,
            "UPDATE topology_snapshots SET ts_ms=ts_ms-90000000;"
            "UPDATE topology_events SET timestamp_ms=timestamp_ms-90000000",
            NULL, NULL, &error) == SQLITE_OK);
        sqlite3_free(error);
        sqlite3_close(sql);
    }
    snapshot = make_snapshot(1, 42);
    assert(jmx_topology_history_capture(snapshot, 0, &result) == 0);
    assert(json_object_get_boolean(field(result, "captured")));
    assert(json_object_get_int(field(result, "pruned_rows")) >= 3);
    json_object_put(result); result = NULL;
    json_object_put(snapshot);
    timestamps = jmx_topology_history_timestamps(1, (int64_t)time(NULL) * 1000LL + 1000);
    assert(json_object_array_length(field(timestamps, "timestamps")) == 1);
    json_object_put(timestamps);
    timeline = jmx_topology_history_timeline(1, (int64_t)time(NULL) * 1000LL + 1000);
    assert(json_object_array_length(field(timeline, "events")) == 1);
    assert(!strcmp(json_object_get_string(field(
        json_object_array_get_idx(field(timeline, "events"), 0), "type")),
        "DEVICE_ONLINE"));
    json_object_put(timeline);

    jmx_topology_history_close();
    snprintf(sidecar, sizeof(sidecar), "%s-wal", db); unlink(sidecar);
    snprintf(sidecar, sizeof(sidecar), "%s-shm", db); unlink(sidecar);
    unlink(db);
    puts("topology_history_test: PASS");
    return 0;
}

#!/usr/bin/env python3
"""Run global mute and trigger summaries through the real notifyd DB code."""

from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
from pathlib import Path

from test_notify_settings_trigger_compile import STUBS


ROOT = Path(__file__).resolve().parents[2]

HARNESS = r'''
#define notifyd_now_s notifyd_host_now_s
#include "notifyd_common.c"
#undef notifyd_now_s

#undef NOTIFYD_DB_PATH
#undef NOTIFYD_CONFIG_DB_PATH
#define NOTIFYD_DB_PATH TEST_NOTIFY_DB
#define NOTIFYD_CONFIG_DB_PATH TEST_CONFIG_DB

static int64_t fixture_now = 1700000000;
int64_t notifyd_now_s(void) { return fixture_now; }

char *blobmsg_format_json(struct blob_attr *msg, bool list)
{
    (void)msg; (void)list;
    return NULL;
}

enum jmx_storage_pressure jmx_storage_guard_evaluate(
    uint64_t total_bytes, uint64_t available_bytes,
    struct jmx_storage_guard_state *state)
{
    (void)total_bytes; (void)available_bytes; (void)state;
    return JMX_STORAGE_PRESSURE_OK;
}
int jmx_storage_guard_check(const char *path, struct jmx_storage_guard_state *state)
{
    (void)path;
    if (state) {
        memset(state, 0, sizeof(*state));
        state->pressure = JMX_STORAGE_PRESSURE_OK;
        snprintf(state->reason, sizeof(state->reason), "%s", "ok");
    }
    return 0;
}
int jmx_storage_guard_allow(const char *path,
                            enum jmx_storage_write_priority priority,
                            struct jmx_storage_guard_state *state)
{
    (void)path; (void)priority; (void)state;
    return 1;
}
void jmx_storage_guard_get_stats(struct jmx_storage_guard_stats *stats)
{
    if (stats) memset(stats, 0, sizeof(*stats));
}
const char *jmx_storage_pressure_name(enum jmx_storage_pressure pressure)
{
    (void)pressure;
    return "ok";
}

#include "notifyd_db.c"

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

static struct json_object *parse(const char *text)
{
    struct json_object *o = json_tokener_parse(text);
    if (!o || !json_object_is_type(o, json_type_object)) {
        fprintf(stderr, "invalid fixture json: %s\n", text);
        exit(1);
    }
    return o;
}

static int64_t scalar(const char *sql)
{
    sqlite3_stmt *st = notifyd_prepare(sql);
    int64_t value = -1;
    CHECK(st);
    if (sqlite3_step(st) == SQLITE_ROW) value = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return value;
}

static struct json_object *find_route(struct json_object *resp, const char *id)
{
    struct json_object *routes = NULL;
    size_t i;
    if (!json_object_object_get_ex(resp, "routes", &routes))
        return NULL;
    for (i = 0; i < json_object_array_length(routes); i++) {
        struct json_object *route = json_object_array_get_idx(routes, i);
        if (!strcmp(notifyd_json_str(route, "id", ""), id)) return route;
    }
    return NULL;
}

int main(void)
{
    struct json_object *request, *response, *mute, *capabilities, *items, *route;
    struct json_object *event_request;
    struct json_object *page, *next_page;
    const char *cursor;
    sqlite3_stmt *st;
    char delivery_sql[512];

    CHECK(notifyd_db_init() == 0);
    CHECK(sqlite3_exec(g_notify_config_db,
        "CREATE TABLE system_settings(id INTEGER PRIMARY KEY, timezone TEXT NOT NULL);"
        "INSERT INTO system_settings(id,timezone) VALUES(1,'UTC')",
        NULL, NULL, NULL) == SQLITE_OK);

    response = notifyd_settings_json();
    CHECK(notifyd_json_bool(response, "ok", 0));
    CHECK(json_object_object_get_ex(response, "mute_schedule", &mute));
    CHECK(!notifyd_json_bool(mute, "enabled", 1));
    CHECK(json_object_object_get_ex(mute, "timezone", &capabilities));
    CHECK(json_object_object_get_ex(mute, "windows", &capabilities));
    CHECK(json_object_object_get_ex(response, "capabilities", &capabilities));
    CHECK(notifyd_json_bool(response, "mute_schedule_supported", 0));
    CHECK(!notifyd_json_bool(response, "mobile_push_supported", 1));
    CHECK(notifyd_json_bool(capabilities, "mute_schedule_supported", 0));
    CHECK(!notifyd_json_bool(capabilities, "mobile_push_supported", 1));
    json_object_put(response);

    request = parse("{\"mobile_push\":false}");
    response = notifyd_settings_update(request);
    CHECK(!notifyd_json_bool(response, "ok", 1));
    CHECK(!strcmp(notifyd_json_str(response, "feature", ""), "mobile_push"));
    CHECK(!strcmp(notifyd_json_str(response, "reason", ""),
                  "device_token_provider_not_configured"));
    json_object_put(response); json_object_put(request);

    request = parse("{\"mute_schedule\":{\"enabled\":true,\"timezone\":\"UTC\","
                    "\"windows\":[{\"days\":[1,2,3,4,5,6,7],"
                    "\"start\":\"00:00\",\"end\":\"23:59\"}]}}");
    response = notifyd_settings_update(request);
    CHECK(notifyd_json_bool(response, "ok", 0));
    json_object_put(response); json_object_put(request);

    event_request = parse("{\"event\":\"WAN_DOWN\",\"severity\":\"warning\","
                          "\"category\":\"INTERNET_AND_WAN\",\"source\":\"fixture\","
                          "\"title\":\"down\"}");
    response = notifyd_enqueue_event(event_request);
    CHECK(notifyd_json_bool(response, "ok", 0));
    CHECK(notifyd_json_int(response, "suppressed", 0) == 1);
    CHECK(notifyd_json_int(response, "enqueued", -1) == 0);
    CHECK(scalar("SELECT COUNT(*) FROM notify_outbox") == 0);
    CHECK(scalar("SELECT COUNT(*) FROM notify_route_triggers") == 1);
    json_object_put(response);

    request = parse("{\"route_id\":\"default-warning\"}");
    response = notifyd_triggers_json(request);
    json_object_put(request);
    CHECK(notifyd_json_bool(response, "ok", 0));
    CHECK(json_object_object_get_ex(response, "items", &items));
    CHECK(json_object_array_length(items) == 1);
    CHECK(!strcmp(notifyd_json_str(json_object_array_get_idx(items, 0), "result", ""), "muted"));
    CHECK(!strcmp(notifyd_json_str(json_object_array_get_idx(items, 0), "mute_result", ""),
                  "global_schedule"));
    CHECK(!json_object_object_get_ex(json_object_array_get_idx(items, 0), "payload", &mute));
    json_object_put(response);

    request = parse("{\"mute_schedule\":{\"enabled\":false}}");
    response = notifyd_settings_update(request);
    json_object_put(request);
    CHECK(notifyd_json_bool(response, "ok", 0));
    json_object_put(response);

    fixture_now++;
    response = notifyd_enqueue_event(event_request);
    CHECK(notifyd_json_bool(response, "ok", 0));
    CHECK(notifyd_json_int(response, "enqueued", 0) == 1);
    CHECK(scalar("SELECT COUNT(*) FROM notify_outbox") == 1);
    CHECK(scalar("SELECT COUNT(*) FROM notify_route_triggers") == 2);
    json_object_put(response); json_object_put(event_request);

    st = notifyd_prepare("SELECT id,channel_id FROM notify_outbox LIMIT 1");
    CHECK(st && sqlite3_step(st) == SQLITE_ROW);
    snprintf(delivery_sql, sizeof(delivery_sql),
        "INSERT INTO notify_deliveries(outbox_id,channel_id,ts,ok,http_status,error) "
        "VALUES('%s','%s',%lld,1,200,''),('%s','%s',%lld,1,200,'')",
        notifyd_sqlite_text(st, 0, ""), notifyd_sqlite_text(st, 1, ""),
        (long long)fixture_now, notifyd_sqlite_text(st, 0, ""),
        notifyd_sqlite_text(st, 1, ""), (long long)fixture_now);
    sqlite3_finalize(st);
    CHECK(sqlite3_exec(g_notify_db, delivery_sql, NULL, NULL, NULL) == SQLITE_OK);

    response = notifyd_routes_json();
    route = find_route(response, "default-warning");
    CHECK(route);
    CHECK(notifyd_json_i64(route, "trigger_count", -1) == 2);
    CHECK(notifyd_json_i64(route, "outbox_count", -1) == 1);
    CHECK(notifyd_json_i64(route, "delivery_count", -1) == 2);
    CHECK(notifyd_json_i64(route, "last_triggered_at", 0) == fixture_now);
    json_object_put(response);

    request = parse("{\"route_id\":\"default-warning\",\"limit\":1}");
    page = notifyd_triggers_json(request);
    json_object_put(request);
    CHECK(notifyd_json_bool(page, "ok", 0));
    CHECK(notifyd_json_bool(page, "has_more", 0));
    cursor = notifyd_json_str(page, "next_cursor", "");
    CHECK(cursor[0]);
    {
        char query[160];
        snprintf(query, sizeof(query),
                 "{\"route_id\":\"default-warning\",\"limit\":1,\"cursor\":\"%s\"}",
                 cursor);
        request = parse(query);
        next_page = notifyd_triggers_json(request);
        json_object_put(request);
    }
    CHECK(notifyd_json_bool(next_page, "ok", 0));
    CHECK(json_object_object_get_ex(next_page, "items", &items));
    CHECK(json_object_array_length(items) == 1);
    CHECK(!notifyd_json_bool(next_page, "has_more", 1));
    json_object_put(next_page); json_object_put(page);

    request = parse("{\"enabled\":true}");
    response = notifyd_settings_update(request);
    json_object_put(request);
    CHECK(notifyd_json_bool(response, "ok", 0));
    CHECK(json_object_object_get_ex(response, "mute_schedule", &mute));
    CHECK(!notifyd_json_bool(mute, "enabled", 1));
    json_object_put(response);

    notifyd_db_close();
    puts("ok - notifyd global mute and trigger summaries pass real DB runtime fixture");
    return 0;
}
'''


def main() -> None:
    flags = subprocess.check_output(
        ["pkg-config", "--cflags", "--libs", "json-c", "sqlite3"], text=True
    ).strip()
    env = os.environ.copy()
    env.pop("LD_LIBRARY_PATH", None)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for relative, content in STUBS.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        harness = root / "runtime.c"
        binary = root / "runtime"
        harness.write_text(HARNESS, encoding="utf-8")
        subprocess.run(
            [
                os.environ.get("CC", "cc"),
                "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                f"-DTEST_NOTIFY_DB=\"{root / 'notify.db'}\"",
                f"-DTEST_CONFIG_DB=\"{root / 'config.db'}\"",
                f"-I{root}", f"-I{ROOT / 'src'}", f"-I{ROOT / 'src/notifyd'}",
                str(harness), "-o", str(binary), *shlex.split(flags),
            ],
            check=True,
            env=env,
        )
        subprocess.run([str(binary)], check=True, env=env)


if __name__ == "__main__":
    main()

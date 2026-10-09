// SPDX-License-Identifier: GPL-2.0-or-later
#include "jmx_metrics_store.h"

#include <assert.h>
#include <json-c/json.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct json_object *jmx_gen_api_response_data(int code, struct json_object *data)
{
    struct json_object *root = json_object_new_object();
    json_object_object_add(root, "code", json_object_new_int(code));
    json_object_object_add(root, "data", data ? data : json_object_new_object());
    return root;
}

static void set_now(long long now)
{
    char value[32];
    snprintf(value, sizeof(value), "%lld", now);
    assert(setenv("DREAMINGWRT_METRICS_TEST_NOW", value, 1) == 0);
}

static long long scalar(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *st = NULL;
    long long value = -1;
    assert(sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK);
    if (sqlite3_step(st) == SQLITE_ROW)
        value = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return value;
}

static void write_snapshot(const char *path, const char *text)
{
    FILE *fp = fopen(path, "w");

    assert(fp);
    assert(fputs(text, fp) >= 0);
    assert(fclose(fp) == 0);
}

static struct json_object *response_data(struct json_object *root)
{
    struct json_object *data = NULL;
    assert(root);
    assert(json_object_object_get_ex(root, "data", &data));
    return data;
}

static struct json_object *activity(const char *range, const char *wan_id)
{
    struct json_object *req = json_object_new_object();
    struct json_object *root;
    json_object_object_add(req, "range", json_object_new_string(range));
    if (wan_id)
        json_object_object_add(req, "wan_id", json_object_new_string(wan_id));
    root = jmx_metrics_activity_api(req);
    json_object_put(req);
    return root;
}

static void create_legacy(sqlite3 **db, const char *path, long long now)
{
    sqlite3_stmt *st = NULL;
    int i;
    assert(sqlite3_open(path, db) == SQLITE_OK);
    assert(sqlite3_exec(*db,
        "CREATE TABLE dashboard_activity_sample("
        "ts INTEGER NOT NULL,wan_id TEXT NOT NULL,up_rate INTEGER NOT NULL,"
        "down_rate INTEGER NOT NULL,connections INTEGER NOT NULL,"
        "latency_avg REAL,latency_min REAL,latency_max REAL,"
        "PRIMARY KEY(ts,wan_id));", NULL, NULL, NULL) == SQLITE_OK);
    assert(sqlite3_prepare_v2(*db,
        "INSERT INTO dashboard_activity_sample VALUES(?1,?2,?3,?4,?5,10,8,12)",
        -1, &st, NULL) == SQLITE_OK);
    for (i = 0; i < 120; i++) {
        sqlite3_reset(st);
        sqlite3_bind_int64(st, 1, now - 7200 + i * 10);
        sqlite3_bind_text(st, 2, i % 3 == 0 ? "global" :
                                     (i % 2 ? "wan" : "wan2"),
                          -1, SQLITE_STATIC);
        sqlite3_bind_int(st, 3, 100 + i);
        sqlite3_bind_int(st, 4, 200 + i);
        sqlite3_bind_int(st, 5, i % 20);
        assert(sqlite3_step(st) == SQLITE_DONE);
    }
    sqlite3_finalize(st);
}

int main(int argc, char **argv)
{
    char metrics_path[512], snapshot_path[512], legacy_path[512];
    char sql[1024];
    sqlite3 *db = NULL, *legacy = NULL;
    struct json_object *root, *data, *buckets, *field;
    struct jmx_metrics_usage usage;
    long long base = (1700000000LL / 3600) * 3600;
    long long before_generation;
    long long snapshot_generation;
    long long migrated_once;
    char snapshot_text[2048];

    assert(argc == 2);
    snprintf(metrics_path, sizeof(metrics_path), "%s/metrics.db", argv[1]);
    snprintf(snapshot_path, sizeof(snapshot_path), "%s/hot.snapshot", argv[1]);
    snprintf(legacy_path, sizeof(legacy_path), "%s/legacy.db", argv[1]);
    assert(setenv("DREAMINGWRT_METRICS_DB", metrics_path, 1) == 0);
    assert(setenv("DREAMINGWRT_METRICS_SNAPSHOT", snapshot_path, 1) == 0);
    set_now(base + 10);
    assert(jmx_metrics_store_init() == 0);
    assert(sqlite3_open(metrics_path, &db) == SQLITE_OK);

    /* Samples in an open minute stay memory-only and global is query-derived. */
    jmx_metrics_record_sample("wan", 100, 200, 3, 10, 9, 11);
    jmx_metrics_record_sample("wan2", 50, 70, 4, 20, 18, 22);
    set_now(base + 12);
    jmx_metrics_record_sample("wan", 300, 400, 5, 12, 10, 14);
    assert(scalar(db, "SELECT COUNT(*) FROM metric_bucket") == 0);
    assert(scalar(db, "SELECT COUNT(*) FROM metric_bucket WHERE wan_id='global'") == 0);

    root = activity("1h", NULL);
    data = response_data(root);
    assert(json_object_object_get_ex(data, "source", &field));
    assert(!strcmp(json_object_get_string(field), "metrics_minute"));
    assert(json_object_object_get_ex(data, "hot_source", &field));
    assert(!strcmp(json_object_get_string(field), "memory_hot"));
    assert(json_object_object_get_ex(data, "buckets", &buckets));
    assert(json_object_array_length(buckets) == 1);
    field = json_object_array_get_idx(buckets, 0);
    assert(json_object_get_int64(json_object_object_get(data, "sample_count")) == 3);
    assert(json_object_get_int64(json_object_object_get(data, "series_count")) == 2);
    assert(json_object_get_int64(json_object_object_get(data, "expected_sample_count")) == 3600);
    assert(json_object_get_int64(json_object_object_get(field, "up_avg")) == 250);
    assert(json_object_get_int64(json_object_object_get(field, "down_avg")) == 370);
    assert(json_object_get_int64(json_object_object_get(field, "connections_avg")) == 8);
    assert(!strcmp(json_object_get_string(json_object_object_get(field, "source")),
                   "memory_hot"));
    json_object_put(root);

    /* Crossing a minute closes all WAN accumulators in one persistent batch. */
    set_now(base + 65);
    jmx_metrics_record_sample("wan", 500, 600, 6, 15, 14, 16);
    assert(scalar(db, "SELECT COUNT(*) FROM metric_bucket WHERE resolution=60") == 2);
    assert(scalar(db, "SELECT COUNT(*) FROM metric_bucket WHERE wan_id='global'") == 0);
    assert(scalar(db, "SELECT sample_count FROM metric_bucket WHERE wan_id='wan'") == 2);

    /* Hourly monotonic counters survive reset and process restart. */
    set_now(base + 10);
    jmx_metrics_counter_observe("wan", 1000, 2000, 1);
    set_now(base + 20);
    jmx_metrics_counter_observe("wan", 1200, 2300, 1);
    set_now(base + 3605);
    jmx_metrics_counter_observe("wan", 2000, 3000, 1);
    assert(jmx_metrics_usage_query("wan", base, base + 3605, &usage) == 0);
    assert(usage.down_bytes == 1000 && usage.up_bytes == 1000);
    assert(!usage.counter_reset);
    set_now(base + 3700);
    jmx_metrics_counter_observe("wan", 100, 200, 1);
    assert(jmx_metrics_usage_query("wan", base, base + 3700, &usage) == 0);
    assert(usage.down_bytes == 1100 && usage.up_bytes == 1200);
    assert(usage.counter_reset);
    assert(scalar(db, "SELECT COUNT(*) FROM counter_checkpoint WHERE wan_id='wan'") == 3);
    assert(scalar(db,
        "SELECT MIN(bucket_ts) FROM counter_checkpoint WHERE wan_id='wan'") == base + 10);
    assert(scalar(db,
        "SELECT COUNT(*) FROM counter_checkpoint WHERE wan_id='wan' AND bucket_ts=1700002800") == 0);
    assert(scalar(db,
        "SELECT COUNT(DISTINCT generation) FROM counter_checkpoint WHERE wan_id='wan'") == 2);

    /* Without an exact period boundary, report only the observed partial window. */
    assert(jmx_metrics_usage_query("wan", base + 1800, base + 3700, &usage) == 0);
    assert(usage.down_bytes == 100 && usage.up_bytes == 200);
    assert(usage.estimated);
    assert(usage.completeness_ratio == 0.05);
    assert(!strcmp(usage.gap_reason, "checkpoint_window_partial"));

    sqlite3_close(db);
    assert(unlink(snapshot_path) == 0);
    jmx_metrics_store_close();
    set_now(base + 70);
    assert(jmx_metrics_store_init() == 0);
    assert(sqlite3_open(metrics_path, &db) == SQLITE_OK);
    jmx_metrics_record_sample("wan", 700, 800, 7, 15, 14, 16);
    root = activity("1d", NULL);
    data = response_data(root);
    assert(json_object_object_get_ex(data, "buckets", &buckets));
    assert(json_object_array_length(buckets) == 1);
    field = json_object_array_get_idx(buckets, 0);
    assert(!strcmp(json_object_get_string(json_object_object_get(field, "source")),
                   "metrics_store+memory_hot"));
    assert(json_object_get_int64(json_object_object_get(field, "up_avg")) == 400);
    assert(json_object_get_double(json_object_object_get(field, "latency_avg")) > 15.0);
    assert(json_object_get_double(json_object_object_get(field, "latency_avg")) < 15.5);
    assert(json_object_get_double(json_object_object_get(field, "latency_min")) == 9.0);
    assert(json_object_get_double(json_object_object_get(field, "latency_max")) == 22.0);
    json_object_put(root);

    set_now(base + 3800);
    assert(jmx_metrics_usage_query("wan", base, base + 3800, &usage) == 0);
    assert(usage.down_bytes == 1100 && usage.up_bytes == 1200);
    assert(usage.counter_reset);
    jmx_metrics_counter_observe("wan", 200, 300, 1);
    assert(jmx_metrics_usage_query("wan", base, base + 5001, &usage) == 0);
    assert(usage.down_bytes == 1200 && usage.up_bytes == 1300);
    assert(usage.counter_reset);

    /* Global usage is derived from real WANs and uses the least-complete window. */
    set_now(base + 3810);
    jmx_metrics_counter_observe("wan2", 500, 700, 1);
    set_now(base + 3820);
    jmx_metrics_counter_observe("wan2", 800, 1100, 1);
    snprintf(sql, sizeof(sql),
        "INSERT OR REPLACE INTO counter_checkpoint VALUES"
        "(%lld,'global',1,1,1,1,0,0,1,'legacy_global'),"
        "(%lld,'global',999999,999999,999999,999999,0,0,1,'legacy_global');",
        base + 20, base + 3800);
    assert(sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK);
    assert(jmx_metrics_usage_query("all_wans", base, base + 3820, &usage) == 0);
    assert(usage.down_bytes == 1500 && usage.up_bytes == 1700);
    assert(usage.total_bytes == usage.down_bytes + usage.up_bytes);
    assert(usage.completeness_ratio > 0.002 && usage.completeness_ratio < 0.003);
    assert(usage.estimated);

    /* Legacy migration is bounded/idempotent and ignores persisted global rows. */
    create_legacy(&legacy, legacy_path, base + 3800);
    jmx_metrics_store_set_legacy_db(legacy);
    assert(jmx_metrics_store_maintenance() == 0);
    migrated_once = scalar(db,
        "SELECT COUNT(*) FROM metric_bucket WHERE source='legacy_rate_estimate'");
    assert(migrated_once > 0);
    assert(scalar(db, "SELECT COUNT(*) FROM metric_bucket WHERE wan_id='global'") == 0);
    assert(jmx_metrics_store_maintenance() == 0);
    assert(scalar(db,
        "SELECT COUNT(*) FROM metric_bucket WHERE source='legacy_rate_estimate'") == migrated_once);

    /* A closed 5-minute rollup is reproducible and deletes old minute rows. */
    assert(sqlite3_exec(db,
        "INSERT OR REPLACE INTO metric_bucket VALUES"
        "(1699822800,'rollup',60,10,5,15,20,10,30,2,3,8,7,9,30,60,1,0,'native_counter_rate'),"
        "(1699822860,'rollup',60,30,25,35,40,35,45,4,5,12,11,13,30,60,1,0,'native_counter_rate');",
        NULL, NULL, NULL) == SQLITE_OK);
    assert(jmx_metrics_store_maintenance() == 0);
    assert(scalar(db,
        "SELECT COUNT(*) FROM metric_bucket WHERE wan_id='rollup' AND resolution=60") == 0);
    assert(scalar(db,
        "SELECT CAST(up_avg AS INTEGER) FROM metric_bucket WHERE wan_id='rollup' AND resolution=300") == 20);
    assert(scalar(db,
        "SELECT sample_count FROM metric_bucket WHERE wan_id='rollup' AND resolution=300") == 60);

    /* Long ranges combine old five-minute rollups with the recent minute tier. */
    root = activity("1w", NULL);
    data = response_data(root);
    assert(!strcmp(json_object_get_string(json_object_object_get(data, "source")),
                   "metrics_mixed_rollup"));
    assert(json_object_object_get_ex(data, "buckets", &buckets));
    assert(json_object_array_length(buckets) >= 2);
    json_object_put(root);

    /* Clock rollback starts a new generation and publishes an explicit gap. */
    root = activity("1h", "wan");
    data = response_data(root);
    before_generation = json_object_get_int64(json_object_object_get(data, "generation"));
    json_object_put(root);
    set_now(base + 3000);
    jmx_metrics_record_sample("wan", 1, 2, 1, 0, 0, 0);
    root = activity("1h", "wan");
    data = response_data(root);
    assert(json_object_get_int64(json_object_object_get(data, "generation")) !=
           before_generation);
    assert(!strcmp(json_object_get_string(json_object_object_get(data, "gap_reason")),
                   "clock_rollback"));
    json_object_put(root);

    /* Keep the v2 snapshot across close/init and verify hot samples, minute
     * accumulators, and counter state are restored rather than silently reset. */
    set_now(base + 6000);
    jmx_metrics_record_sample("wan", 900, 1000, 8, 16, 15, 17);
    assert(access(snapshot_path, F_OK) == 0);
    sqlite3_close(db);
    jmx_metrics_store_close();
    set_now(base + 6001);
    assert(jmx_metrics_store_init() == 0);
    assert(sqlite3_open(metrics_path, &db) == SQLITE_OK);
    root = activity("1h", "wan");
    data = response_data(root);
    snapshot_generation = json_object_get_int64(
        json_object_object_get(data, "generation"));
    assert(!strcmp(json_object_get_string(json_object_object_get(data, "gap_reason")),
                   "restored_tmpfs_snapshot"));
    assert(snapshot_generation == base + 6000);
    assert(json_object_object_get_ex(data, "buckets", &buckets));
    field = NULL;
    for (size_t bi = 0; bi < json_object_array_length(buckets); bi++) {
        struct json_object *candidate = json_object_array_get_idx(buckets, bi);
        struct json_object *source = NULL;
        if (candidate && json_object_object_get_ex(candidate, "source", &source) &&
            source && strstr(json_object_get_string(source), "memory_hot")) {
            field = candidate;
            break;
        }
    }
    assert(field);
    assert(json_object_get_int64(json_object_object_get(field, "up_avg")) == 900);
    assert(json_object_get_double(json_object_object_get(field, "latency_avg")) == 16.0);
    assert(json_object_get_int64(json_object_object_get(data, "generation")) ==
           snapshot_generation);
    json_object_put(root);
    set_now(base + 6002);
    jmx_metrics_counter_observe("wan", 300, 400, 1);
    assert(jmx_metrics_usage_query("wan", base, base + 6002, &usage) == 0);
    assert(usage.down_bytes == 1300 && usage.up_bytes == 1400);

    /* The restored open minute must flush exactly once when the next minute
     * receives a sample; this proves the minute accumulator survived restart. */
    set_now(base + 6065);
    jmx_metrics_record_sample("wan", 100, 200, 1, 5, 4, 6);
    assert(scalar(db,
        "SELECT sample_count FROM metric_bucket WHERE wan_id='wan' "
        "AND resolution=60 AND bucket_ts=1700005200") == 1);

    /* Trailing garbage invalidates the whole snapshot instead of allowing a
     * partially restored hot tier. */
    sqlite3_close(db);
    jmx_metrics_store_close();
    set_now(base + 6066);
    snprintf(snapshot_text, sizeof(snapshot_text),
             "generation=%lld saved_at=%lld version=2\n"
             "sample %lld wan 1 2 1 0 0 0 trailing\n",
             base + 6000, base + 6065, base + 6065);
    write_snapshot(snapshot_path, snapshot_text);
    assert(jmx_metrics_store_init() == 0);
    assert(sqlite3_open(metrics_path, &db) == SQLITE_OK);
    root = activity("1h", "wan");
    data = response_data(root);
    assert(!strcmp(json_object_get_string(json_object_object_get(data, "gap_reason")),
                   "snapshot_stale_or_invalid"));
    buckets = json_object_object_get(data, "buckets");
    for (size_t bi = 0; bi < json_object_array_length(buckets); bi++) {
        struct json_object *candidate = json_object_array_get_idx(buckets, bi);
        struct json_object *source = NULL;
        assert(candidate);
        if (json_object_object_get_ex(candidate, "source", &source))
            assert(strcmp(json_object_get_string(source), "memory_hot") != 0);
    }
    json_object_put(root);

    /* Duplicate minute records are rejected rather than silently overwritten. */
    sqlite3_close(db);
    jmx_metrics_store_close();
    set_now(base + 6067);
    snprintf(snapshot_text, sizeof(snapshot_text),
             "generation=%lld saved_at=%lld version=2\n"
             "minute %lld wan 1 %lld %lld 1 2 1 1 2 2 1 1 0 0 0 0\n"
             "minute %lld wan 1 %lld %lld 1 2 1 1 2 2 1 1 0 0 0 0\n",
             base + 6000, base + 6066, base + 6060, base + 6060, base + 6060,
             base + 6060, base + 6060, base + 6060);
    write_snapshot(snapshot_path, snapshot_text);
    assert(jmx_metrics_store_init() == 0);
    assert(sqlite3_open(metrics_path, &db) == SQLITE_OK);
    root = activity("1h", "wan");
    data = response_data(root);
    assert(!strcmp(json_object_get_string(json_object_object_get(data, "gap_reason")),
                   "snapshot_stale_or_invalid"));
    json_object_put(root);

    /* Duplicate counter records follow the same fail-closed rule. */
    sqlite3_close(db);
    jmx_metrics_store_close();
    set_now(base + 6068);
    snprintf(snapshot_text, sizeof(snapshot_text),
             "generation=%lld saved_at=%lld version=2\n"
             "counter wan 1 3 4 5 6 0 %lld %lld %lld %lld\n"
             "counter wan 1 3 4 5 6 0 %lld %lld %lld %lld\n",
             base + 6000, base + 6067, base + 6000, base + 6067,
             base + 3600, base + 6000, base + 6067, base + 3600,
             base + 6000, base + 6067);
    write_snapshot(snapshot_path, snapshot_text);
    assert(jmx_metrics_store_init() == 0);
    assert(sqlite3_open(metrics_path, &db) == SQLITE_OK);
    root = activity("1h", "wan");
    data = response_data(root);
    assert(!strcmp(json_object_get_string(json_object_object_get(data, "gap_reason")),
                   "snapshot_stale_or_invalid"));
    json_object_put(root);

    sqlite3_close(legacy);
    sqlite3_close(db);
    jmx_metrics_store_close();
    puts("ok: metrics hot tier, rollups, checkpoints, reset/restart and migration");
    return 0;
}

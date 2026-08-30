// SPDX-License-Identifier: GPL-2.0-or-later
/* Dashboard hot telemetry and bounded rollup storage. */
#include "jmx_metrics_store.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define API_CODE_SUCCESS 2000
#define API_CODE_ERROR 4000
extern struct json_object *jmx_gen_api_response_data(int code,
                                                     struct json_object *data_obj);

#define METRICS_SCHEMA_VERSION 1
#define HOT_RETENTION_SEC 900
#define HOT_CAP 8192
#define WAN_CAP 32
#define MIGRATE_BATCH_ROWS 1000
#define MINUTE_SEC 60
#define FIVE_MINUTE_SEC 300
#define HOUR_SEC 3600
#define DAY_SEC 86400
#define RETENTION_SEC (31LL * DAY_SEC)
#define SNAPSHOT_INTERVAL_SEC 30
#define SNAPSHOT_PATH "/tmp/dreamingwrt-metrics-hot.snapshot"

struct hot_sample {
    int64_t ts;
    char wan_id[32];
    int64_t up_rate;
    int64_t down_rate;
    int connections;
    double latency_avg;
    double latency_min;
    double latency_max;
};

struct minute_acc {
    int active;
    int64_t bucket_ts;
    char wan_id[32];
    int samples;
    int64_t first_ts;
    int64_t last_ts;
    long double up_sum;
    long double down_sum;
    int64_t up_min;
    int64_t up_max;
    int64_t down_min;
    int64_t down_max;
    long double conn_sum;
    int conn_max;
    long double latency_sum;
    double latency_min;
    double latency_max;
    int latency_samples;
};

struct counter_state {
    int active;
    int online;
    char wan_id[32];
    uint64_t raw_rx;
    uint64_t raw_tx;
    uint64_t total_rx;
    uint64_t total_tx;
    int reset_count;
    int64_t first_ts;
    int64_t last_ts;
    int64_t checkpoint_hour;
    int64_t generation;
};

static sqlite3 *g_metrics;
static sqlite3 *g_legacy;
static struct hot_sample g_hot[HOT_CAP];
static size_t g_hot_head;
static size_t g_hot_count;
static struct minute_acc g_minutes[WAN_CAP];
static struct counter_state g_counters[WAN_CAP];
static int64_t g_generation;
static int64_t g_last_snapshot;
static int64_t g_last_maintenance_minute;
static int64_t g_last_wall;
static char g_hot_gap_reason[64] = "process_start";

static int64_t metrics_now(void)
{
    const char *test_now = getenv("DREAMINGWRT_METRICS_TEST_NOW");
    char *end = NULL;
    long long value;

    if (!test_now || !test_now[0])
        return (int64_t)time(NULL);
    errno = 0;
    value = strtoll(test_now, &end, 10);
    return errno == 0 && end && *end == '\0' ? (int64_t)value :
                                                (int64_t)time(NULL);
}

static const char *metrics_snapshot_path(void)
{
    const char *path = getenv("DREAMINGWRT_METRICS_SNAPSHOT");
    return path && path[0] ? path : SNAPSHOT_PATH;
}

static void metrics_observe_clock(int64_t now)
{
    if (!g_last_wall) {
        g_last_wall = now;
        return;
    }
    if (now < g_last_wall || now - g_last_wall > 300) {
        memset(g_hot, 0, sizeof(g_hot));
        memset(g_minutes, 0, sizeof(g_minutes));
        g_hot_head = 0;
        g_hot_count = 0;
        g_generation = now;
        snprintf(g_hot_gap_reason, sizeof(g_hot_gap_reason), "%s",
                 now < g_last_wall ? "clock_rollback" : "collection_gap");
    }
    g_last_wall = now;
}

static int metrics_exec(const char *sql)
{
    char *error = NULL;
    int rc = sqlite3_exec(g_metrics, sql, NULL, NULL, &error);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "metrics sqlite rc=%d error=%s\n",
                rc, error ? error : "");
        sqlite3_free(error);
        return -1;
    }
    return 0;
}

static const char *metrics_path(void)
{
    const char *path = getenv("DREAMINGWRT_METRICS_DB");
    return path && path[0] ? path : JMX_METRICS_DB_PATH_DEFAULT;
}

static void metrics_restore_snapshot(void)
{
    FILE *fp = fopen(metrics_snapshot_path(), "r");
    struct hot_sample sample;
    long long generation = 0;
    long long saved_at = 0;
    long long up_rate = 0;
    long long down_rate = 0;
    int restored = 0;
    int64_t cutoff = metrics_now() - HOT_RETENTION_SEC;

    if (!fp)
        return;
    if (fscanf(fp, "generation=%lld saved_at=%lld\n", &generation, &saved_at) != 2 ||
        saved_at < cutoff) {
        fclose(fp);
        snprintf(g_hot_gap_reason, sizeof(g_hot_gap_reason), "snapshot_stale_or_invalid");
        return;
    }
    while (fscanf(fp, "%lld %31s %lld %lld %d %lf %lf %lf\n",
                  &generation, sample.wan_id, &up_rate, &down_rate,
                  &sample.connections, &sample.latency_avg, &sample.latency_min,
                  &sample.latency_max) == 8) {
        sample.ts = generation;
        sample.up_rate = (int64_t)up_rate;
        sample.down_rate = (int64_t)down_rate;
        if (sample.ts < cutoff || !strcmp(sample.wan_id, "global"))
            continue;
        g_hot[g_hot_head] = sample;
        g_hot_head = (g_hot_head + 1) % HOT_CAP;
        if (g_hot_count < HOT_CAP)
            g_hot_count++;
        restored++;
    }
    fclose(fp);
    if (restored > 0)
        snprintf(g_hot_gap_reason, sizeof(g_hot_gap_reason), "restored_tmpfs_snapshot");
}

static void metrics_snapshot(int64_t now)
{
    char tmp[160];
    FILE *fp;
    size_t i;
    int64_t cutoff = now - HOT_RETENTION_SEC;

    if (now - g_last_snapshot < SNAPSHOT_INTERVAL_SEC)
        return;
    snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", metrics_snapshot_path(),
             (long)getpid());
    fp = fopen(tmp, "w");
    if (!fp)
        return;
    fprintf(fp, "generation=%lld saved_at=%lld\n",
            (long long)g_generation, (long long)now);
    for (i = 0; i < g_hot_count; i++) {
        size_t idx = (g_hot_head + HOT_CAP - g_hot_count + i) % HOT_CAP;
        const struct hot_sample *s = &g_hot[idx];
        if (s->ts < cutoff)
            continue;
        fprintf(fp, "%lld %s %lld %lld %d %.3f %.3f %.3f\n",
                (long long)s->ts, s->wan_id, (long long)s->up_rate,
                (long long)s->down_rate, s->connections, s->latency_avg,
                s->latency_min, s->latency_max);
    }
    if (fflush(fp) == 0 && fsync(fileno(fp)) == 0 && fclose(fp) == 0 &&
        rename(tmp, metrics_snapshot_path()) == 0) {
        g_last_snapshot = now;
    } else {
        unlink(tmp);
    }
}

int jmx_metrics_store_init(void)
{
    const char *path;
    if (g_metrics)
        return 0;
    path = metrics_path();
    if (!getenv("DREAMINGWRT_METRICS_DB"))
        mkdir("/etc/dreamingwrt", 0755);
    if (sqlite3_open(path, &g_metrics) != SQLITE_OK) {
        fprintf(stderr, "open metrics db failed path=%s\n", path);
        if (g_metrics) sqlite3_close(g_metrics);
        g_metrics = NULL;
        return -1;
    }
    sqlite3_busy_timeout(g_metrics, 2000);
    if (metrics_exec("PRAGMA journal_mode=WAL;") != 0 ||
        metrics_exec("PRAGMA synchronous=NORMAL;") != 0 ||
        metrics_exec("PRAGMA wal_autocheckpoint=256;") != 0 ||
        metrics_exec("CREATE TABLE IF NOT EXISTS metrics_meta("
                     "key TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at INTEGER NOT NULL);") != 0 ||
        metrics_exec("CREATE TABLE IF NOT EXISTS metric_bucket("
                     "bucket_ts INTEGER NOT NULL,wan_id TEXT NOT NULL,"
                     "resolution INTEGER NOT NULL,up_avg REAL NOT NULL,"
                     "up_min INTEGER NOT NULL,up_max INTEGER NOT NULL,"
                     "down_avg REAL NOT NULL,down_min INTEGER NOT NULL,"
                     "down_max INTEGER NOT NULL,connections_avg REAL NOT NULL,"
                     "connections_max INTEGER NOT NULL,latency_avg REAL,"
                     "latency_min REAL,latency_max REAL,sample_count INTEGER NOT NULL,"
                     "valid_duration INTEGER NOT NULL,generation INTEGER NOT NULL,"
                     "estimated INTEGER NOT NULL DEFAULT 0,source TEXT NOT NULL,"
                     "PRIMARY KEY(bucket_ts,wan_id,resolution));") != 0 ||
        metrics_exec("CREATE INDEX IF NOT EXISTS metric_bucket_wan_time "
                     "ON metric_bucket(wan_id,resolution,bucket_ts);") != 0 ||
        metrics_exec("CREATE TABLE IF NOT EXISTS counter_checkpoint("
                     "bucket_ts INTEGER NOT NULL,wan_id TEXT NOT NULL,"
                     "raw_rx INTEGER NOT NULL,raw_tx INTEGER NOT NULL,"
                     "total_rx INTEGER NOT NULL,total_tx INTEGER NOT NULL,"
                     "reset_count INTEGER NOT NULL,counter_reset INTEGER NOT NULL,"
                     "generation INTEGER NOT NULL,source TEXT NOT NULL,"
                     "PRIMARY KEY(bucket_ts,wan_id));") != 0 ||
        metrics_exec("CREATE INDEX IF NOT EXISTS counter_checkpoint_wan_time "
                     "ON counter_checkpoint(wan_id,bucket_ts);") != 0) {
        sqlite3_close(g_metrics);
        g_metrics = NULL;
        return -1;
    }
    g_generation = metrics_now();
    metrics_restore_snapshot();
    return 0;
}

void jmx_metrics_store_close(void)
{
    if (!g_metrics) return;
    jmx_metrics_store_maintenance();
    sqlite3_close(g_metrics);
    g_metrics = NULL;
    g_legacy = NULL;
    memset(g_hot, 0, sizeof(g_hot));
    memset(g_minutes, 0, sizeof(g_minutes));
    memset(g_counters, 0, sizeof(g_counters));
    g_hot_head = 0;
    g_hot_count = 0;
    g_generation = 0;
    g_last_snapshot = 0;
    g_last_maintenance_minute = 0;
    g_last_wall = 0;
    snprintf(g_hot_gap_reason, sizeof(g_hot_gap_reason), "process_start");
}

void jmx_metrics_store_set_legacy_db(sqlite3 *db) { g_legacy = db; }

static struct minute_acc *minute_for(const char *wan_id, int64_t bucket)
{
    int i;
    for (i = 0; i < WAN_CAP; i++)
        if (g_minutes[i].active && !strcmp(g_minutes[i].wan_id, wan_id))
            return &g_minutes[i];
    for (i = 0; i < WAN_CAP; i++) {
        if (!g_minutes[i].active) {
            memset(&g_minutes[i], 0, sizeof(g_minutes[i]));
            g_minutes[i].active = 1;
            g_minutes[i].bucket_ts = bucket;
            snprintf(g_minutes[i].wan_id, sizeof(g_minutes[i].wan_id), "%s", wan_id);
            return &g_minutes[i];
        }
    }
    return NULL;
}

static int write_minute(sqlite3_stmt *st, const struct minute_acc *a,
                        int estimated, const char *source)
{
    int duration;
    if (!a || a->samples <= 0) return 0;
    duration = a->last_ts > a->first_ts ? (int)(a->last_ts - a->first_ts + 2) : 2;
    if (duration > MINUTE_SEC) duration = MINUTE_SEC;
    sqlite3_reset(st);
    sqlite3_clear_bindings(st);
    sqlite3_bind_int64(st, 1, a->bucket_ts);
    sqlite3_bind_text(st, 2, a->wan_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(st, 3, (double)(a->up_sum / a->samples));
    sqlite3_bind_int64(st, 4, a->up_min);
    sqlite3_bind_int64(st, 5, a->up_max);
    sqlite3_bind_double(st, 6, (double)(a->down_sum / a->samples));
    sqlite3_bind_int64(st, 7, a->down_min);
    sqlite3_bind_int64(st, 8, a->down_max);
    sqlite3_bind_double(st, 9, (double)(a->conn_sum / a->samples));
    sqlite3_bind_int(st, 10, a->conn_max);
    if (a->latency_samples > 0) {
        sqlite3_bind_double(st, 11, (double)(a->latency_sum / a->latency_samples));
        sqlite3_bind_double(st, 12, a->latency_min);
        sqlite3_bind_double(st, 13, a->latency_max);
    } else {
        sqlite3_bind_null(st, 11); sqlite3_bind_null(st, 12); sqlite3_bind_null(st, 13);
    }
    sqlite3_bind_int(st, 14, a->samples);
    sqlite3_bind_int(st, 15, duration);
    sqlite3_bind_int64(st, 16, g_generation);
    sqlite3_bind_int(st, 17, estimated);
    sqlite3_bind_text(st, 18, source, -1, SQLITE_STATIC);
    return sqlite3_step(st) == SQLITE_DONE ? 0 : -1;
}

static int flush_closed_minutes(int64_t current_minute)
{
    static const char sql[] =
        "INSERT INTO metric_bucket(bucket_ts,wan_id,resolution,up_avg,up_min,up_max,"
        "down_avg,down_min,down_max,connections_avg,connections_max,latency_avg,"
        "latency_min,latency_max,sample_count,valid_duration,generation,estimated,source)"
        "VALUES(?1,?2,60,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18) "
        "ON CONFLICT(bucket_ts,wan_id,resolution) DO UPDATE SET "
        "up_avg=excluded.up_avg,up_min=excluded.up_min,up_max=excluded.up_max,"
        "down_avg=excluded.down_avg,down_min=excluded.down_min,down_max=excluded.down_max,"
        "connections_avg=excluded.connections_avg,connections_max=excluded.connections_max,"
        "latency_avg=excluded.latency_avg,latency_min=excluded.latency_min,"
        "latency_max=excluded.latency_max,sample_count=excluded.sample_count,"
        "valid_duration=excluded.valid_duration,generation=excluded.generation,"
        "estimated=excluded.estimated,source=excluded.source";
    sqlite3_stmt *st = NULL;
    int i, wrote = 0, rc = 0;
    if (!g_metrics || sqlite3_prepare_v2(g_metrics, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (metrics_exec("BEGIN IMMEDIATE;") != 0) { sqlite3_finalize(st); return -1; }
    for (i = 0; i < WAN_CAP; i++) {
        if (!g_minutes[i].active || g_minutes[i].bucket_ts >= current_minute)
            continue;
        if (write_minute(st, &g_minutes[i], 0, "native_counter_rate") != 0) {
            rc = -1; break;
        }
        memset(&g_minutes[i], 0, sizeof(g_minutes[i]));
        wrote++;
    }
    sqlite3_finalize(st);
    if (rc == 0 && metrics_exec("COMMIT;") == 0)
        return wrote;
    metrics_exec("ROLLBACK;");
    return -1;
}

static int migrate_legacy_batch(void)
{
    sqlite3_stmt *read = NULL;
    sqlite3_stmt *write = NULL;
    sqlite3_stmt *meta = NULL;
    int64_t cursor = 0;
    int rows = 0;
    if (!g_legacy || !g_metrics) return 0;
    if (sqlite3_prepare_v2(g_metrics,
        "SELECT CAST(value AS INTEGER) FROM metrics_meta WHERE key='legacy_activity_rowid'",
        -1, &meta, NULL) == SQLITE_OK && sqlite3_step(meta) == SQLITE_ROW)
        cursor = sqlite3_column_int64(meta, 0);
    sqlite3_finalize(meta);
    if (sqlite3_prepare_v2(g_legacy,
        "SELECT rowid,ts,wan_id,up_rate,down_rate,connections,latency_avg,latency_min,latency_max "
        "FROM dashboard_activity_sample WHERE rowid>?1 AND wan_id<>'global' "
        "ORDER BY rowid LIMIT ?2", -1, &read, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_int64(read, 1, cursor);
    sqlite3_bind_int(read, 2, MIGRATE_BATCH_ROWS);
    if (sqlite3_prepare_v2(g_metrics,
        "INSERT INTO metric_bucket(bucket_ts,wan_id,resolution,up_avg,up_min,up_max,"
        "down_avg,down_min,down_max,connections_avg,connections_max,latency_avg,"
        "latency_min,latency_max,sample_count,valid_duration,generation,estimated,source) "
        "VALUES(?1,?2,60,?3,?3,?3,?4,?4,?4,?5,?5,?6,?7,?8,1,10,0,1,'legacy_rate_estimate') "
        "ON CONFLICT(bucket_ts,wan_id,resolution) DO UPDATE SET "
        "up_avg=(metric_bucket.up_avg*metric_bucket.sample_count+excluded.up_avg)/(metric_bucket.sample_count+1),"
        "up_min=MIN(metric_bucket.up_min,excluded.up_min),up_max=MAX(metric_bucket.up_max,excluded.up_max),"
        "down_avg=(metric_bucket.down_avg*metric_bucket.sample_count+excluded.down_avg)/(metric_bucket.sample_count+1),"
        "down_min=MIN(metric_bucket.down_min,excluded.down_min),down_max=MAX(metric_bucket.down_max,excluded.down_max),"
        "connections_avg=(metric_bucket.connections_avg*metric_bucket.sample_count+excluded.connections_avg)/(metric_bucket.sample_count+1),"
        "connections_max=MAX(metric_bucket.connections_max,excluded.connections_max),"
        "sample_count=metric_bucket.sample_count+1,valid_duration=MIN(60,metric_bucket.valid_duration+10),"
        "estimated=1,source='legacy_rate_estimate' "
        "WHERE metric_bucket.source='legacy_rate_estimate'",
        -1, &write, NULL) != SQLITE_OK) {
        sqlite3_finalize(read); return -1;
    }
    if (metrics_exec("BEGIN IMMEDIATE;") != 0) {
        sqlite3_finalize(read); sqlite3_finalize(write); return -1;
    }
    while (sqlite3_step(read) == SQLITE_ROW) {
        int64_t ts = sqlite3_column_int64(read, 1);
        cursor = sqlite3_column_int64(read, 0);
        sqlite3_reset(write); sqlite3_clear_bindings(write);
        sqlite3_bind_int64(write, 1, (ts / 60) * 60);
        sqlite3_bind_text(write, 2, (const char *)sqlite3_column_text(read, 2), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(write, 3, sqlite3_column_int64(read, 3));
        sqlite3_bind_int64(write, 4, sqlite3_column_int64(read, 4));
        sqlite3_bind_int(write, 5, sqlite3_column_int(read, 5));
        if (sqlite3_column_type(read, 6) == SQLITE_NULL) sqlite3_bind_null(write, 6);
        else sqlite3_bind_double(write, 6, sqlite3_column_double(read, 6));
        if (sqlite3_column_type(read, 7) == SQLITE_NULL) sqlite3_bind_null(write, 7);
        else sqlite3_bind_double(write, 7, sqlite3_column_double(read, 7));
        if (sqlite3_column_type(read, 8) == SQLITE_NULL) sqlite3_bind_null(write, 8);
        else sqlite3_bind_double(write, 8, sqlite3_column_double(read, 8));
        if (sqlite3_step(write) != SQLITE_DONE) { rows = -1; break; }
        rows++;
    }
    sqlite3_finalize(read); sqlite3_finalize(write);
    if (rows >= 0 && sqlite3_prepare_v2(g_metrics,
        "INSERT INTO metrics_meta(key,value,updated_at) VALUES('legacy_activity_rowid',?1,?2) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
        -1, &meta, NULL) == SQLITE_OK) {
        char value[32]; snprintf(value, sizeof(value), "%lld", (long long)cursor);
        sqlite3_bind_text(meta, 1, value, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(meta, 2, metrics_now());
        if (sqlite3_step(meta) != SQLITE_DONE) rows = -1;
    }
    sqlite3_finalize(meta);
    if (rows >= 0 && metrics_exec("COMMIT;") == 0) return rows;
    metrics_exec("ROLLBACK;");
    return -1;
}

int jmx_metrics_store_maintenance(void)
{
    int64_t now = metrics_now();
    int64_t rollup_cutoff =
        ((now - DAY_SEC) / FIVE_MINUTE_SEC) * FIVE_MINUTE_SEC;
    char sql[4096];
    if (jmx_metrics_store_init() != 0) return -1;
    snprintf(sql, sizeof(sql),
        "BEGIN IMMEDIATE;"
        "INSERT INTO metric_bucket(bucket_ts,wan_id,resolution,up_avg,up_min,up_max,"
        "down_avg,down_min,down_max,connections_avg,connections_max,latency_avg,"
        "latency_min,latency_max,sample_count,valid_duration,generation,estimated,source) "
        "SELECT (bucket_ts/300)*300,wan_id,300,"
        "SUM(up_avg*valid_duration)/SUM(valid_duration),MIN(up_min),MAX(up_max),"
        "SUM(down_avg*valid_duration)/SUM(valid_duration),MIN(down_min),MAX(down_max),"
        "SUM(connections_avg*valid_duration)/SUM(valid_duration),MAX(connections_max),"
        "CASE WHEN COUNT(latency_avg)>0 THEN AVG(latency_avg) END,MIN(latency_min),MAX(latency_max),"
        "SUM(sample_count),SUM(valid_duration),MAX(generation),MAX(estimated),'minute_rollup' "
        "FROM metric_bucket WHERE resolution=60 AND bucket_ts<%lld "
        "GROUP BY (bucket_ts/300)*300,wan_id "
        "ON CONFLICT(bucket_ts,wan_id,resolution) DO UPDATE SET "
        "up_avg=excluded.up_avg,up_min=excluded.up_min,up_max=excluded.up_max,"
        "down_avg=excluded.down_avg,down_min=excluded.down_min,down_max=excluded.down_max,"
        "connections_avg=excluded.connections_avg,connections_max=excluded.connections_max,"
        "latency_avg=excluded.latency_avg,latency_min=excluded.latency_min,latency_max=excluded.latency_max,"
        "sample_count=excluded.sample_count,valid_duration=excluded.valid_duration,"
        "generation=excluded.generation,estimated=excluded.estimated,source=excluded.source;"
        "DELETE FROM metric_bucket WHERE resolution=60 AND bucket_ts<%lld;"
        "DELETE FROM metric_bucket WHERE resolution=300 AND bucket_ts<%lld;"
        "DELETE FROM counter_checkpoint WHERE bucket_ts<%lld;COMMIT;",
        (long long)rollup_cutoff, (long long)rollup_cutoff,
        (long long)(now - RETENTION_SEC), (long long)(now - RETENTION_SEC));
    if (metrics_exec(sql) != 0) { metrics_exec("ROLLBACK;"); return -1; }
    migrate_legacy_batch();
    return 0;
}

void jmx_metrics_record_sample(const char *wan_id, int64_t up_rate,
                               int64_t down_rate, int connections,
                               double latency_avg, double latency_min,
                               double latency_max)
{
    struct hot_sample *h;
    struct minute_acc *a;
    int64_t now = metrics_now();
    int64_t minute = (now / MINUTE_SEC) * MINUTE_SEC;
    if (!wan_id || !wan_id[0] || !strcmp(wan_id, "global")) return;
    if (jmx_metrics_store_init() != 0) return;
    metrics_observe_clock(now);
    if (up_rate < 0) up_rate = 0;
    if (down_rate < 0) down_rate = 0;
    if (g_last_maintenance_minute != minute) {
        flush_closed_minutes(minute);
        if (g_last_maintenance_minute > 0) jmx_metrics_store_maintenance();
        g_last_maintenance_minute = minute;
    }
    h = &g_hot[g_hot_head];
    memset(h, 0, sizeof(*h));
    h->ts = now; snprintf(h->wan_id, sizeof(h->wan_id), "%s", wan_id);
    h->up_rate = up_rate; h->down_rate = down_rate; h->connections = connections;
    h->latency_avg = latency_avg; h->latency_min = latency_min; h->latency_max = latency_max;
    g_hot_head = (g_hot_head + 1) % HOT_CAP;
    if (g_hot_count < HOT_CAP) g_hot_count++;
    a = minute_for(wan_id, minute);
    if (!a) return;
    if (a->bucket_ts != minute) { memset(a, 0, sizeof(*a)); a->active = 1; a->bucket_ts = minute; snprintf(a->wan_id, sizeof(a->wan_id), "%s", wan_id); }
    if (a->samples == 0) {
        a->first_ts = now; a->up_min = a->up_max = up_rate;
        a->down_min = a->down_max = down_rate; a->conn_max = connections;
    } else {
        if (up_rate < a->up_min) a->up_min = up_rate;
        if (up_rate > a->up_max) a->up_max = up_rate;
        if (down_rate < a->down_min) a->down_min = down_rate;
        if (down_rate > a->down_max) a->down_max = down_rate;
        if (connections > a->conn_max) a->conn_max = connections;
    }
    a->last_ts = now; a->samples++; a->up_sum += up_rate; a->down_sum += down_rate; a->conn_sum += connections;
    if (latency_avg > 0) {
        if (a->latency_samples == 0) { a->latency_min = latency_min > 0 ? latency_min : latency_avg; a->latency_max = latency_max > 0 ? latency_max : latency_avg; }
        if (latency_min > 0 && latency_min < a->latency_min) a->latency_min = latency_min;
        if (latency_max > a->latency_max) a->latency_max = latency_max;
        a->latency_sum += latency_avg; a->latency_samples++;
    }
    metrics_snapshot(now);
}

static struct counter_state *counter_for(const char *wan_id)
{
    int i;
    for (i = 0; i < WAN_CAP; i++) if (g_counters[i].active && !strcmp(g_counters[i].wan_id, wan_id)) return &g_counters[i];
    for (i = 0; i < WAN_CAP; i++) if (!g_counters[i].active) { memset(&g_counters[i], 0, sizeof(g_counters[i])); g_counters[i].active = 1; snprintf(g_counters[i].wan_id, sizeof(g_counters[i].wan_id), "%s", wan_id); return &g_counters[i]; }
    return NULL;
}

static void write_checkpoint(struct counter_state *c, int64_t hour, int reset)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_metrics,
        "INSERT INTO counter_checkpoint(bucket_ts,wan_id,raw_rx,raw_tx,total_rx,total_tx,"
        "reset_count,counter_reset,generation,source) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'kernel_counter') "
        "ON CONFLICT(bucket_ts,wan_id) DO UPDATE SET raw_rx=excluded.raw_rx,raw_tx=excluded.raw_tx,"
        "total_rx=excluded.total_rx,total_tx=excluded.total_tx,reset_count=excluded.reset_count,"
        "counter_reset=excluded.counter_reset,generation=excluded.generation", -1, &st, NULL) != SQLITE_OK) return;
    sqlite3_bind_int64(st, 1, hour); sqlite3_bind_text(st, 2, c->wan_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)c->raw_rx); sqlite3_bind_int64(st, 4, (sqlite3_int64)c->raw_tx);
    sqlite3_bind_int64(st, 5, (sqlite3_int64)c->total_rx); sqlite3_bind_int64(st, 6, (sqlite3_int64)c->total_tx);
    sqlite3_bind_int(st, 7, c->reset_count); sqlite3_bind_int(st, 8, reset);
    sqlite3_bind_int64(st, 9, c->generation ? c->generation : g_generation);
    sqlite3_step(st); sqlite3_finalize(st);
}

void jmx_metrics_counter_observe(const char *wan_id, uint64_t rx_bytes,
                                 uint64_t tx_bytes, int online)
{
    struct counter_state *c;
    sqlite3_stmt *st = NULL;
    int64_t now = metrics_now();
    int64_t hour = (now / HOUR_SEC) * HOUR_SEC;
    int reset = 0;
    if (!wan_id || !wan_id[0] || jmx_metrics_store_init() != 0) return;
    metrics_observe_clock(now);
    c = counter_for(wan_id); if (!c) return;
    if (!online) {
        c->online = 0;
        c->last_ts = now;
        return;
    }
    if (!c->first_ts && sqlite3_prepare_v2(g_metrics,
        "SELECT raw_rx,raw_tx,total_rx,total_tx,reset_count,bucket_ts,generation "
        "FROM counter_checkpoint WHERE wan_id=?1 ORDER BY bucket_ts DESC LIMIT 1",
        -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            c->raw_rx = (uint64_t)sqlite3_column_int64(st, 0);
            c->raw_tx = (uint64_t)sqlite3_column_int64(st, 1);
            c->total_rx = (uint64_t)sqlite3_column_int64(st, 2);
            c->total_tx = (uint64_t)sqlite3_column_int64(st, 3);
            c->reset_count = sqlite3_column_int(st, 4);
            c->checkpoint_hour =
                (sqlite3_column_int64(st, 5) / HOUR_SEC) * HOUR_SEC;
            c->generation = sqlite3_column_int64(st, 6);
            c->first_ts = sqlite3_column_int64(st, 5);
        }
        sqlite3_finalize(st);
    }
    if (!c->first_ts) {
        c->first_ts = now;
        c->generation = now;
        c->total_rx = rx_bytes;
        c->total_tx = tx_bytes;
    }
    else {
        if (rx_bytes >= c->raw_rx) c->total_rx += rx_bytes - c->raw_rx; else { c->total_rx += rx_bytes; reset = 1; }
        if (tx_bytes >= c->raw_tx) c->total_tx += tx_bytes - c->raw_tx; else { c->total_tx += tx_bytes; reset = 1; }
        if (reset) {
            c->reset_count++;
            c->generation = now;
        }
    }
    c->raw_rx = rx_bytes; c->raw_tx = tx_bytes; c->last_ts = now; c->online = online;
    if (!c->checkpoint_hour) {
        write_checkpoint(c, now, 0);
        c->checkpoint_hour = hour;
    } else if (c->checkpoint_hour != hour) {
        write_checkpoint(c, now, reset);
        c->checkpoint_hour = hour;
    } else if (reset) {
        write_checkpoint(c, now, 1);
    }
}

static int usage_one(const char *wan_id, int64_t start, int64_t end,
                     int64_t *up, int64_t *down, int *samples, int *reset,
                     int64_t *coverage_start)
{
    sqlite3_stmt *st = NULL;
    int64_t btx = 0, brx = 0, etx = 0, erx = 0, bts = 0;
    int breset = 0, ereset = 0;
    struct counter_state *c = counter_for(wan_id);
    if (sqlite3_prepare_v2(g_metrics,
        "SELECT bucket_ts,total_tx,total_rx,reset_count FROM counter_checkpoint "
        "WHERE wan_id=?1 AND bucket_ts=?2 LIMIT 1", -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT); sqlite3_bind_int64(st, 2, start);
    if (sqlite3_step(st) == SQLITE_ROW) { bts=sqlite3_column_int64(st,0); btx=sqlite3_column_int64(st,1); brx=sqlite3_column_int64(st,2); breset=sqlite3_column_int(st,3); }
    sqlite3_finalize(st); st=NULL;
    if (!bts && sqlite3_prepare_v2(g_metrics,
        "SELECT bucket_ts,total_tx,total_rx,reset_count FROM counter_checkpoint "
        "WHERE wan_id=?1 AND bucket_ts>=?2 AND bucket_ts<=?3 ORDER BY bucket_ts LIMIT 1", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st,1,wan_id,-1,SQLITE_TRANSIENT); sqlite3_bind_int64(st,2,start); sqlite3_bind_int64(st,3,end);
        if (sqlite3_step(st)==SQLITE_ROW) { bts=sqlite3_column_int64(st,0); btx=sqlite3_column_int64(st,1); brx=sqlite3_column_int64(st,2); breset=sqlite3_column_int(st,3); }
    }
    sqlite3_finalize(st);
    if (!bts) return -1;
    if (c && c->active && c->last_ts > 0 && c->last_ts <= end) { etx=c->total_tx; erx=c->total_rx; ereset=c->reset_count; }
    else if (sqlite3_prepare_v2(g_metrics,
        "SELECT total_tx,total_rx,reset_count FROM counter_checkpoint WHERE wan_id=?1 AND bucket_ts<=?2 ORDER BY bucket_ts DESC LIMIT 1", -1, &st, NULL)==SQLITE_OK) {
        sqlite3_bind_text(st,1,wan_id,-1,SQLITE_TRANSIENT); sqlite3_bind_int64(st,2,end);
        if (sqlite3_step(st)==SQLITE_ROW) { etx=sqlite3_column_int64(st,0); erx=sqlite3_column_int64(st,1); ereset=sqlite3_column_int(st,2); }
        sqlite3_finalize(st);
    }
    if (etx < btx || erx < brx) return -1;
    *up += etx-btx; *down += erx-brx; *samples += 2; if (ereset>breset) *reset=1;
    if (!*coverage_start || bts > *coverage_start) *coverage_start=bts;
    return 0;
}

int jmx_metrics_usage_query(const char *wan_id, int64_t start, int64_t end,
                            struct jmx_metrics_usage *out)
{
    sqlite3_stmt *st = NULL;
    int found = 0;
    int64_t coverage_start = 0;
    if (!out || start <= 0 || end <= start || jmx_metrics_store_init() != 0) return -1;
    memset(out,0,sizeof(*out)); out->period_start=start; out->period_end=end;
    if (wan_id && wan_id[0] && strcmp(wan_id,"global") && strcmp(wan_id,"all_wans") && strcmp(wan_id,"*"))
        found = usage_one(wan_id,start,end,&out->up_bytes,&out->down_bytes,&out->sample_count,&out->counter_reset,&coverage_start)==0;
    else if (sqlite3_prepare_v2(g_metrics,
        "SELECT DISTINCT wan_id FROM counter_checkpoint "
        "WHERE bucket_ts>=?1 AND bucket_ts<=?2 AND wan_id<>'global' ORDER BY wan_id",
        -1,&st,NULL)==SQLITE_OK) {
        sqlite3_bind_int64(st,1,start-HOUR_SEC); sqlite3_bind_int64(st,2,end);
        while (sqlite3_step(st)==SQLITE_ROW) { const char *id=(const char *)sqlite3_column_text(st,0); if(id && usage_one(id,start,end,&out->up_bytes,&out->down_bytes,&out->sample_count,&out->counter_reset,&coverage_start)==0) found++; }
        sqlite3_finalize(st);
    }
    if (!found) { snprintf(out->source,sizeof(out->source),"unavailable"); snprintf(out->gap_reason,sizeof(out->gap_reason),"no_counter_checkpoint"); return -1; }
    out->total_bytes=out->up_bytes+out->down_bytes;
    out->completeness_ratio=(double)(end-(coverage_start>start?coverage_start:start))/(double)(end-start);
    if(out->completeness_ratio<0)out->completeness_ratio=0;
    if(out->completeness_ratio>1)out->completeness_ratio=1;
    out->estimated=coverage_start!=start; snprintf(out->source,sizeof(out->source),"counter_checkpoint");
    if(out->completeness_ratio<0.999)snprintf(out->gap_reason,sizeof(out->gap_reason),"checkpoint_window_partial");
    return 0;
}

static const char *req_string(struct json_object *req, const char *key, const char *def)
{ struct json_object *v=NULL; return req && json_object_object_get_ex(req,key,&v) && v ? json_object_get_string(v) : def; }

struct hot_query_acc {
    int active;
    int64_t bucket_ts;
    char wan_id[32];
    int samples;
    int64_t up_sum, down_sum;
    int64_t up_min, up_max, down_min, down_max;
    int64_t conn_sum;
    int conn_max;
    double latency_sum, latency_min, latency_max;
    int latency_samples;
};

static int append_hot_query_buckets(struct json_object *buckets, int64_t cutoff,
                                    int64_t output_res, const char *wan,
                                    int global, int64_t *sample_total)
{
    struct hot_query_acc acc[WAN_CAP * 16];
    size_t i;
    int used = 0, added = 0;

    memset(acc, 0, sizeof(acc));
    for (i = 0; i < g_hot_count; i++) {
        size_t idx = (g_hot_head + HOT_CAP - g_hot_count + i) % HOT_CAP;
        const struct hot_sample *s = &g_hot[idx];
        int64_t bucket;
        int j;

        if (s->ts < cutoff || (!global && strcmp(s->wan_id, wan)))
            continue;
        bucket = (s->ts / output_res) * output_res;
        for (j = 0; j < used; j++)
            if (acc[j].bucket_ts == bucket && !strcmp(acc[j].wan_id, s->wan_id))
                break;
        if (j == used) {
            if (used >= (int)(sizeof(acc) / sizeof(acc[0])))
                continue;
            acc[j].active = 1;
            acc[j].bucket_ts = bucket;
            snprintf(acc[j].wan_id, sizeof(acc[j].wan_id), "%s", s->wan_id);
            acc[j].up_min = acc[j].up_max = s->up_rate;
            acc[j].down_min = acc[j].down_max = s->down_rate;
            acc[j].conn_max = s->connections;
            used++;
        }
        acc[j].samples++;
        acc[j].up_sum += s->up_rate;
        acc[j].down_sum += s->down_rate;
        acc[j].conn_sum += s->connections;
        if (s->up_rate < acc[j].up_min) acc[j].up_min = s->up_rate;
        if (s->up_rate > acc[j].up_max) acc[j].up_max = s->up_rate;
        if (s->down_rate < acc[j].down_min) acc[j].down_min = s->down_rate;
        if (s->down_rate > acc[j].down_max) acc[j].down_max = s->down_rate;
        if (s->connections > acc[j].conn_max) acc[j].conn_max = s->connections;
        if (s->latency_avg > 0) {
            if (!acc[j].latency_samples) {
                acc[j].latency_min = s->latency_min > 0 ? s->latency_min : s->latency_avg;
                acc[j].latency_max = s->latency_max > 0 ? s->latency_max : s->latency_avg;
            }
            if (s->latency_min > 0 && s->latency_min < acc[j].latency_min)
                acc[j].latency_min = s->latency_min;
            if (s->latency_max > acc[j].latency_max)
                acc[j].latency_max = s->latency_max;
            acc[j].latency_sum += s->latency_avg;
            acc[j].latency_samples++;
        }
    }
    for (i = 0; i < (size_t)used; ) {
        if (!acc[i].active) {
            i++;
            continue;
        }
        int64_t bucket = acc[i].bucket_ts;
        int j;
        int64_t up_avg = 0, down_avg = 0, conn_avg = 0;
        int64_t up_min = 0, up_max = 0, down_min = 0, down_max = 0;
        int conn_max = 0, samples = 0, latency_series = 0;
        double latency_avg = 0, latency_min = 0, latency_max = 0;
        struct json_object *b;

        for (j = 0; j < used; j++) {
            struct hot_query_acc *a = &acc[j];
            if (!a->active || a->bucket_ts != bucket || a->samples <= 0)
                continue;
            up_avg += a->up_sum / a->samples;
            down_avg += a->down_sum / a->samples;
            conn_avg += a->conn_sum / a->samples;
            up_min += a->up_min; up_max += a->up_max;
            down_min += a->down_min; down_max += a->down_max;
            conn_max += a->conn_max;
            if (a->latency_samples) {
                double av = a->latency_sum / a->latency_samples;
                latency_avg += av;
                if (!latency_series || a->latency_min < latency_min) latency_min = a->latency_min;
                if (!latency_series || a->latency_max > latency_max) latency_max = a->latency_max;
                latency_series++;
            }
            if (a->samples > samples) samples = a->samples;
            a->active = 0;
        }
        b = json_object_new_object();
        json_object_object_add(b, "ts", json_object_new_int64(bucket));
        json_object_object_add(b, "up_avg", json_object_new_int64(up_avg));
        json_object_object_add(b, "up_min", json_object_new_int64(up_min));
        json_object_object_add(b, "up_max", json_object_new_int64(up_max));
        json_object_object_add(b, "down_avg", json_object_new_int64(down_avg));
        json_object_object_add(b, "down_min", json_object_new_int64(down_min));
        json_object_object_add(b, "down_max", json_object_new_int64(down_max));
        json_object_object_add(b, "connections", json_object_new_int64(conn_avg));
        json_object_object_add(b, "connections_avg", json_object_new_int64(conn_avg));
        json_object_object_add(b, "connections_max", json_object_new_int(conn_max));
        if (latency_series) {
            json_object_object_add(b, "latency_avg",
                                   json_object_new_double(latency_avg / latency_series));
            json_object_object_add(b, "latency_min", json_object_new_double(latency_min));
            json_object_object_add(b, "latency_max", json_object_new_double(latency_max));
        }
        json_object_object_add(b, "sample_count", json_object_new_int(samples));
        json_object_object_add(b, "valid_duration",
                               json_object_new_int(samples * 2 > output_res ?
                                                   (int)output_res : samples * 2));
        json_object_object_add(b, "source", json_object_new_string("memory_hot"));
        {
            size_t n = json_object_array_length(buckets);
            struct json_object *existing = NULL;
            size_t k;

            for (k = 0; k < n; k++) {
                struct json_object *candidate = json_object_array_get_idx(buckets, k);
                struct json_object *candidate_ts = NULL;

                if (candidate &&
                    json_object_object_get_ex(candidate, "ts", &candidate_ts) &&
                    json_object_get_int64(candidate_ts) == bucket) {
                    existing = candidate;
                    break;
                }
            }
            if (existing) {
                static const char *avg_names[] = {
                    "up_avg", "down_avg", "connections_avg", NULL
                };
                static const char *min_names[] = {
                    "up_min", "down_min", NULL
                };
                static const char *max_names[] = {
                    "up_max", "down_max", "connections_max", NULL
                };
                struct json_object *old_value = NULL;
                struct json_object *new_value = NULL;
                int64_t old_duration = 0;
                int64_t new_duration = 0;
                int64_t total_duration;
                int m;

                if (json_object_object_get_ex(existing, "valid_duration", &old_value))
                    old_duration = json_object_get_int64(old_value);
                if (json_object_object_get_ex(b, "valid_duration", &new_value))
                    new_duration = json_object_get_int64(new_value);
                total_duration = old_duration + new_duration;
                if (total_duration > output_res)
                    total_duration = output_res;
                for (m = 0; avg_names[m]; m++) {
                    double old_avg = 0;
                    double new_avg = 0;

                    if (json_object_object_get_ex(existing, avg_names[m], &old_value))
                        old_avg = json_object_get_double(old_value);
                    if (json_object_object_get_ex(b, avg_names[m], &new_value))
                        new_avg = json_object_get_double(new_value);
                    if (old_duration + new_duration > 0)
                        json_object_object_add(existing, avg_names[m],
                            json_object_new_double((old_avg * old_duration +
                                                    new_avg * new_duration) /
                                                   (old_duration + new_duration)));
                }
                if (json_object_object_get_ex(existing, "connections_avg", &old_value))
                    json_object_object_add(existing, "connections",
                                           json_object_get(old_value));
                {
                    struct json_object *old_latency = NULL;
                    struct json_object *new_latency = NULL;
                    int have_old = json_object_object_get_ex(existing, "latency_avg",
                                                             &old_latency);
                    int have_new = json_object_object_get_ex(b, "latency_avg",
                                                             &new_latency);

                    if (have_old && have_new && old_duration + new_duration > 0) {
                        double merged =
                            (json_object_get_double(old_latency) * old_duration +
                             json_object_get_double(new_latency) * new_duration) /
                            (old_duration + new_duration);
                        json_object_object_add(existing, "latency_avg",
                                               json_object_new_double(merged));
                    } else if (have_new) {
                        json_object_object_add(existing, "latency_avg",
                                               json_object_get(new_latency));
                    }
                    if (json_object_object_get_ex(b, "latency_min", &new_latency)) {
                        if (!json_object_object_get_ex(existing, "latency_min",
                                                       &old_latency) ||
                            json_object_get_double(new_latency) <
                                json_object_get_double(old_latency))
                            json_object_object_add(existing, "latency_min",
                                                   json_object_get(new_latency));
                    }
                    if (json_object_object_get_ex(b, "latency_max", &new_latency)) {
                        if (!json_object_object_get_ex(existing, "latency_max",
                                                       &old_latency) ||
                            json_object_get_double(new_latency) >
                                json_object_get_double(old_latency))
                            json_object_object_add(existing, "latency_max",
                                                   json_object_get(new_latency));
                    }
                }
                for (m = 0; min_names[m]; m++) {
                    int64_t old_min = 0;
                    int64_t new_min = 0;

                    if (json_object_object_get_ex(existing, min_names[m], &old_value))
                        old_min = json_object_get_int64(old_value);
                    if (json_object_object_get_ex(b, min_names[m], &new_value))
                        new_min = json_object_get_int64(new_value);
                    json_object_object_add(existing, min_names[m],
                        json_object_new_int64(old_min < new_min ? old_min : new_min));
                }
                for (m = 0; max_names[m]; m++) {
                    int64_t old_max = 0;
                    int64_t new_max = 0;

                    if (json_object_object_get_ex(existing, max_names[m], &old_value))
                        old_max = json_object_get_int64(old_value);
                    if (json_object_object_get_ex(b, max_names[m], &new_value))
                        new_max = json_object_get_int64(new_value);
                    json_object_object_add(existing, max_names[m],
                        json_object_new_int64(old_max > new_max ? old_max : new_max));
                }
                if (json_object_object_get_ex(existing, "sample_count", &old_value) &&
                    json_object_object_get_ex(b, "sample_count", &new_value))
                    json_object_object_add(existing, "sample_count",
                        json_object_new_int64(json_object_get_int64(old_value) +
                                              json_object_get_int64(new_value)));
                json_object_object_add(existing, "valid_duration",
                                       json_object_new_int64(total_duration));
                json_object_object_add(existing, "source",
                                       json_object_new_string("metrics_store+memory_hot"));
                json_object_put(b);
            } else {
                json_object_array_add(buckets, b);
            }
        }
        if (sample_total) *sample_total += samples;
        added++;
        i++;
    }
    return added;
}

static int64_t hot_query_start(const char *wan, int global, int64_t now)
{
    int64_t start = (now / MINUTE_SEC) * MINUTE_SEC;
    int64_t cutoff = now - HOT_RETENTION_SEC;
    size_t i;

    for (i = 0; i < g_hot_count; i++) {
        size_t idx = (g_hot_head + HOT_CAP - g_hot_count + i) % HOT_CAP;
        const struct hot_sample *s = &g_hot[idx];
        int64_t bucket;

        if (s->ts < cutoff || (!global && strcmp(s->wan_id, wan)))
            continue;
        bucket = (s->ts / MINUTE_SEC) * MINUTE_SEC;
        if (bucket < start)
            start = bucket;
    }
    return start;
}

struct json_object *jmx_metrics_activity_api(struct json_object *req)
{
    const char *range=req_string(req,"range","1d"); const char *wan=req_string(req,"wan_id","");
    int64_t now=metrics_now(), retention=DAY_SEC, output_res=300;
    int64_t hot_start;
    int64_t minute_start;
    int source_res=60;
    int global=!wan||!wan[0]||!strcmp(wan,"all")||!strcmp(wan,"global");
    sqlite3_stmt *st=NULL; struct json_object *data=json_object_new_object(), *buckets=json_object_new_array();
    char sql[4096]; int64_t samples=0, expected; int estimated=0;
    if(!strcmp(range,"1h")){retention=3600;output_res=60;} else if(!strcmp(range,"1d")){retention=DAY_SEC;output_res=300;} else if(!strcmp(range,"1w")){retention=7LL*DAY_SEC;output_res=3600;} else if(!strcmp(range,"1m")){retention=30LL*DAY_SEC;output_res=DAY_SEC;} else range="1d";
    if(jmx_metrics_store_init()!=0) return jmx_gen_api_response_data(API_CODE_ERROR,data);
    source_res=(retention>DAY_SEC)?300:60;
    hot_start=hot_query_start(wan,global,now);
    minute_start=((now-DAY_SEC)/FIVE_MINUTE_SEC)*FIVE_MINUTE_SEC;
    snprintf(sql,sizeof(sql),
      "WITH p AS (SELECT bucket_ts,SUM(up_avg) up_avg,SUM(up_min) up_min,SUM(up_max) up_max,"
      "SUM(down_avg) down_avg,SUM(down_min) down_min,SUM(down_max) down_max,"
      "SUM(connections_avg) conn_avg,SUM(connections_max) conn_max,AVG(latency_avg) lat_avg,"
      "MIN(latency_min) lat_min,MAX(latency_max) lat_max,MAX(sample_count) samples,"
      "MAX(valid_duration) duration,MAX(estimated) estimated FROM metric_bucket "
      "WHERE bucket_ts>=?1 AND bucket_ts<?2 AND wan_id<>'global' AND "
      "((?3=60 AND resolution=60) OR "
      "(?3=300 AND ((resolution=300 AND bucket_ts<?4) OR "
      "(resolution=60 AND bucket_ts>=?4)))) %s GROUP BY bucket_ts) "
      "SELECT (bucket_ts/?5)*?5,SUM(up_avg*duration)/SUM(duration),MIN(up_min),MAX(up_max),"
      "SUM(down_avg*duration)/SUM(duration),MIN(down_min),MAX(down_max),"
      "SUM(conn_avg*duration)/SUM(duration),MAX(conn_max),AVG(lat_avg),MIN(lat_min),MAX(lat_max),"
      "SUM(samples),SUM(duration),MAX(estimated) FROM p GROUP BY (bucket_ts/?5)*?5 ORDER BY 1",
      global?"":"AND wan_id=?6");
    if(sqlite3_prepare_v2(g_metrics,sql,-1,&st,NULL)==SQLITE_OK){
      sqlite3_bind_int64(st,1,now-retention);sqlite3_bind_int64(st,2,hot_start);sqlite3_bind_int(st,3,source_res);sqlite3_bind_int64(st,4,minute_start);sqlite3_bind_int64(st,5,output_res);if(!global)sqlite3_bind_text(st,6,wan,-1,SQLITE_TRANSIENT);
      while(sqlite3_step(st)==SQLITE_ROW){struct json_object *b=json_object_new_object(); int i; const char *names[]={"ts","up_avg","up_min","up_max","down_avg","down_min","down_max","connections_avg","connections_max","latency_avg","latency_min","latency_max","sample_count","valid_duration"}; for(i=0;i<14;i++){if(sqlite3_column_type(st,i)==SQLITE_NULL)continue;if(i==9||i==10||i==11)json_object_object_add(b,names[i],json_object_new_double(sqlite3_column_double(st,i)));else json_object_object_add(b,names[i],json_object_new_int64(sqlite3_column_int64(st,i)));} json_object_object_add(b,"source",json_object_new_string(source_res==60?"metrics_minute":"metrics_mixed_rollup")); samples+=sqlite3_column_int64(st,12); if(sqlite3_column_int(st,14))estimated=1; json_object_array_add(buckets,b);}
      sqlite3_finalize(st);
    }
    append_hot_query_buckets(buckets, hot_start, output_res,
                             wan, global, &samples);
    expected=(retention/2)*(global?1:1);
    json_object_object_add(data,"ts",json_object_new_int64(now));json_object_object_add(data,"range",json_object_new_string(range));json_object_object_add(data,"wan_id",json_object_new_string(global?"":wan));json_object_object_add(data,"scope",json_object_new_string(global?"global":"wan"));
    json_object_object_add(data,"start_ts",json_object_new_int64(now-retention));json_object_object_add(data,"end_ts",json_object_new_int64(now));json_object_object_add(data,"bucket_sec",json_object_new_int64(output_res));json_object_object_add(data,"retention_sec",json_object_new_int64(retention));json_object_object_add(data,"resolution_sec",json_object_new_int(source_res));
    json_object_object_add(data,"source",json_object_new_string(source_res==60?"metrics_minute":"metrics_mixed_rollup"));json_object_object_add(data,"hot_source",json_object_new_string("memory_hot"));json_object_object_add(data,"sample_count",json_object_new_int64(samples));json_object_object_add(data,"expected_sample_count",json_object_new_int64(expected));json_object_object_add(data,"completeness_ratio",json_object_new_double(expected>0?(samples>expected?1.0:(double)samples/expected):0));json_object_object_add(data,"generation",json_object_new_int64(g_generation));json_object_object_add(data,"gap_reason",json_object_new_string(g_hot_gap_reason));json_object_object_add(data,"counter_reset",json_object_new_boolean(0));json_object_object_add(data,"estimated",json_object_new_boolean(estimated));json_object_object_add(data,"period_start",json_object_new_int64(now-retention));json_object_object_add(data,"period_end",json_object_new_int64(now));json_object_object_add(data,"unit",json_object_new_string("B/s"));json_object_object_add(data,"latency_unit",json_object_new_string("ms"));
    if(json_object_array_length(buckets)==0){json_object_object_add(data,"degraded",json_object_new_boolean(1));json_object_object_add(data,"missing",json_object_new_string("no metrics buckets yet"));}
    json_object_object_add(data,"buckets",buckets); return jmx_gen_api_response_data(API_CODE_SUCCESS,data);
}

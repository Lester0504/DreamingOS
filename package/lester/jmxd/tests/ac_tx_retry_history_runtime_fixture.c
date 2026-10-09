// SPDX-License-Identifier: GPL-2.0-or-later
/* Exercises the AC's TX retry cursor, buckets and history query.
 *
 * The chain under test is deliberately separate from the Survey one: retry
 * counters come from a different producer (`apstats -v` summed over VAPs) and
 * can be unavailable while airtime works. Every case here is one the handoff
 * names: warming-up on the first sample, a recomputable delta on the second,
 * rebaselining on wrap / clock rewind / source change, refusal of instantaneous
 * rates, retention, and readability after a restart.
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>
#include <sqlite3.h>

#define AP_ID "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
#define EPOCH "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define EPOCH_B "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
#define BASE 20000000

struct ac_device_model_report {
    char model[256];
    char board_name[128];
    char model_source[64];
    char reason[128];
    int model_available;
};

extern sqlite3 *g_ac_db;
int ac_db_init(void);
void ac_db_close(void);
int ac_db_ap_session_begin(const char *, const char *, int, int64_t);
int ac_db_ap_telemetry_store(const char *, const char *, int64_t, int64_t,
                             int64_t, const char *,
                             const struct ac_device_model_report *,
                             struct json_object *);
struct json_object *ac_db_tx_retry_history_json(const char *, const char *,
                                                int64_t, int64_t, int, int,
                                                int64_t);

static int scalar(const char *sql)
{
    sqlite3_stmt *st = NULL;
    int result = -1;

    if (sqlite3_prepare_v2(g_ac_db, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        result = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return result;
}

static double scalar_double(const char *sql)
{
    sqlite3_stmt *st = NULL;
    double result = -1.0;

    if (sqlite3_prepare_v2(g_ac_db, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        result = sqlite3_column_double(st, 0);
    sqlite3_finalize(st);
    return result;
}

enum retry_shape {
    RETRY_SHAPE_CUMULATIVE = 0,
    /* Cumulative counters present but not declared cumulative. */
    RETRY_SHAPE_NO_SEMANTICS,
    /* Producer says it has no retry source. */
    RETRY_SHAPE_UNAVAILABLE,
    /* Only the instantaneous percentage, which must never seed history. */
    RETRY_SHAPE_RATE_ONLY,
};

static struct json_object *snapshot_new(int64_t observed_at, int64_t tx_total,
                                        int64_t tx_retries, const char *source,
                                        enum retry_shape shape)
{
    struct json_object *root = json_object_new_object();
    struct json_object *radios = json_object_new_array();
    struct json_object *radio = json_object_new_object();
    struct json_object *survey = json_object_new_object();
    struct json_object *air = json_object_new_object();

    if (!root || !radios || !radio || !survey || !air)
        goto fail;
    json_object_object_add(root, "observed_at",
                           json_object_new_int64(observed_at));
    json_object_object_add(root, "complete", json_object_new_boolean(1));
    json_object_object_add(root, "radios", radios);
    json_object_object_add(root, "ssids", json_object_new_array());
    json_object_object_add(root, "stations", json_object_new_array());
    json_object_object_add(radio, "id", json_object_new_string("phy0"));
    json_object_object_add(survey, "source",
                           json_object_new_string("apstats_radio"));
    json_object_object_add(survey, "complete", json_object_new_boolean(1));
    json_object_object_add(survey, "interface", json_object_new_string("ath0"));
    /* Radio-level `retries` is a different counter and must not be mistaken for
     * the VAP aggregate; it is present here on purpose. */
    json_object_object_add(air, "retries", json_object_new_int64(7));
    json_object_object_add(air, "retry_rate_pct",
                           json_object_new_double(3.5));
    if (shape != RETRY_SHAPE_UNAVAILABLE && shape != RETRY_SHAPE_RATE_ONLY) {
        json_object_object_add(air, "tx_total",
                               json_object_new_int64(tx_total));
        json_object_object_add(air, "tx_retries",
                               json_object_new_int64(tx_retries));
        json_object_object_add(air, "tx_retry_available",
                               json_object_new_boolean(1));
        json_object_object_add(air, "tx_retry_source",
                               json_object_new_string(source));
        if (shape == RETRY_SHAPE_CUMULATIVE)
            json_object_object_add(air, "tx_retry_counter_semantics",
                                   json_object_new_string("cumulative"));
        else
            json_object_object_add(air, "tx_retry_counter_semantics",
                                   json_object_new_string("instantaneous"));
    } else if (shape == RETRY_SHAPE_RATE_ONLY) {
        json_object_object_add(air, "tx_retry_available",
                               json_object_new_boolean(1));
        json_object_object_add(air, "tx_retry_source",
                               json_object_new_string(source));
        json_object_object_add(air, "tx_retry_counter_semantics",
                               json_object_new_string("cumulative"));
    } else {
        json_object_object_add(air, "tx_retry_available",
                               json_object_new_boolean(0));
        json_object_object_add(air, "tx_retry_reason",
            json_object_new_string("apstats_vap_retries_absent"));
    }
    json_object_object_add(survey, "air_stats", air);
    json_object_object_add(radio, "survey", survey);
    json_object_array_add(radios, radio);
    return root;
fail:
    json_object_put(air);
    json_object_put(survey);
    json_object_put(radio);
    json_object_put(radios);
    json_object_put(root);
    return NULL;
}

static int store(const struct ac_device_model_report *report, int64_t sequence,
                 const char *epoch, int64_t received_at, int64_t tx_total,
                 int64_t tx_retries, const char *source, enum retry_shape shape)
{
    struct json_object *snapshot = snapshot_new(received_at, tx_total,
                                                tx_retries, source, shape);
    char snapshot_id[80];
    int rc;

    if (!snapshot)
        return -1;
    snprintf(snapshot_id, sizeof(snapshot_id), "retry-%lld",
             (long long)sequence);
    rc = ac_db_ap_telemetry_store(AP_ID, epoch, sequence, received_at,
                                  received_at, snapshot_id, report, snapshot);
    json_object_put(snapshot);
    return rc;
}

static int bucket_count(void)
{
    return scalar("SELECT COUNT(*) FROM ac_radio_tx_retry_bucket "
                  "WHERE ap_id='" AP_ID "' AND radio_id='phy0'");
}

static int cursor_total(void)
{
    return scalar("SELECT tx_total FROM ac_radio_tx_retry_cursor "
                  "WHERE ap_id='" AP_ID "' AND radio_id='phy0'");
}

static int history_points(int64_t start, int64_t end, int limit,
                          int64_t after_id, const char **reason_out)
{
    struct json_object *page = ac_db_tx_retry_history_json(AP_ID, "phy0", start,
                                                          end, 300, limit,
                                                          after_id);
    struct json_object *points = NULL;
    struct json_object *value = NULL;
    static char reason[64];
    int count = -1;

    reason[0] = '\0';
    if (page && json_object_object_get_ex(page, "ok", &value) &&
        json_object_get_boolean(value) &&
        json_object_object_get_ex(page, "points", &points))
        count = (int)json_object_array_length(points);
    if (page && json_object_object_get_ex(page, "reason", &value) && value &&
        json_object_is_type(value, json_type_string))
        snprintf(reason, sizeof(reason), "%s", json_object_get_string(value));
    if (reason_out)
        *reason_out = reason;
    json_object_put(page);
    return count;
}

static int contract(void)
{
    struct ac_device_model_report report = {0};
    struct json_object *page = NULL;
    struct json_object *points = NULL;
    struct json_object *point = NULL;
    struct json_object *value = NULL;
    const char *reason = NULL;
    int64_t cursor;
    int rc = -1;

    snprintf(report.model, sizeof(report.model), "Retry Fixture AP");
    snprintf(report.board_name, sizeof(report.board_name), "fixture,retry");
    snprintf(report.model_source, sizeof(report.model_source), "fixture");
    report.model_available = 1;
    if (sqlite3_exec(g_ac_db,
            "INSERT INTO ac_aps(ap_id,site_id,name,adoption_state,last_seen_at) "
            "VALUES('" AP_ID "','default','Retry Fixture','adopted',1)",
            NULL, NULL, NULL) != SQLITE_OK ||
        ac_db_ap_session_begin(AP_ID, EPOCH, 2, BASE) != 0)
        return 1;

    /* An instantaneous-only payload must not seed the cursor: reversing a
     * percentage into counters is exactly the fabrication the handoff bans. */
    if (store(&report, 1, EPOCH, BASE, 0, 0, "apstats_vap_aggregate",
              RETRY_SHAPE_RATE_ONLY) != 0)
        return 2;
    if (scalar("SELECT COUNT(*) FROM ac_radio_tx_retry_cursor") != 0)
        return 3;
    /* Cumulative numbers not declared cumulative are equally unusable. */
    if (store(&report, 2, EPOCH, BASE + 300, 1000, 50, "apstats_vap_aggregate",
              RETRY_SHAPE_NO_SEMANTICS) != 0)
        return 4;
    if (scalar("SELECT COUNT(*) FROM ac_radio_tx_retry_cursor") != 0)
        return 5;
    /* Producer reporting no retry source at all. */
    if (store(&report, 3, EPOCH, BASE + 600, 0, 0, "apstats_vap_aggregate",
              RETRY_SHAPE_UNAVAILABLE) != 0)
        return 6;
    if (scalar("SELECT COUNT(*) FROM ac_radio_tx_retry_cursor") != 0)
        return 7;

    /* First usable sample: cursor only, no bucket. */
    if (store(&report, 4, EPOCH, BASE + 900, 100000, 4000,
              "apstats_vap_aggregate", RETRY_SHAPE_CUMULATIVE) != 0)
        return 8;
    if (scalar("SELECT COUNT(*) FROM ac_radio_tx_retry_cursor") != 1 ||
        bucket_count() != 0)
        return 9;
    if (history_points(BASE, BASE + 100000, 16, 0, &reason) != 0 ||
        strcmp(reason, "warming_up"))
        return 10;

    /* Second usable sample 300s later: one bucket whose deltas recompute. */
    if (store(&report, 5, EPOCH, BASE + 1200, 110000, 4500,
              "apstats_vap_aggregate", RETRY_SHAPE_CUMULATIVE) != 0)
        return 11;
    if (bucket_count() != 1)
        return 12;
    if (scalar("SELECT tx_total_delta FROM ac_radio_tx_retry_bucket") != 10000 ||
        scalar("SELECT tx_retries_delta FROM ac_radio_tx_retry_bucket") != 500)
        return 13;
    if (fabs(scalar_double("SELECT retry_rate_pct FROM ac_radio_tx_retry_bucket")
             - 5.0) > 0.000001)
        return 14;

    /* Below the minimum interval: ignored rather than written as a spike. */
    if (store(&report, 6, EPOCH, BASE + 1260, 111000, 4600,
              "apstats_vap_aggregate", RETRY_SHAPE_CUMULATIVE) != 0)
        return 15;
    if (bucket_count() != 1 || cursor_total() != 110000)
        return 16;

    /* Counter wrap: drop the delta, rebaseline on the smaller value. */
    if (store(&report, 7, EPOCH, BASE + 1500, 500, 10,
              "apstats_vap_aggregate", RETRY_SHAPE_CUMULATIVE) != 0)
        return 17;
    if (bucket_count() != 1 || cursor_total() != 500)
        return 18;

    /* Source change with monotonic counters: still a rebaseline, because two
     * producers' totals are not differenceable against each other. */
    if (store(&report, 8, EPOCH, BASE + 1800, 900, 20,
              "apstats_vap_aggregate", RETRY_SHAPE_CUMULATIVE) != 0 ||
        bucket_count() != 2)
        return 19;
    if (store(&report, 9, EPOCH, BASE + 2100, 1400, 40,
              "other_producer", RETRY_SHAPE_CUMULATIVE) != 0)
        return 20;
    if (bucket_count() != 2)
        return 21;
    if (scalar("SELECT COUNT(*) FROM ac_radio_tx_retry_cursor "
               "WHERE source='other_producer'") != 1)
        return 22;

    /* Session change: a new APD session restarts its counters, so the first
     * sample of the new epoch rebaselines instead of differencing. */
    if (ac_db_ap_session_begin(AP_ID, EPOCH_B, 3, BASE + 2400) != 0)
        return 23;
    if (store(&report, 1, EPOCH_B, BASE + 2400, 50, 1, "other_producer",
              RETRY_SHAPE_CUMULATIVE) != 0)
        return 24;
    if (bucket_count() != 2)
        return 25;

    /* Clock rewind inside one session rebaselines rather than producing a
     * negative interval. */
    if (store(&report, 2, EPOCH_B, BASE + 2700, 4000, 100, "other_producer",
              RETRY_SHAPE_CUMULATIVE) != 0 ||
        bucket_count() != 3)
        return 26;
    if (sqlite3_exec(g_ac_db,
            "UPDATE ac_radio_tx_retry_cursor SET received_at=" "99999999"
            " WHERE ap_id='" AP_ID "'", NULL, NULL, NULL) != SQLITE_OK)
        return 27;
    if (store(&report, 3, EPOCH_B, BASE + 3000, 9000, 300, "other_producer",
              RETRY_SHAPE_CUMULATIVE) != 0)
        return 28;
    if (bucket_count() != 3)
        return 29;

    /* Query contract: paging is stable and the cursor resumes without
     * duplicating or skipping a point. */
    page = ac_db_tx_retry_history_json(AP_ID, "phy0", BASE, BASE + 100000, 300,
                                       2, 0);
    if (!page || !json_object_object_get_ex(page, "points", &points) ||
        json_object_array_length(points) != 2 ||
        !json_object_object_get_ex(page, "limited", &value) ||
        !json_object_get_boolean(value) ||
        !json_object_object_get_ex(page, "next_cursor", &value))
        goto done;
    cursor = json_object_get_int64(value);
    point = json_object_array_get_idx(points, 0);
    /* The published point must carry the differenced pair, not the raw
     * cumulative counters, and must name its producer. */
    if (!json_object_object_get_ex(point, "tx_total_delta", &value) ||
        json_object_get_int64(value) != 10000 ||
        !json_object_object_get_ex(point, "tx_retries_delta", &value) ||
        json_object_get_int64(value) != 500 ||
        !json_object_object_get_ex(point, "source", &value) ||
        strcmp(json_object_get_string(value), "apstats_vap_aggregate"))
        goto done;
    json_object_put(page);
    page = ac_db_tx_retry_history_json(AP_ID, "phy0", BASE, BASE + 100000, 300,
                                       16, cursor);
    if (!page || !json_object_object_get_ex(page, "points", &points) ||
        json_object_array_length(points) != 1)
        goto done;
    json_object_put(page);
    page = NULL;

    /* An out-of-range window is empty rather than an error. The baseline still
     * exists, so the reason is warming_up, not "this radio has no counters". */
    if (history_points(BASE + 500000, BASE + 600000, 16, 0, &reason) != 0 ||
        strcmp(reason, "warming_up"))
        goto done;
    /* A radio that never reported retry counters is a different state. */
    if (history_points(BASE, BASE + 100000, 16, 0, &reason) < 1)
        goto done;
    {
        struct json_object *other = ac_db_tx_retry_history_json(AP_ID, "phy9",
            BASE, BASE + 100000, 300, 16, 0);
        const char *other_reason = NULL;

        if (other && json_object_object_get_ex(other, "reason", &value) &&
            value && json_object_is_type(value, json_type_string))
            other_reason = json_object_get_string(value);
        if (!other_reason || strcmp(other_reason, "no_samples")) {
            json_object_put(other);
            goto done;
        }
        json_object_put(other);
    }
    /* A rejected query must be distinguishable from an empty one. */
    page = ac_db_tx_retry_history_json(AP_ID, "phy0", BASE + 100, BASE, 300, 16,
                                       0);
    if (!page || !json_object_object_get_ex(page, "ok", &value) ||
        json_object_get_boolean(value) ||
        !json_object_object_get_ex(page, "error", &value) ||
        strcmp(json_object_get_string(value),
               "invalid_tx_retry_history_query"))
        goto done;
    json_object_put(page);
    page = NULL;

    /* Retention has two independent limits and they must be exercised
     * separately. These 600 rows sit inside the 48h time window on purpose, so
     * what trims them is the row cap rather than the age cut -- otherwise the
     * row limit would never be reached and this case would prove nothing. */
    if (sqlite3_exec(g_ac_db,
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<600) "
            "INSERT OR REPLACE INTO ac_radio_tx_retry_bucket(ap_id,radio_id,"
            "resolution_seconds,bucket_start,first_received_at,last_received_at,"
            "sample_count,tx_total_delta,tx_retries_delta,retry_rate_pct,source) "
            "SELECT '" AP_ID "','phy0',300,40000000+x*300,40000000+x*300,"
            "40000000+x*300,1,100,5,5.0,'other_producer' FROM n;",
            NULL, NULL, NULL) != SQLITE_OK)
        goto done;
    /* Two samples one interval apart: the first only rebaselines (the jump from
     * the previous sample exceeds the gap threshold), the second produces the
     * delta whose write runs the prune. */
    if (store(&report, 4, EPOCH_B, 40200000, 20000, 900, "other_producer",
              RETRY_SHAPE_CUMULATIVE) != 0 ||
        store(&report, 5, EPOCH_B, 40200300, 21000, 950, "other_producer",
              RETRY_SHAPE_CUMULATIVE) != 0)
        goto done;
    if (bucket_count() > 576)
        goto done;
    /* The row cap has to actually be the thing that bounded the table, not an
     * age cut that emptied it: a near-full table proves the trim kept the
     * newest 576 instead of discarding everything. */
    if (bucket_count() < 500)
        goto done;
    /* The prune must trim the oldest rows, not the newest: the bucket that was
     * just written has to survive its own retention pass. */
    if (scalar("SELECT COUNT(*) FROM ac_radio_tx_retry_bucket "
               "WHERE bucket_start=40200300-40200300%300") != 1)
        goto done;

    printf("schema=%d warming_up=1 delta_recomputed=1 wrap_rebaselined=1 "
           "source_change_rebaselined=1 session_change_rebaselined=1 "
           "rewind_rebaselined=1 rate_only_rejected=1 semantics_enforced=1 "
           "paging=1 bounded_rows=%d\n",
           scalar("SELECT version FROM ac_schema_meta WHERE singleton=1"),
           bucket_count());
    rc = 0;
done:
    json_object_put(page);
    return rc;
}

int main(int argc, char **argv)
{
    int rc;

    if (ac_db_init() != 0)
        return 2;
    if (argc == 2 && !strcmp(argv[1], "init-only")) {
        ac_db_close();
        return 0;
    }
    /* Reopening the same database must find the buckets still queryable, which
     * is the "survives a restart" requirement. */
    if (argc == 2 && !strcmp(argv[1], "readback")) {
        const char *reason = NULL;
        int count = history_points(BASE, 50000000, 16, 0, &reason);

        printf("readback_points=%d readback_reason=%s\n", count,
               reason ? reason : "");
        ac_db_close();
        return count >= 2 ? 0 : 1;
    }
    rc = contract();
    ac_db_close();
    if (rc)
        fprintf(stderr, "tx retry fixture check %d\n", rc);
    return rc == 0 ? 0 : 1;
}

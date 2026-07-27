// SPDX-License-Identifier: GPL-2.0-or-later
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>
#include <sqlite3.h>

#define AP_ID "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
#define EPOCH "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define BASE 10000000

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
struct json_object *ac_db_survey_history_json(const char *, const char *,
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

static struct json_object *snapshot_new(int64_t observed_at, int frequency,
                                        int64_t active, int64_t busy)
{
    struct json_object *root = json_object_new_object();
    struct json_object *radios = json_object_new_array();
    struct json_object *radio = json_object_new_object();
    struct json_object *survey = json_object_new_object();

    if (!root || !radios || !radio || !survey)
        goto fail;
    json_object_object_add(root, "observed_at",
                           json_object_new_int64(observed_at));
    json_object_object_add(root, "complete", json_object_new_boolean(1));
    json_object_object_add(root, "radios", radios);
    json_object_object_add(root, "ssids", json_object_new_array());
    json_object_object_add(root, "stations", json_object_new_array());
    json_object_object_add(radio, "id", json_object_new_string("phy0"));
    json_object_object_add(survey, "source", json_object_new_string("iw_survey"));
    json_object_object_add(survey, "complete", json_object_new_boolean(1));
    json_object_object_add(survey, "interface", json_object_new_string("wlan0"));
    json_object_object_add(survey, "frequency_mhz",
                           json_object_new_int(frequency));
    json_object_object_add(survey, "channel_active_time_ms",
                           json_object_new_int64(active));
    json_object_object_add(survey, "channel_busy_time_ms",
                           json_object_new_int64(busy));
    json_object_object_add(survey, "channel_receive_time_ms",
                           json_object_new_int64(busy / 2));
    json_object_object_add(survey, "channel_transmit_time_ms",
                           json_object_new_int64(busy / 4));
    json_object_object_add(survey, "noise_dbm", json_object_new_int(-92));
    json_object_object_add(radio, "survey", survey);
    json_object_array_add(radios, radio);
    return root;
fail:
    json_object_put(survey);
    json_object_put(radio);
    json_object_put(radios);
    json_object_put(root);
    return NULL;
}

static int store_sample(const struct ac_device_model_report *report,
                        int64_t sequence, int64_t received_at, int frequency,
                        int64_t active, int64_t busy)
{
    struct json_object *snapshot = snapshot_new(received_at, frequency,
                                                active, busy);
    char snapshot_id[80];
    int rc;

    if (!snapshot)
        return -1;
    snprintf(snapshot_id, sizeof(snapshot_id), "fixture-%lld",
             (long long)sequence);
    rc = ac_db_ap_telemetry_store(AP_ID, EPOCH, sequence, received_at,
                                  received_at, snapshot_id, report, snapshot);
    json_object_put(snapshot);
    return rc;
}

static int history_contract(void)
{
    struct ac_device_model_report report = {0};
    struct json_object *page = NULL;
    struct json_object *points = NULL;
    struct json_object *value = NULL;
    int64_t cursor;
    int rc = -1;

    snprintf(report.model, sizeof(report.model), "Fixture AP");
    snprintf(report.board_name, sizeof(report.board_name), "fixture,ap");
    snprintf(report.model_source, sizeof(report.model_source), "fixture");
    report.model_available = 1;
    if (sqlite3_exec(g_ac_db,
            "INSERT INTO ac_aps(ap_id,site_id,name,adoption_state,last_seen_at) "
            "VALUES('" AP_ID "','default','Fixture AP','adopted'," "10000000" ")",
            NULL, NULL, NULL) != SQLITE_OK ||
        ac_db_ap_session_begin(AP_ID, EPOCH, 2, BASE) != 0 ||
        store_sample(&report, 1, BASE, 5180, 1000, 100) != 0 ||
        store_sample(&report, 2, BASE + 100, 5180, 1100, 110) != 0 ||
        scalar("SELECT received_at FROM ac_radio_survey_cursor") != BASE ||
        store_sample(&report, 3, BASE + 300, 5180, 1300, 160) != 0 ||
        store_sample(&report, 4, BASE + 600, 5180, 1600, 220) != 0 ||
        store_sample(&report, 5, BASE + 900, 2412, 100, 10) != 0 ||
        store_sample(&report, 6, BASE + 1200, 2412, 400, 70) != 0 ||
        store_sample(&report, 7, BASE + 1500, 2412, 10, 1) != 0 ||
        store_sample(&report, 8, BASE + 1800, 2412, 310, 61) != 0 ||
        store_sample(&report, 9, BASE + 2100, 2412, 410, 71) != 0)
        return -1;
    if (scalar("SELECT COUNT(*) FROM ac_radio_survey_bucket WHERE resolution_seconds=300") != 5 ||
        scalar("SELECT COUNT(*) FROM ac_radio_survey_bucket WHERE resolution_seconds=3600") < 1 ||
        scalar("SELECT COUNT(*) FROM ac_radio_survey_bucket WHERE active_delta_ms<=0 OR busy_delta_ms>active_delta_ms") != 0 ||
        fabs(scalar_double("SELECT MAX(ABS(utilization_pct-(CAST(busy_delta_ms AS REAL)*100.0/active_delta_ms))) FROM ac_radio_survey_bucket")) > 0.000001)
        return -1;
    page = ac_db_survey_history_json(AP_ID, "phy0", BASE - 1,
                                     BASE + 3000, 300, 2, 0);
    if (!page || !json_object_object_get_ex(page, "ok", &value) ||
        !json_object_get_boolean(value) ||
        !json_object_object_get_ex(page, "points", &points) ||
        json_object_array_length(points) != 2 ||
        !json_object_object_get_ex(page, "limited", &value) ||
        !json_object_get_boolean(value) ||
        !json_object_object_get_ex(page, "next_cursor", &value))
        goto done;
    cursor = json_object_get_int64(value);
    json_object_put(page);
    page = ac_db_survey_history_json(AP_ID, "phy0", BASE - 1,
                                     BASE + 3000, 300, 16, cursor);
    if (!page || !json_object_object_get_ex(page, "points", &points) ||
        json_object_array_length(points) != 3)
        goto done;
    json_object_put(page);
    page = NULL;
    if (sqlite3_exec(g_ac_db,
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<600) "
            "INSERT OR REPLACE INTO ac_radio_survey_bucket(ap_id,radio_id,resolution_seconds,bucket_start,"
            "first_received_at,last_received_at,sample_count,active_delta_ms,busy_delta_ms,utilization_pct) "
            "SELECT '" AP_ID "','phy0',300,20000000+x*300," "10002400,10002400,1,100,10,10.0 FROM n;"
            "INSERT OR REPLACE INTO ac_radio_survey_bucket(ap_id,radio_id,resolution_seconds,bucket_start,"
            "first_received_at,last_received_at,sample_count,active_delta_ms,busy_delta_ms,utilization_pct) "
            "VALUES('" AP_ID "','phy0',3600,0,1,1,1,100,10,10.0);",
            NULL, NULL, NULL) != SQLITE_OK ||
        store_sample(&report, 10, BASE + 2400, 2412, 710, 131) != 0 ||
        scalar("SELECT COUNT(*) FROM ac_radio_survey_bucket WHERE ap_id='" AP_ID "' AND radio_id='phy0' AND resolution_seconds=300") > 576 ||
        scalar("SELECT COUNT(*) FROM ac_radio_survey_bucket WHERE resolution_seconds=3600 AND last_received_at=1") != 0)
        return -1;
    printf("schema=%d fine_points=5 dense_suppressed=1 reset_safe=1 weighted=1 "
           "pagination=1 bounded_rows=%d old_rows=%d\n",
           scalar("SELECT version FROM ac_schema_meta WHERE singleton=1"),
           scalar("SELECT COUNT(*) FROM ac_radio_survey_bucket WHERE ap_id='" AP_ID "' AND radio_id='phy0' AND resolution_seconds=300"),
           scalar("SELECT COUNT(*) FROM ac_radio_survey_bucket WHERE resolution_seconds=3600 AND last_received_at=1"));
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
    rc = history_contract();
    ac_db_close();
    return rc == 0 ? 0 : 1;
}

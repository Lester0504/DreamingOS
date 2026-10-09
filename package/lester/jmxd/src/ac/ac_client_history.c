// SPDX-License-Identifier: GPL-2.0-or-later
/* Included once by ac_db.c, alongside its transaction. Also compiled directly
 * by the SQLite fixture. No events or current station cache become samples. */
#include "ac_client_history.h"
#include "ac_client_candidates.c"
#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

static struct json_object *ch_get(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    if (o) json_object_object_get_ex(o, key, &v);
    return v;
}

static const char *ch_str(struct json_object *o, const char *key)
{
    struct json_object *v = ch_get(o, key);
    return v && json_object_is_type(v, json_type_string) ?
        json_object_get_string(v) : "";
}

int ac_client_history_mac_valid(const char *mac)
{
    size_t i;
    if (!mac || strlen(mac) != 17) return 0;
    for (i = 0; i < 17; i++)
        if (i % 3 == 2 ? mac[i] != ':' : !isxdigit((unsigned char)mac[i]))
            return 0;
    return 1;
}

static struct json_object *ch_number(struct json_object *o, const char *key,
                                     double minimum, double maximum)
{
    struct json_object *v = ch_get(o, key);
    double n;
    if (!v || (!json_object_is_type(v, json_type_int) &&
               !json_object_is_type(v, json_type_double))) return NULL;
    n = json_object_get_double(v);
    return isfinite(n) && n >= minimum && n <= maximum ? v : NULL;
}

static void ch_copy_number(struct json_object *out, const char *key,
    struct json_object *from, const char *field, double minimum, double maximum)
{
    json_object_object_add(out, key,
        json_object_get(ch_number(from, field, minimum, maximum)));
}

int ac_client_history_init(sqlite3 *db)
{
    return !db || sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS ac_client_health_samples("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,mac TEXT NOT NULL COLLATE NOCASE,"
        "ap_id TEXT NOT NULL,epoch TEXT NOT NULL,interface TEXT NOT NULL,"
        "observed_at INTEGER NOT NULL,received_at INTEGER NOT NULL,"
        "sample_json TEXT NOT NULL,"
        "UNIQUE(ap_id,epoch,observed_at,mac,interface));"
        "CREATE INDEX IF NOT EXISTS ac_client_health_mac_id "
        "ON ac_client_health_samples(mac,id);"
        "CREATE INDEX IF NOT EXISTS ac_client_health_received "
        "ON ac_client_health_samples(received_at);",
        NULL, NULL, NULL) != SQLITE_OK ? -1 : 0;
}

static struct json_object *ch_radio(struct json_object *snapshot,
    const char *interface, const char **radio_id)
{
    struct json_object *ssids = ch_get(snapshot, "ssids");
    struct json_object *radios = ch_get(snapshot, "radios");
    size_t i;
    *radio_id = "";
    for (i = 0; ssids && i < json_object_array_length(ssids); i++) {
        struct json_object *s = json_object_array_get_idx(ssids, i);
        if (!strcmp(ch_str(s, "interface"), interface)) {
            *radio_id = ch_str(s, "radio_id");
            break;
        }
    }
    for (i = 0; radios && i < json_object_array_length(radios); i++) {
        struct json_object *r = json_object_array_get_idx(radios, i);
        if ((*radio_id)[0] && !strcmp(ch_str(r, "id"), *radio_id)) return r;
    }
    return NULL;
}

static struct json_object *ch_sample(struct json_object *snapshot,
    struct json_object *station, const char *ap_id, const char *epoch,
    int64_t observed_s, int64_t received_s)
{
    struct json_object *out = json_object_new_object();
    struct json_object *radio, *survey, *air, *connected;
    const char *radio_id, *interface = ch_str(station, "interface");
    const char *source = ch_str(station, "source");
    int complete, air_current;
    const char *const counters[] = {
        "tx_packets", "rx_packets", "tx_retries", "tx_bytes", "rx_bytes", NULL
    };
    size_t i;
    radio = ch_radio(snapshot, interface, &radio_id);
    survey = ch_get(radio, "survey");
    air = ch_get(survey, "air_stats");
    complete = radio && source[0] &&
        !json_object_get_boolean(ch_get(snapshot, "stale")) &&
        !json_object_get_boolean(ch_get(station, "stale")) &&
        json_object_get_int64(ch_get(station, "observed_at")) == observed_s;
    air_current = complete && json_object_get_boolean(ch_get(air, "available")) &&
        json_object_get_int64(ch_get(survey, "observed_at")) == observed_s;
    json_object_object_add(out, "timestamp", json_object_new_int64(received_s * 1000));
    json_object_object_add(out, "observed_at", json_object_new_int64(observed_s * 1000));
    json_object_object_add(out, "received_at", json_object_new_int64(received_s * 1000));
    json_object_object_add(out, "source", json_object_new_string(source));
    json_object_object_add(out, "scope", json_object_new_string("station"));
    json_object_object_add(out, "ap_id", json_object_new_string(ap_id));
    json_object_object_add(out, "radio_id", json_object_new_string(radio_id));
    json_object_object_add(out, "interface", json_object_new_string(interface));
    json_object_object_add(out, "session_epoch", json_object_new_string(epoch));
    json_object_object_add(out, "complete", json_object_new_boolean(complete));
    json_object_object_add(out, "reason", json_object_new_string(complete ? "" :
        "station_source_incomplete"));
    ch_copy_number(out, "signal_dbm", complete ? station : NULL,
                   "signal_dbm", -127, -1);
    for (i = 0; counters[i]; i++) {
        struct json_object *v = complete ? ch_get(station, counters[i]) : NULL;
        if (!v || !json_object_is_type(v, json_type_int) || json_object_get_int64(v) < 0)
            v = NULL;
        json_object_object_add(out, counters[i], json_object_get(v));
    }
    connected = complete ? ch_get(station, "connected_time_seconds") : NULL;
    if (!connected || !json_object_is_type(connected, json_type_int) ||
        json_object_get_int64(connected) < 0 ||
        json_object_get_int64(connected) > observed_s) connected = NULL;
    json_object_object_add(out, "association_started_at", connected ?
        json_object_new_int64((observed_s - json_object_get_int64(connected)) * 1000) : NULL);
    ch_copy_number(out, "interference_pct", air_current ? air : NULL,
                   "obss_util_pct", 0, 100);
    json_object_object_add(out, "device_source", json_object_new_string(
        air_current ? ch_str(air, "source") : ""));
    json_object_object_add(out, "device_complete", json_object_new_boolean(
        air_current && ch_get(out, "interference_pct")));
    return out;
}

int ac_client_history_ingest(sqlite3 *db, const char *ap_id,
    const char *epoch, int64_t observed_s, int64_t received_s,
    struct json_object *snapshot)
{
    struct json_object *stations = ch_get(snapshot, "stations");
    sqlite3_stmt *st = NULL;
    size_t i;
    int rc = -1;
    /* Caller owns the accepted telemetry transaction, including rollback. */
    if (!db || !ap_id || !epoch || observed_s <= 0 || received_s <= 0 ||
        !stations || !json_object_is_type(stations, json_type_array)) return -1;
    if (sqlite3_prepare_v2(db,
        "INSERT OR IGNORE INTO ac_client_health_samples"
        "(mac,ap_id,epoch,interface,observed_at,received_at,sample_json)"
        "VALUES(?1,?2,?3,?4,?5,?6,?7)", -1, &st, NULL) != SQLITE_OK) return -1;
    for (i = 0; i < json_object_array_length(stations); i++) {
        struct json_object *station = json_object_array_get_idx(stations, i);
        const char *mac = ch_str(station, "mac");
        struct json_object *sample;
        if (!ac_client_history_mac_valid(mac) || !ch_str(station, "interface")[0]) continue;
        sample = ch_sample(snapshot, station, ap_id, epoch, observed_s, received_s);
        sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, ap_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, epoch, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, ch_str(station, "interface"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 5, observed_s * 1000);
        sqlite3_bind_int64(st, 6, received_s * 1000);
        sqlite3_bind_text(st, 7, json_object_to_json_string_ext(sample,
            JSON_C_TO_STRING_PLAIN), -1, SQLITE_TRANSIENT);
        json_object_put(sample);
        if (sqlite3_step(st) != SQLITE_DONE) goto done;
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
    }
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(db,
        "DELETE FROM ac_client_health_samples WHERE received_at<?1 OR id<="
        "(SELECT id FROM ac_client_health_samples ORDER BY id DESC LIMIT 1 OFFSET 200000)",
        -1, &st, NULL) != SQLITE_OK) goto done;
    sqlite3_bind_int64(st, 1, received_s * 1000 - AC_CLIENT_HISTORY_RETENTION_MS);
    if (sqlite3_step(st) == SQLITE_DONE) rc = 0;
done:
    sqlite3_finalize(st);
    return rc;
}

static const char *ch_continuity(struct json_object *sample, struct json_object *previous)
{
    int64_t elapsed, received_gap, association_gap;
    const char *const identity[] = {"ap_id", "radio_id", "interface", "session_epoch", "source", NULL};
    size_t i;
    if (!previous) return "no_previous_sample";
    if (!json_object_get_boolean(ch_get(sample, "complete")) ||
        !json_object_get_boolean(ch_get(previous, "complete"))) return "incomplete_sample";
    for (i = 0; identity[i]; i++)
        if (strcmp(ch_str(sample, identity[i]), ch_str(previous, identity[i])))
            return "attachment_or_session_changed";
    elapsed = json_object_get_int64(ch_get(sample, "observed_at")) -
              json_object_get_int64(ch_get(previous, "observed_at"));
    received_gap = json_object_get_int64(ch_get(sample, "received_at")) -
                   json_object_get_int64(ch_get(previous, "received_at"));
    if (elapsed <= 0 || elapsed > AC_CLIENT_HISTORY_GAP_MS ||
        received_gap <= 0 || received_gap > AC_CLIENT_HISTORY_GAP_MS) return "sample_gap";
    if (!ch_get(sample, "association_started_at") || !ch_get(previous, "association_started_at"))
        return "association_epoch_unknown";
    association_gap = json_object_get_int64(ch_get(sample, "association_started_at")) -
                      json_object_get_int64(ch_get(previous, "association_started_at"));
    if (association_gap < -2000 || association_gap > 2000) return "association_changed";
    return "";
}

static const char *ch_delta(struct json_object *sample, struct json_object *previous)
{
    int64_t packets, retries;
    const char *reason = ch_continuity(sample, previous);
    json_object_object_add(sample, "tx_retry_pct", NULL);
    if (reason[0]) return reason;
    if (strcmp(ch_str(sample, "source"), "iw_station_dump") ||
        !ch_get(sample, "tx_packets") || !ch_get(previous, "tx_packets") ||
        !ch_get(sample, "tx_retries") || !ch_get(previous, "tx_retries")) return "retry_counters_unavailable";
    packets = json_object_get_int64(ch_get(sample, "tx_packets")) -
              json_object_get_int64(ch_get(previous, "tx_packets"));
    retries = json_object_get_int64(ch_get(sample, "tx_retries")) -
              json_object_get_int64(ch_get(previous, "tx_retries"));
    if (packets < 0 || retries < 0) return "counter_reset";
    if (!packets && !retries) return "no_tx_attempts";
    json_object_object_add(sample, "tx_retry_pct", json_object_new_double(
        (double)retries * 100.0 / ((double)packets + (double)retries)));
    return "";
}

struct ch_activity_totals {
    int samples, valid, active;
    int64_t valid_ms, active_ms, covered_until;
};

/* The AP checks every 30 s but suppresses unchanged snapshots until its 300 s
 * refresh. Weight the retained, contiguous intervals by their actual duration;
 * a byte delta only proves traffic somewhere in that interval, not airtime. */
static void ch_activity(struct json_object *sample, struct json_object *previous,
    int64_t window_start, struct ch_activity_totals *totals)
{
    struct json_object *interval = json_object_new_object();
    const char *reason = ch_continuity(sample, previous);
    const char *const counters[] = {"tx_bytes", "rx_bytes"};
    int64_t start = json_object_get_int64(ch_get(previous, "received_at"));
    int64_t end = json_object_get_int64(ch_get(sample, "received_at"));
    int64_t delta[2] = {0, 0};
    int valid, active;
    size_t i;
    totals->samples++;
    if (!reason[0] && start < window_start) reason = "interval_outside_window";
    if (!reason[0] && start < totals->covered_until) reason = "overlapping_interval";
    for (i = 0; !reason[0] && i < 2; i++) {
        struct json_object *now = ch_get(sample, counters[i]);
        struct json_object *old = ch_get(previous, counters[i]);
        if (!now || !old || !json_object_is_type(now, json_type_int) ||
            !json_object_is_type(old, json_type_int) ||
            json_object_get_int64(now) < 0 || json_object_get_int64(old) < 0) {
            reason = "byte_counters_unavailable";
            break;
        }
        delta[i] = json_object_get_int64(now) - json_object_get_int64(old);
        if (delta[i] < 0) reason = "counter_reset";
    }
    valid = !reason[0];
    active = valid && (delta[0] > 0 || delta[1] > 0);
    if (valid) {
        totals->valid++;
        totals->active += active;
        totals->valid_ms += end - start;
        totals->active_ms += active ? end - start : 0;
        totals->covered_until = end;
    }
    json_object_object_add(sample, "activity_pct", valid ?
        json_object_new_int(active ? 100 : 0) : NULL);
    json_object_object_add(interval, "start", start > 0 ? json_object_new_int64(start) : NULL);
    json_object_object_add(interval, "end", json_object_new_int64(end));
    json_object_object_add(interval, "duration_ms", start > 0 && end > start ?
        json_object_new_int64(end - start) : NULL);
    json_object_object_add(interval, "valid", json_object_new_boolean(valid));
    json_object_object_add(interval, "reason", json_object_new_string(reason));
    json_object_object_add(interval, "tx_bytes_delta", valid ? json_object_new_int64(delta[0]) : NULL);
    json_object_object_add(interval, "rx_bytes_delta", valid ? json_object_new_int64(delta[1]) : NULL);
    json_object_object_add(sample, "activity_interval", interval);
}

static struct json_object *ch_activity_summary(const struct ch_activity_totals *totals,
    int64_t start, int64_t end, int supported, const char *query_reason)
{
    struct json_object *o = json_object_new_object();
    int failed = query_reason[0] && strcmp(query_reason, "no_samples") &&
                 strcmp(query_reason, "outside_retention");
    int available = !failed && totals->valid_ms > 0;
    int64_t window_ms = start > 0 && end >= start ? end - start : 0;
    json_object_object_add(o, "supported", json_object_new_boolean(supported));
    json_object_object_add(o, "available", json_object_new_boolean(available));
    json_object_object_add(o, "complete", json_object_new_boolean(
        available && totals->valid_ms == window_ms));
    json_object_object_add(o, "definition", json_object_new_string("positive_byte_delta_duration_ratio"));
    json_object_object_add(o, "timestamp_basis", json_object_new_string("controller_received_at"));
    json_object_object_add(o, "start", json_object_new_int64(start));
    json_object_object_add(o, "end", json_object_new_int64(end));
    json_object_object_add(o, "gap_ms", json_object_new_int64(AC_CLIENT_HISTORY_GAP_MS));
    json_object_object_add(o, "sample_count", json_object_new_int(totals->samples));
    json_object_object_add(o, "valid_intervals", json_object_new_int(totals->valid));
    json_object_object_add(o, "active_intervals", json_object_new_int(totals->active));
    json_object_object_add(o, "excluded_samples", json_object_new_int(totals->samples - totals->valid));
    json_object_object_add(o, "valid_duration_ms", json_object_new_int64(totals->valid_ms));
    json_object_object_add(o, "active_duration_ms", json_object_new_int64(totals->active_ms));
    json_object_object_add(o, "window_duration_ms", json_object_new_int64(window_ms));
    json_object_object_add(o, "uncovered_duration_ms", failed ? NULL :
        json_object_new_int64(window_ms - totals->valid_ms));
    json_object_object_add(o, "coverage_pct", !failed && window_ms > 0 ?
        json_object_new_double(100.0 * totals->valid_ms / window_ms) : NULL);
    json_object_object_add(o, "activity_pct", available ?
        json_object_new_double(100.0 * totals->active_ms / totals->valid_ms) : NULL);
    json_object_object_add(o, "reason", json_object_new_string(failed ? query_reason :
        (available ? "sampled_coverage" : "no_valid_intervals")));
    return o;
}

static struct json_object *ch_unavailable(const char *reason)
{
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "available", json_object_new_boolean(0));
    json_object_object_add(o, "supported", json_object_new_boolean(0));
    json_object_object_add(o, "reason", json_object_new_string(reason));
    return o;
}

struct json_object *ac_client_history_query(sqlite3 *db, const char *mac,
    int64_t start_ms, int64_t end_ms, int limit, int64_t after_id, int64_t now_ms)
{
    struct json_object *root = json_object_new_object(), *health = json_object_new_object();
    struct json_object *device = json_object_new_object(), *attachment = json_object_new_object();
    struct json_object *rows = json_object_new_array(), *devices = json_object_new_array();
    struct json_object *attachments = json_object_new_array();
    sqlite3_stmt *st = NULL;
    struct ch_activity_totals activity = {0};
    int rc = SQLITE_DONE, more = 0, count = 0;
    int64_t next = after_id, oldest = 0;
    const char *reason = "";
    json_object_object_add(root, "client_health", health);
    json_object_object_add(root, "device_health", device);
    json_object_object_add(root, "attachment_history", attachment);
    json_object_object_add(health, "history", rows);
    json_object_object_add(device, "history", devices);
    json_object_object_add(attachment, "history", attachments);
    if (!ac_client_history_mac_valid(mac) || start_ms <= 0 || end_ms < start_ms ||
        end_ms > now_ms + 60000 || limit < 1 || limit > AC_CLIENT_HISTORY_LIMIT_MAX || after_id < 0)
        reason = "invalid_history_query";
    else if (!db) reason = "history_store_unavailable";
    if (reason[0]) goto done;
    if (sqlite3_prepare_v2(db, "SELECT MIN(received_at) FROM ac_client_health_samples WHERE mac=?1",
                          -1, &st, NULL) != SQLITE_OK) { reason = "history_query_failed"; goto done; }
    sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) oldest = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT s.id,s.sample_json,p.sample_json FROM ac_client_health_samples s "
        "LEFT JOIN ac_client_health_samples p ON p.id=(SELECT MAX(id) "
        "FROM ac_client_health_samples WHERE mac=s.mac AND id<s.id) "
        "WHERE s.mac=?1 AND s.received_at>=?2 AND s.received_at<=?3 "
        "ORDER BY s.id", -1, &st, NULL) != SQLITE_OK) {
        reason = "history_query_failed"; goto done;
    }
    sqlite3_bind_text(st, 1, mac, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, start_ms > now_ms - AC_CLIENT_HISTORY_RETENTION_MS ?
                       start_ms : now_ms - AC_CLIENT_HISTORY_RETENTION_MS);
    sqlite3_bind_int64(st, 3, end_ms);
    /* Scan the bounded retained window for a cursor-independent summary. Only
     * the requested page is serialized; every row keeps its real predecessor. */
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        struct json_object *sample, *previous, *d, *a;
        const char *raw = (const char *)sqlite3_column_text(st, 1);
        const char *old = (const char *)sqlite3_column_text(st, 2);
        const char *const fields[] = {"timestamp", "observed_at", "received_at", "ap_id", "radio_id", "interface", "session_epoch", NULL};
        size_t i;
        sample = raw ? json_tokener_parse(raw) : NULL;
        previous = old ? json_tokener_parse(old) : NULL;
        if (!sample) { json_object_put(previous); reason = "history_sample_corrupt"; break; }
        json_object_object_add(sample, "retry_reason", json_object_new_string(ch_delta(sample, previous)));
        ch_activity(sample, previous,
            start_ms > now_ms - AC_CLIENT_HISTORY_RETENTION_MS ?
            start_ms : now_ms - AC_CLIENT_HISTORY_RETENTION_MS, &activity);
        json_object_put(previous);
        if (sqlite3_column_int64(st, 0) <= after_id || count == limit) {
            if (sqlite3_column_int64(st, 0) > after_id) more = 1;
            json_object_put(sample);
            continue;
        }
        next = sqlite3_column_int64(st, 0);
        json_object_object_add(sample, "sample_id", json_object_new_int64(next));
        d = json_object_new_object(); a = json_object_new_object();
        for (i = 0; fields[i]; i++) {
            json_object_object_add(d, fields[i], json_object_get(ch_get(sample, fields[i])));
            json_object_object_add(a, fields[i], json_object_get(ch_get(sample, fields[i])));
        }
        json_object_object_add(a, "complete", json_object_get(ch_get(sample, "complete")));
        json_object_object_add(a, "source", json_object_get(ch_get(sample, "source")));
        json_object_object_add(a, "gateway", NULL);
        json_object_object_add(a, "wan", NULL);
        json_object_object_add(d, "interference_pct", json_object_get(ch_get(sample, "interference_pct")));
        json_object_object_add(d, "source", json_object_get(ch_get(sample, "device_source")));
        json_object_object_add(d, "complete", json_object_get(ch_get(sample, "device_complete")));
        json_object_object_add(d, "errors", NULL);
        json_object_object_add(d, "drops", NULL);
        json_object_object_add(d, "multicast_packets", NULL);
        json_object_array_add(rows, sample);
        json_object_array_add(devices, d);
        json_object_array_add(attachments, a);
        count++;
    }
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) reason = "history_query_failed";
    if (!reason[0] && !count) reason = end_ms < now_ms - AC_CLIENT_HISTORY_RETENTION_MS ?
        "outside_retention" : "no_samples";
done:
    sqlite3_finalize(st);
    json_object_object_add(health, "available", json_object_new_boolean(count > 0));
    json_object_object_add(health, "supported", json_object_new_boolean(db != NULL));
    json_object_object_add(health, "complete", json_object_new_boolean(0));
    json_object_object_add(health, "reason", json_object_new_string(reason[0] ? reason : "sampled_coverage"));
    json_object_object_add(health, "source", json_object_new_string("ap_station_telemetry"));
    json_object_object_add(health, "scope", json_object_new_string(mac ? mac : ""));
    json_object_object_add(health, "start", json_object_new_int64(start_ms));
    json_object_object_add(health, "end", json_object_new_int64(end_ms));
    json_object_object_add(health, "observed_at", json_object_new_int64(now_ms));
    json_object_object_add(health, "earliest_retained_at", oldest ? json_object_new_int64(oldest) : NULL);
    json_object_object_add(health, "retention_ms", json_object_new_int64(AC_CLIENT_HISTORY_RETENTION_MS));
    json_object_object_add(health, "retention_row_limit", json_object_new_int(200000));
    json_object_object_add(health, "retention_clipped", json_object_new_boolean(
        start_ms < now_ms - AC_CLIENT_HISTORY_RETENTION_MS || (oldest && start_ms < oldest)));
    json_object_object_add(health, "gap_ms", json_object_new_int64(AC_CLIENT_HISTORY_GAP_MS));
    json_object_object_add(health, "timestamp_basis", json_object_new_string("controller_received_at"));
    json_object_object_add(health, "counter_kind", json_object_new_string("cumulative_ap_station_counters"));
    json_object_object_add(health, "tx_retry_definition", json_object_new_string("AP-to-client delta retries / (delta packets + delta retries)"));
    {
        struct json_object *summary = ch_activity_summary(&activity, start_ms, end_ms, db != NULL, reason);
        json_object_object_add(health, "activity_reason", json_object_get(ch_get(summary, "reason")));
        json_object_object_add(health, "activity", summary);
    }
    json_object_object_add(health, "has_more", json_object_new_boolean(more));
    json_object_object_add(health, "next_after_id", more ? json_object_new_int64(next) : NULL);
    json_object_object_add(device, "source", json_object_new_string("sample_time_attached_radio"));
    json_object_object_add(device, "scope", json_object_new_string("sample.ap_id/sample.radio_id"));
    json_object_object_add(attachment, "source", json_object_new_string("sample_time_station_attachment"));
    json_object_object_add(attachment, "path_reason", json_object_new_string("gateway_wan_and_hop_latency_not_measured"));
    json_object_object_add(root, "person", ch_unavailable("person_association_not_configured"));
    json_object_object_add(root, "candidate_ap_measurement",
        ac_client_candidates_query(db, mac, start_ms, end_ms, now_ms));
    json_object_object_add(root, "site_dns", ch_unavailable("dns_probe_history_unavailable"));
    return root;
}

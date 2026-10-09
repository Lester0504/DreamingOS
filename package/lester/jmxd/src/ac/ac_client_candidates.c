// SPDX-License-Identifier: GPL-2.0-or-later
/* Standalone read-only projection; may be included once by ac_db's history TU. */
#include "ac_client_candidates.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#define CCAND_ROWS_MAX 2048
#define CCAND_RESULTS_MAX 256

static struct json_object *ccand_get(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    if (o && json_object_is_type(o, json_type_object))
        json_object_object_get_ex(o, key, &v);
    return v;
}

static const char *ccand_str(struct json_object *o, const char *key)
{
    struct json_object *v = ccand_get(o, key);
    return v && json_object_is_type(v, json_type_string) ?
        json_object_get_string(v) : "";
}

static int ccand_mac(const char *input, char out[18])
{
    size_t i;
    if (!input || strlen(input) != 17) return 0;
    for (i = 0; i < 17; i++) {
        if (i % 3 == 2 ? input[i] != ':' : !isxdigit((unsigned char)input[i]))
            return 0;
        out[i] = (char)tolower((unsigned char)input[i]);
    }
    out[17] = '\0';
    return 1;
}

static int ccand_table(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    int rc, present;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM sqlite_master "
            "WHERE type='table' AND name=?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    rc = sqlite3_step(st);
    present = rc == SQLITE_ROW ? 1 : rc == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(st);
    return present;
}

static struct json_object *ccand_name(sqlite3_stmt *st, const char *ap_id)
{
    struct json_object *name = NULL;
    if (!st) return NULL;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW &&
        sqlite3_column_type(st, 0) == SQLITE_TEXT)
        name = json_object_new_string((const char *)sqlite3_column_text(st, 0));
    sqlite3_reset(st);
    sqlite3_clear_bindings(st);
    return name;
}

struct json_object *ac_client_candidates_query(sqlite3 *db, const char *mac,
    int64_t start_ms, int64_t end_ms, int64_t now_ms)
{
    struct json_object *root = json_object_new_object();
    struct json_object *items = json_object_new_array(), *meta = json_object_new_object();
    sqlite3_stmt *st = NULL, *names = NULL;
    char normalized[18] = "";
    int supported = 0, scanned = 0, expired = 0, excluded = 0, corrupt = 0;
    int truncated = 0, rc = SQLITE_DONE;
    const char *reason = "";
    json_object_object_add(root, "candidates", items);
    json_object_object_add(root, "meta", meta);
    if (!ccand_mac(mac, normalized) || start_ms <= 0 || end_ms < start_ms ||
        now_ms <= 0 || end_ms > now_ms + 60000) {
        reason = "invalid_candidate_query"; goto done;
    }
    if (!db) { reason = "candidate_store_unavailable"; goto done; }
    rc = ccand_table(db, "ac_roaming_audit");
    if (rc < 0) { reason = "candidate_query_failed"; goto done; }
    if (!rc) { reason = "candidate_table_unavailable"; goto done; }
    supported = 1;
    /* The read cap is reported as incomplete, never hidden as a complete list. */
    if (sqlite3_prepare_v2(db,
            "SELECT audit_id,observed_at,candidates_json FROM ac_roaming_audit "
            "WHERE station_mac=?1 COLLATE NOCASE AND observed_at>=?2 "
            "AND observed_at<=?3 ORDER BY observed_at DESC,audit_id DESC LIMIT ?4",
            -1, &st, NULL) != SQLITE_OK) {
        reason = "candidate_query_failed"; goto done;
    }
    sqlite3_bind_text(st, 1, normalized, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, start_ms / 1000 + (start_ms % 1000 != 0));
    sqlite3_bind_int64(st, 3, end_ms / 1000);
    sqlite3_bind_int(st, 4, CCAND_ROWS_MAX + 1);
    if (ccand_table(db, "ac_aps") == 1)
        sqlite3_prepare_v2(db, "SELECT name FROM ac_aps WHERE ap_id=?1",
                          -1, &names, NULL);
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const char *raw;
        struct json_object *candidates;
        int64_t audit_id = sqlite3_column_int64(st, 0);
        int64_t audit_s = sqlite3_column_int64(st, 1);
        size_t i;
        if (scanned == CCAND_ROWS_MAX) { truncated = 1; break; }
        scanned++;
        raw = (const char *)sqlite3_column_text(st, 2);
        candidates = raw ? json_tokener_parse(raw) : NULL;
        if (!candidates || !json_object_is_type(candidates, json_type_array)) {
            corrupt++; json_object_put(candidates); continue;
        }
        for (i = 0; i < json_object_array_length(candidates); i++) {
            struct json_object *c = json_object_array_get_idx(candidates, i);
            struct json_object *measured = ccand_get(c, "signal_measured");
            struct json_object *randomized = ccand_get(c, "signal_randomized");
            struct json_object *observed = ccand_get(c, "signal_observed_at");
            struct json_object *signal = ccand_get(c, "signal_estimate_dbm");
            const char *source = ccand_str(c, "signal_source");
            const char *direction = ccand_str(c, "signal_direction");
            const char *ap_id = ccand_str(c, "ap_id"), *radio_id = ccand_str(c, "radio_id");
            struct json_object *previous = NULL, *out;
            int64_t observed_s, observed_ms, ttl;
            size_t j, replace = json_object_array_length(items);
            if (!strcmp(source, "ieee80211k_beacon_report") ||
                !strcmp(source, "ieee80211k_beacon_table")) ttl = 120000;
            else if (!strcmp(source, "ap_probe_request")) ttl = 30000;
            else { excluded++; continue; }
            if (!measured || !json_object_is_type(measured, json_type_boolean) ||
                !json_object_get_boolean(measured) || !randomized ||
                !json_object_is_type(randomized, json_type_boolean) ||
                json_object_get_boolean(randomized) ||
                strcmp(direction, ttl == 120000 ? "downlink" : "uplink") ||
                !ap_id[0] || strlen(ap_id) > 64 || !radio_id[0] || strlen(radio_id) > 64 ||
                !observed || !json_object_is_type(observed, json_type_int) ||
                !signal || !json_object_is_type(signal, json_type_int) ||
                json_object_get_int64(signal) < -110 || json_object_get_int64(signal) > 0) {
                excluded++; continue;
            }
            observed_s = json_object_get_int64(observed);
            /* Reject producer clock tolerance/future values, not just the TTL. */
            if (observed_s <= 0 || observed_s > INT64_MAX / 1000 ||
                observed_s > audit_s) { excluded++; continue; }
            observed_ms = observed_s * 1000;
            if (observed_ms > end_ms || observed_ms > now_ms) { excluded++; continue; }
            if (observed_ms < start_ms || end_ms - observed_ms > ttl) {
                expired++; continue;
            }
            for (j = 0; j < json_object_array_length(items); j++) {
                struct json_object *item = json_object_array_get_idx(items, j);
                if (!strcmp(ap_id, ccand_str(item, "ap_id")) &&
                    !strcmp(radio_id, ccand_str(item, "radio_id"))) {
                    replace = j; previous = item; break;
                }
            }
            if (previous &&
                (json_object_get_int64(ccand_get(previous, "observed_at")) > observed_ms ||
                 (json_object_get_int64(ccand_get(previous, "observed_at")) == observed_ms &&
                  json_object_get_int64(ccand_get(previous, "audit_id")) >= audit_id)))
                continue;
            if (!previous && replace >= CCAND_RESULTS_MAX) { truncated = 1; continue; }
            out = json_object_new_object();
            json_object_object_add(out, "ap_id", json_object_new_string(ap_id));
            json_object_object_add(out, "radio_id", json_object_new_string(radio_id));
            json_object_object_add(out, "name", ccand_name(names, ap_id));
            json_object_object_add(out, "signal_dbm", json_object_get(signal));
            json_object_object_add(out, "source", json_object_new_string(source));
            json_object_object_add(out, "direction", json_object_new_string(direction));
            json_object_object_add(out, "observed_at", json_object_new_int64(observed_ms));
            json_object_object_add(out, "age_ms", json_object_new_int64(end_ms - observed_ms));
            json_object_object_add(out, "ttl_ms", json_object_new_int64(ttl));
            json_object_object_add(out, "audit_id", json_object_new_int64(audit_id));
            json_object_array_put_idx(items, replace, out);
        }
        json_object_put(candidates);
    }
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) reason = "candidate_query_failed";
    else if (!scanned) reason = "no_candidate_samples";
    else if (!json_object_array_length(items)) reason = corrupt ? "candidate_data_invalid" :
        expired ? "candidate_measurements_expired" : "candidate_measurements_unavailable";
done:
    sqlite3_finalize(st);
    sqlite3_finalize(names);
    json_object_object_add(root, "available", json_object_new_boolean(json_object_array_length(items) > 0));
    json_object_object_add(root, "supported", json_object_new_boolean(supported));
    json_object_object_add(root, "complete", json_object_new_boolean(0));
    json_object_object_add(root, "reason", json_object_new_string(reason[0] ? reason :
        truncated || corrupt ? "partial_candidate_measurements" : "recorded_candidate_measurements"));
    json_object_object_add(root, "source", json_object_new_string("ac_roaming_audit.measured_candidates"));
    json_object_object_add(root, "scope", json_object_new_string(normalized));
    json_object_object_add(root, "start", json_object_new_int64(start_ms));
    json_object_object_add(root, "end", json_object_new_int64(end_ms));
    json_object_object_add(meta, "status", json_object_new_string(reason[0] ? reason : "available"));
    json_object_object_add(meta, "timestamp_unit", json_object_new_string("milliseconds"));
    json_object_object_add(meta, "freshness_at", json_object_new_int64(end_ms));
    json_object_object_add(meta, "name_source", json_object_new_string("ac_aps.current_name"));
    json_object_object_add(meta, "rows_scanned", json_object_new_int(scanned));
    json_object_object_add(meta, "expired_measurements", json_object_new_int(expired));
    json_object_object_add(meta, "excluded_measurements", json_object_new_int(excluded));
    json_object_object_add(meta, "corrupt_rows", json_object_new_int(corrupt));
    json_object_object_add(meta, "truncated", json_object_new_boolean(truncated));
    json_object_object_add(meta, "row_limit", json_object_new_int(CCAND_ROWS_MAX));
    json_object_object_add(meta, "candidate_limit", json_object_new_int(CCAND_RESULTS_MAX));
    return root;
}

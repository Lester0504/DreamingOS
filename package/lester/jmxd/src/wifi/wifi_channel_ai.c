// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Deterministic, read-only Channel AI planner.
 *
 * This is deliberately a small policy layer over the evidence already
 * collected by APD/webd.  It does not invoke iw, schedule scans, or mutate
 * UCI.  Survey scoring follows the hostapd ACS shape while the surrounding
 * policy adds neighbour overlap, same-site radio cost, legal width expansion,
 * freshness gates, and stable multi-radio assignment.
 */
#include "wifi_channel_ai.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#define CAI_PROFILE "hostapd-acs-v1+unifi-policy-v1"
#define CAI_NEIGHBOR_MAX_AGE_S 86400
#define CAI_SURVEY_MAX_AGE_S 900
#define CAI_USAGE_MAX_AGE_S 3600
#define CAI_MAX_RADIOS 64
#define CAI_MAX_CANDIDATES 256
#define CAI_MAX_SURVEY_SAMPLES 256
#define CAI_MAX_ASSIGNMENT_RADIOS 16
#define CAI_MAX_ASSIGNMENT_COMBINATIONS 1000000ULL
#define CAI_CHANGE_MIN_IMPROVEMENT 0.05

struct cai_candidate {
    int channel;
    int width_mhz;
    double score;
    double survey_score;
    double neighbor_score;
    double own_score;
    double risk_score;
    double change_cost;
    int measured;
    int degraded;
};

struct cai_radio {
    struct json_object *obj;
    const char *id;
    const char *ap_id;
    const char *band;
    int current_channel;
    int current_width;
    int clients;
    double retry_pct;
    double usage_pct;
    int have_retry;
    int have_usage;
    int stale;
    struct cai_candidate candidates[CAI_MAX_CANDIDATES];
    size_t candidate_count;
    size_t selected;
    int assignment_selected;
};

struct cai_survey_point {
    double noise;
    double occupancy;
    double rx_ratio;
    int use_busy;
};

static struct json_object *child(struct json_object *obj, const char *key)
{
    struct json_object *value = NULL;

    if (!obj || !key || !json_object_is_type(obj, json_type_object) ||
        !json_object_object_get_ex(obj, key, &value) || !value)
        return NULL;
    return value;
}

static struct json_object *child_obj(struct json_object *obj, const char *key)
{
    struct json_object *value = child(obj, key);

    return value && json_object_is_type(value, json_type_object) ? value : NULL;
}

static struct json_object *child_array(struct json_object *obj, const char *key)
{
    struct json_object *value = child(obj, key);

    return value && json_object_is_type(value, json_type_array) ? value : NULL;
}

static const char *strv(struct json_object *obj, const char *key,
                        const char *fallback)
{
    struct json_object *value = child(obj, key);

    if (!value || !json_object_is_type(value, json_type_string))
        return fallback;
    return json_object_get_string(value);
}

static int intv(struct json_object *obj, const char *key, int fallback)
{
    struct json_object *value = child(obj, key);

    if (!value || (!json_object_is_type(value, json_type_int) &&
                   !json_object_is_type(value, json_type_double)))
        return fallback;
    return json_object_get_int(value);
}

static int64_t i64v(struct json_object *obj, const char *key, int64_t fallback)
{
    struct json_object *value = child(obj, key);

    if (!value || (!json_object_is_type(value, json_type_int) &&
                   !json_object_is_type(value, json_type_double)))
        return fallback;
    return json_object_get_int64(value);
}

static double dblv(struct json_object *obj, const char *key, double fallback,
                   int *present)
{
    struct json_object *value = child(obj, key);

    if (!value || (!json_object_is_type(value, json_type_int) &&
                   !json_object_is_type(value, json_type_double))) {
        if (present) *present = 0;
        return fallback;
    }
    if (present) *present = 1;
    return json_object_get_double(value);
}

static int boolv(struct json_object *obj, const char *key, int fallback)
{
    struct json_object *value = child(obj, key);

    if (!value || (!json_object_is_type(value, json_type_boolean) &&
                   !json_object_is_type(value, json_type_int)))
        return fallback;
    return json_object_get_boolean(value);
}

static int entry_blocked(struct json_object *entry)
{
    const char *dfs_state;

    if (!entry)
        return 1;
    if (boolv(entry, "disabled", 0) || boolv(entry, "no_ir", 0) ||
        boolv(entry, "radar_detection", 0) || boolv(entry, "dfs", 0))
        return 1;
    dfs_state = strv(entry, "dfs_state", "");
    return !strcmp(dfs_state, "required") ||
           !strcmp(dfs_state, "radar") ||
           !strcmp(dfs_state, "unavailable");
}

static struct json_object *clone_json(struct json_object *value)
{
    const char *text;

    if (!value)
        return NULL;
    text = json_object_to_json_string_ext(value, JSON_C_TO_STRING_PLAIN);
    return text ? json_tokener_parse(text) : NULL;
}

static int radio_cmp(const void *left, const void *right)
{
    const struct cai_radio *a = left;
    const struct cai_radio *b = right;
    int cmp = strcmp(a->band, b->band);

    if (cmp) return cmp;
    cmp = strcmp(a->ap_id, b->ap_id);
    if (cmp) return cmp;
    return strcmp(a->id, b->id);
}

static int candidate_cmp(const void *left, const void *right)
{
    const struct cai_candidate *a = left;
    const struct cai_candidate *b = right;

    if (a->score < b->score) return -1;
    if (a->score > b->score) return 1;
    if (a->channel != b->channel) return a->channel - b->channel;
    return a->width_mhz - b->width_mhz;
}

static int radio_high_load(const struct cai_radio *radio)
{
    return radio && ((radio->clients >= 10) ||
                     (radio->have_usage && radio->usage_pct >= 70.0) ||
                     (radio->have_retry && radio->retry_pct >= 20.0));
}

static int band_is_24(const char *band)
{
    return band && (!strcmp(band, "2g") || !strcmp(band, "2.4GHz") ||
                    !strcmp(band, "2.4g") || !strcmp(band, "2GHz"));
}

static int channel_overlap(int a, int aw, int b, int bw, const char *band)
{
    int spacing = 5;
    int a_half = aw > 0 ? aw / 2 : 10;
    int b_half = bw > 0 ? bw / 2 : 10;
    int delta = abs(a - b) * spacing;

    (void)band;

    return delta <= a_half + b_half;
}

static int width_allowed(struct json_object *catalog,
                         struct json_object *entry, int width)
{
    struct json_object *widths = child_array(entry, "supported_widths_mhz");
    size_t i;

    if (!widths)
        widths = child_array(catalog, "supported_widths_mhz");
    if (!widths)
        return width == 20;
    for (i = 0; i < json_object_array_length(widths); i++)
        if (json_object_get_int(json_object_array_get_idx(widths, i)) == width)
            return 1;
    return 0;
}

static int catalog_segment_legal(struct json_object *catalog,
                                 struct json_object *start, int width)
{
    struct json_object *entries = child_array(catalog, "channels");
    int start_freq = intv(start, "frequency_mhz", 0);
    int need = width / 20;
    int found = 0;
    size_t i;

    if (width == 20)
        return 1;
    if (!entries || !start_freq || need < 2)
        return 0;
    for (i = 0; i < (size_t)need; i++) {
        int expected_freq = start_freq + (int)i * 20;
        int segment_entry = 0;
        size_t j;

        for (j = 0; j < json_object_array_length(entries); j++) {
            struct json_object *entry = json_object_array_get_idx(entries, j);

            if (intv(entry, "frequency_mhz", 0) != expected_freq)
                continue;
            segment_entry = 1;
            if (entry_blocked(entry) || !width_allowed(catalog, entry, width))
                return 0;
            break;
        }
        if (!segment_entry)
            return 0;
        found++;
    }
    return found >= need;
}

static int sample_matches(struct json_object *sample, int channel, int frequency)
{
    int sample_channel = intv(sample, "channel", 0);
    int sample_freq = intv(sample, "frequency_mhz", 0);

    return (channel && sample_channel == channel) ||
           (frequency && sample_freq == frequency);
}

static double survey_score_for(struct json_object *wifi_data,
                               struct cai_radio *radio, int channel,
                               int frequency,
                               int64_t now_s,
                               int *measured)
{
    struct json_object *environment = child_obj(wifi_data, "environment");
    struct json_object *channel_survey = child_obj(environment, "channel_survey");
    struct json_object *samples = child_array(channel_survey, "samples");
    struct json_object *survey = child_obj(radio->obj, "survey");
    struct cai_survey_point points[CAI_MAX_SURVEY_SAMPLES];
    double best = 0.0;
    double minimum_noise = -100.0;
    size_t point_count = 0;
    size_t i;

    for (i = 0; samples && i < json_object_array_length(samples); i++) {
        struct json_object *sample = json_object_array_get_idx(samples, i);
        double noise, active, busy, tx, rx;
        int hn, ha, hb, ht, hr;

        if (!sample || strcmp(strv(sample, "radio_id", ""), radio->id) ||
            !sample_matches(sample, channel, frequency))
            continue;
        if (boolv(sample, "stale", 0) ||
            (i64v(sample, "sample_time", 0) > 0 && now_s >
             i64v(sample, "sample_time", 0) + CAI_SURVEY_MAX_AGE_S))
            continue;
        noise = dblv(sample, "noise_dbm", 0.0, &hn);
        active = dblv(sample, "channel_active_time_ms", 0.0, &ha);
        busy = dblv(sample, "channel_busy_time_ms", 0.0, &hb);
        tx = dblv(sample, "channel_transmit_time_ms", 0.0, &ht);
        rx = dblv(sample, "channel_receive_time_ms", 0.0, &hr);
        if (!hn || !ha || active <= 0.0 || point_count >= CAI_MAX_SURVEY_SAMPLES)
            continue;
        if (hb && ht && tx >= 0.0 && busy >= tx && busy <= active &&
            active > tx) {
            double denominator = active - tx;
            double occupancy = (busy - tx) / denominator;

            if (occupancy < 0.0 || occupancy > 1.0)
                continue;
            points[point_count].noise = noise;
            points[point_count].occupancy = occupancy;
            points[point_count].rx_ratio = 0.0;
            points[point_count].use_busy = 1;
            point_count++;
            if (point_count == 1 || noise < minimum_noise)
                minimum_noise = noise;
        } else if (hr && rx >= 0.0 && rx <= active) {
            points[point_count].noise = noise;
            points[point_count].occupancy = 0.0;
            points[point_count].rx_ratio = rx / active;
            points[point_count].use_busy = 0;
            point_count++;
            if (point_count == 1 || noise < minimum_noise)
                minimum_noise = noise;
        }
    }
    if (point_count == 0 && survey &&
        (!intv(survey, "channel", 0) || intv(survey, "channel", 0) == channel) &&
        (!intv(survey, "frequency_mhz", 0) ||
         intv(survey, "frequency_mhz", 0) == frequency) &&
        !boolv(survey, "stale", 0) &&
        !(i64v(survey, "sample_time", 0) > 0 && now_s >
          i64v(survey, "sample_time", 0) + CAI_SURVEY_MAX_AGE_S)) {
        double noise, active, busy, tx, rx;
        int hn, ha, hb, ht, hr;

        noise = dblv(survey, "noise_dbm", 0.0, &hn);
        active = dblv(survey, "channel_active_time_ms", 0.0, &ha);
        busy = dblv(survey, "channel_busy_time_ms", 0.0, &hb);
        tx = dblv(survey, "channel_transmit_time_ms", 0.0, &ht);
        rx = dblv(survey, "channel_receive_time_ms", 0.0, &hr);
        if (hn && ha && active > 0.0 && point_count < CAI_MAX_SURVEY_SAMPLES &&
            hb && ht && tx >= 0.0 && busy >= tx && busy <= active &&
            active > tx) {
            double occupancy = (busy - tx) / (active - tx);

            if (occupancy >= 0.0 && occupancy <= 1.0) {
                points[0].noise = noise;
                points[0].occupancy = occupancy;
                points[0].rx_ratio = 0.0;
                points[0].use_busy = 1;
                minimum_noise = noise;
                point_count = 1;
            }
        } else if (hn && ha && active > 0.0 && hr && rx >= 0.0 && rx <= active) {
            points[0].noise = noise;
            points[0].occupancy = 0.0;
            points[0].rx_ratio = rx / active;
            points[0].use_busy = 0;
            minimum_noise = noise;
            point_count = 1;
        }
    }
    if (point_count > 0) {
        double minimum_noise_amp = pow(10.0, minimum_noise / 10.0);

        for (i = 0; i < point_count; i++) {
            double noise_amp = pow(10.0, points[i].noise / 10.0);

            best += pow(10.0, points[i].noise / 5.0) +
                    (points[i].use_busy ?
                     points[i].occupancy * pow(2.0,
                         noise_amp - minimum_noise_amp) :
                     points[i].rx_ratio);
        }
        best /= (double)point_count;
    }
    if (measured) *measured = point_count > 0;
    return point_count > 0 ? best : 0.0;
}

static double neighbor_score_for(struct json_object *wifi_data,
                                 struct cai_radio *radio, int channel,
                                 int width, int64_t now_s, int *degraded)
{
    struct json_object *rows = child_array(wifi_data, "interference");
    struct json_object *environment = child_obj(wifi_data, "environment");
    struct json_object *neighbor_scan = child_obj(environment, "neighbor_scan");
    int64_t observed_at = i64v(neighbor_scan, "observed_at", 0);
    double score = 0.0;
    size_t i;

    /* An expired scan is a freshness signal, not current RF evidence. */
    if (neighbor_scan && ((boolv(neighbor_scan, "stale", 0)) ||
        (observed_at > 0 && now_s > observed_at + CAI_NEIGHBOR_MAX_AGE_S))) {
        if (degraded)
            *degraded = 0;
        return 0.0;
    }

    for (i = 0; rows && i < json_object_array_length(rows); i++) {
        struct json_object *row = json_object_array_get_idx(rows, i);
        const char *row_radio = strv(row, "radio_id", "");
        const char *row_local = strv(row, "local_radio_id", "");
        int row_channel = intv(row, "channel", 0);
        int row_freq = intv(row, "frequency_mhz", 0);
        int row_width = intv(row, "width_mhz", intv(row, "width", 20));
        int rssi_present = 0;
        double rssi = dblv(row, "rssi_dbm", -100.0, &rssi_present);
        if (!rssi_present)
            rssi = dblv(row, "signal", -100.0, &rssi_present);
        int overlap = row_channel ? channel_overlap(channel, width, row_channel,
                                                     row_width, radio->band) :
                                    (row_freq != 0);

        if (!row || (row_radio[0] && strcmp(row_radio, radio->id) &&
                     strcmp(row_local, radio->id)) || !overlap)
            continue;
        if (!rssi_present)
            rssi = -100.0;
        score += pow(10.0, (rssi + 100.0) / 10.0) *
                 (row_width > 0 ? (double)row_width / 20.0 : 1.0);
    }
    if (degraded)
        *degraded = score > 0.0;
    return score;
}

static int radio_has_neighbor_evidence(struct json_object *wifi_data,
                                       const struct cai_radio *radio,
                                       int64_t now_s)
{
    struct json_object *rows = child_array(wifi_data, "interference");
    struct json_object *environment = child_obj(wifi_data, "environment");
    struct json_object *neighbor_scan = child_obj(environment, "neighbor_scan");
    int64_t observed_at = i64v(neighbor_scan, "observed_at", 0);
    size_t i;

    if (neighbor_scan && (boolv(neighbor_scan, "stale", 0) ||
        (observed_at > 0 && now_s > observed_at + CAI_NEIGHBOR_MAX_AGE_S)))
        return 0;

    for (i = 0; rows && i < json_object_array_length(rows); i++) {
        struct json_object *row = json_object_array_get_idx(rows, i);
        const char *row_radio = strv(row, "radio_id", "");
        const char *row_local = strv(row, "local_radio_id", "");

        if (!row || (row_radio[0] && strcmp(row_radio, radio->id) &&
                     strcmp(row_local, radio->id)))
            continue;
        if (intv(row, "channel", 0) > 0 || intv(row, "frequency_mhz", 0) > 0)
            return 1;
    }
    return 0;
}

static size_t neighbor_count_for(struct json_object *wifi_data,
                                 const struct cai_radio *radio,
                                 int64_t now_s)
{
    struct json_object *environment = child_obj(wifi_data, "environment");
    struct json_object *neighbor_scan = child_obj(environment, "neighbor_scan");
    struct json_object *rows = child_array(wifi_data, "interference");
    int64_t observed_at = i64v(neighbor_scan, "observed_at", 0);
    size_t count = 0;
    size_t i;

    if (neighbor_scan && (boolv(neighbor_scan, "stale", 0) ||
        (observed_at > 0 && now_s > observed_at + CAI_NEIGHBOR_MAX_AGE_S)))
        return 0;
    for (i = 0; rows && i < json_object_array_length(rows); i++) {
        struct json_object *row = json_object_array_get_idx(rows, i);
        const char *row_radio = strv(row, "radio_id", "");
        const char *row_local = strv(row, "local_radio_id", "");

        if (row && (!row_radio[0] || !strcmp(row_radio, radio->id) ||
                    !strcmp(row_local, radio->id)))
            count++;
    }
    return count;
}

static size_t survey_sample_count_for(struct json_object *wifi_data,
                                      const struct cai_radio *radio,
                                      int64_t now_s)
{
    struct json_object *environment = child_obj(wifi_data, "environment");
    struct json_object *channel_survey = child_obj(environment, "channel_survey");
    struct json_object *samples = child_array(channel_survey, "samples");
    size_t count = 0;
    size_t i;

    for (i = 0; samples && i < json_object_array_length(samples); i++) {
        struct json_object *sample = json_object_array_get_idx(samples, i);
        int64_t sample_time;

        if (!sample || strcmp(strv(sample, "radio_id", ""), radio->id) ||
            boolv(sample, "stale", 0))
            continue;
        sample_time = i64v(sample, "sample_time", 0);
        if (sample_time > 0 && now_s > sample_time + CAI_SURVEY_MAX_AGE_S)
            continue;
        count++;
    }
    return count;
}

static int radio_load(struct cai_radio *radio)
{
    int present;
    int usage_present;

    radio->clients = intv(radio->obj, "clients", intv(radio->obj, "client_count", 0));
    radio->retry_pct = dblv(radio->obj, "retry_rate", 0.0, &present);
    radio->have_retry = present;
    radio->usage_pct = dblv(radio->obj, "usage_pct", 0.0, &usage_present);
    if (!usage_present)
        radio->usage_pct = dblv(radio->obj, "usage_24h_pct", 0.0,
                                &usage_present);
    radio->have_usage = usage_present;
    radio->stale = boolv(radio->obj, "stale", 0);
    return 0;
}

static double own_network_score(struct cai_radio *radio, struct cai_radio *all,
                                size_t count, int channel, int width)
{
    double score = 0.0;
    size_t i;

    for (i = 0; i < count; i++) {
        double load;

        if (&all[i] == radio || strcmp(all[i].band, radio->band) ||
            all[i].current_channel <= 0 ||
            !channel_overlap(channel, width, all[i].current_channel,
                             all[i].current_width, radio->band))
            continue;
        load = all[i].clients > 0 ? all[i].clients : 1;
        if (all[i].have_retry) load += all[i].retry_pct / 10.0;
        if (all[i].have_usage) load += all[i].usage_pct / 10.0;
        score += load;
    }
    return score;
}

static void candidate_add(struct cai_radio *radio, struct json_object *wifi_data,
                          struct json_object *catalog, struct json_object *entry,
                          struct cai_radio *all, size_t all_count, int width,
                          int64_t now_s)
{
    struct cai_candidate *candidate;
    int channel = intv(entry, "channel", 0);
    int measured = 0;
    int degraded = 0;
    double survey;
    double neighbor;
    double own;
    double change_cost = 0.0;
    const char *band = radio->band;

    if (!channel || radio->candidate_count >= CAI_MAX_CANDIDATES ||
        entry_blocked(entry) || !width_allowed(catalog, entry, width) ||
        !catalog_segment_legal(catalog, entry, width))
        return;
    if (radio->current_channel == channel && radio->current_width == width)
        change_cost = 0.0;
    else {
        change_cost = radio->clients * 0.02;
        if (radio->have_retry) change_cost += radio->retry_pct * 0.01;
        if (radio->have_usage) change_cost += radio->usage_pct * 0.005;
    }
    survey = survey_score_for(wifi_data, radio, channel,
                              intv(entry, "frequency_mhz", 0),
                              now_s,
                              &measured);
    neighbor = neighbor_score_for(wifi_data, radio, channel, width, now_s,
                                  &degraded);
    /* A usable BSS scan is evidence even when this particular candidate has
     * no overlapping BSS.  Keep those candidates in the conservative
     * degraded tier instead of treating an observed clean channel as an
     * unknown zero-cost channel. */
    if (!measured && !degraded &&
        radio_has_neighbor_evidence(wifi_data, radio, now_s))
        degraded = 1;
    own = own_network_score(radio, all, all_count, channel, width);
    if (band_is_24(band) && channel != 1 && channel != 6 && channel != 11)
        neighbor += 0.25;
    candidate = &radio->candidates[radio->candidate_count++];
    memset(candidate, 0, sizeof(*candidate));
    candidate->channel = channel;
    candidate->width_mhz = width;
    candidate->survey_score = survey;
    candidate->neighbor_score = neighbor;
    candidate->own_score = own;
    /* A candidate without either current survey evidence or a BSS
     * observation is unknown, not clean. Keep it visible for diagnostics but
     * make it ineligible for selection while measured/degraded candidates
     * exist. */
    candidate->risk_score = (!measured && !degraded) ? 1000000.0 : 0.0;
    candidate->change_cost = change_cost;
    candidate->score = survey + neighbor + own + candidate->risk_score +
                       change_cost;
    candidate->measured = measured;
    candidate->degraded = degraded;
}

static void build_candidates(struct cai_radio *radio, struct json_object *wifi_data,
                             struct cai_radio *all, size_t all_count,
                             int64_t now_s)
{
    struct json_object *catalog = child_obj(radio->obj, "channel_catalog");
    struct json_object *entries = child_array(catalog, "channels");
    struct json_object *supported = child_array(catalog, "supported_widths_mhz");
    int widths[] = {20, 40, 80, 160, 320};
    size_t i, w;

    if (!catalog || !boolv(catalog, "complete", 0) || !entries)
        return;
    for (i = 0; i < json_object_array_length(entries); i++) {
        struct json_object *entry = json_object_array_get_idx(entries, i);

        for (w = 0; w < sizeof(widths) / sizeof(widths[0]); w++) {
            int allowed = supported == NULL ? (widths[w] == 20) : 0;

            if (supported) {
                size_t j;
                allowed = 0;
                for (j = 0; j < json_object_array_length(supported); j++)
                    if (json_object_get_int(json_object_array_get_idx(supported, j)) == widths[w])
                        allowed = 1;
            }
            if (allowed)
                candidate_add(radio, wifi_data, catalog, entry, all, all_count,
                              widths[w], now_s);
        }
    }
    qsort(radio->candidates, radio->candidate_count,
          sizeof(radio->candidates[0]), candidate_cmp);
}

static double assignment_cost(const struct cai_radio *radio,
                              const struct cai_radio *assigned,
                              size_t assigned_count, size_t candidate_index)
{
    const struct cai_candidate *candidate = &radio->candidates[candidate_index];
    double cost = candidate->score;
    size_t i;

    for (i = 0; i < assigned_count; i++) {
        if (strcmp(assigned[i].band, radio->band) ||
            !channel_overlap(candidate->channel, candidate->width_mhz,
                             assigned[i].candidates[assigned[i].selected].channel,
                             assigned[i].candidates[assigned[i].selected].width_mhz,
                             radio->band))
            continue;
        if (radio_high_load(radio) && radio_high_load(&assigned[i]))
            cost += 1000000.0;
        else
            cost += 10.0 + assigned[i].clients + radio->clients;
    }
    return cost;
}

static void select_assignment(struct cai_radio *radios, size_t count)
{
    size_t i, j;

    for (i = 0; i < count; i++) {
        double best = HUGE_VAL;
        size_t best_index = 0;

        for (j = 0; j < radios[i].candidate_count; j++) {
            double cost = assignment_cost(&radios[i], radios, i, j);

            if (cost < best || (cost == best &&
                candidate_cmp(&radios[i].candidates[j],
                              &radios[i].candidates[best_index]) < 0)) {
                best = cost;
                best_index = j;
            }
        }
        radios[i].selected = best_index;
        radios[i].assignment_selected = 1;
    }
}

static int assignment_combination_too_large(const struct cai_radio *radios,
                                            size_t count)
{
    unsigned long long combinations = 1;
    size_t i;

    if (count > CAI_MAX_ASSIGNMENT_RADIOS)
        return 1;
    for (i = 0; i < count; i++) {
        size_t candidates = radios[i].candidate_count;

        if (!candidates)
            continue;
        if (combinations > CAI_MAX_ASSIGNMENT_COMBINATIONS / candidates)
            return 1;
        combinations *= candidates;
    }
    return 0;
}

static int assignment_has_high_load_conflict(const struct cai_radio *radios,
                                             size_t count)
{
    size_t i, j;

    for (i = 0; i < count; i++) {
        if (!radios[i].assignment_selected || !radio_high_load(&radios[i]))
            continue;
        for (j = i + 1; j < count; j++) {
            if (!radios[j].assignment_selected ||
                !radio_high_load(&radios[j]) ||
                strcmp(radios[i].band, radios[j].band))
                continue;
            if (channel_overlap(
                    radios[i].candidates[radios[i].selected].channel,
                    radios[i].candidates[radios[i].selected].width_mhz,
                    radios[j].candidates[radios[j].selected].channel,
                    radios[j].candidates[radios[j].selected].width_mhz,
                    radios[i].band))
                return 1;
        }
    }
    return 0;
}

static void hex_digest(const unsigned char *digest, char *out)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        out[i * 2] = digits[digest[i] >> 4];
        out[i * 2 + 1] = digits[digest[i] & 15];
    }
    out[SHA256_DIGEST_LENGTH * 2] = '\0';
}

static void add_reason(struct json_object *reasons, const char *code,
                       int channel, const char *evidence)
{
    struct json_object *reason = json_object_new_object();

    json_object_object_add(reason, "code", json_object_new_string(code));
    if (channel > 0)
        json_object_object_add(reason, "channel", json_object_new_int(channel));
    json_object_object_add(reason, "evidence",
                           json_object_new_string(evidence));
    json_object_array_add(reasons, reason);
}

static struct json_object *candidate_components(
    const struct cai_candidate *candidate)
{
    struct json_object *components = json_object_new_object();

    if (!components || !candidate)
        return components;
    json_object_object_add(components, "survey_score",
                           json_object_new_double(candidate->survey_score));
    json_object_object_add(components, "neighbor_bss_score",
                           json_object_new_double(candidate->neighbor_score));
    json_object_object_add(components, "own_network_overlap_score",
                           json_object_new_double(candidate->own_score));
    json_object_object_add(components, "dfs_radar_risk_score",
                           json_object_new_double(candidate->risk_score));
    json_object_object_add(components, "change_cost_score",
                           json_object_new_double(candidate->change_cost));
    return components;
}

static int plan_digest_hex(struct json_object *root, const char *domain,
                           char *out, size_t out_len)
{
    struct json_object *canonical;
    struct json_object *plan;
    const char *serialized;
    EVP_MD_CTX *context = NULL;
    unsigned char digest[SHA256_DIGEST_LENGTH];

    if (!root || !out || out_len < SHA256_DIGEST_LENGTH * 2 + 1)
        return -1;
    canonical = clone_json(root);
    if (!canonical)
        return -1;
    plan = child_obj(canonical, "plan");
    if (!plan) {
        json_object_put(canonical);
        return -1;
    }
    /* The generation time is response metadata, not part of the RF plan.
     * Removing it makes an unchanged evidence snapshot retain one identity. */
    json_object_object_del(plan, "generated_at");
    json_object_object_del(plan, "plan_id");
    json_object_object_del(plan, "plan_digest");
    json_object_object_del(plan, "evidence_digest");
    serialized = json_object_to_json_string_ext(canonical,
                                                 JSON_C_TO_STRING_PLAIN);
    if (!serialized) {
        json_object_put(canonical);
        return -1;
    }
    context = EVP_MD_CTX_new();
    if (!context || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(context, domain, strlen(domain)) != 1 ||
        EVP_DigestUpdate(context, serialized, strlen(serialized)) != 1 ||
        EVP_DigestFinal_ex(context, digest, NULL) != 1) {
        EVP_MD_CTX_free(context);
        json_object_put(canonical);
        return -1;
    }
    EVP_MD_CTX_free(context);
    hex_digest(digest, out);
    json_object_put(canonical);
    return 0;
}

struct json_object *wifi_channel_ai_plan_json(struct json_object *wifi_data,
                                              int64_t now_s)
{
    struct json_object *root = json_object_new_object();
    struct json_object *plan = json_object_new_object();
    struct json_object *radios_json = child_array(wifi_data, "radios");
    struct json_object *out_radios = json_object_new_array();
    struct cai_radio radios[CAI_MAX_RADIOS];
    struct json_object *blocked = json_object_new_array();
    char digest_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    char evidence_digest_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    const char *status = "ready";
    size_t count = 0, i;
    int scan_recommended = 0;
    int insufficient = 0;
    int configuration_too_complex = 0;
    int degraded_only = 0;

    if (!root || !plan || !out_radios || !blocked)
        goto fail;
    memset(radios, 0, sizeof(radios));
    for (i = 0; radios_json && i < json_object_array_length(radios_json) &&
                count < CAI_MAX_RADIOS; i++) {
        struct json_object *radio = json_object_array_get_idx(radios_json, i);
        struct cai_radio *dst;

        if (!radio || !json_object_is_type(radio, json_type_object))
            continue;
        dst = &radios[count++];
        dst->obj = radio;
        dst->id = strv(radio, "id", "");
        dst->ap_id = strv(radio, "ap_id", "local");
        dst->band = strv(radio, "band", "");
        dst->current_channel = intv(radio, "channel", 0);
        dst->current_width = intv(radio, "width_mhz",
                                   intv(radio, "width", 20));
        radio_load(dst);
    }
    qsort(radios, count, sizeof(radios[0]), radio_cmp);
    if (count == 0)
        insufficient = 1;
    for (i = 0; i < count; i++) {
        struct json_object *catalog = child_obj(radios[i].obj, "channel_catalog");
        int64_t observed = i64v(catalog, "observed_at", 0);
        struct json_object *neighbor = child_obj(wifi_data, "environment");
        struct json_object *neighbor_scan = child_obj(neighbor, "neighbor_scan");
        int64_t neighbor_at = i64v(neighbor_scan, "observed_at",
                                   i64v(radios[i].obj, "neighbor_observed_at", 0));
        struct json_object *neighbor_samples_obj = child_array(neighbor_scan,
                                                                "samples");
        int neighbor_samples = neighbor_samples_obj ?
            (int)json_object_array_length(neighbor_samples_obj) : 0;

        if (!catalog || !boolv(catalog, "complete", 0)) {
            insufficient = 1;
            continue;
        }
        if ((neighbor_at > 0 && now_s > neighbor_at + CAI_NEIGHBOR_MAX_AGE_S) ||
            (neighbor_scan && !neighbor_samples &&
             !strcmp(strv(neighbor_scan, "reason", ""), "scan_not_yet_run")))
            scan_recommended = 1;
        build_candidates(&radios[i], wifi_data, radios, count, now_s);
        {
            int have_measured = 0;
            int have_degraded = radio_has_neighbor_evidence(wifi_data,
                                                            &radios[i], now_s);
            size_t candidate_index;

            for (candidate_index = 0;
                 candidate_index < radios[i].candidate_count;
                 candidate_index++) {
                have_measured |= radios[i].candidates[candidate_index].measured;
                have_degraded |= radios[i].candidates[candidate_index].degraded;
            }
            if (!have_measured && !have_degraded)
                insufficient = 1;
            if (!have_measured && have_degraded)
                degraded_only = 1;
        }
        if (radios[i].candidate_count == 0)
            insufficient = 1;
        (void)observed;
    }
    if (assignment_combination_too_large(radios, count))
        configuration_too_complex = 1;
    if (!insufficient && !configuration_too_complex && !scan_recommended)
        select_assignment(radios, count);
    if (!configuration_too_complex &&
        assignment_has_high_load_conflict(radios, count)) {
        configuration_too_complex = 1;
        for (i = 0; i < count; i++)
            radios[i].assignment_selected = 0;
    }
    if (scan_recommended)
        status = "scan_recommended";
    else if (insufficient)
        status = "insufficient_evidence";
    else if (configuration_too_complex)
        status = "configuration_too_complex";
    else if (degraded_only)
        status = "partial_support";

    for (i = 0; i < count; i++) {
        if (!radios[i].candidate_count || configuration_too_complex ||
            scan_recommended) {
            struct json_object *item = json_object_new_object();

            json_object_object_add(item, "radio_id",
                                   json_object_new_string(radios[i].id));
            json_object_object_add(item, "ap_id",
                                   json_object_new_string(radios[i].ap_id));
            json_object_object_add(item, "reason", json_object_new_string(
                configuration_too_complex ? "configuration_too_complex" :
                scan_recommended ? "scan_recommended" : "channels_insufficient"));
            if (configuration_too_complex)
                json_object_object_add(item, "included",
                                       json_object_new_boolean(0));
            json_object_array_add(blocked, item);
        }
    }

    {
        struct json_object *capabilities = child_obj(wifi_data, "capabilities");
        int64_t config_revision = capabilities ?
            i64v(capabilities, "wifi_desired_revision",
                 i64v(wifi_data, "revision", 0)) :
            i64v(wifi_data, "revision", 0);

        json_object_object_add(plan, "plan_revision",
                               json_object_new_int64(config_revision));
        json_object_object_add(plan, "expected_config_revision",
                               json_object_new_int64(config_revision));
    }
    json_object_object_add(plan, "status", json_object_new_string(status));
    json_object_object_add(plan, "generated_at", json_object_new_int64(now_s));
    json_object_object_add(plan, "scoring_profile", json_object_new_string(CAI_PROFILE));
    {
        struct json_object *policy = json_object_new_object();
        json_object_object_add(policy, "neighbor_max_age_s", json_object_new_int(CAI_NEIGHBOR_MAX_AGE_S));
        json_object_object_add(policy, "survey_max_age_s", json_object_new_int(CAI_SURVEY_MAX_AGE_S));
        json_object_object_add(policy, "usage_max_age_s", json_object_new_int(CAI_USAGE_MAX_AGE_S));
        json_object_object_add(plan, "freshness_policy", policy);
    }
    for (i = 0; i < count; i++) {
        struct json_object *row = json_object_new_object();
        struct json_object *current = json_object_new_object();
        struct json_object *proposed = json_object_new_object();
        struct json_object *reasons = json_object_new_array();
        struct cai_candidate *best = NULL;
        struct cai_candidate *current_candidate = NULL;
        size_t j;
        const char *action = "keep_current";
        const char *confidence = "unknown";
        double before = 0.0;
        double after = 0.0;

        if (radios[i].candidate_count > 0 && radios[i].assignment_selected) {
            best = &radios[i].candidates[radios[i].selected];
            after = best->score;
            for (j = 0; j < radios[i].candidate_count; j++) {
                if (radios[i].candidates[j].channel == radios[i].current_channel &&
                    radios[i].candidates[j].width_mhz == radios[i].current_width) {
                    current_candidate = &radios[i].candidates[j];
                    before = current_candidate->score;
                    break;
                }
            }
            if (!current_candidate)
                before = after;
            if (best->channel != radios[i].current_channel ||
                best->width_mhz != radios[i].current_width) {
                double improvement = before - after;
                double threshold = CAI_CHANGE_MIN_IMPROVEMENT + radios[i].clients * 0.005;

                if (improvement > threshold) {
                    action = "suggest_change";
                    add_reason(reasons, "lower_neighbor_overlap", best->channel,
                               best->degraded ? "neighbor_scan" : "channel_catalog");
                } else {
                    add_reason(reasons, "keep_current_hysteresis",
                               radios[i].current_channel, "usage");
                }
            }
            if (best->measured)
                confidence = "measured";
            else if (best->degraded)
                confidence = "degraded_bss_only";
            else
                confidence = "unknown";
            if (best->measured)
                add_reason(reasons, "lower_busy_ratio", best->channel, "iw_survey");
            add_reason(reasons, "width_segment_legal", best->channel, "channel_catalog");
        }
        json_object_object_add(current, "channel", json_object_new_int(radios[i].current_channel));
        json_object_object_add(current, "width_mhz", json_object_new_int(radios[i].current_width));
        if (best) {
            json_object_object_add(proposed, "channel", json_object_new_int(best->channel));
            json_object_object_add(proposed, "width_mhz", json_object_new_int(best->width_mhz));
        } else {
            json_object_object_add(proposed, "channel", json_object_new_null());
            json_object_object_add(proposed, "width_mhz", json_object_new_null());
        }
        json_object_object_add(row, "ap_id", json_object_new_string(radios[i].ap_id));
        json_object_object_add(row, "radio_id", json_object_new_string(radios[i].id));
        json_object_object_add(row, "band", json_object_new_string(radios[i].band));
        json_object_object_add(row, "current", current);
        json_object_object_add(row, "proposed", proposed);
        json_object_object_add(row, "score_before", json_object_new_double(before));
        json_object_object_add(row, "score_after", json_object_new_double(after));
        json_object_object_add(row, "score_components_before",
                               candidate_components(current_candidate ?
                                                    current_candidate : best));
        json_object_object_add(row, "score_components_after",
                               candidate_components(best));
        json_object_object_add(row, "improvement_pct", json_object_new_double(before > 0.0 ? (before - after) * 100.0 / before : 0.0));
        json_object_object_add(row, "action", json_object_new_string(action));
        json_object_object_add(row, "confidence", json_object_new_string(confidence));
        json_object_object_add(row, "reasons", reasons);
        {
            struct json_object *evidence = json_object_new_object();
            struct json_object *environment = child_obj(wifi_data, "environment");
            struct json_object *neighbor_scan = child_obj(environment,
                                                           "neighbor_scan");
            struct json_object *catalog = child_obj(radios[i].obj,
                                                    "channel_catalog");

            json_object_object_add(evidence, "neighbor_count",
                                   json_object_new_int((int)neighbor_count_for(
                                       wifi_data, &radios[i], now_s)));
            json_object_object_add(evidence, "neighbor_observed_at",
                neighbor_scan ? json_object_new_int64(i64v(neighbor_scan,
                                                             "observed_at", 0)) :
                                json_object_new_null());
            json_object_object_add(evidence, "survey_samples",
                                   json_object_new_int((int)
                                       survey_sample_count_for(wifi_data,
                                                               &radios[i],
                                                               now_s)));
            json_object_object_add(evidence, "catalog_observed_at",
                catalog ? json_object_new_int64(i64v(catalog, "observed_at", 0)) :
                         json_object_new_null());
            json_object_object_add(evidence, "client_count", json_object_new_int(radios[i].clients));
            json_object_object_add(evidence, "retry_pct", radios[i].have_retry ? json_object_new_double(radios[i].retry_pct) : json_object_new_null());
            json_object_object_add(row, "evidence", evidence);
        }
        json_object_array_add(out_radios, row);
    }
    json_object_object_add(plan, "radios", out_radios);
    json_object_object_add(plan, "blocked", blocked);
    json_object_object_add(plan, "radios_total", json_object_new_int((int)count));
    {
        struct json_object *summary = json_object_new_object();
        int unchanged = 0;
        int planned = 0;
        double estimated_before = 0.0;
        double estimated_after = 0.0;

        for (i = 0; i < count; i++) {
            int current_found = 0;
            size_t j;

            if (radios[i].candidate_count > 0 && radios[i].assignment_selected &&
                radios[i].candidates[radios[i].selected].channel ==
                    radios[i].current_channel &&
                radios[i].candidates[radios[i].selected].width_mhz ==
                    radios[i].current_width)
                unchanged++;
            if (radios[i].candidate_count > 0 && radios[i].assignment_selected)
                planned++;
            if (!radios[i].assignment_selected)
                continue;
            estimated_after += radios[i].candidates[radios[i].selected].score;
            for (j = 0; j < radios[i].candidate_count; j++) {
                if (radios[i].candidates[j].channel ==
                        radios[i].current_channel &&
                    radios[i].candidates[j].width_mhz ==
                        radios[i].current_width) {
                    estimated_before += radios[i].candidates[j].score;
                    current_found = 1;
                    break;
                }
            }
            if (!current_found)
                estimated_before += radios[i].candidates[radios[i].selected].score;
        }
        json_object_object_add(summary, "radios_total",
                               json_object_new_int((int)count));
        json_object_object_add(summary, "radios_planned",
                               json_object_new_int(planned));
        json_object_object_add(summary, "radios_unchanged",
                               json_object_new_int(unchanged));
        json_object_object_add(summary, "radios_scan_recommended",
                               json_object_new_int(scan_recommended ? (int)count : 0));
        json_object_object_add(summary, "estimated_score_before",
                               json_object_new_double(estimated_before));
        json_object_object_add(summary, "estimated_score_after",
                               json_object_new_double(estimated_after));
        json_object_object_add(plan, "summary", summary);
    }
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "plan", plan);
    if (plan_digest_hex(root, "channel-ai-plan-v1\n", digest_hex,
                        sizeof(digest_hex)) != 0 ||
        plan_digest_hex(root, "channel-ai-evidence-v1\n", evidence_digest_hex,
                        sizeof(evidence_digest_hex)) != 0)
        goto fail;
    {
        char full[80];
        char evidence_full[80];
        char plan_id[80];

        snprintf(full, sizeof(full), "sha256:%s", digest_hex);
        snprintf(evidence_full, sizeof(evidence_full), "sha256:%s",
                 evidence_digest_hex);
        snprintf(plan_id, sizeof(plan_id), "cai-%lld-%.*s",
                 (long long)i64v(plan, "plan_revision", 0), 16, digest_hex);
        json_object_object_add(plan, "plan_digest", json_object_new_string(full));
        json_object_object_add(plan, "evidence_digest",
                               json_object_new_string(evidence_full));
        json_object_object_add(plan, "plan_id", json_object_new_string(plan_id));
    }
    return root;

fail:
    if (blocked) json_object_put(blocked);
    if (out_radios) json_object_put(out_radios);
    if (plan) json_object_put(plan);
    if (root) json_object_put(root);
    return NULL;
}

struct json_object *wifi_channel_ai_status_json(struct json_object *wifi_data,
                                                int64_t now_s)
{
    struct json_object *plan = wifi_channel_ai_plan_json(wifi_data, now_s);
    struct json_object *status = json_object_new_object();
    struct json_object *plan_obj = child_obj(plan, "plan");

    if (!status)
        goto done;
    json_object_object_add(status, "available", json_object_new_boolean(
        plan_obj && (!strcmp(strv(plan_obj, "status", ""), "ready") ||
                     !strcmp(strv(plan_obj, "status", ""),
                             "partial_support"))));
    json_object_object_add(status, "reason", json_object_new_string(
        strv(plan_obj, "status", "insufficient_evidence")));
    if (plan_obj)
        json_object_object_add(status, "plan", clone_json(plan_obj));
done:
    if (plan) json_object_put(plan);
    return status;
}

struct json_object *wifi_channel_ai_apply_disabled_json(const char *plan_id,
                                                        const char *reason)
{
    struct json_object *root = json_object_new_object();

    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "error", json_object_new_string("capability_disabled"));
    json_object_object_add(root, "capability", json_object_new_string("channel_plan"));
    json_object_object_add(root, "reason", json_object_new_string(reason ? reason : "transactional_apply_readback_pending"));
    json_object_object_add(root, "plan_id", json_object_new_string(plan_id ? plan_id : ""));
    json_object_object_add(root, "applied", json_object_new_boolean(0));
    json_object_object_add(root, "rollback", json_object_new_string("not_started"));
    return root;
}

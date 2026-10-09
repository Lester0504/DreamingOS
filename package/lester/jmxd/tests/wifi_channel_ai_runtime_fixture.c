// SPDX-License-Identifier: GPL-2.0-or-later
/* Deterministic Channel AI planner contract. */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <json-c/json.h>

#include "../src/wifi/wifi_channel_ai.h"

static const char *sample_data(void);

static struct json_object *parse(const char *text)
{
    struct json_tokener *tok = json_tokener_new();
    struct json_object *value = json_tokener_parse_ex(tok, text, -1);

    if (!value) {
        fprintf(stderr, "json error: %s\n", json_tokener_error_desc(json_tokener_get_error(tok)));
        fprintf(stderr, "%s\n", text);
        abort();
    }
    json_tokener_free(tok);
    return value;
}

static struct json_object *child(struct json_object *obj, const char *key)
{
    struct json_object *value = NULL;

    if (!obj || !json_object_object_get_ex(obj, key, &value) || !value) {
        fprintf(stderr, "missing %s in %s\n", key,
                obj ? json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN) : "null");
        abort();
    }
    return value;
}

static const char *string(struct json_object *obj, const char *key)
{
    return json_object_get_string(child(obj, key));
}

static int integer(struct json_object *obj, const char *key)
{
    return json_object_get_int(child(obj, key));
}

static struct json_object *radio_row(struct json_object *plan,
                                     const char *radio_id)
{
    struct json_object *rows = child(plan, "radios");
    size_t i;

    for (i = 0; i < json_object_array_length(rows); i++) {
        struct json_object *row = json_object_array_get_idx(rows, i);

        if (row && !strcmp(string(row, "radio_id"), radio_id))
            return row;
    }
    fprintf(stderr, "missing radio row %s\n", radio_id);
    abort();
}

static int has_blocked_reason(struct json_object *plan, const char *reason)
{
    struct json_object *blocked = child(plan, "blocked");
    size_t i;

    for (i = 0; i < json_object_array_length(blocked); i++) {
        struct json_object *row = json_object_array_get_idx(blocked, i);

        if (row && !strcmp(string(row, "reason"), reason))
            return 1;
    }
    return 0;
}

static void apply_manifest_contract(void)
{
    struct json_object *plan;
    struct json_object *manifest;
    struct json_object *targets;
    struct json_object *target;
    struct json_object *candidate;
    struct json_object *sections;
    struct json_object *options;
    const char *digest;

    plan = parse(
        "{\"status\":\"ready\",\"radios\":[{"
        "\"ap_id\":\"local\",\"radio_id\":\"local:radio:radio0\","
        "\"local_radio_id\":\"radio0\",\"band\":\"5g\","
        "\"action\":\"suggest_change\","
        "\"current\":{\"channel\":36,\"width_mhz\":80,\"htmode\":\"HE80\"},"
        "\"proposed\":{\"channel\":44,\"width_mhz\":40,\"htmode\":\"HE40\"}}]}"
    );
    manifest = wifi_channel_ai_apply_manifest_json(plan);
    assert(json_object_get_boolean(child(manifest, "ok")));
    assert(!strcmp(string(manifest, "scope"), "local"));
    assert(json_object_array_length(child(manifest, "local_radios")) == 1);
    target = json_object_array_get_idx(child(manifest, "local_radios"), 0);
    assert(!strcmp(string(target, "id"), "radio0"));
    assert(integer(target, "channel") == 44);
    assert(integer(target, "width") == 40);
    assert(!strcmp(string(target, "htmode"), "HE40"));
    json_object_put(manifest);
    json_object_put(plan);

    plan = parse(
        "{\"status\":\"partial_support\",\"radios\":[{"
        "\"ap_id\":\"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb\","
        "\"radio_id\":\"ap:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb:radio:radio1\","
        "\"local_radio_id\":\"radio1\",\"band\":\"5g\","
        "\"action\":\"suggest_change\","
        "\"current\":{\"channel\":36,\"width_mhz\":80,\"htmode\":\"EHT80\"},"
        "\"proposed\":{\"channel\":100,\"width_mhz\":160,\"htmode\":\"EHT160\"}}]}"
    );
    manifest = wifi_channel_ai_apply_manifest_json(plan);
    assert(json_object_get_boolean(child(manifest, "ok")));
    assert(!strcmp(string(manifest, "scope"), "managed_ap"));
    targets = child(manifest, "managed_targets");
    assert(json_object_array_length(targets) == 1);
    target = json_object_array_get_idx(targets, 0);
    digest = string(target, "candidate_digest");
    assert(!strncmp(digest, "sha256:", 7));
    assert(strlen(digest) == 71);
    candidate = parse(string(target, "candidate"));
    assert(!strcmp(string(candidate, "format"), "uci-wireless-candidate.v1"));
    assert(!strcmp(string(candidate, "candidate_digest"), digest));
    sections = child(candidate, "sections");
    assert(json_object_array_length(sections) == 1);
    target = json_object_array_get_idx(sections, 0);
    assert(!strcmp(string(target, "section"), "radio1"));
    options = child(target, "options");
    assert(!strcmp(string(options, "channel"), "100"));
    assert(!strcmp(string(options, "htmode"), "EHT160"));
    json_object_put(candidate);
    json_object_put(manifest);
    json_object_put(plan);

    plan = parse(
        "{\"status\":\"ready\",\"radios\":[{"
        "\"ap_id\":\"local\",\"radio_id\":\"local:radio:radio0\","
        "\"local_radio_id\":\"radio0\",\"band\":\"2g\","
        "\"action\":\"keep_current\","
        "\"current\":{\"channel\":1,\"width_mhz\":20,\"htmode\":\"HE20\"},"
        "\"proposed\":{\"channel\":1,\"width_mhz\":20,\"htmode\":\"HE20\"}}]}"
    );
    manifest = wifi_channel_ai_apply_manifest_json(plan);
    assert(json_object_get_boolean(child(manifest, "ok")));
    assert(!strcmp(string(manifest, "scope"), "noop"));
    assert(integer(manifest, "suggested_count") == 0);
    json_object_put(manifest);
    json_object_put(plan);

    plan = parse(
        "{\"status\":\"ready\",\"radios\":["
        "{\"ap_id\":\"local\",\"local_radio_id\":\"radio0\",\"band\":\"2g\","
        "\"action\":\"suggest_change\",\"proposed\":{\"channel\":6,\"width_mhz\":20,\"htmode\":\"HE20\"}},"
        "{\"ap_id\":\"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb\",\"local_radio_id\":\"radio1\",\"band\":\"5g\","
        "\"action\":\"suggest_change\",\"proposed\":{\"channel\":44,\"width_mhz\":80,\"htmode\":\"HE80\"}}]}"
    );
    manifest = wifi_channel_ai_apply_manifest_json(plan);
    assert(!json_object_get_boolean(child(manifest, "ok")));
    assert(!strcmp(string(manifest, "reason"),
                   "mixed_scope_atomic_apply_unsupported"));
    json_object_put(manifest);
    json_object_put(plan);

    plan = parse(
        "{\"status\":\"ready\",\"radios\":["
        "{\"ap_id\":\"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb\",\"local_radio_id\":\"radio0\",\"band\":\"2g\","
        "\"action\":\"suggest_change\",\"proposed\":{\"channel\":6,\"width_mhz\":20,\"htmode\":\"HE20\"}},"
        "{\"ap_id\":\"cccccccc-cccc-4ccc-8ccc-cccccccccccc\",\"local_radio_id\":\"radio1\",\"band\":\"5g\","
        "\"action\":\"suggest_change\",\"proposed\":{\"channel\":44,\"width_mhz\":80,\"htmode\":\"HE80\"}}]}"
    );
    manifest = wifi_channel_ai_apply_manifest_json(plan);
    assert(json_object_get_boolean(child(manifest, "ok")));
    assert(!strcmp(string(manifest, "scope"), "managed_ap"));
    assert(json_object_array_length(child(manifest, "managed_targets")) == 2);
    json_object_put(manifest);
    json_object_put(plan);
}

static struct json_object *new_catalog(const int *channels,
                                       const int *frequencies,
                                       const int *blocked,
                                       size_t count,
                                       const int *widths,
                                       size_t width_count)
{
    struct json_object *catalog = json_object_new_object();
    struct json_object *entries = json_object_new_array();
    struct json_object *supported = json_object_new_array();
    size_t i;

    json_object_object_add(catalog, "complete", json_object_new_boolean(1));
    json_object_object_add(catalog, "observed_at", json_object_new_int64(1999));
    for (i = 0; i < width_count; i++)
        json_object_array_add(supported, json_object_new_int(widths[i]));
    json_object_object_add(catalog, "supported_widths_mhz", supported);
    for (i = 0; i < count; i++) {
        struct json_object *entry = json_object_new_object();

        json_object_object_add(entry, "channel", json_object_new_int(channels[i]));
        json_object_object_add(entry, "frequency_mhz",
                               json_object_new_int(frequencies[i]));
        json_object_object_add(entry, "disabled", json_object_new_boolean(
            blocked && blocked[i] == 1));
        json_object_object_add(entry, "no_ir", json_object_new_boolean(
            blocked && blocked[i] == 2));
        json_object_object_add(entry, "radar_detection",
                               json_object_new_boolean(blocked && blocked[i] == 3));
        json_object_array_add(entries, entry);
    }
    json_object_object_add(catalog, "channels", entries);
    return catalog;
}

static struct json_object *new_radio(const char *id, const char *band,
                                     int channel, int clients,
                                     struct json_object *catalog)
{
    struct json_object *radio = json_object_new_object();

    json_object_object_add(radio, "id", json_object_new_string(id));
    json_object_object_add(radio, "ap_id", json_object_new_string("ap-1"));
    json_object_object_add(radio, "band", json_object_new_string(band));
    json_object_object_add(radio, "channel", json_object_new_int(channel));
    json_object_object_add(radio, "width_mhz", json_object_new_int(20));
    json_object_object_add(radio, "clients", json_object_new_int(clients));
    json_object_object_add(radio, "channel_catalog", catalog);
    return radio;
}

static struct json_object *new_root(struct json_object *radios,
                                    struct json_object *survey,
                                    struct json_object *interference,
                                    int64_t revision,
                                    int64_t observed_at)
{
    struct json_object *root = json_object_new_object();
    struct json_object *environment = json_object_new_object();
    struct json_object *neighbor_scan = json_object_new_object();

    json_object_object_add(root, "revision", json_object_new_int64(revision));
    json_object_object_add(neighbor_scan, "observed_at",
                           json_object_new_int64(observed_at));
    json_object_object_add(neighbor_scan, "samples", json_object_new_array());
    json_object_object_add(environment, "neighbor_scan", neighbor_scan);
    if (survey)
        json_object_object_add(environment, "channel_survey", survey);
    json_object_object_add(root, "environment", environment);
    json_object_object_add(root, "interference", interference ? interference :
                           json_object_new_array());
    json_object_object_add(root, "radios", radios);
    return root;
}

static struct json_object *survey_for(const char *radio_id,
                                      const int *channels,
                                      const int *frequencies,
                                      const int *busy,
                                      size_t count)
{
    struct json_object *survey = json_object_new_object();
    struct json_object *samples = json_object_new_array();
    size_t i;

    for (i = 0; i < count; i++) {
        struct json_object *sample = json_object_new_object();

        json_object_object_add(sample, "radio_id",
                               json_object_new_string(radio_id));
        json_object_object_add(sample, "channel",
                               json_object_new_int(channels[i]));
        json_object_object_add(sample, "frequency_mhz",
                               json_object_new_int(frequencies[i]));
        json_object_object_add(sample, "noise_dbm", json_object_new_int(-95));
        json_object_object_add(sample, "channel_active_time_ms",
                               json_object_new_int(1000));
        json_object_object_add(sample, "channel_busy_time_ms",
                               json_object_new_int(busy[i]));
        json_object_object_add(sample, "channel_transmit_time_ms",
                               json_object_new_int(10));
        json_object_array_add(samples, sample);
    }
    json_object_object_add(survey, "samples", samples);
    return survey;
}

static void five_ghz_width_rejects_blocked_subchannel(void)
{
    const int channels[] = {36, 40, 44, 48};
    const int frequencies[] = {5180, 5200, 5220, 5240};
    const int blocked[] = {0, 0, 0, 3};
    const int widths[] = {20, 80};
    const int busy[] = {100, 120, 140, 160};
    struct json_object *radios = json_object_new_array();
    struct json_object *data;
    struct json_object *result;
    struct json_object *plan;
    struct json_object *row;

    json_object_array_add(radios, new_radio("phy5", "5g", 36, 1,
        new_catalog(channels, frequencies, blocked, 4, widths, 2)));
    data = new_root(radios, survey_for("phy5", channels, frequencies, busy, 4),
                    NULL, 1, 1999);
    result = wifi_channel_ai_plan_json(data, 2000);
    plan = child(result, "plan");
    row = radio_row(plan, "phy5");
    assert(!strcmp(string(plan, "status"), "ready"));
    assert(integer(child(row, "proposed"), "width_mhz") == 20);
    json_object_put(result);
    json_object_put(data);
}

static void expired_neighbor_scan_is_fail_closed(void)
{
    const int channels[] = {1, 6, 11};
    const int frequencies[] = {2412, 2437, 2462};
    const int widths[] = {20};
    const int busy[] = {100, 120, 140};
    struct json_object *radios = json_object_new_array();
    struct json_object *interference = json_object_new_array();
    struct json_object *neighbor = json_object_new_object();
    struct json_object *data;
    struct json_object *result;
    struct json_object *plan;

    json_object_array_add(radios, new_radio("phy0", "2g", 1, 1,
        new_catalog(channels, frequencies, NULL, 3, widths, 1)));
    {
        struct json_object *row = json_object_new_object();

        json_object_object_add(row, "channel", json_object_new_int(1));
        json_object_object_add(row, "rssi_dbm", json_object_new_int(-40));
        json_object_array_add(interference, row);
    }
    data = new_root(radios, survey_for("phy0", channels, frequencies, busy, 3),
                    interference, 2, 100);
    json_object_object_get_ex(child(data, "environment"), "neighbor_scan", &neighbor);
    json_object_object_add(neighbor, "stale", json_object_new_boolean(1));
    result = wifi_channel_ai_plan_json(data, 90000);
    plan = child(result, "plan");
    assert(!strcmp(string(plan, "status"), "scan_recommended"));
    assert(has_blocked_reason(plan, "scan_recommended"));
    json_object_put(result);
    json_object_put(data);
}

static void survey_missing_uses_degraded_bss_only(void)
{
    const int channels[] = {1, 6, 11};
    const int frequencies[] = {2412, 2437, 2462};
    const int widths[] = {20};
    struct json_object *radios = json_object_new_array();
    struct json_object *interference = json_object_new_array();
    struct json_object *row = json_object_new_object();
    struct json_object *data;
    struct json_object *result;
    struct json_object *plan;
    struct json_object *radio;

    json_object_array_add(radios, new_radio("phy0", "2g", 1, 1,
        new_catalog(channels, frequencies, NULL, 3, widths, 1)));
    json_object_object_add(row, "channel", json_object_new_int(1));
    json_object_object_add(row, "rssi_dbm", json_object_new_int(-45));
    json_object_array_add(interference, row);
    data = new_root(radios, NULL, interference, 3, 1999);
    result = wifi_channel_ai_plan_json(data, 2000);
    plan = child(result, "plan");
    radio = radio_row(plan, "phy0");
    assert(!strcmp(string(plan, "status"), "partial_support"));
    assert(!strcmp(string(radio, "confidence"), "degraded_bss_only"));
    assert(strcmp(string(radio, "confidence"), "measured"));
    json_object_put(result);
    json_object_put(data);
}

static void blocked_catalog_reports_channels_insufficient(void)
{
    const int channels[] = {36, 40};
    const int frequencies[] = {5180, 5200};
    const int blocked[] = {1, 2};
    const int widths[] = {20, 40};
    struct json_object *radios = json_object_new_array();
    struct json_object *data;
    struct json_object *result;
    struct json_object *plan;

    json_object_array_add(radios, new_radio("phy5", "5g", 36, 1,
        new_catalog(channels, frequencies, blocked, 2, widths, 2)));
    data = new_root(radios, NULL, NULL, 4, 1999);
    result = wifi_channel_ai_plan_json(data, 2000);
    plan = child(result, "plan");
    assert(!strcmp(string(plan, "status"), "insufficient_evidence"));
    assert(has_blocked_reason(plan, "channels_insufficient"));
    json_object_put(result);
    json_object_put(data);
}

static void high_load_overlap_fails_closed(void)
{
    const int channels[] = {1};
    const int frequencies[] = {2412};
    const int widths[] = {20};
    struct json_object *radios = json_object_new_array();
    struct json_object *interference = json_object_new_array();
    struct json_object *data;
    struct json_object *result;
    struct json_object *plan;
    struct json_object *row;

    row = new_radio("phy-a", "2g", 1, 10,
                    new_catalog(channels, frequencies, NULL, 1, widths, 1));
    json_object_array_add(radios, row);
    row = new_radio("phy-b", "2g", 1, 10,
                    new_catalog(channels, frequencies, NULL, 1, widths, 1));
    json_object_array_add(radios, row);
    row = json_object_new_object();
    json_object_object_add(row, "radio_id", json_object_new_string("phy-a"));
    json_object_object_add(row, "channel", json_object_new_int(1));
    json_object_object_add(row, "rssi_dbm", json_object_new_int(-45));
    json_object_array_add(interference, row);
    row = json_object_new_object();
    json_object_object_add(row, "radio_id", json_object_new_string("phy-b"));
    json_object_object_add(row, "channel", json_object_new_int(1));
    json_object_object_add(row, "rssi_dbm", json_object_new_int(-45));
    json_object_array_add(interference, row);
    data = new_root(radios, NULL, interference, 5, 1999);
    result = wifi_channel_ai_plan_json(data, 2000);
    plan = child(result, "plan");
    assert(!strcmp(string(plan, "status"), "configuration_too_complex"));
    assert(has_blocked_reason(plan, "configuration_too_complex"));
    json_object_put(result);
    json_object_put(data);
}

static void candidate_combination_limit_fails_closed(void)
{
    enum { candidate_count = 101, radio_count = 3 };
    int channels[candidate_count];
    int frequencies[candidate_count];
    int widths[] = {20};
    struct json_object *radios = json_object_new_array();
    struct json_object *interference = json_object_new_array();
    struct json_object *data;
    struct json_object *result;
    struct json_object *plan;
    int i;

    for (i = 0; i < candidate_count; i++) {
        channels[i] = i + 1;
        frequencies[i] = 5000 + i * 20;
    }
    for (i = 0; i < radio_count; i++) {
        char radio_id[16];
        struct json_object *row;

        snprintf(radio_id, sizeof(radio_id), "phy-%d", i);
        json_object_array_add(radios,
            new_radio(radio_id, "5g", 1, 1,
                      new_catalog(channels, frequencies, NULL,
                                  candidate_count, widths, 1)));
        row = json_object_new_object();
        json_object_object_add(row, "radio_id", json_object_new_string(radio_id));
        json_object_object_add(row, "channel", json_object_new_int(1));
        json_object_object_add(row, "rssi_dbm", json_object_new_int(-60));
        json_object_array_add(interference, row);
    }
    data = new_root(radios, NULL, interference, 6, 1999);
    result = wifi_channel_ai_plan_json(data, 2000);
    plan = child(result, "plan");
    assert(!strcmp(string(plan, "status"), "configuration_too_complex"));
    assert(has_blocked_reason(plan, "configuration_too_complex"));
    json_object_put(result);
    json_object_put(data);
}

static void input_change_changes_digest(void)
{
    struct json_object *first_input = parse(sample_data());
    struct json_object *second_input = parse(sample_data());
    struct json_object *first = wifi_channel_ai_plan_json(first_input, 2000);
    struct json_object *second;
    struct json_object *survey_samples;
    struct json_object *sample;
    const char *first_digest;
    const char *second_digest;
    const char *first_evidence_digest;
    const char *second_evidence_digest;

    second = wifi_channel_ai_plan_json(second_input, 3000);
    first_digest = string(child(first, "plan"), "plan_digest");
    second_digest = string(child(second, "plan"), "plan_digest");
    first_evidence_digest = string(child(first, "plan"), "evidence_digest");
    second_evidence_digest = string(child(second, "plan"), "evidence_digest");
    assert(!strcmp(first_digest, second_digest));
    assert(!strcmp(first_evidence_digest, second_evidence_digest));
    assert(strcmp(first_digest, first_evidence_digest));
    survey_samples = child(child(child(second_input, "environment"),
                                  "channel_survey"), "samples");
    sample = json_object_array_get_idx(survey_samples, 1);
    json_object_object_add(sample, "channel_busy_time_ms", json_object_new_int(900));
    json_object_put(second);
    second = wifi_channel_ai_plan_json(second_input, 2000);
    second_digest = string(child(second, "plan"), "plan_digest");
    second_evidence_digest = string(child(second, "plan"), "evidence_digest");
    assert(strcmp(first_digest, second_digest));
    assert(strcmp(first_evidence_digest, second_evidence_digest));
    json_object_put(second);
    json_object_put(first);
    json_object_put(second_input);
    json_object_put(first_input);
}

static const char *sample_data(void)
{
    return "{\"revision\":17,\"environment\":{\"neighbor_scan\":{\"observed_at\":1990,\"samples\":[{}]},\"channel_survey\":{\"samples\":["
           "{\"radio_id\":\"phy0\",\"channel\":1,\"frequency_mhz\":2412,\"noise_dbm\":-95,\"channel_active_time_ms\":1000,\"channel_busy_time_ms\":500,\"channel_transmit_time_ms\":100},"
           "{\"radio_id\":\"phy0\",\"channel\":6,\"frequency_mhz\":2437,\"noise_dbm\":-95,\"channel_active_time_ms\":1000,\"channel_busy_time_ms\":100,\"channel_transmit_time_ms\":20},"
           "{\"radio_id\":\"phy0\",\"channel\":11,\"frequency_mhz\":2462,\"noise_dbm\":-95,\"channel_active_time_ms\":1000,\"channel_busy_time_ms\":900,\"channel_transmit_time_ms\":100}]}} ,"
           "\"interference\":[{\"channel\":1,\"rssi_dbm\":-45,\"width_mhz\":20}],"
           "\"radios\":[{\"id\":\"phy0\",\"ap_id\":\"ap-1\",\"band\":\"2g\",\"channel\":1,\"width_mhz\":20,\"clients\":2,\"retry_rate\":5,\"channel_catalog\":{\"complete\":true,\"observed_at\":1995,\"supported_widths_mhz\":[20],\"channels\":["
           "{\"channel\":1,\"frequency_mhz\":2412,\"disabled\":false,\"no_ir\":false,\"radar_detection\":false},"
           "{\"channel\":6,\"frequency_mhz\":2437,\"disabled\":false,\"no_ir\":false,\"radar_detection\":false},"
           "{\"channel\":11,\"frequency_mhz\":2462,\"disabled\":false,\"no_ir\":false,\"radar_detection\":false}]}}]}";
}

int main(void)
{
    struct json_object *input = parse(sample_data());
    struct json_object *first = wifi_channel_ai_plan_json(input, 2000);
    struct json_object *second = wifi_channel_ai_plan_json(input, 2000);
    struct json_object *plan = child(first, "plan");
    struct json_object *rows = child(plan, "radios");
    struct json_object *row;
    struct json_object *proposed;
    struct json_object *status = wifi_channel_ai_status_json(input, 2000);
    struct json_object *disabled = wifi_channel_ai_apply_disabled_json(
        "cai-17", "transactional_apply_readback_pending");

    assert(json_object_array_length(rows) == 1);
    row = json_object_array_get_idx(rows, 0);
    proposed = child(row, "proposed");

    assert(!strcmp(json_object_get_string(child(plan, "status")), "ready"));
    assert(json_object_get_int(child(proposed, "channel")) == 6);
    assert(!strcmp(json_object_get_string(child(row, "confidence")), "measured"));
    assert(!strcmp(json_object_get_string(child(plan, "plan_digest")),
                  json_object_get_string(child(child(second, "plan"), "plan_digest"))));
    assert(!strcmp(json_object_get_string(child(plan, "evidence_digest")),
                  json_object_get_string(child(child(second, "plan"), "evidence_digest"))));
    assert(strcmp(json_object_get_string(child(plan, "plan_digest")),
                  json_object_get_string(child(plan, "evidence_digest"))));
    assert(json_object_get_boolean(child(status, "available")));
    assert(!json_object_get_boolean(child(disabled, "ok")));
    assert(!strcmp(json_object_get_string(child(disabled, "error")),
                  "capability_disabled"));
    five_ghz_width_rejects_blocked_subchannel();
    expired_neighbor_scan_is_fail_closed();
    survey_missing_uses_degraded_bss_only();
    blocked_catalog_reports_channels_insufficient();
    high_load_overlap_fails_closed();
    candidate_combination_limit_fails_closed();
    input_change_changes_digest();
    apply_manifest_contract();
    json_object_put(disabled);
    json_object_put(status);
    json_object_put(second);
    json_object_put(first);
    json_object_put(input);
    puts("ok: deterministic read-only channel AI planner");
    return 0;
}

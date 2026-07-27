// SPDX-License-Identifier: GPL-2.0-or-later
/* Runtime contract for the Phase W1 read-only wifi transaction validate:
 *   - revision conflict rejection against the desired-config revision;
 *   - evidence-based channel/width/tx-power checks from the reported
 *     channel_catalog (missing/stale/incomplete evidence fail closed);
 *   - secret material never transits validate;
 *   - changeset parsing bounds and ssid target checks;
 *   - schema v10 columns (ac_ssids.secret_present,
 *     ac_ssid_bindings.updated_at).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>
#include <sqlite3.h>

#define AP_ID "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
#define NOW 20000000

extern sqlite3 *g_ac_db;
int ac_db_init(void);
void ac_db_close(void);
struct json_object *ac_db_wifi_transaction_validate_json(
    const char *ap_id, int64_t base_revision, const char *idempotency_key,
    const char *changes_json, int64_t now);

static int exec_sql(const char *sql)
{
    return sqlite3_exec(g_ac_db, sql, NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}

static struct json_object *field(struct json_object *object,
                                 const char *name)
{
    struct json_object *value = NULL;

    return object && json_object_object_get_ex(object, name, &value) ?
           value : NULL;
}

static const char *text(struct json_object *object, const char *name)
{
    struct json_object *value = field(object, name);

    return value ? json_object_get_string(value) : "";
}

static int boolean(struct json_object *object, const char *name)
{
    return json_object_get_boolean(field(object, name));
}

static int errors_contain(struct json_object *target, const char *code)
{
    struct json_object *errors = field(target, "errors");
    size_t i;

    if (!errors)
        return 0;
    for (i = 0; i < json_object_array_length(errors); i++)
        if (!strcmp(json_object_get_string(
                json_object_array_get_idx(errors, i)), code))
            return 1;
    return 0;
}

static struct json_object *validate(int64_t base_revision,
                                    const char *changes)
{
    return ac_db_wifi_transaction_validate_json(
        AP_ID, base_revision, "fixture.validate.1", changes, NOW);
}

static struct json_object *single_target(struct json_object *result)
{
    struct json_object *targets = field(result, "targets");

    return targets && json_object_array_length(targets) == 1 ?
           json_object_array_get_idx(targets, 0) : NULL;
}

static int column_exists(const char *table, const char *column)
{
    sqlite3_stmt *st = NULL;
    char sql[128];
    int found = 0;

    snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table);
    if (sqlite3_prepare_v2(g_ac_db, sql, -1, &st, NULL) != SQLITE_OK)
        return 0;
    while (sqlite3_step(st) == SQLITE_ROW)
        if (!strcmp((const char *)sqlite3_column_text(st, 1), column))
            found = 1;
    sqlite3_finalize(st);
    return found;
}

static int seed_runtime(void)
{
    static const char fresh[] =
        "INSERT INTO ac_radio_runtime(radio_id,ap_id,observed_at,"
        "runtime_json,stale) VALUES('phy1','" AP_ID "',19999990,"
        "'{\"id\":\"phy1\",\"channel_catalog\":{\"complete\":true,"
        "\"observed_at\":19999990,\"supported_widths_mhz\":[20,40],"
        "\"supported_channels\":[1,6,11],"
        "\"tx_power_range_dbm\":{\"min\":20.0,\"max\":23.0}}}',0)";
    static const char widthless[] =
        "INSERT INTO ac_radio_runtime(radio_id,ap_id,observed_at,"
        "runtime_json,stale) VALUES('phy2','" AP_ID "',19999990,"
        "'{\"id\":\"phy2\",\"channel_catalog\":{\"complete\":true,"
        "\"observed_at\":19999990,\"supported_channels\":[36]}}',0)";
    static const char stale[] =
        "INSERT INTO ac_radio_runtime(radio_id,ap_id,observed_at,"
        "runtime_json,stale) VALUES('phy3','" AP_ID "',19000000,"
        "'{\"id\":\"phy3\",\"channel_catalog\":{\"complete\":true,"
        "\"observed_at\":19000000,\"supported_channels\":[36]}}',0)";
    static const char incomplete[] =
        "INSERT INTO ac_radio_runtime(radio_id,ap_id,observed_at,"
        "runtime_json,stale) VALUES('phy4','" AP_ID "',19999990,"
        "'{\"id\":\"phy4\",\"channel_catalog\":{\"complete\":false,"
        "\"reason\":\"iw_phy_failed\"}}',0)";

    return exec_sql(fresh) || exec_sql(widthless) || exec_sql(stale) ||
           exec_sql(incomplete);
}

int main(void)
{
    struct json_object *result;
    struct json_object *target;
    int rc = 1;

    if (ac_db_init() != 0) {
        fprintf(stderr, "db init failed\n");
        return 1;
    }
    if (!column_exists("ac_ssids", "secret_present") ||
        !column_exists("ac_ssid_bindings", "updated_at")) {
        fprintf(stderr, "schema v10 columns missing\n");
        goto done;
    }
    if (seed_runtime() != 0) {
        fprintf(stderr, "seed failed\n");
        goto done;
    }

    /* Revision conflict fails closed before any target work. */
    result = validate(5, "{\"radios\":[{\"radio_id\":\"phy1\","
                         "\"channel\":6}]}");
    if (!boolean(result, "ok") || boolean(result, "valid") ||
        strcmp(text(result, "error"), "revision_conflict") ||
        json_object_get_int64(field(result, "current_revision")) != 0) {
        fprintf(stderr, "revision conflict: %s\n",
                json_object_to_json_string(result));
        goto done;
    }
    json_object_put(result);

    /* Fully evidenced change validates. */
    result = validate(0, "{\"radios\":[{\"radio_id\":\"phy1\","
                         "\"channel\":6,\"width_mhz\":40,"
                         "\"tx_power_dbm\":21}]}");
    target = single_target(result);
    if (!boolean(result, "valid") || !target ||
        !boolean(target, "valid") ||
        json_object_get_int64(field(target, "evidence_observed_at")) !=
            19999990) {
        fprintf(stderr, "valid change: %s\n",
                json_object_to_json_string(result));
        goto done;
    }
    json_object_put(result);

    /* Unsupported channel, width and out-of-range power all reject. */
    result = validate(0, "{\"radios\":[{\"radio_id\":\"phy1\","
                         "\"channel\":100,\"width_mhz\":320,"
                         "\"tx_power_dbm\":30}]}");
    target = single_target(result);
    if (boolean(result, "valid") || !target || boolean(target, "valid") ||
        !errors_contain(target, "channel_not_supported") ||
        !errors_contain(target, "width_not_supported") ||
        !errors_contain(target, "tx_power_out_of_range")) {
        fprintf(stderr, "unsupported change: %s\n",
                json_object_to_json_string(result));
        goto done;
    }
    json_object_put(result);

    /* Width without width evidence fails closed, channel still checked. */
    result = validate(0, "{\"radios\":[{\"radio_id\":\"phy2\","
                         "\"channel\":36,\"width_mhz\":40}]}");
    target = single_target(result);
    if (boolean(result, "valid") || !target ||
        !errors_contain(target, "width_evidence_missing") ||
        errors_contain(target, "channel_not_supported")) {
        fprintf(stderr, "width evidence: %s\n",
                json_object_to_json_string(result));
        goto done;
    }
    json_object_put(result);

    /* Stale, incomplete and missing evidence each fail closed. */
    result = validate(0, "{\"radios\":[{\"radio_id\":\"phy3\","
                         "\"channel\":36}]}");
    target = single_target(result);
    if (!target || !errors_contain(target, "radio_evidence_stale")) {
        fprintf(stderr, "stale evidence: %s\n",
                json_object_to_json_string(result));
        goto done;
    }
    json_object_put(result);
    result = validate(0, "{\"radios\":[{\"radio_id\":\"phy4\","
                         "\"channel\":36}]}");
    target = single_target(result);
    if (!target || !errors_contain(target, "channel_catalog_incomplete")) {
        fprintf(stderr, "incomplete evidence: %s\n",
                json_object_to_json_string(result));
        goto done;
    }
    json_object_put(result);
    result = validate(0, "{\"radios\":[{\"radio_id\":\"phy9\","
                         "\"channel\":36}]}");
    target = single_target(result);
    if (!target || !errors_contain(target, "radio_evidence_missing")) {
        fprintf(stderr, "missing evidence: %s\n",
                json_object_to_json_string(result));
        goto done;
    }
    json_object_put(result);

    /* Secrets never transit validate, at any nesting depth. */
    result = validate(0, "{\"ssids\":[{\"ssid_id\":\"guest\","
                         "\"name\":\"Guest\",\"psk\":\"hunter2\"}]}");
    if (boolean(result, "valid") ||
        strcmp(text(result, "error"), "secret_in_validate")) {
        fprintf(stderr, "secret guard: %s\n",
                json_object_to_json_string(result));
        goto done;
    }
    json_object_put(result);

    /* Parse bounds. */
    result = validate(0, "not json");
    if (strcmp(text(result, "error"), "changes_invalid_json"))
        goto done;
    json_object_put(result);
    result = validate(0, "{}");
    if (strcmp(text(result, "error"), "changes_empty"))
        goto done;
    json_object_put(result);
    result = validate(0, "{\"surprise\":true}");
    if (strcmp(text(result, "error"), "changes_unknown_field"))
        goto done;
    json_object_put(result);

    /* SSID target: valid name+binding passes, oversized name rejects. */
    result = validate(0, "{\"ssids\":[{\"ssid_id\":\"guest\","
                         "\"name\":\"Guest WiFi\",\"enabled\":true,"
                         "\"bindings\":[{\"radio_id\":\"phy1\"}]}]}");
    target = single_target(result);
    if (!boolean(result, "valid") || !target || !boolean(target, "valid")) {
        fprintf(stderr, "ssid valid: %s\n",
                json_object_to_json_string(result));
        goto done;
    }
    json_object_put(result);
    result = validate(0, "{\"ssids\":[{\"ssid_id\":\"guest\","
                         "\"name\":\"123456789012345678901234567890123\","
                         "\"bindings\":[{\"radio_id\":\"phy9\"}]}]}");
    target = single_target(result);
    if (boolean(result, "valid") || !target ||
        !errors_contain(target, "ssid_name_invalid") ||
        !errors_contain(target, "ssid_binding_radio_evidence_missing")) {
        fprintf(stderr, "ssid invalid: %s\n",
                json_object_to_json_string(result));
        goto done;
    }
    json_object_put(result);

    printf("ok\n");
    rc = 0;
done:
    ac_db_close();
    return rc;
}

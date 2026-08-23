// SPDX-License-Identifier: GPL-2.0-or-later
#include "otad_internal.h"

static int readiness_fail(struct otad_boot_readiness *result,
                          const char *dimension, const char *reason,
                          const char *subject)
{
    if (!result)
        return -1;
    result->ready = 0;
    snprintf(result->dimension, sizeof(result->dimension), "%s",
             dimension ? dimension : "health_contract");
    snprintf(result->reason, sizeof(result->reason), "%s",
             reason ? reason : "boot_readiness_malformed");
    snprintf(result->subject, sizeof(result->subject), "%s",
             subject ? subject : "");
    return -1;
}

int otad_boot_services_evaluate(int core_available, int network_available,
                                struct otad_boot_readiness *result)
{
    if (!result)
        return -1;
    memset(result, 0, sizeof(*result));
    if (!core_available)
        return readiness_fail(result, "core_ubus",
                              "core_ubus_unavailable", "dreamingwrt");
    if (!network_available)
        return readiness_fail(result, "network_ubus",
                              "network_ubus_unavailable", "network.interface");
    result->ready = 1;
    snprintf(result->dimension, sizeof(result->dimension), "services");
    snprintf(result->reason, sizeof(result->reason), "required_ubus_ready");
    return 0;
}

static int object_bool(struct json_object *o, const char *key, int *value)
{
    struct json_object *v = NULL;

    if (!o || !value || !json_object_object_get_ex(o, key, &v) || !v ||
        !json_object_is_type(v, json_type_boolean))
        return -1;
    *value = json_object_get_boolean(v) ? 1 : 0;
    return 0;
}

static int object_int(struct json_object *o, const char *key, int *value)
{
    struct json_object *v = NULL;

    if (!o || !value || !json_object_object_get_ex(o, key, &v) || !v ||
        !json_object_is_type(v, json_type_int))
        return -1;
    *value = json_object_get_int(v);
    return 0;
}

static int object_string(struct json_object *o, const char *key,
                         const char **value)
{
    struct json_object *v = NULL;

    if (!o || !value || !json_object_object_get_ex(o, key, &v) || !v ||
        !json_object_is_type(v, json_type_string) || !json_object_get_string(v))
        return -1;
    *value = json_object_get_string(v);
    return 0;
}

static int maintenance_reason_allowed(const char *level, const char *scope,
                                      const char *reason)
{
    if (!level || (strcmp(level, "warning") && strcmp(level, "critical")) ||
        !scope || !scope[0] || !reason)
        return 0;
    return !strcmp(reason, "table_rows_warning") ||
           !strcmp(reason, "table_rows_critical") ||
           !strcmp(reason, "db_size_warning") ||
           !strcmp(reason, "db_size_critical") ||
           !strcmp(reason, "filesystem_usage_warning") ||
           !strcmp(reason, "filesystem_usage_critical") ||
           !strcmp(reason, "filesystem_free_warning") ||
           !strcmp(reason, "filesystem_free_critical") ||
           !strcmp(reason, "tmp_file_size_warning") ||
           !strcmp(reason, "tmp_file_size_critical");
}

int otad_boot_readiness_requires_rollback(
    const struct otad_boot_readiness *result)
{
    const char *reason;

    if (!result || result->ready)
        return 0;
    reason = result->reason;
    if (!strcmp(reason, "core_ubus_unavailable") ||
        !strcmp(reason, "network_ubus_unavailable") ||
        !strcmp(reason, "dreamingwrt_init_unavailable") ||
        !strcmp(reason, "boot_readiness_output_invalid") ||
        !strcmp(reason, "supervisor_status_missing") ||
        !strcmp(reason, "supervisor_not_running") ||
        !strcmp(reason, "jmx_module_status_missing") ||
        !strcmp(reason, "jmx_module_not_loaded") ||
        !strcmp(reason, "critical_component_status_invalid") ||
        !strcmp(reason, "critical_components_failed") ||
        !strcmp(reason, "persistent_store_status_missing") ||
        !strcmp(reason, "persistent_store_not_writable") ||
        !strcmp(reason, "required_database_status_missing") ||
        !strcmp(reason, "core_storage_health_unavailable") ||
        !strcmp(reason, "required_db_missing") ||
        !strcmp(reason, "sqlite_open_failed") ||
        !strcmp(reason, "database_read_only") ||
        !strcmp(reason, "database_integrity_failed") ||
        !strcmp(reason, "required_table_missing") ||
        !strcmp(reason, "required_database_set_incomplete") ||
        strstr(reason, "_database_integrity_failed"))
        return 1;
    return 0;
}

static const char *required_anchor(const char *database)
{
    if (!strcmp(database, "config")) return "web_users";
    if (!strcmp(database, "apid")) return "web_sessions";
    if (!strcmp(database, "core")) return "clients";
    if (!strcmp(database, "logd")) return "log_events";
    if (!strcmp(database, "notifyd")) return "notify_outbox";
    return NULL;
}

static unsigned int required_database_bit(const char *database)
{
    if (!strcmp(database, "config")) return 1U << 0;
    if (!strcmp(database, "apid")) return 1U << 1;
    if (!strcmp(database, "core")) return 1U << 2;
    if (!strcmp(database, "logd")) return 1U << 3;
    if (!strcmp(database, "notifyd")) return 1U << 4;
    return 0;
}

static int validate_required_databases(struct json_object *storage,
                                       struct otad_boot_readiness *result)
{
    struct json_object *databases = NULL;
    unsigned int required_seen = 0;
    size_t i;

    if (!json_object_object_get_ex(storage, "databases", &databases) ||
        !databases || !json_object_is_type(databases, json_type_array))
        return readiness_fail(result, "storage_contract",
                              "databases_missing_or_invalid", "storage");
    for (i = 0; i < json_object_array_length(databases); i++) {
        struct json_object *db = json_object_array_get_idx(databases, i);
        struct json_object *v = NULL;
        struct json_object *tables = NULL;
        const char *name = NULL;
        const char *anchor;
        unsigned int required_bit;
        int required;
        int present;
        int anchor_present = 0;
        size_t j;

        if (!db || !json_object_is_type(db, json_type_object) ||
            object_string(db, "name", &name) != 0 || !name[0] ||
            object_bool(db, "required", &required) != 0 ||
            object_bool(db, "present", &present) != 0)
            return readiness_fail(result, "storage_contract",
                                  "database_entry_malformed", "storage");
        if (required && !present)
            return readiness_fail(result, "storage_database",
                                  "required_db_missing", name);
        if (json_object_object_get_ex(db, "open_error", &v) && v)
            return readiness_fail(result, "storage_database",
                                  "sqlite_open_failed", name);
        if (json_object_object_get_ex(db, "read_only", &v) && v &&
            json_object_is_type(v, json_type_boolean) && json_object_get_boolean(v))
            return readiness_fail(result, "storage_database",
                                  "database_read_only", name);
        if (json_object_object_get_ex(db, "writable", &v) && v &&
            json_object_is_type(v, json_type_boolean) && !json_object_get_boolean(v))
            return readiness_fail(result, "storage_database",
                                  "database_read_only", name);
        if (json_object_object_get_ex(db, "integrity_ok", &v) && v &&
            json_object_is_type(v, json_type_boolean) && !json_object_get_boolean(v))
            return readiness_fail(result, "storage_database",
                                  "database_integrity_failed", name);
        if (!required)
            continue;
        anchor = required_anchor(name);
        required_bit = required_database_bit(name);
        if (!anchor || !required_bit || (required_seen & required_bit) ||
            !json_object_object_get_ex(db, "tables", &tables) ||
            !tables || !json_object_is_type(tables, json_type_array))
            return readiness_fail(result, "storage_schema",
                                  "required_schema_unavailable", name);
        required_seen |= required_bit;
        for (j = 0; j < json_object_array_length(tables); j++) {
            struct json_object *table = json_object_array_get_idx(tables, j);
            const char *table_name = NULL;
            int table_present;

            if (!table || !json_object_is_type(table, json_type_object) ||
                object_string(table, "name", &table_name) != 0 ||
                object_bool(table, "present", &table_present) != 0)
                return readiness_fail(result, "storage_contract",
                                      "table_entry_malformed", name);
            if (!strcmp(table_name, anchor))
                anchor_present = table_present;
        }
        if (!anchor_present) {
            char subject[160];

            snprintf(subject, sizeof(subject), "%s.%s", name, anchor);
            return readiness_fail(result, "storage_schema",
                                  "required_table_missing", subject);
        }
    }
    if (required_seen != ((1U << 5) - 1))
        return readiness_fail(result, "storage_schema",
                              "required_database_set_incomplete", "storage");
    return 0;
}

int otad_boot_readiness_evaluate(struct json_object *health,
                                 struct otad_boot_readiness *result)
{
    struct json_object *storage = NULL;
    struct json_object *reasons = NULL;
    const char *storage_source = NULL;
    const char *storage_health = NULL;
    int supervisor_running;
    int module_loaded;
    int critical_failed;
    int persistent_store_writable;
    int required_databases_ready;
    size_t i;

    if (!result)
        return -1;
    memset(result, 0, sizeof(*result));
    if (!health || !json_object_is_type(health, json_type_object))
        return readiness_fail(result, "health_contract",
                              "boot_readiness_malformed", "dreamingwrt-init");
    if (object_bool(health, "supervisor_running", &supervisor_running) != 0)
        return readiness_fail(result, "supervisor",
                              "supervisor_status_missing", "dreamingwrt-init");
    if (!supervisor_running)
        return readiness_fail(result, "supervisor",
                              "supervisor_not_running", "dreamingwrt-init");
    if (object_bool(health, "jmx_module_loaded", &module_loaded) != 0)
        return readiness_fail(result, "kernel_runtime",
                              "jmx_module_status_missing", "jmx");
    if (!module_loaded)
        return readiness_fail(result, "kernel_runtime",
                              "jmx_module_not_loaded", "jmx");
    if (object_int(health, "critical_components_failed", &critical_failed) != 0 ||
        critical_failed < 0)
        return readiness_fail(result, "runtime_components",
                              "critical_component_status_invalid", "supervisor");
    if (critical_failed != 0)
        return readiness_fail(result, "runtime_components",
                              "critical_components_failed", "supervisor");
    if (object_bool(health, "persistent_store_writable",
                    &persistent_store_writable) != 0)
        return readiness_fail(result, "storage_runtime",
                              "persistent_store_status_missing", "/etc/dreamingwrt");
    if (!persistent_store_writable)
        return readiness_fail(result, "storage_runtime",
                              "persistent_store_not_writable", "/etc/dreamingwrt");
    if (object_bool(health, "required_databases_ready",
                    &required_databases_ready) != 0)
        return readiness_fail(result, "storage_database",
                              "required_database_status_missing", "storage");
    if (!required_databases_ready)
        return readiness_fail(result, "storage_database",
                              otad_json_str(health, "required_databases_reason",
                                            "required_database_unhealthy"),
                              "storage");
    if (object_string(health, "storage_source", &storage_source) != 0 ||
        strcmp(storage_source, "core"))
        return readiness_fail(result, "storage_contract",
                              "core_storage_health_unavailable", "dreamingwrt");
    if (!json_object_object_get_ex(health, "storage", &storage) || !storage ||
        !json_object_is_type(storage, json_type_object) ||
        object_string(storage, "health", &storage_health) != 0 ||
        (strcmp(storage_health, "ok") && strcmp(storage_health, "warning") &&
         strcmp(storage_health, "critical")))
        return readiness_fail(result, "storage_contract",
                              "storage_health_malformed", "storage");
    if (validate_required_databases(storage, result) != 0)
        return -1;
    if (!json_object_object_get_ex(storage, "reasons", &reasons) || !reasons ||
        !json_object_is_type(reasons, json_type_array))
        return readiness_fail(result, "storage_contract",
                              "storage_reasons_missing_or_invalid", "storage");
    if (!strcmp(storage_health, "ok") && json_object_array_length(reasons) != 0)
        return readiness_fail(result, "storage_contract",
                              "storage_health_reason_mismatch", "storage");
    if (strcmp(storage_health, "ok") && json_object_array_length(reasons) == 0)
        return readiness_fail(result, "storage_contract",
                              "storage_degradation_unclassified", "storage");
    for (i = 0; i < json_object_array_length(reasons); i++) {
        struct json_object *reason_obj = json_object_array_get_idx(reasons, i);
        const char *level = NULL;
        const char *scope = NULL;
        const char *name = NULL;
        const char *reason = NULL;

        if (!reason_obj || !json_object_is_type(reason_obj, json_type_object) ||
            object_string(reason_obj, "level", &level) != 0 ||
            object_string(reason_obj, "scope", &scope) != 0 ||
            object_string(reason_obj, "name", &name) != 0 ||
            object_string(reason_obj, "reason", &reason) != 0 || !name[0])
            return readiness_fail(result, "storage_contract",
                                  "storage_reason_malformed", "storage");
        if (!maintenance_reason_allowed(level, scope, reason))
            return readiness_fail(result, "storage", reason, name);
        result->degraded = 1;
    }
    result->ready = 1;
    snprintf(result->dimension, sizeof(result->dimension), "%s",
             result->degraded ? "storage_maintenance" : "ready");
    snprintf(result->reason, sizeof(result->reason), "%s",
             result->degraded ? "retention_watermark_non_blocking" : "boot_ready");
    return 0;
}

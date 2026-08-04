// SPDX-License-Identifier: GPL-2.0-or-later
#include "otad_internal.h"

#define WORKER_STATUS_VERSION "1.0"

static void add_release_json(struct json_object *resp)
{
    struct json_object *release = NULL;
    const char *selected_path = NULL;
    char error[OTAD_MAX_TEXT] = "";
    int rc;

    rc = otad_release_metadata_read(&release, &selected_path,
                                    error, sizeof(error));
    if (rc != 0) {
        release = json_object_new_object();
        json_object_object_add(release, "available", json_object_new_boolean(0));
        otad_json_add_string(release, "error", error);
        otad_json_add_string(release, "preferred_path", OTAD_RELEASE_NEW_PATH);
        otad_json_add_string(release, "fallback_path", OTAD_RELEASE_PATH);
    } else {
        json_object_object_add(release, "available", json_object_new_boolean(1));
        otad_json_add_string(release, "path", selected_path);
    }
    json_object_object_add(resp, "release", release);
}

static void add_mount_status(struct json_object *resp)
{
    struct json_object *mounts = json_object_new_object();
    struct statvfs vfs;

    json_object_object_add(mounts, "etc_dreamingwrt_exists",
                           json_object_new_boolean(otad_dir_exists("/etc/dreamingwrt")));
    json_object_object_add(mounts, "data_exists",
                           json_object_new_boolean(otad_dir_exists("/data")));
    if (statvfs("/etc/dreamingwrt", &vfs) == 0) {
        json_object_object_add(mounts, "etc_dreamingwrt_blocks",
                               json_object_new_int64((int64_t)vfs.f_blocks));
        json_object_object_add(mounts, "etc_dreamingwrt_bavail",
                               json_object_new_int64((int64_t)vfs.f_bavail));
    }
    json_object_object_add(resp, "mounts", mounts);
}

static void add_slot_rows(struct json_object *resp)
{
    struct json_object *slots = json_object_new_array();
    sqlite3_stmt *st;

    st = otad_config_prepare(
        "SELECT slot_name,version,build_id,state,boot_attempts,last_boot_at,last_good_at,last_error,rootfs_sha256 "
        "FROM ota_slots ORDER BY slot_name");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();

            otad_json_add_string(o, "slot_name", (const char *)sqlite3_column_text(st, 0));
            otad_json_add_string(o, "version", (const char *)sqlite3_column_text(st, 1));
            otad_json_add_string(o, "build_id", (const char *)sqlite3_column_text(st, 2));
            otad_json_add_string(o, "state", (const char *)sqlite3_column_text(st, 3));
            json_object_object_add(o, "boot_attempts", json_object_new_int(sqlite3_column_int(st, 4)));
            json_object_object_add(o, "last_boot_at", json_object_new_int64(sqlite3_column_int64(st, 5)));
            json_object_object_add(o, "last_good_at", json_object_new_int64(sqlite3_column_int64(st, 6)));
            otad_json_add_string(o, "last_error", (const char *)sqlite3_column_text(st, 7));
            otad_json_add_string(o, "rootfs_sha256", (const char *)sqlite3_column_text(st, 8));
            json_object_array_add(slots, o);
        }
        sqlite3_finalize(st);
    }
    json_object_object_add(resp, "slots", slots);
}

static void add_space_gate_status(struct json_object *resp)
{
    char value[2048];
    struct json_object *gate = NULL;

    otad_state_get("space_gate", value, sizeof(value), "");
    if (value[0])
        gate = json_tokener_parse(value);
    if (!gate || !json_object_is_type(gate, json_type_object)) {
        if (gate)
            json_object_put(gate);
        gate = json_object_new_object();
        json_object_object_add(gate, "checked", json_object_new_boolean(0));
        json_object_object_add(gate, "gate_open", json_object_new_boolean(0));
        otad_json_add_string(gate, "reason", "not_checked");
        json_object_object_add(gate, "retryable", json_object_new_boolean(1));
    }
    json_object_object_add(resp, "space_gate", gate);
}

static int otad_status_query_config(int *schema_version, char *last_error,
                                    size_t last_error_len, int64_t *updated_at,
                                    struct json_object *datasets)
{
    sqlite3_stmt *st;
    int rc;
    int ok = 1;

    st = otad_config_prepare(
        "SELECT CAST(value AS INTEGER),updated_at FROM ota_state WHERE key='schema_version'");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            *schema_version = sqlite3_column_int(st, 0);
            *updated_at = sqlite3_column_int64(st, 1);
        } else {
            ok = 0;
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
    }
    st = otad_config_prepare(
        "SELECT error,updated_at FROM ("
        "SELECT last_error AS error,updated_at FROM ota_slots WHERE last_error<>'' "
        "UNION ALL SELECT error,updated_at FROM ota_jobs WHERE error<>'') "
        "ORDER BY updated_at DESC LIMIT 1");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            snprintf(last_error, last_error_len, "%s",
                     sqlite3_column_text(st, 0) ? (const char *)sqlite3_column_text(st, 0) : "");
            if (sqlite3_column_int64(st, 1) > *updated_at)
                *updated_at = sqlite3_column_int64(st, 1);
        } else if (rc != SQLITE_DONE) {
            ok = 0;
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
    }
    st = otad_config_prepare(
        "SELECT (SELECT COUNT(*) FROM ota_slots),(SELECT COUNT(*) FROM ota_jobs)");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            json_object_object_add(datasets, "slots", json_object_new_int(sqlite3_column_int(st, 0)));
            json_object_object_add(datasets, "jobs", json_object_new_int(sqlite3_column_int(st, 1)));
        } else {
            ok = 0;
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
    }
    return ok;
}

static int otad_status_query_inventory(char *last_error, size_t last_error_len,
                                       int64_t *updated_at, struct json_object *datasets)
{
    sqlite3_stmt *st;
    int rc;
    int ok = 1;

    st = otad_inventory_prepare(
        "SELECT error_code,error_message,updated_at FROM ota_operations "
        "WHERE error_code<>'' OR error_message<>'' ORDER BY updated_at DESC LIMIT 1");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW && sqlite3_column_int64(st, 2) >= *updated_at) {
            const char *code = sqlite3_column_text(st, 0) ?
                               (const char *)sqlite3_column_text(st, 0) : "";
            const char *message = sqlite3_column_text(st, 1) ?
                                  (const char *)sqlite3_column_text(st, 1) : "";

            snprintf(last_error, last_error_len, "%s%s%s", code,
                     code[0] && message[0] ? ": " : "", message);
            *updated_at = sqlite3_column_int64(st, 2);
        } else if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
            ok = 0;
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
    }
    st = otad_inventory_prepare(
        "SELECT (SELECT COUNT(*) FROM ota_operations),"
        "(SELECT COUNT(*) FROM inventory_files),"
        "(SELECT COUNT(*) FROM inventory_unknowns),"
        "(SELECT COUNT(*) FROM inventory_snapshots)");
    if (st) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            json_object_object_add(datasets, "operations", json_object_new_int(sqlite3_column_int(st, 0)));
            json_object_object_add(datasets, "inventory_files", json_object_new_int(sqlite3_column_int(st, 1)));
            json_object_object_add(datasets, "inventory_unknowns", json_object_new_int(sqlite3_column_int(st, 2)));
            json_object_object_add(datasets, "inventory_snapshots", json_object_new_int(sqlite3_column_int(st, 3)));
        } else {
            ok = 0;
        }
        sqlite3_finalize(st);
    } else {
        ok = 0;
    }
    return ok;
}

struct json_object *otad_status_json(void)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *slot_status = otad_slot_status_json();
    struct json_object *dependencies = json_object_new_object();
    struct json_object *datasets = json_object_new_object();
    char state[64];
    char scan_at[64];
    char state_error[OTAD_MAX_TEXT] = "";
    char last_error[OTAD_MAX_TEXT] = "";
    int schema_version = 0;
    int64_t updated_at = 0;
    int ok;
    int degraded;
    int topology_supported =
        otad_json_bool(slot_status, "topology_readonly_verified", 0);
    int boot_state_ready = topology_supported &&
        otad_json_bool(slot_status, "boot_state_readonly_verified", 0);
    int inactive_bootable = boot_state_ready &&
        otad_json_bool(slot_status, "inactive_slot_bootable_verified", 0);
    int rollback_ready = inactive_bootable;

    ok = otad_state_get("state", state, sizeof(state), "idle") == 0;
    if (otad_state_get("last_inventory_scan_at", scan_at, sizeof(scan_at), "0") != 0)
        ok = 0;
    if (otad_state_get("last_error", state_error, sizeof(state_error), "") != 0)
        ok = 0;
    if (!otad_status_query_config(&schema_version, last_error, sizeof(last_error),
                                  &updated_at, datasets))
        ok = 0;
    if (!otad_status_query_inventory(last_error, sizeof(last_error), &updated_at, datasets))
        ok = 0;
    if (state_error[0])
        snprintf(last_error, sizeof(last_error), "%s", state_error);
    if (!ok && !last_error[0])
        snprintf(last_error, sizeof(last_error), "%s", "status_query_failed");
    degraded = !ok || last_error[0] || strstr(state, "failed") || strstr(state, "unhealthy");
    json_object_object_add(resp, "ok", json_object_new_boolean(ok));
    json_object_object_add(resp, "service", json_object_new_string("dreamingwrt-otad"));
    json_object_object_add(resp, "version", json_object_new_string(WORKER_STATUS_VERSION));
    json_object_object_add(resp, "schema_version", json_object_new_int(schema_version));
    json_object_object_add(resp, "schema_source",
                           json_object_new_string("config.db:ota_state.schema_version"));
    json_object_object_add(resp, "migration_state", json_object_new_string(
        schema_version == OTAD_STATE_SCHEMA_VERSION ? "current" :
        (schema_version > 0 ? "version_mismatch" : "unknown")));
    json_object_object_add(resp, "stage", json_object_new_string("ab-slot-guarded"));
    json_object_object_add(resp, "state", json_object_new_string(state));
    json_object_object_add(resp, "degraded", json_object_new_boolean(degraded));
    json_object_object_add(resp, "last_error", json_object_new_string(last_error));
    json_object_object_add(resp, "updated_at", json_object_new_int64(updated_at));
    json_object_object_add(resp, "full_firmware_validate_enabled", json_object_new_boolean(1));
    {
        struct json_object *trust = otad_release_trust_status();
        int trust_ready = otad_json_bool(trust, "ready", 0);
        /*
         * Writing a slot needs three independent things to hold, so all three
         * are read rather than assumed: a usable trust policy with an active
         * signing key, an A/B layout proven by read-only probing, and a
         * bootloader state that can be steered and rolled back.
         *
         * These were hard zeros before, with a reason that blamed the trust
         * policy no matter what. That sent operators to provision keys against
         * a gate that would not have opened either way, and it hid which
         * precondition was actually missing.
         */
        int slot_write_ready = trust_ready && topology_supported && rollback_ready;
        const char *gate_reason =
            !trust_ready ? otad_json_str(trust, "reason", "release_trust_unavailable") :
            (!topology_supported ? "ab_topology_readonly_evidence_incomplete" :
             (!rollback_ready ? "bootloader_slot_state_not_rollback_capable" : ""));

        json_object_object_add(resp, "apply_enabled",
                               json_object_new_boolean(slot_write_ready));
        json_object_object_add(resp, "full_firmware_apply_enabled",
                               json_object_new_boolean(slot_write_ready));
        /* Stays closed: the hot update writer is compiled out, see below. */
        json_object_object_add(resp, "hot_update_apply_enabled",
                               json_object_new_boolean(0));
        json_object_object_add(resp, "slot_write_enabled",
                               json_object_new_boolean(slot_write_ready));
        json_object_object_add(resp, "firmware_authenticity_verifier_ready",
                               json_object_new_boolean(trust_ready));
        json_object_object_add(resp, "firmware_target_matcher_ready",
                               json_object_new_boolean(1));
        json_object_object_add(resp, "firmware_release_trust", trust);
        /*
         * The full firmware write path is implemented: signature verification,
         * inactive-slot write with SHA256 readback, fsck, one-shot pending boot
         * and automatic fallback all exist in otad_firmware.c. What used to be
         * missing was permission to reach it, not the code.
         *
         * Hot update is a different story and must not be reported as the same:
         * its writer is still compiled out, so it stays unavailable no matter
         * how the trust policy is configured.
         */
        json_object_object_add(resp, "full_firmware_apply_implemented",
                               json_object_new_boolean(1));
        json_object_object_add(resp, "hot_update_apply_implemented",
                               json_object_new_boolean(0));
        otad_json_add_string(resp, "full_firmware_apply_reason", gate_reason);
        otad_json_add_string(resp, "hot_update_apply_reason",
                             "hot_update_writer_disabled_in_build");
        if (!trust_ready)
            otad_json_add_string(resp, "release_trust_setup_reason",
                                 otad_json_str(trust, "reason",
                                               "trust_policy_unavailable"));
    }
    json_object_object_add(resp, "rollback_enabled",
                           json_object_new_boolean(rollback_ready));
    otad_json_add_string(resp, "rollback_reason", rollback_ready ? "" :
        (!topology_supported ? "ab_topology_readonly_evidence_incomplete" :
         (!boot_state_ready ?
          otad_json_str(slot_status, "boot_state_reason",
                        "bootloader_slot_state_not_readonly_verified") :
          "inactive_slot_not_bootable")));
    json_object_object_add(resp, "slot_status", slot_status);
    json_object_object_add(resp, "firmware_info_required", json_object_new_boolean(1));
    json_object_object_add(resp, "firmware_manifest_allowed", json_object_new_boolean(0));
    {
        struct json_object *types = json_object_new_array();
        json_object_array_add(types, json_object_new_string("firmware"));
        json_object_array_add(types, json_object_new_string("database"));
        json_object_array_add(types, json_object_new_string("component"));
        json_object_object_add(resp, "firmware_types", types);
    }
    json_object_object_add(resp, "hot_update_manifest_required", json_object_new_boolean(1));
    json_object_object_add(resp, "hot_update_slot_write", json_object_new_boolean(0));
    json_object_object_add(resp, "hot_update_deletions_supported", json_object_new_boolean(1));
    json_object_object_add(resp, "md5_required", json_object_new_boolean(1));
    json_object_object_add(resp, "sha256_required", json_object_new_boolean(1));
    json_object_object_add(resp, "writeback_sha256_required", json_object_new_boolean(1));
    json_object_object_add(resp, "signature_verified", json_object_new_boolean(0));
    json_object_object_add(resp, "signature_required", json_object_new_boolean(1));
    json_object_object_add(resp, "config_db", json_object_new_string(OTAD_CONFIG_DB_PATH));
    json_object_object_add(resp, "inventory_db", json_object_new_string(OTAD_INVENTORY_DB_PATH));
    json_object_object_add(dependencies, "config_db", json_object_new_boolean(g_otad_config_db != NULL));
    json_object_object_add(dependencies, "inventory_db", json_object_new_boolean(g_otad_inventory_db != NULL));
    json_object_object_add(dependencies, "ab_slots", json_object_new_boolean(
        topology_supported));
    json_object_object_add(resp, "dependencies", dependencies);
    json_object_object_add(datasets, "inventory_schema_version",
                           json_object_new_int(OTAD_INVENTORY_SCHEMA_VERSION));
    json_object_object_add(resp, "datasets", datasets);
    json_object_object_add(resp, "last_inventory_scan_at", json_object_new_int64(atoll(scan_at)));
    add_release_json(resp);
    add_mount_status(resp);
    add_slot_rows(resp);
    add_space_gate_status(resp);
    json_object_object_add(resp, "ts", json_object_new_int64(otad_now_s()));
    return resp;
}

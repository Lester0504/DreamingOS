// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_CONFIG_MIGRATE_H
#define DREAMINGWRT_CONFIG_MIGRATE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Legacy config.db backups predate the DWRT application_id/user_version
 * contract: they carry application_id=0, user_version=0 and the 86 business
 * tables that existed before system/appearance/work-mode settings were split
 * out. The restore path may not overwrite the current database with such a
 * library, so migration runs on a private copy and only publishes a result
 * that already satisfies the current schema contract.
 */

#ifndef DWRT_CONFIG_MIGRATE_DIR
#define DWRT_CONFIG_MIGRATE_DIR "/etc/dreamingwrt/restore-staging/migrate"
#endif
#ifndef DWRT_CONFIG_MIGRATE_DB
#define DWRT_CONFIG_MIGRATE_DB DWRT_CONFIG_MIGRATE_DIR "/config.db"
#endif
#ifndef DWRT_CONFIG_MIGRATE_REPORT
#define DWRT_CONFIG_MIGRATE_REPORT DWRT_CONFIG_MIGRATE_DIR "/report.json"
#endif

#define DWRT_CONFIG_MIGRATE_REPORT_FORMAT "dreamingwrt-config-migration-v1"

/* Legacy libraries report themselves as version 0 through PRAGMA user_version. */
#define DWRT_CONFIG_LEGACY_VERSION 0

#define DWRT_CONFIG_MIGRATE_MAX_TABLES 160

enum dwrt_migrate_table_action {
    DWRT_MIGRATE_TABLE_MIGRATED = 0, /* rows carried over verbatim */
    DWRT_MIGRATE_TABLE_PRESERVED,    /* table kept, no rows to carry */
    DWRT_MIGRATE_TABLE_CREATED,      /* absent in source, created by schema */
    DWRT_MIGRATE_TABLE_DROPPED,      /* intentionally not carried over */
};

struct dwrt_migrate_table_report {
    char name[64];
    char reason[96];
    enum dwrt_migrate_table_action action;
    int64_t source_rows;
    int64_t migrated_rows;
};

struct dwrt_migrate_report {
    char error[192];
    char source_sha256[65];
    int from_version;
    int to_version;
    int steps_applied;
    int table_count;
    int64_t started_at;
    int64_t finished_at;
    int secret_references_preserved;
    int media_metadata_preserved;
    struct dwrt_migrate_table_report tables[DWRT_CONFIG_MIGRATE_MAX_TABLES];
};

/*
 * Returns 1 when the file is a readable SQLite config library whose version is
 * older than the current schema and therefore a migration candidate, 0 when it
 * is not a candidate, and -1 when the file cannot be inspected at all.
 */
int dwrt_config_migrate_needed(const char *path, int *from_version);

/*
 * Migrates `source` through the explicit version chain into `dest`.
 * `source` is never modified. On failure `dest` is removed so no partially
 * migrated library can be published, and the reason is recorded in `report`.
 */
int dwrt_config_migrate_run(const char *source, const char *dest,
                            struct dwrt_migrate_report *report);

/* Serializes the per-table migration/preservation report as JSON. */
int dwrt_config_migrate_write_report(const char *path,
                                     const struct dwrt_migrate_report *report);

const char *dwrt_config_migrate_action_name(enum dwrt_migrate_table_action action);

#endif

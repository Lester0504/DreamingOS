// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_CONFIG_SNAPSHOT_H
#define DREAMINGWRT_CONFIG_SNAPSHOT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

/*
 * OTA config snapshot contract.
 *
 * Before an OTA operation writes a new system slot, otad creates an
 * operation-scoped snapshot of the DreamingWrt configuration.  The snapshot
 * survives the upgrade and is used by the first-boot restore path to
 * materialize the configuration into the new system.
 *
 * The snapshot is stored in a location that is NOT destroyed by the upgrade:
 *   - BPI-R4 (eMMC): /data/persist/dreamingwrt-ota-snapshots/<operation_id>/
 *   - W1700K (NAND UBI): sysupgrade.tgz (via /lib/upgrade/keep.d/dreamingwrt)
 *
 * The snapshot format is versioned and includes:
 *   - A manifest with file list, sizes, and sha256 digests
 *   - SQLite backups of all databases (using online backup API)
 *   - Copies of key/certificate files
 *   - UCI config files
 */

#ifndef DWRT_CONFIG_SNAPSHOT_DIR
#define DWRT_CONFIG_SNAPSHOT_DIR "/data/persist/dreamingwrt-ota-snapshots"
#endif

#ifndef DWRT_CONFIG_SNAPSHOT_STAGING
#define DWRT_CONFIG_SNAPSHOT_STAGING "/tmp/dreamingwrt-ota-snapshot"
#endif

/* Cross-process state written by the storage supervisor.  The OTA snapshot
 * producer runs in dreamingwrt-otad, not inside core, so an in-process flag
 * cannot close the write gate during a storage migration. */
#ifndef DWRT_CONFIG_SNAPSHOT_STORAGE_STATE
#define DWRT_CONFIG_SNAPSHOT_STORAGE_STATE "/etc/dreamingwrt/storage/snapshots-runtime.state"
#endif

#define DWRT_CONFIG_SNAPSHOT_FORMAT "dreamingwrt-ota-config-snapshot-v1"
#define DWRT_CONFIG_SNAPSHOT_SCHEMA_VERSION 1

#define DWRT_CONFIG_SNAPSHOT_MAX_FILES 256
#define DWRT_CONFIG_SNAPSHOT_MAX_DBS 16

#define DWRT_SNAPSHOT_OK                    0
#define DWRT_SNAPSHOT_ERR_INVALID_ARGS     -1
#define DWRT_SNAPSHOT_ERR_MKDIR_FAILED     -2
#define DWRT_SNAPSHOT_ERR_BACKUP_FAILED    -3
#define DWRT_SNAPSHOT_ERR_MANIFEST_FAILED  -4
#define DWRT_SNAPSHOT_ERR_HASH_MISMATCH    -5
#define DWRT_SNAPSHOT_ERR_INTEGRITY_FAILED -6
#define DWRT_SNAPSHOT_ERR_RESTORE_FAILED   -7
#define DWRT_SNAPSHOT_ERR_VERIFY_FAILED    -8

struct dwrt_config_snapshot_file {
    char path[512];
    uint64_t size;
    char sha256[65];
    mode_t mode;
};

struct dwrt_config_snapshot_db {
    char path[512];
    char integrity[32];
    int schema_version;
};

struct dwrt_config_snapshot_manifest {
    char format[64];
    char snapshot_id[96];
    char board[64];
    char source_release[128];
    int schema_version;
    int64_t created_at;
    char scope[64];

    int file_count;
    struct dwrt_config_snapshot_file files[DWRT_CONFIG_SNAPSHOT_MAX_FILES];

    int db_count;
    struct dwrt_config_snapshot_db dbs[DWRT_CONFIG_SNAPSHOT_MAX_DBS];
};

int dwrt_config_snapshot_create(const char *operation_id,
                                const char *board,
                                const char *source_release,
                                char *error, size_t error_len);

int dwrt_config_snapshot_validate(const char *operation_id,
                                  const char *expected_board,
                                  char *error, size_t error_len);

int dwrt_config_snapshot_restore(const char *operation_id,
                                 char *error, size_t error_len);

int dwrt_config_snapshot_exists(const char *operation_id);

int dwrt_config_snapshot_path(const char *operation_id,
                              char *out, size_t out_len);

/* Read the supervisor-owned cross-process snapshot storage state. */
int dwrt_config_snapshot_storage_state(char *active_path, size_t path_len,
                                       int *frozen);

#endif

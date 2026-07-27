// SPDX-License-Identifier: GPL-2.0-or-later
/* Promote immutable firmware databases into the persistent runtime store. */
#include "system_db_sync.h"
#include "jmx_path_provider.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef DWRT_SYSTEM_DB_LEGACY_DIR
#ifdef DWRT_SYSTEM_DB_DIR
#define DWRT_SYSTEM_DB_LEGACY_DIR DWRT_SYSTEM_DB_DIR
#else
#define DWRT_SYSTEM_DB_LEGACY_DIR "/usr/share/dreamingwrt/system-db"
#endif
#endif
#ifndef DWRT_SYSTEM_DB_NEW_DIR
#define DWRT_SYSTEM_DB_NEW_DIR "/usr/share/dreamingos/system-db"
#endif
#ifndef DWRT_SYSTEM_DB_STATE_DIR
#define DWRT_SYSTEM_DB_STATE_DIR "/etc/dreamingwrt/system-db-state"
#endif
#ifndef DWRT_RUNTIME_DB_DIR
#define DWRT_RUNTIME_DB_DIR "/etc/dreamingwrt"
#endif
#ifndef DWRT_FIRMWARE_RELEASE_PATH
#define DWRT_FIRMWARE_RELEASE_PATH "/etc/dreamingwrt-release.json"
#endif
#define DWRT_FINGERPRINT_APP_ID 1146570320
#define DWRT_FINGERPRINT_SCHEMA_VERSION 1

enum system_db_kind {
    SYSTEM_DB_DPI = 0,
    SYSTEM_DB_FINGERPRINT = 1,
};

struct system_db_spec {
    const char *name;
    const char *new_source;
    const char *legacy_source;
    const char *target;
    const char *marker;
    const char *backup;
    enum system_db_kind kind;
};

static const struct system_db_spec g_system_dbs[] = {
    {
        "dpi",
        DWRT_SYSTEM_DB_NEW_DIR "/dreamingwrt_signatures.db",
        DWRT_SYSTEM_DB_LEGACY_DIR "/dreamingwrt_signatures.db",
        DWRT_RUNTIME_DB_DIR "/dreamingwrt_signatures.db",
        DWRT_SYSTEM_DB_STATE_DIR "/dpi.sha256",
        DWRT_SYSTEM_DB_STATE_DIR "/dreamingwrt_signatures.db.previous",
        SYSTEM_DB_DPI,
    },
    {
        "fingerprint",
        DWRT_SYSTEM_DB_NEW_DIR "/fingerprint.db",
        DWRT_SYSTEM_DB_LEGACY_DIR "/fingerprint.db",
        DWRT_RUNTIME_DB_DIR "/fingerprint/fingerprint.db",
        DWRT_SYSTEM_DB_STATE_DIR "/fingerprint.sha256",
        DWRT_SYSTEM_DB_STATE_DIR "/fingerprint.db.previous",
        SYSTEM_DB_FINGERPRINT,
    },
};

static int mkdir_p(const char *path, mode_t mode)
{
    char tmp[512];
    char *p;

    if (!path || !path[0] || strlen(path) >= sizeof(tmp))
        return -1;
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(tmp, mode) != 0 && errno != EEXIST)
            return -1;
        *p = '/';
    }
    return mkdir(tmp, mode) == 0 || errno == EEXIST ? 0 : -1;
}

static int fsync_retry(int fd)
{
    int rc;

    do {
        rc = fsync(fd);
    } while (rc != 0 && errno == EINTR);
    return rc;
}

static int fsync_parent(const char *path)
{
    char parent[512];
    char *slash;
    int fd;
    int rc;

    if (!path || strlen(path) >= sizeof(parent))
        return -1;
    snprintf(parent, sizeof(parent), "%s", path);
    slash = strrchr(parent, '/');
    if (!slash)
        return -1;
    if (slash == parent)
        slash[1] = '\0';
    else
        *slash = '\0';
    fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    rc = fsync_retry(fd);
    close(fd);
    return rc;
}

static int sha256_file(const char *path, char out[65])
{
    EVP_MD_CTX *ctx = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    unsigned char buf[64 * 1024];
    FILE *fp = NULL;
    size_t n;
    unsigned int i;
    int rc = -1;

    out[0] = '\0';
    fp = fopen(path, "rb");
    ctx = EVP_MD_CTX_new();
    if (!fp || !ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
        goto done;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (EVP_DigestUpdate(ctx, buf, n) != 1)
            goto done;
    }
    if (ferror(fp) || EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1 ||
        digest_len != 32)
        goto done;
    for (i = 0; i < digest_len; i++)
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    out[64] = '\0';
    rc = 0;
done:
    if (fp)
        fclose(fp);
    EVP_MD_CTX_free(ctx);
    return rc;
}

static int sqlite_scalar_int(sqlite3 *db, const char *sql, int *value)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW) {
        if (value)
            *value = sqlite3_column_int(st, 0);
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

static int sqlite_table_exists(sqlite3 *db, const char *table)
{
    sqlite3_stmt *st = NULL;
    int found = 0;

    if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, table, -1, SQLITE_STATIC);
    found = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return found;
}

static int validate_database(const char *path, enum system_db_kind kind)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int application_id = 0;
    int schema_version = 0;
    int ok = -1;

    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        goto done;
    sqlite3_busy_timeout(db, 3000);
    if (sqlite3_prepare_v2(db, "PRAGMA quick_check", -1, &st, NULL) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_ROW || !sqlite3_column_text(st, 0) ||
        strcmp((const char *)sqlite3_column_text(st, 0), "ok"))
        goto done;
    sqlite3_finalize(st);
    st = NULL;

    if (kind == SYSTEM_DB_DPI) {
        if (!sqlite_table_exists(db, "app") ||
            !sqlite_table_exists(db, "dpi_rule") ||
            !sqlite_table_exists(db, "domain_entry"))
            goto done;
    } else {
        if (sqlite_scalar_int(db, "PRAGMA application_id", &application_id) != 0 ||
            sqlite_scalar_int(db, "PRAGMA user_version", &schema_version) != 0 ||
            application_id != DWRT_FINGERPRINT_APP_ID ||
            schema_version != DWRT_FINGERPRINT_SCHEMA_VERSION ||
            !sqlite_table_exists(db, "fingerprint_device") ||
            !sqlite_table_exists(db, "fingerprint_meta"))
            goto done;
    }
    ok = 0;
done:
    sqlite3_finalize(st);
    if (db)
        sqlite3_close(db);
    return ok;
}

static int copy_file(const char *source, const char *target, mode_t mode)
{
    unsigned char buf[64 * 1024];
    int in_fd = -1;
    int out_fd = -1;
    ssize_t n;
    int rc = -1;

    in_fd = open(source, O_RDONLY | O_CLOEXEC);
    out_fd = open(target, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (in_fd < 0 || out_fd < 0)
        goto done;
    while ((n = read(in_fd, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t written = write(out_fd, buf + off, (size_t)(n - off));
            if (written < 0) {
                if (errno == EINTR)
                    continue;
                goto done;
            }
            off += written;
        }
    }
    if (n < 0 || fchmod(out_fd, mode) != 0 || fsync_retry(out_fd) != 0)
        goto done;
    rc = 0;
done:
    if (in_fd >= 0)
        close(in_fd);
    if (out_fd >= 0)
        close(out_fd);
    if (rc != 0)
        unlink(target);
    return rc;
}

static int firmware_identity(char out[65])
{
    if (sha256_file(DWRT_FIRMWARE_RELEASE_PATH, out) == 0)
        return 0;
    /* Recovery images predating the release manifest still get deterministic
     * one-time promotion keyed by the source database itself. */
    out[0] = '\0';
    return -1;
}

static int read_marker(const char *path, char firmware_hash[65],
                       char source_hash[65])
{
    FILE *fp;

    firmware_hash[0] = '\0';
    source_hash[0] = '\0';
    fp = fopen(path, "r");
    if (!fp)
        return -1;
    if (fscanf(fp, "%64s %64s", firmware_hash, source_hash) != 2) {
        fclose(fp);
        firmware_hash[0] = '\0';
        source_hash[0] = '\0';
        return -1;
    }
    fclose(fp);
    return strlen(firmware_hash) == 64 && strlen(source_hash) == 64 ? 0 : -1;
}

static int write_marker(const char *path, const char *firmware_hash,
                        const char *source_hash)
{
    char tmp[512];
    char value[132];
    size_t value_len;
    int fd;
    int rc = -1;

    if (snprintf(tmp, sizeof(tmp), "%s.new.%ld", path, (long)getpid()) >=
        (int)sizeof(tmp))
        return -1;
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0)
        return -1;
    snprintf(value, sizeof(value), "%s %s\n", firmware_hash, source_hash);
    value_len = strlen(value);
    if (write(fd, value, value_len) == (ssize_t)value_len &&
        fsync_retry(fd) == 0 && rename(tmp, path) == 0 &&
        fsync_parent(path) == 0)
        rc = 0;
    close(fd);
    if (rc != 0)
        unlink(tmp);
    return rc;
}

static int copy_atomic(const char *source, const char *target, mode_t mode,
                       enum system_db_kind kind, const char *expected_hash)
{
    char tmp[512];
    char actual_hash[65];

    if (snprintf(tmp, sizeof(tmp), "%s.new.%ld", target, (long)getpid()) >=
        (int)sizeof(tmp))
        return -1;
    unlink(tmp);
    if (copy_file(source, tmp, mode) != 0 ||
        validate_database(tmp, kind) != 0 ||
        sha256_file(tmp, actual_hash) != 0 ||
        strcmp(actual_hash, expected_hash) ||
        rename(tmp, target) != 0 || fsync_parent(target) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

static int inspect_one(const struct system_db_spec *spec,
                       struct dwrt_system_db_item_status *item)
{
    enum jmx_path_selection selection = JMX_PATH_SELECTION_NONE;
    char selected[sizeof(item->source)];
    char selection_error[64];

    memset(item, 0, sizeof(*item));
    snprintf(item->name, sizeof(item->name), "%s", spec->name);
    snprintf(item->target, sizeof(item->target), "%s", spec->target);
    if (jmx_path_select_immutable(spec->new_source, spec->legacy_source,
                                  selected, sizeof(selected), &selection,
                                  selection_error, sizeof(selection_error)) != 0) {
        item->source_conflict = !strcmp(selection_error, "path_identity_conflict") ||
                                !strcmp(selection_error, "path_not_safe_regular_file");
        snprintf(item->error, sizeof(item->error), "%s",
                 item->source_conflict ? "firmware_source_identity_conflict" :
                                         "firmware_source_invalid");
        return -1;
    }
    snprintf(item->source, sizeof(item->source), "%s", selected);
    snprintf(item->source_selection, sizeof(item->source_selection), "%s",
             jmx_path_selection_name(selection));
    item->source_valid = validate_database(item->source, spec->kind) == 0 &&
                         sha256_file(item->source, item->source_sha256) == 0;
    item->target_valid = validate_database(spec->target, spec->kind) == 0 &&
                         sha256_file(spec->target, item->target_sha256) == 0;
    if (firmware_identity(item->firmware_identity) != 0 && item->source_valid)
        snprintf(item->firmware_identity, sizeof(item->firmware_identity), "%s",
                 item->source_sha256);
    (void)read_marker(spec->marker, item->applied_firmware_identity,
                      item->applied_source_sha256);
    snprintf(item->action, sizeof(item->action), "%s", "inspect");
    if (!item->source_valid) {
        snprintf(item->error, sizeof(item->error), "%s", "firmware_source_invalid");
        return -1;
    }
    return 0;
}

static int sync_one(const struct system_db_spec *spec,
                    struct dwrt_system_db_item_status *item)
{
    char target_parent[512];
    char *slash;
    int need_replace;

    if (inspect_one(spec, item) != 0)
        return -1;
    need_replace = !item->target_valid ||
                   !item->applied_firmware_identity[0] ||
                   strcmp(item->applied_firmware_identity,
                          item->firmware_identity) ||
                   !item->applied_source_sha256[0] ||
                   strcmp(item->applied_source_sha256, item->source_sha256);
    if (!need_replace) {
        snprintf(item->action, sizeof(item->action), "%s", "preserved");
        return 0;
    }

    snprintf(target_parent, sizeof(target_parent), "%s", spec->target);
    slash = strrchr(target_parent, '/');
    if (!slash) {
        snprintf(item->error, sizeof(item->error), "%s", "target_path_invalid");
        return -1;
    }
    *slash = '\0';
    if (mkdir_p(target_parent, 0755) != 0 ||
        mkdir_p(DWRT_SYSTEM_DB_STATE_DIR, 0755) != 0) {
        snprintf(item->error, sizeof(item->error), "%s", "runtime_directory_failed");
        return -1;
    }

    if (item->target_valid) {
        unlink(spec->backup);
        if (copy_file(spec->target, spec->backup, 0600) != 0) {
            snprintf(item->error, sizeof(item->error), "%s", "rollback_backup_failed");
            return -1;
        }
    }
    if (copy_atomic(item->source, spec->target, 0644, spec->kind,
                    item->source_sha256) != 0) {
        snprintf(item->error, sizeof(item->error), "%s", "atomic_replace_failed");
        return -1;
    }
    if (write_marker(spec->marker, item->firmware_identity,
                     item->source_sha256) != 0) {
        if (access(spec->backup, R_OK) == 0) {
            (void)copy_atomic(spec->backup, spec->target, 0644, spec->kind,
                              item->target_sha256);
        } else {
            unlink(spec->target);
            (void)fsync_parent(spec->target);
        }
        snprintf(item->error, sizeof(item->error), "%s", "state_commit_failed");
        return -1;
    }
    snprintf(item->target_sha256, sizeof(item->target_sha256), "%s",
             item->source_sha256);
    snprintf(item->applied_source_sha256,
             sizeof(item->applied_source_sha256), "%s", item->source_sha256);
    snprintf(item->applied_firmware_identity,
             sizeof(item->applied_firmware_identity), "%s",
             item->firmware_identity);
    item->target_valid = 1;
    item->changed = 1;
    snprintf(item->action, sizeof(item->action), "%s", "replaced_from_firmware");
    return 0;
}

static int run_all(struct dwrt_system_db_status *status, int apply)
{
    size_t i;

    if (!status)
        return -1;
    memset(status, 0, sizeof(*status));
    status->count = sizeof(g_system_dbs) / sizeof(g_system_dbs[0]);
    if (apply) {
        /* Preflight every immutable source before replacing either runtime DB. */
        for (i = 0; i < status->count; i++) {
            if (inspect_one(&g_system_dbs[i], &status->items[i]) != 0)
                status->errors++;
            if (status->items[i].source_conflict)
                status->conflicts++;
        }
        if (status->errors)
            return -1;
        memset(status->items, 0, sizeof(status->items));
    }
    for (i = 0; i < status->count; i++) {
        int rc = apply ? sync_one(&g_system_dbs[i], &status->items[i]) :
                         inspect_one(&g_system_dbs[i], &status->items[i]);
        if (rc != 0)
            status->errors++;
        if (status->items[i].source_conflict)
            status->conflicts++;
        if (status->items[i].changed)
            status->changed++;
    }
    return status->errors ? -1 : 0;
}

int dwrt_system_db_sync(struct dwrt_system_db_status *status)
{
    return run_all(status, 1);
}

int dwrt_system_db_inspect(struct dwrt_system_db_status *status)
{
    return run_all(status, 0);
}

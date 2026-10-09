// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE 1
#include "config_snapshot.h"
#include "../jmx_config_schema.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <sqlite3.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define SNAPSHOT_MANIFEST_MAX (128U * 1024U)
#define SNAPSHOT_DB_MAX (512ULL * 1024ULL * 1024ULL)
#define SNAPSHOT_FILE_MAX (64ULL * 1024ULL * 1024ULL)

/*
 * Default allowlist of paths to snapshot.
 *
 * Databases are backed up using SQLite online backup API.
 * Other files are copied directly.
 */
static const char *const snapshot_databases[] = {
    "/etc/dreamingwrt/config.db",
    "/etc/dreamingwrt/dreamingwrt.db",
    "/etc/dreamingwrt/apid.db",
    "/etc/dreamingwrt/notify.db",
};

static const char *const snapshot_config_dirs[] = {
    "/etc/config/",
};

static const char *const snapshot_key_dirs[] = {
    "/etc/dreamingwrt/tls/",
    "/etc/dreamingwrt/credentials/",
};

static const char *const snapshot_key_files[] = {
    "/etc/dreamingwrt/*.key",
};

static const char *const snapshot_data_dirs[] = {
    "/etc/dreamingwrt/geoip/",
    "/etc/dreamingwrt/signatures/",
};

/* Files explicitly excluded from snapshot. */
static const char *const snapshot_exclude_patterns[] = {
    "metrics.db",
    "log.db",
    "*.tmp",
    "*.lock",
    "*.pid",
    "*.wal",
    "*.shm",
};

static void snapshot_error(char *error, size_t error_len, const char *msg)
{
    if (error && error_len)
        snprintf(error, error_len, "%s", msg ? msg : "snapshot_error");
}

static int write_all(int fd, const void *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, (const char *)buf + off, len - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
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
    const char *slash;
    size_t n;
    int fd;

    if (!path || !(slash = strrchr(path, '/')))
        return -1;
    n = slash == path ? 1 : (size_t)(slash - path);
    if (n >= sizeof(parent))
        return -1;
    memcpy(parent, path, n);
    parent[n] = '\0';
    fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (fsync_retry(fd) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return close(fd);
}

static int ensure_dir(const char *path, mode_t mode)
{
    char buf[512];
    char *p;
    size_t n = path ? strlen(path) : 0;

    if (!n || n >= sizeof(buf) || path[0] != '/')
        return -1;
    snprintf(buf, sizeof(buf), "%s", path);
    for (p = buf + 1; ; p++) {
        if (*p != '/' && *p != '\0') continue;
        {
            char saved = *p;
            struct stat st;
            *p = '\0';
            if (mkdir(buf, mode) != 0 && errno != EEXIST)
                return -1;
            if (lstat(buf, &st) != 0 || !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode))
                return -1;
            *p = saved;
            if (saved == '\0') break;
        }
    }
    return chmod(path, mode);
}

static int sha256_file(const char *path, char out[65], uint64_t *size_out)
{
    unsigned char buf[16384];
    unsigned char digest[32];
    uint64_t total = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    int rc = -1;

    if (fd < 0) return -1;
#ifdef __APPLE__
#include <CommonCrypto/CommonDigest.h>
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
#else
#include <openssl/evp.h>
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int digest_len = 0;
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        close(fd);
        return -1;
    }
#endif
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) goto done;
        if (n == 0) break;
#ifdef __APPLE__
        CC_SHA256_Update(&ctx, buf, (CC_LONG)n);
#else
        if (EVP_DigestUpdate(ctx, buf, (size_t)n) != 1) goto done;
#endif
        total += (uint64_t)n;
        if (total > SNAPSHOT_DB_MAX) goto done;
    }
#ifdef __APPLE__
    CC_SHA256_Final(digest, &ctx);
#else
    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1 || digest_len != 32)
        goto done;
#endif
    for (int i = 0; i < 32; i++)
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    out[64] = '\0';
    if (size_out) *size_out = total;
    rc = 0;
done:
#ifndef __APPLE__
    EVP_MD_CTX_free(ctx);
#endif
    close(fd);
    return rc;
}

static int copy_file_atomic(const char *src, const char *dst, mode_t mode)
{
    char tmp[640];
    int in_fd = -1, out_fd = -1;
    char buf[65536];
    ssize_t got;
    int rc = -1;

    if (snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", dst, (long)getpid()) >= (int)sizeof(tmp))
        return -1;
    unlink(tmp);
    in_fd = open(src, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (in_fd < 0) return -1;
    out_fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
    if (out_fd < 0) { close(in_fd); return -1; }
    while ((got = read(in_fd, buf, sizeof(buf))) > 0) {
        if (write_all(out_fd, buf, (size_t)got) != 0) goto done;
    }
    if (got < 0) goto done;
    if (fsync_retry(out_fd) != 0) goto done;
    close(out_fd); out_fd = -1;
    if (rename(tmp, dst) != 0) goto done;
    if (fsync_parent(dst) != 0) goto done;
    rc = 0;
done:
    if (in_fd >= 0) close(in_fd);
    if (out_fd >= 0) close(out_fd);
    if (rc != 0) unlink(tmp);
    return rc;
}

static int sqlite_backup_file(const char *source, const char *dest)
{
    char tmp[640];
    sqlite3 *src = NULL;
    sqlite3 *dst = NULL;
    sqlite3_backup *backup = NULL;
    int rc = -1;
    int step_rc;
    int fd;

    if (snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", dest, (long)getpid()) >= (int)sizeof(tmp))
        return -1;
    unlink(tmp);
    if (sqlite3_open_v2(source, &src, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        goto done;
    sqlite3_busy_timeout(src, 5000);
    if (sqlite3_open_v2(tmp, &dst, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK)
        goto done;
    sqlite3_busy_timeout(dst, 5000);
    backup = sqlite3_backup_init(dst, "main", src, "main");
    if (!backup) goto done;
    do {
        step_rc = sqlite3_backup_step(backup, 256);
        if (step_rc == SQLITE_BUSY || step_rc == SQLITE_LOCKED)
            sqlite3_sleep(20);
    } while (step_rc == SQLITE_OK || step_rc == SQLITE_BUSY || step_rc == SQLITE_LOCKED);
    if (sqlite3_backup_finish(backup) != SQLITE_OK || step_rc != SQLITE_DONE) {
        backup = NULL;
        goto done;
    }
    backup = NULL;
    if (sqlite3_close(dst) != SQLITE_OK) { dst = NULL; goto done; }
    dst = NULL;
    sqlite3_close(src); src = NULL;
    if (chmod(tmp, 0600) != 0) goto done;
    fd = open(tmp, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fsync_retry(fd) != 0) {
        if (fd >= 0) close(fd);
        goto done;
    }
    close(fd);
    if (rename(tmp, dest) != 0 || fsync_parent(dest) != 0) goto done;
    rc = 0;
done:
    if (backup) sqlite3_backup_finish(backup);
    if (dst) sqlite3_close(dst);
    if (src) sqlite3_close(src);
    if (rc != 0) unlink(tmp);
    return rc;
}

static int sqlite_check_integrity(const char *path, char *out, size_t out_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int rc = -1;
    char uri[1024];
    size_t used = 0;
    static const char hex[] = "0123456789ABCDEF";

    if (!path || path[0] != '/') goto fail;
    memcpy(uri, "file:", 5); used = 5;
    for (const unsigned char *p = (const unsigned char *)path; *p; p++) {
        int literal = isalnum(*p) || *p == '/' || *p == '-' || *p == '_' || *p == '.' || *p == '~';
        if (used + (literal ? 1U : 3U) + sizeof("?mode=ro&immutable=1") >= sizeof(uri))
            goto fail;
        if (literal) { uri[used++] = (char)*p; }
        else { uri[used++] = '%'; uri[used++] = hex[*p >> 4]; uri[used++] = hex[*p & 0x0f]; }
    }
    memcpy(uri + used, "?mode=ro&immutable=1", sizeof("?mode=ro&immutable=1"));
    if (sqlite3_open_v2(uri, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_busy_timeout(db, 3000);
    if (sqlite3_prepare_v2(db, "PRAGMA quick_check", -1, &st, NULL) != SQLITE_OK)
        goto fail;
    if (sqlite3_step(st) != SQLITE_ROW || !sqlite3_column_text(st, 0) ||
        strcmp((const char *)sqlite3_column_text(st, 0), "ok")) {
        if (out && out_len) snprintf(out, out_len, "integrity_check_failed");
        goto fail;
    }
    sqlite3_finalize(st); st = NULL;
    if (out && out_len) snprintf(out, out_len, "ok");
    rc = 0;
fail:
    if (st) sqlite3_finalize(st);
    if (db) sqlite3_close(db);
    return rc;
}

static int sqlite_get_schema_version(const char *path)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int version = -1;
    char uri[1024];
    size_t used = 0;
    static const char hex[] = "0123456789ABCDEF";

    if (!path || path[0] != '/') return -1;
    memcpy(uri, "file:", 5); used = 5;
    for (const unsigned char *p = (const unsigned char *)path; *p; p++) {
        int literal = isalnum(*p) || *p == '/' || *p == '-' || *p == '_' || *p == '.' || *p == '~';
        if (used + (literal ? 1U : 3U) + sizeof("?mode=ro&immutable=1") >= sizeof(uri))
            return -1;
        if (literal) { uri[used++] = (char)*p; }
        else { uri[used++] = '%'; uri[used++] = hex[*p >> 4]; uri[used++] = hex[*p & 0x0f]; }
    }
    memcpy(uri + used, "?mode=ro&immutable=1", sizeof("?mode=ro&immutable=1"));
    if (sqlite3_open_v2(uri, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL) != SQLITE_OK)
        return -1;
    sqlite3_busy_timeout(db, 3000);
    if (sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        version = sqlite3_column_int(st, 0);
    if (st) sqlite3_finalize(st);
    if (db) sqlite3_close(db);
    return version;
}

static int is_excluded(const char *path)
{
    const char *name = strrchr(path, '/');
    if (name) name++; else name = path;
    for (size_t i = 0; i < sizeof(snapshot_exclude_patterns) / sizeof(snapshot_exclude_patterns[0]); i++) {
        const char *pat = snapshot_exclude_patterns[i];
        if (pat[0] == '*') {
            const char *ext = pat + 1;
            size_t name_len = strlen(name);
            size_t ext_len = strlen(ext);
            if (name_len >= ext_len && !strcmp(name + name_len - ext_len, ext))
                return 1;
        } else if (!strcmp(name, pat)) {
            return 1;
        }
    }
    return 0;
}

static int collect_config_files(const char *dir_path,
                                struct dwrt_config_snapshot_manifest *manifest)
{
    DIR *dir;
    struct dirent *ent;
    char full_path[512];
    struct stat st;

    dir = opendir(dir_path);
    if (!dir) return 0;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (snprintf(full_path, sizeof(full_path), "%s%s", dir_path, ent->d_name) >= (int)sizeof(full_path))
            continue;
        if (lstat(full_path, &st) != 0) continue;
        if (!S_ISREG(st.st_mode)) continue;
        if (is_excluded(full_path)) continue;
        if (manifest->file_count >= DWRT_CONFIG_SNAPSHOT_MAX_FILES) break;
        struct dwrt_config_snapshot_file *f = &manifest->files[manifest->file_count];
        snprintf(f->path, sizeof(f->path), "%s", full_path);
        f->size = (uint64_t)st.st_size;
        f->mode = st.st_mode & 0777;
        if (sha256_file(full_path, f->sha256, NULL) != 0) continue;
        manifest->file_count++;
    }
    closedir(dir);
    return 0;
}

static int collect_key_files(struct dwrt_config_snapshot_manifest *manifest)
{
    DIR *dir;
    struct dirent *ent;
    char full_path[512];
    struct stat st;

    /* Collect .key files from /etc/dreamingwrt/ */
    dir = opendir("/etc/dreamingwrt/");
    if (dir) {
        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            size_t name_len = strlen(ent->d_name);
            if (name_len < 4 || strcmp(ent->d_name + name_len - 4, ".key") != 0) continue;
            if (snprintf(full_path, sizeof(full_path), "/etc/dreamingwrt/%s", ent->d_name) >= (int)sizeof(full_path))
                continue;
            if (lstat(full_path, &st) != 0 || !S_ISREG(st.st_mode)) continue;
            if (manifest->file_count >= DWRT_CONFIG_SNAPSHOT_MAX_FILES) break;
            struct dwrt_config_snapshot_file *f = &manifest->files[manifest->file_count];
            snprintf(f->path, sizeof(f->path), "%s", full_path);
            f->size = (uint64_t)st.st_size;
            f->mode = st.st_mode & 0777;
            if (sha256_file(full_path, f->sha256, NULL) != 0) continue;
            manifest->file_count++;
        }
        closedir(dir);
    }
    return 0;
}

static int snapshot_manifest_write(const char *dir,
                                   const struct dwrt_config_snapshot_manifest *manifest)
{
    char path[640];
    char tmp[640];
    FILE *fp;
    int fd;

    if (snprintf(path, sizeof(path), "%s/manifest.json", dir) >= (int)sizeof(path))
        return -1;
    if (snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid()) >= (int)sizeof(tmp))
        return -1;
    unlink(tmp);
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    fp = fdopen(fd, "w");
    if (!fp) { close(fd); unlink(tmp); return -1; }

    fprintf(fp, "{\n");
    fprintf(fp, "  \"format\": \"%s\",\n", manifest->format);
    fprintf(fp, "  \"snapshot_id\": \"%s\",\n", manifest->snapshot_id);
    fprintf(fp, "  \"board\": \"%s\",\n", manifest->board);
    fprintf(fp, "  \"source_release\": \"%s\",\n", manifest->source_release);
    fprintf(fp, "  \"schema_version\": %d,\n", manifest->schema_version);
    fprintf(fp, "  \"created_at\": %lld,\n", (long long)manifest->created_at);
    fprintf(fp, "  \"scope\": \"%s\",\n", manifest->scope);

    fprintf(fp, "  \"files\": [\n");
    for (int i = 0; i < manifest->file_count; i++) {
        const struct dwrt_config_snapshot_file *f = &manifest->files[i];
        fprintf(fp, "    {\"path\":\"%s\",\"size\":%llu,\"sha256\":\"%s\",\"mode\":%u}%s\n",
                f->path, (unsigned long long)f->size, f->sha256, (unsigned)f->mode,
                i < manifest->file_count - 1 ? "," : "");
    }
    fprintf(fp, "  ],\n");

    fprintf(fp, "  \"databases\": [\n");
    for (int i = 0; i < manifest->db_count; i++) {
        const struct dwrt_config_snapshot_db *d = &manifest->dbs[i];
        fprintf(fp, "    {\"path\":\"%s\",\"integrity\":\"%s\",\"schema_version\":%d}%s\n",
                d->path, d->integrity, d->schema_version,
                i < manifest->db_count - 1 ? "," : "");
    }
    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");

    if (fflush(fp) != 0 || fsync(fileno(fp)) != 0 || fclose(fp) != 0) {
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, path) != 0 || fsync_parent(path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

int dwrt_config_snapshot_path(const char *operation_id, char *out, size_t out_len)
{
    char root[768] = "";

    if (!operation_id || !operation_id[0] || !out || !out_len)
        return -1;
    /* Validate operation_id contains only safe characters. */
    for (const char *p = operation_id; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!isalnum(c) && c != '_' && c != '-' && c != '.') return -1;
    }
    (void)dwrt_config_snapshot_storage_state(root, sizeof(root), NULL);
    if (!root[0])
        snprintf(root, sizeof(root), "%s", DWRT_CONFIG_SNAPSHOT_DIR);
    if (snprintf(out, out_len, "%s/%s", root, operation_id) >= (int)out_len)
        return -1;
    return 0;
}

int dwrt_config_snapshot_storage_state(char *active_path, size_t path_len,
                                       int *frozen)
{
    FILE *fp;
    char line[1024];
    char path[768] = "";
    int is_frozen = 0;

    if (active_path && path_len)
        active_path[0] = '\0';
    if (frozen)
        *frozen = 0;
    fp = fopen(DWRT_CONFIG_SNAPSHOT_STORAGE_STATE, "re");
    if (!fp)
        return 0; /* missing state is the safe local/default state */
    while (fgets(line, sizeof(line), fp)) {
        char *eq = strchr(line, '=');
        char *value;

        if (!eq)
            continue;
        *eq = '\0';
        value = eq + 1;
        value[strcspn(value, "\r\n")] = '\0';
        if (!strcmp(line, "active_path"))
            snprintf(path, sizeof(path), "%s", value);
        else if (!strcmp(line, "frozen"))
            is_frozen = !strcmp(value, "1");
    }
    fclose(fp);
    if (path[0] && path[0] != '/')
        path[0] = '\0';
    if (active_path && path_len)
        snprintf(active_path, path_len, "%s", path);
    if (frozen)
        *frozen = is_frozen;
    return 0;
}

int dwrt_config_snapshot_exists(const char *operation_id)
{
    char dir[640];
    char manifest_path[640];

    if (dwrt_config_snapshot_path(operation_id, dir, sizeof(dir)) != 0)
        return 0;
    if (snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json", dir) >= (int)sizeof(manifest_path))
        return 0;
    return access(manifest_path, R_OK) == 0;
}

int dwrt_config_snapshot_create(const char *operation_id,
                                const char *board,
                                const char *source_release,
                                char *error, size_t error_len)
{
    char dir[640];
    char db_dest[640];
    char file_dest[640];
    struct dwrt_config_snapshot_manifest manifest;
    int rc = DWRT_SNAPSHOT_ERR_BACKUP_FAILED;
    char active_path[768] = "";
    int storage_frozen = 0;
    char snapshot_root[768] = "";

    if (!operation_id || !operation_id[0]) {
        snapshot_error(error, error_len, "operation_id_required");
        return DWRT_SNAPSHOT_ERR_INVALID_ARGS;
    }
    (void)dwrt_config_snapshot_storage_state(active_path, sizeof(active_path),
                                             &storage_frozen);
    if (storage_frozen) {
        snapshot_error(error, error_len, "storage_migration_frozen");
        return DWRT_SNAPSHOT_ERR_BACKUP_FAILED;
    }
    /* A supervisor-selected snapshots path must be live before the producer
     * writes.  Never silently fall back to overlay when the external provider
     * disappeared; an empty state file preserves the historical local path. */
    if (active_path[0] && access(active_path, W_OK) != 0) {
        snapshot_error(error, error_len, "external_storage_unavailable");
        return DWRT_SNAPSHOT_ERR_BACKUP_FAILED;
    }
    snprintf(snapshot_root, sizeof(snapshot_root), "%s",
             active_path[0] ? active_path : DWRT_CONFIG_SNAPSHOT_DIR);
    if (dwrt_config_snapshot_path(operation_id, dir, sizeof(dir)) != 0) {
        snapshot_error(error, error_len, "operation_id_too_long_or_invalid");
        return DWRT_SNAPSHOT_ERR_INVALID_ARGS;
    }

    memset(&manifest, 0, sizeof(manifest));
    snprintf(manifest.format, sizeof(manifest.format), "%s", DWRT_CONFIG_SNAPSHOT_FORMAT);
    snprintf(manifest.snapshot_id, sizeof(manifest.snapshot_id), "%s", operation_id);
    snprintf(manifest.board, sizeof(manifest.board), "%s", board ? board : "unknown");
    snprintf(manifest.source_release, sizeof(manifest.source_release), "%s", source_release ? source_release : "");
    manifest.schema_version = DWRT_CONFIG_SNAPSHOT_SCHEMA_VERSION;
    manifest.created_at = (int64_t)time(NULL);
    snprintf(manifest.scope, sizeof(manifest.scope), "dreamingwrt-config-v1");

    /* Create snapshot directory. */
    if (ensure_dir(snapshot_root, 0700) != 0) {
        snapshot_error(error, error_len, "snapshot_base_dir_failed");
        return DWRT_SNAPSHOT_ERR_MKDIR_FAILED;
    }
    if (ensure_dir(dir, 0700) != 0) {
        snapshot_error(error, error_len, "snapshot_dir_failed");
        return DWRT_SNAPSHOT_ERR_MKDIR_FAILED;
    }

    /* Backup databases using SQLite online backup API. */
    for (size_t i = 0; i < sizeof(snapshot_databases) / sizeof(snapshot_databases[0]); i++) {
        const char *db_path = snapshot_databases[i];
        const char *db_name;

        if (access(db_path, R_OK) != 0) continue;
        db_name = strrchr(db_path, '/');
        db_name = db_name ? db_name + 1 : db_path;
        if (snprintf(db_dest, sizeof(db_dest), "%s/%s", dir, db_name) >= (int)sizeof(db_dest))
            continue;
        if (sqlite_backup_file(db_path, db_dest) != 0) {
            snprintf(error, error_len, "db_backup_failed:%s", db_path);
            goto fail;
        }
        /* Verify integrity of the backup. */
        char integrity[32];
        if (sqlite_check_integrity(db_dest, integrity, sizeof(integrity)) != 0) {
            snprintf(error, error_len, "db_integrity_failed:%s", db_path);
            goto fail;
        }
        if (manifest.db_count < DWRT_CONFIG_SNAPSHOT_MAX_DBS) {
            struct dwrt_config_snapshot_db *db = &manifest.dbs[manifest.db_count];
            snprintf(db->path, sizeof(db->path), "%s", db_path);
            snprintf(db->integrity, sizeof(db->integrity), "%s", integrity);
            db->schema_version = sqlite_get_schema_version(db_dest);
            manifest.db_count++;
        }
        /* Also add to files list for hash verification. */
        if (manifest.file_count < DWRT_CONFIG_SNAPSHOT_MAX_FILES) {
            struct stat st;
            if (lstat(db_dest, &st) == 0) {
                struct dwrt_config_snapshot_file *f = &manifest.files[manifest.file_count];
                snprintf(f->path, sizeof(f->path), "%s", db_path);
                f->size = (uint64_t)st.st_size;
                f->mode = 0600;
                if (sha256_file(db_dest, f->sha256, NULL) == 0)
                    manifest.file_count++;
            }
        }
    }

    /* Copy UCI config files. */
    for (size_t i = 0; i < sizeof(snapshot_config_dirs) / sizeof(snapshot_config_dirs[0]); i++) {
        collect_config_files(snapshot_config_dirs[i], &manifest);
    }

    /* Copy key/certificate files. */
    collect_key_files(&manifest);

    /* Copy data directories (geoip, signatures). */
    for (size_t i = 0; i < sizeof(snapshot_data_dirs) / sizeof(snapshot_data_dirs[0]); i++) {
        collect_config_files(snapshot_data_dirs[i], &manifest);
    }

    /* Now copy all non-database files to the snapshot directory. */
    for (int i = 0; i < manifest.file_count; i++) {
        const struct dwrt_config_snapshot_file *f = &manifest.files[i];
        const char *src_path = f->path;
        const char *name;

        /* Skip databases (already backed up). */
        int is_db = 0;
        for (int j = 0; j < manifest.db_count; j++) {
            if (!strcmp(manifest.dbs[j].path, f->path)) { is_db = 1; break; }
        }
        if (is_db) continue;

        name = strrchr(src_path, '/');
        name = name ? name + 1 : src_path;
        /* Use a flat structure with path encoded in filename to avoid collisions. */
        char safe_name[512];
        snprintf(safe_name, sizeof(safe_name), "%s", src_path + 1); /* skip leading / */
        for (char *p = safe_name; *p; p++) {
            if (*p == '/') *p = '_';
        }
        if (snprintf(file_dest, sizeof(file_dest), "%s/%s", dir, safe_name) >= (int)sizeof(file_dest))
            continue;
        if (copy_file_atomic(src_path, file_dest, f->mode) != 0) {
            snprintf(error, error_len, "file_copy_failed:%s", src_path);
            goto fail;
        }
    }

    /* Write manifest last (atomic). */
    if (snapshot_manifest_write(dir, &manifest) != 0) {
        snapshot_error(error, error_len, "manifest_write_failed");
        rc = DWRT_SNAPSHOT_ERR_MANIFEST_FAILED;
        goto fail;
    }

    return DWRT_SNAPSHOT_OK;

fail:
    /* Clean up partial snapshot. */
    {
        char cmd[640];
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
        (void)system(cmd);
    }
    return rc;
}

int dwrt_config_snapshot_validate(const char *operation_id,
                                  const char *expected_board,
                                  char *error, size_t error_len)
{
    char dir[640];
    char manifest_path[640];
    char *manifest_data = NULL;
    size_t manifest_len = 0;
    FILE *fp;
    int rc = DWRT_SNAPSHOT_ERR_VERIFY_FAILED;

    if (dwrt_config_snapshot_path(operation_id, dir, sizeof(dir)) != 0) {
        snapshot_error(error, error_len, "invalid_operation_id");
        return DWRT_SNAPSHOT_ERR_INVALID_ARGS;
    }
    if (snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json", dir) >= (int)sizeof(manifest_path)) {
        snapshot_error(error, error_len, "path_too_long");
        return DWRT_SNAPSHOT_ERR_INVALID_ARGS;
    }

    fp = fopen(manifest_path, "r");
    if (!fp) {
        snapshot_error(error, error_len, "manifest_not_found");
        return DWRT_SNAPSHOT_ERR_VERIFY_FAILED;
    }
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (fsize <= 0 || (size_t)fsize > SNAPSHOT_MANIFEST_MAX) {
        fclose(fp);
        snapshot_error(error, error_len, "manifest_size_invalid");
        return DWRT_SNAPSHOT_ERR_VERIFY_FAILED;
    }
    manifest_data = malloc((size_t)fsize + 1);
    if (!manifest_data) { fclose(fp); return DWRT_SNAPSHOT_ERR_VERIFY_FAILED; }
    if (fread(manifest_data, 1, (size_t)fsize, fp) != (size_t)fsize) {
        free(manifest_data); fclose(fp);
        snapshot_error(error, error_len, "manifest_read_failed");
        return DWRT_SNAPSHOT_ERR_VERIFY_FAILED;
    }
    manifest_data[fsize] = '\0';
    fclose(fp);

    /* Verify board matches. */
    if (expected_board && expected_board[0]) {
        char board_buf[64];
        const char *p = strstr(manifest_data, "\"board\":\"");
        if (!p) { free(manifest_data); snapshot_error(error, error_len, "manifest_missing_board"); return DWRT_SNAPSHOT_ERR_VERIFY_FAILED; }
        p += 9;
        size_t i = 0;
        while (*p && *p != '"' && i < sizeof(board_buf) - 1) board_buf[i++] = *p++;
        board_buf[i] = '\0';
        if (strcmp(board_buf, expected_board)) {
            free(manifest_data);
            snprintf(error, error_len, "board_mismatch:%s!=%s", board_buf, expected_board);
            return DWRT_SNAPSHOT_ERR_VERIFY_FAILED;
        }
    }

    /* Verify file hashes. */
    for (int i = 0; i < /* manifest.file_count */ 100; i++) {
        /* Parse file entry from JSON (simplified). */
        char file_path[512];
        char expected_hash[65];
        char actual_hash[65];
        char *entry;
        char path_key[64];
        char hash_key[64];

        snprintf(path_key, sizeof(path_key), "\"path\":\"");
        snprintf(hash_key, sizeof(hash_key), "\"sha256\":\"");

        entry = strstr(manifest_data, path_key);
        if (!entry) break;
        entry += strlen(path_key);
        size_t j = 0;
        while (*entry && *entry != '"' && j < sizeof(file_path) - 1) file_path[j++] = *entry++;
        file_path[j] = '\0';

        entry = strstr(manifest_data, hash_key);
        if (!entry) break;
        entry += strlen(hash_key);
        j = 0;
        while (*entry && *entry != '"' && j < sizeof(expected_hash) - 1) expected_hash[j++] = *entry++;
        expected_hash[j] = '\0';

        /* Check if this is a database (already verified via integrity check). */
        int is_db = 0;
        for (size_t k = 0; k < sizeof(snapshot_databases) / sizeof(snapshot_databases[0]); k++) {
            if (!strcmp(file_path, snapshot_databases[k])) { is_db = 1; break; }
        }
        if (is_db) continue;

        /* Find the actual file in the snapshot. */
        char safe_name[512];
        snprintf(safe_name, sizeof(safe_name), "%s", file_path + 1);
        for (char *p2 = safe_name; *p2; p2++) {
            if (*p2 == '/') *p2 = '_';
        }
        char snapshot_file[640];
        if (snprintf(snapshot_file, sizeof(snapshot_file), "%s/%s", dir, safe_name) >= (int)sizeof(snapshot_file))
            continue;
        if (access(snapshot_file, R_OK) != 0) continue;
        if (sha256_file(snapshot_file, actual_hash, NULL) != 0) {
            snprintf(error, error_len, "hash_failed:%s", file_path);
            free(manifest_data);
            return DWRT_SNAPSHOT_ERR_HASH_MISMATCH;
        }
        if (strcasecmp(actual_hash, expected_hash)) {
            snprintf(error, error_len, "hash_mismatch:%s", file_path);
            free(manifest_data);
            return DWRT_SNAPSHOT_ERR_HASH_MISMATCH;
        }
    }

    free(manifest_data);
    return DWRT_SNAPSHOT_OK;
}

int dwrt_config_snapshot_restore(const char *operation_id,
                                 char *error, size_t error_len)
{
    char dir[640];
    char manifest_path[640];
    char *manifest_data = NULL;
    size_t manifest_len = 0;
    FILE *fp;
    int rc = DWRT_SNAPSHOT_ERR_RESTORE_FAILED;

    if (dwrt_config_snapshot_path(operation_id, dir, sizeof(dir)) != 0) {
        snapshot_error(error, error_len, "invalid_operation_id");
        return DWRT_SNAPSHOT_ERR_INVALID_ARGS;
    }
    if (snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json", dir) >= (int)sizeof(manifest_path)) {
        snapshot_error(error, error_len, "path_too_long");
        return DWRT_SNAPSHOT_ERR_INVALID_ARGS;
    }

    fp = fopen(manifest_path, "r");
    if (!fp) {
        snapshot_error(error, error_len, "manifest_not_found");
        return DWRT_SNAPSHOT_ERR_RESTORE_FAILED;
    }
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (fsize <= 0 || (size_t)fsize > SNAPSHOT_MANIFEST_MAX) {
        fclose(fp);
        snapshot_error(error, error_len, "manifest_size_invalid");
        return DWRT_SNAPSHOT_ERR_RESTORE_FAILED;
    }
    manifest_data = malloc((size_t)fsize + 1);
    if (!manifest_data) { fclose(fp); return DWRT_SNAPSHOT_ERR_RESTORE_FAILED; }
    if (fread(manifest_data, 1, (size_t)fsize, fp) != (size_t)fsize) {
        free(manifest_data); fclose(fp);
        snapshot_error(error, error_len, "manifest_read_failed");
        return DWRT_SNAPSHOT_ERR_RESTORE_FAILED;
    }
    manifest_data[fsize] = '\0';
    fclose(fp);

    /* Restore databases. */
    for (size_t i = 0; i < sizeof(snapshot_databases) / sizeof(snapshot_databases[0]); i++) {
        const char *db_path = snapshot_databases[i];
        const char *db_name = strrchr(db_path, '/');
        db_name = db_name ? db_name + 1 : db_path;
        char db_src[640];
        if (snprintf(db_src, sizeof(db_src), "%s/%s", dir, db_name) >= (int)sizeof(db_src))
            continue;
        if (access(db_src, R_OK) != 0) continue;
        /* Use sqlite backup to restore (reverse direction). */
        char db_tmp[640];
        if (snprintf(db_tmp, sizeof(db_tmp), "%s.tmp.%ld", db_path, (long)getpid()) >= (int)sizeof(db_tmp))
            continue;
        unlink(db_tmp);
        if (copy_file_atomic(db_src, db_tmp, 0600) != 0) {
            snprintf(error, error_len, "db_restore_copy_failed:%s", db_path);
            free(manifest_data);
            return DWRT_SNAPSHOT_ERR_RESTORE_FAILED;
        }
        if (rename(db_tmp, db_path) != 0) {
            unlink(db_tmp);
            snprintf(error, error_len, "db_restore_rename_failed:%s", db_path);
            free(manifest_data);
            return DWRT_SNAPSHOT_ERR_RESTORE_FAILED;
        }
        fsync_parent(db_path);
    }

    /* Restore config files. */
    for (size_t i = 0; i < sizeof(snapshot_config_dirs) / sizeof(snapshot_config_dirs[0]); i++) {
        const char *config_dir = snapshot_config_dirs[i];
        DIR *d = opendir(config_dir);
        if (!d) continue;
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            char src_path[512];
            if (snprintf(src_path, sizeof(src_path), "%s%s", config_dir, ent->d_name) >= (int)sizeof(src_path))
                continue;
            char safe_name[512];
            snprintf(safe_name, sizeof(safe_name), "%s", src_path + 1);
            for (char *p = safe_name; *p; p++) {
                if (*p == '/') *p = '_';
            }
            char snapshot_file[640];
            if (snprintf(snapshot_file, sizeof(snapshot_file), "%s/%s", dir, safe_name) >= (int)sizeof(snapshot_file))
                continue;
            if (access(snapshot_file, R_OK) != 0) continue;
            struct stat st;
            if (lstat(snapshot_file, &st) != 0) continue;
            copy_file_atomic(snapshot_file, src_path, st.st_mode);
        }
        closedir(d);
    }

    free(manifest_data);
    return DWRT_SNAPSHOT_OK;
}

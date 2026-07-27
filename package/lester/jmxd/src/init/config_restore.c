// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE 1
#include "config_restore.h"
#include "../jmx_config_schema.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#include <CommonCrypto/CommonDigest.h>
#else
#include <openssl/evp.h>
#endif
#include <sqlite3.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define RESTORE_MANIFEST_MAX (64U * 1024U)
#define RESTORE_DB_MAX (512ULL * 1024ULL * 1024ULL)
#define RESTORE_BACKUP_DB DWRT_CONFIG_RESTORE_BACKUP_DIR "/config.db"
#define RESTORE_BACKUP_NETWORK DWRT_CONFIG_RESTORE_BACKUP_DIR "/network"
#define RESTORE_BACKUP_DHCP DWRT_CONFIG_RESTORE_BACKUP_DIR "/dhcp"
#define RESTORE_BACKUP_FIREWALL DWRT_CONFIG_RESTORE_BACKUP_DIR "/firewall"
#define RESTORE_BACKUP_SYSTEM DWRT_CONFIG_RESTORE_BACKUP_DIR "/system"
#define RESTORE_BACKUP_RUNTIME_HOSTNAME DWRT_CONFIG_RESTORE_BACKUP_DIR "/runtime-hostname"

static void restore_error(struct dwrt_config_restore_info *out, const char *error)
{
    if (out)
        snprintf(out->error, sizeof(out->error), "%s", error ? error : "restore_error");
}

static int write_all(int fd, const void *buf, size_t len)
{
    size_t off = 0;

    while (off < len) {
        ssize_t n = write(fd, (const char *)buf + off, len - off);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
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
    if (fd < 0)
        return -1;
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
        if (*p != '/' && *p != '\0')
            continue;
        {
            char saved = *p;
            struct stat st;

            *p = '\0';
            if (mkdir(buf, mode) != 0 && errno != EEXIST)
                return -1;
            if (lstat(buf, &st) != 0 || !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode))
                return -1;
            *p = saved;
            if (saved == '\0')
                break;
        }
    }
    return chmod(path, mode);
}

static int read_regular(const char *path, char **out, size_t *out_len, size_t max_len)
{
    struct stat st;
    char *buf = NULL;
    size_t off = 0;
    int fd = -1;

    if (!path || !out || !out_len)
        return -1;
    *out = NULL;
    *out_len = 0;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uint64_t)st.st_size > max_len) {
        if (fd >= 0) close(fd);
        return -1;
    }
    buf = calloc(1, (size_t)st.st_size + 1);
    if (!buf) {
        close(fd);
        return -1;
    }
    while (off < (size_t)st.st_size) {
        ssize_t n = read(fd, buf + off, (size_t)st.st_size - off);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            free(buf);
            close(fd);
            return -1;
        }
        off += (size_t)n;
    }
    close(fd);
    buf[off] = '\0';
    *out = buf;
    *out_len = off;
    return 0;
}

static int write_atomic(const char *path, const void *data, size_t len, mode_t mode)
{
    char tmp[640];
    int fd;
    int rc = -1;

    if (!path || (!data && len) || snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path,
                                             (long)getpid()) >= (int)sizeof(tmp))
        return -1;
    unlink(tmp);
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
    if (fd < 0)
        return -1;
    if (fchmod(fd, mode) == 0 && write_all(fd, data, len) == 0 && fsync_retry(fd) == 0 &&
        close(fd) == 0) {
        fd = -1;
        if (rename(tmp, path) == 0 && fsync_parent(path) == 0)
            rc = 0;
    }
    if (fd >= 0)
        close(fd);
    if (rc != 0)
        unlink(tmp);
    return rc;
}

static int copy_atomic(const char *src, const char *dst)
{
    char *buf = NULL;
    size_t len = 0;
    int rc;

    if (read_regular(src, &buf, &len, RESTORE_DB_MAX) != 0)
        return -1;
    rc = write_atomic(dst, buf, len, 0600);
    free(buf);
    return rc;
}

static const char *json_value(const char *json, const char *field)
{
    static char pattern[128];
    const char *p;

    if (!json || !field || strlen(field) > 96)
        return NULL;
    snprintf(pattern, sizeof(pattern), "\"%s\"", field);
    p = strstr(json, pattern);
    if (!p)
        return NULL;
    p += strlen(pattern);
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p++ != ':')
        return NULL;
    while (*p && isspace((unsigned char)*p)) p++;
    return p;
}

static int json_string(const char *json, const char *field, char *out, size_t out_len)
{
    const char *p = json_value(json, field);
    size_t used = 0;
    int escape = 0;

    if (!p || *p++ != '"' || !out || !out_len)
        return -1;
    while (*p) {
        char c = *p++;
        if (escape) {
            if (c == 'n') c = '\n';
            else if (c == 'r') c = '\r';
            else if (c == 't') c = '\t';
            escape = 0;
        } else if (c == '\\') {
            escape = 1;
            continue;
        } else if (c == '"') {
            out[used] = '\0';
            return 0;
        }
        if ((unsigned char)c < 0x20 || used + 1 >= out_len)
            return -1;
        out[used++] = c;
    }
    return -1;
}

static int json_i64(const char *json, const char *field, int64_t *out)
{
    const char *p = json_value(json, field);
    char *end = NULL;
    long long value;

    if (!p || !out)
        return -1;
    errno = 0;
    value = strtoll(p, &end, 10);
    if (errno || end == p)
        return -1;
    while (*end && isspace((unsigned char)*end)) end++;
    if (*end != ',' && *end != '}' && *end != '\0')
        return -1;
    *out = (int64_t)value;
    return 0;
}

static int safe_id(const char *id)
{
    size_t n = id ? strlen(id) : 0;

    if (!n || n >= 80)
        return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)id[i];
        if (!isalnum(c) && c != '_' && c != '-' && c != '.')
            return 0;
    }
    return 1;
}

static int sha256_file(const char *path, char out[65], uint64_t *size_out)
{
    unsigned char buf[16384];
    unsigned char digest[32];
    uint64_t total = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    int rc = -1;

    if (fd < 0)
        return -1;
#ifdef __APPLE__
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
#else
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
        if (total > RESTORE_DB_MAX) goto done;
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

static int sqlite_has_table(sqlite3 *db, const char *table)
{
    sqlite3_stmt *st = NULL;
    int found = 0;

    if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, table, -1, SQLITE_TRANSIENT);
        found = sqlite3_step(st) == SQLITE_ROW;
        sqlite3_finalize(st);
    }
    return found;
}

static int sqlite_open_immutable(const char *path, sqlite3 **db)
{
    char uri[1536];
    size_t used = 0;
    static const char hex[] = "0123456789ABCDEF";

    if (!path || !db || path[0] != '/')
        return SQLITE_MISUSE;
    memcpy(uri, "file:", 5);
    used = 5;
    for (const unsigned char *p = (const unsigned char *)path; *p; p++) {
        int literal = isalnum(*p) || *p == '/' || *p == '-' || *p == '_' || *p == '.' || *p == '~';

        if (used + (literal ? 1U : 3U) + sizeof("?mode=ro&immutable=1") >= sizeof(uri))
            return SQLITE_TOOBIG;
        if (literal) {
            uri[used++] = (char)*p;
        } else {
            uri[used++] = '%';
            uri[used++] = hex[*p >> 4];
            uri[used++] = hex[*p & 0x0f];
        }
    }
    memcpy(uri + used, "?mode=ro&immutable=1", sizeof("?mode=ro&immutable=1"));
    return sqlite3_open_v2(uri, db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL);
}

static int sqlite_validate(const char *path, struct dwrt_config_restore_info *out)
{
    static const char *required[] = {
        "network_meta", "wan", "lan", "network_global", "web_users",
        "system_ui_settings", "appearance_settings", "system_settings",
        "work_mode_settings"
    };
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (sqlite_open_immutable(path, &db) != SQLITE_OK) {
        rc = -2;
        goto done;
    }
    sqlite3_busy_timeout(db, 3000);
    if (sqlite3_prepare_v2(db, "PRAGMA quick_check", -1, &st, NULL) != SQLITE_OK) {
        rc = -3;
        goto done;
    }
    if (sqlite3_step(st) != SQLITE_ROW ||
        !sqlite3_column_text(st, 0) ||
        strcmp((const char *)sqlite3_column_text(st, 0), "ok")) {
        rc = -4;
        goto done;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(db, "PRAGMA application_id", -1, &st, NULL) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_ROW ||
        sqlite3_column_int(st, 0) != JMX_CONFIG_APPLICATION_ID) {
        rc = -5;
        goto done;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &st, NULL) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_ROW ||
        sqlite3_column_int(st, 0) < JMX_CONFIG_MIN_RESTORE_VERSION ||
        sqlite3_column_int(st, 0) > JMX_CONFIG_SCHEMA_VERSION) {
        rc = -6;
        goto done;
    }
    sqlite3_finalize(st);
    st = NULL;
    for (size_t i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
        if (!sqlite_has_table(db, required[i])) {
            rc = -10 - (int)i;
            goto done;
        }
    }
    if (sqlite3_prepare_v2(db,
            "SELECT value FROM network_meta WHERE key='schema_version' LIMIT 1",
            -1, &st, NULL) != SQLITE_OK || sqlite3_step(st) != SQLITE_ROW ||
        !sqlite3_column_text(st, 0) ||
        atoi((const char *)sqlite3_column_text(st, 0)) != JMX_CONFIG_SCHEMA_VERSION) {
        rc = -20;
        goto done;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT hostname FROM system_settings WHERE id=1",
            -1, &st, NULL) != SQLITE_OK || sqlite3_step(st) != SQLITE_ROW ||
        !sqlite3_column_text(st, 0) || !sqlite3_column_text(st, 0)[0] ||
        strlen((const char *)sqlite3_column_text(st, 0)) > 63) {
        rc = -21;
        goto done;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (out) {
        if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM wan", -1, &st, NULL) == SQLITE_OK &&
            sqlite3_step(st) == SQLITE_ROW)
            out->wan_count = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
        st = NULL;
        if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM lan", -1, &st, NULL) == SQLITE_OK &&
            sqlite3_step(st) == SQLITE_ROW)
            out->lan_count = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
        st = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT ip FROM lan_address WHERE lan_id='lan' ORDER BY is_primary DESC,sort_order LIMIT 1",
                -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW) {
            const char *ip = (const char *)sqlite3_column_text(st, 0);
            snprintf(out->expected_lan_ip, sizeof(out->expected_lan_ip), "%s", ip ? ip : "");
        }
    }
    rc = 0;
done:
    if (st) sqlite3_finalize(st);
    if (db) sqlite3_close(db);
    return rc;
}

static int sqlite_backup_file(const char *source, const char *dest, int source_immutable)
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
    if ((source_immutable ? sqlite_open_immutable(source, &src) :
         sqlite3_open_v2(source, &src, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK)
        goto done;
    sqlite3_busy_timeout(src, 5000);
    if (sqlite3_open_v2(tmp, &dst, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK)
        goto done;
    sqlite3_busy_timeout(dst, 5000);
    backup = sqlite3_backup_init(dst, "main", src, "main");
    if (!backup)
        goto done;
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
    if (sqlite3_close(dst) != SQLITE_OK) {
        dst = NULL;
        goto done;
    }
    dst = NULL;
    sqlite3_close(src);
    src = NULL;
    if (chmod(tmp, 0600) != 0)
        goto done;
    fd = open(tmp, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fsync_retry(fd) != 0) {
        if (fd >= 0) close(fd);
        goto done;
    }
    close(fd);
    if (sqlite_validate(tmp, NULL) != 0 || rename(tmp, dest) != 0 || fsync_parent(dest) != 0)
        goto done;
    rc = 0;
done:
    if (backup) sqlite3_backup_finish(backup);
    if (dst) sqlite3_close(dst);
    if (src) sqlite3_close(src);
    if (rc != 0) unlink(tmp);
    return rc;
}

static int state_write(const struct dwrt_config_restore_info *info)
{
    char json[1536];
    int n;

    if (!info || ensure_dir(DWRT_CONFIG_RESTORE_DIR, 0700) != 0)
        return -1;
    n = snprintf(json, sizeof(json),
        "{\"format\":\"%s\",\"phase\":\"%s\",\"operation_id\":\"%s\","
        "\"source_sha256\":\"%s\",\"size_bytes\":%llu,\"started_at\":%lld,"
        "\"deadline\":%lld,\"expected_lan_ip\":\"%s\",\"wan_count\":%d,"
        "\"lan_count\":%d,\"error\":\"%s\"}\n",
        DWRT_CONFIG_RESTORE_FORMAT, info->phase, info->operation_id,
        info->source_sha256, (unsigned long long)info->size_bytes,
        (long long)info->started_at, (long long)info->deadline,
        info->expected_lan_ip, info->wan_count, info->lan_count, info->error);
    if (n <= 0 || (size_t)n >= sizeof(json))
        return -1;
    return write_atomic(DWRT_CONFIG_RESTORE_STATE, json, (size_t)n, 0600);
}

static int state_read(struct dwrt_config_restore_info *out)
{
    char *json = NULL;
    size_t len = 0;
    int64_t value = 0;

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    if (read_regular(DWRT_CONFIG_RESTORE_STATE, &json, &len, RESTORE_MANIFEST_MAX) != 0) {
        snprintf(out->phase, sizeof(out->phase), "idle");
        return 0;
    }
    (void)len;
    if (json_string(json, "phase", out->phase, sizeof(out->phase)) != 0)
        snprintf(out->phase, sizeof(out->phase), "invalid_state");
    json_string(json, "operation_id", out->operation_id, sizeof(out->operation_id));
    json_string(json, "source_sha256", out->source_sha256, sizeof(out->source_sha256));
    json_string(json, "expected_lan_ip", out->expected_lan_ip, sizeof(out->expected_lan_ip));
    json_string(json, "error", out->error, sizeof(out->error));
    if (json_i64(json, "size_bytes", &value) == 0 && value >= 0) out->size_bytes = (uint64_t)value;
    if (json_i64(json, "started_at", &value) == 0) out->started_at = value;
    if (json_i64(json, "deadline", &value) == 0) out->deadline = value;
    if (json_i64(json, "wan_count", &value) == 0) out->wan_count = (int)value;
    if (json_i64(json, "lan_count", &value) == 0) out->lan_count = (int)value;
    free(json);
    out->pending = access(DWRT_CONFIG_RESTORE_PENDING, F_OK) == 0;
    out->backup_available = access(RESTORE_BACKUP_DB, R_OK) == 0;
    return 0;
}

static int staged_validate(struct dwrt_config_restore_info *out)
{
    char *manifest = NULL;
    size_t manifest_len = 0;
    char format[80] = "";
    char expected_hash[65] = "";
    char actual_hash[65] = "";
    char upload_id[96] = "";
    int64_t expected_size = 0;
    uint64_t actual_size = 0;
    struct stat st;

    if (!out)
        return -1;
    if (lstat(DWRT_CONFIG_RESTORE_DB, &st) != 0 || !S_ISREG(st.st_mode) || S_ISLNK(st.st_mode) ||
        st.st_size <= 0 || (uint64_t)st.st_size > RESTORE_DB_MAX) {
        restore_error(out, "staged_database_invalid");
        return -1;
    }
    if (read_regular(DWRT_CONFIG_RESTORE_MANIFEST, &manifest, &manifest_len,
                     RESTORE_MANIFEST_MAX) != 0) {
        restore_error(out, "manifest_unavailable");
        return -1;
    }
    (void)manifest_len;
    if (json_string(manifest, "format", format, sizeof(format)) != 0 ||
        strcmp(format, DWRT_CONFIG_RESTORE_FORMAT) ||
        json_string(manifest, "sha256", expected_hash, sizeof(expected_hash)) != 0 ||
        strlen(expected_hash) != 64 ||
        json_i64(manifest, "size_bytes", &expected_size) != 0 || expected_size <= 0 ||
        json_string(manifest, "upload_id", upload_id, sizeof(upload_id)) != 0 ||
        !safe_id(upload_id)) {
        free(manifest);
        restore_error(out, "manifest_contract_invalid");
        return -1;
    }
    free(manifest);
    if (sha256_file(DWRT_CONFIG_RESTORE_DB, actual_hash, &actual_size) != 0 ||
        actual_size != (uint64_t)expected_size || strcasecmp(actual_hash, expected_hash)) {
        restore_error(out, "staged_database_hash_mismatch");
        return -1;
    }
    {
        int validate_rc = sqlite_validate(DWRT_CONFIG_RESTORE_DB, out);
        if (validate_rc != 0) {
            snprintf(out->error, sizeof(out->error),
                     "staged_database_schema_or_integrity_invalid:%d", validate_rc);
            return -1;
        }
    }
    snprintf(out->operation_id, sizeof(out->operation_id), "%s", upload_id);
    snprintf(out->source_sha256, sizeof(out->source_sha256), "%s", actual_hash);
    out->size_bytes = actual_size;
    return 0;
}

static int snapshot_current(struct dwrt_config_restore_info *out)
{
    char hostname[256];
    size_t hostname_len;

    if (gethostname(hostname, sizeof(hostname) - 1) != 0) {
        restore_error(out, "runtime_hostname_snapshot_failed");
        return -1;
    }
    hostname[sizeof(hostname) - 1] = '\0';
    hostname_len = strlen(hostname);
    if (ensure_dir(DWRT_CONFIG_RESTORE_BACKUP_DIR, 0700) != 0 ||
        sqlite_backup_file(DWRT_CONFIG_DB, RESTORE_BACKUP_DB, 0) != 0 ||
        copy_atomic(DWRT_NETWORK_CONFIG, RESTORE_BACKUP_NETWORK) != 0 ||
        copy_atomic(DWRT_DHCP_CONFIG, RESTORE_BACKUP_DHCP) != 0 ||
        copy_atomic(DWRT_FIREWALL_CONFIG, RESTORE_BACKUP_FIREWALL) != 0 ||
        copy_atomic(DWRT_SYSTEM_CONFIG, RESTORE_BACKUP_SYSTEM) != 0 ||
        write_atomic(RESTORE_BACKUP_RUNTIME_HOSTNAME, hostname, hostname_len, 0600) != 0) {
        restore_error(out, "target_snapshot_failed");
        return -1;
    }
    return 0;
}

static int replace_config_db(const char *source)
{
    if (sqlite_backup_file(source, DWRT_CONFIG_DB, 1) != 0)
        return -1;
    unlink(DWRT_CONFIG_DB "-wal");
    unlink(DWRT_CONFIG_DB "-shm");
    return fsync_parent(DWRT_CONFIG_DB);
}

static const char *find_program(const char *const *paths)
{
    for (size_t i = 0; paths[i]; i++)
        if (access(paths[i], X_OK) == 0)
            return paths[i];
    return NULL;
}

static int run_argv(const char *path, char *const argv[])
{
    pid_t pid = fork();
    int status;

    if (pid < 0)
        return -1;
    if (pid == 0) {
        int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (fd >= 0) {
            dup2(fd, STDIN_FILENO);
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            if (fd > STDERR_FILENO) close(fd);
        }
        execv(path, argv);
        _exit(127);
    }
    do {
        if (waitpid(pid, &status, 0) >= 0)
            break;
    } while (errno == EINTR);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

#ifndef DWRT_CONFIG_RESTORE_SKIP_NETWORK_APPLY
static int ubus_call(const char *object, const char *method, const char *payload)
{
    static const char *const paths[] = { "/bin/ubus", "/sbin/ubus", "/usr/bin/ubus", NULL };
    const char *bin = find_program(paths);
    char *argv[] = { (char *)bin, "call", (char *)object, (char *)method,
                     (char *)(payload ? payload : "{}"), NULL };

    return bin ? run_argv(bin, argv) : -1;
}

static int apply_table_ids(sqlite3 *db, const char *table, const char *method)
{
    char sql[128];
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (snprintf(sql, sizeof(sql), "SELECT id FROM %s WHERE enabled=1 ORDER BY id", table) >=
        (int)sizeof(sql) || sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    rc = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *id = (const char *)sqlite3_column_text(st, 0);
        char payload[160];

        if (!safe_id(id) || snprintf(payload, sizeof(payload), "{\"id\":\"%s\"}", id) >=
            (int)sizeof(payload) || ubus_call("dreamingwrt", method, payload) != 0) {
            rc = -1;
            break;
        }
    }
    sqlite3_finalize(st);
    return rc;
}

static int expected_hostname(sqlite3 *db, char *out, size_t out_len)
{
    sqlite3_stmt *st = NULL;
    const char *value;

    if (!db || !out || out_len == 0)
        return -1;
    out[0] = '\0';
    if (sqlite3_prepare_v2(db, "SELECT hostname FROM system_settings WHERE id=1",
                           -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_step(st) != SQLITE_ROW) {
        sqlite3_finalize(st);
        return -1;
    }
    value = (const char *)sqlite3_column_text(st, 0);
    if (!value || !value[0] || strlen(value) > 63) {
        sqlite3_finalize(st);
        return -1;
    }
    snprintf(out, out_len, "%s", value);
    sqlite3_finalize(st);
    return 0;
}

static int hostname_materialized(const char *expected)
{
    char runtime[128];
    char *system_config = NULL;
    size_t system_config_len = 0;
    char needle[192];
    int matched = 0;

    if (!expected || gethostname(runtime, sizeof(runtime) - 1) != 0)
        return 0;
    runtime[sizeof(runtime) - 1] = '\0';
    if (strcmp(runtime, expected) != 0 ||
        read_regular(DWRT_SYSTEM_CONFIG, &system_config, &system_config_len,
                     4U * 1024U * 1024U) != 0)
        goto done;
    snprintf(needle, sizeof(needle), "option hostname '%s'", expected);
    matched = strstr(system_config, needle) != NULL;
    if (!matched) {
        snprintf(needle, sizeof(needle), "option hostname %s", expected);
        matched = strstr(system_config, needle) != NULL;
    }
done:
    free(system_config);
    return matched;
}
#endif

static int network_materialize(const struct dwrt_config_restore_hooks *hooks,
                               struct dwrt_config_restore_info *out)
{
#ifdef DWRT_CONFIG_RESTORE_SKIP_NETWORK_APPLY
    (void)hooks;
    (void)out;
    return 0;
#else
    sqlite3 *db = NULL;
    char *network = NULL;
    size_t network_len = 0;
    char hostname[128] = "";
    int rc = -1;

    if (!hooks || !hooks->start_core || hooks->start_core(hooks->opaque) != 0) {
        restore_error(out, "core_start_failed");
        return -1;
    }
    for (int i = 0; i < 30; i++) {
        if (ubus_call("dreamingwrt", "network_global_get", "{}") == 0)
            break;
        sleep(1);
        if (i == 29) {
            restore_error(out, "core_ubus_unavailable");
            return -1;
        }
    }
    if (sqlite3_open_v2(DWRT_CONFIG_DB, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        goto done;
    if (expected_hostname(db, hostname, sizeof(hostname)) != 0)
        goto done;
    if (apply_table_ids(db, "wan", "wan_apply") != 0 ||
        apply_table_ids(db, "lan", "lan_apply") != 0 ||
        ubus_call("dreamingwrt", "dreamingwrt_system_settings_apply", "{}") != 0)
        goto done;
    if (!hostname_materialized(hostname))
        goto done;
    if (out->expected_lan_ip[0]) {
        if (read_regular(DWRT_NETWORK_CONFIG, &network, &network_len, 4U * 1024U * 1024U) != 0 ||
            !strstr(network, out->expected_lan_ip))
            goto done;
    }
    rc = 0;
done:
    free(network);
    if (db) sqlite3_close(db);
    if (rc != 0)
        restore_error(out, "network_materialize_or_readback_failed");
    return rc;
#endif
}

static int restore_previous(const struct dwrt_config_restore_hooks *hooks,
                            struct dwrt_config_restore_info *out)
{
    static const char *const init_paths[] = { "/etc/init.d/network", NULL };
    const char *network_init = find_program(init_paths);
    char *argv[] = { (char *)network_init, "restart", NULL };
    char *runtime_hostname = NULL;
    size_t runtime_hostname_len = 0;
    int rc = 0;

    if (!hooks || !hooks->stop_all || !hooks->start_all)
        return -1;
    hooks->stop_all(hooks->opaque);
    if (replace_config_db(RESTORE_BACKUP_DB) != 0 ||
        copy_atomic(RESTORE_BACKUP_NETWORK, DWRT_NETWORK_CONFIG) != 0 ||
        copy_atomic(RESTORE_BACKUP_DHCP, DWRT_DHCP_CONFIG) != 0 ||
        copy_atomic(RESTORE_BACKUP_FIREWALL, DWRT_FIREWALL_CONFIG) != 0 ||
        copy_atomic(RESTORE_BACKUP_SYSTEM, DWRT_SYSTEM_CONFIG) != 0 ||
        read_regular(RESTORE_BACKUP_RUNTIME_HOSTNAME, &runtime_hostname,
                     &runtime_hostname_len, 256) != 0)
        rc = -1;
    if (rc == 0) {
        while (runtime_hostname_len > 0 &&
               (runtime_hostname[runtime_hostname_len - 1] == '\n' ||
                runtime_hostname[runtime_hostname_len - 1] == '\r'))
            runtime_hostname[--runtime_hostname_len] = '\0';
        if (runtime_hostname_len == 0 || runtime_hostname_len > 63)
            rc = -1;
#ifndef DWRT_CONFIG_RESTORE_SKIP_RUNTIME_HOSTNAME
        else if (sethostname(runtime_hostname, runtime_hostname_len) != 0)
            rc = -1;
#endif
    }
    if (rc == 0 && network_init && run_argv(network_init, argv) != 0)
        rc = -1;
    hooks->start_all(hooks->opaque);
    free(runtime_hostname);
    if (rc != 0)
        restore_error(out, "rollback_restore_failed");
    return rc;
}

int dwrt_config_restore_status(struct dwrt_config_restore_info *out)
{
    return state_read(out);
}

int dwrt_config_restore_is_armed(void)
{
    struct dwrt_config_restore_info info;

    state_read(&info);
    return info.pending && !strcmp(info.phase, "armed");
}

int dwrt_config_restore_arm(struct dwrt_config_restore_info *out)
{
    struct dwrt_config_restore_info current;
    char marker[256];
    int n;

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    state_read(&current);
    if (current.pending && (!strcmp(current.phase, "armed") ||
                            !strcmp(current.phase, "pending_confirmation"))) {
        *out = current;
        restore_error(out, "restore_already_pending");
        return -1;
    }
    if (staged_validate(out) != 0)
        return -1;
    snprintf(out->phase, sizeof(out->phase), "armed");
    out->started_at = (int64_t)time(NULL);
    out->pending = 1;
    n = snprintf(marker, sizeof(marker),
                 "{\"operation_id\":\"%s\",\"armed_at\":%lld}\n",
                 out->operation_id, (long long)out->started_at);
    if (n <= 0 || (size_t)n >= sizeof(marker) ||
        write_atomic(DWRT_CONFIG_RESTORE_PENDING, marker, (size_t)n, 0600) != 0 ||
        state_write(out) != 0) {
        restore_error(out, "restore_arm_commit_failed");
        unlink(DWRT_CONFIG_RESTORE_PENDING);
        return -1;
    }
    return 0;
}

int dwrt_config_restore_apply(const struct dwrt_config_restore_hooks *hooks,
                              struct dwrt_config_restore_info *out)
{
    struct dwrt_config_restore_info armed;
    int replaced = 0;

    if (!out || !hooks || !hooks->stop_all || !hooks->start_all)
        return -1;
    state_read(&armed);
    *out = armed;
    if (!armed.pending || strcmp(armed.phase, "armed")) {
        restore_error(out, "restore_not_armed");
        return -1;
    }
    if (staged_validate(out) != 0 || strcmp(out->operation_id, armed.operation_id))
        return -1;
    snprintf(out->phase, sizeof(out->phase), "applying");
    out->error[0] = '\0';
    state_write(out);
    hooks->stop_all(hooks->opaque);
    if (snapshot_current(out) != 0)
        goto fail;
    out->backup_available = 1;
    if (replace_config_db(DWRT_CONFIG_RESTORE_DB) != 0) {
        restore_error(out, "database_replace_failed");
        goto fail;
    }
    replaced = 1;
    if (network_materialize(hooks, out) != 0)
        goto fail;
    hooks->start_all(hooks->opaque);
    snprintf(out->phase, sizeof(out->phase), "pending_confirmation");
    out->started_at = (int64_t)time(NULL);
    out->deadline = out->started_at + DWRT_CONFIG_RESTORE_CONFIRM_SECONDS;
    out->pending = 1;
    out->error[0] = '\0';
    if (state_write(out) != 0)
        goto fail_after_start;
    return 0;

fail_after_start:
    hooks->stop_all(hooks->opaque);
fail:
    if (replaced && out->backup_available)
        (void)restore_previous(hooks, out);
    else
        hooks->start_all(hooks->opaque);
    snprintf(out->phase, sizeof(out->phase), "failed");
    out->deadline = 0;
    out->pending = 0;
    unlink(DWRT_CONFIG_RESTORE_PENDING);
    state_write(out);
    return -1;
}

int dwrt_config_restore_confirm(struct dwrt_config_restore_info *out)
{
    if (!out)
        return -1;
    state_read(out);
    if (!out->pending || strcmp(out->phase, "pending_confirmation")) {
        restore_error(out, "restore_not_pending_confirmation");
        return -1;
    }
    snprintf(out->phase, sizeof(out->phase), "confirmed");
    out->deadline = 0;
    out->pending = 0;
    out->error[0] = '\0';
    if (unlink(DWRT_CONFIG_RESTORE_PENDING) != 0 && errno != ENOENT)
        return -1;
    if (fsync_parent(DWRT_CONFIG_RESTORE_PENDING) != 0 || state_write(out) != 0)
        return -1;
    return 0;
}

int dwrt_config_restore_rollback(const struct dwrt_config_restore_hooks *hooks,
                                 const char *reason,
                                 struct dwrt_config_restore_info *out)
{
    if (!out)
        return -1;
    state_read(out);
    if (!out->backup_available) {
        restore_error(out, "restore_backup_unavailable");
        return -1;
    }
    if (restore_previous(hooks, out) != 0) {
        snprintf(out->phase, sizeof(out->phase), "rollback_failed");
        state_write(out);
        return -1;
    }
    snprintf(out->phase, sizeof(out->phase), "rolled_back");
    snprintf(out->error, sizeof(out->error), "%s", reason ? reason : "manual_rollback");
    out->deadline = 0;
    out->pending = 0;
    unlink(DWRT_CONFIG_RESTORE_PENDING);
    fsync_parent(DWRT_CONFIG_RESTORE_PENDING);
    state_write(out);
    return 0;
}

int dwrt_config_restore_maybe_rollback(const struct dwrt_config_restore_hooks *hooks,
                                       int64_t now,
                                       struct dwrt_config_restore_info *out)
{
    struct dwrt_config_restore_info info;

    state_read(&info);
    if (out) *out = info;
    if (!info.pending || strcmp(info.phase, "pending_confirmation") ||
        info.deadline <= 0 || now < info.deadline)
        return 0;
    return dwrt_config_restore_rollback(hooks, "confirmation_timeout", out ? out : &info) == 0 ? 1 : -1;
}

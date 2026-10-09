// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE

#include "../dw_business_event.h"
#include "storage_migration.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static jmx_storage_consumer_reopen_fn g_reopen_hook;
static void *g_reopen_arg;
static jmx_storage_consumer_freeze_fn g_freeze_hook;
static jmx_storage_consumer_unfreeze_fn g_unfreeze_hook;
static void *g_freeze_arg;
static pthread_mutex_t g_migration_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_current_provider[128];

static void add_string(struct json_object *o, const char *key, const char *value)
{
    json_object_object_add(o, key, json_object_new_string(value ? value : ""));
}

static const char *request_string(struct json_object *o, const char *key)
{
    struct json_object *value = NULL;

    if (!o || !json_object_object_get_ex(o, key, &value) || !value)
        return "";
    return json_object_get_string(value);
}

static int request_bool(struct json_object *o, const char *key, int fallback)
{
    struct json_object *value = NULL;

    if (!o || !json_object_object_get_ex(o, key, &value) || !value)
        return fallback;
    return json_object_get_boolean(value) ? 1 : 0;
}

static int valid_use(const char *use)
{
    return use && (!strcmp(use, "audit") || !strcmp(use, "aegis") ||
                   !strcmp(use, "log") || !strcmp(use, "snapshots"));
}

static int safe_path(const char *path)
{
    return path && path[0] == '/' && strlen(path) < PATH_MAX &&
           !strstr(path, "/../") && strcmp(path + (strlen(path) >= 3 ? strlen(path) - 3 : 0), "/..") != 0;
}

static int parent_dir(const char *path, char *out, size_t out_len)
{
    const char *slash;
    size_t len;

    if (!path || !out || !out_len)
        return -1;
    slash = strrchr(path, '/');
    if (!slash)
        return -1;
    len = slash == path ? 1 : (size_t)(slash - path);
    if (len >= out_len)
        return -1;
    memcpy(out, path, len);
    out[len] = '\0';
    return 0;
}

static int ensure_dir(const char *path, mode_t mode)
{
    struct stat st;

    if (!path || !path[0])
        return -1;
    if (mkdir(path, mode) == 0)
        return 0;
    if (errno != EEXIST || stat(path, &st) != 0 || !S_ISDIR(st.st_mode))
        return -1;
    return 0;
}

static int ensure_parent(const char *path)
{
    char parent[PATH_MAX];
    char current[PATH_MAX];
    char *cursor;

    if (parent_dir(path, parent, sizeof(parent)) != 0)
        return -1;
    if (!strcmp(parent, "/"))
        return 0;
    if (snprintf(current, sizeof(current), "%s", parent) >= (int)sizeof(current))
        return -1;
    cursor = current + 1;
    while (1) {
        char saved;
        char *slash = strchr(cursor, '/');

        if (slash)
            saved = *slash, *slash = '\0';
        if (ensure_dir(current, 0750) != 0)
            return -1;
        if (!slash)
            break;
        *slash = saved;
        cursor = slash + 1;
    }
    return 0;
}

static int fsync_path(const char *path)
{
    int fd;
    int rc;

    fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    rc = fsync(fd);
    close(fd);
    return rc;
}

static int fsync_parent_path(const char *path)
{
    char parent[PATH_MAX];

    if (parent_dir(path, parent, sizeof(parent)) != 0)
        return -1;
    return fsync_path(parent);
}

static int copy_file(const char *src, const char *dst, mode_t mode,
                     uint64_t *bytes)
{
    int in = -1, out = -1;
    unsigned char buf[65536];
    ssize_t n;
    int rc = -1;

    in = open(src, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (in < 0)
        goto done;
    if (ensure_parent(dst) != 0)
        goto done;
    out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
               mode & 0777);
    if (out < 0)
        goto done;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        ssize_t written = 0;
        while (written < n) {
            ssize_t step = write(out, buf + written, (size_t)(n - written));
            if (step <= 0)
                goto done;
            written += step;
        }
        if (bytes)
            *bytes += (uint64_t)n;
    }
    if (n < 0 || fsync(out) != 0)
        goto done;
    if (fchmod(out, mode & 0777) != 0)
        goto done;
    rc = 0;
done:
    if (out >= 0)
        close(out);
    if (in >= 0)
        close(in);
    return rc;
}

static int copy_tree(const char *src, const char *dst, uint64_t *bytes)
{
    struct stat st;
    DIR *dir;
    struct dirent *entry;

    if (lstat(src, &st) != 0)
        return -1;
    if (S_ISLNK(st.st_mode))
        return -1;
    if (S_ISREG(st.st_mode))
        return copy_file(src, dst, st.st_mode, bytes);
    if (!S_ISDIR(st.st_mode))
        return -1;
    if (ensure_dir(dst, st.st_mode & 0777) != 0)
        return -1;
    dir = opendir(src);
    if (!dir)
        return -1;
    while ((entry = readdir(dir)) != NULL) {
        char child_src[PATH_MAX], child_dst[PATH_MAX];

        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        if (snprintf(child_src, sizeof(child_src), "%s/%s", src,
                     entry->d_name) >= (int)sizeof(child_src) ||
            snprintf(child_dst, sizeof(child_dst), "%s/%s", dst,
                     entry->d_name) >= (int)sizeof(child_dst) ||
            copy_tree(child_src, child_dst, bytes) != 0) {
            closedir(dir);
            return -1;
        }
    }
    closedir(dir);
    return fsync_path(dst);
}

static int sqlite_file(const char *path)
{
    unsigned char header[16];
    FILE *fp;
    int result;

    fp = fopen(path, "rb");
    if (!fp)
        return 0;
    result = fread(header, 1, sizeof(header), fp) == sizeof(header) &&
             !memcmp(header, "SQLite format 3\0", sizeof(header));
    fclose(fp);
    return result;
}

static int sqlite_removed_sidecar(const char *path)
{
    char database[PATH_MAX];
    size_t n = strlen(path);

    /* Checkpoint/close may unlink WAL and SHM while readdir still holds their
     * entries. Only tolerate these entries when the SQLite database remains. */
    if (n <= 4 || n >= sizeof(database) ||
        (strcmp(path + n - 4, "-wal") && strcmp(path + n - 4, "-shm")))
        return 0;
    memcpy(database, path, n - 4);
    database[n - 4] = '\0';
    return sqlite_file(database);
}

static int sqlite_checkpoint_one(const char *path)
{
    sqlite3 *db = NULL;
    int log_frames = 0, checkpointed = 0;
    int rc;
    int fd;

    if (!sqlite_file(path))
        return 0;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    /* Attach the pager before checkpointing; an unopened pager reports a
     * successful no-op even when committed rows still live only in WAL. */
    rc = sqlite3_exec(db, "PRAGMA schema_version", NULL, NULL, NULL);
    if (rc == SQLITE_OK)
        rc = sqlite3_wal_checkpoint_v2(db, NULL, SQLITE_CHECKPOINT_TRUNCATE,
                                   &log_frames, &checkpointed);
    sqlite3_close(db);
    if (rc != SQLITE_OK)
        return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fsync(fd) != 0) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int sqlite_checkpoint_tree(const char *path)
{
    struct stat st;
    DIR *dir;
    struct dirent *entry;

    if (lstat(path, &st) != 0)
        return errno == ENOENT && sqlite_removed_sidecar(path) ? 0 : -1;
    if (S_ISREG(st.st_mode))
        return sqlite_checkpoint_one(path);
    if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode))
        return -1;
    dir = opendir(path);
    if (!dir)
        return -1;
    while ((entry = readdir(dir)) != NULL) {
        char child[PATH_MAX];

        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        if (snprintf(child, sizeof(child), "%s/%s", path, entry->d_name) >=
                (int)sizeof(child)) {
            closedir(dir);
            return -1;
        }
        if (sqlite_checkpoint_tree(child) != 0) {
            closedir(dir);
            return -1;
        }
    }
    closedir(dir);
    return 0;
}

static int remove_tree(const char *path)
{
    struct stat st;
    DIR *dir;
    struct dirent *entry;

    if (lstat(path, &st) != 0)
        return errno == ENOENT ? 0 : -1;
    if (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode))
        return unlink(path);
    if (!S_ISDIR(st.st_mode))
        return -1;
    dir = opendir(path);
    if (!dir)
        return -1;
    while ((entry = readdir(dir)) != NULL) {
        char child[PATH_MAX];

        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        if (snprintf(child, sizeof(child), "%s/%s", path, entry->d_name) >=
                (int)sizeof(child) || remove_tree(child) != 0) {
            closedir(dir);
            return -1;
        }
    }
    closedir(dir);
    return rmdir(path);
}

static int tree_bytes(const char *path, uint64_t *bytes)
{
    struct stat st;
    DIR *dir;
    struct dirent *entry;

    if (lstat(path, &st) != 0)
        return -1;
    if (S_ISREG(st.st_mode)) {
        *bytes += (uint64_t)st.st_size;
        return 0;
    }
    if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode))
        return -1;
    dir = opendir(path);
    if (!dir)
        return -1;
    while ((entry = readdir(dir)) != NULL) {
        char child[PATH_MAX];

        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        if (snprintf(child, sizeof(child), "%s/%s", path, entry->d_name) >=
                (int)sizeof(child) || tree_bytes(child, bytes) != 0) {
            closedir(dir);
            return -1;
        }
    }
    closedir(dir);
    return 0;
}

static int sha256_file(const char *path, char out[65])
{
    EVP_MD_CTX *ctx = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned char buf[65536];
    unsigned int digest_len = 0, i;
    FILE *fp = NULL;
    size_t n;
    int rc = -1;

    out[0] = '\0';
    fp = fopen(path, "rb");
    ctx = EVP_MD_CTX_new();
    if (!fp || !ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
        goto done;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
        if (EVP_DigestUpdate(ctx, buf, n) != 1)
            goto done;
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

static int digest_update(EVP_MD_CTX *ctx, const void *data, size_t len)
{
    return EVP_DigestUpdate(ctx, data, len) == 1 ? 0 : -1;
}

static int compare_names(const void *left, const void *right)
{
    const char *const *a = left;
    const char *const *b = right;

    return strcmp(*a, *b);
}

static int digest_tree(EVP_MD_CTX *ctx, const char *root, const char *relative)
{
    char path[PATH_MAX];
    struct stat st;

    if (snprintf(path, sizeof(path), "%s%s%s", root,
                 relative[0] ? "/" : "", relative) >= (int)sizeof(path) ||
        lstat(path, &st) != 0)
        return -1;
    if (S_ISREG(st.st_mode)) {
        unsigned char buf[65536];
        FILE *fp = fopen(path, "rb");
        size_t n;
        const char kind = 'F';

        if (!fp || digest_update(ctx, &kind, 1) != 0 ||
            digest_update(ctx, relative, strlen(relative) + 1) != 0) {
            if (fp)
                fclose(fp);
            return -1;
        }
        while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
            if (digest_update(ctx, buf, n) != 0) {
                fclose(fp);
                return -1;
            }
        if (ferror(fp)) {
            fclose(fp);
            return -1;
        }
        fclose(fp);
        return 0;
    }
    if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode))
        return -1;
    {
        DIR *dir = opendir(path);
        struct dirent *entry;
        char **names = NULL;
        size_t count = 0, capacity = 0, i;
        const char kind = 'D';

        if (!dir || digest_update(ctx, &kind, 1) != 0 ||
            digest_update(ctx, relative, strlen(relative) + 1) != 0) {
            if (dir)
                closedir(dir);
            return -1;
        }
        while ((entry = readdir(dir)) != NULL) {
            char *name;

            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
                continue;
            if (count == capacity) {
                size_t next = capacity ? capacity * 2 : 16;
                char **grown = realloc(names, next * sizeof(*names));
                if (!grown) {
                    closedir(dir);
                    for (i = 0; i < count; i++)
                        free(names[i]);
                    free(names);
                    return -1;
                }
                names = grown;
                capacity = next;
            }
            name = strdup(entry->d_name);
            if (!name) {
                closedir(dir);
                for (i = 0; i < count; i++)
                    free(names[i]);
                free(names);
                return -1;
            }
            names[count++] = name;
        }
        closedir(dir);
        qsort(names, count, sizeof(*names), compare_names);
        for (i = 0; i < count; i++) {
            char child[PATH_MAX];
            if (snprintf(child, sizeof(child), "%s%s%s", relative,
                         relative[0] ? "/" : "", names[i]) >= (int)sizeof(child) ||
                digest_tree(ctx, root, child) != 0) {
                size_t j;
                for (j = 0; j < count; j++)
                    free(names[j]);
                free(names);
                return -1;
            }
        }
        for (i = 0; i < count; i++)
            free(names[i]);
        free(names);
    }
    return 0;
}

static int sha256_tree(const char *path, char out[65])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0, i;
    struct stat st;
    int rc = -1;

    out[0] = '\0';
    if (!ctx || lstat(path, &st) != 0 ||
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        digest_tree(ctx, path, "") != 0 ||
        EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1 || digest_len != 32)
        goto done;
    for (i = 0; i < digest_len; i++)
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    out[64] = '\0';
    rc = 0;
done:
    EVP_MD_CTX_free(ctx);
    return rc;
}

static int sqlite_integrity_mode(const char *path, int writable)
{
    unsigned char header[16];
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    FILE *fp;
    int rc = 0;

    fp = fopen(path, "rb");
    if (!fp)
        return -1;
    if (fread(header, 1, sizeof(header), fp) != sizeof(header) ||
        memcmp(header, "SQLite format 3\0", 16)) {
        fclose(fp);
        return 0;
    }
    fclose(fp);
    if (sqlite3_open_v2(path, &db, writable ? SQLITE_OPEN_READWRITE : SQLITE_OPEN_READONLY,
                        NULL) != SQLITE_OK) {
        fprintf(stderr, "storage: integrity open failed: %s (%s)\n",
                path, db ? sqlite3_errmsg(db) : "no handle");
        sqlite3_close(db);
        return -1;
    }
    if (sqlite3_prepare_v2(db, "PRAGMA quick_check", -1, &st, NULL) != SQLITE_OK ||
        sqlite3_step(st) != SQLITE_ROW ||
        strcmp((const char *)sqlite3_column_text(st, 0), "ok"))
        rc = -1;
    if (rc != 0)
        fprintf(stderr, "storage: integrity check failed: %s (%s)\n",
                path, sqlite3_errmsg(db));
    sqlite3_finalize(st);
    sqlite3_close(db);
    return rc;
}

static int sqlite_integrity(const char *path)
{
    return sqlite_integrity_mode(path, 0);
}

static int write_manifest(const char *manifest, const char *use,
                          const char *provider, const char *old_path,
                          const char *new_path, const char *snapshot,
                          uint64_t bytes, const char *sha)
{
    FILE *fp;
    struct json_object *o = json_object_new_object();
    const char *serialized;

    if (!o)
        return -1;
    json_object_object_add(o, "manifest_version", json_object_new_int(1));
    json_object_object_add(o, "contract", json_object_new_string(JMX_STORAGE_MIGRATION_CONTRACT));
    json_object_object_add(o, "use", json_object_new_string(use ? use : ""));
    json_object_object_add(o, "provider_id", json_object_new_string(provider ? provider : ""));
    json_object_object_add(o, "old_path", json_object_new_string(old_path ? old_path : ""));
    json_object_object_add(o, "new_path", json_object_new_string(new_path ? new_path : ""));
    json_object_object_add(o, "snapshot_id", json_object_new_string(snapshot ? snapshot : ""));
    json_object_object_add(o, "bytes", json_object_new_int64((int64_t)bytes));
    json_object_object_add(o, "sha256", json_object_new_string(sha ? sha : ""));
    json_object_object_add(o, "checksum_scope",
                           json_object_new_string("payload_tree"));
    json_object_object_add(o, "rollback_command", json_object_new_string("restore snapshot_id"));
    serialized = json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN);
    fp = fopen(manifest, "we");
    if (!fp) {
        json_object_put(o);
        return -1;
    }
    if (fprintf(fp, "%s\n", serialized ? serialized : "{}") < 0 ||
        fflush(fp) != 0 || fsync(fileno(fp)) != 0 || fclose(fp) != 0) {
        json_object_put(o);
        return -1;
    }
    json_object_put(o);
    return fsync_parent_path(manifest);
}

static struct json_object *migration_result(int success, const char *use,
                                            const char *provider,
                                            const char *phase,
                                            const char *reason,
                                            const char *old_path,
                                            const char *new_path,
                                            const char *snapshot,
                                            int rollback_available)
{
    struct json_object *o = json_object_new_object();

    add_string(o, "contract_version", JMX_STORAGE_MIGRATION_CONTRACT);
    add_string(o, "use", use);
    add_string(o, "requested_provider", provider);
    add_string(o, "active_provider", success ? provider : "local");
    add_string(o, "phase", phase);
    add_string(o, "reason", reason);
    add_string(o, "old_path", old_path);
    add_string(o, "new_path", new_path);
    add_string(o, "snapshot_id", snapshot);
    json_object_object_add(o, "rollback_available",
                           json_object_new_boolean(rollback_available));
    json_object_object_add(o, "ok", json_object_new_boolean(success));
    add_string(o, "active_path", success ? new_path : old_path);
    return o;
}

/* Only the execution path uses this wrapper. Preflight and dry-run responses
 * are not migration completions, even when their validation succeeds. */
static struct json_object *migration_finished_result(int success, const char *use,
                                                     const char *provider,
                                                     const char *phase,
                                                     const char *reason,
                                                     const char *old_path,
                                                     const char *new_path,
                                                     const char *snapshot,
                                                     int rollback_available)
{
    struct json_object *o = migration_result(success, use, provider, phase, reason,
                                            old_path, new_path, snapshot,
                                            rollback_available);
    struct json_object *detail = json_object_new_object();
    add_string(detail, "object_id", provider);
    add_string(detail, "provider", provider);
    add_string(detail, "use", use);
    add_string(detail, "task_id", snapshot);
    add_string(detail, "action", "migrate");
    add_string(detail, "result", success ? "success" : "failed");
    if (!success) {
        add_string(detail, "failure_stage", phase);
        add_string(detail, "failure_reason", reason);
    }
    dw_business_event("storage", "STORAGE_MIGRATION_FINISHED", detail);
    json_object_put(detail);
    return o;
}

/* All paths after the consumer freeze must release it before returning.  Keep
 * that error visible: a failed unfreeze leaves the writer stopped and is more
 * important to operators than the earlier copy/rename error. */
static struct json_object *migration_abort(const char *use, const char *provider,
                                           const char *phase, const char *reason,
                                           const char *old_path, const char *new_path,
                                           const char *snapshot, int rollback_available,
                                           int frozen, int *locked)
{
    int unfreeze_rc = frozen && g_unfreeze_hook ?
        g_unfreeze_hook(use, g_freeze_arg) : 0;

    if (locked && *locked) {
        *locked = 0;
        pthread_mutex_unlock(&g_migration_lock);
    }
    if (frozen && unfreeze_rc != 0)
        {
            g_current_provider[0] = '\0';
            return migration_finished_result(0, use, provider, "unfreeze",
                                "consumer_unfreeze_failed", old_path, new_path,
                                snapshot, rollback_available);
        }
    g_current_provider[0] = '\0';
    return migration_finished_result(0, use, provider, phase, reason,
                            old_path, new_path, snapshot, rollback_available);
}

void jmx_storage_migration_set_consumer_reopen_hook(
    jmx_storage_consumer_reopen_fn hook, void *arg)
{
    g_reopen_hook = hook;
    g_reopen_arg = arg;
}

void jmx_storage_migration_set_consumer_freeze_hooks(
    jmx_storage_consumer_freeze_fn freeze_hook,
    jmx_storage_consumer_unfreeze_fn unfreeze_hook, void *arg)
{
    g_freeze_hook = freeze_hook;
    g_unfreeze_hook = unfreeze_hook;
    g_freeze_arg = arg;
}

const char *jmx_storage_migration_current_provider(void)
{
    return g_current_provider;
}

static int offline_integrity_tree(const char *path, int writable)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return errno == ENOENT && sqlite_removed_sidecar(path) ? 0 : -1;
    if (S_ISREG(st.st_mode)) {
        size_t n = strlen(path);
        if (n >= 3 && !strcmp(path + n - 3, ".db") && !sqlite_file(path))
            return -1;
        return sqlite_integrity_mode(path, writable);
    }
    if (!S_ISDIR(st.st_mode))
        return -1;
    DIR *dir = opendir(path);
    struct dirent *entry;
    int rc = 0;
    if (!dir)
        return -1;
    while ((entry = readdir(dir)) != NULL) {
        char child[PATH_MAX];
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        if (snprintf(child, sizeof(child), "%s/%s", path, entry->d_name) >=
            (int)sizeof(child) || offline_integrity_tree(child, writable) != 0) {
            rc = -1;
            break;
        }
    }
    closedir(dir);
    return rc;
}

int jmx_storage_migration_copy_offline(const char *old_path, const char *new_path,
                                      int is_dir, int allow_new,
                                      char *reason, size_t reason_len)
{
    struct stat st;
    char stage[PATH_MAX] = "", old_sha[65], new_sha[65];
    uint64_t bytes = 0, copied = 0;
    const char *failure = "invalid_request";
    int source_exists, staged = 0;

    if (!safe_path(old_path) || !safe_path(new_path) ||
        !strcmp(old_path, new_path))
        goto failed;
    if (lstat(new_path, &st) == 0 || errno != ENOENT) {
        failure = "target_exists_or_unavailable";
        goto failed;
    }
    source_exists = lstat(old_path, &st) == 0;
    if (!source_exists && (errno != ENOENT || !allow_new)) {
        failure = "source_unavailable";
        goto failed;
    }
    if (source_exists &&
        (is_dir ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode))) {
        failure = "source_type_mismatch";
        goto failed;
    }
    if (snprintf(stage, sizeof(stage), "%s.migration-%ld", new_path,
                 (long)getpid()) >= (int)sizeof(stage))
        goto failed;
    if (lstat(stage, &st) == 0 || errno != ENOENT) {
        failure = "staging_exists_or_unavailable";
        goto failed;
    }
    if (source_exists) {
        failure = "sqlite_checkpoint_or_integrity_failed";
        if ((!is_dir && !sqlite_file(old_path)) ||
            sqlite_checkpoint_tree(old_path) != 0 ||
            offline_integrity_tree(old_path, 0) != 0)
            goto failed;
        failure = "source_inventory_failed";
        staged = 1;
        if (tree_bytes(old_path, &bytes) != 0)
            goto failed;
        failure = "copy_size_mismatch";
        if (copy_tree(old_path, stage, &copied) != 0 || bytes != copied)
            goto failed;
        failure = "copy_checksum_mismatch";
        if (sha256_tree(old_path, old_sha) != 0 ||
            sha256_tree(stage, new_sha) != 0 || strcmp(old_sha, new_sha))
            goto failed;
        failure = "target_integrity_failed";
        if (offline_integrity_tree(stage, 1) != 0)
            goto failed;
    } else {
        int fd = -1;
        failure = "target_create_failed";
        if (is_dir) {
            if (mkdir(stage, 0750) != 0)
                goto failed;
            staged = 1;
            if (fsync_path(stage) != 0)
                goto failed;
        } else {
            fd = open(stage, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
            if (fd < 0)
                goto failed;
            staged = 1;
            int sync_rc = fsync(fd);
            int close_rc = close(fd);
            if (sync_rc != 0 || close_rc != 0)
                goto failed;
        }
    }
    failure = "target_commit_failed";
    if (rename(stage, new_path) != 0)
        goto failed;
    staged = 0;
    if (fsync_parent_path(new_path) != 0)
        goto failed;
    snprintf(reason, reason_len, "%s",
             source_exists ? "copied_verified_source_retained" : "initialized_new_dataset");
    return 0;
failed:
    if (staged)
        (void)remove_tree(stage);
    snprintf(reason, reason_len, "%s", failure);
    return -1;
}

struct json_object *jmx_storage_migration_apply(struct json_object *request)
{
    const char *use = request_string(request, "use");
    const char *provider = request_string(request, "provider_id");
    const char *old_path = request_string(request, "old_path");
    const char *new_path = request_string(request, "new_path");
    const char *snapshot = request_string(request, "snapshot_id");
    char stage[PATH_MAX], backup[PATH_MAX];
    char stage_manifest[PATH_MAX], new_manifest[PATH_MAX];
    char old_sha[65] = {0}, new_sha[65] = {0};
    struct stat old_st;
    uint64_t bytes = 0, copied = 0;
    int dry_run = request_bool(request, "dry_run", 0);
    int confirmed = request_bool(request, "confirm", 0);
    int old_moved = 0, stage_moved = 0;
    int old_is_dir;
    int sqlite_rc;
    int frozen = 0;
    int locked = 0;

    if (!valid_use(use) || !provider[0] || !safe_path(old_path) ||
        !safe_path(new_path) || !strcmp(old_path, new_path))
        return migration_result(0, use, provider, "preflight", "invalid_request",
                                old_path, new_path, snapshot, 0);
    if (lstat(old_path, &old_st) != 0 || S_ISLNK(old_st.st_mode) ||
        (!S_ISREG(old_st.st_mode) && !S_ISDIR(old_st.st_mode)))
        return migration_result(0, use, provider, "preflight", "old_path_unavailable",
                                old_path, new_path, snapshot, 0);
    if (tree_bytes(old_path, &bytes) != 0)
        return migration_result(0, use, provider, "preflight", "inventory_failed",
                                old_path, new_path, snapshot, 0);
    sqlite_rc = S_ISREG(old_st.st_mode) ? sqlite_integrity(old_path) : 0;
    if (sqlite_rc != 0)
        return migration_result(0, use, provider, "preflight", "sqlite_integrity_failed",
                                old_path, new_path, snapshot, 0);
    if (dry_run)
        return migration_result(1, use, provider, "preflight", "dry_run_ready",
                                old_path, new_path, snapshot, 0);
    if (!confirmed)
        return migration_result(0, use, provider, "preflight", "confirmation_required",
                                old_path, new_path, snapshot, 0);
    if (!g_reopen_hook)
        return migration_result(0, use, provider, "preflight",
                                "consumer_reopen_not_wired", old_path, new_path,
                                snapshot, 0);
    if (!g_freeze_hook || !g_unfreeze_hook)
        return migration_result(0, use, provider, "preflight",
                                "consumer_freeze_not_wired", old_path, new_path,
                                snapshot, 0);
    if (lstat(new_path, &old_st) == 0)
        return migration_result(0, use, provider, "preflight", "new_path_exists",
                                old_path, new_path, snapshot, 0);
    if (lstat(old_path, &old_st) != 0)
        return migration_result(0, use, provider, "preflight", "old_path_unavailable",
                                old_path, new_path, snapshot, 0);
    old_is_dir = S_ISDIR(old_st.st_mode);
    if (pthread_mutex_trylock(&g_migration_lock) != 0)
        return migration_result(0, use, provider, "preflight", "migration_in_progress",
                                old_path, new_path, snapshot, 0);
    locked = 1;
    snprintf(g_current_provider, sizeof(g_current_provider), "%s", provider);
    if (g_freeze_hook(use, g_freeze_arg) != 0)
        return migration_abort(use, provider, "freeze", "consumer_freeze_failed",
                               old_path, new_path, snapshot, 0, 0, &locked);
    frozen = 1;
    if (sqlite_checkpoint_tree(old_path) != 0) {
        return migration_abort(use, provider, "preflight", "sqlite_checkpoint_failed",
                               old_path, new_path, snapshot, 0, 1, &locked);
    }
    bytes = 0;
    if (tree_bytes(old_path, &bytes) != 0) {
        return migration_abort(use, provider, "preflight", "inventory_failed",
                               old_path, new_path, snapshot, 0, 1, &locked);
    }
    if (ensure_parent(new_path) != 0) {
        return migration_abort(use, provider, "preflight", "new_parent_unavailable",
                               old_path, new_path, snapshot, 0, 1, &locked);
    }
    if (snprintf(stage, sizeof(stage), "%s.migration-%ld", new_path,
                 (long)getpid()) >= (int)sizeof(stage) ||
        snprintf(backup, sizeof(backup), "%s.rollback-%s", old_path,
                 snapshot[0] ? snapshot : "pending") >= (int)sizeof(backup)) {
        return migration_abort(use, provider, "preflight", "path_too_long",
                               old_path, new_path, snapshot, 0, 1, &locked);
    }
    (void)remove_tree(stage);
    copied = 0;
    if (snprintf(stage_manifest, sizeof(stage_manifest), "%s%s",
                 stage, old_is_dir ? "/migration-manifest.json" : ".manifest.json") >=
            (int)sizeof(stage_manifest) ||
        snprintf(new_manifest, sizeof(new_manifest), "%s%s",
                 new_path, old_is_dir ? "/migration-manifest.json" : ".manifest.json") >=
            (int)sizeof(new_manifest) ||
        copy_tree(old_path, stage, &copied) != 0 || copied != bytes ||
        (copied = 0, tree_bytes(stage, &copied) != 0) || copied != bytes ||
        ((old_is_dir &&
          (sha256_tree(old_path, old_sha) != 0 ||
           sha256_tree(stage, new_sha) != 0 || strcmp(old_sha, new_sha))) ||
         (!old_is_dir &&
          (sha256_file(old_path, old_sha) != 0 ||
           sha256_file(stage, new_sha) != 0 || strcmp(old_sha, new_sha)))) ||
        write_manifest(stage_manifest, use, provider, old_path, new_path, snapshot,
                       bytes, old_sha) != 0) {
        (void)remove_tree(stage);
        return migration_abort(use, provider, "copy_verify", "copy_or_manifest_failed",
                               old_path, new_path, snapshot, 0, 1, &locked);
    }
    if (rename(old_path, backup) != 0) {
        (void)remove_tree(stage);
        return migration_abort(use, provider, "atomic_switch", "backup_rename_failed",
                               old_path, new_path, snapshot, 0, frozen, &locked);
    }
    old_moved = 1;
    if (rename(stage, new_path) != 0) {
        (void)rename(backup, old_path);
        (void)remove_tree(stage);
        return migration_abort(use, provider, "atomic_switch", "new_rename_failed",
                               old_path, new_path, snapshot, 1, 1, &locked);
    }
    stage_moved = 1;
    if (!old_is_dir && rename(stage_manifest, new_manifest) != 0) {
        (void)remove_tree(new_path);
        (void)rename(backup, old_path);
        return migration_abort(use, provider, "atomic_switch", "manifest_rename_failed",
                               old_path, new_path, snapshot, 1, 1, &locked);
    }
    if (g_reopen_hook(use, old_path, new_path, g_reopen_arg) != 0) {
        (void)remove_tree(new_path);
        (void)unlink(new_manifest);
        if (rename(backup, old_path) != 0) {
            (void)g_unfreeze_hook(use, g_freeze_arg);
            if (locked) {
                locked = 0;
                pthread_mutex_unlock(&g_migration_lock);
            }
            return migration_finished_result(0, use, provider, "rollback", "rollback_failed",
                                    old_path, new_path, snapshot, 1);
        }
        /* The first reopen may have closed the old handle before discovering
         * the target was unusable.  Reopen the restored path explicitly so a
         * consumer can never retain an fd to the removed target inode. */
        g_current_provider[0] = '\0';
        if (g_reopen_hook(use, new_path, old_path, g_reopen_arg) != 0)
            return migration_abort(use, provider, "rollback",
                                   "consumer_reopen_old_failed", old_path, new_path,
                                   snapshot, 1, 1, &locked);
        return migration_abort(use, provider, "rollback", "consumer_reopen_failed",
                               old_path, new_path, snapshot, 1, 1, &locked);
    }
    (void)fsync_parent_path(new_path);
    (void)fsync_parent_path(old_path);
    (void)old_moved;
    (void)stage_moved;
    (void)frozen;
    if (g_unfreeze_hook(use, g_freeze_arg) != 0) {
        frozen = 0;
        if (locked) {
            locked = 0;
            pthread_mutex_unlock(&g_migration_lock);
        }
        return migration_finished_result(0, use, provider, "unfreeze",
                                "consumer_unfreeze_failed", old_path, new_path,
                                snapshot, 1);
    }
    frozen = 0;
    g_current_provider[0] = '\0';
    if (locked) {
        locked = 0;
        pthread_mutex_unlock(&g_migration_lock);
    }
    return migration_finished_result(1, use, provider, "readback", "migrated",
                            old_path, new_path, snapshot, 1);
}

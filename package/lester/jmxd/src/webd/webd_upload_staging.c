// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Browser upload staging helper for firmware / backup / signature bundles.
 *
 * This module intentionally does not accept caller supplied paths.  Uploads are
 * stored below one controlled root, keyed only by an opaque upload_id generated
 * server-side. Every externally reachable operation is scoped to the stable
 * authenticated owner identity recorded at begin time.
 */
#define _GNU_SOURCE 1
#include "webd_upload_staging.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#if defined(__has_include)
# if __has_include(<openssl/evp.h>)
#  define WEBD_UPLOAD_HAVE_OPENSSL 1
#  include <openssl/evp.h>
# elif __has_include(<CommonCrypto/CommonDigest.h>)
#  define WEBD_UPLOAD_HAVE_COMMONCRYPTO 1
#  include <CommonCrypto/CommonDigest.h>
# endif
#endif
#ifndef WEBD_UPLOAD_HAVE_OPENSSL
#define WEBD_UPLOAD_HAVE_OPENSSL 0
#endif
#ifndef WEBD_UPLOAD_HAVE_COMMONCRYPTO
#define WEBD_UPLOAD_HAVE_COMMONCRYPTO 0
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

#define UPLOAD_DATA_NAME "data.bin"
#define UPLOAD_META_NAME "meta.txt"
#define UPLOAD_META_TMP "meta.tmp"
#define UPLOAD_LOCK_NAME "lock"
#define UPLOAD_GC_PREFIX ".gc-"
#define UPLOAD_CLEANUP_STATUS_NAME ".cleanup-status"
#define UPLOAD_CLEANUP_STATUS_TMP ".cleanup-status.tmp"
#define UPLOAD_ROOT_MAX 512
#define UPLOAD_META_MAX (16 * 1024)
#define UPLOAD_MAX_FIRMWARE (8ULL * 1024ULL * 1024ULL * 1024ULL)
#define UPLOAD_MAX_BACKUP (64ULL * 1024ULL * 1024ULL)
#define UPLOAD_MAX_SIGNATURE (64ULL * 1024ULL * 1024ULL)
#define UPLOAD_MAX_CERTIFICATE (1024ULL * 1024ULL)
#define UPLOAD_TTL_MAX_SECONDS (24U * 3600U)

static char g_upload_root[UPLOAD_ROOT_MAX] = WEBD_UPLOAD_DEFAULT_ROOT;
static struct webd_upload_cleanup_status g_cleanup_status;
static int write_all_fd(int fd, const char *buf, size_t len);

static void cleanup_status_persist_at(int rootfd)
{
    char buf[768];
    int fd;
    int n;

    if (rootfd < 0)
        return;
    n = snprintf(buf, sizeof(buf),
                 "version=1\nlast_run_at=%lld\nlast_success_at=%lld\n"
                 "scanned_count=%llu\ndeleted_count=%llu\nbusy_count=%llu\n"
                 "failed_count=%llu\nrecovered_count=%llu\nlast_error=%s\n",
                 (long long)g_cleanup_status.last_run_at,
                 (long long)g_cleanup_status.last_success_at,
                 (unsigned long long)g_cleanup_status.scanned_count,
                 (unsigned long long)g_cleanup_status.deleted_count,
                 (unsigned long long)g_cleanup_status.busy_count,
                 (unsigned long long)g_cleanup_status.failed_count,
                 (unsigned long long)g_cleanup_status.recovered_count,
                 g_cleanup_status.last_error);
    if (n < 0 || (size_t)n >= sizeof(buf))
        return;
    (void)unlinkat(rootfd, UPLOAD_CLEANUP_STATUS_TMP, 0);
    fd = openat(rootfd, UPLOAD_CLEANUP_STATUS_TMP,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
        return;
    if (write_all_fd(fd, buf, (size_t)n) != 0 || fsync(fd) != 0) {
        close(fd);
        (void)unlinkat(rootfd, UPLOAD_CLEANUP_STATUS_TMP, 0);
        return;
    }
    close(fd);
    if (renameat(rootfd, UPLOAD_CLEANUP_STATUS_TMP,
                 rootfd, UPLOAD_CLEANUP_STATUS_NAME) != 0) {
        (void)unlinkat(rootfd, UPLOAD_CLEANUP_STATUS_TMP, 0);
        return;
    }
    (void)fsync(rootfd);
}

static void upload_err(char *err, size_t err_len, const char *msg)
{
    if (err && err_len) {
        snprintf(err, err_len, "%s", msg ? msg : "upload_staging_error");
    }
}

const char *webd_upload_staging_root(void)
{
    return g_upload_root;
}

int webd_upload_staging_set_root_for_tests(const char *root)
{
    size_t n = root ? strlen(root) : 0;
    if (!n || n >= sizeof(g_upload_root) || root[0] != '/')
        return -1;
    snprintf(g_upload_root, sizeof(g_upload_root), "%s", root);
    return 0;
}

int webd_upload_type_allowed(const char *upload_type)
{
    return upload_type &&
        (!strcmp(upload_type, "firmware") ||
         !strcmp(upload_type, "backup") ||
         !strcmp(upload_type, "signature") ||
         !strcmp(upload_type, "ssl-certificate"));
}

uint64_t webd_upload_type_default_max(const char *upload_type)
{
    if (!strcmp(upload_type ? upload_type : "", "firmware"))
        return UPLOAD_MAX_FIRMWARE;
    if (!strcmp(upload_type ? upload_type : "", "backup"))
        return UPLOAD_MAX_BACKUP;
    if (!strcmp(upload_type ? upload_type : "", "signature"))
        return UPLOAD_MAX_SIGNATURE;
    if (!strcmp(upload_type ? upload_type : "", "ssl-certificate"))
        return UPLOAD_MAX_CERTIFICATE;
    return 0;
}

static int status_ok(const char *status)
{
    return status && (!strcmp(status, "open") || !strcmp(status, "finalized") ||
                      !strcmp(status, "rejected") || !strcmp(status, "expired"));
}

static int owner_id_ok(const char *owner_id)
{
    size_t n = owner_id ? strlen(owner_id) : 0;

    if (!n || n > WEBD_UPLOAD_OWNER_ID_LEN)
        return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)owner_id[i];
        if (c < 0x20 || c == 0x7f)
            return 0;
    }
    return 1;
}

static int origin_ok(const char *origin)
{
    /* "browser" = a web-UI upload; "config_backup" = the config-export flow;
     * "ota-remote" = the server-initiated OTA fetch in api_ota_remote.c that
     * streams a distributor artifact into staging for the existing
     * verify/apply path. otad remains the sole signature authority. */
    return origin && (!strcmp(origin, "browser") ||
                      !strcmp(origin, "config_backup") ||
                      !strcmp(origin, "ota-remote"));
}

static int write_all_fd(int fd, const char *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        off += (size_t)n;
    }
    return 0;
}

static int parse_u64_strict(const char *s, uint64_t *out)
{
    unsigned long long v;
    char *end = NULL;
    if (!s || !*s || *s == '-')
        return -1;
    errno = 0;
    v = strtoull(s, &end, 10);
    if (errno == ERANGE || !end || *end)
        return -1;
    *out = (uint64_t)v;
    return 0;
}

static int parse_time_strict(const char *s, time_t *out)
{
    uint64_t v;
    if (parse_u64_strict(s, &v) != 0 || v > (uint64_t)9223372036854775807ULL)
        return -1;
    *out = (time_t)v;
    return 0;
}

static int upload_id_ok(const char *id)
{
    if (!id || strlen(id) != WEBD_UPLOAD_ID_LEN || strncmp(id, "upl-", 4))
        return 0;
    for (size_t i = 4; i < WEBD_UPLOAD_ID_LEN; i++)
        if (!isxdigit((unsigned char)id[i]))
            return 0;
    return 1;
}

static int upload_gc_id_ok(const char *id)
{
    if (!id || strlen(id) != WEBD_UPLOAD_ID_LEN || strncmp(id, UPLOAD_GC_PREFIX, 4))
        return 0;
    for (size_t i = 4; i < WEBD_UPLOAD_ID_LEN; i++)
        if (!isxdigit((unsigned char)id[i]))
            return 0;
    return 1;
}

static void upload_gc_id(const char *upload_id,
                         char out[WEBD_UPLOAD_ID_LEN + 1])
{
    snprintf(out, WEBD_UPLOAD_ID_LEN + 1, "%s%s", UPLOAD_GC_PREFIX,
             upload_id + 4);
}

static int sha256_hex_ok(const char *hex)
{
    if (!hex || strlen(hex) != WEBD_UPLOAD_SHA256_HEX_LEN)
        return 0;
    for (size_t i = 0; i < WEBD_UPLOAD_SHA256_HEX_LEN; i++)
        if (!isxdigit((unsigned char)hex[i]))
            return 0;
    return 1;
}

static int mkdir_one_at(int parentfd, const char *name, mode_t mode)
{
    struct stat st;
    if (!name || !*name || strchr(name, '/'))
        return -1;
    int fd = openat(parentfd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd >= 0) {
        int ok = (fstat(fd, &st) == 0 && S_ISDIR(st.st_mode));
        close(fd);
        return ok ? 0 : -1;
    }
    if (mkdirat(parentfd, name, mode) != 0 && errno != EEXIST)
        return -1;
    fd = openat(parentfd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    int ok = (fstat(fd, &st) == 0 && S_ISDIR(st.st_mode));
    close(fd);
    return ok ? 0 : -1;
}

static int mkdir_p_private(const char *path)
{
    char tmp[UPLOAD_ROOT_MAX];
    char *save = NULL;
    char *part;
    int fd;
    size_t n = path ? strlen(path) : 0;
    if (!n || n >= sizeof(tmp) || path[0] != '/')
        return -1;
    snprintf(tmp, sizeof(tmp), "%s", path);
    fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    for (part = strtok_r(tmp + 1, "/", &save); part; part = strtok_r(NULL, "/", &save)) {
        int next;
        if (!strcmp(part, ".") || !strcmp(part, "..")) {
            close(fd);
            return -1;
        }
        next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next < 0) {
            if (errno != ENOENT || mkdir_one_at(fd, part, 0700) != 0) {
                close(fd);
                return -1;
            }
            next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        }
        close(fd);
        if (next < 0)
            return -1;
        fd = next;
    }
    close(fd);
    return 0;
}

static int production_data_mount_ready(void)
{
    struct stat root_st;
    struct stat data_st;

    if (strcmp(g_upload_root, WEBD_UPLOAD_DEFAULT_ROOT))
        return 1;
#if defined(OTAD_SINGLE_SLOT_SUPPORTED) && OTAD_SINGLE_SLOT_SUPPORTED
    return stat("/", &root_st) == 0 && stat("/tmp", &data_st) == 0 &&
           S_ISDIR(data_st.st_mode) && root_st.st_dev != data_st.st_dev;
#else
    return stat("/", &root_st) == 0 && stat("/data", &data_st) == 0 &&
           S_ISDIR(data_st.st_mode) && root_st.st_dev != data_st.st_dev;
#endif
}

static int open_root(char *err, size_t err_len)
{
    int fd;
    struct stat st;
    if (!production_data_mount_ready()) {
#if defined(OTAD_SINGLE_SLOT_SUPPORTED) && OTAD_SINGLE_SLOT_SUPPORTED
        upload_err(err, err_len, "temporary_mount_unavailable");
#else
        upload_err(err, err_len, "data_mount_unavailable");
#endif
        return -1;
    }
    if (mkdir_p_private(g_upload_root) != 0) {
        upload_err(err, err_len, "root_unavailable");
        return -1;
    }
    fd = open(g_upload_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode)) {
        if (fd >= 0) close(fd);
        upload_err(err, err_len, "root_open_failed");
        return -1;
    }
    return fd;
}

int webd_upload_staging_check_capacity(uint64_t additional_bytes,
                                      char *err, size_t err_len)
{
#if defined(OTAD_SINGLE_SLOT_SUPPORTED) && OTAD_SINGLE_SLOT_SUPPORTED
    const uint64_t reserve = 128ULL * 1024ULL * 1024ULL;
    struct statvfs vfs;
    uint64_t available;
    int fd = open_root(err, err_len);
    if (fd < 0) return -1;
    int rc = fstatvfs(fd, &vfs);
    close(fd);
    if (rc != 0 || !vfs.f_frsize) {
        upload_err(err, err_len, "staging_space_probe_failed");
        return -1;
    }
    available = (uint64_t)vfs.f_bavail * vfs.f_frsize;
#ifdef __linux__
    /* tmpfs capacity is not RAM availability: enforce both budgets. */
    FILE *mem = fopen("/proc/meminfo", "r");
    char line[256];
    unsigned long long kb = 0;
    if (mem) {
        while (fgets(line, sizeof(line), mem))
            if (sscanf(line, "MemAvailable: %llu kB", &kb) == 1) break;
        fclose(mem);
    }
    if (!kb) {
        upload_err(err, err_len, "staging_memory_probe_failed");
        return -1;
    }
    if (kb * 1024ULL < available) available = kb * 1024ULL;
#endif
    if (available < reserve || additional_bytes > available - reserve) {
        upload_err(err, err_len, "staging_insufficient_space");
        return -1;
    }
#else
    (void)additional_bytes; (void)err; (void)err_len;
#endif
    return 0;
}

static int upload_capacity(const char *type, uint64_t expected,
                           uint64_t written, char *err, size_t err_len)
{
    uint64_t required = expected > written ? expected - written : 0;
    /* Single-slot apply consumes and compacts the existing staging inode. */
    (void)type;
    return webd_upload_staging_check_capacity(required, err, err_len);
}

static int open_upload_dir_at(int rootfd, const char *id, char *err, size_t err_len)
{
    int dirfd;
    struct stat st;
    if (!upload_id_ok(id)) {
        upload_err(err, err_len, "bad_upload_id");
        return -1;
    }
    dirfd = openat(rootfd, id, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0 || fstat(dirfd, &st) != 0 || !S_ISDIR(st.st_mode)) {
        if (dirfd >= 0) close(dirfd);
        upload_err(err, err_len, "upload_not_found");
        return -1;
    }
    return dirfd;
}

static int lock_upload_dir(int dirfd, char *err, size_t err_len)
{
    int lockfd = openat(dirfd, UPLOAD_LOCK_NAME,
                        O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lockfd < 0) {
        upload_err(err, err_len, "lock_failed");
        return -1;
    }
    for (;;) {
        if (flock(lockfd, LOCK_EX) == 0)
            return lockfd;
        if (errno == EINTR)
            continue;
        close(lockfd);
        upload_err(err, err_len, "lock_failed");
        return -1;
    }
}

static int try_lock_upload_dir(int dirfd)
{
    int lockfd = openat(dirfd, UPLOAD_LOCK_NAME,
                        O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lockfd < 0)
        return -1;
    if (flock(lockfd, LOCK_EX | LOCK_NB) != 0) {
        int saved = errno;
        close(lockfd);
        errno = saved;
        return -1;
    }
    return lockfd;
}

static void hex_encode(const char *in, char *out, size_t out_len)
{
    static const char h[] = "0123456789abcdef";
    size_t j = 0;
    for (size_t i = 0; in && in[i] && j + 2 < out_len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c < 0x20 || c == 0x7f)
            c = '_';
        out[j++] = h[c >> 4];
        out[j++] = h[c & 0xf];
    }
    out[j] = '\0';
}

static int hex_value(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void hex_decode(const char *in, char *out, size_t out_len)
{
    size_t j = 0;
    if (!out_len) return;
    for (size_t i = 0; in && in[i] && in[i + 1] && j + 1 < out_len; i += 2) {
        int a = hex_value((unsigned char)in[i]);
        int b = hex_value((unsigned char)in[i + 1]);
        if (a < 0 || b < 0) break;
        out[j++] = (char)((a << 4) | b);
    }
    out[j] = '\0';
}

static int original_filename_ok(const char *name)
{
    size_t n = name ? strlen(name) : 0;
    if (!n || n >= 256)
        return 0;
    if (strstr(name, ".."))
        return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)name[i];
        if (c < 0x20 || c == 0x7f || c == '/' || c == '\\')
            return 0;
    }
    return 1;
}

static int meta_write_at(int dirfd, const struct webd_upload_meta *m,
                         char *err, size_t err_len)
{
    char filename_hex[sizeof(m->original_filename) * 2 + 1];
    char owner_hex[sizeof(m->owner_id) * 2 + 1];
    char buf[UPLOAD_META_MAX];
    int fd;
    ssize_t need;

    hex_encode(m->original_filename, filename_hex, sizeof(filename_hex));
    hex_encode(m->owner_id, owner_hex, sizeof(owner_hex));
    need = snprintf(buf, sizeof(buf),
                    "version=2\n"
                    "upload_id=%s\n"
                    "owner_hex=%s\n"
                    "origin=%s\n"
                    "upload_type=%s\n"
                    "filename_hex=%s\n"
                    "status=%s\n"
                    "size_bytes=%llu\n"
                    "expected_size_bytes=%llu\n"
                    "max_size_bytes=%llu\n"
                    "created_at=%lld\n"
                    "updated_at=%lld\n"
                    "expires_at=%lld\n"
                    "sha256=%s\n"
                    "error=%s\n",
                    m->upload_id, owner_hex, m->origin, m->upload_type,
                    filename_hex, m->status,
                    (unsigned long long)m->size_bytes,
                    (unsigned long long)m->expected_size_bytes,
                    (unsigned long long)m->max_size_bytes,
                    (long long)m->created_at, (long long)m->updated_at,
                    (long long)m->expires_at, m->sha256, m->error);
    if (need < 0 || (size_t)need >= sizeof(buf)) {
        upload_err(err, err_len, "meta_too_large");
        return -1;
    }
    unlinkat(dirfd, UPLOAD_META_TMP, 0);
    fd = openat(dirfd, UPLOAD_META_TMP,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        upload_err(err, err_len, "meta_create_failed");
        return -1;
    }
    if (write_all_fd(fd, buf, (size_t)need) != 0 || fsync(fd) != 0) {
        close(fd);
        unlinkat(dirfd, UPLOAD_META_TMP, 0);
        upload_err(err, err_len, "meta_write_failed");
        return -1;
    }
    close(fd);
    if (renameat(dirfd, UPLOAD_META_TMP, dirfd, UPLOAD_META_NAME) != 0) {
        unlinkat(dirfd, UPLOAD_META_TMP, 0);
        upload_err(err, err_len, "meta_commit_failed");
        return -1;
    }
    (void)fsync(dirfd);
    return 0;
}

static void meta_init_empty(struct webd_upload_meta *m)
{
    memset(m, 0, sizeof(*m));
}

static int meta_parse_buf(const char *buf, struct webd_upload_meta *m)
{
    char *copy = strdup(buf ? buf : "");
    char *save = NULL;
    char *line;
    int version = 0;
    int have_id = 0, have_owner = 0, have_origin = 0;
    int have_type = 0, have_status = 0;
    int have_size = 0, have_expected = 0, have_max = 0;
    int have_created = 0, have_updated = 0, have_expires = 0;
    uint64_t hard;
    if (!copy)
        return -1;
    meta_init_empty(m);
    for (line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq++ = '\0';
        if (!strcmp(line, "version")) version = atoi(eq);
        else if (!strcmp(line, "upload_id")) { snprintf(m->upload_id, sizeof(m->upload_id), "%s", eq); have_id = 1; }
        else if (!strcmp(line, "owner_hex")) { hex_decode(eq, m->owner_id, sizeof(m->owner_id)); have_owner = 1; }
        else if (!strcmp(line, "origin")) { snprintf(m->origin, sizeof(m->origin), "%s", eq); have_origin = 1; }
        else if (!strcmp(line, "upload_type")) { snprintf(m->upload_type, sizeof(m->upload_type), "%s", eq); have_type = 1; }
        else if (!strcmp(line, "filename_hex")) hex_decode(eq, m->original_filename, sizeof(m->original_filename));
        else if (!strcmp(line, "status")) { snprintf(m->status, sizeof(m->status), "%s", eq); have_status = 1; }
        else if (!strcmp(line, "size_bytes")) { if (parse_u64_strict(eq, &m->size_bytes) != 0) goto bad; have_size = 1; }
        else if (!strcmp(line, "expected_size_bytes")) { if (parse_u64_strict(eq, &m->expected_size_bytes) != 0) goto bad; have_expected = 1; }
        else if (!strcmp(line, "max_size_bytes")) { if (parse_u64_strict(eq, &m->max_size_bytes) != 0) goto bad; have_max = 1; }
        else if (!strcmp(line, "created_at")) { if (parse_time_strict(eq, &m->created_at) != 0) goto bad; have_created = 1; }
        else if (!strcmp(line, "updated_at")) { if (parse_time_strict(eq, &m->updated_at) != 0) goto bad; have_updated = 1; }
        else if (!strcmp(line, "expires_at")) { if (parse_time_strict(eq, &m->expires_at) != 0) goto bad; have_expires = 1; }
        else if (!strcmp(line, "sha256")) snprintf(m->sha256, sizeof(m->sha256), "%s", eq);
        else if (!strcmp(line, "error")) snprintf(m->error, sizeof(m->error), "%s", eq);
    }
    free(copy);
    if (version != 2 || !have_id || !have_owner || !have_origin ||
        !have_type || !have_status || !have_size || !have_expected ||
        !have_max || !have_created || !have_updated || !have_expires)
        return -1;
    if (!upload_id_ok(m->upload_id) || !owner_id_ok(m->owner_id) ||
        !origin_ok(m->origin) || !webd_upload_type_allowed(m->upload_type) ||
        !status_ok(m->status) || !original_filename_ok(m->original_filename))
        return -1;
    hard = webd_upload_type_default_max(m->upload_type);
    if (!m->max_size_bytes || m->max_size_bytes > hard || m->expected_size_bytes > m->max_size_bytes ||
        m->size_bytes > m->max_size_bytes || (m->expected_size_bytes && m->size_bytes > m->expected_size_bytes))
        return -1;
    if (m->updated_at < m->created_at || m->expires_at < m->created_at ||
        (uint64_t)(m->expires_at - m->created_at) > UPLOAD_TTL_MAX_SECONDS)
        return -1;
    if (m->sha256[0] && !sha256_hex_ok(m->sha256))
        return -1;
    return 0;
bad:
    free(copy);
    return -1;
}

static int meta_read_at(int dirfd, struct webd_upload_meta *m, char *err, size_t err_len)
{
    char buf[UPLOAD_META_MAX + 1];
    ssize_t n;
    int fd = openat(dirfd, UPLOAD_META_NAME, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        upload_err(err, err_len, "meta_missing");
        return -1;
    }
    n = read(fd, buf, UPLOAD_META_MAX);
    close(fd);
    if (n <= 0 || n >= UPLOAD_META_MAX) {
        upload_err(err, err_len, "meta_invalid");
        return -1;
    }
    buf[n] = '\0';
    if (meta_parse_buf(buf, m) != 0) {
        upload_err(err, err_len, "meta_invalid");
        return -1;
    }
    return 0;
}

static int gen_upload_id(char out[WEBD_UPLOAD_ID_LEN + 1])
{
    unsigned char rnd[16];
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    ssize_t n = read(fd, rnd, sizeof(rnd));
    close(fd);
    if (n != (ssize_t)sizeof(rnd)) return -1;
    snprintf(out, WEBD_UPLOAD_ID_LEN + 1,
             "upl-%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             rnd[0], rnd[1], rnd[2], rnd[3], rnd[4], rnd[5], rnd[6], rnd[7],
             rnd[8], rnd[9], rnd[10], rnd[11], rnd[12], rnd[13], rnd[14], rnd[15]);
    return 0;
}

static int sha256_file_at(int dirfd, char hex[WEBD_UPLOAD_SHA256_HEX_LEN + 1],
                          uint64_t *size_out, char *err, size_t err_len)
{
    unsigned char buf[8192];
    unsigned char digest[32];
    uint64_t total = 0;
    int fd = -1;
    int rc = -1;
#if WEBD_UPLOAD_HAVE_OPENSSL
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int digest_len = 0;
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        upload_err(err, err_len, "sha256_init_failed");
        return -1;
    }
#elif WEBD_UPLOAD_HAVE_COMMONCRYPTO
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
#else
#error "webd_upload_staging requires OpenSSL EVP or CommonCrypto SHA256"
#endif

    fd = openat(dirfd, UPLOAD_DATA_NAME, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        upload_err(err, err_len, "data_missing");
        goto out;
    }
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {
            upload_err(err, err_len, "data_read_failed");
            goto out;
        }
        if (n == 0) break;
#if WEBD_UPLOAD_HAVE_OPENSSL
        if (EVP_DigestUpdate(ctx, buf, (size_t)n) != 1) {
            upload_err(err, err_len, "sha256_update_failed");
            goto out;
        }
#elif WEBD_UPLOAD_HAVE_COMMONCRYPTO
        CC_SHA256_Update(&ctx, buf, (CC_LONG)n);
#endif
        total += (uint64_t)n;
    }
#if WEBD_UPLOAD_HAVE_OPENSSL
    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1 || digest_len != 32) {
        upload_err(err, err_len, "sha256_final_failed");
        goto out;
    }
#elif WEBD_UPLOAD_HAVE_COMMONCRYPTO
    CC_SHA256_Final(digest, &ctx);
#endif
    for (unsigned int i = 0; i < 32; i++)
        snprintf(hex + i * 2, 3, "%02x", digest[i]);
    hex[WEBD_UPLOAD_SHA256_HEX_LEN] = '\0';
    if (size_out) *size_out = total;
    rc = 0;
out:
    if (fd >= 0) close(fd);
#if WEBD_UPLOAD_HAVE_OPENSSL
    EVP_MD_CTX_free(ctx);
#endif
    return rc;
}

int webd_upload_begin(const char *owner_id, const char *origin,
                      const char *upload_type, const char *original_filename,
                      uint64_t expected_size_bytes, uint64_t max_size_bytes,
                      unsigned ttl_seconds, struct webd_upload_meta *out,
                      char *err, size_t err_len)
{
    int rootfd = -1, dirfd = -1, datafd = -1, lockfd = -1;
    struct webd_upload_meta m;
    time_t now = time(NULL);

    /* Best effort: reclaim expired objects before reserving space for another
     * upload. The bounded nonblocking scan must never make begin unavailable. */
    (void)webd_upload_cleanup_expired(now, NULL, NULL, 0);

    if (!owner_id_ok(owner_id)) {
        upload_err(err, err_len, "bad_owner_id");
        return -1;
    }
    if (!origin_ok(origin)) {
        upload_err(err, err_len, "bad_origin");
        return -1;
    }
    if (!webd_upload_type_allowed(upload_type)) {
        upload_err(err, err_len, "bad_upload_type");
        return -1;
    }
    if (!original_filename_ok(original_filename)) {
        upload_err(err, err_len, "bad_filename");
        return -1;
    }
    {
        uint64_t hard = webd_upload_type_default_max(upload_type);
        if (!max_size_bytes)
            max_size_bytes = hard;
        if (!max_size_bytes || max_size_bytes > hard || expected_size_bytes > max_size_bytes) {
            upload_err(err, err_len, "size_limit_exceeded");
            return -1;
        }
    }
    if (!ttl_seconds)
        ttl_seconds = WEBD_UPLOAD_DEFAULT_TTL_SECONDS;
    if (ttl_seconds > UPLOAD_TTL_MAX_SECONDS) {
        upload_err(err, err_len, "ttl_limit_exceeded");
        return -1;
    }
    rootfd = open_root(err, err_len);
    if (rootfd < 0) return -1;

    if (upload_capacity(upload_type, expected_size_bytes, 0, err, err_len) != 0) {
        close(rootfd);
        return -1;
    }
    meta_init_empty(&m);
    for (int tries = 0; tries < 8; tries++) {
        if (gen_upload_id(m.upload_id) != 0) {
            upload_err(err, err_len, "id_generation_failed");
            goto fail;
        }
        if (mkdirat(rootfd, m.upload_id, 0700) == 0) {
            (void)fsync(rootfd);
            break;
        }
        if (errno != EEXIST || tries == 7) {
            upload_err(err, err_len, "upload_dir_create_failed");
            goto fail;
        }
    }
    dirfd = open_upload_dir_at(rootfd, m.upload_id, err, err_len);
    if (dirfd < 0) goto fail;
    lockfd = lock_upload_dir(dirfd, err, err_len);
    if (lockfd < 0) goto fail;
    datafd = openat(dirfd, UPLOAD_DATA_NAME,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (datafd < 0) {
        upload_err(err, err_len, "data_create_failed");
        goto fail;
    }
    (void)fsync(datafd);
    close(datafd);
    datafd = -1;
    (void)fsync(dirfd);

    snprintf(m.owner_id, sizeof(m.owner_id), "%s", owner_id);
    snprintf(m.origin, sizeof(m.origin), "%s", origin);
    snprintf(m.upload_type, sizeof(m.upload_type), "%s", upload_type);
    snprintf(m.original_filename, sizeof(m.original_filename), "%s", original_filename);
    snprintf(m.status, sizeof(m.status), "%s", "open");
    m.size_bytes = 0;
    m.expected_size_bytes = expected_size_bytes;
    m.max_size_bytes = max_size_bytes;
    m.created_at = now;
    m.updated_at = now;
    m.expires_at = now + (time_t)ttl_seconds;
    m.sha256[0] = '\0';
    m.error[0] = '\0';
    if (meta_write_at(dirfd, &m, err, err_len) != 0) goto fail;
    if (out) *out = m;
    close(lockfd); close(dirfd); close(rootfd);
    return 0;
fail:
    if (datafd >= 0) close(datafd);
    if (lockfd >= 0) close(lockfd);
    if (dirfd >= 0) close(dirfd);
    if (rootfd >= 0) {
        if (upload_id_ok(m.upload_id)) {
            int d = openat(rootfd, m.upload_id, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (d >= 0) {
                unlinkat(d, UPLOAD_DATA_NAME, 0);
                unlinkat(d, UPLOAD_META_NAME, 0);
                unlinkat(d, UPLOAD_META_TMP, 0);
                unlinkat(d, UPLOAD_LOCK_NAME, 0);
                close(d);
            }
            unlinkat(rootfd, m.upload_id, AT_REMOVEDIR);
        }
        close(rootfd);
    }
    return -1;
}

int webd_upload_append(const char *owner_id, const char *upload_id,
                       uint64_t offset, const void *chunk,
                       size_t chunk_len, struct webd_upload_meta *out,
                       char *err, size_t err_len)
{
    int rootfd = -1, dirfd = -1, fd = -1, lockfd = -1;
    struct webd_upload_meta m;
    struct stat st;
    ssize_t wrote;

    if (!owner_id_ok(owner_id)) {
        upload_err(err, err_len, "bad_owner_id");
        return -1;
    }
    if (chunk_len && !chunk) {
        upload_err(err, err_len, "bad_chunk");
        return -1;
    }
    rootfd = open_root(err, err_len);
    if (rootfd < 0) return -1;
    dirfd = open_upload_dir_at(rootfd, upload_id, err, err_len);
    if (dirfd < 0) goto fail;
    lockfd = lock_upload_dir(dirfd, err, err_len);
    if (lockfd < 0) goto fail;
    if (meta_read_at(dirfd, &m, err, err_len) != 0) goto fail;
    if (strcmp(m.owner_id, owner_id)) {
        upload_err(err, err_len, "upload_not_found");
        goto fail;
    }
    if (strcmp(m.status, "open")) {
        upload_err(err, err_len, "upload_not_open");
        goto fail;
    }
    if ((uint64_t)time(NULL) > (uint64_t)m.expires_at) {
        snprintf(m.status, sizeof(m.status), "%s", "expired");
        snprintf(m.error, sizeof(m.error), "%s", "expired");
        m.updated_at = time(NULL);
        meta_write_at(dirfd, &m, NULL, 0);
        upload_err(err, err_len, "upload_expired");
        goto fail;
    }
    fd = openat(dirfd, UPLOAD_DATA_NAME, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        upload_err(err, err_len, "data_open_failed");
        goto fail;
    }
    if ((uint64_t)st.st_size != offset || m.size_bytes != offset) {
        upload_err(err, err_len, "bad_offset");
        goto fail;
    }
    if (chunk_len > m.max_size_bytes || offset > m.max_size_bytes - (uint64_t)chunk_len ||
        (m.expected_size_bytes && offset + (uint64_t)chunk_len > m.expected_size_bytes)) {
        upload_err(err, err_len, "size_limit_exceeded");
        goto fail;
    }
    if (upload_capacity(m.upload_type,
                        m.expected_size_bytes ? m.expected_size_bytes : offset + chunk_len,
                        offset, err, err_len) != 0)
        goto fail;
    for (size_t done = 0; done < chunk_len; done += (size_t)wrote) {
        wrote = write(fd, (const char *)chunk + done, chunk_len - done);
        if (wrote < 0 && errno == EINTR) { wrote = 0; continue; }
        if (wrote <= 0) {
            upload_err(err, err_len, "data_write_failed");
            goto fail;
        }
    }
    if (fsync(fd) != 0) {
        upload_err(err, err_len, "data_sync_failed");
        goto fail;
    }
    close(fd); fd = -1;
    m.size_bytes = offset + (uint64_t)chunk_len;
    m.updated_at = time(NULL);
    if (meta_write_at(dirfd, &m, err, err_len) != 0) goto fail;
    if (out) *out = m;
    close(lockfd); close(dirfd); close(rootfd);
    return 0;
fail:
    if (fd >= 0) close(fd);
    if (lockfd >= 0) close(lockfd);
    if (dirfd >= 0) close(dirfd);
    if (rootfd >= 0) close(rootfd);
    return -1;
}

int webd_upload_finalize(const char *owner_id, const char *upload_id,
                         const char *expected_sha256_hex,
                         struct webd_upload_meta *out, char *err, size_t err_len)
{
    int rootfd = -1, dirfd = -1, lockfd = -1;
    struct webd_upload_meta m;
    char actual[WEBD_UPLOAD_SHA256_HEX_LEN + 1];
    uint64_t actual_size = 0;

    if (!owner_id_ok(owner_id)) {
        upload_err(err, err_len, "bad_owner_id");
        return -1;
    }
    if (expected_sha256_hex && *expected_sha256_hex && !sha256_hex_ok(expected_sha256_hex)) {
        upload_err(err, err_len, "bad_sha256");
        return -1;
    }
    rootfd = open_root(err, err_len);
    if (rootfd < 0) return -1;
    dirfd = open_upload_dir_at(rootfd, upload_id, err, err_len);
    if (dirfd < 0) goto fail;
    lockfd = lock_upload_dir(dirfd, err, err_len);
    if (lockfd < 0) goto fail;
    if (meta_read_at(dirfd, &m, err, err_len) != 0) goto fail;
    if (strcmp(m.owner_id, owner_id)) {
        upload_err(err, err_len, "upload_not_found");
        goto fail;
    }
    if (strcmp(m.status, "open")) {
        upload_err(err, err_len, "upload_not_open");
        goto fail;
    }
    if (m.expected_size_bytes && m.size_bytes != m.expected_size_bytes) {
        upload_err(err, err_len, "size_incomplete");
        goto fail;
    }
    if (sha256_file_at(dirfd, actual, &actual_size, err, err_len) != 0) goto fail;
    if (actual_size != m.size_bytes) {
        upload_err(err, err_len, "size_changed");
        goto fail;
    }
    if (expected_sha256_hex && *expected_sha256_hex && strcasecmp(expected_sha256_hex, actual)) {
        snprintf(m.status, sizeof(m.status), "%s", "rejected");
        snprintf(m.error, sizeof(m.error), "%s", "sha256_mismatch");
        m.updated_at = time(NULL);
        meta_write_at(dirfd, &m, NULL, 0);
        upload_err(err, err_len, "sha256_mismatch");
        goto fail;
    }
    snprintf(m.sha256, sizeof(m.sha256), "%s", actual);
    snprintf(m.status, sizeof(m.status), "%s", "finalized");
    m.updated_at = time(NULL);
    if (meta_write_at(dirfd, &m, err, err_len) != 0) goto fail;
    if (out) *out = m;
    close(lockfd); close(dirfd); close(rootfd);
    return 0;
fail:
    if (lockfd >= 0) close(lockfd);
    if (dirfd >= 0) close(dirfd);
    if (rootfd >= 0) close(rootfd);
    return -1;
}

int webd_upload_get(const char *owner_id, const char *upload_id,
                    struct webd_upload_meta *out,
                    char *err, size_t err_len)
{
    int rootfd = open_root(err, err_len);
    int dirfd;
    int rc;
    if (rootfd < 0) return -1;
    dirfd = open_upload_dir_at(rootfd, upload_id, err, err_len);
    if (dirfd < 0) { close(rootfd); return -1; }
    rc = meta_read_at(dirfd, out, err, err_len);
    if (rc == 0 && (!owner_id_ok(owner_id) || strcmp(out->owner_id, owner_id))) {
        upload_err(err, err_len, "upload_not_found");
        rc = -1;
    }
    close(dirfd);
    close(rootfd);
    return rc;
}

static int unlink_upload_file_at(int dirfd, const char *name)
{
    if (unlinkat(dirfd, name, 0) == 0 || errno == ENOENT)
        return 0;
    return -1;
}

static int webd_upload_remove_locked(int rootfd, int dirfd, int lockfd,
                                     const char *gc_id,
                                     char *err, size_t err_len)
{
    int rc = 0;

    if (unlink_upload_file_at(dirfd, UPLOAD_DATA_NAME) != 0 ||
        unlink_upload_file_at(dirfd, UPLOAD_META_NAME) != 0 ||
        unlink_upload_file_at(dirfd, UPLOAD_META_TMP) != 0)
        rc = -1;
    (void)fsync(dirfd);
    if (unlink_upload_file_at(dirfd, UPLOAD_LOCK_NAME) != 0)
        rc = -1;
    close(lockfd);
    close(dirfd);
    if (rc == 0 && unlinkat(rootfd, gc_id, AT_REMOVEDIR) != 0 && errno != ENOENT)
        rc = -1;
    (void)fsync(rootfd);
    if (rc != 0)
        upload_err(err, err_len, "delete_failed");
    return rc;
}

static int webd_upload_recover_gc_at(int rootfd, const char *gc_id,
                                     int nonblocking,
                                     char *err, size_t err_len)
{
    int dirfd;
    int lockfd;

    if (!upload_gc_id_ok(gc_id)) {
        upload_err(err, err_len, "bad_upload_id");
        return -1;
    }
    dirfd = openat(rootfd, gc_id,
                   O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0) {
        if (errno == ENOENT)
            return 0;
        upload_err(err, err_len, "upload_not_found");
        return -1;
    }
    lockfd = nonblocking ? try_lock_upload_dir(dirfd) :
                           lock_upload_dir(dirfd, err, err_len);
    if (lockfd < 0) {
        close(dirfd);
        if (nonblocking && (errno == EWOULDBLOCK || errno == EAGAIN))
            return 1;
        upload_err(err, err_len, "lock_failed");
        return -1;
    }
    return webd_upload_remove_locked(rootfd, dirfd, lockfd, gc_id,
                                     err, err_len);
}

static int webd_upload_delete_internal(const char *owner_id, int enforce_owner,
                                       const char *upload_id, int nonblocking,
                                       int missing_ok, int *deleted,
                                       char *err, size_t err_len)
{
    int rootfd = open_root(err, err_len);
    int dirfd;
    int lockfd;
    int rc;
    char gc_id[WEBD_UPLOAD_ID_LEN + 1];
    struct webd_upload_meta m;

    if (err && err_len)
        err[0] = '\0';
    if (deleted)
        *deleted = 0;
    if (rootfd < 0)
        return -1;
    if (!upload_id_ok(upload_id)) {
        close(rootfd);
        upload_err(err, err_len, "bad_upload_id");
        return -1;
    }
    upload_gc_id(upload_id, gc_id);
    dirfd = open_upload_dir_at(rootfd, upload_id, err, err_len);
    if (dirfd < 0) {
        if (missing_ok) {
            rc = webd_upload_recover_gc_at(rootfd, gc_id, nonblocking,
                                           err, err_len);
            close(rootfd);
            if (rc == 0) {
                if (err && err_len)
                    err[0] = '\0';
                return 0;
            }
            return rc;
        }
        close(rootfd);
        return -1;
    }
    lockfd = nonblocking ? try_lock_upload_dir(dirfd) :
                           lock_upload_dir(dirfd, err, err_len);
    if (lockfd < 0) {
        close(dirfd);
        close(rootfd);
        if (nonblocking && (errno == EWOULDBLOCK || errno == EAGAIN))
            return 1;
        upload_err(err, err_len, "lock_failed");
        return -1;
    }
    if (meta_read_at(dirfd, &m, err, err_len) != 0 ||
        (enforce_owner && (!owner_id_ok(owner_id) || strcmp(m.owner_id, owner_id)))) {
        if (enforce_owner)
            upload_err(err, err_len, "upload_not_found");
        close(lockfd);
        close(dirfd);
        close(rootfd);
        return -1;
    }

    if (renameat(rootfd, upload_id, rootfd, gc_id) != 0) {
        int saved = errno;
        close(lockfd);
        close(dirfd);
        close(rootfd);
        errno = saved;
        upload_err(err, err_len, "delete_stage_failed");
        return -1;
    }
    (void)fsync(rootfd);
    if (deleted)
        *deleted = 1;
    rc = webd_upload_remove_locked(rootfd, dirfd, lockfd, gc_id,
                                   err, err_len);
    close(rootfd);
    return rc;
}

int webd_upload_delete(const char *owner_id, const char *upload_id,
                       char *err, size_t err_len)
{
    return webd_upload_delete_internal(owner_id, 1, upload_id, 0, 0, NULL,
                                       err, err_len);
}

int webd_upload_delete_privileged(const char *upload_id, int *deleted,
                                  char *err, size_t err_len)
{
    return webd_upload_delete_internal(NULL, 0, upload_id, 0, 1, deleted,
                                       err, err_len);
}

int webd_upload_list_all(struct webd_upload_list *out, char *err, size_t err_len)
{
    int rootfd;
    DIR *dir;
    struct dirent *de;
    size_t cap = 0;
    if (!out) return -1;
    out->items = NULL;
    out->count = 0;
    rootfd = open_root(err, err_len);
    if (rootfd < 0) return -1;
    dir = fdopendir(rootfd);
    if (!dir) {
        close(rootfd);
        upload_err(err, err_len, "list_failed");
        return -1;
    }
    while ((de = readdir(dir)) != NULL && out->count < WEBD_UPLOAD_META_SCAN_LIMIT) {
        int dfd;
        struct webd_upload_meta m;
        if (!upload_id_ok(de->d_name)) continue;
        dfd = openat(rootfd, de->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (dfd < 0) continue;
        int lfd = lock_upload_dir(dfd, NULL, 0);
        if (lfd < 0) { close(dfd); continue; }
        if (meta_read_at(dfd, &m, NULL, 0) == 0) {
            if (out->count == cap) {
                size_t ncap = cap ? cap * 2 : 16;
                struct webd_upload_meta *ni = realloc(out->items, ncap * sizeof(*ni));
                if (!ni) { close(dfd); closedir(dir); webd_upload_list_free(out); upload_err(err, err_len, "oom"); return -1; }
                out->items = ni;
                cap = ncap;
            }
            out->items[out->count++] = m;
        }
        close(lfd);
        close(dfd);
    }
    closedir(dir);
    return 0;
}

void webd_upload_list_free(struct webd_upload_list *list)
{
    if (list) {
        free(list->items);
        list->items = NULL;
        list->count = 0;
    }
}

int webd_upload_list_owner(const char *owner_id, struct webd_upload_list *out,
                           char *err, size_t err_len)
{
    struct webd_upload_list all;
    size_t count = 0;

    if (!out || !owner_id_ok(owner_id)) {
        upload_err(err, err_len, "bad_owner_id");
        return -1;
    }
    out->items = NULL;
    out->count = 0;
    if (webd_upload_list_all(&all, err, err_len) != 0)
        return -1;
    for (size_t i = 0; i < all.count; i++)
        if (!strcmp(all.items[i].owner_id, owner_id))
            count++;
    if (count) {
        out->items = calloc(count, sizeof(*out->items));
        if (!out->items) {
            webd_upload_list_free(&all);
            upload_err(err, err_len, "oom");
            return -1;
        }
        for (size_t i = 0; i < all.count; i++)
            if (!strcmp(all.items[i].owner_id, owner_id))
                out->items[out->count++] = all.items[i];
    }
    webd_upload_list_free(&all);
    return 0;
}

int webd_upload_cleanup_expired(time_t now, size_t *deleted_count, char *err, size_t err_len)
{
    struct {
        char name[WEBD_UPLOAD_ID_LEN + 1];
        int gc;
    } entries[WEBD_UPLOAD_META_SCAN_LIMIT];
    int rootfd;
    int scanfd;
    DIR *dir;
    struct dirent *de;
    size_t count = 0;
    size_t deleted = 0;
    size_t busy = 0;
    size_t failed = 0;
    size_t recovered = 0;

    memset(&g_cleanup_status, 0, sizeof(g_cleanup_status));
    g_cleanup_status.last_run_at = now;
    rootfd = open_root(err, err_len);
    if (rootfd < 0) {
        snprintf(g_cleanup_status.last_error,
                 sizeof(g_cleanup_status.last_error), "%s",
                 err && err[0] ? err : "root_unavailable");
        return -1;
    }
    scanfd = dup(rootfd);
    if (scanfd < 0 || !(dir = fdopendir(scanfd))) {
        if (scanfd >= 0)
            close(scanfd);
        close(rootfd);
        upload_err(err, err_len, "list_failed");
        snprintf(g_cleanup_status.last_error,
                 sizeof(g_cleanup_status.last_error), "list_failed");
        return -1;
    }
    while ((de = readdir(dir)) != NULL && count < WEBD_UPLOAD_META_SCAN_LIMIT) {
        int is_gc = upload_gc_id_ok(de->d_name);
        if (!is_gc && !upload_id_ok(de->d_name))
            continue;
        snprintf(entries[count].name, sizeof(entries[count].name), "%s",
                 de->d_name);
        entries[count].gc = is_gc;
        count++;
    }
    closedir(dir);

    for (size_t i = 0; i < count; i++) {
        int rc;
        if (entries[i].gc) {
            rc = webd_upload_recover_gc_at(rootfd, entries[i].name, 1,
                                           NULL, 0);
            if (rc == 0)
                recovered++;
            else if (rc == 1)
                busy++;
            else
                failed++;
            continue;
        }
        {
            int dirfd = openat(rootfd, entries[i].name,
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            int lockfd;
            struct webd_upload_meta meta;
            if (dirfd < 0)
                continue;
            lockfd = try_lock_upload_dir(dirfd);
            if (lockfd < 0) {
                if (errno == EWOULDBLOCK || errno == EAGAIN)
                    busy++;
                else
                    failed++;
                close(dirfd);
                continue;
            }
            rc = meta_read_at(dirfd, &meta, NULL, 0);
            close(lockfd);
            close(dirfd);
            if (rc != 0) {
                failed++;
                continue;
            }
            if (meta.expires_at <= now) {
                int was_deleted = 0;
                rc = webd_upload_delete_internal(NULL, 0, entries[i].name,
                                                 1, 1, &was_deleted,
                                                 NULL, 0);
                if (rc == 0 && was_deleted)
                    deleted++;
                else if (rc == 1)
                    busy++;
                else if (rc != 0)
                    failed++;
            }
        }
    }
    g_cleanup_status.last_success_at = failed ? 0 : now;
    g_cleanup_status.scanned_count = count;
    g_cleanup_status.deleted_count = deleted;
    g_cleanup_status.busy_count = busy;
    g_cleanup_status.failed_count = failed;
    g_cleanup_status.recovered_count = recovered;
    if (failed)
        snprintf(g_cleanup_status.last_error,
                 sizeof(g_cleanup_status.last_error), "cleanup_partial_failure");
    cleanup_status_persist_at(rootfd);
    close(rootfd);
    if (deleted_count) *deleted_count = deleted;
    if (failed) {
        upload_err(err, err_len, "cleanup_partial_failure");
        return -1;
    }
    return 0;
}

void webd_upload_cleanup_status_get(struct webd_upload_cleanup_status *out)
{
    if (out)
        *out = g_cleanup_status;
}

int webd_upload_open_final_readonly(const char *owner_id, const char *upload_id,
                                    char *err, size_t err_len)
{
    int rootfd = -1, dirfd = -1, fd = -1, lockfd = -1;
    struct webd_upload_meta m;
    struct stat st;
    char actual[WEBD_UPLOAD_SHA256_HEX_LEN + 1];
    uint64_t actual_size = 0;
    if (!owner_id_ok(owner_id)) {
        upload_err(err, err_len, "bad_owner_id");
        return -1;
    }
    rootfd = open_root(err, err_len);
    if (rootfd < 0) return -1;
    dirfd = open_upload_dir_at(rootfd, upload_id, err, err_len);
    if (dirfd < 0) goto fail;
    lockfd = lock_upload_dir(dirfd, err, err_len);
    if (lockfd < 0) goto fail;
    if (meta_read_at(dirfd, &m, err, err_len) != 0) goto fail;
    if (strcmp(m.owner_id, owner_id)) {
        upload_err(err, err_len, "upload_not_found");
        goto fail;
    }
    if (strcmp(m.status, "finalized")) {
        upload_err(err, err_len, "upload_not_finalized");
        goto fail;
    }
    if (sha256_file_at(dirfd, actual, &actual_size, err, err_len) != 0)
        goto fail;
    if (actual_size != m.size_bytes || strcasecmp(actual, m.sha256)) {
        upload_err(err, err_len, "finalized_data_changed");
        goto fail;
    }
    fd = openat(dirfd, UPLOAD_DATA_NAME, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || (uint64_t)st.st_size != m.size_bytes) {
        if (fd >= 0) { close(fd); fd = -1; }
        upload_err(err, err_len, "data_open_failed");
    }
fail:
    if (lockfd >= 0) close(lockfd);
    if (dirfd >= 0) close(dirfd);
    if (rootfd >= 0) close(rootfd);
    return fd;
}

// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Durable config-backup store. See webd_backup_store.h for the retention
 * contract; the short version is: retention is by count, the count is set by the
 * user, and hitting it refuses the new backup instead of deleting an old one.
 *
 * Layout, one directory per backup below a single controlled root:
 *
 *   <root>/retention.txt              user-configured retention count
 *   <root>/lock                       store-wide lock (retention + publish)
 *   <root>/<backup_id>/data.bin       the artifact
 *   <root>/<backup_id>/meta.txt       metadata, version=1
 *
 * Caller-supplied paths are never accepted as identity: ids are generated here
 * and validated on every lookup. Nothing in this module expires anything by age.
 */
#define _GNU_SOURCE 1
#include "webd_backup_store.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#if defined(__has_include)
# if __has_include(<openssl/evp.h>)
#  define WEBD_BACKUP_HAVE_OPENSSL 1
#  include <openssl/evp.h>
# elif __has_include(<CommonCrypto/CommonDigest.h>)
#  define WEBD_BACKUP_HAVE_COMMONCRYPTO 1
#  include <CommonCrypto/CommonDigest.h>
# endif
#endif
#ifndef WEBD_BACKUP_HAVE_OPENSSL
#define WEBD_BACKUP_HAVE_OPENSSL 0
#endif
#ifndef WEBD_BACKUP_HAVE_COMMONCRYPTO
#define WEBD_BACKUP_HAVE_COMMONCRYPTO 0
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define BACKUP_DATA_NAME "data.bin"
#define BACKUP_META_NAME "meta.txt"
#define BACKUP_META_TMP "meta.tmp"
#define BACKUP_LOCK_NAME "lock"
#define BACKUP_RETENTION_NAME "retention.txt"
#define BACKUP_RETENTION_TMP "retention.tmp"
#define BACKUP_SCHEDULE_NAME "schedule.txt"
#define BACKUP_SCHEDULE_TMP "schedule.tmp"
#define BACKUP_LASTRUN_NAME "last-run.txt"
#define BACKUP_LASTRUN_TMP "last-run.tmp"
#define BACKUP_ROOT_MAX 512
#define BACKUP_META_MAX (16 * 1024)
#define BACKUP_SCAN_LIMIT 512

static char g_backup_root[BACKUP_ROOT_MAX] = WEBD_BACKUP_DEFAULT_ROOT;

static void backup_err(char *err, size_t err_len, const char *msg)
{
    if (err && err_len)
        snprintf(err, err_len, "%s", msg ? msg : "backup_store_error");
}

const char *webd_backup_store_root(void)
{
    return g_backup_root;
}

int webd_backup_store_set_root_for_tests(const char *root)
{
    size_t n = root ? strlen(root) : 0;
    if (!n || n >= sizeof(g_backup_root) || root[0] != '/')
        return -1;
    snprintf(g_backup_root, sizeof(g_backup_root), "%s", root);
    return 0;
}

int webd_backup_source_valid(const char *source)
{
    return source && (!strcmp(source, WEBD_BACKUP_SOURCE_MANUAL) ||
                      !strcmp(source, WEBD_BACKUP_SOURCE_SCHEDULED));
}

int webd_backup_frequency_valid(const char *frequency)
{
    return frequency && (!strcmp(frequency, WEBD_BACKUP_FREQ_DAILY) ||
                         !strcmp(frequency, WEBD_BACKUP_FREQ_WEEKLY));
}

static int backup_id_ok(const char *id)
{
    if (!id || strlen(id) != WEBD_BACKUP_ID_LEN || strncmp(id, "bak-", 4))
        return 0;
    for (size_t i = 4; i < WEBD_BACKUP_ID_LEN; i++)
        if (!isxdigit((unsigned char)id[i]))
            return 0;
    return 1;
}

static int owner_id_ok(const char *owner_id)
{
    size_t n = owner_id ? strlen(owner_id) : 0;

    if (!n || n > WEBD_BACKUP_OWNER_ID_LEN)
        return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)owner_id[i];
        if (c < 0x20 || c == 0x7f)
            return 0;
    }
    return 1;
}

static int filename_ok(const char *name)
{
    size_t n = name ? strlen(name) : 0;

    if (!n || n >= 256)
        return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)name[i];
        if (c < 0x20 || c == 0x7f || c == '/' || c == '\\')
            return 0;
    }
    return 1;
}

static int sha256_hex_ok(const char *hex)
{
    if (!hex || strlen(hex) != WEBD_BACKUP_SHA256_HEX_LEN)
        return 0;
    for (size_t i = 0; i < WEBD_BACKUP_SHA256_HEX_LEN; i++)
        if (!isxdigit((unsigned char)hex[i]))
            return 0;
    return 1;
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

static int mkdir_one_at(int parentfd, const char *name, mode_t mode)
{
    struct stat st;
    int fd;

    if (!name || !*name || strchr(name, '/'))
        return -1;
    fd = openat(parentfd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
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
    {
        int ok = (fstat(fd, &st) == 0 && S_ISDIR(st.st_mode));
        close(fd);
        return ok ? 0 : -1;
    }
}

static int mkdir_p_private(const char *path)
{
    char tmp[BACKUP_ROOT_MAX];
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

/*
 * Same guard the staging module applies: refuse to use the production root when
 * /data is not a distinct mount, so backups are never written to the overlay and
 * silently lost on upgrade.
 */
static int production_data_mount_ready(void)
{
    struct stat root_st;
    struct stat data_st;

    if (strcmp(g_backup_root, WEBD_BACKUP_DEFAULT_ROOT))
        return 1;
    return stat("/", &root_st) == 0 && stat("/data", &data_st) == 0 &&
           S_ISDIR(data_st.st_mode) && root_st.st_dev != data_st.st_dev;
}

static int open_root(char *err, size_t err_len)
{
    int fd;
    struct stat st;

    if (!production_data_mount_ready()) {
        backup_err(err, err_len, "data_mount_unavailable");
        return -1;
    }
    if (mkdir_p_private(g_backup_root) != 0) {
        backup_err(err, err_len, "root_unavailable");
        return -1;
    }
    fd = open(g_backup_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode)) {
        if (fd >= 0) close(fd);
        backup_err(err, err_len, "root_open_failed");
        return -1;
    }
    return fd;
}

static int lock_store(int rootfd, char *err, size_t err_len)
{
    int lockfd = openat(rootfd, BACKUP_LOCK_NAME,
                        O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);

    if (lockfd < 0) {
        backup_err(err, err_len, "lock_failed");
        return -1;
    }
    for (;;) {
        if (flock(lockfd, LOCK_EX) == 0)
            return lockfd;
        if (errno == EINTR)
            continue;
        close(lockfd);
        backup_err(err, err_len, "lock_failed");
        return -1;
    }
}

static int open_backup_dir_at(int rootfd, const char *id, char *err, size_t err_len)
{
    int dirfd;
    struct stat st;

    if (!backup_id_ok(id)) {
        backup_err(err, err_len, "bad_backup_id");
        return -1;
    }
    dirfd = openat(rootfd, id, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0 || fstat(dirfd, &st) != 0 || !S_ISDIR(st.st_mode)) {
        if (dirfd >= 0) close(dirfd);
        backup_err(err, err_len, "backup_not_found");
        return -1;
    }
    return dirfd;
}

static int gen_backup_id(char out[WEBD_BACKUP_ID_LEN + 1])
{
    unsigned char rnd[16];
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    ssize_t n;

    if (fd < 0) return -1;
    n = read(fd, rnd, sizeof(rnd));
    close(fd);
    if (n != (ssize_t)sizeof(rnd)) return -1;
    snprintf(out, WEBD_BACKUP_ID_LEN + 1,
             "bak-%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             rnd[0], rnd[1], rnd[2], rnd[3], rnd[4], rnd[5], rnd[6], rnd[7],
             rnd[8], rnd[9], rnd[10], rnd[11], rnd[12], rnd[13], rnd[14], rnd[15]);
    return 0;
}

static int sha256_fd(int fd, char hex[WEBD_BACKUP_SHA256_HEX_LEN + 1],
                     uint64_t *size_out, char *err, size_t err_len)
{
    unsigned char buf[8192];
    unsigned char digest[32];
    uint64_t total = 0;
    int rc = -1;
#if WEBD_BACKUP_HAVE_OPENSSL
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int digest_len = 0;

    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        backup_err(err, err_len, "sha256_init_failed");
        return -1;
    }
#elif WEBD_BACKUP_HAVE_COMMONCRYPTO
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
#else
#error "webd_backup_store requires OpenSSL EVP or CommonCrypto SHA256"
#endif

    if (lseek(fd, 0, SEEK_SET) < 0) {
        backup_err(err, err_len, "data_read_failed");
        goto out;
    }
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));

        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {
            backup_err(err, err_len, "data_read_failed");
            goto out;
        }
        if (n == 0) break;
#if WEBD_BACKUP_HAVE_OPENSSL
        if (EVP_DigestUpdate(ctx, buf, (size_t)n) != 1) {
            backup_err(err, err_len, "sha256_update_failed");
            goto out;
        }
#elif WEBD_BACKUP_HAVE_COMMONCRYPTO
        CC_SHA256_Update(&ctx, buf, (CC_LONG)n);
#endif
        total += (uint64_t)n;
        if (total > WEBD_BACKUP_MAX_BYTES) {
            backup_err(err, err_len, "backup_too_large");
            goto out;
        }
    }
#if WEBD_BACKUP_HAVE_OPENSSL
    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1 || digest_len != 32) {
        backup_err(err, err_len, "sha256_final_failed");
        goto out;
    }
#elif WEBD_BACKUP_HAVE_COMMONCRYPTO
    CC_SHA256_Final(digest, &ctx);
#endif
    for (unsigned int i = 0; i < 32; i++)
        snprintf(hex + i * 2, 3, "%02x", digest[i]);
    hex[WEBD_BACKUP_SHA256_HEX_LEN] = '\0';
    if (size_out) *size_out = total;
    rc = 0;
out:
#if WEBD_BACKUP_HAVE_OPENSSL
    EVP_MD_CTX_free(ctx);
#endif
    return rc;
}

static int meta_write_at(int dirfd, const struct webd_backup_meta *m,
                         char *err, size_t err_len)
{
    char filename_hex[sizeof(m->original_filename) * 2 + 1];
    char owner_hex[sizeof(m->owner_id) * 2 + 1];
    char buf[BACKUP_META_MAX];
    int fd;
    ssize_t need;

    hex_encode(m->original_filename, filename_hex, sizeof(filename_hex));
    hex_encode(m->owner_id, owner_hex, sizeof(owner_hex));
    need = snprintf(buf, sizeof(buf),
                    "version=1\n"
                    "backup_id=%s\n"
                    "owner_hex=%s\n"
                    "source=%s\n"
                    "filename_hex=%s\n"
                    "size_bytes=%llu\n"
                    "created_at=%lld\n"
                    "sha256=%s\n"
                    "source_version=%s\n",
                    m->backup_id, owner_hex, m->source, filename_hex,
                    (unsigned long long)m->size_bytes,
                    (long long)m->created_at, m->sha256, m->source_version);
    if (need < 0 || (size_t)need >= sizeof(buf)) {
        backup_err(err, err_len, "meta_too_large");
        return -1;
    }
    fd = openat(dirfd, BACKUP_META_TMP,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        backup_err(err, err_len, "meta_write_failed");
        return -1;
    }
    if (write_all_fd(fd, buf, (size_t)need) != 0 || fsync(fd) != 0) {
        close(fd);
        unlinkat(dirfd, BACKUP_META_TMP, 0);
        backup_err(err, err_len, "meta_write_failed");
        return -1;
    }
    close(fd);
    if (renameat(dirfd, BACKUP_META_TMP, dirfd, BACKUP_META_NAME) != 0) {
        unlinkat(dirfd, BACKUP_META_TMP, 0);
        backup_err(err, err_len, "meta_commit_failed");
        return -1;
    }
    (void)fsync(dirfd);
    return 0;
}

static int meta_parse(char *text, struct webd_backup_meta *m)
{
    char *save = NULL;
    char *line;
    unsigned version = 0;
    int have_id = 0, have_owner = 0, have_source = 0;
    int have_size = 0, have_created = 0;

    memset(m, 0, sizeof(*m));
    for (line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char *eq = strchr(line, '=');

        if (!eq)
            continue;
        *eq++ = '\0';
        if (!strcmp(line, "version")) {
            uint64_t v;
            if (parse_u64_strict(eq, &v) != 0 || v > 1000) return -1;
            version = (unsigned)v;
        }
        else if (!strcmp(line, "backup_id")) { snprintf(m->backup_id, sizeof(m->backup_id), "%s", eq); have_id = 1; }
        else if (!strcmp(line, "owner_hex")) { hex_decode(eq, m->owner_id, sizeof(m->owner_id)); have_owner = 1; }
        else if (!strcmp(line, "source")) { snprintf(m->source, sizeof(m->source), "%s", eq); have_source = 1; }
        else if (!strcmp(line, "filename_hex")) hex_decode(eq, m->original_filename, sizeof(m->original_filename));
        else if (!strcmp(line, "size_bytes")) { if (parse_u64_strict(eq, &m->size_bytes) != 0) return -1; have_size = 1; }
        else if (!strcmp(line, "created_at")) { if (parse_time_strict(eq, &m->created_at) != 0) return -1; have_created = 1; }
        else if (!strcmp(line, "sha256")) snprintf(m->sha256, sizeof(m->sha256), "%s", eq);
        else if (!strcmp(line, "source_version")) snprintf(m->source_version, sizeof(m->source_version), "%s", eq);
    }
    if (version != 1 || !have_id || !have_owner || !have_source || !have_size ||
        !have_created)
        return -1;
    if (!backup_id_ok(m->backup_id) || !owner_id_ok(m->owner_id) ||
        !webd_backup_source_valid(m->source) ||
        !filename_ok(m->original_filename) || !sha256_hex_ok(m->sha256))
        return -1;
    if (!m->size_bytes || m->size_bytes > WEBD_BACKUP_MAX_BYTES)
        return -1;
    return 0;
}

static int meta_read_at(int dirfd, struct webd_backup_meta *m,
                        char *err, size_t err_len)
{
    char buf[BACKUP_META_MAX];
    ssize_t n;
    int fd = openat(dirfd, BACKUP_META_NAME, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);

    if (fd < 0) {
        backup_err(err, err_len, "meta_missing");
        return -1;
    }
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        backup_err(err, err_len, "meta_read_failed");
        return -1;
    }
    buf[n] = '\0';
    if (meta_parse(buf, m) != 0) {
        backup_err(err, err_len, "meta_invalid");
        return -1;
    }
    return 0;
}

/* ── retention count ─────────────────────────────────────────────── */

static unsigned retention_read_at(int rootfd, int *configured)
{
    char buf[64];
    ssize_t n;
    uint64_t v;
    int fd;

    if (configured) *configured = 0;
    fd = openat(rootfd, BACKUP_RETENTION_NAME, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return WEBD_BACKUP_RETENTION_FALLBACK;
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return WEBD_BACKUP_RETENTION_FALLBACK;
    buf[n] = '\0';
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == ' '))
        buf[--n] = '\0';
    if (parse_u64_strict(buf, &v) != 0 ||
        v < WEBD_BACKUP_RETENTION_MIN || v > WEBD_BACKUP_RETENTION_MAX)
        return WEBD_BACKUP_RETENTION_FALLBACK;
    if (configured) *configured = 1;
    return (unsigned)v;
}

unsigned webd_backup_retention_get(int *configured)
{
    unsigned value;
    int rootfd;

    if (configured) *configured = 0;
    rootfd = open_root(NULL, 0);
    if (rootfd < 0)
        return WEBD_BACKUP_RETENTION_FALLBACK;
    value = retention_read_at(rootfd, configured);
    close(rootfd);
    return value;
}

int webd_backup_retention_set(unsigned count, char *err, size_t err_len)
{
    char buf[32];
    int rootfd = -1;
    int lockfd = -1;
    int fd = -1;
    int rc = -1;
    ssize_t need;

    if (count < WEBD_BACKUP_RETENTION_MIN || count > WEBD_BACKUP_RETENTION_MAX) {
        backup_err(err, err_len, "retention_count_out_of_range");
        return -1;
    }
    rootfd = open_root(err, err_len);
    if (rootfd < 0)
        return -1;
    lockfd = lock_store(rootfd, err, err_len);
    if (lockfd < 0)
        goto out;
    need = snprintf(buf, sizeof(buf), "%u\n", count);
    if (need < 0 || (size_t)need >= sizeof(buf)) {
        backup_err(err, err_len, "retention_write_failed");
        goto out;
    }
    fd = openat(rootfd, BACKUP_RETENTION_TMP,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0 || write_all_fd(fd, buf, (size_t)need) != 0 || fsync(fd) != 0) {
        if (fd >= 0) { close(fd); fd = -1; unlinkat(rootfd, BACKUP_RETENTION_TMP, 0); }
        backup_err(err, err_len, "retention_write_failed");
        goto out;
    }
    close(fd);
    fd = -1;
    if (renameat(rootfd, BACKUP_RETENTION_TMP, rootfd, BACKUP_RETENTION_NAME) != 0) {
        unlinkat(rootfd, BACKUP_RETENTION_TMP, 0);
        backup_err(err, err_len, "retention_commit_failed");
        goto out;
    }
    (void)fsync(rootfd);
    rc = 0;
out:
    if (fd >= 0) close(fd);
    if (lockfd >= 0) close(lockfd);
    if (rootfd >= 0) close(rootfd);
    return rc;
}

/* ── listing ─────────────────────────────────────────────────────── */

/* Small helper: atomically replace a root-level state file. */
static int root_file_write_atomic(int rootfd, const char *name, const char *tmpname,
                                  const char *buf, size_t len,
                                  char *err, size_t err_len)
{
    int fd = openat(rootfd, tmpname,
                    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);

    if (fd < 0 || write_all_fd(fd, buf, len) != 0 || fsync(fd) != 0) {
        if (fd >= 0) {
            close(fd);
            unlinkat(rootfd, tmpname, 0);
        }
        backup_err(err, err_len, "state_write_failed");
        return -1;
    }
    close(fd);
    if (renameat(rootfd, tmpname, rootfd, name) != 0) {
        unlinkat(rootfd, tmpname, 0);
        backup_err(err, err_len, "state_commit_failed");
        return -1;
    }
    (void)fsync(rootfd);
    return 0;
}

static ssize_t root_file_read(int rootfd, const char *name, char *buf, size_t buf_len)
{
    ssize_t n;
    int fd = openat(rootfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);

    if (fd < 0)
        return -1;
    n = read(fd, buf, buf_len - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';
    return n;
}

/* ── schedule ────────────────────────────────────────────────────── */

static void schedule_defaults(struct webd_backup_schedule *out)
{
    memset(out, 0, sizeof(*out));
    out->enabled = 0;
    snprintf(out->frequency, sizeof(out->frequency), "%s", WEBD_BACKUP_FREQ_DAILY);
    out->hour = 3;
    out->minute = 30;
    out->weekday = 0;
}

static int schedule_valid(const struct webd_backup_schedule *s)
{
    return s && webd_backup_frequency_valid(s->frequency) &&
           s->hour >= 0 && s->hour <= 23 &&
           s->minute >= 0 && s->minute <= 59 &&
           s->weekday >= 0 && s->weekday <= 6;
}

static void schedule_read_at(int rootfd, struct webd_backup_schedule *out)
{
    char buf[512];
    struct webd_backup_schedule s;
    char *save = NULL;
    char *line;
    ssize_t n;

    schedule_defaults(out);
    n = root_file_read(rootfd, BACKUP_SCHEDULE_NAME, buf, sizeof(buf));
    if (n <= 0)
        return;
    schedule_defaults(&s);
    for (line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char *eq = strchr(line, '=');
        uint64_t v;

        if (!eq)
            continue;
        *eq++ = '\0';
        if (!strcmp(line, "enabled"))
            s.enabled = (!strcmp(eq, "1") || !strcmp(eq, "true")) ? 1 : 0;
        else if (!strcmp(line, "frequency"))
            snprintf(s.frequency, sizeof(s.frequency), "%s", eq);
        else if (!strcmp(line, "hour")) {
            if (parse_u64_strict(eq, &v) != 0 || v > 23) return;
            s.hour = (int)v;
        } else if (!strcmp(line, "minute")) {
            if (parse_u64_strict(eq, &v) != 0 || v > 59) return;
            s.minute = (int)v;
        } else if (!strcmp(line, "weekday")) {
            if (parse_u64_strict(eq, &v) != 0 || v > 6) return;
            s.weekday = (int)v;
        } else if (!strcmp(line, "configured_at")) {
            if (parse_time_strict(eq, &s.configured_at) != 0) return;
        } else if (!strcmp(line, "owner_hex"))
            hex_decode(eq, s.owner_id, sizeof(s.owner_id));
    }
    if (!schedule_valid(&s))
        return;
    *out = s;
}

void webd_backup_schedule_get(struct webd_backup_schedule *out)
{
    int rootfd;

    if (!out)
        return;
    schedule_defaults(out);
    rootfd = open_root(NULL, 0);
    if (rootfd < 0)
        return;
    schedule_read_at(rootfd, out);
    close(rootfd);
}

int webd_backup_schedule_set(const struct webd_backup_schedule *in,
                             char *err, size_t err_len)
{
    char owner_hex[sizeof(in->owner_id) * 2 + 1];
    char buf[512];
    int rootfd = -1;
    int lockfd = -1;
    int rc = -1;
    ssize_t need;

    if (!schedule_valid(in)) {
        backup_err(err, err_len, "schedule_invalid");
        return -1;
    }
    if (in->owner_id[0] && !owner_id_ok(in->owner_id)) {
        backup_err(err, err_len, "bad_owner_id");
        return -1;
    }
    hex_encode(in->owner_id, owner_hex, sizeof(owner_hex));
    need = snprintf(buf, sizeof(buf),
                    "version=1\n"
                    "enabled=%d\n"
                    "frequency=%s\n"
                    "hour=%d\n"
                    "minute=%d\n"
                    "weekday=%d\n"
                    "configured_at=%lld\n"
                    "owner_hex=%s\n",
                    in->enabled ? 1 : 0, in->frequency, in->hour, in->minute,
                    in->weekday, (long long)time(NULL), owner_hex);
    if (need < 0 || (size_t)need >= sizeof(buf)) {
        backup_err(err, err_len, "schedule_too_large");
        return -1;
    }
    rootfd = open_root(err, err_len);
    if (rootfd < 0)
        return -1;
    lockfd = lock_store(rootfd, err, err_len);
    if (lockfd < 0)
        goto out;
    rc = root_file_write_atomic(rootfd, BACKUP_SCHEDULE_NAME, BACKUP_SCHEDULE_TMP,
                                buf, (size_t)need, err, err_len);
out:
    if (lockfd >= 0) close(lockfd);
    if (rootfd >= 0) close(rootfd);
    return rc;
}

/* ── last scheduled run ──────────────────────────────────────────── */

static int last_run_result_valid(const char *result)
{
    return result && (!strcmp(result, "ok") || !strcmp(result, "failed") ||
                      !strcmp(result, "skipped"));
}

static void last_run_read_at(int rootfd, struct webd_backup_last_run *out)
{
    char buf[512];
    struct webd_backup_last_run r;
    char *save = NULL;
    char *line;
    ssize_t n;

    memset(out, 0, sizeof(*out));
    n = root_file_read(rootfd, BACKUP_LASTRUN_NAME, buf, sizeof(buf));
    if (n <= 0)
        return;
    memset(&r, 0, sizeof(r));
    for (line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char *eq = strchr(line, '=');

        if (!eq)
            continue;
        *eq++ = '\0';
        if (!strcmp(line, "at")) {
            if (parse_time_strict(eq, &r.at) != 0) return;
        } else if (!strcmp(line, "result"))
            snprintf(r.result, sizeof(r.result), "%s", eq);
        else if (!strcmp(line, "error_hex"))
            hex_decode(eq, r.error, sizeof(r.error));
        else if (!strcmp(line, "backup_id"))
            snprintf(r.backup_id, sizeof(r.backup_id), "%s", eq);
    }
    if (!last_run_result_valid(r.result) || r.at <= 0)
        return;
    r.present = 1;
    *out = r;
}

void webd_backup_last_run_get(struct webd_backup_last_run *out)
{
    int rootfd;

    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    rootfd = open_root(NULL, 0);
    if (rootfd < 0)
        return;
    last_run_read_at(rootfd, out);
    close(rootfd);
}

int webd_backup_last_run_record(const char *result, const char *error,
                                const char *backup_id, time_t at,
                                char *err, size_t err_len)
{
    char error_hex[sizeof(((struct webd_backup_last_run *)0)->error) * 2 + 1];
    char buf[512];
    int rootfd = -1;
    int rc = -1;
    ssize_t need;

    if (!last_run_result_valid(result)) {
        backup_err(err, err_len, "bad_argument");
        return -1;
    }
    if (backup_id && *backup_id && !backup_id_ok(backup_id)) {
        backup_err(err, err_len, "bad_backup_id");
        return -1;
    }
    hex_encode(error ? error : "", error_hex, sizeof(error_hex));
    need = snprintf(buf, sizeof(buf),
                    "version=1\n"
                    "at=%lld\n"
                    "result=%s\n"
                    "error_hex=%s\n"
                    "backup_id=%s\n",
                    (long long)(at > 0 ? at : time(NULL)), result, error_hex,
                    backup_id ? backup_id : "");
    if (need < 0 || (size_t)need >= sizeof(buf)) {
        backup_err(err, err_len, "state_write_failed");
        return -1;
    }
    rootfd = open_root(err, err_len);
    if (rootfd < 0)
        return -1;
    /*
     * Deliberately not taking the store lock: this is called from the scheduler
     * while it already holds nothing, and the write itself is atomic via rename.
     * Recording an outcome must not be able to block on a long publish.
     */
    rc = root_file_write_atomic(rootfd, BACKUP_LASTRUN_NAME, BACKUP_LASTRUN_TMP,
                                buf, (size_t)need, err, err_len);
    close(rootfd);
    return rc;
}

/*
 * Most recent moment at or before `now` when the schedule should have fired.
 * Returns 0 when there is no such moment within the lookback window.
 */
static time_t schedule_prev_fire(const struct webd_backup_schedule *s, time_t now)
{
    int weekly = !strcmp(s->frequency, WEBD_BACKUP_FREQ_WEEKLY);

    /* Walk back day by day; 8 days covers both daily and weekly. */
    for (int back = 0; back <= 8; back++) {
        time_t probe = now - (time_t)back * 86400;
        struct tm tmv;
        time_t fire;

        if (!localtime_r(&probe, &tmv))
            return 0;
        tmv.tm_hour = s->hour;
        tmv.tm_min = s->minute;
        tmv.tm_sec = 0;
        tmv.tm_isdst = -1;
        fire = mktime(&tmv);
        if (fire == (time_t)-1 || fire > now)
            continue;
        if (weekly) {
            struct tm check;

            if (!localtime_r(&fire, &check))
                return 0;
            if (check.tm_wday != s->weekday)
                continue;
        }
        return fire;
    }
    return 0;
}

int webd_backup_schedule_due(time_t now)
{
    struct webd_backup_schedule s;
    struct webd_backup_last_run last;
    time_t fire;
    int rootfd = open_root(NULL, 0);

    if (rootfd < 0)
        return 0;
    schedule_read_at(rootfd, &s);
    last_run_read_at(rootfd, &last);
    close(rootfd);
    if (!s.enabled)
        return 0;
    fire = schedule_prev_fire(&s, now);
    if (!fire)
        return 0;
    /*
     * A window that closed before the schedule was configured is not owed a
     * backup. Without this, enabling a weekly schedule whose weekday already
     * passed this week would fire at once, which reads as "it backed up the
     * moment I saved settings" and is not what the user asked for.
     */
    if (s.configured_at > 0 && fire < s.configured_at)
        return 0;
    /*
     * Due when the latest scheduled moment has passed and we have not already
     * attempted it. Comparing against the attempt time (not just successes)
     * keeps a failing schedule from retrying in a tight loop every tick, while
     * still leaving the failure visible via last_run.
     */
    if (last.present && last.at >= fire)
        return 0;
    return 1;
}

static int meta_newest_first(const void *a, const void *b)
{
    const struct webd_backup_meta *x = a;
    const struct webd_backup_meta *y = b;

    if (x->created_at != y->created_at)
        return x->created_at < y->created_at ? 1 : -1;
    return strcmp(y->backup_id, x->backup_id);
}

static int list_at(int rootfd, struct webd_backup_list *out,
                   char *err, size_t err_len)
{
    struct webd_backup_meta *items = NULL;
    size_t count = 0;
    size_t cap = 0;
    size_t scanned = 0;
    int dupfd;
    DIR *dir;
    struct dirent *de;

    out->items = NULL;
    out->count = 0;
    dupfd = dup(rootfd);
    if (dupfd < 0) {
        backup_err(err, err_len, "root_open_failed");
        return -1;
    }
    dir = fdopendir(dupfd);
    if (!dir) {
        close(dupfd);
        backup_err(err, err_len, "root_open_failed");
        return -1;
    }
    rewinddir(dir);
    while ((de = readdir(dir)) != NULL) {
        struct webd_backup_meta m;
        int dirfd;

        if (scanned++ >= BACKUP_SCAN_LIMIT)
            break;
        if (!backup_id_ok(de->d_name))
            continue;
        dirfd = openat(rootfd, de->d_name,
                       O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (dirfd < 0)
            continue;
        if (meta_read_at(dirfd, &m, NULL, 0) != 0 ||
            strcmp(m.backup_id, de->d_name)) {
            close(dirfd);
            continue;
        }
        close(dirfd);
        if (count == cap) {
            size_t ncap = cap ? cap * 2 : 8;
            struct webd_backup_meta *tmp = realloc(items, ncap * sizeof(*tmp));

            if (!tmp) {
                free(items);
                closedir(dir);
                backup_err(err, err_len, "oom");
                return -1;
            }
            items = tmp;
            cap = ncap;
        }
        items[count++] = m;
    }
    closedir(dir);
    if (count > 1)
        qsort(items, count, sizeof(*items), meta_newest_first);
    out->items = items;
    out->count = count;
    return 0;
}

int webd_backup_list(struct webd_backup_list *out, char *err, size_t err_len)
{
    int rootfd;
    int rc;

    if (!out) {
        backup_err(err, err_len, "bad_argument");
        return -1;
    }
    rootfd = open_root(err, err_len);
    if (rootfd < 0)
        return -1;
    rc = list_at(rootfd, out, err, err_len);
    close(rootfd);
    return rc;
}

void webd_backup_list_free(struct webd_backup_list *list)
{
    if (!list)
        return;
    free(list->items);
    list->items = NULL;
    list->count = 0;
}

int webd_backup_count(char *err, size_t err_len)
{
    struct webd_backup_list list;
    int count;

    if (webd_backup_list(&list, err, err_len) != 0)
        return -1;
    count = (int)list.count;
    webd_backup_list_free(&list);
    return count;
}

/* ── retention gate ──────────────────────────────────────────────── */

static int retention_admit_at(int rootfd, unsigned *count_out, unsigned *limit_out,
                              char *err, size_t err_len)
{
    struct webd_backup_list list;
    unsigned limit = retention_read_at(rootfd, NULL);
    unsigned count;

    if (list_at(rootfd, &list, err, err_len) != 0)
        return -1;
    count = (unsigned)list.count;
    webd_backup_list_free(&list);
    if (count_out) *count_out = count;
    if (limit_out) *limit_out = limit;
    if (count >= limit) {
        backup_err(err, err_len, "backup_retention_limit_reached");
        return -1;
    }
    return 0;
}

int webd_backup_retention_admit(unsigned *count_out, unsigned *limit_out,
                                char *err, size_t err_len)
{
    int rootfd = open_root(err, err_len);
    int rc;

    if (rootfd < 0)
        return -1;
    rc = retention_admit_at(rootfd, count_out, limit_out, err, err_len);
    close(rootfd);
    return rc;
}

/* ── publish ─────────────────────────────────────────────────────── */

static int copy_fd_to_at(int srcfd, int dirfd, const char *name,
                         char *err, size_t err_len)
{
    char buf[65536];
    int dstfd = openat(dirfd, name,
                       O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);

    if (dstfd < 0) {
        backup_err(err, err_len, "data_write_failed");
        return -1;
    }
    if (lseek(srcfd, 0, SEEK_SET) < 0) {
        close(dstfd);
        backup_err(err, err_len, "data_read_failed");
        return -1;
    }
    for (;;) {
        ssize_t n = read(srcfd, buf, sizeof(buf));

        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {
            close(dstfd);
            backup_err(err, err_len, "data_read_failed");
            return -1;
        }
        if (n == 0) break;
        if (write_all_fd(dstfd, buf, (size_t)n) != 0) {
            close(dstfd);
            backup_err(err, err_len, "data_write_failed");
            return -1;
        }
    }
    if (fsync(dstfd) != 0) {
        close(dstfd);
        backup_err(err, err_len, "data_write_failed");
        return -1;
    }
    close(dstfd);
    return 0;
}

static int rmdir_backup_at(int rootfd, const char *id)
{
    int dirfd = openat(rootfd, id, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);

    if (dirfd >= 0) {
        unlinkat(dirfd, BACKUP_DATA_NAME, 0);
        unlinkat(dirfd, BACKUP_META_NAME, 0);
        unlinkat(dirfd, BACKUP_META_TMP, 0);
        close(dirfd);
    }
    return unlinkat(rootfd, id, AT_REMOVEDIR);
}

int webd_backup_publish(const char *owner_id, const char *source,
                        const char *original_filename,
                        const char *source_version,
                        const char *artifact_path,
                        struct webd_backup_meta *out,
                        char *err, size_t err_len)
{
    struct webd_backup_meta m;
    struct stat st;
    int rootfd = -1;
    int lockfd = -1;
    int dirfd = -1;
    int srcfd = -1;
    int datafd = -1;
    int created_dir = 0;
    int rc = -1;

    if (!owner_id_ok(owner_id) || !webd_backup_source_valid(source) ||
        !filename_ok(original_filename) || !artifact_path || !*artifact_path) {
        backup_err(err, err_len, "bad_argument");
        return -1;
    }
    memset(&m, 0, sizeof(m));
    snprintf(m.owner_id, sizeof(m.owner_id), "%s", owner_id);
    snprintf(m.source, sizeof(m.source), "%s", source);
    snprintf(m.original_filename, sizeof(m.original_filename), "%s", original_filename);
    snprintf(m.source_version, sizeof(m.source_version), "%s",
             source_version ? source_version : "");
    m.created_at = time(NULL);

    srcfd = open(artifact_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (srcfd < 0 || fstat(srcfd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size <= 0) {
        backup_err(err, err_len, "artifact_unreadable");
        goto out;
    }
    if ((uint64_t)st.st_size > WEBD_BACKUP_MAX_BYTES) {
        backup_err(err, err_len, "backup_too_large");
        goto out;
    }
    rootfd = open_root(err, err_len);
    if (rootfd < 0)
        goto out;
    lockfd = lock_store(rootfd, err, err_len);
    if (lockfd < 0)
        goto out;
    /*
     * Re-check under the lock. The caller checks before doing the expensive
     * snapshot so it can fail fast, but two concurrent creates would both pass
     * that early check; this is the one that actually decides.
     */
    if (retention_admit_at(rootfd, NULL, NULL, err, err_len) != 0)
        goto out;
    for (int attempt = 0; attempt < 4; attempt++) {
        if (gen_backup_id(m.backup_id) != 0) {
            backup_err(err, err_len, "id_generation_failed");
            goto out;
        }
        if (mkdirat(rootfd, m.backup_id, 0700) == 0) {
            created_dir = 1;
            break;
        }
        if (errno != EEXIST) {
            backup_err(err, err_len, "backup_dir_create_failed");
            goto out;
        }
    }
    if (!created_dir) {
        backup_err(err, err_len, "backup_dir_create_failed");
        goto out;
    }
    dirfd = openat(rootfd, m.backup_id,
                   O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0) {
        backup_err(err, err_len, "backup_dir_create_failed");
        goto out;
    }
    if (copy_fd_to_at(srcfd, dirfd, BACKUP_DATA_NAME, err, err_len) != 0)
        goto out;
    datafd = openat(dirfd, BACKUP_DATA_NAME, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (datafd < 0) {
        backup_err(err, err_len, "data_read_failed");
        goto out;
    }
    /* Digest what actually landed, not what we were handed. */
    if (sha256_fd(datafd, m.sha256, &m.size_bytes, err, err_len) != 0)
        goto out;
    if (!m.size_bytes || m.size_bytes != (uint64_t)st.st_size) {
        backup_err(err, err_len, "artifact_size_mismatch");
        goto out;
    }
    if (meta_write_at(dirfd, &m, err, err_len) != 0)
        goto out;
    (void)fsync(rootfd);
    if (out) *out = m;
    rc = 0;
out:
    if (datafd >= 0) close(datafd);
    if (dirfd >= 0) close(dirfd);
    if (rc != 0 && created_dir && rootfd >= 0)
        (void)rmdir_backup_at(rootfd, m.backup_id);
    if (srcfd >= 0) close(srcfd);
    if (lockfd >= 0) close(lockfd);
    if (rootfd >= 0) close(rootfd);
    return rc;
}

/* ── lookup / delete / read ──────────────────────────────────────── */

int webd_backup_get(const char *backup_id, struct webd_backup_meta *out,
                    char *err, size_t err_len)
{
    struct webd_backup_meta m;
    int rootfd = -1;
    int dirfd = -1;
    int rc = -1;

    rootfd = open_root(err, err_len);
    if (rootfd < 0)
        return -1;
    dirfd = open_backup_dir_at(rootfd, backup_id, err, err_len);
    if (dirfd < 0)
        goto out;
    if (meta_read_at(dirfd, &m, err, err_len) != 0)
        goto out;
    if (strcmp(m.backup_id, backup_id)) {
        backup_err(err, err_len, "meta_invalid");
        goto out;
    }
    if (out) *out = m;
    rc = 0;
out:
    if (dirfd >= 0) close(dirfd);
    if (rootfd >= 0) close(rootfd);
    return rc;
}

int webd_backup_delete(const char *backup_id, char *err, size_t err_len)
{
    int rootfd = -1;
    int lockfd = -1;
    int dirfd = -1;
    int rc = -1;

    if (!backup_id_ok(backup_id)) {
        backup_err(err, err_len, "bad_backup_id");
        return -1;
    }
    rootfd = open_root(err, err_len);
    if (rootfd < 0)
        return -1;
    lockfd = lock_store(rootfd, err, err_len);
    if (lockfd < 0)
        goto out;
    dirfd = open_backup_dir_at(rootfd, backup_id, err, err_len);
    if (dirfd < 0)
        goto out;
    close(dirfd);
    dirfd = -1;
    if (rmdir_backup_at(rootfd, backup_id) != 0) {
        backup_err(err, err_len, "backup_delete_failed");
        goto out;
    }
    (void)fsync(rootfd);
    rc = 0;
out:
    if (dirfd >= 0) close(dirfd);
    if (lockfd >= 0) close(lockfd);
    if (rootfd >= 0) close(rootfd);
    return rc;
}

int webd_backup_open_readonly(const char *backup_id, char *err, size_t err_len)
{
    struct webd_backup_meta m;
    char actual[WEBD_BACKUP_SHA256_HEX_LEN + 1];
    uint64_t actual_size = 0;
    int rootfd = -1;
    int dirfd = -1;
    int fd = -1;

    rootfd = open_root(err, err_len);
    if (rootfd < 0)
        return -1;
    dirfd = open_backup_dir_at(rootfd, backup_id, err, err_len);
    if (dirfd < 0)
        goto fail;
    if (meta_read_at(dirfd, &m, err, err_len) != 0)
        goto fail;
    fd = openat(dirfd, BACKUP_DATA_NAME, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        backup_err(err, err_len, "data_missing");
        goto fail;
    }
    if (sha256_fd(fd, actual, &actual_size, err, err_len) != 0)
        goto fail;
    if (actual_size != m.size_bytes || strcmp(actual, m.sha256)) {
        backup_err(err, err_len, "backup_integrity_failed");
        goto fail;
    }
    if (lseek(fd, 0, SEEK_SET) < 0) {
        backup_err(err, err_len, "data_read_failed");
        goto fail;
    }
    close(dirfd);
    close(rootfd);
    return fd;
fail:
    if (fd >= 0) close(fd);
    if (dirfd >= 0) close(dirfd);
    if (rootfd >= 0) close(rootfd);
    return -1;
}

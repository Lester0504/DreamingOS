
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <dirent.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#if defined(__linux__)
#include <sys/sysmacros.h>
#endif
#include <sys/wait.h>
#include <net/if.h>
#include "jmx_system.h"

#ifndef JMX_SYSTEM_MOUNT_CONTRACT_ONLY
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <time.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <json-c/json.h>
#include <uci.h>
#include "jmx.h"
#include "jmx_user.h"
#include "jmx_netlink.h"
#include "jmx_ubus.h"
#include "jmx_config.h"
#include "jmx_utils.h"
#include "jmx_network.h"
#include "jmx_uci.h"
#include "jmx_netconfig_db.h"
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#ifndef O_PATH
#define O_PATH O_RDONLY
#endif

#define JMX_FSTAB_DEFAULT_PATH "/etc/config/fstab"
#define JMX_RELEASE_PATH "/etc/dreamingwrt-release.json"
#define JMX_RELEASE_MAX_BYTES (1024 * 1024)

#ifndef JMX_CROND_SPECIAL_TIMES
#define JMX_CROND_SPECIAL_TIMES 0
#endif

static int jmx_mount_path_under(const char *path, const char *root);

#if defined(JMX_SYSTEM_MOUNT_CONTRACT_ONLY) && defined(JMX_SYSTEM_MOUNT_TEST_HOOKS)
extern ssize_t jmx_system_mount_contract_write(int fd, const void *buf, size_t len);
extern int jmx_system_mount_contract_fsync(int fd);
extern void jmx_system_mount_contract_before_readback(const char *path);
#define JMX_MOUNT_WRITE(fd, buf, len) jmx_system_mount_contract_write((fd), (buf), (len))
#define JMX_MOUNT_FSYNC(fd) jmx_system_mount_contract_fsync((fd))
#define JMX_MOUNT_BEFORE_READBACK(path) jmx_system_mount_contract_before_readback((path))
#else
#define JMX_MOUNT_WRITE(fd, buf, len) write((fd), (buf), (len))
#define JMX_MOUNT_FSYNC(fd) fsync((fd))
#define JMX_MOUNT_BEFORE_READBACK(path) do { (void)(path); } while (0)
#endif

static int jmx_mount_verify_block_device(const char *path, const char *dev_root,
                                         unsigned int expected_major,
                                         unsigned int expected_minor)
{
    struct stat st;
    char resolved[PATH_MAX], resolved_root[PATH_MAX];

    if (!path || !dev_root || !realpath(path, resolved) ||
        !realpath(dev_root, resolved_root) || !jmx_mount_path_under(resolved, resolved_root) ||
        stat(resolved, &st) != 0 || !S_ISBLK(st.st_mode))
        return 0;
    return (unsigned int)major(st.st_rdev) == expected_major &&
           (unsigned int)minor(st.st_rdev) == expected_minor;
}

static int jmx_mount_remove_created_target(const struct jmx_system_mount_txn_opts *opts,
                                           const char *target);

static void jmx_mount_set_err(char *err, size_t err_len, const char *msg)
{
    if (err && err_len > 0) {
        snprintf(err, err_len, "%s", msg ? msg : "error");
    }
}

static int jmx_mount_copy_checked(char *dst, size_t dst_len, const char *src)
{
    size_t len;

    if (!dst || !dst_len || !src || (len = strlen(src)) >= dst_len)
        return -1;
    memcpy(dst, src, len + 1);
    return 0;
}

static int jmx_mount_join_path(char *dst, size_t dst_len,
                               const char *base, const char *name)
{
    size_t base_len, name_len;

    if (!dst || !dst_len || !base || !name)
        return -1;
    base_len = strlen(base);
    name_len = strlen(name);
    if (!base_len || base_len > dst_len - 1 || name_len > dst_len - 1 - base_len ||
        base_len + 1 > dst_len - 1 - name_len)
        return -1;
    memcpy(dst, base, base_len);
    dst[base_len] = '/';
    memcpy(dst + base_len + 1, name, name_len + 1);
    return 0;
}

static int jmx_mount_is_safe_abs_path(const char *s, size_t max_len)
{
    const char *segment;
    size_t i, n;

    if (!s || s[0] != '/')
        return 0;
    n = strlen(s);
    if (n == 0 || n >= max_len)
        return 0;
    if (n == 1)
        return 1;

    segment = s + 1;
    for (i = 1; i <= n; i++) {
        size_t segment_len;

        if (i == n || s[i] == '/') {
            segment_len = (size_t)(s + i - segment);
            if (segment_len == 0 ||
                (segment_len == 1 && segment[0] == '.') ||
                (segment_len == 2 && segment[0] == '.' && segment[1] == '.'))
                return 0;
            segment = s + i + 1;
            continue;
        }
        {
            unsigned char c = (unsigned char)s[i];
            if (isalnum(c) || c == '_' || c == '-' || c == '.' || c == ':' || c == '+')
                continue;
            return 0;
        }
    }
    return 1;
}

static int jmx_mount_is_safe_token(const char *s, size_t max_len)
{
    size_t i, n;

    if (!s)
        return 0;
    n = strlen(s);
    if (n == 0 || n >= max_len)
        return 0;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (isalnum(c) || c == '_' || c == '-' || c == '.' || c == ':' || c == '+' ||
            c == '=' || c == '@' || c == '%' || c == '/')
            continue;
        return 0;
    }
    return 1;
}

static int jmx_mount_valid_uuid_body(const char *s)
{
    size_t i, n;
    int hex_count = 0;

    if (!s) return 0;
    n = strlen(s);
    if (n < 8 || n > 64)
        return 0;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (isxdigit(c)) {
            hex_count++;
            continue;
        }
        if (c == '-')
            continue;
        return 0;
    }
    return hex_count >= 8;
}

int jmx_system_mount_validate_source(const char *source, char *err, size_t err_len)
{
    const char *v;

    if (!source || !source[0]) {
        jmx_mount_set_err(err, err_len, "missing_source");
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    if (strlen(source) >= JMX_SYSTEM_MOUNT_SOURCE_MAX) {
        jmx_mount_set_err(err, err_len, "source_too_long");
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    if (!strncmp(source, "UUID=", 5)) {
        v = source + 5;
        if (!jmx_mount_valid_uuid_body(v)) {
            jmx_mount_set_err(err, err_len, "invalid_uuid");
            return JMX_SYSTEM_MOUNT_ERR_INVALID;
        }
        return JMX_SYSTEM_MOUNT_OK;
    }
    if (!strncmp(source, "LABEL=", 6)) {
        v = source + 6;
        if (!jmx_mount_is_safe_token(v, 96) || strchr(v, '/')) {
            jmx_mount_set_err(err, err_len, "invalid_label");
            return JMX_SYSTEM_MOUNT_ERR_INVALID;
        }
        return JMX_SYSTEM_MOUNT_OK;
    }
    if (!strncmp(source, "/dev/disk/by-uuid/", 18)) {
        v = source + 18;
        if (!jmx_mount_is_safe_abs_path(source, JMX_SYSTEM_MOUNT_SOURCE_MAX) ||
            strchr(v, '/') || !jmx_mount_valid_uuid_body(v)) {
            jmx_mount_set_err(err, err_len, "invalid_by_uuid_path");
            return JMX_SYSTEM_MOUNT_ERR_INVALID;
        }
        return JMX_SYSTEM_MOUNT_OK;
    }
    if (!strncmp(source, "/dev/disk/by-label/", 19)) {
        v = source + 19;
        if (!jmx_mount_is_safe_abs_path(source, JMX_SYSTEM_MOUNT_SOURCE_MAX) ||
            strchr(v, '/') || !jmx_mount_is_safe_token(v, 96)) {
            jmx_mount_set_err(err, err_len, "invalid_by_label_path");
            return JMX_SYSTEM_MOUNT_ERR_INVALID;
        }
        return JMX_SYSTEM_MOUNT_OK;
    }
    if (!strncmp(source, "/dev/", 5)) {
        if (!jmx_mount_is_safe_abs_path(source, JMX_SYSTEM_MOUNT_SOURCE_MAX) ||
            strstr(source, "/../") || !strcmp(source, "/dev") ||
            !strncmp(source, "/dev/mtd", 8) || !strncmp(source, "/dev/loop", 9) ||
            !strncmp(source, "/dev/mapper/", 12)) {
            jmx_mount_set_err(err, err_len, "unsafe_device");
            return JMX_SYSTEM_MOUNT_ERR_INVALID;
        }
        return JMX_SYSTEM_MOUNT_OK;
    }
    jmx_mount_set_err(err, err_len, "source_must_be_device_uuid_or_label");
    return JMX_SYSTEM_MOUNT_ERR_INVALID;
}

int jmx_system_mount_validate_target(const char *target, char *err, size_t err_len)
{
    static const char *danger[] = {
        "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64",
        "/overlay", "/proc", "/rom", "/root", "/sbin", "/sys", "/tmp",
        "/usr", "/var", "/www", "/data", "/mnt", "/media", NULL
    };
    int i;

    if (!target || !target[0]) {
        jmx_mount_set_err(err, err_len, "missing_target");
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    if (!jmx_mount_is_safe_abs_path(target, JMX_SYSTEM_MOUNT_TARGET_MAX)) {
        jmx_mount_set_err(err, err_len, "invalid_target_path");
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    for (i = 0; danger[i]; i++) {
        if (!strcmp(target, danger[i])) {
            jmx_mount_set_err(err, err_len, "protected_mountpoint");
            return JMX_SYSTEM_MOUNT_ERR_INVALID;
        }
    }
    if (strncmp(target, "/mnt/", 5) && strncmp(target, "/media/", 7)) {
        jmx_mount_set_err(err, err_len, "mountpoint_must_be_under_mnt_or_media");
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    if (!strncmp(target, "/mnt/root", 9) || !strncmp(target, "/mnt/data", 9) ||
        !strncmp(target, "/media/root", 11) || !strncmp(target, "/media/data", 11)) {
        jmx_mount_set_err(err, err_len, "protected_root_or_data_slot");
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    return JMX_SYSTEM_MOUNT_OK;
}

int jmx_system_mount_validate_fstype(const char *fstype, char *err, size_t err_len)
{
    static const char *allowed[] = {
        "auto", "ext2", "ext3", "ext4", "f2fs", "btrfs", "xfs",
        "vfat", "exfat", "ntfs", "ntfs3", "swap", NULL
    };
    int i;

    if (!fstype || !fstype[0]) {
        jmx_mount_set_err(err, err_len, "missing_fstype");
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    if (!jmx_mount_is_safe_token(fstype, JMX_SYSTEM_MOUNT_FSTYPE_MAX) || strchr(fstype, '/')) {
        jmx_mount_set_err(err, err_len, "invalid_fstype");
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    for (i = 0; allowed[i]; i++) {
        if (!strcmp(fstype, allowed[i]))
            return JMX_SYSTEM_MOUNT_OK;
    }
    jmx_mount_set_err(err, err_len, "unsupported_fstype");
    return JMX_SYSTEM_MOUNT_ERR_INVALID;
}

int jmx_system_mount_validate_options(const char *options, char *err, size_t err_len)
{
    char buf[JMX_SYSTEM_MOUNT_OPTIONS_MAX];
    char *save = NULL;
    char *tok;

    if (!options || !options[0])
        return JMX_SYSTEM_MOUNT_OK;
    if (strlen(options) >= sizeof(buf)) {
        jmx_mount_set_err(err, err_len, "options_too_long");
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    if (strstr(options, ",,") || options[0] == ',' || options[strlen(options) - 1] == ',') {
        jmx_mount_set_err(err, err_len, "invalid_options_list");
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    snprintf(buf, sizeof(buf), "%s", options);
    for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        if (!jmx_mount_is_safe_token(tok, 64) || strchr(tok, '/') ||
            !strcmp(tok, "bind") || !strcmp(tok, "rbind") ||
            !strcmp(tok, "move") || !strcmp(tok, "remount") ||
            !strcmp(tok, "dev") || !strcmp(tok, "suid") || !strcmp(tok, "exec")) {
            jmx_mount_set_err(err, err_len, "unsafe_mount_option");
            return JMX_SYSTEM_MOUNT_ERR_INVALID;
        }
    }
    return JMX_SYSTEM_MOUNT_OK;
}

int jmx_system_mount_validate_spec(const struct jmx_system_mount_spec *spec,
                                   char *err, size_t err_len)
{
    int rc;

    if (!spec) {
        jmx_mount_set_err(err, err_len, "missing_spec");
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    rc = jmx_system_mount_validate_source(spec->source, err, err_len);
    if (rc) return rc;
    rc = jmx_system_mount_validate_target(spec->target, err, err_len);
    if (rc) return rc;
    rc = jmx_system_mount_validate_fstype(spec->fstype, err, err_len);
    if (rc) return rc;
    return jmx_system_mount_validate_options(spec->options, err, err_len);
}

int jmx_system_mount_render_fstab_entry(const struct jmx_system_mount_spec *spec,
                                        char *out, size_t out_len,
                                        char *err, size_t err_len)
{
    const char *opts;
    int n;

    if (!out || out_len == 0) {
        jmx_mount_set_err(err, err_len, "missing_output_buffer");
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    out[0] = '\0';
    if (jmx_system_mount_validate_spec(spec, err, err_len) != 0)
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    opts = spec->options[0] ? spec->options : "rw,noatime,nodev,nosuid,noexec";
    n = snprintf(out, out_len,
                 "config mount\n"
                 "\toption enabled '%d'\n"
                 "\toption target '%s'\n"
                 "\toption device '%s'\n"
                 "\toption fstype '%s'\n"
                 "\toption options '%s'\n"
                 "\toption enabled_fsck '%d'\n",
                 spec->enabled ? 1 : 0,
                 spec->target, spec->source, spec->fstype, opts,
                 spec->check_fs ? 1 : 0);
    if (n < 0 || (size_t)n >= out_len) {
        jmx_mount_set_err(err, err_len, "render_too_large");
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    return JMX_SYSTEM_MOUNT_OK;
}

static int jmx_mount_read_file(const char *path, char **out, size_t *len_out)
{
    FILE *fp;
    char *buf;
    long len;
    size_t got;

    *out = NULL;
    if (len_out) *len_out = 0;
    fp = fopen(path, "rb");
    if (!fp) {
        if (errno == ENOENT) {
            *out = strdup("");
            return *out ? 0 : -1;
        }
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return -1; }
    len = ftell(fp);
    if (len < 0 || len > (4 * 1024 * 1024)) { fclose(fp); errno = EFBIG; return -1; }
    rewind(fp);
    buf = calloc(1, (size_t)len + 1);
    if (!buf) { fclose(fp); return -1; }
    got = fread(buf, 1, (size_t)len, fp);
    fclose(fp);
    if (got != (size_t)len) { free(buf); return -1; }
    *out = buf;
    if (len_out) *len_out = got;
    return 0;
}

static int jmx_mount_write_all(int fd, const char *content, size_t len)
{
    size_t off = 0;

    while (off < len) {
        ssize_t wr = JMX_MOUNT_WRITE(fd, content + off, len - off);

        if (wr < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (wr == 0 || (size_t)wr > len - off) {
            errno = EIO;
            return -1;
        }
        off += (size_t)wr;
    }
    return 0;
}

static int jmx_mount_fsync_retry(int fd)
{
    int rc;

    do {
        rc = JMX_MOUNT_FSYNC(fd);
    } while (rc != 0 && errno == EINTR);
    return rc;
}

static int jmx_mount_fsync_parent(const char *path)
{
    char parent[PATH_MAX];
    const char *slash;
    size_t len;
    int fd;
    int saved_errno;

    if (!path || !path[0]) {
        errno = EINVAL;
        return -1;
    }
    slash = strrchr(path, '/');
    if (!slash) {
        snprintf(parent, sizeof(parent), ".");
    } else if (slash == path) {
        snprintf(parent, sizeof(parent), "/");
    } else {
        len = (size_t)(slash - path);
        if (len >= sizeof(parent)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(parent, path, len);
        parent[len] = '\0';
    }

    fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    if (jmx_mount_fsync_retry(fd) != 0) {
        saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return close(fd);
}

static int jmx_mount_path_exists(const char *path)
{
    struct stat st;
    int rc;

    do {
        rc = lstat(path, &st);
    } while (rc != 0 && errno == EINTR);
    if (rc == 0)
        return 1;
    if (errno == ENOENT)
        return 0;
    return -1;
}

static int jmx_mount_write_file_atomic_mode(const char *path, const char *content,
                                            size_t len, mode_t mode,
                                            int *renamed_out)
{
    char tmp[PATH_MAX];
    int fd = -1;
    int rc;
    int saved_errno;
    int n;

    if (renamed_out)
        *renamed_out = 0;
    if (!path || !path[0] || (!content && len != 0)) {
        errno = EINVAL;
        return -1;
    }
    n = snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", path);
    if (n < 0 || (size_t)n >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    fd = mkstemp(tmp);
    if (fd < 0)
        return -1;
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
        saved_errno = errno;
        close(fd);
        unlink(tmp);
        errno = saved_errno;
        return -1;
    }
    do {
        rc = fchmod(fd, mode);
    } while (rc != 0 && errno == EINTR);
    if (rc != 0 || jmx_mount_write_all(fd, content, len) != 0 ||
        jmx_mount_fsync_retry(fd) != 0) {
        saved_errno = errno;
        close(fd);
        unlink(tmp);
        errno = saved_errno;
        return -1;
    }
    if (close(fd) != 0) {
        saved_errno = errno;
        fd = -1;
        unlink(tmp);
        errno = saved_errno;
        return -1;
    }
    fd = -1;

    do {
        rc = rename(tmp, path);
    } while (rc != 0 && errno == EINTR);
    if (rc != 0) {
        saved_errno = errno;
        unlink(tmp);
        errno = saved_errno;
        return -1;
    }
    if (renamed_out)
        *renamed_out = 1;
    if (jmx_mount_fsync_parent(path) != 0)
        return -1;
    return 0;
}

static int jmx_mount_write_file_atomic(const char *path, const char *content, size_t len,
                                       int *renamed_out)
{
    return jmx_mount_write_file_atomic_mode(path, content, len,
                                            S_IRUSR | S_IWUSR, renamed_out);
}

static int jmx_mount_remove_file_durable(const char *path)
{
    int rc;

    do {
        rc = unlink(path);
    } while (rc != 0 && errno == EINTR);
    if (rc != 0 && errno != ENOENT)
        return -1;
    if (rc == 0 && jmx_mount_fsync_parent(path) != 0)
        return -1;
    return 0;
}

static int jmx_mount_readback_matches(const char *path, const char *expected,
                                      size_t expected_len)
{
    char *readback = NULL;
    size_t readback_len = 0;
    int match;

    if (jmx_mount_read_file(path, &readback, &readback_len) != 0)
        return 0;
    match = readback_len == expected_len &&
            (expected_len == 0 || !memcmp(readback, expected, expected_len));
    free(readback);
    return match;
}

static int jmx_mount_readback_matches_mode(const char *path, const char *expected,
                                           size_t expected_len, mode_t mode)
{
    struct stat st;

    if (!jmx_mount_readback_matches(path, expected, expected_len))
        return 0;
    return lstat(path, &st) == 0 && (st.st_mode & 07777) == (mode & 07777);
}

static int jmx_mount_restore_previous(const char *path, const char *old, size_t old_len,
                                      int old_existed,
                                      struct jmx_system_mount_txn_result *result)
{
    int exists;

    if (old_existed) {
        if (jmx_mount_write_file_atomic(path, old, old_len, NULL) != 0 ||
            !jmx_mount_readback_matches(path, old, old_len))
            return -1;
    } else {
        if (jmx_mount_remove_file_durable(path) != 0)
            return -1;
        exists = jmx_mount_path_exists(path);
        if (exists != 0)
            return -1;
    }
    if (result)
        result->rolled_back = 1;
    return 0;
}

static int jmx_mount_write_backup(const char *path, const char *old, size_t old_len,
                                  int old_existed, char *backup_path, size_t backup_len)
{
    char backup[PATH_MAX];
    int n;

    if (backup_path && backup_len)
        backup_path[0] = '\0';
    if (!old_existed)
        return 0;
    n = snprintf(backup, sizeof(backup), "%s.dreamingwrt.bak", path);
    if (n < 0 || (size_t)n >= sizeof(backup)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (jmx_mount_write_file_atomic(backup, old, old_len, NULL) != 0 ||
        !jmx_mount_readback_matches(backup, old, old_len))
        return -1;
    if (backup_path && backup_len) {
        n = snprintf(backup_path, backup_len, "%s", backup);
        if (n < 0 || (size_t)n >= backup_len) {
            backup_path[0] = '\0';
            errno = ENAMETOOLONG;
            return -1;
        }
    }
    return 0;
}

static char *jmx_mount_remove_matching_block(const char *content,
                                             const struct jmx_system_mount_spec *spec,
                                             int *removed)
{
    const char *p = content ? content : "";
    size_t cap = strlen(p) + 1;
    char *out = calloc(1, cap);
    size_t out_len = 0;

    if (removed) *removed = 0;
    if (!out) return NULL;
    while (*p) {
        const char *line_end = strchr(p, '\n');
        const char *next = line_end ? line_end + 1 : p + strlen(p);
        if (!strncmp(p, "config mount", 12)) {
            const char *block_start = p;
            const char *block_end = next;
            int hit = 0;
            while (*block_end && strncmp(block_end, "config ", 7) != 0) {
                const char *be = strchr(block_end, '\n');
                block_end = be ? be + 1 : block_end + strlen(block_end);
            }
            {
                size_t blen = (size_t)(block_end - block_start);
                char *block = calloc(1, blen + 1);
                if (!block) { free(out); return NULL; }
                memcpy(block, block_start, blen);
                {
                    char target_pat[JMX_SYSTEM_MOUNT_TARGET_MAX + 32];
                    char device_pat[JMX_SYSTEM_MOUNT_SOURCE_MAX + 32];
                    snprintf(target_pat, sizeof(target_pat), "option target '%s'", spec->target);
                    snprintf(device_pat, sizeof(device_pat), "option device '%s'", spec->source);
                    if ((spec->target[0] && strstr(block, target_pat)) ||
                        (spec->source[0] && strstr(block, device_pat)))
                        hit = 1;
                }
                free(block);
            }
            if (hit) {
                if (removed) *removed = 1;
                p = block_end;
                continue;
            }
            next = block_end;
        }
        if (out_len + (size_t)(next - p) + 1 > cap) {
            cap = out_len + (size_t)(next - p) + 4096;
            out = realloc(out, cap);
            if (!out) return NULL;
        }
        memcpy(out + out_len, p, (size_t)(next - p));
        out_len += (size_t)(next - p);
        out[out_len] = '\0';
        p = next;
    }
    return out;
}

static int jmx_mount_write_updated_fstab(const struct jmx_system_mount_spec *spec,
                                         const struct jmx_system_mount_txn_opts *opts,
                                         struct jmx_system_mount_txn_result *result,
                                         int delete_only)
{
    const char *path = opts && opts->fstab_path ? opts->fstab_path : JMX_FSTAB_DEFAULT_PATH;
    char entry[1024];
    char err[JMX_SYSTEM_MOUNT_ERROR_MAX] = {0};
    char *old = NULL;
    char *base = NULL;
    char *newc = NULL;
    size_t old_len = 0;
    size_t need;
    int removed = 0;
    int dry = opts && opts->dry_run;
    int old_existed;
    int renamed = 0;
    int rollback_failed;

    if (result) memset(result, 0, sizeof(*result));
    if (jmx_system_mount_validate_spec(spec, err, sizeof(err)) != 0) {
        if (result) snprintf(result->error, sizeof(result->error), "%s", err);
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    if (!delete_only &&
        jmx_system_mount_render_fstab_entry(spec, entry, sizeof(entry), err, sizeof(err)) != 0) {
        if (result) snprintf(result->error, sizeof(result->error), "%s", err);
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    old_existed = jmx_mount_path_exists(path);
    if (old_existed < 0 || jmx_mount_read_file(path, &old, &old_len) != 0) {
        if (result) snprintf(result->error, sizeof(result->error), "read_fstab_failed");
        return JMX_SYSTEM_MOUNT_ERR_IO;
    }
    base = jmx_mount_remove_matching_block(old, spec, &removed);
    if (!base) {
        free(old);
        if (result) snprintf(result->error, sizeof(result->error), "edit_fstab_failed");
        return JMX_SYSTEM_MOUNT_ERR_IO;
    }
    if (delete_only) {
        newc = base;
        base = NULL;
    } else {
        need = strlen(base) + strlen(entry) + 4;
        newc = calloc(1, need);
        if (!newc) {
            free(old); free(base);
            if (result) snprintf(result->error, sizeof(result->error), "oom");
            return JMX_SYSTEM_MOUNT_ERR_IO;
        }
        snprintf(newc, need, "%s%s%s", base,
                 (base[0] && base[strlen(base) - 1] != '\n') ? "\n" : "",
                 entry);
    }
    if (!strcmp(old, newc)) {
        if (result) result->changed = 0;
        free(old); free(base); free(newc);
        return JMX_SYSTEM_MOUNT_OK;
    }
    if (result) result->changed = 1;
    if (!dry) {
        if (jmx_mount_write_backup(path, old, old_len, old_existed,
                                   result ? result->backup_path : NULL,
                                   result ? sizeof(result->backup_path) : 0) != 0) {
            if (result) snprintf(result->error, sizeof(result->error), "backup_fstab_failed");
            free(old); free(base); free(newc);
            return JMX_SYSTEM_MOUNT_ERR_IO;
        }
        if (jmx_mount_write_file_atomic(path, newc, strlen(newc), &renamed) != 0) {
            rollback_failed = renamed &&
                jmx_mount_restore_previous(path, old, old_len, old_existed, result) != 0;
            if (result) {
                snprintf(result->error, sizeof(result->error), "%s",
                         rollback_failed ? "write_fstab_rollback_failed" : "write_fstab_failed");
            }
            free(old); free(base); free(newc);
            return rollback_failed ? JMX_SYSTEM_MOUNT_ERR_ROLLBACK : JMX_SYSTEM_MOUNT_ERR_IO;
        }
        JMX_MOUNT_BEFORE_READBACK(path);
        if (!jmx_mount_readback_matches(path, newc, strlen(newc))) {
            rollback_failed =
                jmx_mount_restore_previous(path, old, old_len, old_existed, result) != 0;
            if (result) {
                snprintf(result->error, sizeof(result->error), "%s",
                         rollback_failed ? "readback_rollback_failed" : "readback_mismatch");
            }
            free(old); free(base); free(newc);
            return rollback_failed ? JMX_SYSTEM_MOUNT_ERR_ROLLBACK : JMX_SYSTEM_MOUNT_ERR_IO;
        }
    }
    (void)removed;
    free(old); free(base); free(newc);
    return JMX_SYSTEM_MOUNT_OK;
}

static int jmx_mount_remove_created_target(const struct jmx_system_mount_txn_opts *opts,
                                           const char *target);

int jmx_system_mount_save_point(const struct jmx_system_mount_spec *spec,
                                const struct jmx_system_mount_txn_opts *opts,
                                struct jmx_system_mount_txn_result *result)
{
    const char *path = opts && opts->fstab_path ? opts->fstab_path : JMX_FSTAB_DEFAULT_PATH;
    char *old = NULL;
    size_t old_len = 0;
    int old_existed = 0;
    struct jmx_system_mount_txn_result local;
    int rc;

    if (!result) result = &local;
    memset(result, 0, sizeof(*result));
    if (opts && opts->execute_mount && !(opts && opts->dry_run)) {
        old_existed = jmx_mount_path_exists(path);
        if (old_existed < 0 || jmx_mount_read_file(path, &old, &old_len) != 0) {
            snprintf(result->error, sizeof(result->error), "read_fstab_failed");
            free(old);
            return JMX_SYSTEM_MOUNT_ERR_IO;
        }
    }
    rc = jmx_mount_write_updated_fstab(spec, opts, result, 0);
    if (rc != 0) {
        free(old);
        return rc;
    }
    if (opts && opts->execute_mount) {
        struct jmx_system_mount_txn_result exec_res;
        rc = jmx_system_mount_exec_mount(spec, opts, &exec_res);
        result->executed = exec_res.executed;
        if (exec_res.error[0])
            snprintf(result->error, sizeof(result->error), "%s", exec_res.error);
    }
    if (rc != 0 && old && result->changed && !(opts && opts->dry_run)) {
        if (jmx_mount_restore_previous(path, old, old_len, old_existed, result) != 0) {
            snprintf(result->error, sizeof(result->error), "mount_rollback_failed");
            rc = JMX_SYSTEM_MOUNT_ERR_ROLLBACK;
        }
    }
    free(old);
    return rc;
}

int jmx_system_mount_save_batch(const struct jmx_system_mount_spec *specs, size_t count,
                                const struct jmx_system_mount_txn_opts *opts,
                                struct jmx_system_mount_txn_result *result)
{
    const char *path = opts && opts->fstab_path ? opts->fstab_path : JMX_FSTAB_DEFAULT_PATH;
    struct jmx_system_mount_txn_result local;
    char *old = NULL, *next = NULL;
    size_t old_len = 0;
    int old_existed, rc = JMX_SYSTEM_MOUNT_OK;
    size_t i;

    if (!result) result = &local;
    memset(result, 0, sizeof(*result));
    if (!specs || !count || count > 32) {
        snprintf(result->error, sizeof(result->error), "invalid_batch");
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    old_existed = jmx_mount_path_exists(path);
    if (old_existed < 0 || jmx_mount_read_file(path, &old, &old_len) != 0) {
        snprintf(result->error, sizeof(result->error), "read_fstab_failed");
        return JMX_SYSTEM_MOUNT_ERR_IO;
    }
    next = strdup(old ? old : "");
    if (!next) { rc = JMX_SYSTEM_MOUNT_ERR_IO; goto out; }
    for (i = 0; i < count; i++) {
        char entry[1024], err[JMX_SYSTEM_MOUNT_ERROR_MAX] = {0};
        char *base, *combined;
        size_t base_len, entry_len, total;
        int removed = 0;

        if (jmx_system_mount_render_fstab_entry(&specs[i], entry, sizeof(entry),
                                                err, sizeof(err)) != 0) {
            snprintf(result->error, sizeof(result->error), "%s", err);
            rc = JMX_SYSTEM_MOUNT_ERR_INVALID;
            goto out;
        }
        base = jmx_mount_remove_matching_block(next, &specs[i], &removed);
        if (!base) { rc = JMX_SYSTEM_MOUNT_ERR_IO; goto out; }
        base_len = strlen(base);
        entry_len = strlen(entry);
        total = base_len + (base_len && base[base_len - 1] != '\n' ? 1 : 0) + entry_len + 2;
        combined = calloc(1, total);
        if (!combined) { free(base); rc = JMX_SYSTEM_MOUNT_ERR_IO; goto out; }
        memcpy(combined, base, base_len);
        if (base_len && base[base_len - 1] != '\n') combined[base_len++] = '\n';
        memcpy(combined + base_len, entry, entry_len);
        base_len += entry_len;
        if (!base_len || combined[base_len - 1] != '\n') combined[base_len++] = '\n';
        combined[base_len] = '\0';
        free(base); free(next); next = combined;
    }
    result->changed = old_len != strlen(next) || (old_len && memcmp(old, next, old_len));
    if (!result->changed || (opts && opts->dry_run)) goto out;
    if (jmx_mount_write_backup(path, old, old_len, old_existed,
                               result->backup_path, sizeof(result->backup_path)) != 0) {
        snprintf(result->error, sizeof(result->error), "backup_failed");
        rc = JMX_SYSTEM_MOUNT_ERR_IO;
        goto out;
    }
    {
        int renamed = 0;
        int write_rc = jmx_mount_write_file_atomic(path, next, strlen(next), &renamed);
        if (write_rc == 0) JMX_MOUNT_BEFORE_READBACK(path);
        if (write_rc != 0 || !jmx_mount_readback_matches(path, next, strlen(next))) {
            int rollback_failed = renamed &&
                jmx_mount_restore_previous(path, old, old_len, old_existed, result) != 0;
            snprintf(result->error, sizeof(result->error), "%s",
                     rollback_failed ? "batch_write_rollback_failed" : "batch_write_failed");
            rc = rollback_failed ? JMX_SYSTEM_MOUNT_ERR_ROLLBACK : JMX_SYSTEM_MOUNT_ERR_IO;
        }
    }
out:
    free(old); free(next);
    return rc;
}

int jmx_system_mount_apply_batch(const struct jmx_system_mount_spec *specs, size_t count,
                                 const struct jmx_system_mount_txn_opts *opts,
                                 struct jmx_system_mount_batch_result *result)
{
    const char *path = opts && opts->fstab_path ? opts->fstab_path : JMX_FSTAB_DEFAULT_PATH;
    struct jmx_system_mount_txn_opts config_opts;
    char *old = NULL;
    size_t old_len = 0, i;
    int created_targets[32] = {0};
    int old_existed, rc;

    if (!result) return JMX_SYSTEM_MOUNT_ERR_INVALID;
    memset(result, 0, sizeof(*result));
    result->failed_index = (size_t)-1;
    if (!specs || !count || count > 32) {
        snprintf(result->error, sizeof(result->error), "invalid_batch");
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    old_existed = jmx_mount_path_exists(path);
    if (old_existed < 0 || jmx_mount_read_file(path, &old, &old_len) != 0) {
        snprintf(result->error, sizeof(result->error), "read_fstab_failed");
        return JMX_SYSTEM_MOUNT_ERR_IO;
    }
    memset(&config_opts, 0, sizeof(config_opts));
    if (opts) config_opts = *opts;
    config_opts.execute_mount = 0;
    config_opts.execute_umount = 0;
    rc = jmx_system_mount_save_batch(specs, count, &config_opts, &result->config);
    if (rc != 0 || (opts && opts->dry_run) || !(opts && opts->execute_mount)) {
        if (rc != 0) snprintf(result->error, sizeof(result->error), "%s", result->config.error);
        free(old);
        return rc;
    }
    for (i = 0; i < count; i++) {
        struct jmx_system_mount_txn_result mount_result;
        rc = jmx_system_mount_exec_mount(&specs[i], opts, &mount_result);
        if (rc == 0) {
            created_targets[i] = mount_result.target_created;
            result->mounted_count++;
            continue;
        }
        snprintf(result->error, sizeof(result->error), "%s",
                 mount_result.error[0] ? mount_result.error : "mount_failed");
        result->failed_index = i;
        break;
    }
    if (rc != 0) {
        int mounts_ok = 1, directories_ok = 1, config_ok;
        size_t rollback_index = result->mounted_count;
        result->rollback_attempted = 1;
        while (rollback_index > 0) {
            struct jmx_system_mount_txn_result umount_result;
            size_t idx = --rollback_index;
            if (jmx_system_mount_exec_umount(&specs[idx], opts, &umount_result) != 0) {
                mounts_ok = 0;
            } else if (created_targets[idx] &&
                       jmx_mount_remove_created_target(opts, specs[idx].target) != 0) {
                directories_ok = 0;
            }
        }
        config_ok = jmx_mount_restore_previous(path, old, old_len, old_existed,
                                               &result->config) == 0;
        result->mounts_rollback_succeeded = mounts_ok;
        result->directories_rollback_succeeded = directories_ok;
        result->config_rollback_succeeded = config_ok;
        result->rollback_succeeded = mounts_ok && directories_ok && config_ok;
        if (!result->rollback_succeeded) {
            snprintf(result->error, sizeof(result->error), "batch_mount_rollback_failed");
            rc = JMX_SYSTEM_MOUNT_ERR_ROLLBACK;
        }
    }
    free(old);
    return rc;
}

int jmx_system_mount_delete_point(const struct jmx_system_mount_spec *spec,
                                  const struct jmx_system_mount_txn_opts *opts,
                                  struct jmx_system_mount_txn_result *result)
{
    struct jmx_system_mount_txn_result local;
    int executed = 0;
    int rc;

    if (!result) result = &local;
    memset(result, 0, sizeof(*result));
    if (opts && opts->execute_umount) {
        struct jmx_system_mount_txn_result exec_res;
        rc = jmx_system_mount_exec_umount(spec, opts, &exec_res);
        executed = exec_res.executed;
        result->executed = executed;
        if (exec_res.error[0])
            snprintf(result->error, sizeof(result->error), "%s", exec_res.error);
        if (rc != 0)
            return rc;
    }
    rc = jmx_mount_write_updated_fstab(spec, opts, result, 1);
    result->executed = executed;
    return rc;
}

static int jmx_mount_spawn_wait(char *const argv[])
{
    pid_t pid = fork();
    int status;

    if (pid < 0)
        return -1;
    if (pid == 0) {
        execv(argv[0], argv);
        _exit(127);
    }
    do {
        if (waitpid(pid, &status, 0) < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        break;
    } while (1);
    if (!WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

static int jmx_mount_target_location(const struct jmx_system_mount_txn_opts *opts,
                                     const char *target, const char **base_path,
                                     const char **relative)
{
    if (!strncmp(target, "/mnt/", 5)) {
        *base_path = opts && opts->mnt_root ? opts->mnt_root : "/mnt";
        *relative = target + 5;
        return 0;
    }
    if (!strncmp(target, "/media/", 7)) {
        *base_path = opts && opts->media_root ? opts->media_root : "/media";
        *relative = target + 7;
        return 0;
    }
    return -1;
}

static int jmx_mount_prepare_target(const struct jmx_system_mount_txn_opts *opts,
                                    const char *target, int dry_run, int *created)
{
    struct stat st;
    const char *base_path, *relative;
    char resolved[PATH_MAX];
    char relative_buf[JMX_SYSTEM_MOUNT_TARGET_MAX], *segment, *save = NULL;
    int dirfd = -1, nextfd = -1;

    if (created) *created = 0;
    if (jmx_mount_target_location(opts, target, &base_path, &relative) != 0)
        return -1;
    if (!(opts && (opts->mnt_root || opts->media_root)) && lstat(target, &st) == 0) {
        if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode))
            return -1;
        if (!realpath(target, resolved) || strcmp(resolved, target))
            return -1;
        return 0;
    }
    if (!(opts && (opts->mnt_root || opts->media_root)) && errno != ENOENT)
        return -1;
    if (dry_run)
        return 0;
    if (snprintf(relative_buf, sizeof(relative_buf), "%s", relative) >= (int)sizeof(relative_buf))
        return -1;
    dirfd = open(base_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0) return -1;
    for (segment = strtok_r(relative_buf, "/", &save); segment;
         segment = strtok_r(NULL, "/", &save)) {
        int last = save == NULL || *save == '\0';
        nextfd = openat(dirfd, segment, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (nextfd < 0 && errno == ENOENT && last) {
            if (mkdirat(dirfd, segment, 0755) != 0) goto fail;
            if (created) *created = 1;
            nextfd = openat(dirfd, segment, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (nextfd < 0) {
                (void)unlinkat(dirfd, segment, AT_REMOVEDIR);
                if (created) *created = 0;
                goto fail;
            }
        }
        if (nextfd < 0) goto fail;
        close(dirfd); dirfd = nextfd; nextfd = -1;
    }
    if (dirfd >= 0) close(dirfd);
    return 0;
fail:
    if (nextfd >= 0) close(nextfd);
    if (dirfd >= 0) close(dirfd);
    return -1;
}

static int jmx_mount_remove_created_target(const struct jmx_system_mount_txn_opts *opts,
                                           const char *target)
{
    const char *base_path, *relative;
    char relative_buf[JMX_SYSTEM_MOUNT_TARGET_MAX];
    char leaf_name[JMX_SYSTEM_MOUNT_TARGET_MAX];
    char *leaf, *segment, *save = NULL;
    int dirfd, nextfd, rc;
    if (jmx_mount_target_location(opts, target, &base_path, &relative) != 0 ||
        snprintf(relative_buf, sizeof(relative_buf), "%s", relative) >= (int)sizeof(relative_buf))
        return -1;
    leaf = strrchr(relative_buf, '/');
    if (leaf) {
        *leaf++ = '\0';
        if (!leaf[0]) return -1;
    } else {
        leaf = relative_buf;
    }
    if (snprintf(leaf_name, sizeof(leaf_name), "%s", leaf) >= (int)sizeof(leaf_name))
        return -1;
    if (leaf == relative_buf)
        relative_buf[0] = '\0';
    dirfd = open(base_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0) return -1;
    for (segment = relative_buf[0] ? strtok_r(relative_buf, "/", &save) : NULL;
         segment; segment = strtok_r(NULL, "/", &save)) {
        nextfd = openat(dirfd, segment, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (nextfd < 0) { close(dirfd); return -1; }
        close(dirfd);
        dirfd = nextfd;
    }
    rc = unlinkat(dirfd, leaf_name, AT_REMOVEDIR);
    close(dirfd);
    return rc;
}

static int jmx_mount_proc_has_target_path(const char *path, const char *target)
{
    FILE *fp;
    char dev[256], mnt[256], fs[64], opts[256];
    int dump = 0, pass = 0;

    if (!target || !target[0])
        return 0;
    fp = fopen(path && path[0] ? path : "/proc/self/mounts", "r");
    if (!fp && (!path || !path[0]))
        fp = fopen("/proc/mounts", "r");
    if (!fp)
        return -1;
    while (fscanf(fp, "%255s %255s %63s %255s %d %d\n",
                  dev, mnt, fs, opts, &dump, &pass) == 6) {
        (void)dev; (void)fs; (void)opts;
        if (!strcmp(mnt, target)) {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

static int jmx_mount_proc_has_target(const struct jmx_system_mount_txn_opts *opts,
                                     const char *target)
{
    return jmx_mount_proc_has_target_path(opts ? opts->mounts_path : NULL, target);
}

int jmx_system_mount_exec_mount(const struct jmx_system_mount_spec *spec,
                                const struct jmx_system_mount_txn_opts *opts,
                                struct jmx_system_mount_txn_result *result)
{
    char err[JMX_SYSTEM_MOUNT_ERROR_MAX] = {0};
    const char *bin = opts && opts->mount_bin ? opts->mount_bin : "/bin/mount";
    const char *o = spec && spec->options[0] ? spec->options : "rw,noatime,nodev,nosuid,noexec";
    char *argv[] = {(char *)bin, "-t", (char *)spec->fstype, "-o", (char *)o,
                    (char *)spec->source, (char *)spec->target, NULL};
    int rc, created = 0;

    if (result) memset(result, 0, sizeof(*result));
    if (jmx_system_mount_validate_spec(spec, err, sizeof(err)) != 0) {
        if (result) snprintf(result->error, sizeof(result->error), "%s", err);
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    if (jmx_mount_prepare_target(opts, spec->target, opts && opts->dry_run, &created) != 0) {
        if (result) snprintf(result->error, sizeof(result->error), "unsafe_or_uncreatable_target");
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    if (result) result->target_created = created;
    if (opts && opts->dry_run) return JMX_SYSTEM_MOUNT_OK;
    rc = jmx_mount_spawn_wait(argv);
    if (result) result->executed = 1;
    if (rc != 0) {
        if (created) (void)jmx_mount_remove_created_target(opts, spec->target);
        if (result) snprintf(result->error, sizeof(result->error), "mount_failed:%d", rc);
        return JMX_SYSTEM_MOUNT_ERR_EXEC;
    }
    rc = jmx_mount_proc_has_target(opts, spec->target);
    if (rc != 1) {
        struct jmx_system_mount_txn_result cleanup;
        (void)jmx_system_mount_exec_umount(spec, opts, &cleanup);
        if (created) (void)jmx_mount_remove_created_target(opts, spec->target);
        if (result) {
            snprintf(result->error, sizeof(result->error), "%s",
                     rc < 0 ? "mount_readback_failed" : "mount_readback_missing");
        }
        return JMX_SYSTEM_MOUNT_ERR_EXEC;
    }
    return JMX_SYSTEM_MOUNT_OK;
}

int jmx_system_mount_exec_umount(const struct jmx_system_mount_spec *spec,
                                 const struct jmx_system_mount_txn_opts *opts,
                                 struct jmx_system_mount_txn_result *result)
{
    char err[JMX_SYSTEM_MOUNT_ERROR_MAX] = {0};
    const char *bin = opts && opts->umount_bin ? opts->umount_bin : "/bin/umount";
    char *argv[] = {(char *)bin, (char *)spec->target, NULL};
    int rc;

    if (result) memset(result, 0, sizeof(*result));
    if (jmx_system_mount_validate_spec(spec, err, sizeof(err)) != 0) {
        if (result) snprintf(result->error, sizeof(result->error), "%s", err);
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    if (opts && opts->dry_run)
        return JMX_SYSTEM_MOUNT_OK;
    rc = jmx_mount_spawn_wait(argv);
    if (result) result->executed = 1;
    if (rc != 0) {
        if (result) snprintf(result->error, sizeof(result->error), "umount_failed:%d", rc);
        return JMX_SYSTEM_MOUNT_ERR_EXEC;
    }
    rc = jmx_mount_proc_has_target(opts, spec->target);
    if (rc != 0) {
        if (result) {
            snprintf(result->error, sizeof(result->error), "%s",
                     rc < 0 ? "umount_readback_failed" : "umount_readback_still_mounted");
        }
        return JMX_SYSTEM_MOUNT_ERR_EXEC;
    }
    return JMX_SYSTEM_MOUNT_OK;
}

static const char *jmx_mount_opt_path(const char *value, const char *def)
{
    return value && value[0] ? value : def;
}

static int jmx_mount_read_line(const char *path, char *out, size_t out_len)
{
    FILE *fp;
    size_t n;

    if (!path || !out || out_len < 2)
        return -1;
    fp = fopen(path, "r");
    if (!fp)
        return -1;
    if (!fgets(out, (int)out_len, fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    n = strlen(out);
    while (n && (out[n - 1] == '\n' || out[n - 1] == '\r'))
        out[--n] = '\0';
    return 0;
}

static int jmx_mount_name_safe(const char *name)
{
    size_t i, n;

    if (!name || !(n = strlen(name)) || n >= 64)
        return 0;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)name[i];
        if (!isalnum(c) && c != '_' && c != '-' && c != '.')
            return 0;
    }
    return strcmp(name, ".") && strcmp(name, "..");
}

static const char *jmx_mount_basename(const char *path)
{
    const char *slash = path ? strrchr(path, '/') : NULL;
    return slash ? slash + 1 : path;
}

static void jmx_mount_parent_from_sysfs(const char *entry_path, const char *name,
                                        int is_partition, char *out, size_t out_len)
{
    char resolved[PATH_MAX];
    char *slash;

    out[0] = '\0';
    if (!is_partition || !realpath(entry_path, resolved))
        return;
    slash = strrchr(resolved, '/');
    if (!slash)
        return;
    *slash = '\0';
    slash = strrchr(resolved, '/');
    if (slash && strcmp(slash + 1, name) && jmx_mount_name_safe(slash + 1))
        snprintf(out, out_len, "%s", slash + 1);
}

static int jmx_mount_probe_index(struct jmx_system_mount_probe *probes, size_t count,
                                 const char *name)
{
    size_t i;
    for (i = 0; i < count; i++)
        if (!strcmp(probes[i].name, name))
            return (int)i;
    return -1;
}

static void jmx_mount_apply_stable_dir(const char *dir_path, int uuid,
                                       struct jmx_system_mount_probe *probes, size_t count)
{
    DIR *dir;
    struct dirent *de;

    dir = opendir(dir_path);
    if (!dir)
        return;
    while ((de = readdir(dir)) != NULL) {
        char link_path[PATH_MAX], resolved[PATH_MAX];
        const char *name;
        int idx;

        if (de->d_name[0] == '.' ||
            !jmx_mount_is_safe_token(de->d_name, JMX_SYSTEM_MOUNT_ID_MAX) ||
            strchr(de->d_name, '/'))
            continue;
        if (snprintf(link_path, sizeof(link_path), "%s/%s", dir_path, de->d_name) >=
            (int)sizeof(link_path) || !realpath(link_path, resolved))
            continue;
        name = jmx_mount_basename(resolved);
        idx = jmx_mount_probe_index(probes, count, name);
        if (idx < 0)
            continue;
        if (uuid)
            (void)jmx_mount_copy_checked(probes[idx].uuid,
                                         sizeof(probes[idx].uuid), de->d_name);
        else
            (void)jmx_mount_copy_checked(probes[idx].label,
                                         sizeof(probes[idx].label), de->d_name);
    }
    closedir(dir);
}

enum jmx_mount_capture_rc {
    JMX_MOUNT_CAPTURE_OK = 0,
    JMX_MOUNT_CAPTURE_ERROR = -1,
    JMX_MOUNT_CAPTURE_TIMEOUT = -2,
    JMX_MOUNT_CAPTURE_OVERSIZE = -3
};

static long long jmx_mount_monotonic_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static int jmx_mount_capture(char *const argv[], char *out, size_t out_len, int timeout_ms)
{
    int fds[2], status = 0, waited = 0, eof = 0;
    pid_t pid;
    size_t used = 0;
    long long deadline;
    int capture_rc = JMX_MOUNT_CAPTURE_OK;

    if (!argv || !argv[0] || !out || out_len < 2 || pipe(fds) != 0)
        return -1;
    pid = fork();
    if (pid < 0) {
        close(fds[0]); close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        int nullfd;
        (void)setpgid(0, 0);
        close(fds[0]);
        if (dup2(fds[1], STDOUT_FILENO) < 0)
            _exit(127);
        close(fds[1]);
        nullfd = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (nullfd >= 0) {
            dup2(nullfd, STDERR_FILENO);
            close(nullfd);
        }
        execv(argv[0], argv);
        _exit(127);
    }
    (void)setpgid(pid, pid);
    close(fds[1]);
    (void)fcntl(fds[0], F_SETFD, fcntl(fds[0], F_GETFD, 0) | FD_CLOEXEC);
    (void)fcntl(fds[0], F_SETFL, fcntl(fds[0], F_GETFL, 0) | O_NONBLOCK);
    deadline = jmx_mount_monotonic_ms() + (timeout_ms > 0 ? timeout_ms : 2000);
    for (;;) {
        struct pollfd pfd;
        char extra;
        long long now = jmx_mount_monotonic_ms();
        int remain = (int)(deadline - now);
        int full = used + 1 >= out_len;
        ssize_t n;
        pid_t wait_rc;
        if (remain <= 0) { capture_rc = JMX_MOUNT_CAPTURE_TIMEOUT; break; }
        if (!waited) {
            wait_rc = waitpid(pid, &status, WNOHANG);
            if (wait_rc == pid) {
                waited = 1;
            } else if (wait_rc < 0 && errno != EINTR) {
                capture_rc = JMX_MOUNT_CAPTURE_ERROR;
                break;
            }
        }
        if (waited && eof) break;
        if (eof) {
            struct timespec pause = {0, 10 * 1000 * 1000};
            nanosleep(&pause, NULL);
            continue;
        }
        pfd.fd = fds[0]; pfd.events = POLLIN | POLLHUP; pfd.revents = 0;
        if (poll(&pfd, 1, remain > 100 ? 100 : remain) < 0) {
            if (errno == EINTR) continue;
            capture_rc = JMX_MOUNT_CAPTURE_ERROR; break;
        }
        if (!(pfd.revents & (POLLIN | POLLHUP | POLLERR))) continue;
        n = read(fds[0], full ? &extra : out + used, full ? 1 : out_len - used - 1);
        if (n > 0) {
            if (full) { capture_rc = JMX_MOUNT_CAPTURE_OVERSIZE; break; }
            used += (size_t)n;
            continue;
        }
        if (n == 0) { eof = 1; continue; }
        if (errno == EINTR || errno == EAGAIN) continue;
        capture_rc = JMX_MOUNT_CAPTURE_ERROR; break;
    }
    out[used] = '\0';
    close(fds[0]);
    if (capture_rc != JMX_MOUNT_CAPTURE_OK && !waited) {
        if (kill(-pid, SIGKILL) != 0 && errno != ESRCH)
            (void)kill(pid, SIGKILL);
    }
    if (!waited) {
        do {
            if (waitpid(pid, &status, 0) >= 0) { waited = 1; break; }
        } while (errno == EINTR);
    }
    if (capture_rc != JMX_MOUNT_CAPTURE_OK) return capture_rc;
    return waited && WIFEXITED(status) && WEXITSTATUS(status) == 0 ?
           JMX_MOUNT_CAPTURE_OK : JMX_MOUNT_CAPTURE_ERROR;
}

static int jmx_mount_is_protected_target(const char *target)
{
    static const char *exact[] = {
        "/", "/rom", "/overlay", "/data", "/boot", "/boot/efi",
        "/efi", "/etc/config", "/opt/dreamingwrt", NULL
    };
    int i;
    for (i = 0; exact[i]; i++)
        if (!strcmp(target, exact[i])) return 1;
    return !strncmp(target, "/overlay/", 9) || !strncmp(target, "/data/", 6) ||
           !strncmp(target, "/rom/", 5) || !strncmp(target, "/boot/", 6);
}

static int jmx_mount_slot_name(const char *value)
{
    char lower[JMX_SYSTEM_MOUNT_ID_MAX];
    size_t i, n;

    if (!value || !(n = strlen(value)) || n >= sizeof(lower))
        return 0;
    for (i = 0; i <= n; i++) lower[i] = (char)tolower((unsigned char)value[i]);
    return !strcmp(lower, "rootfs") || !strcmp(lower, "rootfs_a") ||
           !strcmp(lower, "rootfs_b") || !strcmp(lower, "rootfs-a") ||
           !strcmp(lower, "rootfs-b") || strstr(lower, "dreamingwrt-root") ||
           !strcmp(lower, "esp") || !strcmp(lower, "efi") ||
           !strcmp(lower, "dreamingwrt-esp") || !strcmp(lower, "dreamingwrt-data");
}

static int jmx_mount_auto_device_class_rejected(const char *name)
{
    static const char *prefixes[] = {
        "loop", "ram", "zram", "dm-", "md", "mtd", "nbd", "sr", "fd", NULL
    };
    int i;
    if (!name) return 1;
    for (i = 0; prefixes[i]; i++)
        if (!strncmp(name, prefixes[i], strlen(prefixes[i]))) return 1;
    return 0;
}

static int jmx_mount_path_under(const char *path, const char *root)
{
    size_t n = root ? strlen(root) : 0;
    return n && !strncmp(path, root, n) && (path[n] == '\0' || path[n] == '/');
}

static int jmx_mount_sysroot(const char *sysdir, char *out, size_t out_len)
{
    static const char suffix[] = "/class/block";
    size_t n;
    char tmp[PATH_MAX];
    if (!sysdir || !out || !out_len ||
        snprintf(tmp, sizeof(tmp), "%s", sysdir) >= (int)sizeof(tmp)) return -1;
    n = strlen(tmp);
    if (n > sizeof(suffix) - 1 && !strcmp(tmp + n - (sizeof(suffix) - 1), suffix))
        tmp[n - (sizeof(suffix) - 1)] = '\0';
    if (!realpath(tmp, out)) return -1;
    return strlen(out) < out_len ? 0 : -1;
}

static void jmx_mount_mark_duplicate_stable_sources(struct jmx_system_mount_probe *probes,
                                                    size_t count)
{
    size_t i, j;
    for (i = 0; i < count; i++) {
        if (!probes[i].stable_source[0]) continue;
        for (j = i + 1; j < count; j++) {
            if (strcmp(probes[i].stable_source, probes[j].stable_source)) continue;
            probes[i].config_eligible = probes[i].mount_eligible = 0;
            probes[j].config_eligible = probes[j].mount_eligible = 0;
            snprintf(probes[i].excluded_reason, sizeof(probes[i].excluded_reason),
                     "duplicate_stable_source");
            snprintf(probes[j].excluded_reason, sizeof(probes[j].excluded_reason),
                     "duplicate_stable_source");
        }
    }
}

static void jmx_mount_apply_mountinfo(const char *path,
                                      struct jmx_system_mount_probe *probes, size_t count)
{
    FILE *fp = fopen(path, "r");
    char line[4096];
    if (!fp) return;
    while (fgets(line, sizeof(line), fp)) {
        unsigned int major_num, minor_num;
        char root[4096], target[4096], source[4096] = {0}, resolved[PATH_MAX];
        char *sep;
        size_t i;
        if (sscanf(line, "%*u %*u %u:%u %4095s %4095s", &major_num, &minor_num,
                   root, target) != 4)
            continue;
        (void)root;
        sep = strstr(line, " - ");
        if (sep) (void)sscanf(sep + 3, "%*4095s %4095s", source);
        for (i = 0; i < count; i++) {
            const char *source_name = source[0] ?
                jmx_mount_basename(realpath(source, resolved) ? resolved : source) : "";
            int stable_match = source[0] &&
                (!strcmp(source, probes[i].stable_source) ||
                 !strcmp(source_name, probes[i].name));
            if ((probes[i].major_num != major_num || probes[i].minor_num != minor_num) &&
                !stable_match)
                continue;
            if (!probes[i].mounted_target[0])
                (void)jmx_mount_copy_checked(probes[i].mounted_target,
                                             sizeof(probes[i].mounted_target), target);
            probes[i].config_eligible = probes[i].mount_eligible = 0;
            snprintf(probes[i].excluded_reason, sizeof(probes[i].excluded_reason), "%s",
                     jmx_mount_is_protected_target(target) ? "protected_system_mount" : "already_mounted_conflict");
            if (jmx_mount_is_protected_target(target))
                probes[i].system_disk = 1;
        }
    }
    fclose(fp);
}

static void jmx_mount_apply_swaps(const char *path,
                                  struct jmx_system_mount_probe *probes, size_t count)
{
    FILE *fp = fopen(path, "r");
    char line[1024];
    if (!fp) return;
    (void)fgets(line, sizeof(line), fp);
    while (fgets(line, sizeof(line), fp)) {
        char source[4096], resolved[PATH_MAX];
        const char *name;
        int idx;
        if (sscanf(line, "%4095s", source) != 1) continue;
        name = realpath(source, resolved) ? jmx_mount_basename(resolved) : jmx_mount_basename(source);
        idx = jmx_mount_probe_index(probes, count, name);
        if (idx >= 0) {
            probes[idx].swap = 1;
            probes[idx].system_disk = 1;
            probes[idx].config_eligible = probes[idx].mount_eligible = 0;
            snprintf(probes[idx].excluded_reason, sizeof(probes[idx].excluded_reason), "swap_in_use");
        }
    }
    fclose(fp);
}

static void jmx_mount_apply_whole_disk_policy(struct jmx_system_mount_probe *probes, size_t count)
{
    size_t i, j;
    for (i = 0; i < count; i++) {
        int has_partition = 0;
        if (probes[i].is_partition) continue;
        for (j = 0; j < count; j++)
            if (probes[j].is_partition && !strcmp(probes[j].parent, probes[i].name)) {
                has_partition = 1;
                break;
            }
        if (has_partition) {
            probes[i].config_eligible = probes[i].mount_eligible = 0;
            snprintf(probes[i].excluded_reason, sizeof(probes[i].excluded_reason),
                     "whole_disk_has_partitions");
        } else if (!probes[i].system_disk && !probes[i].swap &&
                   (!probes[i].excluded_reason[0] ||
                    !strcmp(probes[i].excluded_reason, "whole_disk_not_mount_candidate")) &&
                   probes[i].stable_source[0] && probes[i].fstype[0] &&
                   strcmp(probes[i].fstype, "swap") &&
                   strncmp(probes[i].name, "loop", 4) &&
                   strncmp(probes[i].name, "ram", 3) &&
                   strncmp(probes[i].name, "dm-", 3)) {
            probes[i].config_eligible = probes[i].mount_eligible = 1;
            probes[i].excluded_reason[0] = '\0';
        }
    }
}

int jmx_system_mount_discover(const struct jmx_system_mount_discovery_opts *opts,
                              struct jmx_system_mount_probe *probes,
                              size_t max_probes, size_t *count_out,
                              char *err, size_t err_len)
{
    const char *sysdir = jmx_mount_opt_path(opts ? opts->sys_class_block : NULL, "/sys/class/block");
    const char *devroot = jmx_mount_opt_path(opts ? opts->dev_root : NULL, "/dev");
    const char *uuiddir = jmx_mount_opt_path(opts ? opts->by_uuid_dir : NULL, "/dev/disk/by-uuid");
    const char *labeldir = jmx_mount_opt_path(opts ? opts->by_label_dir : NULL, "/dev/disk/by-label");
    const char *mountinfo = jmx_mount_opt_path(opts ? opts->mountinfo_path : NULL, "/proc/self/mountinfo");
    const char *swaps = jmx_mount_opt_path(opts ? opts->swaps_path : NULL, "/proc/swaps");
    const char *blkid = jmx_mount_opt_path(opts ? opts->blkid_bin : NULL, "/sbin/blkid");
    int blkid_timeout_ms = opts && opts->blkid_timeout_ms ? opts->blkid_timeout_ms : 2000;
    DIR *dir;
    struct dirent *de;
    size_t count = 0, i, j;

    if (count_out) *count_out = 0;
    if (!probes || !max_probes || max_probes > JMX_SYSTEM_MOUNT_PROBE_MAX) {
        jmx_mount_set_err(err, err_len, "invalid_discovery_buffer");
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    memset(probes, 0, max_probes * sizeof(*probes));
    if (blkid_timeout_ms < 100 || blkid_timeout_ms > 10000) {
        jmx_mount_set_err(err, err_len, "invalid_blkid_timeout");
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    dir = opendir(sysdir);
    if (!dir) {
        jmx_mount_set_err(err, err_len, "block_sysfs_unavailable");
        return JMX_SYSTEM_MOUNT_ERR_IO;
    }
    while ((de = readdir(dir)) != NULL) {
        char entry[PATH_MAX], resolved_entry[PATH_MAX], resolved_root[PATH_MAX];
        char devfile[PATH_MAX], partfile[PATH_MAX], devtext[64];
        struct stat st;
        struct jmx_system_mount_probe *p;
        if (de->d_name[0] == '.' || !jmx_mount_name_safe(de->d_name)) continue;
        if (count >= max_probes) {
            closedir(dir);
            jmx_mount_set_err(err, err_len, "too_many_block_devices");
            return JMX_SYSTEM_MOUNT_ERR_INVALID;
        }
        p = &probes[count];
        if (jmx_mount_join_path(entry, sizeof(entry), sysdir, de->d_name) != 0)
            continue;
        if (jmx_mount_sysroot(sysdir, resolved_root, sizeof(resolved_root)) != 0 ||
            !realpath(entry, resolved_entry) ||
            !jmx_mount_path_under(resolved_entry, resolved_root))
            continue;
        if (jmx_mount_join_path(devfile, sizeof(devfile), entry, "dev") != 0)
            continue;
        if (jmx_mount_read_line(devfile, devtext, sizeof(devtext)) != 0 ||
            sscanf(devtext, "%u:%u", &p->major_num, &p->minor_num) != 2)
            continue;
        if (jmx_mount_copy_checked(p->name, sizeof(p->name), de->d_name) != 0 ||
            jmx_mount_join_path(p->devnode, sizeof(p->devnode),
                                devroot, de->d_name) != 0 ||
            jmx_mount_join_path(partfile, sizeof(partfile), entry, "partition") != 0)
            continue;
        p->is_partition = stat(partfile, &st) == 0;
        jmx_mount_parent_from_sysfs(entry, p->name, p->is_partition, p->parent, sizeof(p->parent));
        p->config_eligible = p->mount_eligible = p->is_partition ? 1 : 0;
        if (!(opts && opts->trust_fixture_block_devices) &&
            !jmx_mount_verify_block_device(p->devnode, devroot,
                                           p->major_num, p->minor_num)) {
            p->config_eligible = p->mount_eligible = 0;
            snprintf(p->excluded_reason, sizeof(p->excluded_reason), "devnode_not_block_device");
        } else if (jmx_mount_auto_device_class_rejected(p->name)) {
            p->config_eligible = p->mount_eligible = 0;
            snprintf(p->excluded_reason, sizeof(p->excluded_reason), "unsupported_block_device_class");
        } else if (!p->is_partition)
            snprintf(p->excluded_reason, sizeof(p->excluded_reason), "whole_disk_not_mount_candidate");
        count++;
    }
    closedir(dir);
    jmx_mount_apply_stable_dir(uuiddir, 1, probes, count);
    jmx_mount_apply_stable_dir(labeldir, 0, probes, count);
    for (i = 0; i < count; i++) {
        int blkid_rc;
        if (!strcmp(probes[i].excluded_reason, "devnode_not_block_device") ||
            !strcmp(probes[i].excluded_reason, "unsupported_block_device_class"))
            continue;
        {
            char output[2048], *line, *save = NULL;
            char *argv[] = {(char *)blkid, "-o", "export", probes[i].devnode, NULL};
            blkid_rc = access(blkid, X_OK) == 0 ?
                jmx_mount_capture(argv, output, sizeof(output), blkid_timeout_ms) :
                JMX_MOUNT_CAPTURE_ERROR;
            if (blkid_rc == JMX_MOUNT_CAPTURE_OK) {
                for (line = strtok_r(output, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
                    char *eq = strchr(line, '=');
                    const char *value;
                    if (!eq) continue;
                    *eq = '\0'; value = eq + 1;
                    if (!strcmp(line, "UUID") && !probes[i].uuid[0] &&
                        jmx_mount_is_safe_token(value, sizeof(probes[i].uuid)))
                        snprintf(probes[i].uuid, sizeof(probes[i].uuid), "%s", value);
                    else if (!strcmp(line, "LABEL") && !probes[i].label[0] &&
                             jmx_mount_is_safe_token(value, sizeof(probes[i].label)) && !strchr(value, '/'))
                        snprintf(probes[i].label, sizeof(probes[i].label), "%s", value);
                    else if (!strcmp(line, "PARTLABEL") &&
                             jmx_mount_is_safe_token(value, sizeof(probes[i].partlabel)) && !strchr(value, '/'))
                        snprintf(probes[i].partlabel, sizeof(probes[i].partlabel), "%s", value);
                    else if (!strcmp(line, "TYPE") &&
                             jmx_mount_is_safe_token(value, sizeof(probes[i].fstype)) && !strchr(value, '/'))
                        snprintf(probes[i].fstype, sizeof(probes[i].fstype), "%s", value);
                }
            }
        }
        if (blkid_rc == JMX_MOUNT_CAPTURE_TIMEOUT) {
            probes[i].config_eligible = probes[i].mount_eligible = 0;
            snprintf(probes[i].excluded_reason, sizeof(probes[i].excluded_reason), "blkid_timeout");
        } else if (blkid_rc == JMX_MOUNT_CAPTURE_OVERSIZE) {
            probes[i].config_eligible = probes[i].mount_eligible = 0;
            snprintf(probes[i].excluded_reason, sizeof(probes[i].excluded_reason), "blkid_output_oversize");
        } else if (blkid_rc != JMX_MOUNT_CAPTURE_OK) {
            probes[i].config_eligible = probes[i].mount_eligible = 0;
            snprintf(probes[i].excluded_reason, sizeof(probes[i].excluded_reason), "blkid_probe_failed");
        }
        if (blkid_rc != JMX_MOUNT_CAPTURE_OK) continue;
        if (probes[i].uuid[0] && jmx_mount_valid_uuid_body(probes[i].uuid))
            snprintf(probes[i].stable_source, sizeof(probes[i].stable_source), "UUID=%s", probes[i].uuid);
        else if (probes[i].label[0] && jmx_mount_is_safe_token(probes[i].label, sizeof(probes[i].label)))
            snprintf(probes[i].stable_source, sizeof(probes[i].stable_source), "LABEL=%s", probes[i].label);
        if (jmx_mount_slot_name(probes[i].label) || jmx_mount_slot_name(probes[i].partlabel)) {
            probes[i].system_disk = 1;
            probes[i].config_eligible = probes[i].mount_eligible = 0;
            snprintf(probes[i].excluded_reason, sizeof(probes[i].excluded_reason), "protected_ab_esp_or_data_partition");
        } else if (!probes[i].stable_source[0] && probes[i].is_partition) {
            probes[i].config_eligible = probes[i].mount_eligible = 0;
            snprintf(probes[i].excluded_reason, sizeof(probes[i].excluded_reason), "stable_uuid_or_label_required");
        } else if (!probes[i].fstype[0] && probes[i].is_partition) {
            probes[i].config_eligible = probes[i].mount_eligible = 0;
            snprintf(probes[i].excluded_reason, sizeof(probes[i].excluded_reason), "filesystem_type_unavailable");
        } else if (!strcmp(probes[i].fstype, "swap")) {
            probes[i].swap = 1;
            probes[i].config_eligible = probes[i].mount_eligible = 0;
            snprintf(probes[i].excluded_reason, sizeof(probes[i].excluded_reason), "swap_device");
        }
    }
    jmx_mount_mark_duplicate_stable_sources(probes, count);
    jmx_mount_apply_mountinfo(mountinfo, probes, count);
    jmx_mount_apply_swaps(swaps, probes, count);
    jmx_mount_apply_whole_disk_policy(probes, count);
    for (i = 0; i < count; i++) {
        if (!probes[i].system_disk) continue;
        for (j = 0; j < count; j++) {
            const char *disk_i = probes[i].parent[0] ? probes[i].parent : probes[i].name;
            const char *disk_j = probes[j].parent[0] ? probes[j].parent : probes[j].name;
            if (strcmp(disk_i, disk_j)) continue;
            probes[j].system_disk = 1;
            probes[j].config_eligible = probes[j].mount_eligible = 0;
            snprintf(probes[j].excluded_reason, sizeof(probes[j].excluded_reason), "system_disk_member");
        }
    }
    if (count_out) *count_out = count;
    return JMX_SYSTEM_MOUNT_OK;
}

int jmx_system_mount_runtime_capability(int require_mount_exec)
{
    struct stat st;
    if (stat("/sys/class/block", &st) != 0 || !S_ISDIR(st.st_mode) ||
        access("/sbin/blkid", X_OK) != 0 || access("/etc/config", W_OK) != 0)
        return 0;
    if (require_mount_exec &&
        (access("/bin/mount", X_OK) != 0 || access("/bin/umount", X_OK) != 0))
        return 0;
    return 1;
}

static int jmx_mount_decode_mountinfo_field(const char *input,
                                            char *output, size_t output_len)
{
    size_t in_at = 0, out_at = 0;

    if (!input || !output || !output_len)
        return -1;
    while (input[in_at]) {
        unsigned char value;

        if (input[in_at] == '\\' && input[in_at + 1] >= '0' && input[in_at + 1] <= '7' &&
            input[in_at + 2] >= '0' && input[in_at + 2] <= '7' &&
            input[in_at + 3] >= '0' && input[in_at + 3] <= '7') {
            value = (unsigned char)((input[in_at + 1] - '0') * 64 +
                                    (input[in_at + 2] - '0') * 8 +
                                    (input[in_at + 3] - '0'));
            if (!value)
                return -1;
            in_at += 4;
        } else {
            value = (unsigned char)input[in_at++];
        }
        if (out_at + 1 >= output_len)
            return -1;
        output[out_at++] = (char)value;
    }
    output[out_at] = '\0';
    return 0;
}

static unsigned long long jmx_mount_u64_multiply(unsigned long long left,
                                                  unsigned long long right)
{
    return right && left > ULLONG_MAX / right ? ULLONG_MAX : left * right;
}

static int jmx_mount_runtime_read(const char *path,
                                  struct jmx_system_mount_runtime_entry *entries,
                                  size_t max_entries, size_t *count_out,
                                  char *err, size_t err_len)
{
    FILE *fp;
    char line[16384];
    size_t count = 0;

    if (!entries || !max_entries || !count_out || !(fp = fopen(path, "r"))) {
        jmx_mount_set_err(err, err_len, "mountinfo_unavailable");
        return JMX_SYSTEM_MOUNT_ERR_IO;
    }
    while (fgets(line, sizeof(line), fp)) {
        char *fields[128], *save = NULL, *token;
        char root[JMX_SYSTEM_MOUNT_TARGET_MAX];
        char target[JMX_SYSTEM_MOUNT_TARGET_MAX];
        char device[JMX_SYSTEM_MOUNT_SOURCE_MAX];
        size_t field_count = 0, separator = 0, i;
        unsigned int major_num, minor_num;
        char trailing;
        struct jmx_system_mount_runtime_entry *entry;

        if (!strchr(line, '\n') && !feof(fp)) {
            fclose(fp);
            jmx_mount_set_err(err, err_len, "mountinfo_line_too_long");
            return JMX_SYSTEM_MOUNT_ERR_INVALID;
        }
        line[strcspn(line, "\r\n")] = '\0';
        for (token = strtok_r(line, " ", &save); token;
             token = strtok_r(NULL, " ", &save)) {
            if (field_count >= sizeof(fields) / sizeof(fields[0])) {
                fclose(fp);
                jmx_mount_set_err(err, err_len, "mountinfo_too_many_fields");
                return JMX_SYSTEM_MOUNT_ERR_INVALID;
            }
            fields[field_count++] = token;
        }
        if (field_count < 10)
            continue;
        for (i = 6; i < field_count; i++)
            if (!strcmp(fields[i], "-")) { separator = i; break; }
        if (!separator || separator + 3 >= field_count ||
            sscanf(fields[2], "%u:%u%c", &major_num, &minor_num, &trailing) != 2 ||
            jmx_mount_decode_mountinfo_field(fields[3], root, sizeof(root)) != 0 ||
            jmx_mount_decode_mountinfo_field(fields[4], target, sizeof(target)) != 0 ||
            jmx_mount_decode_mountinfo_field(fields[separator + 2], device,
                                             sizeof(device)) != 0)
            continue;
        if (count >= max_entries) {
            fclose(fp);
            jmx_mount_set_err(err, err_len, "too_many_runtime_mounts");
            return JMX_SYSTEM_MOUNT_ERR_INVALID;
        }
        entry = &entries[count];
        memset(entry, 0, sizeof(*entry));
        entry->major_num = major_num;
        entry->minor_num = minor_num;
        if (jmx_mount_copy_checked(entry->device, sizeof(entry->device), device) != 0 ||
            jmx_mount_copy_checked(entry->root, sizeof(entry->root), root) != 0 ||
            jmx_mount_copy_checked(entry->target, sizeof(entry->target), target) != 0 ||
            jmx_mount_copy_checked(entry->fstype, sizeof(entry->fstype),
                                   fields[separator + 1]) != 0 ||
            jmx_mount_copy_checked(entry->options, sizeof(entry->options), fields[5]) != 0)
            continue;
        entry->bind_mount = strcmp(root, "/") != 0;
        if (entry->bind_mount) {
            int n = snprintf(entry->source, sizeof(entry->source), "%s[%s]", device, root);
            if (n < 0 || (size_t)n >= sizeof(entry->source))
                continue;
        } else if (jmx_mount_copy_checked(entry->source, sizeof(entry->source), device) != 0) {
            continue;
        }
        {
            struct statvfs fs;
            struct stat target_stat;
            int target_fd = -1;

            if (lstat(target, &target_stat) == 0 && !S_ISLNK(target_stat.st_mode))
                target_fd = open(target, O_PATH | O_CLOEXEC | O_NOFOLLOW);
            if (target_fd >= 0 && fstatvfs(target_fd, &fs) == 0) {
                unsigned long long block_size = fs.f_frsize ? fs.f_frsize : fs.f_bsize;
                unsigned long long blocks = fs.f_blocks;
                unsigned long long used_blocks = blocks >= fs.f_bfree ?
                                                  blocks - fs.f_bfree : 0;
                entry->size_bytes = jmx_mount_u64_multiply(block_size, blocks);
                entry->used_bytes = jmx_mount_u64_multiply(block_size, used_blocks);
                entry->available_bytes = jmx_mount_u64_multiply(block_size, fs.f_bavail);
                entry->used_percent = blocks ? (int)((long double)used_blocks * 100.0L /
                                                       (long double)blocks) : 0;
                entry->stat_ok = 1;
            }
            if (target_fd >= 0)
                close(target_fd);
        }
        count++;
    }
    if (ferror(fp)) {
        fclose(fp);
        jmx_mount_set_err(err, err_len, "mountinfo_read_failed");
        return JMX_SYSTEM_MOUNT_ERR_IO;
    }
    fclose(fp);
    *count_out = count;
    return JMX_SYSTEM_MOUNT_OK;
}

/*
 * `root` 是否为 `path` 的路径前缀（按 `/` 分界，不做裸字符串比较，
 * 否则 `/persist/etc` 会错配 `/persist/etcetera`）。`/` 是任何绝对路径的前缀。
 */
static int jmx_mount_root_is_prefix(const char *root, const char *path)
{
    size_t root_len;

    if (!root || !path || root[0] != '/' || path[0] != '/')
        return 0;
    if (!strcmp(root, "/"))
        return 1;
    root_len = strlen(root);
    if (strncmp(root, path, root_len) != 0)
        return 0;
    return path[root_len] == '/' || path[root_len] == '\0';
}

/*
 * 为绑定挂载补上宿主挂载点。判据是同一 major:minor（同一个文件系统）上 root 为本条
 * root 路径前缀、且 root 最长的那条 —— 最长前缀才是真正的宿主，因为宿主自己也可能
 * 是一层绑定挂载。宿主挂载通常 root 为 `/`（如 `/data`），但不假定它一定存在：
 * 只挂了绑定挂载而整卷未挂载时留空，前端按"无宿主"处理而不是显示一个不存在的路径。
 */
static void jmx_mount_resolve_bind_hosts(struct jmx_system_mount_runtime_entry *entries,
                                         size_t count)
{
    size_t i, j;

    if (!entries)
        return;
    for (i = 0; i < count; i++) {
        const struct jmx_system_mount_runtime_entry *best = NULL;

        entries[i].bind_host_target[0] = '\0';
        if (!entries[i].bind_mount)
            continue;
        for (j = 0; j < count; j++) {
            if (j == i ||
                entries[j].major_num != entries[i].major_num ||
                entries[j].minor_num != entries[i].minor_num ||
                strlen(entries[j].root) >= strlen(entries[i].root) ||
                !jmx_mount_root_is_prefix(entries[j].root, entries[i].root))
                continue;
            if (!best || strlen(entries[j].root) > strlen(best->root))
                best = &entries[j];
        }
        if (best)
            (void)jmx_mount_copy_checked(entries[i].bind_host_target,
                                         sizeof(entries[i].bind_host_target),
                                         best->target);
    }
}

static int jmx_mount_uci_next_arg(const char **cursor, char *out, size_t out_len)
{
    const char *p;
    size_t used = 0;
    char quote = '\0';

    if (!cursor || !(p = *cursor) || !out || !out_len)
        return -1;
    while (*p && isspace((unsigned char)*p)) p++;
    if (!*p || *p == '#') return 0;
    if (*p == '\'' || *p == '"') quote = *p++;
    while (*p) {
        char value = *p++;
        if (quote) {
            if (value == quote) {
                quote = '\0';
                break;
            }
        } else if (isspace((unsigned char)value) || value == '#') {
            break;
        }
        if (value == '\\' && *p)
            value = *p++;
        if (used + 1 >= out_len)
            return -1;
        out[used++] = value;
    }
    if (quote)
        return -1;
    out[used] = '\0';
    *cursor = p;
    return used ? 1 : 0;
}

static int jmx_mount_config_finish(struct jmx_system_mount_config_entry *entry,
                                   struct jmx_system_mount_config_entry *entries,
                                   size_t max_entries, size_t *count,
                                   char *err, size_t err_len)
{
    struct jmx_system_mount_spec spec;
    char validate_err[JMX_SYSTEM_MOUNT_ERROR_MAX] = {0};

    if (*count >= max_entries) {
        jmx_mount_set_err(err, err_len, "too_many_configured_mounts");
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    if (!entry->section[0])
        snprintf(entry->section, sizeof(entry->section), "cfg-%zu", *count + 1);
    if (!entry->fstype[0])
        (void)jmx_mount_copy_checked(entry->fstype, sizeof(entry->fstype), "auto");
    memset(&spec, 0, sizeof(spec));
    (void)jmx_mount_copy_checked(spec.source, sizeof(spec.source), entry->source);
    (void)jmx_mount_copy_checked(spec.target, sizeof(spec.target), entry->target);
    (void)jmx_mount_copy_checked(spec.fstype, sizeof(spec.fstype), entry->fstype);
    (void)jmx_mount_copy_checked(spec.options, sizeof(spec.options), entry->options);
    spec.enabled = entry->enabled;
    spec.check_fs = entry->check_fs;
    entry->editable = jmx_system_mount_validate_spec(&spec, validate_err,
                                                      sizeof(validate_err)) == 0;
    entries[(*count)++] = *entry;
    return JMX_SYSTEM_MOUNT_OK;
}

static int jmx_mount_config_read(const char *path,
                                 struct jmx_system_mount_config_entry *entries,
                                 size_t max_entries, size_t *count_out,
                                 char *err, size_t err_len)
{
    FILE *fp;
    char line[2048];
    struct jmx_system_mount_config_entry current;
    int in_mount = 0;
    size_t count = 0;

    memset(&current, 0, sizeof(current));
    current.enabled = 1;
    fp = fopen(path, "r");
    if (!fp && errno == ENOENT) {
        *count_out = 0;
        return JMX_SYSTEM_MOUNT_OK;
    }
    if (!fp) {
        jmx_mount_set_err(err, err_len, "fstab_unavailable");
        return JMX_SYSTEM_MOUNT_ERR_IO;
    }
    while (fgets(line, sizeof(line), fp)) {
        const char *cursor = line;
        char keyword[32], name[64], value[JMX_SYSTEM_MOUNT_OPTIONS_MAX];
        int arg_rc;

        if (!strchr(line, '\n') && !feof(fp)) {
            fclose(fp);
            jmx_mount_set_err(err, err_len, "fstab_line_too_long");
            return JMX_SYSTEM_MOUNT_ERR_INVALID;
        }
        arg_rc = jmx_mount_uci_next_arg(&cursor, keyword, sizeof(keyword));
        if (arg_rc <= 0)
            continue;
        if (!strcmp(keyword, "config")) {
            if (in_mount && jmx_mount_config_finish(&current, entries, max_entries,
                                                     &count, err, err_len) != 0) {
                fclose(fp);
                return JMX_SYSTEM_MOUNT_ERR_INVALID;
            }
            memset(&current, 0, sizeof(current));
            current.enabled = 1;
            in_mount = jmx_mount_uci_next_arg(&cursor, value, sizeof(value)) == 1 &&
                       !strcmp(value, "mount");
            if (in_mount && jmx_mount_uci_next_arg(&cursor, current.section,
                                                    sizeof(current.section)) < 0) {
                fclose(fp);
                jmx_mount_set_err(err, err_len, "invalid_fstab_section");
                return JMX_SYSTEM_MOUNT_ERR_INVALID;
            }
            continue;
        }
        if (!in_mount || strcmp(keyword, "option"))
            continue;
        if (jmx_mount_uci_next_arg(&cursor, name, sizeof(name)) != 1 ||
            jmx_mount_uci_next_arg(&cursor, value, sizeof(value)) != 1) {
            fclose(fp);
            jmx_mount_set_err(err, err_len, "invalid_fstab_option");
            return JMX_SYSTEM_MOUNT_ERR_INVALID;
        }
        if (!strcmp(name, "target"))
            arg_rc = jmx_mount_copy_checked(current.target, sizeof(current.target), value);
        else if (!strcmp(name, "device"))
            arg_rc = jmx_mount_copy_checked(current.source, sizeof(current.source), value);
        else if (!strcmp(name, "uuid"))
            arg_rc = snprintf(current.source, sizeof(current.source), "UUID=%s", value) >=
                     (int)sizeof(current.source) ? -1 : 0;
        else if (!strcmp(name, "label"))
            arg_rc = snprintf(current.source, sizeof(current.source), "LABEL=%s", value) >=
                     (int)sizeof(current.source) ? -1 : 0;
        else if (!strcmp(name, "fstype"))
            arg_rc = jmx_mount_copy_checked(current.fstype, sizeof(current.fstype), value);
        else if (!strcmp(name, "options"))
            arg_rc = jmx_mount_copy_checked(current.options, sizeof(current.options), value);
        else {
            arg_rc = 0;
            if (!strcmp(name, "enabled")) current.enabled = atoi(value) != 0;
            else if (!strcmp(name, "enabled_fsck")) current.check_fs = atoi(value) != 0;
        }
        if (arg_rc != 0) {
            fclose(fp);
            jmx_mount_set_err(err, err_len, "fstab_value_too_long");
            return JMX_SYSTEM_MOUNT_ERR_INVALID;
        }
    }
    if (ferror(fp)) {
        fclose(fp);
        jmx_mount_set_err(err, err_len, "fstab_read_failed");
        return JMX_SYSTEM_MOUNT_ERR_IO;
    }
    if (in_mount && jmx_mount_config_finish(&current, entries, max_entries,
                                             &count, err, err_len) != 0) {
        fclose(fp);
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    fclose(fp);
    *count_out = count;
    return JMX_SYSTEM_MOUNT_OK;
}

static int jmx_mount_config_source_matches_runtime(const char *configured_source,
                                                   const char *runtime_device)
{
    char path[PATH_MAX], configured_real[PATH_MAX], runtime_real[PATH_MAX];
    const char *candidate = configured_source;

    if (!configured_source || !configured_source[0] ||
        !runtime_device || !runtime_device[0])
        return 0;
    if (!strncmp(configured_source, "UUID=", 5)) {
        if (jmx_mount_join_path(path, sizeof(path), "/dev/disk/by-uuid",
                                configured_source + 5) != 0)
            return 0;
        candidate = path;
    } else if (!strncmp(configured_source, "LABEL=", 6)) {
        if (jmx_mount_join_path(path, sizeof(path), "/dev/disk/by-label",
                                configured_source + 6) != 0)
            return 0;
        candidate = path;
    }
    if (!realpath(candidate, configured_real))
        return !strcmp(candidate, runtime_device);
    if (!realpath(runtime_device, runtime_real))
        return !strcmp(configured_real, runtime_device);
    return !strcmp(configured_real, runtime_real);
}

int jmx_system_mount_read(const struct jmx_system_mount_read_opts *opts,
                          struct jmx_system_mount_runtime_entry *runtime,
                          size_t runtime_max, size_t *runtime_count,
                          struct jmx_system_mount_config_entry *configured,
                          size_t configured_max, size_t *configured_count,
                          char *err, size_t err_len)
{
    const char *mountinfo = jmx_mount_opt_path(opts ? opts->mountinfo_path : NULL,
                                                "/proc/self/mountinfo");
    const char *fstab = jmx_mount_opt_path(opts ? opts->fstab_path : NULL,
                                           JMX_FSTAB_DEFAULT_PATH);
    size_t runtime_n = 0, configured_n = 0, i, j;
    int rc;

    if (!runtime || !runtime_max || !runtime_count || !configured || !configured_max ||
        !configured_count || runtime_max > JMX_SYSTEM_MOUNT_READ_MAX ||
        configured_max > JMX_SYSTEM_MOUNT_READ_MAX) {
        jmx_mount_set_err(err, err_len, "invalid_mount_read_buffers");
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    memset(runtime, 0, runtime_max * sizeof(*runtime));
    memset(configured, 0, configured_max * sizeof(*configured));
    *runtime_count = *configured_count = 0;
    rc = jmx_mount_runtime_read(mountinfo, runtime, runtime_max, &runtime_n, err, err_len);
    if (rc != 0)
        return rc;
    jmx_mount_resolve_bind_hosts(runtime, runtime_n);
    rc = jmx_mount_config_read(fstab, configured, configured_max, &configured_n,
                               err, err_len);
    if (rc != 0)
        return rc;
    for (i = 0; i < configured_n; i++)
        for (j = 0; j < runtime_n; j++)
            if (configured[i].target[0] &&
                !strcmp(configured[i].target, runtime[j].target) &&
                jmx_mount_config_source_matches_runtime(configured[i].source,
                                                        runtime[j].device)) {
                configured[i].mounted = 1;
                runtime[j].configured = 1;
            }
    *runtime_count = runtime_n;
    *configured_count = configured_n;
    return JMX_SYSTEM_MOUNT_OK;
}

static int jmx_system_cron_name_value(const char *token, size_t len,
                                      const char *const names[], size_t name_count)
{
    size_t i;

    if (!names || len != 3)
        return -1;
    for (i = 0; i < name_count; i++)
        if (!strncasecmp(token, names[i], len))
            return (int)i;
    return -1;
}

static int jmx_system_cron_atom(const char *token, size_t len, int min_value,
                                int max_value, const char *const names[],
                                size_t name_count, int *value)
{
    size_t i;
    unsigned long parsed = 0;
    int named;

    if (!token || !len || !value)
        return 0;
    named = jmx_system_cron_name_value(token, len, names, name_count);
    if (named >= 0) {
        *value = named + min_value;
        return 1;
    }
    for (i = 0; i < len; i++) {
        if (!isdigit((unsigned char)token[i]))
            return 0;
        parsed = parsed * 10 + (unsigned int)(token[i] - '0');
        if (parsed > (unsigned long)max_value)
            return 0;
    }
    if (parsed < (unsigned long)min_value || parsed > (unsigned long)max_value)
        return 0;
    *value = (int)parsed;
    return 1;
}

static int jmx_system_cron_field_valid(const char *field, size_t len, int field_index)
{
    static const char *const months[] = {
        "jan", "feb", "mar", "apr", "may", "jun",
        "jul", "aug", "sep", "oct", "nov", "dec"
    };
    static const char *const weekdays[] = {
        "sun", "mon", "tue", "wed", "thu", "fri", "sat"
    };
    static const int minimums[] = {0, 0, 1, 1, 0};
    static const int maximums[] = {59, 23, 31, 12, 7};
    const char *const *names = NULL;
    size_t name_count = 0, pos = 0;

    if (!field || !len || len > 256 || field_index < 0 || field_index >= 5)
        return 0;
    if (field_index == 3) {
        names = months;
        name_count = sizeof(months) / sizeof(months[0]);
    } else if (field_index == 4) {
        names = weekdays;
        name_count = sizeof(weekdays) / sizeof(weekdays[0]);
    }
    while (pos < len) {
        size_t item_end = pos, slash = (size_t)-1, dash = (size_t)-1, i;
        int first = 0, last = 0;

        while (item_end < len && field[item_end] != ',') item_end++;
        if (item_end == pos)
            return 0;
        for (i = pos; i < item_end; i++) {
            if (field[i] == '/') {
                if (slash != (size_t)-1) return 0;
                slash = i;
            }
        }
        if (slash != (size_t)-1) {
            int step;
            if (slash == pos || slash + 1 == item_end ||
                !jmx_system_cron_atom(field + slash + 1, item_end - slash - 1,
                                      1, maximums[field_index] - minimums[field_index] + 1,
                                      NULL, 0, &step))
                return 0;
            item_end = slash;
        }
        for (i = pos; i < item_end; i++) {
            if (field[i] == '-') {
                if (dash != (size_t)-1) return 0;
                dash = i;
            }
        }
        if (item_end - pos == 1 && field[pos] == '*') {
            /* all values */
        } else if (dash != (size_t)-1) {
            if (dash == pos || dash + 1 == item_end ||
                !jmx_system_cron_atom(field + pos, dash - pos,
                                      minimums[field_index], maximums[field_index],
                                      names, name_count, &first) ||
                !jmx_system_cron_atom(field + dash + 1, item_end - dash - 1,
                                      minimums[field_index], maximums[field_index],
                                      names, name_count, &last) || first > last)
                return 0;
        } else if (!jmx_system_cron_atom(field + pos, item_end - pos,
                                         minimums[field_index], maximums[field_index],
                                         names, name_count, &first)) {
            return 0;
        }
        pos = slash != (size_t)-1 ? slash : item_end;
        while (pos < len && field[pos] != ',') pos++;
        if (pos < len) pos++;
    }
    return 1;
}

int jmx_system_crontab_special_times_supported(void)
{
    return JMX_CROND_SPECIAL_TIMES ? 1 : 0;
}

int jmx_system_crontab_validate_text(const char *text, size_t *bad_line,
                                     char *err, size_t err_len)
{
    const char *line_start, *p;
    size_t line_no = 1, total_len;

    if (bad_line) *bad_line = 0;
    if (!text || (total_len = strlen(text)) > 65536) {
        jmx_mount_set_err(err, err_len, text ? "crontab_too_large" : "missing_crontab");
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    line_start = text;
    while (*line_start) {
        const char *line_end = strchr(line_start, '\n');
        const char *cursor, *content_end;
        size_t line_len = line_end ? (size_t)(line_end - line_start) : strlen(line_start);
        int field;

        if (line_len > 4096) {
            if (bad_line) *bad_line = line_no;
            jmx_mount_set_err(err, err_len, "cron_line_too_long");
            return JMX_SYSTEM_MOUNT_ERR_INVALID;
        }
        content_end = line_start + line_len;
        if (content_end > line_start && content_end[-1] == '\r')
            content_end--;
        for (p = line_start; p < content_end; p++)
            if ((unsigned char)*p < 0x20 && *p != '\t') {
                if (bad_line) *bad_line = line_no;
                jmx_mount_set_err(err, err_len, "cron_control_character");
                return JMX_SYSTEM_MOUNT_ERR_INVALID;
            }
        cursor = line_start;
        while (cursor < content_end && isspace((unsigned char)*cursor)) cursor++;
        if (cursor < content_end && *cursor != '#') {
            const char *token_end = cursor;

            while (token_end < content_end && !isspace((unsigned char)*token_end)) token_end++;
            if (*cursor == '@') {
                static const char *special[] = {
                    "@reboot", "@yearly", "@annually", "@monthly", "@weekly",
                    "@daily", "@midnight", "@hourly", NULL
                };
                char token[32];
                int matched = 0, i;
                size_t token_len = (size_t)(token_end - cursor);

                if (token_len < sizeof(token)) {
                    memcpy(token, cursor, token_len);
                    token[token_len] = '\0';
                    for (i = 0; special[i]; i++)
                        if (!strcmp(token, special[i])) { matched = 1; break; }
                }
                cursor = token_end;
                while (cursor < content_end && isspace((unsigned char)*cursor)) cursor++;
                if (!jmx_system_crontab_special_times_supported()) {
                    if (bad_line) *bad_line = line_no;
                    jmx_mount_set_err(err, err_len, "cron_special_times_unsupported");
                    return JMX_SYSTEM_MOUNT_ERR_INVALID;
                }
                if (!matched || cursor == content_end) {
                    if (bad_line) *bad_line = line_no;
                    jmx_mount_set_err(err, err_len, "invalid_cron_special");
                    return JMX_SYSTEM_MOUNT_ERR_INVALID;
                }
            } else if (memchr(cursor, '=', (size_t)(token_end - cursor))) {
                const char *eq = memchr(cursor, '=', (size_t)(token_end - cursor));
                size_t name_len = eq ? (size_t)(eq - cursor) : 0;
                if (!eq || eq == cursor || token_end != content_end ||
                    !((name_len == 4 && !memcmp(cursor, "PATH", 4)) ||
                      (name_len == 5 && !memcmp(cursor, "SHELL", 5)) ||
                      (name_len == 6 && !memcmp(cursor, "MAILTO", 6)))) {
                    if (bad_line) *bad_line = line_no;
                    jmx_mount_set_err(err, err_len, "unsupported_cron_environment");
                    return JMX_SYSTEM_MOUNT_ERR_INVALID;
                }
            } else {
                for (field = 0; field < 5; field++) {
                    const char *field_start;
                    while (cursor < content_end && isspace((unsigned char)*cursor)) cursor++;
                    field_start = cursor;
                    while (cursor < content_end && !isspace((unsigned char)*cursor)) cursor++;
                    if (!jmx_system_cron_field_valid(field_start,
                                                     (size_t)(cursor - field_start),
                                                     field)) {
                        if (bad_line) *bad_line = line_no;
                        jmx_mount_set_err(err, err_len, "invalid_cron_field");
                        return JMX_SYSTEM_MOUNT_ERR_INVALID;
                    }
                }
                while (cursor < content_end && isspace((unsigned char)*cursor)) cursor++;
                if (cursor == content_end) {
                    if (bad_line) *bad_line = line_no;
                    jmx_mount_set_err(err, err_len, "cron_command_required");
                    return JMX_SYSTEM_MOUNT_ERR_INVALID;
                }
            }
        }
        if (!line_end)
            break;
        line_start = line_end + 1;
        line_no++;
    }
    return JMX_SYSTEM_MOUNT_OK;
}

static int jmx_system_text_reload(const struct jmx_system_text_apply_opts *opts)
{
    char output[4096];
    char *argv[3];

    if (!opts->reload_bin || !opts->reload_bin[0])
        return JMX_SYSTEM_MOUNT_OK;
    argv[0] = (char *)opts->reload_bin;
    argv[1] = (char *)(opts->reload_action && opts->reload_action[0] ?
                      opts->reload_action : "restart");
    argv[2] = NULL;
    return jmx_mount_capture(argv, output, sizeof(output),
                             opts->reload_timeout_ms > 0 ?
                             opts->reload_timeout_ms : 10000) == JMX_MOUNT_CAPTURE_OK ?
           JMX_SYSTEM_MOUNT_OK : JMX_SYSTEM_MOUNT_ERR_EXEC;
}

int jmx_system_text_apply(const char *text,
                          const struct jmx_system_text_apply_opts *opts,
                          struct jmx_system_text_apply_result *result)
{
    char *old = NULL;
    size_t old_len = 0, text_len;
    int old_existed, renamed = 0, rc = JMX_SYSTEM_MOUNT_ERR_IO;
    mode_t mode, old_mode = S_IRUSR | S_IWUSR;
    struct stat old_stat;

    if (!result)
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    memset(result, 0, sizeof(*result));
    if (!text || !opts || !opts->path || !opts->path[0] ||
        !opts->max_bytes || (text_len = strlen(text)) > opts->max_bytes) {
        snprintf(result->error, sizeof(result->error), "invalid_text_apply_request");
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    old_existed = jmx_mount_path_exists(opts->path);
    if (old_existed < 0 || jmx_mount_read_file(opts->path, &old, &old_len) != 0) {
        snprintf(result->error, sizeof(result->error), "read_existing_failed");
        goto done;
    }
    mode = opts->mode ? (mode_t)opts->mode : (S_IRUSR | S_IWUSR);
    if (old_existed) {
        if (lstat(opts->path, &old_stat) != 0) {
            snprintf(result->error, sizeof(result->error), "stat_existing_failed");
            goto done;
        }
        old_mode = old_stat.st_mode & 07777;
    }
    result->changed = !old_existed || old_len != text_len ||
                      (text_len && memcmp(old, text, text_len)) ||
                      (old_existed && old_mode != (mode & 07777));
    result->applied_at = (int64_t)time(NULL);
    if (!result->changed || opts->dry_run) {
        rc = JMX_SYSTEM_MOUNT_OK;
        goto done;
    }
    if (old_existed && opts->backup_path && opts->backup_path[0]) {
        if (jmx_mount_write_file_atomic_mode(opts->backup_path, old, old_len,
                                             S_IRUSR | S_IWUSR, NULL) != 0 ||
            !jmx_mount_readback_matches(opts->backup_path, old, old_len) ||
            jmx_mount_copy_checked(result->backup_path,
                                   sizeof(result->backup_path),
                                   opts->backup_path) != 0) {
            snprintf(result->error, sizeof(result->error), "backup_failed");
            goto done;
        }
    }
    if (jmx_mount_write_file_atomic_mode(opts->path, text, text_len, mode,
                                         &renamed) != 0 ||
        !jmx_mount_readback_matches_mode(opts->path, text, text_len, mode)) {
        snprintf(result->error, sizeof(result->error), "write_or_readback_failed");
        goto rollback;
    }
    if (jmx_system_text_reload(opts) != 0) {
        snprintf(result->error, sizeof(result->error), "reload_failed");
        goto rollback;
    }
    result->reloaded = opts->reload_bin && opts->reload_bin[0];
    rc = JMX_SYSTEM_MOUNT_OK;
    goto done;

rollback:
    if (renamed) {
        result->rollback_attempted = 1;
        if (((old_existed &&
              jmx_mount_write_file_atomic_mode(opts->path, old, old_len,
                                               old_mode, NULL) == 0 &&
              jmx_mount_readback_matches_mode(opts->path, old, old_len,
                                               old_mode)) ||
             (!old_existed && jmx_mount_remove_file_durable(opts->path) == 0 &&
              jmx_mount_path_exists(opts->path) == 0)) &&
            jmx_system_text_reload(opts) == 0)
            result->rollback_succeeded = 1;
        else
            snprintf(result->error, sizeof(result->error), "rollback_failed");
    }
    rc = result->rollback_attempted && !result->rollback_succeeded ?
         JMX_SYSTEM_MOUNT_ERR_ROLLBACK : JMX_SYSTEM_MOUNT_ERR_EXEC;
done:
    free(old);
    return rc;
}

#ifndef JMX_SYSTEM_MOUNT_CONTRACT_ONLY

struct json_object *jmx_system_mounts_read_json(void)
{
    struct jmx_system_mount_runtime_entry *runtime = NULL;
    struct jmx_system_mount_config_entry *configured = NULL;
    struct json_object *data = json_object_new_object();
    struct json_object *mounted = json_object_new_array();
    struct json_object *config = json_object_new_array();
    char err[JMX_SYSTEM_MOUNT_ERROR_MAX] = {0};
    size_t runtime_count = 0, configured_count = 0, i;
    int rc = JMX_SYSTEM_MOUNT_ERR_IO;

    runtime = calloc(JMX_SYSTEM_MOUNT_READ_MAX, sizeof(*runtime));
    configured = calloc(JMX_SYSTEM_MOUNT_READ_MAX, sizeof(*configured));
    if (!runtime || !configured) {
        jmx_mount_set_err(err, sizeof(err), "mount_read_oom");
    } else {
        rc = jmx_system_mount_read(NULL, runtime, JMX_SYSTEM_MOUNT_READ_MAX,
                                   &runtime_count, configured,
                                   JMX_SYSTEM_MOUNT_READ_MAX, &configured_count,
                                   err, sizeof(err));
    }
    if (rc == 0) {
        for (i = 0; i < runtime_count; i++) {
            struct json_object *o = json_object_new_object();
            char id[32];

            snprintf(id, sizeof(id), "mnt-%zu", i + 1);
            json_object_object_add(o, "id", json_object_new_string(id));
            json_object_object_add(o, "device", json_object_new_string(runtime[i].device));
            json_object_object_add(o, "source", json_object_new_string(runtime[i].source));
            json_object_object_add(o, "root", json_object_new_string(runtime[i].root));
            json_object_object_add(o, "mount", json_object_new_string(runtime[i].target));
            json_object_object_add(o, "target", json_object_new_string(runtime[i].target));
            json_object_object_add(o, "fs", json_object_new_string(runtime[i].fstype));
            json_object_object_add(o, "fstype", json_object_new_string(runtime[i].fstype));
            json_object_object_add(o, "filesystem_type",
                                   json_object_new_string(runtime[i].fstype));
            json_object_object_add(o, "options", json_object_new_string(runtime[i].options));
            json_object_object_add(o, "size_bytes",
                                   json_object_new_int64((int64_t)runtime[i].size_bytes));
            json_object_object_add(o, "used_bytes",
                                   json_object_new_int64((int64_t)runtime[i].used_bytes));
            json_object_object_add(o, "available_bytes",
                                   json_object_new_int64((int64_t)runtime[i].available_bytes));
            json_object_object_add(o, "size",
                                   json_object_new_int64((int64_t)runtime[i].size_bytes));
            json_object_object_add(o, "used_percent",
                                   json_object_new_int(runtime[i].used_percent));
            json_object_object_add(o, "major", json_object_new_int64(runtime[i].major_num));
            json_object_object_add(o, "minor", json_object_new_int64(runtime[i].minor_num));
            json_object_object_add(o, "status", json_object_new_string("mounted"));
            json_object_object_add(o, "origin",
                                   json_object_new_string(runtime[i].bind_mount ? "bind" : "runtime"));
            json_object_object_add(o, "bind_mount",
                                   json_object_new_boolean(runtime[i].bind_mount));
            /*
             * 绑定挂载的自述位。`bind_host_target` 指向宿主挂载点，
             * `capacity_is_host_filesystem` 说明容量三件套来自宿主文件系统而不是一个
             * 独立卷 —— 15 条 persist 绑定挂载与 `/data` 共享同一份容量数字，
             * 前端据此折叠展示，不要让它们各自看起来像独立的 19.5 GB 卷。
             */
            json_object_object_add(o, "bind_host_target",
                                   json_object_new_string(runtime[i].bind_host_target));
            json_object_object_add(o, "bind_host_mount",
                                   json_object_new_string(runtime[i].bind_host_target));
            json_object_object_add(o, "capacity_is_host_filesystem",
                                   json_object_new_boolean(runtime[i].bind_mount));
            json_object_object_add(o, "configured",
                                   json_object_new_boolean(runtime[i].configured));
            json_object_object_add(o, "editable", json_object_new_boolean(0));
            json_object_object_add(o, "capacity_available",
                                   json_object_new_boolean(runtime[i].stat_ok));
            json_object_array_add(mounted, o);
        }
        for (i = 0; i < configured_count; i++) {
            struct json_object *o = json_object_new_object();

            json_object_object_add(o, "id", json_object_new_string(configured[i].section));
            json_object_object_add(o, "device", json_object_new_string(configured[i].source));
            json_object_object_add(o, "source", json_object_new_string(configured[i].source));
            json_object_object_add(o, "mount", json_object_new_string(configured[i].target));
            json_object_object_add(o, "target", json_object_new_string(configured[i].target));
            json_object_object_add(o, "fs", json_object_new_string(configured[i].fstype));
            json_object_object_add(o, "fstype", json_object_new_string(configured[i].fstype));
            json_object_object_add(o, "filesystem_type",
                                   json_object_new_string(configured[i].fstype));
            json_object_object_add(o, "options", json_object_new_string(configured[i].options));
            json_object_object_add(o, "enabled", json_object_new_boolean(configured[i].enabled));
            json_object_object_add(o, "check_fs", json_object_new_boolean(configured[i].check_fs));
            json_object_object_add(o, "mounted", json_object_new_boolean(configured[i].mounted));
            json_object_object_add(o, "status",
                                   json_object_new_string(configured[i].mounted ? "mounted" :
                                                          (configured[i].enabled ? "configured" :
                                                                                   "disabled")));
            json_object_object_add(o, "origin", json_object_new_string("fstab"));
            json_object_object_add(o, "configured", json_object_new_boolean(1));
            json_object_object_add(o, "editable", json_object_new_boolean(configured[i].editable));
            json_object_array_add(config, o);
        }
    }
    json_object_object_add(data, "ok", json_object_new_boolean(rc == 0));
    json_object_object_add(data, "mounted_filesystems", mounted);
    json_object_object_add(data, "configured_points", config);
    json_object_object_add(data, "points", json_object_get(mounted));
    json_object_object_add(data, "runtime_count", json_object_new_int64((int64_t)runtime_count));
    json_object_object_add(data, "configured_count", json_object_new_int64((int64_t)configured_count));
    /*
     * v3 相对 v2 只是新增字段（`bind_host_target` / `bind_host_mount` /
     * `capacity_is_host_filesystem`），未删改任何既有字段，老前端读 v3 仍然正常。
     */
    json_object_object_add(data, "contract_version", json_object_new_string("system-mounts.v3"));
    if (err[0])
        json_object_object_add(data, "read_error", json_object_new_string(err));
    free(runtime);
    free(configured);
    return data;
}

static void jmx_system_release_add_value(struct json_object *system,
                                         struct json_object *release,
                                         const char *key, int *invalid)
{
    struct json_object *value = NULL;

    if (release && json_object_object_get_ex(release, key, &value) && value &&
        json_object_is_type(value, json_type_string) &&
        json_object_get_string(value)[0]) {
        json_object_object_add(system, key,
                               json_object_new_string(json_object_get_string(value)));
        return;
    }
    json_object_object_add(system, key, json_object_new_null());
    if (invalid)
        *invalid = 1;
}

void jmx_system_add_release_contract(struct json_object *system)
{
    struct stat st;
    struct json_object *release = NULL;
    const char *error = NULL;
    int invalid = 0;

    if (!system || !json_object_is_type(system, json_type_object))
        return;
    if (stat(JMX_RELEASE_PATH, &st) != 0) {
        error = "release_file_unavailable";
    } else if (!S_ISREG(st.st_mode) || st.st_size <= 0 ||
               st.st_size > JMX_RELEASE_MAX_BYTES) {
        error = "release_file_invalid_size";
    } else {
        release = json_object_from_file(JMX_RELEASE_PATH);
        if (!release || !json_object_is_type(release, json_type_object))
            error = "release_file_invalid_json";
    }

    jmx_system_release_add_value(system, release, "build_date", &invalid);
    jmx_system_release_add_value(system, release, "build_id", &invalid);
    jmx_system_release_add_value(system, release, "dreamingwrt_version", &invalid);
    jmx_system_release_add_value(system, release, "linux_version", &invalid);
    json_object_object_add(system, "release_source",
                           json_object_new_string(JMX_RELEASE_PATH));
    if (!error && invalid)
        error = "release_fields_missing_or_invalid";
    json_object_object_add(system, "release_error",
                           error ? json_object_new_string(error) :
                                   json_object_new_null());
    if (release)
        json_object_put(release);
}

struct json_object *jmx_api_get_system_info(struct json_object *req_obj) {
    struct json_object *data_obj = json_object_new_object();
    struct json_object *jmx_obj = json_object_new_object();
    jmx_legacy_settings_t settings;
    if (jmx_legacy_settings_get(&settings) != 0) {
        LOG_ERROR("Failed to read system settings from config.db\n");
        json_object_put(jmx_obj);
        json_object_put(data_obj);
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    json_object_object_add(jmx_obj, "lan_ifname", json_object_new_string(settings.lan_ifname));
    json_object_object_add(jmx_obj, "theme_mode", json_object_new_int(settings.theme_mode));
    json_object_object_add(data_obj, "jmx", jmx_obj);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}

/*
 * get_system_status: return system resource snapshot for AI tool / health page.
 * Matches the system_health ubus handler shape but callable as a function.
 */
struct json_object *get_system_status(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *sys = json_object_new_object();
    long long mem_total = 0, mem_used = 0;
    long long disk_total = 0, disk_used = 0;
    char hostname[128] = {0};
    FILE *fp;
    double load1 = 0;
    int cpus, temp = 0, pct, conntrack = 0;
    double up_secs = 0;
    struct statvfs vfs;

    /* hostname */
    fp = fopen("/proc/sys/kernel/hostname", "r");
    if (fp) { fgets(hostname, sizeof(hostname), fp); fclose(fp); }
    {
        size_t hl = strlen(hostname);
        while (hl > 0 && (hostname[hl-1] == '\n' || hostname[hl-1] == '\r')) hostname[--hl] = '\0';
    }

    /* memory */
    {
        long long total_kb = 0, free_kb = 0, buffers_kb = 0, cached_kb = 0, available_kb = -1;
        char line[256];
        fp = fopen("/proc/meminfo", "r");
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                long long v;
                if (sscanf(line, "MemTotal: %lld kB", &v) == 1) { total_kb = v; continue; }
                if (sscanf(line, "MemFree: %lld kB", &v) == 1) { free_kb = v; continue; }
                if (sscanf(line, "Buffers: %lld kB", &v) == 1) { buffers_kb = v; continue; }
                if (sscanf(line, "Cached: %lld kB", &v) == 1) { cached_kb = v; continue; }
                if (sscanf(line, "MemAvailable: %lld kB", &v) == 1) { available_kb = v; continue; }
            }
            fclose(fp);
            mem_total = total_kb * 1024LL;
            mem_used = available_kb >= 0 ? (total_kb - available_kb) * 1024LL : (total_kb - free_kb - buffers_kb - cached_kb) * 1024LL;
            if (mem_used < 0) mem_used = 0;
        }
    }

    /* disk */
    if (statvfs("/", &vfs) == 0) {
        disk_total = (long long)vfs.f_blocks * (long long)vfs.f_frsize;
        disk_used  = disk_total - (long long)vfs.f_bavail * (long long)vfs.f_frsize;
    }

    /* uptime */
    fp = fopen("/proc/uptime", "r");
    if (fp) { if (fscanf(fp, "%lf", &up_secs) != 1) up_secs = 0; fclose(fp); }

    /* cpu percent from loadavg */
    fp = fopen("/proc/loadavg", "r");
    if (fp) { if (fscanf(fp, "%lf", &load1) != 1) load1 = 0; fclose(fp); }
    cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (cpus <= 0) cpus = 1;
    pct = (int)((load1 * 100.0) / cpus);
    if (pct < 0) pct = 0; if (pct > 100) pct = 100;

    /* conntrack */
    {
        long long cv = 0;
        fp = fopen("/proc/sys/net/netfilter/nf_conntrack_count", "r");
        if (fp) { char b[64]; if (fgets(b, sizeof(b), fp)) cv = atoll(b); fclose(fp); }
        conntrack = (int)cv;
    }

    /* temperature */
    {
        static const char *tz_paths[] = {
            "/sys/class/thermal/thermal_zone0/temp",
            "/sys/class/thermal/thermal_zone1/temp",
            NULL
        };
        int i;
        for (i = 0; tz_paths[i]; i++) {
            fp = fopen(tz_paths[i], "r");
            if (fp) {
                if (fscanf(fp, "%d", &temp) == 1) {
                    fclose(fp);
                    if (temp > 1000) temp /= 1000;
                    break;
                }
                fclose(fp);
            }
        }
    }

    json_object_object_add(sys, "hostname", json_object_new_string(hostname));
    json_object_object_add(sys, "model", json_object_new_string("DreamingWrt"));
    json_object_object_add(sys, "uptime", json_object_new_int((int)up_secs));
    json_object_object_add(sys, "cpu_percent", json_object_new_int(pct));
    json_object_object_add(sys, "mem_total", json_object_new_int64(mem_total));
    json_object_object_add(sys, "mem_used", json_object_new_int64(mem_used));
    /* summary.system uses memory_total/memory_used; emit both names so
     * mobile/web clients see one consistent field set (iOS gap #6). The
     * mem_* names stay for existing callers. */
    json_object_object_add(sys, "memory_total", json_object_new_int64(mem_total));
    json_object_object_add(sys, "memory_used", json_object_new_int64(mem_used));
    json_object_object_add(sys, "disk_total", json_object_new_int64(disk_total));
    json_object_object_add(sys, "disk_used", json_object_new_int64(disk_used));
    json_object_object_add(sys, "connections", json_object_new_int(conntrack));
    json_object_object_add(sys, "temperature", json_object_new_int(temp));
    jmx_system_add_release_contract(sys);

    json_object_object_add(data, "system", sys);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

struct json_object *jmx_api_set_system_info(struct json_object *req_obj) {
    jmx_legacy_settings_t old_settings;
    if (!req_obj) {
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *jmx_obj = json_object_object_get(req_obj, "jmx");
    if (!jmx_obj || !json_object_is_type(jmx_obj, json_type_object)) {
        LOG_ERROR("Missing jmx parameter\n");
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *lan_ifname_obj = json_object_object_get(jmx_obj, "lan_ifname");
    if (!lan_ifname_obj || !json_object_is_type(lan_ifname_obj, json_type_string)) {
        LOG_ERROR("Missing lan_ifname parameter\n");
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    const char *lan_ifname = json_object_get_string(lan_ifname_obj);
    if (!lan_ifname || !jmx_interface_name_valid(lan_ifname, 1)) {
        LOG_ERROR("Invalid lan_ifname value\n");
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    
    struct json_object *theme_mode_obj = json_object_object_get(jmx_obj, "theme_mode");
    int theme_mode = 0; // 默认值为0（light）
    if (theme_mode_obj) {
        if (json_object_get_type(theme_mode_obj) == json_type_int) {
            theme_mode = json_object_get_int(theme_mode_obj);
        } else if (json_object_get_type(theme_mode_obj) == json_type_string) {
            theme_mode = atoi(json_object_get_string(theme_mode_obj));
        }
        // 验证值只能是0或1
        if (theme_mode != 0 && theme_mode != 1) {
            LOG_ERROR("Invalid theme_mode value, must be 0 or 1\n");
            return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
        }
    }
    
    if (jmx_legacy_settings_get(&old_settings) != 0) {
        LOG_ERROR("Failed to read current system settings from config.db\n");
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    if (jmx_update_proc_value("lan_ifname", lan_ifname) != 0) {
        LOG_ERROR("Failed to update and verify lan_ifname runtime state\n");
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    if (jmx_legacy_settings_set_system(lan_ifname, theme_mode) != 0) {
        LOG_ERROR("Failed to commit system settings to config.db\n");
        if (jmx_update_proc_value("lan_ifname", old_settings.lan_ifname) != 0)
            LOG_ERROR("Failed to roll back lan_ifname runtime state\n");
        return jmx_gen_api_response_data(API_CODE_ERROR, NULL);
    }
    LOG_DEBUG("Set system config: lan_ifname=%s, theme_mode=%d\n", lan_ifname, theme_mode);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}

static int jmx_mount_json_bool(struct json_object *obj, const char *key, int def)
{
    struct json_object *v = NULL;
    if (!obj || !json_object_object_get_ex(obj, key, &v))
        return def;
    return json_object_get_boolean(v) ? 1 : 0;
}

static const char *jmx_mount_json_str(struct json_object *obj, const char *key, const char *def)
{
    struct json_object *v = NULL;
    if (!obj || !json_object_object_get_ex(obj, key, &v))
        return def;
    return json_object_get_string(v);
}

static void jmx_mount_spec_from_json(struct json_object *obj, struct jmx_system_mount_spec *spec)
{
    const char *s;

    memset(spec, 0, sizeof(*spec));
    s = jmx_mount_json_str(obj, "source", NULL);
    if (!s) s = jmx_mount_json_str(obj, "device", "");
    snprintf(spec->source, sizeof(spec->source), "%s", s ? s : "");
    s = jmx_mount_json_str(obj, "target", NULL);
    if (!s) s = jmx_mount_json_str(obj, "mountpoint", "");
    snprintf(spec->target, sizeof(spec->target), "%s", s ? s : "");
    s = jmx_mount_json_str(obj, "fstype", "auto");
    snprintf(spec->fstype, sizeof(spec->fstype), "%s", s ? s : "auto");
    s = jmx_mount_json_str(obj, "options", "rw,noatime,nodev,nosuid,noexec");
    snprintf(spec->options, sizeof(spec->options), "%s", s ? s : "");
    spec->enabled = jmx_mount_json_bool(obj, "enabled", 1);
    spec->check_fs = jmx_mount_json_bool(obj, "check_fs", 0);
}

static void jmx_mount_opts_from_json(struct json_object *obj, struct jmx_system_mount_txn_opts *opts)
{
    memset(opts, 0, sizeof(*opts));
    /* Public JSON wrappers never trust caller-supplied paths/binaries.
     * Tests and internal callers may pass fstab_path/mount_bin through the C opts. */
    opts->dry_run = jmx_mount_json_bool(obj, "dry_run", 0);
    opts->execute_mount = jmx_mount_json_bool(obj, "execute_mount", 0);
    opts->execute_umount = jmx_mount_json_bool(obj, "execute_umount", 0);
}

static struct json_object *jmx_mount_result_json(int rc,
                                                 const struct jmx_system_mount_spec *spec,
                                                 const struct jmx_system_mount_txn_opts *opts,
                                                 const struct jmx_system_mount_txn_result *res,
                                                 const char *error)
{
    struct json_object *data = json_object_new_object();

    json_object_object_add(data, "ok", json_object_new_boolean(rc == 0));
    json_object_object_add(data, "rc", json_object_new_int(rc));
    json_object_object_add(data, "dry_run", json_object_new_boolean(opts && opts->dry_run));
    json_object_object_add(data, "source", json_object_new_string(spec ? spec->source : ""));
    json_object_object_add(data, "target", json_object_new_string(spec ? spec->target : ""));
    if (res) {
        json_object_object_add(data, "changed", json_object_new_boolean(res->changed));
        json_object_object_add(data, "executed", json_object_new_boolean(res->executed));
        json_object_object_add(data, "rolled_back", json_object_new_boolean(res->rolled_back));
        json_object_object_add(data, "backup_path", json_object_new_string(res->backup_path));
        if (res->error[0])
            json_object_object_add(data, "error", json_object_new_string(res->error));
    }
    if (error && error[0])
        json_object_object_add(data, "error", json_object_new_string(error));
    return jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}

struct json_object *jmx_api_system_mount_validate(struct json_object *req_obj)
{
    struct jmx_system_mount_spec spec;
    struct jmx_system_mount_txn_opts opts;
    char err[JMX_SYSTEM_MOUNT_ERROR_MAX] = {0};
    int rc;

    jmx_mount_spec_from_json(req_obj, &spec);
    jmx_mount_opts_from_json(req_obj, &opts);
    rc = jmx_system_mount_validate_spec(&spec, err, sizeof(err));
    return jmx_mount_result_json(rc, &spec, &opts, NULL, err);
}

struct json_object *jmx_api_system_mount_save_point(struct json_object *req_obj)
{
    struct jmx_system_mount_spec spec;
    struct jmx_system_mount_txn_opts opts;
    struct jmx_system_mount_txn_result res;
    int rc;

    jmx_mount_spec_from_json(req_obj, &spec);
    jmx_mount_opts_from_json(req_obj, &opts);
    rc = jmx_system_mount_save_point(&spec, &opts, &res);
    return jmx_mount_result_json(rc, &spec, &opts, &res, NULL);
}

struct json_object *jmx_api_system_mount_delete_point(struct json_object *req_obj)
{
    struct jmx_system_mount_spec spec;
    struct jmx_system_mount_txn_opts opts;
    struct jmx_system_mount_txn_result res;
    int rc;

    jmx_mount_spec_from_json(req_obj, &spec);
    jmx_mount_opts_from_json(req_obj, &opts);
    rc = jmx_system_mount_delete_point(&spec, &opts, &res);
    return jmx_mount_result_json(rc, &spec, &opts, &res, NULL);
}

struct json_object *jmx_api_system_mount_execute(struct json_object *req_obj)
{
    struct jmx_system_mount_spec spec;
    struct jmx_system_mount_txn_opts opts;
    struct jmx_system_mount_txn_result res;
    const char *action;
    int rc;

    jmx_mount_spec_from_json(req_obj, &spec);
    jmx_mount_opts_from_json(req_obj, &opts);
    action = jmx_mount_json_str(req_obj, "action", "mount");
    if (action && !strcmp(action, "umount"))
        rc = jmx_system_mount_exec_umount(&spec, &opts, &res);
    else
        rc = jmx_system_mount_exec_mount(&spec, &opts, &res);
    return jmx_mount_result_json(rc, &spec, &opts, &res, NULL);
}

static struct json_object *jmx_mount_probe_json(const struct jmx_system_mount_probe *p)
{
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "name", json_object_new_string(p->name));
    json_object_object_add(o, "parent", json_object_new_string(p->parent));
    json_object_object_add(o, "devnode", json_object_new_string(p->devnode));
    json_object_object_add(o, "uuid", json_object_new_string(p->uuid));
    json_object_object_add(o, "label", json_object_new_string(p->label));
    json_object_object_add(o, "partlabel", json_object_new_string(p->partlabel));
    json_object_object_add(o, "fstype", json_object_new_string(p->fstype));
    json_object_object_add(o, "stable_source", json_object_new_string(p->stable_source));
    json_object_object_add(o, "mounted_target", json_object_new_string(p->mounted_target));
    json_object_object_add(o, "excluded_reason", json_object_new_string(p->excluded_reason));
    json_object_object_add(o, "major", json_object_new_int64(p->major_num));
    json_object_object_add(o, "minor", json_object_new_int64(p->minor_num));
    json_object_object_add(o, "is_partition", json_object_new_boolean(p->is_partition));
    json_object_object_add(o, "system_disk", json_object_new_boolean(p->system_disk));
    json_object_object_add(o, "swap", json_object_new_boolean(p->swap));
    json_object_object_add(o, "config_eligible", json_object_new_boolean(p->config_eligible));
    json_object_object_add(o, "mount_eligible", json_object_new_boolean(p->mount_eligible));
    return o;
}

struct json_object *jmx_api_system_mount_discover(struct json_object *req_obj)
{
    struct jmx_system_mount_probe probes[JMX_SYSTEM_MOUNT_PROBE_MAX];
    struct json_object *data = json_object_new_object();
    struct json_object *items = json_object_new_array();
    char err[JMX_SYSTEM_MOUNT_ERROR_MAX] = {0};
    size_t count = 0, i;
    int rc;

    (void)req_obj;
    rc = jmx_system_mount_discover(NULL, probes, JMX_SYSTEM_MOUNT_PROBE_MAX,
                                   &count, err, sizeof(err));
    if (rc == 0)
        for (i = 0; i < count; i++)
            json_object_array_add(items, jmx_mount_probe_json(&probes[i]));
    json_object_object_add(data, "ok", json_object_new_boolean(rc == 0));
    json_object_object_add(data, "items", items);
    json_object_object_add(data, "count", json_object_new_int64((int64_t)count));
    json_object_object_add(data, "stable_id_required", json_object_new_boolean(1));
    json_object_object_add(data, "implicit_mount", json_object_new_boolean(0));
    if (err[0]) json_object_object_add(data, "error", json_object_new_string(err));
    return jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}

#define JMX_MOUNT_BATCH_MAX 32

struct jmx_mount_batch_item {
    struct jmx_system_mount_spec spec;
    int probe_index;
};

static int jmx_mount_find_stable_source(const struct jmx_system_mount_probe *probes,
                                        size_t count, const char *source)
{
    size_t i;
    for (i = 0; i < count; i++)
        if (source && source[0] && !strcmp(probes[i].stable_source, source))
            return (int)i;
    return -1;
}

static void jmx_mount_batch_result_add(struct json_object *results,
                                       const struct jmx_system_mount_spec *spec,
                                       const char *status, int rc,
                                       const struct jmx_system_mount_txn_result *txn,
                                       const char *error)
{
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "source", json_object_new_string(spec ? spec->source : ""));
    json_object_object_add(o, "target", json_object_new_string(spec ? spec->target : ""));
    json_object_object_add(o, "status", json_object_new_string(status ? status : "failed"));
    json_object_object_add(o, "ok", json_object_new_boolean(rc == 0));
    json_object_object_add(o, "rc", json_object_new_int(rc));
    if (txn) {
        json_object_object_add(o, "changed", json_object_new_boolean(txn->changed));
        json_object_object_add(o, "executed", json_object_new_boolean(txn->executed));
        json_object_object_add(o, "rolled_back", json_object_new_boolean(txn->rolled_back));
    }
    if (error && error[0]) json_object_object_add(o, "error", json_object_new_string(error));
    else if (txn && txn->error[0]) json_object_object_add(o, "error", json_object_new_string(txn->error));
    json_object_array_add(results, o);
}

static int jmx_mount_batch_prepare(struct json_object *req_obj, int for_mount,
                                   struct jmx_mount_batch_item *batch, size_t *batch_count,
                                   struct json_object *results, char *error, size_t error_len)
{
    struct jmx_system_mount_probe probes[JMX_SYSTEM_MOUNT_PROBE_MAX];
    struct json_object *candidates = NULL;
    size_t probe_count = 0, i, j, count;
    int rc;

    if (!req_obj || !json_object_is_type(req_obj, json_type_object) ||
        !json_object_object_get_ex(req_obj, "candidates", &candidates) ||
        !json_object_is_type(candidates, json_type_array)) {
        jmx_mount_set_err(error, error_len, "explicit_candidates_required");
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    count = json_object_array_length(candidates);
    if (!count || count > JMX_MOUNT_BATCH_MAX) {
        jmx_mount_set_err(error, error_len, count ? "too_many_candidates" : "empty_candidates");
        return JMX_SYSTEM_MOUNT_ERR_INVALID;
    }
    rc = jmx_system_mount_discover(NULL, probes, JMX_SYSTEM_MOUNT_PROBE_MAX,
                                   &probe_count, error, error_len);
    if (rc != 0) return rc;
    for (i = 0; i < count; i++) {
        struct json_object *candidate = json_object_array_get_idx(candidates, i);
        struct json_object *spec_obj = NULL;
        const char *source, *target, *options;
        int idx;
        char spec_error[JMX_SYSTEM_MOUNT_ERROR_MAX] = {0};

        memset(&batch[i], 0, sizeof(batch[i]));
        if (!candidate || !json_object_is_type(candidate, json_type_object)) {
            jmx_mount_batch_result_add(results, NULL, "rejected", JMX_SYSTEM_MOUNT_ERR_INVALID,
                                       NULL, "candidate_must_be_object");
            jmx_mount_set_err(error, error_len, "candidate_preflight_failed");
            return JMX_SYSTEM_MOUNT_ERR_INVALID;
        }
        if (!json_object_object_get_ex(candidate, "spec", &spec_obj) ||
            !json_object_is_type(spec_obj, json_type_object))
            spec_obj = candidate;
        source = jmx_mount_json_str(spec_obj, "stable_source",
                                    jmx_mount_json_str(spec_obj, "source", ""));
        target = jmx_mount_json_str(spec_obj, "target",
                                    jmx_mount_json_str(spec_obj, "mountpoint", ""));
        options = jmx_mount_json_str(spec_obj, "options", "rw,noatime,nodev,nosuid,noexec");
        if (jmx_mount_copy_checked(batch[i].spec.source,
                                   sizeof(batch[i].spec.source), source) != 0 ||
            jmx_mount_copy_checked(batch[i].spec.target,
                                   sizeof(batch[i].spec.target), target) != 0 ||
            jmx_mount_copy_checked(batch[i].spec.options,
                                   sizeof(batch[i].spec.options), options) != 0) {
            jmx_mount_batch_result_add(results, &batch[i].spec, "rejected",
                                       JMX_SYSTEM_MOUNT_ERR_INVALID, NULL,
                                       "candidate_field_too_long");
            jmx_mount_set_err(error, error_len, "candidate_preflight_failed");
            return JMX_SYSTEM_MOUNT_ERR_INVALID;
        }
        idx = jmx_mount_find_stable_source(probes, probe_count, source);
        if (idx < 0) {
            jmx_mount_batch_result_add(results, &batch[i].spec, "rejected",
                                       JMX_SYSTEM_MOUNT_ERR_INVALID, NULL,
                                       "candidate_not_in_discovery_set");
            jmx_mount_set_err(error, error_len, "candidate_preflight_failed");
            return JMX_SYSTEM_MOUNT_ERR_INVALID;
        }
        batch[i].probe_index = idx;
        if (jmx_mount_copy_checked(batch[i].spec.fstype,
                                   sizeof(batch[i].spec.fstype),
                                   probes[idx].fstype) != 0) {
            jmx_mount_batch_result_add(results, &batch[i].spec, "rejected",
                                       JMX_SYSTEM_MOUNT_ERR_INVALID, NULL,
                                       "discovered_fstype_too_long");
            jmx_mount_set_err(error, error_len, "candidate_preflight_failed");
            return JMX_SYSTEM_MOUNT_ERR_INVALID;
        }
        batch[i].spec.enabled = 1;
        batch[i].spec.check_fs = jmx_mount_json_bool(spec_obj, "check_fs", 0);
        if (!(for_mount ? probes[idx].mount_eligible : probes[idx].config_eligible)) {
            jmx_mount_batch_result_add(results, &batch[i].spec, "excluded",
                                       JMX_SYSTEM_MOUNT_ERR_INVALID, NULL,
                                       probes[idx].excluded_reason[0] ? probes[idx].excluded_reason :
                                                                      "candidate_not_eligible");
            jmx_mount_set_err(error, error_len, "candidate_preflight_failed");
            return JMX_SYSTEM_MOUNT_ERR_INVALID;
        }
        if (jmx_system_mount_validate_spec(&batch[i].spec, spec_error, sizeof(spec_error)) != 0) {
            jmx_mount_batch_result_add(results, &batch[i].spec, "rejected",
                                       JMX_SYSTEM_MOUNT_ERR_INVALID, NULL, spec_error);
            jmx_mount_set_err(error, error_len, "candidate_preflight_failed");
            return JMX_SYSTEM_MOUNT_ERR_INVALID;
        }
        for (j = 0; j < i; j++) {
            if (!strcmp(batch[j].spec.source, batch[i].spec.source) ||
                !strcmp(batch[j].spec.target, batch[i].spec.target)) {
                jmx_mount_batch_result_add(results, &batch[i].spec, "rejected",
                                           JMX_SYSTEM_MOUNT_ERR_INVALID, NULL,
                                           "duplicate_source_or_target");
                jmx_mount_set_err(error, error_len, "candidate_preflight_failed");
                return JMX_SYSTEM_MOUNT_ERR_INVALID;
            }
        }
    }
    *batch_count = count;
    return JMX_SYSTEM_MOUNT_OK;
}

static struct json_object *jmx_mount_batch_run(struct json_object *req_obj, int execute_mount)
{
    struct jmx_mount_batch_item batch[JMX_MOUNT_BATCH_MAX];
    struct jmx_system_mount_txn_opts opts;
    struct json_object *data = json_object_new_object();
    struct json_object *results = json_object_new_array();
    char error[JMX_SYSTEM_MOUNT_ERROR_MAX] = {0};
    struct jmx_system_mount_spec specs[JMX_MOUNT_BATCH_MAX];
    struct jmx_system_mount_batch_result batch_result;
    size_t count = 0, i;
    int rc, failed = 0;

    memset(&opts, 0, sizeof(opts));
    opts.dry_run = jmx_mount_json_bool(req_obj, "dry_run", 0);
    opts.execute_mount = execute_mount ? 1 : 0;
    rc = jmx_mount_batch_prepare(req_obj, execute_mount, batch, &count, results,
                                 error, sizeof(error));
    if (rc == 0) {
        for (i = 0; i < count; i++) specs[i] = batch[i].spec;
        rc = jmx_system_mount_apply_batch(specs, count, &opts, &batch_result);
        if (rc == 0) {
            for (i = 0; i < count; i++)
                jmx_mount_batch_result_add(results, &batch[i].spec,
                                           opts.dry_run ? "planned" :
                                           (execute_mount ? "mounted" : "configured"),
                                           0, &batch_result.config, NULL);
        } else if (execute_mount && batch_result.failed_index != (size_t)-1) {
            for (i = 0; i < count; i++) {
                const char *status = i < batch_result.failed_index ?
                    (batch_result.rollback_succeeded ? "rolled_back" : "rollback_failed") :
                    (i == batch_result.failed_index ? "failed" : "skipped_after_failure");
                jmx_mount_batch_result_add(results, &batch[i].spec, status, rc,
                                           &batch_result.config,
                                           i == batch_result.failed_index ? batch_result.error :
                                           (i > batch_result.failed_index ? "previous_candidate_failed" :
                                            "batch_rollback"));
            }
        } else {
            for (i = 0; i < count; i++)
                jmx_mount_batch_result_add(results, &batch[i].spec,
                                           i == 0 ? "failed" : "skipped_after_failure", rc,
                                           &batch_result.config,
                                           i == 0 ? batch_result.error : "batch_config_failed");
        }
        failed = rc != 0;
    } else {
        failed = 1;
        memset(&batch_result, 0, sizeof(batch_result));
        batch_result.failed_index = (size_t)-1;
    }
    json_object_object_add(data, "ok", json_object_new_boolean(!failed));
    json_object_object_add(data, "dry_run", json_object_new_boolean(opts.dry_run));
    json_object_object_add(data, "action", json_object_new_string(execute_mount ?
                                                                  "mount-connected" : "generate-config"));
    json_object_object_add(data, "implicit_mount", json_object_new_boolean(0));
    json_object_object_add(data, "results", results);
    json_object_object_add(data, "candidate_count", json_object_new_int64((int64_t)count));
    json_object_object_add(data, "rollback_attempted",
                           json_object_new_boolean(batch_result.rollback_attempted));
    json_object_object_add(data, "rollback_succeeded",
                           json_object_new_boolean(batch_result.rollback_succeeded));
    json_object_object_add(data, "config_rollback_succeeded",
                           json_object_new_boolean(batch_result.config_rollback_succeeded));
    json_object_object_add(data, "mounts_rollback_succeeded",
                           json_object_new_boolean(batch_result.mounts_rollback_succeeded));
    if (error[0]) json_object_object_add(data, "error", json_object_new_string(error));
    return jmx_gen_api_response_data(!failed ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}

struct json_object *jmx_api_system_mount_generate_config(struct json_object *req_obj)
{
    return jmx_mount_batch_run(req_obj, 0);
}

struct json_object *jmx_api_system_mount_connected(struct json_object *req_obj)
{
    return jmx_mount_batch_run(req_obj, 1);
}

#endif

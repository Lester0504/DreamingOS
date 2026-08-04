// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE

#include "storage_files.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#ifdef __linux__
#include <linux/openat2.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#endif
#include <time.h>
#include <unistd.h>

#ifndef STORAGE_FILES_MOUNTINFO
#define STORAGE_FILES_MOUNTINFO "/proc/self/mountinfo"
#endif

#define STORAGE_FILES_MAX_ROOTS 64
#define STORAGE_FILES_MAX_ENTRIES 1000
#define STORAGE_FILES_MAX_PATH_DEPTH 64
#define STORAGE_FILES_MAX_SEARCH 128
#define STORAGE_FILES_MAX_TEXT_BYTES (256U * 1024U)
#define STORAGE_FILES_MAX_PROBE_BYTES (4U * 1024U * 1024U)
#define STORAGE_FILES_TRANSACTION_PREFIX ".dreamingwrt-tx-"

enum storage_files_api_code {
    STORAGE_FILES_API_SUCCESS = 2000,
    STORAGE_FILES_API_ERROR = 4000,
};

struct json_object *jmx_gen_api_response_data(int code,
                                               struct json_object *data_obj);

struct storage_file_root {
    char id[48];
    char path[PATH_MAX];
    char source[PATH_MAX];
    char fstype[64];
    unsigned int major_id;
    unsigned int minor_id;
    dev_t dev;
    int read_only;
};

static uint32_t storage_files_hash(const char *text, uint32_t seed)
{
    const unsigned char *p = (const unsigned char *)(text ? text : "");
    uint32_t hash = seed ? seed : 2166136261U;

    while (*p) {
        hash ^= *p++;
        hash *= 16777619U;
    }
    return hash;
}

static struct json_object *storage_files_error(const char *code,
                                                const char *message)
{
    struct json_object *data = json_object_new_object();

    json_object_object_add(data, "error",
                           json_object_new_string(code ? code : "storage_files_error"));
    json_object_object_add(data, "message",
                           json_object_new_string(message ? message : "storage files error"));
    json_object_object_add(data, "contract_version",
                           json_object_new_string("storage-files.v1"));
    return jmx_gen_api_response_data(STORAGE_FILES_API_ERROR, data);
}

static int storage_files_unescape_mount(const char *src, char *dst, size_t len)
{
    size_t i = 0, o = 0;

    if (!src || !dst || len < 2)
        return -1;
    while (src[i]) {
        unsigned int value;

        if (src[i] == '\\' && src[i + 1] >= '0' && src[i + 1] <= '7' &&
            src[i + 2] >= '0' && src[i + 2] <= '7' &&
            src[i + 3] >= '0' && src[i + 3] <= '7') {
            value = (unsigned int)(src[i + 1] - '0') * 64U +
                    (unsigned int)(src[i + 2] - '0') * 8U +
                    (unsigned int)(src[i + 3] - '0');
            if (value == 0 || value == '/')
                return -1;
            if (o + 1 >= len)
                return -1;
            dst[o++] = (char)value;
            i += 4;
            continue;
        }
        if (o + 1 >= len)
            return -1;
        dst[o++] = src[i++];
    }
    dst[o] = '\0';
    return 0;
}

static int storage_files_path_prefix(const char *path, const char *prefix)
{
    size_t n;

    if (!path || !prefix)
        return 0;
    n = strlen(prefix);
    return !strncmp(path, prefix, n) &&
           (path[n] == '\0' || path[n] == '/');
}

static int storage_files_option_present(const char *options, const char *wanted)
{
    const char *cursor;
    size_t wanted_len;

    if (!options || !wanted || !wanted[0])
        return 0;
    wanted_len = strlen(wanted);
    for (cursor = options; *cursor;) {
        const char *end = strchr(cursor, ',');
        size_t token_len = end ? (size_t)(end - cursor) : strlen(cursor);

        if (token_len == wanted_len && !strncmp(cursor, wanted, wanted_len))
            return 1;
        if (!end)
            break;
        cursor = end + 1;
    }
    return 0;
}

/* Files whose contents must never be served even when their filesystem is
 * browsable.  Opening system disks for browsing is a deliberate product choice,
 * but credential stores and live databases are not ordinary documents: reading
 * them yields secrets or a torn snapshot, so they are denied at the server. */
static int storage_files_secret_basename(const char *name)
{
    static const char *const exact[] = {
        "shadow", "gshadow", "shadow-", "gshadow-",
        "master.passwd", "sudoers", NULL
    };
    static const char *const suffixes[] = {
        ".db", ".db-wal", ".db-shm", ".sqlite", ".sqlite3",
        ".key", ".pem", ".p8", ".p12", ".pfx", ".jks", ".keystore", NULL
    };
    size_t len;
    int i;

    if (!name || !name[0])
        return 0;
    for (i = 0; exact[i]; i++)
        if (!strcmp(name, exact[i]))
            return 1;
    len = strlen(name);
    for (i = 0; suffixes[i]; i++) {
        size_t sl = strlen(suffixes[i]);

        if (len > sl && !strcasecmp(name + len - sl, suffixes[i]))
            return 1;
    }
    return 0;
}

/* Directory subtrees whose file contents are withheld.  Listing is still
 * allowed so the tree stays navigable; only reading bytes is refused. */
static int storage_files_secret_path(const char *abs_path)
{
    static const char *const prefixes[] = {
        "/etc/dreamingwrt", "/etc/shadow", "/etc/config",
        "/etc/ssl/private", "/etc/dropbear", "/etc/ssh",
        "/root/.ssh", "/data/dreamingwrt", NULL
    };
    int i;

    if (!abs_path || !abs_path[0])
        return 0;
    for (i = 0; prefixes[i]; i++)
        if (storage_files_path_prefix(abs_path, prefixes[i]))
            return 1;
    return 0;
}

int storage_files_content_denied(const char *abs_path, const char *basename,
                                 const char **reason)
{
    if (storage_files_secret_path(abs_path)) {
        if (reason)
            *reason = "protected_system_path";
        return 1;
    }
    if (storage_files_secret_basename(basename)) {
        if (reason)
            *reason = "protected_credential_or_database_file";
        return 1;
    }
    if (reason)
        *reason = "";
    return 0;
}

/* Write/rename deny-list.  The product decision is to let operators browse and
 * edit ordinary files instead of hiding whole disks, so the compensating control
 * is that anything able to change how the system boots, authenticates, or
 * executes code stays read-only here.  File management moves bytes; it must not
 * become a way to land an executable or rewrite a service definition. */
int storage_files_write_denied(const char *abs_path, const char **reason)
{
    static const char *const exec_prefixes[] = {
        "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/lib", "/usr/lib",
        "/etc/init.d", "/etc/rc.d", "/etc/hotplug.d", "/etc/crontabs",
        "/etc/uci-defaults", "/etc/profile.d", "/boot", "/lib/modules", NULL
    };
    const char *base;
    int i;

    if (!abs_path || !abs_path[0]) {
        if (reason)
            *reason = "";
        return 0;
    }
    base = strrchr(abs_path, '/');
    base = base ? base + 1 : abs_path;
    if (storage_files_secret_path(abs_path)) {
        if (reason)
            *reason = "protected_system_path";
        return 1;
    }
    if (storage_files_secret_basename(base)) {
        if (reason)
            *reason = "protected_credential_or_database_file";
        return 1;
    }
    for (i = 0; exec_prefixes[i]; i++)
        if (storage_files_path_prefix(abs_path, exec_prefixes[i])) {
            if (reason)
                *reason = "protected_executable_or_boot_path";
            return 1;
        }
    if (!strcmp(base, "passwd") || !strcmp(base, "group") ||
        !strcmp(base, "fstab") || !strcmp(base, "inittab")) {
        if (reason)
            *reason = "protected_system_account_or_boot_file";
        return 1;
    }
    if (reason)
        *reason = "";
    return 0;
}

static int storage_files_root_allowed(const char *path, const char *fstype)
{
    static const char *const denied_fs[] = {
        "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "overlay",
        "squashfs", "debugfs", "tracefs", "securityfs", "cgroup",
        "cgroup2", "pstore", "efivarfs", "fusectl", "configfs", NULL
    };
    int i;

    if (!path || !fstype || !path[0] || !fstype[0])
        return 0;
#ifndef STORAGE_FILES_TEST_ALLOW_ANY_MOUNT_ROOT
    if (!(storage_files_path_prefix(path, "/mnt") ||
          storage_files_path_prefix(path, "/media")))
        return 0;
#endif
    for (i = 0; denied_fs[i]; i++)
        if (!strcmp(fstype, denied_fs[i]))
            return 0;
    return 1;
}

static int storage_files_protected_device(dev_t dev)
{
#ifdef STORAGE_FILES_TEST_ALLOW_PROTECTED_DEVICE
    (void)dev;
    return 0;
#else
    static const char *const paths[] = {
        "/", "/data", "/etc/dreamingwrt", "/boot", NULL
    };
    struct stat st;
    int i;

    for (i = 0; paths[i]; i++)
        if (stat(paths[i], &st) == 0 && st.st_dev == dev)
            return 1;
    return 0;
#endif
}

static int storage_files_root_cmp(const void *a, const void *b)
{
    const struct storage_file_root *ra = a;
    const struct storage_file_root *rb = b;

    return strcmp(ra->path, rb->path);
}

static int storage_files_discover_roots(struct storage_file_root *roots,
                                        size_t capacity)
{
    FILE *fp;
    char *line = NULL;
    size_t line_cap = 0;
    int count = 0;

    fp = fopen(STORAGE_FILES_MOUNTINFO, "re");
    if (!fp)
        return -1;
    while (count < (int)capacity && getline(&line, &line_cap, fp) >= 0) {
        char *fields[192];
        char *save = NULL;
        char *token;
        int field_count = 0, dash = -1;
        unsigned int maj = 0, min = 0;
        struct storage_file_root root;
        struct stat st;
        int fd;

        for (token = strtok_r(line, " ", &save); token && field_count < 192;
             token = strtok_r(NULL, " ", &save)) {
            token[strcspn(token, "\r\n")] = '\0';
            fields[field_count] = token;
            if (!strcmp(token, "-"))
                dash = field_count;
            field_count++;
        }
        if (field_count < 10 || dash < 6 || dash + 3 >= field_count ||
            sscanf(fields[2], "%u:%u", &maj, &min) != 2)
            continue;
        memset(&root, 0, sizeof(root));
        if (storage_files_unescape_mount(fields[4], root.path,
                                         sizeof(root.path)) != 0 ||
            storage_files_unescape_mount(fields[dash + 2], root.source,
                                         sizeof(root.source)) != 0)
            continue;
        snprintf(root.fstype, sizeof(root.fstype), "%s", fields[dash + 1]);
        if (!storage_files_root_allowed(root.path, root.fstype))
            continue;
        fd = open(root.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0)
            continue;
        if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) ||
            (unsigned int)major(st.st_dev) != maj ||
            (unsigned int)minor(st.st_dev) != min) {
            close(fd);
            continue;
        }
        close(fd);
        if (storage_files_protected_device(st.st_dev))
            continue;
        root.major_id = maj;
        root.minor_id = min;
        root.dev = st.st_dev;
        root.read_only = storage_files_option_present(fields[5], "ro");
        snprintf(root.id, sizeof(root.id), "mount-%u-%u-%08x", maj, min,
                 storage_files_hash(root.path,
                                    storage_files_hash(root.source, 0)));
        roots[count++] = root;
    }
    free(line);
    fclose(fp);
    qsort(roots, (size_t)count, sizeof(*roots), storage_files_root_cmp);
    return count;
}

static const struct storage_file_root *storage_files_select_root(
    const struct storage_file_root *roots, int count, const char *root_id,
    const char *path)
{
    const struct storage_file_root *best = NULL;
    size_t best_len = 0;
    int i;

    if (root_id && root_id[0]) {
        for (i = 0; i < count; i++)
            if (!strcmp(root_id, roots[i].id))
                return &roots[i];
        return NULL;
    }
    if (!path || !path[0] || !strcmp(path, "/"))
        return count > 0 ? &roots[0] : NULL;
    for (i = 0; i < count; i++) {
        size_t n = strlen(roots[i].path);

        if (n > best_len && storage_files_path_prefix(path, roots[i].path)) {
            best = &roots[i];
            best_len = n;
        }
    }
    return best;
}

static int storage_files_relative_path(const struct storage_file_root *root,
                                       const char *path, char *relative,
                                       size_t relative_len,
                                       char *display, size_t display_len)
{
    const char *cursor;
    size_t depth = 0;
    char copy[PATH_MAX];
    char *save = NULL;
    char *part;

    if (!root || !relative || relative_len < 2 || !display || display_len < 2)
        return -1;
    if (!path || !path[0] || !strcmp(path, "/"))
        path = root->path;
    if (!storage_files_path_prefix(path, root->path))
        return -1;
    cursor = path + strlen(root->path);
    while (*cursor == '/')
        cursor++;
    if (strlen(cursor) >= sizeof(copy))
        return -1;
    snprintf(copy, sizeof(copy), "%s", cursor);
    for (part = strtok_r(copy, "/", &save); part;
         part = strtok_r(NULL, "/", &save)) {
        size_t i;

        if (!part[0] || !strcmp(part, ".") || !strcmp(part, "..") ||
            ++depth > STORAGE_FILES_MAX_PATH_DEPTH)
            return -1;
        for (i = 0; part[i]; i++)
            if ((unsigned char)part[i] < 0x20 || part[i] == '\\')
                return -1;
    }
    if (strlen(cursor) >= relative_len)
        return -1;
    snprintf(relative, relative_len, "%s", cursor);
    if (!relative[0]) {
        if (snprintf(display, display_len, "%s", root->path) >= (int)display_len)
            return -1;
    } else if (snprintf(display, display_len, "%s/%s", root->path, relative) >=
               (int)display_len) {
        return -1;
    }
    return 0;
}

static int storage_files_open_directory(const struct storage_file_root *root,
                                        const char *relative)
{
    int fd;
    struct stat root_stat;

    fd = open(root->path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &root_stat) != 0 ||
        !S_ISDIR(root_stat.st_mode) || root_stat.st_dev != root->dev) {
        if (fd >= 0)
            close(fd);
        errno = EXDEV;
        return -1;
    }
    if (!relative || !relative[0])
        return fd;
#ifdef __linux__
    {
        struct open_how how = {
            .flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC,
            .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
                       RESOLVE_NO_XDEV,
        };
        int next = (int)syscall(SYS_openat2, fd, relative, &how, sizeof(how));
        struct stat st;

        if (next < 0 || fstat(next, &st) != 0 || !S_ISDIR(st.st_mode) ||
            st.st_dev != root->dev) {
            if (next >= 0)
                close(next);
            close(fd);
            errno = EXDEV;
            return -1;
        }
        close(fd);
        return next;
    }
#else
    char copy[PATH_MAX];
    char *save = NULL;
    char *part;

    snprintf(copy, sizeof(copy), "%s", relative);
    for (part = strtok_r(copy, "/", &save); part;
         part = strtok_r(NULL, "/", &save)) {
        struct stat st;
        int next = openat(fd, part,
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);

        if (next < 0 || fstat(next, &st) != 0 || !S_ISDIR(st.st_mode) ||
            st.st_dev != root->dev) {
            if (next >= 0)
                close(next);
            close(fd);
            errno = EXDEV;
            return -1;
        }
        close(fd);
        fd = next;
    }
    return fd;
#endif
}

static int storage_files_open_regular(const struct storage_file_root *root,
                                      const char *relative, struct stat *st)
{
    int root_fd, fd = -1;

    if (!root || !relative || !relative[0] || !st) {
        errno = EINVAL;
        return -1;
    }
    root_fd = open(root->path,
                   O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root_fd < 0 || fstat(root_fd, st) != 0 ||
        !S_ISDIR(st->st_mode) || st->st_dev != root->dev) {
        if (root_fd >= 0)
            close(root_fd);
        errno = EXDEV;
        return -1;
    }
#ifdef __linux__
    {
        struct open_how how = {
            .flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
            .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
                       RESOLVE_NO_XDEV,
        };

        fd = (int)syscall(SYS_openat2, root_fd, relative, &how,
                          sizeof(how));
    }
#else
    {
        char copy[PATH_MAX];
        char *save = NULL;
        char *part;
        int current = root_fd;

        snprintf(copy, sizeof(copy), "%s", relative);
        for (part = strtok_r(copy, "/", &save); part;
             part = strtok_r(NULL, "/", &save)) {
            int last = save == NULL || !save[0];
            int next = openat(current, part,
                              O_RDONLY | O_CLOEXEC | O_NOFOLLOW |
                              O_NONBLOCK | (last ? 0 : O_DIRECTORY));
            struct stat part_st;

            if (next < 0 || fstat(next, &part_st) != 0 ||
                part_st.st_dev != root->dev ||
                (!last && !S_ISDIR(part_st.st_mode))) {
                if (next >= 0)
                    close(next);
                if (current != root_fd)
                    close(current);
                fd = -1;
                break;
            }
            if (current != root_fd)
                close(current);
            current = next;
            if (last)
                fd = next;
        }
    }
#endif
    close(root_fd);
    if (fd < 0 || fstat(fd, st) != 0 || !S_ISREG(st->st_mode) ||
        st->st_dev != root->dev) {
        if (fd >= 0)
            close(fd);
        errno = EXDEV;
        return -1;
    }
    return fd;
}

static int storage_files_utf8_text(const unsigned char *data, size_t len)
{
    size_t i = 0;

    while (i < len) {
        unsigned int cp;
        unsigned char c = data[i++];

        if (c == 0)
            return 0;
        if (c < 0x80)
            continue;
        if (c >= 0xc2 && c <= 0xdf) {
            if (i >= len || (data[i] & 0xc0) != 0x80)
                return 0;
            i++;
            continue;
        }
        if (c >= 0xe0 && c <= 0xef) {
            if (i + 1 >= len || (data[i] & 0xc0) != 0x80 ||
                (data[i + 1] & 0xc0) != 0x80)
                return 0;
            cp = ((unsigned int)(c & 0x0f) << 12) |
                 ((unsigned int)(data[i] & 0x3f) << 6) |
                 (unsigned int)(data[i + 1] & 0x3f);
            if (cp < 0x800 || (cp >= 0xd800 && cp <= 0xdfff))
                return 0;
            i += 2;
            continue;
        }
        if (c >= 0xf0 && c <= 0xf4) {
            if (i + 2 >= len || (data[i] & 0xc0) != 0x80 ||
                (data[i + 1] & 0xc0) != 0x80 ||
                (data[i + 2] & 0xc0) != 0x80)
                return 0;
            cp = ((unsigned int)(c & 0x07) << 18) |
                 ((unsigned int)(data[i] & 0x3f) << 12) |
                 ((unsigned int)(data[i + 1] & 0x3f) << 6) |
                 (unsigned int)(data[i + 2] & 0x3f);
            if (cp < 0x10000 || cp > 0x10ffff)
                return 0;
            i += 3;
            continue;
        }
        return 0;
    }
    return 1;
}

static int storage_files_stat_unchanged(const struct stat *before,
                                        const struct stat *after)
{
    if (before->st_dev != after->st_dev || before->st_ino != after->st_ino ||
        before->st_size != after->st_size ||
        before->st_mtime != after->st_mtime ||
        before->st_ctime != after->st_ctime)
        return 0;
#ifdef __APPLE__
    return before->st_mtimespec.tv_nsec == after->st_mtimespec.tv_nsec &&
           before->st_ctimespec.tv_nsec == after->st_ctimespec.tv_nsec;
#else
    return before->st_mtim.tv_nsec == after->st_mtim.tv_nsec &&
           before->st_ctim.tv_nsec == after->st_ctim.tv_nsec;
#endif
}

static int storage_files_read_text_fd(int fd, const struct stat *initial,
                                      size_t max_bytes,
                                      unsigned char **content,
                                      size_t *content_len,
                                      struct stat *final)
{
    unsigned char *buffer;
    size_t used = 0;

    if (content_len)
        *content_len = 0;
    if (!initial || !content || !content_len || !final ||
        max_bytes > STORAGE_FILES_MAX_TEXT_BYTES ||
        initial->st_size < 0 || (uint64_t)initial->st_size > max_bytes) {
        errno = EFBIG;
        return -1;
    }
    buffer = malloc(max_bytes + 1U);
    if (!buffer) {
        errno = ENOMEM;
        return -1;
    }
    while (used <= max_bytes) {
        ssize_t got = read(fd, buffer + used,
                           max_bytes + 1U - used);

        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0) {
            *content_len = used;
            free(buffer);
            return -1;
        }
        if (got == 0)
            break;
        used += (size_t)got;
        if (used > max_bytes) {
            *content_len = used;
            free(buffer);
            errno = EFBIG;
            return -1;
        }
    }
    if (fstat(fd, final) != 0 || !S_ISREG(final->st_mode) ||
        !storage_files_stat_unchanged(initial, final)) {
        *content_len = used;
        free(buffer);
        errno = ESTALE;
        return -1;
    }
    if (!storage_files_utf8_text(buffer, used)) {
        *content_len = used;
        free(buffer);
        errno = EILSEQ;
        return -1;
    }
    buffer[used] = '\0';
    *content = buffer;
    *content_len = used;
    return 0;
}

static int storage_files_probe_text_at(int dir_fd, const char *name,
                                       const struct storage_file_root *root,
                                       const struct stat *listed,
                                       size_t *probe_budget)
{
    struct stat opened, final;
    unsigned char *content = NULL;
    size_t content_len = 0;
    size_t read_limit;
    int fd, ok;

    if (!probe_budget || *probe_budget == 0 ||
        !S_ISREG(listed->st_mode) || listed->st_size < 0 ||
        (uint64_t)listed->st_size > STORAGE_FILES_MAX_TEXT_BYTES ||
        (uint64_t)listed->st_size > *probe_budget)
        return 0;
    fd = openat(dir_fd, name,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &opened) != 0 || !S_ISREG(opened.st_mode) ||
        opened.st_dev != root->dev || opened.st_ino != listed->st_ino) {
        if (fd >= 0)
            close(fd);
        return 0;
    }
    read_limit = *probe_budget < STORAGE_FILES_MAX_TEXT_BYTES ?
                 *probe_budget : STORAGE_FILES_MAX_TEXT_BYTES;
    ok = storage_files_read_text_fd(fd, &opened, read_limit, &content,
                                    &content_len, &final) == 0;
    {
        size_t charged = content_len ? content_len : 1U;

        if (charged > *probe_budget)
            charged = *probe_budget;
        *probe_budget -= charged;
    }
    free(content);
    close(fd);
    return ok;
}

static void storage_files_mode(char out[11], mode_t mode)
{
    static const mode_t bits[] = {
        S_IRUSR, S_IWUSR, S_IXUSR, S_IRGRP, S_IWGRP,
        S_IXGRP, S_IROTH, S_IWOTH, S_IXOTH
    };
    static const char chars[] = "rwxrwxrwx";
    int i;

    out[0] = S_ISDIR(mode) ? 'd' : S_ISLNK(mode) ? 'l' : S_ISREG(mode) ? '-' : '?';
    for (i = 0; i < 9; i++)
        out[i + 1] = (mode & bits[i]) ? chars[i] : '-';
    out[10] = '\0';
}

static const char *storage_files_kind(mode_t mode)
{
    if (S_ISDIR(mode)) return "directory";
    if (S_ISREG(mode)) return "file";
    if (S_ISLNK(mode)) return "symlink";
    return "other";
}

static int storage_files_name_matches(const char *name, const char *search)
{
    size_t i, j, name_len, search_len;

    if (!search || !search[0])
        return 1;
    name_len = strlen(name);
    search_len = strlen(search);
    if (search_len > name_len)
        return 0;
    for (i = 0; i + search_len <= name_len; i++) {
        for (j = 0; j < search_len; j++)
            if (tolower((unsigned char)name[i + j]) !=
                tolower((unsigned char)search[j]))
                break;
        if (j == search_len)
            return 1;
    }
    return 0;
}

static struct json_object *storage_files_capabilities(int directory,
                                                      int text_read)
{
    static const char *const disabled[] = {
        "download", "write", "mkdir", "create", "rename",
        "permissions", "upload", "download_url", "copy", "move",
        "compress", "extract", "delete", "install_package", NULL
    };
    struct json_object *caps = json_object_new_object();
    int i;

    json_object_object_add(caps, "list", json_object_new_boolean(directory));
    json_object_object_add(caps, "read", json_object_new_boolean(text_read));
    json_object_object_add(caps, "preview", json_object_new_boolean(text_read));
    for (i = 0; disabled[i]; i++)
        json_object_object_add(caps, disabled[i], json_object_new_boolean(0));
    return caps;
}

static struct json_object *storage_files_root_json(const struct storage_file_root *root)
{
    struct json_object *item = json_object_new_object();
    struct statvfs vfs;

    json_object_object_add(item, "id", json_object_new_string(root->id));
    json_object_object_add(item, "label", json_object_new_string(root->path));
    json_object_object_add(item, "path", json_object_new_string(root->path));
    json_object_object_add(item, "source", json_object_new_string(root->source));
    json_object_object_add(item, "fstype", json_object_new_string(root->fstype));
    json_object_object_add(item, "read_only", json_object_new_boolean(root->read_only));
    if (statvfs(root->path, &vfs) == 0) {
        json_object_object_add(item, "total_bytes", json_object_new_int64(
            (int64_t)vfs.f_blocks * (int64_t)vfs.f_frsize));
        json_object_object_add(item, "available_bytes", json_object_new_int64(
            (int64_t)vfs.f_bavail * (int64_t)vfs.f_frsize));
    }
    return item;
}

static struct json_object *storage_files_empty(void)
{
    struct json_object *data = json_object_new_object();
    struct json_object *limits = json_object_new_object();
    struct json_object *reasons = json_object_new_object();

    json_object_object_add(data, "contract_version",
                           json_object_new_string("storage-files.v1"));
    json_object_object_add(data, "source",
                           json_object_new_string("mountinfo+openat-nofollow"));
    json_object_object_add(data, "available", json_object_new_boolean(0));
    json_object_object_add(data, "reason",
                           json_object_new_string("no_eligible_storage_roots"));
    json_object_object_add(data, "root_id", json_object_new_string(""));
    json_object_object_add(data, "path", json_object_new_string("/"));
    json_object_object_add(data, "roots", json_object_new_array());
    json_object_object_add(data, "entries", json_object_new_array());
    json_object_object_add(data, "entries_truncated", json_object_new_boolean(0));
    json_object_object_add(data, "capabilities", storage_files_capabilities(0, 0));
    json_object_object_add(limits, "max_entries", json_object_new_int(
        STORAGE_FILES_MAX_ENTRIES));
    json_object_object_add(limits, "max_path_depth", json_object_new_int(
        STORAGE_FILES_MAX_PATH_DEPTH));
    json_object_object_add(limits, "max_upload_bytes", json_object_new_int64(0));
    json_object_object_add(limits, "max_edit_bytes", json_object_new_int64(0));
    json_object_object_add(limits, "max_text_read_bytes",
                           json_object_new_int64(STORAGE_FILES_MAX_TEXT_BYTES));
    json_object_object_add(data, "limits", limits);
    json_object_object_add(reasons, "list",
                           json_object_new_string("no_eligible_storage_roots"));
    json_object_object_add(data, "capability_reasons", reasons);
    json_object_object_add(data, "generated_at",
                           json_object_new_int64((int64_t)time(NULL)));
    return jmx_gen_api_response_data(STORAGE_FILES_API_SUCCESS, data);
}

struct json_object *jmx_storage_files_list(const char *root_id,
                                           const char *path,
                                           const char *search)
{
    struct storage_file_root roots[STORAGE_FILES_MAX_ROOTS];
    const struct storage_file_root *root;
    struct json_object *data, *root_array, *entries, *limits, *reasons;
    char relative[PATH_MAX], display[PATH_MAX];
    int root_count, fd, dup_fd, emitted = 0, truncated = 0, i;
    size_t probe_budget = STORAGE_FILES_MAX_PROBE_BYTES;
    DIR *dir;
    struct dirent *entry;

    if ((root_id && strlen(root_id) >= 48) ||
        (path && strlen(path) >= PATH_MAX) ||
        (search && strlen(search) > STORAGE_FILES_MAX_SEARCH))
        return storage_files_error("invalid_request", "root, path, or search is too long");
    root_count = storage_files_discover_roots(roots, STORAGE_FILES_MAX_ROOTS);
    if (root_count < 0)
        return storage_files_error("mount_inventory_unavailable",
                                   "mount inventory is unavailable");
    if (root_count == 0 && (!root_id || !root_id[0]) &&
        (!path || !path[0] || !strcmp(path, "/")))
        return storage_files_empty();
    root = storage_files_select_root(roots, root_count, root_id, path);
    if (!root)
        return storage_files_error("storage_root_not_found",
                                   "storage root is not available");
    if (storage_files_relative_path(root, path, relative, sizeof(relative),
                                    display, sizeof(display)) != 0)
        return storage_files_error("invalid_relative_path",
                                   "path must remain inside the selected storage root");
    fd = storage_files_open_directory(root, relative);
    if (fd < 0)
        return storage_files_error(errno == EXDEV ? "mount_boundary_rejected" :
                                   "directory_unavailable",
                                   "directory cannot be opened without following links or mounts");
    dup_fd = dup(fd);
    if (dup_fd < 0) {
        close(fd);
        return storage_files_error("directory_unavailable", "directory handle failed");
    }
    dir = fdopendir(dup_fd);
    if (!dir) {
        close(dup_fd);
        close(fd);
        return storage_files_error("directory_unavailable", "directory stream failed");
    }
    data = json_object_new_object();
    root_array = json_object_new_array();
    entries = json_object_new_array();
    limits = json_object_new_object();
    reasons = json_object_new_object();
    for (i = 0; i < root_count; i++)
        json_object_array_add(root_array, storage_files_root_json(&roots[i]));
    while ((entry = readdir(dir)) != NULL) {
        struct stat st;
        struct json_object *item;
        struct passwd *pw;
        struct group *gr;
        char mode[11], item_path[PATH_MAX], item_id[PATH_MAX + 64];
        const char *kind;
        int text_read;

        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..") ||
            !storage_files_name_matches(entry->d_name, search))
            continue;
        if (emitted >= STORAGE_FILES_MAX_ENTRIES) {
            truncated = 1;
            break;
        }
        if (fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0)
            continue;
        kind = storage_files_kind(st.st_mode);
        text_read = storage_files_probe_text_at(fd, entry->d_name, root, &st,
                                                &probe_budget);
        if (snprintf(item_path, sizeof(item_path), "%s/%s", display,
                     entry->d_name) >= (int)sizeof(item_path) ||
            snprintf(item_id, sizeof(item_id), "%s:%s", root->id,
                     relative[0] ? item_path + strlen(root->path) + 1 :
                     entry->d_name) >= (int)sizeof(item_id))
            continue;
        storage_files_mode(mode, st.st_mode);
        item = json_object_new_object();
        json_object_object_add(item, "id", json_object_new_string(item_id));
        json_object_object_add(item, "name", json_object_new_string(entry->d_name));
        json_object_object_add(item, "path", json_object_new_string(item_path));
        json_object_object_add(item, "kind",
                               json_object_new_string(text_read ? "text" : kind));
        json_object_object_add(item, "mime", json_object_new_string(
            text_read ? "text/plain; charset=utf-8" : ""));
        json_object_object_add(item, "is_dir", json_object_new_boolean(S_ISDIR(st.st_mode)));
        json_object_object_add(item, "is_symlink", json_object_new_boolean(S_ISLNK(st.st_mode)));
        json_object_object_add(item, "size_bytes", json_object_new_int64((int64_t)st.st_size));
        json_object_object_add(item, "modified_unix", json_object_new_int64((int64_t)st.st_mtime));
        json_object_object_add(item, "mode", json_object_new_string(mode));
        {
            char octal[8];
            snprintf(octal, sizeof(octal), "%04o", (unsigned int)(st.st_mode & 07777));
            json_object_object_add(item, "mode_octal", json_object_new_string(octal));
        }
        pw = getpwuid(st.st_uid);
        gr = getgrgid(st.st_gid);
        json_object_object_add(item, "owner",
                               json_object_new_string(pw ? pw->pw_name : ""));
        json_object_object_add(item, "group",
                               json_object_new_string(gr ? gr->gr_name : ""));
        json_object_object_add(item, "capabilities",
                               storage_files_capabilities(S_ISDIR(st.st_mode) &&
                                                          st.st_dev == root->dev,
                                                          text_read));
        json_object_array_add(entries, item);
        emitted++;
    }
    closedir(dir);
    close(fd);
    json_object_object_add(data, "contract_version",
                           json_object_new_string("storage-files.v1"));
    json_object_object_add(data, "source",
                           json_object_new_string("mountinfo+openat-nofollow"));
    json_object_object_add(data, "available", json_object_new_boolean(1));
    json_object_object_add(data, "root_id", json_object_new_string(root->id));
    json_object_object_add(data, "path", json_object_new_string(display));
    json_object_object_add(data, "roots", root_array);
    json_object_object_add(data, "entries", entries);
    json_object_object_add(data, "entries_truncated", json_object_new_boolean(truncated));
    json_object_object_add(data, "capabilities", storage_files_capabilities(1, 0));
    json_object_object_add(limits, "max_entries", json_object_new_int(STORAGE_FILES_MAX_ENTRIES));
    json_object_object_add(limits, "max_path_depth",
                           json_object_new_int(STORAGE_FILES_MAX_PATH_DEPTH));
    json_object_object_add(limits, "max_upload_bytes", json_object_new_int64(0));
    json_object_object_add(limits, "max_edit_bytes", json_object_new_int64(0));
    json_object_object_add(limits, "max_text_read_bytes",
                           json_object_new_int64(STORAGE_FILES_MAX_TEXT_BYTES));
    json_object_object_add(limits, "max_text_probe_bytes_per_listing",
                           json_object_new_int64(STORAGE_FILES_MAX_PROBE_BYTES));
    json_object_object_add(data, "limits", limits);
    json_object_object_add(reasons, "content_read",
                           json_object_new_string("small_utf8_text_only"));
    json_object_object_add(reasons, "write",
                           json_object_new_string("storage_file_write_jobs_pending"));
    json_object_object_add(reasons, "download_url",
                           json_object_new_string("ssrf_safe_download_job_pending"));
    json_object_object_add(reasons, "archive",
                           json_object_new_string("archive_safety_job_pending"));
    json_object_object_add(data, "capability_reasons", reasons);
    json_object_object_add(data, "generated_at",
                           json_object_new_int64((int64_t)time(NULL)));
    return jmx_gen_api_response_data(STORAGE_FILES_API_SUCCESS, data);
}

struct json_object *jmx_storage_files_content(const char *root_id,
                                              const char *path)
{
    struct storage_file_root roots[STORAGE_FILES_MAX_ROOTS];
    const struct storage_file_root *root;
    struct json_object *data;
    struct stat initial, final;
    unsigned char *content = NULL;
    size_t content_len = 0;
    char relative[PATH_MAX], display[PATH_MAX], etag[128];
    const char *newline = "none";
    int root_count, fd;
    size_t i;
    int saw_lf = 0, saw_crlf = 0, saw_cr = 0;

    if ((root_id && strlen(root_id) >= 48) || !path || !path[0] ||
        strlen(path) >= PATH_MAX)
        return storage_files_error("invalid_request",
                                   "root or path is missing or too long");
    root_count = storage_files_discover_roots(roots, STORAGE_FILES_MAX_ROOTS);
    if (root_count < 0)
        return storage_files_error("mount_inventory_unavailable",
                                   "mount inventory is unavailable");
    root = storage_files_select_root(roots, root_count, root_id, path);
    if (!root)
        return storage_files_error("storage_root_not_found",
                                   "storage root is not available");
    if (storage_files_relative_path(root, path, relative, sizeof(relative),
                                    display, sizeof(display)) != 0 ||
        !relative[0])
        return storage_files_error("invalid_relative_path",
                                   "file path must remain inside the selected storage root");
    {
        const char *deny_reason = "";
        const char *base = strrchr(display, '/');

        /* Refuse before opening: a credential store or live database must not be
         * served even if every path guard above is satisfied. */
        if (storage_files_content_denied(display, base ? base + 1 : display,
                                         &deny_reason))
            return storage_files_error("content_protected", deny_reason);
    }
    fd = storage_files_open_regular(root, relative, &initial);
    if (fd < 0)
        return storage_files_error(errno == EXDEV ? "mount_boundary_rejected" :
                                   "file_unavailable",
                                   "file cannot be opened without following links or mounts");
    if (storage_files_read_text_fd(fd, &initial,
                                   STORAGE_FILES_MAX_TEXT_BYTES, &content,
                                   &content_len, &final) != 0) {
        int saved = errno;

        close(fd);
        if (saved == EFBIG)
            return storage_files_error("text_too_large",
                                       "text content exceeds 256 KiB");
        if (saved == EILSEQ)
            return storage_files_error("not_utf8_text",
                                       "file is binary or not valid UTF-8 text");
        return storage_files_error("file_read_failed",
                                   "file changed or could not be read safely");
    }
    close(fd);
    for (i = 0; i < content_len; i++) {
        if (content[i] == '\r' && i + 1 < content_len && content[i + 1] == '\n') {
            saw_crlf = 1;
            i++;
        } else if (content[i] == '\r') {
            saw_cr = 1;
        } else if (content[i] == '\n') {
            saw_lf = 1;
        }
    }
    if ((saw_lf + saw_crlf + saw_cr) > 1)
        newline = "mixed";
    else if (saw_crlf)
        newline = "crlf";
    else if (saw_cr)
        newline = "cr";
    else if (saw_lf)
        newline = "lf";
    snprintf(etag, sizeof(etag), "W/\"%llx-%llx-%llx\"",
             (unsigned long long)final.st_ino,
             (unsigned long long)final.st_size,
             (unsigned long long)final.st_mtime);
    data = json_object_new_object();
    json_object_object_add(data, "contract_version",
                           json_object_new_string("storage-files.v1"));
    json_object_object_add(data, "root_id", json_object_new_string(root->id));
    json_object_object_add(data, "path", json_object_new_string(display));
    json_object_object_add(data, "content",
                           json_object_new_string_len((const char *)content,
                                                      (int)content_len));
    json_object_object_add(data, "text",
                           json_object_new_string_len((const char *)content,
                                                      (int)content_len));
    json_object_object_add(data, "mime",
                           json_object_new_string("text/plain; charset=utf-8"));
    json_object_object_add(data, "encoding", json_object_new_string("utf-8"));
    json_object_object_add(data, "newline", json_object_new_string(newline));
    json_object_object_add(data, "size_bytes",
                           json_object_new_int64((int64_t)content_len));
    json_object_object_add(data, "modified_unix",
                           json_object_new_int64((int64_t)final.st_mtime));
    json_object_object_add(data, "etag", json_object_new_string(etag));
    json_object_object_add(data, "read_only", json_object_new_boolean(1));
    json_object_object_add(data, "truncated", json_object_new_boolean(0));
    free(content);
    return jmx_gen_api_response_data(STORAGE_FILES_API_SUCCESS, data);
}

static const char *storage_files_json_string(struct json_object *object,
                                             const char *key)
{
    struct json_object *value = NULL;

    if (!object || !json_object_object_get_ex(object, key, &value) || !value ||
        !json_object_is_type(value, json_type_string))
        return "";
    return json_object_get_string(value);
}

static int storage_files_json_bool(struct json_object *object, const char *key)
{
    struct json_object *value = NULL;

    return object && json_object_object_get_ex(object, key, &value) && value &&
           json_object_is_type(value, json_type_boolean) &&
           json_object_get_boolean(value);
}

static int storage_files_safe_name(const char *name)
{
    size_t i, length;

    if (!name || !name[0] || !strcmp(name, ".") || !strcmp(name, ".."))
        return 0;
    length = strlen(name);
    if (length > NAME_MAX || !strncmp(name, STORAGE_FILES_TRANSACTION_PREFIX,
                                      strlen(STORAGE_FILES_TRANSACTION_PREFIX)))
        return 0;
    for (i = 0; i < length; i++)
        if ((unsigned char)name[i] < 0x20 || name[i] == '/' || name[i] == '\\')
            return 0;
    return 1;
}

static int storage_files_join_path(char *out, size_t out_len,
                                   const char *parent, const char *name)
{
    size_t parent_len, name_len;
    int slash;

    if (!out || out_len < 2 || !parent || !parent[0] || !name || !name[0])
        return -1;
    parent_len = strlen(parent);
    name_len = strlen(name);
    slash = parent[parent_len - 1] != '/';
    if (parent_len >= out_len || name_len >= out_len ||
        parent_len + (size_t)slash > out_len - name_len - 1)
        return -1;
    memcpy(out, parent, parent_len);
    if (slash)
        out[parent_len++] = '/';
    memcpy(out + parent_len, name, name_len);
    out[parent_len + name_len] = 0;
    return 0;
}

static void storage_files_etag(const struct stat *st, char *out, size_t out_len)
{
    snprintf(out, out_len, "W/\"%llx-%llx-%llx\"",
             (unsigned long long)st->st_ino,
             (unsigned long long)st->st_size,
             (unsigned long long)st->st_mtime);
}

static struct json_object *storage_files_mutation_result(
    const char *transaction_id, const char *action, const char *path,
    int changed, int persisted, int applied, int readback_verified,
    int rolled_back, int cleanup_pending)
{
    struct json_object *data = json_object_new_object();

    json_object_object_add(data, "contract_version",
                           json_object_new_string("storage-files.v1"));
    json_object_object_add(data, "transaction_id",
                           json_object_new_string(transaction_id));
    json_object_object_add(data, "action", json_object_new_string(action));
    json_object_object_add(data, "path", json_object_new_string(path));
    json_object_object_add(data, "changed", json_object_new_boolean(changed));
    json_object_object_add(data, "persisted", json_object_new_boolean(persisted));
    json_object_object_add(data, "applied", json_object_new_boolean(applied));
    json_object_object_add(data, "apply_scope",
                           json_object_new_string("filesystem_namespace"));
    json_object_object_add(data, "readback_verified",
                           json_object_new_boolean(readback_verified));
    json_object_object_add(data, "rolled_back",
                           json_object_new_boolean(rolled_back));
    json_object_object_add(data, "cleanup_pending",
                           json_object_new_boolean(cleanup_pending));
    return jmx_gen_api_response_data(STORAGE_FILES_API_SUCCESS, data);
}

static struct json_object *storage_files_mutation_error(
    const char *code, const char *message, const char *transaction_id,
    int changed, int rolled_back)
{
    struct json_object *response = storage_files_error(code, message);
    struct json_object *data = NULL;

    if (json_object_object_get_ex(response, "data", &data) && data) {
        json_object_object_add(data, "transaction_id",
                               json_object_new_string(transaction_id));
        json_object_object_add(data, "changed", json_object_new_boolean(changed));
        json_object_object_add(data, "persisted", json_object_new_boolean(0));
        json_object_object_add(data, "applied", json_object_new_boolean(0));
        json_object_object_add(data, "readback_verified",
                               json_object_new_boolean(0));
        json_object_object_add(data, "rolled_back",
                               json_object_new_boolean(rolled_back));
    }
    return response;
}

static int storage_files_write_all(int fd, const unsigned char *data, size_t len)
{
    size_t offset = 0;

    while (offset < len) {
        ssize_t written = write(fd, data + offset, len - offset);

        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return -1;
        offset += (size_t)written;
    }
    return 0;
}

static int storage_files_split_relative(const char *relative, char *parent,
                                        size_t parent_len, char *name,
                                        size_t name_len)
{
    const char *slash;

    if (!relative || !relative[0])
        return -1;
    slash = strrchr(relative, '/');
    if (!slash) {
        parent[0] = '\0';
        return snprintf(name, name_len, "%s", relative) < (int)name_len ? 0 : -1;
    }
    if ((size_t)(slash - relative) >= parent_len ||
        snprintf(name, name_len, "%s", slash + 1) >= (int)name_len)
        return -1;
    memcpy(parent, relative, (size_t)(slash - relative));
    parent[slash - relative] = '\0';
    return 0;
}

struct json_object *jmx_storage_files_mutate(struct json_object *payload)
{
    struct storage_file_root roots[STORAGE_FILES_MAX_ROOTS];
    const struct storage_file_root *root;
    const char *action = storage_files_json_string(payload, "action");
    const char *root_id = storage_files_json_string(payload, "root_id");
    const char *path = storage_files_json_string(payload, "path");
    const char *name = storage_files_json_string(payload, "name");
    const char *new_name = storage_files_json_string(payload, "new_name");
    const char *content = storage_files_json_string(payload, "content");
    const char *expected_etag = storage_files_json_string(payload, "expected_etag");
    char relative[PATH_MAX], display[PATH_MAX], parent[PATH_MAX], leaf[NAME_MAX + 1];
    char transaction_id[96], temporary[NAME_MAX + 1], result_path[PATH_MAX];
    int root_count, parent_fd = -1, temp_fd = -1, changed = 0, rolled_back = 0;
    struct stat before, after;
    unsigned int nonce = (unsigned int)time(NULL) ^ (unsigned int)getpid();

    snprintf(transaction_id, sizeof(transaction_id), "storage-%lld-%u",
             (long long)time(NULL), nonce);
    if (!payload || !json_object_is_type(payload, json_type_object) ||
        !storage_files_json_bool(payload, "confirm"))
        return storage_files_mutation_error("confirmation_required",
            "confirm=true is required for storage writes", transaction_id, 0, 0);
    if (strcmp(action, "mkdir") && strcmp(action, "create") &&
        strcmp(action, "write") && strcmp(action, "rename"))
        return storage_files_mutation_error("unsupported_action",
            "only mkdir, create, write and rename are supported", transaction_id, 0, 0);
    root_count = storage_files_discover_roots(roots, STORAGE_FILES_MAX_ROOTS);
    if (root_count < 0)
        return storage_files_mutation_error("mount_inventory_unavailable",
            "mount inventory is unavailable", transaction_id, 0, 0);
    root = storage_files_select_root(roots, root_count, root_id, path);
    if (!root)
        return storage_files_mutation_error("storage_root_not_found",
            "storage root is not available", transaction_id, 0, 0);
    if (root->read_only)
        return storage_files_mutation_error("storage_root_read_only",
            "selected storage root is read only", transaction_id, 0, 0);
    if (storage_files_relative_path(root, path, relative, sizeof(relative),
                                    display, sizeof(display)) != 0)
        return storage_files_mutation_error("invalid_relative_path",
            "path must remain inside the selected storage root", transaction_id, 0, 0);
    {
        const char *deny_reason = "";
        char candidate[PATH_MAX];

        /* Deny writes into protected subtrees, and deny creating a protected
         * name inside an otherwise writable directory.  Checked here rather than
         * only at the HTTP layer so the guard holds for any future caller. */
        if (storage_files_write_denied(display, &deny_reason))
            return storage_files_mutation_error("write_protected", deny_reason,
                                                transaction_id, 0, 0);
        if (name && name[0] &&
            storage_files_join_path(candidate, sizeof(candidate), display, name) == 0 &&
            storage_files_write_denied(candidate, &deny_reason))
            return storage_files_mutation_error("write_protected", deny_reason,
                                                transaction_id, 0, 0);
        if (new_name && new_name[0] &&
            storage_files_join_path(candidate, sizeof(candidate), display, new_name) == 0 &&
            storage_files_write_denied(candidate, &deny_reason))
            return storage_files_mutation_error("write_protected", deny_reason,
                                                transaction_id, 0, 0);
    }

    if (!strcmp(action, "mkdir") || !strcmp(action, "create")) {
        if (!storage_files_safe_name(name))
            return storage_files_mutation_error("invalid_name",
                "name must be one safe path component", transaction_id, 0, 0);
        parent_fd = storage_files_open_directory(root, relative);
        if (parent_fd < 0)
            return storage_files_mutation_error("directory_unavailable",
                "parent directory cannot be opened safely", transaction_id, 0, 0);
        if (storage_files_join_path(result_path, sizeof(result_path), display,
                                    name) != 0)
            goto invalid_path;
        if (!strcmp(action, "mkdir")) {
            if (mkdirat(parent_fd, name, 0755) != 0)
                goto mutation_failed;
            changed = 1;
            if (fsync(parent_fd) != 0 ||
                fstatat(parent_fd, name, &after, AT_SYMLINK_NOFOLLOW) != 0 ||
                !S_ISDIR(after.st_mode) || after.st_dev != root->dev) {
                rolled_back = unlinkat(parent_fd, name, AT_REMOVEDIR) == 0;
                fsync(parent_fd);
                goto mutation_failed;
            }
        } else {
            size_t content_len = strlen(content);

            if (content_len > STORAGE_FILES_MAX_TEXT_BYTES ||
                !storage_files_utf8_text((const unsigned char *)content, content_len))
                goto invalid_content;
            snprintf(temporary, sizeof(temporary), "%s%u",
                     STORAGE_FILES_TRANSACTION_PREFIX, nonce);
            temp_fd = openat(parent_fd, temporary,
                             O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                             0644);
            if (temp_fd < 0)
                goto mutation_failed;
            if (storage_files_write_all(temp_fd,
                                        (const unsigned char *)content,
                                        content_len) != 0 || fsync(temp_fd) != 0 ||
                close(temp_fd) != 0) {
                temp_fd = -1;
                unlinkat(parent_fd, temporary, 0);
                goto mutation_failed;
            }
            temp_fd = -1;
#ifdef __linux__
            if (syscall(SYS_renameat2, parent_fd, temporary, parent_fd, name,
                        RENAME_NOREPLACE) != 0) {
                unlinkat(parent_fd, temporary, 0);
                goto mutation_failed;
            }
            changed = 1;
            if (fsync(parent_fd) != 0 ||
                fstatat(parent_fd, name, &after, AT_SYMLINK_NOFOLLOW) != 0 ||
                !S_ISREG(after.st_mode) || after.st_dev != root->dev ||
                (uint64_t)after.st_size != content_len) {
                rolled_back = unlinkat(parent_fd, name, 0) == 0;
                fsync(parent_fd);
                goto mutation_failed;
            }
#else
            unlinkat(parent_fd, temporary, 0);
            errno = ENOTSUP;
            goto mutation_failed;
#endif
        }
        close(parent_fd);
        return storage_files_mutation_result(transaction_id, action, result_path,
                                             1, 1, 1, 1, 0, 0);
    }

    if (!relative[0] ||
        storage_files_split_relative(relative, parent, sizeof(parent), leaf,
                                     sizeof(leaf)) != 0 ||
        !storage_files_safe_name(leaf))
        goto invalid_path;
    parent_fd = storage_files_open_directory(root, parent);
    if (parent_fd < 0)
        return storage_files_mutation_error("directory_unavailable",
            "parent directory cannot be opened safely", transaction_id, 0, 0);
    if (fstatat(parent_fd, leaf, &before, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(before.st_mode) || before.st_dev != root->dev)
        goto mutation_failed;
    if (!strcmp(action, "rename")) {
        char parent_display[PATH_MAX];

        if (!storage_files_safe_name(new_name))
            goto invalid_name;
        if (parent[0]) {
            if (storage_files_join_path(parent_display, sizeof(parent_display),
                                        root->path, parent) != 0 ||
                storage_files_join_path(result_path, sizeof(result_path),
                                        parent_display, new_name) != 0)
                goto invalid_path;
        } else if (storage_files_join_path(result_path, sizeof(result_path),
                                           root->path, new_name) != 0) {
            goto invalid_path;
        }
#ifdef __linux__
        if (syscall(SYS_renameat2, parent_fd, leaf, parent_fd, new_name,
                    RENAME_NOREPLACE) != 0)
            goto mutation_failed;
        changed = 1;
        if (fsync(parent_fd) != 0 ||
            fstatat(parent_fd, new_name, &after, AT_SYMLINK_NOFOLLOW) != 0 ||
            after.st_dev != before.st_dev || after.st_ino != before.st_ino) {
            rolled_back = syscall(SYS_renameat2, parent_fd, new_name, parent_fd,
                                  leaf, RENAME_NOREPLACE) == 0;
            fsync(parent_fd);
            goto mutation_failed;
        }
#else
        errno = ENOTSUP;
        goto mutation_failed;
#endif
        close(parent_fd);
        return storage_files_mutation_result(transaction_id, action, result_path,
                                             1, 1, 1, 1, 0, 0);
    }

    if (!expected_etag[0]) {
        close(parent_fd);
        return storage_files_mutation_error("expected_etag_required",
            "expected_etag is required for replacing text", transaction_id, 0, 0);
    }
    {
        char current_etag[128];
        size_t content_len = strlen(content);

        storage_files_etag(&before, current_etag, sizeof(current_etag));
        if (strcmp(current_etag, expected_etag)) {
            close(parent_fd);
            return storage_files_mutation_error("revision_conflict",
                "file changed since it was read", transaction_id, 0, 0);
        }
        if (content_len > STORAGE_FILES_MAX_TEXT_BYTES ||
            !storage_files_utf8_text((const unsigned char *)content, content_len))
            goto invalid_content;
        snprintf(temporary, sizeof(temporary), "%s%u", STORAGE_FILES_TRANSACTION_PREFIX,
                 nonce);
        temp_fd = openat(parent_fd, temporary,
                         O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                         before.st_mode & 0777);
        if (temp_fd < 0 ||
            storage_files_write_all(temp_fd, (const unsigned char *)content,
                                    content_len) != 0 ||
            fsync(temp_fd) != 0 || close(temp_fd) != 0) {
            if (temp_fd >= 0)
                close(temp_fd);
            temp_fd = -1;
            unlinkat(parent_fd, temporary, 0);
            goto mutation_failed;
        }
        temp_fd = -1;
#ifdef __linux__
        if (fstatat(parent_fd, leaf, &after, AT_SYMLINK_NOFOLLOW) != 0 ||
            !storage_files_stat_unchanged(&before, &after) ||
            syscall(SYS_renameat2, parent_fd, temporary, parent_fd, leaf,
                    RENAME_EXCHANGE) != 0) {
            unlinkat(parent_fd, temporary, 0);
            goto mutation_failed;
        }
        changed = 1;
        if (fsync(parent_fd) != 0 ||
            fstatat(parent_fd, leaf, &after, AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISREG(after.st_mode) || after.st_dev != root->dev ||
            (uint64_t)after.st_size != content_len) {
            if (syscall(SYS_renameat2, parent_fd, temporary, parent_fd, leaf,
                        RENAME_EXCHANGE) == 0) {
                rolled_back = 1;
                unlinkat(parent_fd, temporary, 0);
                fsync(parent_fd);
            }
            goto mutation_failed;
        }
        if (unlinkat(parent_fd, temporary, 0) != 0) {
            close(parent_fd);
            return storage_files_mutation_result(transaction_id, action, display,
                                                 1, 1, 1, 1, 0, 1);
        }
        if (fsync(parent_fd) != 0) {
            close(parent_fd);
            return storage_files_mutation_result(transaction_id, action, display,
                                                 1, 1, 1, 1, 0, 0);
        }
#else
        unlinkat(parent_fd, temporary, 0);
        errno = ENOTSUP;
        goto mutation_failed;
#endif
    }
    close(parent_fd);
    return storage_files_mutation_result(transaction_id, action, display,
                                         1, 1, 1, 1, 0, 0);

invalid_content:
    if (parent_fd >= 0)
        close(parent_fd);
    return storage_files_mutation_error("invalid_text_content",
        "content must be UTF-8 text no larger than 256 KiB", transaction_id, 0, 0);
invalid_name:
    if (parent_fd >= 0)
        close(parent_fd);
    return storage_files_mutation_error("invalid_name",
        "name must be one safe path component", transaction_id, 0, 0);
invalid_path:
    if (parent_fd >= 0)
        close(parent_fd);
    return storage_files_mutation_error("invalid_relative_path",
        "path must remain inside the selected storage root", transaction_id, 0, 0);
mutation_failed:
    if (temp_fd >= 0)
        close(temp_fd);
    if (parent_fd >= 0)
        close(parent_fd);
    return storage_files_mutation_error("filesystem_transaction_failed",
        "filesystem transaction failed and was not committed", transaction_id,
        changed, rolled_back);
}

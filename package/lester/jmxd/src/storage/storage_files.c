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
#define STORAGE_FILES_TRASH_DIR ".dwrt-trash"
#define STORAGE_FILES_UPLOAD_DIR ".dwrt-upload"
/* Chunked upload: a chunk index fits in chunk.%08u, so bound total chunks. */
#define STORAGE_FILES_MAX_UPLOAD_CHUNKS 100000
#define STORAGE_FILES_UPLOAD_META ".meta"
/* Recursive search bounds: a hard cap on hits returned and on directory
 * entries examined, plus the shared depth ceiling, so a search on a huge tree
 * costs bounded work and memory rather than walking the whole disk. */
#define STORAGE_FILES_MAX_SEARCH_HITS 5000
#define STORAGE_FILES_SEARCH_EXAMINE_BUDGET 200000L
/* Per-directory-level cap on names buffered during a recursive delete/copy:
 * names are collected one level at a time so the tree can be mutated safely
 * while iterating, and this bounds the memory that costs. */
#define STORAGE_FILES_MAX_DIR_ENTRIES 200000
/* Batch move/copy/delete: cap on how many targets one request may carry. */
#define STORAGE_FILES_MAX_BATCH 512
/* Copy I/O buffer for the recursive file copy path. */
#define STORAGE_FILES_COPY_BUF (128U * 1024U)

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
    char mount_root[PATH_MAX];
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
    if (n == 1 && prefix[0] == '/')
        return path[0] == '/';
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
        "/root/.ssh", "/data/dreamingwrt",
        "/overlay/dreamingos-appstore/data/security-center",
        "/overlay/dreamingos-appstore/data/remote-browser", NULL
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

/* Mount points that must never become a browsable root.  These are excluded by
 * path, not by device: the system disk itself stays browsable on purpose, so
 * excluding a whole device would take the entire filesystem with it.  What is
 * withheld here is the credential and live-state material that has no business
 * being served as a document, plus kernel/runtime surfaces that are not files
 * in any useful sense. */
static int storage_files_root_excluded(const char *path)
{
    static const char *const excluded[] = {
        "/etc/shadow", "/etc/dropbear", "/etc/ssh", "/etc/ssl/private",
        "/etc/dreamingwrt", "/data/dreamingwrt",
        "/proc", "/sys", "/dev", "/run", NULL
    };
    int i;

    if (!path || !path[0])
        return 0;
    for (i = 0; excluded[i]; i++)
        if (storage_files_path_prefix(path, excluded[i]))
            return 1;
    return 0;
}

/* Root admission.  The product decision is that operators may browse the real
 * filesystem instead of being shown an empty page, so admission is decided per
 * path and per filesystem type rather than by excluding the system disk
 * wholesale.  The blanket "/mnt + /media only" rule combined with a
 * same-device exclusion left zero roots on any router whose data lives on the
 * system disk, which is every current unit.  Path-traversal defence is
 * unchanged and orthogonal: it lives in the openat2 walk below. */
static int storage_files_root_allowed(const char *path, const char *fstype)
{
    static const char *const denied_fs[] = {
        "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "overlay",
        "squashfs", "debugfs", "tracefs", "securityfs", "cgroup",
        "cgroup2", "pstore", "efivarfs", "fusectl", "configfs",
        "bpf", "nfsd", "mqueue", "hugetlbfs", "binfmt_misc",
        "autofs", "rpc_pipefs", "selinuxfs", NULL
    };
    int i;

    if (!path || !fstype || !path[0] || !fstype[0])
        return 0;
    if (path[0] != '/')
        return 0;
#ifdef STORAGE_FILES_TEST_ALLOW_ANY_MOUNT_ROOT
    (void)storage_files_root_excluded;
#else
    if (storage_files_root_excluded(path))
        return 0;
#endif
    for (i = 0; denied_fs[i]; i++)
        if (!strcmp(fstype, denied_fs[i]))
            return 0;
    return 1;
}

/* Roots that are browsable but must not be written through this interface.
 * Individual paths are still filtered by storage_files_write_denied(); this is
 * the coarser statement that a root holding the running system is presented
 * read-only, so the UI does not offer edit affordances it will then refuse. */
static int storage_files_root_write_protected(const char *path)
{
    static const char *const protected_roots[] = {
        "/", "/boot", "/etc", "/etc/config", "/etc/crontabs",
        "/etc/nginx", "/etc/samba", "/etc/rc.local", NULL
    };
    int i;

    if (!path || !path[0])
        return 0;
    for (i = 0; protected_roots[i]; i++)
        if (!strcmp(path, protected_roots[i]))
            return 1;
    return 0;
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
        if (storage_files_unescape_mount(fields[3], root.mount_root,
                                         sizeof(root.mount_root)) != 0 ||
            storage_files_unescape_mount(fields[4], root.path,
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
        root.major_id = maj;
        root.minor_id = min;
        root.dev = st.st_dev;
        root.read_only = storage_files_option_present(fields[5], "ro");
        if (storage_files_root_write_protected(root.path))
            root.read_only = 1;
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
    relative[0] = '\0';
    for (part = strtok_r(copy, "/", &save); part;
         part = strtok_r(NULL, "/", &save)) {
        size_t i;

        if (!part[0] || !strcmp(part, ".") || !strcmp(part, "..") ||
            ++depth > STORAGE_FILES_MAX_PATH_DEPTH)
            return -1;
        for (i = 0; part[i]; i++)
            if ((unsigned char)part[i] < 0x20 || part[i] == '\\')
                return -1;
        if (strlen(relative) + strlen(part) + 2 > relative_len)
            return -1;
        if (relative[0])
            strcat(relative, "/");
        strcat(relative, part);
    }
    if (!relative[0]) {
        if (snprintf(display, display_len, "%s", root->path) >= (int)display_len)
            return -1;
    } else if (snprintf(display, display_len, "%s%s%s", root->path,
                        !strcmp(root->path, "/") ? "" : "/", relative) >=
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

int storage_files_open_dir(const char *root_id, const char *path, int writing,
                           char *canonical, size_t canonical_size,
                           const char **reason)
{
    struct storage_file_root roots[STORAGE_FILES_MAX_ROOTS];
    char relative[PATH_MAX], display[PATH_MAX];
    int count = storage_files_discover_roots(roots, STORAGE_FILES_MAX_ROOTS);
    const struct storage_file_root *root = count < 0 ? NULL :
        storage_files_select_root(roots, count, root_id, path);
    if (!root) { if (reason) *reason = "storage_root_not_found"; return -1; }
    if (storage_files_relative_path(root, path, relative, sizeof(relative),
                                    display, sizeof(display)) != 0) {
        if (reason) *reason = "invalid_relative_path";
        return -1;
    }
    if (storage_files_content_denied(display, "", reason) ||
        (writing && (root->read_only || storage_files_write_denied(display, reason)))) {
        if (reason && root->read_only) *reason = "storage_root_read_only";
        return -1;
    }
    if (canonical && snprintf(canonical, canonical_size, "%s", display) >= (int)canonical_size) {
        if (reason) *reason = "invalid_relative_path";
        return -1;
    }
    int fd = storage_files_open_directory(root, relative);
    if (fd < 0 && reason) *reason = "directory_unavailable";
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

/* Case-insensitive glob supporting '*' (any run) and '?' (one char), matched
 * against the whole basename.  Iterative with backtracking so a pattern such as
 * "*.log" costs O(name*pattern) worst case and never recurses. */
static int storage_files_wildcard(const char *pattern, const char *name)
{
    const char *p = pattern, *s = name;
    const char *star = NULL, *star_s = NULL;

    if (!pattern || !name)
        return 0;
    while (*s) {
        if (*p == '*') {
            star = p++;
            star_s = s;
        } else if (*p == '?' ||
                   tolower((unsigned char)*p) == tolower((unsigned char)*s)) {
            p++;
            s++;
        } else if (star) {
            p = star + 1;
            s = ++star_s;
        } else {
            return 0;
        }
    }
    while (*p == '*')
        p++;
    return *p == '\0';
}

static struct json_object *storage_files_search_entry(
    const struct storage_file_root *root, const char *display,
    const char *name, const struct stat *st)
{
    struct json_object *item = json_object_new_object();
    char item_id[PATH_MAX + 64];
    const char *rel = display + strlen(root->path);

    while (*rel == '/')
        rel++;
    json_object_object_add(item, "name", json_object_new_string(name));
    json_object_object_add(item, "path", json_object_new_string(display));
    if (snprintf(item_id, sizeof(item_id), "%s:%s", root->id, rel) <
        (int)sizeof(item_id))
        json_object_object_add(item, "id", json_object_new_string(item_id));
    json_object_object_add(item, "root_id", json_object_new_string(root->id));
    json_object_object_add(item, "kind",
                           json_object_new_string(storage_files_kind(st->st_mode)));
    json_object_object_add(item, "is_dir",
                           json_object_new_boolean(S_ISDIR(st->st_mode)));
    json_object_object_add(item, "is_symlink",
                           json_object_new_boolean(S_ISLNK(st->st_mode)));
    json_object_object_add(item, "size_bytes",
                           json_object_new_int64((int64_t)st->st_size));
    json_object_object_add(item, "modified_unix",
                           json_object_new_int64((int64_t)st->st_mtime));
    return item;
}

/* Depth-first recursive match.  Read-only, so deleting-while-iterating is not a
 * concern here; the walk still honours the mount boundary (st_dev == root->dev),
 * never follows symlinks (O_NOFOLLOW + AT_SYMLINK_NOFOLLOW), and stops the moment
 * either the hit limit or the examine budget is spent. */
static void storage_files_search_walk(int dir_fd,
                                      const struct storage_file_root *root,
                                      const char *display_dir, const char *query,
                                      int has_glob, struct json_object *files,
                                      int limit, int depth, long *examined,
                                      int *limited)
{
    int dup_fd;
    DIR *dir;
    struct dirent *entry;

    if (*limited || depth > STORAGE_FILES_MAX_PATH_DEPTH)
        return;
    dup_fd = dup(dir_fd);
    dir = dup_fd >= 0 ? fdopendir(dup_fd) : NULL;
    if (!dir) {
        if (dup_fd >= 0)
            close(dup_fd);
        return;
    }
    while ((entry = readdir(dir)) != NULL) {
        struct stat st;
        char child[PATH_MAX];
        int is_dir, matched, have_child;

        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        if (++(*examined) > STORAGE_FILES_SEARCH_EXAMINE_BUDGET) {
            *limited = 1;
            break;
        }
        if (fstatat(dir_fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0)
            continue;
        is_dir = S_ISDIR(st.st_mode) && st.st_dev == root->dev;
        have_child = snprintf(child, sizeof(child), "%s%s%s", display_dir,
                              !strcmp(display_dir, "/") ? "" : "/", entry->d_name) < (int)sizeof(child);
        matched = has_glob ? storage_files_wildcard(query, entry->d_name) :
                             storage_files_name_matches(entry->d_name, query);
        if (matched && have_child) {
            if (json_object_array_length(files) >= (size_t)limit) {
                *limited = 1;
                break;
            }
            json_object_array_add(files,
                storage_files_search_entry(root, child, entry->d_name, &st));
        }
        if (is_dir && have_child) {
            int child_fd = openat(dir_fd, entry->d_name,
                                  O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                  O_NOFOLLOW);

            if (child_fd >= 0) {
                struct stat cst;

                if (fstat(child_fd, &cst) == 0 && S_ISDIR(cst.st_mode) &&
                    cst.st_dev == root->dev)
                    storage_files_search_walk(child_fd, root, child, query,
                                              has_glob, files, limit, depth + 1,
                                              examined, limited);
                close(child_fd);
            }
        }
        if (*limited)
            break;
    }
    closedir(dir);
}

struct json_object *jmx_storage_files_search(const char *root_id,
                                             const char *path,
                                             const char *query, int limit)
{
    struct storage_file_root roots[STORAGE_FILES_MAX_ROOTS];
    const struct storage_file_root *root;
    struct json_object *data, *files;
    char relative[PATH_MAX], display[PATH_MAX];
    int root_count, fd, has_glob, limited = 0;
    long examined = 0;

    if ((root_id && strlen(root_id) >= 48) ||
        (path && strlen(path) >= PATH_MAX) ||
        !query || strlen(query) > STORAGE_FILES_MAX_SEARCH)
        return storage_files_error("invalid_request",
                                   "root, path, or query is missing or too long");
    if (!query[0])
        return storage_files_error("search_query_required",
                                   "query must not be empty");
    if (limit <= 0 || limit > STORAGE_FILES_MAX_SEARCH_HITS)
        limit = STORAGE_FILES_MAX_SEARCH_HITS;
    root_count = storage_files_discover_roots(roots, STORAGE_FILES_MAX_ROOTS);
    if (root_count < 0)
        return storage_files_error("mount_inventory_unavailable",
                                   "mount inventory is unavailable");
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
    has_glob = strpbrk(query, "*?") != NULL;
    files = json_object_new_array();
    storage_files_search_walk(fd, root, display, query, has_glob, files, limit,
                              0, &examined, &limited);
    close(fd);
    data = json_object_new_object();
    json_object_object_add(data, "contract_version",
                           json_object_new_string("storage-files.v1"));
    json_object_object_add(data, "root_id", json_object_new_string(root->id));
    json_object_object_add(data, "path", json_object_new_string(display));
    json_object_object_add(data, "query", json_object_new_string(query));
    json_object_object_add(data, "files", files);
    json_object_object_add(data, "total",
                           json_object_new_int((int)json_object_array_length(files)));
    json_object_object_add(data, "examined", json_object_new_int64(examined));
    json_object_object_add(data, "limited", json_object_new_boolean(limited));
    json_object_object_add(data, "limit", json_object_new_int(limit));
    json_object_object_add(data, "generated_at",
                           json_object_new_int64((int64_t)time(NULL)));
    return jmx_gen_api_response_data(STORAGE_FILES_API_SUCCESS, data);
}

/* These are object/filesystem capabilities, not grants of HTTP permission.
 * The gateway still gates content/raw/search/writes as MEDIUM. */
static struct json_object *storage_files_capabilities(int directory,
                                                      int text_read,
                                                      int stream_read,
                                                      int writable)
{
    static const char *const unsupported[] = {
        "permissions", "download_url", "compress", "extract", "install_package", NULL
    };
    struct json_object *caps = json_object_new_object();
    int i;
#define CAP(key, value) json_object_object_add(caps, key, json_object_new_boolean(value))
    CAP("list", directory);
    CAP("read", text_read);
    CAP("preview", text_read || stream_read);
    CAP("download", stream_read);
    CAP("search", directory);
    CAP("upload", directory && writable);
    CAP("mkdir", directory && writable);
    CAP("create", directory && writable);
    CAP("rename", writable);
    CAP("delete", writable);
    CAP("move", writable);
    CAP("copy", directory || stream_read);
    CAP("write", writable && (text_read || directory));
#undef CAP
    for (i = 0; unsupported[i]; i++)
        json_object_object_add(caps, unsupported[i], json_object_new_boolean(0));
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
    json_object_object_add(item, "mount_root", json_object_new_string(root->mount_root));
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

struct json_object *storage_files_roots_json(void)
{
    struct storage_file_root roots[STORAGE_FILES_MAX_ROOTS];
    int count = storage_files_discover_roots(roots, STORAGE_FILES_MAX_ROOTS);
    if (count < 0) return NULL;
    struct json_object *items = json_object_new_array();
    for (int i = 0; i < count; i++)
        json_object_array_add(items, storage_files_root_json(&roots[i]));
    return items;
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
    json_object_object_add(data, "capabilities", storage_files_capabilities(0, 0, 0, 0));
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
        int text_read, content_ok, writable;
        const char *deny_reason = "";

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
        if (snprintf(item_path, sizeof(item_path), "%s%s%s", display,
                     !strcmp(display, "/") ? "" : "/", entry->d_name) >= (int)sizeof(item_path) ||
            snprintf(item_id, sizeof(item_id), "%s:%s", root->id,
                     relative[0] ? item_path + strlen(root->path) + 1 :
                     entry->d_name) >= (int)sizeof(item_id))
            continue;
        content_ok = st.st_dev == root->dev &&
            !storage_files_content_denied(item_path, entry->d_name, &deny_reason);
        writable = !root->read_only && st.st_dev == root->dev &&
            (S_ISDIR(st.st_mode) || S_ISREG(st.st_mode)) &&
            !storage_files_write_denied(item_path, &deny_reason);
        text_read = content_ok && storage_files_probe_text_at(
            fd, entry->d_name, root, &st, &probe_budget);
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
                                                          text_read,
                                                          content_ok && S_ISREG(st.st_mode),
                                                          writable));
        if (!content_ok || !writable) {
            struct json_object *why = json_object_new_object();
            if (!content_ok) {
                const char *reason = "mount_boundary_rejected";
                storage_files_content_denied(item_path, entry->d_name, &reason);
                json_object_object_add(why, "preview", json_object_new_string(reason));
                json_object_object_add(why, "read", json_object_new_string(reason));
                json_object_object_add(why, "download", json_object_new_string(reason));
            }
            if (!writable)
                json_object_object_add(why, "write", json_object_new_string(
                    root->read_only ? "storage_root_read_only" :
                    deny_reason[0] ? deny_reason : "object_not_writable"));
            json_object_object_add(item, "capability_reasons", why);
        }
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
    json_object_object_add(data, "capabilities",
                           storage_files_capabilities(1, 0, 0, !root->read_only &&
                               !storage_files_write_denied(display, NULL)));
    json_object_object_add(limits, "max_entries", json_object_new_int(STORAGE_FILES_MAX_ENTRIES));
    json_object_object_add(limits, "max_path_depth",
                           json_object_new_int(STORAGE_FILES_MAX_PATH_DEPTH));
    json_object_object_add(limits, "max_upload_bytes", json_object_new_int64(0));
    json_object_object_add(limits, "max_edit_bytes", json_object_new_int64(STORAGE_FILES_MAX_TEXT_BYTES));
    json_object_object_add(limits, "max_text_read_bytes",
                           json_object_new_int64(STORAGE_FILES_MAX_TEXT_BYTES));
    json_object_object_add(limits, "max_text_probe_bytes_per_listing",
                           json_object_new_int64(STORAGE_FILES_MAX_PROBE_BYTES));
    json_object_object_add(data, "limits", limits);
    json_object_object_add(reasons, "content_read",
                           json_object_new_string("small_utf8_text_only"));
    /* The write route is wired, so the only remaining reason to refuse is a
     * read-only root.  The former "jobs pending" reason would misattribute the
     * refusal in the UI, so it is gone rather than reworded. */
    if (root->read_only)
        json_object_object_add(reasons, "write",
                               json_object_new_string("storage_root_read_only"));
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
    json_object_object_add(data, "read_only", json_object_new_boolean(
        root->read_only || storage_files_write_denied(display, NULL)));
    json_object_object_add(data, "max_edit_bytes", json_object_new_int64(STORAGE_FILES_MAX_TEXT_BYTES));
    json_object_object_add(data, "truncated", json_object_new_boolean(0));
    free(content);
    return jmx_gen_api_response_data(STORAGE_FILES_API_SUCCESS, data);
}

/* Byte-stream open for the raw/download route.
 *
 * Returns a read-only descriptor instead of a JSON body: the caller streams the
 * bytes itself, because a video does not fit in a ubus message and must not be
 * buffered into one.  Every guard the JSON content path applies is applied here
 * in the same order -- root discovery, relative-path validation, the content
 * deny-list, then storage_files_open_regular()'s nofollow / no-xdev open.  The
 * two limits that are specific to *text* (256 KiB and UTF-8 validity) are the
 * only ones deliberately absent, since refusing binary is precisely what this
 * entry point exists to lift.
 *
 * On success the descriptor is positioned at offset 0 and the caller owns it.
 * On failure nothing is opened and *reason is a stable machine code, chosen from
 * the same vocabulary jmx_storage_files_content() already returns so the HTTP
 * layer does not invent a second error dialect.
 */
int storage_files_open_stream(const char *root_id, const char *path,
                              struct storage_files_stream *out,
                              const char **reason)
{
    struct storage_file_root roots[STORAGE_FILES_MAX_ROOTS];
    const struct storage_file_root *root;
    struct stat st;
    char relative[PATH_MAX], display[PATH_MAX];
    const char *base;
    int root_count, fd;

    if (reason)
        *reason = "";
    if (!out || (root_id && strlen(root_id) >= sizeof(roots[0].id)) ||
        !path || !path[0] || strlen(path) >= PATH_MAX) {
        if (reason)
            *reason = "invalid_request";
        return -1;
    }
    memset(out, 0, sizeof(*out));
    out->fd = -1;
    root_count = storage_files_discover_roots(roots, STORAGE_FILES_MAX_ROOTS);
    if (root_count < 0) {
        if (reason)
            *reason = "mount_inventory_unavailable";
        return -1;
    }
    root = storage_files_select_root(roots, root_count, root_id, path);
    if (!root) {
        if (reason)
            *reason = "storage_root_not_found";
        return -1;
    }
    if (storage_files_relative_path(root, path, relative, sizeof(relative),
                                    display, sizeof(display)) != 0 ||
        !relative[0]) {
        if (reason)
            *reason = "invalid_relative_path";
        return -1;
    }
    base = strrchr(display, '/');
    base = base ? base + 1 : display;
    /* Refuse before opening, exactly as the JSON content path does: a
     * credential store or live database must not become downloadable just
     * because the transport changed from JSON to a byte stream. */
    if (storage_files_content_denied(display, base, reason))
        return -1;
    fd = storage_files_open_regular(root, relative, &st);
    if (fd < 0) {
        if (reason)
            *reason = errno == EXDEV ? "mount_boundary_rejected" :
                                       "file_unavailable";
        return -1;
    }
    /* storage_files_open_regular() opens O_NONBLOCK so a fifo cannot stall the
     * open; it also guarantees S_ISREG, so clearing the flag here cannot block
     * on anything.  Streaming wants blocking reads. */
    {
        int flags = fcntl(fd, F_GETFL);

        if (flags >= 0)
            (void)fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    }
    out->fd = fd;
    out->size_bytes = (uint64_t)st.st_size;
    out->modified_unix = (int64_t)st.st_mtime;
    out->inode = (uint64_t)st.st_ino;
    snprintf(out->root_id, sizeof(out->root_id), "%s", root->id);
    snprintf(out->display_path, sizeof(out->display_path), "%s", display);
    /* A single component cannot exceed NAME_MAX on any filesystem we admit as a
     * root, so this cannot trip in practice; it is a hard check rather than a
     * truncating copy because the basename becomes a Content-Disposition
     * filename, and a silently shortened name is a wrong name. */
    {
        size_t base_len = strlen(base);

        if (base_len >= sizeof(out->basename)) {
            close(fd);
            out->fd = -1;
            if (reason)
                *reason = "invalid_relative_path";
            return -1;
        }
        memcpy(out->basename, base, base_len + 1U);
    }
    return 0;
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

/* Snapshot one directory level's names before mutating it.  readdir() over a
 * directory being unlinked from is undefined, so delete and copy collect the
 * names first (one level at a time, bounded by STORAGE_FILES_MAX_DIR_ENTRIES)
 * and then act, instead of deleting mid-iteration. */
static int storage_files_read_dir_names(int dir_fd, char ***out,
                                        size_t *count_out)
{
    int dup_fd = dup(dir_fd);
    DIR *dir = dup_fd >= 0 ? fdopendir(dup_fd) : NULL;
    char **names = NULL;
    size_t cap = 0, count = 0, i;
    struct dirent *entry;

    *out = NULL;
    *count_out = 0;
    if (!dir) {
        if (dup_fd >= 0)
            close(dup_fd);
        return -1;
    }
    while ((entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        if (count >= STORAGE_FILES_MAX_DIR_ENTRIES) {
            errno = EFBIG;
            goto fail;
        }
        if (count == cap) {
            size_t next = cap ? cap * 2 : 64;
            char **grown = realloc(names, next * sizeof(*names));

            if (!grown) {
                errno = ENOMEM;
                goto fail;
            }
            names = grown;
            cap = next;
        }
        names[count] = strdup(entry->d_name);
        if (!names[count]) {
            errno = ENOMEM;
            goto fail;
        }
        count++;
    }
    closedir(dir);
    *out = names;
    *count_out = count;
    return 0;
fail:
    closedir(dir);
    for (i = 0; i < count; i++)
        free(names[i]);
    free(names);
    return -1;
}

/* Check descendants before a directory rename/delete/copy can move protected
 * content indirectly. The caller already has a nofollow parent handle. */
static int storage_files_tree_allowed(int parent_fd, const char *name,
                                      const char *display, dev_t dev,
                                      int writing, int depth, long *budget)
{
    struct stat st;
    const char *reason = "";
    char **names = NULL;
    size_t count = 0, i;
    int fd, rc = 0;
    if (--*budget < 0 || depth > STORAGE_FILES_MAX_PATH_DEPTH) {
        errno = E2BIG;
        return -1;
    }
    if (storage_files_content_denied(display, name, &reason) ||
        (writing && storage_files_write_denied(display, &reason))) {
        errno = EACCES;
        return -1;
    }
    if (fstatat(parent_fd, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return -1;
    if (st.st_dev != dev) { errno = EXDEV; return -1; }
    if (!S_ISDIR(st.st_mode)) return 0;
    fd = openat(parent_fd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (storage_files_read_dir_names(fd, &names, &count) != 0) {
        close(fd);
        return -1;
    }
    for (i = 0; i < count; i++) {
        char child[PATH_MAX];
        if (storage_files_join_path(child, sizeof(child), display, names[i]) != 0 ||
            storage_files_tree_allowed(fd, names[i], child, dev, writing,
                                        depth + 1, budget) != 0) {
            rc = -1;
            break;
        }
    }
    for (i = 0; i < count; i++) free(names[i]);
    free(names);
    close(fd);
    return rc;
}

/* Recursive remove under an already-validated parent fd.  Never follows a
 * symlink (unlinks the link itself) and never crosses a mount boundary: a
 * nested mount shows a different st_dev and makes the delete fail EXDEV rather
 * than reaching into another filesystem. */
static int storage_files_remove_recursive(int parent_fd, const char *name,
                                           dev_t dev, int depth)
{
    struct stat st;
    char **names = NULL;
    size_t count = 0, i;
    int dir_fd, rc = 0;

    if (storage_files_secret_basename(name)) { errno = EACCES; return -1; }
    if (fstatat(parent_fd, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return -1;
    if (st.st_dev != dev) {
        errno = EXDEV;
        return -1;
    }
    if (!S_ISDIR(st.st_mode))
        return unlinkat(parent_fd, name, 0);
    if (depth > STORAGE_FILES_MAX_PATH_DEPTH) {
        errno = ELOOP;
        return -1;
    }
    dir_fd = openat(parent_fd, name,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dir_fd < 0)
        return -1;
    {
        struct stat dst;

        if (fstat(dir_fd, &dst) != 0 || dst.st_dev != dev ||
            dst.st_ino != st.st_ino) {
            close(dir_fd);
            errno = EXDEV;
            return -1;
        }
    }
    if (storage_files_read_dir_names(dir_fd, &names, &count) != 0) {
        close(dir_fd);
        return -1;
    }
    for (i = 0; i < count; i++)
        if (storage_files_remove_recursive(dir_fd, names[i], dev,
                                           depth + 1) != 0) {
            rc = -1;
            break;
        }
    for (i = 0; i < count; i++)
        free(names[i]);
    free(names);
    close(dir_fd);
    if (rc == 0)
        rc = unlinkat(parent_fd, name, AT_REMOVEDIR);
    return rc;
}

static int storage_files_copy_bytes(int src_fd, int dst_fd)
{
    char *buffer = malloc(STORAGE_FILES_COPY_BUF);

    if (!buffer) {
        errno = ENOMEM;
        return -1;
    }
    for (;;) {
        ssize_t got = read(src_fd, buffer, STORAGE_FILES_COPY_BUF);

        if (got < 0) {
            if (errno == EINTR)
                continue;
            free(buffer);
            return -1;
        }
        if (got == 0)
            break;
        if (storage_files_write_all(dst_fd, (const unsigned char *)buffer,
                                    (size_t)got) != 0) {
            free(buffer);
            return -1;
        }
    }
    free(buffer);
    return 0;
}

/* Recursive copy preserving type, permission bits and mtime.  Files are created
 * O_EXCL so a copy can never clobber a name that appeared after the conflict
 * check; symlinks are recreated verbatim (never followed); mounts and other
 * devices are refused by the st_dev guard.  A failed file copy unlinks its
 * partial output so a half-written file is not left behind. */
static int storage_files_copy_recursive(int src_parent, const char *src_name,
                                         int dst_parent, const char *dst_name,
                                         dev_t src_dev, int depth)
{
    struct stat st;
    struct timespec times[2];

    if (depth > STORAGE_FILES_MAX_PATH_DEPTH) {
        errno = ELOOP;
        return -1;
    }
    if (storage_files_secret_basename(src_name) || storage_files_secret_basename(dst_name)) {
        errno = EACCES;
        return -1;
    }
    if (fstatat(src_parent, src_name, &st, AT_SYMLINK_NOFOLLOW) != 0)
        return -1;
    if (st.st_dev != src_dev) {
        errno = EXDEV;
        return -1;
    }
#ifdef __APPLE__
    times[0] = st.st_atimespec;
    times[1] = st.st_mtimespec;
#else
    times[0] = st.st_atim;
    times[1] = st.st_mtim;
#endif
    if (S_ISLNK(st.st_mode)) {
        char target[PATH_MAX];
        ssize_t len = readlinkat(src_parent, src_name, target,
                                 sizeof(target) - 1);

        if (len < 0)
            return -1;
        target[len] = '\0';
        return symlinkat(target, dst_parent, dst_name);
    }
    if (S_ISREG(st.st_mode)) {
        int src_fd, dst_fd, rc;
        struct stat opened;

        src_fd = openat(src_parent, src_name,
                        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (src_fd < 0)
            return -1;
        if (fstat(src_fd, &opened) != 0 || !S_ISREG(opened.st_mode) ||
            opened.st_dev != src_dev) {
            close(src_fd);
            errno = EXDEV;
            return -1;
        }
        dst_fd = openat(dst_parent, dst_name,
                        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                        st.st_mode & 0777);
        if (dst_fd < 0) {
            close(src_fd);
            return -1;
        }
        rc = storage_files_copy_bytes(src_fd, dst_fd);
        if (rc == 0)
            rc = fsync(dst_fd);
        if (rc == 0)
            (void)futimens(dst_fd, times);
        close(src_fd);
        if (close(dst_fd) != 0)
            rc = -1;
        if (rc != 0)
            unlinkat(dst_parent, dst_name, 0);
        return rc;
    }
    if (S_ISDIR(st.st_mode)) {
        int src_fd, dst_fd, rc = 0;
        char **names = NULL;
        size_t count = 0, i;

        if (mkdirat(dst_parent, dst_name, st.st_mode & 0777) != 0 &&
            errno != EEXIST)
            return -1;
        src_fd = openat(src_parent, src_name,
                        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        dst_fd = openat(dst_parent, dst_name,
                        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (src_fd < 0 || dst_fd < 0) {
            if (src_fd >= 0)
                close(src_fd);
            if (dst_fd >= 0)
                close(dst_fd);
            return -1;
        }
        {
            struct stat sdst;

            if (fstat(src_fd, &sdst) != 0 || sdst.st_dev != src_dev) {
                close(src_fd);
                close(dst_fd);
                errno = EXDEV;
                return -1;
            }
        }
        if (storage_files_read_dir_names(src_fd, &names, &count) != 0) {
            close(src_fd);
            close(dst_fd);
            return -1;
        }
        for (i = 0; i < count; i++)
            if (storage_files_copy_recursive(src_fd, names[i], dst_fd, names[i],
                                             src_dev, depth + 1) != 0) {
                rc = -1;
                break;
            }
        for (i = 0; i < count; i++)
            free(names[i]);
        free(names);
        if (rc == 0)
            (void)futimens(dst_fd, times);
        close(src_fd);
        close(dst_fd);
        return rc;
    }
    /* fifo/socket/device nodes are not ordinary documents and are skipped. */
    errno = ENOTSUP;
    return -1;
}

/* Pick a non-colliding "name (n).ext" for on_conflict=rename.  Returns the
 * original name unchanged when it does not already exist. */
static int storage_files_unique_leaf(int dir_fd, const char *base, char *out,
                                     size_t out_len)
{
    struct stat st;
    const char *dot;
    char stem[NAME_MAX + 1], ext[NAME_MAX + 1];
    int i;

    if (fstatat(dir_fd, base, &st, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT)
        return snprintf(out, out_len, "%s", base) < (int)out_len ? 0 : -1;
    dot = strrchr(base, '.');
    if (dot && dot != base) {
        snprintf(stem, sizeof(stem), "%.*s", (int)(dot - base), base);
        snprintf(ext, sizeof(ext), "%s", dot);
    } else {
        snprintf(stem, sizeof(stem), "%s", base);
        ext[0] = '\0';
    }
    for (i = 1; i < 10000; i++) {
        if (snprintf(out, out_len, "%s (%d)%s", stem, i, ext) >= (int)out_len)
            return -1;
        if (fstatat(dir_fd, out, &st, AT_SYMLINK_NOFOLLOW) != 0 &&
            errno == ENOENT)
            return 0;
    }
    return -1;
}

static void storage_files_batch_item(struct json_object *results,
                                     const char *source, const char *target,
                                     int ok, const char *status,
                                     const char *error)
{
    struct json_object *item = json_object_new_object();

    json_object_object_add(item, "source",
                           json_object_new_string(source ? source : ""));
    if (target)
        json_object_object_add(item, "target", json_object_new_string(target));
    json_object_object_add(item, "ok", json_object_new_boolean(ok));
    if (status)
        json_object_object_add(item, "status", json_object_new_string(status));
    if (error && error[0])
        json_object_object_add(item, "error", json_object_new_string(error));
    json_object_array_add(results, item);
}

static struct json_object *storage_files_batch_response(
    const char *transaction_id, const char *action, struct json_object *results,
    int changed, int succeeded, int failed, int skipped)
{
    struct json_object *data = json_object_new_object();

    json_object_object_add(data, "contract_version",
                           json_object_new_string("storage-files.v1"));
    json_object_object_add(data, "transaction_id",
                           json_object_new_string(transaction_id));
    json_object_object_add(data, "action", json_object_new_string(action));
    json_object_object_add(data, "changed", json_object_new_boolean(changed));
    json_object_object_add(data, "persisted", json_object_new_boolean(changed));
    json_object_object_add(data, "applied", json_object_new_boolean(changed));
    json_object_object_add(data, "apply_scope",
                           json_object_new_string("filesystem_namespace"));
    json_object_object_add(data, "succeeded", json_object_new_int(succeeded));
    json_object_object_add(data, "failed", json_object_new_int(failed));
    json_object_object_add(data, "skipped", json_object_new_int(skipped));
    json_object_object_add(data, "results", results);
    return jmx_gen_api_response_data(STORAGE_FILES_API_SUCCESS, data);
}

/* Collect the target display paths for a batch op: the array key first
 * (paths[]/sources[]), then a single-string fallback.  Returns pointers into
 * the payload's json strings, valid for the life of the payload. */
static int storage_files_collect_targets(struct json_object *payload,
                                         const char *array_key,
                                         const char *single_key,
                                         const char **targets, int max)
{
    struct json_object *array = NULL;
    int count = 0;

    if (json_object_object_get_ex(payload, array_key, &array) && array &&
        json_object_is_type(array, json_type_array)) {
        int len = (int)json_object_array_length(array), i;

        for (i = 0; i < len && count < max; i++) {
            struct json_object *el = json_object_array_get_idx(array, i);

            if (el && json_object_is_type(el, json_type_string)) {
                const char *s = json_object_get_string(el);

                if (s && s[0])
                    targets[count++] = s;
            }
        }
        return count;
    }
    {
        const char *single = storage_files_json_string(payload, single_key);

        if ((!single || !single[0]) && strcmp(single_key, "path"))
            single = storage_files_json_string(payload, "path");
        if (single && single[0] && count < max)
            targets[count++] = single;
    }
    return count;
}

static struct json_object *storage_files_delete_batch(
    const struct storage_file_root *root, struct json_object *payload,
    const char *transaction_id)
{
    const char *targets[STORAGE_FILES_MAX_BATCH];
    struct json_object *results;
    int to_trash = storage_files_json_bool(payload, "to_trash");
    int count, i, changed = 0, ok = 0, failed = 0, skipped = 0;
    int trash_fd = -1;
    unsigned int trash_nonce = (unsigned int)time(NULL) ^ (unsigned int)getpid();

    if (root->read_only)
        return storage_files_mutation_error("storage_root_read_only",
            "selected storage root is read only", transaction_id, 0, 0);
    count = storage_files_collect_targets(payload, "paths", "path", targets,
                                          STORAGE_FILES_MAX_BATCH);
    if (count <= 0)
        return storage_files_mutation_error("invalid_request",
            "delete requires path or a non-empty paths[]", transaction_id, 0, 0);
    results = json_object_new_array();
    if (to_trash) {
        int root_fd = storage_files_open_directory(root, "");

        if (root_fd >= 0) {
            (void)mkdirat(root_fd, STORAGE_FILES_TRASH_DIR, 0700);
            trash_fd = openat(root_fd, STORAGE_FILES_TRASH_DIR,
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            close(root_fd);
        }
        if (trash_fd < 0) {
            json_object_put(results);
            return storage_files_mutation_error("trash_unavailable",
                "recycle bin could not be prepared", transaction_id, 0, 0);
        }
    }
    for (i = 0; i < count; i++) {
        char relative[PATH_MAX], display[PATH_MAX];
        char parent[PATH_MAX], leaf[NAME_MAX + 1];
        const char *deny_reason = "";
        int parent_fd;
        struct stat st;

        if (storage_files_relative_path(root, targets[i], relative,
                                        sizeof(relative), display,
                                        sizeof(display)) != 0 || !relative[0]) {
            storage_files_batch_item(results, targets[i], NULL, 0, "failed",
                                     "invalid_relative_path");
            failed++;
            continue;
        }
        if (storage_files_write_denied(display, &deny_reason)) {
            storage_files_batch_item(results, display, NULL, 0, "failed",
                                     deny_reason);
            failed++;
            continue;
        }
        if (storage_files_split_relative(relative, parent, sizeof(parent), leaf,
                                         sizeof(leaf)) != 0 ||
            !storage_files_safe_name(leaf)) {
            storage_files_batch_item(results, display, NULL, 0, "failed",
                                     "invalid_relative_path");
            failed++;
            continue;
        }
        parent_fd = storage_files_open_directory(root, parent);
        if (parent_fd < 0) {
            storage_files_batch_item(results, display, NULL, 0, "failed",
                                     "directory_unavailable");
            failed++;
            continue;
        }
        if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            close(parent_fd);
            storage_files_batch_item(results, display, NULL, 0, "failed",
                                     "not_found");
            failed++;
            continue;
        }
        if (st.st_dev != root->dev) {
            close(parent_fd);
            storage_files_batch_item(results, display, NULL, 0, "failed",
                                     "mount_boundary_rejected");
            failed++;
            continue;
        }
        long budget = STORAGE_FILES_SEARCH_EXAMINE_BUDGET;
        if (storage_files_tree_allowed(parent_fd, leaf, display, root->dev,
                                       1, 0, &budget) != 0) {
            close(parent_fd);
            storage_files_batch_item(results, display, NULL, 0, "failed",
                                     "protected_or_unavailable_descendant");
            failed++;
            continue;
        }
        if (to_trash) {
            char trashed[NAME_MAX + 1];
            int moved = -1, attempt;

            for (attempt = 0; attempt < 16; attempt++) {
                if (snprintf(trashed, sizeof(trashed), "%lld-%x-%s",
                             (long long)time(NULL), trash_nonce++, leaf) >=
                    (int)sizeof(trashed))
                    snprintf(trashed, sizeof(trashed), "%lld-%x",
                             (long long)time(NULL), trash_nonce++);
#ifdef __linux__
                moved = (int)syscall(SYS_renameat2, parent_fd, leaf, trash_fd,
                                     trashed, RENAME_NOREPLACE);
#else
                moved = renameat(parent_fd, leaf, trash_fd, trashed);
#endif
                if (moved == 0 || errno != EEXIST)
                    break;
            }
            if (moved == 0) {
                fsync(parent_fd);
                changed = 1;
                ok++;
                storage_files_batch_item(results, display, NULL, 1, "trashed",
                                         NULL);
            } else {
                storage_files_batch_item(results, display, NULL, 0, "failed",
                                         "filesystem_error");
                failed++;
            }
        } else if (storage_files_remove_recursive(parent_fd, leaf, root->dev,
                                                  0) == 0) {
            fsync(parent_fd);
            changed = 1;
            ok++;
            storage_files_batch_item(results, display, NULL, 1, "deleted", NULL);
        } else {
            storage_files_batch_item(results, display, NULL, 0, "failed",
                                     "filesystem_error");
            failed++;
        }
        close(parent_fd);
    }
    if (trash_fd >= 0)
        close(trash_fd);
    return storage_files_batch_response(transaction_id, "delete", results,
                                        changed, ok, failed, skipped);
}

static struct json_object *storage_files_transfer_batch(
    const struct storage_file_root *roots, int root_count,
    const struct storage_file_root *src_root, struct json_object *payload,
    const char *transaction_id, int is_copy)
{
    const char *action = is_copy ? "copy" : "move";
    const char *target = storage_files_json_string(payload, "target");
    const char *target_root_id = storage_files_json_string(payload,
                                                           "target_root_id");
    const char *on_conflict = storage_files_json_string(payload, "on_conflict");
    const struct storage_file_root *dst_root;
    const char *sources[STORAGE_FILES_MAX_BATCH];
    struct json_object *results;
    char dst_rel[PATH_MAX], dst_disp[PATH_MAX];
    const char *deny_reason = "";
    int dst_dir_fd, count, i, changed = 0, ok = 0, failed = 0, skipped = 0;

    if (!target[0])
        target = storage_files_json_string(payload, "target_path");
    if (!target[0])
        return storage_files_mutation_error("invalid_request",
            "target directory is required", transaction_id, 0, 0);
    if (!is_copy && src_root->read_only)
        return storage_files_mutation_error("storage_root_read_only",
            "source storage root is read only", transaction_id, 0, 0);
    dst_root = storage_files_select_root(roots, root_count,
                                         target_root_id[0] ? target_root_id :
                                         NULL, target);
    if (!dst_root)
        return storage_files_mutation_error("target_root_not_found",
            "target storage root is not available", transaction_id, 0, 0);
    if (dst_root->read_only)
        return storage_files_mutation_error("storage_root_read_only",
            "target storage root is read only", transaction_id, 0, 0);
    if (storage_files_relative_path(dst_root, target, dst_rel, sizeof(dst_rel),
                                    dst_disp, sizeof(dst_disp)) != 0)
        return storage_files_mutation_error("invalid_target_path",
            "target must remain inside the selected storage root",
            transaction_id, 0, 0);
    if (storage_files_write_denied(dst_disp, &deny_reason))
        return storage_files_mutation_error("write_protected", deny_reason,
                                            transaction_id, 0, 0);
    dst_dir_fd = storage_files_open_directory(dst_root, dst_rel);
    if (dst_dir_fd < 0)
        return storage_files_mutation_error("target_directory_unavailable",
            "target directory cannot be opened safely", transaction_id, 0, 0);
    count = storage_files_collect_targets(payload, "sources", "source", sources,
                                          STORAGE_FILES_MAX_BATCH);
    if (count <= 0) {
        close(dst_dir_fd);
        return storage_files_mutation_error("invalid_request",
            "move/copy requires source or a non-empty sources[]",
            transaction_id, 0, 0);
    }
    results = json_object_new_array();
    for (i = 0; i < count; i++) {
        char src_rel[PATH_MAX], src_disp[PATH_MAX];
        char src_parent[PATH_MAX], src_leaf[NAME_MAX + 1];
        char dst_leaf[NAME_MAX + 1], child_disp[PATH_MAX];
        const char *item_deny = "";
        int src_parent_fd;
        struct stat st;
        int same_dev = src_root->dev == dst_root->dev;

        if (storage_files_relative_path(src_root, sources[i], src_rel,
                                        sizeof(src_rel), src_disp,
                                        sizeof(src_disp)) != 0 ||
            !src_rel[0]) {
            storage_files_batch_item(results, sources[i], NULL, 0, "failed",
                                     "invalid_relative_path");
            failed++;
            continue;
        }
        if (!is_copy && storage_files_write_denied(src_disp, &item_deny)) {
            storage_files_batch_item(results, src_disp, NULL, 0, "failed",
                                     item_deny);
            failed++;
            continue;
        }
        if (storage_files_split_relative(src_rel, src_parent, sizeof(src_parent),
                                         src_leaf, sizeof(src_leaf)) != 0 ||
            !storage_files_safe_name(src_leaf)) {
            storage_files_batch_item(results, src_disp, NULL, 0, "failed",
                                     "invalid_relative_path");
            failed++;
            continue;
        }
        snprintf(dst_leaf, sizeof(dst_leaf), "%s", src_leaf);
        if (storage_files_join_path(child_disp, sizeof(child_disp), dst_disp,
                                    dst_leaf) != 0) {
            storage_files_batch_item(results, src_disp, NULL, 0, "failed",
                                     "invalid_target_path");
            failed++;
            continue;
        }
        /* Refuse copying/moving a directory into itself or its own subtree, and
         * refuse a no-op onto the same path -- both would loop or corrupt. */
        if (!strcmp(child_disp, src_disp) ||
            storage_files_path_prefix(dst_disp, src_disp)) {
            storage_files_batch_item(results, src_disp, child_disp, 0, "failed",
                                     "target_within_source");
            failed++;
            continue;
        }
        if (storage_files_write_denied(child_disp, &item_deny)) {
            storage_files_batch_item(results, src_disp, child_disp, 0, "failed",
                                     item_deny);
            failed++;
            continue;
        }
        src_parent_fd = storage_files_open_directory(src_root, src_parent);
        if (src_parent_fd < 0) {
            storage_files_batch_item(results, src_disp, child_disp, 0, "failed",
                                     "directory_unavailable");
            failed++;
            continue;
        }
        if (fstatat(src_parent_fd, src_leaf, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
            st.st_dev != src_root->dev) {
            close(src_parent_fd);
            storage_files_batch_item(results, src_disp, child_disp, 0, "failed",
                                     "not_found");
            failed++;
            continue;
        }
        long budget = STORAGE_FILES_SEARCH_EXAMINE_BUDGET;
        if (storage_files_tree_allowed(src_parent_fd, src_leaf, src_disp,
                                       src_root->dev, !is_copy, 0, &budget) != 0) {
            close(src_parent_fd);
            storage_files_batch_item(results, src_disp, child_disp, 0, "failed",
                                     "protected_or_unavailable_descendant");
            failed++;
            continue;
        }
        /* Resolve a name collision in the target directory. */
        {
            struct stat existing;

            if (fstatat(dst_dir_fd, dst_leaf, &existing,
                        AT_SYMLINK_NOFOLLOW) == 0) {
                if (!strcmp(on_conflict, "skip")) {
                    close(src_parent_fd);
                    storage_files_batch_item(results, src_disp, child_disp, 1,
                                             "skipped", NULL);
                    skipped++;
                    continue;
                }
                if (!strcmp(on_conflict, "overwrite")) {
                    budget = STORAGE_FILES_SEARCH_EXAMINE_BUDGET;
                    if (storage_files_tree_allowed(dst_dir_fd, dst_leaf, child_disp,
                                                   dst_root->dev, 1, 0, &budget) != 0 ||
                        storage_files_remove_recursive(dst_dir_fd, dst_leaf,
                                                       dst_root->dev, 0) != 0) {
                        close(src_parent_fd);
                        storage_files_batch_item(results, src_disp, child_disp,
                                                 0, "failed",
                                                 "target_replace_failed");
                        failed++;
                        continue;
                    }
                } else if (!strcmp(on_conflict, "rename")) {
                    if (storage_files_unique_leaf(dst_dir_fd, src_leaf, dst_leaf,
                                                  sizeof(dst_leaf)) != 0 ||
                        storage_files_join_path(child_disp, sizeof(child_disp),
                                                dst_disp, dst_leaf) != 0) {
                        close(src_parent_fd);
                        storage_files_batch_item(results, src_disp, NULL, 0,
                                                 "failed", "rename_failed");
                        failed++;
                        continue;
                    }
                } else {
                    close(src_parent_fd);
                    storage_files_batch_item(results, src_disp, child_disp, 0,
                                             "failed", "target_exists");
                    failed++;
                    continue;
                }
            }
        }
        if (!is_copy && same_dev) {
#ifdef __linux__
            int moved = (int)syscall(SYS_renameat2, src_parent_fd, src_leaf,
                                     dst_dir_fd, dst_leaf, 0);
#else
            int moved = renameat(src_parent_fd, src_leaf, dst_dir_fd, dst_leaf);
#endif
            if (moved == 0) {
                fsync(src_parent_fd);
                fsync(dst_dir_fd);
                changed = 1;
                ok++;
                storage_files_batch_item(results, src_disp, child_disp, 1,
                                         "moved", NULL);
            } else {
                storage_files_batch_item(results, src_disp, child_disp, 0,
                                         "failed", "filesystem_error");
                failed++;
            }
            close(src_parent_fd);
            continue;
        }
        /* Cross-root move degrades to copy + delete; copy is always this path. */
        if (storage_files_copy_recursive(src_parent_fd, src_leaf, dst_dir_fd,
                                         dst_leaf, src_root->dev, 0) != 0) {
            storage_files_remove_recursive(dst_dir_fd, dst_leaf, dst_root->dev,
                                           0);
            close(src_parent_fd);
            storage_files_batch_item(results, src_disp, child_disp, 0, "failed",
                                     "copy_failed");
            failed++;
            continue;
        }
        fsync(dst_dir_fd);
        changed = 1;
        if (!is_copy) {
            if (storage_files_remove_recursive(src_parent_fd, src_leaf,
                                               src_root->dev, 0) == 0) {
                fsync(src_parent_fd);
                ok++;
                storage_files_batch_item(results, src_disp, child_disp, 1,
                                         "moved", NULL);
            } else {
                /* Copy landed but the source could not be removed: report it as
                 * a partial move so the caller knows a duplicate now exists. */
                storage_files_batch_item(results, src_disp, child_disp, 0,
                                         "partial", "source_delete_failed");
                failed++;
            }
        } else {
            ok++;
            storage_files_batch_item(results, src_disp, child_disp, 1, "copied",
                                     NULL);
        }
        close(src_parent_fd);
    }
    close(dst_dir_fd);
    return storage_files_batch_response(transaction_id, action, results,
                                        changed, ok, failed, skipped);
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
        strcmp(action, "write") && strcmp(action, "rename") &&
        strcmp(action, "delete") && strcmp(action, "move") &&
        strcmp(action, "copy"))
        return storage_files_mutation_error("unsupported_action",
            "only mkdir, create, write, rename, delete, move and copy are supported",
            transaction_id, 0, 0);
    root_count = storage_files_discover_roots(roots, STORAGE_FILES_MAX_ROOTS);
    if (root_count < 0)
        return storage_files_mutation_error("mount_inventory_unavailable",
            "mount inventory is unavailable", transaction_id, 0, 0);
    root = storage_files_select_root(roots, root_count, root_id, path);
    if (!root)
        return storage_files_mutation_error("storage_root_not_found",
            "storage root is not available", transaction_id, 0, 0);
    /* delete/move/copy have a multi-target model of their own (paths[]/sources[]
     * + target) and their own read-only rules -- copy may read FROM a read-only
     * system root and write only to a writable target -- so they dispatch here,
     * before the single-path read-only/relative-path/deny-list block below that
     * exists for mkdir/create/write/rename. */
    if (!strcmp(action, "delete"))
        return storage_files_delete_batch(root, payload, transaction_id);
    if (!strcmp(action, "move") || !strcmp(action, "copy"))
        return storage_files_transfer_batch(roots, root_count, root, payload,
                                            transaction_id,
                                            !strcmp(action, "copy"));
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
        (!S_ISREG(before.st_mode) &&
         !(S_ISDIR(before.st_mode) && !strcmp(action, "rename"))) ||
        before.st_dev != root->dev)
        goto mutation_failed;
    if (!strcmp(action, "rename")) {
        char parent_display[PATH_MAX];

        if (!storage_files_safe_name(new_name))
            goto invalid_name;
        long budget = STORAGE_FILES_SEARCH_EXAMINE_BUDGET;
        if (storage_files_tree_allowed(parent_fd, leaf, display, root->dev,
                                       1, 0, &budget) != 0) {
            close(parent_fd);
            return storage_files_mutation_error("protected_or_unavailable_descendant",
                "directory contains protected or unavailable entries", transaction_id, 0, 0);
        }
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

/* ── Upload to a storage path (binary, in-process from webd) ───────────────
 *
 * These write arbitrary bytes into the browsable tree, so they reuse the exact
 * same sandbox as the mutate actions -- writable-root selection, relative-path
 * validation, the write deny-list, safe_name(), a transactional temp file in
 * the destination directory committed with renameat2() + fsync().  They are
 * NOT UTF-8/256 KiB limited (that limit is specific to the text editor path).
 *
 * storage_files.o is linked into webd as well as core, so the webd upload
 * handlers call these directly, exactly as the raw-stream route calls
 * storage_files_open_stream() -- no ubus round-trip, so a multi-megabyte body
 * never has to fit in a ubus message.
 */

static struct json_object *storage_files_upload_ok(struct json_object *data)
{
    json_object_object_add(data, "contract_version",
                           json_object_new_string("storage-files.v1"));
    return jmx_gen_api_response_data(STORAGE_FILES_API_SUCCESS, data);
}

/* Client-supplied upload ids become a directory component, so they are held to
 * a strict charset with no path separators or dot-only names. */
static int storage_files_safe_upload_id(const char *id)
{
    size_t i, n;

    if (!id || !id[0] || !strcmp(id, ".") || !strcmp(id, ".."))
        return 0;
    n = strlen(id);
    if (n > 64)
        return 0;
    for (i = 0; i < n; i++) {
        char c = id[i];

        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
            return 0;
    }
    return 1;
}

/* Atomically move an already-written temp into its final name in dir_fd.
 * overwrite=0 refuses an existing target (RENAME_NOREPLACE); overwrite=1
 * replaces it.  On success *after holds the committed file's stat. */
static int storage_files_commit_temp(int dir_fd, const char *temp,
                                     const char *filename, int overwrite,
                                     dev_t dev, struct stat *after)
{
#ifdef __linux__
    unsigned int flags = overwrite ? 0u : (unsigned int)RENAME_NOREPLACE;

    if (syscall(SYS_renameat2, dir_fd, temp, dir_fd, filename, flags) != 0)
        return -1;
#else
    if (!overwrite) {
        struct stat existing;

        if (fstatat(dir_fd, filename, &existing, AT_SYMLINK_NOFOLLOW) == 0) {
            errno = EEXIST;
            return -1;
        }
    }
    if (renameat(dir_fd, temp, dir_fd, filename) != 0)
        return -1;
#endif
    if (fsync(dir_fd) != 0 ||
        fstatat(dir_fd, filename, after, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(after->st_mode) || after->st_dev != dev)
        return -1;
    return 0;
}

/* Open (optionally creating) the per-upload staging directory
 * <root>/.dwrt-upload/<id>, returning a dir fd that stays on the root device. */
static int storage_files_open_staging(const struct storage_file_root *root,
                                      const char *id, int create, int *fd_out)
{
    int root_fd, up_fd, id_fd;
    struct stat st;

    *fd_out = -1;
    root_fd = storage_files_open_directory(root, "");
    if (root_fd < 0)
        return -1;
    if (create)
        (void)mkdirat(root_fd, STORAGE_FILES_UPLOAD_DIR, 0700);
    up_fd = openat(root_fd, STORAGE_FILES_UPLOAD_DIR,
                   O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    close(root_fd);
    if (up_fd < 0)
        return -1;
    if (create)
        (void)mkdirat(up_fd, id, 0700);
    id_fd = openat(up_fd, id, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    close(up_fd);
    if (id_fd < 0)
        return -1;
    if (fstat(id_fd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_dev != root->dev) {
        close(id_fd);
        return -1;
    }
    *fd_out = id_fd;
    return 0;
}

static int storage_files_remove_staging(const struct storage_file_root *root,
                                         const char *id)
{
    int root_fd, up_fd, rc;

    root_fd = storage_files_open_directory(root, "");
    if (root_fd < 0)
        return -1;
    up_fd = openat(root_fd, STORAGE_FILES_UPLOAD_DIR,
                   O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    close(root_fd);
    if (up_fd < 0)
        return -1;
    rc = storage_files_remove_recursive(up_fd, id, root->dev, 0);
    close(up_fd);
    return rc;
}

static int storage_files_write_meta(int staging_fd, struct json_object *meta)
{
    const char *text = json_object_to_json_string_ext(meta,
                                                       JSON_C_TO_STRING_PLAIN);
    int fd, rc;

    fd = openat(staging_fd, STORAGE_FILES_UPLOAD_META,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
        return -1;
    rc = storage_files_write_all(fd, (const unsigned char *)text,
                                 strlen(text));
    if (rc == 0)
        rc = fsync(fd);
    if (close(fd) != 0)
        rc = -1;
    return rc;
}

static struct json_object *storage_files_read_meta(int staging_fd)
{
    char buf[8192];
    ssize_t n;
    int fd;
    struct json_object *meta;

    fd = openat(staging_fd, STORAGE_FILES_UPLOAD_META,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return NULL;
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return NULL;
    buf[n] = '\0';
    meta = json_tokener_parse(buf);
    if (meta && json_object_is_type(meta, json_type_object))
        return meta;
    if (meta)
        json_object_put(meta);
    return NULL;
}

static int storage_files_meta_int(struct json_object *meta, const char *key,
                                  int def)
{
    struct json_object *v = NULL;

    if (meta && json_object_object_get_ex(meta, key, &v) && v &&
        json_object_is_type(v, json_type_int))
        return json_object_get_int(v);
    return def;
}

static int64_t storage_files_meta_size(struct json_object *meta)
{
    struct json_object *value = NULL;
    if (!meta || !json_object_object_get_ex(meta, "total_size", &value) ||
        !json_object_is_type(value, json_type_int))
        return -1;
    return json_object_get_int64(value);
}

static const char *storage_files_meta_str(struct json_object *meta,
                                          const char *key)
{
    struct json_object *v = NULL;

    if (meta && json_object_object_get_ex(meta, key, &v) && v &&
        json_object_is_type(v, json_type_string))
        return json_object_get_string(v);
    return "";
}

/* Shared front half: discover roots, pick a WRITABLE one, validate the
 * destination directory + filename against the deny-list, and open the dir.
 * On success returns 0 with *root/dir_fd/display set; on failure returns a
 * json error envelope via *err. */
static int storage_files_upload_prepare(const char *root_id,
                                        const char *dir_path,
                                        const char *filename,
                                        struct storage_file_root *roots,
                                        const struct storage_file_root **root_out,
                                        int *dir_fd_out, char *result_path,
                                        size_t result_len,
                                        struct json_object **err)
{
    const struct storage_file_root *root;
    char relative[PATH_MAX], display[PATH_MAX], candidate[PATH_MAX];
    const char *deny = "";
    int root_count, dir_fd;

    *err = NULL;
    *root_out = NULL;
    *dir_fd_out = -1;
    if (!filename || !storage_files_safe_name(filename)) {
        *err = storage_files_error("invalid_name",
                                   "filename must be one safe path component");
        return -1;
    }
    root_count = storage_files_discover_roots(roots, STORAGE_FILES_MAX_ROOTS);
    if (root_count < 0) {
        *err = storage_files_error("mount_inventory_unavailable",
                                   "mount inventory is unavailable");
        return -1;
    }
    root = storage_files_select_root(roots, root_count, root_id, dir_path);
    if (!root) {
        *err = storage_files_error("storage_root_not_found",
                                   "storage root is not available");
        return -1;
    }
    if (root->read_only) {
        *err = storage_files_error("storage_root_read_only",
                                   "selected storage root is read only");
        return -1;
    }
    if (storage_files_relative_path(root, dir_path, relative, sizeof(relative),
                                    display, sizeof(display)) != 0) {
        *err = storage_files_error("invalid_relative_path",
                                   "path must remain inside the selected storage root");
        return -1;
    }
    if (storage_files_write_denied(display, &deny) ||
        (storage_files_join_path(candidate, sizeof(candidate), display,
                                 filename) == 0 &&
         storage_files_write_denied(candidate, &deny))) {
        *err = storage_files_error("write_protected", deny);
        return -1;
    }
    if (storage_files_join_path(result_path, result_len, display,
                                filename) != 0) {
        *err = storage_files_error("invalid_relative_path",
                                   "destination path is too long");
        return -1;
    }
    dir_fd = storage_files_open_directory(root, relative);
    if (dir_fd < 0) {
        *err = storage_files_error("directory_unavailable",
                                   "destination directory cannot be opened safely");
        return -1;
    }
    *root_out = root;
    *dir_fd_out = dir_fd;
    return 0;
}

struct json_object *jmx_storage_files_store_bytes(const char *root_id,
                                                  const char *dir_path,
                                                  const char *filename,
                                                  const unsigned char *data,
                                                  size_t len, int overwrite)
{
    struct storage_file_root roots[STORAGE_FILES_MAX_ROOTS];
    const struct storage_file_root *root;
    struct json_object *err = NULL, *result;
    char result_path[PATH_MAX], temporary[NAME_MAX + 1];
    struct stat after;
    unsigned int nonce = (unsigned int)time(NULL) ^ (unsigned int)getpid();
    int dir_fd, temp_fd;

    if (storage_files_upload_prepare(root_id, dir_path, filename, roots, &root,
                                     &dir_fd, result_path, sizeof(result_path),
                                     &err) != 0)
        return err;
    snprintf(temporary, sizeof(temporary), "%s%u",
             STORAGE_FILES_TRANSACTION_PREFIX, nonce);
    temp_fd = openat(dir_fd, temporary,
                     O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (temp_fd < 0) {
        close(dir_fd);
        return storage_files_error("filesystem_transaction_failed",
                                   "upload temp file could not be created");
    }
    if ((len && storage_files_write_all(temp_fd, data, len) != 0) ||
        fsync(temp_fd) != 0 || close(temp_fd) != 0) {
        unlinkat(dir_fd, temporary, 0);
        close(dir_fd);
        return storage_files_error("filesystem_transaction_failed",
                                   "upload could not be written");
    }
    if (storage_files_commit_temp(dir_fd, temporary, filename, overwrite,
                                  root->dev, &after) != 0) {
        int existed = (errno == EEXIST);

        unlinkat(dir_fd, temporary, 0);
        close(dir_fd);
        return storage_files_error(existed ? "file_exists" :
                                   "filesystem_transaction_failed",
                                   existed ? "destination already exists" :
                                   "upload could not be committed");
    }
    close(dir_fd);
    result = json_object_new_object();
    json_object_object_add(result, "stored", json_object_new_boolean(1));
    json_object_object_add(result, "path", json_object_new_string(result_path));
    json_object_object_add(result, "size_bytes",
                           json_object_new_int64((int64_t)after.st_size));
    json_object_object_add(result, "overwrite",
                           json_object_new_boolean(overwrite ? 1 : 0));
    return storage_files_upload_ok(result);
}

struct json_object *jmx_storage_files_upload_init(const char *root_id,
                                                  const char *dir_path,
                                                  const char *filename,
                                                  const char *client_upload_id,
                                                  int64_t total_size,
                                                  int total_chunks,
                                                  int overwrite)
{
    struct storage_file_root roots[STORAGE_FILES_MAX_ROOTS];
    const struct storage_file_root *root;
    struct json_object *err = NULL, *result, *uploaded, *meta;
    char result_path[PATH_MAX], relative[PATH_MAX], display[PATH_MAX];
    char upload_id[80];
    int dir_fd, staging_fd, resumed = 0;
    unsigned int nonce = (unsigned int)time(NULL) ^ (unsigned int)getpid();

    if (total_size < 0 || total_chunks <= 0 || total_chunks > STORAGE_FILES_MAX_UPLOAD_CHUNKS)
        return storage_files_error("invalid_request",
                                   "total_chunks is out of range");
    if (storage_files_upload_prepare(root_id, dir_path, filename, roots, &root,
                                     &dir_fd, result_path, sizeof(result_path),
                                     &err) != 0)
        return err;
    /* dir_fd is only used to prove the destination is writable now; the chunk
     * store lives in staging and the merge re-opens the destination. */
    close(dir_fd);
    /* Recompute the relative destination to persist in the session meta. */
    if (storage_files_relative_path(root, dir_path, relative, sizeof(relative),
                                    display, sizeof(display)) != 0)
        return storage_files_error("invalid_relative_path",
                                   "path must remain inside the selected storage root");
    if (client_upload_id && client_upload_id[0]) {
        if (!storage_files_safe_upload_id(client_upload_id))
            return storage_files_error("invalid_upload_id",
                                       "upload_id has an unsafe form");
        snprintf(upload_id, sizeof(upload_id), "%s", client_upload_id);
        if (storage_files_open_staging(root, upload_id, 0, &staging_fd) == 0) {
            resumed = 1;
            close(staging_fd);
        }
    } else {
        snprintf(upload_id, sizeof(upload_id), "up-%llx-%x",
                 (unsigned long long)time(NULL), nonce);
    }
    if (storage_files_open_staging(root, upload_id, 1, &staging_fd) != 0)
        return storage_files_error("upload_staging_failed",
                                   "upload session could not be prepared");
    if (resumed) {
        meta = storage_files_read_meta(staging_fd);
        int matches = meta &&
            !strcmp(storage_files_meta_str(meta, "dir"), display) &&
            !strcmp(storage_files_meta_str(meta, "filename"), filename) &&
            storage_files_meta_int(meta, "total_chunks", 0) == total_chunks &&
            storage_files_meta_size(meta) == total_size &&
            storage_files_meta_int(meta, "overwrite", 0) == !!overwrite;
        if (meta) json_object_put(meta);
        if (!matches) {
            close(staging_fd);
            return storage_files_error("upload_metadata_conflict",
                "upload_id belongs to different destination or file metadata");
        }
    } else {
        meta = json_object_new_object();
        /* Store the ABSOLUTE destination directory: complete() re-validates it
         * through storage_files_relative_path(), which requires a path prefixed
         * by root->path, not a bare relative component. */
        json_object_object_add(meta, "dir", json_object_new_string(display));
        json_object_object_add(meta, "filename",
                               json_object_new_string(filename));
        json_object_object_add(meta, "total_chunks",
                               json_object_new_int(total_chunks));
        json_object_object_add(meta, "total_size",
                               json_object_new_int64(total_size));
        json_object_object_add(meta, "overwrite",
                               json_object_new_int(overwrite ? 1 : 0));
        if (storage_files_write_meta(staging_fd, meta) != 0) {
            json_object_put(meta);
            close(staging_fd);
            storage_files_remove_staging(root, upload_id);
            return storage_files_error("upload_staging_failed",
                                       "upload session metadata could not be written");
        }
        json_object_put(meta);
    }
    /* Report which chunk indices are already staged, for resume. */
    uploaded = json_object_new_array();
    {
        char **names = NULL;
        size_t count = 0, i;

        if (storage_files_read_dir_names(staging_fd, &names, &count) == 0) {
            for (i = 0; i < count; i++) {
                int idx;

                if (sscanf(names[i], "chunk.%d", &idx) == 1 && idx >= 0 &&
                    idx < total_chunks)
                    json_object_array_add(uploaded,
                                          json_object_new_int(idx));
            }
            for (i = 0; i < count; i++)
                free(names[i]);
            free(names);
        }
    }
    close(staging_fd);
    result = json_object_new_object();
    json_object_object_add(result, "upload_id",
                           json_object_new_string(upload_id));
    json_object_object_add(result, "total_chunks",
                           json_object_new_int(total_chunks));
    json_object_object_add(result, "uploaded_chunks", uploaded);
    json_object_object_add(result, "resumed", json_object_new_boolean(resumed));
    json_object_object_add(result, "dest_path",
                           json_object_new_string(result_path));
    return storage_files_upload_ok(result);
}

struct json_object *jmx_storage_files_upload_chunk(const char *root_id,
                                                   const char *upload_id,
                                                   int chunk_index,
                                                   const unsigned char *data,
                                                   size_t len)
{
    struct storage_file_root roots[STORAGE_FILES_MAX_ROOTS];
    const struct storage_file_root *root;
    struct json_object *result;
    char chunk_name[32], temporary[NAME_MAX + 1];
    int root_count, staging_fd, temp_fd, committed;
    unsigned int nonce = (unsigned int)time(NULL) ^ (unsigned int)getpid();

    if (!storage_files_safe_upload_id(upload_id))
        return storage_files_error("invalid_upload_id",
                                   "upload_id has an unsafe form");
    if (chunk_index < 0 || chunk_index >= STORAGE_FILES_MAX_UPLOAD_CHUNKS)
        return storage_files_error("invalid_request",
                                   "chunk_index is out of range");
    root_count = storage_files_discover_roots(roots, STORAGE_FILES_MAX_ROOTS);
    if (root_count < 0)
        return storage_files_error("mount_inventory_unavailable",
                                   "mount inventory is unavailable");
    root = storage_files_select_root(roots, root_count,
                                     (root_id && root_id[0]) ? root_id : NULL, "/");
    if (!root)
        return storage_files_error("storage_root_not_found",
                                   "storage root is not available");
    if (storage_files_open_staging(root, upload_id, 0, &staging_fd) != 0)
        return storage_files_error("upload_not_found",
                                   "upload session is unknown or expired");
    {
        struct json_object *meta = storage_files_read_meta(staging_fd);
        int count = storage_files_meta_int(meta, "total_chunks", 0);
        int64_t size = storage_files_meta_size(meta);
        if (meta) json_object_put(meta);
        if (chunk_index >= count || size < 0 || (uint64_t)len > (uint64_t)size) {
            close(staging_fd);
            return storage_files_error("invalid_chunk", "chunk exceeds upload metadata");
        }
    }
    snprintf(temporary, sizeof(temporary), "%s%u-%d",
             STORAGE_FILES_TRANSACTION_PREFIX, nonce, chunk_index);
    snprintf(chunk_name, sizeof(chunk_name), "chunk.%08d", chunk_index);
    temp_fd = openat(staging_fd, temporary,
                     O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (temp_fd < 0) {
        close(staging_fd);
        return storage_files_error("filesystem_transaction_failed",
                                   "chunk temp file could not be created");
    }
    if ((len && storage_files_write_all(temp_fd, data, len) != 0) ||
        fsync(temp_fd) != 0 || close(temp_fd) != 0) {
        unlinkat(staging_fd, temporary, 0);
        close(staging_fd);
        return storage_files_error("filesystem_transaction_failed",
                                   "chunk could not be written");
    }
    /* Idempotent by index: a retried chunk atomically replaces the prior one. */
    committed = renameat(staging_fd, temporary, staging_fd, chunk_name) == 0;
    if (!committed)
        unlinkat(staging_fd, temporary, 0);
    if (committed)
        fsync(staging_fd);
    close(staging_fd);
    if (!committed)
        return storage_files_error("filesystem_transaction_failed",
                                   "chunk could not be committed");
    result = json_object_new_object();
    json_object_object_add(result, "upload_id",
                           json_object_new_string(upload_id));
    json_object_object_add(result, "chunk_index",
                           json_object_new_int(chunk_index));
    json_object_object_add(result, "received", json_object_new_boolean(1));
    json_object_object_add(result, "bytes",
                           json_object_new_int64((int64_t)len));
    return storage_files_upload_ok(result);
}

struct json_object *jmx_storage_files_upload_complete(const char *root_id,
                                                      const char *upload_id)
{
    struct storage_file_root roots[STORAGE_FILES_MAX_ROOTS];
    const struct storage_file_root *root;
    struct json_object *meta, *result;
    char relative[PATH_MAX], display[PATH_MAX], candidate[PATH_MAX];
    char temporary[NAME_MAX + 1], chunk_name[32];
    char filename[NAME_MAX + 1];
    const char *dir_rel, *deny = "";
    int64_t total_size, staged_size = 0;
    int cleanup_pending;
    struct stat after;
    int root_count, staging_fd, dir_fd, temp_fd, total_chunks, overwrite, i;
    unsigned int nonce = (unsigned int)time(NULL) ^ (unsigned int)getpid();

    if (!storage_files_safe_upload_id(upload_id))
        return storage_files_error("invalid_upload_id",
                                   "upload_id has an unsafe form");
    root_count = storage_files_discover_roots(roots, STORAGE_FILES_MAX_ROOTS);
    if (root_count < 0)
        return storage_files_error("mount_inventory_unavailable",
                                   "mount inventory is unavailable");
    root = storage_files_select_root(roots, root_count,
                                     (root_id && root_id[0]) ? root_id : NULL, "/");
    if (!root)
        return storage_files_error("storage_root_not_found",
                                   "storage root is not available");
    if (root->read_only)
        return storage_files_error("storage_root_read_only",
                                   "selected storage root is read only");
    if (storage_files_open_staging(root, upload_id, 0, &staging_fd) != 0)
        return storage_files_error("upload_not_found",
                                   "upload session is unknown or expired");
    meta = storage_files_read_meta(staging_fd);
    if (!meta) {
        close(staging_fd);
        return storage_files_error("upload_metadata_missing",
                                   "upload session metadata is unavailable");
    }
    dir_rel = storage_files_meta_str(meta, "dir");
    if (strlen(storage_files_meta_str(meta, "filename")) > NAME_MAX) {
        json_object_put(meta);
        close(staging_fd);
        return storage_files_error("upload_metadata_missing", "filename is invalid");
    }
    snprintf(filename, sizeof(filename), "%s", storage_files_meta_str(meta, "filename"));
    total_size = storage_files_meta_size(meta);
    total_chunks = storage_files_meta_int(meta, "total_chunks", 0);
    overwrite = storage_files_meta_int(meta, "overwrite", 0);
    if (!filename[0] || total_size < 0 || total_chunks <= 0 ||
        total_chunks > STORAGE_FILES_MAX_UPLOAD_CHUNKS ||
        !storage_files_safe_name(filename)) {
        json_object_put(meta);
        close(staging_fd);
        return storage_files_error("upload_metadata_missing",
                                   "upload session metadata is invalid");
    }
    /* Re-validate the destination now (it may have changed since init). */
    if (storage_files_relative_path(root, dir_rel[0] ? dir_rel : "", relative,
                                    sizeof(relative), display,
                                    sizeof(display)) != 0) {
        json_object_put(meta);
        close(staging_fd);
        return storage_files_error("invalid_relative_path",
                                   "destination path is no longer valid");
    }
    if (storage_files_write_denied(display, &deny) ||
        (storage_files_join_path(candidate, sizeof(candidate), display,
                                 filename) == 0 &&
         storage_files_write_denied(candidate, &deny))) {
        json_object_put(meta);
        close(staging_fd);
        return storage_files_error("write_protected", deny);
    }
    dir_fd = storage_files_open_directory(root, relative);
    if (dir_fd < 0) {
        json_object_put(meta);
        close(staging_fd);
        return storage_files_error("directory_unavailable",
                                   "destination directory cannot be opened safely");
    }
    /* Every chunk must be present before merging. */
    for (i = 0; i < total_chunks; i++) {
        struct stat cst;

        snprintf(chunk_name, sizeof(chunk_name), "chunk.%08d", i);
        if (fstatat(staging_fd, chunk_name, &cst, AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISREG(cst.st_mode) || cst.st_dev != root->dev) {
            close(dir_fd);
            json_object_put(meta);
            close(staging_fd);
            return storage_files_error("upload_incomplete",
                                       "not all chunks have been uploaded");
        }
        if (cst.st_size < 0 || cst.st_size > total_size - staged_size) {
            close(dir_fd);
            json_object_put(meta);
            close(staging_fd);
            return storage_files_error("upload_size_mismatch", "staged bytes exceed total_size");
        }
        staged_size += cst.st_size;
    }
    json_object_put(meta);
    if (staged_size != total_size) {
        close(dir_fd);
        close(staging_fd);
        return storage_files_error("upload_size_mismatch", "staged bytes differ from total_size");
    }
    snprintf(temporary, sizeof(temporary), "%s%u",
             STORAGE_FILES_TRANSACTION_PREFIX, nonce);
    temp_fd = openat(dir_fd, temporary,
                     O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (temp_fd < 0) {
        close(dir_fd);
        close(staging_fd);
        return storage_files_error("filesystem_transaction_failed",
                                   "merge temp file could not be created");
    }
    for (i = 0; i < total_chunks; i++) {
        int chunk_fd;

        snprintf(chunk_name, sizeof(chunk_name), "chunk.%08d", i);
        chunk_fd = openat(staging_fd, chunk_name,
                          O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (chunk_fd < 0 ||
            storage_files_copy_bytes(chunk_fd, temp_fd) != 0) {
            if (chunk_fd >= 0)
                close(chunk_fd);
            unlinkat(dir_fd, temporary, 0);
            close(temp_fd);
            close(dir_fd);
            close(staging_fd);
            return storage_files_error("filesystem_transaction_failed",
                                       "chunks could not be merged");
        }
        close(chunk_fd);
    }
    struct stat merged;
    int merge_ok = fstat(temp_fd, &merged) == 0 && merged.st_size == total_size &&
                   fsync(temp_fd) == 0;
    if (close(temp_fd) != 0) merge_ok = 0;
    if (!merge_ok) {
        unlinkat(dir_fd, temporary, 0);
        close(dir_fd);
        close(staging_fd);
        return storage_files_error("filesystem_transaction_failed",
                                   "merged upload could not be flushed");
    }
    if (storage_files_commit_temp(dir_fd, temporary, filename, overwrite,
                                  root->dev, &after) != 0) {
        int existed = (errno == EEXIST);

        unlinkat(dir_fd, temporary, 0);
        close(dir_fd);
        close(staging_fd);
        return storage_files_error(existed ? "file_exists" :
                                   "filesystem_transaction_failed",
                                   existed ? "destination already exists" :
                                   "merged upload could not be committed");
    }
    close(dir_fd);
    close(staging_fd);
    cleanup_pending = storage_files_remove_staging(root, upload_id) != 0;
    result = json_object_new_object();
    json_object_object_add(result, "cleanup_pending", json_object_new_boolean(cleanup_pending));
    json_object_object_add(result, "stored", json_object_new_boolean(1));
    {
        char result_path[PATH_MAX];

        if (storage_files_join_path(result_path, sizeof(result_path), display,
                                    filename) == 0)
            json_object_object_add(result, "path",
                                   json_object_new_string(result_path));
    }
    json_object_object_add(result, "size_bytes",
                           json_object_new_int64((int64_t)after.st_size));
    json_object_object_add(result, "upload_id",
                           json_object_new_string(upload_id));
    return storage_files_upload_ok(result);
}

struct json_object *jmx_storage_files_upload_cancel(const char *root_id,
                                                    const char *upload_id)
{
    struct storage_file_root roots[STORAGE_FILES_MAX_ROOTS];
    const struct storage_file_root *root;
    struct json_object *result;
    int root_count;

    if (!storage_files_safe_upload_id(upload_id))
        return storage_files_error("invalid_upload_id",
                                   "upload_id has an unsafe form");
    root_count = storage_files_discover_roots(roots, STORAGE_FILES_MAX_ROOTS);
    if (root_count < 0)
        return storage_files_error("mount_inventory_unavailable",
                                   "mount inventory is unavailable");
    root = storage_files_select_root(roots, root_count,
                                     (root_id && root_id[0]) ? root_id : NULL, "/");
    if (!root)
        return storage_files_error("storage_root_not_found",
                                   "storage root is not available");
    if (storage_files_remove_staging(root, upload_id) != 0 && errno != ENOENT)
        return storage_files_error("upload_cleanup_failed", "upload staging could not be removed");
    result = json_object_new_object();
    json_object_object_add(result, "cancelled", json_object_new_boolean(1));
    json_object_object_add(result, "upload_id",
                           json_object_new_string(upload_id));
    return storage_files_upload_ok(result);
}

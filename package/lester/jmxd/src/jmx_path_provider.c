// SPDX-License-Identifier: GPL-2.0-or-later
#include "jmx_path_provider.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum path_probe_state {
    PATH_PROBE_MISSING = 0,
    PATH_PROBE_VALID,
    PATH_PROBE_INVALID,
};

#if defined(__APPLE__)
#define JMX_STAT_MTIME_NSEC(status) ((status)->st_mtimespec.tv_nsec)
#define JMX_STAT_CTIME_NSEC(status) ((status)->st_ctimespec.tv_nsec)
#else
#define JMX_STAT_MTIME_NSEC(status) ((status)->st_mtim.tv_nsec)
#define JMX_STAT_CTIME_NSEC(status) ((status)->st_ctim.tv_nsec)
#endif

static int stat_identity_unchanged(const struct stat *before,
                                   const struct stat *after)
{
    return before->st_dev == after->st_dev &&
           before->st_ino == after->st_ino &&
           before->st_size == after->st_size &&
           before->st_mtime == after->st_mtime &&
           JMX_STAT_MTIME_NSEC(before) == JMX_STAT_MTIME_NSEC(after) &&
           before->st_ctime == after->st_ctime &&
           JMX_STAT_CTIME_NSEC(before) == JMX_STAT_CTIME_NSEC(after);
}

static void path_error(char *error, size_t error_len, const char *value)
{
    if (error && error_len)
        snprintf(error, error_len, "%s", value ? value : "");
}

static enum path_probe_state path_probe(const char *path, int *fd_out,
                                        struct stat *status)
{
    struct stat lst;
    int fd;

    *fd_out = -1;
    if (!path || path[0] != '/')
        return PATH_PROBE_INVALID;
    if (lstat(path, &lst) != 0)
        return errno == ENOENT ? PATH_PROBE_MISSING : PATH_PROBE_INVALID;
    if (!S_ISREG(lst.st_mode))
        return PATH_PROBE_INVALID;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, status) != 0 || !S_ISREG(status->st_mode) ||
        status->st_dev != lst.st_dev || status->st_ino != lst.st_ino) {
        if (fd >= 0)
            close(fd);
        return PATH_PROBE_INVALID;
    }
    *fd_out = fd;
    return PATH_PROBE_VALID;
}

static int files_equal(int left, const struct stat *left_status,
                       int right, const struct stat *right_status)
{
    struct stat left_after;
    struct stat right_after;
    unsigned char left_buffer[64 * 1024];
    unsigned char right_buffer[64 * 1024];
    ssize_t left_count;
    ssize_t right_count;

    if (left_status->st_size != right_status->st_size)
        return 0;
    if (left_status->st_dev == right_status->st_dev &&
        left_status->st_ino == right_status->st_ino)
        return 1;
    for (;;) {
        do {
            left_count = read(left, left_buffer, sizeof(left_buffer));
        } while (left_count < 0 && errno == EINTR);
        do {
            right_count = read(right, right_buffer, sizeof(right_buffer));
        } while (right_count < 0 && errno == EINTR);
        if (left_count < 0 || right_count < 0)
            return -1;
        if (left_count != right_count)
            return 0;
        if (left_count == 0)
            break;
        if (memcmp(left_buffer, right_buffer, (size_t)left_count))
            return 0;
    }
    if (fstat(left, &left_after) != 0 || fstat(right, &right_after) != 0)
        return -1;
    if (!stat_identity_unchanged(left_status, &left_after) ||
        !stat_identity_unchanged(right_status, &right_after))
        return -1;
    return 1;
}

const char *jmx_path_selection_name(enum jmx_path_selection selection)
{
    switch (selection) {
    case JMX_PATH_SELECTION_NEW:
        return "new-only";
    case JMX_PATH_SELECTION_LEGACY:
        return "legacy-fallback";
    case JMX_PATH_SELECTION_IDENTICAL_NEW:
        return "new-identical-to-legacy";
    default:
        return "none";
    }
}

static int path_select_immutable(const char *new_path, const char *legacy_path,
                                 char *selected_path, size_t selected_path_len,
                                 enum jmx_path_selection *selection,
                                 int *selected_fd,
                                 char *error, size_t error_len)
{
    struct stat new_status;
    struct stat legacy_status;
    enum path_probe_state new_state;
    enum path_probe_state legacy_state;
    enum jmx_path_selection result = JMX_PATH_SELECTION_NONE;
    const char *selected = NULL;
    int new_fd = -1;
    int legacy_fd = -1;
    int equal = 0;
    int rc = -1;

    if (!selected_path || selected_path_len == 0 || !selection) {
        path_error(error, error_len, "invalid_argument");
        return -1;
    }
    selected_path[0] = '\0';
    *selection = JMX_PATH_SELECTION_NONE;
    path_error(error, error_len, "");
    new_state = path_probe(new_path, &new_fd, &new_status);
    legacy_state = path_probe(legacy_path, &legacy_fd, &legacy_status);
    if (new_state == PATH_PROBE_INVALID || legacy_state == PATH_PROBE_INVALID) {
        path_error(error, error_len, "path_not_safe_regular_file");
        goto done;
    }
    if (new_state == PATH_PROBE_MISSING && legacy_state == PATH_PROBE_MISSING) {
        path_error(error, error_len, "path_not_found");
        goto done;
    }
    if (new_state == PATH_PROBE_VALID && legacy_state == PATH_PROBE_VALID) {
        equal = files_equal(new_fd, &new_status, legacy_fd, &legacy_status);
        if (equal < 0) {
            path_error(error, error_len, "path_compare_failed");
            goto done;
        }
        if (!equal) {
            path_error(error, error_len, "path_identity_conflict");
            goto done;
        }
        selected = new_path;
        result = JMX_PATH_SELECTION_IDENTICAL_NEW;
    } else if (new_state == PATH_PROBE_VALID) {
        selected = new_path;
        result = JMX_PATH_SELECTION_NEW;
    } else {
        selected = legacy_path;
        result = JMX_PATH_SELECTION_LEGACY;
    }
    if (snprintf(selected_path, selected_path_len, "%s", selected) >=
        (int)selected_path_len) {
        selected_path[0] = '\0';
        path_error(error, error_len, "selected_path_too_long");
        goto done;
    }
    if (selected_fd) {
        int *chosen_fd = result == JMX_PATH_SELECTION_LEGACY ?
                         &legacy_fd : &new_fd;

        if (lseek(*chosen_fd, 0, SEEK_SET) < 0) {
            selected_path[0] = '\0';
            path_error(error, error_len, "selected_path_seek_failed");
            goto done;
        }
        *selected_fd = *chosen_fd;
        *chosen_fd = -1;
    }
    *selection = result;
    rc = 0;
done:
    if (new_fd >= 0)
        close(new_fd);
    if (legacy_fd >= 0)
        close(legacy_fd);
    return rc;
}

int jmx_path_select_immutable(const char *new_path, const char *legacy_path,
                              char *selected_path, size_t selected_path_len,
                              enum jmx_path_selection *selection,
                              char *error, size_t error_len)
{
    return path_select_immutable(new_path, legacy_path, selected_path,
                                 selected_path_len, selection, NULL,
                                 error, error_len);
}

static int immutable_name_compare(const void *left, const void *right)
{
    const struct jmx_immutable_file *a = left;
    const struct jmx_immutable_file *b = right;

    return strcmp(a->name, b->name);
}

void jmx_path_immutable_file_set_free(struct jmx_immutable_file_set *set)
{
    size_t i;

    if (!set)
        return;
    for (i = 0; i < set->count; i++) {
        free(set->items[i].name);
        free(set->items[i].selected_path);
        if (set->items[i].selected_fd >= 0)
            close(set->items[i].selected_fd);
    }
    free(set->items);
    memset(set, 0, sizeof(*set));
}

static int immutable_file_set_add_name(struct jmx_immutable_file_set *set,
                                       const char *name)
{
    struct jmx_immutable_file *next;
    size_t i;

    for (i = 0; i < set->count; i++)
        if (!strcmp(set->items[i].name, name))
            return 0;
    next = realloc(set->items, (set->count + 1) * sizeof(*next));
    if (!next)
        return -1;
    set->items = next;
    memset(&set->items[set->count], 0, sizeof(set->items[set->count]));
    set->items[set->count].selected_fd = -1;
    set->items[set->count].name = strdup(name);
    if (!set->items[set->count].name)
        return -1;
    set->count++;
    return 0;
}

static int immutable_directory_names(const char *path, const char *suffix,
                                     struct jmx_immutable_file_set *set,
                                     char *error, size_t error_len)
{
    struct stat before;
    struct stat opened;
    struct stat after;
    struct dirent *entry;
    DIR *dir;
    size_t suffix_len = strlen(suffix);

    if (lstat(path, &before) != 0) {
        if (errno == ENOENT)
            return 0;
        path_error(error, error_len, "immutable_directory_probe_failed");
        return -1;
    }
    if (!S_ISDIR(before.st_mode)) {
        path_error(error, error_len, "immutable_directory_not_safe");
        return -1;
    }
    dir = opendir(path);
    if (!dir) {
        path_error(error, error_len, "immutable_directory_open_failed");
        return -1;
    }
    if (fstat(dirfd(dir), &opened) != 0 || !S_ISDIR(opened.st_mode) ||
        opened.st_dev != before.st_dev || opened.st_ino != before.st_ino) {
        closedir(dir);
        path_error(error, error_len, "immutable_directory_changed");
        return -1;
    }
    errno = 0;
    while ((entry = readdir(dir)) != NULL) {
        size_t name_len = strlen(entry->d_name);

        if (entry->d_name[0] == '.' || name_len <= suffix_len ||
            strcmp(entry->d_name + name_len - suffix_len, suffix))
            continue;
        if (strchr(entry->d_name, '/')) {
            closedir(dir);
            path_error(error, error_len, "immutable_file_name_invalid");
            return -1;
        }
        if (immutable_file_set_add_name(set, entry->d_name) != 0) {
            closedir(dir);
            path_error(error, error_len, "out_of_memory");
            return -1;
        }
        errno = 0;
    }
    if (errno != 0) {
        closedir(dir);
        path_error(error, error_len, "immutable_directory_read_failed");
        return -1;
    }
    if (fstat(dirfd(dir), &after) != 0 ||
        !stat_identity_unchanged(&opened, &after)) {
        closedir(dir);
        path_error(error, error_len, "immutable_directory_changed");
        return -1;
    }
    if (closedir(dir) != 0) {
        path_error(error, error_len, "immutable_directory_close_failed");
        return -1;
    }
    return 0;
}

int jmx_path_select_immutable_file_set(
    const char *new_dir, const char *legacy_dir, const char *suffix,
    struct jmx_immutable_file_set *set, char *error, size_t error_len)
{
    char new_path[4096];
    char legacy_path[4096];
    char selected[4096];
    enum jmx_path_selection selection;
    size_t i;

    if (!new_dir || new_dir[0] != '/' || !legacy_dir ||
        legacy_dir[0] != '/' || !suffix || !suffix[0] || !set) {
        path_error(error, error_len, "invalid_argument");
        return -1;
    }
    memset(set, 0, sizeof(*set));
    path_error(error, error_len, "");
    if (immutable_directory_names(new_dir, suffix, set, error, error_len) != 0 ||
        immutable_directory_names(legacy_dir, suffix, set, error, error_len) != 0)
        goto fail;
    if (set->count > 1)
        qsort(set->items, set->count, sizeof(*set->items),
              immutable_name_compare);
    for (i = 0; i < set->count; i++) {
        if (snprintf(new_path, sizeof(new_path), "%s/%s", new_dir,
                     set->items[i].name) >= (int)sizeof(new_path) ||
            snprintf(legacy_path, sizeof(legacy_path), "%s/%s", legacy_dir,
                     set->items[i].name) >= (int)sizeof(legacy_path)) {
            path_error(error, error_len, "immutable_file_path_too_long");
            goto fail;
        }
        if (path_select_immutable(new_path, legacy_path, selected,
                                  sizeof(selected), &selection,
                                  &set->items[i].selected_fd,
                                  error, error_len) != 0)
            goto fail;
        set->items[i].selected_path = strdup(selected);
        if (!set->items[i].selected_path) {
            path_error(error, error_len, "out_of_memory");
            goto fail;
        }
        set->items[i].selection = selection;
    }
    return 0;
fail:
    jmx_path_immutable_file_set_free(set);
    return -1;
}

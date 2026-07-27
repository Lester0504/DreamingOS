// SPDX-License-Identifier: GPL-2.0-or-later
#include "otad_persist_source.h"
#include "jmx_path_provider.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PERSIST_PATH_MAX 512

#if defined(__APPLE__)
#define OTAD_STAT_MTIME_NSEC(status) ((status)->st_mtimespec.tv_nsec)
#define OTAD_STAT_CTIME_NSEC(status) ((status)->st_ctimespec.tv_nsec)
#else
#define OTAD_STAT_MTIME_NSEC(status) ((status)->st_mtim.tv_nsec)
#define OTAD_STAT_CTIME_NSEC(status) ((status)->st_ctim.tv_nsec)
#endif

static int source_stat_unchanged(const struct stat *before,
                                 const struct stat *after)
{
    return before->st_dev == after->st_dev &&
           before->st_ino == after->st_ino &&
           before->st_size == after->st_size &&
           before->st_mtime == after->st_mtime &&
           OTAD_STAT_MTIME_NSEC(before) == OTAD_STAT_MTIME_NSEC(after) &&
           before->st_ctime == after->st_ctime &&
           OTAD_STAT_CTIME_NSEC(before) == OTAD_STAT_CTIME_NSEC(after);
}

static void source_error(struct otad_persist_source_status *status,
                         const char *error)
{
    snprintf(status->error, sizeof(status->error), "%s", error ? error : "");
}

static int persist_path_ok(const char *path)
{
    const unsigned char *cursor;
    size_t len;

    if (!path || path[0] != '/')
        return 0;
    len = strlen(path);
    if (len == 0 || len >= PERSIST_PATH_MAX || strstr(path, "//") ||
        strstr(path, "/../") || strstr(path, "/./") ||
        (len >= 2 && !strcmp(path + len - 2, "/.")) ||
        (len >= 3 && !strcmp(path + len - 3, "/..")))
        return 0;
    for (cursor = (const unsigned char *)path; *cursor; cursor++)
        if (*cursor <= 0x20 || *cursor == 0x7f)
            return 0;
    return 1;
}

static int prefix_add(struct otad_persist_prefixes *prefixes,
                      const char *path)
{
    char **next;
    size_t i;

    if (!persist_path_ok(path))
        return -1;
    for (i = 0; i < prefixes->count; i++)
        if (!strcmp(prefixes->items[i], path))
            return 0;
    if (prefixes->count == prefixes->capacity) {
        size_t capacity = prefixes->capacity ? prefixes->capacity * 2 : 16;

        next = realloc(prefixes->items, capacity * sizeof(*next));
        if (!next)
            return -1;
        prefixes->items = next;
        prefixes->capacity = capacity;
    }
    prefixes->items[prefixes->count] = strdup(path);
    if (!prefixes->items[prefixes->count])
        return -1;
    prefixes->count++;
    return 0;
}

void otad_persist_prefixes_free(struct otad_persist_prefixes *prefixes)
{
    size_t i;

    if (!prefixes)
        return;
    for (i = 0; i < prefixes->count; i++)
        free(prefixes->items[i]);
    free(prefixes->items);
    memset(prefixes, 0, sizeof(*prefixes));
}

static int load_fd(struct otad_persist_prefixes *prefixes, int source_fd)
{
    char line[PERSIST_PATH_MAX];
    struct stat before;
    struct stat after;
    FILE *file;
    int fd;
    int errors = 0;

    fd = dup(source_fd);
    if (fd < 0 || lseek(fd, 0, SEEK_SET) < 0 ||
        fstat(fd, &before) != 0 || !S_ISREG(before.st_mode)) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    file = fdopen(fd, "r");
    if (!file) {
        close(fd);
        return -1;
    }
    while (fgets(line, sizeof(line), file)) {
        char *start = line;
        char *end;
        size_t len = strlen(line);

        if (len == sizeof(line) - 1 && line[len - 1] != '\n' && !feof(file)) {
            int ch;

            while ((ch = fgetc(file)) != '\n' && ch != EOF)
                ;
            errors++;
            continue;
        }
        while (*start == ' ' || *start == '\t')
            start++;
        end = start + strlen(start);
        while (end > start && (end[-1] == '\r' || end[-1] == '\n' ||
                               end[-1] == ' ' || end[-1] == '\t'))
            *--end = '\0';
        if (!start[0] || start[0] == '#')
            continue;
        if (prefix_add(prefixes, start) != 0)
            errors++;
    }
    if (ferror(file) || fstat(fd, &after) != 0 ||
        !source_stat_unchanged(&before, &after))
        errors++;
    if (fclose(file) != 0)
        errors++;
    return errors ? -1 : 0;
}

static int load_runtime_dir(const char *path,
                            struct otad_persist_prefixes *prefixes,
                            struct otad_persist_source_status *status)
{
    struct stat before;
    struct stat opened;
    struct stat after;
    struct dirent *entry;
    DIR *dir;

    if (lstat(path, &before) != 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISDIR(before.st_mode))
        return -1;
    dir = opendir(path);
    if (!dir)
        return -1;
    if (fstat(dirfd(dir), &opened) != 0 || !S_ISDIR(opened.st_mode) ||
        opened.st_dev != before.st_dev || opened.st_ino != before.st_ino)
        goto fail;
    errno = 0;
    while ((entry = readdir(dir)) != NULL) {
        struct stat file_status;
        size_t len = strlen(entry->d_name);
        int fd;

        if (entry->d_name[0] == '.' || len <= 5 ||
            strcmp(entry->d_name + len - 5, ".list"))
            continue;
        fd = openat(dirfd(dir), entry->d_name,
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0 || fstat(fd, &file_status) != 0 ||
            !S_ISREG(file_status.st_mode)) {
            if (fd >= 0)
                close(fd);
            goto fail;
        }
        if (load_fd(prefixes, fd) != 0) {
            close(fd);
            goto fail;
        }
        close(fd);
        status->runtime_files++;
        errno = 0;
    }
    if (errno != 0 || fstat(dirfd(dir), &after) != 0 ||
        !source_stat_unchanged(&opened, &after))
        goto fail;
    return closedir(dir) == 0 ? 0 : -1;
fail:
    closedir(dir);
    return -1;
}

int otad_persist_sources_load(const char *new_dir, const char *legacy_dir,
                              const char *runtime_dir,
                              struct otad_persist_prefixes *prefixes,
                              struct otad_persist_source_status *status)
{
    struct jmx_immutable_file_set files;
    size_t i;

    if (!new_dir || !legacy_dir || !runtime_dir || !prefixes || !status)
        return -1;
    memset(prefixes, 0, sizeof(*prefixes));
    memset(status, 0, sizeof(*status));
    if (jmx_path_select_immutable_file_set(new_dir, legacy_dir, ".list",
                                           &files, status->error,
                                           sizeof(status->error)) != 0)
        return -1;
    for (i = 0; i < files.count; i++) {
        if (load_fd(prefixes, files.items[i].selected_fd) != 0) {
            source_error(status, "immutable_persist_list_read_failed");
            goto fail;
        }
        switch (files.items[i].selection) {
        case JMX_PATH_SELECTION_NEW:
            status->new_only++;
            break;
        case JMX_PATH_SELECTION_LEGACY:
            status->legacy_only++;
            break;
        case JMX_PATH_SELECTION_IDENTICAL_NEW:
            status->identical_new++;
            break;
        default:
            source_error(status, "immutable_persist_selection_invalid");
            goto fail;
        }
    }
    jmx_path_immutable_file_set_free(&files);
    if (load_runtime_dir(runtime_dir, prefixes, status) != 0) {
        source_error(status, "runtime_persist_list_read_failed");
        otad_persist_prefixes_free(prefixes);
        return -1;
    }
    return 0;
fail:
    jmx_path_immutable_file_set_free(&files);
    otad_persist_prefixes_free(prefixes);
    return -1;
}

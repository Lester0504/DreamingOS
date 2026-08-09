// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_STORAGE_FILES_H
#define DREAMINGWRT_STORAGE_FILES_H

#include <limits.h>
#include <stdint.h>

#include <json-c/json.h>

struct json_object *jmx_storage_files_list(const char *root_id,
                                           const char *path,
                                           const char *search);
struct json_object *jmx_storage_files_content(const char *root_id,
                                              const char *path);
struct json_object *jmx_storage_files_mutate(struct json_object *payload);

/* Result of a byte-stream open.  fd is owned by the caller once
 * storage_files_open_stream() succeeds and must be closed by it. */
struct storage_files_stream {
    int fd;
    uint64_t size_bytes;
    uint64_t inode;
    int64_t modified_unix;
    char root_id[48];
    char display_path[PATH_MAX];
    char basename[NAME_MAX + 1];
};

/* Opens a regular file for raw streaming under the same path, mount and
 * deny-list guards as the JSON content read, minus the text-only limits.
 * Returns 0 and fills *out on success, -1 with *reason set otherwise. */
int storage_files_open_stream(const char *root_id, const char *path,
                              struct storage_files_stream *out,
                              const char **reason);

/* Server-side deny-lists.  Exposed so the guards can be exercised directly by
 * tests rather than only through a full request. */
int storage_files_content_denied(const char *abs_path, const char *basename,
                                 const char **reason);
int storage_files_write_denied(const char *abs_path, const char **reason);

#endif

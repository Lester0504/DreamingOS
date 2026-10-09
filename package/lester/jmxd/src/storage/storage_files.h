// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_STORAGE_FILES_H
#define DREAMINGWRT_STORAGE_FILES_H

#include <limits.h>
#include <stdint.h>

#include <json-c/json.h>

struct json_object *jmx_storage_files_list(const char *root_id,
                                           const char *path,
                                           const char *search);
/* Inventory only: no directory entries or file contents are read. */
struct json_object *storage_files_roots_json(void);
struct json_object *jmx_storage_files_content(const char *root_id,
                                              const char *path);
struct json_object *jmx_storage_files_mutate(struct json_object *payload);

/* Bounded recursive name search below a starting directory.  query supports
 * '*'/'?' globs (matched against each basename); without a glob it is a
 * case-insensitive substring match.  limit <= 0 uses the built-in cap. */
struct json_object *jmx_storage_files_search(const char *root_id,
                                             const char *path,
                                             const char *query, int limit);

/* Upload into a storage path (binary, no UTF-8/256 KiB limit).  All reuse the
 * same writable-root + relative-path + deny-list sandbox as the mutate actions,
 * committing via a transactional temp + renameat2.  Intended to be called
 * IN-PROCESS from webd (storage_files.o is linked into webd), so a large body
 * never has to traverse ubus.  Each returns a storage-files.v1 JSON envelope. */
struct json_object *jmx_storage_files_store_bytes(const char *root_id,
                                                  const char *dir_path,
                                                  const char *filename,
                                                  const unsigned char *data,
                                                  size_t len, int overwrite);
struct json_object *jmx_storage_files_upload_init(const char *root_id,
                                                  const char *dir_path,
                                                  const char *filename,
                                                  const char *client_upload_id,
                                                  int64_t total_size,
                                                  int total_chunks,
                                                  int overwrite);
struct json_object *jmx_storage_files_upload_chunk(const char *root_id,
                                                   const char *upload_id,
                                                   int chunk_index,
                                                   const unsigned char *data,
                                                   size_t len);
struct json_object *jmx_storage_files_upload_complete(const char *root_id,
                                                      const char *upload_id);
struct json_object *jmx_storage_files_upload_cancel(const char *root_id,
                                                    const char *upload_id);

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

/* Optional NAS services use this descriptor rather than opening a supplied
 * absolute path. Caller owns fd. Writing requires an ordinary writable root. */
int storage_files_open_dir(const char *root_id, const char *path, int writing,
                           char *canonical, size_t canonical_size,
                           const char **reason);

/* Server-side deny-lists.  Exposed so the guards can be exercised directly by
 * tests rather than only through a full request. */
int storage_files_content_denied(const char *abs_path, const char *basename,
                                 const char **reason);
int storage_files_write_denied(const char *abs_path, const char **reason);

#endif

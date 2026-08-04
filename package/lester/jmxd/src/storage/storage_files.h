// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_STORAGE_FILES_H
#define DREAMINGWRT_STORAGE_FILES_H

#include <json-c/json.h>

struct json_object *jmx_storage_files_list(const char *root_id,
                                           const char *path,
                                           const char *search);
struct json_object *jmx_storage_files_content(const char *root_id,
                                              const char *path);
struct json_object *jmx_storage_files_mutate(struct json_object *payload);

/* Server-side deny-lists.  Exposed so the guards can be exercised directly by
 * tests rather than only through a full request. */
int storage_files_content_denied(const char *abs_path, const char *basename,
                                 const char **reason);
int storage_files_write_denied(const char *abs_path, const char **reason);

#endif

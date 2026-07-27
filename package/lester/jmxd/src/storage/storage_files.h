// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_STORAGE_FILES_H
#define DREAMINGWRT_STORAGE_FILES_H

#include <json-c/json.h>

struct json_object *jmx_storage_files_list(const char *root_id,
                                           const char *path,
                                           const char *search);
struct json_object *jmx_storage_files_content(const char *root_id,
                                              const char *path);

#endif

// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGOS_NAS_MEDIA_H
#define DREAMINGOS_NAS_MEDIA_H
#include <json-c/json.h>
#include <signal.h>
struct json_object *nas_media_read(const char *root, const char *path, const char *domain,
                                   int cache_fd, long id, volatile sig_atomic_t *cancelled);
#endif

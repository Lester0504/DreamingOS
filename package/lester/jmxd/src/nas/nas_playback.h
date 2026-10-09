// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGOS_NAS_PLAYBACK_H
#define DREAMINGOS_NAS_PLAYBACK_H
#include <json-c/json.h>
struct json_object *nas_playback_request(const char *method, const char *route,
    struct json_object *input, int data_fd, const char *root, const char *path, int *status);
void nas_playback_tick(int storage_ready);
void nas_playback_close(void);
void nas_playback_recover(int data_fd);
int nas_playback_active(void);
int nas_playback_capable(void);
#endif

// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGOS_NAS_H
#define DREAMINGOS_NAS_H
#include <json-c/json.h>
struct json_object *nas_request(const char *method, const char *route, struct json_object *input,
                                int *http_status);
int nas_init(const char *config_path);
void nas_close(void);
void nas_tick(void);
#endif

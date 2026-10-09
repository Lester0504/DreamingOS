// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGOS_NAS_DOWNLOADS_H
#define DREAMINGOS_NAS_DOWNLOADS_H
#include <json-c/json.h>
struct json_object *nas_downloads_request(const char *method, const char *route,
                                          struct json_object *input, int *status);
#endif

// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGOS_DATA_STORAGE_H
#define DREAMINGOS_DATA_STORAGE_H
#include <json-c/json.h>

/* Shared persistent default, independent of optional NAS/NVR packages. */
struct json_object *data_storage_response(struct json_object *selection, int *http);
/* A service pins this snapshot for its process lifetime. Unconfigured services
 * may reload it; a configured service must never follow a new default in place. */
struct json_object *data_storage_app_load(const char *config_file);
struct json_object *data_storage_app_resolve(struct json_object *snapshot);
#endif

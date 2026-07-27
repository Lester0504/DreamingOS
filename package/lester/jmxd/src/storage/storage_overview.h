// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_STORAGE_OVERVIEW_H
#define DREAMINGWRT_STORAGE_OVERVIEW_H

#include <json-c/json.h>

/* Returns the complete DreamingWrt code/data envelope. */
struct json_object *jmx_storage_overview_get(const char *range);

#endif /* DREAMINGWRT_STORAGE_OVERVIEW_H */

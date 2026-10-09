// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_STORAGE_POLICY_H
#define DREAMINGWRT_STORAGE_POLICY_H

#include <json-c/json.h>
#include <stddef.h>

/* Discovery/status is read-only. prepare=1 is only for init before consumers. */
struct json_object *jmx_storage_policy_evaluate(int prepare, char *selected,
                                               size_t selected_len,
                                               char *provider, size_t provider_len);

#endif

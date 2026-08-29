// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_TOOLKIT_H
#define WEBD_API_TOOLKIT_H

#include <json-c/json.h>

#include "api_router.h"

extern const struct jmx_api_route toolkit_api_routes[];

/* Still used by the two single-ID DELETE branches left in the legacy chain. */
struct json_object *webd_toolkit_exec(const char *command,
                                      struct json_object *params,
                                      const char *actor,
                                      int timeout_ms,
                                      int *http_status);

#endif /* WEBD_API_TOOLKIT_H */

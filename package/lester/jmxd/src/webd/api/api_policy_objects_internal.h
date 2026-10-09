// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
/*
 * Private contract between the legacy policy write core and the policy
 * zones/objects route module.
 *
 * Policy write helpers are declared by api_policy_write_internal.h.
 * Only the remaining legacy projection helpers are declared below.
 *
 * These prototypes reach <uci.h> and <sqlite3.h>, which is why they are not in
 * api_policy_objects.h: that header is included by api_router.c, and the
 * matcher fixture compiles the router without those libraries present.
 */
#ifndef WEBD_API_POLICY_OBJECTS_INTERNAL_H
#define WEBD_API_POLICY_OBJECTS_INTERNAL_H
#include "api_policy_write_internal.h"

#include <stddef.h>

#include <json-c/json.h>
#include <uci.h>

/*
 * Shared JSON, envelope, error and ubus helpers are already declared in
 * api_json.h / api_error.h / api_ubus.h; only what is still defined in
 * jmx_app_api.c is declared here.
 */
const char *webd_policy_zone_label(const char *zone);
int webd_policy_uci_option_keep(struct uci_section *s, const char *name,
                                char *out, size_t out_len);

#endif /* WEBD_API_POLICY_OBJECTS_INTERNAL_H */

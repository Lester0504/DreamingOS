// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_FLOWD_INTERNAL_H
#define WEBD_API_FLOWD_INTERNAL_H

struct json_object;

/* Defined in jmx_app_api.c; the flowd runtime/wan-health readers in api_flowd.c
 * reuse it to keep a single implementation of the configured-WAN match. */
int webd_runtime_entry_matches_configured_wan(struct json_object *entry,
                                              struct json_object *configured_wans);

#endif /* WEBD_API_FLOWD_INTERNAL_H */

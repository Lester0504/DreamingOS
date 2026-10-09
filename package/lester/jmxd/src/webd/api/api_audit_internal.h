// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_AUDIT_INTERNAL_H
#define WEBD_API_AUDIT_INTERNAL_H

#include <stdint.h>

/*
 * Borrowed from jmx_app_api.c. The 4 webd_insights_* helpers are de-static'd
 * there (their definitions stay in main with their other insights callers); the
 * audit BFF response builders in api_audit.c reuse a single implementation of
 * each. webd_first_nonempty4 / webd_str_contains_i are already extern in main
 * (used def-before-use, so main needs no header) — the audit TU is a separate
 * compilation unit and needs the prototypes.
 */
struct json_object;
struct webd_insights_query;

struct json_object *webd_insights_fetch_flow_app_summary(const struct webd_insights_query *q, int top);
int64_t webd_insights_ts_normalize(int64_t ts);
struct json_object *webd_insights_ubus_data_timeout(const char *method, struct json_object *params, int timeout_ms);
struct json_object *webd_insights_ubus_response_timeout(const char *method, struct json_object *params, int timeout_ms);
const char *webd_first_nonempty4(const char *a, const char *b, const char *c, const char *d);
int webd_str_contains_i(const char *haystack, const char *needle);

#endif /* WEBD_API_AUDIT_INTERNAL_H */

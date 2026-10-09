// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_LOGS_V2_INTERNAL_H
#define WEBD_API_LOGS_V2_INTERNAL_H
/* Phase 7L: EXPORTs de-static'd from jmx_app_api.c so the main TU
 * (handle_client and the audit/redaction paths that stay in main) can still
 * reach them. The logs-v2 response helpers are declared in api_logs_internal.h;
 * the region-local structs stay inside api_logs_v2.c. */
#include <stddef.h>   /* size_t */
struct json_object;
struct http_req;

int webd_ai_log_runtime_ready(void);
char *webd_ai_redact_text(const char *src, size_t max_len);
struct json_object *webd_ai_logs_analyze_response(struct json_object *body,
                                                  const char *actor, int *status);
int webd_logs_download_response(int fd, const struct http_req *req);

#endif /* WEBD_API_LOGS_V2_INTERNAL_H */

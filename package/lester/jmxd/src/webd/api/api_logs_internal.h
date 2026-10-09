// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_LOGS_INTERNAL_H
#define WEBD_API_LOGS_INTERNAL_H

/*
 * Borrowed from jmx_app_api.c. These three logs helpers are de-static'd there
 * (their definitions stay in main, shared with the inline RAW_FD download STAY
 * branch and the non-dispatch logd producers/consumers in other domains); the
 * logs BFF adapters in api_logs.c reuse the single implementations. The logs TU
 * is a separate compilation unit and needs the prototypes.
 */
struct json_object;

struct json_object *webd_logs_v2_response(const char *method, struct json_object *body,
                                          const char *source, int *status);
struct json_object *webd_logs_v2_flat_response(const char *method,
                                               struct json_object *body,
                                               const char *source, int *status);
void webd_logs_attach_actor(struct json_object *body, const char *device_id);

#endif /* WEBD_API_LOGS_INTERNAL_H */

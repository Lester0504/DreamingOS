// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_CLOUD_INTERNAL_H
#define WEBD_API_CLOUD_INTERNAL_H

/* Cloud relay helpers live in api_cloud.c (Phase 7Y). The confirmation
 * wrappers below reuse account/session state owned by jmx_app_api.c. */
struct json_object;
struct http_req;
int webd_cloud_local_request_allowed(const struct http_req *req);
const char *webd_cloud_work_mode(void);
struct json_object *webd_cloud_confirm_password(const char *username,
    const char *password, const char *client_ip, int *status);
struct json_object *webd_cloud_confirm_passkey(struct json_object *assertion,
    const char *username, const char *binding, int *status);
const char *webd_identity_username(const char *identity);

struct json_object *webd_cloud_component_response(const char *method,
                                                  struct json_object *args,
                                                  int *status);
struct json_object *webd_cloud_config_write(struct json_object *body,
                                            int *status);

#endif /* WEBD_API_CLOUD_INTERNAL_H */

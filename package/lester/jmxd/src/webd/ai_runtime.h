// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __WEBD_AI_RUNTIME_H__
#define __WEBD_AI_RUNTIME_H__

#include <json-c/json.h>

struct json_object *webd_ai_runtime_chat(struct json_object *body,
                                         const char *actor,
                                         int *http_status);
int webd_ai_runtime_stream(int fd, struct json_object *body,
                           const char *actor);
struct json_object *webd_ai_runtime_cancel(const char *response_id,
                                           const char *actor,
                                           int *http_status);
struct json_object *webd_ai_runtime_provider_test(const char *actor,
                                                  int *http_status);
struct json_object *webd_ai_runtime_provider_test_id(const char *provider_id,
                                                     const char *actor,
                                                     int *http_status);
struct json_object *webd_ai_runtime_models(const char *actor,
                                           int *http_status);
struct json_object *webd_ai_runtime_models_id(const char *provider_id,
                                              const char *actor,
                                              int *http_status);
struct json_object *webd_ai_attachment_create(struct json_object *body,
                                              const char *actor,
                                              int *http_status);
struct json_object *webd_ai_attachment_get(const char *attachment_id,
                                           const char *actor,
                                           int *http_status);
struct json_object *webd_ai_attachment_delete(const char *attachment_id,
                                              const char *actor,
                                              int *http_status);
struct json_object *webd_ai_runtime_authorization_resolved(
    struct json_object *authorization_response,
    const char *approver,
    int defer_continuation,
    int *http_status);
struct json_object *webd_ai_runtime_resume(const char *resume_token,
                                           const char *actor,
                                           int *http_status);
int webd_ai_runtime_resume_stream(int fd, const char *resume_token,
                                  const char *actor);
void webd_ai_runtime_attach_capabilities(struct json_object *response);

#endif

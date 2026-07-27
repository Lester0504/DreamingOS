// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __DREAMINGWRT_WEBD_AI_OAUTH_H__
#define __DREAMINGWRT_WEBD_AI_OAUTH_H__

#include <stddef.h>
#include <stdint.h>
#include <json-c/json.h>

#ifndef WEBD_AI_OAUTH_STATE_DIR
#define WEBD_AI_OAUTH_STATE_DIR "/etc/dreamingwrt/ai-oauth"
#endif

/* All returned JSON objects are owned by the caller; none contains tokens. */
struct json_object *webd_ai_oauth_catalog(void);
struct json_object *webd_ai_oauth_status(const char *provider,
                                         int *http_status);
struct json_object *webd_ai_oauth_start(struct json_object *request,
                                        const char *actor,
                                        int *http_status);
struct json_object *webd_ai_oauth_poll(struct json_object *request,
                                       const char *actor,
                                       int *http_status);
struct json_object *webd_ai_oauth_refresh(const char *provider,
                                          int *http_status);
struct json_object *webd_ai_oauth_disconnect(const char *provider,
                                             const char *actor,
                                             int *http_status);

/* Runtime helper. It never exposes refresh tokens. */
enum webd_ai_oauth_result {
    WEBD_AI_OAUTH_OK = 0,
    WEBD_AI_OAUTH_INVALID = -1,
    WEBD_AI_OAUTH_UNAVAILABLE = -2,
    WEBD_AI_OAUTH_REFRESH_FAILED = -3,
    WEBD_AI_OAUTH_STORAGE_FAILED = -4,
    WEBD_AI_OAUTH_BUFFER_TOO_SMALL = -5,
};

int webd_ai_oauth_access_token(const char *provider, char *token,
                               size_t token_len, char *routing_id,
                               size_t routing_id_len, int64_t *expires_at);

#endif

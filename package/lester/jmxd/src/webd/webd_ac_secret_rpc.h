// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_WEBD_AC_SECRET_RPC_H
#define DREAMINGWRT_WEBD_AC_SECRET_RPC_H

#include <json-c/json.h>

struct json_object *webd_ac_secret_rotate_response(
    const char *ap_id, const char *ssid_id, const char *actor_id,
    struct json_object *body,
    char *raw_body, size_t raw_body_len, int *http_status);
struct json_object *webd_ac_secret_status_response(const char *job_id,
                                                   int *http_status);

#endif

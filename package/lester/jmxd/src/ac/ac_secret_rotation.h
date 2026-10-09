// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_AC_SECRET_ROTATION_H
#define DREAMINGWRT_AC_SECRET_ROTATION_H

#include <stdint.h>
#include <json-c/json.h>

#define AC_SECRET_ROTATION_SOCKET "/var/run/dreamingwrt-ac-secret.sock"
#define AC_SECRET_ROTATION_MAX_SECTIONS 16U
#define AC_SECRET_ROTATION_SECRET_MAX 64U

int ac_secret_rotation_init(void);
void ac_secret_rotation_close(void);

void ac_secret_rotation_session_begin(const char *ap_id, int capable);
void ac_secret_rotation_session_end(const char *ap_id);
int ac_secret_rotation_available_count(void);
int ac_secret_rotation_ap_available(const char *ap_id);
int ac_secret_rotation_ssid_busy(const char *ssid_id);

struct json_object *ac_secret_rotation_poll(const char *ap_id,
                                             const char *session_epoch,
                                             int64_t reply_to);
struct json_object *ac_secret_rotation_prepare(struct json_object *message,
                                                const char *ap_id,
                                                const char *session_epoch,
                                                int64_t reply_to);
struct json_object *ac_secret_rotation_commit(struct json_object *message,
                                               const char *ap_id,
                                               const char *session_epoch,
                                               int64_t reply_to);
void ac_secret_rotation_scrub_offer(struct json_object *message);

#endif

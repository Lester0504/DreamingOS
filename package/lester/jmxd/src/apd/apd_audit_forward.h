/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef APD_AUDIT_FORWARD_H
#define APD_AUDIT_FORWARD_H

#include <json-c/json.h>
#include <stddef.h>
#include <stdint.h>

#define APD_AUDIT_EVENT_ID_LEN 37
#define APD_AUDIT_ACTOR_LEN 96
#define APD_AUDIT_ACTOR_SESSION_LEN 129
#define APD_AUDIT_ACTION_LEN 129
#define APD_AUDIT_TARGET_LEN 513
#define APD_AUDIT_IP_LEN 65
#define APD_AUDIT_RESULT_LEN 65
#define APD_AUDIT_REASON_LEN 257
#define APD_AUDIT_REQUEST_ID_LEN 65
#define APD_AUDIT_SCHEMA_VERSION 1
#define APD_AUDIT_WAIT_TIMEOUT_MS 12000

struct apd_audit_event {
    char event_id[APD_AUDIT_EVENT_ID_LEN];
    int64_t occurred_at;
    char actor[APD_AUDIT_ACTOR_LEN];
    char actor_session[APD_AUDIT_ACTOR_SESSION_LEN];
    char action[APD_AUDIT_ACTION_LEN];
    char risk[16];
    char target[APD_AUDIT_TARGET_LEN];
    char source_ip[APD_AUDIT_IP_LEN];
    char result[APD_AUDIT_RESULT_LEN];
    char failure_reason[APD_AUDIT_REASON_LEN];
    char request_id[APD_AUDIT_REQUEST_ID_LEN];
};

int apd_audit_forward_init(void);
void apd_audit_forward_close(void);

/* The UBus boundary accepts only generated UUIDv4 event identifiers. */
int apd_audit_event_id_valid(const char *value);

/* Blocks until the active mTLS session reports an AC persistence ACK. */
int apd_audit_forward_submit(struct apd_audit_event *event,
                             char *reason, size_t reason_len);

/* Transport-thread side of the single in-flight handoff. */
int apd_audit_forward_pending(void);
int apd_audit_forward_take(struct apd_audit_event *event);
void apd_audit_forward_complete(const char *event_id, int persisted,
                                const char *reason);
void apd_audit_forward_fail_active(const char *reason);

int apd_audit_forward_ac_reachable(void);
struct json_object *apd_audit_forward_status_json(void);

#endif

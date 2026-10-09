/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __TERMINAL_POLICY_H__
#define __TERMINAL_POLICY_H__

#include <stdint.h>
#include <stddef.h>
#include <json-c/json.h>

#define TP_DB_PATH    "/etc/dreamingwrt/terminal_policy.db"

/* Status constants */
#define TP_STATUS_ACTIVE      "active"
#define TP_STATUS_SCHEDULED   "scheduled"
#define TP_STATUS_BLOCKED_TIME "blocked_time"
#define TP_STATUS_BLOCKED_QUOTA "blocked_quota"
#define TP_STATUS_DISABLED    "disabled"
#define TP_STATUS_APPLY_FAILED "apply_failed"

/* rate_mode values */
#define TP_RATE_PER_IP        "per_ip"
#define TP_RATE_SHARED        "shared"

/* quota_mode values */
#define TP_QUOTA_PER_IP       "per_ip"
#define TP_QUOTA_SHARED       "shared"

/* duration_unit values */
#define TP_UNIT_HOURS         "hours"
#define TP_UNIT_DAYS          "days"
#define TP_UNIT_WEEKS         "weeks"
#define TP_UNIT_MONTHS        "months"
#define TP_UNIT_YEARS         "years"

/* protocol values */
#define TP_PROTO_TCP          "tcp"
#define TP_PROTO_UDP          "udp"
#define TP_PROTO_ICMP         "icmp"

typedef struct tp_policy {
    char id[65];
    char name[129];
    char remark[257];
    int enabled;

    int rate_upload_kbps;     /* 0 = unlimited */
    int rate_download_kbps;
    char rate_mode[16];       /* per_ip or shared */

    int64_t started_at;       /* unix epoch, 0 = on apply */
    int64_t duration_count;   /* > 0 = time limited */
    char duration_unit[16];
    int64_t deadline_at;      /* computed */

    long long quota_bytes;    /* 0 = unlimited */
    /* upload_plus_download is 20 bytes; keep room for the terminator and
     * leave headroom for future accounting labels. */
    char quota_accounting[32];
    char quota_mode[16];     /* per_ip or shared */

    char deny_protocols[64];  /* comma-separated like "tcp,udp" */

    char status[32];         /* active|blocked_time|blocked_quota|disabled|apply_failed|scheduled */
    int64_t last_transition_at;
    unsigned generation;
    int64_t created_at;
    int64_t updated_at;
    int64_t used_upload_bytes;   /* runtime only, loaded from quota_usage table */
    int64_t used_download_bytes; /* runtime only, loaded from quota_usage table */
    int64_t used_bytes;       /* runtime only, loaded from quota_usage table */
} tp_policy_t;

typedef struct tp_error {
    const char *code;
    char detail[256];
} tp_error_t;

/* ---- Lifecycle ---- */
int  tp_db_init(void);
void tp_db_close(void);

/* ---- CRUD ---- */
struct json_object *tp_policy_list(void);
struct json_object *tp_policy_get(const char *id, int expand_targets);
/* Exact storage snapshot used for write rollback.  Unlike tp_policy_get(),
 * it preserves the raw status/generation/timestamps, returns every quota
 * client row (no display cap) and records whether a quota_usage row exists. */
struct json_object *tp_policy_snapshot(const char *id);
struct json_object *tp_policy_create(struct json_object *body, tp_error_t *err);
struct json_object *tp_policy_update(const char *id, struct json_object *body, tp_error_t *err);
int  tp_policy_restore_snapshot(const char *id, struct json_object *snapshot,
                                int recreate, tp_error_t *err);
int  tp_policy_delete(const char *id);
int  tp_policy_reset_usage(const char *id);
int  tp_policy_renew(const char *id, int64_t count, const char *unit, int keep_quota_usage);
int  tp_valid_unit(const char *u);
int  tp_policy_account_usage(const char *id, int64_t upload_delta,
                             int64_t download_delta, int64_t *used_out);
int  tp_policy_account_usage_for_client(const char *id, int family,
                                        const char *client_ip,
                                        int64_t upload_delta,
                                        int64_t download_delta,
                                        int64_t *used_out,
                                        int *exhausted_out);

/* ---- Capabilities ---- */
struct json_object *tp_capabilities(void);

/* ---- Internal helpers (for webd integration) ---- */
const char *tp_expand_status_to_reason(const char *status);
struct json_object *tp_json_from_policy(tp_policy_t *p, int include_targets);

#endif /* __TERMINAL_POLICY_H__ */

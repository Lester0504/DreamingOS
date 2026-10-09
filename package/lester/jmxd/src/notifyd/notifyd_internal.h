// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_NOTIFYD_INTERNAL_H
#define DREAMINGWRT_NOTIFYD_INTERNAL_H

#include <ctype.h>
#include "jmx_dataset_path.h"
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <json-c/json.h>
#include <sqlite3.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include "../event_semantics.h"
#include "../jmx_storage_guard.h"

#define NOTIFYD_DB_PATH jmx_dataset_path("notify")
#define NOTIFYD_CONFIG_DB_PATH "/etc/dreamingwrt/config.db"
#define NOTIFYD_SCHEMA_VERSION 1
#define NOTIFYD_MAX_ID 96
#define NOTIFYD_MAX_TEXT 512
#define NOTIFYD_MAX_JSON 16384
#define NOTIFYD_ROUTE_SCHEMA_VERSION 1
#define NOTIFYD_MAX_ROUTE_ACTIONS 8
#define NOTIFYD_MAX_ROUTE_WINDOWS 32
#define NOTIFYD_MAX_ROUTE_RECEIVERS 64
#define NOTIFYD_MAX_TEMPLATE_SUBJECT 256
#define NOTIFYD_MAX_TEMPLATE_BODY 8192
#define NOTIFYD_MAX_DEDUPE_WINDOW 86400
#define NOTIFYD_DEFAULT_LIMIT 100
#define NOTIFYD_MAX_LIMIT 500
#define NOTIFYD_DELIVERY_TICK_MS 2000
#define NOTIFYD_MAX_DELIVER_PER_TICK 16
#define NOTIFYD_OUTBOX_MAX_ROWS 10000
#define NOTIFYD_DELIVERIES_MAX_ROWS 20000
#define NOTIFYD_OUTBOX_DONE_RETENTION_SEC (7 * 86400)
#define NOTIFYD_OUTBOX_PENDING_RETENTION_SEC (2 * 86400)
/*
 * Per-user notification preference limits.
 *
 * A timed mute is bounded so a mis-set expiry cannot silence an account
 * indefinitely by accident; a genuinely indefinite mute is expressed as
 * muted_until=0 and is therefore explicit rather than a side effect of a bad
 * timestamp.
 */
#define NOTIFYD_USER_MUTE_MAX_DURATION_S (30 * 86400)
#define NOTIFYD_MAX_PREF_CHANNELS 32

struct notifyd_channel {
    char id[NOTIFYD_MAX_ID];
    char name[128];
    char type[32];
    int enabled;
    char options_json[NOTIFYD_MAX_JSON];
};

struct notifyd_settings {
    int enabled;
    char default_channel_id[NOTIFYD_MAX_ID];
    int max_attempts;
    int retry_base_s;
    int retry_max_s;
    char smtp_host[256];
    int smtp_port;
    char smtp_security[16];
    char smtp_from[256];
    char smtp_username[256];
    char smtp_password[512];
    char mute_schedule_json[NOTIFYD_MAX_JSON];
};

struct notifyd_outbox_item {
    char id[NOTIFYD_MAX_ID];
    char channel_id[NOTIFYD_MAX_ID];
    char payload_json[NOTIFYD_MAX_JSON];
    char delivery_options_json[NOTIFYD_MAX_JSON];
    int action_index;
    int attempts;
    int max_attempts;
};

/*
 * Outcome of one delivery attempt.
 *
 * Suppression is deliberately not folded into failure. A recipient who muted
 * their own notifications is an intended, terminal outcome; reporting it as a
 * failure would drive notifyd status to "degraded", burn retry attempts and put
 * a red row in the delivery table for something the user asked for.
 */
enum notifyd_delivery_outcome {
    NOTIFYD_DELIVERY_FAILED = 0,
    NOTIFYD_DELIVERY_OK = 1,
    NOTIFYD_DELIVERY_SUPPRESSED = 2,
};

extern sqlite3 *g_notify_db;
extern sqlite3 *g_notify_config_db;
extern struct ubus_context *g_notify_ubus;
extern struct blob_buf g_notify_blob;
extern uint64_t g_notify_seq;
extern uint64_t g_notify_storage_suppressed;
extern int64_t g_notify_storage_last_suppressed_at;

int64_t notifyd_now_s(void);
void notifyd_make_id(const char *prefix, char *out, size_t out_len);
const char *notifyd_json_str(struct json_object *o, const char *key, const char *def);
int notifyd_json_int(struct json_object *o, const char *key, int def);
int64_t notifyd_json_i64(struct json_object *o, const char *key, int64_t def);
int notifyd_json_bool(struct json_object *o, const char *key, int def);
struct json_object *notifyd_json_parse_or_object(const char *s);
struct json_object *notifyd_json_from_blob(struct blob_attr *msg);
struct json_object *notifyd_payload_or_self(struct json_object *body);
const char *notifyd_sqlite_text(sqlite3_stmt *st, int col, const char *def);
int notifyd_text_ok(const char *s, size_t max_len);
int notifyd_token_ok(const char *s, size_t max_len);
int notifyd_id_ok(const char *s);
int notifyd_url_ok(const char *s);
int notifyd_json_fits(struct json_object *o, size_t max_len);
const char *notifyd_severity(const char *s);
int notifyd_severity_rank(const char *s);

sqlite3_stmt *notifyd_prepare(const char *sql);
sqlite3_stmt *notifyd_config_prepare(const char *sql);
int notifyd_db_init(void);
void notifyd_db_close(void);
int notifyd_settings_load(struct notifyd_settings *out);
struct json_object *notifyd_status_json(void);
struct json_object *notifyd_event_catalog_json(void);
struct json_object *notifyd_settings_json(void);
struct json_object *notifyd_settings_update(struct json_object *body);
struct json_object *notifyd_channels_json(void);
struct json_object *notifyd_channels_update(struct json_object *body);
struct json_object *notifyd_channels_delete(struct json_object *body);
struct json_object *notifyd_routes_json(void);
struct json_object *notifyd_routes_update(struct json_object *body);
struct json_object *notifyd_routes_delete(struct json_object *body);
struct json_object *notifyd_triggers_json(struct json_object *body);
struct json_object *notifyd_preferences_get(struct json_object *body);
struct json_object *notifyd_preferences_update(struct json_object *body);
/*
 * Whether `username` has silenced deliveries that would reach them through
 * `channel_id`. Evaluated against the stored expiry at call time, so a timed
 * mute lapses on its own without a timer or a client clock.
 */
int notifyd_user_mute_active(const char *username, const char *channel_id);
int notifyd_channel_get(const char *id, struct notifyd_channel *out);
int notifyd_prune_if_needed(void);
struct json_object *notifyd_enqueue_event(struct json_object *body);
struct json_object *notifyd_enqueue_direct(struct json_object *body);
struct json_object *notifyd_outbox_list(struct json_object *body);
struct json_object *notifyd_outbox_get(struct json_object *body);
struct json_object *notifyd_outbox_retry(struct json_object *body);
int notifyd_delivery_record(const char *outbox_id, const char *channel_id,
                            int outcome, long http_status, const char *error,
                            int duration_ms, int suppressed_recipients);
int notifyd_mark_delivery_result(const struct notifyd_outbox_item *item,
                                 int outcome, long http_status, const char *error,
                                 int duration_ms, int suppressed_recipients);

struct json_object *notifyd_test_send(struct json_object *body);
struct json_object *notifyd_deliver_one(const char *id);
struct json_object *notifyd_deliver_due(struct json_object *body);
void notifyd_delivery_start(void);
void notifyd_delivery_stop(void);

int notifyd_ubus_start(void);
void notifyd_ubus_stop(void);

#endif

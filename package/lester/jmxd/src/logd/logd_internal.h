// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_LOGD_INTERNAL_H
#define DREAMINGWRT_LOGD_INTERNAL_H

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
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

#include <json-c/json.h>
#include <sqlite3.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include "../jmx_storage_guard.h"

#define LOGD_DB_PATH "/etc/dreamingwrt/log.db"
#define LOGD_CONFIG_DB_PATH "/etc/dreamingwrt/config.db"
#define LOGD_SCHEMA_VERSION 1
#define LOGD_MAX_TEXT 512
#define LOGD_DEFAULT_LIMIT 100
#define LOGD_MAX_LIMIT 1000
#define LOGD_COLLECT_TICK_MS 2000
#define LOGD_MAX_OPTIONS_JSON 2048
#define LOGD_MAX_LOG_LINE 768
#define LOGD_MAX_DETAIL_JSON 8192
#define LOGD_MAX_PORTS 96
#define LOGD_LOGREAD_FALLBACK_LINES 128
#define LOGD_DHCP_LEASE_PATH "/tmp/dhcp.leases"
#define LOGD_RUNTIME_DIR "/run/dreamingwrt"
#define LOGD_EXPORT_DIR LOGD_RUNTIME_DIR "/log_exports"
#define LOGD_MAX_EXPORT_LIMIT 50000
#define LOGD_MAX_DHCP_LEASES 512
#define LOGD_NOTIFYD_TIMEOUT_MS 500
#define LOGD_COOLDOWN_STATE_RETENTION_SEC (2 * 86400)
#define LOGD_COOLDOWN_STATE_MAX_ROWS 2048
#define LOGD_SYSLOG_QUEUE_MAX_LINE 2048
#define LOGD_SYSLOG_QUEUE_BATCH 8
#define LOGD_SYSLOG_MAX_PROFILES 16
#define LOGD_SYSLOG_QUEUE_MAX_ROWS 20000
#define LOGD_SYSLOG_QUEUE_SENT_RETENTION_SEC 86400
#define LOGD_SYSLOG_QUEUE_FAILED_RETENTION_SEC (7 * 86400)

struct logd_collector_runtime {
    const char *name;
    int64_t last_run;
    int64_t last_ok;
    uint64_t runs;
    uint64_t errors;
    char last_error[128];
};

struct logd_collector_config {
    int enabled;
    int interval_s;
    int cooldown_s;
    char options_json[LOGD_MAX_OPTIONS_JSON];
};

extern sqlite3 *g_logd_db;
extern sqlite3 *g_config_db;
extern struct ubus_context *g_logd_ubus;
extern struct blob_buf g_logd_blob;
extern uint64_t g_event_seq;
extern uint64_t g_logd_storage_suppressed;
extern int64_t g_logd_storage_last_suppressed_at;

int64_t logd_now_s(void);
const char *logd_json_str(struct json_object *o, const char *key, const char *def);
int64_t logd_json_i64(struct json_object *o, const char *key, int64_t def);
int logd_json_int(struct json_object *o, const char *key, int def);
int logd_json_bool(struct json_object *o, const char *key, int def);
struct json_object *logd_json_parse_or_object(const char *s);
struct json_object *logd_json_from_blob(struct blob_attr *msg);
struct json_object *logd_payload_or_self(struct json_object *body);
const char *logd_sqlite_text(sqlite3_stmt *st, int col, const char *def);

int logd_file_read_line(const char *path, char *out, size_t out_len);
int logd_file_read_int(const char *path, int def);
int logd_file_exists(const char *path);
void logd_runtime_note(struct logd_collector_runtime *rt, int ok, const char *err);
uint64_t logd_hash64(const char *s);
void logd_hash_hex(const char *s, char *out, size_t out_len);
int logd_text_ok(const char *s, size_t max_len);
int logd_token_ok(const char *s, size_t max_len);
const char *logd_severity(const char *s);
int logd_contains_ci(const char *s, const char *needle);
void logd_sanitize_line(char *s);
void logd_title_from_line(const char *line, char *out, size_t out_len);

sqlite3_stmt *logd_prepare(const char *sql);
sqlite3_stmt *logd_config_prepare(const char *sql);
int logd_db_init(void);
int logd_config_db_init(void);
void logd_db_close(void);
int logd_prune_if_needed(void);
int logd_collector_state_prune(void);
int logd_collector_state_get(const char *name, const char *key,
	                             char *out, size_t out_len, const char *def);
int logd_collector_state_set(const char *name, const char *key, const char *value);
int logd_collector_state_delete(const char *name, const char *key);
struct json_object *logd_status_json(void);
struct json_object *logd_settings_json(void);
struct json_object *logd_settings_update(struct json_object *body);
const char *logd_log_level_group(const char *category);
const char *logd_log_level(const char *level);
int logd_log_level_min_rank(const char *level);
int logd_log_level_for_group(const char *group, char *out, size_t out_len);
void logd_log_level_cache_invalidate(void);
struct json_object *logd_syslog_test(struct json_object *body);
int logd_syslog_enqueue_event(struct json_object *body);
int logd_syslog_process_queue(int limit);
struct json_object *logd_syslog_queue_status(struct json_object *body);
struct json_object *logd_syslog_queue_flush(struct json_object *body);
struct json_object *logd_syslog_queue_clear(struct json_object *body);
struct json_object *logd_syslog_cert_list(struct json_object *body);
struct json_object *logd_syslog_cert_upload(struct json_object *body);
struct json_object *logd_syslog_cert_delete(struct json_object *body);
struct json_object *logd_syslog_presets_json(struct json_object *body);

struct json_object *logd_add_event(struct json_object *body);
struct json_object *logd_list_events(struct json_object *body);
struct json_object *logd_clear_events(struct json_object *body);
struct json_object *logd_unifi_capabilities_json(void);
struct json_object *logd_unifi_search(struct json_object *body);
struct json_object *logd_unifi_get_by_ids(struct json_object *body);
struct json_object *logd_unifi_count(struct json_object *body);
struct json_object *logd_unifi_filter_data(struct json_object *body);
struct json_object *logd_unifi_export(struct json_object *body);
struct json_object *logd_unifi_mark_read(struct json_object *body);
struct json_object *logd_unifi_ack(struct json_object *body);
int logd_publish_event(const char *severity, const char *category, const char *event,
                       const char *source, const char *iface, const char *title,
                       const char *dedupe_key, struct json_object *detail);

struct json_object *logd_collectors_json(void);
struct json_object *logd_collectors_update(struct json_object *body);
struct json_object *logd_collect_now(struct json_object *body);
void logd_collectors_start(void);
void logd_collectors_stop(void);

int logd_ubus_start(void);
void logd_ubus_stop(void);

#endif

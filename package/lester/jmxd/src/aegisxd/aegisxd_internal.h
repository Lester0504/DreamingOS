// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_AEGISXD_INTERNAL_H
#define DREAMINGWRT_AEGISXD_INTERNAL_H

#include <errno.h>
#include <ctype.h>
#include <inttypes.h>
#include <signal.h>
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <curl/curl.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <sqlite3.h>
#include <zlib.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>

#define AEGISXD_CONFIG_DB_PATH "/etc/dreamingwrt/config.db"
#define AEGISXD_DB_PATH "/etc/dreamingwrt/aegis.db"
#define AEGISXD_RUNTIME_DIR "/run/dreamingwrt/aegis"
#define AEGISXD_WORK_DIR "/opt/dreamingwrt/aegis"
#define AEGISXD_FEED_DIR "/opt/dreamingwrt/aegis/feeds"
#define AEGISXD_LEGACY_FEED_DIR "/tmp/dreamingwrt-aegisxd/feeds"
#define AEGISXD_DNSMASQ_LOG_PATH "/var/run/dnsmasq/dreamingwrt-aegis.log"
#define AEGISXD_SURICATA_ACTIVE_PATH AEGISXD_RUNTIME_DIR "/suricata-active.json"
#define AEGISXD_SURICATA_EVE_PATH AEGISXD_WORK_DIR "/suricata/eve.json"
#define AEGISXD_SURICATA_LOG_DIR AEGISXD_WORK_DIR "/suricata"
#define AEGISXD_SURICATA_CONFIG_PATH AEGISXD_RUNTIME_DIR "/suricata.yaml"
#define AEGISXD_SURICATA_PID_PATH AEGISXD_RUNTIME_DIR "/suricata.pid"
#define AEGISXD_HONEYPOT_RUNTIME_PATH AEGISXD_RUNTIME_DIR "/honeypot-runtime.json"
#define AEGISXD_HONEYPOT_NFT_PATH AEGISXD_RUNTIME_DIR "/honeypot.nft"
#define AEGISXD_HONEYPOT_ACTIVE_PATH AEGISXD_RUNTIME_DIR "/honeypot-active.json"
#define AEGISXD_HONEYPOT_BINARY "/usr/bin/dreamingwrt-honeypotd"
#define AEGISXD_SCHEMA_VERSION 8
#define AEGISXD_MAX_PATH 512
#define AEGISXD_MAX_TEXT 1024
#define AEGISXD_MAX_FEED_BYTES (64U * 1024U * 1024U)

struct aegisxd_settings {
    int enabled;
    char mode[32];
    char source_level[32];
    char suricata_version[32];
    char default_action[32];
    int logging_enabled;
};

struct aegisxd_feed_manifest {
    const char *feed_id;
    const char *name;
    const char *kind;
    const char *url;
    const char *format;
    const char *category_hint;
    uint64_t max_bytes;
    long connect_timeout_sec;
    long timeout_sec;
};

extern sqlite3 *g_aegisxd_config_db;
extern sqlite3 *g_aegisxd_db;
extern struct ubus_context *g_aegisxd_ubus;
extern struct blob_buf g_aegisxd_blob;

int64_t aegisxd_now_s(void);
int aegisxd_mkdir_p(const char *path, mode_t mode);
void aegisxd_json_add_string(struct json_object *o, const char *key, const char *value);
const char *aegisxd_json_str(struct json_object *o, const char *key, const char *def);
int aegisxd_json_bool(struct json_object *o, const char *key, int def);
struct json_object *aegisxd_error(const char *code, const char *message);
struct json_object *aegisxd_safe_not_implemented(const char *op);
struct json_object *aegisxd_json_from_blob(struct blob_attr *msg);
struct json_object *aegisxd_payload_or_self(struct json_object *body);
const char *aegisxd_sqlite_text(sqlite3_stmt *st, int col, const char *def);

sqlite3_stmt *aegisxd_config_prepare(const char *sql);
sqlite3_stmt *aegisxd_prepare(const char *sql);
int aegisxd_db_init(void);
void aegisxd_db_close(void);
int aegisxd_settings_load(struct aegisxd_settings *out);
int aegisxd_seed_builtin_feeds(void);

struct json_object *aegisxd_status_json(void);
struct json_object *aegisxd_feeds_json(void);
struct json_object *aegisxd_feed_status_json(void);
int aegisxd_job_result_ok(struct json_object *result);
int aegisxd_job_running_count(void);
int aegisxd_job_record_start(const char *job_id, const char *op,
                             const char *feed_id, int dry_run);
void aegisxd_job_record_pid(const char *job_id, pid_t pid);
void aegisxd_job_record_finish(const char *job_id, struct json_object *result);
struct json_object *aegisxd_feed_jobs_json(int *running_out);
struct json_object *aegisxd_feed_update_start(struct json_object *body);
int aegisxd_feed_update_worker_main(const char *job_id, const char *feed_id, int dry_run);
struct json_object *aegisxd_feed_import_start(struct json_object *body);
int aegisxd_feed_import_worker_main(const char *job_id, const char *feed_id);
struct json_object *aegisxd_import_feed_id(const char *feed_id);
struct json_object *aegisxd_feed_import_status_json(void);
struct json_object *aegisxd_categories_json(void);
struct json_object *aegisxd_signature_categories_json(void);
struct json_object *aegisxd_runtime_json(void);
struct json_object *aegisxd_events_recent_json(void);
struct json_object *aegisxd_stats_json(void);
struct json_object *aegisxd_health_json(void);
struct json_object *aegisxd_compile_plan(struct json_object *body);
struct json_object *aegisxd_apply(struct json_object *body);
struct json_object *aegisxd_set_enabled(struct json_object *body);
struct json_object *aegisxd_set_mode(struct json_object *body);
struct json_object *aegisxd_set_profile(struct json_object *body);

struct json_object *aegisxd_content_policies_json(struct json_object *body);
struct json_object *aegisxd_content_policy_validate_json(struct json_object *body);
struct json_object *aegisxd_content_policy_set_json(struct json_object *body);
struct json_object *aegisxd_content_policy_delete_json(struct json_object *body);
struct json_object *aegisxd_domain_overrides_json(struct json_object *body);
struct json_object *aegisxd_domain_override_set_json(struct json_object *body);
struct json_object *aegisxd_domain_override_delete_json(struct json_object *body);
struct json_object *aegisxd_content_runtime_json(void);
void *aegisxd_content_filter_load(void);
void aegisxd_content_filter_free(void *filter);
int aegisxd_content_filter_domain_blocked(void *filter, const char *domain,
                                          const char *category, int reputation);
int aegisxd_content_filter_write_explicit_blocks(void *filter, FILE *fp);

struct json_object *aegisxd_ingest_suricata_eve(struct json_object *body);
struct json_object *aegisxd_honeypot_get_json(void);
struct json_object *aegisxd_honeypot_validate_json(struct json_object *body);
struct json_object *aegisxd_honeypot_set_json(struct json_object *body);
struct json_object *aegisxd_honeypot_delete_json(struct json_object *body);
struct json_object *aegisxd_honeypot_events_json(struct json_object *body);
struct json_object *aegisxd_honeypot_event_ingest(struct json_object *body);
struct json_object *aegisxd_honeypot_runtime_json(void);
int aegisxd_honeypot_binary_available(void);
int aegisxd_honeypot_active(void);
int aegisxd_honeypot_hit_count(void);
int aegisxd_honeypot_reconcile(void);

struct json_object *aegisxd_geo_get_json(void);
struct json_object *aegisxd_geo_apply_json(struct json_object *body);
struct json_object *aegisxd_geo_status_json(void);
struct json_object *aegisxd_signature_policies_json(struct json_object *body);
struct json_object *aegisxd_set_signature_policy_json(struct json_object *body);
struct json_object *aegisxd_suppress_signature_json(struct json_object *body);
struct json_object *aegisxd_unsuppress_signature_json(struct json_object *body);
struct json_object *aegisxd_signature_policy_counts_json(void);
int aegisxd_signature_policy_problem_count(void);
int aegisxd_signature_policy_effective_enabled_count(void);
int aegisxd_suricata_runtime_available(void);
int aegisxd_signature_policy_effective_rule_text(int gid, int sid, int rev,
                                                 int enabled_default,
                                                 const char *default_action,
                                                 const char *rule_text,
                                                 char *out, size_t out_len,
                                                 int *enabled_out,
                                                 const char **error_out);

void aegisxd_hit_producer_start(void);
void aegisxd_hit_producer_stop(void);
int aegisxd_dns_hit_producer_active(void);
struct json_object *aegisxd_dns_hit_producer_status_json(void);
int aegisxd_nft_hit_producer_active(void);
struct json_object *aegisxd_nft_hit_producer_status_json(void);
int aegisxd_suricata_hit_producer_active(void);
struct json_object *aegisxd_suricata_hit_producer_status_json(void);
int aegisxd_policy_hit_producer_active(void);
int aegisxd_policy_hit_producer_connected(void);
struct json_object *aegisxd_policy_hit_producer_status_json(void);

int aegisxd_ubus_start(void);
void aegisxd_ubus_stop(void);

#endif

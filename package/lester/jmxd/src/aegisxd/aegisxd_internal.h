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
#include <net/if.h>

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

#ifndef AEGISXD_CONFIG_DIR
#define AEGISXD_CONFIG_DIR "/etc/dreamingwrt"
#endif
#ifndef AEGISXD_CONFIG_DB_PATH
#define AEGISXD_CONFIG_DB_PATH AEGISXD_CONFIG_DIR "/config.db"
#endif
#ifndef AEGISXD_DB_PATH
#define AEGISXD_DB_PATH AEGISXD_CONFIG_DIR "/aegis.db"
#endif
#ifndef AEGISXD_CLIENT_DB_PATH
#define AEGISXD_CLIENT_DB_PATH AEGISXD_CONFIG_DIR "/dreamingwrt.db"
#endif
#ifndef AEGISXD_RUNTIME_DIR
#define AEGISXD_RUNTIME_DIR "/run/dreamingwrt/aegis"
#endif
#ifndef AEGISXD_WORK_DIR
#define AEGISXD_WORK_DIR "/opt/dreamingwrt/aegis"
#endif
#ifndef AEGISXD_PKI_DIR
#define AEGISXD_PKI_DIR AEGISXD_CONFIG_DIR "/aegis-pki"
#endif
#ifndef AEGISXD_FEED_DIR
#define AEGISXD_FEED_DIR AEGISXD_WORK_DIR "/feeds"
#endif
#ifndef AEGISXD_LEGACY_FEED_DIR
#define AEGISXD_LEGACY_FEED_DIR "/tmp/dreamingwrt-aegisxd/feeds"
#endif
#ifndef AEGISXD_DNSMASQ_LOG_PATH
#define AEGISXD_DNSMASQ_LOG_PATH "/var/run/dnsmasq/dreamingwrt-aegis.log"
#endif
/*
 * Scoped content policies live in their own table so a failed scoped apply can
 * be torn down without touching the reputation table in dreamingwrt_aegis.
 */
#ifndef AEGISXD_CONTENT_NFT_TABLE
#define AEGISXD_CONTENT_NFT_TABLE "dreamingwrt_aegis_content"
#endif
#define AEGISXD_CONTENT_NFT_PATH AEGISXD_RUNTIME_DIR "/content-scope.nft"
#define AEGISXD_SURICATA_ACTIVE_PATH AEGISXD_RUNTIME_DIR "/suricata-active.json"
#define AEGISXD_SURICATA_EVE_PATH AEGISXD_WORK_DIR "/suricata/eve.json"
#define AEGISXD_SURICATA_LOG_DIR AEGISXD_WORK_DIR "/suricata"
#define AEGISXD_SURICATA_CONFIG_PATH AEGISXD_RUNTIME_DIR "/suricata.yaml"
#define AEGISXD_SURICATA_PID_PATH AEGISXD_RUNTIME_DIR "/suricata.pid"
#define AEGISXD_SURICATA_NFQ_TABLE "dreamingwrt_aegis_ids"
#define AEGISXD_SURICATA_NFQ_PATH AEGISXD_RUNTIME_DIR "/suricata-nfqueue.nft"
#define AEGISXD_HONEYPOT_RUNTIME_PATH AEGISXD_RUNTIME_DIR "/honeypot-runtime.json"
#define AEGISXD_HONEYPOT_NFT_PATH AEGISXD_RUNTIME_DIR "/honeypot.nft"
#define AEGISXD_HONEYPOT_ACTIVE_PATH AEGISXD_RUNTIME_DIR "/honeypot-active.json"
#define AEGISXD_HONEYPOT_BINARY "/usr/bin/dreamingwrt-honeypotd"
#define AEGISXD_SCHEMA_VERSION 11
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
    char suricata_interface[IFNAMSIZ];
    int suricata_queue_num;
    int suricata_fail_open;
    /*
     * Traffic-log collection scope: "all" or "blocked". Filters security
     * events, not forwarded traffic. The three source flags decide whether a
     * class of event is logged at all and deliberately carry no scope of their
     * own; scope is one global choice over the combined set.
     */
    char traffic_log_scope[16];
    int traffic_log_gateway_dns;
    int traffic_log_aegisx_service;
    int traffic_log_device_admin;
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
int aegisxd_traffic_log_scope_valid(const char *scope);
/* NULL scope / negative flag means "unchanged"; -2 signals an invalid scope. */
int aegisxd_traffic_log_settings_save(const char *scope, int gateway_dns,
                                      int aegisx_service, int device_admin);
int aegisxd_seed_builtin_feeds(void);
int aegisxd_certificate_schema_init(void);

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
/* Traffic-log scope + source toggles; omitted fields stay unchanged. */
struct json_object *aegisxd_set_traffic_log(struct json_object *body);

struct json_object *aegisxd_certificate_status_json(void);
struct json_object *aegisxd_certificate_generate_json(struct json_object *body);
struct json_object *aegisxd_certificate_rotate_json(struct json_object *body);
struct json_object *aegisxd_certificate_revoke_json(struct json_object *body);
struct json_object *aegisxd_certificate_download_json(struct json_object *body);
struct json_object *aegisxd_certificate_distribution_downloaded_json(struct json_object *body);
struct json_object *aegisxd_certificate_distributions_json(struct json_object *body);
struct json_object *aegisxd_certificate_distribution_create_json(struct json_object *body);
struct json_object *aegisxd_certificate_distribution_get_json(struct json_object *body);

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
int aegisxd_content_filter_domain_explicitly_blocked(void *filter,
                                                      const char *domain);
int aegisxd_content_filter_mark_category_emitted(void *filter,
                                                  const char *domain);
int aegisxd_content_filter_write_explicit_blocks(void *filter, FILE *fp);
int aegisxd_content_filter_scoped_count(void *filter);
int aegisxd_content_filter_write_scoped_dnsmasq(void *filter, FILE *fp);
int aegisxd_content_filter_write_scoped_nft(void *filter, FILE *fp);
int aegisxd_content_revision_get(void);
int aegisxd_content_installed_dns_rule_match(const char *domain,
                                             char kind[32], char source_id[64],
                                             char matched_rule[254]);
int aegisxd_content_dns_provenance_ready(void);
struct json_object *aegisxd_pcdn_get_json(void);
struct json_object *aegisxd_pcdn_validate_json(struct json_object *body);
struct json_object *aegisxd_pcdn_set_json(struct json_object *body);
struct json_object *aegisxd_pcdn_sync_json(struct json_object *body);
struct json_object *aegisxd_pcdn_active_state_json(void);
int aegisxd_pcdn_sync_worker_main(const char *job_id);
int aegisxd_pcdn_write_dnsmasq(FILE *fp,
                               int (*allow_cb)(const char *domain, void *opaque),
                               void *opaque);
int aegisxd_pcdn_configured(void);
int aegisxd_pcdn_monitor_configured(void);
int aegisxd_pcdn_effective_rule_count(const char *path);
int aegisxd_pcdn_installed_domain_match(const char *domain,
                                        char artifact_sha256[65]);
int aegisxd_pcdn_installed_monitor_match(const char *domain,
                                         char matched_rule[254],
                                         char artifact_sha256[65]);
int aegisxd_pcdn_hit_attribution_ready(void);

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
struct json_object *aegisxd_geo_counters_json(void);
struct json_object *aegisxd_signature_policies_json(struct json_object *body);
struct json_object *aegisxd_set_signature_policy_json(struct json_object *body);
struct json_object *aegisxd_suppress_signature_json(struct json_object *body);
struct json_object *aegisxd_unsuppress_signature_json(struct json_object *body);
struct json_object *aegisxd_signature_policy_counts_json(void);
int aegisxd_signature_policy_problem_count(void);
int aegisxd_signature_policy_effective_enabled_count(void);
int aegisxd_suricata_runtime_available(void);
int aegisxd_suricata_nfqueue_runtime_active(void);
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

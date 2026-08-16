// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_FLOWD_INTERNAL_H
#define DREAMINGWRT_FLOWD_INTERNAL_H

#include <ctype.h>
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
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <curl/curl.h>
#include <json-c/json.h>
#include <sqlite3.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>

#define FLOWD_CONFIG_DB_PATH "/etc/dreamingwrt/config.db"
#define FLOWD_SCHEMA_VERSION 1
#define FLOWD_MAX_ID 96
#define FLOWD_MAX_TEXT 512
#define FLOWD_MAX_JSON 8192
#define FLOWD_DEFAULT_GEOIP_DIR "/etc/dreamingwrt/geoip"
#define FLOWD_DEFAULT_RUNTIME_DIR "/etc/dreamingwrt/geoip/runtime"
#define FLOWD_DEFAULT_MMDB "/etc/dreamingwrt/geoip/GeoLite2-Country.mmdb"
#define FLOWD_DEFAULT_GEOIP_SOURCE_ID "p3terx-geolite2-country"
#define FLOWD_P3TERX_COUNTRY_URL "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
#define FLOWD_MAX_IMPORT_BYTES (128U * 1024U * 1024U)

/* Scheduled GeoIP refresh.  GeoLite2 is rebuilt weekly upstream, so a weekly
 * default check is the useful cadence; anything under a day is refused. */
#define FLOWD_GEOIP_UPDATE_INTERVAL_DEFAULT_S 604800
#define FLOWD_GEOIP_UPDATE_INTERVAL_MIN_S 86400
#define FLOWD_GEOIP_UPDATE_INTERVAL_MAX_S 7776000
/* Exponential backoff on failure: 1h, 2h, 4h ... capped at 24h. */
#define FLOWD_GEOIP_UPDATE_BACKOFF_BASE_S 3600
#define FLOWD_GEOIP_UPDATE_BACKOFF_MAX_S 86400
/* Free space required beyond the download itself before a refresh is attempted. */
#define FLOWD_GEOIP_UPDATE_MIN_FREE_BYTES (16ULL * 1024ULL * 1024ULL)
#define FLOWD_DEFAULT_FLOW_DB_PATH "/etc/dreamingwrt/flow.db"

struct flowd_settings {
    int enabled;
    char geoip_dir[FLOWD_MAX_TEXT];
    char runtime_dir[FLOWD_MAX_TEXT];
    char apply_mode[32];
};

struct flowd_qoe_destination;

struct flowd_runtime_contract_input;

extern sqlite3 *g_flowd_config_db;
extern struct ubus_context *g_flowd_ubus;
extern struct blob_buf g_flowd_blob;
extern uint64_t g_flowd_seq;

int64_t flowd_now_s(void);
void flowd_make_id(const char *prefix, char *out, size_t out_len);
const char *flowd_json_str(struct json_object *o, const char *key, const char *def);
int flowd_json_int(struct json_object *o, const char *key, int def);
int flowd_json_bool(struct json_object *o, const char *key, int def);
struct json_object *flowd_json_parse_or_object(const char *s);
struct json_object *flowd_json_parse_or_array(const char *s);
struct json_object *flowd_json_from_blob(struct blob_attr *msg);
struct json_object *flowd_payload_or_self(struct json_object *body);
struct json_object *flowd_error(const char *code, const char *message);
const char *flowd_sqlite_text(sqlite3_stmt *st, int col, const char *def);
int flowd_text_ok(const char *s, size_t max_len);
int flowd_token_ok(const char *s, size_t max_len);
int flowd_port_expr_ok(const char *s);
int flowd_id_ok(const char *s);
int flowd_path_ok(const char *s);
int flowd_url_ok(const char *s);
int flowd_json_fits(struct json_object *o, size_t max_len);
int flowd_file_exists(const char *path);
int flowd_dir_exists(const char *path);
int flowd_mkdir_p(const char *path, mode_t mode);
const char *flowd_policy_direction(const char *s);
const char *flowd_policy_action(const char *s);
const char *flowd_policy_family(const char *s);
int flowd_countries_normalize(struct json_object *in, char *out, size_t out_len,
                              struct json_object **out_arr);

sqlite3_stmt *flowd_config_prepare(const char *sql);
int flowd_db_init(void);
void flowd_db_close(void);
int flowd_settings_load(struct flowd_settings *out);
struct json_object *flowd_status_json(void);
struct json_object *flowd_settings_json(void);
struct json_object *flowd_settings_update(struct json_object *body);
struct json_object *flowd_export_settings_json(void);
struct json_object *flowd_export_settings_update(struct json_object *body);
struct json_object *flowd_geoip_sources_json(void);
struct json_object *flowd_geoip_source_update(struct json_object *body);
struct json_object *flowd_geoip_source_delete(struct json_object *body);
struct json_object *flowd_geoip_import_status(struct json_object *body);
struct json_object *flowd_geoip_import(struct json_object *body);
int flowd_geoip_configured_mmdb_valid(void);
int flowd_geoip_auto_import_enabled(void);
int flowd_geoip_auto_import_once(void);
int64_t flowd_geoip_next_run_from(int64_t now, int interval_s,
                                  int window_start_h, int window_end_h);
int flowd_geoip_scheduled_update_due(void);
int flowd_geoip_scheduled_update_run(void);
struct json_object *flowd_geoip_update_check(struct json_object *body);
struct json_object *flowd_country_policies_json(void);
struct json_object *flowd_country_policy_update(struct json_object *body);
struct json_object *flowd_country_policy_delete(struct json_object *body);
struct json_object *flowd_country_sets_generate(struct json_object *body);
struct json_object *flowd_objects_json(struct json_object *body);
struct json_object *flowd_object_update(struct json_object *body);
struct json_object *flowd_object_delete(struct json_object *body);
struct json_object *flowd_custom_protocols_json(struct json_object *body);
struct json_object *flowd_custom_protocol_update(struct json_object *body);
struct json_object *flowd_custom_protocol_delete(struct json_object *body);
struct json_object *flowd_route_groups_json(struct json_object *body);
struct json_object *flowd_route_group_update(struct json_object *body);
struct json_object *flowd_route_group_delete(struct json_object *body);
struct json_object *flowd_wan_capacity_json(struct json_object *body);
struct json_object *flowd_wan_capacity_update(struct json_object *body);
struct json_object *flowd_wan_capacity_delete(struct json_object *body);
struct json_object *flowd_wan_health_json(struct json_object *body);
struct json_object *flowd_wan_health_update(struct json_object *body);
struct json_object *flowd_wan_health_delete(struct json_object *body);
struct json_object *flowd_split_rules_json(struct json_object *body);
struct json_object *flowd_split_rule_update(struct json_object *body);
struct json_object *flowd_split_rule_delete(struct json_object *body);
struct json_object *flowd_domain_rules_json(struct json_object *body);
struct json_object *flowd_domain_rule_update(struct json_object *body);
struct json_object *flowd_domain_rule_delete(struct json_object *body);
struct json_object *flowd_qos_settings_json(void);
struct json_object *flowd_qos_settings_update(struct json_object *body);
struct json_object *flowd_qos_classes_json(struct json_object *body);
struct json_object *flowd_qos_class_update(struct json_object *body);
struct json_object *flowd_qos_class_delete(struct json_object *body);
struct json_object *flowd_qos_rules_json(struct json_object *body);
struct json_object *flowd_qos_rule_update(struct json_object *body);
struct json_object *flowd_qos_rule_delete(struct json_object *body);
struct json_object *flowd_smart_qos_categories_json(struct json_object *body);
struct json_object *flowd_smart_qos_category_update(struct json_object *body);
struct json_object *flowd_smart_qos_category_delete(struct json_object *body);
struct json_object *flowd_quota_rules_json(struct json_object *body);
struct json_object *flowd_quota_rule_update(struct json_object *body);
struct json_object *flowd_quota_rule_delete(struct json_object *body);
struct json_object *flowd_conn_limit_rules_json(struct json_object *body);
struct json_object *flowd_conn_limit_rule_update(struct json_object *body);
struct json_object *flowd_conn_limit_rule_delete(struct json_object *body);
struct json_object *flowd_app_rules_json(struct json_object *body);
struct json_object *flowd_app_rule_update(struct json_object *body);
struct json_object *flowd_app_rule_delete(struct json_object *body);
struct json_object *flowd_runtime_json(struct json_object *body);
struct json_object *flowd_compile(struct json_object *body);
struct json_object *flowd_terminal_policy_compile(void);
int flowd_terminal_policy_executor_available(void);
int flowd_terminal_policy_lifecycle_scan(void);
struct json_object *flowd_terminal_policy_apply(const struct flowd_settings *settings);
struct json_object *flowd_terminal_policy_runtime(void);
int flowd_terminal_policy_reconcile(const struct flowd_settings *settings,
                                    char *reason, size_t reason_len);
int flowd_terminal_policy_tc_executor_available(void);
struct json_object *flowd_terminal_policy_tc_apply(const struct flowd_settings *settings);
struct json_object *flowd_terminal_policy_tc_runtime(void);
struct json_object *flowd_nft_revision_status(void);
struct json_object *flowd_nft_revision_apply(struct json_object *body);
struct json_object *flowd_apply_jobs_json(struct json_object *body);
struct json_object *flowd_tc_apply(const struct flowd_settings *settings);
void flowd_tc_runtime_contract_state(struct flowd_runtime_contract_input *input);
int flowd_tc_apply_executor_available(void);
int flowd_tc_runtime_json_add(sqlite3 *db, struct json_object *response,
                              struct json_object *tables, struct json_object *summary,
                              struct json_object *errors, int *ok, int limit);

int flowd_qoe_runtime_init(void);
int flowd_qoe_runtime_start(void);
void flowd_qoe_runtime_close(void);
int flowd_terminal_quota_runtime_start(void);
void flowd_terminal_quota_runtime_stop(void);
struct json_object *flowd_terminal_quota_runtime_status(void);
int flowd_qoe_destination_lookup(const char *ip,
                                 struct flowd_qoe_destination *destination);
struct json_object *flowd_qoe_status_json(void);

int flowd_ubus_start(void);
void flowd_ubus_stop(void);

#endif

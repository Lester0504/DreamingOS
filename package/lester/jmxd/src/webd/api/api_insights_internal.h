// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
/* Private contract between the legacy Insights core and its route module. */
#ifndef WEBD_API_INSIGHTS_INTERNAL_H
#define WEBD_API_INSIGHTS_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include <json-c/json.h>
#include <sqlite3.h>

#include "webd_http_req.h"
#include "../webd_mmdb.h"

#define WEBD_ACTIVITY_MATRIX_DEFAULT 80
#define WEBD_ACTIVITY_MATRIX_MAX     480

#define WEBD_INSIGHTS_FILTER_FIELDS_MAX 40
#define WEBD_INSIGHTS_FILTER_VALUES_MAX 16
#define WEBD_INSIGHTS_FILTER_VALUE_LEN 256

#define WEBD_INSIGHTS_PART_SUMMARY          (1u << 0)
#define WEBD_INSIGHTS_PART_TOP_APPS         (1u << 1)
#define WEBD_INSIGHTS_PART_TOP_DESTINATIONS (1u << 2)
#define WEBD_INSIGHTS_PART_RISK             (1u << 3)
#define WEBD_INSIGHTS_PART_ACTIVITY         (1u << 4)
#define WEBD_INSIGHTS_PART_ALL              (WEBD_INSIGHTS_PART_SUMMARY | \
                                             WEBD_INSIGHTS_PART_TOP_APPS | \
                                             WEBD_INSIGHTS_PART_TOP_DESTINATIONS | \
                                             WEBD_INSIGHTS_PART_RISK | \
                                             WEBD_INSIGHTS_PART_ACTIVITY)

struct webd_current_flows_diag {
    int attempts;
    int limit_requested;
    int limit_used;
    int limit_reduced;
    int too_large;
    int64_t response_bytes;
    int64_t response_limit_bytes;
    char error[64];
    char reason[96];
};

struct webd_insights_filter_entry {
    char field[64];
    char values[WEBD_INSIGHTS_FILTER_VALUES_MAX][WEBD_INSIGHTS_FILTER_VALUE_LEN];
    int count;
};

struct webd_insights_query {
    char period[32];
    char map_scope[32];
    char search[256];
    char risk[64];
    char action[64];
    char direction[64];
    char protocol[64];
    char mode[32];
    char dataset[32];
    int security_only;
    char source_mac[64];
    char source_ip[64];
    char destination_host[256];
    char destination_ip[64];
    char service[128];
    int64_t ts_from;
    int64_t ts_to;
    int page_number;
    int page_size;
    int top;
    int matrix_offset;
    int matrix_limit;
    struct webd_insights_filter_entry include_filters[WEBD_INSIGHTS_FILTER_FIELDS_MAX];
    struct webd_insights_filter_entry exclude_filters[WEBD_INSIGHTS_FILTER_FIELDS_MAX];
    int include_filter_count;
    int exclude_filter_count;
};

struct webd_insights_group {
    char key[256];
    char label[256];
    char mac[32];
    char ip[64];
    char app_proto[64];
    char service[128];
    char category[96];
    char family[64];
    char name_source[32];
    int app_id;
    int canonical_app_id;
    int count;
    int64_t last_ts;
    int64_t rx_bytes;
    int64_t tx_bytes;
    int risk_supported;
    int affected_count;
    int risk_unknown;
    int risk_low;
    int risk_suspicious;
    int risk_concerning;
    int risk_high;
    int action_allow;
    int action_block;
    int action_other;
};

struct webd_insights_risk_annotation {
    int supported;
    int matched;
    char risk[32];
    char level[32];
    char source[64];
    char category[96];
    char feed[128];
    char matched_domain[256];
    char reason[256];
    int severity;
    int confidence;
};

struct webd_insights_risk_ctx {
    sqlite3 *db;
    int db_present;
    int db_open;
    int rep_count;
    int category_count;
    char error[160];
};

struct webd_insights_aegis_stats {
    int schema_supported;
    int available;
    int total_all;
    int total;
    int blocks;
    int alerts;
    int dns_blocks;
    int last_event_at;
    int rows_scanned;
    int limited;
    int risk_unknown;
    int risk_low;
    int risk_suspicious;
    int risk_concerning;
    int risk_high;
    int action_allow;
    int action_block;
    int action_alert;
    int action_other;
    int policy_dns_filter;
    int policy_reputation_ip;
    int policy_ids_ips;
    int policy_route;
    int policy_other;
    int geo_external_event_candidates;
    int client_attributed;
    int client_unattributed;
    char reason[128];
    struct webd_insights_group policies[64];
    int policy_count;
    struct webd_insights_group destinations[64];
    int destination_count;
    struct webd_insights_group clients[64];
    int client_count;
};

struct webd_insights_core_ops {
    int (*db_open_runtime)(void);
    sqlite3_stmt *(*config_prepare)(const char *sql);
    int (*safe_token)(const char *s);
    int (*sqlite_table_exists)(sqlite3 *db, const char *table);
    int (*aegis_events_count_cached)(int *schema_present);
    int (*aegis_policy_type_counts_cached)(char *scope, size_t scope_len,
                                            struct json_object **breakdown_out,
                                            int *dns_filter_out,
                                            int *reputation_ip_out,
                                            int *ids_ips_out,
                                            int *policy_route_out,
                                            int *other_out);
    void (*current_flows_diag_publish)(struct json_object *,
                                       const struct webd_current_flows_diag *);
    const char *(*first_nonempty4)(const char *, const char *, const char *,
                                   const char *);
    void (*read_query)(const struct http_req *, struct json_object *,
                       struct webd_insights_query *);
    struct json_object *(*build_dataset)(const struct webd_insights_query *,
                                         int, int, int, int, unsigned int);
    struct json_object *(*fetch_current_flows_diag)(
        const char *, const char *, int, int, struct webd_current_flows_diag *);
    struct json_object *(*fetch_history_flows)(const struct webd_insights_query *);
    struct json_object *(*fetch_history_flows_limit)(
        const struct webd_insights_query *, int);
    struct json_object *(*fetch_audit_urls)(const struct webd_insights_query *, int);
    struct json_object *(*fetch_clients)(void);
    struct json_object *(*fetch_flow_app_summary)(
        const struct webd_insights_query *, int);
    struct json_object *(*geo_from_flows)(const struct webd_insights_query *, int *);
    struct json_object *(*capabilities)(void);
    struct json_object *(*ubus_data_timeout)(const char *, struct json_object *, int);
    void (*add_option)(struct json_object *, const char *, const char *,
                       const char *);
    void (*add_risk_options)(struct json_object *, struct webd_insights_risk_ctx *);
    void (*add_geo_region_options_for_ip)(struct json_object *,
                                          struct json_object *, const char *,
                                          const char *, webd_mmdb_t *,
                                          webd_mmdb_t *);
    void (*aegis_stats_load)(const struct webd_insights_query *,
                             struct webd_insights_aegis_stats *);
    struct json_object *(*aegis_stats_json)(struct webd_insights_aegis_stats *, int);
    struct json_object *(*aegis_policy_type_breakdown_json)(
        const struct webd_insights_aegis_stats *);
    const char *(*policy_scope_from_stats)(
        const struct webd_insights_aegis_stats *);
    void (*risk_ctx_init)(struct webd_insights_risk_ctx *);
    void (*risk_ctx_close)(struct webd_insights_risk_ctx *);
    void (*annotate_flow_data)(struct json_object *, struct webd_insights_risk_ctx *);
    int (*risk_available)(const struct webd_insights_risk_ctx *);
    webd_mmdb_t *(*cached_city_mmdb)(void);
    webd_mmdb_t *(*cached_country_mmdb)(void);
    void (*filter_clear_selection)(struct webd_insights_query *);
    struct json_object *(*find_client)(struct json_object *, const char *);
    const char *(*client_name)(struct json_object *, const char *);
    int (*app_lookup)(int, char *, size_t, char *, size_t, char *, size_t,
                      int *);
    int (*seen_string)(struct json_object *, const char *, const char *);
};

const struct webd_insights_core_ops *webd_insights_core_ops_get(void);
int webd_insights_app_lookup_ex(int app_id,
                                 char *name, size_t name_len,
                                 char *category, size_t category_len,
                                 char *family, size_t family_len,
                                 char *icon_url, size_t icon_url_len,
                                 int *canonical_app_id);

/* Shared by the legacy Insights aggregation path and the migrated routes. */
int webd_insights_local_location_apply(struct json_object *local,
                                       const char *wan_id,
                                       const char *public_ip);
struct json_object *webd_insights_local_locations_json(void);
int webd_insights_local_location_update(struct json_object *body);
struct json_object *webd_insights_map_config_json(void);
struct json_object *webd_insights_cybersecure_status_response(int *http_status);

/* Reused by the existing WebSocket read model in jmx_app_api.c. */
struct json_object *webd_insights_activity_rate_response(
    const struct http_req *req, struct json_object *body, int *http_status);
struct json_object *webd_insights_activity_traffic_response(
    const struct http_req *req, struct json_object *body, int *http_status);


/* Phase 6M: JMX feature-status catalog (moved from jmx_app_api.c).
 * main declares `struct webd_jmx_features kfeat;` by value, so the type
 * must be visible here. */
#define WEBD_JMX_FEATURE_MAX 64

struct webd_jmx_feature_entry {
    char name[40];
    char state[16];
    char source[64];
};

struct webd_jmx_features {
    int node_present;          /* the proc node opened successfully */
    int schema_version;
    int count;
    char module_version[32];
    char reason[96];           /* why the node is unusable, when it is */
    struct webd_jmx_feature_entry items[WEBD_JMX_FEATURE_MAX];
};

/* Phase 6M: insights-core entry points reached directly by main and the
 * WebSocket read model (the vtable covers the api_insights.c dispatch). */
extern const char *webd_insights_filter_fields[39];
void webd_jmx_features_read(struct webd_jmx_features *fs);
void webd_insights_read_query(const struct http_req *req, struct json_object *body,
                              struct webd_insights_query *q);
struct json_object *webd_insights_build_dataset(const struct webd_insights_query *q,
                                                int fetch_limit,
                                                int include_items,
                                                int page_number,
                                                int page_size,
                                                unsigned int parts);
struct json_object *webd_insights_geo_from_flows(const struct webd_insights_query *q,
                                                 int *http_status);
int webd_insights_ip_is_private_or_local(const char *ip);
int webd_insights_ip_is_router_address(const char *ip);

#endif /* WEBD_API_INSIGHTS_INTERNAL_H */

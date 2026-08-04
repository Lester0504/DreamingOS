// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __JMX_DB_H__
#define __JMX_DB_H__

#include <json-c/json.h>
#include <stddef.h>
#include <stdint.h>
#include <sqlite3.h>

#define JMX_DB_PATH_DEFAULT "/etc/dreamingwrt/dreamingwrt.db"
#define JMX_DB_DIR_DEFAULT  "/etc/dreamingwrt"

sqlite3 *jmx_db_handle(void);
int jmx_db_init(void);
void jmx_db_close(void);
int db_try_import_fingerprint_catalog(void);
void db_startup_sig_match(void);
int jmx_db_sync_clients_from_memory(void);
int jmx_db_observe_signal(const char *mac, const char *source, const char *key, const char *value, int confidence, const char *raw_json);
int jmx_db_observe_signal_by_ip(const char *ip, const char *source, const char *key, const char *value, int confidence, const char *raw_json);
int jmx_db_observe_network_state(const char *mac, const char *ip, const char *iface,
                                 const char *network, const char *parent_mac,
                                 const char *parent_id, const char *port,
                                 const char *link_type, const char *link_speed,
                                 int online);

struct json_object *jmx_db_api_clients_observe(struct json_object *req);
struct json_object *jmx_db_api_client_override(struct json_object *req);
struct json_object *jmx_db_api_client_get(struct json_object *req);
struct json_object *jmx_db_api_clients_list(struct json_object *req);
struct json_object *jmx_db_api_client_identity(struct json_object *req);

/* ── Schema v2: line_load / audit / traffic buckets ── */

int jmx_db_upsert_interface(const char *name, const char *kind,
                            const char *device, const char *proto,
                            const char *carrier);

int jmx_db_write_interface_state(const char *name, int online,
                                 unsigned long long rx_bytes,
                                 unsigned long long tx_bytes,
                                 int64_t rx_rate, int64_t tx_rate,
                                 int latency_ms, int loss_pct);
int jmx_db_update_daily_usage_counter(const char *wan_id,
                                      unsigned long long rx_bytes,
                                      unsigned long long tx_bytes,
                                      int online);

/* Lifetime per-WAN byte totals that survive PPPoE interface rebuilds and 32-bit
 * counter wrap.  rx_bytes/tx_bytes are monotonic; reset_count/last_reset_ts let
 * a caller state honestly whether the underlying counter ever restarted. */
struct jmx_wan_lifetime_usage {
    int64_t first_seen_ts;
    int64_t last_ts;
    int64_t rx_bytes;
    int64_t tx_bytes;
    int reset_count;
    int64_t last_reset_ts;
    int sample_count;
};

int jmx_db_update_wan_lifetime_usage(const char *wan_id,
                                     unsigned long long rx_bytes,
                                     unsigned long long tx_bytes,
                                     int online);
int jmx_db_read_wan_lifetime_usage(const char *wan_id,
                                   struct jmx_wan_lifetime_usage *out);
/* Single place that publishes a WAN's cumulative byte counters, so no response
 * builder can reintroduce the raw-counter zeroing on PPPoE reconnect. */
void jmx_db_add_wan_cumulative_bytes(struct json_object *out, const char *wan_id,
                                     int64_t device_rx_bytes,
                                     int64_t device_tx_bytes);

int jmx_db_write_wan_health(const char *name, int latency_ms, int loss_pct);
/*
 * Group many small related writes into one transaction. Nesting-safe: only the
 * outermost begin/end pair issues BEGIN/COMMIT. Pass commit=0 to roll back.
 * Callers must pair these on every exit path.
 */
int jmx_db_write_batch_begin(void);
int jmx_db_write_batch_end(int commit);

/* Client liveness evidence, gathered by the caller from the DB row and the
 * runtime client node. Kept separate from the decision so the ghost-client
 * rules can be tested directly instead of through a SQLite row. */
struct jmx_db_client_evidence {
    int db_online;                 /* clients.online as stored */
    int runtime_online;            /* runtime node claims online */
    int64_t tx_rate;
    int64_t rx_rate;
    int connections;
    int64_t sample_age_ms;         /* <0 when unknown */
    int64_t last_seen_age;         /* seconds, <0 when unknown */
    int bridge_fdb_present;        /* 1 present, 0 absent, -1 unreadable */
    char neigh_state[32];          /* legacy shared field */
    char neigh_state_v4[32];
    char neigh_state_v6[32];
    const char *runtime_online_source;
};

struct jmx_db_client_verdict {
    int online;
    int sample_valid;
    int neigh_failed;
    int neigh_reachable;
    int has_active_evidence;
    int64_t tx_rate;               /* zeroed when the sample is stale */
    int64_t rx_rate;
    int connections;
    const char *offline_reason;    /* NULL when no specific reason applies */
    const char *online_source;
    const char *zero_reason;
};

void jmx_db_client_online_verdict(const struct jmx_db_client_evidence *ev,
                                  struct jmx_db_client_verdict *out);

int jmx_db_write_traffic_bucket(int64_t bucket_ts, int bucket_sec,
                                const char *iface_name,
                                unsigned long long rx_bytes,
                                unsigned long long tx_bytes);

int jmx_db_flush_audit_urls(int64_t now_ts, int max_rows);
int jmx_db_flush_audit_apps(int64_t now_ts, int max_rows);
int jmx_db_write_audit_stats(int64_t now_ts, uint64_t total, uint64_t dropped,
                             int url_count, int app_count);

int jmx_db_prune_audit(int64_t now_ts, int64_t max_age_sec);
int jmx_db_prune_traffic_buckets(int64_t now_ts, int64_t max_age_sec);
int jmx_db_prune_interface_state(int64_t now_ts, int64_t max_age_sec);
int jmx_db_prune_wan_health(int64_t now_ts, int64_t max_age_sec);
int jmx_db_prune_and_vacuum(void);

struct json_object *jmx_db_api_audit_urls(struct json_object *req);
struct json_object *jmx_db_api_audit_apps(struct json_object *req);
struct json_object *jmx_db_api_audit_status(struct json_object *req);
struct json_object *jmx_db_api_line_load(struct json_object *req);


/* line_health: WAN profile / session / health bucket */
void jmx_db_load_health_config(void);
void jmx_db_load_profiles_from_db(void);
int  jmx_db_upsert_wan_profile(const char *ifname, const char *display_name,
                               const char *note, const char *carrier,
                               const char *access_mode,
                               int configured_up_rate, int configured_down_rate);
void jmx_db_update_wan_session(const char *wan_id, const char *ifname,
                                const char *ip, const char *gateway,
                                const char *access_mode, int online);
int64_t jmx_db_wan_session_uptime(const char *wan_id, int64_t now_ts);
int64_t jmx_db_wan_session_started_at(const char *wan_id);
void jmx_db_add_wan_session_contract(struct json_object *obj,
                                     const char *wan_id,
                                     int64_t now_ts);
void jmx_db_add_wan_loss_contract(struct json_object *obj,
                                  const char *wan_id,
                                  int64_t now_ts);
void jmx_db_update_wan_health_bucket(const char *wan_id, const char *ifname,
                                      int latency_ms, int loss_up_pct,
                                      int loss_down_pct, int64_t rx_rate,
                                      int64_t tx_rate, int online);
int  jmx_db_flush_health_buckets(void);
struct json_object *jmx_db_api_line_health(struct json_object *req);
struct json_object *jmx_db_api_ipv6_load(struct json_object *req);
struct json_object *jmx_db_api_vpn_status(struct json_object *req);
struct json_object *jmx_db_api_client_detail(struct json_object *req);
struct json_object *jmx_db_api_system_health(struct json_object *req);
struct json_object *jmx_db_api_lan_config(struct json_object *req);

/* dashboard_activity_sample: persistent activity sampling */
void jmx_db_write_activity_sample(const char *wan_id, int64_t up_rate, int64_t down_rate,
                                   int connections, double latency_avg,
                                   double latency_min, double latency_max);
int jmx_db_prune_activity_samples(int64_t max_age_sec);
int jmx_db_monthly_usage_estimate(const char *wan_id, int allow_global_fallback,
                                  int64_t *up_bytes, int64_t *down_bytes,
                                  int64_t *total_bytes, int *sample_count,
                                  int64_t *period_start, int64_t *period_end,
                                  char *source, size_t source_len);
int jmx_db_today_usage_estimate(const char *wan_id, int allow_global_fallback,
                                int64_t *up_bytes, int64_t *down_bytes,
                                int64_t *total_bytes, int *sample_count,
                                int64_t *period_start, int64_t *period_end,
                                char *source, size_t source_len);
struct json_object *jmx_db_api_activity(struct json_object *req);

/* system_health_sample: persistent CPU/memory/disk/connection load sampling */
void jmx_db_write_system_health_sample(double cpu_percent, double mem_percent,
                                       double disk_percent, int connections,
                                       int forward_pps, int client_num,
                                       int64_t rx_packets_delta,
                                       int64_t tx_packets_delta,
                                       int counter_reset);
int jmx_db_prune_system_health_samples(int64_t max_age_sec);
struct json_object *jmx_db_api_system_health_history(struct json_object *req);

#endif

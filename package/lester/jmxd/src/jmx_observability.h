/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef JMX_OBSERVABILITY_H
#define JMX_OBSERVABILITY_H

#include <stdint.h>
#include <sqlite3.h>
#include <json-c/json.h>

#define JMX_OBS_SCHEMA_VERSION 1
#define JMX_OBS_SCORING_PROFILE "dwrt-port-anomaly-v1"
#define JMX_OBS_RETENTION_PROFILE "dwrt-observability-v1"

struct jmx_obs_retention_profile {
    char name[64];
    int version;
    int64_t age_ms;
    int row_cap;
    int64_t byte_cap;
    int configured;
};

struct jmx_obs_event {
    /* Optional externally assigned id used when a legacy projection already
     * owns the canonical event identity (for example topology_events). */
    const char *event_id;
    const char *event_type;
    const char *category;
    const char *state;
    const char *severity;
    const char *confidence;
    int64_t observed_at;
    int64_t first_seen;
    int64_t last_seen;
    int64_t duration_ms;
    int count;
    const char *source;
    const char *site_id;
    const char *device_id;
    const char *port_id;
    const char *client_id;
    const char *radio_id;
    const char *correlation_id;
    const char *before_digest;
    const char *after_digest;
    struct json_object *evidence;
    int display_suppressed;
    const char *retention_class;
    const char *detector_revision;
};

/* Builds the immutable event envelope and derives a deterministic event_id. */
struct json_object *jmx_obs_event_json(const struct jmx_obs_event *event);

/* Creates/updates the durable event table. Duplicate event_id updates only the
 * observation counters and timestamps; the original payload remains intact. */
int jmx_obs_event_store_init(sqlite3 *db);
int jmx_obs_event_append(sqlite3 *db, const struct jmx_obs_event *event,
                         int *coalesced);
void jmx_obs_retention_profile_default(struct jmx_obs_retention_profile *profile);
int jmx_obs_retention_profile_load(const char *config_db_path,
                                   struct jmx_obs_retention_profile *profile);
int jmx_obs_event_prune(sqlite3 *db, int64_t now_ms,
                        const struct jmx_obs_retention_profile *profile);
struct json_object *jmx_obs_storage_status(sqlite3 *db, const char *db_path,
                         const struct jmx_obs_retention_profile *profile);
struct json_object *jmx_obs_event_timeline(sqlite3 *db, int64_t start_ms,
                                           int64_t end_ms,
                                           const char *entity_type,
                                           const char *entity_id,
                         const struct jmx_obs_retention_profile *profile);
#define JMX_OBS_TIMELINE_PAGE_DEFAULT 64
#define JMX_OBS_TIMELINE_PAGE_MAX 128
/* Opt-in SQL keyset pagination; the legacy timeline ABI remains unbounded.
 * limit=0 selects the default, larger limits are capped. A NULL cursor id
 * selects the first page. Reuse the returned start/end for later pages and
 * pass next_cursor.first_seen/event_id unchanged. Client MAC matching is
 * case-insensitive; other entity identifiers retain exact matching. */
struct json_object *jmx_obs_event_timeline_page(sqlite3 *db, int64_t start_ms,
                         int64_t end_ms, const char *entity_type,
                         const char *entity_id,
                         const struct jmx_obs_retention_profile *profile,
                         int limit, int64_t cursor_first_seen,
                         const char *cursor_event_id);
int jmx_obs_event_append_json(sqlite3 *db, struct json_object *payload,
                               int *coalesced);
int jmx_obs_online_event_append(sqlite3 *db, int64_t observed_at,
                                const char *legacy_event_type,
                                const char *mac, const char *ip,
                                const char *hostname, const char *ifname,
                                const char *network, const char *vlan,
                                const char *connection, const char *ap_id,
                                int signal_dbm, int lease_time,
                                const char *source, int duration);

enum jmx_obs_category {
    JMX_OBS_CABLE_POWER = 0,
    JMX_OBS_LOOP_BROADCAST_FLOOD,
    JMX_OBS_MULTICAST_DISCOVERY,
    JMX_OBS_TRAFFIC_PATH_HEALTH,
    JMX_OBS_CATEGORY_COUNT
};

struct jmx_obs_detector {
    const char *event_code;
    enum jmx_obs_category category;
    double weight;
    double severity_factor;
    double recurrence_factor;
    int64_t first_seen;
    int64_t last_seen;
    int count;
    int64_t duration_ms;
    struct json_object *evidence;
};

struct jmx_obs_port_input {
    const char *device_id;
    const char *port_id;
    int identity_stable;
    int producer_complete;
    const char *unsupported_reason;
    int64_t window_start;
    int64_t window_end;
    const char *sample_source;
    const struct jmx_obs_detector *detectors;
    size_t detector_count;
};

/* Deterministic, explainable v1 scorer. Missing identity/producer data is
 * reported as unsupported/unknown and never converted to a healthy zero. */
struct json_object *jmx_obs_port_anomaly_score(const struct jmx_obs_port_input *input);

/* One raw sysfs reading for a single physical port at a point in time.
 * Only fields backed by /sys/class/net/<if>/statistics + speed/carrier are
 * carried; counters the hardware does not expose are absent by construction
 * and never synthesised as zero. Cumulative counters use -1 to mean the
 * kernel did not report them for this reading. */
struct jmx_obs_port_reading {
    const char *port_key;      /* churn-stable identity, required */
    const char *ifname;        /* kernel interface name */
    const char *phys_port_id;  /* /sys phys_port_id, "" when unavailable */
    int64_t rx_errors;         /* statistics/rx_errors, -1 if unavailable */
    int64_t tx_errors;         /* statistics/tx_errors, -1 if unavailable */
    int64_t rx_dropped;        /* statistics/rx_dropped, -1 if unavailable */
    int64_t tx_dropped;        /* statistics/tx_dropped, -1 if unavailable */
    int64_t rx_packets;        /* statistics/rx_packets, -1 if unavailable */
    int64_t tx_packets;        /* statistics/tx_packets, -1 if unavailable */
    int64_t rx_multicast;      /* statistics/multicast (rx only), -1 if n/a */
    int speed_mbps;            /* link speed, <=0 when unknown/not reported */
    int carrier;               /* 1 up, 0 down, -1 unknown */
};

/* Self-initialising per-port sample store. Follows the structured_events
 * pattern: CREATE TABLE IF NOT EXISTS + indexes, WAL only when autocommit. */
int jmx_obs_port_sample_store_init(sqlite3 *db);

/* Appends one reading, then prunes rows older than 24h and beyond the per-port
 * row cap. Self-initialises the schema. Returns 0 on success, -1 on failure. */
int jmx_obs_port_sample_append(sqlite3 *db,
                               const struct jmx_obs_port_reading *reading,
                               int64_t now_ms);

/* Loads the recent samples for the port matching device_id/port_id, computes
 * deltas over the scoring window, builds detectors for the sysfs-backed
 * categories only, drives jmx_obs_port_anomaly_score, marks the unsupported
 * families, and bridges DEGRADED/CRITICAL categories into structured_events.
 * Fails closed to UNKNOWN when identity is not stable or fewer than two
 * samples exist. Never fabricates a healthy zero for an unsupported family. */
struct json_object *jmx_obs_port_anomaly_producer_score(sqlite3 *db,
                               const char *device_id, const char *port_id,
                               int64_t now_ms);

#endif

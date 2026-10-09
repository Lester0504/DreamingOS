#ifndef JMX_KERNEL_RUNTIME_H
#define JMX_KERNEL_RUNTIME_H

#include <stdint.h>

/*
 * Single read-only snapshot of the jmx kernel module's observability nodes
 * under /proc/dreamingwrt/jmx.
 *
 * One snapshot per API request: every consumer projects from the same struct so
 * a reply cannot mix counters sampled seconds apart, and so no endpoint has to
 * grow its own fopen/sscanf/fallback ladder. Nothing here writes to the kernel.
 *
 * Missing or unparseable nodes are reported as unavailable with a reason. A
 * counter of 0 always means the kernel said 0; it never means "not read".
 */

#define JMX_KRT_MAX_WANS 8
#define JMX_KRT_MAX_CATEGORIES 32
#define JMX_KRT_MAX_POOLS 8
#define JMX_KRT_MAX_CACHES 8
#define JMX_KRT_MAX_RULES 32
#define JMX_KRT_REASON_LEN 96

/*
 * How the kernel's active_conn column should be read.
 *
 * The module increments it when a flow first binds to a WAN in
 * jmx_route_select_wan_internal(acquire=true) and decrements on the conntrack
 * IPCT_DESTROY event, so it counts route-bound flows, not the live conntrack
 * table. Flows that never obtained a lifecycle extension are never counted, and
 * a missed DESTROY leaves the gauge high until the module reloads.
 *
 * ROUTE_BOUND is therefore the strongest claim this code may make without live
 * increment/decrement verification. LIVE_CONNTRACK exists for a future proof and
 * is not emitted today. UNKNOWN is used whenever the totals look implausible.
 */
typedef enum {
    JMX_KRT_SEMANTICS_UNKNOWN = 0,
    JMX_KRT_SEMANTICS_ROUTE_BOUND,
    JMX_KRT_SEMANTICS_LIVE_CONNTRACK
} jmx_krt_semantics_t;

typedef struct {
    char name[32];
    int64_t active_conn;
    int64_t tx_packets;
    int64_t rx_packets;
    int64_t tx_bytes;
    int64_t rx_bytes;
    int valid;
} jmx_krt_category_t;

typedef struct {
    char id[32];              /* proc directory name, e.g. "wan1" */
    char if_stats_name[32];   /* name column in if_stats, e.g. "wan" */
    int index;                /* wan column in if_stats, 1-based */

    int if_stats_valid;
    int64_t active_conn;
    int64_t tx_packets;
    int64_t rx_packets;
    int64_t tx_bytes;
    int64_t rx_bytes;

    int proto_valid;
    int category_count;
    jmx_krt_category_t categories[JMX_KRT_MAX_CATEGORIES];
    jmx_krt_category_t total;    /* the Total row of proto_stats */
    char proto_path[288];        /* root + "/wanN/proto_stats" */
    char proto_reason[JMX_KRT_REASON_LEN];
} jmx_krt_wan_t;

typedef struct {
    char name[32];
    int64_t capacity;         /* -1 means the node reported "unbounded" */
    int64_t buckets;
    int64_t locks;
    int64_t count;
    int occupancy_valid;
    int64_t occupancy;
} jmx_krt_cache_entry_t;

typedef struct {
    int valid;
    char reason[JMX_KRT_REASON_LEN];
    int entry_count;
    jmx_krt_cache_entry_t entries[JMX_KRT_MAX_CACHES];
    int64_t hit_conn_cached;
    int64_t hit_feature;
    int64_t hit_v2_ac;
    int64_t hit_v3_ac;
    int64_t hit_total;
    int64_t lookup;
    int64_t miss;
    int invariant_valid;
    int invariant_ok;
    int64_t invariant_delta;
    int64_t v3_shadow_hit;
    int64_t v3_budget_exhausted;
} jmx_krt_cache_t;

typedef struct {
    char name[32];
    int64_t alloc;
    int64_t freed;
    int64_t live;
    int64_t objsize;
    int64_t allocfail;
} jmx_krt_pool_t;

typedef struct {
    int valid;
    char reason[JMX_KRT_REASON_LEN];
    int pool_count;
    jmx_krt_pool_t pools[JMX_KRT_MAX_POOLS];
} jmx_krt_memory_t;

typedef struct {
    int valid;
    char reason[JMX_KRT_REASON_LEN];
    int64_t retire_requested;
    int64_t retire_completed;
    int64_t retire_in_flight;
    char state[16];
} jmx_krt_rcu_t;

typedef struct {
    int64_t rule_id;
    int64_t appid;
    int64_t priority;
    int64_t match_cnt;
} jmx_krt_rule_t;

typedef struct {
    int valid;
    char reason[JMX_KRT_REASON_LEN];
    int generation_valid;
    int64_t generation;
    int rule_total_valid;
    int64_t rule_total;         /* rules the header claims exist */
    int rule_count;             /* rows actually captured below */
    jmx_krt_rule_t rules[JMX_KRT_MAX_RULES];
    int64_t match_cnt_total;
} jmx_krt_rules_t;

typedef struct {
    int available;              /* at least one node parsed */
    int degraded;               /* something expected was missing */
    char reason[JMX_KRT_REASON_LEN];
    int64_t observed_at;        /* one wall-clock stamp for the whole snapshot */

    int proc_root_present;

    int if_stats_valid;
    char if_stats_reason[JMX_KRT_REASON_LEN];

    int wan_count;
    jmx_krt_wan_t wans[JMX_KRT_MAX_WANS];

    int global_proto_valid;
    char global_proto_reason[JMX_KRT_REASON_LEN];
    int global_category_count;
    jmx_krt_category_t global_categories[JMX_KRT_MAX_CATEGORIES];
    jmx_krt_category_t global_total;

    jmx_krt_cache_t cache;
    jmx_krt_memory_t memory;
    jmx_krt_rcu_t rcu;
    jmx_krt_rules_t rules;

    jmx_krt_semantics_t active_conn_semantics;
    int active_conn_stale_possible;
    int64_t active_conn_total;
} jmx_krt_snapshot_t;

/*
 * Reads the snapshot. Returns 0 when at least one node was parsed, -1 when the
 * whole tree is unreadable; `snap` is populated with reasons either way.
 *
 * `conntrack_total` is the global /proc/net/nf_conntrack count when the caller
 * already has it, or a negative value when it does not. It is used only to
 * sanity-check the active_conn semantics claim, never to alter a counter.
 */
int jmx_krt_read(jmx_krt_snapshot_t *snap, int64_t conntrack_total);

/* Per-WAN lookup by proc id ("wan1") or if_stats name ("wan"). NULL if absent. */
const jmx_krt_wan_t *jmx_krt_find_wan(const jmx_krt_snapshot_t *snap,
                                      const char *wan_id);

/* Stable strings for the API contract. Never NULL. */
const char *jmx_krt_semantics_str(jmx_krt_semantics_t semantics);
const char *jmx_krt_if_stats_source(void);

/*
 * Test seam: overrides the /proc/dreamingwrt/jmx root for the contract fixture.
 * Production never calls this, so there is no env-controlled read surface.
 */
void jmx_krt_set_root_for_test(const char *root);

#endif /* JMX_KERNEL_RUNTIME_H */

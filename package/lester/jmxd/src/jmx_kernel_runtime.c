/*
 * Read-only reader for the jmx kernel module's /proc/dreamingwrt/jmx nodes.
 *
 * Shared by dreamingwrt-core (line_load projection) and dreamingwrt-webd
 * (kernel-runtime API) so both see identical numbers from one sampling pass.
 *
 * Parsing rules that the node formats force on us:
 *   - if_stats names the first WAN "wan" while its proc directory is "wan1", so
 *     the directory is derived from the numeric column, not from the name.
 *   - "unbounded" appears where cache capacity would be a number, and "n/a"
 *     where occupancy would be, so both need a non-numeric branch.
 *   - counters are unsigned in the kernel and can legitimately be large; they
 *     are parsed as int64 and a failed parse marks the row invalid instead of
 *     silently producing 0.
 */

#include "jmx_kernel_runtime.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define JMX_KRT_PROC_ROOT "/proc/dreamingwrt/jmx"

static char g_krt_root_override[192];

void jmx_krt_set_root_for_test(const char *root)
{
    if (!root || !root[0]) {
        g_krt_root_override[0] = '\0';
        return;
    }
    snprintf(g_krt_root_override, sizeof(g_krt_root_override), "%s", root);
}

static const char *jmx_krt_root(void)
{
    return g_krt_root_override[0] ? g_krt_root_override : JMX_KRT_PROC_ROOT;
}

const char *jmx_krt_if_stats_source(void)
{
    return "jmx_proc_if_stats";
}

const char *jmx_krt_semantics_str(jmx_krt_semantics_t semantics)
{
    switch (semantics) {
    case JMX_KRT_SEMANTICS_ROUTE_BOUND:
        return "jmx_route_bound_flows_with_destroy_accounting";
    case JMX_KRT_SEMANTICS_LIVE_CONNTRACK:
        return "live_conntrack_lifecycle";
    case JMX_KRT_SEMANTICS_UNKNOWN:
    default:
        return "unknown";
    }
}

static void jmx_krt_copy(char *dst, size_t len, const char *src)
{
    if (!dst || len == 0)
        return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    snprintf(dst, len, "%s", src);
}

static FILE *jmx_krt_open(const char *relative)
{
    char path[288];

    if (snprintf(path, sizeof(path), "%s/%s", jmx_krt_root(), relative) >= (int)sizeof(path))
        return NULL;
    return fopen(path, "r");
}

static int jmx_krt_is_comment(const char *line)
{
    while (*line && isspace((unsigned char)*line))
        line++;
    return (*line == '#' || *line == '\0');
}

/* Parses a whitespace-delimited int64 token. Returns 0 on success. */
static int jmx_krt_parse_i64(const char *token, int64_t *out)
{
    char *end = NULL;
    long long value;

    if (!token || !token[0] || !out)
        return -1;
    value = strtoll(token, &end, 10);
    if (end == token)
        return -1;
    while (end && *end && isspace((unsigned char)*end))
        end++;
    if (end && *end)
        return -1;
    *out = (int64_t)value;
    return 0;
}

/*
 * if_stats:
 *   wan  name   active_conn  tx_packets  rx_packets  tx_bytes  rx_bytes
 *   1    wan    1786         29132       25400       5521643   53747875
 */
static void jmx_krt_read_if_stats(jmx_krt_snapshot_t *snap)
{
    char line[512];
    FILE *fp;

    jmx_krt_copy(snap->if_stats_reason, sizeof(snap->if_stats_reason),
                 "if_stats_node_absent");

    fp = jmx_krt_open("if_stats");
    if (!fp)
        return;

    while (fgets(line, sizeof(line), fp)) {
        jmx_krt_wan_t *wan;
        char name[32];
        int index = 0;
        int64_t active = 0, txp = 0, rxp = 0, txb = 0, rxb = 0;

        if (jmx_krt_is_comment(line))
            continue;
        /* header row starts with the literal column name */
        if (!strncmp(line, "wan ", 4) || strstr(line, "active_conn"))
            continue;
        if (sscanf(line, "%d %31s %" SCNd64 " %" SCNd64 " %" SCNd64 " %" SCNd64 " %" SCNd64,
                   &index, name, &active, &txp, &rxp, &txb, &rxb) != 7)
            continue;
        if (index <= 0 || snap->wan_count >= JMX_KRT_MAX_WANS)
            continue;

        wan = &snap->wans[snap->wan_count];
        memset(wan, 0, sizeof(*wan));
        wan->index = index;
        jmx_krt_copy(wan->if_stats_name, sizeof(wan->if_stats_name), name);
        /*
         * The proc directory is wan<N> from the numeric column. Trusting the
         * name column instead would look for /proc/.../wan for the first WAN,
         * which does not exist.
         */
        snprintf(wan->id, sizeof(wan->id), "wan%d", index);
        wan->active_conn = active;
        wan->tx_packets = txp;
        wan->rx_packets = rxp;
        wan->tx_bytes = txb;
        wan->rx_bytes = rxb;
        wan->if_stats_valid = 1;
        snap->active_conn_total += active;
        snap->wan_count++;
    }
    fclose(fp);

    if (!snap->wan_count) {
        jmx_krt_copy(snap->if_stats_reason, sizeof(snap->if_stats_reason),
                     "if_stats_node_unparseable");
        return;
    }
    snap->if_stats_valid = 1;
    jmx_krt_copy(snap->if_stats_reason, sizeof(snap->if_stats_reason),
                 "kernel_if_stats");
}

/*
 * proto_stats (per WAN and global):
 *   category  active_conn  tx_packets  rx_packets  tx_bytes  rx_bytes
 *   Unknown   2108         30245       38205       7045647   84252446
 *   ...
 *   Total     2112         31073       38749       7153726   85121687
 *
 * "Unknown" is preserved as its own row; it is never redistributed into the
 * named categories.
 */
static int jmx_krt_read_proto_stats(const char *relative,
                                    jmx_krt_category_t *rows, int max_rows,
                                    int *row_count, jmx_krt_category_t *total,
                                    char *reason, size_t reason_len)
{
    char line[512];
    FILE *fp;
    int parsed = 0;

    *row_count = 0;
    memset(total, 0, sizeof(*total));
    jmx_krt_copy(reason, reason_len, "proto_stats_node_absent");

    fp = jmx_krt_open(relative);
    if (!fp)
        return -1;

    while (fgets(line, sizeof(line), fp)) {
        jmx_krt_category_t row;
        char name[32];

        if (jmx_krt_is_comment(line))
            continue;
        memset(&row, 0, sizeof(row));
        if (sscanf(line, "%31s %" SCNd64 " %" SCNd64 " %" SCNd64 " %" SCNd64 " %" SCNd64,
                   name, &row.active_conn, &row.tx_packets, &row.rx_packets,
                   &row.tx_bytes, &row.rx_bytes) != 6)
            continue;       /* header row lands here and is skipped */
        jmx_krt_copy(row.name, sizeof(row.name), name);
        row.valid = 1;
        parsed++;

        if (!strcmp(name, "Total")) {
            *total = row;
            continue;
        }
        if (*row_count >= max_rows)
            continue;
        rows[*row_count] = row;
        (*row_count)++;
    }
    fclose(fp);

    if (!parsed) {
        jmx_krt_copy(reason, reason_len, "proto_stats_node_unparseable");
        return -1;
    }
    jmx_krt_copy(reason, reason_len, "kernel_proto_stats");
    return 0;
}

static void jmx_krt_read_wan_proto(jmx_krt_snapshot_t *snap)
{
    int i;

    for (i = 0; i < snap->wan_count; i++) {
        jmx_krt_wan_t *wan = &snap->wans[i];
        char relative[64];
        int written;

        snprintf(relative, sizeof(relative), "%s/proto_stats", wan->id);
        /* Reported as the node's source, so a truncated path would mislabel the
         * data rather than just look untidy; treat overflow as unreadable. */
        written = snprintf(wan->proto_path, sizeof(wan->proto_path), "%s/%s",
                           jmx_krt_root(), relative);
        if (written < 0 || written >= (int)sizeof(wan->proto_path)) {
            jmx_krt_copy(wan->proto_reason, sizeof(wan->proto_reason),
                         "proto_stats_path_too_long");
            snap->degraded = 1;
            continue;
        }
        if (jmx_krt_read_proto_stats(relative, wan->categories,
                                     JMX_KRT_MAX_CATEGORIES,
                                     &wan->category_count, &wan->total,
                                     wan->proto_reason,
                                     sizeof(wan->proto_reason)) == 0)
            wan->proto_valid = 1;
        else
            snap->degraded = 1;
    }
}

static void jmx_krt_read_global_proto(jmx_krt_snapshot_t *snap)
{
    if (jmx_krt_read_proto_stats("proto_stats", snap->global_categories,
                                 JMX_KRT_MAX_CATEGORIES,
                                 &snap->global_category_count,
                                 &snap->global_total,
                                 snap->global_proto_reason,
                                 sizeof(snap->global_proto_reason)) == 0)
        snap->global_proto_valid = 1;
    else
        snap->degraded = 1;
}

static void jmx_krt_read_cache(jmx_krt_snapshot_t *snap)
{
    jmx_krt_cache_t *cache = &snap->cache;
    char line[512];
    FILE *fp;
    int parsed = 0;

    jmx_krt_copy(cache->reason, sizeof(cache->reason), "cache_stats_node_absent");
    fp = jmx_krt_open("cache_stats");
    if (!fp) {
        snap->degraded = 1;
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        char name[32], capacity[24], occupancy[24];
        int64_t buckets = 0, locks = 0, count = 0;
        char state[16];
        int64_t delta = 0;

        if (jmx_krt_is_comment(line))
            continue;

        if (sscanf(line, "hit_conn_cached %" SCNd64, &cache->hit_conn_cached) == 1) { parsed++; continue; }
        if (sscanf(line, "hit_feature %" SCNd64, &cache->hit_feature) == 1) { parsed++; continue; }
        if (sscanf(line, "hit_v2_ac %" SCNd64, &cache->hit_v2_ac) == 1) { parsed++; continue; }
        if (sscanf(line, "hit_v3_ac %" SCNd64, &cache->hit_v3_ac) == 1) { parsed++; continue; }
        if (sscanf(line, "hit_total %" SCNd64, &cache->hit_total) == 1) { parsed++; continue; }
        if (sscanf(line, "lookup %" SCNd64, &cache->lookup) == 1) { parsed++; continue; }
        if (sscanf(line, "miss %" SCNd64, &cache->miss) == 1) { parsed++; continue; }
        if (sscanf(line, "v3_shadow_hit %" SCNd64, &cache->v3_shadow_hit) == 1) { parsed++; continue; }
        if (sscanf(line, "v3_budget_exhausted %" SCNd64, &cache->v3_budget_exhausted) == 1) { parsed++; continue; }
        if (sscanf(line, "invariant_hit_plus_miss %15s delta=%" SCNd64, state, &delta) == 2) {
            cache->invariant_valid = 1;
            cache->invariant_ok = !strcmp(state, "ok");
            cache->invariant_delta = delta;
            parsed++;
            continue;
        }

        /* cache table row: name capacity buckets locks count occupancy */
        if (sscanf(line, "%31s %23s %" SCNd64 " %" SCNd64 " %" SCNd64 " %23s",
                   name, capacity, &buckets, &locks, &count, occupancy) == 6) {
            jmx_krt_cache_entry_t *entry;
            int64_t cap_value = 0;
            int64_t occ_value = 0;

            if (!strcmp(name, "cache"))
                continue;                       /* header row */
            if (cache->entry_count >= JMX_KRT_MAX_CACHES)
                continue;
            entry = &cache->entries[cache->entry_count];
            memset(entry, 0, sizeof(*entry));
            jmx_krt_copy(entry->name, sizeof(entry->name), name);
            /* "unbounded" is the documented way of saying no capacity limit */
            entry->capacity = (jmx_krt_parse_i64(capacity, &cap_value) == 0) ? cap_value : -1;
            entry->buckets = buckets;
            entry->locks = locks;
            entry->count = count;
            if (jmx_krt_parse_i64(occupancy, &occ_value) == 0) {
                entry->occupancy_valid = 1;
                entry->occupancy = occ_value;
            }
            cache->entry_count++;
            parsed++;
            continue;
        }
    }
    fclose(fp);

    if (!parsed) {
        jmx_krt_copy(cache->reason, sizeof(cache->reason), "cache_stats_node_unparseable");
        snap->degraded = 1;
        return;
    }
    cache->valid = 1;
    jmx_krt_copy(cache->reason, sizeof(cache->reason), "kernel_cache_stats");
}

static void jmx_krt_read_memory(jmx_krt_snapshot_t *snap)
{
    jmx_krt_memory_t *mem = &snap->memory;
    char line[512];
    FILE *fp;

    jmx_krt_copy(mem->reason, sizeof(mem->reason), "mem_stats_node_absent");
    fp = jmx_krt_open("mem_stats");
    if (!fp) {
        snap->degraded = 1;
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        jmx_krt_pool_t *pool;
        char name[32];
        int64_t alloc = 0, freed = 0, live = 0, objsize = 0, allocfail = 0;

        if (jmx_krt_is_comment(line))
            continue;
        if (sscanf(line, "%31s %" SCNd64 " %" SCNd64 " %" SCNd64 " %" SCNd64 " %" SCNd64,
                   name, &alloc, &freed, &live, &objsize, &allocfail) != 6)
            continue;   /* header and the live=/cache_count= cross-check lines */
        if (!strcmp(name, "pool"))
            continue;
        if (mem->pool_count >= JMX_KRT_MAX_POOLS)
            continue;
        pool = &mem->pools[mem->pool_count];
        memset(pool, 0, sizeof(*pool));
        jmx_krt_copy(pool->name, sizeof(pool->name), name);
        pool->alloc = alloc;
        pool->freed = freed;
        pool->live = live;
        pool->objsize = objsize;
        pool->allocfail = allocfail;
        mem->pool_count++;
    }
    fclose(fp);

    if (!mem->pool_count) {
        jmx_krt_copy(mem->reason, sizeof(mem->reason), "mem_stats_node_unparseable");
        snap->degraded = 1;
        return;
    }
    mem->valid = 1;
    jmx_krt_copy(mem->reason, sizeof(mem->reason), "kernel_mem_stats");
}

static void jmx_krt_read_rcu(jmx_krt_snapshot_t *snap)
{
    jmx_krt_rcu_t *rcu = &snap->rcu;
    char line[512];
    FILE *fp;
    int parsed = 0;

    jmx_krt_copy(rcu->reason, sizeof(rcu->reason), "rcu_stats_node_absent");
    fp = jmx_krt_open("rcu_stats");
    if (!fp) {
        snap->degraded = 1;
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (jmx_krt_is_comment(line))
            continue;
        if (sscanf(line, "retire_requested %" SCNd64, &rcu->retire_requested) == 1) { parsed++; continue; }
        if (sscanf(line, "retire_completed %" SCNd64, &rcu->retire_completed) == 1) { parsed++; continue; }
        if (sscanf(line, "retire_in_flight %" SCNd64, &rcu->retire_in_flight) == 1) { parsed++; continue; }
        if (sscanf(line, "state %15s", rcu->state) == 1) { parsed++; continue; }
    }
    fclose(fp);

    if (!parsed) {
        jmx_krt_copy(rcu->reason, sizeof(rcu->reason), "rcu_stats_node_unparseable");
        snap->degraded = 1;
        return;
    }
    rcu->valid = 1;
    jmx_krt_copy(rcu->reason, sizeof(rcu->reason), "kernel_rcu_stats");
}

/*
 * rule_match_cnt carries its generation and rule count in a comment header:
 *   # v3 generation 0, 0 rules
 *   rule_id  appid  priority  match_cnt
 *
 * An empty table is a valid state, so this node counts as read when the header
 * parsed even if no rows follow.
 */
static void jmx_krt_read_rules(jmx_krt_snapshot_t *snap)
{
    jmx_krt_rules_t *rules = &snap->rules;
    char line[512];
    FILE *fp;
    int header_seen = 0;

    jmx_krt_copy(rules->reason, sizeof(rules->reason), "rule_match_cnt_node_absent");
    fp = jmx_krt_open("rule_match_cnt");
    if (!fp) {
        snap->degraded = 1;
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        jmx_krt_rule_t *rule;
        int64_t generation = 0, total = 0;
        int64_t rule_id = 0, appid = 0, priority = 0, match_cnt = 0;

        if (sscanf(line, "# v3 generation %" SCNd64 ", %" SCNd64 " rules",
                   &generation, &total) == 2) {
            rules->generation_valid = 1;
            rules->generation = generation;
            rules->rule_total_valid = 1;
            rules->rule_total = total;
            header_seen = 1;
            continue;
        }
        if (jmx_krt_is_comment(line))
            continue;
        if (strstr(line, "match_cnt")) {
            header_seen = 1;    /* column header */
            continue;
        }
        if (sscanf(line, "%" SCNd64 " %" SCNd64 " %" SCNd64 " %" SCNd64,
                   &rule_id, &appid, &priority, &match_cnt) != 4)
            continue;
        rules->match_cnt_total += match_cnt;
        if (rules->rule_count >= JMX_KRT_MAX_RULES)
            continue;
        rule = &rules->rules[rules->rule_count];
        rule->rule_id = rule_id;
        rule->appid = appid;
        rule->priority = priority;
        rule->match_cnt = match_cnt;
        rules->rule_count++;
    }
    fclose(fp);

    if (!header_seen && !rules->rule_count) {
        jmx_krt_copy(rules->reason, sizeof(rules->reason),
                     "rule_match_cnt_node_unparseable");
        snap->degraded = 1;
        return;
    }
    rules->valid = 1;
    jmx_krt_copy(rules->reason, sizeof(rules->reason), "kernel_rule_match_cnt");
}

/*
 * Decides how active_conn may be described.
 *
 * The kernel counts route-bound flows and decrements on IPCT_DESTROY, so
 * ROUTE_BOUND is accurate by construction. It is downgraded to UNKNOWN when the
 * summed gauge exceeds the global conntrack table by more than a small margin,
 * because that pattern is what a missed DESTROY or a stale module looks like,
 * and in that state the number should not be presented as authoritative at all.
 */
static void jmx_krt_classify_active_conn(jmx_krt_snapshot_t *snap,
                                         int64_t conntrack_total)
{
    snap->active_conn_semantics = JMX_KRT_SEMANTICS_UNKNOWN;
    snap->active_conn_stale_possible = 0;

    if (!snap->if_stats_valid)
        return;

    snap->active_conn_semantics = JMX_KRT_SEMANTICS_ROUTE_BOUND;

    if (conntrack_total < 0)
        return;     /* caller has no reference point; claim stays route-bound */

    if (snap->active_conn_total > conntrack_total) {
        /*
         * Observed on 30.1: summed active_conn 7035 against a global conntrack
         * table of 3164. Route-bound accounting can legitimately sit above the
         * live table for a while, but a gap this size means residue is likely,
         * so the gauge is flagged and the semantics fall back to unknown rather
         * than implying a live count.
         */
        snap->active_conn_stale_possible = 1;
        snap->active_conn_semantics = JMX_KRT_SEMANTICS_UNKNOWN;
    }
}

int jmx_krt_read(jmx_krt_snapshot_t *snap, int64_t conntrack_total)
{
    if (!snap)
        return -1;

    memset(snap, 0, sizeof(*snap));
    snap->observed_at = (int64_t)time(NULL);
    snap->proc_root_present = (access(jmx_krt_root(), F_OK) == 0);

    if (!snap->proc_root_present) {
        snap->degraded = 1;
        jmx_krt_copy(snap->reason, sizeof(snap->reason), "jmx_proc_root_absent");
        jmx_krt_copy(snap->if_stats_reason, sizeof(snap->if_stats_reason),
                     "jmx_proc_root_absent");
        jmx_krt_copy(snap->cache.reason, sizeof(snap->cache.reason),
                     "jmx_proc_root_absent");
        jmx_krt_copy(snap->memory.reason, sizeof(snap->memory.reason),
                     "jmx_proc_root_absent");
        jmx_krt_copy(snap->rcu.reason, sizeof(snap->rcu.reason),
                     "jmx_proc_root_absent");
        jmx_krt_copy(snap->rules.reason, sizeof(snap->rules.reason),
                     "jmx_proc_root_absent");
        jmx_krt_copy(snap->global_proto_reason, sizeof(snap->global_proto_reason),
                     "jmx_proc_root_absent");
        return -1;
    }

    jmx_krt_read_if_stats(snap);
    if (!snap->if_stats_valid)
        snap->degraded = 1;
    jmx_krt_read_wan_proto(snap);
    jmx_krt_read_global_proto(snap);
    jmx_krt_read_cache(snap);
    jmx_krt_read_memory(snap);
    jmx_krt_read_rcu(snap);
    jmx_krt_read_rules(snap);
    jmx_krt_classify_active_conn(snap, conntrack_total);

    snap->available = (snap->if_stats_valid || snap->global_proto_valid ||
                       snap->cache.valid || snap->memory.valid ||
                       snap->rcu.valid || snap->rules.valid);
    if (!snap->available) {
        jmx_krt_copy(snap->reason, sizeof(snap->reason), "jmx_proc_nodes_unreadable");
        return -1;
    }
    if (snap->degraded && !snap->reason[0])
        jmx_krt_copy(snap->reason, sizeof(snap->reason), "jmx_proc_partial_read");
    return 0;
}

const jmx_krt_wan_t *jmx_krt_find_wan(const jmx_krt_snapshot_t *snap,
                                      const char *wan_id)
{
    int i;

    if (!snap || !wan_id || !wan_id[0])
        return NULL;
    for (i = 0; i < snap->wan_count; i++) {
        if (!strcmp(snap->wans[i].id, wan_id) ||
            !strcmp(snap->wans[i].if_stats_name, wan_id))
            return &snap->wans[i];
    }
    return NULL;
}

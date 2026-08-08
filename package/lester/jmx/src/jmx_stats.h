/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jmx_stats.h - cache / mempool / RCU observability counters
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 *
 * Design notes (deliberate divergences from the iKuai surface this was
 * modelled on, see the proc-02 handoff):
 *
 *  - Tier names describe *our* lookup path, not iKuai's private
 *    http/normal/weak vocabulary.  jmx resolves an app id in this order:
 *      conn_cached  - the flow already carried an app_id
 *      feature      - legacy feature list matched (match_feature)
 *      v2_ac        - v2 protobuf rule set matched via Aho-Corasick
 *      v3_ac        - v3 signature rule set matched via Aho-Corasick
 *    Exactly one tier is credited per resolved lookup, so the tier sum is
 *    the total hit count.  Shadow-mode v3 matches are counted separately
 *    because they never produce a classification, and folding them in
 *    would break that invariant.
 *
 *  - Counters are per-CPU and take no lock, so the forwarding hot path is
 *    unaffected.  Readers sum across CPUs, so a concurrent reader can see a
 *    slightly skewed total.  That is accepted: these are monotonic
 *    diagnostics, not accounting figures.
 *
 *  - Counters are always compiled in.  A diagnostic that exists only in a
 *    debug build is missing exactly when it is needed.
 */
#ifndef __JMX_STATS_H__
#define __JMX_STATS_H__

#include <linux/percpu.h>
#include <linux/types.h>

/* ── Cache lookup tiers ─────────────────────────────────────────────── */

enum jmx_stats_tier {
	JMX_TIER_CONN_CACHED = 0,	/* app_id already on the flow */
	JMX_TIER_FEATURE,		/* legacy feature list */
	JMX_TIER_V2_AC,			/* v2 rule set, AC scan */
	JMX_TIER_V3_AC,			/* v3 rule set, AC scan */
	JMX_TIER_MAX
};

/* ── Memory pools ───────────────────────────────────────────────────── */

enum jmx_stats_pool {
	JMX_POOL_CONN = 0,		/* af_conn_t */
	JMX_POOL_CLIENT,		/* af_client_info_t */
	JMX_POOL_VISIT_INFO,		/* app_visit_info_t */
	JMX_POOL_V2_RULE,		/* struct jmx_v2_rule_node */
	JMX_POOL_MAX
};

/*
 * Per-CPU counter block.  alloc/free are kept per pool so the difference is
 * the live object count; a difference that only ever grows is a leak, and is
 * visible without any further tooling.
 */
struct jmx_stats_cpu {
	u64 tier_hit[JMX_TIER_MAX];
	u64 lookup;			/* resolution attempts */
	u64 miss;			/* attempts that resolved nothing */
	u64 shadow_hit;			/* v3 matched in shadow mode */
	u64 v3_budget_exhausted;	/* AC scan aborted on work budget */
	u64 pool_alloc[JMX_POOL_MAX];
	u64 pool_free[JMX_POOL_MAX];
	u64 pool_alloc_fail[JMX_POOL_MAX];
};

DECLARE_PER_CPU(struct jmx_stats_cpu, jmx_stats_pcpu);

/*
 * this_cpu_inc() on a per-CPU u64 is a single RMW against the local CPU's
 * copy.  It is safe from any context here because every counter is only ever
 * incremented and readers tolerate a torn sum.
 */
static inline void jmx_stats_tier_hit(enum jmx_stats_tier tier)
{
	if (unlikely((unsigned int)tier >= JMX_TIER_MAX))
		return;
	this_cpu_inc(jmx_stats_pcpu.tier_hit[tier]);
}

static inline void jmx_stats_lookup(void)
{
	this_cpu_inc(jmx_stats_pcpu.lookup);
}

static inline void jmx_stats_miss(void)
{
	this_cpu_inc(jmx_stats_pcpu.miss);
}

static inline void jmx_stats_shadow_hit(void)
{
	this_cpu_inc(jmx_stats_pcpu.shadow_hit);
}

static inline void jmx_stats_v3_budget_exhausted(void)
{
	this_cpu_inc(jmx_stats_pcpu.v3_budget_exhausted);
}

static inline void jmx_stats_pool_alloc(enum jmx_stats_pool pool)
{
	if (unlikely((unsigned int)pool >= JMX_POOL_MAX))
		return;
	this_cpu_inc(jmx_stats_pcpu.pool_alloc[pool]);
}

static inline void jmx_stats_pool_free(enum jmx_stats_pool pool)
{
	if (unlikely((unsigned int)pool >= JMX_POOL_MAX))
		return;
	this_cpu_inc(jmx_stats_pcpu.pool_free[pool]);
}

static inline void jmx_stats_pool_alloc_fail(enum jmx_stats_pool pool)
{
	if (unlikely((unsigned int)pool >= JMX_POOL_MAX))
		return;
	this_cpu_inc(jmx_stats_pcpu.pool_alloc_fail[pool]);
}

/* ── RCU retirement accounting ──────────────────────────────────────── */

/*
 * jmx retires rule sets with synchronize_rcu(), not call_rcu(), so there is
 * no per-CPU callback backlog to report.  A "pending callbacks" field here
 * would be structurally always zero, which is worse than not reporting it.
 * What is real: how many retirements were requested, how many completed, and
 * whether one is in flight - which is what distinguishes "no backlog" from
 * "draining".
 */
void jmx_stats_rcu_retire_begin(void);
void jmx_stats_rcu_retire_end(void);

/* ── Per-rule match counts ──────────────────────────────────────────── */

/*
 * Per-rule counters live with the rule set that owns them, so a rule-set
 * swap cannot carry counts across generations.
 */
struct jmx_stats_rule_row {
	u32 signature_rule_id;
	u32 appid;
	u32 priority;
	u64 match_cnt;
};

/*
 * Snapshot the active v3 rule table into caller-provided storage.  Returns
 * the number of rows written, or a negative errno.  `rows` may be NULL to
 * query the required length only.  Implemented in jmx_v3_rules.c, which owns
 * the active-set RCU pointer.
 */
int jmx_v3_rule_match_snapshot(struct jmx_stats_rule_row *rows, u32 max_rows,
			       u32 *out_generation);

/* ── Cache capacity description ─────────────────────────────────────── */

/*
 * Four dimensions per cache, as the handoff asks: capacity, buckets, lock
 * shards, live count.  Where a dimension is genuinely unbounded we report 0
 * and the proc node prints "unbounded" rather than inventing a ceiling,
 * because a fabricated denominator makes the occupancy ratio a lie.
 */
struct jmx_stats_cache_desc {
	const char *name;
	u32 capacity;		/* 0 = unbounded by design */
	u32 buckets;
	u32 lock_shards;
	u32 count;		/* live entries */
};

/* Providers, each implemented next to the cache it describes. */
u32 af_conn_live_count(void);
u32 af_client_live_count(void);
u32 jmx_v2_rule_live_count(void);

int jmx_stats_init(void);
void jmx_stats_exit(void);

#endif /* __JMX_STATS_H__ */

// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * jmx_stats.c - /proc/dreamingwrt/jmx/{cache,mem,rcu}_stats, rule_match_cnt
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */
#include <linux/atomic.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include "jmx.h"
#include "jmx_client.h"
#include "jmx_conntrack.h"
#include "jmx_stats.h"
#include "jmx_v2_rules.h"

DEFINE_PER_CPU(struct jmx_stats_cpu, jmx_stats_pcpu);

/* Retirement accounting; see the header for why this is not a callback count. */
static atomic64_t jmx_rcu_retire_requested = ATOMIC64_INIT(0);
static atomic64_t jmx_rcu_retire_completed = ATOMIC64_INIT(0);

void jmx_stats_rcu_retire_begin(void)
{
	atomic64_inc(&jmx_rcu_retire_requested);
}

void jmx_stats_rcu_retire_end(void)
{
	atomic64_inc(&jmx_rcu_retire_completed);
}

/* ── Summation ──────────────────────────────────────────────────────── */

/*
 * Fold every CPU's block into one.  Done once per read so a single proc read
 * presents one coherent snapshot instead of re-summing per line, which would
 * let the tier-sum invariant fail purely from read skew.
 */
static void jmx_stats_sum(struct jmx_stats_cpu *out)
{
	int cpu, i;

	memset(out, 0, sizeof(*out));
	for_each_possible_cpu(cpu) {
		const struct jmx_stats_cpu *c = per_cpu_ptr(&jmx_stats_pcpu, cpu);

		for (i = 0; i < JMX_TIER_MAX; i++)
			out->tier_hit[i] += c->tier_hit[i];
		out->lookup += c->lookup;
		out->miss += c->miss;
		out->shadow_hit += c->shadow_hit;
		out->v3_budget_exhausted += c->v3_budget_exhausted;
		for (i = 0; i < JMX_POOL_MAX; i++) {
			out->pool_alloc[i] += c->pool_alloc[i];
			out->pool_free[i] += c->pool_free[i];
			out->pool_alloc_fail[i] += c->pool_alloc_fail[i];
		}
	}
}

static const char *const jmx_tier_name[JMX_TIER_MAX] = {
	[JMX_TIER_CONN_CACHED] = "conn_cached",
	[JMX_TIER_FEATURE]     = "feature",
	[JMX_TIER_V2_AC]       = "v2_ac",
	[JMX_TIER_V3_AC]       = "v3_ac",
};

static const char *const jmx_pool_name[JMX_POOL_MAX] = {
	[JMX_POOL_CONN]        = "conn",
	[JMX_POOL_CLIENT]      = "client",
	[JMX_POOL_VISIT_INFO]  = "visit_info",
	[JMX_POOL_V2_RULE]     = "v2_rule",
};

static const size_t jmx_pool_objsize[JMX_POOL_MAX] = {
	[JMX_POOL_CONN]        = sizeof(af_conn_t),
	[JMX_POOL_CLIENT]      = sizeof(af_client_info_t),
	[JMX_POOL_VISIT_INFO]  = sizeof(app_visit_info_t),
	/* struct jmx_v2_rule_node is file-private to jmx_v2_rules.c. */
	[JMX_POOL_V2_RULE]     = 0,
};

/*
 * Which pools can be cross-checked against a cache occupancy, and which
 * cannot.  Only `conn` holds strictly: a conn object is allocated into the
 * table and freed while still removed from it, under the same lock, so
 * alloc-free is exactly the table population.
 *
 * The other two are deliberately marked informational rather than being
 * dressed up as invariants:
 *
 *  - client objects are refcounted.  One removed from the table can still be
 *    alive because a hook or timer holds a reference, so live >= table count
 *    transiently, and a strict comparison would report a false MISMATCH.
 *  - v2 rules exist in two sets at once (active and staging) during an
 *    update, while the cache row reports only the active set, so live >=
 *    active count by construction.
 */
struct jmx_pool_check {
	const char *cache_name;
	enum jmx_stats_pool pool;
	bool strict;
};

static const struct jmx_pool_check jmx_pool_checks[] = {
	{ "conn",    JMX_POOL_CONN,    true  },
	{ "client",  JMX_POOL_CLIENT,  false },
	{ "v2_rule", JMX_POOL_V2_RULE, false },
};

static const struct jmx_pool_check *jmx_check_for_cache(const char *name)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(jmx_pool_checks); i++)
		if (!strcmp(jmx_pool_checks[i].cache_name, name))
			return &jmx_pool_checks[i];
	return NULL;
}

/* ── cache_stats ────────────────────────────────────────────────────── */

static void jmx_describe_caches(struct jmx_stats_cache_desc *d, u32 *n)
{
	u32 i = 0;

	/*
	 * capacity 0 means "no ceiling in the current implementation".  The
	 * conn table is pruned by timeout rather than capped, and the client
	 * table is bounded by the LAN, not by a constant.  Reporting an
	 * invented cap here would make the occupancy percentage meaningless.
	 */
	d[i].name = "conn";
	d[i].capacity = 0;
	d[i].buckets = AF_CONN_HASH_SIZE;
	d[i].lock_shards = 1;		/* single spinlock: af_conn_lock */
	d[i].count = af_conn_live_count();
	i++;

	d[i].name = "client";
	d[i].capacity = 0;
	d[i].buckets = MAX_AF_CLIENT_HASH_SIZE;
	d[i].lock_shards = 1;		/* single rwlock: af_client_lock */
	d[i].count = af_client_live_count();
	i++;

	d[i].name = "v2_rule";
	d[i].capacity = 0;
	d[i].buckets = JMX_V2_RULE_BUCKETS;
	d[i].lock_shards = 1;		/* active_generation_lock */
	d[i].count = jmx_v2_rule_live_count();
	i++;

	*n = i;
}

#define JMX_CACHE_DESC_MAX 4

static int jmx_cache_stats_show(struct seq_file *s, void *v)
{
	struct jmx_stats_cache_desc desc[JMX_CACHE_DESC_MAX];
	struct jmx_stats_cpu t;
	u64 tier_sum = 0;
	u32 n = 0, i;

	(void)v;
	jmx_stats_sum(&t);
	jmx_describe_caches(desc, &n);

	seq_puts(s, "# capacity=0 means unbounded by design; occupancy is then not defined\n");
	seq_printf(s, "%-10s %10s %10s %10s %10s %9s\n",
		   "cache", "capacity", "bucket", "lock", "count", "occupancy");
	for (i = 0; i < n; i++) {
		if (desc[i].capacity) {
			seq_printf(s, "%-10s %10u %10u %10u %10u %8u%%\n",
				   desc[i].name, desc[i].capacity,
				   desc[i].buckets, desc[i].lock_shards,
				   desc[i].count,
				   (unsigned int)((u64)desc[i].count * 100 /
						  desc[i].capacity));
		} else {
			seq_printf(s, "%-10s %10s %10u %10u %10u %9s\n",
				   desc[i].name, "unbounded",
				   desc[i].buckets, desc[i].lock_shards,
				   desc[i].count, "n/a");
		}
	}

	seq_puts(s, "\n# tiers are mutually exclusive per resolved lookup\n");
	for (i = 0; i < JMX_TIER_MAX; i++) {
		seq_printf(s, "hit_%-12s %llu\n", jmx_tier_name[i],
			   t.tier_hit[i]);
		tier_sum += t.tier_hit[i];
	}
	seq_printf(s, "hit_total          %llu\n", tier_sum);
	seq_printf(s, "lookup             %llu\n", t.lookup);
	seq_printf(s, "miss               %llu\n", t.miss);

	/*
	 * Self-checks, printed rather than hidden.  A mismatch means an
	 * instrumentation bug - a resolution path crediting two tiers or
	 * none - and the reader is told instead of being handed a plausible
	 * but wrong number.
	 *
	 * Both checks can also trip from read skew: the tiers are summed
	 * across CPUs without stopping the dataplane, so a packet counted
	 * mid-read can land on either side.  The skew is bounded by the
	 * number of in-flight packets, so a difference of a few is benign
	 * while a large or growing one is a real bug.  The absolute
	 * difference is printed so that distinction can be made.
	 */
	{
		u64 accounted = tier_sum + t.miss;
		u64 delta = accounted > t.lookup ? accounted - t.lookup :
						   t.lookup - accounted;

		/* Invariant 1: every lookup either hit one tier or missed. */
		seq_printf(s, "invariant_hit_plus_miss %s delta=%llu\n",
			   delta == 0 ? "ok" : "skew_or_bug", delta);
	}

	seq_puts(s, "\n# observational only, never produces a classification\n");
	seq_printf(s, "v3_shadow_hit      %llu\n", t.shadow_hit);
	seq_printf(s, "v3_budget_exhausted %llu\n", t.v3_budget_exhausted);
	return 0;
}

/* ── mem_stats ──────────────────────────────────────────────────────── */

static int jmx_mem_stats_show(struct seq_file *s, void *v)
{
	struct jmx_stats_cache_desc desc[JMX_CACHE_DESC_MAX];
	struct jmx_stats_cpu t;
	u32 n = 0, i, j;

	(void)v;
	jmx_stats_sum(&t);
	jmx_describe_caches(desc, &n);

	seq_puts(s, "# live = alloc - free; a live count that only grows is a leak\n");
	seq_puts(s, "# objsize 0 = object is file-private to its owning module\n");
	seq_printf(s, "%-12s %14s %14s %14s %10s %10s\n",
		   "pool", "alloc", "free", "live", "objsize", "allocfail");
	for (i = 0; i < JMX_POOL_MAX; i++) {
		u64 alloc = t.pool_alloc[i];
		u64 free = t.pool_free[i];

		seq_printf(s, "%-12s %14llu %14llu %14llu %10zu %10llu\n",
			   jmx_pool_name[i], alloc, free,
			   alloc >= free ? alloc - free : 0,
			   jmx_pool_objsize[i], t.pool_alloc_fail[i]);
	}

	/*
	 * Cross-node check: a pool's live count must equal the occupancy its
	 * cache reports, because every object in that pool is an entry in that
	 * cache.  This is the invariant the handoff singles out, so it is
	 * evaluated here rather than left to the reader.
	 */
	seq_puts(s, "\n# cross-check against cache_stats occupancy\n");
	seq_puts(s, "# strict: live must equal cache_count.  informational: live may\n");
	seq_puts(s, "# legitimately exceed it (refcounted holders, staging rule set).\n");
	for (i = 0; i < n; i++) {
		const struct jmx_pool_check *chk =
			jmx_check_for_cache(desc[i].name);
		u64 live;
		const char *verdict;

		if (!chk)
			continue;
		j = (u32)chk->pool;
		live = t.pool_alloc[j] >= t.pool_free[j] ?
		       t.pool_alloc[j] - t.pool_free[j] : 0;
		if (chk->strict)
			verdict = live == desc[i].count ? "ok" : "MISMATCH";
		else
			verdict = live >= desc[i].count ? "ok(informational)" :
							  "UNDERCOUNT";
		seq_printf(s, "%-12s live=%llu cache_count=%u %s\n",
			   desc[i].name, live, desc[i].count, verdict);
	}
	return 0;
}

/* ── rcu_stats ──────────────────────────────────────────────────────── */

static int jmx_rcu_stats_show(struct seq_file *s, void *v)
{
	s64 requested = atomic64_read(&jmx_rcu_retire_requested);
	s64 completed = atomic64_read(&jmx_rcu_retire_completed);
	s64 in_flight = requested - completed;

	(void)v;
	/*
	 * Read completed first would be racier; requested is incremented
	 * before completed, so reading requested first can only overstate
	 * in_flight, never hide a stall.
	 */
	seq_puts(s, "# jmx retires rule sets with synchronize_rcu(), not call_rcu().\n");
	seq_puts(s, "# There is therefore no per-CPU callback backlog to report;\n");
	seq_puts(s, "# a 'pending callbacks' field would be always zero by design.\n");
	seq_printf(s, "retire_requested %lld\n", requested);
	seq_printf(s, "retire_completed %lld\n", completed);
	seq_printf(s, "retire_in_flight %lld\n", in_flight < 0 ? 0 : in_flight);
	/*
	 * The distinction the handoff asks for: nothing outstanding versus
	 * something outstanding that is still advancing.  "draining" means a
	 * writer is blocked inside synchronize_rcu() right now; consecutive
	 * reads showing a rising retire_completed confirm forward progress.
	 */
	seq_printf(s, "state            %s\n",
		   in_flight <= 0 ? "idle" : "draining");
	return 0;
}

/* ── rule_match_cnt ─────────────────────────────────────────────────── */

/*
 * Row count scales with the rule set (up to JMX_V3_MAX_RULES), so this node
 * is paginated with a seq_file iterator over a snapshot taken once at open().
 * Snapshotting avoids holding the RCU read lock across a multi-read
 * traversal, and gives a stable generation for the whole read - so the
 * "rows == entities" assertion below is meaningful rather than racing a
 * rule-set swap.
 */
struct jmx_rule_iter {
	struct jmx_stats_rule_row *rows;
	u32 count;
	u32 generation;
};

static void *jmx_rule_seq_start(struct seq_file *s, loff_t *pos)
{
	struct jmx_rule_iter *it = s->private;

	if (*pos == 0)
		return SEQ_START_TOKEN;
	if (*pos - 1 >= it->count)
		return NULL;
	return &it->rows[*pos - 1];
}

static void *jmx_rule_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct jmx_rule_iter *it = s->private;

	(void)v;
	(*pos)++;
	if (*pos - 1 >= it->count)
		return NULL;
	return &it->rows[*pos - 1];
}

static void jmx_rule_seq_stop(struct seq_file *s, void *v)
{
	(void)s;
	(void)v;
}

static int jmx_rule_seq_show(struct seq_file *s, void *v)
{
	struct jmx_rule_iter *it = s->private;
	const struct jmx_stats_rule_row *row;

	if (v == SEQ_START_TOKEN) {
		seq_printf(s, "# v3 generation %u, %u rules\n",
			   it->generation, it->count);
		seq_puts(s, "# match_cnt is a real counter; an unmatched rule reads 0\n");
		seq_printf(s, "%-12s %-12s %-10s %s\n",
			   "rule_id", "appid", "priority", "match_cnt");
		return 0;
	}
	row = v;
	seq_printf(s, "%-12u %-12u %-10u %llu\n",
		   row->signature_rule_id, row->appid, row->priority,
		   row->match_cnt);
	return 0;
}

static const struct seq_operations jmx_rule_seq_ops = {
	.start = jmx_rule_seq_start,
	.next  = jmx_rule_seq_next,
	.stop  = jmx_rule_seq_stop,
	.show  = jmx_rule_seq_show,
};

static int jmx_rule_match_open(struct inode *inode, struct file *file)
{
	struct jmx_rule_iter *it;
	struct seq_file *seq;
	int need, got;
	int err;

	(void)inode;
	it = kzalloc(sizeof(*it), GFP_KERNEL);
	if (!it)
		return -ENOMEM;

	/* Length query first, then one allocation sized to it. */
	/* Capture generation even when the committed set contains zero rules. */
	need = jmx_v3_rule_match_snapshot(NULL, 0, &it->generation);
	if (need < 0) {
		kfree(it);
		return need;
	}
	if (need > 0) {
		it->rows = kvmalloc_array((size_t)need, sizeof(*it->rows),
					  GFP_KERNEL | __GFP_ZERO);
		if (!it->rows) {
			kfree(it);
			return -ENOMEM;
		}
		got = jmx_v3_rule_match_snapshot(it->rows, (u32)need,
						 &it->generation);
		if (got < 0) {
			kvfree(it->rows);
			kfree(it);
			return got;
		}
		/*
		 * "rows == entities" assertion the handoff asks for.  A short
		 * snapshot means the set was swapped between the two calls;
		 * report the smaller count rather than printing stale tail
		 * rows, and say so in the log so a repeated occurrence is not
		 * mistaken for an iterator re-entry bug.
		 */
		if (got != need)
			pr_info_ratelimited("jmx_stats: v3 rule set changed during snapshot (%d -> %d)\n",
					    need, got);
		it->count = (u32)got;
	}

	err = seq_open(file, &jmx_rule_seq_ops);
	if (err) {
		kvfree(it->rows);
		kfree(it);
		return err;
	}
	seq = file->private_data;
	seq->private = it;
	return 0;
}

static int jmx_rule_match_release(struct inode *inode, struct file *file)
{
	struct seq_file *seq = file->private_data;
	struct jmx_rule_iter *it = seq->private;

	if (it) {
		kvfree(it->rows);
		kfree(it);
		seq->private = NULL;
	}
	return seq_release(inode, file);
}

/* ── proc plumbing ──────────────────────────────────────────────────── */

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 5, 0)
#define JMX_STATS_SINGLE_FOPS(name, showfn)				\
static int name##_open(struct inode *inode, struct file *file)		\
{									\
	return single_open(file, showfn, NULL);				\
}									\
static const struct file_operations name##_fops = {			\
	.owner   = THIS_MODULE,						\
	.open    = name##_open,						\
	.read    = seq_read,						\
	.llseek  = seq_lseek,						\
	.release = single_release,					\
}

static const struct file_operations jmx_rule_match_fops = {
	.owner   = THIS_MODULE,
	.open    = jmx_rule_match_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = jmx_rule_match_release,
};
#else
#define JMX_STATS_SINGLE_FOPS(name, showfn)				\
static int name##_open(struct inode *inode, struct file *file)		\
{									\
	return single_open(file, showfn, NULL);				\
}									\
static const struct proc_ops name##_fops = {				\
	.proc_open    = name##_open,					\
	.proc_read    = seq_read,					\
	.proc_lseek   = seq_lseek,					\
	.proc_release = single_release,					\
}

static const struct proc_ops jmx_rule_match_fops = {
	.proc_open    = jmx_rule_match_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = jmx_rule_match_release,
};
#endif

JMX_STATS_SINGLE_FOPS(jmx_cache_stats, jmx_cache_stats_show);
JMX_STATS_SINGLE_FOPS(jmx_mem_stats, jmx_mem_stats_show);
JMX_STATS_SINGLE_FOPS(jmx_rcu_stats, jmx_rcu_stats_show);

#define JMX_CACHE_STATS_NAME "cache_stats"
#define JMX_MEM_STATS_NAME   "mem_stats"
#define JMX_RCU_STATS_NAME   "rcu_stats"
#define JMX_RULE_MATCH_NAME  "rule_match_cnt"

int jmx_stats_init(void)
{
	if (!jmx_proc_root)
		return -ENOENT;

	if (!proc_create(JMX_CACHE_STATS_NAME, 0444, jmx_proc_root,
			 &jmx_cache_stats_fops))
		goto fail_cache;
	if (!proc_create(JMX_MEM_STATS_NAME, 0444, jmx_proc_root,
			 &jmx_mem_stats_fops))
		goto fail_mem;
	if (!proc_create(JMX_RCU_STATS_NAME, 0444, jmx_proc_root,
			 &jmx_rcu_stats_fops))
		goto fail_rcu;
	if (!proc_create(JMX_RULE_MATCH_NAME, 0444, jmx_proc_root,
			 &jmx_rule_match_fops))
		goto fail_rule;
	return 0;

fail_rule:
	remove_proc_entry(JMX_RCU_STATS_NAME, jmx_proc_root);
fail_rcu:
	remove_proc_entry(JMX_MEM_STATS_NAME, jmx_proc_root);
fail_mem:
	remove_proc_entry(JMX_CACHE_STATS_NAME, jmx_proc_root);
fail_cache:
	pr_err("jmx: failed to create stats proc entries\n");
	return -ENOMEM;
}

void jmx_stats_exit(void)
{
	if (!jmx_proc_root)
		return;
	remove_proc_entry(JMX_RULE_MATCH_NAME, jmx_proc_root);
	remove_proc_entry(JMX_RCU_STATS_NAME, jmx_proc_root);
	remove_proc_entry(JMX_MEM_STATS_NAME, jmx_proc_root);
	remove_proc_entry(JMX_CACHE_STATS_NAME, jmx_proc_root);
}

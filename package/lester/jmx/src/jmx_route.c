// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * jmx_route.c - Phase 5 multi-WAN route policy engine
 *
 * Provides an iKuai-style first-packet route decision core:
 *   policy match -> sticky WAN select -> fwmark -> ct/skb mark
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/jiffies.h>
#include <linux/math64.h>
#include <linux/random.h>

#include "jmx.h"
#include "jmx_log.h"
#include "jmx_conntrack.h"

/* Keep the route-add netlink payload aligned with jmxd's native wire struct. */
static_assert(offsetof(jmx_route_rule_t, wan_ids) == 31);
static_assert(offsetof(jmx_route_rule_t, wan_weights) == 40);
static_assert(offsetof(jmx_route_rule_t, hit_count) == 72);
static_assert(sizeof(jmx_route_rule_t) == 88);

static void jmx_wan_proc_dir_create(u8 wan_id);
static void jmx_wan_proc_dir_remove(u8 wan_id);
static int  jmx_route_stats_init_procfs(void);
static void jmx_route_stats_exit_procfs(void);

static jmx_wan_iface_t g_wans[JMX_MAX_WAN_IFACES];
static jmx_route_rule_t g_rules[JMX_MAX_ROUTE_RULES];
struct jmx_route_rule_enhancement_state {
	u16 prio;
	u32 flags;
};
static struct jmx_route_rule_enhancement_state
	g_rule_enhancements[JMX_MAX_ROUTE_RULES];
static int g_rule_count;

typedef struct jmx_carrier_prefix {
	u32 network;
	u32 mask;
	u8 carrier_id;
} jmx_carrier_prefix_t;

static jmx_carrier_prefix_t g_carriers[JMX_MAX_CARRIER_PREFIXES];
static int g_carrier_count;
static u32 g_wan_generation;
static u64 g_new_flow_seq[JMX_MAX_ROUTE_RULES];
static DEFINE_SPINLOCK(jmx_route_lock);

static u32 jmx_route_enhancements_nolock(u16 prio)
{
	int i;

	for (i = 0; i < JMX_MAX_ROUTE_RULES; i++)
		if (g_rule_enhancements[i].prio == prio)
			return g_rule_enhancements[i].flags;
	return 0;
}

static int jmx_route_set_enhancements_nolock(u16 prio, u32 flags)
{
	int i;
	int free_slot = -1;

	for (i = 0; i < JMX_MAX_ROUTE_RULES; i++) {
		if (g_rule_enhancements[i].prio == prio) {
			g_rule_enhancements[i].flags = flags;
			return 0;
		}
		if (!g_rule_enhancements[i].prio && free_slot < 0)
			free_slot = i;
	}
	if (free_slot < 0)
		return -ENOSPC;
	g_rule_enhancements[free_slot].prio = prio;
	g_rule_enhancements[free_slot].flags = flags;
	return 0;
}

static void jmx_route_clear_enhancements_nolock(u16 prio)
{
	int i;

	for (i = 0; i < JMX_MAX_ROUTE_RULES; i++)
		if (g_rule_enhancements[i].prio == prio) {
			memset(&g_rule_enhancements[i], 0,
			       sizeof(g_rule_enhancements[i]));
			return;
		}
}

/*
 * appid -> category slot map.
 *
 * jmxd pushes `SELECT app_id, category_id FROM app` down after it opens the
 * signature database.  Lookups happen once per flow (at bind time), not per
 * packet, so a chained hash over a fixed bucket array is sufficient and needs
 * no allocation on the forwarding path.
 */
#define JMX_APP_CAT_BUCKETS 1024
#define JMX_APP_CAT_ENTRIES 65536

struct jmx_app_cat_entry {
	u32 appid;
	u8  cat_slot;
	s32 next;   /* index into g_app_cat_pool, -1 terminates */
};

static struct jmx_app_cat_entry *g_app_cat_pool;
static s32 g_app_cat_bucket[JMX_APP_CAT_BUCKETS];
static s32 g_app_cat_used;
static DEFINE_SPINLOCK(jmx_app_cat_lock);

/* Slot 0 is Unknown; slots 1..17 mirror app_category ids 1..17. */
static const char *const jmx_app_cat_names[JMX_APP_CAT_SLOTS] = {
	"Unknown", "Chat", "Game", "Video", "Shopping", "Music",
	"Job", "Download", "Web", "Education", "Life", "Tool",
	"Cloud", "Enterprise", "Finance", "Protocol", "Security", "AI",
};

const char *jmx_app_cat_name(u8 cat_slot)
{
	if (cat_slot >= JMX_APP_CAT_SLOTS)
		return jmx_app_cat_names[JMX_APP_CAT_UNKNOWN];
	return jmx_app_cat_names[cat_slot];
}

static inline u8 jmx_app_cat_slot_from_db(u16 db_category_id)
{
	if (db_category_id == 0 || db_category_id == JMX_APP_CAT_DB_UNKNOWN)
		return JMX_APP_CAT_UNKNOWN;
	if (db_category_id < JMX_APP_CAT_SLOTS)
		return (u8)db_category_id;
	/* Unseen category id from a newer database: count as unknown rather
	 * than silently folding it into an unrelated category. */
	return JMX_APP_CAT_UNKNOWN;
}

static inline u32 jmx_app_cat_hash(u32 appid)
{
	return jhash_1word(appid, 0x9f2ac31b) & (JMX_APP_CAT_BUCKETS - 1);
}

int jmx_app_cat_add(u32 appid, u16 db_category_id)
{
	unsigned long flags;
	u32 bucket;
	s32 idx;
	int rc = 0;

	if (!appid)
		return -EINVAL;

	spin_lock_irqsave(&jmx_app_cat_lock, flags);
	if (!g_app_cat_pool) {
		rc = -ENOMEM;
		goto out;
	}
	bucket = jmx_app_cat_hash(appid);
	for (idx = g_app_cat_bucket[bucket]; idx >= 0;
	     idx = g_app_cat_pool[idx].next) {
		if (g_app_cat_pool[idx].appid == appid) {
			g_app_cat_pool[idx].cat_slot =
				jmx_app_cat_slot_from_db(db_category_id);
			goto out;
		}
	}
	if (g_app_cat_used >= JMX_APP_CAT_ENTRIES) {
		rc = -ENOSPC;
		goto out;
	}
	idx = g_app_cat_used++;
	g_app_cat_pool[idx].appid = appid;
	g_app_cat_pool[idx].cat_slot = jmx_app_cat_slot_from_db(db_category_id);
	g_app_cat_pool[idx].next = g_app_cat_bucket[bucket];
	g_app_cat_bucket[bucket] = idx;
out:
	spin_unlock_irqrestore(&jmx_app_cat_lock, flags);
	return rc;
}

void jmx_app_cat_flush(void)
{
	unsigned long flags;
	int i;

	spin_lock_irqsave(&jmx_app_cat_lock, flags);
	for (i = 0; i < JMX_APP_CAT_BUCKETS; i++)
		g_app_cat_bucket[i] = -1;
	g_app_cat_used = 0;
	spin_unlock_irqrestore(&jmx_app_cat_lock, flags);
}

u8 jmx_app_cat_slot(u32 appid)
{
	unsigned long flags;
	u8 slot = JMX_APP_CAT_UNKNOWN;
	u32 bucket;
	s32 idx;

	if (!appid)
		return JMX_APP_CAT_UNKNOWN;

	spin_lock_irqsave(&jmx_app_cat_lock, flags);
	if (!g_app_cat_pool)
		goto out;
	bucket = jmx_app_cat_hash(appid);
	for (idx = g_app_cat_bucket[bucket]; idx >= 0;
	     idx = g_app_cat_pool[idx].next) {
		if (g_app_cat_pool[idx].appid == appid) {
			slot = g_app_cat_pool[idx].cat_slot;
			break;
		}
	}
out:
	spin_unlock_irqrestore(&jmx_app_cat_lock, flags);
	return slot;
}

int jmx_app_cat_map_count(void)
{
	unsigned long flags;
	int n;

	spin_lock_irqsave(&jmx_app_cat_lock, flags);
	n = g_app_cat_used;
	spin_unlock_irqrestore(&jmx_app_cat_lock, flags);
	return n;
}

struct jmx_route_flow_key {
	u8 family;
	u8 proto;
	u16 src_port;
	u16 dst_port;
	u32 appid;
	union {
		struct {
			u32 src;
			u32 dst;
		} v4;
		struct {
			const struct in6_addr *src;
			const struct in6_addr *dst;
		} v6;
	} addr;
};

static inline int jmx_wan_idx_valid(u8 wan_id)
{
	return wan_id > 0 && wan_id <= JMX_MAX_WAN_IFACES;
}

static inline jmx_wan_iface_t *jmx_wan_by_id_nolock(u8 wan_id)
{
	if (!jmx_wan_idx_valid(wan_id))
		return NULL;
	if (g_wans[wan_id - 1].wan_id != wan_id)
		return NULL;
	return &g_wans[wan_id - 1];
}

static u32 jmx_wan_next_generation_nolock(void)
{
	g_wan_generation++;
	if (!g_wan_generation)
		g_wan_generation++;
	return g_wan_generation;
}

int jmx_wan_register(u8 wan_id, const char *name, u32 fwmark, u32 table_id,
		     u32 gateway, u32 weight)
{
	jmx_wan_iface_t *wan;
	char normalized_name[sizeof(wan->name)];
	u32 effective_table;
	unsigned long flags;
	bool new_incarnation;

	if (!jmx_wan_idx_valid(wan_id) || !fwmark || !weight)
		return -EINVAL;

	strscpy(normalized_name, name ? name : "", sizeof(normalized_name));
	effective_table = table_id ? table_id : (JMX_ROUTE_TABLE_BASE + wan_id);
	spin_lock_irqsave(&jmx_route_lock, flags);
	wan = &g_wans[wan_id - 1];
	new_incarnation = wan->wan_id != wan_id || wan->fwmark != fwmark ||
		wan->table_id != effective_table ||
		strncmp(wan->name, normalized_name, sizeof(wan->name));
	if (new_incarnation) {
		int c;
		memset(wan, 0, sizeof(*wan));
		wan->generation = jmx_wan_next_generation_nolock();
		atomic64_set(&wan->rx_bytes, 0);
		atomic64_set(&wan->active_conn, 0);
		for (c = 0; c < JMX_APP_CAT_SLOTS; c++) {
			atomic64_set(&wan->cats[c].active_conn, 0);
			atomic64_set(&wan->cats[c].tx_packets, 0);
			atomic64_set(&wan->cats[c].rx_packets, 0);
			atomic64_set(&wan->cats[c].tx_bytes, 0);
			atomic64_set(&wan->cats[c].rx_bytes, 0);
		}
		wan->health = 1;
		wan->adaptive_weight = 100;
	}
	wan->wan_id = wan_id;
	strscpy(wan->name, normalized_name, sizeof(wan->name));
	wan->fwmark = fwmark;
	wan->table_id = effective_table;
	wan->gateway = gateway;
	wan->weight = weight;
	spin_unlock_irqrestore(&jmx_route_lock, flags);

	/* proc_mkdir() may sleep, so it must stay outside jmx_route_lock. */
	jmx_wan_proc_dir_create(wan_id);

	JMX_DEBUG_RATELIMITED(1,
		"jmx_route: register wan id=%u name=%s fwmark=0x%x table=%u weight=%u\n",
		wan_id, name ? name : "", fwmark, effective_table, weight);
	return 0;
}

int jmx_wan_set_weight(u8 wan_id, u32 weight)
{
	jmx_wan_iface_t *wan;
	unsigned long flags;
	u32 old_weight = 0;
	bool changed = false;

	if (!jmx_wan_idx_valid(wan_id) || weight < 1 || weight > 100)
		return -EINVAL;

	spin_lock_irqsave(&jmx_route_lock, flags);
	wan = jmx_wan_by_id_nolock(wan_id);
	if (!wan) {
		spin_unlock_irqrestore(&jmx_route_lock, flags);
		return -ENOENT;
	}
	old_weight = wan->weight;
	wan->weight = weight;
	changed = old_weight != weight;
	spin_unlock_irqrestore(&jmx_route_lock, flags);

	if (changed)
		JMX_DEBUG_RATELIMITED(1,
			"jmx_route: wan weight changed id=%u old=%u new=%u\n",
			wan_id, old_weight, weight);
	return 0;
}

int jmx_wan_set_adaptive_weight(u8 wan_id, u32 weight)
{
	jmx_wan_iface_t *wan;
	unsigned long flags;
	u32 old_weight = 0;
	bool changed = false;

	if (!jmx_wan_idx_valid(wan_id) || weight < 1 || weight > 100)
		return -EINVAL;

	spin_lock_irqsave(&jmx_route_lock, flags);
	wan = jmx_wan_by_id_nolock(wan_id);
	if (!wan) {
		spin_unlock_irqrestore(&jmx_route_lock, flags);
		return -ENOENT;
	}
	old_weight = wan->adaptive_weight;
	wan->adaptive_weight = weight;
	changed = old_weight != weight;
	spin_unlock_irqrestore(&jmx_route_lock, flags);

	if (changed)
		JMX_DEBUG_RATELIMITED(1,
			"jmx_route: wan adaptive weight changed id=%u old=%u new=%u\n",
			wan_id, old_weight, weight);
	return 0;
}

void jmx_wan_unregister(u8 wan_id)
{
	unsigned long flags;

	if (!jmx_wan_idx_valid(wan_id))
		return;

	spin_lock_irqsave(&jmx_route_lock, flags);
	memset(&g_wans[wan_id - 1], 0, sizeof(g_wans[wan_id - 1]));
	spin_unlock_irqrestore(&jmx_route_lock, flags);

	/* remove_proc_entry() may sleep; keep it outside the lock as well. */
	jmx_wan_proc_dir_remove(wan_id);
}

void jmx_wan_set_health(u8 wan_id, u8 health)
{
	jmx_wan_iface_t *wan;
	unsigned long flags;
	u8 old_health = 0;
	bool changed = false;

	if (!jmx_wan_idx_valid(wan_id))
		return;

	spin_lock_irqsave(&jmx_route_lock, flags);
	wan = jmx_wan_by_id_nolock(wan_id);
	if (wan) {
		old_health = wan->health;
		wan->health = health ? 1 : 0;
		changed = old_health != wan->health;
	}
	spin_unlock_irqrestore(&jmx_route_lock, flags);
	if (changed)
		JMX_DEBUG_RATELIMITED(1,
			"jmx_route: wan health changed id=%u old=%u new=%u\n",
			wan_id, old_health, health ? 1 : 0);
}

jmx_wan_iface_t *jmx_wan_find(u8 wan_id)
{
	if (!jmx_wan_idx_valid(wan_id))
		return NULL;
	return jmx_wan_by_id_nolock(wan_id);
}

int jmx_wan_get_count(void)
{
	int i, n = 0;
	unsigned long flags;

	spin_lock_irqsave(&jmx_route_lock, flags);
	for (i = 0; i < JMX_MAX_WAN_IFACES; i++)
		if (g_wans[i].wan_id)
			n++;
	spin_unlock_irqrestore(&jmx_route_lock, flags);
	return n;
}

void jmx_wan_flow_account_rx(u8 wan_id, u32 generation, u64 bytes)
{
	jmx_wan_iface_t *wan;
	unsigned long flags;

	if (!bytes || !generation || !jmx_wan_idx_valid(wan_id))
		return;

	spin_lock_irqsave(&jmx_route_lock, flags);
	wan = jmx_wan_by_id_nolock(wan_id);
	if (wan && wan->generation == generation)
		atomic64_add(bytes, &wan->rx_bytes);
	spin_unlock_irqrestore(&jmx_route_lock, flags);
}

void jmx_wan_flow_release(u8 wan_id, u32 generation)
{
	jmx_wan_iface_t *wan;
	unsigned long flags;

	if (!generation || !jmx_wan_idx_valid(wan_id))
		return;

	spin_lock_irqsave(&jmx_route_lock, flags);
	wan = jmx_wan_by_id_nolock(wan_id);
	if (wan && wan->generation == generation &&
	    atomic64_read(&wan->active_conn) > 0)
		atomic64_dec(&wan->active_conn);
	spin_unlock_irqrestore(&jmx_route_lock, flags);
}

/*
 * Replace active_conn with a figure measured from the conntrack table.
 *
 * The incremental gauge drifts upward and cannot be trusted on its own: the
 * increment in jmx_route_select_wan_internal(acquire=true) is unconditional,
 * while jmx_wan_flow_release() decrements only when the caller's generation
 * still matches the live WAN and the counter is above zero. Every mismatch
 * silently drops a decrement. On 30.1 the per-WAN total reached 35x the global
 * nf_conntrack_count after ~43h, with roughly 41% of new bindings never
 * decremented -- pppoe redial cycles the generation, so each redial abandons
 * the decrements of every flow still in flight.
 *
 * The caller counts route-bound flows per WAN by walking conntrack, then hands
 * the result here. Bounded by the WAN id space and called from process context
 * on a periodic worker, never from the forwarding path.
 *
 * generation is checked so a WAN re-registered mid-walk is not assigned a count
 * gathered against its previous incarnation; such a WAN keeps whatever the
 * register path zeroed it to and is corrected on the next pass.
 *
 * counts is indexed by wan_id - 1, matching g_wans; cat_counts is the same
 * indexing flattened over JMX_APP_CAT_SLOTS and may be NULL to leave the
 * per-category gauges untouched.
 *
 * Flows that bind between the walk and this assignment are lost from the new
 * value, so the result can sit one sampling interval behind by however many
 * flows arrived during the walk. That is bounded by the walk duration and
 * self-correcting on the next pass, unlike the unbounded upward drift it
 * replaces.
 */
void jmx_wan_active_conn_reconcile(const u64 *counts, const u64 *cat_counts,
				   const u32 *generations, u8 count)
{
	unsigned long flags;
	u8 i;

	if (!counts || !generations)
		return;
	if (count > JMX_MAX_WAN_IFACES)
		count = JMX_MAX_WAN_IFACES;

	spin_lock_irqsave(&jmx_route_lock, flags);
	for (i = 0; i < count; i++) {
		jmx_wan_iface_t *wan = &g_wans[i];
		u8 c;

		if (!wan->wan_id || !generations[i] ||
		    wan->generation != generations[i])
			continue;
		atomic64_set(&wan->active_conn, (s64)counts[i]);
		if (!cat_counts)
			continue;
		/*
		 * The per-category gauges are acquired and released by the same
		 * asymmetric pair, so they drift for the same reason and are
		 * corrected in the same pass. Keeping them in one critical
		 * section is what makes sum(cats) == active_conn hold for a
		 * reader, rather than being true only between two updates.
		 */
		for (c = 0; c < JMX_APP_CAT_SLOTS; c++)
			atomic64_set(&wan->cats[c].active_conn,
				     (s64)cat_counts[i * JMX_APP_CAT_SLOTS + c]);
	}
	spin_unlock_irqrestore(&jmx_route_lock, flags);
}

/*
 * Snapshot each WAN's current generation so the caller can walk conntrack
 * without holding jmx_route_lock and still detect a WAN that changed underneath
 * it. Returns the highest registered wan_id, or 0 when none are registered.
 */
u8 jmx_wan_generation_snapshot(u32 *generations, u8 count)
{
	unsigned long flags;
	u8 highest = 0;
	u8 i;

	if (!generations || !count)
		return 0;
	if (count > JMX_MAX_WAN_IFACES)
		count = JMX_MAX_WAN_IFACES;

	spin_lock_irqsave(&jmx_route_lock, flags);
	for (i = 0; i < count; i++) {
		generations[i] = g_wans[i].wan_id ? g_wans[i].generation : 0;
		if (g_wans[i].wan_id)
			highest = (u8)(i + 1);
	}
	spin_unlock_irqrestore(&jmx_route_lock, flags);
	return highest;
}

void jmx_wan_flow_account(u8 wan_id, u32 generation, u8 cat_slot,
			  u64 bytes, bool is_reply)
{
	jmx_wan_iface_t *wan;
	jmx_wan_cat_stat_t *cat;
	unsigned long flags;

	if (!bytes || !generation || !jmx_wan_idx_valid(wan_id))
		return;
	if (cat_slot >= JMX_APP_CAT_SLOTS)
		cat_slot = JMX_APP_CAT_UNKNOWN;

	spin_lock_irqsave(&jmx_route_lock, flags);
	wan = jmx_wan_by_id_nolock(wan_id);
	if (wan && wan->generation == generation) {
		cat = &wan->cats[cat_slot];
		if (is_reply) {
			/* Keep the legacy aggregate in step with the new table
			 * so /proc/dreamingwrt/jmx/jmx_route does not regress. */
			atomic64_add(bytes, &wan->rx_bytes);
			atomic64_add(bytes, &cat->rx_bytes);
			atomic64_inc(&cat->rx_packets);
		} else {
			atomic64_add(bytes, &cat->tx_bytes);
			atomic64_inc(&cat->tx_packets);
		}
	}
	spin_unlock_irqrestore(&jmx_route_lock, flags);
}

void jmx_wan_flow_cat_acquire(u8 wan_id, u32 generation, u8 cat_slot)
{
	jmx_wan_iface_t *wan;
	unsigned long flags;

	if (!generation || !jmx_wan_idx_valid(wan_id))
		return;
	if (cat_slot >= JMX_APP_CAT_SLOTS)
		cat_slot = JMX_APP_CAT_UNKNOWN;

	spin_lock_irqsave(&jmx_route_lock, flags);
	wan = jmx_wan_by_id_nolock(wan_id);
	if (wan && wan->generation == generation)
		atomic64_inc(&wan->cats[cat_slot].active_conn);
	spin_unlock_irqrestore(&jmx_route_lock, flags);
}

void jmx_wan_flow_cat_release(u8 wan_id, u32 generation, u8 cat_slot)
{
	jmx_wan_iface_t *wan;
	unsigned long flags;

	if (!generation || !jmx_wan_idx_valid(wan_id))
		return;
	if (cat_slot >= JMX_APP_CAT_SLOTS)
		cat_slot = JMX_APP_CAT_UNKNOWN;

	spin_lock_irqsave(&jmx_route_lock, flags);
	wan = jmx_wan_by_id_nolock(wan_id);
	if (wan && wan->generation == generation &&
	    atomic64_read(&wan->cats[cat_slot].active_conn) > 0)
		atomic64_dec(&wan->cats[cat_slot].active_conn);
	spin_unlock_irqrestore(&jmx_route_lock, flags);
}

static int jmx_route_rule_cmp(const void *a, const void *b)
{
	const jmx_route_rule_t *ra = a;
	const jmx_route_rule_t *rb = b;

	if (ra->prio < rb->prio)
		return -1;
	if (ra->prio > rb->prio)
		return 1;
	return 0;
}

static void jmx_route_sort_rules_nolock(void)
{
	/* small fixed array: insertion sort avoids depending on kernel sort() */
	int i, j;
	for (i = 1; i < g_rule_count; i++) {
		jmx_route_rule_t key = g_rules[i];
		j = i - 1;
		while (j >= 0 && jmx_route_rule_cmp(&g_rules[j], &key) > 0) {
			g_rules[j + 1] = g_rules[j];
			j--;
		}
		g_rules[j + 1] = key;
	}
}


int jmx_carrier_prefix_add(u32 network, u32 mask, u8 carrier_id)
{
	unsigned long flags;

	if (!mask || !carrier_id)
		return -EINVAL;

	spin_lock_irqsave(&jmx_route_lock, flags);
	if (g_carrier_count >= JMX_MAX_CARRIER_PREFIXES) {
		spin_unlock_irqrestore(&jmx_route_lock, flags);
		return -ENOSPC;
	}
	g_carriers[g_carrier_count].network = network & mask;
	g_carriers[g_carrier_count].mask = mask;
	g_carriers[g_carrier_count].carrier_id = carrier_id;
	g_carrier_count++;
	spin_unlock_irqrestore(&jmx_route_lock, flags);
	return 0;
}

void jmx_carrier_prefix_flush(void)
{
	unsigned long flags;
	spin_lock_irqsave(&jmx_route_lock, flags);
	memset(g_carriers, 0, sizeof(g_carriers));
	g_carrier_count = 0;
	spin_unlock_irqrestore(&jmx_route_lock, flags);
}

static u8 jmx_carrier_lookup_nolock(u32 ip)
{
	int i;
	u8 carrier = JMX_CARRIER_ANY;
	u32 best_mask = 0;

	for (i = 0; i < g_carrier_count; i++) {
		jmx_carrier_prefix_t *p = &g_carriers[i];
		if ((ip & p->mask) != p->network)
			continue;
		if (ntohl(p->mask) >= ntohl(best_mask)) {
			best_mask = p->mask;
			carrier = p->carrier_id;
		}
	}
	return carrier;
}

u8 jmx_carrier_lookup(u32 ip)
{
	unsigned long flags;
	u8 carrier;

	spin_lock_irqsave(&jmx_route_lock, flags);
	carrier = jmx_carrier_lookup_nolock(ip);
	spin_unlock_irqrestore(&jmx_route_lock, flags);
	return carrier;
}

int jmx_route_rule_add_with_enhancements(const jmx_route_rule_t *rule,
						 u32 enhancements)
{
	int i;
	unsigned long flags;

	if (!rule || !rule->enabled || rule->wan_count == 0 ||
	    rule->wan_count > JMX_MAX_WAN_IFACES ||
	    rule->sticky_mode > JMX_STICKY_MAX ||
	    (enhancements & ~JMX_ROUTE_ENHANCEMENT_KNOWN))
		return -EINVAL;

	spin_lock_irqsave(&jmx_route_lock, flags);

	/* replace same prio rule */
	for (i = 0; i < g_rule_count; i++) {
		if (g_rules[i].prio == rule->prio) {
			u64 hit_count = g_rules[i].hit_count;
			u64 last_hit_jiffies = g_rules[i].last_hit_jiffies;
			g_rules[i] = *rule;
			g_rules[i].hit_count = hit_count;
			g_rules[i].last_hit_jiffies = last_hit_jiffies;
			if (jmx_route_set_enhancements_nolock(rule->prio, enhancements)) {
				spin_unlock_irqrestore(&jmx_route_lock, flags);
				return -ENOSPC;
			}
			jmx_route_sort_rules_nolock();
			memset(g_new_flow_seq, 0, sizeof(g_new_flow_seq));
			spin_unlock_irqrestore(&jmx_route_lock, flags);
			return 0;
		}
	}

	if (g_rule_count >= JMX_MAX_ROUTE_RULES) {
		spin_unlock_irqrestore(&jmx_route_lock, flags);
		return -ENOSPC;
	}

	g_rules[g_rule_count++] = *rule;
	if (jmx_route_set_enhancements_nolock(rule->prio, enhancements)) {
		g_rule_count--;
		spin_unlock_irqrestore(&jmx_route_lock, flags);
		return -ENOSPC;
	}
	jmx_route_sort_rules_nolock();
	memset(g_new_flow_seq, 0, sizeof(g_new_flow_seq));
	spin_unlock_irqrestore(&jmx_route_lock, flags);
	return 0;
}

int jmx_route_rule_add(const jmx_route_rule_t *rule)
{
	return jmx_route_rule_add_with_enhancements(rule, 0);
}

void jmx_route_rule_del(u16 prio)
{
	int i, j;
	unsigned long flags;

	spin_lock_irqsave(&jmx_route_lock, flags);
	for (i = 0; i < g_rule_count; i++) {
		if (g_rules[i].prio != prio)
			continue;
		for (j = i; j < g_rule_count - 1; j++)
			g_rules[j] = g_rules[j + 1];
		memset(&g_rules[g_rule_count - 1], 0, sizeof(g_rules[0]));
		jmx_route_clear_enhancements_nolock(prio);
		g_rule_count--;
		memset(g_new_flow_seq, 0, sizeof(g_new_flow_seq));
		break;
	}
	spin_unlock_irqrestore(&jmx_route_lock, flags);
}


void jmx_route_rule_clear_hits(u16 prio)
{
	int i;
	unsigned long flags;

	spin_lock_irqsave(&jmx_route_lock, flags);
	for (i = 0; i < g_rule_count; i++) {
		if (prio && g_rules[i].prio != prio)
			continue;
		g_rules[i].hit_count = 0;
		g_rules[i].last_hit_jiffies = 0;
	}
	spin_unlock_irqrestore(&jmx_route_lock, flags);
}

void jmx_route_rule_flush(void)
{
	unsigned long flags;

	spin_lock_irqsave(&jmx_route_lock, flags);
	memset(g_rules, 0, sizeof(g_rules));
	memset(g_rule_enhancements, 0, sizeof(g_rule_enhancements));
	memset(g_new_flow_seq, 0, sizeof(g_new_flow_seq));
	g_rule_count = 0;
	memset(g_carriers, 0, sizeof(g_carriers));
	g_carrier_count = 0;
	spin_unlock_irqrestore(&jmx_route_lock, flags);
}

static inline int jmx_ip_match(u32 ip, u32 rule_ip, u32 mask)
{
	if (!rule_ip || !mask)
		return 1;
	return (ip & mask) == (rule_ip & mask);
}

static int jmx_rule_match(const jmx_route_rule_t *r,
			  const struct jmx_route_flow_key *key)
{
	if (!r->enabled)
		return 0;
	if (r->proto && r->proto != key->proto)
		return 0;
	if (r->appid && r->appid != key->appid)
		return 0;
	if (r->dst_port && r->dst_port != key->dst_port)
		return 0;

	if (key->family == AF_INET) {
		if (r->carrier_id &&
		    r->carrier_id != jmx_carrier_lookup_nolock(key->addr.v4.dst))
			return 0;
		if (!jmx_ip_match(key->addr.v4.src, r->src_addr, r->src_mask))
			return 0;
		if (!jmx_ip_match(key->addr.v4.dst, r->dst_addr, r->dst_mask))
			return 0;
		return 1;
	}

	if (key->family != AF_INET6 || !key->addr.v6.src || !key->addr.v6.dst)
		return 0;

	/* The current route wire ABI carries only IPv4 prefixes and carriers.
	 * Until it grows an address-family field, only family-neutral rules may
	 * select IPv6. This prevents an IPv4-specific rule from matching IPv6. */
	if (r->carrier_id || r->src_addr || r->src_mask ||
	    r->dst_addr || r->dst_mask)
		return 0;
	return 1;
}

static u32 jmx_route_hash4(const jmx_route_rule_t *r,
			   const struct jmx_route_flow_key *key)
{
	u32 src_ip = key->addr.v4.src;
	u32 dst_ip = key->addr.v4.dst;
	u16 src_port = key->src_port;
	u16 dst_port = key->dst_port;
	u8 proto = key->proto;

	switch (r->sticky_mode) {
	case JMX_STICKY_SIP:
		return jhash_1word(src_ip, 0x51a7e001);
	case JMX_STICKY_SIP_SPORT:
		return jhash_2words(src_ip, src_port, 0x51a7e002);
	case JMX_STICKY_SIP_DIP:
		return jhash_2words(src_ip, dst_ip, 0x51a7e003);
	case JMX_STICKY_SIP_DIP_DPORT:
		return jhash_3words(src_ip, dst_ip, dst_port, 0x51a7e004);
	case JMX_STICKY_5TUPLE:
		return jhash_3words(src_ip ^ dst_ip, ((u32)src_port << 16) | dst_port,
					((u32)proto << 24) | r->prio, 0x51a7e005);
	case JMX_STICKY_PRIMARY_BACKUP:
		return 0;
	case JMX_STICKY_DOWNLOAD:
	case JMX_STICKY_CONN_CNT:
	case JMX_STICKY_ADAPTIVE_PENALTY:
		return jhash_3words(src_ip ^ dst_ip,
				    ((u32)src_port << 16) | dst_port,
				    ((u32)proto << 24) | r->prio, 0x51a7e006);
	case JMX_STICKY_NEW_CONN:
	default:
		return jhash_3words(src_ip, dst_ip, ((u32)src_port << 16) | dst_port, jiffies);
	}
}

static u32 jmx_route_hash6(const jmx_route_rule_t *r,
			   const struct jmx_route_flow_key *key)
{
	u32 words[10];

	memcpy(words, key->addr.v6.src, sizeof(struct in6_addr));
	memcpy(words + 4, key->addr.v6.dst, sizeof(struct in6_addr));

	switch (r->sticky_mode) {
	case JMX_STICKY_SIP:
		return jhash2(words, 4, 0x51a7e001);
	case JMX_STICKY_SIP_SPORT:
		words[4] = key->src_port;
		return jhash2(words, 5, 0x51a7e002);
	case JMX_STICKY_SIP_DIP:
		return jhash2(words, 8, 0x51a7e003);
	case JMX_STICKY_SIP_DIP_DPORT:
		words[8] = key->dst_port;
		return jhash2(words, 9, 0x51a7e004);
	case JMX_STICKY_5TUPLE:
		words[8] = ((u32)key->src_port << 16) | key->dst_port;
		words[9] = ((u32)key->proto << 24) | r->prio;
		return jhash2(words, 10, 0x51a7e005);
	case JMX_STICKY_PRIMARY_BACKUP:
		return 0;
	case JMX_STICKY_DOWNLOAD:
	case JMX_STICKY_CONN_CNT:
	case JMX_STICKY_ADAPTIVE_PENALTY:
		words[8] = ((u32)key->src_port << 16) | key->dst_port;
		words[9] = ((u32)key->proto << 24) | r->prio;
		return jhash2(words, 10, 0x51a7e006);
	case JMX_STICKY_NEW_CONN:
	default:
		words[8] = ((u32)key->src_port << 16) | key->dst_port;
		words[9] = key->proto;
		return jhash2(words, 10, jiffies);
	}
}

static u32 jmx_route_hash(const jmx_route_rule_t *r,
			  const struct jmx_route_flow_key *key)
{
	if (key->family == AF_INET6)
		return jmx_route_hash6(r, key);
	return jmx_route_hash4(r, key);
}

static int jmx_weighted_metric_cmp(u64 left, u64 left_weight,
				   u64 right, u64 right_weight)
{
	u64 left_q = div64_u64(left, left_weight);
	u64 right_q = div64_u64(right, right_weight);
	u64 left_r;
	u64 right_r;
	u64 left_fraction;
	u64 right_fraction;

	if (left_q < right_q)
		return -1;
	if (left_q > right_q)
		return 1;

	left_r = (u32)(left - left_q * left_weight);
	right_r = (u32)(right - right_q * right_weight);
	left_fraction = (u64)left_r * right_weight;
	right_fraction = (u64)right_r * left_weight;
	if (left_fraction < right_fraction)
		return -1;
	if (left_fraction > right_fraction)
		return 1;
	return 0;
}

struct jmx_route_candidate {
	jmx_wan_iface_t *wan;
	u32 policy_weight;
};

static u64 jmx_selection_weight(const struct jmx_route_candidate *candidate,
					bool adaptive);

static jmx_wan_iface_t *
jmx_weighted_tie_select(const struct jmx_route_candidate *candidates,
			int count, u32 hash, bool adaptive)
{
	u64 total_weight = 0;
	u64 point;
	u64 hash64;
	int i;

	for (i = 0; i < count; i++)
		total_weight += jmx_selection_weight(&candidates[i], adaptive);
	if (!total_weight)
		return candidates[hash % count].wan;

	hash64 = ((u64)hash << 32) | jhash_1word(hash, 0x51a7e007);
	point = hash64 % total_weight;
	for (i = 0; i < count; i++) {
		if (point < jmx_selection_weight(&candidates[i], adaptive))
			return candidates[i].wan;
		point -= jmx_selection_weight(&candidates[i], adaptive);
	}
	return candidates[count - 1].wan;
}

static u64 jmx_selection_weight(const struct jmx_route_candidate *candidate,
				bool adaptive)
{
	u64 weight = candidate->policy_weight;

	if (adaptive)
		weight *= candidate->wan->adaptive_weight ?
			candidate->wan->adaptive_weight : 100;
	return weight;
}

static jmx_wan_iface_t *
jmx_weighted_slot_select(const struct jmx_route_candidate *candidates,
			 int count, u64 slot, bool adaptive)
{
	u64 total_weight = 0;
	u64 point;
	int i;

	for (i = 0; i < count; i++)
		total_weight += jmx_selection_weight(&candidates[i], adaptive);
	if (!total_weight)
		return candidates[slot % count].wan;

	point = slot % total_weight;
	for (i = 0; i < count; i++) {
		u64 weight = jmx_selection_weight(&candidates[i], adaptive);

		if (point < weight)
			return candidates[i].wan;
		point -= weight;
	}
	return candidates[count - 1].wan;
}

static jmx_wan_iface_t *
jmx_select_min_metric_nolock(const struct jmx_route_candidate *candidates,
			     int count, bool by_connections, u32 hash, bool adaptive)
{
	struct jmx_route_candidate ties[JMX_MAX_WAN_IFACES];
	u64 best_metric;
	int i;
	int tie_count = 1;

	ties[0] = candidates[0];
	best_metric = by_connections ?
		(u64)atomic64_read(&candidates[0].wan->active_conn) :
		(u64)atomic64_read(&candidates[0].wan->rx_bytes);

	for (i = 1; i < count; i++) {
		u64 metric = by_connections ?
			(u64)atomic64_read(&candidates[i].wan->active_conn) :
			(u64)atomic64_read(&candidates[i].wan->rx_bytes);
		int cmp = jmx_weighted_metric_cmp(metric,
			jmx_selection_weight(&candidates[i], adaptive),
			best_metric,
			jmx_selection_weight(&ties[0], adaptive));

		if (cmp < 0) {
			ties[0] = candidates[i];
			best_metric = metric;
			tie_count = 1;
		} else if (cmp == 0) {
			ties[tie_count++] = candidates[i];
		}
	}

	return jmx_weighted_tie_select(ties, tie_count, hash, adaptive);
}

static jmx_wan_iface_t *jmx_select_wan_nolock(jmx_route_rule_t *r,
					       const struct jmx_route_flow_key *key)
{
	struct jmx_route_candidate candidates[JMX_MAX_WAN_IFACES];
	int rule_idx = r - g_rules;
	u32 hash;
	u32 enhancements = jmx_route_enhancements_nolock(r->prio);
	bool adaptive = (enhancements & JMX_ROUTE_ENHANCEMENT_ADAPTIVE_PENALTY) ||
			r->sticky_mode == JMX_STICKY_ADAPTIVE_PENALTY;
	int i, n = 0;

	for (i = 0; i < r->wan_count && i < JMX_MAX_WAN_IFACES; i++) {
		jmx_wan_iface_t *wan = jmx_wan_by_id_nolock(r->wan_ids[i]);
		if (!wan || !wan->health || !wan->fwmark)
			continue;
		candidates[n].wan = wan;
		candidates[n].policy_weight = r->wan_weights[i] ?
			r->wan_weights[i] : wan->weight;
		if (!candidates[n].policy_weight)
			candidates[n].policy_weight = 1;
		n++;
	}

	if (n == 0)
		return NULL;

	if (r->sticky_mode == JMX_STICKY_PRIMARY_BACKUP)
		return candidates[0].wan;
	if (r->sticky_mode == JMX_STICKY_DOWNLOAD)
		return jmx_select_min_metric_nolock(candidates, n, false,
			jmx_route_hash(r, key), adaptive);
	if (r->sticky_mode == JMX_STICKY_CONN_CNT)
		return jmx_select_min_metric_nolock(candidates, n, true,
			jmx_route_hash(r, key), adaptive);

	if ((r->sticky_mode == JMX_STICKY_NEW_CONN ||
	     r->sticky_mode == JMX_STICKY_ADAPTIVE_PENALTY) &&
	    rule_idx >= 0 && rule_idx < JMX_MAX_ROUTE_RULES)
		return jmx_weighted_slot_select(candidates, n,
			g_new_flow_seq[rule_idx]++,
			adaptive);

	hash = jmx_route_hash(r, key);
	return jmx_weighted_slot_select(candidates, n,
		((u64)hash << 32) | jhash_1word(hash, 0x51a7e008), adaptive);
}

static int jmx_route_select_wan_internal(const struct jmx_route_flow_key *key,
					 u32 *out_fwmark, u8 *out_wan_id,
					 u8 *out_route_source, u16 *out_rule_prio,
					 bool acquire, u32 *out_wan_generation)
{
	int i;
	unsigned long flags;
	int ret = -ENOENT;

	if (out_fwmark)
		*out_fwmark = 0;
	if (out_wan_id)
		*out_wan_id = 0;
	if (out_route_source)
		*out_route_source = JMX_ROUTE_SRC_DEFAULT;
	if (out_rule_prio)
		*out_rule_prio = 0;
	if (out_wan_generation)
		*out_wan_generation = 0;

	if (!key || (key->family != AF_INET && key->family != AF_INET6) ||
	    (key->family == AF_INET6 &&
	     (!key->addr.v6.src || !key->addr.v6.dst)))
		return -EINVAL;

	if (!out_fwmark || !out_wan_id || !out_route_source ||
	    (acquire && !out_wan_generation))
		return -EINVAL;

	spin_lock_irqsave(&jmx_route_lock, flags);
	for (i = 0; i < g_rule_count; i++) {
		jmx_route_rule_t *r = &g_rules[i];
		jmx_wan_iface_t *wan;

		if (!jmx_rule_match(r, key))
			continue;

		wan = jmx_select_wan_nolock(r, key);
		if (!wan)
			continue;

		r->hit_count++;
		r->last_hit_jiffies = jiffies;
		*out_fwmark = wan->fwmark;
		*out_wan_id = wan->wan_id;
		*out_route_source = r->appid ? JMX_ROUTE_SRC_APP : (r->carrier_id ? JMX_ROUTE_SRC_DOMAIN : JMX_ROUTE_SRC_TUPLE);
		if (out_rule_prio)
			*out_rule_prio = r->prio;
		if (acquire) {
			atomic64_inc(&wan->active_conn);
			*out_wan_generation = wan->generation;
		}
		ret = 0;
		break;
	}
	spin_unlock_irqrestore(&jmx_route_lock, flags);

	return ret;
}

int jmx_route_select_wan(u32 src_ip, u32 dst_ip, u16 src_port, u16 dst_port,
			 u8 proto, u32 appid, u32 *out_fwmark, u8 *out_wan_id,
			 u8 *out_route_source, u16 *out_rule_prio)
{
	struct jmx_route_flow_key key = { 0 };

	key.family = AF_INET;
	key.proto = proto;
	key.src_port = src_port;
	key.dst_port = dst_port;
	key.appid = appid;
	key.addr.v4.src = src_ip;
	key.addr.v4.dst = dst_ip;

	return jmx_route_select_wan_internal(&key, out_fwmark, out_wan_id,
					     out_route_source, out_rule_prio,
					     false, NULL);
}

int jmx_route_select_wan_acquire(u32 src_ip, u32 dst_ip, u16 src_port,
				 u16 dst_port, u8 proto, u32 appid,
				 u32 *out_fwmark, u8 *out_wan_id,
				 u8 *out_route_source, u16 *out_rule_prio,
				 u32 *out_wan_generation)
{
	struct jmx_route_flow_key key = { 0 };

	key.family = AF_INET;
	key.proto = proto;
	key.src_port = src_port;
	key.dst_port = dst_port;
	key.appid = appid;
	key.addr.v4.src = src_ip;
	key.addr.v4.dst = dst_ip;

	return jmx_route_select_wan_internal(&key, out_fwmark, out_wan_id,
					     out_route_source, out_rule_prio,
					     true, out_wan_generation);
}

int jmx_route_select_wan6(const struct in6_addr *src_ip,
			  const struct in6_addr *dst_ip, u16 src_port,
			  u16 dst_port, u8 proto, u32 appid,
			  u32 *out_fwmark, u8 *out_wan_id,
			  u8 *out_route_source, u16 *out_rule_prio)
{
	struct jmx_route_flow_key key = { 0 };

	key.family = AF_INET6;
	key.proto = proto;
	key.src_port = src_port;
	key.dst_port = dst_port;
	key.appid = appid;
	key.addr.v6.src = src_ip;
	key.addr.v6.dst = dst_ip;

	return jmx_route_select_wan_internal(&key, out_fwmark, out_wan_id,
					     out_route_source, out_rule_prio,
					     false, NULL);
}

int jmx_route_select_wan6_acquire(const struct in6_addr *src_ip,
				  const struct in6_addr *dst_ip, u16 src_port,
				  u16 dst_port, u8 proto, u32 appid,
				  u32 *out_fwmark, u8 *out_wan_id,
				  u8 *out_route_source, u16 *out_rule_prio,
				  u32 *out_wan_generation)
{
	struct jmx_route_flow_key key = { 0 };

	key.family = AF_INET6;
	key.proto = proto;
	key.src_port = src_port;
	key.dst_port = dst_port;
	key.appid = appid;
	key.addr.v6.src = src_ip;
	key.addr.v6.dst = dst_ip;

	return jmx_route_select_wan_internal(&key, out_fwmark, out_wan_id,
					     out_route_source, out_rule_prio,
					     true, out_wan_generation);
}

static int jmx_route_proc_show(struct seq_file *s, void *v)
{
	int i, j;
	unsigned long flags;

	(void)v;
	spin_lock_irqsave(&jmx_route_lock, flags);

	seq_printf(s, "RouteRuleAbi: 2 enhancements: 0x%x\n",
		   JMX_ROUTE_ENHANCEMENT_KNOWN);
	seq_printf(s, "CarrierPrefixes: %d\n\n", g_carrier_count);
	seq_puts(s, "WANs:\n");
	seq_puts(s, "id name fwmark table gateway health weight adaptive_weight active_conn rx_bytes generation rebind_requested rebind_killed rebind_sensitive rebind_mode rebind_at rebind_pending\n");
	for (i = 0; i < JMX_MAX_WAN_IFACES; i++) {
		jmx_wan_iface_t *w = &g_wans[i];
		struct jmx_wan_rebind_stats rebind;
		if (!w->wan_id)
			continue;
		jmx_wan_rebind_stats_snapshot(w->wan_id, &rebind);
		seq_printf(s, "%u %s 0x%x %u %pI4 %u %u %u %llu %llu %u %llu %llu %llu %u %llu %u\n",
			   w->wan_id, w->name, w->fwmark, w->table_id, &w->gateway,
			   w->health, w->weight, w->adaptive_weight,
			   (unsigned long long)atomic64_read(&w->active_conn),
			   (unsigned long long)atomic64_read(&w->rx_bytes),
			   w->generation,
			   (unsigned long long)rebind.requested,
			   (unsigned long long)rebind.killed,
			   (unsigned long long)rebind.skipped_sensitive,
			   rebind.last_mode,
			   (unsigned long long)rebind.last_at,
			   rebind.pending_mode);
	}

	seq_puts(s, "\nRules:\n");
	seq_puts(s, "prio en proto appid carrier src/mask dst/mask dport mode hits last_hit_s enhancements members\n");
	for (i = 0; i < g_rule_count; i++) {
		jmx_route_rule_t *r = &g_rules[i];
		seq_printf(s, "%u %u %u %u %u %pI4/%pI4 %pI4/%pI4 %u %u %llu %lu 0x%x ",
			   r->prio, r->enabled, r->proto, r->appid, r->carrier_id,
			   &r->src_addr, &r->src_mask, &r->dst_addr, &r->dst_mask,
			   r->dst_port, r->sticky_mode, r->hit_count,
			   (unsigned long)(r->last_hit_jiffies ? jiffies_to_msecs(jiffies - r->last_hit_jiffies) / 1000 : 0),
			   jmx_route_enhancements_nolock(r->prio));
		for (j = 0; j < r->wan_count && j < JMX_MAX_WAN_IFACES; j++) {
			jmx_wan_iface_t *wan = jmx_wan_by_id_nolock(r->wan_ids[j]);
			u32 weight = r->wan_weights[j] ? r->wan_weights[j] :
				(wan && wan->weight ? wan->weight : 1);

			seq_printf(s, "%u:%u%s", r->wan_ids[j], weight,
				   j + 1 == r->wan_count ? "" : ",");
		}
		seq_putc(s, '\n');
	}

	spin_unlock_irqrestore(&jmx_route_lock, flags);
	return 0;
}

static int jmx_route_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, jmx_route_proc_show, NULL);
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 5, 0)
static const struct file_operations jmx_route_proc_fops = {
	.owner = THIS_MODULE,
	.open = jmx_route_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
#else
static const struct proc_ops jmx_route_proc_fops = {
	.proc_flags = PROC_ENTRY_PERMANENT,
	.proc_open = jmx_route_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};
#endif

/* ===== per-WAN x per-category statistics proc surface =====
 *
 * Layout:
 *   /proc/dreamingwrt/jmx/wan<N>/proto_stats   one WAN, 18 category rows
 *   /proc/dreamingwrt/jmx/proto_stats          all WANs summed, same format
 *   /proc/dreamingwrt/jmx/if_stats             one summary row per WAN
 *
 * All three use single_open().  The tables are fixed size (at most
 * JMX_APP_CAT_SLOTS rows, or JMX_MAX_WAN_IFACES rows for if_stats), so the
 * whole snapshot fits comfortably in seq_file's buffer and there is no
 * start/next/show iterator that could re-enter and duplicate rows the way
 * iKuai's ik_summary does.
 */

#define JMX_CAT_COL_HDR \
	"category         active_conn        tx_packets        rx_packets              tx_bytes              rx_bytes\n"

struct jmx_cat_snapshot {
	u64 active_conn;
	u64 tx_packets;
	u64 rx_packets;
	u64 tx_bytes;
	u64 rx_bytes;
};

static void jmx_cat_snapshot_add_nolock(struct jmx_cat_snapshot *dst,
					const jmx_wan_cat_stat_t *src)
{
	dst->active_conn += (u64)atomic64_read(&src->active_conn);
	dst->tx_packets  += (u64)atomic64_read(&src->tx_packets);
	dst->rx_packets  += (u64)atomic64_read(&src->rx_packets);
	dst->tx_bytes    += (u64)atomic64_read(&src->tx_bytes);
	dst->rx_bytes    += (u64)atomic64_read(&src->rx_bytes);
}

static void jmx_cat_emit_table(struct seq_file *s,
				 const struct jmx_cat_snapshot *rows)
{
	struct jmx_cat_snapshot total = { 0 };
	unsigned int emitted = 0;
	int i;

	seq_puts(s, JMX_CAT_COL_HDR);
	for (i = 0; i < JMX_APP_CAT_SLOTS; i++) {
		seq_printf(s, "%-14s %11llu %17llu %17llu %21llu %21llu\n",
			   jmx_app_cat_name((u8)i),
			   rows[i].active_conn, rows[i].tx_packets,
			   rows[i].rx_packets, rows[i].tx_bytes,
			   rows[i].rx_bytes);
		emitted++;
		total.active_conn += rows[i].active_conn;
		total.tx_packets  += rows[i].tx_packets;
		total.rx_packets  += rows[i].rx_packets;
		total.tx_bytes    += rows[i].tx_bytes;
		total.rx_bytes    += rows[i].rx_bytes;
	}
	seq_printf(s, "%-14s %11llu %17llu %17llu %21llu %21llu\n",
		   "Total", total.active_conn, total.tx_packets,
		   total.rx_packets, total.tx_bytes, total.rx_bytes);
	emitted++;

	/* Acceptance asked for a self-check that the table cannot silently
	 * double its output.  Rows are category slots plus one Total row. */
	WARN_ONCE(emitted != JMX_APP_CAT_SLOTS + 1,
		  "jmx_route: proto_stats emitted %u rows, expected %d\n",
		  emitted, JMX_APP_CAT_SLOTS + 1);
}

static int jmx_wan_proto_stats_show(struct seq_file *s, void *v)
{
	struct jmx_cat_snapshot rows[JMX_APP_CAT_SLOTS];
	unsigned long wan_id = (unsigned long)s->private;
	jmx_wan_iface_t *wan;
	unsigned long flags;
	bool present = false;
	int i;

	(void)v;
	memset(rows, 0, sizeof(rows));

	spin_lock_irqsave(&jmx_route_lock, flags);
	wan = jmx_wan_by_id_nolock((u8)wan_id);
	if (wan) {
		present = true;
		for (i = 0; i < JMX_APP_CAT_SLOTS; i++)
			jmx_cat_snapshot_add_nolock(&rows[i], &wan->cats[i]);
	}
	spin_unlock_irqrestore(&jmx_route_lock, flags);

	if (!present) {
		/* The directory outlives an unregistered WAN only briefly; be
		 * explicit rather than printing a table of zeros that reads
		 * like real data. */
		seq_printf(s, "# wan%lu not registered\n", wan_id);
		return 0;
	}

	jmx_cat_emit_table(s, rows);
	return 0;
}

static int jmx_proto_stats_show(struct seq_file *s, void *v)
{
	struct jmx_cat_snapshot rows[JMX_APP_CAT_SLOTS];
	unsigned long flags;
	int i, w;

	(void)v;
	memset(rows, 0, sizeof(rows));

	spin_lock_irqsave(&jmx_route_lock, flags);
	for (w = 0; w < JMX_MAX_WAN_IFACES; w++) {
		if (!g_wans[w].wan_id)
			continue;
		for (i = 0; i < JMX_APP_CAT_SLOTS; i++)
			jmx_cat_snapshot_add_nolock(&rows[i], &g_wans[w].cats[i]);
	}
	spin_unlock_irqrestore(&jmx_route_lock, flags);

	jmx_cat_emit_table(s, rows);
	return 0;
}

static int jmx_if_stats_show(struct seq_file *s, void *v)
{
	struct jmx_cat_snapshot row;
	unsigned long flags;
	unsigned int emitted = 0, live = 0;
	int i, w;

	(void)v;
	seq_puts(s, "wan  name             active_conn        tx_packets        rx_packets              tx_bytes              rx_bytes\n");

	spin_lock_irqsave(&jmx_route_lock, flags);
	for (w = 0; w < JMX_MAX_WAN_IFACES; w++) {
		jmx_wan_iface_t *wan = &g_wans[w];

		if (!wan->wan_id)
			continue;
		live++;
		memset(&row, 0, sizeof(row));
		for (i = 0; i < JMX_APP_CAT_SLOTS; i++)
			jmx_cat_snapshot_add_nolock(&row, &wan->cats[i]);
		seq_printf(s, "%-4u %-14s %11llu %17llu %17llu %21llu %21llu\n",
			   wan->wan_id, wan->name[0] ? wan->name : "-",
			   row.active_conn, row.tx_packets, row.rx_packets,
			   row.tx_bytes, row.rx_bytes);
		emitted++;
	}
	spin_unlock_irqrestore(&jmx_route_lock, flags);

	WARN_ONCE(emitted != live,
		  "jmx_route: if_stats emitted %u rows for %u WANs\n",
		  emitted, live);
	return 0;
}

static int jmx_wan_proto_stats_open(struct inode *inode, struct file *file)
{
	/* PDE_DATA() was renamed to lowercase pde_data() in 5.17 and the old
	 * spelling was removed, so calling it on 7.2 yields an implicit
	 * declaration whose int return would be cast into the private pointer. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
	return single_open(file, jmx_wan_proto_stats_show, PDE_DATA(inode));
#else
	return single_open(file, jmx_wan_proto_stats_show, pde_data(inode));
#endif
}

static int jmx_proto_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, jmx_proto_stats_show, NULL);
}

static int jmx_if_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, jmx_if_stats_show, NULL);
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 5, 0)
#define JMX_CAT_FOPS(name, openfn)                       \
	static const struct file_operations name = {       \
		.owner = THIS_MODULE,                      \
		.open = openfn,                            \
		.read = seq_read,                          \
		.llseek = seq_lseek,                       \
		.release = single_release,                  \
	}
#else
#define JMX_CAT_FOPS(name, openfn)                       \
	static const struct proc_ops name = {              \
		.proc_open = openfn,                       \
		.proc_read = seq_read,                     \
		.proc_lseek = seq_lseek,                   \
		.proc_release = single_release,             \
	}
#endif

JMX_CAT_FOPS(jmx_wan_proto_stats_fops, jmx_wan_proto_stats_open);
JMX_CAT_FOPS(jmx_proto_stats_fops, jmx_proto_stats_open);
JMX_CAT_FOPS(jmx_if_stats_fops, jmx_if_stats_open);

/*
 * per-WAN directories.  Acceptance criterion 2 requires that the proc surface
 * follow the kernel's live WAN set, not jmxd's route_wan ledger, because those
 * have already diverged on 30.1 (4 WANs forwarding, 2 in the ledger).  These
 * directories are therefore created from jmx_wan_register() / removed from
 * jmx_wan_unregister(), which is the kernel's own view.
 */
static struct proc_dir_entry *g_wan_proc_dir[JMX_MAX_WAN_IFACES];
static DEFINE_MUTEX(jmx_wan_proc_mutex);

static void jmx_wan_proc_dir_remove(u8 wan_id)
{
	char dirname[8];

	if (!jmx_wan_idx_valid(wan_id))
		return;

	mutex_lock(&jmx_wan_proc_mutex);
	if (g_wan_proc_dir[wan_id - 1]) {
		snprintf(dirname, sizeof(dirname), "wan%u", wan_id);
		remove_proc_entry("proto_stats", g_wan_proc_dir[wan_id - 1]);
		remove_proc_entry(dirname, jmx_proc_root);
		g_wan_proc_dir[wan_id - 1] = NULL;
	}
	mutex_unlock(&jmx_wan_proc_mutex);
}

static void jmx_wan_proc_dir_create(u8 wan_id)
{
	struct proc_dir_entry *dir, *pde;
	char dirname[8];

	if (!jmx_wan_idx_valid(wan_id) || !jmx_proc_root)
		return;

	mutex_lock(&jmx_wan_proc_mutex);
	if (g_wan_proc_dir[wan_id - 1])
		goto out;

	snprintf(dirname, sizeof(dirname), "wan%u", wan_id);
	dir = proc_mkdir(dirname, jmx_proc_root);
	if (!dir) {
		AF_ERROR("jmx_route: proc_mkdir %s failed\n", dirname);
		goto out;
	}
	pde = proc_create_data("proto_stats", 0444, dir,
			       &jmx_wan_proto_stats_fops,
			       (void *)(unsigned long)wan_id);
	if (!pde) {
		AF_ERROR("jmx_route: create %s/proto_stats failed\n", dirname);
		remove_proc_entry(dirname, jmx_proc_root);
		goto out;
	}
	g_wan_proc_dir[wan_id - 1] = dir;
out:
	mutex_unlock(&jmx_wan_proc_mutex);
}

static int jmx_route_stats_init_procfs(void)
{
	if (!proc_create("proto_stats", 0444, jmx_proc_root,
			 &jmx_proto_stats_fops))
		return -ENOMEM;
	if (!proc_create("if_stats", 0444, jmx_proc_root, &jmx_if_stats_fops)) {
		remove_proc_entry("proto_stats", jmx_proc_root);
		return -ENOMEM;
	}
	return 0;
}

static void jmx_route_stats_exit_procfs(void)
{
	int i;

	for (i = 1; i <= JMX_MAX_WAN_IFACES; i++)
		jmx_wan_proc_dir_remove((u8)i);
	remove_proc_entry("if_stats", jmx_proc_root);
	remove_proc_entry("proto_stats", jmx_proc_root);
}

int jmx_route_init_procfs(void)
{
	struct proc_dir_entry *pde;

	pde = proc_create("jmx_route", 0444, jmx_proc_root, &jmx_route_proc_fops);
	if (!pde) {
		AF_ERROR("jmx_route proc file create failed\n");
		return -ENOMEM;
	}
	if (jmx_route_stats_init_procfs()) {
		remove_proc_entry("jmx_route", jmx_proc_root);
		return -ENOMEM;
	}
	return 0;
}

void jmx_route_exit_procfs(void)
{
	jmx_route_stats_exit_procfs();
	remove_proc_entry("jmx_route", jmx_proc_root);
}

int jmx_route_init(void)
{
	unsigned long flags;
	int i;

	/* ~640KB for 65536 entries: allocated once at module init, never on
	 * the forwarding path. */
	g_app_cat_pool = kvcalloc(JMX_APP_CAT_ENTRIES,
				  sizeof(*g_app_cat_pool), GFP_KERNEL);
	if (!g_app_cat_pool) {
		AF_ERROR("jmx_route: app category map alloc failed\n");
		return -ENOMEM;
	}
	for (i = 0; i < JMX_APP_CAT_BUCKETS; i++)
		g_app_cat_bucket[i] = -1;
	g_app_cat_used = 0;

	spin_lock_irqsave(&jmx_route_lock, flags);
	memset(g_wans, 0, sizeof(g_wans));
	g_wan_generation = get_random_u32();
	if (!g_wan_generation)
		g_wan_generation = 1;
	memset(g_rules, 0, sizeof(g_rules));
	memset(g_rule_enhancements, 0, sizeof(g_rule_enhancements));
	memset(g_new_flow_seq, 0, sizeof(g_new_flow_seq));
	g_rule_count = 0;
	memset(g_carriers, 0, sizeof(g_carriers));
	g_carrier_count = 0;
	spin_unlock_irqrestore(&jmx_route_lock, flags);
	AF_INFO("jmx_route: init ok\n");
	return 0;
}

void jmx_route_exit(void)
{
	jmx_route_rule_flush();
	jmx_carrier_prefix_flush();
	jmx_app_cat_flush();
	kvfree(g_app_cat_pool);
	g_app_cat_pool = NULL;
	AF_INFO("jmx_route: exit\n");
}

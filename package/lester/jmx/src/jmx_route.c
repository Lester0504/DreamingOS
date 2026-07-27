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
#include <linux/jiffies.h>
#include <linux/math64.h>
#include <linux/random.h>

#include "jmx.h"
#include "jmx_log.h"
#include "jmx_conntrack.h"

static jmx_wan_iface_t g_wans[JMX_MAX_WAN_IFACES];
static jmx_route_rule_t g_rules[JMX_MAX_ROUTE_RULES];
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

	if (!jmx_wan_idx_valid(wan_id) || !fwmark || !weight)
		return -EINVAL;

	strscpy(normalized_name, name ? name : "", sizeof(normalized_name));
	effective_table = table_id ? table_id : (JMX_ROUTE_TABLE_BASE + wan_id);
	spin_lock_irqsave(&jmx_route_lock, flags);
	wan = &g_wans[wan_id - 1];
	if (wan->wan_id != wan_id || wan->fwmark != fwmark ||
	    wan->table_id != effective_table ||
	    strncmp(wan->name, normalized_name, sizeof(wan->name))) {
		memset(wan, 0, sizeof(*wan));
		wan->generation = jmx_wan_next_generation_nolock();
		atomic64_set(&wan->rx_bytes, 0);
		atomic64_set(&wan->active_conn, 0);
	}
	wan->wan_id = wan_id;
	strscpy(wan->name, normalized_name, sizeof(wan->name));
	wan->fwmark = fwmark;
	wan->table_id = effective_table;
	wan->gateway = gateway;
	wan->health = 1;
	wan->weight = weight;
	spin_unlock_irqrestore(&jmx_route_lock, flags);

	JMX_DEBUG_RATELIMITED(1,
		"jmx_route: register wan id=%u name=%s fwmark=0x%x table=%u weight=%u\n",
		wan_id, name ? name : "", fwmark, effective_table, weight);
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

int jmx_route_rule_add(const jmx_route_rule_t *rule)
{
	int i;
	unsigned long flags;

	if (!rule || !rule->enabled || rule->wan_count == 0 ||
	    rule->wan_count > JMX_MAX_WAN_IFACES ||
	    rule->sticky_mode > JMX_STICKY_CONN_CNT)
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
	jmx_route_sort_rules_nolock();
	memset(g_new_flow_seq, 0, sizeof(g_new_flow_seq));
	spin_unlock_irqrestore(&jmx_route_lock, flags);
	return 0;
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

static int jmx_weighted_metric_cmp(u64 left, u32 left_weight,
				   u64 right, u32 right_weight)
{
	u64 left_q = div64_u64(left, left_weight);
	u64 right_q = div64_u64(right, right_weight);
	u32 left_r;
	u32 right_r;
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

static jmx_wan_iface_t *jmx_weighted_tie_select(jmx_wan_iface_t **candidates,
						 int count, u32 hash)
{
	u64 total_weight = 0;
	u64 point;
	u64 hash64;
	int i;

	for (i = 0; i < count; i++)
		total_weight += candidates[i]->weight;
	if (!total_weight)
		return candidates[hash % count];

	hash64 = ((u64)hash << 32) | jhash_1word(hash, 0x51a7e007);
	point = hash64 % total_weight;
	for (i = 0; i < count; i++) {
		if (point < candidates[i]->weight)
			return candidates[i];
		point -= candidates[i]->weight;
	}
	return candidates[count - 1];
}

static jmx_wan_iface_t *jmx_weighted_slot_select(jmx_wan_iface_t **candidates,
						  int count, u64 slot)
{
	u64 total_weight = 0;
	u64 point;
	int i;

	for (i = 0; i < count; i++)
		total_weight += candidates[i]->weight;
	if (!total_weight)
		return candidates[slot % count];

	point = slot % total_weight;
	for (i = 0; i < count; i++) {
		if (point < candidates[i]->weight)
			return candidates[i];
		point -= candidates[i]->weight;
	}
	return candidates[count - 1];
}

static jmx_wan_iface_t *jmx_select_min_metric_nolock(jmx_wan_iface_t **candidates,
						      int count, bool by_connections,
						      u32 hash)
{
	jmx_wan_iface_t *ties[JMX_MAX_WAN_IFACES];
	u64 best_metric;
	int i;
	int tie_count = 1;

	ties[0] = candidates[0];
	best_metric = by_connections ?
		(u64)atomic64_read(&candidates[0]->active_conn) :
		(u64)atomic64_read(&candidates[0]->rx_bytes);

	for (i = 1; i < count; i++) {
		u64 metric = by_connections ?
			(u64)atomic64_read(&candidates[i]->active_conn) :
			(u64)atomic64_read(&candidates[i]->rx_bytes);
		int cmp = jmx_weighted_metric_cmp(metric, candidates[i]->weight,
						  best_metric, ties[0]->weight);

		if (cmp < 0) {
			ties[0] = candidates[i];
			best_metric = metric;
			tie_count = 1;
		} else if (cmp == 0) {
			ties[tie_count++] = candidates[i];
		}
	}

	return jmx_weighted_tie_select(ties, tie_count, hash);
}

static jmx_wan_iface_t *jmx_select_wan_nolock(jmx_route_rule_t *r,
					       const struct jmx_route_flow_key *key)
{
	jmx_wan_iface_t *candidates[JMX_MAX_WAN_IFACES];
	int rule_idx = r - g_rules;
	u32 hash;
	int i, n = 0;

	for (i = 0; i < r->wan_count && i < JMX_MAX_WAN_IFACES; i++) {
		jmx_wan_iface_t *wan = jmx_wan_by_id_nolock(r->wan_ids[i]);
		if (!wan || !wan->health || !wan->fwmark)
			continue;
		candidates[n++] = wan;
	}

	if (n == 0)
		return NULL;

	if (r->sticky_mode == JMX_STICKY_PRIMARY_BACKUP)
		return candidates[0];
	if (r->sticky_mode == JMX_STICKY_DOWNLOAD)
		return jmx_select_min_metric_nolock(candidates, n, false,
			jmx_route_hash(r, key));
	if (r->sticky_mode == JMX_STICKY_CONN_CNT)
		return jmx_select_min_metric_nolock(candidates, n, true,
			jmx_route_hash(r, key));

	if (r->sticky_mode == JMX_STICKY_NEW_CONN &&
	    rule_idx >= 0 && rule_idx < JMX_MAX_ROUTE_RULES)
		return jmx_weighted_slot_select(candidates, n,
			g_new_flow_seq[rule_idx]++);

	hash = jmx_route_hash(r, key);
	return jmx_weighted_slot_select(candidates, n,
		((u64)hash << 32) | jhash_1word(hash, 0x51a7e008));
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

	seq_printf(s, "CarrierPrefixes: %d\n\n", g_carrier_count);
	seq_puts(s, "WANs:\n");
	seq_puts(s, "id name fwmark table gateway health weight active_conn rx_bytes generation\n");
	for (i = 0; i < JMX_MAX_WAN_IFACES; i++) {
		jmx_wan_iface_t *w = &g_wans[i];
		if (!w->wan_id)
			continue;
		seq_printf(s, "%u %s 0x%x %u %pI4 %u %u %llu %llu %u\n",
			   w->wan_id, w->name, w->fwmark, w->table_id, &w->gateway,
			   w->health, w->weight,
			   (unsigned long long)atomic64_read(&w->active_conn),
			   (unsigned long long)atomic64_read(&w->rx_bytes),
			   w->generation);
	}

	seq_puts(s, "\nRules:\n");
	seq_puts(s, "prio en proto appid carrier src/mask dst/mask dport mode hits last_hit_s wans\n");
	for (i = 0; i < g_rule_count; i++) {
		jmx_route_rule_t *r = &g_rules[i];
		seq_printf(s, "%u %u %u %u %u %pI4/%pI4 %pI4/%pI4 %u %u %llu %lu ",
			   r->prio, r->enabled, r->proto, r->appid, r->carrier_id,
			   &r->src_addr, &r->src_mask, &r->dst_addr, &r->dst_mask,
			   r->dst_port, r->sticky_mode, r->hit_count,
			   (unsigned long)(r->last_hit_jiffies ? jiffies_to_msecs(jiffies - r->last_hit_jiffies) / 1000 : 0));
		for (j = 0; j < r->wan_count && j < JMX_MAX_WAN_IFACES; j++)
			seq_printf(s, "%u%s", r->wan_ids[j], j + 1 == r->wan_count ? "" : ",");
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

int jmx_route_init_procfs(void)
{
	struct proc_dir_entry *pde;

	pde = proc_create("jmx_route", 0444, jmx_proc_root, &jmx_route_proc_fops);
	if (!pde) {
		AF_ERROR("jmx_route proc file create failed\n");
		return -ENOMEM;
	}
	return 0;
}

void jmx_route_exit_procfs(void)
{
	remove_proc_entry("jmx_route", jmx_proc_root);
}

int jmx_route_init(void)
{
	unsigned long flags;

	spin_lock_irqsave(&jmx_route_lock, flags);
	memset(g_wans, 0, sizeof(g_wans));
	g_wan_generation = get_random_u32();
	if (!g_wan_generation)
		g_wan_generation = 1;
	memset(g_rules, 0, sizeof(g_rules));
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
	AF_INFO("jmx_route: exit\n");
}

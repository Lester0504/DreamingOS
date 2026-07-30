// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * jmx_v2_rules.c - Kernel-side v2 rule management + AC automaton
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <linux/compiler.h>
#include <linux/jiffies.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include "jmx_v2_rules.h"
#include "jmx_v2_ac.h"

/* ── Internal rule node ── */

struct jmx_v2_rule_node {
	uint32_t appid;
	uint32_t rule_id;
	uint32_t priority;
	uint8_t  method;
	uint8_t  proto;
	uint8_t  dir;
	uint8_t  port_count;
	uint8_t  len_count;
	uint32_t pkt_seq;
	int32_t  offset;
	uint16_t match_len;
	char     match_str[JMX_V2_MAX_MATCH];
	struct {
		uint16_t min_port;
		uint16_t max_port;
	} ports[JMX_V2_MAX_PORTS];
	struct {
		uint16_t min_len;
		uint16_t max_len;
	} len_rng[JMX_V2_MAX_LEN_RNG];
	struct hlist_node hnode;
};

/* ── Rule set with AC ── */

struct jmx_v2_rule_set_k {
	struct hlist_head buckets[JMX_V2_HASH_BUCKETS];
	uint32_t count;
	uint32_t version;
	uint32_t attempted;
	uint32_t rejected_invalid;
	uint32_t rejected_nomem;
	rwlock_t lock;
	jmx_v2_ac_t *ac;
};

static struct jmx_v2_rule_set_k rule_sets[2];
static int active_idx;
static rwlock_t active_generation_lock;
static DEFINE_MUTEX(rules_update_lock);

#define JMX_V2_TX_TIMEOUT (30U * HZ)

static u32 staging_owner_portid;
static unsigned long staging_deadline;
static struct delayed_work rules_tx_expire_work;

#define ACTIVE_SET()  (&rule_sets[READ_ONCE(active_idx)])
#define STAGING_SET() (&rule_sets[1 - READ_ONCE(active_idx)])

static inline uint32_t hash_appid(uint32_t appid)
{
	return jhash_1word(appid, 0) % JMX_V2_HASH_BUCKETS;
}

static void jmx_v2_rule_set_clear(struct jmx_v2_rule_set_k *s);

/* rules_update_lock must be held. */
static void jmx_v2_tx_reset_locked(bool clear_staging)
{
	if (clear_staging)
		jmx_v2_rule_set_clear(STAGING_SET());
	staging_owner_portid = 0;
	staging_deadline = 0;
}

/* rules_update_lock must be held. */
static bool jmx_v2_tx_expire_locked(void)
{
	if (!staging_owner_portid ||
	    !time_after_eq(jiffies, staging_deadline))
		return false;

	pr_warn_ratelimited("jmx_v2: staging transaction owner=%u expired\n",
			    staging_owner_portid);
	jmx_v2_tx_reset_locked(true);
	return true;
}

static void jmx_v2_tx_expire_workfn(struct work_struct *work)
{
	(void)work;
	mutex_lock(&rules_update_lock);
	jmx_v2_tx_expire_locked();
	mutex_unlock(&rules_update_lock);
}

/* rules_update_lock must be held. */
static int jmx_v2_tx_check_owner_locked(u32 owner_portid)
{
	if (!owner_portid)
		return -EINVAL;
	if (jmx_v2_tx_expire_locked())
		return -ETIMEDOUT;
	if (!staging_owner_portid)
		return -ENOENT;
	if (staging_owner_portid != owner_portid)
		return -EPERM;
	return 0;
}

/* rules_update_lock must be held. */
static void jmx_v2_tx_refresh_locked(void)
{
	staging_deadline = jiffies + JMX_V2_TX_TIMEOUT;
	mod_delayed_work(system_wq, &rules_tx_expire_work,
			 JMX_V2_TX_TIMEOUT);
}

/* ── Init / Exit ── */

int jmx_v2_rules_init(void)
{
	int i, j;
	memset(rule_sets, 0, sizeof(rule_sets));
	for (i = 0; i < 2; i++) {
		rwlock_init(&rule_sets[i].lock);
		for (j = 0; j < JMX_V2_HASH_BUCKETS; j++)
			INIT_HLIST_HEAD(&rule_sets[i].buckets[j]);
	}
	active_idx = 0;
	rwlock_init(&active_generation_lock);
	staging_owner_portid = 0;
	staging_deadline = 0;
	INIT_DELAYED_WORK(&rules_tx_expire_work, jmx_v2_tx_expire_workfn);
	pr_info("jmx_v2: rules+AC initialized\n");
	return 0;
}

void jmx_v2_rules_exit(void)
{
	int i;

	cancel_delayed_work_sync(&rules_tx_expire_work);
	mutex_lock(&rules_update_lock);
	write_lock_bh(&active_generation_lock);
	for (i = 0; i < ARRAY_SIZE(rule_sets); i++) {
		struct jmx_v2_rule_node *r;
		struct hlist_node *tmp;
		int j;

		write_lock_bh(&rule_sets[i].lock);
		if (rule_sets[i].ac) {
			jmx_v2_ac_free(rule_sets[i].ac);
			rule_sets[i].ac = NULL;
		}
		for (j = 0; j < JMX_V2_HASH_BUCKETS; j++) {
			hlist_for_each_entry_safe(r, tmp,
						  &rule_sets[i].buckets[j], hnode) {
				hlist_del(&r->hnode);
				kfree(r);
			}
		}
		rule_sets[i].count = 0;
		rule_sets[i].version = 0;
		rule_sets[i].attempted = 0;
		rule_sets[i].rejected_invalid = 0;
		rule_sets[i].rejected_nomem = 0;
		write_unlock_bh(&rule_sets[i].lock);
	}
	write_unlock_bh(&active_generation_lock);
	staging_owner_portid = 0;
	staging_deadline = 0;
	mutex_unlock(&rules_update_lock);
	pr_info("jmx_v2: rules+AC cleaned up\n");
}

static void jmx_v2_rule_set_clear(struct jmx_v2_rule_set_k *s)
{
	struct jmx_v2_rule_node *r;
	struct hlist_node *tmp;
	int i;

	write_lock_bh(&s->lock);
	if (s->ac) {
		jmx_v2_ac_free(s->ac);
		s->ac = NULL;
	}
	for (i = 0; i < JMX_V2_HASH_BUCKETS; i++) {
		hlist_for_each_entry_safe(r, tmp, &s->buckets[i], hnode) {
			hlist_del(&r->hnode);
			kfree(r);
		}
	}
	s->count = 0;
	s->version = 0;
	s->attempted = 0;
	s->rejected_invalid = 0;
	s->rejected_nomem = 0;
	write_unlock_bh(&s->lock);
}

int jmx_v2_rules_begin(uint32_t owner_portid)
{
	int rc = 0;

	if (!owner_portid)
		return -EINVAL;

	mutex_lock(&rules_update_lock);
	jmx_v2_tx_expire_locked();
	if (staging_owner_portid &&
	    staging_owner_portid != owner_portid) {
		rc = -EBUSY;
		goto out;
	}

	jmx_v2_rule_set_clear(STAGING_SET());
	staging_owner_portid = owner_portid;
	jmx_v2_tx_refresh_locked();
out:
	mutex_unlock(&rules_update_lock);
	return rc;
}

static int jmx_v2_rule_add_locked(const jmx_v2_rule_t *in)
{
	struct jmx_v2_rule_set_k *s = STAGING_SET();
	struct jmx_v2_rule_node *r;
	uint32_t bkt;

	write_lock_bh(&s->lock);
	s->attempted++;
	write_unlock_bh(&s->lock);

	if (!in)
		goto invalid;
	if (in->match_len > JMX_V2_MAX_MATCH ||
	    in->port_count > JMX_V2_MAX_PORTS ||
	    in->len_count > JMX_V2_MAX_LEN_RNG ||
	    in->method > JMX_V2_MATCH_NO_FIXED ||
	    in->proto > JMX_V2_PROTO_UDP ||
	    in->dir > JMX_V2_DIR_REPLY)
		goto invalid;

	r = kmalloc(sizeof(*r), GFP_ATOMIC);
	if (!r) {
		write_lock_bh(&s->lock);
		s->rejected_nomem++;
		write_unlock_bh(&s->lock);
		return -ENOMEM;
	}

	r->appid = in->appid;
	r->rule_id = in->rule_id;
	r->priority = in->priority;
	r->method = in->method;
	r->proto = in->proto;
	r->dir = in->dir;
	r->port_count = in->port_count;
	r->len_count = in->len_count;
	r->pkt_seq = in->pkt_seq;
	r->offset = in->offset;
	r->match_len = in->match_len;
	memcpy(r->match_str, in->match_str, in->match_len);
	memcpy(r->ports, in->ports, sizeof(r->ports[0]) * in->port_count);
	memcpy(r->len_rng, in->len_range, sizeof(r->len_rng[0]) * in->len_count);

	INIT_HLIST_NODE(&r->hnode);
	bkt = hash_appid(r->appid);
	write_lock_bh(&s->lock);
	hlist_add_head(&r->hnode, &s->buckets[bkt]);
	s->count++;
	write_unlock_bh(&s->lock);
	return 0;

invalid:
	write_lock_bh(&s->lock);
	s->rejected_invalid++;
	write_unlock_bh(&s->lock);
	return -EINVAL;
}

int jmx_v2_rule_add(uint32_t owner_portid, const jmx_v2_rule_t *in)
{
	int rc;

	mutex_lock(&rules_update_lock);
	rc = jmx_v2_tx_check_owner_locked(owner_portid);
	if (!rc) {
		rc = jmx_v2_rule_add_locked(in);
		jmx_v2_tx_refresh_locked();
	}
	mutex_unlock(&rules_update_lock);
	return rc;
}

/* ── Commit: build AC + atomic swap ── */

int jmx_v2_rules_commit(uint32_t owner_portid, uint32_t version)
{
	struct jmx_v2_rule_set_k *old;
	struct jmx_v2_rule_set_k *new;
	struct jmx_v2_rule_node *r;
	struct hlist_node *tmp;
	jmx_v2_ac_pattern_t *pats = NULL;
	jmx_v2_ac_t *new_ac = NULL;
	struct jmx_v2_ac_stats ac_stats;
	uint32_t n_pats = 0, eligible = 0, regex_inactive = 0;
	uint32_t no_fixed_inactive = 0, empty_rejected = 0;
	uint32_t db_enabled, loaded, rejected_invalid, rejected_nomem;
	int build_rc = 0;
	int i, j;

	mutex_lock(&rules_update_lock);
	build_rc = jmx_v2_tx_check_owner_locked(owner_portid);
	if (build_rc)
		goto owner_rejected;
	old = ACTIVE_SET();
	new = STAGING_SET();
	memset(&ac_stats, 0, sizeof(ac_stats));
	db_enabled = new->attempted;
	loaded = new->count;
	rejected_invalid = new->rejected_invalid;
	rejected_nomem = new->rejected_nomem;

	for (i = 0; i < JMX_V2_HASH_BUCKETS; i++) {
		hlist_for_each_entry(r, &new->buckets[i], hnode) {
			if (r->method == JMX_V2_MATCH_BM_STR ||
			    r->method == JMX_V2_MATCH_EXACT) {
				if (r->match_len == 0)
					empty_rejected++;
				else
					eligible++;
			} else if (r->method == JMX_V2_MATCH_REGEX) {
				regex_inactive++;
			} else if (r->method == JMX_V2_MATCH_NO_FIXED) {
				no_fixed_inactive++;
			}
		}
	}
	if (rejected_invalid || rejected_nomem || empty_rejected) {
		build_rc = rejected_nomem ? -ENOMEM : -EINVAL;
		goto build_failed;
	}

	if (eligible) {
		pats = kvmalloc_array(eligible, sizeof(*pats),
				       GFP_KERNEL | __GFP_ZERO);
		if (!pats) {
			build_rc = -ENOMEM;
			goto build_failed;
		}

		for (i = 0; i < JMX_V2_HASH_BUCKETS; i++) {
			hlist_for_each_entry(r, &new->buckets[i], hnode) {
				if ((r->method != JMX_V2_MATCH_BM_STR &&
				     r->method != JMX_V2_MATCH_EXACT) ||
				    r->match_len == 0)
					continue;

				pats[n_pats].appid = r->appid;
				pats[n_pats].priority = r->priority;
				pats[n_pats].proto = r->proto;
				pats[n_pats].dir = r->dir;
				pats[n_pats].method = r->method;
				pats[n_pats].pkt_seq = r->pkt_seq;
				pats[n_pats].offset = r->offset;
				pats[n_pats].port_count = r->port_count;
				pats[n_pats].len_count = r->len_count;
				pats[n_pats].match_len = r->match_len;
				memcpy(pats[n_pats].match_str, r->match_str,
				       r->match_len);
				for (j = 0; j < r->port_count; j++) {
					pats[n_pats].ports_min[j] = r->ports[j].min_port;
					pats[n_pats].ports_max[j] = r->ports[j].max_port;
				}
				for (j = 0; j < r->len_count; j++) {
					pats[n_pats].lens_min[j] = r->len_rng[j].min_len;
					pats[n_pats].lens_max[j] = r->len_rng[j].max_len;
				}
				n_pats++;
			}
		}

		if (n_pats != eligible) {
			build_rc = -EIO;
			goto build_failed;
		}
		build_rc = jmx_v2_ac_build(pats, n_pats, &new_ac, &ac_stats);
		if (build_rc)
			goto build_failed;
	}
	kvfree(pats);
	pats = NULL;

	write_lock_bh(&active_generation_lock);
	write_lock_bh(&new->lock);
	new->ac = new_ac;
	new->version = version;
	WRITE_ONCE(active_idx, 1 - READ_ONCE(active_idx));
	write_unlock_bh(&new->lock);
	write_unlock_bh(&active_generation_lock);

	/* Clean old */
	write_lock_bh(&old->lock);
	if (old->ac) { jmx_v2_ac_free(old->ac); old->ac = NULL; }
	for (i = 0; i < JMX_V2_HASH_BUCKETS; i++) {
		hlist_for_each_entry_safe(r, tmp, &old->buckets[i], hnode) {
			hlist_del(&r->hnode);
			kfree(r);
		}
	}
	old->count = 0;
	old->version = 0;
	old->attempted = 0;
	old->rejected_invalid = 0;
	old->rejected_nomem = 0;
	write_unlock_bh(&old->lock);

	pr_info("jmx_v2_LOAD: status=committed version=%u db_enabled=%u loaded=%u compiled=%u rejected=%u duplicate_payloads=%u rejected_invalid=%u rejected_nomem=%u rejected_empty_payload=%u regex_inactive=%u no_fixed_inactive=%u nodes=%u edges=%u outputs=%u\n",
		version, db_enabled, loaded, n_pats,
		rejected_invalid + rejected_nomem + empty_rejected,
		ac_stats.duplicate_payloads, rejected_invalid, rejected_nomem,
		empty_rejected, regex_inactive, no_fixed_inactive,
		ac_stats.nodes, ac_stats.edges, ac_stats.outputs);
	jmx_v2_tx_reset_locked(false);
	cancel_delayed_work(&rules_tx_expire_work);
	mutex_unlock(&rules_update_lock);
	return 0;

build_failed:
	kvfree(pats);
	if (new_ac)
		jmx_v2_ac_free(new_ac);
	pr_err("jmx_v2_LOAD: status=rejected version=%u active_version=%u db_enabled=%u loaded=%u compiled=0 rejected=%u duplicate_payloads=0 rejected_invalid=%u rejected_nomem=%u rejected_empty_payload=%u regex_inactive=%u no_fixed_inactive=%u build_error=%d\n",
		version, old->version, db_enabled, loaded,
		rejected_invalid + rejected_nomem + empty_rejected + eligible,
		rejected_invalid, rejected_nomem, empty_rejected,
		regex_inactive, no_fixed_inactive, build_rc);
	jmx_v2_tx_reset_locked(true);
	cancel_delayed_work(&rules_tx_expire_work);
	mutex_unlock(&rules_update_lock);
	return build_rc;

owner_rejected:
	mutex_unlock(&rules_update_lock);
	return build_rc;
}

uint32_t jmx_v2_rules_count(void)
{
	uint32_t count;

	read_lock_bh(&active_generation_lock);
	count = ACTIVE_SET()->count;
	read_unlock_bh(&active_generation_lock);
	return count;
}

void jmx_v2_rules_get_status(uint32_t *version, uint32_t *count)
{
	struct jmx_v2_rule_set_k *active;

	read_lock_bh(&active_generation_lock);
	active = ACTIVE_SET();
	if (version)
		*version = active->version;
	if (count)
		*count = active->count;
	read_unlock_bh(&active_generation_lock);
}

/* ── Match ── */

uint32_t jmx_v2_match_payload(const uint8_t *payload, uint16_t len,
			      uint8_t proto, uint8_t dir,
			      uint16_t dport, uint32_t pkt_seq,
			      uint32_t *out_priority)
{
	struct jmx_v2_rule_set_k *s;
	uint32_t best = 0, best_pri = 0xFFFFFFFFU;
	uint32_t ac_app, ac_pri;

	read_lock_bh(&active_generation_lock);
	s = ACTIVE_SET();
	if (!s || s->count == 0) {
		read_unlock_bh(&active_generation_lock);
		return 0;
	}

	/* AC handles BM_STR + EXACT */
	if (s->ac) {
		ac_app = jmx_v2_ac_scan(s->ac, payload, len,
					proto, dir, dport, pkt_seq, &ac_pri);
		if (ac_app && ac_pri < best_pri) {
			best_pri = ac_pri;
			best = ac_app;
		}
	}

	/* NO_FIXED app.dat rules are metadata-only guesses. Many entries are
	 * effectively "TCP packet #6, any port, any length" and cause false
	 * positives. Do not classify with NO_FIXED in kernel fast path until the
	 * extra iKuai context for these rules is decoded. */

	read_unlock_bh(&active_generation_lock);
	if (out_priority) *out_priority = best_pri;
	return best;
}

/* ── Check if any REGEX rules exist ── */

int jmx_v2_has_regex_rules(void)
{
	struct jmx_v2_rule_set_k *s;
	struct jmx_v2_rule_node *r;
	int i;

	read_lock_bh(&active_generation_lock);
	s = ACTIVE_SET();
	for (i = 0; i < JMX_V2_HASH_BUCKETS; i++) {
		hlist_for_each_entry(r, &s->buckets[i], hnode) {
			if (r->method == JMX_V2_MATCH_REGEX) {
				read_unlock_bh(&active_generation_lock);
				return 1;
			}
		}
	}
	read_unlock_bh(&active_generation_lock);
	return 0;
}

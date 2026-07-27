// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/errno.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include "jmx_v3_ac.h"
#include "jmx_v3_rules.h"

#define JMX_V3_MAX_RULES  16384U
#define JMX_V3_MAX_STEPS  262144U
#define JMX_V3_MAX_PORTS  131072U
#define JMX_V3_TX_TIMEOUT (30U * HZ)
#define JMX_V3_PACKET_WORK_BUDGET 65536U

struct jmx_v3_rule_k {
	u32 signature_rule_id;
	u32 appid;
	u32 priority;
	u32 required_caps;
	u32 first_step;
	u32 first_port;
	u16 step_count;
	u16 port_count;
	u8 proto;
	u8 dir;
	u8 flags;
};

struct jmx_v3_step_k {
	u32 signature_rule_id;
	s32 depth;
	s32 offset;
	s32 distance;
	s32 within;
	u16 step_index;
	u16 payload_len;
	u8 matcher_type;
	u8 condition;
	u8 case_mode;
	u8 input_view;
	u8 position_flags;
	u8 literal_option;
	u8 payload[JMX_V3_PAYLOAD_MAX];
};

struct jmx_v3_port_k {
	u32 signature_rule_id;
	u16 min_port;
	u16 max_port;
	u8 endpoint;
};

struct jmx_v3_rule_set_k {
	u32 generation;
	u32 mode;
	u32 rule_count;
	u32 step_count;
	u32 port_count;
	u32 rule_capacity;
	u32 step_capacity;
	u32 port_capacity;
	u32 declared_caps;
	u8 catalog_digest[JMX_V3_CATALOG_DIGEST_LEN];
	struct jmx_v3_rule_k *rules;
	struct jmx_v3_step_k *steps;
	struct jmx_v3_port_k *ports;
	struct jmx_v3_ac *ac;
	struct jmx_v3_ac_stats ac_stats;
};

struct jmx_v3_transaction {
	u32 owner_portid;
	u32 generation;
	u32 failed_reason;
	u32 failed_detail;
	unsigned long started;
	unsigned long deadline;
	struct jmx_v3_rule_set_k *set;
	bool failed;
};

static DEFINE_MUTEX(v3_update_lock);
static struct jmx_v3_transaction v3_tx;
static struct jmx_v3_rule_set_k __rcu *v3_active;
static struct delayed_work v3_expire_work;
static atomic64_t v3_budget_exhausted = ATOMIC64_INIT(0);
static bool v3_running;

static u32 v3_le32(jmx_v3_le32 value)
{
	return le32_to_cpu((__force __le32)value);
}

static u16 v3_le16(jmx_v3_le16 value)
{
	return le16_to_cpu((__force __le16)value);
}

static void set_error(u32 *reason, u32 *detail, u32 why, u32 value)
{
	if (reason)
		*reason = why;
	if (detail)
		*detail = value;
}

static int bytes_zero(const u8 *bytes, u32 count);

static void free_set(struct jmx_v3_rule_set_k *set)
{
	if (!set)
		return;
	jmx_v3_ac_free(set->ac);
	kvfree(set->rules);
	kvfree(set->steps);
	kvfree(set->ports);
	kfree(set);
}

static void v3_expire_work_fn(struct work_struct *work)
{
	struct jmx_v3_rule_set_k *expired = NULL;
	u32 owner = 0, generation = 0;
	unsigned long now, deadline;

	(void)work;
	mutex_lock(&v3_update_lock);
	now = jiffies;
	deadline = v3_tx.deadline;
	if (!v3_running) {
		/* Module exit owns staging cleanup after cancel_delayed_work_sync(). */
	} else if (v3_tx.set && time_after_eq(now, deadline)) {
		expired = v3_tx.set;
		owner = v3_tx.owner_portid;
		generation = v3_tx.generation;
		memset(&v3_tx, 0, sizeof(v3_tx));
	} else if (v3_tx.set) {
		mod_delayed_work(system_wq, &v3_expire_work,
				 deadline - now);
	}
	mutex_unlock(&v3_update_lock);
	if (expired) {
		pr_warn("jmx_v3: expired staging owner=%u generation=%u\n",
			owner, generation);
		free_set(expired);
	}
}

u32 jmx_v3_capabilities(void)
{
	return JMX_V3_CAP_PHASE1_MASK;
}

int jmx_v3_rules_init(void)
{
	INIT_DELAYED_WORK(&v3_expire_work, v3_expire_work_fn);
	mutex_lock(&v3_update_lock);
	memset(&v3_tx, 0, sizeof(v3_tx));
	RCU_INIT_POINTER(v3_active, NULL);
	v3_running = true;
	mutex_unlock(&v3_update_lock);
	atomic64_set(&v3_budget_exhausted, 0);
	pr_info("jmx_v3: initialized capabilities=0x%08x mode=off\n",
		jmx_v3_capabilities());
	return 0;
}

void jmx_v3_rules_exit(void)
{
	struct jmx_v3_rule_set_k *active, *staging;

	mutex_lock(&v3_update_lock);
	v3_running = false;
	mutex_unlock(&v3_update_lock);
	cancel_delayed_work_sync(&v3_expire_work);
	mutex_lock(&v3_update_lock);
	staging = v3_tx.set;
	memset(&v3_tx, 0, sizeof(v3_tx));
	active = rcu_dereference_protected(v3_active,
		lockdep_is_held(&v3_update_lock));
	RCU_INIT_POINTER(v3_active, NULL);
	mutex_unlock(&v3_update_lock);
	free_set(staging);
	synchronize_rcu();
	free_set(active);
	/* Drain callbacks queued by any call_rcu()-based active-set retirement
	 * before this module's callback text can be unloaded. */
	rcu_barrier();
}

void jmx_v3_get_snapshot(struct jmx_v3_snapshot *snapshot)
{
	const struct jmx_v3_rule_set_k *set;

	if (!snapshot)
		return;
	memset(snapshot, 0, sizeof(*snapshot));
	snapshot->capabilities = jmx_v3_capabilities();
	mutex_lock(&v3_update_lock);
	set = rcu_dereference_protected(v3_active,
		lockdep_is_held(&v3_update_lock));
	if (set) {
		snapshot->active_generation = set->generation;
		snapshot->active_rules = set->rule_count;
		snapshot->active_steps = set->step_count;
		snapshot->active_ports = set->port_count;
		snapshot->active_mode = set->mode;
		memcpy(snapshot->active_catalog_digest, set->catalog_digest,
		       sizeof(snapshot->active_catalog_digest));
	}
	if (v3_tx.set) {
		snapshot->staging_generation = v3_tx.generation;
		snapshot->staging_state = v3_tx.failed ?
			JMX_V3_STAGING_FAILED : JMX_V3_STAGING_LOADING;
	}
	mutex_unlock(&v3_update_lock);
}

static void expire_staging_locked(void)
{
	if (v3_tx.set &&
	    time_after_eq(jiffies, v3_tx.deadline)) {
		pr_warn("jmx_v3: expired staging owner=%u generation=%u\n",
			v3_tx.owner_portid, v3_tx.generation);
		free_set(v3_tx.set);
		memset(&v3_tx, 0, sizeof(v3_tx));
	}
}

static int check_owner_locked(u32 owner_portid, u32 generation,
			      bool allow_failed, u32 *reason, u32 *detail)
{
	if (!v3_running) {
		set_error(reason, detail, JMX_V3_REASON_BAD_GENERATION, generation);
		return -ESHUTDOWN;
	}
	expire_staging_locked();
	if (!v3_tx.set) {
		set_error(reason, detail, JMX_V3_REASON_BAD_GENERATION, generation);
		return -ENOENT;
	}
	if (v3_tx.owner_portid != owner_portid) {
		set_error(reason, detail, JMX_V3_REASON_NOT_OWNER, owner_portid);
		return -EPERM;
	}
	if (v3_tx.generation != generation ||
	    v3_tx.set->generation != generation) {
		set_error(reason, detail, JMX_V3_REASON_BAD_GENERATION, generation);
		return -EINVAL;
	}
	if (v3_tx.failed && !allow_failed) {
		set_error(reason, detail, v3_tx.failed_reason, v3_tx.failed_detail);
		return -ECANCELED;
	}
	return 0;
}

static void fail_transaction_locked(u32 reason, u32 detail)
{
	if (!v3_tx.set || v3_tx.failed)
		return;
	v3_tx.failed = true;
	v3_tx.failed_reason = reason ? reason : JMX_V3_REASON_BAD_RECORD;
	v3_tx.failed_detail = detail;
}

static void fail_transaction_from_error(u32 *reason, u32 *detail)
{
	fail_transaction_locked(reason ? *reason : JMX_V3_REASON_BAD_RECORD,
				detail ? *detail : 0);
}

static void renew_transaction_locked(void)
{
	lockdep_assert_held(&v3_update_lock);
	v3_tx.deadline = jiffies + JMX_V3_TX_TIMEOUT;
	mod_delayed_work(system_wq, &v3_expire_work, JMX_V3_TX_TIMEOUT);
}

void jmx_v3_tx_fail(u32 owner_portid, u32 generation,
		    u32 reason, u32 detail)
{
	mutex_lock(&v3_update_lock);
	if (!check_owner_locked(owner_portid, generation, true, NULL, NULL))
		fail_transaction_locked(reason, detail);
	mutex_unlock(&v3_update_lock);
}

int jmx_v3_tx_begin(u32 owner_portid, u32 generation,
			const struct jmx_nl_begin_v3 *begin, u32 flags,
			u32 *reason, u32 *detail)
{
	struct jmx_v3_rule_set_k *set = NULL;
	u32 rules, steps, ports, caps, mode;
	int rc = -EINVAL;

	if (!owner_portid || !generation || !begin) {
		set_error(reason, detail, JMX_V3_REASON_BAD_RECORD, 0);
		return -EINVAL;
	}
	if (bytes_zero(begin->catalog_digest, JMX_V3_CATALOG_DIGEST_LEN)) {
		set_error(reason, detail, JMX_V3_REASON_BAD_RECORD, 0);
		return -EINVAL;
	}
	rules = v3_le32(begin->expected_rules);
	steps = v3_le32(begin->expected_steps);
	ports = v3_le32(begin->expected_ports);
	caps = v3_le32(begin->required_capabilities);
	mode = flags & JMX_V3_TX_MODE_MASK;
	if ((flags & ~JMX_V3_TX_KNOWN_FLAGS) || mode > JMX_V3_MODE_ACTIVE ||
	    rules > JMX_V3_MAX_RULES || steps > JMX_V3_MAX_STEPS ||
	    ports > JMX_V3_MAX_PORTS ||
	    (rules == 0 && (steps || ports || caps || mode != JMX_V3_MODE_OFF)) ||
	    (rules && (!steps || mode == JMX_V3_MODE_OFF)) ||
	    (caps & ~jmx_v3_capabilities())) {
		set_error(reason, detail,
			  (caps & ~jmx_v3_capabilities()) ? JMX_V3_REASON_CAPABILITY :
			  JMX_V3_REASON_BAD_RECORD, caps & ~jmx_v3_capabilities());
		return -EINVAL;
	}

	set = kzalloc(sizeof(*set), GFP_KERNEL);
	if (!set) {
		set_error(reason, detail, JMX_V3_REASON_NO_MEMORY, 0);
		return -ENOMEM;
	}
	set->generation = generation;
	set->mode = mode;
	set->rule_capacity = rules;
	set->step_capacity = steps;
	set->port_capacity = ports;
	set->declared_caps = caps;
	memcpy(set->catalog_digest, begin->catalog_digest,
	       sizeof(set->catalog_digest));
	if (rules)
		set->rules = kvmalloc_array(rules, sizeof(*set->rules),
					    GFP_KERNEL | __GFP_ZERO);
	if (steps)
		set->steps = kvmalloc_array(steps, sizeof(*set->steps),
					    GFP_KERNEL | __GFP_ZERO);
	if (ports)
		set->ports = kvmalloc_array(ports, sizeof(*set->ports),
					    GFP_KERNEL | __GFP_ZERO);
	if ((rules && !set->rules) || (steps && !set->steps) ||
	    (ports && !set->ports)) {
		set_error(reason, detail, JMX_V3_REASON_NO_MEMORY, 0);
		rc = -ENOMEM;
		goto out;
	}

	mutex_lock(&v3_update_lock);
	if (!v3_running) {
		set_error(reason, detail, JMX_V3_REASON_BAD_GENERATION, generation);
		mutex_unlock(&v3_update_lock);
		rc = -ESHUTDOWN;
		goto out;
	}
	expire_staging_locked();
	if (v3_tx.set) {
		set_error(reason, detail, JMX_V3_REASON_BUSY, v3_tx.owner_portid);
		mutex_unlock(&v3_update_lock);
		rc = -EBUSY;
		goto out;
	}
	{
		const struct jmx_v3_rule_set_k *active;

		active = rcu_dereference_protected(v3_active,
			lockdep_is_held(&v3_update_lock));
		if (active && active->generation == generation) {
			set_error(reason, detail, JMX_V3_REASON_BAD_GENERATION,
				  generation);
			mutex_unlock(&v3_update_lock);
			rc = -EALREADY;
			goto out;
		}
	}
	v3_tx.owner_portid = owner_portid;
	v3_tx.generation = generation;
	v3_tx.started = jiffies;
	v3_tx.set = set;
	/* Schedule while holding the transaction lock so an old completion cannot
	 * race a new BEGIN and overwrite its deadline. */
	renew_transaction_locked();
	mutex_unlock(&v3_update_lock);
	set = NULL;
	set_error(reason, detail, JMX_V3_REASON_NONE, 0);
	return 0;
out:
	free_set(set);
	return rc;
}

static int bytes_zero(const u8 *bytes, u32 count)
{
	u32 i;
	for (i = 0; i < count; i++)
		if (bytes[i])
			return 0;
	return 1;
}

int jmx_v3_tx_add_rules(u32 owner_portid, u32 generation,
			const struct jmx_nl_rule_v3 *records, u32 count,
			u32 *reason, u32 *detail)
{
	struct jmx_v3_rule_set_k *set;
	u32 i, start_count = 0;
	int rc;

	mutex_lock(&v3_update_lock);
	rc = check_owner_locked(owner_portid, generation, false, reason, detail);
	if (rc)
		goto out;
	set = v3_tx.set;
	start_count = set->rule_count;
	if (count > set->rule_capacity - set->rule_count) {
		set_error(reason, detail, JMX_V3_REASON_COUNT_MISMATCH, count);
		rc = -E2BIG;
		goto fail;
	}
	for (i = 0; i < count; i++) {
		const struct jmx_nl_rule_v3 *wire = &records[i];
		struct jmx_v3_rule_k *rule = &set->rules[set->rule_count];
		u32 id = v3_le32(wire->signature_rule_id);
		u32 caps = v3_le32(wire->required_caps);
		u16 steps = v3_le16(wire->step_count);

		if (!id || !v3_le32(wire->appid) || !steps ||
		    steps > JMX_V3_MAX_STEPS_PER_RULE || wire->flags ||
		    !bytes_zero(wire->reserved, sizeof(wire->reserved)) ||
		    wire->proto > JMX_V3_PROTO_UDP ||
		    wire->dir > JMX_V3_DIR_BIDIRECTIONAL ||
		    (caps & ~set->declared_caps) ||
		    (set->rule_count &&
		     set->rules[set->rule_count - 1].signature_rule_id >= id)) {
			set_error(reason, detail, JMX_V3_REASON_BAD_RECORD,
				  start_count + i);
			rc = -EINVAL;
			goto rollback;
		}
		rule->signature_rule_id = id;
		rule->appid = v3_le32(wire->appid);
		rule->priority = v3_le32(wire->priority);
		rule->required_caps = caps;
		rule->step_count = steps;
		rule->proto = wire->proto;
		rule->dir = wire->dir;
		set->rule_count++;
	}
	set_error(reason, detail, JMX_V3_REASON_NONE, set->rule_count);
	renew_transaction_locked();
	goto out;
rollback:
	memset(&set->rules[start_count], 0,
	       (set->rule_count - start_count) * sizeof(*set->rules));
	set->rule_count = start_count;
	fail_transaction_from_error(reason, detail);
	goto out;
fail:
	fail_transaction_from_error(reason, detail);
out:
	mutex_unlock(&v3_update_lock);
	return rc;
}

static int valid_step_wire(const struct jmx_nl_step_v3 *wire,
			   struct jmx_v3_step_k *step)
{
	u16 payload_len = v3_le16(wire->payload_len);
	u8 expected_case;

	if (!v3_le32(wire->signature_rule_id) ||
	    wire->condition != JMX_V3_CONDITION_POSITIVE ||
	    wire->input_view != JMX_V3_VIEW_RAW ||
	    (wire->position_flags & ~JMX_V3_POS_KNOWN_MASK) ||
	    !payload_len || payload_len > JMX_V3_PAYLOAD_MAX ||
	    !bytes_zero(wire->payload + payload_len,
			JMX_V3_PAYLOAD_MAX - payload_len) ||
	    !bytes_zero(wire->reserved, sizeof(wire->reserved)) ||
	    wire->numeric_encoding ||
	    v3_le16(wire->reference_source) || wire->comparison ||
	    wire->adjust_mode || wire->width || wire->jump_multiplier ||
	    v3_le32(wire->inline_operand) ||
	    v3_le32(wire->adjustment_operand) || v3_le32(wire->jump_base))
		return -EINVAL;
	if (wire->matcher_type == JMX_V3_MATCH_LITERAL_NOCASE)
		expected_case = JMX_V3_CASE_NOCASE;
	else if (wire->matcher_type == JMX_V3_MATCH_LITERAL_EXACT_1 ||
		 wire->matcher_type == JMX_V3_MATCH_LITERAL_EXACT_2)
		expected_case = JMX_V3_CASE_EXACT;
	else
		return -EOPNOTSUPP;
	if (wire->case_mode != expected_case)
		return -EINVAL;
	if (!(wire->literal_option == 0x00 || wire->literal_option == 0x01 ||
	      wire->literal_option == 0x04))
		return -EINVAL;

	step->signature_rule_id = v3_le32(wire->signature_rule_id);
	step->step_index = v3_le16(wire->step_index);
	step->matcher_type = wire->matcher_type;
	step->condition = wire->condition;
	step->case_mode = wire->case_mode;
	step->input_view = wire->input_view;
	step->position_flags = wire->position_flags;
	step->literal_option = wire->literal_option;
	step->depth = (s32)v3_le32(wire->depth);
	step->offset = (s32)v3_le32(wire->offset);
	step->distance = (s32)v3_le32(wire->distance);
	step->within = (s32)v3_le32(wire->within);
	step->payload_len = payload_len;
	memcpy(step->payload, wire->payload, payload_len);
	if ((step->position_flags & JMX_V3_POS_DEPTH) && step->depth < 0)
		return -EINVAL;
	if ((step->position_flags & JMX_V3_POS_OFFSET) && step->offset < 0)
		return -EINVAL;
	if (!(step->position_flags & JMX_V3_POS_DEPTH) && step->depth)
		return -EINVAL;
	if (!(step->position_flags & JMX_V3_POS_OFFSET) && step->offset)
		return -EINVAL;
	if (!(step->position_flags & JMX_V3_POS_DISTANCE) && step->distance)
		return -EINVAL;
	if (!(step->position_flags & JMX_V3_POS_WITHIN) && step->within)
		return -EINVAL;
	if (step->step_index == 0 &&
	    (step->position_flags & (JMX_V3_POS_DISTANCE | JMX_V3_POS_WITHIN)))
		return -EINVAL;
	return 0;
}

int jmx_v3_tx_add_steps(u32 owner_portid, u32 generation,
			const struct jmx_nl_step_v3 *records, u32 count,
			u32 *reason, u32 *detail)
{
	struct jmx_v3_rule_set_k *set;
	u32 i, start_count = 0;
	int rc;

	mutex_lock(&v3_update_lock);
	rc = check_owner_locked(owner_portid, generation, false, reason, detail);
	if (rc)
		goto out;
	set = v3_tx.set;
	start_count = set->step_count;
	if (count > set->step_capacity - set->step_count) {
		set_error(reason, detail, JMX_V3_REASON_COUNT_MISMATCH, count);
		rc = -E2BIG;
		goto fail;
	}
	for (i = 0; i < count; i++) {
		struct jmx_v3_step_k step;
		memset(&step, 0, sizeof(step));
		rc = valid_step_wire(&records[i], &step);
		if (rc) {
			set_error(reason, detail,
				  rc == -EOPNOTSUPP ? JMX_V3_REASON_CAPABILITY :
				  JMX_V3_REASON_BAD_RECORD, start_count + i);
			goto rollback;
		}
		if (set->step_count) {
			const struct jmx_v3_step_k *prev = &set->steps[set->step_count - 1];
			if (step.signature_rule_id < prev->signature_rule_id ||
			    (step.signature_rule_id == prev->signature_rule_id &&
			     step.step_index <= prev->step_index)) {
					set_error(reason, detail, JMX_V3_REASON_STEP_SEQUENCE,
						  start_count + i);
					rc = -EINVAL;
					goto rollback;
			}
		}
		set->steps[set->step_count++] = step;
	}
	set_error(reason, detail, JMX_V3_REASON_NONE, set->step_count);
	renew_transaction_locked();
	goto out;
rollback:
	memset(&set->steps[start_count], 0,
	       (set->step_count - start_count) * sizeof(*set->steps));
	set->step_count = start_count;
	fail_transaction_from_error(reason, detail);
	goto out;
fail:
	fail_transaction_from_error(reason, detail);
out:
	mutex_unlock(&v3_update_lock);
	return rc;
}

int jmx_v3_tx_add_ports(u32 owner_portid, u32 generation,
			const struct jmx_nl_port_v3 *records, u32 count,
			u32 *reason, u32 *detail)
{
	struct jmx_v3_rule_set_k *set;
	u32 i, start_count = 0;
	int rc;

	mutex_lock(&v3_update_lock);
	rc = check_owner_locked(owner_portid, generation, false, reason, detail);
	if (rc)
		goto out;
	set = v3_tx.set;
	start_count = set->port_count;
	if (count > set->port_capacity - set->port_count) {
		set_error(reason, detail, JMX_V3_REASON_COUNT_MISMATCH, count);
		rc = -E2BIG;
		goto fail;
	}
	for (i = 0; i < count; i++) {
		const struct jmx_nl_port_v3 *wire = &records[i];
		struct jmx_v3_port_k port;
		memset(&port, 0, sizeof(port));
		port.signature_rule_id = v3_le32(wire->signature_rule_id);
		port.endpoint = wire->endpoint;
		port.min_port = v3_le16(wire->min_port);
		port.max_port = v3_le16(wire->max_port);
		if (!port.signature_rule_id ||
		    port.endpoint < JMX_V3_PORT_SOURCE ||
		    port.endpoint > JMX_V3_PORT_EITHER ||
		    port.min_port > port.max_port ||
		    !bytes_zero(wire->reserved, sizeof(wire->reserved)) ||
		    (set->port_count &&
		     set->ports[set->port_count - 1].signature_rule_id >
		     port.signature_rule_id)) {
			set_error(reason, detail, JMX_V3_REASON_BAD_RECORD,
				  start_count + i);
			rc = -EINVAL;
			goto rollback;
		}
		set->ports[set->port_count++] = port;
	}
	set_error(reason, detail, JMX_V3_REASON_NONE, set->port_count);
	renew_transaction_locked();
	goto out;
rollback:
	memset(&set->ports[start_count], 0,
	       (set->port_count - start_count) * sizeof(*set->ports));
	set->port_count = start_count;
	fail_transaction_from_error(reason, detail);
	goto out;
fail:
	fail_transaction_from_error(reason, detail);
out:
	mutex_unlock(&v3_update_lock);
	return rc;
}

static u32 step_caps(const struct jmx_v3_step_k *step)
{
	u32 caps = JMX_V3_CAP_RAW_LITERAL_CHAIN;
	if (step->matcher_type == JMX_V3_MATCH_LITERAL_NOCASE)
		caps |= JMX_V3_CAP_NOCASE;
	if (step->position_flags & (JMX_V3_POS_DEPTH | JMX_V3_POS_OFFSET))
		caps |= JMX_V3_CAP_POSITION_ABSOLUTE;
	if (step->position_flags & (JMX_V3_POS_DISTANCE | JMX_V3_POS_WITHIN))
		caps |= JMX_V3_CAP_POSITION_RELATIVE;
	return caps;
}

static int validate_and_index_set(struct jmx_v3_rule_set_k *set,
				  u32 *reason, u32 *detail)
{
	u32 step_cursor = 0, port_cursor = 0, union_caps = 0, i;
	struct jmx_v3_ac_pattern *patterns = NULL;
	int rc = -EINVAL;

	if (set->rule_count != set->rule_capacity ||
	    set->step_count != set->step_capacity ||
	    set->port_count != set->port_capacity) {
		set_error(reason, detail, JMX_V3_REASON_COUNT_MISMATCH,
			  set->rule_count);
		return -EINVAL;
	}
	if (set->rule_count) {
		patterns = kvmalloc_array(set->rule_count, sizeof(*patterns),
					   GFP_KERNEL | __GFP_ZERO);
		if (!patterns) {
			set_error(reason, detail, JMX_V3_REASON_NO_MEMORY, 0);
			return -ENOMEM;
		}
	}
	for (i = 0; i < set->rule_count; i++) {
		struct jmx_v3_rule_k *rule = &set->rules[i];
		u32 inferred = JMX_V3_CAP_PROTOCOL_MAPPING;
		u32 j;

		rule->first_step = step_cursor;
		for (j = 0; j < rule->step_count; j++, step_cursor++) {
			const struct jmx_v3_step_k *step;
			if (step_cursor >= set->step_count)
				goto bad_reference;
			step = &set->steps[step_cursor];
			if (step->signature_rule_id != rule->signature_rule_id ||
			    step->step_index != j)
				goto bad_sequence;
			inferred |= step_caps(step);
		}
		if ((rule->required_caps & inferred) != inferred ||
		    (rule->required_caps & ~jmx_v3_capabilities())) {
			set_error(reason, detail, JMX_V3_REASON_CAPABILITY,
				  rule->signature_rule_id);
			goto out;
		}
		union_caps |= rule->required_caps;
		rule->first_port = port_cursor;
		while (port_cursor < set->port_count &&
		       set->ports[port_cursor].signature_rule_id == rule->signature_rule_id) {
			if (rule->port_count >= JMX_V3_MAX_PORTS_PER_RULE)
				goto bad_reference;
			rule->port_count++;
			port_cursor++;
		}
		patterns[i].rule_index = i;
		patterns[i].step_index = 0;
		patterns[i].len = set->steps[rule->first_step].payload_len;
		memcpy(patterns[i].bytes, set->steps[rule->first_step].payload,
		       patterns[i].len);
	}
	if (step_cursor != set->step_count || port_cursor != set->port_count)
		goto bad_reference;
	if (union_caps != set->declared_caps) {
		set_error(reason, detail, JMX_V3_REASON_CAPABILITY, union_caps);
		goto out;
	}
	if (set->rule_count) {
		rc = jmx_v3_ac_build(patterns, set->rule_count, &set->ac,
				     &set->ac_stats);
		if (rc) {
			set_error(reason, detail, JMX_V3_REASON_BUILD_FAILED, (u32)-rc);
			goto out;
		}
	}
	rc = 0;
	set_error(reason, detail, JMX_V3_REASON_NONE, set->rule_count);
	goto out;
bad_sequence:
	set_error(reason, detail, JMX_V3_REASON_STEP_SEQUENCE, step_cursor);
	goto out;
bad_reference:
	set_error(reason, detail, JMX_V3_REASON_BAD_REFERENCE,
		  step_cursor != set->step_count ? step_cursor : port_cursor);
out:
	kvfree(patterns);
	return rc;
}

int jmx_v3_tx_commit(u32 owner_portid, u32 generation,
			 u32 *reason, u32 *detail)
{
	struct jmx_v3_rule_set_k *set, *old;
	struct jmx_v3_ac_stats stats;
	u32 mode, rule_count, step_count, port_count;
	int rc;

	mutex_lock(&v3_update_lock);
	rc = check_owner_locked(owner_portid, generation, false, reason, detail);
	if (rc)
		goto out;
	set = v3_tx.set;
	rc = validate_and_index_set(set, reason, detail);
	if (rc) {
		fail_transaction_from_error(reason, detail);
		goto out;
	}
	mode = set->mode;
	rule_count = set->rule_count;
	step_count = set->step_count;
	port_count = set->port_count;
	stats = set->ac_stats;
	memset(&v3_tx, 0, sizeof(v3_tx));
	old = rcu_dereference_protected(v3_active,
		lockdep_is_held(&v3_update_lock));
	rcu_assign_pointer(v3_active, set);
	mutex_unlock(&v3_update_lock);
	if (old) {
		synchronize_rcu();
		free_set(old);
	}
	pr_info("jmx_v3_LOAD: status=committed generation=%u mode=%u rules=%u steps=%u ports=%u nodes=%u edges=%u outputs=%u duplicate_payloads=%u owner_portid=%u\n",
		generation, mode, rule_count, step_count, port_count,
		stats.nodes, stats.edges, stats.outputs, stats.duplicate_payloads,
		owner_portid);
	return 0;
out:
	mutex_unlock(&v3_update_lock);
	return rc;
}

int jmx_v3_tx_abort(u32 owner_portid, u32 generation,
			u32 *reason, u32 *detail)
{
	struct jmx_v3_rule_set_k *set;
	int rc;

	mutex_lock(&v3_update_lock);
	rc = check_owner_locked(owner_portid, generation, true, reason, detail);
	if (rc) {
		mutex_unlock(&v3_update_lock);
		return rc;
	}
	set = v3_tx.set;
	memset(&v3_tx, 0, sizeof(v3_tx));
	mutex_unlock(&v3_update_lock);
	free_set(set);
	set_error(reason, detail, JMX_V3_REASON_NONE, 0);
	return 0;
}

static u8 fold_byte(u8 byte)
{
	return byte >= 'A' && byte <= 'Z' ? byte + ('a' - 'A') : byte;
}

static int exact_at(const struct jmx_v3_step_k *step, const u8 *payload,
		    u32 start, u32 len, u32 *work_budget)
{
	u32 i;

	if (start > len || step->payload_len > len - start)
		return 0;
	for (i = 0; i < step->payload_len; i++) {
		u8 left, right;

		if (!*work_budget)
			return -E2BIG;
		(*work_budget)--;
		left = payload[start + i];
		right = step->payload[i];
		if (step->case_mode == JMX_V3_CASE_NOCASE) {
			left = fold_byte(left);
			right = fold_byte(right);
		}
		if (left != right)
			return 0;
	}
	return 1;
}

static int add_signed_offset(u32 base, s32 delta, u32 *result)
{
	s64 value = (s64)base + delta;
	if (value < 0 || value > U32_MAX)
		return -ERANGE;
	*result = (u32)value;
	return 0;
}

static int step_window(const struct jmx_v3_step_k *step, u32 payload_len,
		       u32 previous_end, u32 *window_start, u32 *window_end)
{
	u32 start = 0;
	u32 end = payload_len, value;

	if (step->position_flags & JMX_V3_POS_OFFSET) {
		value = (u32)step->offset;
		if (value > start)
			start = value;
	}
	if (step->position_flags & JMX_V3_POS_DEPTH) {
		value = (u32)step->depth;
		if (value < end)
			end = value;
	}
	if (step->position_flags & JMX_V3_POS_DISTANCE) {
		if (add_signed_offset(previous_end, step->distance, &value))
			return -ERANGE;
		start = value;
		if ((step->position_flags & JMX_V3_POS_OFFSET) &&
		    (u32)step->offset > start)
			start = (u32)step->offset;
	}
	if (step->position_flags & JMX_V3_POS_WITHIN) {
		if (add_signed_offset(previous_end, step->within, &value))
			return -ERANGE;
		if (value < end)
			end = value;
	}
	if (start > end || start > payload_len)
		return -ERANGE;
	if (end > payload_len)
		end = payload_len;
	*window_start = start;
	*window_end = end;
	return 0;
}

static int occurrence_valid(const struct jmx_v3_step_k *step,
			    const u8 *payload, u32 payload_len,
			    u32 previous_end, u32 start, u32 end,
			    u32 *work_budget)
{
	u32 window_start, window_end;
	if (step_window(step, payload_len, previous_end,
			&window_start, &window_end))
		return 0;
	if (start < window_start || end > window_end)
		return 0;
	return exact_at(step, payload, start, payload_len, work_budget);
}

static int complete_chain(const struct jmx_v3_rule_set_k *set,
			  const struct jmx_v3_rule_k *rule,
			  const u8 *payload, u32 payload_len,
			  u32 first_end, u32 *work_budget)
{
	u32 ends[JMX_V3_MAX_STEPS_PER_RULE];
	u32 next_pos[JMX_V3_MAX_STEPS_PER_RULE];
	u32 window_end[JMX_V3_MAX_STEPS_PER_RULE];
	u16 level = 1;

	if (rule->step_count == 1)
		return 1;
	ends[0] = first_end;
	next_pos[level] = U32_MAX;

	while (level > 0) {
		const struct jmx_v3_step_k *step = &set->steps[rule->first_step + level];
		u32 pos;
		int advanced = 0;

		if (next_pos[level] == U32_MAX) {
			if (step_window(step, payload_len, ends[level - 1],
					&next_pos[level], &window_end[level]) ||
			    step->payload_len > window_end[level] - next_pos[level]) {
				next_pos[level] = U32_MAX;
				level--;
				continue;
			}
		}

		for (pos = next_pos[level];
		     pos <= window_end[level] &&
		     step->payload_len <= window_end[level] - pos; pos++) {
			u32 end = pos + step->payload_len;
			int matched;

			if (end < ends[level - 1])
				continue;
			matched = exact_at(step, payload, pos, payload_len,
					   work_budget);
			if (matched < 0)
				return matched;
			if (!matched)
				continue;
			next_pos[level] = pos + 1;
			ends[level] = end;
			if (level + 1 == rule->step_count)
				return 1;
			level++;
			next_pos[level] = U32_MAX;
			advanced = 1;
			break;
		}
		if (advanced)
			continue;
		next_pos[level] = U32_MAX;
		level--;
	}
	return 0;
}

static int rule_gate(const struct jmx_v3_rule_set_k *set,
		     const struct jmx_v3_rule_k *rule,
		     u8 proto, u8 dir, u16 sport, u16 dport,
		     u32 *work_budget)
{
	u32 i;

	if (!*work_budget)
		return -E2BIG;
	(*work_budget)--;
	if (rule->proto != JMX_V3_PROTO_ANY && rule->proto != proto)
		return 0;
	if (rule->dir != JMX_V3_DIR_ANY &&
	    rule->dir != JMX_V3_DIR_BIDIRECTIONAL && rule->dir != dir)
		return 0;
	if (!rule->port_count)
		return 1;
	for (i = 0; i < rule->port_count; i++) {
		const struct jmx_v3_port_k *port = &set->ports[rule->first_port + i];

		if (!*work_budget)
			return -E2BIG;
		(*work_budget)--;
		if ((port->endpoint == JMX_V3_PORT_SOURCE ||
		     port->endpoint == JMX_V3_PORT_EITHER) &&
		    sport >= port->min_port && sport <= port->max_port)
			return 1;
		if ((port->endpoint == JMX_V3_PORT_DESTINATION ||
		     port->endpoint == JMX_V3_PORT_EITHER) &&
		    dport >= port->min_port && dport <= port->max_port)
			return 1;
	}
	return 0;
}

struct match_context {
	const struct jmx_v3_rule_set_k *set;
	const u8 *payload;
	u32 payload_len;
	u32 best_appid;
	u32 best_priority;
	u32 best_rule_id;
	u16 sport;
	u16 dport;
	u8 proto;
	u8 dir;
};

static int evaluate_first(void *opaque, u32 rule_index, u16 step_index,
			  u32 start, u32 end, u32 *work_budget)
{
	struct match_context *ctx = opaque;
	const struct jmx_v3_rule_k *rule;
	u32 previous_end = end;
	int matched;

	if (step_index || rule_index >= ctx->set->rule_count)
		return 0;
	rule = &ctx->set->rules[rule_index];
	matched = rule_gate(ctx->set, rule, ctx->proto, ctx->dir,
			    ctx->sport, ctx->dport, work_budget);
	if (matched <= 0)
		return matched;
	matched = occurrence_valid(&ctx->set->steps[rule->first_step],
				   ctx->payload, ctx->payload_len, 0, start, end,
				   work_budget);
	if (matched <= 0)
		return matched;
	matched = complete_chain(ctx->set, rule, ctx->payload, ctx->payload_len,
				 previous_end, work_budget);
	if (matched <= 0)
		return matched;
	if (rule->priority < ctx->best_priority ||
	    (rule->priority == ctx->best_priority &&
	     rule->signature_rule_id < ctx->best_rule_id)) {
		ctx->best_appid = rule->appid;
		ctx->best_priority = rule->priority;
		ctx->best_rule_id = rule->signature_rule_id;
	}
	return 0;
}

u32 jmx_v3_match_payload(const u8 *payload, u32 len,
			 u8 proto, u8 dir, u16 sport, u16 dport,
			 u32 *out_priority, u8 *out_mode)
{
	const struct jmx_v3_rule_set_k *set;
	struct match_context ctx;
	u32 work_budget = JMX_V3_PACKET_WORK_BUDGET;
	int rc = 0;

	if (out_priority)
		*out_priority = U32_MAX;
	if (out_mode)
		*out_mode = JMX_V3_MODE_OFF;
	if (!payload || !len)
		return 0;
	memset(&ctx, 0, sizeof(ctx));
	ctx.payload = payload;
	ctx.payload_len = len;
	ctx.proto = proto;
	ctx.dir = dir;
	ctx.sport = sport;
	ctx.dport = dport;
	ctx.best_priority = U32_MAX;
	ctx.best_rule_id = U32_MAX;

	rcu_read_lock();
	set = rcu_dereference(v3_active);
	if (!set || set->mode == JMX_V3_MODE_OFF || !set->ac)
		goto out;
	ctx.set = set;
	if (out_mode)
		*out_mode = (u8)set->mode;
	rc = jmx_v3_ac_scan(set->ac, payload, len, evaluate_first, &ctx,
			    &work_budget);
	if (rc) {
		ctx.best_appid = 0;
		ctx.best_priority = U32_MAX;
		if (rc == -E2BIG) {
			long long count = atomic64_inc_return(&v3_budget_exhausted);
			pr_warn_ratelimited("jmx_v3: packet work budget exhausted total=%lld len=%u\n",
				count, len);
		}
	}
out:
	rcu_read_unlock();
	if (out_priority)
		*out_priority = ctx.best_priority;
	return ctx.best_appid;
}

u32 jmx_v3_appid_for_commit(u32 appid, u8 mode)
{
	return mode == JMX_V3_MODE_ACTIVE ? appid : 0;
}

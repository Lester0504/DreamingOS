// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/build_bug.h>
#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include "jmx_nl_rule_v3.h"
#include "jmx_v3_nl_handler.h"
#include "jmx_v3_rules.h"

static_assert(sizeof(struct jmx_nl_v3_hdr) == 32);
static_assert(offsetof(struct jmx_nl_v3_hdr, crc32) == 28);
static_assert(sizeof(struct jmx_nl_begin_v3) == 48);
static_assert(offsetof(struct jmx_nl_begin_v3, catalog_digest) == 16);
static_assert(sizeof(struct jmx_nl_rule_v3) == 24);
static_assert(offsetof(struct jmx_nl_rule_v3, step_count) == 16);
static_assert(sizeof(struct jmx_nl_step_v3) == 116);
static_assert(offsetof(struct jmx_nl_step_v3, depth) == 16);
static_assert(offsetof(struct jmx_nl_step_v3, payload) == 52);
static_assert(sizeof(struct jmx_nl_port_v3) == 12);
static_assert(offsetof(struct jmx_nl_port_v3, min_port) == 8);
static_assert(sizeof(struct jmx_nl_status_v3) == 80);
static_assert(offsetof(struct jmx_nl_status_v3, active_generation) == 20);
static_assert(offsetof(struct jmx_nl_status_v3, active_catalog_digest) == 40);
static_assert(offsetof(struct jmx_nl_status_v3, staging_generation) == 72);
static_assert(offsetof(struct jmx_nl_status_v3, staging_state) == 76);

/* Keep a request and its snapshot ACK indivisible.  Without this lock a
 * second COMMIT can replace the active generation before the first handler
 * builds its ACK, making a successful first COMMIT look like a failure. */
static DEFINE_MUTEX(v3_nl_lock);

static u32 wire_le32(jmx_v3_le32 value)
{
	return le32_to_cpu((__force __le32)value);
}

static u16 wire_le16(jmx_v3_le16 value)
{
	return le16_to_cpu((__force __le16)value);
}

static jmx_v3_le32 wire_cpu32(u32 value)
{
	return (__force jmx_v3_le32)cpu_to_le32(value);
}

static jmx_v3_le16 wire_cpu16(u16 value)
{
	return (__force jmx_v3_le16)cpu_to_le16(value);
}

static u32 payload_crc32(const void *payload, u32 len)
{
	const u8 *bytes = payload;
	u32 crc = ~0U, i;

	for (i = 0; i < len; i++) {
		u32 bit;
		crc ^= bytes[i];
		for (bit = 0; bit < 8; bit++)
			crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1U)));
	}
	return crc ^ ~0U;
}

static int send_status(jmx_v3_nl_reply_fn reply, u32 portid,
		       u32 nlmsg_seq, u32 generation, u32 request_action,
		       u32 status, u32 reason, u32 detail)
{
	struct {
		struct jmx_nl_v3_hdr header;
		struct jmx_nl_status_v3 status;
	} __packed message;
	struct jmx_v3_snapshot snapshot;

	if (!reply || !portid)
		return -EINVAL;
	memset(&message, 0, sizeof(message));
	jmx_v3_get_snapshot(&snapshot);
	message.status.request_action = wire_cpu32(request_action);
	message.status.status = wire_cpu32(status);
	message.status.reason = wire_cpu32(reason);
	message.status.detail = wire_cpu32(detail);
	message.status.engine_capabilities = wire_cpu32(snapshot.capabilities);
	message.status.active_generation = wire_cpu32(snapshot.active_generation);
	message.status.active_rules = wire_cpu32(snapshot.active_rules);
	message.status.active_steps = wire_cpu32(snapshot.active_steps);
	message.status.active_ports = wire_cpu32(snapshot.active_ports);
	message.status.active_mode = wire_cpu32(snapshot.active_mode);
	memcpy(message.status.active_catalog_digest,
	       snapshot.active_catalog_digest,
	       sizeof(message.status.active_catalog_digest));
	message.status.staging_generation = wire_cpu32(snapshot.staging_generation);
	message.status.staging_state = wire_cpu32(snapshot.staging_state);
	message.header.action = wire_cpu32(JMX_NL_ACT_RULESET_STATUS_V3);
	message.header.abi_version = wire_cpu16(JMX_RULE_ABI_V3);
	message.header.header_size = wire_cpu16(sizeof(message.header));
	message.header.record_size = wire_cpu32(sizeof(message.status));
	message.header.generation = wire_cpu32(generation);
	message.header.count = wire_cpu32(1);
	message.header.payload_bytes = wire_cpu32(sizeof(message.status));
	message.header.crc32 = wire_cpu32(payload_crc32(&message.status,
							 sizeof(message.status)));
	return reply(portid, nlmsg_seq, &message, sizeof(message));
}

static int action_is_v3(u32 action)
{
	return action >= JMX_NL_ACT_RULESET_BEGIN_V3 &&
	       action <= JMX_NL_ACT_CAPABILITY_V3;
}

static int action_is_batch(u32 action)
{
	return action == JMX_NL_ACT_RULE_V3_BATCH ||
	       action == JMX_NL_ACT_STEP_V3_BATCH ||
	       action == JMX_NL_ACT_PORT_V3_BATCH;
}

static u32 expected_record_size(u32 action)
{
	switch (action) {
	case JMX_NL_ACT_RULESET_BEGIN_V3:
		return sizeof(struct jmx_nl_begin_v3);
	case JMX_NL_ACT_RULE_V3_BATCH:
		return sizeof(struct jmx_nl_rule_v3);
	case JMX_NL_ACT_STEP_V3_BATCH:
		return sizeof(struct jmx_nl_step_v3);
	case JMX_NL_ACT_PORT_V3_BATCH:
		return sizeof(struct jmx_nl_port_v3);
	default:
		return 0;
	}
}

int jmx_v3_nl_handle(const void *data, u32 len, u32 portid, u32 nlmsg_seq,
			     jmx_v3_nl_reply_fn reply)
{
	const struct jmx_nl_v3_hdr *header;
	const u8 *payload;
	u32 action, generation = 0, count = 0, payload_bytes = 0;
	u32 record_size = 0, flags = 0, expected_size, product;
	u32 reason = JMX_V3_REASON_NONE, detail = 0;
	int rc = -EINVAL;

	if (!data || len < sizeof(jmx_v3_le32))
		return 0;
	memcpy(&action, data, sizeof(action));
	action = le32_to_cpu((__force __le32)action);
	if (!action_is_v3(action))
		return 0;
	if (!portid || !nlmsg_seq) {
		pr_warn_ratelimited("jmx_v3: reject action=%u with sender portid=%u seq=%u\n",
			action, portid, nlmsg_seq);
		return 1;
	}
	mutex_lock(&v3_nl_lock);
	if (len < sizeof(*header)) {
		reason = JMX_V3_REASON_BAD_HEADER;
		goto status;
	}
	header = data;
	generation = wire_le32(header->generation);
	count = wire_le32(header->count);
	payload_bytes = wire_le32(header->payload_bytes);
	record_size = wire_le32(header->record_size);
	flags = wire_le32(header->flags);
	if (wire_le16(header->abi_version) != JMX_RULE_ABI_V3) {
		reason = JMX_V3_REASON_BAD_ABI;
		goto status;
	}
	if (wire_le16(header->header_size) != sizeof(*header)) {
		reason = JMX_V3_REASON_BAD_HEADER;
		goto status;
	}
	if (check_add_overflow((u32)sizeof(*header), payload_bytes,
			       &expected_size) || expected_size != len) {
		reason = JMX_V3_REASON_BAD_SIZE;
		goto status;
	}
	payload = (const u8 *)data + sizeof(*header);
	if (payload_crc32(payload, payload_bytes) != wire_le32(header->crc32)) {
		reason = JMX_V3_REASON_BAD_CRC;
		goto status;
	}
	if (action == JMX_NL_ACT_CAPABILITY_V3 ||
	    action == JMX_NL_ACT_RULESET_STATUS_V3 ||
	    action == JMX_NL_ACT_RULESET_COMMIT_V3 ||
	    action == JMX_NL_ACT_RULESET_ABORT_V3) {
		if (record_size || count || payload_bytes || flags ||
		    (action == JMX_NL_ACT_CAPABILITY_V3 && generation) ||
		    ((action == JMX_NL_ACT_RULESET_COMMIT_V3 ||
		      action == JMX_NL_ACT_RULESET_ABORT_V3) && !generation)) {
			reason = JMX_V3_REASON_BAD_SIZE;
			goto status;
		}
		if (action == JMX_NL_ACT_CAPABILITY_V3 ||
		    action == JMX_NL_ACT_RULESET_STATUS_V3) {
			rc = 0;
			goto status;
		}
		if (action == JMX_NL_ACT_RULESET_COMMIT_V3)
			rc = jmx_v3_tx_commit(portid, generation, &reason, &detail);
		else
			rc = jmx_v3_tx_abort(portid, generation, &reason, &detail);
		goto status;
	}

	expected_size = expected_record_size(action);
	if (!expected_size || record_size != expected_size || !count ||
	    check_mul_overflow(count, record_size, &product) ||
	    product != payload_bytes || !generation) {
		reason = JMX_V3_REASON_BAD_SIZE;
		goto status;
	}
	if (action == JMX_NL_ACT_RULESET_BEGIN_V3) {
		if (count != 1) {
			reason = JMX_V3_REASON_BAD_SIZE;
			goto status;
		}
		rc = jmx_v3_tx_begin(portid, generation,
				     (const struct jmx_nl_begin_v3 *)payload,
				     flags, &reason, &detail);
	} else {
		if (flags) {
			reason = JMX_V3_REASON_BAD_HEADER;
			goto status;
		}
		switch (action) {
		case JMX_NL_ACT_RULE_V3_BATCH:
			rc = jmx_v3_tx_add_rules(portid, generation,
				(const struct jmx_nl_rule_v3 *)payload, count,
				&reason, &detail);
			break;
		case JMX_NL_ACT_STEP_V3_BATCH:
			rc = jmx_v3_tx_add_steps(portid, generation,
				(const struct jmx_nl_step_v3 *)payload, count,
				&reason, &detail);
			break;
		case JMX_NL_ACT_PORT_V3_BATCH:
			rc = jmx_v3_tx_add_ports(portid, generation,
				(const struct jmx_nl_port_v3 *)payload, count,
				&reason, &detail);
			break;
		default:
			reason = JMX_V3_REASON_UNSUPPORTED_ACTION;
			break;
		}
	}
status:
	/* A malformed or rejected data batch makes the generation ambiguous.  Mark
	 * only the matching owner+generation as failed; ABORT remains available. */
	if (rc && generation && action_is_batch(action))
		jmx_v3_tx_fail(portid, generation, reason, detail);
	if (send_status(reply, portid, nlmsg_seq, generation, action,
			rc == 0 ? JMX_V3_STATUS_OK : JMX_V3_STATUS_ERROR,
			reason, detail) < 0)
		pr_warn_ratelimited("jmx_v3: status send failed portid=%u action=%u generation=%u\n",
			portid, action, generation);
	mutex_unlock(&v3_nl_lock);
	return 1;
}

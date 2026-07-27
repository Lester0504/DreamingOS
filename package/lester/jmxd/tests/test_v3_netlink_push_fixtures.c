#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

ssize_t fixture_sendmsg(int fd, const struct msghdr *message, int flags);
ssize_t fixture_recvmsg(int fd, struct msghdr *message, int flags);
int fixture_poll(struct pollfd *fds, nfds_t count, int timeout);

#define sendmsg fixture_sendmsg
#define recvmsg fixture_recvmsg
#define poll fixture_poll
#include "../src/jmx_nl_push.c"
#include "../src/jmx_v3_gate.h"
#undef poll
#undef recvmsg
#undef sendmsg

enum fixture_scenario {
	FIXTURE_NORMAL,
	FIXTURE_COMMIT_NACK,
	FIXTURE_COMMIT_TIMEOUT_MATCH,
	FIXTURE_COMMIT_TIMEOUT_MISMATCH,
};

struct fixture_kernel {
	enum fixture_scenario scenario;
	uint32_t pending_action;
	uint32_t pending_generation;
	uint32_t pending_seq;
	uint32_t actions[16];
	uint32_t action_count;
	uint32_t target_generation;
	uint32_t target_rules;
	uint32_t target_steps;
	uint32_t target_ports;
	uint32_t target_mode;
	uint8_t target_digest[JMX_V3_CATALOG_DIGEST_LEN];
	jmx_v3_kernel_status_t active;
};

static struct fixture_kernel kernel;

static uint32_t fixture_crc32(const void *payload, uint32_t len)
{
	const uint8_t *bytes = payload;
	uint32_t crc = ~0U;
	uint32_t i;

	for (i = 0; i < len; i++) {
		uint32_t bit;
		crc ^= bytes[i];
		for (bit = 0; bit < 8; bit++)
			crc = (crc >> 1) ^
			      (0xedb88320U & (0U - (crc & 1U)));
	}
	return crc ^ ~0U;
}

static void activate_target(void)
{
	kernel.active.active_generation = kernel.target_generation;
	kernel.active.active_rules = kernel.target_rules;
	kernel.active.active_steps = kernel.target_steps;
	kernel.active.active_ports = kernel.target_ports;
	kernel.active.active_mode = kernel.target_mode;
	memcpy(kernel.active.active_catalog_digest, kernel.target_digest,
	       sizeof(kernel.active.active_catalog_digest));
}

static void reset_kernel(enum fixture_scenario scenario)
{
	uint32_t i;

	memset(&kernel, 0, sizeof(kernel));
	kernel.scenario = scenario;
	kernel.active.engine_capabilities = JMX_V3_CAP_PHASE1_MASK;
	kernel.active.active_generation = 40;
	kernel.active.active_rules = 1;
	kernel.active.active_steps = 1;
	kernel.active.active_mode = JMX_V3_MODE_SHADOW;
	for (i = 0; i < JMX_V3_CATALOG_DIGEST_LEN; i++)
		kernel.active.active_catalog_digest[i] = 0xa5;
}

ssize_t fixture_sendmsg(int fd, const struct msghdr *message, int flags)
{
	const struct nlmsghdr *nlh;
	const struct af_msg_hdr_local *outer;
	const struct jmx_nl_v3_hdr *header;
	const uint8_t *inner;
	uint32_t action;

	(void)fd;
	(void)flags;
	assert(message && message->msg_iovlen == 1);
	nlh = message->msg_iov[0].iov_base;
	assert(nlh->nlmsg_len == message->msg_iov[0].iov_len);
	outer = NLMSG_DATA(nlh);
	assert(outer->magic == JMX_NL_MAGIC);
	inner = (const uint8_t *)(outer + 1);
	header = (const struct jmx_nl_v3_hdr *)inner;
	action = v3_le32_to_cpu(header->action);
	assert(kernel.action_count < sizeof(kernel.actions) / sizeof(kernel.actions[0]));
	kernel.actions[kernel.action_count++] = action;
	kernel.pending_action = action;
	kernel.pending_generation = v3_le32_to_cpu(header->generation);
	kernel.pending_seq = nlh->nlmsg_seq;

	if (action == JMX_NL_ACT_RULESET_BEGIN_V3) {
		const struct jmx_nl_begin_v3 *begin =
			(const struct jmx_nl_begin_v3 *)(inner + sizeof(*header));
		kernel.target_generation = kernel.pending_generation;
		kernel.target_rules = v3_le32_to_cpu(begin->expected_rules);
		kernel.target_steps = v3_le32_to_cpu(begin->expected_steps);
		kernel.target_ports = v3_le32_to_cpu(begin->expected_ports);
		kernel.target_mode = v3_le32_to_cpu(header->flags);
		memcpy(kernel.target_digest, begin->catalog_digest,
		       sizeof(kernel.target_digest));
	}
	if (action == JMX_NL_ACT_RULESET_COMMIT_V3 &&
	    (kernel.scenario == FIXTURE_NORMAL ||
	     kernel.scenario == FIXTURE_COMMIT_TIMEOUT_MATCH))
		activate_target();
	return (ssize_t)message->msg_iov[0].iov_len;
}

int fixture_poll(struct pollfd *fds, nfds_t count, int timeout)
{
	(void)timeout;
	assert(fds && count == 1);
	if (kernel.pending_action == JMX_NL_ACT_RULESET_COMMIT_V3 &&
	    (kernel.scenario == FIXTURE_COMMIT_TIMEOUT_MATCH ||
	     kernel.scenario == FIXTURE_COMMIT_TIMEOUT_MISMATCH))
		return 0;
	fds[0].revents = POLLIN;
	return 1;
}

ssize_t fixture_recvmsg(int fd, struct msghdr *message, int flags)
{
	struct nlmsghdr *nlh;
	struct af_msg_hdr_local *outer;
	struct jmx_nl_v3_hdr *header;
	struct jmx_nl_status_v3 *wire;
	struct sockaddr_nl *peer;
	size_t inner_len = sizeof(*header) + sizeof(*wire);
	size_t payload_len = sizeof(*outer) + inner_len;
	size_t message_len = NLMSG_LENGTH(payload_len);
	int nack = kernel.scenario == FIXTURE_COMMIT_NACK &&
		kernel.pending_action == JMX_NL_ACT_RULESET_COMMIT_V3;

	(void)fd;
	(void)flags;
	assert(message && message->msg_iovlen == 1);
	assert(message->msg_iov[0].iov_len >= message_len);
	memset(message->msg_iov[0].iov_base, 0, message->msg_iov[0].iov_len);
	nlh = message->msg_iov[0].iov_base;
	nlh->nlmsg_len = (uint32_t)message_len;
	nlh->nlmsg_seq = kernel.pending_seq;
	nlh->nlmsg_pid = 0;
	outer = NLMSG_DATA(nlh);
	outer->magic = JMX_NL_MAGIC;
	outer->len = (uint32_t)inner_len;
	header = (struct jmx_nl_v3_hdr *)(outer + 1);
	wire = (struct jmx_nl_status_v3 *)(header + 1);
	wire->request_action = v3_cpu_to_le32(kernel.pending_action);
	wire->status = v3_cpu_to_le32(nack ? JMX_V3_STATUS_ERROR : JMX_V3_STATUS_OK);
	wire->reason = v3_cpu_to_le32(nack ? JMX_V3_REASON_COUNT_MISMATCH :
					 JMX_V3_REASON_NONE);
	wire->engine_capabilities =
		v3_cpu_to_le32(kernel.active.engine_capabilities);
	wire->active_generation = v3_cpu_to_le32(kernel.active.active_generation);
	wire->active_rules = v3_cpu_to_le32(kernel.active.active_rules);
	wire->active_steps = v3_cpu_to_le32(kernel.active.active_steps);
	wire->active_ports = v3_cpu_to_le32(kernel.active.active_ports);
	wire->active_mode = v3_cpu_to_le32(kernel.active.active_mode);
	memcpy(wire->active_catalog_digest, kernel.active.active_catalog_digest,
	       sizeof(wire->active_catalog_digest));
	header->action = v3_cpu_to_le32(JMX_NL_ACT_RULESET_STATUS_V3);
	header->abi_version = v3_cpu_to_le16(JMX_RULE_ABI_V3);
	header->header_size = v3_cpu_to_le16(sizeof(*header));
	header->record_size = v3_cpu_to_le32(sizeof(*wire));
	header->generation = v3_cpu_to_le32(kernel.pending_generation);
	header->count = v3_cpu_to_le32(1);
	header->payload_bytes = v3_cpu_to_le32(sizeof(*wire));
	header->crc32 = v3_cpu_to_le32(fixture_crc32(wire, sizeof(*wire)));
	peer = message->msg_name;
	assert(peer);
	memset(peer, 0, sizeof(*peer));
	peer->nl_family = AF_NETLINK;
	peer->nl_pid = 0;
	message->msg_flags = 0;
	return (ssize_t)message_len;
}

static jmx_chain_rule_set_t fixture_ruleset(void)
{
	static jmx_chain_rule_t rule;
	static jmx_chain_step_t step;
	jmx_chain_rule_set_t set;
	uint32_t i;

	memset(&rule, 0, sizeof(rule));
	memset(&step, 0, sizeof(step));
	memset(&set, 0, sizeof(set));
	rule.signature_rule_id = 9001;
	rule.appid = 7001;
	rule.priority = 10;
	rule.required_caps =
		JMX_V3_CAP_RAW_LITERAL_CHAIN | JMX_V3_CAP_PROTOCOL_MAPPING;
	rule.step_count = 1;
	rule.proto = JMX_V3_PROTO_TCP;
	rule.dir = JMX_V3_DIR_ORIGINAL;
	rule.active = 1;
	step.signature_rule_id = rule.signature_rule_id;
	step.matcher_type = JMX_V3_MATCH_LITERAL_EXACT_1;
	step.condition = JMX_V3_CONDITION_POSITIVE;
	step.case_mode = JMX_V3_CASE_EXACT;
	step.input_view = JMX_V3_VIEW_RAW;
	step.literal_option = 0x01;
	step.payload_len = 5;
	memcpy(step.payload, "HELLO", step.payload_len);
	set.rules = &rule;
	set.rule_count = 1;
	set.steps = &step;
	set.step_count = 1;
	for (i = 0; i < JMX_V3_CATALOG_DIGEST_LEN; i++)
		set.catalog_digest[i] = (uint8_t)(i + 1);
	return set;
}

static void require_actions(const uint32_t *expected, uint32_t count)
{
	assert(kernel.action_count == count);
	assert(memcmp(kernel.actions, expected, count * sizeof(expected[0])) == 0);
}

static void test_normal_commit(void)
{
	static const uint32_t actions[] = {
		JMX_NL_ACT_RULESET_BEGIN_V3,
		JMX_NL_ACT_RULE_V3_BATCH,
		JMX_NL_ACT_STEP_V3_BATCH,
		JMX_NL_ACT_RULESET_COMMIT_V3,
	};
	jmx_chain_rule_set_t set = fixture_ruleset();
	jmx_v3_kernel_status_t status;

	reset_kernel(FIXTURE_NORMAL);
	assert(jmx_nl_push_chain_rules(9, &set, 41, JMX_V3_MODE_SHADOW,
				       &status) == 0);
	assert(status.active_generation == 41);
	assert(status.active_mode == JMX_V3_MODE_SHADOW);
	require_actions(actions, sizeof(actions) / sizeof(actions[0]));
}

static void test_explicit_nack_aborts_without_status_probe(void)
{
	static const uint32_t actions[] = {
		JMX_NL_ACT_RULESET_BEGIN_V3,
		JMX_NL_ACT_RULE_V3_BATCH,
		JMX_NL_ACT_STEP_V3_BATCH,
		JMX_NL_ACT_RULESET_COMMIT_V3,
		JMX_NL_ACT_RULESET_ABORT_V3,
	};
	jmx_chain_rule_set_t set = fixture_ruleset();
	jmx_v3_kernel_status_t status;

	reset_kernel(FIXTURE_COMMIT_NACK);
	errno = 0;
	assert(jmx_nl_push_chain_rules(9, &set, 41, JMX_V3_MODE_SHADOW,
				       &status) == -1);
	assert(errno == EPROTO);
	assert(status.reason == JMX_V3_REASON_COUNT_MISMATCH);
	assert(kernel.active.active_generation == 40);
	require_actions(actions, sizeof(actions) / sizeof(actions[0]));
}

static void test_commit_timeout_reconciles_full_active_identity(void)
{
	static const uint32_t actions[] = {
		JMX_NL_ACT_RULESET_BEGIN_V3,
		JMX_NL_ACT_RULE_V3_BATCH,
		JMX_NL_ACT_STEP_V3_BATCH,
		JMX_NL_ACT_RULESET_COMMIT_V3,
		JMX_NL_ACT_RULESET_STATUS_V3,
	};
	jmx_chain_rule_set_t set = fixture_ruleset();
	jmx_v3_kernel_status_t status;

	reset_kernel(FIXTURE_COMMIT_TIMEOUT_MATCH);
	assert(jmx_nl_push_chain_rules(9, &set, 41, JMX_V3_MODE_SHADOW,
				       &status) == 0);
	assert(status.active_generation == 41);
	assert(status.active_rules == 1);
	assert(status.active_steps == 1);
	assert(status.active_mode == JMX_V3_MODE_SHADOW);
	assert(memcmp(status.active_catalog_digest, set.catalog_digest,
		      sizeof(set.catalog_digest)) == 0);
	require_actions(actions, sizeof(actions) / sizeof(actions[0]));
}

static void test_timeout_identity_mismatch_aborts_and_preserves_old_active(void)
{
	static const uint32_t actions[] = {
		JMX_NL_ACT_RULESET_BEGIN_V3,
		JMX_NL_ACT_RULE_V3_BATCH,
		JMX_NL_ACT_STEP_V3_BATCH,
		JMX_NL_ACT_RULESET_COMMIT_V3,
		JMX_NL_ACT_RULESET_STATUS_V3,
		JMX_NL_ACT_RULESET_ABORT_V3,
	};
	jmx_chain_rule_set_t set = fixture_ruleset();
	jmx_v3_kernel_status_t status;

	reset_kernel(FIXTURE_COMMIT_TIMEOUT_MISMATCH);
	errno = 0;
	assert(jmx_nl_push_chain_rules(9, &set, 41, JMX_V3_MODE_SHADOW,
				       &status) == -1);
	assert(errno == EPROTO);
	assert(kernel.active.active_generation == 40);
	assert(status.active_generation == 40);
	require_actions(actions, sizeof(actions) / sizeof(actions[0]));
}

int main(void)
{
	assert(JMX_V3_PRODUCTION_GATE_ENABLED == 0);
	assert(jmx_v3_effective_mode(JMX_V3_MODE_SHADOW) == JMX_V3_MODE_OFF);
	assert(jmx_v3_effective_mode(JMX_V3_MODE_ACTIVE) == JMX_V3_MODE_OFF);
	test_normal_commit();
	test_explicit_nack_aborts_without_status_probe();
	test_commit_timeout_reconciles_full_active_identity();
	test_timeout_identity_mismatch_aborts_and_preserves_old_active();
	puts("ok: v3 userspace netlink push fixtures passed");
	return 0;
}

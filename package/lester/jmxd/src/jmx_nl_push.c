/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jmx_nl_push.c - Push rules to kernel via netlink
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include "jmx_nl_push.h"
#include "jmx_nl_rule.h"
#include "jmx_nl_rule_v3.h"
#include "jmx_rule.h"

#define JMX_NETLINK_ID 29
#define JMX_V2_TIMEOUT_COMMIT_MS 30000
#define JMX_V3_BATCH_SIZE 128U
#define JMX_V3_TIMEOUT_PROBE_STATUS_MS 2000
#define JMX_V3_TIMEOUT_BATCH_BEGIN_ABORT_MS 5000
#define JMX_V3_TIMEOUT_COMMIT_MS 30000

/* ── Netlink socket ── */

int jmx_nl_socket_create(void)
{
	int fd;
	struct sockaddr_nl sa;

	fd = socket(AF_NETLINK, SOCK_RAW, JMX_NETLINK_ID);
	if (fd < 0) {
		perror("netlink socket");
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_pid = 0; /* let kernel assign */

	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("netlink bind");
		close(fd);
		return -1;
	}

	return fd;
}

/* ── Send raw netlink message ── */

/* Magic header expected by kernel jmx_netlink_msg_rcv */
struct af_msg_hdr_local {
	uint32_t magic;
	uint32_t len;
};

static int nl_send_seq(int fd, const void *data, uint32_t len, uint32_t seq)
{
	struct sockaddr_nl sa;
	struct nlmsghdr *nlh;
	struct iovec iov;
	struct msghdr msg;
	ssize_t ret;
	size_t total, alloc_len, nlmsg_len;
	struct af_msg_hdr_local *hdr;

	if ((len && !data) || len > INT_MAX) {
		errno = EINVAL;
		return -1;
	}
#if SIZE_MAX < UINT32_MAX
	if ((size_t)len > SIZE_MAX - sizeof(struct af_msg_hdr_local)) {
		errno = EOVERFLOW;
		return -1;
	}
#endif
	total = (size_t)len + sizeof(struct af_msg_hdr_local);
	alloc_len = NLMSG_SPACE(total);
	nlmsg_len = NLMSG_LENGTH(total);
	if (alloc_len < nlmsg_len || nlmsg_len > UINT32_MAX) {
		errno = EOVERFLOW;
		return -1;
	}
	nlh = calloc(1, alloc_len);
	if (!nlh)
		return -1;

	nlh->nlmsg_len = (uint32_t)nlmsg_len;
	nlh->nlmsg_type = 0;
	nlh->nlmsg_flags = seq ? NLM_F_REQUEST : 0;
	nlh->nlmsg_seq = seq;
	hdr = (struct af_msg_hdr_local *)NLMSG_DATA(nlh);
	hdr->magic = JMX_NL_MAGIC;
	hdr->len = len;
	if (len)
		memcpy((char *)NLMSG_DATA(nlh) + sizeof(struct af_msg_hdr_local),
		       data, len);

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_pid = 0; /* kernel */

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = nlh;
	iov.iov_len = nlh->nlmsg_len;
	msg.msg_name = &sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	ret = sendmsg(fd, &msg, 0);
	if (ret < 0) {
		fprintf(stderr, "nl_send sendmsg failed: %s (len=%zu fd=%d seq=%u)\n",
			strerror(errno), total, fd, seq);
	} else {
		static int sent_cnt = 0;
		if (++sent_cnt <= 3 || (sent_cnt % 20) == 0 || seq)
			fprintf(stderr, "nl_send #%d: %zd bytes seq=%u\n",
				sent_cnt, ret, seq);
	}
	free(nlh);

	if (ret < 0)
		return -1;
	if ((size_t)ret != nlmsg_len) {
		errno = EIO;
		return -1;
	}
	return 0;
}

static int nl_send(int fd, const void *data, int len)
{
	if (len < 0) {
		errno = EINVAL;
		return -1;
	}
	return nl_send_seq(fd, data, (uint32_t)len, 0);
}

static pthread_mutex_t g_nl_lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t g_v2_next_seq;

enum v2_ack_result {
	V2_ACK_OK = 0,
	V2_ACK_NACK = 1,
	V2_RESULT_UNKNOWN = 2,
};

static void v2_lock(void)
{
	pthread_mutex_lock(&g_nl_lock);
}

static void v2_unlock_preserve_errno(void)
{
	int saved_errno = errno;

	pthread_mutex_unlock(&g_nl_lock);
	errno = saved_errno;
}

static uint32_t v2_next_seq_locked(void)
{
	g_v2_next_seq++;
	if (!g_v2_next_seq)
		g_v2_next_seq = 1;
	return g_v2_next_seq;
}

static int64_t nl_monotonic_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return -1;
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static enum v2_ack_result v2_decode_commit_ack(const void *buffer, size_t bytes,
						       uint32_t seq, uint32_t version,
						       uint32_t expected_count)
{
	const struct nlmsghdr *nlh = buffer;
	const struct af_msg_hdr_local *outer;
	const struct jmx_nl_rule_status_msg *ack;
	size_t nl_payload;

	if (bytes < NLMSG_HDRLEN || nlh->nlmsg_len < NLMSG_HDRLEN ||
	    nlh->nlmsg_len > bytes)
		return V2_RESULT_UNKNOWN;
	if (nlh->nlmsg_seq != seq || nlh->nlmsg_pid != 0)
		return V2_RESULT_UNKNOWN;
	nl_payload = nlh->nlmsg_len - NLMSG_HDRLEN;
	if (nl_payload != sizeof(*outer) + sizeof(*ack)) {
		errno = EMSGSIZE;
		return V2_ACK_NACK;
	}
	outer = NLMSG_DATA(nlh);
	if (outer->magic != JMX_NL_MAGIC || outer->len != sizeof(*ack)) {
		errno = EPROTO;
		return V2_ACK_NACK;
	}
	ack = (const struct jmx_nl_rule_status_msg *)(outer + 1);
	if (ack->action != JMX_NL_ACT_RULE_STATUS ||
	    ack->request_action != JMX_NL_ACT_RULE_VERSION ||
	    ack->version != version) {
		errno = EPROTO;
		return V2_ACK_NACK;
	}
	if (ack->status != 0) {
		errno = ack->status < 0 ? -ack->status : EPROTO;
		return V2_ACK_NACK;
	}
	if (ack->active_version != version || ack->active_rules != expected_count) {
		errno = EPROTO;
		return V2_ACK_NACK;
	}
	return V2_ACK_OK;
}

static enum v2_ack_result v2_wait_commit_ack_locked(int fd, uint32_t seq,
						    uint32_t version,
						    uint32_t expected_count)
{
	uint8_t buffer[512];
	int64_t deadline = nl_monotonic_ms();

	if (deadline < 0)
		return V2_RESULT_UNKNOWN;
	deadline += JMX_V2_TIMEOUT_COMMIT_MS;
	for (;;) {
		struct sockaddr_nl peer;
		struct iovec iov = { .iov_base = buffer, .iov_len = sizeof(buffer) };
		struct msghdr msg;
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		int64_t now = nl_monotonic_ms();
		int timeout, rc;
		ssize_t received;
		enum v2_ack_result decoded;

		if (now < 0 || now >= deadline) {
			errno = ETIMEDOUT;
			return V2_RESULT_UNKNOWN;
		}
		timeout = (int)(deadline - now);
		rc = poll(&pfd, 1, timeout);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			return V2_RESULT_UNKNOWN;
		}
		if (rc == 0) {
			errno = ETIMEDOUT;
			return V2_RESULT_UNKNOWN;
		}
		if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			errno = EIO;
			return V2_RESULT_UNKNOWN;
		}
		if (!(pfd.revents & POLLIN))
			continue;
		memset(&peer, 0, sizeof(peer));
		memset(&msg, 0, sizeof(msg));
		msg.msg_name = &peer;
		msg.msg_namelen = sizeof(peer);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		received = recvmsg(fd, &msg, MSG_DONTWAIT);
		if (received < 0) {
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			return V2_RESULT_UNKNOWN;
		}
		if (peer.nl_pid != 0)
			continue;
		if (msg.msg_flags & MSG_TRUNC) {
			errno = EMSGSIZE;
			return V2_RESULT_UNKNOWN;
		}
		decoded = v2_decode_commit_ack(buffer, (size_t)received, seq, version,
						       expected_count);
		if (decoded == V2_ACK_OK || decoded == V2_ACK_NACK)
			return decoded;
	}
}

static int nl_commit_version_locked(int fd, uint32_t version,
					    uint32_t expected_count)
{
	struct jmx_nl_rule_version_msg vmsg = {
		.action = JMX_NL_ACT_RULE_VERSION,
		.version = version,
	};
	uint32_t seq = v2_next_seq_locked();
	enum v2_ack_result ack;

	if (nl_send_seq(fd, &vmsg, sizeof(vmsg), seq) != 0)
		return -1;
	ack = v2_wait_commit_ack_locked(fd, seq, version, expected_count);
	if (ack != V2_ACK_OK) {
		if (ack == V2_ACK_NACK && errno == 0)
			errno = EPROTO;
		fprintf(stderr,
			"nl_commit_version ACK failed: version=%u expected_count=%u seq=%u: %s\n",
			version, expected_count, seq, strerror(errno));
		return -1;
	}
	return 0;
}

static int nl_flush_rules_locked(int fd)
{
	struct jmx_nl_rule_flush_msg msg = {
		.action = JMX_NL_ACT_RULE_FLUSH,
	};
	return nl_send(fd, &msg, sizeof(msg));
}

/* ── Convert jmx_match_rule_t to jmx_nl_rule ── */

static void rule_to_nl(const jmx_match_rule_t *src, struct jmx_nl_rule *dst)
{
	uint8_t i;

	memset(dst, 0, sizeof(*dst));
	dst->appid = src->appid;
	dst->rule_id = src->rule_id;
	dst->priority = src->priority;
	dst->method = (uint8_t)src->method;
	dst->proto = (uint8_t)src->proto;
	dst->dir = (uint8_t)src->dir;
	dst->pkt_seq = src->pkt_seq;
	dst->offset = src->offset;

	/* Copy match_str */
	dst->match_len = src->match_len;
	if (dst->match_len > JMX_NL_MAX_MATCH)
		dst->match_len = JMX_NL_MAX_MATCH;
	memcpy(dst->match_str, src->match_str, dst->match_len);

	/* Copy port ranges */
	dst->port_count = src->port_count;
	if (dst->port_count > JMX_NL_MAX_PORTS)
		dst->port_count = JMX_NL_MAX_PORTS;
	for (i = 0; i < dst->port_count; i++) {
		dst->ports[i].min_port = src->ports[i].min_port;
		dst->ports[i].max_port = src->ports[i].max_port;
	}

	/* Copy len ranges */
	dst->len_count = src->len_count;
	if (dst->len_count > JMX_NL_MAX_LEN_RNG)
		dst->len_count = JMX_NL_MAX_LEN_RNG;
	for (i = 0; i < dst->len_count; i++) {
		dst->len_range[i].min_len = src->len_range[i].min_len;
		dst->len_range[i].max_len = src->len_range[i].max_len;
	}
}

/* ── Push rules in batch ── */

#define BATCH_SIZE 64

int jmx_nl_push_rules(int nl_fd, const jmx_rule_set_t *rs, uint32_t version)
{
	/* Flatten rules into array */
	struct jmx_nl_rule *batch;
	uint32_t total;
	uint32_t pushed = 0;
	uint32_t i, count;
	jmx_match_rule_t *r;
	int ret = -1;

	if (!rs) {
		errno = EINVAL;
		return -1;
	}
	total = rs->total_rules;
	v2_lock();

	/* Even an empty rule set must replace the kernel's previous staging set. */
	if (nl_flush_rules_locked(nl_fd) < 0)
		goto out_unlock;

	if (total == 0) {
		ret = nl_commit_version_locked(nl_fd, version, 0);
		if (ret < 0) {
			fprintf(stderr, "nl_send empty version failed\n");
			goto out_unlock;
		}
		fprintf(stderr, "Pushed 0 rules to kernel (version=%u, ACK active_rules=0)\n",
			version);
		goto out_unlock;
	}

	batch = malloc(sizeof(struct jmx_nl_rule) * BATCH_SIZE);
	if (!batch)
		goto out_unlock;

	/* Iterate all buckets, batch-send */
	for (i = 0; i < JMX_HASH_BUCKETS; i++) {
		for (r = rs->match_buckets[i]; r; r = r->next) {
			rule_to_nl(r, &batch[pushed % BATCH_SIZE]);
			pushed++;

			if (pushed % BATCH_SIZE == 0) {
				/* Send batch */
				count = BATCH_SIZE;
				size_t msg_len = sizeof(struct jmx_nl_rule_batch_msg)
						 + sizeof(struct jmx_nl_rule) * count;
				struct jmx_nl_rule_batch_msg *msg = malloc(msg_len);
				if (!msg) { free(batch); goto out_unlock; }
				msg->action = JMX_NL_ACT_RULE_ADD_BATCH;
				msg->count = count;
				msg->version = version;
				memcpy(msg + 1, batch, sizeof(struct jmx_nl_rule) * count);

				ret = nl_send(nl_fd, msg, (int)msg_len);
				free(msg);
				if (ret < 0) {
					fprintf(stderr, "nl_send batch failed: %s\n",
						strerror(errno));
					free(batch);
					goto out_unlock;
				}
			}
		}
	}

	/* Send remaining rules */
	if (pushed % BATCH_SIZE != 0) {
		count = pushed % BATCH_SIZE;
		size_t msg_len = sizeof(struct jmx_nl_rule_batch_msg)
				 + sizeof(struct jmx_nl_rule) * count;
		struct jmx_nl_rule_batch_msg *msg = malloc(msg_len);
		if (!msg) { free(batch); goto out_unlock; }
		msg->action = JMX_NL_ACT_RULE_ADD_BATCH;
		msg->count = count;
		msg->version = version;
		memcpy(msg + 1, batch, sizeof(struct jmx_nl_rule) * count);

		ret = nl_send(nl_fd, msg, (int)msg_len);
		free(msg);
		if (ret < 0) {
			fprintf(stderr, "nl_send final batch failed\n");
			free(batch);
			goto out_unlock;
		}
	}

	free(batch);

	if (pushed != total) {
		errno = EPROTO;
		ret = -1;
		goto out_unlock;
	}

	/* Signal version commit (atomic swap) and require explicit ACK snapshot. */
	ret = nl_commit_version_locked(nl_fd, version, pushed);
	if (ret < 0) {
		fprintf(stderr, "nl_send version failed\n");
		goto out_unlock;
	}

	fprintf(stderr, "Pushed %u rules to kernel (version=%u, ACK active_rules=%u)\n",
		pushed, version, pushed);
	ret = 0;

out_unlock:
	v2_unlock_preserve_errno();
	return ret;
}

int jmx_nl_flush_rules(int nl_fd)
{
	int rc;

	v2_lock();
	rc = nl_flush_rules_locked(nl_fd);
	v2_unlock_preserve_errno();
	return rc;
}

static uint32_t g_v3_next_seq;

enum v3_ack_result {
	V3_ACK_OK = 0,
	V3_ACK_NACK = 1,
	V3_RESULT_UNKNOWN = 2,
};

static void v3_lock(void)
{
	pthread_mutex_lock(&g_nl_lock);
}

static void v3_unlock_preserve_errno(void)
{
	int saved_errno = errno;

	pthread_mutex_unlock(&g_nl_lock);
	errno = saved_errno;
}

static uint32_t v3_next_seq_locked(void)
{
	g_v3_next_seq++;
	if (!g_v3_next_seq)
		g_v3_next_seq = 1;
	return g_v3_next_seq;
}

static uint16_t v3_cpu_to_le16(uint16_t value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return value;
#else
	return __builtin_bswap16(value);
#endif
}

static uint32_t v3_cpu_to_le32(uint32_t value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return value;
#else
	return __builtin_bswap32(value);
#endif
}

static uint16_t v3_le16_to_cpu(uint16_t value)
{
	return v3_cpu_to_le16(value);
}

static uint32_t v3_le32_to_cpu(uint32_t value)
{
	return v3_cpu_to_le32(value);
}

static uint32_t v3_payload_crc32(const void *payload, uint32_t len)
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

static int64_t v3_monotonic_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return -1;
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int v3_action_timeout_ms(uint32_t action)
{
	switch (action) {
	case JMX_NL_ACT_CAPABILITY_V3:
	case JMX_NL_ACT_RULESET_STATUS_V3:
		return JMX_V3_TIMEOUT_PROBE_STATUS_MS;
	case JMX_NL_ACT_RULESET_COMMIT_V3:
		return JMX_V3_TIMEOUT_COMMIT_MS;
	case JMX_NL_ACT_RULESET_BEGIN_V3:
	case JMX_NL_ACT_RULE_V3_BATCH:
	case JMX_NL_ACT_STEP_V3_BATCH:
	case JMX_NL_ACT_PORT_V3_BATCH:
	case JMX_NL_ACT_RULESET_ABORT_V3:
	default:
		return JMX_V3_TIMEOUT_BATCH_BEGIN_ABORT_MS;
	}
}

static int v3_size_add(size_t a, size_t b, size_t *out)
{
	if (a > SIZE_MAX - b) {
		errno = EOVERFLOW;
		return -1;
	}
	*out = a + b;
	return 0;
}

static int v3_size_mul(uint32_t count, size_t size, uint32_t *out)
{
	size_t total;

	if (size && count > SIZE_MAX / size) {
		errno = EOVERFLOW;
		return -1;
	}
	total = (size_t)count * size;
	if (total > UINT32_MAX) {
		errno = EOVERFLOW;
		return -1;
	}
	*out = (uint32_t)total;
	return 0;
}

static int v3_nl_send_locked(int fd, const void *data, uint32_t len,
				     uint32_t seq)
{
	struct sockaddr_nl sa;
	struct nlmsghdr *nlh;
	struct iovec iov;
	struct msghdr msg;
	struct af_msg_hdr_local *hdr;
	size_t total, alloc_len, nlmsg_len;
	ssize_t sent;

	if ((len && !data) || v3_size_add(sizeof(struct af_msg_hdr_local), len,
						 &total) != 0)
		return -1;
	if (total > (size_t)INT_MAX) {
		errno = EOVERFLOW;
		return -1;
	}
	alloc_len = NLMSG_SPACE(total);
	nlmsg_len = NLMSG_LENGTH(total);
	if (alloc_len < nlmsg_len || nlmsg_len > (size_t)UINT32_MAX) {
		errno = EOVERFLOW;
		return -1;
	}
	nlh = calloc(1, alloc_len);
	if (!nlh)
		return -1;
	nlh->nlmsg_len = (uint32_t)nlmsg_len;
	nlh->nlmsg_type = 0;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = seq;
	nlh->nlmsg_pid = 0;
	hdr = (struct af_msg_hdr_local *)NLMSG_DATA(nlh);
	hdr->magic = 0xa0b0c0d0;
	hdr->len = len;
	if (len)
		memcpy((uint8_t *)NLMSG_DATA(nlh) + sizeof(*hdr), data, len);

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_pid = 0;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = nlh;
	iov.iov_len = nlh->nlmsg_len;
	msg.msg_name = &sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	sent = sendmsg(fd, &msg, 0);
	free(nlh);
	if (sent < 0)
		return -1;
	if ((size_t)sent != nlmsg_len) {
		errno = EIO;
		return -1;
	}
	return 0;
}

static enum v3_ack_result v3_decode_status(const void *buffer, size_t bytes,
					   uint32_t seq,
					   uint32_t request_action,
					   uint32_t generation,
					   jmx_v3_kernel_status_t *status)
{
	const struct nlmsghdr *nlh = buffer;
	const struct af_msg_hdr_local *outer;
	const struct jmx_nl_v3_hdr *header;
	const struct jmx_nl_status_v3 *wire;
	const uint8_t *inner;
	size_t nl_payload, inner_len;
	uint32_t wire_status;

	if (bytes < NLMSG_HDRLEN || nlh->nlmsg_len < NLMSG_HDRLEN ||
	    nlh->nlmsg_len > bytes)
		return V3_RESULT_UNKNOWN;
	if (nlh->nlmsg_seq != seq || nlh->nlmsg_pid != 0)
		return V3_RESULT_UNKNOWN;
	nl_payload = nlh->nlmsg_len - NLMSG_HDRLEN;
	if (nl_payload < sizeof(*outer) + sizeof(*header) + sizeof(*wire))
		return V3_RESULT_UNKNOWN;
	outer = NLMSG_DATA(nlh);
	if (outer->magic != 0xa0b0c0d0 || outer->len == 0 ||
	    (size_t)outer->len != nl_payload - sizeof(*outer))
		return V3_RESULT_UNKNOWN;
	inner = (const uint8_t *)(outer + 1);
	inner_len = (size_t)outer->len;
	header = (const struct jmx_nl_v3_hdr *)inner;
	if (inner_len != sizeof(*header) + sizeof(*wire) ||
	    v3_le32_to_cpu(header->action) != JMX_NL_ACT_RULESET_STATUS_V3 ||
	    v3_le16_to_cpu(header->abi_version) != JMX_RULE_ABI_V3 ||
	    v3_le16_to_cpu(header->header_size) != sizeof(*header) ||
	    v3_le32_to_cpu(header->record_size) != sizeof(*wire) ||
	    v3_le32_to_cpu(header->count) != 1 ||
	    v3_le32_to_cpu(header->payload_bytes) != sizeof(*wire) ||
	    v3_le32_to_cpu(header->flags) != 0 ||
	    v3_le32_to_cpu(header->generation) != generation)
		return V3_RESULT_UNKNOWN;
	wire = (const struct jmx_nl_status_v3 *)(inner + sizeof(*header));
	if (v3_payload_crc32(wire, sizeof(*wire)) !=
	    v3_le32_to_cpu(header->crc32) ||
	    v3_le32_to_cpu(wire->request_action) != request_action)
		return V3_RESULT_UNKNOWN;

	if (status) {
		memset(status, 0, sizeof(*status));
		status->engine_capabilities =
			v3_le32_to_cpu(wire->engine_capabilities);
		status->active_generation =
			v3_le32_to_cpu(wire->active_generation);
		status->active_rules = v3_le32_to_cpu(wire->active_rules);
		status->active_steps = v3_le32_to_cpu(wire->active_steps);
		status->active_ports = v3_le32_to_cpu(wire->active_ports);
		status->active_mode = v3_le32_to_cpu(wire->active_mode);
		memcpy(status->active_catalog_digest,
		       wire->active_catalog_digest,
		       sizeof(status->active_catalog_digest));
		status->staging_generation =
			v3_le32_to_cpu(wire->staging_generation);
		status->staging_state = v3_le32_to_cpu(wire->staging_state);
		status->reason = v3_le32_to_cpu(wire->reason);
		status->detail = v3_le32_to_cpu(wire->detail);
	}
	wire_status = v3_le32_to_cpu(wire->status);
	if (wire_status == JMX_V3_STATUS_OK)
		return V3_ACK_OK;
	errno = EPROTO;
	return V3_ACK_NACK;
}

static enum v3_ack_result v3_wait_status_locked(int fd,
						uint32_t request_action,
						uint32_t generation,
						uint32_t seq,
						jmx_v3_kernel_status_t *status)
{
	uint8_t buffer[4096];
	int64_t deadline = v3_monotonic_ms();
	int timeout_ms = v3_action_timeout_ms(request_action);

	if (deadline < 0)
		return V3_RESULT_UNKNOWN;
	deadline += timeout_ms;
	for (;;) {
		struct sockaddr_nl peer;
		struct iovec iov = { .iov_base = buffer, .iov_len = sizeof(buffer) };
		struct msghdr msg;
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		int64_t now = v3_monotonic_ms();
		int timeout, rc;
		ssize_t received;
		enum v3_ack_result decoded;

		if (now < 0 || now >= deadline) {
			errno = ETIMEDOUT;
			return V3_RESULT_UNKNOWN;
		}
		timeout = (int)(deadline - now);
		rc = poll(&pfd, 1, timeout);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			return V3_RESULT_UNKNOWN;
		}
		if (rc == 0) {
			errno = ETIMEDOUT;
			return V3_RESULT_UNKNOWN;
		}
		if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			errno = EIO;
			return V3_RESULT_UNKNOWN;
		}
		if (!(pfd.revents & POLLIN))
			continue;
		memset(&peer, 0, sizeof(peer));
		memset(&msg, 0, sizeof(msg));
		msg.msg_name = &peer;
		msg.msg_namelen = sizeof(peer);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		received = recvmsg(fd, &msg, MSG_DONTWAIT);
		if (received < 0) {
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			return V3_RESULT_UNKNOWN;
		}
		if (peer.nl_pid != 0)
			continue;
		if (msg.msg_flags & MSG_TRUNC) {
			errno = EMSGSIZE;
			return V3_RESULT_UNKNOWN;
		}
		decoded = v3_decode_status(buffer, (size_t)received, seq,
					       request_action, generation, status);
		if (decoded == V3_ACK_OK || decoded == V3_ACK_NACK)
			return decoded;
	}
}

static enum v3_ack_result v3_send_request_locked(int fd, uint32_t action,
						 uint32_t generation,
						 uint32_t flags,
						 uint32_t record_size,
						 uint32_t count,
						 const void *payload,
						 uint32_t payload_bytes,
						 jmx_v3_kernel_status_t *status)
{
	struct jmx_nl_v3_hdr *header;
	uint8_t *message;
	size_t total;
	uint32_t seq;

	if (payload_bytes && !payload) {
		errno = EINVAL;
		return V3_RESULT_UNKNOWN;
	}
	if (v3_size_add(sizeof(*header), payload_bytes, &total) != 0)
		return V3_RESULT_UNKNOWN;
	if (total > UINT32_MAX) {
		errno = EOVERFLOW;
		return V3_RESULT_UNKNOWN;
	}
	message = calloc(1, total);
	if (!message)
		return V3_RESULT_UNKNOWN;
	header = (struct jmx_nl_v3_hdr *)message;
	header->action = v3_cpu_to_le32(action);
	header->abi_version = v3_cpu_to_le16(JMX_RULE_ABI_V3);
	header->header_size = v3_cpu_to_le16(sizeof(*header));
	header->record_size = v3_cpu_to_le32(record_size);
	header->generation = v3_cpu_to_le32(generation);
	header->count = v3_cpu_to_le32(count);
	header->payload_bytes = v3_cpu_to_le32(payload_bytes);
	header->flags = v3_cpu_to_le32(flags);
	if (payload_bytes)
		memcpy(message + sizeof(*header), payload, payload_bytes);
	header->crc32 = v3_cpu_to_le32(v3_payload_crc32(
		message + sizeof(*header), payload_bytes));
	seq = v3_next_seq_locked();
	if (v3_nl_send_locked(fd, message, (uint32_t)total, seq) != 0) {
		free(message);
		return V3_RESULT_UNKNOWN;
	}
	free(message);
	return v3_wait_status_locked(fd, action, generation, seq, status);
}

static int v3_ack_to_errno(enum v3_ack_result result)
{
	if (result == V3_ACK_OK)
		return 0;
	if (result == V3_ACK_NACK && errno == 0)
		errno = EPROTO;
	return -1;
}

int jmx_nl_v3_probe(int nl_fd, jmx_v3_kernel_status_t *status)
{
	enum v3_ack_result result;

	if (status)
		memset(status, 0, sizeof(*status));
	v3_lock();
	result = v3_send_request_locked(nl_fd, JMX_NL_ACT_CAPABILITY_V3, 0, 0,
					    0, 0, NULL, 0, status);
	v3_unlock_preserve_errno();
	return v3_ack_to_errno(result);
}

int jmx_nl_v3_status(int nl_fd, uint32_t generation,
			  jmx_v3_kernel_status_t *status)
{
	enum v3_ack_result result;

	if (status)
		memset(status, 0, sizeof(*status));
	v3_lock();
	result = v3_send_request_locked(nl_fd, JMX_NL_ACT_RULESET_STATUS_V3,
					    generation, 0, 0, 0, NULL, 0,
					    status);
	v3_unlock_preserve_errno();
	return v3_ack_to_errno(result);
}

static int v3_status_matches(const jmx_v3_kernel_status_t *status,
				     uint32_t generation, uint32_t rules,
				     uint32_t steps, uint32_t ports,
				     uint8_t mode, const uint8_t *catalog_digest)
{
	return status && status->active_generation == generation &&
	       status->active_rules == rules && status->active_steps == steps &&
	       status->active_ports == ports && status->active_mode == mode &&
	       catalog_digest &&
	       memcmp(status->active_catalog_digest, catalog_digest,
		      JMX_V3_CATALOG_DIGEST_LEN) == 0;
}

static int v3_reconcile_status_locked(int fd, uint32_t generation,
					      uint32_t rules, uint32_t steps,
					      uint32_t ports, uint8_t mode,
					      const uint8_t *catalog_digest,
					      jmx_v3_kernel_status_t *status)
{
	enum v3_ack_result result;

	result = v3_send_request_locked(fd, JMX_NL_ACT_RULESET_STATUS_V3,
					generation, 0, 0, 0, NULL, 0, status);
	if (result != V3_ACK_OK)
		return -1;
	if (!v3_status_matches(status, generation, rules, steps, ports, mode,
			       catalog_digest)) {
		errno = EPROTO;
		return -1;
	}
	return 0;
}

static int v3_rule_to_wire(const jmx_chain_rule_t *src,
			    struct jmx_nl_rule_v3 *wire)
{
	if (!src || !wire || src->step_count > JMX_V3_MAX_STEPS_PER_RULE) {
		errno = EINVAL;
		return -1;
	}
	memset(wire, 0, sizeof(*wire));
	wire->signature_rule_id = v3_cpu_to_le32(src->signature_rule_id);
	wire->appid = v3_cpu_to_le32(src->appid);
	wire->priority = v3_cpu_to_le32(src->priority);
	wire->required_caps = v3_cpu_to_le32(src->required_caps);
	wire->step_count = v3_cpu_to_le16(src->step_count);
	wire->proto = src->proto;
	wire->dir = src->dir;
	wire->flags = src->flags;
	return 0;
}

static int v3_step_to_wire(const jmx_chain_step_t *src,
			    struct jmx_nl_step_v3 *wire)
{
	if (!src || !wire || src->payload_len > JMX_V3_PAYLOAD_MAX) {
		errno = EINVAL;
		return -1;
	}
	memset(wire, 0, sizeof(*wire));
	wire->signature_rule_id = v3_cpu_to_le32(src->signature_rule_id);
	wire->step_index = v3_cpu_to_le16(src->step_index);
	wire->matcher_type = src->matcher_type;
	wire->condition = src->condition;
	wire->case_mode = src->case_mode;
	wire->input_view = src->input_view;
	wire->position_flags = src->position_flags;
	wire->numeric_encoding = src->numeric_encoding;
	wire->literal_option = src->literal_option;
	wire->depth = v3_cpu_to_le32((uint32_t)src->depth);
	wire->offset = v3_cpu_to_le32((uint32_t)src->offset);
	wire->distance = v3_cpu_to_le32((uint32_t)src->distance);
	wire->within = v3_cpu_to_le32((uint32_t)src->within);
	wire->payload_len = v3_cpu_to_le16(src->payload_len);
	wire->reference_source = v3_cpu_to_le16(src->reference_source);
	wire->comparison = src->comparison;
	wire->adjust_mode = src->adjust_mode;
	wire->width = src->width;
	wire->jump_multiplier = src->jump_multiplier;
	wire->inline_operand = v3_cpu_to_le32(src->inline_operand);
	wire->adjustment_operand = v3_cpu_to_le32(src->adjustment_operand);
	wire->jump_base = v3_cpu_to_le32((uint32_t)src->jump_base);
	if (src->payload_len)
		memcpy(wire->payload, src->payload, src->payload_len);
	return 0;
}

static int v3_port_to_wire(const jmx_chain_port_t *src,
			    struct jmx_nl_port_v3 *wire)
{
	if (!src || !wire) {
		errno = EINVAL;
		return -1;
	}
	memset(wire, 0, sizeof(*wire));
	wire->signature_rule_id = v3_cpu_to_le32(src->signature_rule_id);
	wire->endpoint = src->endpoint;
	wire->min_port = v3_cpu_to_le16(src->min_port);
	wire->max_port = v3_cpu_to_le16(src->max_port);
	return 0;
}

static int v3_digest_is_zero(const uint8_t *digest)
{
	uint32_t i;

	if (!digest)
		return 1;
	for (i = 0; i < JMX_V3_CATALOG_DIGEST_LEN; i++)
		if (digest[i])
			return 0;
	return 1;
}

static int v3_preflight_ruleset(const jmx_chain_rule_set_t *rs,
				       uint32_t *rules, uint32_t *steps,
				       uint32_t *ports, uint32_t *caps)
{
	size_t i;
	uint64_t rule_count = 0, step_count = 0, port_count = 0;
	uint32_t required = 0;

	if (!rs || !rules || !steps || !ports || !caps) {
		errno = EINVAL;
		return -1;
	}
	if ((rs->rule_count && !rs->rules) || (rs->step_count && !rs->steps) ||
	    (rs->port_count && !rs->ports)) {
		errno = EINVAL;
		return -1;
	}
	for (i = 0; i < rs->rule_count; i++) {
		const jmx_chain_rule_t *rule = &rs->rules[i];
		uint64_t first_step, first_port, step_end, port_end;
		uint32_t j;

		if (!rule->active)
			continue;
		if (rule->step_count > JMX_V3_MAX_STEPS_PER_RULE ||
		    rule->port_count > JMX_V3_MAX_PORTS_PER_RULE) {
			errno = EINVAL;
			return -1;
		}
		first_step = rule->first_step;
		first_port = rule->first_port;
		step_end = first_step + (uint64_t)rule->step_count;
		port_end = first_port + (uint64_t)rule->port_count;
		if (first_step > rs->step_count || step_end > rs->step_count ||
		    first_port > rs->port_count || port_end > rs->port_count) {
			errno = ERANGE;
			return -1;
		}
		if (rule->step_count && !rs->steps) {
			errno = EINVAL;
			return -1;
		}
		if (rule->port_count && !rs->ports) {
			errno = EINVAL;
			return -1;
		}
		for (j = 0; j < rule->step_count; j++) {
			const jmx_chain_step_t *step = &rs->steps[rule->first_step + j];

			if (step->signature_rule_id != rule->signature_rule_id ||
			    step->payload_len > JMX_V3_PAYLOAD_MAX) {
				errno = EINVAL;
				return -1;
			}
		}
		for (j = 0; j < rule->port_count; j++) {
			const jmx_chain_port_t *port = &rs->ports[rule->first_port + j];

			if (port->signature_rule_id != rule->signature_rule_id) {
				errno = EINVAL;
				return -1;
			}
		}
		rule_count++;
		step_count += rule->step_count;
		port_count += rule->port_count;
		required |= rule->required_caps;
		if (rule_count > UINT32_MAX || step_count > UINT32_MAX ||
		    port_count > UINT32_MAX) {
			errno = EOVERFLOW;
			return -1;
		}
	}
	if (rule_count && v3_digest_is_zero(rs->catalog_digest)) {
		errno = EINVAL;
		return -1;
	}
	*rules = (uint32_t)rule_count;
	*steps = (uint32_t)step_count;
	*ports = (uint32_t)port_count;
	*caps = required;
	return 0;
}

static int v3_send_rule_batches_locked(int fd, const jmx_chain_rule_set_t *rs,
				       uint32_t generation,
				       jmx_v3_kernel_status_t *status)
{
	struct jmx_nl_rule_v3 batch[JMX_V3_BATCH_SIZE];
	uint32_t count = 0;
	size_t i;

	for (i = 0; i < rs->rule_count; i++) {
		uint32_t payload_bytes;

		if (!rs->rules[i].active)
			continue;
		if (v3_rule_to_wire(&rs->rules[i], &batch[count++]) != 0)
			return -1;
		if (count == JMX_V3_BATCH_SIZE) {
			if (v3_size_mul(count, sizeof(batch[0]), &payload_bytes) != 0)
				return -1;
			if (v3_send_request_locked(fd, JMX_NL_ACT_RULE_V3_BATCH,
						   generation, 0, sizeof(batch[0]), count,
						   batch, payload_bytes, status) != V3_ACK_OK)
				return -1;
			count = 0;
		}
	}
	if (count) {
		uint32_t payload_bytes;

		if (v3_size_mul(count, sizeof(batch[0]), &payload_bytes) != 0)
			return -1;
		if (v3_send_request_locked(fd, JMX_NL_ACT_RULE_V3_BATCH,
					   generation, 0, sizeof(batch[0]), count,
					   batch, payload_bytes, status) != V3_ACK_OK)
			return -1;
	}
	return 0;
}

static int v3_send_step_batches_locked(int fd, const jmx_chain_rule_set_t *rs,
				       uint32_t generation,
				       jmx_v3_kernel_status_t *status)
{
	struct jmx_nl_step_v3 batch[JMX_V3_BATCH_SIZE];
	uint32_t count = 0;
	size_t i;

	for (i = 0; i < rs->rule_count; i++) {
		const jmx_chain_rule_t *rule = &rs->rules[i];
		uint32_t j;

		if (!rule->active)
			continue;
		for (j = 0; j < rule->step_count; j++) {
			const jmx_chain_step_t *step = &rs->steps[rule->first_step + j];
			uint32_t payload_bytes;

			if (v3_step_to_wire(step, &batch[count++]) != 0)
				return -1;
			if (count == JMX_V3_BATCH_SIZE) {
				if (v3_size_mul(count, sizeof(batch[0]), &payload_bytes) != 0)
					return -1;
				if (v3_send_request_locked(fd, JMX_NL_ACT_STEP_V3_BATCH,
							   generation, 0, sizeof(batch[0]), count,
							   batch, payload_bytes, status) != V3_ACK_OK)
					return -1;
				count = 0;
			}
		}
	}
	if (count) {
		uint32_t payload_bytes;

		if (v3_size_mul(count, sizeof(batch[0]), &payload_bytes) != 0)
			return -1;
		if (v3_send_request_locked(fd, JMX_NL_ACT_STEP_V3_BATCH,
					   generation, 0, sizeof(batch[0]), count,
					   batch, payload_bytes, status) != V3_ACK_OK)
			return -1;
	}
	return 0;
}

static int v3_send_port_batches_locked(int fd, const jmx_chain_rule_set_t *rs,
				       uint32_t generation,
				       jmx_v3_kernel_status_t *status)
{
	struct jmx_nl_port_v3 batch[JMX_V3_BATCH_SIZE];
	uint32_t count = 0;
	size_t i;

	for (i = 0; i < rs->rule_count; i++) {
		const jmx_chain_rule_t *rule = &rs->rules[i];
		uint32_t j;

		if (!rule->active)
			continue;
		for (j = 0; j < rule->port_count; j++) {
			const jmx_chain_port_t *port = &rs->ports[rule->first_port + j];
			uint32_t payload_bytes;

			if (v3_port_to_wire(port, &batch[count++]) != 0)
				return -1;
			if (count == JMX_V3_BATCH_SIZE) {
				if (v3_size_mul(count, sizeof(batch[0]), &payload_bytes) != 0)
					return -1;
				if (v3_send_request_locked(fd, JMX_NL_ACT_PORT_V3_BATCH,
							   generation, 0, sizeof(batch[0]), count,
							   batch, payload_bytes, status) != V3_ACK_OK)
					return -1;
				count = 0;
			}
		}
	}
	if (count) {
		uint32_t payload_bytes;

		if (v3_size_mul(count, sizeof(batch[0]), &payload_bytes) != 0)
			return -1;
		if (v3_send_request_locked(fd, JMX_NL_ACT_PORT_V3_BATCH,
					   generation, 0, sizeof(batch[0]), count,
					   batch, payload_bytes, status) != V3_ACK_OK)
			return -1;
	}
	return 0;
}

int jmx_nl_push_chain_rules(int nl_fd, const jmx_chain_rule_set_t *rs,
			    uint32_t generation, uint8_t mode,
			    jmx_v3_kernel_status_t *status)
{
	/* SHA-256("dreamingwrt-v3-empty-catalog"), used only to transact an
	 * explicit empty/off generation when a legacy DB has no active v3 catalog. */
	static const uint8_t empty_digest[JMX_V3_CATALOG_DIGEST_LEN] = {
		0x95, 0xe4, 0x80, 0x9a, 0x4a, 0xb2, 0xd9, 0x1c,
		0xc2, 0x37, 0x57, 0xae, 0xb0, 0x10, 0x9a, 0xac,
		0x65, 0xe7, 0x19, 0x24, 0x96, 0xda, 0xb5, 0xb3,
		0x46, 0x6d, 0x5e, 0x8c, 0x93, 0x22, 0x64, 0xdc,
	};
	struct jmx_nl_begin_v3 begin;
	jmx_v3_kernel_status_t ignored;
	uint32_t rules, steps, ports, caps;
	enum v3_ack_result ack;
	int begin_sent = 0;
	int rc = -1;

	if (!rs || !generation || mode > JMX_V3_MODE_ACTIVE) {
		errno = EINVAL;
		return -1;
	}
	if (!status)
		status = &ignored;
	memset(status, 0, sizeof(*status));
	if (v3_preflight_ruleset(rs, &rules, &steps, &ports, &caps) != 0)
		return -1;
	if (mode == JMX_V3_MODE_OFF || rules == 0) {
		mode = JMX_V3_MODE_OFF;
		rules = steps = ports = caps = 0;
	}
	memset(&begin, 0, sizeof(begin));
	begin.expected_rules = v3_cpu_to_le32(rules);
	begin.expected_steps = v3_cpu_to_le32(steps);
	begin.expected_ports = v3_cpu_to_le32(ports);
	begin.required_capabilities = v3_cpu_to_le32(caps);
	memcpy(begin.catalog_digest,
	       rules ? rs->catalog_digest : empty_digest,
	       sizeof(begin.catalog_digest));

	v3_lock();
	ack = v3_send_request_locked(nl_fd, JMX_NL_ACT_RULESET_BEGIN_V3,
				      generation, mode, sizeof(begin), 1,
				      &begin, sizeof(begin), status);
	begin_sent = 1;
	if (ack != V3_ACK_OK)
		goto abort;
	if (rules && (v3_send_rule_batches_locked(nl_fd, rs, generation, status) != 0 ||
		      v3_send_step_batches_locked(nl_fd, rs, generation, status) != 0 ||
		      v3_send_port_batches_locked(nl_fd, rs, generation, status) != 0))
		goto abort;

	ack = v3_send_request_locked(nl_fd, JMX_NL_ACT_RULESET_COMMIT_V3,
				      generation, 0, 0, 0, NULL, 0, status);
	if (ack == V3_ACK_NACK)
		goto abort;
	if (ack == V3_RESULT_UNKNOWN) {
		/* Only an unknown COMMIT result is reconciled, and only via STATUS. */
		if (v3_reconcile_status_locked(nl_fd, generation, rules, steps,
						       ports, mode,
						       begin.catalog_digest, status) == 0) {
			rc = 0;
			goto out;
		}
		goto abort_preserve;
	}
	if (!v3_status_matches(status, generation, rules, steps, ports, mode,
			       begin.catalog_digest)) {
		/* A malformed/stale COMMIT OK snapshot is checked through STATUS too. */
		if (v3_reconcile_status_locked(nl_fd, generation, rules, steps,
						       ports, mode,
						       begin.catalog_digest, status) == 0)
			rc = 0;
		else {
			if (errno == 0)
				errno = EPROTO;
			goto abort_preserve;
		}
		goto out;
	}
	rc = 0;
	goto out;

abort:
	if (!errno)
		errno = EPROTO;
abort_preserve:
	{
		int saved_errno = errno ? errno : EPROTO;

		/* Explicit NACKs and pre-COMMIT unknowns do not use capability/status
		 * reconciliation.  BEGIN may have succeeded even if its ACK was lost;
		 * abort best-effort and preserve the original failure. */
		if (begin_sent)
			(void)v3_send_request_locked(nl_fd, JMX_NL_ACT_RULESET_ABORT_V3,
						       generation, 0, 0, 0, NULL, 0,
						       &ignored);
		errno = saved_errno;
	}

out:
	v3_unlock_preserve_errno();
	return rc;
}

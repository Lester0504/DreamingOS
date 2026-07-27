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
#include <sys/socket.h>
#include <linux/netlink.h>
#include "jmx_nl_push.h"
#include "jmx_nl_rule.h"
#include "jmx_rule.h"

#define JMX_NETLINK_ID 29

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

static int nl_send(int fd, const void *data, int len)
{
	struct sockaddr_nl sa;
	struct nlmsghdr *nlh;
	struct iovec iov;
	struct msghdr msg;
	int ret;

	nlh = malloc(NLMSG_SPACE(len));
	if (!nlh) return -1;

	memset(nlh, 0, NLMSG_SPACE(len));
	nlh->nlmsg_len = NLMSG_SPACE(len);
	nlh->nlmsg_type = 0;
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_seq = 0;
	memcpy(NLMSG_DATA(nlh), data, len);

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
	free(nlh);

	return (ret < 0) ? -1 : 0;
}

static int nl_commit_version(int fd, uint32_t version)
{
	struct jmx_nl_rule_version_msg vmsg = {
		.action = JMX_NL_ACT_RULE_VERSION,
		.version = version,
	};
	return nl_send(fd, &vmsg, sizeof(vmsg));
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
	uint32_t total = rs->total_rules;
	uint32_t pushed = 0;
	uint32_t i, j, count;
	jmx_match_rule_t *r;
	int ret;

	/* Even an empty rule set must replace the kernel's previous staging set. */
	if (jmx_nl_flush_rules(nl_fd) < 0)
		return -1;

	if (total == 0) {
		ret = nl_commit_version(nl_fd, version);
		if (ret < 0)
			return -1;
		fprintf(stderr, "Pushed 0 rules to kernel (version=%u)\n", version);
		return 0;
	}

	batch = malloc(sizeof(struct jmx_nl_rule) * BATCH_SIZE);
	if (!batch) return -1;

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
				if (!msg) { free(batch); return -1; }
				msg->action = JMX_NL_ACT_RULE_ADD_BATCH;
				msg->count = count;
				msg->version = version;
				memcpy(msg + 1, batch, sizeof(struct jmx_nl_rule) * count);

				ret = nl_send(nl_fd, msg, msg_len);
				free(msg);
				if (ret < 0) {
					fprintf(stderr, "nl_send batch failed: %s\n",
						strerror(errno));
					free(batch);
					return -1;
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
		if (!msg) { free(batch); return -1; }
		msg->action = JMX_NL_ACT_RULE_ADD_BATCH;
		msg->count = count;
		msg->version = version;
		memcpy(msg + 1, batch, sizeof(struct jmx_nl_rule) * count);

		ret = nl_send(nl_fd, msg, msg_len);
		free(msg);
		if (ret < 0) {
			fprintf(stderr, "nl_send final batch failed\n");
			free(batch);
			return -1;
		}
	}

	free(batch);

	/* Signal version commit (atomic swap) */
	ret = nl_commit_version(nl_fd, version);
	if (ret < 0) {
		fprintf(stderr, "nl_send version failed\n");
		return -1;
	}

	fprintf(stderr, "Pushed %u rules to kernel (version=%u)\n", pushed, version);
	return 0;
}

int jmx_nl_flush_rules(int nl_fd)
{
	struct jmx_nl_rule_flush_msg msg = {
		.action = JMX_NL_ACT_RULE_FLUSH,
	};
	return nl_send(nl_fd, &msg, sizeof(msg));
}

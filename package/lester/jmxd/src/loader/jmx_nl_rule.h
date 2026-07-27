/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jmx_nl_rule.h - Netlink binary rule message format
 * Shared between kernel module (jmx) and userspace daemon (jmxd)
 *
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */
#ifndef __JMX_NL_RULE_H__
#define __JMX_NL_RULE_H__

#include <stdint.h>

/* ── Magic number (same as existing protocol) ── */
#define JMX_NL_MAGIC  0xa0b0c0d0

/* ── Message header (same layout as af_msg_hdr) ── */
struct jmx_nl_hdr {
	int32_t  magic;   /* must be JMX_NL_MAGIC */
	int32_t  len;     /* payload length (excluding this header) */
};

/* ── Message action types ── */
enum jmx_nl_action {
	/* Legacy actions (keep for backward compat) */
	JMX_NL_ACT_INIT          = 0,
	JMX_NL_ACT_ADD_FEATURE   = 1,  /* text feature line (legacy) */
	JMX_NL_ACT_CLEAN_FEATURE = 2,  /* flush legacy features */

	/* New binary rule actions */
	JMX_NL_ACT_RULE_FLUSH    = 10, /* flush all v2 rules */
	JMX_NL_ACT_RULE_ADD      = 11, /* add one binary rule */
	JMX_NL_ACT_RULE_ADD_BATCH = 12, /* add multiple rules in one message */
	JMX_NL_ACT_RULE_VERSION  = 13, /* set rule set version (atomic swap) */
};

/* ── Binary rule payload (matches jmx_match_rule_t layout) ── */
/*
 * Wire format for JMX_NL_ACT_RULE_ADD:
 *   struct jmx_nl_rule_msg {
 *       int32_t  action;      // = JMX_NL_ACT_RULE_ADD
 *       struct jmx_nl_rule    rule;
 *   };
 *
 * Wire format for JMX_NL_ACT_RULE_ADD_BATCH:
 *   struct jmx_nl_rule_batch_msg {
 *       int32_t  action;      // = JMX_NL_ACT_RULE_ADD_BATCH
 *       uint32_t count;       // number of rules
 *       uint32_t version;     // rule set version
 *       struct jmx_nl_rule rules[count];
 *   };
 */

/* Match method (must match jmx_match_method_t values) */
#define JMX_NL_MATCH_EXACT    0
#define JMX_NL_MATCH_BM_STR   1
#define JMX_NL_MATCH_REGEX    2
#define JMX_NL_MATCH_NO_FIXED 3

/* Protocol */
#define JMX_NL_PROTO_ANY  0
#define JMX_NL_PROTO_TCP  1
#define JMX_NL_PROTO_UDP  2

/* Direction */
#define JMX_NL_DIR_ANY      0
#define JMX_NL_DIR_ORIGINAL 1
#define JMX_NL_DIR_REPLY    2

#define JMX_NL_MAX_PORTS    8
#define JMX_NL_MAX_LEN_RNG  4
#define JMX_NL_MAX_MATCH    256

/* Packed binary rule (no padding, wire-safe) */
struct jmx_nl_rule {
	uint32_t appid;
	uint32_t rule_id;
	uint32_t priority;
	uint8_t  method;        /* JMX_NL_MATCH_* */
	uint8_t  proto;         /* JMX_NL_PROTO_* */
	uint8_t  dir;           /* JMX_NL_DIR_* */
	uint8_t  port_count;
	uint8_t  len_count;
	uint8_t  _pad[3];       /* alignment padding */
	uint32_t pkt_seq;
	int32_t  offset;        /* -1 = search anywhere */
	uint16_t match_len;
	char     match_str[JMX_NL_MAX_MATCH];
	/* port ranges: port_count entries */
	struct {
		uint16_t min_port;
		uint16_t max_port;
	} ports[JMX_NL_MAX_PORTS];
	/* len ranges: len_count entries */
	struct {
		uint16_t min_len;
		uint16_t max_len;
	} len_range[JMX_NL_MAX_LEN_RNG];
};

/* Message with action prefix */
struct jmx_nl_rule_msg {
	int32_t action;  /* JMX_NL_ACT_RULE_ADD */
	struct jmx_nl_rule rule;
};

/* Batch message */
struct jmx_nl_rule_batch_msg {
	int32_t  action;   /* JMX_NL_ACT_RULE_ADD_BATCH */
	uint32_t count;
	uint32_t version;
	/* struct jmx_nl_rule rules[count] follow */
};

/* Version message (signals batch complete, triggers atomic swap) */
struct jmx_nl_rule_version_msg {
	int32_t  action;   /* JMX_NL_ACT_RULE_VERSION */
	uint32_t version;
};

/* Flush message */
struct jmx_nl_rule_flush_msg {
	int32_t action;    /* JMX_NL_ACT_RULE_FLUSH */
};

#endif /* __JMX_NL_RULE_H__ */

/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jmx_v2_rules.h - Kernel-side v2 rule management
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */
#ifndef __JMX_V2_RULES_H__
#define __JMX_V2_RULES_H__

#include <linux/types.h>

/* ── Match methods ── */
typedef enum {
	JMX_MATCH_EXACT    = 0,
	JMX_MATCH_BM_STR   = 1,
	JMX_MATCH_REGEX    = 2,
	JMX_MATCH_NO_FIXED = 3,
} jmx_match_method_t;

typedef enum {
	JMX_PROTO_ANY = 0,
	JMX_PROTO_TCP = 1,
	JMX_PROTO_UDP = 2,
} jmx_proto_t;

typedef enum {
	JMX_DIR_ANY      = 0,
	JMX_DIR_ORIGINAL = 1,
	JMX_DIR_REPLY    = 2,
} jmx_dir_t;

#define JMX_MAX_APP_NAME_LEN   64
#define JMX_MAX_MATCH_STR_LEN  256
#define JMX_MAX_PORTS          8
#define JMX_MAX_LEN_RANGES     4
#define JMX_HASH_BUCKETS       256

typedef struct {
	uint16_t min_port;
	uint16_t max_port;
} jmx_port_range_t;

typedef struct {
	uint16_t min_len;
	uint16_t max_len;
} jmx_len_range_t;

typedef struct jmx_match_rule {
	uint32_t appid;
	uint32_t rule_id;
	uint32_t priority;
	jmx_match_method_t method;
	jmx_proto_t proto;
	jmx_dir_t dir;
	uint8_t port_count;
	uint8_t len_count;
	uint32_t pkt_seq;
	int32_t  offset;
	uint16_t match_len;
	char match_str[JMX_MAX_MATCH_STR_LEN];
	jmx_port_range_t ports[JMX_MAX_PORTS];
	jmx_len_range_t len_range[JMX_MAX_LEN_RANGES];
	char app_name[JMX_MAX_APP_NAME_LEN];
	struct jmx_match_rule *next;
} jmx_match_rule_t;

typedef struct jmx_nr_rule {
	uint32_t appid;
	uint32_t rule_id;
	struct jmx_nr_rule *next;
} jmx_nr_rule_t;

typedef struct jmx_rule_set {
	jmx_match_rule_t *match_buckets[JMX_HASH_BUCKETS];
	jmx_nr_rule_t    *nr_buckets[JMX_HASH_BUCKETS];
	uint32_t total_rules;
	uint32_t fast_rules;
	uint32_t slow_rules;
	uint32_t nr_rules;
	uint32_t app_name_count;
} jmx_rule_set_t;

/* ── Kernel-side v2 rule input struct ── */
#define JMX_V2_MATCH_EXACT    0
#define JMX_V2_MATCH_BM_STR   1
#define JMX_V2_MATCH_REGEX    2
#define JMX_V2_MATCH_NO_FIXED 3

#define JMX_V2_PROTO_ANY  0
#define JMX_V2_PROTO_TCP  1
#define JMX_V2_PROTO_UDP  2

#define JMX_V2_DIR_ANY      0
#define JMX_V2_DIR_ORIGINAL 1
#define JMX_V2_DIR_REPLY    2

#define JMX_V2_MAX_PORTS    8
#define JMX_V2_MAX_LEN_RNG  4
#define JMX_V2_MAX_MATCH    256
#define JMX_V2_HASH_BUCKETS 256

/*
 * Connmark for NFQUEUE routing.
 * Kernel sets this on conntrack when fast-path DPI fails.
 * nftables rule matches this mark and sends to NFQUEUE.
 * After regex match, jmxd sets mark | app_id, kernel extracts it.
 */
#define JMX_MARK_REGEX_NEEDED  0x1F000001
#define JMX_MARK_REGEX_MASK    0xFFF00000
#define JMX_MARK_APPID_MASK    0x000FFFFF

/* Netlink action: userspace → kernel regex match result via connmark */
#define JMX_NL_ACT_REGEX_RESULT  20

typedef struct jmx_v2_rule {
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
	} len_range[JMX_V2_MAX_LEN_RNG];
} jmx_v2_rule_t;

typedef struct jmx_regex_result {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t  proto;
	uint8_t  _pad[3];
	uint32_t appid;
} jmx_regex_result_t;

/* ── API ── */
int jmx_v2_rules_init(void);
void jmx_v2_rules_exit(void);
int jmx_v2_rule_add(const jmx_v2_rule_t *rule);
void jmx_v2_rules_flush(void);
int jmx_v2_rules_commit(uint32_t version);
uint32_t jmx_v2_rules_count(void);
void jmx_v2_rules_get_status(uint32_t *version, uint32_t *count);
uint32_t jmx_v2_match_payload(const uint8_t *payload, uint16_t len,
			      uint8_t proto, uint8_t dir,
			      uint16_t dport, uint32_t pkt_seq,
			      uint32_t *out_priority);
int jmx_v2_has_regex_rules(void);

#endif

void jmx_v2_update_active_app(uint32_t appid, uint32_t src_ip, uint32_t dst_ip,
                              uint16_t src_port, uint16_t dst_port, uint8_t proto);
void jmx_v2_update_active_app_ex(uint32_t appid, uint32_t src_ip, uint32_t dst_ip,
                                 uint16_t src_port, uint16_t dst_port, uint8_t proto,
                                 uint8_t app_proto, const char *host, uint8_t host_len);

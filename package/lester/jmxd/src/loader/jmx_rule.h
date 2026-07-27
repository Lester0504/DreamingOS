/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jmx_rule.h - Rule data structures for protobuf-based DPI engine
 * Compatible with iKuai pmd app.dat format
 *
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */
#ifndef __JMX_RULE_H__
#define __JMX_RULE_H__

#include <stdint.h>

/* ── Match method enum (mirrors iKuai protobuf) ── */
typedef enum {
	JMX_MATCH_EXACT          = 0,  /* MATCH_EXACT_MATCH */
	JMX_MATCH_BM_STR         = 1,  /* MATCH_BM_MATCH_STR (Boyer-Moore) */
	JMX_MATCH_REGEX          = 2,  /* MATCH_REGULAR_MATCH */
	JMX_MATCH_NO_FIXED       = 3,  /* MATCH_NO_FIXED_DATA_MATCH */
} jmx_match_method_t;

/* ── Protocol enum ── */
typedef enum {
	JMX_PROTO_TCP = 0,
	JMX_PROTO_UDP = 1,
	JMX_PROTO_ANY = 2,
} jmx_proto_t;

/* ── Direction enum ── */
typedef enum {
	JMX_DIR_ANY       = 0,
	JMX_DIR_ORIGINAL  = 1,  /* client → server */
	JMX_DIR_REPLY     = 2,  /* server → client */
} jmx_dir_t;

/* ── Port range ── */
#define JMX_MAX_PORT_RANGES 8
typedef struct {
	uint16_t min_port;
	uint16_t max_port;
} jmx_port_range_t;

/* ── Length range ── */
#define JMX_MAX_LEN_RANGES 4
typedef struct {
	uint16_t min_len;
	uint16_t max_len;
} jmx_len_range_t;

/* ── Single match rule ── */
#define JMX_MAX_MATCH_STR_LEN 256
typedef struct jmx_match_rule {
	/* identification */
	uint32_t            appid;           /* e.g. 2000003 = QQ_PC */
	uint32_t            rule_id;         /* unique rule id */

	/* matching parameters */
	jmx_match_method_t  method;
	jmx_proto_t         proto;
	jmx_dir_t           dir;
	uint32_t            priority;        /* lower = higher priority */

	/* packet sequence filter (0 = any) */
	uint32_t            pkt_seq;         /* which packet in the flow */
	uint32_t            min_pkt_seq;     /* minimum pkt_seq */

	/* port filters */
	uint8_t             port_count;
	jmx_port_range_t    ports[JMX_MAX_PORT_RANGES];

	/* payload length range */
	uint8_t             len_count;
	jmx_len_range_t     len_range[JMX_MAX_LEN_RANGES];

	/* match data */
	uint16_t            match_len;
	char                match_str[JMX_MAX_MATCH_STR_LEN]; /* regex or BM string */

	/* offset (for BM/exact match, -1 = search anywhere) */
	int32_t             offset;

	/* linked list for hash bucket */
	struct jmx_match_rule *next;
} jmx_match_rule_t;

/* ── App info (name + class) ── */
#define JMX_MAX_APP_NAME_LEN 64
typedef struct {
	uint32_t appid;
	char     name[JMX_MAX_APP_NAME_LEN];
} jmx_app_info_t;

/* ── NR (Number Recognition) rule ── */
#define JMX_MAX_NR_PREFIX_LEN 128
#define JMX_MAX_NR_ID_NAME_LEN 64
typedef struct jmx_nr_rule {
	uint32_t appid;
	uint8_t  is_uniq_id;
	char     id_name[JMX_MAX_NR_ID_NAME_LEN];
	uint16_t prefix_len;
	char     prefix[JMX_MAX_NR_PREFIX_LEN]; /* base64-decoded prefix */
	struct jmx_nr_rule *next;
} jmx_nr_rule_t;

/* ── Rule set (the whole loaded database) ── */
#define JMX_HASH_BUCKETS 256
#define JMX_MAX_RULES 8192
#define JMX_MAX_NR_RULES 2048

typedef struct {
	/* match rules indexed by appid hash */
	jmx_match_rule_t *match_buckets[JMX_HASH_BUCKETS];
	uint32_t          match_count;

	/* NR rules indexed by appid hash */
	jmx_nr_rule_t    *nr_buckets[JMX_HASH_BUCKETS];
	uint32_t          nr_count;

	/* appid → name lookup (linear scan, small enough) */
	jmx_app_info_t    app_info[2048];
	uint32_t          app_info_count;

	/* stats */
	uint32_t          fast_rules;  /* BM/EXACT/NO_FIXED → kernel */
	uint32_t          slow_rules;  /* REGEX → NFQUEUE */
	uint32_t          total_rules;
} jmx_rule_set_t;

/* ── API ── */

/* Initialize an empty rule set */
void jmx_rule_set_init(jmx_rule_set_t *rs);

/* Free all rules in a set */
void jmx_rule_set_free(jmx_rule_set_t *rs);

/* Add a match rule to the set */
int jmx_rule_set_add_match(jmx_rule_set_t *rs, const jmx_match_rule_t *rule);

/* Add an NR rule to the set */
int jmx_rule_set_add_nr(jmx_rule_set_t *rs, const jmx_nr_rule_t *rule);

/* Add app info */
int jmx_rule_set_add_app_info(jmx_rule_set_t *rs, uint32_t appid, const char *name);

/* Lookup app name by appid */
const char *jmx_rule_set_app_name(const jmx_rule_set_t *rs, uint32_t appid);

/* Classify: returns 1 if rule should go to kernel (fast path), 0 for NFQUEUE */
int jmx_rule_is_fast_path(const jmx_match_rule_t *rule);

#endif /* __JMX_RULE_H__ */

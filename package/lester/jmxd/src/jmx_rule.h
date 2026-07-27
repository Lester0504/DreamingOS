/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jmx_rule.h - Rule data structures for protobuf-based DPI engine
 * DreamingWrt DPI signature rule format
 *
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */
#ifndef __JMX_RULE_H__
#define __JMX_RULE_H__

#include <stdint.h>
#include <stddef.h>
#include "jmx_nl_rule_v3.h"

/* ── Match method enum ── */
typedef enum {
	JMX_MATCH_EXACT          = 0,  /* MATCH_EXACT_MATCH */
	JMX_MATCH_BM_STR         = 1,  /* MATCH_BM_MATCH_STR (Boyer-Moore) */
	JMX_MATCH_REGEX          = 2,  /* MATCH_REGULAR_MATCH */
	JMX_MATCH_NO_FIXED       = 3,  /* MATCH_NO_FIXED_DATA_MATCH */
} jmx_match_method_t;

/* ── Protocol enum ── */
typedef enum {
	JMX_PROTO_ANY = 0,
	JMX_PROTO_TCP = 1,
	JMX_PROTO_UDP = 2,
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
#define JMX_MAX_APP_INFOS 8192
typedef struct {
	uint32_t appid;
	char     name[JMX_MAX_APP_NAME_LEN];
} jmx_app_info_t;

/* ── NR (Number Recognition) rule ── */
#define JMX_MAX_NR_PREFIX_LEN  128
#define JMX_MAX_NR_ID_NAME_LEN 64
#define JMX_MAX_NR_CHAR_RANGES 8
#define JMX_MAX_NR_EXTRACTS    8

/* Character range for valid account ID chars */
typedef struct {
	uint8_t min_char;
	uint8_t max_char;
} jmx_nr_char_range_t;

/* Single account extraction pattern (legacy-compatible, currently unused by DreamingWrt DB) */
typedef struct {
	uint8_t  proto;       /* 0=any, from sub-field f1 */
	uint8_t  type;        /* from sub-field f4 (0=body, 7=cookie) */
	uint8_t  is_header;   /* from sub-field f8 (1=match in header) */
	uint8_t  is_reply;    /* from sub-field f13 (1=reply direction) */
	uint16_t prefix_len;
	char     prefix[JMX_MAX_NR_PREFIX_LEN]; /* e.g. "uin_cookie=", "username=" */
} jmx_nr_extract_t;

/* Complete NR rule for one appid */
typedef struct jmx_nr_rule {
	uint32_t appid;
	uint8_t  enabled;                    /* field 9 */
	uint8_t  extract_count;              /* number of extraction patterns */
	uint8_t  char_range_count;           /* number of char ranges */
	uint16_t max_account_len;            /* field 5: max extracted ID length */
	jmx_nr_extract_t  extracts[JMX_MAX_NR_EXTRACTS];
	jmx_nr_char_range_t char_ranges[JMX_MAX_NR_CHAR_RANGES];
	char     app_name[JMX_MAX_NR_ID_NAME_LEN];
	struct jmx_nr_rule *next;
} jmx_nr_rule_t;

/* ── Rule set (the whole loaded database) ── */
#define JMX_HASH_BUCKETS 256
#define JMX_MAX_RULES 16384
#define JMX_MAX_NR_RULES 2048

typedef struct {
	/* match rules indexed by appid hash */
	jmx_match_rule_t *match_buckets[JMX_HASH_BUCKETS];
	uint32_t          match_count;

	/* NR rules indexed by appid hash */
	jmx_nr_rule_t    *nr_buckets[JMX_HASH_BUCKETS];
	uint32_t          nr_count;

	/* appid → name lookup (linear scan, small enough) */
	jmx_app_info_t    app_info[JMX_MAX_APP_INFOS];
	uint32_t          app_info_count;

	/* stats */
	uint32_t          fast_rules;  /* BM/EXACT/NO_FIXED → kernel */
	uint32_t          slow_rules;  /* REGEX → NFQUEUE */
	uint32_t          total_rules;
} jmx_rule_set_t;

/* TDTS chains deliberately use a separate model from the legacy single-match
 * rules.  In particular, v3 exact means an exact candidate at a location, not
 * equality with the complete packet payload. */
typedef struct {
	uint32_t signature_rule_id;
	uint32_t appid;
	uint32_t priority;
	uint32_t required_caps;
	uint32_t first_step;
	uint32_t first_port;
	uint16_t step_count;
	uint16_t port_count;
	uint8_t proto;
	uint8_t dir;
	uint8_t flags;
	uint8_t active;
} jmx_chain_rule_t;

typedef struct {
	uint32_t signature_rule_id;
	uint16_t step_index;
	uint8_t matcher_type;
	uint8_t condition;
	uint8_t case_mode;
	uint8_t input_view;
	uint8_t position_flags;
	uint8_t numeric_encoding;
	uint8_t literal_option;
	int32_t depth;
	int32_t offset;
	int32_t distance;
	int32_t within;
	uint16_t payload_len;
	uint16_t reference_source;
	uint8_t comparison;
	uint8_t adjust_mode;
	uint8_t width;
	uint8_t jump_multiplier;
	uint32_t inline_operand;
	uint32_t adjustment_operand;
	int32_t jump_base;
	uint8_t payload[JMX_V3_PAYLOAD_MAX];
} jmx_chain_step_t;

typedef struct {
	uint32_t signature_rule_id;
	uint16_t min_port;
	uint16_t max_port;
	uint8_t endpoint;
} jmx_chain_port_t;

typedef struct {
	uint32_t legacy_db_rules;
	uint32_t legacy_kernel_rules;
	uint32_t legacy_regex_inactive;
	uint32_t chain_db_rules;
	uint32_t chain_ready_rules;
	uint32_t chain_inactive_by_capability;
	uint32_t chain_unresolved_rules;
	uint32_t chain_steps;
	uint32_t unique_raw_patterns;
	uint32_t unique_uri_patterns;
	uint32_t zero_step_rules;
	uint32_t rejected_records;
} jmx_chain_load_stats_t;

typedef struct {
	jmx_chain_rule_t *rules;
	jmx_chain_step_t *steps;
	jmx_chain_port_t *ports;
	size_t rule_count;
	size_t step_count;
	size_t port_count;
	size_t rule_capacity;
	size_t step_capacity;
	size_t port_capacity;
	uint32_t engine_capabilities;
	uint32_t required_capabilities;
	uint8_t catalog_digest[JMX_V3_CATALOG_DIGEST_LEN];
	uint8_t schema_v2_present;
	jmx_chain_load_stats_t stats;
} jmx_chain_rule_set_t;

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

void jmx_chain_rule_set_init(jmx_chain_rule_set_t *rs, uint32_t engine_caps);
void jmx_chain_rule_set_free(jmx_chain_rule_set_t *rs);
int jmx_chain_rule_set_add_rule(jmx_chain_rule_set_t *rs,
				const jmx_chain_rule_t *rule);
int jmx_chain_rule_set_add_step(jmx_chain_rule_set_t *rs,
				const jmx_chain_step_t *step);
int jmx_chain_rule_set_add_port(jmx_chain_rule_set_t *rs,
				const jmx_chain_port_t *port);
jmx_chain_rule_t *jmx_chain_rule_find(jmx_chain_rule_set_t *rs,
				      uint32_t signature_rule_id);
const jmx_chain_rule_t *jmx_chain_rule_find_const(const jmx_chain_rule_set_t *rs,
						 uint32_t signature_rule_id);

#endif /* __JMX_RULE_H__ */

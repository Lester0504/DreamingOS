/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Stable wire ABI for the DreamingWrt TDTS chain engine.
 *
 * Keep both package copies byte-identical.  The host ABI test compares them
 * because OpenWrt builds jmx and jmxd from
 * separate source directories.
 */
#ifndef __JMX_NL_RULE_V3_H__
#define __JMX_NL_RULE_V3_H__

#ifdef __KERNEL__
#include <linux/types.h>
typedef __u8 jmx_v3_u8;
typedef __le16 jmx_v3_le16;
typedef __le32 jmx_v3_le32;
#else
#include <stdint.h>
typedef uint8_t jmx_v3_u8;
typedef uint16_t jmx_v3_le16;
typedef uint32_t jmx_v3_le32;
#endif

#define JMX_V3_PACKED __attribute__((packed))

#define JMX_RULE_ABI_V3             3U
#define JMX_V3_PAYLOAD_MAX          64U
#define JMX_V3_CATALOG_DIGEST_LEN   32U
#define JMX_V3_MAX_STEPS_PER_RULE   64U
#define JMX_V3_MAX_PORTS_PER_RULE   64U

enum jmx_nl_action_v3 {
	JMX_NL_ACT_RULESET_BEGIN_V3  = 50,
	JMX_NL_ACT_RULE_V3_BATCH     = 51,
	JMX_NL_ACT_STEP_V3_BATCH     = 52,
	JMX_NL_ACT_PORT_V3_BATCH     = 53,
	JMX_NL_ACT_RULESET_COMMIT_V3 = 54,
	JMX_NL_ACT_RULESET_ABORT_V3  = 55,
	JMX_NL_ACT_RULESET_STATUS_V3 = 56,
	JMX_NL_ACT_CAPABILITY_V3     = 57,
};

enum jmx_v3_capability {
	JMX_V3_CAP_RAW_LITERAL_CHAIN        = 0x00000001U,
	JMX_V3_CAP_NOCASE                  = 0x00000002U,
	JMX_V3_CAP_POSITION_ABSOLUTE       = 0x00000004U,
	JMX_V3_CAP_POSITION_RELATIVE       = 0x00000008U,
	JMX_V3_CAP_NORMALIZED_URI          = 0x00000010U,
	JMX_V3_CAP_NEGATIVE                = 0x00000020U,
	JMX_V3_CAP_BYTE_TEST               = 0x00000040U,
	JMX_V3_CAP_BYTE_JUMP               = 0x00000080U,
	JMX_V3_CAP_TCP_STREAM              = 0x00000100U,
	JMX_V3_CAP_CROSS_DIRECTION_STATE   = 0x00000200U,
	JMX_V3_CAP_PROTOCOL_MAPPING        = 0x00000400U,
};

#define JMX_V3_CAP_KNOWN_MASK 0x000007ffU
#define JMX_V3_CAP_PHASE1_MASK \
	(JMX_V3_CAP_RAW_LITERAL_CHAIN | JMX_V3_CAP_NOCASE | \
	 JMX_V3_CAP_POSITION_ABSOLUTE | JMX_V3_CAP_POSITION_RELATIVE | \
	 JMX_V3_CAP_PROTOCOL_MAPPING)

enum jmx_v3_mode {
	JMX_V3_MODE_OFF = 0,
	JMX_V3_MODE_SHADOW = 1,
	JMX_V3_MODE_ACTIVE = 2,
};

#define JMX_V3_TX_MODE_MASK       0x00000003U
#define JMX_V3_TX_KNOWN_FLAGS     JMX_V3_TX_MODE_MASK

enum jmx_v3_proto {
	JMX_V3_PROTO_ANY = 0,
	JMX_V3_PROTO_TCP = 1,
	JMX_V3_PROTO_UDP = 2,
};

enum jmx_v3_direction {
	JMX_V3_DIR_ANY = 0,
	JMX_V3_DIR_ORIGINAL = 1,
	JMX_V3_DIR_REPLY = 2,
	JMX_V3_DIR_BIDIRECTIONAL = 3,
};

enum jmx_v3_matcher_type {
	JMX_V3_MATCH_LITERAL_NOCASE = 0x00,
	JMX_V3_MATCH_LITERAL_EXACT_1 = 0x01,
	JMX_V3_MATCH_LITERAL_EXACT_2 = 0x02,
	JMX_V3_MATCH_NORMALIZED_URI = 0x04,
	JMX_V3_MATCH_BYTE_TEST = 0x20,
	JMX_V3_MATCH_BYTE_JUMP = 0x40,
};

enum jmx_v3_condition {
	JMX_V3_CONDITION_POSITIVE = 1,
	JMX_V3_CONDITION_NEGATIVE = 2,
	JMX_V3_CONDITION_NUMERIC = 3,
	JMX_V3_CONDITION_JUMP = 4,
};

enum jmx_v3_case_mode {
	JMX_V3_CASE_NOT_APPLICABLE = 0,
	JMX_V3_CASE_NOCASE = 1,
	JMX_V3_CASE_EXACT = 2,
};

enum jmx_v3_input_view {
	JMX_V3_VIEW_RAW = 0,
	JMX_V3_VIEW_NORMALIZED_URI = 1,
};

enum jmx_v3_position_flag {
	JMX_V3_POS_DEPTH = 0x01,
	JMX_V3_POS_OFFSET = 0x02,
	JMX_V3_POS_DISTANCE = 0x04,
	JMX_V3_POS_WITHIN = 0x08,
};

#define JMX_V3_POS_KNOWN_MASK 0x0fU

enum jmx_v3_port_endpoint {
	JMX_V3_PORT_SOURCE = 1,
	JMX_V3_PORT_DESTINATION = 2,
	JMX_V3_PORT_EITHER = 3,
};

enum jmx_v3_status_code {
	JMX_V3_STATUS_OK = 0,
	JMX_V3_STATUS_ERROR = 1,
	JMX_V3_STATUS_UNSUPPORTED = 2,
};

enum jmx_v3_staging_state {
	JMX_V3_STAGING_NONE = 0,
	JMX_V3_STAGING_LOADING = 1,
	JMX_V3_STAGING_FAILED = 2,
};

enum jmx_v3_status_reason {
	JMX_V3_REASON_NONE = 0,
	JMX_V3_REASON_BAD_ABI = 1,
	JMX_V3_REASON_BAD_HEADER = 2,
	JMX_V3_REASON_BAD_SIZE = 3,
	JMX_V3_REASON_BAD_CRC = 4,
	JMX_V3_REASON_BAD_GENERATION = 5,
	JMX_V3_REASON_BUSY = 6,
	JMX_V3_REASON_NO_MEMORY = 7,
	JMX_V3_REASON_COUNT_MISMATCH = 8,
	JMX_V3_REASON_BAD_RECORD = 9,
	JMX_V3_REASON_CAPABILITY = 10,
	JMX_V3_REASON_BAD_REFERENCE = 11,
	JMX_V3_REASON_STEP_SEQUENCE = 12,
	JMX_V3_REASON_BUILD_FAILED = 13,
	JMX_V3_REASON_TIMEOUT = 14,
	JMX_V3_REASON_NOT_OWNER = 15,
	JMX_V3_REASON_UNSUPPORTED_ACTION = 16,
};

/* crc32 is IEEE CRC-32 over payload_bytes only, with initial/final xor. */
struct jmx_nl_v3_hdr {
	jmx_v3_le32 action;
	jmx_v3_le16 abi_version;
	jmx_v3_le16 header_size;
	jmx_v3_le32 record_size;
	jmx_v3_le32 generation;
	jmx_v3_le32 count;
	jmx_v3_le32 payload_bytes;
	jmx_v3_le32 flags;
	jmx_v3_le32 crc32;
} JMX_V3_PACKED;

struct jmx_nl_begin_v3 {
	jmx_v3_le32 expected_rules;
	jmx_v3_le32 expected_steps;
	jmx_v3_le32 expected_ports;
	jmx_v3_le32 required_capabilities;
	jmx_v3_u8 catalog_digest[JMX_V3_CATALOG_DIGEST_LEN];
} JMX_V3_PACKED;

struct jmx_nl_rule_v3 {
	jmx_v3_le32 signature_rule_id;
	jmx_v3_le32 appid;
	jmx_v3_le32 priority;
	jmx_v3_le32 required_caps;
	jmx_v3_le16 step_count;
	jmx_v3_u8 proto;
	jmx_v3_u8 dir;
	jmx_v3_u8 flags;
	jmx_v3_u8 reserved[3];
} JMX_V3_PACKED;

struct jmx_nl_step_v3 {
	jmx_v3_le32 signature_rule_id;
	jmx_v3_le16 step_index;
	jmx_v3_u8 matcher_type;
	jmx_v3_u8 condition;
	jmx_v3_u8 case_mode;
	jmx_v3_u8 input_view;
	jmx_v3_u8 position_flags;
	jmx_v3_u8 numeric_encoding;
	jmx_v3_u8 literal_option;
	jmx_v3_u8 reserved[3];
	jmx_v3_le32 depth;
	jmx_v3_le32 offset;
	jmx_v3_le32 distance;
	jmx_v3_le32 within;
	jmx_v3_le16 payload_len;
	jmx_v3_le16 reference_source;
	jmx_v3_u8 comparison;
	jmx_v3_u8 adjust_mode;
	jmx_v3_u8 width;
	jmx_v3_u8 jump_multiplier;
	jmx_v3_le32 inline_operand;
	jmx_v3_le32 adjustment_operand;
	jmx_v3_le32 jump_base;
	jmx_v3_u8 payload[JMX_V3_PAYLOAD_MAX];
} JMX_V3_PACKED;

struct jmx_nl_port_v3 {
	jmx_v3_le32 signature_rule_id;
	jmx_v3_u8 endpoint;
	jmx_v3_u8 reserved[3];
	jmx_v3_le16 min_port;
	jmx_v3_le16 max_port;
} JMX_V3_PACKED;

struct jmx_nl_status_v3 {
	jmx_v3_le32 request_action;
	jmx_v3_le32 status;
	jmx_v3_le32 reason;
	jmx_v3_le32 detail;
	jmx_v3_le32 engine_capabilities;
	jmx_v3_le32 active_generation;
	jmx_v3_le32 active_rules;
	jmx_v3_le32 active_steps;
	jmx_v3_le32 active_ports;
	jmx_v3_le32 active_mode;
	jmx_v3_u8 active_catalog_digest[JMX_V3_CATALOG_DIGEST_LEN];
	jmx_v3_le32 staging_generation;
	jmx_v3_le32 staging_state;
} JMX_V3_PACKED;

#endif /* __JMX_NL_RULE_V3_H__ */

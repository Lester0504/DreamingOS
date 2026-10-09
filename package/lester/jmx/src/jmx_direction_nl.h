/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __JMX_DIRECTION_NL_KERNEL_H__
#define __JMX_DIRECTION_NL_KERNEL_H__

#include <linux/types.h>

#define JMX_NL_ACT_DIRECTION_SNAPSHOT 44U
#define JMX_DIRECTION_NL_ABI_VERSION  1U

#define JMX_DIRECTION_NL_MAX_LAN_PREFIXES 128U
#define JMX_DIRECTION_NL_MAX_LOCAL_ADDRS  128U
#define JMX_DIRECTION_NL_MAX_WANS         255U
#define JMX_DIRECTION_NL_ADDR_BYTES       16U

#define JMX_DIRECTION_NL_FAMILY_IPV4 4U
#define JMX_DIRECTION_NL_FAMILY_IPV6 6U
#define JMX_DIRECTION_NL_FAMILY_MASK_IPV4 (1U << 0)
#define JMX_DIRECTION_NL_FAMILY_MASK_IPV6 (1U << 1)

/* All integer fields are big-endian on the wire. Addresses are raw bytes. */
struct jmx_direction_nl_header {
	__be32 action;
	__be16 abi_version;
	__be16 header_size;
	__be32 message_size;
	__be64 generation;
	u8 ready;
	u8 gateway_mode;
	__be16 lan_prefix_count;
	__be16 local_address_count;
	__be16 wan_count;
	__be16 reserved;
} __packed;

struct jmx_direction_nl_prefix {
	__be32 ifindex;
	u8 family;
	u8 prefix_len;
	__be16 reserved;
	u8 address[JMX_DIRECTION_NL_ADDR_BYTES];
} __packed;

struct jmx_direction_nl_local_address {
	u8 family;
	u8 reserved[3];
	u8 address[JMX_DIRECTION_NL_ADDR_BYTES];
} __packed;

struct jmx_direction_nl_wan {
	u8 wan_id;
	u8 family_mask;
	u8 registered;
	u8 reserved;
	__be32 ifindex;
	__be32 route_identity;
	__be32 table_id;
	__be32 reserved2;
	__be32 reserved3;
} __packed;

static_assert(sizeof(struct jmx_direction_nl_header) == 30);
static_assert(sizeof(struct jmx_direction_nl_prefix) == 24);
static_assert(sizeof(struct jmx_direction_nl_local_address) == 20);
static_assert(sizeof(struct jmx_direction_nl_wan) == 24);

#endif

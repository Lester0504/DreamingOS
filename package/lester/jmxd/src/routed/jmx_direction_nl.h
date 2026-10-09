/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __JMX_DIRECTION_NL_H__
#define __JMX_DIRECTION_NL_H__

#include <stdint.h>

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
    uint32_t action;
    uint16_t abi_version;
    uint16_t header_size;
    uint32_t message_size;
    uint64_t generation;
    uint8_t ready;
    uint8_t gateway_mode;
    uint16_t lan_prefix_count;
    uint16_t local_address_count;
    uint16_t wan_count;
    uint16_t reserved;
} __attribute__((packed));

struct jmx_direction_nl_prefix {
    uint32_t ifindex;
    uint8_t family;
    uint8_t prefix_len;
    uint16_t reserved;
    uint8_t address[JMX_DIRECTION_NL_ADDR_BYTES];
} __attribute__((packed));

struct jmx_direction_nl_local_address {
    uint8_t family;
    uint8_t reserved[3];
    uint8_t address[JMX_DIRECTION_NL_ADDR_BYTES];
} __attribute__((packed));

struct jmx_direction_nl_wan {
    uint8_t wan_id;
    uint8_t family_mask;
    uint8_t registered;
    uint8_t reserved;
    uint32_t ifindex;
    uint32_t route_identity;
    uint32_t table_id;
    uint32_t reserved2;
    uint32_t reserved3;
} __attribute__((packed));

_Static_assert(sizeof(struct jmx_direction_nl_header) == 30,
               "direction netlink header layout changed");
_Static_assert(sizeof(struct jmx_direction_nl_prefix) == 24,
               "direction netlink prefix layout changed");
_Static_assert(sizeof(struct jmx_direction_nl_local_address) == 20,
               "direction netlink local address layout changed");
_Static_assert(sizeof(struct jmx_direction_nl_wan) == 24,
               "direction netlink WAN layout changed");

#endif

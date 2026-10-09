/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __JMX_DIRECTION_H__
#define __JMX_DIRECTION_H__

#include <linux/types.h>

struct net_device;
struct sk_buff;

struct jmx_direction_prefix_k {
	u32 ifindex;
	u8 family;
	u8 prefix_len;
	u8 address[16];
};

struct jmx_direction_local_address_k {
	u8 family;
	u8 address[16];
};

struct jmx_direction_wan_k {
	u8 wan_id;
	u8 family_mask;
	u8 registered;
	u32 ifindex;
	u32 route_identity;
	u32 table_id;
};

struct jmx_direction_packet_k {
	u8 family;
	u8 is_forward;
	u32 ingress_ifindex;
	u32 egress_ifindex;
	u32 egress_route_identity;
	u8 source[16];
	u8 destination[16];
};

enum jmx_direction_class {
	JMX_DIRECTION_UNKNOWN = 0,
	JMX_DIRECTION_LAN_WAN,
	JMX_DIRECTION_LAN_LAN,
	JMX_DIRECTION_ROUTER_LOCAL,
	JMX_DIRECTION_WAN_LOCAL,
	JMX_DIRECTION_BYPASS,
	JMX_DIRECTION_NON_GATEWAY,
};

struct jmx_direction_decision {
	enum jmx_direction_class classification;
	u8 managed_lan_ingress;
	u8 registered_wan_egress;
	u8 ready;
	u8 gateway_mode;
	u64 generation;
};

struct jmx_direction_snapshot_k {
	u32 version;
	u64 generation;
	u8 ready;
	u8 gateway_mode;
	u16 lan_prefix_count;
	u16 local_address_count;
	u16 wan_count;
	struct jmx_direction_prefix_k lan_prefixes[128];
	struct jmx_direction_local_address_k local_addresses[128];
	struct jmx_direction_wan_k wans[255];
};

int jmx_direction_init(void);
void jmx_direction_exit(void);

int jmx_direction_publish_snapshot(const struct jmx_direction_snapshot_k *snapshot);
int jmx_direction_publish_unready(u64 generation, u8 gateway_mode);
u64 jmx_direction_current_generation(void);

int jmx_direction_classify_skb(const struct sk_buff *skb,
				       const struct net_device *in,
				       const struct net_device *out,
				       struct jmx_direction_decision *decision);
int jmx_direction_is_gate_candidate(const struct jmx_direction_decision *decision);
void jmx_direction_observe_skb(const struct sk_buff *skb,
				       const struct net_device *in,
				       const struct net_device *out);

/* Returns 1 for the direction action, including malformed messages. */
int jmx_direction_nl_handle(const void *data, int len);

#endif

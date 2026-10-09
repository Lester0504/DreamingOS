// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * jmx_direction.c - immutable LAN/WAN direction snapshot consumer
 *
 * The control plane publishes a complete versioned snapshot over the existing
 * jmx netlink channel.  The forwarding hook only reads one of two slots under
 * an RCU read-side section; writers never modify the active slot and wait for
 * a grace period before reusing the previous active slot.
 */
#include <linux/byteorder/generic.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

#include "jmx.h"
#include "jmx_direction.h"
#include "jmx_direction_nl.h"
#include "jmx_stats.h"

struct jmx_direction_runtime {
	struct jmx_direction_snapshot_k slots[2];
	unsigned int active_slot;
	struct mutex update_lock;
	struct workqueue_struct *wq;
	bool initialized;
};

static struct jmx_direction_runtime jmx_direction_runtime;

struct jmx_direction_update {
	struct work_struct work;
	struct jmx_direction_snapshot_k snapshot;
};

static size_t direction_family_bytes(u8 family)
{
	return family == JMX_DIRECTION_NL_FAMILY_IPV4 ? 4U :
	       (family == JMX_DIRECTION_NL_FAMILY_IPV6 ? 16U : 0U);
}

static u8 direction_family_mask(u8 family)
{
	return family == JMX_DIRECTION_NL_FAMILY_IPV4 ?
		JMX_DIRECTION_NL_FAMILY_MASK_IPV4 :
	       (family == JMX_DIRECTION_NL_FAMILY_IPV6 ?
		JMX_DIRECTION_NL_FAMILY_MASK_IPV6 : 0U);
}

static bool direction_prefix_matches(u8 family, const u8 *network,
					     u8 prefix_len, const u8 *address)
{
	size_t bytes = direction_family_bytes(family);
	size_t full;
	u8 remainder;

	if (!bytes || !network || !address || prefix_len > bytes * 8U)
		return false;
	full = prefix_len / 8U;
	remainder = prefix_len % 8U;
	if (full && memcmp(network, address, full) != 0)
		return false;
	if (remainder) {
		u8 mask = (u8)(0xffU << (8U - remainder));

		if ((network[full] & mask) != (address[full] & mask))
			return false;
	}
	return true;
}

static bool direction_address_equal(u8 family, const u8 *left,
					    const u8 *right)
{
	size_t bytes = direction_family_bytes(family);

	return bytes && left && right && memcmp(left, right, bytes) == 0;
}

static bool direction_address_is_local(const struct jmx_direction_snapshot_k *snapshot,
					       u8 family, const u8 *address)
{
	u16 i;

	for (i = 0; i < snapshot->local_address_count; i++) {
		const struct jmx_direction_local_address_k *entry =
			&snapshot->local_addresses[i];

		if (entry->family == family &&
		    direction_address_equal(family, entry->address, address))
			return true;
	}
	return false;
}

static bool direction_lan_ingress(const struct jmx_direction_snapshot_k *snapshot,
			const struct jmx_direction_packet_k *packet)
{
	u16 i;

	for (i = 0; i < snapshot->lan_prefix_count; i++) {
		const struct jmx_direction_prefix_k *entry =
			&snapshot->lan_prefixes[i];

		if (entry->ifindex == packet->ingress_ifindex &&
		    entry->family == packet->family &&
		    direction_prefix_matches(packet->family, entry->address,
					      entry->prefix_len, packet->source))
			return true;
	}
	return false;
}

static bool direction_lan_egress(const struct jmx_direction_snapshot_k *snapshot,
					 const struct jmx_direction_packet_k *packet)
{
	u16 i;

	for (i = 0; i < snapshot->lan_prefix_count; i++) {
		const struct jmx_direction_prefix_k *entry =
			&snapshot->lan_prefixes[i];

		if (entry->ifindex == packet->egress_ifindex &&
		    entry->family == packet->family &&
		    direction_prefix_matches(packet->family, entry->address,
					      entry->prefix_len, packet->destination))
			return true;
	}
	return false;
}

static bool direction_wan_egress(const struct jmx_direction_snapshot_k *snapshot,
					 const struct jmx_direction_packet_k *packet)
{
	u8 family_mask = direction_family_mask(packet->family);
	u16 i;

	if (!family_mask)
		return false;
	for (i = 0; i < snapshot->wan_count; i++) {
		const struct jmx_direction_wan_k *entry = &snapshot->wans[i];

		if (!entry->registered || !(entry->family_mask & family_mask))
			continue;
		if (entry->ifindex && entry->ifindex == packet->egress_ifindex)
			return true;
		if (packet->egress_route_identity && entry->route_identity &&
		    entry->route_identity == packet->egress_route_identity)
			return true;
	}
	return false;
}

static bool direction_wan_ingress(const struct jmx_direction_snapshot_k *snapshot,
					  const struct jmx_direction_packet_k *packet)
{
	u8 family_mask = direction_family_mask(packet->family);
	u16 i;

	if (!family_mask)
		return false;
	for (i = 0; i < snapshot->wan_count; i++) {
		const struct jmx_direction_wan_k *entry = &snapshot->wans[i];

		if (entry->registered && (entry->family_mask & family_mask) &&
		    entry->ifindex == packet->ingress_ifindex)
			return true;
	}
	return false;
}

static int direction_packet_from_skb(const struct sk_buff *skb,
					     const struct net_device *in,
					     const struct net_device *out,
					     struct jmx_direction_packet_k *packet)
{
	struct iphdr iph;
	struct ipv6hdr ip6h;
	const void *header;
	unsigned int offset;

	if (!skb || !packet)
		return -EINVAL;
	memset(packet, 0, sizeof(*packet));
	packet->is_forward = 1;
	packet->ingress_ifindex = in ? in->ifindex : 0;
	packet->egress_ifindex = out ? out->ifindex : 0;
	packet->egress_route_identity = skb->mark;
	offset = skb_network_offset(skb);

	if (skb->protocol == htons(ETH_P_IP)) {
		header = skb_header_pointer(skb, offset, sizeof(iph), &iph);
		if (!header || iph.ihl < 5)
			return -EINVAL;
		packet->family = JMX_DIRECTION_NL_FAMILY_IPV4;
		memcpy(packet->source, &iph.saddr, sizeof(iph.saddr));
		memcpy(packet->destination, &iph.daddr, sizeof(iph.daddr));
		return 0;
	}
	if (skb->protocol == htons(ETH_P_IPV6)) {
		header = skb_header_pointer(skb, offset, sizeof(ip6h), &ip6h);
		if (!header)
			return -EINVAL;
		packet->family = JMX_DIRECTION_NL_FAMILY_IPV6;
		memcpy(packet->source, &ip6h.saddr, sizeof(ip6h.saddr));
		memcpy(packet->destination, &ip6h.daddr, sizeof(ip6h.daddr));
		return 0;
	}
	return -EPROTONOSUPPORT;
}

static bool direction_snapshot_valid(const struct jmx_direction_snapshot_k *snapshot)
{
	u16 i, j;

	if (!snapshot || snapshot->version != JMX_DIRECTION_NL_ABI_VERSION ||
	    !snapshot->generation || snapshot->ready > 1 ||
	    snapshot->gateway_mode > 1 ||
	    snapshot->lan_prefix_count > JMX_DIRECTION_NL_MAX_LAN_PREFIXES ||
	    snapshot->local_address_count > JMX_DIRECTION_NL_MAX_LOCAL_ADDRS ||
	    snapshot->wan_count > JMX_DIRECTION_NL_MAX_WANS)
		return false;
	if (!snapshot->ready)
		return snapshot->lan_prefix_count == 0 &&
		       snapshot->local_address_count == 0 &&
		       snapshot->wan_count == 0;
	if (snapshot->gateway_mode && (!snapshot->lan_prefix_count ||
					       !snapshot->wan_count))
		return false;
	for (i = 0; i < snapshot->lan_prefix_count; i++) {
		const struct jmx_direction_prefix_k *entry =
			&snapshot->lan_prefixes[i];
		size_t bytes = direction_family_bytes(entry->family);

		if (!entry->ifindex || !bytes || entry->prefix_len > bytes * 8U)
			return false;
	}
	for (i = 0; i < snapshot->local_address_count; i++)
		if (!direction_family_bytes(snapshot->local_addresses[i].family))
			return false;
	for (i = 0; i < snapshot->wan_count; i++) {
		const struct jmx_direction_wan_k *entry = &snapshot->wans[i];

		if (!entry->wan_id || !entry->registered || !entry->family_mask ||
		    (entry->family_mask & ~(JMX_DIRECTION_NL_FAMILY_MASK_IPV4 |
					   JMX_DIRECTION_NL_FAMILY_MASK_IPV6)) ||
		    (!entry->ifindex && !entry->route_identity && !entry->table_id))
			return false;
		for (j = 0; j < i; j++)
			if (snapshot->wans[j].wan_id == entry->wan_id)
				return false;
	}
	return true;
}

static void direction_publish_locked(const struct jmx_direction_snapshot_k *snapshot)
{
	unsigned int active = smp_load_acquire(&jmx_direction_runtime.active_slot);
	unsigned int inactive = active ^ 1U;

	/* The target was active during the previous publication. */
	synchronize_rcu();
	jmx_direction_runtime.slots[inactive] = *snapshot;
	smp_store_release(&jmx_direction_runtime.active_slot, inactive);
}

static void direction_update_workfn(struct work_struct *work)
{
	struct jmx_direction_update *update = container_of(
		work, struct jmx_direction_update, work);

	if (READ_ONCE(jmx_direction_runtime.initialized) &&
	    direction_snapshot_valid(&update->snapshot)) {
		mutex_lock(&jmx_direction_runtime.update_lock);
		direction_publish_locked(&update->snapshot);
		mutex_unlock(&jmx_direction_runtime.update_lock);
	}
	kfree(update);
}

static int direction_queue_update(struct jmx_direction_update *update)
{
	if (!update || !READ_ONCE(jmx_direction_runtime.initialized) ||
	    !jmx_direction_runtime.wq)
		return -ENODEV;
	if (!queue_work(jmx_direction_runtime.wq, &update->work))
		return -EALREADY;
	return 0;
}

static int direction_publish_unready_internal(u64 generation, u8 gateway_mode)
{
	struct jmx_direction_snapshot_k snapshot;

	if (!generation)
		generation = 1;
	memset(&snapshot, 0, sizeof(snapshot));
	snapshot.version = JMX_DIRECTION_NL_ABI_VERSION;
	snapshot.generation = generation;
	snapshot.gateway_mode = gateway_mode ? 1 : 0;
	mutex_lock(&jmx_direction_runtime.update_lock);
	direction_publish_locked(&snapshot);
	mutex_unlock(&jmx_direction_runtime.update_lock);
	return 0;
}

int jmx_direction_init(void)
{
	memset(&jmx_direction_runtime, 0, sizeof(jmx_direction_runtime));
	mutex_init(&jmx_direction_runtime.update_lock);
	/* Linux 7.2 requires exactly one of WQ_PERCPU / WQ_UNBOUND; passing
	 * neither trips WARN_ONCE in alloc_workqueue (kernel/workqueue.c:5850).
	 * These are ordered reconcile jobs with no CPU-locality requirement. */
	jmx_direction_runtime.wq = alloc_workqueue("jmx_direction",
							WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
	if (!jmx_direction_runtime.wq)
		return -ENOMEM;
	jmx_direction_runtime.slots[0].version = JMX_DIRECTION_NL_ABI_VERSION;
	jmx_direction_runtime.slots[1].version = JMX_DIRECTION_NL_ABI_VERSION;
	jmx_direction_runtime.slots[0].generation = 1;
	jmx_direction_runtime.slots[1].generation = 1;
	jmx_direction_runtime.initialized = true;
	return 0;
}

void jmx_direction_exit(void)
{
	WRITE_ONCE(jmx_direction_runtime.initialized, false);
	if (jmx_direction_runtime.wq) {
		flush_workqueue(jmx_direction_runtime.wq);
		destroy_workqueue(jmx_direction_runtime.wq);
		jmx_direction_runtime.wq = NULL;
	}
}

int jmx_direction_publish_snapshot(const struct jmx_direction_snapshot_k *snapshot)
{
	if (!READ_ONCE(jmx_direction_runtime.initialized) ||
	    !direction_snapshot_valid(snapshot))
		return -EINVAL;
	mutex_lock(&jmx_direction_runtime.update_lock);
	direction_publish_locked(snapshot);
	mutex_unlock(&jmx_direction_runtime.update_lock);
	return 0;
}

int jmx_direction_publish_unready(u64 generation, u8 gateway_mode)
{
	if (!READ_ONCE(jmx_direction_runtime.initialized))
		return -ENODEV;
	return direction_publish_unready_internal(generation, gateway_mode);
}

u64 jmx_direction_current_generation(void)
{
	unsigned int slot;
	u64 generation;

	if (!READ_ONCE(jmx_direction_runtime.initialized))
		return 0;
	rcu_read_lock();
	slot = smp_load_acquire(&jmx_direction_runtime.active_slot);
	generation = READ_ONCE(jmx_direction_runtime.slots[slot].generation);
	rcu_read_unlock();
	return generation;
}

int jmx_direction_classify_skb(const struct sk_buff *skb,
				       const struct net_device *in,
				       const struct net_device *out,
				       struct jmx_direction_decision *decision)
{
	struct jmx_direction_packet_k packet;
	unsigned int slot;
	const struct jmx_direction_snapshot_k *snapshot;
	bool source_local, destination_local;
	bool lan_ingress, lan_egress, wan_ingress, wan_egress;
	int rc;

	if (!decision)
		return -EINVAL;
	memset(decision, 0, sizeof(*decision));
	decision->classification = JMX_DIRECTION_UNKNOWN;
	rc = direction_packet_from_skb(skb, in, out, &packet);
	if (rc)
		return rc;
	if (!READ_ONCE(jmx_direction_runtime.initialized))
		return -ENODEV;

	rcu_read_lock();
	slot = smp_load_acquire(&jmx_direction_runtime.active_slot);
	snapshot = &jmx_direction_runtime.slots[slot];
	decision->generation = READ_ONCE(snapshot->generation);
	decision->ready = READ_ONCE(snapshot->ready);
	decision->gateway_mode = READ_ONCE(snapshot->gateway_mode);
	if (!snapshot->ready || !snapshot->generation ||
	    (snapshot->gateway_mode && (!snapshot->lan_prefix_count ||
					 !snapshot->wan_count)))
		goto out;
	if (!snapshot->gateway_mode) {
		decision->classification = JMX_DIRECTION_BYPASS;
		goto out;
	}

	lan_ingress = direction_lan_ingress(snapshot, &packet);
	lan_egress = direction_lan_egress(snapshot, &packet);
	wan_ingress = direction_wan_ingress(snapshot, &packet);
	wan_egress = direction_wan_egress(snapshot, &packet);
	decision->managed_lan_ingress = lan_ingress ? 1 : 0;
	decision->registered_wan_egress = wan_egress ? 1 : 0;
	source_local = direction_address_is_local(snapshot, packet.family,
						  packet.source);
	destination_local = direction_address_is_local(snapshot, packet.family,
						       packet.destination);
	if (destination_local || source_local) {
		decision->classification = wan_ingress ? JMX_DIRECTION_WAN_LOCAL :
							 JMX_DIRECTION_ROUTER_LOCAL;
		goto out;
	}
	if (!packet.is_forward) {
		decision->classification = JMX_DIRECTION_NON_GATEWAY;
		goto out;
	}
	if (lan_ingress && wan_egress)
		decision->classification = JMX_DIRECTION_LAN_WAN;
	else if (lan_ingress && lan_egress)
		decision->classification = JMX_DIRECTION_LAN_LAN;

out:
	rcu_read_unlock();
	return 0;
}

int jmx_direction_is_gate_candidate(const struct jmx_direction_decision *decision)
{
	return decision && decision->ready && decision->gateway_mode &&
	       decision->managed_lan_ingress && decision->registered_wan_egress &&
	       decision->classification == JMX_DIRECTION_LAN_WAN;
}

void jmx_direction_observe_skb(const struct sk_buff *skb,
				       const struct net_device *in,
				       const struct net_device *out)
{
	struct jmx_direction_decision decision;

	if (jmx_direction_classify_skb(skb, in, out, &decision) != 0) {
		jmx_stats_gate_direction_unknown();
		jmx_stats_gate_direction_fail_open();
		return;
	}
	if (!decision.ready) {
		jmx_stats_gate_direction_unready();
		jmx_stats_gate_direction_fail_open();
		return;
	}
	if (decision.classification == JMX_DIRECTION_UNKNOWN) {
		jmx_stats_gate_direction_unknown();
		jmx_stats_gate_direction_fail_open();
		return;
	}
	if (jmx_direction_is_gate_candidate(&decision))
		jmx_stats_gate_direction_lan_wan();
	else
		jmx_stats_gate_direction_fail_open();
}

static u64 direction_wire_be64(const void *data)
{
	__be64 value;

	memcpy(&value, data, sizeof(value));
	return be64_to_cpu(value);
}

static u64 direction_next_generation(void)
{
	u64 generation = jmx_direction_current_generation();

	return generation == U64_MAX ? 1 : generation + 1;
}

static void direction_fail_unready(const void *data, int len)
{
	u64 generation = direction_next_generation();
	u8 gateway_mode = 1;
	struct jmx_direction_update *update;

	if (data && len >= offsetof(struct jmx_direction_nl_header, generation) +
			      sizeof(__be64)) {
		const u8 *bytes = data;
		u64 candidate = direction_wire_be64(bytes +
			offsetof(struct jmx_direction_nl_header, generation));

		if (candidate)
			generation = candidate;
	}
	if (data && len > offsetof(struct jmx_direction_nl_header, gateway_mode))
		gateway_mode = ((const u8 *)data)[offsetof(
			struct jmx_direction_nl_header, gateway_mode)] ? 1 : 0;
	update = kzalloc(sizeof(*update), GFP_KERNEL);
	if (!update) {
		/* Do not sleep from the netlink callback on allocation failure.  Mark
		 * the consumer unavailable so every packet path stays fail-open. */
		WRITE_ONCE(jmx_direction_runtime.initialized, false);
		return;
	}
	INIT_WORK(&update->work, direction_update_workfn);
	update->snapshot.version = JMX_DIRECTION_NL_ABI_VERSION;
	update->snapshot.generation = generation;
	update->snapshot.gateway_mode = gateway_mode;
	if (direction_queue_update(update) != 0)
	{
		kfree(update);
		WRITE_ONCE(jmx_direction_runtime.initialized, false);
	}
}

static int direction_parse_wire(const void *data, int len,
					struct jmx_direction_snapshot_k *snapshot)
{
	struct jmx_direction_nl_header header;
	const u8 *cursor;
	u32 message_size;
	u16 header_size, lan_count, local_count, wan_count;
	size_t expected;
	u16 i;

	if (!data || !snapshot || len < (int)sizeof(header))
		return -EINVAL;
	memcpy(&header, data, sizeof(header));
	if (be32_to_cpu(header.action) != JMX_NL_ACT_DIRECTION_SNAPSHOT ||
	    be16_to_cpu(header.abi_version) != JMX_DIRECTION_NL_ABI_VERSION ||
	    be16_to_cpu(header.reserved) != 0)
		return -EPROTONOSUPPORT;
	header_size = be16_to_cpu(header.header_size);
	message_size = be32_to_cpu(header.message_size);
	lan_count = be16_to_cpu(header.lan_prefix_count);
	local_count = be16_to_cpu(header.local_address_count);
	wan_count = be16_to_cpu(header.wan_count);
	if (header_size != sizeof(header) || message_size != (u32)len ||
	    header.ready > 1 || header.gateway_mode > 1 ||
	    lan_count > JMX_DIRECTION_NL_MAX_LAN_PREFIXES ||
	    local_count > JMX_DIRECTION_NL_MAX_LOCAL_ADDRS ||
	    wan_count > JMX_DIRECTION_NL_MAX_WANS)
		return -EINVAL;
	expected = sizeof(header) + (size_t)lan_count * sizeof(struct jmx_direction_nl_prefix) +
		   (size_t)local_count * sizeof(struct jmx_direction_nl_local_address) +
		   (size_t)wan_count * sizeof(struct jmx_direction_nl_wan);
	if (expected != (size_t)len)
		return -EMSGSIZE;
	memset(snapshot, 0, sizeof(*snapshot));
	snapshot->version = JMX_DIRECTION_NL_ABI_VERSION;
	snapshot->generation = be64_to_cpu(header.generation);
	snapshot->ready = header.ready;
	snapshot->gateway_mode = header.gateway_mode;
	snapshot->lan_prefix_count = lan_count;
	snapshot->local_address_count = local_count;
	snapshot->wan_count = wan_count;
	if (!snapshot->generation)
		return -EINVAL;
	cursor = (const u8 *)data + sizeof(header);
	for (i = 0; i < lan_count; i++) {
		struct jmx_direction_nl_prefix wire;
		struct jmx_direction_prefix_k *entry =
			&snapshot->lan_prefixes[i];

		memcpy(&wire, cursor, sizeof(wire));
		cursor += sizeof(wire);
		if (be16_to_cpu(wire.reserved) != 0)
			return -EINVAL;
		entry->ifindex = be32_to_cpu(wire.ifindex);
		entry->family = wire.family;
		entry->prefix_len = wire.prefix_len;
		memcpy(entry->address, wire.address, sizeof(entry->address));
	}
	for (i = 0; i < local_count; i++) {
		struct jmx_direction_nl_local_address wire;
		struct jmx_direction_local_address_k *entry =
			&snapshot->local_addresses[i];

		memcpy(&wire, cursor, sizeof(wire));
		cursor += sizeof(wire);
		if (wire.reserved[0] || wire.reserved[1] || wire.reserved[2])
			return -EINVAL;
		entry->family = wire.family;
		memcpy(entry->address, wire.address, sizeof(entry->address));
	}
	for (i = 0; i < wan_count; i++) {
		struct jmx_direction_nl_wan wire;
		struct jmx_direction_wan_k *entry = &snapshot->wans[i];

		memcpy(&wire, cursor, sizeof(wire));
		cursor += sizeof(wire);
		if (wire.reserved || be32_to_cpu(wire.reserved2) != 0 ||
		    be32_to_cpu(wire.reserved3) != 0)
			return -EINVAL;
		entry->wan_id = wire.wan_id;
		entry->family_mask = wire.family_mask;
		entry->registered = wire.registered;
		entry->ifindex = be32_to_cpu(wire.ifindex);
		entry->route_identity = be32_to_cpu(wire.route_identity);
		entry->table_id = be32_to_cpu(wire.table_id);
	}
	return direction_snapshot_valid(snapshot) ? 0 : -EINVAL;
}

int jmx_direction_nl_handle(const void *data, int len)
{
	struct jmx_direction_update *update;
	__be32 action;
	int rc;

	if (!data || len < (int)sizeof(action))
		return 0;
	memcpy(&action, data, sizeof(action));
	if (be32_to_cpu(action) != JMX_NL_ACT_DIRECTION_SNAPSHOT)
		return 0;
	if (!READ_ONCE(jmx_direction_runtime.initialized))
		return 1;
	update = kzalloc(sizeof(*update), GFP_KERNEL);
	if (!update) {
		WRITE_ONCE(jmx_direction_runtime.initialized, false);
		return 1;
	}
	INIT_WORK(&update->work, direction_update_workfn);
	rc = direction_parse_wire(data, len, &update->snapshot);
	if (rc)
	{
		kfree(update);
		direction_fail_unready(data, len);
	}
	else if (direction_queue_update(update) != 0) {
		kfree(update);
		WRITE_ONCE(jmx_direction_runtime.initialized, false);
	}
	return 1;
}

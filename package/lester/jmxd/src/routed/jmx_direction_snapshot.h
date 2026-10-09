/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __JMX_DIRECTION_SNAPSHOT_H__
#define __JMX_DIRECTION_SNAPSHOT_H__

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#define JMX_DIRECTION_SNAPSHOT_VERSION 1U
#define JMX_DIRECTION_ADDR_BYTES 16U
#define JMX_DIRECTION_MAX_LAN_PREFIXES 128U
#define JMX_DIRECTION_MAX_LOCAL_ADDRS 128U
#define JMX_DIRECTION_MAX_WANS 255U
#define JMX_DIRECTION_STORE_SLOTS 2U

#define JMX_DIRECTION_FAMILY_IPV4 4U
#define JMX_DIRECTION_FAMILY_IPV6 6U

#define JMX_DIRECTION_FAMILY_MASK_IPV4 (1U << 0)
#define JMX_DIRECTION_FAMILY_MASK_IPV6 (1U << 1)

enum jmx_direction_class {
    JMX_DIRECTION_UNKNOWN = 0,
    JMX_DIRECTION_LAN_WAN,
    JMX_DIRECTION_LAN_LAN,
    JMX_DIRECTION_ROUTER_LOCAL,
    JMX_DIRECTION_WAN_LOCAL,
    JMX_DIRECTION_BYPASS,
    JMX_DIRECTION_NON_GATEWAY,
};

struct jmx_direction_prefix {
    uint32_t ifindex;
    uint8_t family;
    uint8_t prefix_len;
    uint8_t address[JMX_DIRECTION_ADDR_BYTES];
};

struct jmx_direction_local_address {
    uint8_t family;
    uint8_t address[JMX_DIRECTION_ADDR_BYTES];
};

struct jmx_direction_wan {
    uint8_t wan_id;
    uint8_t family_mask;
    uint8_t registered;
    uint8_t reserved;
    uint32_t ifindex;
    uint32_t route_identity;
    uint32_t table_id;
};

/* Immutable after publication. The kernel consumer must receive this shape
 * through its own fixed netlink contract; it must never read config.db/UCI. */
struct jmx_direction_snapshot {
    uint32_t version;
    uint64_t generation;
    uint8_t ready;
    uint8_t gateway_mode;
    uint16_t lan_prefix_count;
    uint16_t local_address_count;
    uint16_t wan_count;
    uint16_t reserved;
    struct jmx_direction_prefix lan_prefixes[JMX_DIRECTION_MAX_LAN_PREFIXES];
    struct jmx_direction_local_address local_addresses[JMX_DIRECTION_MAX_LOCAL_ADDRS];
    struct jmx_direction_wan wans[JMX_DIRECTION_MAX_WANS];
};

struct jmx_direction_packet {
    uint8_t family;
    uint8_t l4_protocol;
    uint8_t is_forward;
    uint8_t is_local_destination;
    uint8_t is_local_source;
    uint32_t ingress_ifindex;
    uint32_t egress_ifindex;
    uint32_t egress_route_identity;
    uint8_t source[JMX_DIRECTION_ADDR_BYTES];
    uint8_t destination[JMX_DIRECTION_ADDR_BYTES];
};

struct jmx_direction_decision {
    enum jmx_direction_class classification;
    uint8_t managed_lan_ingress;
    uint8_t registered_wan_egress;
};

/* The two slots are never freed. Readers copy from an immutable slot and do
 * not take a mutex; writers publish a fully-built replacement atomically. */
struct jmx_direction_snapshot_store {
    struct jmx_direction_snapshot slots[JMX_DIRECTION_STORE_SLOTS];
    _Atomic unsigned active_slot;
    _Atomic unsigned readers[JMX_DIRECTION_STORE_SLOTS];
    atomic_flag writer_lock;
    _Atomic unsigned initialized;
};

int jmx_direction_snapshot_init(struct jmx_direction_snapshot *snapshot,
                                uint64_t generation, int gateway_mode);
int jmx_direction_snapshot_add_lan_prefix(struct jmx_direction_snapshot *snapshot,
                                          uint32_t ifindex, uint8_t family,
                                          const uint8_t *address, uint8_t prefix_len);
int jmx_direction_snapshot_add_local_address(struct jmx_direction_snapshot *snapshot,
                                             uint8_t family,
                                             const uint8_t *address);
int jmx_direction_snapshot_add_wan(struct jmx_direction_snapshot *snapshot,
                                    uint8_t wan_id, uint8_t family_mask,
                                    uint32_t ifindex, uint32_t route_identity,
                                    uint32_t table_id);
int jmx_direction_snapshot_validate(const struct jmx_direction_snapshot *snapshot);

struct jmx_direction_decision
jmx_direction_classify(const struct jmx_direction_snapshot *snapshot,
                       const struct jmx_direction_packet *packet);
int jmx_direction_is_gate_candidate(const struct jmx_direction_decision *decision);

void jmx_direction_snapshot_store_init(struct jmx_direction_snapshot_store *store);
int jmx_direction_snapshot_store_publish(struct jmx_direction_snapshot_store *store,
                                         const struct jmx_direction_snapshot *snapshot);
int jmx_direction_snapshot_store_read(struct jmx_direction_snapshot_store *store,
                                       struct jmx_direction_snapshot *out);

struct json_object;

/* Build from normalized control-plane JSON. `lan_data` contains `lans`; the
 * registered WAN array contains entries with id/ifname or ifindex/fwmark/table.
 * No interface-name prefix is used as an ownership signal. */
int jmx_direction_snapshot_build_json(
    struct json_object *lan_data,
    struct json_object *registered_wans,
    int gateway_mode,
    uint64_t generation,
    struct jmx_direction_snapshot *out,
    char *error,
    size_t error_len);

/* Publish the current control-plane snapshot used by future gate consumers. */
int jmx_direction_snapshot_refresh_json(struct json_object *lan_data,
                                         struct json_object *registered_wans,
                                         int gateway_mode);
int jmx_direction_snapshot_publish_unready(int gateway_mode);
int jmx_direction_snapshot_read_current(struct jmx_direction_snapshot *out);

#endif

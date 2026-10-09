/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "jmx_direction_snapshot.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef JMX_DIRECTION_SNAPSHOT_NO_JSON
#include <json-c/json.h>
#endif

static size_t family_bytes(uint8_t family)
{
    return family == JMX_DIRECTION_FAMILY_IPV4 ? 4U :
           (family == JMX_DIRECTION_FAMILY_IPV6 ? 16U : 0U);
}

static uint8_t family_mask_for(uint8_t family)
{
    return family == JMX_DIRECTION_FAMILY_IPV4 ? JMX_DIRECTION_FAMILY_MASK_IPV4 :
           (family == JMX_DIRECTION_FAMILY_IPV6 ? JMX_DIRECTION_FAMILY_MASK_IPV6 : 0U);
}

static int prefix_matches(uint8_t family, const uint8_t *network,
                          uint8_t prefix_len, const uint8_t *address)
{
    size_t bytes = family_bytes(family);
    size_t full;
    uint8_t remainder;

    if (!bytes || !network || !address || prefix_len > bytes * 8U)
        return 0;
    full = prefix_len / 8U;
    remainder = prefix_len % 8U;
    if (full && memcmp(network, address, full) != 0)
        return 0;
    if (remainder) {
        uint8_t mask = (uint8_t)(0xffU << (8U - remainder));

        if ((network[full] & mask) != (address[full] & mask))
            return 0;
    }
    return 1;
}

static int address_equal(uint8_t family, const uint8_t *left,
                         const uint8_t *right)
{
    size_t bytes = family_bytes(family);

    return bytes && left && right && memcmp(left, right, bytes) == 0;
}

static void canonicalize_prefix(uint8_t family, uint8_t *address,
                                uint8_t prefix_len)
{
    size_t bytes = family_bytes(family);
    size_t full;
    uint8_t remainder;

    if (!bytes || !address || prefix_len > bytes * 8U)
        return;
    full = prefix_len / 8U;
    remainder = prefix_len % 8U;
    if (remainder)
        address[full] &= (uint8_t)(0xffU << (8U - remainder));
    if (full + (remainder ? 1U : 0U) < bytes)
        memset(address + full + (remainder ? 1U : 0U), 0,
               bytes - full - (remainder ? 1U : 0U));
}

int jmx_direction_snapshot_init(struct jmx_direction_snapshot *snapshot,
                                uint64_t generation, int gateway_mode)
{
    if (!snapshot)
        return -1;
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->version = JMX_DIRECTION_SNAPSHOT_VERSION;
    snapshot->generation = generation;
    snapshot->gateway_mode = gateway_mode ? 1 : 0;
    snapshot->ready = 1;
    return 0;
}

int jmx_direction_snapshot_add_lan_prefix(struct jmx_direction_snapshot *snapshot,
                                          uint32_t ifindex, uint8_t family,
                                          const uint8_t *address, uint8_t prefix_len)
{
    struct jmx_direction_prefix *entry;
    uint8_t canonical[JMX_DIRECTION_ADDR_BYTES] = {0};
    uint16_t i;
    size_t bytes = family_bytes(family);

    if (!snapshot || !ifindex || !bytes || !address ||
        prefix_len > bytes * 8U)
        return -1;
    memcpy(canonical, address, bytes);
    canonicalize_prefix(family, canonical, prefix_len);
    for (i = 0; i < snapshot->lan_prefix_count; i++) {
        entry = &snapshot->lan_prefixes[i];
        if (entry->ifindex == ifindex && entry->family == family &&
            entry->prefix_len == prefix_len &&
            memcmp(entry->address, canonical, bytes) == 0)
            return 0;
    }
    if (snapshot->lan_prefix_count >= JMX_DIRECTION_MAX_LAN_PREFIXES)
        return -1;
    entry = &snapshot->lan_prefixes[snapshot->lan_prefix_count++];
    memset(entry, 0, sizeof(*entry));
    entry->ifindex = ifindex;
    entry->family = family;
    entry->prefix_len = prefix_len;
    memcpy(entry->address, canonical, bytes);
    return 0;
}

int jmx_direction_snapshot_add_local_address(struct jmx_direction_snapshot *snapshot,
                                             uint8_t family,
                                             const uint8_t *address)
{
    struct jmx_direction_local_address *entry;
    size_t bytes = family_bytes(family);
    uint16_t i;

    if (!snapshot || !bytes || !address ||
        snapshot->local_address_count >= JMX_DIRECTION_MAX_LOCAL_ADDRS)
        return -1;
    for (i = 0; i < snapshot->local_address_count; i++)
        if (snapshot->local_addresses[i].family == family &&
            address_equal(family, snapshot->local_addresses[i].address, address))
            return 0;
    entry = &snapshot->local_addresses[snapshot->local_address_count++];
    memset(entry, 0, sizeof(*entry));
    entry->family = family;
    memcpy(entry->address, address, bytes);
    return 0;
}

int jmx_direction_snapshot_add_wan(struct jmx_direction_snapshot *snapshot,
                                    uint8_t wan_id, uint8_t family_mask,
                                    uint32_t ifindex, uint32_t route_identity,
                                    uint32_t table_id)
{
    struct jmx_direction_wan *entry;
    uint16_t i;

    if (!snapshot || !wan_id || !family_mask ||
        (!ifindex && !route_identity && !table_id) ||
        (family_mask & ~(JMX_DIRECTION_FAMILY_MASK_IPV4 |
                         JMX_DIRECTION_FAMILY_MASK_IPV6)))
        return -1;
    for (i = 0; i < snapshot->wan_count; i++) {
        if (snapshot->wans[i].wan_id != wan_id)
            continue;
        snapshot->wans[i].family_mask = family_mask;
        snapshot->wans[i].ifindex = ifindex;
        snapshot->wans[i].route_identity = route_identity;
        snapshot->wans[i].table_id = table_id;
        snapshot->wans[i].registered = 1;
        return 0;
    }
    if (snapshot->wan_count >= JMX_DIRECTION_MAX_WANS)
        return -1;
    entry = &snapshot->wans[snapshot->wan_count++];
    memset(entry, 0, sizeof(*entry));
    entry->wan_id = wan_id;
    entry->family_mask = family_mask;
    entry->ifindex = ifindex;
    entry->route_identity = route_identity;
    entry->table_id = table_id;
    entry->registered = 1;
    return 0;
}

int jmx_direction_snapshot_validate(const struct jmx_direction_snapshot *snapshot)
{
    uint16_t i;

    if (!snapshot || snapshot->version != JMX_DIRECTION_SNAPSHOT_VERSION ||
        !snapshot->ready || snapshot->generation == 0)
        return -1;
    if (!snapshot->gateway_mode)
        return 0;
    if (snapshot->lan_prefix_count == 0 || snapshot->wan_count == 0)
        return -1;
    for (i = 0; i < snapshot->lan_prefix_count; i++) {
        const struct jmx_direction_prefix *entry = &snapshot->lan_prefixes[i];
        size_t bytes = family_bytes(entry->family);

        if (!entry->ifindex || !bytes || entry->prefix_len > bytes * 8U)
            return -1;
    }
    for (i = 0; i < snapshot->wan_count; i++) {
        const struct jmx_direction_wan *entry = &snapshot->wans[i];

        if (!entry->wan_id || !entry->registered ||
            (!entry->ifindex && !entry->route_identity && !entry->table_id) ||
            !entry->family_mask)
            return -1;
    }
    return 0;
}

static int packet_is_local(const struct jmx_direction_snapshot *snapshot,
                           const struct jmx_direction_packet *packet)
{
    uint16_t i;

    if (packet->is_local_destination || packet->is_local_source)
        return 1;
    for (i = 0; i < snapshot->local_address_count; i++) {
        const struct jmx_direction_local_address *entry =
            &snapshot->local_addresses[i];

        if (entry->family != packet->family)
            continue;
        if (address_equal(packet->family, entry->address, packet->destination) ||
            address_equal(packet->family, entry->address, packet->source))
            return 1;
    }
    return 0;
}

static int packet_matches_lan_ingress(const struct jmx_direction_snapshot *snapshot,
                                      const struct jmx_direction_packet *packet)
{
    uint16_t i;

    for (i = 0; i < snapshot->lan_prefix_count; i++) {
        const struct jmx_direction_prefix *entry = &snapshot->lan_prefixes[i];

        if (entry->ifindex != packet->ingress_ifindex ||
            entry->family != packet->family)
            continue;
        if (prefix_matches(packet->family, entry->address, entry->prefix_len,
                           packet->source))
            return 1;
    }
    return 0;
}

static int packet_matches_lan_egress(const struct jmx_direction_snapshot *snapshot,
                                     const struct jmx_direction_packet *packet)
{
    uint16_t i;

    for (i = 0; i < snapshot->lan_prefix_count; i++)
        if (snapshot->lan_prefixes[i].ifindex == packet->egress_ifindex &&
            snapshot->lan_prefixes[i].family == packet->family &&
            prefix_matches(packet->family, snapshot->lan_prefixes[i].address,
                           snapshot->lan_prefixes[i].prefix_len,
                           packet->destination))
            return 1;
    return 0;
}

static int packet_matches_wan_egress(const struct jmx_direction_snapshot *snapshot,
                                     const struct jmx_direction_packet *packet)
{
    uint16_t i;
    uint8_t family_mask = family_mask_for(packet->family);

    if (!family_mask)
        return 0;
    for (i = 0; i < snapshot->wan_count; i++) {
        const struct jmx_direction_wan *entry = &snapshot->wans[i];

        if (!entry->registered || !(entry->family_mask & family_mask))
            continue;
        if (entry->ifindex && entry->ifindex == packet->egress_ifindex)
            return 1;
        if (packet->egress_route_identity && entry->route_identity &&
            entry->route_identity == packet->egress_route_identity)
            return 1;
    }
    return 0;
}

static int packet_matches_wan_ingress(const struct jmx_direction_snapshot *snapshot,
                                      const struct jmx_direction_packet *packet)
{
    uint16_t i;
    uint8_t family_mask = family_mask_for(packet->family);

    if (!family_mask)
        return 0;
    for (i = 0; i < snapshot->wan_count; i++)
        if (snapshot->wans[i].registered &&
            (snapshot->wans[i].family_mask & family_mask) &&
            snapshot->wans[i].ifindex == packet->ingress_ifindex)
            return 1;
    return 0;
}

struct jmx_direction_decision
jmx_direction_classify(const struct jmx_direction_snapshot *snapshot,
                       const struct jmx_direction_packet *packet)
{
    struct jmx_direction_decision decision = {
        .classification = JMX_DIRECTION_UNKNOWN,
    };
    int lan_ingress;
    int lan_egress;
    int wan_egress;
    int wan_ingress;

    if (!snapshot || !packet || snapshot->version != JMX_DIRECTION_SNAPSHOT_VERSION ||
        !snapshot->ready)
        return decision;
    if (packet_is_local(snapshot, packet)) {
        decision.classification = packet_matches_wan_ingress(snapshot, packet) ?
                                  JMX_DIRECTION_WAN_LOCAL : JMX_DIRECTION_ROUTER_LOCAL;
        return decision;
    }
    if (!snapshot->gateway_mode) {
        decision.classification = JMX_DIRECTION_BYPASS;
        return decision;
    }
    if (!packet->is_forward) {
        decision.classification = JMX_DIRECTION_NON_GATEWAY;
        return decision;
    }

    lan_ingress = packet_matches_lan_ingress(snapshot, packet);
    lan_egress = packet_matches_lan_egress(snapshot, packet);
    wan_egress = packet_matches_wan_egress(snapshot, packet);
    wan_ingress = packet_matches_wan_ingress(snapshot, packet);
    decision.managed_lan_ingress = lan_ingress ? 1 : 0;
    decision.registered_wan_egress = wan_egress ? 1 : 0;

    if (lan_ingress && wan_egress)
        decision.classification = JMX_DIRECTION_LAN_WAN;
    else if (lan_ingress && lan_egress)
        decision.classification = JMX_DIRECTION_LAN_LAN;
    else if (wan_ingress && packet->is_local_destination)
        decision.classification = JMX_DIRECTION_WAN_LOCAL;
    else
        decision.classification = JMX_DIRECTION_UNKNOWN;
    return decision;
}

int jmx_direction_is_gate_candidate(const struct jmx_direction_decision *decision)
{
    return decision && decision->managed_lan_ingress &&
           decision->registered_wan_egress &&
           decision->classification == JMX_DIRECTION_LAN_WAN;
}

void jmx_direction_snapshot_store_init(struct jmx_direction_snapshot_store *store)
{
    if (!store)
        return;
    memset(store, 0, sizeof(*store));
    atomic_init(&store->active_slot, 0U);
    atomic_init(&store->readers[0], 0U);
    atomic_init(&store->readers[1], 0U);
    atomic_flag_clear(&store->writer_lock);
    atomic_init(&store->initialized, 1U);
    (void)jmx_direction_snapshot_init(&store->slots[0], 1, 0);
    (void)jmx_direction_snapshot_init(&store->slots[1], 1, 0);
    store->slots[0].ready = 0;
    store->slots[1].ready = 0;
}

int jmx_direction_snapshot_store_publish(struct jmx_direction_snapshot_store *store,
                                         const struct jmx_direction_snapshot *snapshot)
{
    unsigned active;
    unsigned inactive;

    if (!store || !snapshot || snapshot->version != JMX_DIRECTION_SNAPSHOT_VERSION ||
        snapshot->generation == 0 ||
        (snapshot->ready && jmx_direction_snapshot_validate(snapshot) != 0))
        return -1;
    if (!atomic_load_explicit(&store->initialized, memory_order_acquire))
        jmx_direction_snapshot_store_init(store);
    while (atomic_flag_test_and_set_explicit(&store->writer_lock,
                                             memory_order_acquire))
        ;
    active = atomic_load_explicit(&store->active_slot, memory_order_acquire);
    inactive = active ^ 1U;
    while (atomic_load_explicit(&store->readers[inactive], memory_order_acquire))
        ;
    store->slots[inactive] = *snapshot;
    atomic_store_explicit(&store->active_slot, inactive, memory_order_release);
    atomic_flag_clear_explicit(&store->writer_lock, memory_order_release);
    return 0;
}

int jmx_direction_snapshot_store_read(struct jmx_direction_snapshot_store *store,
                                       struct jmx_direction_snapshot *out)
{
    unsigned slot;

    if (!store || !out ||
        !atomic_load_explicit(&store->initialized, memory_order_acquire))
        return -1;
    for (;;) {
        slot = atomic_load_explicit(&store->active_slot, memory_order_acquire);
        atomic_fetch_add_explicit(&store->readers[slot], 1U, memory_order_acquire);
        if (slot == atomic_load_explicit(&store->active_slot, memory_order_acquire))
            break;
        atomic_fetch_sub_explicit(&store->readers[slot], 1U, memory_order_release);
    }
    *out = store->slots[slot];
    atomic_fetch_sub_explicit(&store->readers[slot], 1U, memory_order_release);
    return 0;
}

#ifndef JMX_DIRECTION_SNAPSHOT_NO_JSON

static struct jmx_direction_snapshot_store g_direction_store;
static _Atomic uint64_t g_direction_generation;

static uint64_t direction_next_generation(void)
{
    uint64_t current = atomic_load_explicit(&g_direction_generation,
                                            memory_order_relaxed);

    for (;;) {
        uint64_t next = current == UINT64_MAX ? 1U : current + 1U;

        if (atomic_compare_exchange_weak_explicit(&g_direction_generation,
                                                  &current, next,
                                                  memory_order_relaxed,
                                                  memory_order_relaxed))
            return next;
    }
}

static struct json_object *json_array_value(struct json_object *root,
                                            const char *key)
{
    struct json_object *value = NULL;

    if (!root || !key)
        return NULL;
    if (json_object_is_type(root, json_type_array))
        return root;
    if (!json_object_object_get_ex(root, key, &value) || !value ||
        !json_object_is_type(value, json_type_array))
        return NULL;
    return value;
}

static const char *json_string(struct json_object *root, const char *key)
{
    struct json_object *value = NULL;

    if (!root || !key || !json_object_object_get_ex(root, key, &value) ||
        !value || !json_object_is_type(value, json_type_string))
        return NULL;
    return json_object_get_string(value);
}

static int json_int(struct json_object *root, const char *key, int def)
{
    struct json_object *value = NULL;
    const char *text;
    char *end = NULL;
    long parsed;

    if (!root || !key || !json_object_object_get_ex(root, key, &value) || !value)
        return def;
    if (json_object_is_type(value, json_type_int))
        return json_object_get_int(value);
    if (!json_object_is_type(value, json_type_string))
        return def;
    text = json_object_get_string(value);
    if (!text || !text[0])
        return def;
    errno = 0;
    parsed = strtol(text, &end, 10);
    return !errno && end != text && *end == '\0' && parsed >= INT_MIN &&
           parsed <= INT_MAX ? (int)parsed : def;
}

static int parse_address(const char *value, uint8_t *family,
                         uint8_t address[JMX_DIRECTION_ADDR_BYTES])
{
    if (!value || !family || !address)
        return -1;
    memset(address, 0, JMX_DIRECTION_ADDR_BYTES);
    if (inet_pton(AF_INET, value, address) == 1) {
        *family = JMX_DIRECTION_FAMILY_IPV4;
        return 0;
    }
    if (inet_pton(AF_INET6, value, address) == 1) {
        *family = JMX_DIRECTION_FAMILY_IPV6;
        return 0;
    }
    return -1;
}

static int parse_prefix_value(struct json_object *entry, const char *ip_key,
                               int default_prefix, uint8_t *family,
                               uint8_t address[JMX_DIRECTION_ADDR_BYTES],
                               uint8_t *prefix_len)
{
    const char *ip = json_string(entry, ip_key);
    const char *slash;
    char address_text[128];
    int prefix = default_prefix;
    size_t length;

    if (!ip || !ip[0])
        return -1;
    slash = strchr(ip, '/');
    if (slash) {
        length = (size_t)(slash - ip);
        if (!length || length >= sizeof(address_text))
            return -1;
        memcpy(address_text, ip, length);
        address_text[length] = '\0';
        {
            char *end = NULL;
            long parsed;

            errno = 0;
            parsed = strtol(slash + 1, &end, 10);
            if (errno || end == slash + 1 || *end || parsed < 0 || parsed > 128)
                return -1;
            prefix = (int)parsed;
        }
        ip = address_text;
    }
    if (parse_address(ip, family, address) != 0)
        return -1;
    if (!slash)
        prefix = json_int(entry, "prefix", json_int(entry, "cidr", prefix));
    if (prefix < 0 || prefix > (int)(family_bytes(*family) * 8U))
        return -1;
    *prefix_len = (uint8_t)prefix;
    return 0;
}

static int parse_ifindex(struct json_object *entry, const char *ifname_key)
{
    int ifindex = json_int(entry, "ifindex", 0);
    const char *ifname;

    if (ifindex > 0)
        return ifindex;
    ifname = json_string(entry, ifname_key);
    if (!ifname || !ifname[0] || strlen(ifname) >= IFNAMSIZ)
        return 0;
    return (int)if_nametoindex(ifname);
}

static int add_lan_address(struct jmx_direction_snapshot *snapshot,
                           uint32_t ifindex, const char *ip,
                           int default_prefix, int prefix_override,
                           char *error, size_t error_len)
{
    uint8_t family;
    uint8_t address[JMX_DIRECTION_ADDR_BYTES];
    uint8_t prefix_len;
    struct json_object *address_entry;
    int rc;

    if (!ip || !ip[0])
        return 0;
    address_entry = json_object_new_object();
    if (!address_entry)
        return -1;
    json_object_object_add(address_entry, "ipaddr", json_object_new_string(ip));
    json_object_object_add(address_entry, "prefix",
                           json_object_new_int(prefix_override >= 0 ?
                                               prefix_override : default_prefix));
    rc = parse_prefix_value(address_entry, "ipaddr", default_prefix, &family,
                            address, &prefix_len);
    json_object_put(address_entry);
    if (rc != 0)
        return 0;
    if (jmx_direction_snapshot_add_lan_prefix(snapshot, ifindex, family,
                                               address, prefix_len) != 0 ||
        jmx_direction_snapshot_add_local_address(snapshot, family, address) != 0) {
        if (error && error_len)
            snprintf(error, error_len, "managed LAN snapshot capacity exceeded");
        return -1;
    }
    return 1;
}

static int prefix_len_from_netmask(uint8_t family,
                                   const struct sockaddr *netmask)
{
    const uint8_t *bytes;
    size_t length;
    size_t i;
    int prefix = 0;
    int zero_seen = 0;

    if (!netmask)
        return -1;
    if (family == JMX_DIRECTION_FAMILY_IPV4) {
        if (netmask->sa_family != AF_INET)
            return -1;
        bytes = (const uint8_t *)&((const struct sockaddr_in *)netmask)->sin_addr;
        length = 4U;
    } else if (family == JMX_DIRECTION_FAMILY_IPV6) {
        if (netmask->sa_family != AF_INET6)
            return -1;
        bytes = (const uint8_t *)&((const struct sockaddr_in6 *)netmask)->sin6_addr;
        length = 16U;
    } else {
        return -1;
    }
    for (i = 0; i < length; i++) {
        uint8_t bit;

        for (bit = 0x80U; bit; bit >>= 1) {
            if (bytes[i] & bit) {
                if (zero_seen)
                    return -1;
                prefix++;
            } else {
                zero_seen = 1;
            }
        }
    }
    return prefix;
}

static int add_runtime_lan_addresses(struct jmx_direction_snapshot *snapshot,
                                     uint32_t ifindex, char *error,
                                     size_t error_len)
{
    struct ifaddrs *head = NULL;
    struct ifaddrs *ifa;
    int added = 0;

    if (!snapshot || !ifindex || getifaddrs(&head) != 0)
        return 0;
    for (ifa = head; ifa; ifa = ifa->ifa_next) {
        uint8_t family;
        uint8_t address[JMX_DIRECTION_ADDR_BYTES] = {0};
        int prefix_len;
        unsigned runtime_ifindex;

        if (!ifa->ifa_name || !ifa->ifa_addr || !ifa->ifa_netmask)
            continue;
        runtime_ifindex = if_nametoindex(ifa->ifa_name);
        if (runtime_ifindex != ifindex)
            continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            family = JMX_DIRECTION_FAMILY_IPV4;
            memcpy(address,
                   &((const struct sockaddr_in *)ifa->ifa_addr)->sin_addr,
                   sizeof(struct in_addr));
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            family = JMX_DIRECTION_FAMILY_IPV6;
            memcpy(address,
                   &((const struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr,
                   sizeof(struct in6_addr));
        } else {
            continue;
        }
        prefix_len = prefix_len_from_netmask(family, ifa->ifa_netmask);
        if (prefix_len < 0)
            continue;
        if (jmx_direction_snapshot_add_lan_prefix(
                snapshot, ifindex, family, address, (uint8_t)prefix_len) != 0 ||
            jmx_direction_snapshot_add_local_address(snapshot, family,
                                                      address) != 0) {
            if (error && error_len)
                snprintf(error, error_len,
                         "runtime LAN snapshot capacity exceeded");
            freeifaddrs(head);
            return -1;
        }
        added++;
    }
    freeifaddrs(head);
    return added;
}

static int build_lan_entry(struct jmx_direction_snapshot *snapshot,
                           struct json_object *lan, char *error,
                           size_t error_len)
{
    struct json_object *ipv6 = NULL;
    struct json_object *extra_ips = NULL;
    const char *ipaddr;
    int ifindex;
    int added = 0;
    int i;

    if (!lan || !json_object_is_type(lan, json_type_object))
        return -1;
    ifindex = parse_ifindex(lan, "ifname");
    if (!ifindex)
        ifindex = parse_ifindex(lan, "device");
    if (!ifindex) {
        snprintf(error, error_len, "managed LAN has no ifindex");
        return -1;
    }
    ipaddr = json_string(lan, "ipaddr");
    if (ipaddr)
        added += add_lan_address(snapshot, (uint32_t)ifindex, ipaddr,
                                 json_int(lan, "cidr",
                                          json_int(lan, "prefix", 24)), -1,
                                 error, error_len);
    if (json_object_object_get_ex(lan, "extra_ips", &extra_ips) && extra_ips &&
        json_object_is_type(extra_ips, json_type_array)) {
        for (i = 0; i < (int)json_object_array_length(extra_ips); i++) {
            struct json_object *value = json_object_array_get_idx(extra_ips, i);
            const char *extra = value && json_object_is_type(value, json_type_string) ?
                                json_object_get_string(value) : NULL;

            if (extra)
                added += add_lan_address(snapshot, (uint32_t)ifindex, extra, 24,
                                         -1, error, error_len);
        }
    }
    if (json_object_object_get_ex(lan, "ipv6", &ipv6) && ipv6 &&
        json_object_is_type(ipv6, json_type_object)) {
        const char *static_addr = json_string(ipv6, "addr");
        int ipv6_prefix = json_int(ipv6, "prefix_len", 64);

        if (static_addr && static_addr[0] && ipv6_prefix >= 0 && ipv6_prefix <= 128)
            added += add_lan_address(snapshot, (uint32_t)ifindex, static_addr, 64,
                                     ipv6_prefix, error, error_len);
    }
    i = add_runtime_lan_addresses(snapshot, (uint32_t)ifindex, error, error_len);
    if (i < 0)
        return -1;
    added += i;
    if (!added) {
        snprintf(error, error_len, "managed LAN has no valid IPv4/IPv6 prefix");
        return -1;
    }
    return 0;
}

static int build_wan_entry(struct jmx_direction_snapshot *snapshot,
                           struct json_object *wan, char *error,
                           size_t error_len)
{
    int id = json_int(wan, "id", 0);
    int ifindex = parse_ifindex(wan, "ifname");
    uint32_t route_identity = (uint32_t)json_int(wan, "route_identity",
                                                 json_int(wan, "fwmark", 0));
    uint32_t table_id = (uint32_t)json_int(wan, "table", 0);
    int family_mask = json_int(wan, "family_mask",
                               JMX_DIRECTION_FAMILY_MASK_IPV4 |
                               JMX_DIRECTION_FAMILY_MASK_IPV6);

    if (id <= 0 || id > 255 || (!ifindex && !route_identity && !table_id) ||
        jmx_direction_snapshot_add_wan(snapshot, (uint8_t)id,
                                       (uint8_t)family_mask, (uint32_t)ifindex,
                                       route_identity, table_id) != 0) {
        snprintf(error, error_len, "registered WAN has invalid identity");
        return -1;
    }
    return 0;
}

int jmx_direction_snapshot_build_json(
    struct json_object *lan_data,
    struct json_object *registered_wans,
    int gateway_mode,
    uint64_t generation,
    struct jmx_direction_snapshot *out,
    char *error,
    size_t error_len)
{
    struct json_object *lans;
    size_t i;

    if (error && error_len)
        error[0] = '\0';
    if (!out || !generation || jmx_direction_snapshot_init(out, generation,
                                                            gateway_mode) != 0)
        return -1;
    if (!gateway_mode) {
        out->ready = 1;
        return 0;
    }
    lans = json_array_value(lan_data, "lans");
    if (!lans || !registered_wans ||
        !json_object_is_type(registered_wans, json_type_array) ||
        json_object_array_length(lans) == 0 ||
        json_object_array_length(registered_wans) == 0) {
        if (error && error_len)
            snprintf(error, error_len, "LAN/WAN identity set is empty");
        out->ready = 0;
        return -1;
    }
    for (i = 0; i < json_object_array_length(lans); i++)
        if (build_lan_entry(out, json_object_array_get_idx(lans, i), error,
                            error_len) != 0) {
            out->ready = 0;
            return -1;
        }
    for (i = 0; i < json_object_array_length(registered_wans); i++)
        if (build_wan_entry(out, json_object_array_get_idx(registered_wans, i),
                            error, error_len) != 0) {
            out->ready = 0;
            return -1;
        }
    if (jmx_direction_snapshot_validate(out) != 0) {
        if (error && error_len)
            snprintf(error, error_len, "direction snapshot validation failed");
        out->ready = 0;
        return -1;
    }
    return 0;
}

int jmx_direction_snapshot_refresh_json(struct json_object *lan_data,
                                         struct json_object *registered_wans,
                                         int gateway_mode)
{
    struct jmx_direction_snapshot snapshot;
    char error[128];
    uint64_t generation = direction_next_generation();

    if (jmx_direction_snapshot_build_json(lan_data, registered_wans,
                                           gateway_mode, generation, &snapshot,
                                           error, sizeof(error)) != 0)
        snapshot.ready = 0;
    if (!atomic_load_explicit(&g_direction_store.initialized,
                              memory_order_acquire))
        jmx_direction_snapshot_store_init(&g_direction_store);
    return jmx_direction_snapshot_store_publish(&g_direction_store, &snapshot);
}

int jmx_direction_snapshot_publish_unready(int gateway_mode)
{
    struct jmx_direction_snapshot snapshot;
    uint64_t generation = direction_next_generation();

    if (jmx_direction_snapshot_init(&snapshot, generation, gateway_mode) != 0)
        return -1;
    snapshot.ready = 0;
    if (!atomic_load_explicit(&g_direction_store.initialized,
                              memory_order_acquire))
        jmx_direction_snapshot_store_init(&g_direction_store);
    return jmx_direction_snapshot_store_publish(&g_direction_store, &snapshot);
}

int jmx_direction_snapshot_read_current(struct jmx_direction_snapshot *out)
{
    if (!atomic_load_explicit(&g_direction_store.initialized,
                              memory_order_acquire))
        jmx_direction_snapshot_store_init(&g_direction_store);
    return jmx_direction_snapshot_store_read(&g_direction_store, out);
}

#endif

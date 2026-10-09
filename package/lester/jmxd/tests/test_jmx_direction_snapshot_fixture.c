#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

#define JMX_DIRECTION_SNAPSHOT_NO_JSON 1
#include "../src/routed/jmx_direction_snapshot.c"

static void addr4(const char *text, uint8_t out[16])
{
    assert(inet_pton(AF_INET, text, out) == 1);
}

static void addr6(const char *text, uint8_t out[16])
{
    assert(inet_pton(AF_INET6, text, out) == 1);
}

static struct jmx_direction_packet packet4(uint32_t ingress, uint32_t egress,
                                           const char *source,
                                           const char *destination,
                                           uint8_t l4_protocol)
{
    struct jmx_direction_packet packet;

    memset(&packet, 0, sizeof(packet));
    packet.family = JMX_DIRECTION_FAMILY_IPV4;
    packet.l4_protocol = l4_protocol;
    packet.is_forward = 1;
    packet.ingress_ifindex = ingress;
    packet.egress_ifindex = egress;
    addr4(source, packet.source);
    addr4(destination, packet.destination);
    return packet;
}

static struct jmx_direction_packet packet6(uint32_t ingress, uint32_t egress,
                                           const char *source,
                                           const char *destination,
                                           uint8_t l4_protocol)
{
    struct jmx_direction_packet packet;

    memset(&packet, 0, sizeof(packet));
    packet.family = JMX_DIRECTION_FAMILY_IPV6;
    packet.l4_protocol = l4_protocol;
    packet.is_forward = 1;
    packet.ingress_ifindex = ingress;
    packet.egress_ifindex = egress;
    addr6(source, packet.source);
    addr6(destination, packet.destination);
    return packet;
}

static void assert_class(const struct jmx_direction_snapshot *snapshot,
                         struct jmx_direction_packet packet,
                         enum jmx_direction_class expected,
                         int gate_candidate)
{
    struct jmx_direction_decision decision = jmx_direction_classify(snapshot, &packet);

    assert(decision.classification == expected);
    assert(jmx_direction_is_gate_candidate(&decision) == gate_candidate);
}

int main(void)
{
    struct jmx_direction_snapshot snapshot;
    struct jmx_direction_snapshot unready;
    struct jmx_direction_snapshot_store store;
    struct jmx_direction_snapshot readback;
    struct jmx_direction_packet packet;
    uint8_t address[16];

    assert(jmx_direction_snapshot_init(&snapshot, 7, 1) == 0);
    addr4("192.168.50.1", address);
    assert(jmx_direction_snapshot_add_lan_prefix(
               &snapshot, 10, JMX_DIRECTION_FAMILY_IPV4, address, 24) == 0);
    assert(jmx_direction_snapshot_add_local_address(
               &snapshot, JMX_DIRECTION_FAMILY_IPV4, address) == 0);
    assert(jmx_direction_snapshot_add_wan(
               &snapshot, 1, JMX_DIRECTION_FAMILY_MASK_IPV4, 20, 0x10001, 101) == 0);

    packet = packet4(10, 20, "192.168.50.22", "198.51.100.7", IPPROTO_TCP);
    assert_class(&snapshot, packet, JMX_DIRECTION_LAN_WAN, 1);
    packet.l4_protocol = IPPROTO_UDP;
    assert_class(&snapshot, packet, JMX_DIRECTION_LAN_WAN, 1);
    packet.l4_protocol = IPPROTO_ICMP;
    assert_class(&snapshot, packet, JMX_DIRECTION_LAN_WAN, 1);

    packet = packet4(10, 10, "192.168.50.22", "192.168.50.44", IPPROTO_TCP);
    assert_class(&snapshot, packet, JMX_DIRECTION_LAN_LAN, 0);

    packet = packet4(10, 0, "192.168.50.22", "192.168.50.1", IPPROTO_TCP);
    packet.is_local_destination = 1;
    assert_class(&snapshot, packet, JMX_DIRECTION_ROUTER_LOCAL, 0);

    packet = packet4(20, 0, "198.51.100.7", "192.168.50.1", IPPROTO_UDP);
    packet.is_local_destination = 1;
    assert_class(&snapshot, packet, JMX_DIRECTION_WAN_LOCAL, 0);

    packet = packet4(99, 20, "203.0.113.8", "198.51.100.7", IPPROTO_ICMP);
    assert_class(&snapshot, packet, JMX_DIRECTION_UNKNOWN, 0);

    packet = packet4(10, 0, "192.168.50.22", "198.51.100.7", IPPROTO_TCP);
    packet.is_forward = 0;
    assert_class(&snapshot, packet, JMX_DIRECTION_NON_GATEWAY, 0);

    assert(jmx_direction_snapshot_init(&snapshot, 11, 0) == 0);
    packet = packet4(10, 20, "192.168.50.22", "198.51.100.7", IPPROTO_TCP);
    assert_class(&snapshot, packet, JMX_DIRECTION_BYPASS, 0);

    assert(jmx_direction_snapshot_init(&unready, 8, 1) == 0);
    unready.ready = 0;
    packet = packet4(10, 20, "192.168.50.22", "198.51.100.7", IPPROTO_TCP);
    assert_class(&unready, packet, JMX_DIRECTION_UNKNOWN, 0);

    assert(jmx_direction_snapshot_init(&snapshot, 9, 1) == 0);
    addr6("2001:db8:50::1", address);
    assert(jmx_direction_snapshot_add_lan_prefix(
               &snapshot, 10, JMX_DIRECTION_FAMILY_IPV6, address, 64) == 0);
    assert(jmx_direction_snapshot_add_local_address(
               &snapshot, JMX_DIRECTION_FAMILY_IPV6, address) == 0);
    assert(jmx_direction_snapshot_add_wan(
               &snapshot, 2, JMX_DIRECTION_FAMILY_MASK_IPV6, 21, 0x10002, 102) == 0);
    packet = packet6(10, 21, "2001:db8:50::22", "2001:db8:99::7", IPPROTO_TCP);
    assert_class(&snapshot, packet, JMX_DIRECTION_LAN_WAN, 1);

    jmx_direction_snapshot_store_init(&store);
    assert(jmx_direction_snapshot_store_publish(&store, &snapshot) == 0);
    assert(jmx_direction_snapshot_store_read(&store, &readback) == 0);
    assert(readback.ready && readback.generation == 9);
    /* The global helper is separate from the local fixture store; publish an
     * explicit unready generation to the local store for the read-side proof. */
    unready = snapshot;
    unready.generation = 10;
    unready.ready = 0;
    assert(jmx_direction_snapshot_store_publish(&store, &unready) == 0);
    assert(jmx_direction_snapshot_store_read(&store, &readback) == 0);
    assert(!readback.ready && readback.generation == 10);

    puts("ok: jmx direction snapshot fixture passed");
    return 0;
}

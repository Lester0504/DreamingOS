#!/usr/bin/env python3
"""Static contract checks for the jmx direction snapshot consumer."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
JMX = ROOT / "jmx" / "src"
ROUTE = ROOT / "jmxd" / "src" / "routed"


def test_kernel_consumer_contract() -> None:
    direction = (JMX / "jmx_direction.c").read_text(encoding="utf-8")
    direction_h = (JMX / "jmx_direction.h").read_text(encoding="utf-8")
    direction_nl_h = (JMX / "jmx_direction_nl.h").read_text(encoding="utf-8")
    main = (JMX / "jmx_main.c").read_text(encoding="utf-8")
    stats_h = (JMX / "jmx_stats.h").read_text(encoding="utf-8")
    stats_c = (JMX / "jmx_stats.c").read_text(encoding="utf-8")
    kbuild = (JMX / "Kbuild").read_text(encoding="utf-8")
    route = (ROUTE / "jmx_route.c").read_text(encoding="utf-8")

    for required in (
        "JMX_NL_ACT_DIRECTION_SNAPSHOT 44U",
        "JMX_DIRECTION_NL_ABI_VERSION  1U",
        "static_assert(sizeof(struct jmx_direction_nl_header) == 30)",
        "static_assert(sizeof(struct jmx_direction_nl_prefix) == 24)",
        "static_assert(sizeof(struct jmx_direction_nl_local_address) == 20)",
        "static_assert(sizeof(struct jmx_direction_nl_wan) == 24)",
        "JMX_DIRECTION_NL_MAX_LAN_PREFIXES 128U",
        "JMX_DIRECTION_NL_MAX_LOCAL_ADDRS  128U",
        "JMX_DIRECTION_NL_MAX_WANS         255U",
    ):
        assert required in direction_nl_h

    for required in (
        "struct jmx_direction_snapshot_k slots[2]",
        "alloc_workqueue(\"jmx_direction\"",
        "synchronize_rcu();",
        "rcu_read_lock();",
        "direction_snapshot_valid",
        "jmx_direction_nl_handle",
        "JMX_DIRECTION_LAN_WAN",
        "JMX_DIRECTION_LAN_LAN",
        "JMX_DIRECTION_ROUTER_LOCAL",
        "JMX_DIRECTION_WAN_LOCAL",
        "JMX_DIRECTION_BYPASS",
        "JMX_DIRECTION_NON_GATEWAY",
        "JMX_DIRECTION_UNKNOWN",
    ):
        assert required in direction or required in direction_h

    assert "NF_DROP" not in direction
    assert "NF_QUEUE" not in direction
    assert "jmx_direction_is_gate_candidate" in direction
    assert "managed_lan_ingress" in direction
    assert "registered_wan_egress" in direction
    assert "jmx_direction_observe_skb" in main
    assert "jmx_direction_nl_handle" in main
    assert "jmx_direction_init" in main
    assert "jmx_direction_exit" in main
    assert "jmx_direction.o" in kbuild

    for counter in (
        "gate_direction_unknown",
        "gate_direction_unready",
        "gate_direction_lan_wan",
        "gate_direction_fail_open",
    ):
        assert counter in stats_h
        assert counter in stats_c

    assert "route_direction_store_be16" in route
    assert "route_direction_store_be32" in route
    assert "route_direction_store_be64" in route
    assert "header->message_size" in route
    assert "reserved3" in direction_nl_h
    assert "reserved3" in route
    assert "jmx_direction_snapshot_publish_unready" in route
    assert "route_direction_snapshot_send_current" in route
    assert "route_direction_snapshot_publish(fd" in route


if __name__ == "__main__":
    test_kernel_consumer_contract()
    print("ok: jmx direction kernel consumer contract")

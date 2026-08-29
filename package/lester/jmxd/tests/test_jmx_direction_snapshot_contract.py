#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_direction_snapshot_contract() -> None:
    header = (ROOT / "src/routed/jmx_direction_snapshot.h").read_text(encoding="utf-8")
    source = (ROOT / "src/routed/jmx_direction_snapshot.c").read_text(encoding="utf-8")
    route = (ROOT / "src/routed/jmx_route.c").read_text(encoding="utf-8")
    makefile = (ROOT / "src/Makefile").read_text(encoding="utf-8")

    for required in (
        "JMX_DIRECTION_FAMILY_IPV4",
        "JMX_DIRECTION_FAMILY_IPV6",
        "JMX_DIRECTION_LAN_WAN",
        "JMX_DIRECTION_LAN_LAN",
        "JMX_DIRECTION_ROUTER_LOCAL",
        "JMX_DIRECTION_WAN_LOCAL",
        "JMX_DIRECTION_UNKNOWN",
        "managed_lan_ingress",
        "registered_wan_egress",
        "_Atomic unsigned active_slot",
        "atomic_store_explicit(&store->active_slot",
    ):
        assert required in header or required in source

    assert "jmx_direction_snapshot_publish_unready" in route
    assert "route_direction_snapshot_publish" in route
    assert "jmx_direction_snapshot_refresh_json" in route
    assert "jmx_direction_snapshot.o" in makefile
    assert "getifaddrs(&head)" in source
    assert "ifa->ifa_netmask" in source
    assert "prefix_len_from_netmask" in source
    assert "direction_next_generation" in source
    assert "atomic_compare_exchange_weak_explicit" in source
    assert source.count("static uint64_t generation") == 0
    assert "strncmp(ifname, \"wan\"" not in source
    assert "sqlite" not in source
    assert "fopen(" not in source


if __name__ == "__main__":
    test_direction_snapshot_contract()
    print("ok: jmx direction snapshot contract")

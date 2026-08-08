#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def section(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    return source[begin:source.index(end, begin)]


def main() -> None:
    source = (ROOT / "src/routed/jmx_route.c").read_text(encoding="utf-8")
    snapshot = section(
        source,
        "static int route_network_wan_snapshot_get",
        "static int route_network_wan_runtime_changed",
    )
    sync = section(
        source,
        "static int jmx_route_sync_json(struct json_object *config)\n{",
        "int jmx_route_sync_config(void)",
    )
    tick = section(
        source,
        "void jmx_route_health_tick(void)",
        "\n}",
    )

    assert 'uci_load(ctx, "network", &pkg)' in snapshot
    assert "route_network_iface_is_wan(name, proto)" in snapshot
    assert "route_section_disabled(s)" in snapshot
    assert "route_ifstatus_runtime(name" in snapshot
    assert "return -1" in snapshot
    for field in (
        "wan->name",
        "wan->proto",
        "wan->configured_ifname",
        "wan->l3_ifname",
        "wan->gateway",
        "wan->weight",
        "wan->online",
    ):
        assert field in snapshot

    assert "runtime_snapshot_valid = route_network_wan_snapshot_get" in sync
    assert sync.index("runtime_snapshot_valid = route_network_wan_snapshot_get") < sync.index(
        "jmx_route_nl_rule_flush(fd)"
    )
    assert "if (runtime_snapshot_valid)" in sync
    assert "g_route_network_wans = runtime_snapshot" in sync
    assert "g_route_network_wans_ready = 1" in sync
    baseline = sync.index("if (runtime_snapshot_valid)")
    assert baseline > sync.index("kernel readback mismatch")
    assert "if (runtime_ok && !runtime_online)" in sync
    assert "jmx_route_cleanup_system_route(table_id)" in sync

    assert "route_network_wan_runtime_changed(&runtime_snapshot)" in tick
    assert "runtime_changed > 0 || route_auto_carrier_mapping_changed(config)" in tick
    assert "jmx_route_sync_json(config)" in tick
    assert "jmx_route_sync_config()" not in tick

    print("ok: WAN runtime topology changes trigger guarded route resync")


if __name__ == "__main__":
    main()

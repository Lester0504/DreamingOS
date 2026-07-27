#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def assert_sender(source: str) -> None:
    start = source.index("static int jmx_route_nl_send(")
    end = source.index("int jmx_route_nl_carrier_flush", start)
    sender = source[start:end]
    assert "calloc(1, NLMSG_SPACE(total))" in sender
    assert "nlh->nlmsg_len = NLMSG_LENGTH(total)" in sender
    assert "nlh->nlmsg_len = NLMSG_SPACE(total)" not in sender
    assert "hdr->len = len" in sender


def main() -> None:
    routed = read(ROOT / "src/routed/jmx_route.c")
    legacy = read(ROOT / "src/jmx_route.c")
    assert_sender(routed)
    assert_sender(legacy)

    sync_start = routed.index("int jmx_route_sync_config(void)")
    sync_end = routed.index("static int route_health_enabled_opt", sync_start)
    sync = routed[sync_start:sync_end]
    assert "route_kernel_state_counts" in routed
    assert "route_kernel_state_counts(" in sync
    assert "actual_carriers != carrier_count" in sync
    assert "actual_wans != wan_count" in sync
    assert "actual_rules != rule_count" in sync
    assert "kernel readback mismatch" in sync
    assert "return sync_errors ? -1 : 0" in sync
    print("ok: route netlink uses exact payload length and verifies kernel readback")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""The router's tunnel idle limit must stay strictly below the relay's.

Guards ``Acceptance-to-Backend-tunnel-idle-timeout-symmetric-150s.md``. Both
ends once used 150s, so whichever noticed an idle tunnel first came down to
timing jitter: a race rather than one side cleanly reopening the connection.
The router is the side that can reconnect, so it must be the side that gives up
first, and the ping interval must stay small enough that a live connection
produces traffic well inside the limit.

The relay value is read from the Go source when that tree is present, so the
two halves cannot drift apart unnoticed.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TUNNEL_C = ROOT / "src/cloud/cloud_tunnel.c"
# dreamingrelay sits beside the jmxd package in the workspace, not inside it.
RELAY_GO = ROOT.parent / "dreamingrelay/internal/server/tunnel.go"


def c_define(source: str, name: str) -> int:
    match = re.search(r"^#define\s+" + name + r"\s+(\d+)\s*$", source, re.M)
    if not match:
        raise SystemExit(f"{name} not found in cloud_tunnel.c")
    return int(match.group(1))


def main() -> None:
    source = TUNNEL_C.read_text(encoding="utf-8")
    idle_ms = c_define(source, "CLOUD_TUNNEL_IDLE_LIMIT_MS")
    ping_ms = c_define(source, "CLOUD_TUNNEL_PING_INTERVAL_MS")
    failures = []

    # A live connection must get at least two pongs inside the idle window;
    # one leaves no margin for a single lost frame.
    if idle_ms < ping_ms * 2:
        failures.append(
            f"idle limit {idle_ms}ms must fit at least two ping intervals "
            f"({ping_ms}ms each)"
        )

    relay_ms = None
    if RELAY_GO.exists():
        relay_src = RELAY_GO.read_text(encoding="utf-8")
        match = re.search(r"tunnelIdleTimeout\s*=\s*(\d+)\s*\*\s*time\.Second",
                          relay_src)
        if match:
            relay_ms = int(match.group(1)) * 1000

    if relay_ms is None:
        print("note: relay source unavailable, checking the router side only")
    elif idle_ms >= relay_ms:
        failures.append(
            f"router idle limit {idle_ms}ms must be strictly below the relay's "
            f"{relay_ms}ms; equal values make the two ends race"
        )
    else:
        margin = relay_ms - idle_ms
        # A margin under one ping interval is too tight to be meaningful.
        if margin < ping_ms:
            failures.append(
                f"margin {margin}ms below the relay is thinner than one ping "
                f"interval ({ping_ms}ms)"
            )

    if failures:
        for item in failures:
            print("FAIL: " + item)
        raise SystemExit(1)

    detail = f"router {idle_ms}ms, ping {ping_ms}ms"
    if relay_ms is not None:
        detail += f", relay {relay_ms}ms"
    print(f"ok: tunnel idle timeouts are asymmetric ({detail})")


if __name__ == "__main__":
    main()

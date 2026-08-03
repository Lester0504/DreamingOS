#!/usr/bin/env python3
"""Runtime test for route_status's kernel-nexthop resolution (Acceptance A-013).

Acceptance found three different gateways for the same WAN: route_config_get said
1.31.160.1, route_status said 110.18.155.129, and `ip route` said 116.113.39.193.
route_status now resolves the nexthop the kernel is actually using.

route_proc_device_nexthop() is extracted from src/routed/jmx_route.c and compiled,
so this runs shipped code. The primary input is a verbatim capture of
/proc/net/route from the live router, which is where the byte-order handling gets
decided: the kernel prints the in_addr in host order, so a naive ntohl() would
report 193.39.113.116 instead of 116.113.39.193.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROUTE_C = ROOT / "src/routed/jmx_route.c"
FIXTURE = ROOT / "tests/route_gateway_nexthop_fixture.c"

EXTRACT_START = "static int route_proc_device_nexthop(const char *device"
EXTRACT_END = "static void route_enrich_wan_runtime("

# Captured verbatim from 192.168.30.1 (`cat /proc/net/route`) on 2026-08-02.
# pppoe-wan holds the default route; pppoe-wan2's default lives in a policy
# table, so only its /32 peer route shows up in the main table.
LIVE_CAPTURE = (
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
    "pppoe-wan\t00000000\tC1277174\t0003\t0\t0\t10\t00000000\t0\t0\t0\n"
    "pppoe-wan2\t0100840A\t00000000\t0005\t0\t0\t0\tFFFFFFFF\t0\t0\t0\n"
    "pppoe-wan\tC1277174\t00000000\t0005\t0\t0\t0\tFFFFFFFF\t0\t0\t0\n"
    "docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
    "br-lan\t001EA8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
)

failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def extract_under_test() -> str:
    source = ROUTE_C.read_text()
    begin = source.find(EXTRACT_START)
    if begin < 0:
        raise SystemExit(f"extraction anchor not found: {EXTRACT_START!r}")
    stop = source.find(EXTRACT_END, begin)
    if stop < 0:
        raise SystemExit(f"extraction end anchor not found: {EXTRACT_END!r}")
    return source[begin:stop]


def build(workdir: Path) -> Path:
    (workdir / "route_gateway_extracted.h").write_text(extract_under_test())
    shutil.copy(FIXTURE, workdir / "fixture.c")
    binary = workdir / "fixture"
    command = [
        os.environ.get("CC", "cc"),
        "-O1", "-Wall", "-Wextra", "-Wno-unused-parameter",
        "-Wno-unused-function",
        "-o", str(binary), str(workdir / "fixture.c"), f"-I{workdir}",
    ]
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode != 0:
        raise SystemExit(f"fixture build failed:\n{result.stdout}\n{result.stderr}")
    noise = [line for line in result.stderr.splitlines() if "warning:" in line]
    check(not noise, f"extracted nexthop parser emits warnings: {noise}")
    return binary


def resolve(binary: Path, workdir: Path, table: str, device: str, tag: str) -> dict:
    path = workdir / f"route_{tag}"
    path.write_text(table)
    result = subprocess.run([str(binary), str(path), device],
                            text=True, capture_output=True)
    if result.returncode != 0:
        raise SystemExit(f"fixture run failed:\n{result.stdout}\n{result.stderr}")
    return json.loads(result.stdout)


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        binary = build(workdir)

        # ---- the live router's real table ---------------------------------
        got = resolve(binary, workdir, LIVE_CAPTURE, "pppoe-wan", "live1")
        check(got.get("rc") == 0, f"the WAN with a default route must resolve: {got}")
        check(got.get("nexthop") == "116.113.39.193",
              f"nexthop must match what `ip route` shows, not a byte-swapped "
              f"address: {got.get('nexthop')}")
        check(got.get("via_peer") is False,
              "a real default route must not be reported as a p2p peer")

        got = resolve(binary, workdir, LIVE_CAPTURE, "pppoe-wan2", "live2")
        check(got.get("rc") == 0,
              f"a WAN whose default route lives in a policy table must still "
              f"resolve via its peer route: {got}")
        check(got.get("nexthop") == "10.132.0.1",
              f"peer nexthop wrong: {got.get('nexthop')}")
        check(got.get("via_peer") is True,
              "a peer-derived nexthop must be labelled as such, otherwise the "
              "caller cannot tell it apart from a default gateway")

        # ---- an unrelated device must not borrow another WAN's gateway -----
        got = resolve(binary, workdir, LIVE_CAPTURE, "br-lan", "lan")
        check(got.get("nexthop") != "116.113.39.193",
              "a LAN bridge must never be handed a WAN's gateway")

        got = resolve(binary, workdir, LIVE_CAPTURE, "eth9", "absent")
        check(got.get("rc") != 0 and got.get("nexthop") == "",
              f"an absent device must report failure rather than a stale value: {got}")

        # ---- a default route must win over a peer route on the same device -
        # Row order is deliberately peer-first so a parser that returns the first
        # match it likes fails here.
        ordered = (
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
            "pppoe-wan\tC1277174\t00000000\t0005\t0\t0\t0\tFFFFFFFF\t0\t0\t0\n"
            "pppoe-wan\t00000000\tC1277174\t0003\t0\t0\t10\t00000000\t0\t0\t0\n"
        )
        got = resolve(binary, workdir, ordered, "pppoe-wan", "ordered")
        check(got.get("nexthop") == "116.113.39.193" and got.get("via_peer") is False,
              f"a real default route must take precedence over the peer route: {got}")

        # ---- an on-link default with no gateway ---------------------------
        onlink = (
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
            "wg0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n"
        )
        got = resolve(binary, workdir, onlink, "wg0", "onlink")
        check(got.get("rc") != 0,
              "a gatewayless on-link default must not be reported as a gateway "
              f"address: {got}")

        # ---- prefix-matching device names must not collide -----------------
        collide = (
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
            "pppoe-wan2\t00000000\t0100840A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
        )
        got = resolve(binary, workdir, collide, "pppoe-wan", "collide")
        check(got.get("rc") != 0,
              "'pppoe-wan' must not match the row belonging to 'pppoe-wan2': "
              f"{got}")

        # ---- malformed input must not be mistaken for an answer ------------
        for tag, table in (
            ("empty", ""),
            ("headeronly", "Iface\tDestination\tGateway\n"),
            ("truncated", "Iface\tDestination\tGateway\npppoe-wan\t00000000\n"),
        ):
            got = resolve(binary, workdir, table, "pppoe-wan", tag)
            check(got.get("rc") != 0,
                  f"malformed routing table ({tag}) must not yield a nexthop: {got}")

        # ---- route_status must publish the provenance ----------------------
        route_source = ROUTE_C.read_text()
        for field in ('"kernel_gateway"', '"module_gateway"', '"gateway_source"',
                      '"gateway_matches_kernel"'):
            check(field in route_source,
                  f"route_status must publish {field} so a caller can tell a "
                  f"stale registration from the route actually in force")
        check("route_proc_device_nexthop(" in route_source,
              "route_status no longer resolves the kernel nexthop")

    for message in failures:
        print(f"FAIL: {message}")
    if failures:
        print(f"{len(failures)} check(s) failed")
        return 1
    print("route gateway nexthop runtime checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

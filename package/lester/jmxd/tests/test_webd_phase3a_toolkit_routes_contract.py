#!/usr/bin/env python3
"""Structural contracts for the Phase 3A Toolkit/Diagnostics migration."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
WEBD = SRC / "webd"
API = WEBD / "api"
MAIN = (WEBD / "jmx_app_api.c").read_text(encoding="utf-8")
TOOLKIT = (API / "api_toolkit.c").read_text(encoding="utf-8")
REQUEST = (API / "api_request.c").read_text(encoding="utf-8")
MAKEFILE = (SRC / "Makefile").read_text(encoding="utf-8")

EXPECTED = (
    (596, "/api/v1/toolkit", "GET"),
    (597, "/api/v1/toolkit/router-check", "GET,POST"),
    (598, "/api/v1/toolkit/port-mirror", "GET"),
    (599, "/api/v1/toolkit/port-mirror", "POST,PUT"),
    (600, "/api/v1/toolkit/port-mirror", "DELETE"),
    (602, "/api/v1/toolkit/ddns", "GET"),
    (603, "/api/v1/toolkit/ddns", "POST,PUT"),
    (604, "/api/v1/toolkit/ddns", "DELETE"),
    (605, "/api/v1/toolkit/ddns/update", "POST"),
    (606, "/api/v1/toolkit/wake-on-lan", "POST"),
    (607, "/api/v1/toolkit/throughput", "POST"),
    (608, "/api/v1/toolkit/throughput/status", "GET"),
    (609, "/api/v1/toolkit/throughput/stop", "POST"),
    (610, "/api/v1/diagnostics/ping", "POST,PUT"),
    (611, "/api/v1/diagnostics/traceroute", "POST,PUT"),
    (612, "/api/v1/diagnostics/nslookup", "POST,PUT"),
    (613, "/api/v1/diagnostics/speedtest", "POST,PUT"),
    (960, "/api/v1/diagnostics/port-scan", "POST,PUT"),
    (961, "/api/v1/diagnostics/port-check", "POST,PUT"),
    (962, "/api/v1/diagnostics/tcp-udp-test", "POST,PUT"),
    (963, "/api/v1/diagnostics/ssl-check", "POST,PUT"),
    (964, "/api/v1/diagnostics/http-request", "POST,PUT"),
    (965, "/api/v1/diagnostics/headers", "POST,PUT"),
    (966, "/api/v1/diagnostics/website-check", "POST,PUT"),
    (967, "/api/v1/diagnostics/local-ports", "GET"),
    (968, "/api/v1/diagnostics/local-info", "GET"),
    (969, "/api/v1/diagnostics/arp-scan", "POST,PUT"),
    (970, "/api/v1/diagnostics/mtu-detect", "POST,PUT"),
    (971, "/api/v1/diagnostics/latency-monitor", "POST,PUT"),
    (972, "/api/v1/diagnostics/whois", "POST,PUT"),
    (973, "/api/v1/diagnostics/dns-query", "POST,PUT"),
    (974, "/api/v1/diagnostics/public-ip", "GET"),
    (975, "/api/v1/diagnostics/ip-geo", "POST,PUT"),
    (976, "/api/v1/diagnostics/mac-lookup", "POST,PUT"),
    (977, "/api/v1/diagnostics/speedtest/status", "GET"),
    (978, "/api/v1/diagnostics/speedtest/stop", "POST"),
    (981, "/api/v1/diagnostics/mdns", "POST,PUT"),
)


def route_rows() -> list[tuple[int, str, str]]:
    pattern = re.compile(
        r'JMX_API_ROUTE\((\d+),\s*"([^"]+)",\s*"([^"]*)",'
    )
    return [(int(seq), path, methods)
            for seq, path, methods in pattern.findall(TOOLKIT)]


def test_exact_production_route_contract() -> None:
    assert tuple(route_rows()) == EXPECTED
    assert "toolkit_api_routes," in (API / "api_router.c").read_text(encoding="utf-8")


def test_moved_exact_routes_are_not_duplicated_in_legacy_chain() -> None:
    for _, path, _ in EXPECTED:
        assert f'!strcmp(req.path, "{path}")' not in MAIN
    assert MAIN.count('!strncmp(req.path, "/api/v1/toolkit/port-mirror/", 28)') == 1
    assert MAIN.count('!strncmp(req.path, "/api/v1/toolkit/ddns/", 21)') == 1
    assert "!strchr(req.path + 28, '/')" in MAIN
    assert "!strchr(req.path + 21, '/')" in MAIN


def test_helper_ownership_and_build_objects() -> None:
    for name in ("webd_hex_value", "webd_query_decode", "webd_query_get"):
        assert len(re.findall(rf"(?m)^[A-Za-z_].*\b{name}\s*\(", REQUEST)) == 1
        assert not re.search(rf"(?m)^static .*\b{name}\s*\(", MAIN)
    assert len(re.findall(r"(?m)^struct json_object \*webd_toolkit_exec\s*\(", TOOLKIT)) == 1
    assert "struct json_object *webd_toolkit_exec(" in (API / "api_toolkit.h").read_text(encoding="utf-8")
    assert "webd/api/api_request.o webd/api/api_toolkit.o" in MAKEFILE


def test_every_api_translation_unit_stays_below_the_hard_limit() -> None:
    for path in sorted(API.glob("*.[ch]")):
        lines = len(path.read_text(encoding="utf-8").splitlines())
        assert lines <= 5000, f"{path.name} grew to {lines} lines"


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"ok: {len(tests)} Phase 3A Toolkit/Diagnostics contracts")

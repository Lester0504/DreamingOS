#!/usr/bin/env python3
"""Structural contracts for the Phase 3B Topology read-route migration."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
WEBD = SRC / "webd"
API = WEBD / "api"
MAIN = (WEBD / "jmx_app_api.c").read_text(encoding="utf-8")
TOPOLOGY = (API / "api_topology.c").read_text(encoding="utf-8")
ROUTER = (API / "api_router.c").read_text(encoding="utf-8")
MAKEFILE = (SRC / "Makefile").read_text(encoding="utf-8")

EXPECTED = (
    (331, "/api/v1/topology", "GET", "webd_is_unifi_topology_path"),
    (332, "/api/v1/topology/flow", "GET", None),
    (333, "[helper:webd_topology_history_path]", "GET",
     "webd_topology_history_path"),
    (334, "/api/v1/topology/infrastructure", "GET",
     "webd_is_unifi_infrastructure_path"),
    (335, "[helper:webd_is_unifi_digital_twin_layout_path]", "GET",
     "webd_is_unifi_digital_twin_layout_path"),
)

MOVED_FUNCTIONS = (
    "webd_is_unifi_topology_path",
    "webd_is_unifi_infrastructure_path",
    "webd_parse_epoch_ms",
    "webd_topology_history_response",
    "webd_is_unifi_digital_twin_layout_path",
    "webd_cached_ubus_envelope_response",
    "webd_topology_infrastructure_envelope_valid",
    "webd_topology_infrastructure_shared_cache_read",
    "webd_topology_infrastructure_shared_cache_write",
    "webd_topology_infrastructure_cache_invalidate",
    "webd_topology_infrastructure_cached_response",
)


def route_rows() -> tuple[tuple[int, str, str, str | None], ...]:
    rows = []
    pattern = re.compile(
        r'JMX_API_(PREDICATE_)?ROUTE\(\s*(\d+)\s*,\s*"([^"]+)"\s*,\s*'
        r'"([^"]*)"\s*,\s*[^,]+(?:,\s*([A-Za-z_][A-Za-z0-9_]*))?'
    )
    for predicate_marker, seq, path, methods, predicate in pattern.findall(TOPOLOGY):
        rows.append((int(seq), path, methods,
                     predicate if predicate_marker else None))
    return tuple(rows)


def test_exact_production_route_contract() -> None:
    assert route_rows() == EXPECTED
    assert "topology_api_routes,\n    toolkit_api_routes," in ROUTER


def test_moved_routes_are_absent_from_the_legacy_chain() -> None:
    for literal in ("/api/v1/topology/flow", "/api/v1/topology/infrastructure"):
        assert f'!strcmp(req.path, "{literal}")' not in MAIN
    assert "webd_topology_history_path(req.path" not in MAIN
    assert "webd_is_unifi_topology_path(req.path)" not in MAIN
    assert "webd_is_unifi_infrastructure_path(req.path)" not in MAIN
    assert "webd_is_unifi_digital_twin_layout_path(req.path)" not in MAIN


def test_helper_ownership_and_narrow_export() -> None:
    for name in MOVED_FUNCTIONS:
        assert not re.search(rf"(?m)^static .*\b{name}\s*\(", MAIN), name
    assert len(re.findall(
        r"(?m)^void webd_topology_infrastructure_cache_invalidate\s*\(",
        TOPOLOGY)) == 1
    assert len(re.findall(
        r"(?m)^struct json_object \*webd_topology_infrastructure_cached_response\s*\(",
        TOPOLOGY)) == 1
    header = (API / "api_topology.h").read_text(encoding="utf-8")
    assert "webd_topology_infrastructure_cached_response(int *status);" in header
    assert "void webd_topology_infrastructure_cache_invalidate(void);" in header
    assert "webd/api/api_topology.o" in MAKEFILE


def test_topology_constants_have_one_owner() -> None:
    for name in (
        "WEBD_TOPOLOGY_TTL_SEC", "WEBD_TOPOLOGY_STALE_SEC",
        "WEBD_TOPOLOGY_TIMEOUT_MS", "WEBD_TOPOLOGY_INFRA_CACHE_PATH",
        "WEBD_TOPOLOGY_INFRA_LOCK_PATH",
        "WEBD_TOPOLOGY_INFRA_CACHE_MAX_BYTES",
    ):
        assert not re.search(rf"(?m)^#define {re.escape(name)}\b", MAIN)
        assert TOPOLOGY.count(f"#define {name} ") == 1


def test_every_api_translation_unit_stays_below_the_hard_limit() -> None:
    for path in sorted(API.glob("*.[ch]")):
        lines = len(path.read_text(encoding="utf-8").splitlines())
        assert lines <= 5000, f"{path.name} grew to {lines} lines"


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"ok: {len(tests)} Phase 3B Topology structural contracts")

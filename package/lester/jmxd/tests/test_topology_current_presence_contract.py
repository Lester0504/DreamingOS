#!/usr/bin/env python3
"""Static contract for current topology presence versus historical identity."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
DB = (ROOT / "src" / "jmx_db.c").read_text(encoding="utf-8")
USER = (ROOT / "src" / "jmx_user.c").read_text(encoding="utf-8")
API = (ROOT / "src" / "jmx_dreamingwrt_api.c").read_text(encoding="utf-8")


def body(source: str, symbol: str) -> str:
    match = re.search(rf"\b{re.escape(symbol)}\s*\([^;]*?\)\s*\{{", source, re.S)
    assert match, f"missing function: {symbol}"
    start = match.end()
    depth = 1
    pos = start
    while pos < len(source) and depth:
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
        pos += 1
    assert depth == 0, f"unterminated function: {symbol}"
    return source[start:pos - 1]


def test_stale_neighbor_is_observed_but_cannot_create_online_presence() -> None:
    observed = body(USER, "client_neigh_state_observed")
    online = body(USER, "client_neigh_state_marks_online")
    collector = body(USER, "update_client_from_kernel")

    assert '"STALE"' in observed
    assert '"STALE"' not in online
    assert collector.count("if (!client_neigh_state_marks_online(state))") >= 2
    assert collector.count("if (client_neigh_state_marks_online(state))") >= 2


def test_expired_network_sample_cannot_keep_connections_or_rates_live() -> None:
    row = body(DB, "db_row_to_client")
    downgrade = body(API, "dw_downgrade_stale_client_device")

    for source in (row, downgrade):
        assert "if (!sample_valid)" in source
        assert "connections = 0" in source
        assert "sample_valid &&" in source
        assert "last_seen_age >= 0 && last_seen_age <= 120" in source
    for key in ('"up_rate"', '"down_rate"', '"connections"'):
        assert key in downgrade


def test_identity_records_remain_available_but_unifi_vertices_require_online() -> None:
    db_merge = body(API, "dw_build_devices_from_client_db")
    vertex = body(API, "dw_unifi_add_client_json")

    assert "jmx_db_api_clients_list" in db_merge
    assert 'dw_json_get_bool(c, "online", 0)' in vertex
    assert "return;" in vertex


if __name__ == "__main__":
    tests = [value for name, value in globals().items()
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"ok: {len(tests)} current-topology presence contracts")

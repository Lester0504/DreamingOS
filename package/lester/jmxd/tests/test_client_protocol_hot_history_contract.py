#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE = (ROOT / "src/client_protocol_history.c").read_text(encoding="utf-8")
HEADER = (ROOT / "src/client_protocol_history.h").read_text(encoding="utf-8")
CORE = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")


def test_hot_producer_contract() -> None:
    for token in (
        "af_client_visit_list",
        "PROTOCOL_HISTORY_MAX_GAP_SEC 15",
        "JMX_CLIENT_PROTOCOL_HISTORY_MAX_SERIES 32",
        "JMX_CLIENT_PROTOCOL_HISTORY_MAX_POINTS 72",
        "protocol_history_generation_changed",
        "rows[i].in_bytes < counter->in_bytes",
        "rows[i].out_bytes < counter->out_bytes",
        "protocol_history_tick_add",
        "other_up_bytes_delta",
        "other_down_bytes_delta",
        '"producer_supported"',
        '"per_app_supported"',
        '"per_protocol_supported"',
        '"coverage_ratio"',
        '"producer_generation"',
        '"revision"',
        '"observed_at"',
    ):
        assert token in MODULE or token in HEADER


def test_sampler_reuses_existing_four_second_tick() -> None:
    tick_start = CORE.index("static void dw_client_overview_sample_tick(void)")
    tick_end = CORE.index("static struct json_object *dw_client_overview_history_json", tick_start)
    tick = CORE[tick_start:tick_end]
    assert "now - dw_client_overview_last_sample_ts < 4" in tick
    assert "jmx_client_protocol_history_sample_tick(now, dw_monotonic_ms());" in tick
    assert "sqlite" not in tick.lower()


def test_sql_is_read_only_degraded_fallback() -> None:
    assert "SQLITE_OPEN_READONLY" in MODULE
    assert '"supported", json_object_new_boolean(0)' in MODULE
    assert '"per_app_supported", json_object_new_boolean(0)' in MODULE
    assert '"per_protocol_supported", json_object_new_boolean(0)' in MODULE
    for forbidden in ("CREATE TABLE", "INSERT INTO", "UPDATE ", "DELETE FROM"):
        assert forbidden not in MODULE


if __name__ == "__main__":
    tests = [value for name, value in globals().items() if name.startswith("test_")]
    for test in tests:
        test()
    print(f"ok: {len(tests)} client protocol hot history contract tests")

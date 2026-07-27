#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")


def body(text: str, start: str, end: str) -> str:
    begin = text.index(start)
    finish = text.index(end, begin)
    return text[begin:finish]


def test_minute_flow_fallback_cannot_enable_hot_window_capability() -> None:
    summary = body(
        WEB,
        "static struct json_object *webd_profile_protocol_summary",
        "static void webd_profile_normalize_visits",
    )
    for token in (
        '"producer_supported"',
        '"per_app_supported"',
        '"per_protocol_supported"',
        "protocol_history_ready",
        "if (protocol_history_ready)",
        '"minute_flow_sample_fallback_not_full_hot_window"',
        '"rate_history_fallback_available"',
        '"rate_history_producer_supported"',
    ):
        assert token in summary
    assert 'app_nc_json_bool(protocol_history, "supported", 0)) {' not in summary


def test_rest_and_ws_expose_the_same_producer_diagnostics() -> None:
    summary = body(
        WEB,
        "static struct json_object *webd_profile_protocol_summary",
        "static void webd_profile_normalize_visits",
    )
    ws = body(
        WEB,
        "static struct json_object *webd_ws_client_protocols_data",
        "static struct json_object *webd_ws_client_connections_data",
    )
    for token in (
        '"rate_history_revision"',
        '"rate_history_observed_at"',
        '"rate_history_producer_supported"',
        '"rate_history_complete"',
    ):
        assert token in summary
        assert token in ws
    assert 'json_object_object_add(data, "protocol_summary", json_object_get(summary))' in ws


if __name__ == "__main__":
    tests = [value for name, value in globals().items() if name.startswith("test_")]
    for test in tests:
        test()
    print(f"ok: {len(tests)} client protocol history capability tests")

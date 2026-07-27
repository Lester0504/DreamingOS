#!/usr/bin/env python3
"""Static REST contracts for the Wi-Fi connectivity/roam event bridge."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
AGGREGATE = (ROOT / "src/webd/webd_wifi_aggregate.c").read_text(
    encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    offset = text.index(start)
    return text[offset:text.index(end, offset)]


def test_rest_route_is_get_only_and_bridges_to_ac() -> None:
    route = between(
        WEB,
        'else if (!strcmp(req.path, "/api/v1/wifi/connectivity/events")',
        'else if (!strcmp(req.path, "/api/v1/wifi/scan")',
    )
    assert '!strcmp(req.method, "GET")' in route
    assert "webd_wifi_station_events_params(" in route
    assert 'app_ubus_invoke_object_diag("dreamingwrt.ac",' in route
    assert '"station_events", params' in route
    assert "webd_ac_http_status(resp, status)" in route
    # Upstream rejection is a 400 with a diagnosable reason; only real
    # transport failures return 503.
    assert "diag.rc == UBUS_STATUS_INVALID_ARGUMENT" in route
    assert '"upstream_rejected_request"' in route
    assert "status = 400" in route
    assert "status = 503" in route
    assert "stage=%s rc=%d" in route
    assert "json_object_put(params)" in route


def test_query_parser_is_strict_allowlist() -> None:
    parser = between(
        WEB,
        "static struct json_object *webd_wifi_station_events_params(",
        "static struct json_object *webd_ac_radio_job_create_params",
    )
    for name in ("ap_id", "event", "start", "end", "after_id", "limit"):
        assert f'"{name}"' in parser
    assert "webd_ac_token_id_valid(value)" in parser
    assert '"connect"' in parser and '"disconnect"' in parser
    assert '"roam"' in parser
    assert "webd_wifi_parse_int64_strict" in parser
    assert "return NULL;" in parser
    assert "WEBD_WIFI_STATION_EVENTS_MAX_LIMIT" in parser
    assert "WEBD_WIFI_STATION_EVENTS_MAX_LIMIT 1024" in WEB
    assert "WEBD_WIFI_STATION_EVENTS_DEFAULT_LIMIT 256" in WEB
    assert "start > end" in parser


def test_capability_merge_declares_source_and_endpoint() -> None:
    merge = between(
        AGGREGATE,
        "void webd_wifi_merge_station_events_capability(",
        "struct json_object *webd_wifi_aggregate_data_with_resolver(",
    )
    assert '"station_event_store"' in merge
    assert '"connectivity_events", 1' in merge
    assert '"roaming_history", 1' in merge
    assert '"ac_snapshot_diff"' in merge
    assert '"/api/v1/wifi/connectivity/events"' in merge
    # Fail-closed default with pending reasons stays in the aggregate.
    assert '"wifi_connectivity_event_store_pending"' in AGGREGATE
    assert '"wifi_roaming_event_store_pending"' in AGGREGATE
    assert ("webd_wifi_merge_station_events_capability(data, ac_capabilities)"
            in WEB)


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"ok: {len(tests)} Wi-Fi connectivity events REST contracts")

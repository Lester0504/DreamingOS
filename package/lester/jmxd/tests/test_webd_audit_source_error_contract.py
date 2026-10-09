#!/usr/bin/env python3
"""The audit IM BFF must not turn a Core source error into HTTP 200 + []."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT.parent))
from jmxd.tests.webd_sources import webd_dispatch_text, webd_module_text
WEB = webd_dispatch_text()
API_UBUS = webd_module_text("api_ubus.c")


def function(text: str, name: str, next_name: str) -> str:
    start = text.index(name)
    return text[start:text.index(next_name, start)]


def test_raw_upstream_helper_preserves_error_envelope() -> None:
    helper = function(
        WEB,
        "static struct json_object *webd_insights_ubus_response_timeout(",
        "static struct json_object *webd_insights_ubus_data(",
    )
    assert "app_ubus_invoke_timeout(method, params, timeout_ms)" in helper
    assert "return upstream;" in helper


def test_im_records_maps_core_source_unavailable_to_503() -> None:
    body = function(
        WEB,
        "static struct json_object *webd_audit_im_records_response(",
        "static struct json_object *webd_audit_traffic_response(",
    )
    assert 'webd_insights_ubus_response_timeout("audit_view", NULL, 1800)' in body
    assert "if (!upstream)" in body
    assert 'webd_error("source_unavailable"' in body
    assert "app_response_status(upstream, 503)" in body
    assert "*http_status = app_response_status(upstream, 503)" in body
    assert "view = webd_data_or_self_from_jmx_response(upstream)" in body
    assert "json_object_put(upstream)" in body
    # The old data-only helper would discard code=4000 and build a successful
    # empty response; this route must no longer call it.
    assert 'webd_audit_fetch_view();' not in body


def test_raw_ubus_data_object_is_successful() -> None:
    helper = function(
        API_UBUS,
        "int app_ubus_response_ok(",
        "const char *app_ubus_response_error_code(",
    )
    assert "return json_object_is_type(upstream, json_type_object);" in helper


if __name__ == "__main__":
    test_raw_upstream_helper_preserves_error_envelope()
    test_im_records_maps_core_source_unavailable_to_503()
    test_raw_ubus_data_object_is_successful()
    print("ok: audit IM source errors remain observable and retryable")

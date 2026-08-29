#!/usr/bin/env python3
"""Flowd status bursts must not serialize across persistent WebD workers."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT.parent))
from jmxd.tests.webd_sources import webd_dispatch_text
WEB = webd_dispatch_text()


def between(start: str, end: str) -> str:
    offset = WEB.index(start)
    return WEB[offset:WEB.index(end, offset)]


def test_flowd_status_has_cross_worker_single_flight() -> None:
    body = between(
        "static struct json_object *webd_flowd_status_response(int *http_status)",
        "/* ═══ Policy Engine",
    )
    assert "WEBD_FLOWD_STATUS_SHARED_FRESH_MS 1000" in WEB
    assert "WEBD_FLOWD_STATUS_SHARED_STALE_MS 5000" in WEB
    assert "LOCK_EX | LOCK_NB" in body
    assert '"flowd_status_refresh_in_flight"' in body
    assert '"flowd_status_refresh_failed"' in body
    assert "webd_shared_json_write_locked" in body
    assert 'app_ubus_object_or_error("dreamingwrt.flowd", "status", NULL)' in body
    assert "webd_flowd_status_mark_cache" in body


def test_route_uses_shared_status_helper() -> None:
    route = between(
        'else if (!strcmp(req.path, "/api/v1/flowd/status")',
        'else if (!strcmp(req.path, "/api/v1/flowd/settings")',
    )
    assert "webd_flowd_status_response(&status)" in route
    assert "app_ubus_object_or_error" not in route


if __name__ == "__main__":
    test_flowd_status_has_cross_worker_single_flight()
    test_route_uses_shared_status_helper()
    print("ok: flowd status uses a one-second cross-worker single-flight snapshot")

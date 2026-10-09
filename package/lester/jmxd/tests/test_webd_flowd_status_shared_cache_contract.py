#!/usr/bin/env python3
"""Flowd status bursts must not serialize across persistent WebD workers."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT.parent))
from jmxd.tests.webd_sources import webd_dispatch_text, webd_function_text
WEB = webd_dispatch_text()


def test_flowd_status_has_cross_worker_single_flight() -> None:
    # webd_flowd_status_response moved into api_flowd.c in Phase 6E; read the
    # definition itself, not the module's forward declaration.
    body = webd_function_text("api_flowd.c", "webd_flowd_status_response")
    assert "WEBD_FLOWD_STATUS_SHARED_FRESH_MS 1000" in WEB
    assert "WEBD_FLOWD_STATUS_SHARED_STALE_MS 5000" in WEB
    assert "LOCK_EX | LOCK_NB" in body
    assert '"flowd_status_refresh_in_flight"' in body
    assert '"flowd_status_refresh_failed"' in body
    assert "webd_shared_json_write_locked" in body
    assert 'app_ubus_object_or_error("dreamingwrt.flowd", "status", NULL)' in body
    assert "webd_flowd_status_mark_cache" in body


def test_route_uses_shared_status_helper() -> None:
    # The legacy if-else branch became a route-table handler in Phase 6E. The
    # contract is unchanged: the /api/v1/flowd/status handler goes through the
    # shared single-flight helper, never straight to the ubus proxy.
    handler = webd_function_text("api_flowd.c", "flowd_status_get")
    assert "webd_flowd_status_response(&ctx->status)" in handler
    assert "app_ubus_object_or_error" not in handler


if __name__ == "__main__":
    test_flowd_status_has_cross_worker_single_flight()
    test_route_uses_shared_status_helper()
    print("ok: flowd status uses a one-second cross-worker single-flight snapshot")

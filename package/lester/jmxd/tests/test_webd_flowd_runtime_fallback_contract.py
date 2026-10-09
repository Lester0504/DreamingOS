#!/usr/bin/env python3
"""WebD flowd-runtime fallback must preserve producer truth."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT.parent))
from jmxd.tests.webd_sources import webd_function_text


def fallback_body() -> str:
    # webd_flowd_runtime_response moved into api_flowd.c in Phase 6E. Read its
    # definition directly (brace-matched, not sliced to an adjacent function
    # that no longer neighbours it) so the fallback contract still pins the body.
    return webd_function_text("api_flowd.c", "webd_flowd_runtime_response")


def test_fallback_carries_upstream_runtime_state() -> None:
    body = fallback_body()
    for field in (
        "worker_available",
        "runtime_db_present",
        "runtime_snapshot_available",
        "runtime_db_openable",
        "runtime_populated",
        "runtime_applied",
        "runtime_reason",
        "error",
        "capabilities",
    ):
        assert f'json_object_object_get_ex(upstream, "{field}"' in body
    assert "upstream_worker_available" in body
    assert "upstream_worker_known" in body
    assert "upstream_reason[0]" in body
    assert "upstream_error[0]" in body


def test_registered_worker_is_never_relabelled_as_unregistered() -> None:
    body = fallback_body()
    assert 'upstream_worker_known ? upstream_worker_available : 0' in body
    assert '"flowd worker is registered but runtime snapshot is unavailable; using core runtime read-only sources"' in body
    assert '"flowd worker is not registered; using core runtime read-only sources"' in body
    assert '"runtime_db_missing" : "flowd_worker_unavailable"' in body


def test_fallback_capabilities_fail_closed_and_reasons_stay_machine_readable() -> None:
    body = fallback_body()
    assert 'json_object_object_del(upstream_caps, "flow_engine_apply")' in body
    assert 'json_object_object_del(upstream_caps, "flow_engine_apply_ready")' in body
    assert 'json_object_object_del(upstream_caps, "flow_engine_runtime_readback")' in body
    assert 'json_object_object_add(reasons, "flow_engine_apply"' in body
    assert 'json_object_object_add(reasons, "flow_engine_runtime_readback"' in body
    assert 'json_object_new_boolean(0)' in body
    assert 'const char *cap_reason = upstream_error[0] ? upstream_error :' in body
    assert 'strcmp(upstream_reason, "runtime_state_missing")' in body
    assert '"flowd_worker_unavailable"' in body


if __name__ == "__main__":
    for name, test in sorted(globals().items()):
        if name.startswith("test_"):
            test()
    print("ok: webd runtime fallback preserves worker truth and fails closed")

#!/usr/bin/env python3
"""Bootstrap must aggregate flowd's truthful runtime capability contract."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT.parent))
from jmxd.tests.webd_sources import webd_dispatch_text, webd_function_text
WEBD = webd_dispatch_text()


def between(text: str, start: str, end: str) -> str:
    offset = text.index(start)
    return text[offset:text.index(end, offset)]


def test_bootstrap_uses_flowd_status_as_the_capability_source() -> None:
    start = WEBD.index("static void webd_apply_flowd_runtime_capabilities")
    end = WEBD.index("static void webd_apply_runtime_capabilities", start)
    helper = WEBD[start:end]

    assert 'app_ubus_invoke_object_timeout("dreamingwrt.flowd", "status", NULL, 300)' in helper
    assert 'jmx_cache_get("flowd_runtime_capabilities")' in helper
    assert 'jmx_cache_put("flowd_runtime_capabilities", status, 3)' in helper
    for field in (
        "flow_engine_read",
        "flow_engine_config_write",
        "flow_engine_apply",
        "flow_engine_runtime_readback",
        "flow_engine_capability_reasons",
        "flow_engine_runtime_contract_version",
    ):
        assert f'"{field}"' in helper


def test_missing_status_fails_closed_and_legacy_flags_mean_read_only() -> None:
    start = WEBD.index("static void webd_apply_flowd_runtime_capabilities")
    end = WEBD.index("static void webd_apply_runtime_capabilities", start)
    helper = WEBD[start:end]

    assert 'json_object_new_string("flowd_status_unavailable")' in helper
    assert 'json_object_new_boolean(supported)' in helper
    assert 'json_object_new_boolean(read_supported)' in helper
    assert "webd_json_array_remove_string(disabled_caps, names[i])" in helper
    assert 'webd_json_array_remove_string(disabled_caps, "flow_control")' in helper
    assert '"flow_control"' in helper
    assert '"flow_control_engine"' in helper
    assert "webd_apply_flowd_runtime_capabilities(capabilities, disabled_caps);" in WEBD


def test_runtime_get_keeps_registered_worker_contract_without_runtime_db() -> None:
    # webd_flowd_runtime_empty moved into api_flowd.c in Phase 6E. Read the
    # definition itself (not the module's forward declaration) so the worker/
    # available/db ordering is checked against the real body.
    helper = webd_function_text("api_flowd.c", "webd_flowd_runtime_empty")

    worker_check = helper.index(
        'json_object_object_get_ex(resp, "worker_available", &v)'
    )
    available_check = helper.index(
        'json_object_object_get_ex(resp, "available", &v)'
    )
    db_check = helper.index(
        'json_object_object_get_ex(resp, "runtime_db_present", &v)'
    )
    assert 'return !json_object_get_boolean(v);' in helper
    assert worker_check < available_check
    assert worker_check < db_check


if __name__ == "__main__":
    test_bootstrap_uses_flowd_status_as_the_capability_source()
    test_missing_status_fails_closed_and_legacy_flags_mean_read_only()
    test_runtime_get_keeps_registered_worker_contract_without_runtime_db()
    print("ok: bootstrap aggregates flowd capabilities and fails closed when status is unavailable")

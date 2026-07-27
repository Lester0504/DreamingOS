#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
API = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
INIT = (ROOT / "src/init/dreamingwrt_init.c").read_text(encoding="utf-8")


def test_top_level_status_aggregates_supervisor_and_native_worker_status():
    assert 'UBUS_METHOD("status", dw_handle_unified_status' in API
    assert '"status all --json --no-storage\\n"' in API
    assert 'DW_INIT_CONTROL_SOCKET "/var/run/dreamingwrt-init.sock"' in API
    for object_name in (
        "jmx_audit",
        "dreamingwrt.routed",
        "dreamingwrt.logd",
        "dreamingwrt.notifyd",
        "dreamingwrt.flowd",
        "dreamingwrt.otad",
        "dreamingwrt.aegis",
    ):
        assert f'"{object_name}"' in API
    assert 'dw_status_call_worker(workers[i].object, "status", 1000' in API
    assert "status_ctx = ubus_connect(NULL)" in API
    assert "ubus_invoke(status_ctx, id, method" in API


def test_status_reports_versions_datasets_and_explicit_degradation():
    for field in (
        '"contract_version"',
        '"config_schema_version"',
        '"core_api_version"',
        '"components"',
        '"datasets"',
        '"signatures"',
        '"storage"',
        '"unavailable"',
        '"critical_failure"',
    ):
        assert field in API
    assert 'jmx_signature_db_status(NULL)' in API
    assert 'dw_status_object_ok(status, 0)' in API
    assert 'dw_storage_status_json(0)' in API
    assert 'dw_json_get_bool(payload, "degraded", 0)' in API
    assert 'dw_json_get_string(status, "health", "unknown")' in API
    assert 'json_object_new_string(DWRT_INIT_VERSION)' not in INIT
    assert '\\"version\\": \\"%s\\"' in INIT
    assert 'emit_components_json(out, target, !no_storage)' in INIT


if __name__ == "__main__":
    test_top_level_status_aggregates_supervisor_and_native_worker_status()
    test_status_reports_versions_datasets_and_explicit_degradation()
    print("ok: top-level dreamingwrt status aggregates supervisor and worker health")

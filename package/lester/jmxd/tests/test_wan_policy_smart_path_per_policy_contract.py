#!/usr/bin/env python3
"""Static contract for named WAN policy Smart Path transactions."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT.parent))
from jmxd.tests.webd_sources import webd_dispatch_text
WEB = webd_dispatch_text()
FLOWD_UBUS = (ROOT / "src" / "flowd" / "flowd_ubus.c").read_text(encoding="utf-8")
FLOWD_RUNTIME = (ROOT / "src" / "flowd" / "flowd_qoe_runtime.c").read_text(encoding="utf-8")
ROUTE_DB = (ROOT / "src" / "routed" / "jmx_route_db.c").read_text(encoding="utf-8")


def body(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    return source[begin:source.index(end, begin)]


def test_versioned_read_write_surface_and_three_state_storage() -> None:
    collection = body(WEB, "static struct json_object *webd_wan_policies_collection_data(",
                      "static struct json_object *webd_wan_policies_route_error(")
    merge = body(WEB, "static int webd_wan_policy_merge_smart_path(",
                 "static int webd_wan_policy_merge_rule(")
    assert '"smart_path_scope"' in collection
    assert '"per_policy"' in collection
    assert '"explicit_policy_enabled_or_disabled_overrides_global;inherit_follows_global"' in collection
    assert '"wan-policies.smart-path.v1"' in collection
    assert '"smart_path"' in merge
    assert '"inherit"' in merge and '"enabled"' in merge and '"disabled"' in merge
    assert '"smart_path_mode"' in ROUTE_DB
    assert 'smart_path_mode TEXT NOT NULL DEFAULT \'inherit\'' in ROUTE_DB


def test_per_policy_runtime_is_scoped_by_priority_and_reconcile_is_registered() -> None:
    helper = body(WEB, "static int webd_wan_policy_smart_runtime_matches(",
                  "static struct json_object *webd_wan_policies_runtime_error(")
    handler = body(WEB, "static struct json_object *webd_wan_policies_response(",
                    "static int webd_wan_policy_has_extended_fields(")
    assert '"policy_runtime"' in helper
    assert 'app_nc_json_int(item, "prio", 0) == target_prio' in helper
    assert '"reconcile_ok"' in helper
    assert '"runtime_applied"' in helper
    assert 'app_ubus_invoke_object_timeout(\n        "dreamingwrt.flowd", "smart_path_reconcile"' in handler
    assert '"smart_path_reconciled"' in handler
    assert '"smart_path_runtime"' in handler
    assert 'UBUS_METHOD("smart_path_reconcile"' in FLOWD_UBUS
    assert 'flowd_qoe_reconcile_json()' in FLOWD_UBUS
    assert '"policy_runtime"' in FLOWD_RUNTIME


def test_write_is_snapshot_apply_reconcile_and_compensating_rollback() -> None:
    handler = body(WEB, "static struct json_object *webd_wan_policies_response(",
                    "static int webd_wan_policy_has_extended_fields(")
    error = body(WEB, "static struct json_object *webd_wan_policies_runtime_error(",
                 "static const char *webd_wan_policies_request_revision(")
    assert 'previous_config = webd_json_clone(config_data)' in handler
    assert 'app_ubus_invoke("route_config_set", config)' in handler
    assert 'app_ubus_invoke("route_config_set", previous_config)' in handler
    assert handler.index('previous_config = webd_json_clone(config_data)') < handler.index(
        'app_ubus_invoke("route_config_set", config)')
    assert handler.index('app_ubus_invoke("route_config_set", config)') < handler.index(
        'app_ubus_invoke_object_timeout(\n        "dreamingwrt.flowd", "smart_path_reconcile"')
    assert '"failure_stage"' in error
    assert '"smart_path_rollback_ok"' in WEB
    assert '"route_rollback_ok"' in WEB
    assert '"existing_connections"' in WEB
    assert '"new_connections_only"' in WEB
    assert '"runtime_apply_failed"' in WEB
    assert '"executor_unavailable"' in WEB


def test_failure_response_does_not_claim_new_config_is_canonical() -> None:
    error = body(WEB, "static struct json_object *webd_wan_policies_runtime_error(",
                 "static const char *webd_wan_policies_request_revision(")
    assert 'json_object_new_boolean(0)' in error
    assert '"configured"' in error and '"effective"' in error
    assert '"rollback_attempted"' in error
    assert '"previous_config_restored"' in error
    assert '"readback_unconfirmed"' in error


if __name__ == "__main__":
    for name, test in sorted(globals().items()):
        if name.startswith("test_"):
            test()
            print(f"PASS {name}")
    print("ok: named WAN policy Smart Path per-policy transaction contract")

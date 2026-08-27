#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")
CORE = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
ROUTED = (ROOT / "src/routed/routed_control.c").read_text(encoding="utf-8")
TX = (ROOT / "src/routed/gateway_ports.c").read_text(encoding="utf-8")
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text(encoding="utf-8")


def section(text: str, start: str, end: str) -> str:
    pos = text.index(start)
    return text[pos:text.index(end, pos)]


def function(text: str, signature: str) -> str:
    start = text.index(signature)
    brace = text.index("{", start)
    depth = 0
    for pos in range(brace, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[brace:pos + 1]
    raise AssertionError(f"unterminated function: {signature}")


def test_core_executor_keeps_atomic_runtime_rollback() -> None:
    apply = section(
        DB,
        "struct json_object *jmx_netconfig_gateway_ports_apply(",
        "int jmx_netconfig_physical_port_refresh(",
    )
    for token in (
        'nc_json_bool_def(payload, "confirm", 0)',
        'nc_backup_config("network"',
        'nc_exec("BEGIN IMMEDIATE")',
        "UPDATE wan SET device=?2",
        "DELETE FROM lan_port WHERE port=?1",
        "INSERT INTO lan_port",
        "nc_apply_lan_ports(ctx, netpkg",
        'jmx_uci_commit(ctx, "network")',
        "nc_gateway_runtime_object_exists(plan.management_lan)",
        'nc_restore_config("network", bak_network)',
        'nc_exec("ROLLBACK")',
        "jmx_netconfig_gateway_ports_get()",
    ):
        assert token in apply


def test_core_plan_rejects_ambiguous_or_unsafe_ownership() -> None:
    plan = section(
        DB,
        "static int nc_gateway_port_plan_build(",
        "static struct json_object *nc_gateway_port_plan_response(",
    )
    for error in (
        "assignments_object_required",
        "enabled_wan_requires_port",
        "unknown_physical_port",
        "unknown_wan",
        "physical_port_assigned_twice",
        "displaced_wan_port_requires_bridge_lan",
        "bridge_lan_would_have_no_ports",
        "management_bridge_lan_missing",
    ):
        assert error in plan


def test_v2_preview_and_commit_share_normalized_plan() -> None:
    preview = function(TX, "static struct json_object *gp_preview_internal(")
    apply = function(TX, "struct json_object *gateway_ports_apply(")
    assert "normalized = gp_normalized_request(snapshot, body)" in preview
    assert "gp_plan_digest(snapshot->revision, normalized, changes, digest)" in preview
    assert '"plan", json_object_get(normalized)' in preview
    assert '"expected_revision"' in preview
    assert '"state_digest"' in preview
    for token in (
        '"expected_revision_required"',
        '"plan_digest_required"',
        '"confirmation_required"',
        '"revision_conflict"',
        '"plan_conflict"',
        "gp_preview_internal(submitted_plan, &before, &normalized)",
        "gp_assignments_equal(expected_assignments, actual_assignments)",
        "gp_compensate(&before, actual_assignments, &rollback)",
        '"runtime_readback_and_rollback_failed"',
        "current.revision != before.revision",
        "strcmp(current.state_digest, before.state_digest)",
    ):
        assert token in apply


def test_compensation_requires_apply_and_authoritative_readback() -> None:
    compensate = function(TX, "static int gp_compensate(")
    assert "gp_response_applied(apply)" in compensate
    assert "gp_assignments_equal(before->assignments, actual)" in compensate
    assert '"verified"' in compensate
    assert "core_gateway_port_executor_unavailable" in TX
    caps = function(TX, "static struct json_object *gp_capabilities(")
    assert '"gateway_port_assignment_atomic_apply"' in caps
    assert "json_object_new_boolean(executor_available)" in caps


def test_rest_routed_permissions_csrf_and_audit_are_wired() -> None:
    for method in ("gateway_ports_get", "gateway_ports_preview", "gateway_ports_apply"):
        assert f'UBUS_METHOD("{method}"' in CORE
        assert f'ROUTED_METHOD("{method}")' in ROUTED
        assert f'app_routed_call("{method}"' in WEB
    assert '"/api/v1/network/gateway-ports/apply", "POST,PUT", JMX_RISK_HIGH' in PERMS
    assert '!strncmp(req.path, "/api/v1/network/gateway-ports", 29)' in WEB
    assert '"network.gateway_ports.apply", "high"' in WEB
    assert "webd_topology_infrastructure_cache_invalidate();" in WEB


def test_vlan_task_is_persisted_before_live_mutation() -> None:
    config_apply = section(
        WEB,
        "struct json_object *jmx_config_apply(",
        "struct json_object *jmx_config_confirm(",
    )
    assert config_apply.index("INSERT INTO config_apply_tasks") < config_apply.index(
        "webd_port_manager_apply_network_transaction("
    )
    assert "webd_network_config_restore(snapshot_path" in config_apply


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"ok: {len(tests)} gateway port v2 transaction tests")

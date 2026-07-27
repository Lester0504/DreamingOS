#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DB = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")
CORE = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text(encoding="utf-8")


def section(text: str, start: str, end: str) -> str:
    pos = text.index(start)
    return text[pos:text.index(end, pos)]


def test_core_owns_atomic_assignment_transaction() -> None:
    apply = section(
        DB,
        "struct json_object *jmx_netconfig_gateway_ports_apply(",
        "int jmx_netconfig_physical_port_refresh(",
    )
    assert 'nc_json_bool_def(payload, "confirm", 0)' in apply
    assert 'nc_gateway_port_plan_response(payload, &plan)' in apply
    assert 'nc_backup_config("network"' in apply
    assert 'nc_exec("BEGIN IMMEDIATE")' in apply
    assert 'UPDATE wan SET device=?2' in apply
    assert 'DELETE FROM lan_port WHERE port=?1' in apply
    assert 'INSERT INTO lan_port' in apply
    assert 'nc_apply_lan_ports(ctx, netpkg' in apply
    assert 'jmx_uci_commit(ctx, "network")' in apply
    assert 'nc_reload_network_stack(0, 0, "/tmp/dw-gateway-port-apply.log")' in apply
    assert 'nc_gateway_runtime_object_exists(plan.management_lan)' in apply
    assert 'nc_restore_config("network", bak_network)' in apply
    assert 'nc_exec("ROLLBACK")' in apply
    assert '"rolled_back"' in apply
    assert 'jmx_netconfig_gateway_ports_get()' in apply


def test_plan_rejects_ambiguous_or_unsafe_ownership() -> None:
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
    assert "jmx_netconfig_physical_port_refresh()" in plan
    assert "nc_gateway_port_exists(new_device)" in plan


def test_rest_ubus_permissions_csrf_and_audit_are_wired() -> None:
    for method in ("gateway_ports_get", "gateway_ports_preview", "gateway_ports_apply"):
        assert f'UBUS_METHOD("{method}"' in CORE
        assert f'app_ubus_invoke_timeout("{method}"' in WEB
    assert '"/api/v1/network/gateway-ports/apply", "POST,PUT", JMX_RISK_HIGH' in PERMS
    assert '"/api/v1/topology/node/ports/batch/apply",   "POST,PUT", JMX_RISK_MEDIUM' in PERMS
    assert '!strncmp(req.path, "/api/v1/network/gateway-ports", 29)' in WEB
    assert '"network.gateway_ports.apply", "high"' in WEB
    assert '"gateway_port_assignment_atomic_apply", json_object_new_boolean(1)' in WEB
    assert "webd_topology_ports_cache_invalidate" not in WEB
    assert "webd_topology_infrastructure_cache_invalidate();" in WEB


def test_vlan_task_is_persisted_before_live_mutation() -> None:
    config_apply = section(
        WEB,
        "struct json_object *jmx_config_apply(",
        "struct json_object *jmx_config_confirm(",
    )
    insert = config_apply.index("INSERT INTO config_apply_tasks")
    mutate = config_apply.index("webd_port_manager_apply_network_transaction(")
    assert insert < mutate
    assert 'state=\'failed\'' in config_apply
    assert "webd_network_config_restore(snapshot_path" in config_apply


if __name__ == "__main__":
    test_core_owns_atomic_assignment_transaction()
    test_plan_rejects_ambiguous_or_unsafe_ownership()
    test_rest_ubus_permissions_csrf_and_audit_are_wired()
    test_vlan_task_is_persisted_before_live_mutation()
    print("ok: gateway port assignment, RBAC, rollback, and VLAN task ordering contracts")

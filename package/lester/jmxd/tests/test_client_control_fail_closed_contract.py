#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
CORE = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text(encoding="utf-8")


def body(text: str, start: str, end: str) -> str:
    begin = text.index(start)
    finish = text.index(end, begin)
    return text[begin:finish]


def test_unsupported_scopes_are_rejected_before_db_open() -> None:
    validate = body(
        WEB,
        "static struct json_object *webd_client_control_validate_write",
        "static void webd_control_rule_add_runtime_contract",
    )
    for token in (
        '"control_type", "client_control_rate_limit"',
        '"limit_mode", "client_control_shared_rate_limit"',
        '"line", "client_control_line_runtime"',
        '"protocol", "client_control_protocol_runtime"',
        '"schedule_mode", "client_control_schedule_plan"',
    ):
        assert token in validate
    assert 'webd_client_control_write_error("capability_disabled"' in validate

    upsert = body(
        WEB,
        "static struct json_object *webd_client_control_rule_upsert_response",
        "static struct json_object *webd_client_control_rule_toggle_response",
    )
    assert upsert.index("webd_client_control_validate_write") < upsert.index("app_db_open_runtime")
    assert upsert.index("webd_client_control_validate_write") < upsert.index("INSERT INTO client_control_rules")


def test_errors_cannot_be_interpreted_as_frontend_success() -> None:
    error = body(
        WEB,
        "static struct json_object *webd_client_control_write_error",
        "static struct json_object *webd_client_control_validate_write",
    )
    for token in (
        'webd_error(code, message',
        '"persisted", json_object_new_boolean(0)',
        '"applied", json_object_new_boolean(0)',
        '"changed", json_object_new_boolean(0)',
        '"field"',
        '"capability"',
        '"reason"',
    ):
        assert token in error
    assert "*status = http_status" in error


def test_invalid_identity_and_ownership_rejections_use_zero_write_contract() -> None:
    upsert = body(
        WEB,
        "static struct json_object *webd_client_control_rule_upsert_response",
        "static struct json_object *webd_client_control_rule_toggle_response",
    )
    toggle = body(
        WEB,
        "static struct json_object *webd_client_control_rule_toggle_response",
        "static struct json_object *webd_client_control_rule_delete_response",
    )
    delete = body(
        WEB,
        "static struct json_object *webd_client_control_rule_delete_response",
        "static struct json_object *webd_client_profile_response",
    )
    for handler in (upsert, toggle, delete):
        assert '"invalid_argument"' in handler
        assert '"invalid_client_mac"' in handler
        assert "webd_client_control_write_error" in handler
    for handler in (upsert, toggle, delete):
        assert '"client_control_rule_ownership"' in handler
        assert '"rule_not_owned_by_client"' in handler


def test_supported_write_reports_runtime_truth() -> None:
    upsert = body(
        WEB,
        "static struct json_object *webd_client_control_rule_upsert_response",
        "static struct json_object *webd_client_control_rule_toggle_response",
    )
    for token in (
        '"persisted", json_object_new_boolean(schedule_tick_ok && (!enabled || runtime_apply))',
        '"applied", json_object_new_boolean(runtime_apply)',
        '"runtime_apply_failed"',
        '"schedule_worker_unavailable"',
        '"runtime_scope", "client_mac_on_lan_bridge"',
        '"client_mac_and_l4_protocol"',
    ):
        assert token in upsert
    assert 'json_object_object_add(resp, "ok", json_object_new_boolean(0))' in upsert
    assert "webd_client_control_rule_snapshot" in upsert
    assert "webd_client_control_rule_restore_snapshot" in upsert


def test_resource_ownership_is_mac_and_rule_id() -> None:
    upsert = body(
        WEB,
        "static struct json_object *webd_client_control_rule_upsert_response",
        "static struct json_object *webd_client_control_rule_toggle_response",
    )
    toggle = body(
        WEB,
        "static struct json_object *webd_client_control_rule_toggle_response",
        "static struct json_object *webd_client_control_rule_delete_response",
    )
    delete = body(
        WEB,
        "static struct json_object *webd_client_control_rule_delete_response",
        "static struct json_object *webd_client_profile_response",
    )
    needle = "WHERE id=?1 AND mac=?2"
    assert needle in upsert
    assert needle in toggle
    assert delete.count(needle) >= 2
    assert '"rule_not_found"' in upsert and '"rule_not_found"' in toggle and '"rule_not_found"' in delete


def test_toggle_allows_cleanup_but_blocks_reenable_of_legacy_unsupported_rules() -> None:
    toggle = body(
        WEB,
        "static struct json_object *webd_client_control_rule_toggle_response",
        "static struct json_object *webd_client_control_rule_delete_response",
    )
    assert "if (enabled)" in toggle
    assert "webd_client_control_validate_write(stored" in toggle
    assert toggle.index("if (enabled)") < toggle.index("UPDATE client_control_rules SET enabled")
    assert "webd_client_control_rule_snapshot" in toggle
    assert "webd_client_control_rule_restore_snapshot" in toggle


def test_core_scheduler_cannot_reanimate_degraded_legacy_rules() -> None:
    scheduler = body(CORE, "int jmx_client_control_schedule_tick", "/* ═══ Flash / Firmware Operations")
    for token in (
        "runtime_supported",
        "line_scoped_client_rate_limit_not_implemented",
        "shared_rate_limit_dataplane_not_implemented",
        "unsupported_l4_protocol",
        "nc_rate_limit_protocol_id(r->protocol) < 0",
    ):
        assert token in scheduler
    assert "!rows[i].runtime_supported" in scheduler


def test_rate_limit_dataplane_has_no_unknown_protocol_fallback() -> None:
    proto = body(CORE, "static int nc_rate_limit_protocol_id", "static void nc_rate_limit_emit_filter")
    apply = body(CORE, "static int nc_rate_limit_apply_all", "int nc_client_rate_limit_set_ex")
    setter = body(CORE, "int nc_client_rate_limit_set_ex", "int nc_client_rate_limit_set(")
    assert "return -1;" in proto
    assert "if (proto_id < 0) continue;" in apply
    assert "nc_rate_limit_protocol_id(protocol) < 0" in setter


def test_rate_limit_dataplane_restores_owned_hooks_and_keeps_icmp_families_exact() -> None:
    emit = body(CORE, "static void nc_rate_limit_emit_filter", "static void nc_rate_limit_emit_runtime_cleanup")
    cleanup = body(CORE, "static void nc_rate_limit_emit_runtime_cleanup", "static int nc_rate_limit_apply_all")
    apply = body(CORE, "static int nc_rate_limit_apply_all", "int nc_client_rate_limit_set_ex")
    assert "proto == NC_RATE_LIMIT_PROTO_ICMPV6" in emit
    assert "proto == NC_RATE_LIMIT_PROTO_ICMP || proto == NC_RATE_LIMIT_PROTO_ICMPV6" not in emit
    for token in (
        "LAN_CLSACT_OWNED",
        "IFB_EXISTED",
        "IFB_WAS_UP",
        'rm -f \\"$STATE_FILE\\"',
    ):
        assert token in cleanup
    assert "NC_RATE_LIMIT_STATE_FILE" in apply
    assert "LAN_ROOT" in apply and "IFB_ROOT" in apply
    first_ownership = apply[
        apply.index('if [ ! -r \\"$STATE_FILE\\" ]'):
        apply.index('else\\n', apply.index('if [ ! -r \\"$STATE_FILE\\" ]'))
    ]
    assert "modprobe ifb" not in first_ownership
    assert 'ip link show \\"$IFB_DEV\\" >/dev/null 2>&1; then' in first_ownership
    assert 'tc filter show dev \\"$IFB_DEV\\"' in first_ownership
    assert 'ingress pref %d' in first_ownership
    assert "exit 13" in first_ownership
    assert "set -eu" in apply
    assert "CLEANUP_CONFLICT" in cleanup
    assert cleanup.index("CLEANUP_CONFLICT") < cleanup.index("tc qdisc del dev")
    assert 'qdisc htb 1:' in cleanup and 'qdisc htb 2:' in cleanup
    assert "exit 15" in cleanup
    assert cleanup.index("CLEANUP_CONFLICT") < cleanup.index("tc filter del dev")
    assert "nc_rate_limit_emit_runtime_cleanup(fp)" in apply


def test_rate_limit_runtime_files_are_transactional() -> None:
    setter = body(CORE, "int nc_client_rate_limit_set_ex", "int nc_client_rate_limit_set(")
    delete = body(CORE, "int nc_client_rate_limit_delete", "/* ═══ Client Control Rule Schedule Runtime")
    for handler in (setter, delete):
        assert "rollback_path" in handler
        assert '"%s/.rollback-%s-%ld"' in handler
        assert "rename(fpath, rollback_path)" in handler
        assert "rename(rollback_path, fpath)" in handler
        assert "nc_rate_limit_apply_all()" in handler


def test_profile_capabilities_are_split_by_maturity() -> None:
    profile = body(
        WEB,
        'json_object_object_add(cap, "client_control_rule_api"',
        'json_object_object_add(cap, "bandwidth_history"',
    )
    for token in (
        '"client_control_fail_closed", json_object_new_boolean(1)',
        '"client_control_rate_limit", json_object_new_boolean(1)',
        '"client_control_l4_filter", json_object_new_boolean(1)',
        '"client_control_l4_filter_action", json_object_new_string("rate_limit_only")',
        '"client_control_app_policy", json_object_new_boolean(0)',
        '"client_control_wan_policy", json_object_new_boolean(0)',
        '"client_control_shared_rate_limit", json_object_new_boolean(0)',
        '"client_control_schedule_plan", json_object_new_boolean(0)',
    ):
        assert token in profile


def test_independent_protocol_control_remains_zero_write_unsupported() -> None:
    helper = body(
        WEB,
        "static struct json_object *webd_client_protocol_control_response",
        "#define WEBD_INSIGHTS_FILTER_FIELDS_MAX",
    )
    assert "*status = 501" in helper
    assert '"ok", json_object_new_boolean(0)' in helper
    assert '"protocol_control", json_object_new_boolean(0)' in helper
    for forbidden in ("config_prepare", "sqlite3_step", "app_ubus_call_ok"):
        assert forbidden not in helper


def test_client_control_writes_have_explicit_admin_risk() -> None:
    assert '{ "/api/v1/client_control_rule", "POST,PUT,PATCH,DELETE", JMX_RISK_MEDIUM }' in PERMS
    assert '{ "/api/v1/client_protocol_control", "POST,PUT,PATCH,DELETE", JMX_RISK_MEDIUM }' in PERMS


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_")]
    for test in tests:
        test()
    print(f"ok: {len(tests)} client-control fail-closed contract tests")

#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DB = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")
CORE = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
COMMON = (ROOT / "src/jmx_ubus.c").read_text(encoding="utf-8")
WEBD = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")


def section(text: str, start: str, end: str) -> str:
    pos = text.index(start)
    return text[pos:text.index(end, pos)]


def test_capabilities_match_runtime_consumers() -> None:
    caps = section(DB, "static void nc_upnp_add_caps(",
                   "static int nc_upnp_parse_port_range(")
    for name in (
        "mapping_create", "mapping_update", "mapping_delete",
        "save_upnp_mapping", "delete_upnp_mapping",
        "static_mapping_apply", "static_mapping_readback", "live_packets",
    ):
        assert f'"{name}", json_object_new_boolean(0)' in caps
    assert '"service_update", json_object_new_boolean(has)' in caps
    assert '"acl_create", json_object_new_boolean(has)' in caps
    assert '"mapping_type", json_object_new_string("dynamic")' in DB
    assert '"mapping_type", json_object_new_string("static")' in DB


def test_service_partial_merge_and_validation() -> None:
    save = section(DB, "int jmx_upnp_service_set(",
                   "int jmx_upnp_service_apply(")
    assert 'SELECT enabled,natpmp_enabled,secure_mode,external_iface' in save
    assert 'json_object_object_get_ex(cfg, "internal_ifaces", &arr)' in save
    assert 'json_object_array_length(arr) > 32' in save
    assert 'SELECT 1 FROM wan WHERE id=?1 OR ifname=?1' in save
    assert 'SELECT 1 FROM lan WHERE id=?1' in save
    assert 'nc_upnp_disabled_field_changed(cfg, NULL, NULL, NULL)' in save
    assert 'nc_upnp_import_uci_once()' in DB
    assert "upnp_migration_state" in DB
    assert 'nc_upnp_parse_acl_port_range(ext' in DB
    unconditional = 'if (rc == 0 && nc_prepare(&st, "DELETE FROM upnp_internal_iface'
    assert unconditional not in save


def test_apply_checks_uci_reload_and_rolls_back() -> None:
    apply = section(DB, "int jmx_upnp_service_apply(",
                    "static struct json_object *nc_upnp_result(")
    assert 'nc_uci_delete_managed_sections(ctx,pkg,"upnpd","perm_rule","")' in apply
    assert 'jmx_uci_commit(ctx, "upnpd") != UCI_OK' in apply
    assert 'nc_run_quiet("/etc/init.d/miniupnpd reload' in apply
    assert 'nc_restore_config("upnpd", bak)' in apply
    assert 'dw-upnp-rollback.log' in apply
    assert '"external_iface"' in apply
    assert '"ext_iface"' not in apply
    assert '"enable_pcp"' not in apply
    assert 'clean_interval' not in apply
    assert 'force_forwarding' not in apply
    assert 'port_start' not in apply
    assert 'port_end' not in apply
    assert 'use_stun' not in apply
    assert 'stun_host' not in apply
    assert 'stun_port' not in apply
    assert 'upnp_lease_file' not in apply
    assert 'model_number' not in apply
    assert '* 128' in apply
    get = section(DB, "struct json_object *jmx_upnp_service_get(",
                  "int jmx_upnp_acl_set(")
    assert 'nc_upnp_update_mapping_packets();' not in get
    assert '"sort_order", json_object_new_int(sqlite3_column_int(st, 7))' in get


def test_service_and_acl_return_authoritative_results() -> None:
    assert 'jmx_upnp_service_save_apply_result' in CORE
    assert 'jmx_upnp_acl_save_apply_result' in CORE
    assert 'jmx_upnp_acl_delete_apply_result' in CORE
    assert '"runtime_rolled_back"' in DB
    assert '"persisted"' in DB
    assert '"readback"' in DB
    assert 'changed == 1' in section(DB, "int jmx_upnp_acl_delete(",
                                     "int jmx_upnp_mapping_delete(")
    assert 'app_ubus_invoke_timeout("upnp_service_set", body_json, 20000)' in WEBD
    assert 'app_ubus_invoke_timeout("upnp_acl_set", body_json, 20000)' in WEBD
    assert 'app_ubus_invoke_timeout("upnp_acl_delete", params, 20000)' in WEBD
    common_service = section(COMMON,
                             "static struct json_object *jmx_api_upnp_service_set(",
                             "static struct json_object *jmx_api_upnp_acl_set(")
    common_acl = section(COMMON,
                         "static struct json_object *jmx_api_upnp_acl_set(",
                         "static struct json_object *jmx_api_upnp_mapping_delete(")
    assert 'return jmx_upnp_service_save_apply_result(req_obj);' in common_service
    assert 'jmx_upnp_service_set(req_obj)' not in common_service
    assert 'return jmx_upnp_acl_save_apply_result(req_obj);' in common_acl
    assert 'return jmx_upnp_acl_delete_apply_result(id);' in common_acl
    assert 'jmx_upnp_service_apply()' not in common_acl


def test_disabled_service_fields_fail_closed_before_write() -> None:
    gate = section(DB, "static int nc_upnp_disabled_field_changed(",
                   "int jmx_upnp_service_set(")
    transaction = section(DB,
                          "struct json_object *jmx_upnp_service_save_apply_result(",
                          "struct json_object *jmx_upnp_acl_save_apply_result(")
    save = section(DB, "int jmx_upnp_service_set(",
                   "int jmx_upnp_service_apply(")
    response = section(DB, "static struct json_object *nc_upnp_capability_error(",
                       "static struct json_object *nc_upnp_snapshot_data(")
    for field in (
        "port_range", "port_start", "port_end", "clean_interval",
        "force_forwarding",
        "use_stun", "stun_host", "stun_port", "pcp",
        "lease_file", "uuid", "model_name",
    ):
        assert f'\"{field}\"' in gate
    assert 'nc_upnp_disabled_field_changed(cfg, &field, &capability, &reason)' in transaction
    assert 'if (gate > 0)' in transaction
    assert 'return nc_upnp_capability_error(field, capability, reason);' in transaction
    assert 'nc_upnp_disabled_field_changed(cfg, NULL, NULL, NULL)' in save
    update = next(line for line in save.splitlines()
                  if 'UPDATE upnp_service SET enabled=' in line)
    for field in (
        "port_start", "port_end", "clean_interval",
        "force_forwarding", "use_stun", "stun_host",
        "stun_port", "pcp", "lease_file", "uuid", "model_name",
    ):
        assert field not in update
    for token in (
        '"error", json_object_new_string("capability_disabled")',
        '"field"', '"capability"', '"reason"', '"field_results"',
        '"persisted", json_object_new_boolean(0)',
        '"applied", json_object_new_boolean(0)',
    ):
        assert token in response
    assert 'jmx_upnp_service_get()' not in response
    assert '"service_fail_closed", json_object_new_boolean(1)' in DB
    assert '"service_field_results", json_object_new_boolean(1)' in DB
    ai_dispatch = section(DB, "static struct json_object *nc_ai_tool_dispatch(",
                          "static struct json_object *nc_ai_tool_dispatch_redacted(")
    assert 'return jmx_upnp_service_save_apply_result(params);' in ai_dispatch
    assert 'jmx_upnp_service_set(params)' not in ai_dispatch


def test_static_mapping_writes_are_blocked_everywhere() -> None:
    mapping_delete = section(DB, "int jmx_upnp_mapping_delete(",
                             "int jmx_upnp_service_set(")
    mapping_set = section(DB, "int jmx_upnp_mapping_set(",
                          "/* ── Advanced Routing CRUD ── */")
    assert 'return -3' in mapping_delete
    assert 'return -3' in mapping_set
    assert WEBD.count('"upnp_static_mapping_unsupported"') >= 2
    assert 'app_ubus_ok_only("upnp_mapping_set"' not in WEBD
    assert 'app_ubus_ok_only("upnp_mapping_delete"' not in WEBD


if __name__ == "__main__":
    test_capabilities_match_runtime_consumers()
    test_service_partial_merge_and_validation()
    test_apply_checks_uci_reload_and_rolls_back()
    test_service_and_acl_return_authoritative_results()
    test_disabled_service_fields_fail_closed_before_write()
    test_static_mapping_writes_are_blocked_everywhere()
    print("ok: UPnP service, ACL, apply, rollback, and mapping capability contracts")

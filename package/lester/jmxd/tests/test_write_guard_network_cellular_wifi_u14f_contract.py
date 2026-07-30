#!/usr/bin/env python3
import importlib.util
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")


def function(name: str) -> str:
    signature = f"static int {name}("
    start = SOURCE.index(signature)
    brace = SOURCE.index("{", start)
    depth = 0
    for index in range(brace, len(SOURCE)):
        if SOURCE[index] == "{":
            depth += 1
        elif SOURCE[index] == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[start:index + 1]
    raise AssertionError(f"unterminated function: {name}")


MIGRATED = {
    "dw_handle_hybrid_line_save": "jmx_netconfig_hybrid_line_set(payload)",
    "dw_handle_wan_set": "jmx_netconfig_wan_set(payload)",
    "dw_handle_hybrid_line_add": "jmx_netconfig_hybrid_line_set(payload)",
    "dw_handle_hybrid_line_delete": "jmx_netconfig_hybrid_line_delete(id)",
    "dw_handle_hybrid_line_enable": "jmx_netconfig_hybrid_line_enable(id, enabled)",
    "dw_handle_wan_enable": "jmx_netconfig_wan_set_enabled(id, enabled)",
    "dw_handle_lan_enable": "jmx_netconfig_lan_set_enabled(id, enabled)",
    "dw_handle_wan_config_save": "jmx_netconfig_wan_save_apply_result(payload)",
    "dw_handle_wan_config_delete": "jmx_netconfig_wan_delete_result(id)",
    "dw_handle_wan_delete": "jmx_netconfig_wan_delete(id)",
    "dw_handle_lan_set": "jmx_netconfig_lan_set(payload)",
    "dw_handle_lan_config_save": "jmx_netconfig_lan_save_apply_result(payload)",
    "dw_handle_lan_delete": "jmx_netconfig_lan_delete_result(id, management_client_ip)",
    "dw_handle_lan_set_ports": "jmx_netconfig_lan_set_ports(id, ports)",
    "dw_handle_physical_port_config_apply": "jmx_netconfig_physical_port_config_apply(payload)",
    "dw_handle_gateway_ports_apply": "jmx_netconfig_gateway_ports_apply(payload)",
    "dw_handle_physical_port_profile_set": "jmx_netconfig_physical_port_profile_set(payload)",
    "dw_handle_physical_port_profile_delete": "jmx_netconfig_physical_port_profile_delete(id)",
    "dw_handle_radius_set": "jmx_netconfig_radius_set(payload)",
    "dw_handle_radius_delete": "jmx_netconfig_radius_delete(id)",
    "dw_handle_network_batch": "jmx_netconfig_wan_batch_apply(payload, management_client_ip)",
    "dw_handle_wan_apply": "jmx_netconfig_apply_wan(id)",
    "dw_handle_lan_apply": "jmx_netconfig_apply_lan(id)",
    "dw_handle_cellular_service_set": "jmx_cellular_service_set(payload)",
    "dw_handle_cellular_service_apply": "jmx_cellular_service_apply(dry_run)",
    "dw_handle_cellular_slot_set": "jmx_cellular_slot_set(payload)",
    "dw_handle_cellular_slot_delete": "jmx_cellular_slot_delete(id)",
    "dw_handle_cellular_apn_profile_set": "jmx_cellular_apn_profile_set(payload)",
    "dw_handle_cellular_apn_profile_delete": "jmx_cellular_apn_profile_delete(id)",
    "dw_handle_cellular_sms_delete": "jmx_cellular_sms_delete(id)",
    "dw_handle_wifi_config_save": "jmx_wifi_config_save(payload)",
    "dw_handle_wifi_config_apply": "jmx_wifi_config_apply(payload)",
}


def test_each_handler_guards_before_business_or_side_effect_calls() -> None:
    for handler, first_business_call in MIGRATED.items():
        code = function(handler)
        guard = code.index("dw_parse_write_payload(")
        business = code.index(first_business_call)
        assert guard < business, handler
        assert not re.search(r"\bjmx_[A-Za-z0-9_]+\s*\(", code[:guard]), handler
        assert "json_tokener_parse(" not in code, handler
        assert "blobmsg_format_json(" not in code, handler


def test_wrapped_business_fields_are_read_from_payload() -> None:
    expected = {
        "dw_handle_wan_set": 'dw_json_get_string(payload, "id", "")',
        "dw_handle_hybrid_line_add": 'dw_json_get_string(payload, "parent"',
        "dw_handle_hybrid_line_delete": 'dw_json_get_string(payload, "id", "")',
        "dw_handle_hybrid_line_enable": 'dw_json_get_int(payload, "enabled", 1)',
        "dw_handle_wan_enable": 'dw_json_get_int(payload, "enabled", 1)',
        "dw_handle_lan_enable": 'dw_json_get_int(payload, "enabled", 1)',
        "dw_handle_wan_config_delete": 'dw_json_get_string(payload, "id", "")',
        "dw_handle_wan_delete": 'dw_json_get_string(payload, "id", "")',
        "dw_handle_lan_delete": 'dw_json_get_string(payload, "management_client_ip", "")',
        "dw_handle_lan_set_ports": 'json_object_object_get_ex(payload, "ports", &ports)',
        "dw_handle_physical_port_profile_delete": 'dw_json_get_string(payload, "id", "")',
        "dw_handle_radius_delete": 'dw_json_get_string(payload, "id", "")',
        "dw_handle_network_batch": 'dw_json_get_string(payload, "management_client_ip", "")',
        "dw_handle_wan_apply": 'dw_json_get_string(payload, "id", "")',
        "dw_handle_lan_apply": 'dw_json_get_string(payload, "id", "")',
        "dw_handle_cellular_service_apply": 'json_object_object_get_ex(payload, "dry_run", &v)',
        "dw_handle_cellular_slot_delete": 'dw_json_get_string(payload, "id", "")',
        "dw_handle_cellular_apn_profile_delete": 'dw_json_get_string(payload, "id", "")',
        "dw_handle_cellular_sms_delete": 'dw_json_get_string(payload, "id", "")',
    }
    for handler, expression in expected.items():
        assert expression in function(handler), handler


def test_apply_only_handlers_are_guarded_because_they_consume_payload() -> None:
    for handler in (
        "dw_handle_wan_apply",
        "dw_handle_lan_apply",
        "dw_handle_cellular_service_apply",
    ):
        code = function(handler)
        assert "dw_parse_write_payload(" in code, handler
        assert "payload" in code, handler


def test_null_message_compatibility_is_preserved_by_common_parser() -> None:
    parser_start = SOURCE.index("static struct json_object *dw_parse_payload(")
    parser_end = SOURCE.index("static int dw_parse_write_payload(", parser_start)
    parser = SOURCE[parser_start:parser_end]
    null_branch = parser[parser.index("if (!msg)"):parser.index("if ((size_t)blob_len(msg)")]
    assert "json_object_new_object()" in null_branch
    assert "return *in" in null_branch


def test_read_and_status_handlers_are_not_reclassified_as_writes() -> None:
    for handler in (
        "dw_handle_wan_list",
        "dw_handle_cellular_service_get",
        "dw_handle_wifi_config_get",
        "dw_handle_wifi_status_get",
    ):
        assert "dw_parse_write_payload(" not in function(handler), handler


def remaining_inventory() -> list[tuple[int, str, list[str]]]:
    inventory_path = Path(__file__).with_name("test_write_guard_inventory_u14d_contract.py")
    spec = importlib.util.spec_from_file_location("u14d_inventory", inventory_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.suspicious_unmigrated_handlers()


def test_inventory_excludes_u14f_and_has_updated_count() -> None:
    remaining = remaining_inventory()
    names = {name for _, name, _ in remaining}
    assert not names.intersection(MIGRATED), sorted(names.intersection(MIGRATED))
    assert len(remaining) == 0, len(remaining)


if __name__ == "__main__":
    test_each_handler_guards_before_business_or_side_effect_calls()
    test_wrapped_business_fields_are_read_from_payload()
    test_apply_only_handlers_are_guarded_because_they_consume_payload()
    test_null_message_compatibility_is_preserved_by_common_parser()
    test_read_and_status_handlers_are_not_reclassified_as_writes()
    test_inventory_excludes_u14f_and_has_updated_count()
    print(f"ok: U-14F guarded {len(MIGRATED)} network/cellular/Wi-Fi handlers")
    print(f"remaining suspicious unguarded handlers: {len(remaining_inventory())}")

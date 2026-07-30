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
    "dw_handle_routing_static_route_set": "jmx_routing_static_route_set(payload)",
    "dw_handle_routing_static_route_delete": "jmx_routing_static_route_delete(id)",
    "dw_handle_routing_policy_rule_set": "jmx_routing_policy_rule_set(payload)",
    "dw_handle_routing_policy_rule_delete": "jmx_routing_policy_rule_delete(id)",
    "dw_handle_routing_table_set": "jmx_routing_table_set(payload)",
    "dw_handle_routing_table_delete": "jmx_routing_table_delete(id)",
    "dw_handle_flow_control_rule_set": "jmx_flow_rule_set(r)",
    "dw_handle_flow_control_smart_set": "jmx_flow_control_smart_set(payload)",
    "dw_handle_flow_control_priority_set": "jmx_flow_control_priority_set(payload)",
    "dw_handle_flow_control_group_carrier_set": "jmx_flow_control_group_carrier_set(payload)",
    "dw_handle_flow_control_rule_delete": "jmx_flow_rule_delete(id)",
    "dw_handle_dns_service_set": "jmx_dns_service_save_apply_result(payload, apply)",
    "dw_handle_dns_service_save_apply_result": "jmx_dns_service_save_apply_result(payload, apply)",
    "dw_handle_wan_dns_policy_set": "jmx_wan_dns_policy_save_apply_result(wan_id, payload)",
    "dw_handle_wan_dns_policy_delete": "jmx_wan_dns_policy_delete_apply_result(policy_id)",
}


def test_each_handler_guards_before_its_first_business_call() -> None:
    for handler, first_business_call in MIGRATED.items():
        code = function(handler)
        guard = code.index("dw_parse_write_payload(")
        business = code.index(first_business_call)
        assert guard < business, handler
        prefix = code[:guard]
        assert not re.search(r"\bjmx_[A-Za-z0-9_]+\s*\(", prefix), handler
        assert "json_tokener_parse(" not in code, handler
        assert "blobmsg_format_json(" not in code, handler


def test_payload_wrapper_is_used_for_business_fields() -> None:
    expected = {
        "dw_handle_routing_static_route_delete": 'dw_json_get_string(payload, "id", "")',
        "dw_handle_routing_policy_rule_delete": 'dw_json_get_string(payload, "id", "")',
        "dw_handle_routing_table_delete": 'dw_json_get_string(payload, "id", "")',
        "dw_handle_flow_control_rule_delete": 'dw_json_get_string(payload, "id", "")',
        "dw_handle_wan_dns_policy_set": 'dw_json_get_string(payload, "wan_id", "")',
        "dw_handle_wan_dns_policy_delete": 'dw_json_get_int(payload, "id", 0)',
    }
    for handler, expression in expected.items():
        assert expression in function(handler), handler


def test_null_message_compatibility_remains_in_common_parser() -> None:
    parser_start = SOURCE.index("static struct json_object *dw_parse_payload(")
    parser_end = SOURCE.index("static int dw_parse_write_payload(", parser_start)
    parser = SOURCE[parser_start:parser_end]
    empty = parser[parser.index("if (!msg)"):parser.index("if ((size_t)blob_len(msg)")]
    assert "json_object_new_object()" in empty
    assert "return *in" in empty


def remaining_inventory() -> list[tuple[int, str, list[str]]]:
    inventory_path = Path(__file__).with_name("test_write_guard_inventory_u14d_contract.py")
    spec = importlib.util.spec_from_file_location("u14d_inventory", inventory_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.suspicious_unmigrated_handlers()


def test_inventory_excludes_u14e_and_has_updated_count() -> None:
    remaining = remaining_inventory()
    names = {name for _, name, _ in remaining}
    assert not names.intersection(MIGRATED), sorted(names.intersection(MIGRATED))
    assert len(remaining) == 0, len(remaining)


if __name__ == "__main__":
    test_each_handler_guards_before_its_first_business_call()
    test_payload_wrapper_is_used_for_business_fields()
    test_null_message_compatibility_remains_in_common_parser()
    test_inventory_excludes_u14e_and_has_updated_count()
    print(f"ok: U-14E guarded {len(MIGRATED)} routing/flow-control/DNS handlers")
    print(f"remaining suspicious unguarded handlers: {len(remaining_inventory())}")

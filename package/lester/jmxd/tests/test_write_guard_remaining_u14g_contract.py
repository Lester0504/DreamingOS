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
    "dw_handle_identification_set": "jmx_identification_mode_get(",
    "dw_handle_route_config_set": "jmx_api_route_config_set(payload)",
    "dw_handle_advanced_routing_set": "jmx_advanced_routing_set(payload)",
    "dw_handle_advanced_routing_apply": "jmx_advanced_routing_apply(payload)",
    "dw_handle_custom_config_save": "jmx_custom_config_save(payload)",
    "dw_handle_custom_config_apply": "jmx_custom_config_apply(payload)",
    "dw_handle_network_control_save": "jmx_network_control_save(payload)",
    "dw_handle_rulesd_config_migrate": "jmx_rulesd_config_migrate(payload)",
    "dw_handle_aegis_app_block_delete": "jmx_aegis_app_block_delete(payload)",
    "dw_handle_network_control_apply": "jmx_network_control_apply(payload)",
    "dw_handle_log_center_clear": "jmx_log_center_clear(payload)",
    "dw_handle_log_center_syslog_set": "jmx_log_center_syslog_set(payload)",
    "dw_handle_log_center_settings_set": "jmx_log_center_settings_set(payload)",
    "dw_handle_log_center_event_add": "jmx_log_center_event_add(payload)",
    "dw_handle_log_center_warning_rules_set": "jmx_log_center_warning_rules_set(payload)",
    "dw_handle_log_center_alarm_update": "jmx_log_center_alarm_update(payload)",
    "dw_handle_log_center_delivery_update": "jmx_log_center_delivery_update(payload)",
    "dw_handle_log_center_channels_set": "jmx_log_center_channels_set(payload)",
    "dw_handle_log_center_delivery_claim": "jmx_log_center_delivery_claim(payload)",
    "dw_handle_log_center_delivery_replay": "jmx_log_center_delivery_replay(payload)",
    "dw_handle_log_center_prune": "jmx_log_center_prune(payload)",
    "dw_handle_network_control_bulk_delete": "jmx_network_control_rules_bulk_delete(payload)",
    "dw_handle_system_settings_set": "jmx_system_settings_save_apply_result(payload)",
    "dw_handle_system_settings_apply": "jmx_system_settings_apply_result(payload)",
    "dw_handle_system_service_set": "jmx_system_service_set(payload)",
    "dw_handle_system_cron_set": "jmx_system_cron_set(payload)",
    "dw_handle_signature_update_validate": "jmx_signature_update_validate(payload)",
    "dw_handle_signature_update_apply": "jmx_signature_update_apply(payload)",
    "dw_handle_system_disabled_functions_set": "jmx_system_disabled_functions_set(payload)",
    "dw_handle_ai_config_set": "jmx_ai_config_set(payload)",
    "dw_handle_ai_chat": "jmx_ai_chat(payload)",
    "dw_handle_ai_conversation_save": "jmx_ai_conversation_save(payload)",
    "dw_handle_firewall_geo_block_set": "jmx_geo_block_update(payload)",
}

EXCLUDED = {
    "dw_handle_signature_update_status": (
        "read-only status snapshot; the implementation ignores cfg and performs no "
        "persistence, deletion, runtime apply, or external request"
    ),
}


def test_mutating_and_request_consuming_handlers_guard_before_business_calls() -> None:
    for handler, first_business_call in MIGRATED.items():
        code = function(handler)
        guard = code.index("dw_parse_write_payload(")
        business = code.index(first_business_call)
        assert guard < business, handler
        assert not re.search(r"\bjmx_[A-Za-z0-9_]+\s*\(", code[:guard]), handler
        assert "json_tokener_parse(" not in code, handler
        assert "blobmsg_format_json(" not in code, handler


def test_wrapped_data_is_the_business_payload() -> None:
    for handler, business_call in MIGRATED.items():
        code = function(handler)
        if handler == "dw_handle_identification_set":
            assert 'dw_json_get_string(payload, "mode", "")' in code
        else:
            assert business_call in code, handler
        assert not re.search(r"\bjmx_[A-Za-z0-9_]+\s*\(in\)", code), handler


def test_ai_chat_is_guarded_despite_current_provider_stub() -> None:
    code = function("dw_handle_ai_chat")
    assert code.index("dw_parse_write_payload(") < code.index("jmx_ai_chat(payload)")
    assert "jmx_ai_chat(in)" not in code


def test_signature_status_is_explicitly_excluded_as_read_only() -> None:
    handler = "dw_handle_signature_update_status"
    code = function(handler)
    reason = EXCLUDED[handler]
    assert "read-only" in reason
    assert "performs no persistence" in reason
    assert "dw_parse_write_payload(" not in code
    assert "json_tokener_parse(" not in code
    assert "blobmsg_format_json(" not in code
    assert "(void)msg" in code
    assert "jmx_signature_update_status(NULL)" in code


def remaining_inventory() -> list[tuple[int, str, list[str]]]:
    inventory_path = Path(__file__).with_name("test_write_guard_inventory_u14d_contract.py")
    spec = importlib.util.spec_from_file_location("u14d_inventory", inventory_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.suspicious_unmigrated_handlers()


def test_reviewed_inventory_is_empty() -> None:
    assert remaining_inventory() == []


if __name__ == "__main__":
    test_mutating_and_request_consuming_handlers_guard_before_business_calls()
    test_wrapped_data_is_the_business_payload()
    test_ai_chat_is_guarded_despite_current_provider_stub()
    test_signature_status_is_explicitly_excluded_as_read_only()
    test_reviewed_inventory_is_empty()
    print(f"ok: U-14G guarded {len(MIGRATED)} handlers; excluded 1 read-only status handler")
    print(f"remaining suspicious unguarded handlers: {len(remaining_inventory())}")

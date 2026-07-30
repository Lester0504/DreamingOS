#!/usr/bin/env python3
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
    "dw_handle_dhcp_service_set": "jmx_dhcp_service_get()",
    "dw_handle_dhcp_reservation_delete": "jmx_dhcp_reservation_delete_resolve(",
    "dw_handle_firewall_service_set": "jmx_firewall_service_set(payload)",
    "dw_handle_firewall_service_apply": "jmx_firewall_service_apply(payload)",
    "dw_handle_vpn_config_set": "jmx_vpn_config_set(payload)",
    "dw_handle_vpn_config_apply": "jmx_vpn_config_apply(payload)",
    "dw_handle_bulk_ip_set": "jmx_bulk_ip_set(payload)",
    "dw_handle_bulk_ip_import": "jmx_bulk_ip_import(payload)",
    "dw_handle_bulk_ip_reserve": "jmx_bulk_ip_reserve(payload)",
    "dw_handle_bulk_ip_delete": "jmx_bulk_ip_delete(id)",
    "dw_handle_upnp_service_set": "jmx_upnp_service_save_apply_result(payload)",
    "dw_handle_upnp_acl_set": "jmx_upnp_acl_save_apply_result(payload)",
    "dw_handle_upnp_acl_delete": "jmx_upnp_acl_delete_apply_result(id)",
    "dw_handle_upnp_mapping_set": "jmx_upnp_mapping_set_ex(payload,",
    "dw_handle_upnp_mapping_delete": "jmx_upnp_mapping_delete(id)",
}


def test_next_write_batch_is_guarded_before_every_side_effect() -> None:
    for handler, first_side_effect in MIGRATED.items():
        code = function(handler)
        guard = code.index("dw_parse_write_payload(")
        mutation = code.index(first_side_effect)
        assert guard < mutation, handler
        assert "json_tokener_parse(" not in code, handler
        assert "blobmsg_format_json(" not in code, handler


def test_null_message_compatibility_remains_in_common_parser() -> None:
    parser_start = SOURCE.index("static struct json_object *dw_parse_payload(")
    parser_end = SOURCE.index("static int dw_parse_write_payload(", parser_start)
    parser = SOURCE[parser_start:parser_end]
    empty = parser[parser.index("if (!msg)"):parser.index("if ((size_t)blob_len(msg)")]
    assert "json_object_new_object()" in empty
    assert "return *in" in empty


def suspicious_unmigrated_handlers() -> list[tuple[int, str, list[str]]]:
    mutation = re.compile(
        r"^jmx_.*(?:_set|_save|_apply|_delete|_update|_clear|_prune|_replay|"
        r"_claim|_action|_create|_remove|_import|_reserve|_migrate|_add|"
        r"_cancel|_authorize|_chat)(?:_|$)"
    )
    handlers = []
    for match in re.finditer(r"^static int (dw_handle_[A-Za-z0-9_]+)\(", SOURCE, re.M):
        name = match.group(1)
        code = function(name)
        if "dw_parse_write_payload(" in code:
            continue
        if "json_tokener_parse(" not in code and "dw_parse_payload(" not in code:
            continue
        calls = sorted(set(re.findall(r"\b(jmx_[A-Za-z0-9_]+)\s*\(", code)))
        writes = [call for call in calls if mutation.match(call)]
        if writes:
            line = SOURCE.count("\n", 0, match.start()) + 1
            handlers.append((line, name, writes))
    return handlers


def test_suspicious_inventory_excludes_migrated_batch() -> None:
    suspicious = suspicious_unmigrated_handlers()
    names = {name for _, name, _ in suspicious}
    assert not names.intersection(MIGRATED), sorted(names.intersection(MIGRATED))
    assert "dw_handle_signature_update_status" not in names
    assert suspicious == []


if __name__ == "__main__":
    test_next_write_batch_is_guarded_before_every_side_effect()
    test_null_message_compatibility_remains_in_common_parser()
    test_suspicious_inventory_excludes_migrated_batch()
    remaining = suspicious_unmigrated_handlers()
    print(f"ok: U-14D guarded {len(MIGRATED)} write handlers")
    print(f"remaining suspicious unguarded handlers: {len(remaining)}")
    for line, name, calls in remaining:
        print(f"  {line}: {name}: {', '.join(calls)}")

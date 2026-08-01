#!/usr/bin/env python3
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_user.c").read_text(encoding="utf-8")


def function(name: str) -> str:
    match = re.search(rf"{re.escape(name)}\s*\([^;]*?\)\s*\{{", SOURCE, re.S)
    if not match:
        raise AssertionError(name)
    brace = SOURCE.index("{", match.start())
    depth = 0
    for index in range(brace, len(SOURCE)):
        if SOURCE[index] == "{":
            depth += 1
        elif SOURCE[index] == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[match.start():index + 1]
    raise AssertionError(name)


def test_history_base_dir_rejects_truncation_and_falls_back() -> None:
    body = function("const char *get_client_data_base_dir")
    assert "base_len <= sizeof(g_client_data_base_dir) - sizeof(suffix)" in body
    assert "CLIENT_DATA_BASE_DIR_DEFAULT" in body
    assert "snprintf(g_client_data_base_dir" not in body
    assert "strncpy(g_client_data_base_dir" not in body
    cleanup = function("void check_and_cleanup_history_data_by_size")
    assert "const char *data_dir = get_client_data_base_dir();" in cleanup
    assert '"%s/client_data", history_data_path' not in cleanup


def test_visit_dates_and_client_fields_have_explicit_copy_semantics() -> None:
    date_copy = function("static int copy_visit_filename_date")
    assert "name_len >= date_len" in date_copy
    assert "memcpy(date_str, filename, name_len)" in date_copy
    assert "copy_string_truncated(node->mac" in SOURCE
    assert "copy_string_truncated(node->hostname" in SOURCE
    assert "copy_string_truncated(node->visiting_url" in SOURCE


def test_bridge_sysfs_path_checks_source_contract_before_joining() -> None:
    body = function("static void client_iface_add_bridge_members")
    assert "strnlen(bridge, sizeof(g_client_lan_ifaces[0]))" in body
    assert "sizeof(prefix) - 1 + bridge_len + sizeof(suffix) > sizeof(path)" in body
    assert 'snprintf(path, sizeof(path), "/sys/class/net/%s/brif"' not in body


if __name__ == "__main__":
    test_history_base_dir_rejects_truncation_and_falls_back()
    test_visit_dates_and_client_fields_have_explicit_copy_semantics()
    test_bridge_sysfs_path_checks_source_contract_before_joining()
    print("ok: K-12 jmx_user warning cleanup keeps explicit bounds")

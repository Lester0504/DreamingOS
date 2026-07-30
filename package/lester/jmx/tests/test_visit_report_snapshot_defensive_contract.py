#!/usr/bin/env python3
import re
from pathlib import Path


SOURCE = (Path(__file__).resolve().parents[1] / "src/jmx_client.c").read_text()


def function_body(name: str) -> str:
    match = re.search(rf"\b{name}\s*\([^;]*?\)\s*\{{", SOURCE, re.DOTALL)
    assert match, f"function {name} not found"
    start = match.end() - 1
    depth = 0
    for index in range(start, len(SOURCE)):
        if SOURCE[index] == "{":
            depth += 1
        elif SOURCE[index] == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[start + 1:index]
    raise AssertionError(f"unterminated function {name}")


def test_lock_contains_only_bounded_snapshot_and_counter_updates() -> None:
    body = function_body("__af_visit_info_report")
    lock = body.index("spin_lock_bh(&node->visit_info_lock);")
    unlock = body.index("spin_unlock_bh(&node->visit_info_lock);")
    critical = body[lock:unlock]

    assert "struct visit_report_snapshot snapshots[MAX_RECORD_APP_NUM];" in body
    assert "total_count < ARRAY_SIZE(snapshots)" in critical
    assert "snapshots[total_count].app_id = info->app_id;" in critical
    assert "snapshots[total_count].total_num = info->total_num;" in critical
    assert "snapshots[total_count].latest_action = info->latest_action;" in critical
    assert critical.count("info->total_num = 0;") == 2

    forbidden = ("sort(", "cJSON_", "kzalloc", "kmalloc", "kstrdup", "GFP_KERNEL")
    for token in forbidden:
        assert token not in critical, f"{token} must stay outside visit_info_lock"


def test_sort_and_json_construction_happen_after_unlock() -> None:
    body = function_body("__af_visit_info_report")
    unlock = body.index("spin_unlock_bh(&node->visit_info_lock);")

    assert unlock < body.index("sort(snapshots")
    assert unlock < body.index("visit_report_json_create(cJSON_Object)")
    assert "sizeof(snapshots[0])" in body
    assert "app_visit_info_t *info_array" not in body


def test_json_creation_failures_use_one_cleanup_path() -> None:
    body = function_body("__af_visit_info_report")

    assert body.count("goto json_failed;") >= 5
    assert "cJSON_Delete(visit_obj);" in body
    assert "cJSON_Delete(visit_info_array);" in body
    assert "cJSON_Delete(root_obj);" in body
    assert "kfree(out);" in body
    assert "cJSON_Create" not in body
    assert "cJSON_Add" not in body


if __name__ == "__main__":
    test_lock_contains_only_bounded_snapshot_and_counter_updates()
    test_sort_and_json_construction_happen_after_unlock()
    test_json_creation_failures_use_one_cleanup_path()
    print("ok: visit report snapshot defensive contract passed")

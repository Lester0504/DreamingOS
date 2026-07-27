#!/usr/bin/env python3
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "jmx_main.c"
HEADER = ROOT / "src" / "jmx.h"


def function_body(source: str, name: str) -> str:
    match = re.search(rf"\b{name}\s*\([^;]*?\)\s*\{{", source, re.DOTALL)
    assert match, f"function {name} not found"

    start = match.end() - 1
    depth = 0
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start + 1 : index]
    raise AssertionError(f"unterminated function {name}")


def test_stale_cleanup_uses_callers_lock() -> None:
    source = SOURCE.read_text()
    helper = function_body(source, "af_active_app_clean_stale_locked")
    update = function_body(source, "af_update_active_app_list")

    assert "lockdep_assert_held(&active_app_list_lock);" in helper
    assert "spin_lock" not in helper
    assert "spin_unlock" not in helper
    assert "list_for_each_entry_safe" in helper
    assert "list_del(&node->list);" in helper
    assert "kfree(node);" in helper

    lock = update.index("spin_lock_bh(&active_app_list_lock);")
    cleanup = update.index("af_active_app_clean_stale_locked();")
    traversal = update.index("list_for_each_entry_safe")
    unlock = update.rindex("spin_unlock_bh(&active_app_list_lock);")
    assert lock < cleanup < traversal < unlock
    assert update.count("spin_lock_bh(&active_app_list_lock);") == 1
    assert update.count("spin_unlock_bh(&active_app_list_lock);") == 1


def test_active_app_list_access_contract() -> None:
    source = SOURCE.read_text()
    expected_accessors = [
        "jmx_v2_update_active_app_ex",
        "jmx_v2_update_active_app6_ex",
        "af_active_app_clean_stale_locked",
        "af_update_active_app_list",
        "af_clear_active_app_list",
        "af_active_app_seq_start",
        "af_active_app_seq_next",
        "af_active_app_seq_stop",
        "af_active_app_seq_show",
    ]

    exact_reference = re.compile(r"\bactive_app_list\b")
    reviewed_references = sum(
        len(exact_reference.findall(function_body(source, name)))
        for name in expected_accessors
    )

    # One extra reference is the global LIST_HEAD declaration. Any new runtime
    # access must be added to this reviewed list with its locking contract.
    assert len(exact_reference.findall(source)) == reviewed_references + 1

    for name in ("jmx_v2_update_active_app_ex", "jmx_v2_update_active_app6_ex"):
        body = function_body(source, name)
        lock = body.index("spin_lock_bh(&active_app_list_lock);")
        traversal = body.index("list_for_each_entry_safe")
        unlock = body.rindex("spin_unlock_bh(&active_app_list_lock);")
        assert lock < traversal < unlock

    clear = function_body(source, "af_clear_active_app_list")
    assert clear.index("spin_lock_bh(&active_app_list_lock);") < clear.index(
        "list_for_each_entry_safe"
    ) < clear.index("spin_unlock_bh(&active_app_list_lock);")

    seq_start = function_body(source, "af_active_app_seq_start")
    seq_stop = function_body(source, "af_active_app_seq_stop")
    assert "spin_lock_bh(&active_app_list_lock);" in seq_start
    assert "spin_unlock_bh(&active_app_list_lock);" in seq_stop

    assert "af_find_active_app" not in source
    assert "af_find_active_app" not in HEADER.read_text()


if __name__ == "__main__":
    test_stale_cleanup_uses_callers_lock()
    test_active_app_list_access_contract()
    print("ok: active_app_list locking contract passed")

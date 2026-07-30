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


def test_expiry_walk_never_drops_lock_with_cached_next() -> None:
    for name in ("check_expired_visit_info",):
        body = function_body(name)
        walk = body[body.index("spin_lock_bh"):body.index("spin_unlock_bh")]
        assert "hlist_for_each_entry_safe" in walk
        assert "spin_unlock_bh" not in walk
        assert "kfree" not in walk


def test_expired_nodes_are_freed_after_unlock() -> None:
    for name in ("check_expired_visit_info",):
        body = function_body(name)
        unlock = body.index("spin_unlock_bh")
        free = body.index("kfree(info)")
        assert "HLIST_HEAD(expired)" in body
        assert "hlist_add_head(&info->hlist, &expired)" in body
        assert unlock < free


if __name__ == "__main__":
    test_expiry_walk_never_drops_lock_with_cached_next()
    test_expired_nodes_are_freed_after_unlock()
    print("ok: client visit expiry defensive contract passed")

#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src" / "dw_read_cache.c").read_text()


def function_body(name: str) -> str:
    marker = f"static void {name}("
    start = SOURCE.index(marker)
    brace = SOURCE.index("{", start)
    depth = 0
    for index in range(brace, len(SOURCE)):
        if SOURCE[index] == "{":
            depth += 1
        elif SOURCE[index] == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[brace:index + 1]
    raise AssertionError(f"unterminated function: {name}")


def public_function_body(name: str) -> str:
    marker = f"void {name}("
    start = SOURCE.index(marker)
    brace = SOURCE.index("{", start)
    depth = 0
    for index in range(brace, len(SOURCE)):
        if SOURCE[index] == "{":
            depth += 1
        elif SOURCE[index] == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[brace:index + 1]
    raise AssertionError(f"unterminated function: {name}")


def test_prewarm_entries_survive_idle_eviction() -> None:
    prewarm = public_function_body("dw_read_cache_prewarm")
    evict = function_body("dw_read_cache_evict_idle")

    assert "e->resident = 1;" in prewarm
    assert "if (e->resident)\n            continue;" in evict


def test_capacity_prefers_nonresident_entries() -> None:
    slot_start = SOURCE.index(
        "static struct dw_read_cache_entry *dw_read_cache_slot("
    )
    slot_end = SOURCE.index(
        "static void dw_read_cache_entry_remember", slot_start
    )
    slot = SOURCE[slot_start:slot_end]

    assert "if (!c->resident" in slot
    assert "else if (oldest)\n        e = oldest;" in slot
    assert "else\n        e = oldest_any;" in slot


if __name__ == "__main__":
    test_prewarm_entries_survive_idle_eviction()
    test_capacity_prefers_nonresident_entries()
    print("read cache prewarm residency contract: ok")

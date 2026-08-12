#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_proc_snapshot_captures_generation_for_empty_set() -> None:
    stats = (ROOT / "src/jmx_stats.c").read_text(encoding="utf-8")
    assert "jmx_v3_rule_match_snapshot(NULL, 0, &it->generation)" in stats
    assert "jmx_v3_rule_match_snapshot(NULL, 0, NULL)" not in stats


if __name__ == "__main__":
    test_proc_snapshot_captures_generation_for_empty_set()
    print("ok: v3 zero-rule generation contract passed")

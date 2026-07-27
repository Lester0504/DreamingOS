#!/usr/bin/env python3
"""Static contract for AppFilter per-rule runtime readback and hits."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_app_filter.c").read_text(encoding="utf-8")
HEADER = (ROOT / "src/jmx_app_filter.h").read_text(encoding="utf-8")
MAIN = (ROOT / "src/jmx_main.c").read_text(encoding="utf-8")


def test_proc_contract_is_read_only_and_structured() -> None:
    assert 'proc_create("app_filter_rules", 0444' in SOURCE
    assert '"rule_id enabled app_count mac_count app_hash_xor app_hash_sum mac_value hits last_hit_s\\n"' in SOURCE
    assert "jmx_app_filter_mix_id" in SOURCE
    assert "app_hash_xor ^= mixed" in SOURCE
    assert "app_hash_sum += mixed" in SOURCE
    assert "jmx_app_filter_mac_value" in SOURCE
    assert 'remove_proc_entry("app_filter_rules", jmx_proc_root)' in SOURCE
    assert "single_open" in SOURCE


def test_hits_are_lock_safe_and_counted_on_the_drop_path() -> None:
    assert "atomic64_t hit_count" in HEADER
    assert "atomic64_t last_hit_s" in HEADER
    assert "atomic64_inc(&rule->hit_count)" in SOURCE
    assert "ktime_get_real_seconds()" in SOURCE
    assert "jmx_match_app_filter_rule_record(appid, client->mac, &rule_id)" in MAIN
    old_pointer_path = MAIN[MAIN.index("int match_app_filter_rule("):MAIN.index(
        "int match_mac_filter_rule("
    )]
    assert "jmx_match_app_filter_rule(appid" not in old_pointer_path
    assert "app_filter_rule_t *jmx_match_app_filter_rule(" not in SOURCE


if __name__ == "__main__":
    test_proc_contract_is_read_only_and_structured()
    test_hits_are_lock_safe_and_counted_on_the_drop_path()
    print("ok: AppFilter runtime readback proc and hit counter contract")

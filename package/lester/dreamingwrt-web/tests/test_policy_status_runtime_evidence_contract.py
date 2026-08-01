#!/usr/bin/env python3
"""Static contract for truthful policy-route runtime evidence."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "files/www/dreamingwrt/plugins/native/policy-status.js"
STYLE_PATH = ROOT / "files/www/dreamingwrt/static/css/policy-status.css"
MENU_PATH = ROOT / "files/www/dreamingwrt/static/menu/main.json"
MODULE = MODULE_PATH.read_text(encoding="utf-8")
STYLE = STYLE_PATH.read_text(encoding="utf-8")
MENU = MENU_PATH.read_text(encoding="utf-8")

VERSION = "20260731-policy-runtime-evidence-01"

assert f"const VERSION = '{VERSION}'" in MODULE
assert f'"module_version": "{VERSION}"' in MENU
assert f'"style_version": "{VERSION}"' in MENU

for evidence in (
    "counter_supported",
    "counter_ready",
    "counter_source",
    "counter_precision",
    "aggregate_rule_counter",
    "jmx_route_kernel",
    "last_hit",
    "candidateDecisions",
    "verified !== true",
    "policy_hit !== true",
    "未验证候选，不计入命中",
    "聚合命中",
    "命中未采集",
):
    assert evidence in MODULE, evidence

assert "命中样本" not in MODULE
assert "data-policy-runtime-evidence" in MODULE
assert "data-rule-last-hit" in MODULE
assert ".policy-status-runtime-evidence" in STYLE
assert ".policy-status-rule-hit" in STYLE

# Counter absence must stay unknown instead of becoming a fake zero.
assert "counterAvailable && item.counter_ready !== false ? item.hit_count : null" in MODULE
assert "const hitTotal = counterAvailable ? optionalNumber" in MODULE
assert "rule.hit_count === null ? '未采集'" in MODULE

# Candidate route decisions are explicitly separated from verified aggregate counters.
assert "item.candidate === true && item.verified !== true && item.policy_hit !== true" in MODULE
assert "counterPrecisionLabel" in MODULE
assert "规则级聚合计数" in MODULE

# This slice must not add another page shell, sheet, modal, or private glass implementation.
for forbidden in ("data-dwrt-component=\"page-shell\"", "data-dwrt-component=\"sheet\"", "backdrop-filter:"):
    assert forbidden not in MODULE, forbidden

for source in (MODULE_PATH, STYLE_PATH, MENU_PATH):
    compressed = source.with_name(source.name + ".gz")
    if compressed.exists():
        import gzip
        assert gzip.open(compressed, "rb").read() == source.read_bytes(), f"stale gzip: {source}"

print("ok: policy status distinguishes kernel aggregate counters, unavailable counters, and unverified route candidates")

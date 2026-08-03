#!/usr/bin/env python3
"""Static contract for the DNS settings redesign."""

import gzip
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"
MODULE_PATH = WWW / "plugins/native/network-services.js"
STYLE_PATH = WWW / "static/css/network-services.css"
MENU_PATH = WWW / "static/menu/main.json"
MODULE = MODULE_PATH.read_text(encoding="utf-8")
STYLE = STYLE_PATH.read_text(encoding="utf-8")
MENU = json.loads(MENU_PATH.read_text(encoding="utf-8"))


def walk(items):
    for item in items:
        yield item
        yield from walk(item.get("children", []))


def test_information_hierarchy_preserves_dns_functions():
    for label in ("核心服务", "监听与缓存", "安全与隐私", "上游与路由"):
        assert label in MODULE, label
    for tab in ("概览", "上游 DNS", "DNS 转发", "域名规则", "DNS 分流"):
        assert tab in MODULE, tab
    for field in (
        "enabled", "mode", "listen_interfaces", "listen_port",
        "cache_enabled", "cache_size", "local_domain",
        "rebind_protection", "hijack_protection", "ipv6_dns",
        "edns_client_subnet", "upstreams", "rules", "wanPolicies",
    ):
        assert field in MODULE, field


def test_writes_fail_closed_and_validate_complete_snapshot():
    assert "state.draft.capabilities?.service_update === true" in MODULE
    assert "state.policyReadback" in MODULE
    assert "saveDns()" in MODULE
    assert "dnsValidationError()" in MODULE
    assert "启用 DNS 代理前至少选择一个监听接口" in MODULE
    assert "监听端口必须在 1 到 65535 之间" in MODULE
    assert "缓存容量必须是大于 0 的整数" in MODULE
    assert "runtime_readback === true" in MODULE


def test_request_and_destructive_action_contracts():
    assert "signal: context.signal" in MODULE
    assert "businessFailed" in MODULE
    assert "![0, 200, 2000].includes(code)" in MODULE
    assert "![0, 200, 2000].includes(payloadCode)" in MODULE
    assert "dnsDeleteConfirmationMarkup" in MODULE
    assert "confirmationMarkup" in MODULE
    assert "data-dwrt-confirm-accept" in MODULE
    assert "data-dwrt-confirm-cancel" in MODULE
    dns_drawer = MODULE[MODULE.index("function dnsEditorDrawer()") : MODULE.index("function upnpMappingDrawer()")]
    assert "再次点击删除" not in dns_drawer


def test_material_and_responsive_contracts():
    assert "dns-control-surface dwrt-kit-glass-surface" in MODULE
    assert "floatingSavebarMarkup" in MODULE
    assert "statusBadgeMarkup" in MODULE
    assert "function tabsMarkup()" in MODULE
    assert "dwrt-kit-tabs dwrt-kit-page-tabs" in MODULE
    assert "backdrop-filter" not in STYLE
    assert "!important" not in STYLE
    assert "@media (max-width: 760px)" in STYLE
    assert "grid-template-columns: 1fr" in STYLE


def test_menu_uses_the_new_shared_asset_version():
    items = {item.get("id"): item for item in walk(MENU["items"])}
    for item_id in ("dhcp-service", "dns-service"):
        item = items[item_id]
        assert item["module"] == "native/network-services.js"
        assert item["style"] == "/static/css/network-services.css"
        assert item["module_version"] == "20260802-ui-batch-01"
        assert item["style_version"] == "20260802-ui-batch-01"


def test_gzip_files_match_sources():
    for source in (MODULE_PATH, STYLE_PATH, MENU_PATH):
        compressed = Path(f"{source}.gz")
        assert compressed.is_file(), compressed
        with gzip.open(compressed, "rb") as stream:
            assert stream.read() == source.read_bytes(), compressed


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_")]
    for test in tests:
        test()
    print(f"ok: {len(tests)} DNS redesign contracts")

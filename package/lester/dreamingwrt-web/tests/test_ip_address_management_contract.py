#!/usr/bin/env python3
"""Focused static contract for the read-only IP address workbench."""

import gzip
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"
MODULE_PATH = WWW / "plugins/native/ip-address-management.js"
STYLE_PATH = WWW / "static/css/ip-address-management.css"
MENU_PATH = WWW / "static/menu/main.json"
SHELL_PATH = WWW / "static/js/menu-shell.js"
MANIFEST_PATH = ROOT / "redesign/route-manifest.json"
FIXTURE_PATH = ROOT / "tests/fixtures/ip-address-management.html"

MODULE = MODULE_PATH.read_text(encoding="utf-8")
STYLE = STYLE_PATH.read_text(encoding="utf-8")
SHELL = SHELL_PATH.read_text(encoding="utf-8")
MENU = json.loads(MENU_PATH.read_text(encoding="utf-8"))
MANIFEST = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
FIXTURE = FIXTURE_PATH.read_text(encoding="utf-8")


def walk(items):
    for item in items:
        yield item
        yield from walk(item.get("children", []))


def test_single_read_contract_and_registry_owner() -> None:
    assert "['network.ipam', '/api/v1/bulk-ip', 'jmxd.ipam', 5000" in SHELL
    assert "registry.request('network.ipam'" in MODULE
    assert "registry?.subscribe?.('network.ipam'" in MODULE
    assert "fetch(" not in MODULE
    assert "api.request" not in MODULE
    for endpoint in ("/bulk-ip/reserve", "/bulk-ip/delete", "/bulk-ip/import", "/bulk-ip/export"):
        assert endpoint not in MODULE
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        assert f"method: '{method}'" not in MODULE
        assert f'method: "{method}"' not in MODULE


def test_invalid_selected_network_falls_back_to_a_real_network() -> None:
    assert "networks.some((network) => network.id === requested) ? requested : firstText(networks[0]?.id)" in MODULE
    assert "selected_network" in MODULE
    assert "state.inventory.selectedNetwork || 'all'" in MODULE


def test_data_workbench_uses_shared_kit_components() -> None:
    for component in (
        'data-dwrt-page-shell="data-workbench"',
        'data-dwrt-component="toolbar"',
        'data-dwrt-component="data-table"',
        'data-dwrt-component="select"',
        'data-dwrt-component="expand-search"',
        'data-dwrt-component="icon-button"',
        'data-dwrt-component="state-panel"',
        'data-dwrt-component="sheet"',
        'data-dwrt-sheet-variant="copilot"',
    ):
        assert component in MODULE
    assert "statusBadgeMarkup" in MODULE
    assert "单一" not in MODULE  # no explanatory design copy leaks into the UI
    assert "新建" not in MODULE
    assert "保存并应用" not in MODULE


def test_information_hierarchy_is_one_toolbar_one_inventory_table() -> None:
    assert 'class="ipam-page-toolbar"' in MODULE
    assert 'class="ipam-summary"' in MODULE
    assert 'class="dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface ipam-table"' in MODULE
    assert MODULE.count('data-dwrt-component="data-table"') == 1
    assert MODULE.count('<table ') == 1
    assert MODULE.count('<th>') == 6
    assert '来源 / 类型' in MODULE
    assert '写事务等待后端同源回读' not in MODULE
    assert 'data-dwrt-surface="stable-glass"' not in MODULE
    assert 'data-dwrt-surface="dense-surface"' in MODULE


def test_filters_search_and_truthful_read_only_states_are_present() -> None:
    for marker in (
        "data-ipam-network",
        "data-ipam-status",
        "data-ipam-source",
        "data-ipam-search",
        "data-ipam-refresh",
        "data-ipam-detail",
    ):
        assert marker in MODULE
    for state in ("loading", "forbidden", "error", "stale", "refreshing", "ready"):
        assert f"'{state}'" in MODULE
    assert "当前为只读盘点" in MODULE
    assert "本页不会修改地址配置" in MODULE
    assert '<footer class="dwrt-kit-sheet-footer">' not in MODULE
    assert "conflict" in MODULE and "冲突" in MODULE


def test_transparent_route_root_table_radius_and_copilot_sheet_geometry() -> None:
    assert "background: transparent" in STYLE
    assert "border-radius: var(--app-radius-card, 24px)" in STYLE
    assert "--dwrt-kit-sheet-width: min(460px" in STYLE
    assert "--dwrt-kit-sheet-max-width: min(460px" in STYLE
    assert "overflow: auto" in STYLE
    assert "scrollbar-gutter: stable" in STYLE
    assert "@media (max-width: 760px)" in STYLE
    assert "table-layout: fixed" in STYLE
    assert "min-width: 720px" in STYLE
    assert "overflow-x: hidden" in STYLE
    assert "display: grid" in STYLE
    assert "!important" not in STYLE
    assert "backdrop-filter" not in STYLE
    for color_escape in ("rgba(", "rgb(", "#fff", "#000"):
        assert color_escape not in STYLE


def test_menu_and_manifest_expose_a_read_only_real_route() -> None:
    item = next(item for item in walk(MENU["items"]) if item.get("id") == "bulk-ip")
    assert item["availability"] == "available"
    assert item["frontend_owned"] is True
    assert item["module"] == "native/ip-address-management.js"
    assert item["module_version"] == "20260801-ipam-kit-controls-02"
    assert item["style_version"] == "20260801-ipam-kit-controls-02"
    assert item["style"] == "/static/css/ip-address-management.css"
    route = next(route for route in MANIFEST["routes"] if route["route"] == "#/network/bulk-ip")
    assert route == {
        "route": "#/network/bulk-ip",
        "label": "IP 地址管理",
        "owner": "plugins/native/ip-address-management.js",
        "page_shell": "data-workbench",
        "capability": "ipam_read",
        "registry": ["network.ipam"],
        "availability": "available-readonly",
    }


def test_fixture_covers_required_states_and_gzip_is_current() -> None:
    assert "ipam-workbench-fixture-02" in FIXTURE
    for scenario in ("ready", "loading", "error", "lkg"):
        assert scenario in FIXTURE
    assert "invalid-selected-network" in FIXTURE
    assert "window.IPAM_FIXTURE" in FIXTURE
    for source in (MODULE_PATH, STYLE_PATH):
        compressed = source.with_name(source.name + ".gz")
        assert compressed.is_file(), compressed
        assert gzip.open(compressed, "rb").read() == source.read_bytes(), f"stale gzip: {source.name}"


# The kit paints control material through .dwrt-kit-field descendants (dwrt-ui-kit.css:109)
# and mountAll() adds that class to [data-dwrt-component="field"]. Bare selects therefore
# render as native white controls, which is what made this page look unthemed.
def test_filter_controls_use_kit_material() -> None:
    module = MODULE_PATH.read_text(encoding="utf-8")
    style = STYLE_PATH.read_text(encoding="utf-8")
    assert module.count("dwrt-kit-select ipam-select") == 3
    assert "dwrt-kit-expand-search ipam-search" in module
    # every select sits inside a field wrapper so mountAll() can theme it
    assert module.count('data-dwrt-component="field"') == 3
    assert 'class="ipam-filter-field"' not in module or "ipam-filter-field" in style
    # wrappers stay inline so the toolbar remains a single row
    assert ".ipam-filter-field.dwrt-kit-field" in style
    assert "20260801-ipam-kit-controls-02" in module
    # mountExpandSearch() bails out when the flag is already set, which left the search box
    # as an empty circle. Markup must not pre-stamp it.
    assert 'data-dwrt-expand-search' not in module


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("ok: IP address management read-only contract is complete")

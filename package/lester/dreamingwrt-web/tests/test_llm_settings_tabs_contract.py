#!/usr/bin/env python3

import gzip
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"
MODULE_PATH = WWW / "plugins/native/ai-assistant.js"
STYLE_PATH = WWW / "static/css/ai-assistant.css"
MENU_PATH = WWW / "static/menu/main.json"
FIXTURE = ROOT / "tests/fixtures/llm-settings.html"
BROWSER_TEST = ROOT / "tools/test_llm_settings_fixture.py"
MODULE = MODULE_PATH.read_text()
STYLE = STYLE_PATH.read_text()


def test_settings_route_exposes_three_tabs() -> None:
    assert "SETTINGS_TABS" in MODULE
    for tab_id, label in (("overview", "概览"), ("provider", "供应商设置"), ("advanced", "高级设置")):
        assert f"['{tab_id}', '{label}'" in MODULE
    assert "settingsTab: 'overview'" in MODULE
    assert "data-ai-settings-tab" in MODULE
    assert "ai-settings-tabs" in MODULE
    # the chat tab listener must not capture the settings tabs
    assert ".ai-primary-tabs:not(.ai-settings-tabs)" in MODULE


def test_each_tab_renders_only_its_own_section() -> None:
    for name in ("settingsOverviewSection", "settingsProviderSection", "settingsAdvancedSection", "settingsFooter"):
        assert f"function {name}(" in MODULE
    overview = MODULE[MODULE.index("function settingsOverviewSection"):MODULE.index("function toolPolicyLabel")]
    assert "data-ai-provider" not in overview
    assert 'data-ai-config="temperature"' not in overview
    provider = MODULE[MODULE.index("function settingsProviderSection"):MODULE.index("function settingsAdvancedSection")]
    assert "data-ai-provider" in provider and "data-ai-auth-mode" in provider
    assert 'data-ai-config="temperature"' not in provider
    advanced = MODULE[MODULE.index("function settingsAdvancedSection"):MODULE.index("function settingsFooter")]
    assert 'data-ai-config="temperature"' in advanced and 'data-ai-config="model"' in advanced
    assert "data-ai-provider" not in advanced


def test_overview_uses_shared_kit_cards_and_no_secrets() -> None:
    # 四张概览卡按用户第 17 条提到主卡片之外，所以卡片渲染在 settingsOverviewCards()，
    # settingsOverviewSection() 只留 provider 侧的额外运行态行。
    cards = MODULE[MODULE.index("function settingsOverviewCards"):MODULE.index("function settingsOverviewSection")]
    assert "overviewCardsMarkup" in cards
    assert "dwrt-kit-overview-grid" in cards
    overview = MODULE[MODULE.index("function settingsOverviewSection"):MODULE.index("function toolPolicyLabel")]
    assert "api_key_input" not in overview
    assert "api_key_hint" not in overview
    assert "settingsOverviewCards()" in MODULE[MODULE.index("function settingsView"):MODULE.index("function settingsMasterCard")]


def test_save_bar_stays_available_on_every_tab() -> None:
    view = MODULE[MODULE.index("function settingsView"):MODULE.index("const SETTINGS_TABS")]
    assert "settingsTabContent(" in view and "settingsFooter()" in view
    footer = MODULE[MODULE.index("function settingsFooter"):MODULE.index("function connectionBadge")]
    assert "data-ai-save" in footer


def test_style_supports_tab_header_and_overview() -> None:
    # 用户第 17/18 条要求删掉重复说明与区块标题，所以 facts / hint / heading 三类样式已移除，
    # 概览改为主卡片外的 Kit 卡片带，高级设置切成三个 chamber。
    for selector in (".ai-settings-route-header", ".ai-settings-tabs", ".ai-settings-overview", ".ai-settings-chamber"):
        assert selector in STYLE
    for removed in (".ai-settings-facts", ".ai-settings-hint", ".ai-settings-heading", ".ai-section-title"):
        assert removed not in STYLE
    assert "grid-template-rows: auto auto;" in STYLE


def test_llm_menu_entry_still_targets_this_module() -> None:
    menu = json.loads(MENU_PATH.read_text())
    system = next(item for item in menu["items"] if item["id"] == "system")
    entry = next(item for item in system["children"] if item["id"] == "system-llm-settings")
    assert entry["module"] == "native/ai-assistant.js"


def test_gzip_assets_match_sources() -> None:
    for source in (MODULE_PATH, STYLE_PATH):
        compressed = Path(f"{source}.gz")
        assert compressed.is_file()
        with gzip.open(compressed, "rb") as stream:
            assert stream.read() == source.read_bytes()


def test_browser_fixture_covers_required_viewports() -> None:
    assert FIXTURE.is_file() and BROWSER_TEST.is_file()
    source = BROWSER_TEST.read_text()
    assert "1440" in source and "1024" in source and "375" in source
    assert "writes" in FIXTURE.read_text()


# menu-shell.js derives the browser cache key from module_version/style_version for
# every module outside its shellVersioned allow-list. ai-assistant.js is not on that
# list, so shipping a new file without bumping the version serves the stale module.
def test_cache_version_reflects_the_tab_refactor() -> None:
    menu = json.loads(MENU_PATH.read_text())
    found = []

    def walk(items):
        for item in items:
            if item.get("id") == "system-llm-settings":
                found.append(item)
            walk(item.get("children", []))

    walk(menu["items"])
    assert len(found) == 1
    item = found[0]
    assert item["module"] == "native/ai-assistant.js"
    assert item["module_version"] == "20260802-ui-batch-01"
    assert item["style_version"] == "20260802-ui-batch-01"
    shell = (WWW / "static/js/menu-shell.js").read_text()
    assert "/plugins/native/ai-assistant.js" not in shell.split("shellVersioned")[1][:600]


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_")]
    for test in tests:
        test()
    print(f"ok: {len(tests)} LLM settings tab contracts")

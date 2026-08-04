#!/usr/bin/env python3

import gzip
import json
import re
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


def test_master_switch_only_on_advanced_tab() -> None:
    # 用户 2026-08-04：「启用 llm 服务不用在每一页都显示，在高级设置页面显示就够了」。
    # 总开关是全局状态，跟着每个 Tab 复现一遍只是重复占位 —— 概览页的「接入状态」卡
    # 已经说明了同一件事。这里钉住它在 settingsView 里带 advanced 条件。
    view = MODULE[MODULE.index("function settingsView"):MODULE.index("const SETTINGS_TABS")]
    assert "settingsMasterCard()" in view
    assert "tab === 'advanced' ? settingsMasterCard() : ''" in view, view
    assert "tab === 'overview' ? settingsOverviewCards() : ''" in view


def test_advanced_collapses_when_service_disabled() -> None:
    # demo 2 的停用态：关掉总开关时配置主体收起成占位说明。停用时这些参数保存了也不
    # 生效，摆满一屏可编辑字段会让人以为改了就有用。总开关本身仍要渲染，否则关掉之后
    # 就没有入口再打开。
    advanced = MODULE[MODULE.index("function settingsAdvancedSection"):MODULE.index("function settingsFooter")]
    assert "if (!state.config.enabled)" in advanced
    assert "ai-dormant-chamber" in advanced
    assert advanced.index("if (!state.config.enabled)") < advanced.index('data-ai-config="temperature"')
    assert ".ai-dormant-chamber" in STYLE and ".ai-dormant-body" in STYLE


def test_provider_tab_shows_single_configured_provider_without_fake_multi_controls() -> None:
    # demo 1 的「已配置的供应商」只渲染真实存在的那一个。
    # 2026-08-04 用只读凭据实测 30.1：
    #   GET /api/v1/ai/providers        -> 404
    #   GET /api/v1/ai/dispatch-policy  -> 404
    #   GET /api/v1/ai/config           -> 200，单条，capabilities 里没有任何
    #                                      multi_provider / dispatch / strategy 位
    # `ai_config` 锁死 WHERE id=1，物理上只能存一个供应商。所以 demo 里的调度策略
    # 切换器与多卡阵列**不能实现**，画出来点了没反应就是假控件。
    # 切片必须**只覆盖调用方**：`settingsConfiguredProvider` 的函数定义就在
    # settingsProviderSection 与 settingsAdvancedSection 之间，若把定义也圈进来，
    # 光是那行 `function settingsConfiguredProvider(` 就能让断言通过 ——
    # 删掉调用点也照样绿。实测过这个假阳性，所以在定义处截断。
    provider = MODULE[
        MODULE.index("function settingsProviderSection"):MODULE.index("function settingsConfiguredProvider")
    ]
    assert "${settingsConfiguredProvider()}" in provider, "供应商页必须真的渲染已配置供应商卡"
    configured = MODULE[MODULE.index("function settingsConfiguredProvider"):MODULE.index("function settingsAdvancedSection")]
    assert "ai-configured-card" in configured
    assert "未测试" in configured
    assert "只保存一个供应商" in configured
    # 不得真的去调这两条不存在的路由。判据要限定在**代码**里，不能裸串匹配整个文件：
    # 上面那段注释如实记录了实测到的 404，把它一起判成违规就是假阳性。
    code_lines = [
        line for line in MODULE.splitlines()
        if not line.lstrip().startswith(("*", "//", "/*"))
    ]
    code = "\n".join(code_lines)
    for dead_route in ("/api/v1/ai/providers", "/api/v1/ai/dispatch-policy"):
        assert dead_route not in code, dead_route
    for selector in (".ai-configured-card", ".ai-configured-badge", ".ai-configured-models"):
        assert selector in STYLE, selector


def test_provider_check_state_is_session_scoped_and_labelled_as_such() -> None:
    # 联通状态与延迟来自本次会话的测试连接，不是后端持久记录：后端没有 last_check_* 列
    # （那是多供应商契约里的设计，代码未实现），所以文案必须说清来源。
    assert "providerCheck: { state: 'unknown'" in MODULE
    configured = MODULE[MODULE.index("function settingsConfiguredProvider"):MODULE.index("function settingsAdvancedSection")]
    assert "非后端持久记录" in configured or "刷新页面后需重新测试" in configured
    test_fn = MODULE[MODULE.index("async function testProvider"):MODULE.index("async function saveConfig")]
    assert test_fn.count("state.providerCheck") >= 2, test_fn.count("state.providerCheck")


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
    # Pin main.json to the module's own VERSION rather than to a literal key: a literal
    # goes stale on every legitimate bump and trains people to "fix" the test instead of
    # the cache key. The invariant that actually matters is that the two agree.
    module_src = (WWW / "plugins/native/ai-assistant.js").read_text()
    version = re.search(r"const VERSION = '([^']+)'", module_src).group(1)
    assert item["module_version"] == version
    assert item["style_version"] == version
    shell = (WWW / "static/js/menu-shell.js").read_text()
    assert "/plugins/native/ai-assistant.js" not in shell.split("shellVersioned")[1][:600]


# Acceptance打回：「启用 LLM 服务」总开关卡占满整屏。根因是 .ai-master-card 挂了
# .dwrt-kit-page-surface，而该类含 height: 100%，且它的父级 .ai-settings-card 已经是
# page-surface，于是内层小卡继承 100% 高度撑满一屏。page-surface 是页面级容器类，
# 卡片只应取 .dwrt-kit-glass-surface 作材质。
def test_master_switch_card_is_not_a_page_surface() -> None:
    src = (WWW / "plugins/native/ai-assistant.js").read_text()
    master = [line for line in src.splitlines() if "ai-master-card" in line and "<section" in line]
    assert master, "找不到 .ai-master-card 的渲染行"
    for line in master:
        assert "dwrt-kit-page-surface" not in line, (
            "ai-master-card 不得使用 dwrt-kit-page-surface（height:100% 会让它占满整屏）"
        )
        assert "dwrt-kit-glass-surface" in line, "ai-master-card 仍需 glass-surface 材质"


# 同一页面里只允许一个 page-surface 生效。ai-assistant 的三处分别属于互斥的
# 聊天/历史/设置标签页，任何新增都必须先确认不会嵌套。
def test_page_surface_usage_stays_bounded() -> None:
    src = (WWW / "plugins/native/ai-assistant.js").read_text()
    assert src.count("dwrt-kit-page-surface") == 3, (
        "ai-assistant 的 page-surface 数量变化了，请确认没有把它挂到卡片上或造成嵌套"
    )


# ui-kit 侧留一句说明，挡住下一次误用。
def test_ui_kit_documents_page_surface_height() -> None:
    css = (WWW / "static/ui-kit/dwrt-ui-kit.css").read_text()
    head = css.split(".dwrt-kit-page-surface {")[0]
    note = head[-400:]
    assert "height: 100%" in note and "卡片" in note, (
        "dwrt-kit-page-surface 上方需保留注释，说明它含 height:100% 且不得用于卡片"
    )


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_")]
    for test in tests:
        test()
    print(f"ok: {len(tests)} LLM settings tab contracts")

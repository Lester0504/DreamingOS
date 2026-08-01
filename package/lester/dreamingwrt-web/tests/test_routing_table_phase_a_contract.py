#!/usr/bin/env python3
"""Focused static contract for the Phase A routing workbench."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "files/www/dreamingwrt/plugins/native/routing-table.js"
STYLE_PATH = ROOT / "files/www/dreamingwrt/static/css/routing-table.css"
FIXTURE_PATH = ROOT / "tests/fixtures/routing-table-phase-a.html"
MODULE = MODULE_PATH.read_text(encoding="utf-8")
STYLE = STYLE_PATH.read_text(encoding="utf-8")
FIXTURE = FIXTURE_PATH.read_text(encoding="utf-8")


def test_five_same_page_kit_tabs_are_present() -> None:
    for tab in ("路由策略", "路由表", "路由对象", "跨三层服务", "运行解析"):
        assert tab in MODULE
    assert 'data-dwrt-component="tabs"' in MODULE
    assert "routing-page-tabs dwrt-kit-tabs" in MODULE


def test_dedicated_routing_resources_are_complete() -> None:
    for endpoint in (
        "/api/v1/routing/tables",
        "/api/v1/routing/objects",
        "/api/v1/routing/cross-services",
        "/api/v1/routing/runtime-resolve",
        "/api/v1/routing/external-policies",
    ):
        assert endpoint in MODULE
    assert "state.editorMode === 'create' ? 'POST' : 'PUT'" in MODULE
    assert "method: 'DELETE'" in MODULE
    assert "members: String(editor.membersText" in MODULE
    assert "table_id: Number(editor.table_id)" in MODULE
    assert "service_type: editor.service_type" in MODULE


def test_static_routes_and_pbr_have_no_second_write_path() -> None:
    assert "静态路由与 PBR 在此仅作统一索引" in MODULE
    assert "策略表”作为唯一写入口" in MODULE
    assert "创建路由" not in MODULE
    assert "saveRoute" not in MODULE
    assert "deleteRoute" not in MODULE
    assert "method: 'PATCH'" not in MODULE
    assert "requestJson(`${POLICY_ENDPOINT}" not in MODULE


def test_capabilities_fail_closed_and_runtime_boundary_is_truthful() -> None:
    assert "state.capabilities?.[name] === true" in MODULE
    for capability in (
        "table_crud",
        "object_crud",
        "cross_service_config_crud",
        "cross_service_runtime",
        "runtime_resolve",
    ):
        assert f"cap('{capability}')" in MODULE
    assert "runtime_consumer_not_implemented" in MODULE
    assert "配置可以保存，但运行消费者尚未实现" in MODULE
    assert "保存成功”显示为服务已生效" in MODULE
    assert "configured_resolution_not_per_flow_conntrack_decision" not in MODULE
    assert "不代表逐 flow 的 conntrack 命中" in MODULE


def test_reference_conflicts_and_backend_errors_remain_visible() -> None:
    assert "payload.references" in MODULE
    assert "仍被 ${references.join('、')} 引用" in MODULE
    assert "后端将执行最终冲突校验" in MODULE
    assert "route table id, name and table_id must be unique" not in MODULE
    assert "保存失败：" in MODULE
    assert "删除失败：" in MODULE
    assert "解析失败：" in MODULE


def test_shared_kit_components_and_half_sheet_are_used() -> None:
    for component in (
        'data-dwrt-component="data-table"',
        'data-dwrt-component="sheet"',
        'data-dwrt-sheet-variant="copilot"',
        'data-dwrt-component="switch"',
        'data-dwrt-component="state-panel"',
    ):
        assert component in MODULE
    assert "confirmationMarkup" in MODULE
    assert "data-dwrt-confirm-accept" in MODULE
    assert "data-dwrt-confirm-cancel" in MODULE
    assert "window.confirm" not in MODULE
    assert "--dwrt-kit-sheet-width: min(460px" in STYLE
    assert "--dwrt-kit-sheet-max-width: min(460px" in STYLE
    assert "backdrop-filter" not in STYLE
    assert "letter-spacing: 0" in STYLE


def test_layout_contains_scroll_without_page_level_glass() -> None:
    shell = MODULE[MODULE.index("function render()") : MODULE.index("function defaultEditor")]
    assert 'class="routing-table-shell"' in shell
    assert 'routing-table-shell dwrt-kit-glass-surface' not in shell
    assert "scrollbar-gutter: stable" in STYLE
    assert "overscroll-behavior: contain" in STYLE
    assert "max-width: 100%" in STYLE
    assert "@media (max-width: 720px)" in STYLE
    assert "@media (prefers-reduced-motion: reduce)" in STYLE


def test_fixture_covers_crud_runtime_and_failure_states() -> None:
    assert "routing-table-phase-a-01" in FIXTURE
    for scenario in ("ready", "fail-closed", "reference-conflict", "runtime-missing"):
        assert scenario in FIXTURE
    assert "window.ROUTING_FIXTURE" in FIXTURE
    assert "activeTab" in FIXTURE
    assert "requests" in FIXTURE
    assert "data-dwrt-confirmation" in FIXTURE or "dwrt-ui-kit.js" in FIXTURE

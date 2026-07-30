#!/usr/bin/env python3
"""Aegisx frontend/backend wiring and UniFi traffic-logging layout contracts."""

import gzip
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files" / "www" / "dreamingwrt"
MODULE_PATH = WWW / "plugins" / "native" / "aegisx.js"
STYLE_PATH = WWW / "static" / "css" / "aegisx.css"
MENU_PATH = WWW / "static" / "menu" / "main.json"
MODULE = MODULE_PATH.read_text(encoding="utf-8")
STYLE = STYLE_PATH.read_text(encoding="utf-8")


def test_removed_legacy_cards_and_shared_overview() -> None:
    assert "aegisx-section-header" not in MODULE
    assert "aegisx-capability-note" not in MODULE
    assert "aegisx-stat-grid" not in MODULE
    assert "aegisx-section-header" not in STYLE
    assert "aegisx-capability-note" not in STYLE
    assert "aegisx-stat-grid" not in STYLE
    assert "overviewCardsMarkup" in MODULE
    assert "aegisx-overview-cards" in MODULE


def test_logging_order_and_unifi_groups() -> None:
    overview = MODULE.index("overviewCards([")
    settings = MODULE.index("aegisx-unsupported-panel", overview)
    events = MODULE.index("aegisx-events-card", settings)
    assert overview < settings < events
    for label in (
        "NetFlow (IPFIX)", "流量日志", "Gateway DNS", "活动日志 (Syslog)",
        "数据保留", "SNMP 监控", "日志级别", "近期活动",
    ):
        assert label in MODULE
    assert "const settings = state.logSettings?.settings || state.logSettings || {};" in MODULE
    assert "radio('syslog', 'off', false" in MODULE
    assert "radio('syslog', 'internal', syslogLoaded && !bool(syslog.enabled)" in MODULE
    assert "actionButton('管理', 'log-center', syslogLoaded)" in MODULE


def test_safe_search_identification_and_history_are_wired() -> None:
    for endpoint in (
        "/api/v1/aegis/identification",
        "/api/v1/aegis/traffic-history/clear",
        "/api/v1/aegis/content-policy/validate",
    ):
        assert endpoint in MODULE
    assert "data-content-safe-search" in MODULE
    assert "safe_search: {" in MODULE
    for provider in ("google", "bing", "youtube"):
        assert f"{provider}: bool(draft.safe_search?.{provider})" in MODULE
    for mode in ("disabled", "device_and_traffic", "traffic_only"):
        assert mode in MODULE
    assert "JSON.stringify({ confirm: true })" in MODULE


def test_app_block_full_rest_contract_is_exposed() -> None:
    for endpoint in (
        "/api/v1/aegis/app-blocks",
        "/api/v1/aegis/app-blocks/validate",
        "/api/v1/policy-engine/catalog?app_limit=500",
    ):
        assert endpoint in MODULE
    for field in (
        "source", "app_ids", "schedule", "action: 'block'", "filter_quic: false",
    ):
        assert field in MODULE
    assert "confirm: true, revision" in MODULE
    assert "method: editing ? 'PUT' : 'POST'" in MODULE
    assert "kind === 'app-block' ? { confirm: true, revision:" in MODULE
    assert "data-app-selected-count" in MODULE
    assert "updateAppBlockSaveState()" in MODULE
    assert 'class="aegisx-drawer aegisx-app-drawer' in MODULE
    assert 'data-dwrt-sheet-variant="copilot"' in MODULE
    assert "source_mode" in MODULE
    assert "schedule_ranges" in MODULE
    for mode in ("'always'", "'daily'", "'weekly'", "'custom'"):
        assert mode in MODULE
    assert "data-app-range-add" in MODULE
    assert "data-app-range-remove" in MODULE
    assert "尚未配置" not in MODULE[MODULE.index("function renderProtect"):MODULE.index("function defaultContentDraft")]
    assert "支持始终或按星期时段生效" not in MODULE


def test_pcdn_uses_real_capability_validate_and_guarded_apply() -> None:
    for endpoint in (
        "/api/v1/aegis/content-policy/pcdn",
        "/api/v1/aegis/content-policy/pcdn/validate",
        "/api/v1/aegis/content-policy/pcdn/sync",
    ):
        assert endpoint in MODULE
    assert "pcdnCaps().pcdn_filter_supported" in MODULE
    assert "bool(pcdn.enabled) || bool(pcdn.rules_ready)" in MODULE
    assert "async function validatePcdn(enabled)" in MODULE
    assert "JSON.stringify({ confirm: false })" in MODULE
    assert "state.pcdnJobId = firstText(result.job_id)" in MODULE
    assert "activePcdnJob()" in MODULE
    assert "pcdn_revision_conflict" in MODULE
    assert "state.pcdnPendingIntent = enabled" in MODULE
    assert "confirm: true, apply: true" in MODULE
    assert "event.target.checked = !enabled; validatePcdn(enabled);" in MODULE


def test_intrusion_feed_and_signature_control_plane_is_exposed() -> None:
    for endpoint in (
        "/api/v1/aegis/feeds",
        "/api/v1/aegis/feed-status",
        "/api/v1/aegis/feed-update/start",
        "/api/v1/aegis/feed-import/start",
        "/api/v1/aegis/feed-import/status",
        "/api/v1/aegis/signature-categories",
        "/api/v1/aegis/signatures/policies",
        "/api/v1/aegis/signatures/suppress",
        "/api/v1/aegis/signatures/unsuppress",
    ):
        assert endpoint in MODULE
    for field in (
        "target_rev", "enabled_override", "action: draft.action",
        "suppressed: draft.suppressed", "revision: draft.revision",
    ):
        assert field in MODULE
    assert "data-aegis-action=\"intrusion\"" not in MODULE  # generated by actionButton
    assert "actionButton('规则管理', 'intrusion', true)" in MODULE
    assert "apply_required" in MODULE
    assert "当前缺少 Suricata 生产运行组件" in MODULE
    assert "window.clearTimeout(jobPollTimer)" in MODULE
    assert "state.jobPollAttempts >= 180" in MODULE


def test_optional_endpoints_do_not_break_existing_aegis_page() -> None:
    assert "const optionalKeys = new Set(['appBlocks', 'appCatalog', 'pcdn', 'logSettings', 'clients'])" in MODULE
    assert "item.status === 'rejected' && !optionalKeys.has(key)" in MODULE


def test_region_controls_are_compact_and_dependency_gated() -> None:
    assert "const VERSION = '20260730-aegisx-ux-08'" in MODULE
    assert "switchControl('geo-enabled', regionEnabled, !state.saving" in MODULE
    assert "regionEnabled ? `<div class=\"aegisx-region-dependent\">" in MODULE
    assert "shieldBan:" in MODULE
    assert "shieldCheck:" in MODULE
    assert "icon('shieldBan')" in MODULE
    assert "icon('shieldCheck')" in MODULE
    assert 'class="dwrt-kit-switch aegisx-switch' in MODULE
    assert 'data-dwrt-component="switch"' in MODULE
    assert "return bool(geoRule().enabled) && selectedCountries().length > 0;" in MODULE
    assert "state.geoDraftEnabled === null ? geoConfiguredEnabled() : state.geoDraftEnabled" in MODULE
    assert "if (enabled) render();" in MODULE
    assert "else saveGeo({ closeDrawer: false });" in MODULE
    assert "state.saving || !selected ? 'disabled' : ''" in MODULE
    assert ".aegisx-region-actions button { min-width: 76px; height: 36px;" in STYLE
    assert 'button[data-geo-action="block"] svg { color: #e60012; }' in STYLE
    assert 'button[data-geo-action="allow"] svg { color: #00f900; }' in STYLE


def test_tab_persistence_and_page_owned_vertical_scroll() -> None:
    assert "const ACTIVE_TAB_KEY = 'dreamingwrt.aegisx.activeTab.v1'" in MODULE
    assert "sessionStorage.getItem(ACTIVE_TAB_KEY)" in MODULE
    assert "sessionStorage.setItem(ACTIVE_TAB_KEY, value)" in MODULE
    assert 'data-dwrt-tabs-key="aegisx-main"' in MODULE
    assert "rememberTab(state.tab)" in MODULE
    assert "stage?.classList.add('is-aegisx')" in MODULE
    assert "stage?.classList.remove('is-aegisx')" in MODULE
    assert ".aegisx-route-host { height: auto; min-height: 100%; overflow: visible;" in STYLE
    assert ".console-stage.is-policy-table.is-aegisx { height: auto; min-height: 100%; grid-template-rows: auto; overflow: visible; }" in STYLE
    assert ".console-stage.is-policy-table.is-aegisx .route-preview.aegisx-route-host { height: auto; min-height: 100%; overflow: visible; }" in STYLE
    assert ".aegisx-logging-workspace { min-width: 0; min-height: 0; overflow: visible;" in STYLE
    assert ".aegisx-events-card .dwrt-kit-table-wrap { max-height: 430px; overflow: auto; }" in STYLE


def test_geo_sheet_and_honeypot_action_layout() -> None:
    assert 'data-dwrt-sheet-variant="copilot"' in MODULE
    assert "--dwrt-kit-sheet-width: min(100vw, 460px);" in STYLE
    assert ".aegisx-geo-drawer .aegisx-drawer-body { width: 100%; max-width: 100%; overflow-x: hidden; }" in STYLE
    assert ".aegisx-country-list { width: 100%; max-width: 100%;" in STYLE
    assert "overflow-x: hidden;" in STYLE
    assert ".aegisx-honeypot-row { min-width: 0; width: 100%; display: flex; align-items: center; justify-content: flex-start;" in STYLE
    assert ".aegisx-app-drawer," in STYLE
    assert "--dwrt-kit-sheet-width: 100vw; --dwrt-kit-sheet-max-width: 100vw;" in STYLE
    assert 'data-dwrt-modal-variant="copilot"' in MODULE
    assert 'data-dwrt-component="modal"' in MODULE


def test_content_policy_editor_uses_compact_copilot_relationship_rows() -> None:
    assert 'class="aegisx-drawer aegisx-content-drawer' in MODULE
    assert 'data-dwrt-component="sheet"' in MODULE
    assert 'data-dwrt-sheet-variant="copilot"' in MODULE
    for section in ("基本设置", "过滤", "计划"):
        assert section in MODULE
    for control in (
        'data-content-field="name"', "content-enabled", "content-mode",
        "content-ad-block", "data-content-safe-search", "content-schedule",
    ):
        assert control in MODULE
    assert ".aegisx-content-form-row {" in STYLE
    assert "grid-template-columns: 112px minmax(0, 1fr)" in STYLE
    assert ".aegisx-content-drawer.dwrt-page-liquid-glass { --dwrt-kit-sheet-width: min(100vw, 460px); }" in STYLE


def test_menu_versions_and_gzip_parity() -> None:
    menu = json.loads(MENU_PATH.read_text(encoding="utf-8"))
    policy = next(item for item in menu["items"] if item.get("id") == "policy-engine")
    aegis = next(item for item in policy["children"] if item.get("id") == "policy-aegisx")
    assert aegis["module_version"] == "20260730-aegisx-ux-08"
    assert aegis["style_version"] == "20260730-aegisx-ux-08"
    for source in (MODULE_PATH, STYLE_PATH, MENU_PATH):
        compressed = source.with_name(source.name + ".gz")
        assert compressed.is_file(), compressed
        assert gzip.decompress(compressed.read_bytes()) == source.read_bytes(), compressed


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"ok: {len(tests)} Aegisx backend-open frontend contracts")

#!/usr/bin/env python3
"""Static contract for the standalone UPnP service workbench."""

import gzip
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"
MODULE_PATH = WWW / "plugins/native/upnp-service.js"
STYLE_PATH = WWW / "static/css/upnp-service.css"
MODULE = MODULE_PATH.read_text(encoding="utf-8")
STYLE = STYLE_PATH.read_text(encoding="utf-8")
FIXTURE = ROOT / "tests/fixtures/upnp-service.html"
BROWSER_TEST = ROOT / "tools/test_upnp_service_fixture.py"


def test_standalone_owner_does_not_depend_on_shared_network_services() -> None:
    assert "export function mount(context = {})" in MODULE
    assert "network-services.js" not in MODULE
    assert "network-services.css" not in STYLE
    assert "upnp-service-route-host" in MODULE
    assert "upnp-service-route-host" in STYLE


def test_complete_service_field_inventory_is_preserved() -> None:
    fields = (
        "enabled",
        "natpmp_enabled",
        "pcp",
        "secure_mode",
        "log_packets",
        "system_uptime",
        "force_forwarding",
        "use_stun",
        "external_iface",
        "internal_ifaces",
        "port_range.start",
        "port_range.end",
        "download_mbps",
        "upload_mbps",
        "notify_interval",
        "clean_interval",
        "stun_host",
        "stun_port",
    )
    for field in fields:
        assert field in MODULE, field
    for label in (
        "协议与安全",
        "网络边界与端口范围",
        "运行参数",
        "访问控制",
        "动态映射",
        "静态映射",
    ):
        assert label in MODULE, label


def test_rest_and_crud_contracts_remain_complete() -> None:
    for endpoint in (
        "/api/v1/services/upnp",
        "/api/v1/services/upnp/acl",
        "/api/v1/services/upnp/mappings",
    ):
        assert endpoint in MODULE
    assert "async function saveService()" in MODULE
    assert "async function saveAcl()" in MODULE
    assert "async function deleteAcl()" in MODULE
    assert "async function saveMapping()" in MODULE
    assert "async function deleteMapping()" in MODULE
    assert "method: 'PUT'" in MODULE
    assert "method: 'DELETE'" in MODULE
    assert "businessFailed" in MODULE
    assert "![0, 200, 2000].includes(code)" in MODULE
    assert "![0, 200, 2000].includes(payloadCode)" in MODULE
    assert "signal: context.signal" in MODULE


def test_destructive_actions_use_the_shared_confirmation_component() -> None:
    assert "confirmationMarkup" in MODULE
    assert "data-dwrt-confirm-accept" in MODULE
    assert "data-dwrt-confirm-cancel" in MODULE
    assert "state.confirmDelete = 'acl'" in MODULE
    assert "state.confirmDelete = 'mapping'" in MODULE
    assert "再次点击删除" not in MODULE


def test_dynamic_and_static_mappings_cannot_be_merged() -> None:
    assert "state.dynamicMappings = asArray(servicePayload.mappings)" in MODULE
    assert "state.staticMappings = asArray(mappingsResult.value, ['mappings'])" in MODULE
    assert "mapping_type !== 'static'" in MODULE
    assert "mappingRows(state.dynamicMappings, 'dynamic')" in MODULE
    assert "mappingRows(state.staticMappings, 'static')" in MODULE
    dynamic = MODULE[MODULE.index("function dynamicMarkup()") : MODULE.index("function staticMarkup()")]
    assert "data-upnp-edit-mapping" not in dynamic
    assert "由 UPnP IGD、NAT-PMP 或 PCP 客户端申请" in dynamic


def test_every_write_path_is_capability_gated() -> None:
    for capability in (
        "service_update",
        "acl_create",
        "acl_update",
        "acl_delete",
        "mapping_create",
        "mapping_update",
        "mapping_delete",
        "save_upnp_mapping",
        "delete_upnp_mapping",
        "static_mapping_apply",
        "static_mapping_readback",
        "live_packets",
        "natpmp",
        "pcp",
        "stun",
        "stun_host",
        "stun_port",
        "port_range",
        "clean_interval",
        "force_forwarding",
    ):
        assert f"cap('{capability}')" in MODULE, capability
    assert "if (state.saving || !state.dirty || !cap('service_update')) return;" in MODULE
    assert "state.editor._new ? cap('acl_create') : cap('acl_update')" in MODULE
    assert "if (!cap('acl_delete') || state.saving) return;" in MODULE
    assert "state.editor._new ? (cap('mapping_create') || cap('save_upnp_mapping'))" in MODULE
    assert "if (!(cap('mapping_delete') || cap('delete_upnp_mapping')) || state.saving) return;" in MODULE


def test_design_system_and_dense_settings_contract() -> None:
    for component in (
        'data-dwrt-component="surface"',
        'data-dwrt-component="data-table"',
        'data-dwrt-component="switch"',
        'data-dwrt-component="sheet"',
        'data-dwrt-sheet-variant="copilot"',
        'data-dwrt-component="expand-search"',
    ):
        assert component in MODULE, component
    assert "floatingSavebarMarkup" in MODULE
    assert "statusBadgeMarkup" in MODULE
    assert "dwrt-kit-table-wrap" in MODULE
    assert "dwrt-kit-glass-surface" in MODULE
    assert "aria-expanded" in MODULE
    assert "可用性说明" in MODULE
    assert 'data-dwrt-component="tabs"' in MODULE
    assert "grid-template-columns: repeat(2, minmax(0, 1fr))" in STYLE
    assert "@media (max-width: 720px)" in STYLE
    assert "grid-template-columns: 1fr" in STYLE
    assert "@media (prefers-reduced-motion: reduce)" in STYLE
    assert "backdrop-filter" not in STYLE
    assert "letter-spacing: 0" in STYLE


def test_no_fake_runtime_values_or_browser_persistence() -> None:
    assert "localStorage.setItem" not in MODULE
    assert "/etc/config" not in MODULE
    assert "Math.random" not in MODULE
    assert "setInterval" not in MODULE
    assert "live_packets') ? firstNumber(item.packets).toLocaleString() : '--'" in MODULE
    assert "不显示伪造流量" in MODULE


def test_gzip_files_match_sources() -> None:
    for source in (MODULE_PATH, STYLE_PATH):
        compressed = Path(f"{source}.gz")
        assert compressed.is_file(), compressed
        with gzip.open(compressed, "rb") as stream:
            assert stream.read() == source.read_bytes(), compressed


def test_browser_fixture_is_packaged_with_the_contract() -> None:
    assert FIXTURE.is_file()
    assert BROWSER_TEST.is_file()
    fixture = FIXTURE.read_text(encoding="utf-8")
    browser_test = BROWSER_TEST.read_text(encoding="utf-8")
    assert "plugins/native/upnp-service.js" in fixture
    assert "static/css/upnp-service.css" in fixture
    assert "writes" in fixture
    assert "1440" in browser_test and "1024" in browser_test and "390" in browser_test


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_")]
    for test in tests:
        test()
    print(f"ok: {len(tests)} standalone UPnP frontend contracts")

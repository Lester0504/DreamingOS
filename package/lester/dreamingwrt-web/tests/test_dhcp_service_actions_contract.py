#!/usr/bin/env python3
"""Static contract for real DHCP creation actions and Copilot Sheet geometry."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE = (ROOT / "files/www/dreamingwrt/plugins/native/network-services.js").read_text(encoding="utf-8")
STYLE = (ROOT / "files/www/dreamingwrt/static/css/network-services.css").read_text(encoding="utf-8")


def test_create_buttons_have_real_handlers_and_editors() -> None:
    for marker in (
        "openDhcpAccess()",
        "openDhcpPrefix()",
        "state.drawer === 'dhcp-access'",
        "state.drawer === 'dhcp-prefix'",
        "saveDhcpAccess()",
        "saveDhcpPrefix()",
        "deleteDhcpAccess()",
        "deleteDhcpPrefix()",
        "data-dhcp-access",
        "data-dhcp-prefix",
    ):
        assert marker in MODULE, marker


def test_writes_use_the_existing_scope_replace_contract() -> None:
    assert "function dhcpScopePayload(scope, collection = {})" in MODULE
    assert "allow_deny_list: access" in MODULE
    assert "prefix_reservations: prefixes" in MODULE
    assert "JSON.stringify(dhcpScopePayload(scope, { reservations }))" in MODULE
    assert "...scope.raw" not in MODULE


def test_network_service_sheets_use_the_copilot_contract() -> None:
    assert MODULE.count('data-dwrt-component="sheet" data-dwrt-sheet-variant="copilot"') >= 7
    assert "--dwrt-kit-sheet-width: var(--dwrt-kit-sheet-width-standard)" in STYLE
    # 宽度只能引用 Kit 的四档变量，留白用视口表达；写死像素等于页面自建宽度标准。
    assert "--dwrt-kit-sheet-max-width: calc(100vw - 28px)" in STYLE
    assert "min(92vw, 660px)" not in STYLE


def test_dns_scroll_owner_has_a_bounded_parent_height() -> None:
    shell = STYLE[STYLE.index(".network-service-shell {") : STYLE.index(".network-service-page-header")]
    assert "height: 100%" in shell
    workbench = STYLE[STYLE.index(".network-service-workbench {") : STYLE.index(".network-service-toolbar {")]
    assert "min-height: 0" in workbench
    assert "overflow: auto" in workbench


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_")]
    for test in tests:
        test()
    print(f"ok: {len(tests)} DHCP action contracts")

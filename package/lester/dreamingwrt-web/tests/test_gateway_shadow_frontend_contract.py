#!/usr/bin/env python3

import gzip
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"
MODULE_PATH = WWW / "plugins/native/gateway-shadow.js"
STYLE_PATH = WWW / "static/css/gateway-shadow.css"
MENU_PATH = WWW / "static/menu/main.json"
FIXTURE = ROOT / "tests/fixtures/gateway-shadow.html"
BROWSER_TEST = ROOT / "tools/test_gateway_shadow_fixture.py"
MODULE = MODULE_PATH.read_text()
STYLE = STYLE_PATH.read_text()


def test_all_gateway_shadow_routes_are_integrated() -> None:
    for suffix in ("", "/status", "/preflight", "/pairing/start", "/pairing/approve", "/save", "/apply", "/disable"):
        assert f"{suffix}'" in MODULE or suffix == ""
    menu = json.loads(MENU_PATH.read_text())
    system = next(item for item in menu["items"] if item["id"] == "system")
    item = next(item for item in system["children"] if item["id"] == "system-high-availability")
    assert item["module"] == "native/gateway-shadow.js"
    assert item["style"] == "/static/css/gateway-shadow.css"
    assert item["label"] == "高可用性"
    assert item["path"] == "/app/#/system/high-availability"
    network = next(item for item in menu["items"] if item["id"] == "network-config")
    assert not [child for child in network["children"] if child["id"] == "gateway-shadow"]


def test_writes_fail_closed_on_capability_owner_and_preflight() -> None:
    assert "currentRole() === 'owner'" in MODULE
    for capability in ("save", "preflight", "pairing_supported", "apply_supported", "disable_supported"):
        assert f"writeAllowed('{capability}')" in MODULE
    assert "!state.preflight?.ready" in MODULE
    assert "state.dirty || !state.preflight?.ready" in MODULE
    assert "data-shadow-confirm=\"apply\"" in MODULE
    assert "data-shadow-confirm=\"disable\"" in MODULE
    assert "confirmationMarkup" in MODULE
    assert "force primary" not in MODULE.lower()


def test_sensitive_material_is_ephemeral_and_write_only() -> None:
    assert "type=\"password\"" in MODULE
    assert "autocomplete=\"off\"" in MODULE
    assert "input.value = ''" in MODULE
    assert "clearPairingSecrets()" in MODULE
    for forbidden in ("localStorage.setItem", "sessionStorage", "indexedDB"):
        assert forbidden not in MODULE
    assert "auth_key" not in MODULE[MODULE.index("const DEFAULT_CONFIG"):MODULE.index("const state")]


def test_risk_and_unknown_states_are_explicit() -> None:
    for text in ("best effort", "split-brain", "peer_reachable", "keepalived", "conntrackd", "MASTER", "BACKUP", "FAULT"):
        assert text.lower() in MODULE.lower()
    assert "triState(state.status.peer_reachable)" in MODULE
    assert "state.preflight.checks" in MODULE
    assert "state.preflight.errors" in MODULE


def test_design_system_and_responsive_contract() -> None:
    for component in ('data-dwrt-component=\"surface\"', 'data-dwrt-component=\"tabs\"', 'data-dwrt-component=\"switch\"', "data-adaptive-sample"):
        assert component in MODULE
    assert "@media (max-width: 980px)" in STYLE
    assert "@media (max-width: 720px)" in STYLE
    assert "@media (prefers-reduced-motion: reduce)" in STYLE
    assert "backdrop-filter" not in STYLE
    assert "letter-spacing: 0" in STYLE


def test_glass_material_matches_shared_page_surface() -> None:
    # design.md: wallpaper-facing panels must consume the shared kit glass material
    # and must not paint a competing background locally.
    assert MODULE.count("dwrt-kit-glass-surface") >= 6
    for panel in ("shadow-surface", "shadow-operation-bar", "shadow-preflight", "shadow-availability", "shadow-risk"):
        marker = f'class="{panel}'
        index = MODULE.index(marker)
        assert "dwrt-kit-glass-surface" in MODULE[index:index + 200], panel
    assert "shadow-risk { border" in STYLE
    assert "background: color-mix(in srgb, var(--color-warning" not in STYLE


def test_gzip_assets_match_sources() -> None:
    for source in (MODULE_PATH, STYLE_PATH, MENU_PATH):
        compressed = Path(f"{source}.gz")
        assert compressed.is_file()
        with gzip.open(compressed, "rb") as stream:
            assert stream.read() == source.read_bytes()


def test_browser_fixture_covers_required_viewports() -> None:
    assert FIXTURE.is_file() and BROWSER_TEST.is_file()
    source = BROWSER_TEST.read_text()
    assert "1440" in source and "1024" in source and "375" in source
    assert "writes" in FIXTURE.read_text()


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_")]
    for test in tests:
        test()
    print(f"ok: {len(tests)} Gateway Shadow frontend contracts")

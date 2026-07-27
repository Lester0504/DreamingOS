#!/usr/bin/env python3
"""Contracts for shared drawers, save bars, tooltips, and status badges."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "files" / "www" / "dreamingwrt" / "static"
NATIVE = ROOT / "files" / "www" / "dreamingwrt" / "plugins" / "native"

kit_js = (STATIC / "ui-kit" / "dwrt-ui-kit.js").read_text(encoding="utf-8")
kit_css = (STATIC / "ui-kit" / "dwrt-ui-kit.css").read_text(encoding="utf-8")
client_js = (STATIC / "js" / "client-details.js").read_text(encoding="utf-8")
client_css = (STATIC / "css" / "client-details.css").read_text(encoding="utf-8")
shell = (STATIC / "js" / "menu-shell.js").read_text(encoding="utf-8")
notification_js = (NATIVE / "notification-push.js").read_text(encoding="utf-8")
routing_js = (NATIVE / "routing-table.js").read_text(encoding="utf-8")
file_services_js = (NATIVE / "storage-file-services.js").read_text(encoding="utf-8")

# A body-level tooltip must never survive removal of its trigger or navigation.
assert "if (!trigger?.isConnected) {\n      closeTooltip(trigger);" in kit_js
assert "if (!trigger.isConnected || activeTooltip !== trigger)" in kit_js
assert "function unmountTooltip(trigger)" in kit_js
assert "window.addEventListener('hashchange', () => closeTooltip())" in kit_js
assert "window.addEventListener('pagehide', () => closeTooltip())" in kit_js
assert "document.addEventListener('visibilitychange'" in kit_js
assert "function syncMountedSheetGeometry()" in kit_js
assert "sheet.offsetWidth || Number.parseFloat(getComputedStyle(sheet).width)" in kit_js

# Status semantics are owned by one explicit Kit renderer, not text observers.
assert "function statusBadgeMarkup(label, tone = 'muted', options = {})" in kit_js
assert "function normalizeStatusTone(tone)" in kit_js
assert "statusBadgeMarkup," in kit_js
assert "statusBadgeMarkup: (...args)" in shell
assert "if (routePreview) window.DWRT_UI_KIT?.unmount?.(routePreview);" in shell
for tone in ("success", "warning", "error", "info", "muted"):
    assert f".dwrt-kit-status-badge.is-{tone}" in kit_css
assert "min-height: 22px" in kit_css
assert ".route-preview .dwrt-kit-status-badge" in kit_css
assert "[data-dwrt-component] .dwrt-kit-status-badge" in kit_css
assert "notification-state" not in notification_js
assert "routing-state" not in routing_js
assert "file-service-state" not in file_services_js
assert "statusBadgeMarkup" in notification_js
assert "statusBadgeMarkup" in routing_js
assert "statusBadgeMarkup" in file_services_js

# Dirty actions remain visible at the content viewport edge on long pages.
savebar_css = kit_css[kit_css.index(".dwrt-floating-savebar {"):kit_css.index(".dwrt-kit-savebar.is-hidden")]
assert "position: fixed" in savebar_css
assert "var(--app-menu-glass-width" in savebar_css
assert "var(--dwrt-glass-neutral-density, .06)" in savebar_css
assert "position: sticky" not in savebar_css
assert "calc(100vw - var(--app-menu-glass-width, 48px) - 16px)" in kit_css

# Terminal details retain the centered dialog interaction while using the shared copilot material.
drawer_start = client_js.index("    function detailDrawer()")
drawer_end = client_js.index("\n\n    function columnFilterUnits", drawer_start)
drawer = client_js[drawer_start:drawer_end]
assert "dwrt-kit-modal-layer client-detail-layer" in drawer
assert "dwrt-kit-modal client-detail-drawer" in drawer
assert 'data-dwrt-modal-variant="copilot"' in drawer
assert 'data-dwrt-component="modal"' in drawer
assert "client-stable-glass" not in drawer
assert "dwrt-kit-sheet client-detail-drawer" not in drawer
assert "dwrt-kit-sheet-overlay" not in drawer
assert "backdrop-filter: blur(10px)" not in client_css
assert ".client-detail-layer .dwrt-kit-modal-backdrop" in client_css
assert "background: rgba(2, 7, 15, 0.16)" in client_css
assert '.dwrt-kit-modal[data-dwrt-modal-variant="copilot"]' in kit_css
assert "if (dialog.dataset.dwrtModalVariant === 'copilot') ensureSheetMaterial(dialog);" in kit_js

# The three known page-local save bars consume the shared markup and selectors.
for path, legacy in (
    (NATIVE / "wifi-management.js", "wifi-save-bar"),
    (NATIVE / "network-services.js", "network-service-savebar"),
    (NATIVE / "system-terminal.js", "system-terminal-savebar"),
):
    source = path.read_text(encoding="utf-8")
    assert "floatingSavebarMarkup" in source, path.name
    assert legacy not in source, path.name

print("overlay, savebar, tooltip, and status contracts passed")

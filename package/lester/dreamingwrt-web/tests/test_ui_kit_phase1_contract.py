#!/usr/bin/env python3
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KIT_JS = (ROOT / "files/www/dreamingwrt/static/ui-kit/dwrt-ui-kit.js").read_text(encoding="utf-8")
KIT_CSS = (ROOT / "files/www/dreamingwrt/static/ui-kit/dwrt-ui-kit.css").read_text(encoding="utf-8")
SHELL = (ROOT / "files/www/dreamingwrt/static/js/menu-shell.js").read_text(encoding="utf-8")
APP = (ROOT / "files/www/dreamingwrt/app/index.html").read_text(encoding="utf-8")

assert "observer.observe(document.documentElement" not in KIT_JS
assert "function mount(context = document)" in KIT_JS
assert "function unmount(context)" in KIT_JS
assert "function matchingRoots(context, selector)" in KIT_JS
assert "matchingRoots(context, '.dwrt-kit-modal-layer, [data-dwrt-component=\"modal\"]')" in KIT_JS
assert "mount(document.getElementById('appShell') || document)" in KIT_JS

for component in (
    "button",
    "icon-button",
    "async-button",
    "select",
    "combobox",
    "field",
    "switch",
    "toolbar",
    "disclosure",
    "dependency-group",
    "state-panel",
    "data-table",
    "data-grid",
    "virtual-data-table",
    "filter-sheet",
    "page-shell",
):
    assert f"data-dwrt-component=\"{component}\"" in KIT_JS or f"componentRoots(context, '{component}')" in KIT_JS or f"['button', 'icon-button', 'async-button']" in KIT_JS

assert "min-width: 44px" in KIT_CSS
assert "min-height: 44px" in KIT_CSS
assert '.dwrt-kit-dependency-group > [data-dwrt-dependency-panel]::before' in KIT_CSS
assert '.dwrt-kit-combobox-trigger' in KIT_CSS
assert 'aria-multiselectable' in KIT_JS
assert '.dwrt-kit-state-panel' in KIT_CSS
assert '[data-dwrt-component][hidden]' in KIT_CSS
assert '.dwrt-kit-sheet-overlay[hidden]' in KIT_CSS
sheet_overlay = KIT_CSS[KIT_CSS.index('.dwrt-kit-sheet-overlay {'):KIT_CSS.index('.dwrt-kit-sheet {')]
assert 'pointer-events: none' in sheet_overlay
assert '.dwrt-kit-sheet-overlay.is-open' in sheet_overlay
assert 'pointer-events: auto' in sheet_overlay
assert '.dwrt-kit-page-shell' in KIT_CSS
assert '.dwrt-kit-virtual-table' in KIT_CSS
assert '.dwrt-kit-data-grid' in KIT_CSS
assert '.dwrt-kit-filter-sheet' in KIT_CSS
assert 'function mountDataGrid(root)' in KIT_JS
assert 'dwrt-grid-activate' in KIT_JS
assert 'function updateVirtualDataTable(root, force = true)' in KIT_JS
assert "const loading = declaredState ? declaredState === 'loading'" in KIT_JS
assert "button.getAttribute('aria-busy') !== busy" in KIT_JS
assert "button.getAttribute('aria-disabled') !== 'true'" in KIT_JS
assert "state.sheet?.dataset.dwrtReturnFocus || state.triggerSelector" in KIT_JS
assert "selected instanceof HTMLElement ? selected : state.trigger?.isConnected" in KIT_JS
assert '[data-dwrt-surface="stable-glass"]' in KIT_CSS
assert '[data-dwrt-surface="dense-surface"]' in KIT_CSS
assert 'background: var(--color-surface-stable' in KIT_CSS
assert 'background: var(--color-surface-dense' in KIT_CSS
assert '@media (prefers-reduced-transparency: reduce)' in KIT_CSS

assert 'id="aiBootstrap"' in APP
# Kit 与会话闸门的缓存键都随内容变更 bump，这里只守"引用存在且外壳预热用同一个键"。
_gate = re.compile(r"/static/js/dwrt-session-gate\.js\?v=([0-9a-z.-]+)")
_kit_js = re.compile(r"/static/ui-kit/dwrt-ui-kit\.js\?v=([0-9a-z.-]+)")
_kit_css = re.compile(r"/static/ui-kit/dwrt-ui-kit\.css\?v=([0-9a-z.-]+)")
PREWARM = (ROOT / "files/www/dreamingwrt/static/js/shell-prewarm.js").read_text(encoding="utf-8")
for label, pattern in (("session-gate", _gate), ("ui-kit.js", _kit_js), ("ui-kit.css", _kit_css)):
    in_app = pattern.findall(APP)
    in_prewarm = pattern.findall(PREWARM)
    assert in_app, f"app/index.html 必须带版本号引用 {label}"
    assert in_prewarm, f"shell-prewarm.js 必须带版本号预热 {label}"
    assert set(in_app) == set(in_prewarm), (
        f"{label} 缓存键不一致: app={in_app} prewarm={in_prewarm}"
    )
assert 'id="sessionRecovery"' in APP
assert "window.DWRT_SESSION.fetch" in SHELL
assert "window.DWRT_SESSION.refresh" in SHELL
assert "dwrt-sheet-focus-restored" in KIT_JS
assert "now - startedAt >= 480" in KIT_JS
assert "document.addEventListener('keydown', onDocumentKeydown, true)" in KIT_JS
assert "document.removeEventListener('keydown', state.onDocumentKeydown, true)" in KIT_JS
assert "openSheets.at(-1) !== sheet" in KIT_JS
main_start = SHELL.index("function main()")
main_body = SHELL[main_start:SHELL.index("main();", main_start)]
assert "ensureGlobalAi();" not in main_body
assert "aiBootstrap?.addEventListener('click', () => openGlobalAi())" in SHELL
assert "loadPageStyle(GLOBAL_AI_ASSETS.style)" in SHELL
assert "aiGlobalRoot.replaceChildren(aiBootstrap)" in SHELL
assert "aiBootstrap?.setAttribute('aria-busy', 'false')" in SHELL

print("ok: UI Kit uses explicit component mount/unmount and global AI is interaction-gated")

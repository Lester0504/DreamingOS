#!/usr/bin/env python3
import gzip
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"
APP = (WWW / "app/index.html").read_text(encoding="utf-8")
SHELL = (WWW / "static/js/menu-shell.js").read_text(encoding="utf-8")
STYLE = (WWW / "static/css/menu-shell.css").read_text(encoding="utf-8")
PREWARM = (WWW / "static/js/shell-prewarm.js").read_text(encoding="utf-8")


assert 'class="dwrt-kit-modal-layer session-recovery-layer"' in APP
assert APP.count('id="sessionRecovery"') == 1
assert 'class="session-recovery-clip"' in APP
assert 'class="dwrt-kit-modal session-recovery-dialog"' in APP
assert 'role="alertdialog"' in APP and 'aria-modal="true"' in APP
assert 'data-lucide="key-round"' in APP
assert 'data-lucide="log-in"' in APP
assert "登录状态已失效" in APP
assert "为了确保您的网络安全，系统需要重新验证您的身份。重新登录后，您将返回当前路径。" in APP
assert "重新验证并登录" in APP
assert '<button class="session-recovery-login" id="sessionRecoveryLogin" data-dwrt-component="button" data-variant="primary"' in APP
assert '<a id="sessionRecoveryLogin"' not in APP
assert "Token expired / Re-authentication required" in APP
assert APP.index('id="sessionRecoveryLogin"') < APP.index('id="sessionRecoveryHint"')
assert "emoji" not in APP[APP.index('id="sessionRecovery"'):APP.index('id="sessionRecovery"') + 2200].lower()

recovery_start = SHELL.index("function initSessionRecovery()")
recovery_end = SHELL.index("async function refreshAuthToken()", recovery_start)
recovery = SHELL[recovery_start:recovery_end]
assert "login.dataset.loginUrl = detail.loginUrl" in recovery
assert "if (!recovery.hidden && recovery.classList.contains('is-open')) return;" in recovery
assert "window.DWRT_UI_KIT?.mount(recovery)" in recovery
assert "window.DWRTSampledLiquidGlass" in recovery
assert "root: dialog" in recovery
assert "backgroundElement: appWallpaper" in recovery
assert "cornerRadius: 20" in recovery
assert "neutralDensity: 0.06" in recovery
assert "mapResolution: 0.25" in recovery
assert "trackMotion: false" in recovery
assert "trackScroll: false" in recovery
assert "glassRenderer?.destroy?.()" in recovery
assert "login.disabled = false" in recovery
assert "login.removeAttribute('aria-busy')" in recovery
assert "window.DWRT_SESSION?.clear?.()" in recovery
assert "location.href = loginUrl" in recovery
assert "login.setAttribute('aria-busy', 'true')" in recovery
assert "window.addEventListener('dwrt-session-required'" in recovery
assert "window.addEventListener('dwrt-session-restored'" in recovery

assert ".session-recovery-layer" in STYLE
assert "--dwrt-kit-modal-width: 440px" in STYLE
assert ".dwrt-app #sessionRecoveryLogin.dwrt-kit-button" in STYLE
recovery_style = STYLE[STYLE.index(".session-recovery-layer"):STYLE.index("@media (prefers-reduced-motion", STYLE.index(".session-recovery-layer"))]
assert "background: transparent" in recovery_style
assert "backdrop-filter: none" in recovery_style
assert "linear-gradient(135deg, #087cff 0%, #13b9f4 100%) !important" in recovery_style
assert "color: #fff" in recovery_style
assert "inset 0 1px 0 rgb(255 255 255 / .32) !important" in recovery_style
assert "backdrop-filter: none !important" in recovery_style
assert ".session-recovery-clip" in recovery_style
assert "contain: paint" in recovery_style
assert "clip-path: inset(0 round 20px)" in recovery_style
assert "-webkit-mask-image: -webkit-radial-gradient(white, black)" in recovery_style
assert recovery_style.index(".session-recovery-clip") < recovery_style.index(".session-recovery-dialog")
assert "border-radius: 32px" not in STYLE
assert "backdrop-filter: blur(80px)" not in STYLE

for resource in (
    "app/index.html",
    "static/css/menu-shell.css",
    "static/js/menu-shell.js",
    "static/js/shell-prewarm.js",
):
    source = WWW / resource
    compressed = source.with_name(source.name + ".gz")
    assert compressed.is_file(), f"missing gzip: {resource}"
    assert gzip.open(compressed, "rb").read() == source.read_bytes(), f"stale gzip: {resource}"

assert "/static/css/menu-shell.css?v=20260730-session-recovery-clip-06" in APP
assert "/static/js/menu-shell.js?v=20260731-policy-runtime-evidence-01" in APP
assert "/static/js/shell-prewarm.js?v=20260731-policy-runtime-evidence-01" in APP
assert "/static/css/menu-shell.css?v=20260730-session-recovery-clip-06" in PREWARM
assert "/static/js/menu-shell.js?v=20260731-policy-runtime-evidence-01" in PREWARM

print("ok: expired sessions use one sampled-glass UI Kit modal with a clear primary re-authentication action")

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOGIN_CSS = ROOT / "files/www/dreamingwrt/login/login.css"
LOGIN_HTML = ROOT / "files/www/dreamingwrt/login/index.html"

css = LOGIN_CSS.read_text(encoding="utf-8")
html = LOGIN_HTML.read_text(encoding="utf-8")

assert "animation: loginSlideIn 820ms cubic-bezier(0.22, 1, 0.36, 1) backwards" in css
assert ".login-card-clip" in css
assert "contain: paint" in css
assert "border-radius: var(--lg-corner-radius)" in css
assert "<div class=\"login-card-clip\">" in html
assert ".liquid-card > .dwrt-sampled-glass-media" in css
assert "transform: none" in css
assert "will-change: auto" in css
assert "20260725-corner-clip-01" in html
assert "20260730-safari-glass-lite-06" in html
assert "loginGlassClipId" not in html
assert "loginGlassFilteredLayer" not in html
assert "loginGlassSourceLayer" not in html

# The correction must preserve the explicit sampled renderer and its glass contract.
assert "DWRTSampledLiquidGlass.create" in html
assert "svg-explicit-sampling" in html
assert "backdrop-filter: none" in css

#!/usr/bin/env python3
"""Console stage keeps one route width and leaves the version footer on screen.

Routes used to split between a 1180px column and full-bleed hosts, which made
the same console read as two different layouts. The stage also claimed the whole
viewport height, so the footer could only be reached by scrolling.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSS = (ROOT / "files/www/dreamingwrt/static/css/menu-shell.css").read_text()
APP = (ROOT / "files/www/dreamingwrt/app/index.html").read_text()
PREWARM = (ROOT / "files/www/dreamingwrt/static/js/shell-prewarm.js").read_text()


def block(selector: str) -> str:
    match = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", CSS)
    assert match, f"missing rule: {selector}"
    return match.group(1)


workspace = block(".route-workspace")
assert "width: 100%" in workspace, "route workspace must fill the stage"
assert "min(1180px" not in workspace, "route workspace must not reintroduce the narrow column"
assert "align-content: start" in workspace, "workspace content must start at the top once it stretches"

stage = block(".console-stage")
assert "min-height: var(--app-stage-height)" in stage, "stage must reserve room for the version footer"
assert "min-height: 100dvh" not in stage, "stage must not claim the full viewport height"
assert "grid-template-rows: auto minmax(0, 1fr)" in stage, "header takes its natural height, workspace absorbs the rest"
assert "align-items: end" not in stage, "bottom-aligned rows push short pages down to the footer"

root = block(":root")
assert "--app-page-footer-height" in root, "footer height must be a shared token"
assert "--app-stage-height" in root, "stage height must be a shared token"

# Every full-bleed route must claim the shared stage height. A raw 100dvh covers
# the whole viewport, which is exactly how the footer became unreachable.
for path in sorted((ROOT / "files/www/dreamingwrt/static/css").glob("*.css")):
    text = path.read_text()
    for match in re.finditer(r"((?:\.console-stage(?::has\([^)]*\))?[^{,]*)(?:,\s*\.console-stage(?::has\([^)]*\))?[^{,]*)*)\{([^}]*)\}", text, re.S):
        head, body = match.group(1), match.group(2)
        if "route-preview" in head and "has(" not in head:
            continue
        assert not re.search(r"(min-)?height:\s*100dvh", body), (
            f"{path.name}: stage rule must use var(--app-stage-height), not a raw 100dvh\n{head.strip()[:90]}"
        )

footer = block(".console-page-footer")
assert "position: fixed" not in footer, "footer must stay in flow so long pages can push it below the fold"

# The footer must never displace content or cut through a page-level rail.
SHELL_JS = (ROOT / "files/www/dreamingwrt/static/js/menu-shell.js").read_text()

assert "--console-footer-inset" in footer, "footer must keep clear of a page rail measured by the shell"
rule = block(".console-page-footer::before")
assert "--console-footer-inset" in rule, "the footer rule must start after the rail, not cross it"
assert "--app-page-footer-reserve" in block(":root"), "the reserved strip must be its own token"
assert "--app-stage-height: calc(100dvh - var(--app-page-footer-reserve))" in block(":root"), (
    "stage height must follow the reserve token so releasing the strip gives the rows back"
)
reserve_off = re.search(r'html\[data-footer-reserve="off"\]\s*\{([^}]*)\}', CSS)
assert reserve_off and "--app-page-footer-reserve: 0px" in reserve_off.group(1), (
    "a route that already scrolls must get the reserved strip back"
)
for symbol in ("footerRailInset", "syncPageFooterLayout", "resetPageFooterReserve", "initPageFooterLayout"):
    assert symbol in SHELL_JS, f"footer layout hook missing: {symbol}"
# Reserve decisions must be one-way per render, otherwise releasing the strip
# makes the stage taller, clears the overflow, and the footer oscillates.
sync = re.search(r"function syncPageFooterLayout\(\)\s*\{(.*?)\n  \}", SHELL_JS, re.S)
assert sync, "syncPageFooterLayout must exist"
assert "dataset.footerReserve === 'off'" in sync.group(1), "the strip must not be reclaimed inside a single pass"

# The stage geometry lives in menu-shell.css, which carries its own cache key.
# A stale key means browsers keep the previous layout no matter what shipped.
keys = set(re.findall(r"/static/css/menu-shell\.css\?v=([\w.-]+)", APP + PREWARM))
assert len(keys) == 1, f"menu-shell.css cache key must agree across shell entry points: {keys}"

print("ok: console stage uses one route width, and the footer avoids page rails without displacing content")

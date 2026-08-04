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
# The inset must move the footer's own box, not just its inner padding. Padding
# alone left the element spanning the whole column, so the rule and the centred
# text cleared the rail while the band itself still ran across the rail's bottom
# edge -- which is what the user kept reporting as the footer slicing the side
# menu. Once the box itself is offset, the rule is correctly measured from the
# footer's own left edge and must NOT add the inset a second time.
assert "margin-left: var(--console-footer-inset" in footer, (
    "the inset must offset the footer box itself, not only its padding"
)
rule = block(".console-page-footer::before")
assert "--console-footer-inset" not in rule, (
    "the box is already offset, so adding the inset to the rule would double-count it"
)
# An aside footer releases the reserved strip so the rail reaches the window
# bottom: the strip only ever sat under the rail, and that empty band is what read
# as a chunk cut out of the side menu (measured gapUnderRail=58 at 100% and 125%).
#
# Releasing it is only safe together with the other two halves, so all three are
# pinned. Earlier attempts each failed on exactly one of them: releasing the strip
# with the footer still in flow pushed it off-screen on non-scrolling routes, and
# growing only the rail left its last rows clipped by .route-workspace because the
# stage still ended at the old height.
aside = re.search(r'html\[data-footer-aside="on"\]\s*\{([^}]*)\}', CSS)
assert aside and "--app-page-footer-reserve: 0px" in aside.group(1), (
    "an aside footer must release the strip, otherwise the rail keeps a dead band "
    "under it that browser zoom magnifies"
)
aside_footer = re.search(
    r'html\[data-footer-aside="on"\] \.console-page-footer\s*\{([^}]*)\}', CSS
)
assert aside_footer, "the aside footer needs its own rule once the strip is released"
assert "position: absolute" in aside_footer.group(1), (
    "releasing the strip while the footer stays in flow pushes it off-screen on a "
    "route that does not scroll -- it must be anchored to the scroll container"
)
assert "pointer-events: none" in aside_footer.group(1), (
    "the band overlays the content column, so it must not swallow clicks"
)
column = re.search(
    r'html\[data-footer-aside="on"\] \[data-footer-content-column="on"\]\s*\{([^}]*)\}', CSS
)
assert column and "padding-bottom: var(--app-page-footer-height)" in column.group(1), (
    "the column beside the rail must reserve the band's height or the footer covers "
    "its last row"
)
assert "footerContentColumns" in SHELL_JS, (
    "the shell must tag the content column itself: which element holds the content "
    "differs per route and a CSS sibling selector picked the wrong one"
)
# A column that cannot reflow (topology's absolutely positioned canvas layers)
# must abort the overlay so that route keeps its strip, rather than have the band
# painted over a graph that cannot scroll out from under it.
assert "unpaddable" in SHELL_JS, (
    "columns that cannot reflow must skip the overlay instead of being padded"
)
assert "footerAside" in SHELL_JS, "the shell must flag the aside state it measured"
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

# The strip only ever sat under the rail, so the rail stopping one strip above the
# window bottom left an empty band that read as a chunk cut out of the side menu.
# Measured on 30.1 as gapUnderRail=58 at both 100% and 125% zoom.
#
# Growing just the rail was tried and reverted: .route-workspace still clipped at
# the old stage bottom, so the taller rail box was invisible and its last rows were
# cut off instead (hidden=58 with clipped filter labels on flows, logs and
# wireless-status). The strip is released instead, which the assertions above pin.
assert "footerRailBleed" in SHELL_JS, (
    "the shell must still mark the rail it measured so the overlay can be scoped"
)

# A full-height page rail stops one stage gutter short of the footer, so a fixed
# 4px window never saw it and the footer rule was drawn straight through the rail
# (wireless status, system terminal, web-auth designer). The reach must be
# measured from the stage padding instead of hard-coded.
rail_fn = re.search(r"function footerRailInset\(\)\s*\{(.*?)\n  \}", SHELL_JS, re.S)
assert rail_fn, "footerRailInset must exist"
rail_body = rail_fn.group(1)
assert "paddingBottom" in rail_body, (
    "rail detection must measure the stage gutter; a rail ending one gutter above "
    "the footer is still being cut off"
)
assert not re.search(r"rect\.bottom >= band\.top - 4\b", rail_body), (
    "the band test must use the measured reach, not a fixed 4px window"
)
# Width alone mislabels a wide rail such as the web-auth control column, which
# crosses 45% of the content column below ~1180px.
assert "hasWiderRightSibling" in rail_body, (
    "a rail that is the narrow half of a side-by-side split must be honoured"
)
assert "function hasWiderRightSibling" in SHELL_JS, "hasWiderRightSibling helper missing"
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

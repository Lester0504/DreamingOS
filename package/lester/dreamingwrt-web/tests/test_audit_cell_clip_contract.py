"""Audit table cells truncate instead of running into the next column.

`table-layout: fixed` gives every audit column 125px, but the two-line cells hold a
MAC plus IP, or a domain plus its full URL, on `white-space: nowrap`. Measured on
30.1 the subtitle overflowed its column by 146px on 终端 and 110px on 域名 / URL,
which is the text-on-text the user reported.

Two separate causes, both pinned here:

1. `menu-shell.css` had a bare `.route-preview span { display: block }`. That is the
   shell's eyebrow styling, but `.route-preview` is the whole route host, so it hit
   every span in page content and forced the cell wrapper back to `block`. With the
   wrapper not a grid, its `strong`/`small` stayed inline, and `overflow: hidden`
   plus `text-overflow: ellipsis` do nothing on an inline box, so nothing truncated.
2. The cell needs a width bound, or the ellipsis has nothing to clip against.

The full value goes on the kit tooltip so clipping does not hide information.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"
SHELL_CSS = (WWW / "static/css/menu-shell.css").read_text(encoding="utf-8")
FLOWS_CSS = (WWW / "static/css/insights-flows.css").read_text(encoding="utf-8")
FLOWS_JS = (WWW / "static/js/insights-flows.js").read_text(encoding="utf-8")

# The shell eyebrow rule must not reach into page content.
assert not re.search(r"^\.route-preview span,", SHELL_CSS, re.M), (
    "a bare `.route-preview span` rule restyles every span in every page's content; "
    "it forced the audit cell wrapper to display:block and broke its ellipsis"
)
assert ".route-preview > span," in SHELL_CSS, (
    "the eyebrow rule must stay scoped to the route host's own direct child"
)

# The cell has to be a grid (so its rows are block boxes that can ellipsis) and
# bounded by its column.
cell = re.search(r"\.insights-audit-main-cell \{([^}]*)\}", FLOWS_CSS)
assert cell, "missing .insights-audit-main-cell rule"
assert "display: grid" in cell.group(1), (
    "the wrapper must be a grid: inline rows cannot be truncated with an ellipsis"
)
assert "max-width: 100%" in cell.group(1), (
    "without a width bound the grid item just grows and the text overruns the column"
)

rows = re.search(
    r"\.insights-audit-main-cell strong,\s*\.insights-audit-main-cell small \{([^}]*)\}",
    FLOWS_CSS,
)
assert rows, "missing the shared strong/small truncation rule"
for declaration in ("overflow: hidden", "text-overflow: ellipsis", "white-space: nowrap"):
    assert declaration in rows.group(1), f"cell rows must keep `{declaration}`"

# Clipping is only acceptable because the full text stays reachable on hover.
assert "data-dwrt-tooltip" in FLOWS_JS, (
    "truncated cells must expose the full value through the kit tooltip"
)
cell_fn = re.search(r"function auditMainCell\([^)]*\) \{(.*?)\n    \}", FLOWS_JS, re.S)
assert cell_fn, "auditMainCell not found"
assert "data-dwrt-tooltip" in cell_fn.group(1), (
    "auditMainCell itself must carry the tooltip, since it renders both clipped rows"
)

# Every audit overview card supplies an icon. The kit renders whatever markup it is
# handed, so a stats entry without one leaves a visibly empty icon slot; 20 such
# slots were blank across the five activity sub-pages.
assert "AUDIT_STAT_ICONS" in FLOWS_JS and "function auditStatIcon(" in FLOWS_JS, (
    "audit stats need an icon set, otherwise the overview cards render empty slots"
)
stats_blocks = re.findall(r"const stats = \[(.*?)\n      \];", FLOWS_JS, re.S)
assert stats_blocks, "no audit stats arrays found"
for block in stats_blocks:
    entries = [line for line in block.split("\n") if "label:" in line]
    for entry in entries:
        assert "auditStatIcon(" in entry, (
            f"every audit stat needs an icon or its card shows an empty slot: {entry.strip()[:70]}"
        )

print("ok: audit cells truncate with a tooltip, and every overview card has an icon")

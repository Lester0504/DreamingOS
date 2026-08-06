#!/usr/bin/env python3
"""Insights/activity: the footer yields, the chart is real, the header sticks.

Four defects this pins, all reported against the live page:

1. The version footer kept a full 58px band on a route whose table scrolls.
   test_console_stage_layout_contract.py already covers releasing the reserved
   strip, but releasing it was not enough: in the overlay state the content
   column re-reserves --app-page-footer-height so the band has something to sit
   over, so the rows the stage gave up were handed straight back. Measured on
   30.1 at 1440x900: table viewport 402px against 19257px of rows.

2. The trend chart was hand-drawn SVG with preserveAspectRatio="none", which
   scales the viewBox non-uniformly and deforms the axis numbers along with it.
   Text cannot opt out of that scale, so the SVG had to go.

3. 统计 had no switch, so the chart could not be dismissed to give the table the
   whole board.

4. The table header scrolled away, so a row 400 lines down had unlabelled
   columns.

This file guards source symbols only. Geometry and occlusion are measured by
tests/test_insights_activity_layout_geometry_contract.mjs -- passing here does
not prove any of it renders.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"
SHELL_CSS = (WWW / "static/css/menu-shell.css").read_text()
FLOWS_JS = (WWW / "static/js/insights-flows.js").read_text()
FLOWS_CSS = (WWW / "static/css/insights-flows.css").read_text()


def block(css: str, selector: str) -> str:
    match = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", css)
    assert match, f"missing rule: {selector}"
    # Comments are stripped so an assertion cannot be satisfied (or defeated) by
    # prose: these rules carry long explanations that mention the very properties
    # and functions being asserted against.
    return re.sub(r"/\*.*?\*/", "", match.group(1), flags=re.S)


def test_footer_collapses_on_scrolling_routes() -> None:
    root = block(SHELL_CSS, ":root")
    assert "--app-page-footer-compact" in root, (
        "the collapsed band height must be its own token, not a literal buried in a rule"
    )
    # The band itself shrinks...
    compact = block(SHELL_CSS, 'html[data-footer-reserve="off"] .console-page-footer')
    assert "min-height: var(--app-page-footer-compact)" in compact, (
        "a scrolling route must collapse the band, otherwise the footer keeps charging "
        "a full 58px for one line of text"
    )
    # ...and the content column must stop reserving the full height, which is the
    # half that was missing: the stage released the strip and the column took it back.
    column = block(
        SHELL_CSS,
        'html[data-footer-reserve="off"][data-footer-aside="on"] [data-footer-content-column="on"]',
    )
    assert "padding-bottom: var(--app-page-footer-compact)" in column, (
        "releasing the strip is pointless while the content column still reserves the "
        "full band height for the overlay to sit over"
    )
    # The footer must stay readable and in flow -- collapsing is not hiding.
    assert "display: none" not in compact and "position: fixed" not in compact, (
        "the band collapses; it must not be hidden or pinned"
    )


def test_activity_chart_is_echarts_not_scaled_svg() -> None:
    markup = FLOWS_JS[FLOWS_JS.index("function activityChartMarkup") :]
    markup = markup[: markup.index("\n    function activityTimeLabel")]
    # Scoped to the chart on purpose: the flow map's route layer legitimately uses
    # preserveAspectRatio="none" to stretch a 0-100 coordinate overlay, and it
    # carries no text to deform.
    assert "<svg" not in markup, (
        "a non-uniformly scaled viewBox deforms the axis labels; the chart must not "
        "be hand-drawn SVG"
    )
    assert "activity-y-label" not in FLOWS_CSS and "activity-x-label" not in FLOWS_CSS, (
        "the hand-drawn axis label styles must go with the SVG they styled"
    )
    for symbol in ("activityChartOption", "renderActivityChart", "disposeActivityChart"):
        assert symbol in FLOWS_JS, f"activity chart hook missing: {symbol}"
    assert "data-insights-activity-chart" in FLOWS_JS, "the chart needs a mount target"
    option = FLOWS_JS[FLOWS_JS.index("function activityChartOption") :]
    option = option[: option.index("\n    function disposeActivityChart")]
    # The hover tooltip the user asked for, on the same trigger as system health.
    assert "trigger: 'axis'" in option, "the chart must show a hover tooltip"
    # Axis styling is borrowed from systemHealthChartOption() deliberately.
    assert "rotate: 45" in option, "x labels follow the system health cards"
    assert "type: 'dashed'" in option, "split lines follow the system health cards"
    # A live instance must be updated in place; replacing the markup throws away
    # the canvas and the tooltip on every realtime push.
    assert "patchStableCard(chart" not in FLOWS_JS, (
        "the chart is a live ECharts instance and must be updated via setOption, not "
        "by replacing its container"
    )


def test_statistics_switch_hides_the_chart() -> None:
    assert "activityChartEnabled" in FLOWS_JS, "统计 needs backing state"
    # The switch is only real if the markup, the query and the handler agree on one
    # attribute name. Asserting the string exists somewhere passed even when the
    # attribute was renamed everywhere at once, so each end is pinned separately.
    assert 'type="checkbox" data-activity-chart-toggle' in FLOWS_JS, (
        "统计 needs a checkbox carrying data-activity-chart-toggle"
    )
    assert "querySelector('[data-activity-chart-toggle]')" in FLOWS_JS, (
        "the 统计 switch must be bound by the same attribute the markup renders"
    )
    assert re.search(
        r"data-activity-chart-toggle\]'\)\?\.addEventListener\('change'",
        FLOWS_JS,
    ), "the 统计 switch must be wired to a change handler"
    assert "state.activityChartEnabled ? activityChartMarkup() : ''" in FLOWS_JS, (
        "switching 统计 off must drop the chart from the DOM, not merely hide it"
    )
    # Row count must follow child count or the table lands in a 50% track and the
    # freed half stays empty.
    hidden = block(FLOWS_CSS, ".insights-activity-board.is-chart-hidden")
    assert "grid-template-rows: minmax(0, 1fr)" in hidden, (
        "with the chart gone the board must drop to one row, or the table keeps half "
        "the height and the other half is empty"
    )


def test_activity_table_header_sticks() -> None:
    head = block(FLOWS_CSS, ".insights-activity-table thead th")
    assert "position: sticky" in head and "top: 0" in head, (
        "a long scrolling table must keep its column labels on screen"
    )
    # The background has to be a real colour: color-mix() on the kit's glass token
    # computes to transparent because that token is a gradient list.
    assert "color-mix" not in head, (
        "--dwrt-glass-surface is a gradient list, so color-mix() on it yields "
        "transparent and rows read through the header"
    )
    assert "--insights-sticky-head-bg" in head, "the header tint must be a token"
    for scope, expected in ((":root", "rgba(242,244,248,0.98)"), ('html[data-theme-resolved="dark"]', "rgba(27,34,48,0.98)")):
        assert expected in block(FLOWS_CSS, scope), f"{scope} must define the sticky header tint"
    # A padded scroller top would leave a transparent gap above the header.
    scroll = block(FLOWS_CSS, ".insights-activity-table-scroll")
    assert re.search(r"padding:\s*0 ", scroll), (
        "the scroller must not pad its top, or rows show in the gap above the sticky header"
    )


for name, fn in sorted((k, v) for k, v in list(globals().items()) if k.startswith("test_")):
    fn()
print("insights activity layout contract: ok")

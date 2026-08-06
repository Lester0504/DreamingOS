#!/usr/bin/env python3
"""终端分组 / 路由表: page controls belong to the table card, not a header band.

Two reported defects, one shape:

1. 终端分组 kept search + import/export/create in a <header> above the card, costing a
   58px band before the table started (measured on 30.1: card top 86px, table 134px).
2. 路由表 additionally printed its own "路由表 / 配置版本 19" heading directly under the
   shell's 策略引擎 / 路由表 breadcrumb, so the page named itself twice and the tabs sat
   at y=175 with the first table at y=299.

The routing fix has a second half that is easy to lose: the stage rules that hide
.stage-header for this route live in policy-table.css under .console-stage.is-policy-table,
and the shell does set that class here -- but routing-table.css never imported that
file (terminal-groups.css does), so none of it applied. The rules are declared locally
scoped to the routing host instead.

Geometry is measured by
tests/test_policy_page_toolbar_integration_geometry_contract.mjs; this file guards the
source symbols only.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"
TG_JS = (WWW / "plugins/native/terminal-groups.js").read_text()
TG_CSS = (WWW / "static/css/terminal-groups.css").read_text()
RT_JS = (WWW / "plugins/native/routing-table.js").read_text()
RT_CSS = (WWW / "static/css/routing-table.css").read_text()


def strip_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def test_terminal_groups_controls_live_in_the_table_toolbar() -> None:
    assert "renderTableControls" in TG_JS, "the controls must be a card-level fragment"
    # The old page header must be gone from the shell, not merely restyled.
    assert "renderToolbar" not in TG_JS, "the page-level toolbar header must be removed"
    assert 'class="policy-toolbar terminal-group-toolbar"' not in TG_JS
    shell = re.search(r"policy-table-shell terminal-group-shell\">\$\{([^}]*)\}", TG_JS)
    assert shell and "renderToolbar" not in shell.group(1), (
        "the shell must no longer render a toolbar row"
    )
    # Controls belong to the kit toolbar, beside the count.
    assert "${renderTableControls()}" in TG_JS
    toolbar = re.search(r'dwrt-kit-table-toolbar terminal-group-table-toolbar">(.*?)</div>\s*</div>', TG_JS, re.S)
    assert toolbar and "renderTableControls" in toolbar.group(0), (
        "the controls must render inside the table toolbar"
    )


def test_terminal_groups_rebinds_controls_after_a_card_swap() -> None:
    """patchLoadedTable() replaces the card; the controls now live in it.

    Without a dedicated re-bind the create/import/export handlers were attached once at
    full render and silently lost on every refresh, and the focused search input was
    destroyed mid-keystroke.
    """
    assert "function bindTableControls" in TG_JS, (
        "controls inside the card need their own bind step"
    )
    patch = TG_JS[TG_JS.index("function patchLoadedTable"):]
    patch = patch[: patch.index("\n  }")]
    assert "bindTableControls()" in patch, (
        "a card swap must re-bind the controls it just recreated"
    )
    assert "selectionStart" in patch and "focus()" in patch, (
        "the search box lives in the replaced card; focus and caret must be carried over"
    )


def test_routing_page_does_not_repeat_its_own_title() -> None:
    assert "routing-page-heading" not in RT_JS, "the duplicated page heading must be gone"
    assert "routing-page-heading" not in RT_CSS, "its styles must go with it"
    # Comments are stripped: the rationale for removing this caption naturally quotes it.
    assert "配置版本" not in strip_comments(RT_JS), (
        "the config revision caption was noise; it must not return"
    )
    toolbar = strip_comments(RT_JS[RT_JS.index("function toolbarMarkup"):])
    toolbar = toolbar[: toolbar.index("\n  }")]
    assert "tabsMarkup()" in toolbar, "the page toolbar carries the tabs"
    assert "routing-search" not in toolbar, "search moved into the table card"
    assert "routing-create-button" not in toolbar, "create moved into the table card"


def test_routing_hides_the_shell_stage_header() -> None:
    """The 139px breadcrumb block is what pushed the tabs down.

    policy-table.css already hides it for .is-policy-table, but routing-table.css does
    not import that file, so the rule never reached this route.
    """
    body = strip_comments(RT_CSS)
    rule = re.search(
        r"\.console-stage\.is-policy-table:has\(> \.routing-table-route-host\) \.stage-header\s*\{([^}]*)\}",
        body,
    )
    assert rule and "display: none" in rule.group(1), (
        "the routing route must hide the shell stage header itself; inheriting it from "
        "policy-table.css does not work because that file is never imported here"
    )
    assert "@import" not in body or "policy-table.css" not in body, (
        "importing another page's stylesheet to get two rules pulls in its whole cascade"
    )
    # Stage height must still come from the shared token (design.md rule 2).
    stage = re.search(
        r"\.console-stage\.is-policy-table:has\(> \.routing-table-route-host\)\s*\{([^}]*)\}",
        body,
    )
    assert stage and "var(--app-stage-height)" in stage.group(1), (
        "stage height must reference --app-stage-height, never a raw 100dvh"
    )
    assert "100dvh" not in stage.group(1)


def test_routing_search_is_scoped_to_one_table_per_tab() -> None:
    assert "function tableControlsMarkup" in RT_JS
    # tableShell takes controls as an opt-in argument: 运行解析 renders a resolve panel
    # plus the external table, and two search inputs would fight over one query.
    assert re.search(r"function tableShell\([^)]*controls = ''\)", RT_JS), (
        "controls must be opt-in per table"
    )
    assert RT_JS.count("tableControlsMarkup())") == 5, (
        f"expected one controls slot per tab, found {RT_JS.count('tableControlsMarkup())')}"
    )
    assert "routing-table-controls" in RT_CSS, "the in-card controls need styles"


for name, fn in sorted((k, v) for k, v in list(globals().items()) if k.startswith("test_")):
    fn()
print("policy page toolbar integration contract: ok")

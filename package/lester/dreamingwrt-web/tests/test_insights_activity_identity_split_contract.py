#!/usr/bin/env python3
"""活动页应用识别口径的契约。

缺陷本体：`total_usage_by_app` 里 480 条有 448 条是 `identity_kind: "service"`
的协议/端口兜底（`tcp/11881`、`https`、`dot`），后端已用四个标记如实说明，前端
却把它们和真实应用平铺在同一个"应用"列表里。判据照抄同仓库里已经写对的
`plugins/native/app-filter.js`。

这里只把口径钉住：三个标记必须同时参与判断（少一个就会把兜底条目放进应用组），
覆盖率的分母是全部条目，`identity_reason` 必须被消费。渲染是否真的分开了要靠
浏览器实测，见交接单里记录的 1440/1280/390 三档实测。
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FLOWS_JS = (ROOT / "files/www/dreamingwrt/static/js/insights-flows.js").read_text(encoding="utf-8")
FLOWS_CSS = (ROOT / "files/www/dreamingwrt/static/css/insights-flows.css").read_text(encoding="utf-8")
MENU_JS = (ROOT / "files/www/dreamingwrt/static/js/menu-shell.js").read_text(encoding="utf-8")
APP_FILTER_JS = (ROOT / "files/www/dreamingwrt/plugins/native/app-filter.js").read_text(encoding="utf-8")


def test_identity_predicate_uses_all_three_flags() -> None:
    match = re.search(
        r"function activityIsRealApplication\(item\)\s*\{(.+?)\n    \}",
        FLOWS_JS,
        re.S,
    )
    assert match, "活动页需要一个显式的识别判据函数"
    body = match.group(1)
    # 三个标记缺任何一个，兜底条目都会漏进应用组：只看 is_application 会放进
    # application_name_is_fallback 为真的条目。
    for flag in ("is_application", "app_identified", "application_name_is_fallback"):
        assert flag in body, f"识别判据必须消费 {flag}"
    assert "application_name_is_fallback !== true" in body, (
        "兜底名必须取反参与判断，否则被后端标记为 fallback 的条目仍算应用"
    )


def test_predicate_matches_the_plugin_that_already_got_it_right() -> None:
    # app-filter.js 是同一口径的既有实现，两处不得分叉。
    assert "bool(item.is_application) && bool(item.app_identified)" in APP_FILTER_JS, (
        "参照实现变了，活动页的判据需要重新对齐"
    )


def test_rows_are_split_into_two_groups() -> None:
    assert "function activityIdentityGroups()" in FLOWS_JS, "列表必须按识别结果分组"
    groups = re.search(r"function activityIdentityGroups\(\)\s*\{(.+?)\n    \}", FLOWS_JS, re.S)
    assert groups, "分组函数缺失"
    assert "activityIsRealApplication(item) ? applications : services" in groups.group(1), (
        "分组必须走同一个判据，不能各自判一遍"
    )
    assert "insights-activity-group" in FLOWS_JS, "两组之间需要分组表头行"
    assert "未识别的协议 / 端口" in FLOWS_JS, "兜底组必须有明确说明，不能假装是应用"
    # 分组表头行在 tbody 里，不能和 thead 的 sticky 打架。
    head = re.search(r"\.insights-activity-table tr\.insights-activity-group th \{(.+?)\}", FLOWS_CSS, re.S)
    assert head and "position: sticky" not in head.group(1), (
        "分组表头不得也 sticky，两层 sticky 会互相顶"
    )


def test_coverage_is_visible_and_uses_the_full_denominator() -> None:
    groups = re.search(r"function activityIdentityGroups\(\)\s*\{(.+?)\n    \}", FLOWS_JS, re.S).group(1)
    assert "applications.length / rows.length" in groups, (
        "分母必须是全部条目，只拿应用数当分母会永远算出 100%"
    )
    assert "function activityCoverageMarkup(" in FLOWS_JS, "覆盖率必须渲染出来"
    assert "识别为应用" in FLOWS_JS and "仅协议/端口" in FLOWS_JS, "覆盖率要分别报出两类数量"
    # 覆盖率条不能放进滚动器，否则滚表格时它就滑走了。
    assert re.search(
        r"activityCoverageMarkup\(groups\)\}\s*\n\s*<div class=\"insights-activity-table-scroll\">",
        FLOWS_JS,
    ), "覆盖率条必须在滚动器之外"
    content = re.search(r"\.insights-activity-table-content \{(.+?)\}", FLOWS_CSS, re.S)
    assert content and "display: flex" in content.group(1), (
        "卡内是条件出现的两个子项，用弹性列而不是写死行数的 grid（design.md 规则 11）"
    )
    scroll = re.search(r"\.insights-activity-table-scroll \{(.+?)\}", FLOWS_CSS, re.S)
    assert scroll and "min-height: 0" in scroll.group(1), (
        "滚动器缺 min-height: 0 会被内容顶开，卡片跟着溢出"
    )


def test_identity_reason_is_consumed() -> None:
    assert "identity_reason" in FLOWS_JS, "后端给的未识别原因此前全仓库 0 处引用"
    assert "no_dpi_signature_match_proto_port_used" in FLOWS_JS, (
        "实测的原因取值要有对应文案，不能把机器串直接甩给用户"
    )
    assert "activityIdentityHint(item)" in FLOWS_JS, "原因要挂到条目上"
    assert "data-dwrt-tooltip=\"${escapeAttr(hint)}\"" in FLOWS_JS, (
        "原因走 kit tooltip，与审计表格同一套做法"
    )


def test_asset_cache_key_was_bumped() -> None:
    # 改了 JS/CSS 不 bump 版本，部署后浏览器仍拿旧文件。
    for asset in ("/static/js/insights-flows.js", "/static/css/insights-flows.css"):
        block = MENU_JS[MENU_JS.index(asset):MENU_JS.index(asset) + 220]
        assert "20260805-activity-identity-split-01" in block, (
            f"{asset} 的缓存键必须随本次改动 bump"
        )


for name, fn in sorted((k, v) for k, v in list(globals().items()) if k.startswith("test_")):
    fn()
print("insights activity identity split contract: ok")

#!/usr/bin/env python3
"""洞察筛选栏的 grid 行数必须与子元素数一致。

用户反复打回「菜单被 footer 削掉一块」，我前几轮一直在 footer 那边找原因
（inset、margin、reserve strip），全都不是。真因在筛选栏自己：

`.insights-filter` 的 aside 里**只有两个子元素**——`.insights-filter-scroll`
和 `.insights-filter-footer`——但 CSS 写的是**三行** `auto minmax(0,1fr) auto`。
于是滚动体落进开头那个 `auto` 行，按内容全高展开（实测 1529px），
而 `minmax(0,1fr)` 那一行空着、算出 **0px**。

实测证据（30.1，1440x900）：
  修复前 gridTemplateRows = "818px 0px 0px"，最后一个 section 底边 1531 > 视口 900，
         `.console-stage` 是 overflow:hidden 且高 842，超出的部分被直接裁掉。
  修复后 gridTemplateRows = "726.75px 91.25px"，滚到底后最后一个 section
         fullyVisible=true、clippedByPageFooter=false，
         筛选栏自己的页脚（清除筛选条件/下载/自定义列）完整落在 739-830，
         页面 footer 在 842，互不遮挡。

**教训：行数与子元素数不一致时，多出来的 `1fr` 会静默塌成 0，
把滚动容器变成无限长的 auto 行。** 这类缺陷读 CSS 单看每条属性都合理，
只有量 computed style 才看得出来。
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"
CSS = (WWW / "static/css/insights-flows.css").read_text()
JS = (WWW / "static/js/insights-flows.js").read_text()


def test_filter_rail_row_count_matches_child_count() -> None:
    match = re.search(r"\.insights-filter\s*\{([^}]*)\}", CSS)
    assert match, "找不到 .insights-filter 规则"
    rows = re.search(r"grid-template-rows:\s*([^;]+);", match.group(1))
    assert rows, ".insights-filter 必须显式声明 grid-template-rows"
    track = rows.group(1).strip()

    # aside 的直接子元素：滚动体 + 页脚
    aside = JS[JS.index('<aside class="insights-filter'):]
    aside = aside[:aside.index("</aside>")]
    children = len(re.findall(r"^\s{10}<(?:div|footer|section|header)\b", aside, re.M))
    assert children == 2, f"筛选栏子元素数变了（{children}），请同步调整 grid 行数"

    declared = len(re.findall(r"(minmax\([^)]*\)|auto|[\d.]+(?:px|fr|%)|1fr)", track))
    assert declared == children, (
        f'grid-template-rows 声明了 {declared} 行，但 aside 只有 {children} 个子元素：'
        f'"{track}"。多出来的 1fr 会塌成 0px，让滚动体落进 auto 行按全高展开，'
        "筛选栏溢出被 stage 裁掉，看起来就是 footer 削掉了菜单"
    )


def test_scroll_body_owns_the_flexible_row() -> None:
    """滚动体必须占那个可伸缩的行，否则它不会滚，只会长。"""
    match = re.search(r"\.insights-filter\s*\{([^}]*)\}", CSS)
    track = re.search(r"grid-template-rows:\s*([^;]+);", match.group(1)).group(1)
    first = track.strip().split()[0]
    assert first.startswith("minmax(0"), (
        f"第一行必须是 minmax(0, 1fr) 让滚动体可收缩，实际是 {first}"
    )
    scroll = re.search(r"\.insights-filter-scroll\s*\{([^}]*)\}", CSS)
    assert scroll, "找不到 .insights-filter-scroll"
    assert "overflow: auto" in scroll.group(1), "滚动体必须 overflow: auto"
    assert "min-height: 0" in scroll.group(1), (
        "grid 子项默认 min-height:auto 会拒绝收缩，必须显式归零才会真的滚动"
    )


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("insights filter rail rows contract: ok")

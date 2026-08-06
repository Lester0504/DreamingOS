#!/usr/bin/env python3
"""存储服务各页的布局与工具栏契约（用户 2026-08-05 的三项反馈）。

一、概览「卡片内容没了只剩框架」

`.storage-overview-shell` 写的是 `grid-template-rows: 48px minmax(0, 1fr)`，
但模块模板里 shell 只有一个子节点 `.storage-overview-scroll`：早先那 48px 是留给
页内表头的，表头移除后行定义没跟着改，唯一的内容区落进 48px 那一行，配合
`overflow: hidden` 把卡片主体整块裁掉。实测 scrollHeight 403 / clientHeight 48，
修复后 806 / 806。

二、磁盘分区「卡片不能滚动 + 圆角逃逸」

两个独立缺陷：

1. 表格卡没有行定义、内层 `.dwrt-kit-table-scroll` 也没有 `min-height: 0`，
   于是 kit 的 `overflow: auto` 形同虚设（grid 子项 min-height 默认 auto、不肯收缩），
   滚动层被内容顶到与内容等高。实测灌到 45 行时 scrollHeight === clientHeight === 2063
   而卡片只有 398px，表体溢出卡片被裁掉、哪一层都滚不动；`scrollTop = 400` 后读回 0。
   修复后内层 clientHeight 311 / scrollHeight 2063，`scrollTop` 真的停在 400。
2. 两张卡硬写 `border-radius: 8px`，明显小于同侧页面（概览、RAID 都用
   `var(--app-radius-card)`，实测 24px），观感接近直角。

三、文件管理 / RAID / 文件服务：表格上方那排按钮收进表格工具栏，并删掉复述表头的副标题

断言一律对**去掉注释后**的源码做，否则本轮新增的中文注释里就含有
「圆角」「滚动」「工具栏」这些词，松散的子串匹配会被注释满足。
"""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"


def strip_css_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def strip_js_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", text)


def css(name: str) -> str:
    return strip_css_comments((WWW / f"static/css/{name}").read_text(encoding="utf-8"))


def js(name: str) -> str:
    return strip_js_comments((WWW / f"plugins/native/{name}").read_text(encoding="utf-8"))


def block(text: str, selector: str, *, require: str = "") -> str:
    """取出指定选择器的规则块；require 用于在同名多处时挑出声明了该属性的那一块。"""
    pattern = re.escape(selector) + r"\s*\{[^}]*\}"
    blocks = [b for b in re.findall(pattern, text) if require in b]
    assert blocks, f"找不到 {selector} 的规则块" + (f"（需含 {require}）" if require else "")
    return blocks[0]


def test_overview_shell_rows_match_its_only_child() -> None:
    """shell 的行数必须与模板的子节点数一致，多留一行就会吃掉内容高度。"""
    module = js("storage-overview.js")
    shell_children = re.search(
        r'<section class="storage-overview-shell">(.*?)</section>', module, re.S
    )
    assert shell_children, "storage-overview.js 找不到 shell 模板"
    # 模板里 shell 只包一个 <main>，所以 CSS 不能按两行分配。
    assert shell_children.group(1).count("<main") == 1

    # 桌面态与移动端断点都要查：断点里的同名规则是同一个缺陷的副本，
    # 只断言第一处会让 44px 的移动端版本溜过去。
    style = css("storage-overview.css")
    rules = [b for b in re.findall(r"\.storage-overview-shell\s*\{[^}]*\}", style)
             if "grid-template-rows" in b]
    assert rules, "找不到 .storage-overview-shell 的行定义"
    for rule in rules:
        rows = re.search(r"grid-template-rows:\s*([^;]+);", rule).group(1).strip()
        assert rows == "minmax(0, 1fr)", (
            f"shell 只有一个子节点，行定义应为 minmax(0, 1fr)，实际是 {rows!r}；"
            "多留一行表头会把内容区压掉再被 overflow:hidden 裁没"
        )


def test_partitions_table_card_can_scroll_internally() -> None:
    """表格卡要「工具栏 + 可滚动表体」两行，内层滚动容器必须能收缩。"""
    style = css("storage-partitions.css")

    card = block(style, ".storage-partitions-table", require="grid-template-rows")
    assert "minmax(0, 1fr)" in card, "表体行要用 minmax(0, 1fr)，否则会被内容顶高"
    assert "overflow: hidden" in card, "卡片自身要裁掉溢出，滚动交给内层"

    inner = block(style, ".storage-partitions-table .dwrt-kit-table-scroll")
    assert "min-height: 0" in inner, (
        "grid/flex 子项的 min-height 默认是 auto、不肯收缩，"
        "缺这一行 kit 的 overflow:auto 就永远滚不动"
    )
    assert "overflow: auto" in inner


def test_partitions_cards_use_the_radius_token() -> None:
    """卡片圆角归 token，不写死；硬写 8px 就是圆角逃逸。"""
    style = css("storage-partitions.css")
    for selector in (".storage-partitions-disk-summary", ".storage-partitions-table"):
        rule = block(style, selector, require="border-radius")
        radius = re.search(r"border-radius:\s*([^;]+);", rule).group(1).strip()
        assert radius.startswith("var(--app-radius-card"), (
            f"{selector} 的圆角是 {radius!r}；应走 var(--app-radius-card)，"
            "与概览、RAID 保持一致"
        )


def test_partitions_shell_stays_grid_for_its_grid_host() -> None:
    """shell 不能改成 flex：宿主 .route-workspace 是 grid + align-content: start。

    flex 下 shell 的内容高度会算成 0，那一行随之为 0px，整页塌掉（实测 shellH 0）。
    """
    rule = block(css("storage-partitions.css"), ".storage-partitions-shell", require="display")
    display = re.search(r"display:\s*([^;]+);", rule).group(1).strip()
    assert display == "grid", (
        f".storage-partitions-shell 的 display 是 {display!r}；"
        "宿主是 grid + align-content:start，改成 flex 会让本页整体塌成 0 高"
    )


def test_table_action_bars_live_in_the_table_toolbar() -> None:
    """三个页面的搜索与动作按钮都要落在 .dwrt-kit-table-toolbar 里。"""
    cases = {
        "storage-files.js": ("storage-file-table-actions", "tableActionsMarkup()"),
        "storage-raid.js": ("raid-table-actions", "toolbarMarkup()"),
        "storage-file-services.js": ("file-service-table-actions", "toolbarMarkup()"),
    }
    for name, (action_class, call) in cases.items():
        module = js(name)
        assert action_class in module, f"{name} 缺少表格工具栏动作块 {action_class}"

        toolbar = re.search(r'<div class="dwrt-kit-table-toolbar">(.*?)</div><div class="dwrt-kit-table-scroll"', module, re.S)
        assert toolbar, f"{name} 找不到表格工具栏与表体的衔接处"
        assert call in toolbar.group(1), (
            f"{name} 的动作块没有渲染进 .dwrt-kit-table-toolbar；"
            "按钮留在页面级 header 就是用户要求收起来的那一排"
        )

        # 动作块要贴右，且允许换行，不能把工具栏顶宽。
        sheet = {"storage-files.js": "storage-files.css",
                 "storage-raid.js": "storage-raid.css",
                 "storage-file-services.js": "storage-file-services.css"}[name]
        rule = block(css(sheet), f".{action_class}")
        assert "margin-left: auto" in rule, f"{action_class} 要靠 margin-left:auto 贴右"
        assert "flex-wrap: wrap" in rule, f"{action_class} 窄屏要能换行，不能顶宽工具栏"


def test_file_manager_dropped_the_column_recital_subtitle() -> None:
    """副标题不能复述表头。"""
    module = js("storage-files.js")
    assert "名称、大小、修改时间、权限与属主" not in module, (
        "这句只是把表头又念了一遍，不提供信息（用户 2026-08-05 要求删掉）"
    )
    # 有选中项时仍要给出计数反馈。
    assert "已选择 ${state.selected.size} 项" in module


def test_raid_and_file_services_titles_drop_redundant_subtitles() -> None:
    """RAID 与文件服务的表格标题不再挂描述性副标题。"""
    assert "磁盘成员、阵列健康、同步进度与挂载状态" not in js("storage-raid.js")
    services = js("storage-file-services.js")
    assert "<strong>${escapeHtml(title)}</strong></div>" in services, (
        "文件服务的表格标题应只留主标题"
    )


if __name__ == "__main__":
    test_overview_shell_rows_match_its_only_child()
    test_partitions_table_card_can_scroll_internally()
    test_partitions_cards_use_the_radius_token()
    test_partitions_shell_stays_grid_for_its_grid_host()
    test_table_action_bars_live_in_the_table_toolbar()
    test_file_manager_dropped_the_column_recital_subtitle()
    test_raid_and_file_services_titles_drop_redundant_subtitles()
    print("ok: storage pages fill their shells, partitions scroll with token radius, toolbars own their actions")

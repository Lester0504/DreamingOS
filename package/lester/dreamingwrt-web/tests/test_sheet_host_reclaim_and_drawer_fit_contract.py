#!/usr/bin/env python3
"""页面侧的抽屉契约：清空覆盖层宿主前要回收传送门节点，抽屉内不得溢出。

两组缺陷来自用户 2026-08-05 的同一批反馈。

一、「退出抽屉后页面就卡死了必须刷新一下才能继续操作」

`DWRT_UI_KIT.unmount(host)` 只在 `host` 子树里找 `.dwrt-kit-sheet`
（`dwrt-ui-kit.js` 的 `matchingRoots(context, ...)`），而 `mountAll()` 早已把抽屉
连遮罩搬到 body 直属的 `#dwrtKitSheetPortal`。宿主里空无一物，`unmountSheet()`
不会执行，抽屉和那层 `is-open` 遮罩就永久留在传送门里，盖住页面吞掉所有点击。

三个页面实测同一条链：每开关一轮 `portalKids` 2 -> 4 -> 6，第二轮起抽屉 `left`
错位到 1440（视口之外），关闭后 `elementFromPoint(700,450)` 返回
`dwrt-kit-sheet-overlay is-open`。补上回收后三轮均为 `visSheets:0 / overlays:0 /
portalKids:0`，且抽屉可以再次打开。

二、抽屉宽度归一到 460 之后暴露的两处溢出

抽屉宽度是固定档位，与视口无关，所以视口断点收不动抽屉内的栅格。
`.policy-region-action-grid` 硬写三列时每列只剩约 130px，「区域转发」溢出右边缘；
`.policy-type-picker` 7 个标签靠隐藏滚动条硬塞，「端口转发」被推出抽屉。

断言一律对**去掉注释后**的源码做，否则本轮新增的中文注释里就含有
「抽屉」「宽度」「传送门」这些词，松散的子串匹配会被注释满足。
"""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"

# 每个页面模块：文件名 -> 它给自己节点打的归属标记（dataset 驼峰名）
RECLAIM_PAGES = {
    "policy-regions.js": "regionOverlayOwned",
    "policy-objects.js": "objectOverlayOwned",
    "ip-address-management.js": "ipamOverlayOwned",
}


def strip_comments(text: str) -> str:
    """去掉块注释与行注释，避免断言被注释里的散文满足。"""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", text)


def read_code(relative: str) -> str:
    return strip_comments((WWW / relative).read_text(encoding="utf-8"))


def test_overlay_hosts_reclaim_portaled_sheets_before_unmount() -> None:
    for name, owned_key in RECLAIM_PAGES.items():
        code = read_code(f"plugins/native/{name}")

        assert "function reclaimPortaledSheets(" in code, (
            f"{name} 清空覆盖层宿主前必须回收传送门里的抽屉，否则关闭后遮罩会吞掉所有点击"
        )

        replace_fn = code[code.index("function replaceMarkup("):]
        replace_fn = replace_fn[:replace_fn.index("\n  }") + 4]
        reclaim_at = replace_fn.find("reclaimPortaledSheets(host)")
        unmount_at = replace_fn.find("unmount?.(host)")
        assert reclaim_at != -1, f"{name} 的 replaceMarkup 没有回收传送门节点"
        assert unmount_at != -1, f"{name} 的 replaceMarkup 没有调用 kit 卸载"
        assert reclaim_at < unmount_at, (
            f"{name} 必须先回收再卸载：反过来的话 kit 仍然看不见传送门里的抽屉"
        )

        # 归属标记要同时写入与读取，只写不读等于没有回收依据。
        assert f"dataset.{owned_key}" in code, f"{name} 必须给自己的抽屉与遮罩打归属标记"
        assert f"{owned_key} === undefined" in code, (
            f"{name} 回收时必须按归属标记筛选，否则会抢走别的宿主的抽屉"
        )

        # 回收范围必须同时含抽屉与遮罩：只搬抽屉会留下遮罩继续吞点击。
        reclaim_fn = code[code.index("function reclaimPortaledSheets("):]
        reclaim_fn = reclaim_fn[:reclaim_fn.index("\n  }") + 4]
        assert "dwrtKitSheetPortal" in reclaim_fn, f"{name} 回收要去 kit 的传送门里找"
        assert ".dwrt-kit-sheet" in reclaim_fn and ".dwrt-kit-sheet-overlay" in reclaim_fn, (
            f"{name} 抽屉与遮罩都要回收，漏掉遮罩仍然会卡死"
        )


def test_drawers_use_the_standard_width_tier() -> None:
    """策略表与终端分组的抽屉要与 AI 抽屉同档：引用 standard 档的宽度变量。

    只断言「文件里没有 620px」是不够的：宽度走的是 token，而 620 还会作为
    `font-weight` 出现，两边都会让断言失去意义。这里直接盯 `--dwrt-kit-sheet-width`
    的取值，它必须指向 standard 档，不能是 form / wide 档，也不能写死数值。
    """
    for sheet_css in ("static/css/policy-table.css", "static/css/terminal-groups.css"):
        code = read_code(sheet_css)
        assignments = re.findall(
            r"--dwrt-kit-sheet-width:\s*([^;]+);", code
        )
        assert assignments, f"{sheet_css} 没有声明抽屉宽度档位"
        for value in assignments:
            value = value.strip()
            # 移动端满宽（full 档）是合理例外，其余一律必须是 standard 档。
            if "width-full" in value:
                continue
            assert "var(--dwrt-kit-sheet-width-standard)" == value, (
                f"{sheet_css} 的抽屉宽度是 {value!r}，用户要求与 AI 抽屉一致，"
                "即 var(--dwrt-kit-sheet-width-standard)"
            )


def test_drawer_grids_collapse_by_container_not_viewport() -> None:
    """固定宽度抽屉里的栅格只能按容器自适应，视口断点永远不会命中。"""
    entities = read_code("static/css/policy-entities.css")

    # 该选择器出现多次（共用简写块、断点内的单栏覆盖），只看声明列数的那一块。
    action_grid = next(
        block
        for block in re.findall(
            r"\.policy-region-action-grid\s*\{[^}]*\}", entities
        )
        if "grid-template-columns" in block
    )
    assert "repeat(3," not in action_grid.replace(" ", ""), (
        "抽屉内硬写三列会把长标签挤出右边缘：460px 抽屉每列只剩约 130px"
    )
    assert "auto-fit" in action_grid and "minmax" in action_grid, (
        ".policy-region-action-grid 要用 auto-fit + minmax 按容器收缩"
    )

    # 抽屉正文的内边距归页面：kit 的 .dwrt-kit-sheet-body 一点都不给。
    sheet_body = entities[entities.index(".policy-entity-sheet-body"):]
    sheet_body = sheet_body[:sheet_body.index("}") + 1]
    assert "padding" in sheet_body, (
        "kit 不给抽屉正文内边距，页面漏了就是内容贴边，观感是「吞字」"
    )
    assert "--dwrt-kit-sheet-padding-x" in sheet_body, (
        "左右内边距要用 kit 的抽屉内边距变量，别自己写死数值"
    )


def test_type_picker_wraps_instead_of_hidden_horizontal_scroll() -> None:
    """7 个类型标签在 460px 抽屉里要换行，不能靠隐藏滚动条硬塞。"""
    table = read_code("static/css/policy-table.css")
    picker = table[table.index(".policy-type-picker {"):]
    picker = picker[:picker.index("}") + 1]

    assert "flex-wrap: wrap" in picker, (
        "标签要换行；靠 overflow-x + scrollbar-width:none 会把「端口转发」推出抽屉，"
        "而且滚动条被藏了，用户不知道还能滚"
    )
    assert "overflow-x: auto" not in picker, "换行之后不该再留横向滚动"


if __name__ == "__main__":
    test_overlay_hosts_reclaim_portaled_sheets_before_unmount()
    test_drawers_use_the_standard_width_tier()
    test_drawer_grids_collapse_by_container_not_viewport()
    test_type_picker_wraps_instead_of_hidden_horizontal_scroll()
    print("ok: overlay hosts reclaim portaled sheets; drawers fit 460px without overflow")

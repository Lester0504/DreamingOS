#!/usr/bin/env python3
"""抽屉传送门的作用域、事件委托与回收契约。

Kit 会把 `.dwrt-kit-sheet` 搬到 body 直属的 portal，用来躲开祖先链上的 transform /
backdrop-filter 造成的重锚定。这个搬迁有三个副作用，每一个都曾在真机上表现为可见缺陷：

1. 样式作用域丢失：页面 CSS 里 `.xxx-route-host .dwrt-kit-sheet …` 的前缀不再匹配，
   挂在 `.xxx-shell` 上的自定义属性也解析不到。`border: 1px solid var(--wifi-line)`
   这类整条声明因变量无效而作废，下拉框回落成浏览器原生白底。
2. 事件委托断链：页面模块普遍只绑一条 `root.addEventListener('click', …)`，抽屉离开
   路由子树后冒泡到不了它，抽屉里的按钮集体失灵。
3. 节点泄漏：页面靠重绘 innerHTML 关抽屉，portal 里那份既不会被重绘冲掉也不会被
   unmount 扫到，反复开关会叠出多份，后来的点击命中已滑出视口的残留节点。
"""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"
KIT_JS = (WWW / "static/ui-kit/dwrt-ui-kit.js").read_text(encoding="utf-8")
KIT_CSS = (WWW / "static/ui-kit/dwrt-ui-kit.css").read_text(encoding="utf-8")


def test_portal_mirrors_the_route_scope() -> None:
    assert "PORTAL_SCOPE_PATTERN" in KIT_JS
    # 作用域类名要覆盖路由宿主、页面壳层和页内布局容器三类命名
    head = KIT_JS[KIT_JS.index("PORTAL_SCOPE_PATTERN"):KIT_JS.index("function scopeClassesFor")]
    for suffix in ("-route-host", "-shell", "-workspace", "-layout"):
        assert suffix in head, suffix
    assert "function scopeClassesFor(node)" in KIT_JS
    assert "function applyPortalScope(portal, classes)" in KIT_JS
    assert "state.portalScope = scopeClassesFor(sheet)" in KIT_JS
    assert "applyPortalScope(portal, state.portalScope)" in KIT_JS


def test_portal_itself_stays_layout_neutral() -> None:
    # 镜像下来的壳层规则会带 display / backdrop-filter 等属性，而 backdrop-filter 会重建
    # 包含块，正是 portal 要规避的问题。portal 自身必须被压平。
    block = KIT_CSS[KIT_CSS.index(".dwrt-kit-sheet-portal,"):]
    block = block[:block.index("}")]
    assert "#dwrtKitSheetPortal" in block
    for declaration in (
        "position: static",
        "width: 0",
        "height: 0",
        "display: block",
        "backdrop-filter: none",
        "transform: none",
        "contain: none",
        "background: none",
    ):
        assert declaration in block, declaration


def test_delegated_events_reach_the_original_route_root() -> None:
    assert "DELEGATED_EVENTS" in KIT_JS
    events = KIT_JS[KIT_JS.index("const DELEGATED_EVENTS"):KIT_JS.index("function bindSheetDelegation")]
    for event in ("'click'", "'input'", "'change'", "'submit'"):
        assert event in events, event
    assert "function bindSheetDelegation(sheet, state)" in KIT_JS
    assert "bindSheetDelegation(sheet, state)" in KIT_JS
    # 沿原祖先链一路派发到路由根，因为页面的委托绑在 root 而不是抽屉的直接父节点上
    assert "cursor.id === 'routePreview' || cursor.classList.contains('route-preview')" in KIT_JS
    # 重放事件刻意不冒泡，否则 document 级处理器会把同一次交互跑两遍
    assert "bubbles: false, composed: false" in KIT_JS
    assert "replay.dwrtSheetRelayed = true" in KIT_JS
    assert "if (event.dwrtSheetRelayed) return" in KIT_JS
    # 关闭第二拍（带 bypass 标记的重放）同样要转发，否则抽屉滑走但页面状态不清
    bypass = KIT_JS.index("dwrtSheetBypass === 'true'")
    assert "state.relayToHost?.(event)" in KIT_JS[bypass:bypass + 260]


def test_orphan_sheets_are_reclaimed_on_rerender() -> None:
    assert "function disposeSheet(sheet)" in KIT_JS
    assert "function reclaimStaleSheets(context)" in KIT_JS
    assert "reclaimStaleSheets(context);" in KIT_JS[KIT_JS.index("function mountAll"):]
    # 判定依据是抽屉记住的原宿主：宿主脱离文档或本次重绘的正是它，这份抽屉即为孤儿
    body = KIT_JS[KIT_JS.index("function reclaimStaleSheets"):]
    body = body[:body.index("function watchSheetPortal")] if "function watchSheetPortal" in body else body[:2400]
    assert "portalHome?.parent" in body
    assert "host?.contains(home)" in body
    assert "disposeSheet(node)" in body
    assert "state.releaseDelegation?.()" in KIT_JS


def test_no_page_hardcodes_sheet_pixel_widths() -> None:
    # 抽屉宽度只能引用 Kit 的四档变量。写死像素等于页面自建一套宽度标准。
    offenders = []
    for path in sorted((WWW / "static/css").glob("*.css")):
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"--dwrt-kit-sheet-(?:width|max-width):\s*([^;]+);", text):
            value = match.group(1).strip()
            if "var(--dwrt-kit-sheet-width-" in value:
                continue
            if re.fullmatch(r"calc\(100vw - \d+px\)|100vw", value):
                continue
            # VPN 抽屉刻意按菜单玻璃条的宽度让位，属于有依据的视口留白
            if re.fullmatch(r"calc\(100vw - var\(--app-menu-glass-width[^)]*\)\s*-\s*\d+px\)", value):
                continue
            offenders.append(f"{path.name}: {value}")
        for match in re.finditer(r"\.dwrt-kit-sheet[^{}]*\{[^{}]*?\bwidth:\s*min\((\d+)px", text):
            offenders.append(f"{path.name}: width: min({match.group(1)}px ...)")
    assert not offenders, "抽屉宽度必须引用 Kit 档位变量: " + "; ".join(offenders)


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("sheet portal scope contract: ok")

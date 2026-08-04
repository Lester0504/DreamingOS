#!/usr/bin/env python3
"""终端详情整屏面板的几何契约。

用户要求终端详情从居中卡片改成整屏，但不能盖住左侧菜单栏：菜单是常驻导航，
详情打开时它仍要可见、可点，才不会丢失当前位置。所以这里守三件事：

1. 覆盖层的左边界必须由 `--app-menu-glass-width` 推导。这个变量随侧栏折叠、子菜单
   隐藏和 640px 断点自己变；页面若复制任何一档像素值，折叠侧栏后详情就会压住菜单或
   者留出一条空白缝。
2. 面板宽高必须占满让出来的区域，且不得在断点里被改回「视口减若干像素」的居中卡片。
   之前 900px 断点内就有一份这样的覆盖，是同一个缺陷的来源。
3. 覆盖 Kit 基线几何时选择器必须双类提权。`.client-detail-drawer` 与
   `.dwrt-kit-modal` 同为 0-1-0，而 ui-kit.css 后加载，裸单类会被压掉。
"""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"
CSS = (WWW / "static/css/client-details.css").read_text(encoding="utf-8")
SHELL_CSS = (WWW / "static/css/menu-shell.css").read_text(encoding="utf-8")


def _block(text: str, selector: str) -> str:
    index = text.index(selector)
    start = text.index("{", index)
    return text[start : text.index("}", start)]


def test_layer_avoids_the_menu_rail() -> None:
    block = _block(CSS, ".dwrt-kit-modal-layer.client-detail-layer")
    inset = re.search(r"inset:\s*([^;]+);", block)
    assert inset, "覆盖层必须显式声明 inset"
    value = inset.group(1)
    assert "--app-menu-glass-width" in value, f"左边界必须读菜单玻璃宽度: {value}"
    assert "--app-content-inset-top" in value, f"顶边必须读内容起点变量: {value}"
    assert re.search(r"padding:\s*0;", block)
    assert "place-items: stretch" in block


def test_shell_publishes_the_content_inset() -> None:
    assert "--app-content-inset-top: 0px" in SHELL_CSS
    narrow = SHELL_CSS[SHELL_CSS.index("@media (max-width: 640px)") :]
    assert "--app-content-inset-top: 48px" in narrow, "横条偏移必须落在 640px 断点内"


def test_panel_fills_the_remaining_area() -> None:
    block = _block(CSS, ".dwrt-kit-modal.client-detail-drawer")
    assert re.search(r"width:\s*100%;", block)
    assert re.search(r"height:\s*100%;", block)
    assert re.search(r"max-height:\s*none;", block)
    assert re.search(r"border-radius:\s*0;", block)
    assert re.search(r"border-width:\s*0 0 0 1px;", block)


def test_no_breakpoint_restores_the_centered_card() -> None:
    offenders = []
    for match in re.finditer(r"\.client-detail-drawer[^{}]*\{([^{}]*)\}", CSS):
        body = match.group(1)
        for prop in ("--dwrt-kit-modal-width", "height", "max-height"):
            found = re.search(rf"(?<![-\w]){prop}:\s*([^;]+);", body)
            if not found:
                continue
            value = found.group(1).strip()
            if re.search(r"100vw|100dvh", value):
                offenders.append(f"{prop}: {value}")
    assert not offenders, "断点内不得把详情改回视口内缩的居中卡片: " + "; ".join(offenders)


def test_kit_geometry_overrides_are_specificity_safe() -> None:
    for selector in (".client-detail-layer", ".client-detail-drawer"):
        pattern = rf"(?:^|,|\}})\s*{re.escape(selector)}\s*\{{"
        assert not re.search(pattern, CSS, re.MULTILINE), f"{selector} 必须与 Kit 类联写提权"


def test_connection_table_scrolls_instead_of_widening_the_panel() -> None:
    """连接详情表格声明的 min-width 足够放下全部列（14 列约 1988px）。
    宿主必须允许比内容窄，否则表格会把面板和整个抽屉一起顶宽——grid 子项的
    min-width 默认是 auto，不肯收缩，这就是用户看到的横向溢出。
    """
    host = _block(CSS, ".client-connection-table-host")
    assert re.search(r"min-width:\s*0;", host), "表格宿主必须允许收缩，否则面板被顶宽"
    scroll = _block(CSS, ".client-connection-table-scroll")
    assert re.search(r"overflow:\s*auto;", scroll), "宽表只能在滚动容器内横滚"
    assert re.search(r"min-width:\s*0;", scroll)


def test_detail_values_wrap_instead_of_being_clipped() -> None:
    """信息详情里的值是机器字符串（全局 IPv6、厂商名、SSID），不含空格。
    默认 overflow-wrap 会把它们当成一个不可断的整体，撑出单元格、看起来像被吞字。
    """
    for selector in (".client-detail-list strong", ".client-detail-list span"):
        block = _block(CSS, selector)
        assert "overflow-wrap: anywhere" in block, f"{selector} 必须允许任意位置换行"
        assert re.search(r"min-width:\s*0;", block), f"{selector} 必须允许收缩"


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("client detail fullbleed contract: ok")

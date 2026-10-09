"""洞察审计表格：图标在前、名字在后，以及 sticky 表头不得泛白。

用户 2026-08-09 提的三件事：
  1. 活动页的两行解释性文案删掉（分组表头的 detail、覆盖率下面那句 <p>）。
  2. 活动页 / URL 审计 / 协议与应用的应用列显示图标 + 名字，图标在前。
  3. 终端在线的设备列显示设备图 + MAC，图在前。

这里钉住的是「改回去就会重现原缺陷」的那几处，不重复浏览器契约
(`test_insights_activity_layout_geometry_contract.mjs`) 已经量过的几何。
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "files/www/dreamingwrt/static"
FLOWS_JS = (ROOT / "js/insights-flows.js").read_text(encoding="utf-8")
FLOWS_CSS = (ROOT / "css/insights-flows.css").read_text(encoding="utf-8")


def test_removed_explanatory_lines_stay_removed() -> None:
    assert "识别依赖 DPI 特征库" not in FLOWS_JS, "覆盖率下面那句说明已按用户要求删除"
    assert "DPI 特征库识别到具体应用" not in FLOWS_JS, "分组表头的 detail 文案已删除"
    assert "特征库未命中，只能按协议或端口标识" not in FLOWS_JS, "分组表头的 detail 文案已删除"
    # 删的是文案，不是信息：三档计数与未识别标记必须还在。
    assert "识别为应用" in FLOWS_JS and "仅协议/端口" in FLOWS_JS and "条目合计" in FLOWS_JS, (
        "覆盖率三档是这句话被删掉后唯一的口径来源，不能一起删"
    )
    assert "未识别的协议 / 端口" in FLOWS_JS, "分组名保留"
    assert "identity_reason" in FLOWS_JS, "未识别原因仍要挂 tooltip"


def test_icon_comes_before_the_name() -> None:
    cell = re.search(r"function auditIconCell\(iconMarkup, body\) \{(.+?)\n    \}", FLOWS_JS, re.S)
    assert cell, "缺少图标单元格渲染函数"
    body = cell.group(1)
    assert body.index("iconMarkup") < body.index("body"), "图标必须排在名字之前"


def test_icons_use_backend_fields_not_guesses() -> None:
    src = re.search(r"function auditAppIconSrc\(row\) \{(.+?)\n    \}", FLOWS_JS, re.S)
    assert src, "缺少应用图标来源解析"
    for field in ("icon_url", "icon_file", "icon_key"):
        assert field in src.group(1), f"应用图标要用后端给的 {field}，不能前端猜文件名"
    device = re.search(r"function auditDeviceIconSrc\(row\) \{(.+?)\n    \}", FLOWS_JS, re.S)
    assert device and "DWRT_DEVICE_IMAGES" in device.group(1), (
        "设备图必须走全局解析器，与仪表盘/终端列表同一套优先级"
    )


def test_icon_fields_survive_row_normalisation() -> None:
    # 归一化里丢掉 icon_* 等于图标永远取不到，这是实际踩过的一步。
    for func in ("urlAuditRows", "urlDomainRows", "auditEntityRows"):
        block = re.search(rf"function {func}\(\w*\) \{{(.+?)\n    \}}", FLOWS_JS, re.S)
        assert block, f"{func} 未找到"
        assert "icon_url" in block.group(1), f"{func} 必须把 icon_url 带下来"
    online = re.search(r"function onlineRecordRows\(\) \{(.+?)\n    \}", FLOWS_JS, re.S)
    assert online and "model:" in online.group(1), (
        "设备品牌匹配要用 model，归一化里丢掉会少一条线索"
    )


def test_icon_does_not_squeeze_the_text_column() -> None:
    # table-layout: fixed 只认 thead 的列宽，写在 td 上的 min-width 会被忽略。
    for selector in (
        r"\.online-record-table \.insights-audit-table thead th:nth-child\(2\)",
        r"\.url-audit-table \.insights-audit-table thead th:nth-child\(4\)",
        r"\.protocol-app-table \.insights-audit-table thead th:nth-child\(1\)",
    ):
        rule = re.search(rf"{selector} \{{(.+?)\}}", FLOWS_CSS, re.S)
        assert rule, f"{selector} 缺少列宽规则"
        assert re.search(r"\bwidth:\s*\d+px", rule.group(1)), (
            f"{selector} 必须写 width；fixed 布局忽略单元格上的 min-width"
        )


def test_sticky_head_band_is_opaque_and_beats_the_material_layer() -> None:
    # 材质层是 .dwrt-app .dwrt-kit-table-wrap .dwrt-kit-table thead th + !important，
    # 选择器不够具体就压不过它，实测表头会保持全透明。
    rule = re.search(
        r"\.dwrt-app \.dwrt-kit-table-wrap \.dwrt-kit-table\.insights-audit-table thead th \{(.+?)\}",
        FLOWS_CSS,
        re.S,
    )
    assert rule, "审计表头缺少压过材质层的底色规则"
    assert "--insights-sticky-head-bg" in rule.group(1), "底色走已量过的 sticky 变量"
    assert "!important" in rule.group(1), "材质层用了 !important，这里必须同级压过"


def test_head_band_follows_the_ink_not_the_theme_preference() -> None:
    # data-theme-resolved 是浅/深偏好，墨色由 data-adaptive-foreground 决定。
    # 30.1 实测两者不一致（resolved=light 而前景=light），按主题给底色就会白压白。
    assert re.search(
        r"html\[data-adaptive-foreground=\"light\"\] \{\s*--insights-sticky-head-bg:\s*rgba\(27,34,48",
        FLOWS_CSS,
    ), "浅墨时底色必须是深色带"
    assert re.search(
        r"html\[data-adaptive-foreground=\"dark\"\] \{\s*--insights-sticky-head-bg:\s*rgba\(242,244,248",
        FLOWS_CSS,
    ), "深墨时底色必须是浅色带"


def test_head_ink_is_pinned_to_its_own_band() -> None:
    # 逐 th 采样采的是壁纸，不是这条不透明带子；不钉死就会同一条表头里两种墨色
    # （实测 分类/连接数/终端/线路 拿到 luma 0.049 压在 0.131 的带子上）。
    assert re.search(
        r"\.dwrt-app \.dwrt-kit-table-wrap \.dwrt-kit-table\.insights-audit-table thead th,\s*\n"
        r"\.dwrt-app \.dwrt-kit-table-wrap \.dwrt-kit-table\.insights-audit-table thead th \* \{",
        FLOWS_CSS,
    ), "审计表头墨色必须连子元素一起钉住，按钮文字走的是同一套别名"

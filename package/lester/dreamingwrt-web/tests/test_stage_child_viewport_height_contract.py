#!/usr/bin/env python3
"""舞台子元素不得用裸 100dvh 声明高度。

用户报「菜单被 footer 削掉一块」，我前四轮全部找错方向（footer inset、margin、
reserve strip、grid 行数），因为**我一直在 100% 缩放下测，而这个缺陷只在缩放后出现**。

真因：`.console-stage` 的高度是 `calc(100dvh - var(--app-page-footer-reserve))`,
**比视口矮 58px**（页脚预留条）。而 stage 的子元素若声明 `height: 100dvh` 或
`min-height: 100dvh`，就要求整个视口高度，比容器高出那 58px；
stage 是 `overflow: hidden`，于是底部被直接裁掉 —— 筛选栏尾部连同它自己的
按钮排（清除筛选条件/下载/自定义列）一起消失。

为什么只在缩放时出现：这些规则挂在 `@media (max-width: 980px)` 里。
浏览器缩放会**等比缩小 CSS 视口**，1440px 窗口在 150% 下变成 960px CSS 像素，
跨过 980 断点，规则生效，缺陷显现。100% 下是 1440px，永远进不去这个断点。

实测（30.1，1440x900 窗口 + CDP 模拟缩放）：
  修复前 zoom=1.5 → 视口 960x600，`.insights-filter` 底边 612，超出视口 12px,
         筛选栏页脚底边 600 落在页面 footer 顶边 542 之下（被裁）。
  修复后 zoom=1.5 → 底边 554（在视口内），筛选栏页脚底边 542 与页面 footer 顶边齐平。
  全 71 条路由 x zoom 1.25/1.5 扫描：修复前另有 `/monitor/topology` 溢出 12px，
  同因同修；修复后零溢出。

**教训：布局缺陷必须在多个缩放/断点下验证。** 只测默认尺寸等于只测了一个分支。
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSSDIR = ROOT / "files/www/dreamingwrt/static/css"

# 这些是应用根/外壳级容器，它们**应该**占满视口（页脚就在它们内部），不属于舞台子元素。
SHELL_LEVEL = {
    ".dwrt-app",
    ".console-shell",
    ".setup-welcome",
    ".glass-submenu",
    ".glass-sidebar",
    ".dashboard-status-rail",
    ".console-main",
    ".login-shell",
}


def _selectors(head: str) -> list[str]:
    # 注释里可能出现逗号和选择器样例，先剥掉注释再切分
    head = re.sub(r"/\*.*?\*/", "", head, flags=re.S)
    return [s.strip() for s in head.split(",") if s.strip()]


# 抽屉 / sheet / 弹层是 position: fixed 的覆盖层，铺满视口是正确的：
# 它们不在 .console-stage 的流内，不受舞台高度约束，也不会被舞台裁切。
OVERLAY_HINTS = (
    "drawer", "sheet", "modal", "layer", "overlay", "dialog", "backdrop",
    "setup-page", "login",
)


def _is_overlay(selector: str, body: str) -> bool:
    low = selector.lower()
    if any(hint in low for hint in OVERLAY_HINTS):
        return True
    # 显式 fixed 定位的元素同理
    return bool(re.search(r"position:\s*fixed", body))


def test_stage_children_use_the_stage_height_token() -> None:
    offenders = []
    for path in sorted(CSSDIR.glob("*.css")):
        text = path.read_text()
        for match in re.finditer(r"([^{}]+)\{([^}]*)\}", text):
            head, body = match.group(1), match.group(2)
            if not re.search(r"(?:min-)?height:\s*100dvh", body):
                continue
            for sel in _selectors(head):
                # @media / @container 的条件文本不是选择器
                if sel.startswith("@"):
                    continue
                base = sel.split()[-1].split(":")[0]
                if base in SHELL_LEVEL or any(s in sel for s in SHELL_LEVEL):
                    continue
                # 舞台自身允许，它就是用 token 算出来的那个盒子
                if ".console-stage" in sel:
                    continue
                if _is_overlay(sel, body):
                    continue
                offenders.append(f"{path.name}: {sel.strip()[:70]}")
    assert not offenders, (
        "以下舞台子元素用了裸 100dvh，会比 .console-stage 高出页脚预留条的高度、"
        "底部被 overflow:hidden 裁掉（缩放到 980px 断点以下即可复现）。"
        "请改用 var(--app-stage-height)：\n  " + "\n  ".join(offenders)
    )


def test_stage_height_token_still_subtracts_the_reserve() -> None:
    css = (CSSDIR / "menu-shell.css").read_text()
    root = re.search(r":root\s*\{([^}]*)\}", css).group(1)
    assert "--app-stage-height: calc(100dvh - var(--app-page-footer-reserve))" in root, (
        "舞台高度必须扣掉页脚预留条，否则上面那条契约失去意义"
    )


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("stage child viewport height contract: ok")

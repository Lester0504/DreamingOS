#!/usr/bin/env python3
"""地图光点不得开启 motion blur 残影。

用户反复打回同一个现象：「开花依旧会，指的是一条线，会被平移复制多次」。

前三轮我都判错了，记下来避免第四次：
  F-27 判成「实时推送重绘叠加动画」——错。
  F-28 判成「国家码缺失导致坐标退路粒度太细」——错（那个确实是个缺陷，但不是这个现象）。
  F-29 判成「后端把同 IP 多连接输出成多条弧」——那是真的，但它只会让弧**重叠**，
       不会产生等间距、形状完全相同的一排副本。

真因（用逐层 canvas 像素探针实测到的）：`traffic pulse` 这一层
`effect.trailLength = 0.36`。**任何 > 0 的 trailLength 都会让 ZRender 把该 zlevel
切成 motionBlur 层**，其 `lastFrameAlpha = 0.7` —— 每帧保留上一帧的 70% 而不是清屏。
再叠上 `blendMode: 'lighter'`（加色混合），被保留的残影只会越叠越亮、永不衰减，
于是弧上移动的那个光点把自己拖成一排等间距、形状完全相同的副本。

实测数字（30.1 登录态，逐层取一列统计"不连续 ink 段数"）：
  修复前 layer3 = 14/14/15 段，ink 16398 且随时间增长
  修复后 layer3 =  1/ 1/ 2 段，ink  ~2100 且 15 秒内保持不变

**教训：只数喂给 ECharts 的数据条数是循环论证**，去重后当然是 9 条；
屏幕上多出来的墨迹在 canvas 合成层，必须量像素。
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"
CODE = (WWW / "static/js/insights-flows.js").read_text()


def _strip_comments(text: str) -> str:
    """去掉块注释与行注释。

    解释真因的注释里必然要提到 `blendMode: 'lighter'` 和 `trailLength`，
    否则没法说明为什么不能用它们。断言必须只看真实代码，不然注释本身会让测试报红
    （第一次写这条断言时就踩了这个坑）。
    """
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"^\s*//.*$", "", text, flags=re.M)


def test_no_positive_trail_length_anywhere() -> None:
    """trailLength 必须全部为 0。这是 motionBlur 的唯一开关。"""
    values = re.findall(r"trailLength:\s*([0-9.]+)", _strip_comments(CODE))
    assert values, "找不到 trailLength，渲染结构可能被重写，请重新确认残影行为"
    for value in values:
        assert float(value) == 0, (
            f"trailLength={value} 会把该层切成 motionBlur 残影层"
            "（lastFrameAlpha=0.7，每帧保留上一帧 70% 而不清屏），"
            "叠加 blendMode:'lighter' 后残影不衰减，直接造成用户看到的「一条线被复制多次」"
        )


def test_pulse_layer_does_not_use_additive_blending() -> None:
    """光点层不能用加色混合：一旦该层又变成残影层，加色会累积到饱和。"""
    code = _strip_comments(CODE)
    start = code.index("id: 'dwrt-traffic-pulse'")
    end = code.index("id: 'dwrt-destinations'")
    pulse = code[start:end]
    assert "blendMode: 'lighter'" not in pulse, (
        "traffic pulse 层不得使用 blendMode: 'lighter'"
    )


def test_root_cause_is_documented_next_to_the_setting() -> None:
    """把真因写在设置旁边，挡住下一个人"顺手调回去让它更好看"。"""
    start = CODE.index("id: 'dwrt-traffic-pulse'")
    end = CODE.index("id: 'dwrt-destinations'")
    pulse = CODE[start:end]
    assert "motionBlur" in pulse, "需在 trailLength 旁注明它会触发 motionBlur"
    assert "lastFrameAlpha" in pulse, "需注明每帧保留上一帧的比例"


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("insights map pulse motion-blur contract: ok")

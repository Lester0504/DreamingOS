"""地图上方是一条通栏控制台，不是四张散卡。

用户给了 demo：四个模块共享一张玻璃、等高、竖分割线分隔、排名项带迷你进度条。
原实现是四张各自加玻璃的卡片，1440px 下实测高度 190 / 190 / 174 / 174，
并且在 920px 容器查询下折成 2x2。

这里守三件容易被改回去的事：

1. 玻璃只加在外层容器一处，模块内部不得再挂 `dwrt-glass-card`。
2. 进度条宽度按**该模块自己的排名指标**归一化。目的地/客户端是 `flow_count`，
   应用是 `bytes`；一律按 bytes 算会让条长顺序和列表顺序不一致（实测
   down.debian7.com 146 条流占 24MB，www.coway.com 672 条流只占 6MB）。
3. 风险百分比必须标注抽样口径。实测 `risk_count_scope: "sampled_rows"`、
   76 / 302870 覆盖率约 0.025%，不标注等于宣称整窗口风险已查清。
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"
JS = (WWW / "static/js/insights-flows.js").read_text(encoding="utf-8")
CSS = (WWW / "static/css/insights-flows.css").read_text(encoding="utf-8")


def block(selector: str, text: str) -> str:
    match = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", text)
    assert match, f"missing rule {selector}"
    return match.group(1)


def test_one_shared_glass_not_four_cards() -> None:
    overview = JS[JS.index("function overviewMarkup") : JS.index("function mapPanelMarkup")]
    assert "insights-console" in overview and "dwrt-glass-card" in overview, (
        "通栏控制台的玻璃加在外层容器上"
    )
    # 模块内部不得重复玻璃，否则又变成四张卡叠在一张卡里。
    for fn in ("function summaryMarkup", "function topCard"):
        body = JS[JS.index(fn) : JS.index(fn) + 2600]
        module = body[: body.find("</div>")]
        assert "dwrt-glass-card" not in module, f"{fn} 不应再给模块单独加玻璃"
    assert "insights-top-card" not in JS and "insights-summary-card" not in JS, (
        "旧的四卡类名必须彻底移除，留着下次就会被照着改回去"
    )


def test_modules_are_equal_height_with_vertical_dividers() -> None:
    row = block(".insights-overview-row", CSS)
    assert "align-items: stretch" in row, "四个模块必须等高，高度参差正是这次要修的缺陷"
    assert "grid-template-columns: 1.15fr 1.4fr 1.15fr 1.4fr" in row, (
        "四列栅格：摘要与客户端窄，目的地与应用要放长域名"
    )
    module = block(".insights-console-module", CSS)
    assert "border-right" in module, "模块之间用竖分割线分隔，不是靠卡片间距"
    last = block(".insights-overview-row > .insights-console-module:last-child", CSS)
    assert "border-right: 0" in last, "最后一个模块不画分割线"


def test_narrow_container_threshold_is_760_not_920() -> None:
    # 这页主区被左侧 332px 筛选栏挤过，1440px 视口下实测只有 839px。
    # 阈值留在 920px 会让控制台在默认视口就折成 2x2。
    assert "@container insights-main (max-width: 760px)" in CSS, (
        "760px 是实测出来的阈值：主区 839px 必须仍是四列"
    )
    assert "@container insights-main (max-width: 920px)" not in CSS, (
        "旧的 920px 阈值会在默认视口就把通栏控制台折断"
    )


def test_bar_width_follows_each_module_own_ranking_metric() -> None:
    assert "function topItemWeight(" in JS, "进度条需要一个跟随 metric_type 的权重函数"
    weight = JS[JS.index("function topItemWeight(") : JS.index("function topCard(")]
    assert "metric_type" in weight and "ranking_basis" in weight, (
        "权重必须读后端给的排名依据，而不是一律按字节算"
    )
    assert re.search(r"byte|traffic", weight), "bytes 排名的分支"
    assert re.search(r"count|hit|flow", weight), "flow_count 排名的分支"
    card = JS[JS.index("function topCard(") : JS.index("function topCountLabel(")]
    assert "topItemWeight(item)" in card, "条目宽度要用这个权重"
    assert "peak" in card, "宽度按榜首归一化"


def test_risk_percentages_declare_sampled_scope() -> None:
    assert "function riskScopeBadge(" in JS, (
        "风险分布必须标注口径，实测覆盖率只有 76 / 302870"
    )
    badge = JS[JS.index("function riskScopeBadge(") : JS.index("function riskScopeBadge(") + 900]
    assert "risk_count_sampled_rows" in badge and "risk_count_is_window_total" in badge, (
        "口径要读后端的抽样字段，不能写死成一个字面量"
    )
    summary = JS[JS.index("function summaryMarkup") : JS.index("function riskScopeBadge(")]
    assert "riskScopeBadge()" in summary, "徽标要真的渲染出来"


def test_long_names_clip_with_a_tooltip() -> None:
    name = block(".insights-console-rank-name", CSS)
    for declaration in ("overflow: hidden", "text-overflow: ellipsis", "white-space: nowrap"):
        assert declaration in name, declaration
    assert "display: block" in name, "inline 盒不会触发 ellipsis"
    card = JS[JS.index("function topCard(") : JS.index("function topCountLabel(")]
    assert "data-dwrt-tooltip" in card, "截断后必须能 hover 看全貌"


def test_realtime_patch_anchors_survive() -> None:
    # updateFlowsRealtimeDom() 按这四个 kind 逐块 patch，换掉钩子会让实时刷新静默失效。
    for kind in ("summary", "destination", "client", "application"):
        assert f'data-insights-overview-card="${{html(\'{kind}\')}}"' in JS or kind in JS, kind
    assert 'data-insights-overview-card="summary"' in JS, "摘要模块的 patch 锚点"
    card = JS[JS.index("function topCard(") : JS.index("function topCountLabel(")]
    assert "data-insights-overview-card=" in card, "三个榜单模块的 patch 锚点"


for name, value in sorted(globals().items()):
    if name.startswith("test_") and callable(value):
        value()

print("insights console contract: ok")

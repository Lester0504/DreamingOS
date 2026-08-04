#!/usr/bin/env python3
"""分流状态卡片的时间维度与措辞契约。

用户原话：「这里语义模糊，内核聚合是什么意思？我选的应该是按运营商分流，
那么我是你还能是 0？这里的策略分流是什么意思？」

旧副标题把三个数塞进一句话：`N 条规则 · 当前 M 条 · 内核聚合 K 次`。
前两个是**瞬时值**（近 300 秒活跃流），第三个是**历史累计**（各规则 hit_count 之和,
来自内核计数器）。量级差几个数量级又并列同一行，读者无从分辨。

「内核聚合」描述的是实现机制（内核态计数器聚合），既不指向"规则命中"也不指向"累计"。

实测 30.1（`/api/v1/route_status`，2026-08-03）：`active_flows:21240`、`rule_count:3`、
`hit_total:22063`，且**响应里根本没有 `steered_flows` 字段**——0.0% 的数据侧根因
在后端写死常量 0（见 Handoff/Acceptance-to-Backend-steered-flows-hardcoded-zero.md）,
不是本卡片能修的。本契约只守文案与呈现。

守四件事：

1. 界面不再出现「内核聚合」。
2. 瞬时段与累计段分离，累计段带「累计」字样，措辞集中在一个函数里。
3. 瞬时 0 而累计非 0 时必须显式解释这个矛盾，而不是让用户自己推断。
4. 轮询补丁必须复用同一个措辞与语气函数。抄一份文案在 `patchOverview()` 里,
   下一个轮询周期就会把旧措辞写回 DOM——这正是本次差点漏掉的地方。
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "files/www/dreamingwrt/plugins/native/policy-status.js").read_text(encoding="utf-8")


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


CODE = _strip_comments(SOURCE)


def _fn(name: str, text: str = CODE) -> str:
    match = re.search(rf"function {name}\(", text)
    assert match, f"函数不存在：{name}"
    start = text.index("{", match.end() - 1)
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    raise AssertionError(f"函数体未闭合：{name}")


def test_kernel_aggregate_wording_is_gone_from_rendered_text() -> None:
    """注释里可以解释这个词的来历，渲染路径里不能再出现。"""
    assert "内核聚合" not in CODE, "渲染路径不得再出现「内核聚合」"


def test_cumulative_is_labelled_as_cumulative() -> None:
    detail = _fn("policyDetailText")
    assert "累计命中" in detail, "历史累计必须自称累计"
    assert "条活跃" in detail, "瞬时值必须标明是当前活跃"


def test_contradiction_between_scales_is_explained() -> None:
    detail = _fn("policyDetailText")
    assert "steeredFlows === 0" in detail and "hitTotal" in detail, "必须识别瞬时 0 + 累计非 0"
    assert "当前无活跃分流连接" in detail, "矛盾态必须显式解释，不能让用户自行推断"


def test_contradiction_is_not_painted_as_healthy() -> None:
    tone = _fn("policyTone")
    assert "'warn'" in tone, "矛盾态不能报成 ok 绿色"
    assert "steeredFlows === 0" in tone


def test_polling_reuses_the_same_wording_and_tone() -> None:
    """轮询路径抄一份文案，下一周期就会把旧措辞写回 DOM。"""
    patch = _fn("patchOverview")
    assert "policyDetailText(data)" in patch, "轮询必须复用措辞函数，不得内联副本"
    assert "policyTone(" in patch, "轮询必须同步语气，否则矛盾态会显示成绿卡配警示语"
    assert "条规则 · 当前" not in patch, "不得在轮询路径里内联第二份文案"


def test_wording_has_a_single_source() -> None:
    assert CODE.count("累计命中") == 1, "累计文案只能有一个出口"


# 以下为 2026-08-03 后端新契约（Backend-to-Front-route-status-steering-fields.md）。
# 后端把瞬时量与累计量分开并自描述，且实现了真实的 steered_flows
# （30.1 实测 active=638 / steered=65 / load_balance=683 / bypass=258）。
def test_percentage_uses_instantaneous_over_instantaneous() -> None:
    # 占比必须是瞬时/瞬时。用 hit_total 当分母是瞬时除累计，比值无意义。
    assert "steeredFlows / activeFlows * 100" in CODE
    assert "steeredFlows / hitTotal" not in CODE
    assert "hitTotal * 100" not in CODE


def test_degraded_counter_shows_unavailable_not_zero() -> None:
    """conntrack 不可读时后端给 null 而非 0，前端必须说「不可用」。

    显示 0 会退回到「看起来一条都没分流」的误导，这正是后端特意用 null
    而不是 0 的原因，也是这份交接单点名要求的降级行为。
    """
    detail = CODE.split("function policyDetailText")[1].split("function policyTone")[0]
    assert "steeredFlowsSupported === false" in detail
    assert "steeredFlows === null" in detail
    assert "不可用" in detail
    # 降级态不能被判成绿色
    tone = CODE.split("function policyTone")[1].split("function unsteeredDetailText")[0]
    assert "steeredFlowsSupported === false" in tone
    assert "steeredFlows === null" in tone
    # 瞬时字段一律不得用 `|| 0` 抹掉 null
    for field in ("load_balance_flows", "unattributed_flows", "bypass_flows"):
        assert f"{field} || 0" not in CODE, f"{field} 不得用 || 0 兜底，会把不可用显示成 0"


def test_load_balance_flows_are_visible() -> None:
    """负载均衡连接既不算显式分流也不算未分流，必须单独点出来。

    30.1 实测负载均衡 683 条 > 显式分流 65 条。不显示的话用户只看到 65,
    会以为分流几乎没生效。
    """
    assert "loadBalanceFlows" in CODE
    assert "负载均衡" in CODE
    assert "load_balance_flows" in CODE


def test_unsteered_detail_also_shared_between_render_paths() -> None:
    """与 policyDetailText 同样的坑：轮询补丁必须复用同一个函数。"""
    assert CODE.count("function unsteeredDetailText") == 1
    # 减去定义那一行，剩下的才是调用点：首次渲染与轮询补丁各一次
    calls = CODE.count("unsteeredDetailText(data)") - CODE.count("function unsteeredDetailText(data)")
    assert calls == 2, f"首次渲染与轮询补丁各应调用一次，实际 {calls}"
    patch = CODE.split("function patchOverview")[1]
    assert "当前未匹配显式分流'" not in patch, "不得在轮询路径里内联第二份未分流文案"


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("policy split card time scale contract: ok")

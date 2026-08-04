"""终端管控表单只呈现后端真的会接受的东西。

用户 2026-08-04：「终端详情——管控详情的这几个管控，下面的 UI 是一样的东西，
压根都是假的」。他说得对，而且比"长得一样"更严重 —— 那些选项保存必然失败。

后端 `webd_client_control_validate_write()`（`jmxd/src/webd/jmx_app_api.c:13513`）
对下面每一项都直接返回 409：

    control_type != 'IP限速'            -> unsupported_control_type
    limit_mode == '共享限速'             -> shared_rate_limit_dataplane_not_implemented
    line 选了任何具体值                 -> line_scoped_client_rate_limit_not_implemented
    protocol 不在 TCP/UDP/ICMP/ICMPv6   -> unsupported_l4_protocol
    schedule_mode == 'plan'             -> schedule_plan_reference_not_implemented

实测 `/api/v1/client_control_rules` 的能力位只有
`client_control_rate_limit: true`，另外三种管控连能力位都没有。

原表单把四种类型、共享限速、线路下拉、时间计划全摆出来，而且四种类型共用同一套
限速字段 —— 选「访问控制」照样让人填上下行限速。
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JS = (ROOT / "files/www/dreamingwrt/static/js/client-details.js").read_text(encoding="utf-8")

drawer = JS[JS.index("function controlDrawer(client, profile) {"):JS.index("function controlPanel(")]


def test_unsupported_control_types_cannot_be_chosen() -> None:
    # 四种类型仍然列出（让用户知道规划中有什么），但未开放的必须 disabled。
    assert "const CONTROL_TYPES" in JS
    for label in ("应用管控", "访问控制", "时间管控"):
        assert label in JS, label
    assert "capability: 'client_control_rate_limit'" in JS, (
        "IP限速要绑定后端真实下发的那个能力位"
    )
    assert "disabled" in drawer and "（未开放）" in drawer, (
        "没有数据面的类型必须禁用并标注，否则点了必然 409"
    )
    assert "controlCapability(" in drawer, "可选性要由能力位决定，不能写死"


def test_shared_rate_limit_and_line_are_not_offered() -> None:
    # 这两项后端一律 409，所以不能是可选控件。
    # 「共享限速」这几个字可以出现在只读说明里（解释为什么不提供），
    # 但不能是一个能选的控件。
    assert not re.search(r'<select name="limit_mode"', drawer), (
        "共享限速没有数据面实现，limit_mode 不能是下拉选择"
    )
    assert not re.search(r'<option[^>]*>共享限速', drawer), (
        "共享限速不能作为选项出现"
    )
    assert 'name="limit_mode" value="独立限速"' in drawer, (
        "limit_mode 固定提交独立限速"
    )
    assert 'name="line" value=""' in drawer, (
        "线路必须提交空值：选任何具体线路后端都会以 409 拒绝"
    )
    assert "connectionDefaultLines" not in drawer, "线路下拉必须移除"


def test_schedule_plan_mode_is_gone() -> None:
    # `webd_control_schedule_mode_supported()` 不接受 'plan'。
    assert 'value="plan"' not in drawer, (
        "时间计划模式没有可执行的计划引用，后端会 409"
    )
    assert "CONTROL_SCHEDULE_MODES" in JS
    modes = JS[JS.index("const CONTROL_SCHEDULE_MODES"):]
    modes = modes[: modes.index("];")]
    for value in ("always", "daily", "week", "range"):
        assert f"'{value}'" in modes, value
    assert "plan" not in modes


def test_protocol_options_match_the_dataplane() -> None:
    protocols = JS[JS.index("const CONTROL_PROTOCOLS"):]
    protocols = protocols[: protocols.index("]")]
    for value in ("任意", "TCP", "UDP", "ICMP", "ICMPv6"):
        assert value in protocols, value


def test_rules_and_capabilities_come_from_the_real_endpoint() -> None:
    assert "'/api/v1/client_control_rules'" in JS, (
        "规则与能力位必须取自真实接口，而不是从 profile 里翻十来个候选键"
    )
    assert "function loadControlRules(" in JS
    loader = JS[JS.index("async function loadControlRules("):JS.index("async function postApiResource(")]
    assert "capabilities" in loader, "能力位要落到 page.controlCapabilities"
    assert "response.ok" in loader, (
        "必须先看 HTTP 状态：401 被当成空结果会得出「后端没有数据」的错误结论"
    )
    scoped = JS[JS.index("function controlRules("):JS.index("function controlRuleContent(")]
    assert "controlRuleSource" in scoped, "列表要用接口结果"
    # 过滤必须真的读条目上的 mac 字段，光有 `toLowerCase()` 不算。
    assert re.search(r"item\s*&&\s*item\.mac", scoped), (
        "接口返回全机规则，必须按本终端 MAC 过滤，否则会把别人的规则显示在这台终端上"
    )
    assert re.search(r"target\s*===\s*mac", scoped), "过滤条件要真的比较 MAC"


def test_rule_content_shows_the_actual_limits() -> None:
    normalize = JS[JS.index("function normalizeControlRule("):JS.index("function controlRules(")]
    # 限速值必须真的进到 content 里，而不是只在别处出现过这两个字段名。
    content_expr = re.search(r"const content = ([^;]+);", normalize)
    assert content_expr, "找不到 content 的赋值"
    assert "rate(" in content_expr.group(1), (
        "内容列要显示真实的上下行限速，光有星期与时间段看不出这条规则限了什么"
    )
    assert "up_limit" in normalize and "down_limit" in normalize
    assert "'不限'" in normalize, "0 表示不限制，要照实说"
    assert "apply_state" in normalize or "applyState" in normalize, (
        "要带上后端的下发状态，否则分不清「已保存」和「已生效」"
    )


for name, value in sorted(globals().items()):
    if name.startswith("test_") and callable(value):
        value()

print("ok: client control form only offers what the dataplane actually accepts")

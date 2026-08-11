#!/usr/bin/env python3
"""终端限速拆成「MAC 限速」「IP 限速」两个 tab，且 IP tab 不得放假控件。
来源：`Acceptance-to-Front-Backend-client-speed-limit-two-tabs-ip-and-mac.md`
（用户要求参照 31.1 爱快的 `mac_qos` / `simple_qos` 两张表）。
关键约束来自后端现状，2026-08-04 用只读凭据实测 30.1 + 读源码确认：
  - `client_control_rules` 建表语句只有 `mac TEXT NOT NULL`，**没有** `ip_addr` /
    `target_kind`（`jmxd/src/jmx_netconfig_db.c:803-829`，`:921` 第二处同样没有）。
  - 运行态回读 `runtime_match_precision = "client_mac_exact"`、
    `runtime_match_scope = "client_mac_on_lan_bridge"` —— 名为「IP限速」的规则
    实际按 MAC 生效。
  - 写入路径 `jmxd/src/webd/jmx_app_api.c:13663` 要求 `control_type == 'IP限速'`
    才放行，那个字面值已被 MAC 维度占用。
所以 IP tab 只能是能力门占位：放表单要么把 IP 写进 `mac` 列污染数据，
要么做个存不进去的空壳，两者都比如实说明更糟。
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"
MODULE = (WWW / "plugins/native/client-speed-limit.js").read_text(encoding="utf-8")
STYLE = (WWW / "static/css/user-authentication.css").read_text(encoding="utf-8")

# 1) 两个 tab 都在，且默认停在唯一可用的 MAC
assert "function tabsMarkup" in MODULE
assert "['mac', 'MAC 限速']" in MODULE
assert "['ip', 'IP 限速']" in MODULE
assert "tab: 'mac'" in MODULE, "默认必须停在真正可用的 MAC tab"
assert "data-client-speed-tab" in MODULE
# 页面级 tab 必须消费 Kit 的 62px page-tabs，不再复用表格内分段控件。
assert 'class="dwrt-kit-tabs dwrt-kit-page-tabs client-speed-tabs"' in MODULE
assert 'role="tablist"' in MODULE
assert 'class="dwrt-kit-tab' in MODULE
assert 'role="tab"' in MODULE
assert 'data-value="${id}"' in MODULE
assert "user-auth-segmented client-speed-tabs" not in MODULE

# 2) 主体按 tab 切换
body = MODULE[MODULE.index("function bodyMarkup"):MODULE.index("function macTableMarkup")]
assert "state.tab === 'ip'" in body and "ipPlaceholderMarkup()" in body and "macTableMarkup()" in body

# 3) IP 占位区**不得**包含任何可提交或可编辑的控件。
#    判据限定在占位函数内：整个文件里合法地存在 MAC 侧的表单与按钮。
placeholder = MODULE[MODULE.index("function ipPlaceholderMarkup"):MODULE.index("function macTableMarkup")]
for fake in ("<input", "<select", "<textarea", "<button", "data-client-speed-field", "data-client-speed-save"):
    assert fake not in placeholder, f"IP 占位不得包含 {fake}（后端无 IP 字段，填了无处保存）"
# 必须如实说明为什么不可用，并指向可用的替代路径
assert "尚未开放" in placeholder
assert "MAC 限速" in placeholder, "应告诉用户改用哪条可用路径"
#
# 文案口径在 2026-08-08 由用户改判，见交接单
# `Acceptance-to-Front-acl-expires-and-schedule-copy-is-stale.md` 第 3 条：
# 面向客户的占位文案**不得**暴露内部实现口径（原先要求出现
# `client_mac_on_lan_bridge`、以及「填了也无处保存」），也**不得**论证
# MAC 维度比 IP 更好。改为中性的「即将开放」。
# 判据随之反转：这些说辞出现即为回归。
for banned in ("client_mac_on_lan_bridge", "填了也无处保存", "无处保存", "优势"):
    assert banned not in placeholder, f"占位文案不得再出现「{banned}」（用户明确否决这种答复）"

# 4) 轮询不得整页重建 —— 这是本轮实测抓到的真缺陷。
#
#    原判据是「没有抽屉打开就 renderShell()」，而 `load()` 首尾各调一次 render()，
#    于是每个轮询周期都用 innerHTML 重写整个 shell。30.1 实测：静置 20s 内 shell
#    被重建 **2 次**，肉眼是周期性闪烁，两个 tab 都有。
#    修好后同环境同样 20s 内为 **0 次**。
#
#    正确判据：render() 只在**未挂载**时 renderShell()，已挂载走局部 patch。
render_fn = MODULE[MODULE.index("function render()"):MODULE.index("function patchTabs")]
assert "if (!mounted) {" in render_fn, render_fn
assert "renderShell();" in render_fn
# 不得再出现「没有抽屉就整页重建」那种判据
assert "overlayOpen" not in render_fn, "已挂载时不得因为抽屉没开就整页重建"
for patcher in ("patchTabs()", "patchToolbar()", "patchNotice()", "patchBody()", "renderOverlays()"):
    assert patcher in render_fn, patcher
# IP tab 的主体是静态文本，局部更新时应跳过而不是替换成表格
patch_body = MODULE[MODULE.index("function patchBody"):MODULE.index("function patchToolbar")]
assert "state.tab === 'ip'" in patch_body
assert "client-speed-ip-card" in patch_body

# 5) `0` 必须呈现为「不限 / 不限速」，不是数字 0（爱快语义，后端也回读
#    apply_reason = zero_limit_means_unlimited）
rate = MODULE[MODULE.index("function rateText"):MODULE.index("function scheduleText")]
assert "'不限'" in rate
assert re.search(r"number > 0 \?", rate), rate
assert "填 0 表示不限速" in MODULE, "表单帮助文案也要说明 0 的语义"

# 6) 那个误导性的 `control_type` 字面值只能出现在请求体与校验里，不得直接显示给用户。
#    它是后端历史枚举值，与实际的 MAC 维度矛盾。
for rendered in ('escapeHtml(rule.control_type)', '${rule.control_type}', '${payload.control_type}'):
    assert rendered not in MODULE, f"不得把 control_type 直接渲染给用户：{rendered}"

# 7) 样式：占位卡按内容高度，不能吃掉剩余空间（否则三段文字撑满整屏像加载失败）
assert ".client-speed-ip-card" in STYLE
assert ".client-speed-ip-body" in STYLE
# 切片必须**只覆盖这一条规则**（到第一个 `}` 为止）。取固定字符窗口会顺带圈进
# 下一条 `.client-speed-header { flex: 0 0 auto; }`，于是把占位卡改成 1 1 auto
# 也照样绿 —— 实测过这个假阳性。
_ip_start = STYLE.index("> .client-speed-ip-card")
ip_card = STYLE[_ip_start:STYLE.index("}", _ip_start) + 1]
assert "flex: 0 0 auto" in ip_card, ip_card

print("ok: client speed limit exposes MAC/IP tabs with an honest capability-gated IP placeholder")

#!/usr/bin/env python3
"""复用 `.user-auth-workbench` 的页面必须自己声明弹性列，否则条件出现的提示条会被拉满。
用户 2026-08-04 的反馈：「终端限速这几个按钮太夸张了，点一下他就跳」。
真因不在按钮：`.user-auth-workbench` 的基线是 `grid-template-rows: minmax(0, 1fr)`，
只为「工作区里只有一张表格」写的。启停成功后 `patchNotice()` 往里插提示条，网格给它开
一条隐式行、同样按 1fr 分配，于是一行文字的提示条被拉到与表格等高 —— 30.1 实测
618px，表格从 y=19 掉到 y=654，那一行按钮从光标底下跑掉 635px。
`.user-auth-notice` 自带的 `flex: 0 0 auto` 在网格父级里是无效声明，挡不住这件事，
所以只看源码很容易判成正常。修好后同环境实测提示条 38px、表格 y=74。
design.md 第 11 条已写明这条规则；这里把它钉成契约，避免下一个复用工作区的页面再犯。
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"

BASE = (WWW / "static/css/user-authentication.css").read_text(encoding="utf-8")

# 基线本身必须仍是单行网格；如果哪天它改了，下面各页的覆盖就该重新评估。
assert "grid-template-rows: minmax(0, 1fr)" in BASE

# 每个复用 `.user-auth-workbench` 的路由作用域，都要在自己的样式里把这一层改成弹性列。
SCOPES = {
    ".client-speed-shell > .user-auth-workbench": "static/css/user-authentication.css",
    ".app-filter-shell > .user-auth-workbench": "static/css/user-authentication.css",
    ".web-access-workbench": "static/css/web-access-control.css",
    ".cnc-workbench": "static/css/user-authentication.css",
}

for selector, css_path in SCOPES.items():
    css = (WWW / css_path).read_text(encoding="utf-8")
    block = None
    for match in re.finditer(re.escape(selector) + r"\s*\{([^}]*)\}", css):
        body = match.group(1)
        if "display" in body or "flex-direction" in body or "grid-template-rows" in body:
            block = body
            break
    assert block is not None, f"{selector} 没有任何布局声明（{css_path}）"
    # 允许两种解法：弹性列，或显式写清每一行的固定行模板。禁止继承那条单行基线。
    flex_column = "display: flex" in block and "flex-direction: column" in block
    explicit_rows = "grid-template-rows" in block and "auto" in block
    assert flex_column or explicit_rows, (selector, block.strip())

# 提示条在这些作用域里必须按内容高度，不能吃 1fr。
NOTICE_SCOPES = {
    ".client-speed-shell > .user-auth-workbench > .user-auth-notice": "static/css/user-authentication.css",
    ".app-filter-shell > .user-auth-workbench > .user-auth-notice": "static/css/user-authentication.css",
    ".web-access-workbench > .user-auth-notice": "static/css/web-access-control.css",
}
for selector, css_path in NOTICE_SCOPES.items():
    css = (WWW / css_path).read_text(encoding="utf-8")
    match = re.search(re.escape(selector) + r"[^{]*\{([^}]*)\}", css)
    assert match, f"{selector} 缺少提示条的高度约束"
    assert "flex: 0 0 auto" in match.group(1), (selector, match.group(1).strip())

# 表格卡必须吃掉剩余高度并允许收缩，否则长表把卡片顶出工作区。
for selector in (".client-speed-shell > .user-auth-workbench > .client-speed-table-card",
                 ".app-filter-shell > .user-auth-workbench > .app-filter-table-card"):
    match = re.search(re.escape(selector) + r"[^{]*\{([^}]*)\}", BASE)
    assert match, f"{selector} 缺少剩余高度声明"
    body = match.group(1)
    assert "flex: 1 1 auto" in body and "min-height: 0" in body, (selector, body.strip())

print("ok: shared workbench scopes size their conditional notice by content, not by 1fr")

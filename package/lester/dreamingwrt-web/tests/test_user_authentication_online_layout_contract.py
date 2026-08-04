#!/usr/bin/env python3
"""认证与管控的表格页把搜索与动作按钮收在表格卡里，页顶不留空白带。

用户 2026-08-04 的要求：「认证与管控有很多页面这些按钮没有收到表格里面」。
实测在线用户 / 账号管理 / 代拨服务 / 终端限速四页的按钮都在一个独立
`<header class="policy-toolbar">` 里浮在表格卡之外，与 design.md「Tables」
相悖（计数与操作应在 `.dwrt-kit-table-toolbar` 内）。

这里同时守住原本那条缺陷不复发：没有二级 tab 的页面不得留下一条空 header。
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"
MODULE = (WWW / "plugins/native/user-authentication.js").read_text(encoding="utf-8")
STYLE = (WWW / "static/css/user-authentication.css").read_text(encoding="utf-8")
MENU = (WWW / "static/menu/main.json").read_text(encoding="utf-8")

assert "if (!header.children.length) header.remove();" in MODULE, (
    "没有 tab 也没有工具栏时不能留下空 header，那会在页顶留一条空白带"
)
assert ".user-auth-page-header.is-toolbar-only" in STYLE
assert "min-height: 0;" in STYLE[STYLE.index(".user-auth-page-header.is-toolbar-only"):STYLE.index(".user-auth-notice")]

# 表格页的控件必须走 tableMarkup 的 toolbar 槽位，收进 kit 表格工具栏。
assert "function tableToolbarControls(" in MODULE, (
    "表格页需要一个把搜索与动作放进表格卡工具栏的辅助函数"
)
assert "options.toolbar" in MODULE, "tableMarkup 必须接收 toolbar 槽位"
assert "user-auth-table-controls" in MODULE and "user-auth-table-controls" in STYLE
for label, snippet in (
    ("在线用户", "toolbar: tableToolbarControls({ placeholder: '搜索账号、姓名、IP、MAC 或接口'"),
    ("账号管理", "toolbar: tableToolbarControls({ leading, actions })"),
    ("代拨服务", "const toolbar = tableToolbarControls({ placeholder: online"),
    ("定期通知", "toolbar: tableToolbarControls({ placeholder: '搜索名称、接收对象或备注'"),
):
    assert snippet in MODULE, f"{label} 的工具栏没有收进表格卡"

# 表格工具栏不得为了塞控件被撑成高头部（design.md 要求 48-58px；实测曾顶到 65px）。
rich = STYLE[STYLE.index(".dwrt-kit-table-toolbar.user-auth-table-toolbar-rich"):]
rich = rich[: rich.index("}")]
assert "min-height: 52px" in rich, "工具栏高度要留在 48-58px 区间"
# 搜索框高度来自 kit 的 --dwrt-search-size；硬写 height 压不过 kit 的更具体选择器。
assert "--dwrt-search-size: 36px" in STYLE, (
    "卡内搜索框要通过 kit 变量降高，硬写 height 会被 "
    ".dwrt-kit-expand-search[data-dwrt-expand-search=\"true\"] 覆盖"
)
# 整批 UI 收口后很多路由共用同一个缓存键，全站字符串计数不再等价于本模块的路由数，
# 所以按 module 归属统计这 5 条 user-authentication 路由。
_menu = json.loads(MENU)


def _routes(items):
    for item in items:
        yield item
        yield from _routes(item.get("children") or [])


_auth_routes = [item for item in _routes(_menu["items"]) if item.get("module") == "native/user-authentication.js"]
assert len(_auth_routes) == 5, len(_auth_routes)
# 版本号会随每次改动 bump，钉字面量只会让契约每次都红。要守的是「浏览器不会同时
# 持有两套代码」，但这里的判据不是「三个字段字面相等」——实际生效的键由 menu-shell
# 决定：`user-authentication.js` 与它的 css 都在 `shellVersioned` 白名单里
# （menu-shell.js 的 routeModuleCacheUrl / routeItemStyleEntry），命中白名单时
# main.json 的 module_version / style_version 会被**忽略**，一律用 shell 自己的
# VERSION。所以真正的约束是下面三条。
import re

_module_version = re.search(r"const VERSION = '([^']+)'", MODULE).group(1)
_shell = (WWW / "static/js/menu-shell.js").read_text(encoding="utf-8")

# 1) 模块与样式必须仍在 shell 白名单内。一旦被移出，main.json 的字段就重新生效，
#    此时字段之间的不一致会真的让 js 与 css 走上不同的缓存键。
assert "'/plugins/native/user-authentication.js'" in _shell
assert "'/static/css/user-authentication.css'" in _shell

# 2) 五条路由的版本字段必须彼此一致。跨路由不一致意味着同一个模块在不同菜单项下
#    可能被请求两次，这是「页面频繁崩溃、菜单消失」那次事故的形态。
#    注意：别的角色（APP过滤）会把 style_version 一起 bump 成自己的键，这在白名单
#    生效期间无害，因此只要求组内一致，不要求等于本模块的 VERSION。
assert len({item.get("module_version") for item in _auth_routes}) == 1, [
    item.get("module_version") for item in _auth_routes
]
assert len({item.get("style_version") for item in _auth_routes}) == 1, [
    item.get("style_version") for item in _auth_routes
]

# 3) module_version 仍应记录本模块自己的 VERSION，作为「改了模块就 bump」的账面凭据。
assert _auth_routes[0].get("module_version") == _module_version, (
    _auth_routes[0].get("module_version"),
    _module_version,
)

print("ok: online authentication toolbar occupies the header row without a blank tab band")

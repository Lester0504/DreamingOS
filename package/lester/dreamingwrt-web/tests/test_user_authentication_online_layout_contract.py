#!/usr/bin/env python3
"""Online authentication keeps its toolbar at the page top without a phantom tab row."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"
MODULE = (WWW / "plugins/native/user-authentication.js").read_text(encoding="utf-8")
STYLE = (WWW / "static/css/user-authentication.css").read_text(encoding="utf-8")
MENU = (WWW / "static/menu/main.json").read_text(encoding="utf-8")

assert "const needsHeader = Boolean(tabs) || state.page !== 'web';" in MODULE
assert "user-auth-page-header${tabs ? '' : ' is-toolbar-only'}" in MODULE
assert "if (!header.children.length) header.remove();" in MODULE
assert ".user-auth-page-header.is-toolbar-only" in STYLE
assert "min-height: 0;" in STYLE[STYLE.index(".user-auth-page-header.is-toolbar-only"):STYLE.index(".user-auth-notice")]
assert MODULE.count("20260802-ui-batch-01") == 1
# 整批 UI 收口后很多路由共用同一个缓存键，全站字符串计数不再等价于本模块的路由数，
# 所以按 module 归属统计这 5 条 user-authentication 路由。
_menu = json.loads(MENU)


def _routes(items):
    for item in items:
        yield item
        yield from _routes(item.get("children") or [])


_auth_routes = [item for item in _routes(_menu["items"]) if item.get("module") == "native/user-authentication.js"]
assert len(_auth_routes) == 5, len(_auth_routes)
assert all(item.get("module_version") == "20260802-ui-batch-01" for item in _auth_routes)
assert all(item.get("style_version") == "20260802-ui-batch-01" for item in _auth_routes)

print("ok: online authentication toolbar occupies the header row without a blank tab band")

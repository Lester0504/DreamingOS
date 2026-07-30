#!/usr/bin/env python3
"""Online authentication keeps its toolbar at the page top without a phantom tab row."""

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
assert MODULE.count("20260730-user-auth-online-layout-11") == 1
assert MENU.count('\"module_version\": \"20260730-user-auth-online-layout-11\"') == 5
assert MENU.count('\"style_version\": \"20260730-user-auth-online-layout-11\"') == 5

print("ok: online authentication toolbar occupies the header row without a blank tab band")

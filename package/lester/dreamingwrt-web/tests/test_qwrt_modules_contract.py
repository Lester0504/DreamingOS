#!/usr/bin/env python3
"""QWRT module management contract.

The route used to be a hardcoded "unavailable" stub while the backend already
served /api/v1/services/cellular and its slot/apn/status siblings. These
assertions keep the page bound to the real endpoints and stop the stub or a
fabricated capability gate from coming back.
"""
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"
MODULE = (WWW / "plugins/native/qwrt-modules.js").read_text(encoding="utf-8")
STYLE = (WWW / "static/css/qwrt-modules.css").read_text(encoding="utf-8")
SHELL = (WWW / "static/js/menu-shell.js").read_text(encoding="utf-8")
MENU = json.loads((WWW / "static/menu/main.json").read_text(encoding="utf-8"))

# 版本键每次改动都会 bump，写死字面量会把测试变成日常噪音。这里从模块自身提取，
# 再断言 main.json 的两个版本键与它一致，这才是真正要守的契约。
_version_match = re.search(r"const VERSION = '([^']+)'", MODULE)
assert _version_match, "qwrt-modules.js missing const VERSION"
VERSION = _version_match.group(1)


def find_item(items):
    for item in items:
        if item.get("id") == "qwrt-modules":
            return item
        hit = find_item(item.get("children") or [])
        if hit:
            return hit
    return None


entry = find_item(MENU["items"])
assert entry is not None, "qwrt-modules menu entry missing"

# The stub is gone and the route is wired to a real module + style.
assert entry["availability"] == "available"
assert "unavailable_reason" not in entry
assert entry["module"] == "native/qwrt-modules.js"
assert entry["style"] == "/static/css/qwrt-modules.css"
assert entry["module_version"] == VERSION
assert entry["style_version"] == VERSION
assert entry.get("frontend_owned") is True
assert f"const VERSION = '{VERSION}'" in MODULE

# qwrt-modules is not in the shellVersioned allowlist, so its cache key comes
# from the menu versions above; the route must instead survive the runtime menu
# gate that drops it when no capability bit is declared.
assert "'/plugins/native/qwrt-modules.js'" not in SHELL
assert re.search(
    r"alwaysVisible = new Set\(\[[^\]]*'qwrt-modules'[^\]]*\]\)", SHELL
), "qwrt-modules must stay reachable despite the runtime capability gate"

# Real endpoints only. No invented paths, and the SMS write paths that the
# backend never exposed over HTTP must not be called.
for path in (
    "/api/v1/services/cellular",
    "/api/v1/services/cellular/status",
    "/api/v1/services/cellular/slots",
    "/api/v1/services/cellular/apn-profiles",
):
    assert path in MODULE, path
assert "/api/v1/services/cellular/sms" not in MODULE
assert "cellular_sms_delete" not in MODULE

# Failure classification must stay separated by status, per design.md.
for fragment in ("会话已失效", "没有蜂窝配置权限", "没有实现该接口", "后端返回错误"):
    assert fragment in MODULE, fragment

# Runtime truth: mmcli missing means "cannot verify", never "feature absent".
assert "ModemManager 未安装" in MODULE
assert "运行态未确认" in MODULE
assert "pending_modemmanager_integration" not in MODULE

# Empty collections are a normal state, not a missing contract.
assert "尚未登记蜂窝模组" in MODULE

# SMS is honestly read-only rather than a fake button.
assert "短信当前只读" in MODULE

# Shared label cap, never a per-name special case.
assert "const LABEL_MAX_CHARS = 22;" in MODULE
assert MODULE.count("function clipLabel") == 1

# Kit contracts: fields wrap controls, tabs/sheets/surfaces are declared.
assert 'data-dwrt-component="field"' in MODULE
assert 'data-dwrt-component="tabs"' in MODULE
assert 'data-dwrt-component="sheet"' in MODULE
assert 'data-dwrt-surface="stable-glass"' in MODULE
assert 'data-dwrt-expand-search="true"' not in MODULE

# Destructive actions keep their confirmation step.
assert "data-dwrt-confirm-accept" in MODULE
assert "此操作不可撤销" in MODULE

# Stage height must use the shared token so the version footer stays on screen.
assert "height: var(--app-stage-height)" in STYLE
assert "100dvh" not in STYLE.split(".qwrt-modules-route-host .dwrt-kit-sheet")[0]

# Sheet geometry needs the .dwrt-kit-sheet prefix; a bare page class ties with
# the kit baseline and loses because ui-kit loads first.
assert ".qwrt-modules-route-host .dwrt-kit-sheet.qwrt-sheet" in STYLE
assert not re.search(r"(^|\n)\.qwrt-sheet\s*\{", STYLE)

# One status card row, four across on wide viewports.
assert ".qwrt-overview.dwrt-kit-overview-grid" in STYLE
assert "grid-template-columns: repeat(4, minmax(0, 1fr))" in STYLE

print("qwrt modules contract ok")

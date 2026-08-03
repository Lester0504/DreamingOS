#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE = (ROOT / "files/www/dreamingwrt/plugins/native/client-speed-limit.js").read_text(encoding="utf-8")
STYLE = (ROOT / "files/www/dreamingwrt/static/css/user-authentication.css").read_text(encoding="utf-8")
MENU = (ROOT / "files/www/dreamingwrt/static/menu/main.json").read_text(encoding="utf-8")


assert "'/api/v1/client_control_rules'" in MODULE
assert "'/api/v1/clients'" in MODULE
assert "/api/v1/client_profile" not in MODULE
assert "PROFILE_CONCURRENCY" not in MODULE
assert "正在汇总终端规则" not in MODULE
assert "页面不会逐台读取终端详情" in MODULE
for endpoint in (
    "/api/v1/client_control_rule'",
    "/api/v1/client_control_rule/update",
    "/api/v1/client_control_rule/toggle",
    "/api/v1/client_control_rule/delete",
):
    assert endpoint in MODULE

assert "control_rule_crud === true" in MODULE
assert "client_control_fail_closed === true" in MODULE
assert "client_control_rate_limit === true" in MODULE
assert "control_type: 'IP限速'" in MODULE
assert "limit_mode: '独立限速'" in MODULE
assert "line: ''" in MODULE
assert "['任意', 'TCP', 'UDP', 'ICMP', 'ICMPv6']" in MODULE
assert "共享限速和应用级管控没有数据面合同" in MODULE
assert "window.confirm" not in MODULE
assert "confirmationMarkup" in MODULE
assert 'data-dwrt-sheet-variant="copilot"' in MODULE
assert ".client-speed-drawer { --dwrt-kit-sheet-width: var(--dwrt-kit-sheet-width-standard); }" in STYLE
assert "client-speed-limit.js" in MENU
assert '"availability": "available"' in MENU

print("ok: client speed-limit page uses one rule collection read, client identity join and fail-closed CRUD")

#!/usr/bin/env python3
"""Static contract for the VPN frontend and fail-closed API gate."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"
MODULE = (WWW / "plugins/native/vpn-config.js").read_text(encoding="utf-8")
STYLE = (WWW / "static/css/vpn-config.css").read_text(encoding="utf-8")
MENU = json.loads((WWW / "static/menu/main.json").read_text(encoding="utf-8"))
MANIFEST = json.loads((ROOT / "redesign/route-manifest.json").read_text(encoding="utf-8"))


def walk(items):
    for item in items:
        yield item
        yield from walk(item.get("children", []))


vpn = next(item for item in walk(MENU["items"]) if item.get("id") == "vpn-config")
assert vpn["frontend_owned"] is True and vpn["availability"] == "available"
assert vpn["module"] == "native/vpn-config.js"
assert vpn["style"] == "/static/css/vpn-config.css"
assert (WWW / "plugins/native/vpn-config.js").is_file()
assert (WWW / "static/css/vpn-config.css").is_file()

# The VPN home information architecture remains four sections, not a replacement tab set.
for label in ("Teleport", "VPN 服务器", "VPN 客户端", "站点到站点 VPN"):
    assert label in MODULE
assert "vpn-section-stack" in MODULE
assert "vpn-config-tabs" not in MODULE

# Server/client/site type selection and the observed conditional dimensions are present.
for protocol in ("wireguard", "openvpn", "l2tp", "ikev2", "pppoe", "pptp", "ipsec"):
    assert f"'{protocol}'" in MODULE
for field in (
    "server_address_mode", "fallback_address", "listen_mode", "ipv4_gateway", "ipv6_gateway",
    "auto_dns", "ipv4_mss", "ipv6_mss", "setup_mode", "device_route_mode",
    "content_route_mode", "routing_mode", "ike_version", "ike_encryption", "ike_hash",
    "ike_dh", "esp_encryption", "esp_hash", "esp_dh", "route_distance"
):
    assert field in MODULE, field
assert "管理本地账号" in MODULE and "管理证书" in MODULE

# Missing endpoints never create fake rows or accept a fake save.
for endpoint in (
    "/api/v1/vpn", "/api/v1/vpn/servers", "/api/v1/vpn/clients",
    "/api/v1/vpn/site-to-site", "/api/v1/vpn/accounts", "/api/v1/vpn/certificates"
):
    assert endpoint in MODULE
assert "前端不会使用示例隧道填充列表" in MODULE
assert "后端写入接口未开放" in MODULE
assert "state.writable[kind]" in MODULE
assert "if (!kind || !state.writable[kind]) return;" in MODULE

# Shared UI Kit owns controls, sheets, state panels, tables and status semantics.
for component in ('data-dwrt-component="sheet"', 'data-dwrt-component="state-panel"', 'data-dwrt-component="data-table"', 'data-dwrt-component="field"', 'data-dwrt-component="switch"'):
    assert component in MODULE
assert "statusBadgeMarkup" in MODULE
assert "data-dwrt-sheet-variant=\"copilot\"" in MODULE
assert "data-dwrt-sheet-motion=\"settled\"" in MODULE
assert "@media (max-width: 720px)" in STYLE
assert "grid-template-columns: 1fr" in STYLE

route = next(item for item in MANIFEST["routes"] if item["route"] == "#/network/vpn-config")
assert route["owner"] == "plugins/native/vpn-config.js"
assert route["availability"] == "available"

print("vpn config frontend contract passed")

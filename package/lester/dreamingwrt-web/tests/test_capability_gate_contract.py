#!/usr/bin/env python3
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MENU = json.loads((ROOT / "files/www/dreamingwrt/static/menu/main.json").read_text(encoding="utf-8"))
SHELL = (ROOT / "files/www/dreamingwrt/static/js/menu-shell.js").read_text(encoding="utf-8")


def walk(items):
    for item in items:
        yield item
        yield from walk(item.get("children", []))


expected = {
    "#/network/flow-control",
    "#/network/bulk-ip",
    "#/network/advanced-routing",
    "#/network/custom-config",
    "#/authentication/client-speed-limit",
    "#/authentication/web-access-control",
    "#/authentication/app-filter",
    "#/authentication/client-network-control",
    "#/network/firewall",
    "#/network/qwrt-modules",
    "#/plugins/native",
    "#/plugins/market",
}
gated = {}
for item in walk(MENU["items"]):
    path = item.get("path", "")
    route = path[path.index("#/"):] if "#/" in path else ""
    if item.get("availability") == "unavailable":
        gated[route] = item

assert set(gated) == expected
assert all(item.get("capability") for item in gated.values())
assert all(item.get("unavailable_reason") for item in gated.values())

assert "item.availability === 'unavailable'" in SHELL
assert "renderUnavailableRoute(current, currentPath)" in SHELL
assert 'data-dwrt-component="state-panel" data-dwrt-state="unavailable"' in SHELL
assert "children.filter((child) => !child.disabled)" in SHELL
assert "if (!primary.disabled) entries.push" in SHELL
assert "button.dataset.availability = item.availability || 'available'" in SHELL
assert "unavailableReason ? `${label}，不可用" in SHELL
assert "item?.frontend_owned === true || item?.availability === 'unavailable'" in SHELL

vpn = next(item for item in walk(MENU["items"]) if item.get("id") == "vpn-config")
assert vpn["availability"] == "available"
assert vpn["frontend_owned"] is True
assert vpn["module"] == "native/vpn-config.js"
assert vpn["style"] == "/static/css/vpn-config.css"

multicast = next(item for item in walk(MENU["items"]) if item.get("id") == "multicast-service")
assert multicast["availability"] == "available"
assert multicast["frontend_owned"] is True
assert multicast["module"] == "native/multicast-service.js"
assert multicast["style"] == "/static/css/multicast-service.css"

upnp = next(item for item in walk(MENU["items"]) if item.get("id") == "upnp-service")
assert upnp.get("availability", "available") == "available"
assert upnp["frontend_owned"] is True
assert upnp["module"] == "native/upnp-service.js"
assert upnp["style"] == "/static/css/upnp-service.css"

partitions = next(item for item in walk(MENU["items"]) if item.get("id") == "storage-partitions")
assert partitions["availability"] == "available"
assert partitions["frontend_owned"] is True
assert partitions["module"] == "native/storage-partitions.js"
assert partitions["style"] == "/static/css/storage-partitions.css"

print("ok: placeholder routes use one capability gate; VPN, multicast, UPnP and partitions use real frontend routes")

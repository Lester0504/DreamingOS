#!/usr/bin/env python3
"""Contract for the standalone multicast workbench and fail-closed writes."""

import gzip
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"
MODULE_PATH = WWW / "plugins/native/multicast-service.js"
STYLE_PATH = WWW / "static/css/multicast-service.css"
MENU_PATH = WWW / "static/menu/main.json"
MODULE = MODULE_PATH.read_text(encoding="utf-8")
STYLE = STYLE_PATH.read_text(encoding="utf-8")
MENU = json.loads(MENU_PATH.read_text(encoding="utf-8"))
VERSION = re.search(r"const VERSION = '([^']+)'", MODULE).group(1)


def walk(items):
    for item in items:
        yield item
        yield from walk(item.get("children", []))


route = next(item for item in walk(MENU["items"]) if item.get("id") == "multicast-service")
assert route["availability"] == "available"
assert route["frontend_owned"] is True
assert route["module"] == "native/multicast-service.js"
assert route["style"] == "/static/css/multicast-service.css"
assert route["module_version"] == VERSION
assert route["style_version"] == VERSION

for label in ("总览", "IGMP / MLD 代理", "IPTV 透传", "UDPXY", "局域发现"):
    assert label in MODULE

for field in (
    "igmp_proxy.enabled", "igmp_proxy.version", "igmp_proxy.quick_leave",
    "igmp_proxy.upstream", "igmp_proxy.downstreams", "igmp_proxy.alt_subnets",
    "iptv_passthrough.enabled", "iptv_passthrough.wan_iface",
    "iptv_passthrough.lan_iface", "iptv_passthrough.vlan_id",
    "iptv_passthrough.stb_ports", "iptv_passthrough.mode",
    "iptv_passthrough.keep_internet", "udpxy.enabled", "udpxy.listen_iface",
    "udpxy.listen_port", "udpxy.source_iface", "udpxy.max_clients",
    "udpxy.buffer_kb", "discovery.mdns_reflector", "discovery.ssdp_relay",
    "discovery.igmp_snooping", "discovery.mld_snooping",
    "discovery.querier", "discovery.query_interval", "allowed_groups",
):
    assert field in MODULE, field

for operation in (
    "data-add-instance", "data-remove-instance", "data-add-allow",
    "data-remove-allow", "data-multicast-instance", "data-instance-field",
    "data-multicast-allow", "data-allow-field",
):
    assert operation in MODULE, operation

for endpoint in (
    "'/api/v1/services/multicast'", "'/api/v1/services/multicast/apply'",
    "'/api/v1/network/wans'", "'/api/v1/network/lans'", "'/api/v1/network/ports'",
):
    assert endpoint in MODULE, endpoint

assert "const SUCCESS_CODES = new Set([0, 200, 2000])" in MODULE
assert "businessFailed" in MODULE
assert "service_update" in MODULE and "service_apply" in MODULE
assert "return update && apply" in MODULE
assert "当前为只读" in MODULE
assert "后端未声明组播配置写入与应用能力" in MODULE
assert "if (!canWrite() || !state.dirty || state.saving) return" in MODULE
assert "disabled: !canWrite() || state.saving" in MODULE
confirmation = re.search(r"function confirmationMarkup\(\) \{(?P<body>.*?)\n  \}", MODULE, re.S)
assert confirmation, "confirmationMarkup must remain present"
assert confirmation.group("body").count("disabled: state.saving") == 1
assert "localStorage.setItem" not in MODULE
assert "/etc/config" not in MODULE
assert "mockMulticast" not in MODULE

for runtime_field in (
    "subscribers", "rx_rate", "tx_rate", "dropped", "group_state",
    "last_seen", "client", "运行状态尚未完整验证",
):
    assert runtime_field in MODULE, runtime_field

for kit_contract in (
    "dwrt-kit-page-tabs", "dwrt-kit-table-wrap", 'data-dwrt-surface="dense-surface"',
    "floatingSavebarMarkup", "statusBadgeMarkup", "confirmationMarkup",
    'data-dwrt-component="tabs"',
    'data-dwrt-component="dependency-group"', 'data-dwrt-component="data-table"',
):
    assert kit_contract in MODULE, kit_contract

# 手动刷新按钮按用户第 9 条删除（它是页内唯一的 kit button），改为可见性受控的轮询；
# 错误态的「重试」保留自己的钩子，不再复用刷新属性。
assert "data-multicast-refresh" not in MODULE
assert "data-multicast-retry" in MODULE
assert "state.pollTimer = window.setInterval" in MODULE

for workbench_contract in (
    'role="tablist"',
    'role="tab"',
    "overviewCardsRow",
    "overviewCardsMarkup",
    'className: \'multicast-overview\'',
    'class="multicast-surface-header"',
    'class="multicast-surface-body"',
    # settings panels must sit on the shared Kit glass surface, not straight on the wallpaper
    'data-dwrt-surface="stable-glass"',
):
    assert workbench_contract in MODULE, workbench_contract

# the active tab already names the section, so the surface header must not repeat it
assert "'IGMP / MLD 代理', '配置 IPv4" not in MODULE
assert "'组播服务', '查看当前配置" not in MODULE
assert "multicast-runtime-summary" not in MODULE
assert "dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface" not in MODULE
assert 'data-dwrt-component="page-shell"' not in MODULE
assert 'data-dwrt-page-shell="settings-workbench"' not in MODULE
assert 'multicast-settings-surface dwrt-kit-glass-surface' not in MODULE

assert "border-radius: 8px" in STYLE
assert "border-radius: 6px" in STYLE
assert ".multicast-dependency-fields::before" in STYLE
assert ".multicast-settings-surface" in STYLE
assert ".multicast-surface-header" in STYLE
assert ".multicast-surface-body" in STYLE
assert "multicast-runtime-summary" not in STYLE
assert ".multicast-overview" in STYLE
assert ".multicast-page-actions" in STYLE
assert ".multicast-table .dwrt-kit-table-scroll" in STYLE
assert "overflow-x: auto" in STYLE
assert "@media (max-width: 900px)" in STYLE
assert "@media (max-width: 640px)" in STYLE
assert "font-size: 16px" in STYLE
# Only the shared overview cards may carry a larger metric size (matching the UPnP row);
# everything else must stay out of Hero territory.
_hero = [
    match for match in re.finditer(r"font-size:\s*(?:[2-9]\d|1\d{2,})px", STYLE)
    if ".multicast-overview .dwrt-kit-overview-content strong" not in STYLE[max(0, match.start() - 120):match.start()]
]
assert not _hero, f"page CSS must not introduce Hero-sized text: {[m.group(0) for m in _hero]}"
# material comes from the shared surface contract, so the page still adds no private glass
assert "backdrop-filter:" not in STYLE
# The only permitted !important is the narrow-screen icon hide, which must match the weight
# the Kit itself uses on .dwrt-kit-overview-icon.
_important = re.findall(r"[^\n]*!important[^\n]*", STYLE)
assert _important == ["    display: none !important;"], _important
assert "background: transparent" in STYLE
# tabs / status card row / workbench
assert "grid-template-rows: auto auto minmax(0, 1fr)" in STYLE
assert ".console-stage.is-multicast-service" in STYLE
# The stage claims the shared height token so the version footer stays on screen.
assert "height: var(--app-stage-height)" in STYLE
assert ".multicast-service-main" in STYLE
assert "overflow: auto" in STYLE
assert '<main class="multicast-service-main">${noticeMarkup()}${panelMarkup()}</main>' in MODULE

for source in (MODULE_PATH, STYLE_PATH):
    compressed = source.with_name(source.name + ".gz")
    assert compressed.is_file(), compressed
    assert gzip.decompress(compressed.read_bytes()) == source.read_bytes(), compressed

print("ok: multicast preserves LuCI settings, consumes real interfaces, uses Kit contracts, and fails closed without explicit update/apply capabilities")

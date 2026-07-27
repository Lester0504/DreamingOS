#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GLOBAL_JS = (ROOT / "files/www/dreamingwrt/plugins/native/global-config.js").read_text()
INTERFACE_JS = (ROOT / "files/www/dreamingwrt/plugins/native/network-interface-config.js").read_text()
INTERFACE_CSS = (ROOT / "files/www/dreamingwrt/static/css/network-interface-config.css").read_text()
SHELL_JS = (ROOT / "files/www/dreamingwrt/static/js/menu-shell.js").read_text()


def require(source: str, fragment: str, message: str) -> None:
    if fragment not in source:
        raise AssertionError(message)


require(GLOBAL_JS, "function logicalPortName", "logical names must remove duplicated physical ifname suffixes")
require(GLOBAL_JS, "return logicalPortName(firstText(wan?.id, port.name", "Gateway WAN names must use wan/wan2 instead of repeating ethX")
require(GLOBAL_JS, "<th>角色分配</th>", "Gateway table must use the requested role wording")
require(GLOBAL_JS, "data-gateway-assignment=", "Gateway role assignment must remain interactive")
require(GLOBAL_JS, "if (port.kind === 'wan') return carrierLogo(port.wanOwner", "WAN connection cells must render carrier logos")
require(GLOBAL_JS, "const displayMac = wanOwner ? localMac : neighbor.mac", "WAN rows must use the physical interface MAC")
require(GLOBAL_JS, "const displayIp = wanOwner ? validAddress", "WAN rows must use the current WAN IPv4")
require(GLOBAL_JS, "source.sample_valid === false", "invalid rate samples must be excluded")
require(GLOBAL_JS, "activitySeconds: metric('activity_seconds', 'link_uptime', 'link_up_seconds')", "physical activity must not borrow WAN session uptime")
require(GLOBAL_JS, "if (key === 'name') return `<span class=\"global-cell-stack\"><strong>${escapeHtml(port.name)}</strong></span>`", "name cells must not duplicate ethX")
require(GLOBAL_JS, "function refreshPortStatistics()", "port statistics need a lightweight live refresh path")
require(GLOBAL_JS, "fetchResource('global-ports-live', ENDPOINTS.ports)", "live port refresh must only request the ports endpoint")
require(GLOBAL_JS, "function patchPortStatistics()", "port refresh must patch changing cells instead of rebuilding the table")
require(GLOBAL_JS, "window.setInterval(refreshPortStatistics, 2000)", "port statistics need a bounded refresh interval")
require(GLOBAL_JS, "window.clearInterval(state.statsTimer)", "port statistics refresh must stop when the route unmounts")
require(GLOBAL_JS, "state.statsRefreshing", "slow port responses must not create overlapping refresh requests")
require(GLOBAL_JS, "finally {\n      state.statsRefreshing = false;", "the port refresh lock must always be released")
require(GLOBAL_JS, "const tableWidth = columns.reduce", "the port table width must follow currently visible columns")
require(GLOBAL_JS, "--global-port-table-width:${tableWidth}px", "the calculated port table width must reach CSS")

if "data-interface-ports=" in INTERFACE_JS:
    raise AssertionError("the separate change-port table action must be removed")
require(INTERFACE_JS, "data-interface-editor-toggle=", "editor groups need disclosure controls")
require(INTERFACE_JS, "state.editorOpen = state.editorOpen === next ? '' : next", "editor disclosures must be single-open")
require(INTERFACE_JS, "root.querySelectorAll('[data-interface-editor-group]').forEach", "opening one editor group must close every other group in place")
require(INTERFACE_JS, "aria-expanded=", "editor disclosure state must be announced")
require(INTERFACE_JS, "role=\"region\"", "editor groups need semantic regions")
require(INTERFACE_JS, "function dependentMarkup", "dependent controls must remain visibly associated")
require(INTERFACE_JS, "segmentedField('access_mode'", "WAN access method must be the primary compact choice")
require(INTERFACE_JS, "hybrid_macvlan", "physical NIC hybrid mode must remain represented")
require(INTERFACE_JS, "hybrid_vlan", "VLAN hybrid mode must remain represented")
require(INTERFACE_JS, "pppoe_multi_write", "PPPoE multidial must be capability gated")
require(INTERFACE_JS, "wan_bonding_write", "WAN bonding must be capability gated")
require(INTERFACE_JS, "hybrid_lines.0.pppoe_ac", "hybrid PPPoE discovery dimensions must be represented")
require(INTERFACE_JS, "pppoe_multi.no_individual_persist", "multidial group reconnect semantics must be represented")
require(INTERFACE_JS, "bond.hash_policy", "bond hash policy must be represented")
require(INTERFACE_JS, "extra_ips_text", "LAN extra IPs must be editable")
require(INTERFACE_JS, "ipv6.ra_flags", "LAN RA flags must be editable")
require(INTERFACE_JS, "ipv6.ra_static", "LAN static RA must be editable")

require(INTERFACE_CSS, ".network-interface-editor-panel", "the drawer needs one primary glass surface")
require(INTERFACE_CSS, ".network-interface-dependent::before", "dependent settings need a relationship rail")
require(INTERFACE_CSS, ".network-interface-segmented", "mode choices need compact segmented geometry")
require(INTERFACE_CSS, "@media (prefers-reduced-motion: reduce)", "drawer interactions must respect reduced motion")
require(INTERFACE_CSS, ".network-interface-table.is-wan { min-width: 990px; }", "WAN columns must fit a normal content viewport without gratuitous scrolling")
require(INTERFACE_CSS, ".network-interface-table.is-lan { min-width: 1040px; }", "LAN columns must use compact task-appropriate widths")
require(SHELL_JS, "'.network-interface-editor-group > h3'", "editor headings must use the existing foreground sampler")
require(SHELL_JS, "'.network-interface-dependent'", "dependent fields must use the existing foreground sampler")

print("ok: global ports semantics and grouped LAN/WAN editors match the live contracts")

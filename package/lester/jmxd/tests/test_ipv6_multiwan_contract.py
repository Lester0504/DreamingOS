#!/usr/bin/env python3

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "files" / "dreamingwrt-ipv6-multiwan.sh").read_text()
HOTPLUG = (ROOT / "files" / "95-dreamingwrt-ipv6-mw.hotplug").read_text()
MAKEFILE = (ROOT / "Makefile").read_text()


def require(fragment: str, source: str, message: str) -> None:
    assert fragment in source, message


require("ubus list 'network.interface.wan*'", SCRIPT, "WANs must be discovered at runtime")
require("network.globals.ula_prefix", SCRIPT, "ULA must come from runtime configuration")
require("flock -w 30 9", SCRIPT, "apply operations must be serialized")
require("mktemp -d", SCRIPT, "nft/state generation must use private temporary files")
require("nft -c -f", SCRIPT, "nft transaction must be validated before apply")
require("plan) plan_config", SCRIPT, "operators need a read-only live planning command")
require('iif "$lan_dev" from "$ula_route" fwmark', SCRIPT,
        "marked rules must cover the full delegated ULA domain and remain LAN-directional")
require('"$device" "$ula_route" "$snat"', SCRIPT,
        "SNAT66 must cover downstream ULA subnets, not only the root LAN /64")
require('stale_lan="${pd}/64"', SCRIPT, "deprecated SLAAC rejection must be exact /64")
require('state_has_field "$new_state" 10 "$snat"', SCRIPT, "SNAT cleanup must read the state schema correctly")
require('state_has_field "$new_state" 8 "$pd"', SCRIPT, "PD cleanup must read the state schema correctly")
require("no active WAN with an IPv6 delegated prefix; keeping current dataplane", SCRIPT,
        "empty discovery must preserve the existing dataplane")
require("dreamingwrt-ipv6-mw-hotplug.pending", HOTPLUG,
        "hotplug must retain an event that lands while the worker is active")
require("flock -w 30 9", HOTPLUG, "a last-moment event must wait for the debounce worker")
require('[ -f "$pending" ] || exit 0', HOTPLUG,
        "queued workers must exit when an earlier worker already reconciled the event")
require("sleep 5", HOTPLUG, "hotplug must wait for a quiet delegated-prefix window")
require("/etc/dreamingwrt/ipv6-multiwan.sh apply", HOTPLUG,
        "hotplug must use the serialized main apply path")
require("ifup|ifdown|ifupdate", HOTPLUG, "both loss and recovery must rebuild the path set")
require('[ -f "$pending" ] || break', HOTPLUG,
        "an event arriving during apply must force another reconciliation")
require("./files/dreamingwrt-ipv6-multiwan.sh", MAKEFILE, "runtime script must be packaged")
require("./files/95-dreamingwrt-ipv6-mw.hotplug", MAKEFILE, "hotplug hook must be packaged")

assert "from all fwmark" not in SCRIPT, "reply-mark loop regression: broad fwmark rule returned"
assert 'iif "$lan_dev" from "$ula_lan" fwmark' not in SCRIPT, \
    "downstream ULA regression: marked rules were narrowed back to the root /64"
assert '"$device" "$ula_lan" "$snat"' not in SCRIPT, \
    "downstream ULA regression: SNAT66 was narrowed back to the root /64"
assert 'ip -6 rule del fwmark "$mark"' not in SCRIPT, "cleanup must not delete another owner's fwmark rule"
assert 'stale_lan="${pd}/${pd_mask}"' not in SCRIPT, "rejecting the whole PD breaks downstream routers"
assert 'dev=pppoe-wan' not in SCRIPT, "physical devices must not be hardcoded"

print("ok: IPv6 multi-WAN directional routing and lifecycle contract")

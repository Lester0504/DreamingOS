"""Wireless status explains why metrics are blank instead of showing a bare dash.

The page rendered client, signal and 24h columns as `--` whenever the managed AP
had not reported, which read as "the backend never implemented this". The payload
already carries the cause (`summary.station_count` is null plus a
`station_count_reason`, and `runtime.reason` says the AP is offline), so the cause
is stated once at the top of the page.

Blank must also never collapse to 0: the backend deliberately returns null rather
than 0 so "no telemetry yet" stays distinguishable from a measured zero.
"""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"
MODULE = (WWW / "plugins/native/wifi-management.js").read_text(encoding="utf-8")

# The reason codes the backend actually sends, verified on 30.1:
#   summary.station_count -> null, station_count_reason -> telemetry_stale
#   runtime.reason        -> managed_aps_offline_stale_or_without_snapshot
#   ac/status local_wifi  -> no_phy_detected
for code in (
    "telemetry_stale",
    "managed_aps_offline_stale_or_without_snapshot",
    "no_phy_detected",
):
    assert code in MODULE, f"missing reason code mapping: {code}"

reasons = re.search(r"const RADIO_METRIC_REASONS = \{([^}]*)\}", MODULE)
assert reasons, "RADIO_METRIC_REASONS table missing"
for code in ("telemetry_stale", "managed_aps_offline_stale_or_without_snapshot"):
    assert code in reasons.group(1), f"{code} must resolve to human text, not fall through raw"

assert "function telemetryNotice()" in MODULE, "the page must derive a cause notice"
assert "data-wifi-telemetry-notice" in MODULE, "the notice needs a stable hook for tests"
assert "telemetryNotice()" in MODULE.split("function statusPage()", 1)[1], (
    "statusPage must render the notice, not merely define it"
)

# Unknown is null, not 0. Seeding these counters at 0 made the pre-load skeleton
# claim zero clients as though it had been measured.
skeleton = re.search(r"summary: \{ clients: ([^,]+), station_count: ([^,]+)", MODULE)
assert skeleton, "status skeleton summary not found"
assert skeleton.group(1).strip() == "null", "clients must default to null, not 0"
assert skeleton.group(2).strip() == "null", "station_count must default to null, not 0"

# Cache keys: the module VERSION and every menu entry pointing at it must agree,
# otherwise the browser can serve a stale mix of old and new code.
version = re.search(r"const VERSION = '([^']+)'", MODULE)
assert version, "wifi-management.js missing const VERSION"
menu = json.loads((WWW / "static/menu/main.json").read_text(encoding="utf-8"))


def walk(items):
    for item in items:
        yield item
        for child in item.get("children") or []:
            yield from walk([child])


entries = [i for i in walk(menu["items"]) if i.get("module") == "native/wifi-management.js"]
assert entries, "no menu entry references wifi-management.js"
for entry in entries:
    assert entry["module_version"] == version.group(1), (
        f"{entry.get('id')} module_version must equal the module VERSION"
    )
    assert entry["style_version"] == version.group(1), (
        f"{entry.get('id')} style_version must equal the module VERSION"
    )

print("ok: wireless status states the cause of blank telemetry and keeps null distinct from 0")

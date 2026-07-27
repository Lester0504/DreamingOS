#!/usr/bin/env python3
"""Keep the legacy shared UPnP switch bank compact and responsive."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE = (ROOT / "files/www/dreamingwrt/plugins/native/network-services.js").read_text(encoding="utf-8")
STYLE = (ROOT / "files/www/dreamingwrt/static/css/network-services.css").read_text(encoding="utf-8")

assert MODULE.count('network-service-setting-list is-compact') == 1
assert 'grid-template-columns: repeat(2, minmax(0, 1fr))' in STYLE
assert '.network-service-setting-list.is-compact .network-service-setting-row { min-height: 50px; }' in STYLE
assert '@media (max-width: 760px)' in STYLE
mobile = STYLE[STYLE.index('@media (max-width: 760px)'):]
assert '.network-service-setting-list.is-compact { grid-template-columns: 1fr;' in mobile

print("network services compact controls contract passed")

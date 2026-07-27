#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ROUTE = (ROOT / "src" / "routed" / "jmx_route.c").read_text(encoding="utf-8")
DB = (ROOT / "src" / "routed" / "jmx_route_db.c").read_text(encoding="utf-8")


def test_auto_carrier_resolution_and_explicit_override() -> None:
    assert '#include "jmx_isp.h"' in ROUTE
    assert "route_detect_wan_carrier" in ROUTE
    assert "route_stored_wan_carrier" in ROUTE
    assert "SELECT carrier FROM net_interfaces WHERE name=?1 LIMIT 1" in ROUTE
    assert "jmx_isp_get(name, &isp)" in ROUTE
    assert "isp.confidence >= 50" in ROUTE
    assert "jmx_db_upsert_interface(name, \"wan\", ifname, NULL" in ROUTE
    assert "route_resolve_auto_carrier_wans" in ROUTE
    resolver = ROUTE.split("static void route_resolve_auto_carrier_wans", 1)[1].split("static ", 1)[0]
    assert "rule->wan_count > 0" in resolver
    assert "map[i].carrier_id == rule->carrier_id" in resolver
    assert "route_auto_carrier_mapping_changed(config)" in ROUTE
    assert "jmx_route_sync_json(config)" in ROUTE
    assert '"auto_carrier"' in DB
    assert '"explicit"' in DB
    assert "enabled rule without WAN targets must match a carrier" in DB


if __name__ == "__main__":
    test_auto_carrier_resolution_and_explicit_override()
    print("ok: automatic carrier WAN resolution contract")

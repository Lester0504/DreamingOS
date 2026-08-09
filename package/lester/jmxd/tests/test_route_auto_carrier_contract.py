#!/usr/bin/env python3
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
ROUTE = (ROOT / "src" / "routed" / "jmx_route.c").read_text(encoding="utf-8")
DB = (ROOT / "src" / "routed" / "jmx_route_db.c").read_text(encoding="utf-8")


def test_auto_carrier_resolution_and_explicit_override() -> None:
    assert '#include "jmx_isp.h"' in ROUTE
    assert "route_detect_wan_carrier" in ROUTE
    assert "route_stored_wan_carrier" in ROUTE
    # The property: the stored carrier is looked up from net_interfaces, keyed on
    # the interface, and collapsed to a single row.
    #
    # This used to match the one-line literal
    # "SELECT carrier FROM net_interfaces WHERE name=?1 LIMIT 1". The query was
    # since split across adjacent string literals and broadened to match on
    # device as well as name, with an explicit preference order, so the literal
    # stopped matching and this gate silently stopped checking. Normalise the
    # concatenated literals and assert the parts that carry the meaning.
    joined = re.sub(r'"\s*\n\s*"', "", ROUTE)
    carrier_q = re.search(
        r'SELECT carrier FROM net_interfaces\s+WHERE[^"]*LIMIT 1', joined)
    assert carrier_q, (
        "the stored-carrier lookup against net_interfaces is gone or no longer "
        "returns a single row"
    )
    query = carrier_q.group(0)
    # Check the WHERE clause specifically: 'name=?1' also appears in the
    # ORDER BY preference list, so matching it anywhere in the query would still
    # pass if the filter itself stopped keying on the interface name.
    where = re.search(r'WHERE(.*?)(?:ORDER BY|LIMIT)', query, re.S)
    assert where and "name=?1" in where.group(1), (
        "the carrier lookup must filter on the interface name, not only "
        "mention it in the ordering"
    )
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

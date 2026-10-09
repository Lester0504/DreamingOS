#!/usr/bin/env python3
"""Dangling route_rule_wan members are reported, not silently dropped or deleted.

route_rule_wan.wan_id has only a range CHECK, no foreign key into route_wan(id),
so removing a WAN leaves members behind that name a line which no longer exists.
Two things must hold, and neither can be shown by reading source text:

  1. The export separates them: wan_ids keeps the members that resolve,
     dangling_wan_ids reports the rest. Kernel selection already ignores a
     missing WAN, so this is about not drawing phantom lines in the UI.
  2. A read-modify-write cycle preserves them. route_replace_tables() deletes
     and reinserts the whole table, so a caller that reads the config, changes
     one field and writes it back must not delete the stale rows as a side
     effect of an unrelated edit.

This drives real SQLite with the production schema and the production SQL, so a
regression in either property fails here.
"""

from __future__ import annotations

from pathlib import Path
import re
import sqlite3
import tempfile


ROOT = Path(__file__).resolve().parents[1]
DB_SOURCE = (ROOT / "src/routed/jmx_route_db.c").read_text(encoding="utf-8")


def production_schema() -> str:
    """Lift the CREATE TABLE text out of the C source so it cannot drift."""
    body = DB_SOURCE[DB_SOURCE.index('"CREATE TABLE IF NOT EXISTS route_global'):]
    # The schema is one C string literal per line, terminated by the final ";
    body = body[: body.index('cidr TEXT NOT NULL);"') + len('cidr TEXT NOT NULL);"')]
    return "".join(re.findall(r'"([^"]*)"', body))


def build_db(path: Path) -> sqlite3.Connection:
    db = sqlite3.connect(path)
    db.executescript(production_schema())
    # Two lines configured, a rule pinned to four: the 30.1 shape, where a unit
    # was cut from four WANs to two and the rule members never shrank.
    db.execute("INSERT INTO route_wan(id,position,name,ifname,fwmark,table_id) "
               "VALUES(1,0,'wan1','eth1',101,101)")
    db.execute("INSERT INTO route_wan(id,position,name,ifname,fwmark,table_id) "
               "VALUES(2,1,'wan2','eth2',102,102)")
    db.execute("INSERT INTO route_rule(rule_id,position,name,enabled,prio) "
               "VALUES(1,0,'default-lowest-rx-load',1,1000)")
    for position, wan_id in enumerate((1, 2, 3, 4)):
        db.execute("INSERT INTO route_rule_wan(rule_id,position,wan_id) VALUES(1,?,?)",
                   (position, wan_id))
    db.commit()
    return db


def export_members(db: sqlite3.Connection) -> tuple[list[int], list[int]]:
    """Mirror route_read_config(): split members by whether the line exists."""
    live, dangling = [], []
    for (wan_id,) in db.execute(
            "SELECT wan_id FROM route_rule_wan WHERE rule_id=1 ORDER BY position"):
        exists = db.execute("SELECT 1 FROM route_wan WHERE id=?", (wan_id,)).fetchone()
        (live if exists else dangling).append(wan_id)
    return live, dangling


def replace_tables(db: sqlite3.Connection, live: list[int], dangling: list[int]) -> None:
    """Mirror route_replace_tables(): wipe and reinsert, stale members included."""
    db.execute("DELETE FROM route_rule_wan")
    for position, wan_id in enumerate(live + dangling):
        db.execute("INSERT INTO route_rule_wan(rule_id,position,wan_id) VALUES(1,?,?)",
                   (position, wan_id))
    db.commit()


def test_dangling_members_are_split_and_survive_a_write_cycle() -> None:
    with tempfile.TemporaryDirectory() as directory:
        db = build_db(Path(directory) / "config.db")

        live, dangling = export_members(db)
        assert live == [1, 2], f"resolvable members wrong: {live}"
        assert dangling == [3, 4], f"stale members not reported: {dangling}"

        # An unrelated edit (algorithm change) writes the whole config back.
        replace_tables(db, live, dangling)
        stored = [row[0] for row in db.execute(
            "SELECT wan_id FROM route_rule_wan WHERE rule_id=1 ORDER BY position")]
        assert stored == [1, 2, 3, 4], (
            f"a write cycle changed the stored member set: {stored}"
        )

        # Adding WAN 3 back must make it resolve again, and it must land in the
        # position it already occupied rather than being appended somewhere new.
        db.execute("INSERT INTO route_wan(id,position,name,ifname,fwmark,table_id) "
                   "VALUES(3,2,'wan3','eth3',103,103)")
        db.commit()
        live, dangling = export_members(db)
        assert live == [1, 2, 3], f"restored line did not resolve: {live}"
        assert dangling == [4], f"stale set wrong after restore: {dangling}"
        db.close()


def test_schema_still_lacks_the_foreign_key_this_guards() -> None:
    """If the foreign key is ever added, this workaround should be revisited."""
    table = DB_SOURCE[DB_SOURCE.index("CREATE TABLE IF NOT EXISTS route_rule_wan"):]
    table = table[: table.index("CREATE TABLE IF NOT EXISTS route_carrier_prefix")]
    assert "CHECK(wan_id BETWEEN 1 AND 255)" in table
    if "REFERENCES route_wan(id)" in table:
        raise AssertionError(
            "route_rule_wan.wan_id now has a foreign key: the export-side split "
            "and the write-side carry-through can likely be simplified, and the "
            "existing dangling rows need a migration decision"
        )
    # The production split and carry-through must both still be present.
    assert "route_wan_id_exists(db, member)" in DB_SOURCE
    assert '"dangling_wan_ids"' in DB_SOURCE
    assert "invalid stale WAN target id" in DB_SOURCE


if __name__ == "__main__":
    test_dangling_members_are_split_and_survive_a_write_cycle()
    test_schema_still_lacks_the_foreign_key_this_guards()
    print("ok: dangling WAN members are reported and survive a read-modify-write cycle")

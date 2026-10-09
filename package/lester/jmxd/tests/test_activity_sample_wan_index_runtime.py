#!/usr/bin/env python3
"""Per-WAN activity-sample reads must seek their own rows, not scan the window.

dashboard_activity_sample is keyed PRIMARY KEY(ts, wan_id) and long carried only
a ts index. Every per-WAN reader, though, filters wan_id over a time window:

    SELECT ts,up_rate,down_rate FROM dashboard_activity_sample
     WHERE ts>=? AND ts<=? AND wan_id=? ORDER BY ts ASC

With a ts-leading index only, SQLite walks every row in the window and throws
away the WANs it was not asked about, so each WAN costs the size of the *whole*
window instead of its own slice. On 30.1 that was 655026 rows across 4 live
WANs, about 70 ms each, which is what pushed dw_refresh_wan_state() to
236-254 ms against a 200 ms metrics tick budget -- one step overrunning the
entire budget.

The fix is a (wan_id, ts) index, added by the schema v9 migration. This test
drives real SQLite with the production schema and the production query so the
plan, the result values, and the row order are all checked rather than asserted
about in prose. Reading the source cannot show which index the planner picks.
"""

from __future__ import annotations

from pathlib import Path
import re
import sqlite3
import tempfile


ROOT = Path(__file__).resolve().parents[1]
DB_SOURCE = (ROOT / "src/jmx_db.c").read_text(encoding="utf-8")

# The production query, copied from jmx_db_usage_integrate_window().
INTEGRATE_QUERY = (
    "SELECT ts,up_rate,down_rate "
    "FROM dashboard_activity_sample "
    "WHERE ts>=? AND ts<=? AND wan_id=? "
    "ORDER BY ts ASC"
)

WAN_TS_INDEX = "idx_dashboard_activity_sample_wan_ts"
TS_INDEX = "idx_dashboard_activity_sample_ts"


def production_activity_schema() -> str:
    """Lift the CREATE TABLE text out of the C source so it cannot drift."""
    body = DB_SOURCE[DB_SOURCE.index('"CREATE TABLE dashboard_activity_sample ('):]
    end = body.index('PRIMARY KEY(ts, wan_id));"')
    body = body[: end + len('PRIMARY KEY(ts, wan_id));"')]
    return "".join(re.findall(r'"([^"]*)"', body))


def build_db(path: Path) -> sqlite3.Connection:
    """Reproduce the 30.1 shape: two busy WANs plus two much smaller ones.

    The ratio is what matters. wan3/wan4 hold a fraction of the rows, so under a
    ts-only index they pay for wan/wan2's rows on every read -- the case that
    regressed worst in production.
    """
    db = sqlite3.connect(path)
    db.executescript(production_activity_schema())
    rows = []
    base = 1_700_000_000
    for i in range(4000):
        ts = base + i * 10
        rows.append((ts, "wan", i, i * 2))
        rows.append((ts, "wan2", i, i * 2))
        rows.append((ts, "global", i, i * 2))
        if i % 8 == 0:                      # wan3/wan4 are sparse, as on 30.1
            rows.append((ts, "wan3", i, i * 2))
            rows.append((ts, "wan4", i, i * 2))
    db.executemany(
        "INSERT INTO dashboard_activity_sample(ts,wan_id,up_rate,down_rate) "
        "VALUES(?,?,?,?)",
        rows,
    )
    db.commit()
    return db


def plan_for(db: sqlite3.Connection, wan_id: str) -> str:
    cur = db.execute(
        "EXPLAIN QUERY PLAN " + INTEGRATE_QUERY,
        (0, 9_999_999_999, wan_id),
    )
    return " | ".join(str(row[-1]) for row in cur.fetchall())


def read_rows(db: sqlite3.Connection, wan_id: str) -> list:
    return list(db.execute(INTEGRATE_QUERY, (0, 9_999_999_999, wan_id)))


def test_per_wan_read_uses_a_wan_leading_index() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "activity.db"
        db = build_db(path)

        # Baseline: the ts-only index is what production had, and it forces the
        # full-window scan this defect was about.
        db.execute("CREATE INDEX " + TS_INDEX + " ON dashboard_activity_sample(ts)")
        db.commit()
        before = {wan: read_rows(db, wan) for wan in ("wan", "wan2", "wan3", "wan4")}
        ts_only_plan = plan_for(db, "wan3")
        assert WAN_TS_INDEX not in ts_only_plan

        # The v9 index must change the access path to a wan_id seek.
        db.execute(
            "CREATE INDEX IF NOT EXISTS " + WAN_TS_INDEX +
            " ON dashboard_activity_sample(wan_id, ts)"
        )
        db.commit()

        for wan in ("wan", "wan2", "wan3", "wan4"):
            plan = plan_for(db, wan)
            assert WAN_TS_INDEX in plan, (
                wan + " still does not use the wan-leading index: " + plan
            )
            # A composite (wan_id, ts) index already yields ts order, so the
            # planner must not add a sort. If it does, the index is not actually
            # serving the ORDER BY and the win is smaller than it looks.
            assert "USE TEMP B-TREE" not in plan.upper(), (
                wan + " query now sorts instead of reading in index order: " + plan
            )

        # Same rows, same values, same order. An index must not change results.
        for wan, rows in before.items():
            assert read_rows(db, wan) == rows, wan + " rows changed after indexing"
            assert rows == sorted(rows, key=lambda r: r[0]), wan + " not ts-ascending"

        # Rows must be that WAN's only. This is the actual bug: the old plan
        # visited every WAN's rows and filtered afterwards.
        for wan in ("wan", "wan3"):
            ids = {
                row[0]
                for row in db.execute(
                    "SELECT DISTINCT wan_id FROM dashboard_activity_sample "
                    "WHERE wan_id=?",
                    (wan,),
                )
            }
            assert ids == {wan}, ids

        # The ts index must stay useful: whole-window readers (activity charts)
        # and pruning still filter on ts alone.
        window_plan = " | ".join(
            str(row[-1])
            for row in db.execute(
                "EXPLAIN QUERY PLAN SELECT ts,up_rate FROM "
                "dashboard_activity_sample WHERE ts>=? AND ts<=? ORDER BY ts ASC",
                (0, 9_999_999_999),
            ).fetchall()
        )
        assert TS_INDEX in window_plan, (
            "whole-window read regressed off the ts index: " + window_plan
        )
        prune_plan = " | ".join(
            str(row[-1])
            for row in db.execute(
                "EXPLAIN QUERY PLAN DELETE FROM dashboard_activity_sample "
                "WHERE ts < ?",
                (123,),
            ).fetchall()
        )
        assert TS_INDEX in prune_plan, "prune regressed off the ts index: " + prune_plan
        db.close()


def test_migration_is_present_and_idempotent() -> None:
    """The index must reach existing databases, not only freshly created ones."""
    version = int(
        re.search(r"#define JMX_DB_SCHEMA_VERSION\s+(\d+)", DB_SOURCE).group(1)
    )
    assert version >= 9, "schema version not bumped for the index: " + str(version)

    migration = DB_SOURCE[DB_SOURCE.index("if (version < 9) {"):]
    migration = migration[: migration.index("db_set_schema_version")]
    assert WAN_TS_INDEX in migration, "v9 migration does not create the index"
    assert "IF NOT EXISTS" in migration, "migration is not re-runnable"

    # A fresh install must get it too, or new devices silently keep the slow
    # plan while migrated ones are fast.
    create_path = DB_SOURCE[
        DB_SOURCE.index("creating dashboard_activity_sample table"):
    ]
    create_path = create_path[: create_path.index("dashboard_daily_usage_counter")]
    assert WAN_TS_INDEX in create_path, (
        "the fresh-create path does not add the wan-leading index"
    )

    # Applying the step twice must not fail.
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "mig.db"
        db = build_db(path)
        stmt = (
            "CREATE INDEX IF NOT EXISTS " + WAN_TS_INDEX +
            " ON dashboard_activity_sample(wan_id, ts)"
        )
        db.execute(stmt)
        db.execute(stmt)          # re-run: must be a no-op, not an error
        db.commit()
        names = {
            row[0]
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND tbl_name='dashboard_activity_sample'"
            )
        }
        assert WAN_TS_INDEX in names, names
        db.close()


if __name__ == "__main__":
    test_per_wan_read_uses_a_wan_leading_index()
    test_migration_is_present_and_idempotent()
    print("ok: per-WAN activity reads seek by wan_id and the migration is idempotent")

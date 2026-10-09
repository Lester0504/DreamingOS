#!/usr/bin/env python3
"""Client overrides must outlive the clients row they were created for.

``client_overrides`` holds user intent: a name the user typed, an icon the user
picked, a note the user wrote. Until schema v8 the table hung off
``clients(client_id)`` with ``ON DELETE CASCADE`` while the equivalent mac-keyed
``client_identity_overrides`` had no such link, so the same class of data
disagreed about durability: any future "prune old clients" DELETE would have
silently taken half of it. Handoff-to-Backend-client-overrides-cascade-risk.

The DDL and the migration statements are lifted out of ``src/jmx_db.c`` and run
against a real sqlite3, so this proves behavior rather than asserting that the
source contains some words.
"""
from __future__ import annotations

import re
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB_C = (ROOT / "src/jmx_db.c").read_text()

CLIENTS_DDL = (
    "CREATE TABLE clients (client_id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "mac TEXT NOT NULL UNIQUE, hostname TEXT)"
)
# The pre-v8 shape, kept verbatim so the migration is exercised against the
# schema that is actually out in the field.
LEGACY_OVERRIDES_DDL = """
CREATE TABLE client_overrides (
  client_id INTEGER PRIMARY KEY, custom_name TEXT, custom_icon TEXT,
  custom_device_type TEXT, custom_vendor TEXT,
  pinned INTEGER NOT NULL DEFAULT 0, hidden INTEGER NOT NULL DEFAULT 0,
  note TEXT, updated_at INTEGER NOT NULL,
  FOREIGN KEY(client_id) REFERENCES clients(client_id) ON DELETE CASCADE)
"""

failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def strip_c_comments(text: str) -> str:
    """Remove /* ... */ comments so only real string literals are collected.

    The shipped DDL is a run of concatenated literals with explanatory comments
    interleaved between them; without this the comment prose gets spliced into
    the SQL.
    """
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def c_strings_after(marker: str, source: str, limit: int) -> str:
    """Concatenate the C string literals following a marker, as C would."""
    start = source.find(marker)
    if start < 0:
        raise SystemExit(f"FAIL: marker not found in src/jmx_db.c: {marker!r}")
    window = strip_c_comments(source[start:start + limit])
    return "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', window)).replace('\\"', '"')


def shipped_overrides_ddl() -> str:
    """The CREATE TABLE the daemon ships for a brand-new database."""
    # Anchor on the literal that opens the statement, so the table name and the
    # first columns are inside the captured window rather than behind it.
    marker = '"CREATE TABLE IF NOT EXISTS client_overrides ("'
    text = c_strings_after(marker, DB_C, 4000)
    start = text.find("CREATE TABLE")
    end = text.find(");", start)
    if start < 0 or end < 0:
        raise SystemExit("FAIL: could not delimit the client_overrides DDL")
    return text[start:end + 1]


def _exec_sql(block: str) -> list[str]:
    out: list[str] = []
    for call in re.finditer(r'db_exec\(\s*((?:"(?:[^"\\]|\\.)*"\s*)+)\)',
                            strip_c_comments(block)):
        sql = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', call.group(1)))
        out.append(sql.replace('\\"', '"'))
    return out


def migration_block() -> str:
    start = DB_C.find("if (version < 8) {")
    if start < 0:
        raise SystemExit("FAIL: the v8 migration block is gone from src/jmx_db.c")
    # Stop at the next migration step, not at db_set_schema_version: later steps
    # sit between the two and their DDL touches unrelated tables, which this
    # fixture does not create.
    end = DB_C.find("if (version < 9) {", start)
    if end < 0:
        end = DB_C.find("db_set_schema_version", start)
    return DB_C[start:end]


def migration_statements() -> list[str]:
    """SQL for the rebuild path: a database still carrying the foreign key.

    The rebuild and the ADD COLUMN are mutually exclusive branches in the C, so
    running both against one database would be a fiction -- and would hit
    "duplicate column name", since the rebuilt table already has mac.
    """
    block = migration_block()
    add_column = block.find("} else if (!db_table_has_column(")
    if add_column < 0:
        raise SystemExit("FAIL: the v8 migration no longer branches on "
                         "has_cascade; re-derive which statements apply")
    # The index is created after the branches, so it applies to both paths.
    index = [s for s in _exec_sql(block[add_column:]) if "CREATE INDEX" in s]
    return _exec_sql(block[:add_column]) + index


def add_column_statements() -> list[str]:
    """SQL for the other path: no foreign key, but no mac column yet."""
    block = migration_block()
    start = block.find("} else if (!db_table_has_column(")
    if start < 0:
        raise SystemExit("FAIL: the v8 add-column branch is gone")
    return _exec_sql(block[start:])


def connect() -> sqlite3.Connection:
    """A connection where PRAGMA foreign_keys actually takes effect.

    The default isolation_level opens an implicit transaction, and sqlite
    silently ignores the pragma inside one, which would quietly disable the
    very constraint these tests are about.
    """
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.execute("PRAGMA foreign_keys=ON")
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    return conn


def seed_legacy(conn: sqlite3.Connection) -> None:
    conn.executescript(f"{CLIENTS_DDL};{LEGACY_OVERRIDES_DDL};")
    conn.execute("INSERT INTO clients(mac,hostname) VALUES('AA:BB:CC:00:00:01','phone')")
    conn.execute("INSERT INTO clients(mac,hostname) VALUES('AA:BB:CC:00:00:02','laptop')")
    conn.executemany(
        "INSERT INTO client_overrides(client_id,custom_name,custom_icon,note,updated_at)"
        " VALUES(?,?,?,?,?)",
        [(1, "my phone", "/uploads/phone.svg", "", 100),
         (2, "laptop", "/uploads/laptop.svg", "desk", 100)],
    )
    # A row whose client vanished long ago. The migration must carry it, not
    # quietly drop it.
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("INSERT INTO client_overrides(client_id,custom_name,updated_at)"
                 " VALUES(999,'orphan',100)")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.commit()


def test_legacy_cascade_really_did_delete() -> None:
    """Guard the premise: without the fix, a client DELETE takes the override."""
    conn = connect()
    seed_legacy(conn)
    conn.execute("DELETE FROM clients WHERE client_id=1")
    left = conn.execute("SELECT count(*) FROM client_overrides WHERE client_id=1").fetchone()[0]
    check(left == 0,
          "the pre-v8 schema no longer cascades, so this test's premise is "
          "stale; re-derive it from the current DDL")
    conn.close()


def test_migration_preserves_and_backfills() -> None:
    conn = connect()
    seed_legacy(conn)

    stmts = migration_statements()
    check(bool(stmts), "the v8 migration runs no SQL")
    conn.execute("BEGIN")
    for sql in stmts:
        conn.execute(sql)
    conn.commit()

    rows = dict(conn.execute(
        "SELECT client_id, custom_name FROM client_overrides").fetchall())
    check(rows.get(1) == "my phone", "the migration lost client 1's custom name")
    check(rows.get(2) == "laptop", "the migration lost client 2's custom name")
    check(rows.get(999) == "orphan",
          "the migration dropped an override whose client row was already gone; "
          "user intent must be carried, not garbage-collected")

    macs = dict(conn.execute(
        "SELECT client_id, mac FROM client_overrides").fetchall())
    check(macs.get(1) == "AA:BB:CC:00:00:01", "mac was not back-filled for client 1")
    check(macs.get(2) == "AA:BB:CC:00:00:02", "mac was not back-filled for client 2")
    check(macs.get(999) is None,
          "an orphan row must keep a NULL mac rather than inventing one")

    ddl = conn.execute("SELECT sql FROM sqlite_master WHERE type='table'"
                       " AND name='client_overrides'").fetchone()[0]
    check("REFERENCES" not in ddl.upper(),
          "client_overrides still references clients after the v8 migration")

    # Acceptance criterion: a recycled client row must not take user intent.
    conn.execute("DELETE FROM clients WHERE client_id=2")
    survived = conn.execute("SELECT custom_name, custom_icon FROM client_overrides"
                            " WHERE client_id=2").fetchone()
    check(survived is not None and survived[0] == "laptop"
          and survived[1] == "/uploads/laptop.svg",
          "deleting a clients row still destroys the user's override")
    conn.close()


def test_fresh_database_ships_without_cascade() -> None:
    """A new install must not be born with the cascade the migration removes."""
    ddl = shipped_overrides_ddl()
    check("REFERENCES" not in ddl.upper(),
          "the shipped client_overrides DDL still has a foreign key to clients")
    check(" mac TEXT" in ddl,
          "the shipped client_overrides DDL carries no mac column, so an "
          "override cannot be re-bound after its client row is recreated")

    conn = connect()
    conn.executescript(f"{CLIENTS_DDL};{ddl};")
    conn.execute("INSERT INTO clients(mac) VALUES('AA:BB:CC:00:00:09')")
    conn.execute("INSERT INTO client_overrides(client_id,mac,custom_name,updated_at)"
                 " VALUES(1,'AA:BB:CC:00:00:09','kept',100)")
    conn.commit()
    conn.execute("DELETE FROM clients WHERE client_id=1")
    row = conn.execute("SELECT custom_name FROM client_overrides"
                       " WHERE mac='AA:BB:CC:00:00:09'").fetchone()
    check(row is not None and row[0] == "kept",
          "on a fresh database, deleting a client still deletes its override")
    conn.close()


def test_add_column_path_backfills_mac() -> None:
    """The other migration path: no foreign key, but no mac column either.

    This is the branch that must not re-add a column the rebuild already made,
    and it still has to populate mac for the rows already in the table.
    """
    conn = connect()
    conn.executescript(
        f"{CLIENTS_DDL};"
        "CREATE TABLE client_overrides ("
        " client_id INTEGER PRIMARY KEY, custom_name TEXT, custom_icon TEXT,"
        " custom_device_type TEXT, custom_vendor TEXT,"
        " pinned INTEGER NOT NULL DEFAULT 0, hidden INTEGER NOT NULL DEFAULT 0,"
        " note TEXT, updated_at INTEGER NOT NULL);"
    )
    conn.execute("INSERT INTO clients(mac) VALUES('AA:BB:CC:00:00:07')")
    conn.execute("INSERT INTO client_overrides(client_id,custom_name,updated_at)"
                 " VALUES(1,'kept',100)")

    stmts = add_column_statements()
    check(any("ADD COLUMN mac" in s for s in stmts),
          "the add-column branch no longer adds mac")
    for sql in stmts:
        conn.execute(sql)

    row = conn.execute("SELECT custom_name, mac FROM client_overrides"
                       " WHERE client_id=1").fetchone()
    check(row is not None and row[0] == "kept",
          "the add-column path lost an existing override")
    check(row is not None and row[1] == "AA:BB:CC:00:00:07",
          "the add-column path left mac NULL, so the row cannot be re-bound "
          "after its client row is recreated")
    conn.close()


def test_override_rebinds_to_a_recreated_client() -> None:
    """A device that leaves and comes back inherits its own settings again.

    clients.client_id is AUTOINCREMENT, so the returning device gets a new id
    and the surviving override would otherwise sit stranded on the old one.
    """
    check("UPDATE OR REPLACE client_overrides SET client_id=?1 " in DB_C
          and "WHERE mac=?2 AND client_id<>?1" in DB_C,
          "the mac-keyed re-bind is gone from jmx_db_api_client_override(); a "
          "returning device would silently lose its saved name and icon")

    conn = connect()
    conn.executescript(f"{CLIENTS_DDL};{shipped_overrides_ddl()};")
    conn.execute("INSERT INTO clients(mac) VALUES('AA:BB:CC:00:00:01')")
    conn.execute("INSERT INTO clients(mac) VALUES('AA:BB:CC:00:00:02')")
    conn.execute("INSERT INTO client_overrides(client_id,mac,custom_name,updated_at)"
                 " VALUES(1,'AA:BB:CC:00:00:01','my phone',100)")
    conn.execute("INSERT INTO client_overrides(client_id,mac,custom_name,updated_at)"
                 " VALUES(2,'AA:BB:CC:00:00:02','laptop',100)")
    conn.commit()

    conn.execute("DELETE FROM clients WHERE client_id=1")
    cur = conn.execute("INSERT INTO clients(mac) VALUES('AA:BB:CC:00:00:01')")
    new_id = cur.lastrowid
    check(new_id != 1,
          "AUTOINCREMENT reused a client_id; the re-bind reasoning assumed it "
          "would not, so re-check this path")

    conn.execute("UPDATE OR REPLACE client_overrides SET client_id=?"
                 " WHERE mac=? AND client_id<>?",
                 (new_id, "AA:BB:CC:00:00:01", new_id))
    conn.commit()
    row = conn.execute("SELECT custom_name FROM client_overrides"
                       " WHERE client_id=?", (new_id,)).fetchone()
    check(row is not None and row[0] == "my phone",
          "the returning device did not inherit its own saved name")
    other = conn.execute("SELECT custom_name FROM client_overrides"
                         " WHERE mac='AA:BB:CC:00:00:02'").fetchone()
    check(other is not None and other[0] == "laptop",
          "the re-bind touched a different device's override")
    check(conn.execute("SELECT count(*) FROM client_overrides").fetchone()[0] == 2,
          "the re-bind changed the number of override rows")
    conn.close()


def test_read_path_join_still_works() -> None:
    """The list query joins on client_id; dropping the FK must not break it."""
    check("LEFT JOIN client_overrides o ON o.client_id=c.client_id" in DB_C,
          "the clients list no longer joins client_overrides on client_id; if "
          "the join key changed, this test and the DDL must change together")
    conn = connect()
    conn.executescript(f"{CLIENTS_DDL};{shipped_overrides_ddl()};")
    conn.execute("INSERT INTO clients(mac) VALUES('AA:BB:CC:00:00:01')")
    conn.execute("INSERT INTO client_overrides(client_id,mac,custom_name,updated_at)"
                 " VALUES(1,'AA:BB:CC:00:00:01','my phone',100)")
    row = conn.execute(
        "SELECT COALESCE(o.custom_name,'') FROM clients c "
        "LEFT JOIN client_overrides o ON o.client_id=c.client_id").fetchone()
    check(row is not None and row[0] == "my phone",
          "the join no longer resolves the override")
    conn.close()


def main() -> int:
    for fn in (test_legacy_cascade_really_did_delete,
               test_migration_preserves_and_backfills,
               test_fresh_database_ships_without_cascade,
               test_add_column_path_backfills_mac,
               test_override_rebinds_to_a_recreated_client,
               test_read_path_join_still_works):
        fn()
    if failures:
        for f in failures:
            print(f"FAIL: {f}")
        return 1
    print("ok: client overrides survive a deleted clients row, migrate without "
          "loss, and re-bind to a recreated client")
    return 0


if __name__ == "__main__":
    sys.exit(main())

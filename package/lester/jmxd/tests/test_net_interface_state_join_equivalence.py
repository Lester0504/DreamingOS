#!/usr/bin/env python3
"""The current-state join must preserve rows while removing per-row scans."""

import sqlite3


def _db() -> sqlite3.Connection:
    db = sqlite3.connect(":memory:")
    db.executescript(
        """
        CREATE TABLE net_interfaces (
            iface_id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            kind TEXT NOT NULL
        );
        CREATE TABLE net_interface_state (
            iface_id INTEGER NOT NULL UNIQUE,
            ts INTEGER NOT NULL,
            online INTEGER NOT NULL DEFAULT 0,
            rx_rate INTEGER NOT NULL DEFAULT 0,
            tx_rate INTEGER NOT NULL DEFAULT 0
        );
        INSERT INTO net_interfaces VALUES
            (1, 'wan', 'wan'), (2, 'wan2', 'wan'), (3, 'lan', 'lan');
        INSERT INTO net_interface_state(iface_id, ts, online, rx_rate, tx_rate)
            VALUES (1, 100, 1, 11, 22), (2, 101, 0, 33, 44);
        """
    )
    return db


def test_direct_join_matches_legacy_current_state_rows() -> None:
    db = _db()
    legacy = db.execute(
        """
        SELECT i.name, s.ts, s.online, s.rx_rate, s.tx_rate
        FROM net_interfaces i
        LEFT JOIN net_interface_state s
          ON s.rowid = (
              SELECT rowid FROM net_interface_state
              WHERE iface_id = i.iface_id
              ORDER BY ts DESC LIMIT 1
          )
        WHERE i.kind='wan' ORDER BY i.name
        """
    ).fetchall()
    direct = db.execute(
        """
        SELECT i.name, s.ts, s.online, s.rx_rate, s.tx_rate
        FROM net_interfaces i
        LEFT JOIN net_interface_state s ON s.iface_id = i.iface_id
        WHERE i.kind='wan' ORDER BY i.name
        """
    ).fetchall()
    assert direct == legacy == [('wan', 100, 1, 11, 22), ('wan2', 101, 0, 33, 44)]


def test_direct_join_avoids_correlated_subquery_plan() -> None:
    db = _db()
    plan = db.execute(
        """
        EXPLAIN QUERY PLAN
        SELECT i.name, s.ts
        FROM net_interfaces i
        LEFT JOIN net_interface_state s ON s.iface_id = i.iface_id
        WHERE i.kind='wan'
        """
    ).fetchall()
    text = " ".join(row[-1] for row in plan)
    assert "CORRELATED" not in text.upper()
    assert "iface_id" in text


if __name__ == "__main__":
    test_direct_join_matches_legacy_current_state_rows()
    test_direct_join_avoids_correlated_subquery_plan()
    print("ok: direct interface-state join is equivalent and non-correlated")

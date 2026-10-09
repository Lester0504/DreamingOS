#!/usr/bin/env python3
"""Exercise the activity matrix limit+1 pagination semantics with SQLite."""

import sqlite3


def page(db: sqlite3.Connection, offset: int, limit: int):
    rows = db.execute(
        """
        SELECT app_key, client_key, SUM(rx_bytes + tx_bytes) AS bytes
        FROM samples
        GROUP BY app_key, client_key
        ORDER BY bytes DESC, app_key ASC, client_key ASC
        LIMIT ? OFFSET ?
        """,
        (limit + 1, offset),
    ).fetchall()
    has_more = len(rows) > limit
    returned = rows[:limit]
    next_offset = offset + len(returned) if has_more else None
    return returned, has_more, next_offset


db = sqlite3.connect(":memory:")
db.execute("CREATE TABLE samples(app_key TEXT, client_key TEXT, rx_bytes INTEGER, tx_bytes INTEGER)")
db.executemany(
    "INSERT INTO samples VALUES(?,?,?,?)",
    [
        ("app:a", "client:1", 90, 10),
        ("app:a", "client:2", 80, 20),
        ("app:b", "client:1", 75, 25),
        ("app:b", "client:2", 70, 20),
        ("app:c", "client:1", 60, 20),
    ],
)

first, first_more, first_next = page(db, 0, 2)
second, second_more, second_next = page(db, first_next, 2)
last, last_more, last_next = page(db, second_next, 2)

assert len(first) == 2 and first_more and first_next == 2
assert len(second) == 2 and second_more and second_next == 4
assert len(last) == 1 and not last_more and last_next is None
assert not ({row[:2] for row in first} & {row[:2] for row in second})
assert not ({row[:2] for row in second} & {row[:2] for row in last})
assert [row[:2] for row in first] == [("app:a", "client:1"), ("app:a", "client:2")]

# Exactly one full page must not claim a next page without a lookahead row.
db.execute("DELETE FROM samples WHERE app_key != 'app:a'")
exact, exact_more, exact_next = page(db, 0, 2)
assert len(exact) == 2 and not exact_more and exact_next is None

print("ok: matrix pages are stable, disjoint, and expose an exact next offset")

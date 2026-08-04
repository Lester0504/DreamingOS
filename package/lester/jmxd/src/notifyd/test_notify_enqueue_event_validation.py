#!/usr/bin/env python3
"""Contract tests for notifyd enqueue event-id validation.

Covers `Backend-to-Backend-notifyd-enqueue-accepts-unknown-event-id.md`:
`enqueue` accepted any "event" string, answered ok:true, and returned exit
code 0, so a typo'd event constant was delivered with an id nothing downstream
recognised. Producers only observe the `ubus call` exit code, which is why the
ubus layer has to fail too and not just the JSON body.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NOTIFYD_DB = ROOT / "src" / "notifyd" / "notifyd_db.c"
NOTIFYD_UBUS = ROOT / "src" / "notifyd" / "notifyd_ubus.c"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def c_function(source: str, marker: str) -> str:
    """Return one C function body, ignoring braces inside strings/comments."""
    start = source.index(marker)
    brace = source.index("{", start)
    depth = 0
    quote = ""
    escaped = False
    line_comment = False
    block_comment = False
    i = brace
    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if line_comment:
            if ch == "\n":
                line_comment = False
        elif block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
                i += 1
        elif quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
        elif ch == "/" and nxt == "/":
            line_comment = True
            i += 1
        elif ch == "/" and nxt == "*":
            block_comment = True
            i += 1
        elif ch in "\"'":
            quote = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
        i += 1
    raise AssertionError("unterminated function for " + marker)


def catalog_ids(source: str) -> set[str]:
    start = source.index("static const struct notifyd_event_definition notifyd_event_definitions[]")
    end = source.index("static void notifyd_event_ids_json(", start)
    return set(re.findall(r'\{\s*"([A-Z0-9_]+)"', source[start:end]))


def test_unknown_and_missing_event_are_rejected_before_routing():
    enqueue = c_function(read(NOTIFYD_DB), "struct json_object *notifyd_enqueue_event(")

    assert "event_required" in enqueue, "missing event id must have its own error"
    assert "event_unknown" in enqueue, "unknown event id must have its own error"
    assert "notifyd_event_definition_find(" in enqueue, \
        "enqueue must look the event id up in the catalog"

    # The check has to happen before any route is consulted, otherwise a
    # rejected event can still reach the outbox.
    lookup_at = enqueue.index("notifyd_event_definition_find(")
    routes_at = enqueue.index("FROM notifyd_routes")
    assert lookup_at < routes_at, \
        "event validation must run before the route query"


def test_lookup_covers_pending_definitions_too():
    source = read(NOTIFYD_DB)
    finder = c_function(source, "static const struct notifyd_event_definition *notifyd_event_definition_find(")
    # Matching on `available` would reject catalog ids whose producer is not
    # wired up yet, turning "not collected" into "rejected".
    assert "available" not in finder, \
        "lookup must not filter on the available flag"

    ids = catalog_ids(source)
    for required in ("WAN_DOWN", "PROXY_EGRESS_DRIFT", "ISP_PACKET_LOSS"):
        assert required in ids, f"{required} should be a catalog id"


def test_ubus_layer_returns_nonzero_status():
    handler = c_function(read(NOTIFYD_UBUS), "static int notifyd_handle_enqueue(")

    assert "return UBUS_STATUS_OK;" not in handler, \
        "enqueue must not unconditionally return UBUS_STATUS_OK"
    assert "UBUS_STATUS_NOT_FOUND" in handler, "unknown event needs a failing status"
    assert "UBUS_STATUS_INVALID_ARGUMENT" in handler, \
        "malformed payload needs a failing status"
    for reason in ("event_unknown", "event_required", "invalid_payload"):
        assert reason in handler, f"handler must map {reason} to a status"


def test_real_producer_ids_are_all_in_the_catalog():
    """Guards the compatibility risk: validation must not start rejecting a
    live producer's event. Every id enqueued in-tree has to be a catalog id."""
    ids = catalog_ids(read(NOTIFYD_DB))
    used = set()
    for path in ROOT.rglob("*.c"):
        if "notifyd_db.c" in path.name:
            continue
        for match in re.findall(r'"event"\s*,\s*"([A-Z0-9_]+)"', path.read_text(
                encoding="utf-8", errors="ignore")):
            used.add(match)
    missing = sorted(used - ids)
    assert not missing, f"producers enqueue ids absent from the catalog: {missing}"


if __name__ == "__main__":
    for test in (
        test_unknown_and_missing_event_are_rejected_before_routing,
        test_lookup_covers_pending_definitions_too,
        test_ubus_layer_returns_nonzero_status,
        test_real_producer_ids_are_all_in_the_catalog,
    ):
        test()
    print("ok - notifyd enqueue event validation contracts passed")

#!/usr/bin/env python3
"""Contract and SQLite fixtures for global mute and route trigger summaries."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DB = (ROOT / "src/notifyd/notifyd_db.c").read_text(encoding="utf-8")
UBUS = (ROOT / "src/notifyd/notifyd_ubus.c").read_text(encoding="utf-8")
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text(encoding="utf-8")


def function(source: str, marker: str) -> str:
    start = source.index(marker)
    while True:
        brace = source.index("{", start)
        semicolon = source.find(";", start, brace)
        if semicolon < 0:
            break
        start = source.index(marker, semicolon + 1)
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
                return source[start : i + 1]
        i += 1
    raise AssertionError(f"unterminated function: {marker}")


def joined_c_strings(text: str) -> str:
    values = re.findall(r'"((?:\\.|[^"\\])*)"', text)
    return "".join(bytes(value, "utf-8").decode("unicode_escape") for value in values)


def test_settings_capability_and_fail_closed_contract() -> None:
    get = function(DB, "struct json_object *notifyd_settings_json(")
    update = function(DB, "struct json_object *notifyd_settings_update(")
    normalize = function(DB, "static int notifyd_global_mute_normalize(")

    for token in (
        '"mute_schedule_supported"',
        '"mobile_push_supported"',
        '"device_token_provider_not_configured"',
        '"mute_schedule"',
    ):
        assert token in get
    assert 'json_object_object_add(resp, "mute_schedule_supported"' in get
    assert 'json_object_object_add(resp, "mobile_push_supported"' in get
    assert "notifyd_global_mute_normalize(stored_mute" in get
    assert 'json_object_object_get_ex(body, "mobile_push", &mobile_push)' in update
    assert "json_object_get_boolean(mobile_push)" not in update
    assert '"feature_unsupported"' in update and '"mobile_push"' in update
    for field in ('"enabled"', '"timezone"', '"windows"', '"days"', '"start"', '"end"'):
        assert field in normalize
    assert "day_value" in normalize and "day > 7" in normalize
    assert "end <= start" in normalize and "mute_schedule_window_overlap" in normalize
    active = function(DB, "static int notifyd_global_mute_active(")
    assert 'strcmp(evaluation_reason, "schedule_outside_window")' in active
    assert '"global_mute_schedule_unavailable"' in active


def test_trigger_fact_is_recorded_before_delivery_and_without_secrets() -> None:
    enqueue = function(DB, "struct json_object *notifyd_enqueue_event(")
    timeline = function(DB, "struct json_object *notifyd_triggers_json(")
    mute_check = enqueue.index("notifyd_global_mute_active")
    outbox_insert = enqueue.index("notifyd_insert_outbox_ex")

    assert mute_check < outbox_insert
    assert 'notifyd_route_trigger_record(route_id, body, "muted"' in enqueue
    assert 'notifyd_route_trigger_record(route_id, body, "deduped"' in enqueue
    assert 'notifyd_route_trigger_record(route_id, body, "enqueued"' in enqueue
    for field in (
        '"route_id"', '"event"', '"severity"', '"source"', '"triggered_at"',
        '"result"', '"reason"', '"dedupe_result"', '"mute_result"',
    ):
        assert field in timeline
    for secret in ("payload_json", "receivers", "smtp_password", "password", "token"):
        assert secret not in timeline


def test_route_summary_and_timeline_sql_runtime() -> None:
    marker = '"CREATE TABLE IF NOT EXISTS notify_route_triggers ("'
    start = DB.rfind("notifyd_exec(g_notify_db,", 0, DB.index(marker))
    end = DB.index(") != 0 ||", DB.index(marker))
    create_sql = joined_c_strings(DB[start:end])
    assert create_sql.startswith("CREATE TABLE IF NOT EXISTS notify_route_triggers")

    db = sqlite3.connect(":memory:")
    db.execute(create_sql)
    db.executescript(
        """
        CREATE TABLE notify_outbox(id TEXT PRIMARY KEY, route_id TEXT NOT NULL);
        CREATE TABLE notify_deliveries(id INTEGER PRIMARY KEY, outbox_id TEXT NOT NULL);
        """
    )
    facts = [
        ("route-a", "WAN_DOWN", "warning", "routed", 100, "enqueued", "", "not_deduped", "not_muted"),
        ("route-a", "WAN_DOWN", "warning", "routed", 101, "deduped", "route_or_producer_dedupe", "deduped", "not_muted"),
        ("route-a", "WAN_RESTORED", "notice", "routed", 102, "muted", "global_mute_schedule_active", "not_applicable", "global_schedule"),
        ("route-b", "SYSTEM_LOG", "notice", "logd", 103, "enqueued", "", "not_deduped", "not_muted"),
    ]
    db.executemany(
        "INSERT INTO notify_route_triggers(route_id,event,severity,source,triggered_at,result,reason,dedupe_result,mute_result) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        facts,
    )
    db.executemany("INSERT INTO notify_outbox VALUES(?,?)", [("o1", "route-a"), ("o2", "route-b")])
    db.executemany("INSERT INTO notify_deliveries VALUES(?,?)", [(1, "o1"), (2, "o1"), (3, "o2")])

    assert db.execute(
        "SELECT COUNT(*),MAX(triggered_at) FROM notify_route_triggers WHERE route_id='route-a'"
    ).fetchone() == (3, 102)
    assert db.execute("SELECT COUNT(*) FROM notify_outbox WHERE route_id='route-a'").fetchone() == (1,)
    assert db.execute(
        "SELECT COUNT(*) FROM notify_deliveries d JOIN notify_outbox o ON o.id=d.outbox_id "
        "WHERE o.route_id='route-a'"
    ).fetchone() == (2,)

    page1 = db.execute(
        "SELECT id,route_id,result FROM notify_route_triggers WHERE route_id=? ORDER BY id DESC LIMIT 3",
        ("route-a",),
    ).fetchall()
    assert len(page1) == 3
    next_cursor = page1[1][0]
    page2 = db.execute(
        "SELECT id,route_id,result FROM notify_route_triggers WHERE route_id=? AND id<? "
        "ORDER BY id DESC LIMIT 2",
        ("route-a", next_cursor),
    ).fetchall()
    assert page2 == [(page1[2][0], "route-a", "enqueued")]


def test_readonly_route_is_wired_end_to_end() -> None:
    assert 'UBUS_METHOD("triggers_get"' in UBUS
    assert '"/api/v1/notifyd/triggers"' in WEB
    assert '"route_id"' in WEB and '"cursor"' in WEB and '"limit"' in WEB
    assert '{ "/api/v1/notifyd/triggers",      "GET", JMX_RISK_LOW }' in PERMS


if __name__ == "__main__":
    test_settings_capability_and_fail_closed_contract()
    test_trigger_fact_is_recorded_before_delivery_and_without_secrets()
    test_route_summary_and_timeline_sql_runtime()
    test_readonly_route_is_wired_end_to_end()
    print("ok - notifyd global settings and trigger summary contracts passed")

#!/usr/bin/env python3
"""Source and SQLite fixtures for notifyd route schema v1 capabilities."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DB_SOURCE = ROOT / "src" / "notifyd" / "notifyd_db.c"
DELIVERY_SOURCE = ROOT / "src" / "notifyd" / "notifyd_delivery.c"
HEADER = ROOT / "src" / "notifyd" / "notifyd_internal.h"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def c_function(source: str, marker: str) -> str:
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
                return source[start : i + 1]
        i += 1
    raise AssertionError(f"unterminated C function: {marker}")


def c_strings(function: str) -> list[str]:
    strings = re.findall(r'"((?:\\.|[^"\\])*)"', function)
    return [bytes(value, "utf-8").decode("unicode_escape") for value in strings]


def sql_containing(function: str, needle: str) -> str:
    calls = re.findall(
        r'notifyd_prepare\(\s*((?:"(?:\\.|[^"\\])*"\s*)+)\)',
        function,
        re.S,
    )
    for call in calls:
        combined = "".join(c_strings(call))
        if needle in combined:
            return combined
    raise AssertionError(f"SQL containing {needle!r} not found")


def test_capability_manifest_and_v1_defaults_are_explicit() -> None:
    source = read(DB_SOURCE)
    status = c_function(source, "struct json_object *notifyd_status_json(")
    contract = c_function(source, "static int notifyd_route_contract_build(")

    for feature in (
        "schedule",
        "multi_action",
        "rule_receivers",
        "custom_content",
        "route_dedupe",
    ):
        assert f'route_features, "{feature}", json_object_new_boolean(1)' in status
    for value in ("notify", "channel", "admins", "users", "emails", "default", "custom"):
        assert f'json_object_new_string("{value}")' in status
    for default in (
        'json_object_new_string("always")',
        'json_object_new_string("notify")',
        'json_object_new_string("channel")',
        'json_object_new_string("default")',
        'json_object_new_boolean(0)',
    ):
        assert default in contract
    assert 'json_object_object_add(o, "channel_id"' in source
    assert 'json_object_object_add(o, "min_severity"' in source


def test_schema_validation_has_stable_codes_and_atomic_revision_save() -> None:
    source = read(DB_SOURCE)
    contract = c_function(source, "static int notifyd_route_contract_build(")
    update = c_function(source, "struct json_object *notifyd_routes_update(")

    for code in (
        "route_feature_unsupported",
        "route_action_conflict",
        "action_invalid",
        "channel_incompatible",
        "schedule_invalid",
        "schedule_window_invalid",
        "receiver_mode_incompatible",
        "receiver_invalid",
        "content_template_invalid",
        "dedupe_window_invalid",
        "dedupe_key_invalid",
    ):
        assert f'"{code}"' in contract
    assert '"duplicate_action"' in contract
    assert '"action_index"' in source and '"field"' in source and '"feature"' in source
    assert 'notifyd_route_timezone_ok(timezone)' in contract
    assert "end <= start" in contract
    assert "start < ranges" in contract and "end > ranges" in contract
    assert 'BEGIN IMMEDIATE' in update and 'COMMIT' in update and 'ROLLBACK' in update
    assert 'if (now <= current_updated_at)' in update
    assert 'now = current_updated_at + 1' in update
    revision = c_function(source, "static int notifyd_config_revision_matches(")
    assert "expected < 0 || value == expected" in revision


def test_schedule_suppression_and_multi_action_diagnostics_are_exposed() -> None:
    source = read(DB_SOURCE)
    enqueue = c_function(source, "struct json_object *notifyd_enqueue_event(")
    routes = c_function(source, "static void notifyd_route_row_json(")
    outbox = c_function(source, "static void notifyd_outbox_row_json(")

    assert "notifyd_route_schedule_allows" in enqueue
    assert "notifyd_route_suppression_record" in enqueue
    assert '"suppression_reason"' in enqueue
    assert '"suppression_count"' in routes
    assert '"last_suppressed_at"' in routes
    assert '"last_suppression_reason"' in routes
    assert '"action_index"' in outbox
    assert '"render_failures"' in enqueue and '"partial_enqueue_failed"' in enqueue
    assert "if (!matched_routes && !suppressed" in enqueue


def test_receiver_delivery_is_dynamic_and_warning_safe() -> None:
    source = read(DELIVERY_SOURCE)
    load = c_function(source, "static int notifyd_load_outbox_item(")
    resolve = c_function(source, "static int notifyd_mail_resolve_route_recipients(")
    users = c_function(source, "static void notifyd_mail_resolve_user_ids(")
    admins = c_function(source, "static void notifyd_mail_resolve_admins(")
    warning = c_function(source, "static void notifyd_mail_resolution_warning(")

    assert "delivery_options_json,action_index" in load
    for mode in ("channel", "admins", "users", "emails"):
        assert f'!strcmp(mode, "{mode}")' in resolve
    assert "SELECT status,email FROM web_users WHERE username=?1" in users
    assert "status='enabled'" in admins and "role IN ('owner','admin')" in admins
    assert "%s:%d" in warning
    assert "email" not in warning.lower()


def test_route_and_producer_dedupe_sql_behave_differently() -> None:
    source = read(DB_SOURCE)
    coalesce = c_function(source, "static int notifyd_coalesce_outbox(")
    select_sql = sql_containing(coalesce, "SELECT id,CASE WHEN")
    update_sql = sql_containing(coalesce, "UPDATE notify_outbox SET updated_at")
    db = sqlite3.connect(":memory:")
    db.execute(
        """
        CREATE TABLE notify_outbox(
          id TEXT PRIMARY KEY, updated_at INTEGER, next_attempt_at INTEGER,
          channel_id TEXT, route_id TEXT, action_index INTEGER, event_id TEXT,
          severity TEXT, category TEXT, event TEXT, source TEXT, title TEXT,
          payload_json TEXT, state TEXT, attempts INTEGER, max_attempts INTEGER,
          last_seen INTEGER, count INTEGER, last_error TEXT, last_http_status INTEGER,
          last_warning TEXT,
          delivery_options_json TEXT, dedupe_group TEXT, dedupe_key TEXT,
          producer_dedupe_key TEXT, route_dedupe_key TEXT
        )
        """
    )
    rows = [
        ("producer", 900, 950, "email", "route", 0, "old", "warning", "WAN", "OLD", "src", "old", "{}", "delivered", 3, 3, 900, 1, "old_error", 500, "", "{}", "g", "producer-key", "producer-key", ""),
        ("route", 990, 995, "email", "route", 0, "old", "warning", "WAN", "OLD", "src", "old", "{}", "delivered", 1, 3, 990, 1, "", 0, "", "{}", "g", "", "", "route-key"),
    ]
    db.executemany("INSERT INTO notify_outbox VALUES(" + ",".join("?" for _ in range(26)) + ")", rows)

    candidate = db.execute(
        select_sql,
        ("email", "route", 0, "producer-key", "route-key", 950, "g"),
    ).fetchone()
    assert candidate == ("route", 2), "route-window match must win over producer match"
    db.execute(
        update_sql,
        (1000, candidate[1], "new", "error", "WAN", "NEW", "src", "new", '{"v":2}', 5, '{"receivers":{"mode":"admins"}}', "g", "producer-key", "producer-key", "route-key", candidate[0]),
    )
    route = db.execute(
        "SELECT state,attempts,next_attempt_at,count,payload_json FROM notify_outbox WHERE id='route'"
    ).fetchone()
    producer = db.execute(
        "SELECT state,attempts,count FROM notify_outbox WHERE id='producer'"
    ).fetchone()
    assert route == ("delivered", 1, 995, 2, '{"v":2}')
    assert producer == ("delivered", 3, 1), "only one candidate row may change"

    candidate = db.execute(
        select_sql,
        ("email", "route", 0, "producer-key", "expired-route-key", 950, "g"),
    ).fetchone()
    assert candidate == ("producer", 1)
    db.execute(
        update_sql,
        (1100, candidate[1], "newer", "critical", "WAN", "NEWER", "src", "newer", '{"v":3}', 5, "{}", "g", "producer-key", "producer-key", "", candidate[0]),
    )
    producer = db.execute(
        "SELECT state,attempts,next_attempt_at,count,last_error FROM notify_outbox WHERE id='producer'"
    ).fetchone()
    assert producer == ("pending", 0, 1100, 2, "")

    candidate = db.execute(
        select_sql,
        ("email", "route", 0, "", "route-key", 950, "different-family"),
    ).fetchone()
    assert candidate is None, "route dedupe must not cross recovery families"


def test_route_dedupe_keys_are_bounded_and_recovery_group_is_stable() -> None:
    source = read(DB_SOURCE)
    contract = c_function(source, "static int notifyd_route_dedupe_contract(")
    helper = c_function(source, "static uint64_t notifyd_route_dedupe_hash_part(")

    assert '"v1-%016" PRIx64' in contract
    assert '"g1-%016" PRIx64' in contract
    assert '"event_pair"' in contract
    assert 'definition->recovers_event' in contract
    assert 'definition->recovery_event' in contract
    assert 'pair_event = event' in contract
    assert 'strcmp(field, "severity")' in contract
    assert "1099511628211" in helper
    assert "idx_notify_outbox_route_action_dedupe" in source
    assert "dedupe_group,route_dedupe_key,last_seen" in source
    assert "idx_notify_outbox_producer_action_dedupe" in source


def test_migration_columns_and_action_queries_are_append_only() -> None:
    source = read(DB_SOURCE)
    delivery = read(DELIVERY_SOURCE)
    header = read(HEADER)
    for column in (
        "action_index",
        "dedupe_group",
        "delivery_options_json",
        "producer_dedupe_key",
        "route_dedupe_key",
        "last_warning",
    ):
        assert f"ALTER TABLE notify_outbox ADD COLUMN {column}" in source
    assert "ALTER TABLE notify_deliveries ADD COLUMN warning" in source
    assert "CREATE TABLE IF NOT EXISTS notify_route_suppressions" in source
    assert source.count("count,action_index,last_warning \"") >= 2
    assert "char delivery_options_json[NOTIFYD_MAX_JSON];" in header
    assert "int action_index;" in header
    assert 'json_object_object_add(resp, "action_index"' in delivery
    assert 'ok && error ? error : ""' in source
    assert 'ok ? "warning" : "error"' in delivery


def test_success_warning_and_failure_error_are_persisted_separately() -> None:
    source = read(DB_SOURCE)
    record = c_function(source, "int notifyd_delivery_record(")
    mark = c_function(source, "int notifyd_mark_delivery_result(")
    insert_sql = sql_containing(record, "INSERT INTO notify_deliveries")
    update_sql = sql_containing(mark, "UPDATE notify_outbox SET state=")
    db = sqlite3.connect(":memory:")
    db.execute(
        """
        CREATE TABLE notify_deliveries(
          id INTEGER PRIMARY KEY AUTOINCREMENT, outbox_id TEXT, channel_id TEXT,
          ts INTEGER, ok INTEGER, http_status INTEGER, error TEXT,
          duration_ms INTEGER, warning TEXT, outcome TEXT,
          suppressed_recipients INTEGER
        )
        """
    )
    db.execute(
        """
        CREATE TABLE notify_outbox(
          id TEXT PRIMARY KEY, state TEXT, attempts INTEGER,
          next_attempt_at INTEGER, updated_at INTEGER, last_error TEXT,
          last_http_status INTEGER, last_warning TEXT
        )
        """
    )
    db.execute(
        "INSERT INTO notify_outbox VALUES('item','pending',0,0,0,'stale',500,'stale-warning')"
    )

    warning = "delivered_with_resolution_warning:user_missing:0"
    db.execute(insert_sql, ("item", "email", 100, 1, 250, "", 5, warning, "delivered", 0))
    db.execute(update_sql, ("delivered", 1, 100, 100, "", 250, warning, "item"))
    assert db.execute(
        "SELECT error,warning FROM notify_deliveries WHERE id=1"
    ).fetchone() == ("", warning)
    assert db.execute(
        "SELECT state,last_error,last_warning FROM notify_outbox WHERE id='item'"
    ).fetchone() == ("delivered", "", warning)

    failure = "smtp_connect_failed"
    db.execute(insert_sql, ("item", "email", 200, 0, 0, failure, 7, "", "failed", 0))
    db.execute(update_sql, ("retry", 2, 260, 200, failure, 0, "", "item"))
    assert db.execute(
        "SELECT error,warning FROM notify_deliveries WHERE id=2"
    ).fetchone() == (failure, "")
    assert db.execute(
        "SELECT state,last_error,last_warning FROM notify_outbox WHERE id='item'"
    ).fetchone() == ("retry", failure, "")

    # A user's own mute is a third outcome, not a quiet failure: it keeps ok=1
    # so status does not read it as a delivery fault, and the detail stays in
    # `warning` because `last_error` is what drives the degraded verdict.
    suppressed = "preference_suppressed_all_recipients:1"
    db.execute(insert_sql, ("item", "email", 300, 1, 0, "", 3, suppressed,
                            "suppressed", 1))
    db.execute(update_sql, ("suppressed", 2, 300, 300, "", 0, suppressed, "item"))
    assert db.execute(
        "SELECT ok,outcome,suppressed_recipients,error,warning "
        "FROM notify_deliveries WHERE id=3"
    ).fetchone() == (1, "suppressed", 1, "", suppressed)
    assert db.execute(
        "SELECT state,last_error,last_warning FROM notify_outbox WHERE id='item'"
    ).fetchone() == ("suppressed", "", suppressed)


def test_pending_p1_catalog_entries_remain_unavailable() -> None:
    source = read(DB_SOURCE)
    pending = (
        "VPN_SITE_TO_SITE_DISCONNECTED",
        "VPN_SITE_TO_SITE_RESTORED",
        "CONFIG_COMMIT_FAILED",
        "IMPROPER_SHUTDOWN",
    )
    for event in pending:
        row = re.search(rf'\{{\s*"{event}"[^\n]+\}}', source)
        assert row, f"catalog row missing: {event}"
        assert row.group(0).rstrip().endswith("0 }"), f"{event} must remain unavailable"


def test_structured_p1_producers_are_available_only_for_real_sources() -> None:
    source = read(DB_SOURCE)
    expected = {
        "DEVICE_OFFLINE": "dreamingwrt-core.topology_history",
        "DEVICE_RESTORED": "dreamingwrt-core.topology_history",
        "PORT_TX_RX_ERRORS": "dreamingwrt.logd.collector.port",
        "PORT_DROPPED_TRAFFIC": "dreamingwrt.logd.collector.port",
        "CLIENT_IP_CONFLICT": "dreamingwrt-core.ipam",
        "SECURITY_DETECTION": "dreamingwrt.aegisxd.suricata",
        "APPLICATION_UPDATE_FAILED": "dreamingwrt.otad",
    }
    for event, producer in expected.items():
        row = re.search(rf'\{{\s*"{event}"[^\n]+\}}', source)
        assert row, f"catalog row missing: {event}"
        assert f'"{producer}"' in row.group(0)
        assert row.group(0).rstrip().endswith("1 }")


if __name__ == "__main__":
    for test in (
        test_capability_manifest_and_v1_defaults_are_explicit,
        test_schema_validation_has_stable_codes_and_atomic_revision_save,
        test_schedule_suppression_and_multi_action_diagnostics_are_exposed,
        test_receiver_delivery_is_dynamic_and_warning_safe,
        test_route_and_producer_dedupe_sql_behave_differently,
        test_route_dedupe_keys_are_bounded_and_recovery_group_is_stable,
        test_migration_columns_and_action_queries_are_append_only,
        test_success_warning_and_failure_error_are_persisted_separately,
        test_pending_p1_catalog_entries_remain_unavailable,
        test_structured_p1_producers_are_available_only_for_real_sources,
    ):
        test()
    print("ok - notifyd route capability contracts passed")

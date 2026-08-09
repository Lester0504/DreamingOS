#!/usr/bin/env python3
import copy
import json
import re
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROUTE_EVENT = ROOT / "src" / "routed" / "jmx_route.c"
NETCONFIG_DB = ROOT / "src" / "jmx_netconfig_db.c"
LOGD_EVENT = ROOT / "src" / "logd" / "logd_event.c"
LOGD_UBUS = ROOT / "src" / "logd" / "logd_ubus.c"
NOTIFYD_DB = ROOT / "src" / "notifyd" / "notifyd_db.c"
NOTIFYD_UBUS = ROOT / "src" / "notifyd" / "notifyd_ubus.c"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def c_function(source: str, marker: str) -> str:
    """Return one C function while ignoring braces in strings and comments."""
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
        elif ch in ('"', "'"):
            quote = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[start : i + 1]
        i += 1
    raise AssertionError(f"unterminated C function: {marker}")


def catalog_event_rows(notifyd: str) -> list:
    """Rows of notifyd_event_definitions[] only.

    Scoped to that one initializer on purpose: the file also holds a category
    table whose rows look like `{ "SYSTEM", "System" },`, and a plain
    startswith('{ "') scan swallows those too, which is part of how the old
    hardcoded totals drifted without anyone noticing what they counted.
    """
    lines = notifyd.splitlines()
    start = next(
        i for i, line in enumerate(lines)
        if "notifyd_event_definitions[] = {" in line
    )
    rows = []
    for line in lines[start + 1:]:
        stripped = line.strip()
        if stripped.startswith("};"):
            break
        if not (stripped.startswith('{ "') and stripped.endswith("},")):
            continue
        fields = re.findall(r'"([^"]*)"', stripped)
        available = re.search(r",\s*(\d+)\s*\},$", stripped)
        assert available, f"unparsable catalog row: {stripped}"
        assert len(fields) == 8, f"unexpected field count in catalog row: {stripped}"
        rows.append(fields + [available.group(1)])
    assert rows, "notifyd_event_definitions[] parsed as empty"
    return rows


def test_route_health_source_reaches_logd_and_notifyd_contracts():
    route = read(ROUTE_EVENT)
    netconfig = read(NETCONFIG_DB)
    logd_event = read(LOGD_EVENT)
    logd_ubus = read(LOGD_UBUS)
    notifyd_db = read(NOTIFYD_DB)
    notifyd_ubus = read(NOTIFYD_UBUS)

    emitter = c_function(route, "static int route_health_event_emit(")
    for field, value in {
        "category": "network.wan",
        "module": "dreamingwrt-routed",
        "source": "routed.health",
    }.items():
        assert f'json_object_object_add(o, "{field}", json_object_new_string("{value}"));' in emitter
    for field in ("id", "level", "iface", "title", "event", "detail", "state", "target", "ts"):
        assert f'json_object_object_add(o, "{field}"' in emitter
    assert "wan=%s ifname=%s target=%s reason=%s fail_count=%u ok_count=%u" in emitter
    assert 'json_object_object_add(o, "target", json_object_new_string(st->name));' in emitter
    assert "resp = jmx_log_center_event_add(o);" in emitter
    assert "return 0;" in emitter
    assert 'route_health_event_emit(st, "warning", "wan.failover.down"' in route
    assert 'route_health_event_emit(st, "notice", "wan.failover.recovered"' in route

    store = c_function(netconfig, "static int nc_log_center_event_store(")
    assert store.count("nc_log_event_insert_obj(event)") == 1
    assert store.count("nc_logd_bridge_event(event") == 1
    assert store.index("nc_log_event_insert_obj(event)") < store.index("nc_logd_bridge_event(event")
    assert "return 0;" in store
    bridge = c_function(netconfig, "static int nc_logd_bridge_event(")
    assert "#define NC_LOGD_BRIDGE_TIMEOUT_MS 750" in netconfig
    assert 'ubus_connect("/var/run/ubus/ubus.sock")' in bridge
    assert 'ubus_connect("/var/run/ubus.sock")' in bridge
    assert 'ubus_lookup_id(ctx, "dreamingwrt.logd"' in bridge
    assert 'ubus_invoke(ctx, object_id, "event_add"' in bridge
    assert bridge.count("ubus_invoke(") == 1
    assert "NC_LOGD_BRIDGE_TIMEOUT_MS" in bridge
    payload = c_function(netconfig, "static struct json_object *nc_logd_bridge_payload(")
    metadata = c_function(netconfig, "static void nc_logd_bridge_add_metadata(")
    assert '"detail_json"' in payload and '"severity"' in payload
    assert '"legacy_bridge"' in payload
    assert '"network.wan"' in metadata and '"routed.health"' in metadata
    assert 'nc_json_str_def(event, "target", "")' in metadata
    assert 'json_object_object_add(event, "wan_id"' in metadata
    assert "sscanf" not in metadata and "strtok" not in metadata

    event_add = c_function(netconfig, "struct json_object *jmx_log_center_event_add(")
    assert '"bridged"' in event_add and '"bridge_failed"' in event_add
    assert "failed ? API_CODE_ERROR : API_CODE_SUCCESS" in event_add
    assert "bridge_failed ? API_CODE_ERROR" not in event_add

    logd_handler = c_function(logd_ubus, "static int logd_handle_event_add(")
    assert "logd_add_event(logd_payload_or_self(body))" in logd_handler
    assert 'UBUS_METHOD("event_add", logd_handle_event_add' in logd_ubus
    assert '{ "network.wan", "wan.failover.down", "WAN_FAILOVER_ACTIVE"' in logd_event
    assert '{ "network.wan", "wan.failover.recovered", "WAN_FAILBACK"' in logd_event
    replace_string = c_function(logd_event, "static void logd_json_replace_string(")
    assert replace_string.index("json_object_new_string(") < replace_string.index("json_object_object_del(")
    logd_add = c_function(logd_event, "struct json_object *logd_add_event(")
    assert "logd_notify_contract_find(raw_category, raw_event, event_code)" in logd_add
    assert "logd_clear_recovered_events(dedupe_key, id, notify_contract)" in logd_add
    assert "logd_notifyd_enqueue(notify_body ? notify_body : body)" in logd_add

    notify_handler = c_function(notifyd_ubus, "static int notifyd_handle_enqueue(")
    assert "notifyd_enqueue_event(notifyd_payload_or_self(body))" in notify_handler
    enqueue = c_function(notifyd_db, "struct json_object *notifyd_enqueue_event(")
    assert "notifyd_insert_outbox(" in enqueue
    assert "notifyd_coalesce_outbox(" in notifyd_db

    for path in (ROOT / "src" / "logd").glob("*.c"):
        assert "jmx_log_center_event_add(" not in read(path), f"recursive legacy write in {path.name}"


def test_catalog_available_matches_real_producer_contracts():
    logd = read(LOGD_EVENT)
    notifyd = read(NOTIFYD_DB)
    expected = {
        "WAN_FAILOVER_ACTIVE": "dreamingwrt.routed.health",
        "WAN_FAILBACK": "dreamingwrt.routed.health",
        "PORT_LINK_DOWN": "dreamingwrt.logd.collector.port",
        "PORT_LINK_UP": "dreamingwrt.logd.collector.port",
    }
    for event_code, producer in expected.items():
        assert f'"{event_code}"' in logd
        assert f'"{producer}"' in logd
        line = next(line for line in notifyd.splitlines() if f'{{ "{event_code}",' in line)
        assert f'"{producer}"' in line
        assert line.rstrip().endswith("1 },")
        assert "producer_pending" not in line


def test_pending_events_stay_unavailable_without_true_source():
    notifyd = read(NOTIFYD_DB)
    pending = {
        "SECURITY_DETECTION": "aegis_suricata_event_bridge_pending",
        "APPLICATION_UPDATE_FAILED": "otad_failure_event_producer_pending",
    }
    for event_code, reason in pending.items():
        line = next(line for line in notifyd.splitlines() if f'{{ "{event_code}",' in line)
        assert f'"{reason}"' in line
        assert line.rstrip().endswith("0 },")
    """
    WAN_DOWN used to sit in `pending` above with
    reason="confirmed_wan_reachability_producer_pending". It has a real producer
    now, so the assertion was inverted: see dw_emit_connectivity_transition_event()
    in src/jmx_dreamingwrt_api.c, which enqueues WAN_DOWN / WAN_RESTORED into
    notifyd off healthd's debounced reachability edge (healthd probes ping then
    TCP:443 every 30 s and only flips `internet` to 0 after 3 consecutive
    failures -- check_internet_connectivity() in src/healthd/check_main.c).
    Assert the availability positively so a regression back to unavailable, or a
    producer rename, still fails here.
    """
    for event_code in ("WAN_DOWN", "WAN_RESTORED"):
        line = next(line for line in notifyd.splitlines() if f'{{ "{event_code}",' in line)
        assert '"dreamingwrt-core"' in line
        assert "producer_pending" not in line
        assert line.rstrip().endswith("1 },")

    """
    This used to assert bare totals (18 available / 17 unavailable). The catalog
    has grown to 53 events since, so the numbers only recorded a moment in time
    and went red on every legitimate addition. Assert the invariant that actually
    matters instead: `available` must agree with whether a producer exists, so no
    row can claim an event will arrive while naming nobody to send it, and none
    can be parked as pending without saying what is missing.
    """
    definitions = catalog_event_rows(notifyd)
    assert len(definitions) > 40
    for row in definitions:
        event_code, producer, reason, available = (
            row[0], row[3], row[6], row[-1],
        )
        if available == "1":
            assert producer, f"{event_code} is available with no producer"
            assert not reason, f"{event_code} is available but still carries reason {reason!r}"
        else:
            assert not producer, f"{event_code} is unavailable yet names producer {producer!r}"
            assert reason, f"{event_code} is unavailable without saying what is missing"


def route_health_body(event: str, level: str, title: str, state: str, ts: int) -> dict:
    wan = "wan1"
    iface = "pppoe-wan"
    probe_target = "1.1.1.1"
    reason = "probe_failed" if event == "wan.failover.down" else "probe_ok"
    fail_count = 3 if event == "wan.failover.down" else 0
    ok_count = 0 if event == "wan.failover.down" else 2
    return {
        "id": f"route-wan-7-{state}-{ts}",
        "type": "system",
        "level": level,
        "category": "network.wan",
        "module": "dreamingwrt-routed",
        "source": "routed.health",
        "iface": iface,
        "title": title,
        "event": event,
        "detail": (
            f"wan={wan} ifname={iface} target={probe_target} reason={reason} "
            f"fail_count={fail_count} ok_count={ok_count}"
        ),
        "state": state,
        "target": wan,
        "ts": ts,
    }


def bridge_payload(event: dict) -> dict:
    payload = copy.deepcopy(event)
    detail = payload.get("detail_json")
    if not isinstance(detail, dict):
        detail = {}
    detail.setdefault("text", payload.get("detail", ""))
    wan_id = payload.get("wan_id", "")
    if not wan_id and payload.get("category") == "network.wan" and payload.get("source") == "routed.health":
        wan_id = payload.get("target", "")
    metadata = detail.setdefault("source_metadata", {})
    metadata.update(
        {
            "source": payload.get("source", ""),
            "module": payload.get("module", ""),
            "iface": payload.get("iface", ""),
            "target": payload.get("target", ""),
            "wan_id": wan_id,
            "legacy_event_id": payload.get("id", ""),
            "bridge": "jmx_log_center_event_add",
        }
    )
    if wan_id:
        payload["wan_id"] = wan_id
        detail["wan_id"] = wan_id
    payload["detail_json"] = detail
    payload["severity"] = payload.get("severity", payload.get("level", "info"))
    payload["legacy_bridge"] = "jmx_log_center_event_add"
    return payload


CONTRACTS = {
    ("network.wan", "wan.failover.down"): {
        "event_code": "WAN_FAILOVER_ACTIVE",
        "severity": "warning",
        "recovery_event": "WAN_FAILBACK",
        "recovers_event": "",
    },
    ("network.wan", "wan.failover.recovered"): {
        "event_code": "WAN_FAILBACK",
        "severity": "notice",
        "recovery_event": "WAN_FAILOVER_ACTIVE",
        "recovers_event": "WAN_FAILOVER_ACTIVE",
    },
}
SEVERITY_RANK = {"info": 1, "notice": 2, "warning": 3, "error": 4, "critical": 5}


def normalize_logd_contract(payload: dict) -> tuple[dict, dict]:
    source_category = payload["category"]
    source_event = payload["event"]
    contract = CONTRACTS[(source_category, source_event)]
    normalized = copy.deepcopy(payload)
    severity = normalized.get("severity", "info")
    if SEVERITY_RANK.get(severity, 1) < SEVERITY_RANK[contract["severity"]]:
        severity = contract["severity"]
    wan_id = normalized.get("wan_id") or normalized.get("iface") or normalized.get("target") or "unknown"
    detail = normalized["detail_json"]
    detail.update(
        {
            "event_code": contract["event_code"],
            "producer": "dreamingwrt.routed.health",
            "source_category": source_category,
            "source_event": source_event,
            "recovery_event": contract["recovery_event"],
        }
    )
    if contract["recovers_event"]:
        detail["recovers_event"] = contract["recovers_event"]
    detail["source_metadata"].update(
        {
            "source": normalized.get("source", ""),
            "iface": normalized.get("iface", ""),
            "wan_id": wan_id,
            "ip": normalized.get("ip", ""),
            "mac": normalized.get("mac", ""),
        }
    )
    normalized.update(
        {
            "category": "INTERNET_AND_WAN",
            "event": contract["event_code"],
            "event_code": contract["event_code"],
            "producer": "dreamingwrt.routed.health",
            "severity": severity,
            "dedupe_key": f"wan_failover:{wan_id}",
            "source_category": source_category,
            "source_event": source_event,
            "recovery_event": contract["recovery_event"],
        }
    )
    if contract["recovers_event"]:
        normalized["recovers_event"] = contract["recovers_event"]
    return normalized, contract


def fixture_db() -> sqlite3.Connection:
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript(
        """
        CREATE TABLE legacy_log_event(
            id TEXT PRIMARY KEY, category TEXT, event TEXT, level TEXT, source TEXT,
            iface TEXT, target TEXT, detail TEXT, state TEXT
        );
        CREATE TABLE log_events(
            id TEXT PRIMARY KEY, ts INTEGER, severity TEXT, category TEXT, event TEXT,
            source TEXT, iface TEXT, wan_id TEXT, title TEXT, detail_json TEXT,
            dedupe_key TEXT, state TEXT, first_seen INTEGER, last_seen INTEGER,
            count INTEGER DEFAULT 1
        );
        CREATE TABLE notify_outbox(
            id TEXT PRIMARY KEY, channel_id TEXT, route_id TEXT, event_id TEXT,
            severity TEXT, category TEXT, event TEXT, source TEXT, title TEXT,
            payload_json TEXT, state TEXT DEFAULT 'pending', dedupe_key TEXT,
            first_seen INTEGER, last_seen INTEGER, count INTEGER DEFAULT 1
        );
        CREATE TABLE notifyd_routes(
            id TEXT PRIMARY KEY, enabled INTEGER, channel_id TEXT,
            min_severity TEXT, category TEXT, event TEXT, source TEXT
        );
        INSERT INTO notifyd_routes VALUES(
            'wan-health',1,'local','notice','INTERNET_AND_WAN','','routed.health'
        );
        """
    )
    return db


def notify_enqueue(db: sqlite3.Connection, body: dict) -> None:
    now = body["ts"]
    routes = db.execute(
        "SELECT id,channel_id,min_severity,category,event,source "
        "FROM notifyd_routes WHERE enabled=1 ORDER BY id"
    ).fetchall()
    for route in routes:
        if SEVERITY_RANK[body["severity"]] < SEVERITY_RANK[route["min_severity"]]:
            continue
        if route["category"] and route["category"] != body["category"]:
            continue
        if route["event"] and route["event"] != body["event"]:
            continue
        if route["source"] and route["source"] != body["source"]:
            continue
        changed = db.execute(
            "UPDATE notify_outbox SET event_id=?,severity=?,category=?,event=?,source=?,title=?,"
            "payload_json=?,state='pending',last_seen=?,count=count+1 "
            "WHERE channel_id=? AND route_id=? AND dedupe_key=?",
            (
                body["id"], body["severity"], body["category"], body["event"],
                body["source"], body["title"], json.dumps(body, sort_keys=True), now,
                route["channel_id"], route["id"], body["dedupe_key"],
            ),
        ).rowcount
        if not changed:
            db.execute(
                "INSERT INTO notify_outbox VALUES(?,?,?,?,?,?,?,?,?,?,'pending',?,?,?,1)",
                (
                    f"ntf-{route['id']}-{body['event']}", route["channel_id"],
                    route["id"], body["id"], body["severity"], body["category"],
                    body["event"], body["source"], body["title"],
                    json.dumps(body, sort_keys=True), body["dedupe_key"], now, now,
                ),
            )


def logd_add_fixture(db: sqlite3.Connection, bridged: dict) -> dict:
    body, contract = normalize_logd_contract(bridged)
    now = body["ts"]
    existing = db.execute(
        "SELECT id,severity FROM log_events WHERE dedupe_key=? AND category=? AND event=? AND state!='cleared'",
        (body["dedupe_key"], body["category"], body["event"]),
    ).fetchone()
    deduped = existing is not None
    escalated = bool(existing and SEVERITY_RANK[body["severity"]] > SEVERITY_RANK[existing["severity"]])
    if existing:
        event_id = existing["id"]
        db.execute(
            "UPDATE log_events SET ts=?,severity=?,title=?,detail_json=?,last_seen=?,"
            "count=count+1,state='active' WHERE id=?",
            (now, body["severity"], body["title"], json.dumps(body["detail_json"], sort_keys=True), now, event_id),
        )
    else:
        event_id = f"evt-{body['event']}-{now}"
        db.execute(
            "INSERT INTO log_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
            (
                event_id, now, body["severity"], body["category"], body["event"],
                body["source"], body["iface"], body["wan_id"], body["title"],
                json.dumps(body["detail_json"], sort_keys=True), body["dedupe_key"],
                body.get("state", "active"), now, now,
            ),
        )
    recovered = 0
    if contract["recovers_event"]:
        recovered = db.execute(
            "UPDATE log_events SET state='cleared',last_seen=? WHERE dedupe_key=? "
            "AND id!=? AND event=? AND state!='cleared'",
            (now, body["dedupe_key"], event_id, contract["recovers_event"]),
        ).rowcount
    body["id"] = event_id
    if not deduped or escalated or recovered:
        notify_enqueue(db, body)
    return {"deduplicated": deduped, "recovered_count": recovered, "body": body}


def legacy_add_fixture(db: sqlite3.Connection, event: dict, bridge_ok: bool = True) -> dict:
    db.execute(
        "INSERT OR REPLACE INTO legacy_log_event VALUES(?,?,?,?,?,?,?,?,?)",
        (
            event["id"], event["category"], event["event"], event["level"],
            event["source"], event["iface"], event["target"], event["detail"], event["state"],
        ),
    )
    result = {"code": 2000, "inserted": 1, "failed": 0, "bridged": 0, "bridge_failed": 0}
    if bridge_ok:
        result["bridged"] = 1
        result["logd"] = logd_add_fixture(db, bridge_payload(event))
    else:
        result["bridge_failed"] = 1
        result["bridge_error"] = "ubus_timeout"
    return result


def test_route_health_end_to_end_sqlite_fixture():
    db = fixture_db()
    down = route_health_body(
        "wan.failover.down", "warning", "WAN removed from route group", "active", 1_700_000_100
    )
    first = legacy_add_fixture(db, down)
    duplicate = legacy_add_fixture(db, down)
    assert first["code"] == 2000 and first["bridged"] == 1
    assert duplicate["logd"]["deduplicated"] is True
    assert db.execute("SELECT COUNT(*) FROM legacy_log_event").fetchone()[0] == 1
    assert tuple(db.execute(
        "SELECT COUNT(*),MAX(count),MAX(state) FROM log_events WHERE event='WAN_FAILOVER_ACTIVE'"
    ).fetchone()) == (1, 2, "active")
    assert tuple(db.execute(
        "SELECT COUNT(*),MAX(count),MAX(event) FROM notify_outbox WHERE dedupe_key='wan_failover:wan1'"
    ).fetchone()) == (1, 1, "WAN_FAILOVER_ACTIVE")

    bridged = first["logd"]["body"]
    detail = bridged["detail_json"]
    assert bridged["event_code"] == "WAN_FAILOVER_ACTIVE"
    assert bridged["severity"] == "warning"
    assert bridged["producer"] == "dreamingwrt.routed.health"
    assert bridged["dedupe_key"] == "wan_failover:wan1"
    assert detail["text"] == down["detail"]
    assert detail["source_metadata"] == {
        "source": "routed.health",
        "module": "dreamingwrt-routed",
        "iface": "pppoe-wan",
        "target": "wan1",
        "wan_id": "wan1",
        "legacy_event_id": down["id"],
        "bridge": "jmx_log_center_event_add",
        "ip": "",
        "mac": "",
    }

    recovered = route_health_body(
        "wan.failover.recovered", "notice", "WAN recovered and returned to route group",
        "completed", 1_700_000_200,
    )
    recovery = legacy_add_fixture(db, recovered)
    assert recovery["logd"]["recovered_count"] == 1
    assert db.execute(
        "SELECT state FROM log_events WHERE event='WAN_FAILOVER_ACTIVE'"
    ).fetchone()[0] == "cleared"
    assert db.execute(
        "SELECT state FROM log_events WHERE event='WAN_FAILBACK'"
    ).fetchone()[0] == "completed"
    assert tuple(db.execute(
        "SELECT event,count FROM notify_outbox WHERE dedupe_key='wan_failover:wan1'"
    ).fetchone()) == ("WAN_FAILBACK", 2)
    recovery_payload = json.loads(
        db.execute("SELECT payload_json FROM notify_outbox").fetchone()[0]
    )
    assert recovery_payload["recovers_event"] == "WAN_FAILOVER_ACTIVE"
    assert recovery_payload["detail_json"]["source_metadata"]["target"] == "wan1"


def test_bridge_failure_does_not_rollback_legacy_insert():
    db = fixture_db()
    event = route_health_body(
        "wan.failover.down", "warning", "WAN removed from route group", "active", 1_700_000_300
    )
    result = legacy_add_fixture(db, event, bridge_ok=False)
    assert result == {
        "code": 2000,
        "inserted": 1,
        "failed": 0,
        "bridged": 0,
        "bridge_failed": 1,
        "bridge_error": "ubus_timeout",
    }
    assert db.execute("SELECT COUNT(*) FROM legacy_log_event").fetchone()[0] == 1
    assert db.execute("SELECT COUNT(*) FROM log_events").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM notify_outbox").fetchone()[0] == 0


if __name__ == "__main__":
    for test in (
        test_route_health_source_reaches_logd_and_notifyd_contracts,
        test_catalog_available_matches_real_producer_contracts,
        test_pending_events_stay_unavailable_without_true_source,
        test_route_health_end_to_end_sqlite_fixture,
        test_bridge_failure_does_not_rollback_legacy_insert,
    ):
        test()
    print("ok - route health -> legacy bridge -> logd -> notifyd fixtures passed")

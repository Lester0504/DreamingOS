#!/usr/bin/env python3
"""Contract tests for the recovery-event exemption from route min_severity.

Covers `HandoffWorker-to-Backend-notifyd-single-route-drops-23-of-53-events.md`:
the only factory route is `default-warning` (min_severity=warning), and
`notifyd_route_matches()` compared severity before anything else, so an alarm
passed while the event that clears it did not. `WAN_DOWN` is warning and was
delivered; `WAN_RESTORED` is notice and was dropped inside the router, leaving
the user with an alarm nothing could clear.

These tests read the catalog table and the two severity gates out of the C
source. That is deliberate: the drop happened at the enqueue decision, so the
table and both gates are the contract worth pinning.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NOTIFYD_DB = ROOT / "src" / "notifyd" / "notifyd_db.c"
EVENT_SEMANTICS = ROOT / "src" / "event_semantics.c"
LOGD_EVENT = ROOT / "src" / "logd" / "logd_event.c"

SEVERITY_RANK = {
    "debug": 0,
    "info": 1,
    "notice": 2,
    "warning": 3,
    "error": 4,
    "critical": 5,
}

# Field order in DW_EVENT() inside event_semantics.c.
ROW = re.compile(
    r'DW_EVENT\(\s*"(?P<id>[A-Z0-9_]+)",\s*"(?P<category>[A-Z_]+)",\s*"(?P<label>[^"]*)",'
    r'\s*"(?P<label_zh>[^"]*)",\s*"(?P<producer>[^"]*)",\s*"(?P<recovery>[A-Z0-9_]*)",'
    r'\s*"(?P<recovers>[A-Z0-9_]*)",\s*"(?P<reason>[^"]*)",\s*"(?P<severity>[a-z]+)",'
    r'\s*"[^"]*",\s*(?P<available>[01])\s*\)'
)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def catalog() -> dict:
    source = read(EVENT_SEMANTICS)
    rows = [m.groupdict() for m in ROW.finditer(source)]
    assert rows, "catalog table did not parse"
    return {r["id"]: r for r in rows}


def test_every_catalog_row_parses_with_the_recovers_event_field():
    """A row that silently fails to parse would make the rest vacuously pass."""
    source = read(EVENT_SEMANTICS)
    declared = len(re.findall(r'^\s*DW_EVENT\(', source, re.M))
    parsed = len(ROW.findall(source))
    assert declared == parsed, (
        f"{declared} rows declared but only {parsed} parsed with the shared "
        "DW_EVENT shape; a row is missing recovery metadata"
    )
    assert "const char *recovers_event;" in read(ROOT / "src" / "event_semantics.h")


def test_recovery_events_are_marked_and_are_the_clearing_half():
    """recovers_event must name the alarm, never the event itself."""
    events = catalog()
    recoveries = {k: v for k, v in events.items() if v["recovers"]}

    assert recoveries, "no recovery events marked"
    for event_id, row in recoveries.items():
        alarm = row["recovers"]
        assert alarm in events, f"{event_id} recovers unknown event {alarm}"
        assert alarm != event_id, f"{event_id} cannot recover itself"
        # The pair must agree: the alarm points back via recovery_event.
        assert events[alarm]["recovery"] == event_id, (
            f"{alarm}.recovery_event should be {event_id}, "
            f"got {events[alarm]['recovery']!r}"
        )
        # An alarm must not also be a recovery; that would exempt both halves.
        assert not events[alarm]["recovers"], (
            f"{alarm} is marked as both alarm and recovery"
        )


def test_wan_restored_is_exempt_and_would_otherwise_be_dropped():
    """The exact reported symptom: WAN_DOWN arrives, WAN_RESTORED never does."""
    events = catalog()
    down, restored = events["WAN_DOWN"], events["WAN_RESTORED"]
    factory_floor = SEVERITY_RANK["warning"]

    # The asymmetry that caused the bug must still be real, otherwise this
    # test would pass for the wrong reason.
    assert SEVERITY_RANK[down["severity"]] >= factory_floor
    assert SEVERITY_RANK[restored["severity"]] < factory_floor

    assert restored["recovers"] == "WAN_DOWN"
    assert down["recovery"] == "WAN_RESTORED"


def test_low_severity_non_recovery_events_are_not_exempted():
    """The exemption must not become a blanket threshold drop."""
    events = catalog()
    floor = SEVERITY_RANK["warning"]

    for event_id in ("SYSTEM_LOG", "DHCP_EVENT", "WAN_EVENT", "PORT_EVENT"):
        row = events[event_id]
        assert SEVERITY_RANK[row["severity"]] < floor
        assert not row["recovers"], (
            f"{event_id} is ordinary low-severity traffic and must stay filtered"
        )

    exempt = [e for e, r in events.items() if r["recovers"]]
    below = [e for e, r in events.items() if SEVERITY_RANK[r["severity"]] < floor]
    assert len(exempt) < len(below), (
        "exemption should cover only the recovery subset of sub-warning events"
    )


def test_both_severity_gates_apply_the_exemption():
    """notifyd_route_matches and the default-channel fallback must agree.

    The fallback fires when no route matched at all, so leaving it unpatched
    reintroduces the drop whenever routes are disabled or scoped elsewhere.
    """
    source = read(NOTIFYD_DB)

    assert "static int notifyd_event_is_recovery(" in source
    gates = source.count("notifyd_event_is_recovery(")
    # one definition + two call sites
    assert gates >= 3, f"expected the exemption at both gates, found {gates - 1}"

    enqueue = source.index("struct json_object *notifyd_enqueue_event(")
    body = source[enqueue:source.index("struct json_object *notifyd_enqueue_direct(", enqueue)]
    assert "notifyd_event_is_recovery(notifyd_json_str(body, \"event\", \"\"))" in body

    fallback = source.index("if (!matched_routes && !suppressed && s.default_channel_id[0]")
    assert "notifyd_event_is_recovery(" in source[fallback:fallback + 500]


def test_catalog_exposes_recovery_metadata_to_clients():
    """The frontend must be able to show which events ignore the threshold."""
    source = read(NOTIFYD_DB)
    assert '"recovers_event"' in source
    assert '"severity_exempt"' in source


def test_notifyd_recovery_pairs_agree_with_logd_contracts():
    """Every logd alarm must point to the same recovery family in notifyd.

    A single recovery event may clear several alarm variants, so notifyd's
    scalar recovers_event names the representative clearing half while each
    alarm's recovery_event supplies the complete many-to-one relationship.
    """
    events = catalog()
    recovery_codes = {e for e, row in events.items() if row["recovers"]}
    assert recovery_codes, "no recovery events marked in the shared catalog"
    for code in recovery_codes:
        alarm = events[code]["recovers"]
        assert code in events
        assert alarm in events
        assert events[alarm]["recovery"] == code
    logd = read(LOGD_EVENT)
    start = logd.index("static const struct logd_notify_event_contract logd_notify_event_contracts[]")
    end = logd.index("logd_notify_contract_find", start)
    block = logd[start:end]
    codes = set(re.findall(r'\{\s*"[^"]+",\s*"[^"]+",\s*"([A-Z0-9_]+)"\s*\}', block))
    assert codes, "no logd contracts parsed"
    missing = sorted(codes - set(events))
    assert not missing, f"logd emits events absent from the shared catalog: {missing}"


if __name__ == "__main__":
    for test in (
        test_every_catalog_row_parses_with_the_recovers_event_field,
        test_recovery_events_are_marked_and_are_the_clearing_half,
        test_wan_restored_is_exempt_and_would_otherwise_be_dropped,
        test_low_severity_non_recovery_events_are_not_exempted,
        test_both_severity_gates_apply_the_exemption,
        test_catalog_exposes_recovery_metadata_to_clients,
        test_notifyd_recovery_pairs_agree_with_logd_contracts,
    ):
        test()
    print("ok - notifyd recovery severity exemption contracts passed")

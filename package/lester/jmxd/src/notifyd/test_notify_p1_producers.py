#!/usr/bin/env python3
"""Contract fixtures for the structured P1 notification producers.

These tests deliberately pin the producer-to-logd-to-notifyd source contracts
and the state-edge rules. They do not infer events from ordinary log text.
"""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOPOLOGY = ROOT / "src" / "jmx_topology_history.c"
COLLECTORS = ROOT / "src" / "logd" / "logd_collectors.c"
LOGD_EVENT = ROOT / "src" / "logd" / "logd_event.c"
NETCONFIG = ROOT / "src" / "jmx_netconfig_db.c"
NOTIFYD = ROOT / "src" / "notifyd" / "notifyd_db.c"
AEGIS_HITS = ROOT / "src" / "aegisxd" / "aegisxd_hits.c"
OTAD_DB = ROOT / "src" / "otad" / "otad_db.c"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def function(source: str, marker: str) -> str:
    start = source.index(marker)
    brace = source.index("{", start)
    depth = 0
    quote = ""
    escaped = False
    line_comment = False
    block_comment = False
    for i in range(brace, len(source)):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if line_comment:
            if ch == "\n":
                line_comment = False
        elif block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
        elif quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
        elif ch == "/" and nxt == "/":
            line_comment = True
        elif ch == "/" and nxt == "*":
            block_comment = True
        elif ch in ('"', "'"):
            quote = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[start : i + 1]
    raise AssertionError(f"unterminated function: {marker}")


def test_topology_producer_uses_infrastructure_groups_and_excludes_clients():
    source = read(TOPOLOGY)
    diff = function(source, "static int jth_diff_devices(")
    assert '"gateways", "switches", "aps", "clients"' in diff
    assert "i < 3, notifications" in diff
    assert "jth_queue_device_notification" in source
    queue = function(source, "static void jth_queue_device_notification(")
    for field in ("node_id", "device_group", "mac", "name", "before_online", "online", "transition"):
        assert f'"{field}"' in queue
    assert '"device_offline"' in queue
    assert '"device_restored"' in queue


def test_topology_notification_dispatch_happens_after_commit():
    source = read(TOPOLOGY)
    capture = function(source, "int jmx_topology_history_capture(")
    assert capture.index('jth_exec("COMMIT")') < capture.index("jth_dispatch_notifications(")
    assert "notification_bridge_failed" in capture


def test_port_counter_fixture_has_baseline_reset_and_structured_deltas():
    source = read(COLLECTORS)
    helper = function(source, "static int logd_port_counter_delta(")
    collect = function(source, "static int logd_collect_ports(")
    for field in ("rx_errors", "tx_errors", "rx_dropped", "tx_dropped"):
        assert f'"{field}"' in collect
    for field in ("rx_error_delta", "tx_error_delta", "rx_drop_delta", "tx_drop_delta"):
        assert f'"{field}"' in collect or field in helper
    assert "!ps->counters_valid" in helper
    assert "rx_errors < ps->rx_errors" in helper
    assert "tx_dropped < ps->tx_dropped" in helper
    assert "counter_errors" in collect and "counter_drops" in collect
    assert "error_delta_warn" in source and "drop_delta_warn" in source
    assert "if (!dir)" in collect and "json_object_put(opts)" in collect


def test_logd_contracts_and_notifyd_catalog_match_five_real_p1_sources():
    logd = read(LOGD_EVENT)
    notifyd = read(NOTIFYD)
    contracts = {
        ("port", "counter_errors"): ("PORT_TX_RX_ERRORS", "dreamingwrt.logd.collector.port"),
        ("port", "counter_drops"): ("PORT_DROPPED_TRAFFIC", "dreamingwrt.logd.collector.port"),
        ("topology.device", "device_offline"): ("DEVICE_OFFLINE", "dreamingwrt-core.topology_history"),
        ("topology.device", "device_restored"): ("DEVICE_RESTORED", "dreamingwrt-core.topology_history"),
        ("ipam", "ip_conflict"): ("CLIENT_IP_CONFLICT", "dreamingwrt-core.ipam"),
        ("security", "suricata_detection"): ("SECURITY_DETECTION", "dreamingwrt.aegisxd.suricata"),
        ("system", "application_update_failed"): ("APPLICATION_UPDATE_FAILED", "dreamingwrt.otad"),
    }
    for (category, event), (event_code, producer) in contracts.items():
        assert f'"{category}", "{event}", "{event_code}"' in logd
        assert f'"{producer}"' in logd
        row = next(line for line in notifyd.splitlines() if f'{{ "{event_code}",' in line)
        assert f'"{producer}"' in row
        assert row.rstrip().endswith("1 },")


def test_ipam_conflict_is_edge_triggered_and_post_commit_only():
    source = read(NETCONFIG)
    mark = function(source, "static int nc_ipam_mark_conflict_one(")
    refresh = function(source, "struct json_object *jmx_bulk_ip_refresh(")
    assert "status<>'conflict'" in mark
    assert "nc_ipam_conflict_state_mark_seen" in mark
    assert "if (new_edge)" in mark
    assert "CREATE TABLE IF NOT EXISTS ipam_conflict_state" in source
    clear = function(source, "static int nc_ipam_conflict_state_clear_unseen(")
    assert "active=0" in clear and "seen_revision<>?2" in clear
    assert "UPDATE ipam_address SET status=CASE" in clear
    assert "THEN 'used'" in clear and "ELSE 'reserved'" in clear
    assert "AND NOT EXISTS(SELECT 1 FROM ipam_conflict_state" in clear
    assert "s.seen_revision=?2" in clear
    detect = function(source, "static int nc_ipam_mark_conflicts(")
    assert "status<>'offline'" in detect
    assert "r.status<>'offline' AND a.status<>'offline'" in detect
    assert "nc_ipam_mark_conflicts(notifications, before + 1)" in refresh
    assert refresh.index('nc_exec("COMMIT")') < refresh.index("jmx_log_center_event_add(event)")
    assert "refresh_rolled_back" in refresh
    queue = function(source, "static void nc_ipam_queue_conflict_event(")
    for field in ("network_id", "ip", "macs", "status_before", "status_after", "detection"):
        assert f'"{field}"' in queue
    assert 'json_object_object_add(detail, "macs", macs)' in queue
    assert "SELECT DISTINCT lower(mac)" in queue
    assert "ip-conflict:%s" in queue
    assert 'char event_id[64]' in queue
    assert "edge_revision" in queue


def test_topology_history_unit_has_log_center_stub():
    test_source = read(ROOT / "src" / "tests" / "topology_history_test.c")
    assert "struct json_object *jmx_log_center_event_add(" in test_source


def test_aegis_suricata_bridge_is_production_only_and_post_insert():
    source = read(AEGIS_HITS)
    insert = function(source, "static int aegisxd_hits_insert_suricata_event_ex(")
    bridge = function(source, "static int aegisxd_suricata_notify_logd(")
    assert "manual_ingest = !production_path ||" in insert
    assert "production_event = production_path && !manual_ingest && !test_event" in insert
    assert 'aegisxd_hits_insert_suricata_event_ex(eve, "aegisxd.suricata", 0, 1)' in source
    assert "aegisxd_hits_insert_suricata_event_ex(eve, source, test_event, 0)" in source
    assert insert.index("sqlite3_last_insert_rowid") < insert.index("aegisxd_suricata_notify_logd(")
    assert insert.index("sqlite3_finalize(st)") < insert.index("aegisxd_suricata_notify_logd(")
    assert "if (production_event &&" in insert
    for field in (
        "aegis_event_id", "producer_event_id", "rule_gid", "rule_sid", "rule_rev", "rule_name",
        "rule_category", "direction", "source_ip", "source_port",
        "destination_ip", "destination_port", "protocol", "action",
        "production_event",
    ):
        assert f'"{field}"' in bridge
    assert '"event", "suricata_detection"' in bridge
    assert '"dreamingwrt.logd"' in bridge and '"event_add"' in bridge


def test_otad_failure_bridge_is_post_terminal_persist_and_worker_safe():
    source = read(OTAD_DB)
    update = function(source, "int otad_operation_update(")
    bridge = function(source, "static int otad_notify_failed_operation(")
    assert "sqlite3_changes(g_otad_inventory_db) != 1" in update
    assert update.index("sqlite3_changes(g_otad_inventory_db) != 1") < update.index(
        "otad_notify_failed_operation(operation_id, now)"
    )
    assert 'if (!strcmp(state, "failed")' in update
    assert "temporary_ctx = ubus_connect(NULL)" in bridge
    assert "WHERE operation_id=?1 AND state='failed'" in bridge
    for field in (
        "operation_id", "producer_event_id", "kind", "action", "from_version", "to_version",
        "build_id", "target_slot", "error_code", "error_message",
        "state_before", "state_after",
    ):
        assert f'"{field}"' in bridge
    assert '"event", "application_update_failed"' in bridge
    assert '"dreamingwrt.logd"' in bridge and '"event_add"' in bridge


def test_unimplemented_p1_events_remain_fail_closed():
    source = read(NOTIFYD)
    for event in (
        "VPN_SITE_TO_SITE_DISCONNECTED",
        "VPN_SITE_TO_SITE_RESTORED",
        "CONFIG_COMMIT_FAILED",
        "IMPROPER_SHUTDOWN",
    ):
        row = re.search(rf'\{{\s*"{event}"[^\n]+\}}', source)
        assert row and row.group(0).rstrip().endswith("0 }")


if __name__ == "__main__":
    for test in (
        test_topology_producer_uses_infrastructure_groups_and_excludes_clients,
        test_topology_notification_dispatch_happens_after_commit,
        test_port_counter_fixture_has_baseline_reset_and_structured_deltas,
        test_logd_contracts_and_notifyd_catalog_match_five_real_p1_sources,
        test_ipam_conflict_is_edge_triggered_and_post_commit_only,
        test_topology_history_unit_has_log_center_stub,
        test_aegis_suricata_bridge_is_production_only_and_post_insert,
        test_otad_failure_bridge_is_post_terminal_persist_and_worker_safe,
        test_unimplemented_p1_events_remain_fail_closed,
    ):
        test()
    print("ok - structured P1 producer contracts passed")

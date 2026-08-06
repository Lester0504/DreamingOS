#!/usr/bin/env python3
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
CORE = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
DB = (ROOT / "src/jmx_db.c").read_text(encoding="utf-8")
AUDITD = (ROOT / "src/audit/jmx_auditd.c").read_text(encoding="utf-8")
LOGD_DB = (ROOT / "src/logd/logd_db.c").read_text(encoding="utf-8")
LOGD_COLLECTORS = (ROOT / "src/logd/logd_collectors.c").read_text(encoding="utf-8")
LOGD_COMMON = (ROOT / "src/logd/logd_common.c").read_text(encoding="utf-8")
LOGD_INTERNAL = (ROOT / "src/logd/logd_internal.h").read_text(encoding="utf-8")
NOTIFYD_DB = (ROOT / "src/notifyd/notifyd_db.c").read_text(encoding="utf-8")
NOTIFYD_COMMON = (ROOT / "src/notifyd/notifyd_common.c").read_text(encoding="utf-8")
NOTIFYD_INTERNAL = (ROOT / "src/notifyd/notifyd_internal.h").read_text(encoding="utf-8")
USER = (ROOT / "src/jmx_user.c").read_text(encoding="utf-8")


def body(source: str, name: str) -> str:
    match = re.search(
        rf"(?m)^[^;\n]*\b{re.escape(name)}\s*\([^;]*?\)\s*\{{",
        source,
    )
    if not match:
        raise AssertionError(f"function definition not found: {name}")
    brace = source.index("{", match.start())
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace : index + 1]
    raise AssertionError(f"unterminated function: {name}")


def strip_comments(source: str) -> str:
    """Remove /* */ and // comments, keeping newlines so line structure survives.

    The guard assertions below care about which statement sits under which
    condition, not about how the file is commented. Matching raw text made an
    explanatory comment inserted between `if (bulk_writes_allowed)` and
    `dw_refresh_wan_state();` fail the contract while the guarded semantics were
    unchanged. Comments are stripped before those assertions run.
    """
    out = []
    index = 0
    length = len(source)
    while index < length:
        pair = source[index:index + 2]
        if pair == "/*":
            end = source.find("*/", index + 2)
            if end == -1:
                break
            # Preserve newlines so a stripped block comment does not join lines.
            out.append("\n" * source.count("\n", index, end))
            index = end + 2
        elif pair == "//":
            end = source.find("\n", index)
            if end == -1:
                break
            index = end
        elif source[index] in "\"'":
            quote = source[index]
            out.append(source[index])
            index += 1
            while index < length:
                if source[index] == "\\":
                    out.append(source[index:index + 2])
                    index += 2
                    continue
                out.append(source[index])
                index += 1
                if source[index - 1] == quote:
                    break
        else:
            out.append(source[index])
            index += 1
    return "".join(out)


def guarded_statement(tick: str, condition: str, statement: str) -> bool:
    """True when `statement` is the statement controlled by `if (condition)`.

    Asserts structure rather than layout: comments are removed and whitespace
    between the condition and its statement is collapsed, so reformatting or
    annotating the call site cannot break the contract. A guard that is actually
    removed still fails, which is the property worth protecting.
    """
    cleaned = strip_comments(tick)
    pattern = re.escape(f"if ({condition})") + r"\s*" + re.escape(statement)
    return re.search(pattern, cleaned) is not None


def test_core_keeps_live_sampling_but_suppresses_history_writes() -> None:
    tick = body(CORE, "dw_handle_metrics_tick")
    assert 'jmx_storage_guard_allow(' in tick
    assert "if (wan_health && bulk_writes_allowed)" in tick
    assert guarded_statement(tick, "bulk_writes_allowed", "dw_refresh_wan_state();")
    # Live sampling must keep running under storage pressure. These are now
    # wrapped in DW_METRICS_TICK_STEP for per-step timing, so assert the call is
    # present rather than that it ends in a bare semicolon.
    assert "collect_interface_traffic_rate()" in tick
    assert "dw_client_overview_sample_tick()" in tick
    assert guarded_statement(tick, "ipv6_load", "DW_METRICS_TICK_STEP(\"ipv6_load\"")
    assert "flush_health && bulk_writes_allowed" in tick
    assert "wan_profiles && bulk_writes_allowed" in tick

    for function in ("dw_refresh_wan_state", "dw_update_wan_health",
                     "dw_update_wan_profiles"):
        assert "JMX_STORAGE_WRITE_BULK" in body(CORE, function)
    assert "JMX_STORAGE_WRITE_BULK" in body(DB, "jmx_db_flush_health_buckets")
    assert "JMX_STORAGE_WRITE_BULK" in body(DB, "jmx_db_sync_clients_from_memory")
    for function in ("save_daily_stats_to_file",
                     "save_online_offline_records_to_file",
                     "save_global_traffic_stats_to_file",
                     "save_daily_top_apps_stats_to_file",
                     "save_client_visit_data_to_file"):
        history = body(USER, function)
        assert "get_client_data_base_dir()" in history
        assert "JMX_STORAGE_WRITE_BULK" in history


def test_auditd_gates_startup_reload_periodic_and_daily_writes() -> None:
    helper = body(AUDITD, "audit_bulk_writes_allowed")
    reload_names = body(AUDITD, "maybe_reload_app_names")
    main = body(AUDITD, "main")
    status = body(AUDITD, "handle_status")

    assert "DW_AUDIT_STATE_DIR" in helper
    assert "cache_app_names_to_db();" in reload_names
    assert "audit_bulk_writes_allowed" in reload_names
    assert "url_audit_compact_existing_files();" in main
    assert main.count("audit_bulk_writes_allowed") >= 5
    assert "aggregate_and_store(DAY_SECONDS)" in main
    assert "jmx_storage_guard_check(DW_AUDIT_STATE_DIR" in status
    for field in ("storage_pressure", "storage_available_bytes",
                  "storage_suppressed_samples"):
        assert f'"{field}"' in status


def test_logd_and_notifyd_report_live_pressure_and_suppression() -> None:
    log_status = body(LOGD_DB, "logd_status_json")
    collect_tick = body(LOGD_COLLECTORS, "logd_collect_timer_cb")
    notify_status = body(NOTIFYD_DB, "notifyd_status_json")
    delivery_record = body(NOTIFYD_DB, "notifyd_delivery_record")

    assert 'jmx_storage_guard_check("/", &storage_guard.state)' in log_status
    assert "g_logd_storage_suppressed++" in collect_tick
    assert 'jmx_storage_guard_check("/", &storage_guard.state)' in notify_status
    assert "JMX_STORAGE_WRITE_BULK" in delivery_record
    for status in (log_status, notify_status):
        assert '"storage_pressure"' in status
        assert '"storage_available_bytes"' in status
        assert '"storage_last_suppressed_at"' in status
    for source, header, prefix in (
        (LOGD_COMMON, LOGD_INTERNAL, "g_logd_storage"),
        (NOTIFYD_COMMON, NOTIFYD_INTERNAL, "g_notify_storage"),
    ):
        assert f"uint64_t {prefix}_suppressed;" in source
        assert f"int64_t {prefix}_last_suppressed_at;" in source
        assert f"extern uint64_t {prefix}_suppressed;" in header
        assert f"extern int64_t {prefix}_last_suppressed_at;" in header


if __name__ == "__main__":
    test_core_keeps_live_sampling_but_suppresses_history_writes()
    test_auditd_gates_startup_reload_periodic_and_daily_writes()
    test_logd_and_notifyd_report_live_pressure_and_suppression()
    print("ok: storage guard is wired to core, auditd, logd, and notifyd producers")

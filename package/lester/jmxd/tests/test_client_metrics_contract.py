#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORE = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")


def check(condition: bool, reason: str) -> None:
    """Assert with a reason.

    Bare `assert token in blob` and `str.index` report an empty AssertionError or
    a ValueError traceback, which cannot distinguish a stale assertion from a
    real regression without reading the source. Say what was expected instead.
    """
    if not condition:
        raise AssertionError(reason)


def body(text: str, start: str, end: str) -> str:
    try:
        begin = text.index(start)
    except ValueError:
        raise AssertionError(f"anchor not found in source: {start!r}") from None
    try:
        finish = text.index(end, begin)
    except ValueError:
        raise AssertionError(f"closing anchor not found after {start!r}: {end!r}") from None
    return text[begin:finish]


def test_split_worker_sampler_uses_monotonic_deltas_and_truthful_completeness() -> None:
    sampler = body(
        CORE,
        "static void dw_client_today_add_interval",
        "static void dw_client_overview_sample_tick",
    )
    for token in (
        "dw_monotonic_ms()",
        "delta_ms < 1000",
        "delta_ms > 15000",
        "dw_client_today_last_gap_at",
        "dw_client_today_stat_date != today_start",
        "localtime_r",
        "hourly_online_time[local_tm.tm_hour]",
        "if (active)",
        "DW_CLIENT_ACTIVE_RATE_THRESHOLD_BPS",
        "ring->today_sample_count++",
    ):
        check(token in sampler, f"sampler lost {token!r}")
    # The offline guard must precede the accumulate call, otherwise an offline
    # client's interval still lands in the hourly buckets. Match the call by
    # prefix rather than by a full argument list: the callee grew up_rate and
    # down_rate parameters and is now split across lines, so the old exact
    # string "dw_client_today_add_interval(client, start, now, active)" no
    # longer occurs and str.index raised ValueError instead of checking order.
    guard = "if (!client->mac[0] || !client->online)"
    accumulate = "dw_client_today_add_interval(client, start, now, active"
    check(guard in sampler, f"sampler lost the offline guard {guard!r}")
    check(accumulate in sampler, f"sampler lost the accumulate call {accumulate!r}")
    check(
        sampler.index(guard) < sampler.index(accumulate),
        "the offline guard must run before dw_client_today_add_interval",
    )

    handler = body(
        CORE,
        "static int dw_handle_client_traffic_history",
        "static int dw_handle_client_online_history",
    )
    for token in (
        "hourly_online_time[hour]",
        "hourly_active_time[hour]",
        '"today_metrics"',
        '"metricsd_client_runtime_sampler"',
        '"partial_since_core_start; runtime_memory_not_persisted_across_core_restart"',
        '"complete", json_object_new_boolean(0)',
        '"observed_from"',
        '"last_gap_at"',
        '"sample_count"',
        '"bytes_available"',
        '"active_rate_threshold_bps"',
        '"active_semantics"',
        '"window_start"',
        '"window_end"',
        '"timezone"',
        '"step_sec"',
    ):
        assert token in handler
    assert "c->daily_stats.date == expected_today_start" in handler
    assert "ring->today_sample_count > 0" in handler
    assert "stat = &c->daily_stats;" in handler
    assert "get_today_stat(c)" not in handler


def test_runtime_ring_evicts_only_offline_lru_slots() -> None:
    allocator = body(
        CORE,
        "static int dw_client_runtime_mac_online",
        "static void dw_client_overview_sample_append",
    )
    for token in (
        "!client->online",
        "oldest_sample_at",
        "last_sample_at < oldest_sample_at",
        "!dw_client_runtime_mac_online(dw_client_overview_rings[i].mac)",
        "dw_client_overview_ring_evictions++",
        "dw_client_overview_ring_capacity_rejections++",
    ):
        assert token in allocator
    assert allocator.index("if (evict_idx < 0)") < allocator.index(
        "free_idx = evict_idx"
    )
    assert allocator.index("if (free_idx < 0)") < allocator.index(
        "dw_client_runtime_mac_online(dw_client_overview_rings[i].mac)"
    )
    assert 'ring->last_sample_at = ts;' in CORE
    for token in (
        '"ring_capacity"',
        '"ring_evictions"',
        '"ring_capacity_rejections"',
    ):
        assert token in CORE


def test_profile_uses_canonical_today_metrics_and_reports_completeness() -> None:
    current = body(
        WEB,
        "static struct json_object *webd_client_profile_current",
        "static void webd_profile_normalize_records",
    )
    response = body(
        WEB,
        "static struct json_object *webd_client_profile_response",
        "struct webd_ct_close_target",
    )
    assert 'app_nc_json_int64(today_metrics, "online_time"' in current
    assert 'app_nc_json_int64(today_metrics, "active_time"' in current
    assert 'app_nc_json_bool(today_metrics, "bytes_available", 0) ?' in current
    assert '"today_metrics_complete"' in current
    assert 'json_object_object_get_ex(th, "today_metrics"' in response
    assert '"today_online_time", json_object_new_boolean(' in response
    assert '"today_metrics", today_metrics' in response


def test_total_rate_ring_is_not_exposed_as_unknown_protocol_history() -> None:
    summary = body(
        WEB,
        "static struct json_object *webd_profile_protocol_summary",
        "static void webd_profile_normalize_visits",
    )
    assert '"total_rate_history"' in summary
    assert '"client_runtime_ring_total"' in summary
    assert '"rate_history_supported",\n                           json_object_new_boolean(protocol_history_series > 0)' in summary
    assert '"rate_history_complete",\n                           json_object_new_boolean(protocol_history_complete)' in summary
    assert 'protocol_history_ready && app_nc_json_bool(protocol_history, "complete", 0)' in summary
    assert '"per_protocol_rate_history_supported",\n                           json_object_new_boolean(protocol_history_series > 0)' in summary
    assert '"total_only_separate_from_protocol_history"' in summary
    assert '"per_app_protocol_hot_window_separate_from_client_total_ring"' in summary
    assert 'app_nc_json_str(protocol_history, "source", "unavailable")' in summary
    assert '"monotonic_client_app_counter_delta"' in summary
    assert '"rate_history_fallback_available"' in summary
    assert "protocol_history_fallback_available" in summary
    assert "client_runtime_total_unknown_category" not in summary
    assert 'json_object_object_add(cats, "unknown"' not in summary


def test_core_exposes_read_only_protocol_history_under_canonical_traffic_history() -> None:
    handler = body(
        CORE,
        "static int dw_handle_client_traffic_history",
        "static int dw_handle_client_online_history",
    )
    assert '"protocol_rate_history"' in handler
    assert "jmx_client_protocol_history_query" in handler
    assert "JMX_CLIENT_PROTOCOL_HISTORY_WINDOW_SEC" in handler

    module = (ROOT / "src/client_protocol_history.c").read_text(encoding="utf-8")
    for token in (
        "SQLITE_OPEN_READONLY",
        "LAG(ts) OVER (PARTITION BY flow_id ORDER BY ts)",
        "tx_bytes>=prev_tx AND rx_bytes>=prev_rx",
        "same_flow_adjacent_counter_delta",
        "first_sample_counted",
        "counter_reset_counted",
        "JMX_CLIENT_PROTOCOL_HISTORY_MAX_POINTS",
        "JMX_CLIENT_PROTOCOL_HISTORY_MAX_SERIES_PER_POINT",
        "DENSE_RANK() OVER (ORDER BY ts DESC)",
        "ROW_NUMBER() OVER (PARTITION BY ts",
        "point_rank<=?6 AND series_rank<=?7",
    ):
        assert token in module
    assert "CREATE TABLE" not in module
    assert "INSERT INTO" not in module
    assert "UPDATE " not in module
    assert "DELETE FROM" not in module


def test_ws_uses_the_same_split_history_contract() -> None:
    ws = body(
        WEB,
        "static struct json_object *webd_ws_client_protocols_data",
        "static struct json_object *webd_ws_client_connections_data",
    )
    for token in (
        '"rate_history"',
        '"total_rate_history"',
        '"rate_history_supported"',
        '"per_protocol_rate_history_supported"',
        '"total_rate_history_supported"',
    ):
        assert token in ws


if __name__ == "__main__":
    tests = [value for name, value in globals().items() if name.startswith("test_")]
    for test in tests:
        test()
    print(f"ok: {len(tests)} client metrics contract tests")

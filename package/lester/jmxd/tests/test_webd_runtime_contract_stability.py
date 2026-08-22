#!/usr/bin/env python3
"""Regression checks for stable system, clients, and audit contracts."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEB = (ROOT / "src" / "webd" / "jmx_app_api.c").read_text(encoding="utf-8")
CORE_UBUS = (ROOT / "src" / "jmx_ubus.c").read_text(encoding="utf-8")


def function(name: str, next_name: str) -> str:
    start = WEB.index(name)
    end = WEB.index(next_name, start)
    return WEB[start:end]


def test_system_basic_negotiates_real_core_methods() -> None:
    body = function("static struct json_object *webd_system_basic_response",
                    "static void webd_system_basic_attach_auth_state")
    assert 'app_ubus_invoke_timeout("dreamingwrt_system_settings_get"' in body
    assert 'app_ubus_invoke_timeout("dreamingwrt_system_settings"' in body
    assert "webd_system_basic_attach_interrupt_runtime(data)" in body
    assert 'webd_error("source_unavailable"' in body
    assert '{"dreamingwrt_system_settings", jmx_api_system_settings_get_wrap}' in CORE_UBUS
    assert '{"dreamingwrt_system_settings_get", jmx_api_system_settings_get_wrap}' in CORE_UBUS


def test_interrupt_projection_uses_kernel_runtime_sources() -> None:
    assert 'fopen("/proc/stat", "r")' in WEB
    assert 'fopen("/proc/interrupts", "r")' in WEB
    assert '"/sys/devices/system/cpu/cpu%u/cpufreq/scaling_cur_freq"' in WEB
    assert '"/sys/devices/system/cpu/cpu%u/topology/physical_package_id"' in WEB
    assert '"/proc/irq/%ld/effective_affinity_list"' in WEB
    assert '"hardirq_ticks"' in WEB
    assert '"softirq_ticks"' in WEB
    assert '"interrupt_count"' in WEB
    assert '"online_observable_not_toggle"' in WEB


def test_clients_never_falls_back_to_plain_text() -> None:
    body = function("static struct json_object *webd_clients_response",
                    "static void webd_system_settings_scrub_sensitive")
    # The params argument is NULL for the filtered inventory and carries
    # include_stale for the full history, so the call is not a fixed literal.
    # What matters is that this is the ubus source and the 2500 ms bound.
    assert 'app_ubus_invoke_timeout("clients", params,' in body
    assert "WEBD_CLIENTS_UPSTREAM_TIMEOUT_MS" in body
    assert 'json_object_is_type(clients, json_type_array)' in body
    # The key is chosen at runtime now (clients_inventory vs
    # clients_inventory_all) because the filtered inventory and the full history
    # are different answers and must not overwrite each other. Both key literals
    # and the 2s/30s freshness bounds are still pinned.
    assert 'jmx_cache_put_with_stale(cache_key, upstream, 2, 30)' in body
    assert '"clients_inventory"' in body
    assert '"clients_inventory_all"' in body
    assert '"client inventory source is not available"' in body
    # The route may pass extra options (with_apps), but it must still be this
    # JSON builder that answers, never a plain-text fallback.
    assert 'resp = webd_clients_response(&status' in WEB
    assert 'http_send(fd, 500, "Internal Server Error", "text/plain"' not in WEB
    assert 'http_send_json(fd, 500, resp)' in WEB


def test_capabilities_are_source_based_and_explain_false_values() -> None:
    body = function("static void webd_audit_add_caps",
                    "static int webd_audit_status_table_rows")
    for capability, reason in (
        ("url_persistent_records_available", "audit_url_event_source_unavailable"),
        ("online_records_historical", "online_event_journal_not_available"),
        ("im_records_supported",
         "im_presence_source_unavailable_af_active_app_af_active_host_unreadable"),
        ("protocol_snapshot_supported", "protocol_snapshot_source_unavailable"),
        ("filter_exclude_supported", "audit_bff_exclude_filters_not_implemented"),
    ):
        assert f'"{capability}"' in body
        assert f'"{reason}"' in body
    assert "webd_audit_status_has_table" in WEB
    assert '"url_persistent_records_present"' in WEB
    assert '"protocol_snapshot_records_present"' in WEB
    assert '"records_present"' in WEB


def test_audit_status_reports_im_capability_from_the_collector() -> None:
    """/audit/status must not contradict /audit/im-records on the same bit.

    The status handler used to pass a literal 0 for the IM capability while the
    im-records handler asked the collector, so the two endpoints answered
    differently about the same device at the same moment.
    """
    helper = function("static int webd_audit_view_im_supported",
                      "static int webd_audit_row_any_contains")
    # Collector self-report, never a row count.
    assert '"im_records_supported"' in helper
    assert "json_object_get_boolean" in helper
    assert "array_length" not in helper

    status = function("static struct json_object *webd_audit_status_response",
                      "static struct json_object *webd_audit_domains_from_records")
    assert "webd_audit_view_im_supported(view)" in status
    assert "im_supported, 0)" in status
    # Presence of rows is reported separately from support.
    assert '"im_records_present"' in status

    im = function("static struct json_object *webd_audit_im_records_response",
                  "static struct json_object *webd_audit_traffic_response")
    assert "webd_audit_view_im_supported(view)" in im


def test_capability_tri_state_separates_unknown_from_unavailable() -> None:
    """A handler that never checked a source must not claim it is unavailable."""
    body = function("static void webd_audit_add_caps",
                    "static int webd_audit_status_table_rows")
    assert "im_capability_not_evaluated_by_this_endpoint" in body
    assert "url_persistent_source_not_evaluated_by_this_endpoint" in body
    assert "protocol_snapshot_source_not_evaluated_by_this_endpoint" in body
    # The JSON stays a plain boolean; only the reason distinguishes the cases.
    assert "json_object_new_boolean(im_records_supported > 0)" in body


if __name__ == "__main__":
    test_system_basic_negotiates_real_core_methods()
    test_interrupt_projection_uses_kernel_runtime_sources()
    test_clients_never_falls_back_to_plain_text()
    test_capabilities_are_source_based_and_explain_false_values()
    test_audit_status_reports_im_capability_from_the_collector()
    test_capability_tri_state_separates_unknown_from_unavailable()
    print("ok: stable system/basic, interrupt, clients, and capability contracts")

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
    assert 'app_ubus_invoke_timeout("clients", NULL, 2500)' in body
    assert 'json_object_is_type(clients, json_type_array)' in body
    assert 'jmx_cache_put_with_stale("clients_inventory", upstream, 2, 30)' in body
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
        ("im_records_supported", "im_presence_collector_not_available"),
        ("protocol_snapshot_supported", "protocol_snapshot_source_unavailable"),
        ("filter_exclude_supported", "audit_bff_exclude_filters_not_implemented"),
    ):
        assert f'"{capability}"' in body
        assert f'"{reason}"' in body
    assert "webd_audit_status_has_table" in WEB
    assert '"url_persistent_records_present"' in WEB
    assert '"protocol_snapshot_records_present"' in WEB
    assert '"records_present"' in WEB


if __name__ == "__main__":
    test_system_basic_negotiates_real_core_methods()
    test_interrupt_projection_uses_kernel_runtime_sources()
    test_clients_never_falls_back_to_plain_text()
    test_capabilities_are_source_based_and_explain_false_values()
    print("ok: stable system/basic, interrupt, clients, and capability contracts")

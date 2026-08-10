#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORE = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")
HEADER = (ROOT / "src/jmx_netconfig_db.h").read_text(encoding="utf-8")
COMMON = (ROOT / "src/jmx_ubus.c").read_text(encoding="utf-8")
UBUS = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
SETUP = (ROOT / "src/jmx_setup.c").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    return text[first:text.index(end, first)]


assert "jmx_system_settings_save_apply_result" in HEADER
assert "jmx_system_settings_apply_result" in HEADER

setter = between(
    CORE,
    "int jmx_system_settings_set",
    "static int nc_sys_runtime_hostname_matches",
)
assert "zram restart" not in setter
assert "zram_comp_algo" not in setter
assert '"packet_steering=CASE' not in setter
assert '"irq_balance=CASE' not in setter
assert '"flow_offloading=COALESCE' not in setter
assert "system_ntp_server" not in setter
assert '"timezone=COALESCE' not in setter
assert '"log_level=CASE' not in setter

preflight = between(
    CORE,
    "static const char *nc_sys_general_capability",
    "static struct json_object *nc_sys_settings_snapshot",
)
for field in (
    "timezone",
    "time_sync",
    "ntp_servers",
    "log_level",
    "remote_log_host",
):
    assert f'"{field}"' in preflight
for field in ("zram_size_mb", "packet_steering", "irq_balance", "flow_offloading"):
    assert f'"{field}"' in CORE
assert "nc_sys_projected_value_equal" in preflight
assert "accepted_sections" in preflight
assert '"system_settings_section_write"' in preflight
assert '!strncmp(field, "zram_", 5)' in preflight

# A gated field must be recorded and skipped, not abort the whole request. The
# old builder returned -1 on the first non-writable field, which made a closed
# capability (a log level, a timezone) take the writable hostname down with it.
changed_fields = between(
    CORE,
    "static int nc_sys_add_changed_fields",
    "static struct json_object *nc_sys_build_settings_delta",
)
assert "nc_sys_denied_field_result" in changed_fields
assert "return -1" not in changed_fields
assert changed_fields.count("continue;") >= 3

# Fields GET reports but no writer accepts are skipped silently; fields with a
# real writer that is gated stay visible as rejections.
delta = between(
    CORE,
    "static struct json_object *nc_sys_build_settings_delta",
    "static struct json_object *nc_sys_settings_snapshot",
)
for derived in ("version_source", "version_error", "interrupt_runtime_source",
                "key_management", "disabled_func_path"):
    assert f'"{derived}"' in delta, derived
# `disabled_functions` is deliberately left out of this check: it is classified
# by the advanced-page owner, who lists it as observed state.
for gated in ("led_policy", "update_channel"):
    assert f'"{gated}"' not in delta, gated

# Error responses carry a human readable message, not just a machine token.
assert "nc_sys_settings_reason_message" in CORE
assert '"message"' in CORE
assert "static char message[320]" not in CORE  # reentrancy: core spawns threads
assert '"allocation_failed"' in CORE
assert "if (!denied)" in CORE

transaction = between(
    CORE,
    "struct json_object *jmx_system_settings_save_apply_result",
    "/* ── system_settings_draft_apply",
)

# Rejections reach the client, and an all-gated request is an honest failure
# rather than a silent "nothing changed".
assert "nc_sys_merge_field_results" in transaction
assert '"no_writable_fields"' in transaction
assert '"rejected_fields"' in transaction
assert transaction.index("nc_sys_build_settings_delta") < transaction.index(
    "jmx_system_settings_set(delta)"
)
assert '"capability_disabled"' in CORE
assert '"transactional_runtime_executor_pending"' in CORE
assert '"persisted", json_object_new_boolean(0)' in CORE
assert "nc_sys_settings_snapshot" in transaction
assert "jmx_system_settings_set(snapshot)" in transaction
assert "jmx_system_settings_apply(NULL)" in transaction
assert '"compensated"' in transaction
assert '"partial"' in transaction
assert '"field_results"' in transaction
assert '"saved_only"' in CORE

apply = between(
    CORE,
    "int jmx_system_settings_apply",
    "static int nc_sys_json_equal",
)
assert "nc_backup_config" in apply
assert "jmx_uci_commit" in apply
assert "sethostname" in apply
assert "nc_sys_uci_hostname_matches" in apply
assert "nc_sys_runtime_hostname_matches" in apply
assert "nc_restore_config" in apply

get = between(CORE, "struct json_object *jmx_system_settings_get", "int jmx_system_settings_set")
for capability in (
    '"general_time_write",json_object_new_boolean(0)',
    '"general_logs_write",json_object_new_boolean(0)',
    '"zram_write",json_object_new_boolean(0)',
    '"system_settings_field_results",json_object_new_boolean(1)',
    '"system_settings_fail_closed",json_object_new_boolean(1)',
):
    assert capability in get
assert 'json_object_object_add(d,"field_contracts",contracts)' in get
assert "char path[256]" not in get
assert get.count('json_object_object_add(adv,"zram_memory_threshold"') == 1

common_set = between(
    COMMON,
    "static struct json_object *jmx_api_system_settings_set_wrap",
    "static struct json_object *jmx_api_system_settings_apply_wrap",
)
assert "jmx_system_settings_save_apply_result(req_obj)" in common_set
assert "jmx_system_settings_set(req_obj)" not in common_set

ubus_set = between(
    UBUS,
    "static int dw_handle_system_settings_set",
    "static int dw_handle_system_settings_apply",
)
assert "jmx_system_settings_save_apply_result(payload)" in ubus_set
assert "jmx_system_settings_set(payload)" not in ubus_set

web_save = between(
    WEB,
    "static struct json_object *webd_system_settings_save_response",
    "static struct json_object *webd_capabilities_data",
)
assert 'webd_system_settings_core_payload(body)' in web_save
assert 'app_ubus_or_error("dreamingwrt_system_settings_set", payload)' in web_save
assert 'app_ubus_invoke_timeout("dreamingwrt_system_settings_apply"' not in web_save
assert '"jmxd.dreamingwrt_system_settings_transaction"' in web_save
assert "webd_json_clone(data)" in web_save
assert 'app_nc_json_str(resp, "message"' in web_save
assert web_save.index('app_nc_json_str(resp, "message"') < web_save.index(
    'app_nc_json_str(resp, "reason"'
)

setup_apply = between(SETUP, "if (has_device) {", "if (ok && has_wan)")
assert "jmx_system_settings_save_apply_result(settings_payload)" in setup_apply
assert "jmx_system_settings_set(device)" not in setup_apply

print("ok: system settings fail closed per field and expose verified runtime truth")

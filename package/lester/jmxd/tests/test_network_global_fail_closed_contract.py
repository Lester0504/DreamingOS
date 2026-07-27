#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NET = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")
CORE = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
COMMON = (ROOT / "src/jmx_ubus.c").read_text(encoding="utf-8")
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
RESTORE = (ROOT / "src/init/config_restore.c").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    return text[first:text.index(end, first)]


setter = between(NET, "int jmx_netconfig_global_set(", "int jmx_netconfig_global_apply(")
apply = between(NET, "int jmx_netconfig_global_apply(", "static void nc_physical_port_owner")
assert "return -2;" in setter
assert "return -2;" in apply
for forbidden in (
    "UPDATE network_global",
    "nc_prepare(",
    "nc_backup_config(",
    "uci_load(",
    "nc_uci_set_pkg(",
    "jmx_uci_commit(",
    '"maindhcp"',
):
    assert forbidden not in setter
    assert forbidden not in apply

caps = between(NET, "struct json_object *jmx_netconfig_capabilities(", "struct json_object *jmx_netconfig_radius_list(")
for name in (
    "network_global_save",
    "network_global_apply",
    "network_global_readback",
    "network_global_rollback",
    "default_posture",
    "stp",
    "stp_mode",
    "igmp_snooping",
    "mdns_proxy",
    "rogue_dhcp_detection",
    "jumbo_frames",
    "flow_control",
    "dot1x",
):
    assert f'"{name}", json_object_new_boolean(0)' in caps

get = between(NET, "struct json_object *jmx_netconfig_global_get(", "struct json_object *jmx_netconfig_network_overview")
assert '"network_global"' not in get
assert '"persisted", json_object_new_boolean(1)' in get
assert '"applied", json_object_new_boolean(0)' in get
assert '"apply_state", json_object_new_string("unsupported")' in get

for handler_start, handler_end in (
    ("static int dw_handle_global_set(", "static int dw_handle_global_save_only("),
    ("static int dw_handle_global_save_only(", "static int dw_handle_global_apply_only("),
    ("static int dw_handle_global_apply_only(", "static int dw_handle_physical_port_list("),
):
    handler = between(CORE, handler_start, handler_end)
    assert "dw_global_write_disabled_response()" in handler
    assert "jmx_netconfig_global_set(" not in handler
    assert "jmx_netconfig_global_apply(" not in handler

alias = between(COMMON, "static struct json_object *jmx_api_net_global_set(", "static struct json_object *jmx_api_physical_port_list(")
assert '"capability_disabled"' in alias
assert '"persisted", json_object_new_boolean(0)' in alias
assert '"applied", json_object_new_boolean(0)' in alias
assert "jmx_netconfig_global_set(" not in alias
assert "jmx_netconfig_global_apply(" not in alias

dispatch = between(WEB, "/* ── Global config ── */", "/* ── Ports ── */")
assert dispatch.count('webd_error("capability_disabled"') == 2
assert 'app_ubus_invoke("network_global_save"' not in dispatch
assert 'app_ubus_invoke("network_global_apply"' not in dispatch
assert dispatch.count('"persisted", json_object_new_boolean(0)') == 2
assert dispatch.count('"applied", json_object_new_boolean(0)') == 2

materialize = between(RESTORE, "static int network_materialize(", "static int restore_previous(")
assert 'ubus_call("dreamingwrt", "network_global_apply"' not in materialize
assert 'apply_table_ids(db, "wan", "wan_apply")' in materialize
assert 'apply_table_ids(db, "lan", "lan_apply")' in materialize
assert 'ubus_call("dreamingwrt", "dreamingwrt_system_settings_apply"' in materialize
assert "hostname_materialized(hostname)" in materialize

print("ok: global network writes fail closed without DB/UCI side effects")

#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
DB = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    return text[first:text.index(end, first)]


collector = between(
    WEB,
    "static void webd_policy_add_generic_array_rules",
    "static void webd_policy_collect_ubus_sources",
)
assert 'snprintf(id, sizeof(id), "%s.%s", id_prefix, rid)' in collector

sources = between(
    WEB,
    "static void webd_policy_collect_ubus_sources",
    "static void webd_policy_add_column",
)
for stable_prefix in (
    "network_control.connection_limit",
    "network_control.mac",
    "network_control.url_access",
    "network_control.app",
    "network_control.terminal_limit",
):
    assert stable_prefix in sources

capabilities = between(
    WEB,
    "static struct json_object *webd_policy_capabilities",
    "static void webd_policy_dynamic_filter_inc",
)
assert '"acl_write_partial"' in capabilities
assert '"acl_create"' in capabilities
assert '"acl_enable_disable"' in capabilities
assert '"acl_write_supported_types"' in capabilities
assert 'json_object_new_string("mac")' in capabilities
assert 'json_object_new_string("acl")' in capabilities
assert '"acl_write_pending_types"' in capabilities
assert 'json_object_new_string("connection_limit")' in capabilities
assert '"nft_connlimit_expression_unavailable"' in capabilities
assert '"acl_schedule_supported"' in capabilities
assert 'json_object_new_string("always")' in capabilities
assert '"acl_mac_allow_supported"' in capabilities
assert 'standalone nft base-chain accept cannot bypass later firewall chains' in capabilities

acl = between(
    WEB,
    "static int webd_policy_acl_type_supported",
    "static struct json_object *webd_policy_pbr_reorder_response",
)
assert 'app_ubus_or_error("network_control_save", params)' in acl
assert 'app_ubus_or_error("network_control_bulk_delete", params)' in acl
assert 'app_ubus_or_error("network_control_apply", params)' in acl
assert '"apply_nft"' in acl and '"apply_tc"' in acl
assert '"policy_acl_apply_failed"' in acl
assert 'rolled_back' in acl
assert 'webd_policy_acl_existing(type, raw_id)' in acl
assert "json_tokener_parse(json_object_to_json_string_ext(" in acl
assert "webd_policy_acl_port_spec_ok" in acl
assert "connection_limit protocol must be tcp, udp, or tcp,udp" in acl
assert "ACL name must be a printable single line" in acl
assert "MAC ACL schedule is not implemented; schedule must be always" in acl
assert "MAC ACL currently supports deny only" in acl
assert "unsupported ACL operation" in acl
assert 'return type && !strcmp(type, "mac")' in acl

dispatch = between(
    WEB,
    "static struct json_object *webd_policy_write_preview_response",
    "static void webd_copy_field_if_present",
)
assert "webd_policy_write_is_acl(operation, policy_type, id, body)" in dispatch
assert "webd_policy_acl_apply_response(body, operation, id, http_status)" in dispatch

apply = between(
    DB,
    "struct json_object *jmx_network_control_apply",
    "int jmx_network_control_rules_bulk_delete",
)
assert "runtime_ok" in apply
assert '"runtime_apply_failed"' in apply
assert "(dry||runtime_ok)?API_CODE_SUCCESS:API_CODE_ERROR" in apply
assert "nft_rc" in apply and "tc_rc" in apply

bulk_delete = between(
    DB,
    "int jmx_network_control_rules_bulk_delete",
    "struct json_object *jmx_network_control_status",
)
for detail_table in (
    "network_control_connection_limit",
    "network_control_mac_rule",
    "network_control_url_access_rule",
    "network_control_url_rewrite_rule",
    "network_control_app_rule",
    "network_control_terminal_limit",
):
    assert detail_table in bulk_delete

print("ok: Policy Table ACL has stable ids, guarded partial CRUD, rollback, and truthful runtime status")

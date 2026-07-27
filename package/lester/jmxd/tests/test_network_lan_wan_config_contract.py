#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NETCONFIG = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")
API = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
WEBD = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
HEADER = (ROOT / "src/jmx_netconfig_db.h").read_text(encoding="utf-8")


def section(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    finish = source.index(end, begin)
    return source[begin:finish]


def test_pppoe_secrets_are_write_only_and_preserved() -> None:
    wan_json = section(
        NETCONFIG,
        "static struct json_object *nc_wan_row_to_json",
        "static void nc_wan_load_addresses",
    )
    hybrid_json = section(
        NETCONFIG,
        "static void nc_hybrid_row_to_json",
        "struct json_object *jmx_netconfig_hybrid_line_list",
    )
    wan_set = section(
        NETCONFIG,
        "int jmx_netconfig_wan_set(",
        "int jmx_netconfig_wan_set_enabled",
    )
    hybrid_set = section(
        NETCONFIG,
        "int jmx_netconfig_hybrid_line_set(",
        "int jmx_netconfig_hybrid_line_delete",
    )

    assert '"password_configured"' in wan_json
    assert '"secret_ref_state"' in wan_json
    assert 'json_object_object_add(o, "password"' not in wan_json
    assert 'json_object_object_add(o, "password_ref"' not in wan_json
    assert '"password_configured"' in hybrid_json
    assert 'json_object_object_add(o, "password"' not in hybrid_json
    assert 'json_object_object_add(o, "password_ref"' not in hybrid_json
    assert "nc_redact_secret_fields(multi)" in wan_json

    for body in (wan_set, hybrid_set):
        assert '"clear_password"' in body
        assert "stored_password" in body
        assert "requested_password" in body
        assert "memset(stored_password, 0" in body
    assert "nc_wan_write_uci_draft" not in NETCONFIG
    assert "/etc/config/dreamingwrt_wan_uci" not in NETCONFIG


def test_save_apply_readback_contract_is_core_owned() -> None:
    result = section(
        NETCONFIG,
        "static struct json_object *nc_save_apply_result",
        "struct json_object *jmx_netconfig_wan_save_apply_result",
    )
    for required in (
        'nc_backup_config("network"',
        'nc_exec("BEGIN IMMEDIATE")',
        "jmx_netconfig_wan_set(config)",
        "jmx_netconfig_apply_wan(id)",
        "jmx_netconfig_lan_set(config)",
        "jmx_netconfig_apply_lan(id)",
        'nc_exec("COMMIT")',
        'nc_exec("ROLLBACK")',
        '"saved"',
        '"applied"',
        '"apply_state"',
        '"readback"',
        '"rollback"',
    ):
        assert required in result
    assert 'jmx_netconfig_wan_save_apply_result(in)' in API
    assert 'jmx_netconfig_lan_save_apply_result(in)' in API
    assert 'status = app_response_status(resp, status);' in WEBD


def test_lan_primary_address_field_is_consistent() -> None:
    validate = section(
        NETCONFIG,
        "struct json_object *jmx_netconfig_lan_validate(",
        "int jmx_netconfig_wan_set(",
    )
    save = section(
        NETCONFIG,
        "static int nc_lan_save_addresses(",
        "static int nc_lan_save_dhcp(",
    )

    for body in (validate, save):
        assert 'nc_json_bool(a, "primary"' in body
        assert 'nc_json_bool(a, "is_primary"' in body


def test_network_ids_and_linux_device_names_use_distinct_uci_rules() -> None:
    wan_validate = section(
        NETCONFIG,
        "struct json_object *jmx_netconfig_wan_validate(",
        "struct json_object *jmx_netconfig_lan_validate(",
    )
    lan_validate = section(
        NETCONFIG,
        "struct json_object *jmx_netconfig_lan_validate(",
        "int jmx_netconfig_wan_set(",
    )
    ensure_section = section(
        NETCONFIG,
        "int nc_uci_ensure_section(",
        "static const char *nc_wan_primary_address(",
    )
    lan_ports = section(
        NETCONFIG,
        "static int nc_apply_lan_ports(",
        "static void nc_apply_lan_dhcp(",
    )

    for body in (wan_validate, lan_validate):
        assert '"invalid_uci_section"' in body
        assert "nc_uci_section_name_ok(id)" in body
    assert "nc_uci_section_name_ok(section)" in ensure_section
    assert "nc_uci_delete_loaded_section(ctx, pkg, s)" in ensure_section
    assert "strcmp(s->e.name, section)" in ensure_section
    assert "uci_lookup_ptr(ctx, &ptr, buf, true) != UCI_OK || !ptr.o" in NETCONFIG
    assert "uci_lookup_ptr(ctx, &ptr, buf, true) != UCI_OK || !ptr.s" in NETCONFIG
    assert "nc_uci_ensure_network_device" in lan_ports
    assert 'nc_uci_set_pkg(ctx, "network", section, "type", "bridge")' in lan_ports
    assert "nc_uci_delete_network_device(uctx, netpkg, device)" in NETCONFIG


def test_lan_delete_is_guarded_and_exposed() -> None:
    delete = section(
        NETCONFIG,
        "int jmx_netconfig_lan_delete(",
        "int jmx_netconfig_lan_set_ports",
    )
    for required in (
        'strcmp(id, "lan")',
        'strcmp(id, "default-lan")',
        'SELECT COUNT(*) FROM lan WHERE enabled=1',
        'SELECT COUNT(*) FROM lan_port WHERE lan_id=?1',
        'SELECT COUNT(*) FROM lan WHERE parent_lan_id=?1',
        'SELECT COUNT(*) FROM ipam_network',
        'nc_backup_config("network"',
        'nc_backup_config("dhcp"',
        'nc_backup_config("firewall"',
        'nc_exec("BEGIN IMMEDIATE")',
        'nc_exec("COMMIT")',
        'nc_exec("ROLLBACK")',
        'nc_restore_config("network"',
        'nc_reload_network_stack(1, 1',
    ):
        assert required in delete
    assert "nc_lan_contains_management_ip" in NETCONFIG
    assert "JMX_NETCONFIG_DELETE_MANAGEMENT_PATH" in HEADER
    assert '"management_client_ip"' in WEBD
    assert 'app_ubus_invoke("lan_delete", params)' in WEBD
    assert 'jmx_netconfig_lan_delete_result(id, management_client_ip)' in API


def test_wan_delete_cleans_children_and_firewall_transactionally() -> None:
    delete = section(
        NETCONFIG,
        "int jmx_netconfig_wan_delete(",
        "/* ═",
    )
    for required in (
        '"wan_dns_policy", "wan_address", "wan_advanced", "wan_bond"',
        'DELETE FROM hybrid_line WHERE parent_wan_id=?1',
        'SELECT id FROM hybrid_line WHERE parent_wan_id=?1',
        'nc_backup_config("network"',
        'nc_backup_config("firewall"',
        'nc_apply_wan_firewall_zone(uctx, firepkg, id, 0)',
        'jmx_uci_commit(uctx, "network")',
        'jmx_uci_commit(uctx, "firewall")',
        'nc_reload_network_stack(0, 1',
        'nc_restore_config("network"',
        'nc_restore_config("firewall"',
    ):
        assert required in delete
    result = section(
        NETCONFIG,
        "struct json_object *jmx_netconfig_wan_delete_result",
        "struct json_object *jmx_netconfig_lan_save_apply_result",
    )
    for required in (
        '"saved"', '"applied"', '"deleted"', '"apply_state"',
        '"readback"', '"rollback"',
    ):
        assert required in result
    assert 'jmx_netconfig_wan_delete_result(id)' in API


def test_advanced_write_capabilities_do_not_overclaim() -> None:
    assert '"hybrid_wan_write", json_object_new_boolean(0)' in NETCONFIG
    assert '"pppoe_multi_write", json_object_new_boolean(0)' in NETCONFIG
    assert '"wan_bonding_write", json_object_new_boolean(0)' in NETCONFIG
    assert '"unsupported_write"' in NETCONFIG


def test_csv_memstream_returns_allocated_buffer() -> None:
    for name in ("wan", "lan"):
        csv = section(
            NETCONFIG,
            f"char *jmx_netconfig_{name}_csv",
            "struct json_object *jmx_netconfig_wan_status"
            if name == "lan"
            else "char *jmx_netconfig_lan_csv",
        )
        assert "char *buffer = NULL" in csv
        assert "open_memstream(&buffer, &total)" in csv
        assert "return buffer" in csv
        assert "(char **)out_len" not in csv


def test_csv_export_is_an_authenticated_direct_download() -> None:
    helper = section(
        WEBD,
        "static int webd_network_csv_download_response(int fd, const struct http_req *req,\n                                              int is_wan)\n{",
        "static int webd_config_backup_download_response",
    )
    auth_dispatch = section(
        WEBD,
        "/* ── All remaining routes require Bearer token ── */",
        'if (!strcmp(req.path, "/api/v1/ai/chat/stream")',
    )
    for required in (
        '"wan_config_export_csv"',
        '"lan_config_export_csv"',
        'strcmp(req->method, "GET")',
        'strcmp(req->method, "HEAD")',
        'code != 0 && code != 200 && code != APP_API_CODE_SUCCESS',
        'json_object_object_get_ex(upstream, "data", &data)',
        'json_type_string',
        '"Content-Type: text/csv; charset=utf-8',
        '"Content-Disposition: attachment;',
        '"Cache-Control: no-store',
        '"X-Content-Type-Options: nosniff',
        'WEBD_NETWORK_CSV_MAX_BYTES',
    ):
        assert required in helper
    assert '"password"' not in helper
    assert '"password_ref"' not in helper
    assert '"/api/v1/network/wans/export.csv"' in auth_dispatch
    assert '"/api/v1/network/lans/export.csv"' in auth_dispatch
    export_pos = WEBD.index('"/api/v1/network/wans/export.csv"', WEBD.index("static void handle_client"))
    assert WEBD.index("/* ── All remaining routes require Bearer token ── */") < export_pos
    assert export_pos < WEBD.index('/* ── WAN single ── */')


def test_batch_preview_apply_contract_is_explicitly_partial() -> None:
    batch = section(
        NETCONFIG,
        "static struct json_object *nc_batch_response_data",
        "/* ═",
    )
    for required in (
        '"operations"',
        '"items"',
        '"ids"',
        '"enable"',
        '"disable"',
        '"delete"',
        '"duplicate_id"',
        '"management_reachability_risk"',
        '"last_enabled_lan"',
        '"all_wans_will_be_disabled"',
        '"atomic", json_object_new_boolean(0)',
        '"partial", json_object_new_boolean(1)',
        '"ordered_single_item_transactions"',
        '"stop_on_error"',
        'jmx_netconfig_lan_save_apply_result(config)',
        'jmx_netconfig_wan_save_apply_result(config)',
        'jmx_netconfig_lan_delete_result(id, management_client_ip)',
        'jmx_netconfig_wan_delete_result(id)',
    ):
        assert required in batch
    assert '"network_batch_atomic", json_object_new_boolean(0)' in NETCONFIG
    assert '"network_batch_partial", json_object_new_boolean(1)' in NETCONFIG
    for method in (
        "wan_config_batch_preview",
        "wan_config_batch_apply",
        "lan_config_batch_preview",
        "lan_config_batch_apply",
    ):
        assert f'UBUS_METHOD("{method}"' in API
        assert f'"{method}"' in WEBD
    for route in (
        "/api/v1/network/wans/batch/preview",
        "/api/v1/network/wans/batch/apply",
        "/api/v1/network/lans/batch/preview",
        "/api/v1/network/lans/batch/apply",
    ):
        assert f'"{route}"' in WEBD
    assert '"management_client_ip"' in WEBD
    assert WEBD.index('"/api/v1/network/wans/batch/preview"') < WEBD.index(
        '/* ── WAN single ── */'
    )
    assert WEBD.index('"/api/v1/network/lans/batch/preview"') < WEBD.index(
        'else if (!strncmp(req.path, "/api/v1/network/lans/", 21)'
    )


def test_json_text_fields_are_canonicalized_once() -> None:
    assert "static char *nc_json_array_text_dup" in NETCONFIG
    assert "json_tokener_parse(text)" in NETCONFIG
    assert "json_type_array" in section(
        NETCONFIG,
        "static char *nc_json_array_text_dup",
        "static int nc_parse_pool",
    )
    dhcp = section(
        NETCONFIG,
        "static int nc_lan_save_dhcp",
        "static int nc_lan_save_ipv6",
    )
    ipv6 = section(
        NETCONFIG,
        "static int nc_lan_save_ipv6",
        "int jmx_netconfig_lan_set",
    )
    assert "nc_json_array_text_dup(exclude" in dhcp
    assert "nc_json_array_text_dup(dns" in dhcp
    assert "nc_json_array_text_dup(parents" in ipv6
    assert "nc_json_array_text_dup(dns6" in ipv6


if __name__ == "__main__":
    test_pppoe_secrets_are_write_only_and_preserved()
    test_save_apply_readback_contract_is_core_owned()
    test_lan_delete_is_guarded_and_exposed()
    test_wan_delete_cleans_children_and_firewall_transactionally()
    test_advanced_write_capabilities_do_not_overclaim()
    test_csv_memstream_returns_allocated_buffer()
    test_csv_export_is_an_authenticated_direct_download()
    test_batch_preview_apply_contract_is_explicitly_partial()
    test_json_text_fields_are_canonicalized_once()
    print("ok: LAN/WAN config write, delete, secret, capability, and CSV contracts")

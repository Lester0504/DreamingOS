#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DB = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")
CORE = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
WEBD = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")


def test_dhcp_get_has_unambiguous_structured_contract() -> None:
    assert '"pool_start"' in DB
    assert '"pool_end"' in DB
    assert 'nc_dhcp_text_array((const char*)sqlite3_column_text(st,7))' in DB
    assert '"pool_addresses_full_ipv4"' in DB
    assert '"allow_deny_list",json_object_new_boolean(1)' in DB
    assert '"access_list_replace",json_object_new_boolean(1)' in DB
    assert '"access_list_apply",json_object_new_boolean(1)' in DB
    assert '"dhcpv6_static_prefix",json_object_new_boolean(1)' in DB
    assert '"prefix_reservations"' in DB
    assert '"prefixes"' in DB
    assert 'char selected[128] = "";' in DB
    assert 'char lan_id[128] = "", scope_id[128] = "";' in DB


def test_dhcp_apply_rebuilds_all_scope_reservations_and_checks_reload() -> None:
    start = DB.index("static int nc_dhcp_rebuild_all_reservations(")
    end = DB.index("/* ══════════════════════════════════════════════════════════════════════\n * UPnP", start)
    section = DB[start:end]
    assert 'JOIN dhcp_scope ds ON ds.id=dr.scope_id' in section
    assert 'WHERE dr.enabled=1 AND ds.enabled=1' in section
    reservation_only = section[:section.index('#define NC_DHCP_ACCESS_BEGIN')]
    assert 'WHERE scope_id=?1 AND enabled=1' not in reservation_only
    assert 'nc_backup_config("dhcp"' in section
    assert 'jmx_uci_commit(ctx, "dhcp")' in section
    assert 'nc_run_quiet("/etc/init.d/dnsmasq reload' in section
    assert 'nc_restore_config("dhcp", bak)' in section
    assert 'dw-dhcp-rollback.log' in section


def test_reservation_delete_resolves_scope_and_checks_changes() -> None:
    start = DB.index("int jmx_dhcp_reservation_delete_resolve(")
    end = DB.index("static int nc_dhcp_normalize_exclude_pool", start)
    section = DB[start:end]
    assert 'JOIN dhcp_scope ds ON ds.id=dr.scope_id' in section
    assert 'sqlite3_changes(g_netconfig_db)' in section
    assert 'changed != 1' in section
    assert 'jmx_dhcp_reservation_delete_resolve' in CORE
    assert '"reservation_not_found"' in CORE


def test_standalone_rest_routes_use_core_contract() -> None:
    assert '"/api/v1/services/dhcp"' in WEBD
    assert '"/api/v1/services/dhcp/reservations/"' in WEBD
    assert 'app_ubus_invoke_timeout("dhcp_service_set", merged_body, 15000)' in WEBD
    assert 'app_ubus_invoke_timeout("dhcp_reservation_delete", params, 15000)' in WEBD
    assert '"method_not_allowed", "method not allowed for DHCP service"' in WEBD
    assert '"apply_state"' in CORE
    assert '"readback"' in CORE
    assert 'rc==-2?"validation_failed"' in CORE
    assert '"dhcp_validation_failed"' in CORE


def test_dhcp_allow_deny_list_persisted_validated_and_applied() -> None:
    assert 'CREATE TABLE IF NOT EXISTS dhcp_access_entry' in DB
    assert "CHECK(action IN ('allow','deny'))" in DB
    assert 'UNIQUE(scope_id, mac)' in DB
    assert 'nc_dhcp_access_list_from_payload' in DB
    assert 'nc_dhcp_validate_access_list' in DB
    assert 'invalid_access_action' in DB
    assert 'invalid_access_mac' in DB
    assert 'duplicate_access_mac' in DB
    assert 'invalid_access_sort_order' in DB
    assert 'SELECT id,action,mac,name,remark,enabled,sort_order FROM dhcp_access_entry' in DB
    assert 'json_object_object_add(data,"whitelist",whitelist)' in DB
    assert 'json_object_object_add(data,"blacklist",blacklist)' in DB
    assert 'nc_add_text(item,"scope",st,7)' in DB
    assert 'DELETE FROM dhcp_access_entry WHERE scope_id=?1' in DB
    assert 'INSERT INTO dhcp_access_entry' in DB
    assert 'nc_dhcp_merge_access_extraconf(ctx, pkg, &access_entries)' in DB
    assert 'NC_DHCP_ACCESS_BEGIN' in DB
    assert 'NC_DHCP_ACCESS_END' in DB
    assert 'block_len = strlen(block)' in DB
    assert '"SELECT ds.id,ds.lan_id,"' in DB
    assert 'dhcp-ignore=tag:%s,tag:!%s' in DB
    assert 'dhcp-mac=set:%s,%s' in DB
    assert 'ptr.option = "extraconftext"' in DB
    assert 'nc_dhcp_access_runtime_loaded(access_entries)' in DB
    assert '/tmp/etc/dnsmasq.conf.*' in DB
    assert 'd=$(sed -n \'s/^conf-dir=//p\'' in DB
    assert 'pidof dnsmasq' in DB
    assert '/tmp/dnsmasq.d/dreamingwrt-dhcp-access.conf' not in DB
    assert 'nc_dhcp_rebuild_all_access_entries' not in DB
    assert 'nc_backup_config("dhcp"' in DB
    assert 'nc_restore_config("dhcp", bak)' in DB


def test_dhcp_put_uses_partial_merge_for_lists() -> None:
    assert 'app_dhcp_merge_partial_payload' in WEBD
    assert 'app_dhcp_scope_get(lan_id)' in WEBD
    assert 'json_object_object_foreach(input_dhcp, key, val)' in WEBD
    assert 'app_ubus_invoke_timeout("dhcp_service_set", merged_body, 15000)' in WEBD


def test_dhcp_apply_failure_restores_database_and_runtime() -> None:
    start = CORE.index("static int dw_handle_dhcp_service_set(")
    end = CORE.index("static int dw_handle_dhcp_reservation_delete(", start)
    handler = CORE[start:end]
    assert "struct json_object *before = jmx_dhcp_service_get()" in handler
    assert 'json_object_object_add(restore, "dhcp", json_object_get(scope))' in handler
    assert "jmx_dhcp_service_set(restore) == 0" in handler
    assert "jmx_dhcp_service_apply(lan_id) == 0" in handler
    assert '"apply_failed_rollback_failed"' in handler
    assert '"dhcp_apply_failed_rollback_failed"' in handler


def test_ipv4_only_dhcp_apply_does_not_depend_on_dhcpv6_runtime() -> None:
    start = DB.index("static int nc_dhcp_access_runtime_loaded(")
    end = DB.index("/* ══════════════════════════════════════════════════════════════════════\n * UPnP", start)
    section = DB[start:end]
    assert 'if (entry_count <= 0)' in section
    assert 'return nc_run_quiet("pidof dnsmasq >/dev/null 2>&1")' in section
    assert 'nc_dhcpv6_static_reservations_present(lan_id)' in section
    assert 'nc_dhcpv6_uci_reservations_present(ctx, pkg, lan_id)' in section
    assert 'if (dhcpv6_static_present) {' in section
    assert 'nc_dhcpv6_static_leases_readback_retry(lan_id)' in section
    assert 'for (attempt = 0; attempt < 3; attempt++)' in section


def test_dhcp_apply_exposes_stage_specific_failure_contract() -> None:
    start = CORE.index("static int dw_handle_dhcp_service_set(")
    end = CORE.index("static int dw_handle_dhcp_reservation_delete(", start)
    handler = CORE[start:end]
    for reason in (
        "dnsmasq_reload_failed",
        "dhcp_access_readback_failed",
        "odhcpd_reload_failed",
        "dhcpv6_readback_failed",
        "dnsmasq_config_generation_failed",
        "dhcpv6_config_generation_failed",
        "dhcp_access_config_generation_failed",
        "dhcp_uci_commit_failed",
    ):
        assert reason in DB
    assert 'jmx_dhcp_service_apply_failure_reason(arc)' in handler
    assert 'jmx_dhcp_service_apply_failure_stage(arc)' in handler
    assert '"apply_failure_reason"' in handler
    assert '"failure_stage"' in handler
    assert '"failure_reason"' in handler
    assert 'if (rc == 0 && arc != 0)' in handler


def test_dhcp_validation_preserves_specific_machine_reason() -> None:
    assert 'static __thread char g_dhcp_set_failure_reason[128]' in DB
    assert 'jmx_dhcp_service_set_failure_reason(void)' in DB
    assert 'return nc_dhcp_set_fail(-2, err)' in DB
    for reason in (
        "invalid_reservation_mac",
        "invalid_reservation_ip",
        "reservation_ip_outside_lan",
        "duplicate_reservation_mac",
        "duplicate_reservation_ip",
        "dhcp_scope_conflict",
    ):
        assert reason in DB
    start = CORE.index("static int dw_handle_dhcp_service_set(")
    end = CORE.index("static int dw_handle_dhcp_reservation_delete(", start)
    handler = CORE[start:end]
    assert 'const char *save_reason = jmx_dhcp_service_set_failure_reason()' in handler


def test_dhcp_save_apply_response_covers_success_and_rollback_outcomes() -> None:
    start = CORE.index("static int dw_handle_dhcp_service_set(")
    end = CORE.index("static int dw_handle_dhcp_reservation_delete(", start)
    handler = CORE[start:end]
    assert 'json_object_new_boolean(rc==0&&arc==0)' in handler
    assert 'json_object_new_boolean(rc==0)' in handler
    assert 'json_object_new_boolean(rolled_back)' in handler
    assert 'jmx_dhcp_service_set(restore) == 0' in handler
    assert 'jmx_dhcp_service_apply(lan_id) == 0' in handler
    assert '"apply_failed_rolled_back"' in handler
    assert '"apply_failed_rollback_failed"' in handler
    assert 'rolled_back ? apply_reason : "dhcp_rollback_failed"' in handler
    assert 'json_object_object_add(data,"readback",readback_data)' in handler


def test_dhcp_delete_preserves_apply_failure_reason() -> None:
    start = CORE.index("static int dw_handle_dhcp_reservation_delete(")
    end = CORE.index("static int dw_handle_firewall_service_get(", start)
    handler = CORE[start:end]
    assert 'jmx_dhcp_service_apply_failure_stage(arc)' in handler
    assert 'jmx_dhcp_service_apply_failure_reason(arc)' in handler



def test_dhcpv6_static_prefix_reservations_contract() -> None:
    assert 'CREATE TABLE IF NOT EXISTS dhcpv6_prefix_reservation' in DB
    assert 'UNIQUE(scope_id, duid)' in DB
    assert 'UNIQUE(scope_id, prefix)' in DB
    assert 'CHECK(prefix_len BETWEEN 33 AND 64)' in DB
    assert 'nc_dhcp_prefixes_from_payload' in DB
    assert 'prefix_reservations_must_be_array' in DB
    assert 'invalid_prefix_duid' in DB
    assert 'invalid_prefix_cidr' in DB
    assert 'prefix_outside_lan_parent' in DB
    assert 'prefix_hostid_mismatch' in DB
    assert 'invalid_prefix_hostid_zero' in DB
    assert 'duplicate_prefix_duid' in DB
    assert 'duplicate_prefix_cidr' in DB
    assert 'DELETE FROM dhcpv6_prefix_reservation WHERE scope_id=?1' in DB
    assert 'INSERT INTO dhcpv6_prefix_reservation' in DB
    assert 'SELECT id,name,duid,iaid,prefix,scope_id,lan_id,hostid,prefix_len' in DB
    assert 'json_object_object_add(s,"prefix_reservations",pfx)' in DB
    assert 'json_object_object_add(data,"prefix_reservations",top_pfx)' in DB
    assert 'nc_dhcpv6_rebuild_all_prefix_reservations(ctx, pkg)' in DB
    assert 'nc_uci_delete_managed_sections(ctx, pkg, "dhcp", "host", "dw_pd_")' in DB
    assert 'nc_uci_add_list_pkg(ctx, "dhcp", sec, "duid", duid_with_iaid)' in DB
    assert 'nc_uci_set_pkg(ctx, "dhcp", sec, "hostid", hostid)' in DB
    assert 'nc_uci_set_pkg(ctx, "dhcp", sec, "pd_prefixlen", b)' in DB
    assert 'nc_uci_set_pkg(ctx, "dhcp", sec, "pd_interface", lan_id)' in DB
    assert 'nc_uci_set_pkg(ctx, "dhcp", sec, "pd_only", "1")' in DB
    assert "subnet = (ph ^ parent_high)" in DB
    assert "slot_bits = 64 - parent_len" in DB
    assert "nc_dhcpv6_parent_prefix_for_child" in DB
    assert "ipv6-prefix-assignment" in DB
    assert "json_object_object_get_ex(root, \"leases\", &leases)" in DB
    assert "runtime_configured=1,runtime_bound=?1" in DB
    assert "sqlite3_column_int(st, 0) != configured_count" in DB
    assert 'ubus -S call dhcp static_leases' in DB
    assert "runtime_configured=1,runtime_bound=?1" in DB
    assert 'no active lease' not in DB.lower()
    assert 'odhcpd reload >/tmp/dw-odhcpd-apply.log' in DB
    assert 'odhcpd reload >/tmp/dw-odhcpd-rollback.log' in DB
    assert 'prefix_reservations/prefixes' in CORE
    assert 'json_object_object_add(scope, "prefix_reservations", json_object_get(val))' in WEBD
    assert 'json_object_object_add(scope, "prefixes", json_object_get(val))' in WEBD

if __name__ == "__main__":
    test_dhcp_get_has_unambiguous_structured_contract()
    test_dhcp_apply_rebuilds_all_scope_reservations_and_checks_reload()
    test_reservation_delete_resolves_scope_and_checks_changes()
    test_standalone_rest_routes_use_core_contract()
    test_dhcp_allow_deny_list_persisted_validated_and_applied()
    test_dhcp_put_uses_partial_merge_for_lists()
    test_dhcp_apply_failure_restores_database_and_runtime()
    test_ipv4_only_dhcp_apply_does_not_depend_on_dhcpv6_runtime()
    test_dhcp_apply_exposes_stage_specific_failure_contract()
    test_dhcp_validation_preserves_specific_machine_reason()
    test_dhcp_save_apply_response_covers_success_and_rollback_outcomes()
    test_dhcp_delete_preserves_apply_failure_reason()
    test_dhcpv6_static_prefix_reservations_contract()
    print("ok: DHCP standalone REST, apply, readback, and reservation contracts")

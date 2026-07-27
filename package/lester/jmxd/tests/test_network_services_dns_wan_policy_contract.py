#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DB = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")
CORE = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
WEBD = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")


def section(text: str, start: str, end: str) -> str:
    pos = text.index(start)
    return text[pos:text.index(end, pos)]


def test_get_is_scoped_by_wan_and_reports_real_capabilities() -> None:
    policy_get = section(DB, "struct json_object *jmx_wan_dns_policy_get(",
                         "int jmx_wan_dns_policy_set(")
    assert 'WHERE wan_id=?1' in policy_get
    assert '"read_by_wan", json_object_new_boolean(1)' in policy_get
    assert '"read_all", json_object_new_boolean(0)' in policy_get
    assert '"domains", json_object_new_boolean(1)' in policy_get
    assert '"domain_split_ipv4", json_object_new_boolean(1)' in policy_get
    assert '"domain_split_ipv6", json_object_new_boolean(0)' in policy_get
    assert '"wan_dns_policy_not_found"' in policy_get

    route = section(WEBD, 'else if (!strcmp(req.path, "/api/v1/services/dns/wan-policy")',
                    "/* ── AI Config & Tools ── */")
    assert 'webd_query_get(req.query, "wan_id"' in route
    assert '"wan_id_required"' in route
    assert 'app_ubus_invoke("wan_dns_policy_get", params)' in route


def test_write_validates_domain_runtime_semantics() -> None:
    validate = section(DB, "static int nc_wan_dns_policy_validate(",
                       "int jmx_wan_dns_policy_set(")
    assert 'SELECT 1 FROM route_wan WHERE name=?1 AND fwmark>0 AND table_id>0' in validate
    assert 'nc_wan_dns_domain_owned_elsewhere' in DB
    assert 'domain_count && strcmp(mode, "custom") && strcmp(mode, "upstream")' in validate
    assert 'json_object_array_length(domains) > 128' in validate
    assert "protocol IN ('udp','tcp')" in validate
    assert 'nc_dns_is_ip_literal(server)' in validate
    assert 'domain_count && !nc_dns_is_ipv4_literal(server)' in validate
    assert 'supported = !domain_count || nc_dns_is_ipv4_literal(address)' in validate
    assert 'json_object_array_length(arr) > 64' in validate
    assert '"wan_dns_policy_route_wan_not_ready"' in DB
    assert '"wan_dns_policy_upstream_unsupported"' in DB
    assert 'changed == 1' in DB
    apply = section(DB, "static int nc_apply_wan_dns_policy(",
                    "static void nc_apply_wan_advanced(")
    assert 'nc_uci_set_pkg(ctx, "network", wan_id, "peerdns", "0")' in apply
    assert 'nc_uci_delete_pkg(ctx, "network", wan_id, "dns")' in apply
    assert 'if (domain_scoped)' in apply
    assert 'nc_uci_ensure_section(ctx, NULL, "dhcp"' not in apply


def test_domain_split_uses_dnsmasq_nftset_and_existing_route_marks() -> None:
    assert 'NC_DNS_ROUTE_BEGIN' in DB
    assert 'nc_uci_delete_managed_sections(ctx, pkg, "dhcp", "ipset", "dw_dns_")' in DB
    assert 'nc_uci_set_pkg(ctx, "dhcp", section, "table", "dreamingwrt_dns_route")' in DB
    assert 'nc_uci_set_pkg(ctx, "dhcp", section, "family", "4")' in DB
    assert 'server=/%s/%s%s%d@%s' in DB
    assert 'nc_dns_route_apply()' in DB
    assert 'if (route_count > 0)' in DB
    assert 'block = calloc(1, 1)' in DB
    assert 'static int nc_dnsmasq_wait_ready(void)' in DB
    assert 'static int nc_dnsmasq_process_running(void)' in DB
    assert 'socket(AF_INET, SOCK_DGRAM, 0)' in DB
    assert 'sendto(fd, query, sizeof(query)' in DB
    assert 'response[0] == query[0]' in DB
    assert 'nc_dnsmasq_restart_wait("/tmp/dw-dns-route-reload.log")' in DB
    assert 'jmx_api_route_reload(NULL)' in DB
    routed = (ROOT / "src/routed/jmx_route.c").read_text(encoding="utf-8")
    assert 'JMX_ROUTE_DNS_NFT_TABLE "dreamingwrt_dns_route"' in routed
    assert 'SELECT DISTINCT wan_id FROM wan_dns_policy' in routed
    assert 'ip daddr @wan_%u_v4 meta mark set 0x%x counter' in routed
    assert 'priority mangle + 2' in routed
    assert 'map[i].fwmark = fwmark' in routed
    assert 'route_dns_domain_nft_table_exists' in routed
    assert 'flush chain inet %s prerouting' in routed
    assert 'delete set inet %s wan_%u_v4' in routed
    assert 'destroy table inet %s' not in routed


def test_aggregate_dns_compatibility_preserves_domain_scoped_policies() -> None:
    legacy_save = section(DB, "int jmx_wan_dns_split_save_from_array(",
                          "static int nc_apply_wan_dns_policy(")
    assert "DELETE FROM wan_dns_policy WHERE domains IS NULL OR domains='' OR domains='[]'" in legacy_save
    assert 'DELETE FROM wan_dns_policy WHERE 1=1' not in legacy_save
    aggregate = section(DB, "static void nc_dns_add_wan_dns(",
                        "/* ── UPnP mappings CRUD ── */")
    assert 'json_object_array_length(domains) == 0' in aggregate
    assert 'p0 = candidate' in aggregate
    assert '"wan_policy_domains", json_object_new_boolean(1)' in DB
    assert '"wan_policy_domain_split_ipv4", json_object_new_boolean(1)' in DB
    assert '"wan_policy_domain_split_ipv6", json_object_new_boolean(0)' in DB


def test_write_and_delete_apply_with_restore_and_readback() -> None:
    save = section(DB, "struct json_object *jmx_wan_dns_policy_save_apply_result(",
                   "struct json_object *jmx_wan_dns_policy_delete_apply_result(")
    delete = section(DB, "struct json_object *jmx_wan_dns_policy_delete_apply_result(",
                     "static const char *nc_dns_split_mode_to_policy")
    for body in (save, delete):
        assert 'need_wan_apply ? jmx_netconfig_apply_wan(wan_id) : 0' in body
        assert 'jmx_wan_dns_policy_set(wan_id, restore)' in body
        assert 'rolled_back = 1' in body
    assert 'nc_wan_dns_policies_need_wan_apply' in DB
    assert '"runtime_rolled_back"' in DB
    assert '"readback"' in DB
    assert 'jmx_wan_dns_policy_save_apply_result' in CORE
    assert 'jmx_wan_dns_policy_delete_apply_result' in CORE
    assert 'app_ubus_invoke_timeout("wan_dns_policy_set", body_json, 30000)' in WEBD
    assert 'app_ubus_invoke_timeout("wan_dns_policy_delete", params, 30000)' in WEBD


def test_dns_service_does_not_advertise_absent_collectors_or_transports() -> None:
    caps = section(DB, "static void nc_dns_add_caps(",
                   "struct json_object *jmx_dns_service_get(")
    assert '"live_stats", json_object_new_boolean(0)' in caps
    assert '"doh", json_object_new_boolean(0)' in caps
    assert '"dot", json_object_new_boolean(0)' in caps
    assert 'json_object_new_string("doh")' not in caps
    assert 'json_object_new_string("dot")' not in caps


if __name__ == "__main__":
    test_get_is_scoped_by_wan_and_reports_real_capabilities()
    test_write_validates_domain_runtime_semantics()
    test_domain_split_uses_dnsmasq_nftset_and_existing_route_marks()
    test_aggregate_dns_compatibility_preserves_domain_scoped_policies()
    test_write_and_delete_apply_with_restore_and_readback()
    test_dns_service_does_not_advertise_absent_collectors_or_transports()
    print("ok: DNS WAN policy read, validation, apply, rollback, and capability contracts")

#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DB = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")
CORE = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
COMMON = (ROOT / "src/jmx_ubus.c").read_text(encoding="utf-8")
WEBD = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")


def section(text: str, start: str, end: str) -> str:
    begin = text.index(start)
    return text[begin:text.index(end, begin)]


def test_unsupported_mutations_fail_before_storage_transaction() -> None:
    setter = section(DB, "static int nc_dns_service_set_internal(",
                     "int jmx_dns_service_set(")
    begin = setter.index('nc_exec("BEGIN IMMEDIATE")')
    assert setter.index("nc_dns_complete_snapshot(cfg)") < begin
    assert setter.index("nc_dns_request_capability_check(cfg)") < begin
    assert setter.index("nc_dns_listen_interfaces_valid(cfg)") < begin
    assert 'return -7' in setter
    assert 'return -8' in setter

    gate = section(DB, "static int nc_dns_request_capability_check(",
                   "static int nc_dns_service_set_internal(")
    assert 'strcmp(requested_mode, "proxy")' in gate
    assert 'json_object_get_boolean(value)' in gate
    assert "!= hijack" not in gate
    assert "!= ecs" not in gate
    assert "!= ipv6_dns" not in gate
    assert '"dot"' in gate and '"doh"' in gate
    assert "transition_allowed" in gate
    assert "AND protocol=?5 AND group_name=?6 LIMIT 1" in gate
    assert "return -4" in gate

    response = section(DB, "struct json_object *jmx_dns_service_save_apply_result(",
                       "int jmx_dns_upstream_set(")
    assert '"dns_snapshot_incomplete"' in response
    assert '"dns_listen_interface_invalid"' in response
    assert '"complete_dns_rollback_snapshot_unavailable"' in response
    assert '"capability_disabled"' in response
    assert '"dns_transport"' in response
    assert '"request_validation_failed_before_write"' in response


def test_complete_snapshot_and_resource_validation_are_strict() -> None:
    complete = section(DB, "static int nc_dns_complete_snapshot(",
                       "static int nc_dns_listen_interfaces_valid(")
    for field in (
        "enabled", "mode", "listen_port", "cache_enabled", "cache_size",
        "local_domain", "rebind_protection", "hijack_protection",
        "edns_client_subnet", "ipv6_dns", "listen_interfaces", "upstreams",
        "rules",
    ):
        assert f'"{field}"' in complete
    assert complete.count("json_type_array") >= 3

    listeners = section(DB, "static int nc_dns_listen_interfaces_valid(",
                        "static void nc_dns_apply_state_set(")
    assert "if (enabled && n == 0)" in listeners
    assert "SELECT 1 FROM lan WHERE id=?1 AND enabled=1 LIMIT 1" in listeners
    assert "previous" in listeners

    validation = section(DB, "static int nc_dns_service_set_internal(",
                         "int jmx_dns_service_set(")
    assert "nc_dns_valid_upstream_request" in validation
    assert "nc_dns_valid_domain_rule" in validation
    assert "strchr(local_domain, ':')" in validation
    assert "duplicate" not in validation.lower()  # comparison is structural, not a warning-only path
    assert "for (int j = 0; j < i; j++)" in validation


def test_sqlite_replace_and_aggregate_transactions_check_every_boundary() -> None:
    setter = section(DB, "static int nc_dns_service_set_internal(",
                     "int jmx_dns_service_set(")
    for table in ("dns_listen_interface", "dns_upstream", "dns_rule"):
        assert f'DELETE FROM {table}' in setter
    assert 'if (nc_step_done(st) != 0) rc = -1' in setter
    assert 'if (rc == 0 && nc_exec("COMMIT") != 0) rc = -1' in setter
    assert 'if (rc != 0) nc_exec("ROLLBACK")' in setter

    aggregate = section(DB, "int jmx_wan_dns_split_save_from_array(",
                        "static int nc_apply_wan_dns_policy(")
    assert "DELETE FROM wan_dns_policy WHERE domains IS NULL" in aggregate
    assert 'rc = nc_step_done(st)' in aggregate
    assert 'if (rc == 0 && nc_exec("COMMIT") != 0) rc = -1' in aggregate
    assert 'if (rc != 0) nc_exec("ROLLBACK")' in aggregate
    assert 'DELETE FROM wan_dns_policy WHERE 1=1' not in aggregate


def test_apply_has_uci_backup_restart_dns_query_readback_and_rollback() -> None:
    apply = section(DB, "int jmx_dns_service_apply(void)",
                    "/* ══════════════════════════════════════════════════════════════════════")
    assert 'nc_backup_config("dhcp"' in apply
    assert 'if (nc_backup_config("dhcp"' in apply
    assert 'jmx_uci_commit(ctx, "dhcp")' in apply
    assert 'nc_dnsmasq_restart("/tmp/dw-dns-service-apply.log")' in apply
    assert "nc_dns_runtime_ready(port, 1)" in apply
    assert 'nc_restore_config("dhcp", bak_dhcp)' in apply
    assert 'nc_dnsmasq_restart("/tmp/dw-dns-service-rollback.log")' in apply
    assert '!strcmp(type, "forward") || !strcmp(type, "upstream")' in apply
    assert '!strcmp(proto, "doh") || !strcmp(proto, "dot")' in apply
    assert "continue;" in apply
    assert 'nc_dns_apply_state_set(degraded ? "degraded" : "applied"' in apply

    runtime = section(DB, "static int nc_dnsmasq_process_running(",
                      "static int nc_dnsmasq_restart_wait(")
    assert 'opendir("/proc")' in runtime
    assert '!strcmp(comm, "dnsmasq")' in runtime
    assert "socket(AF_INET, SOCK_DGRAM, 0)" in runtime
    assert "sendto(fd, query, sizeof(query)" in runtime
    assert "poll(&pfd, 1, 250)" in runtime
    assert "response[0] == query[0]" in runtime
    assert "attempts = wait_for_ready ? 50 : 1" in runtime


def test_get_and_write_response_do_not_claim_fake_applied_state() -> None:
    get = section(DB, "struct json_object *jmx_dns_service_get(void)",
                  "static int nc_dns_request_capability_check(")
    assert "nc_dns_runtime_ready(listen_port, 0)" in get
    assert "nc_dns_config_degraded_reason" in get
    assert '"valid"' in get
    assert '"degraded"' in get
    assert '"configuration_supported"' in get
    assert '"dnsmasq_process+dns_query:127.0.0.1:configured_port"' in get
    assert 'json_object_new_boolean(1));\n    json_object_object_add(data, "applied"' not in get

    response = section(DB, "struct json_object *jmx_dns_service_save_apply_result(",
                       "int jmx_dns_upstream_set(")
    assert '"supported_subset_applied"' in response
    assert 'apply && applied == 0 && !degraded' in response
    assert 'degraded ? "degraded" : apply ? "applied" : "saved"' in response
    assert "nc_dns_restore_snapshot(before)" in response
    assert "!before || !nc_dns_snapshot_restorable(before)" in response
    assert "nc_dns_snapshot_restorable(snapshot)" in DB
    assert '"runtime_rolled_back"' in response
    assert 'API_CODE_SUCCESS : API_CODE_ERROR' in response

    caps = section(DB, "static void nc_dns_add_caps(",
                   "struct json_object *jmx_dns_service_get(")
    for capability in ("doh", "dot", "hijack_protection", "ecs", "ipv6_dns",
                       "save_dns_rule", "delete_dns_rule"):
        assert f'"{capability}", json_object_new_boolean(0)' in caps
    assert '"upstreams_bulk_update", json_object_new_boolean(1)' in caps
    assert '"rules_bulk_update", json_object_new_boolean(1)' in caps


def test_legacy_direct_writes_are_disabled_at_every_formal_entry() -> None:
    assert "dw_dns_direct_write_disabled_response" in CORE
    for handler in ("dw_handle_dns_upstream_set", "dw_handle_dns_rule_set",
                    "dw_handle_dns_rule_save", "dw_handle_dns_rule_delete",
                    "dw_handle_dns_rule_delete_save"):
        body = section(CORE, f"static int {handler}(", "return 0;")
        assert "dw_dns_direct_write_disabled_response" in body
    assert '"persisted", json_object_new_boolean(0)' in CORE
    assert '"applied", json_object_new_boolean(0)' in CORE

    assert '"dreamingwrt_dns_upstream_set", jmx_api_dns_direct_write_disabled' in COMMON
    assert '"dreamingwrt_dns_rule_set", jmx_api_dns_direct_write_disabled' in COMMON
    assert '"dreamingwrt_dns_rule_delete", jmx_api_dns_direct_write_disabled' in COMMON

    routes = section(WEBD, "/* ── DNS service ── */",
                     "/* ── AI Config & Tools ── */")
    assert routes.count('status = 409;') >= 2
    assert routes.count('"capability_disabled"') >= 2
    assert "jmx_dns_rule_set(" not in routes
    assert "jmx_dns_rule_delete(" not in routes


def test_ai_and_web_use_only_the_canonical_transaction() -> None:
    dispatch = section(DB, "static struct json_object *nc_ai_tool_dispatch(",
                       "static struct json_object *nc_ai_tool_dispatch_redacted(")
    assert 'return jmx_dns_service_save_apply_result(params, 1)' in dispatch
    assert 'if (!strcmp(module, "dns"))' in dispatch
    assert '"DNS apply requires a complete transactional configuration payload"' in dispatch

    routes = section(WEBD, "/* ── DNS service ── */",
                     "/* ── AI Config & Tools ── */")
    assert 'app_ubus_invoke("dns_service_save_apply_result", body_json)' in routes
    assert "status = app_response_status(resp, status)" in routes
    assert '"dns_snapshot_incomplete"' in WEBD
    assert '"dns_listen_interface_invalid"' in WEBD
    assert "return 422" in WEBD


def test_dns_compat_migration_repairs_legacy_defaults_once() -> None:
    migration = section(DB, "static int nc_dns_config_compat_migrate_once(",
                        "/* ══════════════════════════════════════════════════════════════════════\n * Init / Close")
    assert "NC_DNS_CONFIG_COMPAT_MIGRATION" in migration
    assert "mode='proxy',hijack_protection=0" in migration
    assert "edns_client_subnet=0,ipv6_dns=0" in migration
    assert "INSERT OR IGNORE INTO dns_listen_interface" in migration
    assert "CASE WHEN id='lan' THEN 0 ELSE 1 END" in migration
    assert "if (!listener_seeded)" in migration
    assert "INSERT INTO config_migration" in migration

    init = section(DB, "int jmx_netconfig_db_init(void)",
                   "static int nc_work_mode_import_uci_once(")
    assert init.index("jmx_netconfig_migrate_from_uci()") < init.index(
        "nc_dns_config_compat_migrate_once()")


def test_dns_listener_runtime_reasons_distinguish_missing_and_invalid() -> None:
    listeners = section(DB, "enum nc_dns_listener_state {",
                        "static int nc_dns_complete_snapshot(")
    assert "NC_DNS_LISTENER_NOT_CONFIGURED" in listeners
    assert "NC_DNS_LISTENER_INVALID" in listeners
    assert '"dns_listen_interface_not_configured"' in listeners
    assert '"dns_listen_interface_invalid"' in listeners
    assert "if (total == 0)" in listeners


if __name__ == "__main__":
    test_unsupported_mutations_fail_before_storage_transaction()
    test_complete_snapshot_and_resource_validation_are_strict()
    test_sqlite_replace_and_aggregate_transactions_check_every_boundary()
    test_apply_has_uci_backup_restart_dns_query_readback_and_rollback()
    test_get_and_write_response_do_not_claim_fake_applied_state()
    test_legacy_direct_writes_are_disabled_at_every_formal_entry()
    test_ai_and_web_use_only_the_canonical_transaction()
    test_dns_compat_migration_repairs_legacy_defaults_once()
    test_dns_listener_runtime_reasons_distinguish_missing_and_invalid()
    print("ok: DNS service save/apply/readback/rollback and capability contracts")

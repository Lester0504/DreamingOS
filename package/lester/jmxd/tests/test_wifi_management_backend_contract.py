#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NETCONFIG = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")
API = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
SETUP = (ROOT / "src/jmx_setup.c").read_text(encoding="utf-8")
WEBD = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text(encoding="utf-8")
AGGREGATE = (ROOT / "src/webd/webd_wifi_aggregate.c").read_text(encoding="utf-8")


def test_config_contract_is_versioned_and_revisioned() -> None:
    assert '"contract_version",json_object_new_string("wifi-management.v1")' in NETCONFIG
    assert '"revision",json_object_new_int64(nc_wifi_revision())' in NETCONFIG
    assert "static sqlite3_int64 nc_wifi_revision(void)" in NETCONFIG


def test_capabilities_describe_real_closure_not_route_presence() -> None:
    for capability in (
        "read_config",
        "runtime_status",
        "save_config",
        "apply_config",
        "ssid_create",
        "ssid_update",
        "ssid_delete",
        "radio_update",
        "global_update",
        "speed_limit_create",
        "speed_limit_update",
        "speed_limit_delete",
        "ap_groups",
        "ppsk",
        "radius_mac_auth",
        "schedules",
        "mlo",
        "scan",
        "scan_jobs",
        "airview_realtime",
        "airview_history",
        "websocket",
    ):
        assert f'"{capability}"' in NETCONFIG
    assert '"runtime_dependencies"' in NETCONFIG
    assert '"reasons"' in NETCONFIG
    assert '"transactional_apply_readback_pending"' in NETCONFIG
    # save_config / apply_config are no longer hardcoded to 0: the local-phy
    # write path preserves secrets through the AEAD vault and verifies apply by
    # readback.  What must stay true is that the bits are *computed* from real
    # preconditions rather than asserted, and that each failure still names a
    # cause.  The old "transactional_secret_safe_save_pending" reason belongs to
    # the ubus rejection path in jmx_dreamingwrt_api.c, which still fires when
    # jmx_wifi_config_save() refuses.
    assert 'nc_wifi_add_capability(cap, reasons, "save_config", local_write' in NETCONFIG
    assert '"secret_vault_unavailable"' in NETCONFIG
    # Reporting a capability must not have side effects: the capability path
    # uses the read-only probe, so a plain GET cannot generate key material.
    # Only the save path may create the key on first use.
    assert 'int vault_ok = nc_wifi_secret_key_present() == 0;' in NETCONFIG
    # Slice the *definition*, not the forward declaration: splitting on the bare
    # signature lands on the prototype near the top of the file and yields an
    # empty body, which made this assertion pass no matter what the probe did.
    probe = NETCONFIG.split(
        "static int nc_wifi_secret_key_present(void)\n{")[1].split("\n}")[0]
    assert "ac_secrets_open(" in probe, "probe must open the vault to report on it"
    assert "ac_secrets_open_or_create" not in probe, (
        "the read-only probe must not create the vault key"
    )
    assert '"transactional_secret_safe_save_pending"' in API


def test_disabled_capabilities_never_report_successful_write_apply_or_scan() -> None:
    assert "if(nc_wifi_phy_count()<=0)return -2;" in NETCONFIG
    assert 'json_object_object_add(data, "reason", json_object_new_string("no_phy_detected"))' in API
    assert '"apply_state",json_object_new_string("rejected")' in NETCONFIG
    assert '"supported", json_object_new_boolean(0)' in NETCONFIG
    assert 'nc_wifi_add_capability(cap, reasons, "scan", 0' in NETCONFIG
    assert '"error", json_object_new_string("capability_disabled")' in NETCONFIG
    assert '"invoked", json_object_new_boolean(0)' in NETCONFIG


def test_setup_and_read_paths_preserve_wifi_state() -> None:
    assert 'nc_setup_save_draft("wifi"' not in SETUP
    assert 'nc_setup_wifi_capability("save_config")' in SETUP
    assert 'nc_setup_wifi_capability("apply_config")' in SETUP
    assert '"partial_apply", json_object_new_boolean(0)' in SETUP
    assert "nc_wifi_sync_from_uci" not in NETCONFIG
    config_start = NETCONFIG.index("jmx_wifi_config_get(void)")
    config_end = NETCONFIG.index("int jmx_wifi_config_save", config_start)
    assert "nc_wifi_db_init" not in NETCONFIG[config_start:config_end]


def test_no_phy_config_does_not_publish_stale_radio_or_ssid_rows() -> None:
    assert '"radios",phy_count>0?nc_wifi_rows("radios"):json_object_new_array()' in NETCONFIG
    assert '"ssids",phy_count>0?nc_wifi_rows("ssids"):json_object_new_array()' in NETCONFIG
    assert 'json_object_new_int(wifi_available?maxw:0)' in NETCONFIG
    assert 'if(wifi_available&&c2' in NETCONFIG


def test_rest_routes_and_rbac_are_explicit() -> None:
    for path in (
        "/api/v1/wifi/config",
        "/api/v1/wifi/config/apply",
        "/api/v1/wifi/status",
        "/api/v1/wifi/scan",
        "/api/v1/wifi/scan/jobs",
    ):
        assert path in WEBD
    assert '{ "/api/v1/wifi/config",       "POST,PUT,PATCH,DELETE", JMX_RISK_MEDIUM }' in PERMS
    assert '{ "/api/v1/wifi/config/apply", "POST,PUT", JMX_RISK_MEDIUM }' in PERMS
    assert '{ "/api/v1/wifi/scan",         "POST,PUT", JMX_RISK_MEDIUM }' in PERMS
    assert '{ "/api/v1/wifi/scan/jobs",    "GET,HEAD", JMX_RISK_LOW }' in PERMS
    assert '{ "/api/v1/wifi/scan/jobs/",   "DELETE", JMX_RISK_MEDIUM }' in PERMS


def test_local_and_managed_wifi_are_aggregated_without_frontend_fanout() -> None:
    assert 'webd_wifi_aggregate_response(0)' in WEBD
    assert 'webd_wifi_aggregate_response(1)' in WEBD
    assert '"dreamingwrt.ac", "aps_list"' in WEBD
    assert '"wifi-management.v2"' in AGGREGATE
    assert '"local:radio:%s"' in AGGREGATE
    assert '"ap:%s:%s:%s"' in AGGREGATE
    for field in (
        '"local_wifi"', '"managed_aps"', '"remote_telemetry"',
        '"mixed_source"', '"configured_enabled"',
    ):
        assert field in AGGREGATE


def test_bootstrap_and_menu_use_effective_wifi_capability() -> None:
    assert 'webd_managed_wifi_supported()' in WEBD
    assert '"dreamingwrt.ac", "status"' in WEBD
    assert 'webd_wifi_managed_available(status)' in WEBD
    assert 'jmx_cache_get_allow_stale("managed_wifi_capability", 360' in WEBD
    assert 'if (cached && !stale)' in WEBD
    assert 'if (!status)' in WEBD
    assert 'jmx_cache_put_with_stale("managed_wifi_capability", value, 10, 360)' in WEBD
    assert '"local_wifi"' in WEBD
    assert '"managed_wifi"' in WEBD
    assert 'webd_json_array_remove_string(hide_funcs, "wireless_status")' in WEBD
    assert 'webd_json_array_remove_string(hide_funcs, "wifi")' in WEBD
    assert 'webd_json_array_remove_string(disabled_caps, "wifi")' in WEBD


def test_managed_ap_read_route_is_explicit() -> None:
    assert '"/api/v1/ac/aps"' in WEBD
    assert '"aps_list"' in WEBD
    assert '{ "/api/v1/ac/aps",            "GET,HEAD", JMX_RISK_LOW }' in PERMS


def test_environment_and_scan_job_contracts_are_truthful() -> None:
    for field in (
        '"channel_survey"', '"survey_history"', '"neighbor_scan"',
        '"spectral_fft"', '"neighbor_bssid_scan_producer_pending"',
        '"spectral_fft_driver_producer_pending"',
    ):
        assert field in AGGREGATE
    for field in (
        '"radio_job_create"', '"radio_job_list"', '"radio_job_status"',
        '"radio_job_result"', '"radio_job_cancel"',
    ):
        assert field in WEBD
    ac_protocol = (ROOT / "src/ac/ac_protocol.c").read_text(encoding="utf-8")
    assert '"scan_execution", scan_execution' in ac_protocol
    assert '"scan_dispatch", scan_execution' in ac_protocol
    assert '"no_online_ap_control_v2_session"' in ac_protocol


if __name__ == "__main__":
    test_config_contract_is_versioned_and_revisioned()
    test_capabilities_describe_real_closure_not_route_presence()
    test_disabled_capabilities_never_report_successful_write_apply_or_scan()
    test_setup_and_read_paths_preserve_wifi_state()
    test_no_phy_config_does_not_publish_stale_radio_or_ssid_rows()
    test_rest_routes_and_rbac_are_explicit()
    test_bootstrap_and_menu_use_effective_wifi_capability()
    test_environment_and_scan_job_contracts_are_truthful()
    print("ok: Wi-Fi capability, setup, read-only GET, scan, revision, REST, and RBAC contract")

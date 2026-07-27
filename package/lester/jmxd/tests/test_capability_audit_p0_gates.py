#!/usr/bin/env python3
"""Regression gates for P0 capability-audit safety invariants."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEBD = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
CORE = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")
UBUS = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
SETUP = (ROOT / "src/jmx_setup.c").read_text(encoding="utf-8")
AC_PROTOCOL = (ROOT / "src/ac/ac_protocol.c").read_text(encoding="utf-8")
LEGACY_WEB_PATH = ROOT / "src/jmx_app_api.c"
LEGACY_WEB = (LEGACY_WEB_PATH.read_text(encoding="utf-8")
              if LEGACY_WEB_PATH.is_file() else "")


def body(source: str, name: str) -> str:
    marker = f"{name}("
    start = source.index(marker)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace : index + 1]
    raise AssertionError(f"unterminated function: {name}")


def test_config_tasks_cannot_delete_rollback_journal() -> None:
    reject = body(WEBD, "jmx_tasks_delete_rejected")
    route = WEBD[WEBD.index('!strncmp(req.path, "/api/v1/tasks/"'):]
    route = route[: route.index("/* ── RADIUS servers")]
    assert "DELETE FROM config_apply_tasks" not in WEBD
    assert "DELETE FROM config_apply_tasks" not in LEGACY_WEB
    assert "task_active" in reject
    assert "task_purge_not_supported" in reject
    assert "confirm_before" in reject
    assert 'json_object_new_string("confirm")' in reject
    assert 'json_object_new_string("rollback")' in reject
    assert '"snapshot_available"' in reject
    assert '"snapshot_preserved", json_object_new_boolean(1)' in reject
    assert "jmx_tasks_delete_rejected(tid, &status)" in route
    if LEGACY_WEB:
        legacy_delete = body(LEGACY_WEB, "jmx_tasks_delete")
        assert "return -2;" in legacy_delete
        assert 'json_object_new_string(rc == -2 ? "task_purge_not_supported"' in LEGACY_WEB


def test_wifi_false_capability_is_enforced_at_rest_and_ubus() -> None:
    save = body(CORE, "jmx_wifi_config_save")
    apply = body(CORE, "jmx_wifi_config_apply")
    ubus_save = body(UBUS, "dw_handle_wifi_config_save")
    wifi_routes = WEBD[WEBD.index('!strcmp(req.path, "/api/v1/wifi/config")'):]
    wifi_routes = wifi_routes[: wifi_routes.index("/* ── Multicast")]
    assert "return -3;" in save
    assert save.index("return -3;") < save.index("BEGIN IMMEDIATE")
    assert '"capability_disabled"' in apply
    assert '"persisted"' in apply and '"applied"' in apply
    assert '"capability_disabled"' in ubus_save
    assert 'app_ubus_invoke("wifi_config_save"' not in wifi_routes
    assert 'app_ubus_invoke("wifi_config_apply"' not in wifi_routes
    assert wifi_routes.count('webd_error("capability_disabled"') >= 2
    assert wifi_routes.count("status = 409") >= 2


def test_wifi_setup_scan_and_read_paths_cannot_bypass_capabilities() -> None:
    setup_save = body(SETUP, "jmx_setup_save_wifi")
    setup_apply = body(SETUP, "jmx_setup_apply")
    scan = body(CORE, "jmx_wifi_scan")
    config_get = body(CORE, "jmx_wifi_config_get")
    public_setup = WEBD[WEBD.index("int setup_public_write ="):]
    public_setup = public_setup[: public_setup.index("/* ── All remaining routes require Bearer token")]
    setup_routes = WEBD[WEBD.index('!strcmp(req.path, "/api/v1/setup/save-wifi")'):]
    setup_routes = setup_routes[: setup_routes.index('!strcmp(req.path, "/api/v1/setup/security")')]
    wifi_routes = WEBD[WEBD.index('!strcmp(req.path, "/api/v1/wifi/config")'):]
    wifi_routes = wifi_routes[: wifi_routes.index("/* ── Multicast")]

    assert 'nc_setup_wifi_capability("save_config")' in setup_save
    assert 'nc_setup_save_draft("wifi"' not in setup_save
    assert '"persisted", json_object_new_boolean(0)' in SETUP
    assert '"applied", json_object_new_boolean(0)' in SETUP
    assert '"partial_apply", json_object_new_boolean(0)' in setup_apply
    assert setup_apply.index('nc_setup_wifi_capability("save_config")') < setup_apply.index("jmx_netconfig_wan_set")
    assert setup_apply.index('nc_setup_wifi_capability("apply_config")') < setup_apply.index("jmx_netconfig_lan_set")
    assert 'app_ubus_or_error("setup_save_wifi"' not in public_setup
    assert 'app_ubus_or_error("setup_save_wifi"' not in setup_routes
    assert "app_wifi_capability_disabled_response" in public_setup
    assert "status = 409" in setup_routes

    assert '"capability_disabled"' in scan
    assert '"scan_jobs"' in scan
    assert '"invoked", json_object_new_boolean(0)' in scan
    assert "popen(" not in scan and "system(" not in scan
    assert 'app_ubus_invoke("wifi_config_scan"' not in wifi_routes
    scan_routes = wifi_routes[wifi_routes.index('/api/v1/wifi/scan'):]
    assert '"radio_job_create"' in scan_routes
    assert '"radio_job_list"' in scan_routes
    assert '"radio_job_status"' in scan_routes
    assert '"radio_job_result"' in scan_routes
    assert '"radio_job_cancel"' in scan_routes
    assert '"scan_dispatch", scan_execution' in AC_PROTOCOL
    assert '"scan_execution", scan_execution' in AC_PROTOCOL
    assert '"no_online_ap_control_v2_session"' in AC_PROTOCOL

    assert "nc_wifi_sync_from_uci" not in CORE
    assert "nc_wifi_db_init" not in config_get
    assert "INSERT OR REPLACE INTO wifi_radios" not in config_get
    assert "INSERT OR REPLACE INTO wifi_ssids" not in config_get


def test_placeholder_backup_and_shell_plugin_actions_are_disabled() -> None:
    backup = body(CORE, "jmx_system_backup_create")
    plugin = body(CORE, "jmx_plugin_action")
    plugin_ubus = body(UBUS, "dw_handle_plugin_action")
    plugin_routes = WEBD[WEBD.index('!strcmp(req.path, "/api/v1/plugins/native")'):]
    plugin_routes = plugin_routes[: plugin_routes.index("/* ── VPN config")]
    assert "DreamingWrt backup placeholder" not in CORE
    assert '"deprecated_path_disabled"' in backup
    assert '"artifact_created"' in backup
    assert '"/api/v1/system/config-backups"' in backup
    assert "fopen(" not in backup and "INSERT INTO system_backup_history" not in backup
    assert "return -2;" in plugin
    assert "system(" not in plugin
    assert "opkg " not in plugin
    assert "/etc/init.d/%s" not in plugin
    assert '"capability_disabled"' in plugin_ubus
    plugin_list = body(CORE, "jmx_plugins_list")
    native_list = body(WEBD, "webd_native_plugins_data")
    assert '"actions", json_object_new_boolean(0)' in plugin_list
    assert '"trusted_catalog_job_pipeline_pending"' in plugin_list
    assert '"actions", json_object_new_boolean(0)' in native_list
    assert 'app_ubus_ok_only("plugin_action"' not in plugin_routes
    assert plugin_routes.count('webd_error("capability_disabled"') >= 2


if __name__ == "__main__":
    test_config_tasks_cannot_delete_rollback_journal()
    test_wifi_false_capability_is_enforced_at_rest_and_ubus()
    test_wifi_setup_scan_and_read_paths_cannot_bypass_capabilities()
    test_placeholder_backup_and_shell_plugin_actions_are_disabled()
    print("ok: P0 task, Wi-Fi, backup, and plugin safety gates")

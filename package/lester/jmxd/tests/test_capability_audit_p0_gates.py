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
    # The write path is no longer compiled out: secrets survive a save because
    # they live in the AEAD vault rather than in wifi_ssids, and apply verifies
    # by readback.  So the invariant is no longer "the function refuses"; it is
    # "nothing can reach the database before the preconditions are checked, and
    # REST cannot reach the function at all until the user authorizes it".
    #
    # Precondition order inside the save function.  Each of these must come
    # before any statement that could touch the database.
    for guard in (
        "if(!nc_wifi_ssids_uci_ok(cfg))return -6;",
        "if(nc_wifi_phy_count()<=0)return -2;",
        "if(nc_wifi_secret_key_ready()!=0)return -4;",
    ):
        assert guard in save, f"missing save precondition: {guard}"
    first_write = min(
        save.index(w) for w in ("nc_txn_begin(", "nc_prepare(") if w in save
    )
    for guard in (
        "nc_wifi_ssids_uci_ok(cfg)",
        "nc_wifi_phy_count()<=0",
        "nc_wifi_secret_key_ready()!=0",
    ):
        assert save.index(guard) < first_write, (
            f"{guard!r} is checked after the first database statement; the "
            "writer must reject before it can touch the database"
        )
    # An omitted password must never be written as an empty string, and the
    # upsert must not overwrite the secret columns.
    assert "INSERT OR REPLACE INTO wifi_ssids(" not in save, (
        "the bulk REPLACE would reset secret_id/secret_present on every save"
    )
    assert "ON CONFLICT(id) DO UPDATE SET" in save
    for secret_column in ("secret_id=excluded.secret_id",
                          "secret_present=excluded.secret_present"):
        assert secret_column not in save, (
            f"{secret_column!r} lets a save without a password clear the key"
        )
    # REST exposure stays behind the authorization flip, and it must be a hard
    # compile-time 0 in production rather than a runtime toggle.
    assert "#define WEBD_WIFI_LOCAL_WRITE_ENABLED 0" in WEBD
    assert "WEBD_WIFI_LOCAL_WRITE_ENABLED" in wifi_routes
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
    plugin = body(CORE, "jmx_plugin_action")
    plugin_ubus = body(UBUS, "dw_handle_plugin_action")
    plugin_routes = WEBD[WEBD.index('!strcmp(req.path, "/api/v1/plugins/native")'):]
    plugin_routes = plugin_routes[: plugin_routes.index("/* ── VPN config")]
    # The placeholder backup writer this gate guarded is gone entirely --
    # jmx_system_backup_create() no longer exists in any compiled source, so
    # body(CORE, ...) raised ValueError and the gate checked nothing.
    #
    # It was not renamed or moved: config backup is now a real sqlite3_backup
    # implementation in webd (webd_config_online_backup). So the invariant to
    # protect is no longer "the placeholder refuses" but "the placeholder does
    # not come back, and what replaced it is a genuine backup".
    assert "DreamingWrt backup placeholder" not in CORE
    assert "DreamingWrt backup placeholder" not in WEBD
    assert "jmx_system_backup_create" not in CORE, (
        "the deprecated placeholder backup writer is back in core; config "
        "backup belongs to webd's sqlite3_backup path"
    )
    online_backup = body(WEBD, "webd_config_online_backup")
    assert "sqlite3_backup_init(" in online_backup and "sqlite3_backup_step(" in online_backup, (
        "config backup must be a real online sqlite backup, not a stub that "
        "reports success without copying anything"
    )
    assert "sqlite3_backup_finish(" in online_backup
    # A partial copy must not be reported as a successful backup.
    assert "SQLITE_DONE" in online_backup and "sqlite_backup_failed" in online_backup, (
        "an incomplete backup must fail loudly rather than leave a truncated "
        "artifact looking valid"
    )
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

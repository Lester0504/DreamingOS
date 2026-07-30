#!/usr/bin/env python3
import sqlite3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ROOT.parent
CONFIG_APPLICATION_ID = 1146573396
CONFIG_SCHEMA_VERSION = 1


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def assert_source_contract() -> None:
    netconfig = read(ROOT / "src/jmx_netconfig_db.c")
    webd = read(ROOT / "src/webd/jmx_app_api.c")
    source_makefile = read(ROOT / "src/Makefile")
    package_makefile = read(ROOT / "Makefile")
    web_package_makefile = read(PACKAGES / "dreamingwrt-web/Makefile")
    init_source = read(ROOT / "src/init/dreamingwrt_init.c")
    persist_init = read(
        PACKAGES / "dreamingwrt-installer/files/dreamingwrt-persist.init"
    )

    assert "CREATE TABLE IF NOT EXISTS appearance_settings" in netconfig
    assert "config.db:appearance_settings" in netconfig
    assert "PRAGMA application_id=1146573396" in netconfig
    assert "PRAGMA user_version=1" in netconfig
    assert "NC_THEME_PACKAGE" not in netconfig
    assert "NC_APPEARANCE_PACKAGE" not in netconfig
    assert "uci:dreamingwrt-theme" not in netconfig
    assert "uci:dreamingwrt-web" not in netconfig
    assert "dreamingwrt_lan_uci" not in netconfig
    assert "nc_lan_write_uci_draft" not in netconfig
    assert "int jmx_netconfig_lan_set(" in netconfig
    wan_delete_start = netconfig.index("int jmx_netconfig_wan_delete(")
    wan_delete_end = netconfig.index("/* \u2550", wan_delete_start)
    wan_delete = netconfig[wan_delete_start:wan_delete_end]
    for required in (
        "nc_valid_name(id)",
        'nc_backup_config("network"',
        'nc_exec("BEGIN IMMEDIATE")',
        'DELETE FROM wan WHERE id=?1',
        "sqlite3_changes(g_netconfig_db)",
        'nc_uci_delete_section_pkg(uctx, "network", id)',
        'jmx_uci_commit(uctx, "network")',
        'nc_backup_config("firewall"',
        'DELETE FROM hybrid_line WHERE parent_wan_id=?1',
        'nc_apply_wan_firewall_zone(uctx, firepkg, id, 0)',
        'jmx_uci_commit(uctx, "firewall")',
        'nc_reload_network_stack(0, 1, "/tmp/dw-wan-delete-reload.log")',
        'nc_exec("COMMIT")',
        'nc_exec("ROLLBACK")',
        'nc_restore_config("network", bak_network)',
    ):
        assert required in wan_delete
    assert wan_delete.index("DELETE FROM wan WHERE id=?1") < wan_delete.index(
        'nc_uci_delete_section_pkg(uctx, "network", id)'
    ) < wan_delete.index('nc_reload_network_stack(0, 1, "/tmp/dw-wan-delete-reload.log")')
    assert wan_delete.index('nc_reload_network_stack(0, 1, "/tmp/dw-wan-delete-reload.log")') < wan_delete.index(
        'nc_exec("COMMIT")'
    )
    assert "START=08" in persist_init
    assert "START=8\n" not in persist_init
    assert "wait_for_persistent_store" in init_source
    assert "path_is_mountpoint(DWRT_PERSIST_MOUNT)" in init_source
    assert "refusing to start components" in init_source
    assert 'jmx_uci_commit(ctx, "system")' in netconfig
    assert "sethostname(hostname, strlen(hostname))" in netconfig
    assert "nc_sys_uci_hostname_matches(hostname)" in netconfig
    assert "nc_sys_runtime_hostname_matches(hostname)" in netconfig
    assert "hostname_in_sync" in netconfig
    assert "RESTORE_BACKUP_SYSTEM" in read(ROOT / "src/init/config_restore.c")
    assert "hostname_materialized(hostname)" in read(ROOT / "src/init/config_restore.c")
    assert 'ubus_call("dreamingwrt", "dreamingwrt_system_settings_apply", "{}")' in read(
        ROOT / "src/init/config_restore.c"
    )
    assert 'app_ubus_response_ok(apply_resp)' in webd
    run_start = init_source.index("static int run_supervisor")
    wait_call = init_source.index("wait_for_persistent_store()", run_start)
    load_call = init_source.index("load_config();", wait_call)
    socket_call = init_source.index("setup_socket(sock_path)", load_call)
    assert wait_call < load_call < socket_call

    assert '"/api/v1/public/appearance"' in webd
    assert '"/api/v1/login/theme"' not in webd
    assert '"/api/v1/theme/login"' not in webd
    assert '"/api/v1/auth/theme"' not in webd
    assert '"/static/background/"' in webd
    assert '"config.db:appearance_settings"' in webd
    assert "webd_theme.o" not in source_makefile
    assert "dreamingwrt-theme.config" not in package_makefile
    assert "/etc/config/dreamingwrt-web" not in web_package_makefile
    assert "99-dreamingwrt-web-appearance" not in web_package_makefile

    assert not (ROOT / "src/webd/webd_theme.c").exists()
    assert not (ROOT / "src/webd/webd_theme.h").exists()
    assert not (ROOT / "files/dreamingwrt-theme.config").exists()
    assert not (PACKAGES / "dreamingwrt-web/files/etc/config/dreamingwrt-web").exists()
    assert not (
        PACKAGES
        / "dreamingwrt-web/files/etc/uci-defaults/99-dreamingwrt-web-appearance"
    ).exists()


def assert_sqlite_contract() -> None:
    db = sqlite3.connect(":memory:")
    db.executescript(
        f"""
        PRAGMA application_id={CONFIG_APPLICATION_ID};
        PRAGMA user_version={CONFIG_SCHEMA_VERSION};
        CREATE TABLE network_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO network_meta(key,value) VALUES('schema_version','1');
        CREATE TABLE system_ui_settings(id INTEGER PRIMARY KEY CHECK(id=1));
        CREATE TABLE appearance_settings(
          id INTEGER PRIMARY KEY CHECK(id=1),
          accent_color TEXT NOT NULL DEFAULT 'violet',
          wallpaper_directory TEXT NOT NULL DEFAULT '/www/dreamingwrt/static/background',
          login_enabled INTEGER NOT NULL DEFAULT 1
        );
        INSERT INTO system_ui_settings(id) VALUES(1);
        INSERT INTO appearance_settings(id) VALUES(1);
        """
    )
    assert db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    assert db.execute("PRAGMA application_id").fetchone()[0] == CONFIG_APPLICATION_ID
    assert db.execute("PRAGMA user_version").fetchone()[0] == CONFIG_SCHEMA_VERSION
    assert db.execute(
        "SELECT value FROM network_meta WHERE key='schema_version'"
    ).fetchone()[0] == str(CONFIG_SCHEMA_VERSION)
    assert db.execute(
        "SELECT accent_color,wallpaper_directory,login_enabled "
        "FROM appearance_settings WHERE id=1"
    ).fetchone() == ("violet", "/www/dreamingwrt/static/background", 1)
    db.close()


def main() -> None:
    assert_source_contract()
    assert_sqlite_contract()
    print("ok: config.db owns appearance/LAN; WAN delete is transactional across DB/UCI/netifd")


if __name__ == "__main__":
    main()

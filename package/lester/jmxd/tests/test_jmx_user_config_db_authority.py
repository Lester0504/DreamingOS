#!/usr/bin/env python3
"""Contracts for jmx.config/user_info.config migration into config.db."""

import sqlite3
import ast
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = "jmx_user_uci_v1"


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def schema(db: sqlite3.Connection) -> None:
    db.executescript(
        """
        CREATE TABLE config_migration(
          name TEXT PRIMARY KEY, status TEXT NOT NULL, source TEXT NOT NULL DEFAULT '',
          imported_rows INTEGER NOT NULL DEFAULT 0, imported_at INTEGER NOT NULL DEFAULT 0,
          detail TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE legacy_jmx_settings(
          id INTEGER PRIMARY KEY CHECK(id=1),
          lan_ifname TEXT NOT NULL DEFAULT 'br-lan',
          theme_mode INTEGER NOT NULL DEFAULT 1 CHECK(theme_mode IN (0,1)),
          record_time INTEGER NOT NULL DEFAULT 3 CHECK(record_time>=0),
          app_valid_time INTEGER NOT NULL DEFAULT 3 CHECK(app_valid_time>=0),
          history_data_size TEXT NOT NULL DEFAULT '10',
          history_data_path TEXT NOT NULL DEFAULT '/tmp/jmx',
          monitor_device TEXT NOT NULL DEFAULT '',
          health_flush_sec INTEGER NOT NULL DEFAULT 60,
          health_prune_sec INTEGER NOT NULL DEFAULT 300,
          health_max_age_days INTEGER NOT NULL DEFAULT 30,
          updated_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE client_nickname(
          mac TEXT PRIMARY KEY COLLATE NOCASE, nickname TEXT NOT NULL,
          updated_at INTEGER NOT NULL
        );
        CREATE TABLE network_control_global(
          id INTEGER PRIMARY KEY CHECK(id=1), enabled INTEGER NOT NULL DEFAULT 1,
          appfilter_enabled INTEGER NOT NULL DEFAULT 1,
          macfilter_enabled INTEGER NOT NULL DEFAULT 1,
          record_enabled INTEGER NOT NULL DEFAULT 1,
          updated_at INTEGER NOT NULL DEFAULT 0
        );
        INSERT OR IGNORE INTO legacy_jmx_settings(id) VALUES(1);
        INSERT OR IGNORE INTO network_control_global(id) VALUES(1);
        """
    )


def actual_nc_schema_sql() -> str:
    source = read("src/jmx_netconfig_db.c")
    block = source[
        source.index("static int nc_schema(void)") : source.index(
            'if (nc_exec(sql) != 0) return -1;', source.index("static int nc_schema(void)")
        )
    ]
    assignment = block[block.index("const char *sql =") :]
    return "".join(ast.literal_eval(token) for token in re.findall(r'"(?:[^"\\]|\\.)*"', assignment))


def migrate(db: sqlite3.Connection, settings: tuple, switches: tuple, nicknames: list) -> str:
    if db.execute(
        "SELECT 1 FROM config_migration WHERE name=? AND status='done'", (MIGRATION,)
    ).fetchone():
        return "already_done"
    settings_initialized = db.execute(
        "SELECT updated_at FROM legacy_jmx_settings WHERE id=1"
    ).fetchone()[0] > 0
    controls_initialized = db.execute(
        "SELECT updated_at FROM network_control_global WHERE id=1"
    ).fetchone()[0] > 0
    with db:
        if not settings_initialized:
            db.execute(
                "UPDATE legacy_jmx_settings SET lan_ifname=?,theme_mode=?,record_time=?,"
                "app_valid_time=?,history_data_size=?,history_data_path=?,monitor_device=?,"
                "updated_at=1 WHERE id=1",
                settings,
            )
        if not controls_initialized:
            db.execute(
                "UPDATE network_control_global SET appfilter_enabled=?,macfilter_enabled=?,"
                "record_enabled=?,updated_at=1 WHERE id=1",
                switches,
            )
        for mac, nickname in nicknames:
            db.execute(
                "INSERT INTO client_nickname(mac,nickname,updated_at) VALUES(?,?,1) "
                "ON CONFLICT(mac) DO NOTHING",
                (mac.lower(), nickname),
            )
        row = db.execute(
            "SELECT s.lan_ifname,s.history_data_path,g.record_enabled "
            "FROM legacy_jmx_settings s JOIN network_control_global g ON g.id=s.id"
        ).fetchone()
        assert row and row[0] and row[1]
        db.execute(
            "INSERT INTO config_migration VALUES(?,'done','uci:/etc/config/jmx,user_info',?,1,?)",
            (
                MIGRATION,
                len(nicknames) + (0 if settings_initialized else 1),
                "preserved_existing_config_db_values_and_imported_missing_nicknames"
                if settings_initialized or controls_initialized
                else "legacy_uci_imported_and_read_back",
            ),
        )
    return "done"


def test_first_import_and_second_run_are_atomic_and_idempotent() -> None:
    db = sqlite3.connect(":memory:")
    schema(db)
    settings = ("br-home", 0, 14, 600, "256", "/data/history", "eth9")
    assert migrate(db, settings, (0, 1, 0), [("AA:BB:CC:DD:EE:FF", "Office")]) == "done"
    assert migrate(db, ("bad", 1, 1, 1, "1", "/bad", "bad"), (1, 0, 1), []) == "already_done"
    assert db.execute(
        "SELECT lan_ifname,theme_mode,record_time,app_valid_time,history_data_size,"
        "history_data_path,monitor_device FROM legacy_jmx_settings"
    ).fetchone() == settings
    assert db.execute(
        "SELECT appfilter_enabled,macfilter_enabled,record_enabled FROM network_control_global"
    ).fetchone() == (0, 1, 0)
    assert db.execute("SELECT mac,nickname FROM client_nickname").fetchone() == (
        "aa:bb:cc:dd:ee:ff",
        "Office",
    )


def test_existing_database_values_and_nicknames_win_over_legacy_uci() -> None:
    db = sqlite3.connect(":memory:")
    schema(db)
    db.execute(
        "UPDATE legacy_jmx_settings SET lan_ifname='br-db',history_data_path='/db',updated_at=9"
    )
    db.execute(
        "UPDATE network_control_global SET appfilter_enabled=0,record_enabled=0,updated_at=9"
    )
    db.execute(
        "INSERT INTO client_nickname VALUES('aa:bb:cc:dd:ee:ff','DB nickname',9)"
    )
    migrate(
        db,
        ("br-uci", 0, 99, 99, "99", "/uci", "eth9"),
        (1, 1, 1),
        [("AA:BB:CC:DD:EE:FF", "UCI nickname"), ("00:11:22:33:44:55", "Imported")],
    )
    assert db.execute("SELECT lan_ifname,history_data_path FROM legacy_jmx_settings").fetchone() == (
        "br-db",
        "/db",
    )
    assert db.execute("SELECT nickname FROM client_nickname WHERE mac LIKE 'aa:bb:%'").fetchone()[0] == "DB nickname"
    assert db.execute("SELECT nickname FROM client_nickname WHERE mac='00:11:22:33:44:55'").fetchone()[0] == "Imported"


def test_runtime_sources_use_config_db_and_rulesd_does_not_reimport_switches() -> None:
    sources = {
        name: read(name)
        for name in ("src/jmx_system.c", "src/jmx_ubus.c", "src/jmx_user.c", "src/jmx_config.c")
    }
    for source in sources.values():
        assert "user_info.@user_info" not in source
        assert '"jmx.record.' not in source
        assert '"jmx.dashboard.' not in source
    assert "jmx_legacy_settings_get" in sources["src/jmx_system.c"]
    assert "jmx_client_nickname_set" in sources["src/jmx_ubus.c"]
    assert "jmx_client_nickname_foreach" in sources["src/jmx_user.c"]
    assert "jmx_network_control_appfilter_enabled" in sources["src/jmx_config.c"]
    lua = read("files/rule_manager.lua")
    assert 'cursor:get("jmx"' not in lua
    assert 'cursor:unload("jmx")' not in lua
    core = read("src/jmx_netconfig_db.c")
    assert "ON CONFLICT(mac) DO NOTHING" in core
    assert "legacy_uci_imported_and_read_back" in core
    rulesd = core[core.index("struct json_object *jmx_rulesd_config_migrate"):]
    assert "UPDATE network_control_global SET appfilter_enabled" not in rulesd.split("/* ── nft", 1)[0]
    assert "nc_jmx_compat_project" not in core
    assert "jmx_legacy_settings_project_uci" not in core
    assert "jmx_network_control_set_filter_enabled" in core
    setter = core[
        core.index("int jmx_network_control_set_filter_enabled") :
        core.index("int jmx_work_mode_config_get")
    ]
    assert 'nc_exec("BEGIN IMMEDIATE")' in setter
    assert 'nc_exec("ROLLBACK")' in setter
    assert "nc_prepare(&st, sql) != 0)\n        goto done;" in setter
    for relative in (
        "src/main.c", "src/jmx_dreamingwrt_api.c", "src/jmx_db.c",
        "src/jmx_network.c", "src/jmx_app_filter.c", "src/jmx_mac_filter.c",
        "src/audit/jmx_auditd.c",
    ):
        source = read(relative)
        assert '"jmx.global.' not in source, relative
        assert '"jmx.record.' not in source, relative
        assert '"jmx.appfilter.' not in source, relative
        assert '"jmx.macfilter.' not in source, relative
        assert '"jmx.health.' not in source, relative


def test_seed_installation_is_removed_and_restore_schema_is_self_healing() -> None:
    makefile = read("Makefile")
    assert "files/jmx.config" not in makefile
    assert "files/user_info.config" not in makefile
    assert "files/jmx_cli.sh" not in makefile
    assert "files/uci-defaults" not in makefile
    assert not (ROOT / "files/jmx_cli.sh").exists()
    assert not (ROOT / "files/uci-defaults/100_jmx").exists()
    core = read("src/jmx_netconfig_db.c")
    assert "CREATE TABLE IF NOT EXISTS legacy_jmx_settings" in core
    assert "CREATE TABLE IF NOT EXISTS client_nickname" in core
    assert "INSERT OR IGNORE INTO legacy_jmx_settings(id)" in core
    assert "health_flush_sec" in core
    restored = sqlite3.connect(":memory:")
    restored.executescript("CREATE TABLE network_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);")
    restored.executescript(actual_nc_schema_sql())
    assert restored.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
        "('legacy_jmx_settings','client_nickname') ORDER BY name"
    ).fetchall() == [("client_nickname",), ("legacy_jmx_settings",)]


if __name__ == "__main__":
    test_first_import_and_second_run_are_atomic_and_idempotent()
    test_existing_database_values_and_nicknames_win_over_legacy_uci()
    test_runtime_sources_use_config_db_and_rulesd_does_not_reimport_switches()
    test_seed_installation_is_removed_and_restore_schema_is_self_healing()
    print("ok: jmx/user_info config.db authority and one-time migration contract")

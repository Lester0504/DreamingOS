#!/usr/bin/env python3
import sqlite3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = "rulesd_uci_v1"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_rulesd_runtime_reads_only_config_db_projection():
    lua = read(ROOT / "files/rule_manager.lua")
    makefile = read(ROOT / "Makefile")
    runtime_start = lua.index("local function refresh_rulesd_config()")
    legacy_start = lua.index("local function legacy_uci_payload()")
    legacy_end = lua.index("local function refresh_rulesd_config()")

    assert 'local ubus = require "ubus"' in lua
    assert "+libubus-lua" in makefile
    for legacy_install in (
        "./files/appfilter.config",
        "./files/macfilter.config",
        "./files/appfilter_whitelist.config",
        "./files/macfilter_whitelist.config",
    ):
        assert legacy_install not in makefile
    assert 'core_call("rulesd_config_get")' in lua[runtime_start:]
    assert 'core_call("rulesd_config_migrate", legacy_uci_payload())' in lua
    assert 'require "uci"' in lua[legacy_start:legacy_end]
    assert 'require "uci"' not in lua[:legacy_start]
    assert "uci.cursor()" not in lua[runtime_start:]
    assert "get_uci_enable" not in lua
    assert "from config.db" in lua
    assert "retaining last rules because config.db refresh failed" in lua
    assert lua.index("if not loaded then", lua.index("local function initialize_rules")) < lua.index(
        "flush_all_rules()", lua.index("local function initialize_rules")
    )


def test_core_reuses_network_control_schema_and_atomic_migration():
    db_source = read(ROOT / "src/jmx_netconfig_db.c")
    api_source = read(ROOT / "src/jmx_dreamingwrt_api.c")
    restore_source = read(ROOT / "src/init/config_restore.c")

    for required in (
        "CREATE TABLE IF NOT EXISTS config_migration",
        "CREATE TABLE IF NOT EXISTS network_control_rule",
        "CREATE TABLE IF NOT EXISTS network_control_app_rule",
        "CREATE TABLE IF NOT EXISTS network_control_mac_rule",
        "CREATE TABLE IF NOT EXISTS network_control_whitelist",
        'RULESD_UCI_MIGRATION "rulesd_uci_v1"',
        'nc_exec("BEGIN IMMEDIATE")',
        'nc_exec(rc == 0 ? "COMMIT" : "ROLLBACK")',
        "preserved_existing_config_db_rules",
        "legacy_uci_imported",
        'json_object_new_string("config.db:network_control")',
    ):
        assert required in db_source
    assert "CREATE TABLE IF NOT EXISTS rulesd_rule" not in db_source
    assert "CREATE TABLE IF NOT EXISTS rulesd_config" not in db_source
    assert 'UBUS_METHOD("rulesd_config_get"' in api_source
    assert 'UBUS_METHOD("rulesd_config_migrate"' in api_source
    required_block = restore_source[
        restore_source.index("static const char *required[]") :
        restore_source.index("sqlite3 *db", restore_source.index("static const char *required[]"))
    ]
    for optional_table in (
        "config_migration",
        "network_control_global",
        "network_control_rule",
        "network_control_app_rule",
        "network_control_mac_rule",
        "network_control_whitelist",
    ):
        assert optional_table not in required_block


def _schema(db: sqlite3.Connection) -> None:
    db.executescript(
        """
        CREATE TABLE config_migration(
          name TEXT PRIMARY KEY, status TEXT NOT NULL, source TEXT NOT NULL DEFAULT '',
          imported_rows INTEGER NOT NULL DEFAULT 0, imported_at INTEGER NOT NULL DEFAULT 0,
          detail TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE network_control_rule(
          id TEXT PRIMARY KEY, type TEXT NOT NULL, name TEXT NOT NULL,
          runtime_rule_id INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE network_control_app_rule(
          rule_id TEXT PRIMARY KEY, app_ids TEXT NOT NULL DEFAULT '',
          filter_quic INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE network_control_mac_rule(
          rule_id TEXT PRIMARY KEY, mac TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE network_control_whitelist(
          kind TEXT NOT NULL CHECK(kind IN ('app','mac')), mac TEXT NOT NULL,
          PRIMARY KEY(kind,mac)
        );
        """
    )


def _migrate(db: sqlite3.Connection, legacy_id: str) -> str:
    with db:
        done = db.execute(
            "SELECT 1 FROM config_migration WHERE name=? AND status='done'", (MIGRATION,)
        ).fetchone()
        if done:
            return "already_done"
        existing = db.execute(
            "SELECT COUNT(*) FROM network_control_rule WHERE type IN ('app','mac')"
        ).fetchone()[0]
        if not existing:
            db.execute(
                "INSERT INTO network_control_rule(id,type,name,runtime_rule_id) VALUES(?,?,?,?)",
                (legacy_id, "app", "legacy", 7),
            )
            db.execute(
                "INSERT INTO network_control_app_rule(rule_id,app_ids,filter_quic) VALUES(?,?,?)",
                (legacy_id, '["1001"]', 1),
            )
        detail = "preserved_existing_config_db_rules" if existing else "legacy_uci_imported"
        db.execute(
            "INSERT INTO config_migration(name,status,source,imported_rows,imported_at,detail) "
            "VALUES(?,'done','uci:/etc/config/appfilter,macfilter,jmx',?,1,?)",
            (MIGRATION, 0 if existing else 1, detail),
        )
        return detail


def test_migration_is_once_only_and_preserves_existing_authority():
    db = sqlite3.connect(":memory:")
    _schema(db)
    db.execute(
        "INSERT INTO network_control_rule(id,type,name,runtime_rule_id) VALUES('db-rule','app','db',55)"
    )
    db.execute(
        "INSERT INTO network_control_app_rule(rule_id,app_ids,filter_quic) VALUES('db-rule','[]',0)"
    )
    assert _migrate(db, "legacy-rule") == "preserved_existing_config_db_rules"
    assert _migrate(db, "different-legacy-rule") == "already_done"
    assert db.execute("SELECT id,runtime_rule_id FROM network_control_rule").fetchall() == [
        ("db-rule", 55)
    ]
    assert db.execute(
        "SELECT status,detail FROM config_migration WHERE name=?", (MIGRATION,)
    ).fetchone() == ("done", "preserved_existing_config_db_rules")


def test_empty_database_import_is_committed_once():
    db = sqlite3.connect(":memory:")
    _schema(db)
    assert _migrate(db, "legacy-rule") == "legacy_uci_imported"
    assert _migrate(db, "replacement") == "already_done"
    assert db.execute("SELECT id,runtime_rule_id FROM network_control_rule").fetchall() == [
        ("legacy-rule", 7)
    ]


if __name__ == "__main__":
    test_rulesd_runtime_reads_only_config_db_projection()
    test_core_reuses_network_control_schema_and_atomic_migration()
    test_migration_is_once_only_and_preserves_existing_authority()
    test_empty_database_import_is_committed_once()
    print("ok: rulesd config.db authority and one-time UCI migration contract")

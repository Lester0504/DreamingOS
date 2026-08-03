#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NETCONFIG = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")
DB = (ROOT / "src/jmx_db.c").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    return text[first:text.index(end, first)]


helper = between(
    NETCONFIG,
    "static int nc_add_column_if_missing",
    "void nc_add_text",
)
assert "nc_table_has_column(table, column)" in helper
assert '"ALTER TABLE %s ADD COLUMN %s %s"' in helper
assert "return nc_exec(sql);" in helper

# Schema migration must check table_info before every additive ALTER. Repeated
# unconditional ALTERs contend for SQLite schema locks on multi-process startup.
assert 'nc_exec("ALTER TABLE' not in NETCONFIG
assert NETCONFIG.count("nc_add_column_if_missing(") >= 70

port_restore = between(
    NETCONFIG,
    "int jmx_netconfig_physical_port_apply_saved_all",
    "static void nc_physical_port_profile_to_json",
)
finalize = port_restore.index("sqlite3_finalize(st);")
runtime_apply = port_restore.index("nc_physical_port_ethtool_apply(items[i].ifname")
mark_apply = port_restore.index("nc_physical_port_config_mark_apply(items[i].ifname")
assert finalize < runtime_apply < mark_apply
assert "realloc(items" in port_restore
assert "free(items);" in port_restore

db_init = between(
    DB,
    "int jmx_db_init(void)",
    "void jmx_db_close(void)",
)
assert "JMX_DB_SCHEMA_VERSION 7" in DB
assert 'db_exec("PRAGMA journal_mode=WAL;")' in db_init
version_gate = db_init.index("if (version < JMX_DB_SCHEMA_VERSION)")
begin = db_init.index("if (db_begin() != 0)")
schema_v1 = db_init.index("if (version < 1 && db_schema_v1() != 0)")
schema_v2 = db_init.index("if (version < 2 && db_schema_v2() != 0)")
schema_v3 = db_init.index("if (version < 3)")
schema_v4 = db_init.index("if (version < 4)")
schema_v5 = db_init.index("if (version < 5)")
schema_v6 = db_init.index("if (version < 6)")
schema_v7 = db_init.index("if (version < 7)")
set_version = db_init.index("db_set_schema_version(JMX_DB_SCHEMA_VERSION)")
assert version_gate < begin < schema_v1 < schema_v2 < schema_v3 < schema_v4
assert schema_v4 < schema_v5 < schema_v6 < schema_v7 < set_version
# The v7 migration must create the lifetime WAN counter table inside the same
# transaction as every other migration step, so a failure cannot leave the DB
# claiming v7 without the table.
assert "wan_lifetime_usage" in db_init
assert "if (version > JMX_DB_SCHEMA_VERSION)" in db_init
assert "if (migration_started)\n        db_rollback();" in db_init
assert "sqlite3_close(g_db);\n    g_db = NULL;" in db_init

print("ok: core startup schemas are version-gated/WAL-backed and port restore releases its read statement before writes")

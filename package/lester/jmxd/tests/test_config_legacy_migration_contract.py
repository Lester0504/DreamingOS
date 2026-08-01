#!/usr/bin/env python3
"""B-02 contract: legacy 86-table config backups migrate through an explicit
version chain, report per-table preservation, stay idempotent, and never
mutate or partially publish anything on failure.

The migration module is compiled and driven directly so the test proves real
behavior instead of asserting on source text.
"""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src/init/config_migrate.c"
FIXTURE = Path(__file__).resolve().parent / "fixtures/legacy_config_86_tables.sql"

APPLICATION_ID = 1146573396
SCHEMA_VERSION = 1
REQUIRED_TABLES = (
    "network_meta", "wan", "lan", "network_global", "web_users",
    "system_ui_settings", "appearance_settings", "system_settings",
    "work_mode_settings",
)

DRIVER = r"""
#include <stdio.h>
#include <string.h>
#include "config_migrate.h"

int main(int argc, char **argv)
{
    struct dwrt_migrate_report report;
    int rc;

    if (argc < 4) {
        fprintf(stderr, "usage: driver <source> <dest> <report>\n");
        return 2;
    }
    rc = dwrt_config_migrate_run(argv[1], argv[2], &report);
    if (dwrt_config_migrate_write_report(argv[3], &report) != 0)
        fprintf(stderr, "report_write_failed\n");
    printf("rc=%d error=%s from=%d steps=%d tables=%d\n", rc, report.error,
           report.from_version, report.steps_applied, report.table_count);
    return rc == 0 ? 0 : 1;
}
"""


def find_sqlite3_dev():
    for inc in ("/usr/include/sqlite3.h", "/opt/homebrew/include/sqlite3.h",
                "/usr/local/include/sqlite3.h"):
        if os.path.exists(inc):
            return os.path.dirname(inc)
    # macOS keeps headers inside the active SDK rather than /usr/include.
    try:
        sdk = subprocess.run(["xcrun", "--show-sdk-path"], capture_output=True,
                             text=True, timeout=20)
        if sdk.returncode == 0:
            candidate = os.path.join(sdk.stdout.strip(), "usr/include")
            if os.path.exists(os.path.join(candidate, "sqlite3.h")):
                return candidate
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def build_driver(workdir):
    inc = find_sqlite3_dev()
    if inc is None:
        print("skip: sqlite3 development headers unavailable")
        sys.exit(0)
    driver_c = workdir / "driver.c"
    driver_c.write_text(DRIVER)
    binary = workdir / "driver"
    cmd = [
        os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-I", str(ROOT / "src/init"), "-I", str(ROOT / "src"), "-I", inc,
        str(driver_c), str(SRC), "-o", str(binary),
    ]
    libdir = os.path.join(os.path.dirname(inc), "lib")
    if os.path.isdir(libdir):
        cmd += ["-L", libdir]
    cmd += ["-lsqlite3"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print("compile failed:\n" + proc.stdout + proc.stderr)
        sys.exit(1)
    return binary


def has_columns(conn, table, columns):
    have = {r[1] for r in conn.execute("PRAGMA table_info(" + table + ")")}
    return set(columns).issubset(have)


def make_legacy_db(path, wal=False):
    """Builds a legacy library from the real 86-table fixture schema."""
    conn = sqlite3.connect(path)
    conn.executescript(FIXTURE.read_text())
    if wal:
        # Real backups taken from a running router are usually left in WAL mode.
        conn.execute("PRAGMA journal_mode=WAL")
    # Legacy libraries carry no application identity at all.
    conn.execute("PRAGMA application_id=0")
    conn.execute("PRAGMA user_version=0")
    conn.execute("INSERT INTO network_meta(key,value) VALUES('schema_version','1')")
    conn.execute(
        "INSERT INTO web_users(username,password_hash,status,role,"
        "created_at,updated_at) "
        "VALUES('admin','$5$legacyhash','active','admin',1700000000,1700000000)")
    conn.execute(
        "INSERT INTO lan(id,name,ifname,device,created_at,updated_at) "
        "VALUES('lan','LAN','br-lan','br-lan',1700000000,1700000000)")
    conn.execute(
        "INSERT INTO lan_address(lan_id,ip,prefix,is_primary,sort_order) "
        "VALUES('lan','192.168.30.1',24,1,0)")
    conn.execute("INSERT INTO network_global(id) VALUES(1)")
    if has_columns(conn, "dhcp_lease_cache", ("mac", "ip")):
        conn.execute(
            "INSERT INTO dhcp_lease_cache(mac,ip) "
            "VALUES('aa:bb:cc:dd:ee:ff','192.168.30.50')")
    conn.commit()
    conn.close()


def run(binary, source, dest, report):
    return subprocess.run([str(binary), str(source), str(dest), str(report)],
                          capture_output=True, text=True)


def main():
    assert FIXTURE.exists(), "legacy 86-table fixture missing"
    ddl_tables = FIXTURE.read_text().count("CREATE TABLE")
    assert ddl_tables == 86, "fixture must hold the real 86 legacy tables, got %d" % ddl_tables

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        binary = build_driver(work)

        source = work / "legacy.db"
        dest = work / "migrated.db"
        report_path = work / "report.json"
        make_legacy_db(source)
        source_bytes = source.read_bytes()

        proc = run(binary, source, dest, report_path)
        assert proc.returncode == 0, "migration failed: " + proc.stdout + proc.stderr

        # The source library must be byte-identical after migration.
        assert source.read_bytes() == source_bytes, "migration mutated the source library"

        conn = sqlite3.connect("file:%s?mode=ro" % dest, uri=True)
        assert conn.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        assert conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        for table in REQUIRED_TABLES:
            assert table in names, "migrated library omits required table " + table
        hostname = conn.execute("SELECT hostname FROM system_settings WHERE id=1").fetchone()[0]
        assert hostname, "migrated library must carry a non-empty hostname"
        # Authority rows survive verbatim.
        assert conn.execute("SELECT COUNT(*) FROM web_users").fetchone()[0] == 1
        assert conn.execute(
            "SELECT password_hash FROM web_users WHERE username='admin'"
        ).fetchone()[0] == "$5$legacyhash", "secret reference was not preserved"
        conn.close()

        report = json.loads(report_path.read_text())
        assert report["format"] == "dreamingwrt-config-migration-v1"
        assert report["from_version"] == 0 and report["to_version"] == SCHEMA_VERSION
        assert report["steps_applied"] == 1, "version chain must apply explicit steps"
        assert report["secret_references_preserved"] is True
        assert report["media_metadata_preserved"] is True
        actions = {t["name"]: t["action"] for t in report["tables"]}
        assert len(report["tables"]) == report["table_count"] >= 86
        for table in ("system_settings", "system_ui_settings",
                      "appearance_settings", "work_mode_settings"):
            assert actions[table] == "created", table + " should be reported as created"
        assert actions["web_users"] == "migrated"
        assert actions["dhcp_lease_cache"] == "dropped", "volatile cache must be reported"
        for entry in report["tables"]:
            assert entry["reason"], "table %s has no recorded reason" % entry["name"]

        # Idempotence: re-running against the same source yields identical verdicts.
        again_report = work / "report2.json"
        proc2 = run(binary, source, dest, again_report)
        assert proc2.returncode == 0, "second migration failed: " + proc2.stdout + proc2.stderr
        report2 = json.loads(again_report.read_text())
        assert {t["name"]: t["action"] for t in report2["tables"]} == actions, \
            "migration is not idempotent"

        # A library already on the current schema is not a migration candidate.
        current = work / "current.db"
        shutil.copyfile(dest, current)
        proc3 = run(binary, current, work / "noop.db", work / "report3.json")
        assert proc3.returncode != 0, "current-schema library must not be a migration candidate"
        assert "source_not_migration_candidate" in proc3.stdout + proc3.stderr

        # Failure path: a corrupted legacy library must not publish a product.
        broken = work / "broken.db"
        broken.write_bytes(b"SQLite format 3\x00" + b"\x00" * 512)
        broken_dest = work / "broken-out.db"
        proc4 = run(binary, broken, broken_dest, work / "report4.json")
        assert proc4.returncode != 0, "corrupted library must fail migration"
        assert not broken_dest.exists(), "failed migration left a partial product behind"

        # WAL-mode legacy libraries are the common real-world case: a backup
        # copied off a running router keeps journal_mode=wal, and probing it
        # read-only must not fail just because the -wal/-shm files are gone.
        wal_source = work / "legacy-wal.db"
        make_legacy_db(wal_source, wal=True)
        for suffix in ("-wal", "-shm"):
            stray = Path(str(wal_source) + suffix)
            if stray.exists():
                stray.unlink()
        wal_dest = work / "migrated-wal.db"
        proc5 = run(binary, wal_source, wal_dest, work / "report5.json")
        assert proc5.returncode == 0, \
            "WAL-mode legacy library must migrate: " + proc5.stdout + proc5.stderr
        wal_conn = sqlite3.connect("file:%s?mode=ro" % wal_dest, uri=True)
        assert wal_conn.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID
        assert wal_conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        wal_conn.close()

    print("legacy config migration contract: ok")


if __name__ == "__main__":
    main()

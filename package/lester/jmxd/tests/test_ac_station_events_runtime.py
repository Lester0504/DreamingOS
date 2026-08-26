#!/usr/bin/env python3
"""AC station connectivity event store: diff producer, cursor and bounds."""

from __future__ import annotations

import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/ac/ac_db.c"
UBUS = ROOT / "src/ac/ac_ubus.c"
PROTOCOL = ROOT / "src/ac/ac_protocol.c"
FIXTURE = ROOT / "tests/ac_station_events_runtime_fixture.c"
# AC_SURVEY_TEST_PREFIX layout (include/json-c + lib) overrides the macOS
# Homebrew defaults so the same driver runs against a Linux sysroot.
_ENV_PREFIX = os.environ.get("AC_SURVEY_TEST_PREFIX", "")
JSON_PREFIX = Path(_ENV_PREFIX) if _ENV_PREFIX else Path(
    "/opt/homebrew/var/homebrew/tmp/.cellar/json-c/0.19")
_ENV_OPENSSL = os.environ.get("AC_SURVEY_TEST_OPENSSL_PREFIX", "")
OPENSSL_PREFIX = Path(_ENV_OPENSSL) if _ENV_OPENSSL else (
    JSON_PREFIX if _ENV_PREFIX else Path("/opt/homebrew/opt/openssl@3"))


def schema_version() -> int:
    match = re.search(r"#define AC_SCHEMA_VERSION (\d+)",
                      SOURCE.read_text(encoding="utf-8"))
    assert match, "AC_SCHEMA_VERSION not found in ac_db.c"
    return int(match.group(1))


def static_contract() -> None:
    db = SOURCE.read_text(encoding="utf-8")
    ubus = UBUS.read_text(encoding="utf-8")
    protocol = PROTOCOL.read_text(encoding="utf-8")
    for token in (
        "CREATE TABLE IF NOT EXISTS ac_station_events (",
        "ac_db_station_events_ingest",
        "ac_db_snapshot_hostapd_authoritative",
        "AC_STATION_EVENT_RETENTION_PER_AP 4096",
        "AC_STATION_EVENT_WINDOW_MAX_S 3600",
        "'ac_snapshot_diff'",
        "ac_db_station_events_json",
    ):
        assert token in db, f"missing station event contract: {token}"
    for token in (
        'UBUS_METHOD("station_events", ac_handle_station_events,',
        "ac_station_events_parse_policy",
        "ac_attr_get_s64(tb[AC_STATION_EVENTS_START])",
    ):
        assert token in ubus, f"missing station event ubus contract: {token}"
    assert '"station_event_store", 1' in protocol


def compile_fixture(output: Path) -> None:
    static_lib = JSON_PREFIX / "lib/libjson-c.a"
    json_link = ([str(static_lib)] if static_lib.is_file() else
                 [f"-L{JSON_PREFIX / 'lib'}",
                  f"-Wl,-rpath,{JSON_PREFIX / 'lib'}", "-ljson-c"])
    command = [
        os.environ.get("CC", "cc"), "-std=c11",
        "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
        "-DAC_DB_TEST_STANDALONE", "-DAC_DB_TELEMETRY_TEST_STANDALONE",
        "-Wall", "-Wextra", "-Werror",
        f"-I{JSON_PREFIX / 'include'}", f"-I{OPENSSL_PREFIX / 'include'}",
        str(FIXTURE), str(SOURCE), *json_link,
        f"-L{OPENSSL_PREFIX / 'lib'}", "-lcrypto", "-lsqlite3", "-lm",
        "-o", str(output),
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)


def run(binary: Path, database: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["DREAMINGWRT_AC_DB_PATH"] = str(database)
    return subprocess.run([str(binary), *args], env=env, check=True,
                          capture_output=True, text=True)


def main() -> None:
    static_contract()
    expected_schema = schema_version()
    with tempfile.TemporaryDirectory(prefix="ac-station-events-") as raw:
        directory = Path(raw)
        binary = directory / "fixture"
        compile_fixture(binary)

        migration = directory / "migration.db"
        with sqlite3.connect(migration) as connection:
            connection.execute(
                "CREATE TABLE ac_schema_meta(singleton INTEGER PRIMARY KEY, "
                "version INTEGER NOT NULL, owner TEXT NOT NULL, "
                "migrated_at INTEGER NOT NULL)"
            )
            connection.execute(
                "INSERT INTO ac_schema_meta VALUES(1,8,'dreamingwrt-ac',1)"
            )
        migration.chmod(0o600)
        run(binary, migration, "init-only")
        with sqlite3.connect(migration) as connection:
            assert connection.execute(
                "SELECT version FROM ac_schema_meta WHERE singleton=1"
            ).fetchone() == (expected_schema,)
            assert connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name='ac_station_events'"
            ).fetchone() is not None

        database = directory / "runtime.db"
        result = run(binary, database)
        assert f"schema={expected_schema}" in result.stdout
        assert "diff_events=3" in result.stdout
        assert "gated=1" in result.stdout
        assert "window_bounded=1" in result.stdout
        assert "pagination=1" in result.stdout
        assert "retention=4096" in result.stdout
        with sqlite3.connect(database) as connection:
            assert connection.execute("PRAGMA quick_check").fetchone() == ("ok",)
    print("ok: AC station event diff producer, honest gating, cursor "
          "pagination and bounded retention")


if __name__ == "__main__":
    main()

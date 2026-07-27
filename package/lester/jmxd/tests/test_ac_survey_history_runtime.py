#!/usr/bin/env python3
"""AC Survey history migration, delta, retention and query runtime contract."""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/ac/ac_db.c"
FIXTURE = ROOT / "tests/ac_survey_history_runtime_fixture.c"
# AC_SURVEY_TEST_PREFIX (or the shared AC_PAIRING_TEST_PREFIX layout with
# include/json-c + lib/libjson-c.{a,so}) overrides the macOS Homebrew
# defaults so the same driver runs against a Linux sysroot.
_ENV_PREFIX = os.environ.get("AC_SURVEY_TEST_PREFIX", "")
JSON_PREFIX = Path(_ENV_PREFIX) if _ENV_PREFIX else Path(
    "/opt/homebrew/var/homebrew/tmp/.cellar/json-c/0.19")
_ENV_OPENSSL = os.environ.get("AC_SURVEY_TEST_OPENSSL_PREFIX", "")
OPENSSL_PREFIX = Path(_ENV_OPENSSL) if _ENV_OPENSSL else (
    JSON_PREFIX if _ENV_PREFIX else Path("/opt/homebrew/opt/openssl@3"))


def _json_c_link_args() -> list[str]:
    static_lib = JSON_PREFIX / "lib/libjson-c.a"
    if static_lib.is_file():
        return [str(static_lib)]
    return [f"-L{JSON_PREFIX / 'lib'}",
            f"-Wl,-rpath,{JSON_PREFIX / 'lib'}", "-ljson-c"]


def compile_fixture(output: Path) -> None:
    command = [
        os.environ.get("CC", "cc"), "-std=c11",
        "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
        "-DAC_DB_TEST_STANDALONE", "-DAC_DB_TELEMETRY_TEST_STANDALONE",
        "-Wall", "-Wextra", "-Werror",
        f"-I{JSON_PREFIX / 'include'}", f"-I{OPENSSL_PREFIX / 'include'}",
        str(FIXTURE), str(SOURCE), *_json_c_link_args(),
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
    with tempfile.TemporaryDirectory(prefix="ac-survey-history-") as raw:
        directory = Path(raw)
        binary = directory / "fixture"
        compile_fixture(binary)

        migration = directory / "migration.db"
        with sqlite3.connect(migration) as connection:
            connection.execute(
                "CREATE TABLE ac_schema_meta(singleton INTEGER PRIMARY KEY, "
                "version INTEGER NOT NULL, owner TEXT NOT NULL, migrated_at INTEGER NOT NULL)"
            )
            connection.execute(
                "INSERT INTO ac_schema_meta VALUES(1,7,'dreamingwrt-ac',1)"
            )
        migration.chmod(0o600)
        run(binary, migration, "init-only")
        with sqlite3.connect(migration) as connection:
            assert connection.execute(
                "SELECT version FROM ac_schema_meta WHERE singleton=1"
            ).fetchone() == (11,)
            assert connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name='ac_radio_survey_bucket'"
            ).fetchone() is not None

        database = directory / "runtime.db"
        result = run(binary, database)
        assert "schema=11" in result.stdout
        assert "fine_points=5" in result.stdout
        assert "dense_suppressed=1" in result.stdout
        assert "reset_safe=1" in result.stdout
        assert "weighted=1" in result.stdout
        assert "pagination=1" in result.stdout
        assert "old_rows=0" in result.stdout
        with sqlite3.connect(database) as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM ac_radio_survey_bucket "
                "WHERE resolution_seconds=300"
            ).fetchone()[0]
            assert count <= 576
            assert connection.execute("PRAGMA quick_check").fetchone() == ("ok",)
    print("ok: AC v7-to-v8 Survey history migration, deltas, reset, weighted buckets, retention and pagination")


if __name__ == "__main__":
    main()

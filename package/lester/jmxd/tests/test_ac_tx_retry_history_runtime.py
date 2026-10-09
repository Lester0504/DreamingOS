#!/usr/bin/env python3
"""AC TX retry cursor, bucket, rebaseline, retention and query contract."""

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
FIXTURE = ROOT / "tests/ac_tx_retry_history_runtime_fixture.c"

# AC_SURVEY_TEST_PREFIX (include/json-c + lib/libjson-c.{a,so}) overrides the
# macOS Homebrew defaults so the same driver runs against a Linux sysroot.
_DEFAULT_JSON_PREFIXES = (
    "/opt/homebrew/var/homebrew/tmp/.cellar/json-c/0.19",
    "/opt/homebrew/Cellar/json-c/0.19",
    "/opt/homebrew/opt/json-c",
    "/usr/local/opt/json-c",
)


def _default_json_prefix() -> Path:
    for candidate in _DEFAULT_JSON_PREFIXES:
        if (Path(candidate) / "include/json-c/json.h").is_file():
            return Path(candidate)
    return Path(_DEFAULT_JSON_PREFIXES[0])


_ENV_PREFIX = os.environ.get("AC_SURVEY_TEST_PREFIX", "")
JSON_PREFIX = Path(_ENV_PREFIX) if _ENV_PREFIX else _default_json_prefix()
_ENV_OPENSSL = os.environ.get("AC_SURVEY_TEST_OPENSSL_PREFIX", "")
OPENSSL_PREFIX = Path(_ENV_OPENSSL) if _ENV_OPENSSL else (
    JSON_PREFIX if _ENV_PREFIX else Path("/opt/homebrew/opt/openssl@3"))


def schema_version() -> int:
    match = re.search(r"#define AC_SCHEMA_VERSION (\d+)",
                      SOURCE.read_text(encoding="utf-8"))
    assert match, "AC_SCHEMA_VERSION not found in ac_db.c"
    return int(match.group(1))


def assert_producer_contract() -> None:
    """The ingest must refuse anything it cannot honestly difference."""
    source = SOURCE.read_text(encoding="utf-8")
    ingest = source[
        source.index("static int ac_db_tx_retry_parse"):
        source.index("int ac_db_ap_telemetry_store")
    ]
    # Only counters declared cumulative are differenced.
    assert '"tx_retry_counter_semantics"' in ingest
    assert 'strcmp(semantics, "cumulative")' in ingest
    # The instantaneous percentage must never be read back into history. The
    # bucket does store a derived retry_rate_pct, computed from its own two
    # deltas, so what has to be absent is any *read* of the reported rate.
    parse = source[
        source.index("static int ac_db_tx_retry_parse"):
        source.index("static int ac_db_tx_retry_cursor_write")
    ]
    for forbidden in ('"retry_rate_pct"', '"retries"', '"tx_failures"'):
        assert forbidden not in parse, (
            f"retry history must not read {forbidden} as its numerator"
        )
    # Only the two cumulative fields may be consumed.
    assert '"tx_total"' in parse and '"tx_retries"' in parse
    # Telemetry must actually call the ingest, otherwise nothing is produced.
    assert "ac_db_tx_retry_ingest(ap_id, id, session_epoch, observed_at," in source


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
    assert_producer_contract()
    expected_schema = schema_version()
    with tempfile.TemporaryDirectory(prefix="ac-tx-retry-history-") as raw:
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
                "INSERT INTO ac_schema_meta VALUES(1,7,'dreamingwrt-ac',1)"
            )
        migration.chmod(0o600)
        run(binary, migration, "init-only")
        with sqlite3.connect(migration) as connection:
            assert connection.execute(
                "SELECT version FROM ac_schema_meta WHERE singleton=1"
            ).fetchone() == (expected_schema,)
            for table in ("ac_radio_tx_retry_cursor", "ac_radio_tx_retry_bucket"):
                assert connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                    (table,),
                ).fetchone() is not None, f"missing table after migration: {table}"
            # The cursor has to remember which producer it belongs to, or a
            # source change cannot be detected and rebaselined.
            assert connection.execute(
                "SELECT COUNT(*) FROM pragma_table_info('ac_radio_tx_retry_cursor') "
                "WHERE name='source'"
            ).fetchone() == (1,)

        database = directory / "runtime.db"
        result = run(binary, database)
        for token in (
            f"schema={expected_schema}",
            "warming_up=1",
            "delta_recomputed=1",
            "wrap_rebaselined=1",
            "source_change_rebaselined=1",
            "session_change_rebaselined=1",
            "rewind_rebaselined=1",
            "rate_only_rejected=1",
            "semantics_enforced=1",
            "paging=1",
        ):
            assert token in result.stdout, (token, result.stdout)
        with sqlite3.connect(database) as connection:
            rows = connection.execute(
                "SELECT COUNT(*) FROM ac_radio_tx_retry_bucket"
            ).fetchone()[0]
            assert rows <= 576, rows
            # A bucket whose rate does not match its own deltas would make the
            # chart unreconcilable against the raw counters.
            assert connection.execute(
                "SELECT COUNT(*) FROM ac_radio_tx_retry_bucket WHERE "
                "tx_total_delta<=0 OR tx_retries_delta<0 OR "
                "tx_retries_delta>tx_total_delta OR "
                "ABS(retry_rate_pct-(CAST(tx_retries_delta AS REAL)*100.0/"
                "tx_total_delta))>0.000001"
            ).fetchone() == (0,)
            assert connection.execute("PRAGMA quick_check").fetchone() == ("ok",)

        # Reopen the same file: buckets written before the restart stay queryable.
        readback = run(binary, database, "readback")
        assert "readback_reason=available" in readback.stdout, readback.stdout
    print("ok: AC TX retry cursor, buckets, rebaselining, retention, paging "
          "and restart readback")


if __name__ == "__main__":
    main()

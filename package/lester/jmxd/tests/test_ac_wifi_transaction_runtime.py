#!/usr/bin/env python3
"""W3 wifi transaction orchestration: atomic fan-out to transaction +
per-AP targets + per-AP queued config jobs, idempotent replay, revision
conflict and invalid-target rollback, status join."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/ac/ac_db.c"
FIXTURE = ROOT / "tests/ac_wifi_transaction_runtime_fixture.c"
_ENV_PREFIX = os.environ.get("AC_SURVEY_TEST_PREFIX", "")
JSON_PREFIX = Path(_ENV_PREFIX) if _ENV_PREFIX else Path(
    "/opt/homebrew/var/homebrew/tmp/.cellar/json-c/0.19")
_ENV_OPENSSL = os.environ.get("AC_SURVEY_TEST_OPENSSL_PREFIX", "")
OPENSSL_PREFIX = Path(_ENV_OPENSSL) if _ENV_OPENSSL else (
    JSON_PREFIX if _ENV_PREFIX else Path("/opt/homebrew/opt/openssl@3"))


def static_contract() -> None:
    db = SOURCE.read_text(encoding="utf-8")
    for token in (
        "ac_db_wifi_transaction_apply",
        "ac_db_wifi_transaction_status_json",
        '"revision_conflict"',
        "BEGIN IMMEDIATE",
        "ac_transaction_targets",
    ):
        assert token in db, f"missing transaction contract: {token}"
    # Dormant: no ubus method and no capability flip source in this batch.
    ubus = (ROOT / "src/ac/ac_ubus.c").read_text(encoding="utf-8")
    assert "wifi_transaction_apply" not in ubus, (
        "transaction apply must not be a ubus method"
    )
    protocol = (ROOT / "src/ac/ac_protocol.c").read_text(encoding="utf-8")
    for gate in ('"radio_update", 0', '"ssid_create", 0',
                 '"transactional_apply", 0'):
        assert gate in protocol, f"write gate no longer fail-closed: {gate}"


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


def test_runtime() -> None:
    with tempfile.TemporaryDirectory(prefix="ac-wifi-tx-") as raw:
        temp = Path(raw)
        binary = temp / "fixture"
        compile_fixture(binary)
        env = os.environ.copy()
        env["DREAMINGWRT_AC_DB_PATH"] = str(temp / "config.db")
        completed = subprocess.run([str(binary)], env=env, check=True,
                                   capture_output=True, text=True)
        assert completed.stdout.strip() == "ok", completed.stdout


def main() -> None:
    static_contract()
    test_runtime()
    print("ok: W3 wifi transaction orchestration fan-out contract")


if __name__ == "__main__":
    main()

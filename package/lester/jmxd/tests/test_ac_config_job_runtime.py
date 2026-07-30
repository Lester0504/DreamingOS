#!/usr/bin/env python3
"""W2b AC config job store: idempotent create, session-gated lease,
bound transitions, replayable finish and lease recovery (schema v11)."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/ac/ac_db.c"
INTERNAL = ROOT / "src/ac/ac_internal.h"
FIXTURE = ROOT / "tests/ac_config_job_runtime_fixture.c"
_ENV_PREFIX = os.environ.get("AC_SURVEY_TEST_PREFIX", "")
JSON_PREFIX = Path(_ENV_PREFIX) if _ENV_PREFIX else Path(
    "/opt/homebrew/var/homebrew/tmp/.cellar/json-c/0.19")
_ENV_OPENSSL = os.environ.get("AC_SURVEY_TEST_OPENSSL_PREFIX", "")
OPENSSL_PREFIX = Path(_ENV_OPENSSL) if _ENV_OPENSSL else (
    JSON_PREFIX if _ENV_PREFIX else Path("/opt/homebrew/opt/openssl@3"))


def static_contract() -> None:
    db = SOURCE.read_text(encoding="utf-8")
    internal = INTERNAL.read_text(encoding="utf-8")
    for token in (
        "CREATE TABLE IF NOT EXISTS ac_config_jobs (",
        "idx_ac_config_jobs_idempotency",
        "ac-config-job-request-v1",
        "ac_db_config_jobs_recover(ac_now_s())",
    ):
        assert token in db, f"missing config job contract: {token}"
    assert "#define AC_SCHEMA_VERSION 12" in db
    assert "#define AC_SCHEMA_VERSION 12" in internal
    # No ubus/REST surface may reach the config job store before the W3
    # orchestration lands behind the capability gates.
    ubus = (ROOT / "src/ac/ac_ubus.c").read_text(encoding="utf-8")
    assert "ac_db_config_job" not in ubus, (
        "config job store leaked into the management ubus before W3"
    )


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
    with tempfile.TemporaryDirectory(prefix="ac-config-job-") as raw:
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
    print("ok: W2b AC config job store dispatch contract")


if __name__ == "__main__":
    main()

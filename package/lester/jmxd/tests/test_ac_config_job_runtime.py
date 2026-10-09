#!/usr/bin/env python3
"""AC config jobs: v3 write gate, bound execution and verified finish."""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apd_test_deps  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/ac/ac_db.c"
SECRETS = ROOT / "src/ac/ac_secrets.c"
INTERNAL = ROOT / "src/ac/ac_internal.h"
FIXTURE = ROOT / "tests/ac_config_job_runtime_fixture.c"


def static_contract() -> None:
    db = SOURCE.read_text(encoding="utf-8")
    internal = INTERNAL.read_text(encoding="utf-8")
    for token in (
        "CREATE TABLE IF NOT EXISTS ac_config_jobs (",
        "idx_ac_config_jobs_idempotency",
        "ac-config-job-request-v2",
        "ac_db_config_jobs_recover(ac_now_s())",
    ):
        assert token in db, f"missing config job contract: {token}"
    standalone = re.search(r"#define AC_SCHEMA_VERSION (\d+)", db)
    production = re.search(r"#define AC_SCHEMA_VERSION (\d+)", internal)
    assert standalone and production
    assert int(standalone.group(1)) >= int(production.group(1))
    assert 'ac_add_column("ac_ssid_bindings", "section_name"' in db
    assert "ac_db_ap_write_session_is_current_locked" in db
    assert '"readback_verification_failed"' in db


def compile_fixture(output: Path) -> None:
    json_flags = apd_test_deps.package_flags("json-c")
    openssl_flags = apd_test_deps.package_flags("openssl")
    command = [
        os.environ.get("CC", "cc"), "-std=c11",
        "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
        "-DAC_DB_TEST_STANDALONE", "-DAC_DB_TELEMETRY_TEST_STANDALONE",
        "-Wall", "-Wextra", "-Werror",
        str(FIXTURE), str(SOURCE), str(SECRETS),
        *json_flags, *openssl_flags, "-lsqlite3", "-lm",
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

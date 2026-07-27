#!/usr/bin/env python3
"""W2b config job journal: durable state machine, replay idempotency,
restart recovery surface and the fail-closed previous_json invariant."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
JOURNAL = ROOT / "src/apd/apd_config_job_journal.c"
HEADER = ROOT / "src/apd/apd_config_job_journal.h"
FIXTURE = ROOT / "tests/apd_config_job_journal_fixture.c"
MAKEFILE = ROOT / "src/Makefile"


def static_contract() -> None:
    journal = JOURNAL.read_text(encoding="utf-8")
    header = HEADER.read_text(encoding="utf-8")
    for token in (
        "'offered','staged','applying','applied'",
        "'completed','failed','rolled_back'",
        "BEGIN IMMEDIATE",
        "previous_json",
        "finish_acked",
    ):
        assert token in journal, f"missing journal contract: {token}"
    assert "APD_CONFIG_JOB_RETENTION_SECONDS 86400" in header
    # The rollback reference must be mandatory on the applying transition.
    assert "if (!previous_json || !previous_json[0])" in journal
    assert "apd/apd_config_job_journal.o" in MAKEFILE.read_text(
        encoding="utf-8")


def compile_fixture(output: Path) -> None:
    prefix = os.environ.get("APD_TEST_PREFIX", "")
    extra: list[str] = []
    if prefix:
        extra = [f"-I{Path(prefix) / 'include'}",
                 f"-L{Path(prefix) / 'lib'}",
                 f"-Wl,-rpath,{Path(prefix) / 'lib'}"]
    command = [
        os.environ.get("CC", "cc"), "-std=c11",
        "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
        "-Wall", "-Wextra", "-Werror", *extra,
        str(FIXTURE), str(JOURNAL),
        "-lsqlite3",
        "-o", str(output),
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)


def test_runtime() -> None:
    with tempfile.TemporaryDirectory(prefix="apd-config-journal-") as raw:
        temp = Path(raw)
        binary = temp / "fixture"
        compile_fixture(binary)
        completed = subprocess.run([str(binary), str(temp)], check=True,
                                   capture_output=True, text=True)
        assert completed.stdout.strip() == "ok", completed.stdout


def main() -> None:
    static_contract()
    test_runtime()
    print("ok: W2b config job journal durable state machine contract")


if __name__ == "__main__":
    main()

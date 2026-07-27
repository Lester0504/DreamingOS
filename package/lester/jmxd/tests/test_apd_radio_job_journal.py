#!/usr/bin/env python3
"""Dedicated runtime tests for the APD radio-job durable journal."""

from __future__ import annotations

import os
from pathlib import Path
import glob
import sqlite3
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/apd/apd_radio_job_journal.c"
HEADER = ROOT / "src/apd/apd_radio_job_journal.h"
FIXTURE = ROOT / "tests/apd_radio_job_journal_fixture.c"


def dependency_prefix(name: str) -> Path:
    override = os.environ.get(f"APD_RADIO_JOB_{name.upper()}_PREFIX")
    if override:
        return Path(override)
    result = subprocess.run(
        ["brew", "--prefix", name], check=False, capture_output=True, text=True
    )
    if result.returncode == 0 and Path(result.stdout.strip()).exists():
        return Path(result.stdout.strip())
    candidates = sorted(
        Path(path)
        for pattern in (
            f"/opt/homebrew/Cellar/{name}/*",
            f"/opt/homebrew/var/homebrew/tmp/.cellar/{name}/*",
            f"/usr/local/Cellar/{name}/*",
        )
        for path in glob.glob(pattern)
        if Path(path).is_dir()
    )
    if candidates:
        return candidates[-1]
    return Path("/usr")


def compile_fixture(output: Path) -> None:
    json_c = dependency_prefix("json-c")
    sqlite = dependency_prefix("sqlite")
    command = [
        os.environ.get("CC", "cc"),
        "-std=c11",
        "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
        "-Wall", "-Wextra", "-Werror",
        f"-I{json_c / 'include'}",
        f"-I{sqlite / 'include'}",
        str(FIXTURE), str(SOURCE),
        f"-L{sqlite / 'lib'}",
        f"-Wl,-rpath,{sqlite / 'lib'}",
        str(json_c / "lib/libjson-c.a"), "-lsqlite3", "-o", str(output),
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)


def verify_schema(database: Path) -> None:
    with sqlite3.connect(database) as connection:
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(apd_radio_job_journal)")
        }
        assert {
            "job_id", "attempt_id", "dispatch_generation", "request_digest",
            "ap_id", "session_epoch", "radio_id", "mode", "state",
            "finish_id", "outcome", "error_code", "observed_at", "result_json",
            "result_count", "result_bytes", "result_complete", "finish_acked",
            "finish_acked_at", "created_at", "updated_at",
        } <= columns
        indexes = {
            row[1]
            for row in connection.execute("PRAGMA index_list(apd_radio_job_journal)")
        }
        assert "idx_apd_radio_job_reconcile" in indexes
        assert "idx_apd_radio_job_pending_finish" in indexes
        assert "idx_apd_radio_job_retention" in indexes
        states = dict(
            connection.execute("SELECT job_id,state FROM apd_radio_job_journal")
        )
        assert states["10000000-0000-4000-8000-000000000005"] == "offered"
        assert states["10000000-0000-4000-8000-000000000006"] == "interrupted"
        recovered = connection.execute(
            "SELECT state,finish_id,outcome,error_code,observed_at,result_json,"
            "result_count,result_bytes,result_complete,finish_acked,updated_at "
            "FROM apd_radio_job_journal WHERE job_id=?",
            ("10000000-0000-4000-8000-000000000009",),
        ).fetchone()
        assert recovered == (
            "interrupted", "10000000-0000-4000-8000-000000000001",
            "failed", "apd_restarted_during_execution", 1050, "[]", 0, 2,
            0, 1, 1052,
        )
        finished = connection.execute(
            "SELECT result_count,result_complete,finish_acked,result_json "
            "FROM apd_radio_job_journal WHERE job_id=?",
            ("10000000-0000-4000-8000-000000000001",),
        ).fetchone()
        assert finished == (1, 1, 1, '[{"bssid":"02:00:00:00:00:01"}]')


def verify_source_contract() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    header = HEADER.read_text(encoding="utf-8")
    assert "extern sqlite3 *g_apd_db" in source
    assert 'journal_exec("BEGIN IMMEDIATE")' in source
    assert "sqlite3_bind_" in source
    assert "APD_RADIO_JOB_RESULT_MAX_ITEMS 128" in header
    assert "APD_RADIO_JOB_RESULT_MAX_BYTES (48U * 1024U)" in header
    for api in (
        "apd_radio_job_journal_init", "apd_radio_job_offer_store",
        "apd_radio_job_mark_running", "apd_radio_job_finish_store",
        "apd_radio_job_pending_finish_get", "apd_radio_job_finish_ack",
        "apd_radio_job_pending_reconcile_get",
        "apd_radio_job_restart_recover", "apd_radio_job_cancel_requested",
        "apd_radio_job_session_rebind",
        "apd_radio_job_journal_prune",
    ):
        assert api in source and api in header


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="apd-radio-job-journal-") as temp:
        directory = Path(temp)
        binary = directory / "fixture"
        database = directory / "apd.db"
        compile_fixture(binary)
        result = subprocess.run(
            [str(binary), str(database)], check=True, capture_output=True, text=True
        )
        assert "journal=ok" in result.stdout and "reconcile=ok" in result.stdout
        assert "limits=ok" in result.stdout
        verify_schema(database)
    verify_source_contract()
    print("ok: APD radio job durable journal, replay, recovery, ack and limits")


if __name__ == "__main__":
    main()

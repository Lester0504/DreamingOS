#!/usr/bin/env python3
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/webd/webd_admin_transaction.c"
HEADER = ROOT / "src/webd/webd_admin_transaction.h"
HARNESS = ROOT / "tests/webd_admin_transaction_test.c"
MAKEFILE = ROOT / "src/Makefile"


def test_transaction_contract_markers() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    header = HEADER.read_text(encoding="utf-8")
    makefile = MAKEFILE.read_text(encoding="utf-8")

    for marker in (
        "WEBD_ADMIN_TXN_IRREVERSIBLE",
        "WEBD_ADMIN_TXN_ROLLBACK_FAILED",
        "webd_admin_txn_preflight_fn",
        "webd_admin_txn_snapshot_fn",
        "webd_admin_txn_restore_fn",
        "webd_admin_txn_execute",
    ):
        assert marker in header, f"missing admin transaction contract: {marker}"
    for marker in (
        "irreversible_step_must_be_unique_and_last",
        "reversible_step_requires_snapshot_restore_free",
        "txn_rollback",
        "i + 1",
        "WEBD_ADMIN_TXN_ROLLBACK_FAILED",
    ):
        assert marker in source, f"missing admin transaction behavior: {marker}"
    assert "webd/webd_admin_transaction.o" in makefile
    assert "jmx_app_api" not in source
    assert "sqlite" not in source.lower()
    assert "json-c" not in source


def test_compiled_fault_injection_contract() -> None:
    compiler = os.environ.get("CC") or shutil.which("cc") or shutil.which("gcc")
    assert compiler, "a C compiler is required"
    with tempfile.TemporaryDirectory(prefix="webd-admin-transaction-") as temp_name:
        executable = Path(temp_name) / "webd_admin_transaction_test"
        command = [
            compiler,
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(ROOT / "src/webd"),
            str(SOURCE),
            str(HARNESS),
            "-o",
            str(executable),
        ]
        compiled = subprocess.run(command, text=True, capture_output=True)
        assert compiled.returncode == 0, compiled.stderr
        ran = subprocess.run(
            [str(executable)], text=True, capture_output=True, timeout=10
        )
        assert ran.returncode == 0, ran.stderr + ran.stdout
        assert "webd_admin_transaction_runtime_ok" in ran.stdout


if __name__ == "__main__":
    test_transaction_contract_markers()
    test_compiled_fault_injection_contract()
    print("ok: web admin compensation transaction helper contracts")

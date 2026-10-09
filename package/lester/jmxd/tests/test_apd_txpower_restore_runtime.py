#!/usr/bin/env python3
"""Power changes preserve shared-PHY lifecycle; startup never cycles live Wi-Fi."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile

import apd_test_deps

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="apd-txpower-restore-") as raw:
        binary = Path(raw) / "fixture"
        command = [
            os.environ.get("CC", "cc"), "-std=c11",
            "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
            "-Wall", "-Wextra", "-Werror",
            str(ROOT / "tests/apd_txpower_restore_fixture.c"),
            *apd_test_deps.package_flags("json-c"), "-o", str(binary),
        ]
        compile_result = subprocess.run(command, capture_output=True, text=True)
        assert compile_result.returncode == 0, compile_result.stderr
        result = subprocess.run([str(binary)], cwd=raw, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "ok", result.stdout
    print("ok: APD startup/idempotence, shared-PHY switching and bounded rollback")


if __name__ == "__main__":
    main()

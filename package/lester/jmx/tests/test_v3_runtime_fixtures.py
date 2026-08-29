#!/usr/bin/env python3
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
SRC = ROOT / "src"


def test_v3_kernel_runtime_fixtures() -> None:
    with tempfile.TemporaryDirectory(prefix="jmx-v3-runtime-") as tmp:
        binary = Path(tmp) / "test_v3_runtime_fixtures"
        command = [
            "cc",
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-unused-parameter",
            "-I",
            str(TESTS / "compat"),
            "-I",
            str(SRC),
            str(TESTS / "test_v3_runtime_fixtures.c"),
            str(SRC / "jmx_v3_rules.c"),
            str(SRC / "jmx_v3_nl_handler.c"),
            str(SRC / "jmx_v3_ac.c"),
            "-o",
            str(binary),
        ]
        subprocess.run(command, check=True, cwd=ROOT)
        completed = subprocess.run(
            [str(binary)], check=True, cwd=ROOT, text=True, capture_output=True
        )
        assert completed.stdout.strip() == "ok: v3 kernel runtime fixtures passed"


if __name__ == "__main__":
    test_v3_kernel_runtime_fixtures()
    print("ok: v3 kernel runtime fixture build/run passed")

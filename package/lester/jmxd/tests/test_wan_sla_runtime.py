#!/usr/bin/env python3
"""Compile and execute the production SLA evaluator and transaction fixtures."""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run():
    flags = shlex.split(subprocess.check_output(
        ["pkg-config", "--cflags", "--libs", "json-c", "sqlite3"], text=True))
    with tempfile.TemporaryDirectory(prefix="wan-sla-tests-") as tmp:
        for name in ("eval", "tx"):
            binary = str(Path(tmp) / name)
            subprocess.run([
                os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                "-I", str(ROOT / "src"), str(ROOT / "tests" / f"wan_sla_{name}_fixture.c"),
                str(ROOT / "src/flowd/wan_sla_eval.c"), "-o", binary, *flags, "-lm",
            ], check=True)
            subprocess.run([binary], check=True)


if __name__ == "__main__":
    run()

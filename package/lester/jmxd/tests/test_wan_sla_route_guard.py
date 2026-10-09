#!/usr/bin/env python3
"""Compile and execute the production WAN SLA routed decision guard."""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    flags = shlex.split(subprocess.check_output(
        ["pkg-config", "--cflags", "--libs", "json-c", "sqlite3"], text=True))
    with tempfile.TemporaryDirectory(prefix="wan-sla-route-guard-") as tmp:
        binary = str(Path(tmp) / "guard")
        subprocess.run([
            os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra", "-Werror",
            "-I", str(ROOT / "src"),
            str(ROOT / "tests/wan_sla_route_guard_fixture.c"),
            str(ROOT / "src/routed/wan_sla_route_guard.c"),
            str(ROOT / "src/flowd/wan_sla_config.c"),
            str(ROOT / "src/flowd/wan_sla_eval.c"),
            "-o", binary, *flags, "-lm",
        ], check=True)
        subprocess.run([binary], check=True)


if __name__ == "__main__":
    main()

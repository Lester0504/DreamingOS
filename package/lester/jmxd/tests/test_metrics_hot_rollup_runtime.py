#!/usr/bin/env python3
from pathlib import Path
import os
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/metrics_store_runtime.c"
SOURCE = ROOT / "src/jmx_metrics_store.c"

flags = subprocess.check_output(
    ["pkg-config", "--cflags", "--libs", "sqlite3", "json-c"],
    text=True,
).strip()
run_env = os.environ.copy()
run_env.pop("LD_LIBRARY_PATH", None)

with tempfile.TemporaryDirectory() as tmp:
    binary = Path(tmp) / "metrics-runtime"
    cmd = [
        os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra",
        "-Werror", f"-I{ROOT / 'src'}", str(SOURCE), str(FIXTURE),
        "-o", str(binary), *shlex.split(flags),
    ]
    subprocess.run(cmd, check=True, env=run_env)
    subprocess.run([str(binary), tmp], check=True, env=run_env)

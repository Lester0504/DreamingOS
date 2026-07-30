#!/usr/bin/env python3
"""W2 config-job restart recovery and fail-closed rollback contract."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/apd_config_recovery_fixture.c"
RECOVERY = ROOT / "src/apd/apd_config_recovery.c"
JOURNAL = ROOT / "src/apd/apd_config_job_journal.c"


def main() -> None:
    prefix_raw = os.environ.get("APD_TEST_PREFIX", "")
    prefix = (Path(prefix_raw) if prefix_raw else
              Path("/opt/homebrew/var/homebrew/tmp/.cellar/json-c/0.19"))
    if not (prefix / "include/json-c/json.h").is_file():
        prefix = None
    extra = ([f"-I{prefix / 'include'}", f"-L{prefix / 'lib'}",
              f"-Wl,-rpath,{prefix / 'lib'}"] if prefix else [])
    json_link = ([str(prefix / "lib/libjson-c.a")]
                 if prefix and (prefix / "lib/libjson-c.a").is_file()
                 else ["-ljson-c"])
    with tempfile.TemporaryDirectory(prefix="apd-config-recovery-") as raw:
        binary = Path(raw) / "fixture"
        command = [os.environ.get("CC", "cc"), "-std=c11",
                   "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
                   "-Wall", "-Wextra", "-Werror", *extra,
                   str(FIXTURE), str(RECOVERY), str(JOURNAL),
                   *json_link, "-lsqlite3", "-o", str(binary)]
        subprocess.run(command, check=True, capture_output=True, text=True)
        result = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
        assert result.stdout.strip() == "ok", result.stdout
    print("ok: W2 config job restart recovery is durable and fail-closed")


if __name__ == "__main__":
    main()

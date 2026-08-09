#!/usr/bin/env python3
"""W2 config-job restart recovery and fail-closed rollback contract."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile

import apd_test_deps

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/apd_config_recovery_fixture.c"
RECOVERY = ROOT / "src/apd/apd_config_recovery.c"
JOURNAL = ROOT / "src/apd/apd_config_job_journal.c"


def main() -> None:
    prefix, json_shared = apd_test_deps.resolve_json_prefix()
    extra = ([f"-I{prefix / 'include'}", f"-L{prefix / 'lib'}",
              f"-Wl,-rpath,{prefix / 'lib'}"] if prefix else [])
    # Only take the archive when no .so exists: the staging_dir .a is an LTO
    # archive the host linker rejects.
    json_link = (["-ljson-c"]
                 if json_shared or not (prefix / "lib/libjson-c.a").is_file()
                 else [str(prefix / "lib/libjson-c.a")])
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

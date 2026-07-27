#!/usr/bin/env python3
"""Compile and execute the shared AP control wire boundary."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
OPENSSL = Path("/opt/homebrew/opt/openssl@3")
JSON_C = Path("/opt/homebrew/var/homebrew/tmp/.cellar/json-c/0.19")


def main() -> None:
    prefix_raw = os.environ.get("AP_CONTROL_WIRE_TEST_PREFIX", "")
    prefix = Path(prefix_raw) if prefix_raw else OPENSSL
    with tempfile.TemporaryDirectory(prefix="ap-control-wire-") as raw:
        binary = Path(raw) / "fixture"
        command = [
            os.environ.get("CC", "cc"), "-std=c11",
            "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
            "-Wall", "-Wextra", "-Werror", f"-I{ROOT / 'src'}",
            f"-I{prefix / 'include'}", f"-I{JSON_C / 'include'}",
            f"-L{prefix / 'lib'}", f"-Wl,-rpath,{prefix / 'lib'}",
            str(ROOT / "tests/ap_control_wire_fixture.c"),
            str(ROOT / "src/ap_control_wire.c"),
            str(JSON_C / "lib/libjson-c.a"), "-lssl", "-lcrypto",
            "-o", str(binary),
        ]
        subprocess.run(command, check=True, capture_output=True, text=True)
        env = os.environ.copy()
        if prefix_raw:
            env["LD_LIBRARY_PATH"] = str(prefix / "lib")
        result = subprocess.run([str(binary)], env=env, check=True,
                                capture_output=True, text=True)
        assert result.stdout.strip() == (
            "ok: AP control framing, strict JSON, duplicate keys, and field gates")
    print("ok: shared AP control wire runtime boundary")


if __name__ == "__main__":
    main()

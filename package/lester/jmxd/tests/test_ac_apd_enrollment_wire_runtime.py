#!/usr/bin/env python3
"""Cross-component enrollment wire compatibility test."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/ac_apd_enrollment_wire_fixture.c"
AC_HEADER = ROOT / "tests/ac_enrollment_fixture.h"
AC_ENROLLMENT = ROOT / "src/ac/ac_enrollment.c"
APD_ENROLLMENT = ROOT / "src/apd/apd_enrollment.c"
OPENSSL = Path("/opt/homebrew/opt/openssl@3")


def compile_fixture(output: Path) -> None:
    prefix_raw = os.environ.get("AC_APD_WIRE_TEST_PREFIX", "")
    prefix = Path(prefix_raw) if prefix_raw else None
    flags = (
        [f"-I{prefix / 'include'}", f"-L{prefix / 'lib'}",
         f"-Wl,-rpath,{prefix / 'lib'}"]
        if prefix else [f"-I{OPENSSL / 'include'}", f"-L{OPENSSL / 'lib'}"]
    )
    command = [
        os.environ.get("CC", "cc"), "-std=c11",
        "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
        "-DAC_ENROLLMENT_FIXTURE_TYPES", f"-include{AC_HEADER}",
        "-DAPD_ENROLLMENT_TEST_STANDALONE",
        "-Wall", "-Wextra", "-Werror", *flags,
        str(FIXTURE), str(AC_ENROLLMENT), str(APD_ENROLLMENT),
        "-lcrypto", "-o", str(output),
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="ac-apd-wire-") as raw:
        binary = Path(raw) / "fixture"
        compile_fixture(binary)
        result = subprocess.run([str(binary)], check=True,
                                capture_output=True, text=True)
        assert result.stdout.strip() == (
            "ok: APD binary-v1 bytes and signature verify on the AC side"
        )
        print(result.stdout.strip())


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Compile and exercise the Passkey core through its real route handlers."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile

from apd_test_deps import package_flags


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/passkey_core_fixture.c"
STUBS = ROOT / "tests/passkey_test_stubs.c"
PASSKEY = ROOT / "src/webd/webd_passkey.c"
SESSION = ROOT / "src/webd/webd_session_idle.c"
STUB_INCLUDE = ROOT / "tests/passkey_stubs"


def quoted_define(name: str, value: Path) -> str:
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'-D{name}="{escaped}"'


def compile_fixture(output: Path, sandbox: Path) -> None:
    passkey_dir = sandbox / "passkeys"
    command = [
        os.environ.get("CC", "cc"),
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wno-deprecated-declarations",
        f"-I{STUB_INCLUDE}",
        f"-I{ROOT / 'src'}",
        quoted_define("WEBD_PASSKEY_DIR", passkey_dir),
        quoted_define("WEBD_PASSKEY_CRED_DIR", passkey_dir / "credentials"),
        quoted_define("WEBD_PASSKEY_CONFIG_PATH", passkey_dir / "config.json"),
        quoted_define(
            "WEBD_PASSKEY_CHALLENGE_DIR", sandbox / "runtime/challenges"
        ),
        str(FIXTURE),
        str(STUBS),
        str(PASSKEY),
        str(SESSION),
        *package_flags("json-c", "openssl", "sqlite3"),
        "-o",
        str(output),
    ]
    completed = subprocess.run(command, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr


def run_phase(binary: Path, phase: str) -> None:
    completed = subprocess.run(
        [str(binary), phase], capture_output=True, text=True
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == f"{phase}_ok", completed.stdout


def test_passkey_registration_restart_authentication_and_guards() -> None:
    with tempfile.TemporaryDirectory(prefix="dreamingwrt-passkey-") as raw:
        sandbox = Path(raw)
        binary = sandbox / "passkey-core-fixture"

        compile_fixture(binary, sandbox)
        run_phase(binary, "register")
        run_phase(binary, "authenticate")


if __name__ == "__main__":
    test_passkey_registration_restart_authentication_and_guards()
    print("ok: passkey registration, restart authentication, and guards")

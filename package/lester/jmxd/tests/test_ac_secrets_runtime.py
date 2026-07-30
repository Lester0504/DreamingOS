#!/usr/bin/env python3
"""Authenticated AC secret storage without exposing a management API."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/ac/ac_secrets.c"
HEADER = ROOT / "src/ac/ac_secrets.h"
FIXTURE = ROOT / "tests/ac_secrets_runtime_fixture.c"
OPENSSL_PREFIX = Path(os.environ.get(
    "AC_SECRETS_TEST_OPENSSL_PREFIX", "/opt/homebrew/opt/openssl@3"
))


def static_contract() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    header = HEADER.read_text(encoding="utf-8")
    makefile = (ROOT / "src/Makefile").read_text(encoding="utf-8")
    for token in (
        "EVP_aes_256_gcm", "RAND_bytes", "EVP_CTRL_GCM_GET_TAG",
        "EVP_CTRL_GCM_SET_TAG", "OPENSSL_cleanse", "O_NOFOLLOW",
        "ac_secret_owner_secure", "status.st_mode & 0077",
        "AC_SECRET_AAD_DOMAIN",
        "O_CREAT | O_EXCL", "linkat", "fsync",
    ):
        assert token in source, f"missing secret storage invariant: {token}"
    assert "ac_secrets_open_with_key" in header
    assert "#ifdef AC_SECRETS_TESTING" in header
    assert "ac/ac_secrets.o" in makefile

    # This phase is storage-only and must not create a management surface.
    for relative in ("src/ac/ac_ubus.c", "src/ac/ac_transport.c"):
        assert "ac_secrets_" not in (ROOT / relative).read_text(encoding="utf-8")


def compile_fixture(output: Path) -> None:
    flags: list[str] = []
    if OPENSSL_PREFIX.is_dir():
        flags = [
            f"-I{OPENSSL_PREFIX / 'include'}",
            f"-L{OPENSSL_PREFIX / 'lib'}",
            f"-Wl,-rpath,{OPENSSL_PREFIX / 'lib'}",
        ]
    command = [
        os.environ.get("CC", "cc"), "-std=c11",
        "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
        "-DAC_SECRETS_TESTING", "-Wall", "-Wextra", "-Werror",
        f"-I{ROOT / 'src/ac'}", *flags, str(FIXTURE), str(SOURCE),
        "-lsqlite3", "-lcrypto", "-o", str(output),
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)


def runtime_contract() -> None:
    with tempfile.TemporaryDirectory(prefix="ac-secrets-") as raw:
        temp = Path(raw)
        binary = Path(raw) / "fixture"
        compile_fixture(binary)
        key_path = temp / "ac-secrets.key"
        completed = subprocess.run(
            [str(binary), str(key_path)], check=True, capture_output=True, text=True
        )
        assert completed.stdout.strip() == "ok", completed.stdout
        assert key_path.stat().st_mode & 0o777 == 0o600
        assert key_path.stat().st_size == 32


def main() -> None:
    static_contract()
    runtime_contract()
    print("ok: AC secrets AEAD storage contract")


if __name__ == "__main__":
    main()

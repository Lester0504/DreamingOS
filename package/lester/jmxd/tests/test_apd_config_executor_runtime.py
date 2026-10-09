#!/usr/bin/env python3
"""Candidate-aware AP config executor and fail-closed runtime capability contract."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile

import apd_test_deps


ROOT = Path(__file__).resolve().parents[1]
EXECUTOR = ROOT / "src/apd/apd_config_executor.c"
HEADER = ROOT / "src/apd/apd_config_executor.h"
BACKEND = ROOT / "src/apd/apd_backend_openwrt.c"
PROTOCOL = ROOT / "src/apd/apd_protocol.c"
TRANSPORT = ROOT / "src/apd/apd_transport.c"
COMMAND = ROOT / "src/apd/apd_readonly_command.c"
FIXTURE = ROOT / "tests/apd_config_executor_fixture.c"
MAKEFILE = ROOT / "src/Makefile"


def static_contract() -> None:
    executor = EXECUTOR.read_text(encoding="utf-8")
    header = HEADER.read_text(encoding="utf-8")
    backend = BACKEND.read_text(encoding="utf-8")
    protocol = PROTOCOL.read_text(encoding="utf-8")
    transport = TRANSPORT.read_text(encoding="utf-8")
    for token in (
        "uci-wireless-candidate.v1",
        '"candidate_digest_mismatch"',
        '"candidate_option_not_allowed"',
        '"candidate_value_invalid"',
        '"previous_capture_failed"',
        '"uci_set_failed"',
        '"wifi_reload_failed"',
        "apd_config_restore",
    ):
        assert token in executor, f"missing executor contract: {token}"
    assert "APD_CONFIG_SECTIONS_MAX 16U" in header
    assert "apd_config_candidate_validate(candidate, out)" in backend
    assert "apd_config_stage(&paths, candidate, out)" in backend
    assert "apd_config_apply(&paths, uci_candidate, out)" in backend
    assert "apd_config_readback(&paths, candidate, out)" in backend
    assert "apd_config_rollback(&paths, rollback_ref, out)" in backend
    assert "config_executor_unavailable" in protocol
    assert "apd_config_executor_available_default()" in protocol
    assert "apd_config_executor_available_default()" in transport
    assert "connection.protocol_version == 3 && g_apd_transport.write_capable" in transport
    assert "APD_CONFIG_JOBS_TEST_ENABLE" not in transport
    assert "apd/apd_config_executor.o" in MAKEFILE.read_text(
        encoding="utf-8")


def compile_fixture(output: Path) -> None:
    json_prefix, json_shared = apd_test_deps.resolve_json_prefix()
    openssl_prefix, _ = apd_test_deps.resolve_openssl_prefix()
    # Prefer the .so: preferring the archive picks up the staging_dir LTO
    # archive on the build host, which the host linker cannot consume.
    static_lib = json_prefix / "lib/libjson-c.a"
    json_link = ([f"-L{json_prefix / 'lib'}",
                  f"-Wl,-rpath,{json_prefix / 'lib'}", "-ljson-c"]
                 if json_shared or not static_lib.is_file()
                 else [str(static_lib)])
    command = [
        os.environ.get("CC", "cc"), "-std=c11",
        "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
        "-Wall", "-Wextra", "-Werror",
        f"-I{json_prefix / 'include'}",
        f"-I{openssl_prefix / 'include'}",
        str(FIXTURE), str(EXECUTOR), str(COMMAND), *json_link,
        f"-L{openssl_prefix / 'lib'}", "-lcrypto",
        "-o", str(output),
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)


def test_runtime() -> None:
    with tempfile.TemporaryDirectory(prefix="apd-config-exec-") as raw:
        temp = Path(raw)
        binary = temp / "fixture"
        compile_fixture(binary)
        (temp / "config").mkdir()
        (temp / "staging").mkdir()
        completed = subprocess.run([str(binary), "run", str(temp)],
                                   check=True, capture_output=True,
                                   text=True)
        assert completed.stdout.strip() == "ok", completed.stdout + completed.stderr


def main() -> None:
    static_contract()
    test_runtime()
    print("ok: W2a config executor core state machine and dormancy contract")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""W2a config executor core: candidate contract, stage/apply/readback/
rollback state machine over injected fake uci/wifi commands, and the
production-dormancy contract (ops table and capabilities stay disabled)."""

from __future__ import annotations

import os
from pathlib import Path
import glob
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
EXECUTOR = ROOT / "src/apd/apd_config_executor.c"
HEADER = ROOT / "src/apd/apd_config_executor.h"
BACKEND = ROOT / "src/apd/apd_backend_openwrt.c"
PROTOCOL = ROOT / "src/apd/apd_protocol.c"
COMMAND = ROOT / "src/apd/apd_readonly_command.c"
FIXTURE = ROOT / "tests/apd_config_executor_fixture.c"
MAKEFILE = ROOT / "src/Makefile"


def static_contract() -> None:
    executor = EXECUTOR.read_text(encoding="utf-8")
    header = HEADER.read_text(encoding="utf-8")
    backend = BACKEND.read_text(encoding="utf-8")
    protocol = PROTOCOL.read_text(encoding="utf-8")
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
    # Production dormancy: the backend ops table still refuses every write
    # phase and the capability surface still reports them false.  The W2b
    # config_job wire is the only future caller and it must sit behind
    # these gates.
    for gate in ("phase2_candidate_validation_pending",
                 "phase2_atomic_staging_pending",
                 "phase2_transactional_apply_pending",
                 "phase2_canonical_readback_pending",
                 "phase2_rollback_readback_pending"):
        assert gate in backend, f"ops gate missing: {gate}"
    assert "apd_config_apply" not in backend, (
        "backend ops must not reach the executor before the W2b wire gate"
    )
    for capability in ('"validate", 0', '"stage", 0', '"apply", 0',
                       '"readback", 0', '"rollback", 0'):
        assert capability in protocol, (
            f"apd capability no longer fail-closed: {capability}"
        )
    assert "apd/apd_config_executor.o" in MAKEFILE.read_text(
        encoding="utf-8")


def compile_fixture(output: Path) -> None:
    configured_json = os.environ.get("APD_JSON_C_PREFIX", "")
    json_candidates = [Path(configured_json)] if configured_json else []
    json_candidates.extend((Path("/opt/homebrew/opt/json-c"), Path("/usr/local")))
    json_candidates.extend(Path(value) for value in glob.glob(
        "/opt/homebrew/var/homebrew/tmp/.cellar/json-c/*"
    ))
    json_prefix = next((value for value in json_candidates
                        if (value / "include/json-c/json.h").is_file() and
                           ((value / "lib/libjson-c.a").is_file() or
                            (value / "lib/libjson-c.dylib").is_file() or
                            (value / "lib/libjson-c.so").is_file())), None)
    assert json_prefix, "json-c headers and library are required"

    configured_ssl = os.environ.get("APD_OPENSSL_PREFIX", "")
    ssl_candidates = [Path(configured_ssl)] if configured_ssl else []
    ssl_candidates.extend((Path("/opt/homebrew/opt/openssl@3"), Path("/usr/local"), Path("/usr")))
    ssl_prefix = next((value for value in ssl_candidates
                       if (value / "include/openssl/sha.h").is_file()), None)
    assert ssl_prefix, "OpenSSL headers and library are required"

    static_lib = json_prefix / "lib/libjson-c.a"
    json_link = ([str(static_lib)] if static_lib.is_file() else
                 [f"-L{json_prefix / 'lib'}",
                  f"-Wl,-rpath,{json_prefix / 'lib'}", "-ljson-c"])
    command = [
        os.environ.get("CC", "cc"), "-std=c11",
        "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
        "-Wall", "-Wextra", "-Werror",
        f"-I{json_prefix / 'include'}",
        f"-I{ssl_prefix / 'include'}",
        str(FIXTURE), str(EXECUTOR), str(COMMAND), *json_link,
        f"-L{ssl_prefix / 'lib'}", "-lcrypto",
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
        assert completed.stdout.strip() == "ok", completed.stdout


def main() -> None:
    static_contract()
    test_runtime()
    print("ok: W2a config executor core state machine and dormancy contract")


if __name__ == "__main__":
    main()

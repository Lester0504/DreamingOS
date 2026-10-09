#!/usr/bin/env python3
"""Static contract and compiled-fixture check for the system settings runtime.

Covers the time / logging / zram transaction module produced under the
Acceptance-to-Backend system-settings executors handoff. The wiring into
``jmx_netconfig_db.c`` is a later phase, so this test deliberately does NOT
assert anything about ``src/Makefile``.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/system/system_settings_runtime.c"
HEADER = ROOT / "src/system/system_settings_runtime.h"
FIXTURE = ROOT / "tests/system_settings_runtime_fixture.c"


def static_contract() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    header = HEADER.read_text(encoding="utf-8")
    # Fail-closed error codes the wiring layer keys off of.
    for token in (
        '"local_log_level_unsupported_by_logd"',
        '"fixed_interval_conflicts_with_dhcp_or_server"',
        '"zram_size_out_of_memory_bounds"',
        '"zram_algorithm_unsupported"',
        '"log_file_path_not_allowed"',
        '"invalid_timezone"',
        "ssr_atomic_write",
        "ssr_service_set_state",
    ):
        assert token in source, f"missing runtime contract: {token}"
    # Per-field result surface the wiring layer maps back to capability bits.
    for field in ("general.time_policy", "general.logging", "advanced.zram"):
        assert f'"{field}"' in source, f"missing field result: {field}"
    # Exported transaction interface.
    for symbol in (
        "ssr_time_apply",
        "ssr_time_rollback",
        "ssr_log_apply",
        "ssr_log_rollback",
        "ssr_zram_apply",
        "ssr_zram_rollback",
        "struct ssr_result",
        "struct ssr_executor",
    ):
        assert symbol in header, f"missing exported symbol: {symbol}"


def compile_fixture(output: Path) -> None:
    command = [
        os.environ.get("CC", "cc"), "-std=c11",
        "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
        "-Wall", "-Wextra", "-Werror",
        f"-I{ROOT / 'src'}",
        str(FIXTURE), str(SOURCE),
        "-o", str(output),
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)


def test_runtime() -> None:
    with tempfile.TemporaryDirectory(prefix="ssr-runtime-") as raw:
        temp = Path(raw)
        binary = temp / "fixture"
        compile_fixture(binary)
        completed = subprocess.run([str(binary), str(temp / "root")],
                                   check=True, capture_output=True,
                                   text=True)
        assert completed.stdout.strip() == "ok", completed.stdout + completed.stderr


def main() -> None:
    static_contract()
    test_runtime()
    print("ok: system settings time/logging/zram transaction runtime")


if __name__ == "__main__":
    main()

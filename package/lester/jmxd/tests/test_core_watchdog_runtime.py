#!/usr/bin/env python3
"""Compile and run watchdog stuck/recovery behavior with short thresholds."""

from pathlib import Path
import os
import shlex
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apd_test_deps  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]


def json_c_flags() -> list[str]:
    explicit = os.environ.get("CORE_WATCHDOG_TEST_FLAGS", "").strip()
    if explicit:
        return shlex.split(explicit)
    # Searching Homebrew first picked the static archive even on 31.6, where it
    # is an LTO archive from a different compiler and the link fails. The
    # shared resolver prefers a real shared library wherever it lives.
    return apd_test_deps.package_flags("json-c")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="core-watchdog-") as raw:
        binary = Path(raw) / "fixture"
        command = [
            "cc", "-std=c11", "-Wall", "-Wextra",
            "-D_DARWIN_C_SOURCE", "-D_DEFAULT_SOURCE",
            "-DJMX_CORE_UBUS_STUCK_THRESHOLD_MS=40LL",
            "-DJMX_CORE_LOOP_STALL_THRESHOLD_MS=500LL",
            f"-I{ROOT / 'tests/stubs'}", f"-I{ROOT / 'src'}",
            str(ROOT / "tests/core_watchdog_runtime_fixture.c"),
            str(ROOT / "src/jmx_core_watchdog.c"),
            "-pthread", "-o", str(binary),
            *json_c_flags(),
        ]
        subprocess.run(command, check=True, capture_output=True, text=True)
        result = subprocess.run([str(binary)], check=True, capture_output=True,
                                text=True, timeout=4)
        assert "ok: core watchdog runtime stuck/recovery fields are consistent" in result.stdout
    print("ok: core watchdog runtime stuck/recovery fields are consistent")


if __name__ == "__main__":
    main()

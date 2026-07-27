#!/usr/bin/env python3
"""Compile and run watchdog stuck/recovery behavior with short thresholds."""

from pathlib import Path
import os
import shlex
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def json_c_flags() -> list[str]:
    explicit = os.environ.get("CORE_WATCHDOG_TEST_FLAGS", "").strip()
    if explicit:
        return shlex.split(explicit)
    candidates = [Path("/opt/homebrew/opt/json-c")]
    candidates.extend(Path("/opt/homebrew/var/homebrew/tmp/.cellar/json-c").glob("*"))
    for prefix in candidates:
        header = prefix / "include/json-c/json.h"
        static = prefix / "lib/libjson-c.a"
        dynamic = prefix / "lib/libjson-c.dylib"
        if header.is_file() and static.is_file():
            return [f"-I{prefix / 'include'}", str(static)]
        if header.is_file() and dynamic.is_file():
            return [f"-I{prefix / 'include'}", f"-L{prefix / 'lib'}", "-ljson-c"]
    return shlex.split(subprocess.check_output(
        ["pkg-config", "--cflags", "--libs", "json-c"], text=True
    ))


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

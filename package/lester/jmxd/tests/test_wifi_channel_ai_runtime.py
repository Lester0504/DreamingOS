#!/usr/bin/env python3
"""Compile and run the read-only Channel AI planner fixture."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
ROOT = Path(__file__).resolve().parents[1]

import sys

sys.path.insert(0, str(ROOT / "tests"))
import apd_test_deps  # noqa: E402


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="wifi-channel-ai-") as raw:
        executable = Path(raw) / "fixture"
        flags = apd_test_deps.package_flags("json-c", "openssl")
        subprocess.run(
            [
                os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-I", str(ROOT / "src"),
                str(ROOT / "tests/wifi_channel_ai_runtime_fixture.c"),
                str(ROOT / "src/wifi/wifi_channel_ai.c"),
                *flags, "-lm", "-o", str(executable),
            ],
            check=True,
        )
        subprocess.run([str(executable)], check=True)


if __name__ == "__main__":
    main()

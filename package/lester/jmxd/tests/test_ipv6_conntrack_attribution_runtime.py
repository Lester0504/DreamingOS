#!/usr/bin/env python3
"""Compile and execute the shared IPv4/IPv6 conntrack classifier."""

import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "ipv6_conntrack_attribution_fixture.c"


def test_shared_conntrack_classifier_runtime() -> None:
    with tempfile.TemporaryDirectory(prefix="ipv6-conntrack-") as raw:
        binary = Path(raw) / "fixture"
        subprocess.run(
            [
                os.environ.get("CC", "cc"),
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I",
                str(ROOT / "src"),
                str(FIXTURE),
                "-o",
                str(binary),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        completed = subprocess.run(
            [str(binary)], check=True, capture_output=True, text=True
        )
        assert "ok: shared conntrack attribution runtime fixture" in completed.stdout


if __name__ == "__main__":
    test_shared_conntrack_classifier_runtime()
    print("ok: IPv6 conntrack attribution runtime")

#!/usr/bin/env python3
"""Compile and exercise APD's production hostapd control-socket collector."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/apd_hostapd_snapshot_fixture.c"


def main() -> None:
    compiler = os.environ.get("CC", "cc")
    assert shutil.which(compiler), f"compiler not found: {compiler}"
    with tempfile.TemporaryDirectory(prefix="apd-hostapd-build-") as temporary:
        binary = Path(temporary) / "apd-hostapd-fixture"
        subprocess.run(
            [
                compiler,
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(FIXTURE),
                "-o",
                str(binary),
            ],
            cwd=ROOT,
            check=True,
        )
        for scenario in (
            "success",
            "partial-mlo",
            "timeout",
            "malformed",
            "malformed-station",
            "oversized",
            "station-limit",
            "bss-limit",
            "no-socket",
            "no-phy",
            "unsupported",
            "missing-dir",
            "untrusted-dir",
            "untrusted-local-dir",
            "vendor-dir",
            "stale-global",
        ):
            subprocess.run([str(binary), scenario], check=True, timeout=10)
    print(
        "ok: APD hostapd STATUS/station telemetry, MLO evidence, failure reasons, "
        "secret filtering, and limits"
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Compile and run isolated kernel-module and scheduler transaction fixtures."""

from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="system-kernel-controls-") as raw:
        root = Path(raw)
        binary = root / "fixture"
        command = [
            "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
            f"-I{ROOT}",
            str(ROOT / "tests/system_kernel_controls_fixture.c"),
            str(ROOT / "system/system_kernel_controls.c"),
            "-o", str(binary),
        ]
        subprocess.run(command, check=True, capture_output=True, text=True)
        result = subprocess.run(
            [str(binary), str(root)], check=True, capture_output=True,
            text=True, timeout=5,
        )
        assert "system_kernel_controls: PASS" in result.stdout
    print("system_kernel_controls: PASS")


if __name__ == "__main__":
    main()

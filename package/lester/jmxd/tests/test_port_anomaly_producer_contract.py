#!/usr/bin/env python3
"""Compile and run the autonomous port-anomaly producer contract fixture."""

from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    cflags = subprocess.check_output(
        ["pkg-config", "--cflags", "json-c", "sqlite3", "openssl"],
        text=True,
    ).split()
    libs = subprocess.check_output(
        ["pkg-config", "--libs", "json-c", "sqlite3", "openssl"],
        text=True,
    ).split()
    with tempfile.TemporaryDirectory(prefix="port-anomaly-producer-") as raw:
        binary = Path(raw) / "fixture"
        build = subprocess.run([
            "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
            *cflags, "-I", str(ROOT / "src"),
            str(ROOT / "src" / "jmx_observability.c"),
            str(ROOT / "tests" / "port_anomaly_producer_fixture.c"),
            *libs,
            "-o", str(binary),
        ], capture_output=True, text=True)
        assert build.returncode == 0, build.stdout + build.stderr
        result = subprocess.run([str(binary)], capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "ok: port anomaly producer" in result.stdout


if __name__ == "__main__":
    main()

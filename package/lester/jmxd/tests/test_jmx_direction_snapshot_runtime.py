#!/usr/bin/env python3
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_jmx_direction_snapshot_fixture() -> None:
    with tempfile.TemporaryDirectory(prefix="jmx-direction-") as tmp:
        binary = Path(tmp) / "test_jmx_direction_snapshot_fixture"
        compiler = os.environ.get("CC", "cc")
        subprocess.run(
            [
                compiler,
                "-std=gnu11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I",
                str(ROOT / "src"),
                str(ROOT / "tests" / "test_jmx_direction_snapshot_fixture.c"),
                "-pthread",
                "-o",
                str(binary),
            ],
            check=True,
            cwd=ROOT,
        )
        result = subprocess.run(
            [str(binary)], check=True, cwd=ROOT, text=True, capture_output=True
        )
        assert result.stdout.strip() == "ok: jmx direction snapshot fixture passed"


def test_jmx_direction_snapshot_json_fixture() -> None:
    with tempfile.TemporaryDirectory(prefix="jmx-direction-json-") as tmp:
        binary = Path(tmp) / "test_jmx_direction_snapshot_json_fixture"
        compiler = os.environ.get("CC", "cc")
        json_cflags = subprocess.check_output(
            ["pkg-config", "--cflags", "--libs", "json-c"],
            text=True,
        ).split()
        subprocess.run(
            [
                compiler,
                "-std=gnu11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I",
                str(ROOT / "src"),
                str(ROOT / "tests" / "test_jmx_direction_snapshot_json_fixture.c"),
                str(ROOT / "src/routed/jmx_direction_snapshot.c"),
                *json_cflags,
                "-pthread",
                "-o",
                str(binary),
            ],
            check=True,
            cwd=ROOT,
        )
        result = subprocess.run(
            [str(binary)], check=True, cwd=ROOT, text=True, capture_output=True
        )
        assert result.stdout.strip() == "ok: jmx direction snapshot JSON fixture passed"


if __name__ == "__main__":
    test_jmx_direction_snapshot_fixture()
    test_jmx_direction_snapshot_json_fixture()
    print("ok: jmx direction snapshot fixtures build/run passed")

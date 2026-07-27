#!/usr/bin/env python3
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"


def test_v3_userspace_netlink_push_fixtures() -> None:
    with tempfile.TemporaryDirectory(prefix="jmxd-v3-push-") as tmp:
        binary = Path(tmp) / "test_v3_netlink_push_fixtures"
        command = [
            "cc",
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-unused-function",
            "-I",
            str(TESTS / "compat"),
            "-I",
            str(ROOT / "src"),
            str(TESTS / "test_v3_netlink_push_fixtures.c"),
            "-pthread",
            "-o",
            str(binary),
        ]
        subprocess.run(command, check=True, cwd=ROOT)
        completed = subprocess.run(
            [str(binary)], check=True, cwd=ROOT, text=True, capture_output=True
        )
        assert completed.stdout.strip() == "ok: v3 userspace netlink push fixtures passed"


if __name__ == "__main__":
    test_v3_userspace_netlink_push_fixtures()
    print("ok: v3 userspace netlink push fixture build/run passed")

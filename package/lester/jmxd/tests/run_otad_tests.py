#!/usr/bin/env python3
"""Run every standalone OTAD test without requiring pytest."""

from pathlib import Path
import subprocess
import sys


TEST_DIR = Path(__file__).resolve().parent


def main() -> int:
    tests = sorted(TEST_DIR.glob("test_otad*.py"))
    failures: list[Path] = []
    for test in tests:
        print(f"==> {test.name}", flush=True)
        if subprocess.run([sys.executable, str(test)]).returncode != 0:
            failures.append(test)
    print(f"OTAD tests: {len(tests) - len(failures)} passed, {len(failures)} failed")
    for test in failures:
        print(f"FAILED: {test.name}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

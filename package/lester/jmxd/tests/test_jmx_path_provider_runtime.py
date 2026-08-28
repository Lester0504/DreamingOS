#!/usr/bin/env python3
import os
import shlex
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CC = os.environ.get("CC", "cc")
OUTPUT = Path(os.environ.get(
    "JMX_PATH_PROVIDER_TEST_OUTPUT", "/tmp/jmx_path_provider_fixture"
))


def main() -> None:
    subprocess.run(
        shlex.split(CC) + [
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(ROOT / "src"),
            str(ROOT / "tests/jmx_path_provider_fixture.c"),
            str(ROOT / "src/jmx_path_provider.c"),
            "-o",
            str(OUTPUT),
        ],
        check=True,
    )
    subprocess.run([str(OUTPUT)], check=True)


if __name__ == "__main__":
    main()

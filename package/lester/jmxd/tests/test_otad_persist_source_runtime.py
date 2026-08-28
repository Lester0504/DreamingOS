#!/usr/bin/env python3
import os
import shlex
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CC = os.environ.get("CC", "cc")
OUTPUT = Path(os.environ.get(
    "OTAD_PERSIST_SOURCE_TEST_OUTPUT", "/tmp/otad_persist_source_fixture"
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
            str(ROOT / "tests/otad_persist_source_fixture.c"),
            str(ROOT / "src/otad/otad_persist_source.c"),
            str(ROOT / "src/jmx_path_provider.c"),
            "-o",
            str(OUTPUT),
        ],
        check=True,
    )
    subprocess.run([str(OUTPUT)], check=True)


if __name__ == "__main__":
    main()

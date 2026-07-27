#!/usr/bin/env python3
import os
import shlex
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CC = os.environ.get("CC", "cc")
PREFIX = os.environ.get("CLIENT_PROTOCOL_TEST_PREFIX", "")
OUTPUT = Path(os.environ.get(
    "CLIENT_PROTOCOL_HOT_TEST_OUTPUT", "/tmp/client_protocol_hot_history_fixture"
))


def prefixed(path: str) -> str:
    return str(Path(PREFIX) / path.lstrip("/")) if PREFIX else path


def main() -> None:
    cmd = shlex.split(CC) + [
        "-std=c11",
        "-D_GNU_SOURCE",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-I",
        str(ROOT / "src"),
    ]
    if PREFIX:
        cmd.extend([
            "-I",
            prefixed("/usr/include"),
            "-L",
            prefixed("/usr/lib"),
            f"-Wl,-rpath-link,{prefixed('/usr/lib')}",
        ])
    cmd.extend([
        str(ROOT / "tests/client_protocol_hot_history_fixture.c"),
        str(ROOT / "src/client_protocol_history.c"),
        "-o",
        str(OUTPUT),
        "-ljson-c",
        "-lsqlite3",
    ])
    subprocess.run(cmd, check=True)
    subprocess.run([str(OUTPUT)], check=True)


if __name__ == "__main__":
    main()

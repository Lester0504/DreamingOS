#!/usr/bin/env python3
import os
import shlex
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CC = os.environ.get("CC", "cc")
OUTPUT = Path(os.environ.get(
    "OTAD_INVENTORY_TRANSACTION_TEST_OUTPUT",
    "/tmp/otad_inventory_transaction_fixture",
))


def main() -> None:
    prefix = os.environ.get("OTAD_TRANSACTION_TEST_SQLITE_PREFIX", "")
    flags = []
    if prefix:
        flags += ["-I", str(Path(prefix) / "include"),
                  "-L", str(Path(prefix) / "lib")]
    subprocess.run(
        shlex.split(CC) + [
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(ROOT / "src"),
            str(ROOT / "tests/otad_inventory_transaction_fixture.c"),
            str(ROOT / "src/otad/otad_inventory_transaction.c"),
        ] + flags + ["-lsqlite3", "-o", str(OUTPUT)],
        check=True,
    )
    subprocess.run([str(OUTPUT)], check=True)


if __name__ == "__main__":
    main()

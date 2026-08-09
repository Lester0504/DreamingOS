#!/usr/bin/env python3
import os
import shlex
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CC = os.environ.get("CC", "cc")
PREFIX = os.environ.get("CLIENT_PROTOCOL_TEST_PREFIX", "")
JSON_C_PREFIX = os.environ.get("CLIENT_PROTOCOL_TEST_JSON_C_PREFIX", "")
SQLITE_PREFIX = os.environ.get("CLIENT_PROTOCOL_TEST_SQLITE_PREFIX", "")
OUTPUT = Path(os.environ.get(
    "CLIENT_PROTOCOL_HOT_TEST_OUTPUT", "/tmp/client_protocol_hot_history_fixture"
))


def prefixed(path: str) -> str:
    return str(Path(PREFIX) / path.lstrip("/")) if PREFIX else path


def discover_prefix(library: str) -> str:
    """Find a prefix providing <library>'s header when the host has none.

    The bare "-l<library>" default assumes the build host carries the dev
    package. On the authoritative tree (31.6) json-c exists only inside the
    OpenWrt staging_dir, so the fixture failed with
    "fatal error: json-c/json.h: No such file or directory" and these assertions
    never ran at all. Search a few well-known locations instead of hard-coding
    one machine's absolute path; an explicit
    CLIENT_PROTOCOL_TEST_<DEP>_PREFIX still wins over anything found here.
    """
    header = "json-c/json.h" if library == "json-c" else f"{library}.h"
    candidates = []
    staging = Path(__file__).resolve().parents[4] / "staging_dir"
    if staging.is_dir():
        candidates.extend(sorted(staging.glob("target-*/usr")))
    candidates.extend([
        Path("/opt/homebrew/opt") / library,
        Path("/usr/local/opt") / library,
        Path("/usr"),
    ])
    for candidate in candidates:
        if (candidate / "include" / header).is_file():
            return str(candidate)
    return ""


def dependency_flags(prefix: str, library: str) -> tuple[list[str], list[str]]:
    if not prefix:
        prefix = discover_prefix(library)
    if not prefix:
        return [], [f"-l{library}"]

    root = Path(prefix)
    archive = root / "lib" / f"lib{library}.a"
    shared = root / "lib" / f"lib{library}.so"
    if shared.is_file():
        # Prefer the shared object. An OpenWrt staging_dir .a is an LTO archive
        # built by the cross toolchain, and linking it with the host cc fails
        # with "bytecode stream ... generated with LTO version 16.0 instead of
        # the expected 15.1". The .so carries no bytecode, so it links cleanly.
        link = ["-L", str(root / "lib"), f"-Wl,-rpath,{root / 'lib'}", f"-l{library}"]
    elif archive.is_file():
        link = [str(archive)]
    else:
        link = ["-L", str(root / "lib"), f"-l{library}"]
    return ["-I", str(root / "include")], link


def main() -> None:
    json_c_compile, json_c_link = dependency_flags(JSON_C_PREFIX, "json-c")
    sqlite_compile, sqlite_link = dependency_flags(SQLITE_PREFIX, "sqlite3")
    cmd = shlex.split(CC) + [
        "-std=c11",
        "-D_GNU_SOURCE",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-I",
        str(ROOT / "src"),
    ] + json_c_compile + sqlite_compile
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
    ] + json_c_link + sqlite_link)
    subprocess.run(cmd, check=True)
    subprocess.run([str(OUTPUT)], check=True)


if __name__ == "__main__":
    main()

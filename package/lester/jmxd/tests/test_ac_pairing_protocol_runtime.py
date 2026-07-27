#!/usr/bin/env python3
"""Compile and inspect real AC Phase 1C public JSON serializers."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
SOURCE = ROOT / "src/ac/ac_protocol.c"
JSON_C = Path("/opt/homebrew/var/homebrew/tmp/.cellar/json-c/0.19")
OPENSSL = Path("/opt/homebrew/opt/openssl@3")


def dependency_flags() -> tuple[list[str], list[str], str]:
    configured = os.environ.get("AC_PAIRING_TEST_PREFIX", "")
    if configured:
        prefix = Path(configured)
        for header in ("include/json-c/json.h", "include/openssl/evp.h"):
            assert (prefix / header).is_file(), f"dependency missing: {prefix / header}"
        return ([f"-I{prefix / 'include'}"],
                [f"-L{prefix / 'lib'}", f"-Wl,-rpath,{prefix / 'lib'}"],
                str(prefix / "lib"))
    return ([f"-I{JSON_C / 'include'}", f"-I{OPENSSL / 'include'}"],
            [f"-L{JSON_C / 'lib'}", f"-L{OPENSSL / 'lib'}"],
            f"{JSON_C / 'lib'}:{OPENSSL / 'lib'}")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="ac-pairing-protocol-") as raw:
        binary = Path(raw) / "fixture"
        include_flags, library_flags, library_path = dependency_flags()
        command = [
            os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-include", str(TESTS / "ac_pairing_protocol_fixture.h"),
            f"-I{TESTS}", *include_flags,
            str(TESTS / "ac_pairing_protocol_fixture.c"), str(SOURCE),
            *library_flags, "-ljson-c", "-lcrypto",
            "-o", str(binary),
        ]
        subprocess.run(command, check=True, capture_output=True, text=True)
        env = os.environ.copy()
        env["DYLD_LIBRARY_PATH"] = library_path
        env["LD_LIBRARY_PATH"] = library_path + (
            f":{env['LD_LIBRARY_PATH']}" if env.get("LD_LIBRARY_PATH") else "")
        output = subprocess.run([str(binary)], env=env, check=True,
                                capture_output=True, text=True).stdout
    objects = [json.loads(line) for line in output.splitlines()]
    assert len(objects) == 4
    assert objects[0]["display_once"] is True
    assert objects[0]["token"] == "secret-sentinel-01234567890123456789012345"
    for public in objects[1:]:
        serialized = json.dumps(public).lower()
        for forbidden in ("secret-sentinel", "token_hash", "hardware_digest", "feedface"):
            assert forbidden not in serialized
        assert public.get("mtls_ready", False) is False
        assert public.get("adopted", False) is False
    print("ok: AC pairing create shows the token once and public readback exposes no secret")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Real hostapd action sockets, measurement decoding and truthful job receipts."""

from pathlib import Path
import os
import subprocess
import tempfile

import apd_test_deps

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    json_prefix, _ = apd_test_deps.resolve_json_prefix()
    openssl_prefix, _ = apd_test_deps.resolve_openssl_prefix()
    with tempfile.TemporaryDirectory(prefix="apd-roaming-build-") as raw:
        binary = Path(raw) / "fixture"
        fixture = os.environ.get("APD_ROAMING_FIXTURE", "apd_roaming_actions_fixture.c")
        command = [
            os.environ.get("CC", "cc"), "-std=c11", "-D_GNU_SOURCE",
            "-Wall", "-Wextra", "-Werror", f"-I{ROOT / 'src'}",
            f"-I{json_prefix / 'include'}", f"-I{openssl_prefix / 'include'}",
            str(ROOT / "tests" / fixture),
            str(ROOT / "src/apd/apd_config_executor.c"),
            str(ROOT / "src/apd/apd_readonly_command.c"),
            f"-L{json_prefix / 'lib'}", f"-Wl,-rpath,{json_prefix / 'lib'}",
            "-ljson-c", f"-L{openssl_prefix / 'lib'}", "-lcrypto", "-lpthread",
            "-o", str(binary),
        ]
        if fixture == "apd_reassoc_block_fixture.c":
            command.append("-Wno-unused-function")
        built = subprocess.run(command, capture_output=True, text=True)
        assert built.returncode == 0, built.stderr
        result = subprocess.run([str(binary)], capture_output=True, text=True,
                                timeout=30)
        assert result.returncode == 0, result.stderr
        if fixture == "apd_reassoc_block_fixture.c":
            print(result.stdout.strip())
            return
    print("ok: APD roaming sockets, active/passive/table negotiation, cached "
          "report labels, no timeout retry, TTL, BTM, digest and failure handling")


if __name__ == "__main__":
    main()

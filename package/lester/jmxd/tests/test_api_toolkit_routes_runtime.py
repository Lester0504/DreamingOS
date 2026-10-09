#!/usr/bin/env python3
"""Execute the 35 Phase 3A production handlers against controlled producers."""

from pathlib import Path
import os
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import apd_test_deps  # noqa: E402

SRC = ROOT / "src"
API = SRC / "webd" / "api"
FIXTURE = ROOT / "tests" / "api_toolkit_routes_fixture.c"
HEADER_FLAGS, JSON_LIBS = apd_test_deps.split_package_flags("json-c")


def test_production_handlers_preserve_route_behavior() -> None:
    with tempfile.TemporaryDirectory(prefix="api-toolkit-routes-") as raw:
        work = Path(raw)
        fake = work / "dreamingwrt-toolkit-fixture"
        fake.write_text(
            "#!/bin/sh\n"
            "payload=$(cat)\n"
            "printf '{\"ok\":true,\"command\":\"%s\",\"payload\":%s}\\n' \"$1\" \"$payload\"\n",
            encoding="ascii",
        )
        fake.chmod(0o755)
        binary = work / "api-toolkit-routes-fixture"
        command = [
            "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
            f'-DWEBD_TOOLKIT_BINARY="{fake}"',
            f"-I{SRC}", f"-I{SRC / 'webd'}", f"-I{API}",
            *HEADER_FLAGS,
            str(API / "api_toolkit.c"),
            str(API / "api_request.c"),
            str(FIXTURE),
            *JSON_LIBS,
            "-o", str(binary),
        ]
        built = subprocess.run(command, capture_output=True, text=True)
        assert built.returncode == 0, built.stdout + built.stderr
        result = subprocess.run([str(binary)], capture_output=True, text=True,
                                timeout=60, env={**os.environ})
        assert result.returncode == 0, result.stdout + result.stderr
        assert "ok: 36 production Toolkit/Diagnostics handlers" in result.stdout


if __name__ == "__main__":
    test_production_handlers_preserve_route_behavior()
    print("ok: Phase 3A production route handlers executed")

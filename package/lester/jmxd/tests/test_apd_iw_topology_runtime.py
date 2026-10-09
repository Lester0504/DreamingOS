#!/usr/bin/env python3
"""Compile and run the standalone iw topology parser fixture."""

from pathlib import Path
import os
import shutil
import subprocess
import tempfile

import apd_test_deps

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    compiler = os.environ.get("CC") or shutil.which("clang") or shutil.which("cc")
    assert compiler, "C compiler is required"
    prefix, shared = apd_test_deps.resolve_json_prefix()
    with tempfile.TemporaryDirectory(prefix="apd-iw-topology-") as raw:
        binary = Path(raw) / "fixture"
        command = [
            compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-D_POSIX_C_SOURCE=200809L", f"-I{ROOT / 'src'}",
            f"-I{prefix / 'include'}",
            str(ROOT / "tests/apd_iw_topology_runtime_fixture.c"),
            str(ROOT / "src/apd/apd_iw_topology.c"),
        ]
        command += ([f"-L{prefix / 'lib'}", f"-Wl,-rpath,{prefix / 'lib'}", "-ljson-c"]
                    if shared else [str(prefix / "lib/libjson-c.a")])
        command += ["-o", str(binary)]
        compiled = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        assert compiled.returncode == 0, compiled.stderr
        env = os.environ.copy()
        if shared:
            env["LD_LIBRARY_PATH"] = str(prefix / "lib") + (
                f":{env['LD_LIBRARY_PATH']}" if env.get("LD_LIBRARY_PATH") else "")
        result = subprocess.run([str(binary)], cwd=ROOT, capture_output=True,
                                text=True, timeout=10, env=env)
        assert result.returncode == 0, result.stdout + result.stderr
        assert result.stdout.strip().startswith("ok: APD iw topology")
    print("ok: APD iw topology fixture compiled with -Werror and passed")


if __name__ == "__main__":
    main()

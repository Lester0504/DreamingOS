#!/usr/bin/env python3
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apd_test_deps  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    compiler = os.environ.get("CC") or shutil.which("cc") or shutil.which("clang")
    assert compiler, "host C compiler unavailable"
    configured = os.environ.get("STORAGE_TEST_JSON_C_ROOT", "")
    if configured:
        prefix = Path(configured)
        assert (prefix / "include/json-c/json.h").is_file()
        flags = ["-I", str(prefix / "include"), "-L", str(prefix / "lib"),
                 "-ljson-c", f"-Wl,-rpath,{prefix / 'lib'}"]
    else:
        # pkg-config knows nothing about json-c on 31.6, so resolve the prefix
        # instead of failing the whole fixture on a missing .pc file.
        flags = apd_test_deps.package_flags("json-c")
    with tempfile.TemporaryDirectory(prefix="vpn-transaction-") as raw:
        binary = Path(raw) / "vpn-transaction"
        subprocess.run([
            compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-I", str(ROOT / "src"),
            str(ROOT / "src/webd/webd_vpn_aggregate.c"),
            str(ROOT / "tests/test_vpn_transaction_runtime.c"),
            *flags, "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()

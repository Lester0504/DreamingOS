#!/usr/bin/env python3
"""Cross-check APD enrollment output with the production AC verifier."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
OPENSSL = Path("/opt/homebrew/opt/openssl@3")


def flags() -> list[str]:
    prefix = os.environ.get("AC_PAIRING_TEST_PREFIX")
    if prefix:
        root = Path(prefix)
        return [f"-I{root / 'include'}", f"-L{root / 'lib'}",
                f"-Wl,-rpath,{root / 'lib'}"]
    return [f"-I{OPENSSL / 'include'}", f"-L{OPENSSL / 'lib'}"]


def compile_fixtures(root: Path) -> tuple[Path, Path]:
    cc = os.environ.get("CC", "cc")
    platform = "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE"
    common = [cc, "-std=c11", platform, "-Wall", "-Wextra", "-Werror", *flags()]
    apd = root / "apd-producer"
    ac = root / "ac-consumer"
    subprocess.run([
        *common, "-DAPD_DB_TEST_STANDALONE",
        "-DAPD_ENROLLMENT_TEST_STANDALONE",
        str(ROOT / "tests/apd_enrollment_identity_fixture.c"),
        str(ROOT / "src/apd/apd_db.c"),
        str(ROOT / "src/apd/apd_enrollment.c"),
        "-lcrypto", "-lsqlite3", "-o", str(apd),
    ], check=True, capture_output=True, text=True)
    subprocess.run([
        *common, "-DAC_ENROLLMENT_FIXTURE_TYPES",
        f"-include{ROOT / 'tests/ac_enrollment_fixture.h'}",
        str(ROOT / "tests/ac_apd_enrollment_cross_fixture.c"),
        str(ROOT / "src/ac/ac_enrollment.c"),
        "-lcrypto", "-o", str(ac),
    ], check=True, capture_output=True, text=True)
    return apd, ac


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="ac-apd-cross-") as raw:
        root = Path(raw)
        root.chmod(0o700)
        apd, ac = compile_fixtures(root)
        database = root / "apd.db"
        key = root / "pki/identity.ed25519"
        transcript = root / "transcript.bin"
        signature = root / "signature.bin"
        csr = root / "request.der"
        env = os.environ.copy()
        env["DREAMINGWRT_APD_DB_PATH"] = str(database)
        env["DREAMINGWRT_APD_IDENTITY_KEY_PATH"] = str(key)
        prefix = env.get("AC_PAIRING_TEST_PREFIX")
        if prefix:
            env["LD_LIBRARY_PATH"] = str(Path(prefix) / "lib")
        subprocess.run([str(apd), "enrollment", str(transcript),
                        str(signature), str(csr)], env=env, check=True,
                       capture_output=True, text=True)
        result = subprocess.run([str(ac), str(transcript), str(signature),
                                 str(csr)], env=env, check=True,
                                capture_output=True, text=True)
        assert result.stdout.strip() == (
            "ok: AC accepted APD transcript, CSR, public key, and signature")
    print("ok: APD enrollment wire output is byte-compatible with AC verification")


if __name__ == "__main__":
    main()

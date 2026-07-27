#!/usr/bin/env python3
"""Real SQLite/OpenSSL tests for AC Phase 1E enrollment transactions."""

from __future__ import annotations

import concurrent.futures
import glob
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "src/ac/ac_db.c"
ENROLLMENT = ROOT / "src/ac/ac_enrollment.c"
FIXTURE = ROOT / "tests/ac_enrollment_runtime_fixture.c"
HEADER = ROOT / "tests/ac_enrollment_fixture.h"
OPENSSL = Path("/opt/homebrew/opt/openssl@3")


def json_flags(prefix: Path | None) -> list[str]:
    if prefix:
        assert (prefix / "include/json-c/json.h").is_file()
        return ["-ljson-c"]
    candidates = [Path("/opt/homebrew/opt/json-c")]
    candidates.extend(Path(value) for value in glob.glob(
        "/opt/homebrew/var/homebrew/tmp/.cellar/json-c/*"
    ))
    json_prefix = next((value for value in candidates
                        if (value / "include/json-c/json.h").is_file() and
                           (value / "lib/libjson-c.a").is_file()), None)
    assert json_prefix, "json-c headers and static library are required"
    return [f"-I{json_prefix / 'include'}",
            str(json_prefix / "lib/libjson-c.a")]


def compile_fixture(output: Path) -> None:
    prefix_value = os.environ.get("AC_PAIRING_TEST_PREFIX")
    prefix = Path(prefix_value) if prefix_value else None
    flags = ([f"-I{prefix / 'include'}", f"-L{prefix / 'lib'}",
              f"-Wl,-rpath,{prefix / 'lib'}"] if prefix else
             [f"-I{OPENSSL / 'include'}", f"-L{OPENSSL / 'lib'}"])
    command = [
        os.environ.get("CC", "cc"), "-std=c11",
        "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
        "-DAC_DB_TEST_STANDALONE", "-DAC_ENROLLMENT_FIXTURE_TYPES",
        f"-include{HEADER}",
        "-Wall", "-Wextra", "-Werror", *flags,
        str(FIXTURE), str(DB), str(ENROLLMENT), "-lcrypto", "-lsqlite3",
        *json_flags(prefix), "-lm", "-o", str(output),
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)


def run(binary: Path, db: Path, *args: str, check: bool = True):
    env = os.environ.copy()
    env["DREAMINGWRT_AC_DB_PATH"] = str(db)
    prefix = env.get("AC_PAIRING_TEST_PREFIX")
    if prefix:
        env["LD_LIBRARY_PATH"] = str(Path(prefix) / "lib")
    return subprocess.run([str(binary), *args], env=env, check=check,
                          text=True, capture_output=True)


def field(output: str, name: str) -> str:
    for item in output.split():
        if item.startswith(name + "="):
            return item.split("=", 1)[1]
    raise AssertionError((name, output))


def rows(db: Path):
    with sqlite3.connect(db) as connection:
        token = connection.execute(
            "SELECT claimed_enrollment_id,claimed_at,consumed_at,consumed_enrollment_id,attempts "
            "FROM ac_pairing_tokens").fetchone()
        enrollment = connection.execute(
            "SELECT state,certificate_id,adopted_at FROM ac_enrollments").fetchone()
        ap = connection.execute("SELECT adoption_state FROM ac_aps").fetchone()
        cert = connection.execute(
            "SELECT state,length(certificate_der),length(fingerprint_sha256),activated_at "
            "FROM ac_device_certificates").fetchone()
    return token, enrollment, ap, cert


def test_invalid_proofs_do_not_claim(binary: Path, root: Path) -> None:
    for mode in ("claim-bad-signature", "claim-bad-csr", "claim-bad-nonce"):
        directory = root / mode
        directory.mkdir(mode=0o700)
        db, bundle = directory / "config.db", directory / "bundle.bin"
        run(binary, db, "prepare", str(bundle))
        result = run(binary, db, mode, str(bundle))
        assert field(result.stdout, "result") == "1", result.stdout
        with sqlite3.connect(db) as connection:
            assert connection.execute("SELECT COUNT(*) FROM ac_enrollments").fetchone()[0] == 0
            token = connection.execute(
                "SELECT claimed_enrollment_id,consumed_at,attempts FROM ac_pairing_tokens"
            ).fetchone()
            challenge = connection.execute(
                "SELECT consumed_at FROM ac_enrollment_challenges").fetchone()[0]
        assert token == ("", 0, 0)
        assert challenge == 0


def test_concurrent_claim_and_lifecycle(binary: Path, root: Path) -> None:
    directory = root / "lifecycle"
    directory.mkdir(mode=0o700)
    db, bundle = directory / "config.db", directory / "bundle.bin"
    run(binary, db, "prepare", str(bundle))

    def claim(_: int) -> str:
        return field(run(binary, db, "claim", str(bundle)).stdout, "result")

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(claim, range(24)))
    assert results.count("0") == 1, results
    assert results.count("6") == 23, results
    token, enrollment, ap, cert = rows(db)
    assert token[0] and token[1] > 0 and token[2:] == (0, "", 0)
    assert enrollment[0] == "claimed" and enrollment[1:] == ("", 0)
    assert ap == ("pending_pairing",) and cert is None

    certificate = run(binary, db, "certificate", str(bundle))
    assert field(certificate.stdout, "result") == "0"
    retry = run(binary, db, "certificate", str(bundle))
    assert field(retry.stdout, "result") == "6"
    token, enrollment, ap, cert = rows(db)
    assert token[2] > 0 and token[3] == token[0]
    assert enrollment[0] == "mtls_pending"
    assert cert[0:3] == ("pending_activation", 256, 32)
    assert ap == ("pending_pairing",)
    readback = run(binary, db, "certificate-readback", str(bundle))
    assert field(readback.stdout, "same") == "1"
    assert field(readback.stdout, "pending") == "1"
    assert field(readback.stdout, "active") == "0"

    recovered = run(binary, db, "recover-claim", str(bundle))
    assert field(recovered.stdout, "result") == "6", recovered.stdout
    assert field(recovered.stdout, "requested_enrollment_id") != token[0]
    assert field(recovered.stdout, "recovered_enrollment_id") == token[0]
    with sqlite3.connect(db) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM ac_enrollments").fetchone()[0] == 1

    run(binary, db, "activation-begin", str(bundle))
    wrong_cert = run(binary, db, "activate-wrong-certificate", str(bundle))
    assert field(wrong_cert.stdout, "result") == "1"
    wrong = run(binary, db, "activate-wrong", str(bundle))
    assert field(wrong.stdout, "result") == "1"
    token, enrollment, ap, cert = rows(db)
    assert enrollment[0] == "mtls_pending" and cert[0] == "pending_activation"
    assert ap == ("pending_pairing",)

    adopted = run(binary, db, "activate", str(bundle))
    assert field(adopted.stdout, "result") == "0"
    token, enrollment, ap, cert = rows(db)
    assert enrollment[0] == "adopted" and enrollment[2] > 0
    assert cert[0] == "active" and cert[3] > 0
    assert ap == ("adopted",)
    readback = run(binary, db, "certificate-readback", str(bundle))
    assert field(readback.stdout, "same") == "1"
    assert field(readback.stdout, "pending") == "0"
    assert field(readback.stdout, "active") == "1"


def test_transaction_commit_failures(binary: Path, root: Path) -> None:
    claim_dir = root / "claim-failure"
    claim_dir.mkdir(mode=0o700)
    db, bundle = claim_dir / "config.db", claim_dir / "bundle.bin"
    run(binary, db, "prepare", str(bundle))
    failed = run(binary, db, "claim-commit-failure", str(bundle), check=False)
    assert failed.returncode != 0
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT COUNT(*) FROM ac_enrollments").fetchone()[0] == 0
        assert connection.execute(
            "SELECT claimed_enrollment_id,consumed_at FROM ac_pairing_tokens"
        ).fetchone() == ("", 0)
        assert connection.execute(
            "SELECT consumed_at FROM ac_enrollment_challenges").fetchone()[0] == 0
    assert field(run(binary, db, "claim", str(bundle)).stdout, "result") == "0"

    cert_dir = root / "certificate-failure"
    cert_dir.mkdir(mode=0o700)
    db, bundle = cert_dir / "config.db", cert_dir / "bundle.bin"
    run(binary, db, "prepare", str(bundle))
    run(binary, db, "claim", str(bundle))
    failed = run(binary, db, "certificate-commit-failure", str(bundle), check=False)
    assert failed.returncode != 0
    token, enrollment, ap, cert = rows(db)
    assert token[2] == 0 and token[3] == ""
    assert enrollment[0] == "claimed" and cert is None
    assert field(run(binary, db, "certificate", str(bundle)).stdout, "result") == "0"


def test_startup_rejects_partial_adoption(binary: Path, root: Path) -> None:
    directory = root / "tampered-adoption"
    directory.mkdir(mode=0o700)
    db, bundle = directory / "config.db", directory / "bundle.bin"
    run(binary, db, "prepare", str(bundle))
    run(binary, db, "claim", str(bundle))
    with sqlite3.connect(db) as connection:
        connection.execute("UPDATE ac_aps SET adoption_state='adopted'")
    result = run(binary, db, "claim", str(bundle), check=False)
    assert result.returncode == 2
    assert "controller database validation failed" in result.stderr


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="ac-enrollment-") as raw:
        root = Path(raw)
        root.chmod(0o700)
        binary = root / "ac-enrollment-fixture"
        compile_fixture(binary)
        test_invalid_proofs_do_not_claim(binary, root)
        test_concurrent_claim_and_lifecycle(binary, root)
        test_transaction_commit_failures(binary, root)
        test_startup_rejects_partial_adoption(binary, root)
    print("ok: AC enrollment proof, claim, certificate, and mTLS activation are atomic")


if __name__ == "__main__":
    main()

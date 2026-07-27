#!/usr/bin/env python3
"""Runtime security tests for APD Phase 1B identity persistence."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import time


def key_path(db: Path) -> Path:
    return db.parent / "apd-pki" / "identity.ed25519"


def run(binary: Path, db: Path, command: str = "identity", check: bool = True):
    env = os.environ.copy()
    env["DREAMINGWRT_APD_DB_PATH"] = str(db)
    env["DREAMINGWRT_APD_IDENTITY_KEY_PATH"] = str(key_path(db))
    return subprocess.run(
        [str(binary), command], env=env, text=True, capture_output=True, check=check
    )


def parse(text: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


def assert_identity(db: Path, output: str) -> tuple[str, str, bytes]:
    values = parse(output)
    assert re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", values["ap_id"])
    assert values["algorithm"] == "Ed25519"
    assert re.fullmatch(r"[0-9a-f]{64}", values["public_key"])
    assert values["key_id"] == "sha256:" + hashlib.sha256(bytes.fromhex(values["public_key"])).hexdigest()
    assert values["key_exportable"] == "false"
    with sqlite3.connect(db) as conn:
        row = conn.execute(
            "SELECT ap_id,public_key,key_id,algorithm FROM apd_node_identity_v3"
        ).fetchone()
    assert row is not None and len(row[1]) == 32
    assert row[0] == values["ap_id"] and row[1].hex() == values["public_key"]
    assert row[2] == values["key_id"] and row[3] == "Ed25519"
    private_key = key_path(db).read_bytes()
    assert len(private_key) == 32 and private_key not in db.read_bytes()
    private_hex = private_key.hex()
    assert private_hex not in output.lower()
    return values["ap_id"], values["public_key"], private_key


def test_concurrent_initialization(binary: Path, root: Path) -> Path:
    db = root / "concurrent" / "apd.db"
    db.parent.mkdir(mode=0o700)
    env = os.environ.copy()
    env["DREAMINGWRT_APD_DB_PATH"] = str(db)
    env["DREAMINGWRT_APD_IDENTITY_KEY_PATH"] = str(key_path(db))
    processes = [
        subprocess.Popen([str(binary), "identity"], env=env, text=True,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for _ in range(12)
    ]
    outputs = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=15)
        assert process.returncode == 0, stderr
        outputs.append(stdout)
    identities = {(parse(value)["ap_id"], parse(value)["public_key"]) for value in outputs}
    assert len(identities) == 1
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM apd_node_identity_v3").fetchone()[0] == 1
        assert conn.execute("SELECT version FROM apd_schema_meta").fetchone()[0] == 3
    assert (db.stat().st_mode & 0o777) == 0o600
    assert ((db.parent / "apd.db.init.lock").stat().st_mode & 0o777) == 0o600
    assert (key_path(db).stat().st_mode & 0o777) == 0o600
    assert (key_path(db).parent.stat().st_mode & 0o777) == 0o700
    return db


def test_pairing_state_machine(binary: Path, db: Path, private_key: bytes) -> None:
    assert parse(run(binary, db, "pairing-status").stdout)["state"] == "unpaired"
    run(binary, db, "pairing-begin")
    pending = parse(run(binary, db, "pairing-status").stdout)
    assert pending["state"] == "pending" and pending["mtls_ready"] == "false"
    run(binary, db, "pairing-challenge")
    challenged = parse(run(binary, db, "pairing-status").stdout)
    assert challenged["state"] == "challenge_pending"
    assert challenged["challenge_present"] == "true"
    with sqlite3.connect(db) as conn:
        challenge_hash = conn.execute("SELECT challenge_hash FROM apd_pairing_state").fetchone()[0]
    assert len(challenge_hash) == 32
    run(binary, db, "pairing-wrong")
    assert parse(run(binary, db, "pairing-status").stdout)["attempts"] == "1"
    run(binary, db, "pairing-verify")
    verified_output = run(binary, db, "pairing-status").stdout
    verified = parse(verified_output)
    assert verified["state"] == "challenge_verified"
    assert verified["challenge_present"] == "false"
    assert verified["mtls_ready"] == "false" and verified["adopted"] == "false"
    assert private_key.hex() not in verified_output.lower()
    run(binary, db, "pairing-reset")
    assert parse(run(binary, db, "pairing-status").stdout)["state"] == "unpaired"

    run(binary, db, "pairing-begin")
    run(binary, db, "pairing-challenge")
    for _ in range(5):
        run(binary, db, "pairing-wrong")
    failed = parse(run(binary, db, "pairing-status").stdout)
    assert failed["state"] == "failed" and failed["challenge_present"] == "false"
    run(binary, db, "pairing-reset")

    run(binary, db, "pairing-begin-short")
    run(binary, db, "pairing-challenge")
    time.sleep(3)
    expired = parse(run(binary, db, "pairing-status").stdout)
    assert expired["state"] == "expired" and expired["challenge_present"] == "false"
    run(binary, db, "pairing-reset")
    for sidecar in db.parent.glob(f"{db.name}-*"):
        assert sidecar.is_file() and not sidecar.is_symlink()
        assert (sidecar.stat().st_mode & 0o777) == 0o600


def expect_init_failure(binary: Path, db: Path) -> None:
    result = run(binary, db, check=False)
    assert result.returncode != 0


def test_fail_closed_boundaries(binary: Path, root: Path, source_db: Path) -> None:
    broad_parent = root / "broad-parent"
    broad_parent.mkdir(mode=0o777)
    os.chmod(broad_parent, 0o777)
    expect_init_failure(binary, broad_parent / "apd.db")

    broad_db_dir = root / "broad-db"
    broad_db_dir.mkdir(mode=0o700)
    broad_db = broad_db_dir / "apd.db"
    broad_db.write_bytes(source_db.read_bytes())
    os.chmod(broad_db, 0o644)
    expect_init_failure(binary, broad_db)

    symlink_dir = root / "symlink"
    symlink_dir.mkdir(mode=0o700)
    symlink_db = symlink_dir / "apd.db"
    symlink_db.symlink_to(source_db)
    expect_init_failure(binary, symlink_db)

    hardlink_dir = root / "hardlink"
    hardlink_dir.mkdir(mode=0o700)
    hardlink_db = hardlink_dir / "apd.db"
    os.link(source_db, hardlink_db)
    expect_init_failure(binary, hardlink_db)

    lock_symlink_dir = root / "lock-symlink"
    lock_symlink_dir.mkdir(mode=0o700)
    lock_symlink_db = lock_symlink_dir / "apd.db"
    (lock_symlink_dir / "apd.db.init.lock").symlink_to(source_db)
    expect_init_failure(binary, lock_symlink_db)

    corrupt_dir = root / "corrupt"
    corrupt_dir.mkdir(mode=0o700)
    corrupt_db = corrupt_dir / "apd.db"
    corrupt_db.write_bytes(b"not a sqlite database")
    os.chmod(corrupt_db, 0o600)
    expect_init_failure(binary, corrupt_db)

    tamper_dir = root / "tamper"
    tamper_dir.mkdir(mode=0o700)
    tamper_db = tamper_dir / "apd.db"
    tamper_db.write_bytes(source_db.read_bytes())
    os.chmod(tamper_db, 0o600)
    with sqlite3.connect(tamper_db) as conn:
        conn.execute("UPDATE apd_node_identity_v3 SET public_key=zeroblob(32)")
    tamper_key = key_path(tamper_db)
    tamper_key.parent.mkdir(mode=0o700)
    tamper_key.write_bytes(key_path(source_db).read_bytes())
    os.chmod(tamper_key, 0o600)
    expect_init_failure(binary, tamper_db)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    with tempfile.TemporaryDirectory(prefix="apd-phase1b-") as temporary:
        root = Path(temporary)
        os.chmod(root, 0o700)
        db = test_concurrent_initialization(binary, root)
        first = run(binary, db).stdout
        ap_id, public_key, private_key = assert_identity(db, first)
        second = run(binary, db).stdout
        assert (ap_id, public_key) == (parse(second)["ap_id"], parse(second)["public_key"])
        test_pairing_state_machine(binary, db, private_key)
        test_fail_closed_boundaries(binary, root, db)
    print("ok: APD identity stable, atomic, secret-safe, and fail-closed")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Standalone APD schema-v3 identity, CSR, and binary-v1 enrollment tests."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import sqlite3
import struct
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
DB_SOURCE = ROOT / "src/apd/apd_db.c"
ENROLLMENT_SOURCE = ROOT / "src/apd/apd_enrollment.c"
FIXTURE = ROOT / "tests/apd_enrollment_identity_fixture.c"
OPENSSL = Path("/opt/homebrew/opt/openssl@3")
DOMAIN = b"dreamingwrt-ap-enrollment-v1"


def target_prefix() -> Path | None:
    configured = os.environ.get("APD_ENROLLMENT_TEST_PREFIX", "")
    if not configured:
        return None
    prefix = Path(configured)
    assert (prefix / "include/openssl/evp.h").is_file()
    assert (prefix / "include/sqlite3.h").is_file()
    return prefix


def compile_fixture(output: Path) -> None:
    prefix = target_prefix()
    flags = (
        [f"-I{prefix / 'include'}", f"-L{prefix / 'lib'}",
         f"-Wl,-rpath,{prefix / 'lib'}"]
        if prefix else [f"-I{OPENSSL / 'include'}", f"-L{OPENSSL / 'lib'}"]
    )
    command = [
        os.environ.get("CC", "cc"), "-std=c11",
        "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
        "-DAPD_DB_TEST_STANDALONE", "-DAPD_ENROLLMENT_TEST_STANDALONE",
        "-Wall", "-Wextra", "-Werror", *flags,
        str(FIXTURE), str(DB_SOURCE), str(ENROLLMENT_SOURCE),
        "-lcrypto", "-lsqlite3", "-o", str(output),
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)


def run(binary: Path, db: Path, key: Path, *args: str,
        check: bool = True,
        extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["DREAMINGWRT_APD_DB_PATH"] = str(db)
    env["DREAMINGWRT_APD_IDENTITY_KEY_PATH"] = str(key)
    if extra_env:
        env.update(extra_env)
    prefix = target_prefix()
    if prefix:
        env["LD_LIBRARY_PATH"] = str(prefix / "lib")
    return subprocess.run([str(binary), *args], env=env, check=check,
                          capture_output=True, text=True)


def fields(output: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def identity_schema(db: Path) -> tuple[dict[str, str], tuple[object, ...]]:
    with sqlite3.connect(db) as connection:
        tables = {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert "apd_node_identity_v3" in tables
        assert "apd_node_identity_v2" not in tables
        columns = [row[1] for row in connection.execute(
            "PRAGMA table_info(apd_node_identity_v3)")]
        assert columns == ["singleton", "ap_id", "public_key", "key_id",
                           "algorithm", "created_at"]
        row = connection.execute(
            "SELECT ap_id,public_key,key_id,algorithm,created_at "
            "FROM apd_node_identity_v3").fetchone()
        version = connection.execute(
            "SELECT version FROM apd_schema_meta WHERE singleton=1").fetchone()[0]
    assert version == 3 and row is not None
    return {"tables": ",".join(sorted(tables))}, row


def assert_key_file(key: Path) -> bytes:
    stat = key.stat()
    assert not key.is_symlink()
    assert stat.st_mode & 0o777 == 0o600
    assert stat.st_nlink == 1 and stat.st_uid == os.geteuid()
    private_key = key.read_bytes()
    assert len(private_key) == 32
    assert key.parent.stat().st_mode & 0o777 == 0o700
    return private_key


def fresh_init(binary: Path, root: Path) -> tuple[Path, Path, dict[str, str], bytes]:
    db = root / "fresh" / "apd.db"
    key = root / "fresh" / "pki" / "identity.ed25519"
    db.parent.mkdir(mode=0o700)
    values = fields(run(binary, db, key, "identity").stdout)
    _, row = identity_schema(db)
    private_key = assert_key_file(key)
    assert row[0] == values["ap_id"]
    assert row[1].hex() == values["public_key"]
    assert row[2] == values["key_id"]
    assert row[3] == "Ed25519"
    assert values["key_id"] == "sha256:" + hashlib.sha256(row[1]).hexdigest()
    assert private_key not in db.read_bytes()
    assert private_key.hex() not in run(binary, db, key, "identity").stdout.lower()
    return db, key, values, private_key


def v2_migration(binary: Path, root: Path) -> None:
    db = root / "migration" / "apd.db"
    key = root / "migration" / "pki" / "identity.ed25519"
    db.parent.mkdir(mode=0o700)
    run(binary, db, key, "seed-v2")
    with sqlite3.connect(db) as connection:
        old = connection.execute(
            "SELECT ap_id,private_key,public_key,key_id,created_at "
            "FROM apd_node_identity_v2").fetchone()
    output = fields(run(binary, db, key, "identity").stdout)
    _, migrated = identity_schema(db)
    assert old is not None
    assert output["ap_id"] == old[0] == migrated[0]
    assert bytes.fromhex(output["public_key"]) == old[2] == migrated[1]
    assert output["key_id"] == old[3] == migrated[2]
    assert int(output["created_at"]) == old[4] == migrated[4]
    assert assert_key_file(key) == old[1]
    assert old[1] not in db.read_bytes()


def crash_recovery(binary: Path, root: Path) -> None:
    fresh = root / "fresh-crash-recovery"
    fresh.mkdir(mode=0o700)
    fresh_db = fresh / "apd.db"
    fresh_key = fresh / "pki" / "identity.ed25519"
    failed = run(binary, fresh_db, fresh_key, "identity", check=False,
                 extra_env={"APD_DB_TEST_FAIL_COMMIT_ONCE": "1"})
    assert failed.returncode != 0
    stranded_private = assert_key_file(fresh_key)
    with sqlite3.connect(fresh_db) as connection:
        tables = {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert "apd_node_identity_v3" not in tables
    recovered = fields(run(binary, fresh_db, fresh_key, "identity").stdout)
    _, row = identity_schema(fresh_db)
    assert assert_key_file(fresh_key) == stranded_private
    assert row[0] == recovered["ap_id"]
    assert row[1].hex() == recovered["public_key"]

    migration = root / "v2-crash-recovery"
    migration.mkdir(mode=0o700)
    migration_db = migration / "apd.db"
    migration_key = migration / "pki" / "identity.ed25519"
    run(binary, migration_db, migration_key, "seed-v2")
    with sqlite3.connect(migration_db) as connection:
        old = connection.execute(
            "SELECT ap_id,private_key,public_key,key_id,created_at "
            "FROM apd_node_identity_v2").fetchone()
    assert old is not None
    failed = run(binary, migration_db, migration_key, "identity", check=False,
                 extra_env={"APD_DB_TEST_FAIL_COMMIT_ONCE": "1"})
    assert failed.returncode != 0
    assert assert_key_file(migration_key) == old[1]
    with sqlite3.connect(migration_db) as connection:
        tables = {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert "apd_node_identity_v2" in tables
        assert "apd_node_identity_v3" not in tables
    output = fields(run(binary, migration_db, migration_key, "identity").stdout)
    _, migrated = identity_schema(migration_db)
    assert assert_key_file(migration_key) == old[1]
    assert (output["ap_id"], bytes.fromhex(output["public_key"]),
            output["key_id"], int(output["created_at"])) == (
                old[0], old[2], old[3], old[4])
    assert migrated[0] == old[0] and migrated[1] == old[2]


def expect_failure(binary: Path, db: Path, key: Path) -> None:
    assert run(binary, db, key, "identity", check=False).returncode != 0


def key_boundaries(binary: Path, root: Path, source_db: Path,
                   source_key: Path) -> None:
    def copy_db(name: str) -> tuple[Path, Path]:
        directory = root / name
        directory.mkdir(mode=0o700)
        db = directory / "apd.db"
        db.write_bytes(source_db.read_bytes())
        os.chmod(db, 0o600)
        pki = directory / "pki"
        pki.mkdir(mode=0o700)
        return db, pki / "identity.ed25519"

    db, key = copy_db("key-symlink")
    key.symlink_to(source_key)
    expect_failure(binary, db, key)

    db, key = copy_db("key-hardlink")
    os.link(source_key, key)
    expect_failure(binary, db, key)
    key.unlink()

    db, key = copy_db("key-mode")
    key.write_bytes(source_key.read_bytes())
    os.chmod(key, 0o644)
    expect_failure(binary, db, key)

    db, key = copy_db("key-dir-mode")
    key.write_bytes(source_key.read_bytes())
    os.chmod(key, 0o600)
    os.chmod(key.parent, 0o755)
    expect_failure(binary, db, key)

    if os.geteuid() == 0:
        db, key = copy_db("key-owner")
        key.write_bytes(source_key.read_bytes())
        os.chmod(key, 0o600)
        os.chown(key, 1, -1)
        expect_failure(binary, db, key)


def parse_transcript(raw: bytes) -> tuple[list[bytes], int]:
    assert raw.startswith(DOMAIN)
    offset = len(DOMAIN)
    values: list[bytes] = []
    for _ in range(12):
        length = struct.unpack_from(">H", raw, offset)[0]
        offset += 2
        values.append(raw[offset:offset + length])
        offset += length
    expires_at = struct.unpack_from(">Q", raw, offset)[0]
    offset += 8
    assert offset == len(raw)
    return values, expires_at


def enrollment_crypto(binary: Path, root: Path, db: Path, key: Path,
                      identity: dict[str, str]) -> None:
    transcript = root / "transcript.bin"
    signature = root / "signature.bin"
    csr = root / "request.der"
    output = fields(run(binary, db, key, "enrollment", str(transcript),
                        str(signature), str(csr)).stdout)
    values, expires_at = parse_transcript(transcript.read_bytes())
    assert expires_at == int(output["expires_at"])
    assert values[0] == b"33333333-3333-4333-8333-333333333333"
    assert values[1] == bytes(range(32))
    assert values[2] == bytes(range(32, 64))
    assert values[3] == b"11111111-1111-4111-8111-111111111111"
    assert values[4] == b"22222222-2222-4222-8222-222222222222"
    assert values[5] == b"T" * 43
    assert values[6] == identity["ap_id"].encode()
    assert values[7] == identity["key_id"].encode()
    assert values[8] == bytes.fromhex(identity["public_key"])
    assert values[9] == b"site-fixture"
    assert values[10] == b"sha256:" + b"b" * 64
    assert values[11] == hashlib.sha256(csr.read_bytes()).digest()
    assert len(signature.read_bytes()) == 64

    public_pem = root / "csr-public.pem"
    subprocess.run(["openssl", "req", "-inform", "DER", "-in", str(csr),
                    "-verify", "-noout"], check=True, capture_output=True, text=True)
    details = subprocess.run(
        ["openssl", "req", "-inform", "DER", "-in", str(csr),
         "-noout", "-subject", "-text"], check=True,
        capture_output=True, text=True).stdout
    assert re.search(r"Subject:\s*$", details, re.MULTILINE)
    san = f"URI:urn:dreamingwrt:ap:{identity['ap_id']}"
    assert details.count(san) == 1
    assert "CN =" not in details and "commonName" not in details
    subprocess.run(["openssl", "req", "-inform", "DER", "-in", str(csr),
                    "-pubkey", "-noout", "-out", str(public_pem)], check=True)
    subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin",
                    "-inkey", str(public_pem), "-rawin", "-in", str(transcript),
                    "-sigfile", str(signature)], check=True,
                   capture_output=True, text=True)
    assert fields(run(binary, db, key, "negative").stdout)["rejected"] == "6"


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="apd-phase1e-") as raw:
        root = Path(raw)
        os.chmod(root, 0o700)
        binary = root / "fixture"
        compile_fixture(binary)
        db, key, identity, _ = fresh_init(binary, root)
        v2_migration(binary, root)
        crash_recovery(binary, root)
        key_boundaries(binary, root, db, key)
        enrollment_crypto(binary, root, db, key, identity)
    print("ok: APD v3 key isolation, crash-safe migration, CSR, and binary-v1 signature")


if __name__ == "__main__":
    main()

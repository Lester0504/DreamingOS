#!/usr/bin/env python3
"""Real SQLite and multi-process tests for AC pairing-token Phase 1C."""

from __future__ import annotations

import concurrent.futures
import hashlib
import glob
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
DB_SOURCE = ROOT / "src/ac/ac_db.c"
FIXTURE = ROOT / "tests/ac_pairing_runtime_fixture.c"
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


def target_prefix() -> Path | None:
    configured = os.environ.get("AC_PAIRING_TEST_PREFIX", "")
    if configured:
        prefix = Path(configured)
        assert (prefix / "include/openssl/evp.h").is_file(), (
            f"OpenSSL headers missing below {prefix}")
        assert (prefix / "include/sqlite3.h").is_file(), (
            f"SQLite headers missing below {prefix}")
        return prefix
    return None


def compile_fixture(output: Path) -> None:
    prefix = target_prefix()
    dependency_flags = (
        [f"-I{prefix / 'include'}", f"-L{prefix / 'lib'}",
         f"-Wl,-rpath,{prefix / 'lib'}"]
        if prefix else [f"-I{OPENSSL / 'include'}", f"-L{OPENSSL / 'lib'}"]
    )
    command = [
        os.environ.get("CC", "cc"), "-std=c11",
        "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
        "-DAC_DB_TEST_STANDALONE",
        "-Wall", "-Wextra", "-Werror",
        *dependency_flags, *json_flags(prefix), str(FIXTURE), str(DB_SOURCE),
        "-lcrypto", "-lsqlite3", "-lm", "-o", str(output),
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)


def run(binary: Path, database: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["DREAMINGWRT_AC_DB_PATH"] = str(database)
    prefix = target_prefix()
    if prefix:
        env["LD_LIBRARY_PATH"] = str(prefix / "lib") + (
            f":{env['LD_LIBRARY_PATH']}" if env.get("LD_LIBRARY_PATH") else "")
    return subprocess.run(
        [str(binary), *args], env=env, check=check,
        capture_output=True, text=True,
    )


def fields(output: str) -> dict[str, str]:
    return dict(re.findall(r"([a-z_]+)=([^\s]+)", output))


def create(binary: Path, database: Path, ttl: int = 600, attempts: int = 5,
           site: str = "", hardware: str = "") -> dict[str, str]:
    result = fields(run(binary, database, "create", str(ttl), str(attempts), site, hardware).stdout)
    assert len(result["token_id"]) == 36
    assert len(result["token"]) == 43
    return result


def test_create_and_secret_bound_storage(binary: Path, database: Path) -> None:
    hardware = "sha256:" + hashlib.sha256(b"ap-fixture").hexdigest()
    created = create(binary, database, site="site-a", hardware=hardware)
    token = created["token"]
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT token_hash,digest_version,site_id,hardware_digest FROM ac_pairing_tokens "
            "WHERE token_id=?", (created["token_id"],),
        ).fetchone()
        assert row is not None
        assert isinstance(row[0], bytes) and len(row[0]) == 32
        assert row[1:] == (1, "site-a", hardware)
        assert token.encode() not in database.read_bytes()
    assert database.stat().st_mode & 0o777 == 0o600
    status = run(binary, database, "status", created["token_id"]).stdout
    listing = run(binary, database, "list").stdout
    for public in (status, listing):
        assert token not in public
        assert hardware not in public
        assert "token_hash" not in public and "hardware_bound=1" in public


def test_concurrent_single_consumer(binary: Path, database: Path) -> None:
    created = create(binary, database)

    def redeem(_: int) -> int:
        output = run(binary, database, "redeem", created["token_id"],
                     created["token"], "", "").stdout
        return int(fields(output)["result"])

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(redeem, range(24)))
    assert results.count(0) == 1, results
    assert all(result in {0, 4} for result in results), results
    assert fields(run(binary, database, "status", created["token_id"]).stdout)["state"] == "consumed"


def test_failure_exhaustion_and_binding(binary: Path, database: Path) -> None:
    hardware = "sha256:" + hashlib.sha256(b"expected-ap").hexdigest()
    wrong_hardware = "sha256:" + hashlib.sha256(b"other-ap").hexdigest()
    created = create(binary, database, attempts=3, site="site-b", hardware=hardware)
    wrong = "A" * 43
    attempts = [
        (created["token"], "site-b", wrong_hardware),
        (created["token"], "site-c", hardware),
        (wrong, "site-b", hardware),
    ]
    for token, site, digest in attempts:
        result = fields(run(binary, database, "redeem", created["token_id"],
                            token, site, digest).stdout)
        assert result["result"] == "1"
    status = fields(run(binary, database, "status", created["token_id"]).stdout)
    assert status["state"] == "exhausted" and status["attempts"] == "3"
    result = fields(run(binary, database, "redeem", created["token_id"],
                        created["token"], "site-b", hardware).stdout)
    assert result["result"] == "5"

    malformed = create(binary, database, attempts=1)
    result = fields(run(binary, database, "redeem", malformed["token_id"],
                        "bad", "", "").stdout)
    assert result["result"] == "1"
    status = fields(run(binary, database, "status", malformed["token_id"]).stdout)
    assert status["state"] == "exhausted" and status["attempts"] == "1"

    unbound = create(binary, database)
    result = fields(run(binary, database, "redeem", unbound["token_id"],
                        unbound["token"], "claimant-site", wrong_hardware).stdout)
    assert result["result"] == "0"


def test_expiry_and_revocation(binary: Path, database: Path) -> None:
    expired = create(binary, database)
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE ac_pairing_tokens SET expires_at=? WHERE token_id=?",
                           (int(time.time()) - 1, expired["token_id"]))
    result = fields(run(binary, database, "redeem", expired["token_id"],
                        expired["token"], "", "").stdout)
    assert result["result"] == "2"

    revoked = create(binary, database)
    run(binary, database, "revoke", revoked["token_id"])
    result = fields(run(binary, database, "redeem", revoked["token_id"],
                        revoked["token"], "", "").stdout)
    assert result["result"] == "3"
    assert run(binary, database, "revoke", revoked["token_id"], check=False).returncode != 0


def test_legacy_migration(binary: Path, directory: Path) -> None:
    database = directory / "legacy.db"
    with sqlite3.connect(database) as connection:
        connection.executescript("""
            CREATE TABLE ac_pairing_tokens (
                token_id TEXT PRIMARY KEY, token_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL, max_attempts INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0, consumed_at INTEGER NOT NULL DEFAULT 0,
                scope_json TEXT NOT NULL DEFAULT '{}'
            );
        """)
        connection.execute(
            "INSERT INTO ac_pairing_tokens VALUES(?,?,?,?,?,?,?)",
            ("00000000-0000-4000-8000-000000000000", "legacy-weak-digest",
             int(time.time()) + 3600, 5, 0, 0, "{}"),
        )
    database.chmod(0o600)
    run(binary, database, "init")
    with sqlite3.connect(database) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(ac_pairing_tokens)")}
        row = connection.execute(
            "SELECT digest_version,created_at,revoked_at,site_id,hardware_digest "
            "FROM ac_pairing_tokens"
        ).fetchone()
        version = connection.execute(
            "SELECT version,owner FROM ac_schema_meta WHERE singleton=1"
        ).fetchone()
    assert {"digest_version", "created_at", "revoked_at", "site_id", "hardware_digest"} <= columns
    assert row is not None and row[0] == 0 and row[2] > 0
    assert version == (8, "dreamingwrt-ac")


def test_path_security(binary: Path, directory: Path) -> None:
    insecure = directory / "insecure"
    insecure.mkdir(mode=0o777)
    insecure.chmod(0o777)
    assert run(binary, insecure / "config.db", "init", check=False).returncode != 0
    real = directory / "real.db"
    real.write_bytes(b"")
    real.chmod(0o600)
    symlink = directory / "symlink.db"
    symlink.symlink_to(real)
    assert run(binary, symlink, "init", check=False).returncode != 0
    hardlink = directory / "hardlink.db"
    os.link(real, hardlink)
    assert run(binary, real, "init", check=False).returncode != 0
    loose = directory / "loose.db"
    loose.write_bytes(b"")
    loose.chmod(0o644)
    assert run(binary, loose, "init", check=False).returncode != 0


def test_active_record_tamper_fails_closed(binary: Path, directory: Path) -> None:
    database = directory / "tampered.db"
    created = create(binary, database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE ac_pairing_tokens SET site_id=? WHERE token_id=?",
            ("../not-a-site", created["token_id"]),
        )
    assert run(binary, database, "init", check=False).returncode != 0


def test_commit_failure_rolls_back_and_connection_recovers(
        binary: Path, directory: Path) -> None:
    create_db = directory / "commit-create.db"
    result = run(binary, create_db, "commit-failure-create")
    assert "recovered_token_id=" in result.stdout
    with sqlite3.connect(create_db) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM ac_pairing_tokens"
        ).fetchone()[0] == 1

    redeem_db = directory / "commit-redeem.db"
    created = create(binary, redeem_db)
    result = run(binary, redeem_db, "commit-failure-redeem",
                 created["token_id"], created["token"])
    assert "recovered_result=0" in result.stdout
    assert fields(run(binary, redeem_db, "status",
                      created["token_id"]).stdout)["state"] == "consumed"


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="ac-pairing-") as raw:
        directory = Path(raw)
        binary = directory / "ac-pairing-fixture"
        database = directory / "config.db"
        compile_fixture(binary)
        test_create_and_secret_bound_storage(binary, database)
        test_concurrent_single_consumer(binary, database)
        test_failure_exhaustion_and_binding(binary, database)
        test_expiry_and_revocation(binary, database)
        test_legacy_migration(binary, directory)
        test_path_security(binary, directory)
        test_active_record_tamper_fails_closed(binary, directory)
        test_commit_failure_rolls_back_and_connection_recovers(binary, directory)
    print("ok: AC pairing tokens are one-time, context-bound, concurrent-safe, and secret-safe")


if __name__ == "__main__":
    main()

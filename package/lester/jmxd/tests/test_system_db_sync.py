#!/usr/bin/env python3
"""Exercise firmware-to-persistent database promotion and hot-update retention."""

from __future__ import annotations

import hashlib
import shlex
import sqlite3
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def create_dpi(path: Path, version: str) -> None:
    db = sqlite3.connect(path)
    db.executescript(
        "CREATE TABLE app(id INTEGER PRIMARY KEY, name TEXT);"
        "CREATE TABLE dpi_rule(id INTEGER PRIMARY KEY, pattern TEXT);"
        "CREATE TABLE domain_entry(id INTEGER PRIMARY KEY, domain TEXT);"
        "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);"
    )
    db.execute("INSERT INTO meta VALUES('version',?)", (version,))
    db.commit()
    db.close()


def create_fingerprint(path: Path, version: str) -> None:
    db = sqlite3.connect(path)
    db.execute("PRAGMA application_id=1146570320")
    db.execute("PRAGMA user_version=1")
    db.executescript(
        "CREATE TABLE fingerprint_device(id INTEGER PRIMARY KEY, name TEXT);"
        "CREATE TABLE fingerprint_meta(key TEXT PRIMARY KEY, value TEXT);"
    )
    db.execute("INSERT INTO fingerprint_meta VALUES('version',?)", (version,))
    db.commit()
    db.close()


def compile_harness(root: Path, firmware: Path, runtime: Path, state: Path,
                    release: Path) -> Path:
    binary = root / "system-db-sync"
    flags = shlex.split(
        subprocess.check_output(
            ["pkg-config", "--cflags", "--libs", "openssl", "sqlite3"], text=True
        )
    )
    subprocess.run(
        [
            "cc",
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror",
            f'-DDWRT_SYSTEM_DB_DIR="{firmware}"',
            f'-DDWRT_RUNTIME_DB_DIR="{runtime}"',
            f'-DDWRT_SYSTEM_DB_STATE_DIR="{state}"',
            f'-DDWRT_FIRMWARE_RELEASE_PATH="{release}"',
            f"-I{ROOT / 'src/init'}",
            str(ROOT / "src/init/system_db_sync.c"),
            str(ROOT / "tests/system_db_sync_harness.c"),
            *flags,
            "-o",
            str(binary),
        ],
        check=True,
    )
    return binary


def run(binary: Path) -> str:
    return subprocess.run([str(binary), "sync"], check=True, text=True,
                          stdout=subprocess.PIPE).stdout


def test_system_db_sync_contract() -> None:
    with tempfile.TemporaryDirectory(prefix="dwrt-system-db-") as tmp:
        root = Path(tmp)
        firmware = root / "firmware"
        runtime = root / "runtime"
        state = root / "state"
        release = root / "dreamingwrt-release.json"
        firmware.mkdir()
        runtime.mkdir()
        release.write_text('{"build_id":"firmware-v1"}\n')
        create_dpi(firmware / "dreamingwrt_signatures.db", "firmware-v1")
        create_fingerprint(firmware / "fingerprint.db", "firmware-v1")
        create_dpi(runtime / "dreamingwrt_signatures.db", "old-runtime")

        binary = compile_harness(root, firmware, runtime, state, release)
        first = run(binary)
        assert "changed=2 errors=0" in first
        assert sha256(runtime / "dreamingwrt_signatures.db") == sha256(
            firmware / "dreamingwrt_signatures.db"
        )
        assert sha256(runtime / "fingerprint/fingerprint.db") == sha256(
            firmware / "fingerprint.db"
        )

        # A database hot update remains authoritative across ordinary reboots.
        (runtime / "dreamingwrt_signatures.db").unlink()
        create_dpi(runtime / "dreamingwrt_signatures.db", "hot-update")
        hot_hash = sha256(runtime / "dreamingwrt_signatures.db")
        second = run(binary)
        assert "changed=0 errors=0" in second
        assert sha256(runtime / "dreamingwrt_signatures.db") == hot_hash

        # A later firmware carrying the database replaces it once, even if the
        # bundled database itself is byte-identical.
        release.write_text('{"build_id":"firmware-v2"}\n')
        third = run(binary)
        assert "changed=2 errors=0" in third
        assert sha256(runtime / "dreamingwrt_signatures.db") == sha256(
            firmware / "dreamingwrt_signatures.db"
        )

        # Different database content in another firmware is promoted too.
        release.write_text('{"build_id":"firmware-v3"}\n')
        (firmware / "dreamingwrt_signatures.db").unlink()
        create_dpi(firmware / "dreamingwrt_signatures.db", "firmware-v2")
        fourth = run(binary)
        assert "changed=2 errors=0" in fourth
        assert sha256(runtime / "dreamingwrt_signatures.db") == sha256(
            firmware / "dreamingwrt_signatures.db"
        )

        # Invalid firmware content is rejected without touching the runtime DB.
        good_hash = sha256(runtime / "dreamingwrt_signatures.db")
        (firmware / "dreamingwrt_signatures.db").write_bytes(b"not sqlite")
        failed = subprocess.run([str(binary), "sync"], text=True,
                                stdout=subprocess.PIPE)
        assert failed.returncode != 0
        assert "firmware_source_invalid" in failed.stdout
        assert sha256(runtime / "dreamingwrt_signatures.db") == good_hash


if __name__ == "__main__":
    test_system_db_sync_contract()
    print("ok: firmware system database promotion contract")

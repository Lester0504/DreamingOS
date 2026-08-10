#!/usr/bin/env python3
"""Exercise firmware-to-persistent database promotion and hot-update retention."""

from __future__ import annotations

import hashlib
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apd_test_deps  # noqa: E402


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


def compile_harness(root: Path, legacy_firmware: Path, new_firmware: Path,
                    runtime: Path, state: Path, release: Path) -> Path:
    binary = root / "system-db-sync"
    # Resolved through the shared helper so a host without .pc files still
    # finds a usable prefix instead of failing here.
    flags = apd_test_deps.package_flags("openssl", "sqlite3")
    subprocess.run(
        [
            "cc",
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror",
            f'-DDWRT_SYSTEM_DB_LEGACY_DIR="{legacy_firmware}"',
            f'-DDWRT_SYSTEM_DB_NEW_DIR="{new_firmware}"',
            f'-DDWRT_RUNTIME_DB_DIR="{runtime}"',
            f'-DDWRT_SYSTEM_DB_STATE_DIR="{state}"',
            f'-DDWRT_FIRMWARE_RELEASE_PATH="{release}"',
            f"-I{ROOT / 'src'}",
            f"-I{ROOT / 'src/init'}",
            str(ROOT / "src/init/system_db_sync.c"),
            str(ROOT / "src/jmx_path_provider.c"),
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


def test_system_db_startup_contract() -> None:
    init = (ROOT / "src/init/dreamingwrt_init.c").read_text(encoding="utf-8")
    makefile = (ROOT / "src/Makefile").read_text(encoding="utf-8")
    sync = (ROOT / "src/init/system_db_sync.c").read_text(encoding="utf-8")

    assert "jmx_path_provider.o" in makefile
    wait = init.index("wait_for_persistent_store()")
    system_db = init.index("dwrt_system_db_sync(&system_db_status)", wait)
    conflict = init.index("if (system_db_status.conflicts)", system_db)
    abort = init.index("return 1;", conflict)
    load_config = init.index("load_config();", system_db)
    start_all = init.index("start_all(&dummy, 1);", load_config)
    assert wait < system_db < conflict < abort < load_config < start_all
    command = init.index('if (strcmp(cmd, "system-db") == 0')
    command_end = init.index('if (strcmp(cmd, "config-restore") == 0', command)
    command_body = init[command:command_end]
    assert "emit_system_db_status(out, 1, json, &conflicts)" in command_body
    assert "if (!conflicts)\n                start_all(out, 1);" in command_body
    assert "components remain stopped: system database source conflict" in command_body
    assert "components_restart_allowed" in init
    assert "DWRT_SYSTEM_DB_NEW_DIR \"/usr/share/dreamingos/system-db\"" in sync
    assert "DWRT_SYSTEM_DB_LEGACY_DIR \"/usr/share/dreamingwrt/system-db\"" in sync
    assert "DWRT_RUNTIME_DB_DIR \"/etc/dreamingwrt\"" in sync
    assert "Preflight every immutable source before replacing either runtime DB" in sync


def test_system_db_sync_contract() -> None:
    with tempfile.TemporaryDirectory(prefix="dwrt-system-db-") as tmp:
        root = Path(tmp)
        firmware = root / "firmware-legacy"
        new_firmware = root / "firmware-new"
        runtime = root / "runtime"
        state = root / "state"
        release = root / "dreamingwrt-release.json"
        firmware.mkdir()
        new_firmware.mkdir()
        runtime.mkdir()
        release.write_text('{"build_id":"firmware-v1"}\n')
        create_dpi(firmware / "dreamingwrt_signatures.db", "firmware-v1")
        create_fingerprint(firmware / "fingerprint.db", "firmware-v1")
        create_dpi(runtime / "dreamingwrt_signatures.db", "old-runtime")

        binary = compile_harness(root, firmware, new_firmware, runtime, state, release)
        first = run(binary)
        assert "changed=2 errors=0" in first
        assert "selection=legacy-fallback" in first
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

        # Identical new/legacy firmware paths select the new slug without
        # creating a second runtime writer.
        (firmware / "dreamingwrt_signatures.db").write_bytes(
            (runtime / "dreamingwrt_signatures.db").read_bytes()
        )
        (new_firmware / "dreamingwrt_signatures.db").write_bytes(
            (firmware / "dreamingwrt_signatures.db").read_bytes()
        )
        (new_firmware / "fingerprint.db").write_bytes(
            (firmware / "fingerprint.db").read_bytes()
        )
        identical = run(binary)
        assert identical.count("selection=new-identical-to-legacy") == 2

        # Divergent copies are an identity conflict.  Preflight rejects the
        # whole pair before either persistent runtime database is replaced.
        release.write_text('{"build_id":"firmware-conflict"}\n')
        (new_firmware / "dreamingwrt_signatures.db").unlink()
        create_dpi(new_firmware / "dreamingwrt_signatures.db", "conflicting-new")
        dpi_before = sha256(runtime / "dreamingwrt_signatures.db")
        fingerprint_before = sha256(runtime / "fingerprint/fingerprint.db")
        conflict = subprocess.run([str(binary), "sync"], text=True,
                                  stdout=subprocess.PIPE)
        assert conflict.returncode != 0
        assert "conflicts=1" in conflict.stdout
        assert "firmware_source_identity_conflict" in conflict.stdout
        assert sha256(runtime / "dreamingwrt_signatures.db") == dpi_before
        assert sha256(runtime / "fingerprint/fingerprint.db") == fingerprint_before

        # Existing symlinks are not accepted as immutable firmware authority.
        (new_firmware / "dreamingwrt_signatures.db").unlink()
        (new_firmware / "dreamingwrt_signatures.db").symlink_to(
            runtime / "dreamingwrt_signatures.db"
        )
        unsafe = subprocess.run([str(binary), "sync"], text=True,
                                stdout=subprocess.PIPE)
        assert unsafe.returncode != 0
        assert "conflicts=1" in unsafe.stdout
        assert "firmware_source_identity_conflict" in unsafe.stdout
        assert sha256(runtime / "dreamingwrt_signatures.db") == dpi_before
        (new_firmware / "dreamingwrt_signatures.db").unlink()
        create_dpi(new_firmware / "dreamingwrt_signatures.db", "new-only")

        # A new-only firmware source is accepted and still writes only the
        # existing legacy runtime authority.
        (firmware / "dreamingwrt_signatures.db").unlink()
        (firmware / "fingerprint.db").unlink()
        release.write_text('{"build_id":"firmware-new-only"}\n')
        new_only = run(binary)
        assert new_only.count("selection=new-only") == 2


if __name__ == "__main__":
    test_system_db_startup_contract()
    test_system_db_sync_contract()
    print("ok: firmware system database promotion contract")

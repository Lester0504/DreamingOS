"""Contract and runtime fixture for storage-migration.v1."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_migration_contract_source() -> None:
    source = (ROOT / "src/storage/storage_migration.c").read_text(encoding="utf-8")
    header = (ROOT / "src/storage/storage_migration.h").read_text(encoding="utf-8")
    assert 'JMX_STORAGE_MIGRATION_CONTRACT "storage-migration.v1"' in header
    for marker in (
        "confirm", "dry_run", "preflight", "sqlite_checkpoint_tree",
        "sqlite3_wal_checkpoint_v2", "copy_verify", "fsync", "rename(",
        "rollback", "consumer_reopen_not_wired", "consumer_reopen_failed",
        "consumer_freeze_not_wired", "checksum_scope", "payload_tree",
        "migration-manifest.json", "rollback_command",
    ):
        assert marker in source
    assert "mount(" not in source
    assert "format(" not in source


def test_migration_fixture_success_and_gates() -> None:
    compiler = os.environ.get("CC") or shutil.which("cc") or shutil.which("clang")
    assert compiler
    with tempfile.TemporaryDirectory(prefix="storage-migration-fixture-") as raw:
        temp = Path(raw)
        old_path = temp / "old.db"
        new_path = temp / "target.db"
        old_path.write_bytes(b"fixture-data")
        binary = temp / "migration-fixture"
        flags = subprocess.check_output(
            ["pkg-config", "--cflags", "--libs", "json-c", "sqlite3", "openssl"],
            text=True,
        ).split()
        subprocess.run(
            [compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
             "-I", str(ROOT / "src"),
             str(ROOT / "src/storage/storage_migration.c"),
             str(ROOT / "tests/storage_migration_fixture.c"),
             *flags, "-o", str(binary)],
            check=True,
        )
        run = subprocess.run([str(binary), str(old_path), str(new_path)],
                             text=True, capture_output=True, check=True)
        rows = [json.loads(line) for line in run.stdout.splitlines()]
        events = [json.loads(line.removeprefix("DWRT_BUSINESS_V1 "))
                  for line in run.stderr.splitlines()]
        # Three preflight calls emit nothing; only two real moves and rollback.
        assert len(events) == 3
        assert [e["detail"]["result"] for e in events] == ["success", "failed", "success"]
        assert all(e["event"] == "STORAGE_MIGRATION_FINISHED" for e in events)
        assert events[1]["detail"]["failure_stage"] == "rollback"
        assert events[1]["detail"]["failure_reason"] == "consumer_reopen_failed"
        assert "failure_stage" not in events[0]["detail"]
        assert rows[0]["ok"] is True and rows[0]["reason"] == "dry_run_ready"
        assert rows[1]["ok"] is False and rows[1]["reason"] == "confirmation_required"
        assert rows[2]["ok"] is False and rows[2]["reason"] == "consumer_freeze_not_wired"
        assert rows[3]["ok"] is True and rows[3]["phase"] == "readback"
        assert rows[3]["rollback_available"] is True
        assert rows[4]["ok"] is False and rows[4]["reason"] == "consumer_reopen_failed"
        assert rows[4]["phase"] == "rollback"
        assert rows[5]["ok"] is True and rows[5]["phase"] == "readback"
        assert new_path.read_bytes() == b"fixture-data"
        assert not old_path.exists()
        manifest = new_path.with_name(new_path.name + ".manifest.json")
        assert manifest.is_file()
        manifest_json = json.loads(manifest.read_text())
        assert manifest_json["checksum_scope"] == "payload_tree"
        assert len(manifest_json["sha256"]) == 64
        failed_old = Path(str(old_path) + "-failure")
        failed_new = Path(str(new_path) + "-failure")
        assert failed_old.read_bytes() == b"rollback-fixture"
        assert not failed_new.exists()
        directory_old = Path(str(old_path) + "-directory")
        directory_new = Path(str(new_path) + "-directory")
        assert not directory_old.exists()
        assert (directory_new / 'quote"name.txt').read_bytes() == b"directory-fixture"
        directory_manifest = directory_new / "migration-manifest.json"
        directory_manifest_json = json.loads(directory_manifest.read_text())
        assert directory_manifest_json["checksum_scope"] == "payload_tree"
        assert len(directory_manifest_json["sha256"]) == 64


if __name__ == "__main__":
    test_migration_contract_source()
    test_migration_fixture_success_and_gates()
    print("ok: storage migration contract and fixture")

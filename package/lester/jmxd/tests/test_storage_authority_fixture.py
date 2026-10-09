"""Run the provider/authority readback fixture without touching live state."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys_path = ROOT / "tests"
import sys
sys.path.insert(0, str(sys_path))
import apd_test_deps  # noqa: E402


def main() -> None:
    compiler = os.environ.get("CC") or shutil.which("cc") or shutil.which("clang")
    if not compiler:
        raise SystemExit("no C compiler available")
    cflags = apd_test_deps.package_flags("json-c", "sqlite3", "openssl")
    with tempfile.TemporaryDirectory(prefix="storage-authority-fixture-") as raw:
        binary = Path(raw) / "storage-authority-fixture"
        subprocess.run(
            [compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
             "-I", str(ROOT / "src"),
             str(ROOT / "src/storage/storage_provider.c"),
             str(ROOT / "src/storage/storage_migration.c"),
             str(ROOT / "src/storage/storage_binding.c"),
             str(ROOT / "src/jmx_dataset_path.c"),
             str(ROOT / "src/authority/authority_diagnostics.c"),
             str(ROOT / "tests/storage_authority_contract_fixture.c"),
             *cflags, "-o", str(binary)],
            check=True,
        )
        result = subprocess.run([str(binary)], check=True, text=True,
                                capture_output=True)
    rows = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert len(rows) == 2
    provider = rows[0]
    authority = rows[1]
    assert provider["contract_version"] == "storage-provider.v1"
    assert provider["auto_mount_or_format"] is False
    assert provider["migration_supported"] is False
    assert provider["failure_mode"] == "external_storage_unavailable_fail_closed"
    assert {item["use"] for item in provider["bindings"]["uses"]} == {
        "audit", "aegis", "log", "snapshots", "core", "metrics", "apid",
        "notify", "flow", "wan_sla", "aegis_work"
    }
    assert authority["contract_version"] == "authority-diagnostics.v1"
    names = {item["name"] for item in authority["authorities"]}
    assert {"signatures", "fingerprint", "dreamingwrt.db"} <= names
    for item in authority["authorities"]:
        assert "canonical_path" in item
        assert "active_path" in item
        assert "canonical_present" in item
        assert "canonical_read_only" in item
        assert "present_duplicate_paths" in item
        assert "content_mismatch_paths" in item
        assert "writable_duplicate_paths" in item
        assert "path_observations" in item
        for observation in item["path_observations"]:
            assert {"path", "role", "canonical", "active", "readable",
                    "writable", "read_only"} <= set(observation)
    print("ok: storage provider and authority diagnostics fixture")


if __name__ == "__main__":
    main()

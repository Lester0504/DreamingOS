#!/usr/bin/env python3
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "init" / "config_restore.c"
HDR_DIR = ROOT / "init"

HARNESS = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "config_restore.h"

static int stops;
static int starts;
static int cores;

static int stop_all(void *opaque) { (void)opaque; stops++; return 0; }
static int start_core(void *opaque) { (void)opaque; cores++; return 0; }
static int start_all(void *opaque) { (void)opaque; starts++; return 0; }

int main(int argc, char **argv) {
    struct dwrt_config_restore_hooks hooks = {
        .stop_all = stop_all,
        .start_core = start_core,
        .start_all = start_all,
        .opaque = NULL,
    };
    struct dwrt_config_restore_info info;
    int rc;

    assert(argc == 2);
    memset(&info, 0, sizeof(info));
    if (!strcmp(argv[1], "arm-fail")) {
        assert(dwrt_config_restore_arm(&info) != 0);
        assert(info.error[0]);
        return 0;
    }
    if (!strcmp(argv[1], "arm")) {
        int arm_rc = dwrt_config_restore_arm(&info);
        if (arm_rc != 0)
            fprintf(stderr, "arm failed: phase=%s error=%s\n", info.phase, info.error);
        assert(arm_rc == 0);
        assert(!strcmp(info.phase, "armed"));
        assert(info.pending == 1);
        assert(!strcmp(info.expected_lan_ip, "192.168.1.1"));
        assert(info.wan_count == 1);
        assert(info.lan_count == 1);
        return 0;
    }
    if (!strcmp(argv[1], "apply-fail")) {
        assert(dwrt_config_restore_apply(&hooks, &info) != 0);
        assert(info.error[0]);
        assert(stops == 0);
        return 0;
    }
    if (!strcmp(argv[1], "apply")) {
        int apply_rc = dwrt_config_restore_apply(&hooks, &info);
        if (apply_rc != 0)
            fprintf(stderr, "apply failed: phase=%s error=%s\n", info.phase, info.error);
        assert(apply_rc == 0);
        assert(!strcmp(info.phase, "pending_confirmation"));
        assert(info.pending == 1);
        assert(info.backup_available == 1);
        assert(stops == 1);
        assert(starts == 1);
        assert(cores == 0);
        return 0;
    }
    if (!strcmp(argv[1], "rollback")) {
        assert(dwrt_config_restore_rollback(&hooks, "test_rollback", &info) == 0);
        assert(!strcmp(info.phase, "rolled_back"));
        assert(stops == 1);
        assert(starts == 1);
        return 0;
    }
    if (!strcmp(argv[1], "expire")) {
        rc = dwrt_config_restore_maybe_rollback(&hooks, INT64_MAX, &info);
        assert(rc == 1);
        assert(!strcmp(info.phase, "rolled_back"));
        assert(stops == 1);
        assert(starts == 1);
        return 0;
    }
    if (!strcmp(argv[1], "confirm")) {
        assert(dwrt_config_restore_confirm(&info) == 0);
        assert(!strcmp(info.phase, "confirmed"));
        assert(info.pending == 0);
        return 0;
    }
    if (!strcmp(argv[1], "status")) {
        assert(dwrt_config_restore_status(&info) == 0);
        printf("%s %s\n", info.phase, info.error);
        return 0;
    }
    return 2;
}
'''


def create_db(path: Path, marker: str, lan_ip: str, *, include_work_mode: bool = True) -> None:
    db = sqlite3.connect(path)
    db.executescript(
        """
        PRAGMA application_id=1146573396;
        PRAGMA user_version=1;
        PRAGMA journal_mode=WAL;
        CREATE TABLE network_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE wan(id TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE lan(id TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE lan_address(
            lan_id TEXT NOT NULL, ip TEXT NOT NULL,
            is_primary INTEGER NOT NULL DEFAULT 0,
            sort_order INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE network_global(id INTEGER PRIMARY KEY);
        CREATE TABLE web_users(id INTEGER PRIMARY KEY, username TEXT);
        CREATE TABLE system_ui_settings(id INTEGER PRIMARY KEY CHECK(id=1));
        CREATE TABLE appearance_settings(id INTEGER PRIMARY KEY CHECK(id=1));
        CREATE TABLE system_settings(
            id INTEGER PRIMARY KEY CHECK(id=1),
            hostname TEXT NOT NULL
        );
        CREATE TABLE restore_test(marker TEXT NOT NULL);
        """,
    )
    db.execute("INSERT INTO network_meta VALUES('schema_version', '1')")
    db.execute("INSERT INTO wan VALUES('wan', 1)")
    db.execute("INSERT INTO lan VALUES('lan', 1)")
    db.execute("INSERT INTO lan_address VALUES('lan', ?, 1, 0)", (lan_ip,))
    db.execute("INSERT INTO network_global VALUES(1)")
    db.execute("INSERT INTO web_users VALUES(1, 'Lester')")
    db.execute("INSERT INTO system_ui_settings VALUES(1)")
    db.execute("INSERT INTO appearance_settings VALUES(1)")
    db.execute(
        "INSERT INTO system_settings VALUES(1, ?)",
        ("DreamingWrt" if lan_ip == "192.168.1.1" else "TargetBeforeRestore",),
    )
    if include_work_mode:
        db.executescript(
            """
            CREATE TABLE work_mode_settings(
                id INTEGER PRIMARY KEY CHECK(id=1),
                work_mode TEXT NOT NULL
            );
            INSERT INTO work_mode_settings VALUES(1, 'router');
            """
        )
    db.execute("INSERT INTO restore_test VALUES(?)", (marker,))
    db.commit()
    assert db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    db.close()


def marker(path: Path) -> str:
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        assert db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        return db.execute("SELECT marker FROM restore_test").fetchone()[0]
    finally:
        db.close()


def online_backup(source: Path, destination: Path) -> None:
    source_db = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    destination.unlink(missing_ok=True)
    destination_db = sqlite3.connect(destination)
    try:
        source_db.backup(destination_db)
        destination_db.commit()
        assert destination_db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    finally:
        destination_db.close()
        source_db.close()


def write_manifest(path: Path, db_path: Path, sha_override: str | None = None) -> None:
    payload = db_path.read_bytes()
    manifest = {
        "format": "dreamingwrt-config-backup-v1",
        "product": "DreamingWrt",
        "upload_id": "backup-contract-001",
        "source_version": "Linux7.1-RC5",
        "created_at": 1784070000,
        "size_bytes": len(payload),
        "sha256": sha_override or hashlib.sha256(payload).hexdigest(),
    }
    path.write_text(json.dumps(manifest, separators=(",", ":")), encoding="ascii")


def run(exe: Path, action: str) -> None:
    subprocess.run([str(exe), action], check=True)


def main() -> None:
    text = SRC.read_text(encoding="utf-8")
    for forbidden in ("system(", "popen(", "execl(\"/bin/sh", "cp "):
        assert forbidden not in text, f"restore core must not invoke shell helper: {forbidden}"
    assert "sqlite3_backup_init" in text
    assert "PRAGMA quick_check" in text
    assert "O_NOFOLLOW" in text
    assert "fsync_parent" in text

    with tempfile.TemporaryDirectory() as td:
        root = Path(td).resolve()
        etc_dwrt = root / "etc" / "dreamingwrt"
        etc_config = root / "etc" / "config"
        staging = etc_dwrt / "restore-staging"
        backup = etc_dwrt / "config-restore-backup"
        etc_dwrt.mkdir(parents=True)
        etc_config.mkdir(parents=True)
        staging.mkdir(mode=0o700)

        current = etc_dwrt / "config.db"
        source = root / "source.db"
        incomplete = root / "incomplete.db"
        staged = staging / "config.db"
        manifest = staging / "manifest.json"
        create_db(current, "target-before-restore", "198.51.100.250")
        create_db(source, "source-from-30.1", "192.168.1.1")
        create_db(
            incomplete,
            "same-schema-missing-work-mode",
            "192.168.1.1",
            include_work_mode=False,
        )
        for name, value in (
            ("network", "config interface 'lan'\n\toption ipaddr '198.51.100.250'\n"),
            ("dhcp", "config dhcp 'lan'\n"),
            ("firewall", "config defaults\n"),
            ("system", "config system\n\toption hostname 'TargetBeforeRestore'\n"),
        ):
            (etc_config / name).write_text(value, encoding="ascii")

        harness = root / "restore_harness.c"
        exe = root / "restore_harness"
        harness.write_text(HARNESS, encoding="ascii")
        defs = {
            "DWRT_CONFIG_DB": current,
            "DWRT_CONFIG_RESTORE_DIR": staging,
            "DWRT_CONFIG_RESTORE_DB": staged,
            "DWRT_CONFIG_RESTORE_MANIFEST": manifest,
            "DWRT_CONFIG_RESTORE_PENDING": staging / "pending",
            "DWRT_CONFIG_RESTORE_STATE": staging / "state.json",
            "DWRT_CONFIG_RESTORE_BACKUP_DIR": backup,
            "DWRT_NETWORK_CONFIG": etc_config / "network",
            "DWRT_DHCP_CONFIG": etc_config / "dhcp",
            "DWRT_FIREWALL_CONFIG": etc_config / "firewall",
            "DWRT_SYSTEM_CONFIG": etc_config / "system",
        }
        cmd = [
            os.environ.get("CC", "cc"), "-Wall", "-Wextra", "-Werror",
            "-DDWRT_CONFIG_RESTORE_SKIP_NETWORK_APPLY=1",
            "-DDWRT_CONFIG_RESTORE_SKIP_RUNTIME_HOSTNAME=1",
            *[f'-D{k}="{v}"' for k, v in defs.items()],
            "-I", str(HDR_DIR), str(harness), str(SRC), "-lsqlite3", "-o", str(exe),
        ]
        if os.uname().sysname != "Darwin":
            cmd.insert(-2, "-lcrypto")
        subprocess.run(cmd, check=True)

        # A symlink cannot be armed even when it resolves to a valid SQLite DB.
        staged.symlink_to(source)
        write_manifest(manifest, source)
        run(exe, "arm-fail")
        staged.unlink()

        online_backup(source, staged)
        write_manifest(manifest, staged, "0" * 64)
        run(exe, "arm-fail")

        # A backup cannot claim the current schema while omitting an authoritative
        # domain and then rely on defaults or a legacy UCI import after restore.
        online_backup(incomplete, staged)
        write_manifest(manifest, staged)
        run(exe, "arm-fail")

        online_backup(source, staged)
        write_manifest(manifest, staged)
        run(exe, "arm")

        # Revalidate at apply time; arm-time validation alone is insufficient.
        with staged.open("ab") as fp:
            fp.write(b"tamper")
        run(exe, "apply-fail")
        assert marker(current) == "target-before-restore"

        online_backup(source, staged)
        write_manifest(manifest, staged)
        run(exe, "apply")
        assert marker(current) == "source-from-30.1"
        assert marker(backup / "config.db") == "target-before-restore"
        run(exe, "rollback")
        assert marker(current) == "target-before-restore"
        assert "198.51.100.250" in (etc_config / "network").read_text(encoding="ascii")
        assert "TargetBeforeRestore" in (etc_config / "system").read_text(encoding="ascii")

        run(exe, "arm")
        run(exe, "apply")
        run(exe, "expire")
        assert marker(current) == "target-before-restore"

        run(exe, "arm")
        run(exe, "apply")
        run(exe, "confirm")
        assert marker(current) == "source-from-30.1"
        status = subprocess.check_output([str(exe), "status"], text=True)
        assert status.startswith("confirmed ")

    print("config_restore_contract: PASS")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""AegisX content-filter tables are owned by config.db backup/restore."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESTORE = (ROOT / "src/init/config_restore.c").read_text()

CONTENT_TABLES = {
    "aegis_content_policies",
    "aegis_domain_overrides",
    "aegis_content_meta",
}


def function_body(start: str, end: str) -> str:
    begin = RESTORE.index(start)
    finish = RESTORE.index(end, begin)
    return RESTORE[begin:finish]


def test_content_tables_are_not_old_backup_blockers() -> None:
    validator = function_body("static int sqlite_validate", "static int sqlite_backup_file")
    match = re.search(r"static const char \*required\[\] = \{(.*?)\};", validator, re.S)
    assert match, "config restore required-table allowlist is missing"
    required = set(re.findall(r'"([A-Za-z0-9_]+)"', match.group(1)))

    assert CONTENT_TABLES.isdisjoint(required), (
        "content-filter extension tables must not make an older valid config.db unrestorable"
    )


def test_backup_replace_and_rollback_preserve_the_full_validated_database() -> None:
    backup = function_body("static int sqlite_backup_file", "static int state_write")
    snapshot = function_body("static int snapshot_current", "static int replace_config_db")
    replace = function_body("static int replace_config_db", "static const char *find_program")
    rollback = function_body("static int restore_previous", "int dwrt_config_restore_status")

    assert 'sqlite3_backup_init(dst, "main", src, "main")' in backup
    assert "sqlite_validate(tmp, NULL)" in backup
    assert "sqlite_backup_file(DWRT_CONFIG_DB, RESTORE_BACKUP_DB, 0)" in snapshot
    assert "sqlite_backup_file(source, DWRT_CONFIG_DB, 1)" in replace
    assert "replace_config_db(RESTORE_BACKUP_DB)" in rollback


if __name__ == "__main__":
    test_content_tables_are_not_old_backup_blockers()
    test_backup_replace_and_rollback_preserve_the_full_validated_database()
    print("ok: AegisX content-filter config.db backup/restore ownership")

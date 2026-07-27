#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INIT = (ROOT / "src/init/config_restore.c").read_text()
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text()

REQUIRED = (
    "network_meta",
    "wan",
    "lan",
    "network_global",
    "web_users",
    "system_ui_settings",
    "appearance_settings",
    "system_settings",
    "work_mode_settings",
)


def between(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    finish = source.index(end, begin)
    return source[begin:finish]


init_validator = between(INIT, "static int sqlite_validate", "static int sqlite_backup_file")
web_validator = between(
    WEB,
    "static int webd_config_db_validate_path",
    "static struct json_object *webd_config_restore_control_response",
)
staged_manifest = between(
    WEB,
    "pending_manifest = json_object_new_object();",
    "if (webd_restore_write_manifest",
)

for table in REQUIRED:
    literal = f'"{table}"'
    assert literal in init_validator, f"init restore validator omits {table}"
    assert literal in web_validator, f"web restore validator omits {table}"
    assert literal in staged_manifest, f"staged restore manifest omits {table}"

print("config restore required-table contract: ok")

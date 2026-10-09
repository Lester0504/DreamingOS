#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT.parent))
from jmxd.tests.webd_sources import webd_dispatch_text, webd_function_text
INIT = (ROOT / "src/init/config_restore.c").read_text()
WEB = webd_dispatch_text()

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
# webd_config_db_validate_path and webd_config_restore_stage_response moved to
# webd/api/api_maintenance.c in the Phase 7A split (control_response de-static'd),
# so slice inside each moved definition by name instead of over the whole dispatch text.
web_validator = webd_function_text("api_maintenance.c", "webd_config_db_validate_path")
staged_manifest = between(
    webd_function_text("api_maintenance.c", "webd_config_restore_stage_response"),
    "pending_manifest = json_object_new_object();",
    "if (webd_restore_write_manifest",
)

for table in REQUIRED:
    literal = f'"{table}"'
    assert literal in init_validator, f"init restore validator omits {table}"
    assert literal in web_validator, f"web restore validator omits {table}"
    assert literal in staged_manifest, f"staged restore manifest omits {table}"

print("config restore required-table contract: ok")

#!/usr/bin/env python3
import ast
import re
import sqlite3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DB = (ROOT / "src/otad/otad_db.c").read_text(encoding="utf-8")
FIRMWARE = (ROOT / "src/otad/otad_firmware.c").read_text(encoding="utf-8")
HEADER = (ROOT / "src/otad/otad_internal.h").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    return text[first:text.index(end, first)]


complete = between(
    DB,
    "int otad_operation_complete_confirmed_boot(",
    "static struct json_object *otad_operation_row_json",
)
confirm = between(
    FIRMWARE,
    "struct json_object *otad_confirm_boot(",
    "void otad_reconcile_boot_state(",
)
apply_worker = between(
    FIRMWARE,
    "static int otad_firmware_apply_worker",
    "static struct uloop_process g_otad_operation_process",
)

assert "otad_operation_complete_confirmed_boot" in HEADER
assert "UPDATE ota_operations SET state='success',progress=100,worker_pid=0" in complete
assert "updated_at=?1,completed_at=?1" in complete
assert "kind='firmware' AND action='apply' AND target_slot=?2" in complete
assert "state='rebooting'" in complete
assert "(?3='' OR operation_id=?3)" in complete
assert "(?4='' OR build_id=?4)" in complete
assert "RETURNING operation_id" in complete
assert "state && !strcmp(state, \"success\") ? \"completed\" : state" in DB

assert 'otad_state_set("pending_operation_id", operation_id)' in apply_worker
assert 'otad_state_get("pending_operation_id", expected_operation_id' in confirm
assert "otad_operation_complete_confirmed_boot(" in confirm
assert confirm.index("otad_grubenv_promote(current)") < confirm.index(
    "otad_operation_complete_confirmed_boot("
)
assert confirm.index("otad_operation_complete_confirmed_boot(") < confirm.index(
    'otad_state_set("pending_slot", "")'
)
assert 'otad_state_set("pending_operation_id", "")' in confirm
assert '"operation_completed"' in confirm
assert '"operation_id"' in confirm

reconcile = between(
    FIRMWARE,
    "void otad_reconcile_boot_state(",
    "struct json_object *otad_firmware_rollback(",
)
assert "!strcmp(current, grub_active)" in reconcile
assert "!grub_pending[0]" in reconcile
assert "atoi(grub_tries) == 0" in reconcile
assert "slot_name=?1 AND state='good'" in reconcile
assert 'current, "", good_build_id, completed_operation_id' in reconcile

rollback = between(
    FIRMWARE,
    "struct json_object *otad_firmware_rollback(",
    "struct json_object *otad_slot_status_json(",
)
assert 'otad_state_set("pending_operation_id", "")' in rollback

# Execute the exact adjacent C string literals used by the implementation.
prepare = re.search(r"st = otad_operation_prepare\((.*?)\);", complete, re.S)
assert prepare
sql = "".join(ast.literal_eval(token) for token in re.findall(r'"(?:\\.|[^"\\])*"', prepare.group(1)))
db = sqlite3.connect(":memory:")
db.execute(
    "CREATE TABLE ota_operations (operation_id TEXT PRIMARY KEY, kind TEXT, action TEXT, "
    "target_slot TEXT, build_id TEXT, state TEXT, progress INTEGER, worker_pid INTEGER, error_code TEXT, "
    "error_message TEXT, updated_at INTEGER, created_at INTEGER, completed_at INTEGER)"
)
rows = [
    ("ota-" + "1" * 32, "firmware", "apply", "B", "build-current", "rebooting", 90, 10, "", "", 100, 10, 0),
    ("ota-" + "2" * 32, "firmware", "apply", "B", "build-current", "rebooting", 90, 20, "", "", 200, 20, 0),
    ("ota-" + "3" * 32, "firmware", "apply", "A", "build-current", "rebooting", 90, 30, "", "", 300, 30, 0),
    ("ota-" + "4" * 32, "firmware", "preflight", "B", "build-current", "rebooting", 90, 40, "", "", 400, 40, 0),
    ("ota-" + "5" * 32, "firmware", "apply", "B", "build-current", "success", 100, 0, "", "", 500, 50, 500),
    ("ota-" + "6" * 32, "firmware", "apply", "B", "build-old", "rebooting", 90, 60, "", "", 600, 60, 0),
]
db.executemany("INSERT INTO ota_operations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)

exact_id = rows[0][0]
returned = db.execute(sql, (1000, "B", exact_id, "")).fetchone()
assert returned == (exact_id,)
assert db.execute(
    "SELECT state,progress,worker_pid,updated_at,completed_at FROM ota_operations WHERE operation_id=?",
    (exact_id,),
).fetchone() == ("success", 100, 0, 1000, 1000)
assert db.execute(
    "SELECT state,progress FROM ota_operations WHERE operation_id=?", (rows[1][0],)
).fetchone() == ("rebooting", 90)

# A stale persisted id must not fall back to a different operation.
assert db.execute(sql, (1100, "B", "ota-" + "f" * 32, "")).fetchone() is None
assert db.execute(
    "SELECT state FROM ota_operations WHERE operation_id=?", (rows[1][0],)
).fetchone() == ("rebooting",)

# Legacy boots without pending_operation_id select only the newest matching row.
returned = db.execute(sql, (1200, "B", "", "build-current")).fetchone()
assert returned == (rows[1][0],)
for untouched_id, expected_state in (
    (rows[2][0], "rebooting"),
    (rows[3][0], "rebooting"),
    (rows[4][0], "success"),
    (rows[5][0], "rebooting"),
):
    assert db.execute(
        "SELECT state FROM ota_operations WHERE operation_id=?", (untouched_id,)
    ).fetchone() == (expected_state,)

print("ok: confirm_boot atomically completes only its current-slot firmware apply operation")

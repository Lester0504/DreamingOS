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
    "int otad_operation_complete_automatic_rollback(",
)
complete_rollback = between(
    DB,
    "int otad_operation_complete_automatic_rollback(",
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
assert "UPDATE ota_operations SET state='failed',progress=100,worker_pid=0" in complete_rollback
assert "state IN ('rebooting','reconnecting')" in complete_rollback
assert "error_code=?1,error_message=?2" in complete_rollback
assert "updated_at=?3,completed_at=?3" in complete_rollback
assert "(?5='' OR operation_id=?5 OR 1=(SELECT COUNT(*)" in complete_rollback
assert "RETURNING operation_id" in complete_rollback
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
assert "otad_operation_complete_automatic_rollback(" in reconcile
assert '"boot_attempts_exhausted"' in reconcile
assert 'otad_state_set("pending_operation_id", "")' in reconcile
assert 'otad_state_set("pending_observation_started_at", "")' in reconcile
assert "otad_db_persist_now()" in reconcile
assert 'otad_state_get("state", persisted_state' in reconcile
assert '!strcmp(persisted_state, "rolled_back")' in reconcile
assert '!strcmp(rolled_back_state, "rolled_back")' in reconcile
assert 'strcmp(current, grub_active)' in reconcile
assert 'atoi(grub_tries) != 0' in reconcile

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

# Execute the automatic-rollback transition against a fresh operation set.
rollback_prepare = re.search(
    r"st = otad_operation_prepare\((.*?)\);", complete_rollback, re.S
)
assert rollback_prepare
rollback_sql = "".join(
    ast.literal_eval(token)
    for token in re.findall(r'"(?:\\.|[^"\\])*"', rollback_prepare.group(1))
)
db.execute("DELETE FROM ota_operations")
rollback_rows = [
    ("ota-" + "a" * 32, "firmware", "apply", "A", "build-new", "rebooting", 90, 71, "", "", 700, 70, 0),
    ("ota-" + "b" * 32, "firmware", "apply", "B", "build-old", "rebooting", 90, 72, "", "", 710, 71, 0),
    ("ota-" + "c" * 32, "firmware", "preflight", "A", "build-new", "rebooting", 90, 73, "", "", 720, 72, 0),
]
db.executemany("INSERT INTO ota_operations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rollback_rows)
rolled_back_id = rollback_rows[0][0]
returned = db.execute(
    rollback_sql,
    (
        "boot_attempts_exhausted",
        "boot_attempts_exhausted:table_rows_critical",
        2000,
        "A",
        rolled_back_id,
    ),
).fetchone()
assert returned == (rolled_back_id,)
assert db.execute(
    "SELECT state,progress,worker_pid,error_code,error_message,updated_at,completed_at "
    "FROM ota_operations WHERE operation_id=?",
    (rolled_back_id,),
).fetchone() == (
    "failed",
    100,
    0,
    "boot_attempts_exhausted",
    "boot_attempts_exhausted:table_rows_critical",
    2000,
    2000,
)
assert db.execute(
    "SELECT state FROM ota_operations WHERE operation_id=?", (rollback_rows[1][0],)
).fetchone() == ("rebooting",)
assert db.execute(
    "SELECT state FROM ota_operations WHERE operation_id=?", (rollback_rows[2][0],)
).fetchone() == ("rebooting",)

# A stale persisted id still converges the one active operation for the rolled-
# back slot; the target-slot and action predicates keep other rows untouched.
returned = db.execute(
    rollback_sql,
    ("boot_attempts_exhausted", "stale id", 2100, "B", "ota-" + "f" * 32),
).fetchone()
assert returned == (rollback_rows[1][0],)
assert db.execute(
    "SELECT state,error_code,error_message,completed_at FROM ota_operations WHERE operation_id=?",
    (rollback_rows[1][0],),
).fetchone() == ("failed", "boot_attempts_exhausted", "stale id", 2100)
assert db.execute(
    "SELECT state FROM ota_operations WHERE operation_id=?", (rollback_rows[2][0],)
).fetchone() == ("rebooting",)

print("ok: confirm and automatic rollback terminalize only their bound firmware operation")

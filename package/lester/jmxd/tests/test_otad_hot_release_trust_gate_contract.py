#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = (ROOT / "src/otad/otad_manifest.c").read_text(encoding="utf-8")
HOT = (ROOT / "src/otad/otad_hot.c").read_text(encoding="utf-8")
STATUS = (ROOT / "src/otad/otad_status.c").read_text(encoding="utf-8")
UBUS = (ROOT / "src/otad/otad_ubus.c").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    return text[first:text.index(end, first)]


manifest = between(
    MANIFEST,
    "struct json_object *otad_check_manifest(",
    "\n}",
) + "\n}"
assert '"ok", json_object_new_boolean(0)' in manifest
assert '"validated", json_object_new_boolean(err_count == 0)' in manifest
assert '"integrity_verified", json_object_new_boolean(0)' in manifest
assert '"signature_required", json_object_new_boolean(1)' in manifest
assert '"signature_verified", json_object_new_boolean(0)' in manifest
assert '"safe_to_apply_now", json_object_new_boolean(0)' in manifest
assert '"hot_update_release_trust_gate_closed"' in manifest

verify = between(
    HOT,
    "static struct json_object *hot_verify_internal(",
    "static int hot_parent_prepare(",
)
assert 'otad_json_bool(validation, "validated", 0)' in verify
assert 'hot_payloads_verify(' in verify
assert 'hot_targets_verify_base(' in verify
assert 'hot_deletions_verify_base(' in verify
assert 'hot_space_gates_check(files, count, &gates, 0)' in verify
assert 'otad_space_gate_record(' not in verify
assert 'hot_release_trust_error(' in verify
assert '"validated", json_object_new_boolean(1)' in verify
assert '"ok", json_object_new_boolean(1)' not in verify
assert '"verified", json_object_new_boolean(1)' not in verify
header_failure = between(
    verify,
    "if (hot_header_read(",
    "validation = otad_check_manifest(",
)
assert "hot_release_trust_error(" in header_failure
assert '"diagnostic_error"' in header_failure

gate_fields = between(
    HOT,
    "static void hot_release_trust_fields(",
    "static struct json_object *hot_release_trust_error(",
)
for field in (
    '"verified"',
    '"integrity_verified"',
    '"authenticity_verified"',
    '"signature_required"',
    '"signature_verified"',
    '"target_compatible"',
    '"policy_passed"',
    '"safe_to_apply_now"',
    '"release_gate_reason"',
):
    assert field in gate_fields, f"hot-update trust gate must expose {field}"
assert '"hot_update_release_trust_gate_closed"' in gate_fields

apply = between(
    HOT,
    "struct json_object *otad_update_apply(",
    "\n}",
) + "\n}"
assert apply.index("update_magic_is_hot(path)") < apply.index(
    "hot_release_trust_error("
)
for forbidden in (
    "hot_verify_internal(",
    "otad_state_set(",
    "hot_stage_and_install(",
    "hot_schedule_restarts(",
    "rename(",
):
    assert forbidden not in apply, f"hot apply must fail before {forbidden}"

installer = between(
    HOT,
    "static int hot_stage_and_install(",
    "static int hot_run_restart(",
)
assert '"hot_update_release_trust_gate_closed"' in installer
assert installer.index('"hot_update_release_trust_gate_closed"') < installer.index("#if 0")

restarts = between(
    HOT,
    "static int hot_schedule_restarts(",
    "static int update_magic_is_hot(",
)
assert "(void)manifest;" in restarts
assert restarts.index("return -1;") < restarts.index("#if 0")

ubus_apply = between(
    UBUS,
    "static int otad_handle_apply(",
    "static int otad_handle_operation_status(",
)
assert "otad_update_apply(otad_payload_or_self(body))" in ubus_apply
assert 'UBUS_METHOD("apply", otad_handle_apply' in UBUS

assert '"apply_enabled", json_object_new_boolean(0)' in STATUS
assert '"hot_update_apply_enabled", json_object_new_boolean(0)' in STATUS
assert '"hot_update_apply_reason"' in STATUS
assert '"hot_update_release_trust_gate_closed"' in STATUS

print("ok: database/component hot updates diagnose read-only and fail closed before apply")

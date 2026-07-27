#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIRMWARE = (ROOT / "src/otad/otad_firmware.c").read_text(encoding="utf-8")
STATUS = (ROOT / "src/otad/otad_status.c").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    return text[first:text.index(end, first)]


gate = between(
    FIRMWARE,
    "static int otad_firmware_release_gate(",
    "static struct json_object *otad_firmware_release_gate_error",
)
for field in (
    '"verified"',
    '"safe_to_apply"',
    '"authenticity_verified"',
    '"signature_required"',
    '"signature_verified"',
    '"signature_status"',
    '"target_compatible"',
    '"policy_passed"',
    '"release_gate"',
    '"release_gate_reason"',
):
    assert field in gate, f"release gate must expose {field}"
assert gate.count('json_object_new_boolean(0)') >= 6
assert '"firmware_release_trust_gate_closed"' in gate
assert '"operation_trust_binding_and_ab_topology_pending"' in gate
assert 'return -1;' in gate

validate = between(
    FIRMWARE,
    "static int otad_firmware_validate_fd",
    "static struct json_object *otad_operation_status_by_id",
)
assert '"integrity_verified", json_object_new_boolean(1)' in validate
assert '"architecture_check_supported"' in validate
assert 'otad_release_trust_verify(fd, info->firmware_size, info->json' in validate
assert '"signature_verified", json_object_new_boolean(1)' in validate
assert '"target_compatible", json_object_new_boolean(1)' in validate
assert '"policy_passed", json_object_new_boolean(1)' in validate
assert 'otad_firmware_release_gate(resp, error, error_len)' in validate
assert validate.rstrip().endswith("return -1;\n}")
assert "blockers == 0 || allow_unpreserved" not in validate
assert 'snprintf(error, error_len, "inventory_blocked")' not in validate

preflight = between(
    FIRMWARE,
    "struct json_object *otad_firmware_preflight(",
    "struct json_object *otad_firmware_verify(",
)
assert preflight.index("otad_firmware_validate_fd(") < preflight.index(
    "otad_operation_commit_preflight(operation_id"
)
assert 'otad_operation_update(operation_id, "pending"' not in preflight

apply = between(
    FIRMWARE,
    "struct json_object *otad_firmware_apply(",
    "struct json_object *otad_confirm_boot(",
)
assert apply.index("otad_firmware_release_gate_error()") < apply.index(
    "otad_operation_claim_apply(operation_id)"
)
assert '"firmware_release_trust_gate_closed"' in apply

worker = between(
    FIRMWARE,
    "static int otad_firmware_apply_worker",
    "static struct uloop_process g_otad_operation_process",
)
worker_gate = worker.index("otad_firmware_release_gate(NULL, error, sizeof(error))")
for write_boundary in (
    "otad_staged_upload_open(",
    "otad_grubenv_prepare_target(",
    "open(target, O_WRONLY",
    "otad_gzip_rootfs_stream(",
    "otad_copy_range(upload.fd, info.rootfs.offset",
):
    assert worker_gate < worker.index(write_boundary), (
        f"worker release gate must precede {write_boundary}"
    )

assert '"full_firmware_validate_enabled", json_object_new_boolean(1)' in STATUS
assert '"full_firmware_apply_enabled", json_object_new_boolean(0)' in STATUS
assert '"slot_write_enabled", json_object_new_boolean(0)' in STATUS
assert '"hot_update_apply_enabled", json_object_new_boolean(0)' in STATUS
assert '"hot_update_apply_reason"' in STATUS
assert '"hot_update_release_trust_gate_closed"' in STATUS
assert 'otad_release_trust_status()' in STATUS
assert '"firmware_authenticity_verifier_ready"' in STATUS
assert '"firmware_target_matcher_ready"' in STATUS
assert '"firmware_release_trust"' in STATUS
assert '"release_trust_gate_closed"' in STATUS
assert '"rollback_enabled"' in STATUS
assert "rollback_ready" in STATUS
assert '"inactive_slot_not_bootable"' in STATUS
assert '"bootloader_slot_state_not_readonly_verified"' in STATUS
assert "otad_ab_boot_state_readonly_verify(&topology" in FIRMWARE
assert '"ab_topology_readonly_evidence_incomplete"' in STATUS

print("ok: full firmware apply is fail closed until release authenticity and target match are verified")

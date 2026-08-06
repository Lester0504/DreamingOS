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
    "struct json_object *otad_operation_status_by_id",
)
assert '"integrity_verified", json_object_new_boolean(1)' in validate
assert '"architecture_check_supported"' in validate
assert 'otad_release_trust_verify(fd, info->firmware_size, info->json' in validate
assert '"signature_verified", json_object_new_boolean(1)' in validate
assert '"target_compatible", json_object_new_boolean(1)' in validate
assert '"policy_passed", json_object_new_boolean(1)' in validate
# The gate is called as (resp, NULL, 0) on purpose. By the time it runs, `error`
# already holds the specific cause from otad_release_trust_verify() or
# otad_ab_topology_validate_release(); passing it in would overwrite that with the
# generic "firmware_release_trust_gate_closed" and lose the real reason. The
# closed state still reaches the caller through the resp fields the gate sets.
assert 'otad_firmware_release_gate(resp, NULL, 0)' in validate
assert validate.count('otad_firmware_release_gate(resp, NULL, 0)') >= 2
# The region used to end on "return -1;" because validation could not succeed at
# all. It now ends on "return 0;" after a blockers check, so pin the property that
# actually matters: preflight blockers still fail the validation rather than being
# reported and waved through.
assert validate.rstrip().endswith("return 0;\n}")
assert 'if (blockers) {' in validate
assert 'snprintf(error, error_len, "preflight_blockers_present")' in validate
assert validate.index('if (blockers) {') < validate.rindex('return -1;'), \
    "blockers must still lead to a failure return"
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
# The worker no longer calls otad_firmware_release_gate(). It now performs the
# check inline against the preflight record and then re-verifies the staged bytes
# with otad_operation_reverify_trust_binding(), which is strictly stronger: it
# re-runs ed25519 against the actual file instead of trusting what was stored.
# The gate that must precede every write boundary is that inline check.
assert 'if (!work->authenticity_verified || !work->target_compatible ||' in worker
assert '!work->signing_key_id[0] || work->trust_policy_version < 1) {' in worker
assert 'snprintf(error, sizeof(error), "firmware_release_trust_gate_closed");' in worker
worker_gate = worker.index("if (!work->authenticity_verified || !work->target_compatible ||")
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

# The staged bytes must be re-verified before any write, and the size/sha
# comparison must sit between opening the upload and that re-verification, so a
# file swapped after preflight cannot slip through.
reverify = worker.index("otad_operation_reverify_trust_binding(upload.fd, upload.size, work")
staging_open = worker.index("otad_staged_upload_open(")
staging_size = worker.index("upload.size != work->source_size")
assert staging_open < staging_size < reverify, "size/sha check must precede re-verification"
assert 'snprintf(error, sizeof(error), "staging_source_changed_after_preflight");' in worker
for write_boundary in (
    "otad_grubenv_prepare_target(",
    "open(target, O_WRONLY",
    "otad_gzip_rootfs_stream(",
    "otad_copy_range(upload.fd, info.rootfs.offset",
):
    assert reverify < worker.index(write_boundary), (
        f"staged-bytes re-verification must precede {write_boundary}"
    )

assert '"full_firmware_validate_enabled", json_object_new_boolean(1)' in STATUS
# These three used to be hardcoded to 0 while the apply path was unimplemented.
# They are now derived from real trust/topology/rollback state, so asserting a
# literal 0 would demand the old fail-closed-always behaviour back. What still
# has to hold is that each one is *derived* rather than unconditionally true:
# slot writes require trust AND topology AND rollback; hot update needs trust
# only, because it replaces files in place without touching A/B or the bootloader.
assert 'int slot_write_ready = trust_ready && topology_supported && rollback_ready;' in STATUS
for gate in ('"apply_enabled"', '"full_firmware_apply_enabled"', '"slot_write_enabled"'):
    assert f'{gate},\n                               json_object_new_boolean(slot_write_ready))' in STATUS, \
        f"{gate} must follow slot_write_ready, not be unconditional"
assert '"hot_update_apply_enabled",\n                               json_object_new_boolean(trust_ready))' in STATUS
# No gate may be opened unconditionally.
for gate in ('"full_firmware_apply_enabled"', '"slot_write_enabled"', '"hot_update_apply_enabled"'):
    assert f'{gate}, json_object_new_boolean(1)' not in STATUS, \
        f"{gate} must never be hardcoded open"
assert '"hot_update_apply_reason"' in STATUS
# The reason string is now produced from the live trust reason rather than a
# fixed literal, so assert the mechanism instead of the old constant.
assert 'otad_json_str(trust, "reason"' in STATUS
assert 'otad_release_trust_status()' in STATUS
assert '"firmware_authenticity_verifier_ready"' in STATUS
assert '"firmware_target_matcher_ready"' in STATUS
assert '"firmware_release_trust"' in STATUS
assert '"rollback_enabled"' in STATUS
assert "rollback_ready" in STATUS
assert '"inactive_slot_not_bootable"' in STATUS
assert '"bootloader_slot_state_not_readonly_verified"' in STATUS
assert "otad_ab_boot_state_readonly_verify(&topology" in FIRMWARE
assert '"ab_topology_readonly_evidence_incomplete"' in STATUS

print("ok: full firmware apply is fail closed until release authenticity and target match are verified")

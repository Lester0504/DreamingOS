#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMMON = (ROOT / "src/otad/otad_common.c").read_text(encoding="utf-8")
FIRMWARE = (ROOT / "src/otad/otad_firmware.c").read_text(encoding="utf-8")
HOT = (ROOT / "src/otad/otad_hot.c").read_text(encoding="utf-8")
STATUS = (ROOT / "src/otad/otad_status.c").read_text(encoding="utf-8")
DB = (ROOT / "src/otad/otad_db.c").read_text(encoding="utf-8")
HEADER = (ROOT / "src/otad/otad_internal.h").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    last = text.index(end, first)
    return text[first:last]


for field in (
    '"error"',
    '"reason"',
    '"required_bytes"',
    '"available_bytes"',
    '"path"',
    '"retryable"',
    '"required_inodes"',
    '"available_inodes"',
    '"safety_margin_percent"',
    '"safety_margin_min_bytes"',
    '"capacity_kind"',
):
    assert field in COMMON, f"space gate JSON must expose {field}"

assert "statvfs(" in COMMON
assert "f_bavail" in COMMON
assert "f_favail" in COMMON
assert "OTAD_SPACE_SAFETY_MIN_BYTES" in HEADER
assert "OTAD_SPACE_SAFETY_PERCENT" in HEADER
assert "OTAD_SPACE_SAFETY_INODES" in HEADER
assert "artifact_bytes, gate->safety_margin_bytes" in COMMON
assert '"insufficient_space"' in COMMON
assert '"insufficient_inodes"' in COMMON
assert '"statvfs_failed"' in COMMON

validate = between(
    FIRMWARE,
    "static int otad_firmware_validate_fd",
    "static struct json_object *otad_operation_status_by_id",
)
assert validate.index("otad_ab_topology_discover(") < validate.index(
    "otad_inactive_capacity_gate("
), "space gate must run only after real A/B discovery"
assert validate.index("otad_inactive_capacity_gate(") < validate.index(
    "otad_gzip_rootfs_stream("
), "verify must gate before gzip expansion"
assert "otad_block_capacity_gate_check(" in FIRMWARE
assert '"block_device"' in COMMON
assert '"filesystem"' in COMMON
assert "statvfs(" not in between(
    FIRMWARE,
    "static int otad_inactive_capacity_gate",
    "static void otad_current_release_version",
), "full firmware replaces the slot image and must not inspect old filesystem free space"

apply_worker = between(
    FIRMWARE,
    "static int otad_firmware_apply_worker",
    "static struct uloop_process g_otad_operation_process",
)
assert apply_worker.index("otad_firmware_validate_fd(") < apply_worker.index(
    "otad_grubenv_prepare_target("
)
assert apply_worker.index("otad_firmware_validate_fd(") < apply_worker.index(
    "otad_gzip_rootfs_stream("
)
assert apply_worker.index("otad_firmware_validate_fd(") < apply_worker.index(
    "otad_copy_range(upload.fd, info.rootfs.offset"
)
assert '"ab_layout_unsupported"' in FIRMWARE
assert "otad_ab_topology_discover(&topology" in FIRMWARE
assert "char target_slot[2]" in HEADER
assert 'source_sha256,target_slot,"' in DB
assert 'manifest_digest,signing_key_id,trust_policy_version,trust_policy_digest,device_identity_digest' in DB
assert "work->target_slot" in DB

hot_transaction = between(
    HOT,
    "static int hot_stage_and_install",
    "static int hot_run_restart",
)
assert hot_transaction.index("hot_space_gates_check(") < hot_transaction.index(
    "hot_copy_payload("
), "hot apply must recheck before creating staging files"
assert "gate->artifact_bytes + files[i].size" in HOT
assert "hot_target_required_inodes" in HOT
assert '"space_gates"' in HOT

assert 'otad_state_set("space_gate"' in COMMON
assert 'otad_state_get("space_gate"' in STATUS
assert 'json_object_object_add(resp, "space_gate", gate)' in STATUS
assert "otad_json_bool(slot_status, \"topology_readonly_verified\", 0)" in STATUS
assert "otad_ab_topology_discover(&topology" in FIRMWARE
assert 'json_object_object_add(o, "probes", probes)' in FIRMWARE
assert '"sysfs_blkid_mountinfo_cmdline_and_readonly_grub_state"' in FIRMWARE

print("ok: otad low-space gate contract and write ordering")

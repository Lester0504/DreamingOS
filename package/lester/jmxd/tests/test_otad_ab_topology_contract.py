#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOPOLOGY = (ROOT / "src/otad/otad_topology.c").read_text(encoding="utf-8")
FIRMWARE = (ROOT / "src/otad/otad_firmware.c").read_text(encoding="utf-8")
DB = (ROOT / "src/otad/otad_db.c").read_text(encoding="utf-8")
HEADER = (ROOT / "src/otad/otad_internal.h").read_text(encoding="utf-8")
MAKEFILE = (ROOT / "src/Makefile").read_text(encoding="utf-8")
PACKAGE = (ROOT / "Makefile").read_text(encoding="utf-8")
PROBE = (ROOT / "tests/test_otad_ab_topology_readonly_probe.c").read_text(
    encoding="utf-8"
)


for token in (
    'OTAD_TOPOLOGY_SYS_BLOCK_DIR "/sys/class/block"',
    '"PARTNAME"',
    '"PARTUUID"',
    'OTAD_TOPOLOGY_PARTUUID_DIR "/dev/disk/by-partuuid"',
    'blkid_get_tag_value(NULL, "PARTUUID", path)',
    'blkid_get_tag_value(NULL, "TYPE", path)',
    'OTAD_TOPOLOGY_MOUNTINFO_PATH "/proc/self/mountinfo"',
    '"cmdline_evidence_unavailable"',
    '"cmdline_evidence_truncated"',
    '"cmdline_slot_missing_or_ambiguous"',
    '"cmdline_root_partuuid_missing_or_ambiguous"',
    '"ab_partlabel_missing_or_ambiguous"',
    '"ab_partition_devices_not_distinct"',
    '"ab_partuuid_missing_or_ambiguous"',
    '"ab_partitions_not_on_same_parent_disk"',
    '"ab_partition_filesystems_invalid"',
    '"root_device_is_not_dreamingwrt_slot"',
    '"root_mount_topology_ambiguous"',
    '"current_slot_block_filesystem_mismatch"',
    '"cmdline_slot_root_device_mismatch"',
    '"inactive_slot_is_mounted"',
    '"data_mount_source_mismatch"',
    '"data_mount_missing_or_ambiguous"',
    '"bootloader_readonly_mount_failed"',
    '"bootloader_state_files_unavailable"',
    '"bootloader_grubenv_invalid"',
    '"bootloader_pending_active_slot_conflict"',
    '"bootloader_slot_entry_mismatch"',
    '"bootloader_blank_slot_marked_valid"',
    '"bootloader_readonly_unmount_failed"',
    '"inactive_slot_readonly_unmount_failed"',
    '"signed_ab_layout_incompatible"',
    '"signed_ab_layout_capacity_mismatch"',
    'EVP_Digest(text, strlen(text)',
):
    assert token in TOPOLOGY, token

assert 'a.size != b.size' in TOPOLOGY
assert 'strcmp(mounts.root_fstype, "ext4")' in TOPOLOGY
assert 'strcmp(mounts.data_fstype, "ext4")' in TOPOLOGY
assert 'mounts.root_count != 1' in TOPOLOGY
assert 'mounts.data_count != 1' in TOPOLOGY
assert 'strcasecmp(cmdline.root_partuuid, current_partuuid)' in TOPOLOGY
assert 'MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME' in TOPOLOGY
assert '#include <sys/sysmacros.h>' in TOPOLOGY
assert 'topology_devno_bind(major_text, minor_text, match.rdev' in TOPOLOGY
assert 'OTAD_TOPOLOGY_MAJOR(rdev)' in TOPOLOGY
assert 'OTAD_TOPOLOGY_MINOR(rdev)' in TOPOLOGY
assert 'OTAD_TOPOLOGY_GRUBENV_HEADER "# GRUB Environment Block\\n"' in TOPOLOGY
assert 'strlen(text) != OTAD_TOPOLOGY_GRUBENV_SIZE' in TOPOLOGY
assert 'topology_uint_value(tries, 3, &topology->boot_tries_left)' in TOPOLOGY
assert 'topology_grubcfg_entries(' in TOPOLOGY
assert '!strncmp(trimmed, "menuentry", 9)' in TOPOLOGY
assert 'topology_grub_linux_line(trimmed' in TOPOLOGY
assert 'topology_inactive_kernel_verify(' in TOPOLOGY
assert 'openat(boot_fd, "vmlinuz"' in TOPOLOGY
assert '!S_ISREG(st.st_mode) || st.st_size <= 0' in TOPOLOGY
assert 'topology->inactive_slot_bootable_verified = verified' in TOPOLOGY
assert 'topology->inactive_slot_bootable_verified =\n        topology->inactive_slot' not in TOPOLOGY
assert 'OTAD_TOPOLOGY_BOOT_MOUNT_OPTIONS' in TOPOLOGY
assert '"uid=0,gid=0,fmask=0077,dmask=0077"' in TOPOLOGY
assert 'OTAD_TOPOLOGY_UMOUNT(mount_dir, MNT_DETACH)' in TOPOLOGY
assert 'O_RDONLY | O_CLOEXEC | O_NOFOLLOW' in TOPOLOGY
assert 'topology_open_boot_file(root_fd, "grubenv"' in TOPOLOGY
assert 'topology_open_boot_file(root_fd, "grub.cfg"' in TOPOLOGY
assert 'topology_boot_state_load(topology, &mounts' in TOPOLOGY
assert '"uninitialized_blank"' in TOPOLOGY
assert '"inactive_slot_state"' in TOPOLOGY
for evidence in (
    '"root_mount_verified"',
    '"cmdline_slot_verified"',
    '"cmdline_root_partuuid_verified"',
    '"data_mount_verified"',
    '"inactive_unmounted_verified"',
    '"boot_state_verified"',
    '"inactive_slot_bootable_verified"',
):
    assert evidence in TOPOLOGY, evidence
assert 'OTAD_AB_LAYOUT_SCHEMA "gpt-bios-esp-root_a-root_b-data-v1"' in HEADER
assert "OTAD_BOOT_SCHEMA_VERSION 2" in HEADER
assert "identity->boot_schema = OTAD_BOOT_SCHEMA_VERSION" in (
    ROOT / "src/otad/otad_trust.c"
).read_text(encoding="utf-8")
assert "otad/otad_topology.o" in MAKEFILE
assert "+libblkid" in PACKAGE
otad_libs = PACKAGE.split("JMXD_OTAD_LIBS :=", 1)[1].split("JMXD_AEGISXD_LIBS :=", 1)[0]
assert "-lblkid" in otad_libs

assert "topology_digest TEXT NOT NULL DEFAULT ''" in DB
assert "topology_digest<>''" in DB
assert "length(topology_digest)=64" in DB
assert "work->topology_digest" in DB
assert "otad_ab_topology_discover(&topology" in FIRMWARE
assert "otad_ab_topology_validate_release(&topology" in FIRMWARE
assert "strcasecmp(topology.topology_digest, work->topology_digest)" in FIRMWARE

for function in (
    "struct json_object *otad_confirm_boot(",
    "void otad_reconcile_boot_state(",
    "struct json_object *otad_firmware_rollback(",
    "struct json_object *otad_slot_status_json(",
    "void otad_confirm_timer_start(",
):
    start = FIRMWARE.index(function)
    body = FIRMWARE[start:start + 6000]
    assert "otad_ab_topology_discover(" in body, function

assert "otad_current_slot(" not in FIRMWARE
assert "otad_slots_supported(" not in FIRMWARE
assert "otad_mountpoint_is_data(" not in FIRMWARE
assert "/dev/disk/by-partlabel" not in FIRMWARE
assert '"topology_readonly_verified"' in FIRMWARE
assert '"configuration_values_trusted"' in FIRMWARE
assert '"inactive_slot_write_target_verified"' in FIRMWARE
assert '"inactive_slot_bootable_verified"' in FIRMWARE
assert '"boot_state_readonly_verified"' in FIRMWARE
assert '"boot_state_reason"' in FIRMWARE
assert "otad_topology_missing_evidence(missing, topology_error)" in FIRMWARE
assert 'char current[2] = "";' in FIRMWARE
STATUS = (ROOT / "src/otad/otad_status.c").read_text(encoding="utf-8")
assert 'otad_json_bool(slot_status, "inactive_slot_bootable_verified", 0)' in STATUS
assert '"bootloader_slot_state_not_readonly_verified"' in STATUS
assert '"ab_topology_readonly_evidence_incomplete"' in STATUS
assert "int otad_ab_boot_state_readonly_verify(" in TOPOLOGY
assert "int otad_ab_topology_readonly_probe(" in TOPOLOGY
assert "return topology_discover(topology, 0, error, error_len);" in TOPOLOGY
assert "return topology_discover(topology, 1, error, error_len);" in TOPOLOGY
rollback_start = FIRMWARE.index("struct json_object *otad_firmware_rollback(")
rollback = FIRMWARE[rollback_start:FIRMWARE.index(
    "struct json_object *otad_slot_status_json(", rollback_start
)]
assert "otad_ab_boot_state_readonly_verify(&topology" in rollback
assert '"inactive_slot_not_bootable"' in rollback
inactive_bootable_gate = rollback.index("!topology.inactive_slot_bootable_verified")
assert rollback.index("otad_ab_boot_state_readonly_verify(&topology") < inactive_bootable_gate
assert "topology.boot_active_slot" in rollback
assert "topology.boot_pending_slot" in rollback
assert 'otad_state_get("active_slot"' not in rollback
assert 'otad_state_get("pending_slot"' not in rollback
for mutation in (
    "otad_grubenv_clear_target(",
    "otad_grubenv_set_boot_selection(",
    "otad_state_set_slot_valid(",
    "otad_config_prepare(",
    "otad_operation_update(",
    'otad_state_set("pending_slot"',
):
    assert inactive_bootable_gate < rollback.index(mutation), mutation
assert '"/sys/class/block"' in PROBE
assert '"/proc/self/mountinfo"' in PROBE
assert '"/proc/cmdline"' in PROBE
assert '"blkid:PARTUUID,TYPE"' in PROBE
assert '"topology_readonly_verified"' in PROBE
assert '"boot_state_readonly_verified"' in PROBE
assert '"inactive_slot_bootable_verified"' in PROBE
assert '"DWRT_BOOT:boot/grub/grubenv,grub.cfg"' in PROBE
for forbidden in ("O_WRONLY", "O_RDWR", "BLKDISCARD", "grub-editenv", "reboot"):
    assert forbidden not in PROBE, forbidden

print("ok: OTA A/B topology binds unique block, mount, cmdline root/slot, signed layout and worker digest evidence")

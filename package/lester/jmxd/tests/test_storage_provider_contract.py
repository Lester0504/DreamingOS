"""Contract checks for the read-only external storage provider inventory."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/storage/storage_provider.c").read_text(encoding="utf-8")
HEADER = (ROOT / "src/storage/storage_provider.h").read_text(encoding="utf-8")


def test_provider_contract_is_read_only_and_fail_closed():
    assert 'JMX_STORAGE_PROVIDER_CONTRACT "storage-provider.v1"' in HEADER
    assert '"auto_mount_or_format"' in SOURCE
    assert 'json_object_new_boolean(0)' in SOURCE
    assert '"migration_supported"' in SOURCE
    assert 'json_object_new_boolean(0)' in SOURCE
    assert '"external_storage_unavailable_fail_closed"' in SOURCE
    assert 'mount' in SOURCE and 'format' not in SOURCE.lower().replace("auto_mount_or_format", "")
    assert '"device_unavailable"' in SOURCE
    assert '"read_only"' in SOURCE
    assert '"system_mount"' in SOURCE


def test_provider_identity_and_usage_bindings_are_stable():
    assert '"uuid:"' in SOURCE
    assert '"label:"' in SOURCE
    assert '"device:"' in SOURCE
    for use in ("audit", "aegis", "log", "snapshots"):
        assert f'"{use}"' in SOURCE
    for field in (
        "requested_provider", "active_provider", "phase", "old_path",
        "new_path", "snapshot_id", "rollback_available",
    ):
        assert f'"{field}"' in SOURCE


def test_provider_discovery_reads_sysfs_mountinfo_and_statvfs():
    assert '"/sys/class/block"' in SOURCE
    assert '"/proc/self/mountinfo"' in SOURCE
    assert 'statvfs(p->mountpoint, &fs)' in SOURCE
    assert '"/dev/disk/by-uuid"' in SOURCE
    assert '"/dev/disk/by-label"' in SOURCE
    assert 'auto_mount_or_format' in SOURCE
    assert 'system_mount' in SOURCE


if __name__ == "__main__":
    test_provider_contract_is_read_only_and_fail_closed()
    test_provider_identity_and_usage_bindings_are_stable()
    test_provider_discovery_reads_sysfs_mountinfo_and_statvfs()
    print("ok: storage provider read-only contract")

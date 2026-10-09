"""Linux sysfs fixtures, no block devices, mounts, or source-tree writes."""
import os
from pathlib import Path
import platform
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(platform.system() != "Linux", reason="Linux sysfs policy")


@pytest.fixture
def policy(tmp_path):
    binary = tmp_path / "policy"
    sysfs, mountinfo = tmp_path / "sys", tmp_path / "mountinfo"
    staging = os.environ.get("DWRT_TEST_STAGING")
    uci_prefix = os.environ.get("DWRT_TEST_UCI_PREFIX")
    includes = ["-idirafter", staging + "/usr/include"] if staging else []
    libraries = ([f"-L{uci_prefix}/lib", f"-Wl,--disable-new-dtags,-rpath,{uci_prefix}/lib"]
                 if uci_prefix else []) + ["-luci", "-lubox"]
    subprocess.run([
        os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra",
        "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
        f'-DSTORAGE_POLICY_SYSFS="{sysfs}"',
        f'-DSTORAGE_POLICY_MOUNTINFO="{mountinfo}"',
        f'-DSTORAGE_POLICY_UCI_CONFIG_DIR="{tmp_path}"',
        *includes, str(ROOT / "tests/device_storage_policy_harness.c"),
        str(ROOT / "src/dwrt_features.c"),
        *libraries, "-o", str(binary)], check=True, text=True)
    return binary, sysfs, mountinfo


def invoke(policy, *args):
    return subprocess.check_output([str(policy[0]), *map(str, args)], text=True).splitlines()


def node(policy, relative, name, dev):
    sysfs = policy[1]
    real = sysfs / "devices" / relative / name
    real.mkdir(parents=True)
    for link in (sysfs / "class/block" / name, sysfs / "dev/block" / dev):
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(real)
    return real


def partition(policy, disk, name, dev):
    sysfs = policy[1]
    real = disk / name
    real.mkdir()
    (real / "partition").write_text("1\n")
    for link in (sysfs / "class/block" / name, sysfs / "dev/block" / dev):
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(real)
    return real


def test_partition_and_virtual_slaves_trace_physical_disk(policy):
    nvme = node(policy, "pci/nvme/nvme0", "nvme0n1", "259:0")
    part = partition(policy, nvme, "nvme0n1p1", "259:1")
    dm = node(policy, "virtual/block", "dm-0", "253:0")
    (dm / "slaves").mkdir()
    (dm / "slaves/nvme0n1p1").symlink_to(part)
    assert invoke(policy, "trace", dm) == ["0", "nvme0n1"]
    policy[2].write_text("1 0 253:0 / / rw - ext4 /dev/dm-0 rw\n")
    assert invoke(policy, "system") == ["0", "nvme0n1"]


def test_unknown_fit_backend_rejects_system_identification(policy):
    node(policy, "virtual/block", "fit0", "259:0")
    policy[2].write_text("1 0 259:0 / / rw - squashfs /dev/fit0 ro\n")
    assert invoke(policy, "system")[0] == "-1"


def test_openwrt_fit_platform_traces_lower_dev_and_fails_if_missing(policy):
    mmc = node(policy, "platform/mmc", "mmcblk0", "179:0")
    part = partition(policy, mmc, "mmcblk0p5", "179:5")
    node(policy, "platform/fitblk/fit0/block", "fit0", "259:1")
    policy[2].write_text("1 0 259:1 / /rom ro - squashfs /dev/root ro\n")
    assert invoke(policy, "system")[0] == "-1"
    lower = policy[1] / "devices/platform/fitblk/lower_dev"
    lower.symlink_to(part)
    assert invoke(policy, "system") == ["0", "mmcblk0"]


def test_root_overlay_and_boot_are_all_dependencies(policy):
    for relative, name, dev in [
        ("pci/nvme/nvme0", "nvme0n1", "259:0"),
        ("platform/mmc", "mmcblk0", "179:0"),
        ("pci/ata1/host0", "sda", "8:0"),
    ]:
        node(policy, relative, name, dev)
    policy[2].write_text(
        "1 0 259:0 / / rw - ext4 /dev/nvme0n1 rw\n"
        "2 0 179:0 / /overlay rw - ext4 /dev/mmcblk0 rw\n"
        "3 0 8:0 / /boot rw - vfat /dev/sda rw\n")
    assert set(invoke(policy, "system")[1:]) == {"nvme0n1", "mmcblk0", "sda"}


@pytest.mark.parametrize("card,expected", [("MMC", "emmc"), ("SD", "sd"), ("??", "unknown")])
def test_mmc_identity_comes_from_card_type_not_device_number(policy, card, expected):
    disk = node(policy, "platform/mmc", "mmcblk1", "179:8")
    (disk / "device").mkdir()
    (disk / "device/type").write_text(card + "\n")
    assert invoke(policy, "media", "mmcblk1")[0] == expected


@pytest.mark.parametrize("rotational,expected", [("1", "disk"), ("0", "usb")])
def test_usb_bridge_without_ssd_identity_is_reported_conservatively(policy, rotational, expected):
    disk = node(policy, "pci/usb1/host0", "sda", "8:0")
    (disk / "queue").mkdir()
    (disk / "queue/rotational").write_text(rotational + "\n")
    result = invoke(policy, "media", "sda")
    assert result[0] == expected
    if expected == "usb":
        assert result[1] == "usb_ssd_or_flash_unresolved_classified_usb"


def test_priority_uses_whole_media_tokens(policy):
    assert invoke(policy, "rank", "nvme,disk,usb,sd,emmc,system", "nvme") == ["0"]
    assert invoke(policy, "rank", "nvme,disk,usb,sd,emmc,system", "sd") == ["3"]
    assert invoke(policy, "rank", "nvme,usb,system", "disk") == ["99"]


@pytest.mark.parametrize("enabled,data,reason", [
    ("0", "1", "fstab_disabled"),
    ("1", "0", "data_partition_not_authorized"),
    ("1", "1", "eligible"),
])
def test_fstab_requires_enabled_and_separate_data_authorization(policy, enabled, data, reason):
    (policy[1].parent / "fstab").write_text(
        "config mount\n option uuid 'disk-test'\n option target '/mnt/data'\n"
        f" option enabled '{enabled}'\n option dreamingos_data '{data}'\n")
    result = invoke(policy, "authorized", "disk-test")
    assert result[0] == ("1" if reason == "eligible" else "0")
    assert result[1] == reason
    assert invoke(policy, "authorized", "other-disk")[:2] == [
        "0", "data_partition_not_authorized"]


def test_duplicate_fstab_uuid_cannot_authorize_a_disk(policy):
    entry = ("config mount\n option uuid 'duplicate'\n option target '/mnt/data'\n"
             " option enabled '1'\n option dreamingos_data '1'\n")
    (policy[1].parent / "fstab").write_text(entry + entry)
    assert invoke(policy, "authorized", "duplicate")[:2] == ["0", "duplicate_fstab_uuid"]


def test_mount_never_hides_existing_directory_content(policy):
    target = policy[1].parent / "mountpoint"
    assert invoke(policy, "mountpoint", target) == ["1"]
    marker = target / "existing.db"
    marker.write_text("keep")
    assert invoke(policy, "mountpoint", target) == ["0"]
    assert marker.read_text() == "keep"

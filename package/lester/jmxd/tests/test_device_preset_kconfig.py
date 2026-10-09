"""Resolve real OpenWrt package dependencies without changing the active config."""
import importlib.util
import os
from pathlib import Path
import re
import subprocess

import pytest

PACKAGE = Path(__file__).resolve().parents[1]
OPENWRT = os.environ.get("DWRT_TEST_OPENWRT")
pytestmark = pytest.mark.skipif(not OPENWRT, reason="requires an existing OpenWrt tree")
spec = importlib.util.spec_from_file_location(
    "preset_generator", PACKAGE / "tools/generate-device-preset.py")
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)

TARGETS = {
    "w1700k": (
        "CONFIG_TARGET_airoha=y",
        "CONFIG_TARGET_airoha_an7581=y",
        "CONFIG_TARGET_airoha_an7581_DEVICE_gemtek_w1700k-ubi=y",
    ),
    "bpi-r4": (
        "CONFIG_TARGET_mediatek=y",
        "CONFIG_TARGET_mediatek_filogic=y",
        "CONFIG_TARGET_mediatek_filogic_DEVICE_bananapi_bpi-r4=y",
    ),
}
STORAGE_PACKAGES = ("block-mount", "kmod-fs-ext4", "kmod-nvme",
                    "kmod-usb-storage", "kmod-mmc")


@pytest.mark.parametrize("target", ["w1700k", "bpi-r4"])
def test_core_selects_nfqueue_runtime(kconfig, target):
    lines, _ = resolve(kconfig, target + "-nfqueue", target, [])
    for package in ("libnetfilter-queue", "kmod-nft-queue", "kmod-nfnetlink-queue"):
        assert "CONFIG_PACKAGE_" + package + "=y" in lines


@pytest.fixture(scope="module")
def kconfig(tmp_path_factory):
    root = Path(OPENWRT).resolve()
    out = tmp_path_factory.mktemp("device-preset-kconfig")
    active = root / ".config"
    before = active.read_bytes()
    try:
        # Refresh only this package's metadata, using the native dump/parser.
        # All outputs, including conf's config files, remain outside the tree.
        dump = subprocess.run([
            "make", "--no-print-directory", "-s", "-C", str(PACKAGE),
            "DUMP=1", f"TOPDIR={root}", "SOURCE=package/lester/jmxd",
            f"TMP_DIR={out}", f"TMPDIR={out}", "dumpinfo",
        ], check=True, text=True, capture_output=True)
        (out / "dump.log").write_text(dump.stderr)
        block = "Source-Makefile: package/lester/jmxd/Makefile\n" + dump.stdout
        metadata, count = re.subn(
            r"(?ms)^Source-Makefile: package/lester/jmxd/Makefile\n.*?"
            r"(?=^Source-Makefile:|\Z)",
            lambda _: block + "\n", (root / "tmp/.packageinfo").read_text())
        assert count == 1, "expected exactly one jmxd source record"
        info = out / ".packageinfo"
        info.write_text(metadata)
        package_config = out / "packages.in"
        with package_config.open("w") as result, (out / "metadata.log").open("w") as log:
            subprocess.run([
                "perl", str(root / "scripts/package-metadata.pl"), "config", str(info),
            ], cwd=root, stdout=result, stderr=log, check=True)
        wrapper = out / "Config.in"
        main = (root / "Config.in").read_text()
        original = 'source "tmp/.config-package.in"'
        assert main.count(original) == 1
        wrapper.write_text(main.replace(original, f'source "{package_config}"'))
        yield root, out, wrapper
    finally:
        assert active.read_bytes() == before, "active .config changed"


def resolve(kconfig, name, target, options):
    root, out, wrapper = kconfig
    seed, result = out / (name + ".seed"), out / (name + ".config")
    seed.write_text("\n".join([
        *TARGETS[target], "CONFIG_PACKAGE_dreamingwrt-init=y",
        "CONFIG_PACKAGE_dreamingwrt-core=y", *options, "",
    ]))
    env = dict(os.environ, KCONFIG_CONFIG=str(result),
               KCONFIG_AUTOCONFIG=str(out / "auto.conf"),
               KCONFIG_AUTOHEADER=str(out / "autoconf.h"))
    with (out / (name + ".log")).open("w") as log:
        subprocess.run([
            str(root / "scripts/config/conf"), "--defconfig=" + str(seed), str(wrapper),
        ], cwd=root, env=env, stdout=log, stderr=log, check=True)
    lines = set(result.read_text().splitlines())
    for required in (*TARGETS[target], "CONFIG_PACKAGE_dreamingwrt-init=y",
                     "CONFIG_PACKAGE_dreamingwrt-core=y"):
        assert required in lines, (name, required)
    features = generator.generate(generator.parse_config(result.read_text()))
    (out / (name + ".features")).write_text(features)
    return lines, features


@pytest.mark.parametrize("role", ["INHERIT", "GATEWAY", "AP"])
def test_w1700k_role_keeps_ap_agent_in_image_only_when_requested(kconfig, role):
    lines, features = resolve(kconfig, "w1700k-" + role.lower(), "w1700k", [
        "CONFIG_DREAMINGOS_DEVICE_ROLE_" + role + "=y",
        "CONFIG_PACKAGE_dreamingwrt-apd=m",
    ])
    assert "CONFIG_DREAMINGOS_DEVICE_ROLE_" + role + "=y" in lines
    if role == "AP":
        assert "CONFIG_PACKAGE_dreamingwrt-apd=y" in lines
        assert "Work_mode: ap\n" in features
    else:
        assert "CONFIG_PACKAGE_dreamingwrt-apd=m" in lines
        assert "Work_mode: ap\n" not in features
    assert "Data_storage: legacy\n" in features


@pytest.mark.parametrize("automount", [False, True])
def test_bpi_r4_auto_storage_dependencies_are_builtin(kconfig, automount):
    lines, features = resolve(kconfig, "bpi-r4-auto-" + str(int(automount)), "bpi-r4", [
        "CONFIG_DREAMINGOS_DEVICE_ROLE_GATEWAY=y",
        "CONFIG_DREAMINGOS_DATA_STORAGE_AUTO=y",
        "CONFIG_DREAMINGOS_STORAGE_AUTOMOUNT=" + ("y" if automount else "n"),
        'CONFIG_DREAMINGOS_STORAGE_PRIORITY="usb,nvme,disk,sd,emmc,system"',
        *("CONFIG_PACKAGE_" + name + "=m" for name in STORAGE_PACKAGES),
    ])
    for name in STORAGE_PACKAGES:
        assert "CONFIG_PACKAGE_" + name + "=y" in lines, name
    assert "Data_storage: auto\n" in features
    assert "Storage_automount: " + str(int(automount)) + "\n" in features
    assert "Storage_priority: usb,nvme,disk,sd,emmc,system\n" in features


def test_disabled_storage_does_not_pull_optional_mount_tools(kconfig):
    lines, features = resolve(kconfig, "bpi-r4-legacy", "bpi-r4", [
        "CONFIG_DREAMINGOS_DATA_STORAGE_AUTO=n",
        "CONFIG_PACKAGE_block-mount=m",
    ])
    assert "CONFIG_PACKAGE_block-mount=m" in lines
    assert "Data_storage: legacy\n" in features

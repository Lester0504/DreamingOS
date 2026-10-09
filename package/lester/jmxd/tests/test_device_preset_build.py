"""Factory profile generation and config-only incremental changes."""
import importlib.util
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/generate-device-preset.py"
spec = importlib.util.spec_from_file_location("device_preset", SCRIPT)
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)


def output(config):
    return generator.generate(generator.parse_config(config))


def test_default_is_legacy_and_does_not_write_a_role():
    result = output("")
    assert "Work_mode:" not in result
    assert "Data_storage: legacy" in result
    assert "Storage_automount: 0" in result
    assert "Enabled:" not in result


@pytest.mark.parametrize("role,expected", [("AP", "ap"), ("GATEWAY", "gateway")])
def test_roles(role, expected):
    assert f"Work_mode: {expected}\n" in output(f"CONFIG_DREAMINGOS_DEVICE_ROLE_{role}=y")


@pytest.mark.parametrize("config", [
    "CONFIG_DREAMINGOS_DEVICE_ROLE_AP=y\nCONFIG_DREAMINGOS_DEVICE_ROLE_GATEWAY=y",
    "CONFIG_DREAMINGOS_DEVICE_ROLE_AP=m",
    "CONFIG_DREAMINGOS_DEVICE_ROLE_AP=y\nCONFIG_DREAMINGOS_DEVICE_ROLE_AP=n",
    "CONFIG_DREAMINGOS_STORAGE_AUTOMOUNT=y",
    'CONFIG_DREAMINGOS_STORAGE_PRIORITY=""',
    'CONFIG_DREAMINGOS_STORAGE_PRIORITY="nvme,nvme,system"',
    'CONFIG_DREAMINGOS_STORAGE_PRIORITY="system,nvme"',
    'CONFIG_DREAMINGOS_STORAGE_PRIORITY="nvme"',
    'CONFIG_DREAMINGOS_STORAGE_PRIORITY="bogus,system"',
    'CONFIG_DREAMINGOS_STORAGE_PRIORITY="$(touch /tmp/not-executed),system"',
    "CONFIG_DREAMINGOS_STORAGE_PRIORITY=123",
])
def test_invalid_config_rejected(config):
    with pytest.raises(ValueError):
        output(config)


def test_config_only_rebuild_does_not_retain_prior_values(tmp_path):
    config, target = tmp_path / ".config", tmp_path / "device-preset.features"
    for content, expected, absent in [
        ("CONFIG_DREAMINGOS_DEVICE_ROLE_AP=y", "Work_mode: ap", "Work_mode: gateway"),
        ("CONFIG_DREAMINGOS_DEVICE_ROLE_GATEWAY=y", "Work_mode: gateway", "Work_mode: ap"),
        ('CONFIG_DREAMINGOS_DATA_STORAGE_AUTO=y\nCONFIG_DREAMINGOS_STORAGE_AUTOMOUNT=y\n'
         'CONFIG_DREAMINGOS_STORAGE_PRIORITY="usb,nvme,system"',
         "Storage_priority: usb,nvme,system", "Work_mode:"),
        ("", "Data_storage: legacy", "Data_storage: auto"),
    ]:
        config.write_text(content)
        subprocess.run([sys.executable, str(SCRIPT), "--config", str(config),
                        "--output", str(target)], check=True)
        actual = target.read_text()
        assert expected in actual and absent not in actual
        assert target.stat().st_mode & 0o777 == 0o444


def test_package_dependency_and_install_contract():
    package = (ROOT / "Makefile").read_text()
    assert 'source "$(SOURCE)/Config.in"' in package
    assert "PKG_CONFIG_DEPENDS" in package
    for symbol in generator.KEYS:
        assert "CONFIG_DREAMINGOS_" + symbol in package
    assert "/usr/share/dreamingos/device-preset.features" in package
    assert "--config" in package and '"$(TOPDIR)/.config"' in package
    assert "DREAMINGOS_DEVICE_ROLE_AP:dreamingwrt-apd" in package
    assert "DREAMINGOS_DATA_STORAGE_AUTO:kmod-fs-ext4" in package
    assert "DREAMINGOS_DATA_STORAGE_AUTO:block-mount" in package

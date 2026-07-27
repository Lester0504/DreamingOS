#!/usr/bin/env python3
"""Static contract for the standalone OpenWrt APD procd service."""

from __future__ import annotations

from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = ROOT / "Makefile"
SERVICE = ROOT / "files" / "dreamingwrt-apd.init"


def test_apd_service_is_a_minimal_respawning_procd_service() -> None:
    source = SERVICE.read_text(encoding="utf-8")

    assert source.startswith("#!/bin/sh /etc/rc.common\n")
    assert re.search(r"^USE_PROCD=1$", source, re.MULTILINE)
    assert 'APD_BIN="/usr/bin/dreamingwrt-apd"' in source
    assert 'procd_set_param command "$APD_BIN"' in source
    assert re.search(r"^\s*procd_set_param respawn(?:\s|$)", source, re.MULTILINE)
    assert source.count("procd_set_param command") == 1

    forbidden = (
        "/etc/config/wireless",
        "hostapd",
        "wifi reload",
        "wifi up",
        "wifi down",
        "uci ",
        "ubus ",
    )
    lowered = source.lower()
    for token in forbidden:
        assert token not in lowered, f"APD service must not operate wireless state: {token}"


def test_apd_package_installs_service_without_unified_init_dependency() -> None:
    source = MAKEFILE.read_text(encoding="utf-8")
    package_start = source.index("define Package/dreamingwrt-apd\n")
    package_end = source.index("\nendef", package_start)
    package = source[package_start:package_end]
    install_start = source.index("define Package/dreamingwrt-apd/install\n")
    install_end = source.index("\nendef", install_start)
    install = source[install_start:install_end]

    assert "+dreamingwrt-init" not in package
    assert "$(1)/etc/init.d" in install
    assert "./files/dreamingwrt-apd.init" in install
    assert "$(1)/etc/init.d/dreamingwrt-apd" in install


def test_apd_service_has_valid_shell_syntax() -> None:
    subprocess.run(["sh", "-n", str(SERVICE)], check=True)


if __name__ == "__main__":
    test_apd_service_is_a_minimal_respawning_procd_service()
    test_apd_package_installs_service_without_unified_init_dependency()
    test_apd_service_has_valid_shell_syntax()
    print("ok: APD package installs a minimal respawning procd-only service")

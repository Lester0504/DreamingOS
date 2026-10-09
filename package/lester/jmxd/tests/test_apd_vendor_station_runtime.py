#!/usr/bin/env python3
"""Compile and run APD's production `wlanconfig` station fallback collector.

Covers the Acceptance finding that `iw ... station dump` returns zero stations
on QCA drivers while `wlanconfig <if> list` returns the real association table.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile

import apd_test_deps


ROOT = Path(__file__).resolve().parents[1]


def json_c_flags() -> list[str]:
    """Locate json-c without assuming a Linux default include path."""
    # The interim /opt/homebrew probe that used to sit between pkg-config and
    # the resolver matched 31.6's compatibility symlink, so the fixture linked
    # through a shim rather than the staging_dir it should use.
    return apd_test_deps.package_flags("json-c")


def assert_production_contract() -> None:
    source = (ROOT / "src/apd/apd_backend_openwrt.c").read_text(encoding="utf-8")
    start = source.index("static const char *apd_find_wlanconfig")
    fallback_source = source[start:source.index("static int apd_survey_scan_collect")]

    required = (
        # Bounded argv execution, never a shell.
        '(char *)path, (char *)interface, "list", NULL',
        # Fallback must be driven by absence of data, not absence of a binary.
        '"wlanconfig_no_stations"',
        '"wlanconfig_no_output"',
        '"wlanconfig_failed_or_unsupported"',
        '"wlanconfig_interface_invalid"',
        # Rate normalisation to a single integer unit.
        "apd_vendor_parse_rate_kbps",
    )
    for token in required:
        assert token in fallback_source, f"missing wlanconfig fallback token: {token}"

    for forbidden in ("system(", "popen(", "/bin/sh", "/bin/ash"):
        assert forbidden not in fallback_source, (
            f"station fallback opened forbidden path: {forbidden}"
        )

    # The emitted source must be the one that produced data, and genuinely
    # unavailable metrics must stay null rather than a fabricated zero.
    emitter = source[
        source.index("static int apd_survey_scan_collect"):
        source.index("static int apd_openwrt_probe")
    ]
    for token in (
        '"station_source"',
        '"station_reason"',
        '"wlanconfig_list"',
        '"station_count"',
        '"wifi_standard"',
        '"tx_nss"',
        '"rx_nss"',
        '"tx_rate_kbps"',
        '"rx_rate_kbps"',
        "json_object_new_null()",
    ):
        assert token in emitter, f"missing station emitter token: {token}"


def make_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def main() -> None:
    assert_production_contract()
    compiler = shutil.which("clang") or shutil.which("gcc")
    assert compiler, "clang or gcc is required for the APD station fallback validation"
    with tempfile.TemporaryDirectory(prefix="apd-vendor-station-") as raw:
        temp = Path(raw)
        binary = temp / "apd-vendor-station-fixture"
        # The fixture binary doubles as the stub `iw` and `wlanconfig`, so the
        # production path resolvers must point at it.
        ieee = temp / "sys/class/ieee80211"
        net = temp / "sys/class/net"
        make_file(ieee / "phy1/index", "1\n")
        make_file(net / "ath11/phy80211/index", "1\n")
        make_file(net / "ath11/operstate", "up\n")
        subprocess.run(
            [
                compiler,
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                # apd_collect_channel_catalogs is unused in every standalone
                # fixture; that predates this test and is not silenced here.
                "-Wno-unused-function",
                "-D_POSIX_C_SOURCE=200809L",
                f'-DAPD_IEEE80211_PATH="{ieee}"',
                f'-DAPD_NET_CLASS_PATH="{net}"',
                f'-DAPD_IW_PATH="{binary}"',
                f'-DAPD_WLANCONFIG_PATH="{binary}"',
                f"-I{ROOT / 'src'}",
                str(ROOT / "tests/apd_vendor_station_runtime_fixture.c"),
                str(ROOT / "src/apd/apd_readonly_command.c"),
                *json_c_flags(),
                "-o",
                str(binary),
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        result = subprocess.run(
            [str(binary)],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.stdout.strip() == (
            "ok: APD wlanconfig station fallback parser and bounded argv collection"
        ), result.stdout
    print("ok: APD wlanconfig station fallback compiled with -Werror and passed")


if __name__ == "__main__":
    main()

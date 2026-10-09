#!/usr/bin/env python3
"""Compile and run APD's production `apstats` airtime fallback collector.

Covers the Acceptance finding that `iw ... survey dump` returns an empty body on
QCA drivers while `apstats -r -i wifiN` carries the real airtime counters, and
that firmware-disabled counters must surface as null-plus-reason rather than 0.
"""

from __future__ import annotations

from pathlib import Path
import os
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
    start = source.index("static const char *apd_find_apstats")
    collector = source[start:source.index("static int apd_survey_scan_collect")]

    required = (
        # Bounded argv execution at radio level, never a shell.
        '(char *)path, "-r", "-i", (char *)radio_netdev, NULL',
        # Fallback verdict is absence of data, not absence of a binary.
        '"apstats_no_counters_parsed"',
        '"apstats_no_output"',
        '"apstats_failed_or_unsupported"',
        '"apstats_radio_netdev_invalid"',
        '"apstats_binary_unavailable"',
        # `<DISABLED>` must be recognised rather than parsed as a number.
        "apd_airtime_value_disabled",
        '"<DISABLED>"',
        # Emitter contract consumed by the wireless page.
        '"total_per_pct"',
        '"retry_rate_pct"',
        '"firmware_disabled_channel_utilization"',
        "json_object_new_null()",
    )
    for token in required:
        assert token in collector, f"missing apstats fallback token: {token}"

    for forbidden in ("system(", "popen(", "/bin/sh", "/bin/ash"):
        assert forbidden not in collector, (
            f"airtime fallback opened forbidden path: {forbidden}"
        )

    # The whole production file must stay free of shell execution, which is the
    # invariant the parent station-fallback handoff established.
    assert source.count("popen(") == 0, "apd backend gained a popen call"
    assert source.count("system(") == 0, "apd backend gained a system call"

    # The fallback must not overwrite a survey-derived utilization.
    assert "available && !sample.complete" in source, (
        "airtime fallback must only take over when the survey has no data"
    )
    # air_stats is the key the wireless page already reads.
    assert '"air_stats"' in source, "airtime block must be published as air_stats"

    # Cumulative TX retry aggregate. `Retries` only exists at VAP level, so the
    # producer must call `apstats -v` and sum, and must refuse a partial sum.
    # Bounded at the radio-level derivations below it, which legitimately read
    # tx_failures for the instantaneous retry-rate metric.
    retry = source[
        source.index("static int apd_tx_retry_collect_vap"):
        source.index("static int apd_airtime_retry_pct")
    ]
    for token in (
        '(char *)path, "-v", "-i", (char *)vap, NULL',
        '"apstats_vap_retries_absent"',
        '"apstats_vap_tx_packets_absent"',
        '"apstats_vap_failed_or_unsupported"',
        '"apstats_vap_radio_mapping_unavailable"',
        '"apstats_no_vap_for_wiphy"',
        '"apstats_vap_sum_overflow"',
        '"apstats_vap_retries_exceed_tx_total"',
        # The controller only differences counters flagged cumulative.
        '"tx_retry_counter_semantics"',
        '"cumulative"',
        '"apstats_vap_aggregate"',
        '"tx_total"',
        '"tx_retries"',
    ):
        assert token in retry, f"missing tx retry aggregate token: {token}"
    for forbidden in ("system(", "popen(", "/bin/sh", "/bin/ash"):
        assert forbidden not in retry, (
            f"tx retry aggregate opened forbidden path: {forbidden}"
        )
    # tx_failures is a different counter; substituting it fabricates a curve.
    # Match code references rather than the word, which also appears in the
    # comment explaining why the substitution is refused.
    for forbidden in ("stats.tx_failures", "stats->tx_failures",
                      "has_tx_failures"):
        assert forbidden not in retry, (
            f"tx retry aggregate must not read {forbidden}"
        )


def assert_fixture_sample_is_verbatim() -> None:
    """The sample must keep the real column layout, not a tidied one.

    The parent station fallback shipped a fixture whose columns had been
    reordered, which hid a genuine parsing defect. Assert the traits that a
    hand-tidied sample would lose.
    """
    fixture = (ROOT / "tests/apd_airtime_runtime_fixture.c").read_text(
        encoding="utf-8"
    )
    for trait in (
        # Indented per-AC sub-rows that repeat a parent label.
        " Best effort                    = 39720408",
        # Prefixed rows from the lithium block.
        "lithium_cycle_cnt: Chan NF (BDF averaged NF_dBm) = -90",
        # Firmware-disabled markers, both of them.
        "Channel Utilization (0-255)     = <DISABLED>",
        "Throughput (kbps)               = <DISABLED>",
        # A real measured zero next to the disabled markers.
        "Total PER (%)                   = 0",
        # A label containing parentheses and a bare-word suffix.
        "Rx Mgmt Frames dropped(RSSI too low) = 0",
    ):
        assert trait in fixture, f"fixture sample no longer verbatim: {trait}"


def make_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def main() -> None:
    assert_production_contract()
    assert_fixture_sample_is_verbatim()
    compiler = shutil.which("clang") or shutil.which("gcc")
    assert compiler, "clang or gcc is required for the APD airtime validation"
    with tempfile.TemporaryDirectory(prefix="apd-airtime-") as raw:
        temp = Path(raw)
        binary = temp / "apd-airtime-fixture"
        ieee = temp / "sys/class/ieee80211"
        net = temp / "sys/class/net"
        make_file(ieee / "phy1/index", "1\n")
        make_file(ieee / "phy2/index", "2\n")
        # The radio netdev for phy2 carries ARPHRD 801; the VAPs are plain 1, so
        # the collector has to pick wifi3 by type rather than by name.
        make_file(net / "wifi3/phy80211/index", "2\n")
        make_file(net / "wifi3/type", "801\n")
        make_file(net / "ath11/phy80211/index", "2\n")
        make_file(net / "ath11/type", "1\n")
        make_file(net / "ath11/operstate", "up\n")
        # A second VAP on the same wiphy, so the retry aggregate has something
        # to sum and a partial sum is detectable.
        make_file(net / "ath12/phy80211/index", "2\n")
        make_file(net / "ath12/type", "1\n")
        make_file(net / "ath12/operstate", "up\n")
        make_file(net / "ath0/phy80211/index", "1\n")
        make_file(net / "ath0/type", "1\n")
        # QSDK topology: all three logical radio anchors share one wiphy.
        for index in (0, 1, 2):
            make_file(net / f"wifi{index}/phy80211/index", "0\n")
            make_file(net / f"wifi{index}/type", "801\n")
            make_file(net / f"ath2{index}/phy80211/index", "0\n")
            make_file(net / f"ath2{index}/type", "1\n")
            make_file(net / f"ath2{index}/operstate", "up\n")
            ctrl = temp / f"hostapd-wifi{index}"
            ctrl.mkdir()
            make_file(
                temp / f"hostapd-ath2{index}.conf",
                f"ctrl_interface={ctrl}\n",
            )
        # The aggregate MLD interface has no per-VAP apstats record and no
        # hostapd-ath*.conf; production must skip it without hiding an ordinary
        # VAP whose ownership cannot be established.
        make_file(net / "MLD1/phy80211/index", "0\n")
        make_file(net / "MLD1/type", "1\n")
        subprocess.run(
            [
                compiler,
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wno-unused-function",
                "-D_POSIX_C_SOURCE=200809L",
                f'-DAPD_IEEE80211_PATH="{ieee}"',
                f'-DAPD_NET_CLASS_PATH="{net}"',
                f'-DAPD_IW_PATH="{binary}"',
                f'-DAPD_APSTATS_PATH="{binary}"',
                f'-DAPD_HOSTAPD_CONF_PREFIX="{temp / "hostapd-"}"',
                f"-DAPD_HOSTAPD_EXPECTED_UID={os.getuid()}",
                f"-I{ROOT / 'src'}",
                str(ROOT / "tests/apd_airtime_runtime_fixture.c"),
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
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert result.stdout.strip() == (
            "ok: APD apstats airtime fallback parser and bounded argv collection"
        ), result.stdout
    print("ok: APD apstats airtime fallback compiled with -Werror and passed")


if __name__ == "__main__":
    main()

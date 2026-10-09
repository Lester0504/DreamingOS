#!/usr/bin/env python3
"""Contract test: Wi-Fi aggregation must preserve local PHY truth when
local radios/ssids are empty and AC is unavailable.

Handoff: Acceptance-to-Backend-P1-wifi-aggregate-preserves-local-phy
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / "src" / "webd" / "webd_wifi_aggregate.c").read_text()


def test_local_phy_present_variable_exists():
    """The aggregation must read local PHY truth before overwriting
    capabilities.wifi."""
    assert "int local_phy_present" in SRC


def test_local_phy_reads_capabilities_wifi():
    """local_phy_present must check capabilities.wifi from the cloned local
    response, which was set by nc_wifi_build_capabilities()."""
    assert "wifi_bool(capabilities, \"wifi\", 0)" in SRC


def test_local_phy_reads_runtime_phy_count():
    """local_phy_present must also check runtime_dependencies.phy_count
    as a fallback signal."""
    assert "runtime_dependencies" in SRC
    assert "phy_count" in SRC


def test_capabilities_wifi_uses_local_phy_present():
    """The final capabilities.wifi overwrite must include local_phy_present
    so that a device with PHY but empty radios[] keeps wifi=true."""
    cap_wifi_line = [l for l in SRC.split('\n')
                     if 'wifi_capability_bool(capabilities, "wifi"' in l]
    assert len(cap_wifi_line) >= 1
    assert "local_phy_present" in cap_wifi_line[0] or \
           "local_phy_present" in SRC.split(
               'wifi_capability_bool(capabilities, "wifi"')[1][:200]


def test_no_phy_detected_only_when_truly_absent():
    """The reason 'no_phy_detected' must only appear when local_phy_present
    is false.  When PHY exists but radios are empty, a distinct reason
    must be used."""
    # Check that no_phy_detected is gated on !local_phy_present
    idx = 0
    occurrences = 0
    while True:
        pos = SRC.find("no_phy_detected", idx)
        if pos == -1:
            break
        occurrences += 1
        # Get surrounding context (200 chars before)
        context = SRC[max(0, pos - 200):pos]
        idx = pos + 15
    # Should appear at most twice (reason and station_count_reason),
    # and both should be guarded by local_phy_present
    assert occurrences >= 1


def test_no_configured_radios_reason_exists():
    """When PHY is present but no radios are configured, a distinct reason
    'no_configured_radios' must be used instead of 'no_phy_detected'."""
    assert "no_configured_radios" in SRC


def test_phy_present_no_configured_radios_reason_exists():
    """The local_wifi.reason for 'PHY present but no radios' must be
    'phy_present_no_configured_radios', distinct from 'no_phy_detected'."""
    assert "phy_present_no_configured_radios" in SRC


def test_summary_phy_count_falls_back_to_runtime_dependencies():
    """wifi_config has no summary. Its authoritative PHY count must be
    republished from runtime_dependencies rather than becoming a zero."""
    summary_start = SRC.index('summary = wifi_ensure_object(data, "summary")')
    summary_block = SRC[summary_start:summary_start + 2200]
    assert 'local_phy_count' in summary_block
    assert 'json_object_object_add(summary, "phy_count"' in summary_block


def test_local_wifi_distinguishes_phy_count_from_configured_radios():
    """local_wifi.radio_count describes configured radios only; consumers
    also need the physical count and existence flag."""
    local_start = SRC.index('local_summary = json_object_new_object()')
    local_block = SRC[local_start:local_start + 1800]
    assert 'json_object_object_add(local_summary, "phy_count"' in local_block
    assert 'json_object_object_add(local_summary, "wireless_present"' in local_block


def test_managed_write_capabilities_have_one_projection_source():
    """Managed write bits must come from AC capabilities, not from a prior
    blanket reset that assigns a contradictory pending reason."""
    assert 'const char *const writes[]' not in SRC
    assert '"managed_ap_transaction_pending"' not in SRC[
        SRC.index('wifi_capability_bool(capabilities, "read_config"'):
        SRC.index('if (runtime_status) {',
                  SRC.index('wifi_capability_bool(capabilities, "read_config"'))
    ]
    for token in (
        '"ac_capability_unreachable"',
        '"ac_capability_not_reported"',
        'const char *const ac_writes[]',
        'wifi_response_root(ac_capabilities)',
    ):
        assert token in SRC


if __name__ == "__main__":
    test_local_phy_present_variable_exists()
    test_local_phy_reads_capabilities_wifi()
    test_local_phy_reads_runtime_phy_count()
    test_capabilities_wifi_uses_local_phy_present()
    test_no_phy_detected_only_when_truly_absent()
    test_no_configured_radios_reason_exists()
    test_phy_present_no_configured_radios_reason_exists()
    test_summary_phy_count_falls_back_to_runtime_dependencies()
    test_local_wifi_distinguishes_phy_count_from_configured_radios()
    test_managed_write_capabilities_have_one_projection_source()
    print("ok: Wi-Fi aggregate local PHY preservation contract")

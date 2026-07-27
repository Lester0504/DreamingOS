#!/usr/bin/env python3
"""Validate isolated APD snapshot replies captured from a real ubus process."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict), f"reply is not an object: {path}"
    return value


def assert_source_shape(reply: dict) -> None:
    assert set(reply["sources"]) == {"sysfs", "uci", "netifd", "iw", "hostapd"}
    for name, source in reply["sources"].items():
        for field in ("source", "scope", "available", "complete", "stale", "reason", "observed_at"):
            assert field in source, f"{name} lacks {field}"
        assert source["stale"] is False, f"{name} invents cached state"


def assert_with_phy(reply: dict) -> None:
    assert reply["ok"] is True
    assert reply["snapshot_version"] == "wireless-snapshot.v1"
    assert reply["wireless_present"] is True
    assert reply["phy_count"] == 2
    assert reply["radio_count"] == 2
    assert reply["ssid_count"] == 2
    assert reply["station_count"] == 0
    assert reply["stations"] == []
    assert reply["complete"] is False
    assert reply["reason"] == "partial_runtime_sources"
    assert {radio["id"] for radio in reply["radios"]} == {"phy0", "phy1"}
    assert {ssid["broadcast_name"] for ssid in reply["ssids"]} == {
        "Phase1-2G",
        "Phase1-5G",
    }
    assert reply["sources"]["iw"]["complete"] is True
    assert reply["sources"]["netifd"]["complete"] is False
    assert reply["sources"]["hostapd"]["source"] == "hostapd_control"
    assert reply["sources"]["hostapd"]["stale"] is False
    assert len(reply["desired"]["radios"]) == 2
    assert len(reply["desired"]["ssids"]) == 2
    serialized = json.dumps(reply, ensure_ascii=False).lower()
    for value in ("phase1-secret-2g", "phase1-secret-5g"):
        assert value not in serialized


def assert_without_phy(reply: dict) -> None:
    assert reply["ok"] is True
    assert reply["wireless_present"] is False
    assert reply["phy_count"] == 0
    assert reply["radio_count"] == 0
    assert reply["ssid_count"] == 0
    assert reply["station_count"] == 0
    assert reply["radios"] == []
    assert reply["ssids"] == []
    assert reply["stations"] == []
    assert reply["complete"] is True
    assert reply["reason"] == "no_phy_detected"
    assert len(reply["desired"]["radios"]) == 2
    assert len(reply["desired"]["ssids"]) == 2


def assert_capabilities(reply: dict) -> None:
    assert reply["ok"] is True
    capabilities = reply["capabilities"]
    assert capabilities["snapshot"] is True
    assert capabilities["local_probe"] is True
    for name in (
        "pairing",
        "controller_transport",
        "validate",
        "stage",
        "apply",
        "readback",
        "rollback",
    ):
        assert capabilities[name] is False, f"Phase 1 opened unsupported capability: {name}"
    assert "snapshot" not in capabilities["reasons"]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("with_phy", type=Path)
    parser.add_argument("without_phy", type=Path)
    parser.add_argument("capabilities", type=Path)
    args = parser.parse_args()
    with_phy = load(args.with_phy)
    without_phy = load(args.without_phy)
    capabilities = load(args.capabilities)
    assert_source_shape(with_phy)
    assert_source_shape(without_phy)
    assert_with_phy(with_phy)
    assert_without_phy(without_phy)
    assert_capabilities(capabilities)
    print("ok: APD isolated ubus runtime snapshot with PHY and honest no-PHY empty state")


if __name__ == "__main__":
    main()

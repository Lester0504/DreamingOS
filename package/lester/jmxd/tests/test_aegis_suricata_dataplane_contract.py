#!/usr/bin/env python3
"""Static contracts for explicit Suricata IDS/IPS capture lifecycles."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
INTERNAL = (SRC / "aegisxd/aegisxd_internal.h").read_text(encoding="utf-8")
DB = (SRC / "aegisxd/aegisxd_db.c").read_text(encoding="utf-8")
DATAPLANE = (SRC / "aegisxd/aegisxd_dataplane.c").read_text(encoding="utf-8")
STATUS = (SRC / "aegisxd/aegisxd_status.c").read_text(encoding="utf-8")
WEB = (SRC / "webd/jmx_app_api.c").read_text(encoding="utf-8")


def test_runtime_capture_settings_are_persistent_and_migrated() -> None:
    for field in (
        "suricata_interface",
        "suricata_queue_num",
        "suricata_fail_open",
    ):
        assert field in INTERNAL
        assert f'"{field}"' in DB
        assert f"ALTER TABLE aegis_settings ADD COLUMN {field}" in DB
    assert "AEGISXD_SCHEMA_VERSION 11" in INTERNAL


def test_monitor_uses_explicit_af_packet_interface() -> None:
    assert '"--af-packet="' in DATAPLANE
    assert "if_nametoindex(ifname)" in DATAPLANE
    assert '"suricata_capture_interface_missing"' in DATAPLANE
    assert '"suricata_capture_interface_unavailable"' in DATAPLANE
    assert '"ids_ips_capture_mode"' in STATUS
    assert '"af-packet"' in STATUS


def test_protect_owns_guarded_nfqueue_lifecycle() -> None:
    for needle in (
        'AEGISXD_SURICATA_NFQ_TABLE "dreamingwrt_aegis_ids"',
        '"nft -c -f',
        '"nft -f',
        '"nft delete table inet " AEGISXD_SURICATA_NFQ_TABLE',
        'owned-by=dreamingwrt-aegisxd scope=suricata-nfqueue',
        '-q %d',
        '"suricata_nfqueue_apply_failed"',
    ):
        assert needle in (INTERNAL + DATAPLANE)
    assert '"suricata_nfqueue_not_active"' in STATUS
    assert '"ids_ips_nfqueue_active"' in STATUS


def test_apply_requires_process_eve_and_active_state_readback() -> None:
    assert "AEGISXD_SURICATA_START_WAIT_STEPS" in DATAPLANE
    assert "aegisxd_suricata_pid_running()" in DATAPLANE
    assert "access(AEGISXD_SURICATA_EVE_PATH, R_OK)" in DATAPLANE
    assert '"suricata_active_state_write_failed"' in DATAPLANE
    assert "aegisxd_suricata_nfqueue_delete();" in DATAPLANE
    assert '"ids_ips_production_active"' in STATUS


def test_settings_rest_routes_capture_fields_to_set_mode() -> None:
    for field in (
        '"suricata_interface"',
        '"suricata_queue_num"',
        '"suricata_fail_open"',
    ):
        assert field in WEB
    assert 'method = "set_mode"' in WEB


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"ok: {len(tests)} Suricata dataplane contract tests")

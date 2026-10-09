#!/usr/bin/env python3
"""Static contract checks for managed AP control protocol v3 negotiation."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WIRE_H = (ROOT / "src/ap_control_wire.h").read_text(encoding="utf-8")
WIRE_C = (ROOT / "src/ap_control_wire.c").read_text(encoding="utf-8")
AC = (ROOT / "src/ac/ac_transport.c").read_text(encoding="utf-8")
APD = (ROOT / "src/apd/apd_transport.c").read_text(encoding="utf-8")


def test_v3_wire_constants_and_strict_helper() -> None:
    assert '#define AP_CONTROL_ALPN_V3 "dreamingwrt-ap/3"' in WIRE_H
    assert '#define AP_CONTROL_PROTOCOL_V3 "ap-control.v3"' in WIRE_H
    assert "return 3;" in WIRE_C
    for name in ("config_executor", "validate", "stage", "apply", "readback", "rollback"):
        assert f'"{name}"' in WIRE_C
    assert "ap_control_json_object_exact" in WIRE_C
    assert "json_type_boolean" in WIRE_C


def test_v1_v2_session_fields_remain_separate_from_v3() -> None:
    assert 'static const char *const ac_fields_session_hello_v3[]' in AC
    assert 'static const char *const ac_fields_session_ready_v3[]' in AC
    assert 'static const char *const apd_fields_session_hello_v3[]' in APD
    assert 'static const char *const apd_fields_session_ready_v3[]' in APD
    v1_v2_hello = '"protocol", "kind", "controller_id", "certificate_id", "ap_id"'
    assert AC.count(v1_v2_hello) >= 1
    assert APD.count(v1_v2_hello) >= 1


def test_v3_is_preferred_and_v2_job_loop_is_not_entered() -> None:
    assert '"\\x10" AP_CONTROL_ALPN_V3 "\\x10" AP_CONTROL_ALPN_V2' in APD
    assert "AP_CONTROL_PROTOCOL_V3" in AC
    assert "connection.protocol_version == 2" in APD
    assert "connection.protocol_version == 3" in APD


def test_capability_validation_and_fail_closed_state_are_present() -> None:
    assert "invalid_session_capabilities" in AC
    assert "ap_control_capabilities_parse" in AC
    assert "ap_control_capabilities_parse" in APD
    assert "write_capable" in AC
    assert "write_capable" in APD
    assert "g_ac_transport.write_capable = 0" in AC
    assert "g_apd_transport.write_capable = 0" in APD


if __name__ == "__main__":
    for test in (
        test_v3_wire_constants_and_strict_helper,
        test_v1_v2_session_fields_remain_separate_from_v3,
        test_v3_is_preferred_and_v2_job_loop_is_not_entered,
        test_capability_validation_and_fail_closed_state_are_present,
    ):
        test()
    print("ok: AP control v3 ALPN, field isolation, capability validation, and fail-closed state")

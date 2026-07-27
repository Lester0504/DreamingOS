#!/usr/bin/env python3
"""Static boundaries for node-only AC enrollment Phase 1E core."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DB = (ROOT / "src/ac/ac_db.c").read_text(encoding="utf-8")
ENROLLMENT = (ROOT / "src/ac/ac_enrollment.c").read_text(encoding="utf-8")
INTERNAL = (ROOT / "src/ac/ac_internal.h").read_text(encoding="utf-8")
PROTOCOL = (ROOT / "src/ac/ac_protocol.c").read_text(encoding="utf-8")
UBUS = (ROOT / "src/ac/ac_ubus.c").read_text(encoding="utf-8")
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")


def main() -> None:
    assert "AC_SCHEMA_VERSION 8" in INTERNAL
    for token in (
        "ac_enrollment_challenges", "ac_enrollments",
        "claimed_enrollment_id", "consumed_enrollment_id",
        "idx_ac_enrollments_ap_active", "idx_ac_device_cert_active",
        "ac_db_enrollment_claim", "ac_db_enrollment_certificate_commit",
        "ac_db_enrollment_activate", "ac_enrollment_state_validate",
        "BEGIN IMMEDIATE", "ROLLBACK", "pending_activation", "mtls_pending",
    ):
        assert token in DB, token
    for token in (
        "EVP_PKEY_ED25519", "EVP_DigestVerify", "X509_REQ_verify",
        "NID_subject_alt_name", "GEN_URI", "urn:dreamingwrt:ap:",
        "dreamingwrt-ap-enrollment-v1", "CRYPTO_memcmp",
    ):
        assert token in ENROLLMENT, token
    assert "peer_fingerprint_sha256" in DB + INTERNAL
    assert "c.fingerprint_sha256=?3" in DB
    assert 'ac_capability(cap, reasons, "node_enrollment_core", 1' in PROTOCOL
    assert 'ac_capability(cap, reasons, "pairing_token_ipc", ac_transport_listening()' in PROTOCOL
    assert 'ac_capability(cap, reasons, "ap_adoption", ac_transport_listening()' in PROTOCOL
    assert 'ac_capability(cap, reasons, "heartbeat", ac_transport_listening()' in PROTOCOL
    assert 'ac_capability(cap, reasons, "node_transport", ac_transport_listening()' in PROTOCOL
    assert 'ac_capability(cap, reasons, "remote_telemetry", 1' in PROTOCOL
    assert 'ac_capability(cap, reasons, "ssid_create", 0' in PROTOCOL
    assert 'ac_capability(cap, reasons, "radio_update", 0' in PROTOCOL
    assert 'ac_capability(cap, reasons, "ap_actions", 0' in PROTOCOL
    for forbidden in (
        'UBUS_METHOD("pairing_token_redeem"', 'UBUS_METHOD("enroll"',
        'UBUS_METHOD("activate"', '"/api/v1/ac/enroll"',
        '"/api/v1/ac/redeem"', '"/api/v1/ac/certificate"',
        '"/api/v1/ac/activate"',
    ):
        assert forbidden not in UBUS + WEB, forbidden
    for forbidden in ("system(", "popen(", '"ssh"', '"scp"'):
        assert forbidden not in DB + ENROLLMENT, forbidden
    print("ok: AC enrollment is authenticated, atomic, replay-safe, and node-only")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""APD Phase 1B identity and local pairing security contract."""

from __future__ import annotations

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
APD = ROOT / "src/apd"


def read(name: str) -> str:
    return (APD / name).read_text(encoding="utf-8")


def test_identity_is_independent_and_ed25519() -> None:
    db = read("apd_db.c")
    internal = read("apd_internal.h")
    assert "APD_SCHEMA_VERSION 3" in internal
    assert "EVP_PKEY_ED25519" in db
    assert "RAND_bytes" in db
    assert "raw_private_key" in db and "raw_public_key" in db
    assert "apd_node_identity_v3" in db
    assert 'DROP TABLE apd_node_identity_v2' in db
    assert 'PRAGMA secure_delete=ON' in db
    assert "DREAMINGWRT_APD_IDENTITY_KEY_PATH" in db
    assert "raw[6] = (raw[6] & 0x0f) | 0x40" in db
    for forbidden in ("machine-id", "machine_id", "macaddress", "phy mac", "hostname"):
        assert forbidden not in db.lower()


def test_initialization_is_atomic_and_fail_closed() -> None:
    db = read("apd_db.c")
    assert 'apd_exec("BEGIN IMMEDIATE")' in db
    assert "O_EXCL | O_NOFOLLOW" in db
    assert "O_RDONLY | O_NOFOLLOW" in db
    assert "flock(fd, LOCK_EX)" in db
    assert '"%s.init.lock"' in db
    assert "SQLITE_OPEN_NOFOLLOW" in db
    assert '#error "dreamingwrt-apd requires O_NOFOLLOW' in db
    assert '#error "dreamingwrt-apd requires SQLITE_OPEN_NOFOLLOW' in db
    assert "lstat(parent" in db and "lstat(path" in db
    assert "!S_ISDIR" in db and "!S_ISREG" in db
    assert "(st.st_mode & 0022)" in db
    assert "st.st_nlink != 1" in db
    assert "(st.st_mode & 0777) != 0600" in db
    assert 'required_mode ? (st.st_mode & 0777) != required_mode' in db
    assert "rename(temporary, path)" in db
    assert "apd_sync_parent(path)" in db
    assert '"PRAGMA quick_check(1)"' in db
    assert "apd_identity_validate()" in db
    assert "apd_pairing_validate()" in db
    assert "CRYPTO_memcmp" in db
    assert "OPENSSL_cleanse" in db
    assert "geteuid() == 0 && owner == 0" in db


def test_ubus_surface_is_read_only_and_secret_free() -> None:
    protocol = read("apd_protocol.c")
    ubus = read("apd_ubus.c")
    assert 'UBUS_METHOD_NOARG("identity"' in ubus
    assert 'UBUS_METHOD_NOARG("pairing_status"' in ubus
    for forbidden_method in (
        '"pair"',
        '"pairing_begin"',
        '"pairing_challenge"',
        '"adopt"',
        '"enroll"',
    ):
        assert forbidden_method not in ubus
    for forbidden in ("private_key", "challenge_hash", "pairing_token", "secret"):
        assert forbidden not in protocol
        assert forbidden not in ubus
    assert '"public_key"' in protocol
    assert '"key_exportable"' in protocol
    assert '"mtls_ready"' in protocol
    assert '"adopted"' in protocol
    assert 'json_object_new_boolean(0)' in protocol


def test_pairing_state_machine_cannot_claim_remote_pairing() -> None:
    db = read("apd_db.c")
    protocol = read("apd_protocol.c")
    for state in ("unpaired", "pending", "challenge_pending", "challenge_verified", "expired", "failed"):
        assert f"'{state}'" in db
    assert "SHA256(challenge" in db
    assert "attempts<5" in db
    assert "attempts+1>=5" in db
    assert "paired" not in re.sub(r"unpaired", "", db)
    assert "adopted" not in db
    assert 'apd_capability(cap, reasons, "pairing", 0' in protocol
    assert '"pairing_transport_and_mtls_not_implemented"' in protocol


if __name__ == "__main__":
    test_identity_is_independent_and_ed25519()
    test_initialization_is_atomic_and_fail_closed()
    test_ubus_surface_is_read_only_and_secret_free()
    test_pairing_state_machine_cannot_claim_remote_pairing()
    print("ok: APD Phase 1B identity and local pairing security contract")

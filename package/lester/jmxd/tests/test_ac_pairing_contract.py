#!/usr/bin/env python3
"""Static security contract for AC pairing-token Phase 1C."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INTERNAL = (ROOT / "src/ac/ac_internal.h").read_text(encoding="utf-8")
DATABASE = (ROOT / "src/ac/ac_db.c").read_text(encoding="utf-8")
PROTOCOL = (ROOT / "src/ac/ac_protocol.c").read_text(encoding="utf-8")
PUBLIC = PROTOCOL + (ROOT / "src/ac/ac_ubus.c").read_text(encoding="utf-8")


def main() -> None:
    for token in (
        "RAND_bytes", "EVP_sha256", "CRYPTO_memcmp", "BEGIN IMMEDIATE",
        "consumed_at=0 AND revoked_at=0", "attempts<max_attempts",
        'ac_exec("ROLLBACK")',
        "SQLITE_OPEN_NOFOLLOW", "O_NOFOLLOW", "st_nlink != 1", "0600",
        "AC_SCHEMA_VERSION 8", "digest_version", "hardware_digest", "site_id",
    ):
        assert token in INTERNAL + DATABASE, token
    assert 'json_object_object_add(root, "token",' in PROTOCOL
    assert '"display_once"' in PROTOCOL
    assert '"token_hash"' not in PUBLIC
    # Scope data may enter the strict create-only ubus request, but no public
    # status/list/revoke serializer may disclose the bound digest.
    assert '"hardware_digest"' not in PROTOCOL
    assert '"mtls_ready", json_object_new_boolean(0)' in PROTOCOL
    assert '"adopted", json_object_new_boolean(0)' in PROTOCOL
    for forbidden in ("system(", "popen(", '"ssh"', '"scp"'):
        assert forbidden not in DATABASE + PROTOCOL, forbidden
    print("ok: AC Phase 1C pairing token security and capability boundaries")


if __name__ == "__main__":
    main()

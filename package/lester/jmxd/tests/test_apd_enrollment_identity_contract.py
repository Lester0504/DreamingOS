#!/usr/bin/env python3
"""Static contract for APD Phase 1E identity and enrollment helpers."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APD = ROOT / "src/apd"


def read(name: str) -> str:
    return (APD / name).read_text(encoding="utf-8")


def test_v3_private_key_boundary() -> None:
    header = read("apd_internal.h")
    database = read("apd_db.c")
    assert '#define APD_SCHEMA_VERSION 3' in header
    assert '#define APD_IDENTITY_KEY_PATH "/etc/dreamingwrt/apd-pki/identity.ed25519"' in header
    assert 'getenv("DREAMINGWRT_APD_IDENTITY_KEY_PATH")' in database
    assert '"CREATE TABLE apd_node_identity_v3 ("' in database
    assert '"DROP TABLE apd_node_identity_v2"' in database
    assert 'apd_exec("PRAGMA secure_delete=ON")' in database
    v3_start = database.index('"CREATE TABLE apd_node_identity_v3 ("')
    v3_end = database.index(")", v3_start)
    assert "private_key" not in database[v3_start:v3_end]
    for token in ("O_NOFOLLOW", "O_EXCL", "st.st_nlink != 1", "0600", "0700",
                  "rename(temporary, path)", "fsync(fd)", "apd_sync_parent(path)"):
        assert token in database
    assert "apd_identity_from_private" in database
    assert 'getenv("APD_DB_TEST_FAIL_COMMIT_ONCE")' in database


def test_binary_v1_and_crypto_helpers_are_internal_only() -> None:
    header = read("apd_internal.h")
    enrollment = read("apd_enrollment.c")
    assert 'APD_ENROLLMENT_DOMAIN "dreamingwrt-ap-enrollment-v1"' in enrollment
    order = [
        "input->challenge_id.data", "input->server_nonce", "input->client_nonce",
        "input->enrollment_id.data", "input->token_id.data", "input->token.data",
        "input->ap_id.data", "input->key_id.data", "input->public_key",
        "input->site_id.data", "input->hardware_digest.data", "input->csr_sha256",
    ]
    positions = [enrollment.index(value) for value in order]
    assert positions == sorted(positions)
    assert "out[(*offset)++] = (unsigned char)(len >> 8)" in enrollment
    assert "input->challenge_expires_at >> shift" in enrollment
    assert "EVP_DigestSign" in enrollment
    assert "OPENSSL_cleanse(transcript" in enrollment
    assert "apd_identity_key_open()" in enrollment
    assert "private_key" not in enrollment
    assert "struct apd_enrollment_transcript_v1" in header
    assert "struct json_object" not in enrollment
    assert "ubus" not in enrollment.lower()


def test_csr_identity_contract() -> None:
    enrollment = read("apd_enrollment.c")
    assert '"urn:dreamingwrt:ap:%s"' in enrollment
    assert "NID_subject_alt_name" in enrollment
    assert "GEN_URI" in enrollment
    assert "X509_REQ_sign(request, key, NULL)" in enrollment
    assert "X509_REQ_set_pubkey(request, key)" in enrollment
    assert "NID_commonName" not in enrollment
    assert "X509_NAME_add_entry" not in enrollment


if __name__ == "__main__":
    test_v3_private_key_boundary()
    test_binary_v1_and_crypto_helpers_are_internal_only()
    test_csr_identity_contract()
    print("ok: APD Phase 1E identity/enrollment static contract")

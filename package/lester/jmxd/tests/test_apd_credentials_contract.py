#!/usr/bin/env python3
"""Static security contract for APD enrollment credential persistence."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/apd/apd_credentials.c"


def test_credentials_are_file_scoped_and_not_web_exposed() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    assert 'APD_CREDENTIALS_PKI_DIR "/etc/dreamingwrt/apd-pki"' in source
    assert 'getenv("DREAMINGWRT_APD_PKI_DIR")' in source
    assert 'APD_CREDENTIALS_CERT_FILE "client-cert.der"' in source
    assert 'APD_CREDENTIALS_METADATA_FILE "enrollment.json"' in source
    assert 'APD_CREDENTIALS_BOOTSTRAP_FILE "bootstrap.json"' in source
    assert "sqlite3" not in source.lower()
    assert "ubus" not in source.lower()
    assert "system(" not in source and "popen(" not in source
    assert "struct apd_bootstrap_config" in source
    assert "apd_credentials_bootstrap_load(" in source
    assert "apd_credentials_bootstrap_cleanse(" in source


def test_strict_bootstrap_and_ca_contract() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    for key in (
        '"version"', '"controller_host"', '"controller_port"',
        '"controller_id"', '"token_id"', '"token"', '"site_id"',
        '"hardware_digest"', '"ca_cert_pem_path"',
    ):
        assert key in source
    assert "apd_json_known" in source
    assert "strcmp(out->members[i].key, member->key)" in source
    assert "APD_CREDENTIALS_TOKEN_LEN 43" in source
    assert "inet_pton(AF_INET" in source and "inet_pton(AF_INET6" in source
    assert "X509_check_ca(ca) <= 0" in source
    for token in (
        "O_NOFOLLOW", "status.st_nlink != 1", "status.st_uid != geteuid()",
        "(status.st_mode & 0777) != mode", "S_ISREG", "0700", "0600",
    ):
        assert token in source


def test_certificate_and_identity_binding_contract() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    assert "d2i_X509" in source
    assert "X509_verify_cert" in source
    assert "EVP_PKEY_ED25519" in source
    assert "apd_identity_key_open()" in source
    assert "EVP_PKEY_get_raw_public_key(identity_key" in source
    assert '"urn:dreamingwrt:ap:%s"' in source
    assert "sk_GENERAL_NAME_num(names) != 1" in source
    assert "NID_client_auth" in source
    assert "sk_ASN1_OBJECT_num(usage) != 1" in source
    assert "X509_check_ca(certificate) > 0" in source
    assert "APD_CREDENTIALS_STATE_PENDING \"mtls_pending\"" in source
    assert "APD_CREDENTIALS_STATE_ADOPTED \"adopted\"" in source


def test_atomicity_lock_and_secret_removal_contract() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    for token in (
        "flock(lock->fd, LOCK_EX)", "O_CREAT | O_EXCL", "fsync(fd)",
        "rename(temporary, destination)", "apd_credentials_parent_sync",
        "OPENSSL_cleanse", "unlink(path)",
    ):
        assert token in source
    activate = source[source.index("int apd_credentials_activate("):]
    remove = activate.index("apd_credentials_bootstrap_remove_locked")
    transition = activate.index("APD_CREDENTIALS_STATE_ADOPTED", remove)
    commit = activate.index("apd_credentials_metadata_write_locked", transition)
    assert remove < transition < commit
    metadata = source[source.index("struct apd_enrollment_metadata {"):
                      source.index("};", source.index("struct apd_enrollment_metadata {"))]
    assert "token" not in metadata
    assert "private" not in metadata


if __name__ == "__main__":
    test_credentials_are_file_scoped_and_not_web_exposed()
    test_strict_bootstrap_and_ca_contract()
    test_certificate_and_identity_binding_contract()
    test_atomicity_lock_and_secret_removal_contract()
    print("ok: APD credential persistence static contract")

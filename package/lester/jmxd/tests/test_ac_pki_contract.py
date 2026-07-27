#!/usr/bin/env python3
"""Static contract for the AC private CA and AP certificate issuer."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/ac/ac_pki.c").read_text(encoding="utf-8")


def main() -> None:
    required = (
        'AC_PKI_DEFAULT_DIR "/etc/dreamingwrt/ac-pki"',
        'getenv("DREAMINGWRT_AC_PKI_DIR")',
        'getenv("DREAMINGWRT_AC_LISTEN_NAMES")',
        "#define AC_PKI_CLOCK_SKEW 900",
        "O_NOFOLLOW", "O_DIRECTORY", "O_EXCL", "AT_SYMLINK_NOFOLLOW",
        "st.st_nlink != 1", "geteuid()", "flock(fd, LOCK_EX)",
        "lock_rc != 0 && errno == EINTR",
        "O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW",
        "fd < 0 && errno == EEXIST",
        "fchmod(fd, 0600)", "mkdirat(parent_fd, base, 0700)",
        "fsync(fd)", "renameat(dirfd, temporary, dirfd, name)",
        "ac_pki_sync_directory(dirfd)", "EVP_PKEY_ED25519",
        '"critical,CA:TRUE,pathlen:0"',
        '"critical,keyCertSign,cRLSign"',
        '"critical,CA:FALSE"', '"critical,digitalSignature"',
        '"serverAuth"', '"clientAuth"',
        '"urn:dreamingwrt:ac:%s"', '"urn:dreamingwrt:ap:%s"',
        "X509_REQ_verify", "EVP_PKEY_get_raw_public_key",
        "sk_X509_EXTENSION_num(extensions) != 1",
        "CRYPTO_memcmp", "RAND_bytes", "OPENSSL_cleanse",
        "ac_pki_issue_ap_certificate", "ac_pki_ca_der", "ac_pki_ca_pem",
        "ac_pki_server_private_key_dup",
    )
    for token in required:
        assert token in SOURCE, token
    for forbidden in (
        "system(", "popen(", 'execl(', 'execv(', '"openssl"',
        "sqlite3", "json_object", "ubus", "socket(", "connect(", "listen(",
        "PEM_write_bio_PrivateKey", "PEM_write_PrivateKey",
    ):
        assert forbidden not in SOURCE, forbidden
    assert "private_key" not in SOURCE.split("struct ac_pki {")[1].split("};", 1)[0]
    print("ok: AC PKI is file-secure, Ed25519-only, CA-scoped, and socket-free")


if __name__ == "__main__":
    main()

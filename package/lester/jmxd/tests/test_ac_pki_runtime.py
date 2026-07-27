#!/usr/bin/env python3
"""Real OpenSSL/filesystem tests for the AC private PKI and AP issuer."""

from __future__ import annotations

import concurrent.futures
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/ac/ac_pki.c"
FIXTURE = ROOT / "tests/ac_pki_runtime_fixture.c"
OPENSSL_PREFIX = Path("/opt/homebrew/opt/openssl@3")
FILES = (
    "ca.ed25519", "ca.crt.der", "server.ed25519", "server.crt.der",
    "init.lock",
)


def target_prefix() -> Path | None:
    configured = os.environ.get("AC_PKI_TEST_PREFIX", "")
    if configured:
        prefix = Path(configured)
        assert (prefix / "include/openssl/x509.h").is_file()
        assert (prefix / "lib").is_dir()
        return prefix
    return OPENSSL_PREFIX if OPENSSL_PREFIX.is_dir() else None


def compile_fixture(output: Path) -> None:
    prefix = target_prefix()
    flags = (
        [f"-I{prefix / 'include'}", f"-L{prefix / 'lib'}",
         f"-Wl,-rpath,{prefix / 'lib'}"] if prefix else []
    )
    command = [
        os.environ.get("CC", "cc"), "-std=c11",
        "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
        "-DAC_PKI_TEST_STANDALONE", "-Wall", "-Wextra", "-Werror",
        *flags, str(FIXTURE), str(SOURCE), "-lcrypto", "-o", str(output),
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)


def environment(pki: Path, **extra: str) -> dict[str, str]:
    env = os.environ.copy()
    env["DREAMINGWRT_AC_PKI_DIR"] = str(pki)
    env["DREAMINGWRT_AC_LISTEN_NAMES"] = "ac.test,192.0.2.10,2001:db8::10"
    env.update(extra)
    prefix = target_prefix()
    if prefix and sys.platform != "darwin":
        env["LD_LIBRARY_PATH"] = str(prefix / "lib")
    return env


def run(binary: Path, pki: Path, *args: str, check: bool = True,
        extra: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [str(binary), *args], env=environment(pki, **(extra or {})),
        capture_output=True, text=True,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"command failed ({result.returncode}): {args}\n"
            f"stdout={result.stdout}\nstderr={result.stderr}"
        )
    return result


def fields(output: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def prepare_parent(path: Path) -> None:
    path.parent.mkdir(mode=0o700, parents=True)
    os.chmod(path.parent, 0o700)


def assert_secure_files(pki: Path) -> None:
    assert (pki.stat().st_mode & 0o777) == 0o700
    assert not pki.is_symlink()
    assert {item.name for item in pki.iterdir()} == set(FILES)
    for name in FILES:
        item = pki / name
        stat = item.stat()
        assert item.is_file() and not item.is_symlink(), name
        assert stat.st_nlink == 1, name
        assert stat.st_uid == os.geteuid(), name
        assert (stat.st_mode & 0o777) == 0o600, name
    assert (pki / "ca.ed25519").stat().st_size == 32
    assert (pki / "server.ed25519").stat().st_size == 32
    assert not list(pki.glob("*.tmp.*"))
    assert not list(pki.glob(".*.tmp.*"))


def test_concurrent_stable_initialization(binary: Path, root: Path) -> tuple[Path, dict[str, str]]:
    pki = root / "concurrent" / "ac-pki"
    prepare_parent(pki)

    def initialize(_: int) -> subprocess.CompletedProcess[str]:
        return run(binary, pki, "inspect", check=False)

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(initialize, range(32)))
    assert all(result.returncode == 0 for result in results), [
        (result.returncode, result.stderr) for result in results
    ]
    identities = [fields(result.stdout) for result in results]
    assert len({item["controller_id"] for item in identities}) == 1
    assert len({item["ca_key_id"] for item in identities}) == 1
    assert len({item["ca_fingerprint"] for item in identities}) == 1
    first = identities[0]
    again = fields(run(binary, pki, "inspect").stdout)
    assert again == first
    assert first["ca_key_id"].startswith("sha256:")
    assert first["ca_fingerprint"].startswith("sha256:")
    assert_secure_files(pki)
    return pki, first


def test_crash_recovery(binary: Path, root: Path) -> None:
    stages = ("ca-key", "ca-cert", "server-key", "server-cert")
    for stage in stages:
        pki = root / f"interrupt-{stage}" / "ac-pki"
        prepare_parent(pki)
        interrupted = run(
            binary, pki, "inspect", check=False,
            extra={"AC_PKI_TEST_INTERRUPT_AFTER": stage},
        )
        assert interrupted.returncode != 0, stage
        ca_key_digest = (
            hashlib.sha256((pki / "ca.ed25519").read_bytes()).hexdigest()
            if (pki / "ca.ed25519").is_file() else None
        )
        recovered = fields(run(binary, pki, "inspect").stdout)
        assert recovered["controller_id"] and recovered["ca_fingerprint"]
        if ca_key_digest is not None:
            assert hashlib.sha256((pki / "ca.ed25519").read_bytes()).hexdigest() == ca_key_digest
        assert_secure_files(pki)


def openssl(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    executable = os.environ.get("OPENSSL", "openssl")
    result = subprocess.run([executable, *args], capture_output=True, text=True)
    if check and result.returncode != 0:
        raise AssertionError(
            f"openssl failed: {args}\nstdout={result.stdout}\nstderr={result.stderr}"
        )
    return result


def certificate_text(path: Path) -> str:
    return openssl("x509", "-in", str(path), "-noout", "-text").stdout


def test_x509_and_issuer(binary: Path, root: Path) -> None:
    pki = root / "issuer" / "ac-pki"
    output = root / "issuer" / "output"
    prepare_parent(pki)
    output.mkdir(mode=0o700)
    result = fields(run(binary, pki, "issue", str(output), "valid").stdout)
    assert result["serial"] and len(result["serial"]) == 40
    assert result["issuer_key_id"].startswith("sha256:")
    assert result["client_fingerprint"].startswith("sha256:")
    assert int(result["not_before"]) < int(result["not_after"])
    openssl("verify", "-CAfile", str(output / "ca.pem"),
            "-purpose", "sslserver", str(output / "server.pem"))
    openssl("verify", "-CAfile", str(output / "ca.pem"),
            "-purpose", "sslclient", str(output / "client.pem"))

    ca_text = certificate_text(output / "ca.pem")
    server_text = certificate_text(output / "server.pem")
    client_text = certificate_text(output / "client.pem")
    assert "ED25519" in ca_text.upper()
    assert "CA:TRUE, pathlen:0" in ca_text
    assert "Certificate Sign, CRL Sign" in ca_text
    assert "CA:FALSE" in server_text and "TLS Web Server Authentication" in server_text
    assert "Digital Signature" in server_text
    assert "URI:urn:dreamingwrt:ac:" in server_text
    assert "DNS:ac.test" in server_text
    assert "IP Address:192.0.2.10" in server_text
    assert "IP Address:2001:DB8:0:0:0:0:0:10" in server_text
    assert "CA:FALSE" in client_text and "TLS Web Client Authentication" in client_text
    assert "URI:urn:dreamingwrt:ap:12345678-1234-4abc-8def-123456789abc" in client_text
    assert "TLS Web Server Authentication" not in client_text
    assert client_text.count("X509v3 Subject Alternative Name") == 1

    ca_private = (pki / "ca.ed25519").read_bytes()
    server_private = (pki / "server.ed25519").read_bytes()
    public_outputs = b"".join(item.read_bytes() for item in output.iterdir())
    combined_log = ("\n".join(result.values())).encode()
    assert ca_private not in public_outputs and server_private not in public_outputs
    assert ca_private.hex().encode() not in combined_log
    assert server_private.hex().encode() not in combined_log

    second = root / "issuer" / "output-2"
    second.mkdir(mode=0o700)
    second_result = fields(run(binary, pki, "issue", str(second), "valid").stdout)
    assert second_result["serial"] != result["serial"]
    assert second_result["client_fingerprint"] != result["client_fingerprint"]

    for mode in ("bad-signature", "bad-san", "wrong-key", "extra-extension", "rsa"):
        rejected_output = root / "issuer" / f"reject-{mode}"
        rejected_output.mkdir(mode=0o700)
        rejected = fields(run(binary, pki, "issue", str(rejected_output), mode).stdout)
        assert rejected == {"rejected": "true"}, mode


def clone_pki(source: Path, destination: Path) -> Path:
    destination.parent.mkdir(mode=0o700, parents=True)
    shutil.copytree(source, destination)
    os.chmod(destination, 0o700)
    for item in destination.iterdir():
        os.chmod(item, 0o600)
    return destination


def expect_failure(binary: Path, pki: Path) -> None:
    result = run(binary, pki, "inspect", check=False)
    assert result.returncode != 0, result.stdout


def test_fail_closed_filesystem(binary: Path, root: Path, source: Path) -> None:
    mode_dir = clone_pki(source, root / "bad-mode" / "ac-pki")
    os.chmod(mode_dir / "ca.crt.der", 0o644)
    expect_failure(binary, mode_dir)

    directory_mode = clone_pki(source, root / "bad-directory" / "ac-pki")
    os.chmod(directory_mode, 0o755)
    expect_failure(binary, directory_mode)

    symlink_dir = clone_pki(source, root / "symlink" / "ac-pki")
    (symlink_dir / "server.crt.der").unlink()
    (symlink_dir / "server.crt.der").symlink_to(source / "server.crt.der")
    expect_failure(binary, symlink_dir)

    hardlink_dir = clone_pki(source, root / "hardlink" / "ac-pki")
    (hardlink_dir / "ca.ed25519").unlink()
    os.link(source / "ca.ed25519", hardlink_dir / "ca.ed25519")
    expect_failure(binary, hardlink_dir)
    (hardlink_dir / "ca.ed25519").unlink()
    assert (source / "ca.ed25519").stat().st_nlink == 1

    lock_dir = clone_pki(source, root / "lock-symlink" / "ac-pki")
    (lock_dir / "init.lock").unlink()
    (lock_dir / "init.lock").symlink_to(source / "init.lock")
    expect_failure(binary, lock_dir)

    tamper_key = clone_pki(source, root / "tamper-key" / "ac-pki")
    changed = bytearray((tamper_key / "server.ed25519").read_bytes())
    changed[0] ^= 0x80
    (tamper_key / "server.ed25519").write_bytes(changed)
    os.chmod(tamper_key / "server.ed25519", 0o600)
    expect_failure(binary, tamper_key)

    tamper_cert = clone_pki(source, root / "tamper-cert" / "ac-pki")
    changed = bytearray((tamper_cert / "ca.crt.der").read_bytes())
    changed[-1] ^= 0x01
    (tamper_cert / "ca.crt.der").write_bytes(changed)
    os.chmod(tamper_cert / "ca.crt.der", 0o600)
    expect_failure(binary, tamper_cert)

    missing_key = clone_pki(source, root / "missing-key" / "ac-pki")
    (missing_key / "ca.ed25519").unlink()
    expect_failure(binary, missing_key)

    broad_parent = root / "broad-parent"
    broad_parent.mkdir(mode=0o777)
    os.chmod(broad_parent, 0o777)
    expect_failure(binary, broad_parent / "ac-pki")

    ca_key_before = (source / "ca.ed25519").read_bytes()
    ca_cert_before = (source / "ca.crt.der").read_bytes()
    server_key_before = (source / "server.ed25519").read_bytes()
    server_cert_before = (source / "server.crt.der").read_bytes()
    changed_names = run(
        binary, source, "inspect", check=False,
        extra={"DREAMINGWRT_AC_LISTEN_NAMES": "different.test,192.0.2.11"},
    )
    assert changed_names.returncode == 0, changed_names.stderr
    assert (source / "ca.ed25519").read_bytes() == ca_key_before
    assert (source / "ca.crt.der").read_bytes() == ca_cert_before
    assert (source / "server.ed25519").read_bytes() == server_key_before
    assert (source / "server.crt.der").read_bytes() != server_cert_before
    assert_secure_files(source)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="ac-pki-") as raw:
        root = Path(raw)
        os.chmod(root, 0o700)
        binary = root / "ac-pki-fixture"
        compile_fixture(binary)
        stable_pki, _ = test_concurrent_stable_initialization(binary, root)
        test_crash_recovery(binary, root)
        test_x509_and_issuer(binary, root)
        test_fail_closed_filesystem(binary, root, stable_pki)
    print("ok: AC PKI initialization, recovery, X.509 issuance, and file boundaries verified")


if __name__ == "__main__":
    main()

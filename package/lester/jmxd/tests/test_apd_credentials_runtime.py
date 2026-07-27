#!/usr/bin/env python3
"""Runtime tests for APD enrollment credential persistence."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/apd_credentials_runtime_fixture.c"
OPENSSL = Path("/opt/homebrew/opt/openssl@3")
TOKEN = "A" * 43


def target_prefix() -> Path | None:
    configured = os.environ.get("APD_CREDENTIALS_TEST_PREFIX", "")
    if not configured:
        return None
    prefix = Path(configured)
    assert (prefix / "include/openssl/evp.h").is_file()
    return prefix


def compile_fixture(output: Path) -> None:
    prefix = target_prefix()
    flags = (
        [f"-I{prefix / 'include'}", f"-L{prefix / 'lib'}",
         f"-Wl,-rpath,{prefix / 'lib'}"]
        if prefix else [f"-I{OPENSSL / 'include'}", f"-L{OPENSSL / 'lib'}"]
    )
    command = [
        os.environ.get("CC", "cc"), "-std=c11",
        "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
        "-Wall", "-Wextra", "-Werror", *flags, str(FIXTURE), "-lcrypto",
        "-o", str(output),
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)


def run(binary: Path, pki: Path, *args: str, check: bool = True,
        extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["DREAMINGWRT_APD_PKI_DIR"] = str(pki)
    if extra_env:
        env.update(extra_env)
    prefix = target_prefix()
    if prefix:
        env["LD_LIBRARY_PATH"] = str(prefix / "lib")
    result = subprocess.run([str(binary), *args], env=env, check=False,
                            capture_output=True, text=True)
    if check and result.returncode != 0:
        raise AssertionError(
            f"fixture failed: {args}\nstdout={result.stdout}\nstderr={result.stderr}"
        )
    return result


def fields(output: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def assert_secure(path: Path, directory: bool = False) -> None:
    info = path.lstat()
    assert not path.is_symlink()
    assert stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    assert stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600)
    if not directory:
        assert info.st_nlink == 1
    assert info.st_uid == os.geteuid()


def setup(binary: Path, root: Path, name: str) -> Path:
    pki = root / name / "pki"
    pki.parent.mkdir(mode=0o700)
    run(binary, pki, "setup")
    assert_secure(pki, directory=True)
    for filename in ("identity.ed25519", "bootstrap.json", "controller-ca.pem"):
        assert_secure(pki / filename)
    return pki


def bootstrap_data(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "version": 1,
        "controller_host": "ac.example.test",
        "controller_port": 9443,
        "controller_id": "bbbbbbbb-bbbb-5bbb-8bbb-bbbbbbbbbbbb",
        "token_id": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        "token": TOKEN,
        "site_id": "default",
        "hardware_digest": "",
    }
    value.update(changes)
    return value


def write_bootstrap(pki: Path, value: object) -> None:
    path = pki / "bootstrap.json"
    path.write_text(json.dumps(value, separators=(",", ":")), encoding="ascii")
    path.chmod(0o600)


def bootstrap_contract(binary: Path, root: Path) -> None:
    pki = setup(binary, root, "bootstrap-valid")
    result = run(binary, pki, "bootstrap")
    output = fields(result.stdout)
    assert output["version"] == "1"
    assert output["controller_host"] == "ac.example.test"
    assert output["controller_port"] == "9443"
    assert output["controller_id_present"] == "1"
    assert output["site_id"] == "default"
    assert TOKEN not in result.stdout and "private" not in result.stdout.lower()

    accepted = [
        {"controller_host": "192.0.2.10"},
        {"controller_host": "2001:db8::10"},
        {"controller_id": ""},
        {"site_id": ""},
        {"hardware_digest": "sha256:" + "a" * 64},
        {"site_id": "s" * 64},
    ]
    for index, change in enumerate(accepted):
        candidate = setup(binary, root, f"bootstrap-accepted-{index}")
        write_bootstrap(candidate, bootstrap_data(**change))
        assert run(binary, candidate, "bootstrap", check=False).returncode == 0

    rejected: list[object] = [
        bootstrap_data(version=2),
        bootstrap_data(controller_host="999.999.999.999"),
        bootstrap_data(controller_host="bad_name.example"),
        bootstrap_data(controller_host="-bad.example"),
        bootstrap_data(controller_port=0),
        bootstrap_data(controller_port=65536),
        bootstrap_data(controller_port="9443"),
        bootstrap_data(controller_id="bad"),
        bootstrap_data(token_id="bad"),
        bootstrap_data(token="A" * 42),
        bootstrap_data(token="A" * 42 + "+"),
        bootstrap_data(site_id="s" * 65),
        bootstrap_data(site_id="bad\nsite"),
        bootstrap_data(hardware_digest="sha256:" + "A" * 64),
        bootstrap_data(unknown=True),
        [bootstrap_data()],
    ]
    for index, value in enumerate(rejected):
        candidate = setup(binary, root, f"bootstrap-rejected-{index}")
        write_bootstrap(candidate, value)
        result = run(binary, candidate, "bootstrap", check=False)
        assert result.returncode != 0
        assert TOKEN not in result.stdout + result.stderr

    candidate = setup(binary, root, "bootstrap-duplicate")
    duplicate = json.dumps(bootstrap_data(), separators=(",", ":"))
    duplicate = duplicate[:-1] + ',"token":"' + TOKEN + '"}'
    (candidate / "bootstrap.json").write_text(duplicate, encoding="ascii")
    (candidate / "bootstrap.json").chmod(0o600)
    assert run(binary, candidate, "bootstrap", check=False).returncode != 0

    candidate = setup(binary, root, "bootstrap-nul")
    (candidate / "bootstrap.json").write_bytes(
        json.dumps(bootstrap_data()).encode("ascii") + b"\x00"
    )
    (candidate / "bootstrap.json").chmod(0o600)
    assert run(binary, candidate, "bootstrap", check=False).returncode != 0


def ca_and_file_boundaries(binary: Path, root: Path) -> None:
    pki = setup(binary, root, "bootstrap-mode")
    (pki / "bootstrap.json").chmod(0o644)
    assert run(binary, pki, "bootstrap", check=False).returncode != 0

    pki = setup(binary, root, "ca-mode")
    (pki / "controller-ca.pem").chmod(0o644)
    assert run(binary, pki, "bootstrap", check=False).returncode != 0

    pki = setup(binary, root, "ca-nonca")
    (pki / "controller-ca.pem").write_bytes((pki / "input-nonca.pem").read_bytes())
    (pki / "controller-ca.pem").chmod(0o600)
    assert run(binary, pki, "bootstrap", check=False).returncode != 0

    pki = setup(binary, root, "bootstrap-symlink")
    original = pki / "bootstrap-real.json"
    (pki / "bootstrap.json").rename(original)
    (pki / "bootstrap.json").symlink_to(original)
    assert run(binary, pki, "bootstrap", check=False).returncode != 0

    pki = setup(binary, root, "ca-symlink")
    original = pki / "ca-real.pem"
    (pki / "controller-ca.pem").rename(original)
    (pki / "controller-ca.pem").symlink_to(original)
    assert run(binary, pki, "bootstrap", check=False).returncode != 0

    pki = setup(binary, root, "bootstrap-hardlink")
    os.link(pki / "bootstrap.json", pki / "bootstrap-hardlink.json")
    assert run(binary, pki, "bootstrap", check=False).returncode != 0

    pki = setup(binary, root, "ca-hardlink")
    os.link(pki / "controller-ca.pem", pki / "ca-hardlink.pem")
    assert run(binary, pki, "bootstrap", check=False).returncode != 0

    pki = setup(binary, root, "directory-mode")
    pki.chmod(0o755)
    assert run(binary, pki, "bootstrap", check=False).returncode != 0


def certificate_contract(binary: Path, root: Path) -> None:
    for certificate in (
        "input-wrong-key.der", "input-wrong-san.der", "input-no-eku.der",
        "input-client-ca.der", "input-untrusted.der",
    ):
        pki = setup(binary, root, "reject-" + certificate)
        identity = (pki / "identity.ed25519").read_bytes()
        result = run(binary, pki, "store", certificate, check=False)
        assert result.returncode != 0
        assert not (pki / "client-cert.der").exists()
        assert not (pki / "enrollment.json").exists()
        assert (pki / "identity.ed25519").read_bytes() == identity
        assert TOKEN not in result.stdout + result.stderr

    pki = setup(binary, root, "valid-store")
    identity = (pki / "identity.ed25519").read_bytes()
    valid = (pki / "input-valid.der").read_bytes()
    first = run(binary, pki, "store", "input-valid.der")
    metadata = json.loads((pki / "enrollment.json").read_text(encoding="ascii"))
    assert fields(first.stdout)["state"] == "mtls_pending"
    assert metadata["state"] == "mtls_pending"
    assert metadata["controller_host"] == "ac.example.test"
    assert metadata["controller_port"] == 9443
    assert metadata["ap_id"] == "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    assert metadata["certificate_fingerprint"] == "sha256:" + hashlib.sha256(valid).hexdigest()
    assert TOKEN not in json.dumps(metadata)
    assert "private" not in json.dumps(metadata).lower()
    assert (pki / "client-cert.der").read_bytes() == valid
    assert (pki / "identity.ed25519").read_bytes() == identity
    assert_secure(pki / "client-cert.der")
    assert_secure(pki / "enrollment.json")
    second = run(binary, pki, "store", "input-valid.der")
    assert fields(second.stdout)["state"] == "mtls_pending"
    assert (pki / "identity.ed25519").read_bytes() == identity
    validated = run(binary, pki, "validate")
    assert fields(validated.stdout)["state"] == "mtls_pending"

    processes = [
        subprocess.Popen(
            [str(binary), "store", "input-valid.der"],
            env={**os.environ, "DREAMINGWRT_APD_PKI_DIR": str(pki)},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        for _ in range(12)
    ]
    results = [process.communicate(timeout=15) + (process.returncode,) for process in processes]
    assert all(returncode == 0 for _, _, returncode in results)
    assert all(TOKEN not in stdout + stderr for stdout, stderr, _ in results)


def residue_recovery(binary: Path, root: Path) -> None:
    pki = setup(binary, root, "cert-only")
    valid = (pki / "input-valid.der").read_bytes()
    (pki / "client-cert.der").write_bytes(valid)
    (pki / "client-cert.der").chmod(0o600)
    assert not (pki / "enrollment.json").exists()
    result = run(binary, pki, "store", "input-valid.der")
    assert fields(result.stdout)["state"] == "mtls_pending"
    assert run(binary, pki, "validate", check=False).returncode == 0

    pki = setup(binary, root, "metadata-only")
    run(binary, pki, "store", "input-valid.der")
    (pki / "client-cert.der").unlink()
    assert (pki / "enrollment.json").exists()
    assert run(binary, pki, "store", "input-valid.der", check=False).returncode != 0
    assert run(binary, pki, "validate", check=False).returncode != 0

    pki = setup(binary, root, "cert-tamper")
    run(binary, pki, "store", "input-valid.der")
    (pki / "client-cert.der").write_bytes(b"not-a-certificate")
    (pki / "client-cert.der").chmod(0o600)
    assert run(binary, pki, "store", "input-valid.der", check=False).returncode != 0
    assert run(binary, pki, "validate", check=False).returncode != 0

    pki = setup(binary, root, "metadata-tamper")
    run(binary, pki, "store", "input-valid.der")
    metadata = json.loads((pki / "enrollment.json").read_text(encoding="ascii"))
    metadata["certificate_fingerprint"] = "sha256:" + "0" * 64
    (pki / "enrollment.json").write_text(json.dumps(metadata), encoding="ascii")
    (pki / "enrollment.json").chmod(0o600)
    assert run(binary, pki, "store", "input-valid.der", check=False).returncode != 0
    assert run(binary, pki, "validate", check=False).returncode != 0

    for filename in ("client-cert.der", "enrollment.json"):
        pki = setup(binary, root, "symlink-" + filename)
        run(binary, pki, "store", "input-valid.der")
        original = pki / (filename + ".real")
        (pki / filename).rename(original)
        (pki / filename).symlink_to(original)
        assert run(binary, pki, "validate", check=False).returncode != 0

        pki = setup(binary, root, "hardlink-" + filename)
        run(binary, pki, "store", "input-valid.der")
        os.link(pki / filename, pki / (filename + ".hardlink"))
        assert run(binary, pki, "validate", check=False).returncode != 0

        pki = setup(binary, root, "mode-" + filename)
        run(binary, pki, "store", "input-valid.der")
        (pki / filename).chmod(0o644)
        assert run(binary, pki, "validate", check=False).returncode != 0

    pki = setup(binary, root, "identity-tamper")
    donor = setup(binary, root, "identity-tamper-donor")
    run(binary, pki, "store", "input-valid.der")
    (pki / "identity.ed25519").write_bytes((donor / "identity.ed25519").read_bytes())
    (pki / "identity.ed25519").chmod(0o600)
    assert run(binary, pki, "validate", check=False).returncode != 0

    pki = setup(binary, root, "ca-tamper")
    donor = setup(binary, root, "ca-tamper-donor")
    run(binary, pki, "store", "input-valid.der")
    (pki / "controller-ca.pem").write_bytes((donor / "controller-ca.pem").read_bytes())
    (pki / "controller-ca.pem").chmod(0o600)
    assert run(binary, pki, "validate", check=False).returncode != 0


def activation_and_crash_window(binary: Path, root: Path) -> None:
    pki = setup(binary, root, "activate-alias")
    run(binary, pki, "store", "input-valid.der")
    aliased = run(binary, pki, "activate-alias")
    assert fields(aliased.stdout)["state"] == "adopted"
    assert not (pki / "bootstrap.json").exists()
    assert json.loads((pki / "enrollment.json").read_text())["state"] == "adopted"

    pki = setup(binary, root, "activate-wrong")
    run(binary, pki, "store", "input-valid.der")
    assert run(binary, pki, "activate-wrong", check=False).returncode != 0
    assert (pki / "bootstrap.json").exists()
    assert json.loads((pki / "enrollment.json").read_text())["state"] == "mtls_pending"

    pki = setup(binary, root, "activate-crash")
    run(binary, pki, "store", "input-valid.der")
    failed = run(
        binary, pki, "activate", check=False,
        extra_env={"APD_CREDENTIALS_TEST_FAIL_ADOPT_COMMIT_ONCE": "1"},
    )
    assert failed.returncode != 0
    assert "state=adopted" not in failed.stdout
    assert not (pki / "bootstrap.json").exists()
    assert json.loads((pki / "enrollment.json").read_text())["state"] == "mtls_pending"
    pending = run(binary, pki, "validate")
    assert fields(pending.stdout)["state"] == "mtls_pending"
    adopted = run(binary, pki, "activate")
    assert fields(adopted.stdout)["state"] == "adopted"
    assert not (pki / "bootstrap.json").exists()
    assert json.loads((pki / "enrollment.json").read_text())["state"] == "adopted"
    assert fields(run(binary, pki, "validate").stdout)["state"] == "adopted"
    restarted = fields(run(binary, pki, "validate").stdout)
    assert restarted["controller_host"] == "ac.example.test"
    assert restarted["controller_port"] == "9443"
    assert fields(run(binary, pki, "activate").stdout)["state"] == "adopted"

    (pki / "bootstrap.json").write_text("{}", encoding="ascii")
    (pki / "bootstrap.json").chmod(0o600)
    assert run(binary, pki, "validate", check=False).returncode != 0


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="apd-credentials-") as temporary:
        root = Path(temporary)
        binary = root / "apd-credentials-fixture"
        compile_fixture(binary)
        bootstrap_contract(binary, root)
        ca_and_file_boundaries(binary, root)
        certificate_contract(binary, root)
        residue_recovery(binary, root)
        activation_and_crash_window(binary, root)
    print(
        "ok: APD credentials enforce strict bootstrap, certificate identity, "
        "atomic recovery, adoption, and fail-closed file boundaries"
    )


if __name__ == "__main__":
    main()

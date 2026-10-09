#!/usr/bin/env python3
"""Isolated runtime checks for console TLS identity and default HTTPS wiring."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
TLS_SOURCE = ROOT / "files/usr/libexec/dreamingwrt/dreamingwrt-web-tls-cert"
TLS_DEFAULT = ROOT / "files/etc/uci-defaults/90-dreamingwrt-web-tls"
TLS_ENABLE = ROOT / "files/usr/libexec/dreamingwrt/dreamingwrt-web-tls-enable"
TLS_RENEW = ROOT / "files/etc/uci-defaults/91-dreamingwrt-web-tls-renew"
ROOT_REDIRECT = (
    ROOT / "files/etc/nginx/conf.d/dreamingwrt-root-redirect.locations"
)
MAKEFILE = ROOT / "Makefile"


def write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def run(command: list[str], *, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, env=env, capture_output=True, text=True)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _build_tls_sandbox(sandbox: Path) -> dict:
    """Stand up an isolated copy of the cert tool with fake uci/ip/nginx/proc.

    Returns the rewritten script path plus the handles a test needs to drive it
    (env, cert/key paths, the uci state file, and the nginx pass/fail toggle).
    """
    cert_dir = sandbox / "tls"
    fake_bin = sandbox / "bin"
    fake_proc = sandbox / "proc"
    fake_init = sandbox / "nginx-init"
    state = sandbox / "uci-state"
    nginx_mode = sandbox / "nginx-mode"
    script = sandbox / "dreamingwrt-web-tls-cert"
    fake_bin.mkdir()
    (fake_proc / "123").mkdir(parents=True)
    (fake_proc / "123/cmdline").write_bytes(b"nginx: master process\0")
    state.write_text("router\nconsole.example\n", encoding="utf-8")
    nginx_mode.write_text("ok\n", encoding="utf-8")

    source = TLS_SOURCE.read_text(encoding="utf-8")
    source = source.replace(
        'CERT_DIR="/etc/dreamingwrt/tls"',
        f'CERT_DIR="{cert_dir}"',
    )
    source = source.replace(
        "for p in /proc/[0-9]*; do",
        f'for p in "{fake_proc}"/[0-9]*; do',
    )
    source = source.replace("/etc/init.d/nginx reload", f'"{fake_init}" reload')
    write_executable(script, source)
    write_executable(
        fake_bin / "uci",
        "#!/bin/sh\n"
        f"state='{state}'\n"
        "key=''\n"
        "for key in \"$@\"; do :; done\n"
        "case \"$key\" in\n"
        "  *.hostname) sed -n '1p' \"$state\" ;;\n"
        "  *.console_domain) sed -n '2p' \"$state\" ;;\n"
        "esac\n",
    )
    write_executable(
        fake_bin / "ip",
        "#!/bin/sh\n"
        "printf '%s\\n' '2: lan0    inet 192.168.50.1/24 brd 192.168.50.255 scope global lan0'\n",
    )
    write_executable(fake_bin / "logger", "#!/bin/sh\nexit 0\n")
    write_executable(
        fake_bin / "nginx",
        "#!/bin/sh\n"
        f"grep -q '^ok$' '{nginx_mode}'\n",
    )
    write_executable(fake_init, "#!/bin/sh\nexit 0\n")
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
    return {
        "script": script,
        "env": env,
        "cert_dir": cert_dir,
        "cert": cert_dir / "console.crt",
        "key": cert_dir / "console.key",
        "state": state,
        "nginx_mode": nginx_mode,
    }


def test_tls_san_refresh_and_rollback() -> None:
    with tempfile.TemporaryDirectory(prefix="dreamingwrt-tls-") as raw:
        box = _build_tls_sandbox(Path(raw))
        script, env = box["script"], box["env"]
        cert_dir, cert, key = box["cert_dir"], box["cert"], box["key"]
        state, nginx_mode = box["state"], box["nginx_mode"]

        generated = run([str(script), "force"], env=env)
        assert generated.returncode == 0, generated.stderr
        cert = cert_dir / "console.crt"
        key = cert_dir / "console.key"
        assert cert.stat().st_mode & 0o777 == 0o644
        assert key.stat().st_mode & 0o777 == 0o600
        san = run(
            ["openssl", "x509", "-in", str(cert), "-noout", "-ext", "subjectAltName"],
            env=env,
        )
        assert san.returncode == 0, san.stderr
        for expected in (
            "DNS:router.local",
            "DNS:console.example",
            "IP Address:192.168.50.1",
        ):
            assert expected in san.stdout, san.stdout

        original_cert = digest(cert)
        state.write_text("router\nchanged.example\n", encoding="utf-8")
        ensured = run([str(script), "ensure"], env=env)
        assert ensured.returncode == 0, ensured.stderr
        assert digest(cert) != original_cert
        changed = run(
            ["openssl", "x509", "-in", str(cert), "-noout", "-ext", "subjectAltName"],
            env=env,
        )
        assert "DNS:changed.example" in changed.stdout

        before_failed_cert = digest(cert)
        before_failed_key = digest(key)
        state.write_text("router\nfailed.example\n", encoding="utf-8")
        nginx_mode.write_text("fail\n", encoding="utf-8")
        refreshed = run([str(script), "refresh"], env=env)
        assert refreshed.returncode != 0
        assert digest(cert) == before_failed_cert
        assert digest(key) == before_failed_key


def test_validity_window_under_apple_398_cap_and_renew_is_idempotent() -> None:
    import datetime

    def validity_days(cert: Path, env: dict[str, str]) -> float:
        out = run(
            ["openssl", "x509", "-in", str(cert), "-noout", "-startdate", "-enddate"],
            env=env,
        )
        assert out.returncode == 0, out.stderr
        stamps: dict[str, datetime.datetime] = {}
        for line in out.stdout.splitlines():
            if "=" not in line:
                continue
            field, value = line.split("=", 1)
            # openssl space-pads single-digit days ("Aug  9 ..."); normalise it.
            stamps[field.strip()] = datetime.datetime.strptime(
                " ".join(value.split()), "%b %d %H:%M:%S %Y %Z"
            )
        return (stamps["notAfter"] - stamps["notBefore"]).total_seconds() / 86400.0

    with tempfile.TemporaryDirectory(prefix="dreamingwrt-tls-cap-") as raw:
        box = _build_tls_sandbox(Path(raw))
        script, env, cert = box["script"], box["env"], box["cert"]

        assert run([str(script), "force"], env=env).returncode == 0
        window = validity_days(cert, env)
        # Apple's SecPolicyCreateSSL rejects any leaf whose validity window
        # exceeds ~398 days (errSecCertificateValidityPeriodTooLong), which is
        # the root cause the Front->Back handoff is fixing. Safari/Chrome apply
        # the same web-PKI hygiene rule.
        assert window <= 398, f"validity window {window:.1f}d exceeds Apple's 398-day cap"
        assert window >= 30, f"validity window {window:.1f}d is implausibly short"

        # A freshly minted cert is still good, so `renew` must be a pure no-op:
        # it may not churn the key/fingerprint that local clients pin per-connection.
        before = digest(cert)
        renewed = run([str(script), "renew"], env=env)
        assert renewed.returncode == 0, renewed.stderr
        assert digest(cert) == before

        # But once the covered SANs drift, `renew` re-signs and hot-reloads nginx
        # (via refresh), so a periodic run is self-healing rather than inert.
        box["state"].write_text("router\nmoved.example\n", encoding="utf-8")
        rolled = run([str(script), "renew"], env=env)
        assert rolled.returncode == 0, rolled.stderr
        assert digest(cert) != before
        san = run(
            ["openssl", "x509", "-in", str(cert), "-noout", "-ext", "subjectAltName"],
            env=env,
        )
        assert "DNS:moved.example" in san.stdout


def test_default_https_and_ip_recovery_contract() -> None:
    default = TLS_DEFAULT.read_text(encoding="utf-8")
    makefile = MAKEFILE.read_text(encoding="utf-8")
    redirect = ROOT_REDIRECT.read_text(encoding="utf-8")

    assert '"$ENABLE_TOOL" enable-ssl' in default
    assert "dreamingwrt-web-tls-enable enable-ssl" in makefile
    assert 'if ($host ~ "^[0-9]{1,3}(\\\\.[0-9]{1,3}){3}$")' in redirect
    assert 'if ($host ~ ":") { return 302 /app/; }' in redirect
    assert "return 302 https://$host/app/;" in redirect
    # The renewal cron must actually ship and be wired to the tool's renew mode.
    assert "renew)" in TLS_SOURCE.read_text(encoding="utf-8")
    assert "91-dreamingwrt-web-tls-renew" in makefile
    renew_text = TLS_RENEW.read_text(encoding="utf-8")
    assert "dreamingwrt-web-tls-cert" in renew_text
    assert "renew" in renew_text
    assert "/etc/crontabs/root" in renew_text
    subprocess.run(["sh", "-n", str(TLS_SOURCE)], check=True)
    subprocess.run(["sh", "-n", str(TLS_DEFAULT)], check=True)
    subprocess.run(["sh", "-n", str(TLS_ENABLE)], check=True)
    subprocess.run(["sh", "-n", str(TLS_RENEW)], check=True)


if __name__ == "__main__":
    test_tls_san_refresh_and_rollback()
    test_validity_window_under_apple_398_cap_and_renew_is_idempotent()
    test_default_https_and_ip_recovery_contract()
    print("ok: console TLS SAN refresh, rollback, 398-day cap, renew, and HTTPS wiring")

#!/usr/bin/env python3
"""Exercise setup actor persistence through real forked webd HTTP workers."""

import http.client
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time


PORT = int(os.environ.get("WEBD_SETUP_TEST_PORT", "19117"))


def request(path: str, cookie: str = "", forwarded: str = "192.0.2.10",
            body=None):
    headers = {
        "Content-Type": "application/json",
        "Sec-Fetch-Site": "same-origin",
        "X-Forwarded-For": forwarded,
    }
    if cookie:
        headers["Cookie"] = cookie
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=5)
    conn.request("POST", path, body=json.dumps(body or {}), headers=headers)
    response = conn.getresponse()
    payload = response.read().decode("utf-8")
    result = (response.status, dict(response.getheaders()), json.loads(payload))
    conn.close()
    return result


def totp(secret: str, timestamp: int | None = None) -> str:
    timestamp = int(time.time()) if timestamp is None else timestamp
    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))
    counter = (timestamp // 30).to_bytes(8, "big")
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return f"{binary % 1_000_000:06d}"


def wait_http() -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=1)
            conn.request("GET", "/api/v1/health")
            conn.getresponse().read()
            conn.close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("isolated webd did not become ready")


def run_inside_namespace() -> int:
    root = Path(os.environ["WEBD_SETUP_TEST_ROOT"])
    webd = os.environ["WEBD_SETUP_TEST_BINARY"]
    fixture = os.environ["WEBD_SETUP_TEST_FIXTURE"]
    ubusd = os.environ["WEBD_SETUP_TEST_UBUSD"]
    library_path = os.environ["WEBD_SETUP_TEST_LIBRARY_PATH"]
    logs = root / "logs"
    fixture_ready = logs / "fixture.ready"
    logs.mkdir(exist_ok=True)
    target_env = os.environ.copy()
    target_env["LD_LIBRARY_PATH"] = library_path
    target_env["WEBD_SETUP_TEST_FIXTURE_READY"] = str(fixture_ready)

    processes = []
    try:
        processes.append(subprocess.Popen(
            [ubusd], stdout=(logs / "ubusd.log").open("wb"),
            stderr=subprocess.STDOUT, env=target_env))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if Path("/var/run/ubus/ubus.sock").exists():
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("isolated ubusd socket not ready")

        processes.append(subprocess.Popen(
            [fixture], stdout=(logs / "fixture.log").open("wb"),
            stderr=subprocess.STDOUT, env=target_env))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if fixture_ready.exists():
                break
            if processes[-1].poll() is not None:
                raise RuntimeError("isolated ubus fixture exited before registration")
            time.sleep(0.05)
        else:
            raise RuntimeError("isolated ubus fixture did not register")
        processes.append(subprocess.Popen(
            [webd, str(PORT), "127.0.0.1"],
            stdout=(logs / "webd.log").open("wb"),
            stderr=subprocess.STDOUT, env=target_env))
        wait_http()

        status, headers, _ = request("/api/setup/start")
        assert status == 200, status
        set_cookie = headers.get("Set-Cookie", "")
        assert "dwrt_setup=" in set_cookie
        assert "HttpOnly" in set_cookie and "SameSite=Strict" in set_cookie
        cookie = set_cookie.split(";", 1)[0]
        token = cookie.split("=", 1)[1]
        assert len(token) == 64

        status, _, _ = request("/api/setup/save-device", cookie=cookie)
        assert status == 200, status
        status, _, body = request("/api/setup/save-device")
        assert status == 401 and "setup_session_required" in json.dumps(body), body
        status, _, body = request("/api/setup/start", forwarded="192.0.2.11")
        assert status == 409 and "setup_session_active" in json.dumps(body), body

        db = sqlite3.connect("/etc/dreamingwrt/apid.db")
        row = db.execute(
            "SELECT token_hash,client_ip,expires_at>created_at FROM setup_sessions WHERE id=1"
        ).fetchone()
        db.close()
        assert row and len(row[0]) == 64 and row[0] != token, row
        assert row[1] == "192.0.2.10" and row[2] == 1, row

        db = sqlite3.connect("/etc/dreamingwrt/config.db")
        now = int(time.time())
        db.execute(
            "INSERT INTO web_users(username,password_hash,status,role,"
            "permissions_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            ("first-admin", "fixture-hash", "enabled", "admin", "[]", now, now),
        )
        db.commit()
        db.close()

        status, _, body = request(
            "/api/setup/security/2fa/prepare", cookie=cookie)
        assert status == 200, (status, body)
        data = body["data"]
        secret = data["secret"]
        assert data["username"] == "first-admin"
        assert data["setup_actor_bound"] is True

        db = sqlite3.connect("/etc/dreamingwrt/apid.db")
        challenge = db.execute(
            "SELECT twofa_username,twofa_secret_hash,twofa_prepared_at "
            "FROM setup_sessions WHERE id=1"
        ).fetchone()
        db.close()
        assert challenge and challenge[0] == "first-admin", challenge
        assert len(challenge[1]) == 64 and challenge[1] != secret, challenge
        assert challenge[2] > 0

        status, _, body = request(
            "/api/setup/security/2fa/enable", cookie=cookie,
            body={"secret": secret, "code": totp(secret),
                  "username": "attacker-selected"})
        assert status == 200, (status, body)
        assert body["data"]["username"] == "first-admin", body

        db = sqlite3.connect("/etc/dreamingwrt/config.db")
        enabled = db.execute(
            "SELECT twofa_enabled,twofa_secret FROM web_users "
            "WHERE username='first-admin'"
        ).fetchone()
        db.close()
        assert enabled == (1, secret), enabled
        db = sqlite3.connect("/etc/dreamingwrt/apid.db")
        consumed = db.execute(
            "SELECT twofa_username,twofa_secret_hash,twofa_prepared_at "
            "FROM setup_sessions WHERE id=1"
        ).fetchone()
        db.close()
        assert consumed == ("", "", 0), consumed

        status, headers, body = request(
            "/api/setup/finish", cookie=cookie,
            body={"actor": "request-forged", "completed_by": "request-forged",
                  "version": "request-forged"})
        assert status == 200, (status, body)
        finished = body["data"]
        assert finished["finish_readback_verified"] is True
        assert finished["setup_finished_by"].startswith("setup:")
        assert finished["setup_finished_by"] != "request-forged"
        assert finished["setup_version"] == "fixture-1"
        assert "Max-Age=0" in headers.get("Set-Cookie", "")
        db = sqlite3.connect("/etc/dreamingwrt/apid.db")
        assert db.execute(
            "SELECT COUNT(*) FROM setup_sessions").fetchone()[0] == 0
        db.close()
        print("ok: setup actor, 2FA challenge, finish readback and cleanup verified")
        return 0
    finally:
        for process in reversed(processes):
            process.terminate()
        for process in reversed(processes):
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def main() -> int:
    if os.environ.get("WEBD_SETUP_TEST_IN_NAMESPACE") == "1":
        return run_inside_namespace()

    required = {
        "WEBD_SETUP_TEST_BINARY",
        "WEBD_SETUP_TEST_FIXTURE",
        "WEBD_SETUP_TEST_UBUSD",
        "WEBD_SETUP_TEST_LIBRARY_PATH",
    }
    missing = sorted(name for name in required if not os.environ.get(name))
    if missing:
        raise SystemExit("missing environment: " + ", ".join(missing))
    if os.geteuid() != 0:
        raise SystemExit("runtime test requires root for an isolated mount namespace")

    base = os.environ.get("WEBD_SETUP_TEST_BASE")
    if base:
        Path(base).mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="webd-setup-session-", dir=base) as tmp:
        root = Path(tmp)
        for name in ("bin", "etc", "tmp", "run", "logs"):
            (root / name).mkdir()
        (root / "run" / "ubus").mkdir()
        env = os.environ.copy()
        staged_webd = root / "bin" / "dreamingwrt-webd"
        staged_fixture = root / "bin" / "setup-session-ubus-fixture"
        shutil.copy2(env["WEBD_SETUP_TEST_BINARY"], staged_webd)
        shutil.copy2(env["WEBD_SETUP_TEST_FIXTURE"], staged_fixture)
        env["WEBD_SETUP_TEST_BINARY"] = str(staged_webd)
        env["WEBD_SETUP_TEST_FIXTURE"] = str(staged_fixture)
        env["WEBD_SETUP_TEST_ROOT"] = str(root)
        env["WEBD_SETUP_TEST_IN_NAMESPACE"] = "1"
        script = Path(__file__).resolve()
        shell = """
set -eu
mount --make-rprivate /
mount --bind "$WEBD_SETUP_TEST_ROOT/etc" /etc/dreamingwrt
mount --bind "$WEBD_SETUP_TEST_ROOT/tmp" /tmp
mount --bind "$WEBD_SETUP_TEST_ROOT/run" /run
exec python3 "$1"
"""
        return subprocess.call(
            ["unshare", "--mount", "/bin/sh", "-c", shell, "sh", str(script)],
            env=env,
        )


if __name__ == "__main__":
    sys.exit(main())

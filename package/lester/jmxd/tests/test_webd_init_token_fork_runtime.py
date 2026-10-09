#!/usr/bin/env python3
"""First-run setup token must survive across forked request children.

Runs a real webd in an isolated mount namespace: /etc/dreamingwrt, /tmp and /run
are bind-mounted to a scratch dir, so no real device or DB is touched. Covers the
acceptance criteria of
Acceptance-to-Backend-P0-setup-token-lost-across-forked-request-children.md
"""
import http.client, json, os, shutil, sqlite3, subprocess, sys, tempfile, time
from pathlib import Path

PORT = int(os.environ.get("WEBD_TOKEN_TEST_PORT", "19231"))
APIDB = "/etc/dreamingwrt/apid.db"
CFGDB = "/etc/dreamingwrt/config.db"
FAILED = []
LOGS = None

def req(method, path, body=None, forwarded=None):
    h = {"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"}
    if forwarded:
        h["X-Forwarded-For"] = forwarded
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    c.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
    r = c.getresponse()
    raw = r.read().decode()
    c.close()
    try:
        return r.status, json.loads(raw)
    except json.JSONDecodeError:
        return r.status, {"_raw": raw}

def check(name, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + name + (f"\n        {detail}" if detail else ""))
    if not cond:
        FAILED.append(name)

def flat(o, n=150):
    return json.dumps(o)[:n]

def login():
    st, body = req("POST", "/api/v1/session/login",
                   {"username": "root", "password": "password"})
    d = body.get("data", body)
    return st, d, d.get("setup_token", "")

def init(token=None, username="acceptadmin", password="TokenTest#2026", forwarded=None):
    body = {"username": username, "password": password, "confirm_password": password}
    if token is not None:
        body["setup_token"] = token
    return req("POST", "/api/v1/session/init", body, forwarded=forwarded)

def token_row():
    db = sqlite3.connect(APIDB)
    row = db.execute("SELECT token_hash,boot_id,created_at,expires_at "
                     "FROM webd_init_tokens WHERE id=1").fetchone()
    db.close()
    return row

def users():
    db = sqlite3.connect(CFGDB)
    rows = db.execute("SELECT username,role FROM web_users").fetchall()
    db.close()
    return rows

def wipe_users():
    db = sqlite3.connect(CFGDB)
    db.execute("DELETE FROM web_users")
    db.commit(); db.close()

def start_webd(env, tag):
    p = subprocess.Popen([env["WEBD_TOKEN_TEST_BINARY"], str(PORT), "127.0.0.1"],
                         stdout=(LOGS / f"webd-{tag}.log").open("wb"),
                         stderr=subprocess.STDOUT, env=env)
    end = time.monotonic() + 20
    while time.monotonic() < end:
        if p.poll() is not None:
            raise RuntimeError(f"webd exited early rc={p.returncode}")
        try:
            c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=1)
            c.request("GET", "/api/v1/health"); c.getresponse().read(); c.close()
            return p
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("webd never became ready")

def stop(p):
    if p and p.poll() is None:
        p.terminate()
        try: p.wait(timeout=5)
        except subprocess.TimeoutExpired: p.kill(); p.wait()

def inside():
    global LOGS
    root = Path(os.environ["WEBD_TOKEN_TEST_ROOT"])
    LOGS = root / "logs"; LOGS.mkdir(exist_ok=True)
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = os.environ["WEBD_TOKEN_TEST_LIBRARY_PATH"]
    ubusd = os.environ.get("WEBD_TOKEN_TEST_UBUSD", "")
    procs = []
    webd = None
    try:
        if ubusd and Path(ubusd).exists():
            procs.append(subprocess.Popen([ubusd], stdout=(LOGS/"ubusd.log").open("wb"),
                                          stderr=subprocess.STDOUT, env=env))
            time.sleep(0.4)
        webd = start_webd(env, "run1"); procs.append(webd)

        st, d, _ = 0, {}, ""
        st, body = req("GET", "/api/v1/session/init")
        d = body.get("data", body)
        check("[pre] fresh device reports uninitialized",
              d.get("initialized") is False and d.get("user_count") == 0, flat(d))

        # --- criterion 1: issue in one child, verify in another -------------
        st, d, token = login()
        check("[1a] default login issues a 64-hex setup_token",
              st == 200 and len(token) == 64, f"status={st} len={len(token)}")
        row = token_row()
        check("[1b] token stored as a hash (never plaintext), with boot id + future TTL",
              bool(row) and len(row[0]) == 64 and row[0] != token
              and row[1] != "" and row[3] > row[2],
              f"hash={row[0][:16] if row else None}... boot={row[1][:8] if row else None} ttl={row[3]-row[2] if row else None}s")

        st, body = init(token=None)
        check("[1c] init WITHOUT a token is still refused",
              st == 400 and "invalid_initial_setup_token" in flat(body, 400), f"status={st}")

        st, body = init(token=token)
        d = body.get("data", body)
        check("[1d] THE FIX: init accepts a token issued by a different forked child",
              st == 200 and d.get("ok") is True and d.get("username") == "acceptadmin",
              f"status={st} {flat(d)}")
        check("[1e] the admin account really exists",
              ("acceptadmin", "admin") in users(), str(users())[:120])
        check("[1f] token row cleared after a successful consume",
              token_row() is None, str(token_row()))

        # --- criterion 2: one-shot -----------------------------------------
        # Drop the user so the users>0 short-circuit cannot mask the token check.
        wipe_users()
        st, body = init(token=token, username="replayadmin")
        check("[2] a consumed token cannot be reused",
              st == 400 and "invalid_initial_setup_token" in flat(body, 400),
              f"status={st} {flat(body)}")
        check("[2b] no account created by the replay", users() == [], str(users())[:80])

        # --- criterion 3: TTL ---------------------------------------------
        st, d, token3 = login()
        db = sqlite3.connect(APIDB)
        db.execute("UPDATE webd_init_tokens SET expires_at=? WHERE id=1",
                   (int(time.time()) - 5,))
        db.commit(); db.close()
        st, body = init(token=token3, username="expiredadmin")
        check("[3] an expired token is refused",
              st == 400 and "invalid_initial_setup_token" in flat(body, 400),
              f"status={st} {flat(body)}")
        check("[3b] expiry drops the row, so expired and never-issued converge",
              token_row() is None, str(token_row()))

        # --- criterion 5: non-local source --------------------------------
        st, body = req("POST", "/api/v1/session/login",
                       {"username": "root", "password": "password"},
                       forwarded="203.0.113.7")
        check("[5] a token is still issued for a loopback peer despite a remote XFF",
              st == 200, f"status={st} {flat(body)}")

        # --- criterion 4: token must not survive a webd restart -----------
        st, d, token4 = login()
        row_before = token_row()
        check("[4a] token present before restart", bool(row_before), str(row_before)[:60])
        stop(webd); procs.remove(webd)
        webd = start_webd(env, "run2"); procs.append(webd)
        check("[4b] restart clears the stored token row (chosen semantics: "
              "tokens do NOT survive a webd restart)", token_row() is None,
              str(token_row()))
        st, body = init(token=token4, username="restartadmin")
        check("[4c] a pre-restart token is refused after restart",
              st == 400 and "invalid_initial_setup_token" in flat(body, 400),
              f"status={st} {flat(body)}")

        # --- criterion 6: already-initialized device ----------------------
        st, d, token6 = login()
        st, body = init(token=token6, username="realadmin")
        check("[6a] a fresh token still works after all of the above",
              st == 200, f"status={st} {flat(body)}")
        st, d2, token6b = login()
        st, body = init(token=token6b or token6, username="secondadmin")
        check("[6b] an initialized device answers web_users_already_initialized",
              "web_users_already_initialized" in flat(body, 400), f"status={st} {flat(body)}")
        return 0 if not FAILED else 1
    finally:
        for pr in reversed(procs):
            stop(pr)
        if FAILED:
            for lg in sorted(LOGS.glob("webd-*.log")):
                print(f"--- {lg.name} tail ---")
                print("\n".join(lg.read_text(errors="replace").splitlines()[-15:]))

def main():
    if os.environ.get("WEBD_TOKEN_TEST_IN_NS") == "1":
        return inside()
    required = {"WEBD_TOKEN_TEST_BINARY", "WEBD_TOKEN_TEST_LIBRARY_PATH"}
    missing = sorted(n for n in required if not os.environ.get(n))
    if missing:
        raise SystemExit("missing environment: " + ", ".join(missing))
    if os.geteuid() != 0:
        raise SystemExit("needs root for an isolated mount namespace")
    base = os.environ.get("WEBD_TOKEN_TEST_BASE", "/var/tmp")
    Path(base).mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="webd-token-", dir=base) as tmp:
        root = Path(tmp)
        for n in ("bin", "etc", "tmp", "run", "logs"):
            (root/n).mkdir()
        (root/"run"/"ubus").mkdir()
        staged = root/"bin"/"dreamingwrt-webd"
        shutil.copy2(os.environ["WEBD_TOKEN_TEST_BINARY"], staged)
        env = os.environ.copy()
        env["WEBD_TOKEN_TEST_BINARY"] = str(staged)
        env["WEBD_TOKEN_TEST_ROOT"] = str(root)
        env["WEBD_TOKEN_TEST_IN_NS"] = "1"
        env.setdefault("WEBD_TOKEN_TEST_SCRIPT", str(Path(__file__).resolve()))
        shell = """
set -eu
mount --make-rprivate /
mkdir -p /etc/dreamingwrt
mount --bind "$WEBD_TOKEN_TEST_ROOT/etc" /etc/dreamingwrt
mount --bind "$WEBD_TOKEN_TEST_ROOT/run" /run
mount --bind "$WEBD_TOKEN_TEST_ROOT/tmp" /tmp
exec python3 "$1"
"""
        return subprocess.call(["unshare", "--mount", "/bin/sh", "-c", shell,
                                "sh", env["WEBD_TOKEN_TEST_SCRIPT"]], env=env)

if __name__ == "__main__":
    sys.exit(main())

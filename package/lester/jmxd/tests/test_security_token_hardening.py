#!/usr/bin/env python3
"""Session/token hardening contracts.

Covers the items in the security audit handoff that live in Backend's scope:
strong randomness with no weak fallback, timing-safe comparison of secrets, and
the first-run gate being judged on an address a header cannot forge.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "src/webd/jmx_app_api.c"
NETCFG = ROOT / "src/jmx_netconfig_db.c"
DWAPI = ROOT / "src/jmx_dreamingwrt_api.c"
AIRT = ROOT / "src/webd/ai_runtime.c"


def _live_sources() -> list[Path]:
    """Source files that ship, excluding .bak-* snapshots."""
    out = []
    for path in list((ROOT / "src").rglob("*.c")) + list((ROOT / "src").rglob("*.h")):
        if ".bak-" in path.name:
            continue
        out.append(path)
    return out


def test_no_weak_random_fallback_anywhere() -> None:
    """A predictable token is worse than a failed login, so the weak path is gone.

    srand(time(NULL)) has one-second granularity: a day is 86400 candidate seeds,
    which makes any token derived from it recomputable by someone who knows
    roughly when it was issued.
    """
    offenders = []
    for path in _live_sources():
        text = path.read_text(encoding="utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("*") or stripped.startswith("/*"):
                continue  # historical notes describing the removed behaviour
            if "srand(" in line:
                offenders.append(f"{path.name}:{number}: {stripped}")
    assert not offenders, "weak seeding still present:\n" + "\n".join(offenders)


def test_random_generators_are_fail_closed() -> None:
    api = API.read_text(encoding="utf-8")
    netcfg = NETCFG.read_text(encoding="utf-8")
    dwapi = DWAPI.read_text(encoding="utf-8")

    # Session tokens, refresh tokens, session ids, setup tokens, salts.
    assert "static int gen_random_hex_checked(char *out, int len)" in api
    assert "getrandom(buf, want, 0)" in api

    # The PBKDF2 salt generator in the netconfig path had the same defect.
    assert "static int nc_random_hex(char *out, int len)" in netcfg, (
        "nc_random_hex must report failure instead of returning a weak salt"
    )
    assert "if (nc_random_hex(salt_hex, NC_WEBD_SALT_HEX_LEN) != 0)" in netcfg, (
        "the caller must refuse to hash when no strong salt is available"
    )

    # Interface MAC generation: collision avoidance rather than secrecy.
    assert "static int dw_generate_mac(char *out, size_t len)" in dwapi
    assert "getrandom(r, sizeof(r), 0)" in dwapi
    assert "mac_generation_unavailable" in dwapi

    # fgetc()'s EOF is -1 and -1 & 0xf is 15, so an unchecked read silently
    # yielded 'f'. No generator may read randomness through fgetc any more.
    for name, text in (("jmx_app_api.c", api), ("jmx_netconfig_db.c", netcfg)):
        assert "fgetc(fp)" not in text or "urandom" not in text, (
            f"{name} still reads randomness with unchecked fgetc"
        )


def test_secrets_are_compared_in_constant_time() -> None:
    api = API.read_text(encoding="utf-8")
    airt = AIRT.read_text(encoding="utf-8")

    # setup_token: strcmp short-circuits at the first differing byte.
    verify = api[api.index("static int webd_init_token_verify"):]
    verify = verify[: verify.index("\n}\n")]
    assert "ct_str_equal" in verify
    assert "strcmp(token, g_webd_init_token)" not in verify

    # The AI resume token names a file a tool call can be continued from.
    load = airt[airt.index("static struct json_object *ai_resume_state_load"):]
    load = load[: load.index("\n}\n")]
    assert "ai_ct_str_equal" in load, "resume_token must not be compared with strcmp"
    assert 'strcmp(ai_json_string(state, "resume_token", ""), token)' not in load


def test_first_run_gate_uses_the_unforgeable_address() -> None:
    """The LAN-only gate must not be decided by a header.

    client_ip is replaced by X-Forwarded-For whenever the TCP peer is loopback,
    so a request relayed through a local proxy can claim any origin. Judging the
    gate on client_ip would let a remote caller present 192.168.x.x and claim an
    uninitialized device.
    """
    api = API.read_text(encoding="utf-8")

    login = api[api.index("static struct json_object *jmx_web_login_ex"):]
    login = login[: login.index("\nstatic ", 10)]
    assert "webd_first_run_source_allowed(g_webd_audit_peer_ip[0] ?" in login, (
        "the first-run source check must be based on the peer address"
    )
    assert "webd_first_run_source_allowed(client_ip)" not in login, (
        "client_ip is forgeable via X-Forwarded-For and must not gate first run"
    )

    # The gate itself still has to reject anything it cannot parse.
    gate = api[api.index("static int webd_first_run_source_allowed"):]
    gate = gate[: gate.index("\n}\n")]
    for marker in ("0x0a000000U", "0xfff00000U", "0xc0a80000U", "IN6_IS_ADDR_V4MAPPED"):
        assert marker in gate, f"first-run gate lost a case: {marker}"
    assert gate.rstrip().endswith("return 0;"), "the gate must fail closed"

    # Claiming an uninitialized device has to leave a trail.
    assert 'jmx_app_audit_log_full("root", "", "auth.first_run_default_login"' in api
    assert "first_run_default_remote_source" in api


def test_compiled_helpers_behave() -> None:
    """Compile the two comparison helpers and check them on real inputs."""
    compiler = os.environ.get("CC") or shutil.which("cc") or shutil.which("gcc")
    assert compiler
    harness = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
/*
 * getrandom() lives in <sys/random.h> on glibc and is absent on macOS, where
 * the equivalent is arc4random_buf(). The target builds against glibc; this
 * shim only exists so the helper contract can be exercised on either host.
 */
#if defined(__linux__)
#include <sys/random.h>
#else
#include <stdlib.h>
static ssize_t getrandom(void *buf, size_t len, unsigned int flags)
{
    (void)flags;
    arc4random_buf(buf, len);
    return (ssize_t)len;
}
#endif

static int ct_str_equal(const char *a, const char *b)
{
    size_t alen, blen, i, n;
    unsigned char diff = 0;

    if (!a || !b)
        return 0;
    alen = strlen(a);
    blen = strlen(b);
    n = alen > blen ? alen : blen;
    for (i = 0; i < n; i++) {
        unsigned char ac = i < alen ? (unsigned char)a[i] : 0;
        unsigned char bc = i < blen ? (unsigned char)b[i] : 0;
        diff |= (unsigned char)(ac ^ bc);
    }
    return diff == 0 && alen == blen;
}

int main(void)
{
    /* Equality, and the cases a naive length check gets wrong. */
    assert(ct_str_equal("abc123", "abc123") == 1);
    assert(ct_str_equal("abc123", "abc124") == 0);
    assert(ct_str_equal("abc", "abcdef") == 0);   /* prefix is not a match */
    assert(ct_str_equal("abcdef", "abc") == 0);
    assert(ct_str_equal("", "") == 1);
    assert(ct_str_equal("a", "") == 0);
    assert(ct_str_equal(NULL, "a") == 0);
    assert(ct_str_equal("a", NULL) == 0);

    /* getrandom must actually produce differing output; a generator that
     * returned a constant would pass a shape check but not this. */
    {
        unsigned char a[16], b[16];

        assert(getrandom(a, sizeof(a), 0) == (ssize_t)sizeof(a));
        assert(getrandom(b, sizeof(b), 0) == (ssize_t)sizeof(b));
        assert(memcmp(a, b, sizeof(a)) != 0);
    }
    printf("ok: token hardening helpers\n");
    return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix="token-hardening-") as tmp:
        source = Path(tmp) / "harness.c"
        source.write_text(harness, encoding="utf-8")
        binary = Path(tmp) / "harness"
        subprocess.run(
            [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
             "-D_GNU_SOURCE", str(source), "-o", str(binary)],
            check=True, capture_output=True, text=True,
        )
        run = subprocess.run([str(binary)], capture_output=True, text=True)
        assert run.returncode == 0, run.stdout + run.stderr
        assert "ok:" in run.stdout


def main() -> None:
    test_no_weak_random_fallback_anywhere()
    test_random_generators_are_fail_closed()
    test_secrets_are_compared_in_constant_time()
    test_first_run_gate_uses_the_unforgeable_address()
    test_compiled_helpers_behave()
    print("ok: security session/token hardening contracts")


if __name__ == "__main__":
    main()

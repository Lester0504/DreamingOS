#!/usr/bin/env python3
"""Compile and run the shared ct_appid lookup fixture.

The rich realtime flow path and the compact connection snapshot must agree on
one parser, one sort order and one tuple match rule for the kernel's
per-connection appid export. This test guards that shared surface on the host,
without needing a device.
"""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "src" / "tests" / "test_ct_appid_shared_lookup.c"
SNAPSHOT = ROOT / "src" / "client_connections_snapshot.c"

READ_MODEL_STUB = """
#include <json-c/json.h>
void *dw_rm_create(void) { return 0; }
void dw_rm_destroy(void *r) { (void)r; }
int dw_rm_start(void *r) { (void)r; return -1; }
int dw_rm_view_begin(void *r, void *v) { (void)r; (void)v; return -1; }
void dw_rm_view_end(void *v) { (void)v; }
int dw_rm_view_delta_at(void *v, unsigned long long a, void *b)
{ (void)v; (void)a; (void)b; return -1; }
int dw_rm_resume_begin(void *a, void *b, unsigned long long c, void *d)
{ (void)a; (void)b; (void)c; (void)d; return -1; }
struct json_object *dw_rm_resync_json(void *a) { (void)a; return 0; }
struct json_object *dw_rm_status_json(void *a) { (void)a; return 0; }
"""


def _brew_prefix(package: str) -> str:
    brew = shutil.which("brew")
    if not brew:
        return ""
    try:
        out = subprocess.run([brew, "--prefix", package], check=True,
                             capture_output=True, text=True)
    except subprocess.CalledProcessError:
        return ""
    return out.stdout.strip()


def test_ct_appid_shared_lookup() -> None:
    cflags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT / "src")]
    ldflags = ["-lcrypto", "-ljson-c"]
    for package in ("openssl@3", "json-c"):
        prefix = _brew_prefix(package)
        if prefix:
            cflags += ["-I", f"{prefix}/include"]
            ldflags += ["-L", f"{prefix}/lib"]
    with tempfile.TemporaryDirectory(prefix="ct-appid-") as raw:
        work = Path(raw)
        stub = work / "read_model_stub.c"
        stub.write_text(READ_MODEL_STUB)
        binary = work / "fixture"
        subprocess.run(
            [os.environ.get("CC", "cc")] + cflags +
            [str(FIXTURE), str(SNAPSHOT), str(stub), "-o", str(binary)] + ldflags,
            check=True, capture_output=True, text=True,
        )
        completed = subprocess.run([str(binary)], cwd=work, check=True,
                                   capture_output=True, text=True)
        assert "ct_appid shared lookup tests: ok" in completed.stdout


if __name__ == "__main__":
    test_ct_appid_shared_lookup()
    print("ok: ct_appid shared lookup")

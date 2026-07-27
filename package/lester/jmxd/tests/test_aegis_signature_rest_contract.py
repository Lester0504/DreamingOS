#!/usr/bin/env python3
"""Aegis signature-policy REST, RBAC, validation, and audit contracts."""

from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text(encoding="utf-8")


def test_rest_routes_and_validation() -> None:
    for path in (
        "/api/v1/aegis/signature-policy",
        "/api/v1/aegis/signatures/policies",
        "/api/v1/aegis/signatures/suppress",
        "/api/v1/aegis/signatures/unsuppress",
    ):
        assert path in WEB
        assert path in PERMS
    for marker in (
        '"signature_policies"',
        '"set_signature_policy"',
        '"suppress_signature"',
        '"unsuppress_signature"',
        '"invalid_signature_id"',
        '"signature_revision_mismatch"',
        '"revision_conflict"',
        'parsed > 500',
    ):
        assert marker in WEB


def test_writes_are_audited_and_csrf_guarded() -> None:
    for operation in (
        "aegis.signature_policy.set",
        "aegis.signature.suppress",
        "aegis.signature.unsuppress",
    ):
        assert operation in WEB
    csrf = WEB[WEB.index("if ((!strncmp(req.path, \"/api/v1/uploads\""):]
    assert '!strncmp(req.path, "/api/v1/aegis/", 14)' in csrf[:6000]


def test_rbac_is_executable() -> None:
    harness = r'''
#include <assert.h>
#include "jmx_app_perms.h"
int main(void) {
    assert(jmx_perm_route_risk("GET", "/api/v1/aegis/signature-policy") == JMX_RISK_LOW);
    assert(jmx_perm_route_risk("PUT", "/api/v1/aegis/signature-policy") == JMX_RISK_MEDIUM);
    assert(jmx_perm_route_risk("GET", "/api/v1/aegis/signatures/policies") == JMX_RISK_LOW);
    assert(jmx_perm_route_risk("POST", "/api/v1/aegis/signatures/suppress") == JMX_RISK_MEDIUM);
    assert(jmx_perm_check(JMX_ROLE_ADMIN, JMX_RISK_MEDIUM));
    assert(!jmx_perm_check(JMX_ROLE_VIEWER, JMX_RISK_MEDIUM));
    return 0;
}
'''
    with tempfile.TemporaryDirectory() as td:
        source = Path(td) / "signature_rest_perms.c"
        binary = Path(td) / "signature_rest_perms"
        source.write_text(harness, encoding="utf-8")
        subprocess.run([
            "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-I", str(ROOT / "src/webd"), str(source),
            str(ROOT / "src/webd/jmx_app_perms.c"), "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"ok: {len(tests)} Aegis signature REST tests")

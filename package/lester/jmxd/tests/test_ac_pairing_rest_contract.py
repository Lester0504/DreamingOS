#!/usr/bin/env python3
"""AC pairing management REST, RBAC, CSRF, audit, and boundary contracts."""

from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    offset = text.index(start)
    return text[offset:text.index(end, offset)]


def test_rest_routes_use_only_ac_ubus_management_methods() -> None:
    routes = between(WEB, "/* ── AC controller management plane ── */",
                     "/* ── Multicast ── */")
    for path in (
        "/api/v1/ac/status",
        "/api/v1/ac/capabilities",
        "/api/v1/ac/pairing-tokens",
        "/api/v1/ac/pairing-tokens/",
    ):
        assert path in routes
    for method in (
        "status",
        "capabilities",
        "pairing_token_list",
        "pairing_token_status",
        "pairing_token_create",
        "pairing_token_revoke",
    ):
        assert f'"{method}"' in routes
    assert routes.count('"dreamingwrt.ac"') == 6
    assert "pairing_token_redeem" not in routes
    assert "/redeem" not in WEB
    assert "config.db" not in routes
    assert "ac_pairing_tokens" not in routes
    assert "sqlite3_prepare" not in routes


def test_writes_are_csrf_guarded_and_secret_safe_audited() -> None:
    csrf = between(WEB, 'if ((!strncmp(req.path, "/api/v1/uploads"',
                   "const char *required_permission")
    assert '!strncmp(req.path, "/api/v1/ac/pairing-tokens", 25)' in csrf
    routes = between(WEB, "/* ── AC controller management plane ── */",
                     "/* ── Multicast ── */")
    assert "ac.pairing_token.create" in routes
    assert "ac.pairing_token.revoke" in routes
    assert "webd_ac_audit_reserve" in routes
    assert "webd_ac_audit_finish" in routes
    assert "ac.pairing_token.rate_limited" in routes
    assert "invalid_token_id" in routes
    assert "WEBD_AC_PAIRING_WRITES_PER_MINUTE 10" in WEB
    audit = between(WEB, "static int webd_ac_audit_reserve",
                    "static void webd_ac_audit_finish")
    assert "BEGIN IMMEDIATE" in audit and "COMMIT" in audit
    assert "actor=?2 AND source_ip=?3" in audit
    for forbidden in ("hardware_digest", '"token"', "body_json"):
        assert forbidden not in audit


def test_create_normalizes_only_strict_bounded_fields() -> None:
    helper = between(WEB, "static struct json_object *webd_ac_create_params",
                     "static int webd_ac_http_status")
    for field in ("ttl_seconds", "max_attempts", "site_id", "hardware_digest"):
        assert field in helper
    assert "json_object_object_foreach" in helper
    assert "json_type_int" in helper
    assert "json_type_string" in helper
    assert "ttl_seconds < 60" in helper and "ttl_seconds > 86400" in helper
    assert "max_attempts < 1" in helper and "max_attempts > 10" in helper


def test_rbac_is_executable() -> None:
    harness = r'''
#include <assert.h>
#include "jmx_app_perms.h"
int main(void) {
    assert(jmx_perm_route_risk("GET", "/api/v1/ac/status") == JMX_RISK_LOW);
    assert(jmx_perm_route_risk("HEAD", "/api/v1/ac/capabilities") == JMX_RISK_LOW);
    assert(jmx_perm_route_risk("GET", "/api/v1/ac/pairing-tokens") == JMX_RISK_LOW);
    assert(jmx_perm_route_risk("GET", "/api/v1/ac/pairing-tokens/123") == JMX_RISK_LOW);
    assert(jmx_perm_route_risk("POST", "/api/v1/ac/pairing-tokens") == JMX_RISK_MEDIUM);
    assert(jmx_perm_route_risk("DELETE", "/api/v1/ac/pairing-tokens/123") == JMX_RISK_MEDIUM);
    assert(jmx_perm_check(JMX_ROLE_ADMIN, JMX_RISK_MEDIUM));
    assert(jmx_perm_check(JMX_ROLE_OWNER, JMX_RISK_MEDIUM));
    assert(!jmx_perm_check(JMX_ROLE_OPERATOR, JMX_RISK_MEDIUM));
    assert(!jmx_perm_check(JMX_ROLE_VIEWER, JMX_RISK_MEDIUM));
    return 0;
}
'''
    with tempfile.TemporaryDirectory() as raw:
        directory = Path(raw)
        source = directory / "ac_rest_perms.c"
        binary = directory / "ac_rest_perms"
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
    print(f"ok: {len(tests)} AC pairing management REST contracts")

#!/usr/bin/env python3
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text(encoding="utf-8")
MAKEFILE = (ROOT / "src/Makefile").read_text(encoding="utf-8")
AGGREGATE = (ROOT / "src/webd/webd_vpn_aggregate.c").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    offset = text.index(start)
    return text[offset:text.index(end, offset)]


def test_read_routes_and_single_aggregation_source() -> None:
    routes = between(WEB, "/* ── VPN management v1", "/* ── WAN DNS policy")
    for path in (
        "/api/v1/vpn",
        "/api/v1/vpn/servers",
        "/api/v1/vpn/clients",
        "/api/v1/vpn/site-to-site",
        "/api/v1/vpn/accounts",
        "/api/v1/vpn/certificates",
    ):
        assert path in routes
    assert "webd_vpn_management_response" in routes
    helper = between(WEB, "static struct json_object *webd_vpn_management_response",
                     "static struct json_object *webd_vpn_write_disabled_response")
    assert '"vpn_config_get"' in helper
    assert '"vpn_status"' in helper
    assert "webd_vpn_aggregate_data" in helper
    assert "webd_vpn_resource_view" in helper
    assert "vpn_config_set" not in helper
    assert "vpn_config_apply" not in helper
    assert "webd/webd_vpn_aggregate.o" in MAKEFILE


def test_runtime_unknowns_are_null_and_legacy_fake_zero_fields_are_not_copied() -> None:
    for field in (
        'vpn_add_null(runtime, "connected")',
        'vpn_add_null(runtime, "last_handshake_at")',
        'vpn_add_null(runtime, "duration_seconds")',
        'vpn_add_null(runtime, "latency_ms")',
        'vpn_add_null(runtime, "rx_rate")',
        'vpn_add_null(runtime, "tx_rate")',
        'vpn_add_null(summary, "active_tunnels")',
        'vpn_add_null(summary, "online_users")',
    ):
        assert field in AGGREGATE
    assert '"users_online"' not in AGGREGATE
    assert '"transfer"' not in AGGREGATE
    assert 'vpn_copy(settings, row, "latency")' not in AGGREGATE
    assert '"protocol_session_probe_not_implemented"' in AGGREGATE
    assert '"authoritative_rate_sampler_not_available"' in AGGREGATE


def test_all_rest_writes_fail_closed_without_ubus_side_effects() -> None:
    routes = between(WEB, "/* ── VPN management v1", "/* ── WAN DNS policy")
    rejection = between(WEB, "static struct json_object *webd_vpn_write_disabled_response",
                        "static int webd_port_preference_column_allowed")
    assert "capability_disabled" in rejection
    for field in ('"persisted"', '"applied"', '"changed"', '"rollback_available"'):
        assert field in rejection
    assert "vpn_config_set" not in routes
    assert "vpn_config_apply" not in routes
    assert "webd_vpn_write_disabled_response" in routes
    assert '"transaction", json_object_new_boolean(0)' in AGGREGATE
    assert '"readback", json_object_new_boolean(0)' in AGGREGATE
    assert '"rollback", json_object_new_boolean(0)' in AGGREGATE


def test_permissions_are_executable_and_cookie_writes_are_csrf_guarded() -> None:
    harness = r'''
#include <assert.h>
#include "jmx_app_perms.h"
int main(void) {
    assert(jmx_perm_route_risk("GET", "/api/v1/vpn") == JMX_RISK_LOW);
    assert(jmx_perm_route_risk("GET", "/api/v1/vpn/servers") == JMX_RISK_LOW);
    assert(jmx_perm_route_risk("POST", "/api/v1/vpn") == JMX_RISK_HIGH);
    assert(jmx_perm_route_risk("DELETE", "/api/v1/vpn/servers/id") == JMX_RISK_HIGH);
    assert(jmx_perm_route_risk("GET", "/api/v1/services/vpn") == JMX_RISK_LOW);
    assert(jmx_perm_route_risk("POST", "/api/v1/services/vpn") == JMX_RISK_HIGH);
    assert(jmx_perm_route_risk("POST", "/api/v1/services/vpn/apply") == JMX_RISK_HIGH);
    assert(jmx_perm_check(JMX_ROLE_OWNER, JMX_RISK_HIGH));
    assert(!jmx_perm_check(JMX_ROLE_ADMIN, JMX_RISK_HIGH));
    return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix="vpn-management-contract-") as raw:
        directory = Path(raw)
        source = directory / "permissions.c"
        executable = directory / "permissions"
        source.write_text(harness, encoding="utf-8")
        subprocess.run([
            "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-I", str(ROOT / "src/webd"), str(source),
            str(ROOT / "src/webd/jmx_app_perms.c"), "-o", str(executable),
        ], check=True)
        subprocess.run([str(executable)], check=True)

    csrf = between(WEB, 'if ((!strncmp(req.path, "/api/v1/uploads"',
                   "const char *required_permission")
    assert '!strncmp(req.path, "/api/v1/vpn", 11)' in csrf
    assert "strcmp(req.method, \"GET\")" in csrf
    assert "!webd_cookie_write_csrf_ok(&req)" in csrf


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"ok: {len(tests)} VPN management backend contract tests")

#!/usr/bin/env python3
"""Aegis app-block REST, RBAC, CSRF, and audit contracts."""

from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text(encoding="utf-8")


def test_rest_routes_forward_only_to_core_contract() -> None:
    for path in (
        "/api/v1/aegis/app-blocks",
        "/api/v1/aegis/app-blocks/validate",
        "/api/v1/aegis/app-blocks/",
    ):
        assert path in WEB
        assert path in PERMS
    for method in (
        "aegis_app_blocks",
        "aegis_app_block_validate",
        "aegis_app_block_upsert",
        "aegis_app_block_delete",
    ):
        assert f'"{method}"' in WEB
    route = WEB[WEB.index('!strcmp(req.path, "/api/v1/aegis/app-blocks")'):]
    route = route[:route.index('else if ((!strcmp(req.path, "/api/v1/aegis/geo")')]
    assert "network_control_save" not in route
    assert "network_control_apply" not in route
    assert "nft" not in route.lower()
    assert '"revision_conflict"' in route
    assert '"aegis_app_block_not_found"' in route
    assert '"rule_not_found"' in route


def test_writes_are_audited_and_csrf_guarded() -> None:
    for operation in (
        "aegis.app_block.create",
        "aegis.app_block.update",
        "aegis.app_block.delete",
    ):
        assert operation in WEB
    csrf = WEB[WEB.index('if ((!strncmp(req.path, "/api/v1/uploads"'):]
    assert '!strncmp(req.path, "/api/v1/aegis/", 14)' in csrf[:6000]


def test_rbac_is_executable() -> None:
    harness = r'''
#include <assert.h>
#include "jmx_app_perms.h"
int main(void) {
    assert(jmx_perm_route_risk("GET", "/api/v1/aegis/app-blocks") == JMX_RISK_LOW);
    assert(jmx_perm_route_risk("POST", "/api/v1/aegis/app-blocks") == JMX_RISK_MEDIUM);
    assert(jmx_perm_route_risk("POST", "/api/v1/aegis/app-blocks/validate") == JMX_RISK_LOW);
    assert(jmx_perm_route_risk("GET", "/api/v1/aegis/app-blocks/rule-1") == JMX_RISK_LOW);
    assert(jmx_perm_route_risk("PUT", "/api/v1/aegis/app-blocks/rule-1") == JMX_RISK_MEDIUM);
    assert(jmx_perm_route_risk("DELETE", "/api/v1/aegis/app-blocks/rule-1") == JMX_RISK_MEDIUM);
    assert(jmx_perm_check(JMX_ROLE_ADMIN, JMX_RISK_MEDIUM));
    assert(!jmx_perm_check(JMX_ROLE_VIEWER, JMX_RISK_MEDIUM));
    return 0;
}
'''
    with tempfile.TemporaryDirectory() as td:
        source = Path(td) / "app_block_rest_perms.c"
        binary = Path(td) / "app_block_rest_perms"
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
    print(f"ok: {len(tests)} Aegis app-block REST tests")

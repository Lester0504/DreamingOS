#!/usr/bin/env python3
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text(encoding="utf-8")


def test_geo_read_merges_control_and_runtime() -> None:
    assert "webd_geo_block_response" in WEB
    assert 'app_ubus_invoke("firewall_geo_block_get", NULL)' in WEB
    assert 'app_ubus_object_or_error("dreamingwrt.aegis", "geo_get", NULL)' in WEB
    assert '"geo-block.v3"' in WEB
    assert '"runtime_source"' in WEB
    assert '"dataplane_supported"' in WEB
    assert '"active_readback"' in WEB
    assert "webd_geo_runtime_response" in WEB
    assert 'if (http_status) *http_status = 200;' in WEB
    assert '"source_unavailable"' in WEB
    route = WEB[WEB.index('/* ── Geo-Block ── */'):WEB.index('/* ── Plugins ── */')]
    assert 'resp = webd_geo_block_response(&status);' in route
    assert 'jmx_cache_get("geo_block")' not in route


def test_legacy_save_is_revisioned_but_never_applies_nft() -> None:
    helper = WEB[WEB.index("static struct json_object *webd_geo_block_save"):
                 WEB.index("static void webd_mark_cached_response_stale")]
    assert '"dry_run", json_object_new_boolean(1)' in helper
    assert '"confirm", json_object_new_boolean(1)' in helper
    assert '"apply", json_object_new_boolean(0)' in helper
    assert '"revision", json_object_get(revision)' in helper
    assert "geo_apply" not in helper
    route = WEB[WEB.index('/* ── Geo-Block ── */'):WEB.index('/* ── Plugins ── */')]
    assert 'resp = webd_geo_block_save(body_json, &status);' in route


def test_guarded_geo_dataplane_routes_exist() -> None:
    for path, operation in (
        ("/api/v1/aegis/geo/preview", "preview"),
        ("/api/v1/aegis/geo/apply", "apply"),
        ("/api/v1/aegis/geo/disable", "disable"),
        ("/api/v1/aegis/geo/rollback", "rollback"),
    ):
        assert path in WEB
        assert f'webd_geo_runtime_invoke("{operation}", body_json)' in WEB
    assert 'app_ubus_object_or_error("dreamingwrt.aegis", "geo_apply", request)' in WEB
    assert '"guarded-confirm-revision-readback"' in WEB


def test_per_client_app_policy_fails_closed() -> None:
    marker = '"client_app_policy_scope_unsupported"'
    assert marker in WEB
    block = WEB[WEB.index('} else if (!strcmp(type_str, "app_block")'):
                WEB.index('} else if (!strcmp(type_str, "rate_limit")')]
    assert '"changed", json_object_new_boolean(0)' in block
    assert '"dataplane_changed", json_object_new_boolean(0)' in block
    assert "app_network_control_save_apply_ok" not in block
    assert 'status = 501;' in block


def test_geo_rbac_order_and_owner_only_runtime_apply() -> None:
    apply_rule = '{ "/api/v1/firewall/geo-block/apply", "POST", JMX_RISK_HIGH }'
    generic_rule = '{ "/api/v1/firewall/geo-block", "POST,PUT", JMX_RISK_MEDIUM }'
    assert PERMS.index(apply_rule) < PERMS.index(generic_rule)
    for path in ("apply", "disable", "rollback"):
        assert f'"/api/v1/aegis/geo/{path}"' in PERMS
        line = next(line for line in PERMS.splitlines()
                    if f'"/api/v1/aegis/geo/{path}"' in line)
        assert '"POST", JMX_RISK_HIGH' in line

    harness = r'''
#include <assert.h>
#include "jmx_app_perms.h"
int main(void) {
    assert(jmx_perm_route_risk("POST", "/api/v1/firewall/geo-block/apply") == JMX_RISK_HIGH);
    assert(jmx_perm_route_risk("POST", "/api/v1/firewall/geo-block/disable") == JMX_RISK_HIGH);
    assert(jmx_perm_route_risk("POST", "/api/v1/firewall/geo-block/rollback") == JMX_RISK_HIGH);
    assert(jmx_perm_route_risk("POST", "/api/v1/firewall/geo-block/preview") == JMX_RISK_LOW);
    assert(jmx_perm_route_risk("PUT", "/api/v1/firewall/geo-block") == JMX_RISK_MEDIUM);
    assert(!jmx_perm_check(JMX_ROLE_ADMIN, JMX_RISK_HIGH));
    assert(jmx_perm_check(JMX_ROLE_OWNER, JMX_RISK_HIGH));
    return 0;
}
'''
    with tempfile.TemporaryDirectory() as td:
        source = Path(td) / "geo_perms.c"
        binary = Path(td) / "geo_perms"
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
    print(f"ok: {len(tests)} Aegis Geo REST/RBAC/fail-closed tests")

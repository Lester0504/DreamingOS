#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NETCONFIG = (ROOT / "src/jmx_netconfig_db.c").read_text(encoding="utf-8")
CORE_API = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
WEB_API = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text(encoding="utf-8")


def test_geo_contract_exposes_complete_catalog_and_honest_capabilities():
    assert '"contract_version", json_object_new_string("geo-block.v2")' in NETCONFIG
    assert '"catalog_count"' in NETCONFIG
    assert 'catalog_count == 249' in NETCONFIG
    assert '"flag_url"' in NETCONFIG
    assert '"dataplane_supported", json_object_new_boolean(0)' in NETCONFIG
    assert '"mmdb_source", json_object_new_boolean(1)' in NETCONFIG
    assert '"selected_country_materialization", json_object_new_boolean(1)' in NETCONFIG
    assert '"sqlite_prefix_table_required", json_object_new_boolean(0)' in NETCONFIG
    assert '"mmdb_validation_deferred", json_object_new_boolean(prefix_ready)' in NETCONFIG
    assert '"geoip_country_mmdb_missing"' in NETCONFIG
    assert "geoip_country_prefix" not in NETCONFIG


def test_geo_write_is_strict_revisioned_and_confirmed():
    assert '"confirmation_required"' in NETCONFIG
    assert '"revision_required"' in NETCONFIG
    assert '"revision_conflict"' in NETCONFIG
    assert '"unknown_or_non_official_country"' in NETCONFIG
    assert '"duplicate_country"' in NETCONFIG
    assert '"invalid_geo_rule_action"' in NETCONFIG
    assert '"invalid_geo_rule_direction"' in NETCONFIG
    assert '"geo_apply_requires_aegisxd_guarded_endpoint", revision' in NETCONFIG


def test_geo_ubus_and_webd_preserve_structured_readback():
    handler_start = CORE_API.index("static int dw_handle_firewall_geo_block_set")
    handler_end = CORE_API.index("/* ═══ Plugins ubus handlers", handler_start)
    handler = CORE_API[handler_start:handler_end]
    assert "jmx_geo_block_update(payload)" in handler
    assert "dw_send_json(ctx, req, response)" in handler
    assert "dw_send_ok(ctx, req)" not in handler

    route_start = WEB_API.index('!strcmp(req.path, "/api/v1/firewall/geo-block") && (!strcmp(req.method, "POST")')
    route_end = WEB_API.index("/* ── Plugins ── */", route_start)
    route = WEB_API[route_start:route_end]
    assert 'app_ubus_invoke("firewall_geo_block_set", body_json)' in route
    assert "app_ubus_ok_only" not in route
    assert '"/api/v1/firewall/geo-block/validate"' in route
    assert '"revision_conflict"' in WEB_API


def test_geo_routes_are_classified_by_rbac():
    validate = '{ "/api/v1/firewall/geo-block/validate", "POST", JMX_RISK_LOW }'
    read = '{ "/api/v1/firewall/geo-block", "GET", JMX_RISK_LOW }'
    write = '{ "/api/v1/firewall/geo-block", "POST,PUT", JMX_RISK_MEDIUM }'
    assert validate in PERMS
    assert read in PERMS
    assert write in PERMS
    assert PERMS.index(validate) < PERMS.index(write)


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"ok: {len(tests)} Geo-block backend contract tests")

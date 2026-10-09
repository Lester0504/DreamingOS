#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT.parent))
from jmxd.tests.webd_sources import webd_module_text

MAIN = webd_module_text("jmx_app_api.c")
ROUTER = webd_module_text("api_router.c")
POLICY = webd_module_text("api_policy_read.c")
OBJECTS = webd_module_text("api_policy_objects.c")
OBJECTS_H = webd_module_text("api_policy_objects.h")


def test_only_policy_get_routes_moved_to_the_read_module() -> None:
    for seq, path, match in (
        (140, "/api/v1/policy-engine/policy-table", "JMX_API_EXACT"),
        (141, "/api/v1/policy-engine/policy-table/", "JMX_API_PREFIX"),
        (143, "/api/v1/policy-engine/catalog", "JMX_API_EXACT"),
    ):
        needle = f'JMX_API_ROUTE({seq}, "{path}", "GET", {match}'
        assert needle in POLICY
        assert needle not in MAIN
    assert '#include "api_policy_read.h"' in ROUTER
    assert '    policy_read_api_routes,' in ROUTER


def test_zone_and_object_routes_moved_to_the_objects_module() -> None:
    """Phase 5B: the zone / zone-matrix / object closure has one owner."""
    for needle in (
        'JMX_API_ROUTE(144, "/api/v1/policy-engine/zones", "GET", JMX_API_EXACT',
        'JMX_API_ROUTE(145, "/api/v1/policy-engine/zones", "POST", JMX_API_EXACT',
        'JMX_API_ROUTE(148, "/api/v1/policy-engine/zone-matrix", "GET", JMX_API_EXACT',
    ):
        assert needle in OBJECTS, needle
        assert needle not in MAIN, needle

    # The detail rows must stay predicate-owned. A plain prefix row would make
    # /zones/ a detail request whose id is empty, which the chain refused.
    for seq, methods in ((146, '"GET"'), (147, '"PUT,PATCH,DELETE"')):
        needle = (f'JMX_API_PREDICATE_ROUTE({seq}, '
                  f'"/api/v1/policy-engine/zones/", {methods}, '
                  f'JMX_API_PREDICATE_ONLY')
        assert needle in OBJECTS, needle
    for seq, methods in ((149, '"GET"'), (150, '"POST,PUT,PATCH,DELETE"')):
        needle = (f'JMX_API_PREDICATE_ROUTE({seq}, '
                  f'"/api/v1/policy-engine/objects", {methods}, '
                  f'JMX_API_PREDICATE_MIXED')
        assert needle in OBJECTS, needle

    assert '#include "api_policy_objects.h"' in ROUTER
    assert '    policy_objects_api_routes,' in ROUTER
    assert 'extern const struct jmx_api_route policy_objects_api_routes[];' \
        in OBJECTS_H

    # The legacy dispatch branches must be gone, not kept as dead duplicates.
    for branch in (
        'else if (!strcmp(req.path, "/api/v1/policy-engine/zones")',
        '!strcmp(req.path, "/api/v1/policy-engine/zone-matrix")',
        '!strcmp(req.path, "/api/v1/policy-engine/objects")',
    ):
        assert branch not in MAIN, branch


def test_policy_table_write_dispatch_has_one_module_owner() -> None:
    write = webd_module_text("api_policy_write.c")
    assert 'webd_policy_write_preview_response(&req, body_json, &status)' not in MAIN
    assert 'JMX_API_PREDICATE_ROUTE(142,' in write
    assert '"POST,PUT,PATCH,DELETE"' in write
    assert 'webd_policy_write_preview_response(ctx->req, ctx->body, &ctx->status)' in write
    assert '    policy_write_api_routes,' in ROUTER


if __name__ == "__main__":
    test_only_policy_get_routes_moved_to_the_read_module()
    test_zone_and_object_routes_moved_to_the_objects_module()
    test_policy_table_write_dispatch_has_one_module_owner()
    print("ok: policy read and policy object routes moved without removing "
          "policy-table write registration")

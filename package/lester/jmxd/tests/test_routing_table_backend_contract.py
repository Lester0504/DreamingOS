#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ROUTED = (ROOT / "src/routed/routed_control.c").read_text(encoding="utf-8")
WEBD = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text(encoding="utf-8")


def test_snapshot_has_one_authoritative_static_route_source() -> None:
    assert '#define ROUTED_CONTRACT_VERSION "routing.v1"' in ROUTED
    assert "static sqlite3_int64 routed_object_revision(sqlite3 *db)" in ROUTED
    snapshot = ROUTED[ROUTED.index("static struct json_object *routed_snapshot(void)"):]
    snapshot = snapshot[:snapshot.index("static struct json_object *routed_status_json")]
    assert '"revision", json_object_new_int64(routed_object_revision(db))' in snapshot
    assert '"source_of_truth", json_object_new_string("policy_table")' in ROUTED
    assert '"static_route_projection_source", json_object_new_string("uci:/etc/config/network route/route6")' in ROUTED
    assert '"legacy_static_route_table_projected", json_object_new_boolean(0)' in ROUTED
    projection = ROUTED[ROUTED.index("static struct json_object *routed_static_projection"):]
    projection = projection[:projection.index("static void routed_external_file")]
    assert 'uci_load(ctx, "network", &pkg)' in projection
    assert 'strcmp(s->type, "route")' in projection
    assert 'strcmp(s->type, "route6")' in projection
    assert '"uci-network-%s-%s-%d"' in projection
    assert '"source", json_object_new_string("uci:/etc/config/network")' in projection
    assert 'FROM static_route ORDER BY' not in projection


def test_independent_resources_and_runtime_boundaries_are_explicit() -> None:
    for capability in (
        "table_crud",
        "object_crud",
        "reference_conflict",
        "policy_reorder",
        "runtime_resolve",
        "cross_service_config_crud",
        "cross_service_runtime",
    ):
        assert f'"{capability}"' in ROUTED
    assert '"cross_service_runtime", json_object_new_boolean(0)' in ROUTED
    assert '"runtime_consumer_not_implemented"' in ROUTED
    for method in (
        "snapshot",
        "tables_list",
        "table_set",
        "table_delete",
        "objects_list",
        "object_set",
        "object_delete",
        "cross_services_list",
        "cross_service_set",
        "cross_service_delete",
        "policy_rules_reorder",
        "runtime_resolve",
        "external_policies",
    ):
        assert f'ROUTED_METHOD("{method}")' in ROUTED


def test_rest_routes_use_routed_and_are_permissioned() -> None:
    for path in (
        "/api/v1/routing",
        "/api/v1/routing/tables",
        "/api/v1/routing/objects",
        "/api/v1/routing/cross-services",
        "/api/v1/routing/policy-rules/reorder",
        "/api/v1/routing/runtime-resolve",
        "/api/v1/routing/external-policies",
    ):
        assert path in WEBD
    assert 'app_routed_call("snapshot", NULL)' in WEBD
    assert '"dreamingwrt.routed", method' in WEBD
    assert '{ "/api/v1/routing/tables", "POST,PUT,DELETE", JMX_RISK_MEDIUM }' in PERMS
    assert '{ "/api/v1/routing/objects", "POST,PUT,DELETE", JMX_RISK_MEDIUM }' in PERMS


def test_static_route_persists_user_name_and_comment() -> None:
    # Write path sets the schemaless UCI options name/comment.
    assert 'WEBD_POLICY_SET_ROUTE_OPTION(name_keys, "name")' in WEBD
    assert 'WEBD_POLICY_SET_ROUTE_OPTION(comment_keys, "comment")' in WEBD
    assert '"name", "label", "display_name"' in WEBD
    assert '"comment", "remark", "note", "description"' in WEBD
    # List read path prefers the persisted option name over the generated
    # "Static route <target>" label.
    assert 'webd_policy_uci_option(s, "name", route_name' in WEBD
    # routed projection already reads name + comment back.
    assert 'display_name' in ROUTED and 'comment' in ROUTED


def test_object_crud_scopes_are_distinguishable_across_components() -> None:
    """routed object_crud=1 and policy-engine objects_crud=0 describe different
    resources. Each side must publish its scope so a client can tell them apart
    instead of picking one and calling the other wrong."""
    assert '"object_crud_scope", json_object_new_string("routed:route_object")' in ROUTED
    assert '"object_crud_write_endpoint", json_object_new_string("/api/v1/routing/objects")' in ROUTED
    assert '"composite_object_crud", json_object_new_boolean(0)' in ROUTED
    assert '"composite_object_crud_owner", json_object_new_string("policy_engine")' in ROUTED

    assert '"objects_crud_scope",' in WEBD
    assert '"policy_engine:composite_object"' in WEBD
    assert '"route_object_crud", json_object_new_boolean(1)' in WEBD
    assert '"route_object_crud_owner", json_object_new_string("routed")' in WEBD
    assert '"route_object_write_endpoint",' in WEBD
    # The composite read_only flag must not read as "all objects are read only".
    assert '"read_only_scope", "policy_engine:composite_object"' in WEBD
    assert '"legacy_route_objects_read_only", json_object_new_boolean(0)' in WEBD
    assert '"legacy_route_objects_write_endpoint", "/api/v1/routing/objects"' in WEBD


def test_runtime_reason_is_scoped_per_resource_not_whole_page() -> None:
    """runtime_consumer_not_implemented applies to cross_services only. It was being
    rendered as a whole-page verdict for the routing table, so routed now scopes it
    and publishes per-resource reasons plus the writable resource list."""
    assert '"cross_service_runtime_reason_scope",' in ROUTED
    assert 'json_object_new_string("cross_services")' in ROUTED
    assert '"resource_reasons", reasons' in ROUTED
    assert '"cross_services_runtime",' in ROUTED
    assert '"writable_resources", writable' in ROUTED
    reasons = ROUTED[ROUTED.index('struct json_object *reasons = json_object_new_object();'):]
    reasons = reasons[:reasons.index('json_object_object_add(o, "resource_reasons", reasons);')]
    # Tables and objects are writable, so they must not carry a blocking reason.
    assert '"tables"' not in reasons
    assert '"objects"' not in reasons


if __name__ == "__main__":
    test_snapshot_has_one_authoritative_static_route_source()
    test_independent_resources_and_runtime_boundaries_are_explicit()
    test_rest_routes_use_routed_and_are_permissioned()
    test_static_route_persists_user_name_and_comment()
    test_object_crud_scopes_are_distinguishable_across_components()
    test_runtime_reason_is_scoped_per_resource_not_whole_page()
    print("ok: routed authoritative UCI projection, resources, runtime boundaries, REST, RBAC, name/comment, capability scopes")

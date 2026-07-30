#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
API = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")
PERMS = (ROOT / "src/webd/jmx_app_perms.c").read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    return text[first:text.index(end, first)]


capabilities = between(API, "static struct json_object *webd_policy_capabilities", "static void webd_policy_dynamic_filter_inc")
assert 'json_object_object_add(cap, "reorder", json_object_new_boolean(1))' in capabilities
assert '"reorder_supported_policy_types"' in capabilities
assert '"config.db:policy_route_rule"' in capabilities
assert '"reorder_mixed_sources_supported"' in capabilities

reorder = between(API, "static struct json_object *webd_policy_pbr_reorder_response", "static struct json_object *webd_policy_write_preview_response")
assert '"policy_route_rule."' in reorder
assert '"reorder_scope_conflict"' in reorder
assert 'app_routed_call("policy_rules_reorder", params)' in reorder
assert '"apply_requires_explicit_apply_true"' in reorder
assert 'app_routed_http_status(upstream, 200)' in reorder
assert 'webd_policy_uci_reorder_response' in reorder
assert 'uci_reorder_section(ctx, desired[i], i)' in reorder
assert '"reorder_full_scope_required"' in capabilities
assert '"reorder_uci_foreign_sections_preserved"' in capabilities

catalog = between(API, "static struct json_object *webd_policy_catalog_response", "static struct json_object *webd_policy_table_response")
for source in (
    "webd_policy_catalog_collect_devices",
    "webd_policy_catalog_collect_route_objects",
    "webd_policy_catalog_collect_flowd_objects",
    "webd_policy_catalog_collect_applications",
):
    assert source in catalog
assert 'strcasecmp(proto, "dhcpv6")' in API
assert '"wan6"' in API
assert '"dreamingwrt_signatures.db:app"' in API
assert '"dreamingwrt.flowd.objects"' in API
assert '"config.db:route_object"' in API
assert '"usable_by"' in API
assert '"sources"' in catalog
assert '"/api/v1/policy-engine/policy-table/"' in PERMS
assert 'JMX_RISK_MEDIUM' in PERMS

print("ok: policy catalog uses real sources and Policy Table reorder supports transactional PBR plus same-source UCI scopes")

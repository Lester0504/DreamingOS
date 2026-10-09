#!/usr/bin/env python3
"""The webd route matcher behaves like the if-else chain it replaces.

Phase 3A registered the first production table and Phase 3B adds predicate
matching for structured aliases. The fixture still drives matcher edge cases
with its own tables, and also verifies both production module arrays and order.

So the matcher is driven now, against tables the fixture owns, through the
`JMX_API_ROUTER_TEST_STANDALONE` hook (the same pattern `ac_transport.c` uses).
The shipped `api_router.c` is compiled, not a copy of it.

What is locked here is the part of the chain's behaviour that is easy to lose in
a table rewrite:

  * declaration order decides the winner, so an earlier prefix row keeps
    shadowing a longer path declared later, across module boundaries too;
  * `methods` is a comma list and "" means any method, matched whole rather than
    by prefix;
  * pre-auth and post-auth routes are strictly separated — a post-auth route
    reachable from the pre-auth point would run before the permission gate;
  * only a `JMX_API_RAW_FD` handler sees the socket; everyone else gets -1;
  * a miss leaves the caller's `*out` untouched;
  * a predicate augments a fixed path without bypassing method/pre-auth gates;
  * a predicate-owned row (PREDICATE_ONLY) does not match its own collection
    prefix, and a PREDICATE_MIXED row matches the collection plus the
    subresources its predicate accepts;
  * production tables preserve original route order across Phase 3B and 3A.

Each of those is then re-checked in reverse: the source is mutated in a scratch
copy and the fixture must go red. A green test against a mutated matcher would
mean the assertions describe nothing.
"""

from __future__ import annotations

from pathlib import Path
from functools import lru_cache
import os
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import apd_test_deps  # noqa: E402

WEBD_DIR = Path(os.environ.get("WEBD_SOURCE_DIR", ROOT / "src/webd"))
API_DIR = WEBD_DIR / "api"
ROUTER_C = API_DIR / "api_router.c"
FIXTURE = ROOT / "tests/api_router_fixture.c"

# Only the -I flags are wanted. api_context.h reaches webd_api_keys.h, which
# includes <sqlite3.h>, and api_router.h includes <json-c/json.h>; neither
# library is *called*, so linking them in would only import the LTO-archive
# trouble that apd_test_deps documents for 31.6.
HEADER_FLAGS = (apd_test_deps.split_package_flags("json-c")[0]
                + apd_test_deps.split_package_flags("sqlite3")[0])

# (label, needle, replacement, what the fixture should notice)
MUTATIONS = (
    (
        "preauth-split",
        "if (route_preauth != (preauth ? 1 : 0))",
        "if (0 && route_preauth != (preauth ? 1 : 0))",
        "a post-auth route becomes reachable from the pre-auth point",
    ),
    (
        "prefix-match",
        "fixed_match = !strncmp(path, route->path, strlen(route->path));",
        "fixed_match = !strcmp(path, route->path);",
        "prefix routes stop matching their subresources",
    ),
    (
        "exact-match",
        "fixed_match = !strcmp(path, route->path);",
        "fixed_match = !strncmp(path, route->path, strlen(route->path));",
        "exact routes start matching longer paths",
    ),
    (
        "method-whole-token",
        "if (method_len == len && !strncmp(method, p, len))",
        "if (!strncmp(method, p, len))",
        "a truncated method matches by prefix",
    ),
    (
        "fd-withheld",
        "ctx->fd = -1;",
        "(void)0;",
        "a non-RAW_FD handler is handed the live socket",
    ),
    (
        "predicate-match",
        "return route->predicate ? route->predicate(path) : 0;",
        "return 0;",
        "structured alias routes stop matching their predicate",
    ),
    (
        "policy-read-table-wiring",
        "    policy_read_api_routes,\n    policy_write_api_routes,",
        "    policy_write_api_routes,",
        "the Phase 5A Policy read module disappears from the table of tables",
    ),
    (
        "policy-write-table-wiring",
        "    policy_write_api_routes,\n",
        "",
        "the Phase 5C policy write module disappears from the table of tables",
    ),
    (
        "policy-objects-table-wiring",
        "    policy_objects_api_routes,\n    insights_api_routes,",
        "    insights_api_routes,",
        "the Phase 5B policy objects module disappears from the table of tables",
    ),
    (
        "routing-table-wiring",
        "    topology_api_routes,\n    routing_api_routes,\n    clients_list_api_routes,",
        "    topology_api_routes,\n    clients_list_api_routes,",
        "the Phase 5D routing module disappears from the table of tables",
    ),
    (
        "clients-list-table-wiring",
        "    routing_api_routes,\n    clients_list_api_routes,\n    client_control_api_routes,",
        "    routing_api_routes,\n    client_control_api_routes,",
        "the Phase 6A client-list module disappears from the table of tables",
    ),
    (
        "client-control-table-wiring",
        "    clients_list_api_routes,\n    client_control_api_routes,\n    client_connections_api_routes,",
        "    clients_list_api_routes,\n    client_connections_api_routes,",
        "the Phase 6B client-control module disappears from the table of tables",
    ),
    (
        "client-connections-table-wiring",
        "    client_control_api_routes,\n    client_connections_api_routes,\n    client_profile_api_routes,",
        "    client_control_api_routes,\n    client_profile_api_routes,",
        "the Phase 6C client-connections module disappears from the table of tables",
    ),
    (
        "client-profile-table-wiring",
        "    client_connections_api_routes,\n    client_profile_api_routes,\n    flowd_api_routes,",
        "    client_connections_api_routes,\n    flowd_api_routes,",
        "the Phase 6D client-profile module disappears from the table of tables",
    ),
    (
        "flowd-table-wiring",
        "    client_profile_api_routes,\n    flowd_api_routes,\n    aegis_api_routes,",
        "    client_profile_api_routes,\n    aegis_api_routes,",
        "the Phase 6E flowd module disappears from the table of tables",
    ),
    (
        "wifi-table-wiring",
        "    aegis_api_routes,\n    wifi_api_routes,\n    wifi_certificate_api_routes,",
        "    aegis_api_routes,\n    wifi_certificate_api_routes,",
        "the Phase 6G wifi module disappears from the table of tables",
    ),
    (
        "wifi-certificate-table-wiring",
        "    wifi_api_routes,\n    wifi_certificate_api_routes,\n    logd_api_routes,",
        "    wifi_api_routes,\n    logd_api_routes,",
        "the certificate lifecycle module disappears from the table of tables",
    ),
    (
        "logd-table-wiring",
        "    wifi_certificate_api_routes,\n    logd_api_routes,\n    notifyd_api_routes,",
        "    wifi_certificate_api_routes,\n    notifyd_api_routes,",
        "the Phase 6H logd module disappears from the table of tables",
    ),
    (
        "notifyd-table-wiring",
        "    logd_api_routes,\n    notifyd_api_routes,\n    audit_api_routes,",
        "    logd_api_routes,\n    audit_api_routes,",
        "the Phase 6I notifyd module disappears from the table of tables",
    ),
    (
        "audit-table-wiring",
        "    notifyd_api_routes,\n    audit_api_routes,\n    wan_api_routes,",
        "    notifyd_api_routes,\n    wan_api_routes,",
        "the Phase 6J audit BFF module disappears from the table of tables",
    ),
    (
        "wan-table-wiring",
        "    audit_api_routes,\n    wan_api_routes,\n    authentication_api_routes,",
        "    audit_api_routes,\n    authentication_api_routes,",
        "the Phase 6K WAN-policy BFF module disappears from the table of tables",
    ),
    (
        "authentication-table-wiring",
        "    wan_api_routes,\n    authentication_api_routes,\n    logs_api_routes,",
        "    wan_api_routes,\n    logs_api_routes,",
        "the Phase 6L authentication BFF module disappears from the table of tables",
    ),
    (
        "logs-table-wiring",
        "    authentication_api_routes,\n    logs_api_routes,\n    netcontrol_api_routes,",
        "    authentication_api_routes,\n    netcontrol_api_routes,",
        "the Phase 6N log-center BFF module disappears from the table of tables",
    ),
    (
        "netcontrol-table-wiring",
        "    logs_api_routes,\n    netcontrol_api_routes,\n    setup_api_routes,",
        "    logs_api_routes,\n    setup_api_routes,",
        "the Phase 6O network-control BFF module disappears from the table of tables",
    ),
    (
        "setup-table-wiring",
        "    netcontrol_api_routes,\n    setup_api_routes,\n    storage_api_routes,",
        "    netcontrol_api_routes,\n    storage_api_routes,",
        "the Phase 6P first-run setup wizard BFF module disappears from the table of tables",
    ),
    (
        "storage-table-wiring",
        "    setup_api_routes,\n    storage_api_routes,\n    bulkip_api_routes,",
        "    setup_api_routes,\n    bulkip_api_routes,",
        "the Phase 6Q storage management BFF module disappears from the table of tables",
    ),
    (
        "bulkip-table-wiring",
        "    storage_api_routes,\n    bulkip_api_routes,\n    config_api_routes,",
        "    storage_api_routes,\n    config_api_routes,",
        "the Phase 6R bulk-IP/IPAM BFF module disappears from the table of tables",
    ),
    (
        "config-table-wiring",
        "    bulkip_api_routes,\n    config_api_routes,\n    cloud_api_routes,",
        "    bulkip_api_routes,\n    cloud_api_routes,",
        "the Phase 6S transactional config BFF module disappears from the table of tables",
    ),
    (
        "cloud-table-wiring",
        "    config_api_routes,\n    cloud_api_routes,\n    support_api_routes,",
        "    config_api_routes,\n    support_api_routes,",
        "the Phase 6T cloud enrollment BFF module disappears from the table of tables",
    ),
    (
        "aegis-table-wiring",
        "    flowd_api_routes,\n    aegis_api_routes,\n    wifi_api_routes,",
        "    flowd_api_routes,\n    wifi_api_routes,",
        "the Phase 6F aegis module disappears from the table of tables",
    ),
    (
        "predicate-only-fixed-path",
        "    if (!(route->flags & JMX_API_PREDICATE_ONLY)) {",
        "    if (1) {",
        "a predicate-owned row starts matching its own collection prefix, so "
        "/zones/ is answered as a detail request with an empty id",
    ),
    (
        "production-table-wiring",
        "    desktop_api_routes,\n    people_api_routes,",
        "    people_api_routes,",
        "the desktop module disappears from the table of tables",
    ),
    (
        "people-table-wiring",
        "    people_api_routes,\n    NULL",
        "    NULL",
        "the personnel and device-binding module disappears from the table of tables",
    ),
)



@lru_cache(maxsize=1)
def implementation_text() -> str:
    """Live implementation units, excluding headers, backups and old snapshots."""
    return "\n".join(path.read_text(encoding="utf-8")
                     for path in sorted(WEBD_DIR.rglob("*"))
                     if path.suffix in (".c", ".inc"))


def insights_text() -> str:
    return "\n".join(path.read_text(encoding="utf-8")
                     for path in sorted(API_DIR.glob("api_insights_*.c")))


def assert_exported_definition(signature: str) -> None:
    """Borrowed helpers have one external definition wherever their owner moved."""
    name = signature.split("(")[0].split()[-1].lstrip("*")
    source = implementation_text()
    source = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"',
                    lambda match: re.sub(r'[^\n]', ' ', match.group()), source,
                    flags=re.S)
    definitions = re.findall(
        r'(?m)^((?:static )?[A-Za-z_][\w *]*?\b' + re.escape(name) +
        r'\([^;{]*\))\s*\{', source)
    assert len(definitions) == 1, (name, definitions)
    assert not definitions[0].startswith("static "), (name, definitions[0])


def build(workdir: Path, router_source: Path, strict: bool = True) -> Path:
    binary = workdir / "api-router-fixture"
    command = [
        "cc", "-std=c11", "-Wall", "-Wextra",
        # Mutated copies are compiled without -Werror on purpose: a mutation
        # such as dropping the length comparison leaves a now-unused local, and
        # a build failure would "pass" the reverse check for the wrong reason.
        # The verdict has to come from the fixture running and failing.
        *(["-Werror"] if strict else []),
        "-DJMX_API_ROUTER_TEST_STANDALONE",
        f"-I{API_DIR}",
        *HEADER_FLAGS,
        str(router_source), str(FIXTURE),
        "-o", str(binary),
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, (
        f"router fixture did not compile:\n{result.stdout}{result.stderr}")
    return binary


def run(binary: Path) -> subprocess.CompletedProcess:
    return subprocess.run([str(binary)], capture_output=True, text=True,
                          timeout=60)


def test_matcher_reproduces_chain_semantics() -> None:
    with tempfile.TemporaryDirectory(prefix="api-router-") as raw:
        result = run(build(Path(raw), ROUTER_C))
    assert result.returncode == 0, (
        f"router fixture failed:\n{result.stdout}{result.stderr}")
    assert "ok: matcher honours order" in result.stdout, result.stdout


def test_the_fixture_catches_a_broken_matcher() -> None:
    """Reverse verification: each guarantee, removed one at a time, goes red."""
    source = ROUTER_C.read_text(encoding="utf-8")
    for label, needle, replacement, consequence in MUTATIONS:
        assert source.count(needle) == 1, (
            f"mutation anchor {label!r} matches {source.count(needle)} times in "
            f"{ROUTER_C.name}; the reverse check would test the wrong line")
        with tempfile.TemporaryDirectory(prefix=f"api-router-{label}-") as raw:
            workdir = Path(raw)
            mutated = workdir / "api_router.c"
            mutated.write_text(source.replace(needle, replacement),
                               encoding="utf-8")
            result = run(build(workdir, mutated, strict=False))
        assert result.returncode != 0, (
            f"mutation {label!r} left the fixture green, so nothing verifies "
            f"that {consequence} would be caught:\n{result.stdout}")


def test_routing_module_owns_all_legacy_branches() -> None:
    main = (WEBD_DIR / "jmx_app_api.c").read_text(encoding="utf-8")
    routing = (API_DIR / "api_routing.c").read_text(encoding="utf-8")
    assert not re.search(r'\breq\.path, "/api/v1/routing', main)
    assert routing.count("JMX_API_ROUTE(") + routing.count("JMX_API_PREDICATE_ROUTE(") == 21
    for path in (
        "/api/v1/routing", "/api/v1/routing/apply",
        "/api/v1/routing/static-routes", "/api/v1/routing/policy-rules",
        "/api/v1/routing/tables", "/api/v1/routing/objects",
        "/api/v1/routing/cross-services", "/api/v1/routing/runtime-resolve",
        "/api/v1/routing/external-policies",
    ):
        assert path in routing
    for needle in (
        'app_routed_call("snapshot", NULL)',
        'app_ubus_invoke("route_reload", ctx->body)',
        'app_routed_call("table_delete", params)',
        'json_object_put(params)',
        'read_only_projection',
    ):
        assert needle in routing


def test_clients_list_module_owns_the_legacy_branch() -> None:
    main = (WEBD_DIR / "jmx_app_api.c").read_text(encoding="utf-8")
    clients = (API_DIR / "api_clients_list.c").read_text(encoding="utf-8")
    assert 'else if (!strcmp(req.path, "/api/v1/clients"))' not in main
    assert clients.count("JMX_API_ROUTE(") == 1
    assert re.search(
        r'JMX_API_ROUTE\(\d+,\s*"/api/v1/clients",\s*"",\s*JMX_API_EXACT,',
        clients,
    )
    assert clients.count("webd_clients_response(int *http_status") == 1


def test_client_control_module_owns_the_legacy_branch() -> None:
    main = (WEBD_DIR / "jmx_app_api.c").read_text(encoding="utf-8")
    control = (API_DIR / "api_client_control.c").read_text(encoding="utf-8")
    # All five legacy branches are gone from the monolith.
    assert not re.search(r'\breq\.path, "/api/v1/client_control_rule', main)
    # The module owns exactly the five migrated rows, all POST/GET exact.
    assert control.count("JMX_API_ROUTE(") == 5
    for path, method in (
        ("/api/v1/client_control_rules", "GET"),
        ("/api/v1/client_control_rule", "POST"),
        ("/api/v1/client_control_rule/update", "POST"),
        ("/api/v1/client_control_rule/toggle", "POST"),
        ("/api/v1/client_control_rule/delete", "POST"),
    ):
        assert re.search(
            r'JMX_API_ROUTE\(\d+,\s*"%s",\s*"%s",\s*JMX_API_EXACT,'
            % (re.escape(path), method),
            control,
        ), path
    # The two symbols this module exposes stay defined here, once, and
    # non-static. Their sole caller is webd_client_profile_response, which
    # Phase 6D moved into api_client_profile.c, so the calls live there now, not
    # in the monolith.
    profile = (API_DIR / "api_client_profile.c").read_text(encoding="utf-8")
    assert control.count(
        "struct json_object *webd_client_control_rules_load(const char *mac)") == 1
    assert main.count("webd_client_control_rules_load(") == 0
    assert profile.count("webd_client_control_rules_load(") == 1
    assert main.count("webd_client_control_add_capabilities(") == 0
    assert profile.count("webd_client_control_add_capabilities(") == 1


def test_client_connections_module_owns_the_legacy_branch() -> None:
    main = (WEBD_DIR / "jmx_app_api.c").read_text(encoding="utf-8")
    conn = (API_DIR / "api_client_connections.c").read_text(encoding="utf-8")
    # The three legacy branches are gone from the monolith.
    assert not re.search(r'\breq\.path, "/api/v1/client_connections/', main)
    assert 'req.path, "/api/v1/client_protocol_control"' not in main
    # The module owns exactly the three migrated rows, all POST,PUT exact.
    assert conn.count("JMX_API_ROUTE(") == 3
    for path in (
        "/api/v1/client_connections/clear",
        "/api/v1/client_connections/close",
        "/api/v1/client_protocol_control",
    ):
        assert re.search(
            r'JMX_API_ROUTE\(\d+,\s*"%s",\s*"POST,PUT",\s*JMX_API_EXACT,'
            % re.escape(path),
            conn,
        ), path
    # The conntrack primitives moved here; the one the monolith still calls
    # (its kick action) is exposed once and non-static.
    assert conn.count("int app_run_conntrack_delete(const char *direction") == 1
    assert not re.search(r'\bstatic int app_run_conntrack_delete\b', main)
    assert main.count("app_run_conntrack_delete(") == 2  # kick action, -s and -d


def test_client_profile_module_owns_the_legacy_branch() -> None:
    main = (WEBD_DIR / "jmx_app_api.c").read_text(encoding="utf-8")
    profile = (API_DIR / "api_client_profile.c").read_text(encoding="utf-8")
    core = insights_text()
    # The legacy branch is gone from the monolith.
    assert 'req.path, "/api/v1/client_profile"' not in main
    # The module owns exactly the one migrated row, GET exact.
    assert profile.count("JMX_API_ROUTE(") == 1
    assert re.search(
        r'JMX_API_ROUTE\(\d+,\s*"/api/v1/client_profile",\s*"GET",\s*JMX_API_EXACT,',
        profile,
    )
    # The response builder moved here, exposed once and non-static, because the
    # WebSocket read model in the monolith still renders a profile through it.
    assert profile.count(
        "struct json_object *webd_client_profile_response(const struct http_req *req)") == 1
    assert not re.search(
        r'\bstatic struct json_object \*webd_client_profile_response\b', main)
    assert_exported_definition("webd_client_profile_response(")
    assert (API_DIR / "api_realtime.c").read_text().count("webd_client_profile_response(") >= 1
    # The two connection labels the monolith's insights code still calls are
    # exposed here, once each and non-static.
    assert profile.count(
        "const char *webd_connection_service_field_label(const char *service)") == 1
    assert profile.count(
        "const char *webd_connection_service_label(const char *proto, int port,") == 1
    # app_lookup is borrowed through the insights vtable, so its real definition
    # has one definition in the Insights semantic units; no duplicate
    # prototype leaks into the client_profile module, and
    # the module reaches it only through the vtable macro.
    assert not re.search(r'\bstatic int webd_insights_app_lookup\b', profile)
    assert main.count("static int webd_insights_app_lookup(int app_id,") == 0
    assert_exported_definition("webd_insights_app_lookup(")
    assert core.count(".app_lookup = webd_insights_app_lookup,") == 1  # vtable slot


def test_flowd_module_owns_the_legacy_branches() -> None:
    main = (WEBD_DIR / "jmx_app_api.c").read_text(encoding="utf-8")
    flowd = (API_DIR / "api_flowd.c").read_text(encoding="utf-8")
    # Every /api/v1/flowd/* dispatch branch is gone from the monolith; the
    # interleaved monitor and wan-slas branches stay behind untouched.
    assert 'req.path, "/api/v1/flowd/' not in main
    assert 'req.path, "/api/v1/monitor/line-load"' in main
    assert 'req.path, "/api/v1/network/wan-slas"' in main
    # The module owns exactly the 61 migrated rows, all exact.
    assert flowd.count("JMX_API_ROUTE(") == 61
    assert flowd.count("JMX_API_PREDICATE_ROUTE(") == 0
    # The three richer readers still fall back to core runtime sources.
    assert re.search(
        r'JMX_API_ROUTE\(\d+,\s*"/api/v1/flowd/status",\s*"GET",\s*JMX_API_EXACT,',
        flowd)
    assert re.search(
        r'JMX_API_ROUTE\(\d+,\s*"/api/v1/flowd/wan-health",\s*"GET",\s*JMX_API_EXACT,',
        flowd)
    assert re.search(
        r'JMX_API_ROUTE\(\d+,\s*"/api/v1/flowd/runtime",\s*"GET,POST,PUT",\s*JMX_API_EXACT,',
        flowd)
    # objects/delete keeps its distinct status mapping (app_routed_http_status),
    # unlike the 57 sibling proxies that use app_response_status.
    assert flowd.count("app_routed_http_status(") == 1
    # Two main-owned helpers are borrowed and therefore un-static in the monolith:
    # the line-load cache reader (dashboard sibling) ...
    assert not re.search(r'\bstatic struct json_object \*webd_cached_line_load\b', main)
    assert main.count("struct json_object *webd_cached_line_load(void)") >= 1
    # ... and the configured-WAN match, which keeps its three merge callers here.
    assert not re.search(
        r'\bstatic int webd_runtime_entry_matches_configured_wan\b', main)
    assert_exported_definition("webd_runtime_entry_matches_configured_wan(")
    assert implementation_text().count("webd_runtime_entry_matches_configured_wan(") >= 2
    # The status/runtime shared-cache reader and its private helpers left the
    # monolith entirely — no second implementation.
    assert "webd_flowd_status_response" not in main
    assert "webd_filter_runtime_wans" not in main
    assert "WEBD_FLOWD_STATUS_SHARED_CACHE_PATH" not in main


def test_aegis_module_owns_the_legacy_branches() -> None:
    main = (WEBD_DIR / "jmx_app_api.c").read_text(encoding="utf-8")
    aegis = (API_DIR / "api_aegis.c").read_text(encoding="utf-8")
    core = insights_text()
    # The 46 migrated aegis dispatch branches are gone from the monolith. Sample
    # one from each edge of the moved seq range plus a middle predicate route.
    for gone in (
        'req.path, "/api/v1/aegis/status"',
        'req.path, "/api/v1/aegis/events"',
        'req.path, "/api/v1/aegis/policies"',
        'req.path, "/api/v1/aegis/signatures/suppress"',
        'req.path, "/api/v1/aegis/ingest-suricata-eve"',
    ):
        assert gone not in main, gone
    # The geo branches (shared with the firewall domain), the five strncmp prefix
    # branches, and the RAW_FD certificate download deliberately stay behind.
    for stay in (
        'req.path, "/api/v1/aegis/geo"',
        'req.path, "/api/v1/aegis/geo/apply"',
        'req.path, "/api/v1/firewall/geo-block"',
        'req.path, "/api/v1/aegis/certificates/inspection-ca/download"',
    ):
        assert stay in main, stay
    for prefix in (
        '"/api/v1/aegis/app-blocks/"',
        '"/api/v1/aegis/certificates/inspection-ca/distributions/"',
        '"/api/v1/aegis/honeypot/config/"',
        '"/api/v1/aegis/content-policy/"',
        '"/api/v1/aegis/domain-overrides/"',
    ):
        assert prefix in main, prefix
    # The module owns exactly the 46 migrated rows: 38 plain + 8 predicate-backed.
    assert aegis.count("JMX_API_ROUTE(") == 38
    assert aegis.count("JMX_API_PREDICATE_ROUTE(") == 8
    # The three multi-alias readers keep their structured aliases via predicates.
    assert re.search(
        r'JMX_API_PREDICATE_ROUTE\(\d+,\s*"/api/v1/aegis/events",\s*"GET",\s*'
        r'JMX_API_EXACT,\s*aegis_match_events,', aegis)
    assert re.search(
        r'JMX_API_PREDICATE_ROUTE\(\d+,\s*"/api/v1/aegis/policies",\s*"GET",\s*'
        r'JMX_API_EXACT,\s*aegis_match_policies,', aegis)
    # The policies GET and POST rows share one predicate (identical alias tuple).
    assert aegis.count("aegis_match_policies") == 3  # def + 2 route rows
    # The events reader and its attribution annotator left the monolith entirely.
    assert "webd_aegis_events_response" not in main
    assert "webd_aegis_events_annotate_client_attribution" not in main
    assert aegis.count("webd_aegis_events_response(") >= 1
    # The dnsmasq apply-timeout macro moved to the shared internal header; the two
    # prefix-STAY branches in the monolith still reference it, so the token stays
    # but its #define does not.
    assert "#define WEBD_AEGIS_DNSMASQ_APPLY_TIMEOUT_MS" not in main
    assert "WEBD_AEGIS_DNSMASQ_APPLY_TIMEOUT_MS" in main  # prefix-STAY users
    internal = (API_DIR / "api_aegis_internal.h").read_text(encoding="utf-8")
    assert "#define WEBD_AEGIS_DNSMASQ_APPLY_TIMEOUT_MS" in internal
    # Four main-owned helpers are borrowed and therefore un-static in the monolith;
    # their definitions stay behind because non-aegis callers remain.
    for base, calls in (
        ("int app_parse_positive_int_segment(const char *s, int *out)", 12),
        ("int app_parse_nonnegative_int_segment(const char *s, int *out)", 1),
        ("int webd_aegis_certificate_http_status(struct json_object *response)", 2),
    ):
        assert main.count("static " + base) == 0, base
        assert_exported_definition(base)
    # The attribution annotator aegis borrows was moved to the insights core by
    # Phase 6M (forward-decl + definition, both un-static). It is gone from the
    # monolith; aegis reaches it through the api_aegis_internal.h prototype.
    ins = "void webd_insights_add_client_attribution(struct json_object *obj,"
    assert main.count(ins) == 0
    assert core.count("static " + ins) == 0
    assert_exported_definition(ins)
    assert "void webd_insights_add_client_attribution(struct json_object *obj," in (
        (API_DIR / "api_aegis_internal.h").read_text(encoding="utf-8"))
    # The two aegis helpers keep their non-aegis callers in the monolith; the
    # insights annotator's other callers moved to the core with its definition.
    assert implementation_text().count("app_parse_positive_int_segment(") >= 12
    assert implementation_text().count("webd_aegis_certificate_http_status(") >= 2
    assert core.count("webd_insights_add_client_attribution(") >= 5


def test_wifi_module_owns_the_legacy_branches() -> None:
    main = (WEBD_DIR / "jmx_app_api.c").read_text(encoding="utf-8")
    wifi = (API_DIR / "api_wifi.c").read_text(encoding="utf-8")
    main_dispatch = main[main.index("    /* ── Owner-scoped opaque browser uploads ── */"):]
    # The 14 migrated wifi dispatch branches (seq 630..644, minus the 634
    # channel-ai/plans prefix STAY) are gone from the monolith. Sample edges +
    # a same-path/different-method collision pair from the middle.
    for gone in (
        'req.path, "/api/v1/wifi/config"',
        'req.path, "/api/v1/wifi/channel-ai/status"',
        'req.path, "/api/v1/wifi/channel-ai/plan"',
        'req.path, "/api/v1/wifi/config/apply"',
        'req.path, "/api/v1/wifi/status"',
        'req.path, "/api/v1/wifi/scan"',
        'req.path, "/api/v1/wifi/connectivity/events"',
    ):
        assert gone not in main_dispatch, gone
    # The four strncmp prefix branches deliberately stay behind: channel-ai/plans
    # (via the shared macro), transactions/, scan/jobs/. There is no predicate in
    # this domain — the same-path/different-method pairs are plain routes.
    for stay in (
        '"/api/v1/wifi/transactions/"',
        '"/api/v1/wifi/scan/jobs/"',
        "WEBD_WIFI_CHANNEL_AI_PLANS_PREFIX",
    ):
        assert stay in main, stay
    # The module owns exactly the 14 migrated rows, all plain (no predicates).
    assert wifi.count("JMX_API_ROUTE(") == 14
    assert wifi.count("JMX_API_PREDICATE_ROUTE(") == 0
    # The two same-path/different-method collision pairs became method-suffixed
    # handlers, not predicates.
    assert re.search(
        r'JMX_API_ROUTE\(630,\s*"/api/v1/wifi/config",\s*"GET",\s*'
        r'JMX_API_EXACT,\s*wifi_config_get\)', wifi)
    assert re.search(
        r'JMX_API_ROUTE\(635,\s*"/api/v1/wifi/config",\s*"POST,PUT",\s*'
        r'JMX_API_EXACT,\s*wifi_config_post\)', wifi)
    # Ten main-owned helpers are borrowed and therefore un-static in the monolith;
    # their definitions stay behind because other callers remain. Two of them
    # (aggregate_response, ac_token_id_valid) also carried a forward-decl that
    # was de-static'd, so their single-line signature occurs twice, un-static.
    for sig, total in (
        ("int webd_ac_radio_job_key_valid(const char *value)", 1),
        ("struct json_object *webd_wifi_aggregate_response(int runtime_status)", 2),
        ("int webd_ac_token_id_valid(const char *token_id)", 2),
        ("int webd_ac_http_status(struct json_object *resp, int default_status)", 1),
    ):
        assert main.count("static " + sig) == 0, sig
        assert_exported_definition(sig)
    # The borrowed helpers keep their non-wifi callers in the monolith, and the
    # module reuses each exactly once (single implementation, no second copy).
    assert implementation_text().count("webd_ac_token_id_valid(") >= 15
    assert implementation_text().count("webd_ac_http_status(") >= 19
    assert implementation_text().count("webd_ac_ubus_or_disabled(") >= 23
    assert wifi.count("webd_ac_ubus_or_disabled(") == 3
    # The borrowed prototypes live in the module's internal header.
    internal = (API_DIR / "api_wifi_internal.h").read_text(encoding="utf-8")
    for proto in (
        "webd_wifi_aggregate_response",
        "webd_ac_token_id_valid",
        "webd_ac_ubus_or_disabled",
        "webd_wifi_channel_ai_plan_store",
    ):
        assert proto in internal, proto


def test_logd_module_owns_the_legacy_branches() -> None:
    main = (WEBD_DIR / "jmx_app_api.c").read_text(encoding="utf-8")
    logd = (API_DIR / "api_logd.c").read_text(encoding="utf-8")
    # All 11 migrated logd dispatch branches (seq 106..116) are gone from the
    # monolith. Sample edges plus a same-path/different-method collision pair.
    for gone in (
        'req.path, "/api/v1/logd/status"',
        'req.path, "/api/v1/logd/settings"',
        'req.path, "/api/v1/logd/collectors"',
        'req.path, "/api/v1/logd/collect-now"',
        'req.path, "/api/v1/logd/events"',
        'req.path, "/api/v1/logd/events/query"',
        'req.path, "/api/v1/logd/events/clear"',
    ):
        assert gone not in main, gone
    # No /api/v1/logd/* dispatch branch survives at all.
    assert 'req.path, "/api/v1/logd/' not in main
    # The module owns exactly the 11 migrated rows, all plain (no predicates,
    # no prefixes): the same-path/different-method sets (settings GET vs
    # POST,PUT,PATCH; collectors likewise; events GET vs POST,PUT) are matched
    # on path+method, so no predicate is needed.
    assert logd.count("JMX_API_ROUTE(") == 11
    assert logd.count("JMX_API_PREDICATE_ROUTE(") == 0
    for seq, path, method in (
        (106, "/api/v1/logd/status", "GET"),
        (107, "/api/v1/logd/settings", "GET"),
        (108, "/api/v1/logd/settings", "POST,PUT,PATCH"),
        (110, "/api/v1/logd/collectors", "GET"),
        (111, "/api/v1/logd/collectors", "POST,PUT,PATCH"),
        (113, "/api/v1/logd/events", "GET"),
        (115, "/api/v1/logd/events", "POST,PUT"),
        (116, "/api/v1/logd/events/clear", "POST,PUT"),
    ):
        assert re.search(
            r'JMX_API_ROUTE\(%d,\s*"%s",\s*"%s",\s*JMX_API_EXACT,'
            % (seq, re.escape(path), re.escape(method)),
            logd,
        ), path
    # Zero borrows: the module defines neither shared helper — both are already
    # exported from api_ubus.c / api_error.c, so no de-static and no internal
    # header were needed for this cut.
    assert "app_ubus_object_or_error(const char" not in logd
    assert "int app_response_status(" not in logd
    assert not (API_DIR / "api_logd_internal.h").exists()
    # The non-dispatch logd producers/consumers in other domains stay in the
    # monolith: the audit publisher, the WS logs bridge, capture, logs-v2 and
    # ai-logs all still speak to the dreamingwrt.logd object.
    assert '"dreamingwrt.logd"' in main
    assert 'app_ubus_invoke_object_timeout("dreamingwrt.logd", "event_add"' in main


def test_notifyd_module_owns_the_legacy_branches() -> None:
    main = (WEBD_DIR / "jmx_app_api.c").read_text(encoding="utf-8")
    notifyd = (API_DIR / "api_notifyd.c").read_text(encoding="utf-8")
    # The 16 migrated notifyd exact dispatch branches (seq 117..135, minus the 3
    # prefix STAYs 124/128/134) are gone from the monolith. Sample edges, the
    # rich preferences/me row, and a same-path/different-method collision pair.
    for gone in (
        'req.path, "/api/v1/notifyd/status"',
        'req.path, "/api/v1/notifyd/settings"',
        'req.path, "/api/v1/notifyd/preferences/me"',
        'req.path, "/api/v1/notifyd/channels"',
        'req.path, "/api/v1/notifyd/routes"',
        'req.path, "/api/v1/notifyd/enqueue"',
        'req.path, "/api/v1/notifyd/deliver-due"',
    ):
        assert gone not in main, gone
    # No EXACT notifyd dispatch branch survives; the three strncmp PREFIX branches
    # deliberately stay behind — their single-segment guard (path[N] non-empty &&
    # no further '/') cannot be expressed as a plain JMX_API_PREFIX route.
    assert len(re.findall(r'!strcmp\(req\.path,\s*"/api/v1/notifyd/', main)) == 0
    for stay in (
        '"/api/v1/notifyd/channels/"',
        '"/api/v1/notifyd/routes/"',
        '"/api/v1/notifyd/outbox/"',
    ):
        assert stay in main, stay
    assert len(re.findall(r'!strncmp\(req\.path,\s*"/api/v1/notifyd/', main)) == 3
    # The module owns exactly the 16 migrated rows, all plain (no predicates): the
    # same-path/different-method sets (settings/channels/routes GET vs write) are
    # matched on path+method, so no predicate is needed.
    assert notifyd.count("JMX_API_ROUTE(") == 16
    assert notifyd.count("JMX_API_PREDICATE_ROUTE(") == 0
    for seq, path, method in (
        (117, "/api/v1/notifyd/status", "GET"),
        (119, "/api/v1/notifyd/settings", "GET"),
        (120, "/api/v1/notifyd/settings", "POST,PUT,PATCH"),
        (121, "/api/v1/notifyd/preferences/me", "GET,POST,PUT,PATCH"),
        (122, "/api/v1/notifyd/channels", "GET"),
        (123, "/api/v1/notifyd/channels", "POST,PUT,PATCH"),
        (135, "/api/v1/notifyd/deliver-due", "POST"),
    ):
        assert re.search(
            r'JMX_API_ROUTE\(%d,\s*"%s",\s*"%s",\s*JMX_API_EXACT,'
            % (seq, re.escape(path), re.escape(method)),
            notifyd,
        ), path
    # Two session-identity helpers are borrowed and therefore un-static in the
    # monolith; their definitions stay behind (each keeps ~21 other callers).
    # Each also carried a forward-decl that was de-static'd, so its single-line
    # signature occurs twice, un-static.
    for sig in (
        "int webd_identity_is_user(const char *identity)",
        "const char *webd_identity_username(const char *identity)",
    ):
        assert main.count("static " + sig) == 0, sig
        assert_exported_definition(sig)
    # The borrowed helpers keep their non-notifyd callers in the monolith, and the
    # module reuses each exactly once (single implementation, no second copy).
    assert implementation_text().count("webd_identity_is_user(") >= 20
    assert implementation_text().count("webd_identity_username(") >= 20
    assert notifyd.count("webd_identity_is_user(") == 1
    assert notifyd.count("webd_identity_username(") == 1
    # The borrowed prototypes live in the module's internal header.
    internal = (API_DIR / "api_notifyd_internal.h").read_text(encoding="utf-8")
    for proto in ("webd_identity_is_user", "webd_identity_username"):
        assert proto in internal, proto


def test_audit_module_owns_the_legacy_branches() -> None:
    main = (WEBD_DIR / "jmx_app_api.c").read_text(encoding="utf-8")
    audit = (API_DIR / "api_audit.c").read_text(encoding="utf-8")
    internal = (API_DIR / "api_audit_internal.h").read_text(encoding="utf-8")
    core = insights_text()
    # The 9 migrated audit BFF dispatch branches (seq 207..231) are gone from the
    # monolith. Sample the exact edges, both prefix detail routes, and a middle
    # exact row.
    for gone in (
        'req.path, "/api/v1/audit/status"',
        'req.path, "/api/v1/audit/urls"',
        'req.path, "/api/v1/audit/online-records"',
        'req.path, "/api/v1/audit/im-records"',
        'req.path, "/api/v1/audit/traffic"',
        'req.path, "/api/v1/audit/protocols"',
        'req.path, "/api/v1/audit/apps"',
    ):
        assert gone not in main, gone
    # No BFF dispatch branch survives; both strncmp prefix branches are gone too.
    assert len(re.findall(r'!strcmp\(req\.path,\s*"/api/v1/audit/(?:status|urls|'
                          r'online-records|im-records|traffic|protocols|apps)"',
                          main)) == 0
    assert len(re.findall(r'!strncmp\(req\.path,\s*"/api/v1/audit/(?:protocols|apps)/"',
                          main)) == 0
    # The security audit-LOG publisher is a different subsystem and deliberately
    # stays behind: /api/v1/audit/events (seq 581, ANY-method) and its helpers.
    assert 'req.path, "/api/v1/audit/events"' in main
    assert implementation_text().count("webd_audit_publish_logd(") >= 1
    # The module owns exactly the 9 migrated rows: 7 exact + 2 prefix, no predicate.
    assert audit.count("JMX_API_ROUTE(") == 9
    assert audit.count("JMX_API_PREDICATE_ROUTE(") == 0
    for seq, path, flag in (
        (207, "/api/v1/audit/status", "JMX_API_EXACT"),
        (208, "/api/v1/audit/urls", "JMX_API_EXACT"),
        (209, "/api/v1/audit/online-records", "JMX_API_EXACT"),
        (210, "/api/v1/audit/im-records", "JMX_API_EXACT"),
        (211, "/api/v1/audit/traffic", "JMX_API_EXACT"),
        (228, "/api/v1/audit/protocols/", "JMX_API_PREFIX"),
        (229, "/api/v1/audit/protocols", "JMX_API_EXACT"),
        (230, "/api/v1/audit/apps/", "JMX_API_PREFIX"),
        (231, "/api/v1/audit/apps", "JMX_API_EXACT"),
    ):
        assert re.search(
            r'JMX_API_ROUTE\(%d,\s*"%s",\s*"GET",\s*%s,'
            % (seq, re.escape(path), flag),
            audit,
        ), path
    # The prefix detail row must be declared before the exact collection row it
    # covers, preserving the legacy strncmp-before-strcmp order.
    assert audit.index('"/api/v1/audit/protocols/"') < audit.index('"/api/v1/audit/protocols"')
    assert audit.index('"/api/v1/audit/apps/"') < audit.index('"/api/v1/audit/apps"')
    # The whole audit BFF subsystem left the monolith entirely: the query struct
    # and the 9 response builders are defined only in the module now.
    assert "struct webd_audit_bff_query" not in main
    assert "webd_audit_bff_query" in audit
    for fn in (
        "webd_audit_status_response", "webd_audit_urls_response",
        "webd_audit_online_records_response", "webd_audit_im_records_response",
        "webd_audit_traffic_response", "webd_audit_protocols_response",
        "webd_audit_protocol_detail_response", "webd_audit_apps_response",
        "webd_audit_app_detail_response", "webd_path_tail_token",
    ):
        assert fn not in main, fn
        assert audit.count(fn) >= 1, fn
    # Four insights helpers are borrowed and therefore un-static; Phase 6M moved
    # their definitions out of the monolith into the insights core, so they are
    # gone from main and single-homed (un-static) in the core.
    # webd_insights_ubus_data_timeout also carried a forward-decl that was
    # de-static'd, so its single-line signature occurs twice, un-static.
    for sig, total in (
        ("int64_t webd_insights_ts_normalize(int64_t ts)", 1),
        ("struct json_object *webd_insights_fetch_flow_app_summary(", 1),
        ("struct json_object *webd_insights_ubus_data_timeout(", 2),
        ("struct json_object *webd_insights_ubus_response_timeout(", 1),
    ):
        assert main.count(sig) == 0, sig
        assert core.count("static " + sig) == 0, sig
        assert_exported_definition(sig)
        assert audit.count(sig.split("(")[0].split()[-1].lstrip("*")) >= 1, sig
    # api_util.c now owns these widely shared helpers. Their external singleton
    # definitions and uses across the implementation corpus must survive a split.
    assert_exported_definition("webd_first_nonempty4(")
    assert_exported_definition("webd_str_contains_i(")
    assert implementation_text().count("webd_first_nonempty4(") >= 60
    assert implementation_text().count("webd_str_contains_i(") >= 18
    # All six borrowed prototypes live in the module's internal header.
    for proto in (
        "webd_insights_ts_normalize", "webd_insights_fetch_flow_app_summary",
        "webd_insights_ubus_data_timeout", "webd_insights_ubus_response_timeout",
        "webd_first_nonempty4", "webd_str_contains_i",
    ):
        assert proto in internal, proto
    # The full webd_insights_query type comes from api_insights_internal.h, which
    # the module includes because it uses the struct by value.
    assert '#include "api_insights_internal.h"' in audit


def test_wan_module_owns_the_legacy_branches() -> None:
    main = (WEBD_DIR / "jmx_app_api.c").read_text(encoding="utf-8")
    wan = (API_DIR / "api_wan.c").read_text(encoding="utf-8")
    internal = (API_DIR / "api_wan_internal.h").read_text(encoding="utf-8")
    # The 3 migrated WAN-policy BFF dispatch branches (seq 152..154) are gone from
    # the monolith. The trailing quote disambiguates wan-policy from wan-policies.
    for gone in (
        'req.path, "/api/v1/network/wan-policies"',
        'req.path, "/api/v1/network/wan-policies/"',
        'req.path, "/api/v1/network/wan-policy"',
        'req.path, "/api/v1/network/wan-rules"',
    ):
        assert gone not in main, gone
    # Neither half of the legacy mixed condition survives in the monolith.
    assert '!strcmp(req.path, "/api/v1/network/wan-policies")' not in main
    assert '!strncmp(req.path, "/api/v1/network/wan-policies/"' not in main
    # The network overview builder is a different subsystem and stays behind.
    assert main.count("webd_network_overview_response") >= 1
    assert "webd_network_overview_response" not in wan
    # The module owns exactly the 3 migrated rows: 1 mixed predicate + 2 exact.
    assert wan.count("JMX_API_ROUTE(") == 2
    assert wan.count("JMX_API_PREDICATE_ROUTE(") == 1
    # The wan-policies collection matched `exact OR strncmp of the transaction
    # subtree`, so it is ONE PREDICATE_MIXED row (net-zero: one inventory route).
    assert re.search(
        r'JMX_API_PREDICATE_ROUTE\(152,\s*"/api/v1/network/wan-policies",\s*'
        r'"GET,POST,PATCH,DELETE",\s*JMX_API_PREDICATE_MIXED,\s*'
        r'wan_policies_path,\s*wan_policies\)',
        wan,
    )
    assert re.search(
        r'JMX_API_ROUTE\(153,\s*"/api/v1/network/wan-policy",\s*"GET,PUT,POST",\s*'
        r'JMX_API_EXACT,\s*wan_policy\)',
        wan,
    )
    assert re.search(
        r'JMX_API_ROUTE\(154,\s*"/api/v1/network/wan-rules",\s*"GET",\s*'
        r'JMX_API_EXACT,\s*wan_rules\)',
        wan,
    )
    # The predicate supplies only the strncmp half; the matcher tries the fixed
    # path for the exact-collection case.
    assert re.search(
        r'wan_policies_path\(const char \*path\)\s*\{\s*return path &&\s*'
        r'!strncmp\(path,\s*"/api/v1/network/wan-policies/",\s*29\)',
        wan,
    )
    # The two audit-logging branches are reproduced faithfully with their guards.
    assert 'network.wan_policies.transaction' in wan
    assert 'network.wan_policy.apply' in wan
    assert '/quality-check' in wan  # wan-policies audit skips quality-check + GET
    assert wan.count("jmx_app_audit_log(") == 2  # wan_rules carries no audit
    # The whole WAN-policy BFF subsystem left the monolith: the validator, the
    # atomic route-config apply, the flowd-status shaper and the 3 response
    # builders are defined only in the module now.
    for fn in (
        "webd_wan_policy_validate_members", "webd_route_config_set",
        "webd_wan_policy_flowd_status", "webd_wan_policies_response",
        "webd_wan_policy_response", "webd_wan_rules_response",
    ):
        assert fn not in main, fn
        assert wan.count(fn) >= 1, fn
    # The cluster-local apply-timeout macro travelled inside the DEF block.
    assert "WEBD_ROUTE_CONFIG_APPLY_TIMEOUT_MS" not in main
    assert "WEBD_ROUTE_CONFIG_APPLY_TIMEOUT_MS" in wan
    # Two helpers are borrowed and therefore un-static in the monolith; their
    # definitions stay behind because other callers remain.
    for sig, callers in (
        ("void webd_put_int(", 15),
        ("uint64_t webd_ws_semantic_hash(", 4),
    ):
        assert main.count("static " + sig) == 0, sig
        assert_exported_definition(sig)
        base = sig.split("(")[0].split()[-1]
        assert implementation_text().count(base + "(") >= callers, base
        assert wan.count(base + "(") >= 1, base
    # gen_random_hex_checked was already extern in main (def-before-use); the
    # module is a separate TU and needs only the prototype.
    assert implementation_text().count("gen_random_hex_checked(") >= 15
    # All three borrowed prototypes live in the module's internal header.
    for proto in ("webd_put_int", "webd_ws_semantic_hash", "gen_random_hex_checked"):
        assert proto in internal, proto


def test_authentication_module_owns_the_legacy_branches() -> None:
    main = (WEBD_DIR / "jmx_app_api.c").read_text(encoding="utf-8")
    auth = (API_DIR / "api_authentication.c").read_text(encoding="utf-8")
    internal = (API_DIR / "api_authentication_internal.h").read_text(encoding="utf-8")
    # The 27 migrated authentication BFF exact dispatch branches (seq 79..105) are
    # gone from the monolith. Sample the exact edges, the web/portal/access-rules
    # sub-tree, the accounts write family, and the notifications lifecycle.
    for gone in (
        'req.path, "/api/v1/authentication"',
        'req.path, "/api/v1/authentication/web"',
        'req.path, "/api/v1/authentication/web/portal"',
        'req.path, "/api/v1/authentication/web/access-rules"',
        'req.path, "/api/v1/authentication/online-users"',
        'req.path, "/api/v1/authentication/accounts"',
        'req.path, "/api/v1/authentication/accounts/bulk"',
        'req.path, "/api/v1/authentication/accounts/import"',
        'req.path, "/api/v1/authentication/accounts/password-policy"',
        'req.path, "/api/v1/authentication/notifications"',
        'req.path, "/api/v1/authentication/notifications/preview"',
        'req.path, "/api/v1/authentication/notifications/realtime"',
        'req.path, "/api/v1/authentication/vouchers/expired"',
    ):
        assert gone not in main, gone
    # No EXACT authentication dispatch branch survives; the seven `sizeof()-1`
    # strncmp id-detail prefix branches deliberately stay behind — the inventory
    # tool cannot see a sizeof() length, so moving them as JMX_API_PREFIX rows
    # would show a false +7. Dispatch precedence is preserved because the router
    # checks every module EXACT route before the monolith's inline PREFIX chain.
    assert len(re.findall(r'!strcmp\(req\.path,\s*"/api/v1/authentication', main)) == 0
    for stay in (
        '"/api/v1/authentication/web/access-rules/"',
        '"/api/v1/authentication/delegated-services/"',
        '"/api/v1/authentication/notifications/periodic/"',
        '"/api/v1/authentication/packages/"',
        '"/api/v1/authentication/accounts/"',
        '"/api/v1/authentication/ledger/"',
        '"/api/v1/authentication/vouchers/"',
    ):
        assert stay in main, stay
    assert len(re.findall(r'!strncmp\(req\.path,\s*"/api/v1/authentication', main)) == 7
    # The module owns exactly the 27 migrated rows: 26 exact + the one
    # notifications-kind PREDICATE_ONLY row.
    assert auth.count("JMX_API_ROUTE(") == 26
    assert auth.count("JMX_API_PREDICATE_ROUTE(") == 1
    for seq, path, method in (
        (79, "/api/v1/authentication", "GET"),
        (80, "/api/v1/authentication/web", "GET"),
        (81, "/api/v1/authentication/web", "PUT"),
        (86, "/api/v1/authentication/online-users", "GET"),
        (100, "/api/v1/authentication/accounts/bulk", "POST"),
        (102, "/api/v1/authentication/accounts/password-policy", "PUT,PATCH"),
        (105, "/api/v1/authentication/vouchers/expired", "DELETE"),
    ):
        assert re.search(
            r'JMX_API_ROUTE\(%d,\s*"%s",\s*"%s",\s*JMX_API_EXACT,'
            % (seq, re.escape(path), re.escape(method)),
            auth,
        ), path
    # The notifications realtime|expiry|expired PUT branch matched three exact
    # paths, so it is ONE JMX_API_PREDICATE_ROUTE with JMX_API_PREDICATE_ONLY:
    # the predicate carries the three exact aliases, so the inventory reproduces
    # match='exact' with all_paths=3 (net-zero).
    assert re.search(
        r'JMX_API_PREDICATE_ROUTE\(96,\s*'
        r'"/api/v1/authentication/notifications/realtime",\s*"PUT",\s*'
        r'JMX_API_PREDICATE_ONLY,\s*auth_notifications_kind_path,\s*'
        r'auth_notifications_kind_set\)',
        auth,
    )
    for alias in (
        "/api/v1/authentication/notifications/realtime",
        "/api/v1/authentication/notifications/expiry",
        "/api/v1/authentication/notifications/expired",
    ):
        assert re.search(r'!strcmp\(path,\s*"%s"\)' % re.escape(alias), auth), alias
    # One helper is borrowed and therefore un-static in the monolith; its
    # definition stays behind because the seven inline id-detail STAY branches
    # still call it. The module reuses that single implementation.
    assert not re.search(
        r'\bstatic struct json_object \*app_authentication_write\b', main)
    assert main.count(
        "struct json_object *app_authentication_write(const char *method,") == 1
    assert implementation_text().count("app_authentication_write(") >= 8  # def + STAY callers
    assert auth.count("app_authentication_write(") >= 1
    # The borrowed prototype lives in the module's internal header, alongside the
    # forward-decl the separate TU needs.
    assert "app_authentication_write" in internal
    assert "struct json_object;" in internal
    # No second copy of any moved BFF body remains: the response builders the
    # branches called are reachable through already-exported api_* helpers, so the
    # module needs no header beyond struct http_req and the one write borrow.
    assert '#include "webd_http_req.h"' in auth
    assert '#include "api_authentication_internal.h"' in auth


def test_logs_module_owns_the_legacy_branches() -> None:
    main = (WEBD_DIR / "jmx_app_api.c").read_text(encoding="utf-8")
    logs = (API_DIR / "api_logs.c").read_text(encoding="utf-8")
    internal = (API_DIR / "api_logs_internal.h").read_text(encoding="utf-8")
    # The 30 migrated log-center BFF exact dispatch branches (seq 672-682, 688-705,
    # 719) are gone from the monolith. Sample the edges, both same-path/method
    # collision members, and the bare collection.
    for gone in (
        'req.path, "/api/v1/logs/query"',
        'req.path, "/api/v1/logs/events"',
        'req.path, "/api/v1/logs/alarms"',
        'req.path, "/api/v1/logs/warning-rules"',
        'req.path, "/api/v1/logs/channels"',
        'req.path, "/api/v1/logs/settings"',
        'req.path, "/api/v1/logs/syslog/certs"',
        'req.path, "/api/v1/logs/summary"',
        'req.path, "/api/v1/logs/filter-data"',
    ):
        assert gone not in main, gone
    # No /api/v1/logs/* JSON dispatch branch survives EXCEPT the RAW_FD download,
    # which stays inline (it writes the socket directly and cannot go through the
    # response table). The bare `GET /api/v1/logs` collection branch is also gone.
    surviving = re.findall(r'!strcmp\(req\.path,\s*"(/api/v1/logs(?:/[^"]*)?)"', main)
    assert surviving == ["/api/v1/logs/download"], surviving
    # The module owns exactly the 30 migrated rows, all plain exact (no predicates,
    # no prefixes): the four same-path/different-method sets (warning-rules,
    # channels, settings, syslog/certs — each a GET reader and a POST/PUT writer)
    # are matched on path+method, so no predicate is needed.
    assert logs.count("JMX_API_ROUTE(") == 30
    assert logs.count("JMX_API_PREDICATE_ROUTE(") == 0
    for seq, path, method in (
        (672, "/api/v1/logs/query", "POST,PUT"),
        (677, "/api/v1/logs/alarms", "GET"),
        (679, "/api/v1/logs/warning-rules", "GET"),
        (680, "/api/v1/logs/warning-rules", "POST,PUT"),
        (689, "/api/v1/logs/settings", "GET"),
        (690, "/api/v1/logs/settings", "POST,PUT"),
        (697, "/api/v1/logs/syslog/certs/delete", "POST,PUT,DELETE"),
        (719, "/api/v1/logs", "GET"),
    ):
        assert re.search(
            r'JMX_API_ROUTE\(%d,\s*"%s",\s*"%s",\s*JMX_API_EXACT,'
            % (seq, re.escape(path), re.escape(method)),
            logs,
        ), path
    # The RAW_FD download handler stays behind, whole, in the monolith.
    assert 'webd_logs_download_response(fd, &req)' in main
    # Three borrowed helpers: de-static'd, their single definitions stay in main
    # (shared with the inline download STAY branch and non-dispatch logd
    # producers), reused by the module through the internal-header prototypes.
    # (return-type token, total uses that must remain in main = def + callers)
    for helper, rettype, main_uses in (
        ("webd_logs_v2_response", "struct json_object *", 2),  # def + 1 caller
        ("webd_logs_v2_flat_response", "struct json_object *", 1),  # def only
        ("webd_logs_attach_actor", "void ", 1),  # def only
    ):
        # No static definition survives in main — it was de-static'd so the
        # module can link against it.
        assert ("static " + rettype + helper + "(") not in main, helper
        # Exactly one (now non-static) definition remains in main.
        assert_exported_definition(helper + "(")
        # Its total footprint in main is the definition plus any in-main callers.
        assert implementation_text().count(helper + "(") >= 2, helper
        # The prototype lives in the internal header, and the module reuses it.
        assert helper in internal, helper
        assert logs.count(helper + "(") >= 1, helper
    # The non-dispatch log producers/consumers in other domains stay in the
    # monolith: the ai-logs config, capture, and the WS logs bridge still speak to
    # the dreamingwrt.logd object.
    assert '"dreamingwrt.logd"' in main
    # The module includes the borrow header and the http_req header (for the alias
    # preamble), and no libubus/strbuf gap was needed.
    assert '#include "api_logs_internal.h"' in logs
    assert '#include "webd_http_req.h"' in logs
    assert "struct json_object;" in internal


def test_netcontrol_module_owns_the_legacy_branches() -> None:
    main = (WEBD_DIR / "jmx_app_api.c").read_text(encoding="utf-8")
    nc = (API_DIR / "api_netcontrol.c").read_text(encoding="utf-8")
    internal = (API_DIR / "api_netcontrol_internal.h").read_text(encoding="utf-8")
    # The 20 migrated network-control BFF dispatch branches (seq 410-429: 15
    # exact + 5 prefix) are gone from the monolith. Sample the collection GET,
    # both same-path/different-method members, a trailing-slash prefix, and the
    # runtime-before-prefix precedence edge.
    for gone in (
        # NB: the bare "/api/v1/network-control" collection path is intentionally
        # NOT sampled here — as a substring it also appears inside the CSRF
        # guard's !strncmp(..., 23) prefix literal that legitimately STAYS in
        # main. The `surviving_exact == []` regex below (anchored on !strcmp)
        # proves the bare exact dispatch branch is gone without that collision.
        'req.path, "/api/v1/network-control/terminal-limits"',
        'req.path, "/api/v1/network-control/terminal-policies/runtime"',
        'req.path, "/api/v1/network-control/terminal-policies"',
        'req.path, "/api/v1/network-control/apply"',
        'req.path, "/api/v1/network-control/status"',
        'req.path, "/api/v1/network-control/mac-allowlist"',
        'req.path, "/api/v1/network-control/mac-allowlist/confirm"',
    ):
        assert gone not in main, gone
    # No /api/v1/network-control exact dispatch branch survives in the monolith:
    # all 15 !strcmp rows moved to the module.
    surviving_exact = re.findall(
        r'!strcmp\(req\.path,\s*"(/api/v1/network-control(?:/[^"]*)?)"', main)
    assert surviving_exact == [], surviving_exact
    # The 5 prefix rows also moved, so the ONLY surviving /api/v1/network-control
    # literal in the monolith is the CSRF write-preflight guard's prefix test
    # (strncmp len 23 == strlen("/api/v1/network-control")). That guard stays
    # inline: it writes the socket and close(fd)s on rejection, and it runs
    # textually before the post-auth router dispatch, so every nc write still
    # passes it before reaching the module handlers.
    surviving_prefix = re.findall(
        r'!strncmp\(req\.path,\s*"(/api/v1/network-control[^"]*)",\s*(\d+)\)', main)
    assert surviving_prefix == [("/api/v1/network-control", "23")], surviving_prefix
    assert "webd_cookie_write_csrf_ok" in main
    # The module owns exactly the 20 migrated rows: 15 exact + 5 prefix, no
    # predicates. Several paths carry more than one method row (terminal-limits
    # GET/POST; terminal-policies GET/POST; the three terminal-policies/ prefix
    # method-variants; mac-allowlist GET/POST) — matched on path+method, so no
    # predicate is needed. This is the first phase to move JMX_API_PREFIX rows
    # (their legacy strncmp length literals each equal strlen(path), so the
    # prefix flag reproduces the match byte-for-byte).
    assert nc.count("JMX_API_ROUTE(") == 20
    assert nc.count("JMX_API_PREDICATE_ROUTE(") == 0
    assert len(re.findall(r'JMX_API_ROUTE\(\d+,[^)]*JMX_API_EXACT,', nc)) == 15
    assert len(re.findall(r'JMX_API_ROUTE\(\d+,[^)]*JMX_API_PREFIX,', nc)) == 5
    for seq, path, method, flag in (
        (410, "/api/v1/network-control", "GET", "JMX_API_EXACT"),
        (411, "/api/v1/network-control/terminal-limits", "GET", "JMX_API_EXACT"),
        (413, "/api/v1/network-control/terminal-limits/", "PUT,PATCH", "JMX_API_PREFIX"),
        (415, "/api/v1/network-control/terminal-policies/runtime", "GET", "JMX_API_EXACT"),
        (418, "/api/v1/network-control/terminal-policies/", "GET", "JMX_API_PREFIX"),
        (429, "/api/v1/network-control/mac-allowlist/confirm", "POST", "JMX_API_EXACT"),
    ):
        assert re.search(
            r'JMX_API_ROUTE\(%d,\s*"%s",\s*"%s",\s*%s,'
            % (seq, re.escape(path), re.escape(method), flag),
            nc,
        ), path
    # Eighteen borrowed helpers: de-static'd, their single definitions stay in
    # main (shared with the callers that remain in other domains), reused by the
    # module through the internal-header prototypes. This is the full link
    # contract — the 20 moved bodies reach 7 `int` predicate/schema helpers and 11
    # `struct json_object *` response/build/apply helpers. (An earlier draft
    # de-static'd only 7; the module then failed to link against the other 11, so
    # all 18 are asserted here.)
    # (return-type token, total uses that must remain in main = def + callers)
    for helper, rettype, main_uses in (
        ("webd_mac_for_ip", "int ", 2),
        ("webd_netctl_rule_id_ok", "int ", 2),
        ("webd_netctl_terminal_rule_exists", "int ", 1),  # def only
        ("webd_terminal_policy_apply_ok", "int ", 4),
        ("webd_terminal_policy_apply_rollback_noop", "int ", 2),
        ("webd_terminal_policy_id_ok", "int ", 2),
        ("webd_terminal_policy_init_schema", "int ", 3),
        ("webd_netctl_get_response", "struct json_object *", 1),  # def only
        ("webd_netctl_terminal_capabilities", "struct json_object *", 2),
        ("webd_netctl_terminal_rule_build", "struct json_object *", 2),
        ("webd_netctl_terminal_rules", "struct json_object *", 3),
        ("webd_netctl_terminal_write", "struct json_object *", 1),  # def only
        ("webd_terminal_policy_apply", "struct json_object *", 3),
        ("webd_terminal_policy_apply_error", "struct json_object *", 2),
        ("webd_terminal_policy_flowd", "struct json_object *", 2),
        ("webd_terminal_policy_response", "struct json_object *", 1),  # def only
        ("webd_terminal_policy_restore", "struct json_object *", 2),
        ("webd_terminal_policy_write", "struct json_object *", 1),  # def only
    ):
        # No static definition survives in main — it was de-static'd so the
        # module can link against it.
        assert ("static " + rettype + helper + "(") not in main, helper
        # Exactly one (now non-static) definition remains in main.
        assert_exported_definition(helper + "(")
        # Its total footprint in main is the definition plus any in-main callers.
        assert implementation_text().count(helper + "(") >= 2, helper
        # The prototype lives in the internal header, and the module reuses it.
        assert helper in internal, helper
        assert nc.count(helper + "(") >= 1, helper
    # The module includes the borrow header and the http_req header (for the
    # alias preamble), plus libc headers for snprintf/time/getpid used by the
    # moved bodies.
    assert '#include "api_netcontrol_internal.h"' in nc
    assert '#include "webd_http_req.h"' in nc
    for libc in ('<stdio.h>', '<time.h>', '<unistd.h>'):
        assert libc in nc, libc
    # The internal header forward-declares json_object, pulls <stddef.h> for
    # size_t, and includes terminal_policy.h for tp_error_t + the tp_* prototypes
    # the moved bodies call directly.
    assert "struct json_object;" in internal
    assert "<stddef.h>" in internal
    assert "terminal_policy/terminal_policy.h" in internal
    # WEBD_NETCTL_TERMINAL_MAX_RULES moved out of main into the internal header,
    # so both the module (rule-build cap) and the one surviving in-main use share
    # a single definition. Main must NOT redefine it (that would be a redefinition
    # against the header), but must still USE it once.
    assert "#define WEBD_NETCTL_TERMINAL_MAX_RULES" not in main
    assert "#define WEBD_NETCTL_TERMINAL_MAX_RULES 512" in internal
    assert "WEBD_NETCTL_TERMINAL_MAX_RULES" in implementation_text()


def test_cloud_module_owns_the_legacy_branches() -> None:
    main = (WEBD_DIR / "jmx_app_api.c").read_text(encoding="utf-8")
    cloud = (API_DIR / "api_cloud.c").read_text(encoding="utf-8")
    internal = (API_DIR / "api_cloud_internal.h").read_text(encoding="utf-8")
    # The 5 migrated cloud-enrollment dispatch branches (seq 683-687) are gone.
    for gone in (
        'req.path, "/api/v1/cloud/status"',
        'req.path, "/api/v1/cloud/identity"',
        'req.path, "/api/v1/cloud/config"',
        'req.path, "/api/v1/cloud/enroll"',
        'req.path, "/api/v1/cloud/disable"',
    ):
        assert gone not in main, gone
    # No /api/v1/cloud exact dispatch literal survives; all 5 moved. The only
    # surviving cloud literal is the CSRF write-preflight guard's prefix test
    # (strncmp "/api/v1/cloud/"), which STAYS inline and runs before the
    # post-auth dispatch.
    assert re.findall(
        r'!strcmp\(req\.path,\s*"(/api/v1/cloud(?:/[^"]*)?)"', main) == []
    surviving_prefix = re.findall(
        r'!strncmp\(req\.path,\s*"(/api/v1/cloud[^"]*)"', main)
    assert surviving_prefix == ["/api/v1/cloud/"], surviving_prefix
    assert "webd_cookie_write_csrf_ok" in main
    # The integrated cloud module owns 18 plain routes: 15 exact and 3 prefix.
    # The original enrollment rows retain their method/path/flag contracts.
    assert cloud.count("JMX_API_ROUTE(") == 18
    assert cloud.count("JMX_API_PREDICATE_ROUTE(") == 0
    assert len(re.findall(r'JMX_API_ROUTE\(\d+,[^)]*JMX_API_EXACT,', cloud)) == 15
    assert len(re.findall(r'JMX_API_ROUTE\(\d+,[^)]*JMX_API_PREFIX,', cloud)) == 3
    for seq, path, method in (
        (683, "/api/v1/cloud/status", "GET"),
        (685, "/api/v1/cloud/config", "POST,PUT"),
        (687, "/api/v1/cloud/disable", "POST"),
    ):
        assert re.search(
            r'JMX_API_ROUTE\(%d,\s*"%s",\s*"%s",\s*JMX_API_EXACT,'
            % (seq, re.escape(path), method),
            cloud,
        ), path
    # Two borrowed helpers: de-static'd, their single definitions stay in main,
    # reused by the module through the internal-header prototypes.
    for helper in ("webd_cloud_component_response", "webd_cloud_config_write"):
        assert ("static struct json_object *" + helper + "(") not in main, helper
        assert_exported_definition(helper + "(")
        assert helper in internal, helper
        assert cloud.count(helper + "(") >= 1, helper
    assert '#include "api_cloud_internal.h"' in cloud
    assert '#include "webd_http_req.h"' in cloud
    assert "struct json_object;" in internal


def test_config_module_owns_the_legacy_branches() -> None:
    main = (WEBD_DIR / "jmx_app_api.c").read_text(encoding="utf-8")
    config = (API_DIR / "api_config.c").read_text(encoding="utf-8")
    # The 6 migrated transactional-config dispatch branches (seq 557-562) are gone
    # from the monolith.
    for gone in (
        'req.path, "/api/v1/config/snapshot"',
        'req.path, "/api/v1/config/validate"',
        'req.path, "/api/v1/config/apply"',
        'req.path, "/api/v1/config/confirm"',
        'req.path, "/api/v1/config/rollback"',
        'req.path, "/api/v1/config/last-apply"',
    ):
        assert gone not in main, gone
    # No /api/v1/config exact or prefix literal survives in the monolith: all 6
    # moved, and none appears in the CSRF guard's OR-list.
    assert re.findall(
        r'!strcmp\(req\.path,\s*"(/api/v1/config(?:/[^"]*)?)"', main) == []
    assert re.findall(r'!strncmp\(req\.path,\s*"(/api/v1/config[^"]*)"', main) == []
    # The module owns exactly the 6 migrated single-exact rows; snapshot and
    # last-apply carry no method check (methods="", any method). No prefix, no
    # predicate routes.
    assert config.count("JMX_API_ROUTE(") == 6
    assert config.count("JMX_API_PREDICATE_ROUTE(") == 0
    assert len(re.findall(r'JMX_API_ROUTE\(\d+,[^)]*JMX_API_EXACT,', config)) == 6
    assert len(re.findall(r'JMX_API_ROUTE\(\d+,\s*"[^"]*",\s*"",', config)) == 2
    for seq, path, method in (
        (557, "/api/v1/config/snapshot", ""),
        (559, "/api/v1/config/apply", "POST"),
        (562, "/api/v1/config/last-apply", ""),
    ):
        assert re.search(
            r'JMX_API_ROUTE\(%d,\s*"%s",\s*"%s",\s*JMX_API_EXACT,'
            % (seq, re.escape(path), method),
            config,
        ), path
    # Zero borrowed helpers: no api_config_internal.h, no de-static. The
    # jmx_config_* entry points come from the public jmx_app_api.h.
    assert not (API_DIR / "api_config_internal.h").exists()
    assert '#include "webd_http_req.h"' in config
    assert '#include "../jmx_app_api.h"' in config


def test_bulkip_module_owns_the_legacy_branches() -> None:
    main = (WEBD_DIR / "jmx_app_api.c").read_text(encoding="utf-8")
    bulkip = (API_DIR / "api_bulkip.c").read_text(encoding="utf-8")
    # The 8 migrated bulk-IP BFF dispatch branches (seq 526-533) are gone from the
    # monolith.
    for gone in (
        'req.path, "/api/v1/bulk-ip"',
        'req.path, "/api/v1/bulk-ip/transactions"',
        'req.path, "/api/v1/bulk-ip/refresh"',
        'req.path, "/api/v1/bulk-ip/reserve"',
        'req.path, "/api/v1/bulk-ip/delete"',
        'req.path, "/api/v1/bulk-ip/static-reservations/transactions"',
        'req.path, "/api/v1/bulk-ip/import/preview"',
        'req.path, "/api/v1/bulk-ip/import/commit"',
    ):
        assert gone not in main, gone
    # No /api/v1/bulk-ip exact or prefix literal survives in the monolith: all 8
    # moved. The GET /api/v1/bulk-ip/import/jobs/<job_id> route STAYS inline but is
    # matched by the path helper webd_ipam_job_path_id() (no req.path literal), so
    # it is not a surviving literal and is absent from the merged inventory.
    assert re.findall(
        r'!strcmp\(req\.path,\s*"(/api/v1/bulk-ip(?:/[^"]*)?)"', main) == []
    assert re.findall(
        r'!strncmp\(req\.path,\s*"(/api/v1/bulk-ip[^"]*)"', main) == []
    assert "webd_ipam_job_path_id(req.path" in main
    # The module owns exactly the 8 migrated single-exact rows. No prefix, no
    # predicate routes.
    assert bulkip.count("JMX_API_ROUTE(") == 8
    assert bulkip.count("JMX_API_PREDICATE_ROUTE(") == 0
    assert len(re.findall(r'JMX_API_ROUTE\(\d+,[^)]*JMX_API_EXACT,', bulkip)) == 8
    for seq, path, method, flag in (
        (526, "/api/v1/bulk-ip", "GET", "JMX_API_EXACT"),
        (529, "/api/v1/bulk-ip/reserve", "POST,PUT", "JMX_API_EXACT"),
        (533, "/api/v1/bulk-ip/import/commit", "POST", "JMX_API_EXACT"),
    ):
        assert re.search(
            r'JMX_API_ROUTE\(%d,\s*"%s",\s*"%s",\s*%s,'
            % (seq, re.escape(path), re.escape(method), flag),
            bulkip,
        ), path
    # Zero borrowed helpers: no api_bulkip_internal.h, no de-static.
    assert not (API_DIR / "api_bulkip_internal.h").exists()
    assert '#include "webd_http_req.h"' in bulkip
    assert '#include "../jmx_app_api.h"' in bulkip


def test_storage_module_owns_the_legacy_branches() -> None:
    main = (WEBD_DIR / "jmx_app_api.c").read_text(encoding="utf-8")
    storage = (API_DIR / "api_storage.c").read_text(encoding="utf-8")
    # The 9 migrated storage BFF dispatch branches (seq 401-409) are gone from the
    # monolith. Sample the overview, migration, both raid alias spellings, and the
    # file-browser trio.
    for gone in (
        'req.path, "/api/v1/storage/overview"',
        'req.path, "/api/v1/storage/partitions"',
        'req.path, "/api/v1/storage/raids"',
        'req.path, "/api/v1/storage/raid/scan"',
        'req.path, "/api/v1/storage/files"',
        'req.path, "/api/v1/storage/files/content"',
        'req.path, "/api/v1/storage/files/mutate"',
        'req.path, "/api/v1/storage/file-services"',
    ):
        assert gone not in main, gone
    # Exactly TWO /api/v1/storage exact literals survive in the monolith, both
    # legitimately: GET|HEAD /api/v1/storage/files/raw (a RAW_FD download that
    # writes the socket and close(fd)s, STAYS inline in the early block), and
    # /api/v1/storage/migration as a member of the CSRF write-preflight guard's
    # OR-list (which STAYS inline and runs before the post-auth dispatch, so the
    # moved storage/migration POST still passes it). Neither is a surviving
    # storage dispatch route.
    surviving_exact = sorted(set(re.findall(
        r'!strcmp\(req\.path,\s*"(/api/v1/storage(?:/[^"]*)?)"', main)))
    assert surviving_exact == [
        "/api/v1/storage/files/raw",
        "/api/v1/storage/files/upload",
        "/api/v1/storage/files/upload/chunk",
        "/api/v1/storage/migration",
    ], surviving_exact
    assert "webd_cookie_write_csrf_ok" in main
    # Current storage routes include the original raid|raids predicate alias,
    # 14 exact routes and the files/search/jobs/ prefix.
    assert storage.count("JMX_API_ROUTE(") == 15
    assert storage.count("JMX_API_PREDICATE_ROUTE(") == 1
    assert len(re.findall(r'JMX_API_ROUTE\(\d+,[^)]*JMX_API_EXACT,', storage)) == 14
    assert len(re.findall(r'JMX_API_ROUTE\(\d+,[^)]*JMX_API_PREFIX,', storage)) == 1
    assert len(re.findall(
        r'JMX_API_PREDICATE_ROUTE\(\d+,[^)]*JMX_API_PREDICATE_ONLY,', storage)) == 1
    for seq, path, method, flag in (
        (401, "/api/v1/storage/overview", "GET", "JMX_API_EXACT"),
        (408, "/api/v1/storage/files/mutate", "POST", "JMX_API_EXACT"),
        (409, "/api/v1/storage/file-services", "GET", "JMX_API_EXACT"),
    ):
        assert re.search(
            r'JMX_API_ROUTE\(%d,\s*"%s",\s*"%s",\s*%s,'
            % (seq, re.escape(path), re.escape(method), flag),
            storage,
        ), path
    assert re.search(
        r'JMX_API_PREDICATE_ROUTE\(404,\s*"/api/v1/storage/raid",\s*"GET",\s*'
        r'JMX_API_PREDICATE_ONLY,', storage)
    for alias in ('"/api/v1/storage/raid"', '"/api/v1/storage/raids"'):
        assert storage.count(alias) >= 1, alias
    # Zero borrowed helpers: no api_storage_internal.h, no de-static. The module
    # includes the http_req header (alias preamble) and limits.h (PATH_MAX); every
    # symbol it uses is already exported.
    assert not (API_DIR / "api_storage_internal.h").exists()
    assert '#include "webd_http_req.h"' in storage
    assert "#include <limits.h>" in storage
    assert '#include "../jmx_app_api.h"' in storage


def test_setup_module_owns_the_legacy_branches() -> None:
    main = (WEBD_DIR / "jmx_app_api.c").read_text(encoding="utf-8")
    setup = (API_DIR / "api_setup.c").read_text(encoding="utf-8")
    internal = (API_DIR / "api_setup_internal.h").read_text(encoding="utf-8")
    pubhdr = (WEBD_DIR / "jmx_app_api.h").read_text(encoding="utf-8")
    # The 20 migrated first-run setup wizard dispatch branches (seq 48-68, minus
    # 53=save-lan which STAYS) are gone from the monolith. Sample the wizard
    # status, several write steps, and BOTH detect-wan alias spellings.
    for gone in (
        'req.path, "/api/v1/setup/status"',
        'req.path, "/api/v1/setup/start"',
        'req.path, "/api/v1/setup/save-device"',
        'req.path, "/api/v1/setup/apply"',
        'req.path, "/api/v1/setup/finish"',
        'req.path, "/api/v1/setup/llm"',
        'req.path, "/api/v1/setup/oauth/start"',
        'req.path, "/api/v1/setup/detect-wan/start"',
        'req.path, "/api/v1/setup/detect_wan/start"',
    ):
        assert gone not in main, gone
    # Exactly TWO cross-domain OR branches STAY inline in the monolith: they OR a
    # setup path with a path owned/handled elsewhere (device/config/lan is also a
    # pre-auth public-write target; auth/pair/cancel is also handled pre-auth), so
    # the setup module deliberately does not take ownership of a device or auth
    # path. Their setup-side !strcmp literals are the ONLY surviving
    # /api/v1/setup exact dispatch branches.
    surviving_exact = sorted(set(re.findall(
        r'!strcmp\(req\.path,\s*"(/api/v1/setup(?:/[^"]*)?)"', main)))
    assert surviving_exact == [
        "/api/v1/setup/app-pairing/cancel",
        "/api/v1/setup/save-lan",
    ], surviving_exact
    assert 'req.path, "/api/v1/device/config/lan"' in main
    assert 'req.path, "/api/v1/auth/pair/cancel"' in main
    # The pre-dispatch caller_authorized_initialized_write stamp (a body-mutation
    # preamble, strncmp len 14 == strlen("/api/v1/setup/")) STAYS inline: it runs
    # before the post-auth router dispatch, so every moved setup write is still
    # stamped before reaching the module handlers.
    surviving_prefix = re.findall(
        r'!strncmp\(req\.path,\s*"(/api/v1/setup[^"]*)",\s*(\d+)\)', main)
    assert surviving_prefix == [("/api/v1/setup/", "14")], surviving_prefix
    # The module owns exactly the 20 migrated rows: 18 single-exact + 2 multi-exact
    # detect-wan alias routes emitted as JMX_API_PREDICATE_ROUTE + PREDICATE_ONLY
    # (the hyphen/underscore spellings are one route each; the predicate OR's the
    # two exact aliases, reproducing all_paths=2, match=exact). No prefix routes.
    assert setup.count("JMX_API_ROUTE(") == 21
    assert setup.count("JMX_API_PREDICATE_ROUTE(") == 2
    assert len(re.findall(r'JMX_API_ROUTE\(\d+,[^)]*JMX_API_EXACT,', setup)) == 21
    assert len(re.findall(
        r'JMX_API_PREDICATE_ROUTE\(\d+,[^)]*JMX_API_PREDICATE_ONLY,', setup)) == 2
    for seq, path, method, flag in (
        (48, "/api/v1/setup/status", "GET", "JMX_API_EXACT"),
        (57, "/api/v1/setup/finish", "POST", "JMX_API_EXACT"),
        (68, "/api/v1/setup/oauth/start", "POST", "JMX_API_EXACT"),
    ):
        assert re.search(
            r'JMX_API_ROUTE\(%d,\s*"%s",\s*"%s",\s*%s,'
            % (seq, re.escape(path), re.escape(method), flag),
            setup,
        ), path
    # The two predicate routes carry both alias spellings; the inventory reads
    # all_paths from the predicate body, reproducing the legacy OR match.
    assert re.search(
        r'JMX_API_PREDICATE_ROUTE\(60,\s*"/api/v1/setup/detect-wan/start",\s*'
        r'"POST",\s*JMX_API_PREDICATE_ONLY,', setup)
    assert re.search(
        r'JMX_API_PREDICATE_ROUTE\(61,\s*"/api/v1/setup/detect-wan/status",\s*'
        r'"GET",\s*JMX_API_PREDICATE_ONLY,', setup)
    for alias in (
        '"/api/v1/setup/detect-wan/start"', '"/api/v1/setup/detect_wan/start"',
        '"/api/v1/setup/detect-wan/status"', '"/api/v1/setup/detect_wan/status"',
    ):
        assert setup.count(alias) >= 1, alias
    # Six borrowed helpers: de-static'd, their single definitions stay in main
    # (shared with the callers that remain in other domains), reused by the module
    # through prototypes. Five setup/wifi response helpers live in the
    # domain-internal header; the generic jmx_app_audit_log_ex (39 remaining
    # in-main uses across domains) lives in the public jmx_app_api.h beside
    # jmx_app_audit_log — a maintainer finds it with the code that uses it.
    for helper, rettype, main_uses in (
        ("app_setup_finish_response", "struct json_object *", 2),
        ("app_setup_oauth_response", "struct json_object *", 2),
        ("app_setup_security_response", "struct json_object *", 2),
        ("app_setup_status_slice_response", "struct json_object *", 2),
        ("app_wifi_capability_disabled_response", "struct json_object *", 2),
    ):
        assert ("static " + rettype + helper + "(") not in main, helper
        assert_exported_definition(helper + "(")
        assert implementation_text().count(helper + "(") >= 2, helper
        assert helper in internal, helper
        assert setup.count(helper + "(") >= 1, helper
    # The generic audit helper: de-static'd, one def in main, declared in the
    # PUBLIC header (not the setup-internal header), reused by the module.
    assert "static void jmx_app_audit_log_ex(" not in main
    assert_exported_definition("jmx_app_audit_log_ex(")
    assert "void jmx_app_audit_log_ex(" in pubhdr
    assert setup.count("jmx_app_audit_log_ex(") >= 1
    # The module includes the borrow header and the http_req header (alias
    # preamble); no libubus/strbuf gap was needed.
    assert '#include "api_setup_internal.h"' in setup
    assert '#include "webd_http_req.h"' in setup
    assert "struct json_object;" in internal


if __name__ == "__main__":
    test_matcher_reproduces_chain_semantics()
    test_the_fixture_catches_a_broken_matcher()
    test_routing_module_owns_all_legacy_branches()
    test_clients_list_module_owns_the_legacy_branch()
    test_client_control_module_owns_the_legacy_branch()
    test_client_connections_module_owns_the_legacy_branch()
    test_client_profile_module_owns_the_legacy_branch()
    test_flowd_module_owns_the_legacy_branches()
    test_aegis_module_owns_the_legacy_branches()
    test_wifi_module_owns_the_legacy_branches()
    test_logd_module_owns_the_legacy_branches()
    test_notifyd_module_owns_the_legacy_branches()
    test_audit_module_owns_the_legacy_branches()
    test_wan_module_owns_the_legacy_branches()
    test_authentication_module_owns_the_legacy_branches()
    test_logs_module_owns_the_legacy_branches()
    test_netcontrol_module_owns_the_legacy_branches()
    test_setup_module_owns_the_legacy_branches()
    test_storage_module_owns_the_legacy_branches()
    test_bulkip_module_owns_the_legacy_branches()
    test_config_module_owns_the_legacy_branches()
    test_cloud_module_owns_the_legacy_branches()
    print(f"ok: matcher semantics locked, {len(MUTATIONS)} mutations caught, current "
          "production tables registered")

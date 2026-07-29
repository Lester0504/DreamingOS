#!/usr/bin/env python3
"""Static control-plane contract for Gateway Shadow (VRRP HA).

This suite deliberately describes the minimum honest first-phase backend.  It
may remain red while the C implementation is being developed, but a missing
route or a capability claim must never be hidden by a permissive fallback.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORE_PATH = ROOT / "src/jmx_dreamingwrt_api.c"
MODULE_PATH = ROOT / "src/jmx_gateway_shadow.c"
HEADER_PATH = ROOT / "src/jmx_gateway_shadow.h"
NETCONFIG_PATH = ROOT / "src/jmx_netconfig_db.c"
WEB_PATH = ROOT / "src/webd/jmx_app_api.c"
PERMS_PATH = ROOT / "src/webd/jmx_app_perms.c"
SOURCE_MAKEFILE_PATH = ROOT / "src/Makefile"

CORE = CORE_PATH.read_text(encoding="utf-8")
HEADER = HEADER_PATH.read_text(encoding="utf-8")
NETCONFIG = NETCONFIG_PATH.read_text(encoding="utf-8")
WEB = WEB_PATH.read_text(encoding="utf-8")
PERMS = PERMS_PATH.read_text(encoding="utf-8")
SOURCE_MAKEFILE = SOURCE_MAKEFILE_PATH.read_text(encoding="utf-8")

REST_ROUTES = (
    ("GET", "/api/v1/network/gateway-shadow", "gateway_shadow_get"),
    ("POST", "/api/v1/network/gateway-shadow/preflight", "gateway_shadow_preflight"),
    ("POST", "/api/v1/network/gateway-shadow/pairing/start", "gateway_shadow_pairing_start"),
    ("POST", "/api/v1/network/gateway-shadow/pairing/approve", "gateway_shadow_pairing_approve"),
    ("POST", "/api/v1/network/gateway-shadow/save", "gateway_shadow_save"),
    ("POST", "/api/v1/network/gateway-shadow/apply", "gateway_shadow_apply"),
    ("POST", "/api/v1/network/gateway-shadow/disable", "gateway_shadow_disable"),
    ("GET", "/api/v1/network/gateway-shadow/status", "gateway_shadow_status"),
)
UBUS_METHODS = tuple(item[2] for item in REST_ROUTES)
WRITE_PATHS = tuple(path for method, path, _ in REST_ROUTES if method == "POST")
SECRET_FIELDS = ("auth_key", "pairing_secret", "vrrp_secret", "password", "secret")


def module_source() -> str:
    assert MODULE_PATH.is_file(), (
        "Gateway Shadow implementation is missing: expected "
        f"{MODULE_PATH.relative_to(ROOT)}"
    )
    return MODULE_PATH.read_text(encoding="utf-8")


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    return text[first:text.index(end, first)]


def c_function(text: str, name: str) -> str:
    """Extract one C function body without depending on source ordering."""
    match = re.search(
        rf"(?:static\s+)?(?:struct\s+json_object\s*\*\s*|int\s+|void\s+){re.escape(name)}\s*\([^;]*?\)\s*\{{",
        text,
        re.DOTALL,
    )
    assert match, f"missing C function {name}"
    start = match.start()
    opening = text.find("{", match.start(), match.end())
    depth = 0
    for offset in range(opening, len(text)):
        char = text[offset]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start:offset + 1]
    raise AssertionError(f"unterminated C function {name}")


def route_clause(text: str, path: str, method: str, ubus_method: str) -> str:
    """Return a dispatch clause containing the exact REST-to-ubus mapping."""
    needle = f'"{path}"'
    for match in re.finditer(re.escape(needle), text):
        start = text.rfind("else if", 0, match.start())
        if start < 0 or match.start() - start > 500:
            continue
        end = text.find("else if", match.end())
        if end < 0:
            end = min(len(text), match.end() + 1800)
        clause = text[start:end]
        if (f'"{method}"' in clause and f'"{ubus_method}"' in clause and
                ("app_ubus_invoke" in clause or "app_ubus_or_error" in clause)):
            return clause
    raise AssertionError(f"missing {method} {path} -> {ubus_method} REST dispatch")


def csrf_gate_covers(gate: str, path: str) -> bool:
    if path in re.findall(r'!strcmp\(req\.path,\s*"([^"]+)"\)', gate):
        return True
    for prefix, raw_length in re.findall(
        r'!strncmp\(req\.path,\s*"([^"]+)",\s*(\d+)\)', gate
    ):
        if int(raw_length) == len(prefix) and path.startswith(prefix):
            return True
    return False


def test_dedicated_schema_is_independent_from_network_global() -> None:
    source = module_source()
    for table in (
        "gateway_shadow_config",
        "gateway_shadow_peer",
        "gateway_shadow_runtime",
    ):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in source

    for forbidden in (
        "jmx_netconfig_global_set",
        "jmx_netconfig_global_apply",
        "UPDATE network_global",
        "INSERT INTO network_global",
    ):
        assert forbidden not in source

    global_get = between(
        NETCONFIG,
        "struct json_object *jmx_netconfig_global_get(",
        "struct json_object *jmx_netconfig_network_overview",
    )
    global_set = between(
        NETCONFIG,
        "int jmx_netconfig_global_set(",
        "int jmx_netconfig_global_apply(",
    )
    global_apply = between(
        NETCONFIG,
        "int jmx_netconfig_global_apply(",
        "static void nc_physical_port_owner",
    )
    for legacy_global_path in (global_get, global_set, global_apply):
        assert "gateway_shadow" not in legacy_global_path


def test_all_eight_rest_routes_delegate_to_dedicated_ubus_methods() -> None:
    assert len(REST_ROUTES) == 8
    for method, path, ubus_method in REST_ROUTES:
        clause = route_clause(WEB, path, method, ubus_method)
        assert "network_global" not in clause


def test_all_eight_ubus_methods_are_registered_and_call_the_module() -> None:
    assert '#include "jmx_gateway_shadow.h"' in CORE
    for method in UBUS_METHODS:
        assert f'UBUS_METHOD("{method}"' in CORE, f"missing ubus registration: {method}"
        direct_call = f"jmx_{method}(" in CORE
        generated_handler = re.search(
            rf"GS_HANDLER\s*\([^,]+,\s*jmx_{re.escape(method)}\s*\)", CORE
        )
        assert direct_call or generated_handler, (
            f"ubus handler {method} does not call jmx_{method}"
        )

    source = module_source()
    for method in UBUS_METHODS:
        c_function(source, f"jmx_{method}")

    for function in (
        "jmx_gateway_shadow_schema_ensure",
        "jmx_gateway_shadow_get",
        "jmx_gateway_shadow_preflight",
        "jmx_gateway_shadow_pairing_start",
        "jmx_gateway_shadow_pairing_approve",
        "jmx_gateway_shadow_save",
        "jmx_gateway_shadow_apply",
        "jmx_gateway_shadow_disable",
        "jmx_gateway_shadow_status",
    ):
        assert function in HEADER


def test_pairing_is_honestly_disabled_until_mutual_auth_exists() -> None:
    source = module_source()
    assert re.search(
        r'"pairing_supported"\s*,\s*json_object_new_boolean\(0\)', source
    )
    assert "mutual_authenticated_peer_pairing_pending" in source

    for function in (
        "jmx_gateway_shadow_pairing_start",
        "jmx_gateway_shadow_pairing_approve",
    ):
        body = c_function(source, function)
        helper = c_function(source, "gs_pairing_disabled") if "gs_pairing_disabled" in body else ""
        behavior = body + helper
        assert "capability_disabled" in behavior, f"{function} does not fail closed"
        assert "mutual_authenticated_peer_pairing_pending" in behavior, (
            f"{function} does not return the honest pending reason"
        )
        for mutation in (
            "INSERT INTO gateway_shadow_peer",
            "UPDATE gateway_shadow_peer",
            "DELETE FROM gateway_shadow_peer",
            "auth.key",
        ):
            assert mutation not in behavior, f"disabled pairing mutates state via {mutation}"


def test_secret_material_is_write_only_and_stored_with_owner_permissions() -> None:
    source = module_source()
    save = c_function(source, "jmx_gateway_shadow_save")

    assert any(f'"{field}"' in save for field in SECRET_FIELDS), (
        "save must accept an explicitly write-only authentication field"
    )
    assert "/etc/dreamingwrt/gateway-shadow/auth.key" in source
    assert re.search(r'\b0600\b|S_IRUSR\s*\|\s*S_IWUSR', source)
    assert re.search(
        r'"secrets_write_only"\s*,\s*json_object_new_boolean\(1\)', source
    ), "capabilities must declare secrets_write_only=true"


def test_secret_plaintext_is_never_added_to_json_responses() -> None:
    source = module_source()
    response_add = re.compile(
        r'json_object_object_add\s*\([^,]+,\s*"(' +
        "|".join(re.escape(field) for field in SECRET_FIELDS) +
        r')"\s*,',
        re.MULTILINE,
    )
    assert not response_add.search(source), "secret plaintext must never be added to a response"
    response_helper = re.compile(
        r'(?:gs_add_string|json_object_object_add)\s*\([^,]+,\s*"(' +
        "|".join(re.escape(field) for field in SECRET_FIELDS) +
        r')"\s*,',
        re.MULTILINE,
    )
    assert not response_helper.search(source), "response helper must not emit secret plaintext"


def test_apply_consumes_preflight_before_attempting_activation() -> None:
    source = module_source()
    apply = c_function(source, "jmx_gateway_shadow_apply")

    assert "jmx_gateway_shadow_preflight" in apply, "apply must consume the preflight result"


def test_apply_is_fail_closed_while_pairing_or_dependencies_are_unready() -> None:
    source = module_source()
    apply = c_function(source, "jmx_gateway_shadow_apply")
    preflight = c_function(source, "jmx_gateway_shadow_preflight")

    assert "mutual_authenticated_peer_pairing_pending" in apply + preflight, (
        "the apply preflight path must report pairing pending"
    )
    assert "capability_disabled" in apply or "preflight_failed" in apply, (
        "unready apply must return a fail-closed error"
    )
    for field in ("applied", "changed", "rollback_available"):
        assert re.search(
            rf'"{field}"\s*,\s*json_object_new_boolean\(0\)', apply
        ), f"fail-closed apply response must report {field}=false"
    assert re.search(
        r'"session_continuity"\s*,\s*json_object_new_string\("best_effort"\)',
        source,
    )
    assert not re.search(r'json_object_new_string\("seamless"\)', source)
    for side_effect in (
        "system(", "popen(", "execl(", "execv(",
        "/etc/init.d/keepalived", "/etc/init.d/conntrackd",
    ):
        assert side_effect not in apply, f"blocked apply still invokes {side_effect}"


def test_gateway_shadow_module_is_linked_into_core() -> None:
    assert "jmx_gateway_shadow.o" in SOURCE_MAKEFILE
    assert re.search(r'\bOBJS\s*\+=.*jmx_gateway_shadow\.o', SOURCE_MAKEFILE)


def test_permissions_are_owner_only_for_writes() -> None:
    compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    assert compiler, "a C compiler is required for the permission contract test"

    cases = []
    for method, path, _ in REST_ROUTES:
        expected = "JMX_RISK_LOW" if method == "GET" else "JMX_RISK_HIGH"
        cases.append(f'    CHECK_RISK("{method}", "{path}", {expected});')

    harness = r'''
#include <stdio.h>
#include "jmx_app_perms.h"

#define CHECK_RISK(method, path, expected) do { \
    jmx_risk_t actual = jmx_perm_route_risk((method), (path)); \
    if (actual != (expected)) { \
        fprintf(stderr, "%s %s: risk %d, expected %d\n", \
                (method), (path), (int)actual, (int)(expected)); \
        return 1; \
    } \
} while (0)

int main(void)
{
__CASES__
    if (!jmx_perm_check(JMX_ROLE_OWNER, JMX_RISK_HIGH) ||
        jmx_perm_check(JMX_ROLE_ADMIN, JMX_RISK_HIGH) ||
        jmx_perm_check(JMX_ROLE_OPERATOR, JMX_RISK_HIGH) ||
        jmx_perm_check(JMX_ROLE_VIEWER, JMX_RISK_HIGH) ||
        jmx_perm_check(JMX_ROLE_AI_AGENT, JMX_RISK_HIGH)) {
        fputs("Gateway Shadow writes must be owner-only\n", stderr);
        return 1;
    }
    return 0;
}
'''.replace("__CASES__", "\n".join(cases))

    with tempfile.TemporaryDirectory(prefix="gateway-shadow-perms-") as raw:
        directory = Path(raw)
        source_path = directory / "contract.c"
        executable = directory / "contract"
        source_path.write_text(harness, encoding="utf-8")
        subprocess.run(
            [
                compiler,
                "-std=c99",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I",
                str(ROOT / "src/webd"),
                str(PERMS_PATH),
                str(source_path),
                "-o",
                str(executable),
            ],
            check=True,
        )
        subprocess.run([str(executable)], check=True)


def test_cookie_authenticated_writes_are_csrf_guarded() -> None:
    gate = between(
        WEB,
        'if ((!strncmp(req.path, "/api/v1/uploads"',
        "const char *required_permission",
    )
    for path in WRITE_PATHS:
        assert csrf_gate_covers(gate, path), f"CSRF gate does not cover {path}"
    assert "!webd_cookie_write_csrf_ok(&req)" in gate


if __name__ == "__main__":
    tests = [
        value for name, value in sorted(globals().items())
        if name.startswith("test_") and callable(value)
    ]
    failures = []
    for test in tests:
        try:
            test()
        except Exception as exc:  # report every red contract in one local run
            failures.append((test.__name__, exc))
            print(f"FAIL: {test.__name__}: {exc}", file=sys.stderr)
    if failures:
        print(
            f"failed: {len(failures)}/{len(tests)} Gateway Shadow backend contract tests",
            file=sys.stderr,
        )
        raise SystemExit(1)
    print(f"ok: {len(tests)} Gateway Shadow backend contract tests")

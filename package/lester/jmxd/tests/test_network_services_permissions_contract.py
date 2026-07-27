#!/usr/bin/env python3
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PERMS_PATH = ROOT / "src/webd/jmx_app_perms.c"
WEB_PATH = ROOT / "src/webd/jmx_app_api.c"
PERMS = PERMS_PATH.read_text(encoding="utf-8")
WEB = WEB_PATH.read_text(encoding="utf-8")

ROUTES = (
    "/api/v1/services/dhcp",
    "/api/v1/services/dns/wan-policy",
    "/api/v1/services/upnp",
    "/api/v1/services/upnp/acl",
    "/api/v1/services/upnp/mappings",
)
WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")


def between(text: str, start: str, end: str) -> str:
    first = text.index(start)
    return text[first:text.index(end, first)]


def csrf_gate_covers(gate: str, route: str) -> bool:
    exact_routes = re.findall(r'!strcmp\(req\.path,\s*"([^"]+)"\)', gate)
    if route in exact_routes:
        return True

    for prefix, length in re.findall(
        r'!strncmp\(req\.path,\s*"([^"]+)",\s*(\d+)\)', gate
    ):
        if int(length) == len(prefix) and route.startswith(prefix):
            return True
    return False


def test_routes_have_explicit_medium_risk_entries() -> None:
    for route in ROUTES:
        pattern = (
            r'\{\s*"' + re.escape(route) +
            r'",\s*"POST,PUT,PATCH,DELETE",\s*JMX_RISK_MEDIUM\s*\}'
        )
        assert re.search(pattern, PERMS), f"missing explicit medium-risk entry for {route}"


def test_role_and_readonly_contract_against_compiled_permission_code() -> None:
    compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    assert compiler, "a C compiler is required for the permission contract test"

    cases = []
    for route in ROUTES:
        cases.append(f'    CHECK_RISK("GET", "{route}", JMX_RISK_LOW);')
        cases.append(f'    CHECK_RISK("HEAD", "{route}", JMX_RISK_LOW);')
        for method in WRITE_METHODS:
            cases.append(f'    CHECK_RISK("{method}", "{route}", JMX_RISK_MEDIUM);')

    harness = """
#include <stdio.h>
#include "jmx_app_perms.h"

#define CHECK_RISK(method, path, expected) do { \\
    jmx_risk_t actual = jmx_perm_route_risk((method), (path)); \\
    if (actual != (expected)) { \\
        fprintf(stderr, "%s %s: risk %d, expected %d\\n", \\
                (method), (path), (int)actual, (int)(expected)); \\
        return 1; \\
    } \\
} while (0)

int main(void)
{
__CASES__
    if (!jmx_perm_check(JMX_ROLE_ADMIN, JMX_RISK_MEDIUM) ||
        !jmx_perm_check(JMX_ROLE_OWNER, JMX_RISK_MEDIUM) ||
        jmx_perm_check(JMX_ROLE_OPERATOR, JMX_RISK_MEDIUM) ||
        jmx_perm_check(JMX_ROLE_VIEWER, JMX_RISK_MEDIUM) ||
        jmx_perm_check(JMX_ROLE_AI_AGENT, JMX_RISK_MEDIUM)) {
        fputs("medium-risk role contract failed\\n", stderr);
        return 1;
    }
    return 0;
}
""".replace("__CASES__", "\n".join(cases))

    with tempfile.TemporaryDirectory(prefix="jmxd-network-services-perms-") as tmp:
        tmp_path = Path(tmp)
        include_dir = tmp_path / "include/json-c"
        include_dir.mkdir(parents=True)
        (include_dir / "json.h").write_text("", encoding="utf-8")
        harness_path = tmp_path / "contract.c"
        binary_path = tmp_path / "contract"
        harness_path.write_text(harness, encoding="utf-8")
        subprocess.run(
            [
                compiler,
                "-std=c99",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I",
                str(tmp_path / "include"),
                "-I",
                str(ROOT / "src/webd"),
                str(PERMS_PATH),
                str(harness_path),
                "-o",
                str(binary_path),
            ],
            check=True,
        )
        subprocess.run([str(binary_path)], check=True)


def test_cookie_writes_use_existing_same_origin_guard_but_reads_do_not() -> None:
    helper = between(
        WEB,
        "static int webd_cookie_write_csrf_ok",
        "static struct json_object *webd_user_from_token",
    )
    for readonly_method in ('"GET"', '"HEAD"', '"OPTIONS"'):
        assert readonly_method in helper
    assert "!req->auth_via_cookie" in helper
    assert '"same-origin"' in helper

    gate = between(
        WEB,
        'if ((!strncmp(req.path, "/api/v1/uploads"',
        "const char *required_permission",
    )
    for route in ROUTES:
        assert csrf_gate_covers(gate, route), f"CSRF gate does not cover {route}"
    assert "!webd_cookie_write_csrf_ok(&req)" in gate


if __name__ == "__main__":
    test_routes_have_explicit_medium_risk_entries()
    test_role_and_readonly_contract_against_compiled_permission_code()
    test_cookie_writes_use_existing_same_origin_guard_but_reads_do_not()
    print("ok: network-service writes are admin-scoped and cookie-CSRF guarded")

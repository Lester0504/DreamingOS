#!/usr/bin/env python3
"""Policy write ownership plus executable old/new path predicate comparison."""

import re
import subprocess
import tempfile
from pathlib import Path

from webd_sources import webd_module_text, webd_source_files


def test_single_definitions_and_paths():
    main = webd_module_text("jmx_app_api.c")
    modules = {n: webd_module_text(n) for n in (
        "api_policy_write.c", "api_policy_firewall.c", "api_policy_services.c")}
    names = []
    for name, text in modules.items():
        assert len(text.splitlines()) <= 5000, name
        names += re.findall(
            r"(?m)^(?:static\s+)?[A-Za-z_][\w \t*]*\b(webd_policy_\w+)"
            r"\s*\([^;{}]*\)\s*\{", text)
    assert len(names) == 117
    assert len(set(names)) == 117
    for name in names:
        pattern = rf"(?m)^(?:static\s+)?[A-Za-z_][\w \t*]*\b{name}\s*\([^;{{}}]*\)\s*\{{"
        assert not re.search(pattern, main), name
    assert "webd_policy_write_preview_response(&req" not in main
    all_source = "\n".join(p.read_text() for p in webd_source_files())
    for name in (
        "WEBD_POLICY_CONFIG_FIREWALL", "WEBD_POLICY_CONFIG_NETWORK",
        "WEBD_POLICY_CONFIG_DHCP", "WEBD_POLICY_CONFIG_SQM", "WEBD_POLICY_CONFIG_DB",
        "WEBD_POLICY_SET_BODY_OPTION", "WEBD_POLICY_SET_REDIRECT_OPTION",
        "WEBD_POLICY_SET_NAT_OPTION", "WEBD_POLICY_SET_ROUTE_OPTION",
        "WEBD_POLICY_SET_SQM_OPTION", "WEBD_DB_BUSY_TIMEOUT_MS",
    ):
        assert len(re.findall(rf"(?m)^#define {name}\b", all_source)) == 1, name
    for name in ("api_policy_read.c", "api_policy_objects.c"):
        text = webd_module_text(name)
        assert '#include "api_policy_paths.h"' in text
        assert '#include "api_policy_write_internal.h"' in text


def test_compiled_predicate_preserves_legacy_edge_cases():
    text = webd_module_text("api_policy_write.c")
    match = re.search(r"(?ms)^static int policy_write_path\(.*?^}\n", text)
    assert match
    fixture = r'''
#include <stdio.h>
#include <string.h>
PREDICATE
static int legacy(const char *path)
{
    return !strcmp(path, "/api/v1/policy-engine/policy-table") ||
           !strcmp(path, "/api/v1/policy-engine/policy-table/preview") ||
           !strncmp(path, "/api/v1/policy-engine/policy-table/", 35);
}
int main(void)
{
    const char *paths[] = {
        "", "/api/v1/policy-engine/policy-table",
        "/api/v1/policy-engine/policy-table/",
        "/api/v1/policy-engine/policy-table/preview",
        "/api/v1/policy-engine/policy-table/a",
        "/api/v1/policy-engine/policy-table/ab",
        "/api/v1/policy-engine/policy-table/ab/c",
        "/api/v1/policy-engine/policy-table//",
        "/api/v1/policy-engine/policy-tablex",
        "/api/v1/policy-engine/catalog",
        "/api/v1/policy-engine/objects",
        "/api/v1/routing/snapshot",
    };
    for (unsigned i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
        if (policy_write_path(paths[i]) != legacy(paths[i])) {
            fprintf(stderr, "predicate differs: %s\n", paths[i]);
            return 1;
        }
    }
    return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix="policy-write-predicate-") as raw:
        source = Path(raw) / "fixture.c"
        binary = Path(raw) / "fixture"
        source.write_text(fixture.replace("PREDICATE", match[0]))
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(source), "-o", str(binary)], check=True, capture_output=True)
        subprocess.run([str(binary)], check=True, capture_output=True)


if __name__ == "__main__":
    test_single_definitions_and_paths()
    test_compiled_predicate_preserves_legacy_edge_cases()
    print("ok: 117 unique policy functions, shared macros, legacy path semantics")

#!/usr/bin/env python3
"""Execute the five Phase 3B production Topology handlers with controlled producers."""

from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import apd_test_deps  # noqa: E402

SRC = ROOT / "src"
API = SRC / "webd" / "api"
FIXTURE = ROOT / "tests" / "api_topology_routes_fixture.c"
HEADER_FLAGS, JSON_LIBS = apd_test_deps.split_package_flags("json-c")


def test_production_topology_handlers_preserve_route_behavior() -> None:
    with tempfile.TemporaryDirectory(prefix="api-topology-routes-") as raw:
        binary = Path(raw) / "api-topology-routes-fixture"
        command = [
            "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
            f"-I{SRC}", f"-I{SRC / 'webd'}", f"-I{API}",
            *HEADER_FLAGS,
            str(API / "api_topology.c"),
            str(API / "api_request.c"),
            str(FIXTURE),
            *JSON_LIBS,
            "-o", str(binary),
        ]
        built = subprocess.run(command, capture_output=True, text=True)
        assert built.returncode == 0, built.stdout + built.stderr
        result = subprocess.run([str(binary)], capture_output=True, text=True,
                                timeout=60)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "ok: five production Topology handlers and predicates" in result.stdout


def test_fixture_catches_a_broken_unifi_predicate() -> None:
    source = (API / "api_topology.c").read_text(encoding="utf-8")
    needle = "return suffix && suffix != site && strcmp(suffix, \"/topology\") == 0;"
    assert source.count(needle) == 1
    with tempfile.TemporaryDirectory(prefix="api-topology-predicate-mutation-") as raw:
        work = Path(raw)
        mutated = work / "api_topology.c"
        mutated.write_text(source.replace(needle, "return 0;", 1),
                           encoding="utf-8")
        binary = work / "api-topology-routes-fixture"
        command = [
            "cc", "-std=c11", "-Wall", "-Wextra",
            f"-I{SRC}", f"-I{SRC / 'webd'}", f"-I{API}",
            *HEADER_FLAGS,
            str(mutated), str(API / "api_request.c"), str(FIXTURE),
            *JSON_LIBS, "-o", str(binary),
        ]
        built = subprocess.run(command, capture_output=True, text=True)
        assert built.returncode == 0, built.stdout + built.stderr
        result = subprocess.run([str(binary)], capture_output=True, text=True,
                                timeout=60)
        assert result.returncode != 0, (
            "a disabled UniFi topology predicate left the production fixture green")


if __name__ == "__main__":
    test_production_topology_handlers_preserve_route_behavior()
    test_fixture_catches_a_broken_unifi_predicate()
    print("ok: Phase 3B production Topology route handlers executed")

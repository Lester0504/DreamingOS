#!/usr/bin/env python3
"""U-15: capture budgets must stay under the shared primitive ceiling.

aegisxd requested a 2 MiB nft capture budget while jmx_exec_capture() rejects
anything above 1 MiB in jmx_exec_valid(), before the fork. The call therefore
returned -1 on every poll and the nft counter path could never capture, which a
token-matching test would not have noticed: the shell was gone, so the U-15
migration looked complete while the feature was dead. This contract pins the
ceiling as a single exported definition, checks every caller budget against it,
and runs the primitive to prove the boundary behaviour.
"""
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
EXEC_HEADER = SRC / "jmx_exec.h"
EXEC_SOURCE = SRC / "jmx_exec.c"

CEILING = 1024 * 1024


def _int_of(expr: str) -> int:
    """Evaluate a simple C integer constant expression like (256U * 1024U)."""
    cleaned = re.sub(r"\b(\d+)[Uu][Ll]*", r"\1", expr)
    cleaned = cleaned.replace("*", "*").strip()
    if not re.fullmatch(r"[0-9()*+ ]+", cleaned):
        raise AssertionError("unexpected budget expression: %r" % expr)
    return int(eval(cleaned))  # noqa: S307 - constrained to digits and * + ( )


def test_ceiling_is_exported_once() -> None:
    header = EXEC_HEADER.read_text(encoding="utf-8")
    source = EXEC_SOURCE.read_text(encoding="utf-8")
    match = re.search(
        r"#define\s+JMX_EXEC_OUTPUT_LIMIT_MAX\s+(\(.*?\))\s*$",
        header, re.MULTILINE)
    assert match, "jmx_exec.h must export JMX_EXEC_OUTPUT_LIMIT_MAX"
    assert _int_of(match.group(1)) == CEILING, match.group(1)
    # The implementation must not carry a second, independent literal.
    assert "#define JMX_EXEC_MAX_OUTPUT JMX_EXEC_OUTPUT_LIMIT_MAX" in source, \
        "jmx_exec.c must derive its cap from the exported ceiling"
    assert "output_limit > JMX_EXEC_MAX_OUTPUT" in source


def test_every_caller_budget_is_within_the_ceiling() -> None:
    pattern = re.compile(
        r"#define\s+([A-Z_]*(?:OUTPUT_MAX|CAPTURE_BUDGET)[A-Z_]*)\s+"
        r"(\([0-9Uu()*+ ]+\))\s*$", re.MULTILINE)
    checked = {}
    for path in sorted(SRC.rglob("*.c")) + sorted(SRC.rglob("*.h")):
        text = path.read_text(encoding="utf-8", errors="strict")
        if "jmx_exec" not in text:
            continue
        for name, expr in pattern.findall(text):
            value = _int_of(expr)
            checked["%s:%s" % (path.relative_to(SRC), name)] = value
            assert value <= CEILING, (
                "%s in %s is %d bytes, above the %d byte jmx_exec ceiling; "
                "jmx_exec_capture() would reject it on every call"
                % (name, path.relative_to(SRC), value, CEILING))
    assert len(checked) >= 5, "expected to find several capture budgets: %r" % checked
    aegis = [v for k, v in checked.items() if "aegisxd_hits" in k and "NFT" in k]
    assert aegis and aegis[0] <= CEILING, checked


def test_aegisxd_budgets_are_guarded_at_compile_time() -> None:
    hits = (SRC / "aegisxd/aegisxd_hits.c").read_text(encoding="utf-8")
    assert '#include "jmx_exec.h"' in hits
    for budget in ("AEGISXD_EXEC_IP_OUTPUT_MAX", "AEGISXD_EXEC_NFT_OUTPUT_MAX"):
        assert re.search(
            r"_Static_assert\(\s*%s\s*<=\s*JMX_EXEC_OUTPUT_LIMIT_MAX" % budget,
            hits), "%s needs a _Static_assert against the ceiling" % budget


def test_primitive_enforces_the_boundary_at_runtime() -> None:
    cc = os.environ.get("CC") or shutil.which("cc") or shutil.which("gcc")
    assert cc, "no C compiler available"
    fixture = r'''
#include "jmx_exec.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    char *argv[] = { "/bin/echo", "budget", NULL };
    struct jmx_exec_result r;
    int rc;

    /* One byte above the ceiling must be refused before any fork. */
    rc = jmx_exec_capture(argv[0], argv, JMX_EXEC_OUTPUT_LIMIT_MAX + 1, 2000, &r);
    if (rc == 0) { printf("FAIL: over-ceiling budget accepted\n"); return 1; }

    /* Exactly at the ceiling must be accepted. */
    memset(&r, 0, sizeof(r));
    rc = jmx_exec_capture(argv[0], argv, JMX_EXEC_OUTPUT_LIMIT_MAX, 2000, &r);
    if (rc != 0) { printf("FAIL: at-ceiling budget refused\n"); return 1; }
    if (r.exit_code != 0 || !r.output || !strstr(r.output, "budget")) {
        printf("FAIL: at-ceiling capture produced no output\n"); return 1;
    }
    jmx_exec_result_free(&r);

    /* A small budget still captures, and flags truncation rather than lying. */
    memset(&r, 0, sizeof(r));
    rc = jmx_exec_capture(argv[0], argv, 3, 2000, &r);
    if (rc != 0) { printf("FAIL: small budget refused\n"); return 1; }
    if (r.output_len != 3 || !r.truncated) {
        printf("FAIL: expected truncated 3-byte capture, got len=%zu trunc=%d\n",
               r.output_len, r.truncated);
        return 1;
    }
    jmx_exec_result_free(&r);

    printf("ok\n");
    return 0;
}
'''
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        (tmpdir / "fixture.c").write_text(fixture, encoding="utf-8")
        binary = tmpdir / "fixture"
        build = subprocess.run(
            [cc, "-std=gnu11", "-I", str(SRC), "-o", str(binary),
             str(tmpdir / "fixture.c"), str(EXEC_SOURCE)],
            capture_output=True, text=True)
        assert build.returncode == 0, build.stderr
        run = subprocess.run([str(binary)], capture_output=True, text=True,
                             timeout=60)
        assert run.returncode == 0, run.stdout + run.stderr
        assert "ok" in run.stdout, run.stdout


if __name__ == "__main__":
    test_ceiling_is_exported_once()
    test_every_caller_budget_is_within_the_ceiling()
    test_aegisxd_budgets_are_guarded_at_compile_time()
    test_primitive_enforces_the_boundary_at_runtime()
    print("ok: U-15 capture budgets stay within the shared primitive ceiling")

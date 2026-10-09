#!/usr/bin/env python3
"""§12 item 4: contract for the PURE post-apply link-readback verdict.

nc_port_link_readback_verify() lives in netconfig/007_nc_global_ports.c and is
side-effect free.  This test slices the helper out of the ACTUAL source (so it
cannot drift from a copy), pastes it into a tiny harness, compiles it under the
same -Werror the firmware uses, and exercises the five required cases plus a
duplex mismatch.

The invariants under test are the honesty rules:
  * an auto/unset config that actually brings the link up is verified=true,
  * an auto/unset config on a dark port is verified=false (NOT a fake success),
  * an explicit speed/duplex that does not match the negotiated link is
    verified=false with a precise reason,
  * an unreadable link is verified=indeterminate(-1), never a fake healthy 0,
  * the verdict is evidence only and never invents a value it did not observe.
"""
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "netconfig" / "007_nc_global_ports.c"

START = "static int nc_port_link_readback_verify("
END = "struct json_object *jmx_netconfig_physical_port_config_apply("


def extract_helper(source: str) -> str:
    start = source.index(START)
    end = source.index(END, start)
    helper = source[start:end].strip()
    assert helper.endswith("}"), "helper slice did not end at a closing brace"
    return helper


HARNESS_TMPL = """\
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>

%(helper)s

static int fails;

static void expect(const char *name, int got, int want,
                   const char *reason, const char *reason_prefix)
{
    if (got != want) {
        fprintf(stderr, "FAIL %%s: verdict got=%%d want=%%d reason=%%s\\n",
                name, got, want, reason);
        fails++;
        return;
    }
    if (reason_prefix && strncmp(reason, reason_prefix, strlen(reason_prefix)) != 0) {
        fprintf(stderr, "FAIL %%s: reason=%%s want-prefix=%%s\\n",
                name, reason, reason_prefix);
        fails++;
        return;
    }
    printf("ok %%s: verdict=%%d reason=%%s\\n", name, got, reason);
}

int main(void)
{
    char r[96];

    /* (a) auto/unset + link up -> verified, real negotiated speed observed. */
    expect("auto_link_up",
           nc_port_link_readback_verify(0, "", -1, 1000, "full", 1, 1, r, sizeof(r)),
           1, r, "auto_negotiated_link_up");

    /* (b) auto/unset + link down -> NOT verified. A no-op success is not a
     *     verified link; this is the anti-fake-success case. */
    expect("auto_link_down",
           nc_port_link_readback_verify(0, "", -1, 0, "unknown", -1, 0, r, sizeof(r)),
           0, r, "auto_but_link_down");

    /* (c) explicit 1000/full requested, link up at 100 -> speed mismatch. */
    expect("explicit_speed_mismatch",
           nc_port_link_readback_verify(1000, "full", 0, 100, "full", 0, 1, r, sizeof(r)),
           0, r, "speed_mismatch_intended_1000_observed_100");

    /* explicit duplex mismatch -> NOT verified with a precise reason. */
    expect("explicit_duplex_mismatch",
           nc_port_link_readback_verify(1000, "full", 0, 1000, "half", 0, 1, r, sizeof(r)),
           0, r, "duplex_mismatch_intended_full_observed_half");

    /* (d) explicit match -> verified. */
    expect("explicit_match",
           nc_port_link_readback_verify(1000, "full", 0, 1000, "full", 0, 1, r, sizeof(r)),
           1, r, "explicit_link_matches_intended");

    /* (e) unreadable link -> indeterminate, never a fake healthy/failed 0. */
    expect("unreadable",
           nc_port_link_readback_verify(1000, "full", 0, 0, "unknown", -1, -1, r, sizeof(r)),
           -1, r, "link_state_unreadable");

    /* extra: link up but negotiated speed unreadable in the auto case is also
     *        indeterminate, not a fabricated verified. */
    expect("auto_link_up_speed_unreadable",
           nc_port_link_readback_verify(0, "", -1, 0, "unknown", -1, 1, r, sizeof(r)),
           -1, r, "auto_link_up_speed_unreadable");

    /* extra: explicit intent but link down -> NOT verified. */
    expect("explicit_link_down",
           nc_port_link_readback_verify(1000, "full", 0, 0, "unknown", -1, 0, r, sizeof(r)),
           0, r, "link_down_after_apply");

    if (fails) {
        fprintf(stderr, "port link readback contract: %%d FAILED\\n", fails);
        return 1;
    }
    puts("port link readback verify contract: PASS");
    return 0;
}
"""


def main() -> None:
    helper = extract_helper(SRC.read_text(encoding="utf-8"))
    harness = HARNESS_TMPL % {"helper": helper}
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        src = root / "harness.c"
        binary = root / "harness"
        src.write_text(harness, encoding="utf-8")
        subprocess.run([
            os.environ.get("CC", "cc"),
            "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-Werror=implicit-function-declaration",
            str(src), "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True, timeout=10)


if __name__ == "__main__":
    main()

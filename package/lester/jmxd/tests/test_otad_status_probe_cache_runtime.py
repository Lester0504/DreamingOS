#!/usr/bin/env python3
"""Run the production OTAD probe-age policy against an advanced clock."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
FIRMWARE = (ROOT / "src/otad/otad_firmware.c").read_text(encoding="utf-8")


def extract_block(start_marker: str) -> str:
    start = FIRMWARE.index(start_marker)
    brace = FIRMWARE.index("{", start)
    depth = 0
    for offset in range(brace, len(FIRMWARE)):
        char = FIRMWARE[offset]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return FIRMWARE[start : offset + 1]
    raise AssertionError(f"unterminated production block: {start_marker}")


ENUM = extract_block("enum otad_status_probe_state") + ";"
POLICY = extract_block("static int otad_status_probe_cache_expired(")

HARNESS = f"""
#include <assert.h>
#include <stdint.h>

#define OTAD_STATUS_PROBE_FAILURE_TTL_MS 30000

{ENUM}

{POLICY}

int main(void)
{{
    int64_t probed_ms = 1000;
    int64_t now_ms = probed_ms + 300001;

    assert(!otad_status_probe_cache_expired(
        OTAD_STATUS_PROBE_VERIFIED, now_ms - probed_ms));
    now_ms = probed_ms + 30 * 60 * 1000;
    assert(!otad_status_probe_cache_expired(
        OTAD_STATUS_PROBE_VERIFIED, now_ms - probed_ms));

    now_ms = probed_ms + OTAD_STATUS_PROBE_FAILURE_TTL_MS;
    assert(!otad_status_probe_cache_expired(
        OTAD_STATUS_PROBE_STALE, now_ms - probed_ms));
    now_ms++;
    assert(otad_status_probe_cache_expired(
        OTAD_STATUS_PROBE_STALE, now_ms - probed_ms));
    assert(otad_status_probe_cache_expired(
        OTAD_STATUS_PROBE_UNAVAILABLE, now_ms - probed_ms));
    return 0;
}}
"""


def test_verified_evidence_is_event_driven_but_failures_retry() -> None:
    compiler = shutil.which(os.environ.get("CC", "cc"))
    assert compiler, "C compiler not found"
    with tempfile.TemporaryDirectory(prefix="otad-status-cache-") as directory:
        source = Path(directory) / "fixture.c"
        binary = Path(directory) / "fixture"
        source.write_text(HARNESS, encoding="utf-8")
        subprocess.run(
            [
                compiler,
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(source),
                "-o",
                str(binary),
            ],
            check=True,
        )
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    test_verified_evidence_is_event_driven_but_failures_retry()
    print("otad_status_probe_cache_runtime: PASS")

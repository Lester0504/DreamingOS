#!/usr/bin/env python3
"""Compile and run APD's production passive iw survey collector."""

from __future__ import annotations

from pathlib import Path
import glob
import os
import shutil
import subprocess
import tempfile

import apd_test_deps


ROOT = Path(__file__).resolve().parents[1]


def assert_production_contract() -> None:
    source = (ROOT / "src/apd/apd_backend_openwrt.c").read_text(encoding="utf-8")
    # Bound the survey collector region at the start of the neighbor-scan
    # block.  Anchor on its first declaration rather than on the json-c
    # include guard above it, which is shared with the survey fixture.
    survey_source = source[
        source.index("static int apd_survey_collect_raw"):
        source.index("#define APD_NEIGHBOR_REASON_LEN")
    ]
    required = (
        '"dev", (char *)interface, "survey", "dump", NULL',
        'strcmp(json_object_get_string(type), "AP") != 0',
        'json_object_object_add(radio, "survey", survey)',
        'json_object_new_string("iw_survey")',
        '"sample_time"',
        '"complete"',
        '"stale"',
        '"reason"',
        '"channel_active_time_ms"',
        '"channel_busy_time_ms"',
        '"channel_receive_time_ms"',
        '"channel_transmit_time_ms"',
        '"utilization_pct"',
        'sample->active_time_ms == 0',
        'sample->busy_time_ms > sample->active_time_ms',
        'present ? json_object_new_int64((int64_t)value)',
        'json_object_new_null()',
    )
    for token in required:
        assert token in source, f"missing APD survey contract token: {token}"
    for forbidden in (
        '"scan"',
        'spectral_supported',
        'fft_supported',
        'system(',
        'popen(',
        '/bin/sh',
        '/bin/ash',
    ):
        assert forbidden not in survey_source, f"survey collector opened forbidden path: {forbidden}"

def resolve_json_prefix() -> tuple[Path, bool]:
    """Locate json-c the same way the neighbor-scan fixture does.

    APD_TEST_PREFIX selects a shared-library prefix (used on the build
    host); otherwise fall back to a local static Homebrew build.
    """
    # Delegated to the shared resolver: the old body only honoured
    # APD_TEST_PREFIX and otherwise went straight to Homebrew, so on 31.6 this
    # fixture tried to link a macOS static archive and failed with "plugin
    # needed to handle lto object".
    return apd_test_deps.resolve_json_prefix()


def main() -> None:
    assert_production_contract()
    compiler = shutil.which("clang")
    assert compiler, "clang is required for the local APD survey validation"
    json_prefix, shared = resolve_json_prefix()
    with tempfile.TemporaryDirectory(prefix="apd-survey-") as raw:
        binary = Path(raw) / "apd-survey-fixture"
        subprocess.run(
            [
                compiler,
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                # The channel-catalog block shares this translation unit but
                # is exercised by the neighbor-scan fixture, not this one.
                "-Wno-unused-function",
                "-D_POSIX_C_SOURCE=200809L",
                f"-I{ROOT / 'src'}",
                f"-I{json_prefix / 'include'}",
                str(ROOT / "tests/apd_survey_runtime_fixture.c"),
                str(ROOT / "src/apd/apd_readonly_command.c"),
                *([f"-L{json_prefix / 'lib'}",
                   f"-Wl,-rpath,{json_prefix / 'lib'}", "-ljson-c"]
                  if shared else
                  [str(json_prefix / "lib/libjson-c.a")]),
                "-o",
                str(binary),
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        env = os.environ.copy()
        if shared:
            env["LD_LIBRARY_PATH"] = str(json_prefix / "lib") + (
                f":{env['LD_LIBRARY_PATH']}" if env.get("LD_LIBRARY_PATH") else "")
        result = subprocess.run(
            [str(binary)],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
        assert result.stdout.strip() == (
            "ok: APD passive iw survey parser and bounded argv collection"
        )
    print("ok: APD survey fixture compiled with clang -Werror and passed")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Compile and run APD's production passive iw survey collector."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def assert_production_contract() -> None:
    source = (ROOT / "src/apd/apd_backend_openwrt.c").read_text(encoding="utf-8")
    survey_source = source[
        source.index("static int apd_survey_collect_raw"):
        source.index("#ifdef APD_NEIGHBOR_SCAN_STANDALONE_TEST")
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


def main() -> None:
    assert_production_contract()
    compiler = shutil.which("clang")
    assert compiler, "clang is required for the local APD survey validation"
    with tempfile.TemporaryDirectory(prefix="apd-survey-") as raw:
        binary = Path(raw) / "apd-survey-fixture"
        subprocess.run(
            [
                compiler,
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-D_POSIX_C_SOURCE=200809L",
                f"-I{ROOT / 'src'}",
                str(ROOT / "tests/apd_survey_runtime_fixture.c"),
                str(ROOT / "src/apd/apd_readonly_command.c"),
                "-o",
                str(binary),
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        result = subprocess.run(
            [str(binary)],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.stdout.strip() == (
            "ok: APD passive iw survey parser and bounded argv collection"
        )
    print("ok: APD survey fixture compiled with clang -Werror and passed")


if __name__ == "__main__":
    main()

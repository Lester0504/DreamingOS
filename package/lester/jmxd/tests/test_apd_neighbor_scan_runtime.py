#!/usr/bin/env python3
"""Compile and execute the APD OpenWrt neighbor scan backend contract."""

from __future__ import annotations

from pathlib import Path
import glob
import os
import shutil
import subprocess
import tempfile

import apd_test_deps


ROOT = Path(__file__).resolve().parents[1]


def production_contract() -> None:
    backend = (ROOT / "src/apd/apd_backend_openwrt.c").read_text(encoding="utf-8")
    command = (ROOT / "src/apd/apd_readonly_command.c").read_text(encoding="utf-8")
    header = (ROOT / "src/apd/apd_readonly_command.h").read_text(encoding="utf-8")
    required = (
        "#define APD_NEIGHBOR_SCAN_TIMEOUT_MS 30000",
        "#define APD_NEIGHBOR_SCAN_OUTPUT_LIMIT (1024U * 1024U)",
        "#define APD_NEIGHBOR_SCAN_ITEM_LIMIT 128U",
        "#define APD_NEIGHBOR_SCAN_FRAME_LIMIT (24U * 1024U)",
        '"scan",',
        '"ap-force", "flush", "passive", NULL',
        '"items", json_object_new_array()',
        '"complete"',
        '"truncated"',
        '"error_code"',
        '"radio_not_scannable"',
        '"locally_administered_bssid"',
        # Diagnosable neighbor-scan failure split: "unsupported" may only
        # be claimed on EOPNOTSUPP/ENOTSUP evidence; unproven failures keep
        # the exit status instead of guessing.
        "static int apd_neighbor_scan_stderr_errno",
        "static const char *apd_neighbor_scan_failure_reason",
        '"iw_neighbor_scan_not_supported"',
        '"iw_neighbor_scan_interface_busy"',
        '"iw_neighbor_scan_interface_down"',
        '"iw_neighbor_scan_permission_denied"',
        '"iw_neighbor_scan_driver_rejected"',
        '"iw_neighbor_scan_interface_missing"',
        'iw_neighbor_scan_command_failed_exit_%d',
        "apd_neighbor_attach_failure_evidence",
        "apd_neighbor_scan_log_failure",
        ".neighbor_scan = apd_backend_neighbor_scan",
        "static int apd_survey_scan_collect",
        '"survey", "dump", NULL',
        "apd_backend_survey_scan",
        "name_len = strlen(entry->d_name)",
        "memcpy(out, entry->d_name, name_len + 1)",
        'static const char hex[] = "0123456789abcdef"',
        "out[17] = '\\0'",
    )
    for token in required:
        assert token in backend, f"missing neighbor scan contract: {token}"
    assert "apd_readonly_command_bounded" in command
    assert "output_limited" in command and "output_limited" in header
    scan_start = backend.index("static int apd_neighbor_scan_collect")
    scan_end = backend.index("#endif", scan_start)
    scan = backend[scan_start:scan_end]
    for forbidden in ("system(", "popen(", '"/bin/sh"', '"/bin/ash"'):
        assert forbidden not in scan, f"neighbor scan opened shell path: {forbidden}"


def make_file(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="ascii")


def main() -> None:
    production_contract()
    compiler = os.environ.get("CC") or shutil.which("clang") or shutil.which("cc")
    assert compiler, "C compiler is required"
    # json_shared decides how we link. Keying that off APD_TEST_PREFIX instead
    # meant an unset variable forced the static path, which on the build host
    # resolved to the staging_dir LTO archive and failed to link.
    json_prefix, json_shared = apd_test_deps.resolve_json_prefix()
    with tempfile.TemporaryDirectory(prefix="apd-neighbor-") as raw:
        temp = Path(raw)
        ieee = temp / "ieee80211"
        net = temp / "net"
        make_file(ieee / "mld-phy0/index", "0\n")
        make_file(ieee / "phy1/index", "1\n")
        for name, index, state in (
            ("MLD1", 0, "up"),
            ("wifi0", 1, "unknown"),
            ("ath0", 1, "up"),
        ):
            make_file(net / f"{name}/phy80211/index", f"{index}\n")
            make_file(net / f"{name}/operstate", f"{state}\n")
        binary = temp / "fixture"
        compiled = subprocess.run(
            [
                compiler,
                "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-Wno-unused-function",
                "-D_POSIX_C_SOURCE=200809L",
                f'-DAPD_IEEE80211_PATH="{ieee}"',
                f'-DAPD_NET_CLASS_PATH="{net}"',
                f"-I{ROOT / 'src'}",
                f"-I{json_prefix / 'include'}",
                str(ROOT / "tests/apd_neighbor_scan_runtime_fixture.c"),
                str(ROOT / "src/apd/apd_readonly_command.c"),
                *([f"-L{json_prefix / 'lib'}",
                   f"-Wl,-rpath,{json_prefix / 'lib'}", "-ljson-c"]
                  if json_shared else
                  [str(json_prefix / "lib/libjson-c.a")]),
                "-o", str(binary),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stderr)
        env = os.environ.copy()
        if json_shared:
            env["LD_LIBRARY_PATH"] = str(json_prefix / "lib") + (
                f":{env['LD_LIBRARY_PATH']}" if env.get("LD_LIBRARY_PATH") else "")
        result = subprocess.run(
            [str(binary)], cwd=ROOT, check=False, capture_output=True,
            text=True, timeout=15, env=env,
        )
        if result.returncode:
            raise AssertionError(
                f"fixture rc={result.returncode}\nstdout={result.stdout}\n"
                f"stderr={result.stderr}"
            )
        assert result.stdout.strip() == (
            "ok: APD neighbor scan fixed argv, strict mapping/parser, and honest limits"
        )
    print("ok: APD neighbor scan backend runtime and production bounds passed")


if __name__ == "__main__":
    main()

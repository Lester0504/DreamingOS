#!/usr/bin/env python3
"""Execute APD's bounded argv-only collector, including inherited SIGCHLD ignore."""

from pathlib import Path
import os
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="apd-command-") as raw:
        binary = Path(raw) / "fixture"
        subprocess.run([
            "cc", "-std=c11", "-Wall", "-Wextra", "-D_POSIX_C_SOURCE=200809L",
            "-DAPD_READONLY_COMMAND_TIMEOUT_MS=150", "-DAPD_COMMAND_LIMIT=4096",
            f"-I{ROOT / 'src'}",
            str(ROOT / "tests/apd_readonly_command_fixture.c"),
            str(ROOT / "src/apd/apd_readonly_command.c"),
            "-o", str(binary),
        ], check=True, capture_output=True, text=True)
        expected = {
            "success": ("rc=0", "exit=0", "timeout=0", "output_limited=0", "text=fixture-ok"),
            "failure": ("rc=-1", "exit=3", "timeout=0", "output_limited=0"),
            "timeout": ("rc=-1", "timeout=1", "output_limited=0"),
            "large": ("rc=-1", "timeout=0", "output_limited=1"),
            "ignored": ("rc=-1", "exit=-1", "timeout=0", "output_limited=0"),
        }
        for scenario, tokens in expected.items():
            result = subprocess.run([str(binary), scenario], check=True,
                                    capture_output=True, text=True, timeout=2)
            for token in tokens:
                assert token in result.stdout, (scenario, token, result.stdout)
        policy_env = {**os.environ, "DREAMINGWRT_APD_VENDOR_QUERIES": "0"}
        for name in ("wlanconfig", "apstats", "wifitool", "iwpriv"):
            alias = Path(raw) / name
            alias.symlink_to(binary)
            result = subprocess.run([str(alias), "success"], check=True,
                                    capture_output=True, text=True, timeout=2,
                                    env=policy_env)
            assert "rc=-1 exit=126" in result.stdout, result.stdout
            assert "vendor_queries_disabled_by_policy" in result.stdout
            assert "fixture-ok" not in result.stdout
        alias = Path(raw) / "iw"
        alias.symlink_to(binary)
        result = subprocess.run([str(alias), "success"], check=True,
                                capture_output=True, text=True, timeout=2,
                                env=policy_env)
        assert "rc=0 exit=0" in result.stdout and "fixture-ok" in result.stdout
    print("ok: APD bounded commands and vendor-query quarantine")


if __name__ == "__main__":
    main()

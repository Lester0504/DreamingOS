#!/usr/bin/env python3
"""Runtime contract for persisted managed-AP traffic history."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/ac/ac_db.c"
FIXTURE = ROOT / "tests/ac_ap_traffic_history_runtime_fixture.c"
JSON_PREFIX = Path(os.environ.get("AC_SURVEY_TEST_PREFIX", "/opt/homebrew/opt/json-c"))
OPENSSL_PREFIX = Path(os.environ.get(
    "AC_SURVEY_TEST_OPENSSL_PREFIX", "/opt/homebrew/opt/openssl@3"))


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="ac-ap-traffic-") as raw:
        directory = Path(raw)
        binary = directory / "fixture"
        database = directory / "config.db"
        static_lib = JSON_PREFIX / "lib/libjson-c.a"
        json_link = ([str(static_lib)] if static_lib.is_file() else [
            f"-L{JSON_PREFIX / 'lib'}", f"-Wl,-rpath,{JSON_PREFIX / 'lib'}",
            "-ljson-c",
        ])
        command = [
            os.environ.get("CC", "cc"), "-std=c11",
            "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
            "-DAC_DB_TEST_STANDALONE", "-DAC_DB_TELEMETRY_TEST_STANDALONE",
            "-Wall", "-Wextra", "-Werror", f"-I{JSON_PREFIX / 'include'}",
            f"-I{OPENSSL_PREFIX / 'include'}", str(FIXTURE), str(SOURCE),
            *json_link, f"-L{OPENSSL_PREFIX / 'lib'}", "-lcrypto", "-lsqlite3",
            "-lm", "-o", str(binary),
        ]
        subprocess.run(command, check=True, capture_output=True, text=True)
        env = os.environ.copy()
        env["DREAMINGWRT_AC_DB_PATH"] = str(database)
        result = subprocess.run([str(binary)], env=env, check=False,
                                capture_output=True, text=True)
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert "all_up=150 all_down=300" in result.stdout
        assert "single_up=100 single_down=200" in result.stdout
        assert "resets=2 roam_spike=0 reconnect_spike=0" in result.stdout
        assert "ranges=1h,1d,1w,1m schema=stable" in result.stdout
    print("ok: persisted AP traffic deltas, online-all/offline-single aggregation, "
          "reset/roam/reconnect suppression and 1H/1D/1W/1M schema")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""SQLite persistence and idempotence contract for AC remote telemetry."""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
DB_SOURCE = ROOT / "src/ac/ac_db.c"
FIXTURE = ROOT / "tests/ac_telemetry_runtime_fixture.c"
# AC_SURVEY_TEST_PREFIX layout (include/json-c + lib) overrides the macOS
# Homebrew defaults so the same driver runs against a Linux sysroot.
_ENV_PREFIX = os.environ.get("AC_SURVEY_TEST_PREFIX", "")
JSON_PREFIX = Path(_ENV_PREFIX) if _ENV_PREFIX else Path(
    "/opt/homebrew/var/homebrew/tmp/.cellar/json-c/0.19")
_ENV_OPENSSL = os.environ.get("AC_SURVEY_TEST_OPENSSL_PREFIX", "")
OPENSSL_PREFIX = Path(_ENV_OPENSSL) if _ENV_OPENSSL else (
    JSON_PREFIX if _ENV_PREFIX else Path("/opt/homebrew/opt/openssl@3"))


def compile_fixture(output: Path) -> None:
    json_static = JSON_PREFIX / "lib/libjson-c.a"
    json_link = ([str(json_static)] if json_static.is_file() else
                 [f"-L{JSON_PREFIX / 'lib'}",
                  f"-Wl,-rpath,{JSON_PREFIX / 'lib'}", "-ljson-c"])
    command = [
        os.environ.get("CC", "cc"), "-std=c11",
        "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
        "-DAC_DB_TEST_STANDALONE", "-DAC_DB_TELEMETRY_TEST_STANDALONE",
        "-Wall", "-Wextra", "-Werror",
        f"-I{JSON_PREFIX / 'include'}", f"-I{OPENSSL_PREFIX / 'include'}",
        str(FIXTURE), str(DB_SOURCE), *json_link,
        f"-L{OPENSSL_PREFIX / 'lib'}", "-lcrypto", "-lsqlite3", "-lm",
        "-o", str(output),
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)


def main() -> None:
    source = DB_SOURCE.read_text(encoding="utf-8")
    assert "previous_observed_at == observed_at" in source
    assert "previous_sequence == sequence" in source
    assert "strcmp(previous_snapshot_id, snapshot_id) == 0" in source
    assert "AC_TELEMETRY_STALE_TIMEOUT_SECONDS 360" in source
    assert "runtime_received < observed_at - AC_TELEMETRY_STALE_TIMEOUT_SECONDS" in source
    with tempfile.TemporaryDirectory(prefix="ac-telemetry-") as raw:
        root = Path(raw)
        binary = root / "fixture"
        database = root / "config.db"
        compile_fixture(binary)
        env = os.environ.copy()
        env["DREAMINGWRT_AC_DB_PATH"] = str(database)
        result = subprocess.run(
            [str(binary)], env=env, check=False, capture_output=True, text=True)
        assert result.returncode == 0, (result.stdout, result.stderr)
        fields = dict(re.findall(r"([a-z_]+)=([^\s]+)", result.stdout))
        assert int(fields["first_writes"]) > 0
        assert fields["duplicate_writes"] == "0"
        assert int(fields["changed_writes"]) > 0
        assert fields["epoch_handoff"] == "ok"
        assert fields["old_epoch_rejected"] == "ok"
        assert fields["old_disconnect"] == "ok"
        assert fields["radio"] == fields["ssid"] == fields["station"] == "1"
        assert fields["aps_list"] == "ok"
    print(
        "ok: AC telemetry SQLite persistence "
        f"first_writes={fields['first_writes']} "
        "duplicate_writes=0 "
        f"changed_writes={fields['changed_writes']} "
        "epoch_handoff=ok old_epoch_rejected=ok old_disconnect=ok "
        "radio=1 ssid=1 station=1 aps_list=ok"
    )


if __name__ == "__main__":
    main()

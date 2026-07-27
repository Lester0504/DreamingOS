#!/usr/bin/env python3
"""Phase W1 wifi transaction validate: evidence gating, bounds, schema v10."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/ac/ac_db.c"
UBUS = ROOT / "src/ac/ac_ubus.c"
INTERNAL = ROOT / "src/ac/ac_internal.h"
FIXTURE = ROOT / "tests/ac_wifi_validate_runtime_fixture.c"
_ENV_PREFIX = os.environ.get("AC_SURVEY_TEST_PREFIX", "")
JSON_PREFIX = Path(_ENV_PREFIX) if _ENV_PREFIX else Path(
    "/opt/homebrew/var/homebrew/tmp/.cellar/json-c/0.19")
_ENV_OPENSSL = os.environ.get("AC_SURVEY_TEST_OPENSSL_PREFIX", "")
OPENSSL_PREFIX = Path(_ENV_OPENSSL) if _ENV_OPENSSL else (
    JSON_PREFIX if _ENV_PREFIX else Path("/opt/homebrew/opt/openssl@3"))


def static_contract() -> None:
    db = SOURCE.read_text(encoding="utf-8")
    ubus = UBUS.read_text(encoding="utf-8")
    internal = INTERNAL.read_text(encoding="utf-8")
    for token in (
        "ac_db_wifi_transaction_validate_json",
        "AC_WIFI_VALIDATE_CHANGES_MAX 32768",
        '"revision_conflict"',
        '"secret_in_validate"',
        '"radio_evidence_missing"',
        '"radio_evidence_stale"',
        '"channel_catalog_incomplete"',
        '"width_evidence_missing"',
        'ac_add_column("ac_ssids", "secret_present"',
        'ac_add_column("ac_ssid_bindings", "updated_at"',
    ):
        assert token in db, f"missing validate contract: {token}"
    for token in (
        'UBUS_METHOD("wifi_transaction_validate"',
        "ac_wifi_validate_parse_policy",
        "ac_attr_get_s64(tb[AC_WIFI_VALIDATE_BASE_REVISION])",
    ):
        assert token in ubus, f"missing validate ubus contract: {token}"
    assert "#define AC_SCHEMA_VERSION 11" in internal, (
        "production schema version must match the migrated DB "
        "(2026-07-26 v9 lesson: the standalone test define is not enough)"
    )
    assert "#define AC_SCHEMA_VERSION 11" in db
    # W1 flips no write capability; the 2026-07-20 gates stay fail-closed.
    protocol = (ROOT / "src/ac/ac_protocol.c").read_text(encoding="utf-8")
    for gate in ('"ssid_create", 0', '"ssid_update", 0', '"ssid_delete", 0',
                 '"radio_update", 0', '"ap_actions", 0',
                 '"transactional_apply", 0'):
        assert gate in protocol, f"write gate no longer fail-closed: {gate}"


def compile_fixture(output: Path) -> None:
    static_lib = JSON_PREFIX / "lib/libjson-c.a"
    json_link = ([str(static_lib)] if static_lib.is_file() else
                 [f"-L{JSON_PREFIX / 'lib'}",
                  f"-Wl,-rpath,{JSON_PREFIX / 'lib'}", "-ljson-c"])
    command = [
        os.environ.get("CC", "cc"), "-std=c11",
        "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
        "-DAC_DB_TEST_STANDALONE", "-DAC_DB_TELEMETRY_TEST_STANDALONE",
        "-Wall", "-Wextra", "-Werror",
        f"-I{JSON_PREFIX / 'include'}", f"-I{OPENSSL_PREFIX / 'include'}",
        str(FIXTURE), str(SOURCE), *json_link,
        f"-L{OPENSSL_PREFIX / 'lib'}", "-lcrypto", "-lsqlite3", "-lm",
        "-o", str(output),
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)


def test_runtime() -> None:
    with tempfile.TemporaryDirectory(prefix="ac-wifi-validate-") as raw:
        temp = Path(raw)
        binary = temp / "fixture"
        compile_fixture(binary)
        env = os.environ.copy()
        env["DREAMINGWRT_AC_DB_PATH"] = str(temp / "config.db")
        completed = subprocess.run([str(binary)], env=env, check=True,
                                   capture_output=True, text=True)
        assert completed.stdout.strip() == "ok", completed.stdout


def main() -> None:
    static_contract()
    test_runtime()
    print("ok: W1 wifi transaction validate runtime and schema v10 contract")


if __name__ == "__main__":
    main()

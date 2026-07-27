#!/usr/bin/env python3
"""Validate and compile the AC Phase 1D management pairing ubus surface."""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/ac/ac_ubus.c"
PROTOCOL = ROOT / "src/ac/ac_protocol.c"
FIXTURE = ROOT / "tests/ac_pairing_ubus_fixture.c"
JSON_C = Path("/opt/homebrew/var/homebrew/tmp/.cellar/json-c/0.19")


def test_static_contract() -> None:
    source = SOURCE.read_text()
    protocol = PROTOCOL.read_text()
    methods = set(re.findall(r'UBUS_METHOD(?:_NOARG)?\(\s*"([^"]+)"', source))
    assert methods == {
        "status",
        "capabilities",
        "aps_list",
        "pairing_token_create",
        "pairing_token_list",
        "pairing_token_status",
        "pairing_token_revoke",
        "radio_job_create",
        "radio_job_status",
        "radio_job_cancel",
        "radio_job_result",
        "radio_job_list",
        "radio_job_latest_results",
        "survey_history",
        "station_events",
        "wifi_transaction_validate",
    }
    assert "pairing_token_redeem" not in source
    assert '"admin_pairing_ipc", 1' in protocol
    assert '"pairing_token_ipc", ac_transport_listening()' in protocol
    assert '"ap_adoption", ac_transport_listening()' in protocol
    assert '"heartbeat", ac_transport_listening()' in protocol
    assert '"node_transport", ac_transport_listening()' in protocol
    assert '"remote_telemetry", 1' in protocol
    assert '"ssid_create", 0' in protocol
    assert '"radio_update", 0' in protocol
    assert '"ap_actions", 0' in protocol
    for name, blob_type in {
        "ttl_seconds": "BLOBMSG_TYPE_INT32",
        "max_attempts": "BLOBMSG_TYPE_INT32",
        "site_id": "BLOBMSG_TYPE_STRING",
        "hardware_digest": "BLOBMSG_TYPE_STRING",
        "token_id": "BLOBMSG_TYPE_STRING",
    }.items():
        assert re.search(
            rf'\.name\s*=\s*"{name}"\s*,\s*\.type\s*=\s*{blob_type}',
            source,
        )
    assert "ac_message_is_strict" in source
    # Exact-type strictness with one documented exception: INT32-encoded
    # values are accepted for INT64 policy fields because JSON bridges
    # (webd REST, ubus CLI) always use the smallest integer width.
    assert "ac_policy_type_compatible((int)policy[i].type," in source
    assert "attr_type == BLOBMSG_TYPE_INT32" in source
    assert "return ac_reply_json(ctx, req, response);" in source
    assert "rc = ubus_send_reply(ctx, req, g_ac_blob.head);" in source
    assert "return rc;" in source


def dependency_prefix() -> Path:
    configured = os.environ.get("AC_UBUS_TEST_PREFIX")
    prefix = Path(configured) if configured else JSON_C
    assert (prefix / "include/json-c/json.h").is_file(), (
        f"json-c headers missing under {prefix}"
    )
    return prefix


def test_compiled_fixture() -> None:
    prefix = dependency_prefix()
    with tempfile.TemporaryDirectory(prefix="ac-pairing-ubus-") as raw:
        binary = Path(raw) / "fixture"
        command = [
            os.environ.get("CC", "cc"),
            "-std=c11",
            "-D_POSIX_C_SOURCE=200809L",
            "-Wall",
            "-Wextra",
            "-Werror",
            f"-I{prefix / 'include'}",
            str(FIXTURE),
            f"-L{prefix / 'lib'}",
            f"-Wl,-rpath,{prefix / 'lib'}",
            "-ljson-c",
            "-o",
            str(binary),
        ]
        subprocess.run(command, check=True, capture_output=True, text=True)
        env = os.environ.copy()
        env["DYLD_LIBRARY_PATH"] = str(prefix / "lib")
        env["LD_LIBRARY_PATH"] = str(prefix / "lib")
        completed = subprocess.run(
            [str(binary)], check=True, capture_output=True, text=True, env=env
        )
    assert completed.stdout.strip() == (
        "ok: AC management pairing ubus is strict, secret-safe, and excludes redeem"
    )


def main() -> None:
    test_static_contract()
    test_compiled_fixture()
    print("ok: AC pairing-token management ubus remains node-redeem-free after Phase 1E transport")


if __name__ == "__main__":
    main()

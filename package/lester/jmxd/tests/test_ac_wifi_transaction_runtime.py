#!/usr/bin/env python3
"""W3 wifi transaction orchestration: atomic fan-out to transaction +
per-AP targets + per-AP queued config jobs, idempotent replay, revision
conflict and invalid-target rollback, status join."""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apd_test_deps  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/ac/ac_db.c"
HEADER = ROOT / "src/ac/ac_internal.h"
# ac_db.c derives 802.11r key material through the encrypted secret store on
# the roaming path, which is compiled in standalone mode too, so ac_secrets.c
# has to be linked in or nothing here links at all.  AC_SECRETS_TESTING relaxes
# the key-file owner check from root to the current euid; no case below reaches
# that path, but a future one must not need root or write outside the tempdir.
SECRETS = ROOT / "src/ac/ac_secrets.c"
FIXTURE = ROOT / "tests/ac_wifi_transaction_runtime_fixture.c"
# APD is the authority on the hostapd action vocabulary: it is the side that
# reads these options off the candidate and turns them into control-socket
# commands.  The AC's allow-list is derived from it below rather than restated,
# because a name the AC drops is a steer the AC refuses to carry -- how
# `deauth_reason` went missing while every deauth case still looked green.
APD_BACKEND = ROOT / "src/apd/apd_backend_openwrt.c"
APD_ACTION_DISPATCH = "apd_config_apply_hostapd_actions"


def function_body(source: str, name: str) -> str:
    """Slice one static function definition out of ac_db.c.

    The roaming dispatchers sit inside #ifndef AC_DB_TEST_STANDALONE, so the
    fixture cannot call them; the checks that need them are static, exactly as
    the hostapd wire formats are pinned in the roaming-domain test.

    Some of them are forward-declared, so take the *last* occurrence of the
    signature: the prototype comes first and ends in ';', the definition is
    what carries the body.  Slicing the prototype instead would end the slice
    at some unrelated function, so assert on the brace rather than trusting it.
    """
    start = source.rindex(f"static int {name}(")
    body = source[start:source.index("\n}\n", start)]
    assert ")\n{\n" in body, f"{name}: sliced a prototype, not a definition"
    return body


def static_contract() -> None:
    db = SOURCE.read_text(encoding="utf-8")
    for token in (
        "ac_db_wifi_transaction_apply",
        "ac_db_wifi_transaction_status_json",
        '"revision_conflict"',
        "BEGIN IMMEDIATE",
        "ac_transaction_targets",
    ):
        assert token in db, f"missing transaction contract: {token}"
    for token in ("previous_digest", "readback_digest", "readback_json",
                  "target_write_capability_unavailable"):
        assert token in db, f"missing transaction evidence/gate: {token}"

    # A hostapd runtime action is not a UCI option write, and must not be
    # validated as one -- the whole of Phase 3/4 steering plus 11k neighbour
    # push travels the candidate contract.
    for token in ("ac_config_candidate_section_is_action",
                  "ac_config_candidate_action_option_allowed",
                  "ac_config_candidate_action_type_valid",
                  "ac_config_candidate_action_section_valid",
                  '"candidate_action_type_invalid"'):
        assert token in db, f"missing action-candidate contract: {token}"

    # The standalone build does not include ac_internal.h, so the sentinel is
    # written out three times.  A fixture still passing -1 while the header
    # moved would test nothing, so pin the copies to each other.
    sentinel = "#define AC_WIFI_TX_BASE_REVISION_CURRENT ((int64_t)-1)"
    assert sentinel in HEADER.read_text(encoding="utf-8"), (
        "base-revision sentinel lost from ac_internal.h")
    assert sentinel in db, "base-revision sentinel lost from ac_db.c mirror"
    assert "#define BASE_CURRENT ((int64_t)-1)" in \
        FIXTURE.read_text(encoding="utf-8"), (
            "fixture no longer mirrors the base-revision sentinel")

    for name in ("ac_roam_btm_dispatch", "ac_roam_deauth_dispatch"):
        body = function_body(db, name)
        # Without a digest the transaction answers target_invalid, so the steer
        # fails no matter what the radios do.
        assert "ac_config_candidate_digest" in body, \
            f"{name} dispatches a candidate with no digest"
        # A literal base revision conflicts as soon as anything else has ever
        # been applied, which on a live controller is always.
        assert "AC_WIFI_TX_BASE_REVISION_CURRENT" in body, \
            f"{name} makes a stale optimistic-concurrency claim"
        # The candidate contract admits string values only.
        assert "json_object_new_int" not in body, \
            f"{name} emits a non-string option value"

    action_options()


def action_options() -> None:
    """Every action option APD reads must be one the AC will carry."""
    apd = APD_BACKEND.read_text(encoding="utf-8")
    start = apd.index(f"static int {APD_ACTION_DISPATCH}(")
    dispatch = apd[start:apd.index("\n}\n", start)]
    read = set(re.findall(r'json_object_object_get\(options,\s*\n?\s*"(\w+)"\)',
                          dispatch))
    assert len(read) >= 12, f"APD action option scan found only {sorted(read)}"
    allowed = function_body(SOURCE.read_text(encoding="utf-8"),
                            "ac_config_candidate_action_option_allowed")
    missing = sorted(name for name in read if f'"{name}"' not in allowed)
    assert not missing, f"AC candidate allow-list rejects APD options: {missing}"


def compile_fixture(output: Path) -> None:
    json_flags = apd_test_deps.package_flags("json-c")
    openssl_flags = apd_test_deps.package_flags("openssl")
    command = [
        os.environ.get("CC", "cc"), "-std=c11",
        "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
        "-DAC_DB_TEST_STANDALONE", "-DAC_DB_TELEMETRY_TEST_STANDALONE",
        "-DAC_DB_ROAMING_ACTIONS_TEST",
        "-DAC_SECRETS_TESTING",
        "-DAC_DB_WIFI_TRANSACTION_TEST",
        "-Wall", "-Wextra", "-Werror",
        f"-I{ROOT / 'src/ac'}",
        str(FIXTURE), str(SOURCE), str(SECRETS),
        *json_flags, *openssl_flags, "-lsqlite3", "-lm",
        "-o", str(output),
    ]
    # check=True reports the argv and drops the compiler's own output, which is
    # the only part that says what went wrong.
    done = subprocess.run(command, capture_output=True, text=True)
    if done.returncode != 0:
        raise AssertionError("fixture build failed:\n" + done.stderr)


def test_runtime() -> None:
    with tempfile.TemporaryDirectory(prefix="ac-wifi-tx-") as raw:
        temp = Path(raw)
        binary = temp / "fixture"
        compile_fixture(binary)
        env = os.environ.copy()
        env["DREAMINGWRT_AC_DB_PATH"] = str(temp / "config.db")
        env["DREAMINGWRT_AC_SECRETS_KEY_PATH"] = str(temp / "ac-secrets.key")
        completed = subprocess.run([str(binary)], env=env,
                                   capture_output=True, text=True)
        # The fixture names the failing check on stderr, so keep both streams.
        assert completed.returncode == 0 and completed.stdout.strip() == "ok", \
            completed.stdout + completed.stderr


def main() -> None:
    static_contract()
    test_runtime()
    print("ok: W3 wifi transaction orchestration fan-out contract")


if __name__ == "__main__":
    main()
